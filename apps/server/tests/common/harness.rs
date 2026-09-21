//! The server harness `end_to_end.rs` grew, shared with `reponse_validee.rs`.
//!
//! Moved here verbatim — `Server`, its two credentials, the webhook secret,
//! the wedge deadline and the `claude` that is a shell script — because the
//! second test that wanted a real binary on a private database wanted exactly
//! this one, keys and all, and a second copy is how `private_name` got written
//! wrong three times (see `mod.rs`). Every `pub` below is a field or method a
//! test outside this module reads; nothing else changed.
//!
//! The one addition is [`FakeModel::answers_when`], a reply keyed on a needle
//! in the prompt rather than on the identity line: the answer to a prospect's
//! words has to differ from the first approach, and both are the same seat.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::File;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agentos_domain::ids::TenantId;
use agentos_store::db::Db;
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

/// Long enough for `ApiKeys::MIN_SECRET_LEN`.
pub const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// A second key, and a second *label*: `routes::approvals::held_role` reads the
/// role a credential holds straight off the key's label, and the gate files
/// payment approvals against `APPROVER_ROLE`. One key cannot both request and
/// grant — `may_decide` refuses four-eyes on itself — so a deployment that
/// wants approvals to be decidable at all needs two, which is exactly the shape
/// this proves.
pub const APPROVER_SECRET: &str = "fedcba9876543210fedcba9876543210";

/// The signing secret this deployment registers for the `email` provider.
pub const WEBHOOK_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

/// How long the provisioning loop gets to make **no progress at all** before
/// this test calls it wedged.
///
/// It is not a budget for the whole convergence, and that is the point. The
/// number was 30s, then 120s, then 300s, raised each time after it fired on a
/// machine that was merely loaded — three sibling worktrees compiling on
/// 2026-08-28, parallel agent builds on 2026-08-29, a CI runner on 2026-09-10
/// (run 34461698789, the same test converging in seconds when re-run alone).
/// Each raise bought a few weeks and taught whoever saw the red to re-run
/// without reading, which is the actual cost.
///
/// So the clock now measures the right thing: it is reset every time any step's
/// state changes. A loop that is slow because it is getting a tenth of a core
/// never trips it; a loop that is genuinely stuck trips it after this long with
/// nothing moving, which is the only reading of "wedged" that does not depend
/// on how busy the machine is. 60s because eleven steps against mock adapters
/// take well under a second each even on a runner, so a minute of complete
/// silence is already far past anything healthy.
///
/// **Measured again the same day, and raised to 180s:** running the six
/// packages of this workspace at once on the founder's laptop starved the
/// provisioning loop for a full sixty seconds — the same test converging in
/// 5.2s when run on its own a minute later. Total starvation is still
/// starvation, so the number has to clear it; what changed for good is that it
/// now clears *silence* rather than *duration*, so a loop that is merely slow
/// is never accused, however long it takes.
///
/// **Measured a third time, 2026-09-11 au soir, and raised to 300s.** Same
/// test, same tree, same private database, three runs an hour apart:
///
/// | machine | wall clock |
/// |---|---|
/// | idle | **33 s** |
/// | one agent compiling the workspace | **226 s** |
/// | the same, a minute later | **252 s** |
///
/// 180s of *silence* was still not enough at the top of that range, and the red
/// it produced looked exactly like a product defect — a seat stuck on its
/// browser step. I spent half an hour proving it was the browser before running
/// the control: the same test **without** a browser configured was slower
/// still. Nothing about the product had changed; the laptop had. That half hour
/// is what a deadline set too tight actually costs, and it is why this one is
/// set from a measurement rather than from a guess.
///
/// The asymmetry decides the number: a deadline too long makes a genuine wedge
/// take five minutes to report, which costs five minutes. A deadline too short
/// accuses the product of a defect it does not have, which costs an afternoon
/// and teaches whoever reads the red to stop believing it.
///
/// **Et 300s était encore trop court : rouge en CI à 302s.** Raiser au jugé une
/// quatrième fois serait courir après un runner. Le chiffre se **déduit**, et il
/// se déduit du produit lui-même.
///
/// Un pas en cours de tentative n'écrit **rien** : `EngineEngine::attempt`
/// réessaie en mémoire, sans toucher la ligne, donc `updated_at` ne bouge pas et
/// l'écran que ce test lit est légitimement muet pendant tout le budget de
/// reprise. Le silence normal le plus long vient donc de `EngineConfig`, dont
/// les valeurs par défaut sont dans `crates/app/src/provisioning.rs` :
///
/// | terme | défaut | ce qu'il vaut |
/// |---|---|---|
/// | `max_attempts × (call_timeout + backoff_cap)` | 3 × (20s + 5s) | **75s** |
/// | `lease` — une reprise perdue attend le balayage | 120s | **120s** |
/// | total | | **195s** |
///
/// Puis le facteur de la machine, mesuré et non supposé : le même test converge
/// en **33s** au repos et en **252s** pendant qu'un agent compile. Trois fois.
/// 195 × 3 ≈ 600.
///
/// Dix minutes pour signaler un vrai blocage est le bon prix : il n'arrive
/// jamais, et quand il arrivera on aura dix minutes de retard sur une panne
/// qu'on cherchait de toute façon. Un faux rouge, lui, arrive à chaque vague et
/// coûte un après-midi.
pub const CONVERGE_DEADLINE: Duration = Duration::from_secs(600);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A running server, its database, and the tenant whose key we hold.
pub struct Server {
    child: Child,
    pub base: String,
    admin_url: String,
    database: String,
    /// Where the server's own JSON log went. A file rather than a pipe: a pipe
    /// nobody is reading fills up at 64 KB and blocks the process being tested
    /// on its own `info!`.
    log: PathBuf,
    pub database_url: String,
    /// The tenant the API key speaks for. Kept because the readiness section
    /// installs a policy ceiling against it, which is the one piece of setup a
    /// real deployment also does out of band.
    pub tenant: TenantId,
    /// Set by [`Server::shutdown`]. [`Drop`] reads it and does nothing when the
    /// orderly path already ran.
    reaped: bool,
}

/// **A failing test must not leave a server running.**
///
/// [`Server::shutdown`] takes `self` by value, so a panic anywhere in a test —
/// which is what an assertion failing *is* — skips it entirely. What used to be
/// left behind was a live `agentos-server` holding a connection to an `e2e_*`
/// database nothing would ever drop, and one of those hung a later run for
/// fourteen minutes on a pipe with no reader. A red test is a fact about the
/// code; a red test that also poisons the next six runs is a fact about the
/// harness, and it teaches people to stop trusting the suite.
///
/// SIGKILL and not SIGTERM, deliberately. `shutdown` sends SIGTERM because it is
/// *asserting* the server obeys it — "a pod that will not die" is one of the
/// things that test checks. This path is not asserting anything: it runs while
/// a panic is unwinding, it cannot fail the test it is cleaning up after, and a
/// graceful shutdown it then had to wait on would turn one failure into a
/// timeout. Take the process away and let the panic finish.
///
/// The database is deliberately **not** dropped here: it needs an async runtime
/// and a thread join, both of which can themselves panic, and a panic inside
/// `Drop` during unwinding aborts the process — replacing a readable assertion
/// failure with `SIGABRT`. `scripts/test.sh` drops every database this run
/// created on its way out, which is where that cleanup belongs.
impl Drop for Server {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// `None` when there is no database — these assertions are about rows and
    /// sockets, and a mock of either would be a mock of the test.
    /// Boot a server on a database of its own — the name says so at every
    /// call site, because `crates/app/tests/scoped_deletes.rs` reads test
    /// files for that word: a test that installs an operator ceiling writes
    /// the one global policy row, and must visibly not do it in the shared
    /// pool. The harness always did; moving it here took the word out of the
    /// files that use it.
    pub async fn start_on_private_db() -> Option<Self> {
        Self::start_on_private_db_with(&[]).await
    }

    /// The same server, with `extra` layered over the environment it is spawned
    /// with. `extra` wins, including over `PATH` — which is the whole point:
    /// [`FakeModel`] shadows `claude` by putting a directory of its own in
    /// front, and `CliLlm` resolves the program off `PATH` with no variable to
    /// override it.
    /// [`Self::start_on_private_db`] with extra environment for the server.
    pub async fn start_on_private_db_with(extra: &[(&str, String)]) -> Option<Self> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the end-to-end run needs a real Postgres");
            return None;
        };

        // A database of our own, migrated by the server itself on boot.
        let (base_url, _) = url.rsplit_once('/').expect("DATABASE_URL has a path");
        let admin_url = format!("{base_url}/postgres");
        let database = super::private_name(&url, "e2e");
        let admin = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect to postgres");
        // `CREATE DATABASE` takes no bind parameters, so the name is
        // interpolated — and it is `common::private_name`'s, which is this
        // run's own database name and two integers. That is the audit
        // `AssertSqlSafe` asks for, and it is also what makes the database go
        // away: see that module for what a name of our own choosing cost.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await
            .expect("create the test database");
        admin.close().await;

        let database_url = format!("{base_url}/{database}");
        let db = Db::connect(&database_url).await.expect("connect");
        db.migrate().await.expect("migrate");

        // A tenant for the key to speak for. The key names it; the row has to
        // exist for anything to be inserted against it.
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind("end-to-end")
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        drop(db);

        // Ask the kernel for a free port and hand it straight over. A race with
        // another process is possible and has never been the flaky thing.
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("a free port")
            .local_addr()
            .expect("addr")
            .port();

        let mut env: HashMap<&str, String> = HashMap::from([
            ("APP_BIND", format!("127.0.0.1:{port}")),
            ("PUBLIC_HOST", format!("http://127.0.0.1:{port}")),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com".to_owned()),
            ("DATABASE_URL", database_url.clone()),
            ("AGENTOS_MASTER_KEY", "not-a-real-key".to_owned()),
            // Every adapter is a mock here, so the boot guard has to be told
            // out loud. Without this the server refuses to start — which is
            // its own test, in `boot.rs`.
            ("AGENTOS_ALLOW_MOCKS", "1".to_owned()),
            (
                "AGENTOS_API_KEYS",
                format!(
                    "ops:{tenant}:{SECRET},approver:{tenant}:{APPROVER_SECRET}",
                    tenant = tenant.as_uuid()
                ),
            ),
            (
                "AGENTOS_WEBHOOK_SECRETS",
                format!("email:{}:{WEBHOOK_SECRET}", tenant.as_uuid()),
            ),
            ("RUST_LOG", "info,agentos_server=debug".to_owned()),
        ]);
        env.extend(extra.iter().map(|(k, v)| (*k, v.clone())));

        let log = std::env::temp_dir().join(format!("{database}.log"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentos-server"));
        command
            .env_clear()
            .stdout(Stdio::from(File::create(&log).expect("log file")))
            .stderr(Stdio::inherit());
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
        for (var, value) in &env {
            command.env(var, value);
        }
        let child = command.spawn().expect("start the server");

        let server = Self {
            child,
            base: format!("http://127.0.0.1:{port}"),
            admin_url,
            database,
            log,
            database_url,
            tenant,
            reaped: false,
        };
        server.wait_until_live();
        server.connect_the_model();
        Some(server)
    }

    /// Connect this tenant's model, over the real route, before anything asks
    /// for a turn.
    ///
    /// **Not a fixture shortcut — the product's own first step.** After
    /// `migrations/0041_tenant_model_access.sql` a tenant that has connected no
    /// model takes no turn at all, and this harness is the only place in the
    /// workspace where that step happens the way a customer does it: an HTTP
    /// request to the running binary, answered by the real handler, proved by a
    /// real `Llm::complete`.
    ///
    /// `cli` rather than `api_key`, because these tests must never carry a
    /// credential and must never call a paid API. On this deployment
    /// `AGENTOS_LLM` is the scripted mock or the fake `claude` script the tests
    /// install, so "the model this host has" is exactly what the test scripted —
    /// and `pays_with_our_key()` is false for both, which is what makes the path
    /// legal here at all.
    fn connect_the_model(&self) {
        let (status, body) = self.post("/v1/model", Some(SECRET), r#"{"path":"cli"}"#);
        assert_eq!(status, 200, "connecting the model: {body}");
        assert_eq!(body["connected"], true, "{body}");
        assert_eq!(body["verdict"], "connected", "{body}");
        assert_eq!(body["access"]["path"], "cli", "{body}");
        // The response carries the proof and nothing else — no credential, and
        // on this path there was not one to leak.
        assert!(body["access"].get("api_key").is_none(), "{body}");

        let (status, connected) = self.get("/v1/model", Some(SECRET));
        assert_eq!(status, 200, "{connected}");
        assert_eq!(connected["path"], "cli", "{connected}");
    }

    /// Block until `/livez` answers, or give up and say so.
    fn wait_until_live(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.get("/livez", None).0 == 200 {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the server never became live");
    }

    /// `GET path`, with the API key when `secret` is `Some`.
    pub fn get(&self, path: &str, secret: Option<&str>) -> (u16, Value) {
        self.curl("GET", path, &bearer(secret), None)
    }

    /// `POST path` with a JSON body, with the API key when `secret` is `Some`.
    pub fn post(&self, path: &str, secret: Option<&str>, body: &str) -> (u16, Value) {
        self.curl("POST", path, &bearer(secret), Some(body))
    }

    /// `PUT path` with a JSON body. Always authenticated: nothing in this
    /// server takes a `PUT` from a stranger.
    pub fn put(&self, path: &str, body: &str) -> (u16, Value) {
        self.curl("PUT", path, &bearer(Some(SECRET)), Some(body))
    }

    /// One request. Returns the status and the body parsed as JSON (`Null` when
    /// it is not JSON, e.g. `/livez`).
    pub fn curl(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> (u16, Value) {
        let url = format!("{}{path}", self.base);
        let mut args = vec![
            "-sS".to_owned(),
            "-X".to_owned(),
            method.to_owned(),
            // The status code, on its own last line, after the body.
            "-w".to_owned(),
            "\n%{http_code}".to_owned(),
            url,
        ];
        for (name, value) in headers {
            args.push("-H".to_owned());
            args.push(format!("{name}: {value}"));
        }
        if let Some(body) = body {
            args.push("-H".to_owned());
            args.push("Content-Type: application/json".to_owned());
            args.push("-d".to_owned());
            args.push(body.to_owned());
        }

        let output = Command::new("curl")
            .args(&args)
            .output()
            .expect("curl must be on PATH");
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let (body, status) = text
            .rsplit_once('\n')
            .expect("curl -w writes the status on its own line");

        eprintln!("--- {method} {path} -> {status}\n{body}");
        (
            status.trim().parse().expect("an HTTP status"),
            serde_json::from_str(body).unwrap_or(Value::Null),
        )
    }

    /// Poll one employee until the provisioning loop is done with it.
    ///
    /// Nothing in this function makes provisioning happen — that is the claim.
    /// The loop inside the server converges the employee on its own, and this
    /// only watches.
    ///
    /// "Done" is every step having *left* `pending` and `provisioning`, not
    /// `health` reaching a settled value. Health is derived from the blocking
    /// steps alone, so it goes `degraded` the moment those four land — which
    /// can be a whole wave before the browser, which waits on the vault, has
    /// been attempted at all. Reading health as the finish line makes this test
    /// pass or fail on which poll happened to land where.
    pub fn await_provisioned(&self, id: &str) -> Value {
        // The deadline follows progress rather than the wall clock: every time
        // a step's state changes, the loop has proved it is alive and the
        // countdown starts over. See `CONVERGE_DEADLINE`.
        let mut idle_since = Instant::now();
        let mut seen = String::new();
        loop {
            let (status, employee) = self.get(&format!("/v1/employees/{id}"), Some(SECRET));
            assert_eq!(status, 200, "the id we were handed stopped resolving");

            let resources = employee["resources"].as_array().expect("resources");
            let settled = resources
                .iter()
                .all(|r| !matches!(r["state"].as_str(), Some("pending" | "provisioning")));
            if settled {
                return employee;
            }

            let states: String = resources
                .iter()
                .map(|r| format!("{}={};", r["step"], r["state"]))
                .collect();
            if states != seen {
                seen = states;
                idle_since = Instant::now();
            } else if idle_since.elapsed() >= CONVERGE_DEADLINE {
                // The server writes its log to a file nobody prints, so a
                // wedge on CI used to be unreadable: the resources table said
                // `provisioning` and nothing said why. The loop's own last
                // lines are the only thing that can.
                let log = std::fs::read_to_string(&self.log).unwrap_or_default();
                let tail: Vec<&str> = log
                    .lines()
                    .rev()
                    .take(80)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                panic!(
                    "the provisioning loop moved nothing for {}s; wedged: {employee:#}\n--- server log, last {} lines ---\n{}",
                    CONVERGE_DEADLINE.as_secs(),
                    tail.len(),
                    tail.join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Poll until the employee is activated.
    ///
    /// A second wait, and a second failure message, because this is a second
    /// mechanism: the last step going `ready` enqueues an outbox event, and the
    /// *outbox* loop is what reads it and moves the lifecycle. Resources
    /// settling and the employee becoming usable are one poll interval and one
    /// registered handler apart, and when they disagree it matters which.
    pub fn await_active(&self, id: &str) -> Value {
        let deadline = Instant::now() + CONVERGE_DEADLINE;
        let mut last = Value::Null;
        while Instant::now() < deadline {
            let (_, employee) = self.get(&format!("/v1/employees/{id}"), Some(SECRET));
            if employee["lifecycle"] == "active" {
                return employee;
            }
            last = employee;
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "the employee was provisioned and never activated, so the gate would refuse \
             every action it takes: {last:#}"
        );
    }

    /// SIGTERM, then wait — this is the drain, and it has to finish.
    pub fn shutdown(mut self) -> String {
        let pid = self.child.id();
        // No `nix` dependency for one signal.
        Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("send SIGTERM");

        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            match self.child.try_wait().expect("wait") {
                Some(status) => break status,
                None if Instant::now() > deadline => {
                    let _ = self.child.kill();
                    panic!("the server ignored SIGTERM; a pod that will not die");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        assert!(status.success(), "the server exited {status}");

        let logs = std::fs::read_to_string(&self.log).unwrap_or_default();
        let _ = std::fs::remove_file(&self.log);

        // The database goes with it.
        let (admin_url, database) = (self.admin_url.clone(), self.database.clone());
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    if let Ok(admin) = sqlx::PgPool::connect(&admin_url).await {
                        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                            "DROP DATABASE IF EXISTS {database} (FORCE)"
                        )))
                        .execute(&admin)
                        .await;
                        admin.close().await;
                    }
                });
        })
        .join()
        .expect("drop the test database");

        // Nothing left for `Drop` to reap, and saying so is what stops it
        // SIGKILLing a pid the OS may already have handed to somebody else.
        self.reaped = true;

        logs
    }

    /// Count rows in the server's own database. The assertions the HTTP surface
    /// cannot make: what the loops wrote after answering.
    pub async fn count(&self, sql: &str) -> i64 {
        let pool = sqlx::PgPool::connect(&self.database_url)
            .await
            .expect("connect to the test database");
        // `AssertSqlSafe` because the string is no longer `&'static` — every
        // caller below builds it from a `format!` over ids this test read out
        // of the server's own JSON, and there is nothing else in it.
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&pool)
            .await
            .expect("count");
        pool.close().await;
        n
    }

    /// The whole audit trail, one `kind/decision/reason` line per distinct
    /// ruling, with how many of each.
    ///
    /// A summary rather than the rows because the assertion is about *which
    /// decisions were taken*, and the rows carry ids that change per run. It
    /// doubles as the failure message: an assertion that some ruling is missing
    /// prints every ruling that is there, which is the first thing anybody
    /// debugging it would go and look up.
    ///
    /// `payload->>'denied'` is the second reason column and not an alternative
    /// spelling of the first: the gate has four refusals the domain has no
    /// `DenyReason` for — an inactive employee, an unknown one, a broken policy
    /// book and a missing platform ceiling — and it writes those with a null
    /// `decision` and a `denied` key. A summary that read only
    /// `deny_reason_code` would report the fail-closed refusal this test is
    /// built around as an untyped blank.
    pub async fn audit_summary(&self) -> Vec<String> {
        let pool = sqlx::PgPool::connect(&self.database_url)
            .await
            .expect("connect to the test database");
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT action_kind, \
                    coalesce(decision, payload ->> 'denied', '-') \
                      || coalesce('/' || deny_reason_code, ''), \
                    count(*) \
               FROM audit_log \
              WHERE tenant_id = $1 \
              GROUP BY 1, 2 ORDER BY 1, 2",
        )
        .bind(self.tenant.as_uuid())
        .fetch_all(&pool)
        .await
        .expect("read the audit trail");
        pool.close().await;
        rows.into_iter()
            .map(|(kind, outcome, n)| format!("{kind}/{outcome} x{n}"))
            .collect()
    }

    /// `agentos-server policy install`, the way an operator installs a ceiling.
    ///
    /// The same binary under test, invoked as the subcommand rather than the
    /// server — which is the point: this is the *only* writer of a platform
    /// layer outside a fixture, there is no route that does it, and a test that
    /// called `store::policy::install_ceiling` directly would prove the store
    /// function works and nothing about whether an operator can reach it.
    pub fn install_ceiling(&self) -> String {
        self.policy(&["install"])
    }

    /// `agentos-server policy <args>` against this server's database — the
    /// ceiling above, or a role layer (`install --tenant … --role … <file>`),
    /// which is the same subcommand and the same argument for going through
    /// it rather than through the store.
    pub fn policy(&self, args: &[&str]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_agentos-server"))
            .arg("policy")
            .args(args)
            .env_clear()
            .env("DATABASE_URL", &self.database_url)
            .output()
            .expect("run the policy subcommand");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "the operator could not run `policy {args:?}`: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
    }
}

/// The `Authorization` header, or none at all.
pub fn bearer(secret: Option<&str>) -> Vec<(&'static str, String)> {
    secret
        .map(|secret| vec![("Authorization", format!("Bearer {secret}"))])
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// A model that is a shell script
// ---------------------------------------------------------------------------

/// The request the server built for the model, captured from outside the
/// process, plus the reply it gets back.
///
/// # Why a script on `PATH` and not a mock object
///
/// `agentos_app::mocks::ScriptedLlm` records every [`LlmRequest`] it is handed
/// and is what the in-process tests assert prompt assembly with. It is
/// unreachable from here: `mocks::llm` drops it straight into an
/// `Arc<dyn Llm>` inside a process this test only has a socket to, and there is
/// no route that hands a prompt back.
///
/// `AGENTOS_LLM=cli` selects [`CliLlm`], which spawns `claude` and reads
/// JSON Lines back — one event per line, `--output-format stream-json`. The **conversation** goes to its stdin — never argv,
/// deliberately, because a conversation carries a counterparty's words — and
/// the **system prompt** goes to `--system-prompt`, which is where it has to be
/// for it to be the model's system prompt rather than a user message. So the
/// capture below is argv and stdin concatenated: that is the request, whole.
/// `CliLlm::new()` takes the program off `PATH` and offers no variable to point
/// it elsewhere, so shadowing `claude` with a directory of our own is the seam.
///
/// What that buys is the thing this test exists for: the bytes asserted on
/// below are the bytes the running server produced, not a rendering this test
/// asked a library for. What it costs is that the CLI backend flattens the
/// structured request into one string — the system prompt, then the
/// conversation — so the assertions are on substrings of a prompt rather than
/// on typed fields. That is the same information; `llm_cli::render_prompt` is
/// the only thing between them.
///
/// The tools are the exception: they no longer travel in the prompt at all,
/// they are declared over MCP. The script below asks that server for them and
/// appends the names to the capture, which is why a `## tools` section still
/// exists to assert on.
pub struct FakeModel {
    dir: PathBuf,
}

/// `@DIR@` is substituted rather than `format!`ed in: the script is mostly
/// braces, and escaping every one of them to get four characters replaced is a
/// worse trade than a placeholder.
const FAKE_MODEL: &str = r#"#!/bin/sh
# argv carries the system prompt, stdin carries the conversation and the tool
# schemas. Both, into one file, because the assertions below are about the
# request and it is in two places. Keep every one, in a file of its own,
# because a turn is several round trips and which one said what matters.
d='@DIR@'
p="$(mktemp "$d/prompt.XXXXXXXX")"
# Written aside and renamed into place, never streamed into "$p" — and the
# staging name deliberately does not begin with `prompt.`, which is what
# `await_prompt` matches on.
#
# The bug this fixes: `printf` flushes the system prompt from argv *before*
# `cat` has copied stdin, and the tool schemas are in stdin. `await_prompt`
# polls this directory and returns the first file containing its needle — and
# the needle ("You are head-of-growth,") is in the argv half. So under load
# the reader could catch a file that already had the identity line and not yet
# the `## tools` section, and return it; the assertion that then failed was
# `split_once("\n## tools\n")`, which reads as "the server rendered no tool
# schemas" and is not what happened. `mv` within one directory is atomic, so
# every `prompt.*` a reader can see is either empty or whole.
staging="$d/partial.$$"
{ printf '%s\n' "$@"; cat; } > "$staging"

# Les schemas d'outils ne sont plus dans le prompt : ils partent par MCP, sur un
# serveur de boucle locale que `--mcp-config` nomme — et cette valeur-la EST sur
# argv, donc dans la capture. On lit `tools/list` exactement comme le vrai CLI
# le lit, et on ecrit les noms dans la capture sous `## tools`. Sans ca ce
# harnais ne peut plus rien affirmer sur ce que le tour a offert, et les
# assertions du filtre de politique — la preuve de bout en bout qu'un outil
# refuse n'est pas propose — n'auraient plus de source.
url=$(grep -o 'http://127\.0\.0\.1:[0-9]*/mcp' "$staging" | head -1)
if [ -n "$url" ]; then
  { printf '\n## tools\n'
    curl -s -m 5 -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$url" \
      | jq -r '.result.tools[]?.name | "- name: " + .'
  } >> "$staging"
fi

mv "$staging" "$p"

# Whose turn this is comes out of the prompt itself — the identity line the
# server writes is `You are <slug>, an AI employee at ...`. Branching on it
# rather than on a counter keeps the answers stable when the loops interleave
# two employees' turns, which they do.
r="$d/reply.default"
# A rule with a needle of its own outranks the identity line: `needle.<name>`
# holds the text to look for and `reply.<name>` what to say when it is there.
# That is how one seat gets two different answers — an approach on its
# cadence and a reply once a prospect's words are in the prompt.
for n in "$d"/needle.*; do
  [ -e "$n" ] || continue
  name="${n##*/needle.}"
  if grep -qF -- "$(cat "$n")" "$p"; then
    r="$d/reply.$name"
    break
  fi
done
if [ "$r" = "$d/reply.default" ]; then
  for f in "$d"/reply.*; do
    who="${f##*/reply.}"
    if [ "$who" != default ] && grep -q "You are $who," "$p"; then
      r="$f"
      break
    fi
  done
fi

# A prompt that already carries a tool result is the second round trip of a
# turn. Answer it with prose, or a script that asks for a tool asks for it
# again every round until the turn's budget runs out.
if grep -q '^\[tool ' "$p"; then
  r="$d/reply.default"
fi

# UNE LIGNE, pas un tableau : `--output-format stream-json` est du JSON Lines
# et `llm_cli::parse_stream` lit `stdout.lines()`. Un tableau sur une ligne se
# parse, mais `e["type"]` d'un tableau vaut null, donc aucun evenement `result`
# n'est trouve — `cli_no_result`, que le probe de /v1/model rend en « la cle a
# ete refusee ». C'est ce qui a casse ce test quand le parseur a change.
# Un appel d'outil revient maintenant en bloc `tool_use` d'un evenement
# `assistant`, prefixe `mcp__agentos__` par le CLI — `parse_stream` ne
# re-gonfle plus une reponse en JSON strict. Les fichiers `reply.*` gardent
# leur forme `{"tool": …, "input": …}` : c'est ici qu'on traduit.
inner=$(jq -r . "$r")
name=$(printf '%s' "$inner" | jq -r '.tool // empty')
if [ -n "$name" ]; then
  printf '{"type":"assistant","message":{"id":"msg_%s","content":[{"type":"tool_use","id":"toolu_%s","name":"mcp__agentos__%s","input":%s}]}}\n' \
    "$$" "$$" "$name" "$(printf '%s' "$inner" | jq -c '.input // {}')"
  printf '{"type":"result","subtype":"success","is_error":false,"result":"","stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}\n'
else
  printf '{"type":"result","subtype":"success","is_error":false,"result":%s,"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}\n' \
    "$(printf '%s' "$inner" | jq -c 'if .text then .text else tojson end')"
fi
"#;

impl FakeModel {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("agentos-e2e-model-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("a directory for the fake model");
        let bin = dir.join("claude");
        std::fs::write(
            &bin,
            FAKE_MODEL.replace("@DIR@", &dir.display().to_string()),
        )
        .expect("write the fake model");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let fake = Self { dir };
        // Prose, and valid under the tool contract either way: `CliLlm` demands
        // strict JSON whenever the request carried tool schemas, and every
        // employee here has at least the internal channel in its floor.
        fake.answers("default", r#"{"tool": null, "text": "noted."}"#);
        fake
    }

    /// What the model says when the prompt says it is `who`. `reply` is the
    /// CLI's own tool-call wire format — `{"tool": …}` or `{"tool": null, …}`.
    pub fn answers(&self, who: &str, reply: &str) {
        // Encoded here rather than in the script: the CLI's `result` field is a
        // JSON *string*, and quoting one correctly in `sh` is how this would go
        // wrong silently.
        std::fs::write(
            self.dir.join(format!("reply.{who}")),
            serde_json::to_string(reply).expect("a JSON string"),
        )
        .expect("write a reply");
    }

    /// What the model says when the prompt contains `needle` — whoever the
    /// prompt says it is. Outranks [`Self::answers`]: a seat woken by a
    /// prospect's reply has that reply in its prompt, and its identity line
    /// too, and the words are what decide the answer.
    pub fn answers_when(&self, name: &str, needle: &str, reply: &str) {
        std::fs::write(self.dir.join(format!("needle.{name}")), needle).expect("write a needle");
        self.answers(name, reply);
    }

    /// `PATH` with the fake in front of whatever the runner had. `curl` and
    /// `kill` still resolve; only `claude` is shadowed.
    pub fn path(&self) -> String {
        let inherited = std::env::var("PATH").unwrap_or_default();
        format!("{}:{inherited}", self.dir.display())
    }

    /// Block until some captured prompt contains `needle`, and return it.
    ///
    /// Polling rather than a channel because the thing being waited on is a
    /// loop in another process deciding to wake an employee, and there is
    /// nothing to subscribe to.
    pub fn await_prompt(&self, needle: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            for entry in std::fs::read_dir(&self.dir).expect("read the capture directory") {
                let path = entry.expect("dir entry").path();
                if !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("prompt."))
                {
                    continue;
                }
                let prompt = std::fs::read_to_string(&path).unwrap_or_default();
                if prompt.contains(needle) {
                    return prompt;
                }
            }
            assert!(
                Instant::now() < deadline,
                "no turn ever reached the model with {needle:?} in its prompt; \
                 the employee was never woken, or it was woken and the gate refused"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for FakeModel {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
