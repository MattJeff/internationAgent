//! The whole thing, once, as a client sees it.
//!
//! Every other test in this workspace mounts a router in-process. This one
//! starts the **real binary** against a **real database**, talks to it over a
//! socket with `curl`, and asserts on what comes back. That is the only way to
//! check the things wiring can get wrong and a unit test cannot see:
//!
//! * the routers are actually merged into `app()`, at the paths they claim;
//! * the loops are actually spawned, because nothing else moves an employee out
//!   of `pending` — the provisioning loop has to do it on its own, from a
//!   cold start, with nobody driving it;
//! * the API stack is on the routes that need it and off the ones that must
//!   not have it;
//! * SIGTERM stops the process, loops and all, instead of hanging.
//!
//! # Its own database
//!
//! Created here and dropped at the end. The A2A card resolves "this
//! deployment's one active employee", the outbox poller is cross-tenant, and
//! the provisioning loop claims every tenant's rows — all three are correct
//! behaviours that make a shared database a source of interference rather than
//! a source of test failures worth reading. The server migrates it on boot,
//! which is itself part of what is under test.
//!
//! `curl`, not an HTTP client crate, because the deliverable is the curl
//! output and because `agentos-server` has no client dependency to reach for.
//!
//! # The second test: the life of a company
//!
//! [`a_company_is_drawn_takes_a_turn_talks_to_itself_and_meets_the_gate`] shares
//! this harness and drives the arc a deployment actually has — an org chart, a
//! ceiling, a turn, a colleague, money — because every bug found in this
//! workspace so far has been at a seam and not inside a unit. Four routers
//! written and never merged, a gate that never read stored policy, `spend_caps`
//! with no writer, and three waves of an internal channel that was complete,
//! tested and unreachable: not one of those is visible from inside the module
//! that contains it, and every one of them is visible from a test that makes
//! the whole company do something. See that test's own header for what it can
//! and cannot reach.

mod common;

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
const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// A second key, and a second *label*: `routes::approvals::held_role` reads the
/// role a credential holds straight off the key's label, and the gate files
/// payment approvals against `APPROVER_ROLE`. One key cannot both request and
/// grant — `may_decide` refuses four-eyes on itself — so a deployment that
/// wants approvals to be decidable at all needs two, which is exactly the shape
/// this proves.
const APPROVER_SECRET: &str = "fedcba9876543210fedcba9876543210";

/// The signing secret this deployment registers for the `email` provider.
const WEBHOOK_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

/// How long the provisioning loop gets to converge eleven steps against mock
/// adapters. It normally takes well under a second; this is the "it is wedged"
/// deadline, not the expected one.
///
/// Raised from 30s after it fired for real on 2026-08-28, with three sibling
/// worktrees compiling on the same machine: 31s under load against 5s isolated.
/// Nothing was wedged. A deadline that only holds on an idle machine is worse
/// than a slow one — it fails where the work is, teaches whoever sees it to
/// re-run without reading, and the day it means something nobody believes it.
/// Since this bound is never reached when the loop is healthy, making it
/// generous costs a green run nothing and costs a wedged one only patience.
const CONVERGE_DEADLINE: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A running server, its database, and the tenant whose key we hold.
struct Server {
    child: Child,
    base: String,
    admin_url: String,
    database: String,
    /// Where the server's own JSON log went. A file rather than a pipe: a pipe
    /// nobody is reading fills up at 64 KB and blocks the process being tested
    /// on its own `info!`.
    log: PathBuf,
    database_url: String,
    /// The tenant the API key speaks for. Kept because the readiness section
    /// installs a policy ceiling against it, which is the one piece of setup a
    /// real deployment also does out of band.
    tenant: TenantId,
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
    async fn start() -> Option<Self> {
        Self::start_with(&[]).await
    }

    /// The same server, with `extra` layered over the environment it is spawned
    /// with. `extra` wins, including over `PATH` — which is the whole point:
    /// [`FakeModel`] shadows `claude` by putting a directory of its own in
    /// front, and `CliLlm` resolves the program off `PATH` with no variable to
    /// override it.
    async fn start_with(extra: &[(&str, String)]) -> Option<Self> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the end-to-end run needs a real Postgres");
            return None;
        };

        // A database of our own, migrated by the server itself on boot.
        let (base_url, _) = url.rsplit_once('/').expect("DATABASE_URL has a path");
        let admin_url = format!("{base_url}/postgres");
        let database = common::private_name(&url, "e2e");
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
    fn get(&self, path: &str, secret: Option<&str>) -> (u16, Value) {
        self.curl("GET", path, &bearer(secret), None)
    }

    /// `POST path` with a JSON body, with the API key when `secret` is `Some`.
    fn post(&self, path: &str, secret: Option<&str>, body: &str) -> (u16, Value) {
        self.curl("POST", path, &bearer(secret), Some(body))
    }

    /// `PUT path` with a JSON body. Always authenticated: nothing in this
    /// server takes a `PUT` from a stranger.
    fn put(&self, path: &str, body: &str) -> (u16, Value) {
        self.curl("PUT", path, &bearer(Some(SECRET)), Some(body))
    }

    /// One request. Returns the status and the body parsed as JSON (`Null` when
    /// it is not JSON, e.g. `/livez`).
    fn curl(
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
    fn await_provisioned(&self, id: &str) -> Value {
        let deadline = Instant::now() + CONVERGE_DEADLINE;
        let mut last = Value::Null;
        while Instant::now() < deadline {
            let (status, employee) = self.get(&format!("/v1/employees/{id}"), Some(SECRET));
            assert_eq!(status, 200, "the id we were handed stopped resolving");

            let settled = employee["resources"]
                .as_array()
                .expect("resources")
                .iter()
                .all(|r| !matches!(r["state"].as_str(), Some("pending" | "provisioning")));
            if settled {
                return employee;
            }
            last = employee;
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the provisioning loop never converged the employee: {last:#}");
    }

    /// Poll until the employee is activated.
    ///
    /// A second wait, and a second failure message, because this is a second
    /// mechanism: the last step going `ready` enqueues an outbox event, and the
    /// *outbox* loop is what reads it and moves the lifecycle. Resources
    /// settling and the employee becoming usable are one poll interval and one
    /// registered handler apart, and when they disagree it matters which.
    fn await_active(&self, id: &str) -> Value {
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
    fn shutdown(mut self) -> String {
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
    async fn count(&self, sql: &str) -> i64 {
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
    async fn audit_summary(&self) -> Vec<String> {
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
    fn install_ceiling(&self) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_agentos-server"))
            .args(["policy", "install"])
            .env_clear()
            .env("DATABASE_URL", &self.database_url)
            .output()
            .expect("run the policy subcommand");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "the operator could not install a ceiling: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
    }
}

/// The `Authorization` header, or none at all.
fn bearer(secret: Option<&str>) -> Vec<(&'static str, String)> {
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
/// `AGENTOS_LLM=cli` selects [`CliLlm`], which spawns `claude` and reads a JSON
/// event array back. The **conversation** goes to its stdin — never argv,
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
/// conversation, then the tool schemas as text — so the assertions are on
/// substrings of a prompt rather than on typed fields. That is the same
/// information; `llm_cli::render_prompt` is the only thing between them.
struct FakeModel {
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
mv "$staging" "$p"

# Whose turn this is comes out of the prompt itself — the identity line the
# server writes is `You are <slug>, an AI employee at ...`. Branching on it
# rather than on a counter keeps the answers stable when the loops interleave
# two employees' turns, which they do.
r="$d/reply.default"
for f in "$d"/reply.*; do
  who="${f##*/reply.}"
  if [ "$who" != default ] && grep -q "You are $who," "$p"; then
    r="$f"
    break
  fi
done

# A prompt that already carries a tool result is the second round trip of a
# turn. Answer it with prose, or a script that asks for a tool asks for it
# again every round until the turn's budget runs out.
if grep -q '^\[tool ' "$p"; then
  r="$d/reply.default"
fi

printf '[{"type":"result","result":%s,"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}]' "$(cat "$r")"
"#;

impl FakeModel {
    fn new() -> Self {
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
    fn answers(&self, who: &str, reply: &str) {
        // Encoded here rather than in the script: the CLI's `result` field is a
        // JSON *string*, and quoting one correctly in `sh` is how this would go
        // wrong silently.
        std::fs::write(
            self.dir.join(format!("reply.{who}")),
            serde_json::to_string(reply).expect("a JSON string"),
        )
        .expect("write a reply");
    }

    /// `PATH` with the fake in front of whatever the runner had. `curl` and
    /// `kill` still resolve; only `claude` is shadowed.
    fn path(&self) -> String {
        let inherited = std::env::var("PATH").unwrap_or_default();
        format!("{}:{inherited}", self.dir.display())
    }

    /// Block until some captured prompt contains `needle`, and return it.
    ///
    /// Polling rather than a channel because the thing being waited on is a
    /// loop in another process deciding to wake an employee, and there is
    /// nothing to subscribe to.
    fn await_prompt(&self, needle: &str, within: Duration) -> String {
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

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// One employee, from `POST` to provisioned, plus the two surfaces that must
/// not be behind the API key and the one request that must be refused.
///
/// One test rather than five, because starting a server is the expensive part
/// and every assertion here is about the same running process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_posted_employee_is_provisioned_by_the_loops_and_the_edges_are_authenticated_correctly() {
    let Some(server) = Server::start().await else {
        return;
    };

    // -- an unauthenticated request is refused ------------------------------
    //
    // First, so that nothing below can be explained by "the key was ignored".
    let (status, problem) = server.get("/v1/employees", None);
    assert_eq!(status, 401, "the API is open: {problem:#}");
    assert_eq!(problem["code"], "unauthenticated");

    // -- POST /v1/employees -> 202 ------------------------------------------
    let create = |key: &str| {
        server.curl(
            "POST",
            "/v1/employees",
            &[
                ("Authorization", format!("Bearer {SECRET}")),
                ("Idempotency-Key", key.to_owned()),
            ],
            Some(r#"{"slug":"lena","domain":"agents.example.com"}"#),
        )
    };

    let (status, created) = create("e2e-create-0001");
    assert_eq!(
        status, 202,
        "creation is accepted, not created: {created:#}"
    );
    let id = created["id"].as_str().expect("an id").to_owned();
    assert_eq!(created["lifecycle"], "draft");
    assert_eq!(
        created["health"], "provisioning",
        "nothing is provisioned at the instant of acceptance"
    );

    // A repeat under the same key is the recorded answer, not a second
    // employee — the idempotency layer is in the stack the router inherited.
    let (status, replay) = create("e2e-create-0001");
    assert_eq!(status, 202);
    assert_eq!(replay, created, "the replay must be byte-identical");

    // -- the loops drive it forward on their own ----------------------------
    server.await_provisioned(&id);
    let employee = server.await_active(&id);
    let health = employee["health"].as_str().unwrap_or_default().to_owned();
    assert!(
        health == "online" || health == "degraded",
        "the employee did not converge: {employee:#}"
    );

    // Per resource, because "degraded" is only the right answer for the right
    // reason: every *blocking* step ready, and whatever is not ready is an
    // optional channel that says exactly what it is waiting on.
    let mut states: Vec<(String, String)> = employee["resources"]
        .as_array()
        .expect("resources")
        .iter()
        .map(|r| {
            (
                r["step"].as_str().unwrap_or_default().to_owned(),
                r["state"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    states.sort();
    eprintln!("--- resource states: {states:?}");

    for blocking in ["identity", "email", "vault", "permissions"] {
        let state = states
            .iter()
            .find(|(step, _)| step == blocking)
            .map(|(_, state)| state.as_str());
        assert_eq!(
            state,
            Some("ready"),
            "{blocking} is a blocking step and it is {state:?}: {employee:#}"
        );
    }
    for (step, state) in &states {
        assert_ne!(state, "pending", "{step} was never attempted");
        assert_ne!(state, "provisioning", "{step} is still held by a worker");
    }

    // Provisioned means *active*: an employee the gate would refuse every
    // action for is a row, not an employee.
    assert_eq!(
        employee["lifecycle"], "active",
        "nothing activated the employee: {employee:#}"
    );

    // -- GET /.well-known/agent-card.json, with no credential ---------------
    //
    // At the root, and outside the API-key layer: discovery is what a peer
    // does before it has anything.
    let (status, card) = server.get("/.well-known/agent-card.json", None);
    assert_eq!(status, 200, "the agent card is unreachable: {card:#}");
    assert_eq!(card["name"], "lena");
    for removed in ["url", "preferredTransport", "protocolVersion"] {
        assert!(
            card.get(removed).is_none(),
            "v1.0 removed the top-level `{removed}`: {card:#}"
        );
    }
    let interfaces = card["supportedInterfaces"]
        .as_array()
        .expect("supportedInterfaces");
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0]["protocolBinding"], "JSONRPC");
    assert!(
        interfaces[0]["url"]
            .as_str()
            .is_some_and(|url| url.starts_with(&server.base)),
        "the card must advertise PUBLIC_HOST: {card:#}"
    );
    assert!(
        !card["skills"].as_array().expect("skills").is_empty(),
        "a provisioned employee advertises what it can do: {card:#}"
    );

    // -- and the JSON-RPC binding next to it still needs one ----------------
    let (status, refused) = server.post(
        "/a2a/jsonrpc",
        None,
        r#"{"jsonrpc":"2.0","id":1,"method":"ListTasks"}"#,
    );
    assert_eq!(status, 401, "the A2A binding is open: {refused:#}");

    // -- the webhook door, with no API key at all ---------------------------
    //
    // An unregistered provider is a 404 rather than a 401: there is no secret
    // to check a signature against, and telling a prober which providers we
    // have integrated tells it which secrets are worth guessing.
    let (status, _) = server.post("/v1/webhooks/stripe", None, "{}");
    assert_eq!(status, 404, "an unregistered provider must not be an error");

    // A registered one with no signature is refused *by the webhook handler* —
    // `webhook_unverified`, not `unauthenticated`. That distinction is the
    // assertion: an `unauthenticated` here would mean the route had been
    // mounted behind the API-key layer, where no provider could ever reach it.
    let (status, problem) = server.post("/v1/webhooks/email", None, "{}");
    assert_eq!(status, 401);
    assert_eq!(
        problem["code"], "webhook_unverified",
        "the webhook route is behind the API key: {problem:#}"
    );

    // -- a signed delivery becomes work for the inbound loop ----------------
    //
    // The joint between the HTTP edge and the inbound pipeline: the route
    // stores bytes it cannot parse, and the outbox handler turns them into the
    // `inbound` notice the inbound loop knows how to claim. Nothing wrote one
    // before this was wired, so the loop had nothing to drain.
    let delivery = r#"{"type":"email.received","created_at":"2026-08-24T10:00:00Z","data":{"email_id":"email_e2e_1","from":"AP <ap@supplier.example>","to":["lena@agents.example.com"]}}"#;
    let timestamp = Utc::now().timestamp().to_string();
    let signature = agentos_app::inbound::sign_webhook(
        &agentos_app::inbound::Secret::new(WEBHOOK_SECRET),
        "msg_e2e_1",
        &timestamp,
        delivery.as_bytes(),
    );
    let (status, accepted) = server.curl(
        "POST",
        "/v1/webhooks/email",
        &[
            ("webhook-id", "msg_e2e_1".to_owned()),
            ("webhook-timestamp", timestamp),
            ("webhook-signature", signature),
        ],
        Some(delivery),
    );
    assert_eq!(status, 202, "a correctly signed delivery: {accepted:#}");

    // The outbox poller turns it into a notice within a poll or two.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let notices = server
            .count("SELECT count(*) FROM outbox_events WHERE aggregate_type = 'inbound'")
            .await;
        if notices > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the stored delivery never became an inbound notice: is a handler \
             registered for webhook.email.received?"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("--- the signed delivery became an inbound notice");

    // -- a spam complaint is acted on rather than dead-lettered -------------
    //
    // **The message it is most expensive to lose.** The route files every
    // verified delivery under `webhook.email.received` whatever the provider
    // sent; `InboundNotice::parse` refuses anything but `email.received`; and
    // the handler used to turn that refusal into an error. Three reasonable
    // links, and together they meant a `email.complained` was received,
    // verified, stored, retried eight times and thrown away — while the
    // permanent stream of failures buried every outage that was real.
    //
    // Note the direction: `to` is the person who complained and `from` is our
    // own employee address. A reader that took `from` would suppress the
    // tenant's own sender and end their outbound mail entirely.
    let complaint = r#"{"type":"email.complained","created_at":"2026-08-24T10:05:00Z","data":{"email_id":"email_e2e_2","from":"lena@agents.example.com","to":["AP@Supplier.Example"]}}"#;
    let timestamp = Utc::now().timestamp().to_string();
    let signature = agentos_app::inbound::sign_webhook(
        &agentos_app::inbound::Secret::new(WEBHOOK_SECRET),
        "msg_e2e_2",
        &timestamp,
        complaint.as_bytes(),
    );
    let (status, accepted) = server.curl(
        "POST",
        "/v1/webhooks/email",
        &[
            ("webhook-id", "msg_e2e_2".to_owned()),
            ("webhook-timestamp", timestamp),
            ("webhook-signature", signature),
        ],
        Some(complaint),
    );
    assert_eq!(status, 202, "a signed complaint: {accepted:#}");

    // The poller reads it and puts it on the trail. Normalised to the shape
    // `suppressions_address_normalised` demands, because that row is one call
    // away from being the suppression itself.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let recorded = server
            .count(
                "SELECT count(*) FROM audit_log WHERE action_kind = 'mail_refused' \
                   AND payload->>'reason' = 'complaint' \
                   AND payload->'addresses' @> '[\"ap@supplier.example\"]'::jsonb",
            )
            .await;
        if recorded > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a verified spam complaint left no trace: it is being retried and \
             dead-lettered exactly as it was before"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // And it was *completed*, not merely attempted. This is the half that says
    // the frontier moved: a published row with no failures behind it. A
    // complaint that is retried is a complaint on its way to the dead-letter
    // queue, and `last_error` is where the old behaviour would show up.
    let retried = server
        .count(
            "SELECT count(*) FROM outbox_events \
              WHERE payload->>'event_id' = 'msg_e2e_2' \
                AND (published_at IS NULL OR attempt_count > 1 OR last_error IS NOT NULL)",
        )
        .await;
    assert_eq!(
        retried, 0,
        "the stored complaint was retried or left unpublished; \
         `Err` in on_webhook is eight attempts and then a dead letter"
    );
    eprintln!("--- the spam complaint was recorded on the trail, not dead-lettered");

    // -- readiness refuses a deployment that would deny everything ----------
    //
    // Nothing has installed a platform policy ceiling, and the gate is
    // fail-closed: `policy::load` answers `NoPlatformLayer`, so every action
    // this deployment took would be denied. Everything else about this replica
    // is healthy — the pool answers, the outbox just drained a delivery — which
    // is the whole hazard. A probe that asked only those two would call this
    // ready and put it behind a load balancer to refuse real work.
    let (status, refused) = server.get("/readyz", None);
    assert_eq!(
        status, 503,
        "a deployment with no policy ceiling is not ready: {refused:#}"
    );
    assert_eq!(
        refused["code"], "no_platform_policy",
        "and it has to say which of the three checks failed: {refused:#}"
    );

    // Installed out of band, because that is the only way it arrives on a real
    // deployment: there is no route that writes `policy_layers` yet. The limits
    // are irrelevant here — `policy::install` maintains the platform row as a
    // side effect, and that row is the entire subject.
    agentos_store::policy::install(
        &Db::connect(&server.database_url).await.expect("connect"),
        server.tenant,
        agentos_store::policy::Scope::Tenant,
        &agentos_domain::policy::PolicyLimits::default(),
    )
    .await
    .expect("install a policy ceiling");

    // -- readiness reflects the outbox --------------------------------------
    let (status, ready) = server.get("/readyz", None);
    assert_eq!(status, 200, "the replica is not ready: {ready:#}");
    assert_eq!(ready["ready"], true);

    // -- and readiness says what is not real --------------------------------
    //
    // "The employee replied but the customer never got the mail" is debugged
    // against a running replica, long after the boot log that said so scrolled
    // away. This server runs entirely on mocks, so the probe has to name every
    // one of them rather than answer a bare `ready: true`.
    let mocked = ready["mock_adapters"]
        .as_array()
        .unwrap_or_else(|| panic!("/readyz must publish its adapter inventory: {ready:#}"));
    for adapter in ["email", "telephony", "browser"] {
        assert!(
            mocked.iter().any(|name| name == adapter),
            "{adapter} is a mock here and /readyz did not say so: {ready:#}"
        );
    }
    assert!(
        mocked
            .iter()
            .any(|name| name.as_str().is_some_and(|name| name.starts_with("llm"))),
        "the model is a mock here too: {ready:#}"
    );

    // -- SIGTERM stops the process, loops and all ---------------------------
    //
    // Each loop reporting that it drained is proof of both halves at once: it
    // was spawned, and the shared token reached it. A loop that is never
    // spawned cannot log, and one that ignores the token is aborted instead —
    // which logs the line asserted against below.
    let logs = server.shutdown();
    // The other half of the platform-policy contract, and it is only visible
    // from here: `/readyz` proved the deployment was held out of the load
    // balancer, this proves it also *said so* at boot, in a line an operator
    // reading a crash-loop log would find. Closed without loud is a replica
    // nobody knows how to fix; loud without closed is the outage.
    assert!(
        logs.contains("NO PLATFORM POLICY LAYER"),
        "booting with no policy ceiling has to be loud, not only unready:\n{logs}"
    );
    // The MCP binder joined this list when the operator half of MCP shipped,
    // and the initiative loop the moment after. Adding a loop and not adding
    // it here is the mistake this assertion exists to catch: a loop that is
    // cancelled but never joined lets the process exit while it is still
    // inside a transaction, and nothing else in the suite would notice. It has
    // now caught two additions in a row, which is the whole argument for
    // asserting the count rather than only the names.
    for loop_name in ["provisioning", "outbox", "inbound", "mcp", "initiative"] {
        assert!(
            logs.contains(&format!("\"loop_name\":\"{loop_name}\"")),
            "the {loop_name} loop never reported draining; was it spawned?\n{logs}"
        );
    }
    // `loop_name` is `drain_loops`' own field, so this counts joins rather
    // than also catching a loop's own "…loop drained" farewell line.
    assert_eq!(
        logs.matches("\"loop_name\":").count(),
        5,
        "every loop has to be joined, not all but one:\n{logs}"
    );
    assert!(
        !logs.contains("did not stop in time"),
        "a loop outlived the drain deadline:\n{logs}"
    );
}

// ---------------------------------------------------------------------------
// The life of a company
// ---------------------------------------------------------------------------

/// `docs/TEAMS.md` §7, as an operator draws it: fonction, responsable, mission.
///
/// The last field is `reports_to`, and `fondateur` is deliberately the **last
/// row**. `POST /v1/org` claims every seat is resolved before a single
/// reporting line is drawn, so row one may answer to a manager row seven
/// defines. A handler that resolved rows in order would satisfy every other
/// assertion in this test and fail on the first one.
const CHART: [(&str, &str, &str, &str, &str, &str); 7] = [
    (
        "produit-et-technologie",
        "Produit et technologie",
        "Produit, code, infrastructure, sécurité",
        "cto",
        "CTO/CPO",
        "fondateur",
    ),
    (
        "growth",
        "Growth",
        "Acquisition, contenu, SEO, publicité",
        "head-of-growth",
        "Head of Growth",
        "fondateur",
    ),
    (
        "commercial",
        "Commercial",
        "Prospection, démos, contrats",
        "head-of-sales",
        "Head of Sales",
        "fondateur",
    ),
    (
        "clients",
        "Clients",
        "Support, activation, fidélisation",
        "customer-success",
        "Customer Success",
        "fondateur",
    ),
    (
        "operations",
        "Opérations",
        "Automatisation, procédures, partenaires",
        "coo",
        "COO",
        "fondateur",
    ),
    (
        "finance-et-juridique",
        "Finance et juridique",
        "Comptabilité, trésorerie, conformité",
        "cfo",
        "CFO externalisé",
        "fondateur",
    ),
    (
        "direction",
        "Direction",
        "Vision, stratégie, priorités",
        "fondateur",
        "CEO / fondateur",
        "",
    ),
];

/// A company, from the table an operator draws to the euro that does not get
/// spent.
///
/// # What this proves that the suite does not
///
/// Every unit in this workspace is tested and the whole of it is green, and
/// every bug found in it over four waves has been at a seam: four routers
/// written and never merged, a gate that never read stored policy, `spend_caps`
/// with no writer, a purchasing vertical with no caller, and — three waves
/// running — an internal channel that was complete, tested and *unreachable*
/// because two role packs omitted one enum variant. None of those is expressible
/// as a unit test failure. All of them are expressible as "the company does not
/// work", which is what this drives:
///
/// 1. an org chart is drawn and the reporting lines it asked for exist;
/// 2. before a ceiling exists the deployment refuses to be ready **and** refuses
///    the action — fail-closed, proven rather than described — and installing
///    one the way an operator does turns both around;
/// 3. the CEO orders its Head of Growth across two teams, and a peer is refused;
/// 4. that order wakes a turn, and the request the server builds for the model
///    carries *its* colleagues and *its* role's tools, not the company's — and
///    the turn answers with a tool call that comes back down the line;
/// 5. money is allowed, escalated and denied at the ceiling's three bands;
/// 6. the audit trail says all of that happened and nothing else did.
///
/// # Where the assertions are made
///
/// Steps 1, 2 and 5's configuration are entirely over the wire, and step 4 is
/// asserted on bytes the server wrote to a subprocess. Steps 3 and 5's rulings
/// hold the gate's own `Authorized<A>`, because **there is no HTTP door to
/// either** and that is a fact about this architecture rather than a shortcut
/// here — `docs/TEAMS.md` says so of delegation in as many words, and no route
/// in `app()` proposes a payment. What makes them more than unit tests is that
/// every input is state the *server* wrote: the org chart came out of
/// `POST /v1/org`, the ceiling out of the operator subcommand, the budget out of
/// `PUT …/budget`, the caps out of `PUT …/spend-caps`, the charter out of
/// `PUT …/initiative`. The gate reads rows this test never wrote.
///
/// # What it cannot reach, named rather than skipped
///
/// * **A payment never reaches a provider.** `mocks::ports_for` binds
///   `payments` to `NotConfigured`, which refuses by design — this build has no
///   payment adapter. So the strongest thing available past the ruling is that
///   the ledger *gives the money back*, which is asserted.
/// * **A webhook cannot start a turn on a deployment running mocks.** The
///   route stores a notice, the inbound loop then asks the provider for the
///   body, and `MockEmailProvider`'s inbox is filled by `seed_inbound` — an
///   in-process call with no HTTP or environment seam. The loop retries
///   `not_ready` until the attempt budget runs out. The other test in this file
///   asserts as far as the notice, which is as far as that path goes from
///   outside; everything past it is unreachable without a real email provider.
/// * **The initiative loop's own turn is never observed.** `Cadence::every`
///   floors a cadence at five minutes, so reaching it means sleeping past it or
///   moving `employee_initiative.next_at` by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_company_is_drawn_takes_a_turn_talks_to_itself_and_meets_the_gate() {
    use std::sync::Arc;

    use agentos_app::effects::{
        EffectError, Effects, InternalNote, InternalSend, PaymentCreate, PaymentInstruction,
    };
    use agentos_app::gate::{Denied, PolicyGate, Principal};
    use agentos_app::inbound::Errand;
    use agentos_app::rolepack::CountryCode;
    use agentos_app::rolepack_service;
    use agentos_app::vertical::{self, Charter, DelegationError};
    use agentos_domain::ids::{EmployeeId, Slug};
    use agentos_domain::money::{Currency, Money};
    use serde_json::json;

    let model = FakeModel::new();
    // What the Head of Growth does with the turn a stranger's email starts: ask
    // its manager. A *question* rides the reporting line in either direction,
    // which is the errand a report is allowed to send upward — and this is the
    // only assertion in the file that the internal channel is reachable from
    // inside a real turn rather than from a test holding a token.
    model.answers(
        "head-of-growth",
        r#"{"tool": "message_colleague", "input": {"to": "fondateur", "kind": "question", "body": "An ad network wrote in about our spend. Do we answer them?"}}"#,
    );

    let Some(server) = Server::start_with(&[
        // Not `mock`: the in-process `ScriptedLlm` records every request it is
        // handed and none of that is reachable from out here. `cli` spawns a
        // program off PATH, and `FakeModel` owns the PATH.
        ("AGENTOS_LLM", "cli".to_owned()),
        ("PATH", model.path()),
    ])
    .await
    else {
        return;
    };

    // -- 1. a company is drawn ----------------------------------------------
    let rows: Vec<Value> = CHART
        .iter()
        .map(|(team, name, mission, head, title, reports_to)| {
            let mut row = json!({
                "team": team, "name": name, "mission": mission,
                "head": head, "title": title,
            });
            if !reports_to.is_empty() {
                row["reports_to"] = json!(reports_to);
            }
            row
        })
        .collect();
    let document = json!({ "domain": "agents.example.com", "rows": rows }).to_string();

    let (status, applied) = server.post("/v1/org", Some(SECRET), &document);
    assert_eq!(
        status, 202,
        "a chart that hires is accepted, not created: {applied:#}"
    );
    let chart = applied["chart"].as_array().expect("a chart").clone();
    assert_eq!(chart.len(), CHART.len(), "a seat went missing: {applied:#}");

    let seat = |head: &str| -> Value {
        chart
            .iter()
            .find(|seat| seat["head"] == head)
            .unwrap_or_else(|| panic!("no seat for {head}: {applied:#}"))
            .clone()
    };
    let employee_of = |head: &str| -> EmployeeId {
        EmployeeId::from_uuid(
            seat(head)["employee_id"]
                .as_str()
                .expect("an employee id")
                .parse()
                .expect("a uuid"),
        )
    };

    for (team, name, mission, head, title, _) in CHART {
        let seat = seat(head);
        assert_eq!(
            seat["team"], team,
            "{head} sits on the wrong team: {seat:#}"
        );
        assert_eq!(seat["name"], name, "{head}: {seat:#}");
        assert_eq!(
            seat["mission"], mission,
            "the mission is a string on the team and it did not survive: {seat:#}"
        );
        assert_eq!(seat["title"], title, "{head}: {seat:#}");
        assert_eq!(
            seat["hired"], true,
            "nobody had been hired before this call: {seat:#}"
        );
    }

    // The line, and this is the assertion that is not a tautology: `reports_to`
    // went in as the slug `"fondateur"` and comes back as the employee id the
    // *server* minted for it, which this test could not have known to send.
    let ceo_id = seat("fondateur")["employee_id"].clone();
    assert_eq!(
        seat("fondateur")["reports_to"],
        Value::Null,
        "the CEO answers to nobody"
    );
    for (.., head, _, reports_to) in CHART {
        if reports_to.is_empty() {
            continue;
        }
        assert_eq!(
            seat(head)["reports_to"],
            ceo_id,
            "{head} was pointed at a manager defined *after* it in the document \
             and the line did not land"
        );
    }

    // Read back through a different handler, off the rows rather than out of
    // the transaction that wrote them.
    let (status, teams) = server.get("/v1/teams", Some(SECRET));
    assert_eq!(status, 200, "the roster is unreadable: {teams:#}");
    let listed = teams["teams"].as_array().expect("teams");
    assert_eq!(listed.len(), CHART.len(), "{teams:#}");
    for (team, name, mission, ..) in CHART {
        let row = listed
            .iter()
            .find(|row| row["slug"] == team)
            .unwrap_or_else(|| panic!("{team} is not in the roster: {teams:#}"));
        assert_eq!(row["name"], name, "{teams:#}");
        assert_eq!(
            row["mission"], mission,
            "a mission is re-parsed on every read and this one did not survive it: {teams:#}"
        );
    }

    // A document you keep in git, edit and re-apply. The second apply hires
    // nobody, which is the difference between idempotent and merely repeatable.
    let (status, again) = server.post("/v1/org", Some(SECRET), &document);
    assert_eq!(status, 200, "re-applying hired somebody: {again:#}");
    for seat in again["chart"].as_array().expect("a chart") {
        assert_eq!(
            seat["hired"], false,
            "the same document hired a second employee: {seat:#}"
        );
    }

    // The gate refuses every action for an employee that is not `active`, so
    // nothing below means anything until the loops have finished with the four
    // seats this test uses.
    for head in ["fondateur", "cto", "head-of-growth", "cfo"] {
        let id = seat(head)["employee_id"]
            .as_str()
            .expect("an id")
            .to_owned();
        server.await_provisioned(&id);
        server.await_active(&id);
    }

    // -- 2. the ceiling exists, or nothing works ----------------------------
    let db = Db::connect(&server.database_url).await.expect("connect");
    let gate = PolicyGate::new(db.clone());
    let cfo = Principal::employee(server.tenant, employee_of("cfo"));
    let usd = |minor: u64| Money::new(minor, Currency::Usd).expect("non-zero");
    let payment = |minor: u64| PaymentCreate { amount: usd(minor) };

    let (status, refused) = server.get("/readyz", None);
    assert_eq!(
        status, 503,
        "a deployment with no ceiling denies every action and must not look \
         healthy: {refused:#}"
    );
    assert_eq!(refused["code"], "no_platform_policy", "{refused:#}");

    // The other half of fail-closed, and the half a probe cannot show: the
    // action itself. `$50` is under every band the default ceiling has — it is
    // refused because there is no ceiling at all, not because of a number in it.
    let denied = gate
        .authorize(&cfo, payment(5_000))
        .await
        .expect_err("with no platform layer the gate must refuse");
    assert_eq!(
        denied.code(),
        "no_platform_policy",
        "the gate is not fail-closed: {denied}"
    );

    let report = server.install_ceiling();
    assert!(
        report.contains("installed platform ceiling"),
        "the operator command did not install one:\n{report}"
    );

    let (status, ready) = server.get("/readyz", None);
    assert_eq!(
        status, 200,
        "the ceiling is in and the replica still will not serve: {ready:#}"
    );

    // The same call, the same amount, a different refusal. `no_spend_policy` is
    // the ledger saying this employee has no caps yet — which is proof the
    // ceiling took effect without a restart, because that answer is only
    // reachable *past* the platform layer.
    let denied = gate
        .authorize(&cfo, payment(5_000))
        .await
        .expect_err("no spend caps have been written yet");
    assert_eq!(
        denied.code(),
        "no_spend_policy",
        "the gate is still stuck on the platform layer: {denied}"
    );

    // -- 3. two employees talk along the line, and the turn that starts ------
    //
    // These two steps are one section because in this deployment they are one
    // event: **there is no way to start a turn from outside the process except
    // by being a colleague.** The three doors are all shut from out here.
    //
    // * The **initiative loop** is the trusted turn, and `Cadence::every` floors
    //   a cadence at five minutes, so reaching it means sleeping past that or
    //   reaching into `employee_initiative.next_at` — a test moving the clock on
    //   the thing it is testing.
    // * The **email webhook** lands a notice and the inbound loop then asks the
    //   provider for the body. On a deployment running mocks the provider is
    //   `MockEmailProvider`, whose inbox is filled by `seed_inbound` — an
    //   in-process call with no HTTP or environment seam — so the loop retries
    //   `not_ready` forever and no turn is ever assembled. That is a real hole
    //   in what an end-to-end test can reach and it is named here rather than
    //   worked around.
    // * **A2A** wants a signed peer request, which is a second deployment.
    //
    // So the CEO does it, which is the case worth proving anyway.
    let ports = Arc::new(agentos_app::mocks::ports());
    let ceo = Principal::employee(server.tenant, employee_of("fondateur"));
    let cto = Principal::employee(server.tenant, employee_of("cto"));
    let head_of_growth = Slug::parse("head-of-growth").expect("a slug");
    let order = InternalNote {
        errand: Errand::Order,
        body: "Ship the Q4 landing page this week.".to_owned(),
        thread: None,
    };

    // The charter is what gives the employee a role pack, and therefore a
    // briefing and a tool floor. The cadence that comes with it is set past the
    // end of this test on purpose: what is under test is the shape of the turn,
    // not the clock that could also have started one.
    let growth_id = seat("head-of-growth")["employee_id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (status, charter) = server.put(
        &format!("/v1/employees/{growth_id}/initiative"),
        r#"{"interval_secs":86400,"objective":{"role":"growth",
            "topic":"visa data for travel agencies",
            "market":"FR",
            "measure":"signups from organic search"}}"#,
    );
    assert_eq!(status, 200, "the charter did not take: {charter:#}");

    // Direction -> Growth. **Two different teams**, which is the case that was
    // broken three waves running: an order rides the reporting line, and the
    // line crosses teams on purpose — a head answers to a CEO who sits
    // elsewhere. A rule written as "the same team" refuses exactly this.
    let token = gate
        .authorize(
            &ceo,
            InternalSend {
                to: head_of_growth.clone(),
            },
        )
        .await
        .expect("the internal channel is in the ceiling's allowed channels");
    Effects::new(db.clone(), ports.clone(), ceo.clone())
        .send_internal(token, &order)
        .await
        .expect("a CEO may order the head that reports to it, across teams");

    // -- 4. the turn is shaped by its job -----------------------------------
    //
    // The order above spent one of the recipient's daily turns and enqueued the
    // wake. Nothing else runs it: the server's own outbox loop picks the event
    // up, assembles the turn, and calls the model — which is a shell script
    // this test owns, so what lands in the capture directory is the request the
    // running server built.
    let prompt = model.await_prompt("You are head-of-growth,", Duration::from_secs(90));
    assert!(
        prompt.contains("You are head-of-growth, an AI employee at agents.example.com."),
        "the identity line is not this employee's:\n{prompt}"
    );

    // **Its own colleagues, not the company's.** The Head of Growth is alone on
    // Growth and answers to the CEO, so its roster is exactly one name. The
    // other five heads are real, active, in the same tenant, and unreachable —
    // and a roster built from "every employee" rather than from
    // `team_memberships.reports_to` would list all six.
    //
    // On the entries and not on the section, and equality and not `contains`.
    // The first draft of this was `!roster.contains("cto")`, which went red
    // against a correct roster because the section's own prose says "there is no
    // directory to search" — `cto` is a substring of `directory`. An assertion
    // that reads a name out of an English sentence is one that passes or fails
    // on the wording, so this reads the list.
    let listed: Vec<&str> = prompt
        .split_once("# Colleagues you can reach")
        .expect("a turn offered `message_colleague` is told who it can reach")
        .1
        .lines()
        .take_while(|line| !line.starts_with("## "))
        .filter(|line| line.starts_with("- "))
        .collect();
    assert_eq!(
        listed,
        [
            "- fondateur — your manager — you answer to them; ask them a question, never give them an order"
        ],
        "the roster is not this employee's line: the org chart drew one manager \
         and five strangers, and the prompt has to carry the manager and none of \
         the strangers"
    );

    // **Its role's floor and its deployment's policy, not the catalogue.** The
    // catalogue is longer than what this turn is offered. None of the three
    // absences named below is the taint filter: the order arrived as an
    // `Authorized<InternalSend>` rather than an `Untrusted<…>`, so the turn is
    // **trusted** and `turn::visible` is not taking anything away.
    //
    // Two of them are the floor. `pay` is missing because the Growth pack does
    // not propose `PaymentCreate` and `send_email` because it does not propose
    // `EmailSend` — which is the whole of what a role pack is.
    //
    // The third is the **policy**, and it is the one this test started reporting
    // when `tools_for` was given one. Growth *does* propose `McpCall`, and this
    // deployment installed `store::policy::default_ceiling` and nothing else —
    // which grants no MCP tool, exactly as every fresh install does until an
    // operator binds a server and writes a layer. So the gate would refuse every
    // `call_mcp_tool` this employee could make, with `deny/no_rule`, and the
    // schema is not sent. Before the policy filter existed it was sent anyway:
    // one tool, no inventory, two free strings to guess with, and a refusal that
    // cannot say whether the name was wrong or the tool was out of reach. This
    // assertion is the end-to-end proof, on a real server against a real
    // database, that the guess is no longer on offer.
    let (_, tools) = prompt
        .split_once("\n## tools\n")
        .expect("a request carrying tool schemas renders the contract");
    for offered in ["message_colleague", "brief_direct_reports"] {
        assert!(
            tools.contains(&format!("\n- name: {offered}\n")),
            "the Growth pack proposes {offered} and the turn was not offered it:\n{tools}"
        );
    }
    for withheld in ["send_email", "pay"] {
        assert!(
            !tools.contains(&format!("\n- name: {withheld}\n")),
            "{withheld} is not in this role's floor and the turn was offered it \
             anyway — the catalogue is going out whole:\n{tools}"
        );
    }
    assert!(
        !tools.contains("\n- name: call_mcp_tool\n"),
        "this deployment grants no MCP tool, so every `call_mcp_tool` is denied \
         `no_rule` — offering the schema spends a turn to learn nothing:\n{tools}"
    );

    // And the turn answered with a tool call, so the whole inward chain ran
    // inside the binary: model -> gate -> `Effects::send_internal` ->
    // `may_message` -> a row for the CEO. A question, not an order, because a
    // report may ask upward and may not tell upward.
    let asked = format!(
        "SELECT count(*) FROM messages \
          WHERE channel = 'internal' AND internal_kind = 'question' \
            AND sender = 'head-of-growth' AND employee_id = '{}'",
        seat("fondateur")["employee_id"]
            .as_str()
            .expect("an employee id")
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while server.count(&asked).await == 0 {
        assert!(
            Instant::now() < deadline,
            "the model asked for `message_colleague` and no question ever reached \
             the CEO: the tool, the gate ruling or the write is broken"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // A peer. The CTO and the Head of Growth both answer to the CEO and neither
    // answers to the other, so there is no line and an order has nothing to
    // ride. Note where the refusal comes from: the **gate allows it**, because
    // an `Action` carries a slug and no org chart, and the executor refuses at
    // write time. That is why step 6 finds `internal_send` allows here and no
    // `internal_send` deny at all.
    let token = gate
        .authorize(
            &cto,
            InternalSend {
                to: head_of_growth.clone(),
            },
        )
        .await
        .expect("the gate rules on the channel, not on the org chart");
    let refused = Effects::new(db.clone(), ports.clone(), cto.clone())
        .send_internal(token, &order)
        .await
        .expect_err("a peer may not order a peer");
    assert!(
        matches!(refused, EffectError::Refused("unreachable_colleague")),
        "a peer's order was delivered, or refused for the wrong reason: {refused}"
    );

    // The other half of seniority, and the half the gate *does* rule on:
    // setting a subordinate's standing objective. Done after the turn above,
    // deliberately — it overwrites the charter that turn was shaped by.
    let objective = Charter::Growth {
        objective: rolepack_service::Growth {
            topic: "visa data for travel agencies".to_owned(),
            market: Some(CountryCode::parse("FR").expect("a country")),
            measure: Some("signups from organic search".to_owned()),
        },
    };
    vertical::delegate(
        &gate,
        &db,
        &ceo,
        employee_of("head-of-growth"),
        &objective,
        Utc::now(),
    )
    .await
    .expect("a head may set the charter of the seat that reports to it");

    let refused = vertical::delegate(
        &gate,
        &db,
        &cto,
        employee_of("head-of-growth"),
        &objective,
        Utc::now(),
    )
    .await
    .expect_err("a peer may not re-task a peer");
    assert!(
        matches!(&refused, DelegationError::Refused(denied)
            if denied.code() == "outside_chain_of_command"),
        "the gate did not read the reporting line: {refused}"
    );

    // -- 5. money crosses the gate, and is stopped --------------------------
    //
    // Both writes are HTTP, and both used to have no writer at all: the team's
    // budget and the employee's caps are the two ledgers `org::reserve` takes
    // in that order, and a payment that clears the policy still needs both.
    let finance = seat("cfo")["team_id"]
        .as_str()
        .expect("a team id")
        .to_owned();
    let cfo_id = seat("cfo")["employee_id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (status, budget) = server.put(
        &format!("/v1/teams/{finance}/budget"),
        r#"{"daily_total":{"minor":200000,"currency":"USD"}}"#,
    );
    assert_eq!(status, 200, "the team has no budget: {budget:#}");
    let (status, caps) = server.put(
        &format!("/v1/employees/{cfo_id}/spend-caps"),
        r#"{"daily_total":{"minor":200000,"currency":"USD"},
            "per_transaction":{"minor":50000,"currency":"USD"},
            "daily_transactions":10}"#,
    );
    assert_eq!(status, 200, "the employee has no caps: {caps:#}");

    // Band one: $50, under the default ceiling's $100 approval threshold.
    let token = gate
        .authorize(&cfo, payment(5_000))
        .await
        .expect("$50 is under every band");
    assert!(
        token.reservation().is_some(),
        "an allowed payment holds the day's headroom until it settles"
    );
    let attempted = Effects::new(db.clone(), ports.clone(), cfo.clone())
        .pay(
            token,
            &PaymentInstruction {
                payee: "Cabinet Dubois".to_owned(),
                memo: "August bookkeeping".to_owned(),
            },
        )
        .await;
    // This build has no payment adapter — `mocks::ports_for` binds `payments`
    // to a stub that refuses rather than a fake that pretends. So the furthest
    // this can go is the ruling and what the ledger does afterwards, and what it
    // does is the assertion worth having: a payment that failed returns the
    // money it was holding.
    assert!(
        matches!(attempted, Err(EffectError::Provider(_))),
        "a payment reached a provider in a build that has none: {attempted:?}"
    );
    let held = "SELECT coalesce(sum(reserved_minor), 0)::bigint FROM spend_buckets \
                 WHERE currency = 'USD'";
    assert_eq!(
        server.count(held).await,
        0,
        "the provider refused and the reservation was never released — the day's \
         budget is gone for a payment that did not happen"
    );

    // Band two: $250, over the threshold and under the cap. Not a refusal — a
    // question, filed for a human.
    let escalated = gate
        .authorize(&cfo, payment(25_000))
        .await
        .expect_err("$250 is above the ceiling's $100 approval threshold");
    let Denied::PendingApproval(approval) = escalated else {
        panic!("a payment over the threshold must be escalated, not {escalated}");
    };
    let (status, queue) = server.get("/v1/approvals", Some(SECRET));
    assert_eq!(status, 200, "{queue:#}");
    assert!(
        queue["approvals"]
            .as_array()
            .expect("approvals")
            .iter()
            .any(|row| row["id"] == approval.as_uuid().to_string() && row["state"] == "pending"),
        "the gate filed an approval nobody can see: {queue:#}"
    );

    // Band three: $600, over the ceiling's $500 per-transaction cap. No amount
    // of approving makes this one happen.
    let denied = gate
        .authorize(&cfo, payment(60_000))
        .await
        .expect_err("$600 is above the ceiling's $500 per-transaction cap");
    assert_eq!(
        denied.code(),
        "per_transaction_limit",
        "the cap did not fire, or fired for the wrong reason: {denied}"
    );

    // And the human answers, over HTTP, on a *second* credential — the role a
    // key holds is its label, and `may_decide` refuses four eyes that are one
    // pair. This is the only path in the binary that mints a payment token from
    // a request.
    let (status, redeemed) = server.curl(
        "POST",
        &format!("/v1/approvals/{}/approve", approval.as_uuid()),
        &[("Authorization", format!("Bearer {APPROVER_SECRET}"))],
        Some(r#"{"action":{"action":"payment_create","amount":{"minor":25000,"currency":"USD"}}}"#),
    );
    assert_eq!(status, 200, "the approval could not be spent: {redeemed:#}");
    assert_eq!(redeemed["state"], "redeemed", "{redeemed:#}");
    assert_eq!(
        server.count(held).await,
        25_000,
        "redeeming an approval must take the day's headroom, or an approved \
         payment is one the budget never saw"
    );

    // -- 6. the audit trail is complete -------------------------------------
    //
    // Every ruling above, and nothing else. The absences are the half that
    // matters: an audit trail that grows a row for something that did not
    // happen is worse than one that misses a row, because it is the one an
    // incident is reconstructed from.
    let trail = server.audit_summary().await;
    let happened = |line: &str| trail.iter().any(|row| row.starts_with(line));
    for ruling in [
        // Step 2, both sides of the ceiling.
        "payment_create/no_platform_policy",
        "payment_create/deny/no_spend_policy",
        // Step 5, the three bands, plus the redemption.
        "payment_create/allow",
        "payment_create/require_approval/payment_above_threshold",
        "payment_create/deny/per_transaction_limit",
        // Step 4, both directions of it.
        "internal_send/allow",
        "charter_set/allow",
        "charter_set/deny/outside_chain_of_command",
        // The operator's own writes, which carry no ruling at all.
        "employee_created/-",
        "policy_changed/-",
        // The stranger's email, and the colleague's question after it.
        "message_received/-",
    ] {
        assert!(happened(ruling), "{ruling} is not in the trail: {trail:#?}");
    }
    for never in [
        "contract_sign",
        "data_delete",
        "credential_change",
        "sms_send",
        "whatsapp_send",
        "call_place",
        "browser_write",
        "file_upload",
        "a2a_send",
    ] {
        assert!(
            !happened(never),
            "{never} never happened and the trail says it did: {trail:#?}"
        );
    }
    // The peer's order was allowed by the gate and refused by the org chart, so
    // there is no `internal_send` deny — and the refusal is *only* legible as
    // the `provider_call_attempted` row `Effects` writes for the failed effect.
    // Asserted so that a future change which moves the org-chart check into the
    // gate has to come and update this sentence.
    assert!(
        !happened("internal_send/deny"),
        "the org chart's refusal became a gate denial; the comment above is now \
         wrong: {trail:#?}"
    );

    server.shutdown();
}
