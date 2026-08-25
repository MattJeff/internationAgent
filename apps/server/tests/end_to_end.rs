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

use std::collections::HashMap;
use std::fs::File;
use std::net::TcpListener;
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

/// The signing secret this deployment registers for the `email` provider.
const WEBHOOK_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

/// How long the provisioning loop gets to converge eleven steps against mock
/// adapters. It normally takes well under a second; this is the "it is wedged"
/// deadline, not the expected one.
const CONVERGE_DEADLINE: Duration = Duration::from_secs(30);

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
}

impl Server {
    /// `None` when there is no database — these assertions are about rows and
    /// sockets, and a mock of either would be a mock of the test.
    async fn start() -> Option<Self> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the end-to-end run needs a real Postgres");
            return None;
        };

        // A database of our own, migrated by the server itself on boot.
        let (base_url, _) = url.rsplit_once('/').expect("DATABASE_URL has a path");
        let admin_url = format!("{base_url}/postgres");
        let database = format!("e2e_{}", Uuid::now_v7().simple());
        let admin = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect to postgres");
        // `CREATE DATABASE` takes no bind parameters, so the name is
        // interpolated — and it is `e2e_` plus the hex of a UUID this function
        // just minted, which is the audit `AssertSqlSafe` asks for.
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

        let env: HashMap<&str, String> = HashMap::from([
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
                format!("ops:{}:{SECRET}", tenant.as_uuid()),
            ),
            (
                "AGENTOS_WEBHOOK_SECRETS",
                format!("email:{}:{WEBHOOK_SECRET}", tenant.as_uuid()),
            ),
            ("RUST_LOG", "info,agentos_server=debug".to_owned()),
        ]);

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
        };
        server.wait_until_live();
        Some(server)
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

        logs
    }

    /// Count rows in the server's own database. The assertions the HTTP surface
    /// cannot make: what the loops wrote after answering.
    async fn count(&self, sql: &'static str) -> i64 {
        let pool = sqlx::PgPool::connect(&self.database_url)
            .await
            .expect("connect to the test database");
        let n: i64 = sqlx::query_scalar(sql)
            .fetch_one(&pool)
            .await
            .expect("count");
        pool.close().await;
        n
    }
}

/// The `Authorization` header, or none at all.
fn bearer(secret: Option<&str>) -> Vec<(&'static str, String)> {
    secret
        .map(|secret| vec![("Authorization", format!("Bearer {secret}"))])
        .unwrap_or_default()
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
