//! `docs/ORIZN.md`, executed.
//!
//! The runbook stands a company up in six steps against a real database. This
//! file runs all six — the real binary, the real migrations, the real
//! `policy install`, the real `policy new-tenant`, the real `POST /v1/org` —
//! and then asserts that the company on the other side is the one the document
//! describes.
//!
//! **There is no `psql` left in it, and that is recent.** Three of these steps
//! used to be hand-written SQL, because no route and no subcommand wrote a
//! tenant row, a tenant/role/employee `policy_layers` row, or the active
//! `policy_versions` row the role layers hang off. All three are commands now,
//! and this file runs them as the operator does.
//!
//! The documents are the company, and this test reads the *same documents* the
//! operator does. Edit `docs/orizn-org.json` and this test changes with it;
//! edit a file in `docs/orizn-roles/` and this test **fails**, because the
//! numbers are the one thing it keeps its own copy of. That asymmetry is
//! deliberate: the org chart is a document whose content is its own
//! specification, and the policy layer is a set of decisions somebody argued
//! for in prose. A test that re-derived the limits from the documents would
//! agree with any documents at all.
//!
//! # The two claims that are not "the rows exist"
//!
//! **The ceiling is load-bearing.** `/readyz` is asserted red *before*
//! `policy install` and green after. A deployment with no platform layer has no
//! ceiling and the gate refuses everything; that is the safe direction and it
//! is the first thing an operator sees.
//!
//! **Nothing this company writes tries to widen.** For every role, the raw
//! `policy_layers` row is compared against what `store::policy::load` returns
//! after intersecting it with the ceiling. They must be equal. A layer that
//! named a number *bigger* than
//! the ceiling would still be safe — the loader takes the minimum — but the row
//! an operator reads would no longer be the row the gate rules with, and the
//! next person to open `psql` would believe a limit that does not exist.
//!
//! # What this test does not run
//!
//! No turn, no model call, no payment. `AGENTOS_LLM=mock` and the mock adapters
//! are on: every claim here is about configuration, and the vertical that
//! exercises the gate end to end is `sourcing_e2e.rs`. What this file owns is
//! narrower and nothing else covers it — that the document, the SQL and the
//! running company agree.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agentos_domain::action::{Channel, Domain};
use agentos_domain::ids::{EmployeeId, TenantId};
use agentos_domain::money::Currency;
use agentos_domain::policy::PolicyLimits;
use agentos_store::db::Db;
use agentos_store::policy;
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

/// Long enough for `ApiKeys::MIN_SECRET_LEN`.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// The provisioning loop's "it is wedged" deadline, not its expected one.
const CONVERGE_DEADLINE: Duration = Duration::from_secs(60);

/// `docs/`, from `apps/server/`.
fn docs(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(file)
}

// ---------------------------------------------------------------------------
// The numbers, as `docs/ORIZN.md` argues them
// ---------------------------------------------------------------------------

/// One row of the policy table in `docs/ORIZN.md`, and the whole point of this
/// file. Changing a document in `docs/orizn-roles/` without changing the
/// argument in `docs/ORIZN.md` breaks here.
///
/// The order is the order the layers are installed in, so `role` is also the
/// basename of the file each one comes from.
struct Expected {
    /// The team slug, which is also the `role_name` and also the role pack's
    /// name. See the document on why those three are one string.
    role: &'static str,
    /// The employee slug seated in it.
    head: &'static str,
    turns: u32,
    contacts: u32,
    channels: &'static [Channel],
    domains: &'static [&'static str],
    /// `(per transaction, per day, approval above)`, in USD minor units.
    /// `None` is a layer that permits no spending at all.
    spend: Option<(u64, u64, u64)>,
}

const EXPECTED: &[Expected] = &[
    // A chair, not an employee: zero turns, no channel, no domain, no spend.
    // Without this row the seat at the root of the chart would inherit the
    // ceiling, because an absent layer inherits the one above it.
    //
    // **The zero is load-bearing in a second way now.** It used to also mean
    // "unreachable": every escalation to this seat passed the gate and was then
    // refused by `inbound::send`'s reservation with `no_turn_budget`, which
    // severed the chain of command at its root. `send` asks whether a turn can
    // ever run for a recipient before it charges one, so a message to this seat
    // lands on a desk without waking anybody — no reservation, no
    // `agent.turn.requested`. Raising this number to make escalation work would
    // charter the one seat `docs/orizn-roles/direction.json` exists to keep
    // empty, and would move the monthly figure the test below derives. It is
    // still zero, and `docs/ORIZN.md` argues why under "The zero is still zero".
    Expected {
        role: "direction",
        head: "founder",
        turns: 0,
        contacts: 0,
        channels: &[],
        domains: &[],
        spend: None,
    },
    // Cold outreach stays off. `contacts: 0` is the assertion that this
    // document does not turn prospecting on the moment it is applied.
    Expected {
        role: "sales-development",
        head: "sdr",
        turns: 30,
        contacts: 0,
        channels: &[Channel::Email, Channel::Internal],
        domains: &["orizn.app"],
        spend: None,
    },
    // Not zero contacts, and the difference is the reason: standing is computed
    // from this employee's own outbound trail, so the first reply to somebody
    // who wrote to us first is a "new contact" to the gate.
    Expected {
        role: "customer-success",
        head: "support",
        turns: 20,
        contacts: 20,
        channels: &[Channel::Email, Channel::Internal],
        domains: &["orizn.app"],
        spend: None,
    },
    // Internal only: no outward channel exists, so the zero means what it says.
    Expected {
        role: "growth",
        head: "acquisition",
        turns: 10,
        contacts: 0,
        channels: &[Channel::Internal],
        domains: &["orizn.app"],
        spend: None,
    },
    // The only function that may propose money, and the only row with spend
    // columns. $1 approval threshold: every payment goes to a person.
    Expected {
        role: "finance",
        head: "books",
        turns: 6,
        contacts: 5,
        channels: &[Channel::Email, Channel::Internal],
        domains: &[],
        spend: Some((50_000, 100_000, 100)),
    },
];

/// What `docs/ORIZN.md` promises the whole company costs, and where it comes
/// from. Asserted rather than printed, because a monthly figure nobody checks
/// is the number an operator budgets on and then over-runs.
const TURNS_PER_DAY: u32 = 66;
/// `crates/eval/src/scoping.rs`, "one turn's context at 2 / 10 / 50 staff",
/// at ten staff. A ±20% estimate with no tokenizer behind it — which is why
/// this is a floor and the document says so.
const INPUT_TOKENS_PER_CALL: u32 = 4_639;

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// A pool for the handful of statements this file runs outside `Db`.
///
/// Two connections, not sixteen: several test binaries and their servers share
/// one Postgres here, and `max_connections` is finite.
async fn small_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("connect to postgres")
}

/// The running server, its database, and Orizn's tenant id.
struct Orizn {
    child: Child,
    base: String,
    admin_url: String,
    database: String,
    log: PathBuf,
    database_url: String,
    tenant: TenantId,
}

impl Orizn {
    /// Step 1 of the runbook: boot the server once, so the migrations run.
    ///
    /// `None` when there is no database. Every claim in this file is a claim
    /// about rows, and a mock of the database would be a mock of the test.
    async fn boot() -> Option<Self> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; standing a company up needs a real Postgres");
            return None;
        };

        let (base_url, _) = url.rsplit_once('/').expect("DATABASE_URL has a path");
        let admin_url = format!("{base_url}/postgres");
        let database = common::private_name(&url, "orizn");
        let admin = small_pool(&admin_url).await;
        // Interpolated because CREATE DATABASE takes no bind parameters, and
        // the name is `common::private_name`'s — this run's own database name
        // and two integers, which is also what gets it collected on a ^C.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await
            .expect("create the test database");
        admin.close().await;

        let database_url = format!("{base_url}/{database}");
        let tenant = TenantId::new_v7(Utc::now());
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("a free port")
            .local_addr()
            .expect("addr")
            .port();

        let env: HashMap<&str, String> = HashMap::from([
            ("APP_BIND", format!("127.0.0.1:{port}")),
            ("PUBLIC_HOST", format!("http://127.0.0.1:{port}")),
            // The document's own domain, so the addresses this test mints are
            // the addresses the runbook says it mints.
            ("AGENT_EMAIL_DOMAIN", "agents.orizn.app".to_owned()),
            ("DATABASE_URL", database_url.clone()),
            ("AGENTOS_MASTER_KEY", "not-a-real-key".to_owned()),
            ("AGENTOS_ALLOW_MOCKS", "1".to_owned()),
            ("AGENTOS_LLM", "mock".to_owned()),
            (
                "AGENTOS_API_KEYS",
                format!("ops:{}:{SECRET}", tenant.as_uuid()),
            ),
            ("RUST_LOG", "warn".to_owned()),
        ]);

        // Both streams to the log file, and **not** `Stdio::inherit()` for
        // stderr. An inherited stderr is a pipe the child holds open, so a
        // failed assertion — which panics before `stop()` — leaves a live
        // server keeping the test runner's output pipe open and `cargo test`
        // hangs instead of reporting. The `Drop` below is the other half.
        let log = std::env::temp_dir().join(format!("{database}.log"));
        let logging = || Stdio::from(File::create(&log).expect("log file"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentos-server"));
        command.env_clear().stdout(logging()).stderr(logging());
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

    fn wait_until_live(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.curl("GET", "/livez", false, None).0 == 200 {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the server never became live");
    }

    /// One `agentos-server policy …` invocation, run the way the operator runs
    /// it — the same binary, `DATABASE_URL` and nothing else. Returns stdout.
    ///
    /// Every step of the runbook that writes a policy row now goes through
    /// here. Until these subcommands existed, three of them were `psql`.
    fn policy(&self, args: &[&str]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_agentos-server"))
            .arg("policy")
            .args(args)
            .env_clear()
            .env("DATABASE_URL", &self.database_url)
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .output()
            .expect("run agentos-server policy");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "policy {args:?} exited {}: {stdout}{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
        stdout
    }

    /// Step 2: the platform ceiling.
    fn install_ceiling(&self) {
        let stdout = self.policy(&["install", &docs("orizn-ceiling.json").display().to_string()]);
        assert!(
            stdout.contains("installed platform ceiling"),
            "the installer has to say what it did: {stdout}"
        );
    }

    /// Step 3: the tenant row **and** the active `policy_versions` row its
    /// layers hang off — which is the whole reason this is one command. A
    /// tenant with no active version has invisible layers: the rows exist,
    /// `psql` shows them, and the loader has never read one.
    ///
    /// `--id`, because `AGENTOS_API_KEYS` was written before the server booted
    /// and the key names this uuid.
    fn create_tenant(&self) {
        let stdout = self.policy(&[
            "new-tenant",
            "orizn",
            "Orizn",
            "--id",
            &self.tenant.as_uuid().to_string(),
        ]);
        assert!(
            stdout.contains("active policy version"),
            "the operator has to be told the version exists, because its absence is silent: \
             {stdout}"
        );
    }

    /// Step 5: the five role layers, one command each, from the five documents
    /// the runbook names.
    ///
    /// One invocation per layer, and therefore one policy version per layer —
    /// not one transaction for all five, as the SQL file this replaced was.
    /// What is lost is "all five or none"; what is gained is that a re-run is
    /// idempotent rather than a duplicate-key error, so a partial apply is
    /// repaired by running the loop again. That is the better trade for the
    /// failure that actually happens.
    fn install_role_layers(&self) {
        let tenant = self.tenant.as_uuid().to_string();
        for expected in EXPECTED {
            let file = docs(&format!("orizn-roles/{}.json", expected.role));
            let stdout = self.policy(&[
                "install",
                "--tenant",
                &tenant,
                "--role",
                expected.role,
                &file.display().to_string(),
            ]);
            assert!(
                stdout.contains("installed role layer"),
                "{}: {stdout}",
                expected.role
            );
        }

        // Re-running the whole set changes nothing and says so, which is what
        // makes a half-applied company repairable by re-running it.
        let again = self.policy(&[
            "install",
            "--tenant",
            &tenant,
            "--role",
            "finance",
            &docs("orizn-roles/finance.json").display().to_string(),
        ]);
        assert!(again.contains("unchanged"), "{again}");
    }

    /// One request. Returns the status and the body parsed as JSON.
    fn curl(&self, method: &str, path: &str, auth: bool, body: Option<&str>) -> (u16, Value) {
        let mut args = vec![
            "-sS".to_owned(),
            "-X".to_owned(),
            method.to_owned(),
            "-w".to_owned(),
            "\n%{http_code}".to_owned(),
            format!("{}{path}", self.base),
        ];
        if auth {
            args.push("-H".to_owned());
            args.push(format!("Authorization: Bearer {SECRET}"));
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
        (
            status.trim().parse().expect("an HTTP status"),
            serde_json::from_str(body).unwrap_or(Value::Null),
        )
    }

    fn get(&self, path: &str) -> (u16, Value) {
        self.curl("GET", path, true, None)
    }

    /// Poll one employee until the provisioning loops have finished with it.
    /// Nothing here makes provisioning happen — that is the claim.
    fn await_active(&self, id: &str) {
        let deadline = Instant::now() + CONVERGE_DEADLINE;
        let mut last = Value::Null;
        while Instant::now() < deadline {
            let (status, employee) = self.get(&format!("/v1/employees/{id}"));
            assert_eq!(status, 200, "the id we were handed stopped resolving");
            if employee["lifecycle"] == "active" {
                return;
            }
            last = employee;
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the loops never made the employee active: {last:#}");
    }

    fn stop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait().expect("wait") {
                Some(_) => break,
                None if Instant::now() > deadline => {
                    let _ = self.child.kill();
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let _ = std::fs::remove_file(&self.log);
    }

    fn drop_database(&self) {
        let (admin_url, database) = (self.admin_url.clone(), self.database.clone());
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    if let Ok(admin) = sqlx::postgres::PgPoolOptions::new()
                        .max_connections(1)
                        .connect(&admin_url)
                        .await
                    {
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
    }
}

/// A failed assertion panics before `stop()`, so the server has to be killed
/// from somewhere that runs anyway. Without this a failing run leaves a live
/// server polling a database the next run will try to drop, and the operator
/// debugging the failure has to find it by hand.
impl Drop for Orizn {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            eprintln!(
                "server killed on an early exit; its log is {}",
                self.log.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Reading the company back
// ---------------------------------------------------------------------------

/// The columns `docs/orizn-roles/*.json` actually set, in the store's order:
/// currency, per-transaction, per-day, approval-above, channels, domains,
/// contacts, turns. The three allowlists the file leaves empty everywhere are
/// not read back, because "it stayed `{}`" is asserted by the effective policy
/// below rather than by re-reading a default.
type LayerRow = (
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Vec<String>,
    Vec<String>,
    i32,
    i32,
);

/// The raw `policy_layers` row for one `role_name`, as `PolicyLimits`.
///
/// Read through the store's own decoder rather than by hand, so a column this
/// test forgot is a column the loader would also have forgotten.
async fn stored_layer(db: &Db, tenant: TenantId, role: &str) -> PolicyLimits {
    // Deliberately *not* through `policy::load`: this is the one row, exactly
    // as an operator would see it in `psql`, with no ceiling intersected into
    // it. Comparing it against the loaded policy is the whole assertion.
    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
    let raw: LayerRow = sqlx::query_as(
        "select spend_currency, max_per_transaction_minor, max_per_day_minor,
                    approval_above_minor, allowed_channels, allowed_domains,
                    max_new_contacts_per_day, max_turns_per_day
               from policy_layers l join policy_versions v on v.id = l.version_id
              where v.active and l.layer = 'role' and l.role_name = $1",
    )
    .bind(role)
    .fetch_one(&mut **tx)
    .await
    .unwrap_or_else(|e| panic!("no role layer for {role}: {e}"));
    tx.rollback().await.expect("rollback");

    let (currency, per_txn, per_day, approval, channels, domains, contacts, turns) = raw;
    // Rebuilt through the same serde forms the store writes, so a channel name
    // this file spells differently from `Channel::as_str` fails here.
    let json = serde_json::json!({
        "spend": currency.map(|c| serde_json::json!({
            "max_per_transaction": {"minor": per_txn.unwrap_or(0), "currency": c},
            "max_per_day":         {"minor": per_day.unwrap_or(0), "currency": c},
            "approval_above":      {"minor": approval.unwrap_or(0), "currency": c},
        })),
        "allowed_channels": channels,
        "allowed_domains": domains,
        "max_new_contacts_per_day": contacts,
        "max_turns_per_day": turns,
    });
    serde_json::from_value(json).expect("the stored row is a PolicyLimits")
}

fn channels(of: &[Channel]) -> BTreeSet<Channel> {
    of.iter().copied().collect()
}

fn domains(of: &[&str]) -> BTreeSet<Domain> {
    of.iter()
        .map(|d| Domain::parse(d).expect("a valid domain"))
        .collect()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_runbook_stands_orizn_up_and_the_company_is_the_one_it_describes() {
    let Some(mut server) = Orizn::boot().await else {
        return;
    };

    // --- 2. the ceiling is what makes the deployment usable at all ----------
    // Red before, green after. A replica with no platform layer has no ceiling
    // and the gate refuses everything; that is the safe direction, and it is
    // the first thing `docs/ORIZN.md` tells an operator to expect.
    let (status, problem) = server.curl("GET", "/readyz", false, None);
    assert_eq!(
        status, 503,
        "a fresh deployment must not be ready: {problem:#}"
    );
    assert_eq!(
        problem["code"], "no_platform_policy",
        "and it must say which of the three reasons: {problem:#}"
    );

    server.install_ceiling();

    let (status, ready) = server.curl("GET", "/readyz", false, None);
    assert_eq!(status, 200, "the ceiling did not make it ready: {ready:#}");
    assert_eq!(ready["ready"], true, "{ready:#}");

    // --- 3, 4. the tenant row, then the org chart ---------------------------
    server.create_tenant();

    let document: Value = serde_json::from_str(
        &std::fs::read_to_string(docs("orizn-org.json")).expect("read the org document"),
    )
    .expect("the org document is JSON");
    let (status, applied) = server.curl("POST", "/v1/org", true, Some(&document.to_string()));
    assert_eq!(
        status, 202,
        "a first apply hires, and 202 says so: {applied:#}"
    );

    // Every row of the document, back out, in order. The document is the
    // expectation — there is no second copy of the mission strings anywhere.
    let rows = document["rows"].as_array().expect("rows");
    let chart = applied["chart"].as_array().expect("chart");
    assert_eq!(chart.len(), rows.len(), "a row went missing: {applied:#}");

    let mut seats: HashMap<&str, String> = HashMap::new();
    for (row, seat) in rows.iter().zip(chart) {
        let team = row["team"].as_str().expect("team");
        assert_eq!(seat["team"], row["team"], "row order changed: {seat:#}");
        assert_eq!(seat["name"], row["name"], "{team}: name");
        assert_eq!(seat["mission"], row["mission"], "{team}: mission");
        assert_eq!(seat["head"], row["head"], "{team}: head");
        assert_eq!(seat["title"], row["title"], "{team}: title");
        assert_eq!(
            seat["hired"], true,
            "{team}: nobody was hired for this seat"
        );
        seats.insert(
            row["head"].as_str().expect("head"),
            seat["employee_id"]
                .as_str()
                .expect("employee_id")
                .to_owned(),
        );
    }

    // The reporting line, by id and not by slug: `reports_to` in the document
    // names a head, and what lands is that head's employee id. Four report to
    // the founder; the founder reports to nobody, which is what makes it the
    // root rather than one more seat.
    for (row, seat) in rows.iter().zip(chart) {
        let team = row["team"].as_str().expect("team");
        match row.get("reports_to").and_then(Value::as_str) {
            None => assert!(
                seat["reports_to"].is_null(),
                "{team} is the root and must report to nobody: {seat:#}"
            ),
            Some(manager) => assert_eq!(
                seat["reports_to"].as_str(),
                seats.get(manager).map(String::as_str),
                "{team} reports to {manager}"
            ),
        }
    }

    // The mission survives a round trip through the store, and the team's
    // policy pointer is its slug — which is the whole reason the SQL below can
    // name `role_name` without repointing anything.
    let (status, teams) = server.get("/v1/teams");
    assert_eq!(status, 200);
    let listed: HashMap<&str, &Value> = teams["teams"]
        .as_array()
        .expect("teams")
        .iter()
        .map(|t| (t["slug"].as_str().expect("slug"), t))
        .collect();
    for row in rows {
        let slug = row["team"].as_str().expect("team");
        let team = listed
            .get(slug)
            .unwrap_or_else(|| panic!("{slug} is missing"));
        assert_eq!(team["mission"], row["mission"], "{slug}: mission read back");
        assert_eq!(
            team["policy_role"], slug,
            "{slug}: a team whose policy pointer is not its slug is a team whose \
             limits are written where the gate will not look"
        );
    }

    // Provisioning has to finish before any of these seats is an employee the
    // gate would rule for. Nothing here makes it happen.
    for id in seats.values() {
        server.await_active(id);
    }

    // --- 5. the role layers -------------------------------------------------
    server.install_role_layers();

    let db = Db::connect(&server.database_url).await.expect("connect");
    for expected in EXPECTED {
        let role = expected.role;
        let employee = EmployeeId::from_uuid(
            seats[expected.head]
                .parse::<Uuid>()
                .expect("an employee id"),
        );

        // The loader, on the hot path, with `role: None` — so what resolves the
        // layer is the team membership and its `team_policy` pointer, exactly
        // as it will at decision time.
        let mut tx = db.tenant_tx(server.tenant).await.expect("tenant tx");
        let effective = policy::load(&mut tx, employee)
            .await
            .unwrap_or_else(|e| panic!("{role}: load: {e}"));
        tx.rollback().await.expect("rollback");
        let limits = effective.limits();

        assert_eq!(
            limits.max_turns_per_day, expected.turns,
            "{role}: max_turns_per_day is the token bill; docs/ORIZN.md argues {}",
            expected.turns
        );
        assert_eq!(
            limits.max_new_contacts_per_day, expected.contacts,
            "{role}: max_new_contacts_per_day is a legal boundary, not a throughput target"
        );
        assert_eq!(
            limits.allowed_channels,
            channels(expected.channels),
            "{role}: allowed_channels"
        );
        assert_eq!(
            limits.allowed_domains,
            domains(expected.domains),
            "{role}: allowed_domains"
        );

        match (limits.spend, expected.spend) {
            (None, None) => {}
            (Some(spend), Some((per_txn, per_day, approval))) => {
                assert_eq!(spend.currency(), Currency::Usd, "{role}: currency");
                assert_eq!(
                    spend.max_per_transaction().minor(),
                    per_txn,
                    "{role}: per transaction"
                );
                assert_eq!(spend.max_per_day().minor(), per_day, "{role}: per day");
                assert_eq!(
                    spend.approval_above().minor(),
                    approval,
                    "{role}: the approval threshold is the counterweight to the whole \
                     arrangement; one dollar means every payment goes to a person"
                );
            }
            (found, _) => panic!(
                "{role}: spend is {found:?} and docs/ORIZN.md says {:?}",
                expected.spend
            ),
        }

        // Nothing may widen, and this is where that is checked: the row an
        // operator reads in `psql` must equal the row the gate rules with. They
        // differ exactly when a layer named a number the ceiling had to clamp
        // — safe, because the loader takes the minimum, and misleading, because
        // the next person to open the table would believe the wider number.
        let stored = stored_layer(&db, server.tenant, role).await;
        assert_eq!(
            stored.max_turns_per_day, limits.max_turns_per_day,
            "{role}: the stored max_turns_per_day is not what binds"
        );
        assert_eq!(
            stored.max_new_contacts_per_day, limits.max_new_contacts_per_day,
            "{role}: the stored max_new_contacts_per_day is not what binds"
        );
        assert_eq!(
            stored.allowed_channels, limits.allowed_channels,
            "{role}: the ceiling removed a channel this layer asked for"
        );
        assert_eq!(
            stored.allowed_domains, limits.allowed_domains,
            "{role}: the ceiling removed a domain this layer asked for"
        );
        assert_eq!(
            stored.spend, limits.spend,
            "{role}: the ceiling clamped a spend cap this layer asked for"
        );
    }

    // --- 6. finance, and the two rows a spend layer does not give it --------
    // Three independent things must say yes before a euro moves. The layer
    // above is one; these are the other two, and forgetting either produces a
    // payment that passes the gate and is refused at the reservation.
    let finance_team = listed["finance"]["id"].as_str().expect("finance team id");
    let books = &seats["books"];

    let (status, budget) = server.curl(
        "PUT",
        &format!("/v1/teams/{finance_team}/budget"),
        true,
        Some(r#"{"daily_total": {"minor": 100000, "currency": "USD"}}"#),
    );
    assert_eq!(status, 200, "{budget:#}");
    assert_eq!(budget["remaining_minor"], 100_000, "{budget:#}");

    let (status, caps) = server.curl(
        "PUT",
        &format!("/v1/employees/{books}/spend-caps"),
        true,
        Some(
            r#"{"daily_total":       {"minor": 100000, "currency": "USD"},
                "per_transaction":   {"minor":  50000, "currency": "USD"},
                "daily_transactions": 2}"#,
        ),
    );
    assert_eq!(status, 200, "{caps:#}");
    assert_eq!(caps["caps"]["daily_transactions"], 2, "{caps:#}");

    // No other function gets either call, and the absence is the configuration.
    // `org::reserve` refuses a team with no budget row outright.
    let (status, none) = server.get(&format!(
        "/v1/teams/{}/budget?currency=USD",
        listed["sales-development"]["id"].as_str().expect("id")
    ));
    assert_eq!(status, 200);
    assert!(
        none["daily_total"].is_null(),
        "sales must have no budget: absence of one is 'may not spend', not 'unlimited' — {none:#}"
    );

    // --- 7. still green, with a whole company in it -------------------------
    let (status, ready) = server.curl("GET", "/readyz", false, None);
    assert_eq!(status, 200, "{ready:#}");
    assert_eq!(ready["ready"], true, "{ready:#}");
    assert!(
        ready["outbox_lag_secs"].as_i64().unwrap_or(i64::MAX) < 300,
        "the provisioning the org chart queued never drained: {ready:#}"
    );

    server.stop();
    server.drop_database();
}

/// The monthly figure in `docs/ORIZN.md`, derived rather than quoted.
///
/// No database and no server: this is arithmetic over two constants, one of
/// which (`INPUT_TOKENS_PER_CALL`) is a measurement from
/// `crates/eval/src/scoping.rs` and the other of which is the sum of the turn
/// budgets asserted above. It fails when somebody raises a turn budget in
/// `docs/orizn-roles/` and leaves the cost table in the document saying
/// what the old one cost — which is the drift that actually hurts, because the
/// number an operator budgets on is the one they do not re-derive.
#[test]
fn the_monthly_bill_is_the_sum_of_the_turn_budgets_the_document_argues_for() {
    let turns: u32 = EXPECTED.iter().map(|e| e.turns).sum();
    assert_eq!(
        turns, TURNS_PER_DAY,
        "docs/ORIZN.md's cost table totals {TURNS_PER_DAY} turns a day"
    );

    // Input only, at full price for every token: `scoping.rs` prices cache
    // reads at full rate deliberately, because no rate card lives in this
    // workspace, so this is the honest ceiling and the cache is upside.
    // $5.00 per million input tokens for `claude-opus-5`.
    // Rounded to the cent, not truncated: the document quotes $45.93 and
    // $45.9261 truncates to $45.92, which is the kind of one-cent disagreement
    // that makes a reader distrust the rest of the table.
    let cents = |tokens: u64, per_million: u64| (tokens * per_million + 500_000) / 1_000_000;

    let tokens_per_month = u64::from(turns) * u64::from(INPUT_TOKENS_PER_CALL) * 30;
    assert_eq!(
        cents(tokens_per_month, 500),
        4593,
        "docs/ORIZN.md says $45.93 of input a month at these settings"
    );

    // And the lever, per the document: one more turn a day on one employee.
    assert_eq!(
        cents(u64::from(INPUT_TOKENS_PER_CALL) * 30, 500),
        70,
        "one turn per day is about $0.70 a month of input, which is what makes \
         doubling a turn budget a one-line decision rather than a project"
    );
}
