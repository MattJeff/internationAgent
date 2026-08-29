//! The x402 chain, end to end, against a double — and the exact link where it
//! stops.
//!
//! The founder's chain is *MCP call → 402 → read → `PaymentCreate` → gate →
//! budget → human approval → wallet → payment → replay → receipt*. The first
//! seven links exist, and most of them have a unit test of their own — but
//! **none of them has a test that it is holding the next one's hand**, and a
//! chain is exactly the property a per-unit suite cannot see. `x402.rs` proves a
//! challenge becomes an amount, `gate.rs` proves a payment is escalated and
//! reserved, and between the two sits an `Action` nobody had ever built from a
//! real 402 body and put in front of a real database.
//!
//! "Most", not "all": link one had nothing at all. No test in this workspace
//! answers a 402 to a tool call, because the client cannot read one — see below.
//!
//! So: one run, seven assertions, one per link, each on a thing that is
//! *observable* after the fact — a status on the wire, a parsed amount, an
//! audit row, an approval row, a hash, a bucket. A chain test that only checks
//! "no error came back" would pass with the third link cut.
//!
//! # Where it stops, and why that is a decision rather than a gap
//!
//! Link seven is the last one. `crates/app/src/x402.rs`'s *"The bridge from a
//! human approved to the money moved"* is the single place that argues it; this
//! file does not repeat it. The short form is that
//! `apps/server/src/routes/approvals.rs::approve` mints an `Authorized<Action>`
//! and drops it, because `Authorized<Action>` satisfies no `Effects` bound —
//! and the four links past it (wallet, payment, replay, receipt) are blocked on
//! two decisions about money that only the founder can take.
//!
//! # Why the wire is dialled with `reqwest` and not with the MCP client
//!
//! `crate::mcp::Fleet` cannot hand a 402 body to anybody, and that is written
//! down at length in `mcp::refused_the_credential`: `rmcp` 3.1.4 is built
//! against reqwest 0.13 and this workspace against 0.12, so the status cannot
//! be downcast out of the transport error and a 402 arrives as an opaque,
//! *retryable* failure with the body already thrown away. Routing this test
//! through `Fleet` would therefore prove the chain is broken at link one for a
//! reason that is a `Cargo.lock` rather than this product. It is dialled with
//! the workspace's own client instead — the same 0.12 `reqwest` that
//! `peer_keys` reads a stranger's document with — which is what `Fleet` becomes
//! the day the two versions agree.
//!
//! What that costs, named rather than hidden: this file does not prove the MCP
//! client surfaces a 402. Nothing does, because it does not.
//!
//! # No money moves and no key exists
//!
//! The server is a `TcpListener` on loopback that answers one JSON-RPC request
//! with a 402. `PRICED_ASSETS` stays empty in the shipped code; the asset table
//! below is this test's own, exactly as `x402.rs`'s own tests build theirs.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use agentos_app::gate::{Denied, PolicyGate, Principal, RedemptionFailure};
use agentos_app::x402::{self, Asset};
use agentos_domain::action::Action;
use agentos_domain::ids::{ApprovalId, EmployeeId, TenantId};
use agentos_domain::money::{Currency, Money};
use agentos_domain::policy::{DenyReason, PolicyLimits, SpendLimits};
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_providers::ProviderError;
use agentos_store::db::Db;
use agentos_store::policy::Scope;
use agentos_store::spend::{self, SpendCaps};
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// The numbers, and why each one is the number it is
// ---------------------------------------------------------------------------

/// USDC on Base, as a deployment that had taken the founder's first decision
/// would write it. **A fixture, not a default**: `x402::PRICED_ASSETS` ships
/// empty and `x402.rs`'s `the_shipped_deployment_prices_nothing` goes red the
/// day it does not.
const USDC: Asset = Asset {
    network: "base",
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    currency: Currency::Usd,
    decimals: 6,
};

/// What the server charges, in the asset's base units: 60 000 000 units of a
/// 6-decimal token.
const BASE_UNITS: &str = "60000000";

/// The same price in the currency the gate, `SpendLimits` and `spend_buckets`
/// all speak: $60.00.
///
/// **It crosses the threshold and clears both caps**, which is what makes every
/// assertion below say something. $60 ≥ the $50 `approval_above`, so the gate
/// takes the escalating arm rather than allowing outright; $60 < the $200
/// per-transaction cap and < the $300 daily cap, so the escalation is not a
/// refusal wearing an approval's clothes. Move any of the four and a different
/// arm answers.
const MINOR: u64 = 6_000;

/// The address the server wants paying at. A *stranger's* string: it reaches
/// the approval hash and the founder's queue line and is never checked by
/// anything, which is the whole reason it is on the action.
const PAYEE: &str = "0x00000000000000000000000000000000000000a7";

/// What the server says it is charging for. Ends up in the memo, and the memo
/// is the one field no ruling and no hash is taken over.
const MEMO: &str = "One visa rule lookup";

fn usd(minor: u64) -> Money {
    Money::new(minor, Currency::Usd).expect("nonzero")
}

// ---------------------------------------------------------------------------
// The double
// ---------------------------------------------------------------------------

/// An MCP server that answers `tools/call` with a real `402 Payment Required`.
///
/// The wire, not a mock: HTTP/1.1 on a loopback port, a JSON-RPC envelope in,
/// a status line and an x402 v1 body out. Same shape and same argument as
/// `mcp.rs`'s own `FakeMcp` — a double that speaks the protocol breaks when the
/// protocol handling does, and one that returns a canned struct does not.
struct FakeMcp {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl FakeMcp {
    async fn charging() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let accepted = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let seen = Arc::clone(&accepted);
                tokio::spawn(async move { serve(stream, seen).await });
            }
        });

        Self {
            url: format!("http://{addr}/mcp"),
            seen,
        }
    }

    /// How many times a JSON-RPC method was asked for.
    fn saw(&self, method: &str) -> usize {
        self.seen
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|m| *m == method)
            .count()
    }
}

/// The challenge body, exactly as an x402 v1 server writes one.
fn challenge() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "x402Version": 1,
        "accepts": [{
            "scheme": "exact",
            "network": USDC.network,
            "maxAmountRequired": BASE_UNITS,
            "resource": "https://api.example.com/visa-rules",
            "description": MEMO,
            "mimeType": "application/json",
            "payTo": PAYEE,
            "maxTimeoutSeconds": 60,
            "asset": USDC.address,
        }],
    }))
    .expect("serialise the challenge")
}

async fn serve(mut stream: TcpStream, seen: Arc<Mutex<Vec<String>>>) {
    let mut buffer = Vec::new();
    while let Some(body) = read_request(&mut stream, &mut buffer).await {
        let Ok(request) = serde_json::from_slice::<Value>(&body) else {
            return;
        };
        let method = request["method"].as_str().unwrap_or_default().to_owned();
        seen.lock().expect("not poisoned").push(method.clone());

        // A tool call costs money; the handshake does not. Charging for
        // everything would make the assertion below true for the wrong reason.
        let response = if method == "tools/call" {
            let body = challenge();
            let mut out = format!(
                "HTTP/1.1 402 Payment Required\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(&body);
            out
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
        };
        if stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

/// One HTTP/1.1 request body, or `None` when the peer went away. Borrowed
/// verbatim from `mcp.rs`'s test double.
async fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if let Some(head) = find(buffer, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buffer[..head]).to_lowercase();
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let start = head + 4;
            if buffer.len() >= start + length {
                let body = buffer[start..start + length].to_vec();
                buffer.drain(..start + length);
                return Some(body);
            }
        }
        let mut chunk = [0_u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The database side
// ---------------------------------------------------------------------------

/// A database of this test's own, and **it is not tidiness**.
///
/// `policy::install` writes the deployment's singleton platform ceiling, and a
/// deployment has exactly one spend currency: the function refuses outright when
/// the ceiling already carries another one, because layers in two currencies
/// cannot be intersected. The asset below prices in USD and **every other
/// fixture in this package installs EUR** — `gate.rs`'s `limits()`, and the
/// suites that borrow it. `scripts/test.sh` gives one database per *package*,
/// not per test binary, and cargo runs those binaries concurrently, so on a
/// shared database whichever `install` lands first wins the ceiling and the
/// other one fails. That is a coin flip, in a different test each run, reported
/// as a policy conflict that has nothing to do with what was being tested.
///
/// Same mechanism and same reasoning as `gate.rs`'s `private_db` and
/// `apps/server/src/loops/mod.rs`, which need it for the same row. The name is
/// derived from `DATABASE_URL`, which is the contract `scripts/test.sh`'s
/// cleanup trap relies on to collect it.
///
/// The alternative — denominating this test in EUR to match the neighbours —
/// was rejected: an `Asset` says *this contract, on this network, is that
/// currency*, and USDC on Base is what an x402 challenge actually quotes. The
/// currency is the one thing in this fixture that should not be chosen by what
/// the test harness finds convenient.
async fn db() -> Option<Db> {
    use sqlx::Connection as _;

    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("SKIP: DATABASE_URL is unset; the x402 chain test needs a real Postgres");
        return None;
    };
    let (host_part, tail) = url.rsplit_once('/').expect("DATABASE_URL names a database");
    let (base, options) = tail.split_once('?').map_or((tail, ""), |(b, o)| (b, o));
    let name = format!("{base}_x402chain");
    let mine = if options.is_empty() {
        format!("{host_part}/{name}")
    } else {
        format!("{host_part}/{name}?{options}")
    };

    let db = match Db::connect(&mine).await {
        Ok(db) => db,
        Err(_) => {
            let mut admin = sqlx::PgConnection::connect(&url).await.expect("connect");
            // Ignored: losing the race to create it is fine, the connect below
            // is the real check.
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
                .execute(&mut admin)
                .await;
            admin.close().await.expect("close");
            Db::connect(&mine).await.expect("connect")
        }
    };
    db.migrate().await.expect("migrate");
    Some(db)
}

/// A tenant and one active employee, committed. Same fixture as `gate.rs`'s,
/// scoped to its own tenant so it touches nothing beside it.
async fn seed(db: &Db) -> (TenantId, EmployeeId) {
    let now = Utc::now();
    let tenant = TenantId::new_v7(now);
    let employee = EmployeeId::new_v7(now);
    let label = format!("x402-{}", employee.as_uuid().simple());
    let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

    sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
        .bind(tenant.as_uuid())
        .bind(&label)
        .bind(&label)
        .execute(&mut *tx)
        .await
        .expect("insert tenant");
    sqlx::query(
        "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
         VALUES ($1, $2, 'lena', 'lena', 'active')",
    )
    .bind(employee.as_uuid())
    .bind(tenant.as_uuid())
    .execute(&mut *tx)
    .await
    .expect("insert employee");
    tx.commit().await.expect("commit seed");

    (tenant, employee)
}

/// $200 a payment, $300 a day, a human above $50 — and USD, because the asset
/// above prices in USD and `evaluate` refuses a currency mismatch before it
/// reads a single cap.
fn limits() -> PolicyLimits {
    PolicyLimits {
        spend: Some(SpendLimits::try_new(usd(20_000), usd(30_000), usd(5_000)).expect("coherent")),
        ..PolicyLimits::default()
    }
}

/// The ledger's own caps, which `org::reserve` reads at redemption. Deliberately
/// wider than the policy's: a refusal below can then only be the policy's, and a
/// missing row here would be `NoSpendPolicy` rather than a reservation.
async fn give_caps(db: &Db, tenant: TenantId, employee: EmployeeId) {
    let mut tx = db.tenant_tx(tenant).await.expect("tx");
    spend::set_caps(
        &mut tx,
        employee,
        SpendCaps::new(
            usd(100_000),
            usd(50_000),
            NonZeroU32::new(10).expect("nonzero"),
        )
        .expect("coherent"),
    )
    .await
    .expect("set caps");
    tx.commit().await.expect("commit caps");
}

/// Every audit row for this employee: `(decision, deny_reason_code, payload)`.
async fn audit_rows(
    db: &Db,
    tenant: TenantId,
    employee: EmployeeId,
) -> Vec<(Option<String>, Option<String>, Value)> {
    let mut tx = db.tenant_tx(tenant).await.expect("tx");
    let rows = sqlx::query_as(
        "SELECT decision, deny_reason_code, payload FROM audit_log \
          WHERE employee_id = $1 ORDER BY occurred_at, id",
    )
    .bind(employee.as_uuid())
    .fetch_all(&mut **tx)
    .await
    .expect("read audit");
    tx.commit().await.expect("commit read");
    rows
}

/// `(state, action_hash, nonce, reason)` for one approval — the queue line as
/// the approval UI reads it, nonce out of the row and never out of the gate.
async fn approval_row(
    db: &Db,
    tenant: TenantId,
    id: ApprovalId,
) -> (String, String, String, String) {
    let mut tx = db.tenant_tx(tenant).await.expect("tx");
    let row = sqlx::query_as(
        "SELECT state, action->>'action_hash', action->>'nonce', coalesce(reason, '') \
           FROM approvals WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(&mut **tx)
    .await
    .expect("read approval");
    tx.commit().await.expect("commit read");
    row
}

async fn count(db: &Db, tenant: TenantId, sql: &'static str, employee: EmployeeId) -> i64 {
    let mut tx = db.tenant_tx(tenant).await.expect("tx");
    let n: i64 = sqlx::query_scalar(sql)
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("count");
    tx.commit().await.expect("commit read");
    n
}

const APPROVALS: &str = "SELECT count(*) FROM approvals WHERE employee_id = $1";
const RESERVATIONS: &str =
    "SELECT count(*) FROM spend_reservations WHERE employee_id = $1 AND state = 'reserved'";

/// What this employee's own bucket says it has reserved today, in USD.
async fn reserved_today(db: &Db, tenant: TenantId, employee: EmployeeId) -> i64 {
    let mut tx = db.tenant_tx(tenant).await.expect("tx");
    let reserved: Option<i64> = sqlx::query_scalar(
        "SELECT reserved_minor FROM spend_buckets \
          WHERE employee_id = $1 AND day = $2 AND currency = 'USD'",
    )
    .bind(employee.as_uuid())
    .bind(Utc::now().date_naive())
    .fetch_optional(&mut **tx)
    .await
    .expect("read bucket");
    tx.commit().await.expect("commit read");
    reserved.unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

/// Seven links, seven assertions, one run.
///
/// Read the `-- N --` markers: each one is a link of the founder's chain, and
/// each one asserts on something a reader could go and look at afterwards.
#[tokio::test]
async fn a_402_becomes_an_approval_line_and_stops_there() {
    let Some(db) = db().await else { return };
    let (tenant, employee) = seed(&db).await;
    give_caps(&db, tenant, employee).await;
    agentos_store::policy::install(&db, tenant, Scope::Tenant, &limits())
        .await
        .expect("install the policy");
    let gate = PolicyGate::new(db.clone());

    // -- 1. the MCP call, and the 402 -------------------------------------
    //
    // A real JSON-RPC `tools/call` over a real socket, answered `402 Payment
    // Required`. Both halves are asserted: the server saw a *tool call* (not a
    // handshake it charged for by mistake), and the status is 402 and not
    // merely "not 200".
    let server = FakeMcp::charging().await;
    let response = reqwest::Client::new()
        .post(&server.url)
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "check_visa_requirement", "arguments": {} },
            }))
            .expect("serialise the call"),
        )
        .send()
        .await
        .expect("the double answered");

    assert_eq!(response.status().as_u16(), 402, "the server wants money");
    assert_eq!(server.saw("tools/call"), 1, "the 402 answered a tool call");
    // And the workspace's one rule for classifying a status agrees it is
    // terminal: asking again without paying gets the same answer. This is the
    // half `mcp::refused_the_credential` cannot reach today.
    assert_eq!(
        ProviderError::from_status(response.status().as_u16(), None).code(),
        "payment_required"
    );

    // -- 2. the read ------------------------------------------------------
    //
    // The body is a stranger's bytes from the moment it is received, and
    // `x402::demand` can only ever hand back an `Untrusted<Demand>`. All three
    // fields are asserted, because a parser that got the payee right and the
    // amount wrong is the failure this module exists to prevent.
    let body = Untrusted::new(response.bytes().await.expect("a body").to_vec());
    let parsed = x402::demand(&body, &[USDC]).expect("this deployment prices USDC on Base");
    assert_eq!(parsed.taint(), TrustLabel::Untrusted);

    let demand = parsed.into_inner_for_rendering();
    assert_eq!(demand.amount, usd(MINOR), "60 000 000 base units is $60.00");
    assert_eq!(demand.payee, PAYEE, "the payee is the server's own string");
    assert_eq!(demand.memo, MEMO);

    // -- 3. the action ----------------------------------------------------
    //
    // Both fields travel from the demand into the action the gate rules on.
    // Asserted against the **literals the server sent**, not against the
    // demand's own fields: `action == PaymentCreate { d.amount, d.payee }` is a
    // tautology that a `Demand::action` returning the wrong thing would still
    // satisfy if the demand were wrong in the same way.
    let action = demand.action();
    assert_eq!(
        action,
        Action::PaymentCreate {
            amount: usd(MINOR),
            payee: PAYEE.to_owned(),
        }
    );

    // -- 4. the gate, on the stranger's own demand ------------------------
    //
    // The switch. `PaymentCreate` is high risk and this action is derived from
    // untrusted input, so the last expression of `policy::evaluate` denies it
    // outright — **and files nothing**. The amount is over `approval_above`,
    // which is precisely the case that used to take the escalating branch and
    // put a server's chosen payee and price in the founder's queue under his
    // own employee's name.
    let employee_principal = Principal::employee(tenant, employee);
    let refused = gate
        .authorize(&employee_principal, Untrusted::new(action.clone()))
        .await
        .expect_err("a server's own demand must not reach the executor");
    assert_eq!(refused.code(), DenyReason::UntrustedInput.code());

    let rows = audit_rows(&db, tenant, employee).await;
    assert_eq!(rows.len(), 1, "one outcome, one row");
    assert_eq!(rows[0].0.as_deref(), Some("deny"));
    assert_eq!(rows[0].1.as_deref(), Some("untrusted_input"));
    assert_eq!(
        count(&db, tenant, APPROVALS, employee).await,
        0,
        "no queue line may be written from a stranger's number"
    );
    assert_eq!(count(&db, tenant, RESERVATIONS, employee).await, 0);

    // -- 5. the gate, from trusted ground ---------------------------------
    //
    // Crossing link 4 is not a code change: it is a human reading the challenge
    // and re-proposing the payment himself, which is the flow that already
    // exists. The same action, from an operator's authenticated request, is
    // escalated rather than denied.
    let proposer = Principal::operator(tenant, employee, "ops@founder");
    let Denied::PendingApproval(approval_id) = gate
        .authorize(&proposer, action.clone())
        .await
        .expect_err("$60 is over the $50 threshold")
    else {
        panic!("a payment over the threshold must be escalated, not allowed");
    };

    let rows = audit_rows(&db, tenant, employee).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].0.as_deref(), Some("require_approval"));
    assert_eq!(
        rows[1].2["approval_id"],
        json!(approval_id.as_uuid().to_string()),
        "the gate's row names the line it filed"
    );

    // -- 6. the approval line, and its hash -------------------------------
    //
    // The line a human reads, and the hash that binds it to this exact action.
    // Reproduced here from `canonical_json`, which is public for precisely this
    // reason — a hash nobody outside the store can recompute is a hash nobody
    // can check.
    let (state, action_hash, nonce, reason) = approval_row(&db, tenant, approval_id).await;
    assert_eq!(state, "pending");
    let expected: String = Sha256::digest(
        agentos_store::approvals::canonical_json(&action)
            .expect("canonical")
            .as_bytes(),
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
    assert_eq!(action_hash, expected, "the line is hashed to this action");
    assert!(
        reason.contains("USD 60.00") && reason.contains(&format!("{PAYEE:?}")),
        "the queue line states the amount and quotes the stranger's payee: {reason}"
    );

    // And the hash bites: one cent more is a different action, refused without
    // burning the approval.
    let mutated = Action::PaymentCreate {
        amount: usd(MINOR + 1),
        payee: PAYEE.to_owned(),
    };
    let approver = Principal::operator(tenant, employee, "approver");
    let swapped = gate
        .redeem_approval(&approver, approval_id, &nonce, mutated)
        .await
        .expect_err("a mutated action is not the approved one");
    assert!(matches!(
        swapped,
        Denied::Redemption(RedemptionFailure::ActionMismatch)
    ));
    assert_eq!(
        count(&db, tenant, RESERVATIONS, employee).await,
        0,
        "a refused redemption reserves nothing"
    );

    // -- 7. the budget ----------------------------------------------------
    //
    // The exact action, redeemed. The token carries the reservation, and the
    // reservation is in the ledger — so the day's running total has moved and
    // the next payment this employee proposes is measured against it. That is
    // the wall fifty side-effect 402s would have walked past.
    let authorized = gate
        .redeem_approval(&approver, approval_id, &nonce, action.clone())
        .await
        .expect("the approved action, redeemed by a human");
    assert_eq!(
        authorized
            .reservation()
            .expect("an approved payment reserves")
            .amount()
            .minor(),
        MINOR
    );
    assert_eq!(count(&db, tenant, RESERVATIONS, employee).await, 1);
    assert_eq!(
        reserved_today(&db, tenant, employee).await,
        i64::try_from(MINOR).expect("fits"),
        "the day's bucket moved by exactly the amount the server named"
    );

    let rows = audit_rows(&db, tenant, employee).await;
    assert_eq!(rows.len(), 4, "one row per outcome, refusals included");
    assert_eq!(rows[2].2["denied"], json!("approval_action_mismatch"));
    assert_eq!(rows[3].0.as_deref(), Some("allow"));

    // -- and here the chain stops -----------------------------------------
    //
    // `authorized` is an `Authorized<Action>`. It satisfies no `Effects` bound,
    // so there is nothing this test could call next and nothing the approval
    // route calls either — it returns the decision id and drops the token. The
    // four links past this one are argued in `x402.rs`, "The bridge from a
    // human approved to the money moved".
    assert_eq!(authorized.into_action(), action);
}
