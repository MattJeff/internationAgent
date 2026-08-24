//! `/v1/pool`: the shared phone numbers, who is on them, and who reaches whom.
//!
//! ```text
//! GET  /v1/pool/numbers                 the numbers, region, bundle, capacity, occupancy
//! GET  /v1/pool/routing                 counterparty -> employee, and whether it still routes
//! POST /v1/pool/numbers/{id}/reassign   hand one counterparty to another employee
//! ```
//!
//! # Why an operator needs this at all
//!
//! With a dedicated number per employee, "who does this supplier reach?" has a
//! trivial answer: the owner of the number they dialled. Pool the numbers and
//! that answer moves into [`agentos_app::pool_ops::route_inbound`]'s arbitration
//! rules, where nobody can see it. A mis-route then looks like an employee
//! ignoring a supplier, and the operator has no way to tell the two apart.
//! `GET /v1/pool/routing` is the difference between a diagnosable system and a
//! haunted one — it renders the arbitration's answer, per counterparty, with
//! the reason a row is not routable.
//!
//! # Reassign is an action, not a setting
//!
//! Moving a supplier from Lena to Alex decides which employee a counterparty
//! talks to for the rest of the relationship, and the psyche does **not** move
//! with it: Lena keeps the trust links, the learned expectations and the
//! beliefs she built about that supplier, and Alex starts from the prior. So it
//! goes through the Policy Gate like every other effect in this system, and
//! lands in the audit trail twice over — the gate's own ruling, and a row here
//! naming the number, the counterparty and both employees.
//!
//! The gate is consulted *before* anything moves, and it is consulted about the
//! **receiving** employee, because "is Alex allowed to take on this supplier"
//! includes "is Alex still active", which is precisely the check that stops an
//! operator handing a supplier to somebody who left last week.
//!
//! # Shape
//!
//! Behind the API key, tenant from the credential and never from a path or a
//! body, RFC 9457 problem+json on every failure, keyset pagination on both
//! reads — the same shape as `routes/employees.rs` and `routes/inventory.rs`,
//! deliberately, because a third house style is a third thing to learn.

use std::sync::Arc;

use agentos_app::gate::{PolicyGate, Principal as GatePrincipal};
use agentos_app::pool_ops::{self, Occupant, Pool, PoolError, PoolNumber};
use agentos_domain::action::{Action, E164, McpTool};
use agentos_domain::ids::{EmployeeId, Slug};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::Db;
use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get as get_route, post};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// Page size when the caller does not ask for one.
const DEFAULT_LIMIT: i64 = 50;

/// Largest page we will build, however big a `limit` the caller sends.
const MAX_LIMIT: i64 = 200;

/// The MCP server half of the reassign tool name.
///
/// ponytail: an `Action::McpCall` named `pool/reassign`, exactly as
/// `provisioning.rs` files its reconciliation approvals — [`Action`] is a closed
/// domain enum with no "change a routing affinity" variant and widening it is
/// not this unit's call. It gets the property that matters: the reassignment is
/// gated, it is denied by default, and an operator can allow it per tenant by
/// putting `pool/reassign` in `allowed_mcp_tools`.
const TOOL_SERVER: &str = "pool";
/// The tool half of the reassign tool name.
const TOOL_NAME: &str = "reassign";

/// The routes' shared state: a database for the reads, a gate for the verdict,
/// and the declared pool.
#[derive(Clone)]
pub struct PoolApi {
    db: Db,
    gate: PolicyGate,
    /// Which numbers each tenant owns. Configuration — see [`Pool`] — so it is
    /// shared by every request rather than read per request.
    pool: Arc<Pool>,
}

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before any handler here.
///
#[allow(dead_code)] // not mounted: this binary builds no Pool. See main.rs.
/// ponytail: `allow(dead_code)` for the same reason `routes/inventory.rs` has
/// it — this unit owns this file and one `pub mod` line, and `main.rs`, where
/// routers are merged, belongs to another unit. Delete the attribute in the
/// same commit that adds `.merge(routes::pool::router(db.clone(), gate.clone(),
/// pool))` to `api_router`.
pub fn router(db: Db, gate: PolicyGate, pool: Pool) -> Router {
    Router::new()
        .route("/v1/pool/numbers", get_route(numbers))
        .route("/v1/pool/routing", get_route(routing))
        .route("/v1/pool/numbers/{id}/reassign", post(reassign))
        .with_state(PoolApi {
            db,
            gate,
            pool: Arc::new(pool),
        })
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/// Keyset pagination. `after` is the previous page's last `cursor`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

impl Page {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// Only a full page can have a successor. A short page ends the walk without
/// costing the client one more round trip to discover that.
fn next_after<T>(rows: &[T], limit: i64, cursor: impl Fn(&T) -> String) -> Option<String> {
    (rows.len() as i64 == limit)
        .then(|| rows.last().map(cursor))
        .flatten()
}

// ---------------------------------------------------------------------------
// GET /v1/pool/numbers
// ---------------------------------------------------------------------------

/// One pooled number and what it is carrying.
#[derive(Debug, Serialize)]
struct NumberView<'a> {
    /// The number itself, which is also its id in the reassign path.
    number: &'a str,
    /// ISO country it was bought in.
    region: &'a str,
    /// Whether it needed a regulatory bundle and where that bundle got to. The
    /// field a French rollout is actually blocked on.
    #[serde(flatten)]
    regulatory: &'a pool_ops::Regulatory,
    /// How many employees may share it.
    capacity: u32,
    /// How many do.
    occupancy: usize,
    /// How many of those can currently answer. A gap between this and
    /// `occupancy` is capacity spent on employees that are suspended or
    /// terminated and have not been released.
    active: usize,
    /// Who they are. A pool number carries a handful of employees, so the list
    /// is the answer rather than a second endpoint.
    employees: &'a [Occupant],
    /// Keyset cursor: this row's number.
    cursor: &'a str,
}

/// `GET /v1/pool/numbers` — the tenant's numbers, with live occupancy.
///
/// The numbers come from configuration and the occupancy from the database, so
/// a number with nobody on it is still listed. That is not cosmetic: the last
/// employee leaving a number does **not** give the number back, and an endpoint
/// that dropped empty numbers would make a still-billed, still-regulated asset
/// invisible the moment it went idle.
async fn numbers(
    State(state): State<PoolApi>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let limit = page.limit();

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let seats = pool_ops::occupancy(&mut tx).await?;
    tx.rollback().await?;

    let empty: Vec<Occupant> = Vec::new();
    let mut declared: Vec<&PoolNumber> = state.pool.numbers(principal.tenant_id).iter().collect();
    declared.sort_by(|a, b| a.number().as_str().cmp(b.number().as_str()));

    let views: Vec<NumberView<'_>> = declared
        .iter()
        .filter(|pooled| match page.after.as_deref() {
            Some(after) => pooled.number().as_str() > after,
            None => true,
        })
        .take(limit as usize)
        .map(|pooled| {
            let employees = seats.get(pooled.number().as_str()).unwrap_or(&empty);
            NumberView {
                number: pooled.number().as_str(),
                region: pooled.region_str(),
                regulatory: pooled.regulatory(),
                capacity: pooled.capacity(),
                occupancy: employees.len(),
                active: employees
                    .iter()
                    .filter(|seat| seat.lifecycle == "active")
                    .count(),
                employees,
                cursor: pooled.number().as_str(),
            }
        })
        .collect();

    let next = next_after(&views, limit, |view| view.cursor.to_owned());
    Ok(Json(json!({ "numbers": views, "next_after": next })).into_response())
}

// ---------------------------------------------------------------------------
// GET /v1/pool/routing
// ---------------------------------------------------------------------------

/// `GET /v1/pool/routing` — which counterparty currently reaches which employee.
///
/// Straight out of [`pool_ops::affinities`], including the rows that no longer
/// route. A terminated employee's suppliers are the most important rows on the
/// page: they are relationships nobody is answering, and they stay listed until
/// somebody hands them over on purpose.
async fn routing(
    State(state): State<PoolApi>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let limit = page.limit();
    let after = page
        .after
        .as_deref()
        .map(|after| {
            after
                .parse::<Uuid>()
                .map_err(|_| ApiError::bad_request("after: expected a conversation uuid"))
        })
        .transpose()?;

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows = pool_ops::affinities(&mut tx, after, limit).await?;
    tx.rollback().await?;

    let next = next_after(&rows, limit, |row| row.conversation_id.to_string());
    Ok(Json(json!({ "routing": rows, "next_after": next })).into_response())
}

// ---------------------------------------------------------------------------
// POST /v1/pool/numbers/{id}/reassign
// ---------------------------------------------------------------------------

/// Who to hand which counterparty to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reassign {
    /// The supplier, in E.164. Validated here: an unparseable number would
    /// silently match no conversation and read as "nothing to move".
    counterparty: String,
    /// The employee that should own the relationship from now on.
    to_employee: Uuid,
}

/// `POST /v1/pool/numbers/{id}/reassign` — move one counterparty's affinity.
///
/// `{id}` is the number itself (`/v1/pool/numbers/+33757590001/reassign`): a
/// pooled number has no surrogate id, and inventing one would mean an operator
/// looking up a uuid for something they already know by the only name it has.
///
/// The order is: parse, confirm the number is this tenant's, ask the gate, then
/// write. The gate commits its own transaction and this handler opens another,
/// so a failure after the ruling leaves an audited `allow` for a move that did
/// not happen — the same seam `routes/approvals.rs` has, and the same reason:
/// the alternative is a gate that writes into a caller's transaction and can be
/// rolled back by it.
async fn reassign(
    State(state): State<PoolApi>,
    principal: Principal,
    Path(number): Path<String>,
    body: Result<Json<Reassign>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let number = E164::parse(&number).map_err(|err| {
        ApiError::bad_request(format!("the number in the path is not E.164: {err}"))
    })?;
    let counterparty = E164::parse(&body.counterparty)
        .map_err(|err| ApiError::bad_request(format!("counterparty: {err}")))?;
    let to = EmployeeId::from_uuid(body.to_employee);

    // A number this tenant does not own is a 404, not a 403: telling one tenant
    // that another tenant's number exists is telling it something.
    if state.pool.find(principal.tenant_id, &number).is_none() {
        return Err(ApiError::not_found());
    }

    // The gate, before anything moves. Attributed to the employee that gains
    // the counterparty, so "is this employee allowed to be given work" and "is
    // it still active" are the same question and get asked once.
    let authorized = state
        .gate
        .authorize(
            &GatePrincipal {
                // From the credential. Never from the path, never from the body.
                tenant_id: principal.tenant_id,
                employee_id: to,
                actor: principal.actor.clone(),
            },
            Action::McpCall { tool: tool() },
        )
        .await?;

    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let moved = pool_ops::reassign(&mut tx, &number, counterparty.as_str(), to, now).await?;

    // Same transaction as the move: a handover nobody recorded is a handover
    // nobody can be shown to have made. `decision_id` ties it to the ruling
    // that permitted it.
    audit::append(
        &mut tx,
        &AuditEvent {
            employee_id: Some(to),
            decision_id: Some(authorized.decision_id()),
            payload: json!({
                "number": number.as_str(),
                "counterparty": counterparty.as_str(),
                "to_employee": to.as_uuid().to_string(),
                "from_employees": moved.from.iter().map(Uuid::to_string).collect::<Vec<_>>(),
                "conversations": moved
                    .conversations
                    .iter()
                    .map(Uuid::to_string)
                    .collect::<Vec<_>>(),
                // The one consequence a reader of this row must not have to
                // infer: the relationship moved and the judgement did not.
                "psyche_transferred": false,
            }),
            ..AuditEvent::new(
                principal.actor.clone(),
                AuditKind::ResourceStateChanged,
                now,
            )
        },
    )
    .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "number": number.as_str(),
        "counterparty": counterparty.as_str(),
        "to_employee": to.as_uuid().to_string(),
        "from_employees": moved.from,
        "conversations": moved.conversations,
        "decision_id": authorized.decision_id().as_uuid().to_string(),
    }))
    .into_response())
}

/// `pool/reassign`, the tool the gate rules on.
///
/// Both halves are compile-time literals that satisfy [`Slug`], so the `expect`
/// is a statement about this source file rather than about any input.
fn tool() -> McpTool {
    McpTool::new(
        Slug::parse(TOOL_SERVER).expect("a literal slug"),
        Slug::parse(TOOL_NAME).expect("a literal slug"),
    )
}

impl From<PoolError> for ApiError {
    fn from(err: PoolError) -> Self {
        match err {
            PoolError::Store(err) => err.into(),
            // 409, not 400: the request is well formed and the state is wrong.
            PoolError::NotAllocated => Self::conflict(
                "not_allocated",
                "that employee holds no slot on that number",
            ),
            PoolError::NoAffinity => Self::new(
                StatusCode::NOT_FOUND,
                "no_affinity",
                "nothing reaches that counterparty on that number",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentos_app::gate::PolicyBook;
    use agentos_app::pool_ops::{Regulatory, slot_binding};
    use agentos_domain::employee::{Employee, Lifecycle, ResourceState, Step};
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::PolicyLimits;
    use agentos_store::employee as employee_store;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NUMBER: &str = "+33757590001";
    const SUPPLIER: &str = "+33612345678";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        /// `None` when there is no database. Every claim here is about RLS, the
        /// gate's own transaction, and rows — mocking those mocks the test.
        ///
        /// `allow_reassign` puts `pool/reassign` in the platform policy layer.
        /// With it false the gate denies by default, which is the behaviour an
        /// unconfigured deployment gets and therefore worth a test of its own.
        async fn new(allow_reassign: bool) -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; pool routes need a real Postgres");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");

            let mut limits = PolicyLimits::default();
            if allow_reassign {
                limits.allowed_mcp_tools = BTreeSet::from([tool()]);
            }
            let gate = PolicyGate::new(db.clone(), PolicyBook::new(limits));

            let pool = Pool::new()
                .with_number(
                    a,
                    PoolNumber::new(pooled(), "FR", 10).with_regulatory(Regulatory::Approved {
                        bundle: "BU-fr-1".to_owned(),
                    }),
                )
                .with_number(b, PoolNumber::new(pooled(), "FR", 10));

            Some(Self {
                app: crate::with_api_stack(router(db.clone(), gate, pool), db.clone(), keys),
                db,
                a,
                b,
            })
        }

        async fn get(&self, uri: &str, secret: Option<&str>) -> (StatusCode, Value) {
            self.send("GET", uri, secret, None).await
        }

        async fn post(&self, uri: &str, secret: &str, body: Value) -> (StatusCode, Value) {
            self.send("POST", uri, Some(secret), Some(body)).await
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: Option<&str>,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder().method(method).uri(uri);
            if let Some(secret) = secret {
                req = req.header(header::AUTHORIZATION, format!("Bearer {secret}"));
            }
            let req = match body {
                Some(body) => req
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string())),
                None => req.body(Body::empty()),
            }
            .expect("request");

            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        async fn teardown(self) {
            for tenant in [self.a, self.b] {
                let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
                sqlx::query("DELETE FROM tenants WHERE id = $1")
                    .bind(tenant.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .expect("delete tenant");
                tx.commit().await.expect("commit");
            }
        }
    }

    fn pooled() -> E164 {
        E164::parse(NUMBER).expect("e164")
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'pool-routes')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// An active employee holding a slot on the pooled number.
    async fn allocate(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let now = Utc::now();
        let id = EmployeeId::new_v7(now);
        let mut employee = Employee::new(
            id,
            tenant,
            Slug::parse(slug).expect("slug"),
            agentos_domain::action::Domain::parse("agents.example.com").expect("domain"),
            now,
        );
        employee
            .set_lifecycle(Lifecycle::Active, now)
            .expect("activate");
        employee
            .bind(Step::Phone, slot_binding(&pooled(), id), now)
            .expect("bind");
        for step in [Step::Identity, Step::Phone] {
            employee
                .set_resource(step, ResourceState::Provisioning, now)
                .and_then(|()| employee.set_resource(step, ResourceState::Ready, now))
                .expect("ready");
        }

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        employee_store::insert(&mut tx, &employee)
            .await
            .expect("insert");
        tx.commit().await.expect("commit");
        id
    }

    /// A conversation with `SUPPLIER`, `age_seconds` old.
    async fn talk(db: &Db, tenant: TenantId, employee: EmployeeId, age_seconds: i64) -> Uuid {
        let id = Uuid::now_v7();
        let when = Utc::now() - chrono::TimeDelta::seconds(age_seconds);
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO conversations \
                 (id, tenant_id, employee_id, channel, external_ref, created_at, updated_at) \
             VALUES ($1, $2, $3, 'sms', $4, $5, $5)",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid())
        .bind(SUPPLIER)
        .bind(when)
        .execute(&mut **tx)
        .await
        .expect("insert conversation");
        tx.commit().await.expect("commit");
        id
    }

    /// Where the next inbound from `SUPPLIER` on the pooled number would land.
    async fn lands_on(db: &Db, tenant: TenantId) -> Option<EmployeeId> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let owner = pool_ops::route_inbound(&mut tx, &pooled(), SUPPLIER)
            .await
            .expect("route");
        tx.rollback().await.expect("rollback");
        owner
    }

    // -- auth ---------------------------------------------------------------

    /// The stack answers before the handler does, so an unauthenticated caller
    /// never learns which numbers the tenant owns or who is on them.
    #[tokio::test]
    async fn no_credential_is_a_401_on_every_route() {
        let Some(h) = Harness::new(true).await else {
            return;
        };

        for uri in ["/v1/pool/numbers", "/v1/pool/routing"] {
            let (status, problem) = h.get(uri, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(problem["code"], "unauthenticated");
            assert_eq!(problem["numbers"], Value::Null, "the handler ran anyway");
        }

        let (status, _) = h
            .get("/v1/pool/numbers", Some("wrong-secret-wrong-secret"))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // The write is no different, and it is the one that matters.
        let alex = allocate(&h.db, h.a, "alex").await;
        let (status, _) = h
            .send(
                "POST",
                &format!("/v1/pool/numbers/{NUMBER}/reassign"),
                None,
                Some(json!({ "counterparty": SUPPLIER, "to_employee": alex.as_uuid() })),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        h.teardown().await;
    }

    // -- reads --------------------------------------------------------------

    /// A number nobody is on is still the tenant's number, and still listed.
    #[tokio::test]
    async fn a_number_lists_its_occupancy_and_survives_losing_everyone() {
        let Some(h) = Harness::new(true).await else {
            return;
        };
        let lena = allocate(&h.db, h.a, "lena").await;

        let (status, page) = h.get("/v1/pool/numbers", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        let row = page["numbers"][0].clone();
        assert_eq!(row["number"], NUMBER);
        assert_eq!(row["region"], "FR");
        assert_eq!(row["regulatory"], "approved");
        assert_eq!(row["bundle"], "BU-fr-1", "no bundle to chase: {row}");
        assert_eq!(row["capacity"], 10);
        assert_eq!(row["occupancy"], 1);
        assert_eq!(row["active"], 1);
        assert_eq!(row["employees"][0]["slug"], "lena");

        // The last employee leaves.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        pool_ops::release_slot(&mut tx, lena, Utc::now())
            .await
            .expect("release");
        tx.commit().await.expect("commit");

        let (status, page) = h.get("/v1/pool/numbers", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        let row = page["numbers"][0].clone();
        assert_eq!(
            row["number"], NUMBER,
            "the number vanished with its last occupant: {page}"
        );
        assert_eq!(row["occupancy"], 0);
        assert_eq!(row["employees"], json!([]));

        h.teardown().await;
    }

    /// Neither read may show one tenant anything about another.
    #[tokio::test]
    async fn both_reads_are_tenant_scoped() {
        let Some(h) = Harness::new(true).await else {
            return;
        };
        let mine = allocate(&h.db, h.a, "lena").await;
        let theirs = allocate(&h.db, h.b, "raj").await;
        talk(&h.db, h.a, mine, 3600).await;
        talk(&h.db, h.b, theirs, 3600).await;

        let (status, page) = h.get("/v1/pool/numbers", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["numbers"][0]["occupancy"], 1);
        assert_eq!(page["numbers"][0]["employees"][0]["slug"], "lena");
        assert!(
            !page.to_string().contains("raj"),
            "another tenant's employee is on our number: {page}"
        );

        let (status, page) = h.get("/v1/pool/routing", Some(SECRET_B)).await;
        assert_eq!(status, StatusCode::OK);
        let rows = page["routing"].as_array().expect("routing");
        assert_eq!(rows.len(), 1, "{page}");
        assert_eq!(rows[0]["employee_slug"], "raj");
        assert_eq!(rows[0]["counterparty"], SUPPLIER);
        assert_eq!(rows[0]["routable"], true);
        assert!(!page.to_string().contains(&mine.as_uuid().to_string()));

        // A junk cursor is the caller's mistake, not a 500.
        let (status, _) = h
            .get("/v1/pool/routing?after=not-a-uuid", Some(SECRET_A))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        h.teardown().await;
    }

    // -- reassign -----------------------------------------------------------

    /// The headline: gated, audited, and the next message lands somewhere else.
    #[tokio::test]
    async fn a_reassignment_is_gated_audited_and_moves_the_next_message() {
        let Some(h) = Harness::new(true).await else {
            return;
        };
        let lena = allocate(&h.db, h.a, "lena").await;
        let alex = allocate(&h.db, h.a, "alex").await;
        let thread = talk(&h.db, h.a, lena, 365 * 24 * 3600).await;
        assert_eq!(lands_on(&h.db, h.a).await, Some(lena));

        let (status, body) = h
            .post(
                &format!("/v1/pool/numbers/{NUMBER}/reassign"),
                SECRET_A,
                json!({ "counterparty": SUPPLIER, "to_employee": alex.as_uuid() }),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["to_employee"], alex.as_uuid().to_string());
        assert_eq!(body["conversations"][0], thread.to_string());
        assert_eq!(body["from_employees"][0], lena.as_uuid().to_string());
        let decision_id = body["decision_id"]
            .as_str()
            .expect("decision id")
            .to_owned();

        assert_eq!(
            lands_on(&h.db, h.a).await,
            Some(alex),
            "the supplier still reaches Lena"
        );

        // Two rows: the gate's ruling and what it permitted, joined by the id.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        let (kind, payload, decision): (String, Value, Option<String>) = sqlx::query_as(
            "SELECT action_kind, payload, decision FROM audit_log \
              WHERE decision_id = $1 AND action_kind = 'resource_state_changed'",
        )
        .bind(Uuid::parse_str(&decision_id).expect("uuid"))
        .fetch_one(&mut **tx)
        .await
        .expect("the handover was not audited");
        let ruled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log \
              WHERE decision_id = $1 AND action_kind = 'mcp_call' AND decision = 'allow'",
        )
        .bind(Uuid::parse_str(&decision_id).expect("uuid"))
        .fetch_one(&mut **tx)
        .await
        .expect("count");
        tx.rollback().await.expect("rollback");

        assert_eq!(kind, "resource_state_changed");
        assert_eq!(decision, None, "the handover row is not a gate ruling");
        assert_eq!(payload["number"], NUMBER);
        assert_eq!(payload["counterparty"], SUPPLIER);
        assert_eq!(payload["to_employee"], alex.as_uuid().to_string());
        assert_eq!(payload["from_employees"][0], lena.as_uuid().to_string());
        assert_eq!(
            payload["psyche_transferred"], false,
            "the audit row must say the judgement did not travel"
        );
        assert_eq!(ruled, 1, "the gate did not rule on this move");

        h.teardown().await;
    }

    /// Deny by default: an unconfigured policy refuses, and nothing moves.
    #[tokio::test]
    async fn an_ungated_deployment_cannot_reassign_anything() {
        let Some(h) = Harness::new(false).await else {
            return;
        };
        let lena = allocate(&h.db, h.a, "lena").await;
        let alex = allocate(&h.db, h.a, "alex").await;
        talk(&h.db, h.a, lena, 3600).await;

        let (status, problem) = h
            .post(
                &format!("/v1/pool/numbers/{NUMBER}/reassign"),
                SECRET_A,
                json!({ "counterparty": SUPPLIER, "to_employee": alex.as_uuid() }),
            )
            .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
        assert_eq!(problem["code"], "no_rule");
        assert_eq!(
            lands_on(&h.db, h.a).await,
            Some(lena),
            "a denied reassignment moved the supplier anyway"
        );

        h.teardown().await;
    }

    /// The three refusals a caller can provoke, none of them a 500.
    #[tokio::test]
    async fn a_bad_reassignment_is_refused_specifically() {
        let Some(h) = Harness::new(true).await else {
            return;
        };
        let lena = allocate(&h.db, h.a, "lena").await;
        let alex = allocate(&h.db, h.a, "alex").await;
        talk(&h.db, h.a, lena, 3600).await;
        let uri = format!("/v1/pool/numbers/{NUMBER}/reassign");

        // A number nobody declared. Not in the pool, so not this tenant's.
        let (status, _) = h
            .post(
                "/v1/pool/numbers/+33757599999/reassign",
                SECRET_A,
                json!({ "counterparty": SUPPLIER, "to_employee": alex.as_uuid() }),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Not E.164.
        let (status, _) = h
            .post(
                &uri,
                SECRET_A,
                json!({ "counterparty": "0612345678", "to_employee": alex.as_uuid() }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A counterparty nobody is talking to.
        let (status, problem) = h
            .post(
                &uri,
                SECRET_A,
                json!({ "counterparty": "+33698765432", "to_employee": alex.as_uuid() }),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(problem["code"], "no_affinity");

        // An employee that is not on this number. Mira gives her slot up first.
        let mira = allocate(&h.db, h.a, "mira").await;
        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        pool_ops::release_slot(&mut tx, mira, Utc::now())
            .await
            .expect("release");
        tx.commit().await.expect("commit");

        let (status, problem) = h
            .post(
                &uri,
                SECRET_A,
                json!({ "counterparty": SUPPLIER, "to_employee": mira.as_uuid() }),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{problem}");
        assert_eq!(problem["code"], "not_allocated");
        assert_eq!(lands_on(&h.db, h.a).await, Some(lena));

        h.teardown().await;
    }
}
