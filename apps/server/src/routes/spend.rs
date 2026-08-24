//! `/v1/employees/{id}/spend-caps`: the money ceilings, over HTTP.
//!
//! # The gap this closes
//!
//! [`agentos_store::spend::set_caps`] is the only writer of `spend_caps`, and
//! until this module every one of its call sites was inside a `#[cfg(test)]`
//! block. The reader, [`agentos_store::spend::caps`], is live and sits on the
//! Policy Gate's hot path. So in a shipped deployment the table was empty and
//! stayed empty.
//!
//! Absence **fails closed**, which is the one piece of luck in that story:
//! `caps` returns `Option<SpendCaps>`, `reserve` turns `None` into
//! `CapExceeded::NoCaps`, and the gate turns that into
//! `DenyReason::NoSpendPolicy`. An unconfigured deployment refused every
//! payment rather than allowing every payment. Nobody could spend a cent, and
//! nobody could raise the ceiling either — which is what this module is for.
//!
//! # What a route may not do
//!
//! **It may not take the tenant from the request.** It comes from
//! [`Principal`], i.e. from the API key, and every query runs inside
//! `Db::tenant_tx`. There is no `WHERE tenant_id` written by hand here: RLS
//! adds it, and a second copy is a second place to forget it.
//!
//! The one thing RLS does *not* cover is the employee id in the path.
//! Postgres runs referential-integrity checks with row security bypassed, so
//! `spend_caps`' foreign key on `employees` accepts any employee that exists
//! anywhere, and the row would be filed under the *caller's* `tenant_id` and
//! pass the `WITH CHECK`. [`employee_in_tenant`] is the `SELECT` that runs
//! under RLS and turns another tenant's employee into a 404 — never a 403,
//! which would confirm the id exists. `routes::teams` guards the same gap the
//! same way.
//!
//! **It may not invent a number.** Every value goes through the real
//! constructors: [`Money`] is `u64` minor units plus a currency and refuses
//! zero, `daily_transactions` is a `NonZeroU32`, and [`SpendCaps::new`]
//! refuses two currencies. All three refusals arrive as a 4xx, because they
//! happen in `serde` and in a `Result`, never in a panic.
//!
//! # Caps are per currency, and this endpoint is too
//!
//! A ceiling denominated in USD says nothing about a payment in JPY, so the
//! primary key is `(tenant, employee, currency)` and there is no way to spell
//! "all currencies". The currency of a `PUT` comes from the body's own money;
//! a `GET` names it in the query string, because there is no sensible default
//! to guess.
//!
//! # This is configuration, not enforcement
//!
//! Writing a cap does not touch `spend_buckets`. Lowering one does not claw
//! back what today has already reserved — it constrains what happens next. The
//! enforcement is `spend::reserve`, under a row lock, inside the transaction
//! that writes the payment; see the module docs of [`agentos_store::spend`]
//! for why a cap that is read here and acted on there would not be a cap.

use std::num::NonZeroU32;

use agentos_domain::ids::EmployeeId;
use agentos_domain::money::{Currency, Money};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::spend::{self, SpendCaps};
use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::put;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before any handler here.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/employees/{id}/spend-caps", put(put_caps).get(get_caps))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// `deny_unknown_fields`, so an operator who misspells a field finds out now
/// rather than wondering why the ceiling did not move. On this surface the
/// misspelled field is the one that would have tightened something.
///
/// Every field is a type that refuses what it must: `{"minor": 0}` is a
/// `MoneyError::Zero` inside `Money`'s own deserializer, and
/// `"daily_transactions": 0` is a `serde` error inside `NonZeroU32`. Both come
/// back as a 4xx from the `JsonRejection` arm, not from a check this handler
/// remembered to write.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetCaps {
    /// `{"minor": 30000, "currency": "EUR"}`. Ceiling on everything reserved
    /// in one day.
    daily_total: Money,
    /// Ceiling on any one payment. Must be in the same currency as
    /// `daily_total` — [`SpendCaps::new`] says so, and a daily total in EUR
    /// guarding a per-transaction max in USD is a cap that means nothing.
    per_transaction: Money,
    /// Ceiling on how many payments may be made in one day. The cap that
    /// actually stops one large payment being structured into many small legal
    /// ones. `NonZeroU32`, because "zero transactions allowed" has no spelling
    /// — the way to forbid spending is to have no caps row.
    daily_transactions: NonZeroU32,
}

/// `?currency=EUR`. Required for the same reason `routes::teams`' budget query
/// requires one: caps are per currency and there is nothing to default to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsQuery {
    currency: Currency,
}

/// What one employee may spend, in one currency.
#[derive(Debug, Serialize)]
struct CapsView {
    employee_id: Uuid,
    currency: Currency,
    /// `null` means **no caps row**, and that is not "unlimited" — it is *may
    /// not spend*. `spend::reserve` refuses outright with `NoCaps`, and the
    /// gate renders that as `no_spend_policy`.
    caps: Option<Caps>,
}

/// The three numbers, as stored.
#[derive(Debug, Serialize)]
struct Caps {
    daily_total: Money,
    per_transaction: Money,
    daily_transactions: NonZeroU32,
}

impl From<SpendCaps> for Caps {
    fn from(caps: SpendCaps) -> Self {
        Self {
            daily_total: caps.daily_total(),
            per_transaction: caps.per_transaction(),
            daily_transactions: caps.daily_transactions(),
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `PUT /v1/employees/{id}/spend-caps` — install or replace the ceilings for
/// one employee and currency.
///
/// Idempotent: `spend::set_caps` upserts, so re-running provisioning is not an
/// error and sending the same body twice is not a second cap.
///
/// The audit row is appended in the **same transaction** as the write, so a
/// ceiling that was changed without a trail is a ceiling that was not changed.
/// `AuditKind::PolicyChanged`, matching `routes::teams`: this is an operator's
/// key acting directly, no Policy Gate ruling authorised it, and `decision_id`
/// is therefore honestly `None`.
async fn put_caps(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
    body: Result<Json<SetCaps>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    // The one refusal `Money`'s own deserializer cannot make, because it needs
    // both amounts at once. Its message names only what the caller sent.
    let caps = SpendCaps::new(
        body.daily_total,
        body.per_transaction,
        body.daily_transactions,
    )
    .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let currency = caps.currency();

    let employee_id = EmployeeId::from_uuid(id);
    let now = Utc::now();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    employee_in_tenant(&mut tx, employee_id).await?;

    // Read before write, so the trail records what the ceiling *was*. An
    // operator answering "who lowered this and from what" has one row to read.
    let previous = spend::caps(&mut tx, employee_id, currency).await?;
    spend::set_caps(&mut tx, employee_id, caps).await?;
    audit::append(
        &mut tx,
        &AuditEvent {
            employee_id: Some(employee_id),
            payload: json!({
                "event": "spend.caps_set",
                "currency": currency.code(),
                "from": previous.map(|caps| json!({
                    "daily_total_minor": caps.daily_total().minor(),
                    "per_transaction_minor": caps.per_transaction().minor(),
                    "daily_transactions": caps.daily_transactions().get(),
                })),
                "daily_total_minor": caps.daily_total().minor(),
                "per_transaction_minor": caps.per_transaction().minor(),
                "daily_transactions": caps.daily_transactions().get(),
            }),
            ..AuditEvent::new(principal.actor.clone(), AuditKind::PolicyChanged, now)
        },
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        employee_id = %id,
        currency = currency.code(),
        daily_total_minor = caps.daily_total().minor(),
        per_transaction_minor = caps.per_transaction().minor(),
        daily_transactions = caps.daily_transactions().get(),
        "spend caps set"
    );
    Ok(Json(CapsView {
        employee_id: id,
        currency,
        caps: Some(caps.into()),
    })
    .into_response())
}

/// `GET /v1/employees/{id}/spend-caps?currency=EUR` — what is configured.
///
/// A cap nobody can read is a cap nobody can set: the first question after "why
/// was this payment refused?" is "what is the ceiling", and answering it by
/// opening psql against production means it does not get answered.
///
/// 200 with `caps: null` is the ordinary answer for an employee nobody has
/// configured yet. The 404 is for an employee that does not exist *in this
/// tenant*.
async fn get_caps(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
    query: Result<Query<CapsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;

    let employee_id = EmployeeId::from_uuid(id);
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    employee_in_tenant(&mut tx, employee_id).await?;
    let caps = spend::caps(&mut tx, employee_id, query.currency).await?;
    tx.rollback().await?;

    Ok(Json(CapsView {
        employee_id: id,
        currency: query.currency,
        caps: caps.map(Caps::from),
    })
    .into_response())
}

/// 404 unless this employee belongs to the caller's tenant. See the module
/// docs: the foreign key alone does not do this.
async fn employee_in_tenant(tx: &mut TenantTx<'_>, id: EmployeeId) -> Result<(), ApiError> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM employees WHERE id = $1")
        .bind(id.as_uuid())
        .fetch_optional(&mut ***tx)
        .await
        .map_err(StoreError::from)?
        .map(|_| ())
        .ok_or_else(ApiError::not_found)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentos_app::gate::{Denied, PolicyBook, PolicyGate, Principal as GatePrincipal};
    use agentos_domain::action::{Action, Channel};
    use agentos_domain::ids::TenantId;
    use agentos_domain::money::Currency::Eur;
    use agentos_domain::policy::{DenyReason, PolicyLimits, SpendLimits};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; spend-cap routes need a real Postgres");
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

            Some(Self {
                app: crate::with_api_stack(router(db.clone()), db.clone(), keys),
                db,
                a,
                b,
            })
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<&str>,
        ) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header(header::CONTENT_TYPE, "application/json");
            let req = req
                .body(body.map_or_else(Body::empty, |b| Body::from(b.to_owned())))
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

        async fn put(&self, id: Uuid, secret: &str, body: &str) -> (StatusCode, Value) {
            self.send(
                "PUT",
                &format!("/v1/employees/{id}/spend-caps"),
                secret,
                Some(body),
            )
            .await
        }

        async fn get(&self, id: Uuid, secret: &str, currency: &str) -> (StatusCode, Value) {
            self.send(
                "GET",
                &format!("/v1/employees/{id}/spend-caps?currency={currency}"),
                secret,
                None,
            )
            .await
        }

        /// Every `policy_changed` audit row for this employee, oldest first.
        async fn caps_audit(&self, tenant: TenantId, id: Uuid) -> Vec<Value> {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let rows: Vec<(Value,)> = sqlx::query_as(
                "SELECT payload FROM audit_log \
                  WHERE employee_id = $1 AND action_kind = 'policy_changed' \
                  ORDER BY occurred_at, id",
            )
            .bind(id)
            .fetch_all(&mut **tx)
            .await
            .expect("read audit");
            tx.rollback().await.expect("rollback");
            rows.into_iter().map(|(payload,)| payload).collect()
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

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'spend-caps-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn employee(db: &Db, tenant: TenantId, slug: &str) -> Uuid {
        let id = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    /// A gate whose *policy* is wide open for money — €250 per payment, €300
    /// per day, a human only above €250. Everything these tests refuse is
    /// therefore refused by the **ledger**, which is the thing the route
    /// writes, rather than by a policy layer that never left memory.
    ///
    /// Deliberately an in-memory `PolicyBook`, exactly as `gate.rs`'s own tests
    /// build one: the policy loader is another unit's work in flight, and this
    /// test is about `spend_caps`.
    fn gate(db: &Db) -> PolicyGate {
        let limits = PolicyLimits {
            spend: Some(
                SpendLimits::try_new(
                    Money::new(25_000, Eur).expect("nonzero"),
                    Money::new(30_000, Eur).expect("nonzero"),
                    Money::new(25_000, Eur).expect("nonzero"),
                )
                .expect("coherent"),
            ),
            allowed_channels: BTreeSet::from([Channel::Email]),
            ..PolicyLimits::default()
        };
        PolicyGate::new(db.clone(), PolicyBook::new(limits))
    }

    fn payment(minor: u64) -> Action {
        Action::PaymentCreate {
            amount: Money::new(minor, Eur).expect("nonzero"),
        }
    }

    /// The body an operator sends.
    fn caps_body(daily_total: u64, per_transaction: u64, daily_transactions: u32) -> String {
        json!({
            "daily_total": {"minor": daily_total, "currency": "EUR"},
            "per_transaction": {"minor": per_transaction, "currency": "EUR"},
            "daily_transactions": daily_transactions,
        })
        .to_string()
    }

    // -----------------------------------------------------------------------

    /// The whole point: what the route writes is what the gate enforces.
    ///
    /// Three states in one test because the interesting thing is the
    /// transitions between them — a cap that only ever refuses proves nothing
    /// about whether the gate read it.
    #[tokio::test]
    async fn a_cap_set_through_the_route_is_the_cap_the_gate_enforces() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = employee(&h.db, h.a, "lena").await;
        let gate = gate(&h.db);
        let principal = GatePrincipal::employee(h.a, EmployeeId::from_uuid(id));

        // 1. Unconfigured. This is what every shipped deployment looked like
        //    before this module existed: the table is empty, and empty means
        //    refused. Fails closed, and the operator has no way to change it.
        let refusal = gate
            .authorize(&principal, payment(10_000))
            .await
            .expect_err("no caps row means no spending");
        assert!(
            matches!(refusal, Denied::Policy(DenyReason::NoSpendPolicy)),
            "{refusal}"
        );
        let (status, body) = h.get(id, SECRET_A, "EUR").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["caps"], Value::Null, "null is not unlimited");

        // 2. The operator sets a ceiling, and the very next decision honours
        //    it. Nothing in between reloads anything: `spend::reserve` reads
        //    the row inside the deciding transaction.
        let (status, body) = h.put(id, SECRET_A, &caps_body(30_000, 25_000, 5)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["caps"]["daily_total"]["minor"], 30_000);
        assert_eq!(body["caps"]["per_transaction"]["minor"], 25_000);
        assert_eq!(body["caps"]["daily_transactions"], 5);

        gate.authorize(&principal, payment(10_000))
            .await
            .expect("a €100 payment fits a €250 per-transaction cap");

        // 3. The operator tightens it below that payment, and the same payment
        //    is now refused — by the number the route wrote, on the ledger's
        //    own terms.
        let (status, body) = h.put(id, SECRET_A, &caps_body(30_000, 5_000, 5)).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let refusal = gate
            .authorize(&principal, payment(10_000))
            .await
            .expect_err("€100 is over the €50 the route just set");
        assert!(
            matches!(refusal, Denied::Policy(DenyReason::PerTransactionLimit)),
            "{refusal}"
        );

        // And the read-back agrees with what the gate just enforced.
        let (_, body) = h.get(id, SECRET_A, "EUR").await;
        assert_eq!(body["caps"]["per_transaction"]["minor"], 5_000);

        // Two writes, two audit rows, in the same transactions as the writes —
        // the second one names the ceiling it replaced.
        let trail = h.caps_audit(h.a, id).await;
        assert_eq!(trail.len(), 2, "one row per write: {trail:?}");
        assert_eq!(trail[0]["event"], "spend.caps_set");
        assert_eq!(
            trail[0]["from"],
            Value::Null,
            "the first write had no prior"
        );
        assert_eq!(trail[0]["per_transaction_minor"], 25_000);
        assert_eq!(trail[1]["from"]["per_transaction_minor"], 25_000);
        assert_eq!(trail[1]["per_transaction_minor"], 5_000);
        assert_eq!(trail[1]["currency"], "EUR");

        h.teardown().await;
    }

    /// A cap is a security control, so the isolation is the security property.
    /// B holds a valid credential and the real employee id and still learns
    /// nothing — a 403 would confirm the employee exists.
    #[tokio::test]
    async fn one_tenant_can_neither_read_nor_write_anothers_caps() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = employee(&h.db, h.a, "lena").await;
        h.put(id, SECRET_A, &caps_body(30_000, 25_000, 5)).await;

        let (status, _) = h.get(id, SECRET_B, "EUR").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = h.put(id, SECRET_B, &caps_body(90_000, 90_000, 99)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The refused write left nothing behind. Without the existence check
        // this row would have been filed under B's tenant against A's
        // employee: the foreign key is checked with row security bypassed, so
        // it would have been accepted.
        let mut tx = h.db.admin_tx_bypassing_rls().await.expect("admin tx");
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM spend_caps WHERE employee_id = $1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .expect("count caps");
        tx.rollback().await.expect("rollback");
        assert_eq!(rows, 1, "B's write must not have created a second row");

        // A's own numbers are untouched.
        let (_, body) = h.get(id, SECRET_A, "EUR").await;
        assert_eq!(body["caps"]["per_transaction"]["minor"], 25_000);

        // An id nobody owns reads identically.
        let (status, _) = h.get(Uuid::now_v7(), SECRET_A, "EUR").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        h.teardown().await;
    }

    /// `Money` and `NonZeroU32` refuse zero, negatives and mixed currencies.
    /// Every one of those refusals has to arrive as a 4xx problem document —
    /// an `unwrap` on any of them would be a 500 at best and a panicked worker
    /// at worst.
    #[tokio::test]
    async fn the_constructors_refusals_arrive_as_4xx_and_write_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = employee(&h.db, h.a, "lena").await;

        let bad = [
            // Zero, which `Money::new` has no representation for.
            (
                "zero daily total",
                json!({"daily_total": {"minor": 0, "currency": "EUR"},
                       "per_transaction": {"minor": 100, "currency": "EUR"},
                       "daily_transactions": 5}),
            ),
            (
                "zero per transaction",
                json!({"daily_total": {"minor": 100, "currency": "EUR"},
                       "per_transaction": {"minor": 0, "currency": "EUR"},
                       "daily_transactions": 5}),
            ),
            // Zero transactions a day: `NonZeroU32` refuses it, and the way to
            // forbid spending is to have no row at all.
            (
                "zero transactions",
                json!({"daily_total": {"minor": 100, "currency": "EUR"},
                       "per_transaction": {"minor": 100, "currency": "EUR"},
                       "daily_transactions": 0}),
            ),
            // Negative and fractional minor units: `u64` has neither.
            (
                "negative",
                json!({"daily_total": {"minor": -1, "currency": "EUR"},
                       "per_transaction": {"minor": 100, "currency": "EUR"},
                       "daily_transactions": 5}),
            ),
            (
                "float",
                json!({"daily_total": {"minor": 100.5, "currency": "EUR"},
                       "per_transaction": {"minor": 100, "currency": "EUR"},
                       "daily_transactions": 5}),
            ),
            // Two currencies: the refusal `SpendCaps::new` exists to make.
            (
                "mixed currency",
                json!({"daily_total": {"minor": 30000, "currency": "EUR"},
                       "per_transaction": {"minor": 100, "currency": "USD"},
                       "daily_transactions": 5}),
            ),
            (
                "unknown currency",
                json!({"daily_total": {"minor": 30000, "currency": "XYZ"},
                       "per_transaction": {"minor": 100, "currency": "XYZ"},
                       "daily_transactions": 5}),
            ),
            // A misspelled field is a rejected request, not a silent no-op.
            (
                "unknown field",
                json!({"daily_total": {"minor": 30000, "currency": "EUR"},
                       "per_transaction": {"minor": 100, "currency": "EUR"},
                       "daily_transactions": 5,
                       "daily_totl": 1}),
            ),
        ];

        for (what, body) in bad {
            let (status, problem) = h.put(id, SECRET_A, &body.to_string()).await;
            assert!(
                status.is_client_error(),
                "{what}: expected 4xx, got {status} {problem}"
            );
        }

        // Not one of them wrote a row, so a refused ceiling is not a ceiling.
        let (_, body) = h.get(id, SECRET_A, "EUR").await;
        assert_eq!(body["caps"], Value::Null);

        // A currency the query string cannot parse is the caller's 400, not a
        // 500 from a handler that assumed.
        let (status, _) = h.get(id, SECRET_A, "XYZ").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        h.teardown().await;
    }
}
