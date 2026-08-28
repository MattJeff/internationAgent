//! `/v1/invoices`: the founder's half of the register — read what is owed, and
//! say when it arrived.
//!
//! `migrations/0066_invoices.sql` argues for the table and
//! [`agentos_store::invoices`] is the SQL. This is the only surface that reads
//! either, and the only one that writes `paid_at`.
//!
//! # There is no `POST /v1/invoices`, and that is the design
//!
//! `routes::work` and `routes::calendar` both let an operator create the thing
//! their internal tool is about, because a work item and an appointment are
//! things a founder writes down. An invoice is not: **the only way one exists is
//! `Effects::issue_invoice`, holding a token the Policy Gate minted for an
//! employee.** So issuing leaves a `provider_call_attempted` row linked to the
//! ruling that permitted it, every time, with no second path that does not.
//!
//! An operator route here would be that second path — a demand for money with no
//! decision behind it, indistinguishable in the table from one an employee was
//! authorised to make. `work_items` accepted exactly that ambiguity and paid for
//! it with `0064`'s `posted_by` column; this table declines it up front, which
//! is why `invoices.issued_by` is NOT NULL.
//!
//! The cost is real and is the founder's to switch on: until the `issue_invoice`
//! tool row lands in `agentos_app::turn::catalogue` — written out there
//! verbatim, unapplied, because it moves two pinned digests — no employee can
//! reach the effect from a turn, so the register fills only from Rust. The
//! endpoint that would paper over that is the one this module refuses to be.
//!
//! # Why `paid` is an operator's and never an employee's
//!
//! Nothing in this process can call a bank or a PSP, so "it was paid" is not
//! observed here, it is asserted. The seat that issued an invoice must not be
//! the thing that records the money arriving — an employee that could settle its
//! own receivables has a clean ledger and no revenue — so the assertion comes
//! from the same authority that writes charters and cadences: an API key, not a
//! principal the gate rules on.
//!
//! That is also why there is no `ActionKind::InvoicePaid`. The day a PSP webhook
//! writes it (`routes::webhooks` already verifies signatures and stores raw
//! deliveries) the writer is still not an employee.
//!
//! # No `paid_by` and no audit row
//!
//! `routes::work`'s reason before `0064`, and here it has not stopped being
//! true: every writer of `paid_at` holds an operator key, so the answer would be
//! the same string on every row, and `AuditKind` is a closed vocabulary of
//! *rulings* — a row there for something no gate ruled on would be a decision
//! with no decision in it. The record that survives is the column itself, which
//! `0066`'s trigger makes unwithdrawable.

use agentos_domain::ids::InvoiceId;
use agentos_store::db::Db;
use agentos_store::invoices;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the rate
/// limit and the idempotency layer from `with_api_stack`.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/invoices", get(register))
        .route("/v1/invoices/{id}/paid", post(paid))
        .with_state(db)
}

/// One invoice, as the founder reads it back.
///
/// The amount is split back into minor units and a code rather than rendered,
/// for `routes::billing`'s reason one product along: a formatted figure is a
/// presentation decision, and this endpoint reports what it measured.
#[derive(Serialize)]
struct InvoiceView {
    id: Uuid,
    /// The won deal it bills.
    opportunity_id: Uuid,
    /// The seat that issued it.
    issued_by: Uuid,
    amount_minor: u64,
    currency: &'static str,
    memo: String,
    issued_at: DateTime<Utc>,
    /// When somebody declared the money had arrived. Null is outstanding.
    paid_at: Option<DateTime<Utc>>,
}

impl From<invoices::Invoice> for InvoiceView {
    fn from(invoice: invoices::Invoice) -> Self {
        Self {
            id: invoice.id.as_uuid(),
            opportunity_id: invoice.opportunity_id,
            issued_by: invoice.issued_by.as_uuid(),
            amount_minor: invoice.amount.minor(),
            currency: invoice.amount.currency().code(),
            memo: invoice.memo,
            issued_at: invoice.issued_at,
            paid_at: invoice.paid_at,
        }
    }
}

/// `GET /v1/invoices` — everything this company has issued, oldest first.
///
/// Settled and outstanding together, and no filter, for `GET /v1/work`'s and
/// `GET /v1/calendar`'s reason: what somebody wants at the end of a month is
/// what is outstanding *and* what came in, and a list that hid the second half
/// would make the first look like nothing had happened.
///
/// `outstanding_minor` is a sum per currency and not one number, because there
/// is no exchange rate in this workspace and there must not be one — the same
/// refusal `SpendLimits` makes by rejecting mixed currencies outright.
async fn register(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let all = invoices::register(&mut tx).await?;
    tx.rollback().await?;

    let mut outstanding: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    for invoice in &all {
        if invoice.paid_at.is_none() {
            // Saturating, and it is not laziness: the alternative is a 500 on a
            // read, and a register that refuses to display itself because the
            // total overflowed a u64 is worse than a total that is visibly
            // wrong. Nothing branches on this number.
            let entry = outstanding
                .entry(invoice.amount.currency().code())
                .or_default();
            *entry = entry.saturating_add(invoice.amount.minor());
        }
    }

    Ok(Json(json!({
        "invoices": all.into_iter().map(InvoiceView::from).collect::<Vec<_>>(),
        "outstanding_minor": outstanding,
    }))
    .into_response())
}

/// `POST /v1/invoices/{id}/paid` — the money arrived.
///
/// No body. The instant is the server's, not the caller's, and that is the
/// decision rather than an omission: a caller-supplied date would be the first
/// thing to be wrong, it would need a rule about how far back it may reach, and
/// `0066` has no value-date column for it to mean. When a PSP webhook brings a
/// real value date it brings the column with it.
///
/// 404 when the invoice is not this company's, does not exist, **or was already
/// settled**. The three are one answer on purpose: the first two are RLS's usual
/// silence, and the third is somebody being second — a settlement is declared
/// once and is never withdrawn or re-dated, which `0066`'s trigger enforces
/// underneath this and `invoices::declare_paid`'s `WHERE` reports as `false`.
async fn paid(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let settled = invoices::declare_paid(&mut tx, InvoiceId::from_uuid(id), Utc::now()).await?;
    if !settled {
        // Rolled back rather than committed: nothing was written, and a pooled
        // connection goes back deliberately.
        tx.rollback().await?;
        return Err(
            ApiError::not_found().with_detail("no outstanding invoice by that id in this company")
        );
    }
    tx.commit().await?;

    Ok(Json(json!({ "id": id, "state": "paid" })).into_response())
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::money::{Currency, Money};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY};

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Two companies behind two keys, under the real middleware stack.
    /// `routes::calendar`'s harness, and the second company is the point: a
    /// register another tenant can settle is not a register.
    struct Harness {
        app: Router,
        a: TenantId,
    }

    impl Harness {
        async fn new(db: &Db) -> Self {
            let a = new_tenant(db).await;
            let b = new_tenant(db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            // `b` is not kept: what the second company is for is its *key*,
            // which the tests use to prove that another tenant's register is
            // invisible and unsettleable. Holding its id would be a field
            // nothing reads.
            let _ = b;
            Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    Keyring::new(keys, db.clone(), TEST_MASTER_KEY),
                ),
                a,
            }
        }

        async fn send(&self, method: &str, uri: &str, secret: &str) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header("idempotency-key", Uuid::now_v7().to_string())
                .body(Body::empty())
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
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'invoice-routes-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// One issued invoice for `tenant`, through the same store call the gated
    /// effect uses — there is no operator route that issues, and that absence is
    /// the module's design rather than a gap in this fixture.
    async fn issued(db: &Db, tenant: TenantId) -> InvoiceId {
        let employee = EmployeeId::new_v7(Utc::now());
        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'Lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(format!(
            "lena-{}",
            &employee.as_uuid().simple().to_string()[..8]
        ))
        .execute(&mut *tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Buyer plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("buyer-{}.example", account.simple()))
        .execute(&mut *tx)
        .await
        .expect("account");
        sqlx::query(
            "INSERT INTO opportunities \
                 (id, tenant_id, account_id, stage, currency, value_minor, approval_id, closed_at) \
             VALUES ($1, $2, $3, 'closed_won', 'EUR', 120000, $4, now())",
        )
        .bind(opportunity)
        .bind(tenant.as_uuid())
        .bind(account)
        .bind(Uuid::now_v7())
        .execute(&mut *tx)
        .await
        .expect("opportunity");
        tx.commit().await.expect("commit the deal");

        let id = InvoiceId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        invoices::issue(
            &mut tx,
            id,
            opportunity,
            employee,
            Money::new(120_000, Currency::Eur).expect("nonzero"),
            "March",
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit the invoice");
        id
    }

    /// **The encashment, end to end, and the two things that must not happen
    /// after it**: it cannot be declared twice, and another company cannot
    /// declare it at all.
    #[tokio::test]
    async fn a_settlement_is_declared_once_and_only_by_the_company_that_is_owed() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the register needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let invoice = issued(&db, h.a).await;
        let uri = format!("/v1/invoices/{}/paid", invoice.as_uuid());

        let (status, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["invoices"].as_array().expect("array").len(), 1);
        assert_eq!(body["invoices"][0]["paid_at"], Value::Null);
        assert_eq!(body["outstanding_minor"]["EUR"], json!(120_000));

        // Another company's key: the same silence a request for an invoice that
        // does not exist gets, because under RLS the two are the same fact.
        let (status, _) = h.send("POST", &uri, SECRET_B).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // And it saw nothing either.
        let (_, theirs) = h.send("GET", "/v1/invoices", SECRET_B).await;
        assert!(theirs["invoices"].as_array().expect("array").is_empty());

        let (status, body) = h.send("POST", &uri, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], json!("paid"));

        // Twice is not a second settlement. Same code as "no such invoice", on
        // purpose: both mean "there is no outstanding invoice here to settle".
        let (status, _) = h.send("POST", &uri, SECRET_A).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        assert_ne!(body["invoices"][0]["paid_at"], Value::Null);
        assert_eq!(
            body["outstanding_minor"].as_object().expect("object").len(),
            0,
            "a settled invoice is not owed"
        );
        // The register still shows it: what came in is half of what a founder
        // reads at the end of a month.
        assert_eq!(body["invoices"].as_array().expect("array").len(), 1);
    }
}
