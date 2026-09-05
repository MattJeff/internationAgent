//! A Stripe delivery settles an invoice: the fourth webhook scheme, and the
//! first that writes money *in*.
//!
//! `POST /v1/webhooks/{path}` verifies and stores; `main::on_stripe_webhook`
//! reads the stored row and calls [`record_stripe_payment`]. Same two halves,
//! same reasons, as the three schemes before it (`routes::webhooks` carries the
//! argument). What this module adds is the reading.
//!
//! # Which tenant
//!
//! The one the endpoint belongs to. A `webhook_endpoints` row (0053) is one
//! per `(tenant, provider)` behind an opaque path, and the handler runs in
//! `tenant_tx(endpoint.tenant_id)` — so an invoice number in the payload is
//! looked up under RLS and can only ever resolve to *that* company's document.
//! Two tenants with the same Stripe account are two endpoints; a delivery on
//! B's path naming A's invoice number finds B's invoice of that number or
//! nothing. That is the whole of the cross-tenant argument, and
//! `tenant_b_cannot_settle_tenant_a_s_invoice` is the test.
//!
//! # Which event, and why only one
//!
//! `checkout.session.completed` with `payment_status = "paid"`. A Checkout
//! Session is the one Stripe object a company can create with a plain link,
//! attach `metadata.invoice_number` to, and hand a customer — no Stripe
//! invoice, no customer object, no subscription. Its `amount_total` and
//! `currency` are the figures to compare against ours. `invoice.paid` is
//! Stripe's *own* invoicing product, which this register replaces;
//! `payment_intent.succeeded` fires for every Checkout too but carries the
//! session's metadata only if somebody copied it there. One event, one field
//! ([`INVOICE_NUMBER_KEY`]), documented in `docs/RUNNING.md`.
//!
//! # The figure is compared, and a mismatch pays nothing
//!
//! Stripe's `amount_total` is in the currency's minor unit, which is what
//! `invoices.amount_minor` is. Equal and same currency: `declare_paid`, and an
//! `invoice_paid` audit row carrying the Stripe event id. Anything else: an
//! `invoice_payment_mismatch` row carrying both figures, and the invoice stays
//! outstanding for a person to look at. A partial payment marked paid would be
//! a receivable that vanished from the register.
//!
//! # Replays
//!
//! Three locks, none of them here: `outbox::enqueue` collapses a redelivery
//! onto the first row (the event id is in the dedupe key); `declare_paid`'s
//! `WHERE paid_at IS NULL` makes a second read a no-op that returns `false`;
//! and the audit row is written only when that returned `true`. The
//! signature's timestamp window ([`TOLERANCE_SECS`]) is Stripe's own
//! recommendation and is a fourth, weaker lock on top.

use agentos_domain::ids::InvoiceId;
use agentos_providers::Secret;
use agentos_providers::email::SigError;
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::TenantTx;
use agentos_store::invoices;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::inbound::{InboundError, body_digest, body_hex, ct_eq};

/// The endpoint `provider` whose deliveries are verified here and read by
/// `main::on_stripe_webhook`. `0081` widens
/// `webhook_endpoints_provider_is_wired` to it.
pub const STRIPE_PROVIDER: &str = "stripe";

/// Where Stripe puts its signature: `t=<unix>,v1=<hex>[,v1=<hex>…]`
/// (<https://docs.stripe.com/webhooks#verify-manually>).
pub const STRIPE_SIGNATURE_HEADER: &str = "stripe-signature";

/// How old a signed timestamp may be. Stripe's own default.
pub const TOLERANCE_SECS: i64 = 300;

/// The event this reader acts on.
pub const PAID_EVENT: &str = "checkout.session.completed";

/// The metadata key a Checkout Session carries to name our invoice, as a
/// decimal string: `metadata: { invoice_number: "42" }`.
pub const INVOICE_NUMBER_KEY: &str = "invoice_number";

/// Stripe's signature over `"{timestamp}.{raw}"`, in the header's own spelling.
///
/// Exported for the tests on the route and for a deployment's own smoke check;
/// the verifier below is what a delivery meets.
pub fn sign_stripe_webhook(secret: &Secret, timestamp: i64, raw_body: &[u8]) -> String {
    format!("t={timestamp},v1={}", mac(secret, timestamp, raw_body))
}

fn mac(secret: &Secret, timestamp: i64, raw_body: &[u8]) -> String {
    use hmac::Mac as _;

    let mut mac =
        <hmac::Hmac<sha2::Sha256>>::new_from_slice(secret.expose_for_transport().as_bytes())
            .expect("HMAC-SHA256 takes a key of any length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    body_hex(&mac.finalize().into_bytes())
}

/// Authenticate a Stripe delivery and name the id a replay collapses onto.
///
/// The id is the event's own `id` (`evt_…`) read off the body **after** the
/// MAC over that body passed, so it is authenticated; a body with no readable
/// id dedupes on its digest, like the two schemes with no id header. Any of
/// several `v1` signatures matching is enough — Stripe sends more than one
/// during a secret rotation.
pub fn verify_stripe_webhook(
    secret: &Secret,
    header: &str,
    raw_body: &[u8],
    now: DateTime<Utc>,
) -> Result<String, SigError> {
    let header = header.trim();
    if header.is_empty() {
        return Err(SigError::MissingHeader);
    }
    let mut timestamp: Option<i64> = None;
    let mut presented: Vec<&str> = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", value)) => timestamp = value.parse().ok(),
            Some(("v1", value)) => presented.push(value),
            _ => {}
        }
    }
    let Some(timestamp) = timestamp else {
        return Err(SigError::Malformed);
    };
    if presented.is_empty() {
        return Err(SigError::Malformed);
    }
    if (now.timestamp() - timestamp).abs() > TOLERANCE_SECS {
        return Err(SigError::Stale);
    }
    let expected = mac(secret, timestamp, raw_body);
    // Every candidate is compared, none short-circuits: the loop's length is
    // the header's, not the secret's.
    let mut matched = false;
    for candidate in presented {
        matched |= ct_eq(
            expected.as_bytes(),
            candidate.to_ascii_lowercase().as_bytes(),
        );
    }
    if !matched {
        return Err(SigError::Mismatch);
    }
    let id = serde_json::from_slice::<Value>(raw_body)
        .ok()
        .and_then(|body| body.get("id")?.as_str().map(str::to_owned))
        .filter(|id| !id.is_empty());
    Ok(id.unwrap_or_else(|| body_digest(raw_body)))
}

/// What a verified delivery did to the register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// The figure matched and the invoice is now paid.
    Paid(InvoiceId),
    /// The figure did not match; nothing was marked and a person has a row to
    /// read.
    Mismatch(InvoiceId),
    /// Paid already, or a credit note: the register did not move.
    AlreadySettled(InvoiceId),
    /// An event this reader does not act on, a session not yet paid, or a
    /// number that names no invoice of this company.
    NotOurs,
}

/// Read one stored Stripe delivery against this tenant's register.
///
/// `event_id` is the authenticated id `verify_stripe_webhook` produced, and it
/// goes on the audit row so a settlement can be traced to Stripe's dashboard.
/// A body that is not JSON is [`InboundError::BadNotice`], terminal — the
/// bytes will not become JSON on the eighth retry.
pub async fn record_stripe_payment(
    tx: &mut TenantTx<'_>,
    raw_body: &[u8],
    event_id: &str,
    now: DateTime<Utc>,
) -> Result<Settlement, InboundError> {
    let payload: Value = serde_json::from_slice(raw_body)
        .map_err(|_| InboundError::BadNotice("this Stripe delivery is not JSON"))?;

    // Third-party text, compared against constants and never rendered.
    if payload.get("type").and_then(Value::as_str) != Some(PAID_EVENT) {
        return Ok(Settlement::NotOurs);
    }
    let session = &payload["data"]["object"];
    if session.get("payment_status").and_then(Value::as_str) != Some("paid") {
        return Ok(Settlement::NotOurs);
    }
    let Some(number) = session["metadata"]
        .get(INVOICE_NUMBER_KEY)
        .and_then(Value::as_str)
        .and_then(|raw| raw.trim().parse::<i64>().ok())
    else {
        return Ok(Settlement::NotOurs);
    };
    let Some(invoice) = invoices::find_by_number(tx, number).await? else {
        return Ok(Settlement::NotOurs);
    };

    let paid_minor = session.get("amount_total").and_then(Value::as_i64);
    let paid_currency = session
        .get("currency")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_minor = i64::try_from(invoice.amount.minor()).ok();
    let matches = paid_minor.is_some()
        && paid_minor == expected_minor
        && paid_currency.eq_ignore_ascii_case(invoice.amount.currency().code());

    let mut row = AuditEvent::new(AuditActor::System, AuditKind::InvoicePaid, now);
    row.payload = json!({
        "invoice_id": invoice.id.to_string(),
        "number": invoice.number,
        "stripe_event_id": event_id,
        "expected_minor": invoice.amount.minor(),
        "currency": invoice.amount.currency().code(),
        "paid_minor": paid_minor,
        "paid_currency": paid_currency,
    });

    if !matches {
        row.kind = AuditKind::InvoicePaymentMismatch;
        audit::append(tx, &row).await?;
        return Ok(Settlement::Mismatch(invoice.id));
    }
    if !invoices::declare_paid(tx, invoice.id, now).await? {
        return Ok(Settlement::AlreadySettled(invoice.id));
    }
    audit::append(tx, &row).await?;
    Ok(Settlement::Paid(invoice.id))
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::money::{Currency, Money};
    use agentos_store::db::Db;
    use sqlx::Row as _;
    use uuid::Uuid;

    use super::*;

    const SECRET: &str = "whsec_test_stripe_signing_secret";

    fn body(number: &str, amount: i64, currency: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"evt_1","type":"checkout.session.completed","data":{{"object":{{"payment_status":"paid","amount_total":{amount},"currency":"{currency}","metadata":{{"invoice_number":"{number}"}}}}}}}}"#
        )
        .into_bytes()
    }

    // -- the signature, pure --------------------------------------------------

    #[test]
    fn a_signature_over_the_timestamp_and_the_body_names_the_event() {
        let secret = Secret::new(SECRET);
        let now = Utc::now();
        let raw = body("42", 120_000, "eur");
        let header = sign_stripe_webhook(&secret, now.timestamp(), &raw);
        assert_eq!(
            verify_stripe_webhook(&secret, &header, &raw, now),
            Ok("evt_1".to_owned())
        );
        // A rotation sends two `v1`s; one good one is enough.
        let rotated = format!("{header},v1={}", "0".repeat(64));
        assert!(verify_stripe_webhook(&secret, &rotated, &raw, now).is_ok());
    }

    #[test]
    fn a_forged_stale_or_missing_signature_is_refused() {
        let secret = Secret::new(SECRET);
        let now = Utc::now();
        let raw = body("42", 120_000, "eur");
        let header = sign_stripe_webhook(&secret, now.timestamp(), &raw);
        assert_eq!(
            verify_stripe_webhook(&Secret::new("whsec_other"), &header, &raw, now),
            Err(SigError::Mismatch)
        );
        let mut tampered = raw.clone();
        tampered[10] ^= 1;
        assert_eq!(
            verify_stripe_webhook(&secret, &header, &tampered, now),
            Err(SigError::Mismatch)
        );
        let old = now.timestamp() - TOLERANCE_SECS - 1;
        let stale = sign_stripe_webhook(&secret, old, &raw);
        assert_eq!(
            verify_stripe_webhook(&secret, &stale, &raw, now),
            Err(SigError::Stale)
        );
        assert_eq!(
            verify_stripe_webhook(&secret, "", &raw, now),
            Err(SigError::MissingHeader)
        );
        assert_eq!(
            verify_stripe_webhook(&secret, "v1=abc", &raw, now),
            Err(SigError::Malformed)
        );
    }

    // -- the settlement, against Postgres -------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; settlement tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one employee, one won deal, and one invoice of EUR
    /// 1200.00 against it. Returns the tenant and the invoice.
    async fn invoiced_tenant(db: &Db) -> (TenantId, invoices::Invoice) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("stripe-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");

        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Buyer plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("buyer-{}.example", account.simple()))
        .execute(&mut **tx)
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
        .execute(&mut **tx)
        .await
        .expect("opportunity");
        let invoice = invoices::issue(
            &mut tx,
            invoices::Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: opportunity,
                issued_by: employee,
                amount: Money::new(120_000, Currency::Eur).expect("nonzero"),
                memo: "March",
                due_at: None,
                lines: &[],
            },
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit");
        (tenant, invoice)
    }

    async fn paid_at(db: &Db, tenant: TenantId, id: InvoiceId) -> Option<DateTime<Utc>> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let found = invoices::find(&mut tx, id).await.expect("find");
        tx.rollback().await.expect("rollback");
        found.expect("the invoice exists").paid_at
    }

    /// `(kind, stripe_event_id)` of every settlement row this tenant has.
    async fn trail(db: &Db, tenant: TenantId) -> Vec<(String, Value)> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let rows = sqlx::query(
            "SELECT action_kind, payload FROM audit_log \
              WHERE action_kind IN ('invoice_paid', 'invoice_payment_mismatch') \
              ORDER BY occurred_at, id",
        )
        .fetch_all(&mut **tx)
        .await
        .expect("audit");
        tx.rollback().await.expect("rollback");
        rows.iter()
            .map(|row| (row.get("action_kind"), row.get("payload")))
            .collect()
    }

    async fn settle(db: &Db, tenant: TenantId, raw: &[u8]) -> Settlement {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let settled = record_stripe_payment(&mut tx, raw, "evt_1", Utc::now())
            .await
            .expect("read the delivery");
        tx.commit().await.expect("commit");
        settled
    }

    #[tokio::test]
    async fn a_paid_checkout_naming_the_invoice_settles_it_once() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let raw = body(&invoice.number.to_string(), 120_000, "eur");

        assert_eq!(
            settle(&db, tenant, &raw).await,
            Settlement::Paid(invoice.id)
        );
        let first = paid_at(&db, tenant, invoice.id).await;
        assert!(first.is_some(), "the invoice is paid");

        // The same delivery again: the register does not move and no second
        // audit row is written.
        assert_eq!(
            settle(&db, tenant, &raw).await,
            Settlement::AlreadySettled(invoice.id)
        );
        assert_eq!(paid_at(&db, tenant, invoice.id).await, first);
        let rows = trail(&db, tenant).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "invoice_paid");
        assert_eq!(rows[0].1["stripe_event_id"], json!("evt_1"));
        assert_eq!(rows[0].1["number"], json!(invoice.number));
    }

    #[tokio::test]
    async fn a_different_figure_pays_nothing_and_leaves_a_row() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let number = invoice.number.to_string();

        assert_eq!(
            settle(&db, tenant, &body(&number, 100_000, "eur")).await,
            Settlement::Mismatch(invoice.id)
        );
        assert_eq!(
            settle(&db, tenant, &body(&number, 120_000, "usd")).await,
            Settlement::Mismatch(invoice.id),
            "the right figure in the wrong money is not the demand"
        );
        assert_eq!(paid_at(&db, tenant, invoice.id).await, None);
        let rows = trail(&db, tenant).await;
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|(kind, _)| kind == "invoice_payment_mismatch")
        );
        assert_eq!(rows[0].1["paid_minor"], json!(100_000));
        assert_eq!(rows[0].1["expected_minor"], json!(120_000));
    }

    #[tokio::test]
    async fn tenant_b_cannot_settle_tenant_a_s_invoice() {
        let Some(db) = db().await else { return };
        let (a, invoice) = invoiced_tenant(&db).await;
        let b = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(b.as_uuid())
            .bind(format!("stripe-b-{}", b.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("tenant b");
        tx.commit().await.expect("commit");

        // B's endpoint delivers a paid session naming A's number. B has no
        // invoice of that number, so RLS answers nothing.
        let raw = body(&invoice.number.to_string(), 120_000, "eur");
        assert_eq!(settle(&db, b, &raw).await, Settlement::NotOurs);
        assert_eq!(paid_at(&db, a, invoice.id).await, None);
        assert!(trail(&db, b).await.is_empty());
    }

    #[tokio::test]
    async fn an_unpaid_session_another_event_or_a_non_json_body_moves_nothing() {
        let Some(db) = db().await else { return };
        let (tenant, invoice) = invoiced_tenant(&db).await;
        let number = invoice.number.to_string();
        let unpaid = String::from_utf8(body(&number, 120_000, "eur"))
            .expect("utf-8")
            .replace(r#""payment_status":"paid""#, r#""payment_status":"unpaid""#);
        assert_eq!(
            settle(&db, tenant, unpaid.as_bytes()).await,
            Settlement::NotOurs
        );
        let other = String::from_utf8(body(&number, 120_000, "eur"))
            .expect("utf-8")
            .replace("checkout.session.completed", "payment_intent.succeeded");
        assert_eq!(
            settle(&db, tenant, other.as_bytes()).await,
            Settlement::NotOurs
        );
        assert_eq!(paid_at(&db, tenant, invoice.id).await, None);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let err = record_stripe_payment(&mut tx, b"}{", "evt_x", Utc::now())
            .await
            .expect_err("not JSON");
        tx.rollback().await.expect("rollback");
        assert!(matches!(err, InboundError::BadNotice(_)));
        assert!(!err.is_retryable());
    }
}
