//! `GET /v1/pnl?days=N`: what each seat cost, at the rate the tenant declared,
//! against what it invoiced, collected and spent.
//!
//! # Why this endpoint exists, given `/v1/usage` and `/v1/billing`
//!
//! [`super::usage`] reports tokens and stops, on the argument that no price a
//! customer did not declare could be trusted on their bill. [`super::billing`] reports what *we*
//! charge for the seat. Neither answers the founder's question, which is "is
//! this employee worth what it burns" — and neither can, because the one
//! number that question needs is the rate on the tenant's own Anthropic
//! contract, which only the tenant knows. `migrations/0079_tenant_model_tariff.sql`
//! lets them declare it on `POST /v1/model`; this endpoint multiplies.
//!
//! **No price here but the declared one.** `cost_usd` is
//! `tokens × the declared rate / 1e6`, and `cost_source` says so beside every
//! figure; `agentos_domain::forecast::rate_card` — the dated list price the
//! eval and `/v1/forecast`'s fallback use — is never consulted on this route. No tariff, no figure: `null`, never zero, for the reason `0024` gave
//! for tokens — unknown is not free.
//!
//! # What is in a block, and what a block is
//!
//! One shape, [`Block`], for every seat and for the tenant total: the
//! consumption columns of `model_usage_daily` under `usage`'s definitions
//! (`complete` is "no unmetered call", and `cost_is_floor` follows it), the
//! money the seat moved (`invoices_issued`, `invoices_paid`, `credit_notes`,
//! `spend_reserved`, `spend_settled`, each a count and a sum per currency),
//! and what it got done or was refused (`work_items_closed`,
//! `approvals_requested`, `approvals_denied`, `gate_denials`).
//!
//! **Money is [`Money`], per currency, never summed across currencies and
//! never a float.** A seat that invoiced in EUR and spent in USD shows two
//! entries, because 120.00 EUR + 10.00 USD is not a number. The cost figure is
//! rounded to the cent in SQL over the NUMERIC tariff column and only the cents
//! come back, so no float ever touches an amount.
//!
//! **Totals are the sum of the seat lines**, plus rows whose seat is gone (an
//! invoice whose issuer was removed, an audit row for a deleted employee).
//! Summing seat cents rather than re-deriving from summed tokens means the
//! lines add up to the total, which is what anybody reading a P&L checks
//! first.
//!
//! No break-even here: that needs our own price for the seat beside the
//! tenant's, and it is a separate reading (roadmap task E).
//!
//! # The window and the tenant
//!
//! `?days=N` is the sugar; `?from=` and `?to=` are [`super::autonomy`]'s own
//! [`Window`], so the three surfaces agree on what "the last 30 days" means.
//! Timestamps are bucketed by UTC calendar day, as `employee_autonomy_daily`
//! buckets them. The tenant comes from [`Principal`]; every table read here
//! has RLS forced, so there is no `WHERE tenant_id` and another tenant's books
//! are not filtered out — they are invisible.

use std::collections::BTreeMap;

use agentos_domain::money::{Currency, Money, MoneyError};
use agentos_store::db::{Db, StoreError};
use agentos_store::model_access::{self, CostSource};
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::autonomy::{Window, WindowQuery};
use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/pnl", get_route(get))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------

/// `?days=N`, or `?from=&to=` as [`super::autonomy`] takes them.
///
/// `pub(super)` for [`super::accounting`], which exports the same books line
/// by line and must mean the same thing by "the last 30 days".
#[derive(Debug, Deserialize)]
pub(super) struct PnlQuery {
    pub(super) days: Option<i64>,
    pub(super) from: Option<NaiveDate>,
    pub(super) to: Option<NaiveDate>,
}

impl PnlQuery {
    /// `days` is sugar for `from = to - (days - 1)`; the rest is [`Window`]'s.
    pub(super) fn resolve(&self) -> Result<Window, ApiError> {
        let from = match (self.days, self.from) {
            (Some(_), Some(_)) => {
                return Err(ApiError::bad_request(
                    "days: give either days or from, not both",
                ));
            }
            (Some(days), None) => {
                if days < 1 {
                    return Err(ApiError::bad_request("days: at least 1"));
                }
                let to = self.to.unwrap_or_else(|| Utc::now().date_naive());
                Some(
                    to.checked_sub_signed(Duration::days(days - 1))
                        .unwrap_or(to),
                )
            }
            (None, from) => from,
        };
        Window::resolve(&WindowQuery { from, to: self.to })
    }
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// A count and a sum per currency. Zero entries when nothing happened —
/// `Money` cannot hold zero, and an empty map is the honest rendering of it.
#[derive(Debug, Default, Serialize)]
struct Ledger {
    count: i64,
    /// Keyed by ISO code, one [`Money`] each. Never summed across keys.
    amounts: BTreeMap<Currency, Money>,
}

impl Ledger {
    fn add(&mut self, count: i64, amount: Money) -> Result<(), MoneyError> {
        self.count = self.count.saturating_add(count);
        let total = match self.amounts.get(&amount.currency()) {
            Some(existing) => existing.checked_add(amount)?,
            None => amount,
        };
        self.amounts.insert(amount.currency(), total);
        Ok(())
    }

    fn merge(&mut self, other: &Ledger) -> Result<(), MoneyError> {
        self.count = self.count.saturating_add(other.count);
        for amount in other.amounts.values() {
            self.add(0, *amount)?;
        }
        Ok(())
    }
}

/// One seat's line, or the tenant's total. See the module docs for what each
/// field means and why the shape is the same for both.
#[derive(Debug, Default, Serialize)]
struct Block {
    turns: i64,
    calls: i64,
    calls_unmetered: i64,
    tokens_input: i64,
    tokens_output: i64,
    tokens_cache_read: i64,
    /// `true` when every call reported what it cost — [`super::usage`]'s
    /// definition, verbatim. Filled by [`Block::finish`].
    complete: bool,
    /// Tokens × the declared rate, to the cent. Null without a tariff, and
    /// null when a declared tariff prices the window at nothing — `cost_source`
    /// tells the two apart.
    cost_usd: Option<Money>,
    cost_source: CostSource,
    /// `true` when `cost_usd` is a lower bound: an unmetered call in the
    /// window, or a tariff missing a component.
    cost_is_floor: bool,
    /// Cents, accumulated before `cost_usd` is built. Not in the body.
    #[serde(skip)]
    cost_cents: i64,
    invoices_issued: Ledger,
    invoices_paid: Ledger,
    credit_notes: Ledger,
    spend_reserved: Ledger,
    spend_settled: Ledger,
    work_items_closed: i64,
    approvals_requested: i64,
    approvals_denied: i64,
    gate_denials: i64,
}

impl Block {
    fn add(&mut self, other: &Block) -> Result<(), MoneyError> {
        self.turns = self.turns.saturating_add(other.turns);
        self.calls = self.calls.saturating_add(other.calls);
        self.calls_unmetered = self.calls_unmetered.saturating_add(other.calls_unmetered);
        self.tokens_input = self.tokens_input.saturating_add(other.tokens_input);
        self.tokens_output = self.tokens_output.saturating_add(other.tokens_output);
        self.tokens_cache_read = self
            .tokens_cache_read
            .saturating_add(other.tokens_cache_read);
        self.cost_cents = self.cost_cents.saturating_add(other.cost_cents);
        self.invoices_issued.merge(&other.invoices_issued)?;
        self.invoices_paid.merge(&other.invoices_paid)?;
        self.credit_notes.merge(&other.credit_notes)?;
        self.spend_reserved.merge(&other.spend_reserved)?;
        self.spend_settled.merge(&other.spend_settled)?;
        self.work_items_closed = self
            .work_items_closed
            .saturating_add(other.work_items_closed);
        self.approvals_requested = self
            .approvals_requested
            .saturating_add(other.approvals_requested);
        self.approvals_denied = self.approvals_denied.saturating_add(other.approvals_denied);
        self.gate_denials = self.gate_denials.saturating_add(other.gate_denials);
        Ok(())
    }

    /// Derive the fields that depend on the whole block and on the tariff.
    fn finish(&mut self, source: CostSource, tariff_complete: bool) {
        self.complete = self.calls_unmetered == 0;
        self.cost_source = source;
        self.cost_is_floor = !self.complete || !tariff_complete;
        self.cost_usd = match source {
            CostSource::NoTariff => None,
            _ => u64::try_from(self.cost_cents)
                .ok()
                .and_then(|cents| Money::new(cents, Currency::Usd).ok()),
        };
    }
}

/// One employee, named so an operator does not resolve UUIDs by hand.
#[derive(Debug, Serialize)]
struct Seat {
    employee_id: Uuid,
    slug: String,
    display_name: String,
    #[serde(flatten)]
    block: Block,
}

#[derive(Debug, Serialize)]
struct WindowView {
    /// Inclusive, UTC.
    from: NaiveDate,
    /// Inclusive, UTC.
    to: NaiveDate,
    days: i64,
}

/// What the endpoint answers.
#[derive(Debug, Serialize)]
struct PnlView {
    window: WindowView,
    /// Every seat the tenant has, busiest first by tokens, zeroes and all.
    employees: Vec<Seat>,
    /// The seat lines summed, plus rows whose seat no longer exists.
    totals: Block,
}

// ---------------------------------------------------------------------------
// The queries
// ---------------------------------------------------------------------------
//
// Every statement: no `WHERE tenant_id` (RLS), `$1` the first day, `$2` the
// day after the last, and one row per seat. Timestamps are bucketed by UTC
// calendar day exactly as `employee_autonomy_daily` (0022) buckets them.

#[derive(Debug, sqlx::FromRow)]
struct EmployeeRow {
    id: Uuid,
    slug: String,
    display_name: String,
}

const EMPLOYEES_SQL: &str = "SELECT id, slug, display_name FROM employees";

/// The ledger's columns and, in the same pass, what they cost at the tariff.
///
/// `LEFT JOIN … ON true` against `tenant_model_access`: RLS makes that zero or
/// one row, and `coalesce(…, 0)` keeps the arithmetic total when a component
/// is undeclared — the *reader* decides whether the figure is shown at all
/// (see [`Block::finish`]) and flags it as a floor when a component is
/// missing. `/ 10000` is `/ 1e6` tokens per million and `× 100` cents per
/// dollar, in one exact NUMERIC step; `round` then makes it cents.
#[derive(Debug, sqlx::FromRow)]
struct UsageRow {
    employee_id: Uuid,
    calls: i64,
    calls_unmetered: i64,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_tokens: i64,
    cost_cents: i64,
}

const USAGE_SQL: &str = "\
SELECT u.employee_id, \
       sum(u.calls)::bigint             AS calls, \
       sum(u.calls_unmetered)::bigint   AS calls_unmetered, \
       sum(u.input_tokens)::bigint      AS input_tokens, \
       sum(u.output_tokens)::bigint     AS output_tokens, \
       sum(u.cache_read_tokens)::bigint AS cache_read_tokens, \
       round(( sum(u.input_tokens)      * coalesce(t.usd_per_mtok_input, 0) \
             + sum(u.output_tokens)     * coalesce(t.usd_per_mtok_output, 0) \
             + sum(u.cache_read_tokens) * coalesce(t.usd_per_mtok_cache_read, 0) \
             ) / 10000)::bigint         AS cost_cents \
  FROM model_usage_daily u \
  LEFT JOIN tenant_model_access t ON true \
 WHERE u.day >= $1 AND u.day < $2 \
 GROUP BY u.employee_id, t.usd_per_mtok_input, t.usd_per_mtok_output, t.usd_per_mtok_cache_read";

/// A count per seat. `employee_id` is `Option` because three of the tables
/// below keep a bare uuid (`audit_log`, `invoices.issued_by`) or a nullable
/// one (`work_items.assignee_id`, `approvals.employee_id`).
#[derive(Debug, sqlx::FromRow)]
struct CountRow {
    employee_id: Option<Uuid>,
    n: i64,
}

const TURNS_SQL: &str = "\
SELECT employee_id, sum(turns_taken)::bigint AS n \
  FROM turn_buckets \
 WHERE day >= $1 AND day < $2 \
 GROUP BY employee_id";

const WORK_ITEMS_CLOSED_SQL: &str = "\
SELECT assignee_id AS employee_id, count(*)::bigint AS n \
  FROM work_items \
 WHERE (closed_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (closed_at AT TIME ZONE 'UTC')::date <  $2 \
 GROUP BY assignee_id";

const APPROVALS_REQUESTED_SQL: &str = "\
SELECT employee_id, count(*)::bigint AS n \
  FROM approvals \
 WHERE (requested_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (requested_at AT TIME ZONE 'UTC')::date <  $2 \
 GROUP BY employee_id";

/// `state = 'denied'` is what `super::approvals::deny` writes, and nothing else
/// does; the window is on the decision, not the request.
const APPROVALS_DENIED_SQL: &str = "\
SELECT employee_id, count(*)::bigint AS n \
  FROM approvals \
 WHERE state = 'denied' \
   AND (decided_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (decided_at AT TIME ZONE 'UTC')::date <  $2 \
 GROUP BY employee_id";

/// A Policy Gate refusal of something an employee itself tried: `decision =
/// 'deny'` as `agentos_store::audit::decision_columns` spells it, and an
/// `employee:` actor as `employee_autonomy_daily` tells them apart.
const GATE_DENIALS_SQL: &str = "\
SELECT employee_id, count(*)::bigint AS n \
  FROM audit_log \
 WHERE decision = 'deny' \
   AND actor LIKE 'employee:%' \
   AND (occurred_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (occurred_at AT TIME ZONE 'UTC')::date <  $2 \
 GROUP BY employee_id";

/// A count and a sum, per seat and per currency.
#[derive(Debug, sqlx::FromRow)]
struct LedgerRow {
    employee_id: Option<Uuid>,
    currency: String,
    n: i64,
    minor: i64,
}

/// Invoices proper — `corrects_invoice_id IS NULL` — by the day they were
/// issued. A credit note is a document in the same table (0071) and is
/// counted below, never here.
const INVOICES_ISSUED_SQL: &str = "\
SELECT issued_by AS employee_id, currency, count(*)::bigint AS n, sum(amount_minor)::bigint AS minor \
  FROM invoices \
 WHERE corrects_invoice_id IS NULL \
   AND (issued_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (issued_at AT TIME ZONE 'UTC')::date <  $2 \
 GROUP BY issued_by, currency";

const INVOICES_PAID_SQL: &str = "\
SELECT issued_by AS employee_id, currency, count(*)::bigint AS n, sum(amount_minor)::bigint AS minor \
  FROM invoices \
 WHERE corrects_invoice_id IS NULL \
   AND (paid_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (paid_at AT TIME ZONE 'UTC')::date <  $2 \
 GROUP BY issued_by, currency";

/// A credit note has no issuer of its own (0071: separation of duties), so it
/// lands on the seat that issued the invoice it corrects.
const CREDIT_NOTES_SQL: &str = "\
SELECT o.issued_by AS employee_id, c.currency, count(*)::bigint AS n, sum(c.amount_minor)::bigint AS minor \
  FROM invoices c \
  JOIN invoices o ON o.id = c.corrects_invoice_id \
 WHERE c.corrects_invoice_id IS NOT NULL \
   AND (c.issued_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (c.issued_at AT TIME ZONE 'UTC')::date <  $2 \
 GROUP BY o.issued_by, c.currency";

/// `$3` is the state: `reserved` is still outstanding, `settled` was paid.
/// `released` is neither and is not money the seat moved.
const SPEND_SQL: &str = "\
SELECT employee_id, currency, count(*)::bigint AS n, sum(amount_minor)::bigint AS minor \
  FROM spend_reservations \
 WHERE state = $3 AND day >= $1 AND day < $2 \
 GROUP BY employee_id, currency";

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

/// Which field of a [`Block`] a query's rows land in.
type Field<T> = fn(&mut Block) -> &mut T;

/// The seat's block, or the orphan block for a row whose seat is gone.
fn block_for<'a>(
    seats: &'a mut BTreeMap<Uuid, Block>,
    orphans: &'a mut Block,
    id: Option<Uuid>,
) -> &'a mut Block {
    match id.and_then(|id| seats.get_mut(&id)) {
        Some(block) => block,
        None => orphans,
    }
}

/// A ledger figure as the table holds it — an ISO code and a bigint of minor
/// units — as [`Money`], refusing a currency the domain does not know or a
/// figure the ledger cannot have. Shared with [`super::accounting`].
pub(super) fn money(currency: &str, minor: i64) -> Result<Money, StoreError> {
    let currency: Currency = currency
        .parse()
        .map_err(|err: MoneyError| StoreError::conflict(err.to_string()))?;
    let minor = u64::try_from(minor)
        .map_err(|_| StoreError::conflict("a ledger sum is negative".to_owned()))?;
    Money::new(minor, currency).map_err(|err| StoreError::conflict(err.to_string()))
}

fn arithmetic(err: MoneyError) -> ApiError {
    StoreError::conflict(format!("p&l arithmetic: {err}")).into()
}

/// `GET /v1/pnl?days=N`.
///
/// 200 with zeroes for a tenant whose seats did nothing in the window: "no
/// activity" is a fact, not a missing resource, and every seat is listed so a
/// silent one is visible as silent.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<PnlQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let window = query.resolve()?;
    let (from, end) = (window.from, window.end());

    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    let connection = model_access::load(&mut tx).await?;
    let source = CostSource::of(connection.as_ref());
    let tariff_complete = connection
        .as_ref()
        .and_then(|c| c.tariff)
        .is_some_and(|t| t.is_complete());

    let employees: Vec<EmployeeRow> = sqlx::query_as(EMPLOYEES_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    let mut seats: BTreeMap<Uuid, Block> =
        employees.iter().map(|e| (e.id, Block::default())).collect();
    let mut orphans = Block::default();

    let usage: Vec<UsageRow> = sqlx::query_as(USAGE_SQL)
        .bind(from)
        .bind(end)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    for row in usage {
        let block = block_for(&mut seats, &mut orphans, Some(row.employee_id));
        block.calls = row.calls;
        block.calls_unmetered = row.calls_unmetered;
        block.tokens_input = row.input_tokens;
        block.tokens_output = row.output_tokens;
        block.tokens_cache_read = row.cache_read_tokens;
        block.cost_cents = row.cost_cents;
    }

    let counts: [(&str, Field<i64>); 5] = [
        (TURNS_SQL, |b| &mut b.turns),
        (WORK_ITEMS_CLOSED_SQL, |b| &mut b.work_items_closed),
        (APPROVALS_REQUESTED_SQL, |b| &mut b.approvals_requested),
        (APPROVALS_DENIED_SQL, |b| &mut b.approvals_denied),
        (GATE_DENIALS_SQL, |b| &mut b.gate_denials),
    ];
    for (sql, field) in counts {
        let rows: Vec<CountRow> = sqlx::query_as(sql)
            .bind(from)
            .bind(end)
            .fetch_all(&mut **tx)
            .await
            .map_err(StoreError::from)?;
        for row in rows {
            let slot = field(block_for(&mut seats, &mut orphans, row.employee_id));
            *slot = slot.saturating_add(row.n);
        }
    }

    let ledgers: [(&str, Option<&str>, Field<Ledger>); 5] = [
        (INVOICES_ISSUED_SQL, None, |b| &mut b.invoices_issued),
        (INVOICES_PAID_SQL, None, |b| &mut b.invoices_paid),
        (CREDIT_NOTES_SQL, None, |b| &mut b.credit_notes),
        (SPEND_SQL, Some("reserved"), |b| &mut b.spend_reserved),
        (SPEND_SQL, Some("settled"), |b| &mut b.spend_settled),
    ];
    for (sql, state, field) in ledgers {
        let mut query = sqlx::query_as::<_, LedgerRow>(sql).bind(from).bind(end);
        if let Some(state) = state {
            query = query.bind(state);
        }
        let rows = query.fetch_all(&mut **tx).await.map_err(StoreError::from)?;
        for row in rows {
            let amount = money(&row.currency, row.minor)?;
            field(block_for(&mut seats, &mut orphans, row.employee_id))
                .add(row.n, amount)
                .map_err(arithmetic)?;
        }
    }
    tx.rollback().await?;

    let mut totals = orphans;
    let mut listed = Vec::with_capacity(employees.len());
    for employee in employees {
        let mut block = seats.remove(&employee.id).unwrap_or_default();
        totals.add(&block).map_err(arithmetic)?;
        block.finish(source, tariff_complete);
        listed.push(Seat {
            employee_id: employee.id,
            slug: employee.slug,
            display_name: employee.display_name,
            block,
        });
    }
    totals.finish(source, tariff_complete);
    listed.sort_by(|a, b| {
        let tokens =
            |s: &Seat| s.block.tokens_input + s.block.tokens_output + s.block.tokens_cache_read;
        tokens(b).cmp(&tokens(a)).then_with(|| a.slug.cmp(&b.slug))
    });

    Ok(axum::Json(PnlView {
        window: WindowView {
            from: window.from,
            to: window.to,
            days: (window.to - window.from).num_days() + 1,
        },
        employees: listed,
        totals,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `pub(super)`: [`super::accounting`]'s tests seed the same books and read
/// them back as CSV, so they borrow this harness rather than copy it.
#[cfg(test)]
pub(crate) mod tests {
    use std::num::NonZeroU32;

    use agentos_app::mcp::Credentials;
    use agentos_app::mocks::{self, LlmBackend};
    use agentos_domain::action::Action;
    use agentos_domain::ids::{EmployeeId, InvoiceId, TenantId, WorkItemId};
    use agentos_domain::policy::{Decision, DenyReason};
    use agentos_store::approvals::{self, NewApproval};
    use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
    use agentos_store::invoices::{self, Draft};
    use agentos_store::model_usage::{self, Consumed};
    use agentos_store::spend::{self, SpendCaps};
    use agentos_store::{backlog, model_access};
    use axum::body::{Body, to_bytes};
    use axum::http::{HeaderMap, Request as HttpRequest, StatusCode, header};
    use chrono::Utc;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    pub(crate) const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub(crate) const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    pub(crate) struct Harness {
        app: Router,
        pub(crate) db: Db,
        pub(crate) a: TenantId,
        pub(crate) b: TenantId,
    }

    impl Harness {
        /// This router plus `/v1/model` on the mock backend, so the tariff
        /// goes in the way a tenant puts it in, plus `/v1/accounting/export`,
        /// which must foot to this one.
        pub(crate) async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; pnl routes need a real Postgres");
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

            let routes = router(db.clone())
                .merge(super::super::accounting::router(db.clone()))
                .merge(super::super::model::router(
                    db.clone(),
                    mocks::llm(LlmBackend::Mock, None).expect("mock"),
                    LlmBackend::Mock,
                    Credentials::from_master_key(crate::auth::TEST_MASTER_KEY),
                ));
            Some(Self {
                app: crate::with_api_stack(
                    routes,
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        pub(crate) async fn call(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
            let body = match body {
                Some(json) => {
                    req = req.header(header::CONTENT_TYPE, "application/json");
                    Body::from(json.to_string())
                }
                None => Body::empty(),
            };
            let response = self
                .app
                .clone()
                .oneshot(req.body(body).expect("request"))
                .await
                .expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// A GET whose body is not JSON: status, headers and the bytes as text.
        pub(crate) async fn get_raw(
            &self,
            uri: &str,
            secret: &str,
        ) -> (StatusCode, HeaderMap, String) {
            let req = HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .body(Body::empty())
                .expect("request");
            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                headers,
                String::from_utf8(bytes.to_vec()).expect("utf-8"),
            )
        }

        pub(crate) async fn teardown(self) {
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

    pub(crate) async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'pnl-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    pub(crate) async fn employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    /// A won deal to invoice against — `invoices::issue` refuses any other.
    /// `legal_name` is the buyer's, i.e. third-party text: the export's tests
    /// put a hostile one in.
    pub(crate) async fn won_deal(db: &Db, tenant: TenantId, legal_name: &str) -> Uuid {
        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, $4, $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("buyer-{}.example", account.simple()))
        .bind(legal_name)
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
        tx.commit().await.expect("commit");
        opportunity
    }

    pub(crate) fn eur(minor: u64) -> Money {
        Money::new(minor, Currency::Eur).expect("nonzero")
    }

    fn seat(body: &Value, id: EmployeeId) -> &Value {
        body["employees"]
            .as_array()
            .expect("array")
            .iter()
            .find(|row| row["employee_id"] == id.as_uuid().to_string())
            .unwrap_or_else(|| panic!("seat {id} is listed in {body}"))
    }

    /// Everything one seat can do in a day, through the real writers, and the
    /// figures that come back — null cost until the tariff is declared, the
    /// declared cost after, and lines that add up to the total.
    #[tokio::test]
    async fn a_seats_pnl_adds_up_and_costs_nothing_until_a_tariff_is_declared() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;
        let idle = employee(&h.db, h.a, "idle").await;
        let deal = won_deal(&h.db, h.a, "Buyer plc").await;
        let now = Utc::now();
        let today = now.date_naive();

        // Consumption, the way a turn records it, plus three turns.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        model_usage::record(
            &mut tx,
            lena,
            today,
            Consumed::reported(2, 1_000_000, 100_000, 2_000_000),
        )
        .await
        .expect("record");
        sqlx::query(
            "INSERT INTO turn_buckets (tenant_id, employee_id, day, turns_taken) \
             VALUES ($1, $2, $3, 3)",
        )
        .bind(h.a.as_uuid())
        .bind(lena.as_uuid())
        .bind(today)
        .execute(&mut **tx)
        .await
        .expect("turns");
        tx.commit().await.expect("commit");

        // No tariff: tokens are reported, the cost is null and says why.
        let (status, body) = h.call("GET", "/v1/pnl?days=1", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["window"]["days"], 1);
        let row = seat(&body, lena);
        assert_eq!(row["slug"], "lena");
        assert_eq!(row["display_name"], "lena");
        assert_eq!(row["turns"], 3);
        assert_eq!(row["calls"], 2);
        assert_eq!(row["calls_unmetered"], 0);
        assert_eq!(row["tokens_input"], 1_000_000);
        assert_eq!(row["tokens_output"], 100_000);
        assert_eq!(row["tokens_cache_read"], 2_000_000);
        assert_eq!(row["complete"], true);
        assert_eq!(row["cost_usd"], Value::Null, "unknown is not zero");
        assert_eq!(row["cost_source"], "no_tariff");
        assert_eq!(row["invoices_issued"], json!({"count": 0, "amounts": {}}));
        // The idle seat is listed, with zeroes: silent is visible.
        assert_eq!(seat(&body, idle)["calls"], 0);
        assert_eq!(body["employees"][0]["slug"], "lena", "busiest first");
        assert_eq!(body["totals"]["cost_usd"], Value::Null);

        // The tenant declares their rate on the connect call, on the CLI
        // path, which needs no key and is billed to nobody we meter.
        let (status, body) = h
            .call(
                "POST",
                "/v1/model",
                SECRET_A,
                Some(json!({
                    "path": "cli",
                    "usd_per_mtok_input": 3,
                    "usd_per_mtok_output": 15,
                    "usd_per_mtok_cache_read": 0.30
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["connected"], true, "{body}");
        assert!(
            body.get("tariff").is_none(),
            "the POST body shape is unchanged"
        );

        let (status, body) = h.call("GET", "/v1/model", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["path"], "cli");
        assert_eq!(body["tariff"]["usd_per_mtok_input"], 3.0);
        assert_eq!(body["tariff"]["usd_per_mtok_cache_read"], 0.3);
        assert_eq!(body["cost_source"], "declared_tariff_on_cli_path");

        // The money the seat moved: two invoices, one paid, one credited; a
        // settled spend and an outstanding one; a released one that is
        // neither.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        let paid = invoices::issue(
            &mut tx,
            Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: deal,
                issued_by: lena,
                amount: eur(120_000),
                memo: "onboarding",
                due_at: None,
                lines: &[],
            },
        )
        .await
        .expect("issue");
        assert!(
            invoices::declare_paid(&mut tx, paid.id, paid.issued_at)
                .await
                .expect("paid")
        );
        let wrong = invoices::issue(
            &mut tx,
            Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: deal,
                issued_by: lena,
                amount: eur(30_000),
                memo: "a mistake",
                due_at: None,
                lines: &[],
            },
        )
        .await
        .expect("issue");
        invoices::credit(&mut tx, InvoiceId::new_v7(now), wrong.id, 30_000, "undone")
            .await
            .expect("credit");

        spend::set_caps(
            &mut tx,
            lena,
            SpendCaps::new(eur(100_000), eur(50_000), NonZeroU32::new(10).expect("ten"))
                .expect("caps"),
        )
        .await
        .expect("caps");
        let settled = spend::reserve(&mut tx, lena, today, eur(10_000))
            .await
            .expect("reserve");
        spend::settle(&mut tx, &settled).await.expect("settle");
        spend::reserve(&mut tx, lena, today, eur(5_000))
            .await
            .expect("reserve");
        let released = spend::reserve(&mut tx, lena, today, eur(7_000))
            .await
            .expect("reserve");
        spend::release(&mut tx, &released).await.expect("release");

        // Work closed, approvals asked and one refused, and one gate denial
        // beside an allow that must not be counted.
        let item = WorkItemId::new_v7(now);
        backlog::post(&mut tx, item, "call the buyer", Some(lena), None)
            .await
            .expect("post");
        assert!(
            backlog::close(&mut tx, item, lena, now)
                .await
                .expect("close")
        );

        let action = Action::PaymentCreate {
            amount: eur(20_000),
            payee: "acct_supplier".to_owned(),
        };
        let request = NewApproval {
            employee_id: Some(lena),
            action: &action,
            requested_by: "lena",
            required_role: "founder",
            reason: None,
            expires_at: now + Duration::hours(1),
        };
        let denied = approvals::create(&mut tx, &request, now)
            .await
            .expect("approval");
        let other = Action::PaymentCreate {
            amount: eur(21_000),
            payee: "acct_supplier".to_owned(),
        };
        approvals::create(
            &mut tx,
            &NewApproval {
                action: &other,
                ..request
            },
            now,
        )
        .await
        .expect("approval");
        sqlx::query("UPDATE approvals SET state = 'denied', decided_at = now() WHERE id = $1")
            .bind(denied.id().as_uuid())
            .execute(&mut **tx)
            .await
            .expect("deny");

        for decision in [
            Decision::Deny {
                reason: DenyReason::NoRule,
            },
            Decision::Allow,
        ] {
            let mut event = AuditEvent::new(
                AuditActor::Employee(lena),
                AuditKind::CapabilityDecided,
                now,
            );
            event.employee_id = Some(lena);
            event.decision = Some(decision);
            audit::append(&mut tx, &event).await.expect("audit");
        }
        tx.commit().await.expect("commit");

        let (status, body) = h.call("GET", "/v1/pnl?days=1", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let row = seat(&body, lena);
        // 1M × 3 + 0.1M × 15 + 2M × 0.30 = 3.00 + 1.50 + 0.60 USD.
        assert_eq!(row["cost_usd"], json!({"minor": 510, "currency": "USD"}));
        assert_eq!(row["cost_source"], "declared_tariff_on_cli_path");
        assert_eq!(row["cost_is_floor"], false);
        assert_eq!(
            row["invoices_issued"],
            json!({"count": 2, "amounts": {"EUR": {"minor": 150_000, "currency": "EUR"}}})
        );
        assert_eq!(
            row["invoices_paid"],
            json!({"count": 1, "amounts": {"EUR": {"minor": 120_000, "currency": "EUR"}}})
        );
        assert_eq!(
            row["credit_notes"],
            json!({"count": 1, "amounts": {"EUR": {"minor": 30_000, "currency": "EUR"}}})
        );
        assert_eq!(
            row["spend_reserved"],
            json!({"count": 1, "amounts": {"EUR": {"minor": 5_000, "currency": "EUR"}}})
        );
        assert_eq!(
            row["spend_settled"],
            json!({"count": 1, "amounts": {"EUR": {"minor": 10_000, "currency": "EUR"}}})
        );
        assert_eq!(row["work_items_closed"], 1);
        assert_eq!(row["approvals_requested"], 2);
        assert_eq!(row["approvals_denied"], 1);
        assert_eq!(row["gate_denials"], 1);

        // The total is the seat lines summed; the idle seat adds nothing.
        for key in [
            "turns",
            "cost_usd",
            "invoices_issued",
            "invoices_paid",
            "credit_notes",
            "spend_reserved",
            "spend_settled",
            "work_items_closed",
            "approvals_requested",
            "approvals_denied",
            "gate_denials",
        ] {
            assert_eq!(body["totals"][key], row[key], "{key}");
        }
        let idle_row = seat(&body, idle);
        assert_eq!(idle_row["cost_usd"], Value::Null, "priced nothing at all");
        assert_eq!(idle_row["cost_source"], "declared_tariff_on_cli_path");

        // Yesterday holds none of it.
        let yesterday = today - Duration::days(1);
        let (status, body) = h
            .call(
                "GET",
                &format!("/v1/pnl?from={yesterday}&to={yesterday}"),
                SECRET_A,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["totals"]["calls"], 0);
        assert_eq!(body["totals"]["invoices_issued"]["count"], 0);

        // The window refuses the shapes that would answer nonsense.
        for bad in [
            "/v1/pnl?days=0",
            "/v1/pnl?days=2&from=2026-01-01",
            "/v1/pnl?days=400",
        ] {
            let (status, _) = h.call("GET", bad, SECRET_A, None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }

        h.teardown().await;
    }

    /// An unmetered call makes the figure a floor, and a rate missing a
    /// component does too.
    #[tokio::test]
    async fn an_unmetered_call_or_a_partial_tariff_makes_the_cost_a_floor() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lossy = employee(&h.db, h.a, "lossy").await;
        let today = Utc::now().date_naive();

        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        model_usage::record(&mut tx, lossy, today, Consumed::reported(1, 500_000, 0, 0))
            .await
            .expect("record");
        model_usage::record(&mut tx, lossy, today, Consumed::reported(1, 0, 0, 0))
            .await
            .expect("record");
        tx.commit().await.expect("commit");

        let (status, body) = h
            .call(
                "POST",
                "/v1/model",
                SECRET_A,
                Some(json!({"path": "cli", "usd_per_mtok_input": 2})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = h.call("GET", "/v1/pnl?days=1", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let row = seat(&body, lossy);
        assert_eq!(row["calls_unmetered"], 1);
        assert_eq!(row["complete"], false);
        assert_eq!(row["cost_usd"], json!({"minor": 100, "currency": "USD"}));
        assert_eq!(row["cost_is_floor"], true);

        // A rate below zero is refused before anything is proven or stored.
        let (status, _) = h
            .call(
                "POST",
                "/v1/model",
                SECRET_A,
                Some(json!({"path": "cli", "usd_per_mtok_input": -2})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (_, body) = h.call("GET", "/v1/model", SECRET_A, None).await;
        assert_eq!(body["tariff"]["usd_per_mtok_input"], 2.0, "untouched");

        h.teardown().await;
    }

    /// RLS, not a filter: B holds a valid key and sees none of A's books, its
    /// seats, or its tariff.
    #[tokio::test]
    async fn another_tenants_books_are_invisible_rather_than_filtered() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;
        let deal = won_deal(&h.db, h.a, "Buyer plc").await;
        let now = Utc::now();

        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        model_usage::record(
            &mut tx,
            lena,
            now.date_naive(),
            Consumed::reported(3, 1_000, 200, 0),
        )
        .await
        .expect("record");
        model_access::save(
            &mut tx,
            &agentos_domain::model_access::ModelAccess {
                path: agentos_domain::model_access::ModelPath::Cli,
                model: agentos_domain::policy::ModelId::default(),
                verified_at: now,
            },
            None,
            now,
        )
        .await
        .expect("save");
        assert!(
            model_access::set_tariff(
                &mut tx,
                model_access::Tariff {
                    usd_per_mtok_input: Some(3.0),
                    usd_per_mtok_output: Some(15.0),
                    usd_per_mtok_cache_read: Some(0.3),
                }
            )
            .await
            .expect("tariff")
        );
        invoices::issue(
            &mut tx,
            Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: deal,
                issued_by: lena,
                amount: eur(120_000),
                memo: "theirs",
                due_at: None,
                lines: &[],
            },
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit");

        let (status, body) = h.call("GET", "/v1/pnl?days=7", SECRET_B, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["employees"].as_array().expect("array").len(), 0);
        assert_eq!(body["totals"]["calls"], 0);
        assert_eq!(body["totals"]["invoices_issued"]["count"], 0);
        assert_eq!(body["totals"]["cost_usd"], Value::Null);
        assert_eq!(body["totals"]["cost_source"], "no_tariff");

        // And A's own reading is intact.
        let (_, body) = h.call("GET", "/v1/pnl?days=7", SECRET_A, None).await;
        assert_eq!(seat(&body, lena)["calls"], 3);
        assert_eq!(body["totals"]["cost_source"], "declared_tariff_on_cli_path");

        h.teardown().await;
    }
}
