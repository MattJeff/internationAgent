//! `GET /v1/employees/{id}/reports`: the manager's view of its own line.
//!
//! # Why this endpoint exists
//!
//! `migrations/0027_positions.sql` made the org chart drawable and
//! [`agentos_store::org::reports`] answers "who reports to this seat" with a
//! list of UUIDs. Nothing aggregated it. So an operator running seven AI
//! employees had no way to ask the one question a morning starts with — *what is
//! my team doing, what is it costing me, and what is stuck* — short of opening
//! psql, and a question you answer in psql is a question that does not get
//! answered.
//!
//! Every fact below already existed and was already written by its own
//! enforcing writer. This endpoint invents no number; it puts four ledgers and
//! one anti-join beside each other, per direct report, and stops.
//!
//! # One link, and no `?depth=`
//!
//! Direct reports only. Not a walk down the tree, and there is deliberately no
//! depth parameter — not even one defaulting to 1.
//!
//! The rule is the system's, not this route's: `store::org::manager_of`,
//! `app::inbound::may_message` and the gate's `directs_subject` all take exactly
//! one link, because authority descends a step at a time or it is not a chain of
//! command. A CEO does not thereby direct every employee in the company. A
//! *view* that walked the tree would not grant anything, so the argument for
//! adding one is that reading is not directing — and the argument against is
//! that this is the screen an operator looks at every morning, and the shape it
//! teaches is the shape they believe. A view that renders the whole subtree
//! teaches "the CEO's line is the company", which is the exact reading the org
//! layer refuses everywhere it can be enforced. The head of Growth's own line is
//! the head of Growth's screen; ask for it with its own id.
//!
//! It is also the honest engineering answer. Every aggregate here is keyed on
//! one employee and one day; a subtree turns each of them into a recursive walk
//! whose cost nobody bounds, and the depth bound would then be doing the job
//! this paragraph is doing. If a demand for `?depth=` ever arrives with a real
//! screen behind it, the default still has to be one link, and the argument
//! above still has to be answered in the commit message.
//!
//! # Who may ask
//!
//! **Any operator credential of the tenant, about any employee of the tenant** —
//! the caller does not have to be the manager, and there is no seat check here.
//!
//! That is not laxity, it is the credential this surface actually has.
//! [`Principal`] is a tenant plus an API-key label ([`crate::auth`]); it is not
//! an employee and holds no seat, so "is the caller this employee's manager" is
//! a question the request cannot answer without inventing a mapping from keys to
//! seats that nothing else on this surface has. Inventing one *here*, in a
//! read-only view, while `GET /v1/employees/{id}/turns` and
//! `GET /v1/employees/{id}/spend-caps` hand the same operator the same
//! employee's numbers, would be a permission that looks like a boundary and is
//! not one. The org chart is not a secret from the operator who wrote it.
//!
//! What the tenant boundary *is* remains absolute: it comes from the API key and
//! never from the URL, every statement runs inside `Db::tenant_tx`, and another
//! tenant's employee is a **404** rather than a 403 — a 403 would confirm the id
//! exists.
//!
//! # One round trip per fact, never one per report
//!
//! Four statements, and not one of them grows with the size of the team:
//!
//! | statement | what it answers |
//! |---|---|
//! | existence | is this employee mine (404 vs an empty line) |
//! | [`LINE_SQL`] | one row per direct report: identity, turns, tokens, both unanswered counts |
//! | [`agentos_store::policy::max_turns_per_day`] | the intersected turn ceiling for the whole set |
//! | [`SPEND_SQL`] | one row per (report, currency): today's committed spend and the cap |
//!
//! The naive shape — `org::reports` then five reads per report — is five
//! employees times five facts, and it gets slower every time somebody is hired.
//! A view that gets slower as a team grows is a view that gets turned off, and
//! then nobody sees the employee that stopped.
//!
//! # Money is `Money`
//!
//! Minor units and a currency, never a float. The two derived figures are bare
//! minor units *with the currency beside them in the same object*, because both
//! are legitimately zero and [`Money`] cannot represent zero — the same trade
//! `routes::teams`' budget view makes, spelled the same way so the two read
//! alike.
//!
//! # There is no cost in euros here, and that is the whole discipline
//!
//! `model_usage` is tokens and calls. There is no price per million tokens in
//! this repository, because a price is a fact with a source and a date that
//! nobody is paged to update, and the real number depends on a contract this
//! schema has never seen. A cost figure nobody can trace is worse than a missing
//! one. `migrations/0024_model_usage.sql` carries the full argument and
//! `routes::usage` inherits it; this endpoint reports the measurement, names the
//! calls nobody metered, and stops.

use std::collections::HashMap;
use std::str::FromStr;

use agentos_domain::ids::EmployeeId;
use agentos_domain::money::{Currency, Money};
use agentos_store::db::{Db, StoreError};
use agentos_store::model_usage::Consumed;
use agentos_store::policy;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{NaiveDate, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::usage::Rollup as ModelUsage;
use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before this handler.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/employees/{id}/reports", get_route(get))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// What one report may spend today in one currency, and what it already has.
///
/// Shaped like `routes::teams`' budget view on purpose, for the same reason:
/// `spent_minor` and `remaining_minor` are bare minor units because both are
/// legitimately zero and [`Money`] refuses zero, and `currency` sits beside them
/// so neither is ever a naked integer.
///
/// `daily_total` is `None` when no `spend_caps` row exists, and that is **not**
/// unlimited — it is *may not spend*: `spend::reserve` refuses outright with
/// `NoCaps` and the gate renders that as `no_spend_policy`. An employee showing
/// `daily_total: null` with money already spent today is an employee whose caps
/// were removed after it paid, which is worth seeing.
///
/// **The employee's own bucket, not its team's.** `store::org::reserve` consumes
/// both — the employee's ceiling and then the team's shared budget — and only
/// the first is a fact about *this report*: a team budget is one number several
/// seats draw on, so repeating it on every row would read as several budgets and
/// invite an operator to add them up. `GET /v1/teams/{id}/budget` is the shared
/// pool, and it is one request away.
#[derive(Debug, Serialize)]
struct SpendView {
    currency: Currency,
    daily_total: Option<Money>,
    spent_minor: u64,
    /// `None` when there is no cap: there is no headroom to report.
    remaining_minor: Option<u64>,
}

/// One direct report, as its manager needs to see it.
///
/// The turn fields carry the same four names as `GET /v1/employees/{id}/turns`,
/// deliberately: an operator who drills from this list into one employee must
/// not have to translate.
#[derive(Debug, Serialize)]
struct ReportView {
    employee_id: Uuid,
    slug: String,
    display_name: String,
    /// What the seat is called — "Head of Growth". `None` is a seat nobody has
    /// named, not a missing employee.
    title: Option<String>,
    /// `active`, `suspended`, `terminated`. A terminated employee still holds
    /// its seat until somebody edits the chart, so it still appears here —
    /// which is the point: a line with a dead seat in it is a line to fix.
    lifecycle: String,
    /// Turns started today. Counted at the *start* of a turn, so one that
    /// crashed halfway is in here.
    turns_taken: u32,
    /// The intersected ceiling: platform ∧ tenant ∧ team ∧ employee. Zero when
    /// the deployment has no policy this employee can run under at all, which is
    /// also the state in which it takes no turns.
    max_turns_per_day: u32,
    turns_remaining: u32,
    /// `true` when this employee has stopped for the day. It resumes by itself
    /// at the next UTC midnight; the operator action is to raise the budget, and
    /// this field is the only warning that one is needed.
    exhausted: bool,
    /// Questions somebody put to this employee that it has not answered. **The
    /// most common way an AI company quietly stops**: a question with nobody
    /// answering it blocks the asker forever and appears in no other view.
    questions_owed: i64,
    /// Questions this employee asked that nobody has answered — what it is
    /// blocked on. `app::inbound::outstanding_note` reminds the employee itself
    /// every turn; this is the same fact for the human.
    questions_waiting_on: i64,
    /// One entry per currency this employee has a cap in or has spent in today.
    /// Empty means neither, which is an employee that may not spend at all.
    spend: Vec<SpendView>,
    /// Today's tokens and the calls behind them, and — `runs_unbacked` and
    /// `unbacked_chars` — how much of today's prose has nothing behind it at
    /// all. No money: see the module docs.
    ///
    /// **The two unbacked figures are the ones to read against everything else
    /// on this row.** A seat with turns taken, tokens spent, `runs_unbacked`
    /// equal to those turns and twelve thousand characters against them wrote a
    /// day's report and did no work; `agentos_store::model_usage` carries the
    /// argument and the honest limits. They are a fact for a human to read, not
    /// a verdict — an employee with nothing due says so in thirty characters and
    /// lands in the same column.
    model_usage: ModelUsage,
}

/// What the endpoint answers.
#[derive(Debug, Serialize)]
struct LineView {
    /// The manager asked about, echoed so a cached response identifies itself.
    employee_id: Uuid,
    /// The UTC day every "today" below was read for. Named so nobody has to
    /// guess which midnight the counters reset at — the same day the spend
    /// ledger, the turn budget and the token ledger all key on.
    day: NaiveDate,
    /// Direct reports, oldest seat first. Empty and 200 for a manager with
    /// nobody under it: "this employee has no reports" is a fact, not a missing
    /// resource.
    reports: Vec<ReportView>,
}

// ---------------------------------------------------------------------------
// The queries
// ---------------------------------------------------------------------------

/// One row per direct report: who it is, what it burned today, and what is
/// stuck.
///
/// No `WHERE tenant_id` anywhere: every table here carries `tenant_isolation`
/// from its own migration and the transaction is a `tenant_tx`, so the predicate
/// is the policy rather than a filter each reader has to remember.
///
/// `LEFT JOIN` on the two daily ledgers, because "no row" is how both spell "did
/// nothing today" and an inner join would drop exactly the idle employee a
/// manager most wants to see.
///
/// The two unanswered counts are correlated sub-selects rather than a join,
/// which is what makes them *counts* — a `GROUP BY` over the same anti-join
/// would drop a report with no open questions, and zero is the answer that
/// matters. Both ride the partial indexes `0028_internal_channel.sql` added for
/// exactly this anti-join. They are unbounded, unlike
/// `app::inbound::unanswered`, whose `LIMIT 20` exists because its result goes
/// into a prompt; a number does not have that problem.
///
/// `q.sender = e.slug` is how "who asked" is spelled everywhere in `messages` —
/// the row belongs to the recipient, the sender is a slug, and a slug is unique
/// per tenant and never changes.
const LINE_SQL: &str = "\
SELECT m.employee_id, \
       e.slug, \
       e.display_name, \
       m.title, \
       e.lifecycle, \
       coalesce(t.turns_taken, 0)       AS turns_taken, \
       coalesce(u.calls, 0)             AS calls, \
       coalesce(u.calls_unmetered, 0)   AS calls_unmetered, \
       coalesce(u.input_tokens, 0)      AS input_tokens, \
       coalesce(u.output_tokens, 0)     AS output_tokens, \
       coalesce(u.cache_read_tokens, 0) AS cache_read_tokens, \
       coalesce(u.runs_unbacked, 0)     AS runs_unbacked, \
       coalesce(u.unbacked_chars, 0)    AS unbacked_chars, \
       (SELECT count(*) FROM messages q \
         WHERE q.employee_id = m.employee_id \
           AND q.internal_kind = 'question' \
           AND NOT EXISTS ( \
               SELECT 1 FROM messages a WHERE a.answers_message_id = q.id)) AS questions_owed, \
       (SELECT count(*) FROM messages q \
         WHERE q.sender = e.slug \
           AND q.internal_kind = 'question' \
           AND NOT EXISTS ( \
               SELECT 1 FROM messages a WHERE a.answers_message_id = q.id)) AS questions_waiting_on \
  FROM team_memberships m \
  JOIN employees e ON e.id = m.employee_id \
  LEFT JOIN turn_buckets t ON t.employee_id = m.employee_id AND t.day = $2 \
  LEFT JOIN model_usage_daily u ON u.employee_id = m.employee_id AND u.day = $2 \
 WHERE m.reports_to = $1 \
 ORDER BY m.created_at, m.employee_id";

/// One row per (report, currency) the reports have a cap in **or** have spent in
/// today.
///
/// The `UNION` is the point. A cap with no spending and spending with no cap are
/// both real and both worth seeing — the first is an employee that has not
/// started, the second is an employee whose ceiling was removed after it paid —
/// and either join alone silently drops one of them. `UNION` and not `UNION ALL`
/// so an employee holding both contributes one key.
const SPEND_SQL: &str = "\
WITH held AS ( \
        SELECT employee_id, currency FROM spend_caps WHERE employee_id = ANY($1::uuid[]) \
  UNION SELECT employee_id, currency FROM spend_buckets \
         WHERE employee_id = ANY($1::uuid[]) AND day = $2) \
SELECT h.employee_id, \
       h.currency, \
       c.daily_total_minor, \
       coalesce(b.reserved_minor, 0) AS reserved_minor \
  FROM held h \
  LEFT JOIN spend_caps c \
    ON c.employee_id = h.employee_id AND c.currency = h.currency \
  LEFT JOIN spend_buckets b \
    ON b.employee_id = h.employee_id AND b.currency = h.currency AND b.day = $2 \
 ORDER BY h.employee_id, h.currency";

/// One row of [`LINE_SQL`].
///
/// `#[sqlx(flatten)]` on [`Consumed`] so the token column list lives in exactly
/// one struct, in the store crate beside the writer, and the ledger, the query
/// and the JSON cannot drift apart.
#[derive(Debug, sqlx::FromRow)]
struct LineRow {
    employee_id: Uuid,
    slug: String,
    display_name: String,
    title: Option<String>,
    lifecycle: String,
    turns_taken: i32,
    questions_owed: i64,
    questions_waiting_on: i64,
    #[sqlx(flatten)]
    consumed: Consumed,
}

/// One row of [`SPEND_SQL`].
#[derive(Debug, sqlx::FromRow)]
struct SpendRow {
    employee_id: Uuid,
    currency: String,
    daily_total_minor: Option<i64>,
    reserved_minor: i64,
}

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

/// `GET /v1/employees/{id}/reports`.
///
/// 200 with `reports: []` for a manager nobody answers to — every individual
/// contributor in the company is in that state, and it is not an error. The 404
/// is for an employee that does not exist *in this tenant*, which is why the
/// existence check cannot be skipped: without it, "no such employee" and "no
/// reports" would be the same response, and the operator would read a typo as an
/// empty team.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let day = Utc::now().date_naive();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    // Existence first. No `WHERE tenant_id`: RLS adds it, and a hand-written
    // filter would be a second place to forget it — so another tenant's real id
    // is indistinguishable from an id nobody owns, which is the whole point.
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM employees WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    if exists.is_none() {
        tx.rollback().await?;
        return Err(ApiError::not_found());
    }

    let rows: Vec<LineRow> = sqlx::query_as(LINE_SQL)
        .bind(id)
        .bind(day)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;

    // A manager with no reports asks the database nothing further: two
    // statements with an empty id list would return nothing and cost two round
    // trips to find that out.
    if rows.is_empty() {
        tx.rollback().await?;
        return Ok(Json(LineView {
            employee_id: id,
            day,
            reports: Vec::new(),
        })
        .into_response());
    }

    let ids: Vec<Uuid> = rows.iter().map(|row| row.employee_id).collect();
    let employees: Vec<EmployeeId> = ids.iter().copied().map(EmployeeId::from_uuid).collect();
    let budgets: HashMap<Uuid, u32> = policy::max_turns_per_day(&mut tx, &employees)
        .await?
        .into_iter()
        .map(|(id, cap)| (id.as_uuid(), cap))
        .collect();

    let spend_rows: Vec<SpendRow> = sqlx::query_as(SPEND_SQL)
        .bind(&ids)
        .bind(day)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.rollback().await?;

    let mut spend: HashMap<Uuid, Vec<SpendView>> = HashMap::new();
    for row in spend_rows {
        // The column is text and nothing constrains it to the ten codes this
        // system knows. Dropping the row would under-state what an employee
        // spent, and under-stating is the one direction this codebase refuses to
        // fail in — so a corrupt row takes the whole view down, loudly, with the
        // employee named in the log and nothing leaked to the caller.
        let currency = Currency::from_str(&row.currency).map_err(|err| {
            tracing::error!(
                employee_id = %row.employee_id,
                currency = %row.currency,
                error = %err,
                "a spend row names a currency this build cannot read, so this \
                 employee's spending cannot be stated"
            );
            ApiError::internal()
        })?;
        let spent_minor = nonneg(row.reserved_minor);
        // `Money::new` refuses zero, and `spend_caps.daily_total_minor` is
        // CHECKed positive, so the `ok()` here discards a row that could only be
        // a corrupt cap — and a cap that cannot be read is rendered as no cap,
        // which reads as *may not spend*.
        let daily_total = row
            .daily_total_minor
            .and_then(|minor| Money::new(nonneg(minor), currency).ok());
        spend.entry(row.employee_id).or_default().push(SpendView {
            currency,
            daily_total,
            spent_minor,
            // Saturating: a cap lowered below what today already reserved is a
            // real state, and it means no headroom rather than negative
            // headroom.
            remaining_minor: daily_total.map(|cap| cap.minor().saturating_sub(spent_minor)),
        });
    }

    let reports = rows
        .into_iter()
        .map(|row| {
            // A missing budget row is an employee with no policy to run under.
            // See `policy::max_turns_per_day`: zero, because that is the number
            // of turns it will actually take.
            let max_turns_per_day = budgets.get(&row.employee_id).copied().unwrap_or(0);
            let turns_taken = u32::try_from(row.turns_taken).unwrap_or(0);
            let turns_remaining = max_turns_per_day.saturating_sub(turns_taken);
            ReportView {
                employee_id: row.employee_id,
                slug: row.slug,
                display_name: row.display_name,
                title: row.title,
                lifecycle: row.lifecycle,
                turns_taken,
                max_turns_per_day,
                turns_remaining,
                exhausted: turns_remaining == 0,
                questions_owed: row.questions_owed,
                questions_waiting_on: row.questions_waiting_on,
                spend: spend.remove(&row.employee_id).unwrap_or_default(),
                model_usage: ModelUsage::from(row.consumed),
            }
        })
        .collect();

    Ok(Json(LineView {
        employee_id: id,
        day,
        reports,
    })
    .into_response())
}

/// Postgres `bigint` is signed and both money columns are CHECKed non-negative,
/// so this only ever un-does the signedness. A negative would mean a corrupt
/// row, and clamping to zero fails closed rather than wrapping to 1.8e19 —
/// `store::org` narrows the same two columns the same way.
fn nonneg(v: i64) -> u64 {
    v.max(0) as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use agentos_app::inbound::{self, Errand, Thread};
    use agentos_domain::ids::{IdempotencyKey, Slug, TenantId};
    use agentos_domain::message::Channel;
    use agentos_domain::money::Currency::Usd;
    use agentos_domain::policy::{EffectivePolicy, PolicyLimits};
    use agentos_domain::untrusted::TrustLabel;
    use agentos_store::model_usage::{self, Consumed};
    use agentos_store::spend::{self, SpendCaps};
    use agentos_store::{org, turns};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;
    use crate::auth::ApiKeys;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Every employee in these fixtures may take this many turns a day. Small
    /// enough that `carla` can be driven to its ceiling in a loop, big enough
    /// that nobody else runs out mid-fixture.
    const TURN_BUDGET: u32 = 10;

    /// What a turn that did nothing says about its day.
    ///
    /// Shortened from the real one — a support seat wrote 12,682 tokens of this
    /// and called no tool at all — and kept in the first person on purpose. It
    /// is the shape of the thing this row has to make visible: confident, plural,
    /// specific, and backed by nothing.
    const NARRATION: &str = "Today I worked through the ticket queue. I handled five tickets and \
                             sent five replies, escalating two to the billing team and closing \
                             the rest. Everything is up to date.";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the reports view needs a real Postgres");
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
            // Both tenants: an employee cannot message a colleague without a
            // policy it can run under, and the fixture's questions are real
            // sends through `inbound::send`.
            for tenant in [a, b] {
                agentos_store::policy::install(
                    &db,
                    tenant,
                    agentos_store::policy::Scope::Tenant,
                    &PolicyLimits {
                        allowed_channels: BTreeSet::from([Channel::Internal]),
                        max_turns_per_day: TURN_BUDGET,
                        ..PolicyLimits::default()
                    },
                )
                .await
                .expect("install the policy");
            }

            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        async fn get(&self, uri: &str, secret: &str) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
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

        async fn line(&self, manager: Uuid, secret: &str) -> (StatusCode, Value) {
            self.get(&format!("/v1/employees/{manager}/reports"), secret)
                .await
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'reports-test')")
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

    /// One employee really messages another, through the writer the agents use.
    ///
    /// Hand-inserted `messages` rows would only prove the view matches what this
    /// file believes an internal message looks like, and "unanswered" is derived
    /// from the shape of two of those rows.
    async fn say(
        h: &Harness,
        from: Uuid,
        to: &str,
        errand: Errand,
        thread: Option<Thread>,
        tag: &str,
    ) -> inbound::Delivered {
        let from = EmployeeId::from_uuid(from);
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let sent = inbound::send(
            &mut tx,
            from,
            &Slug::parse(to).expect("a slug"),
            errand,
            "Where are we on the Q3 renewals?",
            TrustLabel::Trusted,
            thread,
            &IdempotencyKey::for_step(from, &format!("internal:{tag}")),
            Utc::now(),
        )
        .await
        .expect("the message goes");
        tx.commit().await.expect("commit the message");
        sent
    }

    /// Burn `n` turns the way the initiative loop does: through the reserving
    /// path, against a policy wide enough that only the fixture's arithmetic
    /// decides when it stops.
    async fn burn(h: &Harness, who: Uuid, n: u32) {
        let limits = PolicyLimits {
            max_turns_per_day: u32::MAX,
            ..PolicyLimits::default()
        };
        let policy =
            EffectivePolicy::try_new(&limits, &limits, &limits, &limits).expect("coherent");
        for _ in 0..n {
            let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
            turns::reserve(
                &mut tx,
                EmployeeId::from_uuid(who),
                Utc::now().date_naive(),
                &policy,
            )
            .await
            .expect("reserve a turn");
            tx.commit().await.expect("commit");
        }
    }

    /// A head, three reports, and one employee a link further down.
    ///
    /// ```text
    /// head ── alba ── dino
    ///      ├─ bruno
    ///      └─ carla
    /// ```
    ///
    /// Then the fixture *works*: questions are asked and one is answered, money
    /// is reserved, tokens are recorded and carla is driven to its turn ceiling.
    /// Asserting zeroes would pass against a handler that returned a constant.
    struct Line {
        head: Uuid,
        alba: Uuid,
        bruno: Uuid,
        carla: Uuid,
        dino: Uuid,
    }

    async fn seed_line(h: &Harness) -> Line {
        let head = employee(&h.db, h.a, "head").await;
        let alba = employee(&h.db, h.a, "alba").await;
        let bruno = employee(&h.db, h.a, "bruno").await;
        let carla = employee(&h.db, h.a, "carla").await;
        let dino = employee(&h.db, h.a, "dino").await;

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let growth = org::create_team(&mut tx, &Slug::parse("growth").expect("slug"), "Growth")
            .await
            .expect("create team");
        for who in [head, alba, bruno, carla, dino] {
            org::set_member(&mut tx, EmployeeId::from_uuid(who), growth, None)
                .await
                .expect("join the team");
        }
        for (who, title, manager) in [
            (head, Some("Head of Growth"), None),
            (alba, Some("Growth rep"), Some(head)),
            // No title: a seat nobody has named is a supported state, and the
            // view has to render it as `null` rather than dropping the row.
            (bruno, None, Some(head)),
            (carla, Some("Ads"), Some(head)),
            (dino, Some("Intern"), Some(alba)),
        ] {
            org::set_position(
                &mut tx,
                EmployeeId::from_uuid(who),
                title,
                manager.map(EmployeeId::from_uuid),
            )
            .await
            .expect("seat");
        }
        // Alba may spend; nobody else has caps at all, which is the ordinary
        // state and reads as *may not spend*.
        spend::set_caps(
            &mut tx,
            EmployeeId::from_uuid(alba),
            SpendCaps::new(
                Money::new(50_000, Usd).expect("nonzero"),
                Money::new(25_000, Usd).expect("nonzero"),
                NonZeroU32::new(9).expect("nonzero"),
            )
            .expect("coherent"),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit the org chart");

        // Alba asks its head something and is still waiting. This also spends
        // one of the *head's* turns, which is what makes it a real message.
        say(h, alba, "head", Errand::Question, None, "q-alba").await;
        // The head asks bruno something and bruno has not answered.
        say(h, head, "bruno", Errand::Question, None, "q-head").await;
        // Bruno asks alba something and alba answers it: the answer must make
        // the question stop counting, because "unanswered" is derived from the
        // absence of a reply and not from a column somebody maintains.
        let asked = say(h, bruno, "alba", Errand::Question, None, "q-bruno").await;
        say(
            h,
            alba,
            "bruno",
            Errand::Answer,
            Some(Thread {
                conversation_id: asked.conversation_id,
                message_id: asked.message_id,
            }),
            "a-alba",
        )
        .await;

        // Alba spends real money, under a real reservation.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        spend::reserve(
            &mut tx,
            EmployeeId::from_uuid(alba),
            Utc::now().date_naive(),
            Money::new(1_000, Usd).expect("nonzero"),
        )
        .await
        .expect("reserve");
        // ...and burns real tokens, through the ledger's only writer.
        model_usage::record(
            &mut tx,
            EmployeeId::from_uuid(alba),
            Utc::now().date_naive(),
            Consumed::reported(3, 100, 20, 5),
        )
        .await
        .expect("record");
        // ...and carla writes a day's report having called nothing at all. The
        // live case this column exists for, through the same only writer: real
        // tokens, a real closing summary, and not one thing the gate ruled on.
        model_usage::record(
            &mut tx,
            EmployeeId::from_uuid(carla),
            Utc::now().date_naive(),
            Consumed::reported(1, 40, 3_000, 0).unbacked(0, NARRATION),
        )
        .await
        .expect("record");
        tx.commit().await.expect("commit the day's work");

        // Carla runs itself out of turns, which is the state a manager most
        // needs to see and the one nothing else on this surface surfaces.
        burn(h, carla, TURN_BUDGET).await;

        Line {
            head,
            alba,
            bruno,
            carla,
            dino,
        }
    }

    /// Find one report by slug, or fail with the whole body attached.
    fn report<'a>(body: &'a Value, slug: &str) -> &'a Value {
        body["reports"]
            .as_array()
            .unwrap_or_else(|| panic!("reports is not a list: {body}"))
            .iter()
            .find(|row| row["slug"] == json!(slug))
            .unwrap_or_else(|| panic!("no report named {slug}: {body}"))
    }

    // -----------------------------------------------------------------------
    // A. the view itself: three reports, and every number is one the fixture
    //    actually produced
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_head_sees_what_each_report_burned_spent_and_is_stuck_on() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let line = seed_line(&h).await;

        let (status, body) = h.line(line.head, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["employee_id"], json!(line.head.to_string()));
        assert_eq!(body["day"], json!(Utc::now().date_naive().to_string()));

        let reports = body["reports"].as_array().expect("a list");
        assert_eq!(reports.len(), 3, "three direct reports: {body}");
        // Oldest seat first, which is the order `org::reports` answers in.
        assert_eq!(reports[0]["slug"], json!("alba"));
        assert_eq!(reports[1]["slug"], json!("bruno"));
        assert_eq!(reports[2]["slug"], json!("carla"));

        // -- alba: one turn spent being asked, blocked on its own question ---
        let alba = report(&body, "alba");
        assert_eq!(alba["employee_id"], json!(line.alba.to_string()));
        assert_eq!(alba["title"], json!("Growth rep"));
        assert_eq!(alba["lifecycle"], json!("active"));
        // Bruno's question woke it once, and nothing else did.
        assert_eq!(alba["turns_taken"], json!(1), "{alba}");
        assert_eq!(alba["max_turns_per_day"], json!(TURN_BUDGET));
        assert_eq!(alba["turns_remaining"], json!(TURN_BUDGET - 1));
        assert_eq!(alba["exhausted"], json!(false));
        // It answered the one question put to it, so it owes nobody — and it is
        // waiting on the head, which is the thing that is stuck.
        assert_eq!(alba["questions_owed"], json!(0), "{alba}");
        assert_eq!(alba["questions_waiting_on"], json!(1), "{alba}");

        // Money: minor units and a currency, never a float, never bare.
        let spend = alba["spend"].as_array().expect("a list");
        assert_eq!(spend.len(), 1, "one currency: {alba}");
        assert_eq!(spend[0]["currency"], json!("USD"));
        assert_eq!(
            spend[0]["daily_total"],
            json!({"minor": 50_000, "currency": "USD"})
        );
        assert_eq!(spend[0]["spent_minor"], json!(1_000));
        assert_eq!(spend[0]["remaining_minor"], json!(49_000));

        // Tokens: what the ledger recorded, with the unmetered count beside it.
        let usage = &alba["model_usage"];
        assert_eq!(usage["calls"], json!(3), "{usage}");
        assert_eq!(usage["calls_unmetered"], json!(0));
        assert_eq!(usage["input_tokens"], json!(100));
        assert_eq!(usage["output_tokens"], json!(20));
        assert_eq!(usage["cache_read_tokens"], json!(5));
        assert_eq!(usage["tokens_measured"], json!(125));
        assert_eq!(usage["complete"], json!(true));
        // Alba's three calls reached the gate, so its prose has rows behind it
        // and there is nothing to say about it. Zero here is the ordinary
        // answer, and it has to be, or the column is an accusation against the
        // whole fleet.
        assert_eq!(usage["runs_unbacked"], json!(0), "{usage}");
        assert_eq!(usage["unbacked_chars"], json!(0));

        // -- bruno: owes the head an answer, and has no caps at all ----------
        let bruno = report(&body, "bruno");
        assert_eq!(bruno["employee_id"], json!(line.bruno.to_string()));
        assert_eq!(bruno["title"], Value::Null, "an unnamed seat is not a gap");
        // The head's question and alba's answer both woke it.
        assert_eq!(bruno["turns_taken"], json!(2), "{bruno}");
        assert_eq!(bruno["questions_owed"], json!(1), "{bruno}");
        // Its own question was answered, so it is blocked on nothing.
        assert_eq!(bruno["questions_waiting_on"], json!(0), "{bruno}");
        assert!(
            bruno["spend"].as_array().expect("a list").is_empty(),
            "no caps and no spending is an empty list, not a zero cap: {bruno}"
        );
        assert_eq!(bruno["model_usage"]["calls"], json!(0));
        assert_eq!(
            bruno["model_usage"]["complete"],
            json!(true),
            "a day with no calls has no unknown calls in it"
        );

        // -- carla: stopped for the day --------------------------------------
        let carla = report(&body, "carla");
        assert_eq!(carla["employee_id"], json!(line.carla.to_string()));
        assert_eq!(carla["turns_taken"], json!(TURN_BUDGET));
        assert_eq!(carla["turns_remaining"], json!(0));
        assert_eq!(
            carla["exhausted"],
            json!(true),
            "an employee at its cap has stopped, and this is the only view that says so"
        );

        // ...and wrote a day's report with nothing behind it. **The failure that
        // looks like success, on the screen an operator opens in the morning.**
        // Without these two fields carla's row is a healthy one: turns taken,
        // tokens spent, three thousand output tokens, no denial, no error.
        let carla_usage = &carla["model_usage"];
        assert_eq!(carla_usage["calls"], json!(1), "{carla_usage}");
        assert_eq!(carla_usage["output_tokens"], json!(3_000));
        assert_eq!(carla_usage["complete"], json!(true), "it was metered");
        assert_eq!(carla_usage["runs_unbacked"], json!(1), "{carla_usage}");
        assert_eq!(
            carla_usage["unbacked_chars"],
            json!(NARRATION.chars().count()),
            "the length is what separates a story from `nothing was due`: {carla_usage}"
        );

        // And bruno, which has no ledger row at all, reads as zero rather than
        // as missing. An employee that did not wake is not an employee that
        // talked its way through the day.
        assert_eq!(bruno["model_usage"]["runs_unbacked"], json!(0), "{bruno}");
        assert_eq!(bruno["model_usage"]["unbacked_chars"], json!(0));

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // B. one link, and one link only
    // -----------------------------------------------------------------------

    /// The rule the whole system holds: a manager sees who answers to it, not
    /// everyone underneath it. Dino answers to alba, so it is on alba's screen
    /// and on nobody else's.
    #[tokio::test]
    async fn an_employee_two_links_down_appears_only_under_its_own_manager() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let line = seed_line(&h).await;

        let (_, head) = h.line(line.head, SECRET_A).await;
        assert!(
            !head.to_string().contains(&line.dino.to_string()),
            "the head's line named an employee two links down: {head}"
        );
        assert_eq!(head["reports"].as_array().expect("a list").len(), 3);

        // ...and it is not lost, it is on the screen of the seat above it.
        let (status, alba) = h.line(line.alba, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{alba}");
        let reports = alba["reports"].as_array().expect("a list");
        assert_eq!(reports.len(), 1, "{alba}");
        assert_eq!(reports[0]["employee_id"], json!(line.dino.to_string()));
        assert_eq!(reports[0]["title"], json!("Intern"));

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // C. a manager with nobody under it
    // -----------------------------------------------------------------------

    /// Every individual contributor is in this state. It is a fact, not a
    /// missing resource — and a 404 here would make a typo in an id
    /// indistinguishable from an employee that manages nobody.
    #[tokio::test]
    async fn a_manager_with_no_reports_gets_an_empty_list_and_a_200() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let line = seed_line(&h).await;

        for (who, what) in [(line.dino, "a seated leaf"), (line.carla, "a seated peer")] {
            let (status, body) = h.line(who, SECRET_A).await;
            assert_eq!(status, StatusCode::OK, "{what}: {body}");
            assert!(
                body["reports"].as_array().expect("a list").is_empty(),
                "{what}: {body}"
            );
            assert_eq!(body["employee_id"], json!(who.to_string()));
        }

        // An employee holding no seat at all is the same answer: it exists, and
        // nobody answers to it.
        let unseated = employee(&h.db, h.a, "unseated").await;
        let (status, body) = h.line(unseated, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["reports"].as_array().expect("a list").is_empty());

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // D. the tenant comes from the key, and the refusal says nothing
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn another_tenants_employee_is_a_404_not_a_403() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let line = seed_line(&h).await;

        // B holds a valid credential and A's real head id, and learns nothing:
        // a 403 would confirm the employee exists.
        let (status, body) = h.line(line.head, SECRET_B).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(
            !body.to_string().contains("alba"),
            "the refusal leaked a report: {body}"
        );

        // An id nobody owns reads identically.
        let (status, _) = h.line(Uuid::now_v7(), SECRET_A).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // And A still sees its own.
        let (status, body) = h.line(line.head, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["reports"].as_array().expect("a list").len(), 3);

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // E. the cost of the view does not grow with the team
    // -----------------------------------------------------------------------

    /// Counts the statements sqlx actually sends, by counting the events it
    /// emits on the `sqlx::query` target — one per executed statement, from
    /// `QueryLogger` in `sqlx-core`.
    ///
    /// ponytail: a tracing layer rather than `pg_stat_statements`, which this
    /// database cannot load (`shared_preload_libraries` is empty and the
    /// extension is not installed). The subscriber is installed with
    /// `set_default`, which is thread-local, so this counts only what the test's
    /// own thread issued and cannot be perturbed by another test in the binary.
    #[derive(Clone, Default)]
    struct CountStatements(Arc<AtomicUsize>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountStatements {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() == "sqlx::query" {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A head with `n` reports, seated on their own team.
    async fn head_of(h: &Harness, label: &str, n: usize) -> Uuid {
        let head = employee(&h.db, h.a, &format!("{label}-head")).await;
        let mut reports = Vec::with_capacity(n);
        for i in 0..n {
            reports.push(employee(&h.db, h.a, &format!("{label}-{i}")).await);
        }

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let team = org::create_team(&mut tx, &Slug::parse(label).expect("slug"), label)
            .await
            .expect("create team");
        org::set_member(&mut tx, EmployeeId::from_uuid(head), team, None)
            .await
            .expect("join");
        org::set_position(&mut tx, EmployeeId::from_uuid(head), Some("Head"), None)
            .await
            .expect("seat the head");
        for who in &reports {
            let who = EmployeeId::from_uuid(*who);
            org::set_member(&mut tx, who, team, None)
                .await
                .expect("join");
            org::set_position(&mut tx, who, None, Some(EmployeeId::from_uuid(head)))
                .await
                .expect("seat");
            // Caps and a bucket each, so the per-currency query really has rows
            // to return for every one of them.
            spend::set_caps(
                &mut tx,
                who,
                SpendCaps::new(
                    Money::new(50_000, Usd).expect("nonzero"),
                    Money::new(25_000, Usd).expect("nonzero"),
                    NonZeroU32::new(9).expect("nonzero"),
                )
                .expect("coherent"),
            )
            .await
            .expect("caps");
            spend::reserve(
                &mut tx,
                who,
                Utc::now().date_naive(),
                Money::new(100, Usd).expect("nonzero"),
            )
            .await
            .expect("reserve");
        }
        tx.commit().await.expect("commit");
        head
    }

    /// **The property that decides whether this endpoint survives contact with a
    /// real fleet.** Five reports must cost what one report costs: the same
    /// statements, with more rows in them.
    ///
    /// The naive shape — `org::reports`, then a turn read, a policy load, a
    /// spend read, a usage read and two question counts per report — is `1 + 6n`
    /// statements against this handler's constant seven. Adding a single
    /// per-report `SELECT` to the handler turns this assertion red at 8 against
    /// 12, which is how it was checked to be measuring anything.
    #[tokio::test]
    async fn the_statement_count_does_not_grow_with_the_size_of_the_team() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let small = head_of(&h, "small", 1).await;
        let large = head_of(&h, "large", 5).await;

        // Warm the pool first: the connection this request runs on must already
        // exist, or the first call pays for opening one and the comparison is
        // measuring that instead.
        h.line(small, SECRET_A).await;

        let counter = CountStatements::default();
        let statements = |counter: &CountStatements| counter.0.swap(0, Ordering::Relaxed);

        // Arm the meter on a real query, and prove it is armed before trusting a
        // number from it.
        //
        // `tracing` caches each callsite's *interest* in a global the first time
        // that callsite is hit, and when only one dispatcher exists it computes
        // that interest from **the registering thread's** default subscriber
        // (`Rebuilder::JustOne` in `tracing_core::callsite`). The other tests in
        // this binary run in parallel with no subscriber of their own, so
        // whichever of them touches sqlx first can pin its callsite to "never"
        // for the whole process — after which no layer sees a statement, and a
        // naive version of this test would read zero and pass its equality
        // vacuously. Registering a second dispatcher rebuilds every known
        // callsite's interest, so the retry converges; arming on a *real* query
        // rather than a hand-written event is what makes it the same callsite
        // the measurement depends on.
        let mut armed = None;
        for _ in 0..10 {
            let guard = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(counter.clone()),
            );
            let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
            sqlx::query("SELECT 1")
                .execute(&mut **tx)
                .await
                .expect("a statement to count");
            tx.rollback().await.expect("rollback");
            if statements(&counter) > 0 {
                armed = Some(guard);
                break;
            }
        }
        let guard = armed.expect(
            "the meter never saw a statement sqlx really executed, so it cannot \
             count them and this test would prove nothing",
        );

        let (status, one) = h.line(small, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{one}");
        let for_one = statements(&counter);

        let (status, five) = h.line(large, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{five}");
        let for_five = statements(&counter);
        drop(guard);

        assert_eq!(one["reports"].as_array().expect("a list").len(), 1);
        assert_eq!(five["reports"].as_array().expect("a list").len(), 5);

        // A request is the transaction's own statements plus the four this
        // handler issues — seven in all today. The exact number is not the
        // property being asserted, but a meter reading nothing at all would make
        // the equality below a green light for any implementation.
        assert!(
            for_one >= 4,
            "one report cost {for_one} statements, which is fewer than this \
             handler issues: the meter is not seeing sqlx"
        );
        assert_eq!(
            for_one, for_five,
            "five reports cost {for_five} statements and one costs {for_one}: \
             this view gets slower every time somebody is hired"
        );

        h.teardown().await;
    }
}
