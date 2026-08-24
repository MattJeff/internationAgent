//! `GET /v1/autonomy`: how much of the work the agents actually did.
//!
//! # Why this endpoint exists
//!
//! The claim this project will eventually have to defend is *"the agents did
//! the work"*, and the first question anybody asks is *"how much did you do
//! yourself?"*. Every action already writes an audit row and every approval
//! writes another, so the evidence was there; nothing aggregated it, so the
//! honest answer was "we don't know". This is the answer, per tenant and per
//! employee, over a window an operator chooses.
//!
//! # The principle, before the numbers
//!
//! **When an event can be read as autonomous or as assisted, it is counted as
//! assisted.** This number will be quoted in public. Every definition below is
//! the one that makes it *smaller*: the percentage truncates rather than
//! rounds, a `system` actor counts against autonomy, and an operator who drove
//! an action through the API counts as an intervention even though the trail
//! cannot say whether they were rescuing the agent or just using the API.
//!
//! A future edit that loosens one of these is loosening a claim, not fixing a
//! bug. Say so in the commit message.
//!
//! # The taxonomy
//!
//! Four kinds of human involvement, kept apart because averaging them together
//! produces a number that flatters whichever is cheapest:
//!
//! | kind | what the row looks like | in the ratio? |
//! |---|---|---|
//! | **approved** | `decision = 'allow'` with an `approval_id` in the payload — only `PolicyGate::redeem_approval` writes that | intervention |
//! | **rejected** | `action_kind = 'approval_decided'`, `payload.outcome = 'denied'` — only [`super::approvals::deny`] writes that | intervention |
//! | **configuring** | `action_kind = 'policy_changed'` | **neither** — setup is not intervention |
//! | **acting in the agent's place** | `decision = 'allow'`, operator actor, no approval spent | intervention |
//!
//! Autonomy is one bucket and one only: `decision = 'allow'`, an *employee*
//! actor, no approval spent.
//!
//! ```text
//! decisions    = actions_taken + human_rejected
//! autonomy_pct = 100 * actions_unassisted / decisions
//! ```
//!
//! A rejection produced no action, so it is not in `actions_taken` — but it is
//! in the denominator, because a human spent attention on it. Configuration is
//! in neither term: letting it inflate `actions_taken` would be the single
//! easiest way to flatter this figure, so it has its own column and no path
//! into the arithmetic. A policy *denial* is not an intervention either — the
//! human who wrote the policy is already counted under configuration, and
//! charging them twice for one act would understate autonomy for a reason that
//! is not true.
//!
//! The full derivation, and the reason each `filter` clause is spelled the way
//! it is, lives in `migrations/0021_autonomy.sql` next to the SQL.
//!
//! # What the audit trail cannot distinguish today
//!
//! Read this before quoting the number anywhere. In full in the migration; the
//! four that change how the figure should be read:
//!
//! * **Operator-initiated is not the same as operator-as-fallback.** Nothing in
//!   the trail says whether a human drove an action *because the agent could
//!   not*. Both are counted as interventions — the strict reading, which
//!   overstates intervention rather than autonomy.
//! * **"Who" is a credential, not a person.** `AuditActor::Operator` holds the
//!   API key's label ([`crate::auth`]). Two humans on one key are one actor.
//! * **Most configuration leaves no audit row at all.** Only `routes::teams`
//!   and `routes::mcp` write `policy_changed`; charters, cadences, psyches and
//!   employee creation write nothing. `configuration_changes` is a floor, not a
//!   count, so the setup behind an autonomous-looking employee is largely
//!   invisible.
//! * **Rulings, not outcomes.** One row per `authorize` call, so an agent that
//!   retries the same email three times books three actions — a chatty agent
//!   scores higher than a careful one. And an authorised action is not a
//!   completed one.
//!
//! # Cost is not here, on purpose
//!
//! There is no revenue-over-cost figure and no `cost_minor`. Token counts come
//! back from the provider (`agentos_providers::llm::Usage`, filled from the
//! Anthropic response in `llm_anthropic.rs`) and are written to exactly two
//! places: a process-local counter that explicitly drops the tenant
//! ([`crate::metrics::record_llm_usage`]) and `tracing` log lines. No table, no
//! audit row, no column anywhere in `migrations/`. There is no price list in
//! this codebase either, so even with tokens a euro figure would rest on a
//! number nobody could trace — and a cost figure nobody can trace is worse than
//! a missing one. Two things must land before one is possible: a `model_usage
//! (tenant_id, employee_id, day, input_tokens, output_tokens,
//! cache_read_tokens)` row written where `finished.usage` is logged today, and
//! a price table with a source.
//!
//! # The aggregate cannot be written by hand
//!
//! `employee_autonomy_daily` is a VIEW over `audit_log`, following
//! `supplier_reputation` in `0007_sourcing.sql` and for the same reason: a
//! score nobody can write is a score nobody can inflate. It aggregates, so
//! Postgres refuses a write to it under any privilege, and `app_role` holds
//! SELECT and nothing else. There is no recompute job to go stale.
//!
//! # The tenant
//!
//! From [`Principal`], i.e. from the API key. The view is `security_invoker`
//! over an RLS'd `audit_log`, so there is no `WHERE tenant_id` here for anyone
//! to forget and another tenant's autonomy is not merely unlisted — it is
//! invisible.

use agentos_store::db::{Db, StoreError};
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// How far back `GET /v1/autonomy` looks when the caller names no window.
///
/// ponytail: a constant, not a setting. Thirty days is the window anybody
/// quoting this number is quoting; make it configurable the day someone asks.
const DEFAULT_WINDOW_DAYS: i64 = 30;

/// The longest window that will be served in one request.
///
/// Not a paging limit — the response is one row per employee either way — but a
/// bound on how much of `audit_log` a single query aggregates, since the view's
/// `day` predicate is an expression and cannot use the trail's index.
const MAX_WINDOW_DAYS: i64 = 366;

/// This unit's routes.
///
/// ponytail: `allow(dead_code)` for the same reason [`super::inventory`] and
/// [`super::turns`] carried it — this unit owns `routes/autonomy.rs` and one
/// `pub mod` line, and `main.rs`, where every router is merged, belongs to
/// another unit. Delete the attribute in the same commit that adds
/// `.merge(routes::autonomy::router(db.clone()))` to `app`; until then the
/// tests below are the only caller.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/autonomy", get_route(get))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------

/// `?from=2026-07-01&to=2026-07-31`, both optional, both UTC calendar days.
///
/// `to` is **inclusive**, because an operator asking for "the 1st to the 31st"
/// means the 31st. The half-open bound the SQL wants is derived once, in
/// [`Window::resolve`], rather than left for each reader to remember.
#[derive(Debug, Deserialize)]
struct WindowQuery {
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
}

/// The resolved window: `[from, to]` inclusive as the caller sees it, `[from,
/// end)` half-open as the query runs it.
#[derive(Debug, Clone, Copy)]
struct Window {
    from: NaiveDate,
    to: NaiveDate,
}

impl Window {
    /// Fill in the defaults and refuse the shapes that would answer nonsense.
    ///
    /// The day is UTC throughout, matching `spend_buckets` and the turn
    /// budget — an employee must not have two "todays".
    fn resolve(query: &WindowQuery) -> Result<Self, ApiError> {
        let today = Utc::now().date_naive();
        let to = query.to.unwrap_or(today);
        let from = query.from.unwrap_or_else(|| {
            to.checked_sub_signed(Duration::days(DEFAULT_WINDOW_DAYS - 1))
                .unwrap_or(to)
        });

        if from > to {
            return Err(ApiError::bad_request("from: must not be after to"));
        }
        let span = (to - from).num_days() + 1;
        if span > MAX_WINDOW_DAYS {
            return Err(ApiError::bad_request(format!(
                "window: at most {MAX_WINDOW_DAYS} days"
            )));
        }
        Ok(Self { from, to })
    }

    /// The exclusive upper bound the SQL uses.
    fn end(self) -> NaiveDate {
        self.to
            .checked_add_signed(Duration::days(1))
            .unwrap_or(self.to)
    }
}

// ---------------------------------------------------------------------------
// The counts
// ---------------------------------------------------------------------------

/// The sums, over the window, for one employee — or for the tenant, once
/// [`Counts::add`] has folded every row together.
///
/// One struct and one query rather than a separate tenant rollup: a second
/// statement would be a second place for the column list to drift, and folding
/// nine integers in Rust is cheaper than that risk.
#[derive(Debug, Clone, Copy, Default, Serialize, sqlx::FromRow)]
struct Counts {
    /// Every Policy Gate ruling that permitted an action. The four fields below
    /// partition this exactly.
    actions_taken: i64,
    /// **The only bucket that counts as autonomy**: the employee acted, and no
    /// approval was spent.
    actions_unassisted: i64,
    /// The gate asked and a person said yes.
    human_approved: i64,
    /// A human drove the action through the API. See the module docs on what
    /// this cannot distinguish.
    operator_initiated: i64,
    /// A cadence tick, a webhook, the outbox poller. Not a human, and not the
    /// agent choosing either — so it is in the denominator and in no numerator.
    system_initiated: i64,
    /// A person said no. Produced no action, so it is *not* in `actions_taken`,
    /// but it is in the denominator.
    human_rejected: i64,
    /// The gate stopped and asked. Context, not an intervention: it resolves
    /// into an approval, a rejection, or silence.
    escalations_raised: i64,
    /// The policy refused. Not a human intervention — see the module docs.
    policy_denied: i64,
    /// Setup: a policy, an MCP endpoint, a team move. Counted, and in neither
    /// term of the ratio.
    configuration_changes: i64,
}

impl Counts {
    /// Fold another row's sums in. Saturating, because a wrapped count would be
    /// a silently wrong public claim.
    fn add(&mut self, other: &Self) {
        self.actions_taken = self.actions_taken.saturating_add(other.actions_taken);
        self.actions_unassisted = self
            .actions_unassisted
            .saturating_add(other.actions_unassisted);
        self.human_approved = self.human_approved.saturating_add(other.human_approved);
        self.operator_initiated = self
            .operator_initiated
            .saturating_add(other.operator_initiated);
        self.system_initiated = self.system_initiated.saturating_add(other.system_initiated);
        self.human_rejected = self.human_rejected.saturating_add(other.human_rejected);
        self.escalations_raised = self
            .escalations_raised
            .saturating_add(other.escalations_raised);
        self.policy_denied = self.policy_denied.saturating_add(other.policy_denied);
        self.configuration_changes = self
            .configuration_changes
            .saturating_add(other.configuration_changes);
    }

    /// Every human intervention, of every kind, in this window.
    ///
    /// Deliberately a sum of three named columns rather than a column of its
    /// own: a reader who disagrees with one of the three can subtract it, which
    /// is not possible once they have been blended into a single stored number.
    const fn interventions(self) -> i64 {
        self.human_approved + self.operator_initiated + self.human_rejected
    }

    /// Everything a human or an agent had to make happen: every action taken,
    /// plus every request a human refused.
    const fn decisions(self) -> i64 {
        self.actions_taken + self.human_rejected
    }

    /// The headline. `None` when there was nothing to divide by, because "no
    /// data" is not "0% autonomous".
    ///
    /// Integer division, so it truncates downward — 99.9% reads as 99. That is
    /// the direction every ambiguity in this module resolves in.
    ///
    /// Mirrors `autonomy_pct` in `migrations/0021_autonomy.sql`, which computes
    /// the same thing for a single day.
    /// `a_one_day_window_agrees_with_the_views_own_ratio` fails if they drift.
    fn autonomy_pct(self) -> Option<i64> {
        let decisions = self.decisions();
        (decisions > 0).then(|| self.actions_unassisted.saturating_mul(100) / decisions)
    }
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// One employee's row, or the tenant's total, with the derived figures spelled
/// out beside the counts they come from.
#[derive(Debug, Serialize)]
struct Rollup {
    #[serde(flatten)]
    counts: Counts,
    interventions: i64,
    decisions: i64,
    /// `null` when this employee did nothing in the window.
    autonomy_pct: Option<i64>,
}

impl From<Counts> for Rollup {
    fn from(counts: Counts) -> Self {
        Self {
            counts,
            interventions: counts.interventions(),
            decisions: counts.decisions(),
            autonomy_pct: counts.autonomy_pct(),
        }
    }
}

/// One row of [`ROLLUP_SQL`]: an employee (or none) and its summed counts.
///
/// `#[sqlx(flatten)]` so the column list lives in exactly one struct —
/// [`Counts`] — and the query, the JSON and the arithmetic cannot disagree
/// about what a column is called.
#[derive(Debug, sqlx::FromRow)]
struct RollupRow {
    employee_id: Option<Uuid>,
    slug: Option<String>,
    #[sqlx(flatten)]
    counts: Counts,
}

/// One employee, named so an operator does not have to resolve UUIDs by hand.
#[derive(Debug, Serialize)]
struct EmployeeRollup {
    employee_id: Uuid,
    /// `None` when the trail names an employee row that no longer exists —
    /// `audit_log` deliberately has no foreign key to `employees`, because
    /// deleting an employee must not delete its history.
    slug: Option<String>,
    #[serde(flatten)]
    rollup: Rollup,
}

/// What the endpoint answers.
#[derive(Debug, Serialize)]
struct AutonomyView {
    /// Inclusive, UTC.
    from: NaiveDate,
    /// Inclusive, UTC.
    to: NaiveDate,
    /// Every row in the window, including the ones attributed to no employee —
    /// tenant-level configuration, a phone number added to the pool.
    tenant: Rollup,
    /// Per employee, busiest first. Rows with no employee are in `tenant` and
    /// not here, because they belong to nobody.
    employees: Vec<EmployeeRollup>,
}

// ---------------------------------------------------------------------------
// The query
// ---------------------------------------------------------------------------

/// One row per employee in the window, plus one for the rows that name none.
///
/// No `WHERE tenant_id`: `employee_autonomy_daily` is `security_invoker` over
/// an RLS'd `audit_log`, so the tenant predicate is the policy rather than a
/// filter each reader has to remember. `sum(...)::bigint` because `sum()` over
/// `bigint` is `numeric` in Postgres, and this crate has no decimal type.
///
/// `LEFT JOIN` on `employees` for the slug: a trail row naming an employee that
/// has since been deleted is a fact worth rendering, not a reason to drop it.
const ROLLUP_SQL: &str = "\
SELECT v.employee_id, \
       e.slug, \
       sum(v.actions_taken)::bigint         AS actions_taken, \
       sum(v.actions_unassisted)::bigint    AS actions_unassisted, \
       sum(v.human_approved)::bigint        AS human_approved, \
       sum(v.operator_initiated)::bigint    AS operator_initiated, \
       sum(v.system_initiated)::bigint      AS system_initiated, \
       sum(v.human_rejected)::bigint        AS human_rejected, \
       sum(v.escalations_raised)::bigint    AS escalations_raised, \
       sum(v.policy_denied)::bigint         AS policy_denied, \
       sum(v.configuration_changes)::bigint AS configuration_changes \
  FROM employee_autonomy_daily v \
  LEFT JOIN employees e ON e.id = v.employee_id \
 WHERE v.day >= $1 AND v.day < $2 \
 GROUP BY v.employee_id, e.slug \
 ORDER BY sum(v.actions_taken) DESC, e.slug NULLS LAST";

/// `GET /v1/autonomy?from=…&to=…`.
///
/// 200 with zeroes is the ordinary answer for a tenant that has done nothing in
/// the window — "no activity" is a fact, not a missing resource — and
/// `autonomy_pct` is `null` there rather than 0, which would read as "the
/// agents did none of the work".
async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<WindowQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let window = Window::resolve(&query)?;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let rows: Vec<RollupRow> = sqlx::query_as(ROLLUP_SQL)
        .bind(window.from)
        .bind(window.end())
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.rollback().await?;

    let mut tenant = Counts::default();
    let mut employees = Vec::with_capacity(rows.len());
    for row in rows {
        tenant.add(&row.counts);
        // Rows with no employee are the tenant's own: configuration, a number
        // added to the pool. They belong in the total and to nobody, so they
        // are folded above and skipped here.
        if let Some(employee_id) = row.employee_id {
            employees.push(EmployeeRollup {
                employee_id,
                slug: row.slug,
                rollup: Rollup::from(row.counts),
            });
        }
    }

    Ok(axum::Json(AutonomyView {
        from: window.from,
        to: window.to,
        tenant: Rollup::from(tenant),
        employees,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::gate::{Denied, PolicyBook, PolicyGate, Principal as GatePrincipal};
    use agentos_domain::action::{Action, Channel, EmailAddress};
    use agentos_domain::ids::{ApprovalId, EmployeeId, TenantId};
    use agentos_domain::policy::PolicyLimits;
    use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // -- fixtures ----------------------------------------------------------
    //
    // Every row these tests measure is written by the real writer: the Policy
    // Gate for actions and escalations, `routes::approvals` for an approval and
    // a rejection. Hand-inserted audit rows would only prove that the view
    // matches what this test file *believes* the trail looks like, which is
    // precisely the thing the taxonomy has to get right.

    /// Email is allowed and contracts always need a human, so one policy book
    /// produces both an autonomous action and an escalation without any
    /// per-test tuning.
    fn limits() -> PolicyLimits {
        PolicyLimits {
            allowed_channels: BTreeSet::from([Channel::Email]),
            // High enough that the cold-outreach budget never fires: these
            // tests are about who acted, not about what the policy allows.
            max_new_contacts_per_day: 1_000,
            ..PolicyLimits::default()
        }
    }

    struct Harness {
        app: Router,
        approvals: Router,
        db: Db,
        gate: PolicyGate,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; autonomy routes need a real Postgres");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            // The key's label *is* the caller's role on the approval queue, so
            // both tenants' keys are labelled `approver`.
            let keys = ApiKeys::parse(&format!(
                "approver:{}:{SECRET_A},approver:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            let gate = PolicyGate::new(db.clone(), PolicyBook::new(limits()));

            Some(Self {
                app: crate::with_api_stack(router(db.clone()), db.clone(), keys.clone()),
                approvals: crate::with_api_stack(
                    super::super::approvals::router(db.clone(), gate.clone()),
                    db.clone(),
                    keys,
                ),
                db,
                gate,
                a,
                b,
            })
        }

        async fn autonomy(&self, uri: &str, secret: &str) -> (StatusCode, Value) {
            call(&self.app, "GET", uri, secret, None).await
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

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        secret: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let req = HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {secret}"));
        let req = match &body {
            Some(body) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => req.body(Body::empty()),
        }
        .expect("request");

        let response = app.clone().oneshot(req).await.expect("service");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'autonomy-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
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

    fn email(to: &str) -> Action {
        Action::EmailSend {
            to: EmailAddress::parse(to).expect("address"),
        }
    }

    fn contract(title: &str) -> Action {
        Action::ContractSign {
            title: title.to_owned(),
        }
    }

    /// The agent acting on its own: one allowed action, no human anywhere.
    async fn agent_acts(h: &Harness, tenant: TenantId, who: EmployeeId, to: &str) {
        h.gate
            .authorize(&GatePrincipal::employee(tenant, who), email(to))
            .await
            .expect("email is allowed");
    }

    /// A human acting in the agent's place: same gate, same action, operator
    /// credential.
    async fn operator_acts(h: &Harness, tenant: TenantId, who: EmployeeId, to: &str) {
        h.gate
            .authorize(&GatePrincipal::operator(tenant, who, "approver"), email(to))
            .await
            .expect("email is allowed");
    }

    /// Ask for something the gate must escalate, and return the filed approval.
    async fn escalate(h: &Harness, tenant: TenantId, who: EmployeeId, title: &str) -> ApprovalId {
        match h
            .gate
            .authorize(&GatePrincipal::employee(tenant, who), contract(title))
            .await
        {
            Err(Denied::PendingApproval(id)) => id,
            other => panic!("expected a pending approval, got {other:?}"),
        }
    }

    /// One configuration change, written exactly as `routes::teams::record` and
    /// `routes::mcp::record` write theirs.
    async fn configure(h: &Harness, tenant: TenantId, who: Option<EmployeeId>) {
        let mut tx = h.db.tenant_tx(tenant).await.expect("tenant tx");
        audit::append(
            &mut tx,
            &AuditEvent {
                employee_id: who,
                payload: json!({ "event": "team_budget_set" }),
                ..AuditEvent::new(
                    AuditActor::Operator("approver".to_owned()),
                    AuditKind::PolicyChanged,
                    Utc::now(),
                )
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");
    }

    // -----------------------------------------------------------------------
    // A. an approval and a rejection are both interventions, and distinguishable
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_approval_and_a_rejection_are_both_interventions_and_stay_apart() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;

        // Two escalations. One a human grants, one a human refuses.
        let granted = escalate(&h, h.a, lena, "the deal we sign").await;
        let refused = escalate(&h, h.a, lena, "the deal we do not sign").await;

        let (status, body) = call(
            &h.approvals,
            "POST",
            &format!("/v1/approvals/{}/approve", granted.as_uuid()),
            SECRET_A,
            Some(json!({ "action": contract("the deal we sign") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            &h.approvals,
            "POST",
            &format!("/v1/approvals/{}/deny", refused.as_uuid()),
            SECRET_A,
            Some(json!({ "note": "the terms are wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = h.autonomy("/v1/autonomy", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let t = &body["tenant"];

        // Both are interventions...
        assert_eq!(t["interventions"], json!(2), "{t}");
        // ...and they are not the same fact.
        assert_eq!(t["human_approved"], json!(1), "{t}");
        assert_eq!(t["human_rejected"], json!(1), "{t}");

        // The approved one produced an action; the refused one did not. That
        // asymmetry is the whole reason they are separate columns.
        assert_eq!(t["actions_taken"], json!(1), "{t}");
        assert_eq!(t["escalations_raised"], json!(2), "{t}");

        // Neither counts as autonomy. The gate ruled twice and acted once, and
        // a human was behind every bit of it.
        assert_eq!(t["actions_unassisted"], json!(0), "{t}");
        assert_eq!(t["decisions"], json!(2), "{t}");
        assert_eq!(t["autonomy_pct"], json!(0), "{t}");

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // B. configuration is not an intervention, and is not autonomy either
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn configuration_is_counted_separately_and_moves_neither_side_of_the_ratio() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;

        // Two actions the agent took on its own. Nothing else.
        agent_acts(&h, h.a, lena, "one@example.com").await;
        agent_acts(&h, h.a, lena, "two@example.com").await;

        let (_, before) = h.autonomy("/v1/autonomy", SECRET_A).await;
        assert_eq!(before["tenant"]["autonomy_pct"], json!(100), "{before}");
        assert_eq!(before["tenant"]["configuration_changes"], json!(0));

        // Now a human configures things — twice for the employee, once for the
        // tenant with no employee at all.
        configure(&h, h.a, Some(lena)).await;
        configure(&h, h.a, Some(lena)).await;
        configure(&h, h.a, None).await;

        let (_, after) = h.autonomy("/v1/autonomy", SECRET_A).await;
        let t = &after["tenant"];

        // Recorded, and visible: setup effort is not hidden.
        assert_eq!(t["configuration_changes"], json!(3), "{t}");

        // ... and in neither term. Setup is not intervention, and it is
        // certainly not an action the agent took.
        assert_eq!(t["interventions"], json!(0), "{t}");
        assert_eq!(t["actions_taken"], json!(2), "{t}");
        assert_eq!(t["decisions"], json!(2), "{t}");
        assert_eq!(t["autonomy_pct"], json!(100), "{t}");

        // The tenant-level row (no employee) is in the total and attributed to
        // nobody, which is the only honest place for it.
        let employees = after["employees"].as_array().expect("a list");
        assert_eq!(employees.len(), 1, "{after}");
        assert_eq!(employees[0]["configuration_changes"], json!(2));
        assert_eq!(employees[0]["slug"], json!("lena"));

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // C. the four buckets partition the allowed actions, and the ambiguous ones
    //    fall on the side that makes autonomy smaller
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_operator_acting_in_the_agents_place_is_not_autonomy() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;

        // Three actions: two by the agent, one by a human through the API.
        agent_acts(&h, h.a, lena, "one@example.com").await;
        agent_acts(&h, h.a, lena, "two@example.com").await;
        operator_acts(&h, h.a, lena, "three@example.com").await;

        let (_, body) = h.autonomy("/v1/autonomy", SECRET_A).await;
        let t = &body["tenant"];

        assert_eq!(t["actions_taken"], json!(3), "{t}");
        assert_eq!(t["actions_unassisted"], json!(2), "{t}");
        assert_eq!(t["operator_initiated"], json!(1), "{t}");
        assert_eq!(t["interventions"], json!(1), "{t}");

        // 2/3 truncates to 66, not 67. Every ambiguity in this module resolves
        // downward, including the rounding.
        assert_eq!(t["autonomy_pct"], json!(66), "{t}");

        // The buckets partition `actions_taken` exactly — no allowed action is
        // counted twice and none escapes classification.
        let sum = t["actions_unassisted"].as_i64().unwrap()
            + t["human_approved"].as_i64().unwrap()
            + t["operator_initiated"].as_i64().unwrap()
            + t["system_initiated"].as_i64().unwrap();
        assert_eq!(sum, t["actions_taken"].as_i64().unwrap(), "{t}");

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // D. one tenant's autonomy is invisible to another
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn one_tenants_autonomy_is_invisible_to_another() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let mine = employee(&h.db, h.a, "lena").await;
        let theirs = employee(&h.db, h.b, "rival").await;

        // A does a lot of work by itself. B does none, and needs a human for
        // the one thing it starts.
        for to in ["one@example.com", "two@example.com", "three@example.com"] {
            agent_acts(&h, h.a, mine, to).await;
        }
        escalate(&h, h.b, theirs, "b's contract").await;

        let (_, a_view) = h.autonomy("/v1/autonomy", SECRET_A).await;
        assert_eq!(a_view["tenant"]["actions_taken"], json!(3), "{a_view}");
        assert_eq!(a_view["tenant"]["autonomy_pct"], json!(100), "{a_view}");
        assert_eq!(a_view["tenant"]["escalations_raised"], json!(0), "{a_view}");
        let a_employees = a_view["employees"].as_array().expect("a list");
        assert_eq!(a_employees.len(), 1, "{a_view}");
        assert_eq!(a_employees[0]["slug"], json!("lena"));

        // B sees its own trail and nothing of A's — not merely unlisted, but
        // absent from the totals, because RLS is doing the scoping.
        let (_, b_view) = h.autonomy("/v1/autonomy", SECRET_B).await;
        assert_eq!(b_view["tenant"]["actions_taken"], json!(0), "{b_view}");
        assert_eq!(b_view["tenant"]["escalations_raised"], json!(1), "{b_view}");
        assert_eq!(b_view["tenant"]["autonomy_pct"], Value::Null, "{b_view}");
        let b_employees = b_view["employees"].as_array().expect("a list");
        assert_eq!(b_employees.len(), 1, "{b_view}");
        assert_eq!(b_employees[0]["slug"], json!("rival"));
        assert!(
            !b_view.to_string().contains(&mine.as_uuid().to_string()),
            "tenant B's view named tenant A's employee: {b_view}"
        );

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // E. the aggregate cannot be written by hand
    // -----------------------------------------------------------------------

    /// The property that makes this a measurement rather than a claim. Same
    /// discipline `supplier_reputation` enforces, and for the same reason.
    #[tokio::test]
    async fn the_aggregate_cannot_be_written_by_hand() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;
        agent_acts(&h, h.a, lena, "one@example.com").await;

        for statement in [
            "INSERT INTO employee_autonomy_daily \
             (tenant_id, employee_id, day, actions_taken, actions_unassisted, autonomy_pct) \
             VALUES ($1, $2, current_date, 1000, 1000, 100)",
            "UPDATE employee_autonomy_daily SET actions_unassisted = 1000 \
              WHERE tenant_id = $1 AND employee_id = $2",
            "DELETE FROM employee_autonomy_daily WHERE tenant_id = $1 AND employee_id = $2",
        ] {
            // A failed statement poisons the transaction, so each attempt gets
            // its own.
            let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
            let err = sqlx::query(statement)
                .bind(h.a.as_uuid())
                .bind(lena.as_uuid())
                .execute(&mut **tx)
                .await
                .expect_err("the autonomy aggregate must not be writable");
            // On the SQLSTATE, never on the message: Postgres translates its
            // text into the server's `lc_messages` locale, and this container
            // runs under fr_FR. `55000` is object_not_in_prerequisite_state,
            // which is what a non-auto-updatable view raises; `42501` is
            // insufficient_privilege, which is what the missing grant would
            // raise if the view ever became updatable.
            let sqlstate = err
                .as_database_error()
                .and_then(|e| e.code())
                .unwrap_or_default()
                .into_owned();
            assert!(
                sqlstate == "55000" || sqlstate == "42501",
                "expected `{statement}` to be refused with 55000 or 42501, \
                 got SQLSTATE {sqlstate}: {err}"
            );
            tx.rollback().await.expect("rollback");
        }

        // And the real number is untouched.
        let (_, body) = h.autonomy("/v1/autonomy", SECRET_A).await;
        assert_eq!(body["tenant"]["actions_unassisted"], json!(1), "{body}");

        h.teardown().await;
    }

    // -----------------------------------------------------------------------
    // F. the window, and the one place the ratio is defined twice
    // -----------------------------------------------------------------------

    /// The route sums the view's daily counts and recomputes the ratio; the
    /// view computes it per day. Over a one-day window the two must agree, and
    /// this is what stops them drifting apart.
    #[tokio::test]
    async fn a_one_day_window_agrees_with_the_views_own_ratio() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;
        agent_acts(&h, h.a, lena, "one@example.com").await;
        agent_acts(&h, h.a, lena, "two@example.com").await;
        operator_acts(&h, h.a, lena, "three@example.com").await;

        let today = Utc::now().date_naive();
        let (status, body) = h
            .autonomy(&format!("/v1/autonomy?from={today}&to={today}"), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let from_view: Option<i32> = sqlx::query_scalar(
            "SELECT autonomy_pct FROM employee_autonomy_daily \
              WHERE employee_id = $1 AND day = $2",
        )
        .bind(lena.as_uuid())
        .bind(today)
        .fetch_one(&mut **tx)
        .await
        .expect("the view's own ratio");
        tx.rollback().await.expect("rollback");

        assert_eq!(
            body["employees"][0]["autonomy_pct"].as_i64(),
            from_view.map(i64::from),
            "the route and the view disagree about the same day: {body}"
        );

        // A window that contains none of it is empty, not wrong.
        let long_ago = today - Duration::days(90);
        let (_, empty) = h
            .autonomy(
                &format!("/v1/autonomy?from={long_ago}&to={long_ago}"),
                SECRET_A,
            )
            .await;
        assert_eq!(empty["tenant"]["actions_taken"], json!(0), "{empty}");
        assert_eq!(empty["tenant"]["autonomy_pct"], Value::Null, "{empty}");
        assert!(empty["employees"].as_array().expect("a list").is_empty());

        h.teardown().await;
    }

    #[tokio::test]
    async fn a_backwards_or_oversized_window_is_refused() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let today = Utc::now().date_naive();

        let (status, _) = h
            .autonomy(
                &format!("/v1/autonomy?from={today}&to={}", today - Duration::days(1)),
                SECRET_A,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = h
            .autonomy(
                &format!(
                    "/v1/autonomy?from={}&to={today}",
                    today - Duration::days(MAX_WINDOW_DAYS)
                ),
                SECRET_A,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // An unparseable date is a 400, not a silently ignored parameter.
        let (status, _) = h.autonomy("/v1/autonomy?from=last-tuesday", SECRET_A).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        h.teardown().await;
    }

    /// The default window, with no parameters at all, is the one an operator
    /// gets — so it has to be the one that is tested.
    #[test]
    fn the_default_window_is_thirty_days_ending_today() {
        let window = Window::resolve(&WindowQuery {
            from: None,
            to: None,
        })
        .expect("the default window is valid");
        let today = Utc::now().date_naive();

        assert_eq!(window.to, today);
        assert_eq!(window.from, today - Duration::days(DEFAULT_WINDOW_DAYS - 1));
        // Inclusive to the caller, half-open to the SQL: the day named in `to`
        // is in the window.
        assert_eq!(window.end(), today + Duration::days(1));
        assert_eq!(
            (window.to - window.from).num_days() + 1,
            DEFAULT_WINDOW_DAYS
        );
    }

    /// The arithmetic, without a database. Every branch of the ratio is a claim
    /// somebody will read off a slide.
    #[test]
    fn the_ratio_truncates_downward_and_is_null_without_data() {
        let nothing = Counts::default();
        assert_eq!(nothing.autonomy_pct(), None, "no data is not 0%");

        // 2 of 3: 66.6…% reads as 66.
        let two_thirds = Counts {
            actions_taken: 3,
            actions_unassisted: 2,
            operator_initiated: 1,
            ..Counts::default()
        };
        assert_eq!(two_thirds.autonomy_pct(), Some(66));
        assert_eq!(two_thirds.interventions(), 1);

        // A rejection is in the denominator even though it produced no action.
        let rejected = Counts {
            actions_taken: 1,
            actions_unassisted: 1,
            human_rejected: 1,
            ..Counts::default()
        };
        assert_eq!(rejected.decisions(), 2);
        assert_eq!(rejected.autonomy_pct(), Some(50));

        // Configuration moves neither term, however much of it there is.
        let configured = Counts {
            configuration_changes: 1_000,
            ..rejected
        };
        assert_eq!(configured.decisions(), 2);
        assert_eq!(configured.autonomy_pct(), Some(50));

        // A `system` actor is in the denominator and in no numerator: a cadence
        // tick is not a human intervening, and it is not the agent choosing.
        let scheduled = Counts {
            actions_taken: 2,
            actions_unassisted: 1,
            system_initiated: 1,
            ..Counts::default()
        };
        assert_eq!(scheduled.interventions(), 0);
        assert_eq!(scheduled.autonomy_pct(), Some(50));
    }
}
