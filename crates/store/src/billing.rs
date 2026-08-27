//! **What we are allowed to charge for, reconstructed from the trail.**
//!
//! The commercial decision this module implements is one sentence, and it is
//! narrow on purpose: *the only thing people pay for is access to the
//! infrastructure, by the number of employees and the services integrated.*
//! Everything else in the product is either free or somebody else's bill.
//!
//! # This module must never read a token, and cannot
//!
//! [`crate::model_usage`] counts input, output and cache tokens per employee per
//! day, and it is easy to mistake for the billing basis. It is not ours — it is
//! **the customer's**. A tenant connects its own Anthropic key through
//! `POST /v1/model`; the tokens its employees burn arrive on the customer's own
//! Anthropic invoice, not on ours. That is what makes a $2–5k seat price
//! defensible at all, and a meter here that summed a token would quietly turn a
//! flat infrastructure fee into a resale margin on somebody else's contract.
//!
//! So the guarantee is structural rather than a rule somebody remembers:
//! [`BILLED_DAYS_SQL`] names `audit_log` and `employees` and nothing else. There
//! is no join to `model_usage_daily`, no `tokens` column in [`BilledDay`], and
//! nothing in this file can reach one.
//!
//! # Derived, never accumulated
//!
//! [`crate::capability`] argued this shape first and the argument transfers
//! whole: a request is a `GROUP BY` over the audit trail rather than a row
//! somebody writes on the path of every denial. A bill is the same kind of
//! object. The alternatives were both worse.
//!
//! * **A daily snapshot job.** A row per tenant per day saying "five employees,
//!   two connectors". Then the bill is only as good as the job's uptime, a day
//!   the process was down is a day nobody can reconstruct, and the direction of
//!   the error is a missing charge nobody notices — or, if somebody backfills by
//!   hand, a charge with no evidence under it.
//! * **A counter on the hire and fire paths.** Two writes to keep in step with
//!   every future path that moves a lifecycle, and a crash between the lifecycle
//!   write and the counter write leaves a bill that disagrees with the product.
//!
//! Deriving needs neither. The trail is append-only at the database level
//! (`0001_core.sql` revokes UPDATE and DELETE *and* installs a trigger), it is
//! written in the same transaction as the thing it describes, and it already
//! carries every mark this query needs. So the bill cannot drift from what
//! happened, and re-running it a year later gives the same answer.
//!
//! # What counts as an employee, case by case
//!
//! **A billable day is a day on which the seat could act.** The Policy Gate
//! refuses every action for a principal that is not [`Lifecycle::Active`], so
//! `active` is not a label we chose for billing — it is the state that
//! distinguishes a seat that works from a seat that does not, enforced in code
//! the customer can observe from outside.
//!
//! | case | billed | why the customer cannot argue |
//! |---|---|---|
//! | still `draft`, provisioning | no | the gate refuses it; nothing it can do has happened yet, and a phone number that never arrives would otherwise bill forever |
//! | `active` | yes | it can work, and does |
//! | `suspended` | no | the customer asked us to stop it and the gate obeys. Charging for a seat we have been told to switch off is the charge that ends a renewal |
//! | hired on the 28th | 3 days, not a month | see the granularity section |
//! | terminated on the 3rd | 3 days | the 3rd is billed: it worked that morning |
//! | suspended the 5th, resumed the 9th | the 5th and the 9th, not the 6th–8th | it acted on both boundary days |
//! | terminated, then the row lingers | nothing after the termination day | `employees` has no DELETE, so a dead seat sits in the table forever; billing off the trail rather than off the table is what stops it accruing |
//!
//! # What counts as an integrated service, case by case
//!
//! A service is one **MCP binding**: a row in `mcp_servers`, keyed by the handle
//! the customer typed. It is billed for the days it was part of the tenant's
//! configuration.
//!
//! | case | billed | why |
//! |---|---|---|
//! | declared, then deleted on the 12th | through the 12th | the same boundary rule as a termination |
//! | deleted and re-declared later | both stretches, not the gap | two spans, and a day inside neither is not billed |
//! | declared and never successfully dialled | yes, **and this is the weak one** | see below |
//! | an OAuth consent flow started and abandoned | no | `mcp.oauth.started` writes a flow row, never a binding, so it never enters the meter |
//! | a tool declared on an existing binding | no line of its own | the tool is not the service; the binding is |
//!
//! **The connector that never worked.** A binding that 401s all month is billed
//! here, and that is a decision rather than an oversight. It is also the one
//! definition on this page a customer could push back on, so it is worth being
//! exact about why the alternative is unavailable: *nothing in the trail records
//! whether a binding answered.* The binder loop dials on a schedule and logs;
//! only the operator-driven `mcp.server.connected` and `mcp.oauth.connected`
//! paths write a row, and both of them prove the endpoint answered **once, on
//! the day it was wired**. Billing on "it worked" would therefore mean either
//! inventing a health signal, or charging on a single verification that may be
//! six months stale — a number nobody measured, which this repository refuses
//! elsewhere for the same reason.
//!
//! What the customer has instead is a remedy that is entirely in their hands and
//! visible from outside: `DELETE /v1/mcp/servers/{handle}` stops the meter the
//! same day. A charge you can end yourself in one call, for a thing you asked
//! for and left in place, is defensible. A charge derived from a liveness number
//! we made up is not.
//!
//! # Granularity: the day, prorated, and what that costs us
//!
//! Three shapes were available and each loses something:
//!
//! * **The maximum over the month.** A customer who tried a sixth employee for
//!   one afternoon pays a full month for it. That is the version that wins an
//!   argument on a spreadsheet and loses one on a phone call.
//! * **The average.** Rewards hiring on the 30th, punishes hiring on the 1st,
//!   and — the disqualifying part — "4.3 employees" is not a thing the customer
//!   ever observed. A figure nobody can check against their own memory is a
//!   figure they will not pay twice.
//! * **Prorated by UTC day.** Taken. Every line of the bill is a date and a
//!   count, and the customer can point at any one of them and say yes or no.
//!
//! **What we accept losing.** A seat active for ten minutes bills a whole day.
//! Going finer would mean a bill made of fractions of a day, which nobody can
//! verify by remembering, and it would invite cycling seats on and off inside a
//! day to shave an hour off. A whole day is the smallest unit that stays
//! checkable, and it is the unit `model_usage_daily`, `spend_buckets` and the
//! turn budget already use — an employee must not have two "todays".
//!
//! The boundary rule is **overlap, not membership**: a day is billed if the
//! billable span touched it at all, so the day of activation and the day of
//! termination are both on the bill. That is chosen so one property holds — *a
//! day on which the seat did anything is a day that appears on the bill* — which
//! is the property a customer actually cross-checks. The end-of-day reading
//! breaks it: a seat that answered mail all morning and was terminated at noon
//! would vanish from the bill for a day it demonstrably worked.
//!
//! # What this cannot see, and will not guess
//!
//! **A seat activated before the trail recorded activations.** The `draft →
//! active` move is made by the outbox handler in `apps/server/src/main.rs`, not
//! by an operator, and until that handler wrote an audit row the transition left
//! no mark at all. Employees activated before that build show `employee_created`
//! and then silence, so they have no billable span and bill **zero**.
//!
//! There is no honest repair inside this query. `employees.updated_at` moves on
//! every save, and `employee_resources.updated_at` for the last blocking step is
//! a second derivation from a different table that would disagree with the trail
//! the first time a resource changed — exactly the drift the audit trail exists
//! to prevent. So the answer is a floor, the error is in the customer's favour,
//! and closing it is a human decision about backfilling a trail (the append-only
//! trigger permits INSERT), not a `coalesce` this module gets to make on its own.
//!
//! [`Lifecycle::Active`]: agentos_domain::employee::Lifecycle::Active

use chrono::NaiveDate;
use serde::Serialize;

use crate::db::{StoreError, TenantTx};

/// The meter a [`BilledDay`] belongs to: one seat, for one day.
///
/// Bound into [`BILLED_DAYS_SQL`] rather than written as a SQL literal, so a
/// rename here is a compile-time move and not a query that silently stops
/// matching the constant the caller folds on.
pub const EMPLOYEE: &str = "employee";

/// The meter a [`BilledDay`] belongs to: one MCP binding, for one day.
pub const CONNECTOR: &str = "connector";

/// One thing that was billable on one UTC day.
///
/// **`subject` is a [`Slug`](agentos_domain::ids::Slug) in both meters** — an
/// employee's is `employees.slug`, a connector's is the handle
/// `routes::mcp::handle` parsed — and that is load-bearing rather than
/// convenient. [`crate::capability`] makes the argument in full: a slug's
/// charset is `[a-z0-9-]`, so it is structurally incapable of carrying a
/// sentence, while `display_name` and a connector's URL are free text that a
/// third party can influence. An invoice is a document a human reads and
/// forwards; there is nowhere on this line for somebody else's prose to land.
///
/// There is deliberately no `employee_id` either. The slug is unique per tenant
/// **forever** (`0001_core.sql`: "an employee's slug is its address-local-part"),
/// so it identifies exactly one seat for all time, and it is the string the
/// customer typed and therefore the one they can check the bill against. A UUID
/// beside it would be a second identifier on a document whose whole job is to be
/// verifiable by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct BilledDay {
    /// UTC. The same day boundary as `model_usage_daily` and the turn budget.
    pub day: NaiveDate,
    /// [`EMPLOYEE`] or [`CONNECTOR`], and nothing else — both are bound in.
    pub meter: String,
    /// The seat's slug, or the binding's handle.
    pub subject: String,
}

/// Every billable subject-day in `[from, to]`, both inclusive.
///
/// # The query, clause by clause
///
/// `marks` is the state machine's edges, read out of the trail. The employee arm
/// turns `employee_created` into `draft` and reads every later state out of
/// `payload ->> 'to'`, which is the column `routes::employees::set_lifecycle`
/// and the activation handler both write. The connector arm treats the three
/// events that create or replace an `mcp_servers` row as "present" and
/// `mcp.server.deleted` as "absent"; `mcp.oauth.started` is excluded because it
/// writes a flow row and no binding, and `mcp.tool.declared` because a tool is
/// not a service.
///
/// **A mark this build cannot read is not billed.** An unrecognised
/// `payload ->> 'to'` compares `NULL = 'active'`, which is `NULL`, which the
/// `WHERE spans.billable` drops. A future lifecycle state therefore bills
/// nothing until somebody teaches this query about it — the direction that
/// under-charges rather than the one that invents.
///
/// `spans` closes each mark with the next one for the same subject, via `lead()`
/// partitioned by `(meter, subject)`. A `NULL` close is a span still open, which
/// the window's own end bounds. The tie-break is `(occurred_at, id)`, the same
/// pair [`crate::audit::trail_for_employee`] orders on, so two marks inside one
/// millisecond order the same way in both readers.
///
/// The `generate_series` expands a span into the days it touched, clipped to the
/// window at both ends, and an empty series is a span that fell outside it — so
/// the clipping *is* the filter and there is no second `WHERE` to keep in step
/// with it. `SELECT DISTINCT` collapses the case the boundary rule creates on
/// purpose: suspended and resumed on the same day is two spans touching one day,
/// and one seat is one seat.
///
/// # No tenant predicate, deliberately
///
/// `audit_log` and `employees` both carry `tenant_isolation`, forced, so the
/// tenant comes from the transaction. Another tenant's bill is not merely
/// unlisted here — there is no clause anybody could get wrong, and the rows do
/// not exist to be summed.
///
/// ponytail: no index of its own. `audit_log_tenant_time_idx` already narrows to
/// one tenant, the two `action_kind`s the employee arm wants are one row per
/// hire and one per lifecycle move, and this endpoint is read about as often as
/// an invoice is cut. If a large trail ever makes it slow, the upgrade is the
/// partial index `0049_capability_requests.sql` added for its own aggregate,
/// over `(tenant_id, action_kind, occurred_at)` — not a snapshot table.
const BILLED_DAYS_SQL: &str = "\
WITH marks AS ( \
    SELECT $3::text AS meter, \
           e.slug   AS subject, \
           a.occurred_at, \
           a.id, \
           (CASE a.action_kind \
              WHEN 'employee_created' THEN 'draft' \
              ELSE a.payload ->> 'to' \
            END) = 'active' AS billable \
      FROM audit_log a \
      JOIN employees e ON e.id = a.employee_id \
     WHERE a.action_kind IN ('employee_created', 'employee_lifecycle_changed') \
    UNION ALL \
    SELECT $4::text, \
           a.payload ->> 'server', \
           a.occurred_at, \
           a.id, \
           (a.payload ->> 'event') <> 'mcp.server.deleted' \
      FROM audit_log a \
     WHERE a.action_kind = 'policy_changed' \
       AND a.payload ->> 'event' IN ('mcp.server.declared', 'mcp.server.connected', \
                                     'mcp.oauth.connected', 'mcp.server.deleted') \
       AND a.payload ->> 'server' IS NOT NULL \
), spans AS ( \
    SELECT meter, subject, billable, \
           (occurred_at AT TIME ZONE 'UTC')::date AS opened, \
           (lead(occurred_at) OVER (PARTITION BY meter, subject \
                                        ORDER BY occurred_at, id) \
              AT TIME ZONE 'UTC')::date AS closed \
      FROM marks \
) \
SELECT DISTINCT billed::date AS day, s.meter, s.subject \
  FROM spans s \
  CROSS JOIN LATERAL generate_series( \
         greatest(s.opened, $1::date)::timestamp, \
         least(coalesce(s.closed, $2::date), $2::date)::timestamp, \
         interval '1 day') AS billed \
 WHERE s.billable \
 ORDER BY day, s.meter, s.subject";

/// Every billable subject-day this tenant had in `[from, to]`, inclusive.
///
/// Rows, not totals. The caller folds them into whatever rollups it shows, so
/// the per-day counts, the per-subject counts and the grand total are all the
/// same rows counted three ways and cannot disagree with each other — the
/// property that makes the bill checkable line by line. A second SQL aggregate
/// for the total would be a second place for the definition of "billable" to
/// live.
pub async fn billed_days(
    tx: &mut TenantTx<'_>,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<BilledDay>, StoreError> {
    let rows = sqlx::query_as(BILLED_DAYS_SQL)
        .bind(from)
        .bind(to)
        .bind(EMPLOYEE)
        .bind(CONNECTOR)
        .fetch_all(&mut ***tx)
        .await?;

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::action::ActionKind;
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::policy::{Decision, DenyReason};
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::*;
    use crate::audit::{self, AuditActor, AuditEvent, AuditKind};
    use crate::db::Db;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the billing basis is a SQL question");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-08-{day:02}T{hour:02}:00:00Z"))
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    fn day(day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, day).expect("valid date")
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'billing-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Hire a seat the way `routes::employees::create` does: the row and the
    /// `employee_created` mark, in one transaction.
    async fn hire(db: &Db, tenant: TenantId, slug: &str, when: DateTime<Utc>) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'draft')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        audit::append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(id),
                payload: json!({ "slug": slug }),
                ..AuditEvent::new(AuditActor::System, AuditKind::EmployeeCreated, when)
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");
        id
    }

    /// Move a seat, the way `set_lifecycle` and the activation handler both do.
    async fn moved(
        db: &Db,
        tenant: TenantId,
        id: EmployeeId,
        from: &str,
        to: &str,
        when: DateTime<Utc>,
    ) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query("UPDATE employees SET lifecycle = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(to)
            .execute(&mut **tx)
            .await
            .expect("update lifecycle");
        audit::append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(id),
                payload: json!({ "from": from, "to": to }),
                ..AuditEvent::new(
                    AuditActor::System,
                    AuditKind::EmployeeLifecycleChanged,
                    when,
                )
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");
    }

    /// One MCP administrative act, exactly as `routes::mcp::record` writes it.
    async fn mcp(db: &Db, tenant: TenantId, event: &str, server: &str, when: DateTime<Utc>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        audit::append(
            &mut tx,
            &AuditEvent {
                payload: json!({ "event": event, "server": server }),
                ..AuditEvent::new(AuditActor::System, AuditKind::PolicyChanged, when)
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");
    }

    async fn bill(db: &Db, tenant: TenantId, from: NaiveDate, to: NaiveDate) -> Vec<BilledDay> {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let rows = billed_days(&mut tx, from, to).await.expect("billed_days");
        tx.rollback().await.expect("rollback");
        rows
    }

    /// The days one subject was billed, in order.
    fn days_of(rows: &[BilledDay], meter: &str, subject: &str) -> Vec<NaiveDate> {
        rows.iter()
            .filter(|r| r.meter == meter && r.subject == subject)
            .map(|r| r.day)
            .collect()
    }

    // -----------------------------------------------------------------------

    /// Every boundary case in the module docs' first table, on one trail.
    #[tokio::test]
    async fn a_seat_is_billed_for_the_days_it_could_act_and_no_others() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;

        // Never leaves draft: provisioning is stuck. Bills nothing, forever.
        hire(&db, tenant, "stuck", at(1, 9)).await;

        // Active on the 1st, still active at the end of the window.
        let lena = hire(&db, tenant, "lena", at(1, 9)).await;
        moved(&db, tenant, lena, "draft", "active", at(1, 10)).await;

        // Hired the 28th: three days of a month, not a month.
        let late = hire(&db, tenant, "late", at(28, 8)).await;
        moved(&db, tenant, late, "draft", "active", at(28, 9)).await;

        // Terminated the 3rd at 09:00 — the 3rd is billed, it worked that
        // morning; the 4th is not.
        let gone = hire(&db, tenant, "gone", at(1, 8)).await;
        moved(&db, tenant, gone, "draft", "active", at(1, 8)).await;
        moved(&db, tenant, gone, "active", "terminated", at(3, 9)).await;

        // Suspended the 5th, resumed the 9th: both boundary days, not the gap.
        let paused = hire(&db, tenant, "paused", at(1, 8)).await;
        moved(&db, tenant, paused, "draft", "active", at(1, 8)).await;
        moved(&db, tenant, paused, "active", "suspended", at(5, 14)).await;
        moved(&db, tenant, paused, "suspended", "active", at(9, 11)).await;

        let rows = bill(&db, tenant, day(1), day(30)).await;

        let stuck = days_of(&rows, EMPLOYEE, "stuck");
        assert!(
            stuck.is_empty(),
            "a seat the gate refuses every action for must bill nothing: {stuck:?}"
        );
        assert_eq!(days_of(&rows, EMPLOYEE, "lena").len(), 30);
        assert_eq!(
            days_of(&rows, EMPLOYEE, "late"),
            vec![day(28), day(29), day(30)]
        );
        assert_eq!(
            days_of(&rows, EMPLOYEE, "gone"),
            vec![day(1), day(2), day(3)],
            "the day of a termination is billed and the day after is not"
        );
        assert_eq!(
            days_of(&rows, EMPLOYEE, "paused"),
            vec![
                day(1),
                day(2),
                day(3),
                day(4),
                day(5),
                day(9),
                day(10),
                day(11),
                day(12),
                day(13),
                day(14),
                day(15),
                day(16),
                day(17),
                day(18),
                day(19),
                day(20),
                day(21),
                day(22),
                day(23),
                day(24),
                day(25),
                day(26),
                day(27),
                day(28),
                day(29),
                day(30),
            ],
            "the suspension's own day and the day it came back are billed; the gap is not"
        );

        // Suspended and resumed inside one day is one seat, not two.
        let churn = hire(&db, tenant, "churn", at(1, 8)).await;
        moved(&db, tenant, churn, "draft", "active", at(1, 8)).await;
        moved(&db, tenant, churn, "active", "suspended", at(2, 10)).await;
        moved(&db, tenant, churn, "suspended", "active", at(2, 15)).await;
        let rows = bill(&db, tenant, day(2), day(2)).await;
        assert_eq!(
            days_of(&rows, EMPLOYEE, "churn"),
            vec![day(2)],
            "one seat cycled twice in a day is one billed day: {rows:?}"
        );

        drop_tenant(&db, tenant).await;
    }

    /// A connector is billed for the days it was in the configuration, and the
    /// three shapes that must not put one there.
    #[tokio::test]
    async fn a_connector_is_billed_while_it_is_configured_and_not_before_or_after() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;

        mcp(&db, tenant, "mcp.server.declared", "github", at(1, 9)).await;
        mcp(&db, tenant, "mcp.server.deleted", "github", at(12, 16)).await;
        // Same handle, wired again a week later: two stretches, not one.
        mcp(&db, tenant, "mcp.server.connected", "github", at(20, 9)).await;

        // Consent started and abandoned: a flow row, never a binding.
        mcp(&db, tenant, "mcp.oauth.started", "slack", at(2, 9)).await;
        // A tool on a binding is not a service of its own.
        mcp(&db, tenant, "mcp.tool.declared", "linear", at(3, 9)).await;
        // Consent completed: a binding, from that day.
        mcp(&db, tenant, "mcp.oauth.connected", "notion", at(4, 22)).await;

        let rows = bill(&db, tenant, day(1), day(30)).await;

        let github = days_of(&rows, CONNECTOR, "github");
        assert_eq!(github.first(), Some(&day(1)));
        assert!(
            github.contains(&day(12)) && !github.contains(&day(13)),
            "the day of a deletion is billed and the day after is not: {github:?}"
        );
        assert!(
            !github.contains(&day(19)) && github.contains(&day(20)),
            "the gap between two bindings of one handle is not billed: {github:?}"
        );
        assert_eq!(github.len(), 12 + 11);

        assert!(
            days_of(&rows, CONNECTOR, "slack").is_empty(),
            "an abandoned consent flow is not an integrated service: {rows:?}"
        );
        assert!(
            days_of(&rows, CONNECTOR, "linear").is_empty(),
            "declaring a tool is not integrating a service: {rows:?}"
        );
        assert_eq!(days_of(&rows, CONNECTOR, "notion").len(), 27);

        drop_tenant(&db, tenant).await;
    }

    /// **The constraint the whole module is under.** The meter reads two tables
    /// and neither holds a token, so this asserts the reachable thing: a tenant
    /// that burned an enormous number of tokens and hired nobody owes nothing,
    /// and one that hired somebody and burned none owes a day.
    #[tokio::test]
    async fn tokens_move_nothing_on_this_bill() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;

        let lena = hire(&db, tenant, "lena", at(1, 9)).await;
        moved(&db, tenant, lena, "draft", "active", at(1, 10)).await;
        let before = bill(&db, tenant, day(1), day(1)).await;
        assert_eq!(before.len(), 1);

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        crate::model_usage::record(
            &mut tx,
            lena,
            day(1),
            crate::model_usage::Consumed::reported(9_000, 800_000_000, 400_000_000, 0),
        )
        .await
        .expect("record");
        tx.commit().await.expect("commit");

        assert_eq!(
            bill(&db, tenant, day(1), day(1)).await,
            before,
            "a billion tokens moved the infrastructure bill; the client's key pays for those"
        );

        drop_tenant(&db, tenant).await;
    }

    /// Rulings, denials and every other kind of trail row are not billable
    /// events. The trail this bill is derived from is dominated by them, so the
    /// query has to be narrow rather than lucky.
    #[tokio::test]
    async fn ordinary_trail_rows_are_not_billable_events() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = hire(&db, tenant, "lena", at(1, 9)).await;
        moved(&db, tenant, lena, "draft", "active", at(1, 10)).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        for hour in 0..12 {
            for kind in [
                AuditKind::Action(ActionKind::EmailSend),
                AuditKind::MessageReceived,
                AuditKind::ProviderCallAttempted,
                AuditKind::ModelConnected,
                AuditKind::CapabilityDecided,
            ] {
                audit::append(
                    &mut tx,
                    &AuditEvent {
                        employee_id: Some(lena),
                        decision: Some(Decision::Deny {
                            reason: DenyReason::ToolNotAllowed,
                        }),
                        // The shapes most likely to be mistaken for a mark: a
                        // `to` that is not a lifecycle, and an `event` that is
                        // not one of the four.
                        payload: json!({
                            "to": "active",
                            "event": "mcp.server.connected",
                            "server": "ghost",
                        }),
                        ..AuditEvent::new(AuditActor::System, kind, at(2, hour))
                    },
                )
                .await
                .expect("append");
            }
        }
        tx.commit().await.expect("commit");

        let rows = bill(&db, tenant, day(1), day(30)).await;
        let ghost = days_of(&rows, CONNECTOR, "ghost");
        assert!(
            ghost.is_empty(),
            "a `server` key on a row that is not an MCP act billed a connector: {ghost:?}"
        );
        assert_eq!(
            rows.len(),
            30,
            "only lena's thirty days should be on this bill"
        );

        drop_tenant(&db, tenant).await;
    }

    /// **The hard constraint.** One tenant never sees another's bill, and there
    /// is no predicate here to forget: the rows are invisible.
    #[tokio::test]
    async fn a_tenant_cannot_see_another_tenants_bill() {
        let Some(db) = db().await else { return };
        let mine = new_tenant(&db).await;
        let theirs = new_tenant(&db).await;

        let lena = hire(&db, theirs, "lena", at(1, 9)).await;
        moved(&db, theirs, lena, "draft", "active", at(1, 10)).await;
        mcp(&db, theirs, "mcp.server.declared", "github", at(1, 9)).await;

        assert_eq!(bill(&db, theirs, day(1), day(30)).await.len(), 60);
        let leaked = bill(&db, mine, day(1), day(30)).await;
        assert!(
            leaked.is_empty(),
            "another tenant's employees and connectors appeared on this bill: {leaked:?}"
        );

        // And my own seat with the same slug is mine alone — the subject is a
        // slug, so the two bills would be indistinguishable if the rows were
        // not.
        let ours = hire(&db, mine, "lena", at(5, 9)).await;
        moved(&db, mine, ours, "draft", "active", at(5, 10)).await;
        assert_eq!(
            days_of(&bill(&db, mine, day(1), day(30)).await, EMPLOYEE, "lena").len(),
            26
        );
        assert_eq!(
            days_of(&bill(&db, theirs, day(1), day(30)).await, EMPLOYEE, "lena").len(),
            30
        );

        drop_tenant(&db, mine).await;
        drop_tenant(&db, theirs).await;
    }

    /// A seat whose activation predates the mark bills zero rather than a
    /// guess — the gap the module docs refuse to `coalesce` away.
    #[tokio::test]
    async fn a_seat_with_no_activation_mark_bills_nothing_rather_than_a_guess() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;

        // Hired, and made active by a build that wrote no mark: the row says
        // active, the trail does not.
        let old = hire(&db, tenant, "old", at(1, 9)).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query("UPDATE employees SET lifecycle = 'active' WHERE id = $1")
            .bind(old.as_uuid())
            .execute(&mut **tx)
            .await
            .expect("activate without a mark");
        tx.commit().await.expect("commit");

        assert!(
            bill(&db, tenant, day(1), day(30)).await.is_empty(),
            "an activation nobody recorded must under-bill, never be invented"
        );

        drop_tenant(&db, tenant).await;
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }
}
