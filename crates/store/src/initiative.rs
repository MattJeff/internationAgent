//! The schedule an employee acts on its own by, and the claim that takes a turn
//! up.
//!
//! ```text
//! operator tx:  set(cadence)                    <- RLS, one tenant
//! poller tx:    claim_due(BATCH, now) ; COMMIT  <- cross-tenant, SKIP LOCKED
//!    the turn:  ...the employee does its work...
//! poller tx:    record_outcome ; COMMIT         <- bookkeeping only
//! ```
//!
//! # The claim is the whole module
//!
//! [`claim_due`] is one statement that takes the work *and reschedules it*, the
//! way [`crate::outbox::claim_except`] takes an event and pushes its
//! `available_at` out. Three properties come from that, and none of them
//! survives splitting it into a SELECT and an UPDATE:
//!
//! * **`FOR UPDATE OF … SKIP LOCKED`** — two pollers take disjoint employees
//!   instead of blocking on each other, so a second replica adds throughput
//!   rather than contention. `OF i` and not a bare `FOR UPDATE`: the statement
//!   joins `employees`, and locking *those* rows would make a poller tick block
//!   an operator suspending somebody.
//!
//! * **`next_at` moves at claim time.** [`Cadence::advance`]'s doc comment is
//!   the argument and it is not repeated here; the short version is that a
//!   schedule which only moved on success would leave a crashed turn permanently
//!   due, and the loop would pick it up again at once, forever. Advancing here
//!   makes a crash cost one missed slot — the same thing every other missed slot
//!   costs. Nothing downstream has to remember to reschedule, because there is
//!   nothing downstream that could.
//!
//! * **Lifecycle is read from `employees`, never from this table.** A released
//!   or terminated employee whose deadline passed must not be claimable, and a
//!   copy of the lifecycle in this row is a copy that can be stale. So the claim
//!   joins and filters on [`Lifecycle::Active`], which is
//!   [`agentos_domain::initiative::initiative`]'s first question transliterated
//!   into SQL — checked first and separately from the clock, for the reason that
//!   function gives.
//!
//! # Cross-tenant, like the outbox
//!
//! [`claim_due`] takes a `&mut PgConnection` from
//! [`admin_tx_bypassing_rls`](crate::db::Db::admin_tx_bypassing_rls) rather than
//! a [`TenantTx`], because a poller that could only see one tenant is not a
//! poller. That is the same exception the outbox takes and it is arranged the
//! same way: RLS is on and forced on the table, the policy binds every
//! connection the API serves a request on, and the one caller that bypasses it
//! is a loop with no request behind it. Everything else here takes a
//! [`TenantTx`].
//!
//! # Jitter
//!
//! Ten employees created by one script share a creation timestamp, so without
//! jitter they share every deadline after it and hit the model provider in a
//! block forever. The domain's answer is that [`Cadence::advance`] takes the
//! offset as an argument and the caller draws it — so this module is the caller,
//! and it draws in SQL with `random()`, exactly as the outbox draws its backoff
//! jitter.
//!
//! The formula itself is `employee_initiative_next_at(from, interval_secs)` in
//! `0017_initiative.sql` rather than a string in this file. Two callers need it —
//! the upsert names the interval as a bind parameter, the claim names it as a
//! column — and the two ways of having one formula in two statements are a copy
//! that drifts or an interpolated query that sqlx rejects as dynamic SQL. A
//! function in the schema is neither.

use std::time::Duration;

use agentos_domain::employee::Lifecycle;
use agentos_domain::ids::{EmployeeId, TenantId};
use agentos_domain::initiative::{Cadence, Initiative, initiative};
use chrono::{DateTime, Utc};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};
use crate::employee::{corrupt, parse_lifecycle};

/// How far past the interval a reschedule may land, as a fraction of it.
///
/// The Rust-side copy of the `0.1` in `employee_initiative_next_at`. It exists
/// so the bound can be *asserted*: `random()` means the value a reschedule
/// produces cannot be stated, only bracketed, and the bracket is
/// `Cadence::advance(now, ZERO)` to `Cadence::advance(now, interval * JITTER)`.
/// A test holds the SQL to it.
pub const JITTER: f64 = 0.1;

/// One employee's schedule, as an operator reads it back.
///
/// Carries the employee's `lifecycle`, joined, because it is not knowable from
/// this table alone and it decides whether the schedule means anything at all —
/// see [`Schedule::initiative`]. What the employee is *for* is not here: that is
/// its charter, and `agentos_app::vertical::Charter` owns it.
#[derive(Debug, Clone)]
pub struct Schedule {
    /// Whose schedule this is.
    pub employee_id: EmployeeId,
    /// How often it wakes up.
    pub cadence: Cadence,
    /// When it may next be taken up.
    pub next_at: DateTime<Utc>,
    /// The employee's lifecycle, joined. Only [`Lifecycle::Active`] may act.
    pub lifecycle: Lifecycle,
    /// When it was last taken up, or `None` if it never has been.
    pub last_claimed_at: Option<DateTime<Utc>>,
    /// How many times it has been taken up. Counted by the claim, so a worker
    /// killed mid-turn still shows here.
    pub claims: i64,
    /// What the poller decided last time: `turn`, `clarify`, `no_objective`, …
    pub last_outcome: Option<String>,
    /// The detail behind it. Ours or the domain's words, never a third party's.
    pub last_detail: Option<String>,
}

impl Schedule {
    /// May this employee start a turn of its own right now?
    ///
    /// The domain's predicate, applied to the row. [`claim_due`] answers the same
    /// question in SQL for a whole batch; this is for showing one operator why
    /// their employee is or is not about to act.
    pub fn initiative(&self, now: DateTime<Utc>) -> Initiative {
        initiative(self.lifecycle, self.next_at, now)
    }
}

/// An employee whose turn has just been taken up, and whose next deadline has
/// already been written.
#[derive(Debug, Clone)]
pub struct Due {
    /// Whose turn it is.
    pub employee_id: EmployeeId,
    /// Which tenant it belongs to, taken from the `employees` row rather than
    /// from this table. The poller is cross-tenant, so the caller has to
    /// re-scope itself with this before touching anything else.
    pub tenant_id: TenantId,
    /// The cadence that produced the new deadline.
    pub cadence: Cadence,
    /// **The deadline this claim wrote**, not the one it consumed. Nothing will
    /// claim this employee again before it.
    pub next_at: DateTime<Utc>,
    /// How many times this employee has been claimed, including this claim.
    pub claims: i64,
}

/// Rebuild a [`Cadence`] from a column.
///
/// Through [`Cadence::every`], which is the only door — the type has no
/// `Deserialize` precisely so that a row cannot hand back a one-second cadence
/// past the constructor that exists to refuse it. The `CHECK` in
/// `0017_initiative.sql` means this should never fire; if it does, somebody
/// edited the table by hand and the loud error is the point.
fn cadence_of(interval_secs: i64) -> Result<Cadence, StoreError> {
    let secs = u64::try_from(interval_secs)
        .map_err(|_| corrupt(format!("interval_secs {interval_secs} is negative")))?;
    Cadence::every(Duration::from_secs(secs))
        .map_err(|err| corrupt(format!("interval_secs {interval_secs}: {err}")))
}

/// Set (or change) an employee's cadence, and schedule its first turn.
///
/// The tenant is taken from the `employees` row rather than from the caller, so
/// a schedule cannot be filed against somebody else's employee — and because the
/// `SELECT` half runs under RLS, an employee this transaction cannot see yields
/// [`StoreError::NotFound`] rather than a row nobody can reach.
///
/// **Changing the cadence moves the next deadline**, measured from `now`. An
/// operator who shortens a cadence from a day to an hour means "sooner", and a
/// `next_at` left where it was would keep them waiting the rest of the day to
/// find out whether it worked. It is the same rule the claim follows: the
/// deadline is a promise about the future, never a debt from the past.
pub async fn set(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    cadence: Cadence,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let written: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO employee_initiative \
             (employee_id, tenant_id, interval_secs, next_at, created_at, updated_at) \
         SELECT e.id, e.tenant_id, $3::bigint, \
                employee_initiative_next_at($1::timestamptz, $3::bigint), \
                $1::timestamptz, $1::timestamptz \
           FROM employees e \
          WHERE e.id = $2::uuid \
         ON CONFLICT (employee_id) DO UPDATE SET \
             interval_secs = excluded.interval_secs, \
             next_at       = excluded.next_at, \
             updated_at    = excluded.updated_at \
         RETURNING employee_id",
    )
    .bind(now)
    .bind(employee_id.as_uuid())
    .bind(cadence.interval().as_secs() as i64)
    .fetch_optional(&mut ***tx)
    .await?;

    // No row selected: no such employee, or it is another tenant's and RLS made
    // those indistinguishable. Deliberately.
    written.map(|_| ()).ok_or(StoreError::NotFound)
}

/// Read one employee's schedule and the lifecycle that decides whether it means
/// anything.
///
/// [`StoreError::NotFound`] when the employee has no schedule, does not exist,
/// or belongs to another tenant — RLS makes the last two indistinguishable.
pub async fn get(tx: &mut TenantTx<'_>, employee_id: EmployeeId) -> Result<Schedule, StoreError> {
    let row = sqlx::query(
        "SELECT i.employee_id, i.interval_secs, i.next_at, i.last_claimed_at, i.claims, \
                i.last_outcome, i.last_detail, e.lifecycle \
           FROM employee_initiative i \
           JOIN employees e ON e.id = i.employee_id AND e.tenant_id = i.tenant_id \
          WHERE i.employee_id = $1",
    )
    .bind(employee_id.as_uuid())
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;

    schedule_from_row(&row)
}

fn schedule_from_row(row: &PgRow) -> Result<Schedule, StoreError> {
    Ok(Schedule {
        employee_id: EmployeeId::from_uuid(row.get("employee_id")),
        cadence: cadence_of(row.get("interval_secs"))?,
        next_at: row.get("next_at"),
        lifecycle: parse_lifecycle(row.get("lifecycle"))?,
        last_claimed_at: row.get("last_claimed_at"),
        claims: row.get("claims"),
        last_outcome: row.get("last_outcome"),
        last_detail: row.get("last_detail"),
    })
}

/// Take up to `limit` employees whose deadline has arrived, across every tenant,
/// and reschedule them in the same statement.
///
/// Runs on a connection from
/// [`admin_tx_bypassing_rls`](crate::db::Db::admin_tx_bypassing_rls) — every
/// tenant's schedule is the poller's whole job and RLS would hide all of it.
/// Pass `&mut *tx`. See the module docs for why that is the same exception the
/// outbox takes rather than a new one.
///
/// Commit before running the turns. `SKIP LOCKED` only excludes another poller
/// for as long as the claiming transaction is open; what actually keeps an
/// employee to one worker is that the same `UPDATE` pushed `next_at` into the
/// future.
///
/// # `WITH … AS MATERIALIZED`, and why it is not decoration
///
/// The obvious spelling of the selection is
/// `WHERE employee_id IN (SELECT … FOR UPDATE SKIP LOCKED LIMIT $n)`, which is
/// what [`crate::outbox::claim_except`] uses and what every queue-in-Postgres
/// article shows. **It did not respect the `LIMIT` here, and only when a second
/// poller was running.**
///
/// A non-correlated `IN (SELECT …)` may be planned as a subplan that is
/// re-executed per candidate outer row. On its own that is harmless, because
/// re-running a deterministic subquery gives the same answer — which is why a
/// single-session reproduction of this returns exactly `$n` and proves nothing.
/// Under a second poller it is not deterministic: each re-execution runs
/// `ORDER BY … FOR UPDATE SKIP LOCKED LIMIT n` afresh, steps over whichever rows
/// the other poller has locked *at that moment*, and returns a different set. The
/// union of those sets is what the `UPDATE` touches. The two-poller test below
/// caught it twice, claiming 13 and then 16 employees against a limit of 10.
///
/// Note what that is not: the claims stayed **disjoint**, so `SKIP LOCKED` was
/// working exactly as advertised and every assertion about it passed. The bound
/// was the thing that broke, and the damage is a poller starting a burst of
/// model calls it was told not to start.
///
/// A CTE is evaluated exactly once, whatever else is happening on the table.
/// `MATERIALIZED` is stated rather than relied on: PostgreSQL 12 began inlining
/// CTEs referenced once, and an inlined one is a subquery again.
pub async fn claim_due(
    conn: &mut PgConnection,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<Due>, StoreError> {
    let rows = sqlx::query(
        "WITH due AS MATERIALIZED ( \
             SELECT i2.employee_id \
               FROM employee_initiative i2 \
               JOIN employees e2 ON e2.id = i2.employee_id \
                                AND e2.tenant_id = i2.tenant_id \
              WHERE e2.lifecycle = $3::text \
                AND i2.next_at <= $1::timestamptz \
              ORDER BY i2.next_at, i2.employee_id \
                FOR UPDATE OF i2 SKIP LOCKED \
              LIMIT $2::bigint) \
         UPDATE employee_initiative AS i \
            SET next_at         = \
                    employee_initiative_next_at($1::timestamptz, i.interval_secs), \
                last_claimed_at = $1::timestamptz, \
                claims          = i.claims + 1, \
                updated_at      = $1::timestamptz \
           FROM due d \
           JOIN employees e ON e.id = d.employee_id \
          WHERE i.employee_id = d.employee_id \
        RETURNING i.employee_id, e.tenant_id, i.interval_secs, i.next_at, i.claims",
    )
    .bind(now)
    .bind(limit)
    // Bound rather than written as a literal, so the spelling stays tied to
    // `Lifecycle::as_str` and a rename is a compile error somewhere rather
    // than a poller that silently claims nothing.
    .bind(Lifecycle::Active.as_str())
    .fetch_all(&mut *conn)
    .await?;

    rows.iter().map(due_from_row).collect()
}

fn due_from_row(row: &PgRow) -> Result<Due, StoreError> {
    Ok(Due {
        employee_id: EmployeeId::from_uuid(row.get("employee_id")),
        tenant_id: TenantId::from_uuid(row.get("tenant_id")),
        cadence: cadence_of(row.get("interval_secs"))?,
        next_at: row.get("next_at"),
        claims: row.get("claims"),
    })
}

/// Write down what the poller decided about one employee.
///
/// Bookkeeping only: the schedule already moved when the employee was claimed,
/// so an employee whose turn crashed before this call is rescheduled anyway.
/// What this adds is the sentence that makes a stalled employee diagnosable
/// without reading logs — which for the `clarify` outcome is the whole feature,
/// because that sentence is a question somebody has to answer.
///
/// Takes a `&mut PgConnection` because the poller holds one.
pub async fn record_outcome(
    conn: &mut PgConnection,
    employee_id: EmployeeId,
    outcome: &str,
    detail: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let updated = sqlx::query(
        "UPDATE employee_initiative \
            SET last_outcome = $2, last_detail = $3, updated_at = $4 \
          WHERE employee_id = $1",
    )
    .bind(employee_id.as_uuid())
    .bind(outcome)
    .bind(detail)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use agentos_domain::initiative::{MAX_INTERVAL, MIN_INTERVAL};
    use chrono::TimeDelta;
    use sqlx::{Postgres, Transaction};
    use tokio::sync::{Barrier, Mutex};

    use super::*;
    use crate::db::Db;

    /// [`claim_due`] is cross-tenant by design — that is the poller's whole job
    /// — so a test that claims sees rows written by any other test running at
    /// the same time, whatever tenant they belong to. cargo runs tests in
    /// parallel, so **every** test in this module takes this first: not only the
    /// ones that claim, but the ones that merely write a schedule, because those
    /// rows are what a concurrent claim would pick up.
    static INITIATIVE_LOCK: Mutex<()> = Mutex::const_new(());

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; initiative tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    const T0: i64 = 1_700_000_000;
    const HOUR: u64 = 3_600;

    fn hourly() -> Cadence {
        Cadence::every(Duration::from_secs(HOUR)).expect("cadence")
    }

    async fn seed_tenant(db: &Db, label: &str) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            // Prefixed so `clear_schedules` names this module's rows rather
            // than the table. A bare label is not unique across modules.
            .bind(format!("{TENANT_SLUG}{label}-{}", tenant.as_uuid()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit tenant");
        tenant
    }

    /// Cascades to employees and their schedules.
    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    /// Anything a previously crashed run left behind, so the cross-tenant claims
    /// below see only what this test wrote. Safe: this is a test database.
    /// The slug every tenant this module creates carries, so
    /// [`clear_schedules`] names its own rows rather than the table.
    const TENANT_SLUG: &str = "store-initiative-";

    async fn clear_schedules(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        // Only this module's tenants, named through the slug its own fixtures
        // mint. See `crates/app/tests/scoped_deletes.rs`.
        sqlx::query(
            "DELETE FROM employee_initiative WHERE tenant_id IN \
             (SELECT id FROM tenants WHERE slug LIKE 'store-initiative-%')",
        )
        .execute(&mut *tx)
        .await
        .expect("clear schedules");
        tx.commit().await.expect("commit clear");
    }

    /// An employee row, without the eleven resource rows the aggregate would
    /// have: nothing here reads them.
    async fn seed_employee(
        db: &Db,
        tenant: TenantId,
        slug: &str,
        lifecycle: Lifecycle,
    ) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, $4)",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(format!("{slug}-{}", id.as_uuid()))
        .bind(lifecycle.as_str())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit employee");
        id
    }

    /// An employee with a schedule that is already overdue.
    async fn seed_due(db: &Db, tenant: TenantId, slug: &str, lifecycle: Lifecycle) -> EmployeeId {
        let id = seed_employee(db, tenant, slug, lifecycle).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set(&mut tx, id, hourly(), at(T0 - 10 * HOUR as i64))
            .await
            .expect("set");
        tx.commit().await.expect("commit");
        id
    }

    // -- set and get -------------------------------------------------------

    #[tokio::test]
    async fn a_cadence_round_trips_and_the_first_deadline_is_one_jittered_interval_out() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        let tenant = seed_tenant(&db, "roundtrip").await;
        let id = seed_employee(&db, tenant, "lena", Lifecycle::Active).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set(&mut tx, id, hourly(), at(T0)).await.expect("set");
        let stored = get(&mut tx, id).await.expect("get");
        tx.commit().await.expect("commit");

        assert_eq!(stored.cadence, hourly());
        assert_eq!(stored.lifecycle, Lifecycle::Active);
        assert_eq!(stored.claims, 0);
        assert_eq!(stored.last_claimed_at, None);

        // The bound `RESCHEDULE_DOC` states, held to the domain's own function:
        // never earlier than the cadence, never more than one jitter later.
        assert!(
            stored.next_at >= hourly().advance(at(T0), Duration::ZERO),
            "jitter must only ever delay: {} < {}",
            stored.next_at,
            hourly().advance(at(T0), Duration::ZERO)
        );
        assert!(
            stored.next_at
                <= hourly().advance(at(T0), Duration::from_secs_f64(HOUR as f64 * JITTER)),
            "jitter must be bounded: {}",
            stored.next_at
        );

        drop_tenant(&db, tenant).await;
    }

    /// Ten employees scheduled in the same instant by one script must not share
    /// a deadline, or they hit the model provider in a block forever.
    #[tokio::test]
    async fn employees_scheduled_together_do_not_stay_in_lockstep() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        let tenant = seed_tenant(&db, "lockstep").await;

        let mut deadlines = Vec::new();
        for n in 0..10 {
            let id = seed_employee(&db, tenant, &format!("e{n}"), Lifecycle::Active).await;
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            set(&mut tx, id, hourly(), at(T0)).await.expect("set");
            deadlines.push(get(&mut tx, id).await.expect("get").next_at);
            tx.commit().await.expect("commit");
        }

        let unique: HashSet<_> = deadlines.iter().collect();
        assert_eq!(
            unique.len(),
            deadlines.len(),
            "all ten deadlines must differ: {deadlines:?}"
        );

        drop_tenant(&db, tenant).await;
    }

    /// Shortening a cadence means sooner. A `next_at` left where it was would
    /// keep the operator waiting out the old interval to find out it worked.
    #[tokio::test]
    async fn changing_the_cadence_moves_the_next_deadline() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        let tenant = seed_tenant(&db, "recadence").await;
        let id = seed_employee(&db, tenant, "raj", Lifecycle::Active).await;
        let daily = Cadence::every(Duration::from_secs(24 * HOUR)).expect("cadence");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set(&mut tx, id, daily, at(T0)).await.expect("set");
        let before = get(&mut tx, id).await.expect("get");
        set(&mut tx, id, hourly(), at(T0)).await.expect("re-set");
        let after = get(&mut tx, id).await.expect("get");
        tx.commit().await.expect("commit");

        assert_eq!(after.cadence, hourly());
        assert!(
            after.next_at < before.next_at,
            "a shorter cadence must pull the deadline in: {} !< {}",
            after.next_at,
            before.next_at
        );
        assert_eq!(after.claims, 0, "re-setting is not a claim");

        drop_tenant(&db, tenant).await;
    }

    /// The floor and the ceiling exist in two places — `Cadence::every` and the
    /// row `CHECK` — and this is what stops them drifting apart. psql is a way
    /// into the table that the constructor does not guard.
    #[tokio::test]
    async fn the_row_check_agrees_with_the_domain_floor_and_ceiling() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        let tenant = seed_tenant(&db, "bounds").await;
        let id = seed_employee(&db, tenant, "bounds", Lifecycle::Active).await;

        for (secs, legal) in [
            (MIN_INTERVAL.as_secs() as i64 - 1, false),
            (MIN_INTERVAL.as_secs() as i64, true),
            (MAX_INTERVAL.as_secs() as i64, true),
            (MAX_INTERVAL.as_secs() as i64 + 1, false),
        ] {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let written = sqlx::query(
                "INSERT INTO employee_initiative (employee_id, tenant_id, interval_secs, next_at) \
                 VALUES ($1, $2, $3, now()) \
                 ON CONFLICT (employee_id) DO UPDATE SET interval_secs = excluded.interval_secs",
            )
            .bind(id.as_uuid())
            .bind(tenant.as_uuid())
            .bind(secs)
            .execute(&mut *tx)
            .await;
            assert_eq!(
                written.is_ok(),
                legal,
                "{secs}s should {} the CHECK",
                if legal { "pass" } else { "fail" }
            );
            tx.rollback().await.expect("rollback");
        }

        drop_tenant(&db, tenant).await;
    }

    // -- the claim ---------------------------------------------------------

    /// The property the whole module exists for, and the one that has bitten
    /// this codebase twice: the clock says yes for every one of these and the
    /// lifecycle must still win.
    #[tokio::test]
    async fn only_an_active_employee_is_ever_claimed_however_overdue() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "lifecycle").await;

        let active = seed_due(&db, tenant, "active", Lifecycle::Active).await;
        let barred = [
            seed_due(&db, tenant, "draft", Lifecycle::Draft).await,
            seed_due(&db, tenant, "suspended", Lifecycle::Suspended).await,
            seed_due(&db, tenant, "terminated", Lifecycle::Terminated).await,
        ];

        // A year past every deadline. Nothing about the clock can save them.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_due(&mut tx, 100, at(T0) + TimeDelta::days(365))
            .await
            .expect("claim");
        tx.commit().await.expect("commit");

        let ids: Vec<EmployeeId> = claimed.iter().map(|d| d.employee_id).collect();
        assert_eq!(ids, vec![active], "only the active employee may be claimed");

        // And the barred rows were not merely skipped in the output — they were
        // not touched at all, so they are still due the instant they are
        // released.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        for id in barred {
            let stored = get(&mut tx, id).await.expect("get");
            assert_eq!(stored.claims, 0, "a barred employee must not be leased");
            assert!(matches!(
                stored.initiative(at(T0)),
                Initiative::Barred { .. }
            ));
        }
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// A suspended employee that is released must act on its cadence rather than
    /// owing a week of turns — the claim reschedules from `now`, never from the
    /// deadline it blew through.
    #[tokio::test]
    async fn a_week_of_missed_slots_is_missed_rather_than_owed() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "backlog").await;
        seed_due(&db, tenant, "returning", Lifecycle::Active).await;

        let late = at(T0) + TimeDelta::days(7);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_due(&mut tx, 100, late).await.expect("claim");
        // A second poller at the same instant: the backlog is not 168 turns.
        let again = claim_due(&mut tx, 100, late).await.expect("claim again");
        tx.commit().await.expect("commit");

        assert_eq!(claimed.len(), 1);
        assert!(
            again.is_empty(),
            "a week overdue must not owe a week of turns"
        );
        assert!(
            claimed[0].next_at > late,
            "the new deadline is measured from when it was taken up"
        );
        assert!(claimed[0].next_at <= hourly().advance(late, Duration::from_secs(HOUR / 10)));

        drop_tenant(&db, tenant).await;
    }

    /// A claim is a lease that expires on its own. Nothing marks a turn
    /// finished, so a worker that dies mid-turn costs exactly one slot — which
    /// is what every other missed slot costs.
    #[tokio::test]
    async fn a_crashed_turn_costs_one_slot_rather_than_spinning() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "crash").await;
        let id = seed_due(&db, tenant, "unlucky", Lifecycle::Active).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_due(&mut tx, 10, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit");
        assert_eq!(claimed.len(), 1);
        let next_at = claimed[0].next_at;

        // The turn now panics. Nothing is recorded, on purpose: this is the
        // crash. The employee must not be claimable again at this instant, nor
        // one second before its new deadline...
        for now in [at(T0), next_at - TimeDelta::seconds(1)] {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let spun = claim_due(&mut tx, 10, now).await.expect("claim");
            tx.rollback().await.expect("rollback");
            assert!(
                spun.is_empty(),
                "a crashed turn must not be re-claimed at {now}"
            );
        }

        // ...and must be claimable exactly once when it arrives. One slot lost,
        // not a spin and not a backlog.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let recovered = claim_due(&mut tx, 10, next_at).await.expect("claim");
        tx.commit().await.expect("commit");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].employee_id, id);
        assert_eq!(
            recovered[0].claims, 2,
            "the claim counts, whatever the turn did"
        );

        drop_tenant(&db, tenant).await;
    }

    /// The batch size is a promise about how many model calls one tick may
    /// start, so `limit` has to mean `limit`.
    ///
    /// The cheap half of a regression test with a scar — see [`claim_due`] for
    /// the bug. **This test would not have caught it**, and that is worth knowing
    /// rather than pretending otherwise: one poller re-executing a deterministic
    /// subquery gets the same answer every time, so the old shape passes this.
    /// What broke the bound was a *second* poller moving the locks between
    /// re-executions, and the test that caught it is
    /// [`two_concurrent_pollers_never_claim_the_same_employee`].
    ///
    /// This one stays because it states the contract on its own terms — `limit`
    /// means `limit`, and the batch size is a promise about how many model calls
    /// one tick may start.
    #[tokio::test]
    async fn a_claim_takes_exactly_the_batch_it_was_asked_for() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "batch").await;

        for n in 0..20 {
            seed_due(&db, tenant, &format!("many{n}"), Lifecycle::Active).await;
        }

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let first = claim_due(&mut tx, 5, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit");
        assert_eq!(first.len(), 5, "a claim of 5 must take 5");

        // The other fifteen are untouched and still due — not skipped, not
        // leased, not rescheduled.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let rest = claim_due(&mut tx, 100, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit");
        assert_eq!(rest.len(), 15);
        assert!(rest.iter().all(|d| d.claims == 1), "each claimed once");

        drop_tenant(&db, tenant).await;
    }

    /// Two pollers, genuinely in parallel on two runtime threads, with the
    /// claiming transactions held open at the same time — the only arrangement
    /// in which `SKIP LOCKED` can be observed to do anything. Serialise the two
    /// transactions and this test passes with the clause deleted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_pollers_never_claim_the_same_employee() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "concurrent").await;

        const EMPLOYEES: usize = 20;
        for n in 0..EMPLOYEES {
            seed_due(&db, tenant, &format!("worker{n}"), Lifecycle::Active).await;
        }

        // Half each. A limit of EMPLOYEES would let whichever poller wins the
        // race take the lot — correct behaviour, but it proves nothing about
        // SKIP LOCKED.
        const BATCH: i64 = (EMPLOYEES / 2) as i64;
        let ready = Arc::new(Barrier::new(2));
        let claimed = Arc::new(Barrier::new(2));

        let poller = |db: Db, ready: Arc<Barrier>, claimed: Arc<Barrier>| async move {
            let mut tx: Transaction<'_, Postgres> =
                db.admin_tx_bypassing_rls().await.expect("admin tx");
            ready.wait().await;
            let got = claim_due(&mut tx, BATCH, at(T0)).await.expect("claim");
            // Hold the locks until the other poller has claimed too.
            claimed.wait().await;
            tx.commit().await.expect("commit");
            got
        };

        let a = tokio::spawn(poller(db.clone(), ready.clone(), claimed.clone()));
        let b = tokio::spawn(poller(db.clone(), ready, claimed));
        let (a, b) = (a.await.expect("poller a"), b.await.expect("poller b"));

        let ids_a: HashSet<Uuid> = a.iter().map(|d| d.employee_id.as_uuid()).collect();
        let ids_b: HashSet<Uuid> = b.iter().map(|d| d.employee_id.as_uuid()).collect();

        assert!(
            ids_a.is_disjoint(&ids_b),
            "the same employee was claimed twice: {:?}",
            &ids_a & &ids_b
        );
        // Both filled their batch, so the second poller was not blocked behind
        // the first one's locks — it stepped over them onto other rows.
        // Exactly the batch, not merely at most it. This is the assertion that
        // caught the `IN (SELECT … LIMIT)` subplan being re-executed under a
        // concurrent poller — it came back with 13, and then 16, against a limit
        // of 10, while staying perfectly disjoint. See `claim_due`.
        assert_eq!(ids_a.len(), BATCH as usize);
        assert_eq!(ids_b.len(), BATCH as usize);
        assert_eq!(ids_a.len() + ids_b.len(), EMPLOYEES);

        // A third poller at the same instant gets nothing: every deadline moved.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let leftovers = claim_due(&mut tx, 100, at(T0)).await.expect("claim");
        tx.rollback().await.expect("rollback");
        assert!(
            leftovers.is_empty(),
            "a claimed employee must not be re-claimable"
        );

        drop_tenant(&db, tenant).await;
    }

    /// The poller is cross-tenant, and that is the feature. It must see both
    /// tenants' due employees in one pass, each carrying its own tenant id.
    #[tokio::test]
    async fn one_poller_claims_across_every_tenant() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let a = seed_tenant(&db, "cross-a").await;
        let b = seed_tenant(&db, "cross-b").await;
        let in_a = seed_due(&db, a, "alpha", Lifecycle::Active).await;
        let in_b = seed_due(&db, b, "beta", Lifecycle::Active).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_due(&mut tx, 100, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit");

        let mut seen: Vec<(EmployeeId, TenantId)> = claimed
            .iter()
            .map(|d| (d.employee_id, d.tenant_id))
            .collect();
        seen.sort_by_key(|(id, _)| id.as_uuid());
        let mut want = vec![(in_a, a), (in_b, b)];
        want.sort_by_key(|(id, _)| id.as_uuid());
        assert_eq!(seen, want);

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    // -- bookkeeping -------------------------------------------------------

    #[tokio::test]
    async fn the_outcome_is_readable_by_the_operator_who_has_to_act_on_it() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "outcome").await;
        let id = seed_due(&db, tenant, "asking", Lifecycle::Active).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        claim_due(&mut tx, 10, at(T0)).await.expect("claim");
        record_outcome(&mut tx, id, "clarify", Some("how many units?"), at(T0))
            .await
            .expect("record");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let stored = get(&mut tx, id).await.expect("get");
        tx.rollback().await.expect("rollback");

        assert_eq!(stored.last_outcome.as_deref(), Some("clarify"));
        assert_eq!(stored.last_detail.as_deref(), Some("how many units?"));
        assert_eq!(stored.claims, 1);
        assert_eq!(stored.last_claimed_at, Some(at(T0)));

        drop_tenant(&db, tenant).await;
    }

    // -- isolation ---------------------------------------------------------

    /// The poller bypasses RLS; nothing else does. One tenant must not read
    /// another's schedule, and must not be able to file a row wearing another's
    /// id — a schedule against somebody else's employee would be a way to make
    /// their employee act.
    #[tokio::test]
    async fn rls_is_on_forced_and_binds_both_directions() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        let a = seed_tenant(&db, "iso-a").await;
        let b = seed_tenant(&db, "iso-b").await;
        let theirs = seed_due(&db, b, "theirs", Lifecycle::Active).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = 'employee_initiative'::regclass",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("pg_class");
        tx.rollback().await.expect("rollback");
        assert!(enabled, "RLS must be enabled on employee_initiative");
        assert!(
            forced,
            "RLS must be forced, or the table owner walks past it"
        );

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        // Invisible, asked for by primary key with no tenant filter in the SQL.
        assert!(matches!(
            get(&mut tx, theirs).await,
            Err(StoreError::NotFound)
        ));
        // And unwritable: `with check` refuses a row wearing B's id...
        let wearing_b = sqlx::query(
            "INSERT INTO employee_initiative (employee_id, tenant_id, interval_secs, next_at) \
             VALUES ($1, $2, 3600, now())",
        )
        .bind(theirs.as_uuid())
        .bind(b.as_uuid())
        .execute(&mut **tx)
        .await;
        assert!(
            wearing_b.is_err(),
            "one tenant must not insert a row wearing another's id"
        );
        tx.rollback().await.expect("rollback");

        // ...and `set` cannot be talked into it either: the employee is not
        // visible, so there is nothing to file a schedule against.
        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        assert!(matches!(
            set(&mut tx, theirs, hourly(), at(T0)).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }
}
