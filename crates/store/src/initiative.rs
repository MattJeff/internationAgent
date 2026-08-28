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
//! `0020_initiative.sql` rather than a string in this file. Two callers need it —
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
    /// What the poller decided about **the beat this row is on** — `turn`,
    /// `clarify`, `no_charter`, … — or `None` when that beat has not said
    /// anything.
    ///
    /// `None` with `claims == 0` is an employee that has never been taken up.
    /// `None` with `claims > 0` is a beat that rang and produced nothing: still
    /// running, or gone with the worker that took it. It is never the beat
    /// before — [`claim_due`] clears this, and its doc comment is the argument.
    pub last_outcome: Option<String>,
    /// The detail behind it, cleared with it by the same claim. Ours or the
    /// domain's words, never a third party's.
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
/// `0020_initiative.sql` means this should never fire; if it does, somebody
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
/// # The claim clears the last outcome, and that is the whole of `0072`'s
/// argument arriving at a table shaped the other way
///
/// The claim commits before the turn exists, so an outcome is necessarily
/// written by a *second* transaction — [`record_outcome`] — and a worker killed
/// between the two writes none. That crash is accepted above: it costs one
/// slot, the same as every other missed slot. What it must not cost is the
/// truth of the row.
///
/// Without this clause it did. `last_outcome` and `last_detail` kept the
/// **previous** beat's words, so a seat whose every beat died went on reading
/// `turn` — an operator asking "is this employee's cadence working" is answered
/// *yes* by a turn that is gone, which is the silent failure nobody looks at
/// precisely because the column says there is nothing to look at. And the row
/// could not be caught out: the claim writes `updated_at` too, and
/// `loops::initiative::tick` hands one `now` to the claim and to the record, so
/// `updated_at` equals `last_claimed_at` after a beat that recorded *and* after
/// a beat that died. There was no witness to compare against.
///
/// `0072` chose the sense of the silence for `appointments` and it is the same
/// one here: **NULL means "it rang and nothing came back", never "it went
/// well"**, and success is the value that has to be earned. What differs is the
/// *mechanism*, because the two tables are shaped differently and the naive
/// copy would have been wrong. An appointment is a row per beat, so 0072 gets
/// NULL by writing nothing at claim time. This is a row per **seat**, so
/// writing nothing at claim time is exactly what leaves the previous beat's
/// answer standing: NULL has to be re-established, and the only statement that
/// can do it is the one that takes the beat up.
///
/// So the inverse schema is refused here for 0072's reason and one more of its
/// own: a `last_outcome` left alone on claim is a default of "whatever went
/// well last time", which is the fatal direction — every lost beat declares
/// itself kept, and it declares it in the words of a beat that really did
/// succeed.
///
/// The alternatives were weighed and are worse:
///
/// * **A `last_outcome_at` beside it**, so a reader can see the outcome is
///   older than the claim. That keeps the previous beat's sentence, which reads
///   well — and it moves the correctness into *every reader*, where a reader
///   that forgets the comparison is the original bug back again. One clause in
///   the one statement all beats pass through is smaller than a rule every
///   caller has to remember, and it makes the wrong reading unspellable rather
///   than merely discouraged.
/// * **A `'running'` code written at claim time.** It names the in-flight beat,
///   at the price of a word written *before* anything happened, which a crash
///   then freezes forever — and of a ninth code in a vocabulary
///   `loops::initiative::Outcome::code` owns and `docs/OPERATIONS.md` prints.
///   Two silences spelled differently in two tables one function writes is
///   drift waiting to happen.
///
/// **What NULL still cannot say**, named rather than hidden: a beat in flight
/// and a beat whose worker died look identical until the clock passes. Nothing
/// can separate them from inside the row, because the process that would write
/// the difference is the one that is gone — `appointments` has the same
/// property and 0072 accepted it for the same reason. `last_claimed_at` is what
/// an operator dates it by.
///
/// ponytail: so this row is a *last*, not a history — it cannot say "seven of
/// the last ten beats died", only "the current one has not answered". The
/// upgrade is a row per beat, inserted by this claim exactly as `appointments`
/// is; the cost is 288 rows per seat per day at `MIN_INTERVAL`, its own RLS,
/// policy, grants and the first pruning job in this schema, and it buys a
/// *rate* that nothing today reads. Build it when somebody asks the rate, not
/// before.
///
/// # A stopped company's employees are not claimed at all
///
/// [`not_stopped!`](crate::not_stopped) on `tenants`, exactly as
/// [`crate::outbox::claim_of`] uses it and in the same place — on the
/// **driver**, so a stopped company never becomes a seat and its schedules are
/// never read.
///
/// A macro rather than a call to [`crate::halt::halted`], which knows both
/// stops: this is cross-tenant SQL driven by `tenants` with an injected clock,
/// and it cannot ask a per-tenant reader. That workaround has already been paid
/// for once — the halt clause landed here while the window clause landed in the
/// outbox only, and for a while a company whose month had ended still had its
/// employees claimed and their cadence spent. A predicate spelled out is a
/// predicate that can be spelled out incompletely, so it is now spelled out in
/// exactly one place and pasted here by the compiler.
///
/// **It is not the model bill, and the difference is worth writing down
/// because the obvious reading is wrong.** This clause was added on a report
/// that a halted company's turns "burn the customer's model tokens", and that
/// does not hold: `agentos_app::model_access::connected` reads the same
/// `company_halts` row and returns `NoModel::CompanyHalted`, and
/// `apps/server`'s initiative loop calls it in `assignment_for` — **before**
/// `turns::reserve` and before any credential is decrypted. A halted company's
/// turn already reached neither the budget nor the model. Measured, by taking
/// this clause back out: `turn_buckets` and `model_usage_daily` do not move.
///
/// What the missing clause really cost is the **slot**. `employee_initiative`
/// has no attempt cap and no dead letter — `claims` is bookkeeping, never
/// compared to anything, so there is no `MAX_ATTEMPTS` here to burn through,
/// which is the mechanism [`crate::outbox::claim_of`] defers for and it does
/// not apply. What this statement destroys instead is the schedule: it
/// reschedules in the same breath, so claiming a stopped company's employee
/// spends its cadence on a refusal — `next_at` jumps a whole interval out,
/// "a week of missed slots is missed rather than owed", and the release does
/// not give them back. One hour of halt on the five-minute floor is twelve
/// slots, and `last_outcome` is left saying `no_model` at an operator whose
/// model is connected perfectly well.
///
/// So it **defers** rather than refuses, which is the same property
/// [`crate::outbox::claim_of`] holds by a different road: not selecting the row
/// leaves `next_at` in the past, so the release makes every stopped employee
/// due at once and costs nothing to replay.
///
/// # `WITH … AS MATERIALIZED`, and why it is not decoration
///
/// The obvious spelling of the selection is
/// `WHERE employee_id IN (SELECT … FOR UPDATE SKIP LOCKED LIMIT $n)`, which is
/// what every queue-in-Postgres article shows. **It did not respect the `LIMIT`
/// here, and only when a second poller was running.**
///
/// This paragraph used to say [`crate::outbox::claim_except`] was still spelled
/// that way. It is not, and neither is `loops::inbound::claim_notices`: all
/// three claims in this workspace take the materialised form now, and each has a
/// two-poller test that asserts the bound rather than only the disjointness.
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
///
/// # `i3.next_at <= $1` is repeated inside `due`, and it is what keeps the
/// claims disjoint at all
///
/// The paragraph above is about the *bound*; this one is about the thing that
/// paragraph took for granted. `seated` reads `employee_initiative` **unlocked**
/// under the statement's snapshot, and `due` is the only node that locks. A row
/// that another poller claimed and committed in between is no longer locked, so
/// `SKIP LOCKED` does not skip it — and `READ COMMITTED`'s recheck
/// (`EvalPlanQual`) walks to the new version and re-runs only the quals that sit
/// *under* the `LockRows` node. With `i3.employee_id = c.employee_id` alone that
/// still passes, and the same employee is claimed twice within milliseconds of
/// one claim that just pushed `next_at` a whole interval out. That is two turns,
/// which is two model calls billed to the customer for one schedule tick.
/// Repeating the predicate here makes the recheck read `next_at` from the
/// version actually locked, and the second poller reads past to the next
/// employee instead. `crate::outbox::claim_of` carries the same repeat for the
/// same reason and was where it was measured; these two queries are one shape
/// written twice, so a fix to either is a fix owed to both.
///
/// # Round-robin, and why FIFO was the wrong queue discipline here too
///
/// This selection used to be `ORDER BY next_at, employee_id` over the whole
/// table, across every tenant. Nothing leaks that way and no lock is held — and
/// a customer's employees still stop acting because *another* customer has more
/// of them. There is no ceiling on how many employees a tenant may schedule, a
/// tenant on the five-minute floor has one due every five minutes per employee,
/// `apps/server`'s initiative loop drains four at a time and each of those may
/// be a model turn up to `TURN_DEADLINE`. So the position of a customer's
/// employee in this queue is a function of how many employees the other
/// customers have, and the symptom is that the company quietly does not act.
///
/// [`crate::outbox::claim_of`] found and fixed exactly this in the queue every
/// *inbound* effect passes through; this is the queue every effect an employee
/// starts **by itself** passes through, and the shape of the fix is the shape of
/// that one, deliberately: `tenants` drives the selection, one `LATERAL` per
/// tenant takes that tenant's earliest due employees, `row_number()` numbers the
/// seats within a tenant, and the outer order is seat-first. A tenant with
/// nobody due contributes nothing and costs one index probe. A tenant alone on
/// the deployment still fills the whole batch — round-robin is not equal shares
/// of a queue nobody else is using.
///
/// `0052_initiative_fair_claim` is the index the lateral reads, and it argues
/// why it also drops the one this ordering used to need.
///
/// # `shortlist`, and why the lock is not taken in the lateral
///
/// The same two spellings [`crate::outbox::claim_of`] measured, with the same
/// answer, and its doc comment carries the `EXPLAIN` numbers. In short: locking
/// **inside** the lateral needs no shortlist, but takes a row lock on
/// `tenants × limit` candidates to claim `limit` of them, which is a write
/// amplification on the hottest statement here. Locking **once over a
/// shortlist** takes exactly `limit` locks — but only if the candidates are cut
/// down first, or the planner joins every seat back to `employee_initiative` and
/// picks a hash join over a sequential scan of it, which is the one plan this
/// change must not produce. Measured here, `due` is a nested loop on the primary
/// key over four candidates.
///
/// # The `LIMIT` inside the lateral does not push down, and that is survivable
///
/// Measured, not assumed: `EXPLAIN (ANALYZE)` against 10 000 due schedules
/// across 52 tenants shows the lateral hash-joining `employees` to that tenant's
/// due rows and *then* taking the top 16 — 192 rows read per tenant, not 16. The
/// lifecycle predicate lives on `employees`, so PostgreSQL has to satisfy it
/// before it may stop, and rewriting the join as an `EXISTS` semi-join changes
/// nothing: the planner turns it straight back into the same hash semi-join.
///
/// [`crate::outbox::claim_of`] gets the pushdown because its lateral touches one
/// table. It also *needs* it, and this does not, because the two tables are not
/// the same kind of thing. `outbox_events` is a queue with no ceiling on what
/// one tenant may put in it; `employee_initiative` holds **exactly one row per
/// employee, permanently**, so the scan is bounded by the deployment's headcount
/// rather than by a backlog, and only the rows that are actually due are read.
/// The measurement above is the worst case that shape allows — every employee of
/// every tenant overdue at the same instant — and it is index scans throughout,
/// four rows locked, about 7 ms, with no sequential scan of either table.
///
/// ponytail: so the ceiling is one tenant's own due headcount per tick, and the
/// upgrade if a deployment ever gets big enough to feel it is to denormalise
/// `lifecycle` onto this table and put it in the index — which costs a column
/// that can go stale, and the module docs above explain why that trade is
/// currently refused.
pub async fn claim_due(
    conn: &mut PgConnection,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<Due>, StoreError> {
    let rows = sqlx::query(concat!(
        "WITH seated AS MATERIALIZED ( \
             SELECT q.employee_id, q.next_at, q.seat \
               FROM tenants t \
               CROSS JOIN LATERAL ( \
                   SELECT top.employee_id, top.next_at, \
                          row_number() OVER (ORDER BY top.next_at, top.employee_id) AS seat \
                     FROM (SELECT i2.employee_id, i2.next_at \
                             FROM employee_initiative i2 \
                             JOIN employees e2 ON e2.id = i2.employee_id \
                                              AND e2.tenant_id = i2.tenant_id \
                            WHERE i2.tenant_id = t.id \
                              AND e2.lifecycle = $3::text \
                              AND i2.next_at <= $1::timestamptz \
                            ORDER BY i2.next_at, i2.employee_id \
                            LIMIT $2::bigint * $4::bigint) top \
               ) q \
              WHERE ",
        crate::not_stopped!("t.id"),
        " \
         ), shortlist AS MATERIALIZED ( \
             SELECT employee_id, seat, next_at FROM seated \
              ORDER BY seat, next_at, employee_id \
              LIMIT $2::bigint * $4::bigint \
         ), due AS MATERIALIZED ( \
             SELECT i3.employee_id \
               FROM shortlist c \
               JOIN employee_initiative i3 ON i3.employee_id = c.employee_id \
              WHERE i3.next_at <= $1::timestamptz \
              ORDER BY c.seat, c.next_at, c.employee_id \
                FOR UPDATE OF i3 SKIP LOCKED \
              LIMIT $2::bigint) \
         UPDATE employee_initiative AS i \
            SET next_at         = \
                    employee_initiative_next_at($1::timestamptz, i.interval_secs), \
                last_claimed_at = $1::timestamptz, \
                claims          = i.claims + 1, \
                last_outcome    = NULL, \
                last_detail     = NULL, \
                updated_at      = $1::timestamptz \
           FROM due d \
           JOIN employees e ON e.id = d.employee_id \
          WHERE i.employee_id = d.employee_id \
        RETURNING i.employee_id, e.tenant_id, i.interval_secs, i.next_at, i.claims",
    ))
    .bind(now)
    .bind(limit)
    // Bound rather than written as a literal, so the spelling stays tied to
    // `Lifecycle::as_str` and a rename is a compile error somewhere rather
    // than a poller that silently claims nothing.
    .bind(Lifecycle::Active.as_str())
    .bind(crate::outbox::POLLER_HEADROOM)
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
/// **The only thing that puts a word in these two columns**, and
/// [`claim_due`] empties them at the top of every beat, so not reaching this
/// call leaves the row saying nothing rather than saying the beat before.
/// A caller that fails here — `loops::initiative::record` logs and swallows —
/// leaves exactly the same NULL a crash does, which is the honest answer in
/// both cases.
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

    /// `n` active employees, each already overdue, in two statements.
    ///
    /// [`seed_due`] is the honest path and every other test uses it; this one
    /// exists because
    /// [`a_claim_that_lands_mid_statement_is_not_handed_out_twice`] needs
    /// thousands of rows and thousands of round trips is a slow test rather
    /// than a careful one.
    async fn seed_many_due(db: &Db, tenant: TenantId, n: i64) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "WITH new_employees AS ( \
                 INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 SELECT gen_random_uuid(), $1, 'store-initiative-bulk-' || g || '-' || $1, \
                        'bulk', $2 \
                   FROM generate_series(1, $3::bigint) g \
                 RETURNING id \
             ) \
             INSERT INTO employee_initiative \
                 (employee_id, tenant_id, interval_secs, next_at) \
             SELECT id, $1, $4::bigint, $5 FROM new_employees",
        )
        .bind(tenant.as_uuid())
        .bind(Lifecycle::Active.as_str())
        .bind(n)
        .bind(HOUR as i64)
        .bind(at(T0 - 10 * HOUR as i64))
        .execute(&mut *tx)
        .await
        .expect("seed many");
        tx.commit().await.expect("commit seed");
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
        // Bounded, because the failure this test exists to catch is a *block*
        // and not a wrong answer: drop `SKIP LOCKED` and the second poller
        // waits on the first one's row locks, while the first one waits at
        // `claimed` for the second — a deadlock the join would sit in forever.
        let (a, b) = tokio::time::timeout(Duration::from_secs(20), async move {
            (a.await.expect("poller a"), b.await.expect("poller b"))
        })
        .await
        .expect(
            "a poller never came back: the second one is waiting on row locks the first \
             one holds until it has claimed, and it never will. That is `FOR UPDATE` \
             without `SKIP LOCKED` — two pollers on one deployment stop being a \
             supported configuration and become a deadlock",
        );

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

    /// **The test above holds both claims open, so it cannot see the poller's
    /// actual arrangement — and in that arrangement the same employee was
    /// claimed twice.**
    ///
    /// `apps/server`'s loop commits the claim *before* the first turn, so in
    /// production the first poller's row locks are gone within milliseconds and
    /// `SKIP LOCKED` has nothing left to skip. What holds the employee from
    /// there is `next_at`, a column the second poller has to re-read — and
    /// `seated` reads `employee_initiative` unlocked under the statement's
    /// snapshot while `due` was joining on `employee_id` and nothing else. When
    /// `READ COMMITTED`'s recheck walked to the version the first poller had
    /// just committed, that join still held, so the employee was claimed again
    /// milliseconds into a schedule that had just moved an hour out. Two turns
    /// for one slot is two model calls billed for one.
    ///
    /// This is the twin of `crate::outbox`'s
    /// `a_claim_that_lands_mid_statement_is_not_handed_out_twice`, in the same
    /// shape and for the same reason: the two claims are one query written
    /// twice, and the mechanism was measured over there. The window is the
    /// `seated`/`shortlist` phase, which is `MATERIALIZED` and complete before
    /// `due` locks anything; the big claim's sort is what widens it and the
    /// small claim commits inside. Rounds rather than one attempt because two
    /// orderings assert nothing and neither is a failure — see the outbox test.
    /// Measured: red on 19 runs of 20 with the predicate removed, green on 20
    /// of 20 with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_claim_that_lands_mid_statement_is_not_handed_out_twice() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "midstatement").await;

        const SLOW: i64 = 1_000;
        const FAST: i64 = 8;
        const ROUNDS: i64 = 5;
        seed_many_due(&db, tenant, (SLOW + FAST) * ROUNDS + 500).await;

        for round in 0..ROUNDS {
            let ready = Arc::new(Barrier::new(2));
            let slow = tokio::spawn({
                let db = db.clone();
                let ready = ready.clone();
                async move {
                    let mut tx: Transaction<'_, Postgres> =
                        db.admin_tx_bypassing_rls().await.expect("admin tx");
                    ready.wait().await;
                    let got = claim_due(&mut tx, SLOW, at(T0)).await.expect("slow claim");
                    tx.commit().await.expect("commit slow");
                    got
                }
            });

            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            crate::db::wait_at_barrier(&ready, "the slow poller").await;
            // Into the big claim's sort rather than alongside its snapshot.
            tokio::time::sleep(Duration::from_millis(2)).await;
            let fast = claim_due(&mut tx, FAST, at(T0)).await.expect("fast claim");
            tx.commit().await.expect("commit fast");

            let slow = slow.await.expect("slow poller");

            // The fingerprint, whichever poller won: an employee handed out
            // twice comes back to the second claimer carrying the first
            // claimer's increment.
            let twice: Vec<EmployeeId> = slow
                .iter()
                .chain(fast.iter())
                .filter(|d| d.claims != 1)
                .map(|d| d.employee_id)
                .collect();
            assert!(
                twice.is_empty(),
                "round {round}: {} employees came back already claimed — the \
                 lock re-read a version somebody else had rescheduled: {twice:?}",
                twice.len()
            );

            let ids_slow: HashSet<Uuid> = slow.iter().map(|d| d.employee_id.as_uuid()).collect();
            let ids_fast: HashSet<Uuid> = fast.iter().map(|d| d.employee_id.as_uuid()).collect();
            assert!(
                ids_slow.is_disjoint(&ids_fast),
                "round {round}: the same employee was claimed by both pollers: {:?}",
                &ids_slow & &ids_fast
            );
        }

        drop_tenant(&db, tenant).await;
    }

    /// **One company's headcount must not decide when another company's
    /// employees act.**
    ///
    /// Not a leak and not a lock: two tenants that never see a byte of each
    /// other's data still share one schedule table, and this claim used to order
    /// it `next_at, employee_id` across every tenant at once. So a customer's
    /// employee is claimed at a position that is a function of *how many
    /// employees the other customers have*, with no ceiling on that number —
    /// while `apps/server`'s initiative loop drains four at a time and each of
    /// those may be a full model turn. The company on the small plan watches its
    /// one employee sit unclaimed because the company on the large plan hired.
    ///
    /// The numbers are the smallest that make the point: one tenant with more
    /// overdue employees than a batch holds, another with one, scheduled so that
    /// FIFO puts it behind all of them. What the claim owes the second tenant is
    /// a seat, not a place in line.
    #[tokio::test]
    async fn one_tenants_headcount_does_not_push_another_tenant_out_of_the_batch() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let big = seed_tenant(&db, "fair-big").await;
        let small = seed_tenant(&db, "fair-small").await;

        const BATCH: i64 = 4;
        const HEADCOUNT: usize = 20;

        // `seed_due` backdates by ten hours, so every one of these is long
        // overdue and they all sort ahead of anything scheduled later.
        for n in 0..HEADCOUNT {
            seed_due(&db, big, &format!("crowd{n}"), Lifecycle::Active).await;
        }
        // The small tenant's only employee, deliberately the *least* overdue row
        // in the table: under FIFO it is last of twenty-one and a batch of four
        // never reaches it.
        let alone = seed_employee(&db, small, "alone", Lifecycle::Active).await;
        let mut tx = db.tenant_tx(small).await.expect("tenant tx");
        set(&mut tx, alone, hourly(), at(T0 - 2 * HOUR as i64))
            .await
            .expect("set");
        tx.commit().await.expect("commit");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_due(&mut tx, BATCH, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit");

        let ids: Vec<EmployeeId> = claimed.iter().map(|d| d.employee_id).collect();
        assert_eq!(ids.len(), BATCH as usize, "the batch is still bounded");
        assert!(
            ids.contains(&alone),
            "the small tenant's only employee was not claimed: another company's \
             headcount decides when this company's employees get to act, and the \
             customer sees nothing but silence"
        );
        // And the big tenant is not punished for being big — it fills every seat
        // the others left. Fair is round-robin, not equal shares of a queue
        // nobody else is using.
        assert_eq!(
            claimed.iter().filter(|d| d.tenant_id == big).count(),
            BATCH as usize - 1
        );

        drop_tenant(&db, big).await;
        drop_tenant(&db, small).await;
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

    /// **A beat that evaporated must not leave the row reporting the beat
    /// before it.**
    ///
    /// The crash [`claim_due`] already accepts, followed all the way to the
    /// column an operator actually reads. The claim commits — that is what
    /// moves the schedule and it is deliberate — and the worker is then killed
    /// before [`record_outcome`]. This test is that kill: a claim that commits
    /// and no record after it, which is byte-for-byte what a `SIGKILL` between
    /// the two transactions leaves behind.
    ///
    /// # Why the first beat is recorded, and why that is the load-bearing line
    ///
    /// Without a *recorded* first beat there is nothing for the second one to
    /// inherit, `last_outcome` is NULL because it was always NULL, and the
    /// assertion below would pass against a table that never cleared anything.
    /// So each round writes an outcome, **asserts it arrived**, and only then
    /// kills the next beat. The fixture has to cross the threshold it is about.
    ///
    /// # `assert_eq!(…, None)` and not `assert_ne!(…, Some("turn"))`
    ///
    /// The second is satisfied by every stale value except one, including the
    /// `clarify` round below — it would go green on exactly the bug. What has
    /// to hold is that the row says *nothing*, so it is spelled as an equality
    /// to `None`.
    ///
    /// # The witness, asserted rather than asserted about
    ///
    /// `updated_at` cannot tell the two cases apart, and the two equalities
    /// below are what say so: it equals `last_claimed_at` after a beat that
    /// recorded **and** after a beat that died, because the claim writes it too
    /// and `loops::initiative::tick` hands one `now` to both statements. They
    /// hold whichever way this module is written; they are here because "the
    /// stale value is undetectable" is the reason the claim has to clear it,
    /// and an unproved premise is how the previous shape survived review.
    #[tokio::test]
    async fn a_beat_killed_before_recording_does_not_report_the_beat_before_it() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db, "stale-outcome").await;
        let id = seed_due(&db, tenant, "unlucky", Lifecycle::Active).await;

        // `Schedule` does not carry `updated_at` — nothing in the product reads
        // it — so the witness is read here rather than widened into the type.
        async fn updated_at(db: &Db, id: EmployeeId) -> DateTime<Utc> {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let got = sqlx::query_scalar(
                "SELECT updated_at FROM employee_initiative WHERE employee_id = $1",
            )
            .bind(id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("updated_at");
            tx.rollback().await.expect("rollback");
            got
        }

        let mut now = at(T0);
        // Two rounds: the outcome that costs the most to be wrong about — an
        // employee whose every beat dies reading `turn`, "working perfectly" —
        // and one carrying a `last_detail`, so the sentence is proved to go
        // with the code rather than survive it. A NULL outcome beside a stale
        // question is the same lie one column over.
        for (outcome, detail) in [("turn", None), ("clarify", Some("how many units?"))] {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let beat = claim_due(&mut tx, 10, now).await.expect("claim");
            tx.commit().await.expect("commit the claim");
            assert_eq!(beat.len(), 1, "the beat at {now} was not taken up");

            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            record_outcome(&mut tx, id, outcome, detail, now)
                .await
                .expect("record");
            tx.commit().await.expect("commit the record");

            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let recorded = get(&mut tx, id).await.expect("get");
            tx.rollback().await.expect("rollback");
            let recorded_updated = updated_at(&db, id).await;

            // The premise, and the line the rest of this test is worthless
            // without: a `None` below proves the claim cleared something only
            // if there was something there to clear.
            assert_eq!(
                recorded.last_outcome.as_deref(),
                Some(outcome),
                "the beat that ran did not record, so the NULL asserted below \
                 would be a column that was never written rather than one the \
                 claim emptied"
            );
            assert_eq!(
                recorded.last_detail.as_deref(),
                detail,
                "the sentence behind the code did not arrive either"
            );
            assert_eq!(
                Some(recorded_updated),
                recorded.last_claimed_at,
                "a beat that recorded leaves `updated_at` on the claim's instant"
            );

            // The next beat is claimed, and the process dies here. Nothing
            // records; that is the whole of the reproduction.
            now = beat[0].next_at;
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let died = claim_due(&mut tx, 10, now).await.expect("claim");
            tx.commit().await.expect("commit the claim");
            assert_eq!(died.len(), 1, "the beat at {now} was not taken up");

            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let after = get(&mut tx, id).await.expect("get");
            tx.rollback().await.expect("rollback");
            let after_updated = updated_at(&db, id).await;

            assert_eq!(
                after.claims,
                recorded.claims + 1,
                "the beat really was taken up, so the row is describing it"
            );
            assert_eq!(
                after.last_outcome, None,
                "the beat that has just been taken up produced nothing, and the \
                 row reports `{outcome}` from the beat before it. An operator \
                 asking whether this cadence works is told about a turn that is \
                 gone — which on `turn` reads as an employee working perfectly \
                 while every one of its beats dies, the one failure nobody looks at"
            );
            assert_eq!(
                after.last_detail, None,
                "the code was cleared and the sentence behind it was not, so the \
                 row now pairs `NULL` with a question from a beat that no longer \
                 exists"
            );
            assert_eq!(
                Some(after_updated),
                after.last_claimed_at,
                "the claim writes `updated_at` too, so a beat that died leaves it \
                 exactly where a beat that recorded leaves it: there is no witness \
                 in this row that could have caught the stale value, which is why \
                 the claim has to clear it rather than a reader having to notice"
            );

            now = died[0].next_at;
        }

        drop_tenant(&db, tenant).await;
    }

    // -- the company-wide stop ---------------------------------------------

    /// **A company whose window ran out is stopped too, and by the same SQL.**
    ///
    /// This exists because the two fixes crossed. [`crate::halt::halted`] was
    /// taught that an expired `company_windows` row is a halt, which covers
    /// every caller that asks it — and this statement does not ask it. It is
    /// cross-tenant SQL driven by `tenants` with an injected clock, so it
    /// spells the predicate out, and a predicate spelled out is one that can be
    /// spelled out incompletely. It was: the halt clause landed here first and
    /// the window clause landed in `outbox::claim_of` only, so a company whose
    /// month ended kept having its employees claimed and their cadence spent.
    ///
    /// The clock is `$1`, not `now()`, or a window that ends between the test's
    /// instant and the server's would decide the outcome.
    #[tokio::test]
    async fn a_company_out_of_time_is_not_claimed_either() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let expired = seed_tenant(&db, "window-expired").await;
        let running = seed_tenant(&db, "window-running").await;

        let waiting = seed_due(&db, expired, "waiting", Lifecycle::Active).await;
        let working = seed_due(&db, running, "working", Lifecycle::Active).await;

        // Both tenants carry a window, so a predicate that skipped every tenant
        // *having* one rather than every tenant *out of* one would still pass.
        let mut tx = db.tenant_tx(expired).await.expect("tenant tx");
        crate::halt::set_window(
            &mut tx,
            at(T0) - TimeDelta::seconds(1),
            "operator:ops",
            at(T0),
        )
        .await
        .expect("set window");
        tx.commit().await.expect("commit expired window");

        let mut tx = db.tenant_tx(running).await.expect("tenant tx");
        crate::halt::set_window(
            &mut tx,
            at(T0) + TimeDelta::days(30),
            "operator:ops",
            at(T0),
        )
        .await
        .expect("set window");
        tx.commit().await.expect("commit open window");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_due(&mut tx, 100, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit claim");

        assert_eq!(
            claimed.iter().map(|d| d.employee_id).collect::<Vec<_>>(),
            vec![working],
            "a company still inside its window works; one out of time does \
             not: {claimed:?}"
        );

        let mut tx = db.tenant_tx(expired).await.expect("tenant tx");
        let after = get(&mut tx, waiting).await.expect("get");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            after.claims, 0,
            "the window spent none of the employee's cadence, so extending it \
             resumes the same overdue row"
        );
    }

    /// **A stopped company's employees wait; their slots are not spent.**
    ///
    /// "Not claimed" is only half the assertion, and the other half is not the
    /// model bill — see [`claim_due`] for why that reading is wrong and what
    /// holds it instead. `employee_initiative` has no attempt cap to burn, but
    /// this statement reschedules in the same breath: a claim-then-refuse
    /// pushes `next_at` a whole interval out and the employee stays silent for
    /// another cadence after the release. Hence `claims` unmoved, `next_at`
    /// unmoved, and the release resuming the same overdue row at the same
    /// instant.
    #[tokio::test]
    async fn a_stopped_company_s_employees_are_not_claimed_and_spend_no_slot() {
        let Some(db) = db().await else { return };
        let _guard = INITIATIVE_LOCK.lock().await;
        clear_schedules(&db).await;
        let stopped = seed_tenant(&db, "halt-stopped").await;
        let running = seed_tenant(&db, "halt-running").await;

        let waiting = seed_due(&db, stopped, "waiting", Lifecycle::Active).await;
        let working = seed_due(&db, running, "working", Lifecycle::Active).await;

        // What `next_at` was before anybody claimed, so the deferral can be
        // asserted against a number this test did not invent.
        let mut tx = db.tenant_tx(stopped).await.expect("tenant tx");
        let before = get(&mut tx, waiting).await.expect("get");
        crate::halt::place(&mut tx, "stop everything", "operator:ops", at(T0))
            .await
            .expect("place")
            .expect("it was running");
        tx.commit().await.expect("commit halt");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_due(&mut tx, 100, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit claim");

        assert_eq!(
            claimed.iter().map(|d| d.employee_id).collect::<Vec<_>>(),
            vec![working],
            "only the running company's employee may be claimed: {claimed:?}"
        );

        // The load-bearing half: the deferred employee is untouched, so the
        // halt costs its cadence nothing and there is nothing to replay.
        let mut tx = db.tenant_tx(stopped).await.expect("tenant tx");
        let after = get(&mut tx, waiting).await.expect("get");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            after.claims, 0,
            "a deferred employee burns no claim, so the halt spent none of its \
             cadence"
        );
        assert_eq!(after.last_claimed_at, None, "and it was never taken up");
        assert_eq!(
            after.next_at, before.next_at,
            "and its deadline was not pushed out either: it is due the instant \
             the company is released, not one whole cadence later"
        );

        let mut tx = db.tenant_tx(stopped).await.expect("tenant tx");
        crate::halt::release(&mut tx)
            .await
            .expect("release")
            .expect("it was halted");
        tx.commit().await.expect("commit release");

        // The same instant as the first claim, so the running company's
        // employee — rescheduled an hour out by the claim that took it — is
        // deterministically not due and this assertion is about the deferred
        // one alone.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let resumed = claim_due(&mut tx, 100, at(T0)).await.expect("claim");
        tx.commit().await.expect("commit claim");
        assert_eq!(
            resumed.iter().map(|d| d.employee_id).collect::<Vec<_>>(),
            vec![waiting],
            "the release resumes exactly the employee that was waiting"
        );
        assert_eq!(
            resumed[0].claims, 1,
            "and it is on its FIRST claim, not its second: the halt cost it nothing"
        );

        drop_tenant(&db, stopped).await;
        drop_tenant(&db, running).await;
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
