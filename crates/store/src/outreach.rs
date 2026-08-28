//! The daily cold-outreach budget: how many strangers an employee may reach.
//!
//! The third of this workspace's three daily ceilings, and the last one to get a
//! ledger. [`crate::turns`] bounds how often an employee acts; [`crate::spend`]
//! bounds what it may pay; this bounds whose inbox it may arrive in for the
//! first time. It is the one of the three an operator answers for in front of a
//! supervisory authority, which is why it is the one that could least afford to
//! be counted rather than reserved.
//!
//! # What it fixes, and it was two things
//!
//! Both were reproduced deterministically before this module existed —
//! `0055_outreach_budget.sql` writes them out, and the tests below hold them
//! open by hand rather than racing a scheduler.
//!
//! * `app::gate::PolicyGate::contacts` reads the day's count as an **unlocked
//!   aggregate over `audit_log`**, and the write that follows it is
//!   `audit::append` — an INSERT into an append-only log with no unique index
//!   and no counter row. Two decisions read `1 of 2`, both are allowed, both
//!   append: three strangers on a ceiling of two.
//! * `routes::queue::export` never reaches the gate on the file path. Its
//!   counter is `revenue::contacted_since`, read unlocked, and the selection
//!   under it takes `FOR UPDATE OF c SKIP LOCKED` — so two exports get
//!   **disjoint** prospects, neither ever blocks, and both take the whole day.
//!
//! Neither counter can be locked: an aggregate over an append-only log has no
//! row to lock, and neither does a `count(*)` over `contacts`. A counter row is
//! the only shape that serialises them, and [`reserve`] is that row's one verb.
//!
//! # Reserved, not counted, and the shape is [`crate::turns`]'s
//!
//! `INSERT … ON CONFLICT DO UPDATE SET contacts_taken = outreach_buckets
//! .contacts_taken RETURNING contacts_taken`. The no-op assignment is what makes
//! it a lock: `DO NOTHING` returns no row to a concurrent inserter and takes no
//! lock at all, which is the race in the first place. The ceiling is compared
//! **after** that statement and the increment is written before the caller's
//! transaction commits, so no second decision can read the count in between.
//!
//! # It only ever refuses more
//!
//! Both counters above keep running. That is not caution, it is the deployment
//! day: a bucket created at noon starts at zero while the trail already holds
//! this morning's strangers, so a bucket that *replaced* the aggregate would
//! hand every tenant a fresh allowance the afternoon the migration lands. Side
//! by side, the day's refusal is the strictest of the two and nothing widens.
//!
//! Sequentially the bucket and the old aggregate agree exactly —
//! [`tests::the_bucket_and_the_audit_aggregate_count_the_same_set`] walks the
//! same sequence past both and compares them at every step — so the set this
//! charges for is the set the gate always charged for. Where they differ, the
//! bucket is the larger number, and it is larger by exactly the concurrent
//! decisions the aggregate could not see.
//!
//! # Which day
//!
//! UTC, `now.date_naive()`, the same day the other two ledgers key on. The
//! argument is [`crate::turns`]'s and it has not changed: there is no
//! `tenants.timezone` column, and an employee whose ledgers roll at different
//! instants has two todays.
//!
//! # No release verb
//!
//! [`crate::spend`] has one because a payment can fail at the provider and the
//! money demonstrably did not move. Nothing here is like that. A reserved
//! contact is a *decision to approach a stranger* that was made, ruled on and
//! written to `audit_log`; the old counter charges it whether or not the send
//! then succeeded, so handing the slot back would free something the trail still
//! shows as spent — and it is the exact path a retry loop would ride to mail one
//! stranger repeatedly. `app::queue::push` already picked this direction for
//! this vertical: marked-and-not-written-to is the survivable error, and
//! written-to-twice is what a sending domain does not recover from.

use agentos_domain::ids::EmployeeId;
use agentos_domain::policy::EffectivePolicy;
use chrono::NaiveDate;
use thiserror::Error;

use crate::db::{StoreError, TenantTx};

/// Why an approach was refused.
///
/// Two refusals rather than one, for [`crate::turns`]'s reason: [`Self::NoBudget`]
/// is a policy nobody wrote, and [`Self::Exhausted`] is a policy doing its job.
#[derive(Debug, Error)]
pub enum ContactBudgetError {
    /// The intersected policy allows this employee no cold outreach at all.
    /// Fails closed by design — `PolicyLimits::default()` is zero, and every
    /// role pack in `docs/` ships zero, so cold outreach is something an
    /// operator turns on rather than something a deployment starts with.
    #[error("no contact budget: the effective policy allows 0 new contacts per day")]
    NoBudget,

    /// Today's strangers are used up. It resumes on its own at UTC midnight.
    #[error("daily budget of {limit} new contacts is already used up ({taken} taken)")]
    Exhausted {
        /// The ceiling.
        limit: u32,
        /// What the bucket held.
        taken: u32,
    },

    /// The database said no.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for ContactBudgetError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

impl ContactBudgetError {
    /// Stable, low-cardinality metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            ContactBudgetError::NoBudget => "no_contact_budget",
            ContactBudgetError::Exhausted { .. } => "contact_budget_exhausted",
            ContactBudgetError::Store(_) => "unavailable",
        }
    }
}

/// Take up to `want` of today's strangers, or refuse. **Returns how many were
/// granted, which is never more than `want` and never zero.**
///
/// Call it in the transaction that records the approach — the gate's audit row,
/// the export's `record_queued` — and before anything leaves the process. The
/// bucket row stays locked until that transaction commits, so between the
/// comparison and the increment nobody else can reserve against the same day.
///
/// The ceiling is not a `u32` parameter. It is read out of an
/// [`EffectivePolicy`], which can only be produced by `EffectivePolicy::try_new`
/// — the one intersection of platform ∧ tenant ∧ role ∧ employee — so a caller
/// cannot inflate the cap the way it could with a bare number, and this module
/// does not re-derive it. The tenant likewise comes from `tx`, which is the only
/// thing row-level security honours anyway.
///
/// # A partial grant, and why this one is not all-or-nothing
///
/// [`crate::turns`] reserves one turn and [`crate::spend`] reserves one amount,
/// so neither has anything to be partial about. This has two callers wanting two
/// sizes: the gate asks for exactly one stranger, and an export asks for the
/// file it has just built. Refusing a file of forty because thirty-eight fit
/// would cost the founder a morning and would not protect anybody — the ceiling
/// is a ceiling on people written to, not on requests. So the grant is
/// `min(want, headroom)` and the caller truncates to it. Asking for one and
/// getting one back is the same statement `turns::reserve` makes.
///
/// `want == 0` is `Ok(0)` and touches nothing: an export with an empty queue
/// must not leave a bucket row behind, for the same reason an employee with no
/// budget must not.
pub async fn reserve(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
    policy: &EffectivePolicy,
    want: u32,
) -> Result<u32, ContactBudgetError> {
    if want == 0 {
        return Ok(0);
    }
    let tenant = tx.tenant_id().as_uuid();
    // ponytail: read inline rather than through a `contacts_remaining` twin of
    // `policy::turns_remaining`. That function earns its place by being called
    // from a route as well as from the ledger; this subtraction has one caller
    // and a second spelling of a limit is how two spellings come to disagree.
    let limit = policy.limits().max_new_contacts_per_day;
    if limit == 0 {
        return Err(ContactBudgetError::NoBudget);
    }

    // Create-if-missing *and* lock, in one statement. `DO UPDATE` with a no-op
    // assignment is what makes it a lock: `DO NOTHING` returns no row to a
    // concurrent inserter and takes no lock, which is the race this module
    // exists to close. RETURNING yields the count as of the lock.
    let taken: i32 = sqlx::query_scalar(
        "INSERT INTO outreach_buckets (tenant_id, employee_id, day) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id, employee_id, day) DO UPDATE SET \
           contacts_taken = outreach_buckets.contacts_taken \
         RETURNING contacts_taken",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .fetch_one(&mut ***tx)
    .await?;

    // -- everything from here to COMMIT runs under that row lock --

    let taken = u32::try_from(taken).unwrap_or(u32::MAX);
    let granted = want.min(limit.saturating_sub(taken));
    if granted == 0 {
        return Err(ContactBudgetError::Exhausted { limit, taken });
    }

    sqlx::query(
        "UPDATE outreach_buckets SET contacts_taken = contacts_taken + $4, updated_at = now() \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .bind(i32::try_from(granted).unwrap_or(i32::MAX))
    .execute(&mut ***tx)
    .await?;

    Ok(granted)
}

/// How many strangers this employee has been cleared to reach on `day`. The
/// operator's question, and the tests'.
///
/// Zero for a day with no bucket row, which is the same answer as a bucket at
/// zero and means the same thing.
pub async fn taken_today(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
) -> Result<u32, StoreError> {
    let taken: Option<i32> = sqlx::query_scalar(
        "SELECT contacts_taken FROM outreach_buckets \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id.as_uuid())
    .bind(day)
    .fetch_optional(&mut ***tx)
    .await?;

    // CHECKed non-negative in the schema. Clamping to zero if it ever is not
    // reports *less* consumption than happened, which is the direction that does
    // not silently silence an employee on a corrupt row.
    Ok(taken.map_or(0, |t| u32::try_from(t).unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::PolicyLimits;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use super::*;
    use crate::db::Db;

    const DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 28) {
        Some(d) => d,
        None => panic!("valid date"),
    };
    const NEXT_DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 29) {
        Some(d) => d,
        None => panic!("valid date"),
    };

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the outreach ledger needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed(db: &Db, label: &str) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("{label}-{}", tenant.as_uuid()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(label)
        .bind(label)
        .execute(&mut *tx)
        .await
        .expect("insert employee");

        tx.commit().await.expect("commit seed");
        (tenant, employee)
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    /// An already-intersected policy allowing `contacts` strangers per day.
    /// Going through `try_new` is the point: there is no other way to spell an
    /// `EffectivePolicy`, which is what stops a caller inflating the cap.
    fn policy(contacts: u32) -> EffectivePolicy {
        let limits = PolicyLimits {
            max_new_contacts_per_day: contacts,
            ..PolicyLimits::default()
        };
        EffectivePolicy::try_new(&limits, &limits, &limits, &limits).expect("coherent")
    }

    /// Reserve in its own committed transaction, the way a caller would.
    async fn reserve_committed(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        day: NaiveDate,
        policy: &EffectivePolicy,
        want: u32,
    ) -> Result<u32, ContactBudgetError> {
        let mut tx = db.tenant_tx(tenant).await?;
        match reserve(&mut tx, employee, day, policy, want).await {
            Ok(granted) => {
                tx.commit().await?;
                Ok(granted)
            }
            Err(e) => {
                tx.rollback().await?;
                Err(e)
            }
        }
    }

    async fn counted(db: &Db, tenant: TenantId, employee: EmployeeId, day: NaiveDate) -> u32 {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let n = taken_today(&mut tx, employee, day).await.expect("read");
        tx.rollback().await.expect("rollback");
        n
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_employee_with_no_contact_budget_reaches_nobody_and_leaves_no_row() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "nocontacts").await;

        let err = reserve_committed(&db, tenant, employee, DAY, &policy(0), 1)
            .await
            .expect_err("an unconfigured policy allows no cold outreach");
        assert!(matches!(err, ContactBudgetError::NoBudget), "{err}");
        assert_eq!(err.code(), "no_contact_budget");
        assert_eq!(counted(&db, tenant, employee, DAY).await, 0);

        // An empty queue is not a refusal and is not a write either.
        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy(10), 0)
                .await
                .expect("asking for nobody is not an error"),
            0
        );
        assert_eq!(counted(&db, tenant, employee, DAY).await, 0);

        drop_tenant(&db, tenant).await;
    }

    /// The cap holds, a batch is granted what fits rather than refused whole,
    /// and a new UTC day is a fresh bucket with no sweeper.
    #[tokio::test]
    async fn the_days_strangers_run_out_and_the_day_rolls_over() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "exhaust").await;
        let policy = policy(3);

        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy, 1)
                .await
                .expect("the first stranger"),
            1
        );
        // A file of ten against two remaining slots is two, not a refusal.
        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy, 10)
                .await
                .expect("what fits is granted"),
            2
        );
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        let err = reserve_committed(&db, tenant, employee, DAY, &policy, 1)
            .await
            .expect_err("three is the budget");
        assert!(
            matches!(err, ContactBudgetError::Exhausted { limit: 3, taken: 3 }),
            "{err}"
        );
        assert_eq!(err.code(), "contact_budget_exhausted");
        assert_eq!(
            counted(&db, tenant, employee, DAY).await,
            3,
            "a refusal does not advance the ledger"
        );

        // Tomorrow is a new bucket; today's record is untouched, because a
        // consumption ledger is not a gauge.
        assert_eq!(
            reserve_committed(&db, tenant, employee, NEXT_DAY, &policy, 3)
                .await
                .expect("tomorrow is a new day"),
            3
        );
        assert_eq!(counted(&db, tenant, employee, NEXT_DAY).await, 3);
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// **The bug.** Two decisions, one slot left, hand-interleaved so the result
    /// does not depend on the scheduler.
    ///
    /// Against the unlocked `audit_log` aggregate the gate used, the second
    /// transaction reads the count as it stood before the first decision, sees
    /// room, and the day ends at 4 strangers against a ceiling of 3 — every
    /// single run. Reproduced in SQL before this module was written.
    ///
    /// **The timeout is not the assertion that matters, and believing it was
    /// cost a mutation run.** A lock-free implementation blocks here too — on
    /// its own final `UPDATE`, not on the read — so the second task fails to
    /// finish inside 500ms either way and the timeout goes green against a
    /// broken `reserve`. What catches it is the *outcome*: a decision made from
    /// an unlocked read returns `Ok(1)` against a bucket that is already full,
    /// and the day ends at 4. Both assertions stay, because the timeout is what
    /// proves the second decision was genuinely in flight rather than never
    /// started, and the outcome is what proves it was in flight *behind the
    /// lock*.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_decisions_cannot_both_take_the_last_stranger() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "interleave").await;
        let policy = policy(3);

        // Two already taken, committed, so the bucket row exists. Without this
        // the two transactions below would race to *create* the row and Postgres
        // would serialise that on the primary key all by itself — which would
        // let a lock-free implementation pass for the wrong reason.
        reserve_committed(&db, tenant, employee, DAY, &policy, 2)
            .await
            .expect("warm-up");

        // The third stranger: reserved, transaction left open exactly as it
        // would be while the audit row and the send are being written beside it.
        let mut first = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(
            reserve(&mut first, employee, DAY, &policy, 1)
                .await
                .expect("the last slot"),
            1
        );

        // A second decision, concurrently. On its own merit the bucket still
        // says 2 of 3 — that is what makes the race work.
        let second = tokio::spawn({
            let db = db.clone();
            let policy = policy.clone();
            async move {
                let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
                let outcome = reserve(&mut tx, employee, DAY, &policy, 1).await;
                // Commit either way: if the implementation wrongly granted it,
                // the damage must be visible in the bucket rather than rolled
                // back by a tidy test.
                tx.commit().await.expect("commit second");
                outcome
            }
        });

        // It must still be blocked. If `reserve` decided anything here it did so
        // from a bucket it had not locked.
        let mut second = std::pin::pin!(second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut second)
                .await
                .is_err(),
            "the second decision ruled while the first held the bucket"
        );

        first.commit().await.expect("commit first");

        let outcome = second.await.expect("task panicked");
        assert!(
            matches!(
                outcome,
                Err(ContactBudgetError::Exhausted { limit: 3, taken: 3 })
            ),
            "the second decision must be refused, got {outcome:?}"
        );
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// **The set this charges for is the set the gate always charged for.**
    ///
    /// Not asserted, walked: one sequence of decisions is pushed through the
    /// bucket and through `PolicyGate::contacts`' own SQL — copied verbatim, so
    /// a change to either is a failure here — and the two are compared after
    /// every step. Repeats are free on both sides, yesterday's stranger is free
    /// on both sides, and an action with no counterparty costs nothing on
    /// either. Sequentially they never disagree; the concurrent case above is
    /// the only place they can, and there the bucket is the larger number.
    #[tokio::test]
    async fn the_bucket_and_the_audit_aggregate_count_the_same_set() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "sameset").await;
        let policy = policy(10);
        let noon = DAY.and_hms_opt(12, 0, 0).expect("valid time").and_utc();

        // Yesterday's stranger, in the trail and not in today's count.
        append_allow(
            &db,
            tenant,
            employee,
            Some("old@example.com"),
            noon - chrono::Duration::days(1),
        )
        .await;

        // The sequence, as the gate would see it: two strangers, a repeat of the
        // first, a repeat of yesterday's, a third stranger, and one allowed
        // action that addresses nobody (a payment, `counterparty` = None).
        let script: [(Option<&str>, bool); 6] = [
            (Some("a@example.com"), true),
            (Some("b@example.com"), true),
            (Some("a@example.com"), false),
            (Some("old@example.com"), false),
            (Some("c@example.com"), true),
            (None, false),
        ];

        for (who, is_new) in script {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            // The gate charges exactly when the counterparty is new to the
            // trail. Assert the fixture's own belief against the trail first, so
            // a wrong script cannot make the comparison below pass.
            assert_eq!(
                standing(&mut tx, employee, who, noon).await,
                is_new,
                "the trail disagrees with the script about {who:?}"
            );
            if is_new {
                assert_eq!(
                    reserve(&mut tx, employee, DAY, &policy, 1)
                        .await
                        .expect("within the budget"),
                    1
                );
            }
            tx.commit().await.expect("commit reservation");
            append_allow(&db, tenant, employee, who, noon).await;

            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let aggregate = new_today(&mut tx, employee, noon).await;
            let bucket = taken_today(&mut tx, employee, DAY).await.expect("bucket");
            tx.rollback().await.expect("rollback");
            assert_eq!(
                bucket, aggregate,
                "the bucket and the audit aggregate must count the same strangers after {who:?}"
            );
        }

        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// A tenant's strangers are its own. RLS, not a WHERE clause somebody adds —
    /// and **forced**, which `SET LOCAL ROLE app_role` alone cannot prove: a
    /// table with `enable` and no `force` is wide open to whoever owns it.
    #[tokio::test]
    async fn one_tenants_outreach_is_invisible_to_another() {
        let Some(db) = db().await else { return };
        let (tenant_a, employee_a) = seed(&db, "tenant-a").await;
        let (tenant_b, _) = seed(&db, "tenant-b").await;

        reserve_committed(&db, tenant_a, employee_a, DAY, &policy(5), 2)
            .await
            .expect("a's strangers");
        assert_eq!(counted(&db, tenant_a, employee_a, DAY).await, 2);
        // B asking about A's employee sees nothing at all.
        assert_eq!(counted(&db, tenant_b, employee_a, DAY).await, 0);

        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = 'outreach_buckets'::regclass",
        )
        .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
        .await
        .expect("catalogue");
        assert!(enabled, "outreach_buckets has row-level security enabled");
        assert!(
            forced,
            "…and forced, or the owning role reads every tenant's cold-outreach ledger"
        );

        drop_tenant(&db, tenant_a).await;
        drop_tenant(&db, tenant_b).await;
    }

    // -- the gate's own SQL, borrowed ---------------------------------------

    /// One allowed audit row, exactly as `PolicyGate::finish` would write it.
    async fn append_allow(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        counterparty: Option<&str>,
        at: DateTime<Utc>,
    ) {
        let payload = counterparty.map_or_else(
            || serde_json::json!({}),
            |who| serde_json::json!({ "counterparty": who }),
        );
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, employee_id, actor, action_kind, \
                                    decision, payload, occurred_at) \
             VALUES ($1, $2, $3, 'op', 'email.send', 'allow', $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid())
        .bind(payload)
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("append");
        tx.commit().await.expect("commit audit");
    }

    /// `PolicyGate::contacts`' first return value, verbatim.
    async fn new_today(tx: &mut TenantTx<'_>, employee: EmployeeId, now: DateTime<Utc>) -> u32 {
        let day_start = now
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap_or_default()
            .and_utc();
        let n: i64 = sqlx::query_scalar(
            "WITH seen AS ( \
                 SELECT payload->>'counterparty' AS counterparty, min(occurred_at) AS first_at \
                   FROM audit_log \
                  WHERE employee_id = $1 \
                    AND decision = 'allow' \
                    AND payload->>'counterparty' IS NOT NULL \
                  GROUP BY 1) \
             SELECT count(*) FILTER (WHERE first_at >= $2) FROM seen",
        )
        .bind(employee.as_uuid())
        .bind(day_start)
        .fetch_one(&mut ***tx)
        .await
        .expect("aggregate");
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// `PolicyGate::contacts`' second return value: true when the counterparty
    /// is new to the trail, which is exactly when the gate charges for it.
    async fn standing(
        tx: &mut TenantTx<'_>,
        employee: EmployeeId,
        counterparty: Option<&str>,
        _now: DateTime<Utc>,
    ) -> bool {
        let Some(who) = counterparty else {
            // No counterparty is no charge, whatever the trail says.
            return false;
        };
        let known: Option<bool> = sqlx::query_scalar(
            "SELECT bool_or(payload->>'counterparty' = $2) \
               FROM audit_log \
              WHERE employee_id = $1 \
                AND decision = 'allow' \
                AND payload->>'counterparty' IS NOT NULL",
        )
        .bind(employee.as_uuid())
        .bind(who)
        .fetch_one(&mut ***tx)
        .await
        .expect("standing");
        !known.unwrap_or(false)
    }
}
