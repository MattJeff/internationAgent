//! The daily turn budget: how often an employee may act at all.
//!
//! Every other ceiling in this workspace is on **money** or on **tool calls
//! inside one turn**. [`crate::spend`] bounds what may be paid;
//! `app::turn::Budgets` bounds one run's tool calls and tokens. Neither is a
//! bound on *turns*, because until an initiative loop existed a turn only
//! happened when a message arrived, and the arrival was the throttle.
//!
//! An autonomous employee has no such throttle. It can wake, think, read and
//! write without ever proposing a payment — tripping no existing limit — while
//! billing model tokens on every cycle. This module is the missing ceiling, and
//! it is a safety property rather than an optimisation: it has to exist before
//! waking on a cadence is switched on.
//!
//! # Reserved, not counted
//!
//! [`reserve`] takes the slot **before** the turn runs, under a row lock, in
//! the caller's transaction — the same shape as [`crate::spend::reserve`] and
//! for a sharper reason. The model call is at the *top* of a turn, so by the
//! time anything can crash the tokens are already paid for. A counter
//! incremented on completion makes a turn that dies after the model call free,
//! and a crash-looping employee then bills forever against a budget that never
//! advances. Reserving first means a crashed turn still costs its slot: the
//! employee runs out early and stops, visibly, instead of spinning for free.
//!
//! That is the trade and it is not free. A turn refused by infrastructure —
//! the database flapping, a cancellation — also burns a slot, so a bad
//! afternoon can eat an employee's day for reasons that were never its fault.
//! Over-counting caps the bill; under-counting does not cap anything. The
//! remedy for the first is an operator raising the budget, and
//! [`taken_today`] is how they see they need to.
//!
//! There is deliberately **no release verb**. [`crate::spend::release`] exists
//! because a payment can fail at the provider and the money demonstrably did
//! not move. A turn that started has already spent its tokens, so a release
//! would hand back something genuinely consumed — and it is the exact path a
//! crash loop would ride: fail late, release, retry, forever.
//!
//! # Which day
//!
//! UTC, from the same `now.date_naive()` the spend ledger keys on. There is no
//! `tenants.timezone` column anywhere in this schema, so a local-midnight
//! rollover would have to invent one, and then the turn day and the spend day
//! would roll at different instants for one employee — making "what did it
//! consume today" a question with two answers. One clock, shared with the
//! money. An employee whose operators sit in UTC+8 gets its fresh allowance
//! mid-morning; the fix, when somebody asks, is a tenant timezone applied to
//! **both** ledgers at once.
//!
//! # Turns, not tokens
//!
//! A token cap is the honest unit of an LLM bill and it cannot be enforced
//! here: the provider counts tokens, and no reliable count exists *before* the
//! call — the only moment a cap can refuse anything. A turn is refusable before
//! it costs money, so turns are the proxy. The multiplier to currency lives
//! outside this workspace, with the rate card.

use agentos_domain::ids::EmployeeId;
use agentos_domain::policy::{EffectivePolicy, turns_remaining};
use chrono::NaiveDate;
use thiserror::Error;

use crate::db::{StoreError, TenantTx};

/// One turn's worth of headroom, already consumed.
///
/// Holding one is what authorises the turn to run. There is no verb that hands
/// it back — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnSlot {
    employee_id: EmployeeId,
    day: NaiveDate,
    taken: u32,
    limit: u32,
}

impl TurnSlot {
    /// Who is acting.
    pub const fn employee_id(&self) -> EmployeeId {
        self.employee_id
    }

    /// The UTC day whose bucket this came out of.
    pub const fn day(&self) -> NaiveDate {
        self.day
    }

    /// Turns consumed today, this one included.
    pub const fn taken(&self) -> u32 {
        self.taken
    }

    /// The intersected ceiling this was measured against.
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Turns still available today, after this one.
    pub const fn remaining(&self) -> u32 {
        self.limit.saturating_sub(self.taken)
    }

    /// **The alert edge.** True on the one reservation that consumed the last
    /// slot, and on no other.
    ///
    /// Exactly-once falls out of the row lock rather than out of a flag: the
    /// bucket is locked for the whole reservation, so precisely one caller can
    /// observe the count crossing the ceiling, and that caller's transaction is
    /// the one that commits. An `alerted_at` column would be written on the
    /// *refusal* path instead, and a refusal's transaction is normally rolled
    /// back — which is how "alert once" quietly becomes "alert on every
    /// attempt".
    ///
    /// ponytail: the known ceiling of deriving it from the crossing is that
    /// there are two ways to be exhausted without one. An employee whose budget
    /// is *lowered* below what it has already spent today never crosses, and
    /// neither does one with no budget at all ([`TurnBudgetError::NoBudget`]) —
    /// both are refused silently until midnight. Both are an operator having
    /// just edited a policy rather than an employee running away, and both are
    /// visible in `GET /v1/employees/{id}/turns`. Upgrade path, if that is not
    /// good enough: alert from the policy *writer*, which is the code that
    /// knows a cap moved — not from here, which would need the flag and the
    /// commit-on-refusal this shape exists to avoid.
    pub const fn exhausts_the_day(&self) -> bool {
        self.remaining() == 0
    }
}

/// Why a turn was refused.
///
/// Two refusals, not one, because the remedies differ: [`Self::NoBudget`] is a
/// policy nobody wrote, and [`Self::Exhausted`] is a policy doing its job.
#[derive(Debug, Error)]
pub enum TurnBudgetError {
    /// The intersected policy grants this employee no turns at all. Fails
    /// closed by design: `PolicyLimits::default()` is zero, so an unconfigured
    /// employee never wakes rather than never stopping.
    #[error("no turn budget: the effective policy allows 0 turns per day")]
    NoBudget,

    /// Today's turns are used up. It resumes on its own at UTC midnight.
    #[error("daily budget of {limit} turns is already used up ({taken} taken)")]
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

impl From<sqlx::Error> for TurnBudgetError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

impl TurnBudgetError {
    /// Stable, low-cardinality metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            TurnBudgetError::NoBudget => "no_turn_budget",
            TurnBudgetError::Exhausted { .. } => "turn_budget_exhausted",
            TurnBudgetError::Store(_) => "unavailable",
        }
    }
}

/// Consume one of today's turns, or refuse.
///
/// Call it in the transaction that starts the turn, **before** the model is
/// called. The bucket row stays locked until that transaction commits, so
/// between the check and the increment nobody else can reserve against the same
/// day — two wakers cannot both read "9 of 10 taken" and both proceed.
///
/// The ceiling is not a `u32` parameter. It is read out of an
/// [`EffectivePolicy`], which can only be produced by
/// `EffectivePolicy::try_new` — the one intersection of platform ∧ tenant ∧
/// role ∧ employee. So a caller cannot inflate the cap the way it could with a
/// bare number, and this module does not have to re-derive it (a second
/// intersection being how a widening bug appears). The tenant likewise comes
/// from `tx`, which is the only thing row-level security honours anyway.
///
/// An employee with no budget leaves no bucket row behind: being refused must
/// not be a write.
pub async fn reserve(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
    policy: &EffectivePolicy,
) -> Result<TurnSlot, TurnBudgetError> {
    let tenant = tx.tenant_id().as_uuid();
    let limit = policy.limits().max_turns_per_day;
    if limit == 0 {
        return Err(TurnBudgetError::NoBudget);
    }

    // Create-if-missing *and* lock, in one statement. `DO UPDATE` with a no-op
    // assignment is what makes it a lock: `DO NOTHING` returns no row to a
    // concurrent inserter and takes no lock, which is the race this module
    // exists to close. RETURNING yields the count as of the lock.
    let taken: i32 = sqlx::query_scalar(
        "INSERT INTO turn_buckets (tenant_id, employee_id, day) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id, employee_id, day) DO UPDATE SET \
           turns_taken = turn_buckets.turns_taken \
         RETURNING turns_taken",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .fetch_one(&mut ***tx)
    .await?;

    // -- everything from here to COMMIT runs under that row lock --

    let taken = u32::try_from(taken).unwrap_or(u32::MAX);
    if turns_remaining(policy, taken) == 0 {
        return Err(TurnBudgetError::Exhausted { limit, taken });
    }

    sqlx::query(
        "UPDATE turn_buckets SET turns_taken = turns_taken + 1, updated_at = now() \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .execute(&mut ***tx)
    .await?;

    let slot = TurnSlot {
        employee_id,
        day,
        taken: taken.saturating_add(1),
        limit,
    };

    // The operator alert, raised here because this is the only place the
    // crossing is observable and it is observable exactly once. An employee
    // that has stopped working must not stop silently, and the follow-up
    // attempts below are plain refusals that say nothing further.
    //
    // ponytail: `tracing::error!`, which is how this workspace already raises
    // an operator alert (see the stranded-resource path in `apps/server`).
    // There is no alerting table and no metrics exporter here; adding one for
    // a single event would be inventing an alerting system. The queryable half
    // is `taken_today` and `GET /v1/employees/{id}/turns`.
    if slot.exhausts_the_day() {
        tracing::error!(
            employee_id = %employee_id.as_uuid(),
            day = %day,
            limit,
            "employee has used its last turn of the day and will not act again \
             until UTC midnight - raise its turn budget if this was not intended"
        );
    }
    Ok(slot)
}

/// How many turns this employee has consumed on `day`. The operator's question.
///
/// Zero for a day with no bucket row, which is the same answer as a bucket at
/// zero and means the same thing.
pub async fn taken_today(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
) -> Result<u32, StoreError> {
    let taken: Option<i32> = sqlx::query_scalar(
        "SELECT turns_taken FROM turn_buckets \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id.as_uuid())
    .bind(day)
    .fetch_optional(&mut ***tx)
    .await?;

    // CHECKed non-negative in the schema. Clamping to zero if it ever is not
    // reports *less* consumption than happened, which is the direction that
    // does not silently lock an employee out on a corrupt row.
    Ok(taken.map_or(0, |t| u32::try_from(t).unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::PolicyLimits;
    use chrono::Utc;

    use super::*;
    use crate::db::Db;

    const DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 23) {
        Some(d) => d,
        None => panic!("valid date"),
    };
    const NEXT_DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 24) {
        Some(d) => d,
        None => panic!("valid date"),
    };

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the turn ledger needs a real Postgres");
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

    /// An already-intersected policy allowing `turns` per day. Going through
    /// `try_new` is the point: there is no other way to spell an
    /// `EffectivePolicy`, which is what stops a caller inflating the cap.
    fn policy(turns: u32) -> EffectivePolicy {
        let limits = PolicyLimits {
            max_turns_per_day: turns,
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
    ) -> Result<TurnSlot, TurnBudgetError> {
        let mut tx = db.tenant_tx(tenant).await?;
        match reserve(&mut tx, employee, day, policy).await {
            Ok(slot) => {
                tx.commit().await?;
                Ok(slot)
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
    async fn an_employee_with_no_turn_budget_never_wakes_and_leaves_no_row() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "noturns").await;

        let err = reserve_committed(&db, tenant, employee, DAY, &policy(0))
            .await
            .expect_err("an unconfigured policy grants no turns");
        assert!(matches!(err, TurnBudgetError::NoBudget), "{err}");
        assert_eq!(err.code(), "no_turn_budget");
        assert_eq!(counted(&db, tenant, employee, DAY).await, 0);

        drop_tenant(&db, tenant).await;
    }

    /// The alert fires on the reservation that takes the last slot, and on
    /// nothing after it. A flag written on the *refusal* path would be rolled
    /// back with the refusal and re-fire on every single attempt — which is the
    /// failure this shape avoids.
    #[tokio::test]
    async fn the_budget_is_exhausted_once_and_refuses_quietly_after_that() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "exhaust").await;
        let policy = policy(3);

        let mut alerts = 0;
        let mut granted = 0;
        let mut refusals = 0;

        for _ in 0..10 {
            match reserve_committed(&db, tenant, employee, DAY, &policy).await {
                Ok(slot) => {
                    granted += 1;
                    assert_eq!(slot.limit(), 3);
                    assert_eq!(slot.taken(), granted);
                    assert_eq!(slot.remaining(), 3 - granted);
                    alerts += u32::from(slot.exhausts_the_day());
                }
                Err(TurnBudgetError::Exhausted { limit, taken }) => {
                    refusals += 1;
                    assert_eq!((limit, taken), (3, 3));
                }
                Err(other) => panic!("unexpected refusal: {other}"),
            }
        }

        assert_eq!(granted, 3, "the cap is the cap");
        assert_eq!(refusals, 7);
        assert_eq!(alerts, 1, "the operator is told once, not seven times");
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        // Rollover: a new UTC day is a fresh bucket, with no operator action
        // and no sweeper. The old day's record is untouched, because a
        // consumption ledger is not a gauge.
        let slot = reserve_committed(&db, tenant, employee, NEXT_DAY, &policy)
            .await
            .expect("tomorrow is a new day");
        assert_eq!(slot.taken(), 1);
        assert_eq!(slot.remaining(), 2);
        assert!(!slot.exhausts_the_day());
        assert_eq!(counted(&db, tenant, employee, NEXT_DAY).await, 1);
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// Two wakers, one slot left, hand-interleaved so the result does not
    /// depend on the scheduler.
    ///
    /// Against a `SELECT` without the lock, the second transaction reads the
    /// count as it stood before the first reservation, sees room, and the day
    /// ends at 4 turns against a cap of 3 — every single run. That is the whole
    /// bug, and it is the one an initiative loop with two replicas hits on its
    /// first afternoon.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_turns_cannot_both_take_the_last_slot() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "interleave").await;
        let policy = policy(3);

        // Two turns already taken, committed, so the bucket row exists. Without
        // this the two transactions below would race to *create* the row and
        // Postgres would serialise that on the primary key all by itself —
        // which would let a lock-free implementation pass for the wrong reason.
        for _ in 0..2 {
            reserve_committed(&db, tenant, employee, DAY, &policy)
                .await
                .expect("warm-up");
        }

        // The third turn: reserved, transaction left open exactly as it would
        // be while the model is being called next to it.
        let mut first = db.tenant_tx(tenant).await.expect("tenant tx");
        let slot = reserve(&mut first, employee, DAY, &policy)
            .await
            .expect("the last slot");
        assert!(slot.exhausts_the_day());

        // A second waker, concurrently. On its own merit the bucket still says
        // 2 of 3 — that is what makes the race work.
        let second = tokio::spawn({
            let db = db.clone();
            let policy = policy.clone();
            async move {
                let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
                let outcome = reserve(&mut tx, employee, DAY, &policy).await;
                // Commit either way: if the implementation wrongly granted it,
                // the damage must be visible in the bucket rather than rolled
                // back by a tidy test.
                tx.commit().await.expect("commit second");
                outcome
            }
        });

        // It must still be blocked. If `reserve` decided anything here it did
        // so from a bucket it had not locked.
        let mut second = std::pin::pin!(second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut second)
                .await
                .is_err(),
            "the second turn decided while the first held the bucket"
        );

        first.commit().await.expect("commit first");

        let outcome = second.await.expect("task panicked");
        assert!(
            matches!(
                outcome,
                Err(TurnBudgetError::Exhausted { limit: 3, taken: 3 })
            ),
            "the second turn must be refused, got {outcome:?}"
        );
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// A tenant's turns are its own. RLS, not a WHERE clause somebody adds.
    #[tokio::test]
    async fn one_tenants_turns_are_invisible_to_another() {
        let Some(db) = db().await else { return };
        let (tenant_a, employee_a) = seed(&db, "tenant-a").await;
        let (tenant_b, _) = seed(&db, "tenant-b").await;

        reserve_committed(&db, tenant_a, employee_a, DAY, &policy(5))
            .await
            .expect("a's turn");
        assert_eq!(counted(&db, tenant_a, employee_a, DAY).await, 1);
        // B asking about A's employee sees nothing at all.
        assert_eq!(counted(&db, tenant_b, employee_a, DAY).await, 0);

        drop_tenant(&db, tenant_a).await;
        drop_tenant(&db, tenant_b).await;
    }
}
