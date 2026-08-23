//! Daily spend caps that are **reserved**, not merely checked.
//!
//! A cap that is read, compared and then acted on is not a cap. Ten concurrent
//! requests all read "nothing spent yet", all decide they are under the limit,
//! and all pay — which is exactly how an agent structures one large payment
//! into many small ones that each pass on their individual merit. Nothing in
//! the logs looks wrong; every individual decision was correct.
//!
//! So the headroom is consumed under a row lock, in the caller's transaction:
//!
//! ```text
//! caller BEGIN
//!   reserve(..)  ── locks the (tenant, employee, day, currency) bucket row,
//!                   re-reads the running total under that lock, and writes the
//!                   new total before releasing it
//!   insert the payment intent
//! caller COMMIT   ── reservation and payment become visible together
//! ```
//!
//! Because [`reserve`] takes `&mut TenantTx` rather than a pool, it cannot be
//! called outside a transaction, and the lock it takes is held until the caller
//! commits. A crash between the reservation and the payment rolls back both.
//!
//! Three caps, all per currency, because a limit denominated in USD says
//! nothing about a payment in JPY:
//!
//! * **per transaction** — how big any single payment may be;
//! * **daily total** — how much may be reserved in a day;
//! * **daily count** — how many payments may be made in a day, which is the one
//!   that actually stops structuring.
//!
//! No caps row means no spending. Absence fails closed.

use std::num::NonZeroU32;

use agentos_domain::ids::EmployeeId;
use agentos_domain::money::{Currency, Money, MoneyError};
use chrono::NaiveDate;
use thiserror::Error;
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

/// What an employee may spend in one day, in one currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendCaps {
    daily_total: Money,
    per_transaction: Money,
    daily_transactions: NonZeroU32,
}

impl SpendCaps {
    /// Both limits must be in the same currency — that currency is what the
    /// caps are keyed on, and a daily total in EUR guarding a per-transaction
    /// max in USD is a cap that means nothing.
    ///
    /// The count is a [`NonZeroU32`] so "zero transactions allowed" has no
    /// spelling; the way to forbid spending is to have no caps row.
    pub fn new(
        daily_total: Money,
        per_transaction: Money,
        daily_transactions: NonZeroU32,
    ) -> Result<Self, MoneyError> {
        if daily_total.currency() != per_transaction.currency() {
            return Err(MoneyError::CurrencyMismatch {
                left: daily_total.currency(),
                right: per_transaction.currency(),
            });
        }
        Ok(Self {
            daily_total,
            per_transaction,
            daily_transactions,
        })
    }

    /// Ceiling on everything reserved in one day.
    pub const fn daily_total(&self) -> Money {
        self.daily_total
    }

    /// Ceiling on any one payment.
    pub const fn per_transaction(&self) -> Money {
        self.per_transaction
    }

    /// Ceiling on how many payments may be made in one day.
    pub const fn daily_transactions(&self) -> NonZeroU32 {
        self.daily_transactions
    }

    /// The currency these caps are denominated in.
    pub const fn currency(&self) -> Currency {
        self.daily_total.currency()
    }
}

/// Headroom that has been taken out of a daily bucket and is now spoken for.
///
/// Holding one of these is what authorises the payment. It stays consumed until
/// somebody [`release`]s it; there is no expiry, because a reservation that
/// times out on its own is a reservation that frees a cap while the payment it
/// authorised may still be in flight at the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    id: Uuid,
    employee_id: EmployeeId,
    day: NaiveDate,
    amount: Money,
}

impl Reservation {
    /// Ledger row id.
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Who is spending.
    pub const fn employee_id(&self) -> EmployeeId {
        self.employee_id
    }

    /// The day whose bucket this came out of.
    pub const fn day(&self) -> NaiveDate {
        self.day
    }

    /// How much is spoken for.
    pub const fn amount(&self) -> Money {
        self.amount
    }
}

/// Why a reservation was refused.
///
/// Every variant is a refusal the caller must act on — there is no "warn and
/// continue" arm, because a cap that only logs is not a cap.
#[derive(Debug, Error)]
pub enum CapExceeded {
    /// No caps are configured for this employee and currency, so it may not
    /// spend. Fails closed by design.
    #[error("no spend caps configured for {currency}")]
    NoCaps {
        /// The currency that has no caps row.
        currency: Currency,
    },

    /// One payment larger than the per-transaction ceiling.
    #[error("{requested} exceeds the per-transaction maximum of {max}")]
    PerTransaction {
        /// What was asked for.
        requested: Money,
        /// The ceiling.
        max: Money,
    },

    /// The day's remaining headroom is smaller than the request. The amount
    /// already reserved is deliberately not in the message: it is the one
    /// number that tells a caller how to structure the next attempt.
    #[error("{requested} would exceed the daily limit of {limit}")]
    DailyTotal {
        /// What was asked for.
        requested: Money,
        /// The day's ceiling.
        limit: Money,
    },

    /// The day's transaction count is used up. The cap that stops a large
    /// payment from being sliced into many small legal ones.
    #[error("daily limit of {limit} transactions is already used up")]
    DailyCount {
        /// The ceiling.
        limit: NonZeroU32,
    },

    /// The database said no.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for CapExceeded {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

/// Install or replace the caps for one employee and currency.
///
/// Upsert, so re-running provisioning is not an error. Lowering a cap does not
/// claw back what is already reserved today; it only constrains what happens
/// next.
pub async fn set_caps(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    caps: SpendCaps,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO spend_caps \
           (tenant_id, employee_id, currency, daily_total_minor, \
            per_transaction_minor, daily_transaction_count) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (tenant_id, employee_id, currency) DO UPDATE SET \
           daily_total_minor = excluded.daily_total_minor, \
           per_transaction_minor = excluded.per_transaction_minor, \
           daily_transaction_count = excluded.daily_transaction_count, \
           updated_at = now()",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id.as_uuid())
    .bind(caps.currency().code())
    .bind(clamp_i64(caps.daily_total.minor()))
    .bind(clamp_i64(caps.per_transaction.minor()))
    .bind(i64::from(caps.daily_transactions.get()))
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// Consume `amount` of today's headroom, or refuse.
///
/// Call this in the same transaction that writes the payment intent. The
/// bucket row is locked for the rest of that transaction, so between the check
/// and the write nobody else can reserve against the same day.
///
/// The tenant is not a parameter: it comes from `tx`, which is the only thing
/// row-level security will honour anyway. Passing it separately would only
/// create a way for the two to disagree. The currency likewise comes from
/// `amount`, so a cross-currency reservation cannot be spelled.
pub async fn reserve(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
    amount: Money,
) -> Result<Reservation, CapExceeded> {
    let tenant = tx.tenant_id().as_uuid();
    let currency = amount.currency();

    // Caps first, before any row is created: an employee with no caps must not
    // leave a bucket row behind as a side effect of being refused.
    let Some(caps) = caps(tx, employee_id, currency).await? else {
        return Err(CapExceeded::NoCaps { currency });
    };

    if amount.minor() > caps.per_transaction.minor() {
        return Err(CapExceeded::PerTransaction {
            requested: amount,
            max: caps.per_transaction,
        });
    }

    // Create-if-missing *and* lock, in one statement. `DO UPDATE` with a no-op
    // assignment is what makes it a lock: `DO NOTHING` would return no row for
    // a concurrent inserter and take no lock, which is precisely the race this
    // module exists to close. RETURNING then yields the values as of the lock.
    let (reserved, count): (i64, i32) = sqlx::query_as(
        "INSERT INTO spend_buckets (tenant_id, employee_id, day, currency) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, employee_id, day, currency) DO UPDATE SET \
           reserved_minor = spend_buckets.reserved_minor \
         RETURNING reserved_minor, txn_count",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .bind(currency.code())
    .fetch_one(&mut ***tx)
    .await?;

    // -- everything from here to COMMIT runs under that row lock --

    if u32::try_from(count).unwrap_or(u32::MAX) >= caps.daily_transactions.get() {
        return Err(CapExceeded::DailyCount {
            limit: caps.daily_transactions,
        });
    }

    let would_total = nonneg(reserved).checked_add(amount.minor());
    if would_total.is_none_or(|total| total > caps.daily_total.minor()) {
        return Err(CapExceeded::DailyTotal {
            requested: amount,
            limit: caps.daily_total,
        });
    }

    sqlx::query(
        "UPDATE spend_buckets SET \
           reserved_minor = reserved_minor + $5, \
           txn_count = txn_count + 1, \
           updated_at = now() \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3 AND currency = $4",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .bind(currency.code())
    .bind(clamp_i64(amount.minor()))
    .execute(&mut ***tx)
    .await?;

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO spend_reservations \
           (id, tenant_id, employee_id, day, currency, amount_minor) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .bind(currency.code())
    .bind(clamp_i64(amount.minor()))
    .execute(&mut ***tx)
    .await?;

    Ok(Reservation {
        id,
        employee_id,
        day,
        amount,
    })
}

/// Give the headroom back, for a payment that failed downstream.
///
/// Refuses a second time with [`StoreError::Conflict`]: the state flip and the
/// bucket decrement are one transaction, so a replayed release cannot hand back
/// headroom twice. (The bucket's non-negative CHECK is the backstop if it ever
/// somehow does.)
pub async fn release(tx: &mut TenantTx<'_>, reservation: &Reservation) -> Result<(), StoreError> {
    finish(tx, reservation, "released").await?;

    sqlx::query(
        "UPDATE spend_buckets SET \
           reserved_minor = reserved_minor - $5, \
           txn_count = txn_count - 1, \
           updated_at = now() \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3 AND currency = $4",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(reservation.employee_id.as_uuid())
    .bind(reservation.day)
    .bind(reservation.amount.currency().code())
    .bind(clamp_i64(reservation.amount.minor()))
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// Mark the payment as actually made.
///
/// Deliberately leaves the bucket alone: money that was spent stays spent
/// against the day's cap. Settling is bookkeeping, not headroom.
pub async fn settle(tx: &mut TenantTx<'_>, reservation: &Reservation) -> Result<(), StoreError> {
    finish(tx, reservation, "settled").await
}

/// Flip a reservation out of `reserved` exactly once.
async fn finish(
    tx: &mut TenantTx<'_>,
    reservation: &Reservation,
    state: &str,
) -> Result<(), StoreError> {
    let done = sqlx::query(
        "UPDATE spend_reservations SET state = $2, updated_at = now() \
         WHERE id = $1 AND state = 'reserved'",
    )
    .bind(reservation.id)
    .bind(state)
    .execute(&mut ***tx)
    .await?
    .rows_affected();

    if done == 0 {
        return Err(StoreError::conflict(format!(
            "spend_reservations {} is not reserved",
            reservation.id
        )));
    }
    Ok(())
}

/// Read the caps for one employee and currency, if any are configured.
pub async fn caps(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    currency: Currency,
) -> Result<Option<SpendCaps>, StoreError> {
    let row: Option<(i64, i64, i32)> = sqlx::query_as(
        "SELECT daily_total_minor, per_transaction_minor, daily_transaction_count \
         FROM spend_caps \
         WHERE tenant_id = $1 AND employee_id = $2 AND currency = $3",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id.as_uuid())
    .bind(currency.code())
    .fetch_optional(&mut ***tx)
    .await?;

    // Every `expect` below is guarded by `spend_caps_positive` in 0003_spend.
    Ok(row.map(|(total, per_txn, count)| SpendCaps {
        daily_total: Money::new(nonneg(total), currency).expect("CHECK daily_total_minor > 0"),
        per_transaction: Money::new(nonneg(per_txn), currency)
            .expect("CHECK per_transaction_minor > 0"),
        daily_transactions: NonZeroU32::new(u32::try_from(count).unwrap_or(u32::MAX))
            .expect("CHECK daily_transaction_count > 0"),
    }))
}

/// Postgres `bigint` is signed and every column here is CHECKed non-negative,
/// so this only ever un-does the signedness. A negative would mean a corrupt
/// row, and clamping it to zero fails closed rather than wrapping to 1.8e19.
fn nonneg(v: i64) -> u64 {
    v.max(0) as u64
}

/// `Money` counts in `u64`, Postgres in `i64`. Saturating a *limit* downwards
/// makes it stricter, never laxer, so this cannot widen a cap.
fn clamp_i64(minor: u64) -> i64 {
    i64::try_from(minor).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use agentos_domain::ids::TenantId;
    use agentos_domain::money::Currency::{Eur, Usd};
    use chrono::Utc;

    use super::*;
    use crate::db::Db;

    const DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 23) {
        Some(d) => d,
        None => panic!("valid date"),
    };

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the spend ledger needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A committed tenant + employee. Torn down by `drop_tenant`, which
    /// cascades through every spend table.
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

    fn usd(minor: u64) -> Money {
        Money::new(minor, Usd).expect("positive")
    }

    fn count(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).expect("positive")
    }

    /// The committed state of a bucket, read straight out of the table.
    async fn bucket(db: &Db, tenant: TenantId, employee: EmployeeId) -> (i64, i32) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let row = sqlx::query_as(
            "SELECT reserved_minor, txn_count FROM spend_buckets \
             WHERE tenant_id = $1 AND employee_id = $2 AND day = $3 AND currency = 'USD'",
        )
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid())
        .bind(DAY)
        .fetch_optional(&mut **tx)
        .await
        .expect("read bucket");
        tx.rollback().await.expect("rollback");
        row.unwrap_or((0, 0))
    }

    /// Reserve in its own committed transaction, the way a caller would.
    async fn reserve_committed(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        amount: Money,
    ) -> Result<Reservation, CapExceeded> {
        let mut tx = db.tenant_tx(tenant).await?;
        let outcome = reserve(&mut tx, employee, DAY, amount).await;
        match outcome {
            Ok(r) => {
                tx.commit().await?;
                Ok(r)
            }
            Err(e) => {
                tx.rollback().await?;
                Err(e)
            }
        }
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn spending_without_caps_is_refused() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "nocaps").await;

        let err = reserve_committed(&db, tenant, employee, usd(1))
            .await
            .expect_err("no caps means no spending");
        assert!(
            matches!(err, CapExceeded::NoCaps { currency: Usd }),
            "{err}"
        );

        // ...and being refused left no bucket row behind.
        assert_eq!(bucket(&db, tenant, employee).await, (0, 0));

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn each_cap_refuses_on_its_own_terms_and_currencies_do_not_share() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "caps").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set_caps(
            &mut tx,
            employee,
            SpendCaps::new(usd(10_000), usd(4_000), count(3)).unwrap(),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit caps");

        // Round-trips.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let stored = caps(&mut tx, employee, Usd).await.expect("read").unwrap();
        assert_eq!(stored.daily_total(), usd(10_000));
        assert_eq!(stored.per_transaction(), usd(4_000));
        assert_eq!(stored.daily_transactions(), count(3));
        // Caps are per currency: EUR has none, so EUR cannot be spent.
        assert!(caps(&mut tx, employee, Eur).await.expect("read").is_none());
        tx.rollback().await.expect("rollback");

        // Too big for one transaction, even though it fits in the day.
        let err = reserve_committed(&db, tenant, employee, usd(4_001))
            .await
            .expect_err("over per-transaction max");
        assert!(matches!(err, CapExceeded::PerTransaction { .. }), "{err}");

        // Two legal ones fit; the third pushes the daily total over.
        reserve_committed(&db, tenant, employee, usd(4_000))
            .await
            .expect("first");
        reserve_committed(&db, tenant, employee, usd(4_000))
            .await
            .expect("second");
        let err = reserve_committed(&db, tenant, employee, usd(4_000))
            .await
            .expect_err("over daily total");
        assert!(matches!(err, CapExceeded::DailyTotal { .. }), "{err}");
        assert_eq!(bucket(&db, tenant, employee).await, (8_000, 2));

        // A payment in another currency is not covered by the USD caps.
        let err = reserve_committed(&db, tenant, employee, Money::new(100, Eur).unwrap())
            .await
            .expect_err("EUR has no caps");
        assert!(
            matches!(err, CapExceeded::NoCaps { currency: Eur }),
            "{err}"
        );

        // Now the count cap, in isolation: raise the total so only the count
        // can bite, and confirm the third small payment is refused for being
        // the third rather than for being too much.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set_caps(
            &mut tx,
            employee,
            SpendCaps::new(usd(1_000_000), usd(4_000), count(3)).unwrap(),
        )
        .await
        .expect("raise caps");
        tx.commit().await.expect("commit caps");

        reserve_committed(&db, tenant, employee, usd(1))
            .await
            .expect("third");
        let err = reserve_committed(&db, tenant, employee, usd(1))
            .await
            .expect_err("over daily count");
        assert!(matches!(err, CapExceeded::DailyCount { .. }), "{err}");
        assert_eq!(bucket(&db, tenant, employee).await, (8_001, 3));

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn release_gives_headroom_back_once_and_settle_never_does() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "release").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set_caps(
            &mut tx,
            employee,
            SpendCaps::new(usd(10_000), usd(10_000), count(5)).unwrap(),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit caps");

        let a = reserve_committed(&db, tenant, employee, usd(6_000))
            .await
            .expect("a");
        let b = reserve_committed(&db, tenant, employee, usd(4_000))
            .await
            .expect("b");
        assert_eq!(bucket(&db, tenant, employee).await, (10_000, 2));

        // The day is full.
        assert!(
            reserve_committed(&db, tenant, employee, usd(1))
                .await
                .is_err()
        );

        // `a`'s payment failed at the provider: give it back.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        release(&mut tx, &a).await.expect("release");
        tx.commit().await.expect("commit release");
        assert_eq!(bucket(&db, tenant, employee).await, (4_000, 1));

        // Replaying the release must not hand back the headroom a second time.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = release(&mut tx, &a).await.expect_err("double release");
        assert!(matches!(err, StoreError::Conflict(_)), "{err}");
        tx.rollback().await.expect("rollback");
        assert_eq!(bucket(&db, tenant, employee).await, (4_000, 1));

        // Settling `b` is bookkeeping only: spent money stays spent.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        settle(&mut tx, &b).await.expect("settle");
        tx.commit().await.expect("commit settle");
        assert_eq!(bucket(&db, tenant, employee).await, (4_000, 1));

        // And a settled reservation can no longer be released.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert!(release(&mut tx, &b).await.is_err());
        tx.rollback().await.expect("rollback");
        assert_eq!(bucket(&db, tenant, employee).await, (4_000, 1));

        drop_tenant(&db, tenant).await;
    }

    /// The same attack as the storm below, but hand-interleaved so the result
    /// does not depend on the scheduler.
    ///
    /// A thousand-task storm is a probabilistic test: a check-then-act
    /// implementation only over-grants when two reads land in the same window,
    /// and on a fast machine with a small pool they often do not. This one
    /// forces the window open. Two transactions each reserve 6,000 against a
    /// 10,000 daily cap; the second must be refused, and it must be refused
    /// *because* it could not read the bucket until the first committed.
    ///
    /// Against a `SELECT` without `FOR UPDATE`, the second transaction reads
    /// the total as it stood before the first reservation, decides 6,000 fits,
    /// and the day ends at 13,000 against a 10,000 cap — every single run.
    /// That is the whole bug.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_reservation_cannot_decide_while_the_first_holds_the_bucket() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "interleave").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set_caps(
            &mut tx,
            employee,
            SpendCaps::new(usd(10_000), usd(6_000), count(9)).unwrap(),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit caps");

        // One small committed payment first, so the day's bucket already
        // exists. Without it the two transactions below would be racing to
        // *create* the row, and Postgres serialises that on the unique index
        // all by itself — which would let a lock-free implementation pass for
        // the wrong reason. The interesting case is the second payment of the
        // day onwards, and that is what this sets up.
        reserve_committed(&db, tenant, employee, usd(1_000))
            .await
            .expect("warm-up");

        // First payment: reserved, but the transaction stays open, exactly as
        // it would while the payment intent is being written next to it.
        let mut first = db.tenant_tx(tenant).await.expect("tenant tx");
        reserve(&mut first, employee, DAY, usd(6_000))
            .await
            .expect("first reservation");

        // Second payment, concurrently. On its own merit 6,000 is a perfectly
        // legal payment — that is what makes structuring work.
        let second = tokio::spawn({
            let db = db.clone();
            async move {
                let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
                let outcome = reserve(&mut tx, employee, DAY, usd(6_000)).await;
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
            "the second reservation completed while the first held the bucket"
        );

        first.commit().await.expect("commit first");

        let outcome = second.await.expect("task panicked");
        assert!(
            matches!(outcome, Err(CapExceeded::DailyTotal { .. })),
            "second reservation must be refused, got {outcome:?}"
        );
        assert_eq!(bucket(&db, tenant, employee).await, (7_000, 2));

        drop_tenant(&db, tenant).await;
    }

    /// The test this module exists for.
    ///
    /// 1000 concurrent reservations of 9,999 against a 200,000/day cap. The
    /// arithmetic is exact: 20 × 9,999 = 199,980 fits, and a 21st would be
    /// 209,979. So the only correct outcome is 20 winners and 980 refusals.
    ///
    /// Every task runs its own transaction against the real database, so the
    /// contention is real — and because a storm that happened to serialise
    /// would pass for a broken implementation too, the test measures how many
    /// reservations were genuinely in flight at once and fails if they were
    /// not actually racing. A green result that proves nothing is worse than a
    /// red one. Even so, a storm is probabilistic; the deterministic proof that
    /// the bucket is genuinely locked is the test above.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_thousand_concurrent_reservations_cannot_structure_past_the_cap() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "race").await;

        const ATTEMPTS: usize = 1000;
        const AMOUNT: u64 = 9_999;
        const DAILY: u64 = 200_000;
        const WINNERS: usize = (DAILY / AMOUNT) as usize; // 20

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set_caps(
            &mut tx,
            employee,
            // The count cap is deliberately far out of reach: this test is
            // about the total, and a count refusal would mask it.
            SpendCaps::new(usd(DAILY), usd(AMOUNT), count(ATTEMPTS as u32 * 2)).unwrap(),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit caps");

        let db = Arc::new(db);
        let tasks: Vec<_> = (0..ATTEMPTS)
            .map(|_| {
                let db = Arc::clone(&db);
                tokio::spawn(async move {
                    // A transaction per task, exactly as a real caller has.
                    // Timed from the moment the transaction exists, so the
                    // window measured is the one where the row lock is held —
                    // not the time spent queueing for a pool connection.
                    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
                    let start = Instant::now();
                    let outcome = reserve(&mut tx, employee, DAY, usd(AMOUNT)).await;
                    let ok = match outcome {
                        Ok(_) => {
                            tx.commit().await.expect("commit");
                            true
                        }
                        Err(CapExceeded::DailyTotal { .. }) => {
                            tx.rollback().await.expect("rollback");
                            false
                        }
                        Err(other) => panic!("unexpected refusal: {other}"),
                    };
                    (ok, start, Instant::now())
                })
            })
            .collect();

        let mut granted = 0usize;
        let mut spans = Vec::with_capacity(ATTEMPTS);
        for task in tasks {
            let (ok, start, end) = task.await.expect("task panicked");
            granted += usize::from(ok);
            spans.push((start, end));
        }

        // Did they actually race? Sweep the [start, end) intervals and take the
        // deepest overlap. If this is 1, every reservation ran alone and the
        // assertions below would hold for a broken implementation too.
        let mut events: Vec<(Instant, i32)> = Vec::with_capacity(ATTEMPTS * 2);
        for (start, end) in spans {
            events.push((start, 1));
            events.push((end, -1));
        }
        events.sort();
        let (mut depth, mut peak) = (0, 0);
        for (_, delta) in events {
            depth += delta;
            peak = peak.max(depth);
        }
        assert!(
            peak >= 8,
            "reservations serialised (peak concurrency {peak}); this test proves nothing"
        );

        // The invariant. Not "roughly 20", not "we logged the overage": the
        // committed total is under the cap and the winners are exact.
        let (reserved, txns) = bucket(&db, tenant, employee).await;
        assert_eq!(granted, WINNERS, "peak concurrency was {peak}");
        assert_eq!(txns as usize, WINNERS);
        assert_eq!(reserved as u64, AMOUNT * WINNERS as u64);
        assert!(
            (reserved as u64) <= DAILY,
            "reserved {reserved} exceeds the daily cap of {DAILY}"
        );

        // The 980 refusals wrote nothing: one ledger row per winner, no more.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM spend_reservations \
             WHERE employee_id = $1 AND state = 'reserved'",
        )
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("count reservations");
        tx.rollback().await.expect("rollback");
        assert_eq!(rows as usize, WINNERS);

        drop_tenant(&db, tenant).await;
    }
}
