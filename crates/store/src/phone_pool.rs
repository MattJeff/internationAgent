//! Persistence for the shared number pool: `0010_phone_pool.sql` in Rust.
//!
//! The schema comment is the design document — read it first. What this module
//! adds is the two operations that have to be atomic and the two lookups that
//! decide who an inbound message reaches.
//!
//! # Why `allocate_atomic` is one statement
//!
//! A pool with one free slot and two employees provisioning at the same
//! instant is the normal case during onboarding, not a corner case. The claim
//! is therefore a single `FOR UPDATE SKIP LOCKED` statement over
//! `phone_numbers`, exactly like [`outbox::claim`](crate::outbox::claim) and
//! the release sweep: the loser skips the row its rival holds, finds no other
//! number with room, and is told the pool is full. It does not block, and it
//! does not take the slot.
//!
//! The occupancy count lives in no column. It is
//! `count(live allocations) < capacity`, evaluated under the row lock, so
//! there is nothing to drift out of sync with the allocations themselves. A
//! cached counter here would be a second copy of a fact that can only ever
//! disagree with the first.
//!
//! # Inbound routing
//!
//! [`resolve_inbound`] is the whole rule: affinity first, longest-standing
//! live allocation second. Both are total orders over immutable columns, so
//! the same inbound message routes to the same employee every time, on every
//! replica. Nothing here is decided by row order.
//!
//! [`touch_affinity`] returns the *incumbent*, which is not necessarily the
//! employee you passed in. That is the arbitration rule and it is the primary
//! key doing the work: whoever spoke to the counterparty first on that number
//! keeps them.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use agentos_domain::action::E164;
use agentos_domain::ids::EmployeeId;

use crate::db::{StoreError, TenantTx};

/// Rehydrate a number the database vouched for.
///
/// `phone_numbers_e164_shape` makes this unreachable in practice; when it does
/// fire, the row is corrupt and a decode error is the honest thing to say.
fn parse_e164(raw: &str) -> Result<E164, StoreError> {
    E164::parse(raw).map_err(|err| StoreError::Database(sqlx::Error::Decode(Box::new(err))))
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

/// Where a number is in its regulatory life.
///
/// Only [`NumberState::Active`] is allocatable, which is what keeps an
/// employee off a French number whose bundle is still with a human reviewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberState {
    /// Bought, or applied for, and not yet cleared to carry traffic.
    PendingRegulatory,
    /// Usable. The only state [`allocate_atomic`] will pick.
    Active,
    /// Temporarily out of the pool. Existing allocations survive; new ones do
    /// not land here. This is how you drain a number before releasing it.
    Suspended,
    /// Given back to the provider.
    Released,
}

impl NumberState {
    /// Stable storage spelling; matches `phone_numbers_state_check`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingRegulatory => "pending_regulatory",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Released => "released",
        }
    }

    /// Parse the column back. `None` means the database knows a state this
    /// build does not.
    pub fn parse(raw: &str) -> Option<Self> {
        [
            Self::PendingRegulatory,
            Self::Active,
            Self::Suspended,
            Self::Released,
        ]
        .into_iter()
        .find(|s| s.as_str() == raw)
    }
}

/// A number about to enter the tenant's pool.
///
/// `capacity` is the whole pooling/dedicated switch: `1` is a dedicated
/// number, which is the right answer where no regulatory bundle is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNumber {
    /// Provider name, as the adapter spells it.
    pub provider: String,
    /// The provider's own id for this number.
    pub external_id: String,
    /// The number itself.
    pub e164: E164,
    /// The provider crate's `Region`, as a string.
    pub region: String,
    /// Regulatory state at registration time.
    pub state: NumberState,
    /// How many employees may share it. Must be positive.
    pub capacity: i32,
    /// The regulatory bundle, where the region needs one.
    pub bundle_ref: Option<String>,
}

/// Put a number in the tenant's pool, or update the one already there.
///
/// Idempotent on `(tenant, e164)` — a provisioning worker that retries
/// registers the same number rather than a second row. The identity columns
/// (`provider`, `external_id`) are not rewritten on conflict: a number that
/// already exists under one provider id does not quietly become another's.
///
/// Returns the row id.
pub async fn register(
    tx: &mut TenantTx<'_>,
    number: &NewNumber,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    let tenant = tx.tenant_id();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO phone_numbers \
             (id, tenant_id, provider, external_id, e164, region, state, capacity, \
              bundle_ref, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10) \
         ON CONFLICT (tenant_id, e164) DO UPDATE \
             SET state = excluded.state, \
                 capacity = excluded.capacity, \
                 bundle_ref = coalesce(excluded.bundle_ref, phone_numbers.bundle_ref), \
                 updated_at = excluded.updated_at \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(&number.provider)
    .bind(&number.external_id)
    .bind(number.e164.as_str())
    .bind(&number.region)
    .bind(number.state.as_str())
    .bind(number.capacity)
    .bind(number.bundle_ref.as_deref())
    .bind(now)
    .fetch_one(&mut ***tx)
    .await?;
    Ok(id)
}

/// Move a number's regulatory state — a bundle clearing, a number being
/// drained before release.
///
/// [`StoreError::NotFound`] when no such number is visible to this tenant.
pub async fn set_state(
    tx: &mut TenantTx<'_>,
    number_id: Uuid,
    state: NumberState,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let updated = sqlx::query("UPDATE phone_numbers SET state = $2, updated_at = $3 WHERE id = $1")
        .bind(number_id)
        .bind(state.as_str())
        .bind(now)
        .execute(&mut ***tx)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

/// One employee's live seat on one pooled number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// Allocation row id.
    pub id: Uuid,
    /// The number allocated.
    pub number_id: Uuid,
    /// That number, for the outbound sender.
    pub e164: E164,
    /// Who holds it.
    pub employee_id: EmployeeId,
    /// Region the seat is in; the uniqueness scope.
    pub region: String,
    /// When the seat was taken. Immutable, and the first-contact tie-break.
    pub allocated_at: DateTime<Utc>,
}

/// Take a seat on any number in `region` that still has room.
///
/// `Ok(None)` means **the pool is full**: every active number in the region is
/// at capacity or is being claimed right now by someone else. It is not an
/// error — the caller buys another number or waits.
///
/// Already-allocated employees get their existing seat back, so a retrying
/// provisioning worker is idempotent. That pre-check is *not* the invariant:
/// two workers racing on one employee both pass it, and the partial unique
/// index `number_allocations_live_employee_region_key` is what makes exactly
/// one of them win. The loser sees [`StoreError::Conflict`] and retries into
/// the pre-check.
///
/// Numbers fill in `e164` order — lowest number first, packed tight. Any total
/// order would do; this one is deterministic and reproducible in a test.
//
// ponytail: best-fit packing (fullest-number-first) would leave whole numbers
// free for release. Nothing releases numbers yet, so lowest-first stays.
pub async fn allocate_atomic(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    region: &str,
    now: DateTime<Utc>,
) -> Result<Option<Allocation>, StoreError> {
    if let Some(existing) = current_allocation(tx, employee, region).await? {
        return Ok(Some(existing));
    }

    let tenant = tx.tenant_id();
    // One statement, and it has to be one: `pick` locks a number with room and
    // `ins` takes the seat inside the same lock. `SKIP LOCKED` is what turns a
    // concurrent claim on the last slot into "full" instead of a block-then-
    // overflow. Zero rows out of `pick` means zero rows inserted.
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, DateTime<Utc>)>(
        "WITH pick AS ( \
             SELECT n.id, n.e164 \
             FROM phone_numbers n \
             WHERE n.tenant_id = $1 AND n.region = $2 AND n.state = 'active' \
               AND (SELECT count(*) FROM number_allocations a \
                    WHERE a.number_id = n.id AND a.released_at IS NULL) < n.capacity \
             ORDER BY n.e164 \
             FOR UPDATE SKIP LOCKED \
             LIMIT 1 \
         ), ins AS ( \
             INSERT INTO number_allocations \
                 (id, tenant_id, number_id, employee_id, region, allocated_at) \
             SELECT $3, $1, pick.id, $4, $2, $5 FROM pick \
             RETURNING id, number_id, allocated_at \
         ) \
         SELECT ins.id, ins.number_id, pick.e164, ins.allocated_at \
         FROM ins JOIN pick ON pick.id = ins.number_id",
    )
    .bind(tenant.as_uuid())
    .bind(region)
    .bind(Uuid::now_v7())
    .bind(employee.as_uuid())
    .bind(now)
    .fetch_optional(&mut ***tx)
    .await?;

    row.map(|(id, number_id, e164, allocated_at)| {
        Ok(Allocation {
            id,
            number_id,
            e164: parse_e164(&e164)?,
            employee_id: employee,
            region: region.to_owned(),
            allocated_at,
        })
    })
    .transpose()
}

/// The seat this employee currently holds in `region`, if any.
pub async fn current_allocation(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    region: &str,
) -> Result<Option<Allocation>, StoreError> {
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, DateTime<Utc>)>(
        "SELECT a.id, a.number_id, n.e164, a.allocated_at \
         FROM number_allocations a JOIN phone_numbers n ON n.id = a.number_id \
         WHERE a.employee_id = $1 AND a.region = $2 AND a.released_at IS NULL",
    )
    .bind(employee.as_uuid())
    .bind(region)
    .fetch_optional(&mut ***tx)
    .await?;

    row.map(|(id, number_id, e164, allocated_at)| {
        Ok(Allocation {
            id,
            number_id,
            e164: parse_e164(&e164)?,
            employee_id: employee,
            region: region.to_owned(),
            allocated_at,
        })
    })
    .transpose()
}

/// Give the seat back. Returns the number that was freed, or `None` if the
/// employee held nothing in this region — releasing twice is not an error, for
/// the same reason `TelephonyProvider::release` tolerates a 404.
///
/// Affinity is deliberately left alone: the counterparties who know this
/// employee on that number keep reaching them, which is the point of the
/// affinity table outliving the allocation.
pub async fn release(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    region: &str,
    now: DateTime<Utc>,
) -> Result<Option<Uuid>, StoreError> {
    Ok(sqlx::query_scalar(
        "UPDATE number_allocations SET released_at = $3 \
         WHERE employee_id = $1 AND region = $2 AND released_at IS NULL \
         RETURNING number_id",
    )
    .bind(employee.as_uuid())
    .bind(region)
    .bind(now)
    .fetch_optional(&mut ***tx)
    .await?)
}

// ---------------------------------------------------------------------------
// Affinity and inbound routing
// ---------------------------------------------------------------------------

/// Record that `counterparty` spoke to `employee` on `number_id`, and return
/// **whoever actually owns that counterparty on that number**.
///
/// The returned id is the incumbent, which differs from `employee` exactly
/// when someone else got there first. Callers must route on the return value,
/// not on what they passed in: that is the arbitration rule, and the primary
/// key on `(tenant, number, counterparty)` is what enforces it. A later
/// contact only advances `last_seen`.
pub async fn touch_affinity(
    tx: &mut TenantTx<'_>,
    number_id: Uuid,
    counterparty: &str,
    employee: EmployeeId,
    now: DateTime<Utc>,
) -> Result<EmployeeId, StoreError> {
    let held: Uuid = sqlx::query_scalar(
        "INSERT INTO counterparty_affinity \
             (tenant_id, number_id, counterparty, employee_id, first_seen, last_seen) \
         VALUES ($1, $2, $3, $4, $5, $5) \
         ON CONFLICT (tenant_id, number_id, counterparty) DO UPDATE \
             SET last_seen = greatest(counterparty_affinity.last_seen, excluded.last_seen) \
         RETURNING employee_id",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(number_id)
    .bind(counterparty)
    .bind(employee.as_uuid())
    .bind(now)
    .fetch_one(&mut ***tx)
    .await?;
    Ok(EmployeeId::from_uuid(held))
}

/// Who an inbound message to `number` from `counterparty` belongs to.
///
/// 1. The incumbent, if this counterparty has used this number before. A
///    supplier who has been dealing with Lena keeps reaching Lena, because
///    Lena is where the trust links, expectations and dated beliefs about that
///    supplier live and a colleague has none of them.
/// 2. Otherwise the longest-standing live allocation on the number, ordered by
///    `(allocated_at, employee_id)` — both immutable, so first contact is
///    deterministic rather than "whichever row came back first".
///
/// `None` means the number is not ours or nobody is allocated to it; the
/// caller decides whether that is a 404 or a human's problem.
pub async fn resolve_inbound(
    tx: &mut TenantTx<'_>,
    number: &E164,
    counterparty: &str,
) -> Result<Option<EmployeeId>, StoreError> {
    // RLS scopes both queries to the tenant; there is no tenant predicate to
    // forget here because there is no way to run them outside `tenant_tx`.
    let incumbent: Option<Uuid> = sqlx::query_scalar(
        "SELECT c.employee_id FROM counterparty_affinity c \
         JOIN phone_numbers n ON n.id = c.number_id \
         WHERE n.e164 = $1 AND c.counterparty = $2",
    )
    .bind(number.as_str())
    .bind(counterparty)
    .fetch_optional(&mut ***tx)
    .await?;
    if let Some(id) = incumbent {
        return Ok(Some(EmployeeId::from_uuid(id)));
    }

    let first_contact: Option<Uuid> = sqlx::query_scalar(
        "SELECT a.employee_id FROM number_allocations a \
         JOIN phone_numbers n ON n.id = a.number_id \
         WHERE n.e164 = $1 AND a.released_at IS NULL \
         ORDER BY a.allocated_at, a.employee_id \
         LIMIT 1",
    )
    .bind(number.as_str())
    .fetch_optional(&mut ***tx)
    .await?;
    Ok(first_contact.map(EmployeeId::from_uuid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentos_domain::ids::TenantId;

    use crate::db::Db;

    const FR: &str = "FR";

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; phone_pool tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant plus `employees.len()` employees, committed.
    async fn seed(db: &Db, label: &str, employees: &[&str]) -> (TenantId, Vec<EmployeeId>) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("{label}-{}", tenant.as_uuid()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");

        let mut ids = Vec::new();
        for slug in employees {
            let id = EmployeeId::new_v7(Utc::now());
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 VALUES ($1, $2, $3, $4, 'active')",
            )
            .bind(id.as_uuid())
            .bind(tenant.as_uuid())
            .bind(slug)
            .bind(slug)
            .execute(&mut *tx)
            .await
            .expect("insert employee");
            ids.push(id);
        }
        tx.commit().await.expect("commit seed");
        (tenant, ids)
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

    /// A pooled number with a provider id nobody else in the database has —
    /// `phone_numbers_provider_external_id_key` is global, and these tests
    /// share a database with every previous run.
    fn pooled(digits: &str, capacity: i32) -> NewNumber {
        NewNumber {
            provider: "twilio".into(),
            external_id: format!("PN{digits}-{}", Uuid::now_v7()),
            e164: E164::parse(digits).expect("e164"),
            region: FR.into(),
            state: NumberState::Active,
            capacity,
            bundle_ref: Some("BU-fr-1".into()),
        }
    }

    /// Register one number in its own committed transaction.
    async fn add_number(db: &Db, tenant: TenantId, number: &NewNumber) -> Uuid {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let id = register(&mut tx, number, Utc::now())
            .await
            .expect("register");
        tx.commit().await.expect("commit");
        id
    }

    // -- the race ----------------------------------------------------------

    /// Two live transactions, one free slot. The point of the whole module.
    ///
    /// Interleaved rather than spawned: with `tokio::join!` the loser might
    /// simply arrive after the winner committed and lose for the boring
    /// reason. Holding the first transaction open forces the second to meet
    /// the row lock, which is the case `SKIP LOCKED` exists for.
    #[tokio::test]
    async fn one_free_slot_has_exactly_one_winner() {
        let Some(db) = db().await else { return };
        let (tenant, staff) = seed(&db, "race", &["lena", "alex"]).await;
        add_number(&db, tenant, &pooled("+33111111111", 1)).await;

        let mut first = db.tenant_tx(tenant).await.expect("tx");
        let won = allocate_atomic(&mut first, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("the only slot");

        // Second transaction, first one still open and holding the row.
        let mut second = db.tenant_tx(tenant).await.expect("tx");
        let lost = allocate_atomic(&mut second, staff[1], FR, Utc::now())
            .await
            .expect("allocate must not error");
        assert!(lost.is_none(), "the last slot must not be taken twice");
        second.rollback().await.expect("rollback");

        first.commit().await.expect("commit");

        // And once the winner has committed, the pool is genuinely full.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            allocate_atomic(&mut tx, staff[1], FR, Utc::now())
                .await
                .expect("allocate")
                .is_none()
        );
        let still = current_allocation(&mut tx, staff[0], FR)
            .await
            .expect("current")
            .expect("winner keeps the seat");
        assert_eq!(still.id, won.id);
        assert_eq!(still.e164.as_str(), "+33111111111");
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn allocation_is_idempotent_and_packs_by_number() {
        let Some(db) = db().await else { return };
        let (tenant, staff) = seed(&db, "pack", &["a", "b", "c", "d"]).await;
        add_number(&db, tenant, &pooled("+33222222222", 2)).await;
        add_number(&db, tenant, &pooled("+33111111111", 1)).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let mut seats = Vec::new();
        for who in &staff[..3] {
            seats.push(
                allocate_atomic(&mut tx, *who, FR, Utc::now())
                    .await
                    .expect("allocate")
                    .expect("room in the pool"),
            );
        }
        // Lowest number first, then the next one.
        assert_eq!(seats[0].e164.as_str(), "+33111111111");
        assert_eq!(seats[1].e164.as_str(), "+33222222222");
        assert_eq!(seats[2].e164.as_str(), "+33222222222");

        // Re-allocating an employee returns the seat it already has.
        let again = allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("same seat");
        assert_eq!(again.id, seats[0].id);

        // Three slots, four employees: the fourth is told the pool is full.
        assert!(
            allocate_atomic(&mut tx, staff[3], FR, Utc::now())
                .await
                .expect("allocate")
                .is_none()
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    // -- the index, not the application ------------------------------------

    #[tokio::test]
    async fn one_live_allocation_per_employee_per_region_is_enforced_by_the_index() {
        let Some(db) = db().await else { return };
        let (tenant, staff) = seed(&db, "unique", &["lena"]).await;
        let number = add_number(&db, tenant, &pooled("+33333333333", 5)).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat");

        // Straight past the pre-check, the way a racing worker would.
        let err: StoreError = sqlx::query(
            "INSERT INTO number_allocations \
                 (id, tenant_id, number_id, employee_id, region, allocated_at) \
             VALUES ($1, $2, $3, $4, $5, now())",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(number)
        .bind(staff[0].as_uuid())
        .bind(FR)
        .execute(&mut **tx)
        .await
        .expect_err("second live allocation must be refused")
        .into();
        match err {
            StoreError::Conflict(constraint) => assert_eq!(
                constraint, "number_allocations_live_employee_region_key",
                "the index must be what refuses it"
            ),
            other => panic!("expected Conflict, got {other:?}"),
        }
        tx.rollback().await.expect("rollback");

        // A released allocation does not occupy the index: allocate, release,
        // allocate again is legal.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let first = allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat");
        release(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("release")
            .expect("freed a number");
        let second = allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat again");
        assert_ne!(first.id, second.id);
        tx.commit().await.expect("commit");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn release_frees_the_slot_for_someone_else() {
        let Some(db) = db().await else { return };
        let (tenant, staff) = seed(&db, "reuse", &["lena", "alex"]).await;
        add_number(&db, tenant, &pooled("+33444444444", 1)).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat");
        assert!(
            allocate_atomic(&mut tx, staff[1], FR, Utc::now())
                .await
                .expect("allocate")
                .is_none(),
            "pool is full"
        );

        release(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("release")
            .expect("freed");
        // Releasing again is a no-op, not an error.
        assert!(
            release(&mut tx, staff[0], FR, Utc::now())
                .await
                .expect("release")
                .is_none()
        );

        assert!(
            allocate_atomic(&mut tx, staff[1], FR, Utc::now())
                .await
                .expect("allocate")
                .is_some(),
            "the freed slot must be reusable"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    // -- routing -----------------------------------------------------------

    #[tokio::test]
    async fn inbound_prefers_affinity_then_the_oldest_allocation() {
        let Some(db) = db().await else { return };
        let (tenant, staff) = seed(&db, "route", &["lena", "alex"]).await;
        let shared = E164::parse("+33555555555").expect("e164");
        let number = add_number(&db, tenant, &pooled("+33555555555", 5)).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let lena = allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat");
        allocate_atomic(&mut tx, staff[1], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat");
        assert_eq!(lena.number_id, number);

        // First contact from an unknown supplier: the longest-standing
        // allocation, which is Lena.
        assert_eq!(
            resolve_inbound(&mut tx, &shared, "supplier-x")
                .await
                .expect("resolve"),
            Some(staff[0])
        );

        // Alex answers a different supplier and becomes its incumbent.
        let held = touch_affinity(&mut tx, number, "supplier-y", staff[1], Utc::now())
            .await
            .expect("affinity");
        assert_eq!(held, staff[1]);
        assert_eq!(
            resolve_inbound(&mut tx, &shared, "supplier-y")
                .await
                .expect("resolve"),
            Some(staff[1]),
            "affinity must beat the first-contact rule"
        );

        // Lena tries to take supplier-y over. The incumbent wins, and says so.
        let held = touch_affinity(&mut tx, number, "supplier-y", staff[0], Utc::now())
            .await
            .expect("affinity");
        assert_eq!(held, staff[1], "whoever spoke first keeps the counterparty");
        assert_eq!(
            resolve_inbound(&mut tx, &shared, "supplier-y")
                .await
                .expect("resolve"),
            Some(staff[1])
        );

        // A number nobody owns routes nowhere.
        assert_eq!(
            resolve_inbound(
                &mut tx,
                &E164::parse("+33999999999").expect("e164"),
                "supplier-x"
            )
            .await
            .expect("resolve"),
            None
        );
        tx.commit().await.expect("commit");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn affinity_survives_reallocation_to_another_number() {
        let Some(db) = db().await else { return };
        let (tenant, staff) = seed(&db, "moved", &["lena"]).await;
        let old = E164::parse("+33666666666").expect("e164");
        let old_id = add_number(&db, tenant, &pooled("+33666666666", 1)).await;
        add_number(&db, tenant, &pooled("+33777777777", 1)).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let seat = allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat");
        assert_eq!(seat.number_id, old_id);
        touch_affinity(&mut tx, old_id, "supplier-z", staff[0], Utc::now())
            .await
            .expect("affinity");

        // Move Lena to the other number: release, take the old one out of the
        // pool, allocate again.
        release(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("release")
            .expect("freed");
        set_state(&mut tx, old_id, NumberState::Suspended, Utc::now())
            .await
            .expect("suspend");
        let moved = allocate_atomic(&mut tx, staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("new seat");
        assert_eq!(moved.e164.as_str(), "+33777777777");

        // The supplier who knows the old number still reaches Lena, even
        // though nobody is allocated to that number any more.
        assert_eq!(
            resolve_inbound(&mut tx, &old, "supplier-z")
                .await
                .expect("resolve"),
            Some(staff[0]),
            "affinity is the relationship memory; re-allocation must not erase it"
        );
        // ...and without affinity that same number routes nowhere.
        assert_eq!(
            resolve_inbound(&mut tx, &old, "supplier-unknown")
                .await
                .expect("resolve"),
            None
        );
        tx.commit().await.expect("commit");

        drop_tenant(&db, tenant).await;
    }

    // -- isolation ---------------------------------------------------------

    #[tokio::test]
    async fn tenants_cannot_see_each_others_pool() {
        let Some(db) = db().await else { return };
        let (a, a_staff) = seed(&db, "iso-a", &["lena"]).await;
        let (b, _) = seed(&db, "iso-b", &["alex"]).await;
        let shared = E164::parse("+33888888888").expect("e164");

        let a_pooled = pooled("+33888888888", 2);
        let a_number = add_number(&db, a, &a_pooled).await;
        let mut tx = db.tenant_tx(a).await.expect("tx");
        allocate_atomic(&mut tx, a_staff[0], FR, Utc::now())
            .await
            .expect("allocate")
            .expect("seat");
        touch_affinity(&mut tx, a_number, "supplier-a", a_staff[0], Utc::now())
            .await
            .expect("affinity");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(b).await.expect("tx");
        for sql in [
            "SELECT count(*) FROM phone_numbers",
            "SELECT count(*) FROM number_allocations",
            "SELECT count(*) FROM counterparty_affinity",
        ] {
            let seen: i64 = sqlx::query_scalar(sql)
                .fetch_one(&mut **tx)
                .await
                .expect("count");
            assert_eq!(seen, 0, "tenant B must not see A's rows: {sql}");
        }
        // Not by primary key either, and not through the routing entry points.
        assert_eq!(
            resolve_inbound(&mut tx, &shared, "supplier-a")
                .await
                .expect("resolve"),
            None,
            "an inbound to A's number must not route to anyone in B"
        );
        assert!(matches!(
            set_state(&mut tx, a_number, NumberState::Released, Utc::now()).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");

        // The same external resource must not be bindable twice, and "twice"
        // includes across tenants: B cannot register A's provider id.
        let mut tx = db.tenant_tx(b).await.expect("tx");
        let err = register(&mut tx, &a_pooled, Utc::now())
            .await
            .expect_err("stealing a provider id must fail");
        match err {
            StoreError::Conflict(constraint) => {
                assert_eq!(constraint, "phone_numbers_provider_external_id_key");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        tx.rollback().await.expect("rollback");

        // A different provider id on the same E.164 is fine, though: the
        // number itself is unique per tenant, not globally.
        let b_number = add_number(&db, b, &pooled("+33888888888", 1)).await;
        assert_ne!(a_number, b_number);

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }
}
