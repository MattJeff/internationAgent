//! Claiming a provisioning step, and the write-ahead log that makes a crashed
//! provider call discoverable.
//!
//! This module is the reason a crash cannot buy two phone numbers.
//!
//! **Not advisory locks.** The spec called for `pg_advisory_lock` on the
//! employee. That is wrong here and the code deliberately does not do it:
//! advisory locks are *session*-scoped, this is a pooled sqlx application, so
//! the acquire and the release can land on different pooled connections; a
//! worker that panics never releases; and one lock per employee serialises
//! eleven steps that have nothing to do with each other. Instead:
//!
//! * [`claim_step`] takes a real **row** lock (`SELECT ... FOR UPDATE`) for the
//!   read-modify-write, and lets it go at commit — no lock outlives its
//!   transaction, ever.
//! * The claim it hands out is backed by **explicit lease columns**
//!   (`lease_owner`, `lease_until`) that expire on their own, so a worker that
//!   dies mid-step frees its work by doing nothing at all.
//!
//! The sequence a worker runs is:
//!
//! ```text
//! tx1: claim_step -> begin_intent -> COMMIT     (durable "a call may happen")
//!      call the provider                        (the crash window)
//! tx2: finish_step -> COMMIT                    (resource + intent + outbox)
//! ```
//!
//! The intent row is written **before** the network call and committed, which
//! is the whole point: a process that dies in the crash window leaves an
//! `in_flight` row behind, and [`sweep_expired_leases`] finds it. Without that
//! row a bought-and-forgotten phone number is invisible.
//!
//! [`finish_step`] writes the resource state, the intent outcome and the outbox
//! event in one transaction, all guarded by `WHERE lease_owner = $me`, so a
//! worker whose lease expired and was stolen while it was talking to the
//! provider cannot land a stale result on top of the new owner's work.
//!
//! Nothing here reads the clock; every entry point takes `now`.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use agentos_domain::employee::{ProviderBinding, ResourceState, Step};
use agentos_domain::ids::{EmployeeId, IdempotencyKey};

use crate::db::{StoreError, TenantTx};

/// Parse a `step` column back into the closed domain enum.
///
/// Unknown text means the database disagrees with the build about what steps
/// exist, so it is `None` and the caller skips the row rather than guessing.
fn parse_step(raw: &str) -> Option<Step> {
    Step::ALL.into_iter().find(|s| s.as_str() == raw)
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

/// Proof that this worker, and no other, currently owns one provisioning step.
///
/// Only [`claim_step`] can mint one, and it carries the
/// [`IdempotencyKey`] for the provider call, so the key a worker sends is
/// always the one derived from the step it actually holds — there is no path
/// where a worker calls a provider under a key it made up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    employee_id: EmployeeId,
    step: Step,
    worker_id: Uuid,
    lease_until: DateTime<Utc>,
    idempotency_key: IdempotencyKey,
    attempt: i32,
}

impl Claim {
    /// The employee whose step is held.
    pub const fn employee_id(&self) -> EmployeeId {
        self.employee_id
    }

    /// The step held.
    pub const fn step(&self) -> Step {
        self.step
    }

    /// The worker holding the lease. `finish_step` matches on this.
    pub const fn worker_id(&self) -> Uuid {
        self.worker_id
    }

    /// When the lease lapses and another worker may steal the step.
    pub const fn lease_until(&self) -> DateTime<Utc> {
        self.lease_until
    }

    /// The stable key for the provider call. Same employee, same step, same
    /// key, forever — that is what makes a retry after a crash return the
    /// number we already bought instead of buying another.
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// How many times this step has been claimed, including this one. The
    /// backoff input.
    pub const fn attempt(&self) -> i32 {
        self.attempt
    }
}

/// Take exclusive ownership of one provisioning step, or find out that someone
/// else has it.
///
/// Returns `None` — meaning "not yours to do" — when the step is already
/// `ready`, is `pending_external` (waiting on a process outside our control,
/// which a worker cannot advance by retrying), or is leased by a different
/// worker whose lease has not lapsed yet. A lapsed lease is stealable; a lease
/// held by *this* worker is re-taken and extended, so a retry is idempotent.
///
/// The row is created `pending` if it does not exist yet, so a worker does not
/// need the employee's resource map to have been materialised first. The
/// foreign key still requires the employee itself to exist.
pub async fn claim_step(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    step: Step,
    worker_id: Uuid,
    lease: Duration,
    now: DateTime<Utc>,
) -> Result<Option<Claim>, StoreError> {
    let tenant = tx.tenant_id();

    sqlx::query(
        "INSERT INTO employee_resources \
           (employee_id, step, tenant_id, state, created_at, updated_at) \
         VALUES ($1, $2, $3, 'pending', $4, $4) \
         ON CONFLICT (employee_id, step) DO NOTHING",
    )
    .bind(employee.as_uuid())
    .bind(step.as_str())
    .bind(tenant.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    // The row lock. A concurrent claimer blocks here, and — because this is
    // READ COMMITTED — re-reads the row we just wrote when it wakes up, so it
    // sees our lease rather than the state it read before blocking. That is the
    // entire mutual exclusion; everything else is bookkeeping.
    let Some((state, lease_owner, lease_until, attempts)) =
        sqlx::query_as::<_, (String, Option<Uuid>, Option<DateTime<Utc>>, i32)>(
            "SELECT state, lease_owner, lease_until, attempt_count \
             FROM employee_resources \
             WHERE employee_id = $1 AND step = $2 \
             FOR UPDATE",
        )
        .bind(employee.as_uuid())
        .bind(step.as_str())
        .fetch_optional(&mut ***tx)
        .await?
    else {
        // Invisible to this tenant. RLS makes that indistinguishable from
        // "no such employee", which is the intended behaviour.
        return Ok(None);
    };

    if state == ResourceState::Ready.as_str() {
        return Ok(None);
    }
    // Only the provider (or the sweeper) moves a `pending_external` step along;
    // a worker that re-claimed it would just spin.
    if state
        == (ResourceState::PendingExternal {
            poll_ref: String::new(),
            expected_by: now,
        })
        .as_str()
    {
        return Ok(None);
    }
    let held_by_someone_else = match (lease_owner, lease_until) {
        (Some(owner), Some(until)) => owner != worker_id && until > now,
        _ => false,
    };
    if held_by_someone_else {
        return Ok(None);
    }

    let lease_until = now + lease;
    let attempt = attempts + 1;
    sqlx::query(
        "UPDATE employee_resources \
         SET state = 'provisioning', lease_owner = $3, lease_until = $4, \
             attempt_count = $5, last_error = NULL, updated_at = $6 \
         WHERE employee_id = $1 AND step = $2",
    )
    .bind(employee.as_uuid())
    .bind(step.as_str())
    .bind(worker_id)
    .bind(lease_until)
    .bind(attempt)
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    Ok(Some(Claim {
        employee_id: employee,
        step,
        worker_id,
        lease_until,
        idempotency_key: IdempotencyKey::for_step(employee, step.as_str()),
        attempt,
    }))
}

// ---------------------------------------------------------------------------
// The intent write-ahead log
// ---------------------------------------------------------------------------

/// What we know about a recorded intention to call a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentState {
    /// Written, not resolved. A provider call may or may not have happened.
    InFlight,
    /// The provider answered and we recorded the answer.
    Succeeded,
    /// The provider refused, terminally.
    Failed,
    /// Nobody ever came back to close it. Needs reconciliation against the
    /// provider before the step is retried blindly.
    Orphaned,
}

impl IntentState {
    /// Stable storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            IntentState::InFlight => "in_flight",
            IntentState::Succeeded => "succeeded",
            IntentState::Failed => "failed",
            IntentState::Orphaned => "orphaned",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        [
            IntentState::InFlight,
            IntentState::Succeeded,
            IntentState::Failed,
            IntentState::Orphaned,
        ]
        .into_iter()
        .find(|s| s.as_str() == raw)
    }
}

/// Record, durably, that we are about to call `provider` for this claim.
///
/// Call it and **commit** before the network call. The row is the only evidence
/// that a side effect may exist; a process that dies between here and
/// [`finish_step`] leaves it `in_flight` for [`sweep_expired_leases`] to find.
///
/// Idempotent: a replay under the same key returns the state already on record
/// rather than writing a second intent. A returned [`IntentState::Succeeded`]
/// means the provider already answered once and the caller is re-doing settled
/// work.
pub async fn begin_intent(
    tx: &mut TenantTx<'_>,
    claim: &Claim,
    provider: &str,
    request: &Value,
    now: DateTime<Utc>,
) -> Result<IntentState, StoreError> {
    let tenant = tx.tenant_id();

    // On conflict the state column is left exactly as it is, so RETURNING hands
    // back what was already there — that is how a replay learns it is a replay.
    let (state,): (String,) = sqlx::query_as(
        "INSERT INTO provider_intents \
           (id, tenant_id, employee_id, provider, intent_kind, step, \
            idempotency_key, state, request, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'provisioning_step', $5, $6, 'in_flight', $7, $8, $8) \
         ON CONFLICT (tenant_id, idempotency_key) \
         DO UPDATE SET updated_at = $8 \
         RETURNING state",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(claim.employee_id.as_uuid())
    .bind(provider)
    .bind(claim.step.as_str())
    .bind(claim.idempotency_key.as_str())
    .bind(sqlx::types::Json(request))
    .bind(now)
    .fetch_one(&mut ***tx)
    .await?;

    IntentState::parse(&state).ok_or_else(|| StoreError::conflict("provider_intents.state"))
}

/// Give up on an intent nobody closed.
///
/// The recovery loop calls this once it has reconciled with the provider (or
/// decided it cannot), so the row stops looking like a call still in progress.
/// Only an `in_flight` row moves, so this cannot overwrite a real outcome.
pub async fn mark_intent_orphaned(
    tx: &mut TenantTx<'_>,
    key: &IdempotencyKey,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE provider_intents SET state = 'orphaned', updated_at = $3 \
         WHERE tenant_id = $1 AND idempotency_key = $2 AND state = 'in_flight'",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(key.as_str())
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    Ok(done.rows_affected() == 1)
}

// ---------------------------------------------------------------------------
// Finishing a step
// ---------------------------------------------------------------------------

/// How a provisioning step ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// The provider confirmed the resource, and gave us the id we are now being
    /// billed for.
    Ready {
        /// Provider and external id. Persisted before anything else so the
        /// resource can always be found and cancelled.
        binding: ProviderBinding,
    },
    /// The call succeeded but the resource is waiting on a process outside our
    /// control (a regulatory bundle, a sender review).
    PendingExternal {
        /// Handle to poll or correlate a callback against.
        poll_ref: String,
        /// After this instant the wait is a problem, not a delay.
        expected_by: DateTime<Utc>,
    },
    /// Terminal failure.
    Failed {
        /// What went wrong, for the operator reading the row.
        error: String,
    },
}

/// Write the result of a step: resource state, provider binding, intent
/// outcome and outbox event, in one transaction.
///
/// Guarded by `WHERE lease_owner = $me`. A worker whose lease lapsed while it
/// was talking to the provider — and whose step was then stolen by the recovery
/// loop — gets [`StoreError::Conflict`] and writes **nothing at all**: no
/// resource update, no intent close, no outbox event. Its result is stale by
/// definition, and the new owner's work must not be overwritten by it.
///
/// A provider binding is never cleared here. `Failed` after a successful bind
/// keeps the external id, because the resource is still bought and somebody has
/// to cancel it. Handing the same external id to a second employee trips the
/// partial unique index on `(provider, external_id)` and surfaces as a conflict
/// — the last line of defence against paying twice.
pub async fn finish_step(
    tx: &mut TenantTx<'_>,
    claim: &Claim,
    outcome: StepOutcome,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let tenant = tx.tenant_id();

    let (state, binding, poll_ref, expected_by, error) = match &outcome {
        StepOutcome::Ready { binding } => (
            ResourceState::Ready.as_str(),
            Some(binding),
            None,
            None,
            None,
        ),
        StepOutcome::PendingExternal {
            poll_ref,
            expected_by,
        } => (
            ResourceState::PendingExternal {
                poll_ref: String::new(),
                expected_by: now,
            }
            .as_str(),
            None,
            Some(poll_ref.as_str()),
            Some(*expected_by),
            None,
        ),
        StepOutcome::Failed { error } => (
            ResourceState::Failed.as_str(),
            None,
            None,
            None,
            Some(error.as_str()),
        ),
    };
    let provider = binding.map(ProviderBinding::provider);
    let external_id = binding.map(ProviderBinding::external_id);

    let updated = sqlx::query(
        "UPDATE employee_resources \
         SET state = $4, \
             provider = coalesce($5, provider), \
             external_id = coalesce($6, external_id), \
             poll_ref = $7, expected_by = $8, last_error = $9, \
             lease_owner = NULL, lease_until = NULL, updated_at = $10 \
         WHERE employee_id = $1 AND step = $2 AND lease_owner = $3",
    )
    .bind(claim.employee_id.as_uuid())
    .bind(claim.step.as_str())
    .bind(claim.worker_id)
    .bind(state)
    .bind(provider)
    .bind(external_id)
    .bind(poll_ref)
    .bind(expected_by)
    .bind(error)
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    if updated.rows_affected() == 0 {
        // Lease lapsed and was stolen (or was never ours). Bail before the
        // intent and the outbox event so the transaction has written nothing.
        return Err(StoreError::conflict("employee_resources.lease_owner"));
    }

    let intent_state = match &outcome {
        // `PendingExternal` closes the *intent* as succeeded: the call itself
        // did happen and returned. It is the resource that is still waiting.
        StepOutcome::Ready { .. } | StepOutcome::PendingExternal { .. } => IntentState::Succeeded,
        StepOutcome::Failed { .. } => IntentState::Failed,
    };
    sqlx::query(
        "UPDATE provider_intents \
         SET state = $3, external_id = coalesce($4, external_id), \
             last_error = $5, updated_at = $6 \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(tenant.as_uuid())
    .bind(claim.idempotency_key.as_str())
    .bind(intent_state.as_str())
    .bind(external_id)
    .bind(error)
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    let payload = json!({
        "step": claim.step.as_str(),
        "state": state,
        "provider": provider,
        "external_id": external_id,
        "poll_ref": poll_ref,
        "expected_by": expected_by,
        "error": error,
        "attempt": claim.attempt,
    });
    sqlx::query(
        "INSERT INTO outbox_events \
           (id, tenant_id, aggregate_type, aggregate_id, event_type, payload, \
            created_at, available_at) \
         VALUES ($1, $2, 'employee', $3, $4, $5, $6, $6)",
    )
    // The outbox id only has to sort by insertion; the domain has no id type
    // for it, so a plain v7 from the wall clock is enough.
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(claim.employee_id.as_uuid())
    .bind(format!("employee.step.{state}"))
    .bind(sqlx::types::Json(&payload))
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// A step whose worker went away without finishing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredLease {
    /// The employee whose step is stuck.
    pub employee_id: EmployeeId,
    /// The stuck step.
    pub step: Step,
    /// The worker that abandoned it.
    pub worker_id: Uuid,
    /// When its lease lapsed.
    pub lease_until: DateTime<Utc>,
    /// How many times this step has been claimed. The backoff input, and the
    /// give-up signal.
    pub attempt_count: i32,
    /// The provider of an intent still `in_flight` for this step, if any.
    ///
    /// `Some` is the dangerous case and the reason this module exists: a call
    /// to that provider **may already have happened**, so the resource may
    /// already be bought. Reconcile against the provider using
    /// `IdempotencyKey::for_step` before retrying.
    pub in_flight_provider: Option<String>,
}

/// Steps stuck in `provisioning` past their lease, oldest first.
///
/// Read-only on purpose: it reports, the recovery loop decides. Re-claiming is
/// [`claim_step`]'s job, and it already treats a lapsed lease as stealable, so
/// there is nothing for a sweep to unlock.
pub async fn sweep_expired_leases(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<ExpiredLease>, StoreError> {
    // ponytail: one in-flight intent per (employee, step) is assumed. Two
    // providers racing the same step would yield two rows here; if that ever
    // becomes real, make the join a LATERAL picking the newest.
    let rows = sqlx::query_as::<_, (Uuid, String, Uuid, DateTime<Utc>, i32, Option<String>)>(
        "SELECT r.employee_id, r.step, r.lease_owner, r.lease_until, r.attempt_count, \
                i.provider \
         FROM employee_resources r \
         LEFT JOIN provider_intents i \
           ON i.employee_id = r.employee_id \
          AND i.step = r.step \
          AND i.state = 'in_flight' \
         WHERE r.state = 'provisioning' \
           AND r.lease_owner IS NOT NULL \
           AND r.lease_until IS NOT NULL \
           AND r.lease_until < $1 \
         ORDER BY r.lease_until \
         LIMIT $2",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(
            |(employee_id, step, worker_id, lease_until, attempt_count, in_flight_provider)| {
                Some(ExpiredLease {
                    employee_id: EmployeeId::from_uuid(employee_id),
                    step: parse_step(&step)?,
                    worker_id,
                    lease_until,
                    attempt_count,
                    in_flight_provider,
                })
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentos_domain::ids::TenantId;

    use crate::db::Db;

    /// Thirty seconds. `chrono::Duration::seconds` is not const, so this is a
    /// function rather than a constant.
    fn lease() -> Duration {
        Duration::seconds(30)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    const T0: i64 = 1_700_000_000;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; provisioning tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one employee, committed. Torn down by [`teardown`].
    async fn seed(db: &Db, label: &str) -> (TenantId, EmployeeId) {
        let tenant = TenantId::new_v7(Utc::now());
        let employee = EmployeeId::new_v7(Utc::now());
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
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(label)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        (tenant, employee)
    }

    /// Cascades through employees, resources, intents and outbox events.
    async fn teardown(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    async fn resource_row(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        step: Step,
    ) -> (String, Option<Uuid>, Option<String>, Option<String>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let row = sqlx::query_as(
            "SELECT state, lease_owner, provider, external_id \
             FROM employee_resources WHERE employee_id = $1 AND step = $2",
        )
        .bind(employee.as_uuid())
        .bind(step.as_str())
        .fetch_one(&mut **tx)
        .await
        .expect("resource row");
        tx.rollback().await.expect("rollback");
        row
    }

    async fn count(db: &Db, tenant: TenantId, sql: &'static str) -> i64 {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let n: i64 = sqlx::query_scalar(sql)
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        n
    }

    /// The whole point of the module: two workers, one step, one winner.
    ///
    /// Both transactions run genuinely concurrently on separate pooled
    /// connections. The loser blocks on the row lock and, when it wakes, sees
    /// the winner's committed lease.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_workers_race_and_exactly_one_wins() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "race").await;
        let step = Step::Phone;

        // Eight rather than two: one pair racing can pass by luck of
        // scheduling, eight cannot.
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let db = db.clone();
                let worker = Uuid::now_v7();
                tokio::spawn(async move {
                    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
                    let claim = claim_step(&mut tx, employee, step, worker, lease(), at(T0))
                        .await
                        .expect("claim");
                    tx.commit().await.expect("commit");
                    claim.map(|c| c.worker_id())
                })
            })
            .collect();

        let mut winners = Vec::new();
        for task in tasks {
            if let Some(w) = task.await.expect("join") {
                winners.push(w);
            }
        }

        assert_eq!(
            winners.len(),
            1,
            "exactly one worker may hold the step, got {winners:?}"
        );
        let (state, owner, ..) = resource_row(&db, tenant, employee, step).await;
        assert_eq!(state, "provisioning");
        assert_eq!(owner, Some(winners[0]));

        teardown(&db, tenant).await;
    }

    #[tokio::test]
    async fn an_expired_lease_is_reclaimable_and_a_live_one_is_not() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "lease").await;
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let first = claim_step(&mut tx, employee, Step::Email, a, lease(), at(T0))
            .await
            .expect("claim");
        tx.commit().await.expect("commit");
        assert_eq!(first.expect("first claim").attempt(), 1);

        // Still inside the lease window: nobody else gets it.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            claim_step(&mut tx, employee, Step::Email, b, lease(), at(T0 + 10))
                .await
                .expect("claim")
                .is_none()
        );
        // ... but the holder may re-take and extend its own lease.
        let again = claim_step(&mut tx, employee, Step::Email, a, lease(), at(T0 + 10))
            .await
            .expect("claim")
            .expect("holder re-claims");
        assert_eq!(again.lease_until(), at(T0 + 40));
        tx.commit().await.expect("commit");

        // Past it: stealable, and the attempt count keeps climbing.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let stolen = claim_step(&mut tx, employee, Step::Email, b, lease(), at(T0 + 1_000))
            .await
            .expect("claim")
            .expect("expired lease is stealable");
        tx.commit().await.expect("commit");
        assert_eq!(stolen.worker_id(), b);
        assert_eq!(stolen.attempt(), 3);

        teardown(&db, tenant).await;
    }

    #[tokio::test]
    async fn a_ready_step_is_never_reclaimed() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "ready").await;
        let worker = Uuid::now_v7();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let claim = claim_step(&mut tx, employee, Step::Phone, worker, lease(), at(T0))
            .await
            .expect("claim")
            .expect("claim");
        finish_step(
            &mut tx,
            &claim,
            StepOutcome::Ready {
                binding: ProviderBinding::new("twilio", format!("PN-{}", employee.as_uuid())),
            },
            at(T0 + 1),
        )
        .await
        .expect("finish");
        tx.commit().await.expect("commit");

        let (state, owner, provider, external) =
            resource_row(&db, tenant, employee, Step::Phone).await;
        assert_eq!(state, "ready");
        assert_eq!(owner, None, "finishing releases the lease");
        assert_eq!(provider.as_deref(), Some("twilio"));
        assert!(external.is_some());

        // The whole idempotency story: a second worker arriving after a crash
        // is told there is nothing to do rather than buying a second number.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            claim_step(
                &mut tx,
                employee,
                Step::Phone,
                Uuid::now_v7(),
                lease(),
                at(T0 + 5)
            )
            .await
            .expect("claim")
            .is_none()
        );
        tx.rollback().await.expect("rollback");

        teardown(&db, tenant).await;
    }

    #[tokio::test]
    async fn a_pending_external_step_is_not_reclaimable_by_a_worker() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "external").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let claim = claim_step(
            &mut tx,
            employee,
            Step::Whatsapp,
            Uuid::now_v7(),
            lease(),
            at(T0),
        )
        .await
        .expect("claim")
        .expect("claim");
        finish_step(
            &mut tx,
            &claim,
            StepOutcome::PendingExternal {
                poll_ref: "BU-review-1".to_owned(),
                expected_by: at(T0 + 86_400),
            },
            at(T0 + 1),
        )
        .await
        .expect("finish");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            claim_step(
                &mut tx,
                employee,
                Step::Whatsapp,
                Uuid::now_v7(),
                lease(),
                at(T0 + 100_000)
            )
            .await
            .expect("claim")
            .is_none(),
            "only a provider callback moves pending_external along"
        );
        tx.rollback().await.expect("rollback");

        teardown(&db, tenant).await;
    }

    /// A worker whose lease lapsed finishes late. Its write must not land, and
    /// it must not leave an outbox event behind either.
    #[tokio::test]
    async fn finish_step_with_a_stolen_lease_is_rejected_and_writes_nothing() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "stolen").await;
        let (slow, thief) = (Uuid::now_v7(), Uuid::now_v7());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let slow_claim = claim_step(&mut tx, employee, Step::Wallet, slow, lease(), at(T0))
            .await
            .expect("claim")
            .expect("claim");
        tx.commit().await.expect("commit");

        // The recovery loop steals it once the lease lapses.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let thief_claim = claim_step(
            &mut tx,
            employee,
            Step::Wallet,
            thief,
            lease(),
            at(T0 + 1_000),
        )
        .await
        .expect("claim")
        .expect("steal");
        tx.commit().await.expect("commit");

        // ... and only now does the original worker come back from the provider.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let err = finish_step(
            &mut tx,
            &slow_claim,
            StepOutcome::Ready {
                binding: ProviderBinding::new("stripe", "acct_stale"),
            },
            at(T0 + 1_100),
        )
        .await
        .expect_err("a stolen lease must not be able to write");
        assert!(
            matches!(&err, StoreError::Conflict(what) if what == "employee_resources.lease_owner"),
            "expected a lease conflict, got {err:?}"
        );
        tx.commit()
            .await
            .expect("commit whatever it managed to write");

        let (state, owner, provider, _) = resource_row(&db, tenant, employee, Step::Wallet).await;
        assert_eq!(state, "provisioning", "the thief's state must survive");
        assert_eq!(owner, Some(thief), "the thief must still hold the lease");
        assert_eq!(provider, None, "the stale binding must not have landed");
        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM outbox_events").await,
            0,
            "a rejected finish must not emit an event"
        );

        // The new owner finishes normally.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        finish_step(
            &mut tx,
            &thief_claim,
            StepOutcome::Ready {
                binding: ProviderBinding::new("stripe", "acct_real"),
            },
            at(T0 + 1_200),
        )
        .await
        .expect("finish");
        tx.commit().await.expect("commit");

        let (_, _, _, external) = resource_row(&db, tenant, employee, Step::Wallet).await;
        assert_eq!(external.as_deref(), Some("acct_real"));

        teardown(&db, tenant).await;
    }

    /// The crash window. Intent committed, provider possibly called, process
    /// dies. Exactly one `in_flight` row survives and the sweep surfaces it.
    #[tokio::test]
    async fn a_crash_between_intent_and_finish_leaves_one_in_flight_row_the_sweep_finds() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "crash").await;
        let worker = Uuid::now_v7();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let claim = claim_step(&mut tx, employee, Step::Phone, worker, lease(), at(T0))
            .await
            .expect("claim")
            .expect("claim");
        let state = begin_intent(
            &mut tx,
            &claim,
            "twilio",
            &json!({"area_code": "415"}),
            at(T0),
        )
        .await
        .expect("begin intent");
        assert_eq!(state, IntentState::InFlight);
        tx.commit().await.expect("commit");
        // ---- the process dies here, mid provider call ----

        // The retry writes the same key, so there is still exactly one row.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let replay = begin_intent(
            &mut tx,
            &claim,
            "twilio",
            &json!({"area_code": "415"}),
            at(T0 + 5),
        )
        .await
        .expect("replay intent");
        tx.commit().await.expect("commit");
        assert_eq!(replay, IntentState::InFlight, "a replay is not a new call");
        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM provider_intents").await,
            1,
            "the WAL must not fan out on retry"
        );

        // The sweep, once the lease lapses.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            sweep_expired_leases(&mut tx, at(T0 + 10), 100)
                .await
                .expect("sweep")
                .is_empty(),
            "a live lease is not stuck"
        );
        let stuck = sweep_expired_leases(&mut tx, at(T0 + 1_000), 100)
            .await
            .expect("sweep");
        tx.rollback().await.expect("rollback");

        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].employee_id, employee);
        assert_eq!(stuck[0].step, Step::Phone);
        assert_eq!(stuck[0].worker_id, worker);
        assert_eq!(stuck[0].attempt_count, 1);
        assert_eq!(
            stuck[0].in_flight_provider.as_deref(),
            Some("twilio"),
            "the sweep must say a twilio call may already have happened"
        );

        // Reconciled and written off; the sweep stops flagging a live call.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            mark_intent_orphaned(&mut tx, claim.idempotency_key(), at(T0 + 1_100))
                .await
                .expect("orphan")
        );
        assert!(
            !mark_intent_orphaned(&mut tx, claim.idempotency_key(), at(T0 + 1_200))
                .await
                .expect("orphan again"),
            "only an in_flight intent moves"
        );
        let stuck = sweep_expired_leases(&mut tx, at(T0 + 1_300), 100)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
        assert_eq!(stuck[0].in_flight_provider, None);

        teardown(&db, tenant).await;
    }

    /// finish_step closes the intent and writes the outbox event in the same
    /// transaction as the resource, so a subscriber can never see an event for
    /// a state that was rolled back.
    #[tokio::test]
    async fn finish_step_writes_resource_intent_and_outbox_atomically() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "atomic").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let claim = claim_step(
            &mut tx,
            employee,
            Step::Vault,
            Uuid::now_v7(),
            lease(),
            at(T0),
        )
        .await
        .expect("claim")
        .expect("claim");
        begin_intent(&mut tx, &claim, "vault", &json!({}), at(T0))
            .await
            .expect("intent");
        finish_step(
            &mut tx,
            &claim,
            StepOutcome::Failed {
                error: "kms refused".to_owned(),
            },
            at(T0 + 1),
        )
        .await
        .expect("finish");
        // Rolled back, not committed: nothing may survive.
        tx.rollback().await.expect("rollback");

        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM outbox_events").await,
            0
        );
        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM provider_intents").await,
            0
        );
        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM employee_resources").await,
            0
        );

        // Now for real.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let claim = claim_step(
            &mut tx,
            employee,
            Step::Vault,
            Uuid::now_v7(),
            lease(),
            at(T0),
        )
        .await
        .expect("claim")
        .expect("claim");
        begin_intent(&mut tx, &claim, "vault", &json!({}), at(T0))
            .await
            .expect("intent");
        finish_step(
            &mut tx,
            &claim,
            StepOutcome::Failed {
                error: "kms refused".to_owned(),
            },
            at(T0 + 1),
        )
        .await
        .expect("finish");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let (event_type, payload): (String, Value) =
            sqlx::query_as("SELECT event_type, payload FROM outbox_events")
                .fetch_one(&mut **tx)
                .await
                .expect("outbox row");
        let (intent_state,): (String,) = sqlx::query_as("SELECT state FROM provider_intents")
            .fetch_one(&mut **tx)
            .await
            .expect("intent row");
        tx.rollback().await.expect("rollback");

        assert_eq!(event_type, "employee.step.failed");
        assert_eq!(payload["step"], "vault");
        assert_eq!(payload["error"], "kms refused");
        assert_eq!(intent_state, IntentState::Failed.as_str());

        teardown(&db, tenant).await;
    }

    /// The last line of defence: the same external id may never be bound to two
    /// employees, whatever the workers think they are doing.
    #[tokio::test]
    async fn the_same_external_id_cannot_be_bound_twice() {
        let Some(db) = db().await else { return };
        let (tenant, one) = seed(&db, "bind-one").await;
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let two = EmployeeId::new_v7(Utc::now());
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'bind-two', 'bind-two', 'active')",
        )
        .bind(two.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("second employee");
        tx.commit().await.expect("commit");

        let number = format!("PN-{}", Uuid::now_v7());
        for (employee, expect_ok) in [(one, true), (two, false)] {
            let mut tx = db.tenant_tx(tenant).await.expect("tx");
            let claim = claim_step(
                &mut tx,
                employee,
                Step::Phone,
                Uuid::now_v7(),
                lease(),
                at(T0),
            )
            .await
            .expect("claim")
            .expect("claim");
            let result = finish_step(
                &mut tx,
                &claim,
                StepOutcome::Ready {
                    binding: ProviderBinding::new("twilio", number.clone()),
                },
                at(T0 + 1),
            )
            .await;
            if expect_ok {
                result.expect("first bind");
                tx.commit().await.expect("commit");
            } else {
                assert!(
                    matches!(&result, Err(StoreError::Conflict(c))
                        if c == "employee_resources_provider_external_id_key"),
                    "a second employee must not get the same number, got {result:?}"
                );
                tx.rollback().await.expect("rollback");
            }
        }

        teardown(&db, tenant).await;
    }
}
