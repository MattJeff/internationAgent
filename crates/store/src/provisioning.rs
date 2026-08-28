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
//! # The same window, for a call that is not a step
//!
//! A send holds no lease and converges no resource, but it has the same gap
//! between the request leaving and the answer arriving. [`begin_send_intent`],
//! [`settle_send_intent`] and [`unsettled_calls`] are that gap's before, after,
//! and — the one that makes the other two worth writing — the reader for the
//! requests that never got an after. They promise less than the step machinery
//! above does, and say so in their own docs.
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
// The intent log for a one-shot provider call
// ---------------------------------------------------------------------------
//
// A send is not a provisioning step. It holds no lease, it converges no
// `employee_resources` row, and it happens once. What it shares with a step is
// the only thing this section is about: there is a window between the request
// leaving and the answer arriving, and a process that dies inside it has done
// something to somebody that no row in this database mentions.
//
// The three functions below are that window's before, after, and — the one that
// makes the other two worth writing — the reader for the calls that never got
// an after.

/// Record, durably, that we are about to ask `provider` to do one thing under
/// `key`.
///
/// The sibling of [`begin_intent`], and it exists because that one cannot be
/// reused: it takes a [`Claim`] — a leased `employee_resources` row plus a
/// [`Step`] — and hard-codes `intent_kind = 'provisioning_step'`. A send has no
/// lease, no step and no row. It leaves `step` NULL, which is what
/// [`unsettled_calls`] reads to tell the two kinds apart.
///
/// Call it and **commit before the request leaves**. That commit is the whole
/// mechanism; everything else here is bookkeeping around it.
///
/// # There is no `ON CONFLICT` clause, and that is the guard rather than the
/// missing half of one
///
/// [`begin_intent`] has one because a provisioning key is *deliberately* stable
/// across attempts — same employee, same step, same key forever — so a retry has
/// to be able to find its own row. A send key is the opposite: it is derived
/// from one Policy Gate ruling, and a ruling is minted fresh per token and
/// consumed by value, so no two requests can ever present the same key. If one
/// somehow did, the right answer is that the request **must not leave**, and
/// `provider_intents_tenant_key_idx` refusing the insert is exactly that answer
/// with no branch here to get wrong. The caller sees a store error and sends
/// nothing.
///
/// # What this does not do, said plainly because the name invites the opposite
///
/// It does **not** make a duplicate impossible, and it does not try to. Nothing
/// here reaches the provider. The send APIs it is written for take no
/// idempotency key and answer no "did key K land" question, so a row left
/// `in_flight` can never be resolved by asking, and the retry that follows a
/// crashed send arrives under a *new* ruling and a new key — this function will
/// happily write it a second row. What it buys, and the whole of what it buys,
/// is that an ambiguous send is **recorded** as ambiguous instead of being
/// invisible, and that a person is shown it: see [`unsettled_calls`]. That is a
/// far smaller claim than the one a reader of the word "idempotency" will
/// assume, and the smaller one is the true one.
pub async fn begin_send_intent(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    provider: &str,
    intent_kind: &str,
    key: &IdempotencyKey,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO provider_intents \
           (id, tenant_id, employee_id, provider, intent_kind, \
            idempotency_key, state, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'in_flight', $7, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(tx.tenant_id().as_uuid())
    .bind(employee.as_uuid())
    .bind(provider)
    .bind(intent_kind)
    .bind(key.as_str())
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    Ok(())
}

/// Close the row [`begin_send_intent`] opened, in whatever transaction also
/// records the effect.
///
/// `answer` is `Ok(external_id)` when the provider named what it did, and
/// `Err(reason)` when the provider **answered and refused** — a request that
/// reached the other end and produced nothing.
///
/// # A call whose answer never came back is not passed here at all
///
/// There is deliberately no third variant meaning "unknown", because the
/// correct write for that case is *no write*: the row stays `in_flight`, which
/// is the only true statement about a request that may have landed. A timeout
/// settled as `failed` would be this whole section lying in its own vocabulary,
/// and the caller that has the classification — `EffectError`'s provider arm —
/// is the one that decides. [`unsettled_calls`] is where those rows surface.
///
/// Only an `in_flight` row moves, so a late second answer cannot overwrite a
/// settled outcome, and a caller that never opened a row of its own cannot
/// clobber somebody else's: the update matches nothing and returns `false`.
pub async fn settle_send_intent(
    tx: &mut TenantTx<'_>,
    key: &IdempotencyKey,
    answer: Result<&str, &str>,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let (state, external_id, error) = match answer {
        Ok(id) => (IntentState::Succeeded, Some(id), None),
        Err(reason) => (IntentState::Failed, None, Some(reason)),
    };

    let done = sqlx::query(
        "UPDATE provider_intents \
         SET state = $3, external_id = $4, last_error = $5, updated_at = $6 \
         WHERE tenant_id = $1 AND idempotency_key = $2 AND state = 'in_flight'",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(key.as_str())
    .bind(state.as_str())
    .bind(external_id)
    .bind(error)
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    Ok(done.rows_affected() == 1)
}

/// One request this system sent to a provider and never learned the outcome of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsettledCall {
    /// What was being attempted — the effect's `ActionKind`, e.g. `sms_send`.
    pub intent_kind: String,
    /// The port it went out through: `telephony`, `email`. The port and not the
    /// vendor, because which adapter is installed behind it is deployment
    /// configuration and this row outlives it.
    pub provider: String,
    /// The key the request carried, verbatim. It spells out the Policy Gate
    /// ruling — `employee:{id}:step:effect:{decision_id}` — which is how a
    /// person joins this row to the `audit_log` row that names the recipient.
    /// The recipient is deliberately not copied here: it already lives in one
    /// place under that tenant's own RLS, and two copies is one to forget.
    pub idempotency_key: String,
    /// When the request left.
    pub started_at: DateTime<Utc>,
}

/// Requests for `employee` that left before `before` and never came back with an
/// answer — oldest first.
///
/// **This is the reader that makes the write-ahead row worth writing.** An
/// `in_flight` row nobody selects is a column that grows forever and tells
/// nobody anything; the point of writing one is that a person can be shown it
/// and settle what the provider will not answer — by looking in the provider's
/// own console for the message, or by asking the recipient.
///
/// `before` is the caller's grace period, and it is what keeps a send that is
/// merely *in progress* out of the answer. Every row here is older than any
/// adapter's request timeout, so "no answer yet" has already stopped being a
/// plausible reading.
///
/// `step IS NULL` is the whole of what separates these from provisioning:
/// [`begin_intent`] and `record_release` both write the step they are for, and a
/// row without one is a one-shot provider call. A payment intent would land in
/// this list too if anything wrote one, and that is correct — an unsettled
/// payment is exactly as much somebody's morning as an unsettled text.
pub async fn unsettled_calls(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    before: DateTime<Utc>,
) -> Result<Vec<UnsettledCall>, StoreError> {
    // ponytail: bounded, with no cursor. A hundred unsettled calls on one seat
    // is an incident and not a page to walk through; if this ever truncates, the
    // number to act on is the first row's age, which is at the top either way.
    let rows = sqlx::query_as::<_, (String, String, String, DateTime<Utc>)>(
        "SELECT intent_kind, provider, idempotency_key, created_at \
           FROM provider_intents \
          WHERE employee_id = $1 \
            AND state = 'in_flight' \
            AND step IS NULL \
            AND created_at < $2 \
          ORDER BY created_at \
          LIMIT 100",
    )
    .bind(employee.as_uuid())
    .bind(before)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(intent_kind, provider, idempotency_key, started_at)| UnsettledCall {
                intent_kind,
                provider,
                idempotency_key,
                started_at,
            },
        )
        .collect())
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
    /// **Nothing was provisioned, because nothing could use it.** Not a
    /// success, not a failure, and — the whole point — not a purchase.
    ///
    /// A capability can be built into this workspace at the provider end and
    /// wired to nothing at the product end: `Step::Phone` bought a number every
    /// employee was billed for monthly while no tool in `turn::catalogue` could
    /// send or receive on it. Reporting that as [`Self::Ready`] bills for a lie;
    /// reporting it as [`Self::Failed`] makes every employee in every deployment
    /// `Health::Degraded` forever over a channel nobody asked for. It is a third
    /// thing and it needed a third word.
    ///
    /// Lands the resource in [`ResourceState::Disabled`], which
    /// `Employee::resource_health` already reads as "off on purpose" — the one
    /// state that neither degrades an employee nor claims a resource exists.
    ///
    /// # The binding is kept, exactly like [`Self::Failed`]
    ///
    /// This arm acquires no binding and clears none: the `coalesce` in
    /// [`finish_step`] leaves whatever was already bought exactly where it is,
    /// because the resource would still be real, still billed, and the external
    /// id is the only thing that says what to cancel.
    ///
    /// `ProvisioningEngine` never actually reaches that case — a step holding a
    /// binding is `Ready`, and `ensure_step` returns on `Ready` before it gets
    /// here, deliberately, so that a build which forgets how to *use* a resource
    /// cannot rewrite the record of having *bought* one. The property is stated
    /// as a fact about this function rather than about the engine, and no test
    /// exercises it, because no caller in this workspace can produce it.
    Disabled {
        /// Why nothing was provisioned, for the operator reading the row.
        /// Lands in `last_error` — the only text column on the row — so it is
        /// what `GET /v1/inventory/stranded` renders as `reason`.
        reason: String,
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
        // No binding, for the same reason `Failed` has none: this arm never
        // *acquires* one. It does not clear one either — `coalesce` below keeps
        // whatever was already bought, which is what the operator has to go and
        // cancel.
        StepOutcome::Disabled { reason } => (
            ResourceState::Disabled.as_str(),
            None,
            None,
            None,
            Some(reason.as_str()),
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
        // There is normally **no intent row at all** for this outcome:
        // `ProvisioningEngine::claim` skips `begin_intent` for a step it is
        // about to disable, because a write-ahead entry for a call that will
        // not happen is what makes the recovery sweep file a reconciliation
        // approval about a purchase nobody made. The UPDATE below therefore
        // matches nothing, and this value is what it would be if some other
        // caller ever did leave one: never `Succeeded`, because no resource
        // came of it.
        StepOutcome::Disabled { .. } => IntentState::Failed,
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
// Releasing
// ---------------------------------------------------------------------------

/// The key a release of one step is recorded under.
///
/// Deliberately **not** `IdempotencyKey::for_step(employee, step)`. That key
/// already names the provisioning intent for the same step, and the two are
/// different questions about one resource — *was it ever created* and *was it
/// ever destroyed*. Sharing a key would have a release close the purchase's
/// intent, and a re-provision close the release's.
pub fn release_key(employee: EmployeeId, step: Step) -> IdempotencyKey {
    IdempotencyKey::for_step(employee, &format!("release:{}", step.as_str()))
}

/// Record how an attempt to give a provider resource back went.
///
/// Written **after** the call, not before, which is the one place release
/// deliberately differs from [`begin_intent`]. A provisioning intent has to be
/// durable before the call because a created-but-unrecorded resource is
/// invisible and a blind retry buys a second one. A release has the opposite
/// shape: every adapter is required to be idempotent and to tolerate a resource
/// that is already gone, so a call whose outcome was lost costs nothing but
/// another call. There is no orphan to park and no human to ask.
///
/// `error: None` means released. `Some(why)` means the resource is **still
/// there and still being billed** — so the caller has not cleared the binding,
/// and this stamps the reason onto both the intent and
/// `employee_resources.last_error`, which is the column an operator actually
/// reads. That pair is the retryable record: the external id still names what
/// to cancel, and the row says why nobody has.
///
/// ponytail: no outbox event. Nothing subscribes to a release yet, and an event
/// type with no handler in the server's dispatch table is a dead letter by
/// construction. Add one here the day something needs to react.
pub async fn record_release(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    step: Step,
    provider: &str,
    error: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let tenant = tx.tenant_id();
    let key = release_key(employee, step);
    let state = if error.is_some() {
        IntentState::Failed
    } else {
        IntentState::Succeeded
    };

    sqlx::query(
        "INSERT INTO provider_intents \
           (id, tenant_id, employee_id, provider, intent_kind, step, \
            idempotency_key, state, request, last_error, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'release_step', $5, $6, $7, $8, $9, $10, $10) \
         ON CONFLICT (tenant_id, idempotency_key) \
         DO UPDATE SET state = excluded.state, \
                       last_error = excluded.last_error, \
                       updated_at = excluded.updated_at",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(employee.as_uuid())
    .bind(provider)
    .bind(step.as_str())
    .bind(key.as_str())
    .bind(state.as_str())
    .bind(sqlx::types::Json(json!({ "step": step.as_str() })))
    .bind(error)
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    // The binding is not touched here, in either direction: clearing one is
    // `Employee::release`'s job and nothing else's, and a failed release must
    // leave the external id exactly where it is.
    sqlx::query(
        "UPDATE employee_resources SET last_error = $3, updated_at = $4 \
         WHERE employee_id = $1 AND step = $2",
    )
    .bind(employee.as_uuid())
    .bind(step.as_str())
    .bind(error)
    .bind(now)
    .execute(&mut ***tx)
    .await?;

    Ok(())
}

/// A resource a terminated employee still holds — still real, still billed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stranded {
    /// The employee that was terminated.
    pub employee_id: EmployeeId,
    /// The step whose resource is still out there.
    pub step: Step,
    /// Who is billing for it.
    pub provider: String,
    /// **What to cancel.** The whole reason this row was not thrown away.
    pub external_id: String,
    /// Where the resource row got stuck: `failed` after a refused release,
    /// `ready` if nothing ever tried.
    pub state: String,
    /// Why the last release did not happen, verbatim. A `release_not_supported`
    /// here means no retry will ever fix it — a human has to.
    pub last_error: Option<String>,
}

/// Everything this tenant's terminated employees are still being billed for.
///
/// **The operator's list.** The termination sweeper retries what it can and
/// gives up on what it cannot (`release_not_supported` is structural: Resend's
/// sending domain is shared across the tenant, so the adapter refuses on
/// purpose and will refuse identically forever). Retrying
/// that would burn a provider call and re-fire an operator alert on every tick
/// for the life of the deployment, so it is excluded from the retry set — which
/// would make it invisible if this query did not exist.
///
/// A query rather than a counter: the operator's task is "go and cancel these
/// by hand", and that needs the provider, the external id and the reason. A
/// number tells nobody what to cancel. (There is also no metrics exporter in
/// this workspace, so a gauge would mean adding one.)
///
/// Tenant-scoped through [`TenantTx`] like everything else here; an operator
/// asks about their own tenant, and nothing about this needs to see across.
pub async fn stranded(tx: &mut TenantTx<'_>, limit: i64) -> Result<Vec<Stranded>, StoreError> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, String, Option<String>)>(
        "SELECT r.employee_id, r.step, r.provider, r.external_id, r.state, r.last_error \
         FROM employee_resources r \
         JOIN employees e ON e.id = r.employee_id \
         WHERE e.lifecycle = 'terminated' \
           AND r.provider IS NOT NULL \
           AND r.external_id IS NOT NULL \
         ORDER BY r.updated_at \
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(
            |(employee_id, step, provider, external_id, state, last_error)| {
                Some(Stranded {
                    employee_id: EmployeeId::from_uuid(employee_id),
                    step: parse_step(&step)?,
                    provider,
                    external_id,
                    state,
                    last_error,
                })
            },
        )
        .collect())
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

    /// A release is recorded *beside* the purchase it undoes, never on top of
    /// it — and a failed one leaves the external id exactly where it is.
    ///
    /// If the two shared an idempotency key, recording a release would rewrite
    /// the row that says a number was bought, and the one durable trace of the
    /// purchase would be gone.
    #[tokio::test]
    async fn a_failed_release_is_a_second_row_and_keeps_the_binding() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "release").await;

        assert_ne!(
            release_key(employee, Step::Phone).as_str(),
            IdempotencyKey::for_step(employee, Step::Phone.as_str()).as_str(),
            "a release must not be able to close the purchase's intent"
        );

        // Buy the number, the ordinary way.
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
        begin_intent(&mut tx, &claim, "twilio", &json!({}), at(T0))
            .await
            .expect("intent");
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

        // Now the provider refuses to take it back.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        record_release(
            &mut tx,
            employee,
            Step::Phone,
            "twilio",
            Some("release release_refused"),
            at(T0 + 2),
        )
        .await
        .expect("record the refusal");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let intents: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT intent_kind, state, last_error FROM provider_intents \
             WHERE employee_id = $1 ORDER BY intent_kind",
        )
        .bind(employee.as_uuid())
        .fetch_all(&mut **tx)
        .await
        .expect("intents");
        let last_error: Option<String> = sqlx::query_scalar(
            "SELECT last_error FROM employee_resources WHERE employee_id = $1 AND step = 'phone'",
        )
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("resource row");
        tx.rollback().await.expect("rollback");

        assert_eq!(
            intents.len(),
            2,
            "the purchase and the release are two facts"
        );
        assert_eq!(intents[0].0, "provisioning_step");
        assert_eq!(intents[0].1, IntentState::Succeeded.as_str());
        assert_eq!(intents[1].0, "release_step");
        assert_eq!(intents[1].1, IntentState::Failed.as_str());
        assert_eq!(intents[1].2.as_deref(), Some("release release_refused"));
        assert_eq!(last_error.as_deref(), Some("release release_refused"));

        // The number is still ours, still named, still cancellable by hand.
        // Recording a refusal must not be a way to lose the id.
        let (state, _, provider, external) = resource_row(&db, tenant, employee, Step::Phone).await;
        assert_eq!(state, "ready", "this function does not move the state");
        assert_eq!(provider.as_deref(), Some("twilio"));
        assert!(external.is_some());

        // And when it finally works, the reason is cleared rather than left to
        // haunt the row.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        record_release(&mut tx, employee, Step::Phone, "twilio", None, at(T0 + 3))
            .await
            .expect("record the success");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let (state, last_error): (String, Option<String>) = sqlx::query_as(
            "SELECT i.state, r.last_error FROM provider_intents i \
             JOIN employee_resources r \
               ON r.employee_id = i.employee_id AND r.step = i.step \
             WHERE i.employee_id = $1 AND i.intent_kind = 'release_step'",
        )
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("release intent");
        tx.rollback().await.expect("rollback");
        assert_eq!(state, IntentState::Succeeded.as_str());
        assert_eq!(last_error, None);
        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM provider_intents").await,
            2,
            "a retried release updates its row rather than fanning out"
        );

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

    /// The predicate that separates the two kinds of intent, checked against
    /// both of them at once.
    ///
    /// `unsettled_calls` filters on `step IS NULL`, and that one word is the
    /// whole of the separation. A stuck provisioning step already has its own
    /// machinery — a lease that expires, [`sweep_expired_leases`], a recovery
    /// pass that files an approval — so reporting it here as well would put a
    /// second alarm on a fire somebody is already fighting, and the reader that
    /// cries about a phone number every morning is the reader nobody opens on
    /// the morning a text is in it.
    ///
    /// The inverse is asserted in the same breath: the send *is* returned. A
    /// predicate that excluded both would satisfy the sentence above and be
    /// useless.
    #[tokio::test]
    async fn a_stuck_provisioning_step_is_not_reported_as_an_unsettled_send() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "unsettled").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        // One of each, for the same employee, both `in_flight`.
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
        begin_intent(&mut tx, &claim, "telephony", &json!({}), at(T0))
            .await
            .expect("the provisioning intent");
        let key = IdempotencyKey::for_step(employee, "effect:a-ruling");
        begin_send_intent(&mut tx, employee, "telephony", "sms_send", &key, at(T0 + 1))
            .await
            .expect("the send intent");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let unsettled = unsettled_calls(&mut tx, employee, at(T0 + 1_000))
            .await
            .expect("read");
        tx.rollback().await.expect("rollback");

        assert_eq!(unsettled.len(), 1, "{unsettled:?}");
        assert_eq!(unsettled[0].intent_kind, "sms_send");
        assert_eq!(unsettled[0].idempotency_key, key.as_str());
        assert_eq!(unsettled[0].started_at, at(T0 + 1));
        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM provider_intents").await,
            2,
            "both rows exist; only one of them is this reader's business"
        );

        teardown(&db, tenant).await;
    }

    /// A settled row leaves the reader, and a timeout that was never settled
    /// stays in it.
    ///
    /// [`settle_send_intent`] is the only way out, and it takes no "unknown"
    /// answer on purpose — the caller with a timeout in hand simply does not
    /// call it. This pins both halves of that: the answered row goes quiet, the
    /// unanswered one does not.
    #[tokio::test]
    async fn only_an_answered_send_leaves_the_reader() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "settled").await;
        let answered = IdempotencyKey::for_step(employee, "effect:answered");
        let silent = IdempotencyKey::for_step(employee, "effect:silent");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        for key in [&answered, &silent] {
            begin_send_intent(&mut tx, employee, "telephony", "sms_send", key, at(T0))
                .await
                .expect("begin");
        }
        assert!(
            settle_send_intent(&mut tx, &answered, Ok("SM0001"), at(T0 + 1))
                .await
                .expect("settle"),
            "an in-flight row is settleable"
        );
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let unsettled = unsettled_calls(&mut tx, employee, at(T0 + 1_000))
            .await
            .expect("read");
        assert_eq!(unsettled.len(), 1, "{unsettled:?}");
        assert_eq!(unsettled[0].idempotency_key, silent.as_str());

        // And a second answer cannot rewrite the first: only `in_flight` moves,
        // so a late arrival is refused rather than overwriting the `sid` a
        // person may already be reconciling against.
        assert!(
            !settle_send_intent(&mut tx, &answered, Err("too_late"), at(T0 + 2))
                .await
                .expect("settle"),
            "a settled row must not move again"
        );
        let (state, external_id, last_error): (String, Option<String>, Option<String>) =
            sqlx::query_as(
                "SELECT state, external_id, last_error FROM provider_intents \
                  WHERE idempotency_key = $1",
            )
            .bind(answered.as_str())
            .fetch_one(&mut **tx)
            .await
            .expect("read the settled row");
        tx.rollback().await.expect("rollback");
        assert_eq!(state, "succeeded");
        assert_eq!(external_id.as_deref(), Some("SM0001"));
        assert_eq!(last_error, None);

        teardown(&db, tenant).await;
    }
}
