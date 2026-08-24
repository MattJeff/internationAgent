//! The provisioning engine: eleven steps, one worker, no duplicate purchases.
//!
//! The engine drives an employee from "row in a table" to "can send email, own
//! a phone number and hold its own secrets". Everything here exists to make one
//! sentence true: **a crash never buys a second phone number.**
//!
//! # No registry
//!
//! There is no `Vec<Arc<dyn Provisioner>>` and no map from step to handler.
//! [`ProvisioningEngine::ensure_step`] reaches exactly one exhaustive `match`
//! over [`Step`] ([`ProvisioningEngine::call`]) and one over which adapter owns
//! it ([`adapter_of`]). Add a twelfth step and the build breaks in both places,
//! which is the entire point: a registry would have compiled fine and silently
//! never provisioned it.
//!
//! # The order steps run in
//!
//! Not [`Step::ALL`] order — that lists `Browser` *before* the `Vault` it loads
//! credentials from. The waves are computed from [`Step::depends_on`] on every
//! pass ([`plan_wave`]), so the dependency edges are the only source of order
//! and a new edge needs no change here. Within a wave the steps are independent
//! by construction and run concurrently in a bounded [`JoinSet`].
//!
//! # One step, in order
//!
//! ```text
//! tx1: sweep -> claim_step -> begin_intent            COMMIT   ("a call may happen")
//!      provider call, under tokio::time::timeout               (the crash window)
//! tx2: finish_step: resource + binding + outbox       COMMIT   (guarded by our lease)
//! ```
//!
//! The intent row is committed **before** the network call, so a process that
//! dies in the crash window leaves evidence. The timeout is not optional: an
//! unbounded await is how a worker hangs forever holding a lease that nobody
//! else may steal until it lapses.
//!
//! # Two ways to have a phone number
//!
//! [`EngineConfig::number_strategy`] decides whether `Step::Phone` buys a
//! number ([`NumberStrategy::Dedicated`], and unchanged) or takes a slot on one
//! the tenant already owns ([`NumberStrategy::Pooled`]). The pooled path is the
//! cheaper *regulatory* path, not the cheaper invoice: one French bundle and
//! one human review serve twenty employees instead of twenty of each. It buys
//! only when no slot is free, releases the slot rather than the number, and
//! spells its binding exactly like `Step::Whatsapp`'s shared company sender —
//! see `ProvisioningEngine::take_pooled_slot`.
//!
//! # Orphans are never retried
//!
//! An intent left `in_flight` by a worker whose lease has lapsed has an
//! **unknown outcome** — the phone number may or may not have been bought, and
//! nothing we hold says which. Retrying it is how you buy two. So the engine
//! files an approval for a human, marks the intent `orphaned`, and refuses to
//! touch that step again: every later pass sees the `orphaned` intent and
//! parks. The refusal is durable, not a flag in this process's memory.
//!
//! That is the *only* thing here that needs a human. A step that failed with an
//! answer — a 4xx, an exhausted retry budget — is retried freely, because the
//! adapter contract is reconcile-before-create and a retry with the same
//! [`agentos_domain::ids::IdempotencyKey`] finds what it already paid for.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use agentos_domain::action::{Action, McpTool};
use agentos_domain::employee::{Employee, Lifecycle, ProviderBinding, ResourceState, Step};
use agentos_domain::ids::{EmployeeId, IdempotencyKey, SecretRef, Slug, TenantId};
use agentos_domain::phone_pool::NumberStrategy;
use agentos_providers::browser::BrowserProvider;
use agentos_providers::email::EmailProvider;
use agentos_providers::secrets::{LocalEnvelopeSecretStore, SecretStore};
use agentos_providers::telephony::{Region, TelephonyProvider};
use agentos_providers::{EnsureCtx, ProviderError, Provisioned, Secret};
use agentos_store::approvals::{self, ApprovalError, NewApproval};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::employee;
use agentos_store::phone_pool;
use agentos_store::provisioning::{self, Claim, IntentState, StepOutcome};
use agentos_store::signing as keys;
use chrono::{DateTime, TimeDelta, Utc};
use rand::Rng;
use serde_json::json;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::gate::Principal;
use crate::identity::{Identity, IdentityError};
use crate::pool_ops;

/// Provider name for a resource that is us: no external system, nothing to
/// cancel, nothing to be billed for.
const LOCAL: &str = "agentos";

/// Provider name for an employee routed to the company's WhatsApp sender.
/// SPEC §6: one verified sender per company, employees are logically routed to
/// it — a dedicated sender per employee is deliberately not assumed.
const WHATSAPP_ROUTING: &str = "whatsapp-routing";

/// Name of the secret the vault step writes and reads back.
const VAULT_CANARY: &str = "provisioning-canary";

/// Who a reconciliation approval is filed against, and by.
const ENGINE_ACTOR: &str = "provisioning-engine";
/// The role a human must hold to act on an orphaned intent.
const RECONCILER_ROLE: &str = "operator";

/// The `constraint` [`provisioning::finish_step`] reports when our lease was
/// stolen while we were talking to the provider.
const LEASE_CONFLICT: &str = "employee_resources.lease_owner";

/// Reported when a tenant is configured to pool numbers in a region it owns no
/// number in. Not a wait and not a provider's fault: somebody pointed a
/// deployment at a pool that was never bought.
const EMPTY_POOL: &str = "empty_pool";

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// The four adapters a provisioning run can reach. Named fields, not a
/// registry: a step that needs a fifth adapter is a compile error in
/// [`ProvisioningEngine::call`], where somebody has to decide what it does.
pub struct Adapters {
    /// Mailbox and sending identity.
    pub email: Arc<dyn EmailProvider>,
    /// Numbers, SMS, WhatsApp.
    pub telephony: Arc<dyn TelephonyProvider>,
    /// Isolated browser contexts.
    pub browser: Arc<dyn BrowserProvider>,
    /// Where the employee's credentials live.
    pub secrets: Arc<dyn SecretStore>,
    /// The cipher that seals an employee's private signing key.
    ///
    /// Concrete, not `Arc<dyn SecretStore>`, and not the field above. What
    /// `Step::Identity` needs is the *cipher* half — `seal` and `open` — over
    /// rows that belong to `employee_signing_keys`, not the key/value map a
    /// `SecretStore` owns. See `crate::identity`, which makes the same choice
    /// for the same reason and explains it at length.
    pub envelope: Arc<LocalEnvelopeSecretStore>,
}

impl std::fmt::Debug for Adapters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait objects have nothing printable, and an adapter's Debug would be
        // the place a credential leaks anyway — as would the master key inside
        // the envelope cipher.
        f.write_str("Adapters { email, telephony, browser, secrets, envelope }")
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// The knobs a run needs. Every one of them is a real operational decision, so
/// none of them is hidden inside the algorithm.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// How long a claimed step is ours. Must comfortably exceed
    /// `max_attempts * (call_timeout + backoff_cap)`, or a slow-but-healthy run
    /// loses its lease mid-call and its result is thrown away.
    pub lease: TimeDelta,
    /// Hard ceiling on one provider call.
    pub call_timeout: Duration,
    /// Attempts per step, including the first.
    pub max_attempts: u32,
    /// First backoff. Doubles per attempt, capped, then jittered.
    pub backoff: Duration,
    /// Longest backoff, before jitter.
    pub backoff_cap: Duration,
    /// Steps run at once inside one wave.
    pub concurrency: usize,
    /// How many stuck steps one recovery sweep looks at.
    pub sweep_limit: i64,
    /// How long a human has to reconcile an orphaned intent.
    pub approval_ttl: TimeDelta,
    /// Where to buy phone numbers.
    pub region: Region,
    /// Whether an employee gets a number of its own or a slot on one the
    /// tenant already owns.
    ///
    /// A per-region operational decision, not a per-employee one, and
    /// deliberately not derived from [`Self::region`]: which countries make a
    /// number cost a human-reviewed regulatory bundle is the provider's
    /// opinion and it changes monthly. [`NumberStrategy::Dedicated`] is the
    /// default and behaves exactly as it always has.
    pub number_strategy: NumberStrategy,
    /// The company's verified WhatsApp sender, if it has one.
    pub whatsapp_sender: Option<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            lease: TimeDelta::seconds(120),
            call_timeout: Duration::from_secs(20),
            max_attempts: 3,
            backoff: Duration::from_millis(200),
            backoff_cap: Duration::from_secs(5),
            concurrency: 4,
            sweep_limit: 100,
            // A possibly-bought resource is a billing question; a day is not
            // enough for a human to get to it, and a month is not urgency.
            approval_ttl: TimeDelta::days(7),
            region: Region::new("US"),
            // A US number needs no bundle and a number of one's own is a
            // better identity where it is free.
            number_strategy: NumberStrategy::Dedicated,
            whatsapp_sender: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// What one step came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepReport {
    /// Provisioned, or already was.
    Ready,
    /// The call landed and something outside our control has to bless it. The
    /// run moved on; a provider callback resolves it later.
    PendingExternal {
        /// Handle to poll, or to match a callback against.
        poll_ref: String,
    },
    /// Terminal, or out of attempts. Retryable by a later run.
    Failed {
        /// Low-cardinality label, safe as a metric dimension.
        code: &'static str,
    },
    /// **Unknown outcome.** A worker died mid-call; an approval is filed and
    /// this step will not be touched again until a human reconciles it.
    Parked,
    /// An operator suspended or terminated the employee, so nothing is
    /// provisioned for it. Not a failure and not a wait: a refusal to spend
    /// money on an employee that is not going to use it.
    Inactive,
    /// Another worker holds the lease.
    Busy,
    /// Our lease lapsed and was stolen while we were talking to the provider,
    /// so the result was thrown away rather than written over the new owner's.
    LeaseLost,
    /// A dependency is not ready, so this step cannot be either.
    Blocked {
        /// The unmet dependency.
        on: Step,
    },
}

impl StepReport {
    /// Did this step reach its desired state?
    pub const fn is_ready(&self) -> bool {
        matches!(self, StepReport::Ready)
    }

    /// Stable metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            StepReport::Ready => "ready",
            StepReport::PendingExternal { .. } => "pending_external",
            StepReport::Failed { code } => code,
            StepReport::Parked => "parked",
            StepReport::Inactive => "inactive",
            StepReport::Busy => "busy",
            StepReport::LeaseLost => "lease_lost",
            StepReport::Blocked { .. } => "blocked",
        }
    }
}

// The server may not name `agentos-providers`, so the one release code it has
// to branch on is re-exported here alongside the report that carries it.
pub use agentos_providers::RELEASE_NOT_SUPPORTED;

/// What one release came to.
///
/// Deliberately not a [`StepReport`]: a release has three outcomes and none of
/// `Parked`, `Busy`, `LeaseLost` or `Blocked` is one of them. Releasing is safe
/// to repeat and safe to race, so it needs neither a lease nor a human — see
/// [`ProvisioningEngine::release_step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseReport {
    /// The resource is gone and the binding is cleared. Also the answer when
    /// the provider had already lost it: same desired state, same report.
    Released,
    /// Nothing was ever bound, so there is nothing out there costing anything.
    NotBound,
    /// The provider would not let go. **The binding is still there**, on
    /// purpose: the resource still exists, somebody is still being billed, and
    /// the external id is the only thing that says what to cancel.
    Failed {
        /// Low-cardinality label, safe as a metric dimension.
        code: &'static str,
    },
}

impl ReleaseReport {
    /// Is there nothing left to give back for this step?
    pub const fn is_done(&self) -> bool {
        matches!(self, ReleaseReport::Released | ReleaseReport::NotBound)
    }

    /// Stable metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            ReleaseReport::Released => "released",
            ReleaseReport::NotBound => "not_bound",
            ReleaseReport::Failed { code } => code,
        }
    }
}

/// The engine could not reach a verdict. Not "the step failed" — that is a
/// [`StepReport`] — but "the database would not answer".
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Storage refused.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The reconciliation approval could not be filed, which means an orphaned
    /// intent would go unnoticed. Loud on purpose.
    #[error("could not file a reconciliation approval: {0}")]
    Approval(#[from] ApprovalError),
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// One provisioning worker.
///
/// Cheap to clone; clones share the pool and the adapters but each `new` gets a
/// fresh `worker_id`, which is what a lease is held by. Clone for concurrency
/// within one worker; `new` again to model a restarted process.
#[derive(Debug, Clone)]
pub struct ProvisioningEngine {
    db: Db,
    adapters: Arc<Adapters>,
    cfg: Arc<EngineConfig>,
    worker_id: Uuid,
}

impl ProvisioningEngine {
    /// Wire an engine to a database, its adapters and its knobs.
    pub fn new(db: Db, adapters: Adapters, cfg: EngineConfig) -> Self {
        Self {
            db,
            adapters: Arc::new(adapters),
            cfg: Arc::new(cfg),
            worker_id: Uuid::now_v7(),
        }
    }

    /// The identity this worker's leases are held by.
    pub const fn worker_id(&self) -> Uuid {
        self.worker_id
    }

    /// Drive every step of one employee as far as it will go, in dependency
    /// order, and report what each came to.
    ///
    /// Idempotent, and that is the whole product requirement: run it twice, run
    /// it after a crash, run it from two workers — it converges on the same
    /// resources rather than creating a second set.
    pub async fn converge(
        &self,
        tenant_id: TenantId,
        employee_id: EmployeeId,
    ) -> Result<BTreeMap<Step, StepReport>, EngineError> {
        let mut reports = BTreeMap::new();
        let mut pending: Vec<Step> = Step::ALL.to_vec();

        while !pending.is_empty() {
            // Reloaded per wave: the previous wave's writes are what unblock
            // this one, and they went to the database, not to this snapshot.
            let employee = Arc::new(self.load(tenant_id, employee_id).await?);
            let (done, runnable, blocked) = plan_wave(&employee, &pending);
            for step in done {
                reports.insert(step, StepReport::Ready);
            }

            if runnable.is_empty() {
                for step in blocked {
                    let on = first_unmet(&employee, step).unwrap_or(step);
                    reports.insert(step, StepReport::Blocked { on });
                }
                break;
            }

            for (step, report) in self.run_wave(&employee, runnable).await? {
                reports.insert(step, report);
            }
            pending = blocked;
        }

        Ok(reports)
    }

    /// Make one step true, exactly once.
    ///
    /// `employee` supplies the slug, the existing binding and the dependency
    /// states; it is a snapshot, and every decision that must not race is taken
    /// against the database inside a transaction.
    pub async fn ensure_step(
        &self,
        employee: &Employee,
        step: Step,
    ) -> Result<StepReport, EngineError> {
        // Nothing is bought for an employee an operator has retired. The
        // provisioning loop's claim query already filters on lifecycle, but
        // this engine is public and `release_all` leaves rows in `disabled` —
        // which *is* claimable. Without this guard, converging a terminated
        // employee buys it a fresh phone number that nobody will ever look at,
        // one release after somebody carefully gave the old one back.
        if !matches!(employee.lifecycle(), Lifecycle::Draft | Lifecycle::Active) {
            return Ok(StepReport::Inactive);
        }
        if let Some(blocker) = first_unmet(employee, step) {
            return Ok(StepReport::Blocked { on: blocker });
        }
        match employee.resource(step).state() {
            ResourceState::Ready => return Ok(StepReport::Ready),
            // Only a provider callback moves this along; a worker that claimed
            // it would spin.
            ResourceState::PendingExternal { poll_ref, .. } => {
                return Ok(StepReport::PendingExternal {
                    poll_ref: poll_ref.clone(),
                });
            }
            ResourceState::Pending
            | ResourceState::Provisioning
            | ResourceState::Failed
            | ResourceState::Disabled => {}
        }

        let claim = match self.claim(employee, step).await? {
            Claimed::Mine(claim) => claim,
            Claimed::Busy => return Ok(StepReport::Busy),
            Claimed::Parked => return Ok(StepReport::Parked),
        };

        // A pooled number is not bought, it is *joined*: the tenant already
        // owns it and this employee takes a slot on it. Handled before the
        // crash window because there is no call to be uncertain about — the
        // slot and the binding are one commit. See [`Self::take_pooled_slot`].
        //
        // It falls through only when every number in the region is at
        // capacity. The one way a pool grows is somebody buying another
        // number, so that case goes on to the provider — and in a region worth
        // pooling that number needs a regulatory bundle, so the answer is the
        // `PendingExternal` the Twilio path has always returned. The wait
        // already exists; a second waiting mechanism for it would not.
        if step == Step::Phone
            && matches!(self.cfg.number_strategy, NumberStrategy::Pooled)
            && let Some(report) = self.take_pooled_slot(employee, &claim).await?
        {
            return Ok(report);
        }

        // The crash window. Nothing is held open across it: no transaction, no
        // row lock — only the lease, and it expires by itself.
        let (outcome, report) = match self.call_until(employee, step, &claim).await {
            Ok(binding) => (StepOutcome::Ready { binding }, StepReport::Ready),
            Err(ProviderError::PendingExternal {
                poll_ref,
                expected_by,
            }) => (
                StepOutcome::PendingExternal {
                    poll_ref: poll_ref.clone(),
                    expected_by,
                },
                StepReport::PendingExternal { poll_ref },
            ),
            Err(err) => (
                StepOutcome::Failed {
                    error: format!("{}: {err}", err.code()),
                },
                StepReport::Failed { code: err.code() },
            ),
        };
        self.finish(employee.tenant_id(), &claim, outcome, report)
            .await
    }

    /// Put this employee on a number the tenant already owns.
    ///
    /// `Ok(None)` means the region has numbers but no room on any of them, and
    /// the caller falls through to the provider. [`PoolError::Full`] and
    /// [`PoolError::AwaitingBundle`] are deliberately not told apart here: both
    /// say the same thing to this engine — *ask for another number* — and the
    /// adapter answers with the bundle to poll and when to expect it, which is
    /// the wait, spelled the one way this system spells waits.
    /// [`PoolError::Empty`] is the third one, and it is nobody's wait: a
    /// deployment pooling a region it never bought into provisions nobody, so
    /// it fails loudly rather than quietly buying a dedicated number and
    /// looking like it worked.
    ///
    /// # Nothing here reaches a provider
    ///
    /// A slot is a row about a number that already exists, so `ensure_number`
    /// is not called. That is the entire point: one French bundle and one human
    /// review serve twenty employees instead of twenty of each.
    ///
    /// # A crash cannot leak a slot
    ///
    /// The allocation and the binding are the **same commit**, so there is no
    /// window in which a slot is taken and nothing points at it — a process
    /// that dies before the commit leaves neither, and one that dies after it
    /// leaves a step that is simply `Ready`. And a slot that did commit cannot
    /// be doubled by any retry from anywhere: `allocate_atomic` hands back the
    /// seat this employee already holds, and
    /// `number_allocations_live_employee_region_key` refuses a second live one
    /// even to a worker that raced past that check. Ensure twice, one slot.
    ///
    /// [`PoolError::Full`]: agentos_domain::phone_pool::PoolError::Full
    /// [`PoolError::AwaitingBundle`]: agentos_domain::phone_pool::PoolError::AwaitingBundle
    /// [`PoolError::Empty`]: agentos_domain::phone_pool::PoolError::Empty
    async fn take_pooled_slot(
        &self,
        employee: &Employee,
        claim: &Claim,
    ) -> Result<Option<StepReport>, EngineError> {
        let now = Utc::now();
        let region = self.cfg.region.as_str();
        let mut tx = self.db.tenant_tx(employee.tenant_id()).await?;

        let Some(seat) = phone_pool::allocate_atomic(&mut tx, employee.id(), region, now).await?
        else {
            // No room. `allocate_atomic` says "full" and "there is no pool"
            // with the same `None`, and they need two different humans.
            let owned: i64 =
                sqlx::query_scalar("SELECT count(*) FROM phone_numbers WHERE region = $1")
                    .bind(region)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(StoreError::from)?;
            tx.rollback().await?;
            if owned > 0 {
                return Ok(None);
            }
            tracing::error!(
                tenant = %employee.tenant_id().as_uuid(), region,
                "pooled number strategy, but this tenant owns no number in this region: \
                 nobody gets a phone until one is registered"
            );
            return self
                .finish(
                    employee.tenant_id(),
                    claim,
                    StepOutcome::Failed {
                        error: format!("{EMPTY_POOL}: the tenant owns no {region} number"),
                    },
                    StepReport::Failed { code: EMPTY_POOL },
                )
                .await
                .map(Some);
        };

        // Same convention as `Step::Whatsapp`'s shared company sender, because
        // it is the same problem: the employee id is in the external id so that
        // N employees on one number are N distinct rows under
        // `employee_resources_provider_external_id_key`, and so that a slot's
        // id can never be mistaken for the number's own provider id by
        // something that deletes.
        let binding = pool_ops::slot_binding(&seat.e164, employee.id());
        match provisioning::finish_step(&mut tx, claim, StepOutcome::Ready { binding }, now).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(Some(StepReport::Ready))
            }
            Err(StoreError::Conflict(what)) if what == LEASE_CONFLICT => {
                // The seat goes back with the rollback: this worker is not the
                // one writing this employee's phone any more.
                tx.rollback().await?;
                Ok(Some(StepReport::LeaseLost))
            }
            Err(err) => {
                tx.rollback().await?;
                Err(err.into())
            }
        }
    }

    // -- releasing ---------------------------------------------------------

    /// Give back everything this employee holds, dependents first.
    ///
    /// The order is [`release_order`]: the dependency graph topologically
    /// sorted and then **reversed**, so the browser context goes before the
    /// vault its credentials live in, and identity goes last. Derived from
    /// [`Step::depends_on`] on every call for the same reason `converge`
    /// derives the forward order — a hardcoded list is a list that will not
    /// notice a new edge.
    ///
    /// Sequential, not a [`JoinSet`]: the order *is* the point.
    ///
    /// Idempotent. A second run reports [`ReleaseReport::NotBound`] for
    /// everything the first one freed and retries only what failed, which is
    /// what makes it safe to hang off a retried outbox event.
    pub async fn release_all(
        &self,
        employee: &Employee,
    ) -> Result<BTreeMap<Step, ReleaseReport>, EngineError> {
        self.release_steps(employee, &Step::ALL).await
    }

    /// [`Self::release_all`], narrowed to `steps`.
    ///
    /// Same order, same idempotency, same reports — the caller only chooses
    /// *which* steps are asked about. That choice belongs to the caller because
    /// the reason to leave one out is never something the engine can see: the
    /// termination sweeper skips a step whose provider has already refused
    /// structurally ([`RELEASE_NOT_SUPPORTED`]), and that fact lives in the
    /// resource row's `last_error`, not in the [`Employee`] aggregate.
    ///
    /// The order still comes from [`release_order`] rather than from the order
    /// `steps` happens to be in, so a caller cannot release the vault before
    /// the browser profile whose credentials live in it by passing a bad list.
    pub async fn release_steps(
        &self,
        employee: &Employee,
        steps: &[Step],
    ) -> Result<BTreeMap<Step, ReleaseReport>, EngineError> {
        let mut reports = BTreeMap::new();
        for step in release_order().into_iter().filter(|s| steps.contains(s)) {
            let report = self.release_step(employee, step).await?;
            if let ReleaseReport::Failed { code } = &report {
                // Loud, and then carry on: one provider refusing is no reason
                // to leave the other ten resources running.
                tracing::error!(
                    employee = %employee.id().as_uuid(), %step, code,
                    "could not release a provider resource; it is still bound and still billed"
                );
            }
            reports.insert(step, report);
        }
        Ok(reports)
    }

    /// Give one resource back, and only then forget its id.
    ///
    /// # Why this has no lease and no write-ahead intent
    ///
    /// `ensure_step` writes its intent *before* the call and parks a step whose
    /// outcome nobody knows, because a created-but-unrecorded resource is
    /// invisible and a blind retry buys a second one. Release is the mirror
    /// image: every adapter is required to be idempotent and to tolerate a
    /// resource that is already gone, so a call whose outcome was lost costs
    /// nothing but another call. There is no orphan to park, no human to ask,
    /// and no reason to serialise two workers that both want the same resource
    /// destroyed.
    ///
    /// What does matter is the write order, and it is the opposite of ensure's:
    /// **ask the provider first, clear the binding second.** A crash in that
    /// window leaves the binding intact and the resource findable, and the next
    /// pass tries again. Clearing first and crashing would leave a paid-for
    /// resource with nothing left pointing at it.
    ///
    /// A refusal is recorded rather than retried in-process: the binding stays,
    /// the row carries the reason, and the caller's own retry (the outbox event
    /// that asked for the termination) comes back round.
    pub async fn release_step(
        &self,
        employee: &Employee,
        step: Step,
    ) -> Result<ReleaseReport, EngineError> {
        let Some(binding) = employee.resource(step).binding().cloned() else {
            // Never bound, or already released. Either way nothing out there is
            // costing anything, and that is a success.
            return Ok(ReleaseReport::NotBound);
        };

        // A pooled slot is given back to the tenant's pool, and to nobody else.
        //
        // **Do not "fix" the missing provider call here.**
        // `TelephonyProvider::release` is `DELETE IncomingPhoneNumbers/{sid}`.
        // There is no "give up our share" of a shared number: it takes the
        // number off the account, cutting off every colleague still sending
        // from it and throwing away a regulatory bundle that cost a human
        // review to obtain. The number is the tenant's property and one
        // employee leaving is not an instruction to give it back. Freeing the
        // row *is* the release, exactly as it is for `Step::Whatsapp`, whose
        // company sender is shared the same way and released the same way.
        let pooled = step == Step::Phone && pool_ops::is_pooled(&binding);

        // No transaction is open across this, and the timeout is not optional
        // for the same reason it is not optional in `call_until`.
        let outcome = if pooled {
            Ok(())
        } else {
            match tokio::time::timeout(
                self.cfg.call_timeout,
                self.release_call(employee, step, &binding),
            )
            .await
            {
                Ok(result) => result,
                Err(_elapsed) => Err(ProviderError::timeout()),
            }
        };

        let now = Utc::now();
        let mut tx = self.db.tenant_tx(employee.tenant_id()).await?;
        if pooled {
            // In the same transaction as the binding clear below: the seat and
            // the thing that names it go together in both directions.
            //
            // ponytail: keyed by the engine's configured region, which is the
            // region the slot was taken in. A deployment that changes region
            // under a live employee wants a migration, not a lookup here.
            let freed = phone_pool::release(&mut tx, employee.id(), self.cfg.region.as_str(), now)
                .await?
                .is_some();
            tracing::info!(
                employee = %employee.id().as_uuid(), freed,
                "pooled slot returned to the tenant's pool; the number stays"
            );
        }
        let stored = employee::load(&mut tx, employee.id()).await?;
        let mut current = stored.employee;

        let report = match &outcome {
            Ok(()) => {
                // `Employee::release` is the only thing in the system that
                // clears a binding, and this is the only place that calls it.
                // Guarded on the id we actually released: if the stored binding
                // has moved on since the snapshot, it names a different
                // resource and forgetting it would strand that one instead.
                if current.resource(step).binding() == Some(&binding) {
                    current.release(step, now);
                }
                // Released, not merely unbound. `Disabled` is the domain's word
                // for "deliberately off for this employee", which is exactly
                // what a terminated employee's resources are.
                if let Err(err) = current.set_resource(step, ResourceState::Disabled, now) {
                    tracing::warn!(%step, error = %err, "released, but could not disable the row");
                }
                ReleaseReport::Released
            }
            Err(err) => {
                // The binding is untouched, on purpose: the resource is still
                // out there and the external id is what says so.
                if let Err(err) = current.set_resource(step, ResourceState::Failed, now) {
                    tracing::warn!(%step, error = %err, "could not mark a failed release");
                }
                ReleaseReport::Failed { code: err.code() }
            }
        };

        employee::update(&mut tx, &current, stored.version).await?;
        // Only steps that reach a provider get a row, exactly as with the
        // provisioning intent: a resource that is us has no outcome to be
        // uncertain about.
        if let Some(adapter) = adapter_of(step) {
            let error = outcome
                .as_ref()
                .err()
                .map(|err| format!("release {}: {err}", err.code()));
            provisioning::record_release(
                &mut tx,
                employee.id(),
                step,
                adapter,
                error.as_deref(),
                now,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(report)
    }

    /// **The exhaustive match, in the other direction.** What giving each step
    /// back actually means.
    ///
    /// No `_` arm, like [`ProvisioningEngine::call`]: a twelfth [`Step`] has to
    /// answer "who cancels this, and what does it cost until somebody does"
    /// before it compiles.
    async fn release_call(
        &self,
        employee: &Employee,
        step: Step,
        binding: &ProviderBinding,
    ) -> Result<(), ProviderError> {
        let binding = agentos_providers::ProviderBinding {
            provider: binding.provider().to_owned(),
            external_id: binding.external_id().to_owned(),
        };
        match step {
            Step::Email => self.adapters.email.release(&binding).await,
            // Only ever a number of this employee's own: `release_step`
            // short-circuits a pooled slot before it gets here, because this
            // call would delete a number four colleagues are still using.
            Step::Phone => self.adapters.telephony.release(&binding).await,
            Step::Browser => self.adapters.browser.release(&binding).await,

            // The vault has no per-resource handle to hand back: the resource
            // *is* the employee's subtree, and `delete_prefix` is the store's
            // own word for offboarding. Deleting nothing is not an error there
            // either, so this is idempotent for free.
            Step::Vault => {
                let gone = self
                    .adapters
                    .secrets
                    .delete_prefix(employee.tenant_id(), Some(employee.id()))
                    .await?;
                tracing::info!(secrets = gone, "vault subtree deleted");
                Ok(())
            }

            // **The employee's private key is destroyed here, and it is not
            // coming back.**
            //
            // Note first what `delete_prefix` above does *not* reach: the
            // sealed private key is not a `SecretStore` row, it is a column in
            // `employee_signing_keys` (see `crate::identity`, which explains
            // why the two are kept apart). So the vault's release does not
            // touch it, and without this arm an offboarded employee's key would
            // outlive it forever.
            //
            // # Destroy, rather than merely stop publishing
            //
            // Publication has *already* stopped: `signing::published_keys`
            // joins on `lifecycle = 'active'`, so the moment an operator
            // terminates an employee its key leaves the JWKS and old signatures
            // stop verifying for anyone who refetches. Destroying the private
            // half changes nothing about that, which is exactly why it is safe.
            //
            // What it does change is that nobody can ever sign in this
            // employee's name again — not with the master key, not with a
            // database dump, not with both. `Lifecycle::Terminated` is
            // absorbing, so there is no future in which that key is wanted,
            // and a sealed private key for an identity that is never coming
            // back is pure liability: one master-key compromise away from a
            // signature a counterparty who cached the old directory still
            // believes.
            //
            // The thing it might have cost — being able to answer "did this
            // employee sign that?" about an old signature — it does not cost.
            // That question is answered by verifying against the published key
            // and by the `message_signed` rows, which carry the `kid` and the
            // payload digest under the ruling that permitted them. Nobody
            // re-proves an old signature by making a new one. The trail
            // survives; the ability to forge does not.
            //
            // Suspension deliberately does **not** come through here: it is
            // reversible, publication already stops, and a suspended employee
            // that is reinstated keeps the identity its counterparties know.
            Step::Identity => {
                let mut tx = self
                    .db
                    .tenant_tx(employee.tenant_id())
                    .await
                    .map_err(|_| ProviderError::timeout())?;
                // Idempotent by the store's own contract: deleting a key that
                // is already gone is `Ok(false)`, which is the desired state.
                let destroyed = keys::delete(&mut tx, employee.id())
                    .await
                    .map_err(|_| ProviderError::timeout())?;
                tx.commit().await.map_err(|_| ProviderError::timeout())?;
                tracing::info!(
                    employee = %employee.id().as_uuid(), destroyed,
                    "signing key destroyed; this employee can never sign again"
                );
                Ok(())
            }

            // Ours. The row is the resource: no external system, nothing to
            // cancel, nobody billing us. Clearing the binding *is* the release.
            Step::Whatsapp
            | Step::Wallet
            | Step::CompanyKnowledge
            | Step::Mcp
            | Step::A2a
            | Step::Permissions => Ok(()),
        }
    }

    // -- transactions ------------------------------------------------------

    /// tx1: recover, claim, and write the intent before anything is called.
    async fn claim(&self, employee: &Employee, step: Step) -> Result<Claimed, EngineError> {
        let now = Utc::now();
        let mut tx = self.db.tenant_tx(employee.tenant_id()).await?;

        // Recovery runs before the claim, because claiming overwrites the very
        // lease that makes a dead worker visible.
        let crashed = provisioning::sweep_expired_leases(&mut tx, now, self.cfg.sweep_limit)
            .await?
            .into_iter()
            .any(|stuck| {
                stuck.employee_id == employee.id()
                    && stuck.step == step
                    && stuck.in_flight_provider.is_some()
            });
        if crashed {
            // Somebody called a provider for this step and never came back.
            // Whether the resource exists is unknowable from here, so this step
            // is not claimed, not retried, and not touched again: the intent
            // becomes `orphaned`, which every later pass will see, and a human
            // gets the question.
            let key = IdempotencyKey::for_step(employee.id(), step.as_str());
            provisioning::mark_intent_orphaned(&mut tx, &key, now).await?;
            self.file_reconciliation(&mut tx, employee, step, now)
                .await?;
            tx.commit().await?;
            tracing::warn!(
                employee = %employee.id().as_uuid(), step = %step,
                "orphaned provider intent; parked for a human rather than retried"
            );
            return Ok(Claimed::Parked);
        }

        let Some(claim) = provisioning::claim_step(
            &mut tx,
            employee.id(),
            step,
            self.worker_id,
            self.cfg.lease,
            now,
        )
        .await?
        else {
            tx.rollback().await?;
            // Ready, pending_external, or held by a live worker. The caller's
            // snapshot already ruled the first two out, so: busy.
            return Ok(Claimed::Busy);
        };

        let Some(adapter) = adapter_of(step) else {
            // Nothing to call, so nothing to be uncertain about, so no
            // write-ahead log entry. An intent that can never be orphaned is
            // a row that only makes the sweep slower.
            tx.commit().await?;
            return Ok(Claimed::Mine(claim));
        };

        let intent = provisioning::begin_intent(
            &mut tx,
            &claim,
            adapter,
            &json!({ "step": step.as_str(), "attempt": claim.attempt() }),
            now,
        )
        .await?;

        if intent == IntentState::Orphaned {
            // Already parked by an earlier pass. Roll back so this pass leaves
            // no trace at all — including the claim we just took.
            tx.rollback().await?;
            return Ok(Claimed::Parked);
        }

        tx.commit().await?;
        Ok(Claimed::Mine(claim))
    }

    /// tx2: resource state, binding and outbox event, in one transaction,
    /// guarded by `lease_owner = me`.
    async fn finish(
        &self,
        tenant_id: TenantId,
        claim: &Claim,
        outcome: StepOutcome,
        report: StepReport,
    ) -> Result<StepReport, EngineError> {
        let mut tx = self.db.tenant_tx(tenant_id).await?;
        match provisioning::finish_step(&mut tx, claim, outcome, Utc::now()).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(report)
            }
            Err(StoreError::Conflict(what)) if what == LEASE_CONFLICT => {
                tx.rollback().await?;
                Ok(StepReport::LeaseLost)
            }
            // Anything else — notably the (provider, external_id) unique index,
            // which means this resource is already bound to another employee —
            // is an alarm, not a step outcome.
            Err(err) => {
                tx.rollback().await?;
                Err(err.into())
            }
        }
    }

    /// File the one thing a human must look at: a provider call whose outcome
    /// nobody knows.
    ///
    /// ponytail: an `Action::McpCall` named `provisioning/<step>`, because
    /// `Action` is a closed domain enum with no "reconcile a provider resource"
    /// variant and it is not mine to widen. The `reason` carries the whole
    /// story; add a real variant the day a second operator workflow needs one.
    async fn file_reconciliation(
        &self,
        tx: &mut TenantTx<'_>,
        employee: &Employee,
        step: Step,
        now: DateTime<Utc>,
    ) -> Result<(), EngineError> {
        let action = Action::McpCall {
            tool: reconcile_tool(step),
        };
        let reason = format!(
            "{} may already have created the {step} resource for employee {}: the worker \
             died mid-call and the outcome is unknown. Reconcile at the provider \
             (idempotency key {}) before retrying — a blind retry is how you end up \
             paying for two.",
            adapter_of(step).unwrap_or(LOCAL),
            employee.id().as_uuid(),
            IdempotencyKey::for_step(employee.id(), step.as_str()).as_str(),
        );
        approvals::create(
            tx,
            &NewApproval {
                employee_id: Some(employee.id()),
                action: &action,
                requested_by: ENGINE_ACTOR,
                required_role: RECONCILER_ROLE,
                reason: Some(&reason),
                expires_at: now + self.cfg.approval_ttl,
            },
            now,
        )
        .await?;
        Ok(())
    }

    // -- the call ----------------------------------------------------------

    /// The provider call, timed out, retried on backoff, and never retried past
    /// an answer.
    async fn call_until(
        &self,
        employee: &Employee,
        step: Step,
        claim: &Claim,
    ) -> Result<ProviderBinding, ProviderError> {
        let mut ctx = EnsureCtx::new(
            employee.tenant_id(),
            employee.id(),
            employee.slug().clone(),
            step.as_str(),
        );
        if let Some(existing) = employee.resource(step).binding() {
            ctx = ctx.with_existing(agentos_providers::ProviderBinding {
                provider: existing.provider().to_owned(),
                external_id: existing.external_id().to_owned(),
            });
        }
        // Both sides derive `IdempotencyKey::for_step(employee, step)`, so the
        // key a provider is called under is always the one this worker holds
        // the claim under. There is no path where they drift.
        debug_assert_eq!(&ctx.idempotency_key, claim.idempotency_key());

        for attempt in 0..self.cfg.max_attempts.max(1) {
            // An unbounded await is how a worker hangs forever holding a lease.
            let err =
                match tokio::time::timeout(self.cfg.call_timeout, self.call(employee, step, &ctx))
                    .await
                {
                    Ok(Ok(binding)) => return Ok(binding),
                    Ok(Err(err)) => err,
                    // The request may even have landed — which is exactly what
                    // reconcile-before-create protects the retry against.
                    Err(_elapsed) => ProviderError::timeout(),
                };

            if !err.is_retryable() || attempt + 1 >= self.cfg.max_attempts.max(1) {
                return Err(err);
            }
            tokio::time::sleep(backoff(&self.cfg, attempt, &err)).await;
            ctx = ctx.retry();
        }
        // `max_attempts.max(1)` guarantees at least one iteration, and every
        // path out of it returns.
        unreachable!("the retry loop always returns")
    }

    /// **The exhaustive match.** What each of the eleven steps actually means.
    ///
    /// No `_` arm, so a twelfth [`Step`] does not compile until somebody
    /// decides what provisioning it needs — which is the only way this stays
    /// honest, because a step nobody implemented looks exactly like a step
    /// nobody needs until an employee cannot do its job.
    async fn call(
        &self,
        employee: &Employee,
        step: Step,
        ctx: &EnsureCtx,
    ) -> Result<ProviderBinding, ProviderError> {
        match step {
            // Identity is the one "local" step that produces something: the
            // employee's Ed25519 keypair, which is what makes it verifiable to
            // a stranger. Everything downstream — the JWKS at
            // `/.well-known/http-message-signatures-directory`, every signed
            // outbound A2A request — is that key, so minting it here is what
            // makes `Step::Identity` mean anything beyond writing a DID string
            // into a column.
            //
            // # A retry cannot mint a second key
            //
            // `Identity::ensure_key` is `INSERT … ON CONFLICT DO NOTHING`
            // followed by a read-back, against a table whose primary key is
            // `(tenant_id, employee_id)`. That is the same guarantee
            // `IdempotencyKey` buys for the phone number, arrived at the other
            // way round: a number lives at Twilio, where the only way to ask
            // "did I already buy this?" is to present a key the provider
            // remembers, so the key is the reconciliation. A signing key lives
            // in our own database, where the question is a unique constraint —
            // which is strictly stronger, because it cannot be lost, cannot
            // expire, and does not depend on a provider honouring it.
            //
            // That is also why this step still has no write-ahead intent (see
            // `adapter_of`): an intent exists to make a *possibly-created,
            // unrecorded* resource visible after a crash, and there is no such
            // state here. The mint commits or it does not; a worker that dies
            // mid-`ensure_key` leaves either no row or a complete one, and the
            // next pass converges on whichever it is.
            Step::Identity => {
                self.identity(employee)
                    .ensure_key()
                    .await
                    .map_err(mint_failure)?;
                Ok(ProviderBinding::new(LOCAL, employee.did().to_owned()))
            }
            Step::Wallet => Ok(local(employee, "wallet")),
            Step::CompanyKnowledge => Ok(local(employee, "knowledge")),
            Step::Mcp => Ok(local(employee, "mcp")),
            Step::A2a => Ok(local(employee, "a2a")),
            Step::Permissions => Ok(local(employee, "permissions")),

            Step::Email => Ok(bind(self.adapters.email.ensure_identity(ctx).await?)),
            // Under `NumberStrategy::Pooled` this is only reached when the pool
            // has no free slot, i.e. as the request that grows it. In a region
            // worth pooling the adapter answers `PendingExternal` with a bundle
            // in human review, which is the wait; where it answers with a
            // number, the employee has one of its own and releases it as such.
            Step::Phone => Ok(bind(
                self.adapters
                    .telephony
                    .ensure_number(ctx, &self.cfg.region)
                    .await?,
            )),
            Step::Browser => Ok(bind(self.adapters.browser.ensure_context(ctx).await?)),

            // One verified company sender, employees routed to it. The routing
            // address carries the employee id so two employees on one sender
            // cannot collide on the (provider, external_id) unique index.
            Step::Whatsapp => match &self.cfg.whatsapp_sender {
                Some(sender) => Ok(ProviderBinding::new(
                    WHATSAPP_ROUTING,
                    format!("{sender}/{}", employee.id().as_uuid()),
                )),
                None => Err(ProviderError::Terminal {
                    code: "no_whatsapp_sender",
                }),
            },

            // The store has no `ensure`: a namespace exists once something is
            // in it. Writing this step's own tag and reading it back is the
            // smallest honest proof that this employee's secrets are storable
            // and retrievable, and it is idempotent by ref.
            Step::Vault => {
                let canary = SecretRef::new(employee.tenant_id(), employee.id(), VAULT_CANARY)
                    .map_err(|_| ProviderError::Terminal {
                        code: "bad_secret_ref",
                    })?;
                self.adapters
                    .secrets
                    .put(&canary, &Secret::new(ctx.tag()))
                    .await?;
                self.adapters.secrets.get(&canary).await?;
                Ok(local(employee, "vault"))
            }
        }
    }

    // -- plumbing ----------------------------------------------------------

    /// This employee's signing identity, over the engine's own pool and cipher.
    fn identity(&self, employee: &Employee) -> Identity {
        Identity::new(
            self.db.clone(),
            Arc::clone(&self.adapters.envelope),
            Principal::employee(employee.tenant_id(), employee.id()),
        )
    }

    async fn load(
        &self,
        tenant_id: TenantId,
        employee_id: EmployeeId,
    ) -> Result<Employee, EngineError> {
        let mut tx = self.db.tenant_tx(tenant_id).await?;
        let stored = employee::load(&mut tx, employee_id).await?;
        tx.rollback().await?;
        Ok(stored.employee)
    }

    /// Run independent steps at once, never more than `concurrency` in flight.
    async fn run_wave(
        &self,
        employee: &Arc<Employee>,
        steps: Vec<Step>,
    ) -> Result<Vec<(Step, StepReport)>, EngineError> {
        let limit = self.cfg.concurrency.max(1);
        let mut queue = steps.into_iter();
        let mut set: JoinSet<(Step, Result<StepReport, EngineError>)> = JoinSet::new();
        let mut out = Vec::new();

        loop {
            while set.len() < limit {
                let Some(step) = queue.next() else { break };
                let engine = self.clone();
                let employee = Arc::clone(employee);
                set.spawn(async move { (step, engine.ensure_step(&employee, step).await) });
            }
            let Some(joined) = set.join_next().await else {
                break;
            };
            let (step, result) = joined.expect("a provisioning step panicked");
            // `?` drops the set, which aborts the siblings mid-call — the same
            // shape as the process dying, and handled the same way: their
            // intents are found `in_flight` next time and parked rather than
            // retried. An `EngineError` means the database is gone, so they
            // were about to fail at their own `finish` anyway.
            out.push((step, result?));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Which adapter owns each step, and `None` for the steps that reach no
/// network — which is exactly the set that needs no write-ahead log entry,
/// because there is nothing to be uncertain about.
///
/// Exhaustive, like [`ProvisioningEngine::call`]: a new step must answer this
/// question too.
const fn adapter_of(step: Step) -> Option<&'static str> {
    match step {
        Step::Email => Some("email"),
        Step::Phone => Some("telephony"),
        Step::Browser => Some("browser"),
        Step::Vault => Some("secrets"),
        Step::Identity
        | Step::Whatsapp
        | Step::Wallet
        | Step::CompanyKnowledge
        | Step::Mcp
        | Step::A2a
        | Step::Permissions => None,
    }
}

/// Exponential, capped, then full-jittered: a fleet of workers that failed
/// together must not come back together, which is how a struggling provider
/// gets a second wave exactly when it is least able to serve one.
fn backoff(cfg: &EngineConfig, attempt: u32, err: &ProviderError) -> Duration {
    // The provider's own advice wins when it gave any.
    let base = match err {
        ProviderError::Retryable { after } => *after,
        ProviderError::RateLimited { retry_after } => *retry_after,
        ProviderError::PendingExternal { .. } | ProviderError::Terminal { .. } => cfg.backoff,
    };
    // `1 << 16` rather than a `pow` that can overflow on a silly attempt count.
    let capped = base
        .saturating_mul(1u32 << attempt.min(16))
        .min(cfg.backoff_cap);
    capped.mul_f64(rand::rng().random_range(0.5..=1.0))
}

/// A failure to mint a signing key, as the one error type [`ProvisioningEngine::call`]
/// speaks.
///
/// The split is retryable versus not. A database that would not answer is the
/// engine's ordinary bad afternoon and a later pass mints the key. A wrong
/// master key or a corrupt row is not fixed by trying again — a step that
/// retries one of those forever is a step nobody ever looks at — so it becomes
/// terminal, carrying [`IdentityError::code`] so the dashboard says which.
fn mint_failure(err: IdentityError) -> ProviderError {
    let code = err.code();
    match err {
        IdentityError::Unavailable(_) => ProviderError::timeout(),
        // Already a provider error, and its code is the useful one.
        IdentityError::Unsealable(inner) => inner,
        // `NoKey` is unreachable from `ensure_key`, which has just written one.
        IdentityError::NoKey | IdentityError::Corrupt(_) => ProviderError::Terminal { code },
    }
}

/// A binding to a resource that is us.
fn local(employee: &Employee, what: &str) -> ProviderBinding {
    ProviderBinding::new(LOCAL, format!("{what}:{}", employee.id().as_uuid()))
}

/// The domain's binding for what a provider handed back.
fn bind(provisioned: Provisioned) -> ProviderBinding {
    ProviderBinding::new(provisioned.provider, provisioned.external_id)
}

/// The dependency that stops this step, if any. Reads
/// [`Step::depends_on`] — never `Step::ALL` order, which lists `Browser`
/// before the `Vault` it needs.
fn first_unmet(employee: &Employee, step: Step) -> Option<Step> {
    step.depends_on()
        .iter()
        .copied()
        .find(|dep| !employee.resource(*dep).is_ready())
}

/// Every step, dependents first and dependencies last.
///
/// The order [`ProvisioningEngine::converge`] runs, reversed — and computed the
/// same way, from [`Step::depends_on`], so a new edge in the domain changes
/// both without either being edited. Writing the list down instead is how you
/// release the vault before the browser profile whose credentials live in it.
fn release_order() -> Vec<Step> {
    let mut order: Vec<Step> = Vec::with_capacity(Step::ALL.len());
    let mut pending: Vec<Step> = Step::ALL.to_vec();

    while !pending.is_empty() {
        let (runnable, blocked): (Vec<Step>, Vec<Step>) = std::mem::take(&mut pending)
            .into_iter()
            .partition(|step| step.depends_on().iter().all(|dep| order.contains(dep)));
        if runnable.is_empty() {
            // Unreachable: the domain has a test that the graph is acyclic.
            // Appending the remainder beats a worker looping forever.
            order.extend(blocked);
            break;
        }
        order.extend(runnable);
        pending = blocked;
    }

    order.reverse();
    order
}

/// Split the outstanding steps into `(already ready, runnable now, blocked)`.
///
/// The topological order, recomputed every wave from the dependency edges, so
/// a new edge in the domain needs no change here.
fn plan_wave(employee: &Employee, pending: &[Step]) -> (Vec<Step>, Vec<Step>, Vec<Step>) {
    let (mut done, mut runnable, mut blocked) = (Vec::new(), Vec::new(), Vec::new());
    for &step in pending {
        if employee.resource(step).is_ready() {
            done.push(step);
        } else if first_unmet(employee, step).is_none() {
            runnable.push(step);
        } else {
            blocked.push(step);
        }
    }
    (done, runnable, blocked)
}

/// The tool name a reconciliation approval is filed under.
fn reconcile_tool(step: Step) -> McpTool {
    // `Slug` is `[a-z0-9-]{2,32}`; every `Step::as_str` is that once its
    // underscores are hyphens. A step that is not gets a generic name rather
    // than a panic in a worker.
    let name = Slug::parse(&step.as_str().replace('_', "-"))
        .or_else(|_| Slug::parse("step"))
        .expect("`step` is a valid slug");
    McpTool::new(
        Slug::parse("provisioning").expect("`provisioning` is a valid slug"),
        name,
    )
}

/// What tx1 came to. Three answers, and only one of them lets a provider be
/// called.
#[derive(Debug)]
enum Claimed {
    /// The step is ours, the intent is durable, go ahead and call.
    Mine(Claim),
    /// Someone else holds the lease.
    Busy,
    /// An intent of unknown outcome. A human owns this step now.
    Parked,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use agentos_domain::action::{Domain, E164};
    use agentos_domain::employee::Health;
    use agentos_domain::ids::IdempotencyKey;
    use agentos_domain::message::CanonicalMessage;
    use agentos_providers::FaultMode;
    use agentos_providers::browser::MockBrowser;
    use agentos_providers::email::MockEmailProvider;
    use agentos_providers::secrets::MemorySecretStore;
    use agentos_providers::telephony::{
        InboundCtx, MockTelephony, OutboundSms, OutboundWhatsapp, ParseError, ProviderMessageId,
        SigError, WebhookBody,
    };
    use async_trait::async_trait;
    use tokio::sync::Notify;

    use super::*;

    // -- fixtures ----------------------------------------------------------

    /// The envelope root these tests seal signing keys under. A literal,
    /// because the deployment's is a literal too — it comes out of the
    /// environment as text and `identity::envelope` is what turns it into 32
    /// bytes, so the tests go through the same function the binary does.
    const TEST_MASTER_KEY: &str = "provisioning-tests-master-key";

    /// These tests share one database, and the `(provider, external_id)` unique
    /// index is global to it while the mocks number their resources from 1. So
    /// they run one at a time and each starts from an empty database, rather
    /// than colliding on `dom_0001` and reporting it as a provisioning bug.
    static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; provisioning tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// Empty the database. Everything cascades from `tenants`.
    async fn reset(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants")
            .execute(&mut *tx)
            .await
            .expect("wipe");
        tx.commit().await.expect("commit wipe");
    }

    /// A tenant and one active employee with all eleven resource rows.
    async fn seed(db: &Db) -> Employee {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(format!("t-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit tenant");

        colleague(db, tenant, "lena").await
    }

    /// Another active employee in an existing tenant — the one already holding
    /// the last slot in the pool.
    async fn colleague(db: &Db, tenant: TenantId, slug: &str) -> Employee {
        let now = Utc::now();
        let mut employee = Employee::new(
            EmployeeId::new_v7(now),
            tenant,
            Slug::parse(slug).expect("slug"),
            Domain::parse("example.com").expect("domain"),
            now,
        );
        employee
            .set_lifecycle(Lifecycle::Active, now)
            .expect("draft -> active");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        employee::insert(&mut tx, &employee).await.expect("insert");
        tx.commit().await.expect("commit employee");
        employee
    }

    fn adapters(telephony: Arc<dyn TelephonyProvider>, email: Arc<dyn EmailProvider>) -> Adapters {
        Adapters {
            email,
            telephony,
            browser: Arc::new(MockBrowser::new()),
            secrets: Arc::new(MemorySecretStore::new()),
            envelope: crate::identity::envelope(TEST_MASTER_KEY),
        }
    }

    /// One attempt, no waiting, one step at a time: every assertion below is
    /// about *what* happened, and a second attempt or a racing wave would only
    /// make the story harder to read.
    fn cfg() -> EngineConfig {
        EngineConfig {
            max_attempts: 1,
            concurrency: 1,
            backoff: Duration::from_millis(1),
            whatsapp_sender: Some("wa-company-sender".to_owned()),
            ..EngineConfig::default()
        }
    }

    // -- the pool ----------------------------------------------------------

    /// The region the pool tests use. France, because France is why the pool
    /// exists: every number there costs a human-reviewed bundle.
    const FR: &str = "FR";
    /// The tenant's shared number.
    const POOLED: &str = "+33755000001";

    /// The same engine, told to pool French numbers instead of buying them.
    fn pooled_cfg() -> EngineConfig {
        EngineConfig {
            region: Region::new(FR),
            number_strategy: NumberStrategy::Pooled,
            ..cfg()
        }
    }

    /// Put a number the tenant owns into the pool. `capacity` is the whole
    /// switch: 1 is a dedicated number under the same contract.
    async fn add_pool_number(db: &Db, tenant: TenantId, e164: &str, capacity: i32) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        phone_pool::register(
            &mut tx,
            &phone_pool::NewNumber {
                provider: "twilio".to_owned(),
                external_id: format!("PN-pool-{}", Uuid::now_v7()),
                e164: E164::parse(e164).expect("e164"),
                region: FR.to_owned(),
                state: phone_pool::NumberState::Active,
                capacity,
                bundle_ref: Some("BU-fr-1".to_owned()),
            },
            Utc::now(),
        )
        .await
        .expect("register a pooled number");
        tx.commit().await.expect("commit");
    }

    /// Seats currently taken across the tenant's whole pool. The "never two"
    /// assertion.
    async fn live_slots(db: &Db, employee: &Employee) -> i64 {
        count(
            db,
            employee,
            "SELECT count(*) FROM number_allocations WHERE released_at IS NULL",
        )
        .await
    }

    /// The slot binding this employee should be holding on `POOLED`.
    fn expected_slot(employee: &Employee) -> String {
        format!("{POOLED}/{}", employee.id().as_uuid())
    }

    /// `(state, lease_owner, provider, external_id, last_error)`.
    async fn row(
        db: &Db,
        employee: &Employee,
        step: Step,
    ) -> (
        String,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let row = sqlx::query_as(
            "SELECT state, lease_owner, provider, external_id, last_error \
             FROM employee_resources WHERE employee_id = $1 AND step = $2",
        )
        .bind(employee.id().as_uuid())
        .bind(step.as_str())
        .fetch_one(&mut **tx)
        .await
        .expect("resource row");
        tx.rollback().await.expect("rollback");
        row
    }

    async fn count(db: &Db, employee: &Employee, sql: &'static str) -> i64 {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let n: i64 = sqlx::query_scalar(sql)
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        n
    }

    async fn reload(db: &Db, employee: &Employee) -> Employee {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let stored = employee::load(&mut tx, employee.id()).await.expect("load");
        tx.rollback().await.expect("rollback");
        stored.employee
    }

    /// What the terminate endpoint does: the lifecycle move, persisted.
    async fn terminate(db: &Db, employee: &Employee) -> Employee {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let stored = employee::load(&mut tx, employee.id()).await.expect("load");
        let mut terminated = stored.employee;
        terminated
            .set_lifecycle(Lifecycle::Terminated, Utc::now())
            .expect("active -> terminated");
        employee::update(&mut tx, &terminated, stored.version)
            .await
            .expect("update");
        tx.commit().await.expect("commit");
        terminated
    }

    /// Steps that still name a provider resource, i.e. that are still billed.
    fn bound(employee: &Employee) -> Vec<Step> {
        Step::ALL
            .into_iter()
            .filter(|step| employee.resource(*step).binding().is_some())
            .collect()
    }

    /// The order the rows were last touched in — the observed release order,
    /// read back out of the database rather than assumed.
    ///
    /// Every step is released in its own transaction with its own `now`, so
    /// `updated_at` is a faithful sequence rather than a tie.
    async fn touch_order(db: &Db, employee: &Employee) -> Vec<Step> {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT step FROM employee_resources WHERE employee_id = $1 ORDER BY updated_at",
        )
        .bind(employee.id().as_uuid())
        .fetch_all(&mut **tx)
        .await
        .expect("rows");
        tx.rollback().await.expect("rollback");

        rows.into_iter()
            .filter_map(|(step,)| Step::ALL.into_iter().find(|s| s.as_str() == step))
            .collect()
    }

    // -- a provider that hangs ---------------------------------------------

    /// Buys the number, then hangs the way a real provider does when the
    /// connection is black-holed: no error, no answer, forever.
    ///
    /// The number is recorded *before* the hang, so this is the crash window
    /// with a stopwatch attached — and [`Self::calls`] is the assertion that
    /// nobody ever bought a second one.
    #[derive(Debug, Default)]
    struct HangingTelephony {
        bought: Mutex<Option<String>>,
        calls: AtomicU32,
        hang: AtomicBool,
        entered: Notify,
    }

    impl HangingTelephony {
        const PROVIDER: &'static str = "hanging-telephony";

        fn hanging() -> Self {
            Self {
                hang: AtomicBool::new(true),
                ..Self::default()
            }
        }

        /// How many times `ensure_number` was entered. Must be 1 across any
        /// number of crashes and restarts.
        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl TelephonyProvider for HangingTelephony {
        async fn ensure_number(
            &self,
            ctx: &EnsureCtx,
            _region: &Region,
        ) -> Result<Provisioned, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let sid = {
                let mut bought = self.bought.lock().expect("poisoned");
                bought
                    .get_or_insert_with(|| format!("PN-{}", ctx.tag()))
                    .clone()
            };
            // The number now exists over there; the test may pull the plug.
            self.entered.notify_one();
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            Ok(Provisioned::new(Self::PROVIDER, sid))
        }

        async fn release(
            &self,
            _binding: &agentos_providers::ProviderBinding,
        ) -> Result<(), ProviderError> {
            let mut bought = self.bought.lock().expect("poisoned");
            *bought = None;
            Ok(())
        }

        async fn send_sms(
            &self,
            _key: &IdempotencyKey,
            _sms: &OutboundSms,
        ) -> Result<ProviderMessageId, ProviderError> {
            unimplemented!("provisioning never sends")
        }

        async fn send_whatsapp(
            &self,
            _key: &IdempotencyKey,
            _message: &OutboundWhatsapp,
        ) -> Result<ProviderMessageId, ProviderError> {
            unimplemented!("provisioning never sends")
        }

        fn verify_webhook(
            &self,
            _url: &str,
            _body: WebhookBody<'_>,
            _headers: &[(String, String)],
        ) -> Result<(), SigError> {
            unimplemented!("provisioning never receives")
        }

        fn normalize(
            &self,
            _ctx: &InboundCtx,
            _raw: &[u8],
        ) -> Result<CanonicalMessage, ParseError> {
            unimplemented!("provisioning never receives")
        }
    }

    // -- a provider that will not let go -----------------------------------

    /// Sells numbers happily and refuses to take them back: the delete endpoint
    /// is broken, or the account lost the permission. The failure mode this
    /// whole path exists for, because the number keeps billing either way.
    #[derive(Debug, Default)]
    struct StubbornTelephony {
        /// tag -> sid, so `ensure_number` still reconciles properly.
        numbers: Mutex<BTreeMap<String, String>>,
        release_attempts: AtomicU32,
    }

    impl StubbornTelephony {
        const PROVIDER: &'static str = "stubborn-telephony";
        /// The code it refuses with. Terminal: retrying inside one pass would
        /// not help, and the record is what makes a later pass possible.
        const REFUSED: &'static str = "release_refused";

        fn release_attempts(&self) -> u32 {
            self.release_attempts.load(Ordering::SeqCst)
        }

        /// Numbers still on the account, i.e. still on the invoice.
        fn number_count(&self) -> usize {
            self.numbers.lock().expect("poisoned").len()
        }
    }

    #[async_trait]
    impl TelephonyProvider for StubbornTelephony {
        async fn ensure_number(
            &self,
            ctx: &EnsureCtx,
            _region: &Region,
        ) -> Result<Provisioned, ProviderError> {
            let mut numbers = self.numbers.lock().expect("poisoned");
            let next = numbers.len() + 1;
            let sid = numbers
                .entry(ctx.tag().to_owned())
                .or_insert_with(|| format!("PN-stubborn-{next}"))
                .clone();
            Ok(Provisioned::new(Self::PROVIDER, sid))
        }

        async fn release(
            &self,
            _binding: &agentos_providers::ProviderBinding,
        ) -> Result<(), ProviderError> {
            self.release_attempts.fetch_add(1, Ordering::SeqCst);
            Err(ProviderError::Terminal {
                code: Self::REFUSED,
            })
        }

        async fn send_sms(
            &self,
            _key: &IdempotencyKey,
            _sms: &OutboundSms,
        ) -> Result<ProviderMessageId, ProviderError> {
            unimplemented!("provisioning never sends")
        }

        async fn send_whatsapp(
            &self,
            _key: &IdempotencyKey,
            _message: &OutboundWhatsapp,
        ) -> Result<ProviderMessageId, ProviderError> {
            unimplemented!("provisioning never sends")
        }

        fn verify_webhook(
            &self,
            _url: &str,
            _body: WebhookBody<'_>,
            _headers: &[(String, String)],
        ) -> Result<(), SigError> {
            unimplemented!("provisioning never receives")
        }

        fn normalize(
            &self,
            _ctx: &InboundCtx,
            _raw: &[u8],
        ) -> Result<CanonicalMessage, ParseError> {
            unimplemented!("provisioning never receives")
        }
    }

    // -- pure tests --------------------------------------------------------

    /// The topological claim. `Step::ALL` lists `Browser` *before* the `Vault`
    /// it loads credentials from, so anything that iterates `ALL` and calls it
    /// an order provisions a browser that will type secrets it does not have.
    #[test]
    fn the_wave_order_comes_from_the_dependency_edges_not_from_step_all() {
        let now = Utc::now();
        let mut employee = Employee::new(
            EmployeeId::new_v7(now),
            TenantId::new_v7(now),
            Slug::parse("lena").expect("slug"),
            Domain::parse("example.com").expect("domain"),
            now,
        );

        // Nothing ready: only the root can run.
        let (done, runnable, blocked) = plan_wave(&employee, &Step::ALL);
        assert!(done.is_empty());
        assert_eq!(runnable, vec![Step::Identity]);
        assert_eq!(blocked.len(), Step::ALL.len() - 1);

        // Identity ready: everything but the browser, which still wants a vault
        // — even though `Step::ALL` would have run it three steps ago.
        ready(&mut employee, Step::Identity, now);
        let (_, runnable, blocked) = plan_wave(&employee, &blocked);
        assert!(runnable.contains(&Step::Vault));
        assert!(!runnable.contains(&Step::Browser));
        assert_eq!(blocked, vec![Step::Browser]);

        // Vault ready: the browser is released, and Identity reports as done
        // rather than being run again.
        ready(&mut employee, Step::Vault, now);
        let (done, runnable, blocked) = plan_wave(&employee, &[Step::Identity, Step::Browser]);
        assert_eq!(done, vec![Step::Identity]);
        assert_eq!(runnable, vec![Step::Browser]);
        assert!(blocked.is_empty());
    }

    /// The mirror claim. Releasing is the ensure order backwards, and it has to
    /// come from the same edges: a vault released before the browser profile
    /// whose credentials live in it takes the credentials with it.
    #[test]
    fn the_release_order_is_the_dependency_order_reversed() {
        let order = release_order();
        assert_eq!(order.len(), Step::ALL.len());
        assert_eq!(
            order
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>(),
            Step::ALL
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            "every step must be released, not just the ones with adapters"
        );

        let position = |step: Step| {
            order
                .iter()
                .position(|s| *s == step)
                .expect("every step is in the order")
        };
        // The general claim, checked against the edges rather than a list.
        for step in Step::ALL {
            for dep in step.depends_on() {
                assert!(
                    position(step) < position(*dep),
                    "{step} must be released before {dep}, which it depends on"
                );
            }
        }
        // ... and the two that cost real money if they are wrong, spelled out.
        assert!(position(Step::Browser) < position(Step::Vault));
        assert_eq!(
            order.last(),
            Some(&Step::Identity),
            "identity is the root, so it is released last"
        );
    }

    fn ready(employee: &mut Employee, step: Step, now: DateTime<Utc>) {
        employee
            .set_resource(step, ResourceState::Provisioning, now)
            .expect("-> provisioning");
        employee
            .set_resource(step, ResourceState::Ready, now)
            .expect("-> ready");
    }

    /// The compile-time claim, restated where a reader will look for it: this
    /// match has no `_` arm, so a twelfth `Step` breaks the build here, in
    /// `adapter_of`, and in `ProvisioningEngine::call` — which is the point.
    /// A registry would have compiled and silently never provisioned it.
    #[test]
    fn every_step_says_which_adapter_owns_it() {
        for step in Step::ALL {
            let reaches_a_network = match step {
                Step::Email | Step::Phone | Step::Browser | Step::Vault => true,
                Step::Identity
                | Step::Whatsapp
                | Step::Wallet
                | Step::CompanyKnowledge
                | Step::Mcp
                | Step::A2a
                | Step::Permissions => false,
            };
            assert_eq!(
                adapter_of(step).is_some(),
                reaches_a_network,
                "{step} disagrees about whether it calls anything"
            );
            // ... and the ones that do are exactly the ones that get a
            // write-ahead log entry, because they are the only ones whose
            // outcome can ever be unknown.
        }
    }

    #[test]
    fn backoff_grows_stays_under_the_cap_and_is_never_the_same_twice() {
        let cfg = EngineConfig {
            backoff: Duration::from_millis(100),
            backoff_cap: Duration::from_secs(2),
            ..EngineConfig::default()
        };
        let err = ProviderError::Retryable {
            after: Duration::from_millis(100),
        };

        for attempt in 0..8 {
            let waited = backoff(&cfg, attempt, &err);
            let ceiling = Duration::from_millis(100)
                .saturating_mul(1 << attempt)
                .min(cfg.backoff_cap);
            assert!(waited <= ceiling, "attempt {attempt} exceeded its ceiling");
            assert!(waited >= ceiling / 2, "attempt {attempt} jittered to zero");
        }

        // A 429's own advice wins over our first guess.
        let advised = backoff(
            &cfg,
            0,
            &ProviderError::RateLimited {
                retry_after: Duration::from_secs(30),
            },
        );
        assert!(advised <= cfg.backoff_cap, "the cap binds the advice too");
        assert!(advised >= cfg.backoff_cap / 2);
    }

    // -- the signing key ---------------------------------------------------

    /// The keys this employee publishes, read the way a stranger reads them.
    async fn published(db: &Db, employee: &Employee) -> Vec<Vec<u8>> {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let rows = keys::published_keys(&mut tx, employee.id())
            .await
            .expect("published");
        tx.rollback().await.expect("rollback");
        rows
    }

    /// **The one that matters for A: converging twice must not mint a second
    /// key.**
    ///
    /// A second keypair would strand every signature made under the first —
    /// silently, at whatever moment the retry happened — and the counterparty
    /// would be the one to find out. So this drives the real engine through the
    /// real step, twice, and then a third time from a *restarted* engine (a new
    /// `worker_id`, which is what a redeploy looks like).
    #[tokio::test]
    async fn provisioning_twice_mints_exactly_one_signing_key() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let email = Arc::new(MockEmailProvider::new());
        let adapters = || adapters(telephony.clone(), email.clone());
        let engine = ProvisioningEngine::new(db.clone(), adapters(), cfg());

        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        let first = published(&db, &employee).await;
        assert_eq!(first.len(), 1, "one employee, one published key");
        assert_eq!(first[0].len(), 32, "and it is an Ed25519 key");

        // Same worker, again.
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge again");
        assert_eq!(published(&db, &employee).await, first, "the key changed");

        // A restarted process: a fresh `worker_id`, fresh adapters, and — the
        // part that would catch a mint keyed on anything in memory — the step
        // forced back to `provisioning` so `ensure_step` actually runs the call
        // again rather than short-circuiting on `Ready`.
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        sqlx::query(
            "UPDATE employee_resources SET state = 'provisioning', lease_owner = NULL, \
             lease_until = NULL WHERE employee_id = $1 AND step = 'identity'",
        )
        .bind(employee.id().as_uuid())
        .execute(&mut **tx)
        .await
        .expect("rewind identity");
        tx.commit().await.expect("commit");

        let restarted = ProvisioningEngine::new(db.clone(), adapters(), cfg());
        assert_ne!(restarted.worker_id(), engine.worker_id());
        assert_eq!(
            restarted
                .ensure_step(&reload(&db, &employee).await, Step::Identity)
                .await
                .expect("re-ensure"),
            StepReport::Ready
        );
        assert_eq!(
            published(&db, &employee).await,
            first,
            "a re-provisioned identity minted a second key and stranded the first"
        );
        assert_eq!(
            count(&db, &employee, "SELECT count(*) FROM employee_signing_keys").await,
            1,
            "the table itself must hold exactly one row for this employee"
        );
    }

    /// Offboarding destroys the private half. See `release_call`'s
    /// `Step::Identity` arm for why that is the right call and not a liability.
    #[tokio::test]
    async fn offboarding_destroys_the_signing_key() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(
                Arc::new(MockTelephony::new(Utc::now(), "tok")),
                Arc::new(MockEmailProvider::new()),
            ),
            cfg(),
        );
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        assert_eq!(published(&db, &employee).await.len(), 1);

        let terminated = terminate(&db, &reload(&db, &employee).await).await;
        // Publication has already stopped — the lifecycle filter did that, and
        // it is why destroying the private half costs nothing.
        assert!(published(&db, &employee).await.is_empty());

        assert_eq!(
            engine
                .release_step(&terminated, Step::Identity)
                .await
                .expect("release identity"),
            ReleaseReport::Released
        );
        assert_eq!(
            count(&db, &employee, "SELECT count(*) FROM employee_signing_keys").await,
            0,
            "the sealed private key outlived the employee"
        );

        // Releasing twice is fine: the store's delete is idempotent, so a
        // retried termination event is not an error.
        assert_eq!(
            engine
                .release_step(&reload(&db, &employee).await, Step::Identity)
                .await
                .expect("release again"),
            ReleaseReport::NotBound,
            "the binding is gone, so there is nothing left to give back"
        );
        assert_eq!(
            count(&db, &employee, "SELECT count(*) FROM employee_signing_keys").await,
            0
        );
    }

    // -- database tests ----------------------------------------------------

    #[tokio::test]
    async fn a_fresh_employee_converges_to_online() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let email = Arc::new(MockEmailProvider::new());
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), email.clone()),
            cfg(),
        );

        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");

        for step in Step::ALL {
            assert_eq!(
                reports.get(&step),
                Some(&StepReport::Ready),
                "{step} did not become ready"
            );
        }
        assert_eq!(reload(&db, &employee).await.health(), Health::Online);
        assert_eq!(telephony.number_count(), 1);
        assert_eq!(email.identity_count(), 1);

        // Every step that reached a provider emitted its outbox event, and no
        // step wrote two.
        assert_eq!(
            count(&db, &employee, "SELECT count(*) FROM outbox_events").await,
            i64::try_from(Step::ALL.len()).expect("small"),
        );

        // The second run is the product requirement: it converges on the same
        // resources instead of creating a second set.
        let again = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge again");
        assert!(again.values().all(StepReport::is_ready));
        assert_eq!(telephony.number_count(), 1, "a re-run must buy nothing");
        assert_eq!(email.identity_count(), 1);
    }

    /// CHAOS 1. The provider succeeds externally and *then* fails, which is the
    /// window that buys a second number. Re-running must reconcile onto the one
    /// that already exists, with the same external id.
    #[tokio::test]
    async fn a_failure_after_the_external_success_reconciles_to_one_resource() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(
            MockTelephony::new(Utc::now(), "tok")
                .with_fault(FaultMode::FailAfterExternalSuccess(ProviderError::timeout())),
        );
        let email = Arc::new(MockEmailProvider::new());
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), email.clone()),
            cfg(),
        );

        // Run one: the number is bought, and the answer is lost.
        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        assert_eq!(
            reports.get(&Step::Phone),
            Some(&StepReport::Failed { code: "retryable" })
        );
        assert_eq!(
            telephony.number_count(),
            1,
            "the number was bought before the failure"
        );
        let (state, lease, provider, external, error) = row(&db, &employee, Step::Phone).await;
        assert_eq!(state, "failed");
        assert_eq!(lease, None, "a finished step releases its lease");
        assert_eq!(provider, None, "we never learned the id");
        assert_eq!(external, None);
        assert!(error.expect("an error is recorded").contains("retryable"));

        // Run two, same faulty provider: `ensure` looks the resource up by tag
        // before it creates, so the retry finds what run one paid for.
        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge again");
        assert_eq!(reports.get(&Step::Phone), Some(&StepReport::Ready));
        assert_eq!(
            telephony.number_count(),
            1,
            "reconcile-before-create: exactly one number, ever"
        );

        let (state, _, provider, external, _) = row(&db, &employee, Step::Phone).await;
        assert_eq!(state, "ready");
        assert_eq!(provider.as_deref(), Some("twilio"));
        let external = external.expect("the id we are billed for is persisted");

        // A third run changes nothing at all — same id, same count.
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge a third time");
        let (_, _, _, again, _) = row(&db, &employee, Step::Phone).await;
        assert_eq!(again.as_deref(), Some(external.as_str()));
        assert_eq!(telephony.number_count(), 1);
    }

    /// CHAOS 2. The worker is killed mid-call. On restart the employee
    /// converges — and the step whose outcome nobody knows is parked behind a
    /// human instead of being retried, because retrying a call that may already
    /// have bought a phone number is how you buy two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn killing_a_run_mid_flight_converges_without_buying_twice() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(HangingTelephony::hanging());
        let email = Arc::new(MockEmailProvider::new());
        // A short lease: the point is the restart after it lapses, not the wait.
        let short_lease = EngineConfig {
            lease: TimeDelta::milliseconds(200),
            ..cfg()
        };
        let dying = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), email.clone()),
            short_lease.clone(),
        );

        let (tenant_id, employee_id) = (employee.tenant_id(), employee.id());
        let run = tokio::spawn(async move { dying.converge(tenant_id, employee_id).await });
        // ---- the number now exists at the provider, and the process dies ----
        telephony.entered.notified().await;
        run.abort();
        let _ = run.await;

        assert_eq!(telephony.calls(), 1);
        let (state, lease, ..) = row(&db, &employee, Step::Phone).await;
        assert_eq!(state, "provisioning");
        assert!(
            lease.is_some(),
            "the dead worker's lease is still on the row"
        );
        assert_eq!(
            count(
                &db,
                &employee,
                "SELECT count(*) FROM provider_intents WHERE state = 'in_flight'"
            )
            .await,
            1,
            "the write-ahead log is the only evidence the call happened"
        );

        // The lease lapses, and a *different* worker picks the employee up.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let restarted = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), email.clone()),
            short_lease,
        );
        let reports = restarted
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge after the crash");

        assert_eq!(reports.get(&Step::Phone), Some(&StepReport::Parked));
        assert_eq!(
            telephony.calls(),
            1,
            "an intent of unknown outcome must never be retried"
        );
        // Everything else converged around it, including the browser, whose
        // vault the dead run never got to.
        for step in Step::ALL.into_iter().filter(|s| *s != Step::Phone) {
            assert_eq!(
                reports.get(&step),
                Some(&StepReport::Ready),
                "{step} should have converged around the parked step"
            );
        }
        assert_eq!(
            reload(&db, &employee).await.health(),
            Health::Degraded,
            "a phone nobody can resolve is a degradation, not an outage"
        );

        // One human question was filed, and the intent says why.
        assert_eq!(
            count(&db, &employee, "SELECT count(*) FROM approvals").await,
            1
        );
        assert_eq!(
            count(
                &db,
                &employee,
                "SELECT count(*) FROM provider_intents WHERE state = 'orphaned'"
            )
            .await,
            1
        );

        // And it stays parked: no second approval, no second call, forever —
        // the refusal is a durable row, not a flag in one process's memory.
        let reports = restarted
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge a third time");
        assert_eq!(reports.get(&Step::Phone), Some(&StepReport::Parked));
        assert_eq!(telephony.calls(), 1);
        assert_eq!(
            count(&db, &employee, "SELECT count(*) FROM approvals").await,
            1,
            "a parked step asks once, not once per pass"
        );
    }

    /// A regulated country sells no number until a human at the regulator says
    /// so. The run records what to poll and gets on with the other ten steps.
    #[tokio::test]
    async fn a_pending_external_step_does_not_block_the_others() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let france = Region::new("FR");
        let telephony =
            Arc::new(MockTelephony::new(Utc::now(), "tok").with_regulated(france.clone()));
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            EngineConfig {
                region: france,
                ..cfg()
            },
        );

        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");

        let Some(StepReport::PendingExternal { poll_ref }) = reports.get(&Step::Phone) else {
            panic!(
                "expected a bundle to poll, got {:?}",
                reports.get(&Step::Phone)
            );
        };
        assert!(poll_ref.starts_with("BU:FR:"), "{poll_ref}");
        assert_eq!(telephony.number_count(), 0, "nothing was bought");

        for step in Step::ALL.into_iter().filter(|s| *s != Step::Phone) {
            assert_eq!(
                reports.get(&step),
                Some(&StepReport::Ready),
                "{step} waited on a bundle that has nothing to do with it"
            );
        }
        assert_eq!(reload(&db, &employee).await.health(), Health::Degraded);

        // A worker cannot advance it; only the provider callback can. So a
        // second pass reports the wait rather than re-buying or spinning.
        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge again");
        assert!(matches!(
            reports.get(&Step::Phone),
            Some(StepReport::PendingExternal { .. })
        ));
        assert_eq!(telephony.number_count(), 0);
    }

    /// An unbounded await is how a worker hangs forever holding a lease nobody
    /// may steal. The timeout is what turns that into an ordinary failure.
    #[tokio::test]
    async fn a_hung_provider_hits_the_timeout_and_releases_its_lease() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(HangingTelephony::hanging());
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            EngineConfig {
                call_timeout: Duration::from_millis(50),
                ..cfg()
            },
        );

        let started = std::time::Instant::now();
        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the run outlived the provider it was waiting on"
        );
        assert_eq!(
            reports.get(&Step::Phone),
            // A timeout is retryable: the request may even have landed, which
            // is exactly what reconcile-before-create protects the retry
            // against.
            Some(&StepReport::Failed { code: "retryable" })
        );

        let (state, lease, ..) = row(&db, &employee, Step::Phone).await;
        assert_eq!(state, "failed");
        assert_eq!(
            lease, None,
            "a timed-out step must hand its lease back, not sit on it"
        );
        // And the rest of the employee is unaffected.
        assert_eq!(reports.get(&Step::Email), Some(&StepReport::Ready));
    }

    /// Two workers, one employee, at the same time. Exactly one provisions each
    /// step; the loser is told so rather than calling the provider anyway.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_workers_on_one_employee_do_not_both_provision() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let email = Arc::new(MockEmailProvider::new());
        let (tenant_id, employee_id) = (employee.tenant_id(), employee.id());

        let runs: Vec<_> = (0..3)
            .map(|_| {
                let engine = ProvisioningEngine::new(
                    db.clone(),
                    adapters(telephony.clone(), email.clone()),
                    cfg(),
                );
                tokio::spawn(async move { engine.converge(tenant_id, employee_id).await })
            })
            .collect();
        for run in runs {
            run.await.expect("join").expect("converge");
        }

        assert_eq!(telephony.number_count(), 1, "three workers, one number");
        assert_eq!(email.identity_count(), 1);
        assert_eq!(
            count(&db, &employee, "SELECT count(*) FROM provider_intents").await,
            4,
            "one write-ahead row per step that reaches a network, not per attempt"
        );
    }

    // -- releasing ---------------------------------------------------------

    /// The whole point: terminating an employee has to stop the bill.
    ///
    /// Before this existed, terminating stopped the employee acting (the gate
    /// refuses anything that is not `Active`) and left the phone number, the
    /// browser process and the vault subtree exactly where they were.
    #[tokio::test]
    async fn terminating_an_employee_releases_every_bound_resource() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let email = Arc::new(MockEmailProvider::new());
        let browser = Arc::new(MockBrowser::new());
        let secrets = Arc::new(MemorySecretStore::new());
        let engine = ProvisioningEngine::new(
            db.clone(),
            Adapters {
                email: email.clone(),
                telephony: telephony.clone(),
                browser: browser.clone(),
                secrets: secrets.clone(),
                envelope: crate::identity::envelope(TEST_MASTER_KEY),
            },
            cfg(),
        );

        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        let provisioned = reload(&db, &employee).await;
        assert_eq!(
            bound(&provisioned),
            Step::ALL.to_vec(),
            "every step should be bound before anything is released"
        );
        assert_eq!(telephony.number_count(), 1);
        assert_eq!(email.identity_count(), 1);
        assert_eq!(browser.context_count(), 1);
        let canary =
            SecretRef::new(employee.tenant_id(), employee.id(), VAULT_CANARY).expect("ref");
        assert!(
            secrets.get(&canary).await.is_ok(),
            "the vault canary is what proves the subtree exists"
        );

        let terminated = terminate(&db, &provisioned).await;
        let reports = engine.release_all(&terminated).await.expect("release");

        for step in Step::ALL {
            assert_eq!(
                reports.get(&step),
                Some(&ReleaseReport::Released),
                "{step} was not released"
            );
        }

        // Nothing at any provider, and nothing left naming it.
        assert_eq!(telephony.number_count(), 0, "the number is still billing");
        assert_eq!(email.identity_count(), 0);
        assert_eq!(browser.context_count(), 0, "the browser is still running");
        assert!(
            secrets.get(&canary).await.is_err(),
            "the vault subtree survived the employee"
        );

        let released = reload(&db, &employee).await;
        assert!(
            bound(&released).is_empty(),
            "these bindings still name a resource: {:?}",
            bound(&released)
        );
        for step in Step::ALL {
            assert_eq!(
                released.resource(step).state(),
                &ResourceState::Disabled,
                "{step} should read as deliberately off, not as merely unbound"
            );
        }
        assert_eq!(released.lifecycle(), Lifecycle::Terminated);
    }

    /// Releasing is retried by whoever asked — the outbox redelivers a
    /// `employee.terminated` event on its own backoff — so a second pass must
    /// be a no-op and not a second, failing, provider call.
    #[tokio::test]
    async fn releasing_twice_is_idempotent_and_the_second_pass_calls_nobody() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let browser = Arc::new(MockBrowser::new());
        let engine = ProvisioningEngine::new(
            db.clone(),
            Adapters {
                email: Arc::new(MockEmailProvider::new()),
                telephony: telephony.clone(),
                browser: browser.clone(),
                secrets: Arc::new(MemorySecretStore::new()),
                envelope: crate::identity::envelope(TEST_MASTER_KEY),
            },
            cfg(),
        );
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        let terminated = terminate(&db, &reload(&db, &employee).await).await;

        let first = engine.release_all(&terminated).await.expect("release");
        assert!(first.values().all(|r| *r == ReleaseReport::Released));

        // The caller re-reads and asks again, exactly as a redelivered event
        // would. Nothing is bound any more, so nothing is called.
        let again = reload(&db, &employee).await;
        let second = engine.release_all(&again).await.expect("release again");
        for step in Step::ALL {
            assert_eq!(
                second.get(&step),
                Some(&ReleaseReport::NotBound),
                "{step} should have had nothing left to release"
            );
        }
        // A third, from the stale snapshot that still carries the bindings:
        // the provider no longer has them and says so by succeeding.
        let third = engine
            .release_all(&terminated)
            .await
            .expect("release again");
        assert!(third.values().all(|r| *r == ReleaseReport::Released));
        assert_eq!(telephony.number_count(), 0);
        assert_eq!(browser.context_count(), 0);
    }

    /// Somebody cancelled the number in the provider's console last week. The
    /// binding is still ours to clear, and a delete that 404s is the state we
    /// were asking for — not an error that strands the row forever.
    #[tokio::test]
    async fn releasing_a_resource_the_provider_no_longer_has_succeeds() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            cfg(),
        );
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");

        let terminated = terminate(&db, &reload(&db, &employee).await).await;
        let binding = terminated
            .resource(Step::Phone)
            .binding()
            .expect("a number was bought");

        // Behind the engine's back: the number is gone, the binding is not.
        telephony
            .release(&agentos_providers::ProviderBinding {
                provider: binding.provider().to_owned(),
                external_id: binding.external_id().to_owned(),
            })
            .await
            .expect("cancelled in the console");
        assert_eq!(telephony.number_count(), 0);

        let reports = engine.release_all(&terminated).await.expect("release");
        assert_eq!(reports.get(&Step::Phone), Some(&ReleaseReport::Released));
        assert!(
            reload(&db, &employee)
                .await
                .resource(Step::Phone)
                .binding()
                .is_none(),
            "an already-gone resource must still let its binding go"
        );
    }

    /// The failure that must never be silent. The provider refuses, so the
    /// number is still on the invoice — and the row still says which number,
    /// why nobody released it, and that somebody should try again.
    #[tokio::test]
    async fn a_provider_that_refuses_to_release_leaves_a_retryable_record() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(StubbornTelephony::default());
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            cfg(),
        );
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");

        let terminated = terminate(&db, &reload(&db, &employee).await).await;
        let reports = engine.release_all(&terminated).await.expect("release");

        assert_eq!(
            reports.get(&Step::Phone),
            Some(&ReleaseReport::Failed {
                code: StubbornTelephony::REFUSED
            })
        );
        assert_eq!(telephony.release_attempts(), 1);
        assert_eq!(telephony.number_count(), 1, "it really is still out there");
        // Everything else still went, because one stubborn provider is no
        // reason to keep paying for the other ten resources.
        for step in Step::ALL.into_iter().filter(|s| *s != Step::Phone) {
            assert_eq!(reports.get(&step), Some(&ReleaseReport::Released), "{step}");
        }

        // The record. The external id is the only thing that says what to
        // cancel, so it is exactly what must NOT have been thrown away.
        let (state, _, provider, external, last_error) = row(&db, &employee, Step::Phone).await;
        assert_eq!(state, "failed");
        assert_eq!(provider.as_deref(), Some(StubbornTelephony::PROVIDER));
        assert!(
            external.is_some(),
            "the binding was cleared on a live number"
        );
        let last_error = last_error.expect("the row must say why");
        assert!(
            last_error.contains(StubbornTelephony::REFUSED),
            "{last_error}"
        );

        let (kind, intent_state): (String, String) = {
            let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
            let found = sqlx::query_as(
                "SELECT intent_kind, state FROM provider_intents \
                 WHERE employee_id = $1 AND step = 'phone' AND intent_kind = 'release_step'",
            )
            .bind(employee.id().as_uuid())
            .fetch_one(&mut **tx)
            .await
            .expect("a release intent");
            tx.rollback().await.expect("rollback");
            found
        };
        assert_eq!(kind, "release_step");
        assert_eq!(intent_state, "failed");

        // Retryable means retried: the next pass asks again rather than
        // treating the failure as settled.
        let stuck = reload(&db, &employee).await;
        let again = engine.release_all(&stuck).await.expect("release again");
        assert_eq!(
            again.get(&Step::Phone),
            Some(&ReleaseReport::Failed {
                code: StubbornTelephony::REFUSED
            })
        );
        assert_eq!(
            telephony.release_attempts(),
            2,
            "a refusal is not a verdict"
        );
    }

    /// The dependency claim, observed rather than assumed: the order the rows
    /// were actually touched in, read back out of Postgres.
    #[tokio::test]
    async fn the_observed_release_order_is_the_reverse_of_the_dependency_order() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(
                Arc::new(MockTelephony::new(Utc::now(), "tok")),
                Arc::new(MockEmailProvider::new()),
            ),
            cfg(),
        );
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        let terminated = terminate(&db, &reload(&db, &employee).await).await;

        engine.release_all(&terminated).await.expect("release");
        let observed = touch_order(&db, &employee).await;
        assert_eq!(observed.len(), Step::ALL.len());

        let position = |step: Step| {
            observed
                .iter()
                .position(|s| *s == step)
                .unwrap_or_else(|| panic!("{step} was never released"))
        };
        for step in Step::ALL {
            for dep in step.depends_on() {
                assert!(
                    position(step) < position(*dep),
                    "observed order {observed:?} released {dep} before {step}, which needs it"
                );
            }
        }
        // The edge that costs credentials rather than money.
        assert!(
            position(Step::Browser) < position(Step::Vault),
            "the vault went first, so the browser profile lost its credentials: {observed:?}"
        );
        assert_eq!(observed.last(), Some(&Step::Identity));
    }

    /// A release is a write against a terminated employee, and `Terminated` is
    /// absorbing. Nothing here may hand an employee back to work.
    #[tokio::test]
    async fn a_late_release_cannot_resurrect_a_terminated_employee() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(
                Arc::new(MockTelephony::new(Utc::now(), "tok")),
                Arc::new(MockEmailProvider::new()),
            ),
            cfg(),
        );
        engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        assert_eq!(reload(&db, &employee).await.health(), Health::Online);

        let terminated = terminate(&db, &reload(&db, &employee).await).await;
        engine.release_all(&terminated).await.expect("release");

        let after = reload(&db, &employee).await;
        assert_eq!(after.lifecycle(), Lifecycle::Terminated);
        assert_ne!(after.health(), Health::Online);
        // And the domain still refuses, so no later handler can undo it either.
        let mut resurrected = after.clone();
        assert!(
            resurrected
                .set_lifecycle(Lifecycle::Active, Utc::now())
                .is_err(),
            "terminated must stay terminated"
        );

        // A re-converge is the other way back in, and it does not open either:
        // every released row is `disabled`, which is not claimable work.
        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge after termination");
        assert!(
            !reports.values().any(StepReport::is_ready),
            "a terminated employee must not re-provision itself: {reports:?}"
        );
        assert_eq!(
            reload(&db, &employee).await.lifecycle(),
            Lifecycle::Terminated
        );
    }

    // -- pooled numbers ----------------------------------------------------

    /// The point of the whole strategy: an employee gets a working phone step
    /// and the provider is never asked for anything. Twenty employees, one
    /// French bundle, one human review.
    #[tokio::test]
    async fn a_pooled_employee_takes_a_slot_and_buys_nothing() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;
        add_pool_number(&db, employee.tenant_id(), POOLED, 5).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            pooled_cfg(),
        );

        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        assert_eq!(reports.get(&Step::Phone), Some(&StepReport::Ready));
        assert_eq!(
            telephony.number_count(),
            0,
            "a pooled slot must not buy a number"
        );

        let (state, lease, provider, external, _) = row(&db, &employee, Step::Phone).await;
        assert_eq!(state, "ready");
        assert_eq!(lease, None, "a finished step releases its lease");
        assert_eq!(provider.as_deref(), Some(pool_ops::PHONE_POOL));
        assert_eq!(
            external.as_deref(),
            Some(expected_slot(&employee).as_str()),
            "the slot must carry the employee id, like the WhatsApp sender does"
        );
        assert_eq!(live_slots(&db, &employee).await, 1);
        assert_eq!(reload(&db, &employee).await.health(), Health::Online);

        // Ensure twice: one allocation, the same binding, one slot.
        let again = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge again");
        assert!(again.values().all(StepReport::is_ready));
        let (_, _, _, second, _) = row(&db, &employee, Step::Phone).await;
        assert_eq!(second, external, "the binding moved under a live employee");
        assert_eq!(
            live_slots(&db, &employee).await,
            1,
            "ensure twice must consume one slot, not two"
        );
        assert_eq!(telephony.number_count(), 0);
    }

    /// A full pool is the signal to buy another number, and another number is
    /// another regulatory bundle in human review. That is a wait with something
    /// to poll — not a failure, and not a second waiting mechanism.
    #[tokio::test]
    async fn a_full_pool_waits_on_a_bundle_instead_of_failing() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let lena = seed(&db).await;
        let alex = colleague(&db, lena.tenant_id(), "alex").await;
        // One number, one seat, two employees.
        add_pool_number(&db, lena.tenant_id(), POOLED, 1).await;

        let telephony =
            Arc::new(MockTelephony::new(Utc::now(), "tok").with_regulated(Region::new(FR)));
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            pooled_cfg(),
        );

        let reports = engine
            .converge(lena.tenant_id(), lena.id())
            .await
            .expect("converge lena");
        assert_eq!(reports.get(&Step::Phone), Some(&StepReport::Ready));

        let reports = engine
            .converge(alex.tenant_id(), alex.id())
            .await
            .expect("converge alex");
        let Some(StepReport::PendingExternal { poll_ref }) = reports.get(&Step::Phone) else {
            panic!(
                "a full pool must be a wait, got {:?}",
                reports.get(&Step::Phone)
            );
        };
        assert!(poll_ref.starts_with("BU:FR:"), "{poll_ref}");
        assert_eq!(telephony.number_count(), 0, "nothing was bought");
        assert_eq!(live_slots(&db, &lena).await, 1, "one seat, one holder");

        // Everything else converged around it, and a second pass is still the
        // same wait rather than a second attempt at the pool.
        for step in Step::ALL.into_iter().filter(|s| *s != Step::Phone) {
            assert_eq!(reports.get(&step), Some(&StepReport::Ready), "{step}");
        }
        let again = engine
            .converge(alex.tenant_id(), alex.id())
            .await
            .expect("converge alex again");
        assert!(matches!(
            again.get(&Step::Phone),
            Some(StepReport::PendingExternal { .. })
        ));
        assert_eq!(live_slots(&db, &lena).await, 1);
    }

    /// The regression bar. `Dedicated` is what every other test in this file
    /// exercises, and it must not notice that a pool exists at all.
    #[tokio::test]
    async fn the_dedicated_strategy_ignores_the_pool_and_buys_its_own_number() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;
        // A perfectly good free seat, which `Dedicated` must not take.
        add_pool_number(&db, employee.tenant_id(), POOLED, 5).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            EngineConfig {
                region: Region::new(FR),
                ..cfg()
            },
        );

        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        assert_eq!(reports.get(&Step::Phone), Some(&StepReport::Ready));
        assert_eq!(telephony.number_count(), 1, "a dedicated number is bought");

        let (_, _, provider, _, _) = row(&db, &employee, Step::Phone).await;
        assert_eq!(provider.as_deref(), Some("twilio"));
        assert_eq!(
            live_slots(&db, &employee).await,
            0,
            "the dedicated path must not touch the pool"
        );
    }

    /// The crash story. A slot and the binding that names it are one commit, so
    /// the only state a crash can leave behind is a seat this employee already
    /// holds — and the next pass lands on that same seat rather than taking a
    /// second one.
    #[tokio::test]
    async fn a_slot_left_by_a_crashed_run_is_reused_never_doubled() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;
        add_pool_number(&db, employee.tenant_id(), POOLED, 5).await;

        // The dead worker's evidence: the seat is taken, nothing points at it.
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let seat = phone_pool::allocate_atomic(&mut tx, employee.id(), FR, Utc::now())
            .await
            .expect("allocate")
            .expect("room in the pool");
        tx.commit().await.expect("commit the orphaned seat");
        assert!(
            reload(&db, &employee)
                .await
                .resource(Step::Phone)
                .binding()
                .is_none()
        );

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            pooled_cfg(),
        );
        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge after the crash");

        assert_eq!(reports.get(&Step::Phone), Some(&StepReport::Ready));
        assert_eq!(
            live_slots(&db, &employee).await,
            1,
            "the crashed run's seat was taken twice"
        );
        let (_, _, _, external, _) = row(&db, &employee, Step::Phone).await;
        assert_eq!(
            external.as_deref(),
            Some(format!("{}/{}", seat.e164.as_str(), employee.id().as_uuid()).as_str()),
            "the reconciled binding must name the seat that already existed"
        );
        assert_eq!(telephony.number_count(), 0);
    }

    /// Termination gives the *slot* back, never the number: four colleagues are
    /// still sending from it, and its bundle cost a human review.
    ///
    /// The adapter here refuses every release, so a `Released` report is proof
    /// that nothing asked the provider to delete anything.
    #[tokio::test]
    async fn releasing_a_pooled_slot_frees_the_seat_and_leaves_the_number() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let lena = seed(&db).await;
        let alex = colleague(&db, lena.tenant_id(), "alex").await;
        add_pool_number(&db, lena.tenant_id(), POOLED, 5).await;

        let telephony = Arc::new(StubbornTelephony::default());
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            pooled_cfg(),
        );
        for who in [&lena, &alex] {
            engine
                .converge(who.tenant_id(), who.id())
                .await
                .expect("converge");
        }
        assert_eq!(live_slots(&db, &lena).await, 2, "both share one number");
        assert_eq!(telephony.number_count(), 0, "nothing was bought");

        let terminated = terminate(&db, &reload(&db, &lena).await).await;
        let reports = engine.release_all(&terminated).await.expect("release");

        assert_eq!(reports.get(&Step::Phone), Some(&ReleaseReport::Released));
        assert_eq!(
            telephony.release_attempts(),
            0,
            "the provider was asked to delete a number four colleagues share"
        );
        // The seat is free, the number is still the tenant's, and the colleague
        // still holds his.
        assert_eq!(live_slots(&db, &lena).await, 1);
        assert_eq!(
            count(&db, &lena, "SELECT count(*) FROM phone_numbers").await,
            1,
            "the number left the pool with the employee"
        );
        let mut tx = db.tenant_tx(lena.tenant_id()).await.expect("tx");
        assert!(
            phone_pool::current_allocation(&mut tx, alex.id(), FR)
                .await
                .expect("current")
                .is_some(),
            "the colleague lost his seat when somebody else was terminated"
        );
        assert!(
            phone_pool::current_allocation(&mut tx, lena.id(), FR)
                .await
                .expect("current")
                .is_none()
        );
        tx.rollback().await.expect("rollback");
        assert!(
            reload(&db, &lena)
                .await
                .resource(Step::Phone)
                .binding()
                .is_none()
        );

        // And it is idempotent, like every other release here.
        let again = engine
            .release_all(&reload(&db, &lena).await)
            .await
            .expect("release again");
        assert_eq!(again.get(&Step::Phone), Some(&ReleaseReport::NotBound));
        assert_eq!(live_slots(&db, &lena).await, 1);
    }

    /// Pooling a region the tenant never bought into provisions nobody. It must
    /// say so instead of quietly buying a dedicated number and looking healthy.
    #[tokio::test]
    async fn a_pooled_region_with_no_numbers_fails_loudly_rather_than_buying() {
        let Some(db) = db().await else { return };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db).await;

        let telephony = Arc::new(MockTelephony::new(Utc::now(), "tok"));
        let engine = ProvisioningEngine::new(
            db.clone(),
            adapters(telephony.clone(), Arc::new(MockEmailProvider::new())),
            pooled_cfg(),
        );

        let reports = engine
            .converge(employee.tenant_id(), employee.id())
            .await
            .expect("converge");
        assert_eq!(
            reports.get(&Step::Phone),
            Some(&StepReport::Failed { code: EMPTY_POOL })
        );
        assert_eq!(telephony.number_count(), 0, "an empty pool must not buy");

        let (state, lease, _, _, last_error) = row(&db, &employee, Step::Phone).await;
        assert_eq!(state, "failed");
        assert_eq!(lease, None, "a finished step releases its lease");
        assert!(
            last_error
                .expect("the row must say why")
                .contains(EMPTY_POOL),
            "the operator has to be able to see what is misconfigured"
        );
    }
}
