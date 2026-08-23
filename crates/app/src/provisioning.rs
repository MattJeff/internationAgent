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
use agentos_domain::employee::{Employee, ProviderBinding, ResourceState, Step};
use agentos_domain::ids::{EmployeeId, IdempotencyKey, SecretRef, Slug, TenantId};
use agentos_providers::browser::BrowserProvider;
use agentos_providers::email::EmailProvider;
use agentos_providers::secrets::SecretStore;
use agentos_providers::telephony::{Region, TelephonyProvider};
use agentos_providers::{EnsureCtx, ProviderError, Provisioned, Secret};
use agentos_store::approvals::{self, ApprovalError, NewApproval};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::employee;
use agentos_store::provisioning::{self, Claim, IntentState, StepOutcome};
use chrono::{DateTime, TimeDelta, Utc};
use rand::Rng;
use serde_json::json;
use tokio::task::JoinSet;
use uuid::Uuid;

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
}

impl std::fmt::Debug for Adapters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait objects have nothing printable, and an adapter's Debug would be
        // the place a credential leaks anyway.
        f.write_str("Adapters { email, telephony, browser, secrets }")
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
            StepReport::Busy => "busy",
            StepReport::LeaseLost => "lease_lost",
            StepReport::Blocked { .. } => "blocked",
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
            // Identity, permissions, the wallet ledger, the knowledge and MCP
            // namespaces are ours: they are true the moment they are written
            // down, and their "external id" names the row that says so.
            Step::Identity => Ok(ProviderBinding::new(LOCAL, employee.did().to_owned())),
            Step::Wallet => Ok(local(employee, "wallet")),
            Step::CompanyKnowledge => Ok(local(employee, "knowledge")),
            Step::Mcp => Ok(local(employee, "mcp")),
            Step::A2a => Ok(local(employee, "a2a")),
            Step::Permissions => Ok(local(employee, "permissions")),

            Step::Email => Ok(bind(self.adapters.email.ensure_identity(ctx).await?)),
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

    use agentos_domain::action::Domain;
    use agentos_domain::employee::{Health, Lifecycle};
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

        let mut employee = Employee::new(
            EmployeeId::new_v7(now),
            tenant,
            Slug::parse("lena").expect("slug"),
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
}
