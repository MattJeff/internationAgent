//! The provisioning loop, the reaper that stops an employee rotting in
//! `pending_external`, and the sweeper that stops a terminated one being billed
//! forever.
//!
//! One tokio task. Every ~200ms it claims a batch of resource rows that want
//! work, hands each employee to [`agentos_app::provisioning::ProvisioningEngine`]
//! — which is what actually runs `ensure_step` per step, in dependency order,
//! under a lease — escalates anything whose external wait has run out of
//! patience, and then re-runs the release for terminated employees that still
//! hold something.
//!
//! # The termination sweep
//!
//! Termination releases resources from an `employee.terminated` outbox event.
//! A provider that is transiently down fails that handler, the outbox retries
//! it on its own backoff, and after eight attempts the event is **dead
//! lettered** — at which point nothing in the system ever tries again. The
//! phone number stays bought, the invoice keeps arriving, and the only trace is
//! a row nobody reads.
//!
//! So [`sweep`] is the standing question "is anybody still holding something
//! they were told to give back", asked of the database rather than of an event:
//!
//! | rule                                      | why |
//! |-------------------------------------------|-----|
//! | `lifecycle = 'terminated'` and bound      | the resource is real and still billed |
//! | never `release_not_supported`             | **structural**, not transient — see below |
//! | `release_attempt_count`, `release_attempted_at` | the release's **own** budget, not provisioning's |
//! | one attempt past the cap escalates        | a human is asked once, then the sweep goes quiet |
//! | `FOR UPDATE ... SKIP LOCKED`              | two replicas do not both call the provider |
//!
//! **`release_not_supported` is never retried.** Resend's sending domain is
//! shared across the tenant, so the adapter refuses to delete it on purpose and
//! will refuse identically forever; retrying would spend a provider call and
//! re-fire an operator alert on every tick for the life of the deployment. The
//! row keeps its binding and its reason and stays out of the retry set, and
//! `agentos_store::provisioning::stranded` is where an operator reads the list
//! of what they have to go and cancel by hand.
//!
//! **Nothing here can resurrect a terminated employee.** The sweep reaches
//! `release_steps` and nothing else — never `converge`, never `ensure_step` —
//! and [`load_terminated`] refuses to hand an employee to the release path
//! unless it really is terminated. That matters because a released row lands in
//! `disabled`, `disabled` *is* claimable, and converging a terminated employee
//! once re-provisioned all eleven steps and bought a fresh phone number.
//!
//! # What counts as work
//!
//! Four predicates, in [`CLAIM_SQL`], and each one is a different failure:
//!
//! | row                                            | why it is work |
//! |------------------------------------------------|----------------|
//! | `pending`                                      | never attempted |
//! | `provisioning` and `lease_until < now`         | **a worker died holding it** |
//! | `pending_external` and `expected_by < now`     | **the wait is now a problem** |
//! | `failed`, cold for `retry_after`, under the cap | a transient failure |
//!
//! ...and one exemption: **a stopped company's rows are not claimed, unless the
//! row is the second one.** A halt, or an operating window that has run out,
//! defers everything that has not started buying; the lapsed lease is the one
//! row that has, and stranding it is the failure `routes::halt` warns about.
//! [`CLAIM_SQL`] carries the whole argument and the table it turns on.
//!
//! The second row is the recovery case and the reason this query is not simply
//! "state = 'pending'". A worker that was killed mid-step leaves the row in
//! `provisioning` with its own lease on it; nothing else in the system ever
//! looks at that row again, so if the loop did not claim it the employee would
//! sit half-provisioned forever. Re-claiming it is safe because
//! `agentos_store::provisioning::claim_step` treats a lapsed lease as stealable
//! and the engine parks — rather than retries — any step whose provider call
//! may already have landed.
//!
//! # The lock is a formality; the lease is the claim
//!
//! [`CLAIM_SQL`] takes `FOR UPDATE ... SKIP LOCKED` so two replicas polling in
//! the same instant do not pick the same batch, and then **commits before
//! converging**. It has to: the engine's own `claim_step` takes `SELECT ... FOR
//! UPDATE` on the very same row, so holding the discovery lock across the
//! engine call would have this task waiting on a lock it holds itself — an
//! application-level deadlock that no database detects. Real mutual exclusion
//! between workers is the lease on `employee_resources`, which expires by
//! itself; the row lock only narrows the window in which two pollers do
//! redundant work.
//!
//! # traceparent
//!
//! An employee is provisioned because of a request, and the request is long
//! gone by the time the work runs. The `traceparent` recorded in
//! `outbox_events.payload` by whoever caused the work is read back here, put on
//! the span, and stamped onto the outbox events this run produces — so a
//! provisioning failure is attributable to the POST that asked for it instead
//! of being an orphan log line at 3am.
//!
//! # Shutdown
//!
//! The token is checked *between* employees and never during one. Cancelling
//! mid-call is precisely the crash that leaves an intent of unknown outcome
//! behind, which costs a human a reconciliation; finishing the employee in
//! flight costs a few seconds of drain.

use std::collections::BTreeMap;
use std::time::Duration;

use agentos_app::provisioning::{
    EngineError, ProvisioningEngine, RELEASE_NOT_SUPPORTED, RETRYABLE_CODES, ReleaseReport,
    StepReport,
};
use agentos_domain::action::{Action, McpTool};
use agentos_domain::employee::{Employee, Lifecycle, ResourceState, Step};
use agentos_domain::ids::{EmployeeId, Slug, TenantId};
use agentos_store::approvals::{self, ApprovalError, NewApproval};
use agentos_store::db::{Db, StoreError};
use agentos_store::employee;
use chrono::{DateTime, TimeDelta, Utc};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

/// Who files an escalation, and who has to answer it.
const REAPER_ACTOR: &str = "provisioning-reaper";
/// Who asks a human to go and cancel a resource the sweep could not release.
const SWEEPER_ACTOR: &str = "termination-sweeper";
/// The role a human must hold to act on an overdue external wait.
const OPERATOR_ROLE: &str = "operator";
/// The MCP server half of the escalation's action name. Distinct from the
/// engine's own `provisioning/<step>` reconciliation, because the two are
/// different questions and the approval hash must not conflate them.
const ESCALATION_SERVER: &str = "provisioning-overdue";
/// The server half for "this terminated employee is still being billed". A
/// third distinct name for a third distinct question, for the same reason.
const RELEASE_SERVER: &str = "release-stuck";

/// Rows a single claim may take.
const DEFAULT_BATCH: i64 = 32;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// The loop's knobs. Every one is an operational decision, so none of them is
/// buried in the algorithm.
#[derive(Debug, Clone)]
pub struct LoopConfig {
    /// Wait between polls when there was nothing to do.
    pub poll: Duration,
    /// Rows one claim may take.
    pub batch: i64,
    /// How cold a `failed` row must be before it is retried. Together with
    /// [`Self::max_attempts`] this is what keeps a permanently broken step —
    /// a region with no numbers for sale, a WhatsApp sender that does not
    /// exist — from being re-attempted five times a second forever.
    ///
    /// The termination sweep reuses it: a provider that is down must not be
    /// called once per 200ms tick either.
    pub retry_after: TimeDelta,
    /// Give up retrying a step after this many claims.
    ///
    /// One number, two independent budgets: provisioning spends
    /// `employee_resources.attempt_count`, the termination sweep spends
    /// `release_attempt_count`. A step that needed three attempts to be
    /// *bought* still gets the full count to be *given back*, because "the
    /// provider would not sell it" and "the provider will not take it back" are
    /// different failures and neither should eat the other's retries.
    pub max_attempts: i32,
    /// How long a human has to answer an escalation.
    pub approval_ttl: TimeDelta,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            poll: Duration::from_millis(200),
            batch: DEFAULT_BATCH,
            retry_after: TimeDelta::seconds(30),
            max_attempts: 5,
            // A resource that may already exist is a billing question; a day is
            // not enough for a human to get to it, a month is not urgency.
            approval_ttl: TimeDelta::days(7),
        }
    }
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/// Drive one employee's provisioning as far as it will go — and, once it is
/// terminated, give the resources back.
///
/// A trait with exactly one production implementation, and it earns that: this
/// crate cannot depend on `agentos-providers` (by design — the binary may not
/// touch a provider), so it cannot build the `Adapters` a real
/// [`ProvisioningEngine`] needs, and without this seam the loop below would
/// have no test at all.
///
/// Both halves of the engine are here because both halves are driven from the
/// one task below, and a second seam would be a second thing to keep in step.
pub trait Converge: Send + Sync + 'static {
    /// Run every runnable step for this employee and report what each came to.
    fn converge(
        &self,
        tenant_id: TenantId,
        employee_id: EmployeeId,
    ) -> impl Future<Output = Result<BTreeMap<Step, StepReport>, EngineError>> + Send;

    /// Give these steps back, dependents first, and report what each came to.
    ///
    /// The caller chooses the steps: the sweep excludes the ones a provider has
    /// already refused structurally, and that fact lives in the resource row
    /// rather than in the employee.
    fn release(
        &self,
        employee: &Employee,
        steps: Vec<Step>,
    ) -> impl Future<Output = Result<BTreeMap<Step, ReleaseReport>, EngineError>> + Send;
}

impl Converge for ProvisioningEngine {
    fn converge(
        &self,
        tenant_id: TenantId,
        employee_id: EmployeeId,
    ) -> impl Future<Output = Result<BTreeMap<Step, StepReport>, EngineError>> + Send {
        ProvisioningEngine::converge(self, tenant_id, employee_id)
    }

    async fn release(
        &self,
        employee: &Employee,
        steps: Vec<Step>,
    ) -> Result<BTreeMap<Step, ReleaseReport>, EngineError> {
        self.release_steps(employee, &steps).await
    }
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// One employee that wants work, and the trace it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Work {
    tenant_id: TenantId,
    employee_id: EmployeeId,
    /// W3C `traceparent` of the request that caused this work, if it left one.
    traceparent: Option<String>,
}

/// The provisioning worker and the pending-external reaper, in one task.
#[derive(Debug, Clone)]
pub struct ProvisioningLoop<C> {
    db: Db,
    engine: C,
    cfg: LoopConfig,
}

impl<C: Converge> ProvisioningLoop<C> {
    /// Wire a loop to a database and an engine.
    pub fn new(db: Db, engine: C) -> Self {
        Self {
            db,
            engine,
            cfg: LoopConfig::default(),
        }
    }

    /// Override the knobs.
    ///
    /// ponytail: the last `allow(dead_code)` in this binary, and a narrow one.
    /// `main.rs` takes [`LoopConfig::default`] — a 200ms poll is the right
    /// answer for every deployment so far, and a knob wired to an environment
    /// variable nobody sets is a knob that only exists to be wrong. The tests
    /// below do use it, to poll at 10ms instead of sleeping through the
    /// default, so this is "unused in the binary" rather than "unused". Delete
    /// the attribute the day a deployment needs a different rate.
    #[allow(dead_code)]
    #[must_use]
    pub fn with_config(mut self, cfg: LoopConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Poll until cancelled, then return once the employee in flight is done.
    pub async fn run(self, cancel: CancellationToken) {
        tracing::info!(poll_ms = self.cfg.poll.as_millis(), "provisioning loop up");

        while !cancel.is_cancelled() {
            match self.tick(Utc::now(), &cancel).await {
                Ok(0) => {}
                Ok(employees) => tracing::debug!(employees, "provisioning batch done"),
                // ponytail: a database outage is polled at the same rate as
                // ordinary work — five queries a second, which no Postgres
                // notices. Add backoff here if that ever shows up in a graph.
                Err(err) => tracing::error!(error = %err, "could not claim provisioning work"),
            }

            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(self.cfg.poll) => {}
            }
        }
        tracing::info!("provisioning loop drained");
    }

    /// One pass: claim a batch, converge each employee, reap what is overdue,
    /// then give back what a terminated employee is still holding.
    ///
    /// Returns how many employees were touched.
    async fn tick(
        &self,
        now: DateTime<Utc>,
        cancel: &CancellationToken,
    ) -> Result<usize, StoreError> {
        let batch = claim(&self.db, &self.cfg, now).await?;
        let mut done = 0;

        for work in batch {
            // Between employees, never during one: see the module docs.
            if cancel.is_cancelled() {
                break;
            }
            let span = tracing::info_span!(
                "provision",
                tenant = %work.tenant_id,
                employee = %work.employee_id.as_uuid(),
                traceparent = work.traceparent.as_deref().unwrap_or("-"),
            );
            self.drive(&work, now).instrument(span).await;
            done += 1;
        }

        // The same tick, the same token, a different question — see the module
        // docs. Its own claim, because "still provisioning" and "terminated and
        // still bound" have no rows in common.
        done += self.sweep(now, cancel).await?;
        Ok(done)
    }

    /// Everything one claimed employee gets: the engine, then the reaper, then
    /// the trace stamp.
    async fn drive(&self, work: &Work, now: DateTime<Utc>) {
        match self.engine.converge(work.tenant_id, work.employee_id).await {
            Ok(reports) => {
                // Every outcome, ready included: a `rate(ready)` that is flat
                // is how you tell "no failures" from "no provisioning". Both
                // labels are `&'static str` from a closed match, so eleven
                // steps times nine codes is the whole series count, forever.
                for (step, report) in &reports {
                    crate::metrics::record_provisioning(*step, report);
                }
                // `NotWired` is left out, and it is the only outcome that is:
                // it is not ready and never will be, so listing it under
                // "steps did not reach ready" would print the same warning on
                // every convergence of every employee for a capability that is
                // deliberately off. The counter above still sees it — under its
                // own `not_wired` label, which is the point of having one.
                let unready: Vec<_> = reports
                    .iter()
                    .filter(|(_, report)| {
                        !report.is_ready() && !matches!(report, StepReport::NotWired)
                    })
                    .map(|(step, report)| format!("{step}={}", report.code()))
                    .collect();
                if unready.is_empty() {
                    tracing::info!("every step is ready");
                } else {
                    tracing::warn!(steps = %unready.join(","), "steps did not reach ready");
                }
            }
            Err(err) => tracing::error!(error = %err, "converge failed"),
        }

        // After the engine, not before: a step the engine has just parked in
        // `pending_external` with a fresh deadline is not overdue, and reaping
        // first would only escalate the previous deadline a tick early.
        match reap(&self.db, &self.cfg, work, now).await {
            Ok(steps) if !steps.is_empty() => {
                let steps: Vec<_> = steps.into_iter().map(Step::as_str).collect();
                tracing::warn!(steps = %steps.join(","), "escalated an overdue external wait");
            }
            Ok(_) => {}
            Err(err) => tracing::error!(error = %err, "could not escalate an overdue wait"),
        }

        if let Some(traceparent) = &work.traceparent
            && let Err(err) = stamp_trace(&self.db, work, traceparent).await
        {
            // The work happened; only the correlation is lost.
            tracing::warn!(error = %err, "could not carry the traceparent onto the outbox");
        }
    }

    /// Re-run the release for terminated employees that still hold something.
    ///
    /// Returns how many employees were swept.
    async fn sweep(
        &self,
        now: DateTime<Utc>,
        cancel: &CancellationToken,
    ) -> Result<usize, StoreError> {
        // Eleven steps of one employee are eleven rows and one unit of work,
        // exactly as in `claim`: `release_steps` walks them in dependency order
        // in one pass, and asking per row would release the vault before the
        // browser profile whose credentials live in it.
        let mut grouped: Vec<(TenantId, EmployeeId, Vec<Release>)> = Vec::new();
        for row in claim_releases(&self.db, &self.cfg, now).await? {
            if let Some((_, _, steps)) =
                grouped.iter_mut().find(|(_, id, _)| *id == row.employee_id)
            {
                steps.push(row);
            } else {
                grouped.push((row.tenant_id, row.employee_id, vec![row]));
            }
        }

        let swept = grouped.len();
        for (tenant_id, employee_id, claimed) in grouped {
            if cancel.is_cancelled() {
                break;
            }
            let span = tracing::info_span!(
                "release-sweep",
                tenant = %tenant_id,
                employee = %employee_id.as_uuid(),
            );
            self.give_back(tenant_id, employee_id, claimed, now)
                .instrument(span)
                .await;
        }
        Ok(swept)
    }

    /// One terminated employee: release what still has budget, ask a human
    /// about what does not.
    async fn give_back(
        &self,
        tenant_id: TenantId,
        employee_id: EmployeeId,
        claimed: Vec<Release>,
        now: DateTime<Utc>,
    ) {
        let employee = match load_terminated(&self.db, tenant_id, employee_id).await {
            Ok(Some(employee)) => employee,
            // Not terminated any more — impossible today, since `Terminated` is
            // absorbing, and cheap insurance against the day it is not.
            // Releasing an employee that is back at work would be this loop
            // taking somebody's phone number away.
            Ok(None) => {
                tracing::warn!("skipped a swept employee that is not terminated");
                return;
            }
            Err(err) => {
                tracing::error!(error = %err, "could not load a swept employee");
                return;
            }
        };

        // Past the cap the sweep stops calling providers and starts asking
        // people. The claim spent the last of the budget getting here, so this
        // employee is not claimed again and the question is asked once.
        let (exhausted, retryable): (Vec<Release>, Vec<Release>) = claimed
            .into_iter()
            .partition(|release| release.attempt > self.cfg.max_attempts);

        if !retryable.is_empty() {
            let steps: Vec<Step> = retryable.iter().map(|release| release.step).collect();
            match self.engine.release(&employee, steps).await {
                Ok(reports) => {
                    let stuck: Vec<_> = reports
                        .iter()
                        .filter(|(_, report)| !report.is_done())
                        .map(|(step, report)| format!("{step}={}", report.code()))
                        .collect();
                    if stuck.is_empty() {
                        tracing::info!("released what a dead-lettered termination left bound");
                    } else {
                        // Still bound, still billed. The row carries the reason
                        // and the next sweep — or the cap — takes it from here.
                        tracing::warn!(steps = %stuck.join(","), "could not release; still billed");
                    }
                }
                Err(err) => tracing::error!(error = %err, "release sweep failed"),
            }
        }

        if !exhausted.is_empty() {
            match escalate_release(&self.db, &self.cfg, &employee, &exhausted, now).await {
                Ok(steps) if !steps.is_empty() => {
                    let steps: Vec<_> = steps.into_iter().map(Step::as_str).collect();
                    tracing::error!(
                        steps = %steps.join(","),
                        "gave up releasing these; a human has to cancel them at the provider"
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::error!(error = %err, "could not escalate a stuck release"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Claiming
// ---------------------------------------------------------------------------

/// The four predicates, the stop, the trace to inherit, and the queue lock.
///
/// `$1` now, `$2` the retry cutoff, `$3` the attempt cap, `$4` the batch size,
/// `$5` the codes a retry could still fix.
///
/// # `failed` was never one thing, and the cap was pricing it as if it were
///
/// The fourth predicate used to read "failed, cold, under the cap" and stop
/// there, so `bad_secret_ref`, `no_numbers_available`, `unauthorized` and every
/// other terminal refusal bought [`LoopConfig::max_attempts`] provider calls
/// each — the same answer, five times, on a backoff, for a step whose own
/// `call_until` had already refused to retry it once inside the pass. The
/// release side of this very file has had the corresponding guard since it
/// existed (`SWEEP_SQL`, and `RELEASE_NOT_SUPPORTED` is bound into it); the
/// converge side did not.
///
/// `$5` is [`agentos_providers::RETRYABLE_CODES`] — bound, never spelled here,
/// for the reason that constant's own docs give. `last_error` on a failed row is
/// `format!("{}: {err}", err.code())` (`ProvisioningEngine::ensure_step`), so
/// `split_part(…, ':', 1)` is the code and nothing else; no provider code
/// contains a colon.
///
/// **NULL `last_error` stays claimable, and that is the safe direction.** It is
/// not "no code we recognise" — it is a row that never carried a provider
/// verdict at all: the reaper's `pending_external -> failed`, whose whole point
/// is that the wait ended and the step should be tried again, and every row
/// written before this predicate existed. Reading NULL as terminal would park
/// those silently, which is the failure mode this change must not become.
///
/// ponytail: an employee claimed for a *retryable* row still converges its
/// terminal steps in the same pass, because `converge` walks all eleven. The
/// ceiling is one extra call per terminal step per genuine retry, not five per
/// tick; closing it means carrying `last_error` into `domain::ResourceStatus`
/// so `ensure_step` can park on it, and that is a domain change to buy a
/// rounding error.
/// # The stop, and exactly how far it reaches
///
/// The last clause is [`not_stopped!`](agentos_store::not_stopped), the same
/// fragment `outbox::claim_of` and `initiative::claim_due` use, correlated on
/// `r.tenant_id` because this query is driven by the queue table rather than by
/// `tenants`. It **defers**: a row that is not selected is not written, so
/// `attempt_count`, `updated_at` and `expected_by` are all exactly what they
/// were, and the tick after the halt is lifted or the window extended finds
/// them due again with nobody's help. That is the same property
/// `initiative::claim_due` holds by leaving `next_at` in the past.
///
/// **The `OR` in front of it is the whole judgement, so it is written down.**
/// `routes::halt` argues that stopping this loop half-way is worse than not
/// stopping it, because interrupting a convergence leaves resources bought and
/// unbound. That argument is right, and it is about *interrupting*. It does not
/// cover *not starting*, and the two are different rows:
///
/// | state | is there a provider call to be uncertain about? |
/// |-------|--------------------------------------------------|
/// | `pending` | no — `claim_step` never ran, so there is no `provider_intents` row at all |
/// | `failed` | no — `finish_step` closed the intent `failed`; a retry is a *fresh* purchase |
/// | `pending_external` | not one we can affect — `ensure_step` returns from this state without touching anything, and the reaper below only files an approval |
/// | `provisioning`, lease lapsed | **yes** — `claim_step` commits the intent *before* the call, so this row is a call whose outcome nobody knows |
///
/// So the fourth row is exempted from the stop and the other three are not.
/// That exemption is not politeness: `ProvisioningEngine::claim` is the only
/// thing in this workspace that closes an orphaned intent —
/// `sweep_expired_leases` and `mark_intent_orphaned` have one call site each,
/// both inside it, reachable only through `converge`, reachable only from this
/// loop. Deferring that row would leave the intent `in_flight` for the length
/// of the stop and leave the human who has to reconcile a possibly-bought phone
/// number unasked. That is precisely the stranded stock `routes::halt`
/// describes, and precisely what this clause refuses to create.
///
/// **What it does not buy back.** `converge` takes an employee, not a step, so
/// an employee exempted for its one lapsed lease has *all eleven* of its steps
/// run, pending ones included. The frontier is therefore per employee and not
/// per row, and closing that last gap needs a `converge` that accepts a step
/// list — the resumable state machine `routes::halt` says is not this unit, and
/// it still is not. It is strictly less spend than before this clause existed,
/// which is the bar every stop in this workspace is held to.
///
/// Measured, so the next reader does not have to: the planner turns both
/// `NOT EXISTS` into **hashed subplans** — one scan of each of the two
/// one-row-per-company tables per execution, not a probe per candidate row — so
/// the clause costs the same whether the batch scans ten rows or ten thousand.
///
/// FOUNDER'S QUESTION, LEFT OPEN, and it is `outbox::claim_of`'s question word
/// for word: a halt has `DELETE /v1/halt`, but a window that ended has no
/// release verb, so a finished company's eleven pending resources now wait here
/// forever. Deferred is the conservative half — nothing is lost, extending the
/// window provisions them all — but "does a finished company ever get
/// provisioned" is a product decision and this file will not invent one.
const CLAIM_SQL: &str = concat!(
    "\
SELECT r.tenant_id,
       r.employee_id,
       (SELECT o.payload->>'traceparent'
          FROM outbox_events o
         WHERE o.aggregate_id = r.employee_id
           AND o.payload->>'traceparent' IS NOT NULL
         ORDER BY o.created_at DESC
         LIMIT 1)
  FROM employee_resources r
  JOIN employees e ON e.id = r.employee_id
 WHERE e.lifecycle IN ('draft', 'active')
   AND (   r.state = 'pending'
        OR (r.state = 'provisioning'     AND r.lease_until < $1)
        OR (r.state = 'pending_external' AND r.expected_by < $1)
        OR (r.state = 'failed' AND r.attempt_count < $3 AND r.updated_at < $2
            AND (   r.last_error IS NULL
                 OR split_part(r.last_error, ':', 1) = ANY($5))))
   AND (   (r.state = 'provisioning' AND r.lease_until < $1)
        OR (",
    agentos_store::not_stopped!("r.tenant_id"),
    "))
 ORDER BY r.updated_at
 LIMIT $4
 FOR UPDATE OF r SKIP LOCKED"
);

/// Take a batch of employees that want work, newest-stale first.
///
/// Cross-tenant by nature, like the outbox poller: the queue is not any one
/// tenant's. The transaction is committed before the caller does anything with
/// the result — see the module docs on why holding it would deadlock.
async fn claim(db: &Db, cfg: &LoopConfig, now: DateTime<Utc>) -> Result<Vec<Work>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let rows: Vec<(Uuid, Uuid, Option<String>)> = sqlx::query_as(CLAIM_SQL)
        .bind(now)
        .bind(now - cfg.retry_after)
        .bind(cfg.max_attempts)
        .bind(cfg.batch)
        .bind(RETRYABLE_CODES.as_slice())
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    // Eleven steps of one employee are eleven rows and one unit of work: the
    // engine converges the whole employee in dependency order, so claiming it
    // once per stale row would just be ten no-op passes.
    let mut work: Vec<Work> = Vec::with_capacity(rows.len());
    for (tenant_id, employee_id, traceparent) in rows {
        let employee_id = EmployeeId::from_uuid(employee_id);
        if work.iter().any(|w| w.employee_id == employee_id) {
            continue;
        }
        work.push(Work {
            tenant_id: TenantId::from_uuid(tenant_id),
            employee_id,
            traceparent,
        });
    }
    Ok(work)
}

// ---------------------------------------------------------------------------
// The pending-external reaper
// ---------------------------------------------------------------------------

/// Escalate every step whose external wait has run out, and stop waiting on it.
///
/// Two writes in one transaction, because half of this is worthless: an
/// approval so a human hears about it, and `pending_external -> failed` so the
/// row stops looking like a wait that is still going somewhere. Without the
/// second write the step is claimed again on the very next poll and the only
/// thing standing between the operator and a thousand identical approvals is
/// the duplicate check.
///
/// Returns the steps that were escalated.
async fn reap(
    db: &Db,
    cfg: &LoopConfig,
    work: &Work,
    now: DateTime<Utc>,
) -> Result<Vec<Step>, ApprovalError> {
    let mut tx = db.tenant_tx(work.tenant_id).await?;
    let stored = employee::load(&mut tx, work.employee_id).await?;
    let overdue = stored.employee.overdue(now);
    if overdue.is_empty() {
        tx.rollback().await?;
        return Ok(Vec::new());
    }

    let mut employee = stored.employee;
    let mut escalated = Vec::with_capacity(overdue.len());
    for step in overdue {
        let action = escalation_action(ESCALATION_SERVER, step);
        if !already_asked(&mut tx, &employee, &action).await? {
            let reason = escalation_reason(&employee, step, now);
            approvals::create(
                &mut tx,
                &NewApproval {
                    employee_id: Some(employee.id()),
                    action: &action,
                    requested_by: REAPER_ACTOR,
                    required_role: OPERATOR_ROLE,
                    reason: Some(&reason),
                    expires_at: now + cfg.approval_ttl,
                },
                now,
            )
            .await?;
        }
        // `overdue` only ever names a `pending_external` step, and that state
        // may always move to `failed` — but a loop task must not panic on a
        // domain invariant, so a surprise is logged and the step is left where
        // a later pass can find it.
        match employee.set_resource(step, ResourceState::Failed, now) {
            Ok(()) => escalated.push(step),
            Err(err) => tracing::error!(error = %err, %step, "could not fail an overdue step"),
        }
    }

    if escalated.is_empty() {
        tx.rollback().await?;
        return Ok(escalated);
    }
    employee::update(&mut tx, &employee, stored.version).await?;
    tx.commit().await?;
    Ok(escalated)
}

/// Has a human already been asked this exact question and not yet answered it?
///
/// The hash is computed by Postgres over the same canonical bytes
/// `approvals::create` hashes, so the two can only ever agree.
async fn already_asked(
    tx: &mut agentos_store::db::TenantTx<'_>,
    employee: &Employee,
    action: &Action,
) -> Result<bool, ApprovalError> {
    let canonical = approvals::canonical_json(action)?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM approvals \
          WHERE employee_id = $1 \
            AND state = 'pending' \
            AND action->>'action_hash' = encode(sha256(convert_to($2::text, 'UTF8')), 'hex') \
          LIMIT 1",
    )
    .bind(employee.id().as_uuid())
    .bind(&canonical)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(StoreError::from)?;

    Ok(existing.is_some())
}

/// The action an escalation authorises a human to go and do.
///
/// ponytail: an `Action::McpCall` named `<server>/<step>`, for the same reason
/// the engine files one — `Action` is a closed domain enum with no "chase a
/// regulator" variant and widening it is not this unit's call. The server half
/// is the question being asked ([`ESCALATION_SERVER`], [`RELEASE_SERVER`], the
/// engine's own `provisioning`) so that three different questions about one
/// step hash differently and none of them suppresses the others.
fn escalation_action(server: &str, step: Step) -> Action {
    let name = Slug::parse(&step.as_str().replace('_', "-"))
        .or_else(|_| Slug::parse("step"))
        .expect("`step` is a valid slug");
    Action::McpCall {
        tool: McpTool::new(Slug::parse(server).expect("a valid slug"), name),
    }
}

/// The whole story, in the one line the operator will actually read.
fn escalation_reason(employee: &Employee, step: Step, now: DateTime<Utc>) -> String {
    let (poll_ref, expected_by) = match employee.resource(step).state() {
        ResourceState::PendingExternal {
            poll_ref,
            expected_by,
        } => (poll_ref.clone(), *expected_by),
        // Unreachable via `overdue`, and a placeholder beats a panic.
        _ => (String::new(), now),
    };
    format!(
        "{step} for employee {} has been waiting on {poll_ref} since before {expected_by}, \
         which is past due. Nothing on our side will move it: check the provider (a rejected \
         bundle or sender review looks exactly like one still in progress from here), then \
         either resolve it there or disable the channel. The step has been marked failed so \
         it stops reporting as a wait.",
        employee.id().as_uuid(),
    )
}

// ---------------------------------------------------------------------------
// The termination sweeper
// ---------------------------------------------------------------------------

/// One resource row this tick has taken responsibility for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Release {
    tenant_id: TenantId,
    employee_id: EmployeeId,
    step: Step,
    /// `release_attempt_count` **after** the claim spent one. Past
    /// [`LoopConfig::max_attempts`] this row buys an escalation instead of a
    /// provider call.
    attempt: i32,
}

/// Terminated, still bound, cold enough to try again, and not structurally
/// impossible. Claimed by bumping the release counter, in one statement.
///
/// `$1` now, `$2` the attempt cap, `$3` the retry cutoff, `$4` the code that is
/// never retried, `$5` the batch size.
///
/// Shaped like `agentos_store::outbox::claim` rather than like [`CLAIM_SQL`],
/// and for the same reason that one is: the claim has to be the write. Counting
/// the attempt here rather than after the release means a worker that is killed
/// mid-call still burns one, so a provider that hangs cannot be retried forever
/// by a fleet of dying workers. `SKIP LOCKED` is what keeps two replicas off
/// the same row, and the stamped `release_attempted_at` is what keeps the
/// *next* tick off it — either alone would do; both is free.
///
/// **`release_*`, not `attempt_count`.** Provisioning's counter belongs to
/// provisioning; spending it here would charge a release for the attempts it
/// took to buy the thing. `coalesce(release_attempted_at, updated_at)` is how a
/// row written before that column existed keeps the backoff it already had:
/// NULL means "never swept under this counter", and falling back to
/// `updated_at` is exactly the old predicate.
///
/// `strpos` rather than `LIKE`: a NULL `last_error` is the common case and must
/// not fall out of the predicate as NULL.
const SWEEP_SQL: &str = "\
UPDATE employee_resources AS r
   SET release_attempt_count = r.release_attempt_count + 1,
       release_attempted_at = $1,
       updated_at = $1
 WHERE (r.employee_id, r.step) IN (
       SELECT c.employee_id, c.step
         FROM employee_resources c
         JOIN employees e ON e.id = c.employee_id
        WHERE e.lifecycle = 'terminated'
          AND c.external_id IS NOT NULL
          AND c.release_attempt_count <= $2
          AND coalesce(c.release_attempted_at, c.updated_at) < $3
          AND strpos(coalesce(c.last_error, ''), $4) = 0
        ORDER BY coalesce(c.release_attempted_at, c.updated_at)
        LIMIT $5
        FOR UPDATE OF c SKIP LOCKED)
 RETURNING r.tenant_id, r.employee_id, r.step, r.release_attempt_count";

/// Take a batch of resources a terminated employee is still being billed for.
///
/// Cross-tenant, like [`claim`] and the outbox poller: an unreleased resource
/// is not any one tenant's problem. Everything downstream of it runs in a
/// [`agentos_store::db::Db::tenant_tx`], so the escape hatch is this statement
/// and nothing else.
async fn claim_releases(
    db: &Db,
    cfg: &LoopConfig,
    now: DateTime<Utc>,
) -> Result<Vec<Release>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let rows: Vec<(Uuid, Uuid, String, i32)> = sqlx::query_as(SWEEP_SQL)
        .bind(now)
        .bind(cfg.max_attempts)
        .bind(now - cfg.retry_after)
        .bind(RELEASE_NOT_SUPPORTED)
        .bind(cfg.batch)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(rows
        .into_iter()
        .filter_map(|(tenant_id, employee_id, step, attempt)| {
            Some(Release {
                tenant_id: TenantId::from_uuid(tenant_id),
                employee_id: EmployeeId::from_uuid(employee_id),
                // Text the build has never heard of means the database
                // disagrees with it about what steps exist. Skip the row rather
                // than guess which resource is being billed.
                step: Step::ALL.into_iter().find(|s| s.as_str() == step)?,
                attempt,
            })
        })
        .collect())
}

/// The employee, but only if it really is terminated.
///
/// The one door between the sweep and the release path. `ensure_step` refuses
/// to provision anything that is not draft or active; this refuses to release
/// anything that is not terminated. Neither can be reached from the other side.
async fn load_terminated(
    db: &Db,
    tenant_id: TenantId,
    employee_id: EmployeeId,
) -> Result<Option<Employee>, StoreError> {
    let mut tx = db.tenant_tx(tenant_id).await?;
    let stored = employee::load(&mut tx, employee_id).await?;
    tx.rollback().await?;
    Ok((stored.employee.lifecycle() == Lifecycle::Terminated).then_some(stored.employee))
}

/// Ask a human to cancel by hand what the sweep could not release.
///
/// Guarded by [`already_asked`], like the reaper: a stuck employee is worth one
/// question, not one per tick. The claim's attempt cap means this is normally
/// reached exactly once anyway — the guard is what makes that true even if two
/// replicas reach it in the same instant.
///
/// Returns the steps a human was actually asked about.
async fn escalate_release(
    db: &Db,
    cfg: &LoopConfig,
    employee: &Employee,
    exhausted: &[Release],
    now: DateTime<Utc>,
) -> Result<Vec<Step>, ApprovalError> {
    let mut tx = db.tenant_tx(employee.tenant_id()).await?;
    let mut asked = Vec::new();

    for release in exhausted {
        let action = escalation_action(RELEASE_SERVER, release.step);
        if already_asked(&mut tx, employee, &action).await? {
            continue;
        }
        let reason = release_reason(employee, release.step, release.attempt);
        approvals::create(
            &mut tx,
            &NewApproval {
                employee_id: Some(employee.id()),
                action: &action,
                requested_by: SWEEPER_ACTOR,
                required_role: OPERATOR_ROLE,
                reason: Some(&reason),
                expires_at: now + cfg.approval_ttl,
            },
            now,
        )
        .await?;
        asked.push(release.step);
    }

    if asked.is_empty() {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }
    Ok(asked)
}

/// The whole story, in the one line the operator will actually read.
fn release_reason(employee: &Employee, step: Step, attempts: i32) -> String {
    let (provider, external_id) = employee
        .resource(step)
        .binding()
        .map_or(("?", "?"), |binding| {
            (binding.provider(), binding.external_id())
        });
    format!(
        "{step} for terminated employee {} is still bound to {provider} resource {external_id} \
         after {attempts} attempts to release it, so it is still being billed. The sweep has \
         stopped retrying: cancel it at the provider by hand, then clear the binding. The row \
         keeps the external id because it is the only thing that says what to cancel.",
        employee.id().as_uuid(),
    )
}

// ---------------------------------------------------------------------------
// traceparent
// ---------------------------------------------------------------------------

/// Put this run's `traceparent` on every event it produced that lacks one.
///
/// ponytail: a stamp after the fact rather than a parameter threaded through
/// `finish_step`, because `agentos-store` is another unit's crate. It is one
/// statement, it is idempotent, and the events are still unpublished — the
/// outbox poller reads the payload it will actually send.
async fn stamp_trace(db: &Db, work: &Work, traceparent: &str) -> Result<(), StoreError> {
    let mut tx = db.tenant_tx(work.tenant_id).await?;
    sqlx::query(
        "UPDATE outbox_events \
            SET payload = jsonb_set(payload, '{traceparent}', to_jsonb($2::text), true) \
          WHERE aggregate_id = $1 \
            AND published_at IS NULL \
            AND payload->>'traceparent' IS NULL",
    )
    .bind(work.employee_id.as_uuid())
    .bind(traceparent)
    .execute(&mut **tx)
    .await?;
    tx.commit().await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use agentos_domain::action::Domain;
    use agentos_domain::employee::Health;

    use super::*;

    /// One database, one schema, and a `(provider, external_id)` index that is
    /// global to it. Tests take turns.
    static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// These tests share one database and read across every tenant in it, so
    /// they go one at a time. `claim` takes a bounded batch of whoever is
    /// stalest, `claim_releases` *writes* to every tenant it can see, and the
    /// sweep escalates employees it was never told about — three assertions
    /// about a global object that a sibling test running beside them changes
    /// under their feet. The private database keeps other *modules* out; this
    /// keeps this module out of its own way. Same reason `loops::outbox` has
    /// one.
    static PROVISIONING_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The slug every tenant this module creates carries, so [`reset`] names
    /// its own rows rather than the table.
    const TENANT_SLUG: &str = "loop-provisioning-";

    /// This module's own database — see [`private_db`](crate::loops::private_db).
    ///
    /// `claim` takes a bounded batch of whoever is stalest across every tenant,
    /// so another test's pending rows push this one's out of the window, and
    /// `claim_releases` *writes* to every tenant it can see. Neither is narrowed
    /// by a `WHERE tenant_id = $1`: the loop is cross-tenant because that is
    /// what a poller is.
    async fn db() -> Option<(Db, tokio::sync::MutexGuard<'static, ()>)> {
        let guard = PROVISIONING_LOCK.lock().await;
        let db = crate::loops::private_db("provisioning").await?;
        Some((db, guard))
    }

    async fn reset(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        // Scoped even though this database is this module's own: see
        // `crates/app/tests/scoped_deletes.rs` for why the rule has no
        // exception for "it is safe here".
        sqlx::query("DELETE FROM tenants WHERE slug LIKE 'loop-provisioning-%'")
            .execute(&mut *tx)
            .await
            .expect("wipe");
        tx.commit().await.expect("commit wipe");
    }

    /// A tenant and one active employee with all eleven resource rows pending.
    async fn seed(db: &Db, slug: &str) -> Employee {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            // The prefix is what makes `reset` a scoped statement instead of a
            // wipe. A predicate that matches nothing deletes nothing and looks
            // exactly like a fix, so the two have to be changed together.
            .bind(format!("{TENANT_SLUG}{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit tenant");

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

    async fn reload(db: &Db, employee: &Employee) -> Employee {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let stored = employee::load(&mut tx, employee.id()).await.expect("load");
        tx.rollback().await.expect("rollback");
        stored.employee
    }

    async fn exec(db: &Db, employee: &Employee, sql: &'static str) {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        sqlx::query(sql)
            .bind(employee.id().as_uuid())
            .execute(&mut **tx)
            .await
            .expect("statement");
        tx.commit().await.expect("commit");
    }

    async fn scalar<T>(db: &Db, employee: &Employee, sql: &'static str) -> T
    where
        T: for<'a> sqlx::Decode<'a, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
    {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let value: T = sqlx::query_scalar(sql)
            .bind(employee.id().as_uuid())
            .fetch_one(&mut **tx)
            .await
            .expect("scalar");
        tx.rollback().await.expect("rollback");
        value
    }

    /// Every step provisioned and bound to a resource somebody is billing for,
    /// touched an hour ago so the sweep's backoff does not hide it.
    async fn bind_all(db: &Db, employee: &Employee) {
        exec(
            db,
            employee,
            "UPDATE employee_resources \
                SET state = 'ready', provider = 'mock', \
                    external_id = 'ext-' || $1::text || '-' || step, \
                    updated_at = now() - interval '1 hour' \
              WHERE employee_id = $1",
        )
        .await;
    }

    /// What the terminate endpoint does: the lifecycle move, persisted. The
    /// resource rows keep their bindings — that is the whole problem.
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

    /// How many resources still name something a provider is billing for.
    async fn still_bound(db: &Db, employee: &Employee) -> i64 {
        scalar(
            db,
            employee,
            "SELECT count(*) FROM employee_resources \
              WHERE employee_id = $1 AND external_id IS NOT NULL",
        )
        .await
    }

    // -- a converger that provisions by fiat ------------------------------

    /// Stands in for the real engine, which this crate cannot build: it has no
    /// access to `agentos-providers` by design. It does what a successful
    /// engine run does to the database — every step ready, every binding given
    /// back — and records every call, which is the assertion that matters.
    #[derive(Debug, Clone, Default)]
    struct FakeEngine {
        db: Option<Db>,
        calls: Arc<Mutex<HashMap<EmployeeId, u32>>>,
        /// Every `release` that reached a provider, in order. Clones share it,
        /// so two loops driving one engine are counted together.
        releases: Arc<Mutex<Vec<(EmployeeId, Step)>>>,
        /// One step whose provider will not let go, and the code it refuses
        /// with. `release_not_supported` is the structural one.
        refuse: Option<(Step, &'static str)>,
        /// Claim the work and do nothing, like a step that is still waiting.
        inert: bool,
    }

    impl FakeEngine {
        fn ready(db: &Db) -> Self {
            Self {
                db: Some(db.clone()),
                ..Self::default()
            }
        }

        fn inert() -> Self {
            Self {
                inert: true,
                ..Self::default()
            }
        }

        #[must_use]
        fn refusing(mut self, step: Step, code: &'static str) -> Self {
            self.refuse = Some((step, code));
            self
        }

        fn calls(&self, employee: EmployeeId) -> u32 {
            *self
                .calls
                .lock()
                .expect("poisoned")
                .get(&employee)
                .unwrap_or(&0)
        }

        /// How many times a provider was asked to give this step back.
        fn releases_of(&self, step: Step) -> usize {
            self.releases
                .lock()
                .expect("poisoned")
                .iter()
                .filter(|(_, released)| *released == step)
                .count()
        }

        /// Every release call, in order.
        fn releases(&self) -> Vec<(EmployeeId, Step)> {
            self.releases.lock().expect("poisoned").clone()
        }
    }

    impl Converge for FakeEngine {
        async fn converge(
            &self,
            tenant_id: TenantId,
            employee_id: EmployeeId,
        ) -> Result<BTreeMap<Step, StepReport>, EngineError> {
            *self
                .calls
                .lock()
                .expect("poisoned")
                .entry(employee_id)
                .or_default() += 1;
            if self.inert {
                return Ok(BTreeMap::new());
            }

            let db = self.db.clone().expect("a working engine needs a database");
            let mut tx = db.tenant_tx(tenant_id).await?;
            sqlx::query(
                "UPDATE employee_resources \
                    SET state = 'ready', poll_ref = NULL, expected_by = NULL, \
                        lease_owner = NULL, lease_until = NULL, updated_at = now() \
                  WHERE employee_id = $1 AND state <> 'ready'",
            )
            .bind(employee_id.as_uuid())
            .execute(&mut **tx)
            .await
            .map_err(StoreError::from)?;
            let stored = employee::load(&mut tx, employee_id).await?;
            let employee = stored.employee;
            // The health column is derived, and the loop's callers read it.
            employee::update(&mut tx, &employee, stored.version).await?;
            tx.commit().await?;

            Ok(Step::ALL
                .into_iter()
                .map(|step| (step, StepReport::Ready))
                .collect())
        }

        /// What the real `release_step` does to the database, in miniature: a
        /// released resource loses its binding and lands in `disabled`, and a
        /// refused one **keeps** the binding — it is the only record of what a
        /// human still has to cancel — and carries the reason.
        async fn release(
            &self,
            employee: &Employee,
            steps: Vec<Step>,
        ) -> Result<BTreeMap<Step, ReleaseReport>, EngineError> {
            let db = self
                .db
                .clone()
                .expect("a releasing engine needs a database");
            let mut reports = BTreeMap::new();

            for step in steps {
                if employee.resource(step).binding().is_none() {
                    reports.insert(step, ReleaseReport::NotBound);
                    continue;
                }
                self.releases
                    .lock()
                    .expect("poisoned")
                    .push((employee.id(), step));

                let mut tx = db.tenant_tx(employee.tenant_id()).await?;
                let report = match self.refuse {
                    Some((refused, code)) if refused == step => {
                        sqlx::query(
                            "UPDATE employee_resources \
                                SET state = 'failed', last_error = $3, updated_at = now() \
                              WHERE employee_id = $1 AND step = $2",
                        )
                        .bind(employee.id().as_uuid())
                        .bind(step.as_str())
                        .bind(format!("release {code}: the provider refused"))
                        .execute(&mut **tx)
                        .await
                        .map_err(StoreError::from)?;
                        ReleaseReport::Failed { code }
                    }
                    _ => {
                        sqlx::query(
                            "UPDATE employee_resources \
                                SET state = 'disabled', provider = NULL, external_id = NULL, \
                                    last_error = NULL, updated_at = now() \
                              WHERE employee_id = $1 AND step = $2",
                        )
                        .bind(employee.id().as_uuid())
                        .bind(step.as_str())
                        .execute(&mut **tx)
                        .await
                        .map_err(StoreError::from)?;
                        ReleaseReport::Released
                    }
                };
                tx.commit().await?;
                reports.insert(step, report);
            }
            Ok(reports)
        }
    }

    fn fast() -> LoopConfig {
        LoopConfig {
            poll: Duration::from_millis(10),
            ..LoopConfig::default()
        }
    }

    // -- claiming ----------------------------------------------------------

    #[tokio::test]
    async fn a_fresh_employee_is_work_and_a_provisioned_one_is_not() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "lena").await;
        let cfg = LoopConfig::default();

        let claimed = claim(&db, &cfg, Utc::now()).await.expect("claim");
        assert_eq!(claimed.len(), 1, "eleven pending rows are one employee");
        assert_eq!(claimed[0].employee_id, employee.id());
        assert_eq!(claimed[0].tenant_id, employee.tenant_id());

        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1",
        )
        .await;
        assert!(
            claim(&db, &cfg, Utc::now())
                .await
                .expect("claim")
                .is_empty(),
            "a fully provisioned employee is not work"
        );
    }

    /// The recovery case. A worker that died mid-step left its own lease on the
    /// row; nothing else in the system will ever look at it again.
    #[tokio::test]
    async fn an_expired_lease_is_reclaimed_and_a_live_one_is_left_alone() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "raj").await;
        let cfg = LoopConfig::default();

        // Everything provisioned except one step, held by a worker that is
        // still alive and still working on it.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1",
        )
        .await;
        exec(
            &db,
            &employee,
            "UPDATE employee_resources \
                SET state = 'provisioning', lease_owner = gen_random_uuid(), \
                    lease_until = now() + interval '2 minutes' \
              WHERE employee_id = $1 AND step = 'phone'",
        )
        .await;
        assert!(
            claim(&db, &cfg, Utc::now())
                .await
                .expect("claim")
                .is_empty(),
            "a live lease is another worker's job, not ours"
        );

        // ...and now that worker is gone.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET lease_until = now() - interval '1 second' \
              WHERE employee_id = $1 AND step = 'phone'",
        )
        .await;
        let claimed = claim(&db, &cfg, Utc::now()).await.expect("claim");
        assert_eq!(
            claimed.len(),
            1,
            "a lapsed lease must be reclaimed by another worker"
        );
        assert_eq!(claimed[0].employee_id, employee.id());
    }

    #[tokio::test]
    async fn a_failed_step_is_retried_cold_and_never_past_the_cap() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "ines").await;
        let cfg = LoopConfig::default();

        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1",
        )
        .await;
        // Failed a moment ago: too hot to retry, or the loop would re-attempt
        // it five times a second forever.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources \
                SET state = 'failed', attempt_count = 1, updated_at = now() \
              WHERE employee_id = $1 AND step = 'email'",
        )
        .await;
        assert!(
            claim(&db, &cfg, Utc::now())
                .await
                .expect("claim")
                .is_empty(),
            "a fresh failure is not retried on the next poll"
        );

        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET updated_at = now() - interval '1 hour' \
              WHERE employee_id = $1 AND step = 'email'",
        )
        .await;
        assert_eq!(
            claim(&db, &cfg, Utc::now()).await.expect("claim").len(),
            1,
            "a cold failure is worth another attempt"
        );

        // Out of attempts: a step that has failed this often is not going to
        // start working, and a human has better evidence than another retry.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET attempt_count = 99 \
              WHERE employee_id = $1 AND step = 'email'",
        )
        .await;
        assert!(
            claim(&db, &cfg, Utc::now())
                .await
                .expect("claim")
                .is_empty(),
            "the attempt cap has to bind, or nothing ever stops"
        );
    }

    // -- a stopped company buys nothing ------------------------------------

    /// Stop this company the way an operator does.
    async fn halt_company(db: &Db, employee: &Employee, reason: &str) {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        agentos_store::halt::place(&mut tx, reason, "operator:test", Utc::now())
            .await
            .expect("place")
            .expect("not already halted");
        tx.commit().await.expect("commit");
    }

    /// Say when this company's agents stop. An `ends_at` in the past is a stop.
    async fn set_window(db: &Db, employee: &Employee, ends_at: DateTime<Utc>) {
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        agentos_store::halt::set_window(&mut tx, ends_at, "operator:test", Utc::now())
            .await
            .expect("set window");
        tx.commit().await.expect("commit");
    }

    /// **Eleven resources, and every one of them is an invoice.** A company
    /// somebody stopped — with the switch, or by letting the operating window it
    /// bought run out — must not have mailboxes opened and phone numbers bought
    /// for it while it is stopped.
    ///
    /// The third tenant is not decoration and neither is the first one's window:
    /// every tenant here *has* a `company_windows` row, so a predicate that
    /// skipped any tenant with a window, or that only ever read `company_halts`,
    /// would pass this test exactly as the right one does.
    #[tokio::test]
    async fn a_stopped_company_is_not_provisioned_and_a_running_one_still_is() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let now = Utc::now();
        // Bigger than the three tenants' thirty-three rows, so "not claimed"
        // can only mean the predicate and never the batch size.
        let cfg = LoopConfig {
            batch: 64,
            ..LoopConfig::default()
        };

        // Stopped by a human, and with a month still on the clock: the switch
        // wins, and the window must not talk this one back into being work.
        let switched = seed(&db, "switched").await;
        set_window(&db, &switched, now + TimeDelta::days(30)).await;
        halt_company(&db, &switched, "the CFO called").await;

        // Stopped by the clock. Nobody threw anything; the time ran out.
        let expired = seed(&db, "expired").await;
        set_window(&db, &expired, now - TimeDelta::seconds(1)).await;

        // The vacant guard: a window, open.
        let running = seed(&db, "running").await;
        set_window(&db, &running, now + TimeDelta::days(30)).await;

        let claimed: Vec<_> = claim(&db, &cfg, now)
            .await
            .expect("claim")
            .into_iter()
            .map(|work| work.employee_id)
            .collect();
        assert_eq!(
            claimed,
            vec![running.id()],
            "a stopped company's pending resources are not work"
        );

        // ...and the loop spends nothing on them, which is the whole defect.
        let engine = FakeEngine::ready(&db);
        let cancel = CancellationToken::new();
        ProvisioningLoop::new(db.clone(), engine.clone())
            .with_config(cfg.clone())
            .tick(now, &cancel)
            .await
            .expect("tick");
        assert_eq!(
            engine.calls(switched.id()),
            0,
            "an operator stopped this company and we bought it eleven resources"
        );
        assert_eq!(
            engine.calls(expired.id()),
            0,
            "this company's month ran out and we bought it eleven resources"
        );
        assert_eq!(
            engine.calls(running.id()),
            1,
            "a running company must still be provisioned"
        );

        // Nothing was spent while they were stopped: not a provider call, not
        // an attempt, not a state.
        for employee in [&switched, &expired] {
            assert_eq!(
                scalar::<i64>(
                    &db,
                    employee,
                    "SELECT count(*) FROM employee_resources \
                      WHERE employee_id = $1 AND state = 'pending' AND attempt_count = 0"
                )
                .await,
                11,
                "a deferred row must be untouched, or the reprise has nothing to give back"
            );
        }

        // **The reprise, with no intervention.** The claim is a pure SELECT, so
        // the rows it did not select were not rescheduled and not counted — the
        // instant the stop lifts they are due again, exactly as they were.
        let mut tx = db.tenant_tx(switched.tenant_id()).await.expect("tx");
        agentos_store::halt::release(&mut tx)
            .await
            .expect("release")
            .expect("was halted");
        tx.commit().await.expect("commit");
        set_window(&db, &expired, now + TimeDelta::days(30)).await;

        let mut back: Vec<_> = claim(&db, &cfg, now)
            .await
            .expect("claim")
            .into_iter()
            .map(|work| work.employee_id)
            .collect();
        back.sort_unstable();
        let mut deferred = vec![switched.id(), expired.id()];
        deferred.sort_unstable();
        assert_eq!(
            back, deferred,
            "lifting the stop must make every deferred row due again by itself"
        );
    }

    /// **Where the wedge stops.** A stop defers a convergence that has not
    /// started; it never interrupts one that has.
    ///
    /// `claim_step` writes the `provider_intents` row and commits it *before*
    /// the provider call, so a row a dead worker left in `provisioning` is a
    /// call whose outcome nobody knows — and `ProvisioningEngine::claim` is the
    /// only thing in the workspace that closes one (`sweep_expired_leases` and
    /// `mark_intent_orphaned` have one call site each, both there, reachable
    /// only through `converge`). Deferring *that* row is what strands bought
    /// resources, which is the argument `routes::halt` makes and it is right.
    ///
    /// A `pending` row has no intent at all, a `failed` one had its intent
    /// closed by `finish_step`, and `ensure_step` returns from a
    /// `pending_external` one without touching anything. None of the three
    /// leaves so much as a row behind by waiting.
    #[tokio::test]
    async fn a_stop_defers_a_convergence_that_has_not_started_and_never_one_in_flight() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let now = Utc::now();
        let cfg = LoopConfig::default();

        // Stopped by the switch. Nothing here has begun: eight never attempted,
        // one failed and cold, one waiting on a provider past its deadline.
        let deferred = seed(&db, "deferred").await;
        set_window(&db, &deferred, now + TimeDelta::days(30)).await;
        halt_company(&db, &deferred, "the CFO called").await;
        exec(
            &db,
            &deferred,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1 \
               AND step IN ('email', 'vault')",
        )
        .await;
        exec(
            &db,
            &deferred,
            "UPDATE employee_resources \
                SET state = 'failed', attempt_count = 1, \
                    updated_at = now() - interval '1 hour' \
              WHERE employee_id = $1 AND step = 'browser'",
        )
        .await;
        exec(
            &db,
            &deferred,
            "UPDATE employee_resources \
                SET state = 'pending_external', poll_ref = 'BU:FR:1234', \
                    expected_by = now() - interval '1 hour' \
              WHERE employee_id = $1 AND step = 'phone'",
        )
        .await;

        // Stopped by the clock, and a worker died holding one of its steps: the
        // lease has lapsed and a provider may already have sold us something.
        let midflight = seed(&db, "midflight").await;
        set_window(&db, &midflight, now - TimeDelta::seconds(1)).await;
        exec(
            &db,
            &midflight,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1",
        )
        .await;
        exec(
            &db,
            &midflight,
            "UPDATE employee_resources \
                SET state = 'provisioning', lease_owner = gen_random_uuid(), \
                    lease_until = now() - interval '1 second' \
              WHERE employee_id = $1 AND step = 'phone'",
        )
        .await;

        let claimed: Vec<_> = claim(&db, &cfg, now)
            .await
            .expect("claim")
            .into_iter()
            .map(|work| work.employee_id)
            .collect();
        assert_eq!(
            claimed,
            vec![midflight.id()],
            "a stop must not strand the one step whose outcome nobody knows, \
             and must not start any of the three that have not begun"
        );
    }

    // -- the loop ----------------------------------------------------------

    #[tokio::test]
    async fn the_loop_drains_an_employee_to_online_exactly_once() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "kim").await;
        assert_eq!(reload(&db, &employee).await.health(), Health::Provisioning);

        let engine = FakeEngine::ready(&db);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(
            ProvisioningLoop::new(db.clone(), engine.clone())
                .with_config(fast())
                .run(cancel.clone()),
        );

        // Drained: the employee is Online and nothing is claimable any more.
        for _ in 0..200 {
            if reload(&db, &employee).await.health() == Health::Online {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(reload(&db, &employee).await.health(), Health::Online);

        // Let several more polls go by; an idle loop must not keep re-running
        // work that is done.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the loop must stop when cancelled")
            .expect("no panic");

        assert_eq!(
            engine.calls(employee.id()),
            1,
            "a drained employee must be provisioned exactly once"
        );
    }

    /// A restart mid-drain is the ordinary case, not the exception: deploys
    /// happen. The second worker picks the employee up and converges it, and
    /// between them they provision it once.
    #[tokio::test]
    async fn a_loop_killed_mid_drain_converges_exactly_once_on_restart() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "nils").await;

        // Worker one claims the employee and dies before it finishes: the fake
        // is inert, so the row stays exactly as claimed.
        let first = FakeEngine::inert();
        let cancel = CancellationToken::new();
        let one = tokio::spawn(
            ProvisioningLoop::new(db.clone(), first.clone())
                .with_config(fast())
                .run(cancel.clone()),
        );
        while first.calls(employee.id()) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), one)
            .await
            .expect("drain")
            .expect("no panic");
        assert_eq!(reload(&db, &employee).await.health(), Health::Provisioning);

        // Worker two, a different process, finds the same employee still
        // wanting work and finishes the job.
        let second = FakeEngine::ready(&db);
        let cancel = CancellationToken::new();
        let two = tokio::spawn(
            ProvisioningLoop::new(db.clone(), second.clone())
                .with_config(fast())
                .run(cancel.clone()),
        );
        for _ in 0..200 {
            if reload(&db, &employee).await.health() == Health::Online {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), two)
            .await
            .expect("drain")
            .expect("no panic");

        assert_eq!(reload(&db, &employee).await.health(), Health::Online);
        assert_eq!(
            second.calls(employee.id()),
            1,
            "the restarted worker converged the employee once, not once per poll"
        );
    }

    // -- the reaper --------------------------------------------------------

    #[tokio::test]
    async fn an_overdue_pending_external_step_is_escalated_once() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "ada").await;
        let cfg = LoopConfig::default();

        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1",
        )
        .await;
        // A Twilio bundle that was silently rejected looks exactly like one
        // still in review — until its deadline passes.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources \
                SET state = 'pending_external', poll_ref = 'BU:FR:1234', \
                    expected_by = now() - interval '1 hour' \
              WHERE employee_id = $1 AND step = 'phone'",
        )
        .await;

        let claimed = claim(&db, &cfg, Utc::now()).await.expect("claim");
        assert_eq!(claimed.len(), 1, "an overdue wait is work");

        let escalated = reap(&db, &cfg, &claimed[0], Utc::now())
            .await
            .expect("reap");
        assert_eq!(escalated, vec![Step::Phone]);

        // A human was asked, and the question names what to go and look at.
        let pending: i64 = scalar(
            &db,
            &employee,
            "SELECT count(*) FROM approvals WHERE employee_id = $1 AND state = 'pending'",
        )
        .await;
        assert_eq!(pending, 1);
        let reason: String = scalar(
            &db,
            &employee,
            "SELECT reason FROM approvals WHERE employee_id = $1",
        )
        .await;
        assert!(reason.contains("BU:FR:1234"), "{reason}");

        // And the step stopped pretending to be a wait, so the employee reads
        // as broken rather than as merely slow.
        let reloaded = reload(&db, &employee).await;
        assert_eq!(
            reloaded.resource(Step::Phone).state(),
            &ResourceState::Failed
        );
        assert!(reloaded.overdue(Utc::now()).is_empty());
        assert_ne!(reloaded.health(), Health::Online);

        // Asking again is the failure mode this test exists for: a poll every
        // 200ms is 18,000 approvals a day for one bundle.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources \
                SET state = 'pending_external', poll_ref = 'BU:FR:1234', \
                    expected_by = now() - interval '1 hour' \
              WHERE employee_id = $1 AND step = 'phone'",
        )
        .await;
        let again = reap(&db, &cfg, &claimed[0], Utc::now())
            .await
            .expect("reap again");
        assert_eq!(again, vec![Step::Phone]);
        let pending: i64 = scalar(
            &db,
            &employee,
            "SELECT count(*) FROM approvals WHERE employee_id = $1 AND state = 'pending'",
        )
        .await;
        assert_eq!(pending, 1, "one bundle, one question");
    }

    #[tokio::test]
    async fn a_wait_that_is_not_due_yet_is_left_alone() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "otto").await;
        let cfg = LoopConfig::default();

        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1",
        )
        .await;
        exec(
            &db,
            &employee,
            "UPDATE employee_resources \
                SET state = 'pending_external', poll_ref = 'BU:FR:9', \
                    expected_by = now() + interval '1 day' \
              WHERE employee_id = $1 AND step = 'whatsapp'",
        )
        .await;

        assert!(
            claim(&db, &cfg, Utc::now())
                .await
                .expect("claim")
                .is_empty(),
            "a wait inside its deadline is not work"
        );
        let work = Work {
            tenant_id: employee.tenant_id(),
            employee_id: employee.id(),
            traceparent: None,
        };
        assert!(
            reap(&db, &cfg, &work, Utc::now())
                .await
                .expect("reap")
                .is_empty()
        );
        let approvals: i64 = scalar(
            &db,
            &employee,
            "SELECT count(*) FROM approvals WHERE employee_id = $1",
        )
        .await;
        assert_eq!(approvals, 0);
    }

    // -- traceparent -------------------------------------------------------

    #[tokio::test]
    async fn the_trace_of_the_request_is_inherited_and_carried_onward() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "vera").await;
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        // What the request that created this employee left behind.
        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        sqlx::query(
            "INSERT INTO outbox_events \
               (id, tenant_id, aggregate_type, aggregate_id, event_type, payload) \
             VALUES ($1, $2, 'employee', $3, 'employee.created', \
                     jsonb_build_object('traceparent', $4::text))",
        )
        .bind(Uuid::now_v7())
        .bind(employee.tenant_id().as_uuid())
        .bind(employee.id().as_uuid())
        .bind(traceparent)
        .execute(&mut **tx)
        .await
        .expect("insert event");
        // ... and an event from the provisioning run itself, with no trace on
        // it, because `finish_step` has no way to know one.
        sqlx::query(
            "INSERT INTO outbox_events \
               (id, tenant_id, aggregate_type, aggregate_id, event_type, payload) \
             VALUES ($1, $2, 'employee', $3, 'employee.step.ready', '{\"step\":\"email\"}')",
        )
        .bind(Uuid::now_v7())
        .bind(employee.tenant_id().as_uuid())
        .bind(employee.id().as_uuid())
        .execute(&mut **tx)
        .await
        .expect("insert event");
        tx.commit().await.expect("commit");

        let claimed = claim(&db, &LoopConfig::default(), Utc::now())
            .await
            .expect("claim");
        assert_eq!(claimed[0].traceparent.as_deref(), Some(traceparent));

        stamp_trace(&db, &claimed[0], traceparent)
            .await
            .expect("stamp");
        let stamped: i64 = scalar(
            &db,
            &employee,
            "SELECT count(*) FROM outbox_events \
              WHERE aggregate_id = $1 AND payload->>'traceparent' IS NOT NULL",
        )
        .await;
        assert_eq!(
            stamped, 2,
            "the asynchronous work must stay on the trace that caused it"
        );
    }

    // -- the termination sweeper -------------------------------------------

    /// **The whole point.** The `employee.terminated` event was retried eight
    /// times against a provider that was down, then dead lettered. Nothing in
    /// the system was ever going to ask again, and eleven resources were going
    /// to keep billing forever. The sweep is what asks again.
    #[tokio::test]
    async fn a_dead_lettered_termination_is_eventually_released_by_the_sweep() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "mara").await;
        bind_all(&db, &employee).await;
        terminate(&db, &employee).await;
        assert_eq!(still_bound(&db, &employee).await, 11);

        let engine = FakeEngine::ready(&db);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(
            ProvisioningLoop::new(db.clone(), engine.clone())
                .with_config(fast())
                .run(cancel.clone()),
        );

        for _ in 0..200 {
            if still_bound(&db, &employee).await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Several more polls: an employee with nothing left must go quiet.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the loop must stop when cancelled")
            .expect("no panic");

        assert_eq!(
            still_bound(&db, &employee).await,
            0,
            "these resources are still being billed"
        );
        assert_eq!(
            engine.releases().len(),
            11,
            "every bound step is asked for exactly once: {:?}",
            engine.releases()
        );
        assert_eq!(
            engine.calls(employee.id()),
            0,
            "a terminated employee must never be converged"
        );
    }

    /// `release_not_supported` is STRUCTURAL. Resend's sending domain is shared
    /// across the tenant, so the adapter refuses on purpose and will refuse
    /// identically forever; a sweep that retried it would spend a provider call
    /// and re-fire an operator alert every 200ms for the life of the
    /// deployment. Asked once, ever — however many ticks run.
    #[tokio::test]
    async fn a_step_that_cannot_be_released_is_never_retried_by_the_sweep() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "resend").await;
        bind_all(&db, &employee).await;
        terminate(&db, &employee).await;

        let engine = FakeEngine::ready(&db).refusing(Step::Email, RELEASE_NOT_SUPPORTED);
        let sweeper = ProvisioningLoop::new(db.clone(), engine.clone()).with_config(fast());
        let cancel = CancellationToken::new();

        // A day of ticks, each one long after the last so backoff never hides
        // anything: if the exclusion were the backoff rather than the code,
        // this loop would find it out.
        let now = Utc::now();
        for tick in 0..24 {
            sweeper
                .tick(now + TimeDelta::hours(tick), &cancel)
                .await
                .expect("tick");
        }

        assert_eq!(
            engine.releases_of(Step::Email),
            1,
            "a structural refusal must be asked exactly once, ever"
        );
        assert_eq!(
            still_bound(&db, &employee).await,
            1,
            "the binding is the only record of what to cancel; it must survive"
        );
        assert_eq!(
            scalar::<i64>(
                &db,
                &employee,
                "SELECT count(*) FROM approvals WHERE employee_id = $1"
            )
            .await,
            0,
            "an alert nobody can act on differently must not be re-fired"
        );
        // Every other step went, because one impossible provider is no reason
        // to keep paying for the other ten resources.
        assert_eq!(engine.releases().len(), 11);
    }

    /// ...and is still visible. It is out of the retry set, so the only thing
    /// standing between the operator and a silent invoice is this query.
    #[tokio::test]
    async fn a_step_that_cannot_be_released_is_still_listed_for_the_operator() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "stranded").await;
        bind_all(&db, &employee).await;
        terminate(&db, &employee).await;

        let engine = FakeEngine::ready(&db).refusing(Step::Email, RELEASE_NOT_SUPPORTED);
        let cancel = CancellationToken::new();
        ProvisioningLoop::new(db.clone(), engine.clone())
            .with_config(fast())
            .tick(Utc::now(), &cancel)
            .await
            .expect("tick");

        let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
        let stranded = agentos_store::provisioning::stranded(&mut tx, 100)
            .await
            .expect("stranded");
        tx.rollback().await.expect("rollback");

        assert_eq!(stranded.len(), 1, "{stranded:?}");
        assert_eq!(stranded[0].employee_id, employee.id());
        assert_eq!(stranded[0].step, Step::Email);
        assert_eq!(stranded[0].provider, "mock");
        assert!(
            stranded[0].external_id.starts_with("ext-"),
            "the operator needs the id to cancel: {stranded:?}"
        );
        assert!(
            stranded[0]
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains(RELEASE_NOT_SUPPORTED),
            "the row must say why nobody is retrying it: {stranded:?}"
        );
    }

    /// A provider that is down must not be called once per 200ms tick, and a
    /// step that will not come back must not ask a human once per tick either.
    #[tokio::test]
    async fn a_repeatedly_failing_release_backs_off_and_escalates_exactly_once() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "stubborn").await;
        bind_all(&db, &employee).await;
        terminate(&db, &employee).await;

        let engine = FakeEngine::ready(&db).refusing(Step::Phone, "release_refused");
        let cfg = LoopConfig {
            max_attempts: 3,
            ..fast()
        };
        let sweeper = ProvisioningLoop::new(db.clone(), engine.clone()).with_config(cfg);
        let cancel = CancellationToken::new();
        let now = Utc::now();

        // Two ticks in the same instant: the second must find nothing, or a
        // provider that is down is called five times a second.
        sweeper.tick(now, &cancel).await.expect("tick");
        sweeper.tick(now, &cancel).await.expect("tick");
        assert_eq!(
            engine.releases_of(Step::Phone),
            1,
            "backoff is what stops a hammered provider"
        );

        // A tick an hour, until well past the cap.
        for tick in 1..12 {
            sweeper
                .tick(now + TimeDelta::hours(tick), &cancel)
                .await
                .expect("tick");
        }

        assert_eq!(
            engine.releases_of(Step::Phone),
            3,
            "the attempt cap has to bind, or nothing ever stops"
        );
        assert_eq!(
            scalar::<i64>(
                &db,
                &employee,
                "SELECT count(*) FROM approvals WHERE employee_id = $1 AND state = 'pending'"
            )
            .await,
            1,
            "one stuck resource, one question — not one per tick"
        );
        let reason: String = scalar(
            &db,
            &employee,
            "SELECT reason FROM approvals WHERE employee_id = $1",
        )
        .await;
        assert!(
            reason.contains("ext-"),
            "the operator needs the id: {reason}"
        );
        assert_eq!(
            still_bound(&db, &employee).await,
            1,
            "a resource nobody could release must keep its id"
        );
    }

    /// Two replicas, one terminated employee. Release is idempotent by
    /// contract, so this is about not wasting provider calls and not corrupting
    /// the attempt count that bounds them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_sweepers_do_not_double_release_a_step() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "twice").await;
        bind_all(&db, &employee).await;
        terminate(&db, &employee).await;

        // One engine, two loops: whatever either replica calls is counted here.
        let engine = FakeEngine::ready(&db);
        let one = ProvisioningLoop::new(db.clone(), engine.clone()).with_config(fast());
        let two = ProvisioningLoop::new(db.clone(), engine.clone()).with_config(fast());
        let cancel = CancellationToken::new();
        let now = Utc::now();

        let (first, second) = tokio::join!(one.tick(now, &cancel), two.tick(now, &cancel));
        first.expect("tick");
        second.expect("tick");

        let calls = engine.releases();
        let mut seen = calls.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            calls.len(),
            seen.len(),
            "a step was released twice: {calls:?}"
        );
        assert_eq!(calls.len(), 11, "{calls:?}");
        assert_eq!(still_bound(&db, &employee).await, 0);
        // One claim per row, so the budget that bounds the retries is intact.
        assert_eq!(
            scalar::<i32>(
                &db,
                &employee,
                "SELECT max(release_attempt_count) FROM employee_resources \
                  WHERE employee_id = $1"
            )
            .await,
            1,
            "concurrent sweepers must not spend the release budget twice"
        );
        assert_eq!(
            scalar::<i32>(
                &db,
                &employee,
                "SELECT max(attempt_count) FROM employee_resources WHERE employee_id = $1"
            )
            .await,
            0,
            "releasing must not spend provisioning's budget at all"
        );
    }

    /// The bug that already bit once: released rows land in `disabled`,
    /// `disabled` is claimable, and converging a terminated employee
    /// re-provisioned all eleven steps and bought a fresh phone number.
    #[tokio::test]
    async fn the_sweep_never_resurrects_a_terminated_employee() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "ghost").await;
        bind_all(&db, &employee).await;
        terminate(&db, &employee).await;

        let engine = FakeEngine::ready(&db);
        let sweeper = ProvisioningLoop::new(db.clone(), engine.clone()).with_config(fast());
        let cancel = CancellationToken::new();
        let now = Utc::now();
        for tick in 0..12 {
            sweeper
                .tick(now + TimeDelta::hours(tick), &cancel)
                .await
                .expect("tick");
        }

        assert_eq!(
            engine.calls(employee.id()),
            0,
            "the sweep must never reach converge, which is what buys things"
        );
        let after = reload(&db, &employee).await;
        assert_eq!(after.lifecycle(), Lifecycle::Terminated);
        assert_ne!(after.health(), Health::Online);
        for step in Step::ALL {
            assert_eq!(
                after.resource(step).state(),
                &ResourceState::Disabled,
                "{step} came back to life"
            );
            assert!(
                after.resource(step).binding().is_none(),
                "{step} is still bound to something"
            );
        }
        // And the released rows, which *are* claimable by state, are still not
        // work: the claim query filters on lifecycle.
        assert!(
            claim(&db, &fast(), Utc::now())
                .await
                .expect("claim")
                .is_empty(),
            "a terminated employee's disabled rows must not read as work"
        );
    }

    /// A terminated employee that never bought anything is not a provider call
    /// waiting to happen. Nothing may be asked about it at all.
    #[tokio::test]
    async fn an_employee_with_nothing_bound_is_not_swept_at_all() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "empty").await;
        // Provisioned, but every step is one of ours: no external id anywhere.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources \
                SET state = 'ready', updated_at = now() - interval '1 hour' \
              WHERE employee_id = $1",
        )
        .await;
        terminate(&db, &employee).await;

        let engine = FakeEngine::ready(&db);
        let sweeper = ProvisioningLoop::new(db.clone(), engine.clone()).with_config(fast());
        let cancel = CancellationToken::new();
        let now = Utc::now();
        for tick in 0..12 {
            sweeper
                .tick(now + TimeDelta::hours(tick), &cancel)
                .await
                .expect("tick");
        }

        assert!(
            engine.releases().is_empty(),
            "nothing was bound, so nobody should have been called: {:?}",
            engine.releases()
        );
        assert_eq!(engine.calls(employee.id()), 0);
        assert_eq!(
            scalar::<i32>(
                &db,
                &employee,
                "SELECT max(release_attempt_count) FROM employee_resources \
                  WHERE employee_id = $1"
            )
            .await,
            0,
            "an employee with nothing bound must not even be claimed"
        );
    }

    // -- the release budget is the release's own ---------------------------

    /// The gap this column closed: a step that fought to be bought used to
    /// arrive at termination with most of its retries already spent, so the
    /// sweep gave up early and asked a human about a resource it had barely
    /// tried to release.
    ///
    /// This is also the migration test. The rows here look exactly like rows
    /// written before 0008: a large `attempt_count`, and the release columns
    /// left at what the migration gives an existing row.
    #[tokio::test]
    async fn a_step_that_burned_its_provisioning_attempts_gets_a_full_release_budget() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "expensive").await;
        bind_all(&db, &employee).await;
        // Every step cost far more than the cap to provision.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET attempt_count = 99 WHERE employee_id = $1",
        )
        .await;
        assert_eq!(
            scalar::<i32>(
                &db,
                &employee,
                "SELECT max(release_attempt_count) FROM employee_resources \
                  WHERE employee_id = $1"
            )
            .await,
            0,
            "an existing row must migrate to a full release budget, not an exhausted one"
        );
        assert!(
            scalar::<Option<DateTime<Utc>>>(
                &db,
                &employee,
                "SELECT max(release_attempted_at) FROM employee_resources \
                  WHERE employee_id = $1"
            )
            .await
            .is_none(),
            "an existing row has never been swept under the new counter"
        );
        terminate(&db, &employee).await;

        // One step's provider refuses transiently, so it needs the whole
        // budget rather than the nothing the old shared counter left it.
        let engine = FakeEngine::ready(&db).refusing(Step::Phone, "release_refused");
        let cfg = LoopConfig {
            max_attempts: 3,
            ..fast()
        };
        let sweeper = ProvisioningLoop::new(db.clone(), engine.clone()).with_config(cfg);
        let cancel = CancellationToken::new();
        let now = Utc::now();
        for tick in 0..12 {
            sweeper
                .tick(now + TimeDelta::hours(tick), &cancel)
                .await
                .expect("tick");
        }

        assert_eq!(
            engine.releases_of(Step::Phone),
            3,
            "the release budget is spent on releases, not on the purchase"
        );
        assert_eq!(
            still_bound(&db, &employee).await,
            1,
            "the other ten were given back"
        );
        assert_eq!(
            scalar::<i32>(
                &db,
                &employee,
                "SELECT max(attempt_count) FROM employee_resources WHERE employee_id = $1"
            )
            .await,
            99,
            "the sweep must not have touched provisioning's counter"
        );
    }

    /// The backoff has to read the new column, not `updated_at`. Those two
    /// disagree the moment anything else writes the row — the engine stamping
    /// `last_error` on a refused release does exactly that.
    #[tokio::test]
    async fn the_sweep_backs_off_on_the_release_column_and_not_on_updated_at() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "backoff").await;
        bind_all(&db, &employee).await;
        terminate(&db, &employee).await;
        let cfg = LoopConfig::default();
        let now = Utc::now();

        assert_eq!(
            claim_releases(&db, &cfg, now).await.expect("claim").len(),
            11,
            "a NULL release_attempted_at falls back to updated_at, which is cold"
        );

        // Stale by `updated_at`, hot by the column that now matters. The old
        // predicate would claim these again immediately.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET updated_at = now() - interval '1 hour' \
              WHERE employee_id = $1",
        )
        .await;
        assert!(
            claim_releases(&db, &cfg, now)
                .await
                .expect("claim")
                .is_empty(),
            "a release attempted a moment ago must not be retried on the next tick"
        );

        // ... and once the release itself has gone cold, it is work again.
        let later = now + TimeDelta::hours(1);
        assert_eq!(
            claim_releases(&db, &cfg, later).await.expect("claim").len(),
            11
        );
        assert_eq!(
            scalar::<i32>(
                &db,
                &employee,
                "SELECT max(release_attempt_count) FROM employee_resources \
                  WHERE employee_id = $1"
            )
            .await,
            2,
            "two claims, two attempts"
        );
    }

    /// A terminal refusal is not a transient failure, and the cap was pricing
    /// it as if it were.
    ///
    /// The expensive half is `bad_secret_ref`: five provider calls, on a
    /// backoff, for an answer that was final the first time. The half that
    /// matters more is everything else in this test — a `retryable` code, a
    /// `rate_limited` code, and a NULL `last_error` all keep every attempt they
    /// had. **A fix that made the whole `failed` state terminal would pass the
    /// first assertion and fail the other three**, which is the only reason
    /// they are here: it is much easier to stop the waste than to stop it
    /// without also stopping the retries that work.
    #[tokio::test]
    async fn a_terminal_code_stops_costing_provider_calls_and_a_transient_one_keeps_its_attempts() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let _guard = DB_LOCK.lock().await;
        reset(&db).await;
        let employee = seed(&db, "noor").await;
        let cfg = LoopConfig::default();

        // Everything provisioned but one step, so the only thing that can make
        // this employee claimable is the failed row itself — which is exactly
        // the shape a half-provisioned employee sits in.
        exec(
            &db,
            &employee,
            "UPDATE employee_resources SET state = 'ready' WHERE employee_id = $1",
        )
        .await;

        // Cold, one attempt spent, four left under the cap. The only variable
        // below is `last_error`.
        let claimable = async |error: &'static str| {
            let mut tx = db.tenant_tx(employee.tenant_id()).await.expect("tx");
            sqlx::query(
                "UPDATE employee_resources \
                    SET state = 'failed', attempt_count = 1, \
                        updated_at = now() - interval '1 hour', \
                        last_error = nullif($2, '') \
                  WHERE employee_id = $1 AND step = 'email'",
            )
            .bind(employee.id().as_uuid())
            .bind(error)
            .execute(&mut **tx)
            .await
            .expect("statement");
            tx.commit().await.expect("commit");
            !claim(&db, &cfg, Utc::now())
                .await
                .expect("claim")
                .is_empty()
        };

        // The whole point. `ensure_step` writes `format!("{}: {err}", code)`, so
        // this is the byte-for-byte shape of a real row.
        assert!(
            !claimable("bad_secret_ref: provider rejected the request: bad_secret_ref").await,
            "a terminal refusal must not buy another provider call: the vault will not have \
             grown the secret since the last one"
        );
        assert!(
            !claimable("no_numbers_available: provider rejected the request: no_numbers_available")
                .await,
            "there are still no numbers"
        );
        assert!(
            !claimable("unauthorized: provider rejected the request: unauthorized").await,
            "the key is still wrong"
        );

        // ...and now the half that a blunt fix breaks.
        assert!(
            claimable("retryable: provider is unavailable, retry after 1s").await,
            "a transient failure keeps every attempt it had; parking these is a worse bug than \
             the one this predicate fixes"
        );
        assert!(
            claimable("rate_limited: provider asked us to slow down, retry after 5s").await,
            "a 429 is the provider telling us to come back, not to give up"
        );
        assert!(
            claimable("").await,
            "a NULL `last_error` never carried a provider verdict — it is the reaper's \
             `pending_external -> failed`, whose whole purpose is that the step be tried again"
        );
    }
}
