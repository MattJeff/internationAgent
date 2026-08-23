//! The provisioning loop, and the reaper that stops an employee rotting in
//! `pending_external`.
//!
//! One tokio task. Every ~200ms it claims a batch of resource rows that want
//! work, hands each employee to [`agentos_app::provisioning::ProvisioningEngine`]
//! — which is what actually runs `ensure_step` per step, in dependency order,
//! under a lease — and then escalates anything whose external wait has run out
//! of patience.
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

// ponytail: the binary does not wire this in yet — main.rs is another unit's
// file and says so. Without this, every item below is dead code in the bin
// target and `-D warnings` fails on a module that is complete and tested.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::time::Duration;

use agentos_app::provisioning::{EngineError, ProvisioningEngine, StepReport};
use agentos_domain::action::{Action, McpTool};
use agentos_domain::employee::{Employee, ResourceState, Step};
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
/// The role a human must hold to act on an overdue external wait.
const OPERATOR_ROLE: &str = "operator";
/// The MCP server half of the escalation's action name. Distinct from the
/// engine's own `provisioning/<step>` reconciliation, because the two are
/// different questions and the approval hash must not conflate them.
const ESCALATION_SERVER: &str = "provisioning-overdue";

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
    pub retry_after: TimeDelta,
    /// Give up retrying a step after this many claims.
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

/// Drive one employee's provisioning as far as it will go.
///
/// A trait with exactly one production implementation, and it earns that: this
/// crate cannot depend on `agentos-providers` (by design — the binary may not
/// touch a provider), so it cannot build the `Adapters` a real
/// [`ProvisioningEngine`] needs, and without this seam the loop below would
/// have no test at all.
pub trait Converge: Send + Sync + 'static {
    /// Run every runnable step for this employee and report what each came to.
    fn converge(
        &self,
        tenant_id: TenantId,
        employee_id: EmployeeId,
    ) -> impl Future<Output = Result<BTreeMap<Step, StepReport>, EngineError>> + Send;
}

impl Converge for ProvisioningEngine {
    fn converge(
        &self,
        tenant_id: TenantId,
        employee_id: EmployeeId,
    ) -> impl Future<Output = Result<BTreeMap<Step, StepReport>, EngineError>> + Send {
        ProvisioningEngine::converge(self, tenant_id, employee_id)
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

    /// One pass: claim a batch, converge each employee, reap what is overdue.
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
        Ok(done)
    }

    /// Everything one claimed employee gets: the engine, then the reaper, then
    /// the trace stamp.
    async fn drive(&self, work: &Work, now: DateTime<Utc>) {
        match self.engine.converge(work.tenant_id, work.employee_id).await {
            Ok(reports) => {
                let unready: Vec<_> = reports
                    .iter()
                    .filter(|(_, report)| !report.is_ready())
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
}

// ---------------------------------------------------------------------------
// Claiming
// ---------------------------------------------------------------------------

/// The four predicates, the trace to inherit, and the queue lock.
///
/// `$1` now, `$2` the retry cutoff, `$3` the attempt cap, `$4` the batch size.
const CLAIM_SQL: &str = "\
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
        OR (r.state = 'failed' AND r.attempt_count < $3 AND r.updated_at < $2))
 ORDER BY r.updated_at
 LIMIT $4
 FOR UPDATE OF r SKIP LOCKED";

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
        let action = escalation_action(step);
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
/// ponytail: an `Action::McpCall` named `provisioning-overdue/<step>`, for the
/// same reason the engine files one — `Action` is a closed domain enum with no
/// "chase a regulator" variant and widening it is not this unit's call. The
/// server half differs from the engine's `provisioning/<step>` so the two
/// questions hash differently and neither suppresses the other.
fn escalation_action(step: Step) -> Action {
    let name = Slug::parse(&step.as_str().replace('_', "-"))
        .or_else(|_| Slug::parse("step"))
        .expect("`step` is a valid slug");
    Action::McpCall {
        tool: McpTool::new(Slug::parse(ESCALATION_SERVER).expect("a valid slug"), name),
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
    use agentos_domain::employee::{Health, Lifecycle};

    use super::*;

    /// One database, one schema, and a `(provider, external_id)` index that is
    /// global to it. Tests take turns.
    static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the provisioning loop needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn reset(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants")
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
            .bind(format!("t-{}", tenant.as_uuid().simple()))
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

    // -- a converger that provisions by fiat ------------------------------

    /// Stands in for the real engine, which this crate cannot build: it has no
    /// access to `agentos-providers` by design. It does what a successful
    /// engine run does to the database — every step ready — and counts how
    /// many times it was asked, which is the assertion that matters.
    #[derive(Debug, Clone, Default)]
    struct FakeEngine {
        db: Option<Db>,
        calls: Arc<Mutex<HashMap<EmployeeId, u32>>>,
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

        fn calls(&self, employee: EmployeeId) -> u32 {
            *self
                .calls
                .lock()
                .expect("poisoned")
                .get(&employee)
                .unwrap_or(&0)
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
        let Some(db) = db().await else { return };
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
        let Some(db) = db().await else { return };
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
        let Some(db) = db().await else { return };
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

    // -- the loop ----------------------------------------------------------

    #[tokio::test]
    async fn the_loop_drains_an_employee_to_online_exactly_once() {
        let Some(db) = db().await else { return };
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
        let Some(db) = db().await else { return };
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
        let Some(db) = db().await else { return };
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
        let Some(db) = db().await else { return };
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
        let Some(db) = db().await else { return };
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
}
