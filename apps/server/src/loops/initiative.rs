//! The initiative loop: an employee's own cadence becomes an agent turn.
//!
//! ```text
//! admin tx:   claim_due(BATCH, now) ; COMMIT     <- cross-tenant, SKIP LOCKED
//!   per employee:
//!     tenant tx: load employee + Charter          <- no charter / gaps -> no turn
//!     take_turn                                   <- gate, run, log
//!     admin tx:  record_outcome ; COMMIT
//! sleep(IDLE) unless the batch came back full
//! ```
//!
//! # Why this is a fourth loop
//!
//! The other three drain a queue somebody else filled: `outbox_events` is work
//! we decided to do, and an inbound notice is work a stranger handed us. There
//! is no row for "it is four o'clock". The work here is *created by the clock*,
//! and the only thing that can create it is something that keeps looking at one.
//!
//! Everything downstream of the claim is [`Agent::on_turn`](crate::Agent)'s
//! assembly with a different opening message, and that is deliberate rather than
//! duplicated: same [`Principal`](agentos_app::gate::Principal), same
//! [`Effects`], same [`PolicyGate`](agentos_app::gate::PolicyGate), same
//! `Authorized<A>` on every provider call, same identity string in front of the
//! same [`Charter::system_prompt`]. An employee that woke itself up has exactly
//! the authority it has when somebody emails it — whatever the gate grants and
//! nothing else.
//!
//! What is *absent* is as deliberate. There is no [`Untrusted`](agentos_domain::untrusted)
//! content in this turn's context and no knowledge recall: nobody wrote to us,
//! so there is no counterparty text to fence and no query to retrieve against.
//! This is the one turn in the codebase that starts trusted by construction. It
//! can still become untrusted the moment it reads a supplier's page through a
//! tool, and `TrustLabel` tracks that on its own.
//!
//! # The claim already rescheduled
//!
//! Nothing here marks a turn finished, and there is nothing to mark: the
//! `UPDATE` that handed out the employee also pushed `next_at` a cadence into
//! the future. So a worker killed mid-turn costs one missed slot rather than
//! spinning on a permanently-due employee, and this loop needs no lease, no
//! heartbeat and no reaper.
//! [`record_outcome`](agentos_store::initiative::record_outcome) writes down
//! *what happened* and nothing that affects the schedule.
//!
//! # An objective with gaps costs nothing
//!
//! Both role packs answer an under-specified objective with a single
//! `Stage::Clarify` task: *ask the person who set this, and do not guess*. The
//! obvious implementation is to start a turn carrying that instruction and let
//! the employee send the question — and it is wrong twice. It costs a model call
//! and an email **every cadence**, forever, to re-ask a question that is already
//! outstanding; and the person who has to answer is the operator, who is looking
//! at the API and not at the employee's inbox.
//!
//! So [`plan_of`] reports the gap and this loop starts **no turn**: the question
//! goes to `employee_initiative.last_detail`, where
//! `GET /v1/employees/{id}/initiative` shows it to the operator who can answer
//! it. Re-checking every cadence then costs one row read and no model call, and
//! the turn starts by itself on the first tick after the objective is completed.
//! Nothing has to notice that it was filled in.
//!
//! # The cost ceiling
//!
//! **Every other limit in this system is on money, or on tool calls inside one
//! turn.** An employee that wakes, thinks, reads and writes without ever
//! proposing a payment trips none of them. Until this loop existed the throttle
//! was that a turn only happened because something arrived; this loop removes
//! exactly that throttle, so it must not ship without a ceiling of its own.
//!
//! [`handle`] reserves one turn out of `PolicyLimits::max_turns_per_day` —
//! intersected through `EffectivePolicy::try_new` like every other limit, so a
//! team layer can only tighten it — before the model is called. Two properties
//! of that, both load-bearing:
//!
//! * **Reserved before the turn runs, and never released.** The same rule the
//!   claim follows: the deadline moves when the employee is taken up, not when
//!   the work succeeds. A budget you can get back by failing is the path a
//!   crash loop rides — fail late, release, retry, forever, at full price.
//!   [`agentos_store::turns::reserve`] has no release verb and this loop must
//!   not grow one for it. The cost is accepted: a turn killed by a database
//!   flap still burns its slot, because over-counting caps the bill and
//!   under-counting caps nothing.
//! * **A refusal skips the employee for this round and does not pull the
//!   deadline back in.** The claim already rescheduled a cadence out, and an
//!   employee over its budget should return on its own rhythm rather than the
//!   instant the day rolls over. So a refusal is an `over_budget` outcome and
//!   no model call — the same shape as [`Outcome::Clarify`], and just as cheap.
//!
//! Nothing here escalates on exhaustion: `reserve` already raised the operator
//! alert on the reservation that crossed the line, once, by construction.

use std::future::Future;
use std::time::Duration;

use agentos_app::effects::Effects;
use agentos_app::gate::Principal as ActingAs;
use agentos_app::turn::{Context, Turn};
use agentos_app::vertical::Charter;
use agentos_app::{rolepack, rolepack_sales};
use agentos_store::db::{Db, StoreError};
use agentos_store::employee as employee_store;
use agentos_store::initiative::{self, Due};
use agentos_store::policy as policy_store;
use agentos_store::turns;
use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::{Agent, TURN_DEADLINE};

/// Employees taken per claim.
///
/// Small, and smaller than the inbound loop's: one item of work here is a whole
/// agent turn — minutes of model time, several provider calls — where an inbound
/// notice is two round trips. A batch is drained one employee at a time, so the
/// batch size is really "how long may shutdown wait", and four turns is already
/// the far side of [`TURN_DEADLINE`].
const BATCH: i64 = 4;

/// How long to wait after finding nothing due.
///
/// Five seconds, not the inbound loop's 250ms. The tightest cadence the platform
/// allows is five minutes, so this is the difference between acting on time and
/// acting on time; polling twenty times a second to serve a five-minute clock is
/// twenty times a second of database traffic for nobody.
const IDLE: Duration = Duration::from_secs(5);

/// One employee's turn, as the loop hands it to whatever takes turns.
pub struct Assignment {
    /// The claim: who, which tenant, and the deadline that was just written.
    pub due: Due,
    /// The employee's own name, domain and address. Ours, from our own
    /// configuration, and byte-identical every turn — the cached prefix.
    pub identity: String,
    /// The address the turn sends from.
    pub address: String,
    /// What this employee was hired to do.
    pub charter: Charter,
}

/// What the loop decided about one due employee. The `String`s are ours: a
/// question this codebase authored or an error it defined, never a third
/// party's text — they go in a column an operator reads.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Nobody chartered this employee. Nothing to do, and nothing to ask: an
    /// operator who sets a cadence and no objective has said what they want by
    /// not saying it.
    NoCharter,
    /// The charter row will not parse back through its own constructors.
    Unreadable(String),
    /// The objective has gaps. Ask the operator, and start no turn.
    Clarify(String),
    /// A turn ran to completion.
    Turn,
    /// A turn started and did not finish.
    Failed(String),
    /// The employee has spent its day, or was never granted one. It resumes by
    /// itself at UTC midnight; nothing here retries and nothing escalates,
    /// because `store::turns::reserve` already raised the operator alert on the
    /// reservation that crossed the line.
    OverBudget(String),
}

impl Outcome {
    /// Stable, low-cardinality label for `employee_initiative.last_outcome`.
    const fn code(&self) -> &'static str {
        match self {
            Outcome::NoCharter => "no_charter",
            Outcome::Unreadable(_) => "unreadable_charter",
            Outcome::Clarify(_) => "clarify",
            Outcome::Turn => "turn",
            Outcome::Failed(_) => "error",
            Outcome::OverBudget(_) => "over_budget",
        }
    }

    /// The sentence behind the code, when there is one.
    fn detail(&self) -> Option<&str> {
        match self {
            Outcome::NoCharter | Outcome::Turn => None,
            Outcome::Unreadable(why)
            | Outcome::Clarify(why)
            | Outcome::Failed(why)
            | Outcome::OverBudget(why) => Some(why),
        }
    }
}

/// The plan for a charter, or the question that has to be answered first.
///
/// `Err` is a `Stage::Clarify` task, which both packs return **alone** — a plan
/// containing it contains nothing else — so collapsing it to a single string
/// loses nothing and makes the caller's decision a `match` rather than a search
/// through a vector for a magic stage.
///
/// Public to the crate because `routes::initiative` shows the operator the same
/// two answers, and two copies of "is this objective workable" would be two
/// copies that disagree.
pub(crate) fn plan_of(charter: &Charter) -> Result<Vec<(&'static str, String)>, String> {
    match charter {
        Charter::Purchasing { pack, objective } => {
            let tasks = pack.plan(objective);
            match tasks.first() {
                Some(first) if first.stage == rolepack::Stage::Clarify => {
                    Err(first.instruction.clone())
                }
                _ => Ok(tasks
                    .into_iter()
                    .map(|task| (task.stage.code(), task.instruction))
                    .collect()),
            }
        }
        Charter::Sales { pack, objective } => {
            let tasks = pack.plan(objective);
            match tasks.first() {
                Some(first) if first.stage == rolepack_sales::Stage::Clarify => {
                    Err(first.instruction.clone())
                }
                _ => Ok(tasks
                    .into_iter()
                    .map(|task| (task.stage.code(), task.instruction))
                    .collect()),
            }
        }
    }
}

/// Start turns until `cancel` fires.
///
/// Spawn one per replica; two on the same database is a supported configuration
/// and the reason the claim is `SKIP LOCKED`.
pub async fn run(db: Db, agent: Agent, cancel: CancellationToken) {
    let pump = db.clone();
    drain(
        &pump,
        &move |assignment: Assignment| {
            let agent = agent.clone();
            async move { take_turn(agent, assignment).await }
        },
        cancel,
    )
    .await;
}

/// The loop itself, over whatever turns an assignment into work having happened.
///
/// ponytail: generic over the turn-taker for the same reason
/// [`crate::loops::inbound`]'s drain is generic over its ingest — the claim,
/// skip and bookkeeping decisions are the part worth testing, and testing them
/// against a real model would be testing the model. There is exactly one
/// production implementation and it is in [`run`].
async fn drain<H, F>(db: &Db, take: &H, cancel: CancellationToken)
where
    H: Fn(Assignment) -> F,
    F: Future<Output = Result<(), String>>,
{
    tracing::info!("initiative loop started");

    loop {
        let claimed = match tick(db, take, &cancel, Utc::now()).await {
            Ok(claimed) => claimed,
            Err(err) => {
                // An unreachable database or a lost race. Both are survivable by
                // waiting, which the sleep below does; exiting would stop every
                // employee in the deployment over a blip.
                tracing::error!(error = %err, "initiative claim failed");
                0
            }
        };

        if cancel.is_cancelled() {
            break;
        }
        // A full batch means more employees are already due.
        if claimed == BATCH as usize {
            continue;
        }

        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }

    tracing::info!("initiative loop stopped");
}

/// One pass: claim a batch of due employees and give each one its turn.
///
/// Returns how many were claimed, so the caller can tell a quiet schedule from a
/// busy one.
async fn tick<H, F>(
    db: &Db,
    take: &H,
    cancel: &CancellationToken,
    now: DateTime<Utc>,
) -> Result<usize, StoreError>
where
    H: Fn(Assignment) -> F,
    F: Future<Output = Result<(), String>>,
{
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let batch = initiative::claim_due(&mut tx, BATCH, now).await?;
    // Before the first model call, always. `SKIP LOCKED` only hides a row while
    // the claiming transaction is open, and holding one across a turn is holding
    // a row lock across the internet for two minutes.
    tx.commit().await?;

    for due in &batch {
        // Shutdown does not have to wait out three more turns to notice. The
        // employees not started here are not lost — they are rows whose deadline
        // has passed, and the next tick or the next replica takes them.
        if cancel.is_cancelled() {
            tracing::info!("initiative loop cancelled mid-batch; the rest stay due");
            break;
        }

        let span = tracing::info_span!(
            "initiative_turn",
            employee_id = %due.employee_id,
            tenant_id = %due.tenant_id,
            claims = due.claims,
        );
        handle(db, take, due, now).instrument(span).await;
    }
    Ok(batch.len())
}

/// Decide what one claimed employee's turn is, take it, and write down what
/// became of it.
///
/// Every failure here is confined to this employee: nothing propagates, because
/// one unreadable charter must not stop the other three in the batch or the loop
/// that carries them.
async fn handle<H, F>(db: &Db, take: &H, due: &Due, now: DateTime<Utc>)
where
    H: Fn(Assignment) -> F,
    F: Future<Output = Result<(), String>>,
{
    let outcome = match assignment_for(db, due).await {
        Ok(Some(assignment)) => {
            // The per-day turn budget, and it lives here rather than inside
            // `take_turn` because the budget belongs to the employee, not to
            // the model call.
            //
            // Reserved *before* the turn runs and never released, for the same
            // reason the claim reschedules at take-up rather than at success: a
            // budget you can get back by failing is a crash loop's fuel. The
            // cost of that is real and accepted — a turn killed by a database
            // flap still burns its slot — but over-counting caps the bill and
            // under-counting caps nothing.
            //
            // This is the only thing standing between an autonomous employee
            // and an unbounded token spend. Every other limit in this system
            // is on *money* or on tool calls within one turn, and an employee
            // that wakes, thinks, reads and writes without ever proposing a
            // payment trips none of them.
            match reserve_a_turn(db, due, now).await {
                Ok(()) => match take(assignment).await {
                    Ok(()) => Outcome::Turn,
                    Err(why) => {
                        tracing::error!(error = %why, "the employee's own turn did not finish");
                        Outcome::Failed(why)
                    }
                },
                Err(why) => Outcome::OverBudget(why),
            }
        }
        Ok(None) => Outcome::NoCharter,
        Err(outcome) => outcome,
    };

    if outcome != Outcome::Turn {
        tracing::info!(
            outcome = outcome.code(),
            detail = outcome.detail().unwrap_or_default(),
            "no turn taken"
        );
    }
    record(db, due, &outcome, now).await;
}

/// Read everything a turn needs for one claimed employee.
///
/// `Ok(None)` is an employee with no charter — a supported state, not a failure.
/// `Err` carries the outcome to record instead of starting a turn.
/// Take one turn out of the employee's day, or say why it cannot.
///
/// Committed on its own, before the turn runs. Not folded into
/// `assignment_for`'s transaction on purpose: that one is a read, and holding a
/// row lock on the turn bucket for the whole length of a model call would make
/// every other worker touching this employee wait on the LLM.
///
/// There is no matching release. `store::turns` has none, and the reason is
/// the same one that makes the claim reschedule at take-up: money that
/// demonstrably did not move can be given back, but a turn that started has
/// really spent its tokens, and a budget you can recover by failing is exactly
/// the path a crash loop rides — fail late, release, retry, forever.
async fn reserve_a_turn(db: &Db, due: &Due, now: DateTime<Utc>) -> Result<(), String> {
    let mut tx = db
        .tenant_tx(due.tenant_id)
        .await
        .map_err(|err| format!("no tenant transaction: {err}"))?;

    // `None` for the role: the role layer resolves through the employee's team
    // when it has one, and falls back to this argument when it does not. An
    // employee on no team inherits its tenant's limits, which is the same
    // answer the gate gives for every other action.
    let policy = policy_store::load(&mut tx, due.employee_id, None)
        .await
        .map_err(|err| format!("could not load the policy: {err}"))?;

    turns::reserve(&mut tx, due.employee_id, now.date_naive(), &policy)
        .await
        .map_err(|err| err.to_string())?;

    tx.commit()
        .await
        .map_err(|err| format!("could not commit the turn reservation: {err}"))
}

async fn assignment_for(db: &Db, due: &Due) -> Result<Option<Assignment>, Outcome> {
    // The claim was cross-tenant; everything after it is not. RLS applies from
    // here, and an employee that vanished between the claim and now is simply
    // not found.
    let mut tx = db
        .tenant_tx(due.tenant_id)
        .await
        .map_err(|err| Outcome::Failed(format!("no tenant transaction: {err}")))?;

    let read = async {
        let employee = employee_store::load(&mut tx, due.employee_id)
            .await
            .map_err(|err| Outcome::Failed(format!("could not load the employee: {err}")))?;
        let charter = Charter::load(&mut tx, due.employee_id)
            .await
            .map_err(|err| Outcome::Unreadable(err.code().to_owned()))?;
        Ok((employee.employee, charter))
    }
    .await;

    // Read-only, so the rollback is bookkeeping rather than a decision — but it
    // is awaited rather than dropped so a pooled connection is handed back
    // deliberately.
    let _ = tx.rollback().await;
    let (employee, charter) = read?;

    let Some(charter) = charter else {
        return Ok(None);
    };
    // The gaps question, before any model call. See the module docs.
    plan_of(&charter).map_err(Outcome::Clarify)?;

    Ok(Some(Assignment {
        due: due.clone(),
        identity: format!(
            "You are {}, an AI employee at {}. You answer from {}.",
            employee.slug(),
            employee.domain(),
            employee.address()
        ),
        address: employee.address().to_string(),
        charter,
    }))
}

/// Write the outcome down, in its own short transaction.
///
/// Failing to record is logged and swallowed. The schedule already moved, so a
/// lost outcome costs an operator one stale line on a status page — where
/// stopping the loop over bookkeeping would cost every employee its next turn.
async fn record(db: &Db, due: &Due, outcome: &Outcome, now: DateTime<Utc>) {
    let mut tx = match db.admin_tx_bypassing_rls().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(error = %err, "no connection to record the initiative outcome");
            return;
        }
    };
    let written = initiative::record_outcome(
        &mut tx,
        due.employee_id,
        outcome.code(),
        outcome.detail(),
        now,
    )
    .await;
    if let Err(err) = written.and(tx.commit().await.map_err(StoreError::from)) {
        tracing::error!(error = %err, "initiative outcome was not recorded");
    }
}

/// Run one employee's self-started turn.
///
/// Assembled to be indistinguishable from [`Agent::on_turn`](crate::Agent) in
/// every respect that decides what the employee is *allowed* to do: the
/// principal is the employee acting for its own tenant, `Effects` is built
/// around that principal, the gate is the process-wide one, and the system
/// prompt is the same identity string in front of the same
/// [`Charter::system_prompt`]. The only difference is the opening message — a
/// plan rather than somebody's email.
async fn take_turn(agent: Agent, assignment: Assignment) -> Result<(), String> {
    let Assignment {
        identity,
        address,
        charter,
        ..
    } = assignment;
    let role = charter.role();

    let principal = ActingAs::employee(assignment.due.tenant_id, assignment.due.employee_id);
    let turn = Turn::new(
        agent.llm,
        agent.gate,
        Effects::new(agent.db, agent.ports, principal.clone()),
        principal,
        charter.system_prompt(&identity),
        agent.model,
        address,
    );

    // `Charter::brief` is the plan, recomputed this turn and stored nowhere. It
    // is a message rather than part of the prompt because it varies per
    // objective — which is what both role packs say about `Task::instruction`,
    // in as many words.
    let context = Context::new()
        .with_task(TURN_BRIEF)
        .with_task(charter.brief());

    let cancel = agent.cancel.child_token();
    let deadline = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            tokio::time::sleep(TURN_DEADLINE).await;
            cancel.cancel();
        }
    });
    let outcome = turn.run(context, &cancel).await;
    deadline.abort();

    let finished = match outcome {
        Ok(finished) => finished,
        // Recorded and dropped rather than retried, and that is the difference
        // between this loop and the outbox. An inbound message has to be
        // answered eventually, so a failure there is retried until it succeeds
        // or dead-letters. A self-started turn has no counterparty waiting: the
        // employee is already scheduled to try again on its own cadence, and
        // retrying inside this tick would just be the next tick, sooner and at
        // the same cost. `code()` and not the error: a closed vocabulary, going
        // into a column an operator reads.
        Err(err) => return Err(err.code().to_owned()),
    };

    tracing::info!(
        role,
        turns = finished.turns,
        tool_calls = finished.tool_calls,
        stop_reason = finished.stop_reason.code(),
        input_tokens = finished.usage.input_tokens,
        output_tokens = finished.usage.output_tokens,
        cache_read_tokens = finished.usage.cache_read_tokens,
        reply_len = finished.reply.trim().len(),
        "the employee took a turn of its own"
    );

    // ponytail: the closing text is logged and stored nowhere. `on_turn` records
    // its reply because there is a conversation it belongs on and a person who is
    // owed it; this turn has neither. Everything the employee actually *did* went
    // through `Effects`, which is gated and lands in `audit_log`, so the closing
    // summary is commentary rather than record. It is also model output, and
    // `employee_initiative.last_detail` holds only text this codebase authored.
    // Give it a home the day there is a work journal to put it in.
    Ok(())
}

/// What a self-started turn is, in the model's terms.
///
/// Ours, operator-written, and the same bytes every turn — part of the cached
/// prefix, like `main.rs`'s `TURN_BRIEF` that it deliberately mirrors. Nothing a
/// counterparty wrote may be interpolated in here; nothing ever is, because
/// nothing a counterparty wrote is in this turn at all.
const TURN_BRIEF: &str = "Nobody has written to you. Your working rhythm has come round, so this \
                          turn is yours to spend on your own objective. You have been here before \
                          and the plan below does not know it: start by finding out where you \
                          actually got to — read your own conversations, notes and records — then \
                          advance the earliest stage that is not finished. One turn is not the \
                          whole plan. Do the next real piece of work, finish it, and write down \
                          what you did. If a stage is blocked on somebody else, say so and move to \
                          what is not blocked rather than waiting inside this turn.";

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use agentos_app::rolepack::CountryCode;
    use agentos_domain::employee::Lifecycle;
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::initiative::Cadence;
    use agentos_domain::money::{Currency, Money};
    use agentos_store::initiative as schedule;
    use tokio::sync::Mutex;

    use super::*;

    /// `claim_due` is cross-tenant and `clear_schedules` below is a global
    /// `DELETE`, so everything in this crate that touches `employee_initiative`
    /// goes one at a time — including `routes::initiative`'s tests, which take
    /// this same lock. Two locks would be two halves of one table.
    pub(crate) static LOOP_LOCK: Mutex<()> = Mutex::const_new(());

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the initiative loop needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    use uuid::Uuid;

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'loop-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");

        tx.commit().await.expect("commit");
        platform_turn_budget(db, 100).await;
        tenant
    }

    /// The platform layer, with a turn budget.
    ///
    /// Two reasons a fixture has to do this. `handle` reserves a turn before it
    /// calls the model, and `store::policy::load` answers `NoPlatformLayer` —
    /// an error, not a permissive default — when nothing installs one, so
    /// without this every employee here is refused before it starts. And the
    /// budget itself has to be granted: `PolicyLimits::default()` is zero
    /// turns, which is the fail-closed half of the design working. An
    /// unconfigured employee never wakes rather than never stopping, so a
    /// fixture that wants a turn has to ask for one exactly like an operator.
    ///
    /// The platform layer is a global singleton — `tenant_id IS NULL` — so this
    /// replaces whatever was there rather than adding a second. `scripts/test.sh`
    /// runs `--test-threads=1`, which is what keeps that safe; see
    /// `routes::turns::tests`, which does the same thing for the same reason.
    async fn platform_turn_budget(db: &Db, turns: i32) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM policy_versions WHERE tenant_id IS NULL")
            .execute(&mut *tx)
            .await
            .expect("clear platform versions");
        let version = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO policy_versions (id, tenant_id, label, active) \
             VALUES ($1, NULL, 'initiative-loop-test', true)",
        )
        .bind(version)
        .execute(&mut *tx)
        .await
        .expect("insert platform version");
        sqlx::query(
            "INSERT INTO policy_layers (id, version_id, tenant_id, layer, max_turns_per_day) \
             VALUES ($1, $2, NULL, 'platform', $3)",
        )
        .bind(Uuid::now_v7())
        .bind(version)
        .bind(turns)
        .execute(&mut *tx)
        .await
        .expect("insert platform layer");
        tx.commit().await.expect("commit platform");
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    async fn clear_schedules(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM employee_initiative")
            .execute(&mut *tx)
            .await
            .expect("clear");
        tx.commit().await.expect("commit");
    }

    fn workable() -> Charter {
        Charter::Purchasing {
            pack: rolepack::RolePack::international_buyer(),
            objective: rolepack::Objective {
                what: "anodised aluminium enclosures".to_owned(),
                quantity: 5_000,
                max_unit_price: Some(Money::from_major(12, Currency::Usd).expect("money")),
                delivery_country: Some(CountryCode::parse("DE").expect("country")),
                requirements: vec!["6063-T5".to_owned()],
            },
        }
    }

    /// An objective a person really would state, with half of it missing.
    fn vague() -> Charter {
        Charter::Sales {
            pack: rolepack_sales::RolePack::sales_development(),
            objective: rolepack_sales::Objective {
                segment: rolepack_sales::Segment::Airline,
                market: None,
                target_accounts: Vec::new(),
            },
        }
    }

    /// An active employee, due now, optionally chartered. The eleven resource
    /// rows are real because `employee_store::load` insists on all of them.
    async fn seed_due(
        db: &Db,
        tenant: TenantId,
        slug: &str,
        charter: Option<Charter>,
    ) -> EmployeeId {
        use agentos_domain::action::Domain;
        use agentos_domain::employee::{Employee, ResourceState, Step};
        use agentos_domain::ids::Slug;

        let now = Utc::now();
        let id = EmployeeId::new_v7(now);
        let mut employee = Employee::new(
            id,
            tenant,
            Slug::parse(&format!("{slug}{:x}", now.timestamp_subsec_nanos())).expect("slug"),
            Domain::parse("agents.example.com").expect("domain"),
            now,
        );
        for step in Step::ALL {
            let _ = employee.set_resource(step, ResourceState::Provisioning, now);
            let _ = employee.set_resource(step, ResourceState::Ready, now);
        }
        employee
            .set_lifecycle(Lifecycle::Active, now)
            .expect("release");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        employee_store::insert(&mut tx, &employee)
            .await
            .expect("insert employee");
        if let Some(charter) = charter {
            charter.save(&mut tx, id, now).await.expect("save charter");
        }
        let hourly = Cadence::every(Duration::from_secs(3_600)).expect("cadence");
        // Scheduled far enough in the past that it is due whatever the jitter.
        schedule::set(&mut tx, id, hourly, now - chrono::TimeDelta::days(1))
            .await
            .expect("set schedule");
        tx.commit().await.expect("commit");
        id
    }

    async fn outcome_of(
        db: &Db,
        tenant: TenantId,
        id: EmployeeId,
    ) -> (String, Option<String>, i64) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let stored = schedule::get(&mut tx, id).await.expect("get");
        tx.rollback().await.expect("rollback");
        (
            stored.last_outcome.unwrap_or_default(),
            stored.last_detail,
            stored.claims,
        )
    }

    /// The loop's whole decision table, and the two properties that matter about
    /// it: an objective it cannot work costs no turn, and one employee's failure
    /// does not stop the batch.
    #[tokio::test]
    async fn a_batch_survives_one_failure_and_only_workable_objectives_cost_a_turn() {
        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;

        let works = seed_due(&db, tenant, "works", Some(workable())).await;
        let fails = seed_due(&db, tenant, "fails", Some(workable())).await;
        let asks = seed_due(&db, tenant, "asks", Some(vague())).await;
        let bare = seed_due(&db, tenant, "bare", None).await;

        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();
        let take = move |assignment: Assignment| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                assert_eq!(assignment.charter.role(), "international-buyer");
                assert!(assignment.identity.starts_with("You are "));
                if assignment.due.employee_id == fails {
                    return Err("turn_failed".to_owned());
                }
                Ok(())
            }
        };

        let cancel = CancellationToken::new();
        let claimed = tick(&db, &take, &cancel, Utc::now()).await.expect("tick");

        assert_eq!(claimed, 4, "all four were due");
        assert_eq!(
            started.load(Ordering::SeqCst),
            2,
            "only the two workable objectives may cost a model call"
        );

        assert_eq!(outcome_of(&db, tenant, works).await.0, "turn");

        // The failure was recorded and the rest of the batch still ran.
        let (outcome, detail, claims) = outcome_of(&db, tenant, fails).await;
        assert_eq!(outcome, "error");
        assert_eq!(detail.as_deref(), Some("turn_failed"));
        assert_eq!(claims, 1, "a failed turn still spent its slot");

        // The vague one asked its operator instead of guessing, and the question
        // names every gap at once.
        let (outcome, detail, _) = outcome_of(&db, tenant, asks).await;
        assert_eq!(outcome, "clarify");
        let question = detail.expect("a clarify outcome carries its question");
        assert!(question.contains("which market"), "{question}");
        assert!(question.contains("which accounts"), "{question}");

        assert_eq!(outcome_of(&db, tenant, bare).await.0, "no_charter");

        // And nothing is due again: the claim rescheduled all four.
        let again = tick(&db, &take, &cancel, Utc::now()).await.expect("tick");
        assert_eq!(again, 0, "a claimed employee must not be re-claimed");

        drop_tenant(&db, tenant).await;
    }

    /// Cancellation is honoured mid-batch: the in-flight turn finishes, the rest
    /// stay due. They are rows, not in-memory state.
    #[tokio::test]
    async fn a_cancelled_loop_stops_between_employees() {
        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;
        for n in 0..4 {
            seed_due(&db, tenant, &format!("e{n}"), Some(workable())).await;
        }

        let cancel = CancellationToken::new();
        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();
        let stop = cancel.clone();
        let take = move |_: Assignment| {
            let counter = counter.clone();
            let stop = stop.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                // The first turn is what SIGTERM lands during.
                stop.cancel();
                Ok(())
            }
        };

        tick(&db, &take, &cancel, Utc::now()).await.expect("tick");
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "the batch must stop at the first employee after cancellation"
        );

        drop_tenant(&db, tenant).await;
    }

    /// A suspended employee is not the loop's business, however overdue. Belt to
    /// the store's braces: the filter is in the claim, and this is the loop
    /// observing that it holds from the outside.
    #[tokio::test]
    async fn a_suspended_employee_never_reaches_a_turn() {
        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;
        let id = seed_due(&db, tenant, "paused", Some(workable())).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("UPDATE employees SET lifecycle = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(Lifecycle::Suspended.as_str())
            .execute(&mut *tx)
            .await
            .expect("suspend");
        tx.commit().await.expect("commit");

        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();
        let take = move |_: Assignment| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        };

        let cancel = CancellationToken::new();
        let claimed = tick(&db, &take, &cancel, Utc::now()).await.expect("tick");
        assert_eq!(claimed, 0);
        assert_eq!(started.load(Ordering::SeqCst), 0);

        drop_tenant(&db, tenant).await;
    }

    /// The gaps question is the role pack's, not this loop's, and it is the same
    /// answer the route shows the operator.
    #[test]
    fn a_complete_objective_plans_and_an_incomplete_one_asks() {
        let plan = plan_of(&workable()).expect("a complete objective plans");
        assert_eq!(plan.first().map(|(stage, _)| *stage), Some("discover"));
        assert_eq!(plan.last().map(|(stage, _)| *stage), Some("order"));
        assert!(plan[0].1.contains("anodised aluminium enclosures"));

        let question = plan_of(&vague()).expect_err("gaps must not produce a plan");
        assert!(question.contains("which market"), "{question}");
    }
}
