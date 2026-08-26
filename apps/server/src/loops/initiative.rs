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
//! # The vertical runs *before* the model, not instead of it
//!
//! [`RolePack::plan`](agentos_app::rolepack::RolePack::plan) says which stage is
//! due, and until this loop called [`agentos_app::vertical`] the employee was
//! *told* the stage and the function that performs it was never called. Closing
//! that had three shapes and only one of them is this system.
//!
//! * **Instead of.** [`vertical::due`](agentos_app::vertical::due) answers
//!   `Stage::Rfq`, so the loop issues the RFQ and never calls the model.
//!   Cheapest and most deterministic, and it deletes the employee: nobody
//!   writes down what happened, nobody notices the supplier who replied "we
//!   don't make that", and nobody can say a stage is blocked. It also has
//!   nowhere to put [`Bought::Model`](agentos_app::vertical::Bought), which is
//!   the vertical's own way of saying *this stage is reading and judging, it is
//!   the model's* — a value that only makes sense if there is a model turn to
//!   fall through to.
//! * **From inside.** The vertical becomes a tool the model may invoke. That is
//!   `(i)` in `vertical.rs`'s module docs, argued against there at length —
//!   twelve tool schemas for two roles against a catalogue that is a
//!   fixed-size array on purpose, and one gate decision covering N recipients
//!   whose per-recipient budget it never saw. Not reversed here.
//! * **Before** — what [`take_turn`] does. [`vertical_step`] runs the due
//!   operation out of the employee's own store, and its
//!   [`Ran::note`](agentos_app::vertical::Ran) becomes the last message of the
//!   opening context. The code decides the step; the model does the language.
//!
//! That is `vertical.rs`'s own sentence — "the model does the language and the
//! role pack decides the stage" — and *before* is the only one of the three
//! that keeps both halves of it. The RFQ's letter is ours rather than the
//! model's for the same reason
//! [`Approach::new`](agentos_app::vertical::Approach) builds the sales message
//! from the evidence rather than from a model: a specification re-worded every
//! cadence is three specifications reaching three suppliers whose quotes then
//! do not compare. The language the model does here is the conversation that
//! follows — the reply to a supplier, the report of what happened, the
//! judgement about who is worth chasing.
//!
//! Nothing about the authority changes. The `Buyer` is built on the same
//! [`Effects`] the turn is built on, around the same principal, gated by the
//! same process-wide [`PolicyGate`](agentos_app::gate::PolicyGate), and every
//! recipient is authorised on its own inside
//! [`Buyer::issue_rfq`](agentos_app::sourcing::Buyer::issue_rfq). The turn
//! budget is still reserved once, in [`handle`], before any of it.
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

use std::sync::Arc;

use agentos_app::effects::{Effects, Ports};
use agentos_app::gate::Principal as ActingAs;
use agentos_app::inbound;
use agentos_app::prompt::Relation;
use agentos_app::proof_of_need::Prober;
use agentos_app::revenue::Seller;
use agentos_app::sourcing::Buyer;
use agentos_app::turn::{Context, Turn};
use agentos_app::vertical::{self, Charter};
use agentos_app::{rolepack, rolepack_sales, rolepack_service};
use agentos_domain::ids::Slug;
use agentos_domain::policy::{EffectivePolicy, ModelId, model_for};
use agentos_store::db::{Db, StoreError};
use agentos_store::employee as employee_store;
use agentos_store::initiative::{self, Due};
use agentos_store::model_usage::{self, Consumed};
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
    /// Who it may message, and why: manager, direct reports, team-mates. Read
    /// in the same transaction as the charter, because it belongs to the same
    /// cached prefix and there is no reason to open a second one.
    pub colleagues: Vec<(Slug, Relation)>,
    /// Which of the tenant's MCP tools this employee may call — the other list
    /// in that same prefix, read in the same transaction for the same reason.
    ///
    /// It is the whole [`EffectivePolicy`], not a set of names, because
    /// `SystemPrompt::with_mcp_tools` asks `policy::evaluate_mcp_call` rather
    /// than reading an allowlist: one rule, and the prompt is a reader of it.
    /// `None` is a policy that would not load, which names nothing — see
    /// [`assignment_for`].
    pub policy: Option<EffectivePolicy>,
    /// Which model this turn runs on: the charter's preference, already
    /// intersected with `policy`'s `allowed_models` by
    /// [`model_for`](agentos_domain::policy::model_for).
    ///
    /// Resolved in [`assignment_for`] rather than in [`take_turn`] because the
    /// empty intersection is a *reason not to start a turn* — the same shape as
    /// a missing charter or an unanswered gap — and every other such reason is
    /// an [`Outcome`] decided there. Resolving it later would mean spending a
    /// reserved turn to discover it.
    pub model: ModelId,
    /// The prospect a sales charter works this turn, resolved here for exactly
    /// the reason [`Assignment::model`] is: **an empty answer is a reason not to
    /// start a turn.**
    ///
    /// `None` for every other role, and the asymmetry is the point rather than
    /// an omission. A buyer with no supplier on file still has a turn worth
    /// taking — mail to read, quotes to chase, a plan to report on — and
    /// [`vertical_step`] hands it `None` and lets it think. A seller with no
    /// prospect due has *nothing*: the whole of its vertical is "run one
    /// prospect's flow and say what it showed", and there is no prospect. So the
    /// buyer's material is read inside the turn and the seller's is read before
    /// it, and a seller whose operator has described no booking flows costs one
    /// query per cadence rather than a model call.
    pub prospect: Option<vertical::DueProspect>,
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
    /// Platform ∧ tenant ∧ role ∧ employee intersected `allowed_models` to the
    /// empty set, so there is no model this employee may think with.
    ///
    /// **Its own code, not `Failed`.** The two are indistinguishable to the
    /// loop and completely different to the operator reading the column: this
    /// one is a policy they wrote, it will produce the identical result on
    /// every cadence until they change it, and no amount of retrying or
    /// provider-status-checking will move it.
    NoModel(String),
    /// The objective has gaps. Ask the operator, and start no turn.
    Clarify(String),
    /// The objective is workable and there is nothing to work on: no prospect
    /// due, or none an operator has described a booking flow for.
    ///
    /// **Its own code, not `Clarify` and not `Turn`.** It is not a question —
    /// the operator answered every question the objective asks, and the answer
    /// to this one is data rather than words. It is not a turn either: a seller
    /// whose whole vertical is "run one prospect's flow" and who has no prospect
    /// has nothing to spend a model call on, and spending one anyway is how a
    /// transcript comes to read like a day's work with nothing behind it.
    ///
    /// It costs one query per cadence and resolves by itself the moment a flow
    /// is configured or a prospect's three days are up. Nothing has to notice.
    NoWork(String),
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
            Outcome::NoModel(_) => "no_model",
            Outcome::Clarify(_) => "clarify",
            Outcome::NoWork(_) => "no_work",
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
            | Outcome::NoModel(why)
            | Outcome::Clarify(why)
            | Outcome::NoWork(why)
            | Outcome::Failed(why)
            | Outcome::OverBudget(why) => Some(why),
        }
    }
}

/// The plan for a charter, or the question that has to be answered first.
///
/// `Err` is a `Stage::Clarify` task, which every pack returns **alone** — a plan
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
        // The four packs in `rolepack_service` share one `Task` and one
        // `Stage`, so they share one arm each and one helper — the branch above
        // is written twice because the two older packs have neither in common.
        Charter::Support { objective } => service_plan(objective.plan()),
        Charter::Growth { objective } => service_plan(objective.plan()),
        Charter::Finance { objective } => service_plan(objective.plan()),
        Charter::EntryRequirements { objective } => service_plan(objective.plan()),
    }
}

/// [`plan_of`]'s answer for a [`rolepack_service`] plan.
fn service_plan(tasks: Vec<rolepack_service::Task>) -> Result<Vec<(&'static str, String)>, String> {
    match tasks.first() {
        Some(first) if first.stage == rolepack_service::Stage::Clarify => {
            Err(first.instruction.clone())
        }
        _ => Ok(tasks
            .into_iter()
            .map(|task| (task.stage.code(), task.instruction))
            .collect()),
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
    let outcome = match assignment_for(db, due, now).await {
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
    let policy = policy_store::load(&mut tx, due.employee_id)
        .await
        .map_err(|err| format!("could not load the policy: {err}"))?;

    turns::reserve(&mut tx, due.employee_id, now.date_naive(), &policy)
        .await
        .map_err(|err| err.to_string())?;

    tx.commit()
        .await
        .map_err(|err| format!("could not commit the turn reservation: {err}"))
}

async fn assignment_for(
    db: &Db,
    due: &Due,
    now: DateTime<Utc>,
) -> Result<Option<Assignment>, Outcome> {
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
        // The org chart, in the same read. A self-started turn has no
        // counterparty, so `message_colleague` is the only outward verb it is
        // likely to want — and an employee that has to guess a slug for it
        // spends one of the few turns its cadence gives it per day.
        let colleagues = inbound::colleagues(&mut tx, due.employee_id)
            .await
            .map_err(|err| Outcome::Failed(format!("could not read the colleagues: {err}")))?;
        // And the allowlist the prefix names the tenant's MCP tools from.
        // `None` for the role, exactly as `reserve_a_turn` and the gate pass it:
        // the role layer resolves through the employee's team when it has one.
        //
        // A policy that will not load is not a reason to abandon the turn here —
        // `reserve_a_turn` is about to load it again and will refuse the turn
        // outright if it is broken, and the gate refuses every action after
        // that. What it means for the prefix is that this employee may call no
        // MCP tool, so it is told about none.
        let policy = match policy_store::load(&mut tx, due.employee_id).await {
            Ok(policy) => Some(policy),
            Err(err) => {
                tracing::warn!(
                    employee_id = %due.employee_id.as_uuid(),
                    error = %err,
                    "no usable policy for this employee; its prefix names no mcp tools"
                );
                None
            }
        };
        Ok((employee.employee, charter, colleagues, policy))
    }
    .await;

    // Read-only, so the rollback is bookkeeping rather than a decision — but it
    // is awaited rather than dropped so a pooled connection is handed back
    // deliberately.
    let _ = tx.rollback().await;
    let (employee, charter, colleagues, policy) = read?;

    let Some(charter) = charter else {
        return Ok(None);
    };
    // The gaps question, before any model call. See the module docs.
    plan_of(&charter).map_err(Outcome::Clarify)?;

    // And the model question, also before any model call and for the same
    // reason: an employee whose policy permits no model cannot take this turn or
    // any other, so it must not reserve one to find that out.
    //
    // No fallback. The expensive model would be a bill nobody authorised and the
    // cheap one would be a policy this operator did not write — see
    // `agentos_domain::policy::model_for`, which returns `None` here rather than
    // choosing.
    let preferred = charter.model();
    let Some(model) = model_for(policy.as_ref(), preferred) else {
        return Err(Outcome::NoModel(format!(
            "role {} asked for {preferred} and `allowed_models` intersected to the empty set; \
             grant one in a policy layer",
            charter.role(),
        )));
    };
    if model != preferred {
        tracing::info!(
            employee_id = %due.employee_id.as_uuid(),
            role = charter.role(),
            %preferred,
            substituted = %model,
            "this employee's policy does not permit its role's model; running the cheapest \
             one it does permit"
        );
    }

    // And the sales vertical's material, for the same reason again and in the
    // same place: **a seller with nobody to work must not pay for a turn to find
    // that out.** `NoCharter`, `Clarify` and `NoModel` are all decided here
    // rather than inside `take_turn` precisely because the reservation is
    // between the two, and this is a fourth reason of exactly that shape.
    //
    // The buyer has no matching arm and does not want one. Its material is read
    // inside the turn because a buyer with no supplier still has a turn worth
    // taking; a seller's whole vertical is one prospect's flow, and with no
    // prospect there is nothing for the model to write about that it did not
    // invent.
    let prospect = match &charter {
        Charter::Sales { objective, .. } => match prospect_for(db, due, objective, now).await? {
            Some(prospect) => Some(prospect),
            None => {
                return Err(Outcome::NoWork(
                    "no prospect is due for this segment with a booking flow described for it; \
                     import prospects, describe a flow, or wait for the follow-up window"
                        .to_owned(),
                ));
            }
        },
        _ => None,
    };

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
        colleagues,
        policy,
        model,
        prospect,
    }))
}

/// The prospect a sales charter would work now, in a read of its own.
///
/// Its own short transaction rather than the one above: that one is already
/// rolled back by the time the charter has been parsed, and re-opening it to
/// carry a read that only one of six roles needs would make every other role pay
/// for the shape of this one.
///
/// A store that will not answer is [`Outcome::Failed`] and no turn — not
/// [`Outcome::NoWork`], which claims the queue is empty, and not a turn taken
/// anyway. "We could not tell whether there is work" and "there is no work" are
/// different sentences on an operator's status page, and only one of them is
/// worth waking up for.
async fn prospect_for(
    db: &Db,
    due: &Due,
    objective: &agentos_app::rolepack_sales::Objective,
    now: DateTime<Utc>,
) -> Result<Option<vertical::DueProspect>, Outcome> {
    let mut tx = db
        .tenant_tx(due.tenant_id)
        .await
        .map_err(|err| Outcome::Failed(format!("no tenant transaction: {err}")))?;
    let read = vertical::due_prospect(&mut tx, objective, now).await;
    // Read-only, so the rollback is bookkeeping rather than a decision — but it
    // is awaited so the pooled connection goes back deliberately.
    let _ = tx.rollback().await;

    read.map_err(|err| Outcome::Failed(format!("could not read this seller's prospects: {err}")))
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
        due,
        identity,
        address,
        charter,
        colleagues,
        policy,
        model,
        prospect,
    } = assignment;
    let role = charter.role();

    // Cloned before `Effects` takes it: the token ledger below needs a
    // connection of its own, because unlike `Agent::on_turn` there is no
    // transaction spanning this turn to write into.
    let db = agent.db.clone();

    // The tenant's own MCP bindings, substituted into a per-turn copy of the
    // process-wide `Ports` exactly as `Agent::on_turn` does it.
    //
    // This loop used to hand `Effects` the process-wide ports, whose `mcp` is
    // the unbound stub — so a self-started turn could never reach a tenant's
    // servers however well they were bound. That was survivable while nothing
    // named the inventory; it stops being survivable the moment the prefix does,
    // because a tool named to a turn that cannot call it is the exact leak
    // `turn::visible` exists to make unrepresentable.
    let fleet = agent.fleets.for_tenant(due.tenant_id);
    let ports = Arc::new(Ports {
        mcp: fleet.clone(),
        ..(*agent.ports).clone()
    });

    let principal = ActingAs::employee(due.tenant_id, due.employee_id);
    let effects = Effects::new(agent.db.clone(), ports, principal.clone());

    // The vertical, before the model and never instead of it. See the module
    // docs on why this is not a branch that skips the turn.
    let done = vertical_step(
        &agent,
        &effects,
        &principal,
        &charter,
        &address,
        prospect.as_ref(),
    )
    .await;

    // Same prefix as `Agent::on_turn`, down to the order of the builders and to
    // the policy the inventory is narrowed by: an employee that wakes itself
    // must be told exactly what an employee woken by a stranger is told, or
    // "same authority either way" is only true of the gate and not of what the
    // model knows to ask for.
    //
    // That now covers the tool schemas too — `SystemPrompt::request` narrows
    // them by this same policy through `turn::tools_for` — which makes the
    // sameness stronger and the `None` arm more load-bearing. `None` is a policy
    // that would not load, and it leaves the catalogue unnarrowed on purpose:
    // see the matching arm in `main.rs`, which argues why a failed read must not
    // read as a grant of nothing.
    let prompt = charter.system_prompt(&identity);
    let prompt = match &policy {
        Some(policy) => prompt.with_mcp_tools(policy, fleet.inventory()),
        None => prompt,
    }
    .with_colleagues(colleagues);

    let turn = Turn::new(
        agent.llm,
        agent.gate,
        effects,
        principal,
        prompt,
        model.as_str(),
        address,
    );

    // `Charter::brief` is the plan, recomputed this turn and stored nowhere. It
    // is a message rather than part of the prompt because it varies per
    // objective — which is what both role packs say about `Task::instruction`,
    // in as many words.
    //
    // The vertical's note goes after the plan and is ours as thoroughly as the
    // plan is: parsed addresses, `Money`, and closed enums, with no supplier's
    // prose and no supplier's legal name in it. So this turn still starts
    // trusted by construction.
    let mut context = Context::new()
        .with_task(TURN_BRIEF)
        .with_task(charter.brief());
    if let Some(note) = done {
        context = context.with_task(note);
    }

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
        Err(failed) => {
            // The bill first: a turn that blew its deadline still paid for the
            // calls it made, and it is the crash-looping employee — the one the
            // turn budget exists for — whose calls are most real and least
            // recorded.
            if failed.turns > 0 {
                let mut tx = db.tenant_tx(due.tenant_id).await.map_err(|err| {
                    format!("no tenant transaction for the failed turn's tokens: {err}")
                })?;
                model_usage::record(
                    &mut tx,
                    due.employee_id,
                    Utc::now().date_naive(),
                    Consumed::reported(
                        failed.turns,
                        failed.usage.input_tokens,
                        failed.usage.output_tokens,
                        failed.usage.cache_read_tokens,
                    ),
                )
                .await
                .map_err(|err| format!("could not record what the failed turn spent: {err}"))?;
                tx.commit()
                    .await
                    .map_err(|err| format!("could not commit the failed turn's tokens: {err}"))?;
            }
            return Err(failed.error.code().to_owned());
        }
    };

    tracing::info!(
        role,
        turns = finished.turns,
        tool_calls = finished.tool_calls,
        // Beside `tool_calls` because it is the half of it that did nothing.
        // Without it a turn whose every proposal was rejected by the parser
        // logs the same line as a turn whose every proposal ran, and the only
        // way to tell them apart is a join against `audit_log`.
        malformed_calls = finished.malformed_calls,
        stop_reason = finished.stop_reason.code(),
        input_tokens = finished.usage.input_tokens,
        output_tokens = finished.usage.output_tokens,
        cache_read_tokens = finished.usage.cache_read_tokens,
        reply_len = finished.reply.trim().len(),
        "the employee took a turn of its own"
    );

    // The token ledger. `Agent::on_turn` writes this inside the transaction that
    // commits the turn's reply; a self-started turn has no such transaction —
    // everything it did went through `Effects`, which commits per effect — so
    // this is one short transaction of its own, immediately after the run.
    //
    // Its failure is returned rather than swallowed, which is the same trade
    // `on_turn` makes and it is worth naming what it costs here: an employee
    // whose ledger write failed is recorded as `Outcome::Failed` and shows
    // `error` on its status page, even though the turn itself worked. That is
    // deliberate. `record` next door swallows a lost *outcome* because a stale
    // status line is cosmetic; a lost usage row is not cosmetic, it is a bill
    // that silently reads lower, and low is the direction that flatters the
    // number. Loud and slightly wrong beats quiet and convenient.
    //
    // `Utc::now()` for the day rather than the tick's clock: `Assignment` does
    // not carry one, and the only case where they differ is a turn that started
    // just before UTC midnight — which books its tokens on the day it finished.
    // ponytail: thread `now` through `Assignment` if that ever matters.
    let mut tx = db
        .tenant_tx(due.tenant_id)
        .await
        .map_err(|err| format!("no tenant transaction for the token ledger: {err}"))?;
    let recorded = model_usage::record(
        &mut tx,
        due.employee_id,
        Utc::now().date_naive(),
        Consumed::reported(
            finished.turns,
            finished.usage.input_tokens,
            finished.usage.output_tokens,
            finished.usage.cache_read_tokens,
        ),
    )
    .await;
    match recorded {
        Ok(()) => tx
            .commit()
            .await
            .map_err(|err| format!("the turn's token usage could not be committed: {err}"))?,
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(format!(
                "the turn's token usage could not be recorded: {err}"
            ));
        }
    }

    // ponytail: the closing text is logged and stored nowhere. `on_turn` records
    // its reply because there is a conversation it belongs on and a person who is
    // owed it; this turn has neither. Everything the employee actually *did* went
    // through `Effects`, which is gated and lands in `audit_log`, so the closing
    // summary is commentary rather than record. It is also model output, and
    // `employee_initiative.last_detail` holds only text this codebase authored.
    // Give it a home the day there is a work journal to put it in.
    Ok(())
}

/// Run whatever vertical operation this charter's plan makes due, and return
/// what to tell the employee about it.
///
/// `None` is "nothing ran", and it is not a failure: a charter this vertical has
/// no material for, or a store that could not be read. The turn goes ahead
/// either way — the budget is already spent, and an employee that cannot read
/// its round can still read its mail and say so.
///
/// Every provider call inside this is [`Buyer`]'s, which gates each address on
/// its own and hands the resulting `Authorized<A>` to the same [`Effects`] the
/// turn below uses. There is no second path and no widened authority: this is
/// the employee doing, before the same employee writes.
async fn vertical_step(
    agent: &Agent,
    effects: &Effects,
    principal: &ActingAs,
    charter: &Charter,
    address: &str,
    prospect: Option<&vertical::DueProspect>,
) -> Option<String> {
    match charter {
        Charter::Purchasing { pack, objective } => {
            let buyer = Buyer::new(
                agent.gate.clone(),
                effects.clone(),
                principal.clone(),
                address.to_owned(),
            );

            match vertical::purchasing_turn(
                &agent.db,
                &buyer,
                principal,
                pack,
                objective,
                Utc::now(),
            )
            .await
            {
                Ok(ran) => {
                    tracing::info!(
                        unreachable = ran.unreachable.len(),
                        "the purchasing vertical ran before the turn"
                    );
                    Some(ran.note())
                }
                // Logged and swallowed. A round that could not be read is not a
                // reason to spend the reserved turn on nothing, and it is not a
                // reason to pull the cadence back in either — the next tick
                // reads it again.
                Err(err) => {
                    tracing::error!(
                        code = err.code(),
                        error = %err,
                        "the purchasing vertical did not run; the employee takes an ordinary turn"
                    );
                    None
                }
            }
        }

        // The prospect was resolved before the turn was reserved, so `None`
        // here is not "nothing due" — that never got this far. It is the one
        // race the split leaves: a prospect that was written to, suppressed or
        // proved something about between `assignment_for` and now. One ordinary
        // turn, and the next cadence reads the queue again.
        Charter::Sales { pack, objective } => {
            let prospect = prospect?;
            selling_step(
                agent, effects, principal, address, pack, objective, prospect,
            )
            .await
        }

        // The four service packs. No vertical operation exists for any of them
        // — there is no `vertical::support_turn` to call, not a decision made
        // here — so the employee takes the ordinary turn it always took, and
        // `Charter::brief` still tells it which stage its own plan makes due.
        Charter::Support { .. }
        | Charter::Growth { .. }
        | Charter::Finance { .. }
        | Charter::EntryRequirements { .. } => None,
    }
}

/// The sales vertical, out of the same [`Effects`] the turn is built on.
///
/// Every provider call inside this is [`Prober`]'s or [`Seller`]'s, each of
/// which gates its own subject and hands the resulting `Authorized<A>` to those
/// same `Effects`. There is no second path and no widened authority: the browser
/// steps are ruled on one domain at a time, the Orizn lookup is an
/// `Action::McpCall` this employee's policy has to name, and the approach is one
/// `EmailSend` per address, counted against the same
/// `max_new_contacts_per_day` every other outbound message spends.
///
/// # The suppression list is loaded, not defaulted
///
/// [`Seller::new`] takes one and every caller in the workspace used to pass an
/// empty one, which was survivable exactly as long as nothing reached
/// [`Seller::touch`](agentos_app::revenue::Seller::touch). This is the dispatch
/// that reaches it. [`vertical::suppression_for`] asks the schema's own
/// `SECURITY DEFINER` lookup — the only reader that can see a *global*
/// suppression, which the per-tenant RLS policy hides from an ordinary `SELECT`
/// — and fails closed.
#[allow(clippy::too_many_arguments)]
async fn selling_step(
    agent: &Agent,
    effects: &Effects,
    principal: &ActingAs,
    address: &str,
    pack: &rolepack_sales::RolePack,
    objective: &rolepack_sales::Objective,
    prospect: &vertical::DueProspect,
) -> Option<String> {
    // The employee's own browser context, as provisioning left it. A `Prober`
    // takes the session rather than looking one up, deliberately — a browser
    // context is a provisioned resource — so this is where the two meet.
    let session = match effects.browser_session().await {
        Ok(session) => session,
        Err(err) => {
            tracing::warn!(
                code = err.code(),
                "this seller has no ready browser context; it takes an ordinary turn"
            );
            return None;
        }
    };

    let seller = Seller::new(
        agent.gate.clone(),
        effects.clone(),
        principal.clone(),
        address.to_owned(),
        vertical::suppression_for(&agent.db, principal, &prospect.to).await,
    );
    let prober = Prober::new(
        agent.db.clone(),
        agent.gate.clone(),
        effects.clone(),
        principal.clone(),
        session,
    );

    match vertical::selling_turn(
        &agent.db,
        &prober,
        &seller,
        &vertical::orizn_binding(),
        principal,
        pack,
        objective,
        prospect,
        Utc::now(),
    )
    .await
    {
        Ok(worked) => {
            // Two stable labels and nothing else. The prospect is on the
            // evidence row and in the note, never on a metric: a counter keyed
            // by prospect is one time series per prospect and a leak in every
            // collector that scrapes it.
            tracing::info!(
                sold = worked.sold.code(),
                filed = worked.filed.is_some(),
                "the sales vertical ran before the turn"
            );
            Some(worked.note())
        }
        // Logged and swallowed, exactly as the buyer's is. A check that could
        // not run is not a reason to spend the reserved turn on nothing — the
        // employee can still read its mail and report — and the attempt is
        // already a row in `proof_of_need_attempts` whatever it came to.
        Err(err) => {
            tracing::error!(
                code = err.code(),
                error = %err,
                "the sales vertical did not run; the employee takes an ordinary turn"
            );
            None
        }
    }
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
    use uuid::Uuid;

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

    /// This module's own database — see [`private_db`](crate::loops::private_db).
    ///
    /// It has to be its own for the same reason the other three pollers do, and
    /// for one more that is this loop's alone. `claim_due` is cross-tenant by
    /// construction — it takes a bounded batch of whoever is due anywhere — so
    /// another test's employees are inside its window and no `WHERE tenant_id`
    /// narrows it. `turn_budget` below used to replace the **platform policy
    /// layer** as well, which is `tenant_id IS NULL` and therefore one row for
    /// the whole database: on the shared database that deleted the layer other
    /// modules were mid-assertion on, which is exactly how this landed seven
    /// failures across `loops::outbox`, `loops::provisioning` and
    /// `routes::turns` in one run. That half is gone — it writes a tenant layer
    /// now — but the cross-tenant claim is reason enough on its own.
    async fn db() -> Option<Db> {
        crate::loops::private_db("initiative").await
    }

    use agentos_domain::policy::PolicyLimits;

    /// The slug every tenant this module creates carries, so `clear_schedules`
    /// names its own rows rather than the table.
    const TENANT_SLUG: &str = "loop-initiative-";

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'loop-test')")
            .bind(tenant.as_uuid())
            // Prefixed so `clear_schedules` can name this module's rows. A bare
            // uuid is unique but unselectable as a group.
            .bind(format!("{TENANT_SLUG}{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");

        tx.commit().await.expect("commit");
        turn_budget(db, tenant, 100).await;
        tenant
    }

    /// This tenant's turn budget, as a `tenant` policy layer.
    ///
    /// Two reasons a fixture has to do this at all. `handle` reserves a turn
    /// before it calls the model, and `store::policy::load` answers
    /// `NoPlatformLayer` — an error, not a permissive default — when nothing
    /// installs a ceiling, so without this every employee here is refused
    /// before it starts. And the budget itself has to be granted:
    /// `PolicyLimits::default()` is zero turns, which is the fail-closed half
    /// of the design working. An unconfigured employee never wakes rather than
    /// never stopping, so a fixture that wants a turn has to ask for one
    /// exactly like an operator.
    ///
    /// It used to write the *platform* layer, which is `tenant_id IS NULL` and
    /// therefore one row for the whole database, and delete whatever was there
    /// first — safe only under `--test-threads=1`, which `scripts/test.sh`
    /// stopped passing. `store::policy::install` maintains one ceiling and
    /// widens it instead, so the number a test cares about goes in its own
    /// tenant's layer and the intersection takes the minimum.
    async fn turn_budget(db: &Db, tenant: TenantId, turns: u32) {
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                max_turns_per_day: turns,
                // Every model: the layers intersect, so a tenant layer that
                // names none permits none and this employee takes no turn at
                // all. Restating the grant is the rule `PolicyLimits`' own docs
                // give for every allowlist here — there is no inherit marker.
                allowed_models: ModelId::ALL.into_iter().collect(),
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the turn budget");
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
        // Only this module's tenants. `employee_initiative` cascades from
        // `tenants`, so naming them there is the whole predicate.
        sqlx::query(
            "DELETE FROM employee_initiative WHERE tenant_id IN \
             (SELECT id FROM tenants WHERE slug LIKE 'loop-initiative-%')",
        )
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
        // A second pass, because `Step::ALL` is not in dependency order:
        // `Step::Browser` needs `Step::Vault`, which comes after it, and
        // `set_resource` refuses a `Ready` whose dependencies are not. One pass
        // left every employee here with a browser stuck in `provisioning` — an
        // employee that cannot probe anything — and nothing noticed until one
        // had to.
        for step in Step::ALL {
            let _ = employee.set_resource(step, ResourceState::Ready, now);
        }
        // The browser binding, which every employee here gets and only a seller
        // uses. `Effects::browser_session` rebuilds the session out of this row
        // and refuses without it, so a `ready` browser with no provider id is an
        // employee that cannot probe anything — which is a real state, and not
        // the one these fixtures are about.
        employee
            .bind(
                Step::Browser,
                // Per employee: `employee_resources` is unique on
                // (provider, external_id), which is the schema refusing to let
                // two employees share one browser context.
                agentos_domain::employee::ProviderBinding::new(
                    "mock-browser",
                    format!("ctx-{}", id.as_uuid().simple()),
                ),
                now,
            )
            .expect("bind the browser");
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

        // One MCP tool, granted the way an operator grants one. The prefix names
        // the tools this employee's *policy* allows, so an assignment that
        // carried no policy would silently name none — and this fixture is the
        // only thing that would notice.
        let slug = |s: &str| agentos_domain::ids::Slug::parse(s).expect("slug");
        let granted = agentos_domain::action::McpTool::new(slug("erp"), slug("lookup"));
        agentos_store::policy::install(
            &db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                max_turns_per_day: 100,
                allowed_mcp_tools: [granted.clone()].into_iter().collect(),
                // Every model: the layers intersect, so a tenant layer that
                // names none permits none and this employee takes no turn at
                // all. Restating the grant is the rule `PolicyLimits`' own docs
                // give for every allowlist here — there is no inherit marker.
                allowed_models: ModelId::ALL.into_iter().collect(),
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the tenant layer");

        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();
        let take = move |assignment: Assignment| {
            let counter = counter.clone();
            let granted = granted.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                assert_eq!(assignment.charter.role(), "international-buyer");
                assert!(assignment.identity.starts_with("You are "));
                // The employee's own allowlist reached the assignment, so
                // `take_turn` has something to narrow the tenant's inventory
                // with. Asked through the gate's rule rather than by reading
                // the set, which is how `with_mcp_tools` will ask it.
                assert!(
                    assignment.policy.as_ref().is_some_and(|policy| {
                        agentos_domain::policy::evaluate_mcp_call(policy, &granted).is_allow()
                    }),
                    "the assignment carries no usable policy, so this employee's prefix \
                     would name no mcp tool however many its tenant has bound"
                );
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

    /// One supplier who sells what the charter is for, with somebody on file
    /// to write to.
    async fn seed_supplier(db: &Db, tenant: TenantId, category: &str, email: &str) {
        use agentos_store::sourcing as sourcing_store;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let supplier = Uuid::now_v7();
        sourcing_store::insert_supplier(
            &mut tx,
            supplier,
            &sourcing_store::NewSupplier {
                legal_name: "Hamburg Praezision GmbH",
                country: "DE",
                categories: &[category.to_owned()],
                website: None,
            },
        )
        .await
        .expect("insert supplier");
        sqlx::query(
            "INSERT INTO supplier_contacts \
                 (id, tenant_id, supplier_id, full_name, email, is_primary) \
             VALUES ($1, $2, $3, 'Sales', $4, true)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(supplier)
        .bind(email)
        .execute(&mut **tx)
        .await
        .expect("insert contact");
        tx.commit().await.expect("commit supplier");
    }

    /// Emails this employee actually got out of a provider, counted in the one
    /// place every effect lands: the audit trail, each row naming the gate
    /// decision that permitted it.
    async fn emails_sent(db: &Db, tenant: TenantId, employee: EmployeeId) -> i64 {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log \
              WHERE employee_id = $1 \
                AND decision_id IS NOT NULL \
                AND payload->>'effect' = 'email_send' \
                AND payload->>'outcome' = 'ok'",
        )
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("count");
        tx.rollback().await.expect("rollback");
        count
    }

    /// The whole seam, through the real path: a chartered buyer whose cadence
    /// comes due reaches [`take_turn`], the vertical runs **before** the model,
    /// the RFQ goes out through the gate, and the row that makes the round
    /// resumable lands.
    ///
    /// And the budget is spent once. The vertical is inside the reservation
    /// [`handle`] already took, not beside it: an employee that emails five
    /// suppliers and then thinks about it has taken one turn, not two.
    #[tokio::test]
    async fn a_due_buyer_issues_its_rfq_through_the_loop_and_spends_one_turn() {
        use agentos_app::gate::PolicyGate;
        use agentos_store::sourcing as sourcing_store;

        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;
        let employee = seed_due(&db, tenant, "buyer", Some(workable())).await;
        // The objective's own words are the supplier search key — there is no
        // category vocabulary in this system and `suppliers.categories` is the
        // buyer's search key, so this is the join the operator makes by typing
        // the same phrase twice.
        seed_supplier(
            &db,
            tenant,
            "anodised aluminium enclosures",
            "sales@hamburg.example",
        )
        .await;

        // The buyer's own role limits, as a real tenant layer. The gate reads
        // its policy out of the database now, so a fixture that only built one
        // in memory would have the employee refused before it reached the
        // vertical — which is exactly what this test would then have been
        // proving nothing about.
        //
        // `spend: None`: nothing on this path proposes a payment, and the
        // buyer's pack is denominated in USD while every other fixture here is
        // in EUR. A deployment has one ceiling and therefore one currency, so
        // installing both would make `EffectivePolicy::try_new` refuse the pair
        // and every action in the test come back `broken_policy`.
        agentos_store::policy::install(
            &db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &agentos_domain::policy::PolicyLimits {
                spend: None,
                ..rolepack::RolePack::international_buyer().limits().clone()
            },
        )
        .await
        .expect("install the buyer's limits");

        let cancel = CancellationToken::new();
        let agent = Agent {
            db: db.clone(),
            llm: Arc::new(agentos_app::mocks::scripted_mock()),
            gate: PolicyGate::new(db.clone()),
            ports: Arc::new(agentos_app::mocks::ports()),
            // No binder loop here, so every tenant's fleet is empty and every
            // MCP call is refused by name.
            fleets: crate::routes::mcp::Fleets::new().0,
            cancel: cancel.clone(),
        };
        let take = move |assignment: Assignment| {
            let agent = agent.clone();
            async move { take_turn(agent, assignment).await }
        };

        let claimed = tick(&db, &take, &cancel, Utc::now()).await.expect("tick");
        assert_eq!(claimed, 1);
        assert_eq!(outcome_of(&db, tenant, employee).await.0, "turn");
        assert_eq!(
            emails_sent(&db, tenant, employee).await,
            1,
            "the RFQ never reached a provider through the gate"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let open = sourcing_store::open_rfq(&mut tx, employee)
            .await
            .expect("open rfq");
        let spent = turns::taken_today(&mut tx, employee, Utc::now().date_naive())
            .await
            .expect("taken today");
        tx.rollback().await.expect("rollback");

        let open = open.expect("the employee emailed a supplier and opened no round");
        assert_eq!(open.quantity, 5_000);
        assert_eq!(
            spent, 1,
            "one cadence must cost exactly one turn, vertical or no vertical"
        );

        drop_tenant(&db, tenant).await;
    }

    /// **A provider that answers nothing but errors, run to the end of the
    /// day.**
    ///
    /// Three claims this module makes in prose and nothing here asserted, in one
    /// pass through the real loop:
    ///
    /// * **The daily turn budget is what bounds it.** Nothing else can: there is
    ///   no retry inside `Turn::run`, no attempt counter on this path — the
    ///   schedule is not a queue and `record_outcome` is bookkeeping — and every
    ///   other ceiling in the system is on money or on tool calls *inside* one
    ///   turn, which a turn that never reaches a tool never touches. With a
    ///   budget of two, a model that is down all afternoon costs two calls and
    ///   then nothing.
    /// * **The slot is burned by the failure, and there is no way to get it
    ///   back.** `store::turns` has no release verb precisely so that "fail
    ///   late, release, retry, forever" is unspellable, and this is the shape
    ///   that would ride it. `turns_taken` must move on a turn that failed
    ///   exactly as it moves on one that worked.
    /// * **The failed turn is billed.** `Failed` carries `usage` and `turns` so
    ///   that [`take_turn`] can write them, and a call that reported no tokens
    ///   is recorded **unmetered rather than free** — `Consumed::reported`'s one
    ///   judgement, asserted here at the seam it exists for. A crash-looping
    ///   employee is the case where the calls are most real and the record is
    ///   most likely to be empty.
    ///
    /// `ScriptedLlm::new(vec![])` is the provider: an exhausted script refuses
    /// every call with a terminal error, which is what a bad API key or a
    /// provider outage looks like from inside `Turn::run` — and it needs no
    /// `ProviderError` in scope, which this crate deliberately cannot name.
    #[tokio::test]
    async fn a_provider_that_fails_forever_is_bounded_by_the_day_and_billed_for_it() {
        use agentos_app::gate::PolicyGate;
        use agentos_app::mocks::ScriptedLlm;

        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;
        // Two turns a day, so the bound is reachable inside a test.
        turn_budget(&db, tenant, 2).await;
        let employee = seed_due(&db, tenant, "downstream", Some(workable())).await;

        let cancel = CancellationToken::new();
        let agent = Agent {
            db: db.clone(),
            llm: Arc::new(ScriptedLlm::new(Vec::new())),
            gate: PolicyGate::new(db.clone()),
            ports: Arc::new(agentos_app::mocks::ports()),
            fleets: crate::routes::mcp::Fleets::new().0,
            cancel: cancel.clone(),
        };
        let take = move |assignment: Assignment| {
            let agent = agent.clone();
            async move { take_turn(agent, assignment).await }
        };

        let day = Utc::now().date_naive();
        // Four cadences, two hours apart, **anchored to this UTC midnight**.
        // The clock has to advance past each reschedule or the employee is not
        // due again — the cadence here is hourly — and it has to stay inside one
        // UTC day or the budget resets underneath the test, which is the bug
        // that a bare `Utc::now() + hours(n)` walks into for anyone running the
        // suite after 16:00 UTC. `take_turn` books the ledger against
        // `Utc::now()` rather than the tick's clock, so both have to be today.
        let midnight = day.and_hms_opt(0, 0, 0).expect("midnight").and_utc();
        for round in 1..=4 {
            let now = midnight + chrono::TimeDelta::hours(round * 2);
            assert_eq!(
                tick(&db, &take, &cancel, now).await.expect("tick"),
                1,
                "round {round}: the employee must still be claimed"
            );
        }

        let (outcome, detail, claims) = outcome_of(&db, tenant, employee).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let spent = turns::taken_today(&mut tx, employee, day)
            .await
            .expect("taken today");
        let billed = model_usage::on_day(&mut tx, employee, day)
            .await
            .expect("ledger");
        tx.rollback().await.expect("rollback");

        // Claimed every round — the schedule keeps offering it, which is why
        // the budget has to be the thing that says no.
        assert_eq!(claims, 4, "the schedule stopped offering the employee");
        // ...and the last two rounds never reached the model.
        assert_eq!(
            outcome, "over_budget",
            "a spent budget must refuse rather than call the model again"
        );
        assert!(
            detail.unwrap_or_default().contains("used up"),
            "the operator is not told which ceiling stopped it"
        );

        // Two turns granted, two burned, none handed back by failing.
        assert_eq!(
            spent, 2,
            "a failed turn either did not cost its slot or the slot came back"
        );

        // And both of them are on the bill, as calls nobody metered rather than
        // as calls that cost nothing.
        assert_eq!(billed.calls, 2, "a failed turn was not billed: {billed:?}");
        assert_eq!(billed.calls_unmetered, 2);
        assert_eq!(billed.tokens_measured(), 0);
        assert!(
            !billed.is_complete(),
            "two calls of unknown cost read as a complete bill"
        );

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

    // -- the selling turn, through the loop ---------------------------------

    /// The prospect's own page, and the two things about it that matter: it
    /// says something categorically wrong, and it says the same thing twice.
    ///
    /// A conflation rather than a contradiction, because a contradiction rests
    /// on our own entry-requirements row and this employee's fleet is empty —
    /// no MCP binding, no authority, and the three findings that stand on the
    /// prospect's own page are the ones left. That is the ordinary production
    /// case on Orizn's keyless surface, not a corner of the fixture.
    const PANEL: &str = "No visa required for this trip. Visa on arrival at the airport.";

    /// The prospect's flow, its selectors, and the account they hang off.
    const PROSPECT_DOMAIN: &str = "book.airline.example";
    const PANEL_SELECTOR: &str = "#visa-info";

    /// A sales objective an operator really would state, complete.
    fn selling() -> Charter {
        Charter::Sales {
            pack: rolepack_sales::RolePack::sales_development(),
            objective: rolepack_sales::Objective {
                segment: rolepack_sales::Segment::Airline,
                market: Some(CountryCode::parse("FR").expect("country")),
                target_accounts: vec!["Airline Example".to_owned()],
            },
        }
    }

    /// One imported prospect with a flow described for it — the two rows the
    /// import lands and the one a human writes.
    async fn seed_prospect(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        // `accounts.domain` is unique per tenant, and it is also the host the
        // gate rules on, so two prospects in one test are two domains.
        domain: &str,
        email: &str,
    ) -> Uuid {
        use agentos_store::revenue as revenue_store;

        let account = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        revenue_store::insert_account(
            &mut tx,
            account,
            &revenue_store::NewAccount {
                legal_name: "Airline Example",
                domain,
                segment: "airline",
                country: "FR",
                location: None,
                website: None,
                employee_id: Some(employee),
            },
        )
        .await
        .expect("insert account");
        revenue_store::insert_contact(
            &mut tx,
            Uuid::now_v7(),
            &revenue_store::NewContact {
                account_id: account,
                full_name: "Head of Digital",
                email: Some(email),
                phone: None,
                role: Some("Head of Digital"),
                language: Some("fr"),
                is_primary: true,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: None,
            },
        )
        .await
        .expect("insert contact");
        sqlx::query(
            "INSERT INTO prospect_flows \
                 (tenant_id, account_id, entry, passport_field, destination_field, date_field, \
                  submit, panel) \
             VALUES ($1, $2, $3, '#passport', '#destination', '#travel-date', '#check', $4)",
        )
        .bind(tenant.as_uuid())
        .bind(account)
        .bind(format!("https://{domain}/entry"))
        .bind(PANEL_SELECTOR)
        .execute(&mut **tx)
        .await
        .expect("insert flow");
        tx.commit().await.expect("commit the prospect");
        account
    }

    /// Everything the sales path needs granted, as a tenant layer: the
    /// prospect's domain to browse, email to send on, and an outreach budget
    /// that is not zero.
    ///
    /// `max_new_contacts_per_day` is the one value that differs from the shipped
    /// `sales_development()` pack, which ships it at **0** on purpose. Raising it
    /// is a deliberate act by an operator who can answer for the lawful basis,
    /// and here it is the difference between testing the send path and testing
    /// the refusal — `the_contact_budget_and_the_suppression_list_both_bite`
    /// next door tests the other side.
    async fn sales_limits(db: &Db, tenant: TenantId, contacts_per_day: u32) {
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                spend: None,
                max_turns_per_day: 100,
                max_new_contacts_per_day: contacts_per_day,
                allowed_domains: [
                    agentos_domain::action::Domain::parse(PROSPECT_DOMAIN).expect("domain")
                ]
                .into_iter()
                .collect(),
                allowed_channels: [agentos_domain::message::Channel::Email]
                    .into_iter()
                    .collect(),
                allowed_models: ModelId::ALL.into_iter().collect(),
                ..rolepack_sales::RolePack::sales_development()
                    .limits()
                    .clone()
            },
        )
        .await
        .expect("install the seller's limits");
    }

    /// The agent the loop runs a seller with: a scripted model, and a browser
    /// whose one page is [`PANEL`].
    fn selling_agent(
        db: &Db,
        cancel: &CancellationToken,
    ) -> (Agent, Arc<agentos_app::mocks::MockBrowser>) {
        use agentos_app::gate::PolicyGate;

        let browser = Arc::new(agentos_app::mocks::MockBrowser::new());
        // One entry, repeating: the same page to both runs of the probe, which
        // is what the evidence bar is looking for.
        browser.set_text(PANEL_SELECTOR, &[PANEL]);
        let ports = agentos_app::effects::Ports {
            browser: browser.clone(),
            ..agentos_app::mocks::ports()
        };
        (
            Agent {
                db: db.clone(),
                llm: Arc::new(agentos_app::mocks::scripted_mock()),
                gate: PolicyGate::new(db.clone()),
                ports: Arc::new(ports),
                // No binder loop, so the fleet is empty and the Orizn lookup is
                // refused by name. See `PANEL`.
                fleets: crate::routes::mcp::Fleets::new().0,
                cancel: cancel.clone(),
            },
            browser,
        )
    }

    /// Findings filed against one account, by kind.
    async fn findings(db: &Db, tenant: TenantId, account: Uuid) -> Vec<String> {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let filed = agentos_store::revenue::evidence_for_account(&mut tx, account, 10)
            .await
            .expect("read the evidence");
        tx.rollback().await.expect("rollback");
        filed.into_iter().map(|finding| finding.kind).collect()
    }

    /// **The whole sales seam, through the real path.**
    ///
    /// The twin of `a_due_buyer_issues_its_rfq_through_the_loop_and_spends_one_turn`,
    /// and it is the test this unit exists for: until it passed,
    /// `vertical_step` answered a sales charter with `return None` and the
    /// entire vertical — `sell`, the prober, the evidence bar, Orizn — was
    /// reachable only from its own tests.
    ///
    /// A chartered seller whose cadence comes due reaches `take_turn`, the
    /// vertical runs **before** the model, the prospect's own flow is run twice,
    /// the approach goes out through the gate, and the finding lands in a row a
    /// human can read. And the budget is spent once: an employee that probes a
    /// site and emails somebody and then thinks about it has taken one turn.
    #[tokio::test]
    async fn a_due_seller_files_a_finding_through_the_loop_and_spends_one_turn() {
        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;
        let employee = seed_due(&db, tenant, "seller", Some(selling())).await;
        let account = seed_prospect(
            &db,
            tenant,
            employee,
            PROSPECT_DOMAIN,
            "head.of.digital@airline.example",
        )
        .await;
        sales_limits(&db, tenant, 5).await;

        let cancel = CancellationToken::new();
        let (agent, browser) = selling_agent(&db, &cancel);
        let take = move |assignment: Assignment| {
            let agent = agent.clone();
            async move { take_turn(agent, assignment).await }
        };

        let claimed = tick(&db, &take, &cancel, Utc::now()).await.expect("tick");
        assert_eq!(claimed, 1);
        assert_eq!(outcome_of(&db, tenant, employee).await.0, "turn");

        assert_eq!(
            findings(&db, tenant, account).await,
            vec!["wrong_requirement".to_owned()],
            "the finding never reached a row a human reads"
        );
        assert_eq!(
            emails_sent(&db, tenant, employee).await,
            1,
            "the approach never reached a provider through the gate"
        );
        // Twice, which is the bar rather than a retry: two identical reads of
        // the panel, and a screenshot only after they agreed.
        assert_eq!(
            browser
                .log()
                .iter()
                .filter(|line| line.contains(&format!("text {PANEL_SELECTOR}")))
                .count(),
            2,
            "the flow was not run twice: {:?}",
            browser.log()
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let spent = turns::taken_today(&mut tx, employee, Utc::now().date_naive())
            .await
            .expect("taken today");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            spent, 1,
            "one cadence must cost exactly one turn, vertical or no vertical"
        );

        drop_tenant(&db, tenant).await;
    }

    /// **A seller with nothing to work spends no turn.**
    ///
    /// Two ways to have nothing, and they are the two an operator will actually
    /// hit: no prospects imported at all, and prospects imported that nobody has
    /// described a booking flow for. Both are `no_work` — a recorded outcome, a
    /// question-free status line, and **no reservation** — because a seller
    /// whose whole vertical is "run one prospect's flow" and has no prospect has
    /// nothing to spend a model call on. A turn taken anyway is a transcript
    /// that reads like a day's work with nothing behind it.
    #[tokio::test]
    async fn a_seller_with_nothing_due_takes_no_turn_and_reserves_none() {
        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;
        let employee = seed_due(&db, tenant, "idle-seller", Some(selling())).await;
        sales_limits(&db, tenant, 5).await;

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

        // Nothing imported.
        assert_eq!(
            tick(&db, &take, &cancel, Utc::now()).await.expect("tick"),
            1
        );
        let (outcome, detail, _) = outcome_of(&db, tenant, employee).await;
        assert_eq!(outcome, "no_work");
        assert!(
            detail.unwrap_or_default().contains("booking flow"),
            "the operator is not told what would give this employee work"
        );

        // Imported, and undescribed. `seed_prospect` writes the flow row too, so
        // this is the account and the contact without it.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let account = Uuid::now_v7();
        agentos_store::revenue::insert_account(
            &mut tx,
            account,
            &agentos_store::revenue::NewAccount {
                legal_name: "Undescribed Airline",
                domain: "undescribed.example",
                segment: "airline",
                country: "FR",
                location: None,
                website: None,
                employee_id: Some(employee),
            },
        )
        .await
        .expect("insert account");
        agentos_store::revenue::insert_contact(
            &mut tx,
            Uuid::now_v7(),
            &agentos_store::revenue::NewContact {
                account_id: account,
                full_name: "Somebody",
                email: Some("somebody@undescribed.example"),
                phone: None,
                role: None,
                language: None,
                is_primary: true,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: None,
            },
        )
        .await
        .expect("insert contact");
        tx.commit().await.expect("commit");

        // Due again on the next cadence, and still nothing to do.
        let later = Utc::now() + chrono::TimeDelta::hours(2);
        assert_eq!(tick(&db, &take, &cancel, later).await.expect("tick"), 1);
        assert_eq!(outcome_of(&db, tenant, employee).await.0, "no_work");

        assert_eq!(
            started.load(Ordering::SeqCst),
            0,
            "a seller with nothing to work started a turn"
        );

        // The whole point: no model call, and no reservation either. A budget
        // spent on nothing is a budget the employee does not have on the day it
        // has something.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let spent = turns::taken_today(&mut tx, employee, Utc::now().date_naive())
            .await
            .expect("taken today");
        tx.rollback().await.expect("rollback");
        assert_eq!(spent, 0, "a turn with no work reserved one anyway");

        drop_tenant(&db, tenant).await;
    }

    /// **The two legal boundaries, on the dispatch that reaches them.**
    ///
    /// `sales_development()` ships `max_new_contacts_per_day: 0` — cold outreach
    /// off until an operator turns it on — so the first half is the shipped
    /// configuration and not a contrived one: the check still runs, the finding
    /// is still filed, and **no email leaves the building**.
    ///
    /// The second half is the hole this dispatch would have opened.
    /// `Seller::new` takes a suppression list and every caller in the workspace
    /// used to pass an empty one, which was survivable exactly as long as
    /// nothing reached `Seller::touch`. This is the caller that reaches it.
    #[tokio::test]
    async fn the_contact_budget_and_the_suppression_list_both_bite_on_this_path() {
        use agentos_store::revenue as revenue_store;

        let Some(db) = db().await else { return };
        let _guard = LOOP_LOCK.lock().await;
        clear_schedules(&db).await;
        let tenant = seed_tenant(&db).await;
        let employee = seed_due(&db, tenant, "broke-seller", Some(selling())).await;
        let account = seed_prospect(
            &db,
            tenant,
            employee,
            PROSPECT_DOMAIN,
            "head.of.digital@airline.example",
        )
        .await;
        // The pack's own default, spelled out.
        sales_limits(&db, tenant, 0).await;

        let cancel = CancellationToken::new();
        let (agent, _browser) = selling_agent(&db, &cancel);
        let take = move |assignment: Assignment| {
            let agent = agent.clone();
            async move { take_turn(agent, assignment).await }
        };

        assert_eq!(
            tick(&db, &take, &cancel, Utc::now()).await.expect("tick"),
            1
        );
        assert_eq!(outcome_of(&db, tenant, employee).await.0, "turn");
        assert_eq!(
            findings(&db, tenant, account).await.len(),
            1,
            "the budget stopped the work as well as the approach"
        );
        assert_eq!(
            emails_sent(&db, tenant, employee).await,
            0,
            "the contact budget is zero and a stranger was mailed anyway"
        );

        // And the suppression list, on a prospect nothing else stops. A second
        // employee, because the first one's account now has evidence and has
        // left the queue.
        let seller = seed_due(&db, tenant, "seller-two", Some(selling())).await;
        let opted_out = "opted.out@airline.example";
        let second = seed_prospect(&db, tenant, seller, "book.other.example", opted_out).await;
        sales_limits(&db, tenant, 5).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        revenue_store::suppress(
            &mut tx,
            Uuid::now_v7(),
            &revenue_store::NewSuppression {
                channel: revenue_store::Channel::Email,
                address: opted_out,
                reason: "opt_out",
                scope: revenue_store::Scope::Tenant,
                contact_id: None,
                note: Some("replied STOP"),
                suppressed_at: Utc::now(),
            },
        )
        .await
        .expect("record the opt-out");
        tx.commit().await.expect("commit the opt-out");

        // Two: the first seller's hourly cadence has come round again as well,
        // and it now has nothing to work — its account has evidence.
        let later = Utc::now() + chrono::TimeDelta::hours(2);
        assert_eq!(tick(&db, &take, &cancel, later).await.expect("tick"), 2);
        assert_eq!(outcome_of(&db, tenant, employee).await.0, "no_work");
        // Nothing to work: the only prospect in this segment either has
        // evidence already or has opted out, and neither is an error.
        assert_eq!(outcome_of(&db, tenant, seller).await.0, "no_work");
        assert_eq!(
            emails_sent(&db, tenant, seller).await,
            0,
            "a person who opted out was written to"
        );
        assert!(
            findings(&db, tenant, second).await.is_empty(),
            "a person who opted out had their site probed"
        );

        drop_tenant(&db, tenant).await;
    }
}
