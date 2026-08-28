//! The Policy Gate, and the capability token that proves it ran.
//!
//! `domain::policy::evaluate` is the *rule*; this module is the *gate*. It is
//! the only place in the workspace that mints an [`Authorized<A>`], and
//! [`crate::effects`] accepts nothing else. So the question "did this code path
//! check permissions?" is answered by the type checker rather than by a
//! reviewer who is having a bad afternoon — the last review missed a
//! `_ => Allow` arm and an employee could sign contracts.
//!
//! # What makes the token unforgeable
//!
//! [`Authorized`] has no public constructor, no `From`, no `Default`, no
//! `Deserialize`, and no public field. It also carries a [`seal::Seal`], a
//! zero-sized type in a private module: even a future edit that makes a field
//! `pub` cannot make the struct constructible from outside, because the seal
//! is not nameable there. `tests/ui/gate_*.rs` proves this with real compiler
//! errors, and that negative test *is* this unit — every other test here is
//! about the gate being right, that one is about it being unbypassable.
//!
//! # The order of operations, and why it is that order
//!
//! 0. **The company before the seat.** If a human has stopped the whole
//!    company ([`agentos_store::halt`]), nothing is authorised and no policy is
//!    read. This is the same rule as (1) one level up, and it is read *here*
//!    rather than at the start of a turn for the reason that makes it worth
//!    anything: a turn is up to ten model calls and twenty effects long, so a
//!    flag checked when the turn woke can still pay an invoice half a minute
//!    after somebody said stop. Read at the door, it cannot — the mint of an
//!    [`Authorized`] and the provider call that spends it are adjacent awaits
//!    (`crate::turn`'s `gated!`), so a halt that commits before the ruling
//!    refuses the ruling, and one that commits after has, at worst, one
//!    already-dispatched HTTP request to outlive.
//! 1. **Lifecycle before policy.** A suspended employee is refused before any
//!    policy is read. A suspension implemented as "remove its permissions"
//!    leaves behind exactly the permissions nobody remembered to remove.
//! 2. **Context from real state.** The policy itself, spend already reserved
//!    today, contacts first reached today, who this employee answers to on the
//!    org chart, the trust label of the input that produced the action — read
//!    from the database inside the same transaction, never taken from the
//!    caller and never from model output.
//!    The policy is [`agentos_store::policy::load`]: platform ∧ tenant ∧ role ∧
//!    employee, four rows, one indexed query, read *here* rather than handed to
//!    the gate at construction. Inside the transaction because the ruling and
//!    the reservation below must be made against the same policy — a load
//!    outside it lets an operator's change land between the two, so the gate
//!    would allow a payment under yesterday's cap and reserve it under today's.
//!    A deployment with no platform layer has no ceiling to enforce, and the
//!    gate refuses every action until an operator installs one. That is
//!    deliberate: the alternative is a misconfigured deployment that is
//!    silently permissive.
//! 3. **Exactly one audit row for every outcome.** Allow, deny and
//!    approval-required alike. A gate that only records denials cannot answer
//!    "why was this payment allowed?", which is the only question anybody ever
//!    asks after the fact.
//! 4. **Allowing a payment reserves it.** In the same transaction, against the
//!    same day's bucket — and against the team's, through
//!    [`agentos_store::org::reserve`], which is where a per-team budget stops
//!    being a number somebody wrote down. Checking a cap without consuming it
//!    is what lets an agent turn one refused payment into ten accepted ones.
//!
//! # Seniority is context, never policy
//!
//! One action has an employee as its subject: [`Action::CharterSet`], a head
//! setting a subordinate's objective. The fact that makes it legal — *does this
//! employee report to that one* — is read here, from `team_memberships`, and
//! travels in [`ActionCtx::directs_subject`] alongside the ledger and the
//! contact book. It is context, not policy, and the distinction is the safety
//! property:
//!
//! * the policy is `platform ∧ tenant ∧ role ∧ employee`, four rows, and
//!   [`agentos_store::policy::load`] does not join the reporting line — so
//!   acquiring a report cannot change one number in an `EffectivePolicy`;
//! * the reporting line is consulted by exactly one arm of
//!   [`agentos_domain::policy::evaluate`], the one that decides whether *this
//!   named employee's* charter may be written, and by nothing else;
//! * a head's own limits still gate everything a head does. Being senior to the
//!   Head of Sales does not hand the CTO's tools to anybody, because there is
//!   no code path from a manager's id to a tool allowlist.
//!
//! So "senior" here means *may direct these people*, and can never come to mean
//! *may do more things*. `crates/domain/src/policy.rs` asserts it directly, and
//! `crates/app/src/vertical.rs` asserts it end to end against a real policy.
//!
//! # Trust
//!
//! The taint travels with the *type* of the action, not with a flag somebody
//! passes: [`Authorizable`] is implemented for [`Action`] (trusted — a human
//! wrote that call site) and for `Untrusted<Action>` (untrusted — it came from
//! a document, a web page or a model). `evaluate` refuses to allow a high-risk
//! action derived from untrusted input, so a supplier PDF saying "wire
//! $10,000" cannot produce an `Authorized<_>` at all.

use agentos_domain::action::{Action, ActionCtx, Actor, ContactStanding};
use agentos_domain::employee::Lifecycle;
use agentos_domain::ids::{ApprovalId, DecisionId, EmployeeId, TenantId};
use agentos_domain::money::{Currency, Money};
use agentos_domain::policy::{Decision, DenyReason, SpendLimits, evaluate, spends_contact_budget};
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_store::approvals::{self, ApprovalError, NewApproval};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::halt;
use agentos_store::org::{self, TeamSpendRefused};
use agentos_store::outreach::{self, ContactBudgetError};
use agentos_store::policy::{self as policy_store, PolicyLoadError};
use agentos_store::spend::{CapExceeded, Reservation};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Map, Value, json};

/// How long a requested approval stays redeemable.
///
/// ponytail: one constant, not a policy field. An approval that outlives the
/// working day it was requested in is a standing authorisation nobody
/// remembers granting. Make it configurable the day an operator asks, not
/// before.
const APPROVAL_TTL: TimeDelta = TimeDelta::hours(24);

/// The role a human must hold to redeem an approval this gate files.
///
/// Stored on the approval for the approval UI to enforce; this crate has no
/// notion of who is clicking. ponytail: constant until roles exist.
const APPROVER_ROLE: &str = "approver";

/// Audit payload key holding the counterparty an action addresses. Read back
/// by [`PolicyGate::contacts`] to derive the cold-outreach budget, so the two
/// must use the same spelling — hence the constant.
const COUNTERPARTY_KEY: &str = "counterparty";

/// Audit payload key naming a refusal that has no [`DenyReason`].
const DENIED_KEY: &str = "denied";

// ---------------------------------------------------------------------------
// The seal
// ---------------------------------------------------------------------------

mod seal {
    /// Zero-sized proof that a value was minted by the gate.
    ///
    /// The module is private and the tuple field is private, so `Seal` cannot
    /// be named — let alone constructed — anywhere but `gate.rs`.
    #[derive(Debug)]
    pub struct Seal(());

    impl Seal {
        pub(super) const fn new() -> Self {
            Self(())
        }
    }
}

// ---------------------------------------------------------------------------
// Authorized
// ---------------------------------------------------------------------------

/// An action the Policy Gate has ruled on and permitted.
///
/// The only way to obtain one is [`PolicyGate::authorize`] or
/// [`PolicyGate::redeem_approval`]. Hold one and you may perform the effect;
/// there is no other proof and no way to fabricate this one.
#[derive(Debug)]
pub struct Authorized<A> {
    action: A,
    decision_id: DecisionId,
    reservation: Option<Reservation>,
    _seal: seal::Seal,
}

impl<A> Authorized<A> {
    /// The action that was permitted.
    pub const fn action(&self) -> &A {
        &self.action
    }

    /// The recorded decision. Matches the `decision_id` on the audit row, so
    /// an executed effect can always be traced back to the ruling that let it
    /// happen.
    pub const fn decision_id(&self) -> DecisionId {
        self.decision_id
    }

    /// The spend headroom consumed by this authorization, for payments.
    ///
    /// The executor owes it an [`agentos_store::spend::settle`] on success or
    /// an [`org::release`] on failure; nothing here does that for it, because
    /// only the caller knows whether the money moved. `org::release` rather
    /// than `spend::release`, for the same reason the reservation was taken
    /// through [`org::reserve`]: the team's headroom has to come back too.
    pub const fn reservation(&self) -> Option<&Reservation> {
        self.reservation.as_ref()
    }

    /// Consume the token and take the action out.
    pub fn into_action(self) -> A {
        self.action
    }
}

// ---------------------------------------------------------------------------
// What can be authorized
// ---------------------------------------------------------------------------

/// A thing the gate can rule on: an [`Action`] plus the provenance of the
/// input that produced it.
///
/// Provenance is a property of the *type*, not an argument, so it cannot be
/// mis-declared at a call site. Untrusted text produces `Untrusted<Action>`
/// and there is no safe conversion back.
pub trait Authorizable {
    /// The action, as the domain evaluator sees it.
    fn to_action(&self) -> Action;

    /// Where the input that produced this action came from.
    fn trust(&self) -> TrustLabel;
}

impl Authorizable for Action {
    fn to_action(&self) -> Action {
        self.clone()
    }

    /// Trusted: an `Action` value written by our own code, from our own
    /// configuration or from an operator's authenticated request.
    fn trust(&self) -> TrustLabel {
        TrustLabel::Trusted
    }
}

impl Authorizable for Untrusted<Action> {
    fn to_action(&self) -> Action {
        // Parsing, not rendering: the gate inspects the action, it does not
        // splice it into a prompt.
        self.expose_for_parsing().clone()
    }

    fn trust(&self) -> TrustLabel {
        self.taint()
    }
}

// ---------------------------------------------------------------------------
// Principal
// ---------------------------------------------------------------------------

/// The acting identity.
///
/// Established by the caller from an authenticated credential — an API key, a
/// session — and **never** from a request body. Deliberately not
/// `Deserialize`: if it could be parsed from JSON it would eventually be
/// parsed from a request body, and then anyone could act as anyone.
#[derive(Debug, Clone)]
pub struct Principal {
    /// The tenant every query in the decision runs under.
    pub tenant_id: TenantId,
    /// The employee the effect is attributed to.
    pub employee_id: EmployeeId,
    /// Who is really driving: the employee itself, or a human on its behalf.
    pub actor: AuditActor,
}

impl Principal {
    /// The employee acting on its own initiative.
    pub const fn employee(tenant_id: TenantId, employee_id: EmployeeId) -> Self {
        Self {
            tenant_id,
            employee_id,
            actor: AuditActor::Employee(employee_id),
        }
    }

    /// A human acting through the employee.
    pub fn operator(tenant_id: TenantId, employee_id: EmployeeId, who: impl Into<String>) -> Self {
        Self {
            tenant_id,
            employee_id,
            actor: AuditActor::Operator(who.into()),
        }
    }

    fn action_actor(&self) -> Actor {
        Actor::new(self.tenant_id, self.employee_id)
    }
}

// ---------------------------------------------------------------------------
// Denied
// ---------------------------------------------------------------------------

/// Why an approval could not be spent. Distinct from a policy denial: the
/// policy already said yes, subject to a human, and something about the
/// redemption itself was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedemptionFailure {
    /// **The interesting one.** A different action was presented at execution
    /// time from the one the human approved.
    ActionMismatch,
    /// The nonce does not belong to this approval.
    BadNonce,
    /// Already redeemed, or already refused.
    AlreadyDecided,
    /// Past its deadline.
    Expired,
    /// No such approval in this tenant.
    NotFound,
}

impl RedemptionFailure {
    /// Stable, low-cardinality metric label.
    pub const fn code(self) -> &'static str {
        match self {
            RedemptionFailure::ActionMismatch => "approval_action_mismatch",
            RedemptionFailure::BadNonce => "approval_bad_nonce",
            RedemptionFailure::AlreadyDecided => "approval_already_decided",
            RedemptionFailure::Expired => "approval_expired",
            RedemptionFailure::NotFound => "approval_not_found",
        }
    }
}

/// The gate's refusal.
///
/// Every variant is a code or an id — never a free-form string — because these
/// become metric labels and alert rules, and a message someone reworded is a
/// dashboard that silently stops counting.
#[derive(Debug, thiserror::Error)]
pub enum Denied {
    /// A human has stopped the whole company. Refused before the employee is
    /// even looked up, let alone its policy read.
    ///
    /// Carries the reason the operator gave, because this refusal is the one
    /// somebody will be reading out loud while a customer is on the phone, and
    /// "denied" without "because your CFO called us at 14:02" is a support
    /// ticket. It is an operator's own sentence, never a model's, and never a
    /// counterparty's: `routes::halt` takes it from an authenticated request
    /// body and nothing else writes the row.
    #[error("the company is stopped: {0}")]
    Halted(String),

    /// The employee is not [`Lifecycle::Active`]. Refused before any policy is
    /// consulted.
    #[error("employee is {0}, not active")]
    NotActive(Lifecycle),

    /// No such employee in this tenant.
    #[error("no such employee")]
    UnknownEmployee,

    /// The policy evaluator said no.
    #[error("denied: {}", .0.code())]
    Policy(DenyReason),

    /// A human has to sign off. The approval has been filed; its nonce went to
    /// the approval UI, never to the caller.
    #[error("awaiting approval {0}")]
    PendingApproval(ApprovalId),

    /// An approval was presented and refused.
    #[error("approval refused: {}", .0.code())]
    Redemption(RedemptionFailure),

    /// The stored policy could not be turned into an enforceable one: no
    /// platform ceiling, a column the domain cannot represent, layers that do
    /// not intersect. Fails closed — a policy nobody can evaluate authorises
    /// nothing — and deliberately *not* a fallback to some in-memory default,
    /// which is how a misconfigured deployment becomes a permissive one.
    #[error("the stored policy is unusable: {0}")]
    BrokenPolicy(PolicyLoadError),

    /// The gate could not reach a verdict — the database was unavailable, or a
    /// row was not what the schema promised. Not a denial of *this* action so
    /// much as a refusal to guess.
    #[error(transparent)]
    Unavailable(StoreError),
}

impl Denied {
    /// Stable, low-cardinality metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            Denied::Halted(_) => audit::COMPANY_HALTED,
            Denied::NotActive(_) => "employee_not_active",
            Denied::UnknownEmployee => "unknown_employee",
            Denied::Policy(reason) => reason.code(),
            Denied::PendingApproval(_) => "pending_approval",
            Denied::Redemption(failure) => failure.code(),
            Denied::BrokenPolicy(err) => broken_code(err),
            Denied::Unavailable(_) => "unavailable",
        }
    }
}

/// Stable, low-cardinality label for a policy that would not load.
///
/// A missing ceiling gets its own code because it is a different problem with a
/// different fix: not "somebody wrote a policy wrong" but "nobody installed
/// one", and it refuses every action for every tenant in the deployment until
/// they do. That is a page, not a dashboard line, and it cannot be one if it
/// shares a label with a malformed row.
const fn broken_code(err: &PolicyLoadError) -> &'static str {
    match err {
        PolicyLoadError::NoPlatformLayer => "no_platform_policy",
        _ => "broken_policy",
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// The one door every side effect goes through.
///
/// A database and nothing else. There is no policy field: the four layers are
/// rows, and they are read per decision inside the decision's own transaction —
/// see the module docs. A gate that held a policy would be a gate an operator
/// could not change without a redeploy, which is what this used to be.
#[derive(Debug, Clone)]
pub struct PolicyGate {
    db: Db,
}

/// What the decision came to, before it is turned into an audit row and a
/// return value. Kept separate so there is exactly one place that writes the
/// audit row — a second `append` call site is how "every outcome is audited"
/// decays into "most outcomes are audited".
#[derive(Debug)]
enum Outcome {
    Allow {
        reservation: Option<Reservation>,
    },
    Deny(DenyReason),
    /// The whole company is stopped. Carries the operator's reason so the audit
    /// row and the refusal say the same sentence.
    Halted(String),
    Approval {
        id: ApprovalId,
        decision: Decision,
    },
    NotActive(Lifecycle),
    UnknownEmployee,
    BrokenPolicy(PolicyLoadError),
    Redemption(RedemptionFailure),
}

impl PolicyGate {
    /// Wire the gate to a database. The policy comes out of it, per decision.
    pub const fn new(db: Db) -> Self {
        Self { db }
    }

    /// Rule on one action.
    ///
    /// One transaction: lifecycle check, context assembly, evaluation, the
    /// approval record or the spend reservation, and the audit row all commit
    /// together or not at all.
    pub async fn authorize<A: Authorizable>(
        &self,
        principal: &Principal,
        action: A,
    ) -> Result<Authorized<A>, Denied> {
        let now = Utc::now();
        let subject = action.to_action();
        let mut tx = self
            .db
            .tenant_tx(principal.tenant_id)
            .await
            .map_err(Denied::Unavailable)?;

        // `?` here drops the transaction unaudited, which is correct: the only
        // error `decide` returns is "no verdict was reached", and a gate that
        // logged a decision it never made would be worse than one that logged
        // nothing.
        let outcome = self
            .decide(&mut tx, principal, &subject, action.trust(), now)
            .await?;

        self.finish(tx, principal, &subject, action, outcome, now, Map::new())
            .await
    }

    /// Spend a human approval on the action that is about to execute.
    ///
    /// `action` is what the executor is *actually* about to do. It is re-hashed
    /// here and compared against the hash the human approved, so an approved
    /// action cannot be swapped for a different one between the click and the
    /// call.
    ///
    /// The policy is deliberately not re-evaluated: it already said "ask a
    /// human", and asking it again would only ask again. The things that *are*
    /// re-checked are the ones a human decision cannot substitute for, and
    /// there are **three**: the company has not been stopped, the employee is
    /// still active, and the ledger still has the headroom. The halt is the one
    /// this sentence used to miss — it was written before `waveJ-j2` put the
    /// arm below in, and the item it left out is the one with the widest blast
    /// radius. A list in a doc comment is a list that has to be re-counted
    /// every time the code below it grows an arm.
    pub async fn redeem_approval<A: Authorizable>(
        &self,
        principal: &Principal,
        approval_id: ApprovalId,
        nonce: &str,
        action: A,
    ) -> Result<Authorized<A>, Denied> {
        let now = Utc::now();
        let subject = action.to_action();
        let mut tx = self
            .db
            .tenant_tx(principal.tenant_id)
            .await
            .map_err(Denied::Unavailable)?;

        let mut extra = Map::new();
        extra.insert(
            "approval_id".to_owned(),
            json!(approval_id.as_uuid().to_string()),
        );

        // The company, before the seat and before the human's click is spent.
        //
        // **This is the arm that makes a halt mean anything at all.** A pending
        // approval is a permission a policy already granted, parked until a
        // person presses a button — so an approval filed at 09:00 is a live
        // effect somebody can still release at 14:03, one minute after the
        // company was stopped, without any code in `decide` ever running. The
        // approval survives: it is refused, not consumed, and the same nonce
        // works the moment the halt is lifted. Refusing here rather than
        // burning it is deliberate — a halt that quietly destroyed every
        // pending approval would make the release the expensive half of the
        // switch.
        let outcome = match halt::halted(&mut tx).await.map_err(Denied::Unavailable)? {
            Some(halt) => Outcome::Halted(halt.reason),
            None => match self.lifecycle(&mut tx, principal).await? {
                Some(Lifecycle::Active) => {
                    self.redeem(&mut tx, principal, approval_id, nonce, &subject, now)
                        .await?
                }
                Some(other) => Outcome::NotActive(other),
                None => Outcome::UnknownEmployee,
            },
        };

        self.finish(tx, principal, &subject, action, outcome, now, extra)
            .await
    }

    /// Write the single audit row, commit, and turn the outcome into a token
    /// or a refusal.
    #[allow(clippy::too_many_arguments)]
    async fn finish<A>(
        &self,
        mut tx: TenantTx<'_>,
        principal: &Principal,
        subject: &Action,
        action: A,
        outcome: Outcome,
        now: DateTime<Utc>,
        extra: Map<String, Value>,
    ) -> Result<Authorized<A>, Denied> {
        let decision_id = DecisionId::new_v7(now);
        let event = audit_event(principal, subject, decision_id, &outcome, now, extra);
        audit::append(&mut tx, &event)
            .await
            .map_err(Denied::Unavailable)?;
        tx.commit().await.map_err(Denied::Unavailable)?;

        match outcome {
            Outcome::Allow { reservation } => Ok(Authorized {
                action,
                decision_id,
                reservation,
                _seal: seal::Seal::new(),
            }),
            Outcome::Deny(reason) => Err(Denied::Policy(reason)),
            Outcome::Halted(reason) => Err(Denied::Halted(reason)),
            Outcome::Approval { id, .. } => Err(Denied::PendingApproval(id)),
            Outcome::NotActive(lifecycle) => Err(Denied::NotActive(lifecycle)),
            Outcome::UnknownEmployee => Err(Denied::UnknownEmployee),
            Outcome::BrokenPolicy(err) => Err(Denied::BrokenPolicy(err)),
            Outcome::Redemption(failure) => Err(Denied::Redemption(failure)),
        }
    }

    /// Everything up to (but not including) the audit row.
    ///
    /// `Err` here means *no verdict was reached* — only infrastructure
    /// failures take that path.
    async fn decide(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        action: &Action,
        trust: TrustLabel,
        now: DateTime<Utc>,
    ) -> Result<Outcome, Denied> {
        // 0. The company, before anything at all. One row by primary key, in
        //    this transaction, with no cache between the switch and the ruling
        //    — so the promise a customer is given is "the next decision", and
        //    "the next decision" is a number of seconds rather than a cache
        //    lifetime.
        //
        //    Read through `tx`, which is pinned to this tenant, so row-level
        //    security is what guarantees one company cannot stop another: the
        //    only row this statement can see is its own tenant's, whatever the
        //    query says. `crates/app/src/gate.rs`'s
        //    `one_company_s_halt_does_not_touch_another_s` is that claim
        //    against a real database.
        if let Some(halt) = halt::halted(tx).await.map_err(Denied::Unavailable)? {
            return Ok(Outcome::Halted(halt.reason));
        }

        // 1. Lifecycle, before anything else is read. A suspended employee
        //    must not be able to act through a permission somebody forgot to
        //    revoke.
        match self.lifecycle(tx, principal).await? {
            Some(Lifecycle::Active) => {}
            Some(other) => return Ok(Outcome::NotActive(other)),
            None => return Ok(Outcome::UnknownEmployee),
        }

        // 2. The intersected policy, out of the database, inside this
        //    transaction — so the rule below and the reservation after it are
        //    the same policy even if an operator changes one between them.
        //
        //    No role to pass: `store::policy::load` resolves the role layer
        //    through the employee's team, full stop. It used to take a fallback
        //    role for an employee on no team, and this call site passed `None`
        //    because there is no role on a `Principal` and inventing one here
        //    would be a second way to answer a question the org chart already
        //    answers. Every other call site said `None` for the same reason, so
        //    the argument went. Same call, same reasoning as the turn-budget
        //    reservation in `loops::initiative`.
        let policy = match policy_store::load(tx, principal.employee_id).await {
            Ok(policy) => policy,
            // A database that cannot answer is not a verdict — same treatment
            // as any other read here, and the transaction is dropped unaudited.
            Err(PolicyLoadError::Store(err)) => return Err(Denied::Unavailable(err)),
            // A policy that is missing or unusable *is* a verdict, and a loud
            // one: every action for this tenant is refused until it is fixed,
            // so it is logged at error, coded for an alert, and audited like
            // every other outcome.
            Err(err) => {
                tracing::error!(
                    tenant_id = %principal.tenant_id.as_uuid(),
                    employee_id = %principal.employee_id.as_uuid(),
                    code = broken_code(&err),
                    error = %err,
                    "the stored policy could not be loaded; refusing the action"
                );
                return Ok(Outcome::BrokenPolicy(err));
            }
        };

        // 3. Context, from state, inside this transaction. Each read is asked
        //    only for the actions whose arm of `evaluate` can use the answer —
        //    the ledger for a payment, the roster for a charter, and now the
        //    trail for the four channel sends, which is the same predicate
        //    `take_contact` charges on.
        let (new_contacts_today, contact) = if spends_contact_budget(action) {
            self.contacts(tx, principal, action, now).await?
        } else {
            // The *refusing* value, not the free one. `channel_rules` denies on
            // `New && new_contacts_today >= max`, so if `spends_contact_budget`
            // ever drifts from `evaluate` this fails closed and loudly instead
            // of handing an unmeasured arm a budget it never spent.
            (u32::MAX, ContactStanding::New)
        };
        let spent_today = match action {
            Action::PaymentCreate { amount } => {
                self.spent_today(tx, principal, amount.currency(), now)
                    .await?
            }
            _ => None,
        };
        // The org chart, for the one action that has an employee as its
        // subject. Read here — from `team_memberships.reports_to`, in this
        // transaction — for the same reason the ledger is: an authority the
        // caller asserts is an authority the caller can invent. Every other
        // action leaves it `false`, which is what `ActionCtx::new` means by the
        // safest context.
        let directs_subject = match action {
            Action::CharterSet { subordinate } => {
                org::manager_of(tx, *subordinate)
                    .await
                    .map_err(Denied::Unavailable)?
                    == Some(principal.employee_id)
            }
            _ => false,
        };
        let ctx = ActionCtx {
            actor: principal.action_actor(),
            trust,
            contact,
            spent_today,
            new_contacts_today,
            directs_subject,
            now,
        };

        // 4. The rule.
        match evaluate(&policy, action, &ctx) {
            Decision::Allow => match action {
                // 5. A permitted payment consumes the headroom it was measured
                //    against, here, before the caller can be told yes — and the
                //    day's ceiling is re-compared under the lock that takes it,
                //    because the one at step 4 was read without one.
                Action::PaymentCreate { amount } => {
                    let day_cap = policy.limits().spend.map(SpendLimits::max_per_day);
                    self.reserve(tx, principal, *amount, day_cap, now).await
                }
                // 5b. …and a permitted approach to a stranger consumes the
                //     day's cold-outreach headroom, for exactly the same reason
                //     and in the same transaction. Two ceilings, two ledgers,
                //     one rule: a decision that was measured against a number
                //     takes that number before anybody is told yes.
                _ => {
                    self.take_contact(tx, principal, action, ctx.contact, &policy, now)
                        .await
                }
            },
            Decision::Deny { reason } => Ok(Outcome::Deny(reason)),
            decision @ Decision::RequireApproval { .. } => {
                self.request_approval(tx, principal, action, decision, now)
                    .await
            }
        }
    }

    /// The employee's lifecycle, or `None` when there is no such employee in
    /// this tenant.
    ///
    /// ponytail: one column, not `store::employee::load`. The gate does not
    /// care about the eleven-row resource map, and `load` refuses an employee
    /// whose provisioning rows are incomplete — which would turn a
    /// half-provisioned employee into an unexplainable gate error.
    async fn lifecycle(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
    ) -> Result<Option<Lifecycle>, Denied> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT lifecycle FROM employees WHERE id = $1")
                .bind(principal.employee_id.as_uuid())
                .fetch_optional(&mut ***tx)
                .await
                .map_err(|e| Denied::Unavailable(e.into()))?;

        // An unrecognised spelling is a row this build cannot reason about.
        // `Terminated` is the closed answer, and the audit row records the raw
        // string alongside it.
        Ok(raw.map(|raw| match raw.as_str() {
            "draft" => Lifecycle::Draft,
            "active" => Lifecycle::Active,
            "suspended" => Lifecycle::Suspended,
            _ => Lifecycle::Terminated,
        }))
    }

    /// `(counterparties first reached today, whether this one is already
    /// known)`.
    ///
    /// Derived from the audit trail, which is the only record of who this
    /// employee has ever contacted: every allowed action the gate lets through
    /// carries its counterparty in the payload, so "first seen today" is a
    /// `min(occurred_at)` away.
    ///
    /// ponytail: aggregates the whole trail for this employee, and there is no
    /// index it can ride. `audit_log` carries `audit_log_tenant_time_idx`
    /// (`tenant_id, occurred_at`) and `audit_log_denials_idx`, which is partial
    /// on `decision = 'deny'` — the wrong half of the only predicate this
    /// statement has. Re-measured on PostgreSQL 17, median of three, one
    /// employee's allowed rows, `EXPLAIN` confirming a Seq Scan at every size:
    ///
    /// ```text
    /// trail rows   this statement
    /// -----------------------------
    ///      1 000      3.4 ms
    ///     10 000     11.6 ms
    ///     50 000     48.9 ms
    ///    100 000     58.8 ms
    ///    500 000    310.3 ms
    /// ```
    ///
    /// **The upgrade this note used to name was the wrong one.** It said "a
    /// `contacts (tenant_id, employee_id, counterparty, first_seen_at)` table,
    /// when the trail outgrows the index" — a dilemma with two branches, keep
    /// the aggregate or materialise it, written when every decision needed the
    /// number. `spends_contact_budget` is the third branch and it arrived on
    /// 2026-08-28 with waveV-v3: eleven of the fifteen action kinds — every
    /// `A2aSend`, every `McpCall`, every browse, every payment, every message
    /// to a colleague — have an arm of `evaluate` that provably cannot read
    /// `new_contacts_today`, and `policy`'s own
    /// `the_contact_budget_charges_exactly_the_arms_the_ceiling_rules_on` is
    /// what proves it, by running the real evaluator twice rather than by
    /// re-reading the list.
    /// v3 used the predicate to narrow the *write* and left the *read* wide, so
    /// the table above was being paid on the eleven arms that throw the answer
    /// away. `decide` now asks the predicate first; the aggregate runs on the
    /// four channel sends and nowhere else.
    ///
    /// Materialising it is still the upgrade for those four, the day the trail
    /// of an employee that really does send mail outgrows the numbers above.
    async fn contacts(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        action: &Action,
        now: DateTime<Utc>,
    ) -> Result<(u32, ContactStanding), Denied> {
        let day_start = now
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap_or_default()
            .and_utc();

        let (new_today, known): (i64, Option<bool>) = sqlx::query_as(
            "WITH seen AS ( \
                 SELECT payload->>$1 AS counterparty, min(occurred_at) AS first_at \
                   FROM audit_log \
                  WHERE employee_id = $2 \
                    AND decision = 'allow' \
                    AND payload->>$1 IS NOT NULL \
                  GROUP BY 1) \
             SELECT count(*) FILTER (WHERE first_at >= $3), bool_or(counterparty = $4) \
               FROM seen",
        )
        .bind(COUNTERPARTY_KEY)
        .bind(principal.employee_id.as_uuid())
        .bind(day_start)
        .bind(counterparty(action))
        .fetch_one(&mut ***tx)
        .await
        .map_err(|e| Denied::Unavailable(e.into()))?;

        let standing = if known.unwrap_or(false) {
            ContactStanding::Known
        } else {
            ContactStanding::New
        };
        Ok((u32::try_from(new_today).unwrap_or(u32::MAX), standing))
    }

    /// Consume one of the day's strangers, for an action the rule has just
    /// allowed. **The counted half of [`Self::contacts`], made race-free.**
    ///
    /// [`Self::contacts`] derives `new_contacts_today` from an unlocked
    /// aggregate over `audit_log`, and the write that follows it is
    /// `audit::append` — an INSERT into an append-only log with no counter row
    /// and no unique index. Two decisions read `1 of 2`, both are allowed, both
    /// append, and the day ends at three strangers on a ceiling of two. That is
    /// reproducible with no threads at all, and it is the last of this
    /// workspace's three daily budgets to have been merely counted:
    /// [`agentos_store::turns`] and [`agentos_store::spend`] both reserve under
    /// a row lock, and this now does too.
    ///
    /// # Which decisions are charged, and it is the set the *rule* refuses on
    ///
    /// One slot when — and only when — [`spends_contact_budget`] says this
    /// action's arm of `evaluate` consults `max_new_contacts_per_day`, and the
    /// standing read a moment ago said [`ContactStanding::New`] (so it is not
    /// already in the aggregate).
    ///
    /// **Not [`counterparty`], which is the wider set and was wrong here.** That
    /// one answers what the audit row records, and it says `Some` for
    /// [`Action::A2aSend`] — correctly: the trail has to know which peer called.
    /// But `evaluate`'s A2A arm asks `allowed_a2a_peers` and never
    /// `channel_rules`, so the ceiling has never ruled on a peer. Reserving on
    /// "has a counterparty" therefore *invented* a refusal the policy does not
    /// express, and on the shipped default — every role pack in `docs/` ships
    /// `max_new_contacts_per_day: 0` — it refused every A2A call there is,
    /// inbound ones included: `crate::a2a::GateInterceptor::before` authorises
    /// each incoming call as an `Action::A2aSend`. The ledger behind a ceiling
    /// may refuse where the ceiling refuses and nowhere else.
    ///
    /// A payment is not an approach and never charges, and neither does a browse
    /// or a message to a colleague: [`Self::contacts`] reports `New` for an
    /// action with no counterparty at all, because `bool_or(counterparty =
    /// NULL)` is NULL, so reserving on the standing alone would have spent a
    /// stranger on every one of them.
    ///
    /// # The bucket is therefore *narrower* than the aggregate, on purpose
    ///
    /// An A2A peer still advances the trail's `count(*)` — [`counterparty`] is
    /// unchanged, so the aggregate the rule reads still counts it, exactly as it
    /// did before this ledger existed. Taking it out of the aggregate as well
    /// would hand the email budget a slot back, and that is a ceiling widening.
    /// The two counters differ only where the bucket declines to refuse, which
    /// leaves the stricter of the two saying the same thing it always said.
    /// `agentos_store::outreach`'s
    /// `the_bucket_and_the_audit_aggregate_count_the_same_set` walks the
    /// sending actions past both and compares them at every step.
    ///
    /// # The aggregate is still what the rule reads
    ///
    /// Both counters run. Not caution — the deployment day: a bucket created at
    /// noon starts at zero while the trail already holds this morning's
    /// strangers, so a bucket that *replaced* the aggregate would hand every
    /// tenant a fresh allowance the afternoon `0055` lands. That is a ceiling
    /// widening, which is the one thing a ceiling may never do. Side by side,
    /// the refusal is the stricter of the two.
    ///
    /// # No savepoint, unlike [`Self::reserve`]
    ///
    /// That one needs one because a team refusal arrives *after* the employee's
    /// own money is already reserved in this transaction. Nothing here is
    /// half-done on the way to a refusal: `outreach::reserve` returns before any
    /// write when the policy grants nothing, and its locking upsert assigns the
    /// row's own value back to itself — so a refused reservation leaves the
    /// bucket at exactly the number it already held, and committing it with the
    /// deny audit row changes nothing.
    ///
    /// # The approval path deliberately does not do this
    ///
    /// [`Self::redeem`] re-takes the spend headroom and not this, because there
    /// is nothing to take: `evaluate` answers `RequireApproval` only for
    /// payments, contract signatures, credential changes, bulk erasure and
    /// charters, and [`spends_contact_budget`] is `false` for every one of
    /// them. A redeemed approval cannot write a row this budget counts.
    ///
    /// **The predicate named here used to be [`counterparty`], and that is now
    /// the wrong one to check.** The two deliberately disagree —
    /// [`Action::A2aSend`] has a counterparty and does not spend this budget —
    /// and the guard below asks `spends_contact_budget`, which is the question
    /// `evaluate` actually answers. The conclusion is unchanged; a reader who
    /// adds an approval-gated channel send has to re-check the live predicate,
    /// not the retired one.
    async fn take_contact(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        action: &Action,
        standing: ContactStanding,
        policy: &agentos_domain::policy::EffectivePolicy,
        now: DateTime<Utc>,
    ) -> Result<Outcome, Denied> {
        if standing != ContactStanding::New || !spends_contact_budget(action) {
            return Ok(Outcome::Allow { reservation: None });
        }
        match outreach::reserve(tx, principal.employee_id, now.date_naive(), policy, 1).await {
            Ok(_) => Ok(Outcome::Allow { reservation: None }),
            Err(ContactBudgetError::Store(err)) => Err(Denied::Unavailable(err)),
            // Both refusals share a reason because they share a remedy — an
            // operator raising `max_new_contacts_per_day`. `NoBudget` is
            // unreachable from here anyway: a ceiling of zero is `0 >= 0`, and
            // `evaluate` refused above.
            Err(_) => Ok(Outcome::Deny(DenyReason::ContactBudgetExhausted)),
        }
    }

    /// What this employee has already reserved today in `currency`.
    ///
    /// ponytail: reads the bucket directly because `store::spend` exposes no
    /// "reserved so far" reader. Move it there the moment a second caller
    /// needs it.
    async fn spent_today(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        currency: Currency,
        now: DateTime<Utc>,
    ) -> Result<Option<Money>, Denied> {
        let reserved: Option<i64> = sqlx::query_scalar(
            "SELECT reserved_minor FROM spend_buckets \
              WHERE tenant_id = $1 AND employee_id = $2 AND day = $3 AND currency = $4",
        )
        .bind(principal.tenant_id.as_uuid())
        .bind(principal.employee_id.as_uuid())
        .bind(now.date_naive())
        .bind(currency.code())
        .fetch_optional(&mut ***tx)
        .await
        .map_err(|e| Denied::Unavailable(e.into()))?;

        // `Money` cannot be zero, so an empty bucket is `None` — which is
        // exactly what `ActionCtx::spent_today` means by "nothing yet".
        Ok(reserved
            .map(|minor| u64::try_from(minor).unwrap_or(0))
            .and_then(|minor| Money::new(minor, currency).ok()))
    }

    /// Take the headroom — the employee's *and* its team's — or turn the
    /// ledger's refusal into a policy reason.
    ///
    /// [`org::reserve`] rather than [`agentos_store::spend::reserve`]: the
    /// employee's own caps do nothing about ten employees on one team each
    /// making a payment that is legal on its own merit, and this is the only
    /// production call site either has. An employee on no team is exactly
    /// `spend::reserve` plus one indexed lookup of the roster.
    ///
    /// # The savepoint
    ///
    /// `org::reserve` documents that **on refusal the caller must roll back**:
    /// a team refusal arrives after the employee's own reservation is already
    /// in this transaction, and committing anyway would burn the employee's
    /// headroom on a payment that never happened. The gate cannot roll the
    /// whole transaction back — the audit row for this very refusal has not
    /// been written yet, and "every outcome is audited" is not negotiable — so
    /// it rolls back to a savepoint instead. The reservation vanishes, the
    /// ruling is still recorded, and one commit still covers both.
    ///
    /// # And why the day's policy cap is asked twice
    ///
    /// `day_cap` is the `max_per_day` the ruling was made against, re-compared
    /// here — because the *first* comparison was made on [`Self::spent_today`],
    /// which is a bare `SELECT` and therefore takes no lock. Two payments
    /// decided at the same instant read the same headroom and both spend it,
    /// and the ledger does not catch it: `spend_caps.daily_total_minor` is a
    /// different number, written by `PUT /v1/employees/{id}/spend-caps`, and a
    /// deployment whose ledger cap is the looser of the two crosses the policy's
    /// day ceiling with nothing failing. `org::reserve` has just taken the
    /// bucket row lock, so re-asking under it is the same question with a
    /// serialisable answer, and it costs one indexed row read on the allow path.
    ///
    /// `None` on the redemption path, which deliberately does not re-read the
    /// policy at all — see [`Self::redeem_approval`]. That path has never
    /// enforced `max_per_day`, and teaching it to is a policy change rather than
    /// a race fix.
    async fn reserve(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        amount: Money,
        day_cap: Option<Money>,
        now: DateTime<Utc>,
    ) -> Result<Outcome, Denied> {
        sqlx::query("SAVEPOINT gate_reservation")
            .execute(&mut ***tx)
            .await
            .map_err(|e| Denied::Unavailable(e.into()))?;

        let refused = match org::reserve(tx, principal.employee_id, now.date_naive(), amount).await
        {
            Ok(reservation) => {
                // The same read as step 3, now under the lock and including this
                // transaction's own increment.
                let over = match (
                    day_cap,
                    self.spent_today(tx, principal, amount.currency(), now)
                        .await?,
                ) {
                    (Some(cap), Some(total)) => total.minor() > cap.minor(),
                    _ => false,
                };
                if over {
                    DenyReason::DailyLimit
                } else {
                    sqlx::query("RELEASE SAVEPOINT gate_reservation")
                        .execute(&mut ***tx)
                        .await
                        .map_err(|e| Denied::Unavailable(e.into()))?;
                    return Ok(Outcome::Allow {
                        reservation: Some(reservation),
                    });
                }
            }
            Err(
                TeamSpendRefused::Store(err) | TeamSpendRefused::Employee(CapExceeded::Store(err)),
            ) => {
                return Err(Denied::Unavailable(err));
            }
            Err(TeamSpendRefused::Employee(CapExceeded::NoCaps { .. })) => {
                DenyReason::NoSpendPolicy
            }
            Err(TeamSpendRefused::Employee(CapExceeded::PerTransaction { .. })) => {
                DenyReason::PerTransactionLimit
            }
            // Both of these are the day's ceiling: one on value, one on count.
            // They share a reason because they share a remedy.
            Err(TeamSpendRefused::Employee(
                CapExceeded::DailyTotal { .. } | CapExceeded::DailyCount { .. },
            )) => DenyReason::DailyLimit,
            // The team's two, which are *not* the employee's: raising this
            // employee's cap would not help either one.
            Err(TeamSpendRefused::NoBudget { .. }) => DenyReason::NoTeamBudget,
            Err(TeamSpendRefused::TeamDailyTotal { .. }) => DenyReason::TeamDailyLimit,
        };

        sqlx::query("ROLLBACK TO SAVEPOINT gate_reservation")
            .execute(&mut ***tx)
            .await
            .map_err(|e| Denied::Unavailable(e.into()))?;
        Ok(Outcome::Deny(refused))
    }

    /// File the approval, hashed to this exact action.
    async fn request_approval(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        action: &Action,
        decision: Decision,
        now: DateTime<Utc>,
    ) -> Result<Outcome, Denied> {
        let summary = match &decision {
            Decision::RequireApproval { summary, .. } => summary.clone(),
            // Unreachable: the only caller matched on RequireApproval.
            _ => String::new(),
        };
        let request = NewApproval {
            employee_id: Some(principal.employee_id),
            action,
            requested_by: &principal.actor.label(),
            required_role: APPROVER_ROLE,
            reason: Some(&summary),
            expires_at: now + APPROVAL_TTL,
        };

        match approvals::create(tx, &request, now).await {
            // The nonce is deliberately dropped here. It is a bearer token for
            // the human who approves, and handing it back to the caller would
            // hand it to the agent that asked — which is the whole failure the
            // approval exists to prevent.
            Ok(requested) => Ok(Outcome::Approval {
                id: requested.id(),
                decision,
            }),
            Err(ApprovalError::Store(err)) => Err(Denied::Unavailable(err)),
            Err(other) => Err(Denied::Unavailable(StoreError::conflict(format!(
                "approval could not be filed: {other}"
            )))),
        }
    }

    /// Re-hash and consume the approval, then take the spend headroom.
    async fn redeem(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        approval_id: ApprovalId,
        nonce: &str,
        action: &Action,
        now: DateTime<Utc>,
    ) -> Result<Outcome, Denied> {
        match approvals::redeem(tx, approval_id, nonce, action, &principal.actor.label()).await {
            Ok(_) => match action {
                // A human approving a payment does not create money: the
                // ledger cap still applies, and burning the approval on a
                // refusal is deliberate — the next attempt needs a fresh human
                // decision rather than a retry loop against the cap.
                //
                // `None`: no policy was loaded on this path and that is the
                // documented choice above, so there is no `max_per_day` to
                // re-compare. Named rather than defaulted.
                Action::PaymentCreate { amount } => {
                    self.reserve(tx, principal, *amount, None, now).await
                }
                _ => Ok(Outcome::Allow { reservation: None }),
            },
            Err(ApprovalError::ActionMismatch { .. }) => {
                Ok(Outcome::Redemption(RedemptionFailure::ActionMismatch))
            }
            Err(ApprovalError::BadNonce) => Ok(Outcome::Redemption(RedemptionFailure::BadNonce)),
            Err(ApprovalError::AlreadyDecided(_)) => {
                Ok(Outcome::Redemption(RedemptionFailure::AlreadyDecided))
            }
            Err(ApprovalError::Expired) => Ok(Outcome::Redemption(RedemptionFailure::Expired)),
            Err(ApprovalError::NotFound) => Ok(Outcome::Redemption(RedemptionFailure::NotFound)),
            Err(ApprovalError::Store(err)) => Err(Denied::Unavailable(err)),
            Err(other) => Err(Denied::Unavailable(StoreError::conflict(format!(
                "approval could not be redeemed: {other}"
            )))),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Who an action addresses, as a stable string. `None` for actions that have
/// no counterparty — a payment is not a contact.
///
/// This function is the cold-outreach budget's **counter**:
/// [`PolicyGate::contacts`] aggregates the trail on the [`COUNTERPARTY_KEY`] it
/// writes, so anything returning `Some` here advances `new_contacts_today` the
/// first time it is allowed, and is measured against it forever after.
///
/// It is **not** the set the ceiling refuses on, and the difference cost a
/// working A2A endpoint once. `evaluate`'s A2A arm asks `allowed_a2a_peers` and
/// never `channel_rules`, so a peer counts here and is never ruled on — which is
/// why [`PolicyGate::take_contact`] charges
/// [`spends_contact_budget`](agentos_domain::policy::spends_contact_budget)'s
/// narrower set and not this one. Widening either direction is a policy change:
/// dropping a peer from this key would hand the email budget a slot back.
fn counterparty(action: &Action) -> Option<String> {
    match action {
        Action::EmailSend { to } => Some(to.to_string()),
        Action::SmsSend { to } | Action::WhatsappSend { to } | Action::CallPlace { to } => {
            Some(to.as_str().to_owned())
        }
        Action::A2aSend { peer } => Some(peer.as_str().to_owned()),
        // `InternalSend` is `None` on purpose, and it is the one entry here
        // that had a plausible-looking wrong answer. A colleague is not a
        // counterparty: writing its slug under this key would make the first
        // message to each colleague consume one of the day's cold contacts, so
        // an employee that had spoken to twenty suppliers could no longer ask
        // its manager a question — and, worse, the budget an operator sized for
        // strangers would silently be shared with the org chart. An inbound
        // message deliberately does not use this key either
        // (`inbound::land` files the sender under `from`); this is the same
        // rule read the other way round.
        Action::BrowserRead { .. }
        | Action::BrowserWrite { .. }
        | Action::FileUpload { .. }
        | Action::McpCall { .. }
        | Action::PaymentCreate { .. }
        | Action::ContractSign { .. }
        | Action::CredentialChange { .. }
        | Action::DataDelete { .. }
        // A subordinate is not a counterparty. It goes in the payload under its
        // own key (see `audit_event`) and deliberately not under this one: this
        // is what the cold-outreach budget counts, and a head that re-tasks its
        // team must not spend the day's allowance of strangers on its own
        // colleagues.
        | Action::CharterSet { .. } => None,
        | Action::InternalSend { .. } => None,
    }
}

/// The one audit row.
///
/// `decision` is `None` only for refusals the domain has no [`DenyReason`]
/// for — a suspended employee, an unknown one, an incoherent policy, a refused
/// approval. Those carry a `denied` code in the payload instead.
///
/// ponytail: those four would be better as real `deny` rows with their own
/// reason codes, which needs `DenyReason` variants this unit does not own.
/// When the domain gains them, delete the payload key and pass a `Decision`.
fn audit_event(
    principal: &Principal,
    action: &Action,
    decision_id: DecisionId,
    outcome: &Outcome,
    now: DateTime<Utc>,
    extra: Map<String, Value>,
) -> AuditEvent {
    let mut payload = extra;
    if let Some(who) = counterparty(action) {
        payload.insert(COUNTERPARTY_KEY.to_owned(), json!(who));
    }
    // "Who re-tasked whom" is the only question anybody asks about a
    // delegation, and the actor half of it is already the row's `actor` and
    // `employee_id`. Without this key the other half is nowhere.
    if let Action::CharterSet { subordinate } = action {
        payload.insert(
            "subject".to_owned(),
            json!(subordinate.as_uuid().to_string()),
        );
    }

    let decision = match outcome {
        Outcome::Allow { reservation } => {
            if let Some(reservation) = reservation {
                payload.insert(
                    "reservation_id".to_owned(),
                    json!(reservation.id().to_string()),
                );
            }
            Some(Decision::Allow)
        }
        Outcome::Deny(reason) => Some(Decision::Deny { reason: *reason }),
        Outcome::Approval { id, decision } => {
            payload.insert("approval_id".to_owned(), json!(id.as_uuid().to_string()));
            Some(decision.clone())
        }
        Outcome::NotActive(lifecycle) => {
            payload.insert(DENIED_KEY.to_owned(), json!("employee_not_active"));
            payload.insert("lifecycle".to_owned(), json!(lifecycle.as_str()));
            None
        }
        Outcome::UnknownEmployee => {
            payload.insert(DENIED_KEY.to_owned(), json!("unknown_employee"));
            None
        }
        // The row that answers "what did not happen while we were stopped".
        // `agentos_store::halt::refused_since` counts exactly these, and the
        // action kind, the counterparty and the employee are already on this
        // same row — so the list a customer asks for after the incident is one
        // query against a trail that was going to be written anyway.
        Outcome::Halted(reason) => {
            payload.insert(DENIED_KEY.to_owned(), json!(audit::COMPANY_HALTED));
            payload.insert("halt_reason".to_owned(), json!(reason));
            None
        }
        Outcome::BrokenPolicy(err) => {
            payload.insert(DENIED_KEY.to_owned(), json!(broken_code(err)));
            payload.insert("detail".to_owned(), json!(err.to_string()));
            None
        }
        Outcome::Redemption(failure) => {
            payload.insert(DENIED_KEY.to_owned(), json!(failure.code()));
            None
        }
    };

    AuditEvent {
        employee_id: Some(principal.employee_id),
        decision_id: Some(decision_id),
        decision,
        payload: Value::Object(payload),
        ..AuditEvent::new(
            principal.actor.clone(),
            AuditKind::Action(action.kind()),
            now,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::num::NonZeroU32;
    use std::time::{Duration, Instant};

    use agentos_domain::action::{Channel, EmailAddress};
    use agentos_domain::ids::Slug;
    use agentos_domain::money::Currency;
    use agentos_domain::policy::{PolicyLimits, SpendLimits};
    use agentos_store::policy::Scope;
    use agentos_store::spend::{self, SpendCaps};
    use uuid::Uuid;

    use super::*;

    // -- fixtures ----------------------------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; gate tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant and one employee at `lifecycle`, committed.
    async fn seed(db: &Db, lifecycle: &str) -> Principal {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("gate-{}", employee.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', $3)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(lifecycle)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        Principal::employee(tenant, employee)
    }

    /// Everything the tests allow: email, and a small budget — €250 per
    /// payment, €300 per day, a human above €200.
    fn limits() -> PolicyLimits {
        PolicyLimits {
            spend: Some(
                SpendLimits::try_new(
                    Money::new(25_000, Currency::Eur).expect("nonzero"),
                    Money::new(30_000, Currency::Eur).expect("nonzero"),
                    Money::new(20_000, Currency::Eur).expect("nonzero"),
                )
                .expect("coherent"),
            ),
            allowed_channels: BTreeSet::from([Channel::Email]),
            max_new_contacts_per_day: 5,
            ..PolicyLimits::default()
        }
    }

    /// The gate, with [`limits`] written into the database as this tenant's
    /// policy layer.
    ///
    /// There is nothing else to configure: the gate holds a `Db` and reads the
    /// four layers per decision, so a fixture that wants a policy writes one
    /// exactly like an operator would.
    async fn gate(db: &Db, principal: &Principal) -> PolicyGate {
        with_policy(db, principal, Scope::Tenant, &limits()).await
    }

    /// Install one layer and hand back a gate that will read it.
    async fn with_policy(
        db: &Db,
        principal: &Principal,
        scope: Scope<'_>,
        limits: &PolicyLimits,
    ) -> PolicyGate {
        agentos_store::policy::install(db, principal.tenant_id, scope, limits)
            .await
            .expect("install the policy");
        PolicyGate::new(db.clone())
    }

    fn email(to: &str) -> Action {
        Action::EmailSend {
            to: EmailAddress::parse(to).expect("address"),
        }
    }

    fn eur(minor: u64) -> Money {
        Money::new(minor, Currency::Eur).expect("nonzero")
    }

    fn payment(minor: u64) -> Action {
        Action::PaymentCreate { amount: eur(minor) }
    }

    fn spend_limits(per_txn: u64, per_day: u64, approval: u64) -> Option<SpendLimits> {
        Some(SpendLimits::try_new(eur(per_txn), eur(per_day), eur(approval)).expect("coherent"))
    }

    /// A second employee inside an existing tenant, for the team tests.
    async fn seed_mate(db: &Db, principal: &Principal, slug: &str) -> Principal {
        let employee = EmployeeId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(employee.as_uuid())
        .bind(principal.tenant_id.as_uuid())
        .bind(slug)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit mate");
        Principal::employee(principal.tenant_id, employee)
    }

    /// A team called `name`, with `members` on it and `budget` for the day.
    ///
    /// `org::create_team` points the team's policy role at its own slug, which
    /// is what `policy::load` resolves the role layer through — so a
    /// `Scope::Role(name)` layer is this team's limits.
    async fn team(
        db: &Db,
        principal: &Principal,
        name: &str,
        budget: Option<Money>,
        members: &[&Principal],
    ) -> Uuid {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let id = org::create_team(&mut tx, &Slug::parse(name).expect("slug"), name)
            .await
            .expect("create team");
        for member in members {
            org::set_member(&mut tx, member.employee_id, id, None)
                .await
                .expect("set member");
        }
        if let Some(budget) = budget {
            org::set_budget(&mut tx, id, budget).await.expect("budget");
        }
        tx.commit().await.expect("commit team");
        id
    }

    /// A database of this test module's own, for the one property that cannot
    /// be arranged inside a shared one: the *absence* of the platform layer,
    /// which is `tenant_id IS NULL` and therefore one row per deployment.
    ///
    /// Same mechanism and same reasoning as `apps/server/src/loops/mod.rs`,
    /// which needs it for the same row.
    async fn private_db(suffix: &str) -> Option<Db> {
        use sqlx::Connection as _;

        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; gate tests need a real Postgres");
            return None;
        };
        let (host_part, tail) = url.rsplit_once('/').expect("DATABASE_URL names a database");
        let (base, options) = tail.split_once('?').map_or((tail, ""), |(b, o)| (b, o));
        let name = format!("{base}_{suffix}");
        let mine = if options.is_empty() {
            format!("{host_part}/{name}")
        } else {
            format!("{host_part}/{name}?{options}")
        };

        let db = match Db::connect(&mine).await {
            Ok(db) => db,
            Err(_) => {
                let mut admin = sqlx::PgConnection::connect(&url).await.expect("connect");
                // Ignored: losing the race to create it is fine, the connect
                // below is the real check.
                let _ = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
                    .execute(&mut admin)
                    .await;
                admin.close().await.expect("close");
                Db::connect(&mine).await.expect("connect")
            }
        };
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// `daily_transactions` is deliberately generous: these tests exercise the
    /// gate's cap arithmetic, not the ledger's, which has its own suite.
    async fn give_caps(db: &Db, principal: &Principal, daily_total: u64, per_txn: u64) {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        spend::set_caps(
            &mut tx,
            principal.employee_id,
            SpendCaps::new(
                Money::new(daily_total, Currency::Eur).expect("nonzero"),
                Money::new(per_txn, Currency::Eur).expect("nonzero"),
                NonZeroU32::new(10).expect("nonzero"),
            )
            .expect("coherent"),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit caps");
    }

    /// Every audit row for this employee: `(decision, deny_reason_code,
    /// payload)`.
    async fn audit_rows(
        db: &Db,
        principal: &Principal,
    ) -> Vec<(Option<String>, Option<String>, Value)> {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let rows = sqlx::query_as(
            "SELECT decision, deny_reason_code, payload FROM audit_log \
              WHERE employee_id = $1 ORDER BY occurred_at, id",
        )
        .bind(principal.employee_id.as_uuid())
        .fetch_all(&mut **tx)
        .await
        .expect("read audit");
        tx.commit().await.expect("commit read");
        rows
    }

    /// What this employee's own bucket says it has reserved today.
    async fn reserved_today(db: &Db, principal: &Principal) -> i64 {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let reserved: Option<i64> = sqlx::query_scalar(
            "SELECT reserved_minor FROM spend_buckets \
              WHERE employee_id = $1 AND day = $2 AND currency = 'EUR'",
        )
        .bind(principal.employee_id.as_uuid())
        .bind(Utc::now().date_naive())
        .fetch_optional(&mut **tx)
        .await
        .expect("read bucket");
        tx.commit().await.expect("commit read");
        reserved.unwrap_or(0)
    }

    /// What the team's bucket says it has reserved today.
    async fn team_spent(db: &Db, principal: &Principal, team_id: Uuid) -> u64 {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let spent = org::spent(&mut tx, team_id, Utc::now().date_naive(), Currency::Eur)
            .await
            .expect("read team bucket");
        tx.commit().await.expect("commit read");
        spent
    }

    /// The backend behind a transaction, so a test can name the thing it is
    /// deliberately holding.
    async fn backend_pid(tx: &mut TenantTx<'_>) -> i32 {
        sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut ***tx)
            .await
            .expect("read the backend pid")
    }

    /// How many backends are queued behind `blocker` — which is how the
    /// concurrency tests below know a decision is genuinely mid-flight rather
    /// than merely slow.
    ///
    /// Keyed on the blocking pid rather than on the query text, and that is not
    /// tidiness: **two tests in this module hold a `spend_buckets` row at the
    /// same time**, in the same database, because `scripts/test.sh` gives one
    /// database per package and not per test. A predicate that counted
    /// *anybody's* waiter would let each of them end its wait on the other's
    /// decision, release its hold early, and assert against a decision that had
    /// not reached the ledger yet.
    ///
    /// Recursive, and that is the whole reason this is not a one-liner:
    /// `pg_blocking_pids` reports the sessions *directly* ahead of a waiter, and
    /// a second waiter for the same row queues on the first waiter's tuple lock
    /// rather than on the holder. Asking only about direct blockers counts one
    /// where there are two, forever — which is a twenty-second timeout, not a
    /// wrong answer, but only because the deadline is there.
    ///
    /// Asked through an admin transaction on purpose: `pg_stat_activity` hides
    /// other sessions from a non-superuser, and `tenant_tx` runs as `app_role`.
    async fn blocked_by(db: &Db, blocker: i32) -> i64 {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let waiting: i64 = sqlx::query_scalar(
            "WITH RECURSIVE queued(pid) AS ( \
                 SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) \
               UNION \
                 SELECT a.pid FROM pg_stat_activity a \
                   JOIN queued q ON q.pid = ANY(pg_blocking_pids(a.pid))) \
             SELECT count(*) FROM queued",
        )
        .bind(blocker)
        .fetch_one(&mut *tx)
        .await
        .expect("read pg_stat_activity");
        tx.commit().await.expect("commit read");
        waiting
    }

    async fn reservation_count(db: &Db, principal: &Principal) -> i64 {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM spend_reservations WHERE employee_id = $1 AND state = 'reserved'",
        )
        .bind(principal.employee_id.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("count reservations");
        tx.commit().await.expect("commit read");
        count
    }

    /// The nonce, read the way the approval UI reads it: out of the row, never
    /// out of the gate's return value.
    async fn nonce_of(db: &Db, principal: &Principal, id: ApprovalId) -> String {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let nonce: String =
            sqlx::query_scalar("SELECT action->>'nonce' FROM approvals WHERE id = $1")
                .bind(id.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("read nonce");
        tx.commit().await.expect("commit read");
        nonce
    }

    // -- the tests ---------------------------------------------------------

    /// The seal, from inside the module. `tests/ui/gate_*.rs` proves the same
    /// construction is impossible from outside, which is the half that matters.
    #[test]
    fn a_token_carries_the_decision_that_minted_it() {
        let id = DecisionId::new_v7(Utc::now());
        let token = Authorized {
            action: email("supplier@example.com"),
            decision_id: id,
            reservation: None,
            _seal: seal::Seal::new(),
        };
        assert_eq!(token.decision_id(), id);
        assert!(token.reservation().is_none());
        assert_eq!(token.action().kind(), token.into_action().kind());
    }

    #[test]
    fn trust_travels_with_the_type() {
        let action = email("supplier@example.com");
        assert_eq!(action.trust(), TrustLabel::Trusted);
        assert_eq!(
            Untrusted::new(action.clone()).trust(),
            TrustLabel::Untrusted
        );
        assert_eq!(Untrusted::new(action.clone()).to_action(), action);
    }

    #[test]
    fn every_refusal_has_a_stable_code() {
        assert_eq!(
            Denied::NotActive(Lifecycle::Suspended).code(),
            "employee_not_active"
        );
        assert_eq!(Denied::UnknownEmployee.code(), "unknown_employee");
        assert_eq!(Denied::Policy(DenyReason::DailyLimit).code(), "daily_limit");
        assert_eq!(
            Denied::Redemption(RedemptionFailure::ActionMismatch).code(),
            "approval_action_mismatch"
        );
    }

    #[tokio::test]
    async fn a_suspended_employee_is_denied_before_any_policy_is_consulted() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "suspended").await;

        // A stored policy that would ALLOW this action if it were ever
        // reached: the refusal below can therefore only have come from the
        // lifecycle.
        let gate = gate(&db, &principal).await;
        let err = gate
            .authorize(&principal, email("supplier@example.com"))
            .await
            .expect_err("suspended employees may not act");

        assert!(matches!(err, Denied::NotActive(Lifecycle::Suspended)));
        assert_eq!(err.code(), "employee_not_active");

        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1, "exactly one audit row");
        assert_eq!(rows[0].2[DENIED_KEY], json!("employee_not_active"));
        assert_eq!(rows[0].2["lifecycle"], json!("suspended"));
    }

    #[tokio::test]
    async fn an_unknown_employee_is_refused() {
        let Some(db) = db().await else { return };
        let real = seed(&db, "active").await;
        let ghost = Principal::employee(real.tenant_id, EmployeeId::new_v7(Utc::now()));

        let err = gate(&db, &real)
            .await
            .authorize(&ghost, email("supplier@example.com"))
            .await
            .expect_err("no such employee");
        assert!(matches!(err, Denied::UnknownEmployee));
    }

    #[tokio::test]
    async fn each_outcome_writes_exactly_one_audit_row() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        let gate = gate(&db, &principal).await;

        // Allow.
        gate.authorize(&principal, email("supplier@example.com"))
            .await
            .expect("email is allowed");
        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.as_deref(), Some("allow"));
        assert_eq!(rows[0].1, None);
        assert_eq!(rows[0].2[COUNTERPARTY_KEY], json!("supplier@example.com"));

        // Deny: SMS is not an allowed channel.
        let err = gate
            .authorize(
                &principal,
                Action::SmsSend {
                    to: agentos_domain::action::E164::parse("+33123456789").expect("number"),
                },
            )
            .await
            .expect_err("sms is not allowed");
        assert_eq!(err.code(), DenyReason::ChannelNotAllowed.code());
        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].0.as_deref(), Some("deny"));
        assert_eq!(
            rows[1].1.as_deref(),
            Some(DenyReason::ChannelNotAllowed.code())
        );

        // RequireApproval: signing always needs a human.
        let err = gate
            .authorize(
                &principal,
                Action::ContractSign {
                    title: "supply agreement".to_owned(),
                },
            )
            .await
            .expect_err("contracts always need a human");
        assert!(matches!(err, Denied::PendingApproval(_)));
        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), 3, "exactly one row per outcome, no more");
        assert_eq!(rows[2].0.as_deref(), Some("require_approval"));
        assert_eq!(rows[2].1.as_deref(), Some("contract_signature"));
    }

    #[tokio::test]
    async fn an_allowed_payment_reserves_and_a_denied_one_does_not() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        give_caps(&db, &principal, 100_000, 50_000).await;
        let gate = gate(&db, &principal).await;

        // Under the approval threshold (20_000) and under both caps.
        let token = gate
            .authorize(&principal, payment(15_000))
            .await
            .expect("within every cap");
        let reservation = token.reservation().expect("an allowed payment reserves");
        assert_eq!(reservation.amount().minor(), 15_000);
        assert_eq!(reservation_count(&db, &principal).await, 1);

        // Over the per-transaction policy cap of 25_000: refused, and nothing
        // reserved. Note the ledger's own cap is 50_000, so this refusal can
        // only have come from the policy.
        let err = gate
            .authorize(&principal, payment(60_000))
            .await
            .expect_err("over the per-transaction cap");
        assert_eq!(err.code(), DenyReason::PerTransactionLimit.code());
        assert_eq!(
            reservation_count(&db, &principal).await,
            1,
            "a refused payment must not consume headroom"
        );

        // The structuring guard: the first reservation is now visible as
        // `spent_today`, so a second payment that fits on its own does not.
        let err = gate
            .authorize(&principal, payment(19_000))
            .await
            .expect_err("15_000 + 19_000 is over the daily policy cap of 30_000");
        assert_eq!(err.code(), DenyReason::DailyLimit.code());
        assert_eq!(reservation_count(&db, &principal).await, 1);
    }

    #[tokio::test]
    async fn an_untrusted_payment_never_reaches_the_ledger() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        give_caps(&db, &principal, 100_000, 50_000).await;

        let err = gate(&db, &principal)
            .await
            .authorize(&principal, Untrusted::new(payment(1_000)))
            .await
            .expect_err("a payment derived from untrusted text is not authorised");

        assert_eq!(err.code(), DenyReason::UntrustedInput.code());
        assert_eq!(reservation_count(&db, &principal).await, 0);
    }

    #[tokio::test]
    async fn an_approval_cannot_be_redeemed_for_a_different_action() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        give_caps(&db, &principal, 100_000, 50_000).await;
        let gate = gate(&db, &principal).await;

        // 25_000 is over the approval threshold, under both caps.
        let approved = payment(25_000);
        let Denied::PendingApproval(approval_id) = gate
            .authorize(&principal, approved.clone())
            .await
            .expect_err("over the approval threshold")
        else {
            panic!("expected a pending approval");
        };
        assert_eq!(
            reservation_count(&db, &principal).await,
            0,
            "an unapproved payment reserves nothing"
        );
        let nonce = nonce_of(&db, &principal, approval_id).await;

        // The swap: same shape, different amount.
        let mutated = payment(45_000);
        let err = gate
            .redeem_approval(&principal, approval_id, &nonce, mutated)
            .await
            .expect_err("the approved action was mutated");
        assert!(matches!(
            err,
            Denied::Redemption(RedemptionFailure::ActionMismatch)
        ));
        assert_eq!(reservation_count(&db, &principal).await, 0);

        // A bad nonce is refused too, and the approval survives both attempts.
        let err = gate
            .redeem_approval(&principal, approval_id, "not-the-nonce", approved.clone())
            .await
            .expect_err("wrong nonce");
        assert!(matches!(
            err,
            Denied::Redemption(RedemptionFailure::BadNonce)
        ));

        // The real thing: redeemed once, reserved once.
        let token = gate
            .redeem_approval(&principal, approval_id, &nonce, approved.clone())
            .await
            .expect("the exact approved action redeems");
        assert_eq!(
            token
                .reservation()
                .expect("payments reserve")
                .amount()
                .minor(),
            25_000
        );
        assert_eq!(reservation_count(&db, &principal).await, 1);

        // And exactly once: the second attempt finds it spent.
        let err = gate
            .redeem_approval(&principal, approval_id, &nonce, approved)
            .await
            .expect_err("an approval is single use");
        assert!(matches!(
            err,
            Denied::Redemption(RedemptionFailure::AlreadyDecided)
        ));
        assert_eq!(reservation_count(&db, &principal).await, 1);

        // One row per outcome: request, mismatch, bad nonce, redeem, replay.
        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].0.as_deref(), Some("require_approval"));
        assert_eq!(rows[1].2[DENIED_KEY], json!("approval_action_mismatch"));
        assert_eq!(rows[2].2[DENIED_KEY], json!("approval_bad_nonce"));
        assert_eq!(rows[3].0.as_deref(), Some("allow"));
        assert_eq!(rows[4].2[DENIED_KEY], json!("approval_already_decided"));
    }

    #[tokio::test]
    async fn the_cold_outreach_budget_counts_first_contacts_not_messages() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        let gate = with_policy(
            &db,
            &principal,
            Scope::Tenant,
            &PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Email]),
                max_new_contacts_per_day: 2,
                ..PolicyLimits::default()
            },
        )
        .await;

        for who in ["a@example.com", "b@example.com"] {
            gate.authorize(&principal, email(who))
                .await
                .unwrap_or_else(|e| panic!("{who} is within the budget: {e}"));
        }

        // A third *new* counterparty is over budget...
        let err = gate
            .authorize(&principal, email("c@example.com"))
            .await
            .expect_err("two new contacts is the budget");
        assert_eq!(err.code(), DenyReason::ContactBudgetExhausted.code());

        // ...while writing again to someone already contacted is not, because
        // the budget counts contacts, not messages.
        gate.authorize(&principal, email("a@example.com"))
            .await
            .expect("a known counterparty costs nothing");
    }

    /// **The same budget, reserved rather than counted.**
    ///
    /// [`PolicyGate::contacts`] derives the day's number from an unlocked
    /// aggregate over `audit_log`, and the write that follows it is an INSERT
    /// into an append-only log: no counter row, no unique index, nothing to
    /// block on. Two decisions read `1 of 2`, both are allowed, both append, and
    /// the day ends at three strangers on a ceiling of two — reproduced in SQL,
    /// with no threads and no timing, before `outreach_buckets` existed.
    ///
    /// Arranged rather than raced, for the same reason
    /// [`a_policy_change_cannot_land_between_the_ruling_and_the_reservation`]
    /// arranges: a slot taken out of the bucket behind the gate's back is
    /// exactly what a concurrent twin leaves there, and it leaves `audit_log`
    /// untouched — so the aggregate still reports the day as free, and the only
    /// thing that can refuse below is the reservation.
    #[tokio::test]
    async fn an_allowed_approach_reserves_the_stranger_it_was_measured_against() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        let day = Utc::now().date_naive();
        // Five strangers and money, plus the internal channel — which is what
        // makes the assertion below possible at all.
        let gate = with_policy(
            &db,
            &principal,
            Scope::Tenant,
            &PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Email, Channel::Internal]),
                ..limits()
            },
        )
        .await;
        give_caps(&db, &principal, 100_000, 50_000).await;

        // **The arm that would have been wrong, and it is not the payment.** A
        // payment is matched one line earlier in `decide` and never reaches the
        // reservation; a message to a colleague does. `contacts` reports `New`
        // for it — `bool_or(counterparty = NULL)` is NULL, and `InternalSend`
        // has no counterparty on purpose — so reserving on the standing alone
        // would make the first message to each colleague spend one of the day's
        // strangers, which is exactly the failure `counterparty` was written to
        // avoid. Same for a browse, an MCP call and a file upload.
        gate.authorize(
            &principal,
            Action::InternalSend {
                to: Slug::parse("bruno").expect("slug"),
            },
        )
        .await
        .expect("a colleague is not a stranger");
        assert_eq!(strangers_today(&db, &principal, day).await, 0);

        gate.authorize(&principal, payment(1_000))
            .await
            .expect("inside every cap");
        assert_eq!(strangers_today(&db, &principal, day).await, 0);

        gate.authorize(&principal, email("a@example.com"))
            .await
            .expect("the first stranger");
        assert_eq!(strangers_today(&db, &principal, day).await, 1);

        // A repeat is free on the ledger for the same reason it is free in the
        // aggregate: the standing is `Known`, so nothing is charged.
        gate.authorize(&principal, email("a@example.com"))
            .await
            .expect("a known counterparty costs nothing");
        assert_eq!(strangers_today(&db, &principal, day).await, 1);

        // The concurrent twin takes the rest of the day, without writing a
        // single audit row — so the aggregate the rule reads still says `1 of 5`.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let policy = policy_store::load(&mut tx, principal.employee_id)
            .await
            .expect("policy");
        assert_eq!(
            outreach::reserve(&mut tx, principal.employee_id, day, &policy, 4)
                .await
                .expect("the rest of the day"),
            4
        );
        tx.commit().await.expect("commit");

        let before = audit_rows(&db, &principal).await.len();
        let err = gate
            .authorize(&principal, email("b@example.com"))
            .await
            .expect_err("the ledger is what decides, not the trail");
        assert_eq!(err.code(), DenyReason::ContactBudgetExhausted.code());
        assert_eq!(
            strangers_today(&db, &principal, day).await,
            5,
            "a refusal does not advance the ledger"
        );

        // Refused, and audited like every other outcome — with the reason the
        // rule would have used, so an operator reads one code for one remedy.
        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), before + 1);
        assert_eq!(rows[before].0.as_deref(), Some("deny"));
        assert_eq!(
            rows[before].1.as_deref(),
            Some(DenyReason::ContactBudgetExhausted.code())
        );
        assert_eq!(rows[before].2[COUNTERPARTY_KEY], json!("b@example.com"));
    }

    /// **The ledger must not refuse what the rule never measured.**
    ///
    /// [`counterparty`] answers `Some` for [`Action::A2aSend`] — a peer is a
    /// counterparty and the trail says so — but `evaluate_rules`' A2A arm asks
    /// `allowed_a2a_peers` and **never `channel_rules`**, so
    /// `max_new_contacts_per_day` has never had an opinion about A2A. Charging
    /// the bucket on `counterparty(action).is_some()` therefore invents a
    /// refusal: `ContactBudgetError::NoBudget` on the shipped default of `0`,
    /// and `Exhausted` once the day's email has spent it.
    ///
    /// It is not a hypothetical path. `a2a::GateInterceptor::before` authorises
    /// every **inbound** call as `Action::A2aSend { peer }`, so on a policy that
    /// grants peers and no cold outreach — which is every role pack in `docs/`,
    /// all of which ship `max_new_contacts_per_day: 0` — the whole A2A endpoint
    /// answers `unsupported_operation` to everybody.
    #[tokio::test]
    async fn a_peer_call_is_not_a_cold_approach_and_does_not_need_the_budget() {
        let Some(db) = db().await else { return };
        let peer = Action::A2aSend {
            peer: agentos_domain::action::Domain::parse("partner.example").expect("domain"),
        };
        let peers = BTreeSet::from([
            agentos_domain::action::Domain::parse("partner.example").expect("domain")
        ]);

        // 1. The shipped default: peers granted, cold outreach off. The rule
        //    allows this call and the ledger must not take it back.
        let principal = seed(&db, "active").await;
        let gate = with_policy(
            &db,
            &principal,
            Scope::Tenant,
            &PolicyLimits {
                allowed_a2a_peers: peers.clone(),
                max_new_contacts_per_day: 0,
                ..PolicyLimits::default()
            },
        )
        .await;
        gate.authorize(&principal, peer.clone())
            .await
            .expect("a peer on the allowlist is not a stranger this budget rules on");

        // 2. And a budget the day's email has spent must not close the endpoint
        //    either: `evaluate` allows the peer whatever `new_contacts_today`
        //    says, so the reservation is the only thing that could refuse.
        let other = seed(&db, "active").await;
        let gate = with_policy(
            &db,
            &other,
            Scope::Tenant,
            &PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Email]),
                allowed_a2a_peers: peers,
                max_new_contacts_per_day: 1,
                ..PolicyLimits::default()
            },
        )
        .await;
        gate.authorize(&other, email("a@example.com"))
            .await
            .expect("the day's one stranger");
        gate.authorize(&other, peer)
            .await
            .expect("a peer call is not the day's second stranger");
        assert_eq!(
            strangers_today(&db, &other, Utc::now().date_naive()).await,
            1,
            "the bucket counts the set the ceiling rules on, and A2A is not in it"
        );
    }

    /// What `outreach_buckets` says this employee has been cleared to reach.
    async fn strangers_today(db: &Db, principal: &Principal, day: chrono::NaiveDate) -> u32 {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let taken = outreach::taken_today(&mut tx, principal.employee_id, day)
            .await
            .expect("read the bucket");
        tx.rollback().await.expect("rollback");
        taken
    }

    #[tokio::test]
    async fn an_unconfigured_gate_denies_everything() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;

        // A layer that grants nothing — which is what an operator who created a
        // tenant and stopped there has.
        let err = with_policy(&db, &principal, Scope::Tenant, &PolicyLimits::default())
            .await
            .authorize(&principal, email("supplier@example.com"))
            .await
            .expect_err("an empty policy grants nothing");
        assert_eq!(err.code(), DenyReason::NoRule.code());
    }

    /// A lower layer may only tighten, and the gate is what proves it end to
    /// end: the employee layer below asks for a channel its tenant never had.
    ///
    /// The loader's own suite proves the same property for the platform layer,
    /// which cannot be varied per test — it is one row for the whole database.
    #[tokio::test]
    async fn a_lower_layer_narrows_but_never_widens() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;

        with_policy(&db, &principal, Scope::Tenant, &limits()).await;
        let gate = with_policy(
            &db,
            &principal,
            Scope::Employee(principal.employee_id),
            &PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Email, Channel::Sms]),
                max_new_contacts_per_day: 5,
                ..PolicyLimits::default()
            },
        )
        .await;

        let err = gate
            .authorize(
                &principal,
                Action::SmsSend {
                    to: agentos_domain::action::E164::parse("+33123456789").expect("number"),
                },
            )
            .await
            .expect_err("an employee cannot grant itself a channel its tenant withheld");
        assert_eq!(err.code(), DenyReason::ChannelNotAllowed.code());

        // ...and the layer is genuinely being read: what the tenant *did* allow
        // still goes through it.
        gate.authorize(&principal, email("supplier@example.com"))
            .await
            .expect("email is allowed by both layers");
    }

    // -- the stored policy -------------------------------------------------

    /// **The unit's reason to exist.** A cap an operator writes into
    /// `policy_layers` refuses an action the gate had just allowed — same
    /// `PolicyGate` value, no redeploy, no restart, because the gate reads the
    /// row rather than a struct it was built with.
    #[tokio::test]
    async fn a_cap_written_to_the_database_changes_what_the_gate_allows() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        // The ledger is generous throughout, so every refusal below can only
        // have come from the stored policy.
        give_caps(&db, &principal, 100_000, 50_000).await;
        let gate = gate(&db, &principal).await;

        gate.authorize(&principal, payment(15_000))
            .await
            .expect("15_000 is inside the installed policy");

        // The operator lowers the tenant's per-transaction cap to 10_000.
        policy_store::install(
            &db,
            principal.tenant_id,
            Scope::Tenant,
            &PolicyLimits {
                spend: spend_limits(10_000, 30_000, 10_000),
                ..limits()
            },
        )
        .await
        .expect("install the tightened policy");

        let err = gate
            .authorize(&principal, payment(15_000))
            .await
            .expect_err("the same payment is now over the tenant's cap");
        assert_eq!(err.code(), DenyReason::PerTransactionLimit.code());
        assert_eq!(
            reservation_count(&db, &principal).await,
            1,
            "the refused payment consumed no headroom"
        );

        // Not only money: a channel taken away is taken away. SMS rather than
        // an empty list, so the refusal is `channel_not_allowed` — an empty
        // allowlist is `no_rule`, which would be a weaker claim.
        policy_store::install(
            &db,
            principal.tenant_id,
            Scope::Tenant,
            &PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Sms]),
                ..limits()
            },
        )
        .await
        .expect("install the muted policy");

        let err = gate
            .authorize(&principal, email("supplier@example.com"))
            .await
            .expect_err("email is no longer an allowed channel");
        assert_eq!(err.code(), DenyReason::ChannelNotAllowed.code());
    }

    /// A team's limits reach its members, and only its members — and a team
    /// that asks for more than its tenant gets its tenant's.
    ///
    /// The role layer resolves through `team_memberships`, so this is the whole
    /// path: employee → team → `team_policy.role_name` → `policy_layers`.
    #[tokio::test]
    async fn a_teams_layer_tightens_its_member_and_a_greedy_teams_does_not() {
        let Some(db) = db().await else { return };
        let thrifty = seed(&db, "active").await;
        let greedy = seed_mate(&db, &thrifty, "greedy-one").await;
        give_caps(&db, &thrifty, 100_000, 100_000).await;
        give_caps(&db, &greedy, 100_000, 100_000).await;

        // The tenant allows 25_000 a payment, a human above 20_000.
        let gate = gate(&db, &thrifty).await;
        team(&db, &thrifty, "thrifty", Some(eur(100_000)), &[&thrifty]).await;
        team(&db, &thrifty, "greedy", Some(eur(100_000)), &[&greedy]).await;

        with_policy(
            &db,
            &thrifty,
            Scope::Role("thrifty"),
            &PolicyLimits {
                spend: spend_limits(5_000, 30_000, 5_000),
                ..limits()
            },
        )
        .await;
        with_policy(
            &db,
            &thrifty,
            Scope::Role("greedy"),
            &PolicyLimits {
                spend: spend_limits(999_999, 999_999, 999_999),
                ..limits()
            },
        )
        .await;

        let err = gate
            .authorize(&thrifty, payment(10_000))
            .await
            .expect_err("the team's cap is 5_000");
        assert_eq!(err.code(), DenyReason::PerTransactionLimit.code());

        // The same payment, from an employee on a different team: the tightened
        // layer is that team's, not the tenant's.
        gate.authorize(&greedy, payment(10_000))
            .await
            .expect("inside the tenant's cap and its own team's");

        // And the greedy team gets the tenant's ceiling, not the one it wrote.
        let err = gate
            .authorize(&greedy, payment(30_000))
            .await
            .expect_err("a team may tighten its tenant's cap and never widen it");
        assert_eq!(err.code(), DenyReason::PerTransactionLimit.code());
    }

    /// The team budget, through the gate: it refuses the second employee, and
    /// the first employee's reservation is the only one that survives.
    ///
    /// `org::reserve` refuses the team *after* writing the employee's own
    /// reservation into the transaction and requires the caller to roll back.
    /// The gate cannot roll the whole transaction back — the audit row for this
    /// refusal is not written yet — so it unwinds to a savepoint, and this is
    /// the test of that: nothing half-reserved, and a ruling on the record.
    #[tokio::test]
    async fn a_team_budget_refuses_the_second_employee_and_leaves_nothing_half_reserved() {
        let Some(db) = db().await else { return };
        let first = seed(&db, "active").await;
        let second = seed_mate(&db, &first, "second").await;
        give_caps(&db, &first, 100_000, 100_000).await;
        give_caps(&db, &second, 100_000, 100_000).await;

        // Each payment is legal on its own merit: 20_000 is inside the policy,
        // inside each employee's own caps, and under the threshold that would
        // ask a human — so the only thing that can refuse the second one is the
        // team.
        let gate = with_policy(
            &db,
            &first,
            Scope::Tenant,
            &PolicyLimits {
                spend: spend_limits(25_000, 100_000, 25_000),
                ..limits()
            },
        )
        .await;
        let purchasing = team(
            &db,
            &first,
            "purchasing",
            Some(eur(25_000)),
            &[&first, &second],
        )
        .await;

        gate.authorize(&first, payment(20_000))
            .await
            .expect("the first fits the team's budget");

        let err = gate
            .authorize(&second, payment(20_000))
            .await
            .expect_err("40_000 is over the team's 25_000");
        assert_eq!(err.code(), DenyReason::TeamDailyLimit.code());

        assert_eq!(
            reservation_count(&db, &second).await,
            0,
            "no reservation row for a payment the team refused"
        );
        assert_eq!(
            reserved_today(&db, &second).await,
            0,
            "and no headroom taken out of the employee's own bucket either"
        );
        assert_eq!(
            team_spent(&db, &first, purchasing).await,
            20_000,
            "the team's bucket holds the first payment and nothing else"
        );

        // The ruling itself survives the unwind, which is the whole reason it
        // is a savepoint and not a rollback.
        let rows = audit_rows(&db, &second).await;
        assert_eq!(rows.len(), 1, "exactly one audit row for the refusal");
        assert_eq!(rows[0].0.as_deref(), Some("deny"));
        assert_eq!(
            rows[0].1.as_deref(),
            Some(DenyReason::TeamDailyLimit.code())
        );

        // A team with no budget at all fails closed rather than open, and says
        // so in its own words: the employee's caps were never the problem.
        let stranger = seed_mate(&db, &first, "stranger").await;
        give_caps(&db, &stranger, 100_000, 100_000).await;
        team(&db, &first, "unfunded", None, &[&stranger]).await;
        let err = gate
            .authorize(&stranger, payment(1_000))
            .await
            .expect_err("a team with no budget may not spend");
        assert_eq!(err.code(), DenyReason::NoTeamBudget.code());
        assert_eq!(reservation_count(&db, &stranger).await, 0);
    }

    /// A deployment with no platform layer refuses everything, loudly.
    ///
    /// The tempting alternative — fall back to an in-memory default — is what
    /// makes a misconfigured deployment silently permissive, so the refusal is
    /// deliberate, it has its own metric code, and it is audited like any other
    /// outcome. A deployment that denies everything *silently* is as hard to
    /// diagnose as one that allows everything.
    ///
    /// Its own database: the platform layer is `tenant_id IS NULL`, one row for
    /// the whole deployment, so "there is not one" cannot be arranged inside a
    /// database other tests are using.
    #[tokio::test]
    async fn a_deployment_with_no_platform_layer_refuses_everything() {
        let Some(db) = private_db("gateceiling").await else {
            return;
        };
        // Its own database, but not a fresh one — the last line of this test
        // installs a ceiling, and the database outlives the run that made it.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM policy_versions WHERE tenant_id IS NULL")
            .execute(&mut *admin)
            .await
            .expect("clear the ceiling");
        admin.commit().await.expect("commit");

        let principal = seed(&db, "active").await;
        give_caps(&db, &principal, 100_000, 50_000).await;
        let gate = PolicyGate::new(db.clone());

        for action in [email("supplier@example.com"), payment(1_000)] {
            let err = gate
                .authorize(&principal, action)
                .await
                .expect_err("no ceiling, no authority");
            assert!(
                matches!(err, Denied::BrokenPolicy(PolicyLoadError::NoPlatformLayer)),
                "{err:?}"
            );
            assert_eq!(
                err.code(),
                "no_platform_policy",
                "its own code: nobody installed a policy, which is not the same \
                 operational problem as somebody writing a bad one"
            );
        }
        assert_eq!(reservation_count(&db, &principal).await, 0);

        let rows = audit_rows(&db, &principal).await;
        assert_eq!(
            rows.len(),
            2,
            "one row per refusal, like every other outcome"
        );
        for row in &rows {
            assert_eq!(row.0, None, "the gate never reached the rule");
            assert_eq!(row.2[DENIED_KEY], json!("no_platform_policy"));
        }

        // And it is the missing ceiling rather than the fixture: install one
        // and the same gate allows.
        with_policy(&db, &principal, Scope::Tenant, &limits())
            .await
            .authorize(&principal, email("supplier@example.com"))
            .await
            .expect("a ceiling and a tenant layer is a policy");
    }

    /// The ruling and the reservation are one policy and one commit, even when
    /// an operator changes the policy in between.
    ///
    /// Arranged rather than raced. The test holds the employee's spend bucket,
    /// which the gate reaches *after* it has read its policy and evaluated the
    /// rule, so the change below lands squarely in the window between the two.
    /// While the decision is stuck there, nothing of it is visible — no audit
    /// row, no reservation — and when it lands, both land together, under the
    /// policy the ruling read. The next decision, and only the next one, sees
    /// the new policy: there is no cache to go stale.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_policy_change_cannot_land_between_the_ruling_and_the_reservation() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        give_caps(&db, &principal, 100_000, 50_000).await;
        let gate = gate(&db, &principal).await;

        // A first payment, so there is a bucket row to hold.
        gate.authorize(&principal, payment(1_000))
            .await
            .expect("inside every cap");

        let mut holder = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let blocker = backend_pid(&mut holder).await;
        sqlx::query(
            "SELECT reserved_minor FROM spend_buckets \
              WHERE employee_id = $1 AND day = $2 AND currency = 'EUR' FOR UPDATE",
        )
        .bind(principal.employee_id.as_uuid())
        .bind(Utc::now().date_naive())
        .fetch_one(&mut **holder)
        .await
        .expect("hold the bucket");

        let in_flight = tokio::spawn({
            let gate = gate.clone();
            let principal = principal.clone();
            async move { gate.authorize(&principal, payment(15_000)).await }
        });

        // Wait until it is genuinely blocked on that row rather than merely
        // slow — a green result from a decision that never started proves
        // nothing.
        let deadline = Instant::now() + Duration::from_secs(20);
        while blocked_by(&db, blocker).await == 0 {
            assert!(
                Instant::now() < deadline,
                "the decision never reached the ledger"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Mid-decision: the ruling is made and nothing of it is visible.
        assert_eq!(
            audit_rows(&db, &principal).await.len(),
            1,
            "the in-flight decision has not committed anything"
        );
        assert_eq!(reservation_count(&db, &principal).await, 1);

        // The operator forbids exactly what is in flight.
        policy_store::install(
            &db,
            principal.tenant_id,
            Scope::Tenant,
            &PolicyLimits {
                spend: spend_limits(1_000, 30_000, 1_000),
                ..limits()
            },
        )
        .await
        .expect("install the tightened policy");

        holder.rollback().await.expect("release the bucket");

        let token = in_flight
            .await
            .expect("join")
            .expect("ruled under the policy it read, not the one that arrived after");
        let reservation = token.reservation().expect("an allowed payment reserves");
        assert_eq!(reservation.amount().minor(), 15_000);

        // Ruling and reservation, one commit: the audit row names the very
        // reservation the token carries.
        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].0.as_deref(), Some("allow"));
        assert_eq!(
            rows[1].2["reservation_id"],
            json!(reservation.id().to_string())
        );
        assert_eq!(reserved_today(&db, &principal).await, 16_000);

        // The next decision reads the row the operator wrote.
        let err = gate
            .authorize(&principal, payment(15_000))
            .await
            .expect_err("the new cap is 1_000");
        assert_eq!(err.code(), DenyReason::PerTransactionLimit.code());
    }

    /// Two payments that are each legal on their own do not become legal
    /// together because they were decided at the same time.
    ///
    /// The policy's `max_per_day` and the ledger's `spend_caps.daily_total` are
    /// **two different numbers**, written on two different screens: the first
    /// comes out of the four policy layers, the second out of
    /// `PUT /v1/employees/{id}/spend-caps`. `spend::reserve` compares against
    /// the second under a row lock, and until this test the first was compared
    /// against a bare `SELECT` — which takes no lock, so two decisions read the
    /// same headroom and both spent it. Here the ledger's cap is deliberately
    /// enormous, so it can refuse nothing and the only ceiling in play is the
    /// policy's €300.
    ///
    /// Arranged rather than raced, exactly like the test above: a third
    /// transaction holds the bucket row, both decisions read their headroom
    /// (that read does *not* block — it is the defect), both then queue on the
    /// reservation, and the hold is released once both are demonstrably there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_payments_decided_at_once_cannot_cross_the_policy_s_day_cap() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        // A ledger that will never be the refusal: 10_000 against a daily total
        // of 1_000_000 leaves the policy's 30_000 as the only ceiling.
        give_caps(&db, &principal, 1_000_000, 50_000).await;
        let gate = gate(&db, &principal).await;

        // €100 of the day's €300, and a bucket row to hold.
        gate.authorize(&principal, payment(10_000))
            .await
            .expect("inside every cap");

        let mut holder = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let blocker = backend_pid(&mut holder).await;
        sqlx::query(
            "SELECT reserved_minor FROM spend_buckets \
              WHERE employee_id = $1 AND day = $2 AND currency = 'EUR' FOR UPDATE",
        )
        .bind(principal.employee_id.as_uuid())
        .bind(Utc::now().date_naive())
        .fetch_one(&mut **holder)
        .await
        .expect("hold the bucket");

        // Each of these is 10_000 + 15_000 = 25_000, under the day's 30_000.
        // Both is 40_000, over it.
        let in_flight: Vec<_> = (0..2)
            .map(|_| {
                let gate = gate.clone();
                let principal = principal.clone();
                tokio::spawn(async move { gate.authorize(&principal, payment(15_000)).await })
            })
            .collect();

        // Both are genuinely queued on the bucket, which means both have
        // already read the headroom they were measured against.
        let deadline = Instant::now() + Duration::from_secs(20);
        while blocked_by(&db, blocker).await < 2 {
            assert!(
                Instant::now() < deadline,
                "both decisions never reached the ledger together"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        holder.rollback().await.expect("release the bucket");

        let mut allowed = 0;
        for task in in_flight {
            match task.await.expect("join") {
                Ok(token) => {
                    allowed += 1;
                    assert_eq!(
                        token.reservation().expect("reserved").amount().minor(),
                        15_000
                    );
                }
                Err(err) => assert_eq!(
                    err.code(),
                    DenyReason::DailyLimit.code(),
                    "the day's ceiling is the only thing that can refuse this"
                ),
            }
        }

        assert_eq!(
            allowed, 1,
            "both payments were allowed: the day's policy cap was decided on a \
             read that takes no lock"
        );
        assert_eq!(
            reserved_today(&db, &principal).await,
            25_000,
            "the bucket is over the policy's max_per_day of 30_000"
        );
        assert_eq!(reservation_count(&db, &principal).await, 2);
    }

    #[test]
    fn a_counterparty_exists_for_exactly_the_addressed_actions() {
        assert_eq!(
            counterparty(&email("a@example.com")).as_deref(),
            Some("a@example.com")
        );
        assert_eq!(counterparty(&payment(1)), None);
        assert_eq!(
            counterparty(&Action::DataDelete {
                scope: agentos_domain::action::DataScope::Conversation {
                    id: agentos_domain::ids::ConversationId::from_uuid(Uuid::nil())
                }
            }),
            None
        );
        // A colleague is not a counterparty. If this were `Some`, the first
        // message to each colleague would spend one of the day's cold contacts,
        // and an employee that had talked to twenty suppliers could no longer
        // ask its own manager a question.
        assert_eq!(
            counterparty(&Action::InternalSend {
                to: Slug::parse("bruno").expect("slug")
            }),
            None
        );
    }

    /// The other half of that promise: the internal channel is judged on the
    /// channel allowlist alone, so an employee whose cold-outreach budget is
    /// spent can still talk to its team.
    #[test]
    fn an_exhausted_contact_budget_does_not_silence_the_internal_channel() {
        let limits = PolicyLimits {
            allowed_channels: BTreeSet::from([Channel::Email, Channel::Internal]),
            max_new_contacts_per_day: 1,
            ..PolicyLimits::default()
        };
        let policy =
            agentos_domain::policy::EffectivePolicy::try_new(&limits, &limits, &limits, &limits)
                .expect("coherent");
        let spent = ActionCtx {
            trust: TrustLabel::Trusted,
            contact: ContactStanding::New,
            new_contacts_today: 50,
            ..ActionCtx::new(
                Actor::new(
                    TenantId::from_uuid(Uuid::nil()),
                    EmployeeId::from_uuid(Uuid::nil()),
                ),
                Utc::now(),
            )
        };

        // A stranger: refused, which is the budget doing its job.
        assert!(matches!(
            agentos_domain::policy::evaluate(&policy, &email("new@example.com"), &spent),
            agentos_domain::policy::Decision::Deny {
                reason: DenyReason::ContactBudgetExhausted
            }
        ));
        // A colleague: allowed.
        assert!(
            agentos_domain::policy::evaluate(
                &policy,
                &Action::InternalSend {
                    to: Slug::parse("bruno").expect("slug")
                },
                &spent,
            )
            .is_allow()
        );
    }

    // -- the company-wide stop ---------------------------------------------

    /// Stop the company, the way `routes::halt` does.
    async fn stop(db: &Db, principal: &Principal, reason: &str) {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        halt::place(&mut tx, reason, "operator:ops-console", Utc::now())
            .await
            .expect("place the halt")
            .expect("it was not already halted");
        tx.commit().await.expect("commit the halt");
    }

    /// Let it run again.
    async fn resume(db: &Db, principal: &Principal) {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        halt::release(&mut tx)
            .await
            .expect("release the halt")
            .expect("it was halted");
        tx.commit().await.expect("commit the release");
    }

    /// **The switch.** The same action, the same policy, the same employee: it
    /// is allowed, then the company is stopped and it is refused, then the
    /// company is released and it is allowed again.
    ///
    /// The policy is installed and never touched, which is the half that makes
    /// this a *halt* rather than a permission edit — the ruling flips twice
    /// while `policy_layers` holds still.
    #[tokio::test]
    async fn a_halt_refuses_what_the_policy_allows_and_the_release_gives_it_back() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        let gate = gate(&db, &principal).await;

        gate.authorize(&principal, email("supplier@example.com"))
            .await
            .expect("email is allowed while the company is running");

        stop(&db, &principal, "the CFO called: stop everything").await;

        let err = gate
            .authorize(&principal, email("supplier@example.com"))
            .await
            .expect_err("a stopped company authorises nothing");
        assert!(
            matches!(&err, Denied::Halted(reason) if reason == "the CFO called: stop everything"),
            "the refusal carries the operator's own sentence: {err:?}"
        );
        assert_eq!(err.code(), audit::COMPANY_HALTED);

        resume(&db, &principal).await;

        gate.authorize(&principal, email("supplier@example.com"))
            .await
            .expect("the release gives back exactly what the halt took");
    }

    /// A halt is refused *before* the policy is read, the same way a suspension
    /// is — and the audit row proves which refusal it was.
    ///
    /// The employee here is `draft`, so a gate that consulted the lifecycle
    /// first would answer `employee_not_active`. It answers `company_halted`,
    /// which is only possible if the halt was read before anything about the
    /// seat was.
    #[tokio::test]
    async fn the_halt_is_read_before_the_employee_and_before_the_policy() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "draft").await;
        let gate = gate(&db, &principal).await;
        stop(&db, &principal, "runaway agent").await;

        let err = gate
            .authorize(&principal, email("supplier@example.com"))
            .await
            .expect_err("stopped");
        assert_eq!(
            err.code(),
            audit::COMPANY_HALTED,
            "the company is read before the seat, so a draft employee in a stopped \
             company is refused for the company: {err:?}"
        );

        let rows = audit_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1, "exactly one audit row: {rows:?}");
        assert_eq!(rows[0].2[DENIED_KEY], json!(audit::COMPANY_HALTED));
        assert_eq!(rows[0].2["halt_reason"], json!("runaway agent"));
        assert_eq!(
            rows[0].2[COUNTERPARTY_KEY],
            json!("supplier@example.com"),
            "the counterparty is still recorded: `what did not happen, and to whom` \
             is the question after the incident"
        );
    }

    /// **The hard constraint: one tenant can never stop another.**
    ///
    /// Two companies, one halted. The other's identical action is still
    /// allowed. This is not a `WHERE` clause being right — `company_halts` has
    /// row-level security forced, and the gate reads it through a `tenant_tx`,
    /// so the halted row is not merely filtered out of the other company's
    /// query, it is invisible to it.
    #[tokio::test]
    async fn one_company_s_halt_does_not_touch_another_s() {
        let Some(db) = db().await else { return };
        let stopped = seed(&db, "active").await;
        let running = seed(&db, "active").await;
        let stopped_gate = gate(&db, &stopped).await;
        let running_gate = gate(&db, &running).await;

        stop(&db, &stopped, "not your company").await;

        let err = stopped_gate
            .authorize(&stopped, email("supplier@example.com"))
            .await
            .expect_err("its own company is stopped");
        assert_eq!(err.code(), audit::COMPANY_HALTED);

        running_gate
            .authorize(&running, email("supplier@example.com"))
            .await
            .expect("a neighbour's emergency is not this company's emergency");

        // And the neighbour cannot even see the row, let alone be stopped by
        // it: RLS, not a filter.
        let mut tx = db.tenant_tx(running.tenant_id).await.expect("tx");
        assert_eq!(
            halt::halted(&mut tx).await.expect("read"),
            None,
            "the other company's halt is invisible from here"
        );
        tx.rollback().await.expect("rollback");
    }

    /// **The pending-approval hole, closed.** A human approval is a permission
    /// the policy already granted, parked until somebody clicks — so it reaches
    /// the world through `redeem_approval`, which never calls `decide` and would
    /// therefore have walked straight past a halt installed only there.
    ///
    /// And the approval *survives*: refused, not consumed, so the same nonce
    /// works the moment the company is released. A halt that destroyed every
    /// pending approval would make coming back up the expensive half.
    #[tokio::test]
    async fn a_halt_refuses_an_approval_without_burning_it() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        // €250 per transaction, human above €200: a €210 payment escalates.
        let gate = gate(&db, &principal).await;
        give_caps(&db, &principal, 100_000, 100_000).await;

        let Err(Denied::PendingApproval(id)) = gate.authorize(&principal, payment(21_000)).await
        else {
            panic!("a payment above the approval threshold should have been escalated");
        };
        let nonce = nonce_of(&db, &principal, id).await;

        stop(&db, &principal, "stop everything").await;

        let err = gate
            .redeem_approval(&principal, id, &nonce, payment(21_000))
            .await
            .expect_err("a stopped company does not let a human spend an approval");
        assert_eq!(
            err.code(),
            audit::COMPANY_HALTED,
            "and it is refused for the halt, not for the approval: {err:?}"
        );

        resume(&db, &principal).await;

        gate.redeem_approval(&principal, id, &nonce, payment(21_000))
            .await
            .expect("the approval was refused, not burned: the same nonce still works");
    }

    /// **Nothing widens, in either direction.** The effective policy is read
    /// before the halt, during it, and after the release, and all three are the
    /// same value.
    ///
    /// This is the property the whole design turns on and the reason a halt is
    /// not an empty policy layer: halting writes no `policy_layers` row, so
    /// releasing has no saved copy to restore wrong. A halt implemented as
    /// "install an empty tenant layer" would make this test's third read depend
    /// on code remembering what the company used to be allowed to do.
    #[tokio::test]
    async fn a_halt_and_its_release_do_not_move_one_number_in_the_policy() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        let _gate = gate(&db, &principal).await;

        async fn effective(db: &Db, principal: &Principal) -> agentos_domain::policy::PolicyLimits {
            let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
            let policy = policy_store::load(&mut tx, principal.employee_id)
                .await
                .expect("load");
            tx.rollback().await.expect("rollback");
            policy.limits().clone()
        }

        let before = effective(&db, &principal).await;
        stop(&db, &principal, "stop").await;
        let during = effective(&db, &principal).await;
        resume(&db, &principal).await;
        let after = effective(&db, &principal).await;

        assert_eq!(before, during, "a halt is not a policy edit");
        assert_eq!(
            before, after,
            "and a release restores nothing, because it took nothing away"
        );
    }

    /// Re-halting says so rather than overwriting the first operator's reason,
    /// and releasing a running company says so rather than reporting success.
    ///
    /// Both matter for the same reason: two people reach for this switch in the
    /// same minute, and the one whose sentence is on the record must be the one
    /// the record names.
    #[tokio::test]
    async fn the_switch_is_honest_about_what_it_did_not_do() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;

        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        assert!(
            halt::release(&mut tx).await.expect("release").is_none(),
            "releasing a company that is running changed nothing"
        );
        halt::place(&mut tx, "first", "operator:alice", Utc::now())
            .await
            .expect("place")
            .expect("it was running");
        assert!(
            halt::place(&mut tx, "second", "operator:bob", Utc::now())
                .await
                .expect("place")
                .is_none(),
            "the second caller is told it changed nothing"
        );
        let held = halt::halted(&mut tx).await.expect("read").expect("halted");
        assert_eq!(held.reason, "first", "the first operator's reason stands");
        assert_eq!(held.halted_by, "operator:alice");
        tx.rollback().await.expect("rollback");
    }
}
