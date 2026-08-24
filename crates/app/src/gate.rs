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
//! 1. **Lifecycle before policy.** A suspended employee is refused before any
//!    policy is read. A suspension implemented as "remove its permissions"
//!    leaves behind exactly the permissions nobody remembered to remove.
//! 2. **Context from real state.** The policy itself, spend already reserved
//!    today, contacts first reached today, the trust label of the input that
//!    produced the action — read from the database inside the same
//!    transaction, never taken from the caller and never from model output.
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
use agentos_domain::policy::{Decision, DenyReason, evaluate};
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_store::approvals::{self, ApprovalError, NewApproval};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::org::{self, TeamSpendRefused};
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
    Allow { reservation: Option<Reservation> },
    Deny(DenyReason),
    Approval { id: ApprovalId, decision: Decision },
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
    /// human", and asking it again would only ask again. The two things that
    /// *are* re-checked are the ones a human decision cannot substitute for —
    /// the employee is still active, and the ledger still has the headroom.
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

        let outcome = match self.lifecycle(&mut tx, principal).await? {
            Some(Lifecycle::Active) => {
                self.redeem(&mut tx, principal, approval_id, nonce, &subject, now)
                    .await?
            }
            Some(other) => Outcome::NotActive(other),
            None => Outcome::UnknownEmployee,
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
        //    `None` for the role: `store::policy::load` resolves the role layer
        //    through the employee's team when it has one, and this argument is
        //    the fallback for an employee on no team. There is no role on a
        //    `Principal` and inventing one here would be a second way to answer
        //    a question the org chart already answers. Same call, same
        //    argument, same reasoning as the turn-budget reservation in
        //    `loops::initiative`.
        let policy = match policy_store::load(tx, principal.employee_id, None).await {
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

        // 3. Context, from state, inside this transaction.
        let (new_contacts_today, contact) = self.contacts(tx, principal, action, now).await?;
        let spent_today = match action {
            Action::PaymentCreate { amount } => {
                self.spent_today(tx, principal, amount.currency(), now)
                    .await?
            }
            _ => None,
        };
        let ctx = ActionCtx {
            actor: principal.action_actor(),
            trust,
            contact,
            spent_today,
            new_contacts_today,
            now,
        };

        // 4. The rule.
        match evaluate(&policy, action, &ctx) {
            Decision::Allow => match action {
                // 5. A permitted payment consumes the headroom it was measured
                //    against, here, before the caller can be told yes.
                Action::PaymentCreate { amount } => self.reserve(tx, principal, *amount, now).await,
                _ => Ok(Outcome::Allow { reservation: None }),
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
    /// ponytail: aggregates the whole trail for this employee on every
    /// decision. Correct, and O(rows since the employee was hired). The
    /// upgrade is a `contacts (tenant_id, employee_id, counterparty,
    /// first_seen_at)` table maintained by this same function — do it when the
    /// trail outgrows the index, not before.
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
    async fn reserve(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        amount: Money,
        now: DateTime<Utc>,
    ) -> Result<Outcome, Denied> {
        sqlx::query("SAVEPOINT gate_reservation")
            .execute(&mut ***tx)
            .await
            .map_err(|e| Denied::Unavailable(e.into()))?;

        let refused = match org::reserve(tx, principal.employee_id, now.date_naive(), amount).await
        {
            Ok(reservation) => {
                sqlx::query("RELEASE SAVEPOINT gate_reservation")
                    .execute(&mut ***tx)
                    .await
                    .map_err(|e| Denied::Unavailable(e.into()))?;
                return Ok(Outcome::Allow {
                    reservation: Some(reservation),
                });
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
                Action::PaymentCreate { amount } => self.reserve(tx, principal, *amount, now).await,
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
fn counterparty(action: &Action) -> Option<String> {
    match action {
        Action::EmailSend { to } => Some(to.to_string()),
        Action::SmsSend { to } | Action::WhatsappSend { to } | Action::CallPlace { to } => {
            Some(to.as_str().to_owned())
        }
        Action::A2aSend { peer } => Some(peer.as_str().to_owned()),
        Action::BrowserRead { .. }
        | Action::BrowserWrite { .. }
        | Action::FileUpload { .. }
        | Action::McpCall { .. }
        | Action::PaymentCreate { .. }
        | Action::ContractSign { .. }
        | Action::CredentialChange { .. }
        | Action::DataDelete { .. } => None,
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

    /// How many backends are stuck on a lock inside a statement that touches
    /// `spend_buckets` — which is how the concurrency test below knows a
    /// decision is genuinely mid-flight rather than merely slow.
    ///
    /// Asked through an admin transaction on purpose: `pg_stat_activity` hides
    /// other sessions' `query` text from a non-superuser, and `tenant_tx` runs
    /// as `app_role`.
    async fn waiting_on_a_bucket(db: &Db) -> i64 {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() \
                AND wait_event_type = 'Lock' \
                AND query ILIKE '%spend_buckets%'",
        )
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
        while waiting_on_a_bucket(&db).await == 0 {
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
    }
}
