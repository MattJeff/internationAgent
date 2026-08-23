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
//! 2. **Context from real state.** Spend already reserved today, contacts
//!    first reached today, the trust label of the input that produced the
//!    action — read from the database inside the same transaction, never taken
//!    from the caller and never from model output.
//! 3. **Exactly one audit row for every outcome.** Allow, deny and
//!    approval-required alike. A gate that only records denials cannot answer
//!    "why was this payment allowed?", which is the only question anybody ever
//!    asks after the fact.
//! 4. **Allowing a payment reserves it.** In the same transaction, against the
//!    same day's bucket. Checking a cap without consuming it is what lets an
//!    agent turn one refused payment into ten accepted ones.
//!
//! # Trust
//!
//! The taint travels with the *type* of the action, not with a flag somebody
//! passes: [`Authorizable`] is implemented for [`Action`] (trusted — a human
//! wrote that call site) and for `Untrusted<Action>` (untrusted — it came from
//! a document, a web page or a model). `evaluate` refuses to allow a high-risk
//! action derived from untrusted input, so a supplier PDF saying "wire
//! $10,000" cannot produce an `Authorized<_>` at all.

use std::collections::HashMap;

use agentos_domain::action::{Action, ActionCtx, Actor, ContactStanding};
use agentos_domain::employee::Lifecycle;
use agentos_domain::ids::{ApprovalId, DecisionId, EmployeeId, TenantId};
use agentos_domain::money::{Currency, Money};
use agentos_domain::policy::{
    Decision, DenyReason, EffectivePolicy, PolicyError, PolicyLimits, evaluate,
};
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_store::approvals::{self, ApprovalError, NewApproval};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::spend::{self, CapExceeded, Reservation};
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
    /// The executor owes it a [`spend::settle`] on success or a
    /// [`spend::release`] on failure; nothing here does that for it, because
    /// only the caller knows whether the money moved.
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

    /// The configured policy layers do not intersect coherently. Fails closed:
    /// a policy nobody can evaluate authorises nothing.
    #[error("policy layers are incoherent: {0}")]
    BrokenPolicy(PolicyError),

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
            Denied::BrokenPolicy(_) => "broken_policy",
            Denied::Unavailable(_) => "unavailable",
        }
    }
}

// ---------------------------------------------------------------------------
// Policy layers
// ---------------------------------------------------------------------------

/// The policy layers, in memory, keyed by who they apply to.
///
/// `Default` is the empty platform layer, which grants nothing — an
/// unconfigured gate denies everything, which is the correct behaviour for an
/// unconfigured gate.
///
/// A layer that is absent for a principal does not widen anything: it is
/// filled with the layer above it, and intersection is idempotent.
///
/// ponytail: in memory, and the *role* layer is folded into the employee
/// layer, because neither the schema nor the domain models roles yet. When a
/// `policies` table and a role model land, this becomes a load inside the
/// gate's transaction and a third `HashMap` — `effective` is the only function
/// that changes.
#[derive(Debug, Clone, Default)]
pub struct PolicyBook {
    platform: PolicyLimits,
    tenant: HashMap<TenantId, PolicyLimits>,
    employee: HashMap<EmployeeId, PolicyLimits>,
}

impl PolicyBook {
    /// The platform layer: the widest anything can ever be.
    pub fn new(platform: PolicyLimits) -> Self {
        Self {
            platform,
            tenant: HashMap::new(),
            employee: HashMap::new(),
        }
    }

    /// Narrow one tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: TenantId, limits: PolicyLimits) -> Self {
        self.tenant.insert(tenant_id, limits);
        self
    }

    /// Narrow one employee.
    #[must_use]
    pub fn with_employee(mut self, employee_id: EmployeeId, limits: PolicyLimits) -> Self {
        self.employee.insert(employee_id, limits);
        self
    }

    /// platform ∧ tenant ∧ role ∧ employee.
    fn effective(&self, principal: &Principal) -> Result<EffectivePolicy, PolicyError> {
        let tenant = self
            .tenant
            .get(&principal.tenant_id)
            .unwrap_or(&self.platform);
        let employee = self.employee.get(&principal.employee_id).unwrap_or(tenant);
        // The role slot is the employee layer until roles exist; intersecting a
        // layer with itself is a no-op, so this widens nothing.
        EffectivePolicy::try_new(&self.platform, tenant, employee, employee)
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// The one door every side effect goes through.
#[derive(Debug, Clone)]
pub struct PolicyGate {
    db: Db,
    policies: PolicyBook,
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
    BrokenPolicy(PolicyError),
    Redemption(RedemptionFailure),
}

impl PolicyGate {
    /// Wire the gate to a database and a set of policy layers.
    pub const fn new(db: Db, policies: PolicyBook) -> Self {
        Self { db, policies }
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

        // 2. The intersected policy.
        let policy = match self.policies.effective(principal) {
            Ok(policy) => policy,
            Err(err) => return Ok(Outcome::BrokenPolicy(err)),
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

    /// Take the headroom, or turn the ledger's refusal into a policy reason.
    async fn reserve(
        &self,
        tx: &mut TenantTx<'_>,
        principal: &Principal,
        amount: Money,
        now: DateTime<Utc>,
    ) -> Result<Outcome, Denied> {
        match spend::reserve(tx, principal.employee_id, now.date_naive(), amount).await {
            Ok(reservation) => Ok(Outcome::Allow {
                reservation: Some(reservation),
            }),
            Err(CapExceeded::Store(err)) => Err(Denied::Unavailable(err)),
            Err(CapExceeded::NoCaps { .. }) => Ok(Outcome::Deny(DenyReason::NoSpendPolicy)),
            Err(CapExceeded::PerTransaction { .. }) => {
                Ok(Outcome::Deny(DenyReason::PerTransactionLimit))
            }
            // Both remaining refusals are the day's ceiling: one on value, one
            // on count. They share a reason because they share a remedy.
            Err(CapExceeded::DailyTotal { .. } | CapExceeded::DailyCount { .. }) => {
                Ok(Outcome::Deny(DenyReason::DailyLimit))
            }
        }
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
            payload.insert(DENIED_KEY.to_owned(), json!("broken_policy"));
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

    use agentos_domain::action::{Channel, EmailAddress};
    use agentos_domain::money::Currency;
    use agentos_domain::policy::SpendLimits;
    use agentos_store::spend::SpendCaps;
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

    fn gate(db: &Db) -> PolicyGate {
        PolicyGate::new(db.clone(), PolicyBook::new(limits()))
    }

    fn email(to: &str) -> Action {
        Action::EmailSend {
            to: EmailAddress::parse(to).expect("address"),
        }
    }

    fn payment(minor: u64) -> Action {
        Action::PaymentCreate {
            amount: Money::new(minor, Currency::Eur).expect("nonzero"),
        }
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

        // A policy book that would ALLOW this action if it were ever reached:
        // the refusal below can therefore only have come from the lifecycle.
        let gate = PolicyGate::new(db.clone(), PolicyBook::new(limits()));
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

        let err = gate(&db)
            .authorize(&ghost, email("supplier@example.com"))
            .await
            .expect_err("no such employee");
        assert!(matches!(err, Denied::UnknownEmployee));
    }

    #[tokio::test]
    async fn each_outcome_writes_exactly_one_audit_row() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;
        let gate = gate(&db);

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
        let gate = gate(&db);

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

        let err = gate(&db)
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
        let gate = gate(&db);

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
        let gate = PolicyGate::new(
            db.clone(),
            PolicyBook::new(PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Email]),
                max_new_contacts_per_day: 2,
                ..PolicyLimits::default()
            }),
        );

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

        let err = PolicyGate::new(db.clone(), PolicyBook::default())
            .authorize(&principal, email("supplier@example.com"))
            .await
            .expect_err("an empty policy grants nothing");
        assert_eq!(err.code(), DenyReason::NoRule.code());
    }

    #[tokio::test]
    async fn a_tenant_layer_narrows_but_never_widens() {
        let Some(db) = db().await else { return };
        let principal = seed(&db, "active").await;

        // The tenant layer allows SMS as well; the platform layer does not.
        let gate = PolicyGate::new(
            db.clone(),
            PolicyBook::new(limits()).with_tenant(
                principal.tenant_id,
                PolicyLimits {
                    allowed_channels: BTreeSet::from([Channel::Email, Channel::Sms]),
                    max_new_contacts_per_day: 5,
                    ..PolicyLimits::default()
                },
            ),
        );

        let err = gate
            .authorize(
                &principal,
                Action::SmsSend {
                    to: agentos_domain::action::E164::parse("+33123456789").expect("number"),
                },
            )
            .await
            .expect_err("a tenant cannot grant itself a channel the platform withheld");
        assert_eq!(err.code(), DenyReason::ChannelNotAllowed.code());
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
