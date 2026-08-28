//! The employee state machine.
//!
//! Two things that look like one thing are kept apart here, because conflating
//! them is what once let a suspended employee with zero resources render as
//! "online":
//!
//! * [`Lifecycle`] is **stored**. It changes only when an operator says so.
//! * [`Health`] is **derived** from the resource map on every read. It is never
//!   stored, so it cannot go stale, and there is no setter for it.
//!
//! The resource map is total by construction: [`Employee::new`] fills all
//! eleven [`Step`]s, the map is private, and [`Employee`] deliberately does not
//! implement `Deserialize` — so no row, no payload and no test helper can
//! produce an employee with a missing or empty map. "Zero resources" is not a
//! state you can reach; it is a state you cannot spell.
//!
//! Nothing here reads the clock. Every mutator takes `now`.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::{Domain, EmailAddress};
use crate::ids::{EmployeeId, Slug, TenantId};

// ---------------------------------------------------------------------------
// Lifecycle — stored, operator-driven
// ---------------------------------------------------------------------------

/// Where an employee sits in its administrative life. Stored, and only an
/// explicit operator action moves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Created, not yet released to work.
    Draft,
    /// Allowed to act. The only lifecycle that can ever be [`Health::Online`].
    Active,
    /// Paused by an operator. Resources survive; the employee must not act.
    Suspended,
    /// End of life. Absorbing — nothing transitions out of it.
    Terminated,
}

impl Lifecycle {
    /// The legal operator transitions, as a table.
    ///
    /// Exhaustive over `self` on purpose: a new lifecycle is a compile error
    /// here rather than a silently unreachable state.
    fn can_move_to(self, to: Lifecycle) -> bool {
        if self == to {
            return true; // re-asserting the current lifecycle is a no-op
        }
        match self {
            Lifecycle::Draft => matches!(to, Lifecycle::Active | Lifecycle::Terminated),
            Lifecycle::Active => matches!(to, Lifecycle::Suspended | Lifecycle::Terminated),
            Lifecycle::Suspended => matches!(to, Lifecycle::Active | Lifecycle::Terminated),
            Lifecycle::Terminated => false,
        }
    }

    /// Stable wire/storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Lifecycle::Draft => "draft",
            Lifecycle::Active => "active",
            Lifecycle::Suspended => "suspended",
            Lifecycle::Terminated => "terminated",
        }
    }
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Health — derived, never stored
// ---------------------------------------------------------------------------

/// Operational readiness, computed from the resource map by
/// [`Employee::health`]. There is no constructor call site outside this module
/// and no field to persist it into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// At least one blocking resource is not ready yet.
    Provisioning,
    /// Every blocking resource is ready, some optional channel is not.
    Degraded,
    /// Everything blocking is ready and nothing optional is outstanding.
    Online,
    /// A blocking resource is in a terminal failure.
    Failed,
}

impl Health {
    /// Stable wire/storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Health::Provisioning => "provisioning",
            Health::Degraded => "degraded",
            Health::Online => "online",
            Health::Failed => "failed",
        }
    }
}

impl fmt::Display for Health {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Step
// ---------------------------------------------------------------------------

/// One provisioning step. The eleven of these are the whole capability surface
/// of an employee.
///
/// Every match on `Step` in this module is exhaustive with no `_` arm, so
/// adding a twelfth step breaks the build in each place that has to make a
/// decision about it — dependencies, blocking-ness, naming — instead of
/// silently inheriting someone's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Machine identity: ids, keys, DID. The root of everything else.
    Identity,
    /// Mailbox and sending domain.
    Email,
    /// E.164 number and webhook binding.
    Phone,
    /// WhatsApp sender or routed company sender.
    Whatsapp,
    /// Spending wallet — **a local binding, not an account anywhere**.
    ///
    /// `app::provisioning` answers this step with `local(employee, "wallet")`
    /// and `adapter_of` gives it no adapter, so nothing is created, nothing is
    /// funded and nothing is billed; the row *is* the resource, which is why
    /// releasing it is a no-op. What the row does is switch a capability on and
    /// off: `Ready` puts the "Purchasing" skill on the employee's A2A card and
    /// `Disabled` takes it off again.
    ///
    /// The word "wallet" is the intent and the direction — this employee
    /// **pays**, it is never paid at this step — and `agentos_app::x402`
    /// argues why that makes this deployment the client of a paid API and not
    /// the seller of one. Nothing here holds a key: `SPEC.md` §13's standing
    /// rule is that a model never holds a private key, and the honest
    /// consequence is that this step provisions a promise the payment port has
    /// not been configured to keep.
    Wallet,
    /// Isolated browser context.
    Browser,
    /// Secret storage for this employee.
    Vault,
    /// Ingested company knowledge.
    CompanyKnowledge,
    /// Connected MCP servers.
    Mcp,
    /// Agent-to-agent identity and gateway registration.
    A2a,
    /// Effective policy bound to the employee.
    Permissions,
}

impl Step {
    /// Every step, in the order the provisioning workflow runs them.
    pub const ALL: [Step; 11] = [
        Step::Identity,
        Step::Email,
        Step::Phone,
        Step::Whatsapp,
        Step::Wallet,
        Step::Browser,
        Step::Vault,
        Step::CompanyKnowledge,
        Step::Mcp,
        Step::A2a,
        Step::Permissions,
    ];

    /// Steps that must be [`ResourceState::Ready`] before this one can be.
    ///
    /// `Identity` is the single root; every other step names it directly, so
    /// "identity precedes everything" is a local fact, not a transitive one you
    /// have to trust a traversal to preserve.
    pub const fn depends_on(self) -> &'static [Step] {
        match self {
            Step::Identity => &[],
            Step::Email
            | Step::Phone
            | Step::Whatsapp
            | Step::Wallet
            | Step::Vault
            | Step::CompanyKnowledge
            | Step::Mcp
            | Step::A2a
            | Step::Permissions => &[Step::Identity],
            // The browser context loads credentials out of the vault, so a
            // browser without a vault is a browser that will type secrets it
            // does not have.
            Step::Browser => &[Step::Identity, Step::Vault],
        }
    }

    /// Blocking steps gate [`Health::Online`]; the rest are optional channels
    /// whose absence only degrades.
    pub const fn is_blocking(self) -> bool {
        match self {
            // Identity, a channel to be reached on, somewhere to keep secrets,
            // and a policy to act under. Without all four there is no employee.
            Step::Identity | Step::Email | Step::Vault | Step::Permissions => true,
            Step::Phone
            | Step::Whatsapp
            | Step::Wallet
            | Step::Browser
            | Step::CompanyKnowledge
            | Step::Mcp
            | Step::A2a => false,
        }
    }

    /// Stable wire/storage spelling. Also the step name in an
    /// [`crate::ids::IdempotencyKey`], so it must never change.
    pub const fn as_str(self) -> &'static str {
        match self {
            Step::Identity => "identity",
            Step::Email => "email",
            Step::Phone => "phone",
            Step::Whatsapp => "whatsapp",
            Step::Wallet => "wallet",
            Step::Browser => "browser",
            Step::Vault => "vault",
            Step::CompanyKnowledge => "company_knowledge",
            Step::Mcp => "mcp",
            Step::A2a => "a2a",
            Step::Permissions => "permissions",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ResourceState
// ---------------------------------------------------------------------------

/// The state of one provisioned resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResourceState {
    /// Nothing attempted yet.
    Pending,
    /// A provisioning attempt is in flight.
    Provisioning,
    /// Confirmed by the provider. Only this state may be shown as ready.
    Ready,
    /// Waiting on a process outside our control: a Twilio regulatory bundle, a
    /// WhatsApp sender review, a domain verification, a KYB decision.
    ///
    /// While pending there is **no resource yet** — no phone number, no
    /// external id — so the state carries the thing to poll and the instant
    /// after which the wait is a problem rather than a normal delay. Without
    /// `expected_by` an employee rots here and nobody notices; see
    /// [`Employee::overdue`].
    PendingExternal {
        /// Provider-side handle to poll or correlate callbacks against (bundle
        /// sid, review id, verification token).
        poll_ref: String,
        /// After this instant the wait is overdue and needs a human.
        expected_by: DateTime<Utc>,
    },
    /// Terminal failure. Only retry moves it.
    Failed,
    /// Deliberately switched off for this employee. Not an error, and not a
    /// reason to withhold [`Health::Online`].
    Disabled,
}

impl ResourceState {
    /// Stable wire/storage spelling of the variant.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ResourceState::Pending => "pending",
            ResourceState::Provisioning => "provisioning",
            ResourceState::Ready => "ready",
            ResourceState::PendingExternal { .. } => "pending_external",
            ResourceState::Failed => "failed",
            ResourceState::Disabled => "disabled",
        }
    }

    /// The legal transition table, exhaustive over the source state.
    ///
    /// Read it as: what may happen to a resource that is currently `self`.
    fn can_move_to(&self, to: &ResourceState) -> bool {
        use ResourceState as S;
        // Re-asserting a state is always allowed: every `ensure_*` step is
        // idempotent, and a `pending_external` refresh carries a new poll ref.
        if self.as_str() == to.as_str() {
            return true;
        }
        match self {
            S::Pending => matches!(
                to,
                S::Provisioning | S::PendingExternal { .. } | S::Failed | S::Disabled
            ),
            S::Provisioning => matches!(
                to,
                S::Ready | S::PendingExternal { .. } | S::Failed | S::Disabled
            ),
            // The provider callback that resolves the wait, a retry, a
            // rejection, or an operator giving up on the channel.
            S::PendingExternal { .. } => {
                matches!(to, S::Ready | S::Provisioning | S::Failed | S::Disabled)
            }
            // Rotation re-provisions; revocation fails or disables it. Ready
            // never falls back to Pending — that would lose the fact that a
            // resource was once real.
            S::Ready => matches!(to, S::Provisioning | S::Failed | S::Disabled),
            S::Failed => matches!(to, S::Pending | S::Provisioning | S::Disabled),
            S::Disabled => matches!(to, S::Pending | S::Provisioning),
        }
    }
}

// ---------------------------------------------------------------------------
// ProviderBinding
// ---------------------------------------------------------------------------

/// The provider-side identity of a resource we are being billed for.
///
/// Write-once: see [`Employee::bind`] / [`Employee::release`]. Dropping an
/// `external_id` does not free the resource, it only makes it invisible — the
/// phone number stays bought, the wallet stays funded, the invoice keeps
/// arriving, and nobody knows what to cancel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderBinding {
    provider: String,
    external_id: String,
}

impl ProviderBinding {
    /// Record which provider issued which id.
    pub fn new(provider: impl Into<String>, external_id: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            external_id: external_id.into(),
        }
    }

    /// Adapter that owns the resource (`twilio`, `stripe`, `browserbase`).
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The provider's id for the resource. Never derive this; never rebuild it.
    pub fn external_id(&self) -> &str {
        &self.external_id
    }
}

/// [`Employee::bind`] refused because the resource already has an id.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{step} is already bound to {provider}:{external_id}; release it first")]
pub struct AlreadyBound {
    /// The step that is already bound.
    pub step: Step,
    /// Provider holding the existing binding.
    pub provider: String,
    /// External id we would have overwritten.
    pub external_id: String,
}

// ---------------------------------------------------------------------------
// ResourceStatus
// ---------------------------------------------------------------------------

/// One row of the resource map: what state the resource is in, what it is bound
/// to at the provider, and when that last changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceStatus {
    state: ResourceState,
    binding: Option<ProviderBinding>,
    updated_at: DateTime<Utc>,
}

impl ResourceStatus {
    /// Rebuild a status from storage.
    pub const fn new(
        state: ResourceState,
        binding: Option<ProviderBinding>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            state,
            binding,
            updated_at,
        }
    }

    /// Current state.
    pub const fn state(&self) -> &ResourceState {
        &self.state
    }

    /// Provider binding, if one was ever acquired. Survives every state change.
    pub const fn binding(&self) -> Option<&ProviderBinding> {
        self.binding.as_ref()
    }

    /// When this row last changed.
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// True once the provider has confirmed the resource.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, ResourceState::Ready)
    }
}

/// Why a requested resource transition was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IllegalTransition {
    /// The transition is not in [`ResourceState::can_move_to`].
    #[error("{step}: cannot move from {from} to {to}")]
    State {
        /// The step whose resource was targeted.
        step: Step,
        /// State it is in.
        from: &'static str,
        /// State the caller asked for.
        to: &'static str,
    },
    /// A step tried to become ready before something it needs.
    #[error("{step} cannot become ready while {blocker} is not ready")]
    DependencyNotReady {
        /// The step that tried to become ready.
        step: Step,
        /// The unmet dependency.
        blocker: Step,
    },
}

/// Why a lifecycle change was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("lifecycle cannot move from {from} to {to}")]
pub struct IllegalLifecycle {
    /// Lifecycle the employee is in.
    pub from: Lifecycle,
    /// Lifecycle the operator asked for.
    pub to: Lifecycle,
}

// ---------------------------------------------------------------------------
// Employee
// ---------------------------------------------------------------------------

/// One AI employee: a stable identity plus a total map of its eleven resources.
///
/// Note the missing `Deserialize`. Every other type in this module round-trips
/// through serde; `Employee` does not, because a derived `Deserialize` would
/// accept `{"resources": {}}` and hand back the exact object this module exists
/// to make unrepresentable. Storage rehydrates through [`Employee::hydrate`],
/// which starts from a complete map and can only overwrite entries in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Employee {
    id: EmployeeId,
    tenant_id: TenantId,
    slug: Slug,
    domain: Domain,
    address: EmailAddress,
    did: String,
    lifecycle: Lifecycle,
    resources: BTreeMap<Step, ResourceStatus>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Employee {
    /// A fresh [`Lifecycle::Draft`] employee with all eleven resources
    /// [`ResourceState::Pending`].
    ///
    /// `address` and `did` are derived here, once, from the slug and domain.
    /// Both inputs are pre-validated newtypes, so the address cannot fail to
    /// parse: a [`Slug`] is `[a-z0-9-]{2,32}` with no leading, trailing or
    /// doubled hyphen, which is a strict subset of a legal email local part,
    /// and a [`Domain`] is already normalised.
    pub fn new(
        id: EmployeeId,
        tenant_id: TenantId,
        slug: Slug,
        domain: Domain,
        now: DateTime<Utc>,
    ) -> Self {
        let address = EmailAddress::parse(&format!("{slug}@{domain}"))
            .expect("a Slug is a valid email local part and a Domain is a valid host");
        let did = format!("did:web:{domain}:employees:{}", id.as_uuid());

        let resources = Step::ALL
            .into_iter()
            .map(|step| (step, ResourceStatus::new(ResourceState::Pending, None, now)))
            .collect();

        Self {
            id,
            tenant_id,
            slug,
            domain,
            address,
            did,
            lifecycle: Lifecycle::Draft,
            resources,
            created_at: now,
            updated_at: now,
        }
    }

    /// Rebuild a stored employee.
    ///
    /// Starts from the complete map [`Employee::new`] builds and overwrites the
    /// rows storage actually has, so a truncated `employee_resources` table
    /// yields `Pending` rows rather than an employee with holes in it. Rows for
    /// unknown steps cannot exist — `Step` is a closed enum.
    #[allow(clippy::too_many_arguments)]
    pub fn hydrate(
        id: EmployeeId,
        tenant_id: TenantId,
        slug: Slug,
        domain: Domain,
        lifecycle: Lifecycle,
        resources: impl IntoIterator<Item = (Step, ResourceStatus)>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        let mut employee = Self::new(id, tenant_id, slug, domain, created_at);
        employee.lifecycle = lifecycle;
        employee.updated_at = updated_at;
        for (step, status) in resources {
            employee.resources.insert(step, status);
        }
        employee
    }

    /// Internal id.
    pub const fn id(&self) -> EmployeeId {
        self.id
    }

    /// Owning tenant.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Handle.
    pub const fn slug(&self) -> &Slug {
        &self.slug
    }

    /// Sending/receiving domain.
    pub const fn domain(&self) -> &Domain {
        &self.domain
    }

    /// `slug@domain` — the stable routing identity, which must survive provider
    /// migration.
    pub const fn address(&self) -> &EmailAddress {
        &self.address
    }

    /// `did:web:{host}:employees:{uuid}`.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The stored lifecycle.
    pub const fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }

    /// When the employee was created.
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// When the employee last changed.
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// The whole resource map. Always exactly [`Step::ALL`].
    pub const fn resources(&self) -> &BTreeMap<Step, ResourceStatus> {
        &self.resources
    }

    /// One resource. Infallible: the map is total.
    pub fn resource(&self, step: Step) -> &ResourceStatus {
        self.resources
            .get(&step)
            .expect("resource map is total by construction")
    }

    /// Move a resource, checking the transition table and the dependency edges.
    ///
    /// The binding is never touched here. There is no path through this
    /// function that clears an `external_id`.
    pub fn set_resource(
        &mut self,
        step: Step,
        state: ResourceState,
        now: DateTime<Utc>,
    ) -> Result<(), IllegalTransition> {
        let current = self.resource(step);
        if !current.state.can_move_to(&state) {
            return Err(IllegalTransition::State {
                step,
                from: current.state.as_str(),
                to: state.as_str(),
            });
        }
        if matches!(state, ResourceState::Ready)
            && let Some(&blocker) = step
                .depends_on()
                .iter()
                .find(|dep| !self.resource(**dep).is_ready())
        {
            return Err(IllegalTransition::DependencyNotReady { step, blocker });
        }

        let status = self
            .resources
            .get_mut(&step)
            .expect("resource map is total by construction");
        status.state = state;
        status.updated_at = now;
        self.updated_at = now;
        Ok(())
    }

    /// Attach the provider id for a resource. Succeeds only while unbound.
    ///
    /// Deliberately not idempotent even for an identical id: a second `bind`
    /// means two provisioning attempts raced, and the caller has to find out
    /// which one bought something.
    pub fn bind(
        &mut self,
        step: Step,
        binding: ProviderBinding,
        now: DateTime<Utc>,
    ) -> Result<(), AlreadyBound> {
        let status = self
            .resources
            .get_mut(&step)
            .expect("resource map is total by construction");
        if let Some(existing) = &status.binding {
            return Err(AlreadyBound {
                step,
                provider: existing.provider.clone(),
                external_id: existing.external_id.clone(),
            });
        }
        status.binding = Some(binding);
        status.updated_at = now;
        self.updated_at = now;
        Ok(())
    }

    /// Detach the provider id, returning it so the caller can cancel the
    /// resource at the provider. The only way a binding is ever cleared, and an
    /// explicit act rather than a side effect of any state change.
    pub fn release(&mut self, step: Step, now: DateTime<Utc>) -> Option<ProviderBinding> {
        let status = self
            .resources
            .get_mut(&step)
            .expect("resource map is total by construction");
        let released = status.binding.take();
        if released.is_some() {
            status.updated_at = now;
            self.updated_at = now;
        }
        released
    }

    /// Change the lifecycle. The one operator-driven mutation.
    pub fn set_lifecycle(
        &mut self,
        to: Lifecycle,
        now: DateTime<Utc>,
    ) -> Result<(), IllegalLifecycle> {
        if !self.lifecycle.can_move_to(to) {
            return Err(IllegalLifecycle {
                from: self.lifecycle,
                to,
            });
        }
        self.lifecycle = to;
        self.updated_at = now;
        Ok(())
    }

    /// Derived readiness. Never stored, so it can never disagree with the map.
    ///
    /// A non-[`Lifecycle::Active`] employee never reports [`Health::Online`],
    /// whatever the resources say — a late webhook cannot un-suspend anyone.
    pub fn health(&self) -> Health {
        match self.resource_health() {
            Health::Online if self.lifecycle != Lifecycle::Active => Health::Degraded,
            derived => derived,
        }
    }

    /// Readiness of the resource map alone, ignoring lifecycle.
    fn resource_health(&self) -> Health {
        let (blocking, optional): (Vec<_>, Vec<_>) = Step::ALL
            .into_iter()
            .partition(|step| Step::is_blocking(*step));

        if blocking
            .iter()
            .any(|step| matches!(self.resource(*step).state, ResourceState::Failed))
        {
            return Health::Failed;
        }
        if !blocking.iter().all(|step| self.resource(*step).is_ready()) {
            return Health::Provisioning;
        }
        // Blocking is done. An optional channel that is off on purpose is fine;
        // anything still in flight, waiting or broken is a degradation.
        if optional.iter().any(|step| {
            !matches!(
                self.resource(*step).state,
                ResourceState::Ready | ResourceState::Disabled
            )
        }) {
            return Health::Degraded;
        }
        Health::Online
    }

    /// Steps stuck in [`ResourceState::PendingExternal`] past their
    /// `expected_by`. The sweeper's whole job: a bundle nobody chased is
    /// indistinguishable from a bundle still in review unless someone asks.
    pub fn overdue(&self, now: DateTime<Utc>) -> Vec<Step> {
        self.resources
            .iter()
            .filter(|(_, status)| match &status.state {
                ResourceState::PendingExternal { expected_by, .. } => *expected_by < now,
                ResourceState::Pending
                | ResourceState::Provisioning
                | ResourceState::Ready
                | ResourceState::Failed
                | ResourceState::Disabled => false,
            })
            .map(|(step, _)| *step)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    const T0: i64 = 1_700_000_000;

    fn employee() -> Employee {
        Employee::new(
            EmployeeId::new_v7(at(T0)),
            TenantId::new_v7(at(T0)),
            Slug::parse("lena").unwrap(),
            Domain::parse("agents.example.com").unwrap(),
            at(T0),
        )
    }

    /// Drive an employee to every-resource-ready.
    ///
    /// Ready is applied by fixpoint rather than in `Step::ALL` order, because
    /// the workflow order is not the dependency order — `Browser` is listed
    /// before the `Vault` it needs. That the loop terminates at all is itself a
    /// check that the graph is acyclic.
    fn all_ready() -> Employee {
        let mut e = employee();
        for step in Step::ALL {
            e.set_resource(step, ResourceState::Provisioning, at(T0 + 1))
                .unwrap();
        }
        for round in 0..Step::ALL.len() {
            for step in Step::ALL {
                let _ = e.set_resource(step, ResourceState::Ready, at(T0 + 2 + round as i64));
            }
        }
        assert!(Step::ALL.into_iter().all(|s| e.resource(s).is_ready()));
        e.set_lifecycle(Lifecycle::Active, at(T0 + 20)).unwrap();
        e
    }

    fn pending_external() -> ResourceState {
        ResourceState::PendingExternal {
            poll_ref: "BU-regulatory-bundle-1".to_owned(),
            expected_by: at(T0 + 86_400),
        }
    }

    // -- construction ------------------------------------------------------

    /// An employee with an empty resource map is not something you can build.
    ///
    /// `new` fills all eleven, `hydrate` starts from that same full map, and
    /// `Employee` has no `Deserialize` and no public `resources` field — so
    /// there is no constructor, no serde path and no setter that produces a
    /// partial map. What is left to assert is that the two constructors are
    /// total; the absence of a third is a property of the type.
    #[test]
    fn an_employee_cannot_be_built_with_an_empty_resource_map() {
        let fresh = employee();
        assert_eq!(fresh.resources().len(), Step::ALL.len());
        for step in Step::ALL {
            assert_eq!(*fresh.resource(step).state(), ResourceState::Pending);
        }

        // Even hydrating from a storage read that returned nothing at all.
        let hydrated = Employee::hydrate(
            fresh.id(),
            fresh.tenant_id(),
            fresh.slug().clone(),
            fresh.domain().clone(),
            Lifecycle::Active,
            std::iter::empty(),
            at(T0),
            at(T0),
        );
        assert_eq!(hydrated.resources().len(), Step::ALL.len());
        // ...and it is emphatically not online.
        assert_eq!(hydrated.health(), Health::Provisioning);
    }

    #[test]
    fn new_derives_address_and_did() {
        let id = EmployeeId::new_v7(at(T0));
        let e = Employee::new(
            id,
            TenantId::new_v7(at(T0)),
            Slug::parse("LeNa").unwrap(),
            Domain::parse("Agents.Example.COM.").unwrap(),
            at(T0),
        );

        assert_eq!(e.address().to_string(), "lena@agents.example.com");
        assert_eq!(
            e.did(),
            format!("did:web:agents.example.com:employees:{}", id.as_uuid())
        );
        assert_eq!(e.lifecycle(), Lifecycle::Draft);
        assert_eq!(e.created_at(), at(T0));
    }

    // -- health ------------------------------------------------------------

    #[test]
    fn health_is_online_when_everything_is_ready() {
        assert_eq!(all_ready().health(), Health::Online);
    }

    #[test]
    fn health_is_degraded_when_an_optional_channel_waits_on_an_external_process() {
        let mut e = all_ready();
        // A ready sender put back into provider review re-provisions first;
        // `ready -> pending_external` directly is not a legal edge.
        e.set_resource(Step::Whatsapp, ResourceState::Provisioning, at(T0 + 9))
            .unwrap();
        e.set_resource(Step::Whatsapp, pending_external(), at(T0 + 10))
            .unwrap();

        assert!(!Step::Whatsapp.is_blocking());
        assert_eq!(e.health(), Health::Degraded);
    }

    #[test]
    fn health_is_failed_when_a_blocking_step_failed() {
        let mut e = all_ready();
        e.set_resource(Step::Vault, ResourceState::Failed, at(T0 + 10))
            .unwrap();

        assert!(Step::Vault.is_blocking());
        assert_eq!(e.health(), Health::Failed);
    }

    #[test]
    fn a_disabled_optional_channel_does_not_degrade() {
        let mut e = all_ready();
        e.set_resource(Step::Wallet, ResourceState::Disabled, at(T0 + 10))
            .unwrap();

        assert_eq!(e.health(), Health::Online);
    }

    #[test]
    fn a_failed_optional_channel_only_degrades() {
        let mut e = all_ready();
        e.set_resource(Step::Mcp, ResourceState::Failed, at(T0 + 10))
            .unwrap();

        assert_eq!(e.health(), Health::Degraded);
    }

    // -- lifecycle vs health ----------------------------------------------

    /// The regression this module exists for: a webhook lands after an operator
    /// suspended the employee. It may update the resource — we still want the
    /// external id and the truth about the provider — but it must not put the
    /// employee back to work.
    #[test]
    fn a_late_webhook_never_un_suspends_an_employee() {
        let mut e = all_ready();
        e.set_resource(Step::Whatsapp, ResourceState::Provisioning, at(T0 + 9))
            .unwrap();
        e.set_resource(Step::Whatsapp, pending_external(), at(T0 + 10))
            .unwrap();
        e.set_lifecycle(Lifecycle::Suspended, at(T0 + 20)).unwrap();

        // The provider finally approves the sender.
        e.set_resource(Step::Whatsapp, ResourceState::Ready, at(T0 + 30))
            .unwrap();
        e.bind(
            Step::Whatsapp,
            ProviderBinding::new("twilio", "MG-whatsapp-1"),
            at(T0 + 30),
        )
        .unwrap();

        assert_eq!(e.lifecycle(), Lifecycle::Suspended);
        assert_ne!(e.health(), Health::Online);
        assert_eq!(e.resource(Step::Whatsapp).state(), &ResourceState::Ready);

        // Only an operator brings it back.
        e.set_lifecycle(Lifecycle::Active, at(T0 + 40)).unwrap();
        assert_eq!(e.health(), Health::Online);
    }

    #[test]
    fn draft_and_terminated_are_never_online() {
        let mut e = all_ready();
        e.set_lifecycle(Lifecycle::Terminated, at(T0 + 10)).unwrap();
        assert_ne!(e.health(), Health::Online);

        // Terminated is absorbing.
        assert_eq!(
            e.set_lifecycle(Lifecycle::Active, at(T0 + 20)),
            Err(IllegalLifecycle {
                from: Lifecycle::Terminated,
                to: Lifecycle::Active,
            })
        );
    }

    // -- transitions -------------------------------------------------------

    #[test]
    fn illegal_resource_transitions_are_refused() {
        let mut e = employee();

        // Pending -> Ready skips provisioning entirely.
        assert_eq!(
            e.set_resource(Step::Identity, ResourceState::Ready, at(T0 + 1)),
            Err(IllegalTransition::State {
                step: Step::Identity,
                from: "pending",
                to: "ready",
            })
        );

        // Ready never falls back to Pending.
        e.set_resource(Step::Identity, ResourceState::Provisioning, at(T0 + 1))
            .unwrap();
        e.set_resource(Step::Identity, ResourceState::Ready, at(T0 + 2))
            .unwrap();
        assert!(
            e.set_resource(Step::Identity, ResourceState::Pending, at(T0 + 3))
                .is_err()
        );
    }

    #[test]
    fn a_step_cannot_become_ready_before_what_it_depends_on() {
        let mut e = employee();
        e.set_resource(Step::Browser, ResourceState::Provisioning, at(T0 + 1))
            .unwrap();

        assert_eq!(
            e.set_resource(Step::Browser, ResourceState::Ready, at(T0 + 2)),
            Err(IllegalTransition::DependencyNotReady {
                step: Step::Browser,
                blocker: Step::Identity,
            })
        );
    }

    #[test]
    fn re_asserting_a_state_is_idempotent_and_refreshes_pending_external() {
        let mut e = employee();
        e.set_resource(Step::Phone, ResourceState::Provisioning, at(T0 + 1))
            .unwrap();
        e.set_resource(Step::Phone, pending_external(), at(T0 + 2))
            .unwrap();

        let refreshed = ResourceState::PendingExternal {
            poll_ref: "BU-regulatory-bundle-2".to_owned(),
            expected_by: at(T0 + 200_000),
        };
        e.set_resource(Step::Phone, refreshed.clone(), at(T0 + 3))
            .unwrap();
        assert_eq!(e.resource(Step::Phone).state(), &refreshed);
    }

    #[test]
    fn pending_external_carries_no_number_and_expires() {
        let mut e = employee();
        e.set_resource(Step::Phone, ResourceState::Provisioning, at(T0 + 1))
            .unwrap();
        e.set_resource(Step::Phone, pending_external(), at(T0 + 2))
            .unwrap();

        // No number exists yet, so no binding exists yet.
        assert!(e.resource(Step::Phone).binding().is_none());
        assert!(e.overdue(at(T0 + 100)).is_empty());
        assert_eq!(e.overdue(at(T0 + 86_401)), vec![Step::Phone]);
    }

    // -- bindings ----------------------------------------------------------

    #[test]
    fn a_binding_is_write_once_and_only_release_clears_it() {
        let mut e = employee();
        e.bind(
            Step::Phone,
            ProviderBinding::new("twilio", "PN-1"),
            at(T0 + 1),
        )
        .unwrap();

        assert_eq!(
            e.bind(
                Step::Phone,
                ProviderBinding::new("twilio", "PN-2"),
                at(T0 + 2)
            ),
            Err(AlreadyBound {
                step: Step::Phone,
                provider: "twilio".to_owned(),
                external_id: "PN-1".to_owned(),
            })
        );
        assert_eq!(
            e.resource(Step::Phone).binding().unwrap().external_id(),
            "PN-1"
        );

        let released = e.release(Step::Phone, at(T0 + 3)).unwrap();
        assert_eq!(released.external_id(), "PN-1");
        assert!(e.resource(Step::Phone).binding().is_none());
        // Only now may a new id be recorded.
        e.bind(
            Step::Phone,
            ProviderBinding::new("twilio", "PN-2"),
            at(T0 + 4),
        )
        .unwrap();
    }

    // -- step graph --------------------------------------------------------

    #[test]
    fn the_dependency_graph_is_acyclic_and_identity_is_its_only_root() {
        fn reaches(from: Step, target: Step, depth: usize) -> bool {
            assert!(depth <= Step::ALL.len(), "cycle reached from {from}");
            from.depends_on()
                .iter()
                .any(|dep| *dep == target || reaches(*dep, target, depth + 1))
        }

        for step in Step::ALL {
            // No cycle: walking upwards terminates, and nothing depends on
            // itself, directly or transitively.
            assert!(!reaches(step, step, 0), "{step} depends on itself");

            if step == Step::Identity {
                assert!(step.depends_on().is_empty(), "identity must be a root");
            } else {
                assert!(!step.depends_on().is_empty(), "{step} has no root path");
                assert!(reaches(step, Step::Identity, 0), "{step} bypasses identity");
            }
        }

        // Exactly one root.
        let roots: Vec<_> = Step::ALL
            .into_iter()
            .filter(|s| s.depends_on().is_empty())
            .collect();
        assert_eq!(roots, vec![Step::Identity]);
    }

    #[test]
    fn step_names_and_variants_are_unique() {
        let names: HashSet<&str> = Step::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), Step::ALL.len());
        let variants: HashSet<Step> = Step::ALL.into_iter().collect();
        assert_eq!(variants.len(), Step::ALL.len());
    }

    // -- properties --------------------------------------------------------

    fn any_step() -> impl Strategy<Value = Step> {
        prop::sample::select(Step::ALL.to_vec())
    }

    fn any_state() -> impl Strategy<Value = ResourceState> {
        prop_oneof![
            Just(ResourceState::Pending),
            Just(ResourceState::Provisioning),
            Just(ResourceState::Ready),
            Just(ResourceState::Failed),
            Just(ResourceState::Disabled),
            ("[A-Z]{2}[0-9]{4}", 0i64..200_000).prop_map(|(poll_ref, offset)| {
                ResourceState::PendingExternal {
                    poll_ref,
                    expected_by: at(T0 + offset),
                }
            }),
        ]
    }

    fn any_lifecycle() -> impl Strategy<Value = Lifecycle> {
        prop_oneof![
            Just(Lifecycle::Draft),
            Just(Lifecycle::Active),
            Just(Lifecycle::Suspended),
            Just(Lifecycle::Terminated),
        ]
    }

    /// A step change, or an operator lifecycle change.
    #[derive(Debug, Clone)]
    enum Op {
        Resource(Step, ResourceState),
        Lifecycle(Lifecycle),
        Bind(Step, String),
    }

    fn any_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            6 => (any_step(), any_state()).prop_map(|(s, st)| Op::Resource(s, st)),
            2 => (any_step(), "[A-Z]{2}-[0-9]{3}").prop_map(|(s, id)| Op::Bind(s, id)),
            1 => any_lifecycle().prop_map(Op::Lifecycle),
        ]
    }

    /// Apply an op, ignoring refusals — refused ops must leave no trace.
    fn apply(e: &mut Employee, op: Op, now: DateTime<Utc>) {
        match op {
            Op::Resource(step, state) => {
                let _ = e.set_resource(step, state, now);
            }
            Op::Bind(step, external_id) => {
                let _ = e.bind(step, ProviderBinding::new("twilio", external_id), now);
            }
            Op::Lifecycle(to) => {
                let _ = e.set_lifecycle(to, now);
            }
        }
    }

    proptest! {
        /// No sequence of state transitions ever clears or rewrites a bound
        /// external id. Only `release` may, and it is not in the op set.
        #[test]
        fn a_bound_external_id_is_never_cleared(ops in prop::collection::vec(any_op(), 0..60)) {
            let mut e = employee();
            let mut bound: BTreeMap<Step, String> = BTreeMap::new();

            for (tick, op) in ops.into_iter().enumerate() {
                let now = at(T0 + 100 + tick as i64);
                apply(&mut e, op, now);

                for step in Step::ALL {
                    let seen = e.resource(step).binding().map(|b| b.external_id().to_owned());
                    if let Some(id) = seen {
                        // First sighting is recorded; later sightings must match.
                        let first = bound.entry(step).or_insert_with(|| id.clone());
                        prop_assert_eq!(&id, first);
                    } else {
                        // Never bound, or we would have recorded it.
                        prop_assert!(!bound.contains_key(&step), "{} lost its external id", step);
                    }
                }
            }
        }

        /// A suspended employee cannot reach `Online` without an operator
        /// explicitly moving it back to `Active` — no webhook storm does it.
        #[test]
        fn suspended_never_reaches_online_without_an_explicit_resume(
            ops in prop::collection::vec(
                prop_oneof![
                    (any_step(), any_state()).prop_map(|(s, st)| Op::Resource(s, st)),
                    (any_step(), "[A-Z]{2}-[0-9]{3}").prop_map(|(s, id)| Op::Bind(s, id)),
                ],
                0..60,
            )
        ) {
            let mut e = all_ready();
            e.set_lifecycle(Lifecycle::Suspended, at(T0 + 50)).unwrap();

            for (tick, op) in ops.into_iter().enumerate() {
                apply(&mut e, op, at(T0 + 100 + tick as i64));
                prop_assert_eq!(e.lifecycle(), Lifecycle::Suspended);
                prop_assert_ne!(e.health(), Health::Online);
            }

            // The explicit resume is the only thing that can restore it.
            e.set_lifecycle(Lifecycle::Active, at(T0 + 1000)).unwrap();
            prop_assert_eq!(e.lifecycle(), Lifecycle::Active);
        }

        /// The map stays total, and `health` never invents `Online` for a
        /// lifecycle that is not `Active`.
        #[test]
        fn the_resource_map_stays_total_and_health_respects_lifecycle(
            ops in prop::collection::vec(any_op(), 0..60)
        ) {
            let mut e = employee();
            for (tick, op) in ops.into_iter().enumerate() {
                apply(&mut e, op, at(T0 + 100 + tick as i64));
                prop_assert_eq!(e.resources().len(), Step::ALL.len());
                if e.lifecycle() != Lifecycle::Active {
                    prop_assert_ne!(e.health(), Health::Online);
                }
            }
        }
    }

    // -- serde -------------------------------------------------------------

    #[test]
    fn resource_state_round_trips_with_its_poll_ref() {
        let state = pending_external();
        let json = serde_json::to_value(&state).unwrap();

        assert_eq!(json["state"], "pending_external");
        assert_eq!(json["poll_ref"], "BU-regulatory-bundle-1");
        assert_eq!(
            serde_json::from_value::<ResourceState>(json).unwrap(),
            state
        );
    }

    #[test]
    fn an_employee_serializes_with_a_derived_health_free_map() {
        let json = serde_json::to_value(all_ready()).unwrap();

        assert_eq!(json["lifecycle"], "active");
        assert_eq!(
            json["resources"]["company_knowledge"]["state"]["state"],
            "ready"
        );
        // Health is derived, so it is not a field that could go stale.
        assert!(json.get("health").is_none());
    }
}
