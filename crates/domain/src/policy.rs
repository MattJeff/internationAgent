//! The policy gate: the one place that decides whether a side effect happens.
//!
//! Two structural commitments, both of which the previous implementation
//! violated and both of which are now enforced by the compiler:
//!
//! 1. **No default-open fallthrough.** [`evaluate`] matches every [`Action`]
//!    variant by name. There is no `_` arm, so the day a sixteenth action is
//!    added the build breaks instead of the action being silently permitted.
//!    The old code ended in `_ => PolicyDecision::Allow`, which is how
//!    "sign this contract" became a thing an employee could do unsupervised.
//! 2. **No policy field the evaluator forgot.** [`evaluate`] destructures
//!    [`PolicyLimits`] field by field with no `..`, so adding a limit that
//!    nothing consults is a compile error, not a silent no-op.
//!
//! Layers combine by **intersection**: platform ∧ tenant ∧ role ∧ employee.
//! Allowlists intersect, denylists union, numeric caps take the minimum,
//! permission flags take the logical AND. A tenant therefore cannot widen a
//! platform limit — the only direction a lower layer can move is tighter.
//!
//! The empty [`PolicyLimits`] grants nothing, so an unconfigured system denies
//! everything. Deny by default is a property of the data, not a rule in the
//! evaluator that someone can forget to write.
//!
//! # The turn budget
//!
//! [`PolicyLimits::max_turns_per_day`] is the one limit here that is *not* an
//! [`Action`], and it exists because every other limit is on money or on tool
//! calls inside one turn. An employee that wakes on a cadence, thinks, reads
//! and writes without ever proposing a payment trips none of them while
//! burning model tokens continuously. Until an initiative loop existed the
//! natural throttle was that a turn only happened when somebody sent something;
//! a loop removes it, so the ceiling has to be written down.
//!
//! It is intersected exactly like the numeric caps — the minimum across
//! platform ∧ tenant ∧ role ∧ employee, so a team can only tighten it — but it
//! is read by [`turns_remaining`] rather than by [`evaluate`], because there is
//! no `Action::TakeTurn` and inventing one would put a non-effect into the
//! audit vocabulary, the tool catalogue and the taint wire for no gain.
//!
//! **Turns, not tokens.** A token cap is the honest unit of an LLM bill and we
//! cannot enforce it: the provider counts tokens, and no reliable count exists
//! *before* the call — which is the only moment a cap can refuse anything. A
//! turn is the thing we can refuse before it costs money, so turns are the
//! proxy, and the multiplier from turns to currency lives outside this
//! workspace with the rate card.
//!
//! # The model allowlist
//!
//! [`PolicyLimits::allowed_models`] is the second limit here that is not an
//! [`Action`], and it is here for the turn budget's reason: the two largest
//! levers on an LLM bill are *how often* an employee thinks and *what it thinks
//! with*, and an operator who can bound one and not the other can only bound
//! half the money. It intersects like every other allowlist — a lower layer
//! narrows, never widens — and [`model_for`] is its evaluator, asked once when a
//! turn is assembled rather than once per action, because a model cannot change
//! inside a turn.
//!
//! The multiplier from a model to currency lives outside this workspace with the
//! rate card, exactly as the multiplier from turns does. What is in here is the
//! *permission*, and the domain deliberately holds no price: `ModelId`'s ordering
//! encodes which models cost more than which, and nothing else.

#![deny(unreachable_patterns)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::{
    Action, ActionCtx, ActionKind, CallingCode, Channel, ContactStanding, DataScope, Domain, E164,
    McpTool,
};
use crate::money::{Currency, Money};

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

/// Which model an employee thinks with.
///
/// # Why this is an enum and not a string
///
/// Every other allowlist in [`PolicyLimits`] is a set of parsed things —
/// [`Channel`], [`CallingCode`], [`Domain`], [`McpTool`] — and none of them is a
/// free string, because an allowlist of free strings cannot tell a typo from a
/// deliberate exclusion. A model name is worse than the others in one specific
/// way: a misspelling in an operator's document would not merely fail to match,
/// it would produce a `PolicyLimits` that names a model no provider serves, and
/// the failure would land at the first model call as a provider 404 that reads
/// like an outage.
///
/// A closed enum makes that a parse error in the operator's file instead.
/// Adding a model is a code change, which is the honest state of affairs: a
/// model with no entry in `agentos_eval::cost`'s rate card is a model whose bill
/// nobody can compute.
///
/// # The ordering is cheapest-first, and it is load-bearing
///
/// `Ord` derives from declaration order, so `BTreeSet<ModelId>` iterates
/// cheapest-first and [`BTreeSet::first`] on an allowlist is *the cheapest model
/// the operator permits*. [`model_for`] relies on exactly that: a role whose
/// preference an operator has excluded falls **down** the price list, never up.
/// Reorder these variants and that guarantee is gone; `the_order_is_the_price_list`
/// is what stops it happening quietly.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum ModelId {
    #[serde(rename = "claude-haiku-4-5")]
    Haiku45,
    #[serde(rename = "claude-sonnet-5")]
    Sonnet5,
    /// The default, because it is what every employee ran before roles could
    /// name a model — a default that changed the bill on upgrade would be a
    /// silent repricing.
    #[default]
    #[serde(rename = "claude-opus-5")]
    Opus5,
    #[serde(rename = "claude-fable-5")]
    Fable5,
}

impl ModelId {
    /// Every model this deployment can name, cheapest first.
    pub const ALL: [ModelId; 4] = [
        ModelId::Haiku45,
        ModelId::Sonnet5,
        ModelId::Opus5,
        ModelId::Fable5,
    ];

    /// What an employee nobody chartered thinks with.
    ///
    /// Its whole job is `turn::UNCHARTERED` — one internal note saying it has
    /// been woken and does not know what it is for. That is the cheapest
    /// sentence in the company and it does not need a frontier model to write
    /// it.
    pub const UNCHARTERED: ModelId = ModelId::Haiku45;

    /// The string the provider is given, verbatim.
    pub const fn as_str(self) -> &'static str {
        match self {
            ModelId::Haiku45 => "claude-haiku-4-5",
            ModelId::Sonnet5 => "claude-sonnet-5",
            ModelId::Opus5 => "claude-opus-5",
            ModelId::Fable5 => "claude-fable-5",
        }
    }

    /// The inverse of [`ModelId::as_str`]. `None` for anything else — a column
    /// or a document naming a model this build does not know is a load failure,
    /// never a silently dropped entry.
    pub fn parse(raw: &str) -> Option<Self> {
        ModelId::ALL.into_iter().find(|m| m.as_str() == raw)
    }

    /// Every model no more expensive than this one, as an allowlist.
    ///
    /// What a role pack ships as its own layer. A role will accept a cheaper
    /// model an operator forces on it and will not accept an *upgrade* past what
    /// its job needs — which is the founder's observation written as a set: a
    /// seller does not need the most expensive model, so a seller's role layer
    /// does not name it.
    pub fn at_most(self) -> BTreeSet<ModelId> {
        ModelId::ALL.into_iter().filter(|m| *m <= self).collect()
    }
}

impl std::fmt::Display for ModelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Spend limits
// ---------------------------------------------------------------------------

/// Why a set of limits is not coherent.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error(
        "approval threshold {approval_above} is above the per-transaction cap {max_per_transaction}: the cap would fire first and the threshold could never be reached"
    )]
    ApprovalAboveTransactionCap {
        approval_above: Money,
        max_per_transaction: Money,
    },
    #[error("per-transaction cap {max_per_transaction} is above the daily cap {max_per_day}")]
    TransactionAboveDailyCap {
        max_per_transaction: Money,
        max_per_day: Money,
    },
    #[error("spend limits mix currencies: {left} and {right}")]
    MixedCurrency { left: Currency, right: Currency },
}

/// The three money caps, guaranteed coherent and single-currency.
///
/// Private fields plus a checked constructor: there is no way to hold a
/// `SpendLimits` whose approval threshold sits above its per-transaction cap,
/// so the evaluator never has to consider that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SpendLimitsWire")]
pub struct SpendLimits {
    max_per_transaction: Money,
    max_per_day: Money,
    approval_above: Money,
}

/// Deserialization funnel, so stored JSON cannot reintroduce an incoherent
/// policy that was written by an older build.
#[derive(Deserialize)]
struct SpendLimitsWire {
    max_per_transaction: Money,
    max_per_day: Money,
    approval_above: Money,
}

impl TryFrom<SpendLimitsWire> for SpendLimits {
    type Error = PolicyError;

    fn try_from(w: SpendLimitsWire) -> Result<Self, Self::Error> {
        SpendLimits::try_new(w.max_per_transaction, w.max_per_day, w.approval_above)
    }
}

impl SpendLimits {
    /// Requires `approval_above <= max_per_transaction <= max_per_day`, all in
    /// one currency.
    pub fn try_new(
        max_per_transaction: Money,
        max_per_day: Money,
        approval_above: Money,
    ) -> Result<Self, PolicyError> {
        let currency = max_per_transaction.currency();
        for other in [max_per_day, approval_above] {
            if other.currency() != currency {
                return Err(PolicyError::MixedCurrency {
                    left: currency,
                    right: other.currency(),
                });
            }
        }
        if approval_above.minor() > max_per_transaction.minor() {
            return Err(PolicyError::ApprovalAboveTransactionCap {
                approval_above,
                max_per_transaction,
            });
        }
        if max_per_transaction.minor() > max_per_day.minor() {
            return Err(PolicyError::TransactionAboveDailyCap {
                max_per_transaction,
                max_per_day,
            });
        }
        Ok(Self {
            max_per_transaction,
            max_per_day,
            approval_above,
        })
    }

    pub const fn max_per_transaction(self) -> Money {
        self.max_per_transaction
    }

    pub const fn max_per_day(self) -> Money {
        self.max_per_day
    }

    /// At or above this amount, a human signs off.
    pub const fn approval_above(self) -> Money {
        self.approval_above
    }

    pub const fn currency(self) -> Currency {
        self.max_per_transaction.currency()
    }

    /// The stricter of two layers: the minimum of each cap. Layers that name
    /// different currencies are incoherent rather than "both allowed" — there
    /// is no exchange rate in the domain and there must not be one.
    fn intersect(self, other: Self) -> Result<Self, PolicyError> {
        if self.currency() != other.currency() {
            return Err(PolicyError::MixedCurrency {
                left: self.currency(),
                right: other.currency(),
            });
        }
        // min of coherent inputs is coherent, but re-check rather than assume.
        SpendLimits::try_new(
            min_money(self.max_per_transaction, other.max_per_transaction),
            min_money(self.max_per_day, other.max_per_day),
            min_money(self.approval_above, other.approval_above),
        )
    }
}

/// Same-currency minimum. Callers check the currency first.
fn min_money(a: Money, b: Money) -> Money {
    if a.minor() <= b.minor() { a } else { b }
}

// ---------------------------------------------------------------------------
// Policy layers
// ---------------------------------------------------------------------------

/// One layer of policy, as written by an operator.
///
/// `Default` grants nothing: empty allowlists, zero budgets, every permission
/// off. That is deliberate — a layer somebody forgot to fill in must not be the
/// layer that opens the gate.
///
/// ponytail: because the layers intersect, every layer has to restate the
/// grants it wants to keep; there is no "inherit" marker. That is more typing
/// for operators and zero ambiguity for the gate. Add an explicit
/// `Inherit`/`Restrict` wrapper per field only if authoring pain shows up in
/// practice — never an `Option` meaning "unconstrained", which is how a tenant
/// layer would end up widening the platform.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyLimits {
    /// `None` means this layer permits no spending at all.
    pub spend: Option<SpendLimits>,
    pub allowed_channels: BTreeSet<Channel>,
    pub allowed_calling_codes: BTreeSet<CallingCode>,
    /// Browser and upload allowlist. Entries match themselves and everything
    /// beneath them.
    pub allowed_domains: BTreeSet<Domain>,
    /// Checked before the allowlist, and unioned across layers, so a lower
    /// layer can always add a block but never remove one.
    pub denied_domains: BTreeSet<Domain>,
    pub allowed_mcp_tools: BTreeSet<McpTool>,
    pub allowed_a2a_peers: BTreeSet<Domain>,
    /// Which models this layer permits an employee to think with.
    ///
    /// **The one allowlist here that is not about an effect**, and the argument
    /// for it being here anyway is the same one [`max_turns_per_day`] makes one
    /// field down: an operator has to be able to bound what an employee spends,
    /// and every other spending bound is in this struct. A model is not an
    /// [`Action`] — there is no `Action::Think` and inventing one would put a
    /// non-effect in the audit vocabulary for no gain — so this field is read by
    /// [`model_for`] rather than by [`evaluate`], exactly as `max_turns_per_day`
    /// is read by [`turns_remaining`].
    ///
    /// It intersects like every other allowlist, so a tenant, a role or an
    /// employee layer can only ever narrow it, and **empty denies**. That is
    /// harsher here than anywhere else in this struct, because an employee with
    /// no permitted model cannot act at all rather than merely losing a
    /// capability — which is why [`model_for`] returns `None` for it instead of
    /// picking something, and why `apps/server`'s two callers turn that `None`
    /// into a named failure rather than a fallback.
    ///
    /// [`max_turns_per_day`]: PolicyLimits::max_turns_per_day
    pub allowed_models: BTreeSet<ModelId>,
    pub max_new_contacts_per_day: u32,
    /// How many times a day this employee may run a turn at all.
    ///
    /// Zero — the default — means it may not act on its own initiative. See
    /// the module docs: this is the only limit here that is not about an
    /// [`Action`], and [`turns_remaining`] is what reads it.
    pub max_turns_per_day: u32,
    pub allow_file_upload: bool,
    pub allow_credential_change: bool,
    pub allow_data_delete: bool,
    /// May this employee hand a prospect to the outbound sending platform,
    /// instead of producing a file for a human to upload?
    ///
    /// **The one field in this struct that chooses a sink rather than bounding
    /// an effect**, and it is here rather than in a config file for one reason:
    /// it is the only place in this system where a permission can be written
    /// down and *cannot* be widened by the layer below it. `false` here on the
    /// platform layer means `false` for every tenant, every role and every
    /// employee under it, because [`PolicyLimits::intersect`] is `&&` — and the
    /// question this answers is "does an address leave the building without a
    /// human looking at it", which is exactly the shape of question that must
    /// only ever get narrower as it travels down.
    ///
    /// [`Default`] is `false`, which is the export path: `agentos_app::queue`
    /// produces the CSV the founder uploads by hand, and every safety check on
    /// that path has already run by the time the bytes exist. Turning this on
    /// does not skip any of them — it replaces the human's upload with a gated,
    /// audited call per prospect. See `agentos_app::queue::push`.
    ///
    /// # Why it is not an `Action` and not an `ActionKind`
    ///
    /// Because the effect already has one. Handing somebody's address to a
    /// mailer *is* sending them an email, and the gate rules on it as
    /// [`Action::EmailSend`] — same channel check, same denylist, same
    /// [`max_new_contacts_per_day`], same audit row. Inventing an
    /// `Action::LeadUpload` beside it would create a second permission for one
    /// act, and the day they disagreed the narrower one would be the one nobody
    /// consulted.
    ///
    /// So this is read by its own evaluator, [`may_upload_leads`], exactly as
    /// [`max_turns_per_day`] is read by [`turns_remaining`] and
    /// [`allowed_models`] by [`model_for`]. [`evaluate`] deliberately does not
    /// consult it: there is no arm it could belong to.
    ///
    /// [`max_new_contacts_per_day`]: PolicyLimits::max_new_contacts_per_day
    /// [`max_turns_per_day`]: PolicyLimits::max_turns_per_day
    /// [`allowed_models`]: PolicyLimits::allowed_models
    pub allow_lead_upload: bool,
}

impl PolicyLimits {
    /// The stricter of two layers.
    fn intersect(&self, other: &Self) -> Result<Self, PolicyError> {
        let spend = match (self.spend, other.spend) {
            (Some(a), Some(b)) => Some(a.intersect(b)?),
            // A layer that permits no spending wins.
            (None, _) | (_, None) => None,
        };
        Ok(Self {
            spend,
            allowed_channels: intersect_sets(&self.allowed_channels, &other.allowed_channels),
            allowed_calling_codes: intersect_sets(
                &self.allowed_calling_codes,
                &other.allowed_calling_codes,
            ),
            allowed_domains: intersect_sets(&self.allowed_domains, &other.allowed_domains),
            denied_domains: self
                .denied_domains
                .union(&other.denied_domains)
                .cloned()
                .collect(),
            allowed_mcp_tools: intersect_sets(&self.allowed_mcp_tools, &other.allowed_mcp_tools),
            allowed_a2a_peers: intersect_sets(&self.allowed_a2a_peers, &other.allowed_a2a_peers),
            allowed_models: intersect_sets(&self.allowed_models, &other.allowed_models),
            max_new_contacts_per_day: self
                .max_new_contacts_per_day
                .min(other.max_new_contacts_per_day),
            max_turns_per_day: self.max_turns_per_day.min(other.max_turns_per_day),
            allow_file_upload: self.allow_file_upload && other.allow_file_upload,
            allow_credential_change: self.allow_credential_change && other.allow_credential_change,
            allow_data_delete: self.allow_data_delete && other.allow_data_delete,
            allow_lead_upload: self.allow_lead_upload && other.allow_lead_upload,
        })
    }
}

fn intersect_sets<T: Ord + Clone>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> BTreeSet<T> {
    a.intersection(b).cloned().collect()
}

/// The four layers, already intersected and validated.
///
/// The inner limits are private and there is no mutable accessor: once built,
/// an `EffectivePolicy` is exactly what [`EffectivePolicy::try_new`] approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EffectivePolicy(PolicyLimits);

impl EffectivePolicy {
    /// Intersect platform ∧ tenant ∧ role ∧ employee.
    ///
    /// Fails when the layers disagree about currency or when any layer's spend
    /// limits are incoherent (`approval_above > max_per_transaction`, or a
    /// per-transaction cap above the daily cap).
    pub fn try_new(
        platform: &PolicyLimits,
        tenant: &PolicyLimits,
        role: &PolicyLimits,
        employee: &PolicyLimits,
    ) -> Result<Self, PolicyError> {
        let limits = platform
            .intersect(tenant)?
            .intersect(role)?
            .intersect(employee)?;
        Ok(Self(limits))
    }

    /// The intersected limits, read-only.
    pub const fn limits(&self) -> &PolicyLimits {
        &self.0
    }
}

/// How many more turns this employee may run today.
///
/// The turn budget's pure half: same policy, same count, same answer, forever.
/// `0` means the day is spent — or that nobody ever granted a turn budget,
/// which reads the same way on purpose, because [`PolicyLimits::default`]
/// grants nothing and an unconfigured employee must not be the one that runs
/// without a ceiling.
///
/// It takes an [`EffectivePolicy`], not a [`PolicyLimits`], so the number it
/// reads can only be one that came out of [`EffectivePolicy::try_new`] — a
/// single un-intersected layer cannot be passed here, which is how a tenant
/// would have widened the platform.
pub const fn turns_remaining(policy: &EffectivePolicy, turns_today: u32) -> u32 {
    policy
        .limits()
        .max_turns_per_day
        .saturating_sub(turns_today)
}

/// Whether this employee's outreach queue may go to the sending platform
/// instead of to a file.
///
/// One field, read through one function, and the function is the point rather
/// than the line inside it: it takes an [`EffectivePolicy`], so the value it
/// reads can only be one that came out of [`EffectivePolicy::try_new`]. A bare
/// [`PolicyLimits`] cannot be passed, which is how a tenant layer would
/// otherwise have said `true` over a platform layer that said `false`. Same
/// argument, same shape, as [`turns_remaining`] — and it is worth more here,
/// because the thing on the other side of a wrong answer is a stranger's inbox.
///
/// `false` is the shipped answer everywhere: [`PolicyLimits::default`] grants
/// nothing, `docs/orizn-ceiling.json` never mentions it and `#[serde(default)]`
/// makes that mean the same thing, and all five `docs/orizn-roles/*.json` write
/// `"allow_lead_upload": false` out by hand. Turning it on is a policy layer
/// somebody writes on purpose.
pub const fn may_upload_leads(policy: &EffectivePolicy) -> bool {
    policy.limits().allow_lead_upload
}

/// Which model this employee actually runs: the role's preference, bounded by
/// the operator's allowlist.
///
/// **The pack proposes and the layer decides**, the same shape `proposable` and
/// the gate already have — `preferred` is what the job needs and
/// [`PolicyLimits::allowed_models`] is what the operator permits, and what runs
/// is drawn from the intersection or the turn does not happen.
///
/// Three answers, and the middle one is the whole design:
///
/// 1. **The preference is permitted** — run it. The common case, and the only
///    one where the role's judgement about its own work survives intact.
/// 2. **The preference is not permitted, but something is** — run the cheapest
///    thing that is. It is `.next()` on a `BTreeSet<ModelId>` whose `Ord` is the
///    price list, so the fallback direction is *down*: an operator who has taken
///    Opus away from a role has said what they meant about money, and answering
///    that by reaching for Fable would be the one behaviour this whole feature
///    exists to prevent. It is not silent — the callers log the substitution —
///    but it is not a refusal either, because "only Sonnet, everywhere" is a
///    sentence an operator is entitled to say without killing the fleet.
/// 3. **Nothing is permitted** — `None`, and the caller must fail closed. An
///    empty allowlist means the same thing here it means everywhere else in
///    [`PolicyLimits`]: nobody granted anything. It cannot mean "unconstrained",
///    because there is no model a system with no rate card and no operator
///    consent should be picking on its own, and it must not mean "the default
///    one", because [`ModelId::default`] is the most expensive model most seats
///    would ever run.
///
/// `policy` is an `Option` for [`crate::policy`]-external reasons that
/// `app::turn::tools_for` states in full: `None` is *"nobody could read a
/// policy"*, which is not the same fact as *"the policy grants nothing"*. An
/// unreadable policy is not evidence about models, so the preference stands and
/// the gate refuses each action on the record — the same trade `tools_for` makes
/// about schemas, made once more so the two cannot disagree.
pub fn model_for(policy: Option<&EffectivePolicy>, preferred: ModelId) -> Option<ModelId> {
    let Some(policy) = policy else {
        return Some(preferred);
    };
    let allowed = &policy.limits().allowed_models;
    if allowed.contains(&preferred) {
        return Some(preferred);
    }
    // Cheapest permitted, or none at all. `BTreeSet` iterates in `Ord` order and
    // `ModelId`'s `Ord` is the price list — see the type's docs.
    allowed.iter().copied().next()
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// Why the gate said no. An enum, not a string, because these become metric
/// labels and alert rules — a free-form reason is a cardinality bomb and an
/// un-greppable one at that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Nothing in the policy addresses this action. The default answer.
    NoRule,
    ChannelNotAllowed,
    CallingCodeNotAllowed,
    ContactBudgetExhausted,
    DomainDenied,
    DomainNotAllowed,
    FileUploadNotAllowed,
    ToolNotAllowed,
    PeerNotAllowed,
    NoSpendPolicy,
    CurrencyMismatch,
    PerTransactionLimit,
    DailyLimit,
    /// The employee is on a team with no budget in this currency. Distinct from
    /// [`DenyReason::NoSpendPolicy`] because the remedy is a different one: the
    /// employee's own caps were fine and the team has none.
    NoTeamBudget,
    /// The team's daily budget, not the employee's. Same distinction, same
    /// reason: raising the employee's cap would not help.
    TeamDailyLimit,
    /// The secret does not belong to the acting principal.
    CrossTenantSecret,
    /// An employee tried to write its own charter. Delegation runs *down* a
    /// reporting line; an employee that can re-task itself has no objective at
    /// all, it has a suggestion.
    SelfDirection,
    /// The subject of the action does not report to the actor. A peer is not a
    /// subordinate, and neither is somebody two levels down: the org chart
    /// grants authority one link at a time.
    OutsideChainOfCommand,
    CredentialChangeNotAllowed,
    DataDeleteNotAllowed,
    /// The action was derived from untrusted input and is too dangerous to run
    /// on that basis. The prompt-injection stop.
    UntrustedInput,
}

impl DenyReason {
    /// Stable, low-cardinality metric label.
    ///
    /// # If the compiler sent you here, [`ALL`](Self::ALL) is owed an entry too
    ///
    /// This match and [`grantable`](Self::grantable) are the only two places a
    /// new variant fails the build — measured over `--workspace --all-targets`,
    /// and nothing outside this file matches this enum exhaustively at all —
    /// and neither of them touches `ALL`. A variant that
    /// answers both and is left out of `ALL` compiles clean, and every rule
    /// proved "total over the enum" by iterating `ALL` — [`Self::GRANTABLE`],
    /// `reason_codes_are_stable_and_unique` — is then total over a list with a
    /// hole in it, silently. `agentos_providers::ProviderError::ALL` carries the
    /// identical residual and its docs carry the argument for why stable Rust
    /// has nothing better; this is the same note at the same door.
    pub const fn code(self) -> &'static str {
        match self {
            DenyReason::NoRule => "no_rule",
            DenyReason::ChannelNotAllowed => "channel_not_allowed",
            DenyReason::CallingCodeNotAllowed => "calling_code_not_allowed",
            DenyReason::ContactBudgetExhausted => "contact_budget_exhausted",
            DenyReason::DomainDenied => "domain_denied",
            DenyReason::DomainNotAllowed => "domain_not_allowed",
            DenyReason::FileUploadNotAllowed => "file_upload_not_allowed",
            DenyReason::ToolNotAllowed => "tool_not_allowed",
            DenyReason::PeerNotAllowed => "peer_not_allowed",
            DenyReason::NoSpendPolicy => "no_spend_policy",
            DenyReason::CurrencyMismatch => "currency_mismatch",
            DenyReason::PerTransactionLimit => "per_transaction_limit",
            DenyReason::DailyLimit => "daily_limit",
            DenyReason::NoTeamBudget => "no_team_budget",
            DenyReason::TeamDailyLimit => "team_daily_limit",
            DenyReason::CrossTenantSecret => "cross_tenant_secret",
            DenyReason::SelfDirection => "self_direction",
            DenyReason::OutsideChainOfCommand => "outside_chain_of_command",
            DenyReason::CredentialChangeNotAllowed => "credential_change_not_allowed",
            DenyReason::DataDeleteNotAllowed => "data_delete_not_allowed",
            DenyReason::UntrustedInput => "untrusted_input",
        }
    }

    /// Whether a human could answer this refusal by widening something.
    ///
    /// **The vocabulary of a capability request, and the whole of it.** An
    /// employee that is refused has no way to say what it wants; the only thing
    /// it can be *observed* to want is the wall it hit, which is this code. So
    /// the set of refusals a human is ever shown as a request is the set of
    /// refusals a human could actually do something about, and this function is
    /// that set — an exhaustive match, so a new variant cannot be added without
    /// somebody deciding which side of the line it is on.
    ///
    /// `false` is not "we have not got round to it". Every `false` below names a
    /// refusal that **no policy document can lift**, and surfacing one as a
    /// request would put a question in front of an operator whose only correct
    /// answer is no — which is worse than silence, because the third or fourth
    /// time it is asked somebody says yes.
    ///
    /// The one that matters most is [`DenyReason::UntrustedInput`]. It is the
    /// prompt-injection stop, it fires on an action the rules had already
    /// allowed, and it is the only refusal a hostile page can *cause on purpose*:
    /// a document that says "wire $10,000" produces exactly this code, three
    /// times, on demand. If it were grantable, a page the employee read would be
    /// able to put "this employee needs the taint check relaxed" in front of a
    /// human — the page writing the request, through the employee, without ever
    /// touching a byte of the text the human reads. There is also no field to
    /// grant: `evaluate` applies the taint wire after the rules and reads no
    /// limit while doing it.
    pub const fn grantable(self) -> bool {
        match self {
            // Something is missing from a list, or from a budget. Each of these
            // has a document an operator can write.
            DenyReason::NoRule
            | DenyReason::ChannelNotAllowed
            | DenyReason::CallingCodeNotAllowed
            | DenyReason::ContactBudgetExhausted
            | DenyReason::DomainNotAllowed
            | DenyReason::FileUploadNotAllowed
            | DenyReason::ToolNotAllowed
            | DenyReason::PeerNotAllowed
            | DenyReason::NoSpendPolicy
            | DenyReason::CurrencyMismatch
            | DenyReason::PerTransactionLimit
            | DenyReason::DailyLimit
            | DenyReason::NoTeamBudget
            | DenyReason::TeamDailyLimit
            | DenyReason::CredentialChangeNotAllowed
            | DenyReason::DataDeleteNotAllowed => true,

            // The blocklist. Blacklists unite and never shrink, so the only
            // shape a grant could take here is *removing* an entry somebody
            // deliberately wrote — the one direction this workspace refuses
            // everywhere else. A denied domain is an answer, not a gap.
            DenyReason::DomainDenied => false,

            // Not a permission at all: the secret belongs to another principal.
            // Widening cannot make it belong to this one, and a request to be
            // shown it is a boundary violation asking to be ratified.
            DenyReason::CrossTenantSecret => false,

            // Both of these are the org chart, and the org chart is not a
            // policy layer — `store::policy::load` does not join the reporting
            // line, precisely so acquiring a report cannot change a limit.
            // "Let me write my own charter" is the request an employee with no
            // objective would make, and it is the one `gate.rs` says has no
            // objective at all, only a suggestion.
            DenyReason::SelfDirection | DenyReason::OutsideChainOfCommand => false,

            // The taint stop. See the docs above: no field grants it, and it is
            // the one code a hostile page can make the employee produce.
            DenyReason::UntrustedInput => false,
        }
    }

    /// Every [`DenyReason`] a human may be shown as a capability request.
    ///
    /// Derived from [`DenyReason::grantable`] rather than written out a second
    /// time — two lists of the same judgement is the drift where a refusal
    /// nobody may grant becomes one somebody is asked about.
    pub const GRANTABLE: [DenyReason; 16] = {
        // A `const` block, so the count below is checked while this constant is
        // being evaluated — which is at compile time, in every crate that reads
        // it. Flipping one arm of `grantable` without touching the length here
        // does not produce a subtly short list; it fails the build.
        let all = DenyReason::ALL;
        let mut out = [DenyReason::NoRule; 16];
        let (mut i, mut n) = (0, 0);
        while i < all.len() {
            if all[i].grantable() {
                assert!(
                    n < 16,
                    "a DenyReason became grantable and GRANTABLE's length was not updated"
                );
                out[n] = all[i];
                n += 1;
            }
            i += 1;
        }
        assert!(
            n == 16,
            "a DenyReason stopped being grantable and GRANTABLE's length was not updated"
        );
        out
    };

    /// Every discriminant. Iterate it to prove a rule covers the whole space.
    pub const ALL: [DenyReason; 21] = [
        DenyReason::NoRule,
        DenyReason::ChannelNotAllowed,
        DenyReason::CallingCodeNotAllowed,
        DenyReason::ContactBudgetExhausted,
        DenyReason::DomainDenied,
        DenyReason::DomainNotAllowed,
        DenyReason::FileUploadNotAllowed,
        DenyReason::ToolNotAllowed,
        DenyReason::PeerNotAllowed,
        DenyReason::NoSpendPolicy,
        DenyReason::CurrencyMismatch,
        DenyReason::PerTransactionLimit,
        DenyReason::DailyLimit,
        DenyReason::NoTeamBudget,
        DenyReason::TeamDailyLimit,
        DenyReason::CrossTenantSecret,
        DenyReason::SelfDirection,
        DenyReason::OutsideChainOfCommand,
        DenyReason::CredentialChangeNotAllowed,
        DenyReason::DataDeleteNotAllowed,
        DenyReason::UntrustedInput,
    ];
}

/// Why a human has to look at this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalReason {
    PaymentAboveThreshold,
    /// Signing binds the tenant. Always.
    ContractSignature,
    CredentialChange,
    BulkDataDelete,
}

impl ApprovalReason {
    /// Stable, low-cardinality metric label.
    pub const fn code(self) -> &'static str {
        match self {
            ApprovalReason::PaymentAboveThreshold => "payment_above_threshold",
            ApprovalReason::ContractSignature => "contract_signature",
            ApprovalReason::CredentialChange => "credential_change",
            ApprovalReason::BulkDataDelete => "bulk_data_delete",
        }
    }
}

/// The gate's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny {
        reason: DenyReason,
    },
    RequireApproval {
        reason: ApprovalReason,
        /// One line for the human who has to press the button. Display only —
        /// nothing downstream branches on this text.
        summary: String,
    },
}

impl Decision {
    pub const fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    const fn deny(reason: DenyReason) -> Self {
        Decision::Deny { reason }
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Decide whether `action` may run.
///
/// Pure: same policy, same action, same context, same answer, forever. No clock
/// (`ctx.now` is passed in), no I/O, no randomness — which is what makes the
/// tests below a real proof rather than a sample.
pub fn evaluate(policy: &EffectivePolicy, action: &Action, ctx: &ActionCtx) -> Decision {
    let decision = evaluate_rules(policy, action, ctx);

    // The taint wire. A high-risk action derived from untrusted text — a web
    // page, an inbound email, an MCP result — never reaches the executor on the
    // strength of a rule alone. Applied *after* the rules, so it cannot be
    // forgotten in one branch: there is exactly one place it can be bypassed,
    // and it is this expression.
    if ctx.trust.is_untrusted() && action.risk().is_high() && decision.is_allow() {
        return Decision::deny(DenyReason::UntrustedInput);
    }
    decision
}

/// An empty allowlist means nobody wrote a rule at all. Report that as
/// [`DenyReason::NoRule`] — the deny-by-default answer — rather than implying
/// there was a list the caller failed to be on.
const fn no_match(list_is_empty: bool, specific: DenyReason) -> DenyReason {
    if list_is_empty {
        DenyReason::NoRule
    } else {
        specific
    }
}

/// **The MCP allowlist rule**, written once because two callers ask it.
///
/// [`evaluate`]'s [`Action::McpCall`] arm is a call to this function, and so is
/// [`evaluate_mcp_call`] — the one `app::prompt` uses to decide which tools an
/// employee is *told* about. Two spellings of one membership test is the copy
/// that drifts, and it drifts in both of the ways that cost something: a tool
/// named in the prefix that the gate refuses burns a turn on a denial the model
/// cannot learn from, and a tool the gate would allow that the prefix never
/// names is a capability nobody can reach.
fn mcp_rules(allowed: &BTreeSet<McpTool>, tool: &McpTool) -> Decision {
    if allowed.contains(tool) {
        Decision::Allow
    } else {
        Decision::deny(no_match(allowed.is_empty(), DenyReason::ToolNotAllowed))
    }
}

/// Whether this policy permits calling one MCP tool, with no [`ActionCtx`] to
/// assemble.
///
/// The same ruling [`evaluate`] gives an [`Action::McpCall`], minus the taint
/// wire — which cannot fire for this action anyway: `Action::McpCall` is `Low`
/// on the domain's risk axis, because the blast radius of an MCP call is a
/// property of the *tool* rather than of the verb, and that lives in
/// `app::mcp::RiskClass` where the operator declared it. So there is no context
/// this answer depends on: it is the intersected allowlist and nothing else,
/// which is what makes it safe to ask once when a prompt is built rather than
/// once per action.
///
/// It exists so the system prompt can name exactly the tools the gate will
/// allow. Asking here rather than reading [`PolicyLimits::allowed_mcp_tools`] at
/// the call site is the choice `app::inbound::colleagues` already makes about
/// `may_message`: the rule has one home, and the prompt is a reader of it.
pub fn evaluate_mcp_call(policy: &EffectivePolicy, tool: &McpTool) -> Decision {
    mcp_rules(&policy.limits().allowed_mcp_tools, tool)
}

/// Is this host on a denylist, or beneath one that is?
///
/// Its own function because three rules read it: the domain rules below, and
/// the email and A2A arms of [`evaluate_rules`], which check the denylist
/// against a recipient's domain and a peer without consulting
/// [`PolicyLimits::allowed_domains`] at all.
fn is_denied(denied: &BTreeSet<Domain>, host: &Domain) -> bool {
    denied.iter().any(|entry| host.is_within(entry))
}

/// **The domain rules**, written once because two callers ask them.
///
/// [`evaluate_rules`]' browser and upload arms call this, and so does
/// [`evaluate_browser_read`] — the one `app::prompt` uses to decide which
/// domains an employee is *told* about. `mcp_rules`' argument, one layer along:
/// two spellings of one membership test is the copy that drifts.
///
/// **The denylist is checked first, always**, because it *unions* across layers
/// where the allowlist intersects: a lower layer can add a block but never
/// remove one, so an allowlist entry must never be able to resurrect a blocked
/// host.
fn domain_rules(allowed: &BTreeSet<Domain>, denied: &BTreeSet<Domain>, host: &Domain) -> Decision {
    if is_denied(denied, host) {
        Decision::deny(DenyReason::DomainDenied)
    } else if allowed.iter().any(|entry| host.is_within(entry)) {
        Decision::Allow
    } else {
        Decision::deny(no_match(allowed.is_empty(), DenyReason::DomainNotAllowed))
    }
}

/// Whether this policy permits reading one domain, with no [`ActionCtx`] to
/// assemble.
///
/// The same ruling [`evaluate`] gives an [`Action::BrowserRead`], minus the
/// taint wire — which cannot fire for this action: a read is `Risk::Low` on the
/// domain's own axis (see [`Action::risk`], and `app::turn`'s catalogue row,
/// which must agree with it), because what makes a page dangerous is what comes
/// *back*, and that is handled by fencing the answer rather than by withholding
/// the tool. So there is no context this answer depends on: it is the
/// intersected allowlist, the unioned denylist, and nothing else — which is what
/// makes it safe to ask once when a prompt is built rather than once per action.
///
/// It exists so the system prompt can name exactly the domains the gate will
/// allow. That is [`evaluate_mcp_call`]'s reason exactly, and it is the same bug
/// one tool along: `read_page` takes a URL as a free string, a refused guess
/// comes back `domain_not_allowed` — which cannot tell the model whether the
/// host was wrong or merely not permitted — and a live run spent five of
/// twenty-three model calls guessing.
///
/// [`Action::BrowserWrite`] and [`Action::FileUpload`] no longer get the same
/// ruling, and that is the change this function exists to carry. They still ask
/// `allowed_domains`; reading asks `Channel::Web` and the denylist. Naming it
/// `browser_read` was a guess about the future that turned out right — the
/// arms it used to share have separated underneath it and no caller had to
/// learn that they had.
///
/// **What it can no longer be used for.** It used to answer "which domains may
/// this employee read?", by being asked once per entry in a finite allowlist.
/// There is no such list now, so a caller wanting to *enumerate* the readable
/// web is asking a question with no answer, and `app::prompt::render_domains`
/// was rewritten to stop asking it. What survives is the per-host question the
/// prober asks before it opens something: *may I read this one?*
pub fn evaluate_browser_read(policy: &EffectivePolicy, domain: &Domain) -> Decision {
    let limits = policy.limits();
    if is_denied(&limits.denied_domains, domain) {
        Decision::deny(DenyReason::DomainDenied)
    } else if limits.allowed_channels.contains(&Channel::Web) {
        Decision::Allow
    } else {
        Decision::deny(no_match(
            limits.allowed_channels.is_empty(),
            DenyReason::ChannelNotAllowed,
        ))
    }
}

/// Does [`evaluate`] rule this action against
/// [`PolicyLimits::max_new_contacts_per_day`]?
///
/// **The set the cold-outreach ceiling refuses on**, which is narrower than the
/// set that carries a counterparty into the audit trail — and the gap between
/// those two is a real refusal somebody invents by using the wrong one.
/// `evaluate_rules`' `channel_rules` is the only reader of that ceiling, and
/// these four arms are the only ones that call it.
///
/// [`Action::A2aSend`] is the arm this exists for. A peer **is** a counterparty
/// and `app::gate::counterparty` says so, because the trail has to record who
/// called — but the A2A arm asks `allowed_a2a_peers` and nothing else, so the
/// ceiling has never had an opinion about a peer. A ledger charging on "has a
/// counterparty" therefore refuses A2A on any policy whose outreach budget is
/// spent, and `app::a2a::GateInterceptor` authorises every **inbound** call as
/// an `Action::A2aSend` — so the whole endpoint went down with the day's email.
///
/// The sentence that used to stand here said "every role pack in `docs/` ships
/// `max_new_contacts_per_day: 0`", and no version of this tree has been true of:
/// `direction` and `growth` ship `0`, `sales-development` and `finance` ship
/// `5`, `customer-success` ships `20`, and `docs/orizn-ceiling.json` ships `20`.
/// Counted rather than asserted, and the corrected fact is the worse one — on
/// the two zero packs A2A was refused outright and obviously, while on the other
/// three it worked in the morning and stopped when the day's outreach ran out.
///
/// [`Action::InternalSend`] is the same pairing read the other way. It has no
/// counterparty and does not come through `channel_rules`, for the reason that
/// arm gives at length: a colleague is not a stranger.
///
/// Exhaustive, with no `_` arm, for [`always_denies`]' reason — a new [`Action`]
/// has to be considered here rather than defaulted into or out of a budget.
pub const fn spends_contact_budget(action: &Action) -> bool {
    match action {
        Action::EmailSend { .. }
        | Action::SmsSend { .. }
        | Action::WhatsappSend { .. }
        | Action::CallPlace { .. } => true,
        Action::A2aSend { .. }
        | Action::BrowserRead { .. }
        | Action::BrowserWrite { .. }
        | Action::FileUpload { .. }
        | Action::McpCall { .. }
        | Action::PaymentCreate { .. }
        | Action::ContractSign { .. }
        | Action::CredentialChange { .. }
        | Action::DataDelete { .. }
        | Action::CharterSet { .. }
        | Action::InternalSend { .. } => false,
    }
}

/// Does this policy deny **every** action of this kind, whatever its payload
/// and whatever context it is ruled in?
///
/// The only question about an [`ActionKind`] that has an answer. [`evaluate`]
/// rules on an [`Action`], and it must: whether a payment is allowed depends on
/// its amount, whether an email is allowed depends on who it is to and how many
/// strangers were written to today. So "would an `EmailSend` be allowed?" is
/// not a question — but "is there *no* `EmailSend` this policy would allow?"
/// is, and it is the one a tool catalogue needs. It exists so `app::turn`'s
/// `tools_for` can withhold a schema whose every invocation is a spent turn,
/// for the reason `app::prompt`'s `with_mcp_tools` already withholds an MCP
/// name: an employee told about a tool it may not call spends a turn finding
/// that out and cannot tell the denial from an argument it spelled wrong.
///
/// # It is deliberately an under-approximation
///
/// `false` means "not provably always denied", never "allowed". Getting this
/// wrong towards `true` is far worse than the bug it fixes: a withheld tool the
/// employee could have used makes it fail at its job silently, with no denial
/// and no audit row to explain it, whereas an offered tool the gate refuses
/// costs one turn and writes a row saying so. So every arm below asks only
/// about the payload-independent half of its rule — the empty allowlist, the
/// flag that is off — and leaves everything that depends on an amount, a
/// domain, a number or an [`ActionCtx`] to [`evaluate`]. An allowlist that is
/// non-empty but happens to contain nothing reachable reads as "not always
/// denied" here, and the gate refuses the call: the conservative direction,
/// taken on purpose.
///
/// # Why it lives here and not in the caller
///
/// The same reason [`evaluate_mcp_call`] does. This is a claim *about*
/// [`evaluate`], and a claim about the evaluator restated in another crate is a
/// claim that drifts the first time an arm below it changes. The match is
/// exhaustive over [`ActionKind`] with no `_` arm and destructures
/// [`PolicyLimits`] with no `..`, exactly as `evaluate_rules` does, so a new
/// action or a new limit stops the build here too — and
/// `the_prediction_never_disagrees_with_the_evaluator` is what keeps the two in
/// step in the meantime.
pub fn always_denies(policy: &EffectivePolicy, kind: ActionKind) -> bool {
    // Exhaustive destructure, no `..`, for `evaluate_rules`' reason: a limit
    // added to `PolicyLimits` has to be considered here as well, and a compile
    // error is the only reliable way to make somebody consider it.
    let PolicyLimits {
        spend,
        allowed_channels,
        allowed_calling_codes,
        allowed_domains,
        // Not read, and it cannot be: a denylist entry blocks the hosts beneath
        // it and says nothing about the rest of the web, so it never makes a
        // whole kind unreachable. `evaluate` applies it per action, where the
        // host is known.
        denied_domains: _,
        allowed_mcp_tools,
        allowed_a2a_peers,
        // Not read, and it cannot be: there is no `ActionKind` a model choice
        // makes unreachable. An employee with no permitted model runs no turn at
        // all, which is `model_for`'s `None` and a failure one level up — not a
        // kind this function could withhold a schema for. Withholding every
        // schema on that basis would be the same claim made twice, in the place
        // where it produces a silent employee instead of a named failure.
        allowed_models: _,
        // Per-action budgets and a per-day turn ceiling: both are counters in
        // an `ActionCtx` or in the store rather than facts about the policy, so
        // neither can answer "every action of this kind". An exhausted contact
        // budget denies today's *new* counterparties and not the known ones.
        max_new_contacts_per_day: _,
        max_turns_per_day: _,
        allow_file_upload,
        allow_credential_change,
        allow_data_delete,
        // Not read, and it cannot be: it withholds no `ActionKind`. Handing a
        // prospect to the sending platform is an `EmailSend` and is denied or
        // allowed as one — the arm below already answers for it. What this flag
        // decides is *which sink* the outreach queue drains into, which is a
        // question about a code path rather than about a tool schema, and its
        // evaluator is `may_upload_leads`. Reading it here would withhold the
        // mail tool from every employee on the export path, i.e. from every
        // employee the founder has today.
        allow_lead_upload: _,
    } = policy.limits();

    let closed = |channel: Channel| !allowed_channels.contains(&channel);

    // One arm per `ActionKind`, each naming the `DenyReason` it is predicting —
    // the reason `evaluate` gives for a specimen that trips nothing else first.
    // `no_match` turns an empty allowlist into `NoRule` there, so several of
    // these predict `NoRule` rather than the specific code.
    match kind {
        // ChannelNotAllowed / NoRule. The recipient's domain and the
        // cold-outreach budget are the payload-dependent half and are not asked.
        ActionKind::EmailSend => closed(Channel::Email),
        // ChannelNotAllowed / NoRule, then CallingCodeNotAllowed / NoRule. An
        // empty calling-code list matches no number that exists.
        ActionKind::SmsSend => closed(Channel::Sms) || allowed_calling_codes.is_empty(),
        ActionKind::WhatsappSend => closed(Channel::Whatsapp) || allowed_calling_codes.is_empty(),
        ActionKind::CallPlace => closed(Channel::Voice) || allowed_calling_codes.is_empty(),
        // **These two stopped agreeing**, and the split is the point.
        //
        // ChannelNotAllowed / NoRule for a read: the allowlist is not asked, so
        // an empty one closes nothing and `Channel::Web` is the only thing that
        // can. A layer that wants a seat off the web drops the channel, which
        // intersects like every other allowlist here.
        ActionKind::BrowserRead => closed(Channel::Web),
        // ChannelNotAllowed / NoRule, then DomainNotAllowed / NoRule. Writing
        // has to clear both, so either half closing shuts the kind — and an
        // empty allowlist is still within nothing.
        ActionKind::BrowserWrite => closed(Channel::Web) || allowed_domains.is_empty(),
        // The same as a write, then FileUploadNotAllowed: an upload has to
        // clear the domain rules *and* the flag, so either half closing shuts
        // the kind. Deliberately keyed on the allowlist rather than the read
        // rule — pushing bytes to a host is the write-shaped verb, whatever
        // the tool is called.
        ActionKind::FileUpload => allowed_domains.is_empty() || !*allow_file_upload,
        // ToolNotAllowed / NoRule — `mcp_rules`, which `evaluate_mcp_call` is
        // the other reader of.
        ActionKind::McpCall => allowed_mcp_tools.is_empty(),
        // PeerNotAllowed / NoRule.
        ActionKind::A2aSend => allowed_a2a_peers.is_empty(),
        // NoSpendPolicy. Note what this does *not* claim: caps of zero-ish size
        // are still a spend policy, and the amount decides — that is
        // `PerTransactionLimit`'s job and it is per action.
        ActionKind::PaymentCreate => spend.is_none(),
        // Never denied by policy: signing escalates to a human under every
        // policy this system can express, empty included, so there is no
        // `DenyReason` to predict and withholding the tool would withhold the
        // approval path with it.
        ActionKind::ContractSign => false,
        // CredentialChangeNotAllowed. `CrossTenantSecret` fires first for a
        // secret belonging to somebody else, which is payload-dependent and a
        // deny either way.
        ActionKind::CredentialChange => !*allow_credential_change,
        // DataDeleteNotAllowed.
        ActionKind::DataDelete => !*allow_data_delete,
        // Never denied by policy either, and for the sharper reason: delegation
        // is decided by the org chart in `ActionCtx`, and there is no field in
        // `PolicyLimits` this arm reads. A policy cannot answer for it, so it
        // must not pretend to.
        ActionKind::CharterSet => false,
        // ChannelNotAllowed / NoRule. This is the one that matters for
        // `turn::UNCHARTERED`: an employee with no charter keeps the internal
        // channel exactly as long as its policy lists `Channel::Internal`, and
        // the shipped ceiling does.
        ActionKind::InternalSend => closed(Channel::Internal),
    }
}

fn evaluate_rules(policy: &EffectivePolicy, action: &Action, ctx: &ActionCtx) -> Decision {
    // Exhaustive destructure, no `..`. Add a field to PolicyLimits and this
    // line stops compiling until the new field is consulted below.
    let PolicyLimits {
        spend,
        allowed_channels,
        allowed_calling_codes,
        allowed_domains,
        denied_domains,
        allowed_mcp_tools,
        allowed_a2a_peers,
        // Not an `Action` either, and for a sharper reason than the turn ceiling
        // below: a turn is at least a thing that happens, whereas a model is the
        // apparatus that decides what to propose. `model_for` is its evaluator,
        // and it is asked once when the turn is assembled rather than once per
        // action, because the answer cannot change inside one turn.
        allowed_models: _,
        max_new_contacts_per_day,
        // Deliberately not consulted here, and this binding is the
        // acknowledgement rather than an oversight: a turn is not an `Action`,
        // so there is no arm below that could read it. `turns_remaining` is
        // its evaluator, and `store::turns::reserve` is what enforces it.
        max_turns_per_day: _,
        allow_file_upload,
        allow_credential_change,
        allow_data_delete,
        // Deliberately not consulted, and this binding is the acknowledgement
        // rather than an oversight — the same shape as `max_turns_per_day`
        // above. There is no `Action` that means "put this person on a list":
        // the act is an `Action::EmailSend` and the arm below rules on it with
        // the channel, the denylist and the contact budget, exactly as it does
        // for a message we send ourselves. This flag only says which piece of
        // our own code performs it, and `may_upload_leads` is where that is
        // asked.
        allow_lead_upload: _,
    } = policy.limits();

    // Both of these are free functions above rather than closures here, because
    // `evaluate_browser_read` asks the same two questions and a second spelling
    // of either is the copy that drifts.
    let blocked = |d: &Domain| is_denied(denied_domains, d);
    let domains = |d: &Domain| domain_rules(allowed_domains, denied_domains, d);
    // **Split from `channel_rules` when reading became a channel**, and the
    // split is not cosmetic. `channel_rules` asks two questions — is this
    // channel open, and may this employee approach a stranger today — and
    // routing `BrowserRead` through it made opening a web page spend the
    // cold-outreach budget. A page is not a person: nobody is contacted, no
    // personal data is processed, and `max_new_contacts_per_day` is the number
    // an operator answers a supervisory authority for. Sharing it with the
    // browser would have quietly halved it.
    //
    // `a_check_that_does_not_reproduce_produces_no_evidence` is what caught it:
    // the prober's second read came back `contact_budget_exhausted`.
    let channel_open = |channel: Channel| -> Option<DenyReason> {
        if allowed_channels.contains(&channel) {
            None
        } else {
            Some(no_match(
                allowed_channels.is_empty(),
                DenyReason::ChannelNotAllowed,
            ))
        }
    };
    let channel_rules = |channel: Channel| -> Option<DenyReason> {
        if let Some(reason) = channel_open(channel) {
            Some(reason)
        } else if ctx.contact == ContactStanding::New
            && ctx.new_contacts_today >= *max_new_contacts_per_day
        {
            Some(DenyReason::ContactBudgetExhausted)
        } else {
            None
        }
    };
    // Country is derived from the number, never read off the action.
    let phone_rules = |to: &E164| -> Option<DenyReason> {
        if allowed_calling_codes.iter().any(|c| to.starts_with(*c)) {
            None
        } else {
            Some(no_match(
                allowed_calling_codes.is_empty(),
                DenyReason::CallingCodeNotAllowed,
            ))
        }
    };

    // Every variant written out by name. No `_` arm — that is the whole point
    // of this file.
    match action {
        Action::EmailSend { to } => {
            if blocked(to.domain()) {
                return Decision::deny(DenyReason::DomainDenied);
            }
            match channel_rules(Channel::Email) {
                Some(reason) => Decision::deny(reason),
                None => Decision::Allow,
            }
        }

        Action::SmsSend { to } => match channel_rules(Channel::Sms).or_else(|| phone_rules(to)) {
            Some(reason) => Decision::deny(reason),
            None => Decision::Allow,
        },

        Action::WhatsappSend { to } => {
            match channel_rules(Channel::Whatsapp).or_else(|| phone_rules(to)) {
                Some(reason) => Decision::deny(reason),
                None => Decision::Allow,
            }
        }

        Action::CallPlace { to } => {
            match channel_rules(Channel::Voice).or_else(|| phone_rules(to)) {
                Some(reason) => Decision::deny(reason),
                None => Decision::Allow,
            }
        }

        // **Reading is a channel, not a list**, and it is the only arm here that
        // changed its shape after shipping. Every other outbound verb asks
        // `channel_rules` first and consults a list about the *recipient*
        // second; browsing asked a list and no channel at all, which left
        // `Channel::Web` in `allowed_channels` with nothing reading it.
        //
        // The list could not be the rule for reading, because the rule it
        // expressed was "an operator has typed this host in advance" — and a
        // seller that must be handed each prospect's domain is not researching,
        // it is transcribing. A live dry run said so in the employee's own
        // words: *"blocked on tool access — I have no way to read their
        // booking/servicing flows, since read_page only reaches orizn.app."*
        //
        // What makes an open read defensible here and not in general is two
        // properties this workspace already had. A page comes back as
        // `Untrusted<String>`, which has no `Display`, no `Deref` and no
        // `Into<String>` — `crates/app/tests/ui` proves `format!("{}", …)`
        // fails to compile — so its bytes cannot become an email, a prompt or a
        // column. And the arm below still asks the allowlist, so
        // `allowed_domains` keeps its whole meaning for the verb that actually
        // changes somebody else's system.
        //
        // **That allowlist is not decorative**, and an early draft of this
        // change assumed it was. No role pack proposes
        // `ActionKind::BrowserWrite`, so no *model* can ever ask for one — but
        // `proof_of_need::Prober` is Rust and asks the gate directly: putting a
        // passport code into a prospect's booking form is a write, on purpose,
        // so that the audit trail says so. Emptying `allowed_domains` on the
        // strength of "nothing writes" stopped the entire selling vertical with
        // `no_rule`, three dry-run passes out of three. Reading is open;
        // *typing into somebody's form* is still a host an operator named.
        //
        // The denylist is still checked, and still first, so an operator can
        // block a host for reading exactly as before. What is gone is the
        // requirement to enumerate the web in order to look at it.
        //
        // Turning reading off entirely is `Channel::Web` absent from a layer —
        // which is a narrowing, intersects like every other allowlist, and is
        // how `direction.json` keeps a chair from browsing without naming a
        // single domain.
        Action::BrowserRead { domain } => {
            if blocked(domain) {
                Decision::deny(DenyReason::DomainDenied)
            } else {
                match channel_open(Channel::Web) {
                    Some(reason) => Decision::deny(reason),
                    None => Decision::Allow,
                }
            }
        }

        // Writing keeps the allowlist, and now asks the channel too — the same
        // two questions in the same order as `EmailSend`. A host somebody may
        // read is not a host anything may post to, and that asymmetry is the
        // whole reason the two arms stopped sharing a rule.
        Action::BrowserWrite { domain } => match channel_open(Channel::Web) {
            Some(reason) => Decision::deny(reason),
            None => domains(domain),
        },

        Action::FileUpload { domain } => match domains(domain) {
            Decision::Allow if *allow_file_upload => Decision::Allow,
            Decision::Allow => Decision::deny(DenyReason::FileUploadNotAllowed),
            refused => refused,
        },

        Action::McpCall { tool } => mcp_rules(allowed_mcp_tools, tool),

        Action::A2aSend { peer } => {
            if blocked(peer) {
                return Decision::deny(DenyReason::DomainDenied);
            }
            if allowed_a2a_peers.iter().any(|entry| peer.is_within(entry)) {
                Decision::Allow
            } else {
                Decision::deny(no_match(
                    allowed_a2a_peers.is_empty(),
                    DenyReason::PeerNotAllowed,
                ))
            }
        }

        Action::PaymentCreate { amount } => {
            let Some(limits) = spend else {
                return Decision::deny(DenyReason::NoSpendPolicy);
            };
            if amount.currency() != limits.currency() {
                return Decision::deny(DenyReason::CurrencyMismatch);
            }
            if amount.minor() > limits.max_per_transaction().minor() {
                return Decision::deny(DenyReason::PerTransactionLimit);
            }
            // The structuring guard: the day's running total, not this payment
            // judged on its own merits.
            let total = match ctx.spent_today {
                None => *amount,
                Some(spent) if spent.currency() != limits.currency() => {
                    return Decision::deny(DenyReason::CurrencyMismatch);
                }
                Some(spent) => match spent.checked_add(*amount) {
                    Ok(total) => total,
                    // Only overflow can land here; either way it is over the cap.
                    Err(_) => return Decision::deny(DenyReason::DailyLimit),
                },
            };
            if total.minor() > limits.max_per_day().minor() {
                return Decision::deny(DenyReason::DailyLimit);
            }
            if amount.minor() >= limits.approval_above().minor() {
                return Decision::RequireApproval {
                    reason: ApprovalReason::PaymentAboveThreshold,
                    summary: format!("pay {amount}"),
                };
            }
            Decision::Allow
        }

        // Unconditional. There is no policy field to widen, no flag to flip and
        // no `if` to get wrong: signing binds the tenant, so a human signs off.
        Action::ContractSign { title } => Decision::RequireApproval {
            reason: ApprovalReason::ContractSignature,
            summary: format!("sign contract {title:?}"),
        },

        Action::CredentialChange { secret } => {
            if secret.tenant_id() != ctx.actor.tenant_id
                || secret.employee_id() != ctx.actor.employee_id
            {
                return Decision::deny(DenyReason::CrossTenantSecret);
            }
            if !*allow_credential_change {
                return Decision::deny(DenyReason::CredentialChangeNotAllowed);
            }
            Decision::RequireApproval {
                reason: ApprovalReason::CredentialChange,
                summary: format!("rotate secret {}", secret.name()),
            }
        }

        Action::DataDelete { scope } => {
            if !*allow_data_delete {
                return Decision::deny(DenyReason::DataDeleteNotAllowed);
            }
            match scope {
                DataScope::Conversation { .. } => Decision::Allow,
                DataScope::AllForEmployee { id } => Decision::RequireApproval {
                    reason: ApprovalReason::BulkDataDelete,
                    summary: format!("erase all data for employee {id}"),
                },
            }
        }

        // Delegation. Two conditions, and neither of them is a field in
        // `PolicyLimits` — which is the whole point.
        //
        // **Nobody writes their own charter**, however senior. An employee that
        // can re-task itself has no objective, it has a preference, and the
        // loop that re-reads the charter every turn would happily follow
        // whatever the last turn decided it preferred.
        //
        // **The subject must report to the actor**, as `ctx.directs_subject`
        // says — read from the org chart by the host, in the transaction the
        // ruling is made in. `ActionCtx::new` sets it to `false`, so a context
        // nobody filled in denies, exactly like an empty policy: this arm has no
        // path to `Allow` that a caller can take by omission.
        //
        // A `may_delegate` bit in `PolicyLimits` was the alternative and it is
        // the mistake this design exists to avoid: it would make authority over
        // *people* a thing a policy *layer* grants, and from there "senior"
        // starts to mean "wider". Seniority narrows whose charter you may write
        // — a set of employees — and there is nothing in this match, or in this
        // file, through which it could reach what an employee may *do*. A head's
        // own limits still gate every action it takes, delegation included.
        //
        // The high-risk taint wire applies as usual: `CharterSet` is
        // [`Risk::High`], so untrusted input cannot reach an `Allow` here at
        // all.
        Action::CharterSet { subordinate } => {
            if *subordinate == ctx.actor.employee_id {
                return Decision::deny(DenyReason::SelfDirection);
            }
            if !ctx.directs_subject {
                return Decision::deny(DenyReason::OutsideChainOfCommand);
            }
            Decision::Allow
        }

        // The channel allowlist and **nothing else**, deliberately not through
        // `channel_rules`.
        //
        // `channel_rules` also charges the cold-outreach budget, and a
        // colleague is not a counterparty: an employee that has already
        // emailed its twenty new suppliers today must still be able to answer
        // the question its manager asked it. Routing this through the same
        // helper would spend a budget meant for strangers on an internal
        // conversation, and would make "who may I still write to today"
        // depend on how much the company talked to itself. The other half of
        // that promise is in `app::gate`, where `counterparty()` returns
        // `None` for this action so an internal message never *enlarges* the
        // budget either.
        //
        // Who specifically may be written to is not decided here. This
        // evaluator is pure and an org chart is a table; `app::inbound::send`
        // resolves the recipient and asks `may_message`, in the transaction
        // that does the write.
        Action::InternalSend { .. } => {
            if allowed_channels.contains(&Channel::Internal) {
                Decision::Allow
            } else {
                Decision::deny(no_match(
                    allowed_channels.is_empty(),
                    DenyReason::ChannelNotAllowed,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{ActionKind, Actor, EmailAddress, TrustLabel};
    use crate::ids::{ConversationId, EmployeeId, SecretRef, Slug, TenantId};
    use crate::money::Currency::{Eur, Usd};
    use chrono::{DateTime, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn actor() -> Actor {
        Actor::new(
            TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            EmployeeId::from_uuid(uuid::Uuid::from_u128(2)),
        )
    }

    fn ctx() -> ActionCtx {
        ActionCtx {
            trust: TrustLabel::Trusted,
            contact: ContactStanding::Known,
            ..ActionCtx::new(actor(), at(1_700_000_000))
        }
    }

    fn domain(s: &str) -> Domain {
        Domain::parse(s).unwrap()
    }

    fn slug(s: &str) -> Slug {
        Slug::parse(s).unwrap()
    }

    fn usd(minor: u64) -> Money {
        Money::new(minor, Usd).unwrap()
    }

    fn secret() -> SecretRef {
        SecretRef::new(actor().tenant_id, actor().employee_id, "smtp_password").unwrap()
    }

    /// The most permissive policy this system can express: everything the
    /// operator could switch on, switched on.
    ///
    /// `Channel::ALL` and not a hand-written list, because a hand-written one
    /// stopped being permissive the moment a seventh channel was added and
    /// nobody noticed: this fixture listed four of seven, so `InternalSend`
    /// was denied under "the most permissive policy" and every arm of the
    /// evaluator that needs `Channel::Internal` went untested. Ask the enum.
    fn permissive() -> PolicyLimits {
        PolicyLimits {
            spend: Some(SpendLimits::try_new(usd(50_000), usd(200_000), usd(50_000)).unwrap()),
            allowed_channels: Channel::ALL.into_iter().collect(),
            allowed_calling_codes: [CallingCode::new(1).unwrap(), CallingCode::new(86).unwrap()]
                .into_iter()
                .collect(),
            allowed_domains: [domain("example.com")].into_iter().collect(),
            denied_domains: BTreeSet::new(),
            allowed_mcp_tools: [McpTool::new(slug("erp"), slug("lookup"))]
                .into_iter()
                .collect(),
            allowed_a2a_peers: [domain("partner.example.com")].into_iter().collect(),
            // Every model, and off the enum rather than by hand: this is the
            // "everything switched on" fixture, and a list that stopped being
            // exhaustive the day a fifth model landed is the bug the
            // `Channel::ALL` note above is about.
            allowed_models: ModelId::ALL.into_iter().collect(),
            max_new_contacts_per_day: 1_000,
            max_turns_per_day: 500,
            allow_file_upload: true,
            allow_credential_change: true,
            allow_data_delete: true,
            allow_lead_upload: true,
        }
    }

    fn effective(limits: &PolicyLimits) -> EffectivePolicy {
        EffectivePolicy::try_new(limits, limits, limits, limits).unwrap()
    }

    /// One sample action per discriminant. The test below proves this list is
    /// complete against `ActionKind::ALL`.
    fn one_of_every_action() -> Vec<Action> {
        vec![
            Action::EmailSend {
                to: EmailAddress::parse("buyer@example.com").unwrap(),
            },
            Action::SmsSend {
                to: E164::parse("+8613800000000").unwrap(),
            },
            Action::WhatsappSend {
                to: E164::parse("+8613800000000").unwrap(),
            },
            Action::CallPlace {
                to: E164::parse("+8613800000000").unwrap(),
            },
            Action::BrowserRead {
                domain: domain("example.com"),
            },
            Action::BrowserWrite {
                domain: domain("example.com"),
            },
            Action::FileUpload {
                domain: domain("example.com"),
            },
            Action::McpCall {
                tool: McpTool::new(slug("erp"), slug("lookup")),
            },
            Action::A2aSend {
                peer: domain("partner.example.com"),
            },
            Action::PaymentCreate { amount: usd(100) },
            Action::ContractSign {
                title: "supply agreement".into(),
            },
            Action::CredentialChange { secret: secret() },
            Action::DataDelete {
                scope: DataScope::Conversation {
                    id: ConversationId::from_uuid(uuid::Uuid::from_u128(3)),
                },
            },
            Action::CharterSet {
                subordinate: EmployeeId::from_uuid(uuid::Uuid::from_u128(4)),
            },
            Action::InternalSend { to: slug("bruno") },
        ]
    }

    #[test]
    fn the_sample_set_covers_every_action_variant() {
        let mut kinds: Vec<ActionKind> = one_of_every_action().iter().map(Action::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();

        let mut all = ActionKind::ALL.to_vec();
        all.sort_unstable();

        assert_eq!(
            kinds, all,
            "one_of_every_action() must cover every ActionKind exactly once"
        );
    }

    /// The regression test for `_ => PolicyDecision::Allow`.
    ///
    /// An empty policy grants nothing, so *no* action may be allowed — not the
    /// obviously dangerous ones, and not the ones nobody wrote a rule for.
    /// Because it iterates the sample set that is pinned to `ActionKind::ALL`
    /// above, a new variant cannot slip past it.
    #[test]
    fn an_empty_policy_allows_nothing_at_all() {
        let policy = effective(&PolicyLimits::default());
        let ctx = ctx();

        for action in one_of_every_action() {
            let decision = evaluate(&policy, &action, &ctx);
            assert!(
                !decision.is_allow(),
                "{} was ALLOWED under an empty policy: {decision:?}",
                action.kind()
            );
        }
    }

    /// The same, stated as the property it protects: only ContractSign is
    /// allowed to answer `RequireApproval` under an empty policy; everything
    /// else must be a hard deny, and the catch-all reason is `NoRule`-shaped
    /// (a named reason, never a silent allow).
    #[test]
    fn an_empty_policy_denies_with_a_named_reason() {
        let policy = effective(&PolicyLimits::default());
        let ctx = ctx();

        for action in one_of_every_action() {
            let kind = action.kind();
            match evaluate(&policy, &action, &ctx) {
                Decision::Deny { reason } => {
                    assert!(!reason.code().is_empty(), "{kind} deny has no metric label");
                }
                Decision::RequireApproval { reason, .. } => {
                    assert_eq!(
                        kind,
                        ActionKind::ContractSign,
                        "only contract signing may escalate under an empty policy, got {reason:?}"
                    );
                }
                Decision::Allow => panic!("{kind} was allowed under an empty policy"),
            }
        }
    }

    /// The mirror of the test above, and the half that was missing.
    ///
    /// "An empty policy allows nothing" only proves the gate can say no. Without
    /// this, an arm that says no *unconditionally* is indistinguishable from a
    /// correct one — which is exactly what happened: `permissive()` listed four
    /// of `Channel`'s seven variants, so `InternalSend` was denied under the
    /// most permissive policy this system can express, and forcing that arm to
    /// `Deny` outright left all 209 domain tests green. The internal channel had
    /// already shipped unreachable once for the same reason, one layer down.
    ///
    /// Deny is the only outcome ruled out. `ContractSign` and `CredentialChange`
    /// escalate however wide the policy is opened, which is the point of both.
    #[test]
    fn the_permissive_policy_denies_nothing_at_all() {
        let policy = effective(&permissive());
        // The favourable context: trusted input, a known counterparty, and
        // authority over the one action that has a subject.
        let ctx = ActionCtx {
            directs_subject: true,
            ..ctx()
        };

        for action in one_of_every_action() {
            let kind = action.kind();
            let decision = evaluate(&policy, &action, &ctx);
            assert!(
                !matches!(decision, Decision::Deny { .. }),
                "{kind} was DENIED under the most permissive policy this system \
                 can express: {decision:?} — either the fixture no longer grants \
                 everything an operator could switch on, or this arm cannot be \
                 reached at all"
            );
            if matches!(
                kind,
                ActionKind::ContractSign | ActionKind::CredentialChange
            ) {
                assert!(matches!(decision, Decision::RequireApproval { .. }));
            } else {
                assert!(decision.is_allow(), "{kind} did not reach Allow");
            }
        }
    }

    #[test]
    fn contract_signing_always_requires_a_human() {
        let ctx = ctx();
        let action = Action::ContractSign {
            title: "exclusive supply agreement".into(),
        };

        for (label, limits) in [
            ("empty", PolicyLimits::default()),
            ("permissive", permissive()),
        ] {
            let decision = evaluate(&effective(&limits), &action, &ctx);
            assert!(
                matches!(
                    decision,
                    Decision::RequireApproval {
                        reason: ApprovalReason::ContractSignature,
                        ..
                    }
                ),
                "{label} policy gave {decision:?}"
            );
        }

        // Untrusted provenance does not downgrade it into a silent allow either.
        let tainted = ActionCtx {
            trust: TrustLabel::Untrusted,
            ..ctx
        };
        assert!(!evaluate(&effective(&permissive()), &action, &tainted).is_allow());
    }

    /// Delegation: down the line only, never sideways, never at oneself — and
    /// **holding authority over somebody widens nothing else**.
    ///
    /// That last clause is the one to read. `directs_subject` is the only input
    /// a reporting line contributes to a ruling, and the loop below flips it on
    /// every other action in the space and asserts the verdict does not move.
    /// A future edit that reads it anywhere but the `CharterSet` arm — "heads
    /// may spend more", "heads may email anyone" — turns this red.
    #[test]
    fn a_reporting_line_decides_whom_not_what() {
        let policy = effective(&permissive());
        let subordinate = EmployeeId::from_uuid(uuid::Uuid::from_u128(7));
        let charter = Action::CharterSet { subordinate };

        let peer = ctx();
        assert!(!peer.directs_subject, "the safe default is no authority");
        let head = ActionCtx {
            directs_subject: true,
            ..ctx()
        };

        // A peer may not re-task a peer, under the most permissive policy this
        // system can express. No allowlist can grant this; only the org chart.
        assert_eq!(
            evaluate(&policy, &charter, &peer),
            Decision::Deny {
                reason: DenyReason::OutsideChainOfCommand
            }
        );
        // Its head may.
        assert_eq!(evaluate(&policy, &charter, &head), Decision::Allow);

        // Nobody writes their own, however senior — and `directs_subject` does
        // not buy the exemption, which is why the self check comes first.
        let self_charter = Action::CharterSet {
            subordinate: actor().employee_id,
        };
        for ctx in [&peer, &head] {
            assert_eq!(
                evaluate(&policy, &self_charter, ctx),
                Decision::Deny {
                    reason: DenyReason::SelfDirection
                }
            );
        }

        // Delegation is high-risk, so a document cannot ask for one.
        let injected = ActionCtx {
            trust: TrustLabel::Untrusted,
            ..head.clone()
        };
        assert_eq!(
            evaluate(&policy, &charter, &injected),
            Decision::Deny {
                reason: DenyReason::UntrustedInput
            }
        );

        // The property: seniority is not a capability. Every other action in
        // the space rules exactly the same for a head as for a peer.
        for action in one_of_every_action() {
            if matches!(action, Action::CharterSet { .. }) {
                continue;
            }
            assert_eq!(
                evaluate(&policy, &action, &head),
                evaluate(&policy, &action, &peer),
                "{} ruled differently for an employee that has reports",
                action.kind()
            );
        }
    }

    #[test]
    fn one_denylist_entry_catches_every_spelling_and_every_subdomain() {
        let limits = PolicyLimits {
            // Deliberately generous allowlist: the denylist must still win.
            allowed_domains: [domain("example.com")].into_iter().collect(),
            denied_domains: [domain("banking.example.com")].into_iter().collect(),
            ..permissive()
        };
        let policy = effective(&limits);
        let ctx = ctx();

        for spelling in [
            "banking.example.com",
            "BANKING.example.com",
            "banking.example.com.",
            "login.banking.example.com",
            "LOGIN.Banking.Example.Com.",
        ] {
            let d = domain(spelling);
            for action in [
                Action::BrowserWrite { domain: d.clone() },
                Action::BrowserRead { domain: d.clone() },
                Action::FileUpload { domain: d.clone() },
            ] {
                assert_eq!(
                    evaluate(&policy, &action, &ctx),
                    Decision::Deny {
                        reason: DenyReason::DomainDenied
                    },
                    "{spelling} slipped past the denylist as {}",
                    action.kind()
                );
            }
        }

        // A sibling that merely looks similar is not caught by the same entry,
        // and an allowlisted host still works.
        assert!(
            evaluate(
                &policy,
                &Action::BrowserWrite {
                    domain: domain("shop.example.com")
                },
                &ctx
            )
            .is_allow()
        );
        // Outside the allowlist: denied, but for the *right* reason.
        assert_eq!(
            evaluate(
                &policy,
                &Action::BrowserWrite {
                    domain: domain("alibaba.com")
                },
                &ctx
            ),
            Decision::Deny {
                reason: DenyReason::DomainNotAllowed
            }
        );
    }

    #[test]
    fn the_gate_derives_the_country_from_the_number_it_is_given() {
        let limits = PolicyLimits {
            // China only.
            allowed_calling_codes: [CallingCode::new(86).unwrap()].into_iter().collect(),
            ..permissive()
        };
        let policy = effective(&limits);
        let ctx = ctx();

        let russian = Action::CallPlace {
            to: E164::parse("+79991234567").unwrap(),
        };
        assert_eq!(
            evaluate(&policy, &russian, &ctx),
            Decision::Deny {
                reason: DenyReason::CallingCodeNotAllowed
            }
        );

        let chinese = Action::CallPlace {
            to: E164::parse("+8613800000000").unwrap(),
        };
        assert!(evaluate(&policy, &chinese, &ctx).is_allow());

        // The same rule covers SMS and WhatsApp, which share the phone path.
        assert!(
            !evaluate(
                &policy,
                &Action::SmsSend {
                    to: E164::parse("+79991234567").unwrap()
                },
                &ctx
            )
            .is_allow()
        );

        // And "claim CN while dialling +7" is not expressible: `CallPlace` has
        // exactly one field, of type `E164`. This line is the assertion — it
        // stops compiling the moment a caller-supplied country comes back.
        let _shape: fn(E164) -> Action = |to| Action::CallPlace { to };

        // Even the serialized form cannot carry one: an unknown `country` key
        // is dropped, and the decision is still driven by the number.
        let forged: Action =
            serde_json::from_str(r#"{"action":"call_place","to":"+79991234567","country":"CN"}"#)
                .unwrap();
        assert_eq!(forged, russian);
        assert!(!evaluate(&policy, &forged, &ctx).is_allow());
    }

    /// Structuring: many small payments, each individually fine, must still hit
    /// the daily wall. The gate is fed the running total, so it cannot judge
    /// each payment on its own merits.
    #[test]
    fn fifty_small_payments_cannot_walk_past_the_daily_cap() {
        let policy = effective(&permissive()); // 50_000 per tx, 200_000 per day
        let each = usd(9_999);

        let mut spent: Option<Money> = None;
        let mut allowed = 0u32;
        let mut denied = 0u32;

        for _ in 0..50 {
            let ctx = ActionCtx {
                spent_today: spent,
                ..ctx()
            };
            let decision = evaluate(&policy, &Action::PaymentCreate { amount: each }, &ctx);

            if decision.is_allow() {
                allowed += 1;
                // Only a payment that was allowed lands on the ledger.
                spent = Some(match spent {
                    Some(s) => s.checked_add(each).unwrap(),
                    None => each,
                });
            } else {
                denied += 1;
                assert_eq!(
                    decision,
                    Decision::Deny {
                        reason: DenyReason::DailyLimit
                    }
                );
            }
        }

        // 20 × 9_999 = 199_980; the 21st would reach 209_979 and is refused.
        assert_eq!(allowed, 20);
        assert_eq!(denied, 30);
        assert_eq!(spent.unwrap().minor(), 199_980);
        assert!(spent.unwrap().minor() <= 200_000);
    }

    #[test]
    fn payment_limits_and_thresholds() {
        let policy = effective(&permissive()); // tx 50_000, day 200_000, approval >= 50_000
        let ctx = ctx();
        let pay = |m: Money| Action::PaymentCreate { amount: m };

        assert!(evaluate(&policy, &pay(usd(5_000)), &ctx).is_allow());
        assert!(matches!(
            evaluate(&policy, &pay(usd(50_000)), &ctx),
            Decision::RequireApproval {
                reason: ApprovalReason::PaymentAboveThreshold,
                ..
            }
        ));
        assert_eq!(
            evaluate(&policy, &pay(usd(50_001)), &ctx),
            Decision::Deny {
                reason: DenyReason::PerTransactionLimit
            }
        );
        assert_eq!(
            evaluate(&policy, &pay(Money::new(5_000, Eur).unwrap()), &ctx),
            Decision::Deny {
                reason: DenyReason::CurrencyMismatch
            }
        );
        // A ledger in the wrong currency is a mismatch, not a free pass.
        let mixed = ActionCtx {
            spent_today: Some(Money::new(1, Eur).unwrap()),
            ..ctx.clone()
        };
        assert_eq!(
            evaluate(&policy, &pay(usd(1_000)), &mixed),
            Decision::Deny {
                reason: DenyReason::CurrencyMismatch
            }
        );
        // No spend policy at all: denied, named.
        let broke = effective(&PolicyLimits {
            spend: None,
            ..permissive()
        });
        assert_eq!(
            evaluate(&broke, &pay(usd(1)), &ctx),
            Decision::Deny {
                reason: DenyReason::NoSpendPolicy
            }
        );
    }

    #[test]
    fn untrusted_input_never_reaches_a_high_risk_side_effect() {
        let policy = effective(&permissive());
        let tainted = ActionCtx {
            trust: TrustLabel::Untrusted,
            ..ctx()
        };

        // The headline case: a payment the policy would happily allow.
        let payment = Action::PaymentCreate { amount: usd(100) };
        assert!(evaluate(&policy, &payment, &ctx()).is_allow());
        assert_eq!(
            evaluate(&policy, &payment, &tainted),
            Decision::Deny {
                reason: DenyReason::UntrustedInput
            }
        );

        // And the property, over every high-risk action.
        for action in one_of_every_action() {
            let decision = evaluate(&policy, &action, &tainted);
            if action.risk().is_high() {
                assert!(
                    !decision.is_allow(),
                    "high-risk {} was allowed from untrusted input: {decision:?}",
                    action.kind()
                );
            }
        }
    }

    #[test]
    fn a_secret_belonging_to_someone_else_is_refused_before_any_flag_is_read() {
        let policy = effective(&permissive());
        let other = SecretRef::new(
            TenantId::from_uuid(uuid::Uuid::from_u128(99)),
            EmployeeId::from_uuid(uuid::Uuid::from_u128(2)),
            "smtp_password",
        )
        .unwrap();

        assert_eq!(
            evaluate(&policy, &Action::CredentialChange { secret: other }, &ctx()),
            Decision::Deny {
                reason: DenyReason::CrossTenantSecret
            }
        );
        assert!(matches!(
            evaluate(
                &policy,
                &Action::CredentialChange { secret: secret() },
                &ctx()
            ),
            Decision::RequireApproval {
                reason: ApprovalReason::CredentialChange,
                ..
            }
        ));
    }

    #[test]
    fn cold_outreach_budget_applies_to_new_contacts_only() {
        let limits = PolicyLimits {
            max_new_contacts_per_day: 2,
            ..permissive()
        };
        let policy = effective(&limits);
        let email = Action::EmailSend {
            to: EmailAddress::parse("buyer@example.com").unwrap(),
        };

        let fresh = ActionCtx {
            contact: ContactStanding::New,
            new_contacts_today: 1,
            ..ctx()
        };
        assert!(evaluate(&policy, &email, &fresh).is_allow());

        let spent = ActionCtx {
            new_contacts_today: 2,
            ..fresh
        };
        assert_eq!(
            evaluate(&policy, &email, &spent),
            Decision::Deny {
                reason: DenyReason::ContactBudgetExhausted
            }
        );

        // A known counterparty is unaffected by the cold-outreach budget.
        let known = ActionCtx {
            contact: ContactStanding::Known,
            ..spent
        };
        assert!(evaluate(&policy, &email, &known).is_allow());
    }

    // -- layering ----------------------------------------------------------

    #[test]
    fn a_lower_layer_can_only_tighten() {
        let platform = PolicyLimits {
            spend: Some(SpendLimits::try_new(usd(10_000), usd(50_000), usd(5_000)).unwrap()),
            allowed_domains: [domain("example.com")].into_iter().collect(),
            max_new_contacts_per_day: 10,
            allow_file_upload: true,
            ..PolicyLimits::default()
        };
        // A tenant that tries to grant itself more of everything.
        let greedy_tenant = PolicyLimits {
            spend: Some(SpendLimits::try_new(usd(999_999), usd(999_999), usd(999_999)).unwrap()),
            allowed_domains: [domain("example.com"), domain("anything.com")]
                .into_iter()
                .collect(),
            max_new_contacts_per_day: 10_000,
            allow_file_upload: true,
            ..PolicyLimits::default()
        };

        let effective =
            EffectivePolicy::try_new(&platform, &greedy_tenant, &platform, &platform).unwrap();
        let limits = effective.limits();

        assert_eq!(limits.spend.unwrap().max_per_transaction(), usd(10_000));
        assert_eq!(limits.spend.unwrap().max_per_day(), usd(50_000));
        assert_eq!(limits.spend.unwrap().approval_above(), usd(5_000));
        assert_eq!(limits.max_new_contacts_per_day, 10);
        assert_eq!(limits.allowed_domains, [domain("example.com")].into());
        assert!(!limits.allowed_domains.contains(&domain("anything.com")));
    }

    /// The turn budget takes the same only-ever-tighter path as every other
    /// numeric cap, including through the `role` layer a team plugs into.
    #[test]
    fn a_team_can_tighten_the_turn_budget_and_a_greedy_one_is_ignored() {
        let platform = PolicyLimits {
            max_turns_per_day: 100,
            ..permissive()
        };
        let cautious_team = PolicyLimits {
            max_turns_per_day: 12,
            ..permissive()
        };
        let greedy_team = PolicyLimits {
            max_turns_per_day: 100_000,
            ..permissive()
        };

        // Tightening lands.
        let tightened =
            EffectivePolicy::try_new(&platform, &platform, &cautious_team, &platform).unwrap();
        assert_eq!(tightened.limits().max_turns_per_day, 12);
        assert_eq!(turns_remaining(&tightened, 0), 12);
        assert_eq!(turns_remaining(&tightened, 11), 1);
        assert_eq!(turns_remaining(&tightened, 12), 0);
        // And a count past the cap does not wrap into a fresh allowance.
        assert_eq!(turns_remaining(&tightened, u32::MAX), 0);

        // Widening does not.
        let greedy =
            EffectivePolicy::try_new(&platform, &platform, &greedy_team, &platform).unwrap();
        assert_eq!(greedy.limits().max_turns_per_day, 100);

        // Nor from the employee layer, nor from the tenant's.
        for widener in [&greedy_team] {
            for stack in [
                EffectivePolicy::try_new(&platform, widener, &platform, &platform),
                EffectivePolicy::try_new(&platform, &platform, &platform, widener),
            ] {
                assert_eq!(stack.unwrap().limits().max_turns_per_day, 100);
            }
        }

        // An unconfigured employee gets no turns at all: the default grants
        // nothing here exactly as it does everywhere else in this file.
        let unconfigured = effective(&PolicyLimits::default());
        assert_eq!(turns_remaining(&unconfigured, 0), 0);
    }

    /// The whole mechanism, in one function's worth of assertions.
    ///
    /// A pack asks for a model, a layer narrows the set, and what runs is drawn
    /// from the intersection — never from the preference and never from a
    /// default. Break any line of `model_for` and one of these goes red.
    #[test]
    fn a_role_gets_the_intersection_and_not_its_preference() {
        let platform = permissive();
        // An operator who has decided this fleet does not run frontier models.
        let thrifty = PolicyLimits {
            allowed_models: [ModelId::Haiku45, ModelId::Sonnet5].into_iter().collect(),
            ..permissive()
        };

        // 1. Preference permitted: the role's own judgement stands.
        let open = effective(&platform);
        assert_eq!(model_for(Some(&open), ModelId::Opus5), Some(ModelId::Opus5));
        assert_eq!(
            model_for(Some(&open), ModelId::Haiku45),
            Some(ModelId::Haiku45)
        );

        // 2. Preference excluded: the cheapest thing that *is* permitted, and
        //    emphatically not the most expensive. A fallback that reached for
        //    `Fable5` here would be the bug this feature exists to prevent.
        let narrowed = EffectivePolicy::try_new(&platform, &thrifty, &platform, &platform).unwrap();
        assert_eq!(
            narrowed.limits().allowed_models,
            [ModelId::Haiku45, ModelId::Sonnet5].into_iter().collect(),
            "a tenant layer narrows the set; it does not replace it"
        );
        assert_eq!(
            model_for(Some(&narrowed), ModelId::Fable5),
            Some(ModelId::Haiku45)
        );

        // 3. A layer can only ever narrow. A greedy team asking for everything
        //    under a thrifty tenant still gets the thrifty tenant's answer.
        let greedy = PolicyLimits {
            allowed_models: ModelId::ALL.into_iter().collect(),
            ..permissive()
        };
        let stacked = EffectivePolicy::try_new(&platform, &thrifty, &greedy, &platform).unwrap();
        assert_eq!(
            model_for(Some(&stacked), ModelId::Opus5),
            Some(ModelId::Haiku45),
            "the role layer named Opus and the intersection ignored it"
        );
        // The preference still lands when the tenant permits it — the role
        // layer widening is what was ignored, not the preference itself.
        assert_eq!(
            model_for(Some(&stacked), ModelId::Sonnet5),
            Some(ModelId::Sonnet5)
        );

        // 4. Empty intersection: no model, and no guess. Two layers that each
        //    permit something, with nothing in common, is the realistic way to
        //    arrive here — a tenant on Sonnet and a team on Opus.
        let sonnet_only = PolicyLimits {
            allowed_models: [ModelId::Sonnet5].into_iter().collect(),
            ..permissive()
        };
        let opus_only = PolicyLimits {
            allowed_models: [ModelId::Opus5].into_iter().collect(),
            ..permissive()
        };
        let contradiction =
            EffectivePolicy::try_new(&platform, &sonnet_only, &opus_only, &platform).unwrap();
        assert!(contradiction.limits().allowed_models.is_empty());
        assert_eq!(model_for(Some(&contradiction), ModelId::Opus5), None);
        assert_eq!(model_for(Some(&contradiction), ModelId::Haiku45), None);

        // 5. The unconfigured default denies, like every other allowlist here.
        assert_eq!(
            model_for(Some(&effective(&PolicyLimits::default())), ModelId::Opus5),
            None
        );

        // 6. And no policy at all is *unknown*, not *nothing* — `tools_for`'s
        //    trade, made once more. The preference stands and the gate refuses
        //    each action on the record.
        assert_eq!(model_for(None, ModelId::Opus5), Some(ModelId::Opus5));
    }

    /// `model_for`'s fallback is `BTreeSet` iteration order, so the enum's
    /// declaration order is a price list and not a stylistic choice. Reorder
    /// the variants and a thrifty operator starts paying frontier rates.
    #[test]
    fn the_order_is_the_price_list() {
        assert_eq!(
            ModelId::ALL,
            [
                ModelId::Haiku45,
                ModelId::Sonnet5,
                ModelId::Opus5,
                ModelId::Fable5
            ]
        );
        let mut sorted = ModelId::ALL;
        sorted.sort_unstable();
        assert_eq!(sorted, ModelId::ALL, "ALL is not in `Ord` order");
        assert_eq!(
            ModelId::Sonnet5.at_most(),
            [ModelId::Haiku45, ModelId::Sonnet5].into_iter().collect(),
            "`at_most` must reach down the price list and never up"
        );
        // Round-trips through the wire form the operator documents use.
        for model in ModelId::ALL {
            assert_eq!(ModelId::parse(model.as_str()), Some(model));
            assert_eq!(
                serde_json::to_string(&model).unwrap(),
                format!("\"{}\"", model.as_str())
            );
        }
        assert_eq!(ModelId::parse("claude-opus-4-8"), None);
    }

    #[test]
    fn a_denylist_entry_from_any_layer_survives_the_intersection() {
        let open = permissive();
        let cautious_employee = PolicyLimits {
            denied_domains: [domain("banking.example.com")].into_iter().collect(),
            ..permissive()
        };
        let policy = EffectivePolicy::try_new(&open, &open, &open, &cautious_employee).unwrap();

        assert_eq!(
            evaluate(
                &policy,
                &Action::BrowserWrite {
                    domain: domain("login.banking.example.com")
                },
                &ctx()
            ),
            Decision::Deny {
                reason: DenyReason::DomainDenied
            }
        );
    }

    /// **The capability that mails strangers can only ever be taken away.**
    ///
    /// Four assertions and each one is a different way to get this wrong: the
    /// shipped default, a layer that tries to grant what its ceiling withholds,
    /// the same in the other direction, and the only arrangement that is
    /// actually permission.
    #[test]
    fn only_a_unanimous_stack_may_upload_leads() {
        let open = permissive();
        let closed = PolicyLimits {
            allow_lead_upload: false,
            ..permissive()
        };

        // What a deployment nobody has configured gets, and what this workspace
        // ships: the export path.
        assert!(
            !PolicyLimits::default().allow_lead_upload,
            "an unwritten layer must not be the one that lets an address leave \
             the building"
        );

        // A tenant, a role or an employee layer saying yes over a platform
        // ceiling that says no. Each position on its own, because an `&&` chain
        // written in the wrong order is right for three of them and wrong for
        // the fourth.
        for (n, layers) in [
            [&closed, &open, &open, &open],
            [&open, &closed, &open, &open],
            [&open, &open, &closed, &open],
            [&open, &open, &open, &closed],
        ]
        .into_iter()
        .enumerate()
        {
            let policy =
                EffectivePolicy::try_new(layers[0], layers[1], layers[2], layers[3]).unwrap();
            assert!(
                !may_upload_leads(&policy),
                "layer {n} withheld lead upload and the intersection granted it \
                 anyway; every other layer saying yes must not add up to a yes"
            );
        }

        // And the one arrangement that is a grant: all four, on purpose.
        let unanimous = EffectivePolicy::try_new(&open, &open, &open, &open).unwrap();
        assert!(
            may_upload_leads(&unanimous),
            "an operator who has switched it on at every layer must be able to \
             switch it on, or the flag is decoration"
        );
    }

    #[test]
    fn a_layer_that_permits_no_spending_removes_spending_entirely() {
        let open = permissive();
        let no_money = PolicyLimits {
            spend: None,
            ..permissive()
        };
        let policy = EffectivePolicy::try_new(&open, &no_money, &open, &open).unwrap();

        assert!(policy.limits().spend.is_none());
        assert_eq!(
            evaluate(&policy, &Action::PaymentCreate { amount: usd(1) }, &ctx()),
            Decision::Deny {
                reason: DenyReason::NoSpendPolicy
            }
        );
    }

    #[test]
    fn incoherent_spend_limits_are_rejected_at_construction() {
        assert_eq!(
            SpendLimits::try_new(usd(1_000), usd(10_000), usd(5_000)),
            Err(PolicyError::ApprovalAboveTransactionCap {
                approval_above: usd(5_000),
                max_per_transaction: usd(1_000),
            })
        );
        assert_eq!(
            SpendLimits::try_new(usd(10_000), usd(1_000), usd(500)),
            Err(PolicyError::TransactionAboveDailyCap {
                max_per_transaction: usd(10_000),
                max_per_day: usd(1_000),
            })
        );
        assert_eq!(
            SpendLimits::try_new(usd(1_000), Money::new(10_000, Eur).unwrap(), usd(500)),
            Err(PolicyError::MixedCurrency {
                left: Usd,
                right: Eur
            })
        );
        // And the same check guards the deserialization path.
        assert!(
            serde_json::from_str::<SpendLimits>(
                r#"{"max_per_transaction":{"minor":1000,"currency":"USD"},
                    "max_per_day":{"minor":10000,"currency":"USD"},
                    "approval_above":{"minor":5000,"currency":"USD"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn layers_in_different_currencies_are_incoherent_not_convertible() {
        let usd_layer = permissive();
        let eur_layer = PolicyLimits {
            spend: Some(
                SpendLimits::try_new(
                    Money::new(50_000, Eur).unwrap(),
                    Money::new(200_000, Eur).unwrap(),
                    Money::new(50_000, Eur).unwrap(),
                )
                .unwrap(),
            ),
            ..permissive()
        };
        assert_eq!(
            EffectivePolicy::try_new(&usd_layer, &eur_layer, &usd_layer, &usd_layer),
            Err(PolicyError::MixedCurrency {
                left: Usd,
                right: Eur
            })
        );
    }

    /// Every variant, and the list drifted once already: it carried seventeen
    /// of twenty-one, so `SelfDirection` could have returned `"no_rule"` and
    /// this test still passed. A duplicate code collapses two alert conditions
    /// into one series, which is the whole reason `code()` exists.
    ///
    /// ponytail: still a hand-written list. `code()`'s own match is exhaustive,
    /// so a *new* variant cannot go label-less; what this catches is two
    /// variants sharing a label, and catching that needs an enumeration. A
    /// `DenyReason::ALL` next to `ActionKind::ALL` would read better and would
    /// not be more total — a fixed-length array does not force itself to grow.
    #[test]
    fn reason_codes_are_stable_and_unique() {
        // `DenyReason::ALL`, not a second copy of it. This list used to be
        // written out here and was the only enumeration of the enum in the
        // workspace; the moment `grantable` needed one too, two lists of the
        // same twenty-one variants would have been two lists to keep in step.
        let reasons = DenyReason::ALL;
        let mut codes: Vec<&str> = reasons.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), reasons.len(), "duplicate deny code");

        assert_eq!(DenyReason::NoRule.code(), "no_rule");
        assert_eq!(
            ApprovalReason::ContractSignature.code(),
            "contract_signature"
        );
    }

    /// **The prompt and the gate ask one question.** `app::prompt` names the
    /// tools an employee may call by calling [`evaluate_mcp_call`]; the gate
    /// rules on the call itself through [`evaluate`]. If those two ever answer
    /// differently, an employee is either being invited to spend a turn on a
    /// denial or holding a capability nobody told it about.
    #[test]
    fn naming_a_tool_and_ruling_on_it_are_the_same_rule() {
        let granted = McpTool::new(slug("erp"), slug("lookup"));
        let withheld = McpTool::new(slug("erp"), slug("drop-table"));
        let policy = effective(&permissive());
        let silent = effective(&PolicyLimits {
            allowed_mcp_tools: BTreeSet::new(),
            ..permissive()
        });

        for policy in [&policy, &silent] {
            for tool in [&granted, &withheld] {
                assert_eq!(
                    evaluate_mcp_call(policy, tool),
                    evaluate(
                        policy,
                        &Action::McpCall { tool: tool.clone() },
                        &ActionCtx {
                            // Both labels, because the prompt asks this once
                            // when it is built and the turn's label moves under
                            // it. An MCP call is Low, so neither answer may
                            // depend on the trust wire.
                            trust: TrustLabel::Untrusted,
                            ..ctx()
                        }
                    ),
                    "{tool} was ruled on differently by the two callers"
                );
            }
        }

        assert!(evaluate_mcp_call(&policy, &granted).is_allow());
        assert!(!evaluate_mcp_call(&policy, &withheld).is_allow());
        // An empty allowlist is nobody having written a rule, not a list this
        // tool failed to be on — the same distinction the gate reports.
        assert_eq!(
            evaluate_mcp_call(&silent, &granted),
            Decision::Deny {
                reason: DenyReason::NoRule
            }
        );
    }

    /// The same claim one tool along: `app::prompt` tells an employee what it
    /// may read by calling [`evaluate_browser_read`], and the gate rules on the
    /// read itself through [`evaluate`]. Two spellings of one rule is the copy
    /// that drifts, and this is what stops it.
    ///
    /// **The rule underneath both of them changed**, which is why the tail of
    /// this test reads the way it does. A read used to clear `allowed_domains`;
    /// it now clears `Channel::Web` and the denylist, and consults no allowlist
    /// at all. The loop below is unchanged and still passes, which is the
    /// interesting part: it never asserted *which* rule, only that one rule has
    /// one answer.
    ///
    /// The denylist is the half that makes this worth its own test. It
    /// **unions** across layers where allowlists intersect, so it is the only
    /// thing that can still refuse a host on the open web — and a prompt that
    /// guessed instead of asking would send a model to spend a turn on
    /// `domain_denied`.
    #[test]
    fn naming_a_domain_and_ruling_on_it_are_the_same_rule() {
        let walled = effective(&PolicyLimits {
            allowed_domains: [domain("example.com"), domain("banking.example.com")]
                .into_iter()
                .collect(),
            denied_domains: [domain("banking.example.com")].into_iter().collect(),
            ..permissive()
        });
        let silent = effective(&PolicyLimits {
            allowed_domains: BTreeSet::new(),
            denied_domains: BTreeSet::new(),
            ..permissive()
        });

        for policy in [&walled, &silent] {
            for host in [
                "example.com",
                "shop.example.com",
                "banking.example.com",
                "login.banking.example.com",
                "alibaba.com",
            ] {
                let host = domain(host);
                assert_eq!(
                    evaluate_browser_read(policy, &host),
                    evaluate(
                        policy,
                        &Action::BrowserRead {
                            domain: host.clone()
                        },
                        &ActionCtx {
                            // A read is Low, so neither answer may depend on the
                            // trust wire — the prompt asks this once when it is
                            // built and the turn's label moves under it.
                            trust: TrustLabel::Untrusted,
                            ..ctx()
                        }
                    ),
                    "{host} was ruled on differently by the two callers"
                );
            }
        }

        assert!(evaluate_browser_read(&walled, &domain("example.com")).is_allow());
        assert!(evaluate_browser_read(&walled, &domain("shop.example.com")).is_allow());
        assert_eq!(
            evaluate_browser_read(&walled, &domain("banking.example.com")),
            Decision::Deny {
                reason: DenyReason::DomainDenied
            }
        );

        // **The change, stated as an assertion.** `alibaba.com` is on nobody's
        // allowlist in either fixture and is readable in both. Before, this was
        // `DomainNotAllowed` under `walled` and `NoRule` under `silent`; a
        // seller therefore could not open a prospect's page until an operator
        // had typed that prospect's domain, which is the thing a live dry run
        // reported as being blocked on.
        assert!(evaluate_browser_read(&walled, &domain("alibaba.com")).is_allow());
        assert!(evaluate_browser_read(&silent, &domain("alibaba.com")).is_allow());

        // What still refuses, and it is a *narrowing* that does it. Dropping
        // `Channel::Web` takes the whole web away in one field, which is how a
        // layer says "this seat does not browse" without enumerating anything.
        let landlocked = effective(&PolicyLimits {
            allowed_channels: [Channel::Email, Channel::Internal].into_iter().collect(),
            ..permissive()
        });
        assert_eq!(
            evaluate_browser_read(&landlocked, &domain("example.com")),
            Decision::Deny {
                reason: DenyReason::ChannelNotAllowed
            }
        );
        // And an empty channel list is nobody having written a rule, not a
        // channel this read failed to be on — the distinction the gate reports
        // everywhere else, now reported here too.
        let mute = effective(&PolicyLimits {
            allowed_channels: BTreeSet::new(),
            ..permissive()
        });
        assert_eq!(
            evaluate_browser_read(&mute, &domain("example.com")),
            Decision::Deny {
                reason: DenyReason::NoRule
            }
        );

        // The denylist outranks the open web, in both directions of the change.
        assert_eq!(
            evaluate_browser_read(&walled, &domain("login.banking.example.com")),
            Decision::Deny {
                reason: DenyReason::DomainDenied
            }
        );

        // **The hole this test had, and the bug that fell through it.**
        //
        // Routing a read through `channel_rules` made it spend
        // `max_new_contacts_per_day`, because that closure asks two questions
        // at once. The loop above could not see it: its `ActionCtx` carries a
        // *known* counterparty, so the contact clause never fired on either
        // side. A page is not a person — nobody is contacted by being read —
        // and the number that clause spends is the one an operator answers a
        // supervisory authority for.
        let spent = effective(&PolicyLimits {
            max_new_contacts_per_day: 0,
            denied_domains: [domain("banking.example.com")].into_iter().collect(),
            ..permissive()
        });
        let stranger = ActionCtx {
            contact: ContactStanding::New,
            ..ctx()
        };
        for host in ["example.com", "alibaba.com"] {
            let host = domain(host);
            assert_eq!(
                evaluate(
                    &spent,
                    &Action::BrowserRead {
                        domain: host.clone()
                    },
                    &stranger
                ),
                evaluate_browser_read(&spent, &host),
                "an exhausted contact budget changed a browser read of {host}"
            );
            assert!(
                evaluate_browser_read(&spent, &host).is_allow(),
                "{host} was refused to an employee that may browse"
            );
        }
        // …while the verb that *does* approach somebody still pays, on the very
        // same policy and the very same context.
        assert_eq!(
            evaluate(
                &spent,
                &Action::EmailSend {
                    to: EmailAddress::parse("buyer@alibaba.com").unwrap()
                },
                &stranger
            ),
            Decision::Deny {
                reason: DenyReason::ContactBudgetExhausted
            }
        );
    }

    // -- always_denies -----------------------------------------------------

    /// The shape of a fresh deployment: `store::policy::default_ceiling` and no
    /// tenant layer, restated here because the domain cannot depend on the
    /// store. Email, the internal channel and the console; no calling codes, no
    /// browsing allowlist, no MCP tools, every dangerous flag off.
    ///
    /// If the shipped ceiling ever changes, this fixture does not follow it
    /// automatically — and it does not need to. What it is here to be is *a*
    /// realistic middle policy between `default()` and `permissive()`, i.e. one
    /// where some kinds are unreachable and others are not, so the matrix below
    /// is not two extremes.
    fn ceiling() -> PolicyLimits {
        PolicyLimits {
            spend: Some(SpendLimits::try_new(usd(50_000), usd(200_000), usd(10_000)).unwrap()),
            allowed_channels: [Channel::Email, Channel::Internal, Channel::Web]
                .into_iter()
                .collect(),
            max_new_contacts_per_day: 50,
            max_turns_per_day: 200,
            ..PolicyLimits::default()
        }
    }

    /// The policies the prediction is checked against: the two extremes, the
    /// shipped ceiling, and `permissive()` with one grant knocked out at a
    /// time — because a predicate that reads the wrong field is only visible
    /// when exactly one field moves.
    fn policy_matrix() -> Vec<(&'static str, EffectivePolicy)> {
        let one_off = [
            (
                "no channels",
                PolicyLimits {
                    allowed_channels: BTreeSet::new(),
                    ..permissive()
                },
            ),
            (
                "no calling codes",
                PolicyLimits {
                    allowed_calling_codes: BTreeSet::new(),
                    ..permissive()
                },
            ),
            (
                "no domains",
                PolicyLimits {
                    allowed_domains: BTreeSet::new(),
                    ..permissive()
                },
            ),
            (
                "everything denylisted",
                PolicyLimits {
                    denied_domains: [domain("example.com"), domain("partner.example.com")]
                        .into_iter()
                        .collect(),
                    ..permissive()
                },
            ),
            (
                "no mcp tools",
                PolicyLimits {
                    allowed_mcp_tools: BTreeSet::new(),
                    ..permissive()
                },
            ),
            (
                "no a2a peers",
                PolicyLimits {
                    allowed_a2a_peers: BTreeSet::new(),
                    ..permissive()
                },
            ),
            (
                "no spend",
                PolicyLimits {
                    spend: None,
                    ..permissive()
                },
            ),
            (
                "a spend policy of almost nothing",
                PolicyLimits {
                    spend: Some(SpendLimits::try_new(usd(1), usd(1), usd(1)).unwrap()),
                    ..permissive()
                },
            ),
            (
                "no contact budget",
                PolicyLimits {
                    max_new_contacts_per_day: 0,
                    ..permissive()
                },
            ),
            (
                "flags off",
                PolicyLimits {
                    allow_file_upload: false,
                    allow_credential_change: false,
                    allow_data_delete: false,
                    ..permissive()
                },
            ),
        ];

        [("empty", PolicyLimits::default()), ("ceiling", ceiling())]
            .into_iter()
            .chain(one_off)
            .chain([("permissive", permissive())])
            .map(|(label, limits)| (label, effective(&limits)))
            .collect()
    }

    /// Every context the evaluator can be given, over the axes it actually
    /// reads. A prediction that holds for a trusted turn and fails for a
    /// tainted one would be a prediction that hides a tool from the turns most
    /// in need of it.
    fn ctx_matrix() -> Vec<ActionCtx> {
        let mut out = Vec::new();
        for trust in [TrustLabel::Trusted, TrustLabel::Untrusted] {
            for contact in [ContactStanding::Known, ContactStanding::New] {
                for (new_today, spent) in [(0, None), (1_000, Some(usd(199_999)))] {
                    for directs_subject in [false, true] {
                        out.push(ActionCtx {
                            trust,
                            contact,
                            new_contacts_today: new_today,
                            spent_today: spent,
                            directs_subject,
                            ..ActionCtx::new(actor(), at(1_700_000_000))
                        });
                    }
                }
            }
        }
        out
    }

    /// Several payloads per kind where the payload is what the gate rules on,
    /// so "denies every action of this kind" is checked against more than one
    /// specimen. `one_of_every_action` is the pinned-to-`ActionKind::ALL` half;
    /// these are the variations that would expose a prediction reading a field
    /// the payload can escape.
    fn every_action_and_then_some() -> Vec<Action> {
        let mut out = one_of_every_action();
        out.extend([
            Action::EmailSend {
                to: EmailAddress::parse("stranger@elsewhere.test").unwrap(),
            },
            Action::SmsSend {
                to: E164::parse("+15550000000").unwrap(),
            },
            Action::WhatsappSend {
                to: E164::parse("+79991234567").unwrap(),
            },
            Action::CallPlace {
                to: E164::parse("+15550000000").unwrap(),
            },
            Action::BrowserRead {
                domain: domain("shop.example.com"),
            },
            Action::BrowserWrite {
                domain: domain("elsewhere.test"),
            },
            Action::FileUpload {
                domain: domain("shop.example.com"),
            },
            Action::McpCall {
                tool: McpTool::new(slug("erp"), slug("drop-table")),
            },
            Action::A2aSend {
                peer: domain("elsewhere.test"),
            },
            Action::PaymentCreate { amount: usd(1) },
            Action::PaymentCreate {
                amount: usd(49_999),
            },
            Action::ContractSign {
                title: "nda".into(),
            },
            Action::CredentialChange {
                secret: SecretRef::new(
                    TenantId::from_uuid(uuid::Uuid::from_u128(99)),
                    actor().employee_id,
                    "smtp_password",
                )
                .unwrap(),
            },
            Action::DataDelete {
                scope: DataScope::AllForEmployee {
                    id: actor().employee_id,
                },
            },
            Action::CharterSet {
                subordinate: actor().employee_id,
            },
            Action::InternalSend { to: slug("anja") },
        ]);
        out
    }

    /// **The prediction and the evaluator agree**, which is the whole licence
    /// [`always_denies`] has to be consulted anywhere.
    ///
    /// One implication, asserted over every kind, a range of policies, several
    /// payloads each and every context axis the gate reads: if the predicate
    /// says a kind is unreachable, `evaluate` denies — outright, never
    /// `RequireApproval`, because an escalation is a path to the effect and a
    /// withheld tool would close it.
    ///
    /// Read the contrapositive and this is also the conservative direction:
    /// anything the gate does *not* deny forces the predicate to `false`, so a
    /// tool that is sometimes usable cannot be withheld. It iterates
    /// `ActionKind::ALL` rather than the specimen list, so a sixteenth action
    /// cannot be added without somebody deciding what this predicate says about
    /// it.
    #[test]
    fn the_prediction_never_disagrees_with_the_evaluator() {
        let actions = every_action_and_then_some();
        let contexts = ctx_matrix();

        for kind in ActionKind::ALL {
            let specimens: Vec<&Action> = actions.iter().filter(|a| a.kind() == kind).collect();
            assert!(
                !specimens.is_empty(),
                "{kind} has no specimen action to check the prediction against"
            );

            for (label, policy) in &policy_matrix() {
                if !always_denies(policy, kind) {
                    continue;
                }
                for action in &specimens {
                    for ctx in &contexts {
                        let decision = evaluate(policy, action, ctx);
                        assert!(
                            matches!(decision, Decision::Deny { .. }),
                            "always_denies said the {label} policy refuses every {kind}, \
                             but the gate answered {decision:?} for {action:?}"
                        );
                    }
                }
            }
        }
    }

    /// **`spends_contact_budget` is a claim about [`evaluate`], so it is checked
    /// against [`evaluate`] rather than re-read.**
    ///
    /// The list in that function is written out by hand — it has to be, it is a
    /// `const fn` over `Action` — and a hand-written list of which arms consult a
    /// ceiling is exactly the copy that drifts when an arm is rewired. So: run
    /// every specimen twice through the real evaluator, changing **nothing but**
    /// `new_contacts_today`, and the predicate must agree with whether that moved
    /// the answer. No reasoning about which refusal fires first is needed,
    /// because both runs meet the same ones.
    #[test]
    fn the_contact_budget_charges_exactly_the_arms_the_ceiling_rules_on() {
        let limits = permissive();
        let policy = effective(&limits);
        let free = ActionCtx {
            trust: TrustLabel::Trusted,
            contact: ContactStanding::New,
            new_contacts_today: 0,
            ..ActionCtx::new(actor(), at(1_700_000_000))
        };
        let spent = ActionCtx {
            new_contacts_today: u32::MAX,
            ..free.clone()
        };

        for action in every_action_and_then_some() {
            let moved = evaluate(&policy, &action, &free) != evaluate(&policy, &action, &spent);
            assert_eq!(
                spends_contact_budget(&action),
                moved,
                "spends_contact_budget disagrees with the evaluator about {action:?}"
            );
        }
    }

    /// The other half, stated positively so it cannot pass vacuously: the
    /// predicate has to actually *fire* on the policies where it should, and
    /// stay quiet on the one where nothing is out of reach.
    ///
    /// The empty policy is the interesting column. Every kind is unreachable
    /// under it except the two that are not decided by `PolicyLimits` at all —
    /// signing, which escalates to a human under every policy, and delegation,
    /// which the org chart decides. A predicate that returned `true` for those
    /// would withhold a tool no policy edit could ever restore.
    #[test]
    fn an_empty_policy_puts_every_kind_but_two_out_of_reach() {
        let empty = effective(&PolicyLimits::default());
        let open = effective(&permissive());

        for kind in ActionKind::ALL {
            let decided_elsewhere =
                matches!(kind, ActionKind::ContractSign | ActionKind::CharterSet);
            assert_eq!(
                always_denies(&empty, kind),
                !decided_elsewhere,
                "{kind} under a policy that grants nothing"
            );
            assert!(
                !always_denies(&open, kind),
                "{kind} was withheld under the most permissive policy this system can express"
            );
        }
    }

    /// **A tool that is sometimes allowed is never withheld.** The direction
    /// that costs more to get wrong: a hidden tool is an employee failing its
    /// job with no denial and no audit row to explain it.
    ///
    /// Each case below is a policy under which the *specimen* action is denied
    /// and some other action of the same kind is not. The predicate must answer
    /// `false` for all of them — "mostly denied" is not "always denied", and the
    /// gate is what tells the difference, per action, on the record.
    #[test]
    fn a_kind_that_is_sometimes_allowed_is_never_withheld() {
        let ctx = ctx();

        // A budget of one cent: nearly every payment is refused and one is not.
        let almost_broke = effective(&PolicyLimits {
            spend: Some(SpendLimits::try_new(usd(1), usd(1), usd(1)).unwrap()),
            ..permissive()
        });
        assert!(!always_denies(&almost_broke, ActionKind::PaymentCreate));
        assert!(
            !evaluate(
                &almost_broke,
                &Action::PaymentCreate {
                    amount: usd(50_000)
                },
                &ctx
            )
            .is_allow()
        );

        // One country. Every other number on earth is denied; that is fifteen
        // arms of the phone tree, not the whole kind.
        let china_only = effective(&PolicyLimits {
            allowed_calling_codes: [CallingCode::new(86).unwrap()].into_iter().collect(),
            ..permissive()
        });
        for kind in [
            ActionKind::SmsSend,
            ActionKind::WhatsappSend,
            ActionKind::CallPlace,
        ] {
            assert!(!always_denies(&china_only, kind));
        }
        assert!(
            !evaluate(
                &china_only,
                &Action::SmsSend {
                    to: E164::parse("+79991234567").unwrap()
                },
                &ctx
            )
            .is_allow()
        );

        // A denylist that happens to cover every host the allowlist names. The
        // kind really is unreachable and the predicate still says `false`,
        // which is the under-approximation working as designed: the gate
        // refuses each host by name, on the record, and nobody is left
        // wondering why the browser tool vanished.
        let walled = effective(&PolicyLimits {
            denied_domains: [domain("example.com")].into_iter().collect(),
            ..permissive()
        });
        assert!(!always_denies(&walled, ActionKind::BrowserRead));
        assert_eq!(
            evaluate(
                &walled,
                &Action::BrowserRead {
                    domain: domain("example.com")
                },
                &ctx
            ),
            Decision::Deny {
                reason: DenyReason::DomainDenied
            }
        );

        // The cold-outreach budget is a counter, not a grant: an employee that
        // has written to its fifty strangers today can still answer the ones it
        // knows, so email is not out of reach.
        let no_new_contacts = effective(&PolicyLimits {
            max_new_contacts_per_day: 0,
            ..permissive()
        });
        assert!(!always_denies(&no_new_contacts, ActionKind::EmailSend));
    }

    /// The kind the reported bug was about, both directions, at the policy a
    /// fresh deployment actually has.
    ///
    /// The shipped ceiling grants no MCP tools, so `call_mcp_tool` is a schema
    /// whose every invocation returns `deny/no_rule` — and one grant later it
    /// is not. The internal channel is the control: `turn::UNCHARTERED` leans on
    /// it and it survives the same ceiling.
    #[test]
    fn the_shipped_ceiling_puts_mcp_out_of_reach_until_a_tool_is_granted() {
        let fresh = effective(&ceiling());
        assert!(always_denies(&fresh, ActionKind::McpCall));
        assert!(!always_denies(&fresh, ActionKind::EmailSend));
        assert!(!always_denies(&fresh, ActionKind::InternalSend));
        assert!(!always_denies(&fresh, ActionKind::PaymentCreate));

        let granted = effective(&PolicyLimits {
            allowed_mcp_tools: [McpTool::new(slug("erp"), slug("lookup"))]
                .into_iter()
                .collect(),
            ..ceiling()
        });
        assert!(!always_denies(&granted, ActionKind::McpCall));
    }

    /// **The refusals a human must never be asked to lift.**
    ///
    /// Named one by one rather than counted, because the count is already
    /// asserted at compile time by `GRANTABLE`'s const block and a count says
    /// nothing about *which*. `UntrustedInput` is the one that costs money if it
    /// ever flips: it is the code a hostile page can make an employee produce on
    /// demand, so a grantable one would let a document put its own request in
    /// front of an operator.
    #[test]
    fn the_taint_stop_and_the_org_chart_are_not_capability_requests() {
        for reason in [
            DenyReason::UntrustedInput,
            DenyReason::DomainDenied,
            DenyReason::CrossTenantSecret,
            DenyReason::SelfDirection,
            DenyReason::OutsideChainOfCommand,
        ] {
            assert!(
                !reason.grantable(),
                "{} became grantable: a human is now being asked to lift it",
                reason.code()
            );
            assert!(
                !DenyReason::GRANTABLE.contains(&reason),
                "{} reached the request vocabulary",
                reason.code()
            );
        }
        // And the headline case is genuinely reachable: `evaluate` produces it
        // from an allowed action, so it is not a code that only exists in this
        // file.
        assert!(!DenyReason::GRANTABLE.contains(&DenyReason::UntrustedInput));
    }

    #[test]
    fn decisions_round_trip_through_json() {
        let decision = Decision::Deny {
            reason: DenyReason::DomainDenied,
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(json, r#"{"decision":"deny","reason":"domain_denied"}"#);
        assert_eq!(serde_json::from_str::<Decision>(&json).unwrap(), decision);
    }
}
