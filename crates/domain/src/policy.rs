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
            max_new_contacts_per_day: self
                .max_new_contacts_per_day
                .min(other.max_new_contacts_per_day),
            max_turns_per_day: self.max_turns_per_day.min(other.max_turns_per_day),
            allow_file_upload: self.allow_file_upload && other.allow_file_upload,
            allow_credential_change: self.allow_credential_change && other.allow_credential_change,
            allow_data_delete: self.allow_data_delete && other.allow_data_delete,
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
        // Per-action budgets and a per-day turn ceiling: both are counters in
        // an `ActionCtx` or in the store rather than facts about the policy, so
        // neither can answer "every action of this kind". An exhausted contact
        // budget denies today's *new* counterparties and not the known ones.
        max_new_contacts_per_day: _,
        max_turns_per_day: _,
        allow_file_upload,
        allow_credential_change,
        allow_data_delete,
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
        // DomainNotAllowed / NoRule. An empty allowlist is within nothing.
        ActionKind::BrowserRead | ActionKind::BrowserWrite => allowed_domains.is_empty(),
        // The same, then FileUploadNotAllowed: an upload has to clear the
        // domain rules *and* the flag, so either half closing shuts the kind.
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
        max_new_contacts_per_day,
        // Deliberately not consulted here, and this binding is the
        // acknowledgement rather than an oversight: a turn is not an `Action`,
        // so there is no arm below that could read it. `turns_remaining` is
        // its evaluator, and `store::turns::reserve` is what enforces it.
        max_turns_per_day: _,
        allow_file_upload,
        allow_credential_change,
        allow_data_delete,
    } = policy.limits();

    // Denylist first, always: an allowlist entry must never be able to
    // resurrect a blocked host.
    let blocked = |d: &Domain| denied_domains.iter().any(|entry| d.is_within(entry));
    let domain_rules = |d: &Domain| -> Option<DenyReason> {
        if blocked(d) {
            Some(DenyReason::DomainDenied)
        } else if allowed_domains.iter().any(|entry| d.is_within(entry)) {
            None
        } else {
            Some(no_match(
                allowed_domains.is_empty(),
                DenyReason::DomainNotAllowed,
            ))
        }
    };
    let channel_rules = |channel: Channel| -> Option<DenyReason> {
        if !allowed_channels.contains(&channel) {
            Some(no_match(
                allowed_channels.is_empty(),
                DenyReason::ChannelNotAllowed,
            ))
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

        Action::BrowserRead { domain } => match domain_rules(domain) {
            Some(reason) => Decision::deny(reason),
            None => Decision::Allow,
        },

        Action::BrowserWrite { domain } => match domain_rules(domain) {
            Some(reason) => Decision::deny(reason),
            None => Decision::Allow,
        },

        Action::FileUpload { domain } => {
            if let Some(reason) = domain_rules(domain) {
                return Decision::deny(reason);
            }
            if *allow_file_upload {
                Decision::Allow
            } else {
                Decision::deny(DenyReason::FileUploadNotAllowed)
            }
        }

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
            max_new_contacts_per_day: 1_000,
            max_turns_per_day: 500,
            allow_file_upload: true,
            allow_credential_change: true,
            allow_data_delete: true,
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
        let reasons = [
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
