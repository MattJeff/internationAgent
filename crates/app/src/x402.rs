//! HTTP 402, read: turning a stranger's demand for money into the one thing
//! this system already knows how to refuse.
//!
//! x402 is payment over HTTP status 402. A server answers `402 Payment
//! Required` with a machine-readable body saying what it wants; the client pays
//! and replays the request with proof. **This module is the first half of the
//! client side and deliberately nothing else** — it reads the demand and stops.
//! There is no wallet here, no key, no network, no replay and no proof. See
//! [the switch](#the-switch-and-why-it-is-not-a-boolean) for the three
//! independent things holding it shut, and [the two
//! decisions](#what-blocks-this-and-the-two-decisions-only-the-founder-can-take)
//! the founder has to take before any of the rest can exist.
//!
//! # Are we the client or the server?
//!
//! Both are coherent products and they are not the same build, so the answer is
//! written down rather than assumed.
//!
//! **We are the client.** An employee that buys something at the moment it
//! needs it — a data lookup, a visa rule, a credit check — is a client paying
//! per call, and that is what every capability in this workspace points at.
//! `apps/server/src/routes/a2a.rs::SKILLS` already says so in the card a peer
//! reads: `Step::Wallet` is advertised as *"Purchasing — places orders and pays
//! for them, within its spending policy."* Places orders. Pays. Client.
//!
//! **We are not the server, and the reason is the API key.** Answering 402 to a
//! peer means selling at the call, which needs three things this build does not
//! have and should not grow speculatively: a price per method, a way to verify
//! somebody else's payment proof (a facilitator, i.e. a network call), and a
//! receipt somebody can dispute. It also has a shape problem. The JSON-RPC
//! binding is mounted **inside** the API-key layer — `a2a::router`, not
//! `a2a::card_router` — so every caller that could be charged has already been
//! issued a credential by a human, which means a commercial relationship
//! already exists and is already billed somewhere else. A 402 on a route that
//! requires a key is metering, not payment discovery; the register for that is
//! `Action::InvoiceIssue` and `migrations/0066_invoices.sql`, which is money in
//! the same direction and already built.
//!
//! So: **this module reads 402s, it never sends one.**
//!
//! # Is paying a 402 an `Action` the gate rules on, or a side effect?
//!
//! This is the question the whole module exists to answer, because getting it
//! wrong is the one way a model in this product spends money without a human
//! reading a sentence.
//!
//! **The case for "side effect".** The gate already ruled. An employee proposed
//! `Action::McpCall { tool }`, the gate allowed it, `Effects::call_tool` minted
//! a token and made the call; the server answered 402. Paying and replaying is
//! arguably just *finishing the call that was authorised*. It would need no new
//! `ActionKind`, no catalogue row, no schema, and the model would never see the
//! payment at all — which sounds like a security property.
//!
//! **The case for "an `Action`", which is the one that wins.** The token says
//! `McpCall`, and an `McpCall`'s subject is a [`McpTool`](agentos_domain::action::McpTool)
//! — a server handle and a tool handle. **It carries no amount.** Every
//! spending control in this system rules on an amount:
//! `SpendLimits::max_per_transaction`, `max_per_day`, `approval_above`, and the
//! reservation `gate.rs` takes against `spend_buckets` in the same transaction
//! as the ruling. An `McpCall` authorisation was minted without any of them
//! being consulted, because there was nothing for them to consult. Paying on
//! the strength of it means money leaves under a token no spend layer ever saw,
//! and — worse and quieter — **nothing is reserved**, so the day's running
//! total does not move and `ActionCtx::spent_today` becomes a lie for every
//! real payment that employee proposes afterwards. The structuring guard in
//! `policy::evaluate`'s `PaymentCreate` arm is built on that total. Fifty
//! side-effect 402s would walk straight past the wall
//! `fifty_small_payments_cannot_walk_past_the_daily_cap` proves is there.
//!
//! So paying a 402 is [`Action::PaymentCreate`], ruled on like any other
//! payment.
//!
//! **And it is not a new `ActionKind`.** That is a separate decision and it
//! goes the same way for the reason `Action::InvoiceIssue`'s own docs give: a
//! verb outside that enum is a verb no policy layer can withhold from a seat
//! and no role pack can decline. `PaymentCreate` already means "money leaves
//! this company"; an `X402Pay` beside it would be a *second* spelling of one
//! act, and the day the two disagreed the narrower one would be the one nobody
//! consulted — `PolicyLimits::allow_lead_upload` refuses to become an
//! `Action::LeadUpload` for exactly this reason, one field over.
//!
//! It is also free. A new kind would need a `turn::catalogue` row or a
//! `turn::UNSERVED` entry, and a catalogue row costs ~1.4k input tokens on
//! **every** model call whether or not it is used. Reusing `PaymentCreate`
//! costs nothing, because the model never proposes this at all: a 402 arrives
//! *inside* an effect that is already running, from bytes the employee never
//! asked for. There is no tool to add.
//!
//! # The switch, and why it is not a boolean
//!
//! A path built and switched off is only worth building if the off-state cannot
//! be flipped by accident. This one is held shut in three independent places,
//! and none of them is a config flag somebody can toggle:
//!
//! 1. **The taint wire.** A 402 body is a stranger's bytes by definition, so
//!    [`demand`] can only ever hand back an [`Untrusted<Demand>`].
//!    `Action::PaymentCreate` is `Risk::High`. `policy::evaluate`'s last
//!    expression denies every high-risk action derived from untrusted input
//!    with `DenyReason::UntrustedInput` — outright, with **no approval filed**,
//!    so not even a human queue is written from a stranger's number.
//!
//!    **The amount does not change the answer, and that is not free.** The wire
//!    used to read `decision.is_allow()`, which meant a demand at or above
//!    `approval_above` took the `RequireApproval` branch and was filed in the
//!    founder's queue instead — with the payee and the amount chosen by the
//!    server that sent the 402, under his own employee's name. A server that
//!    names its own price picks which branch it lands in, so a lock keyed on
//!    the amount is a lock the attacker holds the key to. Both amounts are
//!    proved below in
//!    `a_parsed_demand_is_refused_by_the_gate_whatever_the_policy`.
//!
//!    Turning this on is therefore not a code change here; it is a human
//!    looking at the challenge and re-proposing the payment from trusted
//!    ground, which is the approval flow that already exists.
//! 2. **[`PRICED_ASSETS`] is empty**, so [`demand`] refuses every real
//!    challenge before the taint wire is even reached. See below.
//! 3. **`PaymentProvider` is `NotConfigured`.** Even an allowed, human-approved
//!    payment answers `Terminal { code: "not_configured" }` and says so in the
//!    audit trail. `crates/app/src/mocks.rs` argues why that refusal is worth
//!    keeping, and this module does not touch it.
//!
//! # What blocks this, and the two decisions only the founder can take
//!
//! Neither of them is a missing wallet, which is the surprise.
//!
//! **1. An x402 challenge quotes an ERC-20 contract, and [`Money`] is
//! ISO-4217.** A challenge says `asset: "0x833589f…"`, `network: "base"`,
//! `maxAmountRequired: "10000"`. Nothing in that names a currency, and the
//! number of decimals in the asset's base unit is a property of the contract,
//! not of the message. Reading `"10000"` as $0.01 or as $100.00 differs by a
//! factor of ten thousand, and picking one is inventing a number. So
//! [`PRICED_ASSETS`] is the founder's table — asset, network, currency,
//! decimals — and it ships **empty**, which is this workspace's standing rule
//! that an empty allowlist denies. It is a `const` in source rather than a row
//! in a table on purpose: a table would be writable by whoever holds a tenant
//! API key, and *"this contract is EUR with 2 decimals"* is a sentence that
//! changes what every amount in the system means.
//!
//! **2. `Money` cannot hold a sub-cent price, and x402 exists to charge
//! sub-cent prices.** `Money` is a positive integer of minor units, so the
//! smallest amount it can express is one cent. A typical x402 price is $0.001.
//! [`demand`] refuses those rather than rounding them — borrowed verbatim from
//! `Money::from_major_str`, which already rules that more decimals than the
//! currency has "is an error, not a rounding opportunity" — because rounding a
//! per-call price up to a cent is a 10× overpayment on every call and rounding
//! it down is a zero. That refusal is honest and it is also a wall: with today's
//! `Money`, this employee can pay a 402 that asks for a whole cent and nothing
//! smaller.
//!
//! Widening it is not a change to this file. `SpendLimits`, the `reserved_minor`
//! column in `spend_buckets`, every audit row and every invoice are denominated
//! in the same minor units, so the question — *does `Money` grow a sub-minor
//! representation, or is x402 used only where the price is at least one minor
//! unit?* — is a founder's decision with consequences four crates wide. It is
//! written here because here is where it first bites, and it is left open.
//!
//! # What is deliberately not here
//!
//! No `X-PAYMENT` header, no proof encoding, no replay of the original request,
//! no facilitator client, no receipt table. All four are the *paying* half, and
//! every one of them is unreachable until the two decisions above are taken —
//! writing them now would be scaffolding whose first real use is the day
//! somebody has to re-read assumptions nobody wrote down. What is here is the
//! half that has to be right before any of that is safe: **the amount**.
//!
//! # The bridge from *a human approved* to *the money moved*
//!
//! The intended chain is *MCP call → 402 → read → `PaymentCreate` → gate →
//! budget → human approval → wallet → payment → replay → receipt*. Seven of
//! those exist and `crates/app/tests/x402_chain.rs` runs them in one hand
//! against a loopback double, from a real 402 on the wire to the approval line
//! and its hash. **This section is the eighth link, and it is written here
//! because the answer used to be spread across four files.**
//!
//! ## Where it stops, to the line
//!
//! `apps/server/src/routes/approvals.rs::approve` calls
//! [`PolicyGate::redeem_approval`](crate::gate::PolicyGate::redeem_approval),
//! gets an `Authorized<Action>` back, returns its `decision_id`, and **drops
//! it**. Nothing further happens, and nothing further *can*: every method on
//! [`Effects`](crate::effects::Effects) is bound `A: Subject<Of = …>`, the
//! `subject!` macro implements [`Subject`](crate::effects::Subject) for one
//! newtype per effect, and **there is no `impl Subject for Action`**. So the
//! token that route mints is a receipt for a ruling, not a capability to do
//! anything with it. `crates/app/tests/ui/effects_untrusted_action.rs` is the
//! compiler holding that shut.
//!
//! ## It is a decision, and this is the second time it is being taken
//!
//! `crate::sourcing::place_order` reached the same wall from the other
//! direction and wrote it down: it returns an `ApprovalId` because *"the only
//! thing this function could have returned instead is an `Authorized<Action>`,
//! which no `Effects` method accepts. Money moves later, elsewhere, through a
//! payment the gate rules on separately."*
//!
//! The reason it is a decision rather than an omission: turning the stored
//! `Action` back into a typed subject is a `match` over every variant of
//! [`Action`], from a jsonb column to a newtype, kept in step with the enum by
//! nothing — and the arm somebody got wrong would be the arm that spends a
//! human's click on a different effect from the one they read. That match is
//! worth writing when something is waiting on the far side of it. Today nothing
//! is: `PaymentProvider` is `NotConfigured` (see `crate::mocks`), so it would be
//! a whole-enum match feeding a port whose contract is to refuse.
//!
//! ## What the dead end costs today, named rather than left to be discovered
//!
//! A redeemed payment approval reserves. `Authorized::reservation` says the
//! executor owes it a `spend::settle` or an `org::release` — and the only code
//! that pays that debt is `Effects::book_effect`, reached from no path that
//! starts at this route. **So an approved payment holds the day's headroom
//! until the bucket's day rolls over.** That is the conservative direction —
//! headroom stays spent and is never handed back for money that did not move —
//! but it is a real consequence and it is the *first* thing a bridge has to
//! fix, not the last.
//!
//! ## What crossing it would take, smallest first
//!
//! 1. **A typed redemption for one kind.** `redeem_approval` is already generic
//!    over `A: Authorizable`; the route passes a bare `Action` only because
//!    that is what the request body deserialises to. The bridge is a route that
//!    reads the body into [`effects::PaymentCreate`](crate::effects::PaymentCreate)
//!    when `approvals.action_kind` says `payment_create`, redeems *that*, and
//!    hands the token to [`Effects::pay`](crate::effects::Effects::pay) with
//!    the memo. No new type, no new trait, no `turn::catalogue` row — and
//!    routing through `Effects::pay` is also what settles or releases the
//!    reservation above. That is the whole of link eight.
//! 2. **A `PaymentProvider` that is not `NotConfigured`.** Everything in (1) is
//!    reachable and testable before this exists; it just answers
//!    `Terminal { code: "not_configured" }` in the audit trail.
//! 3. **The two decisions above** — [`PRICED_ASSETS`] and whether [`Money`]
//!    grows a sub-minor representation. Those are what make any of it reachable
//!    from a *402* rather than from a human typing an amount into a form.
//! 4. **Then, and only then, the x402-specific half**: `X-PAYMENT`, proof
//!    encoding, the facilitator, the receipt — and the replay, which is the one
//!    link nothing in this workspace has a shape for. The original `tools/call`
//!    lived inside `Effects::call_tool`, which returned long before a human
//!    looked at the queue, so "replay the request" is a **new**
//!    `Action::McpCall` ruled on again, not a resumption of the old one. Nobody
//!    has decided whether that second call is free because the payment bought
//!    it, or is its own spend against `turn::Budgets::max_tool_calls`. Written
//!    here because that is a founder's question and this is the first place it
//!    is visible.

use agentos_domain::action::Action;
use agentos_domain::money::{Currency, Money, MoneyError};
use agentos_domain::untrusted::Untrusted;
use serde::Deserialize;

/// The most of a 402 body this build will parse.
///
/// Borrowed from `peer_keys::MAX_DIRECTORY_BYTES`, which caps the other place
/// this workspace reads a document off a stranger's HTTP response, rather than
/// invented here — two caps on one kind of risk is one cap somebody forgets to
/// raise.
pub const MAX_CHALLENGE_BYTES: usize = 64 * 1024;

/// The longest payee or memo this build will carry, and **not a number chosen
/// here**.
///
/// It is `invoices_memo_shape`'s upper bound from `migrations/0066_invoices.sql`
/// — the workspace's existing CHECK on "one line saying what a money movement
/// was for", money in the other direction — and it is also
/// `agentos_store::backlog::MAX_TITLE`. Two places already answer this question
/// with 200; inventing a third answer for the same kind of field is how the
/// three drift.
///
/// Enforced before anything opens a transaction, for the reason `turn.rs` gives
/// on `add_work_item`: a CHECK violation surfaces as `StoreError::Database`,
/// which costs a whole run rather than one refusal.
///
/// `pub(crate)` because `turn.rs`'s `pay` arm applies it to the payee a *model*
/// names, on the same argument this module applies it to the payee a *server*
/// names. Two spellings of one bound would be the drift the paragraph above
/// refuses.
pub(crate) const MAX_FIELD_CHARS: usize = 200;

/// One on-chain asset the operator has told this deployment how to read.
///
/// Every field is load-bearing and none of them is derivable from the
/// challenge: the same contract address exists on several networks, and
/// `decimals` is a property of the contract that the 402 body does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asset {
    /// The x402 `network` label, e.g. `"base"`. Compared case-insensitively.
    pub network: &'static str,
    /// The token contract address. Compared case-insensitively, because
    /// EIP-55 checksummed and all-lowercase spellings are the same address.
    pub address: &'static str,
    /// What one unit of this asset is, in the vocabulary the Policy Gate,
    /// `SpendLimits` and `spend_buckets` all speak.
    pub currency: Currency,
    /// Decimal places in the asset's base unit — 6 for USDC, 18 for most
    /// ERC-20s. `maxAmountRequired` is quoted in base units, so this is the
    /// difference between a cent and a hundred dollars.
    pub decimals: u32,
}

/// **The switch.** Which on-chain assets this deployment can price, and empty
/// on purpose.
///
/// Empty means [`demand`] refuses every challenge with
/// [`ChallengeError::UnknownAsset`], which is the same rule every allowlist in
/// `PolicyLimits` follows: a list nobody wrote is a refusal, never a default.
///
/// # The founder's question, left open
///
/// Filling this in is a statement about money — *this contract, on this
/// network, is that currency, with that many decimals* — and it cannot be
/// derived from anything a server sends us, because a hostile server would then
/// be choosing the multiplier on its own invoice. Whoever adds the first row
/// owes an answer to: which asset, on which network, is trusted enough that an
/// employee may pay in it at all; and what happens when its price against the
/// quoted currency moves, given that `SpendLimits` is denominated in fiat and
/// nothing in this workspace holds a rate.
///
/// The second decision is on the module docs: a whole minor unit is the
/// smallest amount `Money` can express, and x402's normal price is smaller.
pub const PRICED_ASSETS: &[Asset] = &[];

/// A 402 read to the point where the Policy Gate could rule on it.
///
/// Exactly what `Effects::pay` needs, split the way that method splits it —
/// [`Self::action`], which is what the gate rules on and what an approval
/// hashes, and the memo, which no rule and no hash is taken over. There is no
/// fourth field, and specifically no scheme, network or deadline: those are the
/// *transport's* problem and the transport does not exist. A struct that
/// carried them would be guessing at the shape of code nobody has written.
///
/// `payee` used to sit beside the memo on an `effects::PaymentInstruction`, "on
/// the side because a payee is not something the gate has an opinion about".
/// The gate still has none. The approval hash and the human reading the queue do,
/// and a 402 is exactly the case where the payee is a *stranger's* string — so
/// it is on the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demand {
    /// What the server wants, in a currency this deployment named.
    pub amount: Money,
    /// The address it wants it at.
    pub payee: String,
    /// What it is charging for; ends up in the audit row.
    pub memo: String,
}

impl Demand {
    /// The action the gate would rule on.
    ///
    /// Takes `&self` rather than consuming, so a caller can put the action in
    /// front of the gate and still hold the memo for the effect — the same
    /// reason `a2a::sign_request` borrows its token.
    #[must_use]
    pub fn action(&self) -> Action {
        Action::PaymentCreate {
            amount: self.amount,
            payee: self.payee.clone(),
        }
    }
}

/// Why a 402 body did not become a [`Demand`].
///
/// Every variant is a refusal to pay, never a smaller payment. The codes are
/// low-cardinality metric labels in the workspace's usual style.
///
/// Nothing here quotes the server's own text back. A 402 body is hostile bytes
/// and an error message is one of the places they would otherwise reach a log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    /// Longer than [`MAX_CHALLENGE_BYTES`], or not JSON, or not the shape x402
    /// v1 describes. One variant for all three, because the useful distinction
    /// to an operator is "this server is not speaking x402 to us".
    #[error("not a readable x402 challenge")]
    Unreadable,

    /// A version this build has not been written against. Not an
    /// [`Unreadable`](Self::Unreadable), because the difference matters: the
    /// server is speaking x402 and we are the ones out of date.
    #[error("x402 version {0} is not the version this build reads")]
    UnsupportedVersion(u64),

    /// `accepts[]` was empty, or held nothing this build could price. A 402
    /// that offers no payable terms is a 402 that cannot be paid.
    #[error("no acceptable terms in the challenge")]
    NoTerms,

    /// The asset and network are not in [`PRICED_ASSETS`], so there is no
    /// currency to state the amount in. **This is the default answer**, because
    /// that table ships empty.
    #[error("no priced asset matches this challenge")]
    UnknownAsset,

    /// The amount is not a whole number of base units, overflows, or does not
    /// land on a whole minor unit of the currency it maps to.
    ///
    /// The last one is the common case and it is a refusal on purpose: see the
    /// module docs on why a sub-cent price is not rounded.
    #[error("the amount cannot be stated as {0}")]
    Unrepresentable(&'static str),

    /// A payee or memo longer than a column will take.
    #[error("a field is longer than this build stores")]
    FieldTooLong,
}

impl ChallengeError {
    /// Stable, low-cardinality metric label.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            ChallengeError::Unreadable => "unreadable",
            ChallengeError::UnsupportedVersion(_) => "unsupported_version",
            ChallengeError::NoTerms => "no_terms",
            ChallengeError::UnknownAsset => "unknown_asset",
            ChallengeError::Unrepresentable(_) => "unrepresentable",
            ChallengeError::FieldTooLong => "field_too_long",
        }
    }
}

/// The only x402 version this build reads.
const X402_VERSION: u64 = 1;

/// The wire shape, named only as far as the decision needs it.
///
/// `#[serde(rename_all = "camelCase")]` because that is what x402 sends;
/// unknown members are ignored, which is deliberate — a server that adds a
/// field must not make its 402 unreadable, and nothing here acts on a field it
/// does not name.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeWire {
    x402_version: u64,
    #[serde(default)]
    accepts: Vec<TermsWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TermsWire {
    network: String,
    asset: String,
    /// A string, not a number, and that is x402's own choice: base units of an
    /// 18-decimal token do not fit in an IEEE double, and a price silently
    /// rounded by a JSON parser is the bug this whole module is about.
    max_amount_required: String,
    pay_to: String,
    /// What the resource is. Ends up in the memo, so an operator asking "what
    /// was that payment for" has an answer — the lesson `Effects::pay` learned
    /// from the other side.
    #[serde(default)]
    resource: String,
    #[serde(default)]
    description: String,
}

/// Read a 402 response body into the demand the Policy Gate would rule on.
///
/// `body` is the response body, wrapped where it was received. `assets` is the
/// deployment's price table — pass [`PRICED_ASSETS`], which is empty, unless
/// you are a test.
///
/// # The return type is the security property
///
/// [`Untrusted<Demand>`] and never a bare one, because there is no path by
/// which a server's own 402 becomes trusted input. A caller therefore holds
/// `Untrusted<Demand>`, builds `Untrusted<Action>` from it, and the gate
/// refuses it — see the module docs and the test below. That is not a
/// convention this function hopes callers follow; it is the only thing its
/// signature lets them do.
///
/// # Why the first acceptable term wins
///
/// `accepts[]` is a list of alternatives and this build takes the first one it
/// can price rather than the cheapest. Choosing the cheapest would mean
/// comparing amounts across currencies, which needs a rate table this workspace
/// does not have and must not grow here; and with [`PRICED_ASSETS`] empty the
/// list of prices this build can compare is empty too. First-match is the
/// answer that involves no arithmetic across currencies at all.
pub fn demand(
    body: &Untrusted<Vec<u8>>,
    assets: &[Asset],
) -> Result<Untrusted<Demand>, ChallengeError> {
    let bytes = body.expose_for_parsing();
    if bytes.len() > MAX_CHALLENGE_BYTES {
        return Err(ChallengeError::Unreadable);
    }
    let wire: ChallengeWire =
        serde_json::from_slice(bytes).map_err(|_| ChallengeError::Unreadable)?;
    if wire.x402_version != X402_VERSION {
        return Err(ChallengeError::UnsupportedVersion(wire.x402_version));
    }
    if wire.accepts.is_empty() {
        return Err(ChallengeError::NoTerms);
    }

    // A blanket `NoTerms` would send an operator to the wrong table: "we have
    // priced this asset and cannot state the amount" and "we have priced
    // nothing" are different problems with different fixes. So the last term's
    // own reason survives.
    //
    // ponytail: *last*, not *most informative*. With several unpriceable terms
    // the reported reason is whichever `accepts[]` happened to end on, which
    // can hide a better one. Rank the variants only if an operator is actually
    // misled by it; a priority order invented now is a rule nobody has needed.
    let mut refusal = ChallengeError::NoTerms;
    for terms in &wire.accepts {
        match read_terms(terms, assets) {
            Ok(demand) => return Ok(Untrusted::new(demand)),
            Err(why) => refusal = why,
        }
    }
    Err(refusal)
}

/// One entry of `accepts[]`, priced or refused.
fn read_terms(terms: &TermsWire, assets: &[Asset]) -> Result<Demand, ChallengeError> {
    let asset = assets
        .iter()
        .find(|a| {
            a.network.eq_ignore_ascii_case(terms.network.trim())
                && a.address.eq_ignore_ascii_case(terms.asset.trim())
        })
        .ok_or(ChallengeError::UnknownAsset)?;

    let amount = to_money(&terms.max_amount_required, asset)?;

    let payee = terms.pay_to.trim();
    let memo = memo_of(terms);
    // Both ends of `invoices_memo_shape`, which is `between 1 and 200`, applied
    // to the payment side. An empty payee is a payment addressed to nobody; an
    // empty memo is a payment nobody can explain afterwards, which is the exact
    // gap `Effects::pay` closed from the other direction when somebody asked
    // "what was that payment for" and the audit row had no answer. Neither is a
    // shape a real x402 challenge has — `resource` is required by the protocol
    // — so refusing them costs nothing and asserts something.
    if payee.is_empty() || memo.is_empty() {
        return Err(ChallengeError::Unreadable);
    }
    if payee.chars().count() > MAX_FIELD_CHARS || memo.chars().count() > MAX_FIELD_CHARS {
        return Err(ChallengeError::FieldTooLong);
    }

    Ok(Demand {
        amount,
        payee: payee.to_owned(),
        memo,
    })
}

/// What the payment was for, in one line.
///
/// The server's own `description` when it wrote one, else the resource it is
/// charging for. Both are the server's words; they are inside the
/// [`Untrusted`] wrapper the whole way, and they land in an audit row rather
/// than in a prompt.
fn memo_of(terms: &TermsWire) -> String {
    let description = terms.description.trim();
    if description.is_empty() {
        terms.resource.trim().to_owned()
    } else {
        description.to_owned()
    }
}

/// Base units of `asset` to [`Money`], or a refusal.
///
/// The whole conversion is one question — how many of the asset's decimal
/// places does the currency have room for — and its two answers are a scale up
/// and an exact division. **A remainder is a refusal**, which is
/// `Money::from_major_str`'s own rule ("more decimals than the currency has is
/// an error, not a rounding opportunity") applied where the digits arrive in
/// base units instead of after a dot.
fn to_money(base_units: &str, asset: &Asset) -> Result<Money, ChallengeError> {
    let raw = base_units.trim();
    // `u128::from_str` accepts a leading `+`; an amount is not a signed
    // quantity and a spelling that only one parser in the pipeline understands
    // is a spelling that means two different things in two places.
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ChallengeError::Unrepresentable("a whole number of units"));
    }
    // u128 rather than u64: an 18-decimal token quotes ordinary prices in
    // numbers that overflow u64, and refusing them as "too large" would be a
    // parser artefact reported as a policy.
    let units: u128 = raw
        .parse()
        .map_err(|_| ChallengeError::Unrepresentable("a whole number of units"))?;

    let exponent = asset.currency.exponent();
    let minor: u128 = if asset.decimals >= exponent {
        let divisor = 10u128
            .checked_pow(asset.decimals - exponent)
            .ok_or(ChallengeError::Unrepresentable("this asset's precision"))?;
        if !units.is_multiple_of(divisor) {
            return Err(ChallengeError::Unrepresentable(
                "a whole minor unit of this currency",
            ));
        }
        units / divisor
    } else {
        let factor = 10u128
            .checked_pow(exponent - asset.decimals)
            .ok_or(ChallengeError::Unrepresentable("this asset's precision"))?;
        units
            .checked_mul(factor)
            .ok_or(ChallengeError::Unrepresentable("an amount this size"))?
    };

    let minor =
        u64::try_from(minor).map_err(|_| ChallengeError::Unrepresentable("an amount this size"))?;
    Money::new(minor, asset.currency).map_err(|err| match err {
        // Zero is the sub-cent case: the division above was exact only because
        // the price was smaller than one minor unit. It is the commonest real
        // x402 price and the module docs say why it is refused.
        MoneyError::Zero => ChallengeError::Unrepresentable("a payable amount"),
        _ => ChallengeError::Unrepresentable("an amount this size"),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentos_domain::action::{ActionCtx, Actor, Channel};
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::policy::{
        Decision, DenyReason, EffectivePolicy, PolicyLimits, SpendLimits,
    };
    use agentos_domain::untrusted::TrustLabel;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    /// USDC on Base, as a deployment that had taken the decision would write it.
    /// **A fixture, not a default** — [`PRICED_ASSETS`] stays empty.
    const USDC: Asset = Asset {
        network: "base",
        address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        currency: Currency::Usd,
        decimals: 6,
    };

    fn cents(minor: u64) -> Money {
        Money::new(minor, Currency::Usd).expect("nonzero")
    }

    fn yen(minor: u64) -> Money {
        Money::new(minor, Currency::Jpy).expect("nonzero")
    }

    fn body(value: serde_json::Value) -> Untrusted<Vec<u8>> {
        Untrusted::new(serde_json::to_vec(&value).expect("serialise"))
    }

    /// A well-formed v1 challenge for `minor` USDC base units.
    fn challenge(base_units: &str) -> Untrusted<Vec<u8>> {
        body(json!({
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": base_units,
                "resource": "https://api.example.com/lookup",
                "description": "One visa rule lookup",
                "mimeType": "application/json",
                "payTo": "0x0000000000000000000000000000000000000001",
                "maxTimeoutSeconds": 60,
                "asset": USDC.address,
            }],
        }))
    }

    // -- the switch --------------------------------------------------------

    /// The state this ships in: a perfectly well-formed challenge, refused,
    /// because nobody has said what the asset is worth.
    ///
    /// This is the whole "built and switched off" claim in one assertion. If
    /// somebody puts a row in `PRICED_ASSETS`, this test fails — which is the
    /// point, because that row is a decision about money and it should not be
    /// possible to take it quietly.
    #[test]
    fn the_shipped_deployment_prices_nothing() {
        assert!(
            PRICED_ASSETS.is_empty(),
            "a priced asset is a founder's decision about money, not a default"
        );
        assert_eq!(
            demand(&challenge("10000"), PRICED_ASSETS),
            Err(ChallengeError::UnknownAsset)
        );
    }

    /// **The load-bearing test.** A challenge this build *can* price still
    /// cannot move money, because what comes back is untrusted and
    /// `PaymentCreate` is high risk.
    ///
    /// The policy here is deliberately generous, and the test runs **two
    /// amounts** because the size of the demand used to decide which half of
    /// the gate answered:
    ///
    /// - $0.01 is under `approval_above`, so the rules say `Allow` and the
    ///   taint wire overrides it.
    /// - $600 is over `approval_above` ($500) and still under the
    ///   per-transaction cap ($1,000), so the rules say `RequireApproval`.
    ///   The wire used to test `decision.is_allow()` and skipped that branch
    ///   entirely — a server could name its own price above the threshold and
    ///   have the demand filed in the founder's queue as his employee's
    ///   proposal. Lock #1 in the module docs was false for exactly this
    ///   amount, and one number is the whole difference between the two cases.
    ///
    /// Either way the refusal is about provenance and nothing else, which is
    /// what makes the off-switch unforgeable: it is not a flag, it is
    /// `policy::evaluate`'s last expression.
    #[test]
    fn a_parsed_demand_is_refused_by_the_gate_whatever_the_policy() {
        let limits = PolicyLimits {
            spend: Some(
                SpendLimits::try_new(
                    Money::from_major(1_000, Currency::Usd).expect("cap"),
                    Money::from_major(10_000, Currency::Usd).expect("cap"),
                    Money::from_major(500, Currency::Usd).expect("threshold"),
                )
                .expect("coherent"),
            ),
            allowed_channels: BTreeSet::from([Channel::Web]),
            ..PolicyLimits::default()
        };
        let policy =
            EffectivePolicy::try_new(&limits, &limits, &limits, &limits).expect("coherent");
        let actor = Actor::new(
            TenantId::from_uuid(Uuid::nil()),
            EmployeeId::from_uuid(Uuid::nil()),
        );

        let tainted = ActionCtx {
            trust: TrustLabel::Untrusted,
            ..ActionCtx::new(actor, Utc::now())
        };
        let ours = ActionCtx {
            trust: TrustLabel::Trusted,
            ..ActionCtx::new(actor, Utc::now())
        };

        // ("10000" = $0.01, under the threshold; "600000000" = $600, over it.)
        for (base_units, trusted_says_allow) in [("10000", true), ("600000000", false)] {
            let parsed = demand(&challenge(base_units), &[USDC]).expect("priced");
            let action = parsed.map(|d| d.action());

            // Untrusted, as `demand` forces: denied, and no approval is filed.
            assert_eq!(
                agentos_domain::policy::evaluate(&policy, action.expose_for_parsing(), &tainted),
                Decision::Deny {
                    reason: DenyReason::UntrustedInput
                },
                "a server's own demand for {base_units} must not reach the executor"
            );

            // The same action from our own code is not refused, which is what
            // makes the refusal above about provenance rather than about
            // limits. Below the threshold that is an `Allow`; above it, the
            // human path the taint wire is deliberately withholding.
            let ruling =
                agentos_domain::policy::evaluate(&policy, action.expose_for_parsing(), &ours);
            if trusted_says_allow {
                assert!(
                    ruling.is_allow(),
                    "the caps are wide enough; the refusal has to be the taint: {ruling:?}"
                );
            } else {
                assert!(
                    matches!(ruling, Decision::RequireApproval { .. }),
                    "the $600 case must be the escalating arm, or it proves nothing: {ruling:?}"
                );
            }
        }
    }

    // -- the amount --------------------------------------------------------

    /// The conversion, in the direction that matters: base units down to minor
    /// units, exactly, or not at all.
    #[test]
    fn base_units_become_minor_units_or_nothing() {
        let paid = |units: &str| {
            demand(&challenge(units), &[USDC]).map(|d| d.into_inner_for_rendering().amount.minor())
        };

        // 10_000 base units of a 6-decimal token is $0.01 — one cent.
        assert_eq!(paid("10000"), Ok(1));
        assert_eq!(paid("1230000"), Ok(123));

        let not_whole = Err(ChallengeError::Unrepresentable(
            "a whole minor unit of this currency",
        ));
        // $0.001, the price x402 exists to charge: a whole number of base
        // units, and not a whole number of cents. Refused, never rounded — the
        // wall the module docs name, in one assertion.
        assert_eq!(paid("1000"), not_whole);
        // One base unit: $0.000001. Same refusal, and specifically *not* zero
        // and not a cent.
        assert_eq!(paid("1"), not_whole);
        // Off by one base unit from a whole cent. The dangerous near-miss: a
        // rounding implementation would answer `Ok(1)` here.
        assert_eq!(paid("10001"), not_whole);
        // Zero is the other way to be unpayable, and it reaches `Money::new`'s
        // own refusal rather than the division's.
        assert_eq!(
            paid("0"),
            Err(ChallengeError::Unrepresentable("a payable amount"))
        );
    }

    /// A zero-decimal currency and an 18-decimal token, i.e. both branches of
    /// the scale. JPY has no minor unit, so a 0-decimal asset scales up.
    #[test]
    fn the_scale_runs_both_ways() {
        const YEN_TOKEN: Asset = Asset {
            network: "base",
            address: "0xabc",
            currency: Currency::Jpy,
            decimals: 0,
        };
        assert_eq!(to_money("500", &YEN_TOKEN), Ok(yen(500)));

        // A 2-decimal currency out of a 0-decimal asset: scale up by 100.
        const CENTLESS_USD: Asset = Asset {
            network: "base",
            address: "0xdef",
            currency: Currency::Usd,
            decimals: 0,
        };
        assert_eq!(to_money("7", &CENTLESS_USD), Ok(cents(700)));

        // 18 decimals: an ordinary price overflows u64 base units, which is why
        // the arithmetic is u128.
        const WEI: Asset = Asset {
            network: "base",
            address: "0xfff",
            currency: Currency::Usd,
            decimals: 18,
        };
        assert_eq!(
            to_money("20000000000000000", &WEI),
            Ok(cents(2)),
            "0.02 of an 18-decimal token is two cents"
        );
    }

    // -- the parser --------------------------------------------------------

    #[test]
    fn a_challenge_this_build_cannot_read_is_never_half_read() {
        // Not JSON.
        assert_eq!(
            demand(&Untrusted::new(b"402".to_vec()), &[USDC]),
            Err(ChallengeError::Unreadable)
        );
        // Over the cap, and **valid JSON**, which is the only version of this
        // assertion that proves anything: a fixture that is merely long and
        // malformed is refused by serde whether or not the cap exists, so it
        // passes with the cap deleted. This one parses into a `FieldTooLong`
        // the moment the length check is removed.
        let padded = body(json!({
            "x402Version": 1,
            "accepts": [{
                "network": "base", "asset": USDC.address, "maxAmountRequired": "10000",
                "payTo": "0x0000000000000000000000000000000000000001",
                "description": "x".repeat(MAX_CHALLENGE_BYTES),
            }],
        }));
        assert!(
            padded.expose_for_parsing().len() > MAX_CHALLENGE_BYTES,
            "the fixture has to be over the cap for the cap to be what refuses it"
        );
        assert_eq!(demand(&padded, &[USDC]), Err(ChallengeError::Unreadable));
        // A version nobody wrote this against.
        assert_eq!(
            demand(&body(json!({"x402Version": 2, "accepts": []})), &[USDC]),
            Err(ChallengeError::UnsupportedVersion(2))
        );
        // Speaking x402 and offering nothing.
        assert_eq!(
            demand(&body(json!({"x402Version": 1, "accepts": []})), &[USDC]),
            Err(ChallengeError::NoTerms)
        );
        // A payee nobody can be paid at — and a memo, so the *payee* is the
        // only thing wrong with it.
        let nobody = body(json!({
            "x402Version": 1,
            "accepts": [{
                "network": "base", "asset": USDC.address, "maxAmountRequired": "10000",
                "payTo": "   ", "description": "One visa rule lookup",
            }],
        }));
        assert_eq!(demand(&nobody, &[USDC]), Err(ChallengeError::Unreadable));

        // A payment nobody could explain afterwards: a real payee, no
        // description and no resource. `invoices_memo_shape` refuses the empty
        // memo on the invoice side and this refuses it on the payment side.
        let unexplained = body(json!({
            "x402Version": 1,
            "accepts": [{
                "network": "base", "asset": USDC.address, "maxAmountRequired": "10000",
                "payTo": "0x0000000000000000000000000000000000000001",
            }],
        }));
        assert_eq!(
            demand(&unexplained, &[USDC]),
            Err(ChallengeError::Unreadable)
        );
    }

    /// A different network is a different asset, even at the same address.
    /// Getting this wrong pays testnet prices out of a mainnet balance.
    #[test]
    fn the_network_is_part_of_the_asset() {
        let sepolia = body(json!({
            "x402Version": 1,
            "accepts": [{
                "network": "base-sepolia", "asset": USDC.address,
                "maxAmountRequired": "10000",
                "payTo": "0x0000000000000000000000000000000000000001",
            }],
        }));
        assert_eq!(demand(&sepolia, &[USDC]), Err(ChallengeError::UnknownAsset));
    }

    /// `accepts[]` is a list of alternatives: an unpriceable one ahead of a
    /// priceable one must not lose the payment, and the reported refusal is the
    /// last term's rather than a blanket "no terms".
    #[test]
    fn the_first_priceable_term_wins_and_the_reason_survives() {
        let mixed = body(json!({
            "x402Version": 1,
            "accepts": [
                { "network": "solana", "asset": "So111", "maxAmountRequired": "10000",
                  "payTo": "0x0000000000000000000000000000000000000001" },
                { "network": "base", "asset": USDC.address, "maxAmountRequired": "20000",
                  "payTo": "0x0000000000000000000000000000000000000002",
                  "description": "Second choice" },
            ],
        }));
        let picked = demand(&mixed, &[USDC])
            .expect("the second term is priceable")
            .into_inner_for_rendering();
        assert_eq!(picked.amount, Money::new(2, Currency::Usd).expect("2c"));
        assert_eq!(picked.memo, "Second choice");

        // Priced asset, unpayable amount: the operator learns that rather than
        // "no terms", which would send them looking at the wrong table.
        let dust = body(json!({
            "x402Version": 1,
            "accepts": [
                { "network": "solana", "asset": "So111", "maxAmountRequired": "10000",
                  "payTo": "0x1" },
                { "network": "base", "asset": USDC.address, "maxAmountRequired": "1",
                  "payTo": "0x0000000000000000000000000000000000000001" },
            ],
        }));
        assert_eq!(
            demand(&dust, &[USDC]),
            Err(ChallengeError::Unrepresentable(
                "a whole minor unit of this currency"
            ))
        );
    }

    /// The memo is what an operator reads when they ask what a payment was
    /// for, and it falls back to the resource rather than to nothing.
    #[test]
    fn the_memo_says_what_was_bought() {
        let described = demand(&challenge("10000"), &[USDC])
            .expect("priced")
            .into_inner_for_rendering();
        assert_eq!(described.memo, "One visa rule lookup");

        let bare = body(json!({
            "x402Version": 1,
            "accepts": [{
                "network": "base", "asset": USDC.address, "maxAmountRequired": "10000",
                "payTo": "0x0000000000000000000000000000000000000001",
                "resource": "https://api.example.com/lookup",
            }],
        }));
        assert_eq!(
            demand(&bare, &[USDC])
                .expect("priced")
                .into_inner_for_rendering()
                .memo,
            "https://api.example.com/lookup"
        );

        // A server that pads its description does not get to pad a column.
        let long = body(json!({
            "x402Version": 1,
            "accepts": [{
                "network": "base", "asset": USDC.address, "maxAmountRequired": "10000",
                "payTo": "0x0000000000000000000000000000000000000001",
                "description": "x".repeat(MAX_FIELD_CHARS + 1),
            }],
        }));
        assert_eq!(demand(&long, &[USDC]), Err(ChallengeError::FieldTooLong));
    }

    /// An amount is digits. A signed or floating spelling is a spelling two
    /// parsers would disagree about, and disagreement about a price is the
    /// whole risk.
    #[test]
    fn an_amount_is_digits_and_nothing_else() {
        for spelling in ["-10000", "+10000", "1e4", "10000.0", "0x2710", "", " "] {
            assert!(
                matches!(
                    demand(&challenge(spelling), &[USDC]),
                    Err(ChallengeError::Unrepresentable(_))
                ),
                "{spelling:?} was read as an amount"
            );
        }
    }
}
