//! The only code in the workspace that calls a provider, and the only way to
//! call one is to hand it an [`Authorized`] token.
//!
//! # Why the provider handles are private
//!
//! [`Effects`] owns the email, telephony, browser, MCP and payment handles as
//! private fields and exposes exactly one method per effect. There is no
//! accessor, no `Deref`, and no method that takes a bare [`Action`]. So "an
//! employee sent an email without a policy decision" is not a bug review has to
//! catch — it is a program that does not compile, and
//! `tests/ui/effects_bare_action.rs` is that claim checked by rustc.
//!
//! # Why each method takes its own subject type
//!
//! `Authorized<A>` is generic, so a plain `Authorized<Action>` would let a
//! token minted for an email be spent on [`Effects::pay`] — the gate ruled, and
//! it ruled on something else. The subjects below ([`EmailSend`], [`SmsSend`],
//! …) are one type per effect, and each method is bound to exactly one of them
//! via [`Subject`]. The token's *type* therefore says which effect was
//! authorised, and the counterparty inside it is the counterparty the provider
//! is given: [`Effects::send_email`] reads `to` off the token and never off the
//! body, so a rendered message cannot be re-addressed after the ruling.
//!
//! Both trust flavours reach the same method: `Authorized<EmailSend>` for an
//! operator's request and `Authorized<Untrusted<EmailSend>>` for a draft the
//! model wrote after reading a stranger's email. They are different types all
//! the way through the gate — which is what makes `evaluate` refuse the
//! high-risk ones — and converge only here, where the effect is finally
//! performed.
//!
//! # What gets recorded
//!
//! Every attempt writes one `provider_call_attempted` audit row carrying the
//! token's [`DecisionId`](agentos_domain::ids::DecisionId) — success and
//! failure alike. A trail that only records successes cannot answer "we
//! authorised this payment, did it go out?", which is the question an incident
//! starts with. Provider failures are *classified*
//! ([`ProviderError::is_retryable`]) and returned, never swallowed.
//!
//! # The reservation
//!
//! A payment token carries the spend reservation the gate took. This module is
//! the executor the gate's docs refer to: it settles on success and releases on
//! failure, in the same transaction as the audit row, so headroom is never held
//! by a payment that did not happen.

use std::sync::Arc;

use agentos_domain::action::{Action, Domain, E164, EmailAddress, McpTool};
use agentos_domain::ids::{AppointmentId, DecisionId, IdempotencyKey, InvoiceId, Slug, WorkItemId};
use agentos_domain::money::Money;
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_providers::browser::{BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep};
use agentos_providers::email::{EmailProvider, OutboundEmail, ProviderMessageId};
use agentos_providers::leads::{self as leads, LeadSink};
use agentos_providers::telephony::{
    OpenWindow, OutboundCall, OutboundSms, OutboundWhatsapp, TelephonyProvider,
};
use agentos_providers::{ProviderBinding, ProviderError};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::invoices;
use agentos_store::org;
use agentos_store::provisioning;
use agentos_store::revenue::RevenueError;
use agentos_store::spend;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use url::Url;
use uuid::Uuid;

use crate::backlog::{Backlog, BacklogError, PgBacklog, WorkAction};
use crate::calendar::{Calendar, CalendarError, PgCalendar};
use crate::gate::{Authorizable, Authorized, Principal};
use crate::inbound::{self, Briefing, Delivered, Errand, InternalError, Thread};
use crate::turn::WHOLE_PAGE;

/// What [`Effects::read_page`] answers when this employee has no browser
/// context to drive.
///
/// A code rather than a message, because it is handed to a model as a failed
/// tool result: "your browser is not provisioned" is a fact about this
/// deployment that no amount of rephrasing the request will change, and the
/// model needs to stop asking rather than try a different URL.
pub const NO_BROWSER: &str = "no_browser";

/// A step that writes, driven by a token the gate ruled as a *read*.
///
/// **This was reachable, and widening reads made it live.** `Browse`
/// (`proof_of_need::Browse`) rules as `Action::BrowserRead` and declares
/// `type Of = BrowserWrite`, so it satisfies [`Effects::browse_write`]'s bound
/// and could drive a `Type` or a `Click`. `read_page`'s own documentation
/// asserted the opposite — *"a token minted for reading cannot be spent on
/// `Effects::browse_write`"* — which was a claim about a bound that both
/// tokens satisfy.
///
/// It mattered little while a read had to clear `allowed_domains`: the two
/// rulings then permitted the same set of hosts, so the escalation bought
/// nothing. Since reads clear `Channel::Web` alone, a read ruling covers the
/// entire public web and a write ruling covers a list an operator typed — so
/// the same token now spans two very different permissions, and the audit row,
/// written from `to_action().kind()`, would have called the typing a
/// `browser_read`.
pub const READ_TOKEN: &str = "read_token";

/// The browser was asked where it is and answered with something that is not a
/// URL — or answered a [`BrowserStep::Goto`] with an outcome that carries no
/// address at all.
///
/// A code and not a panic, because it is a fact about an adapter rather than
/// about a decision, and the honest handling is the one the scope check needs:
/// **an unknown position is refused**. Every browser step is checked against the
/// page the session is actually on (see [`Effects::browse_write`]), so an
/// adapter that cannot say where it is has no step that can be permitted, and
/// the caller learns that from a coded refusal rather than from a keystroke that
/// went somewhere nobody can name.
pub const NO_LOCATION: &str = "no_location";

/// What [`Effects::discover_prospects`] answers when this employee's policy
/// cannot be loaded at all.
///
/// It is very nearly unreachable — the gate loads the same four layers to rule
/// on the browser read that got here — and it is not an
/// [`EffectError::Unavailable`], because the honest reading of "nobody could
/// build an enforceable policy" is that the daily new-contact limit is unknown,
/// and an unknown limit is not a limit. Fails closed and says so, exactly as
/// [`crate::gate::Denied::BrokenPolicy`] does one seam up.
pub const NO_POLICY: &str = "broken_policy";

/// What [`Effects::discover_prospects`] answers when the segment it was handed
/// is not one `accounts_segment` permits.
///
/// A closed set, checked twice: `Turn::propose` names the eight to the model
/// before the gate is troubled, and this is the same refusal at the write.
pub const BAD_SEGMENT: &str = "unknown_segment";

/// What [`Effects::propose_flow`] answers when the page's host belongs to no
/// prospect on this tenant's list.
///
/// A proposal is a row on an `accounts` row and the account is resolved from the
/// host — see [`propose_prospect_flow`](agentos_store::revenue::propose_prospect_flow).
/// So this is not "we could not find the form": it is "there is nobody here this
/// page could be about", and the answer to it is an import, not another read.
pub const NO_PROSPECT: &str = "no_such_prospect";

/// What [`Effects::stage_lead`] answers when the row's `email` column is not
/// the address the gate ruled on.
///
/// The lead-shaped twin of [`READ_TOKEN`]: a token names one counterparty, and
/// a payload that names another is asking for an effect nobody authorised. The
/// difference from a rendered email — where the recipient is simply taken off
/// the token and the body's headers ignored — is that this payload's address
/// column is *also* what the platform substitutes into `{{email}}`, so it
/// cannot merely be overruled. Both spellings have to agree or nothing is
/// staged.
///
/// Unreachable through `crate::queue`, whose `Lead::fields` and `Lead::email`
/// read the same `Recipient`. It is a named refusal rather than an assertion
/// because the two are separated by a gate call and a crate boundary, and the
/// audit row should say which of them moved.
pub const LEAD_NOT_THE_RULED_ADDRESS: &str = "lead_address_mismatch";

/// What [`Effects::issue_invoice`] answers when the deal it was handed is not
/// this company's, or is not one anybody won.
///
/// **One code for both, deliberately**, and it is [`NO_PROSPECT`]'s reasoning
/// with a sharper edge: `agentos_store::invoices::issue` refuses with
/// [`StoreError::NotFound`] either way, and separating them here would turn a
/// failed invoice into an existence oracle for another company's opportunity
/// ids — ask about a uuid, learn from the error whether it is a real deal.
///
/// It is a refusal rather than an [`EffectError::Unavailable`] because nothing
/// is broken: the caller named a deal it may not bill, which is the ceiling
/// working. `migrations/0066_invoices.sql` argues why that ceiling is the
/// structural one.
pub const NO_WON_DEAL: &str = "no_won_deal";

/// The zone a moment was promised in is not a name any tzdata knows.
///
/// A code, for [`NO_BROWSER`]'s reason and with the opposite advice: this one
/// *is* worth trying again, because it is a typo in a field the model wrote.
/// [`crate::calendar::CalendarError::UnknownZone`] argues at length why it is
/// its own error rather than a not-found — a promise naming an employee that
/// does not exist must stay silent, and a promise naming a zone the world does
/// not have must say so.
pub const UNKNOWN_ZONE: &str = "unknown_zone";

/// The words of a promised hour are blank or longer than the column takes.
///
/// Also worth retrying, and also a fact about the caller's own string rather
/// than about this deployment — see [`crate::calendar::CalendarError::SubjectShape`],
/// which argues why the check lives in the adapter and not here.
pub const BAD_SUBJECT: &str = "bad_subject";

/// The last error a rate-limited send is filed under.
///
/// `429` is an answer: the provider read the request and declined to act on it,
/// so the intent is `failed` and not left ambiguous. It sits beside
/// [`ProviderError::code`]'s own spelling on purpose — the same word for the
/// same fact, in the column an operator reads.
const RATE_LIMITED: &str = "rate_limited";

/// What a send's write-ahead row names as its provider: the **port**, not the
/// vendor bound behind it.
///
/// The same two spellings `crate::provisioning::adapter_of` already uses for the
/// same two ports, so an operator reading `provider_intents` sees one vocabulary
/// whether the row came from a provisioning step or from a send. Deliberately
/// not `telephony::PROVIDER` (`"twilio"`) or `ResendEmailProvider::PROVIDER`:
/// which adapter is installed is deployment configuration, this row outlives the
/// deployment, and a row that says `twilio` when a mock was bound is a row that
/// lies to whoever goes looking in the Twilio console.
const TELEPHONY_PORT: &str = "telephony";

/// The email port, for [`TELEPHONY_PORT`]'s reasons.
const EMAIL_PORT: &str = "email";

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

/// What an authorised token is a token *for*, with the trust wrapper (if any)
/// looked through.
///
/// This is how one method serves both `Authorized<EmailSend>` and
/// `Authorized<Untrusted<EmailSend>>` without either being convertible into the
/// other: the bound is `A: Subject<Of = EmailSend>`, which no other subject
/// satisfies.
pub trait Subject: Authorizable {
    /// The subject with the trust wrapper removed.
    type Of;

    /// Borrow it. Inspecting a parsed value the edge already validated — the
    /// text it was parsed *from* is still untrusted and still wrapped.
    fn subject(&self) -> &Self::Of;
}

/// Untrusted provenance never changes which effect a token is for.
impl<T> Subject for Untrusted<T>
where
    Untrusted<T>: Authorizable,
{
    type Of = T;

    fn subject(&self) -> &T {
        self.expose_for_parsing()
    }
}

/// One subject per effect: the newtype the gate rules on and the effect method
/// accepts, in both trust flavours.
macro_rules! subject {
    ($(#[$doc:meta])* $name:ident {
        $($(#[$fdoc:meta])* $field:ident : $ty:ty),+ $(,)?
    } => $variant:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            $(
                $(#[$fdoc])*
                /// Parsed, as the gate was shown it.
                pub $field: $ty,
            )+
        }

        impl Authorizable for $name {
            fn to_action(&self) -> Action {
                Action::$variant { $($field: self.$field.clone()),+ }
            }

            /// Trusted: this value was built by our own code from our own
            /// configuration or from an operator's authenticated request.
            fn trust(&self) -> TrustLabel {
                TrustLabel::Trusted
            }
        }

        impl Authorizable for Untrusted<$name> {
            fn to_action(&self) -> Action {
                self.expose_for_parsing().to_action()
            }

            fn trust(&self) -> TrustLabel {
                self.taint()
            }
        }

        impl Subject for $name {
            type Of = $name;

            fn subject(&self) -> &$name {
                self
            }
        }
    };
}

subject!(
    /// Send an email to one address.
    EmailSend { to: EmailAddress } => EmailSend
);
subject!(
    /// Send an SMS to one number.
    SmsSend { to: E164 } => SmsSend
);
subject!(
    /// Send a WhatsApp message to one number.
    WhatsappSend { to: E164 } => WhatsappSend
);
subject!(
    /// Ring one number.
    ///
    /// The strictest of the four outbound subjects to obtain, and not because
    /// anything here says so — `domain::policy` does, twice over. A call has to
    /// clear `Channel::Voice` **and** match a prefix in `allowed_calling_codes`
    /// (`always_denies` asks both, `evaluate`'s arm asks both in that order),
    /// where an email clears a channel and a denylist. On top of that
    /// `spends_contact_budget` charges it, so the first call to a stranger eats
    /// one of the day's cold contacts exactly as a first email does.
    ///
    /// That is the answer to "is a call worse than an SMS": the packs refuse
    /// SMS by *omitting* it, and voice is refused by a rule instead — which is
    /// the stronger of the two, because a rule survives a pack being rewritten.
    CallPlace { to: E164 } => CallPlace
);
subject!(
    /// Look at what a page on a domain already says.
    ///
    /// **Half of the split the audit trail turns on.** Reading a prospect's
    /// booking flow and typing a passport code into it are two different acts on
    /// the same domain, and `Effects::record` writes the token's own action kind
    /// — so one of them leaves a `browser_read` row and the other a
    /// `browser_write` row, with no flag for a caller to set and nothing to keep
    /// in step. See [`crate::proof_of_need`], which argues it at length and is
    /// the reason it exists.
    ///
    /// Untrusted in the flavour a turn proposes: the domain comes off a URL a
    /// model chose. [`Action::BrowserRead`] is [`agentos_domain::action::Risk`]
    /// `Low`, so the gate rules on the domain rather than on the taint — reading
    /// one more page is not the act a tainted turn is stopped at, and what keeps
    /// it safe is that everything it brings back is [`Untrusted`].
    BrowserRead { domain: Domain } => BrowserRead
);
subject!(
    /// Drive a browser somewhere that changes state on a domain.
    BrowserWrite { domain: Domain } => BrowserWrite
);
subject!(
    /// Call one tool on one MCP server.
    McpCall { tool: McpTool } => McpCall
);
subject!(
    /// Move money: how much, and to whom.
    ///
    /// The only two-field subject here, and the payee is the reason
    /// [`PaymentInstruction`] no longer carries one. See
    /// [`Effects::pay`].
    PaymentCreate {
        amount: Money,
        /// Where it goes. The gate has no opinion about this; the approval
        /// hash and the human's queue line do.
        payee: String,
    } => PaymentCreate
);
subject!(
    /// Ask a customer for money: the same axis as [`PaymentCreate`], pointed the
    /// other way.
    ///
    /// The subject is the amount and nothing else, and it is now the asymmetry
    /// with [`PaymentCreate`] rather than the parallel: which deal is billed
    /// rides on [`InvoiceDraft`], because `agentos_store::invoices` refuses an
    /// `opportunity_id` that is not this company's `closed_won` row and a payee
    /// has no such check to lean on. `Action::InvoiceIssue` carries the
    /// argument in full. `Money` and not an integer, because a figure whose
    /// currency was implied is a figure the customer reads in theirs.
    InvoiceIssue { amount: Money } => InvoiceIssue
);
subject!(
    /// Say something to one peer's agent.
    ///
    /// The odd one out: there is no `Effects::send_a2a`, because nothing in this
    /// crate speaks A2A outbound yet. It exists because
    /// [`crate::a2a::sign_request`] needs a token that *only* an A2A ruling can
    /// produce — `Authorized<A2aSend>` is the bound, and `Authorized<Action>`
    /// does not satisfy it. See `crate::identity` for why a signature must ride
    /// the authority of the action it attests rather than an `Action::Sign` of
    /// its own.
    A2aSend { peer: Domain } => A2aSend
);
subject!(
    /// Say something to a colleague, by short name.
    ///
    /// The only inward subject, and the only one whose trust flavour is read
    /// back out again: [`Effects::send_internal`] asks the token whether it is
    /// an `InternalSend` or an `Untrusted<InternalSend>` and stores the answer
    /// on the message. That is the whole anti-laundering mechanism, and it
    /// works because the two are different types the entire way through the
    /// gate — there is nothing for a caller to declare and nothing for a model
    /// to say.
    InternalSend { to: Slug } => InternalSend
);

/// Undertake one moment of this employee's own time.
///
/// **Written out rather than produced by [`subject!`], because it has no
/// field**, and the absence is the whole point rather than an inconvenience.
/// Every other subject in this file carries the parsed counterparty of its
/// effect; this one's counterparty is the acting employee, which lives in
/// [`Principal`] and never in an [`Action`] — see
/// [`Action::AppointmentBook`](agentos_domain::action::Action::AppointmentBook).
///
/// The instant, the zone and the subject line are not here either. They are
/// arguments to [`Effects::book_hour`], the way a [`RenderedEmail`] is an
/// argument beside an [`EmailSend`] token: the gate ruled on *whether this
/// employee may promise an hour*, and it has no opinion about three o'clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppointmentBook;

impl Authorizable for AppointmentBook {
    fn to_action(&self) -> Action {
        Action::AppointmentBook {}
    }

    /// Trusted: the value itself carries nothing a model chose. The turn's own
    /// label is what decides which flavour is minted — see `turn::gated!`.
    fn trust(&self) -> TrustLabel {
        TrustLabel::Trusted
    }
}

impl Authorizable for Untrusted<AppointmentBook> {
    fn to_action(&self) -> Action {
        self.expose_for_parsing().to_action()
    }

    fn trust(&self) -> TrustLabel {
        self.taint()
    }
}

impl Subject for AppointmentBook {
    type Of = AppointmentBook;

    fn subject(&self) -> &AppointmentBook {
        self
    }
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// An email that has been rendered and is ready to go — everything except who
/// it is addressed to, which comes off the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    /// Envelope sender, `slug@domain`.
    pub from: String,
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub body_text: String,
    /// The message being replied to, for threading.
    pub in_reply_to: Option<ProviderMessageId>,
}

/// A rendered SMS, minus the recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedSms {
    /// The employee's own number.
    pub from: E164,
    /// Body text.
    pub body: String,
}

/// A rendered WhatsApp message, minus the recipient.
///
/// Mirrors [`OutboundWhatsapp`] rather than wrapping it because the 24-hour
/// window proof ([`OpenWindow`]) is load-bearing: free-form text outside the
/// window has to stay unspellable here too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderedWhatsapp {
    /// Free text. Only expressible while the window is open.
    FreeForm {
        /// The employee's own WhatsApp sender.
        from: E164,
        /// Body text.
        body: String,
        /// Proof the window was open.
        window: OpenWindow,
    },
    /// A pre-approved template. Always allowed.
    Template {
        /// The employee's own WhatsApp sender.
        from: E164,
        /// Template name as registered with the provider.
        name: String,
        /// Positional substitutions.
        variables: Vec<String>,
    },
}

impl RenderedWhatsapp {
    /// Address it to the number on the token.
    fn addressed_to(self, to: E164) -> OutboundWhatsapp {
        match self {
            Self::FreeForm { from, body, window } => OutboundWhatsapp::FreeForm {
                from,
                to,
                body,
                window,
            },
            Self::Template {
                from,
                name,
                variables,
            } => OutboundWhatsapp::Template {
                from,
                to,
                name,
                variables,
            },
        }
    }
}

/// What one employee is saying to another. The recipient is on the token.
///
/// There is no trust field, and there must not be one: the message's label
/// comes off the *type* of the token — see [`Effects::send_internal`] — so
/// nothing on the way to a colleague's inbox can be told a lie about where the
/// words came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalNote {
    /// Order, question, answer or handover.
    pub errand: Errand,
    /// What to say.
    pub body: String,
    /// The thread the sending turn is on, when it is on one. Required by
    /// [`Errand::Answer`] and [`Errand::Handover`], which are both *about* it;
    /// ignored by the other two.
    pub thread: Option<Thread>,
}

/// What the payment provider is handed: where the money goes and what for.
///
/// **Built by [`Effects::pay`] and by nothing else** — the payee is copied off
/// the token there, never taken from the caller. That is the whole reason this
/// struct is still a struct instead of a `memo: &str` parameter: it is the
/// provider port's argument, and the port should keep seeing a payee.
///
/// It used to be the caller's argument, with the payee on it, while the amount
/// came off the token. Those were two sources of truth for one payment, and
/// only one of them had been ruled on — so "the gate authorised A, the port was
/// handed B" was a call away. It is now unrepresentable rather than merely
/// refused, which is the move `Calendar::book` makes for whose hour is spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentInstruction {
    /// The payee, in whatever form the payment provider identifies one. Copied
    /// from [`PaymentCreate::payee`] on the authorising token.
    pub payee: String,
    /// What the payment is for; ends up on the statement and in the audit row.
    pub memo: String,
}

/// Which won deal is being billed and what for. The amount is on the token.
///
/// [`PaymentInstruction`]'s shape, one direction along, and the difference
/// between the two fields is the difference between the two acts. A payee is a
/// **string** because it is whatever the payment provider calls an account and
/// nothing here can check it; this names a row in **our own** `opportunities`,
/// so it is a uuid the store looks up — and refuses if it is not this company's
/// or is not `closed_won`. That refusal is the whole ceiling; see
/// `migrations/0066_invoices.sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceDraft {
    /// The won deal this bills.
    pub opportunity_id: Uuid,
    /// What it is for, in one line; ends up on the invoice and in the audit row.
    pub memo: String,
    /// When payment is due, if a term was agreed. `None` carries no date, and
    /// **there is no default**: "net 30" is a commercial agreement between two
    /// companies, not a fact about software. See
    /// `migrations/0071_an_invoice_needs_a_number.sql`.
    pub due_at: Option<DateTime<Utc>>,
    /// What the document is made of. Empty means the memo is the whole
    /// description; otherwise the lines must total the amount on the token,
    /// which the store refuses and the database refuses again at commit.
    ///
    /// A line can carry a tax rate and nothing in this workspace supplies one:
    /// see [`agentos_store::invoices::Line::tax_rate_bp`], which is where that
    /// question is left open for the founder.
    pub lines: Vec<invoices::Line>,
}

// ---------------------------------------------------------------------------
// The two ports whose adapters are not in `agentos-providers`
// ---------------------------------------------------------------------------

/// Calling a tool on an MCP server.
///
/// The result is [`Untrusted`] because it is a stranger's text: an MCP server
/// is exactly the "may provide facts, never authority" boundary, and returning
/// a bare `Value` would let tool output reach a prompt with no wrapper to grep
/// for.
///
/// The implementation is [`crate::mcp::Fleet`], which routes on the tool's
/// server handle across everything one tenant has bound;
/// [`crate::mocks::ports`] still hands out a refusing stub, because a process
/// with no tenant in hand has nothing to bind.
///
/// ponytail: declared here rather than in `agentos-providers` because the MCP
/// client lives in this crate — it needs the domain's risk vocabulary and the
/// gate's decisions, neither of which a provider adapter may see. Move it the
/// day a second consumer appears.
#[async_trait]
pub trait McpCaller: Send + Sync {
    /// Invoke `tool` with `arguments`.
    async fn call(
        &self,
        tool: &McpTool,
        arguments: &Value,
    ) -> Result<Untrusted<Value>, ProviderError>;
}

/// Moving money. Idempotent on `key`, like every other provider send.
///
/// ponytail: same reasoning as [`McpCaller`] — a port with no adapter yet.
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Pay `amount` to the payee named in `instruction`.
    async fn pay(
        &self,
        key: &IdempotencyKey,
        amount: Money,
        instruction: &PaymentInstruction,
    ) -> Result<ProviderMessageId, ProviderError>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an authorised effect did not happen.
///
/// Note what this enum does *not* have: a variant for "the policy says no". By
/// the time anything here runs the gate has already ruled; a policy refusal is
/// a [`crate::gate::Denied`] and never reaches this module.
///
/// [`EffectError::Refused`] is not that. It is the *world* saying no to an
/// action the policy permits — see its own note.
#[derive(Debug, thiserror::Error)]
pub enum EffectError {
    /// The provider refused, failed, or is waiting on someone external.
    /// Classification preserved — see [`ProviderError::is_retryable`].
    #[error(transparent)]
    Provider(ProviderError),

    /// The step would leave the domain the token authorises. The gate ruled on
    /// `portal.example.com`; this navigation goes somewhere else.
    #[error("step leaves the authorized domain {0}")]
    OutOfScope(Domain),

    /// The effect was authorised and could still not be performed, because
    /// something read at write time said no.
    ///
    /// [`Effects::send_internal`] produces four, and they are all facts about
    /// the *recipient*: there is no such colleague on this employee's team, the
    /// thread being answered or handed over is not this employee's, or the
    /// colleague has no turns left in its day. None of them is expressible as an
    /// [`Action`] — an `Action` carries a parsed subject and no org chart and no
    /// ledger — so the gate cannot rule on them, and pushing them into it would
    /// mean a second transaction between the check and the write for a team
    /// membership or a turn budget to change in.
    ///
    /// [`Effects::read_page`] produces two, and they are facts about *this
    /// deployment* rather than about the recipient — same reasoning, one seam
    /// over. [`NO_BROWSER`] is an employee whose browser context is not
    /// provisioned, which is a `employee_resources` row the gate has no business
    /// reading; `not_text` is a browser adapter that answered a text read with
    /// something that is not text, which is a bug in an adapter and not a
    /// decision anybody made.
    ///
    /// The payload is a closed code, because it is handed back to a model as a
    /// failed tool result and it is what teaches it to stop asking.
    #[error("refused: {0}")]
    Refused(&'static str),

    /// The effect could not be recorded, so it is reported as failed. The audit
    /// row and the effect are one unit: an unrecorded effect is worse than a
    /// missing one.
    #[error(transparent)]
    Unavailable(StoreError),
}

impl EffectError {
    /// Stable, low-cardinality metric label.
    pub fn code(&self) -> &'static str {
        match self {
            EffectError::Provider(err) => err.code(),
            EffectError::OutOfScope(_) => "out_of_scope",
            EffectError::Refused(code) => code,
            EffectError::Unavailable(_) => "unavailable",
        }
    }

    /// Whether trying again could work. Only the provider knows; everything
    /// else here is a bug or an outage a retry will not fix.
    ///
    /// # `pub(crate)`, and that is the answer to "who reads this"
    ///
    /// It had one caller outside its own tests — [`Effects::record`], writing
    /// the `retryable` field of an audit row — and a `pub fn` with no caller
    /// across the crate boundary reads like a decision something branches on.
    /// Nothing branches on it, and nothing should: an effect happens inside a
    /// turn, and a turn hands the failure to the model as
    /// `failed (<code>)` — see [`crate::turn`]'s `performed`. The model is the
    /// retrier, `code()` is what it reads, and `"retryable"` is one of the
    /// codes. There is no loop between here and it to teach.
    ///
    /// So the classification stays — the audit column is a real reader, and it
    /// is the one place an operator can ask "was that worth retrying" after the
    /// fact — and the visibility shrinks to match. `ProviderError::is_retryable`
    /// is the `pub` one, and it is `pub` because
    /// `ProvisioningEngine::call_until` and `apps/server/src/loops` really do
    /// branch on it.
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(self, EffectError::Provider(err) if err.is_retryable())
    }
}

// ---------------------------------------------------------------------------
// Where a step actually acted
// ---------------------------------------------------------------------------

/// The host a browser step acted on, when it is **not** the domain on the
/// token.
///
/// Built only when the two differ, so its absence is the ordinary case and
/// carries no cost. See [`Effects::browse_write`] for why a redirect out of the
/// token's domain is followed at all, and what has to permit it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Elsewhere {
    /// The gate ruled on this host too, under a decision of its own. Both ids
    /// go on the row: the one that authorised the *step*, and the one that
    /// authorised the *place*.
    Ruled(Domain, DecisionId),
    /// Nobody authorised it. `None` is a page with no nameable host at all — a
    /// blank tab, an IP literal — which is refused without troubling the gate,
    /// because there is nothing to rule on.
    Unruled(Option<Domain>),
}

/// The audit detail every browsing effect shares.
///
/// `domain` is what the gate ruled on and is always there. `landed` appears
/// only when the step acted somewhere else, and it is a **parsed [`Domain`]**
/// and never the URL: the path and query of a landing page are the page's own
/// bytes, and an audit payload is a column. The rule this workspace keeps —
/// nothing a stranger wrote becomes prose, a prompt or a column — is not
/// suspended because the column is ours.
fn browse_detail(allowed: &Domain, elsewhere: Option<&Elsewhere>) -> Map<String, Value> {
    let mut detail = Map::new();
    detail.insert("domain".to_owned(), json!(allowed.as_str()));
    match elsewhere {
        None => {}
        Some(Elsewhere::Ruled(landed, decision)) => {
            detail.insert("landed".to_owned(), json!(landed.as_str()));
            detail.insert(
                "landed_decision".to_owned(),
                json!(decision.as_uuid().to_string()),
            );
        }
        // No decision to name: this is the refusal. The host is still recorded,
        // because "we were sent here and would not stay" is the sentence an
        // incident starts from.
        Some(Elsewhere::Unruled(Some(landed))) => {
            detail.insert("landed".to_owned(), json!(landed.as_str()));
        }
        // ...and a page with no nameable host leaves nothing but the refusal
        // itself. Inventing a name for `about:blank` would be worse than the
        // silence.
        Some(Elsewhere::Unruled(None)) => {}
    }
    detail
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// Every adapter the process was started with, wired once at boot.
///
/// Public fields on purpose: this is the composition root's struct, built in
/// `main` and shared behind an `Arc`. It is not a way *into* the providers —
/// [`Effects`] keeps its handle private, and only its methods can be reached
/// from a turn.
#[derive(Clone)]
pub struct Ports {
    /// Outbound email.
    pub email: Arc<dyn EmailProvider>,
    /// The outbound sending platform's prospect list.
    ///
    /// Distinct from [`Ports::email`] and not a second implementation of it:
    /// that one sends *a message we composed* to an address we hold, this one
    /// hands a person to a platform that composes from its own campaign
    /// template and mails on its own schedule. They fail differently, they are
    /// billed differently, and only one of them can be told somebody
    /// unsubscribed. See [`agentos_providers::leads`].
    pub leads: Arc<dyn LeadSink>,
    /// SMS, WhatsApp, and the dial. Not what a call says — see
    /// [`Effects::place_call`].
    pub telephony: Arc<dyn TelephonyProvider>,
    /// The employee's browser.
    pub browser: Arc<dyn BrowserProvider>,
    /// MCP tool calls.
    pub mcp: Arc<dyn McpCaller>,
    /// Payments.
    pub payments: Arc<dyn PaymentProvider>,
}

// ---------------------------------------------------------------------------
// Effects
// ---------------------------------------------------------------------------

/// The façade. One per acting principal; the adapters behind it are shared.
#[derive(Clone)]
pub struct Effects {
    db: Db,
    ports: Arc<Ports>,
    principal: Principal,
}

impl Effects {
    /// Bind the ports to the principal every effect will be attributed to.
    ///
    /// ponytail: the token is not checked against this principal —
    /// [`Authorized`] deliberately carries a decision, not an identity. Pairing
    /// them is the caller's job, and a mismatch is still visible in the trail,
    /// because the row's `decision_id` points at a ruling for a different
    /// employee. Put the actor inside the token the day that is not enough.
    pub const fn new(db: Db, ports: Arc<Ports>, principal: Principal) -> Self {
        Self {
            db,
            ports,
            principal,
        }
    }

    /// The identity every effect performed here is attributed to.
    ///
    /// Exposed so that a caller holding an `Effects` cannot also be asked for
    /// the principal separately and hand over a different one. `Turn` used to
    /// take both; the gate authorised as one and the trail recorded the other,
    /// and nothing but the caller's care kept them equal.
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Send the rendered email to the address on the token.
    ///
    /// Fenced by [`Self::begin_send`] and [`Self::record_sent`] — a row committed
    /// before the request leaves and closed after it is answered. Read
    /// [`Self::send_sms`] for exactly how much that is worth; the fence is the
    /// same and so is the bounded promise.
    pub async fn send_email<A: Subject<Of = EmailSend>>(
        &self,
        ok: Authorized<A>,
        body: RenderedEmail,
    ) -> Result<ProviderMessageId, EffectError> {
        let email = OutboundEmail {
            from: body.from,
            // The recipient is the one that was ruled on, not one the renderer
            // put in a header.
            to: vec![ok.action().subject().to.to_string()],
            subject: body.subject,
            body_text: body.body_text,
            in_reply_to: body.in_reply_to,
        };

        // `?`, and no audit row on this arm: the only way this fails is the
        // database being unreachable, at which point `record` cannot write one
        // either. Nothing has been sent, which is the state the failure leaves.
        self.begin_send(&ok, EMAIL_PORT).await?;
        let sent = self.ports.email.send(&self.key_for(&ok), &email).await;
        self.record_sent(&ok, sent).await
    }

    /// Put the prospect on the token onto the sending platform's list.
    ///
    /// **The same act as [`Effects::send_email`], down a different road**, and
    /// it takes the same token type on purpose: `Authorized<EmailSend>`. There
    /// is no `LeadUpload` subject beside `EmailSend`, because inventing one
    /// would create a second permission for one act — and the day the two
    /// disagreed, the narrower one would be the one nobody consulted. The gate
    /// therefore applies the channel check, the denylist and
    /// `max_new_contacts_per_day` to a staged lead exactly as it does to a
    /// message we send ourselves, and the counterparty in the audit trail is
    /// the same string either way.
    ///
    /// `row` is `(column, value)` in the producer's order — see
    /// [`agentos_providers::leads`] for why that shape and not a struct. The
    /// **address is not read from it**: it is taken off the token, the same way
    /// [`Effects::send_email`] takes `to` off the token rather than out of the
    /// rendered body, so a row cannot be re-addressed after the ruling. What
    /// the row's own `email` column is for is the platform's template
    /// substitution, and [`Effects::stage_lead`] refuses when the two disagree
    /// rather than letting the provider pick.
    ///
    /// Idempotent through [`Effects::key_for`], which derives the key from the
    /// ruling's `decision_id`: replaying one token cannot buy a second copy of
    /// the same cold email to the same stranger. That is the weakest of the
    /// three locks on this path — see `crate::queue` for the other two.
    pub async fn stage_lead<A: Subject<Of = EmailSend>>(
        &self,
        ok: Authorized<A>,
        row: &[(&str, &str)],
    ) -> Result<ProviderMessageId, EffectError> {
        let ruled = ok.action().subject().to.to_string();
        // The token is the authority on who this is about. A row whose address
        // column says somebody else is not a row to fix up quietly: the gate
        // ruled on one person and the platform would mail another.
        let addressed = row
            .iter()
            .find(|(name, _)| *name == leads::EMAIL_COLUMN)
            .map(|(_, value)| *value);
        let staged = if addressed == Some(ruled.as_str()) {
            self.ports
                .leads
                .stage(&self.key_for(&ok), row)
                .await
                .map_err(EffectError::Provider)
        } else {
            Err(EffectError::Refused(LEAD_NOT_THE_RULED_ADDRESS))
        };

        self.record(&ok, message_detail(&staged), staged).await
    }

    /// Everyone the sending platform has been told to stop mailing.
    ///
    /// **The one method on this type that takes no [`Authorized`] token, and
    /// the exception is the rule pointing the same way.** Every other method
    /// here performs an effect on the world and must not run without a ruling.
    /// This one performs no effect: it reads a list, and the only thing its
    /// answer can ever do is put rows in `suppressions`, which *removes*
    /// permission to write to somebody. Requiring a token would mean a policy
    /// denial — a suspended employee, an exhausted budget, a ceiling nobody
    /// installed — could stop this system from learning that a stranger asked
    /// to be left alone. That is precisely backwards, and it is the one place
    /// where "fail closed" and "the safe direction" are not the same sentence.
    ///
    /// It is on [`Effects`] rather than on a port the caller holds because the
    /// ports are private here and there is no accessor: this is the crate's one
    /// door to a provider, and an ungated read should be visible *in that
    /// file*, next to the gated writes, rather than hidden behind a handle
    /// somebody passed around.
    ///
    /// No audit row, and deliberately: the record this produces is the
    /// `suppressions` rows themselves, which are append-only, carry the reason
    /// and the note, and outlive both the tenant and the contact. A
    /// `provider_call_attempted` row saying we asked would add a line nobody
    /// queries beside the line everybody does.
    pub async fn opted_out(&self) -> Result<Vec<String>, EffectError> {
        self.ports
            .leads
            .opted_out()
            .await
            .map_err(EffectError::Provider)
    }

    /// Send the rendered SMS to the number on the token.
    ///
    /// # The double-text, and which half of it this fence actually catches
    ///
    /// Twilio's `POST /Messages` takes no idempotency header. When the request
    /// leaves and the answer never comes back, `TwilioTelephony` returns a
    /// retryable error whose own documentation says *"the request may even have
    /// landed"*. Whoever retries then texts the customer a second time, and
    /// **this fence does not stop them** — the retry comes with a new ruling and
    /// a new key, and there is no query on this planet that would tell us
    /// whether the first one arrived.
    ///
    /// What it does is make the ambiguity *exist somewhere*. A row is committed
    /// before the POST and closed after the answer; a send that got no answer is
    /// left `in_flight` on purpose, and `GET /v1/employees/{id}` renders it as
    /// `unsettled_calls` for a person to settle against Twilio's own console.
    /// Before this, a text that may or may not have gone out left nothing behind
    /// but a retryable error nobody was reading. That is the whole of the
    /// improvement, and it is not "cannot double-text".
    pub async fn send_sms<A: Subject<Of = SmsSend>>(
        &self,
        ok: Authorized<A>,
        body: RenderedSms,
    ) -> Result<ProviderMessageId, EffectError> {
        let sms = OutboundSms {
            from: body.from,
            to: ok.action().subject().to.clone(),
            body: body.body,
        };

        self.begin_send(&ok, TELEPHONY_PORT).await?;
        let sent = self
            .ports
            .telephony
            .send_sms(&self.key_for(&ok), &sms)
            .await;
        self.record_sent(&ok, sent).await
    }

    /// Whether this employee may write free text to this number on WhatsApp
    /// right now, and the proof if it may.
    ///
    /// **The half of [`crate::turn::UNSERVED`]'s WhatsApp entry that has stopped
    /// being missing.** [`OpenWindow`] has existed since the adapter was
    /// written and could be obtained nowhere outside a test, because nothing in
    /// this workspace could say when a counterparty last wrote to us on that
    /// channel. The telephony ingest (`0069`,
    /// [`inbound::land_inbound_text`](crate::inbound::land_inbound_text)) makes
    /// that a row, and this is the read of it. The remaining half — a registry
    /// of pre-approved templates, which is what a *closed* window allows — is
    /// still missing and is still named in that entry.
    ///
    /// `None` is a refusal and covers three things on purpose: they have never
    /// written to us here, they wrote more than 24 hours ago, or they wrote
    /// exactly 24 hours ago to the microsecond.
    /// [`OpenWindow::since_last_inbound`] tests `expires_at > now`, strictly, so
    /// the boundary instant itself is shut — the safe direction, since a
    /// free-form send outside the window is a policy violation with Meta rather
    /// than a 4xx to shrug at.
    ///
    /// # No token, for [`Effects::opted_out`]'s reason, one direction along
    ///
    /// This performs no effect: it reads two of our own tables and the only
    /// thing its answer can do is *withhold* a message. Requiring an
    /// [`Authorized`] would mean the caller had to be granted the send before it
    /// could find out whether the send is legal, which is backwards, and a
    /// policy denial could not make an illegal send legal — it can only stop a
    /// legal one from happening, which the gate does anyway at the actual send.
    ///
    /// # The window this returns is already stale, and both halves are named
    ///
    /// **The clock is late.** `messages.received_at` on this path is when our
    /// outbox poller landed the delivery, and Meta's 24 hours run from when
    /// *Meta* received the customer's message — earlier by a provider hop plus
    /// however long the row waited to be claimed. So the expiry here is later
    /// than the real one by that lag, and the last seconds of it are seconds
    /// Meta may already count as outside.
    ///
    /// **And it decays.** The proof is a value, not a lease: it says the window
    /// was open at the instant this was called. A turn can run for
    /// `TURN_DEADLINE` afterwards, so a window with thirty seconds left when the
    /// model asked can be shut when the message reaches the wire. That one is
    /// **already closed, at the wire, by both adapters** —
    /// `MockTelephony::send_whatsapp` and `TwilioTelephony::send_whatsapp` each
    /// refuse `FreeForm` with `Terminal { code: "window_closed" }` when
    /// `expires_at() <= now`. It is deliberately not re-checked here as well: a
    /// third copy of the rule would be a third place for it to drift, and the
    /// one that matters is the one nearest the send.
    ///
    /// # FOUNDER'S QUESTION, LEFT OPEN: what is the safety margin?
    ///
    /// The lag above is real and it is unobservable from here — nothing in a
    /// Twilio messaging callback says when Meta got the message. The honest fix
    /// is to subtract a margin from the derived expiry, and **the margin is a
    /// number this repository cannot source**: it is a judgement about how much
    /// of a 24-hour window to give back in exchange for never sending one second
    /// late. No number is invented here, exactly as `0063` invents no cutoff for
    /// how late is too late to keep an appointment.
    ///
    /// The place for the answer is one subtraction on the `now` below —
    /// `Utc::now() + MARGIN` closes the window early by `MARGIN` and changes
    /// nothing else, because [`OpenWindow`] is derived from `now` and never
    /// stored. What bounds the damage until then: free-form WhatsApp is
    /// unreachable by a model (no catalogue row), the boundary is strict rather
    /// than inclusive, and a late send is refused by the adapter rather than
    /// sent as free text.
    ///
    /// The other unsourced number is the 24 itself — see [`OpenWindow::DURATION`].
    pub async fn whatsapp_window(&self, to: &E164) -> Result<Option<OpenWindow>, EffectError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        let last =
            crate::inbound::last_inbound_whatsapp_at(&mut tx, self.principal.employee_id, to)
                .await
                .map_err(EffectError::Unavailable)?;
        tx.commit().await.map_err(EffectError::Unavailable)?;

        Ok(OpenWindow::since_last_inbound(last, Utc::now()))
    }

    /// Send the rendered WhatsApp message to the number on the token.
    ///
    /// Same fence and the same bounded promise as [`Self::send_sms`].
    pub async fn send_whatsapp<A: Subject<Of = WhatsappSend>>(
        &self,
        ok: Authorized<A>,
        body: RenderedWhatsapp,
    ) -> Result<ProviderMessageId, EffectError> {
        let message = body.addressed_to(ok.action().subject().to.clone());

        self.begin_send(&ok, TELEPHONY_PORT).await?;
        let sent = self
            .ports
            .telephony
            .send_whatsapp(&self.key_for(&ok), &message)
            .await;
        self.record_sent(&ok, sent).await
    }

    /// Ring the number on the token, from this employee's own number.
    ///
    /// # There is no body, and that is the shape of the honest half
    ///
    /// Every other message-shaped method here takes a rendered thing beside its
    /// token — a [`RenderedEmail`], a [`RenderedSms`]. This one takes an
    /// [`E164`] and nothing else, because there is nothing else to take: the
    /// call is silent. What a call *says* is speech synthesis, recognition and
    /// a turn-taking loop over a media stream, none of which exists anywhere in
    /// this workspace, and a `body: String` parameter here would be an argument
    /// every adapter throws away. See
    /// [`OutboundCall`](agentos_providers::telephony::OutboundCall), which has
    /// no field for it for the same reason, and
    /// `telephony_twilio::SILENT_TWIML`, which is the whole of what the callee
    /// hears.
    ///
    /// So this is the *dialling* half of a phone call, built and testable, and
    /// it is deliberately not reachable by a model: `ActionKind::CallPlace` is
    /// still in [`crate::turn::UNSERVED`], with the reason rewritten to name
    /// what is now missing rather than what used to be.
    ///
    /// # `Ok` means the carrier took the request, not that anybody answered
    ///
    /// Restated here and not merely on the port, because this is the layer that
    /// writes the audit row and the row is what an operator reads afterwards.
    /// `provider_call_attempted` with `effect: "call_place"` and an `ok`
    /// outcome says *we asked a carrier to ring this number and it agreed to*.
    /// Busy, no answer, an answering machine and a decline all happen after
    /// this returns, they arrive on a status callback no route in this build
    /// accepts, and none of them can make this row say anything different.
    ///
    /// The `from` number comes from the caller and the `to` number comes off
    /// the token — never the other way round, and never both from one place.
    /// They are the same type, so a swap compiles and returns `Ok`; what
    /// catches it is `the_number_dialled_is_the_number_the_gate_ruled_on`
    /// below, reading the double's own log.
    pub async fn place_call<A: Subject<Of = CallPlace>>(
        &self,
        ok: Authorized<A>,
        from: E164,
    ) -> Result<ProviderMessageId, EffectError> {
        let call = OutboundCall {
            from,
            // The number that was ruled on, exactly as `send_email` takes its
            // recipient off the token rather than out of a rendered header.
            to: ok.action().subject().to.clone(),
        };

        self.begin_send(&ok, TELEPHONY_PORT).await?;
        let placed = self
            .ports
            .telephony
            .place_call(&self.key_for(&ok), &call)
            .await;
        // `message_detail`'s `provider_message_id`, reused rather than spelled
        // a second way: it is the id the provider handed back, which is what
        // the key means, and the row's own `effect` field already says a call
        // is what it was handed back for.
        self.record_sent(&ok, placed).await
    }

    /// Run one browser step in an existing session.
    ///
    /// # The scope check is on the page the session is *on*, not on the URL we
    /// asked for
    ///
    /// This method used to check exactly one thing: that a [`BrowserStep::Goto`]
    /// named a host inside the token's domain. It then threw away the
    /// [`BrowserOutcome::Navigated`] URL that says where the navigation actually
    /// **ended**, and every other step — `Type`, `Click`, `Fill` — was let
    /// through on the strength of holding a token at all, because "which page is
    /// up" was a fact this layer did not have.
    ///
    /// A `302` is all it took. A token minted for `prospect.example`, a `Goto`
    /// to `https://prospect.example/book` that clears the check, a redirect to
    /// `https://booking-engine.example.net/…`, and the session — which is
    /// **shared for the whole employee** — is on a host the gate never saw. The
    /// keystrokes that follow land there, under audit rows naming
    /// `prospect.example`. Both halves are wrong: the effect, and the record of
    /// it.
    ///
    /// So the question every step now asks is the one that was missing: *where
    /// are we?* A `Goto` is the one step whose answer cannot be known before it
    /// runs — the redirect is the site's reply, not our request — so it is
    /// checked from the outcome, after. Every other step acts on a page that is
    /// already up, so it is checked from [`BrowserStep::Location`], before, and
    /// a refusal costs their site nothing.
    ///
    /// # Refusing every off-domain landing would be the wrong fix
    ///
    /// A prospect whose booking funnel is outsourced — an airline on a
    /// third-party engine — is an ordinary customer, and
    /// [`Flow::confirmed`](crate::proof_of_need::Flow::confirmed) requires the
    /// *entry* URL to be within `accounts.domain`, so a redirect is the **only**
    /// route into such a funnel. Blanket refusal would make those prospects
    /// silently unreachable, which is a business decision disguised as a
    /// security one.
    ///
    /// # What authorises being somewhere else: the gate, again, on the real host
    ///
    /// A landing outside the token's domain re-asks
    /// [`PolicyGate::authorize`](crate::gate::PolicyGate::authorize) — same
    /// principal, same policy, same action *kind*, on the host we are actually
    /// on. That answers the question with the thing that already answers it: an
    /// operator's `allowed_domains` for a write, `Channel::Web` and the denylist
    /// for a read. Three consequences, all of them the point:
    ///
    /// * **Nothing widens.** The second ruling is an extra condition, never a
    ///   substitute: the requested URL of a `Goto` still has to be inside the
    ///   token's domain, and the landing has to clear the same intersected
    ///   allowlist and unioned denylist as anything else. A host nobody granted
    ///   is refused whether we arrived by typing it or by being sent there.
    /// * **The trail says where we really went.** The second decision is an
    ///   audit row of its own, naming the landing host, and this method's row
    ///   carries `landed` and `landed_decision` beside the domain that was
    ///   ruled. A row that named only the token's domain was a false statement
    ///   the moment a redirect happened.
    /// * **It is ruled [`Untrusted`].** The landing host is *their* choice. It
    ///   changes no verdict today — `BrowserWrite` is `Risk::Low`, so the taint
    ///   wire does not fire — and it is still the honest label, so the day the
    ///   risk of a browser write is reconsidered this arrives already wired.
    ///
    /// Two alternatives were not taken. A token carrying a *set* of domains
    /// would have to be minted before the redirect is known, which means guessing
    /// — and it would put a set where `Action::BrowserWrite` carries one domain,
    /// so the audit vocabulary would stop naming what was ruled. A new policy
    /// field ("follow redirects to…") would be a second answer to the question
    /// `allowed_domains` already answers, and two lists that must agree are two
    /// lists that will not.
    ///
    /// # A refused landing does not just fail, it un-parks the session
    ///
    /// The browser context is one per employee and outlives this call. Refusing
    /// the step while leaving the tab on the page we refused hands the next
    /// caller a page it never asked for — and *its* location check would refuse
    /// too, forever, for a reason belonging to somebody else's turn. So a
    /// refusal sends the session back to `about:blank`, which has no host and is
    /// therefore inside nobody's domain.
    ///
    /// ponytail: one extra provider round trip per non-navigating step, and on
    /// the Browserbase adapter that is a second CDP socket — see
    /// `the_real_client_satisfies_the_contract`. Bought deliberately: the
    /// alternative is caching the position, and a cached position is a copy of a
    /// page-authored URL that a script-driven navigation makes stale, in the one
    /// place where being stale means a keystroke goes somewhere nobody ruled on.
    /// Fold the address into every outcome the day the round trips are measured
    /// to matter.
    pub async fn browse_write<A: Subject<Of = BrowserWrite>>(
        &self,
        ok: Authorized<A>,
        session: &BrowserSession,
        step: BrowserStep<'_>,
    ) -> Result<BrowserOutcome, EffectError> {
        let allowed = ok.action().subject().domain.clone();
        // **What the gate actually ruled on**, not what the bound admits. Both
        // subjects reach here — see [`READ_TOKEN`] — and only the action says
        // which permission was bought. Written as "a read ruling may drive a
        // reading step" rather than as a denylist of writing steps, so
        // `BrowserStep::is_a_read`'s exhaustive match is the one place a new
        // variant has to be classified.
        let ruled_a_read = matches!(ok.action().to_action(), Action::BrowserRead { .. });

        let mut elsewhere = None;
        let outcome = if ruled_a_read && !step.is_a_read() {
            // First, and before the browser is touched at all: this refusal is
            // about the token, so it must not depend on where the session
            // happens to be, and a fresh context has to answer it too.
            Err(EffectError::Refused(READ_TOKEN))
        } else {
            self.drive(&allowed, ruled_a_read, session, step, &mut elsewhere)
                .await
        };

        let detail = browse_detail(&allowed, elsewhere.as_ref());
        self.record(&ok, Some(Value::Object(detail)), outcome).await
    }

    /// One browser step, with the scope check on both sides of it.
    ///
    /// `elsewhere` is an out-parameter and not a second return value because the
    /// audit row needs it on **both** paths — a refused landing is exactly the
    /// row that has to name the host — and `?` throws the success value away.
    async fn drive(
        &self,
        allowed: &Domain,
        reading: bool,
        session: &BrowserSession,
        step: BrowserStep<'_>,
        elsewhere: &mut Option<Elsewhere>,
    ) -> Result<BrowserOutcome, EffectError> {
        let navigating = matches!(step, BrowserStep::Goto(_));
        // The requested URL still has to be inside the token's domain. Kept
        // ahead of everything: the landing check below *adds* a condition, and
        // dropping this one would turn "you may browse prospect.example" into
        // "you may browse anything your policy allows", which is not what was
        // ruled.
        if let BrowserStep::Goto(url) = &step
            && !within(url.host_str(), allowed)
        {
            return Err(EffectError::OutOfScope(allowed.clone()));
        }
        if !navigating {
            let here = self.here(session).await?;
            self.in_scope(allowed, reading, session, &here, elsewhere)
                .await?;
        }

        let outcome = self
            .ports
            .browser
            .act(session, step)
            .await
            .map_err(EffectError::Provider)?;

        match (&outcome, navigating) {
            (BrowserOutcome::Navigated(here), _) => {
                self.in_scope(allowed, reading, session, here, elsewhere)
                    .await?;
            }
            // A navigation that answered with no address is one whose landing
            // nobody can check. Fails closed rather than passing unexamined.
            (_, true) => return Err(EffectError::Refused(NO_LOCATION)),
            _ => {}
        }
        Ok(outcome)
    }

    /// May this session act on the page it is on?
    ///
    /// `Ok(())` and `elsewhere` untouched is the ordinary answer: we are inside
    /// the domain the token names. Anything else is argued at length on
    /// [`Effects::browse_write`].
    async fn in_scope(
        &self,
        allowed: &Domain,
        reading: bool,
        session: &BrowserSession,
        here: &Url,
        elsewhere: &mut Option<Elsewhere>,
    ) -> Result<(), EffectError> {
        if within(here.host_str(), allowed) {
            return Ok(());
        }
        // Only the *host*, and only once it parses into a `Domain`. The rest of
        // the URL is bytes the page chose — a path, a query, a fragment — and
        // this is the seam where they would become a value the rest of the
        // process carries around. They stop here.
        let Some(host) = here.host_str().and_then(|host| Domain::parse(host).ok()) else {
            // A blank tab, an IP literal, a `file://`: nothing to rule on, so
            // there is nothing that could permit it.
            *elsewhere = Some(Elsewhere::Unruled(None));
            self.park(session).await;
            return Err(EffectError::OutOfScope(allowed.clone()));
        };
        match self.rule_again(reading, &host).await {
            Some(decision) => {
                *elsewhere = Some(Elsewhere::Ruled(host, decision));
                Ok(())
            }
            None => {
                *elsewhere = Some(Elsewhere::Unruled(Some(host)));
                self.park(session).await;
                Err(EffectError::OutOfScope(allowed.clone()))
            }
        }
    }

    /// Where the session is, as the browser itself reports it.
    ///
    /// Asked of the adapter rather than remembered here, because a page can move
    /// itself — a `<meta refresh>`, a `location.assign` on a timer — and a
    /// remembered address would be right until exactly the moment it mattered.
    async fn here(&self, session: &BrowserSession) -> Result<Url, EffectError> {
        match self
            .ports
            .browser
            .act(session, BrowserStep::Location)
            .await
            .map_err(EffectError::Provider)?
        {
            BrowserOutcome::Navigated(here) => Ok(here),
            _ => Err(EffectError::Refused(NO_LOCATION)),
        }
    }

    /// The gate, on the host we turned out to be on.
    ///
    /// The action *kind* is the token's own, so a read ruling re-asks as a read
    /// and a write ruling as a write: a redirect must never be a way to buy the
    /// other permission. `None` is "not authorised", and it deliberately folds
    /// in the database being unreachable — a gate that cannot answer has not
    /// said yes, and it has already written its own audit row either way.
    async fn rule_again(&self, reading: bool, host: &Domain) -> Option<DecisionId> {
        let subject = if reading {
            Action::BrowserRead {
                domain: host.clone(),
            }
        } else {
            Action::BrowserWrite {
                domain: host.clone(),
            }
        };
        // `Untrusted`: *they* chose this host, by answering our request with a
        // redirect. See `browse_write` on why the label is right even though no
        // verdict turns on it today.
        crate::gate::PolicyGate::new(self.db.clone())
            .authorize(&self.principal, Untrusted::new(subject))
            .await
            .ok()
            .map(|ok| ok.decision_id())
    }

    /// Take the shared session off a page nobody authorised.
    ///
    /// Best effort, and it has to be: if it fails the tab stays where it is and
    /// the next call's own location check refuses again, so there is no path
    /// where a failed park lets a step through. Reporting it over the refusal
    /// that actually matters would replace a true answer with a less useful one.
    async fn park(&self, session: &BrowserSession) {
        let blank = agentos_providers::browser::blank_page();
        let _ = self
            .ports
            .browser
            .act(session, BrowserStep::Goto(&blank))
            .await;
    }

    /// Go to a page inside the domain on the token and bring back what one
    /// element of it says.
    ///
    /// # Why this is not two calls to [`Effects::browse_write`]
    ///
    /// A read that a turn can express is *navigate and look*: a
    /// [`BrowserStep::Text`] on its own reads whatever page the session happens
    /// to be showing, which for a fresh context is nothing and for a reused one
    /// is the last page some other task left up. Splitting the pair across two
    /// tool calls would put a page load and the read of it under two rulings,
    /// two turns and two audit rows, with the model free to interleave anything
    /// in between — and the row that mattered ("what did we read, and where")
    /// would be spread across both.
    ///
    /// So it is one token, one ruling, one row. The navigation is scope-checked
    /// against the domain that was ruled on exactly as [`Effects::browse_write`]
    /// checks a [`BrowserStep::Goto`] — literally so: both go through
    /// `Effects::in_scope`, on the requested URL *and* on the one the page
    /// redirected us to. A read that lands somewhere else is re-ruled as a read,
    /// which is what keeps `denied_domains` from being walkable around.
    ///
    /// # It is a read, and it is unspellable as anything else
    ///
    /// The bound is [`BrowserRead`] and not [`BrowserWrite`], so a token minted
    /// for typing into somebody's form cannot be spent here. The audit row
    /// follows from the token — [`Effects::record`] writes
    /// `ok.action().to_action().kind()` — so `browser_read` and `browser_write`
    /// rows say what actually happened, with no flag for a caller to set.
    ///
    /// **The converse was claimed here and was false.** A token minted for
    /// reading *could* be spent on [`Effects::browse_write`], because
    /// `proof_of_need::Browse` rules as a read while declaring
    /// `type Of = BrowserWrite`; the bound admits it. What stops it is a check
    /// inside that method rather than this one's signature — see
    /// [`READ_TOKEN`], which explains why widening reads to the public web
    /// turned a harmless overlap into a live escalation.
    ///
    /// The text comes back [`Untrusted`] because it is a stranger's page, and it
    /// is the adapter that wrapped it — see
    /// [`BrowserOutcome::Text`](agentos_providers::browser::BrowserOutcome::Text).
    pub async fn read_page<A: Subject<Of = BrowserRead>>(
        &self,
        ok: Authorized<A>,
        url: &Url,
        selector: &str,
    ) -> Result<Untrusted<String>, EffectError> {
        let allowed = ok.action().subject().domain.clone();
        let mut elsewhere = None;
        let read = self
            .load_page(&allowed, url, selector, &mut elsewhere)
            .await;
        let mut detail = browse_detail(&allowed, elsewhere.as_ref());
        detail.insert("selector".to_owned(), json!(selector));
        self.record(&ok, Some(Value::Object(detail)), read).await
    }

    /// Read a page that lists companies and turn the addresses on it into
    /// ordinary prospect rows.
    ///
    /// # Why this is one effect and not "read, then write"
    ///
    /// The same argument [`Effects::read_page`] makes about navigate-and-look,
    /// one step further, plus a stronger one. Splitting it would mean handing a
    /// model the page and asking it to hand back the prospects — and a model
    /// transcribing a stranger's page into a tool call is precisely the channel
    /// `apps/server/tests/sourcing_e2e.rs` plants `IGNORE PREVIOUS
    /// INSTRUCTIONS` in a supplier name to test for. Here nothing does: the
    /// page is scanned in Rust by
    /// [`prospects::discover`](crate::prospects::discover), the only strings
    /// that survive are what [`agentos_domain::action::EmailAddress::parse`]
    /// accepted, and what comes back to the caller is a
    /// [`Report`](crate::prospects::Report) of our own counts in our own
    /// sentences. Not one byte the page authored crosses back, which is why the
    /// turn that calls this stays *trusted* while the same page read through
    /// [`Effects::read_page`] taints it — the difference is real and it is this.
    ///
    /// # The ruling is the read
    ///
    /// The token is a [`BrowserRead`], because that is the whole of what this
    /// does to the outside world: one page load on a domain the policy allows,
    /// scope-checked against the token exactly as a read is. Writing rows into
    /// this tenant's own `accounts` and `contacts` is not an
    /// [`Action`] and there is no kind for it — `knowledge::ingest` writes rows
    /// with no ruling at all — so inventing a further [`ActionKind`] to cover
    /// it would put a non-effect in the audit vocabulary.
    ///
    /// The bound on the rows is the policy's `max_new_contacts_per_day`, loaded
    /// here and passed down. See [`crate::prospects`] for why that number and
    /// not a new one.
    ///
    /// [`Action`]: agentos_domain::action::Action
    /// [`ActionKind`]: agentos_domain::action::ActionKind
    pub async fn discover_prospects<A: Subject<Of = BrowserRead>>(
        &self,
        ok: Authorized<A>,
        url: &Url,
        segment: &str,
    ) -> Result<crate::prospects::Report, EffectError> {
        let allowed = ok.action().subject().domain.clone();
        let mut elsewhere = None;
        let found = self
            .scan_directory(&allowed, url, segment, &mut elsewhere)
            .await;
        let mut detail = browse_detail(&allowed, elsewhere.as_ref());
        detail.insert("segment".to_owned(), json!(segment));
        self.record(&ok, Some(Value::Object(detail)), found).await
    }

    /// The provider-and-store half of [`Effects::discover_prospects`], split out
    /// for [`Effects::load_page`]'s reason: the token and the audit row do not
    /// share this method's error paths.
    async fn scan_directory(
        &self,
        allowed: &Domain,
        url: &Url,
        segment: &str,
        elsewhere: &mut Option<Elsewhere>,
    ) -> Result<crate::prospects::Report, EffectError> {
        let page = self.load_page(allowed, url, WHOLE_PAGE, elsewhere).await?;
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;

        // The intersected four layers, read here rather than carried on the
        // token: `Authorized` holds a decision and not a policy, deliberately.
        // One query per call, like `browser_session`.
        let budget = agentos_store::policy::load(&mut tx, self.principal.employee_id)
            .await
            .map_err(|_| EffectError::Refused(NO_POLICY))?
            .limits()
            .max_new_contacts_per_day;

        let list = crate::prospects::List {
            segment,
            // A page does not say where a company is incorporated and this does
            // not guess — `0033_prospect_listing.sql`'s own argument, and the
            // reason `ZZ` exists.
            country: crate::prospects::UNKNOWN_COUNTRY,
            employee_id: Some(self.principal.employee_id),
        };
        let report = crate::prospects::discover(&mut tx, &list, &page, Utc::now(), budget)
            .await
            .map_err(discovery_error)?;
        tx.commit().await.map_err(EffectError::Unavailable)?;
        Ok(report)
    }

    /// Read a prospect's booking page and file what its form is made of, for a
    /// human to confirm.
    ///
    /// # Why this is one effect and not "read, then write"
    ///
    /// [`Effects::discover_prospects`]'s argument, and the same one that put
    /// [`ActionKind::BrowserWrite`] in [`crate::turn::UNSERVED`]: splitting it
    /// would mean handing a model the markup and asking it for the selectors,
    /// and a selector a page talked a model into is exactly what the
    /// confirmation in `0032_prospect_flows.sql` exists to keep out of a probe.
    /// Here nothing does. [`crate::flow_proposal::propose`] scans the markup in
    /// Rust, the only strings that survive are what
    /// [`Selector::parse`](crate::flow_proposal::Selector::parse) accepted, and
    /// what comes back is a [`Proposed`](crate::flow_proposal::Proposed) whose
    /// `summary` is counts and our own field names.
    ///
    /// # The ruling is a read, and the row is a proposal
    ///
    /// [`BrowserRead`], because one page load on a public host is the whole of
    /// what this does to the outside world — the same token, the same scope
    /// check, the same audit kind as [`Effects::read_page`]. It does **not**
    /// need `allowed_domains`, and the promotion later does not grant it
    /// either: `proof_of_need::Prober` types into the form, which is a
    /// `BrowserWrite`, so a promoted flow on a host that is not on the write
    /// list still will not probe. `docs/ORIZN.md` says so where the promotion
    /// is documented, because granting it quietly here would be a policy change
    /// hidden inside a data change.
    ///
    /// The row it writes is this tenant's own and is not an [`Action`], exactly
    /// as `discover_prospects`' rows are not.
    ///
    /// [`Action`]: agentos_domain::action::Action
    /// [`ActionKind`]: agentos_domain::action::ActionKind
    pub async fn propose_flow<A: Subject<Of = BrowserRead>>(
        &self,
        ok: Authorized<A>,
        url: &Url,
    ) -> Result<crate::flow_proposal::Proposed, EffectError> {
        let allowed = ok.action().subject().domain.clone();
        let proposed = self.read_form(&allowed, url).await;
        let detail = Some(json!({ "domain": allowed.as_str() }));
        self.record(&ok, detail, proposed).await
    }

    /// The provider-and-store half of [`Effects::propose_flow`], split out for
    /// [`Effects::load_page`]'s reason.
    async fn read_form(
        &self,
        allowed: &Domain,
        url: &Url,
    ) -> Result<crate::flow_proposal::Proposed, EffectError> {
        let markup = self.load_markup(allowed, url).await?;
        let proposed = crate::flow_proposal::propose(&markup);
        // The markup is dropped here and never leaves this function. It is the
        // most dangerous string this process holds — a stranger's script bodies
        // and inline handlers — and the only thing that ever looked at it was a
        // scanner that returns identifiers.
        drop(markup);

        let host = url.host_str().ok_or(EffectError::Refused(NO_PROSPECT))?;
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        let filed = agentos_store::revenue::propose_prospect_flow(
            &mut tx,
            self.principal.employee_id,
            host,
            &agentos_store::revenue::NewFlowProposal {
                entry_url: url.as_str(),
                passport_field: proposed.passport_field.as_ref().map(sel),
                destination_field: proposed.destination_field.as_ref().map(sel),
                date_field: proposed.date_field.as_ref().map(sel),
                submit: proposed.submit.as_ref().map(sel),
                panel: proposed.panel.as_ref().map(sel),
            },
        )
        .await
        .map_err(|err| match err {
            RevenueError::Store(err) => EffectError::Unavailable(err),
            other => EffectError::Unavailable(StoreError::conflict(other.to_string())),
        })?;
        if filed.is_none() {
            // Nothing was written, so nothing to commit; the message is the
            // point. A host no account owns is a page about nobody.
            return Err(EffectError::Refused(NO_PROSPECT));
        }
        tx.commit().await.map_err(EffectError::Unavailable)?;
        Ok(proposed)
    }

    /// The provider half of [`Effects::propose_flow`].
    ///
    /// Deliberately **not** a `selector` parameter, unlike [`Effects::load_page`]:
    /// there is one element worth asking for and it is the whole document, so
    /// there is nothing here for a caller to choose. A markup read that took a
    /// selector would be a markup read a tool could one day be built on.
    async fn load_markup(
        &self,
        allowed: &Domain,
        url: &Url,
    ) -> Result<Untrusted<String>, EffectError> {
        if !within(url.host_str(), allowed) {
            return Err(EffectError::OutOfScope(allowed.clone()));
        }
        let session = self.browser_session().await?;
        self.ports
            .browser
            .act(&session, BrowserStep::Goto(url))
            .await
            .map_err(EffectError::Provider)?;
        match self
            .ports
            .browser
            .act(&session, BrowserStep::Markup(WHOLE_PAGE))
            .await
            .map_err(EffectError::Provider)?
        {
            // Already wrapped by the adapter, and it stays that way.
            BrowserOutcome::Markup(html) => Ok(html),
            // Only a broken adapter answers a markup read with something else —
            // including with a `Text`, which is why those are two variants.
            _ => Err(EffectError::Refused("not_markup")),
        }
    }

    /// The provider half of [`Effects::read_page`], split out so the token, the
    /// audit row and the two steps do not share one method's error paths.
    ///
    /// **It navigates, so it has the redirect problem too**, and it has it in
    /// the sharper form: what a read brings back is quoted. A directory page
    /// that answers with a `302` would have its landing scanned for prospects,
    /// and a prospect's panel would be read off a host the token never named and
    /// filed as *their* page. So the landing goes through the same check
    /// [`Effects::browse_write`] argues, with `reading = true` — the ruling a
    /// read bought is the ruling a redirected read gets, which for the shipped
    /// policy means `Channel::Web` and the denylist, and the denylist is the
    /// half a redirect could otherwise walk around.
    async fn load_page(
        &self,
        allowed: &Domain,
        url: &Url,
        selector: &str,
        elsewhere: &mut Option<Elsewhere>,
    ) -> Result<Untrusted<String>, EffectError> {
        if !within(url.host_str(), allowed) {
            return Err(EffectError::OutOfScope(allowed.clone()));
        }
        let session = self.browser_session().await?;
        match self
            .ports
            .browser
            .act(&session, BrowserStep::Goto(url))
            .await
            .map_err(EffectError::Provider)?
        {
            BrowserOutcome::Navigated(here) => {
                self.in_scope(allowed, true, &session, &here, elsewhere)
                    .await?;
            }
            _ => return Err(EffectError::Refused(NO_LOCATION)),
        }
        match self
            .ports
            .browser
            .act(&session, BrowserStep::Text(selector))
            .await
            .map_err(EffectError::Provider)?
        {
            // Already wrapped by the adapter, and it stays that way.
            BrowserOutcome::Text(text) => Ok(text),
            // Only a broken adapter answers a text read with something else.
            _ => Err(EffectError::Refused("not_text")),
        }
    }

    /// This employee's own browser context, as provisioning left it.
    ///
    /// [`BrowserSession`] is a provisioned resource and not a handle this crate
    /// may conjure — see `providers::browser`. What it *is*, though, is one row:
    /// `Step::Browser` reaches [`BrowserProvider::ensure_context`] and the
    /// binding it answers with is written to `employee_resources`, so pairing it
    /// with this principal's employee id rebuilds the session the provisioner
    /// made. That is the whole of what a turn was missing, and it is why the
    /// browser is reachable from one now: nothing new is created here, an
    /// existing resource is looked up.
    ///
    /// An employee whose browser is not `ready` gets [`EffectError::Refused`]
    /// with a code the model is shown, not a panic and not a silent no-op.
    ///
    /// ponytail: one query per browsing tool call, not a cached field.
    /// `Effects` is built per turn and a turn browses once or twice; a cache
    /// here would be a copy of a row that provisioning can retire underneath it.
    /// Cache it the day a turn drives a ten-step plan.
    ///
    /// Public because [`Prober`](crate::proof_of_need::Prober) is built around a
    /// session rather than looking one up — it takes the handle in its
    /// constructor precisely so that a browser context is a *provisioned
    /// resource* and not something a module can conjure — and the caller that
    /// builds a `Prober` for a self-started turn has an `Effects` and nothing
    /// else. It widens nothing: the row is this principal's own, the query is a
    /// read, and every step taken with the session still goes through the gate.
    pub async fn browser_session(&self) -> Result<BrowserSession, EffectError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        let read = sqlx::query_as::<_, (Option<String>, Option<String>)>(
            "SELECT provider, external_id FROM employee_resources \
              WHERE employee_id = $1 AND step = 'browser' AND state = 'ready'",
        )
        .bind(self.principal.employee_id.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|err| EffectError::Unavailable(StoreError::from(err)));
        let _ = tx.rollback().await;

        match read? {
            Some((Some(provider), Some(external_id))) => Ok(BrowserSession {
                employee_id: self.principal.employee_id,
                binding: ProviderBinding {
                    provider,
                    external_id,
                },
                // `None` everywhere in this workspace: no shipped adapter reads
                // it, and the one that would (self-hosted Chrome) is told its
                // profile directory when the process is started, not here.
                user_data_dir: None,
            }),
            _ => Err(EffectError::Refused(NO_BROWSER)),
        }
    }

    /// Call the MCP tool named on the token.
    ///
    /// The result stays [`Untrusted`]: it is a stranger's text, and the audit
    /// row records that the call happened, not what it said.
    pub async fn call_tool<A: Subject<Of = McpCall>>(
        &self,
        ok: Authorized<A>,
        arguments: &Value,
    ) -> Result<Untrusted<Value>, EffectError> {
        let tool = ok.action().subject().tool.clone();
        let called = self
            .ports
            .mcp
            .call(&tool, arguments)
            .await
            .map_err(EffectError::Provider);

        let detail = Some(json!({ "tool": tool.to_string() }));
        self.record(&ok, detail, called).await
    }

    /// Move the money the token authorises **to the payee it authorises**, then
    /// settle or release the reservation it carries.
    ///
    /// # Why this takes a memo and not an instruction
    ///
    /// Both halves of the payment now come off the token, and the caller is
    /// left with the one field no ruling and no approval hash is taken over:
    /// the memo, which is a sentence for a statement and an audit row.
    ///
    /// It used to take a whole [`PaymentInstruction`], amount from the token
    /// and payee from the argument. A human approving `pay EUR 500.00` in the
    /// queue was told by `routes::approvals` that restating the action wrong
    /// would be refused — and it would not have been, because the payee was in
    /// neither the action nor the hash. Putting it on
    /// [`agentos_domain::action::Action::PaymentCreate`] closed that; leaving
    /// this signature alone would have reopened it one layer down, where the
    /// gate rules on A and the port is handed B. There is nothing here to
    /// compare, because there is nothing to disagree with.
    pub async fn pay<A: Subject<Of = PaymentCreate>>(
        &self,
        ok: Authorized<A>,
        memo: &str,
    ) -> Result<ProviderMessageId, EffectError> {
        let PaymentCreate { amount, payee } = ok.action().subject().clone();
        let instruction = PaymentInstruction {
            payee,
            memo: memo.to_owned(),
        };
        let paid = self
            .ports
            .payments
            .pay(&self.key_for(&ok), amount, &instruction)
            .await
            .map_err(EffectError::Provider);

        let detail = Some(json!({
            "payee": instruction.payee,
            // `PaymentInstruction::memo` says it lands in the audit row, and
            // until this line it did not: the field was built by `Turn::perform`
            // from the model's own arguments, handed to the port, and read by
            // nothing this side of an adapter that does not exist yet. An
            // operator asking "what was that payment for" now has the answer
            // here rather than only on a statement nobody in this system sees.
            "memo": instruction.memo,
            "minor": amount.minor(),
            "currency": amount.currency().code(),
            "provider_message_id": paid.as_ref().ok().map(ProviderMessageId::as_str),
        }));
        self.record(&ok, detail, paid).await
    }

    /// Ask for the money the token authorises: write one row of the register.
    ///
    /// # The one effect here with no provider, and why that is not a shortcut
    ///
    /// Every other method on this struct hands something to a port and records
    /// what came back. There is no `InvoiceProvider` and there must not be one
    /// today: this workspace may not call a PSP, so a port would be an interface
    /// with no implementation and one caller — and what an invoice *is* at this
    /// stage is a row saying somebody owes us. `Effects::send_internal` already
    /// makes the same move for the same reason ("the provider here is our own
    /// database") and this is that argument with the network removed entirely.
    ///
    /// **Nothing is sent.** Putting the demand in front of the customer is an
    /// [`Effects::send_email`], gated and audited as one, deliberately not
    /// folded in here: an invoice recorded and not sent is a mistake somebody
    /// can see, and one sent and not recorded is not.
    ///
    /// # Why the bound is `Authorized<InvoiceIssue>` and not `A: Subject<Of = …>`
    ///
    /// Every sibling takes the generic bound so that one method serves both
    /// `Authorized<S>` and `Authorized<Untrusted<S>>`. This one takes the
    /// trusted newtype **only**, so a token minted from a tainted turn does not
    /// typecheck here at all.
    ///
    /// It is belt to the domain's braces rather than the only stop. `Action::
    /// InvoiceIssue` is [`Risk::High`](agentos_domain::action::Risk) and the
    /// evaluator's arm answers `Allow`, so `evaluate`'s taint wire already
    /// refuses an untrusted one with `DenyReason::UntrustedInput` — no token is
    /// minted and, unlike `ContractSign`, no approval request is filed for a
    /// human to be shown a stranger's demand.
    ///
    /// The bound is here because that property depends on the arm continuing to
    /// answer `Allow`, and the day somebody adds the amount threshold
    /// `0066_invoices.sql` leaves open it will not: the wire is written
    /// `decision.is_allow()`, so an untrusted invoice over the threshold would
    /// come back `RequireApproval` and slip past it, exactly as a signature does
    /// today. **What this signature saves then is the effect, not the filing** —
    /// no token of the untrusted flavour can reach this method, so nothing is
    /// written; but the approval request would be on somebody's queue, authored
    /// by a stranger. `crate::revenue`'s module docs name that hole and the one
    /// expression in `domain::policy::evaluate` that closes it for every
    /// high-risk action at once, and that expression is the fix to make on the
    /// same day, not this bound.
    ///
    /// # What the audit row carries, and what it does not
    ///
    /// The amount, its currency, the memo, the deal and the invoice id. Not the
    /// customer's name: it is not in the subject, it is a join away, and the
    /// deal id is what a reader follows. `Effects::pay` learned the same lesson
    /// from the other side — its `memo` reached the audit row only after
    /// somebody asked "what was that payment for" and found nothing.
    pub async fn issue_invoice(
        &self,
        ok: Authorized<InvoiceIssue>,
        draft: &InvoiceDraft,
    ) -> Result<InvoiceId, EffectError> {
        let amount = ok.action().subject().amount;
        let id = InvoiceId::new_v7(Utc::now());

        let issued = self
            .write_invoice(id, amount, draft)
            .await
            .map(|()| id)
            .map_err(|err| match err {
                // The store's silence for "not this company's deal, or nobody
                // won it". A closed code rather than the store error, because it
                // is handed back to a caller as a failure and it must not become
                // an existence oracle for another company's opportunity ids.
                StoreError::NotFound => EffectError::Refused(NO_WON_DEAL),
                other => EffectError::Unavailable(other),
            });

        let detail = Some(json!({
            "opportunity_id": draft.opportunity_id.to_string(),
            "memo": draft.memo,
            "minor": amount.minor(),
            "currency": amount.currency().code(),
            "invoice_id": issued.as_ref().ok().map(|id: &InvoiceId| id.to_string()),
        }));
        self.record(&ok, detail, issued).await
    }

    /// The write, in its own transaction, so [`Effects::issue_invoice`] reads
    /// like its siblings: do the thing, then record it.
    ///
    /// Two transactions and not one, exactly as `send_internal` uses two — the
    /// audit row records that the attempt happened, which is true whether or not
    /// the row landed, and folding them together would make an unrecordable
    /// audit row roll back an invoice the customer has already been told about.
    async fn write_invoice(
        &self,
        id: InvoiceId,
        amount: Money,
        draft: &InvoiceDraft,
    ) -> Result<(), StoreError> {
        let mut tx = self.db.tenant_tx(self.principal.tenant_id).await?;
        let written = invoices::issue(
            &mut tx,
            invoices::Draft {
                id,
                opportunity_id: draft.opportunity_id,
                issued_by: self.principal.employee_id,
                amount,
                memo: &draft.memo,
                due_at: draft.due_at,
                lines: &draft.lines,
            },
        )
        .await;
        match written {
            Ok(_) => {
                tx.commit().await?;
                Ok(())
            }
            Err(err) => {
                // Rolled back rather than dropped: nothing was written and a
                // pooled connection goes back deliberately.
                let _ = tx.rollback().await;
                Err(err)
            }
        }
    }

    /// Say something to the colleague named on the token, and wake them.
    ///
    /// # Where the message's trust label comes from
    ///
    /// `ok.action().trust()`, and nowhere else. `A` is either `InternalSend` —
    /// which [`Authorizable`] answers `Trusted` for, because such a value is
    /// only ever built by our own code from our own configuration — or
    /// `Untrusted<InternalSend>`, which answers `Untrusted`. `Turn::perform`
    /// picks between the two from the turn's own live label, in a macro that
    /// cannot pick the wrong one, and there is no third way to obtain a token.
    ///
    /// So the label stored on the message is not a claim the sender makes about
    /// itself. It is the same type-level provenance that keeps a supplier's PDF
    /// away from the payment tool, followed one hop further: an employee that
    /// read a hostile email and then messaged a colleague relays its taint with
    /// it, and the colleague receives data rather than an order. Read
    /// `crate::inbound`'s module docs for the argument in full.
    ///
    /// # Not a provider
    ///
    /// The "provider" here is our own database, so unlike an email this effect
    /// is transactional: the recipient's reserved turn, the message row and the
    /// wake-up commit together or not at all. The audit row still goes through
    /// [`Effects::record`] in a second transaction, like every other effect —
    /// what it records is that the attempt happened, which is true either way.
    pub async fn send_internal<A: Subject<Of = InternalSend>>(
        &self,
        ok: Authorized<A>,
        note: &InternalNote,
    ) -> Result<Delivered, EffectError> {
        let to = ok.action().subject().to.clone();
        let trust = ok.action().trust();
        let key = self.key_for(&ok);

        let delivered = self.deliver(&to, note, trust, &key).await;
        let detail = Some(json!({
            "to": to.as_str(),
            "internal_kind": note.errand.as_str(),
            // The label the colleague will receive it at, on the record.
            "trust_label": match trust {
                TrustLabel::Trusted => "trusted",
                TrustLabel::Untrusted => "untrusted",
            },
            "message_id": delivered.as_ref().ok().map(|d: &Delivered| d.message_id),
        }));
        self.record(&ok, detail, delivered).await
    }

    /// The transactional half of [`Effects::send_internal`].
    ///
    /// Split out so the token, the trust label and the audit row stay in one
    /// readable method while the transaction has a scope of its own — and so
    /// that every error path rolls back rather than leaving a reserved turn
    /// behind for a message that was refused.
    async fn deliver(
        &self,
        to: &Slug,
        note: &InternalNote,
        trust: TrustLabel,
        key: &IdempotencyKey,
    ) -> Result<Delivered, EffectError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;

        let sent = inbound::send(
            &mut tx,
            self.principal.employee_id,
            to,
            note.errand,
            &note.body,
            trust,
            note.thread,
            key,
            Utc::now(),
        )
        .await;

        match sent {
            Ok(delivered) => {
                tx.commit().await.map_err(EffectError::Unavailable)?;
                Ok(delivered)
            }
            Err(err) => {
                let _ = tx.rollback().await;
                Err(match err {
                    InternalError::Store(err) => EffectError::Unavailable(err),
                    // Unreachable colleague, unanswerable question, somebody
                    // else's thread, a colleague out of turns. All four are the
                    // world saying no to something the policy allows.
                    refused => EffectError::Refused(refused.code()),
                })
            }
        }
    }

    /// Who this employee may brief: its direct reports, by short name.
    ///
    /// A read and not an effect — there is no token, because nothing happens.
    /// It is here rather than on the turn because [`Effects`] is what holds the
    /// database handle and the principal, and a turn that could open its own
    /// transaction could read anything.
    pub async fn line(&self) -> Result<Vec<Slug>, EffectError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        let line = inbound::line(&mut tx, self.principal.employee_id).await;
        let _ = tx.rollback().await;
        line.map_err(EffectError::Unavailable)
    }

    /// Brief the line: the same words to every direct report, in one
    /// transaction.
    ///
    /// # One token per report, and why there is no `Action::InternalBrief`
    ///
    /// A briefing is not a new authority. It is N internal sends whose
    /// *addresses* the org chart supplied instead of the model, so it is ruled
    /// on as N internal sends — one [`Authorized`] per report, in `line` order,
    /// each with its own decision, its own audit row naming its own colleague,
    /// and its own [`IdempotencyKey`]. A briefing-shaped `Action` would have
    /// been one ruling covering five recipients, and `domain::policy` would
    /// have had nothing new to say about it: the evaluator's `InternalSend` arm
    /// asks only whether the internal channel is allowed, and the arm for a
    /// briefing would have been that same arm. A variant that adds no rule adds
    /// a discriminant to `ActionKind::ALL`, a row to every role pack's
    /// partition of the action space, and one more thing for the next reader to
    /// tell apart from the one it duplicates.
    ///
    /// The keys falling out for free is the payoff, not a coincidence: the
    /// `messages` table is unique on `(tenant_id, idempotency_key)`, so a
    /// fan-out needs N distinct keys, and N decisions already give N.
    ///
    /// # Where the trust label comes from
    ///
    /// The same place as [`Effects::send_internal`]'s: the *type* of the token.
    /// `Turn::perform` mints the whole line's tokens inside one branch of its
    /// trust match, so `A` is `InternalSend` for every report or
    /// `Untrusted<InternalSend>` for every report — a briefing cannot be half
    /// tainted, and a tainted manager's briefing lands on all N desks as data.
    ///
    /// # No `record` call
    ///
    /// Deliberately, and it is the only effect here that skips it. Nothing is
    /// missing: `PolicyGate::authorize` wrote one audit row per ruling, and
    /// `inbound::send` writes one `MessageReceived` row per delivery *inside
    /// the transaction that wrote the message*. [`Effects::record`] takes one
    /// token and one outcome; calling it N times would mean N more rows saying
    /// what those 2N already say, and calling it once would mean picking a
    /// report to attribute the whole briefing to.
    pub async fn brief<A: Subject<Of = InternalSend>>(
        &self,
        line: Vec<Authorized<A>>,
        note: &InternalNote,
    ) -> Result<Briefing, EffectError> {
        let Some(first) = line.first() else {
            return Ok(Briefing::default());
        };
        let trust = first.action().trust();
        let audience: Vec<(Slug, IdempotencyKey)> = line
            .iter()
            .map(|ok| (ok.action().subject().to.clone(), self.key_for(ok)))
            .collect();

        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        let briefed = inbound::brief(
            &mut tx,
            self.principal.employee_id,
            &audience,
            &note.body,
            trust,
            Utc::now(),
        )
        .await;

        match briefed {
            Ok(briefing) => {
                tx.commit().await.map_err(EffectError::Unavailable)?;
                Ok(briefing)
            }
            Err(err) => {
                let _ = tx.rollback().await;
                Err(match err {
                    InternalError::Store(err) => EffectError::Unavailable(err),
                    // Not reachable from `inbound::brief`, which puts every
                    // per-recipient refusal in the receipt instead of returning
                    // it. Mapped rather than asserted: a refusal that escaped
                    // should surface as a coded tool result, not a panic.
                    refused => EffectError::Refused(refused.code()),
                })
            }
        }
    }

    /// Write one item onto this company's board — for this employee, or for a
    /// seat it directly manages.
    ///
    /// `assignee` is `None` for a note to self. There is deliberately no way to
    /// spell *the shared board*: `store::backlog::open_for` hands an employee
    /// its assigned items only, so an unassigned item posted from a turn would
    /// be a write with no reader, and the founder's `POST /v1/work` is where
    /// unassigned work comes from.
    ///
    /// # Why there is no token, and why the founder's argument needed redoing
    ///
    /// `POST /v1/work` established that posting is not an [`Action`]: every
    /// [`ActionKind`](agentos_domain::action::ActionKind) names something that
    /// leaves the building or spends, and the one internal verb that is an
    /// action — [`InternalSend`] — is one because it consumes a turn of the
    /// recipient's daily budget. A work item wakes nobody.
    ///
    /// That was argued about an **operator holding an API key**, and it does not
    /// transfer for free. A founder answers for what he types; an employee is a
    /// model, and a model is steerable by any text it has read. So the question
    /// is not "does this leave the building" but "what can a hostile page buy by
    /// steering this call", and there are three answers:
    ///
    /// 1. **Instructions into a colleague's context — no.**
    ///    [`Backlog::open_for`] returns [`Untrusted`] per item, unconditionally,
    ///    with nowhere in the trait for an adapter to claim otherwise, and
    ///    `loops::initiative::waiting` never unwraps one. A turn shown its board
    ///    is an untrusted turn and is offered no high-risk schema. So a
    ///    supplier's sentence relayed through the board arrives as quoted
    ///    material — the same landing a tainted `message_colleague` gets, minus
    ///    the wake. One hop launders nothing.
    /// 2. **A woken colleague or a spent budget — no**, and this half of the
    ///    founder's argument is a claim about the mechanism rather than about
    ///    the writer, so it survives the change intact. `open_for` is read at
    ///    the top of a turn the cadence had already scheduled.
    /// 3. **Flooding — yes, and it is the only thing that changes.** There is no
    ///    ceiling on `work_items` anywhere, and an employee that could file for
    ///    anyone could bury anyone. That is what
    ///    [`inbound::may_assign`] bounds, and it bounds it with the org chart
    ///    rather than with a number nobody has: the set of people whose day this
    ///    employee may fill is the set it may already order about — and an order
    ///    spends their turns, which is strictly worse than a line on a board.
    ///    **The new verb is weaker than one the employee already had, against
    ///    exactly the same people.** Nothing widens.
    ///
    /// So: still not an action. Inventing `ActionKind::WorkItemPost` would put a
    /// discriminant in [`ActionKind::ALL`](agentos_domain::action::ActionKind),
    /// a row in every role pack's partition and an arm in
    /// `domain::policy::evaluate` — and that arm would have nothing to say,
    /// because `PolicyLimits` has no field a board could be measured against and
    /// the founder's brief is explicit that the bound must not be an invented
    /// number. It is the same variant-that-adds-no-rule [`Effects::brief`]
    /// refuses for a briefing.
    ///
    /// And the ruling that *is* made lives here for the reason
    /// [`EffectError::Refused`] already gives: an [`Action`] carries a parsed
    /// subject and no org chart, so the gate cannot see a reporting line. It is
    /// the same seam `send_internal` refuses an unreachable colleague at.
    ///
    /// # Two transactions, and why they cannot be one
    ///
    /// The org chart is read here and the item is written by the board, which is
    /// a port: a customer's Jira has no transaction of ours to join. So a guard
    /// that insisted on one transaction with the write would be a guard no
    /// second adapter could ever satisfy. The window is the same one
    /// [`Effects::brief`] has between `line()` and `brief()`, and what fits in
    /// it is one item filed against a seat that stopped reporting to this
    /// employee a moment ago.
    ///
    /// `title` is not length-checked here. `work_items_title_shape` is a `CHECK`
    /// and a violation classifies as [`StoreError::Database`], which
    /// `Turn::performed` turns into an aborted run — so the bound is enforced
    /// against [`agentos_store::backlog::MAX_TITLE`] in `Turn::propose`, where a
    /// too-long line costs a tool result the model can act on instead of the
    /// rest of its turn.
    pub async fn post_work(&self, assignee: Option<&Slug>, title: &str) -> Result<(), EffectError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        let target = inbound::may_assign(&mut tx, self.principal.employee_id, assignee).await;
        // Rolled back, not committed: nothing here took a lock or wrote a row.
        let _ = tx.rollback().await;

        let target = target.map_err(|err| match err {
            InternalError::Store(err) => EffectError::Unavailable(err),
            refused => EffectError::Refused(refused.code()),
        })?;

        // ponytail: the third `PgBacklog::new` in the workspace, beside
        // `routes::work` and `loops::initiative`. All three say the same thing
        // — this tenant's own table — and the day a `backlog_bindings` row can
        // say otherwise, one constructor replaces all three at once. Choosing
        // the adapter here would be inventing that selection point in the least
        // visible of the three places.
        PgBacklog::new(self.db.clone(), self.principal.tenant_id)
            .post(title, Some(target), Some(self.principal.employee_id))
            .await
            .map(|_| ())
            .map_err(|err| match err {
                BacklogError::Unavailable(err) => EffectError::Unavailable(err),
                BacklogError::Provider(err) => EffectError::Provider(err),
            })
    }

    /// Take one item off the pool, or say one of yours is done.
    ///
    /// `Ok(false)` is the ordinary answer and not a failure: somebody claimed it
    /// first, or the item is not this employee's to close. The two are one
    /// answer on purpose — a distinguishable one lets a turn walk the board by
    /// asking, which is the silence [`inbound::may_assign`] keeps one function
    /// over.
    ///
    /// # Why neither of these is an [`Action`] either
    ///
    /// [`Effects::post_work`] argues the case for filing, and both verbs here
    /// are *narrower* than filing was:
    ///
    /// **Claiming** moves work into this employee's own day and nobody else's.
    /// It takes a row that was nobody's; the seat it costs is the claimant's own
    /// turn budget, which is already metered by the thing that woke it. There is
    /// no org-chart guard because there is nobody to guard: the pool is the
    /// founder's undecided work — an employee cannot put anything in it — and an
    /// employee taking a job the founder wrote down is the whole point of a
    /// board being shared. The only rule is the one the `UPDATE` enforces: it is
    /// still there, and it is still open.
    ///
    /// **Closing** asserts something about this employee's own board. It wakes
    /// nobody, spends nothing and reaches nothing outside; and it is safe to
    /// give a model at all only because `0061` refused `DELETE`, so the worst a
    /// hijacked turn can do is mark its own items done — visibly, reversibly,
    /// and one `PUT /v1/work/{id}` from being undone. A verb whose damage is
    /// fully reversible by the person who can see it is not a verb the gate has
    /// anything to rule on.
    ///
    /// What is *not* recorded is who closed it. `assignee_id` answers it for
    /// every turn-close, because a turn can only close what is its own; it
    /// cannot tell a founder's close from the assignee's, and a `closed_by`
    /// column is the fix the day that difference is worth a migration.
    pub async fn work_item(
        &self,
        item: WorkItemId,
        action: WorkAction,
    ) -> Result<bool, EffectError> {
        let board = PgBacklog::new(self.db.clone(), self.principal.tenant_id);
        let who = self.principal.employee_id;
        match action {
            WorkAction::Claim => board.claim(item, who).await,
            WorkAction::Close => board.close(item, who).await,
        }
        .map_err(|err| match err {
            BacklogError::Unavailable(err) => EffectError::Unavailable(err),
            BacklogError::Provider(err) => EffectError::Provider(err),
        })
    }

    /// Promise one moment of this employee's own time.
    ///
    /// # Where the seat comes from, which is the whole security argument
    ///
    /// [`PgCalendar`] is built here, from `self.principal` — never from the
    /// tool's arguments, which do not carry an employee and cannot be made to.
    /// [`Calendar::book`] takes no employee either, so a `dyn Calendar` can only
    /// ever promise a moment of its holder's own time and spend a turn out of
    /// its holder's own budget. "Book an hour of somebody else's day" is
    /// unrepresentable rather than refused, which is what
    /// [`crate::calendar`]'s module docs mean by the absence being a security
    /// property.
    ///
    /// # Why this one *is* an [`Action`] where posting work is not
    ///
    /// [`Effects::post_work`] refuses a discriminant that would add no rule, and
    /// this one adds one: `always_denies` answers for it and
    /// `evaluate_rules` has an arm, both on `Channel::Internal`, so a policy
    /// layer can take the verb away from a seat. Posting work has no such
    /// rule — its only bound is the org chart, which no `Action` can carry —
    /// and inventing a kind for it would have put a decision in the trail that
    /// nobody made.
    ///
    /// # The third adapter this reaches for
    ///
    /// ponytail: the third `PgCalendar::new` in the workspace, beside
    /// `routes::calendar` and `loops::initiative`, and it is the same choice
    /// `post_work` makes about `PgBacklog` for the same reason — all three say
    /// "our own table", and the day a `calendar_bindings` row can say otherwise
    /// one constructor replaces all three at once.
    pub async fn book_hour<A: Subject<Of = AppointmentBook>>(
        &self,
        ok: Authorized<A>,
        at: DateTime<Utc>,
        zone: &str,
        subject: &str,
    ) -> Result<AppointmentId, EffectError> {
        let booked = PgCalendar::new(
            self.db.clone(),
            self.principal.tenant_id,
            self.principal.employee_id,
        )
        .book(at, zone, subject)
        .await
        // Total, with no `_` arm, so a fourth `CalendarError` has to be
        // classified rather than defaulted. `UnknownZone` is `Refused` and not
        // `Unavailable` on purpose: `Turn::performed` turns an `Unavailable`
        // into the end of the run, and a mistyped zone must cost one tool
        // result the model can correct — the same argument `Turn::propose`
        // makes about an over-long work-item title.
        .map_err(|err| match err {
            CalendarError::Provider(err) => EffectError::Provider(err),
            CalendarError::Unavailable(err) => EffectError::Unavailable(err),
            CalendarError::UnknownZone => EffectError::Refused(UNKNOWN_ZONE),
            CalendarError::SubjectShape => EffectError::Refused(BAD_SUBJECT),
        });

        // What the row says, and what it deliberately does not. The instant and
        // the zone are ours — parsed by `Turn::propose`, formatted by chrono —
        // and the *subject line* is not: it is free text the model wrote about
        // whatever it has been reading, and `browse_detail` already sets the
        // rule that nothing a stranger authored becomes an audit column. An
        // operator who wants the words reads `appointments.subject`, which is
        // the column that holds them, under the tenant's own RLS.
        let detail = Some(json!({
            "at": at.to_rfc3339(),
            "at_zone": zone,
            "appointment_id": booked.as_ref().ok().map(AppointmentId::as_uuid),
        }));
        self.record(&ok, detail, booked).await
    }

    /// The de-duplication token for one authorised effect.
    ///
    /// Derived from the decision, so a crash between the provider's `202` and
    /// our own commit replays into the provider's idempotency cache instead of
    /// sending twice. A *fresh* authorization is deliberately a fresh key: two
    /// identical emails an operator asked for twice are two emails.
    ///
    /// ponytail: reuses [`IdempotencyKey::for_step`]'s deterministic format,
    /// because `domain::ids` is not this unit's file. A `for_decision`
    /// constructor belongs there.
    fn key_for<A>(&self, ok: &Authorized<A>) -> IdempotencyKey {
        IdempotencyKey::for_step(
            self.principal.employee_id,
            &format!("effect:{}", ok.decision_id().as_uuid()),
        )
    }

    /// Write, **and commit**, "a request under this ruling is about to leave for
    /// `provider`" — before it does.
    ///
    /// # This is the frontier, and the commit is the whole of it
    ///
    /// [`Self::record`] opens its transaction *after* the provider has answered,
    /// which is correct and is not enough: the interesting failure is the one
    /// where no answer arrives, and in that failure `record` is never reached.
    /// Everything this system knew about the request dies with the process. So
    /// there are two writes around every send now — this one, committed before
    /// the request leaves, and [`Self::record_sent`]'s, committed after — and a
    /// crash between them leaves an `in_flight` row instead of silence.
    ///
    /// # What it does **not** do: refuse a second send
    ///
    /// There is no "this ruling already sent something" branch here, and adding
    /// one would be a guard on a door nobody can open. [`Self::key_for`] derives
    /// the key from the ruling's `decision_id`; every mint of an
    /// [`Authorized`] takes a fresh `DecisionId::new_v7`, the token is not
    /// `Clone`, and each send method consumes it **by value** — so two requests
    /// can never present the same key, and a branch keyed on finding a prior row
    /// could never run. A refusal code that cannot fire is worse than no code at
    /// all: it reads, to the next person, as a promise that duplicates are
    /// impossible.
    ///
    /// They are not. The realistic double-send is a crashed turn retried under a
    /// *new* ruling, which arrives here with a new key and gets a second row. It
    /// is not stopped, it is **recorded** — see [`Self::record_sent`] for what is
    /// left behind, and `GET /v1/employees/{id}`'s `unsettled_calls` for who
    /// reads it. If a caller ever does reuse a key, the insert hits
    /// `provider_intents_tenant_key_idx`, this returns
    /// [`EffectError::Unavailable`], and nothing leaves — which is the outcome
    /// the branch would have wanted, obtained from a constraint that cannot rot.
    ///
    /// `provider` is the port — `telephony`, `email` — spelled the way
    /// `crate::provisioning::adapter_of` spells it, because which vendor is
    /// bound behind that port is deployment configuration and the row outlives
    /// it.
    async fn begin_send<A: Subject>(
        &self,
        ok: &Authorized<A>,
        provider: &str,
    ) -> Result<(), EffectError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        provisioning::begin_send_intent(
            &mut tx,
            self.principal.employee_id,
            provider,
            ok.action().to_action().kind().as_str(),
            &self.key_for(ok),
            Utc::now(),
        )
        .await
        .map_err(EffectError::Unavailable)?;
        tx.commit().await.map_err(EffectError::Unavailable)
    }

    /// One audit row per attempt, plus the reservation bookkeeping, in one
    /// transaction.
    ///
    /// The provider call has already happened when this runs — it cannot be
    /// inside the transaction, because a database transaction must not be held
    /// open across a call to a third party. If the row fails to commit the
    /// effect is reported as [`EffectError::Unavailable`] even though it
    /// landed; the send was idempotent on a key derived from the decision, so
    /// re-running the *same* token records it without sending again.
    async fn record<A: Subject, T>(
        &self,
        ok: &Authorized<A>,
        detail: Option<Value>,
        outcome: Result<T, EffectError>,
    ) -> Result<T, EffectError> {
        let now = Utc::now();
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;
        self.book_effect(&mut tx, ok, detail, &outcome, now).await?;
        tx.commit().await.map_err(EffectError::Unavailable)?;
        outcome
    }

    /// [`Self::record`], plus closing the row [`Self::begin_send`] committed —
    /// in the same transaction, so the audit trail and the intent log cannot
    /// disagree about what happened.
    ///
    /// # The classification is the honest part
    ///
    /// Only the caller of a provider knows the difference between "it said no"
    /// and "it never said anything", and that difference is the entire value of
    /// the row. So the match below is total over [`ProviderError`] and there is
    /// no `_` arm: a fifth variant has to be classified by whoever adds it.
    ///
    /// * [`ProviderError::Terminal`] and [`ProviderError::RateLimited`] are
    ///   **answers**. The provider read the request and declined; nothing was
    ///   sent, and the row is settled `failed` so it stops asking for attention.
    /// * [`ProviderError::Retryable`] is the arm worth reading twice, because
    ///   the obvious sentence about it is the wrong way round. It is **not**
    ///   mostly "the request may even have landed". Every adapter in
    ///   `agentos-providers` funnels its entire transport failure set through
    ///   [`ProviderError::timeout`] in one `map_err(|_| …)` around
    ///   `reqwest::send` — `email_resend::call` and `telephony_twilio`'s
    ///   `ApiError::transport` both — so a refused connection, a DNS failure
    ///   and a TLS handshake that never finished all arrive here, and
    ///   [`ProviderError::from_status`] adds 408, 425 and every 5xx on top. In
    ///   every one of those the request either never left this process or was
    ///   turned away without being acted on. The genuinely ambiguous member —
    ///   a read timeout *after* the bytes went out, which is what
    ///   `telephony_twilio` means by *"the request may even have landed"* — is
    ///   one case in that class and not the usual one.
    ///
    ///   Nothing is written and the row stays `in_flight` anyway. That is a
    ///   **pessimistic** answer by construction and not a neutral one: from the
    ///   near side of the socket there is nothing to branch on, so it
    ///   over-reports on purpose. Most rows this leaves behind will be sends
    ///   that never happened, and the reader has to be told that or it will
    ///   read a list of near-misses as a list of double-sends — see
    ///   [`Self::send_sms`], `routes::employees`'s `unsettled_calls`, and
    ///   `docs/OPERATIONS.md` §6. Settling them `failed` instead would be
    ///   pleasant to read and wrong on precisely the row that mattered.
    /// * [`ProviderError::PendingExternal`] is filed with the timeout and not
    ///   with the refusals, deliberately: it means somebody outside must act
    ///   before the resource is usable, it carries no message id, and a send
    ///   cannot produce one at all — so if one ever arrives here, an adapter is
    ///   doing something this method has no honest answer for, and leaving the
    ///   row for a person is the answer that does not invent one.
    ///
    /// It takes the port's own `Result` rather than an [`EffectError`] because
    /// that is what makes the match total: by the time an error has been widened
    /// to `EffectError` the refusals this method must not settle — including
    /// [`Self::begin_send`]'s own — are indistinguishable from the provider's.
    async fn record_sent<A: Subject>(
        &self,
        ok: &Authorized<A>,
        sent: Result<ProviderMessageId, ProviderError>,
    ) -> Result<ProviderMessageId, EffectError> {
        let now = Utc::now();
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(EffectError::Unavailable)?;

        // `None` is the case this whole fence exists for, and it writes nothing.
        if let Some(answer) = match &sent {
            Ok(id) => Some(Ok(id.as_str())),
            Err(ProviderError::Terminal { code }) => Some(Err(*code)),
            Err(ProviderError::RateLimited { .. }) => Some(Err(RATE_LIMITED)),
            Err(ProviderError::Retryable { .. } | ProviderError::PendingExternal { .. }) => None,
        } {
            provisioning::settle_send_intent(&mut tx, &self.key_for(ok), answer, now)
                .await
                .map_err(EffectError::Unavailable)?;
        }

        let sent = sent.map_err(EffectError::Provider);
        self.book_effect(&mut tx, ok, message_detail(&sent), &sent, now)
            .await?;
        tx.commit().await.map_err(EffectError::Unavailable)?;
        sent
    }

    /// The reservation bookkeeping and the audit row, in a transaction the
    /// caller opens and commits.
    ///
    /// Extracted so [`Self::record_sent`] can put the intent's closing write in
    /// the *same* transaction as the audit row rather than in a third one; the
    /// body is byte-for-byte what [`Self::record`] used to do inline.
    async fn book_effect<A: Subject, T>(
        &self,
        tx: &mut TenantTx<'_>,
        ok: &Authorized<A>,
        detail: Option<Value>,
        outcome: &Result<T, EffectError>,
        now: DateTime<Utc>,
    ) -> Result<(), EffectError> {
        // Only a payment carries one, and it is the whole reason the gate's
        // docs call this module the executor: money that did not move must not
        // keep holding the day's headroom.
        if let Some(reservation) = ok.reservation() {
            let settled = if outcome.is_ok() {
                // No team arm, and it is not a symmetry that got missed:
                // settling is bookkeeping and deliberately leaves *both*
                // buckets charged — money that moved stays spent against the
                // employee's day and against the team's. `spend::settle` flips
                // the reservation row and touches no bucket at all.
                spend::settle(tx, reservation).await
            } else {
                // `org::release` and not `spend::release`, because the gate
                // reserved through `org::reserve` and that charged **two**
                // buckets: the employee's `spend_buckets` row and the team's
                // `team_spend_buckets` row. `Authorized::reservation`'s
                // contract has said `org::release` since it was written and
                // this line said `spend::release`, so a payment the provider
                // refused gave the seat its headroom back and left the charge
                // on the team until midnight.
                //
                // That is the half that costs, because the team row is shared:
                // one seat's provider outage refuses *every* seat on the team
                // with `team_daily_limit`, for a day, with no money moved.
                // `a_failed_payment_gives_the_team_its_headroom_back_too` is
                // the test, and the one beside it could not see this because
                // its fixture seats nobody on a team.
                //
                // `org::release` calls `spend::release` first, so the employee
                // half is byte-for-byte what it was; an employee on no team is
                // exactly the old behaviour.
                org::release(tx, reservation).await
            };
            settled.map_err(EffectError::Unavailable)?;
        }

        let mut payload = Map::new();
        payload.insert(
            "effect".to_owned(),
            json!(ok.action().to_action().kind().as_str()),
        );
        match outcome {
            Ok(_) => {
                payload.insert("outcome".to_owned(), json!("ok"));
            }
            Err(err) => {
                payload.insert("outcome".to_owned(), json!("error"));
                payload.insert("error".to_owned(), json!(err.code()));
                payload.insert("retryable".to_owned(), json!(err.is_retryable()));
            }
        }
        if let Some(detail) = detail {
            payload.insert("detail".to_owned(), detail);
        }

        let event = AuditEvent {
            employee_id: Some(self.principal.employee_id),
            // The link the whole trail exists for: this effect, and the ruling
            // that permitted it.
            decision_id: Some(ok.decision_id()),
            payload: Value::Object(payload),
            ..AuditEvent::new(
                self.principal.actor.clone(),
                AuditKind::ProviderCallAttempted,
                now,
            )
        };
        audit::append(tx, &event)
            .await
            .map(drop)
            .map_err(EffectError::Unavailable)
    }
}

/// Whether a URL's host sits inside the authorised domain. `None` (an IP
/// literal, a `file://` URL) is never inside anything.
fn within(host: Option<&str>, allowed: &Domain) -> bool {
    host.and_then(|host| Domain::parse(host).ok())
        .is_some_and(|host| host.is_within(allowed))
}

/// An import error, as the thing that will be handed back to a model.
///
/// Three of the four variants are decided before any write and the fourth is
/// the database saying no, so the split is between "you asked for something
/// this schema does not have" and "we could not reach the tables".
/// [`crate::prospects::ImportError::Header`] cannot arise here — there is no
/// header on a page — and is folded in with the segment for the same reason a
/// wrong country is: the caller named something the store will not take.
fn discovery_error(err: crate::prospects::ImportError) -> EffectError {
    use crate::prospects::ImportError;
    match err {
        ImportError::Store(RevenueError::Store(err)) => EffectError::Unavailable(err),
        // `upsert_contact` answers `Upserted::Suppressed` rather than raising,
        // so this is the trigger underneath it firing on something else.
        ImportError::Store(other) => {
            EffectError::Unavailable(StoreError::conflict(other.to_string()))
        }
        ImportError::Header(_) | ImportError::Segment(_) | ImportError::Country(_) => {
            EffectError::Refused(BAD_SEGMENT)
        }
    }
}

/// A proposed selector as the store takes it. One place, so the five bindings
/// in [`Effects::read_form`] cannot each spell it differently.
fn sel(selector: &crate::flow_proposal::Selector) -> &str {
    selector.as_str()
}

/// The payload detail every message-shaped effect shares.
fn message_detail(sent: &Result<ProviderMessageId, EffectError>) -> Option<Value> {
    sent.as_ref()
        .ok()
        .map(|id| json!({ "provider_message_id": id.as_str() }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::num::NonZeroU32;
    use std::sync::Mutex;

    use agentos_domain::action::{ActionKind, CallingCode, Channel};
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::message::CanonicalMessage;
    use agentos_domain::money::Currency;
    use agentos_domain::policy::{DenyReason, PolicyLimits, SpendLimits};
    use agentos_providers::browser::MockBrowser;
    use agentos_providers::email::MockEmailProvider;
    use agentos_providers::leads::MockLeadSink;
    use agentos_providers::telephony::{
        InboundCtx, MockTelephony, ParseError, Region, SigError, WebhookBody,
    };
    use agentos_providers::{EnsureCtx, FaultMode, ProviderBinding, Provisioned};
    use agentos_store::org;
    use agentos_store::spend::SpendCaps;
    use chrono::{SubsecRound, TimeDelta};
    use url::Url;
    use uuid::Uuid;

    use super::*;
    use crate::gate::{Denied, PolicyGate};

    // -- test doubles for the two ports that have no adapter ---------------

    struct StubMcp;

    #[async_trait]
    impl McpCaller for StubMcp {
        async fn call(
            &self,
            _tool: &McpTool,
            _arguments: &Value,
        ) -> Result<Untrusted<Value>, ProviderError> {
            Ok(Untrusted::new(json!({ "ok": true })))
        }
    }

    /// Pays, or refuses with whatever it was told to refuse with. Keeps every
    /// idempotency key it was handed, so the de-duplication token can be
    /// asserted on.
    #[derive(Default)]
    struct MockPayments {
        fault: Option<ProviderError>,
        keys: Mutex<Vec<String>>,
        /// Every payee the port was handed. There is no way for a caller to
        /// put one in here that the gate did not rule on, and that is the
        /// claim `the_payee_the_provider_sees_is_the_one_on_the_token` makes
        /// against a running database rather than against this doc comment.
        payees: Mutex<Vec<String>>,
    }

    impl MockPayments {
        fn healthy() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn broken(err: ProviderError) -> Arc<Self> {
            Arc::new(Self {
                fault: Some(err),
                ..Self::default()
            })
        }

        fn keys(&self) -> Vec<String> {
            self.keys.lock().expect("poisoned").clone()
        }

        fn payees(&self) -> Vec<String> {
            self.payees.lock().expect("poisoned").clone()
        }
    }

    #[async_trait]
    impl PaymentProvider for MockPayments {
        async fn pay(
            &self,
            key: &IdempotencyKey,
            _amount: Money,
            instruction: &PaymentInstruction,
        ) -> Result<ProviderMessageId, ProviderError> {
            self.keys
                .lock()
                .expect("poisoned")
                .push(key.as_str().to_owned());
            self.payees
                .lock()
                .expect("poisoned")
                .push(instruction.payee.clone());
            match &self.fault {
                Some(err) => Err(err.clone()),
                None => Ok(ProviderMessageId::new("pay_0001")),
            }
        }
    }

    // -- fixtures ----------------------------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; effects tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant, one active employee, and generous ledger caps.
    async fn seed(db: &Db) -> Principal {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("fx-{}", employee.as_uuid().simple());
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
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        spend::set_caps(
            &mut tx,
            employee,
            SpendCaps::new(
                Money::new(100_000, Currency::Eur).expect("nonzero"),
                Money::new(50_000, Currency::Eur).expect("nonzero"),
                NonZeroU32::new(10).expect("nonzero"),
            )
            .expect("coherent"),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit caps");

        // The policy the gate will read: email, `portal.example.com`, and a
        // small budget. It is a row, not a constructor argument — the gate
        // loads the four layers per decision.
        install_policy(db, tenant, &["portal.example.com"], BTreeSet::new()).await;

        Principal::employee(tenant, employee)
    }

    /// The tenant layer, with exactly the hosts a test wants written to and
    /// exactly the ones it wants blocked.
    ///
    /// A function rather than a literal in `seed` because the redirect tests
    /// need three different shapes of the same policy: the partner granted, the
    /// partner not granted, and the partner denied.
    async fn install_policy(db: &Db, tenant: TenantId, allowed: &[&str], denied: BTreeSet<Domain>) {
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                spend: Some(
                    SpendLimits::try_new(
                        Money::new(25_000, Currency::Eur).expect("nonzero"),
                        Money::new(30_000, Currency::Eur).expect("nonzero"),
                        Money::new(20_000, Currency::Eur).expect("nonzero"),
                    )
                    .expect("coherent"),
                ),
                // `Channel::Web` because this fixture browses. It used to be
                // enough to name the domain; browsing is a channel now, and a
                // policy that grants a host without granting the channel grants
                // nothing — which is what the browser tests below discovered
                // one `ChannelNotAllowed` at a time.
                // `Channel::Voice` and the calling code below because this
                // fixture now dials, and a policy that grants one without the
                // other grants nothing: `evaluate`'s `CallPlace` arm asks the
                // channel *and* the prefix, which is the whole of what makes
                // voice the strictest outbound channel in this file.
                //
                // Widening a shared fixture is normally how a test starts
                // passing for the wrong reason, and here it cannot: no other
                // test in this module authorises a phone-shaped action, so
                // `Voice` and `+1` are read by exactly one of them. What it is
                // **not** is a claim about a real deployment —
                // `store::policy::default_ceiling` grants neither, layers only
                // narrow, and this database has no platform layer at all. See
                // `turn::UNSERVED`'s `CallPlace` entry.
                // `Channel::Sms` joins them for the write-ahead tests below, on
                // the same argument `Voice` makes one paragraph up — but not on
                // the sentence that used to be written here, which claimed
                // `SmsSend` "appears in exactly two places in this crate" and is
                // false. The token is in `gate`, `turn`, `provisioning` and
                // three rolepacks as `Action::SmsSend` / `ActionKind::SmsSend`,
                // and the subject type of that name is in this module's own docs
                // and in the tests below on top of the two it named.
                //
                // The claim that does hold is narrower and is the one the
                // widening actually rests on: `Channel::Sms` is read in exactly
                // two places in `domain::policy` — `always_denies`'
                // `ActionKind::SmsSend` arm and `evaluate`'s `Action::SmsSend`
                // arm — and nowhere else, so this entry cannot loosen a ruling
                // on any other verb, whatever else spells the name. Within this
                // test module the only SMS-shaped actions are the ones the
                // write-ahead tests authorise. `evaluate`'s arm asks the channel
                // *and* the calling code, so the `+1` below is load-bearing for
                // it too.
                allowed_channels: BTreeSet::from([
                    Channel::Email,
                    Channel::Web,
                    Channel::Voice,
                    Channel::Sms,
                ]),
                allowed_calling_codes: BTreeSet::from([
                    CallingCode::new(1).expect("+1 is a calling code")
                ]),
                // Still here, and still doing work: reading no longer consults
                // it, but `BrowserWrite` and `FileUpload` do, and the browser
                // tests below authorise writes against exactly this entry.
                allowed_domains: allowed
                    .iter()
                    .map(|host| Domain::parse(host).expect("domain"))
                    .collect(),
                denied_domains: denied,
                max_new_contacts_per_day: 5,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");
    }

    fn gate(db: &Db) -> PolicyGate {
        PolicyGate::new(db.clone())
    }

    /// A second active employee in the same company.
    async fn hire(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let employee = EmployeeId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit hire");
        employee
    }

    /// The org chart `post_work` is bounded by, with one seat of every shape
    /// around the acting employee.
    ///
    /// **All five share one team on purpose.** The rule is the reporting line
    /// and not the team, so a fixture that put the peer somewhere else would
    /// make every refusal below pass for the wrong reason — the same trap
    /// `inbound`'s `department` fixture names.
    ///
    /// ```text
    ///     carla ─(no manager, same team: a peer)
    ///     lena  ─── bruno ─── eve
    ///        the actor    one link   two links
    /// ```
    async fn org_around(db: &Db, principal: &Principal) -> (EmployeeId, EmployeeId, EmployeeId) {
        let tenant = principal.tenant_id;
        let bruno = hire(db, tenant, "bruno").await;
        let carla = hire(db, tenant, "carla").await;
        let eve = hire(db, tenant, "eve").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let team = agentos_store::org::create_team(
            &mut tx,
            &Slug::parse("desk").expect("slug"),
            "The desk",
        )
        .await
        .expect("create team");
        for who in [principal.employee_id, bruno, carla, eve] {
            agentos_store::org::set_member(&mut tx, who, team, None)
                .await
                .expect("join team");
        }
        agentos_store::org::set_position(&mut tx, principal.employee_id, Some("Head"), None)
            .await
            .expect("seat lena");
        agentos_store::org::set_position(
            &mut tx,
            bruno,
            Some("Buyer"),
            Some(principal.employee_id),
        )
        .await
        .expect("seat bruno under lena");
        agentos_store::org::set_position(&mut tx, carla, Some("Head of the other desk"), None)
            .await
            .expect("seat carla beside lena");
        agentos_store::org::set_position(&mut tx, eve, Some("Junior"), Some(bruno))
            .await
            .expect("seat eve under bruno");
        tx.commit().await.expect("commit the org chart");

        (bruno, carla, eve)
    }

    /// The titles waiting on one seat's board, in the board's own order.
    async fn board_of(db: &Db, tenant: TenantId, who: EmployeeId) -> Vec<(String, Option<Uuid>)> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let items = agentos_store::backlog::open_for(&mut tx, who)
            .await
            .expect("read the board");
        tx.rollback().await.expect("rollback");
        items
            .into_iter()
            .map(|item| (item.title, item.posted_by.map(|e| e.as_uuid())))
            .collect()
    }

    fn slug(raw: &str) -> Slug {
        Slug::parse(raw).expect("slug")
    }

    fn ports(email: MockEmailProvider, payments: Arc<MockPayments>) -> Arc<Ports> {
        with_leads(email, payments, Arc::new(MockLeadSink::new()))
    }

    /// The same ports with a lead sink the caller keeps a handle on, for the
    /// `stage_lead` tests: what those assert is what actually reached the
    /// platform, which is unreadable through an `Arc<dyn LeadSink>`.
    fn with_leads(
        email: MockEmailProvider,
        payments: Arc<MockPayments>,
        leads: Arc<MockLeadSink>,
    ) -> Arc<Ports> {
        Arc::new(Ports {
            email: Arc::new(email),
            telephony: Arc::new(MockTelephony::new(Utc::now(), "token")),
            browser: Arc::new(MockBrowser::new()),
            mcp: Arc::new(StubMcp),
            payments,
            leads,
        })
    }

    /// The same, with the browser kept in hand — for the tests that script a
    /// redirect and then ask where the session ended up.
    ///
    /// `leads` is a sink nothing in these tests reaches, and it is here because
    /// `Ports` has no `..Default::default()`: a port added to that struct has to
    /// be answered by every fixture, which is how a build stops when somebody
    /// adds a way to affect the world and a test harness quietly does not.
    fn ports_browsing(browser: Arc<MockBrowser>) -> Arc<Ports> {
        Arc::new(Ports {
            email: Arc::new(MockEmailProvider::new()),
            telephony: Arc::new(MockTelephony::new(Utc::now(), "token")),
            browser,
            mcp: Arc::new(StubMcp),
            payments: MockPayments::healthy(),
            leads: Arc::new(MockLeadSink::new()),
        })
    }

    /// The same ports, with the telephony double left in the **caller's** hand:
    /// the dial test asks it which number actually got rung and
    /// [`ReadsTheLogMidFlight`] is asked what it saw, neither of which the
    /// `Ports` field can answer once the double is behind a `dyn`.
    ///
    /// The parameter is the trait object rather than [`MockTelephony`] because
    /// there are two doubles now; each caller keeps its own concrete `Arc` and
    /// hands a coerced clone in here.
    fn ports_dialling(telephony: Arc<dyn TelephonyProvider>) -> Arc<Ports> {
        Arc::new(Ports {
            email: Arc::new(MockEmailProvider::new()),
            telephony,
            browser: Arc::new(MockBrowser::new()),
            mcp: Arc::new(StubMcp),
            payments: MockPayments::healthy(),
            leads: Arc::new(MockLeadSink::new()),
        })
    }

    fn session_for(principal: &Principal) -> BrowserSession {
        BrowserSession {
            employee_id: principal.employee_id,
            binding: ProviderBinding {
                provider: "mock-browser".to_owned(),
                external_id: "ctx-1".to_owned(),
            },
            user_data_dir: None,
        }
    }

    /// The `employee_resources` row `Effects::browser_session` rebuilds a
    /// session from — the whole of what `read_page` needs, since nothing hands
    /// it a `BrowserSession`.
    async fn provision_browser(db: &Db, principal: &Principal) {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employee_resources \
                 (employee_id, step, tenant_id, state, provider, external_id) \
             VALUES ($1, 'browser', $2, 'ready', 'mock-browser', $3)",
        )
        .bind(principal.employee_id.as_uuid())
        .bind(principal.tenant_id.as_uuid())
        // Unique across employees, per
        // `employee_resources_provider_external_id_key`.
        .bind(format!("ctx-{}", principal.employee_id.as_uuid().simple()))
        .execute(&mut **tx)
        .await
        .expect("insert the browser resource");
        tx.commit().await.expect("commit the browser resource");
    }

    fn body() -> RenderedEmail {
        RenderedEmail {
            from: "lena@acme.example".to_owned(),
            subject: "quote".to_owned(),
            body_text: "please send a quote".to_owned(),
            in_reply_to: None,
        }
    }

    fn to(raw: &str) -> EmailSend {
        EmailSend {
            to: EmailAddress::parse(raw).expect("address"),
        }
    }

    fn euros(minor: u64) -> PaymentCreate {
        euros_to(minor, "acct_supplier")
    }

    fn euros_to(minor: u64, payee: &str) -> PaymentCreate {
        PaymentCreate {
            amount: Money::new(minor, Currency::Eur).expect("nonzero"),
            payee: payee.to_owned(),
        }
    }

    const MEMO: &str = "invoice 42";

    fn billed(minor: u64) -> InvoiceIssue {
        InvoiceIssue {
            amount: Money::new(minor, Currency::Eur).expect("nonzero"),
        }
    }

    fn draft(opportunity_id: Uuid) -> InvoiceDraft {
        InvoiceDraft {
            opportunity_id,
            memo: "March".to_owned(),
            due_at: None,
            lines: Vec::new(),
        }
    }

    /// An account and one opportunity at `stage`, for this principal's company.
    ///
    /// Inserted directly rather than through `agentos_store::revenue`, because
    /// what the invoice tests turn on is the *stage* and a helper that could
    /// only build won deals would make the refusal untestable.
    async fn deal(db: &Db, principal: &Principal, stage: &str) -> Uuid {
        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Buyer plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(principal.tenant_id.as_uuid())
        .bind(format!("buyer-{}.example", account.simple()))
        .execute(&mut **tx)
        .await
        .expect("insert account");
        sqlx::query(
            "INSERT INTO opportunities \
                 (id, tenant_id, account_id, stage, currency, value_minor, approval_id, closed_at) \
             VALUES ($1, $2, $3, $4, 'EUR', 120000, $5, now())",
        )
        .bind(opportunity)
        .bind(principal.tenant_id.as_uuid())
        .bind(account)
        .bind(stage)
        .bind(Uuid::now_v7())
        .execute(&mut **tx)
        .await
        .expect("insert opportunity");
        tx.commit().await.expect("commit the deal");
        opportunity
    }

    async fn won_deal(db: &Db, principal: &Principal) -> Uuid {
        deal(db, principal, "closed_won").await
    }

    async fn open_deal(db: &Db, principal: &Principal) -> Uuid {
        deal(db, principal, "negotiation").await
    }

    /// One `provider_intents` row as the write-ahead tests read it:
    /// `(intent_kind, provider, step, state, external_id, last_error)`.
    ///
    /// `step` is in here and is asserted NULL rather than ignored: it is the
    /// column `store::provisioning::unsettled_calls` filters on to tell a send
    /// apart from a provisioning step, so a send that quietly acquired one would
    /// vanish from the reader while every other assertion stayed green.
    type IntentRow = (
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    );

    /// Every write-ahead row this seat has, oldest first.
    async fn intent_rows(db: &Db, principal: &Principal) -> Vec<IntentRow> {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let rows = sqlx::query_as(
            "SELECT intent_kind, provider, step, state, external_id, last_error \
               FROM provider_intents WHERE employee_id = $1 ORDER BY created_at, id",
        )
        .bind(principal.employee_id.as_uuid())
        .fetch_all(&mut **tx)
        .await
        .expect("read provider_intents");
        tx.commit().await.expect("commit read");
        rows
    }

    /// The reader an operator gets through `GET /v1/employees/{id}`, called
    /// directly. `before` is the caller's grace: a request younger than it is
    /// still in progress, not an ambiguity.
    async fn unsettled(
        db: &Db,
        principal: &Principal,
        before: DateTime<Utc>,
    ) -> Vec<agentos_store::provisioning::UnsettledCall> {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let calls = provisioning::unsettled_calls(&mut tx, principal.employee_id, before)
            .await
            .expect("read unsettled calls");
        tx.commit().await.expect("commit read");
        calls
    }

    /// Every `provider_call_attempted` row: `(decision_id, payload)`.
    async fn effect_rows(db: &Db, principal: &Principal) -> Vec<(Option<Uuid>, Value)> {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let rows = sqlx::query_as(
            "SELECT decision_id, payload FROM audit_log \
              WHERE employee_id = $1 AND action_kind = 'provider_call_attempted' \
              ORDER BY occurred_at, id",
        )
        .bind(principal.employee_id.as_uuid())
        .fetch_all(&mut **tx)
        .await
        .expect("read audit");
        tx.commit().await.expect("commit read");
        rows
    }

    async fn reservation_states(db: &Db, principal: &Principal) -> Vec<String> {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let states =
            sqlx::query_scalar("SELECT state FROM spend_reservations WHERE employee_id = $1")
                .bind(principal.employee_id.as_uuid())
                .fetch_all(&mut **tx)
                .await
                .expect("read reservations");
        tx.commit().await.expect("commit read");
        states
    }

    // -- the tests ---------------------------------------------------------

    /// The compile-time half of this unit is `tests/ui/effects_bare_action.rs`.
    /// This is the runtime half: a subject is exactly one action, its trust is
    /// a property of the type it arrived in, and the two flavours of the same
    /// subject reach the same effect method.
    #[test]
    fn a_subject_is_one_action_and_carries_its_own_trust() {
        let subject = to("supplier@example.com");
        assert_eq!(
            subject.to_action(),
            Action::EmailSend {
                to: EmailAddress::parse("supplier@example.com").expect("address")
            }
        );
        assert_eq!(subject.trust(), TrustLabel::Trusted);

        let tainted = Untrusted::new(subject.clone());
        assert_eq!(tainted.trust(), TrustLabel::Untrusted);
        assert_eq!(tainted.to_action(), subject.to_action());
        assert_eq!(tainted.subject(), &subject, "same effect, same recipient");

        // A payment is a different subject type, so a token for one can never
        // be spent on the other — see the compile-fail case.
        assert_eq!(euros(100).to_action().kind(), ActionKind::PaymentCreate);
    }

    /// A staged lead is an email, so it leaves the same trail an email leaves —
    /// and a row that names somebody other than the person the gate ruled on is
    /// refused rather than reconciled.
    ///
    /// The mismatch is unreachable through `crate::queue`, whose `Lead` builds
    /// both spellings off one `Recipient`. It is checked here because the two
    /// are separated by a gate call and a crate boundary, and because the
    /// failure it prevents — the platform mailing a different person from the
    /// one in the audit row — is unrecoverable and silent.
    #[tokio::test]
    async fn a_staged_lead_is_ruled_on_by_address_and_refused_when_they_disagree() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let gate = gate(&db);
        let leads = Arc::new(MockLeadSink::new());
        let effects = Effects::new(
            db.clone(),
            with_leads(
                MockEmailProvider::new(),
                MockPayments::healthy(),
                leads.clone(),
            ),
            principal.clone(),
        );

        // The happy path: the row agrees with the token.
        let ok = gate
            .authorize(&principal, to("buyer@example.com"))
            .await
            .expect("email is allowed");
        let staged = effects
            .stage_lead(ok, &[("email", "buyer@example.com"), ("objet_email", "s")])
            .await
            .expect("staged");
        assert_eq!(leads.staged_addresses(), ["buyer@example.com"]);

        // One `provider_call_attempted` row, tied to the ruling that allowed it
        // — the same trail `send_email` leaves, because it is the same act.
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1["effect"], json!("email_send"));
        assert_eq!(rows[0].1["outcome"], json!("ok"));
        assert_eq!(
            rows[0].1["detail"]["provider_message_id"],
            json!(staged.as_str())
        );

        // And the mismatch: ruled on one person, row names another.
        let ok = gate
            .authorize(&principal, to("buyer@example.com"))
            .await
            .expect("email is allowed");
        let err = effects
            .stage_lead(ok, &[("email", "someone.else@example.com")])
            .await
            .expect_err("a row that names somebody the gate did not rule on");
        assert_eq!(err.code(), LEAD_NOT_THE_RULED_ADDRESS);
        assert_eq!(
            leads.staged_addresses(),
            ["buyer@example.com"],
            "and nobody new reached the platform"
        );
    }

    /// The seam, and the two things that can only go wrong at it.
    ///
    /// `OutboundCall` has two `E164` fields, and this method is the only place
    /// in the workspace where they are filled in from two different sources —
    /// one off the token, one off the argument. A swap type-checks, returns
    /// `Ok`, writes a perfectly ordinary audit row, and rings the employee's
    /// own desk from the stranger's number. Nothing but this assertion is
    /// between that and production.
    ///
    /// The second half is the number the gate refuses. `+33…` is outside the
    /// fixture's `allowed_calling_codes`, so it is denied for a reason no other
    /// channel has — and the assertion that matters is not the `Denied`, it is
    /// that the double's dial log did not grow.
    #[tokio::test]
    async fn the_number_dialled_is_the_number_the_gate_ruled_on() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let gate = gate(&db);
        let phone = Arc::new(MockTelephony::new(Utc::now(), "token"));
        let effects = Effects::new(db.clone(), ports_dialling(phone.clone()), principal.clone());

        let mine = E164::parse("+15005550006").expect("e164");
        let theirs = E164::parse("+14158675309").expect("e164");
        let ok = gate
            .authorize(&principal, CallPlace { to: theirs.clone() })
            .await
            .expect("voice and +1 are both granted by the fixture policy");
        let placed = effects
            .place_call(ok, mine.clone())
            .await
            .expect("the carrier took it");

        // The assembly, read off the provider rather than off our own hopes.
        assert_eq!(
            phone.dialled(),
            [OutboundCall {
                from: mine.clone(),
                to: theirs
            }],
            "the numbers are the token's `to` and the caller's `from`, in that order"
        );

        // And the row an operator reads afterwards. `ok` here means the carrier
        // agreed to dial and nothing more — no field of this row can say
        // whether anybody picked up, which is `place_call`'s whole caveat.
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1["effect"], json!("call_place"));
        assert_eq!(rows[0].1["outcome"], json!("ok"));
        assert_eq!(
            rows[0].1["detail"]["provider_message_id"],
            json!(placed.as_str())
        );

        // A number outside the granted calling codes: refused before any
        // adapter is troubled, which is the half a `Denied` alone would not
        // prove.
        let elsewhere = gate
            .authorize(
                &principal,
                CallPlace {
                    to: E164::parse("+33123456789").expect("e164"),
                },
            )
            .await;
        assert!(
            matches!(
                elsewhere,
                Err(Denied::Policy(DenyReason::CallingCodeNotAllowed))
            ),
            "a calling code nobody granted must not be dialable: {elsewhere:?}"
        );
        assert_eq!(phone.dialled().len(), 1, "the refused number rang anyway");
    }

    /// **The seat the window belongs to.**
    ///
    /// `last_inbound_whatsapp_at`'s own boundary and channel seams are proved
    /// in `inbound`, against the ingest that writes the rows. What is only
    /// provable here is the plumbing: that this method asks about *this*
    /// principal's employee, in *this* principal's tenant. A wrong id there
    /// returns `None` forever and nothing complains — the window is simply
    /// never open, and the symptom is an employee that can never reply.
    ///
    /// So the two halves are both asserted, and the second is the one that
    /// catches it: `None` before the message, `Some` after. `None` alone is the
    /// answer a completely disconnected method would also give.
    #[tokio::test]
    async fn the_window_this_employee_holds_is_read_for_this_employee() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );

        // A sender no other run has used: `(provider, external_id)` is unique
        // across the whole table and these rows are left behind.
        let sender = E164::parse(&format!(
            "+33{:012}",
            Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .unsigned_abs()
                % 1_000_000_000_000
        ))
        .expect("e164");
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employee_resources \
                 (employee_id, step, tenant_id, state, provider, external_id) \
             VALUES ($1, 'whatsapp', $2, 'ready', 'twilio', $3)",
        )
        .bind(principal.employee_id.as_uuid())
        .bind(principal.tenant_id.as_uuid())
        .bind(sender.as_str())
        .execute(&mut *tx)
        .await
        .expect("allocate the whatsapp sender");
        tx.commit().await.expect("commit allocation");

        let them = E164::parse("+33612345678").expect("e164");
        assert!(
            effects
                .whatsapp_window(&them)
                .await
                .expect("the read succeeds")
                .is_none(),
            "a number that has never written to us has no window"
        );

        // One inbound message, through the ingest that writes the row rather
        // than by hand — the shape of that row is what the query reads.
        let telephony = MockTelephony::new(Utc::now(), "token");
        // Microsecond-truncated: `timestamptz` keeps six digits, Linux's clock
        // offers nine, and macOS's often offers six — so a round-trip
        // comparison passes on a developer's machine and goes red on CI. Third
        // time this repository has paid that; `inbound.rs` and `prospects.rs`
        // carry the same line for the same reason.
        let landed_at = Utc::now().trunc_subsecs(6);
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("MessageSid", "WA_effects")
            .append_pair("From", &format!("whatsapp:{}", them.as_str()))
            .append_pair("To", &format!("whatsapp:{}", sender.as_str()))
            .append_pair("Body", "bonjour")
            .finish()
            .into_bytes();
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        crate::inbound::land_inbound_text(&mut tx, &telephony, &form, landed_at)
            .await
            .expect("the message lands on this employee");
        tx.commit().await.expect("commit the landing");

        let window = effects
            .whatsapp_window(&them)
            .await
            .expect("the read succeeds")
            .expect("they wrote to us a moment ago");
        assert_eq!(
            window.expires_at(),
            landed_at + OpenWindow::DURATION,
            "the expiry is 24h from their message, not from now"
        );

        // And it is theirs alone: another number on the same sender has none.
        assert!(
            effects
                .whatsapp_window(&E164::parse("+33698675309").expect("e164"))
                .await
                .expect("the read succeeds")
                .is_none(),
            "one counterparty's message opened a window for another"
        );

        // **The clock is the wall clock, and this is the only assertion that
        // says so.** This method takes no `now` — it reads `Utc::now()` — so a
        // version that compared the message against *itself* would report every
        // window open forever, and every assertion above would still pass:
        // they all turn on whether a message exists at all. Somebody who wrote
        // 25 hours ago is the case that tells the two apart.
        let stale = E164::parse("+33755500001").expect("e164");
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("MessageSid", "WA_effects_stale")
            .append_pair("From", &format!("whatsapp:{}", stale.as_str()))
            .append_pair("To", &format!("whatsapp:{}", sender.as_str()))
            .append_pair("Body", "hier")
            .finish()
            .into_bytes();
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        crate::inbound::land_inbound_text(
            &mut tx,
            &telephony,
            &form,
            landed_at - OpenWindow::DURATION - chrono::TimeDelta::hours(1),
        )
        .await
        .expect("the old message lands");
        tx.commit().await.expect("commit the old landing");

        assert!(
            effects
                .whatsapp_window(&stale)
                .await
                .expect("the read succeeds")
                .is_none(),
            "a message from 25 hours ago left the window open"
        );
    }

    /// A number the fixture policy grants, for the three write-ahead tests.
    fn a_number() -> E164 {
        E164::parse("+14158675309").expect("e164")
    }

    fn a_text(body: &str) -> RenderedSms {
        RenderedSms {
            from: E164::parse("+15005550006").expect("e164"),
            body: body.to_owned(),
        }
    }

    /// A telephony port that answers a send only after looking at
    /// `provider_intents` **from a second connection**.
    ///
    /// The second connection is the whole mechanism. An `INSERT` that has not
    /// committed is invisible outside its own transaction, so every row this
    /// records is a row that was already durable at the instant the provider was
    /// called — which is the one question the other two write-ahead tests cannot
    /// ask, because by the time they read, both writes have happened.
    ///
    /// ponytail: this rather than a port that blocks with a
    /// `tokio::time::timeout` wrapped round the send. That buys the same
    /// assertion with a wall clock — a duration to pick, and a loaded CI box to
    /// be wrong on. Nothing here waits for anything.
    ///
    /// Every other method is `unimplemented!` on purpose: this is not a second
    /// [`MockTelephony`] and nothing should grow into using it as one.
    struct ReadsTheLogMidFlight {
        db: Db,
        tenant: TenantId,
        /// `(state, external_id)` of every send row visible from outside, as of
        /// the moment the provider held the request.
        seen: Mutex<Vec<(String, Option<String>)>>,
    }

    #[async_trait]
    impl TelephonyProvider for ReadsTheLogMidFlight {
        async fn send_sms(
            &self,
            _key: &IdempotencyKey,
            _sms: &OutboundSms,
        ) -> Result<ProviderMessageId, ProviderError> {
            let mut tx = self
                .db
                .tenant_tx(self.tenant)
                .await
                .expect("a second connection while the send is in flight");
            let rows = sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT state, external_id FROM provider_intents \
                  WHERE step IS NULL ORDER BY created_at",
            )
            .fetch_all(&mut **tx)
            .await
            .expect("read provider_intents from outside the send");
            tx.rollback().await.expect("rollback the read");
            *self.seen.lock().expect("seen mutex poisoned") = rows;
            Ok(ProviderMessageId::new("SM-observed"))
        }

        async fn ensure_number(
            &self,
            _ctx: &EnsureCtx,
            _region: &Region,
        ) -> Result<Provisioned, ProviderError> {
            unimplemented!("this double only sends texts")
        }

        async fn release(&self, _binding: &ProviderBinding) -> Result<(), ProviderError> {
            unimplemented!("this double only sends texts")
        }

        async fn send_whatsapp(
            &self,
            _key: &IdempotencyKey,
            _message: &OutboundWhatsapp,
        ) -> Result<ProviderMessageId, ProviderError> {
            unimplemented!("this double only sends texts")
        }

        async fn place_call(
            &self,
            _key: &IdempotencyKey,
            _call: &OutboundCall,
        ) -> Result<ProviderMessageId, ProviderError> {
            unimplemented!("this double only sends texts")
        }

        fn verify_webhook(
            &self,
            _url: &str,
            _body: WebhookBody<'_>,
            _headers: &[(String, String)],
        ) -> Result<(), SigError> {
            unimplemented!("this double only sends texts")
        }

        fn normalize(
            &self,
            _ctx: &InboundCtx,
            _raw: &[u8],
        ) -> Result<CanonicalMessage, ParseError> {
            unimplemented!("this double only sends texts")
        }
    }

    /// **The order of the two commits, observed while the request is in
    /// flight.** This is the property the whole fence *is*, and the one the two
    /// tests below do not pin.
    ///
    /// They read `provider_intents` after `send_sms` has returned. From there a
    /// row written before the provider call and a row written after it look
    /// identical — so a refactor that folded [`Effects::begin_send`] and
    /// [`Effects::record_sent`] into one transaction wrapped around the call
    /// would keep every one of their assertions green and delete the entire
    /// guarantee. There is nothing left of this feature except the order: a
    /// process that dies with the request on the wire leaves something behind
    /// **only** if the row committed first.
    ///
    /// So the observation happens from inside the provider call, on a second
    /// connection, where an uncommitted insert cannot be seen.
    ///
    /// # What it asserts, and the two ways of being wrong it separates
    ///
    /// Not just "a row exists". `in_flight` *and* no `external_id`: a fence
    /// that committed the row early and already claimed an id it had not been
    /// given would be the other way of lying, and one assertion on presence
    /// alone would admit it. The settled row is then checked after the call
    /// returns, so what was seen mid-flight is established as a **window** and
    /// not as a state the row never leaves — a build that never settled
    /// anything would pass the first half and turn the operator's reader into a
    /// log of every message ever sent.
    #[tokio::test]
    async fn the_write_ahead_row_is_committed_before_the_request_leaves() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let phone = Arc::new(ReadsTheLogMidFlight {
            db: db.clone(),
            tenant: principal.tenant_id,
            seen: Mutex::new(Vec::new()),
        });
        let effects = Effects::new(db.clone(), ports_dialling(phone.clone()), principal.clone());

        let ok = gate(&db)
            .authorize(&principal, SmsSend { to: a_number() })
            .await
            .expect("sms and +1 are both granted by the fixture policy");
        let sent = effects
            .send_sms(ok, a_text("your delivery is late"))
            .await
            .expect("the port answered");

        let mid_flight = phone.seen.lock().expect("seen mutex poisoned").clone();
        assert_eq!(
            mid_flight.len(),
            1,
            "nothing was visible from a second connection while the provider held \
             the request: the write-ahead row did not commit before the send"
        );
        assert_eq!(
            mid_flight[0].0, "in_flight",
            "the row was committed early and already settled, which is a claim \
             about an answer nobody had yet"
        );
        assert_eq!(
            mid_flight[0].1, None,
            "an external id the provider had not handed back yet"
        );

        // And the same row is closed by the time the call returns, so what was
        // observed above is a window and not where the row lives.
        let rows = intent_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1, "one request, one row: {rows:?}");
        assert_eq!(rows[0].3, "succeeded");
        assert_eq!(rows[0].4.as_deref(), Some(sent.as_str()));
    }

    /// **The crash window, fabricated.** The request reaches the provider and
    /// the answer never comes back.
    ///
    /// `FaultMode::FailAfterExternalSuccess` is this workspace's own word for
    /// exactly that shape — the double records the send and *then* fails — and
    /// `ProviderError::Retryable` is the variant `TwilioTelephony` produces for a
    /// read timeout, whose own documentation says *"the request may even have
    /// landed"*. So the error under test is the production one and not a
    /// test-only stand-in.
    ///
    /// # What is asserted, and the sentence that is deliberately not asserted
    ///
    /// Not "the customer was not texted twice". Nothing in this system can say
    /// that: Twilio's Messages API takes no idempotency key, the retry after a
    /// crashed turn arrives under a fresh Policy Gate ruling and therefore a
    /// fresh key, and there is no query that would settle it.
    ///
    /// What is asserted is that the send **left something behind**: a row whose
    /// state is the honest one, still `in_flight` after the call returned,
    /// carrying no external id it never received — and a reader that hands it to
    /// a person once the grace has run out. Before this, a text that may or may
    /// not have gone out left one retryable error nobody was reading.
    #[tokio::test]
    async fn a_send_whose_answer_never_came_back_is_left_on_the_record() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let phone = Arc::new(MockTelephony::new(Utc::now(), "token").with_fault(
            FaultMode::FailAfterExternalSuccess(ProviderError::Retryable {
                after: std::time::Duration::from_secs(1),
            }),
        ));
        let effects = Effects::new(db.clone(), ports_dialling(phone.clone()), principal.clone());

        let ok = gate(&db)
            .authorize(&principal, SmsSend { to: a_number() })
            .await
            .expect("sms and +1 are both granted by the fixture policy");
        let err = effects
            .send_sms(ok, a_text("your delivery is late"))
            .await
            .expect_err("the answer never came back");
        // The exact classification and not `is_err()`: an `Unavailable` from the
        // write-ahead commit is also an error, and it would mean the request
        // never left — the opposite of the case being fabricated.
        assert_eq!(err.code(), "retryable");

        let rows = intent_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1, "one request, one row: {rows:?}");
        let (kind, provider, step, state, external_id, last_error) = &rows[0];
        assert_eq!(kind, "sms_send");
        assert_eq!(provider, "telephony");
        assert_eq!(step.as_deref(), None, "a send is not a provisioning step");
        assert_eq!(
            state, "in_flight",
            "a timeout is not a failure; the row must keep saying we do not know"
        );
        assert_eq!(external_id.as_deref(), None);
        assert_eq!(
            last_error.as_deref(),
            None,
            "there is no error to quote: the provider never said anything"
        );

        // The grace, crossed in both directions off the same row. A request that
        // is merely in progress must not page anybody, and the same request must
        // once its answer is overdue — a reader that always answered the same
        // way would satisfy exactly one of these.
        let now = Utc::now();
        assert!(
            unsettled(&db, &principal, now - TimeDelta::hours(1))
                .await
                .is_empty(),
            "a send younger than the grace is in progress, not an ambiguity"
        );
        let waiting = unsettled(&db, &principal, now + TimeDelta::hours(1)).await;
        assert_eq!(waiting.len(), 1, "{waiting:?}");
        assert_eq!(waiting[0].intent_kind, "sms_send");
        assert_eq!(waiting[0].provider, "telephony");
        // The key spells out the ruling, which is the join to the audit row that
        // names the recipient. Nobody can settle a text without knowing who it
        // was to.
        let decision = effect_rows(&db, &principal).await[0]
            .0
            .expect("the effect row carries its ruling");
        assert!(
            waiting[0].idempotency_key.ends_with(&decision.to_string()),
            "the key must lead back to the ruling: {}",
            waiting[0].idempotency_key
        );
    }

    /// The other half, and the one that keeps the reader worth reading: a
    /// provider that **answered** settles its row and asks for nobody.
    ///
    /// Both answers are here because they are one decision seen from two sides.
    /// A build that left every send `in_flight` would pass the test above and
    /// turn `unsettled_calls` into a log of every message ever sent, which is
    /// the state in which a person stops opening it — and then the one row that
    /// mattered is in there too, unread.
    ///
    /// All three answers a provider can give are here, because they are one
    /// decision seen from three sides:
    ///
    /// * `Ok` — the id is recorded, which is what a person reconciles against.
    /// * `Terminal` (`empty_body`) — a request that reached the provider and
    ///   produced nothing. Settled `failed`, with the provider's own code
    ///   quoted, because that much is knowable.
    /// * `RateLimited` — a `429`, which is **also an answer** and the arm most
    ///   worth pinning: it is retryable, so the lazy reading files it with the
    ///   timeout and leaves the row open. It is not the same thing. The provider
    ///   read the request and declined to act on it; nothing was sent, nobody
    ///   needs to look, and a throttled hour would otherwise fill this reader
    ///   with rows that are not ambiguous at all.
    #[tokio::test]
    async fn a_provider_that_answered_settles_its_row_and_asks_for_nobody() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let phone = Arc::new(MockTelephony::new(Utc::now(), "token"));
        let effects = Effects::new(db.clone(), ports_dialling(phone.clone()), principal.clone());
        let gate = gate(&db);

        let ok = gate
            .authorize(&principal, SmsSend { to: a_number() })
            .await
            .expect("sms is allowed");
        let sent = effects
            .send_sms(ok, a_text("we are on our way"))
            .await
            .expect("the provider took it");

        let ok = gate
            .authorize(&principal, SmsSend { to: a_number() })
            .await
            .expect("sms is allowed");
        let err = effects
            .send_sms(ok, a_text(""))
            .await
            .expect_err("the provider refuses an empty body");
        assert_eq!(err.code(), "empty_body");

        // The same seat, a throttled provider. `FailBefore` is a refusal that
        // arrives before the double touches anything, which is the shape of a
        // `429`.
        let throttled = Arc::new(MockTelephony::new(Utc::now(), "token").with_fault(
            FaultMode::FailBefore(ProviderError::RateLimited {
                retry_after: std::time::Duration::from_secs(30),
            }),
        ));
        let effects = Effects::new(db.clone(), ports_dialling(throttled), principal.clone());
        let ok = gate
            .authorize(&principal, SmsSend { to: a_number() })
            .await
            .expect("sms is allowed");
        let err = effects
            .send_sms(ok, a_text("still on our way"))
            .await
            .expect_err("the provider is throttling us");
        assert_eq!(err.code(), "rate_limited");
        assert!(
            err.is_retryable(),
            "a 429 stays retryable to the caller; that is not the same question \
             as whether the row is ambiguous"
        );

        let rows = intent_rows(&db, &principal).await;
        assert_eq!(rows.len(), 3, "three rulings, three rows: {rows:?}");
        assert_eq!(rows[0].3, "succeeded");
        assert_eq!(
            rows[0].4.as_deref(),
            Some(sent.as_str()),
            "the id the provider handed back is what a person reconciles against"
        );
        assert_eq!(rows[1].3, "failed");
        assert_eq!(rows[1].5.as_deref(), Some("empty_body"));
        assert_eq!(rows[2].3, "failed");
        assert_eq!(rows[2].5.as_deref(), Some("rate_limited"));

        // With the grace opened as wide as it goes, neither is an ambiguity.
        assert!(
            unsettled(&db, &principal, Utc::now() + TimeDelta::hours(1))
                .await
                .is_empty(),
            "an answered request is not somebody's morning, whichever answer it was"
        );
    }

    #[test]
    fn a_navigation_outside_the_authorised_domain_is_not_within_it() {
        let allowed = Domain::parse("portal.example.com").expect("domain");
        assert!(within(Some("portal.example.com"), &allowed));
        assert!(within(Some("login.portal.example.com"), &allowed));
        // The classic near-miss, and the two non-hosts.
        assert!(!within(Some("evilportal.example.com"), &allowed));
        assert!(!within(Some("203.0.113.9"), &allowed));
        assert!(!within(None, &allowed));
    }

    #[test]
    fn a_failure_keeps_the_provider_classification() {
        let rate_limited = EffectError::Provider(ProviderError::from_status(429, None));
        assert_eq!(rate_limited.code(), "rate_limited");
        assert!(rate_limited.is_retryable());

        let terminal = EffectError::Provider(ProviderError::from_status(400, None));
        assert_eq!(terminal.code(), "bad_request");
        assert!(!terminal.is_retryable());

        let scope = EffectError::OutOfScope(Domain::parse("a.example.com").expect("domain"));
        assert_eq!(scope.code(), "out_of_scope");
        assert!(!scope.is_retryable());
    }

    #[tokio::test]
    async fn a_sent_email_is_recorded_against_the_decision_that_authorised_it() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );

        let token = gate(&db)
            .authorize(&principal, to("supplier@example.com"))
            .await
            .expect("email is allowed");
        let decision_id = token.decision_id();

        let id = effects
            .send_email(token, body())
            .await
            .expect("the mock sends");

        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1, "one row per attempt");
        assert_eq!(
            rows[0].0,
            Some(decision_id.as_uuid()),
            "the row points at the ruling that permitted it"
        );
        assert_eq!(rows[0].1["outcome"], json!("ok"));
        assert_eq!(rows[0].1["effect"], json!("email_send"));
        assert_eq!(
            rows[0].1["detail"]["provider_message_id"],
            json!(id.as_str())
        );
    }

    #[tokio::test]
    async fn a_provider_failure_is_classified_and_recorded_not_swallowed() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        // A 429: the provider is fine, we were throttled.
        let throttled = MockEmailProvider::with_fault(FaultMode::FailBefore(
            ProviderError::from_status(429, None),
        ));
        let effects = Effects::new(
            db.clone(),
            ports(throttled, MockPayments::healthy()),
            principal.clone(),
        );

        let token = gate(&db)
            .authorize(&principal, to("supplier@example.com"))
            .await
            .expect("email is allowed");
        let decision_id = token.decision_id();

        let err = effects
            .send_email(token, body())
            .await
            .expect_err("the provider refused");
        assert_eq!(err.code(), "rate_limited");
        assert!(err.is_retryable(), "a 429 is worth retrying");

        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1, "a failed effect is recorded too");
        assert_eq!(rows[0].0, Some(decision_id.as_uuid()));
        assert_eq!(rows[0].1["outcome"], json!("error"));
        assert_eq!(rows[0].1["error"], json!("rate_limited"));
        assert_eq!(rows[0].1["retryable"], json!(true));
    }

    #[tokio::test]
    async fn a_payment_settles_on_success() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let payments = MockPayments::healthy();
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), payments.clone()),
            principal.clone(),
        );

        let token = gate(&db)
            .authorize(
                &principal,
                euros_to(15_000, "acct_the_one_that_was_ruled_on"),
            )
            .await
            .expect("under every cap");
        assert!(token.reservation().is_some(), "the gate reserved");
        let decision_id = token.decision_id();

        effects.pay(token, MEMO).await.expect("the mock pays");
        assert_eq!(
            reservation_states(&db, &principal).await,
            vec!["settled".to_owned()]
        );

        // **The payee the provider was handed is the payee the gate ruled on**,
        // and it is not a comparison this method makes — `pay` reads it off the
        // token and there is no argument for a caller to pass a different one.
        // The audit row says the same thing, so "what left the building" and
        // "what an operator can later read" cannot come apart either.
        assert_eq!(
            payments.payees(),
            vec!["acct_the_one_that_was_ruled_on".to_owned()]
        );
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(
            rows[0].1["detail"]["payee"],
            json!("acct_the_one_that_was_ruled_on")
        );
        assert_eq!(rows[0].1["detail"]["memo"], json!(MEMO));

        // The de-duplication token is the decision: a retry of *this* payment
        // hits the provider's idempotency cache instead of paying twice.
        let key = payments.keys().pop().expect("the provider saw a key");
        assert!(key.contains(&decision_id.as_uuid().to_string()), "{key}");
    }

    #[tokio::test]
    async fn a_failed_payment_gives_the_headroom_back() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let effects = Effects::new(
            db.clone(),
            ports(
                MockEmailProvider::new(),
                MockPayments::broken(ProviderError::from_status(400, None)),
            ),
            principal.clone(),
        );

        let token = gate(&db)
            .authorize(&principal, euros(15_000))
            .await
            .expect("under every cap");

        let err = effects
            .pay(token, MEMO)
            .await
            .expect_err("the payment provider refused");
        assert_eq!(err.code(), "bad_request");
        assert!(!err.is_retryable());
        assert_eq!(
            reservation_states(&db, &principal).await,
            vec!["released".to_owned()],
            "money that did not move must not hold the day's headroom"
        );

        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1["outcome"], json!("error"));
        assert_eq!(rows[0].1["effect"], json!("payment_create"));
    }

    /// **The team's headroom comes back too**, which the test above cannot see
    /// and never could.
    ///
    /// `seed` puts its employee on **no team**, so `org::reserve` takes the
    /// employee's bucket and stops — the team half of the ledger is never
    /// touched, and a release that forgets it looks exactly like one that does
    /// not. Every seat the founder actually runs is on a team with a budget
    /// (`routes::teams` is the surface for writing one), so the shape this
    /// fixture had was not the shape production has.
    ///
    /// What the miss costs is not one payment: `team_spend_buckets` is keyed
    /// `(tenant, team, day, currency)` and shared by every seat on the team, so
    /// a provider outage that refuses four payments of the budget's quarter
    /// leaves the whole purchasing team refused with `team_daily_limit` until
    /// midnight — with no money moved and nothing in the trail saying why.
    ///
    /// It asserts the employee's side as well, so a "fix" that swapped one
    /// release for the other rather than adding the team half goes red here.
    #[tokio::test]
    async fn a_failed_payment_gives_the_team_its_headroom_back_too() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;

        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let team = org::create_team(
            &mut tx,
            &Slug::parse("purchasing").expect("slug"),
            "Purchasing",
        )
        .await
        .expect("team");
        org::set_member(&mut tx, principal.employee_id, team, None)
            .await
            .expect("seat");
        org::set_budget(
            &mut tx,
            team,
            Money::new(60_000, Currency::Eur).expect("nonzero"),
        )
        .await
        .expect("budget");
        tx.commit().await.expect("commit team");

        let effects = Effects::new(
            db.clone(),
            ports(
                MockEmailProvider::new(),
                MockPayments::broken(ProviderError::from_status(400, None)),
            ),
            principal.clone(),
        );

        let token = gate(&db)
            .authorize(&principal, euros(15_000))
            .await
            .expect("under every cap, the team's included");

        // The charge landed on the **team** ledger, or the assertion below is
        // vacuous. One ledger, not both: an earlier version of this line said
        // both and only one is asserted, which is the kind of sentence that
        // survives because nobody re-reads a comment next to a passing test.
        let day = Utc::now().date_naive();
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        assert_eq!(
            org::spent(&mut tx, team, day, Currency::Eur)
                .await
                .expect("team bucket"),
            15_000,
            "the gate reserves through org::reserve, which charges the team too"
        );
        tx.rollback().await.expect("rollback");

        effects
            .pay(token, MEMO)
            .await
            .expect_err("the payment provider refused");

        assert_eq!(
            reservation_states(&db, &principal).await,
            vec!["released".to_owned()],
            "the employee's own reservation is released"
        );
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        assert_eq!(
            org::spent(&mut tx, team, day, Currency::Eur)
                .await
                .expect("team bucket"),
            0,
            "money that did not move must not hold the *team's* day either: \
             `Authorized::reservation`'s contract says org::release, and a \
             spend::release leaves this charge on the team until midnight"
        );
        tx.rollback().await.expect("rollback");
    }

    /// **The selling side reaches the register**, and the row it writes is
    /// linked to the ruling that permitted it.
    ///
    /// The three facts this pins, none of which the store's own tests can see
    /// because they hold no token: an invoice is `Allow`ed rather than escalated
    /// (a `RequireApproval` would come back `Denied::PendingApproval` and there
    /// would be no token to spend), the audit row names `invoice_issue` and
    /// carries the deal and the memo, and the amount reaches the register in the
    /// currency it was ruled on.
    #[tokio::test]
    async fn an_invoice_is_ruled_on_recorded_and_written_to_the_register() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let opportunity = won_deal(&db, &principal).await;
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );

        let token = gate(&db)
            .authorize(&principal, billed(120_000))
            .await
            .expect("the seeded policy opens Channel::Email");
        let decision_id = token.decision_id();
        assert!(
            token.reservation().is_none(),
            "an invoice draws down no spend headroom: the money comes the other way"
        );

        let id = effects
            .issue_invoice(token, &draft(opportunity))
            .await
            .expect("a won deal is invoiceable");

        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let register = agentos_store::invoices::register(&mut tx)
            .await
            .expect("read the register");
        tx.rollback().await.expect("rollback");
        assert_eq!(register.len(), 1);
        assert_eq!(register[0].id, id);
        assert_eq!(
            register[0].amount,
            Money::new(120_000, Currency::Eur).unwrap()
        );
        assert_eq!(register[0].issued_by, Some(principal.employee_id));
        assert_eq!(register[0].paid_at, None);

        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].0,
            Some(decision_id.as_uuid()),
            "linked to the ruling"
        );
        assert_eq!(rows[0].1["effect"], json!("invoice_issue"));
        assert_eq!(rows[0].1["outcome"], json!("ok"));
        assert_eq!(rows[0].1["detail"]["currency"], json!("EUR"));
        assert_eq!(rows[0].1["detail"]["minor"], json!(120_000));
        assert_eq!(rows[0].1["detail"]["memo"], json!("March"));
        assert_eq!(
            rows[0].1["detail"]["opportunity_id"],
            json!(opportunity.to_string())
        );
    }

    /// **The ceiling, from the side that holds a token.**
    ///
    /// The gate says yes — this employee may bill — and the write still refuses,
    /// because the party is not the seat's to choose: an invoice may only name a
    /// deal somebody won, and winning one needs a human's approval id
    /// (`opportunities_won_needs_approval`, 0011). That is the whole of what
    /// stops a hundred invoices to strangers, so the assertion is on the
    /// refusal — and on the audit row, because a refused demand for money is
    /// exactly the thing an operator has to be able to see afterwards.
    #[tokio::test]
    async fn an_authorised_seat_still_cannot_invoice_a_deal_nobody_won() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let opportunity = open_deal(&db, &principal).await;
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );

        let token = gate(&db)
            .authorize(&principal, billed(120_000))
            .await
            .expect("the gate permits the verb");
        let err = effects
            .issue_invoice(token, &draft(opportunity))
            .await
            .expect_err("a deal in negotiation is not billable");
        assert_eq!(err.code(), NO_WON_DEAL);

        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let register = agentos_store::invoices::register(&mut tx)
            .await
            .expect("read the register");
        tx.rollback().await.expect("rollback");
        assert!(register.is_empty(), "nothing was written");

        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1, "the refusal is on the record");
        assert_eq!(rows[0].1["effect"], json!("invoice_issue"));
        assert_eq!(rows[0].1["outcome"], json!("error"));
        assert_eq!(rows[0].1["error"], json!(NO_WON_DEAL));
    }

    /// **A stranger's text cannot produce a demand for money, and it does not
    /// produce an approval request either.**
    ///
    /// `Action::InvoiceIssue` is `Risk::High` and its arm answers `Allow`, so
    /// `evaluate`'s taint wire fires and the gate denies outright with
    /// `UntrustedInput`. The second assertion is the one that matters and is why
    /// this is not modelled on `ContractSign`: an escalation here would file a
    /// stranger's invoice in front of a human to approve.
    #[tokio::test]
    async fn a_tainted_turn_cannot_invoice_anybody() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;

        let denied = gate(&db)
            .authorize(&principal, Untrusted::new(billed(120_000)))
            .await
            .expect_err("a tainted invoice is refused");
        assert!(
            matches!(denied, Denied::Policy(DenyReason::UntrustedInput)),
            "expected the taint stop, got {denied:?}"
        );
        assert!(
            !matches!(denied, Denied::PendingApproval(_)),
            "an untrusted invoice must not become a question a human is asked"
        );

        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM approvals WHERE state = 'pending'")
                .fetch_one(&mut **tx)
                .await
                .expect("count approvals");
        tx.rollback().await.expect("rollback");
        assert_eq!(pending, 0, "no approval was filed by a stranger");
    }

    /// **A read ruling cannot buy a keystroke on somebody's page.**
    ///
    /// `proof_of_need::Browse` rules as `Action::BrowserRead` and declares
    /// `type Of = BrowserWrite`, so it satisfies `browse_write`'s bound. That
    /// overlap was harmless while a read had to clear `allowed_domains` — the
    /// two rulings permitted the same hosts. Since a read clears
    /// `Channel::Web` alone it permits the entire public web, so the same
    /// token spanned "look at anything" and "type into a named list", and the
    /// audit row would have called the typing a `browser_read`.
    ///
    /// The fixture's employee has `portal.example.com` on its write list, so
    /// the host is not what refuses this: the *ruling* is. Both directions are
    /// asserted, because a check that only refused would pass by being an off
    /// switch and would break every `Goto` the prober makes.
    #[tokio::test]
    async fn a_read_ruling_cannot_drive_a_step_that_types() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );
        let session = BrowserSession {
            employee_id: principal.employee_id,
            binding: ProviderBinding {
                provider: "mock-browser".to_owned(),
                external_id: "ctx-1".to_owned(),
            },
            user_data_dir: None,
        };
        let host = Domain::parse("portal.example.com").expect("domain");
        let reading = crate::proof_of_need::Browse::of(host.clone());

        for step in [
            BrowserStep::Type {
                sel: "#passport",
                text: "FRA",
            },
            BrowserStep::Click("#search"),
        ] {
            let token = gate(&db)
                .authorize(&principal, reading.clone())
                .await
                .expect("a read is allowed: the seat carries the web channel");
            let err = effects
                .browse_write(token, &session, step)
                .await
                .expect_err("a read ruling must not type");
            assert_eq!(err.code(), READ_TOKEN);
        }

        // Refusals are recorded like any other failed effect, and as what the
        // token was — a read that did not happen, not a write that did.
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1["error"], json!(READ_TOKEN));
        assert_eq!(rows[0].1["effect"], json!("browser_read"));

        // And the steps a read *is* for still run, or the prober's every
        // navigation would have died with this fix.
        // `Text` is a read too and is deliberately not exercised here: this
        // mock browser has no page loaded, so it answers `no_such_element` and
        // would fail for a reason that is not this test's. `Goto` is the step
        // the neighbouring test already proves the mock serves.
        let inside = Url::parse("https://portal.example.com/book").expect("url");
        let token = gate(&db)
            .authorize(&principal, reading.clone())
            .await
            .expect("still a read");
        effects
            .browse_write(token, &session, BrowserStep::Goto(&inside))
            .await
            .expect("a reading step on a read ruling");

        // `Location` is a reading step too, and it has to be: the scope guard
        // asks it before every step it did not itself navigate, so classifying
        // it as a write would make a read ruling unable to drive anything at
        // all.
        let token = gate(&db)
            .authorize(&principal, reading.clone())
            .await
            .expect("still a read");
        effects
            .browse_write(token, &session, BrowserStep::Location)
            .await
            .expect("asking where we are is looking, not writing");

        // The write ruling keeps typing, which is the half that must not have
        // been taken away.
        let token = gate(&db)
            .authorize(&principal, BrowserWrite { domain: host })
            .await
            .expect("portal.example.com is on the write list");
        effects
            .browse_write(
                token,
                &session,
                BrowserStep::Type {
                    sel: "#passport",
                    text: "FRA",
                },
            )
            .await
            .expect("a write ruling may type");
    }

    #[tokio::test]
    async fn a_browser_step_may_not_leave_the_authorised_domain() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );
        let session = BrowserSession {
            employee_id: principal.employee_id,
            binding: ProviderBinding {
                provider: "mock-browser".to_owned(),
                external_id: "ctx-1".to_owned(),
            },
            user_data_dir: None,
        };
        let subject = BrowserWrite {
            domain: Domain::parse("portal.example.com").expect("domain"),
        };

        let elsewhere = Url::parse("https://evil.example.net/steal").expect("url");
        let token = gate(&db)
            .authorize(&principal, subject.clone())
            .await
            .expect("portal.example.com is on the allowlist");
        let err = effects
            .browse_write(token, &session, BrowserStep::Goto(&elsewhere))
            .await
            .expect_err("the gate ruled on portal.example.com");
        assert_eq!(err.code(), "out_of_scope");

        // ...and the refusal is recorded like any other failed effect.
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1["error"], json!("out_of_scope"));

        // The same step inside the domain reaches the provider.
        let inside = Url::parse("https://portal.example.com/orders").expect("url");
        let token = gate(&db)
            .authorize(&principal, subject)
            .await
            .expect("still allowed");
        effects
            .browse_write(token, &session, BrowserStep::Goto(&inside))
            .await
            .expect("inside the authorised domain");
        assert_eq!(effect_rows(&db, &principal).await.len(), 2);
    }

    /// **A `302` off the token's domain is refused, and the tab is not left
    /// there.**
    ///
    /// The bug this guard exists for, run end to end. Before it, every line
    /// below succeeded: the `Goto` cleared the check on the URL it *asked* for,
    /// the landing URL the outcome carries was dropped on the floor, and the
    /// keystroke that followed went to `booking-engine.example.net` under two
    /// audit rows that both said `portal.example.com` and `ok`.
    ///
    /// The last part is the one a "just refuse it" fix would miss: the browser
    /// context is shared for the whole employee, so a refusal that leaves the
    /// tab on the refused page has only moved the problem to whoever calls next.
    #[tokio::test]
    async fn a_redirect_off_the_token_domain_is_refused_and_the_session_is_parked() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let browser = Arc::new(MockBrowser::new());
        let effects = Effects::new(
            db.clone(),
            ports_browsing(browser.clone()),
            principal.clone(),
        );
        let session = session_for(&principal);
        let subject = BrowserWrite {
            domain: Domain::parse("portal.example.com").expect("domain"),
        };

        let asked = Url::parse("https://portal.example.com/book").expect("url");
        let landed = Url::parse("https://booking-engine.example.net/step1").expect("url");
        browser.set_redirect(&asked, &landed);

        // 1. The navigation is inside the token's domain and still refused,
        //    because it did not *end* inside it and nobody granted where it
        //    ended.
        let token = gate(&db)
            .authorize(&principal, subject.clone())
            .await
            .expect("portal.example.com is on the write list");
        let err = effects
            .browse_write(token, &session, BrowserStep::Goto(&asked))
            .await
            .expect_err("their site sent us somewhere nobody ruled on");
        assert_eq!(err.code(), "out_of_scope");

        // 2. The row names the host we were really on. One that said only
        //    `portal.example.com` would be a false statement about a page we
        //    had already loaded.
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1["detail"]["domain"], json!("portal.example.com"));
        assert_eq!(
            rows[0].1["detail"]["landed"],
            json!("booking-engine.example.net"),
            "the trail has to say where we actually went: {}",
            rows[0].1
        );
        assert_eq!(rows[0].1["outcome"], json!("error"));

        // 3. The shared tab was taken off their page.
        assert_eq!(
            browser.act(&session, BrowserStep::Location).await.unwrap(),
            BrowserOutcome::Navigated(agentos_providers::browser::blank_page()),
            "the next caller inherits this session"
        );

        // 4. And the keystroke that used to follow cannot happen: a step is
        //    checked against where the session *is* before it touches anything,
        //    so even a tab somebody else parked off-domain refuses it.
        browser
            .act(&session, BrowserStep::Goto(&landed))
            .await
            .expect("something parks the tab off-domain behind our back");
        let token = gate(&db)
            .authorize(&principal, subject)
            .await
            .expect("still allowed on paper");
        let err = effects
            .browse_write(
                token,
                &session,
                BrowserStep::Type {
                    sel: "#passport",
                    text: "FRA",
                },
            )
            .await
            .expect_err("the page under that selector is not the ruled one");
        assert_eq!(err.code(), "out_of_scope");
        assert!(
            !browser.log().iter().any(|line| line.contains(" type ")),
            "nothing was typed on their page: {:?}",
            browser.log()
        );
    }

    /// **An outsourced booking funnel still works — because an operator granted
    /// the partner, and for no other reason.**
    ///
    /// The half a blanket refusal would have destroyed.
    /// `proof_of_need::Flow::confirmed` requires a prospect's entry URL to be
    /// within `accounts.domain`, so a redirect is the *only* route into a funnel
    /// run by somebody else; refusing every off-domain landing would have made
    /// those prospects unreachable and said nothing about it.
    ///
    /// What permits it is what already permits typing anywhere at all:
    /// `allowed_domains`. No new policy field and no new action kind — and the
    /// rows name the partner and the second decision that cleared it.
    #[tokio::test]
    async fn an_outsourced_funnel_is_driven_when_the_operator_granted_the_partner() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        install_policy(
            &db,
            principal.tenant_id,
            &["portal.example.com", "booking-engine.example.net"],
            BTreeSet::new(),
        )
        .await;
        let browser = Arc::new(MockBrowser::new());
        let effects = Effects::new(
            db.clone(),
            ports_browsing(browser.clone()),
            principal.clone(),
        );
        let session = session_for(&principal);
        let subject = BrowserWrite {
            domain: Domain::parse("portal.example.com").expect("domain"),
        };

        let asked = Url::parse("https://portal.example.com/book").expect("url");
        let landed = Url::parse("https://booking-engine.example.net/step1").expect("url");
        browser.set_redirect(&asked, &landed);

        let token = gate(&db)
            .authorize(&principal, subject.clone())
            .await
            .expect("the entry is on the prospect's own domain");
        effects
            .browse_write(token, &session, BrowserStep::Goto(&asked))
            .await
            .expect("the partner is granted, so the landing is ruled and kept");

        let token = gate(&db)
            .authorize(&principal, subject)
            .await
            .expect("still ruled on the prospect's domain");
        effects
            .browse_write(
                token,
                &session,
                BrowserStep::Type {
                    sel: "#passport",
                    text: "FRA",
                },
            )
            .await
            .expect("typing into the partner's field, ruled on the partner");

        assert_eq!(
            browser.log(),
            [
                "ctx-1 goto https://portal.example.com/book",
                "ctx-1 type #passport FRA",
            ],
            "the funnel ran"
        );

        // Both rows carry the token's domain *and* the host the step really
        // acted on, plus the id of the ruling that permitted being there.
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows.len(), 2);
        for (_, row) in &rows {
            assert_eq!(row["outcome"], json!("ok"));
            assert_eq!(row["detail"]["domain"], json!("portal.example.com"));
            assert_eq!(
                row["detail"]["landed"],
                json!("booking-engine.example.net"),
                "{row}"
            );
            assert!(
                row["detail"]["landed_decision"].is_string(),
                "the second ruling has to be findable from this row: {row}"
            );
        }
        // ...and it is a fresh ruling per step, not one id copied forward: a
        // policy an operator narrows mid-plan stops the plan.
        assert_ne!(
            rows[0].1["detail"]["landed_decision"], rows[1].1["detail"]["landed_decision"],
            "one re-decision per step, or the trail cannot say which step went where"
        );
    }

    /// **A read may be redirected, and the denylist still holds.**
    ///
    /// Reads clear `Channel::Web` rather than an allowlist, so a redirected read
    /// is normally fine — `example.com` to `www.example.com` to a country
    /// splash, all day. The one thing a redirect must not buy is a host an
    /// operator explicitly blocked; and `read_page` navigates outside
    /// `browse_write` entirely, so it needs the check in its own right rather
    /// than inheriting one.
    #[tokio::test]
    async fn a_redirected_read_is_refused_when_it_lands_on_a_denied_host() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        install_policy(
            &db,
            principal.tenant_id,
            &["portal.example.com"],
            BTreeSet::from([Domain::parse("banking.example.net").expect("domain")]),
        )
        .await;
        let browser = Arc::new(MockBrowser::new());
        let effects = Effects::new(
            db.clone(),
            ports_browsing(browser.clone()),
            principal.clone(),
        );
        provision_browser(&db, &principal).await;

        let asked = Url::parse("https://portal.example.com/statement").expect("url");
        let denied = Url::parse("https://banking.example.net/accounts").expect("url");
        browser.set_redirect(&asked, &denied);
        browser.set_text("#balance", &["EUR 12,340"]);

        let reading = || BrowserRead {
            domain: Domain::parse("portal.example.com").expect("domain"),
        };
        let token = gate(&db)
            .authorize(&principal, reading())
            .await
            .expect("reading is a channel, and this seat has it");
        let err = effects
            .read_page(token, &asked, "#balance")
            .await
            .expect_err("the operator blocked that host");
        assert_eq!(err.code(), "out_of_scope");
        assert!(
            !browser.log().iter().any(|line| line.contains(" text ")),
            "their page was never read: {:?}",
            browser.log()
        );
        let rows = effect_rows(&db, &principal).await;
        assert_eq!(rows[0].1["detail"]["landed"], json!("banking.example.net"));

        // The same read without a redirect still works, or this guard would be
        // an off switch for reading rather than a bound on it.
        let straight = Url::parse("https://portal.example.com/page").expect("url");
        let token = gate(&db)
            .authorize(&principal, reading())
            .await
            .expect("still allowed");
        let text = effects
            .read_page(token, &straight, "#balance")
            .await
            .expect("an ordinary read");
        assert_eq!(text.into_inner_for_rendering(), "EUR 12,340");
    }

    #[tokio::test]
    async fn an_untrusted_draft_still_sends_but_an_untrusted_payment_never_does() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );
        let gate = gate(&db);

        // Low risk: a reply the model drafted after reading a stranger's email
        // is authorised, and `Authorized<Untrusted<EmailSend>>` reaches the
        // same method — the taint travelled the whole way and cost nothing.
        let token = gate
            .authorize(&principal, Untrusted::new(to("supplier@example.com")))
            .await
            .expect("replying is low risk");
        effects
            .send_email(token, body())
            .await
            .expect("the mock sends");

        // High risk: no token is minted at all, so `pay` cannot be called.
        let denied = gate
            .authorize(&principal, Untrusted::new(euros(1_000)))
            .await
            .expect_err("a payment a supplier's email asked for");
        assert_eq!(denied.code(), "untrusted_input");
        assert!(reservation_states(&db, &principal).await.is_empty());
        assert_eq!(effect_rows(&db, &principal).await.len(), 1);
    }

    /// **The frontier the founder drew**: an employee files work for itself and
    /// for the seats it directly manages, and for nobody else on the board.
    ///
    /// One run against one org chart, because the rule is a single relation and
    /// splitting it into six tests would be six fixtures of one company. Every
    /// refusal is checked twice — the coded answer *and* the board, because a
    /// guard that returns the right error after writing the row has refused
    /// nothing.
    ///
    /// The negative half is the half worth having, and each case is a different
    /// way the rule could have been written wrong:
    ///
    /// * **carla** is on the same team and answers to nobody. A guard written
    ///   against the team — which is what a question and a handover ride on —
    ///   would file for her, and an employee that can fill a peer's board can
    ///   bury a peer.
    /// * **eve** answers to bruno who answers to lena. A guard that walked the
    ///   chart instead of taking one link would file for her, and a head would
    ///   thereby own the day of every seat beneath it.
    /// * **carla filing for lena** is the line read upward. Escalation is a
    ///   `question`, which spends the asker's own turn; an item on a manager's
    ///   board is work a report put there.
    /// * **a terminated report** is still `reports_to` in the chart. The
    ///   lifecycle join is `directs`', inherited rather than restated, and this
    ///   is what proves it was inherited.
    #[tokio::test]
    async fn an_employee_files_work_for_itself_and_its_line_and_for_nobody_else() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let (bruno, carla, eve) = org_around(&db, &principal).await;
        let (tenant, lena) = (principal.tenant_id, principal.employee_id);
        let effects = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            principal.clone(),
        );

        // A note to self, which is the case that needs no org chart at all: it
        // survives the turn and risks nothing, and `may_message` would have
        // refused it out of hand because a message to yourself is a wake-up
        // loop and this is not.
        effects
            .post_work(None, "check the tariff code tomorrow")
            .await
            .expect("an employee may always write itself a note");
        // Naming your own slug is the same act spelled the long way.
        effects
            .post_work(Some(&slug("lena")), "and the customs email")
            .await
            .expect("naming yourself is the same as saying nothing");
        // One link down: the whole of what the founder widened.
        effects
            .post_work(Some(&slug("bruno")), "confirm the HS code with the broker")
            .await
            .expect("a manager may put work in a direct report's day");

        assert_eq!(
            board_of(&db, tenant, lena).await,
            vec![
                (
                    "check the tariff code tomorrow".to_owned(),
                    Some(lena.as_uuid())
                ),
                ("and the customs email".to_owned(), Some(lena.as_uuid())),
            ],
            "both landed on lena's own board, and `0064` says who wrote them — \
             which is the only record anywhere that an employee did"
        );
        assert_eq!(
            board_of(&db, tenant, bruno).await,
            vec![(
                "confirm the HS code with the broker".to_owned(),
                Some(lena.as_uuid())
            )],
            "the report reads it at the top of its next turn, and the board says \
             its manager put it there"
        );

        // -- and now everything that must not work --------------------------
        for (who, why) in [
            (
                "carla",
                "a peer shares the team and not the line: a question rides the team, work does not",
            ),
            (
                "eve",
                "one link and never a walk — a report's report is not this employee's to fill",
            ),
            (
                "mallory",
                "nobody by that name, and it must read exactly like the two above",
            ),
        ] {
            let err = effects
                .post_work(Some(&slug(who)), "do this for me")
                .await
                .expect_err(why);
            assert!(
                matches!(err, EffectError::Refused("unreachable_colleague")),
                "{why}: got {err:?}"
            );
        }
        assert!(
            board_of(&db, tenant, carla).await.is_empty()
                && board_of(&db, tenant, eve).await.is_empty(),
            "a refusal that wrote the row anyway has refused nothing"
        );

        // Upward. Carla is a head of her own, so this is not "an employee with
        // no authority": it is authority pointed the wrong way.
        let upward = Effects::new(
            db.clone(),
            ports(MockEmailProvider::new(), MockPayments::healthy()),
            Principal::employee(tenant, carla),
        );
        assert!(
            matches!(
                upward.post_work(Some(&slug("lena")), "handle this").await,
                Err(EffectError::Refused("unreachable_colleague"))
            ),
            "the line runs one way: a report escalates with a question, not by \
             filing work on its manager"
        );

        // A terminated report is still `reports_to` in the chart, and `directs`
        // joins `employees` on `lifecycle = 'active'` at both ends.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("UPDATE employees SET lifecycle = 'terminated' WHERE id = $1")
            .bind(bruno.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("terminate bruno");
        tx.commit().await.expect("commit");
        assert!(
            matches!(
                effects
                    .post_work(Some(&slug("bruno")), "one more thing")
                    .await,
                Err(EffectError::Refused("unreachable_colleague"))
            ),
            "a seat nobody works cannot be given work"
        );
        assert_eq!(
            board_of(&db, tenant, bruno).await.len(),
            1,
            "…and what was filed while it was working is still there: closing is \
             a column and terminating is not a delete"
        );
    }

    /// **The loop, end to end, through the port**: the founder writes work down
    /// without deciding who does it, one employee takes it, a second is told it
    /// is gone, the holder finishes it, and the founder still has the record.
    ///
    /// Before this there was no loop — the founder assigned and the employee
    /// read, and the three verbs in between did not exist. Everything here goes
    /// through `Effects`, so it is the path a turn takes and not the store
    /// underneath it.
    #[tokio::test]
    async fn one_employee_takes_the_work_the_other_is_told_it_is_gone_and_the_holder_closes_it() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let (bruno, _, _) = org_around(&db, &principal).await;
        let (tenant, lena) = (principal.tenant_id, principal.employee_id);
        let effects = |who| {
            Effects::new(
                db.clone(),
                ports(MockEmailProvider::new(), MockPayments::healthy()),
                Principal::employee(tenant, who),
            )
        };
        let (lena_acts, bruno_acts) = (effects(lena), effects(bruno));

        // The founder's half, and the only writer that can leave an item
        // unheld: `post_work` has no spelling for "nobody", on purpose.
        let board = PgBacklog::new(db.clone(), tenant);
        let item = board
            .post("chase the tariff code", None, None)
            .await
            .expect("the founder writes it down without deciding who does it");

        // Both employees see it, and it is on neither board. That is what the
        // pool is, and it is not scoped to a team or a line.
        for who in [lena, bruno] {
            assert_eq!(
                board.unclaimed().await.expect("pool").len(),
                1,
                "the pool is the whole company's"
            );
            assert!(
                board_of(&db, tenant, who).await.is_empty(),
                "and an unheld item is on nobody's board"
            );
        }

        assert!(
            lena_acts
                .work_item(item, WorkAction::Claim)
                .await
                .expect("the board answers"),
            "the first one to reach for it gets it"
        );
        assert!(
            !bruno_acts
                .work_item(item, WorkAction::Claim)
                .await
                .expect("the board answers"),
            "and the second is told so — `Ok(false)`, not an error: losing a race \
             is an answer, and a model told 'failed' would retry"
        );
        assert!(
            board.unclaimed().await.expect("pool").is_empty(),
            "it is out of the pool the moment it is taken"
        );

        // Closing is the holder's word. Bruno is Lena's report and could not
        // even file this for her; he certainly cannot sign it off.
        assert!(
            !bruno_acts
                .work_item(item, WorkAction::Close)
                .await
                .expect("the board answers"),
            "you close what is on your own board and nothing else"
        );
        assert_eq!(
            board_of(&db, tenant, lena).await.len(),
            1,
            "…and the refusal closed nothing"
        );

        assert!(
            lena_acts
                .work_item(item, WorkAction::Close)
                .await
                .expect("the board answers"),
            "the holder can"
        );
        assert!(
            board_of(&db, tenant, lena).await.is_empty()
                && board.unclaimed().await.expect("pool").is_empty(),
            "a closed item is nobody's work and does not fall back into the pool"
        );

        // And the founder still has it, which is the whole reason a model is
        // allowed to close anything at all: `0061` refused `DELETE`.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let all = agentos_store::backlog::board(&mut tx)
            .await
            .expect("the founder's board");
        tx.rollback().await.expect("rollback");
        assert_eq!(all.len(), 1, "closing is a column, not a delete");
        assert!(all[0].closed_at.is_some() && all[0].assignee_id == Some(lena));
    }
}
