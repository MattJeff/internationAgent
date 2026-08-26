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
use agentos_domain::ids::{DecisionId, IdempotencyKey, Slug};
use agentos_domain::money::Money;
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_providers::browser::{BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep};
use agentos_providers::email::{EmailProvider, OutboundEmail, ProviderMessageId};
use agentos_providers::telephony::{OpenWindow, OutboundSms, OutboundWhatsapp, TelephonyProvider};
use agentos_providers::{ProviderBinding, ProviderError};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError};
use agentos_store::revenue::RevenueError;
use agentos_store::spend;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value, json};
use url::Url;

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
    ($(#[$doc:meta])* $name:ident { $field:ident : $ty:ty } => $variant:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            /// The parsed counterparty of the effect, as the gate ruled on it.
            pub $field: $ty,
        }

        impl Authorizable for $name {
            fn to_action(&self) -> Action {
                Action::$variant { $field: self.$field.clone() }
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
    /// Move money.
    PaymentCreate { amount: Money } => PaymentCreate
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

/// Where the money goes and what it is for. The amount is on the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentInstruction {
    /// The payee, in whatever form the payment provider identifies one.
    pub payee: String,
    /// What the payment is for; ends up on the statement and in the audit row.
    pub memo: String,
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
    pub fn is_retryable(&self) -> bool {
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
    /// SMS and WhatsApp.
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

    /// Send the rendered email to the address on the token.
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

        let sent = self
            .ports
            .email
            .send(&self.key_for(&ok), &email)
            .await
            .map_err(EffectError::Provider);
        self.record(&ok, message_detail(&sent), sent).await
    }

    /// Send the rendered SMS to the number on the token.
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

        let sent = self
            .ports
            .telephony
            .send_sms(&self.key_for(&ok), &sms)
            .await
            .map_err(EffectError::Provider);
        self.record(&ok, message_detail(&sent), sent).await
    }

    /// Send the rendered WhatsApp message to the number on the token.
    pub async fn send_whatsapp<A: Subject<Of = WhatsappSend>>(
        &self,
        ok: Authorized<A>,
        body: RenderedWhatsapp,
    ) -> Result<ProviderMessageId, EffectError> {
        let message = body.addressed_to(ok.action().subject().to.clone());

        let sent = self
            .ports
            .telephony
            .send_whatsapp(&self.key_for(&ok), &message)
            .await
            .map_err(EffectError::Provider);
        self.record(&ok, message_detail(&sent), sent).await
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
    /// with no ruling at all — so inventing a sixteenth [`ActionKind`] to cover
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

    /// Move the money the token authorises, then settle or release the
    /// reservation it carries.
    pub async fn pay<A: Subject<Of = PaymentCreate>>(
        &self,
        ok: Authorized<A>,
        instruction: &PaymentInstruction,
    ) -> Result<ProviderMessageId, EffectError> {
        let amount = ok.action().subject().amount;
        let paid = self
            .ports
            .payments
            .pay(&self.key_for(&ok), amount, instruction)
            .await
            .map_err(EffectError::Provider);

        let detail = Some(json!({
            "payee": instruction.payee,
            "minor": amount.minor(),
            "currency": amount.currency().code(),
            "provider_message_id": paid.as_ref().ok().map(ProviderMessageId::as_str),
        }));
        self.record(&ok, detail, paid).await
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

        // Only a payment carries one, and it is the whole reason the gate's
        // docs call this module the executor: money that did not move must not
        // keep holding the day's headroom.
        if let Some(reservation) = ok.reservation() {
            let settled = if outcome.is_ok() {
                spend::settle(&mut tx, reservation).await
            } else {
                spend::release(&mut tx, reservation).await
            };
            settled.map_err(EffectError::Unavailable)?;
        }

        let mut payload = Map::new();
        payload.insert(
            "effect".to_owned(),
            json!(ok.action().to_action().kind().as_str()),
        );
        match &outcome {
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
        audit::append(&mut tx, &event)
            .await
            .map_err(EffectError::Unavailable)?;
        tx.commit().await.map_err(EffectError::Unavailable)?;

        outcome
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

    use agentos_domain::action::{ActionKind, Channel};
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::money::Currency;
    use agentos_domain::policy::{PolicyLimits, SpendLimits};
    use agentos_providers::browser::MockBrowser;
    use agentos_providers::email::MockEmailProvider;
    use agentos_providers::telephony::MockTelephony;
    use agentos_providers::{FaultMode, ProviderBinding};
    use agentos_store::spend::SpendCaps;
    use url::Url;
    use uuid::Uuid;

    use super::*;
    use crate::gate::PolicyGate;

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
    }

    #[async_trait]
    impl PaymentProvider for MockPayments {
        async fn pay(
            &self,
            key: &IdempotencyKey,
            _amount: Money,
            _instruction: &PaymentInstruction,
        ) -> Result<ProviderMessageId, ProviderError> {
            self.keys
                .lock()
                .expect("poisoned")
                .push(key.as_str().to_owned());
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
                allowed_channels: BTreeSet::from([Channel::Email, Channel::Web]),
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

    fn ports(email: MockEmailProvider, payments: Arc<MockPayments>) -> Arc<Ports> {
        Arc::new(Ports {
            email: Arc::new(email),
            telephony: Arc::new(MockTelephony::new(Utc::now(), "token")),
            browser: Arc::new(MockBrowser::new()),
            mcp: Arc::new(StubMcp),
            payments,
        })
    }

    /// The same, with the browser kept in hand — for the tests that script a
    /// redirect and then ask where the session ended up.
    fn ports_browsing(browser: Arc<MockBrowser>) -> Arc<Ports> {
        Arc::new(Ports {
            email: Arc::new(MockEmailProvider::new()),
            telephony: Arc::new(MockTelephony::new(Utc::now(), "token")),
            browser,
            mcp: Arc::new(StubMcp),
            payments: MockPayments::healthy(),
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
        PaymentCreate {
            amount: Money::new(minor, Currency::Eur).expect("nonzero"),
        }
    }

    fn invoice() -> PaymentInstruction {
        PaymentInstruction {
            payee: "acct_supplier".to_owned(),
            memo: "invoice 42".to_owned(),
        }
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
            .authorize(&principal, euros(15_000))
            .await
            .expect("under every cap");
        assert!(token.reservation().is_some(), "the gate reserved");
        let decision_id = token.decision_id();

        effects.pay(token, &invoice()).await.expect("the mock pays");
        assert_eq!(
            reservation_states(&db, &principal).await,
            vec!["settled".to_owned()]
        );

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
            .pay(token, &invoice())
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
}
