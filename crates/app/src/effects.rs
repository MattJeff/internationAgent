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
use agentos_domain::ids::{IdempotencyKey, Slug};
use agentos_domain::money::Money;
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_providers::browser::{BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep};
use agentos_providers::email::{EmailProvider, OutboundEmail, ProviderMessageId};
use agentos_providers::telephony::{OpenWindow, OutboundSms, OutboundWhatsapp, TelephonyProvider};
use agentos_providers::{ProviderBinding, ProviderError};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError};
use agentos_store::spend;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value, json};
use url::Url;

use crate::gate::{Authorizable, Authorized, Principal};
use crate::inbound::{self, Briefing, Delivered, Errand, InternalError, Thread};

/// What [`Effects::read_page`] answers when this employee has no browser
/// context to drive.
///
/// A code rather than a message, because it is handed to a model as a failed
/// tool result: "your browser is not provisioned" is a fact about this
/// deployment that no amount of rephrasing the request will change, and the
/// model needs to stop asking rather than try a different URL.
pub const NO_BROWSER: &str = "no_browser";

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
    /// A [`BrowserStep::Goto`] is checked against the token's domain: the gate
    /// ruled on a domain, and a plan that navigates away from it is asking for
    /// an effect nobody authorised. The other steps act on whatever page the
    /// session already shows, which this layer cannot see — for those, the
    /// guard that matters is that they got here holding a token at all.
    pub async fn browse_write<A: Subject<Of = BrowserWrite>>(
        &self,
        ok: Authorized<A>,
        session: &BrowserSession,
        step: BrowserStep<'_>,
    ) -> Result<BrowserOutcome, EffectError> {
        let allowed = ok.action().subject().domain.clone();
        let outcome = if let BrowserStep::Goto(url) = &step
            && !within(url.host_str(), &allowed)
        {
            Err(EffectError::OutOfScope(allowed.clone()))
        } else {
            self.ports
                .browser
                .act(session, step)
                .await
                .map_err(EffectError::Provider)
        };

        let detail = Some(json!({ "domain": allowed.as_str() }));
        self.record(&ok, detail, outcome).await
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
    /// checks a [`BrowserStep::Goto`], because it is the same check on the same
    /// field.
    ///
    /// # It is a read, and it is unspellable as anything else
    ///
    /// The bound is [`BrowserRead`] and not [`BrowserWrite`], so a token minted
    /// for typing into somebody's form cannot be spent here and a token minted
    /// for reading cannot be spent on [`Effects::browse_write`]. The audit row
    /// follows from the token — [`Effects::record`] writes
    /// `ok.action().to_action().kind()` — so `browser_read` and `browser_write`
    /// rows say what actually happened, with no flag for a caller to set.
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
        let read = self.load_page(&allowed, url, selector).await;
        let detail = Some(json!({ "domain": allowed.as_str(), "selector": selector }));
        self.record(&ok, detail, read).await
    }

    /// The provider half of [`Effects::read_page`], split out so the token, the
    /// audit row and the two steps do not share one method's error paths.
    async fn load_page(
        &self,
        allowed: &Domain,
        url: &Url,
        selector: &str,
    ) -> Result<Untrusted<String>, EffectError> {
        if !within(url.host_str(), allowed) {
            return Err(EffectError::OutOfScope(allowed.clone()));
        }
        let session = self.session().await?;
        self.ports
            .browser
            .act(&session, BrowserStep::Goto(url))
            .await
            .map_err(EffectError::Provider)?;
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
    async fn session(&self) -> Result<BrowserSession, EffectError> {
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
                allowed_channels: BTreeSet::from([Channel::Email]),
                allowed_domains: BTreeSet::from([
                    Domain::parse("portal.example.com").expect("domain")
                ]),
                max_new_contacts_per_day: 5,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");

        Principal::employee(tenant, employee)
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
