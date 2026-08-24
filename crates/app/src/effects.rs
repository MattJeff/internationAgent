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
use agentos_domain::ids::IdempotencyKey;
use agentos_domain::money::Money;
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_providers::ProviderError;
use agentos_providers::browser::{BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep};
use agentos_providers::email::{EmailProvider, OutboundEmail, ProviderMessageId};
use agentos_providers::telephony::{OpenWindow, OutboundSms, OutboundWhatsapp, TelephonyProvider};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError};
use agentos_store::spend;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value, json};

use crate::gate::{Authorizable, Authorized, Principal};

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
/// Note what this enum does *not* have: a variant for "not allowed". By the
/// time anything here runs the gate has already ruled; a refusal is a
/// [`crate::gate::Denied`] and never reaches this module.
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
    use crate::gate::{PolicyBook, PolicyGate};

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

        Principal::employee(tenant, employee)
    }

    /// Email, `portal.example.com`, and a small budget.
    fn gate(db: &Db) -> PolicyGate {
        PolicyGate::new(
            db.clone(),
            PolicyBook::new(PolicyLimits {
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
            }),
        )
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
