//! The closed set of side effects an employee can ask the world to perform,
//! plus the parsed value types those side effects are addressed with.
//!
//! The governing rule of this module: **an [`Action`] never carries a
//! caller-supplied *claim about* another field.** It carries the thing itself,
//! already parsed. `CallPlace` carries an [`E164`] and the gate derives the
//! calling code from it; the old design carried a `country: String` next to the
//! number, which an LLM (or an attacker steering one) could set to `"CN"` while
//! dialling `+7`. `BrowserWrite` carries a normalised [`Domain`], not a string
//! that gets re-spelled at every comparison site.
//!
//! Facts the gate needs that are *not* part of the action — how much has been
//! spent today, whether the recipient is a new contact, whether the input that
//! produced this action was trusted — live in [`ActionCtx`], which is assembled
//! by the host, never by the model.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Url};

use crate::ids::{ConversationId, EmployeeId, SecretRef, Slug, TenantId};
use crate::money::Money;

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// Why a string is not a usable [`Domain`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainError {
    #[error("domain is empty")]
    Empty,
    #[error("not a bare host name: {0:?}")]
    NotAHost(String),
    #[error("an ip address is not a domain: {0:?}")]
    IpAddress(String),
    #[error("host needs at least two labels: {0:?}")]
    TooFewLabels(String),
    /// A name that only resolves inside somebody's network.
    ///
    /// Its own variant rather than [`NotAHost`](DomainError::NotAHost) because
    /// it is a *well-formed* host that this system refuses on purpose, and an
    /// operator reading the error deserves to know which of the two happened.
    #[error("host is not on the public internet: {0:?}")]
    NotPublic(String),
}

/// Suffixes that never name a host on the public internet.
///
/// **This became load-bearing when reading stopped consulting an allowlist.**
/// While `policy::evaluate` answered a browser read out of `allowed_domains`,
/// an internal name was refused by not being on anybody's list. It is now
/// refused by not being expressible: `Channel::Web` grants the whole public
/// web, so the line between "the web" and "somebody's network" has to be drawn
/// here, at the only constructor, where a `Domain` that names a router admin
/// page cannot come into existence to be read, mailed to, or bound as a peer.
///
/// [RFC 6761] reserves `localhost`; [RFC 6762] reserves `local` for mDNS;
/// [RFC 8375] reserves `home.arpa`; ICANN reserved `internal` for private use
/// in 2024. `localhost` is single-label and already dies on
/// [`DomainError::TooFewLabels`], and it is listed anyway because
/// `foo.localhost` is not.
///
/// **Not listed, deliberately:** `test`, `example`, `example.com` — and
/// `invalid`, which was listed for one commit until
/// `peer_keys::a_pinned_peer_never_touches_the_network` failed on
/// `nobody.example.invalid`. All four are reserved against *collision*, not
/// against routing: they resolve nowhere and reach nothing, so refusing them
/// buys no safety. `invalid` is the sharpest case — RFC 6761 guarantees it
/// never resolves, which makes it the correct host for a test asserting that
/// no packet leaves, and banning it would have deleted the only spelling of
/// "this must not be reachable".
///
/// **What this does not cover, and cannot.** A perfectly public name that
/// resolves to `10.0.0.5`. No parser can see that; it needs the resolver, and
/// checking it here would be a check on a different address from the one the
/// browser eventually connects to (`crates/providers` owns that, and DNS
/// rebinding means even there it is a narrowing rather than a proof).
///
/// [RFC 6761]: https://www.rfc-editor.org/rfc/rfc6761
/// [RFC 6762]: https://www.rfc-editor.org/rfc/rfc6762
/// [RFC 8375]: https://www.rfc-editor.org/rfc/rfc8375
const PRIVATE_USE_SUFFIXES: &[&str] = &["local", "internal", "localhost", "home.arpa"];

/// A host name normalised once, at the edge, so every later comparison is a
/// byte comparison.
///
/// Normalisation is delegated to the URL parser, which is the same code the
/// browser will use to resolve the request: IDNA/punycode mapping, ASCII
/// lowercasing, and label validation. A trailing root dot is stripped first.
/// The result is that `BANKING.example.com`, `banking.example.com.` and
/// `ｂａｎｋｉｎｇ.example.com` are all the *same* `Domain` value, so a
/// denylist entry cannot be evaded by re-spelling it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Domain(String);

impl Domain {
    /// Normalise and validate. The only way to build a `Domain`.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let trimmed = raw.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(DomainError::Empty);
        }
        // A bare host has no scheme, no credentials, no port, no path. Reject
        // those outright rather than letting the URL parser quietly drop them.
        if trimmed.contains(['/', '\\', '@', ':', '?', '#', ' ']) {
            return Err(DomainError::NotAHost(raw.to_owned()));
        }

        let url = Url::parse(&format!("https://{trimmed}/"))
            .map_err(|_| DomainError::NotAHost(raw.to_owned()))?;

        match url.host() {
            Some(Host::Domain(host)) => {
                if !host.contains('.') {
                    return Err(DomainError::TooFewLabels(host.to_owned()));
                }
                if PRIVATE_USE_SUFFIXES
                    .iter()
                    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
                {
                    return Err(DomainError::NotPublic(host.to_owned()));
                }
                Ok(Self(host.to_owned()))
            }
            Some(Host::Ipv4(_) | Host::Ipv6(_)) => Err(DomainError::IpAddress(raw.to_owned())),
            None => Err(DomainError::NotAHost(raw.to_owned())),
        }
    }

    /// The normalised, punycoded, lowercased host.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `self` *is* `other` or sits underneath it, at a label
    /// boundary: `login.banking.example.com` is within `banking.example.com`,
    /// and `evilbanking.example.com` is not.
    ///
    /// ponytail: label-suffix match, not a public-suffix-list lookup. It is the
    /// right answer for allow/deny entries an operator typed. Swap in the
    /// `publicsuffix` crate the day we need to reason about who *owns* a
    /// registrable domain (e.g. refusing a rule for the bare `co.uk`).
    pub fn is_within(&self, other: &Domain) -> bool {
        self.0 == other.0 || self.0.ends_with(&format!(".{}", other.0))
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Domain {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Domain {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Domain> for String {
    fn from(value: Domain) -> Self {
        value.0
    }
}

// ---------------------------------------------------------------------------
// Phone numbers
// ---------------------------------------------------------------------------

/// Why a string is not a usable [`E164`] or [`CallingCode`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PhoneError {
    #[error("E.164 numbers must start with '+'")]
    MissingPlus,
    #[error("E.164 numbers are 1..=15 digits, got {0}")]
    Length(usize),
    #[error("E.164 numbers are digits only, found {0:?}")]
    NotADigit(char),
    #[error("a number must not start with 0")]
    LeadingZero,
    #[error("calling codes are 1..=3 digits")]
    CallingCodeLength,
}

/// A phone number in E.164 form: `+` followed by 1..=15 digits, no separators.
///
/// There is no `country` field and there never will be one. The country a
/// number belongs to is a *function of the number*, so the gate computes it
/// instead of believing it — see [`E164::starts_with`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct E164(String);

impl E164 {
    /// Parse `+<digits>`. Whitespace around the number is tolerated; anything
    /// inside it is not.
    pub fn parse(raw: &str) -> Result<Self, PhoneError> {
        let digits = raw
            .trim()
            .strip_prefix('+')
            .ok_or(PhoneError::MissingPlus)?;
        if let Some(bad) = digits.chars().find(|c| !c.is_ascii_digit()) {
            return Err(PhoneError::NotADigit(bad));
        }
        if !(1..=15).contains(&digits.len()) {
            return Err(PhoneError::Length(digits.len()));
        }
        if digits.starts_with('0') {
            return Err(PhoneError::LeadingZero);
        }
        Ok(Self(format!("+{digits}")))
    }

    /// The number including its leading `+`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The digits without the leading `+`.
    pub fn digits(&self) -> &str {
        &self.0[1..]
    }

    /// Whether this number is routed by `code`. E.164 assignment is a prefix
    /// code — no calling code is a prefix of another — so prefix matching is
    /// exactly the routing rule, and needs no country table to be correct.
    pub fn starts_with(&self, code: CallingCode) -> bool {
        self.digits().starts_with(&code.as_u16().to_string())
    }
}

impl fmt::Display for E164 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for E164 {
    type Err = PhoneError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for E164 {
    type Error = PhoneError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<E164> for String {
    fn from(value: E164) -> Self {
        value.0
    }
}

/// An ITU country calling code: `86` for mainland China, `7` for Russia and
/// Kazakhstan, `1` for the NANP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct CallingCode(u16);

impl CallingCode {
    /// 1..=999, no leading zero.
    pub const fn new(code: u16) -> Result<Self, PhoneError> {
        if code == 0 || code > 999 {
            return Err(PhoneError::CallingCodeLength);
        }
        Ok(Self(code))
    }

    /// Parse `86` or `+86`.
    pub fn parse(raw: &str) -> Result<Self, PhoneError> {
        let digits = raw.trim().strip_prefix('+').unwrap_or(raw.trim());
        if let Some(bad) = digits.chars().find(|c| !c.is_ascii_digit()) {
            return Err(PhoneError::NotADigit(bad));
        }
        if digits.starts_with('0') {
            return Err(PhoneError::LeadingZero);
        }
        let code = digits
            .parse::<u16>()
            .map_err(|_| PhoneError::CallingCodeLength)?;
        Self::new(code)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for CallingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "+{}", self.0)
    }
}

impl FromStr for CallingCode {
    type Err = PhoneError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<u16> for CallingCode {
    type Error = PhoneError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CallingCode> for u16 {
    fn from(value: CallingCode) -> Self {
        value.0
    }
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

/// Why a string is not a usable [`EmailAddress`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EmailError {
    #[error("email address needs exactly one '@'")]
    Shape,
    #[error("local part must be 1..=64 characters")]
    LocalLength,
    #[error("local part may only contain A-Z, a-z, 0-9, '.', '_', '+' and '-', found {0:?}")]
    LocalCharset(char),
    #[error("local part must not start or end with '.'")]
    LocalBoundary,
    #[error("email domain: {0}")]
    Domain(#[from] DomainError),
}

/// `local@domain`, with the domain normalised as a [`Domain`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmailAddress {
    local: String,
    domain: Domain,
}

impl EmailAddress {
    /// Deliberately narrower than RFC 5322: no quoted strings, no comments, no
    /// routing syntax. Anything an address parser could disagree about is
    /// rejected rather than interpreted.
    pub fn parse(raw: &str) -> Result<Self, EmailError> {
        let raw = raw.trim();
        let (local, domain) = raw.split_once('@').ok_or(EmailError::Shape)?;
        if domain.contains('@') {
            return Err(EmailError::Shape);
        }
        if local.is_empty() || local.len() > 64 {
            return Err(EmailError::LocalLength);
        }
        if let Some(bad) = local
            .chars()
            .find(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '+' | '-'))
        {
            return Err(EmailError::LocalCharset(bad));
        }
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return Err(EmailError::LocalBoundary);
        }
        Ok(Self {
            local: local.to_ascii_lowercase(),
            domain: Domain::parse(domain)?,
        })
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub const fn domain(&self) -> &Domain {
        &self.domain
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl FromStr for EmailAddress {
    type Err = EmailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for EmailAddress {
    type Error = EmailError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<EmailAddress> for String {
    fn from(value: EmailAddress) -> Self {
        value.to_string()
    }
}

// ---------------------------------------------------------------------------
// Small supporting types
// ---------------------------------------------------------------------------

/// One tool on one MCP server. Both halves are [`Slug`]s, so an allowlist entry
/// and a call site cannot differ by casing or whitespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct McpTool {
    pub server: Slug,
    pub name: Slug,
}

impl McpTool {
    pub const fn new(server: Slug, name: Slug) -> Self {
        Self { server, name }
    }
}

impl fmt::Display for McpTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.server, self.name)
    }
}

/// What a delete request covers. Erasing one thread and erasing an employee's
/// entire history are different risks, so they are different values.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum DataScope {
    Conversation { id: ConversationId },
    AllForEmployee { id: EmployeeId },
}

/// The principal on whose behalf the action would run. Supplied by the host
/// from the authenticated session, never by the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Actor {
    pub tenant_id: TenantId,
    pub employee_id: EmployeeId,
}

impl Actor {
    pub const fn new(tenant_id: TenantId, employee_id: EmployeeId) -> Self {
        Self {
            tenant_id,
            employee_id,
        }
    }
}

/// Provenance of the text that produced this action.
///
/// `Untrusted` means some part of the prompt came from outside the tenant — a
/// web page, an inbound email, an MCP tool result. It is the taint bit that
/// keeps prompt injection away from irreversible side effects.
///
/// Re-exported rather than redefined: the taint an [`ActionCtx`] carries must be
/// the *same* type that [`crate::untrusted::Untrusted`] hands out, or the wire
/// from "this text came from a supplier PDF" to "the gate refuses to authorize a
/// payment" would need a lossy conversion at exactly the point where it matters.
pub use crate::untrusted::TrustLabel;

/// Whether the counterparty is someone this employee has dealt with before.
/// A host-supplied fact — the model does not get to declare an unknown number
/// "known" to dodge the cold-outreach budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactStanding {
    Known,
    New,
}

/// How much damage an action does if it turns out to have been steered by an
/// attacker. `High` means irreversible, expensive, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    High,
}

impl Risk {
    pub const fn is_high(self) -> bool {
        matches!(self, Risk::High)
    }
}

/// The transport an action speaks over, for channel allowlisting.
///
/// Same type as the one a [`crate::message::CanonicalMessage`] arrives on. A
/// policy that allows a channel and an inbound message that reports one must
/// agree by construction, not by a lookup table someone forgets to extend.
pub use crate::message::Channel;

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// The discriminant of an [`Action`], with no payload.
///
/// Exists so tests can enumerate the action space and so metrics have a stable
/// low-cardinality label. [`ActionKind::ALL`] is the enumeration; because
/// [`Action::kind`] is an exhaustive match with no `_` arm, a new `Action`
/// variant cannot be added without touching both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    EmailSend,
    SmsSend,
    WhatsappSend,
    CallPlace,
    BrowserRead,
    BrowserWrite,
    FileUpload,
    McpCall,
    A2aSend,
    PaymentCreate,
    InvoiceIssue,
    ContractSign,
    CredentialChange,
    DataDelete,
    CharterSet,
    InternalSend,
    AppointmentBook,
}

impl ActionKind {
    /// Every discriminant. Iterate this to prove a rule covers the whole space.
    pub const ALL: [ActionKind; 17] = [
        ActionKind::EmailSend,
        ActionKind::SmsSend,
        ActionKind::WhatsappSend,
        ActionKind::CallPlace,
        ActionKind::BrowserRead,
        ActionKind::BrowserWrite,
        ActionKind::FileUpload,
        ActionKind::McpCall,
        ActionKind::A2aSend,
        ActionKind::PaymentCreate,
        ActionKind::InvoiceIssue,
        ActionKind::ContractSign,
        ActionKind::CredentialChange,
        ActionKind::DataDelete,
        ActionKind::CharterSet,
        ActionKind::InternalSend,
        ActionKind::AppointmentBook,
    ];

    /// Stable metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionKind::EmailSend => "email_send",
            ActionKind::SmsSend => "sms_send",
            ActionKind::WhatsappSend => "whatsapp_send",
            ActionKind::CallPlace => "call_place",
            ActionKind::BrowserRead => "browser_read",
            ActionKind::BrowserWrite => "browser_write",
            ActionKind::FileUpload => "file_upload",
            ActionKind::McpCall => "mcp_call",
            ActionKind::A2aSend => "a2a_send",
            ActionKind::PaymentCreate => "payment_create",
            ActionKind::InvoiceIssue => "invoice_issue",
            ActionKind::ContractSign => "contract_sign",
            ActionKind::CredentialChange => "credential_change",
            ActionKind::DataDelete => "data_delete",
            ActionKind::CharterSet => "charter_set",
            ActionKind::InternalSend => "internal_send",
            ActionKind::AppointmentBook => "appointment_book",
        }
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every side effect the system can perform. Closed on purpose: if it is not
/// in here, no executor can be asked to do it.
///
/// Each variant carries the *parsed* subject of the effect and nothing else.
/// No variant carries a self-description that the gate then trusts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    EmailSend {
        to: EmailAddress,
    },
    SmsSend {
        to: E164,
    },
    WhatsappSend {
        to: E164,
    },
    /// The gate derives the destination country from `to`. There is no
    /// `country` field: a claim about the number is not the number.
    CallPlace {
        to: E164,
    },
    BrowserRead {
        domain: Domain,
    },
    BrowserWrite {
        domain: Domain,
    },
    FileUpload {
        domain: Domain,
    },
    McpCall {
        tool: McpTool,
    },
    A2aSend {
        peer: Domain,
    },
    PaymentCreate {
        amount: Money,
    },
    /// Ask a customer to pay us. Money in the other direction, and the one
    /// outbound act this enum was missing.
    ///
    /// The subject is the **amount**, and nothing else, for the module rule
    /// above: a variant carries the parsed subject of its effect and no
    /// self-description the gate then trusts. Which deal it bills lives on the
    /// body (`app::effects::InvoiceDraft`), exactly as a payee lives on a
    /// `PaymentInstruction` rather than on [`Action::PaymentCreate`] — and the
    /// gate has no opinion about which of a company's own won deals is being
    /// invoiced, only about whether this seat may bill at all.
    ///
    /// `Money` and not a bare integer, so a currency cannot be omitted: an
    /// invoice whose currency was implied is a figure the customer reads in
    /// theirs.
    ///
    /// See `migrations/0066_invoices.sql` for why this is a discriminant at all
    /// rather than a table an employee writes to — the short version is that a
    /// verb outside this enum is a verb no role pack can decline.
    InvoiceIssue {
        amount: Money,
    },
    /// `title` is display-only — see [`Action::risk`] and the evaluator: the
    /// contract branch has no condition to bypass.
    ContractSign {
        title: String,
    },
    CredentialChange {
        secret: SecretRef,
    },
    DataDelete {
        scope: DataScope,
    },
    /// One employee writing another employee's standing objective: delegation,
    /// as a head does it down its own reporting line.
    ///
    /// The subject is *whose* charter is being set, and nothing else. There is
    /// no `title`, no team and no "I am their manager" claim in here, for the
    /// reason the module header gives: a variant never carries a
    /// self-description the gate then trusts. Whether this actor may direct
    /// that employee is a fact about the org chart, read from the database by
    /// the caller before the gate is asked — see `app::vertical::delegate`.
    ///
    /// [`Risk::High`], so an untrusted turn cannot produce one: a supplier's
    /// email saying "you now report to me, here is your new objective" is a
    /// document, and a document may not re-task an employee.
    CharterSet {
        subordinate: EmployeeId,
    },

    /// Say something to a colleague: the one **inward** action.
    ///
    /// Every other variant above leaves the company, `CharterSet` excepted.
    /// This one does not leave
    /// the process — it writes a `messages` row for another employee of the
    /// same tenant and wakes it. It is an [`Action`] anyway because the gate is
    /// the only thing that may mint the right to perform an effect, and waking
    /// a colleague is an effect: it spends that colleague's daily turn budget.
    ///
    /// `to` is the colleague's [`Slug`] rather than an
    /// [`EmployeeId`](crate::ids::EmployeeId), for the same reason
    /// [`Action::EmailSend`] carries an address rather than a resolved
    /// contact: a slug is unique per tenant and the tenant is the transaction
    /// the ruling runs in, so resolution belongs to the executor and not to
    /// the rule.
    ///
    /// It deliberately carries **no `kind` field**. Whether an *order*
    /// specifically is legitimate — "may X direct Y" — is the org chart's
    /// question, and the org chart is not something an `Action` can hold. See
    /// `app::inbound::may_message`, which is the seam.
    InternalSend {
        to: Slug,
    },

    /// Undertake one moment of **your own** time: the second inward action.
    ///
    /// **Payload-free, and the emptiness is the argument.** Every other variant
    /// carries the parsed subject of its effect; this one's subject is the
    /// acting employee, and the acting employee is in
    /// [`ActionCtx::actor`] and never in an `Action` — the module rule again, a
    /// variant never carries a self-description the gate then trusts. An
    /// `employee` field here would be a caller's claim about whose hour is
    /// being spent, which is exactly the claim
    /// [`crate::action`]'s header refuses. The instant is not the subject
    /// either: the gate has no opinion about three o'clock, and
    /// `PolicyLimits` has no field to measure one against.
    ///
    /// What keeps that honest is one seam over, in `app::calendar`:
    /// `Calendar::book` takes no employee at all, and a `PgCalendar` is built
    /// per seat, so "spend somebody else's hour" is unrepresentable rather than
    /// merely refused.
    ///
    /// It is an `Action` — rather than a bare effect like posting work — for the
    /// reason `app::calendar`'s module docs give: [`ActionKind`] is the alphabet
    /// every role pack's `proposable` set is spelled with and the key
    /// `app::turn`'s catalogue is written in, so a verb outside it is a verb no
    /// policy layer can withhold and no role pack can decline. A finance clerk
    /// would hold the same power to promise a stranger an hour as a seller,
    /// forever, with nothing able to say no.
    AppointmentBook {},
}

impl Action {
    /// Alias for [`ActionKind::ALL`], so `Action::ALL_DISCRIMINANTS` reads at
    /// the call site.
    pub const ALL_DISCRIMINANTS: [ActionKind; 17] = ActionKind::ALL;

    /// Which discriminant this is. Exhaustive by construction — no `_` arm.
    pub const fn kind(&self) -> ActionKind {
        match self {
            Action::EmailSend { .. } => ActionKind::EmailSend,
            Action::SmsSend { .. } => ActionKind::SmsSend,
            Action::WhatsappSend { .. } => ActionKind::WhatsappSend,
            Action::CallPlace { .. } => ActionKind::CallPlace,
            Action::BrowserRead { .. } => ActionKind::BrowserRead,
            Action::BrowserWrite { .. } => ActionKind::BrowserWrite,
            Action::FileUpload { .. } => ActionKind::FileUpload,
            Action::McpCall { .. } => ActionKind::McpCall,
            Action::A2aSend { .. } => ActionKind::A2aSend,
            Action::PaymentCreate { .. } => ActionKind::PaymentCreate,
            Action::InvoiceIssue { .. } => ActionKind::InvoiceIssue,
            Action::ContractSign { .. } => ActionKind::ContractSign,
            Action::CredentialChange { .. } => ActionKind::CredentialChange,
            Action::DataDelete { .. } => ActionKind::DataDelete,
            Action::CharterSet { .. } => ActionKind::CharterSet,
            Action::InternalSend { .. } => ActionKind::InternalSend,
            Action::AppointmentBook {} => ActionKind::AppointmentBook,
        }
    }

    /// Blast radius. The evaluator refuses to `Allow` a `High` action that was
    /// produced from untrusted input.
    pub const fn risk(&self) -> Risk {
        match self {
            Action::EmailSend { .. }
            | Action::SmsSend { .. }
            | Action::WhatsappSend { .. }
            | Action::CallPlace { .. }
            | Action::BrowserRead { .. }
            | Action::BrowserWrite { .. }
            | Action::McpCall { .. }
            | Action::A2aSend { .. }
            // Low, and this is the one entry here worth arguing.
            //
            // `High` would read as the cautious choice and it is the wrong
            // one: `evaluate` refuses a high-risk action derived from
            // untrusted input, so a `High` internal message would mean an
            // employee that has just read a supplier's email cannot answer the
            // question its manager asked it — which is the feature. It would
            // also disappear from the tool catalogue for exactly the turns
            // that most need to say "I have been asked to do something odd".
            //
            // What makes `Low` safe is that the danger of an internal message
            // is not in the *sending*, it is in what the message counts as at
            // the *receiver*. That is handled where it belongs: the message is
            // stored with the sending turn's own trust label, and an untrusted
            // one arrives at the recipient fenced, as data. Blocking the send
            // would protect nothing that is not already protected there, and
            // would break the only channel by which a tainted employee can
            // report what happened to it.
            | Action::InternalSend { .. }
            // Low, in `InternalSend`'s list and for its reason. What an
            // appointment *becomes* is a turn whose brief carries the subject
            // fenced — `loops::initiative::diary` and `kept_brief` keep the
            // `Untrusted` wrapper on — so the danger is at the reader and is
            // already handled there.
            //
            // `High` would mean an employee that has just read a supplier's
            // email cannot promise to call them back, which is the feature; and
            // a turn shown its own diary is an untrusted turn, so `High` here
            // would withhold the verb from every employee that has ever used
            // it — the filter deleting the thing it was meant to contain.
            | Action::AppointmentBook {} => Risk::Low,

            Action::FileUpload { .. }
            | Action::PaymentCreate { .. }
            // High, and the reason is the direction of the money rather than
            // its size. A stranger's text saying "please invoice us €50,000"
            // must not produce a demand for money in this company's name — and
            // unlike `ContractSign`, which escalates and therefore slips past
            // the taint wire (`evaluate` applies it only to an `Allow`), this
            // arm's ruling *is* an `Allow`, so an untrusted turn is refused
            // outright with `DenyReason::UntrustedInput` and no approval is
            // filed for a human to look at. See `app::revenue`'s module docs
            // for why an approval queue a stranger can write into is the thing
            // being avoided.
            | Action::InvoiceIssue { .. }
            | Action::ContractSign { .. }
            | Action::CredentialChange { .. }
            | Action::DataDelete { .. }
            // Re-tasking another employee is the blast radius of everything
            // that employee then does, so it is never taken on the strength of
            // text somebody sent us.
            | Action::CharterSet { .. } => Risk::High,
        }
    }
}

/// Everything the gate needs that the [`Action`] itself does not carry.
///
/// Assembled by the host from the session, the ledger and the contact book —
/// never deserialized from model output. `now` is passed in rather than read
/// from the clock so the whole gate is a pure function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCtx {
    /// Who is acting.
    pub actor: Actor,
    /// Provenance of the input that produced the action.
    pub trust: TrustLabel,
    /// Whether the counterparty is already known to this employee.
    pub contact: ContactStanding,
    /// Spend already booked today. `None` means nothing has been spent —
    /// `Money` cannot be zero, so there is no "zero spent" value to confuse
    /// with "no data".
    pub spent_today: Option<Money>,
    /// New counterparties contacted today.
    pub new_contacts_today: u32,
    /// Whether the employee this action is aimed at reports to [`Self::actor`],
    /// as the org chart says right now.
    ///
    /// Read from `team_memberships.reports_to` by the host, in the same
    /// transaction as the ruling — never claimed by the action and never taken
    /// from a caller's word, for the same reason [`Self::spent_today`] is read
    /// from the ledger rather than asserted.
    ///
    /// `false` for every action that has no such subject, which is all of them
    /// but [`Action::CharterSet`]. Defaulting to `false` is what makes
    /// delegation deny-by-default: a context nobody filled in authorises
    /// nothing, exactly like an empty [`crate::policy::PolicyLimits`].
    ///
    /// It is emphatically **not** a capability. It says who this employee may
    /// direct, never what it may do: no rule in `policy::evaluate` reads it
    /// except the one that decides whether a charter may be written for that
    /// one named employee, and no layer of the policy stack can set it.
    pub directs_subject: bool,
    /// The decision instant.
    pub now: DateTime<Utc>,
}

impl ActionCtx {
    /// The safest context: untrusted input, unknown counterparty, no history,
    /// no authority over anybody. Callers widen from here as they learn more.
    pub const fn new(actor: Actor, now: DateTime<Utc>) -> Self {
        Self {
            actor,
            trust: TrustLabel::Untrusted,
            contact: ContactStanding::New,
            spent_today: None,
            new_contacts_today: 0,
            directs_subject: false,
            now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shape of `CallPlace` is asserted at compile time: this line only
    // typechecks while the variant has exactly one field, `to: E164`. Adding a
    // caller-supplied `country` back would break the build here, which is the
    // strongest form the "not even expressible" test can take.
    const _CALL_PLACE_TAKES_ONLY_A_NUMBER: fn(E164) -> Action = |to| Action::CallPlace { to };

    #[test]
    fn domain_normalisation_collapses_respellings() {
        let canonical = Domain::parse("banking.example.com").unwrap();
        for spelling in [
            "banking.example.com",
            "BANKING.example.com",
            "banking.EXAMPLE.CoM",
            "banking.example.com.",
            "  banking.example.com  ",
        ] {
            assert_eq!(
                Domain::parse(spelling).unwrap(),
                canonical,
                "{spelling:?} did not normalise"
            );
        }
        // Full-width confusables map through IDNA to the same ASCII host.
        assert_eq!(
            Domain::parse("ｂａｎｋｉｎｇ.example.com").unwrap(),
            canonical
        );
        // Real IDN becomes punycode, deterministically.
        assert_eq!(
            Domain::parse("münchen.de").unwrap().as_str(),
            "xn--mnchen-3ya.de"
        );
    }

    #[test]
    fn domain_rejects_things_that_are_not_bare_hosts() {
        for bad in [
            "",
            "  ",
            ".",
            "https://example.com",
            "example.com/path",
            "user@example.com",
            "example.com:443",
            "example com",
            "localhost",
            "127.0.0.1",
        ] {
            assert!(Domain::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// **A name that only resolves inside a network cannot be built.**
    ///
    /// This is the half of the browsing change that is not in `policy.rs`.
    /// While a read had to clear `allowed_domains`, an internal name was
    /// refused for not being on a list somebody typed. Reading now clears
    /// `Channel::Web` and the denylist only — the whole public web — so
    /// "public" has to mean something, and the only place it can mean anything
    /// is here, at the one constructor.
    ///
    /// Both halves are asserted: the value cannot be *read*, and it cannot be
    /// *blocked* either, because a denylist entry is a `Domain` too. That is
    /// the right trade — an operator cannot block what nobody can name.
    #[test]
    fn a_name_inside_somebody_s_network_is_not_a_domain() {
        for host in [
            "printer.local",
            "vault.internal",
            "api.home.arpa",
            "app.localhost",
            // The bare reserved labels, which `TooFewLabels` also refuses —
            // asserted here so that relaxing the two-label rule cannot quietly
            // let them back in.
            "localhost",
            "local",
        ] {
            assert!(
                Domain::parse(host).is_err(),
                "{host} parsed, and a policy that grants the public web would read it"
            );
        }

        // Reserved against collision rather than against routing. These reach
        // nothing, so refusing them buys nothing — and every fixture in this
        // workspace would break.
        for host in [
            "example.com",
            "nordmetall.example",
            "shop.test",
            "orizn.app",
        ] {
            assert!(Domain::parse(host).is_ok(), "{host} was refused");
        }

        // Not a suffix match on the raw string: a real public host that merely
        // ends in those letters is public.
        for host in ["mylocal.com", "internal-affairs.gov.uk", "local.orizn.app"] {
            assert!(Domain::parse(host).is_ok(), "{host} was refused");
        }
    }

    #[test]
    fn is_within_matches_at_label_boundaries_only() {
        let entry = Domain::parse("banking.example.com").unwrap();

        for inside in [
            "banking.example.com",
            "login.banking.example.com",
            "a.b.banking.example.com",
        ] {
            assert!(Domain::parse(inside).unwrap().is_within(&entry), "{inside}");
        }
        for outside in [
            "example.com",
            "evilbanking.example.com",
            "banking.example.com.evil.com",
            "banking.example.org",
        ] {
            assert!(
                !Domain::parse(outside).unwrap().is_within(&entry),
                "{outside}"
            );
        }
    }

    #[test]
    fn e164_parses_and_derives_its_own_calling_code() {
        let cn = E164::parse("+8613800000000").unwrap();
        let ru = E164::parse("+79991234567").unwrap();
        let china = CallingCode::parse("+86").unwrap();

        assert!(cn.starts_with(china));
        assert!(!ru.starts_with(china));
        assert_eq!(cn.digits(), "8613800000000");
        assert_eq!(cn.to_string(), "+8613800000000");
    }

    #[test]
    fn e164_rejects_anything_a_dialler_could_misread() {
        for bad in [
            "8613800000000",
            "+",
            "+0123456",
            "+86 138 0000 0000",
            "+86-138",
            "+1234567890123456",
            "+86a",
            "",
        ] {
            assert!(E164::parse(bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(
            E164::parse("  +8613800000000 ").unwrap().digits(),
            "8613800000000"
        );
    }

    #[test]
    fn calling_code_bounds() {
        assert!(CallingCode::new(0).is_err());
        assert!(CallingCode::new(1000).is_err());
        assert_eq!(CallingCode::parse("86").unwrap().as_u16(), 86);
        assert_eq!(
            CallingCode::parse("+86").unwrap(),
            CallingCode::new(86).unwrap()
        );
        assert!(CallingCode::parse("+086").is_err());
        assert_eq!(CallingCode::new(86).unwrap().to_string(), "+86");
    }

    #[test]
    fn email_parses_into_a_normalised_domain() {
        let addr = EmailAddress::parse("Lena.Wu+po@Supplier.Example.COM").unwrap();
        assert_eq!(addr.local(), "lena.wu+po");
        assert_eq!(addr.domain().as_str(), "supplier.example.com");
        assert_eq!(addr.to_string(), "lena.wu+po@supplier.example.com");

        for bad in [
            "lena",
            "@example.com",
            "lena@",
            "a@b@c.com",
            ".lena@x.com",
            "lena@localhost",
        ] {
            assert!(EmailAddress::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn kind_covers_every_variant_exactly_once() {
        let mut seen = ActionKind::ALL.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), ActionKind::ALL.len(), "duplicate discriminant");
        assert_eq!(Action::ALL_DISCRIMINANTS.len(), 17);
    }

    /// Fourteen of the seventeen actions leave the company. The three that do
    /// not are `CharterSet`, the internal channel and `AppointmentBook`; the
    /// latter two are deliberately `Low`, see the paragraph on
    /// [`Action::risk`].
    //
    // Two waves added a sixteenth kind at the same time — `InvoiceIssue` and
    // `AppointmentBook` — and the count in this sentence is the only place the
    // collision was not a compile error. That is why it is a sentence about a
    // partition and not a number on its own: `ALL.len()` is checked below, and
    // whoever adds an eighteenth has to decide which side it falls on.
    #[test]
    fn talking_to_a_colleague_is_low_risk_and_has_no_counterparty() {
        let internal = Action::InternalSend {
            to: Slug::parse("bruno").unwrap(),
        };
        assert_eq!(internal.kind(), ActionKind::InternalSend);
        assert_eq!(internal.risk(), Risk::Low);
        assert_eq!(internal.kind().as_str(), "internal_send");
    }

    /// **Promising an hour carries no subject at all**, which is the security
    /// property rather than an ergonomic one.
    ///
    /// Written as a compile-time assertion and not only as a value: this line
    /// typechecks exactly while `AppointmentBook` has no fields, so adding an
    /// `employee`, an `at` or a `zone` to it breaks the build here. That is the
    /// strongest form "whose hour is spent is not something a caller may claim"
    /// can take — the same shape as `_CALL_PLACE_TAKES_ONLY_A_NUMBER` above.
    #[test]
    fn promising_an_hour_names_nobody_and_is_low_risk() {
        const _APPOINTMENT_TAKES_NOTHING: fn() -> Action = || Action::AppointmentBook {};

        let hour = Action::AppointmentBook {};
        assert_eq!(hour.kind(), ActionKind::AppointmentBook);
        assert_eq!(hour.risk(), Risk::Low);
        assert_eq!(hour.kind().as_str(), "appointment_book");
        // The wire form has the tag and nothing else, so there is no field a
        // forged payload could set — the `call_place` test below proves the
        // same point for a variant that does have one.
        assert_eq!(
            serde_json::to_string(&hour).unwrap(),
            r#"{"action":"appointment_book"}"#
        );
    }

    #[test]
    fn action_round_trips_through_json() {
        let action = Action::CallPlace {
            to: E164::parse("+8613800000000").unwrap(),
        };
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, r#"{"action":"call_place","to":"+8613800000000"}"#);
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), action);

        // And a country cannot be smuggled in through the wire either: the
        // field simply is not part of the variant.
        let forged = r#"{"action":"call_place","to":"+79991234567","country":"CN"}"#;
        let parsed: Action = serde_json::from_str(forged).unwrap();
        assert_eq!(
            parsed,
            Action::CallPlace {
                to: E164::parse("+79991234567").unwrap()
            }
        );
    }
}
