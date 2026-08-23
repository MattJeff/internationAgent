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
}

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
    ContractSign,
    CredentialChange,
    DataDelete,
}

impl ActionKind {
    /// Every discriminant. Iterate this to prove a rule covers the whole space.
    pub const ALL: [ActionKind; 13] = [
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
        ActionKind::ContractSign,
        ActionKind::CredentialChange,
        ActionKind::DataDelete,
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
            ActionKind::ContractSign => "contract_sign",
            ActionKind::CredentialChange => "credential_change",
            ActionKind::DataDelete => "data_delete",
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
}

impl Action {
    /// Alias for [`ActionKind::ALL`], so `Action::ALL_DISCRIMINANTS` reads at
    /// the call site.
    pub const ALL_DISCRIMINANTS: [ActionKind; 13] = ActionKind::ALL;

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
            Action::ContractSign { .. } => ActionKind::ContractSign,
            Action::CredentialChange { .. } => ActionKind::CredentialChange,
            Action::DataDelete { .. } => ActionKind::DataDelete,
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
            | Action::A2aSend { .. } => Risk::Low,

            Action::FileUpload { .. }
            | Action::PaymentCreate { .. }
            | Action::ContractSign { .. }
            | Action::CredentialChange { .. }
            | Action::DataDelete { .. } => Risk::High,
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
    /// The decision instant.
    pub now: DateTime<Utc>,
}

impl ActionCtx {
    /// The safest context: untrusted input, unknown counterparty, no history.
    /// Callers widen from here as they learn more.
    pub const fn new(actor: Actor, now: DateTime<Utc>) -> Self {
        Self {
            actor,
            trust: TrustLabel::Untrusted,
            contact: ContactStanding::New,
            spent_today: None,
            new_contacts_today: 0,
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
        assert_eq!(Action::ALL_DISCRIMINANTS.len(), 13);
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
