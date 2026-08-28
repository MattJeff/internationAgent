//! Identifiers, slugs, secret references and idempotency keys.
//!
//! Every id here is a distinct newtype over [`Uuid`], so the compiler rejects
//! passing a [`TenantId`] where an [`EmployeeId`] belongs. Ids are UUIDv7, so
//! they sort by creation time and keep Postgres index inserts local.
//!
//! Nothing in this module reads the clock: construction takes `now` so the
//! callers stay testable.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use uuid::{NoContext, Timestamp, Uuid};

/// UUIDv7 stamped with an explicit instant. Pre-epoch instants clamp to the
/// epoch — a negative timestamp has no representation in v7 anyway.
fn uuid_v7_at(now: DateTime<Utc>) -> Uuid {
    let seconds = u64::try_from(now.timestamp()).unwrap_or(0);
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        seconds,
        now.timestamp_subsec_nanos(),
    ))
}

macro_rules! uuid_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh time-ordered id stamped at `now`.
            pub fn new_v7(now: DateTime<Utc>) -> Self {
                Self(uuid_v7_at(now))
            }

            /// Rehydrate an id that already exists (database row, request path).
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// The wrapped UUID, for storage and wire formats only.
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

uuid_newtype!(
    /// The organisation an employee, conversation or secret belongs to.
    TenantId
);
uuid_newtype!(
    /// One AI employee.
    EmployeeId
);
uuid_newtype!(
    /// One conversation thread with an employee.
    ConversationId
);
uuid_newtype!(
    /// One human approval request.
    ApprovalId
);
uuid_newtype!(
    /// One recorded policy decision.
    DecisionId
);
uuid_newtype!(
    /// One item on a company's shared work board.
    /// See `migrations/0061_work_items.sql`.
    WorkItemId
);

// ---------------------------------------------------------------------------
// Slug
// ---------------------------------------------------------------------------

/// Why a candidate string is not a usable [`Slug`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlugError {
    /// Outside `2..=32` characters after normalisation.
    #[error(
        "slug must be {min}..={max} characters after normalisation, got {got}",
        min = Slug::MIN_LEN,
        max = Slug::MAX_LEN
    )]
    Length {
        /// Length after NFKC + lowercasing.
        got: usize,
    },
    /// A character that is not `a-z`, `0-9` or `-` survived normalisation.
    #[error("slug may only contain a-z, 0-9 and '-', found {found:?}")]
    Charset {
        /// The first offending character.
        found: char,
    },
    /// Leading or trailing hyphen.
    #[error("slug must start and end with a letter or digit")]
    Boundary,
    /// Two hyphens in a row.
    #[error("slug must not contain consecutive hyphens")]
    ConsecutiveHyphens,
}

/// A validated employee handle.
///
/// A slug becomes the local part of an email address *and* a DNS label, so it
/// is deliberately narrower than either: NFKC-folded, lowercased, and then
/// restricted to `[a-z0-9-]` with no leading, trailing or doubled hyphen.
///
/// The NFKC fold happens *before* validation, so compatibility confusables
/// (full-width `ｌｅｎａ`, ligatures, superscripts) collapse into plain ASCII
/// and are accepted as their ASCII form; anything that does not collapse into
/// `[a-z0-9-]` is rejected. That is what makes two different-looking inputs
/// unable to produce two different slugs that render alike.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Slug(String);

impl Slug {
    /// Shortest accepted slug.
    pub const MIN_LEN: usize = 2;
    /// Longest accepted slug (fits a DNS label with room to spare).
    pub const MAX_LEN: usize = 32;

    /// Normalise and validate. This is the only way to build a `Slug`.
    pub fn parse(raw: &str) -> Result<Self, SlugError> {
        let normalized: String = raw.nfkc().flat_map(char::to_lowercase).collect();

        if let Some(found) = normalized
            .chars()
            .find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-'))
        {
            return Err(SlugError::Charset { found });
        }

        // Every remaining char is ASCII, so bytes == chars.
        let len = normalized.len();
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&len) {
            return Err(SlugError::Length { got: len });
        }
        if normalized.starts_with('-') || normalized.ends_with('-') {
            return Err(SlugError::Boundary);
        }
        if normalized.contains("--") {
            return Err(SlugError::ConsecutiveHyphens);
        }

        Ok(Self(normalized))
    }

    /// The normalised slug text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Slug {
    type Err = SlugError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Slug {
    type Error = SlugError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Slug> for String {
    fn from(slug: Slug) -> Self {
        slug.0
    }
}

// ---------------------------------------------------------------------------
// SecretRef
// ---------------------------------------------------------------------------

/// Why a string is not a usable [`SecretRef`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    /// Missing the `secret://` scheme.
    #[error("secret ref must start with `secret://`")]
    Scheme,
    /// Wrong segment count or wrong literal segments.
    #[error("secret ref must look like secret://tenant/{{tenant}}/employee/{{employee}}/{{name}}")]
    Shape,
    /// A path segment that should be a UUID is not one.
    #[error("secret ref {field} is not a uuid")]
    NotAUuid {
        /// `tenant` or `employee`.
        field: &'static str,
    },
    /// Secret name empty or too long.
    #[error(
        "secret name must be 1..={max} characters",
        max = SecretRef::MAX_NAME_LEN
    )]
    NameLength,
    /// Secret name contains something other than `[A-Za-z0-9_-]`.
    #[error("secret name may only contain A-Z, a-z, 0-9, '_' and '-', found {found:?}")]
    NameCharset {
        /// The first offending character.
        found: char,
    },
}

/// A parsed pointer into the secret store, scoped to a tenant and an employee.
///
/// This is untrusted input — an LLM can emit any string — so it is parsed into
/// its parts rather than pattern-matched. The scoping segments are UUIDs and
/// the name excludes `.` and `/`, which is what makes path traversal
/// unrepresentable: there is no way to spell `..` in a `SecretRef`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef {
    tenant_id: TenantId,
    employee_id: EmployeeId,
    name: String,
}

impl SecretRef {
    /// Longest accepted secret name.
    pub const MAX_NAME_LEN: usize = 64;

    /// Build a ref from already-trusted parts. The name is still validated.
    pub fn new(
        tenant_id: TenantId,
        employee_id: EmployeeId,
        name: &str,
    ) -> Result<Self, SecretRefError> {
        if name.is_empty() || name.len() > Self::MAX_NAME_LEN {
            return Err(SecretRefError::NameLength);
        }
        if let Some(found) = name
            .chars()
            .find(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-'))
        {
            return Err(SecretRefError::NameCharset { found });
        }
        Ok(Self {
            tenant_id,
            employee_id,
            name: name.to_owned(),
        })
    }

    /// Parse `secret://tenant/{tenant}/employee/{employee}/{name}`.
    pub fn parse(raw: &str) -> Result<Self, SecretRefError> {
        let rest = raw
            .strip_prefix("secret://")
            .ok_or(SecretRefError::Scheme)?;

        let segments: Vec<&str> = rest.split('/').collect();
        let ["tenant", tenant, "employee", employee, name] = segments[..] else {
            return Err(SecretRefError::Shape);
        };

        let tenant_id =
            TenantId::from_str(tenant).map_err(|_| SecretRefError::NotAUuid { field: "tenant" })?;
        let employee_id = EmployeeId::from_str(employee)
            .map_err(|_| SecretRefError::NotAUuid { field: "employee" })?;

        Self::new(tenant_id, employee_id, name)
    }

    /// The tenant this secret is scoped to; compare against the acting principal.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// The employee this secret is scoped to; compare against the acting principal.
    pub const fn employee_id(&self) -> EmployeeId {
        self.employee_id
    }

    /// The secret's name within its scope.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "secret://tenant/{}/employee/{}/{}",
            self.tenant_id, self.employee_id, self.name
        )
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for SecretRef {
    type Error = SecretRefError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.to_string()
    }
}

// ---------------------------------------------------------------------------
// IdempotencyKey
// ---------------------------------------------------------------------------

/// Why a client-supplied idempotency key is rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdempotencyKeyError {
    /// Outside the accepted length window.
    #[error(
        "idempotency key must be {min}..={max} characters",
        min = IdempotencyKey::MIN_CLIENT_LEN,
        max = IdempotencyKey::MAX_CLIENT_LEN
    )]
    Length,
    /// Contains whitespace, a control character or a non-ASCII byte.
    #[error("idempotency key must be printable ASCII without spaces, found {found:?}")]
    Charset {
        /// The first offending character.
        found: char,
    },
}

/// A stable de-duplication token for an at-most-once side effect.
///
/// [`IdempotencyKey::for_step`] is a pure function of its inputs — no clock, no
/// randomness — so a provisioning run that is retried after a crash produces
/// the same key and the provider hands back the phone number it already sold
/// us instead of selling a second one.
///
/// Client keys are prefixed, so a caller cannot craft a header value that
/// collides with an internal provisioning key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Shortest accepted client key — short keys collide by accident.
    pub const MIN_CLIENT_LEN: usize = 8;
    /// Longest accepted client key.
    pub const MAX_CLIENT_LEN: usize = 200;

    /// The key for one provisioning step of one employee.
    ///
    /// Deterministic and stable across processes: same inputs, same key,
    /// forever. Do not make this hash, salt or timestamp anything.
    pub fn for_step(employee: EmployeeId, step_name: &str) -> Self {
        Self(format!("employee:{employee}:step:{step_name}"))
    }

    /// Accept an `Idempotency-Key` header value.
    pub fn from_client(raw: &str) -> Result<Self, IdempotencyKeyError> {
        if !(Self::MIN_CLIENT_LEN..=Self::MAX_CLIENT_LEN).contains(&raw.len()) {
            return Err(IdempotencyKeyError::Length);
        }
        if let Some(found) = raw.chars().find(|c| !c.is_ascii_graphic()) {
            return Err(IdempotencyKeyError::Charset { found });
        }
        Ok(Self(format!("client:{raw}")))
    }

    /// The key as stored and sent to providers.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = IdempotencyKeyError;

    /// Rehydrate a stored key. Both flavours are already prefixed, so this only
    /// re-checks the shape invariants.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > Self::MAX_CLIENT_LEN + "client:".len() {
            return Err(IdempotencyKeyError::Length);
        }
        if let Some(found) = value.chars().find(|c| !c.is_ascii_graphic()) {
            return Err(IdempotencyKeyError::Charset { found });
        }
        Ok(Self(value))
    }
}

impl From<IdempotencyKey> for String {
    fn from(value: IdempotencyKey) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    // -- ids ---------------------------------------------------------------

    #[test]
    fn ids_round_trip_as_plain_uuid_strings() {
        let id = EmployeeId::new_v7(at(1_700_000_000));
        let json = serde_json::to_string(&id).unwrap();

        assert_eq!(json, format!("\"{}\"", id.as_uuid()));
        assert_eq!(serde_json::from_str::<EmployeeId>(&json).unwrap(), id);

        // And the same wire shape as a bare Uuid, so columns stay compatible.
        let uuid = id.as_uuid();
        assert_eq!(json, serde_json::to_string(&uuid).unwrap());
    }

    #[test]
    fn ids_are_v7_and_sort_by_creation_time() {
        let mut previous = EmployeeId::new_v7(at(1_700_000_000));
        assert_eq!(previous.as_uuid().get_version_num(), 7);

        for offset in 1..100 {
            let next = EmployeeId::new_v7(at(1_700_000_000 + offset));
            assert!(previous < next, "{previous} should sort before {next}");
            previous = next;
        }
    }

    #[test]
    fn id_display_and_from_str_round_trip() {
        let id = TenantId::new_v7(at(1_700_000_000));
        assert_eq!(TenantId::from_str(&id.to_string()).unwrap(), id);
        assert!(TenantId::from_str("not-a-uuid").is_err());
    }

    // -- slug --------------------------------------------------------------

    #[test]
    fn slug_accepts_well_formed_handles() {
        for good in ["lena", "lena-2", "a1", "a-b-c-d", &"x".repeat(32)] {
            assert!(Slug::parse(good).is_ok(), "expected {good:?} to parse");
        }
        assert_eq!(Slug::parse("LeNa").unwrap().as_str(), "lena");
    }

    #[test]
    fn slug_rejects_anything_an_address_parser_could_misread() {
        assert!(matches!(
            Slug::parse("a@b"),
            Err(SlugError::Charset { found: '@' })
        ));
        assert!(matches!(
            Slug::parse("\n"),
            Err(SlugError::Charset { found: '\n' })
        ));
        assert!(matches!(
            Slug::parse("le na"),
            Err(SlugError::Charset { found: ' ' })
        ));
        // "A" lowercases to "a": one character, below the floor.
        assert!(matches!(
            Slug::parse("A"),
            Err(SlugError::Length { got: 1 })
        ));
        assert!(matches!(Slug::parse(""), Err(SlugError::Length { got: 0 })));
        assert!(matches!(
            Slug::parse(&"x".repeat(33)),
            Err(SlugError::Length { got: 33 })
        ));
        assert!(matches!(Slug::parse("-lena"), Err(SlugError::Boundary)));
        assert!(matches!(Slug::parse("lena-"), Err(SlugError::Boundary)));
        assert!(matches!(
            Slug::parse("-"),
            Err(SlugError::Length { got: 1 })
        ));
        assert!(matches!(Slug::parse("--"), Err(SlugError::Boundary)));
        assert!(matches!(
            Slug::parse("le--na"),
            Err(SlugError::ConsecutiveHyphens)
        ));
    }

    /// Deliberate choice: NFKC runs *before* validation, so compatibility
    /// confusables fold into ASCII and are ACCEPTED as their ASCII form. Two
    /// spellings can therefore never yield two distinct look-alike slugs —
    /// they yield the same slug, and the uniqueness index rejects the second.
    #[test]
    fn slug_folds_confusables_into_ascii_instead_of_minting_a_lookalike() {
        assert_eq!(Slug::parse("ｌｅｎａ").unwrap().as_str(), "lena");
        assert_eq!(
            Slug::parse("ｌｅｎａ").unwrap(),
            Slug::parse("lena").unwrap()
        );
        // Cyrillic "а" is not a compatibility equivalent of "a" — no fold, reject.
        assert!(matches!(
            Slug::parse("len\u{0430}"),
            Err(SlugError::Charset { found: '\u{0430}' })
        ));
    }

    #[test]
    fn slug_serde_validates_on_the_way_in() {
        let slug = Slug::parse("lena-2").unwrap();
        assert_eq!(serde_json::to_string(&slug).unwrap(), "\"lena-2\"");
        assert_eq!(serde_json::from_str::<Slug>("\"lena-2\"").unwrap(), slug);
        assert!(serde_json::from_str::<Slug>("\"-lena\"").is_err());
    }

    // -- idempotency -------------------------------------------------------

    #[test]
    fn for_step_is_stable_across_calls() {
        let employee = EmployeeId::new_v7(at(1_700_000_000));
        let first = IdempotencyKey::for_step(employee, "phone");

        for _ in 0..100 {
            assert_eq!(IdempotencyKey::for_step(employee, "phone"), first);
        }
    }

    #[test]
    fn for_step_separates_steps_and_employees() {
        let a = EmployeeId::new_v7(at(1_700_000_000));
        let b = EmployeeId::new_v7(at(1_700_000_001));

        assert_ne!(
            IdempotencyKey::for_step(a, "phone"),
            IdempotencyKey::for_step(a, "wallet")
        );
        assert_ne!(
            IdempotencyKey::for_step(a, "phone"),
            IdempotencyKey::for_step(b, "phone")
        );
    }

    #[test]
    fn client_keys_are_bounded_and_cannot_forge_a_step_key() {
        let employee = EmployeeId::new_v7(at(1_700_000_000));
        let step = IdempotencyKey::for_step(employee, "phone");

        // A client replaying the internal key verbatim lands in its own namespace.
        let forged = IdempotencyKey::from_client(step.as_str()).unwrap();
        assert_ne!(forged, step);

        assert!(IdempotencyKey::from_client("short").is_err());
        assert!(IdempotencyKey::from_client(&"x".repeat(201)).is_err());
        assert!(matches!(
            IdempotencyKey::from_client("has space"),
            Err(IdempotencyKeyError::Charset { found: ' ' })
        ));
        assert!(matches!(
            IdempotencyKey::from_client("has\nnewline"),
            Err(IdempotencyKeyError::Charset { found: '\n' })
        ));
        assert!(IdempotencyKey::from_client("abcd-1234").is_ok());
    }

    // -- secret refs -------------------------------------------------------

    fn secret_ref_text(name: &str) -> (TenantId, EmployeeId, String) {
        let tenant = TenantId::new_v7(at(1_700_000_000));
        let employee = EmployeeId::new_v7(at(1_700_000_001));
        let text = format!("secret://tenant/{tenant}/employee/{employee}/{name}");
        (tenant, employee, text)
    }

    #[test]
    fn secret_ref_parses_and_exposes_its_scope() {
        let (tenant, employee, text) = secret_ref_text("smtp_password");
        let parsed = SecretRef::parse(&text).unwrap();

        assert_eq!(parsed.tenant_id(), tenant);
        assert_eq!(parsed.employee_id(), employee);
        assert_eq!(parsed.name(), "smtp_password");
        assert_eq!(parsed.to_string(), text);
        assert_eq!(SecretRef::parse(&parsed.to_string()).unwrap(), parsed);
    }

    #[test]
    fn secret_ref_rejects_hostile_input() {
        let (_, _, valid) = secret_ref_text("smtp_password");

        // Missing scheme.
        assert_eq!(
            SecretRef::parse(valid.trim_start_matches("secret://")),
            Err(SecretRefError::Scheme)
        );
        assert_eq!(
            SecretRef::parse("https://tenant/x/employee/y/z"),
            Err(SecretRefError::Scheme)
        );

        // Traversal: extra segments and a dotted name are both unrepresentable.
        let (_, _, traversal) = secret_ref_text("../../other/api_key");
        assert_eq!(SecretRef::parse(&traversal), Err(SecretRefError::Shape));
        let (_, _, dotted) = secret_ref_text("..");
        assert_eq!(
            SecretRef::parse(&dotted),
            Err(SecretRefError::NameCharset { found: '.' })
        );

        // Wrong segment count / wrong literals.
        assert_eq!(
            SecretRef::parse("secret://tenant/x/employee/y"),
            Err(SecretRefError::Shape)
        );
        let (tenant, employee, _) = secret_ref_text("x");
        assert_eq!(
            SecretRef::parse(&format!("secret://org/{tenant}/employee/{employee}/x")),
            Err(SecretRefError::Shape)
        );

        // Embedded newline in the name.
        let (_, _, newline) = secret_ref_text("api\nkey");
        assert_eq!(
            SecretRef::parse(&newline),
            Err(SecretRefError::NameCharset { found: '\n' })
        );

        // Non-uuid scope segments.
        assert_eq!(
            SecretRef::parse("secret://tenant/acme/employee/lena/api_key"),
            Err(SecretRefError::NotAUuid { field: "tenant" })
        );

        // Name bounds.
        let (_, _, empty_name) = secret_ref_text("");
        assert_eq!(
            SecretRef::parse(&empty_name),
            Err(SecretRefError::NameLength)
        );
        let (_, _, long_name) = secret_ref_text(&"x".repeat(65));
        assert_eq!(
            SecretRef::parse(&long_name),
            Err(SecretRefError::NameLength)
        );
    }

    #[test]
    fn secret_ref_serde_round_trips_as_a_string() {
        let (_, _, text) = secret_ref_text("api_key");
        let parsed = SecretRef::parse(&text).unwrap();
        let json = serde_json::to_string(&parsed).unwrap();

        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(serde_json::from_str::<SecretRef>(&json).unwrap(), parsed);
        assert!(serde_json::from_str::<SecretRef>("\"nope\"").is_err());
    }
}
