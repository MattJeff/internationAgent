//! RFC 9421 HTTP Message Signatures, Ed25519, over the JWKS this deployment
//! already publishes.
//!
//! # Why this format and not a header of our own
//!
//! A bespoke `X-Fabrikam-Signature: <base64>` is about forty lines and works
//! this afternoon. It is also a format with exactly one implementation, which
//! means every counterparty who wants to verify us has to be told what to hash,
//! in what order, with which encoding — and told again the first time somebody
//! adds a header to the covered set. That conversation is the cost, and it is
//! paid once per counterparty, forever.
//!
//! RFC 9421 is the same forty lines plus a canonicalisation nobody has to
//! explain, and it is what actually shipped: Cloudflare's Web Bot Auth signs
//! with RFC 9421 over Ed25519 and publishes a JWKS at
//! [`DIRECTORY_PATH`](agentos_domain::identity::DIRECTORY_PATH), which is the
//! endpoint `routes::well_known` already serves, at that path, with that media
//! type. The previous wave chose this before this module existed —
//! `agentos_providers::signing::Signature::to_base64` documents itself as "the
//! RFC 8941 byte-sequence encoding RFC 9421 puts inside a `Signature:` header"
//! — so the honest description of this file is that it finishes a decision, not
//! that it makes one.
//!
//! What that buys concretely: a peer running Cloudflare's verifier, or any of
//! the `http-message-signatures` libraries, verifies us with configuration
//! rather than code.
//!
//! # No dependency was added for it
//!
//! ponytail: the signature base is a canonical string, and building it is
//! `format!`. There is no RFC 9421 crate in `Cargo.lock` and pulling one in for
//! string concatenation plus a `sha2` call — both already here — would be the
//! most expensive way to write [`base`]. The day this needs the full component
//! grammar (structured-field parameters, `@request-response`, byte-sequence
//! headers) is the day to reach for one.
//!
//! # The profile
//!
//! One signature, labelled [`LABEL`], covering:
//!
//! ```text
//! ("@method" "@authority" "@path" "@query" "content-digest")
//! ```
//!
//! `content-digest` is what makes the body covered — RFC 9421 signs headers,
//! not bodies, so a signature without it proves only that somebody addressed
//! this URL. [`verify_request`] therefore refuses a signature that does not
//! cover it, and refuses one whose `Content-Digest` disagrees with the bytes
//! that arrived. `@query` is covered because our own A2A endpoint carries
//! `?employee=<uuid>`: leaving it out would let a signature for one employee's
//! endpoint be replayed against another's.
//!
//! # What verifying proves, and what it does not
//!
//! It proves **who** sent these bytes and that they are unaltered. It says
//! nothing whatever about whether the content is safe, and a verified peer is
//! still a stranger's agent: everything it sends stays
//! [`Untrusted`](agentos_domain::untrusted::Untrusted). A verified signature is
//! never a reason to unwrap one.
//!
//! ponytail: no replay cache. `created`/`expires` bound the window to
//! [`LIFETIME`], which is the same protection every bearer credential on the
//! wire has and is the property a verifier can check with no state. A nonce
//! table is the upgrade path, and it is worth building the day an idempotent
//! replay actually costs something — for `SendMessage` it appends a duplicate
//! turn, not money.

use agentos_domain::identity::{KeyId, PublicKey};
use agentos_providers::signing::{Signature, verify};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};

/// The signature label. One signature per request; see [`verify_request`] for
/// why a second one is a refusal rather than a choice.
pub const LABEL: &str = "sig1";

/// `Signature-Input`, lowercased the way an HTTP map hands it over.
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
/// `Signature`.
pub const SIGNATURE_HEADER: &str = "signature";
/// `Content-Digest`, RFC 9530.
pub const CONTENT_DIGEST_HEADER: &str = "content-digest";

/// The algorithm parameter. Ed25519 is the only thing this system has a key
/// for, so a signature claiming anything else is refused rather than tried.
const ALG: &str = "ed25519";

/// The components a signature we emit covers, in order.
const COVERED: [&str; 5] = [
    "@method",
    "@authority",
    "@path",
    "@query",
    CONTENT_DIGEST_HEADER,
];

/// How long a signature we emit is good for.
///
/// Short, because the only thing it protects is one request in flight. Long
/// enough to survive a retry and a slow peer.
pub const LIFETIME: TimeDelta = TimeDelta::minutes(5);

/// Clock skew we forgive on an inbound signature, in both directions. Two
/// machines with NTP are within a second; a minute is generous without making
/// [`LIFETIME`] meaningless.
const SKEW: TimeDelta = TimeDelta::minutes(1);

// ---------------------------------------------------------------------------
// The request, reduced to what a signature covers
// ---------------------------------------------------------------------------

/// One HTTP request, reduced to the parts [`COVERED`] names.
///
/// Borrowed rather than owned: on the verifying side every field is already a
/// slice of the request that arrived, and copying them would be copying the
/// body.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Uppercase, e.g. `POST`. RFC 9421 §2.2.1 signs it verbatim.
    pub method: &'a str,
    /// The host the request is addressed to, lowercased, with the port only if
    /// it is not the scheme's default.
    pub authority: &'a str,
    /// The absolute path, e.g. `/a2a/jsonrpc`. Never empty — `/` if the URL had
    /// no path.
    pub path: &'a str,
    /// The query string **without** its leading `?`, or `None` if there was
    /// none. RFC 9421 spells the two cases differently; see [`base`].
    pub query: Option<&'a str>,
    /// The body exactly as it goes on (or came off) the wire.
    pub body: &'a [u8],
}

/// The three headers a signed request carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// `Content-Digest`.
    pub content_digest: String,
    /// `Signature-Input`.
    pub signature_input: String,
    /// `Signature`.
    pub signature: String,
}

impl Signed {
    /// The headers as `(name, value)` pairs, ready to be set on a request.
    pub fn headers(&self) -> [(&'static str, &str); 3] {
        [
            (CONTENT_DIGEST_HEADER, self.content_digest.as_str()),
            (SIGNATURE_INPUT_HEADER, self.signature_input.as_str()),
            (SIGNATURE_HEADER, self.signature.as_str()),
        ]
    }
}

/// The three headers a verifier reads, as they arrived. `None` for a header
/// that was absent — which is a different thing from present and empty.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignatureHeaders<'a> {
    /// `Signature-Input`.
    pub signature_input: Option<&'a str>,
    /// `Signature`.
    pub signature: Option<&'a str>,
    /// `Content-Digest`.
    pub content_digest: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// The bytes to sign, and the `Signature-Input` value that describes them.
///
/// Split out from [`Signed`] because signing happens elsewhere: the private key
/// is reachable only through [`crate::identity::Identity::sign`], which needs a
/// capability token, and this module deliberately holds no key material and no
/// way to obtain any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToSign {
    /// The RFC 9421 signature base. Sign exactly these bytes.
    pub base: String,
    /// The `Signature-Input` header value the verifier rebuilds it from.
    pub signature_input: String,
    /// The `Content-Digest` header value, already folded into `base`.
    pub content_digest: String,
}

impl ToSign {
    /// Pair the base with the signature made over it.
    pub fn finish(self, signature: &Signature) -> Signed {
        Signed {
            content_digest: self.content_digest,
            signature_input: self.signature_input,
            signature: format!("{LABEL}=:{}:", signature.to_base64()),
        }
    }
}

/// Everything a signature needs except the signature.
pub fn to_sign(request: &Request<'_>, key_id: &KeyId, now: DateTime<Utc>) -> ToSign {
    let content_digest = content_digest(request.body);
    let params = signature_params(
        &COVERED,
        key_id,
        now.timestamp(),
        (now + LIFETIME).timestamp(),
    );
    ToSign {
        base: base(request, &COVERED, &content_digest, &params),
        signature_input: format!("{LABEL}={params}"),
        content_digest,
    }
}

/// `sha-256=:<base64>:` over the body — RFC 9530 §3.
///
/// An empty body gets a digest too, and it is the digest of nothing rather
/// than an absent header: "there is no body" and "the body was removed" have
/// to be different messages or the signature does not cover the difference.
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", B64.encode(Sha256::digest(body)))
}

/// The `@signature-params` value: the covered list plus this signature's
/// metadata, in the exact order RFC 9421 requires them to be reproduced.
fn signature_params(covered: &[&str], key_id: &KeyId, created: i64, expires: i64) -> String {
    let list = covered
        .iter()
        .map(|component| format!("\"{component}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "({list});created={created};expires={expires};keyid=\"{keyid}\";alg=\"{ALG}\"",
        keyid = key_id.as_str()
    )
}

/// The signature base: one line per covered component, then
/// `"@signature-params"`, joined by `\n` with **no** trailing newline.
///
/// This function is the interoperability surface. Every byte of it is
/// specified — the lowercase component names, the `": "` separator, the absence
/// of a final newline — and getting any of them wrong produces a signature that
/// verifies against nothing and says nothing about why.
fn base(request: &Request<'_>, covered: &[&str], digest: &str, params: &str) -> String {
    let mut out = String::new();
    for component in covered {
        let value = match *component {
            "@method" => request.method,
            "@authority" => request.authority,
            "@path" => request.path,
            // RFC 9421 §2.2.7: the query *with* its leading `?`, and a bare `?`
            // when there is none — so "no query" and "empty query" are the same
            // string, which is what a proxy that drops a trailing `?` needs.
            "@query" => {
                out.push_str("\"@query\": ?");
                if let Some(query) = request.query {
                    out.push_str(query);
                }
                out.push('\n');
                continue;
            }
            CONTENT_DIGEST_HEADER => digest,
            // Unreachable: `verify_request` refuses an unknown component before
            // it gets here, and the signing side uses `COVERED`.
            _ => "",
        };
        out.push_str(&format!("\"{component}\": {value}\n"));
    }
    out.push_str(&format!("\"@signature-params\": {params}"));
    out
}

// ---------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------

/// What a verifier concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The request carried no signature at all.
    ///
    /// **Not** a failure. No peer signs today, and refusing an unsigned request
    /// would take every existing integration down in exchange for nothing: the
    /// caller was already authenticated by its API key, and the body was
    /// already `Untrusted`. The caller decides what an unsigned request is
    /// worth; see `routes::a2a`.
    Unsigned,
    /// The signature is good, and this is the key that made it.
    Verified(KeyId),
}

/// Why a signature that *was* offered is not acceptable.
///
/// Every variant here is a refusal, not a downgrade. A request that went to the
/// trouble of carrying a signature and got it wrong is either a bug in a peer
/// or somebody rewriting traffic, and neither is something to accept quietly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// `Signature` without `Signature-Input`, or the other way round.
    #[error("the request carries half a signature")]
    HalfSigned,

    /// More than one signature, or a header this profile cannot parse.
    #[error("the signature headers are not one parseable signature")]
    Malformed,

    /// A covered component this profile does not implement.
    #[error("the signature covers a component this verifier does not implement")]
    UnsupportedComponent,

    /// The body is not covered, so the signature proves nothing about it.
    #[error("the signature does not cover content-digest")]
    BodyNotCovered,

    /// `Content-Digest` is missing, unparseable, or does not match the body.
    #[error("content-digest does not match the body")]
    DigestMismatch,

    /// Outside `created`/`expires`, allowing for [`SKEW`].
    #[error("the signature is expired or not yet valid")]
    Stale,

    /// `alg` is not [`ALG`].
    #[error("the signature does not claim ed25519")]
    WrongAlgorithm,

    /// **The interesting one.** The `keyid` is not in this peer's published key
    /// directory, so whoever signed it, it was not them.
    #[error("the signature names a key this peer does not publish")]
    UnknownKey,

    /// The key is theirs and the signature is not.
    #[error("the signature does not verify")]
    BadSignature,
}

impl VerifyError {
    /// Stable, low-cardinality metric label. Also what goes back to the peer:
    /// a verifier that says only "no" is a verifier nobody can integrate with.
    pub const fn code(self) -> &'static str {
        match self {
            VerifyError::HalfSigned => "half_signed",
            VerifyError::Malformed => "malformed_signature",
            VerifyError::UnsupportedComponent => "unsupported_component",
            VerifyError::BodyNotCovered => "body_not_covered",
            VerifyError::DigestMismatch => "digest_mismatch",
            VerifyError::Stale => "stale_signature",
            VerifyError::WrongAlgorithm => "wrong_algorithm",
            VerifyError::UnknownKey => "unknown_key",
            VerifyError::BadSignature => "bad_signature",
        }
    }
}

/// Check one request against the keys a peer publishes.
///
/// `keys` is that peer's key directory — see [`crate::peer_keys`]. An empty
/// slice makes every signature [`VerifyError::UnknownKey`], which is the right
/// answer: a peer that publishes nothing has no signature we can believe.
///
/// The order of the checks is deliberate. Everything free happens before
/// anything that touches the key: a malformed header, a stale timestamp or a
/// body whose digest is wrong is refused without an Ed25519 verification, so a
/// flood of junk costs a parse rather than a curve operation.
pub fn verify_request(
    request: &Request<'_>,
    headers: &SignatureHeaders<'_>,
    keys: &[PublicKey],
    now: DateTime<Utc>,
) -> Result<Verdict, VerifyError> {
    let (input, signature) = match (headers.signature_input, headers.signature) {
        (None, None) => return Ok(Verdict::Unsigned),
        (Some(input), Some(signature)) => (input.trim(), signature.trim()),
        // Exactly one of the pair. Not "unsigned" — something removed half of
        // a signature, and pretending it was never there is how a stripped
        // signature becomes an accepted request.
        _ => return Err(VerifyError::HalfSigned),
    };

    // A comma at the top level is a second dictionary member, i.e. a second
    // signature. This profile verifies one; picking one of several by position
    // is how a proxy's signature ends up standing in for the peer's.
    if input.contains(',') || signature.contains(',') {
        return Err(VerifyError::Malformed);
    }

    let params = strip_label(input).ok_or(VerifyError::Malformed)?;
    let covered = covered_components(params)?;
    if !covered.iter().any(|c| c == CONTENT_DIGEST_HEADER) {
        return Err(VerifyError::BodyNotCovered);
    }

    if param(params, "alg").as_deref() != Some(ALG) {
        return Err(VerifyError::WrongAlgorithm);
    }

    // `created` is required; `expires` is not, and its absence means our own
    // LIFETIME rather than "forever" — a signature with no stated end is not a
    // signature we keep believing.
    let created: i64 = param(params, "created")
        .and_then(|raw| raw.parse().ok())
        .ok_or(VerifyError::Malformed)?;
    let expires: i64 = match param(params, "expires") {
        Some(raw) => raw.parse().map_err(|_| VerifyError::Malformed)?,
        None => created + LIFETIME.num_seconds(),
    };
    let now = now.timestamp();
    let skew = SKEW.num_seconds();
    if created > now + skew || expires < now - skew {
        return Err(VerifyError::Stale);
    }

    // The body, before the key: this is the check that makes the signature
    // mean anything about the payload, and it costs a hash.
    let digest = headers.content_digest.ok_or(VerifyError::DigestMismatch)?;
    if !digest_matches(digest.trim(), request.body) {
        return Err(VerifyError::DigestMismatch);
    }

    let key_id = param(params, "keyid").ok_or(VerifyError::Malformed)?;
    let key = keys
        .iter()
        .find(|key| key.key_id().as_str() == key_id)
        .ok_or(VerifyError::UnknownKey)?;

    let covered: Vec<&str> = covered.iter().map(String::as_str).collect();
    let base = base(request, &covered, digest.trim(), params);
    let signature =
        Signature::from_base64(strip_signature(signature).ok_or(VerifyError::Malformed)?)
            .map_err(|_| VerifyError::Malformed)?;

    if verify(key, base.as_bytes(), &signature) {
        Ok(Verdict::Verified(key.key_id()))
    } else {
        Err(VerifyError::BadSignature)
    }
}

/// `sig1=(…);…` → `(…);…`. The label itself is not checked against
/// [`LABEL`]: a peer may label its signature anything, and the label is not
/// part of what is signed.
fn strip_label(input: &str) -> Option<&str> {
    let rest = input.split_once('=')?.1;
    rest.starts_with('(').then_some(rest)
}

/// `sig1=:<base64>:` → `<base64>`.
fn strip_signature(value: &str) -> Option<&str> {
    value
        .split_once('=')?
        .1
        .trim()
        .strip_prefix(':')?
        .strip_suffix(':')
}

/// The covered components, checked against what [`base`] can actually render.
///
/// A component this profile does not implement is a refusal and not a skip:
/// silently ignoring one would build a base the signer never signed, which
/// fails at the curve with no explanation — or, far worse, would succeed while
/// covering less than the peer believed.
fn covered_components(params: &str) -> Result<Vec<String>, VerifyError> {
    let list = params
        .strip_prefix('(')
        .and_then(|rest| rest.split_once(')'))
        .map(|(list, _)| list)
        .ok_or(VerifyError::Malformed)?;

    let mut covered = Vec::new();
    for raw in list.split_whitespace() {
        let name = raw
            .strip_prefix('"')
            .and_then(|n| n.strip_suffix('"'))
            .ok_or(VerifyError::Malformed)?;
        if !COVERED.contains(&name) {
            return Err(VerifyError::UnsupportedComponent);
        }
        covered.push(name.to_owned());
    }
    if covered.is_empty() {
        return Err(VerifyError::Malformed);
    }
    Ok(covered)
}

/// One `;name=value` parameter, unquoted. Values here are integers or quoted
/// tokens, neither of which can contain a `;`.
fn param(params: &str, name: &str) -> Option<String> {
    params
        .split(';')
        .skip(1)
        .filter_map(|part| part.split_once('='))
        .find(|(key, _)| key.trim() == name)
        .map(|(_, value)| value.trim().trim_matches('"').to_owned())
}

/// Does `sha-256=:…:` describe these bytes?
///
/// Compared as text over the encoding, which is a byte-for-byte comparison of a
/// hash — nothing secret is on either side, so there is no timing question
/// here, unlike the signature check, which `ed25519-dalek` owns.
fn digest_matches(header: &str, body: &[u8]) -> bool {
    // A peer may send several digests (`sha-256=…, sha-512=…`); we need only
    // find the one we can check, and having found it, it must be right.
    header
        .split(',')
        .map(str::trim)
        .filter(|entry| entry.starts_with("sha-256="))
        .any(|entry| entry == content_digest(body))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_providers::signing::SigningKey;

    use super::*;

    const BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"SendMessage"}"#;

    fn request() -> Request<'static> {
        Request {
            method: "POST",
            authority: "partner.example.com",
            path: "/a2a/jsonrpc",
            query: Some("employee=0192f0a0-0000-7000-8000-000000000000"),
            body: BODY,
        }
    }

    /// Sign `request` with a fresh key and hand back everything a verifier
    /// needs. The whole round trip, so a test never asserts against a base it
    /// built itself.
    fn signed(request: &Request<'_>, now: DateTime<Utc>) -> (PublicKey, Signed) {
        let key = SigningKey::generate();
        let to_sign = to_sign(request, &key.public_key().key_id(), now);
        let signature = key.sign(to_sign.base.as_bytes());
        (key.public_key(), to_sign.finish(&signature))
    }

    fn headers(signed: &Signed) -> SignatureHeaders<'_> {
        SignatureHeaders {
            signature_input: Some(&signed.signature_input),
            signature: Some(&signed.signature),
            content_digest: Some(&signed.content_digest),
        }
    }

    // -- the base ----------------------------------------------------------

    /// The one test that would catch a canonicalisation change: the exact
    /// bytes, written out. If this fails, every counterparty's verifier fails
    /// too, and that is worth an ugly literal.
    #[test]
    fn the_signature_base_is_the_bytes_rfc9421_specifies() {
        let request = request();
        let key_id = PublicKey::new([7u8; 32]).key_id();
        let to_sign = to_sign(
            &request,
            &key_id,
            DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
        );

        let expected = format!(
            "\"@method\": POST\n\
             \"@authority\": partner.example.com\n\
             \"@path\": /a2a/jsonrpc\n\
             \"@query\": ?employee=0192f0a0-0000-7000-8000-000000000000\n\
             \"content-digest\": {digest}\n\
             \"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\" \
             \"content-digest\");created=1700000000;expires=1700000300;\
             keyid=\"{keyid}\";alg=\"ed25519\"",
            digest = content_digest(BODY),
            keyid = key_id.as_str(),
        );
        assert_eq!(to_sign.base, expected);

        // No trailing newline: RFC 9421 §2.5 joins the lines, it does not
        // terminate them, and an extra byte here is a signature nobody verifies.
        assert!(!to_sign.base.ends_with('\n'));

        // `Signature-Input` is the label plus the exact `@signature-params`
        // line the base ends with — that identity is what lets a verifier
        // rebuild the base from nothing but the header.
        let params = to_sign
            .signature_input
            .strip_prefix(&format!("{LABEL}="))
            .expect("labelled");
        assert!(
            to_sign
                .base
                .ends_with(&format!("\"@signature-params\": {params}")),
            "{}",
            to_sign.base
        );
    }

    #[test]
    fn a_request_with_no_query_signs_a_bare_question_mark() {
        let mut request = request();
        request.query = None;
        let base = to_sign(&request, &PublicKey::new([1u8; 32]).key_id(), Utc::now()).base;
        assert!(base.contains("\"@query\": ?\n"), "{base}");
    }

    #[test]
    fn the_content_digest_is_rfc9530_shaped_and_covers_the_empty_body() {
        // Known vector: base64(SHA-256("")).
        assert_eq!(
            content_digest(b""),
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
        assert_ne!(content_digest(b""), content_digest(b"x"));
    }

    // -- the round trip ----------------------------------------------------

    #[test]
    fn a_signature_we_emit_verifies_and_every_kind_of_tampering_does_not() {
        let now = Utc::now();
        let request = request();
        let (key, signed) = signed(&request, now);

        assert_eq!(
            verify_request(&request, &headers(&signed), &[key], now),
            Ok(Verdict::Verified(key.key_id()))
        );

        // The body.
        let mut tampered = request;
        tampered.body = br#"{"jsonrpc":"2.0","id":1,"method":"SendMessagf"}"#;
        assert_eq!(
            verify_request(&tampered, &headers(&signed), &[key], now),
            Err(VerifyError::DigestMismatch)
        );

        // Every covered component, one at a time. Each is a thing an attacker
        // in the middle would want to change, and each must break it.
        for mutate in [
            (|r: &mut Request<'_>| r.method = "GET") as fn(&mut Request<'_>),
            |r| r.authority = "victim.example.com",
            |r| r.path = "/a2a/admin",
            |r| r.query = Some("employee=0192f0a0-0000-7000-8000-00000000ffff"),
        ] {
            let mut moved = request;
            mutate(&mut moved);
            assert_eq!(
                verify_request(&moved, &headers(&signed), &[key], now),
                Err(VerifyError::BadSignature),
                "a moved request still verified"
            );
        }

        // Somebody else's key does not verify our signature...
        let stranger = SigningKey::generate().public_key();
        assert_eq!(
            verify_request(&request, &headers(&signed), &[stranger], now),
            Err(VerifyError::UnknownKey),
            "the keyid names a key this peer does not publish"
        );
        // ...and a key that answers to the right kid but is not the right key
        // cannot exist, because the kid *is* the key. That is the property
        // `agentos_domain::identity` buys by deriving it.
    }

    #[test]
    fn a_body_the_digest_does_not_cover_is_refused_before_the_curve_is_touched() {
        let now = Utc::now();
        let request = request();
        let (key, mut signed) = signed(&request, now);

        // The digest header rewritten to describe different bytes. The
        // signature over the *base* is then also wrong, but the digest check
        // is what fires, and it fires without an Ed25519 verification.
        signed.content_digest = content_digest(b"something else");
        assert_eq!(
            verify_request(&request, &headers(&signed), &[key], now),
            Err(VerifyError::DigestMismatch)
        );

        // ...and an absent digest header is the same refusal, not a pass.
        let mut headers = headers(&signed);
        headers.content_digest = None;
        assert_eq!(
            verify_request(&request, &headers, &[key], now),
            Err(VerifyError::DigestMismatch)
        );
    }

    // -- refusals ----------------------------------------------------------

    #[test]
    fn an_unsigned_request_is_unsigned_and_half_a_signature_is_a_refusal() {
        let request = request();
        assert_eq!(
            verify_request(&request, &SignatureHeaders::default(), &[], Utc::now()),
            Ok(Verdict::Unsigned)
        );

        let (_, signed) = signed(&request, Utc::now());
        for headers in [
            SignatureHeaders {
                signature_input: Some(&signed.signature_input),
                ..SignatureHeaders::default()
            },
            SignatureHeaders {
                signature: Some(&signed.signature),
                ..SignatureHeaders::default()
            },
        ] {
            assert_eq!(
                verify_request(&request, &headers, &[], Utc::now()),
                Err(VerifyError::HalfSigned),
                "a stripped signature must not read as an unsigned request"
            );
        }
    }

    #[test]
    fn a_signature_outside_its_window_is_stale_in_both_directions() {
        let now = Utc::now();
        let request = request();
        let (key, signed) = signed(&request, now);

        assert_eq!(
            verify_request(
                &request,
                &headers(&signed),
                &[key],
                now + LIFETIME + SKEW + TimeDelta::seconds(1)
            ),
            Err(VerifyError::Stale)
        );
        // A peer whose clock is a week fast is not a peer we accept early.
        assert_eq!(
            verify_request(
                &request,
                &headers(&signed),
                &[key],
                now - TimeDelta::days(7)
            ),
            Err(VerifyError::Stale)
        );
        // Inside the window, at both edges.
        assert!(verify_request(&request, &headers(&signed), &[key], now + LIFETIME).is_ok());
        assert!(verify_request(&request, &headers(&signed), &[key], now - SKEW).is_ok());
    }

    #[test]
    fn a_profile_we_do_not_implement_is_refused_rather_than_half_verified() {
        let now = Utc::now();
        let request = request();
        let (key, signed) = signed(&request, now);

        let cases = [
            // A component we cannot render.
            (
                signed
                    .signature_input
                    .replace("\"@path\"", "\"@target-uri\""),
                VerifyError::UnsupportedComponent,
            ),
            // The body left out of the covered set.
            (
                signed.signature_input.replace(" \"content-digest\")", ")"),
                VerifyError::BodyNotCovered,
            ),
            // Another algorithm's signature offered against an Ed25519 key.
            (
                signed.signature_input.replace("ed25519", "rsa-pss-sha512"),
                VerifyError::WrongAlgorithm,
            ),
            // Two signatures. We verify one; choosing between them by position
            // is how a proxy's signature stands in for the peer's.
            (
                format!("{}, sig2=(\"@method\")", signed.signature_input),
                VerifyError::Malformed,
            ),
            // Not a signature input at all.
            ("nonsense".to_owned(), VerifyError::Malformed),
        ];

        for (input, expected) in cases {
            let headers = SignatureHeaders {
                signature_input: Some(&input),
                signature: Some(&signed.signature),
                content_digest: Some(&signed.content_digest),
            };
            assert_eq!(
                verify_request(&request, &headers, &[key], now),
                Err(expected),
                "{input}"
            );
        }
    }

    #[test]
    fn a_peer_that_publishes_no_keys_verifies_nothing() {
        let now = Utc::now();
        let request = request();
        let (_, signed) = signed(&request, now);

        assert_eq!(
            verify_request(&request, &headers(&signed), &[], now),
            Err(VerifyError::UnknownKey)
        );
    }

    /// A peer signing a narrower profile than ours still verifies, as long as
    /// the body is covered. This is the interoperability the exact-match
    /// alternative would have cost.
    #[test]
    fn a_peer_that_omits_the_query_still_verifies() {
        let now = Utc::now();
        let request = request();
        let key = SigningKey::generate();
        let key_id = key.public_key().key_id();

        let covered = ["@method", "@authority", "@path", CONTENT_DIGEST_HEADER];
        let digest = content_digest(request.body);
        let params = signature_params(
            &covered,
            &key_id,
            now.timestamp(),
            (now + LIFETIME).timestamp(),
        );
        let signature = key.sign(base(&request, &covered, &digest, &params).as_bytes());

        let input = format!("{LABEL}={params}");
        let signature = format!("{LABEL}=:{}:", signature.to_base64());
        assert_eq!(
            verify_request(
                &request,
                &SignatureHeaders {
                    signature_input: Some(&input),
                    signature: Some(&signature),
                    content_digest: Some(&digest),
                },
                &[key.public_key()],
                now,
            ),
            Ok(Verdict::Verified(key_id))
        );
    }
}
