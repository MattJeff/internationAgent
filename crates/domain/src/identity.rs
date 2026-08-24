//! An employee's verifiable identity: an Ed25519 public key, its key id, and
//! the JWKS document those are published as.
//!
//! Pure. No network, no storage, no crypto library — a public key is 32 bytes
//! and a JWK is a JSON object, and neither needs one. Signing and verifying
//! live in `agentos-providers`, which is where the cipher dependencies belong.
//!
//! # Why not `did:web`
//!
//! `did:web` is a JSON document at a well-known URL over exactly these keys, so
//! it is a rendering of this type, not a different design. The Rust toolchain
//! for it is not: `spruceid/didkit` is archived and `spruceid/ssi` is a
//! low-single-hundred-star crate with a broken docs build, and being the
//! load-bearing user of a dying dependency is a worse problem than the one it
//! solves. Meanwhile key discovery at a well-known URL is what actually
//! shipped — Cloudflare's Web Bot Auth serves a JWKS at
//! `/.well-known/http-message-signatures-directory` and signs with RFC 9421.
//!
//! So the door is left open rather than walked through: [`PublicKey`] is the
//! key material, [`PublicKey::jwk`] is one rendering of it, and a
//! `did_document()` beside it would be a second one over the same bytes. That
//! is a function, not a migration. **Do not add it until somebody asks.**
//!
//! # The key id is the key
//!
//! [`KeyId`] is `base64url(public key)`, unpadded. `kid` is an opaque string by
//! JWK's own definition, and deriving it from the key buys two things for no
//! code: it is stable without being stored, and it cannot name a key it is not
//! — there is no registry to get out of step with, and a rotated key gets a
//! fresh `kid` for free.
//!
//! ponytail: not an RFC 7638 thumbprint, which would be
//! `base64url(SHA-256(canonical JWK))` and would need a hash dependency in this
//! crate. Both are opaque to a verifier. Swap it the day a consumer demands the
//! thumbprint specifically — one function body, and every published `kid`
//! changes, so do it before there are counterparties, not after.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::{Value, json};

use crate::ids::{EmployeeId, SecretRef, SecretRefError, TenantId};

/// Length of an Ed25519 public key. Fixed by the curve, not by us.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Where a JWKS lives, ours and everybody else's.
///
/// Cloudflare's Web Bot Auth directory path. Here, in the crate both sides
/// depend on, because two spellings of it is two protocols: the route that
/// serves ours and the fetcher that reads a peer's must agree, and a constant
/// they share is the only way that stays true after a rename.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";

/// The [`SecretRef`] name an employee's private signing key is stored under.
///
/// One constant, because the name is the envelope's AAD: seal under one
/// spelling and open under another and the ciphertext simply does not
/// authenticate. See `agentos_providers::secrets`.
pub const SIGNING_KEY_NAME: &str = "signing-key";

/// Where an employee's private signing key lives.
///
/// Infallible in practice — [`SIGNING_KEY_NAME`] is a literal that satisfies
/// [`SecretRef::new`]'s charset — but the error is returned rather than
/// unwrapped so a future rename cannot panic in production.
pub fn signing_key_ref(
    tenant_id: TenantId,
    employee_id: EmployeeId,
) -> Result<SecretRef, SecretRefError> {
    SecretRef::new(tenant_id, employee_id, SIGNING_KEY_NAME)
}

// ---------------------------------------------------------------------------
// KeyId
// ---------------------------------------------------------------------------

/// The `kid` a signature names and a verifier looks up in the JWKS.
///
/// Derived from the key material; see the module docs. Constructible only via
/// [`PublicKey::key_id`], so a `kid` that belongs to no key cannot be spelled.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl KeyId {
    /// The id as it appears on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<KeyId> for String {
    fn from(id: KeyId) -> Self {
        id.0
    }
}

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

/// Why some bytes are not an Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublicKeyError {
    /// Wrong length. An Ed25519 public key is always [`PUBLIC_KEY_LEN`] bytes.
    #[error("an Ed25519 public key is {PUBLIC_KEY_LEN} bytes, got {got}")]
    Length {
        /// What was offered.
        got: usize,
    },

    /// A JWK's `x` member was not unpadded base64url.
    #[error("a JWK x member must be unpadded base64url")]
    Encoding,
}

/// An employee's Ed25519 public key.
///
/// Public by construction: this is the value whose entire purpose is to be
/// handed to strangers, so unlike its private counterpart it is `Debug`,
/// `Clone` and `Copy` with no ceremony at all. The asymmetry is deliberate and
/// is the clearest statement of which half is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// Wrap 32 bytes that are already known to be a key.
    pub const fn new(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Wrap bytes of unknown length — a database column, a JWK's `x`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| PublicKeyError::Length { got: bytes.len() })
    }

    /// Decode the `x` member of an Ed25519 JWK.
    pub fn from_jwk_x(x: &str) -> Result<Self, PublicKeyError> {
        let bytes = B64URL.decode(x).map_err(|_| PublicKeyError::Encoding)?;
        Self::from_slice(&bytes)
    }

    /// The raw key.
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// The `kid` this key is published and referenced under.
    pub fn key_id(&self) -> KeyId {
        KeyId(B64URL.encode(self.0))
    }

    /// This key as one JWK, RFC 8037 §2 (`OKP` / `Ed25519`).
    ///
    /// `use` and `alg` are pinned because this key does exactly one thing: an
    /// Ed25519 key offered for encryption is a key somebody will eventually try
    /// to encrypt with.
    pub fn jwk(&self) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": self.key_id().as_str(),
            "x": B64URL.encode(self.0),
        })
    }
}

/// The JWKS document a verifier fetches: `{"keys": [ … ]}`, and nothing else.
///
/// A key set rather than a single key because rotation needs an overlap window
/// — the new key has to be publishable before the old one stops signing — and
/// because a verifier that has to special-case "one key" is a verifier that
/// breaks on the first rotation.
///
/// **Nothing but public keys can appear in the output of this function.** It
/// takes [`PublicKey`] values, which are 32 bytes with no room for anything
/// else, so there is no field a private key could ride in on.
pub fn jwks(keys: impl IntoIterator<Item = PublicKey>) -> Value {
    json!({ "keys": keys.into_iter().map(|k| k.jwk()).collect::<Vec<_>>() })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    /// A key whose bytes are recognisable in any encoding.
    fn key() -> PublicKey {
        PublicKey::new([7u8; PUBLIC_KEY_LEN])
    }

    #[test]
    fn a_public_key_is_exactly_thirty_two_bytes() {
        assert_eq!(
            PublicKey::from_slice(&[0u8; 32]),
            Ok(PublicKey::new([0; 32]))
        );
        assert_eq!(
            PublicKey::from_slice(&[0u8; 31]),
            Err(PublicKeyError::Length { got: 31 })
        );
        assert_eq!(
            PublicKey::from_slice(&[0u8; 33]),
            Err(PublicKeyError::Length { got: 33 })
        );
        assert_eq!(
            PublicKey::from_slice(&[]),
            Err(PublicKeyError::Length { got: 0 })
        );
    }

    #[test]
    fn the_kid_is_derived_and_therefore_stable_without_being_stored() {
        assert_eq!(key().key_id(), key().key_id());
        assert_ne!(key().key_id(), PublicKey::new([8u8; 32]).key_id());

        // Unpadded base64url: no '=', no '+', no '/', so it is safe in a URL
        // fragment — which is where did:web would eventually put it.
        let kid = key().key_id().to_string();
        assert!(!kid.contains(['=', '+', '/']), "{kid}");
    }

    #[test]
    fn the_jwk_is_rfc8037_and_round_trips_through_its_x_member() {
        let jwk = key().jwk();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["kid"], key().key_id().as_str());

        let x = jwk["x"].as_str().expect("x is a string");
        assert_eq!(PublicKey::from_jwk_x(x), Ok(key()));

        // Exactly six members. A seventh is somebody publishing something that
        // is not a public key, and this is where that gets noticed.
        assert_eq!(jwk.as_object().expect("object").len(), 6);
    }

    #[test]
    fn the_jwks_is_a_key_set_even_for_one_key() {
        let set = jwks([key()]);
        assert_eq!(set["keys"].as_array().expect("array").len(), 1);
        assert_eq!(set["keys"][0], key().jwk());
        assert_eq!(set.as_object().expect("object").len(), 1);

        // Empty is still well-formed: a verifier gets "no keys", not a parse
        // error it has to guess at.
        assert_eq!(jwks([])["keys"].as_array().expect("array").len(), 0);
    }

    #[test]
    fn the_signing_key_ref_is_scoped_to_one_employee() {
        let now = Utc::now();
        let (tenant, employee) = (TenantId::new_v7(now), EmployeeId::new_v7(now));
        let secret_ref = signing_key_ref(tenant, employee).expect("valid name");

        assert_eq!(secret_ref.tenant_id(), tenant);
        assert_eq!(secret_ref.employee_id(), employee);
        assert_eq!(secret_ref.name(), SIGNING_KEY_NAME);
    }
}
