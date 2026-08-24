//! Ed25519 signing: the private half of an employee's identity, and the only
//! type in the workspace that holds one.
//!
//! # The private key gets the `Secret` treatment, because it is one
//!
//! [`SigningKey`] deliberately has **no** `Display`, **no** `Deref`, **no**
//! `Serialize`, **no** `Clone`, **no** `PartialEq`, and a hand-written `Debug`
//! that prints [`Secret::REDACTED`] and nothing else. That is the same discipline
//! [`Secret`] applies to an API key and [`Untrusted`](agentos_domain::untrusted::Untrusted)
//! applies to hostile text, for the same reason: the leak is never a deliberate
//! `println!`, it is a `#[derive(Debug)]` on the struct three layers up that
//! someone logged on a bad afternoon.
//!
//! `ed25519_dalek::SigningKey` derives `Debug` and prints its bytes, and it
//! implements `Serialize` under a feature flag. So it is wrapped and never
//! exposed — there is no accessor that returns it, and the only way material
//! leaves this type is [`SigningKey::to_secret`], which hands it to the
//! envelope encryption on its way to a database column. `tests/ui/` proves the
//! missing impls with real compiler errors, which is the part that survives a
//! refactor nobody reviewed carefully.
//!
//! The public half is [`agentos_domain::identity::PublicKey`] and is `Copy`,
//! `Debug` and cheerfully printable. The asymmetry is the documentation.
//!
//! # Ed25519, not the DID toolchain
//!
//! See `agentos_domain::identity` for why there is no `didkit` here. What a
//! counterparty needs is a signature and a key it can fetch over HTTPS, and
//! this module plus a JWKS endpoint is that, in about a hundred lines instead
//! of a dependency tree.
//!
//! # No trait, no mock
//!
//! ponytail: a bare struct, not a `SigningProvider` port with a mock beside it.
//! Every other adapter in this crate wraps a third party that can be slow, be
//! down, or bill us; signing is 60µs of local arithmetic that cannot fail.
//! There is nothing to fault-inject and nothing to reconcile. The day signing
//! moves to a KMS or an HSM — which is the real reason a trait would ever be
//! wanted — [`SigningKey::sign`] becomes an `async fn` on a port and this file
//! becomes its local implementation.

use std::fmt;

use agentos_domain::identity::PublicKey;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, Verifier};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{ProviderError, Secret};

/// Bytes of an Ed25519 seed, which is what a private key actually is.
const SEED_LEN: usize = 32;

/// Bytes of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// One Ed25519 signature.
///
/// Public material — a signature reveals nothing without the message — so this
/// one is `Debug`, `Clone` and comparable, like [`PublicKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// The raw 64 bytes.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// Rehydrate a signature from bytes off the wire.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ProviderError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ProviderError::Terminal {
                code: "signature_length",
            })
    }

    /// Standard (padded) base64, which is the RFC 8941 byte-sequence encoding
    /// RFC 9421 puts inside a `Signature:` header. Not base64url: that is the
    /// JWS spelling, and mixing the two is how a verifier gets a signature it
    /// cannot decode.
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
}

// ---------------------------------------------------------------------------
// SigningKey
// ---------------------------------------------------------------------------

/// An employee's private signing key.
///
/// Read the module docs before adding a derive to this type. Every impl it does
/// not have, it does not have on purpose.
pub struct SigningKey(ed25519_dalek::SigningKey);

// Hand-written, and the whole point of the type. `ed25519_dalek::SigningKey`
// derives `Debug` and prints its bytes; forwarding to it would publish the
// private key into the first log line that formats a struct containing one.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Secret::REDACTED)
    }
}

impl SigningKey {
    /// Mint a fresh keypair.
    ///
    /// Seeded from `rand::rng()` — the OS CSPRNG, the same source
    /// [`crate::secrets`] draws its data keys and nonces from — rather than
    /// through `ed25519-dalek`'s own `rand_core` integration, which would pull
    /// a second copy of `rand_core` into the tree for one 32-byte fill.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rand::rng().fill_bytes(seed.as_mut());
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// The public half, to publish.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.0.verifying_key().to_bytes())
    }

    /// The key as a [`Secret`], on its way into envelope encryption.
    ///
    /// **The only exit.** Named for what it is for: the returned value goes
    /// straight into [`crate::secrets::LocalEnvelopeSecretStore::seal`] and
    /// nowhere else. `Secret` zeroizes on drop and cannot be printed or
    /// serialised, so the material stays wrapped the whole way to the column.
    ///
    /// Base64 because [`Secret`] holds text; the seed is 32 arbitrary bytes and
    /// most of them are not UTF-8.
    pub fn to_secret(&self) -> Secret {
        Secret::new(B64.encode(self.0.to_bytes()))
    }

    /// Rebuild a key from what [`SigningKey::to_secret`] produced.
    pub fn from_secret(secret: &Secret) -> Result<Self, ProviderError> {
        let malformed = ProviderError::Terminal {
            code: "signing_key_malformed",
        };
        let seed = Zeroizing::new(
            B64.decode(secret.expose_for_transport())
                .map_err(|_| malformed.clone())?,
        );
        let seed: [u8; SEED_LEN] = seed.as_slice().try_into().map_err(|_| malformed)?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// Sign `payload`.
    ///
    /// Infallible, which is a property of Ed25519 and not an assumption: it
    /// needs no randomness, so there is no entropy failure, and it has no
    /// message-length limit worth naming. Whether this employee *may* sign is
    /// decided long before here — see `agentos_app::identity`.
    pub fn sign(&self, payload: &[u8]) -> Signature {
        Signature(self.0.sign(payload).to_bytes())
    }
}

/// Does `signature` prove that the holder of `key` signed `payload`?
///
/// The counterparty's half of the protocol, kept here so our own tests verify
/// through exactly the code a verifier would, rather than through a shortcut
/// that would still pass if we published the wrong key.
pub fn verify(key: &PublicKey, payload: &[u8], signature: &Signature) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(key.as_bytes()).is_ok_and(|key| {
        key.verify(
            payload,
            &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
        )
        .is_ok()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use chrono::Utc;

    use super::*;
    use crate::secrets::LocalEnvelopeSecretStore;

    const PAYLOAD: &[u8] = b"POST /a2a/jsonrpc HTTP/1.1\nhost: agents.example\n\n{}";

    #[test]
    fn a_signature_verifies_and_a_tampered_payload_does_not() {
        let key = SigningKey::generate();
        let signature = key.sign(PAYLOAD);

        assert!(verify(&key.public_key(), PAYLOAD, &signature));

        // One flipped byte anywhere in the message.
        for i in 0..PAYLOAD.len() {
            let mut tampered = PAYLOAD.to_vec();
            tampered[i] ^= 0x01;
            assert!(
                !verify(&key.public_key(), &tampered, &signature),
                "byte {i} was changed and the signature still verified"
            );
        }

        // A different employee's key does not verify our signature.
        assert!(!verify(
            &SigningKey::generate().public_key(),
            PAYLOAD,
            &signature
        ));

        // Nor does a tampered signature.
        let mut forged = *signature.as_bytes();
        forged[0] ^= 0x01;
        assert!(!verify(
            &key.public_key(),
            PAYLOAD,
            &Signature::from_slice(&forged).unwrap()
        ));
    }

    #[test]
    fn every_employee_gets_a_different_key() {
        let (a, b) = (SigningKey::generate(), SigningKey::generate());
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.public_key().key_id(), b.public_key().key_id());
    }

    #[test]
    fn a_key_survives_the_round_trip_through_the_envelope() {
        let now = Utc::now();
        let (tenant, employee) = (TenantId::new_v7(now), EmployeeId::new_v7(now));
        let secret_ref =
            agentos_domain::identity::signing_key_ref(tenant, employee).expect("valid name");
        let store = LocalEnvelopeSecretStore::new([7u8; 32]);

        let key = SigningKey::generate();
        let sealed = store.seal(&secret_ref, &key.to_secret()).expect("seal");

        let reopened = SigningKey::from_secret(&store.open(&secret_ref, &sealed).expect("open"))
            .expect("a key we sealed ourselves");

        assert_eq!(reopened.public_key(), key.public_key());
        // The real test: the reconstructed key signs what the original verifies.
        assert!(verify(&key.public_key(), PAYLOAD, &reopened.sign(PAYLOAD)));

        // And the envelope is bound to this employee. Another employee's
        // context does not open it, so a stolen row is not a stolen identity.
        let sibling =
            agentos_domain::identity::signing_key_ref(tenant, EmployeeId::new_v7(now)).unwrap();
        assert!(store.open(&sibling, &sealed).is_err());
    }

    #[test]
    fn a_malformed_secret_is_refused_rather_than_silently_producing_a_key() {
        for bad in [
            "",
            "not base64!!",
            &B64.encode([0u8; 31]),
            &B64.encode([0u8; 33]),
        ] {
            assert_eq!(
                SigningKey::from_secret(&Secret::new(bad))
                    .unwrap_err()
                    .code(),
                "signing_key_malformed",
                "{bad:?} must not parse"
            );
        }
        assert_eq!(
            Signature::from_slice(&[0u8; 63]).unwrap_err().code(),
            "signature_length"
        );
    }

    /// The regression this module exists to prevent.
    ///
    /// Written against the *actual bytes* of a real key in every encoding a
    /// leak would plausibly take, so swapping the hand-written `Debug` for a
    /// derive fails here — a derive would print `SigningKey([12, 240, …])`, and
    /// the decimal-array form is one of the needles below.
    #[test]
    fn nothing_printable_contains_the_private_key() {
        let key = SigningKey::generate();
        let secret = key.to_secret();
        let seed_b64 = secret.expose_for_transport().to_owned();
        let seed = B64.decode(&seed_b64).expect("our own base64");

        // Every rendering a leak could take.
        let needles = [
            seed_b64.clone(),
            hex(&seed),
            format!("{seed:?}"), // "[12, 240, …]", the derive's shape
            seed.iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ];

        // Everything that can be printed, including the key nested inside a
        // struct — which is how it would actually get logged.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct EmployeeIdentity {
            employee: &'static str,
            key: SigningKey,
        }
        let nested = EmployeeIdentity {
            employee: "ada",
            key: SigningKey::from_secret(&secret).expect("round trip"),
        };

        let rendered = format!(
            "{key:?} {secret:?} {nested:?} {} {:?} {}",
            key.public_key().key_id(),
            key.public_key(),
            serde_json::to_string(&agentos_domain::identity::jwks([key.public_key()])).unwrap(),
        );

        for needle in &needles {
            assert!(
                !rendered.contains(needle.as_str()),
                "the private key leaked as {needle:?} into: {rendered}"
            );
        }
        assert!(rendered.contains(Secret::REDACTED), "{rendered}");

        // Sanity: the needles are real. If `seed` were empty every assertion
        // above would pass vacuously, which is the way this kind of test rots.
        assert_eq!(seed.len(), SEED_LEN);
        assert!(needles.iter().all(|n| !n.is_empty()));
        assert!(format!("{seed_b64}{}", hex(&seed)).contains(&needles[1]));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
