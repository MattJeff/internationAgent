//! Minting and verifying the credentials customers hold.
//!
//! `agentos_store::api_keys` owns the four statements; this owns the one value
//! that must never reach them. A secret is generated here, hashed here, and
//! handed to exactly one caller — the response that issues it. Nothing below
//! this module has ever seen it.
//!
//! # HMAC, not argon2, and the reasoning is not "it is faster"
//!
//! The prompt for this decision is usually "passwords are hashed with argon2, so
//! hash these with argon2". That reasoning does not transfer, because the input
//! is not a password:
//!
//! * **An argon2 defends a guessable input.** Its work factor multiplies the
//!   cost of a dictionary walk. [`mint`] takes 32 bytes from the OS CSPRNG, so
//!   there is no dictionary; the walk is 2^256 long and multiplying it by fifty
//!   milliseconds multiplies a number that already ended the argument.
//!   `identity::envelope` makes the same call about the same kind of input, in
//!   the same words: *feeding a high-entropy secret through Argon2 buys latency,
//!   not security.*
//! * **An argon2 must be salted per row, and a salted digest cannot be looked
//!   up.** This is the decisive one and it is structural, not a matter of taste.
//!   The lookup **precedes knowing the tenant** — a bearer token arrives and its
//!   whole job is to say whose it is — so there is no row to fetch first and
//!   verify against. A salted scheme therefore has to run the KDF once per row
//!   in the table on every request. At argon2's default cost that is 64 MiB and
//!   ~50 ms *per key on file*, spent by anybody who sends a wrong
//!   `Authorization` header. The authentication path becomes a denial-of-service
//!   amplifier reachable without credentials. The escape is to put a row id in
//!   the token (`ak_<id>.<secret>`) so one row can be fetched — more format,
//!   more parsing, and an enumerable id on the wire — to buy back a property
//!   that was worth nothing at 256 bits.
//! * **So the digest must be a function of the secret alone**, and the only
//!   question left is whether it is keyed. Keying costs one extra compression
//!   round and no configuration, because the key is derived from
//!   `AGENTOS_MASTER_KEY`, which every deployment already has and already cannot
//!   run without.
//!
//! ## What keying buys, precisely
//!
//! A database dump — a backup on object storage, a read replica, a `pg_dump` in
//! a support ticket — is not enough to *test a candidate secret*. Unkeyed, an
//! attacker who obtained a secret by some other route (a log line elsewhere, a
//! screenshot, a committed `.env`) could confirm from the dump alone that it is
//! live and whose it is; keyed, they cannot. It also makes a digest
//! non-transferable between deployments, so one leaked dump does not index
//! another.
//!
//! ## What I accept to lose, said plainly
//!
//! **A dump plus `AGENTOS_MASTER_KEY` makes every digest verifiable offline.**
//! That is real and it is the honest cost of a keyed hash over an argon2. Two
//! things make it the right trade anyway:
//!
//! 1. Verifiable offline still is not invertible: the attacker can confirm a
//!    secret they already hold, not derive one they do not. At 256 bits there is
//!    no search to run.
//! 2. An attacker holding `AGENTOS_MASTER_KEY` holds every employee's private
//!    signing key, every tenant's model credential and every MCP token, because
//!    all three are sealed under it (`identity::envelope`,
//!    `providers::secrets`). The api-key table is not what they came for, and an
//!    argon2 here would defend one table inside a building they already own.
//!
//! # Constant time
//!
//! `apps/server`'s env keyring compares raw secrets and does it with `ct_eq`,
//! because there the presented bytes are compared against the real bytes. Here
//! nothing compares a secret: the equality happens inside a Postgres btree, over
//! `HMAC(k, presented)`, and what an attacker would have to steer to exploit its
//! early exit is the *output* of a keyed hash they cannot invert. Learning a
//! stored digest byte by byte would still leave them with a digest, and the
//! secret it stands for is not recoverable from it. See
//! [`Hasher::digest`].

use agentos_domain::ids::TenantId;
use agentos_providers::Secret;
use agentos_store::api_keys::{self, ApiKeyRecord, Principal};
use agentos_store::audit::AuditActor;
use agentos_store::db::{Db, StoreError};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// What every issued secret starts with.
///
/// Not decoration. A fixed, unusual prefix is what makes a leaked key findable
/// by the tools that look for leaked keys — GitHub push protection, `gitleaks`,
/// a `grep` over a log archive — before somebody uses it. `aos_` plus 43
/// characters of base64url is a regex anyone can write:
/// `aos_[A-Za-z0-9_-]{43}`.
///
/// It is also what lets this system tell "you pasted your Anthropic key into the
/// wrong box" from "your key is wrong", although nothing does that yet.
pub const SECRET_PREFIX: &str = "aos_";

/// Bytes of entropy in an issued secret.
///
/// 32, i.e. 256 bits, i.e. the reason the whole argon2 argument above resolves
/// the way it does. It is not a tunable: lowering it silently invalidates the
/// "there is nothing to stretch" premise that justifies a fast digest.
const SECRET_BYTES: usize = 32;

/// Domain-separation tag mixed into the HMAC key.
///
/// `identity::envelope` turns `AGENTOS_MASTER_KEY` into 32 bytes with a bare
/// SHA-256, and those 32 bytes are the AES key that seals every private signing
/// key in the deployment. Deriving *this* key the same way would make the two
/// the same value, so a bug that exposed one would expose the other. One extra
/// string in the hash costs nothing and makes them independent.
///
/// The `v1` is not a rotation plan — there is none, see the `ponytail:` note on
/// [`Hasher::from_master_key`] — it is a place to put one.
const HMAC_DOMAIN: &str = "agentos.api_keys.v1";

/// The deployment's key-hashing key.
///
/// Cheap to clone (32 bytes) and held for the life of the process, because the
/// authentication path needs it on every request.
///
/// **`Hasher` and not `Keyring`**, even though it is half of one: `apps/server`
/// has an `auth::Keyring` that holds this *plus* the environment entries plus
/// the pool, and two types with one name in the same security path is how a
/// reviewer stops reading carefully.
///
/// No `Debug`: the derived key is not the master key, but it is a value that
/// verifies every credential in the deployment, and a struct that can be printed
/// is a struct that ends up in a panic message.
#[derive(Clone)]
pub struct Hasher([u8; 32]);

/// A secret that has just been minted, on its way to the one response that
/// carries it.
///
/// The secret is an `agentos_providers::Secret`, so `{:?}` on this renders
/// `[redacted]` and reaching the plaintext is one deliberately ugly call. There
/// is no `Serialize`: the route builds its body field by field, which is what
/// makes "the secret appears in exactly one response" something a reader can
/// check rather than something a derive decides.
#[derive(Debug)]
pub struct Issued {
    /// The row's id — the handle a revocation names. Safe to log, store and
    /// display; it is not a credential.
    pub id: Uuid,
    /// Whose key it is.
    pub tenant_id: TenantId,
    /// Its human name, which becomes the audit actor when it authenticates.
    pub label: String,
    /// **The only copy that will ever exist.** Not stored, not recoverable, not
    /// in the audit trail. A customer who loses it issues another and revokes
    /// this one.
    pub secret: Secret,
}

impl Hasher {
    /// Derive the hashing key from the deployment's master key.
    ///
    /// ponytail: no key id and no rotation. Rotating this key invalidates every
    /// issued secret at once, because a digest cannot be recomputed without the
    /// secret and the secret is gone by design. The upgrade path, if that ever
    /// has to be survivable, is a `hash_version smallint` column on `api_keys`
    /// plus a second [`Hasher`] tried after the first — at which point rotation
    /// is "issue new keys, then drop the old version", which is the same
    /// sentence as today with a longer overlap. `identity::envelope` has the
    /// same shape of note for the same reason.
    pub fn from_master_key(master_key: &str) -> Self {
        let mut hash = Sha256::new();
        hash.update(HMAC_DOMAIN.as_bytes());
        hash.update([0u8]);
        hash.update(master_key.as_bytes());
        Self(hash.finalize().into())
    }

    /// `HMAC-SHA256(key, presented)`.
    ///
    /// Takes the token exactly as it came off the wire, prefix and all: the
    /// prefix is part of the secret's identity, and stripping it here would mean
    /// `aos_X` and `X` authenticate the same, which turns a scanner's regex into
    /// a thing an attacker can evade by deleting four characters.
    ///
    /// The output is fixed-width, so the digest column leaks nothing about the
    /// secret's length. Whether the *presented* value was long or short is
    /// visible from timing here, as it is in any hash, and it is not a secret —
    /// `apps/server/src/auth.rs::ct_eq` makes the same concession in the same
    /// words.
    pub fn digest(&self, presented: &str) -> [u8; 32] {
        let mut mac = <Hmac<Sha256>>::new_from_slice(&self.0)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(presented.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

/// Mint a secret, store its digest, and hand back the only copy.
///
/// The order matters and is not negotiable: the row is written **before** the
/// secret is returned. A caller that fails after this has handed nobody a
/// working key and left a row that can be revoked; the reverse would hand out a
/// live credential this system has no record of.
///
/// `label` is whatever the issuer calls the key. It is unique per tenant, so a
/// second key called `ops-console` is [`StoreError::Conflict`] rather than two
/// rows nobody can tell apart at revocation time.
pub async fn issue(
    db: &Db,
    hasher: &Hasher,
    tenant_id: TenantId,
    label: &str,
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<Issued, StoreError> {
    let secret = mint();
    let digest = hasher.digest(secret.expose_for_transport());
    let id = Uuid::now_v7();

    api_keys::issue(db, id, tenant_id, label, &digest, actor, now).await?;

    Ok(Issued {
        id,
        tenant_id,
        label: label.to_owned(),
        secret,
    })
}

/// Resolve a presented bearer token.
///
/// `Ok(None)` is "no live key has this digest", which deliberately covers
/// unknown, revoked and malformed alike. `Err` is the database being unreachable
/// — a caller must render that as a 5xx and **never** as a 401, or an outage
/// becomes indistinguishable from a wrong key and every customer is told to
/// rotate their credential.
pub async fn authenticate(
    db: &Db,
    hasher: &Hasher,
    presented: &str,
) -> Result<Option<Principal>, StoreError> {
    api_keys::lookup(db, &hasher.digest(presented)).await
}

/// Destroy one key; returns the tenant it belonged to.
pub async fn revoke(
    db: &Db,
    id: Uuid,
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<TenantId, StoreError> {
    api_keys::revoke(db, id, actor, now).await
}

/// One tenant's live keys — ids, labels and dates. Never a digest, never a
/// secret.
pub async fn list(db: &Db, tenant_id: TenantId) -> Result<Vec<ApiKeyRecord>, StoreError> {
    api_keys::list(db, tenant_id).await
}

/// `aos_` plus 32 CSPRNG bytes in base64url.
///
/// `rand::rng()` is the OS CSPRNG — the same source `providers::signing` seeds
/// Ed25519 keys from and `providers::secrets` draws data keys from, named there
/// at length. A secret a human chose would break the premise this module's whole
/// hashing argument rests on, which is why nothing here accepts one.
fn mint() -> Secret {
    let mut bytes = [0u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    Secret::new(format!("{SECRET_PREFIX}{}", B64.encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_secret_is_long_prefixed_and_never_the_same_twice() {
        let a = mint();
        let b = mint();
        let (a, b) = (a.expose_for_transport(), b.expose_for_transport());

        assert!(a.starts_with(SECRET_PREFIX), "{a}");
        // `apps/server`'s env keyring refuses anything under 32 characters, and
        // a secret this system mints must clear its own floor.
        assert!(a.len() >= 32 + SECRET_PREFIX.len(), "{} chars", a.len());
        assert_ne!(a, b, "two mints must not collide");
        assert!(
            a[SECRET_PREFIX.len()..]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "the scanner regex is aos_[A-Za-z0-9_-]+: {a}"
        );
    }

    #[test]
    fn the_secret_does_not_render_itself() {
        let issued = Issued {
            id: Uuid::nil(),
            tenant_id: TenantId::from_uuid(Uuid::nil()),
            label: "ops".to_owned(),
            secret: Secret::new("aos_do-not-print-me"),
        };
        let rendered = format!("{issued:?}");
        assert!(!rendered.contains("do-not-print-me"), "{rendered}");
        assert!(rendered.contains(Secret::REDACTED), "{rendered}");
    }

    #[test]
    fn the_digest_is_keyed_deterministic_and_domain_separated() {
        let a = Hasher::from_master_key("master-one");
        let b = Hasher::from_master_key("master-two");

        assert_eq!(a.digest("aos_x"), a.digest("aos_x"), "a lookup needs this");
        assert_ne!(a.digest("aos_x"), a.digest("aos_y"));
        assert_ne!(
            a.digest("aos_x"),
            b.digest("aos_x"),
            "a digest must not transfer between deployments"
        );
        // The prefix is part of the secret: stripping it must not authenticate.
        assert_ne!(a.digest("aos_x"), a.digest("x"));
        // And the derived key is not the envelope key, or one leak is two.
        assert_ne!(
            a.0,
            <[u8; 32]>::from(Sha256::digest("master-one".as_bytes())),
            "domain separation from identity::envelope"
        );
    }

    #[test]
    fn the_digest_composition_is_pinned() {
        // Not a vector for HMAC itself — the `hmac` crate carries RFC 4231 —
        // but a pin on *this* function's composition: the domain tag, the NUL
        // separator, the order of the two updates and the prefix being part of
        // the input. Change any of them and every issued key in every
        // deployment stops authenticating, silently and all at once. This is
        // the line that says so before the deploy does.
        let hasher = Hasher::from_master_key("hunter2");
        assert_eq!(
            B64.encode(hasher.digest("aos_pinned")),
            "up_zhgi7JN3giRqkLV0EEz9yK8R1JQ68B97zgpMPtao",
            "the digest composition changed; every issued key just stopped working"
        );
    }
}
