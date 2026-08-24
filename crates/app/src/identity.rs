//! Signing in an employee's name: minting its keypair, and spending it.
//!
//! # Is signing an action that needs the Policy Gate? Yes.
//!
//! It has to be, and the reasoning is the one this workspace already made for
//! every other effect. A signature is not a computation, it is an **assertion
//! made in the company's name** — the entire value of it to a counterparty is
//! that Fabrikam stands behind what was signed. That is the same kind of thing
//! as sending an email or moving money, and `effects.rs` says what happens to
//! effects that do not pass the gate: they are side effects that escaped the
//! design, and the type system is supposed to make them unspellable.
//!
//! So [`Identity::sign`] takes an [`Authorized<A>`], whose only constructors
//! are private to `gate.rs`. There is no `sign(&self, payload)`. A caller that
//! wants a signature must first have had the gate rule on the thing it is
//! signing, and a suspended employee cannot obtain a token at all.
//!
//! ## Why it does not get an `Action::Sign` of its own
//!
//! The other half of the decision, and the one that is easy to get wrong.
//! Adding `Action::Sign` would put a *second* ruling in front of every
//! signature, and the gate would be ruling on the wrong question: "may this
//! employee sign?" is never the question anybody has. The question is always
//! "may this employee send this A2A request / this email / this order?" — and
//! once that is answered yes, refusing to sign it would produce an
//! authorised message that nobody can verify, which is worse than either
//! outcome.
//!
//! Worse, a standalone `Action::Sign` is a **signing oracle**. An employee that
//! can obtain a bare signing authorization can sign arbitrary bytes — including
//! bytes that are somebody else's contract — and every one of those signatures
//! is valid against our published key forever. The gate would have approved
//! "signing", not the assertion.
//!
//! So the rule is: **a signature rides the authority of the action it
//! attests.** `Authorized<A2aSend>` signs the A2A request. `Authorized<PaymentCreate>`
//! signs the payment instruction. The token that permitted the assertion is the
//! token that permits putting the company's name on it, the trail links them by
//! [`Authorized::decision_id`], and there is no path to a signature that no
//! ruling stands behind.
//!
//! ## What the trail records
//!
//! One `message_signed` row per signature, carrying the decision id, the `kid`
//! that signed, and the SHA-256 of the payload — not the payload. The digest is
//! what makes the row worth having: given a signature a counterparty disputes,
//! the trail can say whether *this* employee signed *that exact* payload and
//! under which ruling. Storing the payload itself would put outbound message
//! bodies in the audit log forever.
//!
//! # Storage
//!
//! The private key never exists in the database as a key. It is sealed by
//! [`LocalEnvelopeSecretStore`] under the employee's own [`SecretRef`], so the
//! master key protects the data key and the data key protects the seed, with
//! `tenant={id}` and the full ref as the two AADs — a row lifted into another
//! tenant's context fails to authenticate rather than decrypting to our
//! identity. See `agentos_providers::secrets`.
//!
//! ponytail: [`LocalEnvelopeSecretStore`] concrete rather than
//! `Arc<dyn SecretStore>`, and that is deliberate rather than lazy. The
//! `SecretStore` trait is keyed on a `SecretRef` and owns its own rows; here the
//! rows are `employee_signing_keys`, so what is wanted is the *cipher* half of
//! that type — `seal` and `open` — and not its map. Those are exactly the two
//! functions its module docs promise stay signature-compatible when this becomes
//! `kms:Encrypt`/`kms:Decrypt`.

use std::sync::Arc;

use agentos_domain::identity::{PublicKey, PublicKeyError, signing_key_ref};
use agentos_domain::ids::SecretRefError;
use agentos_providers::ProviderError;
use agentos_providers::secrets::{Envelope, LocalEnvelopeSecretStore};
use agentos_providers::signing::{Signature, SigningKey};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError};
use agentos_store::signing::{self as keys, StoredKey};
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::gate::{Authorized, Principal};

/// Audit payload key holding the `kid` that signed. Public metadata: it is the
/// same string the JWKS publishes.
const KID_KEY: &str = "kid";

/// Audit payload key holding the SHA-256 of what was signed. A digest, never
/// the payload — see the module docs.
const DIGEST_KEY: &str = "payload_sha256";

/// The envelope cipher every [`Identity`] in this process shares, from the
/// deployment's `AGENTOS_MASTER_KEY`.
///
/// # Why SHA-256 and not a KDF
///
/// `LocalEnvelopeSecretStore` takes 32 bytes and the variable is text, so
/// something has to bridge them, and doing it in one place is the point — two
/// spellings of this function are two deployments that cannot read each other's
/// rows. SHA-256 is the bridge because the input is a **secret**, not a
/// password: it comes out of a secret manager with full entropy, so there is
/// nothing for a KDF's salt and work factor to defend against. Feeding a
/// high-entropy secret through Argon2 buys latency, not security.
///
/// The corollary is an operational one and it is load-bearing: an
/// `AGENTOS_MASTER_KEY` that somebody *typed* has the entropy of a typed
/// string, and this function will not fix that. Generate it (`openssl rand
/// -base64 32`) and store it where the rest of the credentials live.
///
/// ponytail: no key id, no versioning, no rotation path. Rotating this key
/// means re-sealing every row, which is a migration and a maintenance window,
/// not a constant. The real answer is KMS — where this argument becomes a key
/// id and rotation becomes somebody else's problem — and `agentos_providers::secrets`
/// documents that swap as a body change.
pub fn envelope(master_key: &str) -> Arc<LocalEnvelopeSecretStore> {
    Arc::new(LocalEnvelopeSecretStore::new(
        Sha256::digest(master_key.as_bytes()).into(),
    ))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an employee could not sign, or could not be given a key.
///
/// Codes, not messages: these land on dashboards. Nothing here can carry key
/// material — every variant is an enum or an id.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// This employee has no signing key. Provisioning never ran, or the key was
    /// destroyed at offboarding.
    #[error("employee has no signing key")]
    NoKey,

    /// The stored key could not be unsealed or is not a key. A wrong
    /// `AGENTOS_MASTER_KEY`, a row from another tenant, or a corrupt column —
    /// indistinguishable to the caller, which is the point.
    #[error(transparent)]
    Unsealable(ProviderError),

    /// The stored public key is not 32 bytes. The database check makes this
    /// unreachable; when it fires the row is corrupt and saying so is the
    /// honest answer.
    #[error(transparent)]
    Corrupt(PublicKeyError),

    /// The database was unavailable, so the signature is reported as failed.
    /// Same direction as [`crate::effects`]: an unrecorded assertion in the
    /// company's name is worse than a missing one.
    #[error(transparent)]
    Unavailable(StoreError),
}

impl IdentityError {
    /// Stable, low-cardinality metric label.
    pub fn code(&self) -> &'static str {
        match self {
            IdentityError::NoKey => "no_signing_key",
            IdentityError::Unsealable(err) => err.code(),
            IdentityError::Corrupt(_) => "corrupt_public_key",
            IdentityError::Unavailable(_) => "unavailable",
        }
    }
}

impl From<SecretRefError> for IdentityError {
    /// Unreachable in practice — the ref is built from a literal name — but a
    /// rename must not panic in production.
    fn from(_: SecretRefError) -> Self {
        IdentityError::Unsealable(ProviderError::Terminal {
            code: "signing_key_ref",
        })
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// One employee's signing identity. Mirrors [`crate::effects::Effects`]: bound
/// to the principal every signature is attributed to, sharing one envelope
/// cipher and one pool.
#[derive(Clone)]
pub struct Identity {
    db: Db,
    envelope: Arc<LocalEnvelopeSecretStore>,
    principal: Principal,
}

// Hand-written. A derived `Debug` would reach into `LocalEnvelopeSecretStore`,
// which holds the master key; its own `Debug` redacts, but relying on that is
// relying on a type two crates away never changing.
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("employee_id", &self.principal.employee_id)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Bind the envelope cipher and the database to one principal.
    pub const fn new(
        db: Db,
        envelope: Arc<LocalEnvelopeSecretStore>,
        principal: Principal,
    ) -> Self {
        Self {
            db,
            envelope,
            principal,
        }
    }

    /// Give this employee a keypair if it does not have one, and return the
    /// public half either way.
    ///
    /// Idempotent, and it has to be: it runs from a provisioning step that gets
    /// retried, and minting a second key would strand every signature made
    /// under the first. The insert is `ON CONFLICT DO NOTHING`, so two racing
    /// callers agree on whichever key landed rather than one of them silently
    /// replacing the other's — the freshly generated key is simply dropped.
    ///
    /// **Not gated.** Holding a key is not an assertion; it is the employee
    /// having a name at all, exactly like being issued an email address. The
    /// gate rules on what is *done* with it, which is [`Identity::sign`].
    pub async fn ensure_key(&self) -> Result<PublicKey, IdentityError> {
        let secret_ref = signing_key_ref(self.principal.tenant_id, self.principal.employee_id)?;
        let fresh = SigningKey::generate();
        let sealed = self
            .envelope
            .seal(&secret_ref, &fresh.to_secret())
            .map_err(IdentityError::Unsealable)?;

        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(IdentityError::Unavailable)?;
        keys::ensure(
            &mut tx,
            self.principal.tenant_id,
            self.principal.employee_id,
            &StoredKey {
                public_key: fresh.public_key().as_bytes().to_vec(),
                sealed_private_key: sealed.to_bytes(),
            },
        )
        .await
        .map_err(IdentityError::Unavailable)?;
        // Read back rather than trusting `fresh`: on the losing side of a race
        // the row holds somebody else's key, and returning the one we generated
        // would publish a key nothing can sign with.
        let stored = keys::load(&mut tx, self.principal.employee_id)
            .await
            .map_err(IdentityError::Unavailable)?;
        tx.commit().await.map_err(IdentityError::Unavailable)?;

        PublicKey::from_slice(&stored.public_key).map_err(IdentityError::Corrupt)
    }

    /// The key this employee currently signs and publishes under.
    ///
    /// Read through [`keys::published_keys`] — the *same* query the JWKS route
    /// runs — and not through [`keys::load`], deliberately. A signer needs to
    /// name a `kid` in the signature it emits, and the only `kid` worth naming
    /// is one a verifier will find when it fetches the directory. Reading from
    /// a different query than the one strangers read is how a signature ends up
    /// pointing at a key nobody publishes.
    ///
    /// [`IdentityError::NoKey`] when nothing is published — no key was ever
    /// minted, or the employee is not `active`.
    pub async fn public_key(&self) -> Result<PublicKey, IdentityError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(IdentityError::Unavailable)?;
        let published = keys::published_keys(&mut tx, self.principal.employee_id)
            .await
            .map_err(IdentityError::Unavailable)?;
        tx.commit().await.map_err(IdentityError::Unavailable)?;

        // One key per employee is the primary key of the table, so `first` is
        // "the" key and not a choice — see `0014_identity.sql`. It stays `first`
        // rather than an assertion so that adding a rotation overlap window is a
        // change to what is *chosen*, not a panic in a signing path.
        let first = published.first().ok_or(IdentityError::NoKey)?;
        PublicKey::from_slice(first).map_err(IdentityError::Corrupt)
    }

    /// Sign `payload` in this employee's name, on the authority of `ok`.
    ///
    /// The token is the whole security argument — read the module docs before
    /// changing this signature. `ok` is borrowed rather than consumed because
    /// signing is one step of performing an effect, not the effect itself: the
    /// caller still needs the token to hand to [`crate::effects`] afterwards.
    pub async fn sign<A>(
        &self,
        ok: &Authorized<A>,
        payload: &[u8],
    ) -> Result<Signature, IdentityError> {
        let secret_ref = signing_key_ref(self.principal.tenant_id, self.principal.employee_id)?;

        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(IdentityError::Unavailable)?;
        let stored = match keys::load(&mut tx, self.principal.employee_id).await {
            Ok(stored) => stored,
            Err(StoreError::NotFound) => return Err(IdentityError::NoKey),
            Err(err) => return Err(IdentityError::Unavailable(err)),
        };

        // The key is alive for exactly these three lines and drops (zeroizing)
        // at the end of the block. Same shape as `SecretResolver::with_secret`,
        // and for the same reason: a private key bound to a long-lived variable
        // is a private key in a core dump.
        let (signature, key_id) = {
            let envelope = Envelope::from_bytes(&stored.sealed_private_key)
                .map_err(IdentityError::Unsealable)?;
            let key = SigningKey::from_secret(
                &self
                    .envelope
                    .open(&secret_ref, &envelope)
                    .map_err(IdentityError::Unsealable)?,
            )
            .map_err(IdentityError::Unsealable)?;
            (key.sign(payload), key.public_key().key_id())
        };

        // The row commits before the signature is returned. There is no path on
        // which a caller holds an assertion the trail does not know about.
        audit::append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(self.principal.employee_id),
                decision_id: Some(ok.decision_id()),
                payload: json!({
                    KID_KEY: key_id.as_str(),
                    DIGEST_KEY: hex(&Sha256::digest(payload)),
                }),
                ..AuditEvent::new(
                    self.principal.actor.clone(),
                    AuditKind::MessageSigned,
                    Utc::now(),
                )
            },
        )
        .await
        .map_err(IdentityError::Unavailable)?;
        tx.commit().await.map_err(IdentityError::Unavailable)?;

        Ok(signature)
    }

    /// This employee's published key set, built from the same query the
    /// unauthenticated JWKS endpoint runs.
    ///
    /// Here so that a caller wanting to publish the document — the HTTP route,
    /// a test proving a signature verifies against what is published — cannot
    /// build it from a different source than the one strangers actually read.
    /// Empty when the employee is not `active`; see `agentos_store::signing`.
    pub async fn published_jwks(&self) -> Result<Value, IdentityError> {
        let mut tx = self
            .db
            .tenant_tx(self.principal.tenant_id)
            .await
            .map_err(IdentityError::Unavailable)?;
        let raw = keys::published_keys(&mut tx, self.principal.employee_id)
            .await
            .map_err(IdentityError::Unavailable)?;
        tx.commit().await.map_err(IdentityError::Unavailable)?;

        let keys = raw
            .iter()
            .map(|bytes| PublicKey::from_slice(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(IdentityError::Corrupt)?;
        Ok(agentos_domain::identity::jwks(keys))
    }
}

/// Lowercase hex, for the payload digest in the audit row.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::action::{Action, Domain};
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::policy::PolicyLimits;
    use agentos_providers::signing::verify;
    use agentos_store::audit::AuditRecord;
    use std::collections::BTreeSet;

    use super::*;
    use crate::gate::{PolicyBook, PolicyGate};

    // A 32-byte master key, which is what `LocalEnvelopeSecretStore::new` takes.
    // Not a passphrase: there is no KDF here, and inventing one in a test would
    // be inventing a second key-derivation story the real deployment does not have.
    const MASTER: [u8; 32] = [7u8; 32];
    const PEER: &str = "partner.example.com";
    const PAYLOAD: &[u8] = b"\"@method\": POST\n\"@authority\": agents.fabrikam.example\n";

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the identity unit needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one active employee, and the identity bound to it.
    async fn seed(db: &Db, lifecycle: &str) -> (Principal, Identity) {
        let now = Utc::now();
        let (tenant, employee) = (TenantId::new_v7(now), EmployeeId::new_v7(now));

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().simple().to_string())
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, $4)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid().simple().to_string())
        .bind(lifecycle)
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");

        let principal = Principal::employee(tenant, employee);
        let identity = Identity::new(
            db.clone(),
            Arc::new(LocalEnvelopeSecretStore::new(MASTER)),
            principal.clone(),
        );
        (principal, identity)
    }

    /// A gate that allows an A2A message to one peer, so a real token exists.
    fn gate(db: &Db) -> PolicyGate {
        PolicyGate::new(
            db.clone(),
            PolicyBook::new(PolicyLimits {
                allowed_a2a_peers: BTreeSet::from([Domain::parse(PEER).expect("domain")]),
                max_new_contacts_per_day: 20,
                ..PolicyLimits::default()
            }),
        )
    }

    async fn token(db: &Db, principal: &Principal) -> Authorized<Action> {
        gate(db)
            .authorize(
                principal,
                Action::A2aSend {
                    peer: Domain::parse(PEER).expect("domain"),
                },
            )
            .await
            .expect("the peer is on the allowlist")
    }

    async fn trail(db: &Db, principal: &Principal) -> Vec<AuditRecord> {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let rows = audit::trail_for_employee(&mut tx, principal.employee_id, 100)
            .await
            .expect("trail");
        tx.commit().await.expect("commit");
        rows
    }

    /// Verify exactly as a counterparty would: parse the JWKS we publish, take
    /// the key whose `kid` is in the document, and check the signature with it.
    fn verifies_against(jwks: &Value, payload: &[u8], signature: &Signature) -> bool {
        jwks["keys"]
            .as_array()
            .expect("a key set")
            .iter()
            .filter_map(|jwk| PublicKey::from_jwk_x(jwk["x"].as_str()?).ok())
            .any(|key| verify(&key, payload, signature))
    }

    // -- the tests ---------------------------------------------------------

    #[tokio::test]
    async fn a_signature_verifies_against_the_published_jwks_and_a_tampered_payload_does_not() {
        let Some(db) = db().await else { return };
        let (principal, identity) = seed(&db, "active").await;

        let minted = identity.ensure_key().await.expect("mint");
        let signature = identity
            .sign(&token(&db, &principal).await, PAYLOAD)
            .await
            .expect("sign");

        // The document a stranger fetches, built by the same call the route
        // makes — not from `minted`, which is what makes this test worth
        // anything.
        let jwks = identity.published_jwks().await.expect("jwks");
        assert_eq!(jwks["keys"].as_array().expect("array").len(), 1);
        assert_eq!(jwks["keys"][0]["kid"], minted.key_id().as_str());

        assert!(verifies_against(&jwks, PAYLOAD, &signature));

        // One byte changed anywhere and it stops verifying.
        for i in 0..PAYLOAD.len() {
            let mut tampered = PAYLOAD.to_vec();
            tampered[i] ^= 0x01;
            assert!(
                !verifies_against(&jwks, &tampered, &signature),
                "byte {i} was changed and the signature still verified"
            );
        }

        // And another employee's published key does not verify ours.
        let (_, stranger) = seed(&db, "active").await;
        stranger.ensure_key().await.expect("mint");
        let theirs = stranger.published_jwks().await.expect("jwks");
        assert!(!verifies_against(&theirs, PAYLOAD, &signature));
    }

    #[tokio::test]
    async fn minting_a_key_twice_keeps_the_first_one() {
        let Some(db) = db().await else { return };
        let (principal, identity) = seed(&db, "active").await;

        let first = identity.ensure_key().await.expect("mint");
        assert_eq!(identity.ensure_key().await.expect("again"), first);

        // The retained key is the one that still signs — a second `ensure_key`
        // must not have stranded the identity.
        let signature = identity
            .sign(&token(&db, &principal).await, PAYLOAD)
            .await
            .expect("sign");
        assert!(verify(&first, PAYLOAD, &signature));
    }

    #[tokio::test]
    async fn signing_records_the_ruling_it_rode_and_the_digest_of_what_was_signed() {
        let Some(db) = db().await else { return };
        let (principal, identity) = seed(&db, "active").await;
        let key = identity.ensure_key().await.expect("mint");

        let ok = token(&db, &principal).await;
        let decision_id = ok.decision_id();
        identity.sign(&ok, PAYLOAD).await.expect("sign");

        let rows = trail(&db, &principal).await;
        let signed: Vec<&AuditRecord> = rows
            .iter()
            .filter(|r| r.action_kind == AuditKind::MessageSigned.as_str())
            .collect();
        assert_eq!(signed.len(), 1, "one signature, one row");
        assert_eq!(signed[0].decision_id, Some(decision_id));
        assert_eq!(signed[0].payload[KID_KEY], json!(key.key_id().as_str()));
        assert_eq!(
            signed[0].payload[DIGEST_KEY],
            json!(hex(&Sha256::digest(PAYLOAD)))
        );

        // The digest, not the payload: the outbound body is not in the trail.
        let rendered = format!("{rows:?}");
        assert!(
            !rendered.contains(std::str::from_utf8(PAYLOAD).expect("utf8")),
            "{rendered}"
        );

        // The gate's own ruling is in the same trail, under the same id, which
        // is what makes "which decision let this be signed?" answerable.
        assert!(
            rows.iter()
                .any(|r| r.decision_id == Some(decision_id)
                    && r.decision.as_deref() == Some("allow"))
        );
    }

    #[tokio::test]
    async fn an_employee_with_no_key_cannot_sign() {
        let Some(db) = db().await else { return };
        let (principal, identity) = seed(&db, "active").await;

        let err = identity
            .sign(&token(&db, &principal).await, PAYLOAD)
            .await
            .expect_err("nothing was ever minted");
        assert!(matches!(err, IdentityError::NoKey));
        assert_eq!(err.code(), "no_signing_key");
    }

    #[tokio::test]
    async fn a_suspended_employee_signs_nothing_and_publishes_nothing() {
        let Some(db) = db().await else { return };
        let (principal, identity) = seed(&db, "active").await;
        identity.ensure_key().await.expect("mint");

        // Suspension is the revocation lever.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        sqlx::query("UPDATE employees SET lifecycle = 'suspended' WHERE id = $1")
            .bind(principal.employee_id.as_uuid())
            .execute(&mut **tx)
            .await
            .expect("suspend");
        tx.commit().await.expect("commit");

        // The gate refuses the token, so `sign` is unreachable — there is no
        // second lifecycle check here, and there does not need to be one.
        assert!(
            gate(&db)
                .authorize(
                    &principal,
                    Action::A2aSend {
                        peer: Domain::parse(PEER).expect("domain")
                    },
                )
                .await
                .is_err()
        );

        // And the key stops being published, so signatures already out there
        // stop verifying for anyone who refetches.
        let jwks = identity.published_jwks().await.expect("jwks");
        assert_eq!(jwks["keys"].as_array().expect("array").len(), 0);
    }

    #[tokio::test]
    async fn the_wrong_master_key_opens_nothing_and_says_nothing_useful() {
        let Some(db) = db().await else { return };
        let (principal, identity) = seed(&db, "active").await;
        identity.ensure_key().await.expect("mint");

        let impostor = Identity::new(
            db.clone(),
            Arc::new(LocalEnvelopeSecretStore::new([9u8; 32])),
            principal.clone(),
        );
        let err = impostor
            .sign(&token(&db, &principal).await, PAYLOAD)
            .await
            .expect_err("the seed does not unseal");
        assert_eq!(err.code(), "secret_decrypt_failed");
    }

    /// The regression that matters most: no rendering of anything this module
    /// produces or stores contains the private key.
    #[tokio::test]
    async fn the_private_key_is_in_no_debug_output_no_row_and_no_published_document() {
        let Some(db) = db().await else { return };
        let (principal, identity) = seed(&db, "active").await;
        identity.ensure_key().await.expect("mint");
        identity
            .sign(&token(&db, &principal).await, PAYLOAD)
            .await
            .expect("sign");

        // Recover the actual seed the only legitimate way, so the needles below
        // are the real private key and not a stand-in.
        let secret_ref = signing_key_ref(principal.tenant_id, principal.employee_id).unwrap();
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let stored = keys::load(&mut tx, principal.employee_id)
            .await
            .expect("load");
        tx.commit().await.expect("commit");
        let envelope = Envelope::from_bytes(&stored.sealed_private_key).expect("envelope");
        let seed_b64 = LocalEnvelopeSecretStore::new(MASTER)
            .open(&secret_ref, &envelope)
            .expect("open")
            .expose_for_transport()
            .to_owned();
        let seed = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            seed_b64.as_bytes(),
        )
        .expect("our own base64");
        assert_eq!(seed.len(), 32, "the needle must be the real key");

        let needles = [
            seed_b64.clone(),
            hex(&seed),
            format!("{seed:?}"),
            seed.iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ];

        // Everything a leak could ride out on: the facade's Debug, the stored
        // row's Debug, the audit trail as text, and the published document.
        let jwks = identity.published_jwks().await.expect("jwks");
        let rendered = format!(
            "{identity:?} {stored:?} {:?} {} {}",
            trail(&db, &principal).await,
            serde_json::to_string(&jwks).expect("jwks serialises"),
            serde_json::to_string(&stored.public_key).expect("public key is public"),
        );

        for needle in &needles {
            assert!(
                !rendered.contains(needle.as_str()),
                "the private key leaked as {needle:?}"
            );
        }

        // The sealed blob is what IS in the row, and it is not the key.
        assert!(!stored.sealed_private_key.windows(32).any(|w| w == seed));

        // Sanity: this test would notice. The public key IS findable in the
        // same rendering, so the assertions above are not passing because the
        // haystack is empty.
        assert!(
            rendered.contains(
                PublicKey::from_slice(&stored.public_key)
                    .expect("32 bytes")
                    .key_id()
                    .as_str()
            )
        );
    }
}
