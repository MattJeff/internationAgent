//! Secret storage, keyed on [`SecretRef`].
//!
//! Two implementations:
//!
//! * [`MemorySecretStore`] — the mock. A map, nothing else.
//! * [`LocalEnvelopeSecretStore`] — AES-256-GCM envelope encryption for local
//!   and self-hosted deployments, deliberately shaped like KMS.
//!
//! # Why the local implementation is KMS-shaped
//!
//! It does what KMS does, in process: a fresh random **data key** encrypts the
//! plaintext, and the **master key** encrypts the data key. Only the wrapped
//! data key and the ciphertext are stored. Swapping in `kms:Encrypt` /
//! `kms:Decrypt` later replaces the body of two private functions —
//! [`LocalEnvelopeSecretStore::seal`] and [`LocalEnvelopeSecretStore::open`]
//! keep their signatures, and nothing above them changes.
//!
//! The part that must be right *now* is the AAD, because AAD is KMS's
//! encryption context and it is authenticated, not encrypted — you cannot add
//! it to existing ciphertexts afterwards without re-encrypting every secret you
//! own:
//!
//! * The data key is wrapped under `tenant={tenant_id}`. A ciphertext row
//!   lifted out of tenant A and replayed in tenant B's context fails to
//!   authenticate, so it decrypts to nothing at all — not to A's password. That
//!   is the cross-tenant boundary, enforced by the cipher rather than by a
//!   `WHERE tenant_id = $1` somebody may one day forget.
//! * The payload is sealed under the full [`SecretRef`], so a ciphertext cannot
//!   be moved between employees or renamed between fields inside one tenant
//!   either.
//!
//! Nonces are 96-bit random and drawn fresh for every encryption — GCM nonce
//! reuse under one key is catastrophic, not merely untidy.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use agentos_domain::ids::{EmployeeId, SecretRef, TenantId};
use async_trait::async_trait;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{ProviderError, Secret};

/// GCM's only sane nonce size.
const NONCE_LEN: usize = 12;
/// AES-256.
const KEY_LEN: usize = 32;

fn not_found() -> ProviderError {
    ProviderError::Terminal {
        code: "secret_not_found",
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Where an employee's credentials live.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Store (or overwrite) the value at `secret_ref`.
    async fn put(&self, secret_ref: &SecretRef, value: &Secret) -> Result<(), ProviderError>;

    /// Fetch the value. `Terminal { code: "secret_not_found" }` if absent.
    async fn get(&self, secret_ref: &SecretRef) -> Result<Secret, ProviderError>;

    /// Delete a whole subtree and report how many secrets went with it.
    ///
    /// `employee_id: Some(e)` deletes one employee's secrets — offboarding.
    /// `None` deletes everything the tenant owns — tenant deletion. There is no
    /// wider prefix on purpose: "delete all secrets" is not an API.
    async fn delete_prefix(
        &self,
        tenant_id: TenantId,
        employee_id: Option<EmployeeId>,
    ) -> Result<usize, ProviderError>;
}

/// Does this ref fall inside the requested subtree?
fn in_prefix(secret_ref: &SecretRef, tenant_id: TenantId, employee_id: Option<EmployeeId>) -> bool {
    secret_ref.tenant_id() == tenant_id && employee_id.is_none_or(|e| secret_ref.employee_id() == e)
}

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

/// In-memory [`SecretStore`] for tests. Plaintext, in a map, on purpose.
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    rows: Mutex<HashMap<SecretRef, Secret>>,
}

impl MemorySecretStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SecretRef, Secret>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    async fn put(&self, secret_ref: &SecretRef, value: &Secret) -> Result<(), ProviderError> {
        self.lock().insert(
            secret_ref.clone(),
            Secret::new(value.expose_for_transport()),
        );
        Ok(())
    }

    async fn get(&self, secret_ref: &SecretRef) -> Result<Secret, ProviderError> {
        self.lock()
            .get(secret_ref)
            .map(|s| Secret::new(s.expose_for_transport()))
            .ok_or_else(not_found)
    }

    async fn delete_prefix(
        &self,
        tenant_id: TenantId,
        employee_id: Option<EmployeeId>,
    ) -> Result<usize, ProviderError> {
        let mut rows = self.lock();
        let before = rows.len();
        rows.retain(|k, _| !in_prefix(k, tenant_id, employee_id));
        Ok(before - rows.len())
    }
}

// ---------------------------------------------------------------------------
// Local envelope store
// ---------------------------------------------------------------------------

/// One encrypted secret: the wrapped data key and the payload it protects.
///
/// The plaintext appears nowhere, and neither does the data key.
///
/// [`Envelope::to_bytes`] is the persistence form, and it leads with a version
/// byte rather than deriving `Serialize`. Two reasons, and the second is the
/// one that matters. A derived encoding is defined by whatever the struct
/// fields happen to be, so reordering a field silently invalidates every row
/// already written. And a key rotation has to be able to read the old format
/// while writing the new one — a rewrap that cannot read what it is replacing
/// is not a rewrap. The tag is what makes that possible later without a
/// migration that decrypts the whole table in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Data key encrypted under the master key, AAD `tenant={tenant_id}`.
    wrapped_key: Vec<u8>,
    /// Nonce used to wrap the data key.
    key_nonce: [u8; NONCE_LEN],
    /// Payload encrypted under the data key, AAD the full [`SecretRef`].
    ciphertext: Vec<u8>,
    /// Nonce used for the payload.
    nonce: [u8; NONCE_LEN],
}

/// The only encoding version that exists. A reader that meets any other byte
/// refuses rather than guessing, because guessing at a ciphertext layout means
/// handing AES-GCM the wrong nonce and getting an authentication failure that
/// looks like a corrupt master key.
const ENVELOPE_V1: u8 = 1;

impl Envelope {
    /// The persistence form: `[version][key_nonce][nonce][u32 wrapped_len][wrapped_key][ciphertext]`.
    ///
    /// Lengths are big-endian and the trailing ciphertext is implicit, so the
    /// encoding is unambiguous without a length prefix on the last field.
    /// Nothing secret is exposed by this — both fields are already ciphertext,
    /// and the data key is wrapped under the master key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let wrapped_len = u32::try_from(self.wrapped_key.len())
            .expect("a wrapped AES-256 data key is 40 bytes, not 4 GiB");
        let mut out = Vec::with_capacity(
            1 + NONCE_LEN * 2 + 4 + self.wrapped_key.len() + self.ciphertext.len(),
        );
        out.push(ENVELOPE_V1);
        out.extend_from_slice(&self.key_nonce);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&wrapped_len.to_be_bytes());
        out.extend_from_slice(&self.wrapped_key);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Read back what [`Envelope::to_bytes`] wrote.
    ///
    /// Every length is checked before it is used to slice. A stored row is
    /// attacker-reachable in exactly one scenario — someone who can already
    /// write the table — but a panic there would be a denial of service reached
    /// through a column, so this returns an error for every malformed input
    /// including the empty one.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, ProviderError> {
        const HEAD: usize = 1 + NONCE_LEN * 2 + 4;
        let malformed = || ProviderError::Terminal {
            code: "envelope_malformed",
        };

        if raw.len() < HEAD || raw[0] != ENVELOPE_V1 {
            return Err(malformed());
        }
        let key_nonce: [u8; NONCE_LEN] =
            raw[1..1 + NONCE_LEN].try_into().map_err(|_| malformed())?;
        let nonce: [u8; NONCE_LEN] = raw[1 + NONCE_LEN..1 + NONCE_LEN * 2]
            .try_into()
            .map_err(|_| malformed())?;
        let wrapped_len = u32::from_be_bytes(
            raw[1 + NONCE_LEN * 2..HEAD]
                .try_into()
                .map_err(|_| malformed())?,
        ) as usize;

        // Checked add: a hostile length near u32::MAX would otherwise wrap and
        // pass the bounds check below on a 32-bit target.
        let end = HEAD.checked_add(wrapped_len).ok_or_else(malformed)?;
        if end > raw.len() {
            return Err(malformed());
        }
        Ok(Self {
            wrapped_key: raw[HEAD..end].to_vec(),
            key_nonce,
            ciphertext: raw[end..].to_vec(),
            nonce,
        })
    }
}

/// AES-256-GCM envelope store with a local master key.
///
/// Stands in for KMS in dev and in self-hosted deployments; see the module docs
/// for what has to be right today so the swap stays a body change.
pub struct LocalEnvelopeSecretStore {
    master_key: Zeroizing<[u8; KEY_LEN]>,
    rows: Mutex<HashMap<SecretRef, Envelope>>,
}

impl fmt::Debug for LocalEnvelopeSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEnvelopeSecretStore")
            .field("master_key", &Secret::REDACTED)
            .field("rows", &self.lock().len())
            .finish()
    }
}

impl LocalEnvelopeSecretStore {
    /// Build a store around a 32-byte master key.
    ///
    /// In production this comes from the deployment's own secret material; the
    /// equivalent under KMS is a key id, at which point this argument goes away.
    pub fn new(master_key: [u8; KEY_LEN]) -> Self {
        Self {
            master_key: Zeroizing::new(master_key),
            rows: Mutex::new(HashMap::new()),
        }
    }

    /// Encrypt a value for `secret_ref`, without storing it.
    ///
    /// Public so a test can prove that an envelope produced for one tenant does
    /// not open under another's context.
    pub fn seal(&self, secret_ref: &SecretRef, value: &Secret) -> Result<Envelope, ProviderError> {
        let mut data_key = Zeroizing::new([0u8; KEY_LEN]);
        rand::rng().fill_bytes(data_key.as_mut());

        let (nonce, ciphertext) = encrypt(
            &data_key,
            payload_aad(secret_ref).as_bytes(),
            value.expose_for_transport().as_bytes(),
        )?;
        let (key_nonce, wrapped_key) = encrypt(
            &self.master_key,
            wrap_aad(secret_ref).as_bytes(),
            &*data_key,
        )?;

        Ok(Envelope {
            wrapped_key,
            key_nonce,
            ciphertext,
            nonce,
        })
    }

    /// Decrypt an envelope *as* `secret_ref`.
    ///
    /// Both AADs are rebuilt from the ref supplied here, so opening with the
    /// wrong tenant, employee or name fails authentication rather than
    /// returning someone else's password.
    pub fn open(
        &self,
        secret_ref: &SecretRef,
        envelope: &Envelope,
    ) -> Result<Secret, ProviderError> {
        let unwrapped = Zeroizing::new(decrypt(
            &self.master_key,
            wrap_aad(secret_ref).as_bytes(),
            &envelope.key_nonce,
            &envelope.wrapped_key,
        )?);
        let data_key: [u8; KEY_LEN] =
            unwrapped
                .as_slice()
                .try_into()
                .map_err(|_| ProviderError::Terminal {
                    code: "secret_key_length",
                })?;
        let data_key = Zeroizing::new(data_key);

        let plain = Zeroizing::new(decrypt(
            &data_key,
            payload_aad(secret_ref).as_bytes(),
            &envelope.nonce,
            &envelope.ciphertext,
        )?);
        let text = std::str::from_utf8(&plain).map_err(|_| ProviderError::Terminal {
            code: "secret_not_utf8",
        })?;
        Ok(Secret::new(text))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SecretRef, Envelope>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The encryption context that binds a ciphertext to its tenant.
fn wrap_aad(secret_ref: &SecretRef) -> String {
    format!("tenant={}", secret_ref.tenant_id())
}

/// The encryption context that binds a payload to its exact slot.
fn payload_aad(secret_ref: &SecretRef) -> String {
    secret_ref.to_string()
}

/// Encrypt under a fresh random nonce, which is returned with the ciphertext.
fn encrypt(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    msg: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), ProviderError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);

    let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .encrypt(Nonce::from_slice(&nonce), Payload { msg, aad })
        .map_err(|_| ProviderError::Terminal {
            code: "secret_encrypt_failed",
        })?;
    Ok((nonce, ciphertext))
}

fn decrypt(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        // One code for every failure: a wrong key, a wrong tenant and a
        // tampered tag are indistinguishable to the caller, which is the point.
        .map_err(|_| ProviderError::Terminal {
            code: "secret_decrypt_failed",
        })
}

#[async_trait]
impl SecretStore for LocalEnvelopeSecretStore {
    async fn put(&self, secret_ref: &SecretRef, value: &Secret) -> Result<(), ProviderError> {
        let envelope = self.seal(secret_ref, value)?;
        self.lock().insert(secret_ref.clone(), envelope);
        Ok(())
    }

    async fn get(&self, secret_ref: &SecretRef) -> Result<Secret, ProviderError> {
        let envelope = self.lock().get(secret_ref).cloned().ok_or_else(not_found)?;
        self.open(secret_ref, &envelope)
    }

    async fn delete_prefix(
        &self,
        tenant_id: TenantId,
        employee_id: Option<EmployeeId>,
    ) -> Result<usize, ProviderError> {
        let mut rows = self.lock();
        let before = rows.len();
        rows.retain(|k, _| !in_prefix(k, tenant_id, employee_id));
        Ok(before - rows.len())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    const MASTER: [u8; KEY_LEN] = [7u8; KEY_LEN];

    fn envelope_store() -> LocalEnvelopeSecretStore {
        LocalEnvelopeSecretStore::new(MASTER)
    }

    fn secret_ref(tenant_id: TenantId, employee_id: EmployeeId, name: &str) -> SecretRef {
        SecretRef::new(tenant_id, employee_id, name).unwrap()
    }

    fn ids() -> (TenantId, EmployeeId) {
        (TenantId::new_v7(Utc::now()), EmployeeId::new_v7(Utc::now()))
    }

    /// Behaviour every [`SecretStore`] owes its callers.
    async fn verify_contract<S: SecretStore>(store: &S) {
        let (tenant_a, employee_a1) = ids();
        let employee_a2 = EmployeeId::new_v7(Utc::now());
        let (tenant_b, employee_b) = ids();

        let portal = secret_ref(tenant_a, employee_a1, "portal-password");
        let smtp = secret_ref(tenant_a, employee_a1, "smtp-token");
        let sibling = secret_ref(tenant_a, employee_a2, "portal-password");
        let other_tenant = secret_ref(tenant_b, employee_b, "portal-password");

        // Missing is missing.
        assert_eq!(
            store.get(&portal).await.unwrap_err().code(),
            "secret_not_found"
        );

        for r in [&portal, &smtp, &sibling, &other_tenant] {
            store.put(r, &Secret::new("hunter2")).await.unwrap();
        }
        assert_eq!(
            store.get(&portal).await.unwrap().expose_for_transport(),
            "hunter2"
        );

        // Overwrite in place.
        store.put(&portal, &Secret::new("hunter3")).await.unwrap();
        assert_eq!(
            store.get(&portal).await.unwrap().expose_for_transport(),
            "hunter3"
        );

        // Offboarding one employee takes exactly that employee's subtree.
        assert_eq!(
            store.delete_prefix(tenant_a, Some(employee_a1)).await,
            Ok(2)
        );
        assert!(store.get(&portal).await.is_err());
        assert!(store.get(&smtp).await.is_err());
        assert!(store.get(&sibling).await.is_ok());
        assert!(store.get(&other_tenant).await.is_ok());

        // Deleting the tenant takes the rest of it, and nothing of tenant B.
        assert_eq!(store.delete_prefix(tenant_a, None).await, Ok(1));
        assert!(store.get(&sibling).await.is_err());
        assert!(store.get(&other_tenant).await.is_ok());
    }

    #[tokio::test]
    async fn memory_store_satisfies_the_contract() {
        verify_contract(&MemorySecretStore::new()).await;
    }

    #[tokio::test]
    async fn envelope_store_satisfies_the_contract() {
        verify_contract(&envelope_store()).await;
    }

    #[test]
    fn a_ciphertext_does_not_open_in_another_tenants_context() {
        let store = envelope_store();
        let (tenant_a, employee) = ids();
        let tenant_b = TenantId::new_v7(Utc::now());

        let mine = secret_ref(tenant_a, employee, "portal-password");
        // Same employee, same name, different tenant: only the AAD differs.
        let theirs = secret_ref(tenant_b, employee, "portal-password");

        let envelope = store.seal(&mine, &Secret::new("hunter2")).unwrap();
        assert_eq!(
            store.open(&mine, &envelope).unwrap().expose_for_transport(),
            "hunter2"
        );

        let stolen = store.open(&theirs, &envelope).unwrap_err();
        assert_eq!(stolen.code(), "secret_decrypt_failed");
        assert!(!stolen.is_retryable());

        // Nor moved between employees or fields inside one tenant.
        let other_employee =
            secret_ref(tenant_a, EmployeeId::new_v7(Utc::now()), "portal-password");
        assert!(store.open(&other_employee, &envelope).is_err());
        assert!(
            store
                .open(&secret_ref(tenant_a, employee, "smtp-token"), &envelope)
                .is_err()
        );
    }

    #[test]
    fn the_same_plaintext_encrypts_differently_every_time() {
        let store = envelope_store();
        let (tenant, employee) = ids();
        let r = secret_ref(tenant, employee, "portal-password");

        let first = store.seal(&r, &Secret::new("hunter2")).unwrap();
        let second = store.seal(&r, &Secret::new("hunter2")).unwrap();

        // Fresh nonce, fresh data key: nothing about the two rows matches.
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.key_nonce, second.key_nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(first.wrapped_key, second.wrapped_key);

        // Both still open.
        for e in [&first, &second] {
            assert_eq!(store.open(&r, e).unwrap().expose_for_transport(), "hunter2");
        }
    }

    #[test]
    fn a_tampered_envelope_is_rejected_and_never_partially_decrypted() {
        let store = envelope_store();
        let (tenant, employee) = ids();
        let r = secret_ref(tenant, employee, "portal-password");

        let mut envelope = store.seal(&r, &Secret::new("hunter2")).unwrap();
        envelope.ciphertext[0] ^= 0xff;
        assert_eq!(
            store.open(&r, &envelope).unwrap_err().code(),
            "secret_decrypt_failed"
        );
    }

    #[test]
    fn a_wrong_master_key_opens_nothing() {
        let (tenant, employee) = ids();
        let r = secret_ref(tenant, employee, "portal-password");

        let envelope = envelope_store().seal(&r, &Secret::new("hunter2")).unwrap();
        let impostor = LocalEnvelopeSecretStore::new([9u8; KEY_LEN]);
        assert_eq!(
            impostor.open(&r, &envelope).unwrap_err().code(),
            "secret_decrypt_failed"
        );
    }

    #[test]
    fn debug_leaks_neither_the_master_key_nor_a_plaintext() {
        let store = envelope_store();
        let (tenant, employee) = ids();
        let r = secret_ref(tenant, employee, "portal-password");
        let envelope = store.seal(&r, &Secret::new("hunter2")).unwrap();

        let rendered = format!("{store:?} {envelope:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains(Secret::REDACTED), "{rendered}");
    }
}
