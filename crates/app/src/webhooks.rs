//! Which customer a provider callback belongs to — the half of the answer that
//! needs a cipher.
//!
//! `agentos_store::webhooks` reads the row. This opens the sealed secret in it
//! and hands `apps/server` an [`Endpoint`] it can verify a signature against.
//! `migrations/0053_webhook_endpoints.sql` argues the design; the two things
//! worth repeating here are the two this file is responsible for.
//!
//! # The AAD is `webhook://<tenant>`
//!
//! The lookup **bypasses RLS** — it has to, it precedes knowing the tenant — so
//! the property that has to hold without help from the database is that a row
//! cannot be opened as anybody but its own tenant. Sealing under a context built
//! from the row's own `tenant_id` is what provides it: a blob lifted out of
//! another tenant's row opens as nothing, so a database dump is not a set of
//! signing secrets and an operator with UPDATE on the table cannot point tenant
//! B's endpoint at tenant A's secret.
//!
//! Not `webhook://<tenant>/<path>`, which was the first draft. A tenant has
//! exactly one row per provider (`webhook_endpoints_tenant_provider_key`), so
//! there is no second row of the same tenant to move a blob between and the path
//! would defend nothing — while a rotation, which keeps the stored path on
//! purpose, would seal under a path the row does not have and produce an
//! endpoint that 401s every genuine delivery. `crate::model_access` seals under
//! `model://<tenant>` for the same reason.
//!
//! The `webhook://` scheme keeps this key space disjoint from `secret://`
//! (`SecretRef`), `mcp://` (`crate::mcp`) and `model://` (`crate::model_access`),
//! which is the rule [`crate::mcp::Credentials::seal_as`] states for its
//! `context` argument.
//!
//! # The plaintext lives here, for the length of one signature check
//!
//! [`resolve`] returns a [`Secret`], which is `agentos-providers`' redacting
//! type — no `Debug`, no `Display`, no `Serialize`. `apps/server` already holds
//! one of those for every `AGENTOS_WEBHOOK_SECRETS` entry (that is why
//! `crate::inbound` re-exports `Secret` and `verify_signature` at all), so this
//! adds a *source* of secrets to the HTTP layer and not a *kind*. What it must
//! not add is a rendering, and the search for one is
//! `apps/server/tests/platform_signup.rs::a_providers_signing_secret_is_usable_and_findable_nowhere`
//! — in that file rather than a binary of its own because the property being
//! searched is what a *separate process* wrote to its log, which is the same
//! hazard `crates/app/tests/model_key_never_leaks.rs` opens by describing and
//! the same harness that already sidesteps it.

use agentos_domain::ids::TenantId;
use agentos_providers::Secret;
use agentos_store::audit::AuditActor;
use agentos_store::db::{Db, StoreError};
use agentos_store::webhooks as store;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{DateTime, Utc};
use rand::RngCore as _;

use crate::mcp::Credentials;

/// What every minted path starts with. `whe_` for *webhook endpoint*, and a
/// fixed prefix is what makes one recognisable in a provider's dashboard next to
/// twelve other URLs.
pub const PATH_PREFIX: &str = "whe_";

/// Bytes of entropy in a minted path.
///
/// 16, i.e. 128 bits. Not a credential — the signature is still checked — but
/// see `0053`: when two tenants sit behind one provider account they hold the
/// same signing secret, and the address is then the only thing separating them.
/// It is not a tunable for that reason.
const PATH_BYTES: usize = 16;

/// A resolved endpoint: whose the delivery is, what reads it, what signed it.
///
/// One type for both registries. `apps/server` builds these from
/// `AGENTOS_WEBHOOK_SECRETS` at boot and gets them from [`resolve`] at request
/// time, and there is exactly one `verify_signature` call downstream of both —
/// two would be two places a check can be dropped from.
pub struct Endpoint {
    /// The tenant the delivery is filed against. From the registration or the
    /// row, never from the path and never from the payload — a body that could
    /// name its own tenant is a body that can write into someone else's queue.
    pub tenant_id: TenantId,
    /// Which ingest reads the stored delivery; becomes
    /// `webhook.{provider}.received`. Separate from the path because a minted
    /// path is opaque and cannot name it.
    pub provider: String,
    /// The signing secret this endpoint's deliveries are MACed with.
    pub secret: Secret,
}

/// Why an endpoint could not be resolved or registered.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// The database said no.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// The row is there and this deployment cannot read it: the master key
    /// changed, or the blob was moved between rows. **Never a 404 and never a
    /// 401** — both would point an operator at the provider when the fault is on
    /// our side of the wire, which is `McpError::Credential`'s argument in full.
    ///
    /// Carries the cipher's own code and nothing else: no blob, no context, no
    /// length.
    #[error("the stored signing secret for this endpoint could not be read: {code}")]
    Cipher {
        /// `envelope_malformed` or `secret_decrypt_failed`.
        code: &'static str,
    },
}

impl EndpointError {
    /// Stable, low-cardinality metric label. Never third-party text.
    pub const fn code(&self) -> &'static str {
        match self {
            EndpointError::Store(_) => "store",
            EndpointError::Cipher { code } => code,
        }
    }
}

/// `whe_` plus 16 CSPRNG bytes in base64url — 26 characters, inside the table's
/// `^[A-Za-z0-9_-]{16,64}$`.
///
/// `rand::rng()` is the OS CSPRNG, the same source `crate::api_keys::mint` draws
/// a secret from and `providers::secrets` draws data keys from.
pub fn mint_path() -> String {
    let mut bytes = [0u8; PATH_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    format!("{PATH_PREFIX}{}", B64.encode(bytes))
}

/// The encryption context a row's secret is sealed under. See the module docs.
fn context(tenant_id: TenantId) -> String {
    format!("webhook://{}", tenant_id.as_uuid())
}

/// The endpoint registered under this path, with its secret opened.
///
/// `Ok(None)` is "no such endpoint", which the route answers 404 — before it
/// reads a byte of the body, and without telling an unauthenticated prober which
/// paths exist.
pub async fn resolve(
    db: &Db,
    credentials: &Credentials,
    path: &str,
) -> Result<Option<Endpoint>, EndpointError> {
    let Some(row) = store::lookup(db, path).await? else {
        return Ok(None);
    };

    // Opened as the row's own tenant. Nothing from the request is in the context
    // — the request supplied the path, and the path is how we found the row, not
    // what proves whose it is.
    let secret = credentials
        .open_as(row.tenant_id, &context(row.tenant_id), &row.sealed_secret)
        .map_err(|err| EndpointError::Cipher { code: err.code() })?;

    Ok(Some(Endpoint {
        tenant_id: row.tenant_id,
        provider: row.provider,
        secret,
    }))
}

/// Register an endpoint for this tenant, or rotate the secret on the one it has.
///
/// Returns the path to paste into the provider's dashboard — a **new** minted
/// one when this is the tenant's first endpoint for `provider`, and the existing
/// one when it is a rotation — together with which of the two it was. See
/// `agentos_store::webhooks::register` for why rotating must not move the URL.
///
/// Takes the secret as a `String` **by value** and never gives it back:
/// `String -> String` is the identity conversion, so the buffer the request body
/// allocated is the one `Secret` zeroizes on drop, where taking a `&str` would
/// copy it and leave the original in the heap. This is `Credentials::seal`'s
/// signature and it is its signature for this reason.
pub async fn register(
    db: &Db,
    credentials: &Credentials,
    tenant_id: TenantId,
    provider: &str,
    secret: String,
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<(String, bool), EndpointError> {
    // Sealed before the transaction opens, so a cipher failure is an error with
    // nothing written — and sealed under the tenant alone, which is why a
    // rotation that discards this freshly minted path in favour of the stored
    // one still produces a row that opens.
    let sealed = seal(credentials, tenant_id, secret)?;
    let path = mint_path();

    Ok(store::register(db, tenant_id, provider, &path, &sealed, actor, now).await?)
}

/// Seal one secret for `tenant_id`.
fn seal(
    credentials: &Credentials,
    tenant_id: TenantId,
    secret: String,
) -> Result<Vec<u8>, EndpointError> {
    credentials
        .seal_as(tenant_id, &context(tenant_id), &Secret::new(secret))
        .map_err(|err| EndpointError::Cipher { code: err.code() })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "webhook-endpoint-tests-master-key";
    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

    fn credentials() -> Credentials {
        Credentials::from_master_key(MASTER)
    }

    #[test]
    fn a_minted_path_is_long_prefixed_and_never_the_same_twice() {
        let (a, b) = (mint_path(), mint_path());
        assert!(a.starts_with(PATH_PREFIX), "{a}");
        assert_ne!(a, b, "two mints must not collide");
        // The table's own `^[A-Za-z0-9_-]{16,64}$`, asserted here so a mint that
        // stops satisfying it fails in this crate rather than as a constraint
        // violation in an operator's terminal.
        assert!((16..=64).contains(&a.len()), "{} chars", a.len());
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "not one URL segment: {a}"
        );
    }

    /// The claim the AAD exists for. Seal for one tenant, try to open as the
    /// other: it must fail authentication rather than hand back a secret. This
    /// is the property the RLS-bypassing lookup depends on.
    #[test]
    fn a_blob_lifted_into_another_tenants_row_opens_as_nothing() {
        let credentials = credentials();
        let (mine, theirs) = (TenantId::new_v7(Utc::now()), TenantId::new_v7(Utc::now()));

        let sealed = seal(&credentials, mine, SECRET.to_owned()).expect("seal");

        // The control: it opens as itself. Without this the test would pass if
        // sealing were broken outright.
        let opened = credentials
            .open_as(mine, &context(mine), &sealed)
            .expect("opens as itself");
        assert_eq!(opened.expose_for_transport(), SECRET);

        // The case a `psql` UPDATE produces.
        assert!(
            credentials
                .open_as(theirs, &context(theirs), &sealed)
                .is_err(),
            "another tenant's row opened this secret"
        );
    }

    /// Two deployments, two master keys, one blob. The second must not open it.
    #[test]
    fn another_deployments_master_key_does_not_open_it() {
        let tenant = TenantId::new_v7(Utc::now());
        let sealed = seal(&credentials(), tenant, SECRET.to_owned()).expect("seal");

        assert!(
            Credentials::from_master_key("a-different-deployment")
                .open_as(tenant, &context(tenant), &sealed)
                .is_err(),
            "a foreign master key opened the secret"
        );
    }

    /// A blob from the neighbouring column of the neighbouring table is not a
    /// signing secret. The scheme is what makes that true.
    #[test]
    fn a_blob_sealed_under_another_scheme_does_not_open_here() {
        let credentials = credentials();
        let tenant = TenantId::new_v7(Utc::now());

        let elsewhere = credentials
            .seal_as(
                tenant,
                &format!("model://{}", tenant.as_uuid()),
                &Secret::new(SECRET.to_owned()),
            )
            .expect("seal");

        assert!(
            credentials
                .open_as(tenant, &context(tenant), &elsewhere)
                .is_err(),
            "a `model://` blob opened as a webhook secret"
        );
    }

    /// The error carries the cipher's code and nothing that could reconstruct
    /// the blob.
    #[test]
    fn a_cipher_failure_names_a_code_and_no_material() {
        let tenant = TenantId::new_v7(Utc::now());
        let sealed = seal(&credentials(), tenant, SECRET.to_owned()).expect("seal");

        let err = credentials()
            .open_as(
                TenantId::new_v7(Utc::now()),
                &context(TenantId::new_v7(Utc::now())),
                &sealed,
            )
            .map_err(|err| EndpointError::Cipher { code: err.code() })
            .expect_err("must not open");

        let rendered = format!("{err} {err:?} {}", err.code());
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(
            !rendered.contains(&B64.encode(&sealed)),
            "the error carries the blob"
        );
    }
}
