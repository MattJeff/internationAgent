//! Who is calling, established from the credential and from nothing else.
//!
//! # The hole this closes
//!
//! The previous API took `tenant_id` from wherever it appeared — a path
//! segment, a JSON field, a header a client set. Any of those means a caller
//! can name a tenant that is not theirs, and the only thing standing between
//! them and its data is every handler remembering to check. One did not.
//!
//! So [`Principal`] is produced in exactly one place: [`require_api_key`],
//! from the `Authorization` header. It is not `Deserialize`, so it cannot
//! arrive in a body. Handlers get it as an extractor, and the tenant id they
//! read is the one the key proved. A path parameter named `tenant_id` should
//! not exist; if one ever does, it is decoration, and this module is still the
//! authority.
//!
//! # Where the keys live
//!
//! `AGENTOS_API_KEYS`, as `label:tenant-uuid:secret`, comma separated. There
//! is no `api_keys` table in the schema, and inventing one is a migration this
//! unit does not own.
//!
//! ponytail: an env-var keyring. It has the properties that matter — the
//! secret is never in the database, rotation is a redeploy, and an unset var
//! authenticates nobody — and it has one real ceiling: keys cannot be issued
//! or revoked without a restart. When self-service keys are a requirement,
//! this becomes an `api_keys (tenant_id, label, secret_hash)` table read
//! through `Db::admin_tx_bypassing_rls` (the lookup precedes knowing the
//! tenant, so it cannot be tenant-scoped) with an argon2 or HMAC digest
//! instead of the raw secret. [`ApiKeys::lookup`] is the only function that
//! changes.

use std::sync::Arc;

use agentos_domain::ids::TenantId;
use agentos_store::audit::AuditActor;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;

/// The authenticated caller.
///
/// Deliberately not `Deserialize` and deliberately without a public
/// constructor from strings: the only way to get one is to present a key.
///
/// Not to be confused with `agentos_app::gate::Principal`, which additionally
/// names the *employee* an action is attributed to. A route builds that one by
/// pairing this tenant and actor with an employee id from its path — and the
/// tenant still comes from here, so a path naming another tenant's employee
/// simply finds nothing.
#[derive(Debug, Clone)]
pub struct Principal {
    /// The tenant every query this request makes will be confined to.
    pub tenant_id: TenantId,
    /// Who to attribute the request to in the audit trail.
    pub actor: AuditActor,
}

/// One configured credential.
#[derive(Debug, Clone)]
struct ApiKey {
    /// Human name for the key, e.g. `ops-console`. Becomes the audit actor —
    /// so the trail says which key acted, never what the secret was.
    label: String,
    tenant_id: TenantId,
    secret: String,
}

/// The keyring, parsed once at boot and shared by every request.
#[derive(Debug, Clone, Default)]
pub struct ApiKeys(Arc<Vec<ApiKey>>);

/// Why `AGENTOS_API_KEYS` could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ApiKeysError {
    /// An entry was not `label:tenant-uuid:secret`.
    #[error("entry {index} is not `label:tenant-uuid:secret`")]
    Shape {
        /// Zero-based position of the offending entry.
        index: usize,
    },
    /// The middle field is not a UUID.
    #[error("entry {index} has an unparseable tenant id")]
    TenantId {
        /// Zero-based position of the offending entry.
        index: usize,
    },
    /// A short secret is a guessable secret.
    #[error("entry {index} has a secret shorter than {min} characters", min = ApiKeys::MIN_SECRET_LEN)]
    WeakSecret {
        /// Zero-based position of the offending entry.
        index: usize,
    },
}

impl ApiKeys {
    /// Shortest secret we will boot with. 32 characters of anything is beyond
    /// online guessing; anything shorter is a typo or a placeholder, and both
    /// are better caught at boot than at 3am.
    pub const MIN_SECRET_LEN: usize = 32;

    /// Parse `label:tenant-uuid:secret,label:tenant-uuid:secret,…`.
    ///
    /// An empty string is a valid, empty keyring — the server boots and
    /// authenticates nobody, which is the correct failure mode for a
    /// misconfigured deployment.
    pub fn parse(raw: &str) -> Result<Self, ApiKeysError> {
        let keys = raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .enumerate()
            .map(|(index, entry)| {
                // `splitn(3)` so a secret may itself contain colons.
                let mut fields = entry.splitn(3, ':');
                let (Some(label), Some(tenant), Some(secret)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return Err(ApiKeysError::Shape { index });
                };
                if label.is_empty() {
                    return Err(ApiKeysError::Shape { index });
                }
                if secret.len() < Self::MIN_SECRET_LEN {
                    return Err(ApiKeysError::WeakSecret { index });
                }
                Ok(ApiKey {
                    label: label.to_owned(),
                    tenant_id: tenant
                        .parse()
                        .map_err(|_| ApiKeysError::TenantId { index })?,
                    secret: secret.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self(Arc::new(keys)))
    }

    /// No keys configured: nothing can authenticate.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many keys are configured. For the boot log — never the secrets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Resolve a presented secret.
    ///
    /// A linear scan with a constant-time comparison, not a `HashMap`: the map
    /// would hash the attacker's input and then compare it with `==`, which
    /// returns as soon as two bytes differ. Ten keys is not a scan worth
    /// optimising.
    pub fn lookup(&self, presented: &str) -> Option<Principal> {
        self.0
            .iter()
            .find(|key| ct_eq(key.secret.as_bytes(), presented.as_bytes()))
            .map(|key| Principal {
                tenant_id: key.tenant_id,
                actor: AuditActor::Operator(key.label.clone()),
            })
    }
}

/// Compare without an early exit. The length is allowed to leak — the secret's
/// length is not the secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reject the request, or attach a [`Principal`] to it.
///
/// Sits above every route that touches tenant data and below `/livez` and
/// `/readyz`, which must answer while the keyring is empty or the database is
/// down.
pub async fn require_api_key(
    State(keys): State<ApiKeys>,
    mut req: Request,
    next: Next,
) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    let Some(principal) = presented.and_then(|secret| keys.lookup(secret)) else {
        // One response for "no header", "wrong scheme" and "wrong secret": the
        // distinction is only ever useful to someone probing.
        let mut response = ApiError::unauthorized().into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"agentos\""),
        );
        return response;
    };

    // The one place a Principal enters the request.
    req.extensions_mut().insert(principal);
    next.run(req).await
}

impl<S: Send + Sync> FromRequestParts<S> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            // Not a client error: a route that extracts a Principal was mounted
            // outside `require_api_key`. Fail closed and page someone.
            tracing::error!(
                path = %parts.uri.path(),
                "route extracts a Principal but is not behind require_api_key"
            );
            ApiError::internal()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210";

    fn keyring() -> (TenantId, ApiKeys) {
        let tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let raw = format!("ops-console:{}:{SECRET}", tenant.as_uuid());
        (tenant, ApiKeys::parse(&raw).expect("valid keyring"))
    }

    /// A router whose only handler flips `reached`, behind the auth layer.
    fn app(keys: ApiKeys, reached: Arc<AtomicBool>) -> Router {
        Router::new()
            .route(
                "/employees/{id}",
                get(move |principal: Principal| {
                    let reached = reached.clone();
                    async move {
                        reached.store(true, Ordering::SeqCst);
                        principal.tenant_id.to_string()
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(keys, require_api_key))
    }

    async fn call(app: Router, header: Option<&str>) -> (StatusCode, String) {
        let mut req = HttpRequest::builder().uri("/employees/anything");
        if let Some(value) = header {
            req = req.header(header::AUTHORIZATION, value);
        }
        let response = app
            .oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("service");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn an_unauthenticated_request_is_refused_before_the_handler_runs() {
        let (_, keys) = keyring();

        for header in [
            None,
            Some("Bearer wrong"),
            // Right secret, wrong scheme.
            Some(SECRET),
            Some(&format!("Basic {SECRET}")),
            // A key for a tenant this deployment does not have.
            Some(&format!("Bearer {OTHER}")),
        ] {
            let reached = Arc::new(AtomicBool::new(false));
            let (status, _) = call(app(keys.clone(), reached.clone()), header).await;

            assert_eq!(status, StatusCode::UNAUTHORIZED, "for header {header:?}");
            assert!(
                !reached.load(Ordering::SeqCst),
                "the handler ran for header {header:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_valid_key_names_its_own_tenant() {
        let (tenant, keys) = keyring();
        let reached = Arc::new(AtomicBool::new(false));

        let (status, body) = call(
            app(keys, reached.clone()),
            Some(&format!("Bearer {SECRET}")),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(reached.load(Ordering::SeqCst));
        assert_eq!(
            body,
            tenant.to_string(),
            "the tenant came from the key, not from the path"
        );
    }

    #[tokio::test]
    async fn an_empty_keyring_authenticates_nobody() {
        let keys = ApiKeys::parse("   ").expect("empty is valid");
        assert!(keys.is_empty());

        let reached = Arc::new(AtomicBool::new(false));
        let (status, _) = call(
            app(keys, reached.clone()),
            Some(&format!("Bearer {SECRET}")),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!reached.load(Ordering::SeqCst));
    }

    #[test]
    fn a_malformed_keyring_is_a_boot_failure_not_a_silent_skip() {
        let tenant = Uuid::from_u128(1);
        assert!(matches!(
            ApiKeys::parse("no-colons-here"),
            Err(ApiKeysError::Shape { index: 0 })
        ));
        assert!(matches!(
            ApiKeys::parse(&format!("label:not-a-uuid:{SECRET}")),
            Err(ApiKeysError::TenantId { index: 0 })
        ));
        assert!(matches!(
            ApiKeys::parse(&format!("label:{tenant}:short")),
            Err(ApiKeysError::WeakSecret { index: 0 })
        ));
        // The index points at the offending entry, not at the first one.
        assert!(matches!(
            ApiKeys::parse(&format!("a:{tenant}:{SECRET}, b:{tenant}:short")),
            Err(ApiKeysError::WeakSecret { index: 1 })
        ));
    }

    #[test]
    fn a_secret_may_contain_colons() {
        let tenant = Uuid::from_u128(7);
        let secret = format!("{SECRET}:with:colons");
        let keys = ApiKeys::parse(&format!("label:{tenant}:{secret}")).expect("valid");
        assert_eq!(keys.len(), 1);
        assert!(keys.lookup(&secret).is_some());
        assert!(keys.lookup(SECRET).is_none());
    }

    #[test]
    fn the_actor_is_the_key_label_never_the_secret() {
        let (_, keys) = keyring();
        let principal = keys.lookup(SECRET).expect("known key");
        match principal.actor {
            AuditActor::Operator(who) => assert_eq!(who, "ops-console"),
            other => panic!("expected an operator, got {other:?}"),
        }
    }

    #[test]
    fn comparison_does_not_short_circuit() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }
}
