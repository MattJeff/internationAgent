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
//! # Where the keys live: two keyrings, and the split is the design
//!
//! **`api_keys`, a table** — every credential a *customer* holds. Issued and
//! destroyed over HTTP with no restart, hashed with HMAC-SHA256
//! (`agentos_app::api_keys` argues that at length), looked up on every request
//! with no cache, so a `DELETE` is felt by the next call and not by the next
//! deploy. This is what the module's old `ponytail:` note promised and this
//! wave built.
//!
//! **`AGENTOS_API_KEYS`, the environment** — unchanged, still `label:tenant-uuid:secret`
//! comma separated, still consulted **first**. It is not a deprecated path: the
//! whole test suite and the runbook stand a server up with it, and resolving one
//! of its entries costs no round trip because [`Keyring::resolve`] returns
//! before it queries anything. Its ceiling is real and now bounded — issuing and
//! revoking still mean a redeploy — so it is a keyring for the deployment's own
//! operators, not for customers.
//!
//! ## Which wins when both name the same secret
//!
//! The environment. Two reasons, and the second is the one that matters:
//!
//! * It is the cheaper path — a linear scan of a handful of entries in memory,
//!   no round trip — and putting it first means the ordinary case pays nothing.
//! * **It cannot be changed by anything running at runtime.** A row is written
//!   by a process; a variable is written by whoever deploys. If the table won,
//!   an INSERT would be able to shadow the operator's own console key and point
//!   it at another tenant, which is a privilege escalation with a
//!   `INSERT ... ON CONFLICT`. The precedence is a `find`-then-`else`, and
//!   `an_env_key_wins_over_a_table_row_naming_the_same_secret` is the test.
//!
//! # And a third keyring, which is not a tenant at all
//!
//! [`PlatformKeys`], from `AGENTOS_PLATFORM_KEYS`, as `label:secret` — no
//! tenant uuid, because it does not speak for one. It authorises exactly two
//! verbs: create a tenant, and issue or revoke that tenant's keys. See
//! `crate::routes::platform` for why the authority to mint had to be a separate
//! principal and not a permission on a tenant's own key.
//!
//! The obvious objection is that this puts a credential back in an environment
//! variable, which is the ceiling this wave exists to break. It does, on
//! purpose, and the split is the answer: **the N credentials customers hold move
//! into the database; the 1 credential the vendor holds stays in the
//! environment.** Rotating the customer's key must not require a deploy, because
//! a deploy interrupts every *other* customer. Rotating the vendor's own key is
//! a deploy the vendor was going to do anyway. And the recursion has to stop
//! somewhere: whatever mints the first credential cannot itself have been
//! minted.

use std::sync::Arc;

use agentos_domain::ids::TenantId;
use agentos_store::audit::AuditActor;
use agentos_store::db::Db;
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
#[derive(Clone)]
struct ApiKey {
    /// Human name for the key, e.g. `ops-console`. Becomes the audit actor —
    /// so the trail says which key acted, never what the secret was.
    label: String,
    tenant_id: TenantId,
    secret: String,
}

// Hand-written, like every other type in this workspace that holds one: a
// derived `Debug` prints `secret` verbatim, and a keyring is exactly the sort of
// thing somebody renders while working out why a request 401'd. The label and
// the tenant are the half that answers that question; the secret never was.
impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("label", &self.label)
            .field("tenant_id", &self.tenant_id)
            .field("secret", &"<redacted>")
            .finish()
    }
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

// ---------------------------------------------------------------------------
// The two keyrings a tenant credential can come from
// ---------------------------------------------------------------------------

/// Everything `require_api_key` needs to answer "whose is this".
///
/// Holds the environment keyring, the pool, and the deployment's key-hashing
/// key. Cheap to clone: an `Arc<Vec<_>>`, a pooled handle and 32 bytes.
///
/// No `Debug`. Not because a rendering would leak — [`ApiKeys`] redacts, and so
/// does [`agentos_app::api_keys::Hasher`] by having none. Because this is the
/// type an axum layer holds, so it is the type that appears in a `Service` type
/// name in a panic, and the fewer ways there are to render a keyring the better.
#[derive(Clone)]
pub struct Keyring {
    /// `AGENTOS_API_KEYS`. Consulted first — see the module docs.
    env: ApiKeys,
    /// Where the `api_keys` table lives.
    db: Db,
    /// Turns a presented token into the digest the table is indexed on.
    hasher: agentos_app::api_keys::Hasher,
}

impl Keyring {
    /// Build the composite keyring. `master_key` is `AGENTOS_MASTER_KEY`; the
    /// hashing key is derived from it, never equal to it.
    pub fn new(env: ApiKeys, db: Db, master_key: &str) -> Self {
        Self {
            env,
            db,
            hasher: agentos_app::api_keys::Hasher::from_master_key(master_key),
        }
    }

    /// The hasher, for the routes that issue and revoke.
    pub fn hasher(&self) -> &agentos_app::api_keys::Hasher {
        &self.hasher
    }

    /// Environment first, then the table.
    ///
    /// `Ok(None)` is "nobody". `Err` is the database, and the caller must not
    /// render it as a 401: a Postgres that is down would otherwise be
    /// indistinguishable from a wrong key, and every customer would be told to
    /// rotate a credential that is fine.
    async fn resolve(
        &self,
        presented: &str,
    ) -> Result<Option<Principal>, agentos_store::db::StoreError> {
        if let Some(principal) = self.env.lookup(presented) {
            return Ok(Some(principal));
        }
        Ok(
            agentos_app::api_keys::authenticate(&self.db, &self.hasher, presented)
                .await?
                .map(|found| Principal {
                    tenant_id: found.tenant_id,
                    // The same actor shape an env key produces, deliberately:
                    // the trail says which key acted, and where the key was
                    // kept is not a fact about the action.
                    actor: AuditActor::Operator(found.label),
                }),
        )
    }
}

/// The master key this crate's own tests derive a hashing key from.
///
/// One constant rather than a literal per test module. Most of those tests
/// exercise the *environment* half of the keyring, where the value only has to
/// exist; the ones that mean to exercise the table half issue a key against this
/// same value, and sharing it is what makes the two halves line up.
#[cfg(test)]
pub(crate) const TEST_MASTER_KEY: &str = "agentos-tests-master-key";

/// Reject the request, or attach a [`Principal`] to it.
///
/// Sits above every route that touches tenant data and below `/livez` and
/// `/readyz`, which must answer while the keyring is empty or the database is
/// down.
///
/// ponytail: the table is read on every authenticated request, with no cache in
/// front of it. That is one indexed equality on a unique `bytea` — and it is
/// what makes revocation instantaneous rather than eventually-consistent, which
/// is the entire point of moving keys out of the environment. The known ceiling
/// is that an unauthenticated flood costs one round trip per request, because
/// the rate limiter is *below* this layer and cannot be above it (it is keyed on
/// the tenant this layer establishes). The upgrade path is a connection-limited
/// ingress, not a TTL: see `agentos_store::api_keys::lookup` on why a cache here
/// would have to be measured in "how long a stolen key still works".
pub async fn require_api_key(
    State(keys): State<Keyring>,
    mut req: Request,
    next: Next,
) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    let resolved = match presented {
        None => Ok(None),
        Some(secret) => keys.resolve(secret).await,
    };

    let principal = match resolved {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            // One response for "no header", "wrong scheme" and "wrong secret":
            // the distinction is only ever useful to someone probing.
            return unauthorized();
        }
        // Never a 401. `ApiError::from` logs the driver error and answers 500 —
        // or 503 for a retryable abort — so an outage reads as an outage.
        Err(err) => return ApiError::from(err).into_response(),
    };

    // The one place a Principal enters the request.
    req.extensions_mut().insert(principal);
    next.run(req).await
}

/// 401 plus the challenge header, in one place so the two middlewares here
/// cannot answer a missing credential two different ways.
fn unauthorized() -> Response {
    let mut response = ApiError::unauthorized().into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"agentos\""),
    );
    response
}

// ---------------------------------------------------------------------------
// The platform principal
// ---------------------------------------------------------------------------

/// A credential that belongs to **no tenant**.
///
/// Its whole reason for existing is what it is *not*: it is not a [`Principal`],
/// so it cannot be extracted by any route in this server that reads tenant data,
/// because every one of those extracts `Principal` and only [`require_api_key`]
/// inserts one. A platform key presented to `/v1/employees` is simply a secret
/// that is not in the tenant keyring, and gets the same 401 as a typo.
///
/// The converse holds by the same construction: a tenant's key is not in
/// [`PlatformKeys`], so it cannot mint or revoke anything. That is the sentence
/// revocation depends on — a stolen key that could issue keys would make
/// revoking it pointless.
#[derive(Debug, Clone)]
pub struct PlatformPrincipal {
    /// The key's human name. Becomes the audit actor on every row the platform
    /// writes into a tenant's trail, so `operator:signup-service` is who a
    /// customer sees issued their credential.
    pub label: String,
}

/// One configured platform credential.
#[derive(Clone)]
struct PlatformKey {
    label: String,
    secret: String,
}

// Hand-written, for the reason [`ApiKey`]'s is — and this one guards the single
// credential that can mint another tenant's keys.
impl std::fmt::Debug for PlatformKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformKey")
            .field("label", &self.label)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The platform keyring, parsed once at boot.
///
/// Empty is the default and the correct default: a deployment that has not been
/// given a platform key has no signup surface at all, and `/v1/platform/*`
/// answers 401 to everybody including us.
#[derive(Debug, Clone, Default)]
pub struct PlatformKeys(Arc<Vec<PlatformKey>>);

/// Why `AGENTOS_PLATFORM_KEYS` could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PlatformKeysError {
    /// An entry was not `label:secret`.
    #[error("entry {index} is not `label:secret`")]
    Shape {
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

impl PlatformKeys {
    /// Parse `label:secret,label:secret,…`.
    ///
    /// **Two fields, not three, and the missing one is the point.** An entry
    /// here names no tenant because this credential speaks for none; a form that
    /// accepted a tenant uuid would be a form somebody eventually pastes a
    /// tenant key into, and it would then hold both authorities at once.
    pub fn parse(raw: &str) -> Result<Self, PlatformKeysError> {
        let keys = raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .enumerate()
            .map(|(index, entry)| {
                // `splitn(2)` so a secret may itself contain colons, same as the
                // tenant keyring.
                let (label, secret) = entry
                    .split_once(':')
                    .ok_or(PlatformKeysError::Shape { index })?;
                if label.is_empty() {
                    return Err(PlatformKeysError::Shape { index });
                }
                if secret.len() < ApiKeys::MIN_SECRET_LEN {
                    return Err(PlatformKeysError::WeakSecret { index });
                }
                Ok(PlatformKey {
                    label: label.to_owned(),
                    secret: secret.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self(Arc::new(keys)))
    }

    /// No platform keys configured: nothing can sign anybody up.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many are configured. For the boot log — never the secrets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Resolve a presented secret. Constant-time, linear, for the same reason
    /// [`ApiKeys::lookup`] is.
    fn lookup(&self, presented: &str) -> Option<PlatformPrincipal> {
        self.0
            .iter()
            .find(|key| ct_eq(key.secret.as_bytes(), presented.as_bytes()))
            .map(|key| PlatformPrincipal {
                label: key.label.clone(),
            })
    }
}

/// Reject the request, or attach a [`PlatformPrincipal`] to it.
///
/// Sits above `/v1/platform/*` and nothing else.
pub async fn require_platform_key(
    State(keys): State<PlatformKeys>,
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
        return unauthorized();
    };

    req.extensions_mut().insert(principal);
    next.run(req).await
}

impl<S: Send + Sync> FromRequestParts<S> for PlatformPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            tracing::error!(
                path = %parts.uri.path(),
                "route extracts a PlatformPrincipal but is not behind require_platform_key"
            );
            ApiError::internal()
        })
    }
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

    /// Shared with every other test module in this crate — see
    /// [`TEST_MASTER_KEY`].
    const MASTER: &str = TEST_MASTER_KEY;

    fn env_keyring() -> (TenantId, ApiKeys) {
        let tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let raw = format!("ops-console:{}:{SECRET}", tenant.as_uuid());
        (tenant, ApiKeys::parse(&raw).expect("valid keyring"))
    }

    /// A secret no `api_keys` row can hold, because nothing has ever seen it.
    ///
    /// **`lookup` is cross-tenant by definition** — it scans the table with no
    /// tenant predicate, which is the whole reason it needs an admin
    /// transaction — so a row another test in this binary left behind is a row
    /// these assertions can see. `an_env_key_wins_over_a_table_row_naming_the_same_secret`
    /// really does leave one holding `SECRET`, deliberately, and a test that
    /// then asserted `SECRET` authenticates nobody would be asserting about the
    /// wrong keyring. A fresh uuid costs nothing and cannot collide.
    fn unheld_secret() -> String {
        format!("{SECRET}-{}", Uuid::now_v7())
    }

    /// A pool, or `None` when there is nothing to talk to.
    ///
    /// [`Keyring`] holds one because the second half of every lookup is a table.
    /// The tests below that are only about the *environment* half still need it
    /// — the type cannot be built without one — and they are still meaningful
    /// without a row in that table, which is the state they run in.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the auth keyring needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A router whose only handler flips `reached`, behind the auth layer.
    fn app(keys: Keyring, reached: Arc<AtomicBool>) -> Router {
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
        let Some(db) = db().await else { return };
        let (_, env) = env_keyring();
        let keys = Keyring::new(env, db, MASTER);

        for header in [
            None,
            Some("Bearer wrong"),
            // Right secret, wrong scheme.
            Some(SECRET),
            Some(&format!("Basic {SECRET}")),
            // A secret neither keyring holds.
            Some(&format!("Bearer {}", unheld_secret())),
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
        let Some(db) = db().await else { return };
        let (tenant, env) = env_keyring();
        let reached = Arc::new(AtomicBool::new(false));

        let (status, body) = call(
            app(Keyring::new(env, db, MASTER), reached.clone()),
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
        let Some(db) = db().await else { return };
        let env = ApiKeys::parse("   ").expect("empty is valid");
        assert!(env.is_empty());

        let reached = Arc::new(AtomicBool::new(false));
        let (status, _) = call(
            app(Keyring::new(env, db, MASTER), reached.clone()),
            Some(&format!("Bearer {}", unheld_secret())),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!reached.load(Ordering::SeqCst));
    }

    /// **Which keyring wins.** One secret, two homes, two different tenants —
    /// and the answer has to be the one nothing at runtime can rewrite.
    ///
    /// Break it by swapping the two branches of [`Keyring::resolve`] and this
    /// says:
    ///
    /// ```text
    /// assertion `left == right` failed: a row must not be able to shadow the
    /// deployment's own keyring
    /// ```
    #[tokio::test]
    async fn an_env_key_wins_over_a_table_row_naming_the_same_secret() {
        let Some(db) = db().await else { return };

        // A secret of this run's own, in *both* keyrings. Fresh rather than the
        // module's `SECRET`, because `api_keys.secret_hash` is unique: a fixed
        // one would make the row survive the run and the second run collide on
        // it, and a test that only passes against a clean database is a test
        // nobody can re-run while debugging the thing it caught.
        let shared = unheld_secret();
        let env_tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let env = ApiKeys::parse(&format!("ops-console:{}:{shared}", env_tenant.as_uuid()))
            .expect("valid keyring");

        // A real tenant with a real key whose secret is byte-for-byte the one
        // the environment already claims.
        let row_tenant = TenantId::new_v7(chrono::Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'shadow')")
            .bind(row_tenant.as_uuid())
            .bind(format!("shadow-{}", row_tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");

        let hasher = agentos_app::api_keys::Hasher::from_master_key(MASTER);
        agentos_store::api_keys::issue(
            &db,
            uuid::Uuid::now_v7(),
            row_tenant,
            "shadow",
            &hasher.digest(&shared),
            &AuditActor::Operator("test".to_owned()),
            chrono::Utc::now(),
        )
        .await
        .expect("issue");

        let reached = Arc::new(AtomicBool::new(false));
        let (status, body) = call(
            app(Keyring::new(env, db, MASTER), reached.clone()),
            Some(&format!("Bearer {shared}")),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            env_tenant.to_string(),
            "a row must not be able to shadow the deployment's own keyring"
        );
    }

    /// **The revocation proof, through the whole HTTP stack.** Issue a key, use
    /// it, delete it, use it again — no restart, no waiting.
    #[tokio::test]
    async fn a_revoked_table_key_is_refused_by_the_very_next_request() {
        let Some(db) = db().await else { return };
        let tenant = TenantId::new_v7(chrono::Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'revoked')")
            .bind(tenant.as_uuid())
            .bind(format!("revoked-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");

        let keys = Keyring::new(ApiKeys::parse("").expect("empty"), db.clone(), MASTER);
        let issued = agentos_app::api_keys::issue(
            &db,
            keys.hasher(),
            tenant,
            "ops",
            &AuditActor::Operator("platform".to_owned()),
            chrono::Utc::now(),
        )
        .await
        .expect("issue");
        let header = format!("Bearer {}", issued.secret.expose_for_transport());

        let reached = Arc::new(AtomicBool::new(false));
        let (status, body) = call(app(keys.clone(), reached.clone()), Some(&header)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, tenant.to_string(), "the row named the tenant");

        agentos_app::api_keys::revoke(
            &db,
            issued.id,
            &AuditActor::Operator("platform".to_owned()),
            chrono::Utc::now(),
        )
        .await
        .expect("revoke");

        let reached = Arc::new(AtomicBool::new(false));
        let (status, _) = call(app(keys, reached.clone()), Some(&header)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the request after the DELETE must fail; there is no cache to expire"
        );
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
        let (_, keys) = env_keyring();
        let principal = keys.lookup(SECRET).expect("known key");
        match principal.actor {
            AuditActor::Operator(who) => assert_eq!(who, "ops-console"),
            other => panic!("expected an operator, got {other:?}"),
        }
    }

    /// **A keyring must not print what it holds.**
    ///
    /// [`Keyring`] has no `Debug` at all, which is what keeps these off the one
    /// surface that renders types by accident — but these two are `pub`, they
    /// are what `Config` holds, and one `tracing::debug!(?keys)` anywhere is a
    /// log line carrying every operator credential in the deployment. The
    /// labels are the half worth printing and the half that is already the
    /// audit actor; the secrets are the half that is never worth printing.
    #[test]
    fn a_keyring_renders_its_labels_and_never_its_secrets() {
        let tenant = Uuid::from_u128(1);
        let env = ApiKeys::parse(&format!("ops-console:{tenant}:{SECRET}")).expect("valid");
        let rendered = format!("{env:?}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(
            rendered.contains("ops-console") && rendered.contains(&tenant.to_string()),
            "the half worth printing is missing: {rendered}"
        );

        let platform = PlatformKeys::parse(&format!("signup:{OTHER}")).expect("valid");
        let rendered = format!("{platform:?}");
        assert!(!rendered.contains(OTHER), "{rendered}");
        assert!(rendered.contains("signup"), "{rendered}");
    }

    #[test]
    fn comparison_does_not_short_circuit() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    // -- the platform keyring ---------------------------------------------

    #[test]
    fn a_platform_entry_names_no_tenant_and_a_malformed_one_is_a_boot_failure() {
        let keys = PlatformKeys::parse(&format!("signup:{SECRET}, ops:{OTHER}")).expect("valid");
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys.lookup(SECRET).expect("known").label,
            "signup",
            "the label is the audit actor"
        );
        assert!(keys.lookup("nope").is_none());

        assert!(PlatformKeys::parse("").expect("empty is valid").is_empty());
        assert!(matches!(
            PlatformKeys::parse("no-colon-here"),
            Err(PlatformKeysError::Shape { index: 0 })
        ));
        assert!(matches!(
            PlatformKeys::parse("label:short"),
            Err(PlatformKeysError::WeakSecret { index: 0 })
        ));
        assert!(matches!(
            PlatformKeys::parse(&format!("a:{SECRET}, b:short")),
            Err(PlatformKeysError::WeakSecret { index: 1 })
        ));
        // A three-field entry is a tenant keyring line pasted into the wrong
        // variable. It parses — the uuid becomes part of the secret — and it
        // therefore authenticates nobody, which is the failure direction that
        // does not hand a tenant's key platform authority.
        let pasted = PlatformKeys::parse(&format!("ops:{}:{SECRET}", Uuid::from_u128(1)))
            .expect("parses as label + a secret containing colons");
        assert!(
            pasted.lookup(SECRET).is_none(),
            "the tenant uuid is part of the secret, so the tenant's key does not open this"
        );
    }

    /// **The two keyrings do not overlap, and that is what makes revocation
    /// mean anything.** A tenant's key cannot mint; the minting key cannot read.
    #[tokio::test]
    async fn a_tenant_key_is_not_a_platform_key_and_the_reverse() {
        let Some(db) = db().await else { return };
        let (_, env) = env_keyring();
        let tenant_keys = Keyring::new(env, db, MASTER);
        let platform_keys = PlatformKeys::parse(&format!("signup:{OTHER}")).expect("valid");

        // The tenant's secret, offered to the platform keyring.
        assert!(platform_keys.lookup(SECRET).is_none());

        // The platform's secret, offered to a tenant route.
        let reached = Arc::new(AtomicBool::new(false));
        let (status, _) = call(
            app(tenant_keys, reached.clone()),
            Some(&format!("Bearer {OTHER}")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a platform key must not read tenant data"
        );
        assert!(!reached.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_platform_layer_refuses_before_the_handler_runs() {
        let keys = PlatformKeys::parse(&format!("signup:{SECRET}")).expect("valid");
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        let router = Router::new()
            .route(
                "/v1/platform/keys",
                get(move |principal: PlatformPrincipal| {
                    let flag = flag.clone();
                    async move {
                        flag.store(true, Ordering::SeqCst);
                        principal.label
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                keys,
                require_platform_key,
            ));

        for (header, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(format!("Bearer {OTHER}")), StatusCode::UNAUTHORIZED),
            (Some(SECRET.to_owned()), StatusCode::UNAUTHORIZED),
            (Some(format!("Bearer {SECRET}")), StatusCode::OK),
        ] {
            reached.store(false, Ordering::SeqCst);
            let mut req = HttpRequest::builder().uri("/v1/platform/keys");
            if let Some(value) = &header {
                req = req.header(header::AUTHORIZATION, value);
            }
            let response = router
                .clone()
                .oneshot(req.body(Body::empty()).expect("request"))
                .await
                .expect("service");
            assert_eq!(response.status(), expected, "for header {header:?}");
            assert_eq!(
                reached.load(Ordering::SeqCst),
                expected == StatusCode::OK,
                "for header {header:?}"
            );
        }
    }

    /// An empty platform keyring is the default, and it closes the door rather
    /// than opening it.
    #[tokio::test]
    async fn no_platform_key_configured_means_nobody_can_sign_anybody_up() {
        let keys = PlatformKeys::parse("").expect("empty is valid");
        assert!(keys.is_empty());
        assert!(keys.lookup(SECRET).is_none());
        assert!(keys.lookup("").is_none());
    }
}
