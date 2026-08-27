//! `POST /v1/webhooks/{path}` — the one door third parties knock on.
//!
//! # The order is the unit
//!
//! ```text
//! look up the endpoint  ->  buffer the RAW bytes  ->  verify over those bytes  ->  enqueue  ->  202
//! ```
//!
//! Read the body **first, as bytes, and verify over exactly those bytes**. An
//! axum `Json<T>` extractor placed anywhere above the verification silently
//! breaks every signature scheme in existence, because what it hands on is a
//! *re-serialisation*: key order, whitespace and number formatting are all
//! gone, and the MAC was computed over what was actually sent. The failure mode
//! is the dangerous one — it does not error, it just starts refusing genuine
//! webhooks, and the fix somebody reaches for at 3am is to stop verifying. So
//! this handler takes [`Request`], not `Json`, and nothing in this file
//! deserialises the payload at all.
//!
//! # And the handler does no work
//!
//! Verify, write one row, answer 202. No normalisation, no recipient
//! resolution, no provider round trip — the inbound loop (U37) claims the row
//! and does all of that. A webhook endpoint that does work is a webhook
//! endpoint that exceeds the provider's timeout, gets no 2xx, and is redelivered
//! *while the first copy is still running*. The stored row is what makes
//! "answered 202, then crashed" survivable.
//!
//! # Where it must be mounted
//!
//! Outside the API-key layer — a provider has no API key, it has a signature —
//! and inside the outer stack (request id, tracing, body limit, timeout). So
//! [`router`] is merged into the router *before* `with_api_stack` is applied,
//! never after. The body cap is enforced here as well as by the outer
//! `RequestBodyLimitLayer`, so the guarantee "oversized is refused before we
//! compute a MAC over it" holds for this router on its own.
//!
//! ponytail: no rate limit of its own. The one in `main.rs` is keyed on the
//! tenant from the API key, and there is no API key here; a per-source limiter
//! belongs at the ingress proxy, which is also the only place that can see the
//! real client address. What this endpoint does have is a hard body cap and a
//! handler that is one INSERT — add a limiter here when a provider is
//! observed to hammer it, not before.
//!
//! # Two registries, and the path is what tells them apart
//!
//! `AGENTOS_WEBHOOK_SECRETS` is a `HashMap` keyed on the path segment, so it
//! holds **one endpoint per path for the whole deployment** — that is what
//! `ConfigError::WebhookProviderTwice` refuses at boot, and it is why it is not
//! multi-tenancy. `webhook_endpoints` (`migrations/0053`) is the other half: one
//! row per `(tenant, provider)`, addressed by an opaque minted path, read
//! through `admin_tx_bypassing_rls` because the lookup precedes knowing the
//! tenant. Read that migration for why the path is opaque rather than
//! `/{tenant}/{provider}`.
//!
//! **The environment is consulted first, and a row cannot shadow it.** Same rule
//! and same reason as `auth::Keyring`: a variable cannot be rewritten by
//! anything that is running, so if a row could win, any bug that writes this
//! table would be able to move a deployment's configured inbound mail into
//! another tenant's queue. The failure direction is also the right one — an
//! operator who registers a row on a legacy path finds that mail keeps arriving
//! where it always did, rather than finding out that it silently moved.
//!
//! ponytail: one signature scheme — the Standard Webhooks / Svix one, which is
//! what `agentos_providers::email` signs and what Resend sends. Twilio's
//! HMAC-SHA1-over-the-callback-URL scheme lives in
//! `agentos_providers::telephony::verify_twilio_signature` and is not wired
//! here, because there is no telephony ingest on the other end of the queue to
//! read the row. When there is: [`Endpoint`] grows a `scheme` field, the
//! `verify` call below grows a `match`, `0053`'s
//! `webhook_endpoints_provider_is_wired` grows a value, and nothing else
//! changes.

use std::collections::HashMap;
use std::sync::Arc;

use agentos_app::inbound::{WebhookHeaders, verify_signature};
use agentos_app::mcp::Credentials;
use agentos_app::webhooks::{self, Endpoint};
use agentos_domain::untrusted::Untrusted;
use agentos_store::db::Db;
use agentos_store::outbox::{self, NewEvent};
use axum::body::to_bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error::ApiError;

/// Largest webhook body we will buffer. Comfortably above any provider's
/// notification payload — they carry ids and envelopes, never content — and
/// small enough that a flood of them cannot be an allocation attack.
pub const MAX_WEBHOOK_BYTES: usize = 256 * 1024;

/// `aggregate_type` of a stored raw delivery.
pub const RAW_AGGREGATE: &str = "webhook";

/// The `event_type` a stored delivery from `provider` is filed under.
///
/// One function rather than two `format!`s, because the other one is in
/// `main.rs`, where the outbox handler for it is registered — and an event
/// nobody registered a handler for is retried eight times and then dead-
/// lettered, which is a very quiet way to stop receiving email.
pub fn received_event(provider: &str) -> String {
    format!("webhook.{provider}.received")
}

/// The endpoints `AGENTOS_WEBHOOK_SECRETS` registered, keyed by path segment.
///
/// Still a `HashMap`, so it still holds one endpoint per path and
/// `ConfigError::WebhookProviderTwice` still has something to refuse. The table
/// is what serves a second tenant; see the module docs on which wins.
#[derive(Clone, Default)]
pub struct Webhooks(Arc<HashMap<String, Endpoint>>);

impl Webhooks {
    /// Take the registry as parsed at boot.
    pub fn new(endpoints: HashMap<String, Endpoint>) -> Self {
        Self(Arc::new(endpoints))
    }

    /// The endpoint registered under this path segment, if any.
    fn endpoint(&self, path: &str) -> Option<&Endpoint> {
        self.0.get(path)
    }
}

/// Where a resolved endpoint came from.
///
/// Two owners and one borrow: the environment registry *lends* its `Endpoint`
/// for the length of the request and the table hands over a fresh one. A
/// `clone()` to unify the two would be a second copy of a signing secret in the
/// heap for no reason.
enum Resolved<'a> {
    Registered(&'a Endpoint),
    Stored(Endpoint),
}

impl Resolved<'_> {
    fn get(&self) -> &Endpoint {
        match self {
            Self::Registered(endpoint) => endpoint,
            Self::Stored(endpoint) => endpoint,
        }
    }
}

/// What the handler needs: somewhere to write, the deployment's cipher, and the
/// endpoints the environment registered.
#[derive(Clone)]
struct Ingress {
    db: Db,
    credentials: Credentials,
    webhooks: Webhooks,
}

/// The webhook surface. Merge this **outside** `with_api_stack`.
pub fn router(db: Db, credentials: Credentials, webhooks: Webhooks) -> Router {
    Router::new()
        .route("/v1/webhooks/{path}", post(ingest))
        .with_state(Ingress {
            db,
            credentials,
            webhooks,
        })
}

/// Verify, store, 202.
///
/// [`Request`] is the last argument because it consumes the body, and it is
/// the *only* body extractor in this file — see the module docs.
async fn ingest(
    State(ingress): State<Ingress>,
    Path(path): Path<String>,
    req: Request,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    // Before the body, so an unregistered path costs no memory. 404 rather
    // than 401: there is no secret to check a signature against, and telling
    // an unauthenticated prober which endpoints exist is telling it which
    // secrets are worth guessing — which is exactly what an opaque path is
    // there to withhold.
    //
    // The environment first and the table second. See the module docs: a row
    // must not be able to shadow a variable.
    //
    // ponytail: a path that is in neither registry costs one primary-key
    // lookup, so an unauthenticated flood costs one round trip per request.
    // Same ceiling and same upgrade path as `auth::require_api_key`, which pays
    // it on every request rather than only on the unregistered ones: a
    // connection-limited ingress, which is also the only place that can see the
    // client address. Not a cache — a cache here would have to be measured in
    // "how long a deleted endpoint still accepts a customer's mail".
    let resolved = match ingress.webhooks.endpoint(&path) {
        Some(endpoint) => Resolved::Registered(endpoint),
        None => match webhooks::resolve(&ingress.db, &ingress.credentials, &path).await {
            Ok(Some(endpoint)) => Resolved::Stored(endpoint),
            Ok(None) => {
                // The path is third-party-controlled text. `path` is bound by
                // the route to one segment and the table's own CHECK keeps a
                // stored one to `[A-Za-z0-9_-]{16,64}`, but a *probe* is under
                // no such rule, so it is logged with `?` (the `Debug`
                // rendering, which escapes) and never with `%`.
                tracing::warn!(path = ?path, "webhook for an unregistered path");
                return Err(ApiError::not_found());
            }
            Err(err) => {
                // The row is there and we cannot read it: our master key, not
                // their signature. A 404 or a 401 here would send an operator
                // to the provider's dashboard to chase a fault on our side.
                tracing::error!(
                    path = ?path,
                    code = err.code(),
                    "a registered endpoint could not be opened"
                );
                return Err(ApiError::internal());
            }
        },
    };
    let endpoint = resolved.get();
    let provider = endpoint.provider.as_str();

    let (parts, body) = req.into_parts();
    // Bytes, before anything looks at them. `to_bytes` refuses a declared
    // content-length over the cap without reading a chunk.
    //
    // Every buffering failure is one status: a body we could not read whole is
    // a body we cannot verify, and 413 is the one the provider can act on.
    let raw = to_bytes(body, MAX_WEBHOOK_BYTES).await.map_err(|err| {
        tracing::warn!(%provider, error = %err, "webhook body was not buffered");
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "webhook_too_large",
            "webhook body is too large",
        )
    })?;

    // The signature covers `id . timestamp . raw`, so the id and timestamp are
    // authenticated too — which is what makes the id below safe to dedupe on.
    // The replay window lives inside `verify_signature`.
    let headers = signature_headers(&parts.headers);
    let now = Utc::now();
    verify_signature(&endpoint.secret, &headers, &raw, now).map_err(|err| {
        // The variant is low-cardinality and carries no third-party text; it
        // is the difference between "we are being probed" and "the secret
        // rotation is half applied". The caller gets none of it.
        tracing::warn!(%provider, error = %err, "webhook signature rejected");
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "webhook_unverified",
            "webhook signature could not be verified",
        )
    })?;

    // Verified, and still not trusted: everything below is storage, not
    // interpretation. A body that is not UTF-8 is not a webhook.
    let raw = Untrusted::new(
        String::from_utf8(raw.to_vec())
            .map_err(|_| ApiError::bad_request("webhook body is not UTF-8"))?,
    );

    let event = NewEvent {
        aggregate_type: RAW_AGGREGATE.to_owned(),
        // There is no aggregate yet. Which employee, which conversation, is
        // precisely what the loop works out from the payload; nil is the
        // stable placeholder the dedupe id derivation needs.
        aggregate_id: Uuid::nil(),
        // From the endpoint, never from the URL. A minted path is opaque and
        // cannot name the ingest that reads the row, and an `event_type` with no
        // handler in `main::handlers` is not skipped — it is retried eight times
        // and dead-lettered, which is a quiet way to stop receiving email.
        event_type: received_event(provider),
        // The provider's own event id, from the header the signature covers.
        // A redelivery reuses it, so the second copy collapses onto the first.
        // Two tenants behind one provider account see the same id: the derived
        // outbox id mixes the tenant in, so those are two rows and not a
        // collision — `outbox::dedupe_keys_do_not_collide_across_tenants`.
        dedupe_key: Some(format!("{provider}:{}", headers.id)),
        payload: json!({
            "provider": provider,
            "event_id": headers.id,
            // Third-party text, stored verbatim into jsonb — never rendered,
            // and never re-serialised, so the loop parses exactly the bytes
            // that were signed.
            "body": raw.expose_for_parsing(),
        }),
        traceparent: None,
    };

    let mut tx = ingress.db.tenant_tx(endpoint.tenant_id).await?;
    let id = outbox::enqueue(&mut tx, &event, now).await?;
    tx.commit().await?;

    // 202, not 200: nothing has been processed. And 202 on a redelivery too —
    // anything else keeps the provider retrying an event we already hold.
    Ok((StatusCode::ACCEPTED, Json(json!({ "event_id": id }))))
}

/// The three Standard Webhooks headers, under either spelling.
///
/// A missing one becomes an empty string rather than an early return, so the
/// "which header was wrong?" decision is made in one place — the verifier —
/// instead of two that can disagree.
fn signature_headers(headers: &HeaderMap) -> WebhookHeaders {
    let pick = |names: [&str; 2]| {
        names
            .iter()
            .find_map(|name| headers.get(*name))
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };

    WebhookHeaders {
        id: pick(["webhook-id", "svix-id"]),
        timestamp: pick(["webhook-timestamp", "svix-timestamp"]),
        signature: pick(["webhook-signature", "svix-signature"]),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::inbound::{Secret, sign_webhook};
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    use super::*;

    const PROVIDER: &str = "email";
    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const MASTER: &str = "webhook-route-tests-master-key";

    async fn connect() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; webhook ingress needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let label = format!("hook-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// A tenant, its `AGENTOS_WEBHOOK_SECRETS` endpoint, and the router in front
    /// of it.
    ///
    /// Needs a real Postgres: the claim under test is a row, and a mock of the
    /// row would be a mock of the test.
    async fn harness() -> Option<(Db, TenantId, Router)> {
        let db = connect().await?;
        let tenant = seed_tenant(&db).await;

        let endpoints = HashMap::from([(
            PROVIDER.to_owned(),
            Endpoint {
                tenant_id: tenant,
                provider: PROVIDER.to_owned(),
                secret: Secret::new(SECRET),
            },
        )]);
        let router = router(
            db.clone(),
            Credentials::from_master_key(MASTER),
            Webhooks::new(endpoints),
        );
        Some((db, tenant, router))
    }

    /// A delivery signed the way the provider signs it, to any path.
    fn signed_to(path: &str, secret: &str, id: &str, body: &[u8]) -> HttpRequest<Body> {
        let timestamp = Utc::now().timestamp().to_string();
        let signature = sign_webhook(&Secret::new(secret), id, &timestamp, body);
        HttpRequest::post(format!("/v1/webhooks/{path}"))
            .header("webhook-id", id)
            .header("webhook-timestamp", timestamp)
            .header("webhook-signature", signature)
            .header("content-type", "application/json")
            .body(Body::from(body.to_vec()))
            .expect("request")
    }

    fn signed(id: &str, body: &[u8]) -> HttpRequest<Body> {
        signed_to(PROVIDER, SECRET, id, body)
    }

    fn payload(email_id: &str) -> Vec<u8> {
        format!(
            "{{\"type\":\"email.received\",\"created_at\":\"2026-08-24T10:00:00Z\",\
              \"data\":{{\"email_id\":\"{email_id}\",\"from\":\"ap@supplier.example\",\
              \"to\":[\"lena@agents.example.com\"]}}}}"
        )
        .into_bytes()
    }

    async fn call(router: &Router, req: HttpRequest<Body>) -> (StatusCode, Value) {
        let response = router.clone().oneshot(req).await.expect("service");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), MAX_WEBHOOK_BYTES)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn stored(db: &Db, tenant: TenantId) -> Vec<(String, Value)> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let rows = sqlx::query_as(
            "SELECT event_type, payload FROM outbox_events \
              WHERE aggregate_type = $1 ORDER BY created_at",
        )
        .bind(RAW_AGGREGATE)
        .fetch_all(&mut **tx)
        .await
        .expect("read outbox");
        tx.commit().await.expect("commit read");
        rows
    }

    // -- pure ---------------------------------------------------------------

    #[test]
    fn either_header_spelling_is_read_and_a_missing_one_is_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("svix-id", "msg_1".parse().expect("value"));
        headers.insert("webhook-timestamp", "1700000000".parse().expect("value"));

        let read = signature_headers(&headers);
        assert_eq!(read.id, "msg_1");
        assert_eq!(read.timestamp, "1700000000");
        // Absent, not a panic and not a default that could ever verify.
        assert_eq!(read.signature, "");
    }

    // -- the endpoint -------------------------------------------------------

    /// The claim the whole unit exists for: the MAC is checked against the
    /// bytes that arrived. Flip one byte of the body and the same signature
    /// must stop working — which it only does if nothing re-serialised it on
    /// the way in.
    #[tokio::test]
    async fn a_tampered_body_is_rejected_and_nothing_is_queued() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let honest = payload("email_tamper");
        let mut forged = honest.clone();
        let last = forged.len() - 1;
        forged[last - 2] ^= 0x01;

        // Signed over `honest`, delivered as `forged`.
        let mut req = signed("msg_tamper", &honest);
        *req.body_mut() = Body::from(forged);
        let (status, _) = call(&router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(stored(&db, tenant).await.is_empty(), "a forgery was queued");

        // The same secret, the same route, the honest body: accepted. Without
        // this the test would also pass if verification always failed.
        let (status, _) = call(&router, signed("msg_tamper", &honest)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(stored(&db, tenant).await.len(), 1);
    }

    /// A stolen signature does not travel: it is bound to the id and timestamp
    /// it was minted with.
    #[tokio::test]
    async fn a_signature_lifted_onto_another_delivery_is_rejected() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let body = payload("email_lift");
        let stolen = signed("msg_lift", &body);
        let signature = stolen
            .headers()
            .get("webhook-signature")
            .expect("signature")
            .clone();

        let mut req = signed("msg_other", &body);
        req.headers_mut().insert("webhook-signature", signature);
        let (status, _) = call(&router, req).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(stored(&db, tenant).await.is_empty());
    }

    /// Every provider redelivers. Three deliveries of one event must leave one
    /// row — and must all be answered 202, because a 4xx or a 5xx is the
    /// provider's cue to keep trying forever.
    #[tokio::test]
    async fn a_replayed_event_id_is_stored_once_and_still_answered_202() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let body = payload("email_replay");
        let mut ids = Vec::new();
        for attempt in 1..=3 {
            let (status, answer) = call(&router, signed("msg_replay", &body)).await;
            assert_eq!(status, StatusCode::ACCEPTED, "delivery {attempt}");
            ids.push(answer["event_id"].clone());
        }
        assert_eq!(ids[0], ids[1], "a redelivery must name the original row");
        assert_eq!(ids[1], ids[2]);

        let rows = stored(&db, tenant).await;
        assert_eq!(
            rows.len(),
            1,
            "three deliveries produced {} rows",
            rows.len()
        );
        assert_eq!(rows[0].0, format!("webhook.{PROVIDER}.received"));
        assert_eq!(rows[0].1["event_id"], json!("msg_replay"));
        // Stored verbatim: the loop parses the bytes that were signed, not a
        // round trip through serde_json.
        assert_eq!(
            rows[0].1["body"].as_str().expect("body"),
            String::from_utf8(body).expect("utf8")
        );

        // A different event id from the same provider is a different row.
        let (status, _) = call(&router, signed("msg_replay_2", &payload("email_2"))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(stored(&db, tenant).await.len(), 2);
    }

    #[tokio::test]
    async fn an_unregistered_provider_is_a_404() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let body = payload("email_stranger");
        let mut req = signed("msg_stranger", &body);
        *req.uri_mut() = "/v1/webhooks/stripe".parse().expect("uri");

        let (status, _) = call(&router, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(stored(&db, tenant).await.is_empty());
    }

    /// The cap bites before the MAC is computed. A caller that can make us hash
    /// an arbitrary number of megabytes has a cheap way to spend our CPU, and
    /// it does not even need a valid signature to do it.
    #[tokio::test]
    async fn an_oversized_body_is_refused_before_verification() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let oversized = vec![b'x'; MAX_WEBHOOK_BYTES + 1];
        for declared in [true, false] {
            // Deliberately unsigned: if the answer were 401 we would know
            // verification had run first.
            let mut req = HttpRequest::post(format!("/v1/webhooks/{PROVIDER}"))
                .header("webhook-id", "msg_big")
                .header("webhook-timestamp", Utc::now().timestamp().to_string())
                .header("webhook-signature", "v1,AAAA");
            if declared {
                req = req.header("content-length", oversized.len());
            }
            let req = req
                .body(Body::from(oversized.clone()))
                .expect("oversized request");

            let (status, _) = call(&router, req).await;
            assert_eq!(
                status,
                StatusCode::PAYLOAD_TOO_LARGE,
                "declared content-length: {declared}"
            );
        }
        assert!(stored(&db, tenant).await.is_empty());
    }

    /// Missing headers are a refusal, not a panic and not a pass.
    #[tokio::test]
    async fn an_unsigned_delivery_is_rejected() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let req = HttpRequest::post(format!("/v1/webhooks/{PROVIDER}"))
            .header("content-type", "application/json")
            .body(Body::from(payload("email_naked")))
            .expect("request");

        let (status, _) = call(&router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(stored(&db, tenant).await.is_empty());
    }

    /// A delivery signed with a secret we do not hold — the wrong provider
    /// account, or a rotation applied on one side only.
    #[tokio::test]
    async fn a_delivery_signed_with_another_secret_is_rejected() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let body = payload("email_wrong_key");
        let timestamp = Utc::now().timestamp().to_string();
        let req = HttpRequest::post(format!("/v1/webhooks/{PROVIDER}"))
            .header("webhook-id", "msg_wrong_key")
            .header("webhook-timestamp", &timestamp)
            .header(
                "webhook-signature",
                sign_webhook(
                    &Secret::new("whsec_notoursnotours"),
                    "msg_wrong_key",
                    &timestamp,
                    &body,
                ),
            )
            .body(Body::from(body))
            .expect("request");

        let (status, _) = call(&router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(stored(&db, tenant).await.is_empty());
    }

    /// The tenant on the row is the registration's. Nothing in the payload can
    /// move a delivery into another tenant's queue.
    #[tokio::test]
    async fn the_tenant_comes_from_the_registration_not_from_the_payload() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let other = TenantId::new_v7(Utc::now());
        let body = format!(
            "{{\"type\":\"email.received\",\"tenant_id\":\"{}\",\
              \"created_at\":\"2026-08-24T10:00:00Z\",\
              \"data\":{{\"email_id\":\"email_claim\",\"from\":\"a@b.example\",\"to\":[]}}}}",
            other.as_uuid()
        )
        .into_bytes();

        let (status, _) = call(&router, signed("msg_claim", &body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        // Visible to the registered tenant...
        assert_eq!(stored(&db, tenant).await.len(), 1);
        // ...and the row's own tenant_id is that one, not the claimed one.
        //
        // `IN ($2, $3)` and not just the `event_id`: this read bypasses RLS,
        // `msg_claim` is a literal, and the tenants are fresh every run — so
        // without the filter it picks up the row a *previous* run of this test
        // left behind and reports a stale tenant id as a security failure.
        // Both candidates are in the list, so the assertion still has to
        // discriminate between them.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let owner: Uuid = sqlx::query_scalar(
            "SELECT tenant_id FROM outbox_events \
              WHERE payload->>'event_id' = $1 AND tenant_id IN ($2, $3)",
        )
        .bind("msg_claim")
        .bind(tenant.as_uuid())
        .bind(other.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .expect("read row");
        tx.commit().await.expect("commit");
        assert_eq!(owner, tenant.as_uuid());
        assert_ne!(owner, other.as_uuid());
    }

    // -- two customers, one provider account ---------------------------------

    /// **The claim this whole wave exists for.**
    ///
    /// Two tenants behind one provider account, so they hold the **same signing
    /// secret** — which means the signature cannot tell them apart and the
    /// endpoint is the only thing that can. Two registrations, two deliveries,
    /// and each queue holds its own and only its own.
    ///
    /// The same `webhook-id` on both deliveries, deliberately. The outbox
    /// derives a row id from `md5(tenant : … : dedupe_key)`, so if the tenant
    /// came from anywhere but the row the two would collapse onto one id and
    /// one of the customers would silently lose the message.
    ///
    /// What this would catch: keying the registry on the provider again,
    /// resolving the tenant from the payload, opening a row under a tenant that
    /// is not its own, or writing through anything but `tenant_tx(row.tenant_id)`.
    #[tokio::test]
    async fn two_tenants_behind_one_provider_account_do_not_receive_each_others_mail() {
        let Some(db) = connect().await else { return };
        let credentials = Credentials::from_master_key(MASTER);
        let (a, b) = (seed_tenant(&db).await, seed_tenant(&db).await);

        // One account, one secret, two endpoints.
        let now = Utc::now();
        let (path_a, _) = agentos_app::webhooks::register(
            &db,
            &credentials,
            a,
            PROVIDER,
            SECRET.to_owned(),
            &agentos_store::audit::AuditActor::Operator("platform".to_owned()),
            now,
        )
        .await
        .expect("register a");
        let (path_b, _) = agentos_app::webhooks::register(
            &db,
            &credentials,
            b,
            PROVIDER,
            SECRET.to_owned(),
            &agentos_store::audit::AuditActor::Operator("platform".to_owned()),
            now,
        )
        .await
        .expect("register b");
        assert_ne!(path_a, path_b, "two customers were given one address");

        // No environment registry at all: this is the deployment the table is
        // for, where every endpoint is a row.
        let router = router(db.clone(), credentials, Webhooks::default());

        let for_a = payload("email_for_a");
        let for_b = payload("email_for_b");
        let (status, _) = call(&router, signed_to(&path_a, SECRET, "msg_shared", &for_a)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (status, _) = call(&router, signed_to(&path_b, SECRET, "msg_shared", &for_b)).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        // Read through `tenant_tx`, so RLS is answering the question and not a
        // WHERE clause this test wrote.
        let mine = stored(&db, a).await;
        let theirs = stored(&db, b).await;
        assert_eq!(mine.len(), 1, "tenant A holds {} rows", mine.len());
        assert_eq!(theirs.len(), 1, "tenant B holds {} rows", theirs.len());
        // The event type follows the endpoint's `provider`, not the URL. A
        // minted path in the event type is an event type `main::handlers`
        // registered nothing for — eight retries and a dead letter per message,
        // which is silence and not an error.
        assert_eq!(mine[0].0, "webhook.email.received", "{:?}", mine[0].0);
        assert_eq!(theirs[0].0, "webhook.email.received", "{:?}", theirs[0].0);
        assert_eq!(
            mine[0].1["body"].as_str().expect("body"),
            String::from_utf8(for_a).expect("utf8"),
            "tenant A is holding the other customer's mail"
        );
        assert_eq!(
            theirs[0].1["body"].as_str().expect("body"),
            String::from_utf8(for_b).expect("utf8"),
            "tenant B is holding the other customer's mail"
        );
    }

    /// A stored endpoint is verified like any other, and a bad signature writes
    /// nothing — including no row saying somebody knocked.
    #[tokio::test]
    async fn a_stored_endpoint_refuses_a_forgery_before_anything_is_written() {
        let Some(db) = connect().await else { return };
        let credentials = Credentials::from_master_key(MASTER);
        let tenant = seed_tenant(&db).await;
        let (path, _) = agentos_app::webhooks::register(
            &db,
            &credentials,
            tenant,
            PROVIDER,
            SECRET.to_owned(),
            &agentos_store::audit::AuditActor::Operator("platform".to_owned()),
            Utc::now(),
        )
        .await
        .expect("register");
        let router = router(db.clone(), credentials, Webhooks::default());

        let body = payload("email_stored_forgery");
        let (status, _) = call(
            &router,
            signed_to(&path, "whsec_notoursnotours", "msg_forged", &body),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(stored(&db, tenant).await.is_empty(), "a forgery was queued");

        // The control: the same path with the right secret is accepted, so the
        // refusal above was the signature and not a broken endpoint.
        let (status, _) = call(&router, signed_to(&path, SECRET, "msg_honest", &body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(stored(&db, tenant).await.len(), 1);
    }

    /// **The environment wins.** One path, two homes, two different tenants —
    /// and the variable's answer is the one that counts, for
    /// `auth::Keyring`'s reason: a variable cannot be rewritten by anything that
    /// is running, so a row that could shadow one would be a way for any write
    /// to this table to move a deployment's configured inbound mail into another
    /// tenant's queue.
    #[tokio::test]
    async fn a_row_cannot_shadow_an_environment_registration() {
        let Some(db) = connect().await else { return };
        let credentials = Credentials::from_master_key(MASTER);
        let (configured, intruder) = (seed_tenant(&db).await, seed_tenant(&db).await);

        // A path both registries can hold. An ordinary environment entry is a
        // provider name — `email`, five characters — which
        // `webhook_endpoints_path_shape` refuses outright, so the collision this
        // test is about needs a path long enough to be a legal row. That is
        // itself worth knowing: for every realistic value of
        // `AGENTOS_WEBHOOK_SECRETS` a shadowing row is not merely refused, it is
        // unrepresentable.
        let contested = format!("collide_{}", intruder.as_uuid().simple());

        // **The intruder's row holds a real, openable secret — the same one.**
        // Bytes that were not an envelope would make a table-first order fail
        // with a 500 and fall back to the environment anyway, so the test would
        // pass against the very ordering it exists to forbid. Registered
        // properly and then moved onto the contested path, which the AAD permits
        // because it binds the tenant and not the path.
        agentos_app::webhooks::register(
            &db,
            &Credentials::from_master_key(MASTER),
            intruder,
            PROVIDER,
            SECRET.to_owned(),
            &agentos_store::audit::AuditActor::Operator("platform".to_owned()),
            Utc::now(),
        )
        .await
        .expect("register the intruder");
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("UPDATE webhook_endpoints SET path = $1 WHERE tenant_id = $2")
            .bind(&contested)
            .bind(intruder.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("move the row onto the contested path");
        tx.commit().await.expect("commit");

        let endpoints = HashMap::from([(
            contested.clone(),
            Endpoint {
                tenant_id: configured,
                provider: PROVIDER.to_owned(),
                secret: Secret::new(SECRET),
            },
        )]);
        let router = router(db.clone(), credentials, Webhooks::new(endpoints));

        let (status, _) = call(
            &router,
            signed_to(&contested, SECRET, "msg_shadow", &payload("email_shadow")),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            stored(&db, configured).await.len(),
            1,
            "the environment's tenant did not receive its own delivery"
        );
        assert!(
            stored(&db, intruder).await.is_empty(),
            "a row shadowed the deployment's own registration"
        );
    }
}
