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
//! # Three signature schemes, and the endpoint's `provider` is what picks
//!
//! Le troisième est arrivé avec `0077` : Smartlead pousse ses désabonnements et
//! signe en HMAC-SHA256 hexadécimal sur le corps brut. C'est aussi le seul des
//! trois qui refuse **toutes** les livraisons aujourd'hui, et délibérément —
//! le nom de l'en-tête où cette plateforme met sa signature n'a jamais été lu
//! sur une livraison réelle, `agentos_app::inbound::SMARTLEAD_SIGNATURE_HEADER`
//! vaut `None`, et un vérificateur qui devine son en-tête accepte ou refuse au
//! hasard. La suite de ce paragraphe vaut pour les deux premiers.
//!
//! This file used to carry a note saying there was one — the Standard Webhooks
//! / Svix scheme, which is what `agentos_providers::email` signs and what Resend
//! sends — and that Twilio's HMAC-SHA1-over-the-callback-URL scheme was "not
//! wired here, because there is no telephony ingest on the other end of the
//! queue to read the row". There is one now:
//! `main::on_telephony_webhook`. The note's own recipe is what was followed,
//! minus one line of it.
//!
//! **No `scheme` field on [`Endpoint`], and that is the deliberate deviation.**
//! It would be a column whose value is a pure function of a column next to it:
//! `provider` already has to name the ingest that reads the row — that is what
//! `0053`'s `webhook_endpoints_provider_is_wired` CHECK is *for* — and the
//! ingest and the scheme are the same choice. A second field is a second place
//! for them to disagree, and the shape of that disagreement is an endpoint
//! whose deliveries verify under one scheme and are read by the other.
//!
//! Both directions of a mismatch fail **closed and loudly**: an endpoint
//! registered under the wrong provider has its genuine deliveries answered 401,
//! which is a support ticket. Neither direction skips a check.
//!
//! # What the telephony arm needs that the other does not: the URL
//!
//! Twilio MACs the callback URL itself, so verifying requires knowing the
//! address the provider was configured to post to. It is taken from
//! `PUBLIC_HOST` — whose own documentation is "the origin this deployment is
//! reachable at, **for webhook URLs** and A2A agent cards" — plus the request's
//! own path and query, and never from the `Host` header, which the caller
//! controls.
//!
//! ponytail: derived, not stored. The ceiling is that the operator must paste
//! exactly `${PUBLIC_HOST}/v1/webhooks/{path}` into the provider's console, and
//! a deployment whose idea of its own address differs by one character refuses
//! every genuine delivery. That is why a telephony verification failure logs the
//! URL it signed over — it is our own configured string, not a secret, and it
//! turns "everything 401s" from a mystery into one line. Give
//! `webhook_endpoints` a `callback_url` column the day a deployment needs two
//! origins, and not before.

use std::collections::HashMap;
use std::sync::Arc;

use agentos_app::inbound::{
    SMARTLEAD_SIGNATURE_HEADER, TELEPHONY_SIGNATURE_HEADER, WebhookHeaders, callback_origin,
    verify_signature, verify_smartlead_secret_key, verify_smartlead_webhook,
    verify_telephony_webhook,
};
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

/// The endpoint `provider` whose deliveries are verified with Twilio's scheme
/// and read by `main::on_telephony_webhook`.
///
/// Re-exported from `agentos_app` rather than spelled again, because three
/// places have to agree on it — this file's `match`, `main::handlers`'
/// registration, and `0069`'s widened
/// `webhook_endpoints_provider_is_wired` — and two of them are compiled.
pub use agentos_app::inbound::TELEPHONY_PROVIDER;

/// The endpoint `provider` whose deliveries are verified with Smartlead's
/// scheme and read by `main::on_smartlead_webhook`.
///
/// Re-exported for the reason above it, and with the same three places that
/// have to agree: this file's `match`, `main::handlers`, and `0077`'s widened
/// `webhook_endpoints_provider_is_wired`.
pub use agentos_app::inbound::SMARTLEAD_PROVIDER;

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

/// What the handler needs: somewhere to write, the deployment's cipher, the
/// endpoints the environment registered, and this deployment's own address.
#[derive(Clone)]
struct Ingress {
    db: Db,
    credentials: Credentials,
    webhooks: Webhooks,
    /// `PUBLIC_HOST`, normalised to a scheme-bearing origin with no trailing
    /// slash. Half of the string Twilio's scheme MACs; unread by the other one.
    callback_origin: Arc<str>,
}

/// The webhook surface. Merge this **outside** `with_api_stack`.
///
/// `public_host` is `PUBLIC_HOST`. It is a parameter and not a lazy read of the
/// environment for the reason every other route takes its configuration this
/// way — a test has to be able to point it somewhere else — and it is required
/// rather than optional because a deployment with no idea of its own address
/// cannot verify a scheme that signs one, and the honest failure for that is at
/// boot rather than on the first text message.
pub fn router(db: Db, credentials: Credentials, webhooks: Webhooks, public_host: &str) -> Router {
    Router::new()
        .route("/v1/webhooks/{path}", post(ingest))
        .with_state(Ingress {
            db,
            credentials,
            webhooks,
            callback_origin: Arc::from(callback_origin(public_host)),
        })
}

// `callback_origin` used to be a private function here. It moved to
// `agentos_app::inbound`, beside the sign/verify pair for the same scheme, the
// day a *placed call* acquired a status callback: the origin is now MACed at
// both ends — reconstructed here to verify an arriving delivery, and handed to
// the adapter by `agentos_app::mocks::telephony_provider` so a call knows where
// to report back. Two spellings of it is a deployment that answers every call
// and learns the outcome of none, so there is one.

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

    let now = Utc::now();
    // The variant is low-cardinality and carries no third-party text; it is the
    // difference between "we are being probed" and "the secret rotation is half
    // applied". The caller gets none of it, on either scheme.
    let unverified = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "webhook_unverified",
            "webhook signature could not be verified",
        )
    };

    // **The authentication and the dedupe id are decided together**, because on
    // one of these two schemes the id is not in a header and there is no safe
    // way for this file to go and find it. See
    // `agentos_app::inbound::verify_telephony_webhook`: reaching for
    // `headers.id` on a Twilio callback yields the empty string on every
    // delivery a deployment ever receives, `outbox::enqueue` collapses them all
    // onto the first, and every text after the first is answered 202 and
    // dropped. Producing the id here, out of the same expression that verified,
    // is what stops that from being spellable.
    let delivery_id = if provider == TELEPHONY_PROVIDER {
        // **This scheme has no replay window, and it cannot have one.** The
        // Standard Webhooks arm below MACs a timestamp and `verify_signature`
        // refuses one that is too old; Twilio signs the URL and the form fields
        // and nothing else, so a captured callback stays valid for as long as
        // the auth token does. That is the provider's design, not a gap here.
        //
        // What makes it survivable is that a replay lands nothing rather than
        // being refused: identical bytes give an identical dedupe id, so
        // `outbox::enqueue` hands back the original row — and even a second row
        // would land as a duplicate, because `inbound::land` arbitrates on
        // `messages.idempotency_key`, which is keyed on `MessageSid`. A replay
        // is a no-op, and it is not an error. Rotating the auth token is the
        // only thing that invalidates one.
        //
        // Reconstructed from **our own** configuration, never from the `Host`
        // header. Not because the header would break the MAC's guarantee — a
        // caller who picks the URL still cannot forge a signature over it — but
        // because `PUBLIC_HOST` is the address an operator pasted into the
        // provider's console, and a header is not.
        let url = format!(
            "{}{}",
            ingress.callback_origin,
            parts
                .uri
                .path_and_query()
                .map_or("", axum::http::uri::PathAndQuery::as_str)
        );
        let signature = parts
            .headers
            .get(TELEPHONY_SIGNATURE_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        verify_telephony_webhook(&endpoint.secret, &url, signature, &raw).map_err(|err| {
            // `%url` on purpose, and it is the only place in this file a
            // rejection says anything but its own variant. The URL is a string
            // this deployment configured for itself, it is in every provider
            // dashboard already, and it is the single most likely cause of a
            // scheme that MACs a URL refusing everything: `PUBLIC_HOST` and the
            // pasted callback disagreeing. Without it the fix somebody reaches
            // for at 3am is to stop verifying.
            tracing::warn!(%provider, %url, error = %err, "telephony signature rejected");
            unverified()
        })?
    } else if provider == SMARTLEAD_PROVIDER {
        // **Le troisième schéma, et le seul qui refuse tout aujourd'hui.**
        // `agentos_app::webhooks::register` ferme déjà la porte de la table ;
        // celle-ci est l'autre registre — `AGENTOS_WEBHOOK_SECRETS`, qui est lu
        // en premier et ne passe par aucun `register`. Une entrée
        // `smartlead:<tenant>:<secret>` dans une variable d'environnement est
        // légale à écrire, donc le refus doit exister ici aussi ou il n'existe
        // pas.
        //
        // Deviner le nom de l'en-tête serait pire que refuser : voir
        // `agentos_app::inbound::SMARTLEAD_SIGNATURE_HEADER`, qui porte les
        // trois lignes d'évidence et le rapport de production de quelqu'un qui
        // a répondu `401` à toutes ses livraisons authentiques pendant des
        // semaines pour l'avoir deviné.
        //
        // **Deux schémas, et le second est celui qui marche aujourd'hui.** Si
        // quelqu'un finit par lire un en-tête de signature sur une livraison
        // réelle et le pose dans `SMARTLEAD_SIGNATURE_HEADER`, c'est lui qu'on
        // prend : un MAC sur le corps authentifie le corps, ce qu'un secret
        // dans le corps ne fait pas. Tant que le const vaut `None` — et la
        // recherche prédit qu'il le restera — on vérifie ce que la plateforme
        // envoie vraiment : son `secret_key`, dans le JSON.
        //
        // L'ordre compte et n'est pas une préférence de style : le jour où
        // l'en-tête existe, une livraison qui ne le porte pas doit être
        // refusée, pas rattrapée par le chemin d'en dessous.
        match SMARTLEAD_SIGNATURE_HEADER {
            Some(header) => {
                let signature = parts
                    .headers
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();

                verify_smartlead_webhook(&endpoint.secret, signature, &raw).map_err(|err| {
                    tracing::warn!(%provider, error = %err, "smartlead signature rejected");
                    unverified()
                })?
            }
            None => verify_smartlead_secret_key(&endpoint.secret, &raw).map_err(|err| {
                // Pas de `%url` ici, contrairement au schéma téléphonie : rien
                // dans cette vérification ne dépend d'une adresse configurée,
                // donc il n'y a pas de désaccord de configuration à nommer. Le
                // seul dépannage utile est « le secret enregistré n'est pas
                // celui que Smartlead renvoie », et la variante le dit.
                tracing::warn!(%provider, error = %err, "smartlead secret_key rejected");
                unverified()
            })?,
        }
    } else {
        // The signature covers `id . timestamp . raw`, so the id and timestamp
        // are authenticated too — which is what makes the id safe to dedupe on.
        // The replay window lives inside `verify_signature`.
        let headers = signature_headers(&parts.headers);
        verify_signature(&endpoint.secret, &headers, &raw, now).map_err(|err| {
            tracing::warn!(%provider, error = %err, "webhook signature rejected");
            unverified()
        })?;
        headers.id
    };

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
        // What identifies this delivery under whichever scheme authenticated
        // it: the provider's own event id from the header the signature covers,
        // or — where the scheme has no such header — a digest of the bytes it
        // covered. A redelivery reuses it either way, so the second copy
        // collapses onto the first. Two tenants behind one provider account see
        // the same id: the derived outbox id mixes the tenant in, so those are
        // two rows and not a collision —
        // `outbox::dedupe_keys_do_not_collide_across_tenants`.
        dedupe_key: Some(format!("{provider}:{delivery_id}")),
        payload: json!({
            "provider": provider,
            "event_id": delivery_id,
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
    use agentos_app::inbound::{Secret, sign_telephony_webhook, sign_webhook};
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    use super::*;

    const PROVIDER: &str = "email";
    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const MASTER: &str = "webhook-route-tests-master-key";

    /// What this deployment believes its own address is. Half of the string
    /// Twilio's scheme MACs, so a test that signs must build the URL the same
    /// way the route does — see [`callback_url`].
    const ORIGIN: &str = "https://agents.test";

    /// Twilio's auth token, which is the signing secret on that scheme. Not a
    /// `whsec_…`: the two schemes take different secrets from different
    /// dashboards, and one endpoint holds one of them.
    const AUTH_TOKEN: &str = "a-twilio-auth-token-that-is-not-the-other-one";

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
            ORIGIN,
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

    // -- the telephony scheme -----------------------------------------------

    /// The callback URL as the route reconstructs it, which is the URL the
    /// operator pasted into the provider's console. Built here the same way and
    /// deliberately by hand: a helper shared with the route would make both
    /// sides wrong together, which is the one thing this test cannot afford.
    fn callback_url(path: &str) -> String {
        format!("{ORIGIN}/v1/webhooks/{path}")
    }

    /// A Twilio messaging webhook body — an inbound text, as the provider
    /// posts it.
    fn twilio_form(sid: &str, from: &str, body: &str) -> Vec<u8> {
        url_encoded(&[
            ("MessageSid", sid),
            ("From", from),
            ("To", "+33755500001"),
            ("Body", body),
        ])
    }

    /// `application/x-www-form-urlencoded`, spelled out rather than pulled in:
    /// `url` is not a dependency of this crate and must not become one for a
    /// four-field fixture.
    fn url_encoded(pairs: &[(&str, &str)]) -> Vec<u8> {
        let escape = |raw: &str| {
            raw.bytes().fold(String::new(), |mut out, byte| {
                match byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                    true => out.push(byte as char),
                    false => out.push_str(&format!("%{byte:02X}")),
                }
                out
            })
        };
        pairs
            .iter()
            .map(|(key, value)| format!("{}={}", escape(key), escape(value)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes()
    }

    /// A telephony delivery signed the way the provider signs it: HMAC-SHA1
    /// over the callback URL and the sorted form fields, in one header.
    fn signed_twilio(path: &str, token: &str, url: &str, form: &[u8]) -> HttpRequest<Body> {
        HttpRequest::post(format!("/v1/webhooks/{path}"))
            .header(
                TELEPHONY_SIGNATURE_HEADER,
                sign_telephony_webhook(&Secret::new(token), url, form),
            )
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.to_vec()))
            .expect("request")
    }

    /// A tenant whose endpoint is a Twilio one, and the router in front of it.
    async fn telephony_harness() -> Option<(Db, TenantId, Router)> {
        let db = connect().await?;
        let tenant = seed_tenant(&db).await;
        let endpoints = HashMap::from([(
            TELEPHONY_PROVIDER.to_owned(),
            Endpoint {
                tenant_id: tenant,
                provider: TELEPHONY_PROVIDER.to_owned(),
                secret: Secret::new(AUTH_TOKEN),
            },
        )]);
        let router = router(
            db.clone(),
            Credentials::from_master_key(MASTER),
            Webhooks::new(endpoints),
            ORIGIN,
        );
        Some((db, tenant, router))
    }

    // -- the smartlead scheme -----------------------------------------------

    /// La clé partagée d'un endpoint Smartlead — ni un `whsec_…`, ni un jeton
    /// Twilio. Trois schémas, trois tableaux de bord, un secret par endpoint.
    const SMARTLEAD_SECRET: &str = "a-smartlead-shared-secret-that-is-not-the-others";

    /// Un tenant dont l'endpoint est un endpoint Smartlead, et la route devant.
    async fn smartlead_harness() -> Option<(Db, TenantId, Router)> {
        let db = connect().await?;
        let tenant = seed_tenant(&db).await;
        let endpoints = HashMap::from([(
            SMARTLEAD_PROVIDER.to_owned(),
            Endpoint {
                tenant_id: tenant,
                provider: SMARTLEAD_PROVIDER.to_owned(),
                secret: Secret::new(SMARTLEAD_SECRET),
            },
        )]);
        let router = router(
            db.clone(),
            Credentials::from_master_key(MASTER),
            Webhooks::new(endpoints),
            ORIGIN,
        );
        Some((db, tenant, router))
    }

    /// La paire qui prouve que le schéma réel est vivant : le bon secret passe,
    /// un secret voisin ne passe pas.
    ///
    /// Ce test s'appelait `a_correctly_signed_smartlead_delivery_is_refused_while_its_header_is_unposed`
    /// et il affirmait qu'une livraison correctement signée était refusée quand
    /// même, faute de savoir dans quel en-tête regarder. Sa dernière ligne de
    /// documentation disait : « le jour où quelqu'un pose l'en-tête, ce test
    /// devient rouge, et c'est voulu ». Ce jour est arrivé par l'autre bout —
    /// il n'y a pas d'en-tête à poser, Smartlead renvoie son secret dans le
    /// corps, et c'est ce schéma-là qui est câblé.
    ///
    /// Les deux moitiés sont dans le même test à dessein. Un témoin qui passe
    /// sans falsification à côté prouverait seulement qu'on accepte ; une
    /// falsification refusée sans témoin prouverait seulement qu'on refuse. Ce
    /// qu'on veut savoir est que la comparaison **discrimine**.
    #[tokio::test]
    async fn the_body_secret_is_what_lets_a_smartlead_delivery_through() {
        let Some((db, tenant, router)) = smartlead_harness().await else {
            return;
        };

        // Une falsification d'abord, sur la même adresse et le même corps à un
        // caractère près. Elle passe en premier pour que le témoin ne puisse
        // pas être expliqué par un état laissé derrière.
        let faux = format!(
            r#"{{"event_type":"EMAIL_UNSUBSCRIBED","sl_lead_email":"quiet@prospect.example","secret_key":"{SMARTLEAD_SECRET}x"}}"#
        );
        let request = HttpRequest::post(format!("/v1/webhooks/{SMARTLEAD_PROVIDER}"))
            .header("content-type", "application/json")
            .body(Body::from(faux))
            .expect("request");
        let (status, _) = call(&router, request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "un secret voisin a été accepté : la comparaison ne compare rien"
        );
        assert!(
            stored(&db, tenant).await.is_empty(),
            "une livraison non vérifiée a été mise en file"
        );

        // Et le témoin : exactement le même corps, avec le secret que
        // l'opérateur a enregistré.
        let vrai = format!(
            r#"{{"event_type":"EMAIL_UNSUBSCRIBED","sl_lead_email":"quiet@prospect.example","secret_key":"{SMARTLEAD_SECRET}"}}"#
        );
        let request = HttpRequest::post(format!("/v1/webhooks/{SMARTLEAD_PROVIDER}"))
            .header("content-type", "application/json")
            .body(Body::from(vrai))
            .expect("request");
        let (status, _) = call(&router, request).await;
        // 202 et non 204 : la route met en file et rend la main. Le fournisseur
        // n'attend pas que le désabonnement soit écrit — c'est ce que dit
        // l'en-tête de ce module sur la boucle d'ingestion.
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "une livraison portant le bon secret a été refusée"
        );
        assert!(
            !stored(&db, tenant).await.is_empty(),
            "une livraison vérifiée n'a rien mis en file"
        );
    }

    /// Un corps sans `secret_key` du tout est refusé, et pas par accident.
    ///
    /// C'est le cas qu'un attaquant essaie en premier — poster un JSON valide à
    /// une adresse devinée — et c'est aussi ce qui arriverait si Smartlead
    /// changeait le nom du champ sans le dire. Les deux se réparent
    /// différemment mais se refusent pareil.
    #[tokio::test]
    async fn a_smartlead_body_without_its_secret_is_refused() {
        let Some((db, tenant, router)) = smartlead_harness().await else {
            return;
        };
        let body =
            br#"{"event_type":"EMAIL_UNSUBSCRIBED","sl_lead_email":"quiet@prospect.example"}"#;
        let request = HttpRequest::post(format!("/v1/webhooks/{SMARTLEAD_PROVIDER}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_vec()))
            .expect("request");

        let (status, _) = call(&router, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            stored(&db, tenant).await.is_empty(),
            "une livraison sans credential a été mise en file"
        );
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

    /// **An unsigned `email.complained` is refused like anything else, and that
    /// matters more than it used to.**
    ///
    /// A refusal is no longer inert. `main::on_webhook` now reads one, and
    /// `app::inbound::record_refusal` writes it to an append-only trail that is
    /// one call short of `suppressions` — a table with no DELETE, for anybody,
    /// by trigger. So a forged complaint that got past this door would be a way
    /// for an unauthenticated stranger to have a tenant's own customers marked
    /// do-not-contact, permanently, one address per request.
    ///
    /// The only thing standing between those two facts is this refusal, and
    /// "nothing was queued" is the whole of it: `on_webhook` reads outbox rows
    /// and nothing else, so a delivery that is never stored can never be read.
    #[tokio::test]
    async fn an_unsigned_complaint_reaches_neither_the_queue_nor_the_trail() {
        let Some((db, tenant, router)) = harness().await else {
            return;
        };

        let complaint = br#"{"type":"email.complained","created_at":"2026-08-24T10:00:00Z","data":{"email_id":"email_forged","from":"lena@agents.example.com","to":["victim@customer.example"]}}"#;

        // Unsigned, then signed with a secret we do not hold. Both are the same
        // answer, and neither leaves a row.
        let naked = HttpRequest::post(format!("/v1/webhooks/{PROVIDER}"))
            .header("content-type", "application/json")
            .body(Body::from(complaint.to_vec()))
            .expect("request");
        let (status, _) = call(&router, naked).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = call(
            &router,
            signed_to(PROVIDER, "whsec_notoursnotours", "msg_forged", complaint),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            stored(&db, tenant).await.is_empty(),
            "a forged complaint was queued; it is one outbox drain away from \
             suppressing somebody else's customer for good"
        );

        // The control: the same bytes, signed properly, are accepted — so the
        // two refusals above were the signature and not the payload shape.
        let (status, _) = call(&router, signed("msg_honest_complaint", complaint)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(stored(&db, tenant).await.len(), 1);
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
        let router = router(db.clone(), credentials, Webhooks::default(), ORIGIN);

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
        let router = router(db.clone(), credentials, Webhooks::default(), ORIGIN);

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
        let router = router(db.clone(), credentials, Webhooks::new(endpoints), ORIGIN);

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

    // -- telephony -----------------------------------------------------------

    /// `PUBLIC_HOST` is the origin the MAC is computed over, and every
    /// deployment configured before this scheme existed set it without one.
    /// Left alone, that is a deployment where every genuine text message is
    /// answered 401.
    #[test]
    fn a_public_host_with_no_scheme_becomes_an_https_origin() {
        assert_eq!(
            callback_origin("agents.example.com"),
            "https://agents.example.com"
        );
        assert_eq!(
            callback_origin("agents.example.com/"),
            "https://agents.example.com"
        );
        // A host that names its own scheme keeps it — a development box on
        // plain http must not be rewritten into one that cannot be reached.
        assert_eq!(
            callback_origin("http://localhost:8080"),
            "http://localhost:8080"
        );
        assert_eq!(
            callback_origin(" https://agents.test/ "),
            "https://agents.test"
        );
    }

    /// **The claim the telephony arm exists for.** The other scheme's verifier
    /// would reject this delivery outright — it carries none of the three
    /// Standard Webhooks headers — so an endpoint that accepts it is an
    /// endpoint that ran Twilio's verifier, and a forgery under the same scheme
    /// is still refused.
    #[tokio::test]
    async fn a_telephony_delivery_is_verified_with_twilios_own_scheme() {
        let Some((db, tenant, router)) = telephony_harness().await else {
            return;
        };
        let url = callback_url(TELEPHONY_PROVIDER);
        let form = twilio_form("SM_verify", "+33612345678", "bonjour");

        // Unsigned: no header at all.
        let naked = HttpRequest::post(format!("/v1/webhooks/{TELEPHONY_PROVIDER}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.clone()))
            .expect("request");
        let (status, _) = call(&router, naked).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Signed with a token we do not hold.
        let (status, _) = call(
            &router,
            signed_twilio(TELEPHONY_PROVIDER, "not-our-auth-token", &url, &form),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Signed correctly, then a byte of the body flipped: the MAC covers the
        // form fields, so the same header must stop working.
        let mut tampered = signed_twilio(TELEPHONY_PROVIDER, AUTH_TOKEN, &url, &form);
        *tampered.body_mut() = Body::from(twilio_form("SM_verify", "+33612345678", "bonjouR"));
        let (status, _) = call(&router, tampered).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        assert!(
            stored(&db, tenant).await.is_empty(),
            "an unverified text was queued; it is one outbox drain away from a turn"
        );

        // The control: the same bytes, the right token, the right URL.
        let (status, _) = call(
            &router,
            signed_twilio(TELEPHONY_PROVIDER, AUTH_TOKEN, &url, &form),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let rows = stored(&db, tenant).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, format!("webhook.{TELEPHONY_PROVIDER}.received"));
        // Verbatim, so `land_inbound_text` reads exactly the bytes that were
        // signed rather than a round trip through serde_json.
        assert_eq!(
            rows[0].1["body"].as_str().expect("body").as_bytes(),
            form.as_slice()
        );
    }

    /// **The one this scheme can get wrong silently, and the reason the dedupe
    /// id is not `headers.id`.**
    ///
    /// Twilio sends no `webhook-id`, so `signature_headers` reads an empty
    /// string for it. An edge that deduped on that would compute the key
    /// `twilio:` for every callback a deployment ever receives, `outbox::enqueue`
    /// would collapse them all onto the first row, and every text after the
    /// first would be answered 202 and dropped — with no error anywhere and a
    /// customer whose second message was never read.
    ///
    /// Two distinct texts must be two rows; three deliveries of one text must be
    /// one. Both halves, because a key that is unique per delivery would pass
    /// the first assertion and break redelivery instead.
    #[tokio::test]
    async fn two_texts_are_two_rows_and_three_deliveries_of_one_are_one() {
        let Some((db, tenant, router)) = telephony_harness().await else {
            return;
        };
        let url = callback_url(TELEPHONY_PROVIDER);

        let first = twilio_form("SM_one", "+33612345678", "the invoice is wrong");
        let mut ids = Vec::new();
        for attempt in 1..=3 {
            let (status, answer) = call(
                &router,
                signed_twilio(TELEPHONY_PROVIDER, AUTH_TOKEN, &url, &first),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "delivery {attempt}");
            ids.push(answer["event_id"].clone());
        }
        assert_eq!(ids[0], ids[1], "a redelivery must name the original row");
        assert_eq!(ids[1], ids[2]);
        assert_eq!(stored(&db, tenant).await.len(), 1);

        // A second message from the same person on the same number.
        let second = twilio_form("SM_two", "+33612345678", "and so is the delivery date");
        let (status, _) = call(
            &router,
            signed_twilio(TELEPHONY_PROVIDER, AUTH_TOKEN, &url, &second),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let rows = stored(&db, tenant).await;
        assert_eq!(
            rows.len(),
            2,
            "a second text collapsed onto the first: every message after the first is lost"
        );
        let bodies: Vec<&str> = rows
            .iter()
            .map(|(_, payload)| payload["body"].as_str().expect("body"))
            .collect();
        assert!(
            bodies.iter().any(|body| body.contains("SM_one")),
            "{bodies:?}"
        );
        assert!(
            bodies.iter().any(|body| body.contains("SM_two")),
            "{bodies:?}"
        );
    }

    /// The callback URL is inside the MAC, which is what `PUBLIC_HOST` has to
    /// get exactly right. A signature minted for a neighbouring origin is not
    /// accepted here — stated as a test so that the cost of getting that
    /// variable wrong is a documented refusal rather than a mystery.
    #[tokio::test]
    async fn a_signature_minted_for_another_origin_is_refused() {
        let Some((db, tenant, router)) = telephony_harness().await else {
            return;
        };
        let form = twilio_form("SM_origin", "+33612345678", "hello");

        for elsewhere in [
            "https://agents.test.evil.example/v1/webhooks/twilio",
            "http://agents.test/v1/webhooks/twilio",
            "https://agents.test/v1/webhooks/twilio/",
        ] {
            let (status, _) = call(
                &router,
                signed_twilio(TELEPHONY_PROVIDER, AUTH_TOKEN, elsewhere, &form),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{elsewhere}");
        }
        assert!(stored(&db, tenant).await.is_empty());

        // The control, so the three refusals above were the URL and not the
        // fixture.
        let (status, _) = call(
            &router,
            signed_twilio(
                TELEPHONY_PROVIDER,
                AUTH_TOKEN,
                &callback_url(TELEPHONY_PROVIDER),
                &form,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    /// **The scheme follows the endpoint's `provider`, and a mismatch fails
    /// closed in both directions.**
    ///
    /// This is the property that lets `Endpoint` carry no `scheme` field. An
    /// endpoint registered under the wrong provider does not fall back to the
    /// other verifier, does not skip verification, and writes nothing.
    #[tokio::test]
    async fn an_endpoint_verifies_only_its_own_scheme() {
        let Some(db) = connect().await else { return };
        let (mail, phone) = (seed_tenant(&db).await, seed_tenant(&db).await);
        let endpoints = HashMap::from([
            (
                PROVIDER.to_owned(),
                Endpoint {
                    tenant_id: mail,
                    provider: PROVIDER.to_owned(),
                    secret: Secret::new(SECRET),
                },
            ),
            (
                TELEPHONY_PROVIDER.to_owned(),
                Endpoint {
                    tenant_id: phone,
                    provider: TELEPHONY_PROVIDER.to_owned(),
                    secret: Secret::new(AUTH_TOKEN),
                },
            ),
        ]);
        let router = router(
            db.clone(),
            Credentials::from_master_key(MASTER),
            Webhooks::new(endpoints),
            ORIGIN,
        );

        // A correctly signed Twilio delivery, posted to the email endpoint.
        let form = twilio_form("SM_cross", "+33612345678", "hello");
        let (status, _) = call(
            &router,
            signed_twilio(PROVIDER, AUTH_TOKEN, &callback_url(PROVIDER), &form),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A correctly signed Standard Webhooks delivery, posted to the
        // telephony endpoint.
        let (status, _) = call(
            &router,
            signed_to(
                TELEPHONY_PROVIDER,
                SECRET,
                "msg_cross",
                &payload("email_cross"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        assert!(
            stored(&db, mail).await.is_empty(),
            "a cross-scheme delivery was queued"
        );
        assert!(
            stored(&db, phone).await.is_empty(),
            "a cross-scheme delivery was queued"
        );

        // The two controls, each on its own endpoint and its own scheme.
        let (status, _) = call(
            &router,
            signed_to(PROVIDER, SECRET, "msg_ok", &payload("email_ok")),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (status, _) = call(
            &router,
            signed_twilio(
                TELEPHONY_PROVIDER,
                AUTH_TOKEN,
                &callback_url(TELEPHONY_PROVIDER),
                &form,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(stored(&db, mail).await.len(), 1);
        assert_eq!(stored(&db, phone).await.len(), 1);
    }

    /// **The migration and the route, together.** A tenant registers a
    /// telephony endpoint through the real platform path — which mints an
    /// opaque `whe_…` and seals the auth token — and a signed callback to that
    /// address is accepted.
    ///
    /// This is the production shape, and it is the one `0053`'s
    /// `webhook_endpoints_provider_is_wired` CHECK made impossible until `0069`
    /// widened it: a row naming a provider with no reader is eight retries and
    /// a dead letter per customer message, so the CHECK refused the value until
    /// the reader existed. It exists, so a `twilio` row must now be storable —
    /// and a provider with still no reader must still be refused, or the CHECK
    /// has stopped meaning anything.
    #[tokio::test]
    async fn a_stored_telephony_endpoint_is_registrable_and_verifies() {
        let Some(db) = connect().await else { return };
        let credentials = Credentials::from_master_key(MASTER);
        let tenant = seed_tenant(&db).await;

        let (path, _) = agentos_app::webhooks::register(
            &db,
            &credentials,
            tenant,
            TELEPHONY_PROVIDER,
            AUTH_TOKEN.to_owned(),
            &agentos_store::audit::AuditActor::Operator("platform".to_owned()),
            Utc::now(),
        )
        .await
        .expect("a telephony endpoint must be registrable once its ingest exists");

        // Still a fence, not a formality: a provider nothing reads is refused
        // by the table.
        assert!(
            agentos_app::webhooks::register(
                &db,
                &credentials,
                seed_tenant(&db).await,
                "stripe",
                "sk_whatever".to_owned(),
                &agentos_store::audit::AuditActor::Operator("platform".to_owned()),
                Utc::now(),
            )
            .await
            .is_err(),
            "an endpoint was stored for a provider no handler reads; every delivery to it is a \
             dead letter"
        );

        let router = router(db.clone(), credentials, Webhooks::default(), ORIGIN);
        let form = twilio_form("SM_stored", "+33612345678", "hello");

        // The forgery first, so an accepted delivery below is the signature and
        // not an endpoint that verifies nothing.
        let (status, _) = call(
            &router,
            signed_twilio(&path, "not-our-auth-token", &callback_url(&path), &form),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(stored(&db, tenant).await.is_empty(), "a forgery was queued");

        let (status, _) = call(
            &router,
            signed_twilio(&path, AUTH_TOKEN, &callback_url(&path), &form),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let rows = stored(&db, tenant).await;
        assert_eq!(rows.len(), 1);
        // From the endpoint's `provider`, never from the opaque path — an
        // `event_type` naming a minted path is an event type nothing handles.
        assert_eq!(rows[0].0, format!("webhook.{TELEPHONY_PROVIDER}.received"));
    }
}
