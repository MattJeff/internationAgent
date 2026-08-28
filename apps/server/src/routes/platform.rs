//! `/v1/platform`: step zero — a customer arriving, and a credential they can
//! lose without taking everybody else down with them.
//!
//! # The question this file exists to answer: who may issue a key
//!
//! It is the hard half, and the two easy answers are both wrong.
//!
//! **"A tenant issues its own keys."** This is what every SaaS console does and
//! it is exactly what must not happen here, for one reason: *a stolen key would
//! mint more*. Revocation would then be a race against whoever holds the key,
//! and losing that race is silent — the attacker's second key has a different id
//! and a different digest and looks like every other key the customer ever
//! asked for. Revocation that a compromised credential can undo is not
//! revocation. So there is **no route anywhere in this server that mints a key
//! for the caller's own tenant**, and `auth::Principal` is not accepted by any
//! handler in this file.
//!
//! **"The operator does it with a shell."** This is what the deployment already
//! does for the thing with the same shape — the platform policy ceiling, whose
//! row belongs to no tenant, is written by `agentos-server policy install`, on
//! the strength of `DATABASE_URL` and nothing else. `apps/server/src/policy.rs`
//! argues that at length and the argument is right about ceilings. It is only a
//! *partial* answer here, and it says so itself:
//!
//! > What a route would add, if one is ever wanted: a hosted control plane where
//! > the *vendor* — not a tenant — widens the ceiling for a customer without
//! > shell access to the box. Build it when there is a platform principal to
//! > authenticate.
//!
//! A subcommand cannot be step zero. A customer filling in a form cannot ssh
//! anywhere, and "the founder runs a command per signup" is the same ceiling as
//! the environment variable wearing a different hat: the customer's first step
//! is still a human being of ours.
//!
//! # So: a platform principal, and it is not a tenant
//!
//! [`PlatformPrincipal`] comes from `AGENTOS_PLATFORM_KEYS`, holds no tenant id,
//! and is a different Rust type from `auth::Principal`. That is the enforcement,
//! not a convention:
//!
//! * Every route that reads tenant data extracts `auth::Principal`, and only
//!   `auth::require_api_key` ever inserts one. A platform key presented there is
//!   a string that is not in the tenant keyring — a 401, the same as a typo.
//! * Every route in this file extracts [`PlatformPrincipal`], and only
//!   `auth::require_platform_key` inserts one. A tenant's key presented here is
//!   a string that is not in the platform keyring.
//!
//! **What that makes impossible.** A stolen tenant key cannot issue a key,
//! cannot revoke one, cannot create a tenant, and cannot see that any of these
//! endpoints exist. Revoking it therefore ends the incident. A stolen platform
//! key cannot read one row of one tenant's data with the credential it is — it
//! has to *issue itself a key first*, and that issuance is an `api_key_issued`
//! row in the victim's own append-only trail, naming the label the thief chose,
//! in a table `app_role` holds no DELETE on and a trigger refuses to UPDATE even
//! for a superuser. A total compromise of the vendor is therefore loud rather
//! than silent, which is the most a design can promise about the credential that
//! sits at the root.
//!
//! **What it makes possible.** A signup form. The vendor's front end holds the
//! platform key, `POST /v1/platform/tenants` returns a working credential in one
//! call, and the customer's next request is `GET /v1/whoami` with a key nobody
//! deployed. That is the step that did not exist.
//!
//! # Why these routes are not behind `with_api_stack`
//!
//! Because that stack *is* `auth::require_api_key` — a platform key would be
//! refused by it before any handler ran. They sit in the outer stack (request
//! id, trace, body limit, timeout) with `require_platform_key` in front, which
//! is the same shape `routes::webhooks` uses for the same reason: a credential
//! this server understands, that is not a tenant's.
//!
//! ponytail: no rate limiter and no idempotency layer on this tier. Both are
//! keyed on a tenant that does not exist yet, and the two writes here are
//! protected by uniqueness instead — a replayed signup collides on
//! `tenants_slug_key`, a replayed issue collides on `api_keys_tenant_label_key`,
//! and both answer 409 rather than quietly making a second of anything.

use agentos_domain::ids::{Slug, TenantId};
use agentos_store::api_keys::ApiKeyRecord;
use agentos_store::audit::AuditActor;
use agentos_store::db::{Db, StoreError};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Router, response::Result as AxumResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::PlatformPrincipal;
use crate::error::ApiError;

/// Everything the platform surface needs.
///
/// The hashing key comes from `auth::Keyring`, which is the same value the
/// authentication path uses — deliberately one derivation, because two would be
/// a deployment that issues keys it cannot verify.
#[derive(Clone)]
pub struct PlatformState {
    db: Db,
    hasher: agentos_app::api_keys::Hasher,
    /// The deployment's cipher, for sealing a signing secret into
    /// `webhook_endpoints`. The same handle `routes::mcp` and the agent hold:
    /// two ciphers over one `AGENTOS_MASTER_KEY` is a deployment where what one
    /// half sealed the other cannot open.
    credentials: agentos_app::mcp::Credentials,
}

/// This unit's routes. Mounted with `auth::require_platform_key` in front and
/// nothing else.
pub fn router(
    db: Db,
    hasher: agentos_app::api_keys::Hasher,
    credentials: agentos_app::mcp::Credentials,
) -> Router {
    Router::new()
        .route("/v1/platform/tenants", post(create_tenant))
        .route("/v1/platform/keys", post(issue_key).get(list_keys))
        .route("/v1/platform/keys/{id}", delete(revoke_key))
        .route("/v1/platform/webhooks", post(register_webhook))
        .with_state(PlatformState {
            db,
            hasher,
            credentials,
        })
}

// ---------------------------------------------------------------------------
// The one response that carries a secret
// ---------------------------------------------------------------------------

/// A freshly minted credential.
///
/// **This struct is the only place in the system where a secret is serialised,
/// and it happens once.** There is no `GET` that returns it, no field on any
/// listing that holds it, and nothing recomputes it: the digest is one-way and
/// the plaintext is dropped when this value is.
///
/// The customer who loses it issues another and revokes this one, which is two
/// calls and is the entire disaster-recovery story for a secret on purpose.
#[derive(Serialize)]
struct IssuedKeyBody {
    /// The handle a revocation names. Not a credential — safe to store, log and
    /// display next to the key in a console.
    id: Uuid,
    /// Whose key it is.
    tenant_id: Uuid,
    /// Its human name, which becomes the audit actor when it authenticates.
    label: String,
    /// **Shown once.** Everything above can be recovered from
    /// `GET /v1/platform/keys`; this cannot be recovered from anywhere.
    secret: String,
    /// Said in the payload as well as in the docs, because the client that
    /// forgets to save this is a support ticket and a revocation.
    warning: &'static str,
}

/// What the field above says, once, in the body a client is about to parse.
const SHOWN_ONCE: &str = "This secret is shown exactly once. It is stored only as an HMAC digest and cannot be \
     recovered; if it is lost, issue another key and revoke this one.";

impl IssuedKeyBody {
    fn new(issued: agentos_app::api_keys::Issued) -> Self {
        Self {
            id: issued.id,
            tenant_id: issued.tenant_id.as_uuid(),
            label: issued.label,
            // The one call in the binary that takes the plaintext out. It goes
            // straight into the field being serialised and is bound to no
            // variable that outlives this expression, which is the rule
            // `agentos_providers::Secret::expose_for_transport` states.
            secret: issued.secret.expose_for_transport().to_owned(),
            warning: SHOWN_ONCE,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/platform/tenants` — a company, its policy version, and its first
/// key, in one call.
///
/// The three together because any two of them is a broken install:
///
/// * a `tenants` row with no active `policy_versions` row has invisible layers
///   (`store::policy::create_tenant` argues this and writes both);
/// * a tenant with no key is a tenant nobody can reach, which is the state this
///   whole wave exists to end.
///
/// Not idempotent, and it says so with a status: a second call with the same
/// slug is `409`, because the alternative is returning the *existing* tenant
/// together with a *new* secret, and a call that mints a credential must never
/// be something a client retries by reflex.
#[derive(Deserialize)]
struct CreateTenantRequest {
    /// The handle every other document refers to this company by.
    slug: String,
    /// Its display name.
    name: String,
    /// What to call the first key. Defaults to `owner`.
    #[serde(default)]
    key_label: Option<String>,
}

async fn create_tenant(
    State(state): State<PlatformState>,
    who: PlatformPrincipal,
    body: Result<Json<CreateTenantRequest>, JsonRejection>,
) -> AxumResult<Response, ApiError> {
    let Json(request) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    // A slug, not free text — `Slug::parse` is what the rest of the system means
    // by one, and `policy new-tenant` applies the identical rule to the
    // identical field.
    let slug = Slug::parse(&request.slug)
        .map_err(|err| ApiError::bad_request(format!("slug: {err}")))?
        .as_str()
        .to_owned();
    let name = request.name.trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::bad_request("name: must not be blank"));
    }
    let label = key_label(request.key_label.as_deref())?;

    // v7, so a directory of tenants sorts by when it was created. Minted here
    // and not accepted from the body: a caller-chosen id is a caller who can
    // aim a signup at an existing tenant's uuid and find out whether it is
    // taken.
    let tenant_id = TenantId::new_v7(Utc::now());
    agentos_store::policy::create_tenant(&state.db, tenant_id, &slug, &name)
        .await
        .map_err(|err| match err {
            StoreError::Conflict(_) => {
                ApiError::conflict("tenant_exists", "a tenant with this slug already exists")
            }
            err => err.into(),
        })?;

    // **Two transactions, and the window between them is named rather than
    // hidden.** `create_tenant` commits the `tenants` row and its policy version
    // together (that pair is its own invariant); the key is a second commit. A
    // database that dies in between leaves a tenant whose slug is taken and
    // whose key nobody has, and the caller's retry would get `409` forever with
    // no way to name what it collided with.
    //
    // ponytail: the fix is the tenant id in the refusal, not one transaction
    // spanning two modules. The repair is then `POST /v1/platform/keys` with
    // that id, which is a call this surface already has. Make it one transaction
    // the day `store::policy::create_tenant` takes a transaction instead of a
    // `&Db` — at which point `store::api_keys::issue` can join it.
    let issued = issue_for(&state, tenant_id, &label, &who)
        .await
        .map_err(|err| {
            tracing::error!(
                tenant_id = %tenant_id.as_uuid(),
                %slug,
                "the tenant was created and its first key was not; it is reachable by nobody"
            );
            err.with_detail(format!(
                "The tenant was created as {} and its first API key was not issued. It exists, its \
             slug is taken, and nothing can authenticate as it: issue one with \
             `POST /v1/platform/keys` naming that id.",
                tenant_id.as_uuid()
            ))
        })?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "tenant_id": tenant_id.as_uuid(),
            "slug": slug,
            "name": name,
            "key": IssuedKeyBody::new(issued),
        })),
    )
        .into_response())
}

/// `POST /v1/platform/keys` — another key for a tenant that exists.
///
/// **This is the rotation path**, and it is the reason revocation is usable: an
/// operator whose key has leaked issues the replacement first, deploys it, and
/// only then revokes the old one — so the incident costs no downtime, which is
/// the property that makes people actually revoke instead of waiting for a
/// maintenance window.
#[derive(Deserialize)]
struct IssueKeyRequest {
    /// Whose key this is. Named by the platform, never by the key itself.
    tenant_id: Uuid,
    /// What to call it. Unique within the tenant.
    #[serde(default)]
    label: Option<String>,
}

async fn issue_key(
    State(state): State<PlatformState>,
    who: PlatformPrincipal,
    body: Result<Json<IssueKeyRequest>, JsonRejection>,
) -> AxumResult<Response, ApiError> {
    let Json(request) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let label = key_label(request.label.as_deref())?;
    let tenant_id = TenantId::from_uuid(request.tenant_id);

    let issued = issue_for(&state, tenant_id, &label, &who).await?;
    Ok((StatusCode::CREATED, Json(IssuedKeyBody::new(issued))).into_response())
}

/// `GET /v1/platform/keys?tenant_id=…` — this tenant's live keys.
///
/// Ids, labels and dates. **No digests**, because a digest is the one value an
/// attacker who also has `AGENTOS_MASTER_KEY` could test candidates against, and
/// there is no reason for it to leave the database.
#[derive(Deserialize)]
struct ListQuery {
    tenant_id: Uuid,
}

#[derive(Serialize)]
struct KeyBody {
    id: Uuid,
    label: String,
    created_at: chrono::DateTime<Utc>,
}

impl From<ApiKeyRecord> for KeyBody {
    fn from(record: ApiKeyRecord) -> Self {
        Self {
            id: record.id,
            label: record.label,
            created_at: record.created_at,
        }
    }
}

async fn list_keys(
    State(state): State<PlatformState>,
    _who: PlatformPrincipal,
    // The rejection is taken rather than left to axum: its default is a
    // text/plain body, and `crate::error` exists so that every refusal on this
    // surface is one problem+json vocabulary.
    query: Result<Query<ListQuery>, QueryRejection>,
) -> AxumResult<Json<serde_json::Value>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let keys: Vec<KeyBody> =
        agentos_app::api_keys::list(&state.db, TenantId::from_uuid(query.tenant_id))
            .await?
            .into_iter()
            .map(KeyBody::from)
            .collect();
    Ok(Json(json!({ "keys": keys })))
}

/// `DELETE /v1/platform/keys/{id}` — the key stops working on the next request.
///
/// No tenant id in the path or the body: the row knows whose key it is, and
/// asking the caller to say would be asking them to get it right. The response
/// reports the tenant, so an operator revoking from a screenshot finds out which
/// customer they just interrupted.
///
/// `404` for a key that is not there, which is also the answer for one revoked a
/// second ago. Revoking twice is the state the caller wanted, and a script that
/// has to special-case "already gone" is a script that stops on the one path
/// where stopping is worst.
async fn revoke_key(
    State(state): State<PlatformState>,
    who: PlatformPrincipal,
    id: Result<Path<Uuid>, PathRejection>,
) -> AxumResult<Json<serde_json::Value>, ApiError> {
    let Path(id) = id.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let tenant_id = agentos_app::api_keys::revoke(
        &state.db,
        id,
        &AuditActor::Operator(who.label.clone()),
        Utc::now(),
    )
    .await?;

    // The id and the tenant, never the label's secret — there is none to leak,
    // and the log line is what an operator greps at 3am.
    tracing::info!(
        key_id = %id,
        tenant_id = %tenant_id.as_uuid(),
        by = %who.label,
        "api key revoked"
    );
    Ok(Json(json!({
        "key_id": id,
        "tenant_id": tenant_id.as_uuid(),
        "revoked": true,
    })))
}

/// `POST /v1/platform/webhooks` — the URL to paste into a provider's dashboard,
/// and the secret that dashboard gave you, in one call.
///
/// # Why this is on the platform surface and not a subcommand
///
/// The same argument as the rest of this file, and it lands harder here. An
/// endpoint is registered *per customer*, at signup, by whoever is doing the
/// signup — so "the founder runs a command on the box per new customer" is the
/// ceiling `AGENTOS_WEBHOOK_SECRETS` already had, wearing a different hat. And
/// it is a platform act and not a tenant act for the reason `webhook_endpoints`
/// exists at all: the row says whose mail this is, and a tenant that could write
/// its own row could name a path and start collecting somebody else's
/// deliveries. **No handler in this server accepts an `auth::Principal` for this
/// table**, which is the enforcement rather than the convention.
///
/// # The secret goes in and never comes back
///
/// The mirror image of [`IssuedKeyBody`], and the asymmetry is the point. There
/// the secret is ours and is shown once; here the secret is the *provider's* and
/// is shown never — it is sealed under `webhook://<tenant>` before the
/// transaction opens and this response carries the path, which is an address and
/// not a credential. The search for a place that forgot is
/// `apps/server/tests/platform_signup.rs`, third test.
///
/// # Registering twice rotates
///
/// One row per `(tenant, provider)`, and a second call replaces the secret **and
/// keeps the path**, so rotating at the provider does not mean re-pasting a URL
/// and — the half that matters — does not leave the old secret verifying on a
/// second endpoint nobody remembers. `200`, not `201`, when that happens: the
/// body says `rotated`, and a caller that treats a rotation as a creation would
/// be a caller storing two URLs for one customer.
#[derive(Deserialize)]
struct RegisterWebhookRequest {
    /// Whose deliveries these are. Named by the platform, never by the request
    /// that later arrives on the endpoint.
    tenant_id: Uuid,
    /// Which ingest reads them. `email` and `twilio` are wired — the table's
    /// `webhook_endpoints_provider_is_wired` CHECK is what says so, and each is
    /// paired with an ingest in `routes::webhooks`.
    ///
    /// This said "`email` is the only one wired" until somebody read it beside
    /// the constraint: `0069_a_number_is_an_endpoint_too.sql` widened it to two
    /// and this line was not moved with it. The CHECK is the answer; a comment
    /// that restates a constraint is a comment that goes stale the next time the
    /// constraint moves.
    #[serde(default = "default_provider")]
    provider: String,
    /// The `whsec_…` signing secret from the provider's dashboard.
    secret: String,
}

fn default_provider() -> String {
    "email".to_owned()
}

async fn register_webhook(
    State(state): State<PlatformState>,
    who: PlatformPrincipal,
    body: Result<Json<RegisterWebhookRequest>, JsonRejection>,
) -> AxumResult<Response, ApiError> {
    let Json(request) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let tenant_id = TenantId::from_uuid(request.tenant_id);

    // Trimmed and refused when blank, before anything is sealed. A form that
    // posts `""` for an untouched field is the single most common way an
    // endpoint ends up rejecting every genuine delivery, and an empty secret
    // seals and stores perfectly well — see `Credentials::seal`, which makes
    // the same check for the same reason.
    let secret = request.secret.trim().to_owned();
    if secret.is_empty() {
        return Err(ApiError::bad_request("secret: must not be blank"));
    }

    let (path, rotated) = agentos_app::webhooks::register(
        &state.db,
        &state.credentials,
        tenant_id,
        &request.provider,
        secret,
        &AuditActor::Operator(who.label.clone()),
        Utc::now(),
    )
    .await
    .map_err(|err| registration_refused(err, request.tenant_id))?;

    // The path and the tenant. **Never the secret**, and nothing derived from
    // it — this line is what an operator greps, and a grep-able log is a log
    // somebody ships to a third party.
    tracing::info!(
        tenant_id = %tenant_id.as_uuid(),
        provider = %request.provider,
        %path,
        rotated,
        by = %who.label,
        "webhook endpoint registered"
    );

    Ok((
        if rotated {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "tenant_id": tenant_id.as_uuid(),
            "provider": request.provider,
            "path": path,
            // The caller cannot work this out from the path alone, and the two
            // outcomes ask for different next acts: paste a URL, or do nothing
            // because the URL did not move.
            "rotated": rotated,
            // Said in the body because the operator's next act is to paste this
            // somewhere, and a path without its route is a support ticket. Not
            // an absolute URL: this server does not know what is in front of it,
            // and `config.public_host` is the agent card's answer to a different
            // question.
            "route": format!("/v1/webhooks/{path}"),
        })),
    )
        .into_response())
}

/// Postgres SQLSTATE for `check_violation`.
///
/// Named here rather than reached for from `agentos_store::db`, which keeps its
/// own list private: this is the one route that has a reason to tell one
/// constraint failure apart from a database that is simply down.
const SQLSTATE_CHECK_VIOLATION: &str = "23514";

/// Why a webhook endpoint was not registered.
///
/// A named function rather than the closure this was, so the arm below can be
/// tested without a database — which is the whole point, because **the arm that
/// was wrong is the one no end-to-end test can reach on purpose**: it fires when
/// the database is down.
///
/// The `Database` arm used to match every driver error and answer `400
/// provider: no ingest reads this provider's deliveries`. A pool timeout, a
/// dropped connection, a table missing after a half-applied migration — each of
/// them told an operator that a `provider` value which was correct is wrong, and
/// sent them to change it while the thing that is down is ours. It is the same
/// wrong-culprit failure `StoreError::UnknownTenant` was split out of, pointing
/// the other way: there a 500 blamed us for the caller's mistake, here a 400
/// blames the caller for ours.
///
/// So the arm now names the SQLSTATE it means. Everything else falls through to
/// `StoreError`'s own mapping, which is a 500 — or a 503 for a retryable abort,
/// which this route is one `webhook_endpoints_pkey` race away from producing.
fn registration_refused(err: agentos_app::webhooks::EndpointError, tenant_id: Uuid) -> ApiError {
    use agentos_app::webhooks::EndpointError;

    match err {
        // The tenant uuid was made up. A 404, not the `400 unknown_tenant`
        // `ApiError::from` produces — that message is addressed to the holder of
        // a *tenant* key and tells them their own key names a tenant that was
        // never created, which this caller cannot act on.
        EndpointError::Store(StoreError::UnknownTenant(_)) => {
            ApiError::new(StatusCode::NOT_FOUND, "unknown_tenant", "no such tenant").with_detail(
                format!(
                    "There is no tenant {tenant_id}. Create one with `POST /v1/platform/tenants`."
                ),
            )
        }
        // A provider with no ingest is refused by the table, not by a list in
        // this file: one place to widen, and it is the same place as the CHECK.
        // `webhook_endpoints_provider_is_wired` is the only CHECK this insert
        // can break, so the SQLSTATE is enough to say so without reading the
        // constraint name back out — which `error.rs` would not let into the
        // body anyway.
        EndpointError::Store(StoreError::Database(ref err))
            if err
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref()
                == Some(SQLSTATE_CHECK_VIOLATION) =>
        {
            ApiError::bad_request(
                "provider: no ingest reads this provider's deliveries on this build",
            )
        }
        EndpointError::Store(err) => err.into(),
        // Ours, not theirs: the master key. The cipher's code goes to the log
        // and never into the body.
        EndpointError::Cipher { code } => {
            tracing::error!(code, "a webhook signing secret could not be sealed");
            ApiError::internal()
        }
    }
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Mint one key, mapping the two failures a caller can actually cause.
///
/// `UnknownTenant` is the interesting one: the platform named a tenant uuid and
/// there is no row for it. That is a 404 and not the `400 unknown_tenant`
/// `ApiError::from` produces, because that message tells the *holder of a tenant
/// key* that their own key names a tenant that was never created — advice this
/// caller cannot act on and did not ask for.
async fn issue_for(
    state: &PlatformState,
    tenant_id: TenantId,
    label: &str,
    who: &PlatformPrincipal,
) -> Result<agentos_app::api_keys::Issued, ApiError> {
    let issued = agentos_app::api_keys::issue(
        &state.db,
        &state.hasher,
        tenant_id,
        label,
        &AuditActor::Operator(who.label.clone()),
        Utc::now(),
    )
    .await
    .map_err(|err| match err {
        StoreError::UnknownTenant(_) => ApiError::not_found(),
        StoreError::Conflict(_) => ApiError::conflict(
            "key_label_exists",
            "this tenant already has a key with that label",
        ),
        err => err.into(),
    })?;

    // The id and the label. The secret is in the response and in no log line,
    // which `apps/server/tests/platform_signup.rs` is the search for.
    tracing::info!(
        key_id = %issued.id,
        tenant_id = %tenant_id.as_uuid(),
        label = %issued.label,
        by = %who.label,
        "api key issued"
    );
    Ok(issued)
}

/// A key's name: a slug, defaulting to `owner`.
///
/// `Slug::parse` and not free text, for the same reason the tenant's own handle
/// is one: the label is what an operator types to find a key to revoke, and
/// `Ops Console ` and `ops console` being two different keys is a way to revoke
/// the wrong one.
///
/// **The label is not cosmetic, and a reader has to know it.** It becomes the
/// audit actor, and `routes::approvals::held_role` reads the *role* a credential
/// holds straight off it — so a key labelled `approver` can decide the approvals
/// the gate files against `APPROVER_ROLE`, and an A2A peer's key must be labelled
/// with that peer's domain. That is exactly what an `AGENTOS_API_KEYS` entry has
/// always done with its own first field; this route inherits the property rather
/// than inventing one, which is why there is no separate `role` parameter to get
/// out of step with it.
///
/// It follows that whoever holds the platform key can hand a tenant a key that
/// approves its own payments. They could already: they can mint any key for any
/// tenant, and a second key with a second label is one more call. The defence is
/// not a validation rule here — it is that every issuance is an `api_key_issued`
/// row in that tenant's append-only trail, naming the label.
fn key_label(raw: Option<&str>) -> Result<String, ApiError> {
    let raw = raw.map(str::trim).filter(|value| !value.is_empty());
    let Some(raw) = raw else {
        return Ok("owner".to_owned());
    };
    Ok(Slug::parse(raw)
        .map_err(|err| ApiError::bad_request(format!("label: {err}")))?
        .as_str()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_label_defaults_and_is_a_slug() {
        assert_eq!(key_label(None).expect("default"), "owner");
        assert_eq!(key_label(Some("  ")).expect("blank is absent"), "owner");
        assert_eq!(key_label(Some("Ops Console")).ok(), None, "not a slug");
        assert_eq!(key_label(Some("ops-console")).expect("slug"), "ops-console");
    }

    /// **A database that is down is not a caller who typed the wrong provider.**
    ///
    /// The arm this pins fires only when the database fails, so no end-to-end
    /// test can reach it on purpose — which is exactly why it was wrong for as
    /// long as it was. `PoolTimedOut` is the cheapest real driver failure to
    /// hold in a test: it is a unit variant, it carries no connection, and it is
    /// what a saturated pool actually produces.
    ///
    /// A 400 here reads `provider: no ingest reads this provider's deliveries`,
    /// which sends an operator to change a field that was right while ours is
    /// the thing that is down.
    #[test]
    fn a_database_failure_is_not_the_caller_s_provider_being_wrong() {
        let refused = registration_refused(
            agentos_app::webhooks::EndpointError::Store(StoreError::Database(
                sqlx::Error::PoolTimedOut,
            )),
            Uuid::nil(),
        );
        assert_eq!(
            refused.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a driver failure is ours to own; only a CHECK violation is the provider's"
        );

        // The two arms that were already right, kept beside it: a tenant that
        // does not exist, and a master key that cannot seal.
        assert_eq!(
            registration_refused(
                agentos_app::webhooks::EndpointError::Store(StoreError::UnknownTenant(
                    "webhook_endpoints_tenant_id_fkey".to_owned()
                )),
                Uuid::nil(),
            )
            .into_response()
            .status(),
            StatusCode::NOT_FOUND
        );
        let cipher = registration_refused(
            agentos_app::webhooks::EndpointError::Cipher {
                code: "secret_decrypt_failed",
            },
            Uuid::nil(),
        );
        assert_eq!(cipher.detail(), None, "the cipher's code is a log line");
        assert_eq!(
            cipher.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// The secret is in the body once, and the body says so.
    #[test]
    fn the_issued_body_carries_the_secret_and_the_warning() {
        let body = IssuedKeyBody::new(agentos_app::api_keys::Issued {
            id: Uuid::nil(),
            tenant_id: TenantId::from_uuid(Uuid::nil()),
            label: "owner".to_owned(),
            // `agentos_providers` is deliberately not a dependency of this
            // binary; `agentos_app` re-exports the type, and `routes::model`
            // reaches for the same path for the same reason.
            secret: agentos_app::inbound::Secret::new("aos_the-only-copy"),
        });
        let rendered = serde_json::to_string(&body).expect("serialise");
        assert!(rendered.contains("aos_the-only-copy"), "{rendered}");
        assert!(rendered.contains("shown exactly once"), "{rendered}");
    }
}
