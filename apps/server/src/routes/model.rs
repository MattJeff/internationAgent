//! `/v1/model`: the tenant connects the model their employees think with.
//!
//! **This is the step that has to work in five minutes, and it is the step where
//! the bill changes hands.** Everything before it — the connectors, the email
//! domain, the phone number — spends nothing at a model. `POST /v1/model` makes
//! one model call, on the credential the customer just pasted, and from that
//! moment every token this product ever generates for them is theirs.
//!
//! # Why it is a route and not an environment variable
//!
//! Because the credential belongs to a *tenant* and a variable belongs to a
//! *process*. `AGENTOS_LLM` plus `ANTHROPIC_API_KEY` — which is what the model
//! was until this file — is one key for every tenant on the box, read at boot,
//! invisible to the person whose bill it is not. `apps/server/src/policy.rs`
//! argues at length for keeping operator documents out of HTTP, and none of that
//! argument applies here: a policy layer is written by whoever runs the
//! deployment, and this is written by the customer about their own account.
//!
//! # Three rules this handler keeps
//!
//! **The key is in the request body and nowhere else afterwards.** It is not a
//! query parameter (query strings are logged by every proxy in the path), it is
//! never echoed, and [`ConnectRequest`] has no `Serialize` — so it is
//! structurally impossible to return the thing that came in. The response is
//! `agentos_app::model_access::Outcome`, which holds a verdict, a path, a model
//! and a timestamp, and has no credential field to forget to skip.
//!
//! **A refused key is a 200, not a 4xx.** The request was well formed and we did
//! exactly what it asked: we tried the key and it did not work. That is a
//! *result*, and `Verdict::explain` is a sentence a person can act on. A 401
//! here would be read by every HTTP client in the world as "your API key to
//! *this* service is wrong", which is a different key and sends whoever is
//! setting this up to the wrong console. The verdict is in the body and
//! `connected` is a boolean the front end branches on.
//!
//! **The tenant comes from the API key, never from the body.** [`Principal`] is
//! the authority, `tenant_model_access` has RLS forced, and the audit row names
//! the key label that acted.
//!
//! # What `GET` deliberately does not tell you
//!
//! Whether the connection *still* works. It reports what was proven and when,
//! because that is the only honest thing a row can say — a key can be revoked, a
//! balance can empty and a workspace can lose a model between the proof and the
//! read. Somebody who wants today's answer re-posts, which costs the same
//! fraction of a cent and proves it again.

use std::sync::Arc;

use agentos_app::mocks::{Llm, LlmBackend, SecretStore};
use agentos_app::model_access::{self, ConnectError, Outcome};
use agentos_domain::model_access::ModelPath;
use agentos_domain::policy::ModelId;
use agentos_store::db::Db;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiError;

/// Everything this route needs that is not the database.
///
/// The host's own backend and what it costs us are both here because the CLI
/// path spends whatever this machine has: `agentos_app::model_access` refuses
/// that path when `AGENTOS_LLM=anthropic`, since the key would then be ours.
#[derive(Clone)]
pub struct ModelState {
    db: Db,
    /// This deployment's own model, for the CLI path.
    host: Arc<dyn Llm>,
    /// Which backend that is — the input to "would this be billed to us".
    backend: LlmBackend,
    /// Where a proven key is stored. The same vault every turn reads.
    secrets: Arc<dyn SecretStore>,
}

/// This unit's routes. Merged into the API router, so auth, the rate limit and
/// the idempotency layer are already in front of it.
pub fn router(
    db: Db,
    host: Arc<dyn Llm>,
    backend: LlmBackend,
    secrets: Arc<dyn SecretStore>,
) -> Router {
    Router::new()
        .route("/v1/model", post(connect).get(status))
        .with_state(ModelState {
            db,
            host,
            backend,
            secrets,
        })
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// What a tenant sends to connect their model.
///
/// **Deliberately not `Serialize`.** Deriving both is how a request struct ends
/// up in a response body, in a `Debug` line, or in an error's `detail` — and one
/// of its three fields is a live credential. `Deserialize` only, and no `Debug`
/// either, so `{req:?}` does not compile.
#[derive(Deserialize)]
pub struct ConnectRequest {
    /// `api_key` or `cli`.
    path: ModelPath,
    /// The credential, for `api_key`. Required there, ignored on `cli`.
    ///
    /// A `String` and not a `Secret`: it arrives as JSON either way, and
    /// wrapping it at the serde boundary would buy a redacted `Debug` on a type
    /// that has no `Debug` to redact. It is moved into a `Secret` on the next
    /// line of the handler and never copied.
    #[serde(default)]
    api_key: Option<String>,
    /// Which model to prove. Defaults to [`ModelId::default`], which is what an
    /// unnarrowed fleet runs.
    ///
    /// **Proving one model proves nothing about the other three.** The
    /// verification call names exactly one, and the response says which — see
    /// this module's docs and `agentos_domain::model_access::ModelAccess::model`.
    #[serde(default)]
    model: Option<ModelId>,
}

/// What a connection attempt answers with.
///
/// [`Outcome`] flattened plus the two fields that make it readable without a
/// lookup table: a boolean the caller branches on and the sentence a person
/// reads. Nothing here is derived from the credential.
#[derive(Serialize)]
struct ConnectResponse {
    /// `true` only for [`Verdict::Connected`].
    connected: bool,
    /// Ours, fixed, and containing none of the provider's own text.
    explain: &'static str,
    #[serde(flatten)]
    outcome: Outcome,
}

impl From<Outcome> for ConnectResponse {
    fn from(outcome: Outcome) -> Self {
        Self {
            connected: outcome.verdict.is_connected(),
            explain: outcome.verdict.explain(),
            outcome,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/model` — prove a credential, then store it.
///
/// One model call, billed to whoever owns the credential being proven. See
/// `agentos_app::model_access` for what it costs and why it is a completion
/// rather than a free model listing.
async fn connect(
    State(state): State<ModelState>,
    principal: Principal,
    body: Result<Json<ConnectRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let model = request.model.unwrap_or_default();

    // Trimmed and emptied here rather than deep inside `connect`, because
    // "you sent whitespace" is something the caller got wrong and belongs in a
    // 400 with a `detail`. The key itself never appears in that detail.
    let key = request
        .api_key
        .map(|raw| raw.trim().to_owned())
        .filter(|raw| !raw.is_empty())
        .map(agentos_app::inbound::Secret::new);
    if request.path.needs_secret() && key.is_none() {
        return Err(ApiError::bad_request(
            "the api_key path needs `api_key` in the body, and it was missing or blank",
        ));
    }

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let outcome = model_access::connect(
        &mut tx,
        state.secrets.as_ref(),
        &state.host,
        state.backend,
        request.path,
        model,
        key,
        // `None` is the real API. See `model_access::ApiBase`: this is not a
        // configuration surface, and the day a deployment needs an egress proxy
        // it wants a named variable in `config.rs` rather than a body field a
        // caller could point at a listener of their own.
        None,
        // The actor itself, never `label()`: that renders `operator:<who>`, and
        // `AuditEvent` renders it again on the way to the column.
        principal.actor.clone(),
        Utc::now(),
    )
    .await
    .map_err(connect_error)?;
    tx.commit().await?;

    // A refused key is a 200. See the module docs: the request was well formed
    // and the answer to it is the verdict.
    Ok(Json(ConnectResponse::from(outcome)).into_response())
}

/// `GET /v1/model` — what is connected, and when it was proven.
///
/// 404 when nothing is: an unconnected tenant is a tenant with no such
/// resource, which is the same answer the turn path gives and the same shape
/// every other route in this surface uses for absence.
async fn status(
    State(state): State<ModelState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let access = agentos_store::model_access::load(&mut tx).await?;
    tx.commit().await?;

    match access {
        Some(access) => Ok(Json(access).into_response()),
        None => Err(ApiError::not_found().with_detail(
            "no model is connected for this tenant, so none of its employees can take a turn. \
             POST /v1/model with an Anthropic API key, or with this host's claude CLI",
        )),
    }
}

/// The failures that are not verdicts.
///
/// [`ConnectError::Vault`] and [`ConnectError::Unavailable`] are ours and become
/// a 500 with nothing about how — `error.rs`'s first rule. The other two are the
/// caller's, and both name what to do instead.
fn connect_error(err: ConnectError) -> ApiError {
    match err {
        ConnectError::NoKey => ApiError::bad_request(err.to_string()),
        ConnectError::HostModelIsNotYours => ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "host_model_is_not_yours",
            "this host's model is not yours to spend",
        )
        .with_detail(err.to_string())
        .with_extension("paths", json!([ModelPath::ApiKey.as_str()])),
        ConnectError::Vault(inner) => {
            tracing::error!(code = inner.code(), "the vault refused a model credential");
            ApiError::internal()
        }
        ConnectError::Unavailable(inner) => inner.into(),
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::model_access::Verdict;

    use super::*;

    /// The response body is a fixed set of fields, and a credential is not one
    /// of them.
    ///
    /// A shape test rather than a leak test — `crates/app/tests/model_key_never_leaks.rs`
    /// is the leak test, and it searches the surfaces a key actually passes
    /// through. What this one guards is the thing that would silently undo it:
    /// somebody adding a field here.
    #[test]
    fn the_response_names_the_verdict_the_path_and_the_model_and_nothing_else() {
        let outcome = Outcome {
            verdict: Verdict::Connected,
            access: Some(agentos_domain::model_access::ModelAccess {
                path: ModelPath::ApiKey,
                model: ModelId::Opus5,
                verified_at: Utc::now(),
            }),
        };
        let body = serde_json::to_value(ConnectResponse::from(outcome)).expect("serialize");
        let object = body.as_object().expect("an object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["access", "connected", "explain", "verdict"]);
        assert_eq!(body["connected"], true);
        assert_eq!(body["verdict"], "connected");
        assert_eq!(body["access"]["path"], "api_key");
        assert_eq!(body["access"]["model"], "claude-opus-5");
        assert!(body["access"].get("api_key").is_none());
        assert!(body["access"].get("key").is_none());
        assert!(body["access"].get("secret_ref").is_none());
    }

    /// Every refusal answers 200 with `connected: false` and a sentence, and
    /// every sentence says nothing was stored.
    #[test]
    fn a_refusal_is_a_two_hundred_that_says_what_to_do() {
        for verdict in [
            Verdict::KeyRefused,
            Verdict::ModelNotAccessible,
            Verdict::Unusable,
            Verdict::Unreachable,
        ] {
            let body = serde_json::to_value(ConnectResponse::from(Outcome {
                verdict,
                access: None,
            }))
            .expect("serialize");
            assert_eq!(body["connected"], false, "{}", verdict.code());
            assert_eq!(body["access"], serde_json::Value::Null);
            assert!(
                body["explain"]
                    .as_str()
                    .expect("a sentence")
                    .contains("Nothing was stored"),
                "{}",
                verdict.code()
            );
        }
    }

    /// The request parses the two shapes a setup flow sends, and refuses a path
    /// nobody has a backend for.
    #[test]
    fn the_request_defaults_the_model_and_refuses_an_unknown_path() {
        let api = serde_json::from_str::<ConnectRequest>(r#"{"path":"api_key","api_key":"sk-x"}"#)
            .expect("parses");
        assert_eq!(api.path, ModelPath::ApiKey);
        assert_eq!(api.model, None, "the handler substitutes the default");
        assert_eq!(api.api_key.as_deref(), Some("sk-x"));

        let cli =
            serde_json::from_str::<ConnectRequest>(r#"{"path":"cli","model":"claude-haiku-4-5"}"#)
                .expect("parses");
        assert_eq!(cli.path, ModelPath::Cli);
        assert_eq!(cli.model, Some(ModelId::Haiku45));
        assert!(cli.api_key.is_none());

        assert!(serde_json::from_str::<ConnectRequest>(r#"{"path":"bedrock"}"#).is_err());
        assert!(
            serde_json::from_str::<ConnectRequest>(r#"{"path":"api_key","model":"gpt-5"}"#)
                .is_err()
        );
    }
}
