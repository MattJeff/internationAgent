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
//!
//! # The tariff rides on the same POST
//!
//! Three optional body fields — `usd_per_mtok_input`, `usd_per_mtok_output`,
//! `usd_per_mtok_cache_read` — are the rate on the tenant's own Anthropic
//! contract, and `migrations/0079_tenant_model_tariff.sql` is why they live on
//! the connection row. They are stored only after the credential is proven,
//! because every refusal on this route means "nothing was stored" and a rate
//! filed against a key that did not work would be the first exception. A
//! `cli` connection may carry one too: the figure `GET /v1/pnl` derives from it
//! is then labelled `declared_tariff_on_cli_path`, because nobody meters that
//! path against this rate. Absent from the body means untouched; present means
//! replaced, all three at once — see `agentos_store::model_access::set_tariff`.

use std::sync::Arc;

use agentos_app::mcp::Credentials;
use agentos_app::mocks::{Llm, LlmBackend};
use agentos_app::model_access::{self, ConnectError, Outcome};
use agentos_domain::model_access::{ModelAccess, ModelPath};
use agentos_domain::policy::ModelId;
use agentos_store::db::Db;
use agentos_store::model_access::{CostSource, Tariff};
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
    /// The cipher a proven key is sealed with. **Not a store**: since
    /// `0050_tenant_model_key` the credential is a column on the row this
    /// handler writes, so what the route needs is the master key and not
    /// somewhere to put things. The same handle `routes::mcp` uses, so a
    /// deployment cannot end up with two ciphers over one `AGENTOS_MASTER_KEY`.
    credentials: Credentials,
}

/// This unit's routes. Merged into the API router, so auth, the rate limit and
/// the idempotency layer are already in front of it.
pub fn router(db: Db, host: Arc<dyn Llm>, backend: LlmBackend, credentials: Credentials) -> Router {
    Router::new()
        .route("/v1/model", post(connect).get(status))
        .with_state(ModelState {
            db,
            host,
            backend,
            credentials,
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
    /// The tenant's own rate, USD per million tokens, all three optional. Not
    /// `flatten`ed: `Option<Tariff>` under `flatten` would always be `Some`,
    /// and "absent" has to stay distinguishable from "declared nothing".
    #[serde(default)]
    usd_per_mtok_input: Option<f64>,
    #[serde(default)]
    usd_per_mtok_output: Option<f64>,
    #[serde(default)]
    usd_per_mtok_cache_read: Option<f64>,
}

impl ConnectRequest {
    /// The tariff, if the body named any component of one.
    fn tariff(&self) -> Option<Tariff> {
        Tariff {
            usd_per_mtok_input: self.usd_per_mtok_input,
            usd_per_mtok_output: self.usd_per_mtok_output,
            usd_per_mtok_cache_read: self.usd_per_mtok_cache_read,
        }
        .declared()
    }
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

/// What `GET` answers: the proof, the declared rate, and what a cost built
/// from that rate would be called.
///
/// `ModelAccess` flattened rather than nested, so the fields a client read
/// before the tariff existed are where they were.
#[derive(Serialize)]
struct StatusResponse {
    #[serde(flatten)]
    access: ModelAccess,
    /// Null until the tenant declares one.
    tariff: Option<Tariff>,
    cost_source: CostSource,
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
    let tariff = request.tariff();
    if tariff.is_some_and(Tariff::is_malformed) {
        return Err(ApiError::bad_request(
            "usd_per_mtok_*: a rate is a finite number of dollars per million tokens, zero or more",
        ));
    }
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
        &state.credentials,
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

    // Only after the proof, and in the same transaction: a refusal stores
    // nothing, the tariff included. `set_tariff` finds the row `connect` just
    // wrote, so `false` here would be a bug and not a state.
    if let (Some(tariff), true) = (tariff, outcome.verdict.is_connected()) {
        agentos_store::model_access::set_tariff(&mut tx, tariff).await?;
    }
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
///
/// # This 200 is honest again, and it is the schema that made it so
///
/// It still reads only the row and still asks no credential store, exactly as
/// before — but before `0050_tenant_model_key` that meant it answered 200 with a
/// `verified_at` for keys that had evaporated with the last restart, against
/// `agentos_app::model_access`'s stated invariant that no state exists where the
/// row says connected and the credential does not work. The credential is now a
/// column on this very row, so "a row exists" and "the credential exists" are
/// the same observation and there is nothing left for this handler to check.
///
/// `.access` drops the sealed half on the floor. It could not be returned even
/// by accident: `Connection` has no `Serialize`, which is why the type exists
/// rather than a tuple.
async fn status(
    State(state): State<ModelState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let connection = agentos_store::model_access::load(&mut tx).await?;
    tx.commit().await?;

    match connection {
        Some(connection) => Ok(Json(StatusResponse {
            cost_source: CostSource::of(Some(&connection)),
            access: connection.access,
            tariff: connection.tariff,
        })
        .into_response()),
        None => Err(ApiError::not_found().with_detail(
            "no model is connected for this tenant, so none of its employees can take a turn. \
             POST /v1/model with an Anthropic API key, or with this host's claude CLI",
        )),
    }
}

/// The failures that are not verdicts.
///
/// [`ConnectError::Seal`] and [`ConnectError::Unavailable`] are ours and become
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
        ConnectError::Seal(inner) => {
            tracing::error!(
                code = inner.code(),
                "a model credential could not be sealed; check AGENTOS_MASTER_KEY"
            );
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
        assert_eq!(
            cli.tariff(),
            None,
            "no rate named is no tariff, not a zero one"
        );

        // A rate on the CLI path is accepted by the parser; what it is worth is
        // `cost_source`'s business. A component left out is unknown.
        let priced = serde_json::from_str::<ConnectRequest>(
            r#"{"path":"cli","usd_per_mtok_input":3,"usd_per_mtok_output":15}"#,
        )
        .expect("parses");
        let tariff = priced.tariff().expect("declared");
        assert_eq!(tariff.usd_per_mtok_input, Some(3.0));
        assert_eq!(tariff.usd_per_mtok_cache_read, None);
        assert!(!tariff.is_complete());
        assert!(!tariff.is_malformed());
        assert!(
            serde_json::from_str::<ConnectRequest>(r#"{"path":"cli","usd_per_mtok_input":-1}"#)
                .expect("parses")
                .tariff()
                .is_some_and(Tariff::is_malformed)
        );

        assert!(serde_json::from_str::<ConnectRequest>(r#"{"path":"bedrock"}"#).is_err());
        assert!(
            serde_json::from_str::<ConnectRequest>(r#"{"path":"api_key","model":"gpt-5"}"#)
                .is_err()
        );
    }
}
