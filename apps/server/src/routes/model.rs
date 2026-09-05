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
//! # One path this handler used to have, and refuses
//!
//! A `cli` body carrying `oauth_token` — the tenant's pasted `claude
//! setup-token` — is a 400 since 2026-09-06, because Anthropic's terms forbid
//! collecting, storing or intermediating a Claude.ai credential. The whole
//! argument, and the sentence the caller reads, is
//! [`SUBSCRIPTION_TOKEN_REFUSED`]. What stays: `api_key`, and `cli` with no
//! token, which is this host's own session.
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
    /// **Refused since 2026-09-06.** It used to be the tenant's Claude
    /// subscription, as `claude setup-token` prints it, sealed on the row and
    /// handed to the binary per call. See [`SUBSCRIPTION_TOKEN_REFUSED`] for
    /// the licence text that closed it.
    ///
    /// **The field stays**, and that is deliberate: `deny_unknown_fields` on a
    /// console that still sends one produces serde's `unknown field
    /// `oauth_token`` — a sentence naming no remedy, reading like our bug, and
    /// sending a founder to look for a typo. Parsed, then answered with a 400
    /// that says why and what to send instead. It is read by exactly one
    /// function, [`ConnectRequest::intermediates_a_subscription`], and never
    /// reaches a probe, a transaction or a column.
    #[serde(default)]
    oauth_token: Option<String>,
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

/// What a `cli` body carrying `oauth_token` is answered with, in full.
///
/// **The licence closed this path, not a design change.** Anthropic's
/// `code.claude.com/docs/en/legal-and-compliance`, read on 2026-09-06:
/// developers "may not collect, store, or intermediate Claude.ai credentials or
/// session tokens — sign-in to a Claude account must complete through
/// Anthropic's own flow", and customers "may not pay for, resell, or
/// intermediate Claude usage on their end users' behalf. Each end user must
/// authenticate with their own Anthropic API key, Claude subscription plan
/// credentials, or 3P inference provider credential."
///
/// Taking a pasted `claude setup-token`, sealing it into
/// `tenant_model_access.sealed_key` and exporting it as
/// `CLAUDE_CODE_OAUTH_TOKEN` on every call was collecting, storing *and*
/// intermediating — the three verbs, in one feature.
///
/// The detail names both remedies because a founder reading a 400 has to know
/// what to paste next, and because the second one is the answer for a company
/// whose Anthropic access is not a direct account at all.
const SUBSCRIPTION_TOKEN_REFUSED: &str = concat!(
    "`oauth_token` is refused: Anthropic's terms forbid a developer to collect, store or ",
    "intermediate Claude.ai credentials or session tokens, so this deployment cannot run your ",
    "employees on your Claude subscription. Send `path: \"api_key\"` with your own Anthropic API ",
    "key instead — a Bedrock, Vertex or Foundry credential is the other permitted answer — and ",
    "note that `path: \"cli\"` with no token is unaffected: it runs on this host's own session.",
);

impl ConnectRequest {
    /// Does this body ask us to run a tenant's employees on *their* Claude
    /// subscription?
    ///
    /// The `cli` path with a token attached, and nothing else — `api_key` is
    /// the permitted path and a tokenless `cli` is the host's own session.
    /// Blank is not a token: a console that always sends the field would
    /// otherwise be refused for sending nothing, which is the confusing 400
    /// this whole guard exists to avoid.
    fn intermediates_a_subscription(&self) -> bool {
        self.path == ModelPath::Cli
            && self
                .oauth_token
                .as_deref()
                .is_some_and(|token| !token.trim().is_empty())
    }

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
    /// Whether a credential of the tenant's own is sealed on the row: always on
    /// `api_key`, and never on `cli` since the subscription token was refused —
    /// a `cli` row that still says `true` was written before 2026-09-06 and
    /// takes no turn. Never the credential, not even its shape.
    own_credential: bool,
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

    // **First, before the tariff, before the transaction, before any probe.** A
    // credential we may not hold must not reach a database handle, an audit
    // line or a network call — the earliest possible refusal is the only one
    // that can honestly say we never collected it. `agentos_app::model_access`
    // refuses the same thing again for callers that are not this route.
    if request.intermediates_a_subscription() {
        return Err(ApiError::bad_request(SUBSCRIPTION_TOKEN_REFUSED));
    }

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
    // The `cli` path carries no credential any more: the only one it ever
    // carried was a Claude subscription token, refused above. `None` here, and
    // not `request.oauth_token`, so the column stays unwritten on this path
    // whatever a future edit does to the guard.
    let raw = match request.path {
        ModelPath::ApiKey => request.api_key,
        ModelPath::Cli => None,
    };
    let key = raw
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
            own_credential: connection.sealed_key.is_some(),
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
        // Unreachable through this handler — `intermediates_a_subscription`
        // answers first, with a detail written for a founder rather than for a
        // caller of the crate. Mapped anyway, and to the same 400: the day a
        // second route calls `model_access::connect`, the wall is already
        // rendered.
        ConnectError::SubscriptionIsNotOursToHold => ApiError::bad_request(err.to_string()),
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
    use agentos_domain::ids::TenantId;
    use agentos_domain::model_access::Verdict;
    use agentos_store::audit::AuditActor;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    use super::*;

    /// A tenant, a mock model and a cipher — everything [`connect`] needs that
    /// is not the request.
    ///
    /// `None` when there is no database, the same skip every other unit in this
    /// workspace uses. The guard itself is tested without one, on purpose:
    /// a licence wall that only runs where Postgres does is a wall that stops
    /// running the day CI loses its database.
    async fn fixture() -> Option<(ModelState, Principal)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; POST /v1/model needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'model route')")
            .bind(tenant_id.as_uuid())
            .bind(format!("model-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");

        let host: Arc<dyn Llm> = Arc::new(agentos_app::mocks::ScriptedLlm::looping(vec![Ok(
            agentos_app::mocks::LlmResponse::text("h", agentos_app::mocks::Usage::new(9, 1, 0)),
        )]));
        Some((
            ModelState {
                db,
                host,
                // Mock costs nobody anything, so the tokenless cli path is not
                // refused by the founder's rule and the licence wall is the
                // only thing that could stop this request.
                backend: LlmBackend::Mock,
                credentials: Credentials::from_master_key(crate::auth::TEST_MASTER_KEY),
            },
            Principal {
                tenant_id,
                actor: AuditActor::Operator("founder@example.com".to_owned()),
            },
        ))
    }

    fn request(json: &str) -> Result<Json<ConnectRequest>, JsonRejection> {
        Ok(Json(
            serde_json::from_str::<ConnectRequest>(json).expect("parses"),
        ))
    }

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

    /// **A pasted Claude subscription is recognised for what it is, and only
    /// that.**
    ///
    /// Needs no database, because the guard is meant to run before anything
    /// does. The three bodies that must *not* trip it are here beside the one
    /// that must: `api_key` is the permitted path, a tokenless `cli` is the
    /// host's own session, and a blank field is a console being tidy rather
    /// than a credential.
    #[test]
    fn only_a_cli_body_with_a_real_token_is_intermediating_a_subscription() {
        let parse = |json: &str| serde_json::from_str::<ConnectRequest>(json).expect("parses");

        assert!(
            parse(r#"{"path":"cli","oauth_token":"sk-ant-oat01-pasted"}"#)
                .intermediates_a_subscription()
        );
        assert!(!parse(r#"{"path":"cli"}"#).intermediates_a_subscription());
        assert!(!parse(r#"{"path":"cli","oauth_token":"  "}"#).intermediates_a_subscription());
        assert!(
            !parse(r#"{"path":"api_key","api_key":"sk-ant-api03-x"}"#)
                .intermediates_a_subscription(),
            "the api_key path is the remedy, not the offence"
        );

        // The sentence a founder reads has to answer "then what do I paste?".
        assert!(SUBSCRIPTION_TOKEN_REFUSED.contains("api_key"));
        assert!(SUBSCRIPTION_TOKEN_REFUSED.contains("Anthropic API key"));
        assert!(SUBSCRIPTION_TOKEN_REFUSED.contains("Bedrock, Vertex or Foundry"));
    }

    /// The handler answers a `cli` body carrying a token with a 400 that names
    /// the API key — and answers the same body without one exactly as it did
    /// before the wall existed.
    ///
    /// One test for both because the pair is the claim: the licence closed
    /// *one* shape of request, and the deployment that pastes nothing is
    /// untouched. Split into two, a refactor that broke the second half would
    /// still leave the first one green and the product unusable.
    #[tokio::test]
    async fn a_cli_connection_is_refused_with_a_token_and_accepted_without_one() {
        let Some((state, principal)) = fixture().await else {
            return;
        };

        let err = connect(
            State(state.clone()),
            principal.clone(),
            request(r#"{"path":"cli","oauth_token":"sk-ant-oat01-nobody-issued-this"}"#),
        )
        .await
        .expect_err("a subscription token must not be connectable");
        let detail = err.detail().expect("a sentence").to_owned();
        assert!(detail.contains("Anthropic API key"), "{detail}");
        assert!(detail.contains("Bedrock, Vertex or Foundry"), "{detail}");
        assert!(
            !detail.contains("sk-ant-oat01"),
            "the refusal must not echo the credential: {detail}"
        );
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);

        // Nothing was written, which is the half a status code cannot show: the
        // guard returns before the transaction is even opened.
        let mut tx = state.db.tenant_tx(principal.tenant_id).await.expect("tx");
        assert!(
            agentos_store::model_access::load(&mut tx)
                .await
                .expect("load")
                .is_none()
        );
        tx.commit().await.expect("commit");

        // …and the same path with no token connects, on this host's own model,
        // exactly as it did before.
        let response = connect(State(state), principal, request(r#"{"path":"cli"}"#))
            .await
            .expect("the tokenless cli path is untouched");
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(body["connected"], true, "{body}");
        assert_eq!(body["access"]["path"], "cli");
    }
}
