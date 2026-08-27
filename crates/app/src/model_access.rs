//! Connecting a tenant's own model, proving it, and handing the proof to a turn.
//!
//! `crates/domain/src/model_access.rs` argues why the connection is a tenant
//! resource and not a policy field; `migrations/0041_tenant_model_access.sql`
//! argues the table. This module is the only place the two meet a network, and
//! it makes four decisions.
//!
//! # 1. Prove first, store second. Never the other way round.
//!
//! [`connect`] runs the verification call **before** the credential reaches the
//! vault, and writes nothing at all unless the call returned a completion. So a
//! stored key is always a key that answered, and there is no state where the row
//! says "connected" and the credential does not work.
//!
//! The alternative — store, then verify, then mark — buys one thing (the user
//! does not re-paste a key that failed for a transient reason) and costs the
//! guarantee. It also creates the exact failure this feature exists to move off
//! go-live: a credential that looks connected in the setup flow and 400s at the
//! first employee turn a week later.
//!
//! # 2. The proof is a real turn, through the real adapter
//!
//! [`probe`] is one [`Llm::complete`] with `max_tokens: 1`, no system prompt and
//! no tools. Not a `GET /v1/models` — that endpoint is free and it was the
//! obvious cheap answer, and it is the wrong one, because it proves
//! *authentication* and not *inference*. A key on an account with an empty
//! credit balance lists models happily and refuses to complete anything, which
//! is precisely the failure that would then land at go-live. The whole reason
//! verification moved to connect time is that the setup flow is where a person
//! can still fix it.
//!
//! Going through [`Llm`] rather than a bespoke request has a second consequence
//! worth stating: the CLI path is verified by the same function and the same
//! call, so "connected" means the same verb on both paths even though it does
//! not mean the same promise — see [`probe`]'s own docs.
//!
//! **What that call costs, and who pays it.** It is a handful of input tokens
//! and one output token. Against `agentos_eval::cost::rate_card`, on the most
//! expensive model this build can name, that is under two hundredths of a US
//! cent — call it $0.0002 and round up. It is billed to the credential being
//! verified, which is the point rather than a side effect: the first model call
//! this system ever makes on a tenant's behalf is already on the tenant's bill,
//! before a single employee exists. It is also the **only** model call in the
//! whole entry path — `crates/store/src/provisioning.rs` knows three steps,
//! `Email`, `Phone` and `Whatsapp`, none of which is a model, and the first turn
//! is the next one.
//!
//! # 3. A verdict is a closed enum, and a failure stores nothing
//!
//! Every non-success verdict returns the key to the caller's stack to be
//! dropped, writes no row, and appends no audit line. `Verdict::explain` is
//! ours, fixed, and contains none of the provider's own text — a verification
//! response is the one place in this system where a credential and an error body
//! have been in the same function.
//!
//! # 4. The tenant's key is what pays for the tenant's turns
//!
//! [`for_turn`] resolves the row into the [`Llm`] a turn actually runs on:
//! [`ModelPath::ApiKey`] builds an `AnthropicLlm` around the stored credential,
//! [`ModelPath::Cli`] hands back the host's own backend. **No row means no
//! turn** — [`NoModel::NotConnected`], which the two turn sites in `apps/server`
//! render as the same named, non-retryable refusal an empty `allowed_models`
//! already produces.
//!
//! What it deliberately does **not** do is choose the model. That is still
//! `agentos_domain::policy::model_for` over the four intersected layers, and it
//! is unchanged: a tenant who connects a key for Opus under a policy that
//! permits only Haiku runs Haiku. `a_connected_key_cannot_widen_the_allowlist`
//! is what says so.

use std::sync::Arc;

use agentos_domain::ids::TenantId;
use agentos_domain::model_access::{ModelAccess, ModelPath, Verdict};
use agentos_domain::policy::ModelId;
use agentos_providers::llm::{Llm, LlmRequest, Message};
use agentos_providers::llm_anthropic::AnthropicLlm;
use agentos_providers::secrets::SecretStore;
use agentos_providers::{ProviderError, Secret};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{StoreError, TenantTx};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;

use crate::mocks::LlmBackend;

/// The prompt every verification call sends.
///
/// Two ASCII characters and no system prompt, because the cheapest question is
/// the one with the fewest input tokens and there is nothing to learn from the
/// answer — a 200 is the whole finding. It is ours and fixed: nothing a
/// counterparty ever wrote can reach a probe.
const PROBE_PROMPT: &str = "hi";

/// The generated-token ceiling for a verification call. One.
///
/// The response will stop on `max_tokens` and that is fine: the question is
/// whether the provider accepted the request, ran the model and billed the
/// account, and it did all three before deciding to stop.
const PROBE_MAX_TOKENS: u32 = 1;

/// Where the Anthropic API lives for this call.
///
/// `None` is the real one. It is a parameter rather than a constant for one
/// stated reason: **a verification path that cannot be pointed at a listener has
/// no test but a paraphrase of itself.** The alternative — a test that
/// re-implements `connect` against a local server — asserts that the copy is
/// right and says nothing about the function the product runs, which is the one
/// bug this argument is worth avoiding.
///
/// It is not a configuration surface: `apps/server` passes `None` at both call
/// sites and reads no variable for it. A deployment behind an egress proxy is
/// the day this stops being test-only, and that day it wants a named variable in
/// `config.rs` rather than a second meaning for this argument.
pub type ApiBase<'a> = Option<&'a str>;

/// The client one tenant's key is proven and then spent with.
fn client(key: &Secret, api_base: ApiBase<'_>) -> AnthropicLlm {
    // A fresh `Secret` rather than the caller's, so the caller keeps ownership
    // of the one it has to store and this one dies with the client.
    let client = AnthropicLlm::new(Secret::new(key.expose_for_transport()));
    match api_base {
        Some(origin) => client.with_base_url(origin),
        None => client,
    }
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

/// One verification call, reduced to a verdict.
///
/// # What "connected" means on each path, and what it cannot promise
///
/// On [`ModelPath::ApiKey`] it means: this key authenticated, this model was
/// addressable on it, the account could be billed, and a completion came back.
/// That is a strong statement about a moment. It is not a statement about
/// tomorrow — a key can be revoked, a balance can empty, a workspace can lose a
/// model — and nothing here pretends otherwise; the row records *when* it was
/// proven precisely so the claim stays dated.
///
/// On [`ModelPath::Cli`] it means considerably less, and the honest list is
/// short: **a `claude` binary on this host answered a prompt.** It does not mean
///
/// * …that the model that answered is the model asked for. `llm_cli` passes
///   `--model`, and the session, the subscription and the plan can all override
///   it. The adapter's own header records a day when 7 of 7 completed turns came
///   back in French because of a setting on the operator's laptop.
/// * …that tool calls will arrive. The CLI exposes no structured `tool_use`, so
///   `llm_cli::bridge_tool_call` re-inflates JSON out of prose. That shim's own
///   documented measurement is 8 of 23 calls with the wrong argument shape.
/// * …anything about cost. `cache_read_tokens` from that backend is dominated by
///   Claude Code's own system prompt, so `model_usage_daily` records a number
///   that is about the CLI and not about the employee. `0024_model_usage.sql`
///   calls the same thing out as `calls_unmetered`.
/// * …that it will still work in an hour. There is no credential we hold and no
///   session we own; the login belongs to whoever is at the keyboard.
///
/// The repository already states the consequence for measurement, in
/// `agentos_eval::toolchoice`'s `unmeasured` list: *"the production LLM path —
/// llm_cli is a lossy shim with a JSON tool contract, so live scores are the
/// CLI's, not llm_anthropic's"*. A CLI connection is a way to try this product
/// without an API key. It is not the thing the product sells.
///
/// And one weaker still: on a deployment where `AGENTOS_LLM=mock` the host path
/// probes the scripted fake, so "connected" there means *the fake answered*.
/// That is not a hole this function can close — the fake is the deployment's own
/// choice, declared at boot by `LlmBackend::mock_label` and gated behind
/// `AGENTOS_ALLOW_MOCKS=1`, and refusing it here would leave every development
/// box and every end-to-end test unable to take a turn. What it means is that a
/// green verdict is only ever as strong as the thing on the other end of it, and
/// on the one path where that thing is ours, we say so.
pub async fn probe(llm: &dyn Llm, model: ModelId) -> Verdict {
    let request = LlmRequest::new(model.as_str(), "", PROBE_MAX_TOKENS)
        .with_message(Message::user(PROBE_PROMPT));

    match llm.complete(request).await {
        Ok(_) => Verdict::Connected,
        // The code, never the error: `ProviderError::code` is the stable
        // low-cardinality label, and it is deliberately the only thing that
        // crosses from the transport into a verdict a person will read.
        Err(err) => Verdict::from_provider_code(err.code()),
    }
}

// ---------------------------------------------------------------------------
// Connecting
// ---------------------------------------------------------------------------

/// What a connection attempt produced.
///
/// `Serialize`, and safe to be: [`ModelAccess`] holds a path, a model and a
/// timestamp, and there is no credential field to forget to skip. That is why
/// `apps/server` returns this verbatim instead of a hand-written "public view"
/// struct somebody has to keep in sync with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Outcome {
    /// What the one call proved.
    pub verdict: Verdict,
    /// The stored row — present **exactly** when `verdict` is
    /// [`Verdict::Connected`], because nothing is stored on any other verdict.
    pub access: Option<ModelAccess>,
}

/// Why a connection attempt never got as far as a verdict.
///
/// Distinct from [`Verdict`] on purpose: a verdict is a fact about somebody's
/// credential, and these are facts about the request or about us. Rendering them
/// as verdicts would tell a customer their key was refused when their key was
/// never tried.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// [`ModelPath::ApiKey`] with nothing to try.
    #[error("the api_key path needs a key, and none was supplied")]
    NoKey,

    /// [`ModelPath::Cli`] on a deployment whose own model is an API key we pay
    /// for.
    ///
    /// **The founder's rule, enforced rather than documented.** The CLI path
    /// means "spend whatever model this host already has". On a host configured
    /// with `AGENTOS_LLM=anthropic` that is our credential, and a tenant
    /// connected to it would be a tenant whose entire fleet runs on our bill —
    /// which is the one arrangement this product says never happens.
    #[error(
        "this host's model is an API key that is not yours, so the cli path would bill us for \
         your employees. Connect your own key instead"
    )]
    HostModelIsNotYours,

    /// The credential could not be stored. Nothing was written; the row is not
    /// there either, because it is written after this.
    #[error("the credential store refused the key: {0}")]
    Vault(ProviderError),

    /// The row or the audit line could not be written.
    #[error(transparent)]
    Unavailable(#[from] StoreError),
}

/// Connect this tenant's model: prove it, then store it.
///
/// `key` is `Some` for [`ModelPath::ApiKey`] and ignored for
/// [`ModelPath::Cli`]. `host` is the deployment's own backend, used as the
/// thing to probe on the CLI path and never touched on the key path.
///
/// The order of the three writes is the contract, and it is the same order
/// `provisioning.rs` uses for a phone number: the expensive irreversible thing
/// first, then the record of it.
///
/// 1. **Probe.** Anything but [`Verdict::Connected`] returns here with the key
///    still on the caller's stack, where it is dropped and zeroized.
/// 2. **Vault.** The credential is written under a ref derived from the tenant
///    id. If the caller's transaction later rolls back, the worst that survives
///    is an orphan credential nothing points at — which the next attempt
///    overwrites and tenant deletion removes.
/// 3. **Row and audit line, in the caller's transaction.** They commit together
///    or not at all, so the trail cannot claim a connection the table lacks.
///
/// The caller commits. Nothing here does, because the route that calls it has
/// other work in the same transaction and two commits would be two chances to
/// half-succeed.
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    tx: &mut TenantTx<'_>,
    secrets: &dyn SecretStore,
    host: &Arc<dyn Llm>,
    backend: LlmBackend,
    path: ModelPath,
    model: ModelId,
    key: Option<Secret>,
    api_base: ApiBase<'_>,
    actor: AuditActor,
    now: DateTime<Utc>,
) -> Result<Outcome, ConnectError> {
    let tenant_id = tx.tenant_id();

    // Which client does the proving. On the key path it is a client built
    // around the customer's credential *here* and thrown away at the end of this
    // function — the caller never holds one, so the key is in exactly one
    // long-lived place and it is the vault.
    //
    // **The key is narrowed to the path here, and that is not tidiness.** It is
    // the invariant this module exists for: what gets stored has to be the thing
    // that was proven. A `cli` request that also carried an `api_key` would
    // otherwise be proved against the *host's* model and then have that
    // untouched credential written to the vault — a stored key nobody tried,
    // which is exactly the state "prove first, store second" is supposed to make
    // unreachable. One `match`, both jobs, and no path where they can disagree.
    let (verdict, key) = match path {
        ModelPath::ApiKey => {
            let key = key.ok_or(ConnectError::NoKey)?;
            (probe(&client(&key, api_base), model).await, Some(key))
        }
        ModelPath::Cli => {
            if backend.pays_with_our_key() {
                return Err(ConnectError::HostModelIsNotYours);
            }
            // Dropped, whatever the caller sent. The host's model was proven and
            // a credential is not part of that proof.
            (probe(host.as_ref(), model).await, None)
        }
    };

    if !verdict.is_connected() {
        // Nothing stored, nothing audited, and the key goes out of scope with
        // this function. A refused attempt leaves no trace in the tenant's data
        // on purpose: the trace it would leave is a row about a credential.
        tracing::info!(
            tenant_id = %tenant_id.as_uuid(),
            path = %path,
            %model,
            verdict = verdict.code(),
            "model connection refused; nothing stored"
        );
        return Ok(Outcome {
            verdict,
            access: None,
        });
    }

    if let Some(key) = key {
        let secret_ref = ModelAccess::secret_ref(tenant_id).map_err(|_| {
            // Unreachable: `MODEL_SECRET_NAME` is a const that satisfies
            // `SecretRef::new`, and an unreachable arm that unwraps is an
            // unreachable arm that panics one refactor later.
            ConnectError::Vault(ProviderError::Terminal {
                code: "secret_ref_invalid",
            })
        })?;
        secrets
            .put(&secret_ref, &key)
            .await
            .map_err(ConnectError::Vault)?;
    }

    let access = ModelAccess {
        path,
        model,
        verified_at: now,
    };
    agentos_store::model_access::save(tx, &access, now).await?;
    audit::append(
        tx,
        &AuditEvent {
            // The path and the model that was proven. **No credential and
            // nothing derived from one** — not a prefix, not a length, not a
            // hash. A hash of a secret is a secret with an offline attack
            // attached, and the trail has no question that needs one.
            payload: json!({
                "path": path.as_str(),
                "verified_model": model.as_str(),
            }),
            // The caller's own `AuditActor`, not a string it formatted. A
            // rendered label is already `operator:<who>`, so taking one and
            // wrapping it again produced `operator:operator:<who>` in the
            // trail — a real bug this signature makes unrepresentable rather
            // than a convention somebody has to remember at the call site.
            ..AuditEvent::new(actor, AuditKind::ModelConnected, now)
        },
    )
    .await?;

    tracing::info!(
        tenant_id = %tenant_id.as_uuid(),
        path = %path,
        %model,
        "model connected"
    );
    Ok(Outcome {
        verdict,
        access: Some(access),
    })
}

// ---------------------------------------------------------------------------
// Spending it
// ---------------------------------------------------------------------------

/// Why this tenant's employees cannot take a turn.
///
/// Every variant is **terminal**: retrying changes nothing and the remedy is a
/// person doing something. That is the same shape `model_for` returning `None`
/// already has at both turn sites, and it is deliberate — an employee that
/// cannot think must fail with a sentence naming the fix, not with a provider
/// error that reads like an outage and sends somebody to a status page.
#[derive(Debug, thiserror::Error)]
pub enum NoModel {
    /// **The state every tenant is in until somebody connects one.**
    #[error(
        "this tenant has connected no model, so none of its employees can take a turn. \
         Connect one with POST /v1/model — an Anthropic API key, or this host's claude CLI. \
         Nothing about this is a provider failure and retrying will not fix it"
    )]
    NotConnected,

    /// The row says [`ModelPath::Cli`] and this host's own model is a key we
    /// pay for. See [`ConnectError::HostModelIsNotYours`]: the same rule, at the
    /// other end, because a deployment's `AGENTOS_LLM` can change after a tenant
    /// connected.
    #[error(
        "this tenant is connected to this host's model, and this host's model is now an API key \
         that is not theirs. Reconnect with their own key, or point AGENTOS_LLM back at a \
         credential nobody is billed for"
    )]
    HostModelIsNotTheirs,

    /// The row says [`ModelPath::ApiKey`] and the vault has nothing at the
    /// derived ref. A database restored without its secrets, or a master key
    /// that changed.
    #[error(
        "this tenant's connection names an API key the credential store does not have. \
         Reconnect: the key has to be pasted again, because we never kept a copy we could show \
         you and cannot recover one"
    )]
    KeyMissing,

    /// A human has stopped the whole company.
    ///
    /// **In this enum because this enum is the answer to this function's
    /// question**, which its own title states: *may this tenant's employees
    /// take a turn at all*. A halt is one of the two ways the answer is no, and
    /// the other four variants are already reasons that have nothing to do with
    /// the model being broken — `NotConnected` is a company nobody set up, this
    /// is a company somebody stopped.
    ///
    /// Putting it here rather than beside the caller is what buys the property
    /// that matters: [`connected`] is asked *before* `turns::reserve`, so a
    /// halted company loses no turns out of anybody's daily budget. A check
    /// added one line later in the initiative loop would be a check the
    /// message-driven path in `apps/server/src/main.rs` does not have.
    #[error(
        "this company has been stopped by an operator ({0}), so none of its employees will take \
         a turn. Nothing about this is a provider failure and retrying will not fix it — release \
         it with DELETE /v1/halt"
    )]
    CompanyHalted(String),

    /// The connection row could not be read.
    #[error(transparent)]
    Unavailable(#[from] StoreError),
}

/// **May this tenant's employees take a turn at all**, and on what.
///
/// One row by primary key and no credential read, so it is cheap enough to be
/// asked *before* anything irreversible happens — which is the whole reason it
/// is separate from [`llm_for`]. `apps/server`'s initiative loop asks it before
/// it reserves a turn out of the employee's daily budget, exactly as it already
/// asks `model_for` before reserving one: a refusal that costs a turn from a
/// budget of four is a refusal that costs a quarter of the employee's day.
///
/// # The company-wide stop is asked here, and first
///
/// `PolicyGate` already refuses every *effect* while a company is halted, so
/// this read is not what keeps a stopped company off the world — it is what
/// keeps a stopped company off the customer's bill. A turn that reaches the
/// model and is then refused at every tool call still costs Anthropic tokens
/// billed to the tenant's own credential, still sends their data to a third
/// party, and still burns a slot out of `max_turns_per_day` that has no release
/// verb. Asking one row here, before `turns::reserve` and before the credential
/// is even read, is what makes "we stopped" also mean "you stopped paying for
/// it", and what makes the release cost nothing: **no turn is consumed during a
/// halt, so there is nothing to give back and nothing to replay.**
///
/// It is the same row the gate reads, with no cache on either side, so the two
/// answers cannot disagree.
pub async fn connected(tx: &mut TenantTx<'_>) -> Result<ModelAccess, NoModel> {
    if let Some(halt) = agentos_store::halt::halted(tx).await? {
        return Err(NoModel::CompanyHalted(halt.reason));
    }
    agentos_store::model_access::load(tx)
        .await?
        .ok_or(NoModel::NotConnected)
}

/// The model client a turn on this connection runs on.
///
/// **A fresh client per turn, and no cache.** Building an `AnthropicLlm` is a
/// `reqwest::Client::builder().build()`, which is microseconds against a turn
/// measured in seconds, and a cache here would be a map holding every tenant's
/// live credential in process memory for the lifetime of the server, invalidated
/// by nothing. Add one the day a profiler asks, and give it an eviction rule in
/// the same commit.
///
/// Two failures are left after [`connected`] has run, and neither falls back to
/// anything: a credential the vault no longer has, and a host whose own model
/// became a key of ours. A missing or forbidden credential must never quietly
/// become somebody else's bill, which is what any fallback here would be.
pub async fn llm_for(
    tenant_id: TenantId,
    access: ModelAccess,
    secrets: &dyn SecretStore,
    host: &Arc<dyn Llm>,
    backend: LlmBackend,
    api_base: ApiBase<'_>,
) -> Result<Arc<dyn Llm>, NoModel> {
    match access.path {
        ModelPath::Cli => {
            // The founder's rule at the spending end. `connect` refuses this
            // path on a host whose model is a key of ours; `AGENTOS_LLM` can
            // change after a tenant connected, so it is checked again here —
            // once, in the one function that hands out a client, rather than at
            // every call site that wants one.
            if backend.pays_with_our_key() {
                return Err(NoModel::HostModelIsNotTheirs);
            }
            Ok(Arc::clone(host))
        }
        ModelPath::ApiKey => {
            let secret_ref = ModelAccess::secret_ref(tenant_id).map_err(|_| NoModel::KeyMissing)?;
            // Straight to the store rather than through
            // `crate::secrets::SecretResolver`, and the reason is that
            // resolver's own rule: it compares the ref against the acting
            // principal, and this ref's employee segment is the nil uuid, so
            // **no employee can ever resolve it**. That is the property we want
            // — a seat cannot read the company's model key — and it is why this
            // read happens here, above the turn, rather than inside one.
            //
            // No audit row per read. The connect is audited once, the turn it
            // pays for is recorded in `model_usage_daily` and `turn_buckets`,
            // and a row per turn saying "we read the key to do the thing the
            // next row describes" is volume without a question behind it.
            let key = secrets
                .get(&secret_ref)
                .await
                .map_err(|_| NoModel::KeyMissing)?;
            Ok(Arc::new(client(&key, api_base)))
        }
    }
}

/// [`connected`] and then [`llm_for`], for the caller that has a transaction
/// open anyway.
///
/// `apps/server`'s message-driven turn uses this: it is already inside the
/// transaction that reads the policy, so what pays for the turn and what bounds
/// the turn come from one snapshot. The initiative loop cannot — its read
/// transaction is rolled back before the turn starts — so it calls the two
/// halves at the two moments that are right for it.
pub async fn for_turn(
    tx: &mut TenantTx<'_>,
    secrets: &dyn SecretStore,
    host: &Arc<dyn Llm>,
    backend: LlmBackend,
    api_base: ApiBase<'_>,
) -> Result<(Arc<dyn Llm>, ModelAccess), NoModel> {
    let tenant_id = tx.tenant_id();
    let access = connected(tx).await?;
    let llm = llm_for(tenant_id, access, secrets, host, backend, api_base).await?;
    Ok((llm, access))
}

#[cfg(test)]
mod tests {
    use agentos_domain::policy::{EffectivePolicy, PolicyLimits, model_for};
    use agentos_providers::llm::{LlmResponse, ScriptedLlm, Usage};
    use agentos_providers::secrets::{LocalEnvelopeSecretStore, MemorySecretStore};
    use agentos_store::db::Db;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    use super::*;

    /// The string this whole module exists to keep out of everything.
    const KEY: &str = "sk-ant-api03-DO-NOT-LEAK-ME-4a9f2c";

    // -----------------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------------

    /// A one-shot HTTP server, the same twenty lines `llm_anthropic`'s tests
    /// use. No wiremock in this workspace, and a listener beats a dependency.
    async fn server(status: &str, body: &str) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let raw = read_request(&mut sock).await;
            sock.write_all(response.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            raw
        });
        (origin, handle)
    }

    async fn read_request(sock: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = sock.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
            let len: usize = head
                .split("content-length:")
                .nth(1)
                .and_then(|rest| rest.split(['\r', '\n']).next())
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn fixture() -> Option<(Db, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; model_access needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'model access')")
            .bind(tenant_id.as_uuid())
            .bind(format!("mac-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");
        Some((db, tenant_id))
    }

    fn host() -> Arc<dyn Llm> {
        Arc::new(ScriptedLlm::looping(vec![Ok(LlmResponse::text(
            "h",
            Usage::new(9, 1, 0),
        ))]))
    }

    // -----------------------------------------------------------------------
    // The probe
    // -----------------------------------------------------------------------

    /// One call, and it is the cheapest request this workspace can express.
    #[tokio::test]
    async fn the_probe_is_one_call_with_one_output_token_and_no_prompt() {
        let llm = ScriptedLlm::responses(vec![LlmResponse::text("h", Usage::new(9, 1, 0))]);
        assert_eq!(probe(&llm, ModelId::Opus5).await, Verdict::Connected);

        assert_eq!(llm.calls(), 1, "verification is ONE call");
        let sent = &llm.requests()[0];
        assert_eq!(sent.model, "claude-opus-5");
        assert_eq!(sent.max_tokens, 1);
        assert!(sent.system.is_empty(), "no system prompt to pay for");
        assert!(sent.tools.is_empty(), "no tool schemas to pay for");
        assert_eq!(sent.messages.len(), 1);
        assert_eq!(sent.cache_breakpoint, None);
    }

    /// Every failure a person can act on, told apart. These are the three
    /// sentences the setup flow shows.
    #[tokio::test]
    async fn a_refused_key_a_missing_model_and_an_outage_are_three_different_answers() {
        for (status, expected) in [
            ("401 Unauthorized", Verdict::KeyRefused),
            ("403 Forbidden", Verdict::KeyRefused),
            ("404 Not Found", Verdict::ModelNotAccessible),
            ("400 Bad Request", Verdict::Unusable),
            ("529 Overloaded", Verdict::Unreachable),
            ("429 Too Many Requests", Verdict::Unreachable),
        ] {
            let (origin, _h) = server(status, "{}").await;
            let client = AnthropicLlm::new(Secret::new(KEY)).with_base_url(&origin);
            assert_eq!(probe(&client, ModelId::Opus5).await, expected, "{status}");
        }
    }

    // -----------------------------------------------------------------------
    // Connecting
    // -----------------------------------------------------------------------

    /// A key that is refused leaves nothing behind — no row, no audit line, and
    /// nothing in the vault to be found later by whoever inherits the box.
    #[tokio::test]
    async fn a_refused_key_is_not_stored_anywhere() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let (origin, _h) = server("401 Unauthorized", "{}").await;
        let secrets = LocalEnvelopeSecretStore::new([5u8; 32]);
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &secrets,
            &host(),
            LlmBackend::Mock,
            ModelPath::ApiKey,
            ModelId::Opus5,
            Some(Secret::new(KEY)),
            Some(&origin),
            AuditActor::Operator("founder@example.com".to_owned()),
            now,
        )
        .await
        .expect("connect");

        assert_eq!(outcome.verdict, Verdict::KeyRefused);
        assert!(outcome.access.is_none());
        assert_eq!(
            agentos_store::model_access::load(&mut tx).await.unwrap(),
            None
        );
        let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(audits, 0, "a refusal writes no trail about a credential");
        tx.commit().await.expect("commit");

        let secret_ref = ModelAccess::secret_ref(tenant_id).unwrap();
        assert_eq!(
            secrets.get(&secret_ref).await.unwrap_err().code(),
            "secret_not_found"
        );
    }

    /// The founder's rule, at both ends: a host whose model is our key may
    /// neither be connected to nor spent.
    #[tokio::test]
    async fn the_cli_path_is_refused_when_the_hosts_model_is_ours() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let secrets = MemorySecretStore::new();
        let host = host();
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let err = connect(
            &mut tx,
            &secrets,
            &host,
            LlmBackend::Anthropic,
            ModelPath::Cli,
            ModelId::Opus5,
            None,
            None,
            AuditActor::Operator("founder@example.com".to_owned()),
            now,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(err, ConnectError::HostModelIsNotYours), "{err}");

        // The same tenant on a host that is not billing us connects fine…
        let outcome = connect(
            &mut tx,
            &secrets,
            &host,
            LlmBackend::Cli,
            ModelPath::Cli,
            ModelId::Opus5,
            None,
            None,
            AuditActor::Operator("founder@example.com".to_owned()),
            now,
        )
        .await
        .expect("connect");
        assert_eq!(outcome.verdict, Verdict::Connected);

        // …and stops being able to take a turn the moment the host's own model
        // becomes a key somebody else pays for.
        let Err(err) = for_turn(&mut tx, &secrets, &host, LlmBackend::Anthropic, None).await else {
            panic!("must refuse");
        };
        assert!(matches!(err, NoModel::HostModelIsNotTheirs), "{err}");
        assert!(
            for_turn(&mut tx, &secrets, &host, LlmBackend::Cli, None)
                .await
                .is_ok()
        );
        tx.commit().await.expect("commit");
    }

    /// **What is stored is what was proven, and nothing else.**
    ///
    /// A `cli` connection that also carries a key proves the *host's* model. The
    /// key was never tried, so it must not reach the vault — otherwise "a stored
    /// credential is always one that answered" is a sentence in a doc comment
    /// rather than a property.
    #[tokio::test]
    async fn a_cli_connection_does_not_store_a_key_it_never_tried() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let secrets = MemorySecretStore::new();
        let host = host();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &secrets,
            &host,
            LlmBackend::Cli,
            ModelPath::Cli,
            ModelId::Opus5,
            // Never tried: the probe above went to the host, not to this.
            Some(Secret::new("sk-ant-never-tried")),
            None,
            AuditActor::Operator("founder@example.com".to_owned()),
            Utc::now(),
        )
        .await
        .expect("connect");
        assert_eq!(outcome.verdict, Verdict::Connected);
        assert_eq!(outcome.access.expect("stored").path, ModelPath::Cli);
        tx.commit().await.expect("commit");

        let secret_ref = ModelAccess::secret_ref(tenant_id).unwrap();
        // Two steps, so the failure names the fact rather than printing
        // `unwrap_err() on an Ok value` at whoever broke it.
        let found = secrets.get(&secret_ref).await;
        assert!(
            found.is_err(),
            "the vault holds a key that was never proven against anything"
        );
        assert_eq!(found.unwrap_err().code(), "secret_not_found");
    }

    /// The api_key path with no key never reaches a provider.
    #[tokio::test]
    async fn the_api_key_path_without_a_key_is_not_a_verdict() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let secrets = MemorySecretStore::new();
        let host = host();
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let err = connect(
            &mut tx,
            &secrets,
            &host,
            LlmBackend::Mock,
            ModelPath::ApiKey,
            ModelId::Opus5,
            None,
            None,
            AuditActor::Operator("founder@example.com".to_owned()),
            Utc::now(),
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(err, ConnectError::NoKey), "{err}");
        tx.rollback().await.expect("rollback");
    }

    // -----------------------------------------------------------------------
    // Spending it
    // -----------------------------------------------------------------------

    /// **No connection, no turn.** The state every tenant is in after 0041.
    #[tokio::test]
    async fn an_unconnected_tenant_takes_no_turn_at_all() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let secrets = MemorySecretStore::new();
        let host = host();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let Err(err) = for_turn(&mut tx, &secrets, &host, LlmBackend::Mock, None).await else {
            panic!("must refuse");
        };
        assert!(matches!(err, NoModel::NotConnected), "{err}");
        // The message names the remedy and does not read like an outage.
        let rendered = err.to_string();
        assert!(rendered.contains("POST /v1/model"), "{rendered}");
        assert!(rendered.contains("retrying will not fix it"), "{rendered}");
        tx.commit().await.expect("commit");
    }

    /// A row that names a key the vault does not have refuses, and says the one
    /// thing that is true: we cannot show you the key, so paste it again.
    #[tokio::test]
    async fn a_connection_whose_key_is_gone_refuses_rather_than_falling_back() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let secrets = MemorySecretStore::new();
        let host = host();
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        agentos_store::model_access::save(
            &mut tx,
            &ModelAccess {
                path: ModelPath::ApiKey,
                model: ModelId::Opus5,
                verified_at: now,
            },
            now,
        )
        .await
        .expect("save");

        let Err(err) = for_turn(&mut tx, &secrets, &host, LlmBackend::Mock, None).await else {
            panic!("must refuse");
        };
        assert!(matches!(err, NoModel::KeyMissing), "{err}");
        // Not the host's model. A missing credential must never quietly become
        // somebody else's bill.
        tx.commit().await.expect("commit");
    }

    /// **Connecting a key does not widen anything.**
    ///
    /// The tenant proves Fable — the most expensive model this build can name —
    /// and the operator's four layers permit only Haiku. What runs is Haiku, and
    /// when the layers permit nothing, nothing runs.
    #[tokio::test]
    async fn a_connected_key_cannot_widen_the_allowlist() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let secrets = MemorySecretStore::new();
        let host = host();
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &secrets,
            &host,
            LlmBackend::Cli,
            ModelPath::Cli,
            ModelId::Fable5,
            None,
            None,
            AuditActor::Operator("founder@example.com".to_owned()),
            now,
        )
        .await
        .expect("connect");
        assert_eq!(outcome.verdict, Verdict::Connected);

        let (_llm, access) = for_turn(&mut tx, &secrets, &host, LlmBackend::Cli, None)
            .await
            .expect("connected");
        assert_eq!(access.model, ModelId::Fable5);
        tx.commit().await.expect("commit");

        // The operator's word, unchanged by any of the above.
        let haiku_only = PolicyLimits {
            allowed_models: [ModelId::Haiku45].into_iter().collect(),
            ..PolicyLimits::default()
        };
        let policy =
            EffectivePolicy::try_new(&haiku_only, &haiku_only, &haiku_only, &haiku_only).unwrap();
        assert_eq!(
            model_for(Some(&policy), access.model),
            Some(ModelId::Haiku45),
            "a proven model is not a permitted model"
        );

        let nothing = EffectivePolicy::try_new(
            &PolicyLimits::default(),
            &haiku_only,
            &haiku_only,
            &haiku_only,
        )
        .unwrap();
        assert_eq!(
            model_for(Some(&nothing), access.model),
            None,
            "a connected tenant whose policy permits nothing still takes no turn"
        );
    }

    /// **A stopped company thinks about nothing, and is billed for nothing.**
    ///
    /// The tenant is fully connected, so the only thing standing between it and
    /// a model call is the halt. The refusal has to arrive *here*, before
    /// `turns::reserve` — a check one line later would let a stopped company
    /// spend a turn out of a budget that has no release verb, and every minute
    /// of a long halt would cost a day of somebody's initiative.
    #[tokio::test]
    async fn a_stopped_company_takes_no_turn_and_is_billed_for_nothing() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let secrets = MemorySecretStore::new();
        let host = host();
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        agentos_store::model_access::save(
            &mut tx,
            &ModelAccess {
                path: ModelPath::Cli,
                model: ModelId::Opus5,
                verified_at: now,
            },
            now,
        )
        .await
        .expect("save");
        // Connected: it takes a turn.
        for_turn(&mut tx, &secrets, &host, LlmBackend::Mock, None)
            .await
            .expect("a connected, running company thinks");

        agentos_store::halt::place(&mut tx, "stop everything", "operator:ops", now)
            .await
            .expect("place")
            .expect("it was running");

        let Err(err) = for_turn(&mut tx, &secrets, &host, LlmBackend::Mock, None).await else {
            panic!("a stopped company must not be handed a model client");
        };
        assert!(
            matches!(&err, NoModel::CompanyHalted(reason) if reason == "stop everything"),
            "{err}"
        );
        // Named, non-retryable, and it names the remedy — the same shape as
        // every other refusal in this enum, because a poller that read this as
        // an outage would retry a company somebody deliberately stopped.
        let rendered = err.to_string();
        assert!(rendered.contains("DELETE /v1/halt"), "{rendered}");
        assert!(rendered.contains("retrying will not fix it"), "{rendered}");

        // And the release gives it straight back, with nothing to replay.
        agentos_store::halt::release(&mut tx)
            .await
            .expect("release")
            .expect("it was halted");
        for_turn(&mut tx, &secrets, &host, LlmBackend::Mock, None)
            .await
            .expect("released");
        tx.commit().await.expect("commit");
    }
}
