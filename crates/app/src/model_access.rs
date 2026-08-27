//! Connecting a tenant's own model, proving it, and handing the proof to a turn.
//!
//! `crates/domain/src/model_access.rs` argues why the connection is a tenant
//! resource and not a policy field; `migrations/0041_tenant_model_access.sql`
//! argues the table and `migrations/0050_tenant_model_key.sql` the credential
//! column. This module is the only place any of them meets a network, and it
//! makes five decisions.
//!
//! # 0. The credential is a column on the row it proves
//!
//! `migrations/0050_tenant_model_key.sql` is the argument in full; the part that
//! belongs here is what it changed about this module. Until 0050 the key went to
//! an `agentos_providers::secrets::SecretStore` and the row went to Postgres,
//! and the only `SecretStore` this deployment ever wires is
//! `MemorySecretStore` — a `HashMap` in the server process. So the two halves of
//! a connection had different lifetimes, and every restart produced the state
//! the sentence below promises is unreachable: a row saying "connected" and a
//! credential that was not there. Worse, it produced it *expensively*, because
//! [`connected`] reads the row and `reserve_a_turn` commits before anything
//! looks for the key.
//!
//! Now the sealed credential is `tenant_model_access.sealed_key`, written by the
//! same INSERT as the proof and read by the same SELECT, under AAD
//! `model://<tenant>` — the shape `0040_mcp_credentials` established for MCP
//! bearer tokens and `crates/app/src/mcp.rs`'s [`Credentials`] already
//! implements. This module builds no cipher of its own and stores nothing
//! anywhere else.
//!
//! # 1. Prove first, store second. Never the other way round.
//!
//! [`connect`] runs the verification call **before** the credential is sealed
//! into the row, and writes nothing at all unless the call returned a
//! completion. So a stored key is always a key that answered, and there is no
//! state where the row says "connected" and the credential does not work.
//!
//! Since 0050 that is a property of the schema rather than of this function's
//! ordering: the CHECK constraint makes `path = 'api_key'` and a present
//! `sealed_key` a biconditional, so the half-written state cannot be spelled in
//! SQL at all, by this function or by anything else.
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
use agentos_providers::Secret;
use agentos_providers::llm::{Llm, LlmRequest, Message};
use agentos_providers::llm_anthropic::AnthropicLlm;
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::model_access::Connection;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;

use crate::mcp::{Credentials, McpError};
use crate::mocks::LlmBackend;

/// The encryption context this module's credential is sealed under.
///
/// One tenant, one credential, so the tenant id is the whole of it — the MCP
/// spelling needs a server slug because a tenant has many bindings and
/// `tenant_model_access` has a single-column primary key precisely so it cannot.
///
/// The `model://` scheme is the convention
/// [`LocalEnvelopeSecretStore::seal_in`](agentos_providers::secrets::LocalEnvelopeSecretStore::seal_in)
/// asks every caller to follow — "`context` must be unambiguous across callers
/// or two key spaces collide" — and this is the fourth key space in the
/// workspace, beside `secret://`, `mcp://` and `crate::oauth`'s.
///
/// What the disjointness buys, concretely: the four columns holding these blobs
/// are one `UPDATE … SELECT` apart for anybody who can write the tables, and a
/// tenant's own MCP bearer token landing in `tenant_model_access.sealed_key`
/// would be sent to Anthropic as an API key, on a request they are billed for.
/// The tenant AAD does not stop that one — both blobs belong to the same tenant
/// — so the payload context is the only thing that does.
///
/// `an_mcp_token_moved_into_the_model_column_opens_nothing` is the test, and it
/// fails when this function returns a string any other caller can also produce.
fn model_context(tenant_id: TenantId) -> String {
    format!("model://{tenant_id}")
}

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

    /// The credential could not be sealed, so nothing was written at all —
    /// the row carries the ciphertext, so there is no half of this to fail
    /// separately any more.
    ///
    /// Reachable only through the cipher itself (`secret_encrypt_failed`), which
    /// in practice means the deployment's master key is wrong. Named `Seal`
    /// rather than the `Vault` it was before 0050, because there is no vault on
    /// this path to blame and an operator sent to look for one finds a
    /// `HashMap`.
    #[error("the credential could not be sealed: {0}")]
    Seal(McpError),

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
/// The order is the contract, and it is the same order `provisioning.rs` uses
/// for a phone number: the expensive irreversible thing first, then the record
/// of it.
///
/// 1. **Probe.** Anything but [`Verdict::Connected`] returns here with the key
///    still on the caller's stack, where it is dropped and zeroized.
/// 2. **Seal.** In memory, into an envelope bound to `model://<tenant>`.
///    Nothing is stored by this step, so nothing survives a rollback.
/// 3. **Row, credential and audit line, in the caller's transaction.** One
///    INSERT carries the proof *and* the ciphertext, so they commit together or
///    not at all — this is the sentence `0041` wrote about the vault and could
///    not keep, and the reason 0050 exists.
/// 4. **Requeue.** See below.
///
/// The caller commits. Nothing here does, because the route that calls it has
/// other work in the same transaction and two commits would be two chances to
/// half-succeed.
///
/// # Why connecting a model unsticks the mailbox
///
/// A customer's first inbound mail routinely arrives *before* they finish
/// setting up. `apps/server/src/main.rs` renders [`NoModel`] into a `String` and
/// returns it as a handler failure, which puts a named, human-remediable refusal
/// into the outbox's retry channel: eight attempts, roughly two minutes end to
/// end, and then the row is a dead letter that nothing in this workspace ever
/// claimed again. So the customer who pastes their key ten minutes later has a
/// working deployment and a silently abandoned inbox.
///
/// [`agentos_store::outbox::requeue_dead_letters`] is called here, in the same
/// transaction, so it is atomic with the connection that justifies it — a commit
/// that stores the key and a commit that revives the mail cannot come apart.
/// It runs only on [`Verdict::Connected`]; a refused key has changed nothing and
/// has no business touching a queue.
///
/// **The `?` at `apps/server/src/main.rs`'s `for_turn` call is deliberately left
/// alone.** Turning it into `Ok(())` would reach `mark_done`, which sets
/// `published_at` and clears `last_error` — converting a recoverable, alerting
/// dead letter into an irrecoverable silent success. The failure is correctly
/// recorded; what was missing was any way back.
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    tx: &mut TenantTx<'_>,
    credentials: &Credentials,
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
    // long-lived place and it is the sealed column.
    //
    // **The key is narrowed to the path here, and that is not tidiness.** It is
    // the invariant this module exists for: what gets stored has to be the thing
    // that was proven. A `cli` request that also carried an `api_key` would
    // otherwise be proved against the *host's* model and then have that
    // untouched credential sealed into the row — a stored key nobody tried,
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

    // Sealed here and dropped at the end of this function. The plaintext exists
    // on this stack and in the client that just proved it, and reaches no other
    // owner: `seal_as` borrows the `Secret` and hands back ciphertext, which is
    // what makes "the key never crosses into `apps/server`" a property of the
    // signature rather than four handlers being careful.
    let sealed = key
        .map(|key| credentials.seal_as(tenant_id, &model_context(tenant_id), &key))
        .transpose()
        .map_err(ConnectError::Seal)?;

    let access = ModelAccess {
        path,
        model,
        verified_at: now,
    };
    agentos_store::model_access::save(tx, &access, sealed.as_deref(), now).await?;
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

    // The mail that arrived before the model did. See this function's docs: the
    // count is logged rather than returned, because it is an operational fact
    // about a queue and `Outcome` is an answer about a credential — putting it
    // in the response body would be a number the setup UI has to explain.
    let revived = agentos_store::outbox::requeue_dead_letters(tx, now).await?;
    if revived > 0 {
        tracing::info!(
            tenant_id = %tenant_id.as_uuid(),
            revived,
            "events that had exhausted their attempts before this tenant had a model are \
             deliverable again"
        );
    }

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

    /// The row says [`ModelPath::ApiKey`] and its sealed credential will not
    /// open.
    ///
    /// **Since 0050 this no longer means "a restart lost it".** The ciphertext
    /// is a column on the row, so it is present whenever the row is — the CHECK
    /// constraint makes the pair inseparable. What is left is the genuinely
    /// unrecoverable case the sentence has always described: a deployment whose
    /// `AGENTOS_MASTER_KEY` changed, or a database restored under a different
    /// one. Both are real, both need the same remedy, and neither is fixable by
    /// waiting.
    #[error(
        "this tenant's connection names an API key this deployment can no longer decrypt — its \
         master key has changed since the key was stored. Reconnect: the key has to be pasted \
         again, because we never kept a copy we could show you and cannot recover one"
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
///
/// # It returns the credential too, sealed, and that is the point
///
/// The [`Connection`] this hands back carries the ciphertext alongside the
/// proof. Before 0050 this function returned the proof alone and the caller went
/// looking for the credential later, in a different place, at a different time —
/// which is exactly how a reservation got committed for a key that was not
/// there. Now the two travel together from one `SELECT`, so the only thing
/// between [`connected`] saying yes and [`llm_for`] producing a client is a
/// decryption that cannot fail for want of storage.
///
/// It is still "no credential read": the blob is opaque here. Nothing is
/// decrypted until [`llm_for`], which is what keeps this cheap enough to ask
/// before `turns::reserve`.
pub async fn connected(tx: &mut TenantTx<'_>) -> Result<Connection, NoModel> {
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
/// anything: a credential this deployment can no longer decrypt, and a host
/// whose own model became a key of ours. A missing or forbidden credential must
/// never quietly become somebody else's bill, which is what any fallback here
/// would be.
///
/// **It takes no database handle and no store.** Everything it needs came out of
/// the one row [`connected`] already read, which is what lets the initiative
/// loop roll its read transaction back before the turn starts and still spend
/// the right credential.
pub async fn llm_for(
    tenant_id: TenantId,
    connection: &Connection,
    credentials: &Credentials,
    host: &Arc<dyn Llm>,
    backend: LlmBackend,
    api_base: ApiBase<'_>,
) -> Result<Arc<dyn Llm>, NoModel> {
    match connection.access.path {
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
            // `None` here is a row 0050's CHECK constraint forbids, so reaching
            // this arm means somebody dropped the constraint or restored a
            // database from before it. `KeyMissing` is the right answer to that
            // for the reason it is the right answer to a rotated master key: we
            // cannot produce the credential, and the only remedy is a person
            // pasting it again.
            let sealed = connection
                .sealed_key
                .as_deref()
                .ok_or(NoModel::KeyMissing)?;
            // No audit row per read. The connect is audited once, the turn it
            // pays for is recorded in `model_usage_daily` and `turn_buckets`,
            // and a row per turn saying "we opened the key to do the thing the
            // next row describes" is volume without a question behind it.
            //
            // The cipher's own code is dropped rather than carried: it is
            // `envelope_malformed` or `secret_decrypt_failed`, both of which are
            // facts about a credential, and this error is read by an operator
            // through `last_outcome_detail`. What they need is the remedy.
            let key = credentials
                .open_as(tenant_id, &model_context(tenant_id), sealed)
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
    credentials: &Credentials,
    host: &Arc<dyn Llm>,
    backend: LlmBackend,
    api_base: ApiBase<'_>,
) -> Result<(Arc<dyn Llm>, ModelAccess), NoModel> {
    let tenant_id = tx.tenant_id();
    let connection = connected(tx).await?;
    let llm = llm_for(tenant_id, &connection, credentials, host, backend, api_base).await?;
    // The proof half only. The ciphertext stays inside this function: a caller
    // that wanted it would be a caller building a second client, and there is
    // exactly one place that builds clients.
    Ok((llm, connection.access))
}

#[cfg(test)]
mod tests {
    use agentos_domain::policy::{EffectivePolicy, PolicyLimits, model_for};
    use agentos_providers::llm::{LlmResponse, ScriptedLlm, Usage};
    use agentos_store::db::Db;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    use super::*;

    /// The string this whole module exists to keep out of everything.
    const KEY: &str = "sk-ant-api03-DO-NOT-LEAK-ME-4a9f2c";

    /// What `api.anthropic.com` answers a successful probe with.
    const OK_BODY: &str = r#"{"content":[{"type":"text","text":"h"}],
        "stop_reason":"max_tokens","usage":{"input_tokens":9,"output_tokens":1}}"#;

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

    /// The deployment's cipher, from a master key spelled out here.
    ///
    /// A *text* master key rather than 32 raw bytes, because that is what
    /// `Credentials::from_master_key` takes and what `AGENTOS_MASTER_KEY` is —
    /// and the derivation from one to the other is the thing a second spelling
    /// would get wrong. Tests that want to prove a restart build a second one
    /// from the same string.
    fn cipher() -> Credentials {
        Credentials::from_master_key("test-master-key-for-model-access")
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
    /// no ciphertext to be found later by whoever inherits the box.
    #[tokio::test]
    async fn a_refused_key_is_not_stored_anywhere() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let (origin, _h) = server("401 Unauthorized", "{}").await;
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &cipher(),
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
        assert!(
            agentos_store::model_access::load(&mut tx)
                .await
                .unwrap()
                .is_none()
        );
        let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(audits, 0, "a refusal writes no trail about a credential");

        // And no ciphertext either. Since 0050 the credential has exactly one
        // home, so "nothing was stored" is one COUNT rather than a search of two
        // places that could disagree.
        let blobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tenant_model_access WHERE sealed_key IS NOT NULL",
        )
        .fetch_one(&mut **tx)
        .await
        .expect("count");
        assert_eq!(blobs, 0);
        tx.commit().await.expect("commit");
    }

    /// The founder's rule, at both ends: a host whose model is our key may
    /// neither be connected to nor spent.
    #[tokio::test]
    async fn the_cli_path_is_refused_when_the_hosts_model_is_ours() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let host = host();
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let err = connect(
            &mut tx,
            &cipher(),
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
            &cipher(),
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
        let Err(err) = for_turn(&mut tx, &cipher(), &host, LlmBackend::Anthropic, None).await
        else {
            panic!("must refuse");
        };
        assert!(matches!(err, NoModel::HostModelIsNotTheirs), "{err}");
        assert!(
            for_turn(&mut tx, &cipher(), &host, LlmBackend::Cli, None)
                .await
                .is_ok()
        );
        tx.commit().await.expect("commit");
    }

    /// **What is stored is what was proven, and nothing else.**
    ///
    /// A `cli` connection that also carries a key proves the *host's* model. The
    /// key was never tried, so it must not be sealed into the row — otherwise "a
    /// stored credential is always one that answered" is a sentence in a doc
    /// comment rather than a property.
    #[tokio::test]
    async fn a_cli_connection_does_not_store_a_key_it_never_tried() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let host = host();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &cipher(),
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

        // Two steps, so the failure names the fact rather than printing
        // `unwrap_err() on an Ok value` at whoever broke it.
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let stored = agentos_store::model_access::load(&mut tx)
            .await
            .expect("load")
            .expect("connected");
        assert!(
            stored.sealed_key.is_none(),
            "the row holds a key that was never proven against anything"
        );
        tx.commit().await.expect("commit");
    }

    /// The api_key path with no key never reaches a provider.
    #[tokio::test]
    async fn the_api_key_path_without_a_key_is_not_a_verdict() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let host = host();
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let err = connect(
            &mut tx,
            &cipher(),
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
        let host = host();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let Err(err) = for_turn(&mut tx, &cipher(), &host, LlmBackend::Mock, None).await else {
            panic!("must refuse");
        };
        assert!(matches!(err, NoModel::NotConnected), "{err}");
        // The message names the remedy and does not read like an outage.
        let rendered = err.to_string();
        assert!(rendered.contains("POST /v1/model"), "{rendered}");
        assert!(rendered.contains("retrying will not fix it"), "{rendered}");
        tx.commit().await.expect("commit");
    }

    /// **A key survives a restart, and a rotated master key is the only way it
    /// does not.**
    ///
    /// The regression test for the whole of 0050, and it is two halves of one
    /// story because the second is what proves the first was not vacuous.
    ///
    /// The restart is simulated the only way it honestly can be in-process: a
    /// *second* `Credentials`, built from the same `AGENTOS_MASTER_KEY` text and
    /// sharing nothing with the first — no `Arc`, no map, no cipher. Before this
    /// migration the credential lived in a `HashMap` owned by the connecting
    /// process, so this is precisely the boundary a pod replan crosses, and the
    /// old code failed here with `KeyMissing`.
    ///
    /// Then the same row, read by a deployment whose master key has changed:
    /// still `KeyMissing`, and still not a silent fallback to the host's model,
    /// because a credential we cannot produce must never quietly become somebody
    /// else's bill.
    #[tokio::test]
    async fn a_key_survives_a_restart_and_only_a_rotated_master_key_loses_it() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let host = host();
        let now = Utc::now();
        let (origin, _h) = server("200 OK", OK_BODY).await;

        // The process that served POST /v1/model.
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &cipher(),
            &host,
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
        assert_eq!(outcome.verdict, Verdict::Connected);
        tx.commit().await.expect("commit");

        // The pod is replanned. Nothing of the process above survives except
        // the database and the master key in the environment.
        let after_restart = Credentials::from_master_key("test-master-key-for-model-access");
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let (_llm, access) = for_turn(
            &mut tx,
            &after_restart,
            &host,
            LlmBackend::Mock,
            Some(&origin),
        )
        .await
        .expect("the key outlived the process that stored it");
        assert_eq!(access.path, ModelPath::ApiKey);
        assert_eq!(access.model, ModelId::Opus5);

        // And a deployment whose master key changed cannot open it, which is the
        // one case `KeyMissing` is left describing.
        let rotated = Credentials::from_master_key("a-different-master-key-entirely");
        let Err(err) = for_turn(&mut tx, &rotated, &host, LlmBackend::Mock, Some(&origin)).await
        else {
            panic!("a rotated master key must not open the row");
        };
        assert!(matches!(err, NoModel::KeyMissing), "{err}");
        let rendered = err.to_string();
        assert!(rendered.contains("master key has changed"), "{rendered}");
        assert!(rendered.contains("pasted again"), "{rendered}");
        tx.commit().await.expect("commit");
    }

    /// **A sealed key copied into another tenant's row opens nothing.**
    ///
    /// `0050_tenant_model_key` claims this in prose — "a row lifted into another
    /// tenant's context fails to authenticate rather than decrypting to somebody
    /// else's key" — and a claim about a cipher with no test is a claim about
    /// nothing. The attack is one `UPDATE` by anyone who can already write the
    /// table, and the cheapest wrong design (sealing under a constant context,
    /// or under none) would make it work.
    ///
    /// Written through `admin_tx_bypassing_rls` because RLS is the *other*
    /// defence and this test is about what is left when it is gone. Both AADs
    /// carry the tenant — the data key's wrap and the payload's
    /// `model://<tenant>` — so the theft fails at the first of them.
    #[tokio::test]
    async fn a_sealed_key_does_not_open_in_another_tenants_row() {
        let Some((db, mine)) = fixture().await else {
            return;
        };
        let Some((_, theirs)) = fixture().await else {
            return;
        };
        let host = host();
        let now = Utc::now();
        let (origin, _h) = server("200 OK", OK_BODY).await;

        let mut tx = db.tenant_tx(mine).await.expect("tx");
        connect(
            &mut tx,
            &cipher(),
            &host,
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
        tx.commit().await.expect("commit");

        // The theft: my ciphertext, filed under their tenant id.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query(
            "INSERT INTO tenant_model_access \
               (tenant_id, path, verified_model, verified_at, sealed_key, updated_at) \
             SELECT $1, path, verified_model, verified_at, sealed_key, updated_at \
               FROM tenant_model_access WHERE tenant_id = $2",
        )
        .bind(theirs.as_uuid())
        .bind(mine.as_uuid())
        .execute(&mut *admin)
        .await
        .expect("the row really was copied, or this test proves nothing");
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        let Err(err) = for_turn(&mut tx, &cipher(), &host, LlmBackend::Mock, Some(&origin)).await
        else {
            panic!("a stolen credential opened for the tenant that stole it");
        };
        assert!(matches!(err, NoModel::KeyMissing), "{err}");
        tx.commit().await.expect("commit");

        // …and the rightful owner is unaffected.
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        for_turn(&mut tx, &cipher(), &host, LlmBackend::Mock, Some(&origin))
            .await
            .expect("the owner still opens their own");
        tx.commit().await.expect("commit");
    }

    /// **One tenant's own MCP bearer token is not their model key either.**
    ///
    /// The half the cross-tenant test cannot reach. Both ciphertexts belong to
    /// the same tenant, so the data key's `tenant=<id>` wrap authenticates for
    /// both and only the *payload* context separates them — which is exactly
    /// what [`model_context`] is for and the only thing this test can fail on.
    ///
    /// It matters because the two columns are one `UPDATE … SELECT` apart, and
    /// the consequence of a collision is specific and bad: a customer's MCP
    /// bearer token would be sent to Anthropic as an API key, on a request they
    /// are billed for, in a header they never chose.
    ///
    /// The blob is produced by `Credentials::seal_as` under the same
    /// `mcp://<tenant>/<server>` string `crate::mcp::credential_context` builds,
    /// so the thing being confused is the real encoding and not a stand-in.
    #[tokio::test]
    async fn an_mcp_token_moved_into_the_model_column_opens_nothing() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let host = host();
        let now = Utc::now();

        let credentials = cipher();
        let mcp_blob = credentials
            .seal_as(
                tenant_id,
                &crate::mcp::credential_context(tenant_id, &"github".parse().expect("a slug")),
                &Secret::new("ghp_a_bearer_token_for_an_mcp_server"),
            )
            .expect("seal");

        // Same tenant, right cipher, right master key, wrong context.
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        agentos_store::model_access::save(
            &mut tx,
            &ModelAccess {
                path: ModelPath::ApiKey,
                model: ModelId::Opus5,
                verified_at: now,
            },
            Some(&mcp_blob),
            now,
        )
        .await
        .expect("the row really was written, or this test proves nothing");

        let Err(err) = for_turn(&mut tx, &credentials, &host, LlmBackend::Mock, None).await else {
            panic!("an MCP bearer token was about to be sent to Anthropic as an API key");
        };
        assert!(matches!(err, NoModel::KeyMissing), "{err}");
        tx.rollback().await.expect("rollback");
    }

    /// **Connecting a model gives the tenant's abandoned mail its attempts
    /// back.**
    ///
    /// The downstream half. `apps/server/src/main.rs` renders `NoModel` into a
    /// handler failure, so mail that arrives before setup burns eight attempts
    /// in about two minutes and is then claimed by nothing, ever — there was no
    /// verb in the workspace that wrote `attempt_count = 0`.
    ///
    /// It runs only on a success: a refused key has changed nothing about why
    /// those events failed, and reviving them would be eight more attempts spent
    /// on the same wall.
    ///
    /// **Asserted on the row, not through `claim`.** `outbox::claim` is
    /// cross-tenant by design and libtest runs this binary's tests in parallel,
    /// so a sibling test's poller can lease this event out from under the
    /// assertion — a flake that looks like a bug in the requeue. What `claim`
    /// does with a revived row is proved once, under a lock, in
    /// `agentos_store::outbox`'s own
    /// `a_requeued_dead_letter_is_claimed_again_and_only_the_tenants_own`. What
    /// belongs here is whether `connect` calls it, and on which verdict.
    #[tokio::test]
    async fn connecting_a_model_revives_the_mail_that_arrived_before_it() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let host = host();
        let now = Utc::now();

        // One event, dead exactly the way `NoModel` kills them.
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let id = agentos_store::outbox::enqueue(
            &mut tx,
            &agentos_store::outbox::NewEvent::new("inbound", tenant_id.as_uuid(), "email.received"),
            now,
        )
        .await
        .expect("enqueue");
        sqlx::query("UPDATE outbox_events SET attempt_count = $2 WHERE id = $1")
            .bind(id)
            .bind(agentos_store::outbox::MAX_ATTEMPTS)
            .execute(&mut **tx)
            .await
            .expect("exhaust");
        tx.commit().await.expect("commit");

        async fn attempts(db: &Db, tenant_id: TenantId, id: uuid::Uuid) -> i32 {
            let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
            let n = sqlx::query_scalar("SELECT attempt_count FROM outbox_events WHERE id = $1")
                .bind(id)
                .fetch_one(&mut **tx)
                .await
                .expect("attempt_count");
            tx.commit().await.expect("commit");
            n
        }

        // A refused key changes nothing.
        let (refused, _h) = server("401 Unauthorized", "{}").await;
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &cipher(),
            &host,
            LlmBackend::Mock,
            ModelPath::ApiKey,
            ModelId::Opus5,
            Some(Secret::new(KEY)),
            Some(&refused),
            AuditActor::Operator("founder@example.com".to_owned()),
            now,
        )
        .await
        .expect("connect");
        assert_eq!(outcome.verdict, Verdict::KeyRefused);
        tx.commit().await.expect("commit");
        assert_eq!(
            attempts(&db, tenant_id, id).await,
            agentos_store::outbox::MAX_ATTEMPTS,
            "a refused key must not revive anything"
        );

        // Connecting one does.
        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &cipher(),
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
        tx.commit().await.expect("commit");
        assert_eq!(
            attempts(&db, tenant_id, id).await,
            0,
            "the mail that arrived before the model is deliverable again"
        );
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
        let host = host();
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        let outcome = connect(
            &mut tx,
            &cipher(),
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

        let (_llm, access) = for_turn(&mut tx, &cipher(), &host, LlmBackend::Cli, None)
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
            None,
            now,
        )
        .await
        .expect("save");
        // Connected: it takes a turn.
        for_turn(&mut tx, &cipher(), &host, LlmBackend::Mock, None)
            .await
            .expect("a connected, running company thinks");

        agentos_store::halt::place(&mut tx, "stop everything", "operator:ops", now)
            .await
            .expect("place")
            .expect("it was running");

        let Err(err) = for_turn(&mut tx, &cipher(), &host, LlmBackend::Mock, None).await else {
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
        for_turn(&mut tx, &cipher(), &host, LlmBackend::Mock, None)
            .await
            .expect("released");
        tx.commit().await.expect("commit");
    }
}
