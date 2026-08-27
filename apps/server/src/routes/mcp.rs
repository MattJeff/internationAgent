//! `/v1/mcp`: the operator half of MCP — declaring a server, and the one path
//! by which a declaration becomes a live binding.
//!
//! [`agentos_app::mcp`] has been a complete MCP client for a while: an SSRF
//! check at bind time, one round trip per call, risk classes that only an
//! operator may lower, and a SHA-256 pin on the exact tool a human read. None of
//! it ran, because nothing ever created a binding. `mcp_servers` and
//! `mcp_tool_declarations` existed and could only be written with psql. This
//! module is the door, and the things it has to get right are below.
//!
//! # 0. Every connector is a bound MCP server, and the two that were missing
//!
//! The onboarding step this module serves is one sentence: *the customer arrives
//! with a SaaS, names the tools their company already uses, clicks each one, and
//! it connects.* GitHub, Trello, Discord, Smartlead, their own box — the claim is
//! that all of them are the same thing, an MCP server, and that everything
//! underneath is already built and already guarded.
//!
//! That claim held. What was missing was not a subsystem, it was two things:
//!
//! * **A credential.** Every remote MCP server worth connecting authenticates,
//!   and `McpServer::bind` used `StreamableHttpClientTransport::from_uri`, which
//!   sets `auth_header: None` in so many words. So the whole client could bind
//!   exactly one class of server: the ones that need nothing. `0040_mcp_credentials`
//!   is the column and [`agentos_app::mcp::Credentials`] is the path — a token
//!   taken once, sealed, and never returned by any signature in either crate.
//! * **A catalogue.** [`agentos_app::catalog`] is the list of connectors *we*
//!   wrote down: the URL, whether it needs a token, and the floor under the risk
//!   class a customer may grant its tools. It is a `const`, not a table, which is
//!   argued in its own module docs.
//!
//! Where the claim **stops** is SSH, and it stops hard. A key and a host is a
//! credential for *running programs*, and `agentos_app::mcp`'s module docs spend
//! ninety lines on why this process will not spawn one. The honest shape for a
//! customer's own box is that they run an MCP server on it and give us the URL,
//! which is `catalog::CUSTOM` — a different sentence to the customer than "paste
//! your key", and the only one that is true.
//!
//! [`connect`] is the route that does all of it in one request, and its own doc
//! comment argues why one and not three.
//!
//! # 1. The digest is the operator's, and there is no verb that advances it
//!
//! [`Declaration::digest`](agentos_app::mcp::Declaration::digest) is what makes
//! a granted risk class stick to the tool that was *read* rather than to the
//! name it was read under. A server can redeploy `lookup` with a `callback_url`
//! parameter; if the class travelled with the name, a human's "this is
//! read-only" would silently cover a tool that now exfiltrates on demand.
//!
//! An immutable baseline deletes that attack class. A moving one converts it
//! into a drift-detection problem, which is a thing you have to go looking for.
//! So:
//!
//! * **Nothing here computes a digest and stores it on the operator's behalf.**
//!   [`declare_tool`] takes 64 hex characters from the request body. There is no
//!   "accept current", no `?refresh=true`, no first-write-wins.
//! * **And the digest must be one the server is serving right now.**
//!   [`declare_tool`] binds, finds the tool, and refuses with `digest_mismatch`
//!   unless the bytes match. So the value cannot be invented either: an operator
//!   who has not looked cannot produce it.
//! * **[`discover`] is where they look.** It binds and reports what it found —
//!   every tool, its wire name, the server's own description of it, and the
//!   digest of all three canonicalised together. It writes nothing. Reading it
//!   and then declaring is the whole flow, and it is two requests on purpose:
//!   one that shows, one that decides.
//! * **A `digest_mismatch` does not hand back the correct digest.** It would be
//!   the same two requests with the looking removed, which is the one step this
//!   design exists to force.
//!
//! # 2. Binding is slow and fallible, so it happens in a loop
//!
//! [`McpServer::bind`] resolves DNS, refuses every address that is not globally
//! routable (unless the operator opted the binding into `private`), opens a
//! connection and walks `tools/list`. Seconds, over a network, against an
//! endpoint somebody else operates. That cannot sit on the turn path, and a
//! fleet rebuilt per turn — which is what [`Fleet::bind`]'s own docs flag — pays
//! it on every inbound message.
//!
//! It also cannot sit at boot before the listener: an MCP server that is down
//! would delay or fail a deployment that has nothing else wrong with it.
//!
//! So it belongs where the other slow, fallible, retried work in this binary
//! already lives — a tokio loop next to provisioning, outbox and inbound,
//! cancelled by the same token. [`run`] is that loop, and it wakes on two
//! things:
//!
//! * **A nudge**, sent by every mutation in this module, so an operator's
//!   change is live in this process about as fast as they can refresh the page.
//! * **A tick**, every [`REFRESH`], because a nudge is an in-process channel and
//!   deployments have more than one replica. The replica that did not serve the
//!   `POST` finds out on the tick. It is also the TTL on a cached *risk
//!   classification*, which is the one kind of stale value this whole subsystem
//!   is built to prevent.
//!
//! [`Fleets`] is what the loop writes and what `main` hands to a turn. A server
//! that will not bind is left out of its tenant's [`Fleet`] with the reason
//! recorded — not a panic, not a boot failure, not an empty fleet for the
//! tenant's other servers — and [`list_servers`] renders that reason, because
//! "my tools stopped working" is answered by that string and the operator cannot
//! read the deployment's logs.
//!
//! Two routes here *do* bind inline, and they are the two where that is the
//! point: [`discover`] exists to make the call, and [`declare_tool`] cannot
//! verify a pin without one. Both are an operator's own synchronous admin
//! request under the 30-second request timeout, not the path an inbound email
//! takes.
//!
//! # 3. The tenant comes from the key, and RLS does the rest
//!
//! Every handler opens a [`Db::tenant_tx`] on [`Principal::tenant_id`] and
//! writes no `WHERE tenant_id` of its own — `0013_mcp`'s `tenant_isolation`
//! policies add it, on `USING` and on `WITH CHECK` both.
//! `0019_mcp_operator_writes.sql` is what granted `app_role` the DML to do
//! that; see its header for why the privilege moved out of
//! `admin_tx_bypassing_rls`.
//!
//! Every mutation writes an audit row in the same transaction as the write.
//! These are administrative acts with a real blast radius — binding a URL,
//! granting a risk class — performed by an operator's key, and a change nobody
//! recorded is a change that did not happen.
//!
//! # 4. A credential goes in once and there is no way out
//!
//! The rule is stronger than "no handler returns it", because a rule about what
//! four handlers do is a rule that breaks when a fifth is written. It is enforced
//! in three places, none of which is a handler:
//!
//! * **The type.** `apps/server` never names [`Secret`](agentos_providers::Secret)
//!   and never holds the cipher — it holds an [`agentos_app::mcp::Credentials`],
//!   whose only public operations take a plaintext `String` **in** and hand
//!   ciphertext **out**. There is no signature reachable from this crate that
//!   returns a decrypted credential, so there is nothing here to leak.
//! * **The query.** [`SELECT_SERVERS`] — what the listing reads — does not
//!   project `sealed_token`. It projects `sealed_token IS NOT NULL`. So
//!   [`ServerRow`], which feeds the `Serialize` view, has no field a credential
//!   could occupy, the same construction `store::signing::published_keys` uses
//!   for the private half of a signing key. [`load_binding`] is the one query
//!   that reads the column and it feeds its own non-`Serialize` row type.
//! * **The cipher.** Even the column is not the token: it is an AES-256-GCM
//!   envelope bound by AAD to `(tenant, server)`, so a database dump is not a
//!   credential leak and a row moved one column sideways does not open.
//!
//! What a UI gets instead is `has_credential`. Not `token_last_four`, not a
//! fingerprint: `0040_mcp_credentials` decision 4 argues that a column whose
//! purpose is to be displayed is a column that gets displayed, and a prefix of a
//! credential is a credential.
//!
//! `a_credential_is_taken_once_and_never_comes_back` is the test, and it searches
//! every response, the audit trail, the fleet as it renders, and the raw columns
//! — not a representative sample.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentos_app::catalog::{self, Connector, Credential};
use agentos_app::mcp::{BindFailure, Credentials, Declaration, Fleet, McpServer, Reach, RiskClass};
use agentos_domain::ids::{Slug, TenantId};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::auth::Principal;
use crate::error::ApiError;

/// Largest list any read here will build.
///
/// ponytail: a cap, not a keyset — same call as `routes::teams`. A tenant's MCP
/// servers are typed in by a human and there are tens of them at most. A full
/// page coming back is the signal to paginate.
const MAX_ROWS: i64 = 500;

/// How often every tenant's fleet is rebound from scratch.
///
/// ponytail: a whole-fleet rebind, not a diff. It costs one connect and one
/// `tools/list` per configured server per replica per five minutes, which is
/// nothing next to the alternative — a change feed for a table that changes
/// when a human clicks something. It is also the staleness ceiling: a tool the
/// server silently changed keeps its old classification for at most this long
/// on a replica nobody nudged. Shorten it, or move to LISTEN/NOTIFY, the day a
/// deployment has enough servers for the rebind to show up in a trace.
const REFRESH: Duration = Duration::from_secs(300);

/// How many pending rebinds are queued before a nudge is dropped.
///
/// Dropping is safe: [`REFRESH`] picks it up, and a full queue means the binder
/// is already behind on work that includes this tenant.
const NUDGE_QUEUE: usize = 64;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Every tenant's bound fleet, and the way to ask for a rebind.
///
/// Cheap to clone; clones share one map. The lock is a `std::sync::Mutex` and
/// is never held across an `await` — the slow part (binding) happens outside it
/// and only the finished [`Fleet`] goes in.
#[derive(Clone)]
pub struct Fleets {
    bound: Arc<Mutex<HashMap<TenantId, Arc<Fleet>>>>,
    nudge: mpsc::Sender<TenantId>,
}

impl Fleets {
    /// The registry and the queue [`run`] drains. One pair per process.
    pub fn new() -> (Self, mpsc::Receiver<TenantId>) {
        let (nudge, rebinds) = mpsc::channel(NUDGE_QUEUE);
        (
            Self {
                bound: Arc::new(Mutex::new(HashMap::new())),
                nudge,
            },
            rebinds,
        )
    }

    /// This tenant's bindings, or an empty fleet.
    ///
    /// An empty fleet is the fail-closed answer and the honest one: before the
    /// binder has reached a tenant, and after every one of its servers has
    /// failed to bind, the tenant has no MCP tools. Every call naming one is
    /// refused by [`Fleet`] itself, and nothing is in the system prompt.
    pub fn for_tenant(&self, tenant: TenantId) -> Arc<Fleet> {
        self.bound
            .lock()
            .expect("not poisoned")
            .get(&tenant)
            .map_or_else(|| Arc::new(Fleet::empty()), Arc::clone)
    }

    /// Ask the binder to redo this tenant, soon.
    fn ask_for_rebind(&self, tenant: TenantId) {
        if self.nudge.try_send(tenant).is_err() {
            // Full, or nobody is listening (a test with no binder task). The
            // periodic refresh is the backstop, so this is a latency event, not
            // a correctness one.
            tracing::debug!(%tenant, "mcp rebind nudge dropped; the refresh tick will catch it");
        }
    }
}

/// What the handlers need: the database, the registry to nudge, and the cipher.
#[derive(Clone)]
pub struct McpState {
    db: Db,
    fleets: Fleets,
    /// The deployment's cipher, behind `agentos_app`'s own handle.
    ///
    /// Not an `Arc<LocalEnvelopeSecretStore>`: `apps/server/Cargo.toml` says
    /// `agentos-providers` is deliberately absent from this crate, and a header
    /// is not a reason to delete that. `Credentials` is the `agentos-app` type
    /// that owns the cipher, and its docs argue the second thing it buys — no
    /// plaintext credential crosses this boundary in either direction.
    ///
    /// The same handle the binder loop holds, so a token sealed by a handler is
    /// one the loop can open. Two of these built independently is a deployment
    /// where every credential seals and none of them opens.
    credentials: Credentials,
}

impl McpState {
    /// Wire the routes to the pool, the registry `main` also gives the loop,
    /// and the cipher it also gives the loop.
    pub const fn new(db: Db, fleets: Fleets, credentials: Credentials) -> Self {
        Self {
            db,
            fleets,
            credentials,
        }
    }
}

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before any handler here.
pub fn router(state: McpState) -> Router {
    Router::new()
        // The catalogue, so a UI can render buttons instead of a URL field. A
        // `GET` with no tenant in it: the entries are the same for everyone
        // because they are a `const` in this binary.
        .route("/v1/mcp/catalog", axum::routing::get(catalog))
        // The five-minute path. See its doc comment for why it is one request
        // and not three.
        .route("/v1/mcp/connect", post(connect))
        .route("/v1/mcp/servers", post(declare_server).get(list_servers))
        .route(
            "/v1/mcp/servers/{server}",
            axum::routing::delete(delete_server),
        )
        .route("/v1/mcp/servers/{server}/discover", post(discover))
        .route("/v1/mcp/servers/{server}/tools/{tool}", put(declare_tool))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// `deny_unknown_fields` throughout: on this surface a misspelled field is
/// usually the one that would have tightened something.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclareServer {
    /// The handle an `Action::McpCall` will name this server by. A `Slug`.
    server: String,
    /// Where it lives. `http` or `https`, with a host.
    url: String,
    /// `public` (the default) or `private`. `private` additionally permits
    /// loopback and RFC 1918 space, for a sidecar; it never permits link-local,
    /// which is where every cloud's credential endpoint is.
    #[serde(default)]
    reach: Option<String>,
    /// The bearer token this binding sends, if it needs one.
    ///
    /// Taken once and sealed. Nothing reads it back — see [`connect`] for the
    /// whole argument and `0040_mcp_credentials` for the storage.
    ///
    /// It is accepted *here*, on the route that contacts nothing, because this
    /// is the door for a server that is not up yet: refusing the token here
    /// would mean the only way to configure a credentialled server is [`connect`],
    /// which requires the server to answer. A customer bringing one up would
    /// have nowhere to put it.
    #[serde(default)]
    token: Option<String>,
}

/// One tool, as the operator vets it.
///
/// Both fields are required, and `digest` deliberately has no `Option`. The
/// nullable column exists so a tenant written by hand before this route can be
/// migrated one tool at a time; the HTTP surface does not offer the unpinned
/// path, because a class granted to a name alone is the weakness the pin
/// replaces.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclareTool {
    /// `read`, `write` or `destructive`.
    risk: String,
    /// 64 lowercase hex characters, from [`discover`].
    digest: String,
}

/// One `mcp_servers` row joined to one of its declarations, **for the listing**.
///
/// `has_credential` is a boolean the database computed, not the column: there is
/// no field here a credential could be in. See [`SELECT_SERVERS`].
#[derive(Debug, FromRow)]
struct ServerRow {
    server: String,
    url: String,
    reach: String,
    connector: String,
    created_at: DateTime<Utc>,
    has_credential: bool,
    tool: Option<String>,
    risk: Option<String>,
    digest: Option<Vec<u8>>,
}

/// The same join **for binding**, which is the only thing that needs the sealed
/// credential.
///
/// A second row type rather than an `Option` on the first one, deliberately.
/// [`ServerRow`] feeds a `Serialize` view; this one feeds `McpServer::bind` and
/// nothing else. One type carrying both jobs is one `derive(Serialize)` away
/// from putting the credential in a response, and the compiler would not object.
///
/// No `Debug`: `tracing::debug!(?row)` is one keystroke.
#[derive(FromRow)]
struct BindingRow {
    url: String,
    reach: String,
    connector: String,
    sealed_token: Option<Vec<u8>>,
    tool: Option<String>,
    risk: Option<String>,
    digest: Option<Vec<u8>>,
}

/// One declared tool, as stored.
#[derive(Debug, Serialize)]
struct DeclarationView {
    tool: String,
    risk: String,
    /// `null` only for a row written before this route existed.
    digest: Option<String>,
}

/// One configured server, its declarations, and whether it is actually bound.
#[derive(Debug, Serialize)]
struct ServerView {
    server: String,
    url: String,
    reach: String,
    /// Which catalogue entry it came from, as stored. `custom` for anything
    /// declared through [`declare_server`] or written before 0040.
    connector: String,
    /// Whether a credential is stored — **not** any part of one.
    ///
    /// This is the whole of what a UI is owed: a "Connected / needs a token"
    /// badge and a "replace" button. There is no `token_last_four` here and
    /// `0040_mcp_credentials` decision 4 is why: a prefix of a credential is a
    /// credential, and a column that exists to be shown is a column that gets
    /// shown.
    has_credential: bool,
    created_at: DateTime<Utc>,
    /// `bound`, `failed`, or `pending`.
    ///
    /// `pending` is not a synonym for `failed`: it means this replica's binder
    /// has not reached the tenant yet, which is a normal state for the first
    /// seconds after a declaration and an abnormal one after that.
    status: &'static str,
    /// Why it is not bound. `null` unless `status` is `failed`.
    error: Option<Value>,
    tools: Vec<DeclarationView>,
}

/// One tool as the server is serving it, for a human to read before declaring.
///
/// # Every string in here was written by a stranger
///
/// `wire_name` and `description` come off the wire from a server we do not
/// operate, and they are the point of the endpoint: they are what the customer
/// reads instead of typing. The containment is that this is the **only** exit,
/// and it exits into an operator's JSON response:
///
/// * `BoundTool::description` is an `Untrusted<String>` in `app::mcp`, so
///   reaching the text at all needs `expose_for_parsing`, which greps.
/// * `Fleet::inventory` — the one path into a system prompt — hands the model
///   `McpTool` handles and a `Risk`, never a description, and only for tools an
///   operator has already declared. `app::mcp`'s module docs argue that at
///   length and `crates/app/src/prompt.rs` is what enforces it.
/// * So a hostile `description` can lie to a *human* about what a tool does,
///   which is a real attack and the reason `digest` is beside it: the class the
///   human grants is pinned to the exact bytes they were shown, including the
///   description, and a server that changes its story afterwards loses the
///   grant.
///
/// What is deliberately NOT done: sanitising, truncating or stripping this text.
/// A filter that made a hostile description *look* safe would be worse than
/// none, because the reader would trust the output of the filter. It is rendered
/// as data, in a JSON string, to a person.
#[derive(Debug, Serialize)]
struct DiscoveredTool {
    /// The policy handle — what goes in the path of [`declare_tool`], and what
    /// an allowlist entry spells.
    tool: String,
    /// The server's own spelling, which is what goes on the wire.
    wire_name: String,
    /// **What to copy into a declaration.** SHA-256 over the name, the
    /// description and the input schema, canonicalised.
    digest: String,
    /// What this tool would be classed at right now: the operator's declaration
    /// if it still matches, raised by anything worse the server admits to, and
    /// `destructive` for anything undeclared.
    risk: &'static str,
    /// Whether an operator has already written this tool's name down.
    declared: bool,
    /// The lowest class this tool may be declared at, from the connector's
    /// catalogue entry.
    ///
    /// Here so a UI can grey out the options it must not offer, rather than
    /// letting a customer pick one and be refused. It is a *hint about* the
    /// enforcement in [`declare_tool`], never the enforcement: a client that
    /// ignores this field still gets a 422.
    floor: &'static str,
    /// The server's own one-liner. **A stranger wrote this**, which is exactly
    /// why it is here: it is half of what the human is deciding on, and it is
    /// rendered to an operator reading a JSON response, never to a model.
    description: Option<String>,
}

/// Every tool on a bound server, as a human should be shown it.
///
/// One function because three routes need the same list and a fourth will: the
/// containment argument on [`DiscoveredTool`] is only true for as long as there
/// is one place that builds one.
fn discovered(bound: &McpServer, connector: &'static Connector) -> Vec<DiscoveredTool> {
    bound
        .tools()
        .iter()
        .map(|(tool, found)| DiscoveredTool {
            tool: tool.as_str().to_owned(),
            wire_name: found.wire_name().to_owned(),
            digest: to_hex(found.digest()),
            risk: found.risk().code(),
            declared: found.is_declared(),
            floor: connector.floor.code(),
            // The one place a server's own prose leaves `Untrusted`, and it
            // leaves it into a JSON field an operator reads. It never reaches a
            // system prompt: `Fleet::inventory` hands the model names only.
            description: found
                .description()
                .map(|text| text.expose_for_parsing().clone()),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

/// `POST /v1/mcp/servers` — record a server. Nothing is contacted.
///
/// 201, and the binding is not live yet: the loop picks it up on the nudge this
/// sends. That is deliberate — an endpoint that is down must not make declaring
/// it fail, or an operator cannot configure a system they are in the middle of
/// bringing up. [`discover`] is how they check it actually works.
///
/// The URL is scheme-checked here so `file:///etc/passwd` is a 400 in the
/// operator's face rather than a warning in a log. The *address* check is not
/// here: it costs a DNS lookup and it belongs at the connection, where a host
/// that re-resolves is caught every time rather than once.
async fn declare_server(
    State(state): State<McpState>,
    principal: Principal,
    body: Result<Json<DeclareServer>, JsonRejection>,
) -> Result<Response, ApiError> {
    // `err.body_text()` names the field that failed and serde's reason for it,
    // never the value — and `deny_unknown_fields` echoes a *key*. Proven, not
    // assumed: `a_malformed_body_never_echoes_the_token_back`.
    let Json(mut body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let server =
        Slug::parse(&body.server).map_err(|err| ApiError::bad_request(format!("server: {err}")))?;
    agentos_app::mcp::vet_url(&body.url)
        .map_err(|_| ApiError::bad_request("url: must be an http(s) url with a host"))?;
    let reach = match body.reach.as_deref() {
        None => Reach::default(),
        Some(raw) => Reach::parse(raw)
            .ok_or_else(|| ApiError::bad_request("reach: expected \"public\" or \"private\""))?,
    };

    // Sealed before the transaction opens, so a cipher failure is a 500 with
    // nothing written rather than a rollback. `body.token` is moved out here and
    // is not read again — the `String` in the request body is the last copy of
    // the plaintext this handler has, and it dies with the body.
    let sealed = seal_token(
        &state.credentials,
        principal.tenant_id,
        &server,
        body.token.take(),
    )?;

    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    // No `WHERE tenant_id` and no `tenant_id` guesswork: the column is bound
    // from the transaction's own tenant, and RLS's WITH CHECK refuses anything
    // else. A duplicate handle trips the primary key, which `error.rs` renders
    // as a 409.
    sqlx::query(
        "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector, sealed_token) \
         VALUES ($1, $2, $3, $4, 'custom', $5)",
    )
    .bind(principal.tenant_id.as_uuid())
    .bind(server.as_str())
    .bind(&body.url)
    .bind(reach.code())
    .bind(sealed.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(StoreError::from)?;

    record(
        &mut tx,
        &principal.actor,
        json!({
            "event": "mcp.server.declared",
            "server": server.as_str(),
            "url": body.url,
            "reach": reach.code(),
            // Whether, never what. The trail's job here is to answer "when did
            // this binding acquire a credential, and who gave it one".
            "credential": sealed.is_some(),
        }),
        now,
    )
    .await?;
    tx.commit().await?;

    state.fleets.ask_for_rebind(principal.tenant_id);
    tracing::info!(
        tenant_id = %principal.tenant_id,
        server = server.as_str(),
        reach = reach.code(),
        credential = sealed.is_some(),
        "mcp server declared"
    );

    Ok((
        StatusCode::CREATED,
        Json(ServerView {
            server: server.as_str().to_owned(),
            url: body.url,
            reach: reach.code().to_owned(),
            connector: catalog::CUSTOM.key.to_owned(),
            has_credential: sealed.is_some(),
            created_at: now,
            status: "pending",
            error: None,
            tools: Vec::new(),
        }),
    )
        .into_response())
}

/// Seal a credential for storage, or `Ok(None)` when there is none.
///
/// A thin wrapper over [`Credentials::seal`] that turns the cipher's own failure
/// into a 500. It is separate only because two handlers want the same mapping,
/// and it takes the plaintext `String` **by value** so this crate holds no copy
/// after the call: the buffer the request body allocated is moved into the
/// `SecretString` that zeroizes it.
fn seal_token(
    credentials: &Credentials,
    tenant_id: TenantId,
    server: &Slug,
    token: Option<String>,
) -> Result<Option<Vec<u8>>, ApiError> {
    credentials.seal(tenant_id, server, token).map_err(|err| {
        // The cipher's code, and nothing about the value. A seal that fails is a
        // deployment problem — a master key of the wrong length — and the
        // operator needs to know which, not what was being sealed.
        tracing::error!(code = err.code(), "could not seal an mcp credential");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            err.code(),
            "the credential could not be stored",
        )
    })
}

/// `GET /v1/mcp/servers` — what is configured, what is declared on it, and
/// whether it is actually working.
///
/// The last part is the reason this is not a plain `SELECT`: a server that
/// fails the address check is dropped from the fleet on purpose, so that one
/// bad row cannot stop an employee answering its email — and a drop that is
/// only visible in a log line is invisible.
async fn list_servers(
    State(state): State<McpState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows: Vec<ServerRow> = sqlx::query_as(SELECT_SERVERS)
        .bind(MAX_ROWS)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.rollback().await?;

    let fleet = state.fleets.for_tenant(principal.tenant_id);
    let mut servers: Vec<ServerView> = Vec::new();
    for row in rows {
        // The LEFT JOIN repeats the server once per declaration; the query is
        // ordered by server, so a run of equal handles is one server.
        if servers.last().is_none_or(|last| last.server != row.server) {
            let (status, error) = match Slug::parse(&row.server) {
                Ok(handle) => bind_status(&fleet, &handle),
                // Unreachable while `Slug` is what the route parses on the way
                // in, but a row written by hand is not this route's promise.
                Err(_) => ("failed", Some(json!({"code": "no_policy_handle"}))),
            };
            servers.push(ServerView {
                server: row.server.clone(),
                url: row.url.clone(),
                reach: row.reach.clone(),
                connector: row.connector.clone(),
                has_credential: row.has_credential,
                created_at: row.created_at,
                status,
                error,
                tools: Vec::new(),
            });
        }
        if let Some(view) = declaration_view(&row)
            && let Some(last) = servers.last_mut()
        {
            last.tools.push(view);
        }
    }

    Ok(Json(json!({ "servers": servers })).into_response())
}

/// `DELETE /v1/mcp/servers/{server}` — stop binding it.
///
/// 204, and the declarations go with it: `mcp_tool_declarations_server_fk` is
/// `on delete cascade`. That is the intended shape — a class granted to a tool
/// on a server that is no longer configured is a grant with nothing to apply
/// to, and leaving the rows would silently re-arm every one of them if the same
/// handle were declared again against a different URL.
async fn delete_server(
    State(state): State<McpState>,
    principal: Principal,
    Path(server): Path<String>,
) -> Result<Response, ApiError> {
    let server = handle(&server)?;

    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let deleted = sqlx::query("DELETE FROM mcp_servers WHERE server = $1")
        .bind(server.as_str())
        .execute(&mut **tx)
        .await
        .map_err(StoreError::from)?
        .rows_affected();
    if deleted == 0 {
        // Another tenant's server is invisible under RLS, so this is a 404 for
        // "does not exist" and for "is not yours" alike — deliberately
        // indistinguishable.
        tx.rollback().await?;
        return Err(ApiError::not_found());
    }
    record(
        &mut tx,
        &principal.actor,
        json!({ "event": "mcp.server.deleted", "server": server.as_str() }),
        now,
    )
    .await?;
    tx.commit().await?;

    state.fleets.ask_for_rebind(principal.tenant_id);
    tracing::info!(
        tenant_id = %principal.tenant_id,
        server = server.as_str(),
        "mcp server deleted"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// The catalogue, and the one-request connect it feeds
// ---------------------------------------------------------------------------

/// `GET /v1/mcp/catalog` — the connectors a customer can click.
///
/// No tenant in the answer and none in the question: the catalogue is a `const`
/// in this binary, identical for everybody. It is behind the API stack anyway
/// because everything under `/v1` is, and an unauthenticated route is a second
/// auth surface to reason about for no gain.
///
/// `url` is deliberately included. It is not a secret — it is a vendor's
/// published endpoint — and showing it is how a customer verifies they are about
/// to hand a token to GitHub rather than to us guessing.
async fn catalog(_principal: Principal) -> Result<Response, ApiError> {
    let connectors: Vec<Value> = catalog::CATALOG
        .iter()
        .map(|c| {
            json!({
                "connector": c.key,
                "label": c.label,
                // `null` means "you supply it" — the `custom` case, and the only
                // one where the connect body's `url` is read.
                "url": c.url,
                "reach": c.reach.code(),
                "credential": c.credential.code(),
                "floor": c.floor.code(),
            })
        })
        .collect();
    Ok(Json(json!({ "connectors": connectors })).into_response())
}

/// What connecting a catalogue entry takes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connect {
    /// A key from [`catalog`]. Unknown is a 404 and never a fallback to
    /// `custom`, which would turn a typo into "bind whatever URL was in the
    /// body".
    connector: String,
    /// The handle this binding is named by, and the one an allowlist entry and
    /// an `Action::McpCall` will spell.
    server: String,
    /// The credential, when the entry asks for one. Sealed and never returned.
    #[serde(default)]
    token: Option<String>,
    /// The endpoint — **only** for `custom`, whose catalogue entry has no URL.
    /// Sending one for a named connector is a 400: silently ignoring it would
    /// let a caller believe they had pointed GitHub's entry somewhere else.
    #[serde(default)]
    url: Option<String>,
    /// `public` or `private`, **only** for `custom`. A named connector's reach
    /// is ours to state.
    #[serde(default)]
    reach: Option<String>,
}

/// `POST /v1/mcp/connect` — "your company is connected", and it means it.
///
/// This is the five-minute path, and it is one request because the alternative
/// is not.
///
/// # Why not `POST /servers` then `POST /discover`
///
/// Those two exist and they stay: the first records a binding without contacting
/// anything, which is what a customer *bringing a server up* needs. But run in
/// sequence they are a bad onboarding step, and specifically the failure between
/// them is bad: the server row is written, the discover fails, and the customer
/// is left with a binding that is configured, listed, retried by the loop
/// forever, and does nothing. "Connected" then means "we stored what you typed",
/// which is the meaning that makes a customer stop reading the word.
///
/// So: **a connection is validated only if it was tried.** One round trip, made
/// before anything is written, and it is the same round trip the binder loop
/// will make — same `McpServer::bind`, same DNS lookup, same address check, same
/// `tools/list`. Nothing here is a simulation of the real path.
///
/// # What happens when it half-works
///
/// The interesting failure is the token that authenticates and exposes nothing:
/// a PAT with no scopes, an account with no seats. The server binds. `tools/list`
/// returns `[]`. Every mechanism downstream says success.
///
/// **That is a 502 and nothing is written.** The argument is that the customer
/// clicked this to gain a capability, and a binding with no tools is not a
/// partial capability, it is none: `Fleet::inventory` will contribute nothing to
/// any prompt, every `McpCall` naming it is refused as `unknown_tool`, and the
/// only observable difference from never having connected is a row in a list.
/// Reporting success there teaches the customer that the green tick is
/// decorative, and they will find out three days later when an employee is
/// denied — which is the expensive moment to discover a scope was missing.
///
/// The case against, honestly: a server that legitimately exposes zero tools
/// today and more tomorrow now cannot be connected at all, and the customer has
/// to use [`declare_server`]. That door is open, it is one route over, and it is
/// the right home for "I know it is not ready" — which is why this one can
/// afford to be strict. If a real customer hits it, the fix is a `force` flag on
/// this route, not a softer definition of connected.
///
/// # Rotation
///
/// `ON CONFLICT DO UPDATE`. Connecting the same handle again replaces the URL
/// and the credential, and it is the only way to replace a credential — which is
/// correct, because it is also the only way that *proves the new one works
/// before the old one is destroyed*. The declarations survive by primary key. If
/// the URL moved, their digests will not match what the new endpoint serves and
/// `app::mcp::inventory` demotes every one of them to destructive, which is the
/// fail-closed direction and needs no code here.
async fn connect(
    State(state): State<McpState>,
    principal: Principal,
    body: Result<Json<Connect>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(mut body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let server = handle(&body.server)?;
    let connector = catalog::find(&body.connector).ok_or_else(ApiError::not_found)?;

    // The URL and the reach come from the catalogue for everything we named, and
    // from the request only for `custom`. This is most of what the catalogue is
    // worth: a customer who cannot mistype GitHub's host cannot be walked into
    // binding one that looks like it.
    let (url, reach) = match connector.url {
        Some(url) => {
            if body.url.is_some() || body.reach.is_some() {
                return Err(ApiError::bad_request(format!(
                    "url and reach are not yours to set for the {:?} connector",
                    connector.key
                )));
            }
            (url.to_owned(), connector.reach)
        }
        None => {
            let url = body
                .url
                .take()
                .ok_or_else(|| ApiError::bad_request("url: required for this connector"))?;
            agentos_app::mcp::vet_url(&url)
                .map_err(|_| ApiError::bad_request("url: must be an http(s) url with a host"))?;
            let reach = match body.reach.as_deref() {
                // The tight one by default, here as everywhere: an operator who
                // wants loopback says so.
                None => Reach::default(),
                Some(raw) => Reach::parse(raw).ok_or_else(|| {
                    ApiError::bad_request("reach: expected \"public\" or \"private\"")
                })?,
            };
            // ponytail: unreachable while `custom` is the only entry with no
            // URL, because its own reach is `private`. Kept rather than deleted
            // because it is the invariant, not the branch: `Connector::reach` is
            // a *ceiling*, and the day a second entry takes a customer-supplied
            // URL with `reach: Public`, this is the line that stops loopback.
            // Deleting it now means noticing then.
            if reach == Reach::Private && connector.reach != Reach::Private {
                return Err(ApiError::bad_request(
                    "reach: this connector may not reach private address space",
                ));
            }
            (url, reach)
        }
    };

    // The catalogue says what this connector takes, and both mismatches are a
    // 400 rather than a shrug: a token silently dropped is a customer who
    // believes they authenticated, and a missing one is a 401 from a stranger's
    // server that we could have predicted.
    //
    // Sealed here, before anything is contacted, and for a reason that is not
    // ordering hygiene: `Credentials::bind` takes the **sealed** form, so the
    // round trip below runs on exactly the bytes `Fleet::bind` will read from
    // the column five minutes from now. A seal that cannot be opened therefore
    // fails in front of the customer who is watching, rather than silently after
    // they were told "connected".
    let sealed = seal_token(
        &state.credentials,
        principal.tenant_id,
        &server,
        body.token.take(),
    )?;
    match (connector.credential, sealed.is_some()) {
        (Credential::None, true) => {
            return Err(ApiError::bad_request(
                "token: this connector takes no credential",
            ));
        }
        (Credential::Bearer, false) => {
            return Err(ApiError::bad_request("token: required for this connector"));
        }
        _ => {}
    }

    // --- the round trip that decides whether this is a connection ----------
    //
    // Before the write, deliberately. Everything below this point is either a
    // failure with nothing stored or a binding that was observed working.
    let bound = state
        .credentials
        .bind(
            principal.tenant_id,
            server.clone(),
            &url,
            &std::collections::BTreeMap::new(),
            reach,
            sealed.as_deref(),
            CancellationToken::new(),
        )
        .await
        .map_err(bind_failed(&server))?;
    let tools = discovered(&bound, connector);
    let addresses: Vec<String> = bound
        .pinned_addresses()
        .iter()
        .map(ToString::to_string)
        .collect();
    let _ = bound.close().await;

    if tools.is_empty() {
        tracing::warn!(
            tenant_id = %principal.tenant_id,
            server = server.as_str(),
            connector = connector.key,
            "mcp connect reached a server that exposes no tools; nothing was stored"
        );
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "no_tools_exposed",
            "the server answered but offers no tools; the credential may lack scopes",
        ));
    }

    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    sqlx::query(
        "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector, sealed_token) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (tenant_id, server) DO UPDATE \
           SET url = excluded.url, reach = excluded.reach, \
               connector = excluded.connector, sealed_token = excluded.sealed_token, \
               updated_at = now()",
    )
    .bind(principal.tenant_id.as_uuid())
    .bind(server.as_str())
    .bind(&url)
    .bind(reach.code())
    .bind(connector.key)
    .bind(sealed.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(StoreError::from)?;

    record(
        &mut tx,
        &principal.actor,
        json!({
            "event": "mcp.server.connected",
            "server": server.as_str(),
            "connector": connector.key,
            "url": url,
            "reach": reach.code(),
            // Whether, never what.
            "credential": sealed.is_some(),
            // The verification is the interesting fact: this row is the record
            // that somebody proved the endpoint answered, on this date, with
            // this many tools on it.
            "tools_discovered": tools.len(),
            "addresses": &addresses,
        }),
        now,
    )
    .await?;
    tx.commit().await?;

    state.fleets.ask_for_rebind(principal.tenant_id);
    tracing::info!(
        tenant_id = %principal.tenant_id,
        server = server.as_str(),
        connector = connector.key,
        tools = tools.len(),
        "mcp server connected and verified"
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "server": server.as_str(),
            "connector": connector.key,
            "url": url,
            "reach": reach.code(),
            "addresses": addresses,
            // The word the customer is shown, and it is only ever here after a
            // real round trip that found real tools.
            "status": "verified",
            // What to validate instead of typing. Each entry carries the digest
            // to send straight back to `declare_tool`.
            "tools": tools,
        })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Discovery, and the declaration it feeds
// ---------------------------------------------------------------------------

/// `POST /v1/mcp/servers/{server}/discover` — bind, and report what is there.
///
/// **The looking half of the flow.** It writes nothing: no declaration, no
/// digest, no risk class. It binds the server exactly as the loop would — same
/// DNS lookup, same address check, same `tools/list` walk — and hands back every
/// tool with the digest of what is being served, so a human can read the name,
/// the description and the schema and then decide.
///
/// `POST` rather than `GET` because it makes an outbound connection to a
/// third-party endpoint on demand, which is not a safe method however read-only
/// the effect on our own state is. No audit row for the same reason there is no
/// row to audit: nothing changed.
///
/// A server that does not bind is a 502 carrying the client's own stable
/// reason code — `blocked_address` for a host that resolves somewhere we refuse
/// to talk to, `connect_failed` for one that is down, `ambiguous_tool` for two
/// names that collapse to one policy handle. That is exactly the diagnosis
/// [`list_servers`] shows, arrived at synchronously.
async fn discover(
    State(state): State<McpState>,
    principal: Principal,
    Path(server): Path<String>,
) -> Result<Response, ApiError> {
    let server = handle(&server)?;

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let binding = load_binding(&mut tx, &server).await?;
    tx.rollback().await?;

    let bound = bind_now(&state.credentials, principal.tenant_id, &server, &binding).await?;
    let tools = discovered(&bound, binding.connector);

    let addresses: Vec<String> = bound
        .pinned_addresses()
        .iter()
        .map(ToString::to_string)
        .collect();
    let body = json!({
        "server": server.as_str(),
        "url": binding.url,
        "reach": binding.reach.code(),
        "connector": binding.connector.key,
        "addresses": addresses,
        "tools": tools,
    });
    // The connection was opened for this one answer; close it rather than wait
    // for the drop.
    let _ = bound.close().await;

    Ok(Json(body).into_response())
}

/// `PUT /v1/mcp/servers/{server}/tools/{tool}` — grant a risk class to one
/// tool, pinned to the tool that was read.
///
/// **The deciding half.** Idempotent: the same body twice is the same row.
/// Sending a different `risk` with the same `digest` is how a class is changed,
/// and it re-confirms the pin on the way through, which is the right amount of
/// ceremony for re-classifying something.
///
/// The order of the refusals is the contract:
///
/// 1. `risk` and `digest` are parsed before anything is contacted — a typo
///    costs a 400, not a round trip.
/// 2. **The connector's floor**, from `agentos_app::catalog`. A customer may
///    always declare a tool *stricter* than the floor and never more permissive
///    than it. Lowering past it is an operator act and the code already says how
///    one is performed: `app_role` reaches these tables through a tenant
///    transaction and this route, so an operator who genuinely means it writes
///    the row through `Db::admin_tx_bypassing_rls` — a sentence somebody has to
///    type, in a place that is audited by being deliberate, exactly as
///    `0013_mcp` decision 3 described the operator path.
/// 3. The server is bound. A server that cannot be reached cannot have anything
///    declared on it, and that is the *point*: a digest is only ever accepted
///    against a live answer, so there is no way to write one that was not
///    observed.
/// 4. The tool has to exist on it — a 404 naming neither, because a handle that
///    is not in the inventory is not a tool.
/// 5. The digest has to match. If it does not, 409 `digest_mismatch`, and the
///    response does **not** carry the digest that would have worked. Handing it
///    over would turn the two-request flow into one request and a copy, with
///    the reading — which is the entire mechanism — skipped.
async fn declare_tool(
    State(state): State<McpState>,
    principal: Principal,
    Path((server, tool)): Path<(String, String)>,
    body: Result<Json<DeclareTool>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let server = handle(&server)?;
    let tool = handle(&tool)?;
    let risk = RiskClass::parse(&body.risk).ok_or_else(|| {
        ApiError::bad_request("risk: expected \"read\", \"write\" or \"destructive\"")
    })?;
    let digest = from_hex(&body.digest).ok_or_else(|| {
        ApiError::bad_request("digest: expected 64 hex characters, from the discover endpoint")
    })?;

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let binding = load_binding(&mut tx, &server).await?;
    tx.rollback().await?;

    // The floor, before anything is contacted: a class the catalogue refuses
    // costs a 422, not a round trip, and it cannot be argued out of by anything
    // the server says next.
    if let Err(floor) = binding.connector.admits(risk) {
        tracing::warn!(
            tenant_id = %principal.tenant_id,
            server = server.as_str(),
            tool = tool.as_str(),
            asked = risk.code(),
            floor = floor.code(),
            "refused an mcp declaration below the connector's floor"
        );
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "risk_below_connector_floor",
            "this connector's tools may not be declared that permissively",
        )
        .with_detail(format!(
            "{} tools are declared {:?} or stricter; {:?} is not",
            binding.connector.key,
            floor.code(),
            risk.code(),
        )));
    }

    let bound = bind_now(&state.credentials, principal.tenant_id, &server, &binding).await?;
    let served = bound.tools().get(&tool).map(|found| *found.digest());
    let _ = bound.close().await;

    let Some(served) = served else {
        return Err(ApiError::not_found());
    };
    if served != digest {
        tracing::warn!(
            tenant_id = %principal.tenant_id,
            server = server.as_str(),
            tool = tool.as_str(),
            "refused an mcp declaration whose digest is not what the server is serving"
        );
        return Err(ApiError::conflict(
            "digest_mismatch",
            "that is not the tool this server is serving; run discover and read it first",
        ));
    }

    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    sqlx::query(
        "INSERT INTO mcp_tool_declarations (tenant_id, server, tool, risk, digest) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id, server, tool) DO UPDATE \
           SET risk = excluded.risk, digest = excluded.digest, updated_at = now()",
    )
    .bind(principal.tenant_id.as_uuid())
    .bind(server.as_str())
    .bind(tool.as_str())
    .bind(risk.code())
    .bind(digest.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(StoreError::from)?;

    record(
        &mut tx,
        &principal.actor,
        json!({
            "event": "mcp.tool.declared",
            "server": server.as_str(),
            "tool": tool.as_str(),
            "risk": risk.code(),
            // The pin itself, in the trail. It is a hash of a public tool
            // definition, not a secret, and "which build of this tool was
            // blessed, and by whom" is the question an audit of a bad MCP call
            // starts from.
            "digest": body.digest,
        }),
        now,
    )
    .await?;
    tx.commit().await?;

    state.fleets.ask_for_rebind(principal.tenant_id);
    tracing::info!(
        tenant_id = %principal.tenant_id,
        server = server.as_str(),
        tool = tool.as_str(),
        risk = risk.code(),
        "mcp tool declared"
    );

    Ok(Json(DeclarationView {
        tool: tool.as_str().to_owned(),
        risk: risk.code().to_owned(),
        digest: Some(body.digest),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// The binder loop
// ---------------------------------------------------------------------------

/// Keep [`Fleets`] in step with the database, forever.
///
/// Cancelled by the process-wide token, like every other loop, so SIGTERM
/// ends it between binds rather than mid-connection. It never returns an error
/// and it never panics on a bad binding: a tenant whose configuration cannot be
/// read is logged and retried on the next tick, and a *server* that will not
/// bind is [`Fleet::bind`]'s business — it is left out with its reason recorded
/// and the tenant's other servers still work.
///
/// `credentials` is the same handle [`McpState`] holds — the deployment's one
/// cipher. A binding whose sealed credential will not open under it is left out
/// of the fleet with the reason recorded, exactly like a host that will not
/// resolve; see `Fleet::bind`.
pub async fn run(
    db: Db,
    fleets: Fleets,
    credentials: Credentials,
    mut rebinds: mpsc::Receiver<TenantId>,
    ct: CancellationToken,
) {
    // Startup: every tenant that has configured anything. Not gated on the
    // listener, so a slow MCP server delays tool availability and nothing else.
    rebind_all(&db, &fleets, &credentials, &ct).await;

    let mut refresh = tokio::time::interval(REFRESH);
    refresh.tick().await; // The first tick is immediate; we just did it.

    loop {
        tokio::select! {
            () = ct.cancelled() => break,
            _ = refresh.tick() => rebind_all(&db, &fleets, &credentials, &ct).await,
            received = rebinds.recv() => match received {
                Some(tenant) => rebind(&db, &fleets, &credentials, tenant, &ct).await,
                // Every sender is gone, which means the router that holds the
                // other half is gone, which means the process is on its way
                // down. Nothing left to keep current.
                None => break,
            },
        }
    }
    tracing::info!("mcp binder stopped");
}

/// Rebind one tenant, replacing whatever was there.
///
/// The old fleet stays in place until the new one is ready, so a rebind is not
/// a window in which the tenant has no tools. It is dropped on assignment,
/// which closes its connections.
async fn rebind(
    db: &Db,
    fleets: &Fleets,
    credentials: &Credentials,
    tenant: TenantId,
    ct: &CancellationToken,
) {
    let mut tx = match db.tenant_tx(tenant).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%tenant, error = %err, "could not read mcp configuration");
            return;
        }
    };
    let fleet = Fleet::bind(&mut tx, credentials, ct).await;
    // A read-only transaction either way; rolling back is the cheaper unwind.
    let _ = tx.rollback().await;

    match fleet {
        Ok(fleet) => {
            tracing::info!(
                %tenant,
                tools = fleet.inventory().len(),
                failed = fleet.failures().len(),
                "mcp fleet rebound"
            );
            fleets
                .bound
                .lock()
                .expect("not poisoned")
                .insert(tenant, Arc::new(fleet));
        }
        Err(err) => tracing::error!(%tenant, error = %err, "could not bind mcp fleet"),
    }
}

/// Every tenant with at least one configured server.
///
/// Cross-tenant by nature, like the outbox poller, which is why this is the
/// third legitimate `admin_tx_bypassing_rls` in the codebase: there is no
/// tenant to scope to until this query answers. It reads one column of one
/// table and writes nothing.
async fn rebind_all(db: &Db, fleets: &Fleets, credentials: &Credentials, ct: &CancellationToken) {
    let tenants: Vec<TenantId> = match db.admin_tx_bypassing_rls().await {
        Ok(mut tx) => {
            let ids: Result<Vec<uuid::Uuid>, _> =
                sqlx::query_scalar("SELECT DISTINCT tenant_id FROM mcp_servers")
                    .fetch_all(&mut *tx)
                    .await;
            let _ = tx.rollback().await;
            match ids {
                Ok(ids) => ids.into_iter().map(TenantId::from_uuid).collect(),
                Err(err) => {
                    tracing::error!(error = %err, "could not list tenants with mcp servers");
                    return;
                }
            }
        }
        Err(err) => {
            tracing::error!(error = %err, "could not open a transaction to list mcp tenants");
            return;
        }
    };

    // A tenant whose last server was deleted keeps no stale fleet — otherwise
    // its tools stay in the system prompt and stay callable.
    //
    // ponytail: a linear scan per live entry, so O(map × tenants). Both numbers
    // are "tenants that configured MCP", which is a human-sized number; make it
    // a `HashSet` the day that stops being true.
    fleets
        .bound
        .lock()
        .expect("not poisoned")
        .retain(|tenant, _| tenants.contains(tenant));

    for tenant in tenants {
        if ct.is_cancelled() {
            return;
        }
        rebind(db, fleets, credentials, tenant, ct).await;
    }
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// One server per declaration row; `NULL`s in the right-hand columns for a
/// server with none. Ordered by server so [`list_servers`] can fold a run of
/// equal handles into one view without a second map.
///
/// **`sealed_token` is not in this projection and must never be.** This is what
/// [`list_servers`] reads, [`ServerRow`] is what it reads into, and [`ServerView`]
/// — which is `Serialize` — is built from it. Keeping the column out of the
/// `SELECT` means "the listing cannot leak the credential" is a property of the
/// query rather than a review obligation about the handler, which is the same
/// construction `store::signing::published_keys` uses for the private half of a
/// signing key.
const SELECT_SERVERS: &str = "\
    SELECT s.server, s.url, s.reach, s.connector, s.created_at, \
           s.sealed_token IS NOT NULL AS has_credential, \
           d.tool, d.risk, d.digest \
      FROM mcp_servers s \
      LEFT JOIN mcp_tool_declarations d \
             ON d.tenant_id = s.tenant_id AND d.server = s.server \
     ORDER BY s.server, d.tool \
     LIMIT $1";

/// What one server needs to be bound.
///
/// Deliberately not `Debug` and not `Serialize`: it holds the sealed credential,
/// and a type that can be rendered is a type that ends up in a log line.
struct Binding {
    url: String,
    reach: Reach,
    /// The catalogue entry this binding was created from, resolved.
    ///
    /// A stored value the current [`catalog`] does not know resolves to
    /// [`catalog::CUSTOM`] — see `0040_mcp_credentials` for why that direction
    /// is the chosen one.
    connector: &'static Connector,
    /// Still sealed. [`Binding::token`] is the only thing that opens it.
    sealed_token: Option<Vec<u8>>,
    declared: std::collections::BTreeMap<Slug, Declaration>,
}

/// Load one server's URL, reach, connector, sealed credential and declarations,
/// or 404.
///
/// Another tenant's server is invisible under RLS and therefore simply not
/// found — never a 403, which would confirm the handle exists somewhere.
///
/// This is the *one* query in this module that projects `sealed_token`, and the
/// two callers of it both hand the plaintext straight to [`McpServer::bind`].
async fn load_binding(tx: &mut TenantTx<'_>, server: &Slug) -> Result<Binding, ApiError> {
    let rows: Vec<BindingRow> = sqlx::query_as(
        "SELECT s.url, s.reach, s.connector, s.sealed_token, d.tool, d.risk, d.digest \
           FROM mcp_servers s \
           LEFT JOIN mcp_tool_declarations d \
                  ON d.tenant_id = s.tenant_id AND d.server = s.server \
          WHERE s.server = $1 \
          ORDER BY d.tool",
    )
    .bind(server.as_str())
    .fetch_all(&mut ***tx)
    .await
    .map_err(StoreError::from)?;

    let first = rows.first().ok_or_else(ApiError::not_found)?;
    let mut binding = Binding {
        url: first.url.clone(),
        reach: Reach::parse(&first.reach).unwrap_or_default(),
        connector: connector_or_custom(&first.connector),
        sealed_token: first.sealed_token.clone(),
        declared: std::collections::BTreeMap::new(),
    };
    for row in &rows {
        // Same fail-closed reading as `Fleet::bind`: a row this build cannot
        // parse leaves the tool undeclared, which is destructive, which needs a
        // human. There is no branch here that widens anything.
        let Some((Ok(tool), Some(risk))) = row.tool.as_deref().map(|tool| {
            (
                Slug::parse(tool),
                row.risk.as_deref().and_then(RiskClass::parse),
            )
        }) else {
            continue;
        };
        let digest = match row.digest.as_deref() {
            None => None,
            Some(bytes) => match <[u8; 32]>::try_from(bytes) {
                Ok(digest) => Some(digest),
                Err(_) => continue,
            },
        };
        binding.declared.insert(tool, Declaration { risk, digest });
    }
    Ok(binding)
}

/// Bind one stored server synchronously, for the two routes that must.
///
/// The credential is opened inside [`Credentials::bind`] and never appears in
/// this crate — see that type's docs for why the boundary is drawn there.
///
/// The failure is the MCP client's own stable code, rendered as a 502 with the
/// detail the operator needs — which host, which address, which two tool names,
/// or that the stored credential no longer opens. That is their own
/// configuration reflected back, not a server-side error leaking: see `error.rs`
/// on what `detail` is for.
async fn bind_now(
    credentials: &Credentials,
    tenant_id: TenantId,
    server: &Slug,
    binding: &Binding,
) -> Result<McpServer, ApiError> {
    credentials
        .bind(
            tenant_id,
            server.clone(),
            &binding.url,
            &binding.declared,
            binding.reach,
            binding.sealed_token.as_deref(),
            CancellationToken::new(),
        )
        .await
        .map_err(bind_failed(server))
}

/// How a bind failure reads to an operator.
///
/// A closure factory rather than a plain function because [`connect`] binds
/// without a stored [`Binding`] and needs the same mapping.
///
/// `detail` is `McpError`'s `Display`, and
/// `mcp::a_refused_bind_never_carries_the_credential_in_its_message` is what
/// keeps that safe to render: no variant of that error can hold the token.
fn bind_failed(server: &Slug) -> impl FnOnce(agentos_app::mcp::McpError) -> ApiError + use<'_> {
    move |err| {
        tracing::warn!(
            server = server.as_str(),
            code = err.code(),
            "mcp bind failed: {err}"
        );
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            err.code(),
            "the mcp server could not be bound",
        )
        .with_detail(err.to_string())
    }
}

/// Resolve a stored connector key, falling back to [`catalog::CUSTOM`].
///
/// The fallback is argued in `0040_mcp_credentials`: the catalogue is code, so a
/// stored key can outlive its entry, and locking a working binding out of its
/// own declarations because we deleted a row from an array is a worse failure
/// than losing a coarse guard.
fn connector_or_custom(key: &str) -> &'static Connector {
    catalog::find(key).unwrap_or_else(|| {
        tracing::warn!(
            connector = key,
            "unknown mcp connector; treating it as custom"
        );
        &catalog::CUSTOM
    })
}

/// `bound` / `failed` / `pending`, and the reason when there is one.
fn bind_status(fleet: &Fleet, server: &Slug) -> (&'static str, Option<Value>) {
    if fleet.is_bound(server) {
        return ("bound", None);
    }
    match fleet.failures().get(server) {
        Some(BindFailure { code, detail }) => {
            ("failed", Some(json!({ "code": code, "detail": detail })))
        }
        None => ("pending", None),
    }
}

/// One stored declaration out of a joined row, or `None` when the row carries
/// none.
fn declaration_view(row: &ServerRow) -> Option<DeclarationView> {
    let (tool, risk) = row.tool.as_deref().zip(row.risk.as_deref())?;
    Some(DeclarationView {
        tool: tool.to_owned(),
        risk: risk.to_owned(),
        digest: row.digest.as_deref().map(to_hex_slice),
    })
}

/// A path segment as a policy handle, or a 400 that says why.
fn handle(raw: &str) -> Result<Slug, ApiError> {
    Slug::parse(raw).map_err(|err| ApiError::bad_request(format!("{raw:?} is not a handle: {err}")))
}

fn to_hex(bytes: &[u8; 32]) -> String {
    to_hex_slice(bytes)
}

fn to_hex_slice(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// 64 hex characters to 32 bytes, or `None`.
///
/// The `is_ascii_hexdigit` pass is not decoration: `u8::from_str_radix` accepts
/// a leading `+`, so `"+f"` would otherwise parse as 15 and a digest could be
/// spelled more than one way.
fn from_hex(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(raw.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// One administrative act, in the same transaction as the act itself.
///
/// `AuditKind::PolicyChanged` for all of them, the same call `routes::teams`
/// makes and for the same reason: every write here changes what an employee may
/// do — which endpoint its tools come from, and what class each one is granted
/// at. The specific act is `payload.event`.
///
/// `decision_id` is `None` throughout, and that is honest: no Policy Gate ruling
/// authorised these. They are an operator's key acting directly, and `actor` is
/// the key's label.
async fn record(
    tx: &mut TenantTx<'_>,
    actor: &AuditActor,
    payload: Value,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    audit::append(
        tx,
        &AuditEvent {
            payload,
            ..AuditEvent::new(actor.clone(), AuditKind::PolicyChanged, now)
        },
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::ApiKeys;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The cloud metadata endpoint. Link-local, so `McpServer::bind` refuses it
    /// for both reaches — and it is a literal, so the refusal costs no DNS.
    const METADATA: &str = "http://169.254.169.254/mcp";

    struct Harness {
        app: Router,
        db: Db,
        fleets: Fleets,
        /// The one cipher these tests seal and open with, shared by the router
        /// and by every hand-driven `rebind` below — the same sharing `main`
        /// does, and for the same reason.
        credentials: Credentials,
        a: TenantId,
        b: TenantId,
    }

    /// A master key for the tests. Any 32 bytes; what matters is that one value
    /// is used everywhere, so a credential sealed by a handler opens in a
    /// rebind.
    const MASTER_KEY: &str = "a-test-master-key-for-mcp-credentials";

    impl Harness {
        /// `None` when there is no database. Every contract here is a contract
        /// about rows in Postgres — RLS, a primary key, a cascading foreign key
        /// — and a mock of those is a mock of the test.
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; mcp routes need a real Postgres");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");

            // The receiver is dropped: no binder task runs, so a rebind happens
            // only where a test asks for one and nothing races the assertions.
            let (fleets, _rebinds) = Fleets::new();
            let credentials = Credentials::from_master_key(MASTER_KEY);
            Some(Self {
                app: crate::with_api_stack(
                    router(McpState::new(
                        db.clone(),
                        fleets.clone(),
                        credentials.clone(),
                    )),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                fleets,
                credentials,
                a,
                b,
            })
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: Option<&str>,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder().method(method).uri(uri);
            if let Some(secret) = secret {
                req = req.header(header::AUTHORIZATION, format!("Bearer {secret}"));
            }
            let req = match &body {
                Some(body) => req
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string())),
                None => req.body(Body::empty()),
            }
            .expect("request");

            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// Declare a server and assert it took.
        async fn declare(&self, secret: &str, server: &str, url: &str) {
            let (status, body) = self
                .send(
                    "POST",
                    "/v1/mcp/servers",
                    Some(secret),
                    Some(json!({"server": server, "url": url})),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }

        /// Plant a declaration directly. The HTTP route requires a live digest
        /// from a real MCP server; these tests are about isolation and cascade,
        /// so the fixture they need is a row.
        async fn declare_tool_row(&self, tenant: TenantId, server: &str, tool: &str, risk: &str) {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            sqlx::query(
                "INSERT INTO mcp_tool_declarations (tenant_id, server, tool, risk) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(tenant.as_uuid())
            .bind(server)
            .bind(tool)
            .bind(risk)
            .execute(&mut **tx)
            .await
            .expect("insert declaration");
            tx.commit().await.expect("commit");
        }

        /// `payload ->> 'event'` for every audit row this tenant has.
        async fn audit_events(&self, tenant: TenantId) -> Vec<String> {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let events = sqlx::query_scalar(
                "SELECT payload ->> 'event' FROM audit_log \
                  WHERE payload ->> 'event' LIKE 'mcp.%' ORDER BY occurred_at, id",
            )
            .fetch_all(&mut **tx)
            .await
            .expect("audit");
            tx.commit().await.expect("commit");
            events
        }

        /// Every audit row this tenant has, whole, as text.
        ///
        /// Deliberately the *whole* row and not `payload ->> 'event'`: the
        /// question these tests ask of the trail is "is the token anywhere in
        /// it", and a projection is a place to hide.
        async fn audit_text(&self, tenant: TenantId) -> String {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let rows: Vec<String> = sqlx::query_scalar("SELECT to_jsonb(a)::text FROM audit_log a")
                .fetch_all(&mut **tx)
                .await
                .expect("audit");
            tx.commit().await.expect("commit");
            rows.join("\n")
        }

        /// Every `mcp_servers` row, whole, as text — `sealed_token` included,
        /// rendered as the hex `bytea` literal.
        ///
        /// This is the assertion that matters most: it does not trust the
        /// projection in `SELECT_SERVERS`, it reads the columns themselves. A
        /// plaintext token stored by mistake would be right here in the output.
        async fn servers_text(&self, tenant: TenantId) -> String {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let rows: Vec<String> =
                sqlx::query_scalar("SELECT to_jsonb(s)::text FROM mcp_servers s")
                    .fetch_all(&mut **tx)
                    .await
                    .expect("servers");
            tx.commit().await.expect("commit");
            rows.join("\n")
        }

        /// How many `mcp_servers` rows this tenant has.
        async fn server_count(&self, tenant: TenantId) -> i64 {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let count = sqlx::query_scalar("SELECT count(*) FROM mcp_servers")
                .fetch_one(&mut **tx)
                .await
                .expect("count");
            tx.commit().await.expect("commit");
            count
        }

        async fn teardown(self) {
            for tenant in [self.a, self.b] {
                let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
                sqlx::query("DELETE FROM tenants WHERE id = $1")
                    .bind(tenant.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .expect("delete tenant");
                tx.commit().await.expect("commit");
            }
        }
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'mcp-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    fn servers(page: &Value) -> &Vec<Value> {
        page["servers"].as_array().expect("servers")
    }

    // -- the schema this unit added ----------------------------------------

    /// 0016 moved a privilege; it must not have moved a policy with it. RLS is
    /// the only thing confining these writes now, so "enabled" is not enough —
    /// `force` is what makes the policy bind for the table's owner too.
    #[tokio::test]
    async fn the_tables_are_under_forced_rls_and_writable_by_the_runtime() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let mut tx = h.db.admin_tx_bypassing_rls().await.expect("admin tx");
        for table in ["mcp_servers", "mcp_tool_declarations"] {
            let (enabled, forced): (bool, bool) = sqlx::query_as(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1",
            )
            .bind(table)
            .fetch_one(&mut *tx)
            .await
            .expect("pg_class");
            assert!(enabled, "{table} does not have row level security enabled");
            assert!(forced, "{table} does not force row level security");

            for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
                let granted: bool =
                    sqlx::query_scalar("SELECT has_table_privilege('app_role', $1, $2)")
                        .bind(table)
                        .bind(privilege)
                        .fetch_one(&mut *tx)
                        .await
                        .expect("privilege check");
                assert!(granted, "app_role cannot {privilege} on {table}");
            }
        }
        tx.rollback().await.expect("rollback");

        h.teardown().await;
    }

    // -- isolation ----------------------------------------------------------

    /// The headline. Two tenants, two servers under the same handle, two
    /// different sets of declarations — and neither sees the other's.
    #[tokio::test]
    async fn a_tenant_never_sees_another_tenants_declarations() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.declare(SECRET_A, "erp", "https://erp-a.example.com/mcp")
            .await;
        h.declare(SECRET_B, "erp", "https://erp-b.example.com/mcp")
            .await;
        h.declare_tool_row(h.a, "erp", "lookup", "read").await;
        h.declare_tool_row(h.b, "erp", "drop-table", "destructive")
            .await;

        let (status, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(servers(&page).len(), 1, "{page}");
        assert_eq!(servers(&page)[0]["url"], "https://erp-a.example.com/mcp");
        assert_eq!(servers(&page)[0]["tools"][0]["tool"], "lookup");
        assert!(
            !page.to_string().contains("drop-table"),
            "B's declaration leaked into A's page: {page}"
        );
        assert!(
            !page.to_string().contains("erp-b.example.com"),
            "B's endpoint leaked into A's page: {page}"
        );

        let (status, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_B), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(servers(&page)[0]["tools"][0]["tool"], "drop-table");
        assert!(
            !page.to_string().contains("erp-a.example.com"),
            "A's endpoint leaked into B's page: {page}"
        );

        // And the same handle in another tenant is not a resource this one can
        // reach: deleting it is a 404, not somebody else's outage.
        let (status, _) = h
            .send("DELETE", "/v1/mcp/servers/nope", Some(SECRET_A), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A tenant's rows are still there afterwards.
        let (_, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_B), None).await;
        assert_eq!(servers(&page).len(), 1, "{page}");

        h.teardown().await;
    }

    #[tokio::test]
    async fn no_credential_is_a_401_before_the_handler_runs() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for (method, uri) in [
            ("GET", "/v1/mcp/servers"),
            ("POST", "/v1/mcp/servers"),
            ("DELETE", "/v1/mcp/servers/erp"),
            ("POST", "/v1/mcp/servers/erp/discover"),
            ("PUT", "/v1/mcp/servers/erp/tools/lookup"),
        ] {
            let (status, problem) = h.send(method, uri, None, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
            assert_eq!(problem["code"], "unauthenticated");
        }

        h.teardown().await;
    }

    // -- the address check, through the operator path -----------------------

    /// **A binding to a link-local address is refused**, and the operator is
    /// told which address and why.
    ///
    /// Both halves matter. The binder must drop it — `169.254.169.254` is every
    /// major cloud's credential endpoint and no legitimate MCP server lives
    /// there — and it must drop it *visibly*, because a binding that silently
    /// disappears is indistinguishable from one nobody configured.
    #[tokio::test]
    async fn a_link_local_binding_is_refused_and_the_operator_is_told_why() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.declare(SECRET_A, "metadata", METADATA).await;

        // Before the binder has run, the honest answer is "pending" — not
        // "failed", which would be a diagnosis nobody has made yet.
        let (_, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(servers(&page)[0]["status"], "pending", "{page}");

        rebind(
            &h.db,
            &h.fleets,
            &h.credentials,
            h.a,
            &CancellationToken::new(),
        )
        .await;

        let (status, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(servers(&page)[0]["status"], "failed", "{page}");
        assert_eq!(servers(&page)[0]["error"]["code"], "blocked_address");
        assert!(
            servers(&page)[0]["error"]["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("169.254.169.254"),
            "the refused address is what the operator needs: {page}"
        );

        // Nothing is bound, so the tenant's fleet offers the model no tools and
        // refuses every call naming this server.
        let fleet = h.fleets.for_tenant(h.a);
        assert!(fleet.inventory().is_empty());
        assert!(!fleet.is_bound(&Slug::parse("metadata").expect("slug")));

        // The synchronous path says the same thing, with the same code.
        let (status, problem) = h
            .send(
                "POST",
                "/v1/mcp/servers/metadata/discover",
                Some(SECRET_A),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(problem["code"], "blocked_address", "{problem}");

        h.teardown().await;
    }

    /// One bad binding must not take the tenant's other servers with it, and
    /// must not take the process down.
    #[tokio::test]
    async fn a_server_that_will_not_bind_is_left_out_and_nothing_else_breaks() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.declare(SECRET_A, "metadata", METADATA).await;
        // Loopback with `reach: public` is the other refusal, and it is the one
        // an operator hits by accident with a sidecar.
        let (status, _) = h
            .send(
                "POST",
                "/v1/mcp/servers",
                Some(SECRET_A),
                Some(json!({"server": "sidecar", "url": "http://127.0.0.1:1/mcp"})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);

        rebind(
            &h.db,
            &h.fleets,
            &h.credentials,
            h.a,
            &CancellationToken::new(),
        )
        .await;

        let fleet = h.fleets.for_tenant(h.a);
        assert_eq!(fleet.failures().len(), 2, "{:?}", fleet.failures());
        for handle in ["metadata", "sidecar"] {
            let slug = Slug::parse(handle).expect("slug");
            assert_eq!(
                fleet.failures()[&slug].code,
                "blocked_address",
                "{handle} was not refused on its address"
            );
        }

        h.teardown().await;
    }

    // -- input the operator controls ---------------------------------------

    #[tokio::test]
    async fn a_url_that_could_never_be_an_mcp_server_is_refused_at_declare_time() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for url in [
            "file:///etc/passwd",
            "gopher://example.com/",
            "not a url",
            "https://",
        ] {
            let (status, problem) = h
                .send(
                    "POST",
                    "/v1/mcp/servers",
                    Some(SECRET_A),
                    Some(json!({"server": "erp", "url": url})),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{url} was accepted");
            assert_eq!(problem["code"], "bad_request");
        }

        // ... and so is a handle no allowlist entry could spell, an unknown
        // reach, and a field nobody meant to send.
        for body in [
            json!({"server": "Not A Slug!", "url": "https://erp.example.com/mcp"}),
            json!({"server": "erp", "url": "https://erp.example.com/mcp", "reach": "internal"}),
            json!({"server": "erp", "url": "https://erp.example.com/mcp", "reachh": "private"}),
        ] {
            let (status, _) = h
                .send(
                    "POST",
                    "/v1/mcp/servers",
                    Some(SECRET_A),
                    Some(body.clone()),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {body}");
        }

        // Nothing was written by any of that.
        let (_, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert!(servers(&page).is_empty(), "{page}");

        h.teardown().await;
    }

    #[tokio::test]
    async fn the_same_handle_twice_is_a_conflict_not_a_silent_replacement() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.declare(SECRET_A, "erp", "https://erp.example.com/mcp")
            .await;
        let (status, _) = h
            .send(
                "POST",
                "/v1/mcp/servers",
                Some(SECRET_A),
                Some(json!({"server": "erp", "url": "https://evil.example.com/mcp"})),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a second declaration must not repoint an existing handle"
        );

        let (_, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(servers(&page)[0]["url"], "https://erp.example.com/mcp");

        h.teardown().await;
    }

    // -- the digest is never accepted on trust ------------------------------

    /// **Never auto-accept.** A declaration is only ever written against a
    /// digest the server is serving *now*, so a server that cannot be reached
    /// cannot have anything declared on it — there is no path that stores an
    /// unverified pin, not even a plausible one.
    #[tokio::test]
    async fn a_digest_is_refused_unless_the_server_confirms_it() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.declare(SECRET_A, "metadata", METADATA).await;
        let plausible = "0".repeat(64);

        let (status, problem) = h
            .send(
                "PUT",
                "/v1/mcp/servers/metadata/tools/lookup",
                Some(SECRET_A),
                Some(json!({"risk": "read", "digest": plausible})),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "a pin was accepted without a live answer: {problem}"
        );
        assert_eq!(problem["code"], "blocked_address");

        // And nothing was written.
        let (_, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(
            servers(&page)[0]["tools"],
            json!([]),
            "a refused declaration must leave no row: {page}"
        );

        // A digest that is not 32 bytes of hex never reaches the network at all.
        for digest in [
            "",
            "deadbeef",
            &"g".repeat(64),
            &format!("+{}", "0".repeat(63)),
            &"0".repeat(65),
        ] {
            let (status, _) = h
                .send(
                    "PUT",
                    "/v1/mcp/servers/metadata/tools/lookup",
                    Some(SECRET_A),
                    Some(json!({"risk": "read", "digest": digest})),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "accepted digest {digest:?}"
            );
        }

        // As does an unknown risk class, and a body with no digest at all —
        // the unpinned path is not on this surface.
        for body in [
            json!({"risk": "harmless", "digest": plausible}),
            json!({"risk": "read"}),
        ] {
            let (status, _) = h
                .send(
                    "PUT",
                    "/v1/mcp/servers/metadata/tools/lookup",
                    Some(SECRET_A),
                    Some(body.clone()),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {body}");
        }

        h.teardown().await;
    }

    // -- deletion and the trail ---------------------------------------------

    /// Deleting a server takes its declarations with it, so a handle declared
    /// again against a different URL does not inherit a human's blessing.
    #[tokio::test]
    async fn deleting_a_server_takes_its_declarations_with_it_and_is_audited() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.declare(SECRET_A, "erp", "https://erp.example.com/mcp")
            .await;
        h.declare_tool_row(h.a, "erp", "lookup", "read").await;

        let (status, _) = h
            .send("DELETE", "/v1/mcp/servers/erp", Some(SECRET_A), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let orphans: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_tool_declarations")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.commit().await.expect("commit");
        assert_eq!(orphans, 0, "a declaration outlived its server");

        // Re-declaring the same handle against a different endpoint starts
        // clean: nothing is vetted on it.
        h.declare(SECRET_A, "erp", "https://elsewhere.example.com/mcp")
            .await;
        let (_, page) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(servers(&page)[0]["tools"], json!([]), "{page}");

        assert_eq!(
            h.audit_events(h.a).await,
            [
                "mcp.server.declared",
                "mcp.server.deleted",
                "mcp.server.declared"
            ],
            "every administrative act leaves a row"
        );
        // ... and it says who.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let actor: String = sqlx::query_scalar(
            "SELECT actor FROM audit_log WHERE payload ->> 'event' = 'mcp.server.deleted'",
        )
        .fetch_one(&mut **tx)
        .await
        .expect("audit row");
        tx.commit().await.expect("commit");
        assert_eq!(actor, "operator:ops-a");

        h.teardown().await;
    }

    /// A tenant whose last server is deleted must not keep a stale fleet: the
    /// tools would stay in its system prompt and stay callable.
    #[tokio::test]
    async fn a_tenant_with_no_servers_left_keeps_no_fleet() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.declare(SECRET_A, "metadata", METADATA).await;
        rebind(
            &h.db,
            &h.fleets,
            &h.credentials,
            h.a,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(h.fleets.for_tenant(h.a).failures().len(), 1);

        let (status, _) = h
            .send("DELETE", "/v1/mcp/servers/metadata", Some(SECRET_A), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        rebind_all(&h.db, &h.fleets, &h.credentials, &CancellationToken::new()).await;
        let fleet = h.fleets.for_tenant(h.a);
        assert!(fleet.failures().is_empty(), "{:?}", fleet.failures());
        assert!(fleet.inventory().is_empty());

        h.teardown().await;
    }

    // -- pure ---------------------------------------------------------------

    #[test]
    fn a_digest_has_exactly_one_spelling() {
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let hex = to_hex(&bytes);
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("000102"), "{hex}");
        assert_eq!(from_hex(&hex), Some(bytes));

        // `u8::from_str_radix` accepts a leading `+`; without the hexdigit pass
        // this would parse and one digest would have two spellings.
        assert_eq!(from_hex(&format!("+f{}", "0".repeat(62))), None);
        assert_eq!(from_hex(&hex.to_uppercase()), Some(bytes), "case is not");
        assert_eq!(from_hex(""), None);
        assert_eq!(from_hex(&"0".repeat(63)), None);
        assert_eq!(from_hex(&"0".repeat(65)), None);
        // Non-ASCII of the right byte length must not slip through `len()`.
        assert_eq!(from_hex(&"é".repeat(32)), None);
    }

    #[test]
    fn a_binding_that_nobody_has_tried_yet_is_pending_not_failed() {
        let fleet = Fleet::empty();
        let erp = Slug::parse("erp").expect("slug");
        assert_eq!(bind_status(&fleet, &erp), ("pending", None));
    }

    /// The registry is what `main` substitutes into a turn's ports, so an
    /// unconfigured tenant has to come back empty rather than panic.
    #[test]
    fn an_unknown_tenant_gets_an_empty_fleet() {
        let (fleets, _rebinds) = Fleets::new();
        let fleet = fleets.for_tenant(TenantId::from_uuid(Uuid::nil()));
        assert!(fleet.inventory().is_empty());
        assert!(fleet.failures().is_empty());
    }

    // -----------------------------------------------------------------------
    // The connector catalogue, the credential, and "connected"
    // -----------------------------------------------------------------------

    /// A token distinctive enough that finding it anywhere is unambiguous.
    ///
    /// Not `hunter2`: a short common word turns up as a substring of a UUID or a
    /// base64 blob by accident, and a leak test that cries wolf is a leak test
    /// somebody deletes.
    const TOKEN: &str = "zzz-mcp-credential-must-never-surface-9f3a1c";

    fn slug(raw: &str) -> Slug {
        Slug::parse(raw).expect("a handle")
    }

    /// The catalogue is behind the API stack and says what a UI needs to render.
    #[tokio::test]
    async fn the_catalogue_names_what_each_connector_asks_for() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.send("GET", "/v1/mcp/catalog", Some(SECRET_A), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let connectors = body["connectors"].as_array().expect("a list").clone();
        assert!(!connectors.is_empty());

        let custom = connectors
            .iter()
            .find(|c| c["connector"] == "custom")
            .expect("the custom entry is always there");
        assert_eq!(custom["url"], Value::Null, "the customer supplies it");
        assert_eq!(custom["credential"], "bearer");

        let github = connectors
            .iter()
            .find(|c| c["connector"] == "github")
            .expect("github is catalogued");
        assert_eq!(github["url"], "https://api.githubcopilot.com/mcp/");
        assert_eq!(github["reach"], "public");
        assert_eq!(
            github["floor"], "write",
            "the floor has to be visible or a UI cannot grey out what it must not offer"
        );

        h.teardown().await;
    }

    /// **"Connexion validée" means a round trip happened**, and what comes back
    /// is the list to validate instead of typing.
    ///
    /// The whole onboarding step, end to end: the customer names a connector,
    /// pastes a token, and gets back every tool with the digest that
    /// [`declare_tool`] will accept — no second request to look anything up, and
    /// no field for them to transcribe.
    #[tokio::test]
    async fn connecting_verifies_the_endpoint_and_hands_back_the_tools_to_validate() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let mcp = agentos_app::mocks::FakeMcpServer::start(&["lookup", "write_note"]).await;

        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "custom",
                    "server": "erp",
                    "url": mcp.url(),
                    // Loopback, so the binding has to opt in — the same opt-in
                    // an operator writes for a sidecar.
                    "reach": "private",
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["status"], "verified");
        assert_eq!(body["addresses"], json!(["127.0.0.1"]));

        // The credential really went to the server, on every request.
        let sent = mcp.authorizations();
        assert!(!sent.is_empty(), "the endpoint was never authenticated");
        assert!(
            sent.iter().all(|v| v == &format!("Bearer {TOKEN}")),
            "{sent:?}"
        );

        // What came back is what the customer validates.
        let tools = body["tools"].as_array().expect("a list");
        assert_eq!(tools.len(), 2);
        let lookup = tools
            .iter()
            .find(|t| t["tool"] == "lookup")
            .expect("the handle is the kebab-case fold of the wire name");
        assert_eq!(lookup["wire_name"], "lookup");
        assert_eq!(
            lookup["risk"], "destructive",
            "nothing is declared yet, and undeclared is destructive"
        );
        assert_eq!(lookup["declared"], false);
        assert_eq!(lookup["floor"], "read", "custom makes no claim");
        // The underscore fold, which is what an allowlist entry has to spell.
        assert!(tools.iter().any(|t| t["tool"] == "write-note"));

        // The description is a stranger's prose and it is here verbatim, for a
        // human. Not sanitised — a filter that made it *look* safe would be
        // worse than none.
        assert!(
            lookup["description"]
                .as_str()
                .expect("a description")
                .contains("IGNORE ALL PREVIOUS INSTRUCTIONS"),
            "the operator has to see exactly what the server wrote"
        );

        // And the digest is usable straight from this response: no discover
        // round trip, nothing transcribed.
        let digest = lookup["digest"].as_str().expect("a digest");
        let (status, body) = h
            .send(
                "PUT",
                "/v1/mcp/servers/erp/tools/lookup",
                Some(SECRET_A),
                Some(json!({ "risk": "read", "digest": digest })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["risk"], "read");

        // Which is exactly what the binder loop then classifies it as.
        rebind(
            &h.db,
            &h.fleets,
            &h.credentials,
            h.a,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(
            h.fleets.for_tenant(h.a).inventory(),
            vec![(
                agentos_domain::action::McpTool::new(slug("erp"), slug("lookup")),
                agentos_domain::action::Risk::Low,
            )],
            "the tool the customer validated is the only one in the inventory"
        );

        h.teardown().await;
    }

    /// **The leak hunt.** The credential goes in once and is not in any response,
    /// any audit row, any log-shaped field, or any column but the sealed one.
    ///
    /// Every surface that exists is searched, not a representative sample: the
    /// connect response, the listing, discover, a successful declaration, a
    /// *failed* declaration, a rejected body, the whole audit trail, the fleet
    /// as it renders, and the whole `mcp_servers` row including `sealed_token`
    /// as hex. The last one is the important one, because it does not trust the
    /// projection in [`SELECT_SERVERS`] — it reads the columns.
    #[tokio::test]
    async fn a_credential_is_taken_once_and_never_comes_back() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let mcp = agentos_app::mocks::FakeMcpServer::start(&["lookup"]).await;

        let (status, connected) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "custom",
                    "server": "erp",
                    "url": mcp.url(),
                    "reach": "private",
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{connected}");

        let (_, listed) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        let (_, discovered) = h
            .send("POST", "/v1/mcp/servers/erp/discover", Some(SECRET_A), None)
            .await;
        let digest = discovered["tools"][0]["digest"]
            .as_str()
            .expect("a digest")
            .to_owned();
        let (_, declared) = h
            .send(
                "PUT",
                "/v1/mcp/servers/erp/tools/lookup",
                Some(SECRET_A),
                Some(json!({ "risk": "read", "digest": digest })),
            )
            .await;
        // A refusal too: an error body is where a value most often escapes.
        let (status, refused) = h
            .send(
                "PUT",
                "/v1/mcp/servers/erp/tools/lookup",
                Some(SECRET_A),
                Some(json!({ "risk": "read", "digest": "0".repeat(64) })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        // And a rejected body that had the token in it.
        let (_, malformed) = h
            .send(
                "POST",
                "/v1/mcp/servers",
                Some(SECRET_A),
                Some(json!({ "server": "crm", "url": "not a url", "token": TOKEN })),
            )
            .await;

        // The binder holds the fleet in memory; its rendering is a log line
        // waiting to happen.
        rebind(
            &h.db,
            &h.fleets,
            &h.credentials,
            h.a,
            &CancellationToken::new(),
        )
        .await;
        let fleet = format!("{:?}", h.fleets.for_tenant(h.a));

        let surfaces: [(&str, String); 8] = [
            ("the connect response", connected.to_string()),
            ("the listing", listed.to_string()),
            ("the discover response", discovered.to_string()),
            ("the declaration", declared.to_string()),
            ("a digest_mismatch refusal", refused.to_string()),
            ("a malformed-body refusal", malformed.to_string()),
            ("the audit trail", h.audit_text(h.a).await),
            ("the bound fleet, rendered", fleet),
        ];
        for (where_, text) in surfaces {
            assert!(
                !text.contains(TOKEN),
                "the credential surfaced in {where_}: {text}"
            );
        }

        // The columns themselves. `sealed_token` is in this string, as hex, and
        // the plaintext is not in it — which is the difference between encrypted
        // and merely out of the projection.
        let rows = h.servers_text(h.a).await;
        assert!(
            !rows.contains(TOKEN),
            "mcp_servers holds the plaintext: {rows}"
        );
        assert!(
            rows.contains("sealed_token"),
            "the column was not read at all, so this proved nothing: {rows}"
        );
        assert!(
            !rows.contains("\"sealed_token\": null") && !rows.contains("\"sealed_token\":null"),
            "the credential was never stored, so this proved nothing: {rows}"
        );

        // What a UI is owed, and the whole of it.
        assert_eq!(listed["servers"][0]["has_credential"], true);
        assert_eq!(listed["servers"][0]["connector"], "custom");

        h.teardown().await;
    }

    /// A body that does not parse must not echo the value back in its message.
    ///
    /// `ApiError::bad_request(err.body_text())` puts axum's own rejection text
    /// in a response, and that text is built by serde. Serde names the field and
    /// the expected type; the assumption that it never names the *value* is what
    /// this pins.
    #[tokio::test]
    async fn a_malformed_body_never_echoes_the_token_back() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for body in [
            // A wrong type beside the token.
            json!({ "server": 7, "url": "https://example.invalid/mcp", "token": TOKEN }),
            // `deny_unknown_fields`, with the token present and spelled wrong.
            json!({ "server": "erp", "url": "https://example.invalid/mcp", "tokenn": TOKEN }),
            // The token itself of the wrong type, so serde reads the value.
            json!({ "server": "erp", "url": "https://example.invalid/mcp", "token": [TOKEN] }),
        ] {
            let (status, answered) = h
                .send("POST", "/v1/mcp/servers", Some(SECRET_A), Some(body))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{answered}");
            assert!(
                !answered.to_string().contains(TOKEN),
                "a rejection echoed the credential: {answered}"
            );
        }

        h.teardown().await;
    }

    /// **The half-failure.** A server that authenticates and exposes nothing is
    /// not a connection, and nothing is written.
    ///
    /// This is the token with no scopes, and it is the case the whole route
    /// exists for: every mechanism below reports success, the customer is told
    /// "connected", and they find out three days later when an employee is
    /// denied.
    #[tokio::test]
    async fn a_server_that_exposes_no_tools_is_not_a_connection() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let scopeless = agentos_app::mocks::FakeMcpServer::start(&[]).await;

        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "custom",
                    "server": "erp",
                    "url": scopeless.url(),
                    "reach": "private",
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body["code"], "no_tools_exposed");

        // It really did authenticate — this is a *half* failure, not a refusal
        // before the wire.
        assert!(!scopeless.authorizations().is_empty());

        // And nothing was kept: no row, no credential, no audit row claiming a
        // connection happened.
        assert_eq!(h.server_count(h.a).await, 0);
        assert!(h.audit_events(h.a).await.is_empty());

        h.teardown().await;
    }

    /// **The new binding path goes through the same address check**, and a
    /// failed connect stores nothing.
    ///
    /// `connect` is a second door onto `McpServer::bind`, which is exactly the
    /// shape that historically grows a bypass. It does not have one: the address
    /// check runs before the credential is read, so there is no token that buys
    /// an address.
    #[tokio::test]
    async fn connecting_cannot_reach_an_address_the_address_check_refuses() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for reach in ["public", "private"] {
            let (status, body) = h
                .send(
                    "POST",
                    "/v1/mcp/connect",
                    Some(SECRET_A),
                    Some(json!({
                        "connector": "custom",
                        "server": "erp",
                        "url": METADATA,
                        "reach": reach,
                        "token": TOKEN,
                    })),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{reach}: {body}");
            assert_eq!(
                body["code"], "blocked_address",
                "{reach} let the metadata endpoint through: {body}"
            );
            assert!(!body.to_string().contains(TOKEN), "{body}");
        }

        // A scheme the client would never dial is refused before any of it.
        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "custom",
                    "server": "erp",
                    "url": "file:///etc/passwd",
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        assert_eq!(
            h.server_count(h.a).await,
            0,
            "a failed connect stored a row"
        );
        h.teardown().await;
    }

    /// A named connector's URL is ours, and an unknown one is a 404 — never a
    /// silent fallback to `custom`.
    ///
    /// The fallback is the interesting refusal: if a typo in `connector` fell
    /// through to `custom`, the request body's `url` would suddenly be the one
    /// that gets bound, which is the exact substitution the catalogue exists to
    /// prevent.
    #[tokio::test]
    async fn a_connector_name_is_exact_and_its_url_is_not_the_customers_to_choose() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let mcp = agentos_app::mocks::FakeMcpServer::start(&["lookup"]).await;

        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "githubb",
                    "server": "gh",
                    "url": mcp.url(),
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // And naming a real connector does not let the URL through either.
        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "github",
                    "server": "gh",
                    "url": mcp.url(),
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(!body.to_string().contains(TOKEN), "{body}");

        // A connector that wants a credential will not connect without one, and
        // says so before it dials.
        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({ "connector": "custom", "server": "erp", "url": mcp.url() })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        assert_eq!(h.server_count(h.a).await, 0);
        h.teardown().await;
    }

    /// **A customer may tighten a risk class and never loosen it past the
    /// catalogue's floor.**
    ///
    /// Checked before anything is contacted, which is why this test needs no MCP
    /// server at all: a class the catalogue refuses is a 422 that cannot be
    /// argued out of by whatever the endpoint says next.
    #[tokio::test]
    async fn a_customer_cannot_declare_a_tool_below_its_connectors_floor() {
        let Some(h) = Harness::new().await else {
            return;
        };

        // GitHub's entry: floor `write`, and its URL is not reachable from a
        // test, which is the point — the refusal happens first.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector) \
             VALUES ($1, 'gh', 'https://api.githubcopilot.com/mcp/', 'public', 'github')",
        )
        .bind(h.a.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("insert");
        tx.commit().await.expect("commit");

        let (status, body) = h
            .send(
                "PUT",
                "/v1/mcp/servers/gh/tools/get-issue",
                Some(SECRET_A),
                Some(json!({ "risk": "read", "digest": "a".repeat(64) })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "read slipped under github's write floor: {body}"
        );
        assert_eq!(body["code"], "risk_below_connector_floor");

        // Stricter is always allowed, and gets as far as the endpoint — which is
        // unreachable from a test, so anything but a 422 is the proof that the
        // floor let it past.
        for risk in ["write", "destructive"] {
            let (status, body) = h
                .send(
                    "PUT",
                    "/v1/mcp/servers/gh/tools/get-issue",
                    Some(SECRET_A),
                    Some(json!({ "risk": risk, "digest": "a".repeat(64) })),
                )
                .await;
            assert_ne!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{risk} is at or above the floor and was refused by it: {body}"
            );
        }

        // A `custom` binding makes no claim, so `read` is allowed there — the
        // floor is per connector, not a global tightening.
        h.declare(SECRET_A, "erp", "https://mcp.invalid.example/mcp")
            .await;
        let (status, body) = h
            .send(
                "PUT",
                "/v1/mcp/servers/erp/tools/lookup",
                Some(SECRET_A),
                Some(json!({ "risk": "read", "digest": "a".repeat(64) })),
            )
            .await;
        assert_ne!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "the floor tightened a connector that makes no claim: {body}"
        );

        // And a stored connector this build no longer has an entry for is
        // treated as `custom` — never as "whichever entry happens to be first".
        //
        // The catalogue is a `const`, so there is no foreign key and a stored
        // key can outlive its entry; `0040_mcp_credentials` argues why the
        // fallback is the permissive one. What must not happen is a *different*
        // connector's floor being applied to a binding that has nothing to do
        // with it, which is what any fallback other than `CUSTOM` would do.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector) \
             VALUES ($1, 'gone', 'https://mcp.invalid.example/mcp', 'public', \
                     'a-connector-this-build-does-not-have')",
        )
        .bind(h.a.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("insert");
        tx.commit().await.expect("commit");

        let (status, body) = h
            .send(
                "PUT",
                "/v1/mcp/servers/gone/tools/lookup",
                Some(SECRET_A),
                Some(json!({ "risk": "read", "digest": "a".repeat(64) })),
            )
            .await;
        assert_ne!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "an unrecognised connector borrowed some other entry's floor: {body}"
        );

        h.teardown().await;
    }

    /// Connecting the same handle again replaces the credential, and is the only
    /// way to — which is also the only way that proves the new one works first.
    #[tokio::test]
    async fn reconnecting_rotates_the_credential_and_keeps_the_declarations() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let mcp = agentos_app::mocks::FakeMcpServer::start(&["lookup"]).await;
        const REPLACEMENT: &str = "zzz-the-replacement-credential-8b21";

        let connect = async |token: &str| {
            h.send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "custom",
                    "server": "erp",
                    "url": mcp.url(),
                    "reach": "private",
                    "token": token,
                })),
            )
            .await
        };

        let (status, body) = connect(TOKEN).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let digest = body["tools"][0]["digest"]
            .as_str()
            .expect("digest")
            .to_owned();
        let (status, body) = h
            .send(
                "PUT",
                "/v1/mcp/servers/erp/tools/lookup",
                Some(SECRET_A),
                Some(json!({ "risk": "read", "digest": digest })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = connect(REPLACEMENT).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(h.server_count(h.a).await, 1, "rotation is not a second row");

        // The new one is what goes on the wire now, and neither is in the row.
        let sent = mcp.authorizations();
        assert!(
            sent.iter().any(|v| v == &format!("Bearer {REPLACEMENT}")),
            "{sent:?}"
        );
        let rows = h.servers_text(h.a).await;
        assert!(!rows.contains(TOKEN), "{rows}");
        assert!(!rows.contains(REPLACEMENT), "{rows}");

        // The declaration survived: it is keyed on (tenant, server, tool) and
        // the handle did not change.
        let (_, listed) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(listed["servers"][0]["tools"][0]["tool"], "lookup");
        assert_eq!(listed["servers"][0]["tools"][0]["risk"], "read");

        h.teardown().await;
    }

    /// A binding whose credential no longer opens is **left out of the fleet**
    /// with a reason, rather than bound without the header.
    ///
    /// The cause in the field is a rotated `AGENTOS_MASTER_KEY`. Binding anyway
    /// gets a 401 from a stranger's server, which points an operator at the
    /// customer's token when the fault is ours.
    #[tokio::test]
    async fn a_credential_that_no_longer_opens_is_a_named_failure_not_a_silent_bind() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let mcp = agentos_app::mocks::FakeMcpServer::start(&["lookup"]).await;

        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "custom",
                    "server": "erp",
                    "url": mcp.url(),
                    "reach": "private",
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let authenticated = mcp.authorizations().len();

        // A different deployment's master key: same rows, new cipher.
        let rotated = Credentials::from_master_key("a-different-master-key-entirely");
        rebind(&h.db, &h.fleets, &rotated, h.a, &CancellationToken::new()).await;

        let fleet = h.fleets.for_tenant(h.a);
        assert!(
            !fleet.is_bound(&slug("erp")),
            "it bound without the credential"
        );
        assert_eq!(
            fleet.failures().get(&slug("erp")).map(|f| f.code),
            Some("secret_decrypt_failed"),
            "the operator cannot tell this from a network problem: {:?}",
            fleet.failures()
        );
        assert_eq!(
            mcp.authorizations().len(),
            authenticated,
            "it dialled the server anyway, so the 401 would have blamed the customer"
        );

        // And the operator sees exactly that on the listing, which is the only
        // place they can see it.
        let (_, listed) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(listed["servers"][0]["status"], "failed");
        assert_eq!(
            listed["servers"][0]["error"]["code"],
            "secret_decrypt_failed"
        );
        assert!(!listed.to_string().contains(TOKEN), "{listed}");

        h.teardown().await;
    }
}
