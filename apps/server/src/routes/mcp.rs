//! `/v1/mcp`: the operator half of MCP — declaring a server, and the one path
//! by which a declaration becomes a live binding.
//!
//! [`agentos_app::mcp`] has been a complete MCP client for a while: an SSRF
//! check at bind time, one round trip per call, risk classes that only an
//! operator may lower, and a SHA-256 pin on the exact tool a human read. None of
//! it ran, because nothing ever created a binding. `mcp_servers` and
//! `mcp_tool_declarations` existed and could only be written with psql. This
//! module is the door, and the three things it has to get right are below.
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
//! policies add it, on `USING` and on `WITH CHECK` both. `0016` is what granted
//! `app_role` the DML to do that; see its header for why the privilege moved out
//! of `admin_tx_bypassing_rls`.
//!
//! Every mutation writes an audit row in the same transaction as the write.
//! These are administrative acts with a real blast radius — binding a URL,
//! granting a risk class — performed by an operator's key, and a change nobody
//! recorded is a change that did not happen.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentos_app::mcp::{BindFailure, Declaration, Fleet, McpServer, Reach, RiskClass};
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

/// What the handlers need: the database, and the registry to nudge.
#[derive(Clone)]
pub struct McpState {
    db: Db,
    fleets: Fleets,
}

impl McpState {
    /// Wire the routes to the pool and the registry `main` also gives the loop.
    pub const fn new(db: Db, fleets: Fleets) -> Self {
        Self { db, fleets }
    }
}

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before any handler here.
pub fn router(state: McpState) -> Router {
    Router::new()
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

/// One `mcp_servers` row joined to one of its declarations.
#[derive(Debug, FromRow)]
struct ServerRow {
    server: String,
    url: String,
    reach: String,
    created_at: DateTime<Utc>,
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
    /// The server's own one-liner. **A stranger wrote this**, which is exactly
    /// why it is here: it is half of what the human is deciding on, and it is
    /// rendered to an operator reading a JSON response, never to a model.
    description: Option<String>,
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
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let server =
        Slug::parse(&body.server).map_err(|err| ApiError::bad_request(format!("server: {err}")))?;
    agentos_app::mcp::vet_url(&body.url)
        .map_err(|_| ApiError::bad_request("url: must be an http(s) url with a host"))?;
    let reach = match body.reach.as_deref() {
        None => Reach::default(),
        Some(raw) => Reach::parse(raw)
            .ok_or_else(|| ApiError::bad_request("reach: expected \"public\" or \"private\""))?,
    };

    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    // No `WHERE tenant_id` and no `tenant_id` guesswork: the column is bound
    // from the transaction's own tenant, and RLS's WITH CHECK refuses anything
    // else. A duplicate handle trips the primary key, which `error.rs` renders
    // as a 409.
    sqlx::query("INSERT INTO mcp_servers (tenant_id, server, url, reach) VALUES ($1, $2, $3, $4)")
        .bind(principal.tenant_id.as_uuid())
        .bind(server.as_str())
        .bind(&body.url)
        .bind(reach.code())
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
        "mcp server declared"
    );

    Ok((
        StatusCode::CREATED,
        Json(ServerView {
            server: server.as_str().to_owned(),
            url: body.url,
            reach: reach.code().to_owned(),
            created_at: now,
            status: "pending",
            error: None,
            tools: Vec::new(),
        }),
    )
        .into_response())
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

    let bound = bind_now(&server, &binding).await?;
    let tools: Vec<DiscoveredTool> = bound
        .tools()
        .iter()
        .map(|(tool, found)| DiscoveredTool {
            tool: tool.as_str().to_owned(),
            wire_name: found.wire_name().to_owned(),
            digest: to_hex(found.digest()),
            risk: found.risk().code(),
            declared: found.is_declared(),
            // The one place a server's own prose leaves `Untrusted`, and it
            // leaves it into a JSON field an operator reads. It never reaches a
            // system prompt: `Fleet::inventory` hands the model names only.
            description: found
                .description()
                .map(|text| text.expose_for_parsing().clone()),
        })
        .collect();

    let addresses: Vec<String> = bound
        .pinned_addresses()
        .iter()
        .map(ToString::to_string)
        .collect();
    let body = json!({
        "server": server.as_str(),
        "url": binding.url,
        "reach": binding.reach.code(),
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
/// 2. The server is bound. A server that cannot be reached cannot have anything
///    declared on it, and that is the *point*: a digest is only ever accepted
///    against a live answer, so there is no way to write one that was not
///    observed.
/// 3. The tool has to exist on it — a 404 naming neither, because a handle that
///    is not in the inventory is not a tool.
/// 4. The digest has to match. If it does not, 409 `digest_mismatch`, and the
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

    let bound = bind_now(&server, &binding).await?;
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
/// Cancelled by the process-wide token, like the other three loops, so SIGTERM
/// ends it between binds rather than mid-connection. It never returns an error
/// and it never panics on a bad binding: a tenant whose configuration cannot be
/// read is logged and retried on the next tick, and a *server* that will not
/// bind is [`Fleet::bind`]'s business — it is left out with its reason recorded
/// and the tenant's other servers still work.
pub async fn run(
    db: Db,
    fleets: Fleets,
    mut rebinds: mpsc::Receiver<TenantId>,
    ct: CancellationToken,
) {
    // Startup: every tenant that has configured anything. Not gated on the
    // listener, so a slow MCP server delays tool availability and nothing else.
    rebind_all(&db, &fleets, &ct).await;

    let mut refresh = tokio::time::interval(REFRESH);
    refresh.tick().await; // The first tick is immediate; we just did it.

    loop {
        tokio::select! {
            () = ct.cancelled() => break,
            _ = refresh.tick() => rebind_all(&db, &fleets, &ct).await,
            received = rebinds.recv() => match received {
                Some(tenant) => rebind(&db, &fleets, tenant, &ct).await,
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
async fn rebind(db: &Db, fleets: &Fleets, tenant: TenantId, ct: &CancellationToken) {
    let mut tx = match db.tenant_tx(tenant).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%tenant, error = %err, "could not read mcp configuration");
            return;
        }
    };
    let fleet = Fleet::bind(&mut tx, ct).await;
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
async fn rebind_all(db: &Db, fleets: &Fleets, ct: &CancellationToken) {
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
        rebind(db, fleets, tenant, ct).await;
    }
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// One server per declaration row; `NULL`s in the right-hand columns for a
/// server with none. Ordered by server so [`list_servers`] can fold a run of
/// equal handles into one view without a second map.
const SELECT_SERVERS: &str = "\
    SELECT s.server, s.url, s.reach, s.created_at, d.tool, d.risk, d.digest \
      FROM mcp_servers s \
      LEFT JOIN mcp_tool_declarations d \
             ON d.tenant_id = s.tenant_id AND d.server = s.server \
     ORDER BY s.server, d.tool \
     LIMIT $1";

/// What one server needs to be bound.
struct Binding {
    url: String,
    reach: Reach,
    declared: std::collections::BTreeMap<Slug, Declaration>,
}

/// Load one server's URL, reach and declarations, or 404.
///
/// Another tenant's server is invisible under RLS and therefore simply not
/// found — never a 403, which would confirm the handle exists somewhere.
async fn load_binding(tx: &mut TenantTx<'_>, server: &Slug) -> Result<Binding, ApiError> {
    let rows: Vec<ServerRow> = sqlx::query_as(
        "SELECT s.server, s.url, s.reach, s.created_at, d.tool, d.risk, d.digest \
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

/// Bind one server synchronously, for the two routes that must.
///
/// The failure is the MCP client's own stable code, rendered as a 502 with the
/// detail the operator needs — which host, which address, which two tool names.
/// That is their own configuration reflected back, not a server-side error
/// leaking: see `error.rs` on what `detail` is for.
async fn bind_now(server: &Slug, binding: &Binding) -> Result<McpServer, ApiError> {
    McpServer::bind(
        server.clone(),
        &binding.url,
        &binding.declared,
        binding.reach,
        CancellationToken::new(),
    )
    .await
    .map_err(|err| {
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
        a: TenantId,
        b: TenantId,
    }

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
            Some(Self {
                app: crate::with_api_stack(
                    router(McpState::new(db.clone(), fleets.clone())),
                    db.clone(),
                    keys,
                ),
                db,
                fleets,
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

        rebind(&h.db, &h.fleets, h.a, &CancellationToken::new()).await;

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

        rebind(&h.db, &h.fleets, h.a, &CancellationToken::new()).await;

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
        rebind(&h.db, &h.fleets, h.a, &CancellationToken::new()).await;
        assert_eq!(h.fleets.for_tenant(h.a).failures().len(), 1);

        let (status, _) = h
            .send("DELETE", "/v1/mcp/servers/metadata", Some(SECRET_A), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        rebind_all(&h.db, &h.fleets, &CancellationToken::new()).await;
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
}
