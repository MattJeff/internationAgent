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
//! **There is now a third shape, and this surface refuses it.**
//! [`catalog::Provision::Host`] is a connector whose server ships only as a
//! stdio package, which we run for the tenant in a container this process does
//! not own — [`agentos_app::hosted`] is the whole design. It is refused here,
//! with a 503 and not a half-write, because no bridge runtime ships in this
//! workspace: there is nothing to start, so there is nothing this route's own
//! rule can be true of. The storage works and `app::mcp` binds such a row when
//! it is handed a runtime; what is missing is the runtime, and saying so with a
//! status code is more honest than storing what the customer typed.
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
use agentos_app::oauth::{self, Claimed, OauthClients};
use agentos_domain::ids::{Slug, TenantId};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
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
    /// The OAuth applications *this deployment* registered, one per connector.
    ///
    /// Deployment scope, not tenant scope — `agentos_app::oauth` argues the
    /// whole split. Shared with the binder loop for the same reason
    /// [`McpState::credentials`] is: the loop refreshes with the same client
    /// registration the callback exchanged with, and two of them is a deployment
    /// where a token can be obtained and never renewed.
    clients: Arc<OauthClients>,
    /// Where a provider sends the browser back, built once from `PUBLIC_HOST`.
    ///
    /// **One string, produced in one place**, because RFC 6749 requires the
    /// token request to repeat byte-for-byte the redirect URI the authorization
    /// request used, and it must also equal what is registered with the
    /// provider. Three copies of a URL that must be identical is two chances to
    /// get an `invalid_grant` whose message names nothing on our side.
    redirect_uri: Arc<str>,
    /// The connectors this process offers.
    ///
    /// [`catalog::CATALOG`] in every build that runs, threaded through rather
    /// than read from the `const` at four call sites — see
    /// [`catalog::find_in`] for why. It is a `&'static [Connector]` set once at
    /// wiring: nothing reachable from a request can name it, and every handler
    /// reads it the same way in every build.
    catalog: &'static [Connector],
}

impl McpState {
    /// Wire the routes to the pool, the registry `main` also gives the loop,
    /// the cipher it also gives the loop, and the OAuth registrations it also
    /// gives the loop.
    ///
    /// `public_host` is the deployment's origin. The callback path is appended
    /// here and nowhere else — see [`McpState::redirect_uri`].
    pub fn new(
        db: Db,
        fleets: Fleets,
        credentials: Credentials,
        clients: Arc<OauthClients>,
        public_host: &str,
    ) -> Self {
        Self {
            db,
            fleets,
            credentials,
            clients,
            redirect_uri: Arc::from(format!(
                "{}{CALLBACK_PATH}",
                public_host.trim_end_matches('/')
            )),
            catalog: catalog::CATALOG,
        }
    }

    /// The same state over a different catalogue.
    ///
    /// Tests only, and it is a *builder* rather than a branch: every handler
    /// still reads one field, identically, in both builds. What differs is the
    /// array, not the code — which is the distinction `agentos_app::mcp`'s
    /// module docs draw when they refuse a test-only path through a module.
    ///
    /// It exists because the routes below cannot otherwise be exercised at all:
    /// an OAuth connector's authorization server is a `&'static str` naming
    /// somebody else's host, so without this the callback's most dangerous line
    /// — the one that decides whose tenant a token is stored under — has no test
    /// that can reach it.
    #[cfg(test)]
    const fn over(mut self, catalog: &'static [Connector]) -> Self {
        self.catalog = catalog;
        self
    }
}

/// Where a provider redirects the browser back to.
///
/// A `const` and not configuration: it is registered with every provider by
/// hand, and a deployment that could change it would be a deployment whose
/// registrations silently stop matching.
const CALLBACK_PATH: &str = "/v1/mcp/oauth/callback";

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
        // The half of the OAuth dance that *does* have a tenant. The other half
        // is [`public_router`], and the split is the whole security story.
        .route("/v1/mcp/oauth/start", post(oauth_start))
        .with_state(state)
}

/// The one route here that a stranger may call, mounted **outside** the API
/// stack.
///
/// # Why it cannot be in [`router`]
///
/// The provider redirects a *browser* back to us and a browser holds no API
/// key. Putting this behind `with_api_stack` would answer every real callback
/// 401. So it sits beside `routes::webhooks` and the A2A agent card, in
/// `main.rs`'s `public` tier — request id, trace, body limit, timeout, and no
/// credential.
///
/// # What replaces the credential
///
/// The `state` query parameter, and nothing else. It selects one row of
/// `mcp_oauth_flows`, that row carries the tenant, and every other fact this
/// handler uses comes out of the same row. `agentos_app::oauth`'s module docs
/// enumerate the five properties that makes that safe — 256 bits of entropy,
/// stored only as a hash, single use by an atomic claim, ten-minute expiry, and
/// a tenant that is read and never written by anything on this path.
///
/// ponytail: no rate limit of its own, the same call and the same argument as
/// `routes::webhooks` — the limiter in `main.rs` is keyed on the tenant from an
/// API key and there is no key here. What this route does have is a body-less
/// GET, a lookup by primary key, and a 404 for every state that is not live. A
/// per-source limit belongs at the ingress, which is the only thing that can see
/// a client address.
pub fn public_router(state: McpState) -> Router {
    Router::new()
        .route(CALLBACK_PATH, axum::routing::get(oauth_callback))
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
    /// `NULL` for a binding we host — `0043_mcp_hosted.sql`. An `Option` and not
    /// a `String`, because a decode error here is a 500 on a listing for the
    /// whole tenant, and the row shape that causes it is one the schema permits.
    url: Option<String>,
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
    /// `NULL` for a hosted binding — `0043_mcp_hosted.sql`.
    url: Option<String>,
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
    /// `null` for a hosted binding, and that is the honest render: there is no
    /// address, and the one it runs at belongs to our infrastructure rather than
    /// to this tenant's configuration. `connector` is what says which server it
    /// is; the catalogue is where a client looks that up.
    url: Option<String>,
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
            // Always `Some` here: this route takes a URL and is the door for a
            // server somebody else runs. Hosting has no door on this surface.
            url: Some(body.url),
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
async fn catalog(
    State(state): State<McpState>,
    _principal: Principal,
) -> Result<Response, ApiError> {
    let connectors: Vec<Value> = state
        .catalog
        .iter()
        // An OAuth connector this deployment has no client registration for is
        // **not offered**. It is not greyed out and it does not answer 422 after
        // a click: it is absent, because a button that cannot work is worse than
        // no button, and the customer has no way to fix it — the missing thing is
        // an environment variable of ours. `agentos_app::oauth::OauthClients` is
        // the registry and `AGENTOS_OAUTH_CLIENTS` is where it comes from.
        //
        // This is also what makes adding a catalogue entry safe: an entry whose
        // application nobody has registered yet is invisible until somebody does.
        .filter(|c| offered(c, &state.clients))
        .map(|c| {
            json!({
                "connector": c.key,
                "label": c.label,
                // Which of the three shapes this is, and the field a UI has to
                // read before it decides what to render. `url` alone cannot
                // answer it any more: it is `null` for `customer`, where the
                // caller supplies an address, and `null` for `hosted`, where
                // nobody may. Two opposite meanings behind one absent value is
                // how a form ends up asking a customer for the address of a
                // container that does not exist yet.
                "provision": match c.provision {
                    catalog::Provision::Dial(_) => "dial",
                    catalog::Provision::Customer => "customer",
                    catalog::Provision::Host(_) => "hosted",
                },
                // Present only for `dial`; see the doc comment above.
                "url": c.url(),
                "reach": c.reach.code(),
                "credential": c.credential.code(),
                // What the consent screen will ask the customer to approve, so a
                // UI can say it before they click rather than after. `null` for
                // everything that is not OAuth.
                "scopes": c.credential.oauth().map(|o| o.scopes),
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
    let connector =
        catalog::find_in(state.catalog, &body.connector).ok_or_else(ApiError::not_found)?;

    // The URL and the reach come from the catalogue for everything we named, and
    // from the request only for `custom`. This is most of what the catalogue is
    // worth: a customer who cannot mistype GitHub's host cannot be walked into
    // binding one that looks like it.
    let (url, reach) = match connector.provision {
        catalog::Provision::Dial(url) => {
            if body.url.is_some() || body.reach.is_some() {
                return Err(ApiError::bad_request(format!(
                    "url and reach are not yours to set for the {:?} connector",
                    connector.key
                )));
            }
            (url.to_owned(), connector.reach)
        }
        // **The one branch that is not built, and it is refused rather than
        // half-built.** A hosted connector has no endpoint until a bridge
        // runtime starts one, and `agentos_app::hosted` deliberately ships no
        // runtime — so there is nothing for this route's own rule to be true
        // of: *a connection is validated only if it was tried*. Writing the row
        // anyway would be storing what the customer typed and calling it
        // connected, which is the meaning this route exists to refuse.
        //
        // A 503, not a 404 and not a 400: the connector is real, the request is
        // well formed, and what is missing is on our side and is temporary in
        // the only sense that matters — it is a deployment away. See
        // `agentos_app::hosted` for what that deployment is. The row shape
        // itself works and is exercised by
        // `mcp::tests::a_hosted_binding_starts_a_bridge_and_never_names_its_address`.
        //
        // **What is left to write here, when the branch opens, and in what
        // order.** The process cap is done and did not wait for this route:
        // `hosted::BRIDGES_PER_TENANT` is the number and `app::mcp::Fleet::bind`
        // applies it before any runtime is asked, so opening this branch cannot
        // hand a tenant an unbounded number of containers whatever it writes.
        // What is still owed *here* is the refusal a customer can read: count
        // this tenant's rows on hosted connectors and answer 409 past the cap,
        // in the same change that first lets one be written. Without it a
        // customer is told "verified" about a row that will bind as
        // `hosted_cap_reached` forever — a lie rather than a load, which is the
        // whole reason this half is second and not first.
        //
        // The count belongs in the same transaction as the INSERT below, and it
        // needs `pg_advisory_xact_lock(hashtextextended($tenant::text, 0))` in
        // front of it — the pattern `0027_positions.sql` already uses for a
        // per-tenant invariant — or two concurrent requests each count N and
        // each write. The catalogue cannot be a SQL predicate (`0043`'s
        // decision 2 says why), so the hosted connector keys go down as a
        // parameter read out of `catalog::CATALOG` at the call, never as a
        // stored copy.
        catalog::Provision::Host(_) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "hosting_unavailable",
                "this deployment runs no bridge runtime, so it cannot host this connector's server",
            ));
        }
        catalog::Provision::Customer => {
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
        // **Not a wildcard.** An OAuth connector reached through this route would
        // accept a pasted string as though it were the token a consent flow
        // issues — and then store it in the column `oauth::refresh_due` reads,
        // with no refresh token and no expiry beside it. It would bind, once,
        // and stop working at a moment nobody could predict, with a 401 from a
        // third party as the only symptom. `POST /v1/mcp/oauth/start` is the
        // door for these, and saying so is more useful than a 401 later.
        (Credential::OAuth(_), _) => {
            return Err(ApiError::bad_request(
                "connector: this one connects by consent — start at /v1/mcp/oauth/start",
            ));
        }
        (Credential::None, false) | (Credential::Bearer, true) => {}
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
// OAuth: a consent page instead of a pasted token
// ---------------------------------------------------------------------------

/// What starting a flow takes. Two fields, and neither of them is a URL.
///
/// There is deliberately no `scope`, no `redirect_uri` and no `authorize_url`
/// here. All three come from the catalogue entry and the deployment, and
/// `agentos_app::catalog::OAuth` argues why: the consent page is the screen a
/// person is *expected* to approve access on, so the address the browser is sent
/// to must come from this binary, and the scope string is the only thing that
/// bounds what the resulting token can do at the provider.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OauthStart {
    /// A key from [`catalog`] whose credential is OAuth.
    connector: String,
    /// The handle the binding will be stored under, exactly as [`connect`]
    /// takes one.
    server: String,
}

/// `POST /v1/mcp/oauth/start` — mint a consent URL for this tenant.
///
/// Writes one row and contacts nobody. The row is what the public callback will
/// later find, and it is the only thing that will connect that callback to this
/// tenant — so everything about it that matters is in `agentos_app::oauth`'s
/// module docs and in `0042_mcp_oauth`'s header.
///
/// # The response carries a capability
///
/// `authorize_url` has the `state` in it. Whoever holds that URL can complete
/// this flow. It goes to the tenant that asked for it, over TLS, in one
/// response — and into no log line and no audit payload, which is why the audit
/// row below records the *hash* instead. That hash is also what joins this row
/// to the one the callback writes, so "who asked for this connection" is
/// answerable without ever having stored the answer's key.
async fn oauth_start(
    State(state): State<McpState>,
    principal: Principal,
    body: Result<Json<OauthStart>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let server = handle(&body.server)?;
    // 404 and never a fallback, the same rule [`connect`] follows: a typo in a
    // connector name must not become "start a flow against something else".
    let connector =
        catalog::find_in(state.catalog, &body.connector).ok_or_else(ApiError::not_found)?;
    let now = Utc::now();
    let started = oauth::start(
        &state.clients,
        &state.credentials,
        principal.tenant_id,
        connector,
        &state.redirect_uri,
        now,
    )
    .map_err(|err| oauth_failed(&server, err))?;

    // **After `oauth::start`, and the order is the message.** A connector whose
    // URL the *customer* supplies cannot connect by consent — the flow row
    // carries no URL, so the callback would have nothing to put in
    // `mcp_servers.url`, which is `NOT NULL`, and the honest value would be the
    // empty string. But `catalog::CUSTOM` fails that test *and* is not an OAuth
    // connector at all, and "this one takes a pasted token" is the sentence that
    // tells a caller what to do instead. `oauth::start` produces that one, so it
    // goes first; this check is for the case it does not cover, which is an
    // OAuth entry with no endpoint of its own. `start` writes nothing, so
    // running it and then refusing costs one hash.
    // `url()` rather than the field this was written against: `waveI-i2`
    // replaced `Connector.url` with `Provision`, and `url()` is `Some` exactly
    // for `Provision::Dial` — an address we ship. A `Customer` entry has none
    // until the caller supplies one, and a `Host` entry has none until a bridge
    // mints one, and neither can be the endpoint a consent flow returns to. The
    // question is unchanged; only its spelling moved.
    if connector.url().is_none() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connector_has_no_endpoint",
            "this connector has no endpoint of its own to connect by consent",
        ));
    }

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    // The reaper, and the reason there is no job for one. RLS has already
    // narrowed this to the tenant's own rows, and a tenant's dead flows are
    // collected the next time that tenant starts one. See `0042_mcp_oauth`.
    sqlx::query("DELETE FROM mcp_oauth_flows WHERE expires_at < $1")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    sqlx::query(
        "INSERT INTO mcp_oauth_flows \
           (state_hash, tenant_id, connector, server, sealed_verifier, redirect_uri, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(started.state_hash.as_slice())
    .bind(principal.tenant_id.as_uuid())
    .bind(connector.key)
    .bind(server.as_str())
    .bind(started.sealed_verifier.as_slice())
    .bind(state.redirect_uri.as_ref())
    .bind(started.expires_at)
    .execute(&mut **tx)
    .await
    .map_err(StoreError::from)?;

    record(
        &mut tx,
        &principal.actor,
        json!({
            "event": "mcp.oauth.started",
            "server": server.as_str(),
            "connector": connector.key,
            // The hash, never the state, and never the URL that carries it.
            // This is the join key to the row the callback writes: it is what
            // makes "an operator asked for this, and it completed" one story
            // without storing the capability that completes it.
            "flow": to_hex(&started.state_hash),
        }),
        now,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        tenant_id = %principal.tenant_id,
        server = server.as_str(),
        connector = connector.key,
        // Not the URL. It has the state in it.
        flow = %to_hex(&started.state_hash),
        "mcp oauth flow started"
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "server": server.as_str(),
            "connector": connector.key,
            // Send the browser here. Treat it as a secret until it is used.
            "authorize_url": started.authorize_url,
            "expires_at": started.expires_at,
        })),
    )
        .into_response())
}

/// What a provider puts in the redirect.
///
/// **No `deny_unknown_fields`, and that is the one place on this surface where
/// it would be wrong.** Providers append their own parameters to a callback —
/// Google alone sends `scope`, `authuser`, `prompt` and sometimes `hd` — and
/// refusing them would refuse every real callback while passing every test
/// written against a fake one.
#[derive(Debug, Deserialize)]
struct CallbackParams {
    /// The authorization code, present when the human approved.
    code: Option<String>,
    /// The value [`oauth_start`] minted. The only thing tying this request to a
    /// tenant.
    state: String,
    /// The provider's refusal code when they did not. Read only to distinguish
    /// "declined" from "malformed"; **never rendered back**, because it is a
    /// stranger's string on a page a person is looking at.
    error: Option<String>,
}

/// One claimed flow, straight out of `mcp_oauth_flows`.
///
/// No `Debug` and no `Serialize`: it holds the sealed verifier, and the rule
/// [`BindingRow`] states applies unchanged — a row type that can be rendered is
/// a row type that ends up in a log line.
#[derive(FromRow)]
struct FlowRow {
    tenant_id: uuid::Uuid,
    connector: String,
    server: String,
    sealed_verifier: Vec<u8>,
    redirect_uri: String,
}

/// Claim a flow, once, or find nothing.
///
/// **The atomic single-use claim.** `consumed_at IS NULL` inside the `UPDATE`
/// means two callbacks racing on one state produce one winner; the loser sees no
/// row and is indistinguishable from an expired one, which is deliberate.
///
/// `admin_tx_bypassing_rls` is legitimate here for the same reason `rebind_all`
/// gives: the tenant is what this query is *for*, so there is nothing to scope
/// to until it answers. It is the narrowest possible use of that hatch — one
/// lookup, by primary key, over a table whose only other reader is scoped.
const CLAIM_FLOW: &str = "\
    UPDATE mcp_oauth_flows \
       SET consumed_at = now() \
     WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
 RETURNING tenant_id, connector, server, sealed_verifier, redirect_uri";

/// `GET /v1/mcp/oauth/callback` — the provider sends the browser here.
///
/// Public. See [`public_router`] for what stands in for a credential.
///
/// # The order, and why the claim commits before the exchange
///
/// ```text
///   hash the state -> claim the row (commit) -> exchange -> store -> bind -> page
/// ```
///
/// The claim is its own transaction and it commits first. If the exchange then
/// fails — the provider is down, the code was already redeemed, the clock is
/// wrong — the state is spent anyway and the customer clicks connect again. The
/// alternative is one transaction around the whole thing, and its failure mode is
/// a state that survives a crash mid-exchange and can be replayed. Burning a flow
/// costs one click; leaving one replayable costs the property this route is built
/// on.
///
/// # What is stored even when the bind fails
///
/// The tokens, always. This is the one place this module deliberately disagrees
/// with [`connect`], which throws away everything when the server exposes no
/// tools — and the difference is that an authorization code cannot be presented
/// twice. Discarding a successful exchange would cost the customer a second trip
/// through a consent screen to recover from a third party being briefly slow.
/// A pasted token has no such cost, which is why `connect` can afford to be
/// strict and this cannot.
///
/// The bind still happens, and the page still says what it found, so "connected"
/// means the same thing on both routes: somebody proved the endpoint answered.
async fn oauth_callback(
    State(state): State<McpState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let state_hash = oauth::state_hash(&params.state);

    // --- claim, and commit before anything else can fail --------------------
    let claimed: Option<FlowRow> = match state.db.admin_tx_bypassing_rls().await {
        Ok(mut tx) => {
            let row = sqlx::query_as(CLAIM_FLOW)
                .bind(state_hash.as_slice())
                .fetch_optional(&mut *tx)
                .await;
            match row {
                Ok(row) => {
                    if tx.commit().await.is_err() {
                        return page(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Something went wrong",
                            "The connection could not be recorded. Please try again.",
                        );
                    }
                    row
                }
                Err(err) => {
                    tracing::error!(error = %err, "could not claim an mcp oauth flow");
                    let _ = tx.rollback().await;
                    return page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Something went wrong",
                        "The connection could not be recorded. Please try again.",
                    );
                }
            }
        }
        Err(err) => {
            tracing::error!(error = %err, "could not open a transaction to claim an mcp oauth flow");
            return page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "The connection could not be recorded. Please try again.",
            );
        }
    };

    let Some(row) = claimed else {
        // Expired, already used, or never existed — one answer for all three,
        // deliberately. Distinguishing them would tell whoever is guessing which
        // states have ever been real.
        tracing::warn!(
            flow = %to_hex(&state_hash),
            "an mcp oauth callback named no live flow"
        );
        return page(
            StatusCode::NOT_FOUND,
            "This link is no longer valid",
            "It may have already been used, or it may have expired. Start the connection again.",
        );
    };

    let tenant_id = TenantId::from_uuid(row.tenant_id);
    let Ok(server) = Slug::parse(&row.server) else {
        tracing::error!(%tenant_id, server = row.server, "an mcp oauth flow has no policy handle");
        return page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "This connection was recorded under a name we cannot use.",
        );
    };
    // Exact, never `connector_or_custom`: the floor is a coarse guard and may
    // fall back, but the *token endpoint* may not. An unknown key here means the
    // catalogue changed under a live flow, and the honest answer is to refuse.
    let Some(connector) = catalog::find_in(state.catalog, &row.connector) else {
        tracing::error!(%tenant_id, connector = row.connector, "an mcp oauth flow names no connector");
        return page(
            StatusCode::NOT_FOUND,
            "This connector is no longer available",
            "Nothing was changed. Please start the connection again.",
        );
    };
    // `oauth_start` refuses a connector with no endpoint, so this is only
    // reachable if the catalogue changed under a live flow. A refusal rather
    // than an empty string: `mcp_servers.url` is `NOT NULL`, and a binding
    // stored against `""` is a row that can never bind and that nothing would
    // ever explain.
    let Some(endpoint) = connector.url() else {
        tracing::error!(%tenant_id, connector = connector.key, "an oauth flow names a connector with no endpoint");
        return page(
            StatusCode::NOT_FOUND,
            "This connector is no longer available",
            "Nothing was changed. Please start the connection again.",
        );
    };

    // --- the human said no --------------------------------------------------
    let Some(code) = params.code else {
        // `params.error` is a stranger's string and is not rendered. It is worth
        // one log line at a bounded length, because "the customer keeps
        // declining" and "the provider keeps rejecting our client" look
        // identical from here otherwise.
        tracing::warn!(
            %tenant_id,
            server = server.as_str(),
            connector = connector.key,
            declined = params.error.as_deref().map(|e| e.chars().take(64).collect::<String>()),
            "an mcp oauth flow came back without a code"
        );
        return page(
            StatusCode::BAD_REQUEST,
            "Not connected",
            "Access was not granted, so nothing was stored. You can close this window.",
        );
    };

    // --- exchange -----------------------------------------------------------
    let now = Utc::now();
    let flow = Claimed {
        tenant_id,
        connector,
        server: server.clone(),
        state_hash,
        sealed_verifier: row.sealed_verifier,
    };
    let sealed = match oauth::complete(
        &state.clients,
        &state.credentials,
        &flow,
        code,
        &row.redirect_uri,
        now,
    )
    .await
    {
        Ok(sealed) => sealed,
        Err(err) => {
            tracing::warn!(
                %tenant_id,
                server = server.as_str(),
                connector = connector.key,
                code = err.code(),
                "an mcp oauth exchange failed: {err}"
            );
            return page(
                StatusCode::BAD_GATEWAY,
                "Not connected",
                "The provider did not issue a token. Nothing was stored — please start again.",
            );
        }
    };

    // --- store --------------------------------------------------------------
    //
    // The same upsert `connect` writes, plus the two columns 0042 added. The
    // declarations survive by primary key, and if this connector's endpoint
    // moved their digests will not match what it serves — which `app::mcp`
    // demotes to destructive, needing a human, with no code here.
    let stored = store_oauth_binding(
        &state, tenant_id, &server, connector, endpoint, &sealed, now,
    )
    .await;
    if let Err(err) = stored {
        tracing::error!(
            %tenant_id,
            server = server.as_str(),
            // `?`, not `%`: `ApiError` is a problem document, not a `Display`.
            // Its own `Debug` carries the status and the stable code, which is
            // the pair an operator needs, and it holds nothing from the flow.
            error = ?err,
            "could not store an mcp oauth binding"
        );
        return page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "The provider granted access but we could not record it. Please start again.",
        );
    }
    state.fleets.ask_for_rebind(tenant_id);

    // --- and prove it, because "connected" has to mean the same thing here ---
    //
    // `connect` refuses to say the word without a round trip, and two routes
    // that both say "connected" must mean it the same way. The difference is
    // only what happens on failure: there, nothing is stored; here, the tokens
    // are already safe and this is a report.
    let bound = state
        .credentials
        .bind(
            tenant_id,
            server.clone(),
            endpoint,
            &std::collections::BTreeMap::new(),
            connector.reach,
            Some(sealed.access.as_slice()),
            CancellationToken::new(),
        )
        .await;
    let tools = match bound {
        Ok(bound) => {
            let count = bound.tools().len();
            let _ = bound.close().await;
            count
        }
        Err(err) => {
            tracing::warn!(
                %tenant_id,
                server = server.as_str(),
                code = err.code(),
                "an mcp oauth binding was stored but did not bind: {err}"
            );
            return page(
                StatusCode::OK,
                "Connected, but not answering yet",
                "Access was granted and stored. The server has not answered yet — \
                 it will be retried automatically.",
            );
        }
    };

    tracing::info!(
        %tenant_id,
        server = server.as_str(),
        connector = connector.key,
        tools,
        "mcp server connected over oauth and verified"
    );
    page(
        StatusCode::OK,
        "Connected",
        "Access was granted and the server answered. You can close this window.",
    )
}

/// Write the binding and its audit row, in one transaction.
///
/// A function because [`oauth_callback`] is already long and this is the part
/// that must be all-or-nothing: a stored token with no audit row is a credential
/// nobody recorded arriving.
#[allow(clippy::too_many_arguments)]
async fn store_oauth_binding(
    state: &McpState,
    tenant_id: TenantId,
    server: &Slug,
    connector: &'static Connector,
    endpoint: &str,
    sealed: &oauth::Sealed,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let mut tx = state.db.tenant_tx(tenant_id).await?;
    sqlx::query(
        "INSERT INTO mcp_servers \
           (tenant_id, server, url, reach, connector, sealed_token, \
            sealed_refresh_token, token_expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (tenant_id, server) DO UPDATE \
           SET url = excluded.url, reach = excluded.reach, \
               connector = excluded.connector, sealed_token = excluded.sealed_token, \
               sealed_refresh_token = excluded.sealed_refresh_token, \
               token_expires_at = excluded.token_expires_at, \
               updated_at = now()",
    )
    .bind(tenant_id.as_uuid())
    .bind(server.as_str())
    .bind(endpoint)
    .bind(connector.reach.code())
    .bind(connector.key)
    .bind(sealed.access.as_slice())
    .bind(sealed.refresh.as_deref())
    .bind(sealed.expires_at)
    .execute(&mut **tx)
    .await
    .map_err(StoreError::from)?;

    record(
        &mut tx,
        // Nobody is authenticated here — the caller is a browser following a
        // provider's redirect. `System` is the honest actor, and the operator
        // who asked for this is in the `mcp.oauth.started` row that carries the
        // same `flow`.
        &AuditActor::System,
        json!({
            "event": "mcp.oauth.connected",
            "server": server.as_str(),
            "connector": connector.key,
            // Whether, never what — and the same three facts 0040 argued for.
            "credential": true,
            "refreshable": sealed.refresh.is_some(),
            "token_expires_at": sealed.expires_at,
        }),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// One page for a person, in a browser, with no stylesheet and no script.
///
/// # Why this is HTML and not a `303` back to an application
///
/// Because there is no application to go back to. This deployment serves an API;
/// the customer arrived from whatever front end sent them to `authorize_url`, and
/// this server does not know what that was and must not learn it from a
/// parameter — a redirect target taken from a request is an open redirect, and an
/// open redirect on the one route that handles authorization codes is the exact
/// place not to have one.
///
/// ponytail: four lines of HTML, no template engine, no `<style>`. The ceiling is
/// that it looks like 1994. The upgrade is a `303` to a configured
/// `AGENTOS_OAUTH_RETURN_TO` — one variable, checked at boot against a fixed
/// origin — the day there is a front end to return to.
///
/// **Nothing dynamic reaches this function.** Every string it is called with is a
/// literal in this file. That is not a convention, it is why there is no escaping
/// here: a provider's `error`, a server's description and a token are all things
/// that would need it, and none of them can get here.
fn page(status: StatusCode, headline: &'static str, detail: &'static str) -> Response {
    (
        status,
        Html(format!(
            "<!doctype html><meta charset=utf-8><title>{headline}</title>\
             <h1>{headline}</h1><p>{detail}</p>"
        )),
    )
        .into_response()
}

/// How a flow failure reads to the tenant that asked for one.
///
/// Only [`oauth_start`] uses it: the callback answers a browser with a page, not
/// a problem document. The stable code goes in the body — `connector_is_not_oauth`
/// and `connector_not_registered` are different problems with different fixes,
/// and only the second one is ours.
fn oauth_failed(server: &Slug, err: oauth::OauthError) -> ApiError {
    tracing::warn!(
        server = server.as_str(),
        code = err.code(),
        "mcp oauth start failed: {err}"
    );
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        err.code(),
        "this connector cannot be connected by oauth here",
    )
    .with_detail(err.to_string())
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
    clients: Arc<OauthClients>,
    mut rebinds: mpsc::Receiver<TenantId>,
    ct: CancellationToken,
) {
    // Startup: every tenant that has configured anything. Not gated on the
    // listener, so a slow MCP server delays tool availability and nothing else.
    rebind_all(&db, &fleets, &credentials, &clients, &ct).await;

    let mut refresh = tokio::time::interval(REFRESH);
    refresh.tick().await; // The first tick is immediate; we just did it.

    loop {
        tokio::select! {
            () = ct.cancelled() => break,
            _ = refresh.tick() => rebind_all(&db, &fleets, &credentials, &clients, &ct).await,
            received = rebinds.recv() => match received {
                Some(tenant) => rebind(&db, &fleets, &credentials, &clients, tenant, &ct).await,
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
    clients: &OauthClients,
    tenant: TenantId,
    ct: &CancellationToken,
) {
    // **Before the bind, in its own committed transaction, and on this tick.**
    //
    // An OAuth access token expires and a refresh token does not, so something
    // has to swap one for the other before an employee needs it — and this loop
    // is already awake for exactly this tenant, exactly this often. A second
    // timer over the same rows is how a token gets renewed by one task while
    // another binds with the copy it read a moment earlier, and the symptom is a
    // 401 nobody can reproduce.
    //
    // It is a separate transaction because `Fleet::bind` runs read-only and
    // rolls back: a refresh *writes*, and a write that is rolled back is a
    // provider round trip whose result was thrown away — with, for a provider
    // that rotates its refresh tokens, the stored one now dead. Refresh, commit,
    // then read.
    refresh_tokens(db, credentials, clients, tenant).await;

    let mut tx = match db.tenant_tx(tenant).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%tenant, error = %err, "could not read mcp configuration");
            return;
        }
    };
    // `None`: this deployment runs no bridge runtime, because none exists to
    // run — `agentos_app::hosted` is the contract for one and deliberately
    // ships no implementation. Every hosted binding therefore fails to bind
    // with `hosting_unavailable`, which `list_servers` renders, and no tenant
    // gets tools from a container nobody started. The day a runtime is
    // deployed, this is the line that hands it in, and nothing else here
    // changes.
    //
    // It cannot be handed in without a number: `Bridges::new` takes the
    // per-tenant cap, and the value it is required to be passed here is
    // `hosted::BRIDGES_PER_TENANT`, which is zero until somebody answers the
    // question written on it. So the wiring change is a `Some(...)` that still
    // starts nothing, and turning hosting on is a second, deliberate edit to a
    // constant — which is the order that stops "wire it up" from also meaning
    // "and let a customer run as many processes as they like on our box".
    let fleet = Fleet::bind(&mut tx, credentials, None, ct).await;
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
/// Cross-tenant by nature, like the outbox poller, and legitimately so: there
/// is no tenant to scope to until this query answers. It reads one column of
/// one table and writes nothing.
///
/// This used to say "the third `admin_tx_bypassing_rls` in the codebase". There
/// are twenty-six outside tests, and there were already more than three when
/// that was written. `crates/store/src/db.rs` asks for the escape hatch to be
/// justified where it is used and *not* counted — a number in a doc comment is
/// wrong the day after it is written, and the last one was wrong in the
/// direction that reads as reassurance. `grep -rn admin_tx_bypassing_rls` is
/// the list.
async fn rebind_all(
    db: &Db,
    fleets: &Fleets,
    credentials: &Credentials,
    clients: &OauthClients,
    ct: &CancellationToken,
) {
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
        rebind(db, fleets, credentials, clients, tenant, ct).await;
    }
}

/// Renew this tenant's OAuth tokens that are close to expiring.
///
/// Its own transaction, always committed, and every failure inside it is
/// already swallowed and logged by `agentos_app::oauth::refresh_due` — one
/// provider being down must not stop the tenant's other bindings, or the other
/// tenants, from being rebound. So this returns nothing: there is no outcome the
/// caller could act on that the next tick will not act on anyway.
async fn refresh_tokens(
    db: &Db,
    credentials: &Credentials,
    clients: &OauthClients,
    tenant: TenantId,
) {
    let mut tx = match db.tenant_tx(tenant).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(%tenant, error = %err, "could not open a transaction to refresh oauth tokens");
            return;
        }
    };
    // `catalog::CATALOG` and not `state.catalog`: the binder loop is not a
    // route and holds no `McpState`. The array is the same one in every build
    // that runs — see `catalog::find_in`, and `McpState::catalog` above, which
    // is that same constant threaded a different way for the same reason.
    let written =
        oauth::refresh_due(&mut tx, credentials, clients, catalog::CATALOG, Utc::now()).await;
    // Committed unconditionally, and the `if written == 0 { rollback }` that
    // used to stand here is deleted rather than corrected.
    //
    // It was an optimisation — "nothing was written, so a rollback is the
    // cheaper unwind" — resting on a count meaning exactly what the writer
    // thought it meant. `refresh_due` now also *parks* a binding whose refresh
    // token the provider refused, which is a write; a count that missed it
    // would roll the park back every tick and the loop would go on presenting a
    // dead credential to somebody else's authorization server forever. That is
    // a seam where the bug is invisible on both sides: each function is right
    // about itself.
    //
    // An empty COMMIT once per tenant per five-minute tick is not worth a
    // second place for the two of them to disagree. `written` survives as a log
    // field and nothing branches on it.
    if let Err(err) = tx.commit().await {
        // The tokens the provider issued are lost with the transaction, and the
        // old ones are still in the row and still valid until they expire. The
        // next tick tries again. What is NOT survivable is a provider that
        // rotated its refresh token, which is why this is an error and not a
        // warning: that binding is now on a countdown to needing a human.
        tracing::error!(%tenant, written, error = %err, "could not commit refreshed oauth tokens");
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
    /// `None` for a hosted binding: there is no stored address, and
    /// [`bind_now`] refuses rather than inventing one.
    url: Option<String>,
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
/// A hosted binding cannot be bound here at all, and the refusal is in this one
/// function rather than in its two callers: [`discover`] and [`declare_tool`]
/// both route through it, so a guard in either would leave the other reaching
/// for a `url` that a hosted row does not have.
///
/// The connector decides, not the presence of the URL — the same authority
/// `app::mcp::provisioned` uses, so the two readers cannot disagree about what a
/// row is.
async fn bind_now(
    credentials: &Credentials,
    tenant_id: TenantId,
    server: &Slug,
    binding: &Binding,
) -> Result<McpServer, ApiError> {
    let url = match (binding.connector.package(), binding.url.as_deref()) {
        // Hosted: binding it means starting a bridge, and this deployment runs
        // no runtime to start one in. See `connect` for the whole argument and
        // `agentos_app::hosted` for what a deployment has to add.
        (Some(_), _) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "hosting_unavailable",
                "this deployment runs no bridge runtime, so this server cannot be reached",
            ));
        }
        (None, Some(url)) => url,
        // A dialled binding with no address. Unreachable through any route
        // here, and the honest answer if a hand-written row ever makes it
        // reachable: there is nothing to contact, which is not the same failure
        // as contacting it and being refused.
        (None, None) => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "binding_has_no_endpoint",
                "this binding has no url and names no connector we host",
            ));
        }
    };
    credentials
        .bind(
            tenant_id,
            server.clone(),
            url,
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

/// Whether this deployment can actually offer this connector.
///
/// A named function and not an inline closure, because it is the whole of the
/// rule and the rule is worth a test of its own: a connector that needs no OAuth
/// registration is always offered, and one that does is offered only where the
/// registration exists. There is no third answer and no "offer it and fail
/// later".
fn offered(connector: &Connector, clients: &OauthClients) -> bool {
    connector.credential.oauth().is_none() || clients.has(connector.key)
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
    use chrono::SubsecRound;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The cloud metadata endpoint. Link-local, so `McpServer::bind` refuses it
    /// for both reaches — and it is a literal, so the refusal costs no DNS.
    const METADATA: &str = "http://169.254.169.254/mcp";

    struct Harness {
        /// The unauthenticated tier: the provider's callback and nothing else.
        public: Router,
        /// The deployment's OAuth registrations, shared with the state.
        clients: Arc<OauthClients>,
        /// Kept so a test can stand the same routes up over another catalogue.
        keys: ApiKeys,
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
            // One registration, for a connector that does not use OAuth. It is
            // there so `has` answers something, and its uselessness is the
            // point: `CATALOG` holds no OAuth entry to register for, which
            // `agentos_app::catalog` argues at length. The predicate itself is
            // tested directly in `an_unregistered_oauth_connector_is_not_offered`.
            let clients = Arc::new(
                OauthClients::parse("github:cid:csecret,acme:acme-client-id:acme-client-secret")
                    .expect("clients"),
            );
            let state = McpState::new(
                db.clone(),
                fleets.clone(),
                credentials.clone(),
                clients.clone(),
                "https://agentos.test",
            );
            Some(Self {
                // `state` is built above with the five-argument `McpState::new`
                // that `waveI-i1` introduced; the `Keyring` is `waveJ-j1`'s,
                // which made the environment keyring one half of a resolver
                // whose other half is the `api_keys` table. Both are needed and
                // neither replaces the other.
                app: crate::with_api_stack(
                    router(state.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(
                        keys.clone(),
                        db.clone(),
                        crate::auth::TEST_MASTER_KEY,
                    ),
                ),
                // The public tier, with no API key layer over it — exactly how
                // `main.rs` mounts it, because a callback that needed one could
                // never arrive.
                public: public_router(state),
                db,
                fleets,
                credentials,
                clients,
                keys,
                a,
                b,
            })
        }

        /// Hit the **public** tier, the way a provider's redirect does: a `GET`,
        /// no API key, no `Content-Type`.
        async fn callback(&self, query: &str) -> (StatusCode, String) {
            let req = HttpRequest::builder()
                .method("GET")
                .uri(format!("{CALLBACK_PATH}?{query}"))
                .body(Body::empty())
                .expect("request");
            let response = self.public.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }

        /// Plant a flow row the way [`oauth_start`] would have.
        ///
        /// Directly, because the route cannot start a real one: `CATALOG` holds
        /// no OAuth entry (its own docs argue why), and these tests are about
        /// what the *callback* does with a row — the claim, the replay, the
        /// tenant — every one of which happens before a connector is contacted.
        async fn plant_flow(
            &self,
            tenant: TenantId,
            connector: &str,
            server: &str,
            expires_at: DateTime<Utc>,
        ) -> String {
            let state = format!("state-{}", uuid::Uuid::new_v4().simple());
            let sealed = self
                .credentials
                .seal(
                    tenant,
                    &Slug::parse(server).expect("slug"),
                    Some("v".to_owned()),
                )
                .expect("seal")
                .expect("some");
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            sqlx::query(
                "INSERT INTO mcp_oauth_flows                    (state_hash, tenant_id, connector, server, sealed_verifier, redirect_uri, expires_at)                  VALUES ($1, $2, $3, $4, $5, 'https://agentos.test/v1/mcp/oauth/callback', $6)",
            )
            .bind(oauth::state_hash(&state).as_slice())
            .bind(tenant.as_uuid())
            .bind(connector)
            .bind(server)
            .bind(sealed.as_slice())
            .bind(expires_at)
            .execute(&mut **tx)
            .await
            .expect("insert flow");
            tx.commit().await.expect("commit");
            state
        }

        /// `consumed_at` for one flow, by its state.
        async fn consumed(&self, tenant: TenantId, state: &str) -> Option<DateTime<Utc>> {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let at =
                sqlx::query_scalar("SELECT consumed_at FROM mcp_oauth_flows WHERE state_hash = $1")
                    .bind(oauth::state_hash(state).as_slice())
                    .fetch_one(&mut **tx)
                    .await
                    .expect("flow row");
            tx.rollback().await.expect("rollback");
            at
        }

        /// The same routes, over a catalogue this test wrote.
        ///
        /// Returns the authenticated tier and the public one, exactly as
        /// `main.rs` mounts them — the OAuth flow is split across the two and a
        /// test that only had one of them could not follow it.
        fn over(&self, catalog: &'static [Connector]) -> (Router, Router) {
            let state = McpState::new(
                self.db.clone(),
                self.fleets.clone(),
                self.credentials.clone(),
                self.clients.clone(),
                "https://agentos.test",
            )
            .over(catalog);
            (
                crate::with_api_stack(
                    router(state.clone()),
                    self.db.clone(),
                    // The fixture keeps `ApiKeys`, not a `Keyring`: these tests
                    // present environment keys only, so the table half of the
                    // resolver `waveJ-j1` introduced is never reached. Built
                    // here rather than stored, so the fixture keeps saying what
                    // it actually holds.
                    crate::auth::Keyring::new(
                        self.keys.clone(),
                        self.db.clone(),
                        crate::auth::TEST_MASTER_KEY,
                    ),
                ),
                public_router(state),
            )
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
            &h.clients,
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
            &h.clients,
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
            &h.clients,
            h.a,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(h.fleets.for_tenant(h.a).failures().len(), 1);

        let (status, _) = h
            .send("DELETE", "/v1/mcp/servers/metadata", Some(SECRET_A), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        rebind_all(
            &h.db,
            &h.fleets,
            &h.credentials,
            &h.clients,
            &CancellationToken::new(),
        )
        .await;
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
        assert_eq!(custom["provision"], "customer");

        let github = connectors
            .iter()
            .find(|c| c["connector"] == "github")
            .expect("github is catalogued");
        assert_eq!(github["url"], "https://api.githubcopilot.com/mcp/");
        assert_eq!(github["reach"], "public");
        assert_eq!(github["provision"], "dial");
        assert_eq!(
            github["floor"], "write",
            "the floor has to be visible or a UI cannot grey out what it must not offer"
        );

        // **The hosted entry, and why `provision` had to exist.** Its `url` is
        // null exactly like `custom`'s, and the two mean opposite things: one
        // asks the customer for an address and the other refuses to let anybody
        // name one. A UI that branched on `url == null` would put a text field
        // in front of a customer for a container that does not exist yet.
        let hosted = connectors
            .iter()
            .find(|c| c["connector"] == "orizn-visa")
            .expect("the hosted entry is catalogued");
        assert_eq!(hosted["url"], Value::Null);
        assert_eq!(hosted["provision"], "hosted");
        assert_eq!(
            hosted["credential"], "bearer",
            "the customer still pastes one string; where it goes is ours to know"
        );

        h.teardown().await;
    }

    /// **Hosting is refused until a runtime is deployed, and nothing is
    /// written.**
    ///
    /// The customer-visible half of `agentos_app::hosted`'s "what has to be
    /// deployed". The connector is real and catalogued, the request is well
    /// formed, and the answer is a 503 with a stable code — not a stored row
    /// that would list as `pending` forever and never bind.
    ///
    /// The second half of the assertion is the one that matters: a refusal that
    /// still wrote the binding would be exactly the half-connected state
    /// [`connect`] exists to prevent, and it would be invisible in the response.
    #[tokio::test]
    async fn hosting_is_refused_until_a_runtime_is_deployed_and_nothing_is_stored() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/connect",
                Some(SECRET_A),
                Some(json!({
                    "connector": "orizn-visa",
                    "server": "visa",
                    "token": TOKEN,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["code"], "hosting_unavailable", "{body}");

        let (status, body) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["servers"].as_array().map(Vec::len),
            Some(0),
            "a refused connect wrote a binding anyway: {body}"
        );

        // And the token it was handed did not survive the refusal anywhere a
        // response can reach.
        assert!(!body.to_string().contains(TOKEN), "{body}");

        h.teardown().await;
    }

    /// **A hosted row written by hand still reads, lists and refuses cleanly.**
    ///
    /// Until a runtime is deployed, the only way a hosted binding exists is the
    /// way every MCP binding existed before `0019_mcp_operator_writes.sql`: an
    /// operator with psql. That makes this the *reachable* shape, not a
    /// hypothetical one, and two things about it are easy to get wrong and both
    /// were:
    ///
    /// * `url` is NULL, so a row type that reads it as `String` fails to decode
    ///   — and it is the **listing** that reads it, so one hand-written row
    ///   would 500 the whole tenant's server list.
    /// * [`discover`] binds inline, and a hosted binding has no address to bind
    ///   to. It has to refuse with the hosting code rather than reach for a URL
    ///   that is not there.
    #[tokio::test]
    async fn a_hosted_row_lists_without_a_url_and_refuses_to_be_discovered() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector) \
             VALUES ($1, 'visa', NULL, 'public', 'orizn-visa')",
        )
        .bind(h.a.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("a hosted row is storable");
        tx.commit().await.expect("commit");

        let (status, body) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = &body["servers"].as_array().expect("a list")[0];
        assert_eq!(listed["server"], "visa");
        assert_eq!(
            listed["url"],
            Value::Null,
            "a hosted binding has no address of its own to render"
        );
        assert_eq!(listed["connector"], "orizn-visa");

        // The binder reaches it and records why it is not bound, so the
        // operator reading this list learns something they can act on.
        rebind(
            &h.db,
            &h.fleets,
            &h.credentials,
            &h.clients,
            h.a,
            &CancellationToken::new(),
        )
        .await;
        let (_, body) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        let listed = &body["servers"].as_array().expect("a list")[0];
        assert_eq!(listed["status"], "failed", "{body}");
        assert_eq!(listed["error"]["code"], "hosting_unavailable", "{body}");

        // And the two routes that bind inline refuse the same way rather than
        // dialling something that is not there.
        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/servers/visa/discover",
                Some(SECRET_A),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["code"], "hosting_unavailable", "{body}");

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
            &h.clients,
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
            &h.clients,
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
        rebind(
            &h.db,
            &h.fleets,
            &rotated,
            &h.clients,
            h.a,
            &CancellationToken::new(),
        )
        .await;

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

    // -- OAuth: the public callback and what ties it to a tenant -------------

    /// A connector this deployment has not registered is not on the menu.
    ///
    /// The predicate directly, because `CATALOG` has no OAuth entry to filter —
    /// see its own docs. This is the rule that makes adding one safe: it is
    /// invisible until an application is registered, so nobody ever clicks a
    /// button that cannot work.
    #[test]
    fn an_unregistered_oauth_connector_is_not_offered() {
        const ENDPOINTS: catalog::OAuth = catalog::OAuth {
            authorize: "https://accounts.example.com/authorize",
            token: "https://accounts.example.com/token",
            scopes: "read",
            auth: catalog::ClientAuth::Basic,
        };
        let entry = Connector {
            key: "example",
            credential: Credential::OAuth(&ENDPOINTS),
            ..catalog::CUSTOM
        };
        let registered = OauthClients::parse("example:id:secret").expect("parse");

        assert!(offered(&entry, &registered));
        assert!(!offered(&entry, &OauthClients::default()));
        // A connector that needs no registration is always offered — including
        // in a deployment that has registered nothing at all.
        for connector in catalog::CATALOG {
            assert!(
                offered(connector, &OauthClients::default()),
                "{}",
                connector.key
            );
        }
    }

    /// The route is on the tier a browser can reach, and only that one.
    #[tokio::test]
    async fn the_callback_is_reachable_without_a_credential_and_only_there() {
        let Some(h) = Harness::new().await else {
            return;
        };

        // No API key, and it is not a 401. It is the route's own answer.
        let (status, _) = h.callback("state=nothing-was-ever-minted").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no key must not mean 401");

        // And it is NOT on the authenticated tier: mounting it there would
        // answer every real callback 401, because a provider's redirect is a
        // browser and a browser has no key.
        let (status, _) = h
            .send(
                "GET",
                &format!("{CALLBACK_PATH}?state=x"),
                Some(SECRET_A),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "the api tier must not serve the callback"
        );
    }

    /// **The replay mutation.** One state, two callbacks, one winner — and the
    /// claim commits before anything that can fail.
    ///
    /// The first call gets past the claim and then fails at the exchange, which
    /// is exactly the shape being asserted: `consumed_at` is set even though the
    /// request did not succeed. Delete `AND consumed_at IS NULL` from
    /// [`CLAIM_FLOW`] and the second call stops being a 404, which is a state
    /// that can be presented forever.
    #[tokio::test]
    async fn a_state_is_spent_the_first_time_it_is_presented() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let state = h
            .plant_flow(
                h.a,
                "github",
                "gh",
                Utc::now() + chrono::TimeDelta::minutes(5),
            )
            .await;

        assert!(h.consumed(h.a, &state).await.is_none(), "not yet");

        // `github` is a real catalogue entry that takes a pasted bearer, so the
        // exchange refuses — after the claim, which is the point.
        let (first, body) = h.callback(&format!("state={state}&code=whatever")).await;
        assert_eq!(first, StatusCode::BAD_GATEWAY, "{body}");
        assert!(
            h.consumed(h.a, &state).await.is_some(),
            "the claim must commit before the exchange, or a crash mid-exchange \
             leaves a replayable state"
        );

        let (second, body) = h.callback(&format!("state={state}&code=whatever")).await;
        assert_eq!(
            second,
            StatusCode::NOT_FOUND,
            "a state must not be presentable twice: {body}"
        );
    }

    /// An expired flow is the same 404 as one that never existed.
    #[tokio::test]
    async fn an_expired_flow_and_an_invented_one_are_the_same_answer() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let stale = h
            .plant_flow(
                h.a,
                "github",
                "gh",
                Utc::now() - chrono::TimeDelta::seconds(1),
            )
            .await;

        let (expired, expired_body) = h.callback(&format!("state={stale}&code=c")).await;
        let (invented, invented_body) = h.callback("state=never-minted&code=c").await;
        assert_eq!(expired, StatusCode::NOT_FOUND);
        assert_eq!(invented, StatusCode::NOT_FOUND);
        assert_eq!(
            expired_body, invented_body,
            "telling the two apart tells whoever is guessing which states were real"
        );
        assert!(
            h.consumed(h.a, &stale).await.is_none(),
            "an expired flow is not claimed, so it can still be reaped"
        );
    }

    /// **The tenant mutation.** The callback reads its tenant from the row it
    /// found, and nothing in the request can move it.
    ///
    /// Two tenants hold a flow each. One state is presented, with the *other*
    /// tenant's API key on the request and its id in the query string — the two
    /// shapes a "take the tenant from the request" bug takes. Only the tenant
    /// whose row was found is touched.
    #[tokio::test]
    async fn a_callback_names_no_tenant_and_cannot_choose_one() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let mine = h
            .plant_flow(
                h.a,
                "github",
                "gh",
                Utc::now() + chrono::TimeDelta::minutes(5),
            )
            .await;
        let theirs = h
            .plant_flow(
                h.b,
                "github",
                "gh",
                Utc::now() + chrono::TimeDelta::minutes(5),
            )
            .await;

        // Tenant B's key, tenant B's id, tenant A's state. Extra parameters are
        // accepted on purpose — providers append their own — so this is exactly
        // what an attacker would send.
        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "{CALLBACK_PATH}?state={mine}&code=c&tenant_id={}&tenant={}",
                h.b.as_uuid(),
                h.b.as_uuid()
            ))
            .header(header::AUTHORIZATION, format!("Bearer {SECRET_B}"))
            .body(Body::empty())
            .expect("request");
        let response = h.public.clone().oneshot(req).await.expect("service");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        assert!(
            h.consumed(h.a, &mine).await.is_some(),
            "the row that was found is the one that was spent"
        );
        assert!(
            h.consumed(h.b, &theirs).await.is_none(),
            "the tenant named in the request must have had nothing happen to it"
        );
    }

    /// A human who declines leaves nothing behind but a spent state.
    #[tokio::test]
    async fn a_refused_consent_stores_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let state = h
            .plant_flow(
                h.a,
                "github",
                "declined",
                Utc::now() + chrono::TimeDelta::minutes(5),
            )
            .await;

        let (status, body) = h
            .callback(&format!("state={state}&error=access_denied"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("Not connected"), "{body}");
        assert!(
            !body.contains("access_denied"),
            "a provider's error string is a stranger's text and is not rendered: {body}"
        );

        let (listed, _) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(listed, StatusCode::OK);
        assert!(
            h.consumed(h.a, &state).await.is_some(),
            "declining still spends the state"
        );
    }

    /// The upsert the callback writes, on its own.
    ///
    /// Called directly because the exchange in front of it needs an
    /// authorization server, and this is the half with eight bound parameters in
    /// it. What it has to get right: the access token in the column
    /// `Fleet::bind` reads, the refresh token in the one only
    /// `oauth::refresh_due` reads, an expiry the refresh query can select on,
    /// and an audit row that says *whether*, never *what*.
    #[tokio::test]
    async fn a_stored_oauth_binding_lands_in_the_columns_that_read_it() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let state = McpState::new(
            h.db.clone(),
            h.fleets.clone(),
            h.credentials.clone(),
            h.clients.clone(),
            "https://agentos.test",
        );
        let server = Slug::parse("gh-oauth").expect("slug");
        // `timestamptz` holds microseconds, and the assertion below compares
        // this instant against the one the refresh loop selects on after a
        // round trip. macOS hands out a microsecond clock so nothing is lost;
        // Linux hands out nanoseconds and the last three digits go. Three
        // sibling tests carried this same defect and were green on every
        // laptop for as long as they existed.
        let expires_at = (Utc::now() + chrono::TimeDelta::hours(1)).trunc_subsecs(6);
        let sealed = oauth::Sealed {
            access: h
                .credentials
                .seal(h.a, &server, Some("the-access-token".to_owned()))
                .expect("seal")
                .expect("some"),
            refresh: Some(
                h.credentials
                    .seal(h.a, &server, Some("the-refresh-token".to_owned()))
                    .expect("seal")
                    .expect("some"),
            ),
            expires_at,
        };

        store_oauth_binding(
            &state,
            h.a,
            &server,
            catalog::find("github").expect("github"),
            "https://api.githubcopilot.com/mcp/",
            &sealed,
            Utc::now(),
        )
        .await
        .expect("store");

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let row: (String, String, bool, bool, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT url, connector, sealed_token IS NOT NULL, \
                    sealed_refresh_token IS NOT NULL, token_expires_at \
               FROM mcp_servers WHERE server = $1",
        )
        .bind(server.as_str())
        .fetch_one(&mut **tx)
        .await
        .expect("row");
        tx.rollback().await.expect("rollback");
        assert_eq!(row.0, "https://api.githubcopilot.com/mcp/");
        assert_eq!(row.1, "github", "the floor is enforced against this key");
        assert!(row.2 && row.3, "both envelopes are stored");
        assert_eq!(row.4, Some(expires_at), "the refresh loop selects on this");

        // The listing says a credential exists and cannot say more: the query it
        // reads does not project either column.
        let (status, body) = h.send("GET", "/v1/mcp/servers", Some(SECRET_A), None).await;
        assert_eq!(status, StatusCode::OK);
        let rendered = body.to_string();
        assert!(rendered.contains("\"has_credential\":true"), "{rendered}");
        for secret in ["the-access-token", "the-refresh-token"] {
            assert!(!rendered.contains(secret), "{secret} leaked: {rendered}");
        }

        let trail = h.audit_text(h.a).await;
        assert!(trail.contains("mcp.oauth.connected"), "{trail}");
        assert!(trail.contains("\"refreshable\": true"), "{trail}");
        for secret in ["the-access-token", "the-refresh-token"] {
            assert!(
                !trail.contains(secret),
                "{secret} leaked into the trail: {trail}"
            );
        }
    }

    /// Starting a flow refuses the two connectors that cannot have one, and the
    /// refusals are different sentences because the fixes are different.
    #[tokio::test]
    async fn a_flow_can_only_start_for_a_connector_that_has_one() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/oauth/start",
                Some(SECRET_A),
                Some(json!({"connector": "not-a-connector", "server": "erp"})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // `custom` takes a pasted token and has no authorization server.
        let (status, body) = h
            .send(
                "POST",
                "/v1/mcp/oauth/start",
                Some(SECRET_A),
                Some(json!({"connector": "custom", "server": "erp"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["code"], "connector_is_not_oauth", "{body}");

        // And nothing was written for a refusal.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let flows: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_oauth_flows")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!(flows, 0, "a refused start leaves no flow behind");
    }

    // -- OAuth, end to end, against an authorization server we stand up -------
    //
    // The catalogue is a `const` of `&'static str`s naming other people's hosts,
    // so the only way to exercise these routes at all is to hand them one that
    // names a loopback port. `McpState::over` is that seam and its doc comment
    // argues it; what follows is what the seam buys, which is a test for the
    // line that decides whose tenant a third party's token is stored under.

    /// A token endpoint on a loopback port, recording what it was sent.
    async fn fake_authorization_server(
        access: &str,
        refresh: &str,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let origin = format!("http://{}", listener.local_addr().expect("addr"));
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let payload = format!(
            r#"{{"access_token":"{access}","refresh_token":"{refresh}","expires_in":3600}}"#
        );
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                let payload = payload.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buffer = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    while let Ok(n) = stream.read(&mut chunk).await {
                        if n == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..n]);
                        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    recorded
                        .lock()
                        .expect("not poisoned")
                        .push(String::from_utf8_lossy(&buffer).into_owned());
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (origin, seen)
    }

    /// A catalogue with exactly one OAuth entry, pointed at `origin`.
    ///
    /// Leaked, because `Connector` is `&'static` on purpose: production entries
    /// are literals in a `const` array and the type says so.
    fn oauth_catalog(origin: &str) -> &'static [Connector] {
        let endpoints: &'static catalog::OAuth = Box::leak(Box::new(catalog::OAuth {
            authorize: Box::leak(format!("{origin}/authorize").into_boxed_str()),
            token: Box::leak(format!("{origin}/token").into_boxed_str()),
            scopes: "read:things write:things",
            auth: catalog::ClientAuth::Post,
        }));
        Box::leak(Box::new([Connector {
            key: "acme",
            label: "Acme",
            // A host that does not answer, deliberately: the callback's final
            // bind is a *report*, and the branch worth covering is the one where
            // the tokens are kept anyway.
            provision: agentos_app::catalog::Provision::Dial("https://mcp.acme.invalid/mcp"),
            reach: Reach::Public,
            credential: Credential::OAuth(endpoints),
            floor: RiskClass::Write,
            opt_outs: agentos_app::catalog::OptOuts::NoStrangers,
        }]))
    }

    /// The `state` out of a consent URL.
    fn state_of(authorize_url: &str) -> String {
        authorize_url
            .split(['?', '&'])
            .find_map(|pair| pair.strip_prefix("state="))
            .expect("the consent url carries a state")
            .to_owned()
    }

    async fn get(app: &Router, uri: &str, secret: Option<&str>) -> (StatusCode, String) {
        let mut req = HttpRequest::builder().method("GET").uri(uri);
        if let Some(secret) = secret {
            req = req.header(header::AUTHORIZATION, format!("Bearer {secret}"));
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("service");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn post_json(app: &Router, uri: &str, secret: &str, body: Value) -> (StatusCode, Value) {
        let req = HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = app.clone().oneshot(req).await.expect("service");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// One click, one consent, one binding — and the tokens land sealed.
    #[tokio::test]
    async fn a_consent_becomes_a_binding_and_the_tokens_are_never_readable_again() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (origin, seen) = fake_authorization_server("acme-at-secret", "acme-rt-secret").await;
        let (api, public) = h.over(oauth_catalog(&origin));

        // The connector is offered, because this deployment has a registration
        // for it. `Harness` registers `acme`.
        let (status, body) = get(&api, "/v1/mcp/catalog", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"connector\":\"acme\""), "{body}");
        assert!(
            body.contains("read:things write:things"),
            "a UI has to be able to say what the consent screen will ask for: {body}"
        );

        let (status, started) = post_json(
            &api,
            "/v1/mcp/oauth/start",
            SECRET_A,
            json!({"connector": "acme", "server": "acme-erp"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        let authorize_url = started["authorize_url"].as_str().expect("a url").to_owned();
        assert!(
            authorize_url.starts_with(&format!("{origin}/authorize?")),
            "{authorize_url}"
        );
        assert!(
            authorize_url.contains("code_challenge_method=S256"),
            "{authorize_url}"
        );
        assert!(
            authorize_url
                .contains("redirect_uri=https%3A%2F%2Fagentos.test%2Fv1%2Fmcp%2Foauth%2Fcallback"),
            "the redirect uri is ours and is escaped: {authorize_url}"
        );

        // The state is a capability. It is in the response, because that is the
        // response's job, and in nothing else.
        let state = state_of(&authorize_url);
        let trail = h.audit_text(h.a).await;
        assert!(trail.contains("mcp.oauth.started"), "{trail}");
        assert!(
            !trail.contains(&state),
            "the state must not be in the audit trail: {trail}"
        );

        // …and now the browser comes back.
        let (status, page) = get(
            &public,
            &format!("{CALLBACK_PATH}?state={state}&code=the-code&scope=read%3Athings"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        // The MCP endpoint in this catalogue does not resolve, so the honest
        // page is the one that says the tokens are stored and the server has not
        // answered — and that branch is exactly what must not throw the tokens
        // away, because an authorization code cannot be presented twice.
        assert!(page.contains("Connected"), "{page}");

        // The exchange really happened, with PKCE and the client secret.
        let requests = seen.lock().expect("not poisoned").clone();
        assert_eq!(requests.len(), 1, "one exchange");
        assert!(requests[0].contains("code_verifier="), "{}", requests[0]);
        assert!(requests[0].contains("code=the-code"), "{}", requests[0]);

        // The binding is stored, sealed, with an expiry the refresh loop reads.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let row: (String, bool, bool, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT connector, sealed_token IS NOT NULL, sealed_refresh_token IS NOT NULL, \
                    token_expires_at FROM mcp_servers WHERE server = 'acme-erp'",
        )
        .fetch_one(&mut **tx)
        .await
        .expect("row");
        tx.rollback().await.expect("rollback");
        assert_eq!(row.0, "acme");
        assert!(row.1 && row.2 && row.3.is_some());

        // And nothing anybody can read holds either token.
        let (_, listed) = get(&api, "/v1/mcp/servers", Some(SECRET_A)).await;
        let trail = h.audit_text(h.a).await;
        for surface in [&listed, &trail, &page] {
            for secret in ["acme-at-secret", "acme-rt-secret", "the-code", &state] {
                assert!(
                    !surface.contains(secret),
                    "{secret} leaked into:\n{surface}"
                );
            }
        }
        assert!(listed.contains("\"has_credential\":true"), "{listed}");
        assert!(trail.contains("mcp.oauth.connected"), "{trail}");
    }

    /// **The tenant mutation.** The binding lands under the tenant that started
    /// the flow, and nothing in the callback request can move it.
    ///
    /// Tenant B holds an API key and knows its own id. It sends both, alongside
    /// tenant A's state — the exact shape of "take the tenant from the request".
    /// Replace `TenantId::from_uuid(row.tenant_id)` in [`oauth_callback`] with
    /// anything read off `params` and this goes red.
    #[tokio::test]
    async fn a_binding_lands_under_the_tenant_that_started_the_flow() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (origin, _) = fake_authorization_server("at-x", "rt-x").await;
        let (api, public) = h.over(oauth_catalog(&origin));

        let (status, started) = post_json(
            &api,
            "/v1/mcp/oauth/start",
            SECRET_A,
            json!({"connector": "acme", "server": "acme-erp"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        let state = state_of(started["authorize_url"].as_str().expect("a url"));

        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "{CALLBACK_PATH}?state={state}&code=c&tenant_id={b}&tenant={b}",
                b = h.b.as_uuid()
            ))
            .header(header::AUTHORIZATION, format!("Bearer {SECRET_B}"))
            .body(Body::empty())
            .expect("request");
        let response = public.clone().oneshot(req).await.expect("service");
        assert_eq!(response.status(), StatusCode::OK);

        let count = async |tenant: TenantId| -> i64 {
            let mut tx = h.db.tenant_tx(tenant).await.expect("tenant tx");
            let n =
                sqlx::query_scalar("SELECT count(*) FROM mcp_servers WHERE server = 'acme-erp'")
                    .fetch_one(&mut **tx)
                    .await
                    .expect("count");
            tx.rollback().await.expect("rollback");
            n
        };
        assert_eq!(count(h.a).await, 1, "the tenant whose row was found");
        assert_eq!(
            count(h.b).await,
            0,
            "the tenant the request named must have had nothing happen to it"
        );
    }

    /// A deployment with no registration does not offer the connector, and does
    /// not let a caller start a flow for it either.
    #[tokio::test]
    async fn an_oauth_connector_with_no_registration_is_invisible_and_unstartable() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (origin, _) = fake_authorization_server("at", "rt").await;
        // A catalogue whose single entry is keyed `acme`, against a harness that
        // registered `acme` — then the same thing with the registration removed.
        let entries = oauth_catalog(&origin);
        let unregistered: &'static [Connector] = Box::leak(Box::new([Connector {
            key: "unregistered",
            ..entries[0]
        }]));
        let (api, _) = h.over(unregistered);

        let (status, body) = get(&api, "/v1/mcp/catalog", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !body.contains("unregistered"),
            "a button that cannot work must not be rendered: {body}"
        );

        let (status, body) = post_json(
            &api,
            "/v1/mcp/oauth/start",
            SECRET_A,
            json!({"connector": "unregistered", "server": "acme-erp"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["code"], "connector_not_registered", "{body}");
    }

    /// The two doors do not overlap: a connector that connects by consent
    /// cannot be connected by pasting a string at it.
    ///
    /// Without this, `connect`'s `match` fell through a wildcard and stored the
    /// pasted value in `sealed_token` — the column `oauth::refresh_due` reads —
    /// with no refresh token and no expiry beside it. It would bind once and
    /// stop at a moment nobody could predict.
    #[tokio::test]
    async fn a_consent_connector_is_not_connectable_by_pasting_a_token() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (origin, _) = fake_authorization_server("at", "rt").await;
        let (api, _) = h.over(oauth_catalog(&origin));

        for body in [
            json!({"connector": "acme", "server": "acme-erp", "token": "pasted"}),
            json!({"connector": "acme", "server": "acme-erp"}),
        ] {
            let (status, answered) = post_json(&api, "/v1/mcp/connect", SECRET_A, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{answered}");
            assert!(
                answered["detail"]
                    .as_str()
                    .is_some_and(|d| d.contains("/v1/mcp/oauth/start")),
                "the refusal has to name the door that works: {answered}"
            );
        }

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_servers")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!(rows, 0, "a refused connect stores nothing");
    }

    /// A connector whose URL the customer supplies cannot connect by consent:
    /// the flow row carries no URL, so the callback would have nothing to store
    /// in a `NOT NULL` column.
    #[tokio::test]
    async fn a_consent_connector_has_to_own_its_endpoint() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (origin, _) = fake_authorization_server("at", "rt").await;
        let entries = oauth_catalog(&origin);
        // `Provision::Customer` is `waveI-i2`'s spelling of "this connector has
        // no endpoint of its own": the customer supplies one at connect time.
        // That is the exact shape a consent flow cannot use, because the
        // callback would have nothing to return to.
        let endpointless: &'static [Connector] = Box::leak(Box::new([Connector {
            provision: agentos_app::catalog::Provision::Customer,
            ..entries[0]
        }]));
        let (api, _) = h.over(endpointless);

        let (status, body) = post_json(
            &api,
            "/v1/mcp/oauth/start",
            SECRET_A,
            json!({"connector": "acme", "server": "acme-erp"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["code"], "connector_has_no_endpoint", "{body}");
    }
}
