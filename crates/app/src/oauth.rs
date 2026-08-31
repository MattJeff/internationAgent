//! The authorization code flow, so connecting a connector is a click.
//!
//! # What this unlocks, and why it is the only thing that was in the way
//!
//! [`crate::catalog`] can name exactly one connector today, and its own docs say
//! why: GitHub's remote MCP server takes a personal access token, and every
//! other one worth connecting — Notion, Linear, Sentry, Atlassian, Stripe,
//! Cloudflare, anything of Google's — takes OAuth. The MCP client was never the
//! limit. `McpServer::bind` sends `Authorization: Bearer <string>` and does not
//! care where the string came from; what was missing was a way to *obtain* one
//! without asking a customer to go and mint it by hand, which is the step that
//! turns a five-minute onboarding into a support ticket.
//!
//! So this module produces the same string [`crate::mcp::Credentials`] already
//! stores, and everything downstream of the column is untouched. That is the
//! whole shape of the change and it is why it is small.
//!
//! # The parcours, and where each secret lives
//!
//! ```text
//!   browser                    us                          the provider
//!  ────────────────────────────────────────────────────────────────────────
//!   click "connect"  ──▶  POST /v1/mcp/oauth/start
//!                          (tenant comes from the API key)
//!                          mint state + PKCE verifier
//!                          row in mcp_oauth_flows, keyed by sha256(state),
//!                          verifier sealed under the deployment's cipher
//!                    ◀──  { authorize_url }
//!   follow it  ─────────────────────────────────────────▶  consent page
//!                                                          (client_id, scopes,
//!                                                           redirect_uri,
//!                                                           state, challenge)
//!   ◀──────────────────────────────────────────────────  302 back to us
//!   GET /v1/mcp/oauth/callback?code&state   ── public, no API key ──
//!                          claim the flow row by sha256(state), once
//!                          open the verifier
//!                          POST the token endpoint  ─────▶  code + verifier
//!                                                            + client secret
//!                                                   ◀─────  access + refresh
//!                          seal both, write mcp_servers
//!                    ◀──  "connected"
//! ```
//!
//! Four secrets, four homes, and mixing any two of them up is the bug this
//! module is arranged to prevent:
//!
//! * **`client_id` / `client_secret` are OURS, per connector.** They identify
//!   *this product* to the provider, not the customer, and one registration
//!   serves every tenant. They live in the deployment's environment
//!   ([`OauthClients::parse`], read by `apps/server/src/config.rs`), never in a
//!   table and never in a tenant's row. Putting them in the database would mean
//!   a tenant-scoped copy of a deployment-scoped fact, and the first customer to
//!   edit theirs would be impersonating our application.
//! * **The `code_verifier` is per flow.** Sealed into `mcp_oauth_flows`, opened
//!   once, and gone with the row.
//! * **The access token and the refresh token are the TENANT's.** Sealed into
//!   `mcp_servers` under an AAD that names the tenant and the server handle,
//!   exactly like a pasted bearer, because after the exchange that is all it is.
//! * **The `state` is a capability**, not an identifier. Whoever holds it can
//!   finish somebody's flow. It exists inside [`Started::authorize_url`] and in
//!   the browser's address bar, and it is stored only as a SHA-256 — see below.
//!
//! # What binds a public callback to a tenant
//!
//! The callback route cannot carry an API key: the provider's redirect is a
//! browser navigation and the browser has no key. So the only thing that says
//! which tenant a `code` belongs to is the `state` parameter, and it has to
//! carry that weight alone.
//!
//! * **Unguessable.** [`STATE_BYTES`] straight from the operating system's
//!   entropy source, base64url. 256 bits.
//! * **Ours.** The tenant is read out of the row `start` wrote. It is never in
//!   the query string, never in the redirect URI, and never derived from
//!   anything the browser sent — the same sentence
//!   `routes::webhooks::Endpoint::tenant_id` carries, for the same reason.
//! * **Single use.** The row is claimed with one `UPDATE … WHERE consumed_at IS
//!   NULL … RETURNING`, which is atomic, so two callbacks racing on one state
//!   produce one winner and one 404. That transaction commits *before* the token
//!   exchange, so even a crash mid-exchange cannot leave a replayable state.
//! * **Short lived.** [`FLOW_TTL`]. A consent page a customer left open over
//!   lunch is a state sitting in a browser history.
//! * **Not recoverable from the database.** The column is `sha256(state)`, so
//!   read access to `mcp_oauth_flows` does not let anybody complete a flow. It
//!   is a lookup key, not a bearer token at rest, and the two are stored
//!   differently for the same reason a password is.
//!
//! Take `state` away and the route would have to take a tenant id from the query
//! string. Then anyone on the internet could send their own provider `code` to
//! `?tenant=<somebody else>` and attach *their* account to *that* company's
//! employees — every task the tenant runs through that connector executing in an
//! attacker's workspace, and every result read back out of it. That is the
//! mutation, and it is written down in this module's tests.
//!
//! # PKCE, and what it defends that `state` does not
//!
//! `state` proves the callback belongs to a flow we started. It says nothing
//! about who is *presenting* the code. An authorization code travels in a URL:
//! through the browser's address bar and history, through any `Referer` a page on
//! the redirect origin sends, through proxy and CDN logs, and — for the flows
//! that ever touch a native app — through whatever else registered the redirect
//! scheme. A code that leaks any of those ways is redeemable by whoever picked it
//! up, once, and once is enough.
//!
//! PKCE closes it: the consent request commits to `S256(verifier)`, the token
//! request has to present the `verifier`, and the verifier is in our database
//! and never in a browser. An intercepted code is then worth nothing.
//!
//! `S256` and never `plain`: `plain` puts the verifier in the authorize URL,
//! which is precisely the place we are assuming leaks, so it defends nothing
//! while looking like it does. There is no branch here that can select it.
//!
//! # Refreshing, on the clock that already exists
//!
//! An access token expires; a refresh token does not. Something has to swap one
//! for the other *before* an employee needs it, because an employee that waits
//! for a token exchange is an employee that waits.
//!
//! There is already a loop rebinding every tenant's fleet every five minutes —
//! `apps/server/src/routes/mcp.rs`'s binder — and [`refresh_due`] is a step
//! inside it, not a second timer. That matters more than it sounds: two clocks
//! over one table is how a token gets refreshed by one task while another is
//! binding with the copy it read a moment ago, and the failure is a 401 nobody
//! can reproduce. One loop, one order: refresh what is due, commit, then bind.
//!
//! [`REFRESH_MARGIN`] is deliberately several ticks wide, so a token is offered
//! for refresh three or four times before it could possibly expire and a single
//! failed attempt is not an outage.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use agentos_domain::ids::{Slug, TenantId};
use agentos_providers::{ProviderError, Secret};
use agentos_store::db::{StoreError, TenantTx};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use url::Url;

use crate::catalog::{self, ClientAuth, Connector, OAuth};
use crate::mcp::Credentials;

/// How much entropy a `state` carries. 256 bits, from the OS.
///
/// Not a UUID. A v7 UUID is mostly a timestamp and carries 74 unpredictable
/// bits, which is plenty against a blind guess and is *not* the threat here —
/// the threat is somebody who can watch flows start and is trying to collide
/// with one. Random bytes cost the same and answer both.
const STATE_BYTES: usize = 32;

/// PKCE verifier length before encoding. 32 bytes is 43 base64url characters,
/// which is exactly RFC 7636's minimum, and the minimum is 43 because that is
/// 256 bits.
const VERIFIER_BYTES: usize = 32;

/// How long a consent page stays completable.
///
/// Ten minutes is the width of "click connect, read the scopes, approve". A
/// customer who takes longer clicks connect again, which costs them one click
/// and costs an attacker who found the URL in a history file everything.
pub const FLOW_TTL: Duration = Duration::from_secs(600);

/// How far ahead of expiry a token is refreshed.
///
/// The binder ticks every five minutes, so this is three ticks. A token is
/// therefore offered for refresh three times before it could expire, and the
/// provider being briefly unreachable is a retry rather than an outage.
///
/// ponytail: a constant, not a fraction of the token's own lifetime. A provider
/// that issues five-minute tokens would be refreshed on every tick, which is
/// correct and slightly wasteful; one that issues thirty-day tokens is refreshed
/// once a month. Both are fine. Make it `min(margin, lifetime/2)` the day a
/// provider issues something shorter than the tick.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(900);

/// What a token endpoint gets before we give up on it.
///
/// Short on purpose: on the callback path a customer's browser is waiting on
/// this, and on the refresh path it is inside the binder's serial loop over
/// every tenant.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(15);

/// The most a token response may be. A token endpoint answers with four short
/// fields; anything larger is not one.
const MAX_TOKEN_BYTES: usize = 64 * 1024;

/// What to assume when a provider does not say how long its token lasts.
///
/// `expires_in` is a SHOULD in RFC 6749, and a provider that omits it has not
/// promised the token is eternal — it has said nothing. Recording "no expiry"
/// would take that silence as a promise and the binding would work until the
/// day it did not. An hour is the common default across providers that do
/// answer, and being wrong in this direction costs one extra refresh.
const ASSUMED_LIFETIME: Duration = Duration::from_secs(3600);

/// The [`OauthError::Endpoint`] code for "the authorization server answered, and
/// the answer was no on a status a second attempt will not change".
///
/// One spelling, because it is written in [`post_token`] and matched in
/// [`refresh_due`], and a rule in two literals is a rule that diverges the day
/// somebody fixes a typo in one of them. It is the same discipline
/// `RELEASE_NOT_SUPPORTED` gets on the provisioning side.
const REJECTED: &str = "rejected";

// ---------------------------------------------------------------------------
// The deployment's client registrations
// ---------------------------------------------------------------------------

/// One OAuth application, as registered with one provider by us.
///
/// No `Debug`, no `Serialize`, no accessor for the secret outside this module:
/// the only thing that ever reads it is the form body [`post_token`] builds.
struct Client {
    id: String,
    secret: Secret,
}

/// Every connector this deployment can run an OAuth flow for.
///
/// # Why this is configuration and not a table
///
/// A `client_secret` identifies *the product* to a provider. It is the same
/// value for every tenant, it is rotated by whoever holds the provider account,
/// and no customer has any business reading or writing one. A table would give
/// it a tenant column that means nothing, an RLS policy that protects nothing,
/// and a write path that should not exist. `AGENTOS_WEBHOOK_SECRETS` is the same
/// call for the same kind of value, and `routes::webhooks` argues it.
///
/// The visible consequence is the good one: a connector this deployment has no
/// registration for is **not advertised in the catalogue at all**, so a customer
/// never clicks a button that cannot work.
#[derive(Default)]
pub struct OauthClients(HashMap<String, Client>);

/// Why a registration string could not be read.
#[derive(Debug, thiserror::Error)]
#[error("entry {index} is not `connector:client_id:client_secret`")]
pub struct ClientsError {
    /// Which comma-separated entry, counting from zero.
    pub index: usize,
}

impl std::fmt::Debug for OauthClients {
    /// Names the connectors and nothing else. A derived one would print the
    /// `client_id`, which is not a secret, and then somebody would add a field.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl OauthClients {
    /// Parse `connector:client_id:client_secret[,…]`.
    ///
    /// Split on the first two colons only: a `client_secret` is an opaque
    /// vendor string and several vendors put separators in theirs. The first two
    /// fields are ours to constrain and the third is not.
    ///
    /// An empty string is an empty registry, which is a deployment that offers
    /// no OAuth connectors — not an error. Every other malformed entry is,
    /// because a registration that was *meant* to be there and is skipped is a
    /// connector that vanishes from the catalogue with no explanation.
    pub fn parse(raw: &str) -> Result<Self, ClientsError> {
        let mut clients = HashMap::new();
        for (index, entry) in raw
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .enumerate()
        {
            let mut parts = entry.splitn(3, ':');
            let (Some(connector), Some(id), Some(secret)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Err(ClientsError { index });
            };
            if connector.is_empty() || id.is_empty() || secret.is_empty() {
                return Err(ClientsError { index });
            }
            clients.insert(
                connector.to_owned(),
                Client {
                    id: id.to_owned(),
                    secret: Secret::new(secret),
                },
            );
        }
        Ok(Self(clients))
    }

    /// Whether this deployment can run a flow for this connector.
    ///
    /// What the catalogue handler filters on. A `false` here hides the entry
    /// rather than letting a customer click into a 500.
    pub fn has(&self, connector: &str) -> bool {
        self.0.contains_key(connector)
    }

    fn get(&self, connector: &str) -> Option<&Client> {
        self.0.get(connector)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything a flow can fail with.
///
/// **No variant carries a provider's response body, a code, a token, or a
/// verifier**, and that is not a convention — it is the whole enum. Every one of
/// these is rendered into an HTTP response by
/// `apps/server/src/routes/mcp.rs` and into a `tracing` line, and a token
/// endpoint's error body routinely echoes the request back.
#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    /// This deployment has no client registration for the connector.
    #[error("this deployment has no oauth registration for {connector:?}")]
    NotRegistered {
        /// The catalogue key. Ours, not a customer's string.
        connector: &'static str,
    },

    /// The connector does not use OAuth at all.
    #[error("{connector:?} does not use oauth")]
    NotOauth {
        /// The catalogue key.
        connector: &'static str,
    },

    /// The token endpoint could not be reached, answered a failure, or answered
    /// something that is not a token response.
    #[error("the authorization server did not issue a token: {code}")]
    Endpoint {
        /// `unreachable`, [`REJECTED`], `too_large`, `unparseable`, or
        /// `no_access_token`.
        code: &'static str,
    },

    /// A sealed value could not be sealed or opened.
    #[error("a sealed value in this flow could not be read: {0}")]
    Credential(#[from] crate::mcp::McpError),

    /// The database said no while a refresh was being written back.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl OauthError {
    /// Is this the answer that means **stop asking**?
    ///
    /// True only for [`REJECTED`]: the authorization server answered, on a
    /// status a second attempt will not change, and the refresh token behind it
    /// is dead until a human consents again. [`refresh_due`] parks on this and
    /// on nothing else — an `unreachable` (the connection failed, or a 429/5xx),
    /// a `too_large`, an `unparseable` or a `no_access_token` all keep their
    /// token and their retries.
    ///
    /// A named predicate rather than a `matches!` at the one call site, because
    /// there is a second reader: the tests that prove a 400 parks and a 503 does
    /// not. Spelling the arm twice is how the two drift, and this rule costs a
    /// customer a consent screen when it drifts the wrong way.
    fn needs_a_human(&self) -> bool {
        matches!(self, OauthError::Endpoint { code } if *code == REJECTED)
    }

    /// Stable, low-cardinality metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            OauthError::NotRegistered { .. } => "connector_not_registered",
            OauthError::NotOauth { .. } => "connector_is_not_oauth",
            OauthError::Endpoint { code } => code,
            OauthError::Credential(err) => err.code(),
            OauthError::Store(_) => "store",
        }
    }
}

// ---------------------------------------------------------------------------
// Starting a flow
// ---------------------------------------------------------------------------

/// Everything one started flow leaves behind.
///
/// No `Debug` and no `Serialize`, and the reason is [`Self::authorize_url`]: it
/// carries the `state`, which is the capability to finish this flow. A derived
/// `Debug` is one `tracing::info!(?started)` away from putting it in a log that
/// a support engineer pastes into a ticket.
pub struct Started {
    /// Where to send the browser. **Carries the `state`.** It goes in one HTTP
    /// response, to the tenant that asked for it, and into no other surface.
    pub authorize_url: String,
    /// What `mcp_oauth_flows` is keyed by. The `state` itself is not stored.
    pub state_hash: [u8; 32],
    /// The PKCE verifier, sealed under this flow's own AAD.
    pub sealed_verifier: Vec<u8>,
    /// When the row stops being claimable.
    pub expires_at: DateTime<Utc>,
}

/// Mint a flow: the consent URL, and the two values the callback will need.
///
/// Writes nothing — the caller stores the row, inside its own transaction and
/// its own tenant, which is the only place row-level security can see it.
///
/// `redirect_uri` is the deployment's callback, built once by `apps/server` from
/// `PUBLIC_HOST`. It is passed here rather than assembled here because it must be
/// **byte-identical** to what the exchange later sends and to what is registered
/// with the provider, and one caller producing it is the only way that is true.
/// # It does not take the server handle, and that is deliberate
///
/// The handle the binding will be stored under is the caller's business and
/// belongs in the row, not in the consent URL. Anything this function put in
/// that URL travels through a browser and comes back editable — so the one
/// thing the callback uses to find its way home is a lookup key, and everything
/// else is read out of the row that key finds.
pub fn start(
    clients: &OauthClients,
    credentials: &Credentials,
    tenant_id: TenantId,
    connector: &'static Connector,
    redirect_uri: &str,
    now: DateTime<Utc>,
) -> Result<Started, OauthError> {
    let (endpoints, client) = registration(clients, connector)?;

    let state = random_b64url(STATE_BYTES);
    let verifier = random_b64url(VERIFIER_BYTES);
    let state_hash = state_hash(&state);
    // `S256`, and the challenge is over the base64url *text* of the verifier,
    // not the bytes behind it — RFC 7636 is explicit that the verifier is the
    // ASCII string, and hashing the bytes instead produces a challenge that
    // every provider rejects with an error about PKCE that names nothing.
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));

    let sealed_verifier = credentials.seal_as(
        tenant_id,
        &flow_context(tenant_id, &state_hash),
        &Secret::new(verifier),
    )?;

    // `Url` rather than `format!`: a scope string has spaces in it and a
    // `client_id` is a vendor's opaque value. Hand-building the query is how one
    // of them ends up unescaped and the provider reads a truncated redirect_uri.
    let mut url = Url::parse(endpoints.authorize).map_err(|_| OauthError::Endpoint {
        code: "unparseable",
    })?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", endpoints.scopes)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(Started {
        authorize_url: url.into(),
        state_hash,
        sealed_verifier,
        expires_at: now + FLOW_TTL,
    })
}

/// The lookup key for a `state`, as `mcp_oauth_flows` stores it.
///
/// Public because the callback route holds the raw `state` from the query string
/// and has to arrive at the same 32 bytes. One function, so the writer and the
/// reader cannot disagree — the same argument
/// [`crate::mcp::credential_context`] makes about an AAD.
pub fn state_hash(state: &str) -> [u8; 32] {
    Sha256::digest(state.as_bytes()).into()
}

// ---------------------------------------------------------------------------
// Finishing one
// ---------------------------------------------------------------------------

/// One flow, as the callback recovered it from the row [`start`] wrote.
///
/// Every field comes out of the database. **Nothing here is read from the
/// request**, which is the property that makes the public route safe: the
/// browser supplies one opaque string, and that string selects a row rather than
/// describing one.
///
/// Named for the `UPDATE … RETURNING` that produces it rather than for the
/// concept, and not `Flow`: `proof_of_need::Flow` already exists in this crate,
/// and two types under one name make every compiler message about either of them
/// print a full path — including the ones `tests/ui` pins.
pub struct Claimed {
    /// Whose flow this is. From the row, never from the query string.
    pub tenant_id: TenantId,
    /// Which catalogue entry, resolved.
    pub connector: &'static Connector,
    /// The handle the resulting binding is stored under.
    pub server: Slug,
    /// The key the row was found by, and half of the verifier's AAD.
    pub state_hash: [u8; 32],
    /// The PKCE verifier, still sealed.
    pub sealed_verifier: Vec<u8>,
}

/// What a completed flow leaves for `mcp_servers`.
///
/// Sealed on the way out, so the plaintext of neither token ever crosses back
/// into `apps/server` — the same boundary [`crate::mcp::Credentials`] draws for a
/// pasted bearer, and for the same reason.
pub struct Sealed {
    /// The access token, sealed under the binding's own AAD. Goes in
    /// `mcp_servers.sealed_token` and down the wire as a bearer, indistinguishable
    /// from one a customer typed.
    pub access: Vec<u8>,
    /// The refresh token, if the provider issued one. `None` means this binding
    /// dies when its access token does, which is a real thing some providers do
    /// and is visible as a bind failure rather than a silent stop.
    pub refresh: Option<Vec<u8>>,
    /// When the access token stops working.
    pub expires_at: DateTime<Utc>,
}

/// Exchange the code for tokens and seal them.
///
/// The verifier is opened here and dies with this call. The `code` is taken by
/// value for the same reason [`Credentials::seal`] takes its token by value: the
/// `String` the query string was parsed into is the last copy, and it is moved
/// into the form body rather than borrowed and left behind.
pub async fn complete(
    clients: &OauthClients,
    credentials: &Credentials,
    flow: &Claimed,
    code: String,
    redirect_uri: &str,
    now: DateTime<Utc>,
) -> Result<Sealed, OauthError> {
    let (endpoints, client) = registration(clients, flow.connector)?;
    let verifier = credentials.open_as(
        flow.tenant_id,
        &flow_context(flow.tenant_id, &flow.state_hash),
        &flow.sealed_verifier,
    )?;

    let issued = post_token(
        endpoints,
        client,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            // The half a stolen code cannot produce.
            ("code_verifier", verifier.expose_for_transport()),
        ],
    )
    .await?;

    seal(credentials, flow.tenant_id, &flow.server, &issued, now)
}

// ---------------------------------------------------------------------------
// Keeping them alive
// ---------------------------------------------------------------------------

/// One binding that is close enough to expiry to be worth a round trip.
#[derive(sqlx::FromRow)]
struct DueRow {
    server: String,
    connector: String,
    sealed_refresh_token: Vec<u8>,
}

/// Bindings whose access token expires within [`REFRESH_MARGIN`] and that have
/// something to refresh it with.
///
/// A binding with no refresh token is not selected: there is nothing to send,
/// and re-running the consent flow is a human's decision, not a loop's.
///
/// # `FOR UPDATE SKIP LOCKED`, and it is not an optimisation
///
/// A deployment has more than one replica and every one of them runs the binder
/// loop on the same five-minute tick. Without the lock, two replicas read the
/// same refresh token and both present it — and for the providers that **rotate**
/// refresh tokens (Atlassian is the one everybody meets), the second exchange is
/// refused because the first already invalidated it, while the second replica's
/// `UPDATE` may still land afterwards and overwrite the good token with the dead
/// one. The binding then cannot be renewed by anything and needs a human back in
/// a consent screen.
///
/// `SKIP LOCKED` rather than plain `FOR UPDATE`: a second replica should do
/// nothing at all, not queue behind a fifteen-second HTTP call to arrive at a
/// token that has already been replaced. It is the same choice, for the same
/// reason, that the outbox poller makes about claiming work.
///
/// The lock is held for the length of the caller's transaction, which spans one
/// tenant's refreshes. That is the cost and it is bounded by
/// [`TOKEN_TIMEOUT`] per due binding — a tenant with a hundred OAuth connectors
/// would want this batched, and has other problems first.
const SELECT_DUE: &str = "\
    SELECT server, connector, sealed_refresh_token \
      FROM mcp_servers \
     WHERE sealed_refresh_token IS NOT NULL \
       AND token_expires_at IS NOT NULL \
       AND token_expires_at < $1 \
     ORDER BY server \
       FOR UPDATE SKIP LOCKED";

/// Refresh every token this tenant has that is about to expire.
///
/// Returns **how many rows it wrote** — renewals plus the parks below — which is
/// what the caller needs to decide between a commit and a rollback, and is why
/// it is not "how many were refreshed". **Never fails the caller**: the binder
/// loop runs this for every tenant in turn, and one provider being down must not
/// stop the other tenants — or the other bindings of the same tenant — from
/// being rebound. Each failure is logged with its stable code and the old token
/// is left in place, which keeps working until it expires and then shows up as
/// an ordinary bind failure in `GET /v1/mcp/servers`.
///
/// # A dead refresh token is not a transient failure, and this loop used to
/// treat it as one
///
/// [`SELECT_DUE`] matches on `token_expires_at`, which a failed refresh does not
/// move. So a binding whose refresh token the provider has *revoked* — the
/// customer disconnected our app, an admin rotated it, the grant expired — was
/// re-presented every five minutes, forever, against somebody else's
/// authorization server, with a credential that will never work again. That is
/// the argument `crates/app/src/mcp.rs` already makes against itself in
/// [`reached_the_server`](crate::mcp): retrying hammers a third party with a
/// dead credential and hides a broken binding behind a status that reads like
/// progress. It is also the kind of traffic that gets an OAuth client
/// suspended.
///
/// So a [`REJECTED`] refresh clears `sealed_refresh_token`, and that is the
/// whole park: `SELECT_DUE` requires the column to be NOT NULL, and
/// `0042_mcp_oauth` already gives NULL a meaning — "this binding cannot outlive
/// its access token" — because some providers issue no refresh token at all. The
/// binding keeps the access token it has, works until that expires, and then
/// surfaces as an ordinary bind failure on the page an operator already reads.
/// **No new notification, no new table, no new column**: re-consenting is a
/// human's decision, which is the sentence [`due`] was written under.
///
/// Only [`REJECTED`] parks. `unreachable` (the connection failed, or the status
/// was a 429/5xx), `too_large`, `unparseable` and `no_access_token` all keep
/// their token and their retries — a provider having a bad minute must not cost
/// a customer a trip back through a consent screen.
///
/// The tenant is `tx`'s, because row-level security honours nothing else. The
/// caller commits — this writes, which is why it cannot share the read-only
/// transaction `Fleet::bind` runs in.
///
/// # `catalog` is a parameter, and it is what makes this loop testable at all
///
/// The lookup below used to be [`catalog::find`], which reads the `const`
/// [`CATALOG`](catalog::CATALOG). Every OAuth entry in it points at somebody
/// else's authorization server through a `&'static str` https literal, so the
/// only way to run this function end to end was to reach one — and a test that
/// reaches a real provider is a test nobody runs. Everything on the far side of
/// the lookup was therefore proved one link at a time, by tests that call
/// [`refresh_one`] and then [`park_refresh`] **by hand, in that order**: the
/// loop body written a second time, next to a loop nothing ran.
///
/// [`catalog::find_in`] already existed for exactly this, with the argument
/// written on it: `apps/server`'s routes thread the array through for the same
/// reason and at four call sites. This is the fifth. **There is no branch here
/// that behaves differently for one catalogue than for another** — the shipped
/// wiring passes `catalog::CATALOG` in one place, and a test passes a one-entry
/// slice whose token endpoint is a loopback port.
///
/// ponytail: the SQL is here rather than in `agentos-store`, the same call
/// `mcp::Fleet::bind` makes two hundred lines away and for the same reason —
/// there is one caller. Move both the day there is a second.
pub async fn refresh_due(
    tx: &mut TenantTx<'_>,
    credentials: &Credentials,
    clients: &OauthClients,
    catalog: &'static [Connector],
    now: DateTime<Utc>,
) -> usize {
    let tenant_id = tx.tenant_id();
    let rows = match due(tx, now).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(%tenant_id, error = %err, "could not list mcp tokens due for refresh");
            return 0;
        }
    };

    let mut written = 0;
    for row in rows {
        // Same fail-closed reading as `Fleet::bind`: a row this build cannot
        // name, or whose connector this build no longer has, is a binding that
        // is skipped — not one refreshed against an endpoint we guessed.
        let Ok(server) = Slug::parse(&row.server) else {
            continue;
        };
        let Some(connector) = catalog::find_in(catalog, &row.connector) else {
            tracing::warn!(
                %tenant_id,
                server = server.as_str(),
                connector = row.connector,
                "an oauth binding names a connector this build does not know; not refreshing it"
            );
            continue;
        };
        match refresh_one(
            tx,
            credentials,
            clients,
            tenant_id,
            &server,
            connector,
            &row,
            now,
        )
        .await
        {
            Ok(()) => written += 1,
            // The authorization server answered, and its answer will not change.
            // Stop asking it. See this function's docs for why the park is a
            // NULL in a column that already means this.
            Err(err) if err.needs_a_human() => {
                match park_refresh(tx, &server).await {
                    Ok(()) => {
                        written += 1;
                        // No token, no sealed bytes, no provider body — the
                        // handle and the reason, which is all an operator can
                        // act on anyway.
                        tracing::warn!(
                            %tenant_id,
                            server = server.as_str(),
                            "this mcp oauth refresh token was refused and has been dropped; the \
                             binding works until its access token expires and then needs a human \
                             to connect it again"
                        );
                    }
                    // Left selectable, which means it is retried — the old
                    // behaviour, for one binding, rather than a park that
                    // silently did not happen.
                    Err(err) => tracing::error!(
                        %tenant_id,
                        server = server.as_str(),
                        error = %err,
                        "an mcp oauth refresh token was refused and could not be dropped"
                    ),
                }
            }
            Err(err) => tracing::warn!(
                %tenant_id,
                server = server.as_str(),
                code = err.code(),
                "could not refresh an mcp oauth token; the stored one is left in place: {err}"
            ),
        }
    }
    written
}

/// Drop a refresh token the authorization server has refused.
///
/// The access token is deliberately untouched: it may well still work, and
/// throwing it away would break a binding that is currently serving tools in
/// order to react to a renewal that is not due yet. What this ends is the
/// asking — [`SELECT_DUE`] requires `sealed_refresh_token IS NOT NULL`.
///
/// Scoped by handle inside the caller's tenant transaction, so row-level
/// security is what keeps it off another tenant's row; the same shape as the
/// `UPDATE` in [`refresh_one`].
async fn park_refresh(tx: &mut TenantTx<'_>, server: &Slug) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE mcp_servers SET sealed_refresh_token = NULL, updated_at = now() \
          WHERE server = $1",
    )
    .bind(server.as_str())
    .execute(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    Ok(())
}

/// The selection, on its own.
///
/// Extracted from [`refresh_due`] because it is the half with a `WHERE` clause
/// in it and therefore the half that can be wrong quietly: a margin that
/// compares the wrong way round selects everything or nothing, and both look
/// like a working loop from the outside. A caller can run this and count.
async fn due(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Result<Vec<DueRow>, StoreError> {
    sqlx::query_as(SELECT_DUE)
        .bind(now + REFRESH_MARGIN)
        .fetch_all(&mut ***tx)
        .await
        .map_err(StoreError::from)
}

/// One refresh, written back in the caller's transaction.
#[allow(clippy::too_many_arguments)]
async fn refresh_one(
    tx: &mut TenantTx<'_>,
    credentials: &Credentials,
    clients: &OauthClients,
    tenant_id: TenantId,
    server: &Slug,
    connector: &'static Connector,
    row: &DueRow,
    now: DateTime<Utc>,
) -> Result<(), OauthError> {
    let (endpoints, client) = registration(clients, connector)?;

    let refresh_token = credentials.open_as(
        tenant_id,
        &refresh_context(tenant_id, server),
        &row.sealed_refresh_token,
    )?;
    let issued = post_token(
        endpoints,
        client,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose_for_transport()),
        ],
    )
    .await?;
    drop(refresh_token);

    let sealed = seal(credentials, tenant_id, server, &issued, now)?;
    // `coalesce`, so a provider that does NOT rotate its refresh token — most of
    // them — keeps the one we have instead of having it overwritten with NULL.
    // A provider that DOES rotate (Atlassian, and it is not alone) sends a new
    // one, and the old one stops working the moment this response was issued, so
    // storing it is not optional: skip this and the binding refreshes exactly
    // once and is then unrecoverable without a human re-consenting.
    sqlx::query(
        "UPDATE mcp_servers \
            SET sealed_token = $2, \
                sealed_refresh_token = coalesce($3, sealed_refresh_token), \
                token_expires_at = $4, \
                updated_at = now() \
          WHERE server = $1",
    )
    .bind(server.as_str())
    .bind(sealed.access.as_slice())
    .bind(sealed.refresh.as_deref())
    .bind(sealed.expires_at)
    .execute(&mut ***tx)
    .await
    .map_err(StoreError::from)?;

    tracing::info!(
        %tenant_id,
        server = server.as_str(),
        connector = connector.key,
        // The expiry, never the token. "When does this stop working" is the
        // question an operator asks; "what is it" is not a question we answer.
        expires_at = %sealed.expires_at,
        "refreshed an mcp oauth token"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/// What a token endpoint gave us.
///
/// No `Debug`, no `Serialize`, no `Clone`. It holds two live credentials and it
/// exists for the four statements between the HTTP response and the cipher.
struct Issued {
    access: Secret,
    refresh: Option<Secret>,
    lifetime: Duration,
}

/// One POST to a token endpoint, with the deployment's client credentials.
///
/// `form` is the grant-specific half; the client authentication is added here so
/// that no caller can forget it and no caller can choose it.
///
/// # The address check, and why this one is different
///
/// There is none, deliberately, and the argument is the same one
/// `crate::mcp::McpServer::bind` makes in reverse. That check exists because a
/// binding URL is a string a **customer** supplies, and `resolve_and_vet` is what
/// stops an agent naming the cloud metadata endpoint. `endpoints.token` is a
/// `&'static str` in a `const` array in this binary. There is no request, no
/// column and no model output anywhere on the path that produces it, so there is
/// nothing to check it against that is not already true by construction — and a
/// check that can only ever pass is a check that teaches people the pattern
/// without the property. `catalog`'s own test holds those literals to https.
///
/// Redirects are off, which is not the same question: a token endpoint that 302s
/// somewhere is a token endpoint we would otherwise re-send the client secret to.
async fn post_token(
    endpoints: &'static OAuth,
    client: &Client,
    form: &[(&str, &str)],
) -> Result<Issued, OauthError> {
    let mut body: Vec<(&str, &str)> = form.to_vec();
    let mut request = http_client().post(endpoints.token);
    match endpoints.auth {
        // RFC 6749 §2.3.1's mandatory scheme, and the one that keeps the secret
        // out of a body some providers log.
        ClientAuth::Basic => {
            request = request.basic_auth(&client.id, Some(client.secret.expose_for_transport()))
        }
        // §2.3.1's optional one, which several large providers document as their
        // only example. Never both: "the client MUST NOT use more than one
        // authentication method in each request", and a server that sees two
        // answers `invalid_client` with no hint about which.
        ClientAuth::Post => {
            body.push(("client_id", &client.id));
            body.push(("client_secret", client.secret.expose_for_transport()));
        }
    }

    let response = request
        .form(&body)
        .send()
        .await
        .map_err(|_| OauthError::Endpoint {
            code: "unreachable",
        })?;
    if !response.status().is_success() {
        // Includes the 3xx a redirect-following client would have chased. The
        // provider's body is deliberately not read: it echoes the request, and
        // this error is rendered into an HTTP response.
        //
        // **The status is read, though, and only the status.** A 400
        // `invalid_grant` and a 503 are both "no token" to the caller of a
        // callback, and they are opposite instructions to [`refresh_due`]: one
        // says the credential is dead and a human has to re-consent, the other
        // says the authorization server is having a bad minute. Told apart by
        // `ProviderError::from_status`, which is this workspace's one rule for
        // whether a far side's status means try again — the same rule
        // `crates/app/src/mcp.rs` reaches for when an MCP server refuses a
        // token, and for the same stated reason: one vocabulary, not two.
        //
        // A retryable status folds into `unreachable` rather than earning a
        // code of its own, because to everything upstream it *is* the connect
        // failure above: the authorization server did not answer, ask later.
        return Err(OauthError::Endpoint {
            code: if ProviderError::from_status(response.status().as_u16(), None).is_retryable() {
                "unreachable"
            } else {
                REJECTED
            },
        });
    }

    parse_issued(&bounded_body(response).await?)
}

/// The response body, refused **while it streams** if it is too large.
///
/// Not `Content-Length` and then `bytes()`: a chunked response carries no length
/// and `bytes()` buffers whatever arrives. `peer_keys::body` is the same twelve
/// lines for the same reason.
async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, OauthError> {
    let mut buffer = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| OauthError::Endpoint {
        code: "unreachable",
    })? {
        if buffer.len() + chunk.len() > MAX_TOKEN_BYTES {
            return Err(OauthError::Endpoint { code: "too_large" });
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

/// A token response into [`Issued`].
///
/// Lenient about `expires_in` and strict about everything else. `expires_in` is
/// a number in the RFC and a string at more than one large provider, and the
/// difference is not worth refusing a token over — a missing or unreadable one
/// falls back to [`ASSUMED_LIFETIME`], which is the conservative direction.
/// `access_token` has no fallback: a response without one is not a token
/// response, whatever status it arrived under.
fn parse_issued(body: &[u8]) -> Result<Issued, OauthError> {
    let document: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| OauthError::Endpoint {
            code: "unparseable",
        })?;
    let access = document["access_token"]
        .as_str()
        .filter(|token| !token.is_empty())
        .ok_or(OauthError::Endpoint {
            code: "no_access_token",
        })?;
    let lifetime = document["expires_in"]
        .as_u64()
        .or_else(|| document["expires_in"].as_str()?.parse().ok())
        .filter(|seconds| *seconds > 0)
        .map_or(ASSUMED_LIFETIME, Duration::from_secs);
    Ok(Issued {
        access: Secret::new(access),
        refresh: document["refresh_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .map(Secret::new),
        lifetime,
    })
}

/// The one HTTP client this module uses.
///
/// A `OnceLock` rather than a field on something: there is no object here to
/// hang it on, and a client per call is a TLS handshake per refresh. Redirects
/// off — see [`post_token`].
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TOKEN_TIMEOUT)
            .build()
            .unwrap_or_default()
    })
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// The endpoints and the client registration, or the reason there are none.
///
/// One function, so both refusals are spelled once and in the same order: a
/// connector that does not do OAuth is a different sentence to an operator than
/// one this deployment has not registered, and only the second is fixable by
/// setting an environment variable.
fn registration<'a>(
    clients: &'a OauthClients,
    connector: &'static Connector,
) -> Result<(&'static OAuth, &'a Client), OauthError> {
    let endpoints = connector.credential.oauth().ok_or(OauthError::NotOauth {
        connector: connector.key,
    })?;
    let client = clients
        .get(connector.key)
        .ok_or(OauthError::NotRegistered {
            connector: connector.key,
        })?;
    Ok((endpoints, client))
}

/// Seal what a token endpoint issued, for the two columns that hold it.
fn seal(
    credentials: &Credentials,
    tenant_id: TenantId,
    server: &Slug,
    issued: &Issued,
    now: DateTime<Utc>,
) -> Result<Sealed, OauthError> {
    // The access token is sealed under the *binding's* context — the same one a
    // pasted bearer uses — because after this point it is one, and
    // `Credentials::bind` opens it without knowing which it was.
    let access = credentials.seal_as(
        tenant_id,
        &crate::mcp::credential_context(tenant_id, server),
        &issued.access,
    )?;
    let refresh = issued
        .refresh
        .as_ref()
        .map(|token| credentials.seal_as(tenant_id, &refresh_context(tenant_id, server), token))
        .transpose()?;
    Ok(Sealed {
        access,
        refresh,
        expires_at: now
            + chrono::TimeDelta::from_std(issued.lifetime)
                .unwrap_or_else(|_| chrono::TimeDelta::seconds(3600)),
    })
}

/// The AAD a refresh token is sealed under.
///
/// A **different** scheme to `credential_context`, which is what the access
/// token uses, and the difference is the point: the two blobs sit in two columns
/// of one row, they are the same length, and a query that swapped them would
/// otherwise produce a binding that sends a refresh token as a bearer and
/// refreshes with an access token. Neither would decrypt now, and the failure is
/// `secret_decrypt_failed` at the moment of the swap rather than a 401 from a
/// stranger's server a week later.
fn refresh_context(tenant_id: TenantId, server: &Slug) -> String {
    format!("mcp-refresh://{tenant_id}/{}", server.as_str())
}

/// The AAD a PKCE verifier is sealed under.
///
/// Named by the state hash, so a verifier is bound to the one flow it belongs
/// to. A blob copied from another row of `mcp_oauth_flows` — the same tenant,
/// even the same connector — does not open, so an attacker who can write that
/// table still cannot pair a verifier they know with a state they chose.
fn flow_context(tenant_id: TenantId, state_hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let hex = state_hash.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    });
    format!("mcp-oauth://{tenant_id}/{hex}")
}

/// `n` bytes from the OS, base64url with no padding.
///
/// `try_fill_bytes` on the OS source, not `rand::rng()`: the thread generator is
/// seeded from the OS and is fine for jitter, and a `state` is not jitter. A
/// generator that could not be seeded is a `panic` here rather than a flow with
/// predictable entropy, which is the one outcome worth crashing over — and it
/// cannot happen on any platform this runs on.
fn random_b64url(n: usize) -> String {
    let mut bytes = vec![0_u8; n];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system's entropy source");
    B64URL.encode(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use agentos_providers::secrets::LocalEnvelopeSecretStore;
    use agentos_store::db::Db;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::catalog::{Credential, OAuth};
    use crate::mcp::{Reach, RiskClass};

    // -- a real authorization server, in process ----------------------------
    //
    // It speaks the wire, not a mock of this module: a form-encoded POST over
    // HTTP/1.1 on a loopback port, answered with the JSON RFC 6749 describes.
    // The half that makes it a contract test rather than a fixture is that it
    // **verifies PKCE itself** — it recomputes `S256(code_verifier)` and refuses
    // anything that does not match the challenge it was shown. So a change here
    // that stopped sending the verifier would not quietly pass.

    /// What one token request looked like when it arrived.
    #[derive(Clone, Debug, Default)]
    struct Seen {
        form: HashMap<String, String>,
        authorization: Option<String>,
    }

    struct FakeProvider {
        origin: String,
        inner: Arc<Mutex<Inner>>,
    }

    #[derive(Default)]
    struct Inner {
        /// What the authorize URL committed to. `None` skips the check, which is
        /// only used by the refresh tests — a refresh carries no verifier.
        challenge: Option<String>,
        seen: Vec<Seen>,
        /// Answered in order; the last one repeats.
        script: Vec<(u16, String)>,
    }

    impl FakeProvider {
        async fn start(script: Vec<(u16, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr: SocketAddr = listener.local_addr().expect("addr");
            let inner = Arc::new(Mutex::new(Inner {
                script,
                ..Inner::default()
            }));

            let served = Arc::clone(&inner);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let inner = Arc::clone(&served);
                    tokio::spawn(async move { serve(stream, inner).await });
                }
            });
            Self {
                origin: format!("http://{addr}"),
                inner,
            }
        }

        /// Everything a successful exchange answers with.
        fn issuing() -> Vec<(u16, String)> {
            vec![(
                200,
                r#"{"access_token":"at-first","refresh_token":"rt-first",
                    "token_type":"Bearer","expires_in":3600}"#
                    .to_owned(),
            )]
        }

        fn expect_challenge(&self, challenge: &str) {
            self.inner.lock().expect("not poisoned").challenge = Some(challenge.to_owned());
        }

        fn seen(&self) -> Vec<Seen> {
            self.inner.lock().expect("not poisoned").seen.clone()
        }
    }

    async fn serve(mut stream: TcpStream, inner: Arc<Mutex<Inner>>) {
        let mut buffer = Vec::new();
        loop {
            let Some((head, body)) = read_request(&mut stream, &mut buffer).await else {
                return;
            };
            let form: HashMap<String, String> = url::form_urlencoded::parse(&body)
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            // Matched case-insensitively on the NAME and kept verbatim for the
            // VALUE. Lowercasing the head to find the header would lowercase the
            // base64 with it, and RFC 7617's alphabet is case-sensitive — which
            // is a decoding failure that reads exactly like a wrong credential.
            let authorization = head
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_owned());

            let (status, payload) = {
                let mut inner = inner.lock().expect("not poisoned");
                inner.seen.push(Seen {
                    form: form.clone(),
                    authorization: authorization.clone(),
                });
                // The PKCE check, done by the party that is supposed to do it —
                // and only on the grant PKCE applies to. A refresh carries no
                // code and therefore no verifier, and a fake that demanded one
                // there would be testing its own confusion.
                let is_code_grant =
                    form.get("grant_type").map(String::as_str) == Some("authorization_code");
                let pkce_ok = match (&inner.challenge, form.get("code_verifier")) {
                    _ if !is_code_grant => true,
                    (None, _) => true,
                    (Some(expected), Some(verifier)) => {
                        &B64URL.encode(Sha256::digest(verifier.as_bytes())) == expected
                    }
                    (Some(_), None) => false,
                };
                if pkce_ok {
                    if inner.script.len() > 1 {
                        inner.script.remove(0)
                    } else {
                        inner
                            .script
                            .first()
                            .cloned()
                            .unwrap_or((500, String::new()))
                    }
                } else {
                    (
                        400,
                        r#"{"error":"invalid_grant","error_description":"pkce"}"#.to_owned(),
                    )
                }
            };

            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
                payload.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    /// One HTTP/1.1 request: the head **verbatim**, and the body bytes.
    ///
    /// Verbatim and not lowercased, which the sibling helper in `mcp.rs` can
    /// afford to be and this one cannot: an `Authorization: Basic` value is
    /// base64, RFC 4648's alphabet is case-sensitive, and folding the head to
    /// find a header name corrupts the credential inside it. Header *names* are
    /// matched case-insensitively instead, which is what the HTTP spec actually
    /// says.
    async fn read_request(
        stream: &mut TcpStream,
        buffer: &mut Vec<u8>,
    ) -> Option<(String, Vec<u8>)> {
        loop {
            if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
                let length: usize = head
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|line| line.split_once(':'))
                    .and_then(|(_, v)| v.trim().parse().ok())
                    .unwrap_or(0);
                if buffer.len() >= end + 4 + length {
                    let body = buffer[end + 4..end + 4 + length].to_vec();
                    buffer.drain(..end + 4 + length);
                    return Some((head, body));
                }
            }
            let mut chunk = [0_u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }

    // -- a synthetic catalogue entry ----------------------------------------
    //
    // `Box::leak`, because `Connector` and `OAuth` are `&'static` on purpose:
    // production entries are literals in a `const` array, and the signature says
    // so. A test that wants a connector pointed at a loopback port has to make
    // one static, and leaking two small structs per test is cheaper than making
    // the production type carry an owned string it never needs.
    fn connector_for(provider: &FakeProvider, auth: ClientAuth) -> &'static Connector {
        let endpoints: &'static OAuth = Box::leak(Box::new(OAuth {
            authorize: Box::leak(format!("{}/authorize", provider.origin).into_boxed_str()),
            token: Box::leak(format!("{}/token", provider.origin).into_boxed_str()),
            scopes: "read:things write:things",
            auth,
        }));
        Box::leak(Box::new(Connector {
            key: "fake",
            label: "A fake provider",
            // `waveI-i2` replaced `url: Option<&str>` with `Provision`, which
            // is the same fact said better: a connector is dialled at an
            // address we ship (`Dial`), at one the customer supplies
            // (`Customer`), or at one a bridge mints (`Host`). This fixture
            // dials a fake authorisation server, so it is `Dial`.
            provision: catalog::Provision::Dial("https://mcp.example.test/mcp"),
            reach: Reach::Public,
            credential: Credential::OAuth(endpoints),
            floor: RiskClass::Write,
            // A fake authorisation server has no strangers to reach. `vet` runs
            // over `CATALOG`, not over fixtures, so this is only the field the
            // struct literal owes.
            opt_outs: catalog::OptOuts::NoStrangers,
        }))
    }

    fn credentials() -> Credentials {
        Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([7_u8; 32])))
    }

    fn clients() -> OauthClients {
        OauthClients::parse("fake:our-client-id:our-client-secret").expect("registration")
    }

    const REDIRECT: &str = "https://agentos.test/v1/mcp/oauth/callback";

    fn tenant() -> TenantId {
        TenantId::new_v7(Utc::now())
    }

    /// One query parameter out of an authorize URL.
    fn param(url: &str, name: &str) -> String {
        Url::parse(url)
            .expect("a url")
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| panic!("{name} is not in {url}"))
    }

    /// Drive one whole flow and hand back what the provider saw.
    async fn run_flow(
        provider: &FakeProvider,
        connector: &'static Connector,
    ) -> (Sealed, Started, TenantId) {
        let (creds, clients, tenant) = (credentials(), clients(), tenant());
        let server = Slug::parse("fake-erp").expect("slug");
        let now = Utc::now();
        let started = start(&clients, &creds, tenant, connector, REDIRECT, now).expect("start");
        provider.expect_challenge(&param(&started.authorize_url, "code_challenge"));

        let flow = Claimed {
            tenant_id: tenant,
            connector,
            server,
            state_hash: started.state_hash,
            sealed_verifier: started.sealed_verifier.clone(),
        };
        let sealed = complete(
            &clients,
            &creds,
            &flow,
            "the-authorization-code".to_owned(),
            REDIRECT,
            now,
        )
        .await
        .expect("complete");
        (sealed, started, tenant)
    }

    // -- the flow ------------------------------------------------------------
    /// A provider's own query parameters survive the ones `start` appends.
    ///
    /// `google-gmail`'s `authorize` is not a bare path: it carries
    /// `access_type=offline&prompt=consent`, and without the first of them
    /// Google issues no refresh token at all — a binding that works for one hour
    /// and then has nothing for `refresh_due` to renew. The whole of that
    /// depends on `Url::query_pairs_mut` *appending* rather than replacing, which
    /// is a property of a dependency and therefore exactly the kind of thing to
    /// assert instead of remember. This drives the real catalogue literal, so it
    /// also fails if somebody edits the two parameters out of it.
    #[test]
    fn a_providers_own_authorize_query_survives_what_start_appends() {
        let connector = catalog::find("google-gmail").expect("google-gmail is catalogued");
        let clients =
            OauthClients::parse("google-gmail:our-client-id:our-client-secret").expect("clients");
        let started = start(
            &clients,
            &credentials(),
            tenant(),
            connector,
            REDIRECT,
            Utc::now(),
        )
        .expect("start");

        assert_eq!(
            param(&started.authorize_url, "access_type"),
            "offline",
            "no refresh token without it, and the binding dies in an hour"
        );
        assert_eq!(param(&started.authorize_url, "prompt"), "consent");
        // And what `start` adds is still all there, on the same URL.
        assert_eq!(param(&started.authorize_url, "response_type"), "code");
        assert_eq!(param(&started.authorize_url, "client_id"), "our-client-id");
        assert_eq!(
            param(&started.authorize_url, "code_challenge_method"),
            "S256"
        );
    }

    /// The whole path, against a provider that checks PKCE itself.
    #[tokio::test]
    async fn a_flow_sends_the_verifier_the_challenge_committed_to() {
        let provider = FakeProvider::start(FakeProvider::issuing()).await;
        let connector = connector_for(&provider, ClientAuth::Post);
        let (sealed, started, _) = run_flow(&provider, connector).await;

        // The consent URL is what a customer's browser follows, so every field a
        // provider needs has to be on it, spelled the way the RFC spells it.
        assert_eq!(param(&started.authorize_url, "response_type"), "code");
        assert_eq!(param(&started.authorize_url, "client_id"), "our-client-id");
        assert_eq!(param(&started.authorize_url, "redirect_uri"), REDIRECT);
        assert_eq!(
            param(&started.authorize_url, "scope"),
            "read:things write:things",
            "the scope is ours, from the catalogue, and no request can widen it"
        );
        assert_eq!(
            param(&started.authorize_url, "code_challenge_method"),
            "S256"
        );

        let seen = provider.seen();
        assert_eq!(seen.len(), 1, "one exchange, one round trip");
        assert_eq!(seen[0].form["grant_type"], "authorization_code");
        assert_eq!(seen[0].form["code"], "the-authorization-code");
        assert_eq!(seen[0].form["redirect_uri"], REDIRECT);
        // The provider already refused anything else — see `serve` — so this
        // asserts the value is present as well as correct.
        assert_eq!(
            B64URL.encode(Sha256::digest(seen[0].form["code_verifier"].as_bytes())),
            param(&started.authorize_url, "code_challenge"),
        );

        assert!(!sealed.access.is_empty());
        assert!(sealed.refresh.is_some(), "the provider issued one");
        assert!(sealed.expires_at > Utc::now());
    }

    /// **The PKCE mutation.** Present a verifier that is not the one the
    /// challenge was built from and the provider refuses the exchange.
    ///
    /// Sealed under the flow's own AAD, so this is not "a blob that will not
    /// open" — it opens perfectly and holds the wrong string, which is exactly
    /// the position an attacker who stole a `code` is in.
    #[tokio::test]
    async fn a_stolen_code_without_the_verifier_buys_nothing() {
        let provider = FakeProvider::start(FakeProvider::issuing()).await;
        let connector = connector_for(&provider, ClientAuth::Post);
        let (creds, clients, tenant) = (credentials(), clients(), tenant());
        let server = Slug::parse("fake-erp").expect("slug");
        let now = Utc::now();
        let started = start(&clients, &creds, tenant, connector, REDIRECT, now).expect("start");
        provider.expect_challenge(&param(&started.authorize_url, "code_challenge"));

        let forged = creds
            .seal_as(
                tenant,
                &flow_context(tenant, &started.state_hash),
                &Secret::new("a-verifier-the-challenge-was-not-built-from"),
            )
            .expect("seal");
        let flow = Claimed {
            tenant_id: tenant,
            connector,
            server,
            state_hash: started.state_hash,
            sealed_verifier: forged,
        };
        // `let Err(…) else`, not `expect_err`: `Sealed` has no `Debug` on
        // purpose — it is two credentials — and the compiler refusing to print
        // it in a test failure is that decision being enforced.
        let Err(err) = complete(
            &clients,
            &creds,
            &flow,
            "the-stolen-code".to_owned(),
            REDIRECT,
            now,
        )
        .await
        else {
            panic!("a code presented without its verifier must not be exchangeable");
        };
        assert_eq!(err.code(), "rejected", "{err}");
    }

    /// Two flows never share a state, and the state is not in the row.
    #[tokio::test]
    async fn every_state_is_fresh_and_only_its_hash_is_kept() {
        let provider = FakeProvider::start(FakeProvider::issuing()).await;
        let connector = connector_for(&provider, ClientAuth::Post);
        let (creds, clients, tenant) = (credentials(), clients(), tenant());

        let one = start(&clients, &creds, tenant, connector, REDIRECT, Utc::now()).expect("start");
        let two = start(&clients, &creds, tenant, connector, REDIRECT, Utc::now()).expect("start");

        let (first, second) = (
            param(&one.authorize_url, "state"),
            param(&two.authorize_url, "state"),
        );
        assert_ne!(first, second, "two flows, two states");
        assert_ne!(one.state_hash, two.state_hash);
        // 32 bytes, base64url, no padding.
        assert_eq!(first.len(), 43, "{first}");
        assert_eq!(
            state_hash(&first),
            one.state_hash,
            "one spelling of the key"
        );
        assert_ne!(
            first.as_bytes(),
            one.state_hash,
            "the row stores the hash, never the value"
        );
        // Same for the verifier: RFC 7636's minimum is 43 characters because
        // that is 256 bits, and a shorter one is brute-forceable offline.
        let verifier = creds
            .open_as(
                tenant,
                &flow_context(tenant, &one.state_hash),
                &one.sealed_verifier,
            )
            .expect("open");
        assert_eq!(verifier.expose_for_transport().len(), 43);
    }

    /// A verifier is bound to its own flow: another flow's blob does not open.
    #[tokio::test]
    async fn a_verifier_from_another_flow_does_not_open() {
        let provider = FakeProvider::start(FakeProvider::issuing()).await;
        let connector = connector_for(&provider, ClientAuth::Post);
        let (creds, clients, tenant) = (credentials(), clients(), tenant());
        let server = Slug::parse("fake-erp").expect("slug");
        let one = start(&clients, &creds, tenant, connector, REDIRECT, Utc::now()).expect("start");
        let two = start(&clients, &creds, tenant, connector, REDIRECT, Utc::now()).expect("start");

        // The shape of the attack: an attacker who can write `mcp_oauth_flows`
        // pairs a verifier they know with a state they chose.
        let flow = Claimed {
            tenant_id: tenant,
            connector,
            server,
            state_hash: one.state_hash,
            sealed_verifier: two.sealed_verifier,
        };
        let Err(err) = complete(
            &clients,
            &creds,
            &flow,
            "code".to_owned(),
            REDIRECT,
            Utc::now(),
        )
        .await
        else {
            panic!("a verifier from another flow must not open");
        };
        assert_eq!(err.code(), "secret_decrypt_failed", "{err}");
        assert!(
            provider.seen().is_empty(),
            "and it must fail before anything is sent"
        );
    }

    /// One authentication method per request, and it is the one the entry names.
    #[tokio::test]
    async fn the_client_secret_goes_exactly_one_place() {
        for auth in [ClientAuth::Basic, ClientAuth::Post] {
            let provider = FakeProvider::start(FakeProvider::issuing()).await;
            let connector = connector_for(&provider, auth);
            run_flow(&provider, connector).await;

            let seen = provider.seen().remove(0);
            match auth {
                ClientAuth::Basic => {
                    let header = seen.authorization.expect("a basic header");
                    assert!(
                        header.to_ascii_lowercase().starts_with("basic "),
                        "{header}"
                    );
                    // Standard base64 with padding: RFC 7617's, not the URL
                    // alphabet this module uses for its own values.
                    let encoded = base64::engine::general_purpose::STANDARD
                        .decode(
                            header
                                .split_once(' ')
                                .map_or(header.as_str(), |(_, value)| value),
                        )
                        .expect("base64");
                    assert_eq!(
                        String::from_utf8_lossy(&encoded),
                        "our-client-id:our-client-secret"
                    );
                    assert!(
                        !seen.form.contains_key("client_secret"),
                        "RFC 6749 §2.3: never two authentication methods"
                    );
                }
                ClientAuth::Post => {
                    assert_eq!(seen.form["client_id"], "our-client-id");
                    assert_eq!(seen.form["client_secret"], "our-client-secret");
                    assert!(
                        seen.authorization.is_none(),
                        "RFC 6749 §2.3: never two authentication methods"
                    );
                }
            }
        }
    }

    /// A 200 that is not a token response is not a token.
    #[tokio::test]
    async fn a_response_without_an_access_token_is_refused() {
        for (status, body) in [
            (200, r#"{"token_type":"Bearer","expires_in":3600}"#),
            (200, r#"{"access_token":""}"#),
            (200, "not json at all"),
            (400, r#"{"error":"invalid_client"}"#),
        ] {
            let provider = FakeProvider::start(vec![(status, body.to_owned())]).await;
            let connector = connector_for(&provider, ClientAuth::Post);
            let (creds, clients, tenant) = (credentials(), clients(), tenant());
            let server = Slug::parse("fake-erp").expect("slug");
            let started =
                start(&clients, &creds, tenant, connector, REDIRECT, Utc::now()).expect("start");
            let flow = Claimed {
                tenant_id: tenant,
                connector,
                server,
                state_hash: started.state_hash,
                sealed_verifier: started.sealed_verifier,
            };
            let Err(err) = complete(
                &clients,
                &creds,
                &flow,
                "c".to_owned(),
                REDIRECT,
                Utc::now(),
            )
            .await
            else {
                panic!("{status} {body:?} must not be read as a token");
            };
            assert!(
                matches!(err.code(), "no_access_token" | "unparseable" | "rejected"),
                "{status} {body}: {}",
                err.code()
            );
        }
    }

    /// A provider that says nothing about expiry gets an assumed lifetime, not
    /// eternity — otherwise the refresh loop never selects the row and the
    /// binding dies silently.
    #[tokio::test]
    async fn silence_about_expiry_is_not_a_promise_of_eternity() {
        let issued = parse_issued(br#"{"access_token":"at"}"#).expect("a token");
        assert_eq!(issued.lifetime, ASSUMED_LIFETIME);
        // And a string is as good as a number: several providers send one.
        let issued = parse_issued(br#"{"access_token":"at","expires_in":"120"}"#).expect("token");
        assert_eq!(issued.lifetime, Duration::from_secs(120));
    }

    // -- the registry --------------------------------------------------------

    #[test]
    fn a_registration_is_three_fields_and_the_third_may_contain_colons() {
        let clients = OauthClients::parse("a:id-a:se:cret,b:id-b:plain").expect("parse");
        assert!(clients.has("a") && clients.has("b"));
        assert!(!clients.has("c"));
        assert_eq!(
            clients.get("a").expect("a").secret.expose_for_transport(),
            "se:cret",
            "only the first two colons are ours"
        );
        // Empty is a deployment with no OAuth connectors, not an error.
        assert!(!OauthClients::parse("").expect("empty").has("a"));
        // Anything else is a boot failure: a registration meant to be there and
        // silently skipped is a connector that vanishes with no explanation.
        for (index, bad) in ["a:id", "a", ":id:secret", "a::secret", "a:id:"]
            .into_iter()
            .enumerate()
        {
            let err = OauthClients::parse(bad).expect_err("{bad} must not parse");
            assert_eq!(err.index, 0, "entry {index}: {bad}");
        }
        assert_eq!(
            OauthClients::parse("a:id:secret,broken")
                .expect_err("second entry")
                .index,
            1,
            "the index names which entry"
        );
    }

    /// The registry's `Debug` names connectors and never a credential.
    #[test]
    fn the_registry_never_prints_what_it_holds() {
        let rendered = format!(
            "{:?}",
            OauthClients::parse("a:id-a:se-cret").expect("parse")
        );
        assert!(rendered.contains('a'), "{rendered}");
        assert!(!rendered.contains("se-cret"), "{rendered}");
        assert!(!rendered.contains("id-a"), "{rendered}");
    }

    /// Both refusals, and they are different sentences: one is fixed by an
    /// environment variable and the other cannot be fixed at all.
    #[tokio::test]
    async fn a_connector_needs_both_endpoints_and_a_registration() {
        let provider = FakeProvider::start(FakeProvider::issuing()).await;
        let connector = connector_for(&provider, ClientAuth::Post);

        let Err(err) = start(
            &OauthClients::default(),
            &credentials(),
            tenant(),
            connector,
            REDIRECT,
            Utc::now(),
        ) else {
            panic!("a connector with no client registration cannot start a flow");
        };
        assert_eq!(err.code(), "connector_not_registered", "{err}");

        let Err(err) = start(
            &clients(),
            &credentials(),
            tenant(),
            &catalog::CUSTOM,
            REDIRECT,
            Utc::now(),
        ) else {
            panic!("`custom` takes a pasted token and has no authorization server");
        };
        assert_eq!(err.code(), "connector_is_not_oauth", "{err}");
    }

    // -- refreshing ----------------------------------------------------------

    /// The loop's step: what is due is renewed, what is not is left alone, and a
    /// rotated refresh token replaces the one that issued it.
    #[tokio::test]
    async fn the_binder_loop_renews_what_is_about_to_expire() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the oauth refresh step needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        // The second answer rotates the refresh token, which is what Atlassian
        // and friends do and what silently breaks a client that does not store
        // the new one.
        let provider = FakeProvider::start(vec![
            (
                200,
                r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}"#.to_owned(),
            ),
            (
                200,
                r#"{"access_token":"at-2","refresh_token":"rt-2-rotated","expires_in":3600}"#
                    .to_owned(),
            ),
        ])
        .await;
        let connector = connector_for(&provider, ClientAuth::Post);
        let creds = credentials();
        let clients = clients();
        let tenant = tenant();
        let server = Slug::parse("fake-erp").expect("slug");

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(format!("oauth-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        admin.commit().await.expect("commit");

        // Seed a binding through the real path, so what is stored is what a
        // callback would have stored.
        let now = Utc::now();
        let started = start(&clients, &creds, tenant, connector, REDIRECT, now).expect("start");
        provider.expect_challenge(&param(&started.authorize_url, "code_challenge"));
        let flow = Claimed {
            tenant_id: tenant,
            connector,
            server: server.clone(),
            state_hash: started.state_hash,
            sealed_verifier: started.sealed_verifier,
        };
        let first = complete(&clients, &creds, &flow, "code".to_owned(), REDIRECT, now)
            .await
            .expect("complete");

        // Due in ten minutes, which is inside the margin.
        let expires_at = now + chrono::TimeDelta::minutes(10);
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO mcp_servers \
               (tenant_id, server, url, reach, connector, sealed_token, \
                sealed_refresh_token, token_expires_at) \
             VALUES ($1, $2, 'https://mcp.example.test/mcp', 'public', 'fake', $3, $4, $5)",
        )
        .bind(tenant.as_uuid())
        .bind(server.as_str())
        .bind(first.access.as_slice())
        .bind(first.refresh.as_deref())
        .bind(expires_at)
        .execute(&mut **tx)
        .await
        .expect("insert binding");
        // And a second binding that is nowhere near expiring.
        sqlx::query(
            "INSERT INTO mcp_servers \
               (tenant_id, server, url, reach, connector, sealed_token, \
                sealed_refresh_token, token_expires_at) \
             VALUES ($1, 'later', 'https://mcp.example.test/mcp', 'public', 'fake', $2, $3, $4)",
        )
        .bind(tenant.as_uuid())
        .bind(first.access.as_slice())
        .bind(first.refresh.as_deref())
        .bind(now + chrono::TimeDelta::days(1))
        .execute(&mut **tx)
        .await
        .expect("insert binding");
        tx.commit().await.expect("commit");

        // 1. The selection. This is the half with a `WHERE` in it: a margin
        //    compared the wrong way round selects everything or nothing, and
        //    both look like a working loop from outside.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let selected = due(&mut tx, now).await.expect("select");
        assert_eq!(
            selected
                .iter()
                .map(|r| r.server.as_str())
                .collect::<Vec<_>>(),
            vec![server.as_str()],
            "only the binding inside the margin is due"
        );

        // 2. The refresh itself, with the connector resolved. `refresh_due` does
        //    that lookup against `catalog::find`, which cannot know about a
        //    provider on a loopback port — so the test supplies the entry and
        //    exercises everything on the far side of it.
        refresh_one(
            &mut tx,
            &creds,
            &clients,
            tenant,
            &server,
            connector,
            &selected[0],
            now,
        )
        .await
        .expect("refresh");
        tx.commit().await.expect("commit");

        // What the provider was asked for, and what came back.
        let seen = provider.seen();
        assert_eq!(seen.len(), 2, "one exchange, one refresh");
        assert_eq!(seen[1].form["grant_type"], "refresh_token");
        assert_eq!(
            seen[1].form["refresh_token"], "rt-1",
            "the refresh presents the token the exchange issued"
        );
        assert!(
            !seen[1].form.contains_key("code_verifier"),
            "a refresh carries no code and therefore no verifier"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let (access, refresh, expiry): (Vec<u8>, Option<Vec<u8>>, DateTime<Utc>) = sqlx::query_as(
            "SELECT sealed_token, sealed_refresh_token, token_expires_at \
               FROM mcp_servers WHERE server = $1",
        )
        .bind(server.as_str())
        .fetch_one(&mut **tx)
        .await
        .expect("row");
        tx.rollback().await.expect("rollback");

        assert_eq!(
            creds
                .open_as(
                    tenant,
                    &crate::mcp::credential_context(tenant, &server),
                    &access
                )
                .expect("open")
                .expose_for_transport(),
            "at-2",
            "the binding now carries the token the refresh issued"
        );
        assert_eq!(
            creds
                .open_as(
                    tenant,
                    &refresh_context(tenant, &server),
                    &refresh.expect("stored")
                )
                .expect("open")
                .expose_for_transport(),
            "rt-2-rotated",
            "a rotated refresh token replaces the one that issued it; keeping the \
             old one is a binding that renews exactly once"
        );
        assert!(expiry > expires_at, "the clock moved forward");
    }

    /// The status is what tells a dead credential from a bad minute, and both
    /// directions are one bug away from each other.
    ///
    /// A pure unit over [`post_token`]'s classification, so that the two
    /// database tests below can be about parking rather than about HTTP.
    #[tokio::test]
    async fn a_refused_grant_and_an_overloaded_server_are_not_the_same_answer() {
        let clients = clients();
        for (status, expected) in [
            // RFC 6749 §5.2: `invalid_grant` — the refresh token is dead.
            (400, REJECTED),
            (401, REJECTED),
            (403, REJECTED),
            // ...and the ones that mean "later".
            (429, "unreachable"),
            (500, "unreachable"),
            (503, "unreachable"),
        ] {
            let provider = FakeProvider::start(vec![(status, "{}".to_owned())]).await;
            let connector = connector_for(&provider, ClientAuth::Post);
            let (endpoints, client) =
                registration(&clients, connector).expect("a registered connector");
            let Err(err) = post_token(endpoints, client, &[("grant_type", "refresh_token")]).await
            else {
                panic!("a {status} is not a token");
            };
            assert_eq!(err.code(), expected, "{status}");
            // The `code()` above is what an operator reads; this is what
            // `refresh_due` actually branches on, and only one of them decides
            // whether a customer is sent back through a consent screen.
            assert_eq!(err.needs_a_human(), expected == REJECTED, "{status}");
        }
    }

    /// The whole point of the park: **one** presentation of a refused refresh
    /// token, not one every five minutes for the life of the deployment.
    ///
    /// Both halves are asserted against the same fake in the same test, because
    /// they are the same claim: the second tick must select nothing, and the
    /// provider must see nothing.
    #[tokio::test]
    async fn a_refused_refresh_token_is_presented_once_and_then_never_again() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the oauth refresh step needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        // The exchange succeeds; every refresh after it is refused the way a
        // provider refuses a revoked grant.
        let provider = FakeProvider::start(vec![
            (
                200,
                r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}"#.to_owned(),
            ),
            (400, r#"{"error":"invalid_grant"}"#.to_owned()),
        ])
        .await;
        let connector = connector_for(&provider, ClientAuth::Post);
        let (creds, clients, tenant) = (credentials(), clients(), tenant());
        let server = Slug::parse("fake-erp").expect("slug");
        let now = seed_binding(&db, &provider, connector, &creds, &clients, tenant, &server).await;

        // Tick one: due, presented, refused, parked.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(
            due(&mut tx, now).await.expect("select").len(),
            1,
            "the binding is inside the margin and has something to refresh with"
        );
        let selected = due(&mut tx, now).await.expect("select");
        let Err(err) = refresh_one(
            &mut tx,
            &creds,
            &clients,
            tenant,
            &server,
            connector,
            &selected[0],
            now,
        )
        .await
        else {
            panic!("a 400 from the token endpoint is not a refreshed binding");
        };
        assert_eq!(err.code(), REJECTED);
        assert!(
            err.needs_a_human(),
            "this is the verdict `refresh_due` parks on"
        );
        park_refresh(&mut tx, &server).await.expect("park");
        tx.commit().await.expect("commit");

        // Tick two, and every tick after it.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert!(
            due(&mut tx, now + chrono::TimeDelta::hours(6))
                .await
                .expect("select")
                .is_empty(),
            "a binding whose refresh token was refused must fall out of the selection; leaving \
             it in is a dead credential presented to a third party every five minutes forever"
        );

        // The access token is untouched, which is what makes this a park and
        // not a disconnection: the binding keeps working until it expires.
        let (access, refresh): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT sealed_token, sealed_refresh_token FROM mcp_servers WHERE server = $1",
        )
        .bind(server.as_str())
        .fetch_one(&mut **tx)
        .await
        .expect("row");
        tx.rollback().await.expect("rollback");
        assert!(refresh.is_none(), "the refused refresh token is gone");
        assert_eq!(
            creds
                .open_as(
                    tenant,
                    &crate::mcp::credential_context(tenant, &server),
                    &access
                )
                .expect("open")
                .expose_for_transport(),
            "at-1",
            "the access token is left alone: it may still work, and throwing it away would \
             break a binding that is currently serving tools"
        );

        assert_eq!(
            provider.seen().len(),
            2,
            "one exchange and exactly one refusal — the provider is asked once, not forever"
        );
    }

    /// The mirror, and the one that stops the fix above from being "park
    /// everything".
    ///
    /// A 503 is the provider having a bad minute. Parking on it would cost the
    /// customer a trip back through a consent screen for an outage that ended
    /// while they were reading the email.
    #[tokio::test]
    async fn an_overloaded_authorization_server_does_not_cost_a_binding_its_refresh_token() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the oauth refresh step needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        let provider = FakeProvider::start(vec![
            (
                200,
                r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}"#.to_owned(),
            ),
            (503, "overloaded".to_owned()),
        ])
        .await;
        let connector = connector_for(&provider, ClientAuth::Post);
        let (creds, clients, tenant) = (credentials(), clients(), tenant());
        let server = Slug::parse("fake-erp").expect("slug");
        let now = seed_binding(&db, &provider, connector, &creds, &clients, tenant, &server).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let selected = due(&mut tx, now).await.expect("select");
        let Err(err) = refresh_one(
            &mut tx,
            &creds,
            &clients,
            tenant,
            &server,
            connector,
            &selected[0],
            now,
        )
        .await
        else {
            panic!("a 503 is not a refreshed binding");
        };
        assert_eq!(err.code(), "unreachable", "{err}");
        assert!(
            !err.needs_a_human(),
            "an outage is not a dead credential; parking on it costs the customer a trip \
             back through a consent screen for something that fixed itself"
        );
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(
            due(&mut tx, now).await.expect("select").len(),
            1,
            "an outage must leave the binding due: the refresh token is still good and the \
             next tick is what renews it"
        );
        let refresh: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT sealed_refresh_token FROM mcp_servers WHERE server = $1")
                .bind(server.as_str())
                .fetch_one(&mut **tx)
                .await
                .expect("row");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            creds
                .open_as(
                    tenant,
                    &refresh_context(tenant, &server),
                    &refresh.expect("still stored")
                )
                .expect("open")
                .expose_for_transport(),
            "rt-1",
            "the refresh token survives an outage, or a bad minute at the provider becomes a \
             consent screen for every customer"
        );
    }

    /// The `for` inside [`refresh_due`], which nothing had ever run.
    ///
    /// Every link it chains is proved on its own above — the classification by
    /// `a_refused_grant_and_an_overloaded_server_are_not_the_same_answer`, the
    /// park and the disappearance by the two tests before this one, the
    /// predicate by [`OauthError::needs_a_human`]'s own asserts. And each of
    /// those tests calls [`refresh_one`] and then [`park_refresh`] **by hand, in
    /// that order**, which is this loop's body written a second time. What no
    /// test ran is the loop's own judgement: *which* of the two failures gets
    /// the park, and what the count it returns means afterwards.
    ///
    /// **Two bindings, opposite answers, one tick.** A test with only the
    /// refused one passes against a loop that parks unconditionally, and a test
    /// with only the outage passes against a loop that never parks. Neither
    /// half is a test of a branch; both together are.
    ///
    /// Three claims, and each is a different production failure:
    ///
    /// * the refused binding falls out of the selection — otherwise a dead
    ///   credential is presented to somebody else's authorization server every
    ///   five minutes forever;
    /// * the outage binding stays in it, with the token it could not use —
    ///   otherwise a provider's bad minute costs every customer on it a trip
    ///   back through a consent screen;
    /// * the count is 1 and not 0 or 2. `routes::mcp::refresh_tokens` commits on
    ///   the strength of what that number means: a park is a write, an outage is
    ///   not, and a count that missed the park had the loop rolling it back on
    ///   every tick.
    #[tokio::test]
    async fn one_tick_parks_the_dead_credential_and_leaves_the_outage_alone() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the oauth refresh step needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        // Two exchanges at seed time, then one refusal and one outage. The
        // refreshes arrive in `SELECT_DUE`'s `ORDER BY server`, which is why the
        // handles are named to sort that way.
        let provider = FakeProvider::start(vec![
            (
                200,
                r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}"#.to_owned(),
            ),
            (
                200,
                r#"{"access_token":"at-2","refresh_token":"rt-2","expires_in":3600}"#.to_owned(),
            ),
            (400, r#"{"error":"invalid_grant"}"#.to_owned()),
            (503, "overloaded".to_owned()),
        ])
        .await;
        let connector = connector_for(&provider, ClientAuth::Post);
        // The catalogue the loop resolves against. A token endpoint on a
        // loopback port will never be in `CATALOG`, which is the whole reason
        // `refresh_due` takes this rather than reading the `const`.
        let catalog: &'static [Connector] = std::slice::from_ref(connector);
        let (creds, clients, tenant) = (credentials(), clients(), tenant());
        let dead = Slug::parse("fake-dead").expect("slug");
        let outage = Slug::parse("fake-outage").expect("slug");
        let now = seed_binding(&db, &provider, connector, &creds, &clients, tenant, &dead).await;
        seed_binding(&db, &provider, connector, &creds, &clients, tenant, &outage).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(
            due(&mut tx, now).await.expect("select").len(),
            2,
            "both bindings are inside the margin, or this tick proves nothing"
        );
        let written = refresh_due(&mut tx, &creds, &clients, catalog, now).await;
        tx.commit().await.expect("commit");

        assert_eq!(
            written, 1,
            "the park is a write and the failed refresh is not — this is the number \
             `refresh_tokens` decided to stop branching on, and it has to mean what it says"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let still_due: Vec<String> = due(&mut tx, now)
            .await
            .expect("select")
            .into_iter()
            .map(|row| row.server)
            .collect();
        assert_eq!(
            still_due,
            vec![outage.as_str().to_owned()],
            "the loop parks the refused binding and only the refused one: a 400 is a credential \
             that will never work again, a 503 is a provider having a bad minute, and the two \
             cost opposite things when they are confused"
        );

        let refresh: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT sealed_refresh_token FROM mcp_servers WHERE server = $1")
                .bind(outage.as_str())
                .fetch_one(&mut **tx)
                .await
                .expect("row");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            creds
                .open_as(
                    tenant,
                    &refresh_context(tenant, &outage),
                    &refresh.expect("still stored")
                )
                .expect("open")
                .expose_for_transport(),
            "rt-2",
            "an outage leaves the very token it could not spend"
        );

        assert_eq!(
            provider.seen().len(),
            4,
            "two exchanges and exactly one presentation each — a tick does not retry inside itself"
        );
    }

    /// A tenant, a binding seeded through the real callback path, and a
    /// `token_expires_at` inside [`REFRESH_MARGIN`]. Returns `now`.
    ///
    /// Lifted out of `the_binder_loop_renews_what_is_about_to_expire` when the
    /// two park tests needed the same forty lines. It seeds through `start` and
    /// `complete` rather than by hand, so what is stored is what a real callback
    /// would have stored — sealed under the real AAD, which is the half a
    /// hand-written INSERT gets wrong.
    #[allow(clippy::too_many_arguments)]
    async fn seed_binding(
        db: &Db,
        provider: &FakeProvider,
        connector: &'static Connector,
        creds: &Credentials,
        clients: &OauthClients,
        tenant: TenantId,
        server: &Slug,
    ) -> DateTime<Utc> {
        // `DO NOTHING`, so this can be called twice for the same tenant and
        // seed a **second** binding. The slug is derived from the id, so the
        // only conflict it can swallow is this same row.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query(
            "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2) ON CONFLICT DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(format!("oauth-{}", tenant.as_uuid().simple()))
        .execute(&mut *admin)
        .await
        .expect("tenant");
        admin.commit().await.expect("commit");

        let now = Utc::now();
        let started = start(clients, creds, tenant, connector, REDIRECT, now).expect("start");
        provider.expect_challenge(&param(&started.authorize_url, "code_challenge"));
        let flow = Claimed {
            tenant_id: tenant,
            connector,
            server: server.clone(),
            state_hash: started.state_hash,
            sealed_verifier: started.sealed_verifier,
        };
        let issued = complete(clients, creds, &flow, "code".to_owned(), REDIRECT, now)
            .await
            .expect("complete");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO mcp_servers \
               (tenant_id, server, url, reach, connector, sealed_token, \
                sealed_refresh_token, token_expires_at) \
             VALUES ($1, $2, 'https://mcp.example.test/mcp', 'public', 'fake', $3, $4, $5)",
        )
        .bind(tenant.as_uuid())
        .bind(server.as_str())
        .bind(issued.access.as_slice())
        .bind(issued.refresh.as_deref())
        .bind(now + chrono::TimeDelta::minutes(10))
        .execute(&mut **tx)
        .await
        .expect("insert binding");
        tx.commit().await.expect("commit");
        now
    }
}
