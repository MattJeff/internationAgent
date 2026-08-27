//! The MCP client: one bound server, its tools, and the risk class of each.
//!
//! A concrete struct, not a trait. There is exactly one MCP implementation and
//! there will only ever be one — the protocol *is* the abstraction, and a
//! `trait McpClient` with a single impl would only be a second place to keep
//! in sync.
//!
//! # The two things this module exists to prevent
//!
//! **1. Server-side request forgery.** An agent that can name a URL can name
//! `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, and
//! then the "MCP server" it just connected to is your cloud instance metadata
//! endpoint handing out role credentials. So the check happens at
//! [`McpServer::bind`] — once, when an *operator* configures a server — and
//! never at call time. [`Action::McpCall`] carries a [`McpTool`] (a server
//! handle and a tool handle, both [`Slug`]s), never a URL, so there is no
//! call-time string for a model to steer. Binding resolves the host, refuses
//! every address that is not globally routable, and records the addresses it
//! resolved to.
//!
//! **2. A tool call turning into three.** [`rmcp`] offers `call_tool`, which
//! silently drives SEP-2322 multi-round rounds: the server answers "I need
//! more input", the client answers it, and the extra exchanges happen *behind
//! the Policy Gate's back* — the gate ruled on one call and got several. This
//! module uses `call_tool_once` and treats "another round required" as a
//! refusal. One authorization, one round trip.
//!
//! # There is one transport, it is HTTP, and there will not be a second
//!
//! MCP defines two transports. This module implements one of them, and the
//! omission is a decision rather than a gap, so it is argued here — the day
//! somebody wants to talk to a stdio server, this is the paragraph they have to
//! beat.
//!
//! **What was asked for.** Every MCP server people actually ship is a stdio
//! server: a command, spawned as a child process, JSON-RPC over its pipes. The
//! real Orizn visa server is `npx -y orizn-visa-mcp`, and it is the exact case
//! this product exists to serve. Adding
//! `rmcp::transport::TokioChildProcess` next to
//! [`StreamableHttpClientTransport`] is about fifteen lines.
//!
//! **Why those fifteen lines are not here.** A binding is a row in
//! `mcp_servers`, written through `apps/server/src/routes/mcp.rs` by anyone
//! holding a tenant API key (migration 0019). A stdio transport turns that row's
//! payload from a URL into a **command line**, and the two are not variations on
//! a theme:
//!
//! * A URL is checked by `resolve_and_vet`. There is a real, closed, checkable
//!   property — "does this resolve somewhere globally routable" — and
//!   `placement` is that property, written down. A command has no analogous
//!   property. `sh`, `node -e`, `python -c` and `/proc/self/exe` are all
//!   "a program", and an allowlist of permitted programs *is* the configuration,
//!   which makes the tenant-supplied command redundant.
//! * A URL reaches a process somebody else runs. A spawned command runs **as the
//!   server**, in the server's process tree, with the server's environment —
//!   which holds `DATABASE_URL`, the AES key `crate::secrets` decrypts every
//!   tenant's credentials with, and every provider token in the deployment. The
//!   SSRF defence above exists to stop an agent reading the cloud metadata
//!   endpoint; a child process does not need the metadata endpoint, because it
//!   already has `/proc/self/environ`.
//! * None of the machinery below would notice. [`RiskClass`] classes what a tool
//!   *does on the server side*, and `allowed_mcp_tools` names tools by handle.
//!   Both reason about calls. A hostile binding does its work at spawn time,
//!   before any tool is called, and every control in this file rules on calls.
//!   Fail-closed on tool classification is not fail-closed on process creation.
//!
//! So the honest containment for a tenant-configurable stdio transport is a
//! sandbox: a per-tenant container, a scrubbed environment, a read-only root, a
//! seccomp profile, and a resource limit — a piece of infrastructure larger than
//! this crate, and one whose absence would be invisible until the day it
//! mattered. The rule this module already follows is that a control it cannot
//! state is a control it does not have, and it cannot state that one.
//!
//! **The two shapes that were rejected, and why HTTP-only beat them.**
//!
//! *Stdio in the product, contained.* Rejected on the paragraph above: the
//! containment is unbuilt, and shipping the transport first and the sandbox
//! later means shipping remote code execution behind a `CHECK` constraint. The
//! containment is the feature; the transport is the easy part.
//!
//! *An operator-level stdio bridge — a command named in the deployment's config
//! rather than in a tenant's row.* This is the closest call, and it is genuinely
//! safer: the operator already chooses the binary the server runs. But it buys
//! that safety by asserting the operator is trusted, which is the same assertion
//! HTTP-only makes with **no new code, no second configuration surface, and no
//! second class of binding** for `Fleet` to route between. It would also fork
//! this file's one clean sentence — *a binding is a URL, checked at bind time* —
//! into two sentences with different security properties, and the second one
//! would be the one nobody re-reads. An operator who wants a local stdio server
//! can already have one, by running it and pointing a `private` binding at it,
//! which is what [`Reach::Private`] is for and is why it exists.
//!
//! **A server that already speaks Streamable HTTP needs none of this.** Bind its
//! URL and stop; that is the ordinary case and it is the whole of what this
//! module was built for. Orizn's own data is reachable that way — the MCP
//! endpoint under `visa.orizn.app` answers `tools/list` and `tools/call` over
//! HTTP directly — so the tenant this workspace exists to serve does not need a
//! bridge at all. Do not read the paragraph below as the Orizn path; it is not.
//!
//! **What the operator has to run for a server that speaks only stdio.** One
//! process per such server, in front of it, translating to Streamable HTTP. This
//! is the general mechanism and it is the reason the decision above cost
//! nothing: refusing stdio *in the product* does not refuse stdio *servers*, it
//! moves the containment to where the operator already has it. Off the shelf:
//!
//! ```text
//! npx -y supergateway --stdio "<the server's own command>" \
//!     --outputTransport streamableHttp --port 8931 --streamableHttpPath /mcp
//! ```
//!
//! and then a binding at `http://127.0.0.1:8931/mcp` with `reach = 'private'`.
//! That is a sidecar — the case [`Reach::Private`] was written for — and it is
//! how `crates/app/tests/orizn.rs` reaches `orizn-visa-mcp`'s **stdio** package,
//! with the same command and no test-only path through this module. That test
//! keeps using the bridge deliberately even though the HTTP endpoint exists,
//! because the bridge is the path every *other* tenant's stdio server will take
//! and it should be exercised by something. Writing our own proxy instead would
//! be re-implementing a JSON-RPC pipe pump in order to avoid depending on one.
//!
//! The containment moves with the process: the bridge runs where the operator
//! puts it, under whatever the operator's platform gives it, and this server
//! keeps talking to a socket. That is the whole argument — not that stdio is
//! bad, but that *spawning* is a different privilege from *dialling*, and this
//! process should only ever do the second one.
//!
//! **Where that argument now stands.** It stands, unchanged, and
//! [`crate::hosted`] is what it invited: the last sentence above is the load
//! bearing one, and the way to serve a customer who cannot run a bridge is not
//! to weaken it but to move the spawning somewhere this process has no
//! privilege at all. A hosted binding is a [`Package`](crate::hosted::Package)
//! this binary names — never a tenant's command line, which is the objection
//! above and is not answered, only avoided — started by a
//! [`BridgeRuntime`](crate::hosted::BridgeRuntime) that is a different process
//! on a different network, and reached from here as a URL like any other. Every
//! control in this file still rules on calls, and now nothing in this file has
//! to rule on process creation, because this process still creates none.
//!
//! # Risk classes are declared, not discovered
//!
//! Every discovered tool gets a [`RiskClass`]. It comes from the operator's
//! declaration, because the alternative — the server's own `annotations` —
//! is written by the thing we are defending against. The MCP specification
//! says so itself: *"Clients should never make tool use decisions based on
//! ToolAnnotations received from untrusted servers."* So a server's hints can
//! only make a tool **more** dangerous than declared, never less, and a tool
//! nobody declared is [`RiskClass::Destructive`] — which needs a human.
//!
//! # What comes back is untrusted
//!
//! A tool result is text a third party wrote. It leaves this module as an
//! [`Untrusted<CallToolResult>`] so it cannot be spliced into a prompt without
//! a call site that greps.
//!
//! # Where a binding comes from, and what the model is told about it
//!
//! [`Fleet`] is this module's production entry point: it reads one tenant's
//! `mcp_servers` / `mcp_tool_declarations` rows (migration 0013), binds each
//! one, and is the [`McpCaller`] behind
//! [`Effects::call_tool`](crate::effects::Effects::call_tool).
//!
//! Those rows come from `apps/server/src/routes/mcp.rs`, which is the operator's
//! door and the only writer. Two things about it are load-bearing here and are
//! not this module's to enforce: a [`Declaration::digest`] is only ever accepted
//! against a digest the server is serving *at that moment*, so a pin cannot be
//! invented by someone who has not looked; and [`Fleet::bind`] is called from a
//! background loop rather than from a request, because it resolves DNS and opens
//! a connection. [`Fleet::failures`] is what that loop reports back — a server
//! that will not bind is dropped from the fleet on purpose, and a drop nobody
//! can see is a drop nobody can fix.
//!
//! [`Fleet::inventory`] is the other half, and it is the half that was missing:
//! the turn loop offers ONE `call_mcp_tool` schema for every MCP tool on every
//! server (see [`crate::turn`] for why that stays), so without a list of names
//! the model can only guess one and the gate denies the guess. The inventory is
//! that list, and it is deliberately narrow:
//!
//! * **Only tools the operator declared.** A tool nobody declared is named by
//!   the server and by nobody else, and [`crate::prompt`] exists to keep a
//!   counterparty's text out of the cached prefix. An undeclared tool is still
//!   bound and still callable by exact name — it is just not something a
//!   hostile server gets to write into a system prompt.
//! * **Names only, never descriptions.** [`BoundTool::description`] is the
//!   server's own prose, which is why it is an [`Untrusted<String>`]. It is for
//!   a human reading an approval, not for the prefix.
//! * **Filtered by the turn's trust label**, by
//!   [`SystemPrompt::render`](crate::prompt::SystemPrompt::render), on the same
//!   axis and through the same predicate as the tool schemas —
//!   [`crate::turn::visible`].
//! * **Narrowed to what the employee may call**, by
//!   [`SystemPrompt::with_mcp_tools`](crate::prompt::SystemPrompt::with_mcp_tools),
//!   through the policy allowlist the gate rules with. This is a *tenant's*
//!   inventory: an employee is one seat in it, and telling every seat about
//!   every server is both a token bill that grows with the company's
//!   integrations and an invitation to spend turns being denied.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use agentos_domain::action::{McpTool, Risk};
use agentos_domain::ids::Slug;
use agentos_domain::policy::{ApprovalReason, Decision, DenyReason};
use agentos_domain::untrusted::Untrusted;
use agentos_providers::secrets::LocalEnvelopeSecretStore;
use agentos_providers::{ProviderError, Secret};
use agentos_store::db::{StoreError, TenantTx};
use async_trait::async_trait;
use rmcp::RoleClient;
use rmcp::ServiceError;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities, ClientInfo,
    Implementation, JsonObject, ProtocolVersion, Tool, ToolAnnotations,
};
use rmcp::service::{ClientLifecycleMode, RunningService, serve_client_with_lifecycle_and_ct};
use rmcp::transport::streamable_http_client::{
    AuthRequiredError, InsufficientScopeError, StreamableHttpClientTransportConfig,
};
use rmcp::transport::{DynamicTransportError, StreamableHttpClientTransport};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::effects::McpCaller;

/// What we tell an MCP server we are. Display only; nothing authorises off it.
const CLIENT_NAME: &str = "agentos";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The only schemes a binding URL may use.
///
/// ponytail: a constant, not config. `file:`, `ftp:` and `gopher:` are how a
/// URL allowlist gets walked around; if an operator needs a third scheme they
/// can ask, and we can ask why.
const ALLOWED_SCHEMES: [&str; 2] = ["http", "https"];

/// How long one tool call may take before it is abandoned.
///
/// **This is the only bound on it.** Nothing between here and `Turn::run`
/// applies a clock to an effect: the turn's `CancellationToken` races the model
/// call and not the tool call, and `apps/server`'s `TURN_DEADLINE` fires that
/// token — so a tool call that never returns is a turn that never returns and,
/// on the inbound path, an outbox handler's transaction that is never
/// committed or rolled back.
///
/// Half of `TURN_DEADLINE`'s 120 seconds, which is the number this has to fit
/// inside: a call allowed to run to the deadline leaves the turn no time to do
/// anything with the answer, and a turn is allowed several calls.
///
/// ponytail: one constant, not per-server config, and the ceiling is that a
/// genuinely slow tool — a long ERP report — is cut off at a number nobody
/// chose for it. The upgrade is a column on `mcp_servers` read at bind time and
/// carried on `McpServer`, the day an operator has one that needs it. Two
/// numbers that can disagree is worse than one that is occasionally short.
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long one binding may take to hand shake and list its tools.
///
/// **This is the only bound on it, and the thing it protects is other tenants.**
/// [`CALL_TIMEOUT`] covers `tools/call` and nothing covered the two exchanges
/// before it. `routes::mcp::run` walks the deployment's tenants one at a time
/// and awaits each [`Fleet::bind`], and [`Fleet::bind`] walks a tenant's servers
/// one at a time — so a single socket that accepts a connection and then says
/// nothing wedges the binder for **every tenant in the process**, permanently.
/// Their fleets are never bound and never refreshed, their employees take turns
/// with no MCP tools, and the operator's binding page says `pending` with no
/// reason on it. A connect timeout does not see this: the connect succeeded.
///
/// Thirty seconds, and the floor under that number is `ClientLifecycleMode::Auto`
/// — it probes `server/discover` and falls back to the legacy `initialize`
/// handshake after ten seconds of silence, so anything at or under ten would
/// abandon exactly the older servers the fallback exists for. What is left is
/// twenty seconds for the legacy handshake and `tools/list`, against an endpoint
/// that is by construction not on a turn's critical path: binding happens in a
/// background loop, and the two routes that bind inline are an operator's own
/// admin request under the 30-second request timeout.
///
/// ponytail: one constant, like [`CALL_TIMEOUT`], with the same ceiling — a
/// genuinely slow server is cut off at a number nobody chose for it, and the
/// upgrade is the same per-server column. Two numbers that can disagree is
/// worse than one that is occasionally short.
const BIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

/// How much damage one tool does if the call was steered by an attacker.
///
/// Ordered: `Read < Write < Destructive`, so "the stricter of two opinions" is
/// [`Ord::max`] and nothing has to remember which way round the comparison
/// goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskClass {
    /// Observes without changing anything.
    Read,
    /// Changes something, reversibly.
    Write,
    /// Irreversible, or expensive to undo. Needs a human.
    Destructive,
}

impl RiskClass {
    /// Stable, low-cardinality metric label.
    pub const fn code(self) -> &'static str {
        match self {
            RiskClass::Read => "read",
            RiskClass::Write => "write",
            RiskClass::Destructive => "destructive",
        }
    }

    /// The spelling `mcp_tool_declarations.risk` accepts back.
    ///
    /// The same strings [`RiskClass::code`] emits, so the metric label and the
    /// stored value cannot drift into two vocabularies. An unknown spelling is
    /// `None` — never a default — because every default here is a class
    /// somebody did not choose.
    pub fn parse(raw: &str) -> Option<Self> {
        [RiskClass::Read, RiskClass::Write, RiskClass::Destructive]
            .into_iter()
            .find(|class| class.code() == raw)
    }

    /// The class a server's own annotations claim.
    ///
    /// Only ever used to *raise* a declared class — see [`classify`]. The
    /// defaults follow the MCP schema: a tool that says nothing about itself
    /// is assumed destructive.
    fn from_hints(hints: &ToolAnnotations) -> Self {
        if hints.read_only_hint == Some(true) {
            RiskClass::Read
        } else if hints.destructive_hint == Some(false) {
            RiskClass::Write
        } else {
            RiskClass::Destructive
        }
    }
}

/// The blast radius a [`RiskClass`] is worth on the domain's own axis.
///
/// One mapping, in one place, because the trust filter in [`crate::turn`] and
/// the evaluator in `domain::policy` both reason in [`Risk`], and a second
/// opinion about what "high" means is how a schema the model can see stops
/// matching the ruling it will get. `Destructive` is the irreversible one, and
/// it is the only one an untrusted turn is not told about.
impl From<RiskClass> for Risk {
    fn from(class: RiskClass) -> Self {
        match class {
            RiskClass::Read | RiskClass::Write => Risk::Low,
            RiskClass::Destructive => Risk::High,
        }
    }
}

/// The final class for one tool: what the operator declared, raised by
/// anything worse the server admits to.
///
/// An undeclared tool is [`RiskClass::Destructive`] whatever the server says
/// about it. That is the fail-closed half: discovering a new tool must never
/// silently widen what an employee can do.
fn classify(declared: Option<RiskClass>, hints: Option<&ToolAnnotations>) -> RiskClass {
    let Some(declared) = declared else {
        return RiskClass::Destructive;
    };
    match hints.map(RiskClass::from_hints) {
        Some(hinted) => declared.max(hinted),
        None => declared,
    }
}

// ---------------------------------------------------------------------------
// Reach
// ---------------------------------------------------------------------------

/// Which resolved addresses a binding may point at.
///
/// Neither variant permits link-local, multicast, unspecified or reserved
/// space: `169.254.169.254` — every major cloud's credential endpoint — is
/// link-local, and no legitimate MCP server lives there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reach {
    /// Globally routable addresses only. The default, and the right answer for
    /// anything an operator typed into a tenant's configuration.
    #[default]
    Public,
    /// Also permits loopback and RFC 1918 / unique-local space, for an MCP
    /// server running as a sidecar on the same host or the same VPC.
    /// Deliberately opt-in and deliberately per-binding.
    Private,
}

impl Reach {
    /// The spelling `mcp_servers.reach` accepts back, and the one an operator
    /// writes on the wire. Matches `mcp_servers_reach_known`.
    pub const fn code(self) -> &'static str {
        match self {
            Reach::Public => "public",
            Reach::Private => "private",
        }
    }

    /// Parse a stored or submitted spelling. `None` for anything else — the
    /// caller decides, and every caller here decides [`Reach::Public`], which
    /// is the one that refuses loopback.
    pub fn parse(raw: &str) -> Option<Self> {
        [Reach::Public, Reach::Private]
            .into_iter()
            .find(|reach| reach.code() == raw)
    }
}

/// Where one resolved address sits.
///
/// `pub(crate)` for [`crate::hosted`], which has to run this *before* its own
/// narrower check and must not restate it: a bridge network that happens to
/// contain the metadata endpoint still does not get it, and the only way to
/// promise that is for both callers to ask the same function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Routable on the public internet.
    Global,
    /// Reachable but internal: loopback, RFC 1918, unique-local.
    Private,
    /// Never a legitimate MCP server: metadata endpoints, multicast,
    /// unspecified, reserved.
    Forbidden,
}

pub(crate) fn placement(ip: IpAddr) -> Placement {
    match ip {
        IpAddr::V4(v4) => placement_v4(v4),
        // `::1` first: it sits inside the IPv4-compatible range and would
        // otherwise be read as the v4 address `0.0.0.1`.
        IpAddr::V6(v6) if v6.is_loopback() => Placement::Private,
        // An IPv4 address wearing an IPv6 costume is still that IPv4 address.
        // `to_ipv4` covers both spellings — `::ffff:169.254.169.254` and the
        // deprecated `::169.254.169.254` — and neither may skip the v4 rules.
        IpAddr::V6(v6) => v6.to_ipv4().map_or_else(|| placement_v6(v6), placement_v4),
    }
}

fn placement_v4(ip: Ipv4Addr) -> Placement {
    let [a, b, ..] = ip.octets();
    if ip.is_link_local()          // 169.254/16 — the cloud metadata endpoint
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0                  // "this network"
        || (a == 100 && (64..128).contains(&b))  // CGNAT 100.64/10
        || (a == 192 && b == 0)    // IETF protocol assignments 192.0.0/24
        || (a == 198 && (b == 18 || b == 19))    // benchmarking 198.18/15
        || a >= 240
    {
        Placement::Forbidden
    } else if ip.is_loopback() || ip.is_private() {
        Placement::Private
    } else {
        Placement::Global
    }
}

fn placement_v6(ip: Ipv6Addr) -> Placement {
    // `is_unicast_link_local` and `is_unique_local` are still unstable, so the
    // two prefixes are matched by hand: fe80::/10 and fc00::/7.
    let head = ip.segments()[0];
    if ip.is_unspecified() || ip.is_multicast() || (head & 0xffc0) == 0xfe80 {
        Placement::Forbidden
    } else if ip.is_loopback() || (head & 0xfe00) == 0xfc00 {
        Placement::Private
    } else {
        Placement::Global
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything binding or calling can fail with.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    /// Not `http` or `https`, or not a URL at all.
    #[error("{0:?} is not an http(s) url")]
    BadUrl(String),

    /// DNS said nothing, or said something we could not use.
    #[error("could not resolve {host:?}: {detail}")]
    Unresolvable { host: String, detail: String },

    /// **The SSRF stop.** The host resolves somewhere we refuse to talk to.
    #[error("{host:?} resolves to {ip}, which is not a permitted destination")]
    Blocked { host: String, ip: IpAddr },

    /// Two of the server's tool names collapse to one policy handle, so an
    /// allowlist entry would be ambiguous. Refused rather than guessed.
    #[error("tools {first:?} and {second:?} both map to the handle {handle}")]
    AmbiguousTool {
        handle: Slug,
        first: String,
        second: String,
    },

    /// The tool is not on this binding, or the action names another server.
    #[error("{0} is not a tool on this server")]
    UnknownTool(McpTool),

    /// The tool's risk class refuses the call on its own, before the server is
    /// contacted. Carries the ruling so the caller can file an approval.
    #[error("refused before dispatch: {0:?}")]
    Refused(Decision),

    /// The server wants another exchange to finish this call — a SEP-2322
    /// input round, or a background task. One authorization buys one round
    /// trip, so this is a refusal, not something to loop on.
    #[error("{0} needs a second round trip, which this authorization does not cover")]
    MoreRoundsRequired(McpTool),

    /// The connection could not be established.
    #[error("could not connect to the mcp server: {0}")]
    Connect(String),

    /// The server took the request and did not answer inside
    /// [`CALL_TIMEOUT`].
    ///
    /// Its own variant rather than a [`Self::Connect`] with a different string,
    /// because the two are different sentences at 3am: `connect_failed` says the
    /// server is unreachable and `timed_out` says it is reachable and slow, and
    /// the second one is the operator's problem to take up with whoever runs it.
    #[error("{tool} did not answer within {secs}s")]
    TimedOut {
        /// Which call gave up.
        tool: McpTool,
        /// The ceiling it hit.
        secs: u64,
    },

    /// The server accepted the connection and did not finish the handshake or
    /// list its tools inside [`BIND_TIMEOUT`].
    ///
    /// Distinct from [`Self::Connect`] for the reason [`Self::TimedOut`] gives —
    /// the connect succeeded, so `connect_failed` would point an operator at
    /// DNS and firewalls when the fault is the endpoint being mute — and
    /// distinct from [`Self::TimedOut`] because there is no tool yet to name.
    /// This is what an operator sees in `BindFailure::detail` when their
    /// binding never comes up.
    #[error("the mcp server accepted the connection and went quiet for {secs}s")]
    BindTimedOut {
        /// The ceiling it hit.
        secs: u64,
    },

    /// The stored credential could not be read.
    ///
    /// Its own variant rather than a [`Self::Connect`], because it is the one
    /// failure in this enum that is **ours**: the endpoint is fine, the address
    /// is fine, and what changed is the deployment's master key or the row. The
    /// alternative — binding without the header — produces a 401 from a
    /// stranger's server, which is the single most misleading answer this
    /// subsystem can give, because it points an operator at the customer's token
    /// when the fault is on our side of the wire.
    ///
    /// Carries the cipher's own code and **nothing else**: no blob, no context,
    /// no length. This error is rendered into `BindFailure::detail`, which
    /// `apps/server` puts in a JSON response.
    #[error("the stored credential for this server could not be read: {code}")]
    Credential {
        /// `envelope_malformed` or `secret_decrypt_failed`.
        code: &'static str,
    },

    /// A [`crate::hosted`] binding has no bridge to talk to.
    ///
    /// One variant for the whole hosting path, carrying a `&'static str`, and
    /// both halves of that are the design: this is rendered into
    /// [`BindFailure::detail`] and from there into a JSON response, so a
    /// runtime's own words must not be able to reach it. See
    /// [`crate::hosted::BridgeError`].
    ///
    /// The codes: `hosting_unavailable` (this deployment runs no bridge
    /// runtime), `bridge_endpoint_refused` (the address it answered with is not
    /// one we may dial), `bridge_endpoint_not_an_address` (it answered with a
    /// name), or whatever code the runtime itself returned. A row naming a
    /// connector this build does not host is not in here on purpose: it is not
    /// a hosted binding at all, so it is skipped by [`provisioned`] like any
    /// other row that names nothing.
    #[error("no bridge for this hosted server: {code}")]
    Hosting {
        /// Stable and low cardinality, by construction.
        code: &'static str,
    },

    /// The server was reached and the exchange failed.
    #[error(transparent)]
    Transport(#[from] ServiceError),
}

impl McpError {
    /// Stable, low-cardinality metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            McpError::BadUrl(_) => "bad_url",
            McpError::Unresolvable { .. } => "unresolvable",
            McpError::Blocked { .. } => "blocked_address",
            McpError::AmbiguousTool { .. } => "ambiguous_tool",
            McpError::UnknownTool(_) => "unknown_tool",
            McpError::Refused(_) => "refused",
            McpError::MoreRoundsRequired(_) => "more_rounds_required",
            McpError::Connect(_) => "connect_failed",
            McpError::TimedOut { .. } => "timed_out",
            McpError::BindTimedOut { .. } => "bind_timed_out",
            // The cipher's own code passes through: `envelope_malformed` and
            // `secret_decrypt_failed` are already stable, low-cardinality, and
            // they say which of the two things went wrong.
            McpError::Credential { code } => code,
            // Same pass-through, same reason: `hosted::BridgeError` is a
            // `&'static str` precisely so that it already is a metric label.
            McpError::Hosting { code } => code,
            McpError::Transport(_) => "transport",
        }
    }
}

// ---------------------------------------------------------------------------
// Bound tools
// ---------------------------------------------------------------------------

/// One tool, as it was discovered at bind time.
#[derive(Debug, Clone)]
pub struct BoundTool {
    /// The name to put on the wire. Kept verbatim because it is the server's
    /// spelling, not ours — `read_file`, not `read-file`.
    wire_name: String,
    risk: RiskClass,
    /// The server's own one-liner, for an approval prompt. Untrusted: a server
    /// that wanted a human to click "approve" would write it here.
    description: Option<Untrusted<String>>,
    /// Whether an operator wrote this tool's NAME down.
    ///
    /// Not the same question as "what class is it": a declaration whose digest
    /// no longer matches is `declared` and [`RiskClass::Destructive`]. This bit
    /// answers only "did a human choose this string", which is what
    /// [`Fleet::inventory`] needs before it puts the string in a system prompt.
    declared: bool,
    /// The digest of this tool **as the server is serving it right now**.
    ///
    /// Not the declared one: [`Declaration::digest`] is what a human vetted, and
    /// the whole point is that the two are allowed to disagree. This is the
    /// value an operator has to be shown before they can pin anything, which is
    /// what [`McpServer::bind`] plus this field make possible without a
    /// "refresh the digest" verb that would advance the baseline for them.
    digest: [u8; 32],
}

impl BoundTool {
    /// The name this tool is called by on the wire.
    pub fn wire_name(&self) -> &str {
        &self.wire_name
    }

    /// The class this tool was bound at.
    pub const fn risk(&self) -> RiskClass {
        self.risk
    }

    /// The server's description, still wrapped.
    pub const fn description(&self) -> Option<&Untrusted<String>> {
        self.description.as_ref()
    }

    /// Whether an operator named this tool in their configuration.
    pub const fn is_declared(&self) -> bool {
        self.declared
    }

    /// The digest of the tool the server served at bind time.
    ///
    /// The operator's copy of this is what a [`Declaration`] pins. Showing it
    /// is the only supported way to obtain one: nothing in this crate writes a
    /// declaration, so a digest reaches the database only by a human reading
    /// this and sending it back.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// The policy handle for a wire tool name.
///
/// MCP names are conventionally `snake_case`; a [`Slug`] is `kebab-case`, so
/// underscores fold to hyphens. The fold is not injective, which is why
/// [`McpServer::bind`] refuses a server whose names collide — otherwise
/// allowlisting `read-file` would silently also allow `read_file`.
fn handle(wire_name: &str) -> Option<Slug> {
    Slug::parse(&wire_name.replace('_', "-")).ok()
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// One MCP server, bound and ready.
///
/// Construct with [`McpServer::bind`]. The connection lives for as long as the
/// value does, or until the [`CancellationToken`] it was given is cancelled.
pub struct McpServer {
    /// The handle an [`Action::McpCall`] names this server by.
    server: Slug,
    url: Url,
    /// The addresses the host resolved to at bind time.
    pinned: Vec<IpAddr>,
    tools: BTreeMap<Slug, BoundTool>,
    client: RunningService<RoleClient, ClientInfo>,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("server", &self.server)
            .field("url", &self.url.as_str())
            .field("pinned", &self.pinned)
            .field("tools", &self.tools)
            .finish()
    }
}

impl McpServer {
    /// Vet the URL, connect, and discover the server's tools.
    ///
    /// `declared` maps a tool handle to the class an operator vetted it at.
    /// Anything the server offers that is not in there is bound as
    /// [`RiskClass::Destructive`]; anything in there that the server does not
    /// offer is ignored.
    ///
    /// `token` is sent as `Authorization: Bearer <it>` on every request this
    /// binding makes, and `None` sends no header at all — not an empty one. It
    /// is borrowed rather than owned so the plaintext is alive for the length of
    /// this call and not for the length of the binding: what the transport keeps
    /// is a header value it built, and [`Secret`] zeroizes when the caller's
    /// copy drops. See [`crate::secrets::SecretResolver::with_secret`], which is
    /// the same shape.
    ///
    /// **The credential does not widen anything.** It is read *after*
    /// [`vet_url`] and [`resolve_and_vet`], so there is no token that buys a
    /// binding to an address the SSRF check refuses; and `rmcp`'s reqwest client
    /// is built with `redirect::Policy::none()`, so the header cannot be
    /// replayed to a host that never passed the check.
    ///
    /// Every side effect that matters happens here, once, under operator
    /// control: the DNS lookup, the address check, and the tool inventory.
    /// Nothing at call time takes a string from anywhere but this struct.
    pub async fn bind(
        server: Slug,
        url: &str,
        declared: &BTreeMap<Slug, Declaration>,
        reach: Reach,
        token: Option<&Secret>,
        ct: CancellationToken,
    ) -> Result<Self, McpError> {
        let url = vet_url(url)?;
        // Before the credential is touched, and the order is the property: a
        // token is not a key to an address, and there is no arrangement of this
        // function in which one becomes one.
        let pinned = resolve_and_vet(&url, reach).await?;

        // ponytail: the resolved addresses are recorded, not forced onto the
        // socket — `rmcp`'s convenience transport builds its own HTTP client
        // and this crate cannot name reqwest to hand it a `.resolve()` pin.
        // The residual hole is DNS rebinding between this lookup and the first
        // request. Closing it is one line (`reqwest::Client::builder()
        // .resolve(host, addr)` fed to `StreamableHttpClientTransport::
        // with_client`) the day `reqwest` is a direct dependency of this crate.
        let mut config = StreamableHttpClientTransportConfig::with_uri(url.as_str());
        if let Some(token) = token {
            // `auth_header` takes the token WITHOUT the `Bearer ` prefix; rmcp
            // writes the scheme itself. Prefixing it here would send
            // `Bearer Bearer …`, which every server answers 401 to and no error
            // message explains.
            config = config.auth_header(token.expose_for_transport());
        }
        let transport = StreamableHttpClientTransport::from_config(config);
        let info = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new(CLIENT_NAME, CLIENT_VERSION),
        );
        // Everything from here to the inventory is somebody else's server
        // talking, and until this timeout existed none of it was bounded. See
        // [`BIND_TIMEOUT`] for whose outage that became. It wraps both exchanges
        // rather than each of them, because the ceiling that matters is how long
        // *this binding* holds the loop — a server that spends the whole budget
        // on the handshake and then lists instantly has still spent it.
        //
        // Dropping the future on timeout drops the transport with it, which
        // closes the socket; there is nothing to unwind and nothing to leak.
        let bound = tokio::time::timeout(BIND_TIMEOUT, async move {
            let client = serve_client_with_lifecycle_and_ct(
                info,
                transport,
                // `Auto`, not `Discover`. The note that used to sit here said to
                // switch it "the day a server that predates the revision has to be
                // supported — it is the same one literal", and that day arrived the
                // first time this client was pointed at a server somebody else
                // wrote. `Discover` is sessionless — no `initialize`, no session id,
                // the protocol version on every request — and `rmcp` is explicit
                // that it "does not fall back; a legacy server is an error". Every
                // MCP server in the wild today is that error: the reference SDKs
                // answer `server/discover` with `-32601 Method not found`, and the
                // real Orizn server (2025-06-18) is one of them, so `Discover` made
                // `bind` a function that could not bind anything a tenant owns.
                //
                // `Auto` probes with `server/discover` first and falls back to the
                // legacy `initialize` handshake on a correlated JSON-RPC error or
                // after ten seconds of silence. It costs one extra round trip at
                // bind time — which happens once, in a background loop, never on a
                // turn — and it buys the entire installed base.
                //
                // `legacy_version` is `V_2025_06_18` rather than `None` (which would
                // leave `ClientInfo`'s own `LATEST`, currently 2025-11-25) because
                // the fallback is for servers that are *behind*, and a fallback that
                // opens by naming a revision older servers reject is a fallback that
                // fails on the servers it exists for. 2025-06-18 is the oldest
                // revision that still carries the tool-annotation fields
                // `RiskClass::from_hints` reads.
                ClientLifecycleMode::Auto {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                    legacy_version: Some(ProtocolVersion::V_2025_06_18),
                },
                ct,
            )
            .await
            .map_err(|e| McpError::Connect(e.to_string()))?;

            // `list_all_tools` walks `next_cursor` for us; a partial inventory
            // would silently classify the tools on page two as undeclared.
            let discovered = client.list_all_tools().await?;
            let tools = inventory(&discovered, declared)?;
            Ok::<_, McpError>((client, tools))
        })
        .await
        .map_err(|_| McpError::BindTimedOut {
            secs: BIND_TIMEOUT.as_secs(),
        })?;
        let (client, tools) = bound?;

        Ok(Self {
            server,
            url,
            pinned,
            tools,
            client,
        })
    }

    /// The handle this server is named by.
    pub const fn name(&self) -> &Slug {
        &self.server
    }

    /// The addresses the host resolved to when it was bound.
    pub fn pinned_addresses(&self) -> &[IpAddr] {
        &self.pinned
    }

    /// Everything discovered, by policy handle.
    pub const fn tools(&self) -> &BTreeMap<Slug, BoundTool> {
        &self.tools
    }

    /// What this tool's class demands, on top of whatever the policy said.
    ///
    /// This is a *second* gate, not a replacement for `policy::evaluate`: the
    /// policy decides whether an employee may touch this tool at all, and this
    /// decides whether a human has to watch. Feed the [`Decision`] to
    /// `PolicyGate::redeem_approval` when it asks for one.
    pub fn verdict(&self, tool: &McpTool) -> Decision {
        let Some(bound) = self.lookup(tool) else {
            return Decision::Deny {
                reason: DenyReason::ToolNotAllowed,
            };
        };
        match bound.risk {
            RiskClass::Read | RiskClass::Write => Decision::Allow,
            RiskClass::Destructive => Decision::RequireApproval {
                // ponytail: `ApprovalReason` is a closed domain enum this unit
                // does not own and it has no "destructive tool" variant.
                // `BulkDataDelete` is the nearest true statement — the class
                // means irreversible data change. Swap it the day the domain
                // grows the variant; nothing branches on this value.
                reason: ApprovalReason::BulkDataDelete,
                summary: format!("{tool} is classed {} and needs a human", bound.risk.code()),
            },
        }
    }

    /// Call one tool. Exactly one request reaches the server.
    ///
    /// Refuses before dispatch when [`verdict`](Self::verdict) is not
    /// `Allow` — an unknown tool never becomes a request, and a destructive
    /// one needs an approval this module cannot grant itself.
    pub async fn call(
        &self,
        tool: &McpTool,
        arguments: Option<JsonObject>,
    ) -> Result<Untrusted<CallToolResult>, McpError> {
        let bound = self.lookup(tool).ok_or_else(|| {
            // A tool on another server is "unknown here", which is the honest
            // answer: this binding cannot speak for a binding it is not.
            McpError::UnknownTool(tool.clone())
        })?;
        match self.verdict(tool) {
            Decision::Allow => {}
            refusal => return Err(McpError::Refused(refusal)),
        }

        let mut params = CallToolRequestParams::new(bound.wire_name.clone());
        if let Some(arguments) = arguments {
            params = params.with_arguments(arguments);
        }

        // `call_tool_once`, never `call_tool`: the latter answers the server's
        // follow-up rounds by itself, which would be extra dispatches the gate
        // never ruled on.
        // **Bounded, because nothing above this is.** `Turn::run` races the
        // *model* call against its `CancellationToken` and nothing races the
        // effect, so a tool call that never returns is a turn that never
        // returns — and on the inbound path that turn is inside the outbox
        // handler's tenant transaction, so the wedge is an open Postgres
        // transaction and a pooled connection held for as long as the server
        // stays quiet, while the outbox lease expires underneath it and a second
        // poller re-runs the same turn. `main.rs`'s `TURN_DEADLINE` cannot reach
        // in here; only a timeout on the call itself can.
        //
        // `rmcp`'s `StreamableHttpClientTransport::from_uri` builds its own HTTP
        // client and this crate cannot name `reqwest` to configure one, which is
        // why the bound is here rather than on the socket.
        let called =
            match tokio::time::timeout(CALL_TIMEOUT, self.client.call_tool_once(params)).await {
                Ok(called) => called?,
                Err(_) => {
                    return Err(McpError::TimedOut {
                        tool: tool.clone(),
                        secs: CALL_TIMEOUT.as_secs(),
                    });
                }
            };
        match called {
            CallToolResponse::Complete(result) => Ok(Untrusted::new(result)),
            // `InputRequired`, `Task`, and whatever `#[non_exhaustive]` adds
            // next all mean the same thing here: this is not a finished
            // result. Fail closed rather than let a future variant fall
            // through to something that looks like success.
            _ => Err(McpError::MoreRoundsRequired(tool.clone())),
        }
    }

    /// Close the connection.
    pub async fn close(self) -> Result<(), McpError> {
        self.client
            .cancel()
            .await
            .map(drop)
            .map_err(|e| McpError::Connect(e.to_string()))
    }

    fn lookup(&self, tool: &McpTool) -> Option<&BoundTool> {
        (tool.server == self.server)
            .then(|| self.tools.get(&tool.name))
            .flatten()
    }
}

/// Turn the server's tool list into the bound inventory.
///
/// Tools whose names have no [`Slug`] spelling are dropped: no allowlist entry
/// could ever name them, so they are unreachable anyway, and dropping them is
/// quieter than inventing a mangled handle.
/// What an operator vetted, for one tool.
///
/// The class alone is not enough, because it is keyed by NAME. An operator vets
/// a tool by reading what it *does*; keying only on what it is *called* means a
/// server can redeploy the same name with a different input schema — `lookup`
/// growing a `callback_url` parameter — and keep the class a human granted to
/// something else. Every name-keyed check in this system then agrees with every
/// other one, and all of them are wrong together: `classify` matches a name,
/// and so does the gate's `allowed_mcp_tools`.
///
/// `digest` pins the declaration to the exact tool that was read. It is the
/// operator's, and it NEVER advances on its own — a moving baseline is what
/// forces a system to go hunting for slow drift, and an immutable one deletes
/// that attack class instead of detecting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declaration {
    /// The class a human granted.
    pub risk: RiskClass,
    /// The tool this class was granted to. `None` opts out — the class then
    /// travels with the name alone, which is the behaviour this type exists to
    /// replace, so only leave it unset while migrating.
    pub digest: Option<[u8; 32]>,
}

/// A stable hash of everything about a tool an operator would have read.
///
/// Canonical, so a server that reorders its JSON does not look like a server
/// that changed it: object keys are sorted recursively before hashing. Covers
/// name, description and input schema — the description matters even though it
/// never reaches the model, because it is what the human based the decision on.
fn digest(tool: &Tool) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    fn canonical(value: &serde_json::Value, out: &mut String) {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_unstable();
                out.push('{');
                for key in keys {
                    out.push_str(key);
                    out.push(':');
                    canonical(&map[key], out);
                    out.push(',');
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for item in items {
                    canonical(item, out);
                    out.push(',');
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }

    let mut buf = String::new();
    buf.push_str(&tool.name);
    buf.push('\u{1f}');
    buf.push_str(tool.description.as_deref().unwrap_or(""));
    buf.push('\u{1f}');
    canonical(
        &serde_json::Value::Object((*tool.input_schema).clone()),
        &mut buf,
    );

    Sha256::digest(buf.as_bytes()).into()
}

fn inventory(
    discovered: &[Tool],
    declared: &BTreeMap<Slug, Declaration>,
) -> Result<BTreeMap<Slug, BoundTool>, McpError> {
    let mut tools: BTreeMap<Slug, BoundTool> = BTreeMap::new();
    for tool in discovered {
        let Some(handle) = handle(&tool.name) else {
            tracing::warn!(tool = %tool.name, "mcp tool name has no policy handle; skipping");
            continue;
        };
        if let Some(clash) = tools.get(&handle) {
            return Err(McpError::AmbiguousTool {
                handle,
                first: clash.wire_name.clone(),
                second: tool.name.to_string(),
            });
        }
        // A declaration whose digest does not match this tool is not a
        // declaration for this tool. Falling through to `None` reuses the
        // existing fail-closed branch — Destructive, so a human sees it — rather
        // than adding a second way to refuse.
        let named_by_operator = declared.contains_key(&handle);
        let served = digest(tool);
        let vetted = declared.get(&handle).and_then(|d| match d.digest {
            Some(pinned) if pinned != served => {
                tracing::warn!(
                    tool = %tool.name,
                    "mcp tool no longer matches what the operator vetted; treating it as undeclared"
                );
                None
            }
            _ => Some(d.risk),
        });
        let risk = classify(vetted, tool.annotations.as_ref());
        tools.insert(
            handle,
            BoundTool {
                wire_name: tool.name.to_string(),
                risk,
                description: tool
                    .description
                    .as_ref()
                    .map(|d| Untrusted::new(d.to_string())),
                declared: named_by_operator,
                digest: served,
            },
        );
    }
    Ok(tools)
}

/// Parse and scheme-check. Rejects anything that is not http(s) with a host.
///
/// Public so an operator route can refuse `file:///etc/passwd` with a 400 at the
/// moment it is typed, rather than storing it and letting the binder log a
/// warning nobody is reading. It is *not* the SSRF check — that is
/// [`resolve_and_vet`], it costs a DNS lookup, and it stays where the connection
/// is made.
pub fn vet_url(raw: &str) -> Result<Url, McpError> {
    let url = Url::parse(raw).map_err(|_| McpError::BadUrl(raw.to_owned()))?;
    if !ALLOWED_SCHEMES.contains(&url.scheme()) || url.host_str().is_none() {
        return Err(McpError::BadUrl(raw.to_owned()));
    }
    Ok(url)
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// The deployment's cipher, and the only two things an MCP binding does with it.
///
/// # Why this type exists at all
///
/// `apps/server/Cargo.toml` says it out loud: *"agentos-providers is
/// deliberately absent: the server may not touch a provider directly."* The
/// credential path needs a cipher and a [`Secret`], both of which live in
/// `agentos-providers`, so the naive shape — `apps/server` holding an
/// `Arc<LocalEnvelopeSecretStore>` — would have deleted that rule to add a
/// header. This type is what keeps it: `apps/server` holds a `Credentials`,
/// which is an `agentos-app` type, and never names a provider.
///
/// The layering is not the only thing it buys, and the second thing is bigger.
/// **A plaintext credential never crosses the crate boundary in either
/// direction.** The HTTP layer hands a `String` in ([`seal`](Self::seal),
/// which takes it by value) and hands sealed bytes back in
/// ([`bind`](Self::bind)); there is no signature here that returns a
/// [`Secret`], so "the token is never in a response, a log or an error" is a
/// property of the API rather than a discipline in four handlers.
///
/// # And it makes the connect path bind the way the loop binds
///
/// [`bind`](Self::bind) takes the **sealed** form, so the route that verifies a
/// brand-new credential seals it first and binds from the ciphertext — exactly
/// the input `Fleet::bind` will use five minutes later. A seal/open bug
/// therefore fails in front of the customer who is watching, instead of
/// silently five minutes after they were told "connected".
#[derive(Clone)]
pub struct Credentials {
    cipher: std::sync::Arc<LocalEnvelopeSecretStore>,
}

// Hand-written. A derived one would reach into the cipher, which holds the
// master key; `LocalEnvelopeSecretStore`'s own `Debug` redacts it, and this
// does not depend on that staying true.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials")
    }
}

impl Credentials {
    /// Build from the deployment's `AGENTOS_MASTER_KEY`.
    ///
    /// Goes through [`crate::identity::envelope`] rather than deriving the key
    /// again here, and that is the whole point of the call: two spellings of the
    /// text-to-32-bytes bridge are two deployments that cannot read each other's
    /// rows, and this one would only be discovered by an operator whose MCP
    /// credentials stopped opening after a restart.
    pub fn from_master_key(master_key: &str) -> Self {
        Self {
            cipher: crate::identity::envelope(master_key),
        }
    }

    /// Wrap a cipher that already exists. For tests, and for a caller that
    /// shares one with [`crate::identity`].
    pub const fn new(cipher: std::sync::Arc<LocalEnvelopeSecretStore>) -> Self {
        Self { cipher }
    }

    /// Seal a token a customer typed, for storage in `mcp_servers.sealed_token`.
    ///
    /// **Takes the `String` by value and never gives it back.** `String ->
    /// String` is the identity conversion, so the buffer the request body
    /// allocated becomes the one `SecretString` zeroizes on drop; taking a `&str`
    /// would copy it and leave the original in the heap.
    ///
    /// A token that is empty or all whitespace is `None`, not an empty
    /// credential. A form that posts `""` for an untouched field is the single
    /// most common way a binding ends up sending `Authorization: Bearer ` and
    /// getting a 401 nobody can explain.
    pub fn seal(
        &self,
        tenant_id: agentos_domain::ids::TenantId,
        server: &Slug,
        token: Option<String>,
    ) -> Result<Option<Vec<u8>>, McpError> {
        let Some(raw) = token.filter(|t| !t.trim().is_empty()) else {
            return Ok(None);
        };
        self.cipher
            .seal_in(
                tenant_id,
                &credential_context(tenant_id, server),
                &Secret::new(raw),
            )
            .map(|sealed| Some(sealed.to_bytes()))
            .map_err(|err| McpError::Credential { code: err.code() })
    }

    /// Seal one string under an encryption context this module did not choose.
    ///
    /// `pub(crate)`, and the visibility is the whole design. [`crate::oauth`]
    /// has two more things to seal than a bearer token — a PKCE verifier and a
    /// refresh token — and each needs an AAD of its own so that two blobs in two
    /// columns of one row cannot be swapped for each other. Giving it a context
    /// parameter is how those live here, under one cipher, instead of a second
    /// `LocalEnvelopeSecretStore` built somewhere else from the same master key.
    ///
    /// It stays inside the crate because the promise this type makes is about
    /// the *crate boundary*: `apps/server` cannot name a [`Secret`], so it
    /// cannot call this, so the promise holds without this function having to
    /// keep it.
    pub(crate) fn seal_as(
        &self,
        tenant_id: agentos_domain::ids::TenantId,
        context: &str,
        value: &Secret,
    ) -> Result<Vec<u8>, McpError> {
        self.cipher
            .seal_in(tenant_id, context, value)
            .map(|sealed| sealed.to_bytes())
            .map_err(|err| McpError::Credential { code: err.code() })
    }

    /// The other half of [`seal_as`](Self::seal_as). Same visibility, same
    /// reason.
    pub(crate) fn open_as(
        &self,
        tenant_id: agentos_domain::ids::TenantId,
        context: &str,
        sealed: &[u8],
    ) -> Result<Secret, McpError> {
        let envelope = agentos_providers::secrets::Envelope::from_bytes(sealed)
            .map_err(|err| McpError::Credential { code: err.code() })?;
        self.cipher
            .open_in(tenant_id, context, &envelope)
            .map_err(|err| McpError::Credential { code: err.code() })
    }

    /// Open a stored credential.
    ///
    /// Private: the plaintext exists inside this module, for the length of a
    /// [`bind`](Self::bind), and nowhere else. Making this `pub` would be the
    /// one change that undoes what this type is for.
    fn open(
        &self,
        tenant_id: agentos_domain::ids::TenantId,
        server: &Slug,
        sealed: &[u8],
    ) -> Result<Secret, McpError> {
        let envelope = agentos_providers::secrets::Envelope::from_bytes(sealed)
            .map_err(|err| McpError::Credential { code: err.code() })?;
        self.cipher
            .open_in(tenant_id, &credential_context(tenant_id, server), &envelope)
            .map_err(|err| McpError::Credential { code: err.code() })
    }

    /// Open the credential and bind, in one expression, so the plaintext lives
    /// for one statement.
    ///
    /// The [`Secret`] is a local that drops when this function returns. What the
    /// transport keeps is a header value it built from it.
    ///
    /// `sealed` is `None` for a binding that sends no credential, which is the
    /// ordinary case for a server that needs none — not an error, and not an
    /// empty header.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        &self,
        tenant_id: agentos_domain::ids::TenantId,
        server: Slug,
        url: &str,
        declared: &BTreeMap<Slug, Declaration>,
        reach: Reach,
        sealed: Option<&[u8]>,
        ct: CancellationToken,
    ) -> Result<McpServer, McpError> {
        let token = match sealed {
            None => None,
            Some(sealed) => Some(self.open(tenant_id, &server, sealed)?),
        };
        McpServer::bind(server, url, declared, reach, token.as_ref(), ct).await
    }

    /// The same, for a server we run ourselves: start the bridge, then bind to
    /// the address it answered with.
    ///
    /// # The credential goes somewhere else, and that is the only difference
    ///
    /// It is opened by the same [`open`](Self::open), from the same column,
    /// under the same AAD — and then it is handed to
    /// [`Bridges::endpoint`](crate::hosted::Bridges::endpoint) to be placed in
    /// the package's environment instead of onto a header. The plaintext lives
    /// for this function and nothing else: the [`Secret`] is a local, and
    /// [`crate::hosted::BridgeSpec`] borrows it rather than owning it, so there
    /// is no copy that outlives the call.
    ///
    /// **The token is deliberately `None` on the [`McpServer::bind`] below.**
    /// Sending the same secret a second time as `Authorization: Bearer` would
    /// put a tenant's credential on a hop that does not need it, and the bridge
    /// is not the thing being authenticated — it is a process we started for
    /// this tenant, reachable only on the operator's bridge network.
    ///
    /// **And `Reach::Private` there is not the check.** The check already
    /// happened in `endpoint`, which is stricter than any `Reach`: an IP
    /// literal, in private space, inside the operator's bridge network. What
    /// `McpServer::bind` does with it is re-resolve a literal to itself, which
    /// is why the contract says an address and not a name — there is no second
    /// lookup that could answer differently.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_hosted(
        &self,
        tenant_id: agentos_domain::ids::TenantId,
        server: Slug,
        package: &crate::hosted::Package,
        declared: &BTreeMap<Slug, Declaration>,
        sealed: Option<&[u8]>,
        bridges: &crate::hosted::Bridges,
        ct: CancellationToken,
    ) -> Result<McpServer, McpError> {
        let secret = match sealed {
            None => None,
            Some(sealed) => Some(self.open(tenant_id, &server, sealed)?),
        };
        let endpoint = bridges
            .endpoint(crate::hosted::BridgeSpec {
                tenant: tenant_id,
                server: &server,
                package,
                secret: secret.as_ref(),
            })
            .await?;
        McpServer::bind(
            server,
            endpoint.as_str(),
            declared,
            Reach::Private,
            None,
            ct,
        )
        .await
    }
}

/// The encryption context one binding's credential is sealed under.
///
/// **One function, because an AAD that two call sites spell differently is a
/// credential that seals and never opens** — and the failure is a
/// `secret_decrypt_failed` that looks exactly like a corrupted master key. The
/// sealer (`routes::mcp`) and the opener ([`Fleet::bind`]) both call this.
///
/// It names the server handle, not only the tenant, and that is the useful half:
/// a `sealed_token` blob copied from one row to another inside one tenant will
/// not open. The handle is what selects the URL, so without it a customer could
/// point a credential at an endpoint it was never issued for by editing one
/// column.
///
/// The `mcp://` scheme keeps this key space disjoint from `secret://`, which is
/// what [`SecretRef`](agentos_domain::ids::SecretRef) renders and what
/// [`LocalEnvelopeSecretStore::seal`] uses.
pub fn credential_context(tenant_id: agentos_domain::ids::TenantId, server: &Slug) -> String {
    format!("mcp://{tenant_id}/{}", server.as_str())
}

/// Resolve the host and refuse every address `reach` does not permit.
///
/// *Every* address, not the first one: a host that resolves to one public
/// address and one metadata address is a host that will reach the metadata
/// address on the retry.
pub(crate) async fn resolve_and_vet(url: &Url, reach: Reach) -> Result<Vec<IpAddr>, McpError> {
    let host = url.host_str().unwrap_or_default().to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| McpError::Unresolvable {
            host: host.clone(),
            detail: e.to_string(),
        })?;

    let mut addresses = Vec::new();
    for socket in resolved {
        let ip = socket.ip();
        match placement(ip) {
            Placement::Global => {}
            Placement::Private if reach == Reach::Private => {}
            _ => {
                return Err(McpError::Blocked {
                    host: host.clone(),
                    ip,
                });
            }
        }
        addresses.push(ip);
    }

    if addresses.is_empty() {
        return Err(McpError::Unresolvable {
            host,
            detail: "no addresses".to_owned(),
        });
    }
    Ok(addresses)
}

// ---------------------------------------------------------------------------
// The fleet: every server one tenant has bound
// ---------------------------------------------------------------------------

/// The bindings one tenant's operator configured, and the [`McpCaller`] the
/// turn loop reaches them through.
///
/// A single [`McpServer`] cannot be the port, because [`McpCaller::call`] is
/// handed an [`McpTool`] that names *which* server — and one binding "cannot
/// speak for a binding it is not". This is the thing that can: it routes on
/// [`McpTool::server`] and hands the rest to that binding's own refusals.
#[derive(Debug, Default)]
pub struct Fleet {
    servers: BTreeMap<Slug, McpServer>,
    failures: BTreeMap<Slug, BindFailure>,
}

/// Why one configured server is not in the fleet.
///
/// Kept rather than only logged, because "my tools stopped working" is answered
/// by *this* string and the operator cannot read the deployment's logs. A
/// dropped binding is otherwise indistinguishable from a server nobody
/// configured, which is the failure mode that makes people restart pods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindFailure {
    /// [`McpError::code`]: stable, low cardinality, safe on a metric.
    pub code: &'static str,
    /// The whole error, rendered. Names the address that was refused, the host
    /// that would not resolve, the two tool names that collided.
    pub detail: String,
}

/// What one row of `mcp_servers` joined to its declarations looks like.
///
/// TEXT columns parsed on the way out, not `sqlx` enums: a row this build
/// cannot read is a binding that is *skipped*, and skipping is the fail-closed
/// answer. A hard error would let one malformed row take a tenant's whole turn
/// down with it.
///
/// Deliberately not `Serialize`, and it is the one type in this module that
/// would be tempting to make so: it carries `sealed_token`. Same rule as
/// `store::signing::StoredKey` — a row type that can be serialised is a row type
/// that ends up in a response body. The blob is useless without the master key,
/// which is exactly the argument somebody makes right before it is in a log.
#[derive(sqlx::FromRow)]
struct ConfigRow {
    server: String,
    /// `NULL` for a binding we host: there is no address for anybody to write
    /// down, and `0043_mcp_hosted.sql` is the column becoming nullable so that
    /// the absence is storable rather than faked with an empty string.
    url: Option<String>,
    reach: String,
    /// The catalogue entry this binding came from (`0040_mcp_credentials.sql`),
    /// and the only thing that says whether it is dialled or hosted. One column
    /// answering that, not two, because two can disagree.
    connector: String,
    /// The envelope from `providers::secrets`, or `NULL` for a binding that
    /// sends no credential. Opaque here until [`Fleet::bind`] opens it.
    sealed_token: Option<Vec<u8>>,
    tool: Option<String>,
    risk: Option<String>,
    digest: Option<Vec<u8>>,
}

/// Every binding this tenant has, with its declarations alongside.
///
/// A LEFT JOIN: a server with no declarations at all is still a binding — every
/// tool on it is undeclared, which is [`RiskClass::Destructive`], which is the
/// honest state of a server nobody has vetted yet.
const SELECT_BINDINGS: &str = "\
    SELECT s.server, s.url, s.reach, s.connector, s.sealed_token, d.tool, d.risk, d.digest \
      FROM mcp_servers s \
      LEFT JOIN mcp_tool_declarations d \
             ON d.tenant_id = s.tenant_id AND d.server = s.server \
     ORDER BY s.server, d.tool";

impl Fleet {
    /// No bindings. What a tenant that configured none gets, and what a caller
    /// falls back to when the servers cannot be reached.
    pub const fn empty() -> Self {
        Self {
            servers: BTreeMap::new(),
            failures: BTreeMap::new(),
        }
    }

    /// A fleet over already-bound servers. Two bindings under one handle is a
    /// configuration that cannot exist — the primary key of `mcp_servers` — so
    /// the last one wins rather than this returning a `Result` nobody can act
    /// on.
    pub fn new(servers: impl IntoIterator<Item = McpServer>) -> Self {
        Self {
            servers: servers
                .into_iter()
                .map(|server| (server.server.clone(), server))
                .collect(),
            failures: BTreeMap::new(),
        }
    }

    /// Read this tenant's configuration and bind every server in it.
    ///
    /// The tenant is `tx`'s, because row-level security honours nothing else.
    ///
    /// A server that will not bind — DNS gone, endpoint down, an address the
    /// SSRF check refuses, two tool names that collapse to one handle — is
    /// logged and left out. That is deliberate: an MCP server being unreachable
    /// is an *availability* fact, and it must not stop an employee from
    /// answering its email. Leaving it out is still fail-closed, because a
    /// server that is not in the fleet has no tools in the inventory and every
    /// call naming it is refused.
    ///
    /// ponytail: the SQL is here rather than in `agentos-store`, for the same
    /// reason `gate.rs` reads `spend_buckets` directly — there is one caller.
    /// Move it to a `store::mcp` the moment there is a second.
    ///
    /// ponytail: binds on every call, so a caller that does this per turn pays
    /// a connect and a `tools/list` per turn. The upgrade path is a
    /// process-wide cache keyed by tenant with a TTL; it is worth writing the
    /// day the latency shows up in a trace, and not before — a cache here holds
    /// a *risk classification*, and a stale one of those is the bug this module
    /// spends 200 lines preventing.
    /// A credential that will not open is a **binding that is skipped**, with
    /// the reason recorded, exactly like a URL that will not resolve — see
    /// [`McpError::Credential`] for why the alternative is worse than useless.
    ///
    /// `bridges` is what a hosted binding needs and a dialled one ignores.
    /// `None` means this deployment runs no bridge runtime, which is every
    /// deployment today: hosted rows then fail to bind with
    /// `hosting_unavailable` and their tenant has no tools on them, which is the
    /// same fail-closed shape as a server that is down. See [`crate::hosted`]
    /// for what has to be deployed to change that.
    pub async fn bind(
        tx: &mut TenantTx<'_>,
        credentials: &Credentials,
        bridges: Option<&crate::hosted::Bridges>,
        ct: &CancellationToken,
    ) -> Result<Self, StoreError> {
        let tenant_id = tx.tenant_id();
        let rows: Vec<ConfigRow> = sqlx::query_as(SELECT_BINDINGS)
            .fetch_all(&mut ***tx)
            .await?;

        let mut configured: BTreeMap<Slug, Binding> = BTreeMap::new();
        for row in rows {
            let Ok(server) = Slug::parse(&row.server) else {
                tracing::warn!(server = %row.server, "mcp binding has no policy handle; skipping");
                continue;
            };
            let Some(how) = provisioned(&row) else {
                tracing::warn!(
                    server = %row.server,
                    connector = %row.connector,
                    "mcp binding has neither a url to dial nor a package we host; skipping"
                );
                continue;
            };
            let sealed = row.sealed_token.clone();
            let entry = configured.entry(server).or_insert_with(|| Binding {
                how,
                sealed_token: sealed,
                declared: BTreeMap::new(),
            });
            if let Some((handle, declaration)) = declaration(&row) {
                entry.declared.insert(handle, declaration);
            }
        }

        let mut servers = BTreeMap::new();
        let mut failures = BTreeMap::new();
        for (name, binding) in configured {
            let sealed = binding.sealed_token.as_deref();
            let bound = match &binding.how {
                Provisioned::Dial { url, reach } => {
                    credentials
                        .bind(
                            tenant_id,
                            name.clone(),
                            url,
                            &binding.declared,
                            *reach,
                            sealed,
                            ct.clone(),
                        )
                        .await
                }
                // A hosted binding on a deployment with no runtime is a
                // *failure*, recorded and rendered, not a binding quietly
                // missing from the list: the operator connected something and
                // has to be told why it has no tools.
                Provisioned::Hosted { package } => match bridges {
                    None => Err(McpError::Hosting {
                        code: "hosting_unavailable",
                    }),
                    Some(bridges) => {
                        credentials
                            .bind_hosted(
                                tenant_id,
                                name.clone(),
                                package,
                                &binding.declared,
                                sealed,
                                bridges,
                                ct.clone(),
                            )
                            .await
                    }
                },
            };
            match bound {
                Ok(server) => {
                    servers.insert(name, server);
                }
                Err(err) => {
                    tracing::warn!(
                        server = %name,
                        code = err.code(),
                        "mcp server did not bind; its tools are not available this turn: {err}"
                    );
                    failures.insert(
                        name,
                        BindFailure {
                            code: err.code(),
                            detail: err.to_string(),
                        },
                    );
                }
            }
        }
        Ok(Self { servers, failures })
    }

    /// Whether this handle is bound. A server with no *declared* tools still
    /// answers `true`, which is why this is not "does `inventory` mention it".
    pub fn is_bound(&self, server: &Slug) -> bool {
        self.servers.contains_key(server)
    }

    /// Every configured server that did not bind, and why.
    pub const fn failures(&self) -> &BTreeMap<Slug, BindFailure> {
        &self.failures
    }

    /// Every tool an operator named, on every server that bound, with its blast
    /// radius on the domain's axis.
    ///
    /// **Not filtered by trust.** The turn's label changes mid-run — one tool
    /// result and the rest of the turn is untrusted — so filtering here would
    /// freeze the wrong answer into a value built once per turn.
    /// [`SystemPrompt::render`](crate::prompt::SystemPrompt::render) does it,
    /// per turn, through [`crate::turn::visible`].
    ///
    /// **Nor by policy**, and for the opposite reason: a fleet is one *tenant's*
    /// bindings and has no employee in it, so it has nothing to narrow with.
    /// [`SystemPrompt::with_mcp_tools`](crate::prompt::SystemPrompt::with_mcp_tools)
    /// takes the employee's `EffectivePolicy` and is where "this tenant has
    /// bound it" becomes "this employee may call it". Callers that want the
    /// tenant-wide answer — an operator's binding page counting what it just
    /// configured — are asking this function the right question.
    ///
    /// Undeclared tools are absent: see this module's docs for why an operator
    /// has to have written the string before it reaches a system prompt.
    pub fn inventory(&self) -> Vec<(McpTool, Risk)> {
        self.servers
            .values()
            .flat_map(|server| {
                server
                    .tools
                    .iter()
                    .filter(|(_, bound)| bound.declared)
                    .map(|(handle, bound)| {
                        (
                            McpTool::new(server.server.clone(), handle.clone()),
                            bound.risk.into(),
                        )
                    })
            })
            .collect()
    }
}

/// One server's configuration, before it is bound.
///
/// No `Debug`, and that is not an oversight: a derived one would print
/// `sealed_token`, which is a ciphertext today and one refactor away from being
/// the thing it protects.
struct Binding {
    how: Provisioned,
    /// The envelope blob straight out of the column, still sealed.
    /// [`Credentials::bind`] is the only thing that opens it.
    sealed_token: Option<Vec<u8>>,
    declared: BTreeMap<Slug, Declaration>,
}

/// Which of the two ways this binding reaches a server.
///
/// The distinction is not a flag on the row, it is what the *catalogue* says
/// about the row's connector — see [`provisioned`].
enum Provisioned {
    /// An address somebody else operates, and the [`Reach`] the row allows.
    Dial { url: String, reach: Reach },
    /// A package we run for this tenant. No URL: the address is minted per
    /// start by the bridge runtime and vetted by [`crate::hosted::accept`].
    Hosted {
        package: &'static crate::hosted::Package,
    },
}

/// Decide how one row is provisioned, or `None` for a row that cannot be.
///
/// **The connector decides, and the URL does not get a vote.** A row whose
/// connector names a hosted package is hosted even if some past write left a URL
/// in the column, and that ordering is the safe one: the alternative — "dial the
/// URL if there is one" — would make a stray value in a tenant-writable column
/// into an address this process connects to, which is the whole class of thing
/// `resolve_and_vet` exists to bound.
///
/// Every `None` is a binding that is skipped: a connector we do not host, with
/// no URL of its own, is a row that names nothing. Skipping is the same
/// fail-closed answer the rest of this loop gives, and a `None` here can never
/// widen anything because it removes a binding rather than adding one.
///
/// An unrecognised connector is not hosted — `catalog::find` returns `None` —
/// which is the reading `0040_mcp_credentials.sql` asks for ("the reader must
/// tolerate a value it does not recognise") pointed in the direction that
/// refuses: an unknown name cannot cause us to start a program.
fn provisioned(row: &ConfigRow) -> Option<Provisioned> {
    match crate::catalog::find(&row.connector).and_then(crate::catalog::Connector::package) {
        Some(package) => Some(Provisioned::Hosted { package }),
        None => row.url.clone().map(|url| Provisioned::Dial {
            url,
            // An unrecognised spelling is the tight one. `mcp_servers_reach_known`
            // makes it unreachable; if that CHECK is ever dropped, this is
            // still the answer that refuses loopback.
            reach: Reach::parse(&row.reach).unwrap_or_default(),
        }),
    }
}

/// One declaration out of a joined row, or `None` when the row carries none or
/// carries one this build cannot read.
///
/// Every `None` is a tool that stays undeclared, which is
/// [`RiskClass::Destructive`], which needs a human. There is no branch here
/// that can widen anything.
fn declaration(row: &ConfigRow) -> Option<(Slug, Declaration)> {
    let (tool, risk) = row.tool.as_deref().zip(row.risk.as_deref())?;
    let handle = Slug::parse(tool)
        .inspect_err(|_| tracing::warn!(%tool, "mcp declaration has no policy handle; ignoring"))
        .ok()?;
    let class = RiskClass::parse(risk).or_else(|| {
        tracing::warn!(%tool, %risk, "mcp declaration names an unknown risk class; ignoring");
        None
    })?;
    // `mcp_tool_declarations_digest_is_sha256` makes the wrong length
    // unreachable; if it is ever dropped, a digest that cannot be read is a
    // declaration that is not applied, not one applied without its pin.
    let digest = match row.digest.as_deref() {
        None => None,
        Some(bytes) => Some(
            <[u8; 32]>::try_from(bytes)
                .inspect_err(|_| tracing::warn!(%tool, "mcp declaration digest is not sha-256"))
                .ok()?,
        ),
    };
    Some((
        handle,
        Declaration {
            risk: class,
            digest,
        },
    ))
}

/// How a failure to call one tool reads to the effect layer.
///
/// Only the ones that mean "the network was unlucky" are retryable. A refusal —
/// a destructive class, an unknown tool, a second round trip nobody authorised
/// — is [`ProviderError::Terminal`], because retrying a refusal is how a loop
/// spends its whole budget being told no.
///
/// [`McpError::Transport`] used to sit in the retryable arm with the other two,
/// and it does not belong there: it is `rmcp`'s box for *everything that
/// happened after the connection was made*, which is both sentences at once —
/// a socket that died halfway, and a server that answered `401`. See
/// [`reached_the_server`] for the split and for what the second one costs.
fn as_provider_error(err: &McpError) -> ProviderError {
    match err {
        McpError::Connect(_) | McpError::TimedOut { .. } => ProviderError::timeout(),
        McpError::Transport(exchange) => reached_the_server(exchange),
        other => ProviderError::Terminal { code: other.code() },
    }
}

/// Which of its two meanings [`McpError::Transport`] is carrying this time.
///
/// **"The server did not answer" and "the server said no" are the same
/// [`ServiceError`] to `rmcp` and must not be the same [`ProviderError`] to
/// us.** The second one is what a revoked token looks like: the binding came up
/// when the credential was live, the customer rotated it, and now every
/// `tools/call` is a `401`. Classified as retryable, that is `Reply::Error`
/// telling the model `retryable` — so it asks again inside the turn — plus an
/// audit row that says `retryable: true` and an operator whose binding page
/// reads "in progress" forever. The dead credential is hammered at somebody
/// else's server and nothing anywhere says the connection is broken.
///
/// So the retryable side is enumerated and everything else is terminal,
/// including whatever `#[non_exhaustive]` adds next: a variant this build has
/// never seen is not evidence that asking again helps.
fn reached_the_server(err: &ServiceError) -> ProviderError {
    match err {
        // Nothing came back. The peer hung up, the wait was cut short, the
        // subscription fell behind — the same "we were unlucky" as a connect
        // failure, and worth the same backoff.
        ServiceError::TransportClosed
        | ServiceError::Timeout { .. }
        | ServiceError::Cancelled { .. }
        | ServiceError::SubscriptionLagged { .. } => ProviderError::timeout(),
        // The send failed. Usually the wire — but a `401`/`403` is delivered
        // through here too, and that one is the server refusing the credential.
        ServiceError::TransportSend(sent) => {
            refused_the_credential(sent).unwrap_or_else(ProviderError::timeout)
        }
        // The server answered, and the answer was an error. It will be the same
        // error next time: `tools/call` carries no state that a second attempt
        // changes.
        _ => ProviderError::Terminal {
            code: "server_refused",
        },
    }
}

/// The terminal ruling behind a failed send, when what failed it was an
/// authorization challenge rather than the wire.
///
/// `rmcp` knows how to answer this — `DynamicTransportError::is_authorization_
/// required` is the same walk — but keeps it `pub(crate)`, and the transport
/// error it wraps is generic over `reqwest::Error`, which this crate may not
/// name. What *is* public is the cause: [`AuthRequiredError`] and
/// [`InsufficientScopeError`] are plain structs on the source chain, so
/// downcasting for them costs six lines and no dependency.
///
/// The codes are [`ProviderError::from_status`]'s own, so a refused MCP
/// credential reads in an audit row exactly like a refused HTTP one — one
/// vocabulary for "the far side would not take this token", not two.
fn refused_the_credential(sent: &DynamicTransportError) -> Option<ProviderError> {
    let mut cause = Some(sent.error.as_ref() as &(dyn std::error::Error + 'static));
    while let Some(err) = cause {
        if err.is::<AuthRequiredError>() {
            return Some(ProviderError::from_status(401, None));
        }
        if err.is::<InsufficientScopeError>() {
            return Some(ProviderError::from_status(403, None));
        }
        cause = err.source();
    }
    None
}

#[async_trait]
impl McpCaller for Fleet {
    /// Route to the binding the tool names, and keep the wrapper on the way
    /// back.
    ///
    /// The result never leaves [`Untrusted`]: `CallToolResult` goes to [`Value`]
    /// inside [`Untrusted::map`], so there is no point in this function where a
    /// stranger's text exists unwrapped.
    async fn call(
        &self,
        tool: &McpTool,
        arguments: &Value,
    ) -> Result<Untrusted<Value>, ProviderError> {
        let server = self.servers.get(&tool.server).ok_or_else(|| {
            tracing::warn!(%tool, "no mcp server is bound under that handle");
            ProviderError::Terminal {
                code: McpError::UnknownTool(tool.clone()).code(),
            }
        })?;

        // `null` is the model omitting the field; anything that is not an
        // object is a call this client cannot make.
        let arguments = match arguments {
            Value::Null => None,
            Value::Object(map) => Some(map.clone()),
            _ => {
                return Err(ProviderError::Terminal {
                    code: "arguments_not_an_object",
                });
            }
        };

        let result = server.call(tool, arguments).await.map_err(|err| {
            tracing::warn!(%tool, code = err.code(), "mcp call failed: {err}");
            as_provider_error(&err)
        })?;

        result
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| ProviderError::Terminal {
                code: "unserializable_result",
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex;

    use agentos_domain::ids::TenantId;
    use agentos_domain::untrusted::TrustLabel;
    use agentos_store::db::Db;
    use chrono::Utc;
    use rmcp::model::{ContentBlock, DiscoverResult, ListToolsResult, ServerCapabilities};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::prompt::SystemPrompt;

    // -- a real MCP server, in process -------------------------------------
    //
    // rmcp's own server lives behind the `server` feature, which this
    // workspace does not enable (we are a client, and pulling in a server we
    // never ship would be a dependency for a test). So the fake below speaks
    // the wire instead: HTTP/1.1 on a loopback port, JSON-RPC bodies built
    // from rmcp's own model types, which is what makes it a contract test and
    // not a mock — if the client's serialization changes, this breaks.

    /// A server that answers `server/discover`, `tools/list` (paginated) and
    /// `tools/call`, and remembers every method it was asked for.
    struct FakeMcp {
        url: String,
        seen: Arc<Mutex<Vec<String>>>,
    }

    /// What [`FakeMcp`] does with a `tools/call`. Everything before the call —
    /// the handshake, the paginated `tools/list` — is the ordinary path in all
    /// three, which is what makes the two unhappy ones say something about the
    /// *call* and not about binding.
    #[derive(Clone, Copy)]
    enum Calls {
        /// Answer it.
        Answer,
        /// Accept it and never answer — the shape [`CALL_TIMEOUT`] exists for.
        Swallow,
        /// Answer `401` with a challenge, the way a server whose token was
        /// revoked after the binding came up does.
        Refuse,
    }

    impl FakeMcp {
        async fn start(pages: Vec<Vec<Tool>>) -> Self {
            Self::start_with(pages, Calls::Answer).await
        }

        async fn start_swallowing_calls(pages: Vec<Vec<Tool>>) -> Self {
            Self::start_with(pages, Calls::Swallow).await
        }

        async fn start_refusing_calls(pages: Vec<Vec<Tool>>) -> Self {
            Self::start_with(pages, Calls::Refuse).await
        }

        async fn start_with(pages: Vec<Vec<Tool>>, calls: Calls) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr: SocketAddr = listener.local_addr().expect("addr");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let pages = Arc::new(pages);

            let accepted = Arc::clone(&seen);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let seen = Arc::clone(&accepted);
                    let pages = Arc::clone(&pages);
                    tokio::spawn(async move {
                        serve_connection(stream, seen, pages, calls).await;
                    });
                }
            });

            Self {
                url: format!("http://{addr}/mcp"),
                seen,
            }
        }

        /// How many times a JSON-RPC method was asked for.
        fn count(&self, method: &str) -> usize {
            self.seen
                .lock()
                .expect("not poisoned")
                .iter()
                .filter(|m| *m == method)
                .count()
        }
    }

    async fn serve_connection(
        mut stream: TcpStream,
        seen: Arc<Mutex<Vec<String>>>,
        pages: Arc<Vec<Vec<Tool>>>,
        calls: Calls,
    ) {
        let mut buffer = Vec::new();
        loop {
            let Some(body) = read_request(&mut stream, &mut buffer).await else {
                return;
            };
            let Ok(request) = serde_json::from_slice::<Value>(&body) else {
                return;
            };
            let method = request["method"].as_str().unwrap_or_default().to_owned();
            seen.lock().expect("not poisoned").push(method.clone());

            // Took the request, will not answer. The socket stays open, so this
            // is the failure a connect timeout cannot see.
            if matches!(calls, Calls::Swallow) && method == "tools/call" {
                std::future::pending::<()>().await;
            }

            // Took the request and refused it. The `WWW-Authenticate` header is
            // not decoration: `rmcp` only reads a 401 as an authorization
            // challenge when the challenge is there, and a bearer token a
            // server has stopped accepting is answered exactly like this.
            if matches!(calls, Calls::Refuse) && method == "tools/call" {
                let refusal = "HTTP/1.1 401 Unauthorized\r\n\
                     WWW-Authenticate: Bearer realm=\"mcp\", error=\"invalid_token\"\r\n\
                     Content-Length: 0\r\n\r\n";
                let _ = stream.write_all(refusal.as_bytes()).await;
                return;
            }

            let response = match request.get("id") {
                // A notification: nothing to answer.
                None | Some(Value::Null) => "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"
                    .as_bytes()
                    .to_vec(),
                Some(id) => {
                    let result = answer(&method, &request, &pages);
                    let body =
                        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
                            .expect("serialize");
                    let mut out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    out.extend_from_slice(&body);
                    out
                }
            };
            if stream.write_all(&response).await.is_err() {
                return;
            }
        }
    }

    /// One HTTP/1.1 request body, or `None` when the peer went away.
    async fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
        loop {
            if let Some(head) = find(buffer, b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buffer[..head]).to_lowercase();
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let start = head + 4;
                if buffer.len() >= start + length {
                    let body = buffer[start..start + length].to_vec();
                    buffer.drain(..start + length);
                    return Some(body);
                }
            }
            let mut chunk = [0_u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn answer(method: &str, request: &Value, pages: &[Vec<Tool>]) -> Value {
        match method {
            "server/discover" => serde_json::to_value(DiscoverResult::new(
                vec![ProtocolVersion::V_2026_07_28],
                ServerCapabilities::default(),
            )),
            "tools/list" => {
                let cursor = request["params"]["cursor"].as_str().unwrap_or("0");
                let page: usize = cursor.parse().unwrap_or(0);
                let mut result =
                    ListToolsResult::with_all_items(pages.get(page).cloned().unwrap_or_default());
                if page + 1 < pages.len() {
                    result.next_cursor = Some((page + 1).to_string());
                }
                serde_json::to_value(result)
            }
            "tools/call" => {
                serde_json::to_value(CallToolResult::success(vec![ContentBlock::text(format!(
                    "ran {}",
                    request["params"]["name"].as_str().unwrap_or("?")
                ))]))
            }
            other => panic!("the fake server was asked for {other}"),
        }
        .expect("serialize")
    }

    // -- fixtures ----------------------------------------------------------

    fn slug(s: &str) -> Slug {
        Slug::parse(s).expect("slug")
    }

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_owned(),
            "a tool".to_owned(),
            Arc::new(JsonObject::new()),
        )
    }

    fn erp() -> Slug {
        slug("erp")
    }

    fn call(name: &str) -> McpTool {
        McpTool::new(erp(), slug(name))
    }

    /// A stored policy that allows exactly these tools.
    ///
    /// `SystemPrompt::with_mcp_tools` takes one because the prefix names what
    /// the gate would allow; here it is set to the whole fixture inventory, so
    /// what the assertions below vary is the *declaration* and never the
    /// allowlist.
    fn may_call(
        tools: impl IntoIterator<Item = McpTool>,
    ) -> agentos_domain::policy::EffectivePolicy {
        let limits = agentos_domain::policy::PolicyLimits {
            allowed_mcp_tools: tools.into_iter().collect(),
            ..Default::default()
        };
        agentos_domain::policy::EffectivePolicy::try_new(&limits, &limits, &limits, &limits)
            .expect("coherent layers")
    }

    fn declared() -> BTreeMap<Slug, Declaration> {
        // No digests here: these fixtures predate pinning and exercise the
        // name-only path that `Declaration::digest = None` preserves. The
        // pinning itself is covered by its own tests below.
        BTreeMap::from([
            (
                slug("lookup"),
                Declaration {
                    risk: RiskClass::Read,
                    digest: None,
                },
            ),
            (
                slug("write-note"),
                Declaration {
                    risk: RiskClass::Write,
                    digest: None,
                },
            ),
            (
                slug("drop-table"),
                Declaration {
                    risk: RiskClass::Destructive,
                    digest: None,
                },
            ),
        ])
    }

    /// Two pages, so `list_all_tools` has to follow a cursor to see them all.
    fn two_pages() -> Vec<Vec<Tool>> {
        vec![
            vec![tool("lookup")],
            vec![tool("write_note"), tool("drop_table"), tool("undeclared")],
        ]
    }

    async fn bound(server: &FakeMcp) -> McpServer {
        bound_with(server, declared()).await
    }

    async fn bound_with(server: &FakeMcp, declared: BTreeMap<Slug, Declaration>) -> McpServer {
        McpServer::bind(
            erp(),
            &server.url,
            &declared,
            Reach::Private,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("bind to the fake server")
    }

    /// The two credential shapes every bind-time refusal below is run through.
    ///
    /// Not decoration. Adding a credential added an argument to the one function
    /// that performs the address check, and the failure this guards against is
    /// the obvious refactor: read the token first, build the transport, *then*
    /// vet. Every SSRF test therefore runs twice, and a token that bought an
    /// address would fail half of them.
    const CREDENTIALS: [Option<&str>; 2] = [None, Some("ghp_a_real_looking_token")];

    fn credential(raw: Option<&str>) -> Option<Secret> {
        raw.map(Secret::new)
    }

    // -- SSRF --------------------------------------------------------------

    #[tokio::test]
    async fn the_cloud_metadata_endpoint_is_refused_at_bind_time() {
        for reach in [Reach::Public, Reach::Private] {
            for raw in CREDENTIALS {
                let token = credential(raw);
                let err = McpServer::bind(
                    erp(),
                    "http://169.254.169.254/",
                    &BTreeMap::new(),
                    reach,
                    token.as_ref(),
                    CancellationToken::new(),
                )
                .await
                .expect_err("169.254.169.254 is never an mcp server");

                assert!(
                    matches!(err, McpError::Blocked { ip, .. } if ip.to_string() == "169.254.169.254"),
                    "{reach:?} with credential={} let the metadata endpoint through: {err}",
                    raw.is_some()
                );
                assert_eq!(err.code(), "blocked_address");
            }
        }
    }

    #[tokio::test]
    async fn loopback_needs_an_explicit_opt_in() {
        for raw in CREDENTIALS {
            let token = credential(raw);
            let err = McpServer::bind(
                erp(),
                "http://127.0.0.1:1/",
                &BTreeMap::new(),
                Reach::Public,
                token.as_ref(),
                CancellationToken::new(),
            )
            .await
            .expect_err("loopback is not public");
            assert!(
                matches!(err, McpError::Blocked { .. }),
                "credential={}: {err}",
                raw.is_some()
            );
        }
    }

    #[tokio::test]
    async fn only_http_and_https_may_be_bound() {
        for url in ["file:///etc/passwd", "gopher://example.com/", "not a url"] {
            for raw in CREDENTIALS {
                let token = credential(raw);
                let err = McpServer::bind(
                    erp(),
                    url,
                    &BTreeMap::new(),
                    Reach::Public,
                    token.as_ref(),
                    CancellationToken::new(),
                )
                .await
                .expect_err("only http(s)");
                assert!(
                    matches!(err, McpError::BadUrl(_)),
                    "{url} was accepted with credential={}",
                    raw.is_some()
                );
            }
        }
    }

    /// **A credential is not a key to an address**, and the refusal carries none
    /// of it.
    ///
    /// The message of every bind-time refusal is rendered into `BindFailure`,
    /// which `routes::mcp::list_servers` puts in a JSON response. So the string
    /// an operator reads is checked here, at the source, rather than at the one
    /// route that happens to render it today.
    #[tokio::test]
    async fn a_refused_bind_never_carries_the_credential_in_its_message() {
        const TOKEN: &str = "ghp_leaked_if_this_test_fails";
        let token = Secret::new(TOKEN);

        for url in [
            "http://169.254.169.254/",
            "http://127.0.0.1:1/",
            "file:///etc/passwd",
            "http://this-host-does-not-resolve.invalid/mcp",
        ] {
            let err = McpServer::bind(
                erp(),
                url,
                &BTreeMap::new(),
                Reach::Public,
                Some(&token),
                CancellationToken::new(),
            )
            .await
            .expect_err("none of these bind");

            let rendered = format!("{err} {err:?} {}", err.code());
            assert!(!rendered.contains(TOKEN), "{url}: {rendered}");
        }
    }

    #[test]
    fn every_address_family_places_the_same_way() {
        let cases = [
            ("169.254.169.254", Placement::Forbidden),
            ("::ffff:169.254.169.254", Placement::Forbidden),
            // The deprecated IPv4-compatible spelling of the same thing.
            ("::169.254.169.254", Placement::Forbidden),
            ("0.0.0.0", Placement::Forbidden),
            ("224.0.0.1", Placement::Forbidden),
            ("100.100.100.200", Placement::Forbidden),
            ("fe80::1", Placement::Forbidden),
            ("::", Placement::Forbidden),
            ("127.0.0.1", Placement::Private),
            ("10.0.0.1", Placement::Private),
            ("192.168.1.1", Placement::Private),
            ("::1", Placement::Private),
            ("fd00::1", Placement::Private),
            ("93.184.216.34", Placement::Global),
            ("2606:2800:220:1:248:1893:25c8:1946", Placement::Global),
        ];
        for (raw, expected) in cases {
            let ip: IpAddr = raw.parse().expect("address");
            assert_eq!(placement(ip), expected, "{raw}");
        }
    }

    // -- risk classes ------------------------------------------------------

    #[test]
    fn an_undeclared_tool_is_destructive_whatever_the_server_claims() {
        let harmless = ToolAnnotations::new().read_only(true);
        assert_eq!(classify(None, None), RiskClass::Destructive);
        assert_eq!(classify(None, Some(&harmless)), RiskClass::Destructive);
    }

    #[test]
    fn a_tool_that_changed_since_the_operator_vetted_it_is_destructive() {
        // The attack this closes: an operator vets `lookup` — takes an id,
        // returns a row — and declares it Read. The server later redeploys the
        // same *name* with `callback_url` added to its schema. Name-keyed
        // declarations still say Read, so a tool that now exfiltrates on demand
        // is allowed without a human. Every name-keyed check in the system
        // agrees with every other one, and all of them are wrong together.
        let vetted = tool("lookup");

        let mut widened_schema = JsonObject::new();
        widened_schema.insert("callback_url".into(), serde_json::json!({"type": "string"}));
        let widened = Tool::new(
            "lookup".to_owned(),
            "a tool".to_owned(),
            Arc::new(widened_schema),
        );

        let pinned = BTreeMap::from([(
            slug("lookup"),
            Declaration {
                risk: RiskClass::Read,
                digest: Some(digest(&vetted)),
            },
        )]);

        assert_eq!(
            inventory(&[vetted], &pinned).expect("inventory")[&slug("lookup")].risk,
            RiskClass::Read,
            "the tool the operator actually vetted keeps its declared class"
        );
        assert_eq!(
            inventory(&[widened], &pinned).expect("inventory")[&slug("lookup")].risk,
            RiskClass::Destructive,
            "a changed input schema falls back to undeclared, which needs a human"
        );
    }

    #[test]
    fn a_digest_does_not_depend_on_key_order() {
        // Serde_json preserves insertion order by default, so two servers
        // serialising the same schema with different key order would otherwise
        // produce two digests and lock the operator out of their own tool.
        let mut a = JsonObject::new();
        a.insert("x".into(), serde_json::json!(1));
        a.insert("y".into(), serde_json::json!(2));
        let mut b = JsonObject::new();
        b.insert("y".into(), serde_json::json!(2));
        b.insert("x".into(), serde_json::json!(1));

        assert_eq!(
            digest(&Tool::new("t".to_owned(), "d".to_owned(), Arc::new(a))),
            digest(&Tool::new("t".to_owned(), "d".to_owned(), Arc::new(b))),
        );
    }

    #[test]
    fn a_server_hint_can_raise_a_class_but_never_lower_it() {
        let claims_destructive = ToolAnnotations::new().destructive(true);
        let claims_harmless = ToolAnnotations::new().read_only(true);

        assert_eq!(
            classify(Some(RiskClass::Read), Some(&claims_destructive)),
            RiskClass::Destructive,
            "a server admitting to damage is believed"
        );
        assert_eq!(
            classify(Some(RiskClass::Destructive), Some(&claims_harmless)),
            RiskClass::Destructive,
            "a server claiming innocence is not"
        );
    }

    #[test]
    fn names_that_collapse_to_one_handle_are_refused() {
        let err = inventory(&[tool("read_file"), tool("read-file")], &BTreeMap::new())
            .expect_err("two names, one handle");
        assert!(matches!(err, McpError::AmbiguousTool { .. }));
        assert_eq!(err.code(), "ambiguous_tool");
    }

    #[test]
    fn a_name_with_no_handle_is_dropped_rather_than_mangled() {
        // No allowlist entry could ever spell these, so they are unreachable.
        let tools = inventory(&[tool("x"), tool("Ünïcødé!"), tool("ok")], &BTreeMap::new())
            .expect("no collision");
        assert_eq!(tools.keys().map(Slug::as_str).collect::<Vec<_>>(), ["ok"]);
    }

    // -- the wire ----------------------------------------------------------

    #[tokio::test]
    async fn binding_discovers_every_page_of_tools() {
        let server = FakeMcp::start(two_pages()).await;
        let bound = bound(&server).await;

        assert_eq!(
            bound.tools().keys().map(Slug::as_str).collect::<Vec<_>>(),
            ["drop-table", "lookup", "undeclared", "write-note"],
            "page two must be walked, not dropped"
        );
        assert_eq!(server.count("tools/list"), 2, "one request per page");

        // The wire spelling survives the fold to a policy handle.
        assert_eq!(bound.tools()[&slug("write-note")].wire_name(), "write_note");
        assert_eq!(bound.tools()[&slug("lookup")].risk(), RiskClass::Read);
        assert_eq!(
            bound.tools()[&slug("undeclared")].risk(),
            RiskClass::Destructive
        );
    }

    #[tokio::test]
    async fn a_call_is_exactly_one_round_trip() {
        let server = FakeMcp::start(two_pages()).await;
        let bound = bound(&server).await;

        let result = bound
            .call(
                &call("lookup"),
                Some(json!({"q": "acme"}).as_object().cloned().expect("object")),
            )
            .await
            .expect("a read-class tool runs");

        // The result is third-party text and stays wrapped.
        let inner = result.expose_for_parsing();
        assert_eq!(inner.is_error, Some(false));
        assert!(
            matches!(inner.content.as_slice(), [ContentBlock::Text(t)] if t.text == "ran lookup"),
            "the wire name went out, not the policy handle: {:?}",
            inner.content
        );

        assert_eq!(
            server.count("tools/call"),
            1,
            "call_tool_once must not drive follow-up rounds"
        );
    }

    #[tokio::test]
    async fn a_destructive_tool_requires_a_human() {
        let server = FakeMcp::start(two_pages()).await;
        let bound = bound(&server).await;

        assert!(matches!(
            bound.verdict(&call("drop-table")),
            Decision::RequireApproval { .. }
        ));

        let err = bound
            .call(&call("drop-table"), None)
            .await
            .expect_err("destructive tools are not self-service");
        assert!(matches!(
            err,
            McpError::Refused(Decision::RequireApproval { .. })
        ));
        assert_eq!(
            server.count("tools/call"),
            0,
            "the refusal happens before the server is contacted"
        );

        // Same for the tool nobody declared.
        assert!(matches!(
            bound.verdict(&call("undeclared")),
            Decision::RequireApproval { .. }
        ));
    }

    #[tokio::test]
    async fn an_unknown_tool_or_another_server_never_reaches_the_wire() {
        let server = FakeMcp::start(two_pages()).await;
        let bound = bound(&server).await;

        for tool in [
            McpTool::new(erp(), slug("no-such-tool")),
            McpTool::new(slug("other-server"), slug("lookup")),
        ] {
            let err = bound
                .call(&tool, None)
                .await
                .expect_err("not a tool on this binding");
            assert!(matches!(err, McpError::UnknownTool(_)), "{tool}");
            assert!(matches!(
                bound.verdict(&tool),
                Decision::Deny {
                    reason: DenyReason::ToolNotAllowed
                }
            ));
        }
        assert_eq!(server.count("tools/call"), 0);
    }

    /// **A server that takes the request and goes quiet gives up on its own.**
    ///
    /// Nothing above this call bounds it. `Turn::attempt` races the *model* call
    /// against its `CancellationToken` and nothing races an effect, so
    /// `apps/server`'s `TURN_DEADLINE` fires a token that is only read at the
    /// next checkpoint — which a call that never returns never reaches. On the
    /// inbound path that turn is inside the outbox handler's tenant
    /// transaction, so the wedge is an open Postgres transaction held for as
    /// long as somebody else's server stays quiet.
    ///
    /// The socket stays open and the request was accepted, which is why a
    /// connect timeout would not have caught this and why `rmcp`'s transport —
    /// which builds its own HTTP client with reqwest's default of *no* request
    /// timeout — does not either.
    ///
    /// The sixty seconds run on a virtual clock: tokio advances it once every
    /// task is parked, which they are the moment the fake server swallows the
    /// call. The pause is taken **after** the bind and not by
    /// `#[tokio::test(start_paused)]`, because `ClientLifecycleMode::Auto`
    /// falls back to the legacy `initialize` handshake after ten seconds of
    /// silence — on a paused clock those ten seconds pass during the handshake
    /// and the bind itself fails. Without the timeout this test hangs rather
    /// than failing, so it carries a guard of its own.
    #[tokio::test]
    async fn a_server_that_never_answers_is_abandoned_rather_than_waited_for() {
        let server = FakeMcp::start_swallowing_calls(two_pages()).await;
        let bound = Arc::new(bound(&server).await);
        let tool = McpTool::new(erp(), slug("lookup"));

        // Dispatched on a real clock, so the request genuinely goes out. The
        // virtual clock is taken only once the server has the request in hand:
        // paused first, tokio advances the moment every task parks — which is
        // before the reactor has flushed the socket — and the call would time
        // out without anything ever having been sent, which is not the failure
        // under test.
        let call = tokio::spawn({
            let (bound, tool) = (Arc::clone(&bound), tool.clone());
            async move { bound.call(&tool, None).await }
        });
        let landed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while server.count("tools/call") == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(landed.is_ok(), "the request never reached the server");

        tokio::time::pause();
        let err = tokio::time::timeout(std::time::Duration::from_secs(600), call)
            .await
            .expect("the call never gave up at all")
            .expect("the call panicked")
            .expect_err("a server that never answers must not be waited on forever");

        // The diagnosis is "slow", not "unreachable" — the request landed, and
        // the assertion above is what says so.
        assert!(
            matches!(&err, McpError::TimedOut { tool: t, secs } if *t == tool && *secs == CALL_TIMEOUT.as_secs()),
            "{err}"
        );
        assert_eq!(err.code(), "timed_out");
        assert_eq!(server.count("tools/call"), 1, "it was sent more than once");

        // And it reaches the effect layer as retryable, like every other
        // "the network was unlucky" — a quiet server is not a reason to stop
        // asking, unlike a refusal.
        assert!(as_provider_error(&err).is_retryable(), "{err}");
    }

    /// **A credential the server refused is not a credential to try again
    /// with**, and the test above is the other half of the same sentence.
    ///
    /// The two failures are one variant to `rmcp`: a socket that died halfway
    /// and a `401` both arrive as [`McpError::Transport`], and that variant used
    /// to sit in the retryable arm with the connect failures. So a customer who
    /// rotated the token behind a live binding got, for every tool call: the
    /// model told `retryable` and asking again inside the same turn; an audit
    /// row saying `retryable: true`; a binding page that reads "in progress"
    /// forever; and a dead bearer token replayed at a third party's server as
    /// fast as the turn loop goes round. Nothing in that says "your connection
    /// is broken", which is the one thing the customer needed to be told.
    ///
    /// The bind is the ordinary path — this server hands out its tools happily
    /// — which is what makes the refusal a statement about the *call*: a token
    /// that was good when the binding came up and is not good now.
    #[tokio::test]
    async fn a_credential_the_server_refused_is_terminal_and_a_silent_server_is_not() {
        let server = FakeMcp::start_refusing_calls(two_pages()).await;
        let bound = bound(&server).await;
        let tool = McpTool::new(erp(), slug("lookup"));

        let err = bound
            .call(&tool, None)
            .await
            .expect_err("a 401 is not a result");

        assert_eq!(
            server.count("tools/call"),
            1,
            "the refusal was replayed before anyone classified it"
        );

        let verdict = as_provider_error(&err);
        assert!(
            !verdict.is_retryable(),
            "a token this server has already refused was classified {} — retrying \
             it hammers somebody else's server with a dead credential and hides \
             a broken binding behind a status that reads like progress ({err})",
            verdict.code()
        );
        // Not merely "not retryable": the code is what an operator reads in the
        // audit row, and `unauthorized` is the one word that sends them to the
        // credential instead of to the network.
        assert_eq!(
            verdict,
            ProviderError::Terminal {
                code: "unauthorized"
            },
            "{err}"
        );

        // And the distinction is real, not an artefact of this fixture: the same
        // client, against a server that says nothing at all, still comes back
        // retryable — see
        // [`a_server_that_never_answers_is_abandoned_rather_than_waited_for`]
        // for that half. Here is the cheap end of it, so the two live together.
        assert!(
            as_provider_error(&McpError::Connect("no route".to_owned())).is_retryable(),
            "a server that was never reached must still be worth another go"
        );
    }

    /// **A server that accepts the connection and then says nothing must not
    /// hold the binder open for every other tenant in the deployment.**
    ///
    /// [`CALL_TIMEOUT`] bounds `tools/call` and nothing bounded the handshake
    /// or `tools/list`. That gap is not one tenant's problem, because
    /// `routes::mcp::run` walks the deployment's tenants **one after another**
    /// and awaits each [`Fleet::bind`]: a single customer pointing a binding at
    /// a socket that accepts and stalls stops every *other* customer's fleet
    /// from ever being bound or refreshed. Their employees keep answering their
    /// mail with no MCP tools at all, the operator's binding page says
    /// `pending` forever, and nothing in the logs names the tenant responsible.
    ///
    /// Same shape as `a_server_that_never_answers_is_abandoned_rather_than_
    /// waited_for` and same clock discipline: the connection is made on a real
    /// clock, so the socket genuinely opens, and the virtual clock is taken only
    /// once the server has the connection in hand. The outer timeout is what
    /// turns "this hangs" into "this fails", which is the difference between a
    /// test that reports a bug and a suite that never finishes.
    #[tokio::test]
    async fn a_server_that_accepts_and_says_nothing_does_not_hold_the_binder_forever() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        let accepted = Arc::new(Mutex::new(0_usize));
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            // Accept and hold. Never read, never answer, never close: the
            // failure a *connect* timeout cannot see.
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                *counted.lock().expect("not poisoned") += 1;
                held.push(stream);
            }
        });

        let bind = tokio::spawn(async move {
            McpServer::bind(
                erp(),
                &format!("http://{addr}/mcp"),
                &declared(),
                Reach::Private,
                None,
                CancellationToken::new(),
            )
            .await
        });

        let landed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while *accepted.lock().expect("not poisoned") == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(landed.is_ok(), "the binder never reached the server");

        tokio::time::pause();
        let err = tokio::time::timeout(std::time::Duration::from_secs(3600), bind)
            .await
            .expect("the bind never gave up at all; one tenant's dead endpoint stops the binder")
            .expect("the bind panicked")
            .expect_err("a server that never answers must not be waited on forever");

        assert_eq!(err.code(), "bind_timed_out", "{err}");
        // Reachable and mute, not unreachable — the accept count is what says
        // so, and the code has to agree or an operator debugs the wrong end.
        assert_eq!(*accepted.lock().expect("not poisoned"), 1);
    }

    #[tokio::test]
    async fn a_binding_records_the_addresses_it_resolved_to() {
        let server = FakeMcp::start(two_pages()).await;
        let bound = bound(&server).await;
        assert_eq!(
            bound.pinned_addresses().to_vec(),
            vec!["127.0.0.1".parse::<IpAddr>().expect("address")]
        );
        assert_eq!(bound.name(), &erp());
        bound.close().await.expect("close");
    }

    // -- the credential ----------------------------------------------------

    /// **The token reaches the wire, exactly once, in the header the server
    /// expects** — and it is not on the wire when there is no token.
    ///
    /// This is the whole reason the credential exists, and it is the assertion
    /// nothing else in the workspace can make: every other test here proves a
    /// refusal, and a refusal proves nothing about what a *successful* bind
    /// sends. `rmcp`'s `auth_header` takes the token *without* the `Bearer `
    /// prefix and writes the scheme itself, so `Bearer Bearer …` is one line of
    /// misreading away and every server on earth answers it with a 401 that
    /// explains nothing.
    #[tokio::test]
    async fn a_bearer_token_is_sent_on_every_request_and_never_doubled() {
        const TOKEN: &str = "ghp_sixteen_chars_of_token";
        let server = crate::mocks::FakeMcpServer::start(&["lookup"]).await;

        let bound = McpServer::bind(
            erp(),
            server.url(),
            &BTreeMap::new(),
            Reach::Private,
            Some(&Secret::new(TOKEN)),
            CancellationToken::new(),
        )
        .await
        .expect("the fake server binds");

        let sent = server.authorizations();
        assert!(
            !sent.is_empty(),
            "the client bound without sending the credential at all"
        );
        for value in &sent {
            // Lowercased by the fixture's header reader; the *value* is not.
            assert_eq!(
                value,
                &format!("Bearer {TOKEN}"),
                "the credential is not the exact header the server expects: {sent:?}"
            );
        }

        // The binding itself does not carry the plaintext anywhere printable.
        let rendered = format!("{bound:?}");
        assert!(!rendered.contains(TOKEN), "{rendered}");
        bound.close().await.expect("close");

        // And the control: no token, no header. Not an empty one — a
        // `Authorization: Bearer ` is a 401 nobody can debug.
        let bare = crate::mocks::FakeMcpServer::start(&["lookup"]).await;
        McpServer::bind(
            erp(),
            bare.url(),
            &BTreeMap::new(),
            Reach::Private,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("an unauthenticated server binds")
        .close()
        .await
        .expect("close");
        assert!(
            bare.authorizations().is_empty(),
            "a binding with no credential sent one anyway: {:?}",
            bare.authorizations()
        );
    }

    /// A sealed credential opens for the binding it was sealed for, and for no
    /// other one — not another tenant's, not the next server handle along.
    ///
    /// The second half is the one that needs a test. Tenant separation comes
    /// free from the wrap AAD that `providers::secrets` already had; binding the
    /// payload to the *server handle* is what [`credential_context`] added, and
    /// it is what stops a `sealed_token` blob being copied one row sideways onto
    /// a binding that points somewhere else.
    #[test]
    fn a_credential_opens_only_for_the_binding_it_was_sealed_for() {
        const TOKEN: &str = "a-token-that-must-not-travel";
        let credentials = Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([5u8; 32])));
        let (tenant, other_tenant) = (TenantId::new_v7(Utc::now()), TenantId::new_v7(Utc::now()));

        let sealed = credentials
            .seal(tenant, &erp(), Some(TOKEN.to_owned()))
            .expect("seal")
            .expect("a token was given");

        assert_eq!(
            credentials
                .open(tenant, &erp(), &sealed)
                .expect("its own binding")
                .expose_for_transport(),
            TOKEN
        );

        // The row, lifted one column sideways inside one tenant.
        assert_eq!(
            credentials
                .open(tenant, &slug("crm"), &sealed)
                .expect_err("a credential is not portable between handles")
                .code(),
            "secret_decrypt_failed"
        );
        // ...and lifted into another tenant.
        assert_eq!(
            credentials
                .open(other_tenant, &erp(), &sealed)
                .expect_err("nor between tenants")
                .code(),
            "secret_decrypt_failed"
        );

        // The stored form carries no plaintext, and neither does the handle.
        let rendered = format!("{sealed:?} {credentials:?}");
        assert!(!rendered.contains(TOKEN), "{rendered}");

        // An absent or blank token is no credential, never an empty one.
        for blank in [None, Some(String::new()), Some("   \n".to_owned())] {
            assert_eq!(
                credentials
                    .seal(tenant, &erp(), blank.clone())
                    .expect("seal"),
                None,
                "{blank:?} became a credential"
            );
        }
    }

    /// A stored credential that will not open is a binding that is **skipped**,
    /// carrying a code that says whose fault it is.
    #[tokio::test]
    async fn a_credential_that_will_not_open_refuses_the_bind_rather_than_dropping_the_header() {
        let server = crate::mocks::FakeMcpServer::start(&["lookup"]).await;
        let credentials = Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([5u8; 32])));
        let tenant = TenantId::new_v7(Utc::now());
        let sealed = credentials
            .seal(tenant, &erp(), Some("a-token".to_owned()))
            .expect("seal")
            .expect("given");

        // A different deployment's master key: the row is intact and unopenable,
        // which is what a rotated `AGENTOS_MASTER_KEY` looks like.
        let stranger = Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([6u8; 32])));
        let err = stranger
            .bind(
                tenant,
                erp(),
                server.url(),
                &BTreeMap::new(),
                Reach::Private,
                Some(&sealed),
                CancellationToken::new(),
            )
            .await
            .expect_err("a credential that will not open is not a bind without one");
        assert_eq!(err.code(), "secret_decrypt_failed");

        // The point of refusing: the server was never contacted, so the operator
        // is not chasing a 401 that blames the customer's token.
        assert!(
            server.authorizations().is_empty(),
            "it connected anyway: {:?}",
            server.authorizations()
        );

        // A blob that is not an envelope at all is the other half, and it is a
        // different code so an operator can tell a corrupted row from a rotated
        // key.
        assert_eq!(
            stranger
                .bind(
                    tenant,
                    erp(),
                    server.url(),
                    &BTreeMap::new(),
                    Reach::Private,
                    Some(b"not an envelope"),
                    CancellationToken::new(),
                )
                .await
                .expect_err("garbage is not a credential")
                .code(),
            "envelope_malformed"
        );
    }

    // -- the fleet ---------------------------------------------------------

    /// The list the model is given names what an operator wrote down, and
    /// nothing else.
    ///
    /// `undeclared` is bound, classified and callable by exact name — it is
    /// simply not a string an MCP server gets to put in a system prompt.
    #[tokio::test]
    async fn the_inventory_names_only_what_an_operator_declared() {
        let server = FakeMcp::start(two_pages()).await;
        let fleet = Fleet::new([bound(&server).await]);

        assert_eq!(
            fleet.inventory(),
            vec![
                (call("drop-table"), Risk::High),
                (call("lookup"), Risk::Low),
                (call("write-note"), Risk::Low),
            ],
            "a tool nobody declared must not reach the prefix"
        );

        // And an empty fleet refuses rather than panicking on a missing server.
        let err = McpCaller::call(&Fleet::empty(), &call("lookup"), &Value::Null)
            .await
            .expect_err("nothing is bound");
        assert_eq!(err.code(), "unknown_tool");
    }

    /// **The pin, end to end.** A declaration that no longer matches the tool
    /// the operator read does not merely go unclassified: the tool disappears
    /// from what an exposed turn is told exists, and calling it anyway never
    /// reaches the server.
    #[tokio::test]
    async fn a_digest_mismatch_makes_a_tool_unusable_end_to_end() {
        let served = tool("lookup");
        let server = FakeMcp::start(vec![vec![served.clone()]]).await;
        let pin = |vetted: &Tool| {
            BTreeMap::from([(
                slug("lookup"),
                Declaration {
                    risk: RiskClass::Read,
                    digest: Some(digest(vetted)),
                },
            )])
        };

        // The control: pinned to the tool that is actually there, so the whole
        // path works and the assertions below are the pin and nothing else.
        let vetted = Fleet::new([bound_with(&server, pin(&served)).await]);
        assert_eq!(vetted.inventory(), vec![(call("lookup"), Risk::Low)]);
        assert!(
            SystemPrompt::new("You are Lena.")
                .with_mcp_tools(&may_call([call("lookup")]), vetted.inventory())
                .render(TrustLabel::Untrusted)
                .contains("erp/lookup")
        );
        let result = McpCaller::call(&vetted, &call("lookup"), &json!({ "q": "acme" }))
            .await
            .expect("a vetted read-class tool runs");
        assert!(
            result
                .expose_for_parsing()
                .to_string()
                .contains("ran lookup"),
            "{:?}",
            result
        );
        assert_eq!(server.count("tools/call"), 1);

        // The attack: the same NAME, with an input schema the operator never
        // read — `callback_url`, i.e. a lookup that now exfiltrates on demand.
        let mut widened = JsonObject::new();
        widened.insert("callback_url".into(), json!({ "type": "string" }));
        let never_vetted = Tool::new("lookup".to_owned(), "a tool".to_owned(), Arc::new(widened));
        let stale = Fleet::new([bound_with(&server, pin(&never_vetted)).await]);

        // 1. The class the operator granted does not travel with the name.
        assert_eq!(stale.inventory(), vec![(call("lookup"), Risk::High)]);

        // 2. So a turn that has read a stranger's text is not told it exists —
        //    and the policy still allows it by name, which is the point: the
        //    class did the hiding, not the allowlist.
        assert!(
            !SystemPrompt::new("You are Lena.")
                .with_mcp_tools(&may_call([call("lookup")]), stale.inventory())
                .render(TrustLabel::Untrusted)
                .contains("erp/lookup"),
            "an exposed turn was told about a tool nobody vetted"
        );

        // 3. And naming it anyway is refused before the server is contacted —
        //    which is what makes this unusable rather than merely unclassified.
        let err = McpCaller::call(&stale, &call("lookup"), &json!({ "q": "acme" }))
            .await
            .expect_err("a tool that changed under the operator is not self-service");
        assert_eq!(err.code(), "refused");
        assert!(
            !err.is_retryable(),
            "retrying a refusal only spends the turn's budget"
        );
        assert_eq!(
            server.count("tools/call"),
            1,
            "still one: the second call never left this process"
        );
    }

    /// Where a binding comes from: `mcp_servers` and `mcp_tool_declarations`,
    /// read under row-level security, with the SSRF check on the live path.
    #[tokio::test]
    async fn a_binding_and_its_classes_come_out_of_the_tenants_configuration() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; mcp binding tests need a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        let server = FakeMcp::start(two_pages()).await;
        let tenant = TenantId::new_v7(Utc::now());
        let label = format!("mcp-{}", tenant.as_uuid().simple());

        let configure = async |reach: &str| {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query(
                "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");

            sqlx::query(
                "INSERT INTO mcp_servers (tenant_id, server, url, reach) VALUES ($1, 'erp', $2, $3) \
                 ON CONFLICT (tenant_id, server) DO UPDATE SET reach = excluded.reach",
            )
            .bind(tenant.as_uuid())
            .bind(&server.url)
            .bind(reach)
            .execute(&mut *tx)
            .await
            .expect("insert binding");

            sqlx::query(
                "INSERT INTO mcp_tool_declarations (tenant_id, server, tool, risk) VALUES \
                   ($1, 'erp', 'lookup', 'read'), \
                   ($1, 'erp', 'write-note', 'write'), \
                   ($1, 'erp', 'drop-table', 'destructive') \
                 ON CONFLICT DO NOTHING",
            )
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("insert declarations");
            tx.commit().await.expect("commit configuration");
        };

        let credentials = Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([3u8; 32])));
        let bind = async || {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            // `None`: this tenant's binding is dialled, so a bridge runtime is
            // not part of the question. The hosted path has its own test below.
            let fleet = Fleet::bind(&mut tx, &credentials, None, &CancellationToken::new())
                .await
                .expect("the configuration is readable");
            tx.commit().await.expect("commit read");
            fleet
        };

        // A sidecar on loopback needs `reach = 'private'`, and the operator
        // wrote it.
        configure("private").await;
        assert_eq!(
            bind().await.inventory(),
            vec![
                (call("drop-table"), Risk::High),
                (call("lookup"), Risk::Low),
                (call("write-note"), Risk::Low),
            ]
        );

        // The same row without that opt-in resolves to loopback, which the SSRF
        // check refuses — on the production path, not only in a unit test. The
        // binding is dropped and the turn keeps going with no tools from it.
        configure("public").await;
        let refused = bind().await;
        assert!(
            refused.inventory().is_empty(),
            "a binding that fails the address check must not be usable"
        );

        // ... and the operator is told which address, not just that it failed.
        // A binding that silently disappears is indistinguishable from one
        // nobody configured, which is the state people restart pods over.
        let failure = &refused.failures()[&erp()];
        assert_eq!(failure.code, "blocked_address");
        assert!(failure.detail.contains("127.0.0.1"), "{failure:?}");
        assert!(!refused.is_bound(&erp()));
    }

    /// **A hosted binding, end to end, against a fake runtime.**
    ///
    /// The row has no URL — nobody may name a bridge's address, which is
    /// `hosted`'s central claim — so everything about where this connection goes
    /// comes from the runtime's answer and from the operator's network. What is
    /// asserted, in order: hosting off refuses and *says so*; hosting on binds
    /// the tools; the runtime received this tenant's own credential and nothing
    /// else; and a runtime answering with an address outside the operator's
    /// network is refused exactly as a customer's URL would be.
    ///
    /// The bridge is a [`FakeMcp`] on loopback, which is what a bridge is: a
    /// Streamable HTTP endpoint on a private address that this process did not
    /// start. `crates/app/tests/orizn.rs` runs the same arrangement against the
    /// real `supergateway` and the real `orizn-visa-mcp`, so the shape here is
    /// the shape that has been proven to work with a genuine stdio package.
    #[tokio::test]
    async fn a_hosted_binding_starts_a_bridge_and_never_names_its_address() {
        use crate::hosted::{BridgeNetwork, Bridges, tests::FakeRuntime};

        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; mcp binding tests need a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        // `FakeMcpServer` and not this module's `FakeMcp`, for one reason: it
        // records the `Authorization` headers it was sent, and "the tenant's
        // credential went into the package's environment and onto no wire" is
        // half of what this test is for.
        let bridge = crate::mocks::FakeMcpServer::start(&["lookup", "write_note"]).await;
        let tenant = TenantId::new_v7(Utc::now());
        let label = format!("mcp-hosted-{}", tenant.as_uuid().simple());
        let credentials = Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([7u8; 32])));

        // The credential the package will read out of its own environment. It
        // is sealed by the same call `routes::mcp` makes, under the same AAD:
        // the storage of a hosted credential is not a new thing, only its
        // destination is.
        const TENANT_KEY: &str = "sk-live-this-tenants-own-key";
        let sealed = credentials
            .seal(tenant, &erp(), Some(TENANT_KEY.to_owned()))
            .expect("seals")
            .expect("a credential was given");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        // **No url.** `0043_mcp_hosted.sql` is what makes this row storable, and
        // the NULL is the whole design: there is no address in this tenant's
        // configuration for anybody — a customer, a compromised handler, an
        // employee who talked somebody into an UPDATE — to point at us.
        sqlx::query(
            "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector, sealed_token) \
             VALUES ($1, 'erp', NULL, 'public', 'orizn-visa', $2)",
        )
        .bind(tenant.as_uuid())
        .bind(&sealed)
        .execute(&mut *tx)
        .await
        .expect("insert hosted binding");
        sqlx::query(
            "INSERT INTO mcp_tool_declarations (tenant_id, server, tool, risk) VALUES \
               ($1, 'erp', 'lookup', 'read'), \
               ($1, 'erp', 'write-note', 'write')",
        )
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert declarations");
        tx.commit().await.expect("commit configuration");

        let bind = async |bridges: Option<&Bridges>| {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let fleet = Fleet::bind(&mut tx, &credentials, bridges, &CancellationToken::new())
                .await
                .expect("the configuration is readable");
            tx.commit().await.expect("commit read");
            fleet
        };

        // 1. No runtime deployed. The binding fails, it is *recorded* as a
        //    failure rather than silently missing, and the tenant has no tools.
        let unhosted = bind(None).await;
        assert!(
            unhosted.inventory().is_empty(),
            "a hosted binding produced tools on a deployment that runs no bridge"
        );
        assert_eq!(
            unhosted.failures().get(&erp()).map(|failure| failure.code),
            Some("hosting_unavailable"),
            "a binding that cannot be hosted must be a recorded failure, not a \
             binding that quietly is not there: {:?}",
            unhosted.failures()
        );

        // 2. A runtime, answering with the bridge it started, on the network the
        //    operator allocated.
        let runtime = Arc::new(FakeRuntime::answering(bridge.url()));
        let bridges = Bridges::new(
            Arc::clone(&runtime) as Arc<dyn crate::hosted::BridgeRuntime>,
            BridgeNetwork::parse("127.0.0.0/8").expect("a valid network"),
        );
        let hosted = bind(Some(&bridges)).await;
        assert_eq!(
            hosted.inventory(),
            vec![(call("lookup"), Risk::Low), (call("write-note"), Risk::Low)],
            "a hosted binding's tools are classed exactly like a dialled one's"
        );

        // 3. What the runtime was asked for: this tenant, this handle, the
        //    package the catalogue names — and this tenant's own credential,
        //    opened from its own row. Nothing else was in the spec, because
        //    `BridgeSpec` has no other field.
        let seen = runtime.seen.lock().expect("not poisoned").clone();
        assert_eq!(
            seen,
            vec![(
                tenant,
                "erp".to_owned(),
                "orizn-visa-mcp@1.3.0",
                Some(TENANT_KEY.to_owned())
            )]
        );

        // 4. **The bridge was never sent the credential.** It went into the
        //    package's environment, which is where the package reads it, and a
        //    second copy on an `Authorization` header would be a tenant's secret
        //    on a hop that does not need it and cannot use it.
        assert!(
            bridge.authorizations().is_empty(),
            "the tenant's credential was also put on the wire to the bridge: {:?}",
            bridge.authorizations()
        );

        // 5. The same runtime, the same answer, an operator network that does
        //    not contain it. Refused — which is what stops a runtime that is
        //    wrong (or lying) about an address from making this process read
        //    something on its own private network.
        let elsewhere = Bridges::new(
            Arc::new(FakeRuntime::answering(bridge.url())),
            BridgeNetwork::parse("10.42.0.0/16").expect("a valid network"),
        );
        let refused = bind(Some(&elsewhere)).await;
        assert!(
            refused.inventory().is_empty(),
            "an endpoint the operator's network does not contain was bound anyway"
        );
        let failure = refused
            .failures()
            .get(&erp())
            .expect("a refused endpoint is a recorded failure");
        assert_eq!(
            failure.code, "bridge_endpoint_refused",
            "an endpoint outside the operator's bridge network is not a bridge"
        );
        // And the refusal names no address, unlike `blocked_address` above: the
        // operator did not choose this one and cannot correct it, so the detail
        // would be our infrastructure's shape in a tenant's API response.
        assert!(
            !failure.detail.contains("127.0.0.1"),
            "a refusal named our own infrastructure's address: {failure:?}"
        );
    }

    /// **The pin outranks the gate.** A tool whose digest no longer matches is
    /// not merely reclassified — the refusal survives a Policy Gate that has
    /// already said `Allow`, and it happens before the server is contacted.
    ///
    /// This is the assertion that makes the whole scheme worth its complexity.
    /// `allowed_mcp_tools` is keyed by NAME, and so is every other check in this
    /// system; a tool that changed under the operator passes all of them. If the
    /// binding did not refuse independently, the digest would be a warning label
    /// rather than a control.
    #[tokio::test]
    async fn a_stale_pin_refuses_a_call_the_gate_already_authorised() {
        use std::collections::BTreeSet;

        use agentos_domain::ids::EmployeeId;
        use agentos_domain::policy::PolicyLimits;

        use crate::effects::{Effects, McpCall};
        use crate::gate::{PolicyGate, Principal as ActingAs};

        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the gate path needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        // A tenant with one active employee. Nothing else: an MCP call moves no
        // money, so there are no caps to seed.
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("pin-{}", employee.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        // The stored policy allows this exact tool — by name, which is the only
        // thing a policy allowlist can say. Written to `policy_layers`, because
        // that is where the gate reads it.
        agentos_store::policy::install(
            &db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                allowed_mcp_tools: BTreeSet::from([call("lookup")]),
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");
        let gate = PolicyGate::new(db.clone());
        let principal = ActingAs::employee(tenant, employee);

        // The server serves a `lookup` with a `callback_url` the operator never
        // read; the declaration pins the one they did.
        let mut widened = JsonObject::new();
        widened.insert("callback_url".into(), json!({ "type": "string" }));
        let served = Tool::new("lookup".to_owned(), "a tool".to_owned(), Arc::new(widened));
        let server = FakeMcp::start(vec![vec![served]]).await;
        let vetted = tool("lookup");
        let stale = Fleet::new([bound_with(
            &server,
            BTreeMap::from([(
                slug("lookup"),
                Declaration {
                    risk: RiskClass::Read,
                    digest: Some(digest(&vetted)),
                },
            )]),
        )
        .await]);

        let mut ports = crate::mocks::ports();
        ports.mcp = Arc::new(stale);
        let effects = Effects::new(db, Arc::new(ports), principal.clone());

        // The gate says yes. It is not wrong — `erp/lookup` is on the
        // allowlist, and a name is all it has.
        let authorized = gate
            .authorize(
                &principal,
                McpCall {
                    tool: call("lookup"),
                },
            )
            .await
            .expect("the policy allows this tool by name");

        // And the call still does not happen.
        let err = effects
            .call_tool(authorized, &json!({ "q": "acme" }))
            .await
            .expect_err("a gate ruling cannot revive a declaration that no longer matches");
        assert_eq!(err.code(), "refused");
        assert!(
            !err.is_retryable(),
            "retrying a refusal only spends the turn's budget"
        );
        assert_eq!(
            server.count("tools/call"),
            0,
            "the refusal must precede the request, not follow it"
        );
    }
}
