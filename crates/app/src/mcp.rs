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

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use agentos_domain::action::McpTool;
use agentos_domain::ids::Slug;
use agentos_domain::policy::{ApprovalReason, Decision, DenyReason};
use agentos_domain::untrusted::Untrusted;
use rmcp::RoleClient;
use rmcp::ServiceError;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities, ClientInfo,
    Implementation, JsonObject, ProtocolVersion, Tool, ToolAnnotations,
};
use rmcp::service::{ClientLifecycleMode, RunningService, serve_client_with_lifecycle_and_ct};
use rmcp::transport::StreamableHttpClientTransport;
use tokio_util::sync::CancellationToken;
use url::Url;

/// What we tell an MCP server we are. Display only; nothing authorises off it.
const CLIENT_NAME: &str = "agentos";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The only schemes a binding URL may use.
///
/// ponytail: a constant, not config. `file:`, `ftp:` and `gopher:` are how a
/// URL allowlist gets walked around; if an operator needs a third scheme they
/// can ask, and we can ask why.
const ALLOWED_SCHEMES: [&str; 2] = ["http", "https"];

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

/// Where one resolved address sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Routable on the public internet.
    Global,
    /// Reachable but internal: loopback, RFC 1918, unique-local.
    Private,
    /// Never a legitimate MCP server: metadata endpoints, multicast,
    /// unspecified, reserved.
    Forbidden,
}

fn placement(ip: IpAddr) -> Placement {
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
    /// Every side effect that matters happens here, once, under operator
    /// control: the DNS lookup, the address check, and the tool inventory.
    /// Nothing at call time takes a string from anywhere but this struct.
    pub async fn bind(
        server: Slug,
        url: &str,
        declared: &BTreeMap<Slug, RiskClass>,
        reach: Reach,
        ct: CancellationToken,
    ) -> Result<Self, McpError> {
        let url = vet_url(url)?;
        let pinned = resolve_and_vet(&url, reach).await?;

        // ponytail: the resolved addresses are recorded, not forced onto the
        // socket — `rmcp`'s convenience transport builds its own HTTP client
        // and this crate cannot name reqwest to hand it a `.resolve()` pin.
        // The residual hole is DNS rebinding between this lookup and the first
        // request. Closing it is one line (`reqwest::Client::builder()
        // .resolve(host, addr)` fed to `StreamableHttpClientTransport::
        // with_client`) the day `reqwest` is a direct dependency of this crate.
        let transport = StreamableHttpClientTransport::from_uri(url.as_str());
        let info = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new(CLIENT_NAME, CLIENT_VERSION),
        );
        let client = serve_client_with_lifecycle_and_ct(
            info,
            transport,
            // Sessionless, per MCP 2026-07-28: no `initialize`, no session id,
            // the protocol version travels on every request. ponytail: switch
            // this to `Auto` the day a server that predates the revision has
            // to be supported — it is the same one literal.
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
            ct,
        )
        .await
        .map_err(|e| McpError::Connect(e.to_string()))?;

        // `list_all_tools` walks `next_cursor` for us; a partial inventory
        // would silently classify the tools on page two as undeclared.
        let discovered = client.list_all_tools().await?;
        let tools = inventory(&discovered, declared)?;

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
        match self.client.call_tool_once(params).await? {
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
fn inventory(
    discovered: &[Tool],
    declared: &BTreeMap<Slug, RiskClass>,
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
        let risk = classify(declared.get(&handle).copied(), tool.annotations.as_ref());
        tools.insert(
            handle,
            BoundTool {
                wire_name: tool.name.to_string(),
                risk,
                description: tool
                    .description
                    .as_ref()
                    .map(|d| Untrusted::new(d.to_string())),
            },
        );
    }
    Ok(tools)
}

/// Parse and scheme-check. Rejects anything that is not http(s) with a host.
fn vet_url(raw: &str) -> Result<Url, McpError> {
    let url = Url::parse(raw).map_err(|_| McpError::BadUrl(raw.to_owned()))?;
    if !ALLOWED_SCHEMES.contains(&url.scheme()) || url.host_str().is_none() {
        return Err(McpError::BadUrl(raw.to_owned()));
    }
    Ok(url)
}

/// Resolve the host and refuse every address `reach` does not permit.
///
/// *Every* address, not the first one: a host that resolves to one public
/// address and one metadata address is a host that will reach the metadata
/// address on the retry.
async fn resolve_and_vet(url: &Url, reach: Reach) -> Result<Vec<IpAddr>, McpError> {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex;

    use rmcp::model::{ContentBlock, DiscoverResult, ListToolsResult, ServerCapabilities};
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

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

    impl FakeMcp {
        async fn start(pages: Vec<Vec<Tool>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr: SocketAddr = listener.local_addr().expect("addr");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let pages = Arc::new(pages);

            let accepted = Arc::clone(&seen);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let seen = Arc::clone(&accepted);
                    let pages = Arc::clone(&pages);
                    tokio::spawn(async move { serve_connection(stream, seen, pages).await });
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

    fn declared() -> BTreeMap<Slug, RiskClass> {
        BTreeMap::from([
            (slug("lookup"), RiskClass::Read),
            (slug("write-note"), RiskClass::Write),
            (slug("drop-table"), RiskClass::Destructive),
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
        McpServer::bind(
            erp(),
            &server.url,
            &declared(),
            Reach::Private,
            CancellationToken::new(),
        )
        .await
        .expect("bind to the fake server")
    }

    // -- SSRF --------------------------------------------------------------

    #[tokio::test]
    async fn the_cloud_metadata_endpoint_is_refused_at_bind_time() {
        for reach in [Reach::Public, Reach::Private] {
            let err = McpServer::bind(
                erp(),
                "http://169.254.169.254/",
                &BTreeMap::new(),
                reach,
                CancellationToken::new(),
            )
            .await
            .expect_err("169.254.169.254 is never an mcp server");

            assert!(
                matches!(err, McpError::Blocked { ip, .. } if ip.to_string() == "169.254.169.254"),
                "{reach:?} let the metadata endpoint through: {err}"
            );
            assert_eq!(err.code(), "blocked_address");
        }
    }

    #[tokio::test]
    async fn loopback_needs_an_explicit_opt_in() {
        let err = McpServer::bind(
            erp(),
            "http://127.0.0.1:1/",
            &BTreeMap::new(),
            Reach::Public,
            CancellationToken::new(),
        )
        .await
        .expect_err("loopback is not public");
        assert!(matches!(err, McpError::Blocked { .. }));
    }

    #[tokio::test]
    async fn only_http_and_https_may_be_bound() {
        for url in ["file:///etc/passwd", "gopher://example.com/", "not a url"] {
            let err = McpServer::bind(
                erp(),
                url,
                &BTreeMap::new(),
                Reach::Public,
                CancellationToken::new(),
            )
            .await
            .expect_err("only http(s)");
            assert!(matches!(err, McpError::BadUrl(_)), "{url} was accepted");
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
}
