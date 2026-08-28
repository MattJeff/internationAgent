//! Running somebody else's stdio MCP server *for* a tenant, without running it
//! in our process tree.
//!
//! # The paragraph this module exists to beat
//!
//! [`crate::mcp`] implements one transport, argues the refusal of the other for
//! ninety lines, and ends by inviting the argument that beats it. Its three
//! bullets are about a **tenant-configurable stdio transport**, and each one is
//! answered by something structural here rather than by a promise:
//!
//! * *"A command has no analogous property … an allowlist of permitted programs
//!   **is** the configuration, which makes the tenant-supplied command
//!   redundant."* Agreed, and taken literally: the allowlist is the
//!   configuration. A tenant never supplies a command. A hosted binding names a
//!   [`crate::catalog::Connector`], the connector carries a [`Package`], and a
//!   `Package` is a `const` in this binary — the same call `catalog` makes for
//!   URLs and `mcp::ALLOWED_SCHEMES` makes for schemes. Adding a package is a
//!   deploy, which is the correct price for adding a program we agree to run.
//! * *"A spawned command runs **as the server**, in the server's process tree,
//!   with the server's environment."* That is the whole objection, and it is an
//!   objection to *spawning*, not to hosting. Nothing here spawns. [`BridgeRuntime::start`]
//!   describes a process to a [`BridgeRuntime`] that lives somewhere else, and
//!   the environment that process gets is **enumerated** by [`BridgeSpec`]
//!   rather than inherited: there is no code path in this crate that copies
//!   `std::env` into a spec, because the type has no field that could hold one.
//!   `/proc/self/environ` inside a bridge holds one variable this system put
//!   there, and it is that tenant's own credential.
//! * *"None of the machinery below would notice … a hostile binding does its
//!   work at spawn time, before any tool is called, and every control in this
//!   file rules on calls."* Still true, and now harmless: the work that used to
//!   happen at spawn time happens in a place that holds no `DATABASE_URL`, no
//!   master key and no other tenant's anything. Everything after the bridge is
//!   unchanged — from [`crate::mcp`]'s point of view a bridge is a URL, so the
//!   address check, the digest pin, undeclared-means-destructive and the
//!   one-round-trip rule all apply to it exactly as they apply to GitHub.
//!
//! # What this buys, and why it is not optional
//!
//! Every MCP server people actually ship is a stdio package. `crates/app/tests/
//! orizn.rs` measures the consequence on the one vendor this workspace knows
//! best: `https://visa.orizn.app/mcp` serves one tool of six and **ignores an
//! API key in every header form**, while the stdio package serves all six and
//! reads `ORIZN_API_KEY` out of its environment. So "connect your SaaS" for
//! that class of vendor is not a header, it is a process with a variable in it,
//! and the only documented answer today — the customer runs `supergateway`
//! themselves — is a deployment step in the middle of a five-minute onboarding.
//!
//! # The isolation boundary, mechanism by mechanism
//!
//! Listing what a bridge must never reach is worth nothing without saying by
//! *which* mechanism, so each row names one, and the rows we cannot enforce
//! from this crate say so instead of claiming a mechanism they do not have.
//!
//! | The bridge must not reach | Refused by |
//! |---|---|
//! | This server's environment — `DATABASE_URL`, `AGENTOS_MASTER_KEY`, every provider token | **The process is not ours.** Nothing on this path calls `Command::spawn`, so there is no tree to inherit; and [`BridgeSpec`] enumerates the environment it asks for, so inheritance is not expressible rather than merely not done — the type has no field a `std::env::vars()` could go in. |
//! | This server's filesystem | Same mechanism: nothing shares a mount namespace with a process we never create. The runtime is additionally required to give the bridge a read-only root and no bind mounts — a **deployment requirement**, listed below, not something this crate can check. |
//! | The database | Nothing in a [`BridgeSpec`] names it. The bridge network must not route to Postgres — a **deployment requirement**, and the reason [`BridgeNetwork`] is an operator's value rather than a default. |
//! | Another tenant's credential | **One bridge per (tenant, server)**, never shared — see [`BridgeSpec`]. The single secret in a bridge's environment is opened from that tenant's own `mcp_servers` row under the AAD `mcp://<tenant>/<server>` ([`crate::mcp::credential_context`]), so there is no second tenant's value in scope to leak. |
//! | Our internal network, *through us* | [`accept`]: a bridge endpoint must be an **IP literal** inside [`BridgeNetwork`], which is operator configuration and is empty by default — and the empty set refuses everything. |
//! | The cloud metadata endpoint, through us | [`crate::mcp::placement`] runs first and unchanged: `169.254.0.0/16` is `Forbidden` whatever the bridge network says. |
//!
//! # Why the endpoint is an address and never a name
//!
//! This is the question the whole design turns on: *a bridge sits on a private
//! address, and so does everything we are defending — how does a legitimate
//! bridge distinguish itself from an attempt to make us read our own network?*
//!
//! Not by its address class. `mcp::Reach::Private` already admits all of RFC
//! 1918, so "it is on 10/8" is a description of the attack as much as of the
//! bridge. Three things separate them, and they compose:
//!
//! 1. **Nobody outside this process names it.** A hosted binding stores no URL
//!    at all (`0043_mcp_hosted.sql` is the column becoming nullable); the
//!    endpoint is minted by the runtime, per start, and is never read back from
//!    a tenant-writable column. The SSRF question "what URL did the caller
//!    supply" has no answer on this path because there is no caller-supplied
//!    URL.
//! 2. **It is inside a range the operator wrote down.** [`BridgeNetwork`] is
//!    deployment configuration — the subnet the runtime puts bridges on. It
//!    intersects with `placement`, it never widens it, and an unset value is an
//!    empty set, which refuses every endpoint and turns hosting off. Read what
//!    it actually says, though: not "this is a bridge" but "this address is in
//!    the range you named", so the strength of the whole point is the strength
//!    of the range. A subnet that also holds a cache or an admin surface admits
//!    those too. That is deployment requirement 2 below, and it is a
//!    requirement rather than a check because nothing in this process can see
//!    what else lives on an operator's network.
//! 3. **It is an address, not a hostname.** A name is resolved twice — once
//!    when it is checked and once when it is dialled — and DNS is free to
//!    answer differently the second time. `crate::mcp`'s own docs flag that
//!    residual hole for ordinary bindings. Here it is closed rather than
//!    documented: [`accept`] refuses anything whose host is not an IPv4 or IPv6
//!    literal, so the value that was checked is the value that is dialled and
//!    there is no window between them. It costs the runtime nothing — it knows
//!    the address it just assigned.
//!
//! # The credential, and what happens at restart
//!
//! The tenant's key is stored exactly where a bearer token is stored — sealed
//! in `mcp_servers.sealed_token`, under the AAD from
//! [`crate::mcp::credential_context`] — and the difference is only where it
//! goes on the way out: into [`Package::env`] inside the bridge instead of into
//! an `Authorization` header. It is opened for one statement, by
//! [`crate::mcp::Credentials`], which is the only type in the workspace that
//! can, and it is handed to the runtime as a [`Secret`] that zeroizes when the
//! statement ends.
//!
//! Nothing persists it anywhere else. The runtime is required not to write it
//! to a manifest, a log or a disk, and the reason that requirement is cheap to
//! meet is the restart story: **a bridge that dies is not repaired, it is
//! replaced.** There is no state in a bridge worth keeping — an MCP server over
//! stdio is a request/response process — so the binder loop's next pass calls
//! [`BridgeRuntime::start`] again, the secret is opened again from the row, and
//! the
//! deployment's master key is the only thing that had to survive. A runtime
//! that persisted the plaintext would be storing a credential in a second place
//! to save work nobody needs done.
//!
//! # Lifecycle: one bridge per binding, and no stop verb
//!
//! **Per (tenant, server), never shared.** A bridge shared between two tenants
//! is a process holding two tenants' credentials in one environment, which is
//! the exact failure this module exists to prevent, arrived at from the other
//! direction — and the package reads its key from that environment, so sharing
//! is not a smaller boundary, it is the absence of one. The cost is real: idle
//! containers for tenants who are not working. That is the correct trade at
//! high ticket, where the number of tenants is small and the number of secrets
//! that must not meet is the whole product.
//!
//! **[`BridgeRuntime`] has one method, and stopping is not it.** The obvious
//! second method — `stop`, called when a binding is deleted — is a promise this
//! process cannot keep: it is exactly the call that does not happen when a
//! replica is killed mid-request, and a bridge that outlives its binding
//! because nobody was alive to say so is a container holding a credential with
//! no owner. So the contract is a **lease**: [`BridgeRuntime::start`] is
//! idempotent per (tenant, server, package), the binder loop in
//! `apps/server/src/routes/mcp.rs` calls it on every refresh tick, and a
//! runtime reaps a bridge nobody has asked for since its idle TTL expired.
//! Deleting a binding then stops the asking, and the
//! bridge goes away on its own, whether or not this process was there to see
//! it. One method, no reconciliation loop, and the failure mode of our crashing
//! is a container that expires rather than one that leaks.
//!
//! **The lease has a renewal period and it is a number in another crate.** That
//! sentence used to name an `IDLE_TTL` that exists nowhere in this workspace,
//! which made the whole argument above rest on a free variable. The renewal is
//! `REFRESH` in `apps/server/src/routes/mcp.rs` — **300 seconds** — because that
//! is the only thing that calls `start` on a schedule, and the requirement is an
//! inequality:
//!
//! > A runtime's idle TTL must be **strictly greater than `REFRESH`, with margin
//! > for missed ticks.** Fifteen minutes is the smallest defensible value: it
//! > survives two consecutive ticks lost to a slow bind, a restart or a
//! > rescheduled replica.
//!
//! Both directions of getting it wrong are real and neither is loud. A TTL
//! **below** 300 s reaps every bridge between ticks, so hosting flaps: each
//! refresh is a cold container start, the tenant's tools appear and disappear,
//! and the symptom at the top is an intermittent `hosting_unavailable` that
//! reproduces nowhere. A TTL far **above** it is the leak this design accepted
//! on purpose — a deleted binding's container holds that tenant's credential
//! until the TTL runs out — so the margin buys reliability and is paid for in
//! how long a revoked credential stays resident. Fifteen minutes is where those
//! two meet; a deployment that shortens `REFRESH` must shorten the TTL with it,
//! and the two numbers only make sense read together.
//!
//! # What this does NOT cover, said plainly
//!
//! * **The package's code.** Nobody here has read `orizn-visa-mcp`. Isolation
//!   bounds what it can touch of *ours*; it does not make it trustworthy. A
//!   hostile package holds the credential of the tenant who asked for it, and
//!   answers that tenant's tool calls — both by design, and neither is
//!   contained by any mechanism above.
//! * **Its egress.** A bridge needs the internet to be useful, so it has it, so
//!   it can post whatever it is given wherever it likes. The bound is that what
//!   it is given belongs to one tenant.
//! * **Version drift.** `npx -y foo` resolves a version at start. [`Package`]
//!   entries therefore pin an exact version, and a package that ignores its own
//!   lockfile is still fetching code nobody read.
//! * **A compromised runtime.** It holds every bridge's environment, so it is
//!   operator infrastructure with an operator's blast radius, and [`accept`]
//!   re-checks its answer for exactly that reason — a runtime that is wrong
//!   about an address still cannot point us at one.
//! * **What one bridge consumes.** CPU, memory and process limits are the
//!   runtime's; nothing here can bound them.
//! * **How many bridges a tenant gets, which is NOT the runtime's** and is the
//!   correction to the sentence that used to stand here. The runtime is
//!   *required* to start a second container for a second `(tenant, server)` —
//!   that is the isolation unit and refusing would break a legitimate second
//!   binding — so it has no basis on which to say no. The count is decided
//!   upstream, by how many rows a tenant has in `mcp_servers` on a hosted
//!   connector, and `server` is a slug the tenant chooses: **`0013_mcp.sql`
//!   caps nothing and no route counts.** For a dialled binding that is
//!   harmless, because a row is an address we connect to on demand. For a
//!   hosted one, every row is a container that the binder loop's refresh tick
//!   keeps alive indefinitely — the lease is renewed exactly as fast as it
//!   expires. Nothing today can create such a row (see the deployment section),
//!   which is the only reason this is a note and not a hole; a per-tenant cap
//!   on hosted bindings has to ship in the same change as the route that
//!   creates them, and is listed there.
//! * **The child this deployment already has.** "This process spawns nothing"
//!   is true of the MCP path and is *not* true of the binary:
//!   `crates/providers/src/llm_cli.rs` runs `claude` as a child when
//!   `AGENTOS_LLM=cli`, and it adds three environment variables without
//!   clearing the rest — so that child does see `DATABASE_URL` and
//!   `AGENTOS_MASTER_KEY`. It is a different trust class (a binary the
//!   *operator* named in deployment configuration, not a package a tenant
//!   asked for) and nothing here makes it worse, but a module claiming an
//!   isolation boundary must not let the reader infer one that is not there.
//!   Whether that spawn should scrub its environment is a question for whoever
//!   owns `llm_cli`, not for this file.
//!
//! # What has to be deployed before any of this runs
//!
//! Nothing in this module starts anything, and no implementation of
//! [`BridgeRuntime`] ships in this workspace. **Nor is there any wiring that
//! could hand one in**, and that is worth saying separately because the two
//! read alike and are not: `Fleet::bind`'s `bridges` argument is the literal
//! `None` at `apps/server/src/routes/mcp.rs`, which is its one production call
//! site; [`Bridges`] is constructed nowhere outside tests; and no environment
//! variable in this workspace feeds [`BridgeNetwork::parse`]. So [`accept`],
//! [`BridgeNetwork`] and [`Bridges`] are today reached only from tests —
//! everything they refuse, they refuse in a test. Until a runtime *and* its
//! wiring land, a hosted binding fails to bind with `hosting_unavailable` and
//! its tenant simply has no tools on it — the same fail-closed path as a server
//! that is down. What a deployment has to add:
//!
//! 1. **A bridge runtime**, reachable from this process, that starts a
//!    container per (tenant, server) from a pinned runner image, wraps the
//!    package's stdio in Streamable HTTP (`supergateway` is the off-the-shelf
//!    one, and is what `tests/orizn.rs` already runs), and answers with the
//!    address it assigned. Its container contract: read-only root, no bind
//!    mounts, an environment containing only [`BridgeSpec`]'s variables, a
//!    network with no route to Postgres or to this server's admin surface, an
//!    idle TTL satisfying the inequality above — and **a log stream that is
//!    dropped rather than shipped**. That last row is the one a container
//!    contract usually forgets: the package's own stdout and stderr are
//!    somebody else's code writing whatever it likes, a stdio MCP server prints
//!    diagnostics there by convention, and a package that echoes its
//!    environment on startup puts a *tenant's* credential into the operator's
//!    log aggregator — where it is durable, indexed, and outside every
//!    mechanism the table above names. "Do not persist the secret" was written
//!    for the runtime's own manifests and does not reach the child's file
//!    descriptors.
//! 2. **`BridgeNetwork`**, as the subnet that runtime allocates from, and the
//!    requirement is sharper than "where bridges live": **it must contain
//!    nothing but bridges.** [`accept`]'s guarantee is only ever as good as
//!    that, because what it authorises is not "this is a bridge" but "this
//!    address is inside the range you wrote down" — so a bridge subnet carved
//!    out of a shared VPC range, which is the ordinary way to deploy, hands a
//!    compromised runtime every neighbour in it: a cache, a broker, an internal
//!    admin surface. `placement` narrows that to private space and no further.
//!    A dedicated range is the mechanism; unset means hosting is off.
//! 3. **A transport to it that is not the public internet** — a unix socket or
//!    mTLS on the same private network — because the request carrying
//!    [`BridgeSpec`] carries a tenant's credential.
//! 4. **A per-tenant cap on hosted bindings, in the same change as the route
//!    that creates them.** `POST /v1/mcp/connect` answers `503
//!    hosting_unavailable` for a [`crate::catalog::Provision::Host`] connector
//!    today, so no tenant can create a hosted row at all — which is what makes
//!    the uncapped count above a note rather than a hole. Opening that branch
//!    without a cap turns a tenant-chosen slug into a container: `mcp_servers`
//!    is keyed `(tenant_id, server)`, nothing counts the rows, and the refresh
//!    tick renews every lease as fast as it expires. The cap belongs on the
//!    write, not on the bind — a refusal at bind time is a container already
//!    started.

use std::net::IpAddr;

use agentos_domain::ids::{Slug, TenantId};
use agentos_providers::Secret;
use async_trait::async_trait;
use url::{Host, Url};

use crate::mcp::{McpError, Placement, placement, vet_url};

/// One stdio MCP server we have agreed to run.
///
/// A `const`, exactly like [`crate::catalog::CATALOG`], and for the sharper
/// version of the same reason: this is the "allowlist of permitted programs"
/// `crate::mcp` says a stdio transport would need, so it is the configuration
/// and there is nothing left for a tenant to supply. There is no statement that
/// writes an array in a binary, so there is no privilege to withhold and no row
/// that can arrive malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Package {
    /// What the runner runs. **Pinned to an exact version**, because `npx -y
    /// foo` resolves whatever was published this morning, and the point of
    /// writing a program down is that it is the one that was written down.
    pub spec: &'static str,
    /// The environment variable the package reads its credential from, or
    /// `None` for a package that needs none.
    ///
    /// The *name* is ours and the *value* is the tenant's. Keeping the name in
    /// the binary rather than in a column is what makes the column boring: the
    /// row holds one sealed blob and nothing that says where it goes.
    pub env: Option<&'static str>,
}

/// One request to run one package for one tenant.
///
/// # The environment is enumerated, not inherited
///
/// This struct is the whole of what a bridge's environment may contain, and
/// that is a property of the type rather than a discipline: there is no field
/// here that could hold `std::env::vars()`, so the construction that leaks this
/// process's environment into a child cannot be written without changing this
/// declaration and having the change reviewed.
///
/// # The key is (tenant, server), and that is the isolation unit
///
/// Two tenants running the same package get two bridges. See the module docs
/// for why sharing one is not a smaller boundary but the absence of one.
pub struct BridgeSpec<'a> {
    /// Whose binding this is. Half of the runtime's idempotency key.
    pub tenant: TenantId,
    /// Which binding, within that tenant. The other half.
    pub server: &'a Slug,
    /// What to run.
    pub package: &'a Package,
    /// The value of [`Package::env`], opened for the length of one call.
    ///
    /// Borrowed rather than owned so the plaintext lives for the statement that
    /// starts the bridge and not for the length of anything else — the same
    /// shape as [`crate::mcp::McpServer::bind`]'s token parameter.
    pub secret: Option<&'a Secret>,
}

// Hand-written, and not derived even though `Secret`'s own `Debug` redacts.
// The rule this file has to keep is "a tenant's secret never appears in a log",
// and a derived impl keeps it only for as long as somebody else's type keeps
// theirs. This one prints whether there is a secret and never what it is, which
// is the same distinction `has_credential` draws on the HTTP surface.
impl std::fmt::Debug for BridgeSpec<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeSpec")
            .field("tenant", &self.tenant)
            .field("server", &self.server)
            .field("package", &self.package)
            .field("secret", &self.secret.map(|_| "<redacted>"))
            .finish()
    }
}

/// Why a bridge did not start.
///
/// **A code, not a sentence, and the type is most of what enforces it.** An
/// implementation cannot hand back a message built from its own internals
/// without going out of its way — `&'static str` takes a literal, and producing
/// one from a computed `String` means reaching for `Box::leak`, which is a line
/// nobody writes by accident and nobody misses at a review. That matters
/// because this ends up in [`crate::mcp::BindFailure::detail`], which
/// `apps/server` renders into a JSON response for whoever holds the tenant's
/// API key. Stable and low cardinality for the same reason
/// [`McpError::code`](crate::mcp::McpError::code) is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeError(pub &'static str);

/// The thing that runs a package somewhere this process cannot reach.
///
/// A trait with no production implementation in this workspace, which is
/// unusual here and is the point: the implementation is a piece of
/// infrastructure — a container runtime — and `crates/app` may not become one.
/// What lives here is the contract it has to satisfy, so that the day somebody
/// deploys one, the argument about what it must guarantee has already been had.
///
/// # The contract
///
/// * **Idempotent per (tenant, server, package).** Called again with the same
///   key and the same package, it returns the same bridge rather than starting
///   a second one. The binder loop calls it on every pass; a runtime that
///   started a container per call would grow one per five minutes per binding.
/// * **A different package under the same key replaces the bridge.** The
///   package is part of the identity, not an argument to it: a binding whose
///   connector changed is a different program, and it must not answer on a
///   process started for the previous one.
/// * **Leased, not stopped.** A bridge nobody has asked for within the
///   runtime's idle TTL is reaped by the runtime. See the module docs for why
///   there is no `stop` here.
/// * **The environment is exactly [`BridgeSpec`]'s.** One variable when
///   [`Package::env`] is set, none when it is not, plus whatever the runner
///   image needs for itself. Never this process's.
/// * **The answer is an address.** An `http://<ip>:<port>/<path>` URL on the
///   operator's bridge network. A hostname is refused by [`accept`], not
///   because a name is dishonest but because it is resolved twice.
#[async_trait]
pub trait BridgeRuntime: Send + Sync {
    /// Start (or find) the bridge for this spec and answer with its endpoint.
    async fn start(&self, spec: BridgeSpec<'_>) -> Result<String, BridgeError>;
}

/// The addresses an operator's bridges live on.
///
/// # Empty means refuse, and unset means empty
///
/// The workspace rule — a blank list is a denial, not a default — is load
/// bearing here rather than decorative: a deployment that has not been told
/// where bridges live is a deployment that cannot tell a bridge from anything
/// else on its private network, and the honest behaviour for it is to host
/// nothing at all.
///
/// # It only ever narrows
///
/// [`accept`] runs [`crate::mcp::placement`] first and requires
/// [`Placement::Private`] before this is consulted, so a network containing
/// `0.0.0.0/0` grants nothing: link-local, multicast, CGNAT and the whole
/// global internet are already refused by the time this is asked. The
/// intersection is the effective answer, which is the same direction every
/// other list in this system composes in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeNetwork(Vec<(IpAddr, u8)>);

impl BridgeNetwork {
    /// Parse `10.42.0.0/16,fd00:bridge::/64` — comma separated, whitespace
    /// tolerated, empty entries skipped.
    ///
    /// **Each entry must be the network address of its own prefix.**
    /// `10.42.0.7/16` is an error, not sixty-five thousand addresses, and the
    /// argument is at the check: the only way a typo here can hurt is by
    /// naming more than it spells, so the one reading that is never taken is
    /// the generous one.
    ///
    /// ponytail: hand-rolled prefix matching rather than the `ipnet` crate. Two
    /// comparisons over the octets of an address is less code than the
    /// dependency's own feature flags, and this is the only place in the
    /// workspace that needs it. The ceiling is that it understands prefixes and
    /// nothing else — no ranges, no exclusions — and the upgrade is `ipnet` the
    /// day an operator needs one of those.
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        let mut nets = Vec::new();
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (addr, bits) = entry.split_once('/').ok_or("expected <address>/<prefix>")?;
            let addr: IpAddr = addr.parse().map_err(|_| "not an ip address")?;
            let bits: u8 = bits.parse().map_err(|_| "not a prefix length")?;
            let width = if addr.is_ipv4() { 32 } else { 128 };
            if bits > width {
                return Err("prefix longer than the address family allows");
            }
            // **`10.42.0.7/16` is refused, not silently read as `10.42.0.0/16`.**
            //
            // Masking it would be the convenient reading and it is the one that
            // widens: the operator who typed that address meant one host, and
            // the value that would take effect covers sixty-five thousand of
            // them — every one of which `accept` would then agree to dial. It is
            // the same class of mistake as `/33` and gets the same treatment
            // this type already argues for: a typo in a network is a boot-time
            // error, because "empty means refuse" cannot save a list that
            // parsed into something bigger than what was written.
            if host_bits_set(addr, bits) {
                return Err("prefix has bits set below its length; write the network address");
            }
            nets.push((addr, bits));
        }
        Ok(Self(nets))
    }

    /// Whether any configured prefix covers this address. Always false when
    /// empty, which is the whole of the "unset means off" behaviour.
    fn covers(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|(net, bits)| prefix_eq(*net, ip, *bits))
    }
}

/// Whether `a` and `b` agree on their first `bits` bits, and are the same
/// family.
///
/// Byte-wise on the octets, so v4 and v6 go through one function: a v4 address
/// is four octets and a v6 is sixteen, and comparing a v4 to a v6 is a family
/// mismatch rather than a `::ffff:` coincidence — [`accept`] has already put
/// every IPv4-in-IPv6 spelling through `placement`, and a bridge network is
/// written in whichever family the operator's subnet actually is.
fn prefix_eq(a: IpAddr, b: IpAddr, bits: u8) -> bool {
    let (a, b) = (octets(a), octets(b));
    if a.len() != b.len() {
        return false;
    }
    let whole = usize::from(bits / 8);
    let rest = bits % 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    // The high `rest` bits of the next octet. `0xff << (8 - rest)` is the mask,
    // and `rest` is 1..=7 here so the shift cannot be 8.
    let mask = 0xffu8 << (8 - rest);
    a[whole] & mask == b[whole] & mask
}

/// The octets of an address, four or sixteen of them.
///
/// One function for both families, so every bit-level rule in this module reads
/// the same address the same way — the alternative is two spellings of the same
/// arithmetic that agree until one of them is edited.
fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Whether any bit at or below position `bits` is set — i.e. whether this
/// address is something other than the network address of its own prefix.
///
/// `bits` is `<= width` by the time this is called, so `whole` is in range when
/// `rest` is non-zero and is exactly `octets.len()` when `rest` is zero and the
/// prefix is the whole address, where the tail slice is empty and the answer is
/// `false`.
fn host_bits_set(ip: IpAddr, bits: u8) -> bool {
    let octets = octets(ip);
    let whole = usize::from(bits / 8);
    let rest = bits % 8;
    // The low `8 - rest` bits of the straddled octet, when there is one...
    if rest != 0 && octets[whole] & (0xffu8 >> rest) != 0 {
        return true;
    }
    // ...and every octet after it, which is all of them when `rest` is zero.
    octets[whole + usize::from(rest != 0)..]
        .iter()
        .any(|&byte| byte != 0)
}

/// A runtime, and the network its answers must land in.
///
/// # Why the two are one value
///
/// So that the check cannot be skipped. [`Bridges::endpoint`] is the only way
/// to reach the runtime from outside this module — the field is private and
/// there is no accessor — so "start a bridge" and "vet what it answered" are
/// one operation with no arrangement of the caller in which the second half is
/// forgotten. It is the same construction `crate::mcp::McpServer::bind` uses to
/// keep the address check attached to the connect.
pub struct Bridges {
    runtime: std::sync::Arc<dyn BridgeRuntime>,
    network: BridgeNetwork,
}

impl std::fmt::Debug for Bridges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridges")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl Bridges {
    /// Wire a runtime to the subnet it allocates from.
    pub const fn new(runtime: std::sync::Arc<dyn BridgeRuntime>, network: BridgeNetwork) -> Self {
        Self { runtime, network }
    }

    /// Start the bridge and vet the address it answered with.
    ///
    /// The only path from a [`BridgeSpec`] to a URL, and therefore the only
    /// place a runtime's answer becomes something this process will dial.
    pub(crate) async fn endpoint(&self, spec: BridgeSpec<'_>) -> Result<Url, McpError> {
        let endpoint = self
            .runtime
            .start(spec)
            .await
            .map_err(|BridgeError(code)| McpError::Hosting { code })?;
        accept(&endpoint, &self.network)
    }
}

/// Vet an endpoint a runtime just handed us.
///
/// Three refusals, in the order that makes the last one cheap:
///
/// 1. Not `http(s)` with a host — [`crate::mcp::vet_url`], the same function a
///    customer's own URL goes through.
/// 2. Not an IP **literal**. See the module docs: a name is checked once and
///    resolved again at connect time, and this is the one place where insisting
///    on an address costs nobody anything.
/// 3. Not [`Placement::Private`], or not inside the operator's
///    [`BridgeNetwork`]. Both, in that order: `placement` refuses link-local,
///    CGNAT, multicast and the global internet regardless of what the operator
///    wrote, and the network narrows what is left.
///
/// Public because it is the contract, and because a runtime implementation
/// living in another crate one day will want to assert against it.
pub fn accept(endpoint: &str, network: &BridgeNetwork) -> Result<Url, McpError> {
    let url = vet_url(endpoint).map_err(|_| McpError::Hosting {
        code: "bridge_endpoint_refused",
    })?;
    let ip = match url.host() {
        Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
        Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
        // A hostname, or no host at all. Refused: see the module docs for why
        // an address is the contract.
        _ => {
            return Err(McpError::Hosting {
                code: "bridge_endpoint_not_an_address",
            });
        }
    };
    if placement(ip) != Placement::Private || !network.covers(ip) {
        return Err(McpError::Hosting {
            code: "bridge_endpoint_refused",
        });
    }
    Ok(url)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A runtime that answers with whatever it was told to, and records what it
    /// was asked.
    ///
    /// The fake exists because the real one is infrastructure this workspace
    /// deliberately does not contain. What it can prove is everything on our
    /// side of the wire: that the spec carries one tenant's secret and no
    /// other, that the answer is vetted before it is dialled, and that a
    /// refusal is a skipped binding rather than an exception.
    pub(crate) struct FakeRuntime {
        /// What `start` answers with. A `Result` so a test can make the runtime
        /// itself fail.
        pub answer: Result<String, BridgeError>,
        /// Every spec it was handed, flattened to what a test can assert on —
        /// including the exposed secret, which is the only place in this
        /// workspace that is allowed to look, and is the only way to prove the
        /// right one arrived.
        pub seen: std::sync::Mutex<Vec<Started>>,
    }

    /// One remembered start: whose, which handle, which package, and the
    /// credential that went into its environment.
    pub(crate) type Started = (TenantId, String, &'static str, Option<String>);

    impl FakeRuntime {
        pub(crate) fn answering(endpoint: &str) -> Self {
            Self {
                answer: Ok(endpoint.to_owned()),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn failing(code: &'static str) -> Self {
            Self {
                answer: Err(BridgeError(code)),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl BridgeRuntime for FakeRuntime {
        async fn start(&self, spec: BridgeSpec<'_>) -> Result<String, BridgeError> {
            self.seen.lock().expect("not poisoned").push((
                spec.tenant,
                spec.server.as_str().to_owned(),
                spec.package.spec,
                spec.secret.map(|s| s.expose_for_transport().to_owned()),
            ));
            self.answer.clone()
        }
    }

    const PACKAGE: Package = Package {
        spec: "example-mcp@1.0.0",
        env: Some("EXAMPLE_API_KEY"),
    };

    fn net(raw: &str) -> BridgeNetwork {
        BridgeNetwork::parse(raw).expect("a valid network")
    }

    fn code(err: &McpError) -> &'static str {
        err.code()
    }

    /// **An empty network refuses every endpoint**, including one that is
    /// otherwise perfect. This is "le vide veut dire refus" and it is what makes
    /// an unconfigured deployment host nothing rather than host anything.
    #[test]
    fn an_unconfigured_network_refuses_everything() {
        let empty = BridgeNetwork::default();
        assert_eq!(empty, net(""), "an unset variable parses to the empty set");
        let refused = accept("http://10.42.0.7:8931/mcp", &empty)
            .expect_err("an unconfigured deployment hosts nothing, so it dials nothing");
        assert_eq!(code(&refused), "bridge_endpoint_refused");
        // The same address, with a network that names it, is accepted — so the
        // assertion above is about the network and not about the address.
        assert!(accept("http://10.42.0.7:8931/mcp", &net("10.42.0.0/16")).is_ok());
    }

    /// **A hostname is refused even when it resolves inside the network.**
    ///
    /// `localhost` resolves to `127.0.0.1`, which is `Placement::Private` and
    /// which the network below contains — so this is refused for the one reason
    /// that matters: the value that was checked has to be the value that is
    /// dialled, and a name is resolved twice.
    #[test]
    fn a_hostname_is_refused_however_well_it_resolves() {
        let network = net("127.0.0.0/8");
        assert!(accept("http://127.0.0.1:8931/mcp", &network).is_ok());
        let refused = accept("http://localhost:8931/mcp", &network)
            .expect_err("a name is checked once and resolved again, so it is not an endpoint");
        assert_eq!(code(&refused), "bridge_endpoint_not_an_address");
    }

    /// **`placement` runs first and the network cannot overrule it.**
    ///
    /// An operator who writes `0.0.0.0/0` — or, less absurdly, a cloud subnet in
    /// CGNAT space — does not thereby buy the metadata endpoint, the public
    /// internet, or anything else `mcp::placement` refuses. The two lists
    /// intersect; the lower one only narrows.
    #[test]
    fn the_operators_network_can_never_widen_placement() {
        let everything = net("0.0.0.0/0");
        for endpoint in [
            // The cloud credential endpoint: link-local, Forbidden.
            "http://169.254.169.254/mcp",
            // Carrier-grade NAT: Forbidden, and a real cloud subnet.
            "http://100.64.3.4:8931/mcp",
            // A globally routable address is not a bridge.
            "http://93.184.216.34:8931/mcp",
            // Unspecified.
            "http://0.0.0.0:8931/mcp",
        ] {
            let refused = accept(endpoint, &everything)
                .expect_err(&format!("{endpoint} must not be a bridge"));
            assert_eq!(code(&refused), "bridge_endpoint_refused", "{endpoint}");
        }
        // And the one thing 0.0.0.0/0 does admit is what `placement` already
        // called private, which is no wider than `Reach::Private`.
        assert!(accept("http://10.0.0.1:8931/mcp", &everything).is_ok());
    }

    /// A prefix that is not on an octet boundary still masks correctly, in both
    /// families.
    #[test]
    fn prefixes_mask_at_the_bit_and_not_the_byte() {
        let network = net("10.42.128.0/17, fd00:b::/48");
        assert!(accept("http://10.42.200.9:1/mcp", &network).is_ok());
        // 10.42.0.9 shares two octets and differs in the 17th bit.
        assert_eq!(
            code(
                &accept("http://10.42.0.9:1/mcp", &network)
                    .expect_err("10.42.0.9 is outside 10.42.128.0/17")
            ),
            "bridge_endpoint_refused"
        );
        assert!(accept("http://[fd00:b:0:1::5]:1/mcp", &network).is_ok());
        assert_eq!(
            code(
                &accept("http://[fd00:c::5]:1/mcp", &network)
                    .expect_err("fd00:c:: is outside fd00:b::/48")
            ),
            "bridge_endpoint_refused"
        );
    }

    /// A v4 address is never covered by a v6 prefix, or the reverse.
    #[test]
    fn families_do_not_cross() {
        assert_eq!(
            code(
                &accept("http://10.0.0.1:1/mcp", &net("fd00::/8"))
                    .expect_err("a v4 address is not inside a v6 prefix")
            ),
            "bridge_endpoint_refused"
        );
        assert_eq!(
            code(
                &accept("http://[fd00::1]:1/mcp", &net("10.0.0.0/8"))
                    .expect_err("a v6 address is not inside a v4 prefix")
            ),
            "bridge_endpoint_refused"
        );
    }

    /// Malformed configuration is a boot-time error, not a silently empty
    /// network — the one case where "empty means refuse" would hide a typo
    /// behind behaviour that looks deliberate.
    #[test]
    fn a_malformed_network_is_an_error_and_not_an_empty_one() {
        for raw in ["10.42.0.0", "10.42.0.0/33", "not-an-ip/8", "10.42.0.0/x"] {
            assert!(BridgeNetwork::parse(raw).is_err(), "{raw:?} parsed");
        }
        // **A prefix with host bits set is refused rather than masked**, and
        // this is the half that is about widening rather than about typos: each
        // of these, read as its network address, covers strictly more than what
        // was written, and `accept` would agree to dial every extra address.
        // The first two are the realistic mistake — a host address with the
        // subnet's prefix length on it, which is how an operator writes down
        // what `ip addr` printed.
        for raw in [
            "10.42.0.7/16",
            "10.42.128.9/17",
            // The one whose only set host bit is *inside* the straddled octet:
            // `192 & 0x7f` is `0x40`, and every octet after it is zero. Nothing
            // but the partial-octet half of `host_bits_set` catches this, which
            // is why it is written down separately from its neighbours.
            "10.42.192.0/17",
            "fd00:b::5/48",
            "10.0.0.1/0",
            "fd00::1/8",
        ] {
            assert!(
                BridgeNetwork::parse(raw).is_err(),
                "{raw:?} parsed, and it names more addresses than it spells"
            );
        }
        // The network address of each of those is accepted, so the refusals
        // above are about the host bits and not about the prefix length.
        for raw in [
            "10.42.0.0/16",
            "10.42.128.0/17",
            "fd00:b::/48",
            "0.0.0.0/0",
            "fd00::/8",
        ] {
            assert!(BridgeNetwork::parse(raw).is_ok(), "{raw:?} did not parse");
        }
        // A full-width prefix is the whole address and has no host bits, in
        // either family — the boundary `host_bits_set` indexes closest to.
        assert!(BridgeNetwork::parse("10.42.0.7/32").is_ok());
        assert!(BridgeNetwork::parse("fd00:b::5/128").is_ok());
        // Whitespace and empty entries are tolerated, because a comma-separated
        // environment variable is typed by a human.
        assert_eq!(
            BridgeNetwork::parse(" 10.0.0.0/8 , ,10.1.0.0/16").expect("parses"),
            net("10.0.0.0/8,10.1.0.0/16")
        );
    }

    /// **The runtime's answer is vetted before anything dials it**, and a
    /// runtime that answers with the database's address is refused exactly like
    /// a customer who typed it.
    #[tokio::test]
    async fn a_runtimes_answer_is_not_trusted() {
        let bridges = Bridges::new(
            std::sync::Arc::new(FakeRuntime::answering("http://169.254.169.254/mcp")),
            net("0.0.0.0/0"),
        );
        let server = Slug::parse("example").expect("a slug");
        let refused = bridges
            .endpoint(BridgeSpec {
                tenant: TenantId::new_v7(chrono::Utc::now()),
                server: &server,
                package: &PACKAGE,
                secret: None,
            })
            .await
            .expect_err("the metadata endpoint is not a bridge");
        assert_eq!(code(&refused), "bridge_endpoint_refused");
    }

    /// A runtime failure carries its code and nothing else.
    #[tokio::test]
    async fn a_runtime_failure_is_a_code() {
        let bridges = Bridges::new(
            std::sync::Arc::new(FakeRuntime::failing("bridge_image_missing")),
            net("10.0.0.0/8"),
        );
        let server = Slug::parse("example").expect("a slug");
        let refused = bridges
            .endpoint(BridgeSpec {
                tenant: TenantId::new_v7(chrono::Utc::now()),
                server: &server,
                package: &PACKAGE,
                secret: None,
            })
            .await
            .expect_err("the runtime said no");
        assert_eq!(code(&refused), "bridge_image_missing");
    }

    /// **A spec does not print the secret**, whoever holds it.
    ///
    /// The assertion is on the rendered bytes, not on which impl produced them,
    /// and that is deliberate: today *two* things keep this true — this module's
    /// hand-written `Debug` and `providers::Secret`'s own redaction — and the
    /// property has to survive either of them changing. Swapping this impl for a
    /// derived one would still pass, and should: what must never pass is the
    /// value appearing. `providers` losing its redaction is what this catches
    /// and what nothing else here would.
    #[test]
    fn a_spec_never_renders_its_secret() {
        let server = Slug::parse("example").expect("a slug");
        let secret = Secret::new("sk-live-do-not-print-me");
        let rendered = format!(
            "{:?}",
            BridgeSpec {
                tenant: TenantId::new_v7(chrono::Utc::now()),
                server: &server,
                package: &PACKAGE,
                secret: Some(&secret),
            }
        );
        assert!(
            !rendered.contains("sk-live"),
            "the secret is in the debug output: {rendered}"
        );
        assert!(rendered.contains("example-mcp@1.0.0"), "{rendered}");
    }

    /// Every package we have written down pins a version.
    ///
    /// Not style: `npx -y foo` fetches whatever was published this morning, so
    /// an unpinned entry is a program that changes without a deploy, which is
    /// the one property this file claims a `const` gives us.
    #[test]
    fn every_catalogued_package_pins_a_version() {
        for connector in crate::catalog::CATALOG {
            let crate::catalog::Provision::Host(package) = connector.provision else {
                continue;
            };
            assert!(
                package.spec.contains('@'),
                "{}: {:?} does not pin a version",
                connector.key,
                package.spec
            );
            // A credential that has nowhere to go, or a variable nobody fills,
            // are both configurations that look connected and are not.
            assert_eq!(
                package.env.is_some(),
                connector.credential != crate::catalog::Credential::None,
                "{}: the package's environment and the connector's credential disagree",
                connector.key
            );
        }
    }
}
