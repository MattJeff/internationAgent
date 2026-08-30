//! The container runtime `agentos_app::hosted` describes and deliberately does
//! not contain.
//!
//! [`hosted`](agentos_app::hosted) declares [`BridgeRuntime`] and then says, in
//! as many words, that no implementation belongs in `crates/app` because the
//! implementation is a piece of infrastructure. This is that piece. It lives in
//! the binary for the same reason the Postgres pool and the listener do: it is a
//! property of *this deployment* — which container runtime, which subnet, how
//! long a lease — and not of the system's logic. `crates/app` still cannot start
//! a process; it can only hand a [`BridgeSpec`] to something that can.
//!
//! # Why `docker` the command and not an API client
//!
//! One dependency was on the table (`bollard`, a typed client over the daemon's
//! unix socket) and it buys nothing this file needs. Five verbs are used here —
//! `ps`, `run`, `rm`, `port` is not even one of them — and each is one argv and
//! one line of output. What the socket client *would* add is a second way to be
//! wedged when the daemon is: a pooled connection with its own timeouts on top
//! of the ones below. `Command` with `kill_on_drop` and a hard timeout is the
//! shape that fails loudly, and a wedged daemon starving a machine is a thing
//! this workspace has already paid for once.
//!
//! # The address, and why the port is published rather than routed
//!
//! [`accept`](agentos_app::hosted::accept) requires an IP **literal** inside the
//! operator's [`BridgeNetwork`](agentos_app::hosted::BridgeNetwork), and the
//! module docs describe that as the container's own address on a bridge network.
//! This runtime publishes a port instead — `-p <bind>:0:<PORT>` — and hands back
//! `http://<bind>:<published>/mcp`.
//!
//! That is the same guarantee by a shorter route, and one that is true on every
//! host rather than on Linux only. A container's own address is not reachable
//! from the host on macOS at all, so a runtime that returned one would be a
//! runtime that works on the deploy box and cannot be run by the person who
//! wrote it. What the operator configures is one address — `MCP_BRIDGE_BIND` —
//! and `config` derives the admitted network as that address's own `/32`, so the
//! set of endpoints `accept` will take is exactly the set this runtime can
//! produce. A `/32` is the tightest network expressible and it is not a
//! coincidence: the two values used to be independent, and two settings that
//! must agree are one setting somebody eventually gets wrong.
//!
//! The isolation the module argues for is unchanged by the routing: the package
//! runs in its own container, with its own network namespace, with an
//! environment that has exactly the variables [`BridgeSpec`] carries.
//!
//! # Leases
//!
//! The contract says "leased, not stopped": a bridge nobody has asked for within
//! the idle TTL is reaped *by the runtime*, and there is no `stop` on the trait
//! because a caller that could stop one could stop a colleague's. Docker has no
//! TTL of its own, so the lease is a `HashMap` here: [`Containers::start`]
//! stamps a name on every answer and sweeps whatever has gone quiet. The binder
//! loop calls `start` on every pass, so a binding that still exists renews
//! itself and one whose row was deleted stops being renewed and goes.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use agentos_app::hosted::{BridgeError, BridgeRuntime, BridgeSpec};
use agentos_domain::ids::{Slug, TenantId};
use async_trait::async_trait;
use tokio::process::Command;

/// The port the runner listens on *inside* its container. Fixed, because it is
/// ours: the published port is what varies and the runtime asks Docker for it.
const PORT: u16 = 8000;

/// The path the runner serves Streamable HTTP on. Also ours, and also fixed.
const PATH: &str = "/mcp";

/// What marks a container as one of ours, for the sweep at startup.
const MARK: &str = "agentos.bridge=1";

/// What records which package a running container was started for, so a binding
/// whose connector changed is replaced rather than answered by the old program.
const PACKAGE_LABEL: &str = "agentos.package";

/// How long any one `docker` invocation may take before it is killed.
///
/// Not a tuning knob and not generous. Every command here is local IPC to a
/// daemon on the same machine; a `run` that pulls an image is the only one that
/// could legitimately take seconds, and the image is pulled once per host. What
/// this number is really sized for is the daemon being *wedged*, where the
/// honest behaviour is a bind that fails with a code and a loop that tries again
/// in five minutes — not a task parked forever on a socket read while the
/// binder's other tenants wait behind it.
const DOCKER_TIMEOUT: Duration = Duration::from_secs(90);

/// How long a bridge nobody has asked for survives.
///
/// A constant and not a variable, unlike the three things `config::Hosting`
/// holds, because it is not an operator's decision — it is a function of how
/// often the binder loop passes. `routes::mcp::REFRESH` is five minutes, so
/// anything under that reaps bridges the next pass would have renewed, and the
/// cost of a longer one is paid in the multiplier
/// `hosted::BRIDGES_PER_TENANT` documents: containers held ≈ cap × TTL ÷ pass
/// interval. Four passes is the smallest number that tolerates a slow pass
/// without holding a tenant's containers for an hour after they stop asking.
pub const IDLE: Duration = Duration::from_secs(20 * 60);

/// The default runner image: a Node runtime, nothing else.
///
/// The image is a plain `node` because the *program* is supplied per bridge —
/// `npx` fetches the package named in the catalogue — and an image built to hold
/// one package would be an image per catalogue entry, rebuilt on every pin bump.
/// An operator who wants the fetch to happen at build time instead of at start
/// time sets `MCP_BRIDGE_IMAGE` to their own image; the command below is what it
/// has to be able to run.
pub const DEFAULT_IMAGE: &str = "node:22-alpine";

/// The stdio-to-HTTP bridge, pinned like everything else this system runs.
///
/// `hosted::Package::spec` is pinned "because `npx -y foo` resolves whatever was
/// published this morning". The same sentence applies to the program doing the
/// resolving, and it is the more dangerous of the two: the package sees a
/// tenant's credential, the gateway sees every byte in both directions.
///
/// # It publishes no licence, and that is a decision somebody else's to make
///
/// `npm view supergateway license` is empty — npm renders that as
/// "Proprietary". It is the only npm package that does the transport this
/// contract needs (stdio → Streamable HTTP; `mcp-proxy` is MIT and speaks SSE),
/// so it is the default rather than the choice. **A deployment that will not
/// run an unlicensed program in front of its customers' MCP traffic sets
/// `MCP_BRIDGE_IMAGE` to an image with its own gateway**, which is the whole
/// reason that variable exists — the image is what supplies this program, and
/// this constant is only what the default image runs.
const GATEWAY: &str = "supergateway@3.4.3";

/// A `docker` on the host, and the bridges it is holding for us.
pub struct Containers {
    image: String,
    bind: IpAddr,
    idle: Duration,
    /// Container name → when `start` last answered for it. A `std::sync::Mutex`
    /// and not tokio's: every critical section below is a map lookup with no
    /// `.await` in it, and the `docker` calls happen outside the guard.
    leases: Mutex<HashMap<String, Instant>>,
}

impl Containers {
    /// Wire a runtime to the address it publishes on and the lease it keeps.
    pub fn new(image: String, bind: IpAddr, idle: Duration) -> Self {
        Self {
            image,
            bind,
            idle,
            leases: Mutex::new(HashMap::new()),
        }
    }

    /// Remove every container this build has ever started, and log what went.
    ///
    /// Called once at boot. A bridge outlives the process that started it —
    /// that is what "leased, not stopped" means — so a restart inherits
    /// containers whose leases are in a `HashMap` that no longer exists, and
    /// nothing would ever reap them. The next bind pass starts replacements
    /// under the same names anyway, so the cost of sweeping is one cold start
    /// per binding and the cost of not sweeping is a container per binding per
    /// deploy, forever.
    ///
    /// ponytail: one runtime per Docker daemon. Two servers sharing a host would
    /// have each one's boot kill the other's bridges — survivable (the next pass
    /// restarts them) but noisy. If that deployment ever exists, put an instance
    /// id in `MARK` and accept that a dead instance's orphans are cleaned by
    /// whoever inherits its id.
    pub async fn sweep(&self) {
        let Ok(listed) = self
            .docker(&["ps", "-aq", "--filter", &format!("label={MARK}")], None)
            .await
        else {
            tracing::warn!("bridge sweep could not list containers; none removed");
            return;
        };
        let ids: Vec<&str> = listed.split_whitespace().collect();
        if ids.is_empty() {
            return;
        }
        let mut argv = vec!["rm", "-f"];
        argv.extend_from_slice(&ids);
        match self.docker(&argv, None).await {
            Ok(_) => tracing::info!(count = ids.len(), "swept bridges left by a previous run"),
            Err(BridgeError(code)) => tracing::warn!(code, "bridge sweep failed"),
        }
    }

    /// The container name for one binding, and the runtime's idempotency key.
    ///
    /// `(tenant, server)` and nothing else, exactly as the trait requires. The
    /// package is deliberately *not* in the name: a binding whose connector
    /// changed must **replace** its bridge, and a package in the name would make
    /// it start a second one beside the first under a name nothing reaps.
    fn name(tenant: TenantId, server: &Slug) -> String {
        // `Slug` is `[a-z0-9-]`, 2–32, no leading or trailing hyphen, so this is
        // a valid Docker name and cannot be mistaken for a flag.
        format!("agentos-bridge-{}-{server}", tenant.as_uuid().simple())
    }

    /// Run one `docker` invocation to completion, or kill it.
    ///
    /// `env` is the one variable a package may receive. It is set on the *child
    /// docker CLI* and named — not valued — in the argv, so the plaintext is
    /// never an argument: `ps` on the host shows `-e ORIZN_API_KEY` and no
    /// value. It still reaches `docker inspect` on the resulting container,
    /// which is a property of every container runtime and the reason
    /// `hosted::transportable` exists rather than something this file can fix.
    async fn docker(
        &self,
        argv: &[&str],
        env: Option<(&str, &str)>,
    ) -> Result<String, BridgeError> {
        let mut command = Command::new("docker");
        command
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Inherited by nothing: the child is the CLI, and the CLI passes on
            // only what `-e` names. This is what keeps the *server's* secrets
            // out of the daemon call in the first place.
            .env_clear()
            // `docker` needs to find its socket and its config.
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .kill_on_drop(true);
        if let Some((name, value)) = env {
            command.env(name, value);
        }

        let finished = tokio::time::timeout(DOCKER_TIMEOUT, command.output()).await;
        let output = match finished {
            Err(_) => return Err(BridgeError("bridge_runtime_timeout")),
            // The daemon is not running, or `docker` is not on PATH. Distinct
            // from a command that ran and refused, because the operator's fix is
            // different.
            Ok(Err(_)) => return Err(BridgeError("bridge_runtime_unreachable")),
            Ok(Ok(output)) => output,
        };
        if !output.status.success() {
            // The stderr is logged and never returned: `BridgeError` is a code
            // that reaches a tenant's API response, and a daemon's message is
            // neither stable nor ours to forward.
            tracing::warn!(
                argv = ?argv.first(),
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "docker refused"
            );
            return Err(BridgeError("bridge_runtime_refused"));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Drop the containers nobody has asked for within the TTL.
    async fn reap(&self) {
        let expired: Vec<String> = {
            let mut leases = self.leases.lock().expect("bridge leases");
            let cutoff = Instant::now() - self.idle;
            let gone: Vec<String> = leases
                .iter()
                .filter(|(_, seen)| **seen < cutoff)
                .map(|(name, _)| name.clone())
                .collect();
            for name in &gone {
                leases.remove(name);
            }
            gone
        };
        for name in expired {
            // Dropped from the map first and unconditionally. A `rm` that fails
            // must not keep the lease alive, or a container Docker has already
            // lost would be renewed by this process forever.
            let _ = self.docker(&["rm", "-f", &name], None).await;
            tracing::info!(bridge = %name, "bridge lease expired");
        }
    }
}

/// The published host port for `PORT`, out of `docker ps --format {{.Ports}}`.
///
/// The field is a comma-separated list of `ip:host->container/proto`, and a
/// container may publish more than one thing. Written as a scan for our own
/// container port rather than a split-on-colon, because the IPv6 form
/// (`[::1]:54321->8000/tcp`) has colons in the address too.
fn published(ports: &str) -> Option<u16> {
    let suffix = format!("->{PORT}/tcp");
    ports
        .split(", ")
        .find_map(|entry| entry.strip_suffix(&suffix))
        .and_then(|address| address.rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
}

#[async_trait]
impl BridgeRuntime for Containers {
    async fn start(&self, spec: BridgeSpec<'_>) -> Result<String, BridgeError> {
        self.reap().await;

        let name = Self::name(spec.tenant, spec.server);
        // Through `SocketAddr` and not `format!("{ip}:{port}")`, because an IPv6
        // literal needs brackets in both places this string is built — the URL
        // `accept` parses and the `--publish` Docker parses — and `SocketAddr`'s
        // `Display` is the one that already knows.
        let endpoint = |port| format!("http://{}{PATH}", SocketAddr::new(self.bind, port));

        // Running, ours, and started for this package. `docker ps` lists only
        // running containers, and both filters are `AND`ed, so one command
        // answers all three questions and a `no` to any of them takes the same
        // branch: tear down whatever is there and start the right thing. A
        // stopped container, a container from a previous pin, and no container
        // at all are the same situation from here.
        let live = self
            .docker(
                &[
                    "ps",
                    "--filter",
                    &format!("name=^{name}$"),
                    "--filter",
                    &format!("label={PACKAGE_LABEL}={}", spec.package.spec),
                    "--format",
                    "{{.Ports}}",
                ],
                None,
            )
            .await?;
        if let Some(port) = published(&live) {
            self.leases
                .lock()
                .expect("bridge leases")
                .insert(name, Instant::now());
            return Ok(endpoint(port));
        }

        // Ignored: the usual answer is "no such container", which is the case
        // this is here to make idempotent.
        let _ = self.docker(&["rm", "-f", &name], None).await;

        let publish = format!("{}:{PORT}", SocketAddr::new(self.bind, 0));
        let package = format!("{PACKAGE_LABEL}={}", spec.package.spec);
        let port = PORT.to_string();
        let mut argv = vec![
            "run",
            "-d",
            "--name",
            &name,
            "--label",
            MARK,
            "--label",
            &package,
            "--publish",
            &publish,
            // The package is third-party code holding a tenant's credential.
            // None of this is speculative hardening: it is the difference
            // between "somebody else's program in a container" and "somebody
            // else's program". `npx` writes to its cache, so the filesystem is
            // not read-only; everything that does not need to be granted is not.
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "512m",
            "--pids-limit",
            "256",
            &self.image,
            "npx",
            "-y",
            GATEWAY,
            "--stdio",
        ];
        // The inner command, as one argument. `--stdio` takes a command line and
        // this is the whole of it; it is built here rather than interpolated
        // into a shell, so the pinned spec is one argv element and cannot become
        // two.
        let stdio = format!("npx -y {}", spec.package.spec);
        argv.push(&stdio);
        argv.extend_from_slice(&[
            "--outputTransport",
            "streamableHttp",
            "--port",
            &port,
            "--streamableHttpPath",
            PATH,
        ]);

        // `-e NAME`, never `-e NAME=value`: see `docker` above.
        let env = spec.package.env.map(|name| {
            (
                name,
                spec.secret
                    .map_or("", |secret| secret.expose_for_transport()),
            )
        });
        if let Some((name, _)) = env {
            argv.push("-e");
            argv.push(name);
        }
        self.docker(&argv, env).await?;

        // Docker picked the port; ask what it picked. A second command rather
        // than a guess, because `-p 0` is the only way to avoid two tenants
        // racing for one number and the answer is only knowable afterwards.
        let started = self
            .docker(
                &[
                    "ps",
                    "--filter",
                    &format!("name=^{name}$"),
                    "--format",
                    "{{.Ports}}",
                ],
                None,
            )
            .await?;
        let Some(port) = published(&started) else {
            // It started and is not publishing what we asked for, or it exited
            // between the two commands. Either way it is not a bridge, and
            // leaving it would leave a container no lease covers.
            let _ = self.docker(&["rm", "-f", &name], None).await;
            return Err(BridgeError("bridge_no_endpoint"));
        };
        self.leases
            .lock()
            .expect("bridge leases")
            .insert(name.clone(), Instant::now());
        tracing::info!(bridge = %name, package = spec.package.spec, "bridge started");
        Ok(endpoint(port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one piece of parsing on the path, against the shapes Docker actually
    /// prints. A wrong answer here is a bridge dialled on somebody else's port.
    #[test]
    fn published_reads_our_container_port_and_nothing_else() {
        assert_eq!(published("127.0.0.1:54321->8000/tcp"), Some(54321));
        // Multiple publications: ours is not first, and the other one is on a
        // port whose *host* side is the number we are looking for.
        assert_eq!(
            published("127.0.0.1:8000->9000/tcp, 127.0.0.1:49155->8000/tcp"),
            Some(49155)
        );
        // IPv6, which is why this is not a split on ':'.
        assert_eq!(published("[::1]:49160->8000/tcp"), Some(49160));
        // Nothing published, which is what a container that exited looks like.
        assert_eq!(published(""), None);
        // Published, but not the port we asked for.
        assert_eq!(published("127.0.0.1:49155->9000/tcp"), None);
        // UDP on our number is not our endpoint.
        assert_eq!(published("127.0.0.1:49155->8000/udp"), None);
    }

    /// `(tenant, server)` is the key the trait requires, and the package is not
    /// in it — see `Containers::name`.
    #[test]
    fn the_name_is_the_idempotency_key() {
        let tenant = TenantId::from_uuid(uuid::Uuid::nil());
        let server = Slug::parse("orizn-visa").expect("slug");
        let other = Slug::parse("github").expect("slug");

        assert_eq!(
            Containers::name(tenant, &server),
            Containers::name(tenant, &server)
        );
        assert_ne!(
            Containers::name(tenant, &server),
            Containers::name(tenant, &other)
        );
        assert!(Containers::name(tenant, &server).starts_with("agentos-bridge-"));
    }
}
