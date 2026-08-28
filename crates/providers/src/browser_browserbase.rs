//! The real [`BrowserProvider`] against Browserbase's HTTP API.
//!
//! The shape is [`crate::browser`]'s — this module only supplies the wire
//! calls. Four things about Browserbase are load-bearing, none of them are
//! guessable from the trait, and two of them contradict the obvious design.
//!
//! # There is no SDK, and none is needed
//!
//! Browserbase publishes no official Rust SDK (the `browserbase` crate on
//! crates.io is one release by a stranger and must not be depended on). From
//! Rust the whole surface this adapter needs is plain REST — `POST
//! /v1/contexts`, `POST /v1/sessions` — plus the CDP websocket URL the session
//! hands back. `reqwest` is the entire dependency.
//!
//! # Persistence lives in the CONTEXT; the SESSION is disposable
//!
//! A **context** is the durable thing: cookies, localStorage and saved logins
//! for one employee, stored by Browserbase and re-hydrated into whatever
//! browser runs next. A **session** is a running browser: hard-capped at six
//! hours, and *destroyed when the last CDP client disconnects*. So any design
//! that keeps a long-lived per-employee session is wrong — it will be reaped
//! under you, and it will be reaped for certain at the six-hour cap.
//!
//! Hence: **one persistent context per employee, one short session per task.**
//! [`BrowserProvider::ensure_context`] provisions the context (and is the thing
//! subject to the crate's reconcile-before-create contract);
//! [`BrowserbaseBrowser::act`] opens a session, runs the step and lets the
//! session go. Nothing about a session is cached in this struct — there is
//! nowhere in it to put one, on purpose.
//!
//! [`BrowserSession::user_data_dir`] is therefore always `None` here — see
//! [`BrowserbaseBrowser::session_for`]. That is not the "ephemeral, will not
//! stay logged in" case the trait warns about: the state persists, it just
//! persists over there instead of in a local profile directory.
//!
//! # Why this adapter is worth having at all
//!
//! Self-hosted Chrome cannot give you cheap multiplexing *and* persistent
//! identity at the same time. Persistence is bound to `--user-data-dir`, which
//! is a **process** argument: one profile, one running Chrome, so N employees
//! that stay logged in cost N browser processes. The cheap alternative inside
//! one process, CDP's `Target.createBrowserContext`, is incognito-shaped: it
//! gives isolation **without** persistence and is discarded with the browser.
//! You may pick one. Browserbase Contexts exist precisely to remove that
//! trade-off — persistent identity that is not welded to a local process — and
//! that removal is the whole reason to pay for this adapter instead of running
//! Chrome yourself.
//!
//! # Never rebuild the connect URL
//!
//! `POST /v1/sessions` returns a `connectUrl`. Use it **verbatim**. It carries
//! session routing and credentials that are not reconstructable from the
//! session id, and a hand-assembled `wss://…?apiKey=…&sessionId=…` will break
//! the day Browserbase changes its edge. Because that URL embeds the API key,
//! [`LiveSession`] keeps it as a [`Secret`]: it is as leakable as the key
//! itself.
//!
//! # What is deliberately not here: the CDP socket
//!
//! Driving the DOM means speaking CDP over a websocket, and none of that is in
//! *this file*. The seam is [`CdpDriver`]: the adapter owns the
//! Browserbase-shaped work (contexts, session lifecycle, secret hygiene) and
//! hands the verbatim connect URL to whoever owns the socket. Building
//! `Page.navigate` frames is Chrome knowledge, not Browserbase knowledge, and
//! belongs next to the socket that ships them.
//!
//! ponytail: one trait, one method — and the implementation is
//! [`crate::cdp::CdpWebsocket`], in this crate, over `tokio_tungstenite`.
//!
//! This note used to read "no in-tree implementation — a websocket dependency
//! is not on the table for this crate today. Delete [`CdpDriver`] and inline a
//! client the day one is." All three claims were overtaken the same afternoon
//! they were written, by the commit that added `cdp.rs`, and the instruction
//! is the wrong way round: the seam earned its keep rather than expiring.
//! `crate::mocks`' real adapter is handed a `CdpWebsocket` unconditionally, so
//! the trait's job now is the file split, not the missing client.

use std::sync::Arc;
use std::time::Duration;

use agentos_domain::ids::EmployeeId;
use async_trait::async_trait;
use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};

use crate::browser::{BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep};

/// Hard ceiling on one request to Browserbase, connect included.
///
/// `reqwest::Client::new()` has **no request timeout**, and until this constant
/// existed neither did this adapter. That is not a latency preference, it is
/// what bounds a turn: `Turn::attempt` races the *model* call against its
/// cancellation token and nothing races an effect, so a provider that never
/// answers is a turn that never ends. On the inbound path that turn runs inside
/// the outbox handler's tenant transaction — so the wedge is an open Postgres
/// transaction and a pooled connection held indefinitely, while the lease
/// expires and a second poller re-runs the same turn.
///
/// 60 seconds, and generous on purpose: this is a backstop against a hung
/// socket, not a service-level objective. A vendor that is merely slow should
/// still succeed; one that has stopped answering should stop costing us a
/// connection. `agentos_app::mcp::CALL_TIMEOUT` makes the same argument at the
/// same value, and `peer_keys::FETCH_TIMEOUT` is two seconds because a key
/// directory is on a request path and this is not.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
use crate::{
    EnsureCtx, ProviderBinding, ProviderError, Provisioned, RELEASE_NOT_SUPPORTED, Secret,
};

/// Adapter identity, recorded on every [`Provisioned`] this module returns.
pub const PROVIDER: &str = "browserbase";

/// Browserbase's public API root.
pub const API_ROOT: &str = "https://api.browserbase.com";

/// Header Browserbase authenticates on.
const API_KEY_HEADER: &str = "X-BB-API-Key";

/// Ceiling on a single API call. Generous: session creation cold-starts a
/// browser. A blown deadline is [`ProviderError::Retryable`], never terminal.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// The CDP seam
// ---------------------------------------------------------------------------

/// Runs one [`BrowserStep`] over a CDP websocket.
///
/// The implementation receives the `connectUrl` **exactly** as Browserbase
/// returned it and must connect to that string without editing it. It is a
/// [`Secret`] because it contains the account API key.
#[async_trait]
pub trait CdpDriver: Send + Sync {
    /// Connect, run the step, return what it produced.
    async fn run(
        &self,
        connect_url: &Secret,
        step: &BrowserStep<'_>,
    ) -> Result<BrowserOutcome, ProviderError>;
}

// ---------------------------------------------------------------------------
// A running session
// ---------------------------------------------------------------------------

/// A browser Browserbase started for us, and the URL to drive it.
///
/// Short-lived by construction: it dies with the last CDP client and in any
/// case at the six-hour cap. Do not stash one.
#[derive(Debug)]
pub struct LiveSession {
    /// Browserbase's session id, for logs and for the release call.
    pub id: String,
    /// The `connectUrl`, verbatim. Secret: it embeds the API key.
    connect_url: Secret,
}

impl LiveSession {
    /// The connect URL exactly as the provider returned it.
    pub fn connect_url(&self) -> &Secret {
        &self.connect_url
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Contexts and sessions against the real Browserbase API.
pub struct BrowserbaseBrowser {
    http: Client,
    base: String,
    project_id: String,
    api_key: Secret,
    timeout: Duration,
    cdp: Option<Arc<dyn CdpDriver>>,
}

/// Hand-written so the key cannot be printed even by accident, and so the
/// struct stays `Debug` despite the `dyn` driver.
impl std::fmt::Debug for BrowserbaseBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserbaseBrowser")
            .field("base", &self.base)
            .field("project_id", &self.project_id)
            .field("api_key", &self.api_key)
            .field("timeout", &self.timeout)
            .field("cdp", &self.cdp.is_some())
            .finish()
    }
}

impl BrowserbaseBrowser {
    /// A client for one Browserbase project.
    pub fn new(project_id: impl Into<String>, api_key: &str) -> Self {
        Self {
            // Built rather than `new()`: see `REQUEST_TIMEOUT`. `build` fails
            // only if the TLS backend cannot be initialised, at which point
            // nothing else in this process works either.
            http: Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base: API_ROOT.to_owned(),
            project_id: project_id.into(),
            api_key: Secret::new(api_key),
            timeout: DEFAULT_TIMEOUT,
            cdp: None,
        }
    }

    /// Point the client at another origin: a test server, or a proxy.
    #[must_use]
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base = base.into().trim_end_matches('/').to_owned();
        self
    }

    /// Override the per-request deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Supply the thing that can actually speak CDP. Without it
    /// [`BrowserProvider::act`] is `Terminal { code: "no_cdp_driver" }` —
    /// [`BrowserbaseBrowser::open_session`] still works, so a caller with its
    /// own client can drive the connect URL itself.
    #[must_use]
    pub fn with_cdp(mut self, cdp: Arc<dyn CdpDriver>) -> Self {
        self.cdp = Some(cdp);
        self
    }

    /// Pair an employee with a provisioned context.
    ///
    /// `user_data_dir` is `None` and must stay that way: the login state lives
    /// in the Browserbase context, not in a local profile directory.
    pub fn session_for(employee_id: EmployeeId, context: &Provisioned) -> BrowserSession {
        BrowserSession {
            employee_id,
            binding: context.binding(),
            user_data_dir: None,
        }
    }

    /// Send, authenticate, and classify anything that is not a 2xx.
    async fn call(&self, request: RequestBuilder) -> Result<Value, ProviderError> {
        let response = request
            .header(API_KEY_HEADER, self.api_key.expose_for_transport())
            .timeout(self.timeout)
            .send()
            .await
            // Connect failure, TLS failure, deadline: the request may even have
            // landed, which is exactly what reconcile-before-create covers.
            // None of them are the caller's fault, so none of them are terminal.
            .map_err(|_| ProviderError::timeout())?;

        let status = response.status().as_u16();
        // Read the header before the body: `json()` consumes the response.
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let body: Value = response.json().await.unwrap_or(Value::Null);

        if (200..300).contains(&status) {
            return Ok(body);
        }
        // Provider text is never interpolated into the error: a 401 body can
        // quote the key back at us.
        Err(ProviderError::from_status(status, retry_after))
    }

    /// Step 1 of the reconcile contract: is a context already carrying this
    /// idempotency key in its name?
    async fn find_context(&self, tag: &str) -> Result<Option<String>, ProviderError> {
        let body = self
            .call(
                self.http
                    .get(format!("{}/v1/contexts", self.base))
                    .query(&[("projectId", self.project_id.as_str())]),
            )
            .await?;

        // Accept both framings the API has shipped: `{"contexts": [...]}` and a
        // bare array.
        let items = body["contexts"]
            .as_array()
            .or_else(|| body.as_array())
            .map(Vec::as_slice)
            .unwrap_or_default();

        let mut hits = items
            .iter()
            .filter(|context| context["name"].as_str() == Some(tag));
        let first = hits
            .next()
            .and_then(|context| context["id"].as_str())
            .map(str::to_owned);
        if hits.next().is_some() {
            // Two contexts wearing one key means an older adapter created one
            // without reconciling. Papering over it splits the employee's login
            // state across two stores, at random.
            return Err(ProviderError::Terminal {
                code: "duplicate_context",
            });
        }
        Ok(first)
    }

    /// Start a browser on top of an employee's context.
    ///
    /// Public because the connect URL is the handoff point for a caller that
    /// brings its own CDP client. The session is disposable: release it, or
    /// just disconnect.
    pub async fn open_session(
        &self,
        session: &BrowserSession,
    ) -> Result<LiveSession, ProviderError> {
        let body = self
            .call(
                self.http
                    .post(format!("{}/v1/sessions", self.base))
                    .json(&json!({
                        "projectId": self.project_id,
                        "browserSettings": {
                            "context": {
                                "id": session.binding.external_id,
                                // Write the cookies back when the session ends.
                                // Without this the context is read-only and the
                                // employee is logged out again next task.
                                "persist": true,
                            },
                        },
                    })),
            )
            .await?;

        let connect_url = body["connectUrl"].as_str().ok_or(ProviderError::Terminal {
            code: "no_connect_url",
        })?;
        Ok(LiveSession {
            id: body["id"].as_str().unwrap_or_default().to_owned(),
            // Verbatim. Never rebuilt from the id.
            connect_url: Secret::new(connect_url),
        })
    }

    /// Ask Browserbase to stop paying for a session now.
    async fn close_session(&self, id: &str) -> Result<(), ProviderError> {
        self.call(
            self.http
                .post(format!("{}/v1/sessions/{id}", self.base))
                .json(&json!({ "projectId": self.project_id, "status": "REQUEST_RELEASE" })),
        )
        .await
        .map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

#[async_trait]
impl BrowserProvider for BrowserbaseBrowser {
    async fn ensure_context(&self, ctx: &EnsureCtx) -> Result<Provisioned, ProviderError> {
        // 0. What a previous run persisted needs no round trip at all.
        if let Some(existing) = &ctx.existing
            && existing.provider == PROVIDER
        {
            return Ok(Provisioned::new(PROVIDER, existing.external_id.clone()));
        }
        // 1. Reconcile on the tag we stamp into the context name.
        if let Some(id) = self.find_context(ctx.tag()).await? {
            return Ok(Provisioned::new(PROVIDER, id));
        }
        // 2. Only then create, stamping the same tag the lookup reads.
        let created = self
            .call(
                self.http
                    .post(format!("{}/v1/contexts", self.base))
                    .json(&json!({ "projectId": self.project_id, "name": ctx.tag() })),
            )
            .await?;

        created["id"]
            .as_str()
            .map(|id| Provisioned::new(PROVIDER, id))
            .ok_or(ProviderError::Terminal {
                code: "no_context_id",
            })
    }

    async fn act(
        &self,
        session: &BrowserSession,
        step: BrowserStep<'_>,
    ) -> Result<BrowserOutcome, ProviderError> {
        let cdp = self.cdp.as_ref().ok_or(ProviderError::Terminal {
            code: "no_cdp_driver",
        })?;

        // A session per act, and no field to keep one in. Sessions die with the
        // socket and at the six-hour cap, so a cached one is a handle to a
        // browser that is already gone; the login state we actually care about
        // is in the context and survives regardless.
        //
        // ponytail: one session per step is the honest reading of a trait whose
        // unit is a step. Batch a whole plan into one session the day a
        // `run(&[BrowserStep])` exists to hang it on.
        let live = self.open_session(session).await?;
        let outcome = cdp.run(&live.connect_url, &step).await;
        // Best effort: the session is dead as soon as the driver disconnects
        // anyway, so a failure here changes nothing about the step's result.
        let _ = self.close_session(&live.id).await;
        outcome
    }

    async fn release(&self, binding: &ProviderBinding) -> Result<(), ProviderError> {
        match self
            .call(
                self.http
                    .delete(format!("{}/v1/contexts/{}", self.base, binding.external_id)),
            )
            .await
        {
            Ok(_) => Ok(()),
            // Already gone is the state we asked for. Reporting it as a failure
            // would strand the binding.
            Err(error) if error.code() == "not_found" => Ok(()),
            // 405/501: this account's API has no context delete. The context is
            // still there and still billed, so say so instead of returning
            // `Ok(())` — the binding has to stay put for someone to find.
            Err(ProviderError::Terminal {
                code: "client_error",
            }) => Err(ProviderError::Terminal {
                code: RELEASE_NOT_SUPPORTED,
            }),
            Err(other) => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use agentos_domain::ids::{Slug, TenantId};
    use chrono::{DateTime, Utc};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use url::Url;

    use super::*;

    const PROJECT: &str = "proj_test";
    const KEY: &str = "bb_live_sup3r-secret";
    const T0: i64 = 1_700_000_000;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    // -- a fake Browserbase, on a loopback port -----------------------------
    //
    // Not a mock of our own client: it speaks HTTP/1.1 and reads the real JSON
    // bodies, so if the adapter stops stamping the tag into `name` the tests
    // fail. No account, no network, no key.

    #[derive(Default)]
    struct FakeState {
        /// (id, name) of every context that actually exists.
        contexts: Vec<(String, String)>,
        /// Context creates that reached the wire.
        creates: usize,
        /// Session ids handed out, oldest first.
        sessions: Vec<String>,
        /// Session ids the adapter asked to release.
        released: Vec<String>,
        /// Answer the next request with this status instead of doing the work.
        next_status: Option<u16>,
        /// Accept the request and never answer it.
        hang: bool,
        /// Every `X-BB-API-Key` we were sent.
        keys: Vec<String>,
    }

    struct FakeBrowserbase {
        base: String,
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeBrowserbase {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr: SocketAddr = listener.local_addr().expect("addr");
            let state = Arc::new(Mutex::new(FakeState::default()));

            let served = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let state = Arc::clone(&served);
                    tokio::spawn(async move { serve(stream, state).await });
                }
            });

            Self {
                base: format!("http://{addr}"),
                state,
            }
        }

        fn client(&self) -> BrowserbaseBrowser {
            BrowserbaseBrowser::new(PROJECT, KEY)
                .with_base_url(&self.base)
                // Short: one test deliberately waits for it.
                .with_timeout(Duration::from_millis(200))
        }

        fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state.lock().expect("fake state mutex poisoned")
        }
    }

    /// The `connectUrl` this fake hands out: opaque, signed, and impossible to
    /// rebuild from the session id. Any adapter that assembles its own URL
    /// produces something else, and the assertion catches it.
    fn connect_url(session: &str) -> String {
        format!(
            "wss://connect.edge-7.browserbase.invalid/v1/{session}?apiKey={KEY}&signature=opaque-abc123"
        )
    }

    async fn serve(mut stream: TcpStream, state: Arc<Mutex<FakeState>>) {
        let mut buffer = Vec::new();
        while let Some(request) = read_request(&mut stream, &mut buffer).await {
            let answered = {
                let mut state = state.lock().expect("fake state mutex poisoned");
                state.keys.push(request.api_key.clone());
                match (state.hang, state.next_status.take()) {
                    (true, _) => None,
                    (false, Some(status)) => {
                        Some((status, json!({"error": "injected", "status": status})))
                    }
                    (false, None) => Some(answer(&request, &mut state)),
                }
            };
            // Accept the request and never answer it: the adapter's own
            // deadline has to be what ends this.
            let Some((status, body)) = answered else {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            };
            if stream.write_all(&respond(status, &body)).await.is_err() {
                return;
            }
        }
    }

    fn answer(request: &Request, state: &mut FakeState) -> (u16, Value) {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/v1/contexts") => {
                let hits: Vec<Value> = state
                    .contexts
                    .iter()
                    .map(|(id, name)| json!({"id": id, "name": name}))
                    .collect();
                (200, json!({ "contexts": hits }))
            }
            ("POST", "/v1/contexts") => {
                state.creates += 1;
                let id = format!("ctx_{}", state.contexts.len() + 1);
                let name = request.body["name"].as_str().unwrap_or_default().to_owned();
                state.contexts.push((id.clone(), name.clone()));
                (201, json!({"id": id, "name": name}))
            }
            ("DELETE", path) if path.starts_with("/v1/contexts/") => {
                let id = path.trim_start_matches("/v1/contexts/").to_owned();
                let before = state.contexts.len();
                state.contexts.retain(|(have, _)| *have != id);
                if state.contexts.len() == before {
                    return (404, json!({"error": "not found"}));
                }
                // The real API answers 204. This fake speaks a single framing —
                // status, Content-Length, body — and a 204 carrying one is
                // malformed HTTP that breaks the next request on the same
                // connection. Every 2xx takes the identical path in the
                // adapter, which never reads this body.
                (200, json!({}))
            }
            ("POST", "/v1/sessions") => {
                // The context has to be named, and named with something that
                // exists: a session on a context id we never issued is the bug
                // "rebuild the URL yourself" leads to.
                let context = request.body["browserSettings"]["context"]["id"]
                    .as_str()
                    .unwrap_or_default();
                if !state.contexts.iter().any(|(id, _)| id == context) {
                    return (400, json!({"error": "unknown context"}));
                }
                let id = format!("sess_{}", state.sessions.len() + 1);
                state.sessions.push(id.clone());
                (
                    201,
                    json!({
                        "id": id,
                        "status": "RUNNING",
                        "connectUrl": connect_url(&id),
                    }),
                )
            }
            ("POST", path) if path.starts_with("/v1/sessions/") => {
                let id = path.trim_start_matches("/v1/sessions/").to_owned();
                state.released.push(id);
                (200, json!({"status": "REQUEST_RELEASE"}))
            }
            _ => (404, json!({"error": "not found"})),
        }
    }

    fn respond(status: u16, body: &Value) -> Vec<u8> {
        let body = serde_json::to_vec(body).expect("serialize");
        // The only header any assertion depends on.
        let extra = if status == 429 {
            "Retry-After: 7\r\n"
        } else {
            ""
        };
        let mut out = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(&body);
        out
    }

    struct Request {
        method: String,
        path: String,
        body: Value,
        api_key: String,
    }

    /// One HTTP/1.1 request, or `None` when the peer went away.
    async fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Request> {
        loop {
            if let Some(head_end) = find(buffer, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
                let mut lines = head.lines();
                let mut start_line = lines.next()?.split(' ');
                let method = start_line.next()?.to_owned();
                let target = start_line.next()?.to_owned();

                let mut length = 0;
                let mut api_key = String::new();
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    let value = value.trim();
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.parse().unwrap_or(0);
                    } else if name.eq_ignore_ascii_case(API_KEY_HEADER) {
                        api_key = value.to_owned();
                    }
                }

                let body_start = head_end + 4;
                if buffer.len() >= body_start + length {
                    let raw = buffer[body_start..body_start + length].to_vec();
                    buffer.drain(..body_start + length);
                    let path = target.split('?').next().unwrap_or(&target).to_owned();
                    return Some(Request {
                        method,
                        path,
                        body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
                        api_key,
                    });
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

    // -- a CDP driver that only records -------------------------------------

    #[derive(Default)]
    struct RecordingCdp {
        /// The connect URL exactly as the adapter passed it, per call.
        urls: Mutex<Vec<String>>,
        /// Where the tab is. A driver that answers `Location` with `Done` is a
        /// driver `app::effects` refuses every step through, so the contract
        /// suite makes even a recorder keep this.
        here: Mutex<Option<Url>>,
    }

    impl RecordingCdp {
        fn urls(&self) -> Vec<String> {
            self.urls.lock().expect("recorder mutex poisoned").clone()
        }
    }

    #[async_trait]
    impl CdpDriver for RecordingCdp {
        async fn run(
            &self,
            connect_url: &Secret,
            step: &BrowserStep<'_>,
        ) -> Result<BrowserOutcome, ProviderError> {
            self.urls
                .lock()
                .expect("recorder mutex poisoned")
                .push(connect_url.expose_for_transport().to_owned());
            Ok(match step {
                BrowserStep::Goto(url) => {
                    *self.here.lock().expect("recorder mutex poisoned") = Some((*url).clone());
                    BrowserOutcome::Navigated((*url).clone())
                }
                BrowserStep::Location => BrowserOutcome::Navigated(
                    self.here
                        .lock()
                        .expect("recorder mutex poisoned")
                        .clone()
                        .unwrap_or_else(crate::browser::blank_page),
                ),
                _ => BrowserOutcome::Done,
            })
        }
    }

    // -- fixtures ------------------------------------------------------------

    fn ctx() -> EnsureCtx {
        EnsureCtx::new(
            TenantId::new_v7(at(T0)),
            EmployeeId::new_v7(at(T0)),
            Slug::parse("ada").expect("slug"),
            "browser",
        )
    }

    fn session(context: &Provisioned) -> BrowserSession {
        BrowserbaseBrowser::session_for(EmployeeId::new_v7(at(T0)), context)
    }

    // -- the shared contract -------------------------------------------------

    /// The real client held to the same assertions the mock passes.
    ///
    /// Hermetic: a loopback fake Browserbase plus [`RecordingCdp`], so no
    /// browser starts and no session is billed. The CDP driver is supplied
    /// because `act` without one is `Terminal { code: "no_cdp_driver" }` — a
    /// contract run against half an adapter proves half a contract.
    #[tokio::test]
    async fn the_real_client_satisfies_the_contract() {
        let fake = FakeBrowserbase::start().await;
        let client = fake
            .client()
            .with_cdp(Arc::new(RecordingCdp::default()) as Arc<dyn CdpDriver>);

        crate::browser::contract_suite(&client).await;

        let state = fake.state();
        assert_eq!(state.creates, 1, "reconcile bought a second context");
        assert!(
            state.contexts.is_empty(),
            "the contract releases what it made"
        );
        // Every `act` opens its own session and gives it back; the contract
        // drives two steps — the navigation, and the question about where it
        // landed that `app::effects` asks before every step it did not itself
        // navigate. **That is a session per question**, which is this adapter's
        // shape and is what the guard costs on it: see `Effects::browse_write`.
        assert_eq!(state.sessions.len(), 2);
        assert_eq!(state.released, state.sessions);
    }

    // -- reconcile before create ---------------------------------------------

    #[tokio::test]
    async fn ensure_context_twice_creates_exactly_one_context() {
        let fake = FakeBrowserbase::start().await;
        let client = fake.client();
        let ctx = ctx();

        let first = client.ensure_context(&ctx).await.expect("first create");
        // The retry rebuilds the identical key: the lookup on `name` has to
        // find what the first attempt already created.
        let second = client
            .ensure_context(&ctx.clone().retry())
            .await
            .expect("reconciled");

        assert_eq!(first, second);
        assert_eq!(first.provider, PROVIDER);
        assert_eq!(first.external_id, "ctx_1");
        assert_eq!(fake.state().contexts.len(), 1, "created a second context");
        assert_eq!(fake.state().creates, 1, "posted a second create");
        // And the tag we searched on is the one we stamped.
        assert_eq!(fake.state().contexts[0].1, ctx.tag());
    }

    #[tokio::test]
    async fn a_persisted_binding_short_circuits_the_lookup() {
        let fake = FakeBrowserbase::start().await;
        let client = fake.client();

        let known = ProviderBinding {
            provider: PROVIDER.to_owned(),
            external_id: "ctx_from_last_run".to_owned(),
        };
        let out = client
            .ensure_context(&ctx().with_existing(known.clone()))
            .await
            .expect("honour what we persisted");

        assert_eq!(out.external_id, known.external_id);
        assert_eq!(fake.state().creates, 0);
        assert!(fake.state().keys.is_empty(), "no round trip was needed");
    }

    #[tokio::test]
    async fn two_contexts_wearing_one_key_is_terminal() {
        let fake = FakeBrowserbase::start().await;
        let ctx = ctx();
        fake.state()
            .contexts
            .push(("ctx_1".to_owned(), ctx.tag().to_owned()));
        fake.state()
            .contexts
            .push(("ctx_2".to_owned(), ctx.tag().to_owned()));

        let error = fake
            .client()
            .ensure_context(&ctx)
            .await
            .expect_err("a duplicate must not be papered over");
        assert_eq!(error.code(), "duplicate_context");
        assert!(!error.is_retryable());
    }

    // -- sessions are disposable ---------------------------------------------

    #[tokio::test]
    async fn the_connect_url_is_used_verbatim_and_never_rebuilt() {
        let fake = FakeBrowserbase::start().await;
        let recorder = Arc::new(RecordingCdp::default());
        let client = fake
            .client()
            .with_cdp(Arc::clone(&recorder) as Arc<dyn CdpDriver>);

        let context = client.ensure_context(&ctx()).await.expect("context");
        let url = Url::parse("https://portal.example.com/login").expect("url");
        let outcome = client
            .act(&session(&context), BrowserStep::Goto(&url))
            .await
            .expect("goto");

        assert_eq!(outcome, BrowserOutcome::Navigated(url));
        assert_eq!(
            recorder.urls(),
            vec![connect_url("sess_1")],
            "the adapter edited or rebuilt the connect URL"
        );
    }

    /// The session is infrastructure with a six-hour cap that dies with its
    /// socket. Every act gets a fresh one, and none of them is kept.
    #[tokio::test]
    async fn every_act_opens_its_own_session_and_gives_it_back() {
        let fake = FakeBrowserbase::start().await;
        let recorder = Arc::new(RecordingCdp::default());
        let client = fake
            .client()
            .with_cdp(Arc::clone(&recorder) as Arc<dyn CdpDriver>);

        let context = client.ensure_context(&ctx()).await.expect("context");
        let live = session(&context);
        assert_eq!(
            live.user_data_dir, None,
            "persistence belongs to the context, not to a local profile dir"
        );

        for _ in 0..2 {
            client
                .act(&live, BrowserStep::Click("#next"))
                .await
                .expect("click");
        }

        assert_eq!(
            fake.state().sessions,
            vec!["sess_1".to_owned(), "sess_2".to_owned()],
            "a session was cached and reused past its lifetime"
        );
        assert_eq!(
            fake.state().released,
            vec!["sess_1".to_owned(), "sess_2".to_owned()],
            "sessions were left running"
        );
        // Two sessions, two distinct connect URLs, each taken from its own
        // create response.
        assert_eq!(
            recorder.urls(),
            vec![connect_url("sess_1"), connect_url("sess_2")]
        );
    }

    #[tokio::test]
    async fn acting_without_a_driver_is_terminal_and_starts_nothing() {
        let fake = FakeBrowserbase::start().await;
        let client = fake.client();
        let context = client.ensure_context(&ctx()).await.expect("context");

        let error = client
            .act(&session(&context), BrowserStep::Screenshot)
            .await
            .expect_err("no driver, no DOM");
        assert_eq!(error.code(), "no_cdp_driver");
        assert!(
            fake.state().sessions.is_empty(),
            "paid for a browser anyway"
        );
    }

    // -- failure mapping ------------------------------------------------------

    #[tokio::test]
    async fn a_429_is_rate_limited_with_the_providers_own_backoff() {
        let fake = FakeBrowserbase::start().await;
        fake.state().next_status = Some(429);

        let error = fake
            .client()
            .ensure_context(&ctx())
            .await
            .expect_err("throttled");
        assert_eq!(
            error,
            ProviderError::RateLimited {
                retry_after: Duration::from_secs(7)
            }
        );
        assert!(error.is_retryable());
        assert_eq!(fake.state().creates, 0);
    }

    #[tokio::test]
    async fn a_4xx_is_terminal() {
        let fake = FakeBrowserbase::start().await;

        for (status, code) in [(401, "unauthorized"), (400, "bad_request")] {
            fake.state().next_status = Some(status);
            let error = fake
                .client()
                .ensure_context(&ctx())
                .await
                .expect_err("rejected");
            assert_eq!(error.code(), code);
            assert!(!error.is_retryable(), "retrying a {status} makes it worse");
        }
    }

    #[tokio::test]
    async fn a_5xx_is_retryable() {
        let fake = FakeBrowserbase::start().await;
        fake.state().next_status = Some(503);

        let error = fake
            .client()
            .ensure_context(&ctx())
            .await
            .expect_err("unavailable");
        assert!(error.is_retryable());
        assert!(matches!(error, ProviderError::Retryable { .. }));
    }

    /// A blown deadline is the crash window reconcile-before-create exists for:
    /// the context may already exist over there. Calling it terminal abandons
    /// a healthy provider mid-run and strands whatever it created.
    #[tokio::test]
    async fn a_timeout_is_retryable_and_never_terminal() {
        let fake = FakeBrowserbase::start().await;
        fake.state().hang = true;

        let error = fake
            .client()
            .ensure_context(&ctx())
            .await
            .expect_err("nobody answered");
        assert!(
            matches!(error, ProviderError::Retryable { .. }),
            "{error:?}"
        );
        assert!(error.is_retryable());
        assert_eq!(error.code(), "retryable");
    }

    // -- release --------------------------------------------------------------

    #[tokio::test]
    async fn releasing_a_context_deletes_it_and_repeats_safely() {
        let fake = FakeBrowserbase::start().await;
        let client = fake.client();
        let context = client.ensure_context(&ctx()).await.expect("context");
        assert_eq!(fake.state().contexts.len(), 1);

        client.release(&context.binding()).await.expect("released");
        assert_eq!(fake.state().contexts.len(), 0);
        client
            .release(&context.binding())
            .await
            .expect("already gone is the state we asked for");
        client
            .release(&ProviderBinding {
                provider: PROVIDER.to_owned(),
                external_id: "ctx_never_existed".to_owned(),
            })
            .await
            .expect("and so is never having existed");
    }

    /// If the account cannot delete contexts, the resource is still there and
    /// still billed. `Ok(())` would clear the binding and lose it forever.
    #[tokio::test]
    async fn a_refused_delete_is_reported_not_swallowed() {
        let fake = FakeBrowserbase::start().await;
        fake.state().next_status = Some(405);

        let error = fake
            .client()
            .release(&ProviderBinding {
                provider: PROVIDER.to_owned(),
                external_id: "ctx_1".to_owned(),
            })
            .await
            .expect_err("the context still exists");
        assert_eq!(error.code(), RELEASE_NOT_SUPPORTED);
    }

    // -- secret hygiene --------------------------------------------------------

    #[tokio::test]
    async fn the_api_key_never_appears_in_debug_or_error_output() {
        let fake = FakeBrowserbase::start().await;
        let client = fake.client();
        let context = client.ensure_context(&ctx()).await.expect("context");
        let live = client
            .open_session(&session(&context))
            .await
            .expect("session");

        // The key really is being sent, so the assertions below are not vacuous.
        assert!(fake.state().keys.iter().all(|sent| sent == KEY));
        // And the connect URL really does embed it.
        assert!(live.connect_url().expose_for_transport().contains(KEY));

        let mut rendered = vec![format!("{client:?}"), format!("{live:?}")];
        fake.state().next_status = Some(401);
        let error = client
            .ensure_context(&ctx().retry())
            .await
            .expect_err("rejected");
        rendered.push(format!("{error:?}"));
        rendered.push(format!("{error}"));

        for output in rendered {
            assert!(!output.contains(KEY), "leaked the api key: {output}");
            assert!(!output.contains("bb_live"), "leaked a key prefix: {output}");
        }
        assert!(format!("{client:?}").contains(Secret::REDACTED));
        assert!(format!("{live:?}").contains(Secret::REDACTED));
    }
}
