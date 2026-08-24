//! A real [`CdpDriver`]: Chrome DevTools Protocol over a websocket.
//!
//! [`crate::browser_browserbase`] owns the Browserbase-shaped work and hands us
//! a verbatim `connectUrl`. This module owns the socket and the Chrome
//! knowledge, and nothing else. It implements the smallest slice of CDP that
//! [`BrowserStep`] needs — `Page.navigate`, `Page.captureScreenshot`,
//! `Runtime.evaluate`, `Runtime.callFunctionOn` — and no general CDP client.
//!
//! # Frames are answered out of order
//!
//! CDP is JSON-RPC: `{"id":N,"method":…,"params":…}` out, and back either
//! `{"id":N,"result":…}`, `{"id":N,"error":…}`, or an unsolicited
//! `{"method":…,"params":…}` event with no `id` at all. Chrome interleaves
//! events with answers and is free to answer a later `id` first. So
//! [`Cdp::call`] **matches on `id`** and drops everything else on the floor. A
//! driver that reads one frame and assumes it is the answer passes every test
//! written against a polite fake and corrupts results under load.
//!
//! # Where the credential goes
//!
//! [`BrowserStep::Fill`] carries a [`Secret`], and the obvious implementation —
//! interpolate it into a `Runtime.evaluate` expression — puts the password into
//! the one field of a CDP frame that anybody would reasonably print when
//! debugging. So [`Cdp::fill`] does it in two calls instead: `Runtime.evaluate`
//! resolves the field to a remote `objectId` using an expression built only from
//! the selector, then `Runtime.callFunctionOn` passes the plaintext as
//! `arguments[0].value` of a function whose *body* only ever names the parameter
//! `v`. The plaintext exists in exactly one place, the `arguments` array of one
//! outbound frame, and in nothing this crate builds a string out of.
//!
//! The same reasoning covers the connect URL, which embeds the account API key:
//! it is exposed inside the [`connect_async`] call expression and nowhere else,
//! and no error from this module carries provider text — [`ProviderError`] codes
//! are `&'static str`, so there is nothing to leak into.
//!
//! # Failure classification
//!
//! Transport, EOF and both deadlines are [`ProviderError::Retryable`] and never
//! terminal: the browser is disposable and the session is reopened from scratch,
//! so a retry is always the right move. A CDP `error` response is
//! [`ProviderError::Terminal`] — Chrome understood us and said no.
//!
//! # ponytail: a hand-pumped tungstenite instead of `WebSocketStream`
//!
//! `tokio_tungstenite::WebSocketStream` is driven through `Stream`/`Sink`, whose
//! traits this crate cannot name (no `futures-util` dependency, and adding one
//! for two method calls is not worth it). So we take the socket
//! [`connect_async`] already negotiated TLS and the HTTP upgrade on, and drive
//! the *synchronous* `tungstenite::WebSocket` over it through [`Pipe`], a
//! byte buffer that reports `WouldBlock` when empty — the non-blocking mode
//! tungstenite is explicitly built for. Framing, masking, ping/pong and close
//! stay tungstenite's problem. Delete all of it the day `futures-util` is on the
//! dependency list.

use std::io;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocket};
use tokio_tungstenite::{MaybeTlsStream, connect_async};
use url::Url;

use crate::browser::{BrowserOutcome, BrowserStep};
use crate::browser_browserbase::CdpDriver;
use crate::{ProviderError, Secret};

// ---------------------------------------------------------------------------
// Terminal codes
// ---------------------------------------------------------------------------

/// Chrome answered our command with an `error` object.
pub const CDP_ERROR: &str = "cdp_error";
/// Chrome answered, but not with the shape the command documents.
pub const CDP_PROTOCOL: &str = "cdp_protocol";
/// The selector matched nothing in the live document.
pub const NO_SUCH_ELEMENT: &str = "no_such_element";
/// The injected expression threw.
pub const SCRIPT_FAILED: &str = "script_failed";
/// `Page.navigate` came back with an `errorText`.
pub const NAVIGATION_FAILED: &str = "navigation_failed";

/// Ceiling on the websocket handshake, TLS included.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Ceiling on one CDP command, from writing the frame to matching its `id`.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything a `Fill` does to the field, with the credential as an argument
/// rather than as source text. `this` is the element `callFunctionOn` targets.
const FILL_FN: &str = "function (v) { this.focus(); this.value = v; \
     this.dispatchEvent(new Event('input', { bubbles: true })); \
     this.dispatchEvent(new Event('change', { bubbles: true })); return true; }";

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// Drives one [`BrowserStep`] over one CDP websocket, then hangs up.
///
/// Holds no socket and no session: a connection lives exactly as long as
/// [`CdpDriver::run`], which is the lifetime a Browserbase session has anyway.
#[derive(Debug, Clone)]
pub struct CdpWebsocket {
    connect_timeout: Duration,
    command_timeout: Duration,
}

impl Default for CdpWebsocket {
    fn default() -> Self {
        Self::new()
    }
}

impl CdpWebsocket {
    /// A driver with the default deadlines.
    pub fn new() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
        }
    }

    /// Override the handshake deadline.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the per-command deadline.
    #[must_use]
    pub fn with_command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// Open the socket the connect URL points at.
    async fn connect(
        &self,
        connect_url: &Secret,
    ) -> Result<Cdp<MaybeTlsStream<TcpStream>>, ProviderError> {
        // The URL is exposed straight into the handshake call and bound to no
        // name that outlives this expression.
        let attempt = tokio::time::timeout(
            self.connect_timeout,
            connect_async(connect_url.expose_for_transport()),
        )
        .await;

        let stream = match attempt {
            // Deadline: dropping the future here drops the half-open socket,
            // which is what closes it.
            Err(_) => return Err(ProviderError::timeout()),
            // tungstenite's error Display quotes the request URL, so the error
            // value is dropped rather than mapped through anything that
            // formats it.
            Ok(Err(_)) => return Err(ProviderError::timeout()),
            Ok(Ok((stream, _response))) => stream,
        };

        // `into_inner` gives back the TCP/TLS stream with the upgrade already
        // done. It also discards whatever tungstenite may have read past the
        // 101 — which is nothing: a fresh CDP connection with no domain enabled
        // produces no events until we send the first command, and we enable no
        // domains.
        Ok(Cdp {
            conn: WsConn::client(stream.into_inner()),
            next_id: 0,
            deadline: self.command_timeout,
        })
    }
}

#[async_trait]
impl CdpDriver for CdpWebsocket {
    async fn run(
        &self,
        connect_url: &Secret,
        step: &BrowserStep<'_>,
    ) -> Result<BrowserOutcome, ProviderError> {
        let mut cdp = self.connect(connect_url).await?;
        let outcome = cdp.step(step).await;
        // Hang up politely whatever happened. Browserbase reaps the session
        // when the last CDP client disconnects, so a failed close costs
        // nothing; a leaked socket costs a browser.
        let _ = cdp.conn.close().await;
        outcome
    }
}

// ---------------------------------------------------------------------------
// One connection's worth of CDP
// ---------------------------------------------------------------------------

/// A connected CDP endpoint with a monotonic request id.
struct Cdp<S> {
    conn: WsConn<S>,
    next_id: u64,
    deadline: Duration,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Cdp<S> {
    /// Run one step.
    async fn step(&mut self, step: &BrowserStep<'_>) -> Result<BrowserOutcome, ProviderError> {
        match step {
            BrowserStep::Goto(url) => self.goto(url).await,
            BrowserStep::Click(sel) => {
                let js = format!(
                    "(() => {{ const e = document.querySelector({}); \
                     if (!e) return false; e.click(); return true; }})()",
                    js_string(sel)
                );
                self.expect_hit(js).await
            }
            // Visible text, so unlike a `Fill` it may live in the expression.
            BrowserStep::Type { sel, text } => {
                let js = format!(
                    "(() => {{ const e = document.querySelector({}); if (!e) return false; \
                     e.focus(); e.value = {}; \
                     e.dispatchEvent(new Event('input', {{ bubbles: true }})); \
                     e.dispatchEvent(new Event('change', {{ bubbles: true }})); return true; }})()",
                    js_string(sel),
                    js_string(text)
                );
                self.expect_hit(js).await
            }
            BrowserStep::Fill { sel, secret } => self.fill(sel, secret).await,
            BrowserStep::Screenshot => self.screenshot().await,
        }
    }

    /// Navigate, then read back where we actually ended up.
    ///
    /// `Page.navigate` reports the frame, not the address, and the trait asks
    /// for the URL *after* redirects — so the second call is the answer, not a
    /// nicety. If it comes back unparseable we fall back to what was asked for
    /// rather than failing a navigation that succeeded.
    async fn goto(&mut self, url: &Url) -> Result<BrowserOutcome, ProviderError> {
        let nav = self
            .call("Page.navigate", json!({ "url": url.as_str() }))
            .await?;
        if !nav["errorText"].is_null() {
            return Err(ProviderError::Terminal {
                code: NAVIGATION_FAILED,
            });
        }
        let here = self.evaluate("location.href".to_owned()).await?;
        let landed = here
            .as_str()
            .and_then(|href| Url::parse(href).ok())
            .unwrap_or_else(|| url.clone());
        Ok(BrowserOutcome::Navigated(landed))
    }

    /// Type a credential into a field without ever putting it in a string we
    /// build.
    async fn fill(&mut self, sel: &str, secret: &Secret) -> Result<BrowserOutcome, ProviderError> {
        // 1. Resolve the field. The expression is selector-only, and is the
        //    part of this exchange that is safe to print.
        let found = self
            .call(
                "Runtime.evaluate",
                json!({ "expression": format!("document.querySelector({})", js_string(sel)) }),
            )
            .await?;
        let object_id = found["result"]["objectId"]
            .as_str()
            .ok_or(ProviderError::Terminal {
                code: NO_SUCH_ELEMENT,
            })?
            .to_owned();

        // 2. Hand the plaintext over as an *argument*. `FILL_FN` names it `v`;
        //    the credential appears only in `arguments[0].value` of this one
        //    frame, on its way to the DOM, and in nothing that is formatted,
        //    traced or returned.
        self.call(
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": FILL_FN,
                "arguments": [{ "value": secret.expose_for_transport() }],
                "returnByValue": true,
            }),
        )
        .await?;
        Ok(BrowserOutcome::Done)
    }

    /// PNG bytes of the viewport.
    async fn screenshot(&mut self) -> Result<BrowserOutcome, ProviderError> {
        let shot = self
            .call("Page.captureScreenshot", json!({ "format": "png" }))
            .await?;
        let png = shot["data"]
            .as_str()
            .and_then(|data| BASE64.decode(data).ok())
            .ok_or(ProviderError::Terminal { code: CDP_PROTOCOL })?;
        Ok(BrowserOutcome::Screenshot(png))
    }

    /// Run an expression that returns `true` on success and `false` when the
    /// selector matched nothing.
    async fn expect_hit(&mut self, expression: String) -> Result<BrowserOutcome, ProviderError> {
        match self.evaluate(expression).await? {
            Value::Bool(true) => Ok(BrowserOutcome::Done),
            _ => Err(ProviderError::Terminal {
                code: NO_SUCH_ELEMENT,
            }),
        }
    }

    /// `Runtime.evaluate`, unwrapped to the returned value.
    async fn evaluate(&mut self, expression: String) -> Result<Value, ProviderError> {
        let out = self
            .call(
                "Runtime.evaluate",
                json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                }),
            )
            .await?;
        if !out["exceptionDetails"].is_null() {
            // Deliberately not carrying the exception text: it is page content,
            // and `Terminal::code` is a metric label.
            return Err(ProviderError::Terminal {
                code: SCRIPT_FAILED,
            });
        }
        Ok(out["result"]["value"].clone())
    }

    /// One JSON-RPC round trip, bounded, answered by `id`.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, ProviderError> {
        let deadline = self.deadline;
        match tokio::time::timeout(deadline, self.call_inner(method, params)).await {
            Ok(result) => result,
            // A wedged browser must not hold a worker forever, and a blown
            // deadline is never the caller's fault.
            Err(_) => Err(ProviderError::timeout()),
        }
    }

    async fn call_inner(&mut self, method: &str, params: Value) -> Result<Value, ProviderError> {
        self.next_id += 1;
        let id = self.next_id;
        // `params` can carry a credential (see `fill`), so the frame goes to
        // the socket and to no logger.
        let frame = json!({ "id": id, "method": method, "params": params }).to_string();
        tracing::debug!(target: "agentos::cdp", method, id, "cdp command");

        self.conn
            .send(Message::text(frame))
            .await
            .map_err(|_| ProviderError::timeout())?;

        loop {
            let text = match self.conn.recv().await {
                Ok(Message::Text(text)) => text,
                // The peer hung up mid-command: the session is gone, and a
                // fresh one is one retry away.
                Ok(Message::Close(_)) | Err(_) => return Err(ProviderError::timeout()),
                // Binary frames, and pings tungstenite already answered.
                Ok(_) => continue,
            };
            let Ok(value) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            // The whole point: an event has no `id`, and another command's
            // answer has someone else's. Neither is ours.
            if value["id"].as_u64() != Some(id) {
                continue;
            }
            if !value["error"].is_null() {
                return Err(ProviderError::Terminal { code: CDP_ERROR });
            }
            return Ok(value["result"].clone());
        }
    }
}

/// A JS string literal for `value`. JSON string syntax is a subset of JS's, so
/// this is the escaping, not an approximation of it.
fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

// ---------------------------------------------------------------------------
// Async plumbing under a synchronous tungstenite
// ---------------------------------------------------------------------------

/// The "socket" tungstenite thinks it has: a byte buffer in each direction.
///
/// Reads report `WouldBlock` when drained, which is tungstenite's non-blocking
/// contract; writes always succeed into `outbox` and are pushed to the real
/// socket by [`WsConn::drain`].
#[derive(Debug, Default)]
struct Pipe {
    inbox: Vec<u8>,
    read_pos: usize,
    outbox: Vec<u8>,
}

impl io::Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = &self.inbox[self.read_pos..];
        if available.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.read_pos += n;
        Ok(n)
    }
}

impl io::Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbox.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Push whatever tungstenite queued out to the real socket.
async fn drain_pipe<S: AsyncWrite + Unpin>(pipe: &mut Pipe, io: &mut S) -> io::Result<()> {
    if pipe.outbox.is_empty() {
        return Ok(());
    }
    let out = std::mem::take(&mut pipe.outbox);
    io.write_all(&out).await?;
    io.flush().await
}

/// Wait for more bytes from the real socket and give them to tungstenite.
async fn fill_pipe<S: AsyncRead + Unpin>(pipe: &mut Pipe, io: &mut S) -> io::Result<()> {
    let mut chunk = [0_u8; 8192];
    let n = io.read(&mut chunk).await?;
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    // Drop what tungstenite already consumed, so a long-lived connection does
    // not grow a buffer forever.
    pipe.inbox.drain(..pipe.read_pos);
    pipe.read_pos = 0;
    pipe.inbox.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// A websocket message loop: a synchronous tungstenite plus the async socket
/// its [`Pipe`] is pumped from.
struct WsConn<S> {
    ws: WebSocket<Pipe>,
    io: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsConn<S> {
    /// Adopt a stream whose handshake is already done.
    fn client(io: S) -> Self {
        Self {
            ws: WebSocket::from_raw_socket(Pipe::default(), Role::Client, None),
            io,
        }
    }

    async fn send(&mut self, message: Message) -> io::Result<()> {
        self.ws.send(message).map_err(io::Error::other)?;
        self.drain().await
    }

    async fn recv(&mut self) -> io::Result<Message> {
        loop {
            match self.ws.read() {
                Ok(message) => {
                    // A read can queue a pong or a close echo.
                    self.drain().await?;
                    return Ok(message);
                }
                Err(tokio_tungstenite::tungstenite::Error::Io(e))
                    if e.kind() == io::ErrorKind::WouldBlock =>
                {
                    self.drain().await?;
                    self.fill().await?;
                }
                Err(e) => return Err(io::Error::other(e)),
            }
        }
    }

    /// Send a close frame and shut the write half down, so the peer sees the
    /// disconnect immediately instead of at its own idle timeout.
    async fn close(&mut self) -> io::Result<()> {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
        self.drain().await?;
        self.io.shutdown().await
    }

    async fn drain(&mut self) -> io::Result<()> {
        drain_pipe(self.ws.get_mut(), &mut self.io).await
    }

    async fn fill(&mut self) -> io::Result<()> {
        fill_pipe(self.ws.get_mut(), &mut self.io).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::handshake::HandshakeError;

    use super::*;
    use crate::browser::BrowserProvider as _;
    use crate::browser_browserbase::BrowserbaseBrowser;

    const PASSWORD: &str = "hunter2-correct-horse";
    const API_KEY: &str = "bb_live_sup3r-secret";

    // -- a fake Chrome on a loopback port ------------------------------------
    //
    // A real websocket server: real handshake, real frames. `script` turns each
    // request into the frames to answer with, so a test can reorder them, add
    // events, or answer nothing at all. No network, no Browserbase, no key.

    type Script = Arc<dyn Fn(&Value) -> Vec<Value> + Send + Sync>;

    struct FakeChrome {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Value>>>,
        hung_up: Arc<Mutex<bool>>,
    }

    impl FakeChrome {
        async fn start(script: impl Fn(&Value) -> Vec<Value> + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let hung_up = Arc::new(Mutex::new(false));

            let script: Script = Arc::new(script);
            let (seen_task, hung_task) = (Arc::clone(&seen), Arc::clone(&hung_up));
            tokio::spawn(async move {
                while let Ok((io, _)) = listener.accept().await {
                    let script = Arc::clone(&script);
                    let seen = Arc::clone(&seen_task);
                    let hung_up = Arc::clone(&hung_task);
                    tokio::spawn(async move { serve(io, script, seen, hung_up).await });
                }
            });

            Self {
                addr,
                seen,
                hung_up,
            }
        }

        /// A connect URL shaped like Browserbase's: opaque, and carrying the key.
        fn connect_url(&self) -> Secret {
            Secret::new(format!(
                "ws://{}/v1/sess_1?apiKey={API_KEY}&signature=opaque-abc123",
                self.addr
            ))
        }

        fn seen(&self) -> Vec<Value> {
            self.seen.lock().expect("seen mutex poisoned").clone()
        }

        fn hung_up(&self) -> bool {
            *self.hung_up.lock().expect("hangup mutex poisoned")
        }
    }

    async fn serve(
        mut io: tokio::net::TcpStream,
        script: Script,
        seen: Arc<Mutex<Vec<Value>>>,
        hung_up: Arc<Mutex<bool>>,
    ) {
        // The server side of the same hand-pumped tungstenite the driver uses.
        let mut attempt = tokio_tungstenite::tungstenite::accept(Pipe::default());
        let mut conn = loop {
            match attempt {
                Ok(ws) => break WsConn { ws, io },
                Err(HandshakeError::Interrupted(mut mid)) => {
                    let pipe = mid.get_mut().get_mut();
                    if drain_pipe(pipe, &mut io).await.is_err() {
                        return;
                    }
                    if fill_pipe(pipe, &mut io).await.is_err() {
                        return;
                    }
                    attempt = mid.handshake();
                }
                Err(HandshakeError::Failure(_)) => return,
            }
        };
        // The 101 response tungstenite queued while we were holding the pipe.
        if conn.drain().await.is_err() {
            return;
        }

        while let Ok(message) = conn.recv().await {
            let text = match message {
                Message::Text(text) => text,
                Message::Close(_) => break,
                _ => continue,
            };
            let request: Value = serde_json::from_str(&text).expect("the driver sent non-JSON");
            seen.lock()
                .expect("seen mutex poisoned")
                .push(request.clone());
            for frame in script(&request) {
                if conn.send(Message::text(frame.to_string())).await.is_err() {
                    return;
                }
            }
        }
        *hung_up.lock().expect("hangup mutex poisoned") = true;
    }

    /// A well-behaved Chrome: one answer per command, in order.
    fn chrome(request: &Value) -> Vec<Value> {
        vec![json!({ "id": request["id"], "result": result_for(request) })]
    }

    fn result_for(request: &Value) -> Value {
        match request["method"].as_str().unwrap_or_default() {
            "Page.navigate" => json!({ "frameId": "frame-1" }),
            "Page.captureScreenshot" => json!({ "data": BASE64.encode(b"\x89PNG-pixels") }),
            "Runtime.callFunctionOn" => json!({ "result": { "type": "boolean", "value": true } }),
            "Runtime.evaluate" => {
                let expression = request["params"]["expression"].as_str().unwrap_or_default();
                if expression == "location.href" {
                    // A redirect happened: we asked for /login and landed on /home.
                    json!({ "result": { "type": "string", "value": "https://portal.example.com/home" } })
                } else if expression.starts_with("document.querySelector") {
                    json!({ "result": { "type": "object", "objectId": "obj-1" } })
                } else if expression.contains("#missing") {
                    json!({ "result": { "type": "boolean", "value": false } })
                } else {
                    json!({ "result": { "type": "boolean", "value": true } })
                }
            }
            other => panic!("driver sent an unexpected CDP method: {other}"),
        }
    }

    fn driver() -> CdpWebsocket {
        CdpWebsocket::new()
            .with_connect_timeout(Duration::from_millis(250))
            .with_command_timeout(Duration::from_millis(250))
    }

    /// Poll a condition until it holds or the test gives up on it.
    async fn eventually(mut condition: impl FnMut() -> bool) -> bool {
        for _ in 0..100 {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    // -- the steps -------------------------------------------------------------

    #[tokio::test]
    async fn a_navigation_reports_where_it_actually_landed() {
        let chrome_at = FakeChrome::start(chrome).await;
        let asked = Url::parse("https://portal.example.com/login").expect("url");

        let outcome = driver()
            .run(&chrome_at.connect_url(), &BrowserStep::Goto(&asked))
            .await
            .expect("navigated");

        assert_eq!(
            outcome,
            BrowserOutcome::Navigated(Url::parse("https://portal.example.com/home").expect("url")),
            "reported the requested URL instead of the one after redirects"
        );
        let methods: Vec<String> = chrome_at
            .seen()
            .iter()
            .filter_map(|frame| frame["method"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(methods, ["Page.navigate", "Runtime.evaluate"]);
    }

    #[tokio::test]
    async fn click_and_type_reach_the_dom_and_a_miss_is_terminal() {
        let chrome_at = FakeChrome::start(chrome).await;

        assert_eq!(
            driver()
                .run(&chrome_at.connect_url(), &BrowserStep::Click("#next"))
                .await
                .expect("click"),
            BrowserOutcome::Done
        );
        assert_eq!(
            driver()
                .run(
                    &chrome_at.connect_url(),
                    &BrowserStep::Type {
                        sel: "#user",
                        text: "ada@example.com",
                    },
                )
                .await
                .expect("type"),
            BrowserOutcome::Done
        );

        // A selector that matches nothing is our fault, not the browser's.
        let error = driver()
            .run(&chrome_at.connect_url(), &BrowserStep::Click("#missing"))
            .await
            .expect_err("nothing to click");
        assert_eq!(error.code(), NO_SUCH_ELEMENT);
        assert!(!error.is_retryable());

        let sent = chrome_at.seen();
        let expressions: String = sent
            .iter()
            .filter_map(|frame| frame["params"]["expression"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(expressions.contains("#next"), "{expressions}");
        // Visible text is not a secret and stays in the expression.
        assert!(expressions.contains("ada@example.com"), "{expressions}");
    }

    #[tokio::test]
    async fn a_screenshot_comes_back_as_decoded_png_bytes() {
        let chrome_at = FakeChrome::start(chrome).await;

        let outcome = driver()
            .run(&chrome_at.connect_url(), &BrowserStep::Screenshot)
            .await
            .expect("screenshot");
        assert_eq!(
            outcome,
            BrowserOutcome::Screenshot(b"\x89PNG-pixels".to_vec())
        );
    }

    // -- the thing that makes it correct: id matching --------------------------

    /// Chrome interleaves events with answers and may answer a later `id`
    /// first. Taking the next frame and hoping passes against a polite fake and
    /// returns another command's result under load.
    #[tokio::test]
    async fn a_response_is_matched_by_id_not_by_arrival_order() {
        let chrome_at = FakeChrome::start(|request| {
            let id = request["id"].as_u64().unwrap_or_default();
            vec![
                // An unsolicited event: no `id` at all.
                json!({
                    "method": "Page.frameNavigated",
                    "params": { "frame": { "id": "frame-1", "url": "about:blank" } },
                }),
                // Somebody else's answer, with a *later* id, arriving first.
                json!({ "id": id + 41, "result": { "result": { "value": "decoy" } } }),
                // Ours, last.
                json!({ "id": id, "result": { "result": { "type": "boolean", "value": true } } }),
            ]
        })
        .await;

        let outcome = driver()
            .run(&chrome_at.connect_url(), &BrowserStep::Click("#next"))
            .await
            .expect("the driver must wait for its own id");
        assert_eq!(outcome, BrowserOutcome::Done);
    }

    // -- failure classification -------------------------------------------------

    #[tokio::test]
    async fn a_cdp_error_response_is_terminal() {
        let chrome_at = FakeChrome::start(|request| {
            vec![json!({
                "id": request["id"],
                "error": { "code": -32000, "message": "Cannot find context with specified id" },
            })]
        })
        .await;

        let error = driver()
            .run(&chrome_at.connect_url(), &BrowserStep::Click("#next"))
            .await
            .expect_err("chrome said no");
        assert_eq!(error.code(), CDP_ERROR);
        assert!(
            !error.is_retryable(),
            "retrying a command chrome rejected makes it worse"
        );
    }

    /// A socket that accepts and never speaks. The listener exists, so the TCP
    /// connect succeeds and the *handshake* is what hangs.
    #[tokio::test]
    async fn a_connect_timeout_is_retryable_and_leaks_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Held, never accepted: the kernel completes the TCP handshake into the
        // backlog and nobody ever answers the upgrade.
        let url = Secret::new(format!("ws://{addr}/v1/sess_1?apiKey={API_KEY}"));

        let error = driver()
            .run(&url, &BrowserStep::Screenshot)
            .await
            .expect_err("nobody upgraded the connection");

        assert!(
            matches!(error, ProviderError::Retryable { .. }),
            "{error:?}"
        );
        assert!(error.is_retryable(), "a wedged browser is worth retrying");
        for rendered in [format!("{error:?}"), format!("{error}")] {
            assert!(
                !rendered.contains(API_KEY),
                "leaked the api key: {rendered}"
            );
            assert!(!rendered.contains(&addr.to_string()), "{rendered}");
        }
        drop(listener);
    }

    #[tokio::test]
    async fn a_command_timeout_is_retryable_and_closes_the_socket() {
        // Accepts, handshakes, and then answers nothing at all.
        let chrome_at = FakeChrome::start(|_| Vec::new()).await;

        let error = driver()
            .run(&chrome_at.connect_url(), &BrowserStep::Screenshot)
            .await
            .expect_err("the command was never answered");

        assert!(
            matches!(error, ProviderError::Retryable { .. }),
            "{error:?}"
        );
        assert!(error.is_retryable());
        assert!(
            eventually(|| chrome_at.hung_up()).await,
            "the driver left the socket open on a blown deadline"
        );
        assert_eq!(chrome_at.seen().len(), 1, "gave up without asking");
    }

    // -- secret hygiene ----------------------------------------------------------

    /// The password must reach the DOM and nothing else. It goes in as a
    /// `callFunctionOn` argument, so it is in exactly one frame and in no
    /// expression, no `Debug`, no error.
    #[tokio::test]
    async fn a_filled_credential_reaches_the_dom_and_nothing_else() {
        let chrome_at = FakeChrome::start(chrome).await;
        let password = Secret::new(PASSWORD);
        let driver = driver();

        let outcome = driver
            .run(
                &chrome_at.connect_url(),
                &BrowserStep::Fill {
                    sel: "#password",
                    secret: &password,
                },
            )
            .await
            .expect("filled");
        assert_eq!(outcome, BrowserOutcome::Done);

        let sent = chrome_at.seen();
        assert_eq!(sent.len(), 2, "expected a lookup and a callFunctionOn");
        assert_eq!(sent[0]["method"], "Runtime.evaluate");
        assert_eq!(sent[1]["method"], "Runtime.callFunctionOn");

        // It really was typed, so nothing below is vacuous.
        assert_eq!(sent[1]["params"]["arguments"][0]["value"], PASSWORD);
        // And it lives only there: not in any expression, not in the function
        // body, not in a second copy anywhere in the exchange.
        assert!(!sent[0].to_string().contains(PASSWORD), "{}", sent[0]);
        assert!(
            !sent[1]["params"]["functionDeclaration"]
                .as_str()
                .unwrap_or_default()
                .contains(PASSWORD)
        );
        let occurrences = sent
            .iter()
            .map(|frame| frame.to_string().matches(PASSWORD).count())
            .sum::<usize>();
        assert_eq!(occurrences, 1, "the credential was copied");

        // Nor in anything anyone would print.
        for rendered in [
            format!("{driver:?}"),
            format!(
                "{:?}",
                BrowserStep::Fill {
                    sel: "#password",
                    secret: &password
                }
            ),
            format!("{outcome:?}"),
        ] {
            assert!(
                !rendered.contains(PASSWORD),
                "leaked a credential: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn the_connect_url_never_reaches_debug_output() {
        let chrome_at = FakeChrome::start(chrome).await;
        let url = chrome_at.connect_url();
        // The URL really does embed the key.
        assert!(url.expose_for_transport().contains(API_KEY));

        let driver = driver();
        driver
            .run(&url, &BrowserStep::Screenshot)
            .await
            .expect("screenshot");

        for rendered in [
            format!("{driver:?}"),
            format!("{url:?}"),
            format!("{:?}", CdpWebsocket::default()),
        ] {
            assert!(
                !rendered.contains(API_KEY),
                "leaked the api key: {rendered}"
            );
            assert!(
                !rendered.contains("bb_live"),
                "leaked a key prefix: {rendered}"
            );
        }
        assert_eq!(format!("{url:?}"), Secret::REDACTED);
    }

    // -- the seam it exists to fill -----------------------------------------------

    /// The adapter refuses to start a session without a driver. Given this one
    /// it stops refusing — which is the only reason this module exists.
    #[tokio::test]
    async fn browserbase_with_this_driver_stops_reporting_no_cdp_driver() {
        // Browserbase's own API is not reachable here, and does not need to be:
        // `no_cdp_driver` is decided before any HTTP call is made.
        let browser = BrowserbaseBrowser::new("proj_test", API_KEY)
            // A closed port, so the session create fails fast.
            .with_base_url("http://127.0.0.1:1")
            .with_timeout(Duration::from_millis(200))
            .with_cdp(Arc::new(driver()));

        let session = BrowserbaseBrowser::session_for(
            agentos_domain::ids::EmployeeId::new_v7(chrono::Utc::now()),
            &crate::Provisioned::new("browserbase", "ctx_1"),
        );
        let error = browser
            .act(&session, BrowserStep::Screenshot)
            .await
            .expect_err("there is no browserbase at 127.0.0.1:1");

        assert_ne!(
            error.code(),
            "no_cdp_driver",
            "the adapter still thinks it has no CDP driver"
        );
        assert!(error.is_retryable(), "{error:?}");
    }
}
