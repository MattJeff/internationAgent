//! A [`BrowserProvider`] that is a `GET` and an HTML parser: no JavaScript, no
//! process, no vendor.
//!
//! # Why it exists — measured in production on 2026-09-10
//!
//! `readyz` listed `browser` under `mock_adapters`: there was no Browserbase
//! key, so every `read_page` an Orizn employee made went to [`MockBrowser`]
//! and answered [`NO_SUCH_ELEMENT`], on `visa.orizn.app` and on `example.com`
//! alike. Their CTO diagnosed it himself — "our fetch layer is broken" — and he
//! was right in the way that matters: the fetch layer was a fake. The founder
//! will not pay for a hosted browser before a task needs one (the repository's
//! rule: software before resources with a gatekeeper), and reading a static
//! page never needed one. A prospect's site, a directory, a booking page: a
//! request and a parser answer the question a model is asking.
//!
//! # What it serves and what it refuses
//!
//! The steps [`agentos_app::effects`] sends for a read are exactly four:
//! [`BrowserStep::Goto`], [`BrowserStep::Location`], [`BrowserStep::Text`] and
//! [`BrowserStep::Markup`] — plus a `Goto(about:blank)` to park a session. All
//! four are served here. Everything that puts something of ours on a
//! stranger's page — `Click`, `Type`, `Fill` — needs a DOM that reacts, and a
//! `Screenshot` needs a renderer; those come back as
//! `Terminal { code: NEEDS_REAL_BROWSER }`, with the page and the step in the
//! log line, so the refusal a model reads says "this site needs a real
//! browser" rather than "the element is missing".
//!
//! # What it does not do, on purpose
//!
//! No JavaScript: a page that builds itself client-side reads as the empty
//! shell the server sent, which is the truth about that page from here. No
//! cache: a read is one request, and a second read is a second request. No
//! `robots.txt`: this is a person's employee reading one page they were asked
//! to read, not a crawler walking a site, and the rate is one page per turn.
//! Say so in the docs; do not add it quietly.
//!
//! # The one thing it shares with the MCP client: the address check
//!
//! Every URL — the one asked for and every redirect after it — goes through
//! [`UrlVet`] before a socket opens, and the addresses the vet resolved are
//! the addresses the socket is pinned to. `agentos_app::mcp::resolve_and_vet`
//! is the implementation in production; it lives one crate up because that is
//! where the SSRF vocabulary is, and a second copy here would be the two lists
//! `config.rs` exists to avoid. Pinning closes the hole that module's ponytail
//! note names: DNS rebinding between the check and the connect.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, LOCATION, RETRY_AFTER};
use reqwest::redirect::Policy;
use scraper::{ElementRef, Html, Node, Selector};
use url::{Host, Url};

use crate::browser::{
    BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep, NO_SUCH_ELEMENT, blank_page,
};
use crate::{EnsureCtx, ProviderBinding, ProviderError, Provisioned};
use agentos_domain::untrusted::Untrusted;

/// The step needs a DOM that reacts or a renderer, and this adapter has
/// neither. Terminal: retrying the same step on the same adapter is the same
/// answer. The upgrade is `BROWSER_API_KEY`, not a retry.
pub const NEEDS_REAL_BROWSER: &str = "needs_real_browser";
/// The server answered with something a parser cannot read as a page — a PDF,
/// an image, a JSON API, or no `Content-Type` at all.
pub const NOT_HTML: &str = "not_html";
/// The body is over [`MAX_BODY`]. Terminal: the page will still be that size.
pub const PAGE_TOO_LARGE: &str = "page_too_large";
/// More than [`MAX_REDIRECTS`] hops. A loop, or a site that does not want to
/// be read this way.
pub const TOO_MANY_REDIRECTS: &str = "too_many_redirects";
/// Not `http` or `https`. `about:blank` is the one exception and it is a park,
/// not a navigation.
pub const NOT_HTTP: &str = "not_http";
/// The selector does not parse. Distinct from [`NO_SUCH_ELEMENT`]: that one is
/// a selector that names nothing on *this* page, this one names nothing on any.
pub const BAD_SELECTOR: &str = "bad_selector";

/// Who we say we are. Named, versioned, and with a page to complain at — a
/// site that wants to refuse us should be able to refuse *us*.
pub const USER_AGENT: &str = concat!(
    "InternationalAgent/",
    env!("CARGO_PKG_VERSION"),
    " (+https://siglair.com)"
);
/// Connect plus body, for one hop. Fifteen seconds and not the sixty the
/// vendor adapters take: a static page that takes longer is a page a real
/// browser would not have finished either, and the turn is waiting.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// The most HTML one page may be. Two megabytes is the whole of a long
/// directory listing; anything larger is a download wearing a `text/html`
/// header.
pub const MAX_BODY: usize = 2 * 1024 * 1024;
/// Hops followed before giving up. Five is `http`→`https`→`www`→country
/// splash→page, with one to spare.
pub const MAX_REDIRECTS: usize = 5;
/// Characters of visible text one [`BrowserStep::Text`] hands back.
///
/// The caller does not truncate — `Reply::Untrusted` reaches the model as it
/// is — so this is the only ceiling between a two-megabyte page and a prompt.
/// Thirty-two thousand characters is roughly eight thousand tokens: the whole
/// of an ordinary page, and a fraction of a listing nobody would read to the
/// end either.
pub const MAX_TEXT: usize = 32_000;

/// Elements whose text is never visible: code, style, and the markup a page
/// keeps for later. `noscript` is on the list because its text is what a
/// browser *without* script shows — which is what we are — but it is almost
/// always "please enable JavaScript", which is not what the page says.
const INVISIBLE: &[&str] = &["script", "style", "noscript", "template"];
/// Elements that start a new line when rendered. Enough to keep a heading off
/// the paragraph under it; not the whole CSS `display` table.
#[rustfmt::skip]
const BLOCKS: &[&str] = &[
    "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "ul", "ol", "tr", "br", "section",
    "article", "header", "footer", "nav", "main", "aside", "table", "blockquote", "pre", "dl",
    "dt", "dd", "form", "hr", "option", "title", "address", "figcaption",
];

// ---------------------------------------------------------------------------
// The address check
// ---------------------------------------------------------------------------

/// Resolve a host and refuse every address it must not reach.
///
/// One method, and it returns the addresses rather than `()` on purpose: the
/// caller pins its socket to them, so what was vetted is what is dialled. The
/// production implementation is in `agentos_app::mocks`, over
/// `agentos_app::mcp::resolve_and_vet` with `Reach::Public`.
#[async_trait]
pub trait UrlVet: Send + Sync {
    /// The addresses `url`'s host resolves to, or why none of them may be used.
    async fn resolve_and_vet(&self, url: &Url) -> Result<Vec<IpAddr>, ProviderError>;
}

/// A vet for a hermetic test: one host name resolves to one address, and
/// nothing else resolves at all.
///
/// `pub` because two crates run this adapter against a loopback fake site
/// under a real-looking host name (`Domain::parse` refuses `localhost` and IP
/// literals, so the effects tests cannot use either). Refusing every other
/// host is what makes "a redirect to `127.0.0.1` is refused" provable: the
/// literal is not the pinned name.
#[derive(Debug)]
pub struct PinnedHost {
    host: String,
    ip: IpAddr,
}

impl PinnedHost {
    /// `host` resolves to `ip`; anything else is `blocked_address`.
    pub fn new(host: impl Into<String>, ip: IpAddr) -> Self {
        Self {
            host: host.into(),
            ip,
        }
    }
}

#[async_trait]
impl UrlVet for PinnedHost {
    async fn resolve_and_vet(&self, url: &Url) -> Result<Vec<IpAddr>, ProviderError> {
        if url.host_str() == Some(self.host.as_str()) {
            Ok(vec![self.ip])
        } else {
            Err(ProviderError::Terminal {
                code: "blocked_address",
            })
        }
    }
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// Where one session is, and the document it is looking at.
#[derive(Debug, Default)]
struct Page {
    /// `None` is [`blank_page`]: nothing loaded, or parked.
    here: Option<Url>,
    /// The body as served. Re-parsed on every read: `scraper::Html` is not
    /// `Send` and a page is a few milliseconds to parse, which is nothing next
    /// to the request that fetched it.
    html: String,
}

/// The `GET`-and-parse browser.
///
/// State is per binding — [`BrowserSession::binding`]'s `external_id` — so two
/// seats reading two pages do not see each other's, exactly as two Browserbase
/// contexts would not.
pub struct HttpBrowser {
    vet: Arc<dyn UrlVet>,
    pages: Mutex<BTreeMap<String, Page>>,
}

impl std::fmt::Debug for HttpBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpBrowser")
            .field("sessions", &self.lock().len())
            .finish()
    }
}

impl HttpBrowser {
    /// Adapter identity, recorded on every [`Provisioned`] this module returns.
    pub const PROVIDER: &'static str = "http-browser";

    /// A browser that dials only what `vet` permits.
    pub fn new(vet: Arc<dyn UrlVet>) -> Self {
        Self {
            vet,
            pages: Mutex::new(BTreeMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Page>> {
        self.pages.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `GET`, following at most [`MAX_REDIRECTS`], every hop vetted and
    /// pinned. Returns where it landed and what was there.
    async fn fetch(&self, asked: &Url) -> Result<(Url, String), ProviderError> {
        let mut url = asked.clone();
        for _ in 0..=MAX_REDIRECTS {
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ProviderError::Terminal { code: NOT_HTTP });
            }
            let addresses = self.vet.resolve_and_vet(&url).await?;
            let port = url.port_or_known_default().unwrap_or(443);
            let mut client = reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .timeout(FETCH_TIMEOUT)
                // Followed by hand below, so the vet sees every hop. `reqwest`'s
                // own policy is synchronous and cannot resolve a name.
                .redirect(Policy::none());
            if let Some(Host::Domain(host)) = url.host() {
                // ponytail: a client per hop, because the pin is a builder
                // setting. Building one is a TLS config and an empty pool —
                // milliseconds — against a network round trip.
                let pinned: Vec<SocketAddr> = addresses
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, port))
                    .collect();
                client = client.resolve_to_addrs(host, &pinned);
            }
            let client = client.build().map_err(|_| ProviderError::timeout())?;

            let response = client
                .get(url.clone())
                .send()
                .await
                .map_err(|_| ProviderError::timeout())?;
            let status = response.status();

            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| ProviderError::from_status(status.as_u16(), None))?;
                url = url
                    .join(location)
                    .map_err(|_| ProviderError::Terminal { code: NOT_HTTP })?;
                continue;
            }
            if !status.is_success() {
                let retry_after = response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .map(Duration::from_secs);
                return Err(ProviderError::from_status(status.as_u16(), retry_after));
            }
            if !is_page(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
            ) {
                return Err(ProviderError::Terminal { code: NOT_HTML });
            }
            let body = read_capped(response).await?;
            return Ok((url, body));
        }
        Err(ProviderError::Terminal {
            code: TOO_MANY_REDIRECTS,
        })
    }
}

/// `text/*` and XHTML. A missing header is not a page: a server that cannot
/// say what it sent is not one to parse on faith.
fn is_page(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
        .is_some_and(|mime| mime.starts_with("text/") || mime == "application/xhtml+xml")
}

/// The body, refused by the header when it announces its size and by the
/// count when it does not — a chunked response has no `Content-Length` to
/// read, and a cap that trusted the header alone would be a cap on honest
/// servers only.
///
/// ponytail: bytes are read as UTF-8 with replacement. A Latin-1 page arrives
/// with a few wrong accents; charset sniffing (`<meta charset>`, the header's
/// `charset=`) is the upgrade the day a prospect's page comes back unreadable.
async fn read_capped(mut response: reqwest::Response) -> Result<String, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY as u64)
    {
        return Err(ProviderError::Terminal {
            code: PAGE_TOO_LARGE,
        });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ProviderError::timeout())?
    {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BODY {
            return Err(ProviderError::Terminal {
                code: PAGE_TOO_LARGE,
            });
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

// ---------------------------------------------------------------------------
// Reading a document
// ---------------------------------------------------------------------------

/// The first match of `sel` in `html`, handed to `read`. `Ok(None)` is no
/// match — the caller turns it into [`NO_SUCH_ELEMENT`].
///
/// Synchronous and self-contained so the `!Send` `Html` never lives across an
/// `await`.
fn first_match<T>(
    html: &str,
    sel: &str,
    read: impl FnOnce(ElementRef<'_>) -> T,
) -> Result<Option<T>, ProviderError> {
    let selector =
        Selector::parse(sel).map_err(|_| ProviderError::Terminal { code: BAD_SELECTOR })?;
    let document = Html::parse_document(html);
    Ok(document.select(&selector).next().map(read))
}

/// What a person sees of `element`: text nodes minus [`INVISIBLE`] subtrees,
/// a line break at every [`BLOCKS`] boundary, whitespace collapsed, capped at
/// [`MAX_TEXT`].
fn visible_text(element: ElementRef<'_>) -> String {
    /// `ego_tree::NodeRef<Node>`, named through the one type this crate
    /// imports rather than through a second dependency on the tree crate.
    type NodeRef<'a> = <ElementRef<'a> as std::ops::Deref>::Target;
    fn walk(node: NodeRef<'_>, out: &mut String) {
        for child in node.children() {
            match child.value() {
                Node::Text(text) => out.push_str(text),
                Node::Element(element) => {
                    let name = element.name();
                    if INVISIBLE.contains(&name) {
                        continue;
                    }
                    let block = BLOCKS.contains(&name);
                    if block {
                        out.push('\n');
                    }
                    walk(child, out);
                    if block {
                        out.push('\n');
                    }
                }
                _ => {}
            }
        }
    }
    let mut raw = String::new();
    walk(*element, &mut raw);

    let mut text = raw
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if let Some((cut, _)) = text.char_indices().nth(MAX_TEXT) {
        text.truncate(cut);
    }
    text
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

#[async_trait]
impl BrowserProvider for HttpBrowser {
    async fn ensure_context(&self, ctx: &EnsureCtx) -> Result<Provisioned, ProviderError> {
        if let Some(existing) = &ctx.existing
            && existing.provider == Self::PROVIDER
        {
            return Ok(Provisioned::new(
                Self::PROVIDER,
                existing.external_id.clone(),
            ));
        }
        // The tag, and never a counter: `employee_resources_provider_external_id_key`
        // is global, and `MockBrowser::booted` documents the eighth seat that
        // could not provision because `ctx-1` was somebody else's since a
        // boot five days earlier. The tag is one seat's idempotency key, so
        // it is unique across seats and identical across retries and boots —
        // which is the whole of the reconcile contract, with no lookup to do.
        Ok(Provisioned::new(
            Self::PROVIDER,
            format!("ctx-{}", ctx.tag()),
        ))
    }

    async fn act(
        &self,
        session: &BrowserSession,
        step: BrowserStep<'_>,
    ) -> Result<BrowserOutcome, ProviderError> {
        let ctx = session.binding.external_id.as_str();
        match step {
            BrowserStep::Goto(url) if *url == blank_page() => {
                // A park: `app::effects` sends the session here after a refused
                // landing. Nothing to fetch, and the old document must go.
                self.lock().remove(ctx);
                Ok(BrowserOutcome::Navigated(blank_page()))
            }
            BrowserStep::Goto(url) => {
                let (landed, html) = self.fetch(url).await?;
                self.lock().insert(
                    ctx.to_owned(),
                    Page {
                        here: Some(landed.clone()),
                        html,
                    },
                );
                Ok(BrowserOutcome::Navigated(landed))
            }
            BrowserStep::Location => Ok(BrowserOutcome::Navigated(
                self.lock()
                    .get(ctx)
                    .and_then(|page| page.here.clone())
                    .unwrap_or_else(blank_page),
            )),
            BrowserStep::Text(sel) => {
                let html = self.lock().get(ctx).map(|page| page.html.clone());
                // No document is `about:blank`, whose `body` is there and empty
                // — the same answer a real tab gives.
                first_match(html.as_deref().unwrap_or_default(), sel, visible_text)?
                    .map(|text| BrowserOutcome::Text(Untrusted::new(text)))
                    .ok_or(ProviderError::Terminal {
                        code: NO_SUCH_ELEMENT,
                    })
            }
            BrowserStep::Markup(sel) => {
                let html = self.lock().get(ctx).map(|page| page.html.clone());
                first_match(html.as_deref().unwrap_or_default(), sel, |element| {
                    element.html()
                })?
                .map(|markup| BrowserOutcome::Markup(Untrusted::new(markup)))
                .ok_or(ProviderError::Terminal {
                    code: NO_SUCH_ELEMENT,
                })
            }
            BrowserStep::Click(_)
            | BrowserStep::Type { .. }
            | BrowserStep::Fill { .. }
            | BrowserStep::Screenshot => {
                // The page and the step, by name only — `BrowserStep::name`
                // argues why the argument never reaches a log line.
                let here = self
                    .lock()
                    .get(ctx)
                    .and_then(|page| page.here.clone())
                    .unwrap_or_else(blank_page);
                tracing::warn!(
                    url = %here,
                    step = step.name(),
                    "this site needs a real browser: the http-browser has no JavaScript, \
                     no DOM events and no renderer; set BROWSER_API_KEY to drive it"
                );
                Err(ProviderError::Terminal {
                    code: NEEDS_REAL_BROWSER,
                })
            }
        }
    }

    async fn release(&self, binding: &ProviderBinding) -> Result<(), ProviderError> {
        // Nothing was bought; the only thing to give back is the document.
        self.lock().remove(&binding.external_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use agentos_domain::ids::{EmployeeId, Slug, TenantId};
    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use chrono::Utc;
    use tokio::net::TcpListener;

    use super::*;
    use crate::Secret;

    /// The name the fake site is reached under. A real-looking domain, because
    /// `PinnedHost` is what makes it resolve and the effects tests need a name
    /// `Domain::parse` accepts.
    const SITE: &str = "portal.example.com";

    // -- a fake prospect's site, on a loopback port ---------------------------
    //
    // axum rather than the hand-rolled HTTP/1.1 of `FakeResend`: this fake is
    // the *server* side of an ordinary GET, and every route below is one line
    // of the thing being tested — a redirect, a content type, a body size.

    #[derive(Default)]
    struct Hits(Mutex<Vec<String>>);

    async fn static_page() -> Response {
        html(
            "<!doctype html><html><head><title>Portal</title>\
             <style>h1 { color: red }</style></head>\
             <body>\n  <h1>  Book a   trip </h1>\n\
             <p>Visa <b>required</b> for stays over 90 days.</p>\
             <script>document.write('injected')</script>\
             <form id=\"book\"><input id=\"passport\"></form>\
             </body></html>",
        )
    }

    async fn js_only() -> Response {
        html(
            "<!doctype html><html><head><script src=\"/app.js\"></script></head><body></body></html>",
        )
    }

    async fn big() -> Response {
        html(&"<p>x</p>".repeat(MAX_BODY / 8 + 1))
    }

    async fn pdf() -> Response {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pdf"),
            )],
            "%PDF-1.4",
        )
            .into_response()
    }

    /// `/hop`: to the loopback *literal* on this very server — the redirect an
    /// SSRF walks through when only the first URL is checked.
    async fn hop(State(port): State<u16>) -> Response {
        redirect(&format!("http://127.0.0.1:{port}/secret"))
    }

    async fn secret(State(hits): State<Arc<Hits>>) -> Response {
        hits.0.lock().unwrap().push("/secret".to_owned());
        html("<h1>internal</h1>")
    }

    async fn bounce() -> Response {
        redirect("/static")
    }

    async fn forever() -> Response {
        redirect("/forever")
    }

    fn html(body: &str) -> Response {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            body.to_owned(),
        )
            .into_response()
    }

    fn redirect(to: &str) -> Response {
        (
            StatusCode::FOUND,
            [(header::LOCATION, HeaderValue::from_str(to).unwrap())],
        )
            .into_response()
    }

    struct FakeSite {
        addr: SocketAddr,
        hits: Arc<Hits>,
    }

    impl FakeSite {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let hits = Arc::new(Hits::default());
            let app = Router::new()
                .route("/login", get(static_page))
                .route("/static", get(static_page))
                .route("/js-only", get(js_only))
                .route("/big", get(big))
                .route("/pdf", get(pdf))
                .route("/bounce", get(bounce))
                .route("/forever", get(forever))
                .route("/hop", get(hop).with_state(addr.port()))
                .route("/secret", get(secret).with_state(Arc::clone(&hits)));
            tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
            Self { addr, hits }
        }

        fn url(&self, path: &str) -> Url {
            Url::parse(&format!("http://{SITE}:{}{path}", self.addr.port())).expect("url")
        }

        fn browser(&self) -> HttpBrowser {
            HttpBrowser::new(Arc::new(PinnedHost::new(
                SITE,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )))
        }

        fn hits(&self) -> Vec<String> {
            self.hits.0.lock().unwrap().clone()
        }
    }

    fn ctx(employee_id: EmployeeId) -> EnsureCtx {
        EnsureCtx::new(
            TenantId::new_v7(Utc::now()),
            employee_id,
            Slug::parse("ada").unwrap(),
            "browser",
        )
    }

    async fn session(p: &HttpBrowser) -> BrowserSession {
        let provisioned = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .expect("ensure");
        BrowserSession {
            employee_id: EmployeeId::new_v7(Utc::now()),
            binding: provisioned.binding(),
            user_data_dir: None,
        }
    }

    async fn text(p: &HttpBrowser, s: &BrowserSession, sel: &str) -> Result<String, ProviderError> {
        match p.act(s, BrowserStep::Text(sel)).await? {
            BrowserOutcome::Text(text) => Ok(text.into_inner_for_rendering()),
            other => panic!("a text read answered {other:?}"),
        }
    }

    /// The same suite the mock and Browserbase pass, against a page this
    /// adapter can actually fetch.
    #[tokio::test]
    async fn the_http_browser_satisfies_the_contract() {
        let site = FakeSite::start().await;
        crate::browser::contract_suite_on(&site.browser(), &site.url("/login")).await;
    }

    #[tokio::test]
    async fn a_static_page_reads_by_selector_and_as_a_whole() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let s = session(&p).await;

        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site.url("/static")))
                .await
                .unwrap(),
            BrowserOutcome::Navigated(site.url("/static"))
        );
        assert_eq!(text(&p, &s, "h1").await.unwrap(), "Book a trip");
        // The whole page: the title and the prose, no stylesheet, no script
        // body, headings on their own line, runs of whitespace collapsed.
        assert_eq!(
            text(&p, &s, "body").await.unwrap(),
            "Book a trip\nVisa required for stays over 90 days."
        );
        assert_eq!(
            text(&p, &s, "html").await.unwrap(),
            "Portal\nBook a trip\nVisa required for stays over 90 days."
        );
        // Markup is `outerHTML`, which is what `flow_proposal` derives ids from.
        match p.act(&s, BrowserStep::Markup("form")).await.unwrap() {
            BrowserOutcome::Markup(markup) => {
                let markup = markup.into_inner_for_rendering();
                assert!(markup.starts_with("<form id=\"book\">"), "{markup}");
                assert!(markup.contains("id=\"passport\""), "{markup}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// The distinction `proof_of_need` rests on, kept: a page that has no such
    /// element is an error about our selector, not a page that says nothing.
    #[tokio::test]
    async fn a_missing_selector_is_no_such_element_and_a_bad_one_is_named() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site.url("/static")))
            .await
            .unwrap();

        let err = text(&p, &s, "#visa-panel").await.unwrap_err();
        assert_eq!(err.code(), NO_SUCH_ELEMENT);
        assert!(!err.is_retryable());

        let err = text(&p, &s, "[[not a selector").await.unwrap_err();
        assert_eq!(err.code(), BAD_SELECTOR);
    }

    /// A page that builds itself client-side is, from here, the empty shell the
    /// server sent. That is a fact about the page and it reads as one — not as
    /// a broken selector.
    #[tokio::test]
    async fn a_page_rendered_by_javascript_reads_as_empty_not_as_an_error() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site.url("/js-only")))
            .await
            .unwrap();
        assert_eq!(text(&p, &s, "body").await.unwrap(), "");
    }

    #[tokio::test]
    async fn a_write_step_says_the_site_needs_a_real_browser() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site.url("/static")))
            .await
            .unwrap();
        let secret = Secret::new("hunter2");

        for step in [
            BrowserStep::Click("#submit"),
            BrowserStep::Type {
                sel: "#passport",
                text: "FRA",
            },
            BrowserStep::Fill {
                sel: "#password",
                secret: &secret,
            },
            BrowserStep::Screenshot,
        ] {
            let name = step.name();
            let err = p.act(&s, step).await.unwrap_err();
            assert_eq!(err.code(), NEEDS_REAL_BROWSER, "{name}");
            assert!(
                !err.is_retryable(),
                "{name}: a retry has no JavaScript either"
            );
        }
        // And the page it was on is still up: a refusal is not a navigation.
        assert_eq!(text(&p, &s, "h1").await.unwrap(), "Book a trip");
    }

    /// **Every hop is vetted, not only the first.** The site is reached under
    /// its name; it answers with a redirect to the loopback literal on the
    /// same port. The literal is not the pinned name, so the vet refuses it —
    /// and the proof that the refusal came *before* the connect is that the
    /// route it pointed at was never hit.
    #[tokio::test]
    async fn a_redirect_to_a_loopback_address_is_refused_before_it_is_followed() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site.url("/static")))
            .await
            .unwrap();

        let err = p
            .act(&s, BrowserStep::Goto(&site.url("/hop")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "blocked_address");
        assert!(
            site.hits().is_empty(),
            "the redirect was followed: {:?}",
            site.hits()
        );
        // The session stayed where it was; a refused navigation went nowhere.
        assert_eq!(
            p.act(&s, BrowserStep::Location).await.unwrap(),
            BrowserOutcome::Navigated(site.url("/static"))
        );
    }

    /// A permitted redirect lands, and `Location` says where — which is what
    /// `app::effects` rules on.
    #[tokio::test]
    async fn a_relative_redirect_lands_and_the_session_says_so() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let s = session(&p).await;
        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site.url("/bounce")))
                .await
                .unwrap(),
            BrowserOutcome::Navigated(site.url("/static"))
        );
        assert_eq!(
            p.act(&s, BrowserStep::Location).await.unwrap(),
            BrowserOutcome::Navigated(site.url("/static"))
        );
        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site.url("/forever")))
                .await
                .unwrap_err()
                .code(),
            TOO_MANY_REDIRECTS
        );
    }

    #[tokio::test]
    async fn a_body_over_the_cap_and_a_pdf_are_both_refused_by_name() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let s = session(&p).await;
        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site.url("/big")))
                .await
                .unwrap_err()
                .code(),
            PAGE_TOO_LARGE
        );
        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site.url("/pdf")))
                .await
                .unwrap_err()
                .code(),
            NOT_HTML
        );
        assert_eq!(
            p.act(
                &s,
                BrowserStep::Goto(&Url::parse("ftp://portal.example.com/").unwrap())
            )
            .await
            .unwrap_err()
            .code(),
            NOT_HTTP
        );
        // None of them replaced the document: the session is still nowhere.
        assert_eq!(
            p.act(&s, BrowserStep::Location).await.unwrap(),
            BrowserOutcome::Navigated(blank_page())
        );
    }

    /// The id is the seat's tag: distinct across seats, stable across boots,
    /// and never `ctx-1` — see `MockBrowser::booted` for the outage that was.
    #[tokio::test]
    async fn two_seats_get_two_contexts_and_neither_is_a_counter() {
        let p = HttpBrowser::new(Arc::new(PinnedHost::new(
            SITE,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )));
        let ada = ctx(EmployeeId::new_v7(Utc::now()));
        let bob = ctx(EmployeeId::new_v7(Utc::now()));
        let a = p.ensure_context(&ada).await.unwrap();
        let b = p.ensure_context(&bob).await.unwrap();
        assert_ne!(a.external_id, b.external_id);
        assert_eq!(a.external_id, format!("ctx-{}", ada.tag()));
        assert_eq!(a.provider, HttpBrowser::PROVIDER);
        // Same seat, next boot: the same id, with nothing to look up.
        let again = HttpBrowser::new(Arc::new(PinnedHost::new(
            SITE,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )));
        assert_eq!(again.ensure_context(&ada).await.unwrap(), a);
    }

    /// Two seats, two documents: what one loaded the other cannot read.
    #[tokio::test]
    async fn two_seats_do_not_share_a_page() {
        let site = FakeSite::start().await;
        let p = site.browser();
        let ada = session(&p).await;
        let bob = session(&p).await;
        p.act(&ada, BrowserStep::Goto(&site.url("/static")))
            .await
            .unwrap();
        assert_eq!(text(&p, &ada, "h1").await.unwrap(), "Book a trip");
        assert_eq!(
            text(&p, &bob, "h1").await.unwrap_err().code(),
            NO_SUCH_ELEMENT,
            "bob's tab is blank"
        );
        assert_eq!(text(&p, &bob, "body").await.unwrap(), "");
    }

    #[test]
    fn visible_text_is_capped_at_a_char_boundary() {
        let page = format!("<body><p>{}</p></body>", "é".repeat(MAX_TEXT + 10));
        let text = first_match(&page, "body", visible_text).unwrap().unwrap();
        assert_eq!(text.chars().count(), MAX_TEXT);
        assert!(is_page(Some("Text/HTML; charset=iso-8859-1")));
        assert!(is_page(Some("application/xhtml+xml")));
        assert!(!is_page(Some("application/json")));
        assert!(!is_page(None));
    }
}
