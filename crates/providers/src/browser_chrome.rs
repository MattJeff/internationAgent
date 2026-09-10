//! « Notre Browserbase » : un Chromium sans tête qu'on fait tourner soi-même,
//! piloté par le [`CdpWebsocket`] existant, avec la persistance par employé
//! ramenée à la seule chose qu'elle est vraiment — un pot de cookies.
//!
//! `docs/BROWSER.md` est le contrat ; ce module l'exécute. Trois choses
//! méritent d'être lues avant le code, parce qu'elles ne se devinent pas du
//! trait et que deux d'entre elles contredisent la première lecture.
//!
//! # Un contexte CDP par tâche, et le pot de cookies scellé entre deux
//!
//! `browser_browserbase.rs` argumente que Chrome oblige à choisir entre
//! isolation (`Target.createBrowserContext`, incognito, jeté avec le
//! processus) et persistance (`--user-data-dir`, un processus par employé).
//! Le choix ici est le troisième : **le contexte est jetable, le pot de
//! cookies ne l'est pas**. À l'ouverture d'un onglet, `Network.setCookies`
//! ré-injecte ce que la tâche précédente a laissé ; à la fermeture,
//! `Network.getAllCookies` exporte, et [`CookieJar::save`] range — scellé côté
//! application, sous `browser://<locataire>/<employé>`, dans
//! `employee_resources.sealed_cookies` (migration 0095). C'est exactement ce
//! que Browserbase fait côté serveur derrière `persist: true`, sans qu'on le
//! voie. Un `localStorage` ne survit pas ; une session ouverte par cookie, si,
//! et c'est le cas qui compte : rester connecté à un portail.
//!
//! # L'onglet vit le temps d'un tour, et le trait ne dit pas quand un tour finit
//!
//! [`BrowserProvider::act`] prend **une** étape. `effects.rs::load_page` en
//! envoie deux d'affilée (`Goto` puis `Text`) sur la même session, et
//! `drive` demande `Location` avant chaque étape qui ne navigue pas : un
//! onglet ouvert par étape, comme Browserbase le fait avec sa session, lirait
//! `about:blank` à la deuxième étape. L'onglet est donc **tenu par
//! liaison** (`BrowserSession::binding.external_id`) entre deux `act`, comme
//! `HttpBrowser` tient son document — et il est fermé par la première des
//! trois choses qui arrivent : un `Goto(about:blank)` (le « park » d'`effects`,
//! qui est la seule fin de tâche que le trait sait dire), une erreur qui
//! concerne le navigateur plutôt que notre sélecteur ([`tab_survives`]), ou
//! [`TAB_IDLE`] sans étape. Rien ne survit à la troisième : un moissonneur par
//! onglet ferme, exporte les cookies et rend le jeton.
//!
//! # Trois onglets, jamais plus, et l'attente est bornée
//!
//! 3 819 Mo de RAM sur le VPS, Chromium plafonné à 1 Go : au-delà de
//! [`DEFAULT_MAX_TABS`] onglets, on **attend** [`DEFAULT_QUEUE_WAIT`] puis on
//! répond `Retryable` — on ne lance pas un quatrième processus de rendu. Le
//! sémaphore est pris à l'ouverture de l'onglet et rendu à sa fermeture, pas
//! par étape : une étape sur un onglet déjà ouvert ne fait pas la queue.
//!
//! # Ce qui a été mesuré en l'écrivant (2026-09-10, Chrome 152)
//!
//! `GET http://browser:9222/json/version` répond **« Host header is specified
//! and is not an IP address or localhost. »** : Chrome refuse tout `Host` qui
//! n'est pas une adresse. `BROWSER_CDP_URL=http://browser:9222` reste la forme
//! de configuration — c'est le nom du service compose — mais l'adaptateur
//! résout le nom lui-même ([`ChromeBrowser::endpoint`]) et compose tous ses
//! appels, HTTP comme websocket, sur `ws://<ip>:9222`. Le
//! `webSocketDebuggerUrl` rendu n'est pas pris verbatim non plus, pour la même
//! raison : Chrome y écrit `127.0.0.1`, l'adresse à laquelle *lui* s'écoute,
//! pas celle par laquelle on l'atteint.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

use crate::browser::{
    BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep, NO_SUCH_ELEMENT, blank_page,
};
use crate::browser_browserbase::CdpDriver as _;
use crate::browser_http::UrlVet;
use crate::cdp::{CdpWebsocket, NAVIGATION_FAILED, SCRIPT_FAILED};
use crate::{EnsureCtx, ProviderBinding, ProviderError, Provisioned, Secret};

/// Adapter identity, recorded on every [`Provisioned`] this module returns.
pub const PROVIDER: &str = "chrome";

/// The site answered the navigation with a wall — a challenge page, an
/// « access denied », a 403/503 — and no retry from this address changes
/// that. The ceiling of the v1: no proxy, no stealth. `docs/PROVIDERS.md`
/// names it so an operator reading the audit trail knows the upgrade is
/// `BROWSER_API_KEY`, not a retry.
pub const BLOCKED_BY_SITE: &str = "blocked_by_site";
/// `Target.createBrowserContext` or `Target.createTarget` answered without
/// the id the protocol documents.
pub const NO_TARGET: &str = "no_target";

/// Tabs open at once, process-wide. See the module docs for the arithmetic.
pub const DEFAULT_MAX_TABS: usize = 3;
/// How long a task waits for a tab before `Retryable`.
pub const DEFAULT_QUEUE_WAIT: Duration = Duration::from_secs(60);
/// Ceiling on one step, socket included: the same backstop
/// `browser_browserbase::REQUEST_TIMEOUT` argues — a turn that never ends is
/// a Postgres transaction that never ends.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// An onglet nobody has driven for this long is closed, cookies exported.
///
/// Two minutes because between two steps of one turn there is a model call,
/// and a model call is tens of seconds; shorter, and a plan's second step
/// would find `about:blank` where its first step had left a page.
pub const TAB_IDLE: Duration = Duration::from_secs(120);

/// Titles a wall wears, lower-cased. Cloudflare's challenge, Akamai's and
/// nginx's refusals, Cloudflare's no-script fallback.
const BLOCKED_TITLES: &[&str] = &[
    "just a moment",
    "access denied",
    "attention required",
    "enable javascript and cookies to continue",
];

/// What the page says about itself once it has parsed: its title and the
/// status its document was served with. Waits for `DOMContentLoaded` because
/// `Page.navigate` returns at commit, before the `<title>` has been read.
///
/// `responseStatus` is Chrome 109+; an older Chrome reads `0`, which is
/// « not a wall », the safe direction.
const WALL_CHECK: &str = "new Promise(done => { const answer = () => done([document.title, \
     (performance.getEntriesByType('navigation')[0] || {}).responseStatus || 0]); \
     document.readyState !== 'loading' ? answer() : \
     document.addEventListener('DOMContentLoaded', answer); })";

// ---------------------------------------------------------------------------
// The cookie jar
// ---------------------------------------------------------------------------

/// Where an employee's cookies live between two tasks.
///
/// Keyed by the **context id** — [`BrowserSession::binding`]'s `external_id`,
/// `ctx-<tag>` — and not by the employee, because that id is the one thing
/// both [`BrowserProvider::act`] and [`BrowserProvider::release`] hold: a
/// release is handed a [`ProviderBinding`] and nothing else, and the jar is
/// the only thing it has to throw away.
///
/// The value is a [`Secret`]: a JSON array of CDP `CookieParam`s, in the
/// clear on this side because `Network.setCookies` needs them so. **The
/// sealing is the implementation's business**, one crate up
/// (`agentos_app::cookie_jar`), where the cipher and the tenant are: this
/// crate has the AES-GCM envelope but not the master key, and the encryption
/// context `browser://<tenant>/<employee>` needs a tenant the session does not
/// carry. A session cookie is a credential, so the type says so.
#[async_trait]
pub trait CookieJar: Send + Sync {
    /// The cookies the last task left, or `None` for a context that never
    /// closed a tab.
    async fn load(&self, ctx: &str) -> Result<Option<Secret>, ProviderError>;
    /// Replace the jar. Called when a tab closes, with everything the context
    /// holds.
    async fn save(&self, ctx: &str, cookies: &Secret) -> Result<(), ProviderError>;
    /// Throw the jar away. Idempotent: a context that never had one is the
    /// desired state already.
    async fn forget(&self, ctx: &str) -> Result<(), ProviderError>;
}

/// A jar in a map: what a test and [`agentos_app::mocks::ports`] use. Not
/// durable and not sealed, and it says so in its name.
#[derive(Default)]
pub struct MemoryCookieJar {
    jars: Mutex<BTreeMap<String, String>>,
}

impl MemoryCookieJar {
    /// An empty jar.
    pub fn new() -> Self {
        Self::default()
    }

    /// Contexts that have a jar, for a test to assert on.
    pub fn contexts(&self) -> Vec<String> {
        self.jars
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }
}

#[async_trait]
impl CookieJar for MemoryCookieJar {
    async fn load(&self, ctx: &str) -> Result<Option<Secret>, ProviderError> {
        Ok(self
            .jars
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(ctx)
            .map(Secret::new))
    }

    async fn save(&self, ctx: &str, cookies: &Secret) -> Result<(), ProviderError> {
        self.jars
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ctx.to_owned(), cookies.expose_for_transport().to_owned());
        Ok(())
    }

    async fn forget(&self, ctx: &str) -> Result<(), ProviderError> {
        self.jars
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(ctx);
        Ok(())
    }
}

/// `Network.getAllCookies` answers `Cookie`s; `Network.setCookies` takes
/// `CookieParam`s, and the two are not the same shape. Keep what a
/// `CookieParam` accepts and what re-creates the same cookie: `size` and
/// `session` are facts about the stored cookie, not inputs; `expires: -1`
/// means « session cookie » on the way out and « invalid » on the way in;
/// `partitionKey` changed shape between Chrome versions and a login does not
/// need it.
fn cookie_params(cookies: &[Value]) -> Vec<Value> {
    const KEEP: &[&str] = &[
        "name", "value", "domain", "path", "secure", "httpOnly", "sameSite",
    ];
    cookies
        .iter()
        .map(|cookie| {
            let mut param = serde_json::Map::new();
            for key in KEEP {
                if let Some(value) = cookie.get(key) {
                    param.insert((*key).to_owned(), value.clone());
                }
            }
            if let Some(expires) = cookie["expires"].as_f64()
                && expires > 0.0
            {
                param.insert("expires".to_owned(), json!(expires));
            }
            Value::Object(param)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// One open tab: the CDP context and target it lives in, and the token it
/// holds. Dropping it returns the token; closing it properly is
/// [`Inner::close`]'s job.
struct Tab {
    context_id: String,
    target_id: String,
    /// `ws://<ip>:<port>/devtools/page/<target>`, handed to the driver
    /// verbatim at every step.
    page_url: String,
    last_used: Instant,
    _permit: OwnedSemaphorePermit,
}

struct Inner {
    cdp_url: Url,
    http: reqwest::Client,
    driver: CdpWebsocket,
    vet: Arc<dyn UrlVet>,
    jar: Arc<dyn CookieJar>,
    tokens: Arc<Semaphore>,
    tabs: Mutex<BTreeMap<String, Tab>>,
    queue_wait: Duration,
    step_timeout: Duration,
    tab_idle: Duration,
}

/// The self-hosted browser. `Clone` is cheap and shares the tabs and the
/// tokens: one process, one Chromium, one ceiling.
#[derive(Clone)]
pub struct ChromeBrowser {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ChromeBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChromeBrowser")
            .field("cdp_url", &self.inner.cdp_url.as_str())
            .field("open_tabs", &self.inner.lock().len())
            .field("free_tokens", &self.inner.tokens.available_permits())
            .finish()
    }
}

impl ChromeBrowser {
    /// A browser at `cdp_url` (`http://browser:9222`), dialling only what
    /// `vet` permits, keeping cookies in `jar`.
    pub fn new(cdp_url: Url, vet: Arc<dyn UrlVet>, jar: Arc<dyn CookieJar>) -> Self {
        Self {
            inner: Arc::new(Inner {
                cdp_url,
                http: reqwest::Client::builder()
                    .timeout(crate::cdp::DEFAULT_CONNECT_TIMEOUT)
                    .build()
                    .unwrap_or_default(),
                driver: CdpWebsocket::new(),
                vet,
                jar,
                tokens: Arc::new(Semaphore::new(DEFAULT_MAX_TABS)),
                tabs: Mutex::new(BTreeMap::new()),
                queue_wait: DEFAULT_QUEUE_WAIT,
                step_timeout: STEP_TIMEOUT,
                tab_idle: TAB_IDLE,
            }),
        }
    }

    /// `BROWSER_MAX_TABS`. Only before the first tab: the semaphore is built here.
    #[must_use]
    pub fn with_max_tabs(self, max_tabs: usize) -> Self {
        self.map(|inner| inner.tokens = Arc::new(Semaphore::new(max_tabs.max(1))))
    }

    /// `BROWSER_QUEUE_WAIT_SECS`.
    #[must_use]
    pub fn with_queue_wait(self, wait: Duration) -> Self {
        self.map(|inner| inner.queue_wait = wait)
    }

    /// Override the per-step ceiling.
    #[must_use]
    pub fn with_step_timeout(self, timeout: Duration) -> Self {
        self.map(|inner| inner.step_timeout = timeout)
    }

    /// Override how long an idle tab is kept.
    #[must_use]
    pub fn with_tab_idle(self, idle: Duration) -> Self {
        self.map(|inner| inner.tab_idle = idle)
    }

    /// Drive with a differently-tuned websocket — tests shorten its deadlines.
    #[must_use]
    pub fn with_driver(self, driver: CdpWebsocket) -> Self {
        self.map(|inner| inner.driver = driver)
    }

    /// Builders run before the `Arc` is shared, so `get_mut` always succeeds
    /// here; a builder called on a clone would be a programming error and is
    /// answered by leaving the value alone rather than by a panic.
    fn map(mut self, edit: impl FnOnce(&mut Inner)) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            edit(inner);
        }
        self
    }

    /// Tabs open right now. For tests and for `Debug`.
    pub fn open_tabs(&self) -> usize {
        self.inner.lock().len()
    }

    /// Pair an employee with a provisioned context. `user_data_dir` is `None`:
    /// persistence is the jar's, not a profile directory's.
    pub fn session_for(
        employee_id: agentos_domain::ids::EmployeeId,
        context: &Provisioned,
    ) -> BrowserSession {
        BrowserSession {
            employee_id,
            binding: context.binding(),
            user_data_dir: None,
        }
    }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Tab>> {
        self.tabs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Where Chrome is reachable *by address*: the host of `cdp_url` resolved
    /// now, because Chrome refuses a `Host` header that is a name (module
    /// docs) and because a container's address changes on restart. IPv4
    /// first: Chrome listens on `127.0.0.1` by default and a `localhost` that
    /// resolves to `::1` first would dial an ear that is not there.
    async fn endpoint(&self) -> Result<SocketAddr, ProviderError> {
        let host = self.cdp_url.host_str().ok_or(ProviderError::Terminal {
            code: "bad_cdp_url",
        })?;
        let port = self.cdp_url.port_or_known_default().unwrap_or(9222);
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| ProviderError::timeout())?
            .collect();
        addresses
            .iter()
            .find(|addr| matches!(addr.ip(), IpAddr::V4(_)))
            .or(addresses.first())
            .copied()
            .ok_or_else(ProviderError::timeout)
    }

    /// The browser endpoint: `GET /json/version` → `webSocketDebuggerUrl`,
    /// re-based on the address we actually reach Chrome at.
    async fn browser_ws(&self, at: SocketAddr) -> Result<String, ProviderError> {
        let version: Value = self
            .http
            .get(format!("http://{at}/json/version"))
            .send()
            .await
            .map_err(|_| ProviderError::timeout())?
            .json()
            .await
            .map_err(|_| ProviderError::timeout())?;
        let advertised = version["webSocketDebuggerUrl"]
            .as_str()
            .and_then(|raw| Url::parse(raw).ok())
            .ok_or(ProviderError::Terminal {
                code: "no_browser_endpoint",
            })?;
        Ok(format!("ws://{at}{}", advertised.path()))
    }

    /// The tab this context is driving, opened if there is none. Touches it.
    async fn tab(self: &Arc<Self>, ctx: &str) -> Result<String, ProviderError> {
        if let Some(tab) = self.lock().get_mut(ctx) {
            tab.last_used = Instant::now();
            return Ok(tab.page_url.clone());
        }
        let tab = self.open(ctx).await?;
        let page_url = tab.page_url.clone();
        self.lock().insert(ctx.to_owned(), tab);
        self.reap_later(ctx.to_owned());
        Ok(page_url)
    }

    /// Token, browser socket, context, target, cookies — in that order, and
    /// anything that fails after the context exists disposes it on the way
    /// out, or Chromium keeps a renderer nobody can reach.
    async fn open(&self, ctx: &str) -> Result<Tab, ProviderError> {
        let permit =
            tokio::time::timeout(self.queue_wait, Arc::clone(&self.tokens).acquire_owned())
                .await
                // Every tab is busy and has been for the whole wait: the turn is
                // better off retried later than parked with a terminal error.
                .map_err(|_| ProviderError::Retryable {
                    after: self.queue_wait,
                })?
                .map_err(|_| ProviderError::Terminal { code: "no_browser" })?;

        let at = self.endpoint().await?;
        let browser_ws = self.browser_ws(at).await?;
        let mut browser = self.driver.connect(&Secret::new(browser_ws)).await?;

        let context_id = browser
            .call("Target.createBrowserContext", json!({}))
            .await?["browserContextId"]
            .as_str()
            .ok_or(ProviderError::Terminal { code: NO_TARGET })?
            .to_owned();
        let target = browser
            .call(
                "Target.createTarget",
                json!({ "url": "about:blank", "browserContextId": context_id }),
            )
            .await;
        let target_id = match target.as_ref().map(|out| out["targetId"].as_str()) {
            Ok(Some(id)) => id.to_owned(),
            _ => {
                let _ = browser
                    .call(
                        "Target.disposeBrowserContext",
                        json!({ "browserContextId": context_id }),
                    )
                    .await;
                browser.close().await;
                return Err(target
                    .err()
                    .unwrap_or(ProviderError::Terminal { code: NO_TARGET }));
            }
        };
        browser.close().await;

        let page_url = format!("ws://{at}/devtools/page/{target_id}");
        let tab = Tab {
            context_id,
            target_id,
            page_url,
            last_used: Instant::now(),
            _permit: permit,
        };

        // The jar goes in before the first navigation, so the first request
        // already carries the login. A jar that will not parse or that Chrome
        // refuses is logged and skipped rather than fatal: the employee is
        // logged out, which is recoverable, where a tab that cannot open is
        // not.
        if let Some(jar) = self.jar.load(ctx).await? {
            let cookies: Vec<Value> =
                serde_json::from_str(jar.expose_for_transport()).unwrap_or_default();
            if !cookies.is_empty() {
                let mut page = self
                    .driver
                    .connect(&Secret::new(tab.page_url.clone()))
                    .await?;
                if page
                    .call("Network.setCookies", json!({ "cookies": cookies }))
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        ctx,
                        "chrome refused the employee's cookie jar; starting logged out"
                    );
                }
                page.close().await;
            }
        }
        Ok(tab)
    }

    /// Export the cookies, then tear the tab down. Best effort at every
    /// stage: a tab whose socket is already dead still has to give its
    /// context back, and the permit is returned when `tab` drops whatever
    /// Chrome said.
    async fn close(&self, ctx: &str, tab: Tab) {
        if let Ok(mut page) = self
            .driver
            .connect(&Secret::new(tab.page_url.clone()))
            .await
        {
            if let Ok(out) = page.call("Network.getAllCookies", json!({})).await
                && let Some(cookies) = out["cookies"].as_array()
            {
                let jar = Secret::new(Value::Array(cookie_params(cookies)).to_string());
                if let Err(err) = self.jar.save(ctx, &jar).await {
                    tracing::warn!(
                        ctx,
                        code = err.code(),
                        "the employee's cookies were not saved"
                    );
                }
            }
            page.close().await;
        }
        if let Ok(at) = self.endpoint().await
            && let Ok(browser_ws) = self.browser_ws(at).await
            && let Ok(mut browser) = self.driver.connect(&Secret::new(browser_ws)).await
        {
            let _ = browser
                .call("Target.closeTarget", json!({ "targetId": tab.target_id }))
                .await;
            let _ = browser
                .call(
                    "Target.disposeBrowserContext",
                    json!({ "browserContextId": tab.context_id }),
                )
                .await;
            browser.close().await;
        }
        drop(tab);
    }

    /// Take the tab out of the map and close it, if there is one.
    async fn close_tab(&self, ctx: &str) {
        let tab = self.lock().remove(ctx);
        if let Some(tab) = tab {
            self.close(ctx, tab).await;
        }
    }

    /// The reaper: sleeps until the tab has been idle for `tab_idle`, then
    /// closes it — unless a step touched it meanwhile, in which case it sleeps
    /// again. One task per open tab, gone when the tab is.
    fn reap_later(self: &Arc<Self>, ctx: String) {
        let inner = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let due = match inner.lock().get(&ctx) {
                    Some(tab) => tab.last_used + inner.tab_idle,
                    None => return,
                };
                tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
                let idle = {
                    let mut tabs = inner.lock();
                    match tabs.get(&ctx) {
                        None => return,
                        Some(tab) if tab.last_used.elapsed() >= inner.tab_idle => tabs.remove(&ctx),
                        Some(_) => None,
                    }
                };
                if let Some(tab) = idle {
                    inner.close(&ctx, tab).await;
                    return;
                }
            }
        });
    }

    /// After a navigation landed: is the page a wall?
    async fn wall_check(&self, page_url: &str) -> Result<(), ProviderError> {
        let mut page = self
            .driver
            .connect(&Secret::new(page_url.to_owned()))
            .await?;
        let answer = page.evaluate(WALL_CHECK.to_owned()).await;
        page.close().await;
        let answer = answer?;
        let title = answer[0].as_str().unwrap_or_default().to_ascii_lowercase();
        let status = answer[1].as_u64().unwrap_or_default();
        if matches!(status, 403 | 503) || BLOCKED_TITLES.iter().any(|wall| title.contains(wall)) {
            tracing::warn!(
                status,
                "the site answered with a wall; no proxy and no stealth here"
            );
            return Err(ProviderError::Terminal {
                code: BLOCKED_BY_SITE,
            });
        }
        Ok(())
    }
}

/// Does the tab outlive this error? Yes when the error is about **our step**
/// — a selector that matched nothing, a script that threw, an address that
/// did not load — because the page is still there and the model's next step
/// may name a better selector. No when it is about the browser: a dead
/// socket, a protocol refusal, a wall. Those tabs are closed so the next
/// step starts clean, with the cookies exported first.
fn tab_survives(err: &ProviderError) -> bool {
    matches!(
        err.code(),
        NO_SUCH_ELEMENT | SCRIPT_FAILED | NAVIGATION_FAILED
    )
}

#[async_trait]
impl BrowserProvider for ChromeBrowser {
    async fn ensure_context(&self, ctx: &EnsureCtx) -> Result<Provisioned, ProviderError> {
        if let Some(existing) = &ctx.existing
            && existing.provider == PROVIDER
        {
            return Ok(Provisioned::new(PROVIDER, existing.external_id.clone()));
        }
        // Nothing is created at Chromium: a CDP context does not survive the
        // process, so the id is ours — the tag, for `HttpBrowser`'s reason
        // (unique across seats, stable across boots) — and the context is
        // recreated at every task. The jar is the only durable thing.
        Ok(Provisioned::new(PROVIDER, format!("ctx-{}", ctx.tag())))
    }

    async fn act(
        &self,
        session: &BrowserSession,
        step: BrowserStep<'_>,
    ) -> Result<BrowserOutcome, ProviderError> {
        let inner = &self.inner;
        let ctx = session.binding.external_id.as_str();
        match &step {
            // The park: `effects` sends the session here after a refused
            // landing, and it is the one « end of task » the trait can say.
            // Cookies out, tab down, token back.
            BrowserStep::Goto(url) if **url == blank_page() => {
                inner.close_tab(ctx).await;
                return Ok(BrowserOutcome::Navigated(blank_page()));
            }
            // A question about a tab that is not open needs no tab: it is
            // nowhere, and nowhere has no host.
            BrowserStep::Location if !inner.lock().contains_key(ctx) => {
                return Ok(BrowserOutcome::Navigated(blank_page()));
            }
            // Before a tab is even opened, let alone `Page.navigate` sent:
            // a refused address costs Chromium nothing.
            BrowserStep::Goto(url) => {
                inner.vet.resolve_and_vet(url).await?;
            }
            _ => {}
        }

        let page_url = inner.tab(ctx).await?;
        let navigating = matches!(step, BrowserStep::Goto(_));
        let drive = async {
            let outcome = inner
                .driver
                .run(&Secret::new(page_url.clone()), &step)
                .await?;
            if navigating {
                inner.wall_check(&page_url).await?;
            }
            Ok(outcome)
        };
        let outcome = match tokio::time::timeout(inner.step_timeout, drive).await {
            Ok(outcome) => outcome,
            Err(_) => Err(ProviderError::timeout()),
        };

        match &outcome {
            Ok(_) => {
                if let Some(tab) = inner.lock().get_mut(ctx) {
                    tab.last_used = Instant::now();
                }
            }
            Err(err) if tab_survives(err) => {}
            Err(_) => inner.close_tab(ctx).await,
        }
        outcome
    }

    async fn release(&self, binding: &ProviderBinding) -> Result<(), ProviderError> {
        // The jar is the only thing that exists. A tab still open under this
        // context would save the jar back on close, so it goes first.
        self.inner.close_tab(&binding.external_id).await;
        self.inner.jar.forget(&binding.external_id).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Where a **test** site must advertise itself so the Chromium under test can
/// reach it — `BROWSER_TEST_SITE_HOST`, loopback when unset.
///
/// `pub` and outside `cfg(test)` because `agentos-app`'s end-to-end read needs
/// the same answer and cannot see this crate's test module. Nothing in
/// production reads it: a deployment has no test site.
pub fn test_site_host() -> IpAddr {
    std::env::var("BROWSER_TEST_SITE_HOST")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use agentos_domain::ids::{EmployeeId, Slug, TenantId};
    use chrono::Utc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::HandshakeError;

    use super::*;
    use crate::browser_http::PinnedHost;
    use crate::cdp::{Pipe, WsConn, drain_pipe, fill_pipe};

    const SITE: &str = "portal.example.com";
    /// Chromium's own words, verbatim.
    const HOST_REFUSED: &str = "Host header is specified and is not an IP address or localhost.";

    // -- a fake Chrome: `/json/version` over HTTP, `Target.*`/`Network.*`/
    //    `Page.*`/`Runtime.*` over websocket, on one loopback port ------------
    //
    // One listener, because the adapter builds every URL from the address it
    // fetched `/json/version` at; a fake that answered HTTP on one port and
    // websocket on another would pass an adapter that builds them wrong.

    #[derive(Default)]
    struct FakeState {
        /// (websocket path, frame) for every command, in order.
        seen: Vec<(String, Value)>,
        contexts: usize,
        targets: usize,
        /// Where the page is, as `location.href` will answer.
        here: String,
        /// What `Network.getAllCookies` answers.
        cookies: Vec<Value>,
        /// What the wall check answers: (title, status).
        page: (String, u64),
        /// Answer nothing to `Runtime.evaluate` on a page.
        hang_page: bool,
        /// Every `Host` header the HTTP endpoint was asked under.
        hosts: Vec<String>,
    }

    struct FakeChrome {
        addr: SocketAddr,
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeChrome {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let state = Arc::new(Mutex::new(FakeState {
                here: "about:blank".to_owned(),
                page: ("Portal".to_owned(), 200),
                ..FakeState::default()
            }));
            let served = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((io, _)) = listener.accept().await {
                    let state = Arc::clone(&served);
                    tokio::spawn(async move { serve(io, addr, state).await });
                }
            });
            Self { addr, state }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn methods(&self) -> Vec<String> {
            self.state()
                .seen
                .iter()
                .filter_map(|(_, frame)| frame["method"].as_str().map(str::to_owned))
                .collect()
        }

        fn frames(&self, method: &str) -> Vec<(String, Value)> {
            self.state()
                .seen
                .iter()
                .filter(|(_, frame)| frame["method"] == method)
                .cloned()
                .collect()
        }

        fn browser(&self, jar: Arc<dyn CookieJar>) -> ChromeBrowser {
            ChromeBrowser::new(
                Url::parse(&format!("http://{}", self.addr)).expect("url"),
                Arc::new(PinnedHost::new(SITE, IpAddr::V4(Ipv4Addr::LOCALHOST))),
                jar,
            )
            .with_driver(
                CdpWebsocket::new()
                    .with_connect_timeout(Duration::from_millis(500))
                    .with_command_timeout(Duration::from_millis(300)),
            )
            .with_queue_wait(Duration::from_millis(200))
            .with_step_timeout(Duration::from_secs(2))
        }
    }

    async fn serve(mut io: TcpStream, addr: SocketAddr, state: Arc<Mutex<FakeState>>) {
        // HTTP or websocket? The first bytes say, and `peek` leaves them for
        // whichever handshake reads them next.
        let mut head = [0u8; 512];
        let n = io.peek(&mut head).await.unwrap_or(0);
        let head = String::from_utf8_lossy(&head[..n]);
        if !head.to_ascii_lowercase().contains("upgrade: websocket") {
            let mut sink = [0u8; 4096];
            let _ = io.read(&mut sink).await;
            let host = head
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Host: ")
                        .or_else(|| line.strip_prefix("host: "))
                })
                .unwrap_or_default()
                .trim()
                .to_owned();
            state.lock().unwrap().hosts.push(host.clone());
            // Measured on Chromium 151 and 152 (`devtools_http_handler.cc`,
            // `RequestIsSafeToServe`): a `Host` that is neither an address
            // nor `localhost` is a 500 with exactly this sentence. The fake
            // says it too, so an adapter that dials the name fails here.
            let name = host
                .rsplit_once(':')
                .map_or(host.as_str(), |(name, _)| name);
            let response = if name == "localhost"
                || name.trim_matches(['[', ']']).parse::<IpAddr>().is_ok()
            {
                // Chrome writes the loopback address *it* listens on, whatever
                // `Host` asked — which is why the adapter re-bases the path.
                let body = json!({
                    "Browser": "FakeChrome/1",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9/devtools/browser/fake-browser-id",
                })
                .to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            } else {
                format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n{HOST_REFUSED}",
                    HOST_REFUSED.len()
                )
            };
            let _ = io.write_all(response.as_bytes()).await;
            let _ = io.shutdown().await;
            return;
        }
        let _ = addr;

        // The websocket path is what tells a browser socket from a page
        // socket, and what proves the adapter built the page URL right.
        let path = Arc::new(Mutex::new(String::new()));
        let seen_path = Arc::clone(&path);
        #[allow(clippy::result_large_err)]
        let callback = move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                             response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            *seen_path.lock().unwrap() = request.uri().path().to_owned();
            Ok(response)
        };
        let mut attempt = tokio_tungstenite::tungstenite::accept_hdr(Pipe::default(), callback);
        let mut conn = loop {
            match attempt {
                Ok(ws) => break WsConn { ws, io },
                Err(HandshakeError::Interrupted(mut mid)) => {
                    let pipe = mid.get_mut().get_mut();
                    if drain_pipe(pipe, &mut io).await.is_err()
                        || fill_pipe(pipe, &mut io).await.is_err()
                    {
                        return;
                    }
                    attempt = mid.handshake();
                }
                Err(HandshakeError::Failure(_)) => return,
            }
        };
        if conn.drain().await.is_err() {
            return;
        }
        let path = path.lock().unwrap().clone();

        while let Ok(message) = conn.recv().await {
            let text = match message {
                Message::Text(text) => text,
                Message::Close(_) => break,
                _ => continue,
            };
            let request: Value = serde_json::from_str(&text).expect("the adapter sent non-JSON");
            let answer = {
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                state.seen.push((path.clone(), request.clone()));
                answer(&path, &request, &mut state)
            };
            let Some(result) = answer else {
                // Hang: the adapter's deadline has to be what ends this.
                tokio::time::sleep(Duration::from_secs(5)).await;
                return;
            };
            let frame = json!({ "id": request["id"], "result": result });
            if conn.send(Message::text(frame.to_string())).await.is_err() {
                return;
            }
        }
    }

    fn answer(path: &str, request: &Value, state: &mut FakeState) -> Option<Value> {
        let method = request["method"].as_str().unwrap_or_default();
        let on_browser = path.starts_with("/devtools/browser/");
        let on_page = path.starts_with("/devtools/page/");
        Some(match method {
            "Target.createBrowserContext" if on_browser => {
                state.contexts += 1;
                json!({ "browserContextId": format!("ctx{}", state.contexts) })
            }
            "Target.createTarget" if on_browser => {
                state.targets += 1;
                json!({ "targetId": format!("target{}", state.targets) })
            }
            "Target.closeTarget" if on_browser => json!({ "success": true }),
            "Target.disposeBrowserContext" if on_browser => json!({}),
            "Network.setCookies" if on_page => json!({}),
            "Network.getAllCookies" if on_page => json!({ "cookies": state.cookies }),
            "Page.navigate" if on_page => {
                state.here = request["params"]["url"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                json!({ "frameId": "frame-1" })
            }
            "Runtime.evaluate" if on_page => {
                if state.hang_page {
                    return None;
                }
                let expression = request["params"]["expression"].as_str().unwrap_or_default();
                if expression == "location.href" {
                    json!({ "result": { "type": "string", "value": state.here } })
                } else if expression == WALL_CHECK {
                    json!({ "result": { "type": "object", "value": [state.page.0, state.page.1] } })
                } else if expression.contains("innerText") {
                    json!({ "result": { "type": "string", "value": "Book a trip" } })
                } else {
                    json!({ "result": { "type": "boolean", "value": !expression.contains("#missing") } })
                }
            }
            other => panic!("the adapter sent {other} on {path}"),
        })
    }

    fn ctx() -> EnsureCtx {
        EnsureCtx::new(
            TenantId::new_v7(Utc::now()),
            EmployeeId::new_v7(Utc::now()),
            Slug::parse("ada").expect("slug"),
            "browser",
        )
    }

    async fn session(p: &ChromeBrowser) -> BrowserSession {
        let provisioned = p.ensure_context(&ctx()).await.expect("ensure");
        ChromeBrowser::session_for(EmployeeId::new_v7(Utc::now()), &provisioned)
    }

    fn site(path: &str) -> Url {
        Url::parse(&format!("https://{SITE}{path}")).expect("url")
    }

    async fn eventually(mut condition: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    // -- the contract -----------------------------------------------------------

    #[tokio::test]
    async fn the_chrome_browser_satisfies_the_contract() {
        let chrome = FakeChrome::start().await;
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        crate::browser::contract_suite_on(&p, &site("/login")).await;
        // The contract released the context; the tab went with it.
        assert_eq!(p.open_tabs(), 0);
    }

    /// The exact CDP conversation one task is: what the doc promises, in
    /// order, on the endpoint it promises. The page socket is the target's
    /// own URL and the browser socket is the advertised path re-based on the
    /// address we reached Chrome at — not the `127.0.0.1:9` it advertised.
    #[tokio::test]
    async fn one_task_is_context_target_cookies_steps_cookies_close_dispose() {
        let chrome = FakeChrome::start().await;
        let jar = Arc::new(MemoryCookieJar::new());
        jar.save("unused", &Secret::new("[]")).await.unwrap();
        let p = chrome.browser(jar.clone());
        let s = session(&p).await;
        jar.save(
            &s.binding.external_id,
            &Secret::new(
                r#"[{"name":"seat","value":"ada","domain":"portal.example.com","path":"/"}]"#,
            ),
        )
        .await
        .unwrap();

        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap(),
            BrowserOutcome::Navigated(site("/login"))
        );
        assert_eq!(
            p.act(&s, BrowserStep::Location).await.unwrap(),
            BrowserOutcome::Navigated(site("/login")),
            "the tab survived between two steps"
        );
        assert_eq!(p.open_tabs(), 1);
        p.act(&s, BrowserStep::Goto(&blank_page())).await.unwrap();
        assert_eq!(p.open_tabs(), 0, "a park closes the tab");

        assert_eq!(
            chrome.methods(),
            [
                "Target.createBrowserContext",
                "Target.createTarget",
                "Network.setCookies",
                "Page.navigate",
                "Runtime.evaluate", // location.href
                "Runtime.evaluate", // the wall check
                "Runtime.evaluate", // Location
                "Network.getAllCookies",
                "Target.closeTarget",
                "Target.disposeBrowserContext",
            ]
        );
        let paths: Vec<String> = chrome
            .state()
            .seen
            .iter()
            .map(|(path, _)| path.clone())
            .collect();
        assert_eq!(paths[0], "/devtools/browser/fake-browser-id");
        assert_eq!(paths[3], "/devtools/page/target1");
        let create = &chrome.frames("Target.createTarget")[0].1;
        assert_eq!(create["params"]["browserContextId"], "ctx1");
        assert_eq!(create["params"]["url"], "about:blank");
        assert_eq!(
            chrome.frames("Target.disposeBrowserContext")[0].1["params"]["browserContextId"],
            "ctx1"
        );
        assert_eq!(
            chrome.frames("Target.closeTarget")[0].1["params"]["targetId"],
            "target1"
        );
    }

    // -- the semaphore ----------------------------------------------------------

    /// Four tasks, three tokens: the fourth waits `queue_wait` and is told to
    /// come back, and a tab that closes lets it in.
    #[tokio::test]
    async fn the_fourth_tab_waits_then_is_retryable_until_one_closes() {
        let chrome = FakeChrome::start().await;
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let mut sessions = Vec::new();
        for _ in 0..4 {
            sessions.push(session(&p).await);
        }
        for s in &sessions[..3] {
            p.act(s, BrowserStep::Goto(&site("/login")))
                .await
                .expect("a tab each");
        }
        assert_eq!(p.open_tabs(), 3);

        let started = Instant::now();
        let err = p
            .act(&sessions[3], BrowserStep::Goto(&site("/login")))
            .await
            .expect_err("no token left");
        assert!(err.is_retryable(), "{err:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "did not wait"
        );
        assert_eq!(chrome.state().targets, 3, "a fourth renderer was launched");

        // Disarm: park one, and the fourth gets in.
        p.act(&sessions[0], BrowserStep::Goto(&blank_page()))
            .await
            .unwrap();
        p.act(&sessions[3], BrowserStep::Goto(&site("/login")))
            .await
            .expect("a token came back");
        assert_eq!(p.open_tabs(), 3);
    }

    // -- the cookie jar ---------------------------------------------------------

    /// What `getAllCookies` handed the previous task is what `setCookies`
    /// receives on the next — in `CookieParam` shape, not `Cookie` shape.
    #[tokio::test]
    async fn the_jar_goes_out_on_close_and_comes_back_in_on_open() {
        let chrome = FakeChrome::start().await;
        chrome.state().cookies = vec![json!({
            "name": "seat", "value": "ada", "domain": "portal.example.com", "path": "/",
            "expires": -1, "size": 7, "httpOnly": true, "secure": true, "session": true,
            "sameSite": "Lax", "priority": "Medium", "partitionKey": { "topLevelSite": "x" }
        })];
        let jar = Arc::new(MemoryCookieJar::new());
        let p = chrome.browser(jar.clone());
        let s = session(&p).await;

        // First task: nothing to inject, so no `setCookies` at all.
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();
        assert!(chrome.frames("Network.setCookies").is_empty());
        p.act(&s, BrowserStep::Goto(&blank_page())).await.unwrap();
        assert_eq!(jar.contexts(), std::slice::from_ref(&s.binding.external_id));

        // Second task: the jar goes in before the navigation.
        p.act(&s, BrowserStep::Goto(&site("/account")))
            .await
            .unwrap();
        let set = chrome.frames("Network.setCookies");
        assert_eq!(set.len(), 1);
        assert_eq!(
            set[0].1["params"]["cookies"],
            json!([{
                "name": "seat", "value": "ada", "domain": "portal.example.com", "path": "/",
                "httpOnly": true, "secure": true, "sameSite": "Lax"
            }]),
            "a Cookie was replayed as a CookieParam"
        );
        let order = chrome.methods();
        let set_at = order
            .iter()
            .rposition(|m| m == "Network.setCookies")
            .unwrap();
        let nav_at = order.iter().rposition(|m| m == "Page.navigate").unwrap();
        assert!(set_at < nav_at, "{order:?}");

        // Release throws the jar away, and that is all it has to do.
        p.release(&s.binding).await.unwrap();
        assert!(jar.contexts().is_empty());
        assert_eq!(p.open_tabs(), 0);
    }

    // -- teardown on failure ----------------------------------------------------

    /// A step whose socket never answers: the tab is closed — cookies out,
    /// target closed, context disposed — and the token comes back.
    #[tokio::test]
    async fn a_step_that_fails_still_closes_the_target_and_disposes_the_context() {
        let chrome = FakeChrome::start().await;
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();

        chrome.state().hang_page = true;
        let err = p
            .act(&s, BrowserStep::Click("#next"))
            .await
            .expect_err("hung");
        assert!(err.is_retryable(), "{err:?}");
        chrome.state().hang_page = false;

        assert_eq!(p.open_tabs(), 0);
        assert!(
            eventually(|| {
                let methods = chrome.methods();
                methods.contains(&"Target.closeTarget".to_owned())
                    && methods.contains(&"Target.disposeBrowserContext".to_owned())
            })
            .await
        );
        assert_eq!(p.inner.tokens.available_permits(), DEFAULT_MAX_TABS);

        // Disarm: an error about *our* selector keeps the tab.
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();
        let err = p
            .act(&s, BrowserStep::Click("#missing"))
            .await
            .expect_err("no such element");
        assert_eq!(err.code(), NO_SUCH_ELEMENT);
        assert_eq!(
            p.open_tabs(),
            1,
            "a wrong selector is not a reason to lose the page"
        );
    }

    /// An idle tab is reaped, with its cookies.
    #[tokio::test]
    async fn an_idle_tab_is_closed_by_the_reaper() {
        let chrome = FakeChrome::start().await;
        chrome.state().cookies = vec![json!({ "name": "seat", "value": "ada" })];
        let jar = Arc::new(MemoryCookieJar::new());
        let p = chrome
            .browser(jar.clone())
            .with_tab_idle(Duration::from_millis(100));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();
        assert_eq!(p.open_tabs(), 1);
        assert!(
            eventually(|| p.open_tabs() == 0).await,
            "the reaper never came"
        );
        assert!(
            eventually(|| !jar.contexts().is_empty()).await,
            "reaped without saving"
        );
    }

    // -- the wall -----------------------------------------------------------------

    #[tokio::test]
    async fn a_challenge_page_or_a_403_is_blocked_by_site() {
        let chrome = FakeChrome::start().await;
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;

        for page in [
            ("Just a moment...".to_owned(), 200),
            ("Portal".to_owned(), 403),
            ("Access Denied".to_owned(), 200),
            ("Portal".to_owned(), 503),
        ] {
            chrome.state().page = page.clone();
            let err = p
                .act(&s, BrowserStep::Goto(&site("/login")))
                .await
                .expect_err("a wall");
            assert_eq!(err.code(), BLOCKED_BY_SITE, "{page:?}");
            assert!(
                !err.is_retryable(),
                "retrying a wall from the same address is the same wall"
            );
            assert_eq!(p.open_tabs(), 0, "the tab on a wall is closed");
        }
        // Disarm: an ordinary page is not a wall.
        chrome.state().page = ("Attention to detail".to_owned(), 200);
        p.act(&s, BrowserStep::Goto(&site("/login")))
            .await
            .expect("not a wall");
    }

    // -- the Host header ----------------------------------------------------------------

    /// `BROWSER_CDP_URL` names a service (`http://browser:9222`) and Chromium
    /// refuses a `Host` that is a name. The adapter resolves the name and
    /// dials the address; the fake refuses the name with Chromium's exact
    /// sentence, and the disarm half proves the fake actually does.
    #[tokio::test]
    async fn the_cdp_host_is_resolved_and_dialled_by_address_never_by_name() {
        let chrome = FakeChrome::start().await;
        // Disarm first: a client that sends the name gets the 500.
        let client = reqwest::Client::builder()
            .resolve("browser", chrome.addr)
            .build()
            .unwrap();
        let refused = client
            .get(format!(
                "http://browser:{}/json/version",
                chrome.addr.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status().as_u16(), 500);
        assert_eq!(refused.text().await.unwrap(), HOST_REFUSED);

        // The adapter, given a *name*, arrives with the address.
        let p = ChromeBrowser::new(
            Url::parse(&format!("http://localhost:{}", chrome.addr.port())).unwrap(),
            Arc::new(PinnedHost::new(SITE, IpAddr::V4(Ipv4Addr::LOCALHOST))),
            Arc::new(MemoryCookieJar::new()),
        )
        .with_driver(CdpWebsocket::new().with_command_timeout(Duration::from_millis(300)));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login")))
            .await
            .expect("navigate");
        let hosts = chrome.state().hosts.clone();
        assert_eq!(
            hosts,
            [
                format!("browser:{}", chrome.addr.port()),
                chrome.addr.to_string()
            ]
        );
        // And the page socket is on the same address, not on what Chromium
        // advertised (`127.0.0.1:9`) and not on the name.
        let (page_path, _) = chrome.frames("Page.navigate")[0].clone();
        assert_eq!(page_path, "/devtools/page/target1");
    }

    // -- the address check ----------------------------------------------------------

    /// A private address is refused by the vet before a tab is opened, let
    /// alone `Page.navigate` sent.
    #[tokio::test]
    async fn a_private_url_is_refused_before_any_tab_or_navigation() {
        let chrome = FakeChrome::start().await;
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;

        let err = p
            .act(
                &s,
                BrowserStep::Goto(&Url::parse("http://10.0.0.1/admin").unwrap()),
            )
            .await
            .expect_err("not the pinned host");
        assert_eq!(err.code(), "blocked_address");
        assert!(chrome.methods().is_empty(), "{:?}", chrome.methods());
        assert_eq!(p.open_tabs(), 0);
        // And the session is nowhere, without a tab having been spent on the
        // question.
        assert_eq!(
            p.act(&s, BrowserStep::Location).await.unwrap(),
            BrowserOutcome::Navigated(blank_page())
        );
        assert!(chrome.methods().is_empty());
    }

    // -- a real Chromium --------------------------------------------------------------
    //
    // `BROWSER_CDP_URL=http://127.0.0.1:9222`, or these skip — the same
    // discipline as `DATABASE_URL`. Launch it with:
    //
    //   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    //     --headless=new --remote-debugging-port=9222 --user-data-dir=$(mktemp -d) \
    //     --host-resolver-rules="MAP portal.example.com 127.0.0.1" about:blank &
    //
    // The resolver rule is what `effects.rs`'s end-to-end read needs
    // (`Domain::parse` refuses an IP literal); the suites here reach the site
    // as `127.0.0.1` and need no rule.

    fn real_chrome() -> Option<Url> {
        let Ok(raw) = std::env::var("BROWSER_CDP_URL") else {
            eprintln!("SKIP: BROWSER_CDP_URL is unset; the Chromium tests need a real browser");
            return None;
        };
        Some(Url::parse(&raw).expect("BROWSER_CDP_URL is a URL"))
    }

    /// Where the browser must look for the site these tests serve.
    ///
    /// Locally the browser and the site share a loopback. In CI (siglair's
    /// workflows, 2026-09-10) Chromium runs in a service **container**, where
    /// `127.0.0.1` is the container itself — three tests failed with
    /// `navigation_failed` for exactly that. So the site binds every interface
    /// and advertises the address the runner hands it in
    /// `BROWSER_TEST_SITE_HOST`; unset means loopback, as before.
    pub(crate) fn site_host() -> IpAddr {
        super::test_site_host()
    }

    /// A site Chromium can actually fetch: a login page, a page that sets a
    /// cookie, a page that echoes the cookies it received, and a page that
    /// only says something once its script has run.
    async fn real_site() -> SocketAddr {
        use axum::Router;
        use axum::http::{HeaderMap, HeaderValue, header};
        use axum::response::{Html, IntoResponse, Response};
        use axum::routing::get;

        async fn login() -> Html<&'static str> {
            Html("<!doctype html><title>Portal</title><h1>Book a trip</h1>")
        }
        async fn set() -> Response {
            (
                [(
                    header::SET_COOKIE,
                    HeaderValue::from_static("seat=ada; Path=/; HttpOnly"),
                )],
                Html("<title>Set</title><p>cookie set</p>"),
            )
                .into_response()
        }
        async fn echo(headers: HeaderMap) -> Html<String> {
            let cookie = headers
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("none");
            Html(format!("<title>Echo</title><p id=\"cookie\">{cookie}</p>"))
        }
        async fn app() -> Html<&'static str> {
            Html(
                "<!doctype html><title>App</title><div id=\"app\"></div>\
                 <script>document.getElementById('app').textContent='rendu'</script>",
            )
        }
        async fn wall() -> Response {
            (
                axum::http::StatusCode::FORBIDDEN,
                Html("<title>Portal</title><p>go away</p>"),
            )
                .into_response()
        }
        let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind");
        let addr = SocketAddr::new(site_host(), listener.local_addr().expect("addr").port());
        let app = Router::new()
            .route("/login", get(login))
            .route("/set", get(set))
            .route("/echo", get(echo))
            .route("/app", get(app))
            .route("/wall", get(wall));
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        addr
    }

    fn real_browser(cdp: Url, jar: Arc<dyn CookieJar>) -> ChromeBrowser {
        ChromeBrowser::new(
            cdp,
            Arc::new(PinnedHost::new(site_host().to_string(), site_host())),
            jar,
        )
    }

    async fn text(
        p: &ChromeBrowser,
        s: &BrowserSession,
        sel: &str,
    ) -> Result<String, ProviderError> {
        match p.act(s, BrowserStep::Text(sel)).await? {
            BrowserOutcome::Text(text) => Ok(text.into_inner_for_rendering()),
            other => panic!("a text read answered {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_real_chromium_satisfies_the_contract() {
        let Some(cdp) = real_chrome() else { return };
        let addr = real_site().await;
        let p = real_browser(cdp, Arc::new(MemoryCookieJar::new()));
        let url = Url::parse(&format!("http://{addr}/login")).unwrap();
        crate::browser::contract_suite_on(&p, &url).await;
        assert_eq!(p.open_tabs(), 0);
    }

    /// The whole reason this adapter exists over `HttpBrowser`: a page that
    /// says something only after its script ran. The `GET` browser reads the
    /// empty shell — measured here, beside — and Chromium reads the word.
    #[tokio::test]
    async fn a_real_chromium_reads_a_page_rendered_by_javascript() {
        let Some(cdp) = real_chrome() else { return };
        let addr = real_site().await;
        let url = Url::parse(&format!("http://{addr}/app")).unwrap();

        let p = real_browser(cdp, Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&url)).await.expect("navigate");
        assert_eq!(text(&p, &s, "#app").await.unwrap(), "rendu");
        p.release(&s.binding).await.unwrap();

        let http = crate::browser_http::HttpBrowser::new(Arc::new(PinnedHost::new(
            site_host().to_string(),
            site_host(),
        )));
        let hs = ChromeBrowser::session_for(
            EmployeeId::new_v7(Utc::now()),
            &http.ensure_context(&ctx()).await.unwrap(),
        );
        http.act(&hs, BrowserStep::Goto(&url)).await.expect("fetch");
        match http.act(&hs, BrowserStep::Text("#app")).await.unwrap() {
            BrowserOutcome::Text(text) => assert_eq!(
                text.into_inner_for_rendering(),
                "",
                "the GET browser cannot run the script"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// The jar, on a real Chromium: a cookie the site set in one task is on
    /// the request the next task makes, through a fresh context.
    #[tokio::test]
    async fn a_real_chromium_stays_logged_in_across_tasks_through_the_jar() {
        let Some(cdp) = real_chrome() else { return };
        let addr = real_site().await;
        let jar = Arc::new(MemoryCookieJar::new());
        let p = real_browser(cdp, jar.clone());
        let s = session(&p).await;
        let at = |path: &str| Url::parse(&format!("http://{addr}{path}")).unwrap();

        p.act(&s, BrowserStep::Goto(&at("/set")))
            .await
            .expect("set");
        p.act(&s, BrowserStep::Goto(&blank_page()))
            .await
            .expect("park");
        assert!(!jar.contexts().is_empty(), "nothing was exported");

        p.act(&s, BrowserStep::Goto(&at("/echo")))
            .await
            .expect("echo");
        assert_eq!(text(&p, &s, "#cookie").await.unwrap(), "seat=ada");
        p.release(&s.binding).await.unwrap();

        // Disarm: a context with no jar arrives without the cookie.
        let fresh = session(&p).await;
        p.act(&fresh, BrowserStep::Goto(&at("/echo")))
            .await
            .expect("echo");
        assert_eq!(text(&p, &fresh, "#cookie").await.unwrap(), "none");
        p.release(&fresh.binding).await.unwrap();
    }

    #[tokio::test]
    async fn a_real_chromium_reports_a_403_as_blocked_by_site() {
        let Some(cdp) = real_chrome() else { return };
        let addr = real_site().await;
        let p = real_browser(cdp, Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;
        let err = p
            .act(
                &s,
                BrowserStep::Goto(&Url::parse(&format!("http://{addr}/wall")).unwrap()),
            )
            .await
            .expect_err("a 403");
        assert_eq!(err.code(), BLOCKED_BY_SITE);
        p.release(&s.binding).await.unwrap();
    }
}
