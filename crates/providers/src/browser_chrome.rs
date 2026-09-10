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
//!
//! # La deuxième phase : raconter, ressembler, et rapporter ce qui n'est pas une page
//!
//! Trois ajouts du 2026-09-10, tous en logiciel — `docs/BROWSER.md` § v2 trie
//! ce qui se construit de ce qui s'achète, et rien ici ne s'achète.
//!
//! * **Narration.** L'adaptateur dit ce qu'il fait à un
//!   [`BrowserObserver`](crate::browser_observer::BrowserObserver) : une tâche
//!   commence à l'ouverture d'un onglet, chaque étape est nommée et mesurée,
//!   la tâche finit à sa fermeture — park, erreur ou moissonneur, les trois
//!   fins que ce module connaissait déjà. Il ne sait pas qui écoute : le
//!   journal et la vue en direct sont deux lecteurs du même port, écrits
//!   ailleurs. Tant que personne ne regarde ([`BrowserObserver::wants_frames`]
//!   à faux) aucune image n'est capturée — un screencast qui tourne pour
//!   personne, c'est un encodeur JPEG par onglet sur un VPS à 2 vCPU.
//! * **Furtivité, en logiciel.** Un script à chaque document et un
//!   `Emulation.setUserAgentOverride` : voir [`stealth_script`] pour ce que
//!   ça couvre et surtout pour ce que ça ne couvre pas. Le plafond est écrit
//!   là et dans `PROVIDERS.md` ; `blocked_by_site` reste la sortie honnête.
//! * **Documents.** Une navigation dont la réponse n'est pas HTML n'est plus
//!   une erreur : elle revient en [`BrowserOutcome::Document`], et c'est
//!   `effects.rs` qui la range au classeur. La v2 y ouvrait une **deuxième
//!   socket** ; la v3 l'a repliée dans celle de l'onglet — voir plus bas.
//!
//! # L'émulation est par contexte, et le port ressemble au pot de cookies
//!
//! [`BrowserProfiles`] est indexé par l'identifiant de contexte pour la raison
//! que [`CookieJar`] donne : c'est la seule chose que ce module tient des deux
//! côtés. Le défaut — `fr-FR`, `Europe/Paris`, 1366×768, sans position — n'est
//! pas neutre et c'est voulu : un employé sans profil est un employé français,
//! pas un employé américain dans un fuseau UTC, ce que `--headless` annonce
//! sinon.
//!
//! # La troisième phase : les prises, et la flotte
//!
//! Trois ajouts du 2026-09-10, et le tri du dépôt tient : le **logiciel** se
//! construit, la **ressource** se paie par une clé que le client apporte. Rien
//! ici n'ouvre de compte nulle part, et un déploiement sans clé se comporte
//! exactement comme la v2.
//!
//! * **Le proxy est passé au contexte, pas au processus.**
//!   `Target.createBrowserContext { proxyServer, proxyBypassList }` — les deux
//!   noms sont relevés le 2026-09-10 dans `GET /json/protocol` de Chrome
//!   152.0.7977.83, où ils sont décrits « similar to the one passed to
//!   `--proxy-server` ». C'est *pourquoi* on ne touche pas à `--proxy-server` :
//!   un drapeau de processus voudrait un Chromium par locataire, là où un
//!   paramètre de contexte donne une adresse de sortie par tâche sans
//!   redémarrer quoi que ce soit. Le port est [`Proxies`], indexé par contexte
//!   comme [`CookieJar`], et sa table est au locataire (migration 0098).
//! * **Un défi de captcha est nommé, il n'est plus un mur.** Trois signatures
//!   lues dans [`WALL_CHECK`], une seule évaluation avec la détection de mur
//!   parce que les deux attendent le même `DOMContentLoaded`. Sans solveur
//!   branché : `Terminal { code: "captcha" }`, distinct de [`BLOCKED_BY_SITE`]
//!   — voir [`crate::captcha`] pour pourquoi la distinction se paie.
//! * **La flotte.** [`Fleet`] : `BROWSER_CDP_URL` accepte une liste, chaque
//!   point a son sémaphore, sa santé et ses onglets. **Rien n'attache un
//!   employé à une machine** — le pot de cookies est chez nous, dans une
//!   colonne scellée, et le profil aussi : c'est exactement ce qui rend la
//!   flotte possible, et c'est ce qui manquait à un `--user-data-dir` par
//!   employé. Une tâche reste sur son point pour toute sa vie parce que
//!   l'onglet y est, pas parce que l'employé y est.
//!
//! # Une seule session `Fetch` par onglet
//!
//! La v2 avait deux usages de `Fetch` en tête : la navigation (un document qui
//! n'est pas une page) et, maintenant, l'authentification du proxy. **Deux
//! sockets qui activent `Fetch` sur la même cible, c'est deux interceptions qui
//! se disputent le même `requestPaused`.** Donc il n'y en a qu'une : la socket
//! qui tenait déjà l'habillage ([`Tab::dressed`], vivante aussi longtemps que
//! l'onglet et déjà en train de lire des événements pour ne pas les
//! accumuler) porte aussi `Fetch.enable`, et sa boucle est le seul
//! consommateur. Voir [`Inner::pump`] pour ce que la mesure a corrigé dans les
//! motifs.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;
use uuid::Uuid;

use crate::browser::{
    BrowserOutcome, BrowserProvider, BrowserSession, BrowserStep, NO_SUCH_ELEMENT, blank_page,
};
use crate::browser_browserbase::CdpDriver as _;
use crate::browser_http::UrlVet;
use crate::browser_observer::{BrowserObserver, NoopObserver, StepOutcome, StepReport, TaskRef};
use crate::captcha::{CAPTCHA, CaptchaSolver, Challenge, ChallengeKind, NoSolver};
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
/// The navigation answered with a document bigger than [`MAX_DOCUMENT`].
///
/// Terminal, and deliberately not a truncation: half a PDF filed under a name
/// that says « tariff » is worse than no PDF, because the second is visibly
/// missing and the first reads as complete.
pub const TOO_LARGE: &str = "too_large";

/// The ceiling on a document a navigation brings back, in bytes.
///
/// 8 Mo, and the number is the socket's rather than the classeur's: the body
/// crosses the CDP websocket base64-encoded, so 8 Mo of PDF is ~10,7 Mo of
/// frame held in memory twice — once decoded, once not — on a container capped
/// at 1 Go with two other tabs beside it. `files` would take far more.
pub const MAX_DOCUMENT: usize = 8 * 1024 * 1024;

/// How long a pump waits for an event before asking whether it is still wanted.
///
/// One second: [`BrowserObserver::wants_frames`] going false must stop the
/// screencast promptly, and a page that shows nothing sends no frames — so the
/// answer cannot be « when the next frame arrives ».
const PUMP_PATIENCE: Duration = Duration::from_secs(1);

/// Combien de temps entre deux sondes de santé d'un point de la flotte.
///
/// Trente secondes, **hors du chemin d'une tâche** : un `GET /json/version`
/// devant chaque ouverture d'onglet paierait un aller-retour HTTP pour une
/// question dont la réponse ne change qu'au redémarrage d'un conteneur. Le prix
/// de la réponse périmée est borné par le fait qu'un point malade choisi par
/// erreur échoue à l'ouverture — ce qui est un `Retryable`, pas une perte.
const HEALTH_PROBE: Duration = Duration::from_secs(30);

/// What replaces a document in the tab, so the tab stays a tab.
///
/// `Fetch.fulfillRequest` has to answer *something* — the renderer is waiting
/// on that response — and answering with the PDF would leave Chromium showing
/// a viewer that no selector reads and that `Location` reports oddly. A page
/// that says what happened, in our own words, keeps every later step honest.
const DOCUMENT_PLACEHOLDER: &str = "<!doctype html><meta charset=\"utf-8\"><title>Document</title>\
     <p>Ce document a été récupéré et rangé au classeur.</p>";

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

/// What the page says about itself once it has parsed: its title, the status
/// its document was served with, **and the captcha it carries, if it carries
/// one**. Waits for `DOMContentLoaded` because `Page.navigate` returns at
/// commit, before the `<title>` has been read.
///
/// `responseStatus` is Chrome 109+; an older Chrome reads `0`, which is
/// « not a wall », the safe direction.
///
/// # Pourquoi les quatre valeurs sortent ensemble
///
/// Le mur et le défi attendent le **même** `DOMContentLoaded` : deux
/// `Runtime.evaluate` seraient deux fois la même promesse, deux allers-retours
/// de socket et deux façons de désaccorder ce que « la page » veut dire. Une
/// seule évaluation, quatre cases — `['', '']` quand il n'y a pas de défi, ce
/// qui est le cas de toutes les pages sauf une poignée.
///
/// # Les trois signatures, et ce qu'elles ne couvrent pas
///
/// `.g-recaptcha[data-sitekey]`, `.cf-turnstile[data-sitekey]`,
/// `.h-captcha[data-sitekey]` : la classe *et* l'attribut, parce que la clé de
/// site est ce qu'un solveur demande et qu'un widget sans elle est un widget
/// rendu par script après coup, que nous ne saurions pas résoudre non plus.
/// Arkose, DataDome et GeeTest n'ont pas cet attribut et restent
/// [`BLOCKED_BY_SITE`] — voir [`crate::captcha`].
const WALL_CHECK: &str = "new Promise(done => { const answer = () => { \
     const hit = [['recaptcha2', '.g-recaptcha'], ['turnstile', '.cf-turnstile'], \
       ['hcaptcha', '.h-captcha']] \
       .map(([k, s]) => [k, document.querySelector(s + '[data-sitekey]')]) \
       .find(([, e]) => e); \
     done([document.title, \
       (performance.getEntriesByType('navigation')[0] || {}).responseStatus || 0, \
       hit ? hit[0] : '', hit ? hit[1].getAttribute('data-sitekey') : '']); }; \
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
// The proxy
// ---------------------------------------------------------------------------

/// L'adresse par laquelle les onglets d'un contexte sortent.
///
/// Trois champs et pas quatre : le mot de passe n'a pas de champ à lui, il est
/// la deuxième moitié de `credentials`, pour qu'aucune ligne de code ne puisse
/// nommer un mot de passe sans nommer l'utilisateur qui va avec — et pour que
/// le `Debug` écrit à la main n'ait qu'un champ à taire.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// `http://hote:port` ou `socks5://hote:port`, tel que
    /// `Target.createBrowserContext.proxyServer` l'accepte. Sans identifiants
    /// dedans : ils sont à côté, et un `http://user:pass@…` serait un mot de
    /// passe dans une colonne en clair.
    pub server: String,
    /// Ce que `--proxy-bypass-list` accepte, ou rien.
    pub bypass: Option<String>,
    /// `(utilisateur, mot de passe)`, quand le proxy en demande.
    pub credentials: Option<(String, String)>,
}

impl std::fmt::Debug for ProxyConfig {
    /// À la main, et c'est le point : un `derive` mettrait le mot de passe dans
    /// la première ligne de trace que quelqu'un écrit en déboguant.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("server", &self.server)
            .field("bypass", &self.bypass)
            .field("has_credentials", &self.credentials.is_some())
            .finish()
    }
}

/// D'où vient le proxy d'un contexte.
///
/// Un port pour la raison de [`CookieJar`] et avec sa clé : l'identifiant de
/// contexte est la seule chose que ce crate tient des deux côtés, et la ligne
/// qui porte l'adresse est au **locataire** (migration 0098), derrière une
/// recherche que cet adaptateur ne sait pas faire. Le scellé des identifiants
/// s'ouvre un crate plus haut, sous `browser://<locataire>/proxy`, là où vivent
/// le chiffre et la clé maître.
#[async_trait]
pub trait Proxies: Send + Sync {
    /// Le proxy de ce contexte, ou `None` — qui veut dire « sort par l'adresse
    /// de la machine », l'état de tout locataire qui n'a rien posé.
    ///
    /// Une erreur ici **n'est pas fatale à l'onglet** et c'est délibéré, pour
    /// la raison de [`BrowserProfiles::profile_for`] tournée dans l'autre
    /// sens : un onglet qui refuse de s'ouvrir est un tour mort, là qu'un
    /// onglet qui sort par la mauvaise adresse est visible et récupérable.
    /// Voir [`Inner::open`], qui le journalise plutôt que d'échouer.
    async fn proxy_for(&self, ctx: &str) -> Result<Option<ProxyConfig>, ProviderError>;
}

/// Personne ne passe par un proxy. Le défaut de l'adaptateur et celui des
/// tests, et l'état de tout déploiement qui n'en a pas acheté.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProxies;

#[async_trait]
impl Proxies for NoProxies {
    async fn proxy_for(&self, _ctx: &str) -> Result<Option<ProxyConfig>, ProviderError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// The profile
// ---------------------------------------------------------------------------

/// What a context's browser should look like from the outside.
///
/// Every field is something a page can read in one line of JavaScript, and
/// every one of them is a **fact about the seat**, not about the container:
/// an employee who answers French prospects from Paris whose browser reports
/// `en-US`/`UTC`/`800×600` is telling every site it visits that it is a
/// datacentre. That is not a captcha problem, it is a coherence problem, and
/// it is fixed in software.
#[derive(Debug, Clone, PartialEq)]
pub struct BrowserProfile {
    /// BCP 47, e.g. `fr-FR`. Drives `Emulation.setLocaleOverride`,
    /// `navigator.language(s)` and the `Accept-Language` header — the three
    /// have to agree or the disagreement is itself the signal.
    pub locale: String,
    /// IANA, e.g. `Europe/Paris`.
    pub timezone: String,
    /// `(width, height, mobile)`. `deviceScaleFactor` is derived: 1 on a
    /// desktop, 2 on a phone, because a phone that reports a scale of 1 is a
    /// desktop pretending.
    pub viewport: (u32, u32, bool),
    /// `(latitude, longitude)`, or nothing at all.
    ///
    /// `None` is **not** « position 0,0 »: it is
    /// `Emulation.setGeolocationOverride` with no parameters, which is CDP's
    /// own way of saying « position unavailable », the answer a laptop with
    /// the permission denied gives. A pair of zeroes is the Gulf of Guinea and
    /// is a much stranger thing to be than nowhere.
    pub geolocation: Option<(f64, f64)>,
}

impl Default for BrowserProfile {
    fn default() -> Self {
        Self {
            locale: "fr-FR".to_owned(),
            timezone: "Europe/Paris".to_owned(),
            viewport: (1366, 768, false),
            geolocation: None,
        }
    }
}

impl BrowserProfile {
    /// `Accept-Language` for this locale: the locale itself, its language, and
    /// English as a last resort — the header a French Chrome actually sends.
    fn accept_language(&self) -> String {
        let language = self.locale.split('-').next().unwrap_or("fr");
        format!("{},{language};q=0.9,en;q=0.8", self.locale)
    }

    /// `navigator.languages`, which must be the same list `Accept-Language`
    /// carries and in the same order. One source, two renderings.
    fn languages(&self) -> Vec<String> {
        let language = self.locale.split('-').next().unwrap_or("fr");
        if language == self.locale {
            vec![self.locale.clone(), "en".to_owned()]
        } else {
            vec![self.locale.clone(), language.to_owned(), "en".to_owned()]
        }
    }

    /// What `navigator.platform` and the UA's own platform token say.
    /// Consistent with `mobile`, because those two disagreeing is the cheapest
    /// detection there is.
    const fn platform(&self) -> &'static str {
        if self.viewport.2 {
            "Linux armv81"
        } else {
            "Linux x86_64"
        }
    }
}

/// Where a context's [`BrowserProfile`] comes from.
///
/// A port for [`CookieJar`]'s reason and with [`CookieJar`]'s key: the
/// context id is the one identifier this crate holds on both sides, and the
/// employee row that actually carries the profile lives one crate up, behind
/// a tenant this adapter does not know.
#[async_trait]
pub trait BrowserProfiles: Send + Sync {
    /// The profile for this context. An error here is **not** fatal to the
    /// tab — see [`Inner::open`]: a browser that emulates the default is a
    /// working browser, and a task that cannot open is not.
    async fn profile_for(&self, ctx: &str) -> Result<BrowserProfile, ProviderError>;
}

/// `fr-FR / Europe/Paris / 1366×768 / desktop / sans position`, for every
/// context. The adapter's default and the tests'.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultProfiles;

#[async_trait]
impl BrowserProfiles for DefaultProfiles {
    async fn profile_for(&self, _ctx: &str) -> Result<BrowserProfile, ProviderError> {
        Ok(BrowserProfile::default())
    }
}

// ---------------------------------------------------------------------------
// Stealth, and its ceiling
// ---------------------------------------------------------------------------

/// A stable 32-bit seed for a context id.
///
/// The whole point is **stable**: an employee whose canvas hash and whose GPU
/// strings change on every task is more identifiable than one that never
/// changed them, because « a new device every visit » is a shape no fleet of
/// real laptops has. SHA-256 of the context id, first four bytes.
fn seed_of(ctx: &str) -> u32 {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(ctx.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// GPU strings a real machine reports. Picked by seed, so one seat is one
/// machine for as long as its context id lasts.
const GPUS: &[(&str, &str)] = &[
    ("Intel Inc.", "Intel(R) UHD Graphics 620"),
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x000046A6) Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
    (
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
    (
        "Google Inc. (AMD)",
        "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
];

/// The script every document in this context runs **before its own scripts**.
///
/// # Where the list comes from
///
/// Each patch below answers a detection that is public, testable and old:
/// they are the evasions `puppeteer-extra-plugin-stealth` ships
/// (`navigator.webdriver`, `navigator.plugins`, `navigator.languages`,
/// `window.chrome.runtime`, `webgl.vendor`, and the `user-agent-override` that
/// strips `HeadlessChrome`), read 2026-09-10 from that project's evasion
/// directory and from the `fingerprintjs` surface the same detections are
/// written against. Nothing here is reverse-engineered from a paying
/// anti-bot service, and nothing here needs one.
///
/// # The ceiling, written where somebody will read it before believing otherwise
///
/// **This passes naïve detection and it does not pass Cloudflare Turnstile or
/// DataDome.** Those two do not read `navigator.webdriver`; they score TLS
/// fingerprints, IP reputation, timing and behaviour, and no script injected
/// into a page changes any of the four. The three things that would — a
/// residential address, a solver, a real profile with history — are
/// *resources*, and `docs/BROWSER.md` puts them in v3 behind a key the client
/// brings. So a wall is still a wall: [`BLOCKED_BY_SITE`] is the honest
/// outcome and stays one.
///
/// Two things this deliberately does **not** do. It does not lie about the
/// number of CPUs or the amount of memory (`hardwareConcurrency`,
/// `deviceMemory`): a container reporting 2 cores *is* a machine with 2
/// cores, and a claim of 8 is contradicted by the first timing measurement
/// any real detector takes. And it does not touch `Notification.permission`
/// or `Permissions.query`: they are consistent already under `--headless=new`,
/// which is the reason that flag replaced the old headless mode.
fn stealth_script(ctx: &str, profile: &BrowserProfile) -> String {
    let seed = seed_of(ctx);
    let (vendor, renderer) = GPUS[seed as usize % GPUS.len()];
    let languages = serde_json::to_string(&profile.languages()).unwrap_or_else(|_| "[]".to_owned());
    let language =
        serde_json::to_string(&profile.locale).unwrap_or_else(|_| "\"fr-FR\"".to_owned());
    let platform =
        serde_json::to_string(profile.platform()).unwrap_or_else(|_| "\"Linux x86_64\"".to_owned());
    let vendor = serde_json::to_string(vendor).unwrap_or_else(|_| "\"\"".to_owned());
    let renderer = serde_json::to_string(renderer).unwrap_or_else(|_| "\"\"".to_owned());
    // One IIFE, everything inside a `try`: a page that loads before our patch
    // throws is a page we still want. A stealth script that breaks the
    // document is worse than no stealth script — it is a *unique* breakage.
    format!(
        "(() => {{ try {{\n\
         const seed = {seed};\n\
         const own = (o, k, v) => Object.defineProperty(o, k, \
           {{ get: () => v, configurable: true, enumerable: true }});\n\
         own(Navigator.prototype, 'webdriver', false);\n\
         own(Navigator.prototype, 'languages', Object.freeze({languages}));\n\
         own(Navigator.prototype, 'language', {language});\n\
         own(Navigator.prototype, 'platform', {platform});\n\
         const mimes = [\n\
           {{ type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' }},\n\
           {{ type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format' }}\n\
         ];\n\
         const names = ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', \
           'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'];\n\
         const plugins = names.map(name => Object.create(Plugin.prototype, {{\n\
           name: {{ value: name, enumerable: true }},\n\
           filename: {{ value: 'internal-pdf-viewer', enumerable: true }},\n\
           description: {{ value: 'Portable Document Format', enumerable: true }},\n\
           length: {{ value: mimes.length, enumerable: true }}\n\
         }}));\n\
         const list = (items, proto) => {{\n\
           const array = Object.create(proto);\n\
           items.forEach((item, i) => {{ array[i] = item; }});\n\
           Object.defineProperty(array, 'length', {{ value: items.length }});\n\
           array.item = i => items[i] || null;\n\
           array.namedItem = n => items.find(x => x.name === n || x.type === n) || null;\n\
           return array;\n\
         }};\n\
         own(Navigator.prototype, 'plugins', list(plugins, PluginArray.prototype));\n\
         own(Navigator.prototype, 'mimeTypes', list(mimes, MimeTypeArray.prototype));\n\
         if (!window.chrome) {{\n\
           window.chrome = {{ app: {{ isInstalled: false }}, runtime: {{}},\n\
             csi: function () {{}}, loadTimes: function () {{}} }};\n\
         }}\n\
         const paint = HTMLCanvasElement.prototype.toDataURL;\n\
         HTMLCanvasElement.prototype.toDataURL = function () {{\n\
           try {{\n\
             const g = this.getContext('2d');\n\
             if (g && this.width && this.height) {{\n\
               const px = g.getImageData(0, 0, 1, 1);\n\
               px.data[0] = (px.data[0] + (seed & 3)) & 255;\n\
               px.data[1] = (px.data[1] + ((seed >> 2) & 3)) & 255;\n\
               g.putImageData(px, 0, 0);\n\
             }}\n\
           }} catch (e) {{}}\n\
           return paint.apply(this, arguments);\n\
         }};\n\
         for (const gl of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {{\n\
           if (!gl) continue;\n\
           const read = gl.prototype.getParameter;\n\
           gl.prototype.getParameter = function (p) {{\n\
             if (p === 37445) return {vendor};\n\
             if (p === 37446) return {renderer};\n\
             return read.apply(this, arguments);\n\
           }};\n\
         }}\n\
         }} catch (e) {{}} }})()"
    )
}

/// The User-Agent to claim, from the one Chromium reports about itself.
///
/// **Measured 2026-09-10, Chrome 152**: `/json/version` answers a `User-Agent`
/// that reads `HeadlessChrome/152.0.7258.67`. That token is the single most
/// checked string in every anti-bot script ever written, it is sent on every
/// request including the very first, and it costs one `replace` to remove. The
/// version stays the binary's own: a UA claiming 141 from a browser that
/// implements 152 disagrees with every feature test a page can run, which is a
/// *worse* signal than the one it hides.
fn honest_user_agent(reported: &str) -> String {
    reported.replace("HeadlessChrome/", "Chrome/")
}

// ---------------------------------------------------------------------------
// The fleet
// ---------------------------------------------------------------------------

/// Un Chromium de la flotte : son adresse de configuration, ses jetons, sa
/// santé.
///
/// **Le sémaphore est par machine et non au total**, et c'est tout le sujet :
/// `BROWSER_MAX_TABS` est une arithmétique de mémoire (≈ 400 Mo de base et
/// 100–150 Mo par onglet dans un conteneur plafonné à 1 Go), donc trois
/// machines portent neuf onglets, pas trois. Un plafond global aurait fait de
/// la deuxième machine une dépense sans effet.
///
/// Les onglets ouverts ne sont pas comptés à part : `max_tabs -
/// tokens.available_permits()` est le compte, il ne peut pas se désaccorder du
/// sémaphore, et c'est la charge sur laquelle [`Fleet::pick`] classe.
struct Endpoint {
    url: Url,
    tokens: Arc<Semaphore>,
    max_tabs: usize,
    /// **Vraie au départ, et c'est délibéré.** Un point présumé malade tant
    /// qu'une sonde n'a pas dit le contraire ferait attendre trente secondes à
    /// la première tâche d'un déploiement qui vient de démarrer. Optimiste,
    /// donc, et la sonde corrige — le prix d'une erreur est une ouverture
    /// d'onglet qui échoue, c'est-à-dire un `Retryable`.
    healthy: AtomicBool,
}

impl Endpoint {
    /// Onglets ouverts sur ce point, maintenant.
    fn open_tabs(&self) -> usize {
        self.max_tabs
            .saturating_sub(self.tokens.available_permits())
    }
}

/// Les Chromium que ce processus pilote.
///
/// Une seule valeur dans `BROWSER_CDP_URL` reste valide et donne une flotte
/// d'un point : rien ne distingue le cas d'avant, ni dans la configuration ni
/// dans le code.
struct Fleet {
    endpoints: Vec<Endpoint>,
    /// Les sondes sont démarrées à la première ouverture d'onglet et pas dans
    /// `new` : `tokio::spawn` hors d'un exécuteur panique, et `ChromeBrowser`
    /// se construit dans des tests qui n'en ont pas.
    probing: AtomicBool,
}

impl Fleet {
    fn new(urls: Vec<Url>, max_tabs: usize) -> Self {
        let max_tabs = max_tabs.max(1);
        Self {
            endpoints: urls
                .into_iter()
                .map(|url| Endpoint {
                    url,
                    tokens: Arc::new(Semaphore::new(max_tabs)),
                    max_tabs,
                    healthy: AtomicBool::new(true),
                })
                .collect(),
            probing: AtomicBool::new(false),
        }
    }

    /// Le point sain le moins chargé, ou `None` si aucun n'est sain.
    ///
    /// « Le moins chargé » et non « le premier libre » : le premier libre
    /// remplit la machine 1 avant de toucher la machine 2, ce qui donne un
    /// point à trois onglets et un point à zéro alors que le travail tient à
    /// deux et deux. Le classement est lu sans verrou et n'est qu'une
    /// préférence — le sémaphore du point choisi est le vrai verrou, et si
    /// quelqu'un le remplit entre les deux, l'attente bornée s'applique là.
    fn pick(&self) -> Option<&Endpoint> {
        self.endpoints
            .iter()
            .filter(|endpoint| endpoint.healthy.load(Ordering::Acquire))
            .min_by_key(|endpoint| endpoint.open_tabs())
    }

    /// `(total, sains)`, pour `/readyz`.
    fn health(&self) -> (usize, usize) {
        (
            self.endpoints.len(),
            self.endpoints
                .iter()
                .filter(|endpoint| endpoint.healthy.load(Ordering::Acquire))
                .count(),
        )
    }
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// One open tab: the CDP context and target it lives in, and the token it
/// holds. Dropping it returns the token; closing it properly is
/// [`Inner::close`]'s job.
struct Tab {
    /// **L'adresse du point de la flotte où cet onglet vit**, résolue à
    /// l'ouverture et gardée : une tâche ne change pas de machine, parce que
    /// l'onglet est sur celle-là. Gardée plutôt que re-résolue à la fermeture
    /// pour que fermer une cible ne dépende pas d'un DNS qui a bougé depuis.
    at: SocketAddr,
    context_id: String,
    target_id: String,
    /// `ws://<ip>:<port>/devtools/page/<target>`, handed to the driver
    /// verbatim at every step.
    page_url: String,
    last_used: Instant,
    /// What this tab is, to whoever is listening. Minted at
    /// [`Inner::open`] and echoed on every call, so a listener keyed by
    /// `task_id` needs no state between them.
    task: TaskRef,
    /// How the last step went, which is what [`BrowserObserver::task_finished`]
    /// reports. A tab closed by the reaper or by a park ends on whatever the
    /// task last managed; a tab closed by an error ends on that error.
    outcome: StepOutcome,
    /// True while a screencast pump is running on this tab. The pump clears it
    /// on its way out and [`Inner::close`] clears it to stop one.
    filming: Arc<AtomicBool>,
    /// True while the socket that dressed this tab is still held open.
    ///
    /// **Two measurements on Chrome 152, 2026-09-10, and both contradict the
    /// obvious reading of the protocol.**
    ///
    /// First: an `Emulation.*` override is undone when the client that set it
    /// disconnects. The first version applied the locale, the timezone, the
    /// viewport and the UA on a socket it then closed, and the probe page read
    /// `Asia/Manila` — the *machine's* zone, not `Europe/Paris` — because by
    /// the time anything navigated the override had already been reverted.
    ///
    /// Second: `Page.addScriptToEvaluateOnNewDocument` **does nothing without
    /// `Page.enable`**, and answers a perfectly good `identifier` either way.
    /// With the socket held open but the domain never enabled, the probe read
    /// Chrome's own `navigator.languages` and a `null` WebGL vendor: the
    /// script had been accepted and never ran. `Page.disable` afterwards
    /// un-registers it again, so the session has to stay subscribed for as
    /// long as the tab lives.
    ///
    /// Which is why the socket is not a field here but is owned by a task
    /// ([`Inner::pump`]): a subscribed session that nobody reads is an event
    /// queue that nobody drains, and `Page` is a chatty domain — a dozen frames
    /// per navigation into a socket buffer that eventually blocks Chromium's
    /// own writer. The flag is how [`Inner::close`] lets it go.
    ///
    /// **Depuis la v3 cette socket porte aussi `Fetch`** : c'est *la* session
    /// d'interception de l'onglet, une seule, et sa boucle est le seul
    /// consommateur de `Fetch.requestPaused` et de `Fetch.authRequired`. Voir
    /// [`Inner::pump`].
    dressed: Arc<AtomicBool>,
    /// Ce que la pompe a trouvé pendant la navigation en cours. Armé par
    /// [`BrowserProvider::act`] avant `Page.navigate`, désarmé par la pompe
    /// quand elle a décidé.
    watch: Arc<Watch>,
    _permit: OwnedSemaphorePermit,
}

/// Le rendez-vous entre la pompe `Fetch` et l'étape qui navigue.
///
/// **La synchronisation est l'ordre d'écriture, pas un canal.** `Fetch.enable`
/// met la réponse en attente : `Page.navigate` ne rend la main que lorsque
/// quelqu'un a continué ou rempli cette réponse. La pompe écrit `found`
/// **avant** de répondre à la requête en attente ; donc au retour de
/// `Page.navigate`, `found` est déjà posé. Un `oneshot` ferait le même travail
/// avec une allocation par navigation et une branche « et si l'émetteur est
/// mort » qui n'a pas de bonne réponse.
#[derive(Default)]
struct Watch {
    /// Vrai entre l'armement et la décision. Une réponse de document en
    /// attente que personne n'a armée est simplement continuée.
    armed: AtomicBool,
    /// `Some` quand la navigation a rapporté un document (ou un refus de
    /// document) ; `None` quand c'était une page.
    found: Mutex<Option<Result<BrowserOutcome, ProviderError>>>,
}

impl Watch {
    fn arm(&self) {
        *self.found.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.armed.store(true, Ordering::Release);
    }

    /// Désarme et rend ce que la pompe a trouvé.
    fn take(&self) -> Option<Result<BrowserOutcome, ProviderError>> {
        self.armed.store(false, Ordering::Release);
        self.found.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

struct Inner {
    fleet: Fleet,
    http: reqwest::Client,
    driver: CdpWebsocket,
    vet: Arc<dyn UrlVet>,
    jar: Arc<dyn CookieJar>,
    observer: Arc<dyn BrowserObserver>,
    profiles: Arc<dyn BrowserProfiles>,
    proxies: Arc<dyn Proxies>,
    solver: Arc<dyn CaptchaSolver>,
    /// The User-Agent this Chromium reports, `HeadlessChrome` already taken
    /// out of it. Filled by the first [`Inner::browser_ws`] and never again:
    /// a running binary does not change version.
    ///
    /// Une flotte est faite de la même image épinglée par le même
    /// `compose.yml` ; le premier point qui répond décide donc pour tous, et
    /// deux versions dans une flotte est un problème de déploiement, pas
    /// d'adaptateur.
    user_agent: Mutex<Option<String>>,
    tabs: Mutex<BTreeMap<String, Tab>>,
    queue_wait: Duration,
    step_timeout: Duration,
    tab_idle: Duration,
    health_probe: Duration,
}

/// The self-hosted browser. `Clone` is cheap and shares the tabs and the
/// tokens: one process, one Chromium, one ceiling.
#[derive(Clone)]
pub struct ChromeBrowser {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ChromeBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (total, healthy) = self.inner.fleet.health();
        f.debug_struct("ChromeBrowser")
            .field("endpoints", &total)
            .field("healthy", &healthy)
            .field("open_tabs", &self.inner.lock().len())
            .finish()
    }
}

impl ChromeBrowser {
    /// A browser on `cdp_urls` (`[http://browser:9222]`), dialling only what
    /// `vet` permits, keeping cookies in `jar`.
    ///
    /// La liste est la flotte, dans l'ordre de `BROWSER_CDP_URL` ; une seule
    /// adresse reste le cas ordinaire et ne coûte rien de plus.
    pub fn new(cdp_urls: Vec<Url>, vet: Arc<dyn UrlVet>, jar: Arc<dyn CookieJar>) -> Self {
        Self {
            inner: Arc::new(Inner {
                fleet: Fleet::new(cdp_urls, DEFAULT_MAX_TABS),
                http: reqwest::Client::builder()
                    .timeout(crate::cdp::DEFAULT_CONNECT_TIMEOUT)
                    .build()
                    .unwrap_or_default(),
                driver: CdpWebsocket::new(),
                vet,
                jar,
                observer: Arc::new(NoopObserver),
                profiles: Arc::new(DefaultProfiles),
                proxies: Arc::new(NoProxies),
                solver: Arc::new(NoSolver),
                user_agent: Mutex::new(None),
                tabs: Mutex::new(BTreeMap::new()),
                queue_wait: DEFAULT_QUEUE_WAIT,
                step_timeout: STEP_TIMEOUT,
                tab_idle: TAB_IDLE,
                health_probe: HEALTH_PROBE,
            }),
        }
    }

    /// `BROWSER_MAX_TABS`, **par machine**. Only before the first tab: the
    /// semaphores are built here.
    #[must_use]
    pub fn with_max_tabs(self, max_tabs: usize) -> Self {
        self.map(|inner| {
            let urls = inner
                .fleet
                .endpoints
                .iter()
                .map(|endpoint| endpoint.url.clone())
                .collect();
            inner.fleet = Fleet::new(urls, max_tabs);
        })
    }

    /// Par où les onglets de chaque contexte sortent. Défaut : [`NoProxies`].
    #[must_use]
    pub fn with_proxies(self, proxies: Arc<dyn Proxies>) -> Self {
        self.map(|inner| inner.proxies = proxies)
    }

    /// Qui franchit un défi de captcha. Défaut : [`NoSolver`], qui refuse.
    #[must_use]
    pub fn with_solver(self, solver: Arc<dyn CaptchaSolver>) -> Self {
        self.map(|inner| inner.solver = solver)
    }

    /// Raccourcir la cadence des sondes de santé — les tests seuls.
    #[must_use]
    pub fn with_health_probe(self, every: Duration) -> Self {
        self.map(|inner| inner.health_probe = every)
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

    /// Tell somebody what this browser is doing.
    ///
    /// The default is [`NoopObserver`], which is what the contract suite and
    /// every test that does not care about narration get; a deployment hands
    /// the journal. Nothing about the adapter's behaviour turns on which one
    /// it is — except one thing, and it is the point of the port:
    /// [`BrowserObserver::wants_frames`] answering true is what starts a
    /// screencast, and a `NoopObserver` never says true, so a deployment
    /// nobody is watching encodes nothing.
    #[must_use]
    pub fn with_observer(self, observer: Arc<dyn BrowserObserver>) -> Self {
        self.map(|inner| inner.observer = observer)
    }

    /// Where each context's [`BrowserProfile`] comes from. Default:
    /// [`DefaultProfiles`].
    #[must_use]
    pub fn with_profiles(self, profiles: Arc<dyn BrowserProfiles>) -> Self {
        self.map(|inner| inner.profiles = profiles)
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

    /// Where a Chrome is reachable *by address*: the host of `url` resolved
    /// now, because Chrome refuses a `Host` header that is a name (module
    /// docs) and because a container's address changes on restart. IPv4
    /// first: Chrome listens on `127.0.0.1` by default and a `localhost` that
    /// resolves to `::1` first would dial an ear that is not there.
    async fn endpoint(url: &Url) -> Result<SocketAddr, ProviderError> {
        let host = url.host_str().ok_or(ProviderError::Terminal {
            code: "bad_cdp_url",
        })?;
        let port = url.port_or_known_default().unwrap_or(9222);
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
    ///
    /// The same answer carries the `User-Agent`, so this is also where it is
    /// learned. One request and not two: the UA has to be the *running*
    /// binary's or it contradicts every feature test a page makes, and this
    /// call already asks the running binary who it is.
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
        if let Some(reported) = version["User-Agent"].as_str() {
            *self.user_agent.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(honest_user_agent(reported));
        }
        let advertised = version["webSocketDebuggerUrl"]
            .as_str()
            .and_then(|raw| Url::parse(raw).ok())
            .ok_or(ProviderError::Terminal {
                code: "no_browser_endpoint",
            })?;
        Ok(format!("ws://{at}{}", advertised.path()))
    }

    // -- la flotte ----------------------------------------------------------

    /// Démarre une sonde par point, une fois pour la vie du processus.
    ///
    /// Appelée depuis le chemin d'une tâche mais **ne s'y trouve pas** : elle
    /// arme des tâches détachées et rend la main. Ce que le chemin d'une tâche
    /// paie, c'est un `compare_exchange`.
    fn start_probes(self: &Arc<Self>) {
        if self
            .fleet
            .probing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        for index in 0..self.fleet.endpoints.len() {
            let inner = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(inner.health_probe).await;
                    let endpoint = &inner.fleet.endpoints[index];
                    // `/json/version` et rien d'autre : c'est ce que le
                    // `healthcheck` du conteneur interroge déjà, donc les deux
                    // ne peuvent pas être d'avis différents sur ce qu'est un
                    // Chromium vivant.
                    let alive = match Self::endpoint(&endpoint.url).await {
                        Ok(at) => inner
                            .http
                            .get(format!("http://{at}/json/version"))
                            .send()
                            .await
                            .is_ok_and(|response| response.status().is_success()),
                        Err(_) => false,
                    };
                    // Journalisé au changement seulement : une flotte saine ne
                    // doit pas écrire une ligne toutes les trente secondes.
                    if endpoint.healthy.swap(alive, Ordering::AcqRel) != alive {
                        if alive {
                            tracing::info!(endpoint = %endpoint.url, "browser endpoint is back");
                        } else {
                            tracing::warn!(endpoint = %endpoint.url, "browser endpoint is down");
                        }
                    }
                }
            });
        }
    }

    /// The tab this context is driving, opened if there is none. Touches it.
    async fn tab(
        self: &Arc<Self>,
        ctx: &str,
        employee: agentos_domain::ids::EmployeeId,
    ) -> Result<String, ProviderError> {
        if let Some(tab) = self.lock().get_mut(ctx) {
            tab.last_used = Instant::now();
            return Ok(tab.page_url.clone());
        }
        self.start_probes();
        let tab = self.open(ctx, employee).await?;
        let page_url = tab.page_url.clone();
        // The narration starts here and not at the first step: a task is a
        // tab's life, and everything before this — a vetoed address, a
        // `Location` on a session that is nowhere — costs Chromium nothing and
        // belongs to no task.
        self.observer.task_started(&tab.task, Utc::now());
        self.lock().insert(ctx.to_owned(), tab);
        self.reap_later(ctx.to_owned());
        // Somebody may already be watching this seat's live view when the tab
        // opens — the console page was open before the turn started — so the
        // question is asked here as well as after every step.
        self.film(ctx);
        Ok(page_url)
    }

    /// Token, browser socket, context, target, disguise, cookies — in that
    /// order, and anything that fails after the context exists disposes it on
    /// the way out, or Chromium keeps a renderer nobody can reach.
    async fn open(
        &self,
        ctx: &str,
        employee: agentos_domain::ids::EmployeeId,
    ) -> Result<Tab, ProviderError> {
        // Le point est choisi **avant** le jeton, parce que le jeton est celui
        // d'un point. Aucun point sain : rien à attendre ici — le sémaphore
        // d'une machine morte se libérerait sans que la machine revienne — donc
        // `Retryable` tout de suite, et le message nomme les deux nombres, la
        // seule ligne qui distingue « la flotte est pleine » de « la flotte est
        // tombée ».
        let Some(endpoint) = self.fleet.pick() else {
            let (total, healthy) = self.fleet.health();
            tracing::warn!(
                endpoints = total,
                unhealthy = total - healthy,
                "no healthy browser endpoint: all {total} of them are down"
            );
            return Err(ProviderError::Retryable {
                after: self.health_probe,
            });
        };
        let permit = tokio::time::timeout(
            self.queue_wait,
            Arc::clone(&endpoint.tokens).acquire_owned(),
        )
        .await
        // Every tab is busy and has been for the whole wait: the turn is
        // better off retried later than parked with a terminal error.
        .map_err(|_| ProviderError::Retryable {
            after: self.queue_wait,
        })?
        .map_err(|_| ProviderError::Terminal { code: "no_browser" })?;

        // Read before the browser socket is even open: one of the six
        // commands it drives is on the *browser* endpoint (the geolocation
        // permission is granted per context, not per page) and the other five
        // are on the page. A failure here is the default profile, never a
        // failed tab — see `dress`.
        let profile = self.profiles.profile_for(ctx).await.unwrap_or_else(|_| {
            tracing::warn!(
                ctx,
                "no browser profile for this context; using the default"
            );
            BrowserProfile::default()
        });
        // Et le proxy, pour la raison symétrique : une ligne illisible est un
        // onglet qui sort par l'adresse de la machine — visible, récupérable —
        // là où un onglet qui refuse de s'ouvrir est un tour mort.
        let proxy = self.proxies.proxy_for(ctx).await.unwrap_or_else(|err| {
            tracing::warn!(
                ctx,
                code = err.code(),
                "no proxy for this context; the tab leaves by the machine's own address"
            );
            None
        });

        let at = Self::endpoint(&endpoint.url).await?;
        let browser_ws = self.browser_ws(at).await?;
        let mut browser = self.driver.connect(&Secret::new(browser_ws)).await?;

        // **Le proxy est un paramètre du contexte, jamais un drapeau du
        // processus.** `--proxy-server` voudrait un Chromium par locataire ;
        // `proxyServer` ici donne une adresse de sortie par tâche sur le même
        // binaire, et le contexte est déjà jeté à la fin de la tâche. Les deux
        // noms sont ceux du protocole, relevés le 2026-09-10 dans
        // `GET /json/protocol` de Chrome 152.0.7977.83.
        let mut params = serde_json::Map::new();
        if let Some(proxy) = &proxy {
            params.insert("proxyServer".to_owned(), json!(proxy.server));
            if let Some(bypass) = &proxy.bypass {
                params.insert("proxyBypassList".to_owned(), json!(bypass));
            }
        }
        let context_id = browser
            .call("Target.createBrowserContext", Value::Object(params))
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
        // A geolocation override with no permission behind it is a page whose
        // `getCurrentPosition` callback is never called — which reads exactly
        // like a user who clicked « block », and is the wrong answer when we
        // went to the trouble of saying where the seat is. Granted on the
        // context so it dies with it; nothing is granted when there is no
        // position to give.
        if profile.geolocation.is_some() {
            let _ = browser
                .call(
                    "Browser.grantPermissions",
                    json!({
                        "browserContextId": context_id,
                        "permissions": ["geolocation"],
                    }),
                )
                .await;
        }
        browser.close().await;

        let page_url = format!("ws://{at}/devtools/page/{target_id}");
        let tab = Tab {
            at,
            context_id,
            target_id,
            page_url,
            last_used: Instant::now(),
            task: TaskRef {
                task_id: Uuid::now_v7(),
                employee_id: employee,
                context: ctx.to_owned(),
                provider: PROVIDER,
            },
            outcome: StepOutcome::Ok,
            filming: Arc::new(AtomicBool::new(false)),
            dressed: Arc::new(AtomicBool::new(false)),
            watch: Arc::new(Watch::default()),
            _permit: permit,
        };

        // Everything that has to be true *before the first navigation* happens
        // on one page socket: the disguise, the emulation, and the jar. One
        // socket because they share a deadline and an « or the tab is useless
        // » quality, and because three connections to the same target for
        // three commands is three handshakes on a box with two vCPU.
        //
        // The whole block is best effort, for the jar's original reason
        // carried one step further: an employee browsing with the default
        // locale and no disguise is an employee who may get blocked, which is
        // recoverable and visible; a tab that refuses to open is a turn that
        // died over a cosmetic. What is *not* best effort is the order —
        // `addScriptToEvaluateOnNewDocument` after the first `Page.navigate`
        // patches the document after its own scripts have already read the
        // truth, which is worse than not patching at all because it looks like
        // it worked.
        if let Ok(mut page) = self
            .driver
            .connect(&Secret::new(tab.page_url.clone()))
            .await
        {
            self.dress(&mut page, ctx, &profile).await;
            if let Ok(Some(jar)) = self.jar.load(ctx).await {
                let cookies: Vec<Value> =
                    serde_json::from_str(jar.expose_for_transport()).unwrap_or_default();
                if !cookies.is_empty()
                    && page
                        .call("Network.setCookies", json!({ "cookies": cookies }))
                        .await
                        .is_err()
                {
                    tracing::warn!(
                        ctx,
                        "chrome refused the employee's cookie jar; starting logged out"
                    );
                }
            }
            // L'interception, sur **cette** socket et sur aucune autre : c'est
            // la seule qui vive aussi longtemps que l'onglet, et deux sessions
            // `Fetch` sur une même cible sont deux interceptions qui se
            // disputent le même `requestPaused`. Un Chromium trop vieux pour
            // `Fetch` est un Chromium qui lit des pages : pas d'interception,
            // pas d'échec.
            let credentials = proxy.as_ref().and_then(|proxy| proxy.credentials.clone());
            let intercepting = page
                .call("Fetch.enable", fetch_patterns(credentials.is_some()))
                .await
                .is_ok();
            tab.dressed.store(true, Ordering::Release);
            // Not closed, and not kept here either. See `Tab::dressed`: closing
            // it is what made the emulation invisible to every page, and
            // holding it unread is what would fill a socket buffer.
            Self::pump(
                page,
                Arc::clone(&tab.dressed),
                Arc::clone(&tab.watch),
                intercepting.then_some(credentials).flatten(),
            );
        }
        Ok(tab)
    }

    /// **La seule session `Fetch` de l'onglet**, et la socket qui porte
    /// l'habillage.
    ///
    /// Elle existait déjà en v2 pour une raison qui n'a pas changé :
    /// `Emulation.*` est défait quand le client qui l'a posé se déconnecte, et
    /// `addScriptToEvaluateOnNewDocument` est inerte sans `Page.enable` —
    /// donc quelqu'un doit rester abonné, et quelqu'un doit donc lire les
    /// événements pour qu'ils ne s'empilent pas. Ce quelqu'un fait maintenant
    /// le travail au lieu de le jeter.
    ///
    /// Trois choses arrivent ici :
    ///
    /// * **`Fetch.authRequired`** → `continueWithAuth`, avec les identifiants
    ///   quand il y en a et `Default` sinon. `Default` et pas `CancelAuth` :
    ///   un site qui demande une authentification HTTP à laquelle nous n'avons
    ///   rien à répondre doit se comporter comme pour un humain qui ferme la
    ///   boîte de dialogue, c'est-à-dire rendre son 401 à la page.
    /// * **Une requête en attente** (`requestPaused` sans `responseStatusCode`)
    ///   → `continueRequest`. C'est l'étage que l'authentification oblige à
    ///   ajouter, voir [`fetch_patterns`].
    /// * **Une réponse en attente** → si une navigation est armée
    ///   ([`Watch`]), la décision document/page est prise ici et **écrite avant
    ///   que la réponse soit rendue** ; sinon la réponse est simplement
    ///   continuée.
    fn pump(
        mut page: crate::cdp::PageSocket,
        alive: Arc<AtomicBool>,
        watch: Arc<Watch>,
        credentials: Option<(String, String)>,
    ) {
        tokio::spawn(async move {
            while alive.load(Ordering::Acquire) {
                // A dead socket ends the hold, and with it the disguise — the
                // tab is on its way out anyway when that happens.
                let event = match page.next_event(PUMP_PATIENCE).await {
                    Ok(Some(event)) => event,
                    Ok(None) => continue,
                    Err(_) => break,
                };
                match event["method"].as_str() {
                    Some("Fetch.authRequired") => {
                        let answer = match &credentials {
                            Some((username, password)) => json!({
                                "response": "ProvideCredentials",
                                "username": username,
                                // Le mot de passe est ici, dans le corps d'une
                                // trame sortante, et nulle part ailleurs : rien
                                // de cette fonction ne le formate, et
                                // `cdp.rs::call_inner` trace la méthode et
                                // l'identifiant, jamais les paramètres.
                                "password": password,
                            }),
                            None => json!({ "response": "Default" }),
                        };
                        let _ = page
                            .call(
                                "Fetch.continueWithAuth",
                                json!({
                                    "requestId": event["params"]["requestId"],
                                    "authChallengeResponse": answer,
                                }),
                            )
                            .await;
                    }
                    Some("Fetch.requestPaused") => {
                        answer_paused(&mut page, &event["params"], &watch).await;
                    }
                    _ => {}
                }
            }
            page.close().await;
        });
    }

    /// The disguise and the emulation, on an already-open page socket.
    ///
    /// Six commands, and the order inside them does not matter — but the fact
    /// that all six run before any navigation does. See [`stealth_script`] for
    /// what the first one covers and, more importantly, what it does not.
    async fn dress(
        &self,
        page: &mut crate::cdp::Cdp<
            impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
        >,
        ctx: &str,
        profile: &BrowserProfile,
    ) {
        let _ = page.call("Page.enable", json!({})).await;
        let _ = page
            .call(
                "Page.addScriptToEvaluateOnNewDocument",
                json!({ "source": stealth_script(ctx, profile) }),
            )
            .await;
        // The UA is the running binary's, minus `HeadlessChrome`. If
        // `/json/version` never answered one we send none rather than invent a
        // version: a UA that disagrees with the engine is a louder signal than
        // the headless token it would hide.
        let user_agent = self
            .user_agent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(user_agent) = user_agent {
            let _ = page
                .call(
                    "Emulation.setUserAgentOverride",
                    json!({
                        "userAgent": user_agent,
                        "acceptLanguage": profile.accept_language(),
                        "platform": profile.platform(),
                    }),
                )
                .await;
        }
        let _ = page
            .call(
                "Emulation.setLocaleOverride",
                json!({ "locale": profile.locale }),
            )
            .await;
        let _ = page
            .call(
                "Emulation.setTimezoneOverride",
                json!({ "timezoneId": profile.timezone }),
            )
            .await;
        let (width, height, mobile) = profile.viewport;
        let _ = page
            .call(
                "Emulation.setDeviceMetricsOverride",
                json!({
                    "width": width,
                    "height": height,
                    "mobile": mobile,
                    // Derived and not configured: a « phone » reporting a
                    // scale factor of 1 is a desktop wearing a small window.
                    "deviceScaleFactor": if mobile { 2 } else { 1 },
                }),
            )
            .await;
        // Sent in both cases, and the empty params are the point: CDP reads
        // `setGeolocationOverride {}` as « position unavailable », which is a
        // laptop with the permission denied. Not sending it at all would leave
        // whatever the container's own geoip says.
        let _ = page
            .call(
                "Emulation.setGeolocationOverride",
                match profile.geolocation {
                    Some((latitude, longitude)) => json!({
                        "latitude": latitude,
                        "longitude": longitude,
                        "accuracy": 40,
                    }),
                    None => json!({}),
                },
            )
            .await;
    }

    // -- the live view ------------------------------------------------------

    /// Start a screencast on this tab if somebody is watching and nobody is
    /// filming yet. Cheap and idempotent: called at the tab's opening and
    /// after every step.
    fn film(self: &Arc<Self>, ctx: &str) {
        // The task and the socket are copied out *before* the observer is
        // asked anything: `wants_frames` is somebody else's code and the port
        // says it must not block, but holding the tab map across a foreign
        // call would make that a promise rather than a fact.
        let watching = {
            let tabs = self.lock();
            tabs.get(ctx).map(|tab| {
                (
                    tab.task.clone(),
                    tab.page_url.clone(),
                    Arc::clone(&tab.filming),
                )
            })
        };
        let Some((task, page_url, filming)) = watching else {
            return;
        };
        if !self.observer.wants_frames(&task) {
            return;
        }
        // Compare-and-swap and not a plain load: two steps finishing at once
        // on the same tab would otherwise start two encoders on one page.
        if filming
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let inner = Arc::clone(self);
        tokio::spawn(async move { inner.screencast(task, page_url, filming).await });
    }

    /// The pump: one socket, one `Page.startScreencast`, and a frame at a
    /// time until nobody is watching.
    ///
    /// **A second socket on the same page, and that is the whole design.**
    /// `CdpDriver::run` skips every frame that is not the answer to its own
    /// command — deliberately, and `cdp.rs` argues why — so there is nowhere
    /// on the command path for an unbidden `Page.screencastFrame` to land.
    /// Teaching `call` to buffer events would give every command an unbounded
    /// queue nobody drains; a socket whose only job is events has neither
    /// problem and dies without touching the step that is running.
    ///
    /// `everyNthFrame: 2` and `quality: 60` are the ceiling, not a preference:
    /// this is a live view for a human, on a VPS with two vCPU shared with
    /// three tabs and a Postgres. Thirty frames a second of JPEG would be the
    /// browser's whole budget spent on somebody watching it.
    async fn screencast(&self, task: TaskRef, page_url: String, filming: Arc<AtomicBool>) {
        // Whatever happens below, the flag is cleared on the way out, or the
        // tab never films again.
        let Ok(mut page) = self.driver.connect(&Secret::new(page_url)).await else {
            filming.store(false, Ordering::Release);
            return;
        };
        if page
            .call(
                "Page.startScreencast",
                json!({
                    "format": "jpeg",
                    "quality": 60,
                    "maxWidth": 1280,
                    "everyNthFrame": 2,
                }),
            )
            .await
            .is_err()
        {
            filming.store(false, Ordering::Release);
            page.close().await;
            return;
        }
        while filming.load(Ordering::Acquire) && self.observer.wants_frames(&task) {
            // `Ok(None)` is a quiet second — a page that shows nothing sends
            // nothing — and it is why the loop condition is re-checked on a
            // timer rather than on a frame.
            let event = match page.next_event(PUMP_PATIENCE).await {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(_) => break,
            };
            if event["method"] != "Page.screencastFrame" {
                continue;
            }
            // The ack goes first and unconditionally: Chromium sends at most
            // one un-acked frame, so a pump that decoded before acking would
            // halve its own rate, and one that failed to decode would stop the
            // stream for good.
            let _ = page
                .call(
                    "Page.screencastFrameAck",
                    json!({ "sessionId": event["params"]["sessionId"] }),
                )
                .await;
            if let Some(data) = event["params"]["data"].as_str()
                && let Ok(jpeg) = BASE64.decode(data)
            {
                self.observer.frame(&task, &jpeg, Utc::now());
            }
        }
        let _ = page.call("Page.stopScreencast", json!({})).await;
        page.close().await;
        filming.store(false, Ordering::Release);
    }

    /// Export the cookies, then tear the tab down. Best effort at every
    /// stage: a tab whose socket is already dead still has to give its
    /// context back, and the permit is returned when `tab` drops whatever
    /// Chrome said.
    async fn close(&self, ctx: &str, tab: Tab) {
        // The pump goes first: it holds a socket on a target that is about to
        // be closed, and it stops within `PUMP_PATIENCE` of this line. Nothing
        // waits for it — a `Page.stopScreencast` on a target that is already
        // gone is an error nobody reads.
        tab.filming.store(false, Ordering::Release);
        // And with it the session that held the disguise: it is subscribed to
        // a target that is about to be closed. Both let go within
        // `PUMP_PATIENCE` and nothing waits for either.
        tab.dressed.store(false, Ordering::Release);
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
        // `tab.at` et non une nouvelle résolution : la cible et le contexte
        // sont sur *cette* machine-là, et un DNS qui a bougé depuis
        // l'ouverture enverrait la fermeture sur un Chromium qui n'a jamais
        // entendu parler d'eux.
        if let Ok(browser_ws) = self.browser_ws(tab.at).await
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
        // Last, and after the cookies are safe: a listener that hears
        // `task_finished` is entitled to assume the task left nothing behind.
        self.observer
            .task_finished(&tab.task, &tab.outcome, Utc::now());
        drop(tab);
    }

    /// Take the tab out of the map and close it, if there is one.
    ///
    /// `outcome` is how the task ends, for whoever is listening: the park and
    /// the reaper end it on whatever the last step managed, an error ends it
    /// on the error.
    async fn close_tab(&self, ctx: &str, outcome: Option<StepOutcome>) {
        let tab = self.lock().remove(ctx);
        if let Some(mut tab) = tab {
            if let Some(outcome) = outcome {
                tab.outcome = outcome;
            }
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

    /// After a navigation landed: is the page a wall, or a challenge we can
    /// name?
    ///
    /// **Le défi passe avant le mur, et c'est l'ordre qui compte.** Une page
    /// Turnstile porte le titre « Just a moment… » *et* un `.cf-turnstile` :
    /// les deux tests réussissent, et le plus précis des deux est celui qui
    /// dit quoi faire. `blocked_by_site` reste pour ce qui n'a pas de défi
    /// lisible — un 403 nu, un « Access denied » — c'est-à-dire pour ce qu'une
    /// clé de solveur ne changerait pas.
    async fn wall_check(&self, page_url: &str, landed: &Url) -> Result<(), ProviderError> {
        let mut page = self
            .driver
            .connect(&Secret::new(page_url.to_owned()))
            .await?;
        let answer = page.evaluate(WALL_CHECK.to_owned()).await;
        let answer = match answer {
            Ok(answer) => answer,
            Err(err) => {
                page.close().await;
                return Err(err);
            }
        };
        let title = answer[0].as_str().unwrap_or_default().to_ascii_lowercase();
        let status = answer[1].as_u64().unwrap_or_default();
        let challenge =
            ChallengeKind::parse(answer[2].as_str().unwrap_or_default()).and_then(|kind| {
                let site_key = answer[3].as_str().unwrap_or_default();
                (!site_key.is_empty()).then(|| Challenge {
                    kind,
                    site_key: site_key.to_owned(),
                    page_url: landed.clone(),
                })
            });

        if let Some(challenge) = challenge {
            let outcome = self.solve(&mut page, &challenge).await;
            page.close().await;
            return outcome;
        }
        page.close().await;

        if matches!(status, 403 | 503) || BLOCKED_TITLES.iter().any(|wall| title.contains(wall)) {
            tracing::warn!(
                status,
                "the site answered with a wall; no challenge to name in it"
            );
            return Err(ProviderError::Terminal {
                code: BLOCKED_BY_SITE,
            });
        }
        Ok(())
    }

    /// Franchir un défi : demander le jeton, le poser dans le champ, et rendre
    /// la main.
    ///
    /// # Ce que « poursuivre » veut dire, et ce qu'il ne veut pas dire
    ///
    /// Le jeton est posé dans le champ que le widget expose
    /// ([`ChallengeKind::response_field`]), créé s'il n'y est pas — c'est ce
    /// que reCAPTCHA fait lui-même : un `<textarea>` caché dans le conteneur.
    /// C'est ce champ que le `submit` de la page lit, donc l'étape suivante du
    /// modèle (un `Click` sur le bouton) part avec le jeton.
    ///
    /// **Le plafond, écrit ici parce que quelqu'un le croira plus large.** Un
    /// widget dont le *rappel* JavaScript soumet le formulaire tout seul n'est
    /// pas couvert : nous posons une valeur, nous n'appelons pas son rappel,
    /// parce que le nom du rappel est celui du site et qu'aller le chercher
    /// dans `___grecaptcha_cfg` est exactement le genre d'astuce qui marche
    /// jusqu'au jour où elle échoue sans le dire. La montée, le jour où un
    /// client la paie : lire les rappels enregistrés et en appeler un.
    async fn solve(
        &self,
        page: &mut crate::cdp::PageSocket,
        challenge: &Challenge,
    ) -> Result<(), ProviderError> {
        let token = match self.solver.solve(challenge).await {
            Ok(token) => token,
            Err(err) => {
                tracing::warn!(
                    kind = challenge.kind.as_str(),
                    code = err.code(),
                    solver = self.solver.configured(),
                    "a captcha stood in the way and was not solved"
                );
                return Err(err);
            }
        };
        let field = challenge.kind.response_field();
        // Le jeton n'est pas un identifiant — c'est un porteur à usage unique
        // pour un widget public — mais il traverse quand même l'expression
        // échappé plutôt que concaténé, parce qu'une chaîne rendue par un
        // tiers dans du JavaScript qu'on construit n'a qu'une bonne façon
        // d'entrer.
        let js = format!(
            "(() => {{ const name = {name}, token = {token}; \
             let e = document.querySelector('[name=\"' + name + '\"]'); \
             if (!e) {{ const host = document.querySelector({host}); if (!host) return false; \
               e = document.createElement('textarea'); e.name = name; e.id = name; \
               e.style.display = 'none'; host.appendChild(e); }} \
             e.value = token; \
             e.dispatchEvent(new Event('input', {{ bubbles: true }})); \
             e.dispatchEvent(new Event('change', {{ bubbles: true }})); return true; }})()",
            name = json!(field),
            token = json!(token),
            host = json!(match challenge.kind {
                ChallengeKind::Recaptcha2 => ".g-recaptcha",
                ChallengeKind::Turnstile => ".cf-turnstile",
                ChallengeKind::HCaptcha => ".h-captcha",
            }),
        );
        if page.evaluate(js).await? != Value::Bool(true) {
            tracing::warn!(
                kind = challenge.kind.as_str(),
                "the captcha was solved but the page has nowhere to put the token"
            );
            return Err(ProviderError::Terminal { code: CAPTCHA });
        }
        tracing::info!(
            kind = challenge.kind.as_str(),
            "a captcha was solved and its token posted in {field}"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The one Fetch session
// ---------------------------------------------------------------------------

/// Les motifs d'interception de l'onglet, et le seul jeu qu'il y aura.
///
/// # Ce que la mesure a contredit (2026-09-10, Chrome 152.0.7977.83)
///
/// La v2 interceptait `{ requestStage: "Response", resourceType: "Document" }`
/// — la réponse seule, pour ne pas mettre un aller-retour de socket devant
/// chaque image de chaque page. Le brief supposait qu'ajouter
/// `handleAuthRequests: true` suffisait à faire arriver `Fetch.authRequired`.
/// **C'est faux.** Avec ce seul motif, contre un proxy qui répond `407` :
///
/// * aucun `Fetch.authRequired` n'arrive ;
/// * le `407` arrive en `requestPaused` **au stade réponse**, comme une
///   réponse ordinaire ;
/// * et le continuer donne `net::ERR_INVALID_AUTH_CREDENTIALS` à la
///   navigation.
///
/// Autrement dit, l'interception au stade réponse *avale* le défi
/// d'authentification avant que la pile réseau ait pu le poser. En ajoutant
/// `{ requestStage: "Request", resourceType: "Document" }`, la même navigation
/// donne : pause au stade requête → `continueRequest` → `Fetch.authRequired` →
/// `continueWithAuth { ProvideCredentials }` → pause au stade réponse avec un
/// `200`, **sur le même `requestId`**. Le proxy voit alors deux requêtes, la
/// seconde portant `Proxy-Authorization: Basic …`.
///
/// D'où le motif conditionnel : le stade requête n'est ajouté que quand il y a
/// des identifiants à fournir. Il coûte un aller-retour de socket **par
/// document**, pas par sous-ressource — et seulement aux locataires qui ont
/// acheté un proxy authentifié. Un déploiement sans proxy envoie exactement la
/// trame que la v2 envoyait.
fn fetch_patterns(with_credentials: bool) -> Value {
    let mut patterns = Vec::with_capacity(2);
    if with_credentials {
        patterns.push(json!({ "requestStage": "Request", "resourceType": "Document" }));
    }
    patterns.push(json!({ "requestStage": "Response", "resourceType": "Document" }));
    json!({ "patterns": patterns, "handleAuthRequests": with_credentials })
}

/// Répondre à une requête en attente, et décider si la navigation armée a
/// rapporté un document.
///
/// ponytail: the **first** document response of the navigation decides, and a
/// 3xx is skipped so a redirect to a PDF still lands here. An iframe cannot
/// beat its own parent's response, so « first » is « the main navigation » in
/// practice. The upgrade, if a frame ever does race: compare `frameId` against
/// `Page.getFrameTree`.
async fn answer_paused(page: &mut crate::cdp::PageSocket, params: &Value, watch: &Watch) {
    let request_id = params["requestId"].clone();
    // Pas de `responseStatusCode` : la requête est en attente *avant* d'être
    // envoyée. C'est l'étage que l'authentification de proxy oblige à ajouter
    // (voir `fetch_patterns`), et il n'y a rien à décider dessus — y compris
    // pour la tentative `https://` que Chrome fait avant `http://`, mesurée le
    // 2026-09-10, qui est paus­ée ici et n'arrive jamais au stade réponse.
    if params["responseStatusCode"].is_null() && params["responseErrorReason"].is_null() {
        let _ = page
            .call("Fetch.continueRequest", json!({ "requestId": request_id }))
            .await;
        return;
    }

    let status = params["responseStatusCode"].as_u64().unwrap_or_default();
    let headers = &params["responseHeaders"];
    let content_type = header(headers, "content-type").unwrap_or_default();
    let disposition = header(headers, "content-disposition");
    let armed = watch.armed.load(Ordering::Acquire);

    // A redirect has no body worth having and is not the answer: let it
    // through and keep watching, which is how `Goto(/tarifs)` → `302` →
    // `/tarifs.pdf` still arrives here. Une réponse que personne n'a armée est
    // continuée sans autre forme de procès.
    if !armed || (300..400).contains(&status) || !is_a_document(content_type, disposition) {
        let _ = page
            .call("Fetch.continueResponse", json!({ "requestId": request_id }))
            .await;
        // The main navigation's response is the first document response of a
        // navigation, and it was this one. It is a page; there is nothing left
        // for this watch to find.
        if armed && !(300..400).contains(&status) {
            watch.armed.store(false, Ordering::Release);
        }
        return;
    }

    let content_type = content_type.to_owned();
    let filename = disposition.and_then(filename_from);
    // La déclaration d'abord, pour qu'un export de 400 Mo soit refusé *avant*
    // de traverser la socket en base64. Un serveur qui ne déclare rien est
    // quand même attrapé plus bas, le transfert payé.
    let declared = header(headers, "content-length").and_then(|raw| raw.parse::<usize>().ok());
    let found = if declared.is_some_and(|length| length > MAX_DOCUMENT) {
        Err(ProviderError::Terminal { code: TOO_LARGE })
    } else {
        match page
            .call("Fetch.getResponseBody", json!({ "requestId": request_id }))
            .await
        {
            Ok(body) => {
                let raw = body["body"].as_str().unwrap_or_default();
                let bytes = if body["base64Encoded"].as_bool().unwrap_or(false) {
                    BASE64.decode(raw).unwrap_or_default()
                } else {
                    raw.as_bytes().to_vec()
                };
                if bytes.len() > MAX_DOCUMENT {
                    Err(ProviderError::Terminal { code: TOO_LARGE })
                } else {
                    Ok(BrowserOutcome::Document {
                        content_type,
                        filename,
                        bytes,
                    })
                }
            }
            // The tab still has to become a page, whatever the body did.
            Err(err) => Err(err),
        }
    };

    // **L'ordre est la synchronisation** : la décision est posée avant que la
    // réponse en attente soit rendue, et c'est le fait de la rendre qui laisse
    // `Page.navigate` revenir. Voir [`Watch`].
    *watch.found.lock().unwrap_or_else(|e| e.into_inner()) = Some(found);
    watch.armed.store(false, Ordering::Release);
    fulfil_placeholder(page, &request_id).await;
}

/// A header value by name, case-insensitively — CDP hands headers back as an
/// array of `{name, value}` and HTTP says the name is not case-sensitive.
fn header<'a>(headers: &'a Value, wanted: &str) -> Option<&'a str> {
    headers.as_array()?.iter().find_map(|entry| {
        entry["name"]
            .as_str()?
            .eq_ignore_ascii_case(wanted)
            .then(|| entry["value"].as_str())?
    })
}

/// Is this response a document to file rather than a page to read?
///
/// The list is `docs/BROWSER.md`'s and it is deliberately short. `text/html`
/// and `application/xhtml+xml` are pages. `application/json`, `text/plain` and
/// every image are *readable* — a selector finds them, Chromium renders them,
/// and turning them into files would take a working read away. What is left is
/// the three families an employee actually meets on a supplier's site: a PDF,
/// a CSV, an Office document. `application/octet-stream` is the shrug a badly
/// configured server sends, so it counts only when the server also said
/// `attachment`, which is the same server saying it meant a file.
fn is_a_document(content_type: &str, disposition: Option<&str>) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if essence == "application/octet-stream" {
        return disposition.is_some_and(|value| {
            value.split(';').next().unwrap_or_default().trim() == "attachment"
        });
    }
    essence == "application/pdf" || essence == "text/csv" || essence.starts_with("application/vnd.")
}

/// `Content-Disposition`'s `filename`, when there is one and it is a name.
///
/// A path separator in it is a counterparty writing into our classeur's name
/// space, so the last segment is all that survives — the same reduction
/// `effects.rs` makes again on the other side, because a name that crosses two
/// crates should be refused by both.
fn filename_from(disposition: &str) -> Option<String> {
    let raw = disposition.split(';').skip(1).find_map(|part| {
        let (key, value) = part.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("filename")
            .then(|| value.trim().trim_matches('"'))
    })?;
    let name = raw.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    (!name.is_empty() && name != "." && name != "..").then(|| name.to_owned())
}

/// Answer the paused request with a page of our own, so the tab stays a tab.
///
/// Called on every exit that took the body, refused it, or failed to read it:
/// a paused request that is never answered is a renderer waiting forever, and
/// `Page.navigate` waiting with it.
async fn fulfil_placeholder<S>(page: &mut crate::cdp::Cdp<S>, request_id: &Value)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let _ = page
        .call(
            "Fetch.fulfillRequest",
            json!({
                "requestId": request_id,
                "responseCode": 200,
                "responseHeaders": [
                    { "name": "content-type", "value": "text/html; charset=utf-8" }
                ],
                "body": BASE64.encode(DOCUMENT_PLACEHOLDER),
            }),
        )
        .await;
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

/// How a step went, as the observer's vocabulary has it.
///
/// The line between `Refused` and `Failed` is the one
/// [`crate::browser_observer::StepOutcome`] draws: *we* declined, versus *the
/// page or the browser* fell over. A wall and a document too big to take are
/// both refusals — nothing broke, we said no — where a dead socket, a missing
/// element and a navigation that would not load are failures. Same codes as
/// [`ProviderError::code`], so a journal row and a metric label read alike.
fn outcome_of(outcome: &Result<BrowserOutcome, ProviderError>) -> StepOutcome {
    match outcome {
        Ok(_) => StepOutcome::Ok,
        Err(err) => match err.code() {
            code @ (BLOCKED_BY_SITE
            | TOO_LARGE
            | CAPTCHA
            | crate::captcha::CAPTCHA_UNSOLVED
            | "blocked_address"
            | "unresolvable") => StepOutcome::Refused { code },
            code => StepOutcome::Failed { code },
        },
    }
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
                // No `step_done` for the park itself: it is the end of the
                // task, not a step of it, and a listener that saw a « goto »
                // here would have a row for a navigation nobody asked for.
                inner.close_tab(ctx, None).await;
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

        let page_url = inner.tab(ctx, session.employee_id).await?;
        let navigating = matches!(step, BrowserStep::Goto(_));
        let watch = inner.lock().get(ctx).map(|tab| Arc::clone(&tab.watch));
        let started = Instant::now();
        let drive = async {
            // Armé avant `Page.navigate` et pas après : `Fetch.enable` met la
            // réponse en attente, donc la décision se prend pendant la
            // navigation, par la pompe de l'onglet. Voir [`Watch`] pour
            // pourquoi rien n'attend ici.
            if let (true, Some(watch)) = (navigating, watch.as_ref()) {
                watch.arm();
            }
            let outcome = inner
                .driver
                .run(&Secret::new(page_url.clone()), &step)
                .await;
            // Au retour de `Page.navigate`, la pompe a déjà décidé : c'est sa
            // réponse à la requête en attente qui a laissé la navigation
            // revenir.
            let document = match (navigating, watch.as_ref()) {
                (true, Some(watch)) => watch.take(),
                _ => None,
            };
            // A document outranks the navigation's own answer, including its
            // failure: `Page.navigate` reporting nothing useful about a
            // response we intercepted and filed is not an error, it is the
            // interception working.
            if let Some(document) = document {
                return document;
            }
            let outcome = outcome?;
            if navigating {
                // Only a real page can be a wall. Skipped above, because the
                // page a document leaves in the tab is one we wrote. L'adresse
                // où l'on a atterri est celle que le défi de captcha porte :
                // le solveur refait la navigation depuis chez lui.
                let landed = match &outcome {
                    BrowserOutcome::Navigated(url) => url.clone(),
                    _ => blank_page(),
                };
                inner.wall_check(&page_url, &landed).await?;
            }
            Ok(outcome)
        };
        let outcome = match tokio::time::timeout(inner.step_timeout, drive).await {
            Ok(outcome) => outcome,
            Err(_) => Err(ProviderError::timeout()),
        };

        // The narration, from what the step *was* and never from what it
        // carried: `BrowserStep::name` is `&'static str` precisely so a
        // credential cannot be threaded into an audit line, and the same
        // argument holds one port over. The URL is the exception the observer
        // asks for, and only for `Goto`.
        let report = StepReport {
            kind: step.name(),
            url: match &step {
                BrowserStep::Goto(url) => Some((*url).to_string()),
                _ => None,
            },
            outcome: outcome_of(&outcome),
            took: started.elapsed(),
        };
        let task = inner.lock().get(ctx).map(|tab| tab.task.clone());
        if let Some(task) = task {
            inner.observer.step_done(&task, &report, Utc::now());
        }

        match &outcome {
            Err(err) if !tab_survives(err) => {
                inner.close_tab(ctx, Some(report.outcome.clone())).await;
            }
            _ => {
                if let Some(tab) = inner.lock().get_mut(ctx) {
                    if outcome.is_ok() {
                        tab.last_used = Instant::now();
                    }
                    tab.outcome = report.outcome.clone();
                }
                // Somebody may have opened the live view during the step —
                // a console page opened between two model calls is the
                // ordinary case, not the exotic one.
                inner.film(ctx);
            }
        }
        outcome
    }

    async fn release(&self, binding: &ProviderBinding) -> Result<(), ProviderError> {
        // The jar is the only thing that exists. A tab still open under this
        // context would save the jar back on close, so it goes first.
        self.inner.close_tab(&binding.external_id, None).await;
        self.inner.jar.forget(&binding.external_id).await
    }

    fn fleet_health(&self) -> Option<(usize, usize)> {
        Some(self.inner.fleet.health())
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
    /// What `/json/version` answers on Chrome 152 under `--headless=new`,
    /// measured 2026-09-10. The token in the middle is the point.
    const FAKE_HEADLESS_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
         (KHTML, like Gecko) HeadlessChrome/152.0.7258.67 Safari/537.36";
    /// A JPEG's first bytes and nothing else: the pump must not decode it, only
    /// hand it over.
    const FAKE_JPEG: &[u8] = b"\xff\xd8\xff\xe0 fake frame";

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
        /// What the navigation's response is, when it is not a page:
        /// (content-type, content-disposition, body). `None` is an ordinary
        /// HTML page, which is what `Fetch` sees on every other test.
        document: Option<(String, Option<String>, Vec<u8>)>,
        /// What `Content-Length` claims, when it should disagree with the
        /// body — the only way to test the refusal that happens *before* the
        /// transfer.
        declared_length: Option<usize>,
        /// `(famille, clé de site)` que la sonde de mur rapporte, quand la page
        /// porte un défi.
        captcha: Option<(String, String)>,
        /// Le jeton que l'expression d'injection a posé, si elle est passée.
        injected: Option<String>,
        /// Le proxy réclame une authentification : `Fetch.enable` fait alors
        /// suivre un `Fetch.authRequired`, comme Chromium le fait à la première
        /// requête. Mesuré le 2026-09-10 : le vrai n'y arrive qu'avec un motif
        /// au stade requête, ce que `fetch_patterns` ajoute.
        demands_auth: bool,
        /// Ce Chromium ne répond plus à `/json/version` : la sonde de santé le
        /// verra.
        down: bool,
        /// Vrai entre le `Fetch.requestPaused` que le faux a posé et la réponse
        /// que quelqu'un y donne. C'est l'état qui retient `Page.navigate` ;
        /// voir le rendez-vous dans [`serve`].
        paused: bool,
        /// Réveille le `Page.navigate` retenu quand la réponse en attente vient
        /// d'être continuée ou remplie.
        unpaused: Arc<tokio::sync::Notify>,
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
                vec![Url::parse(&format!("http://{}", self.addr)).expect("url")],
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
            let down = state.lock().unwrap().down;
            let response = if down {
                // Ce que la sonde de santé lit : pas une connexion refusée (le
                // port répond encore), un Chromium qui ne va pas bien.
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_owned()
            } else if name == "localhost" || name.trim_matches(['[', ']']).parse::<IpAddr>().is_ok()
            {
                // Chrome writes the loopback address *it* listens on, whatever
                // `Host` asked — which is why the adapter re-bases the path.
                let body = json!({
                    "Browser": "FakeChrome/1",
                    // With the token the adapter has to take out of it. A fake
                    // that advertised a clean UA would pass an adapter that
                    // never stripped anything.
                    "User-Agent": FAKE_HEADLESS_UA,
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
            let (answer, events) = {
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                state.seen.push((path.clone(), request.clone()));
                let answer = answer(&path, &request, &mut state);
                let events = events_for(&request, &mut state);
                (answer, events)
            };
            // **Le rendez-vous, et il *est* la garantie du vrai protocole.**
            // Avec `Fetch.enable` posé, Chromium ne rend pas la main à
            // `Page.navigate` tant que la réponse mise en attente n'a pas été
            // continuée ou remplie ; et la pompe écrit sa décision *avant* de
            // répondre à cette requête (voir [`Watch`]). Donc au retour de
            // `Page.navigate`, `found` est déjà posé — par construction, pas
            // par chance.
            //
            // Le faux répondait `{"frameId":"frame-1"}` tout de suite. L'étape
            // qui navigue courait alors contre la pompe, qui vit sur une autre
            // socket, et sur une machine chargée elle gagnait cette course et
            // lisait un `Watch` vide.
            //
            // **La mesure, 2026-09-10, sans le rendez-vous** (retard injecté
            // sur l'envoi du `Fetch.requestPaused` du faux, cinquante tours par
            // ligne) :
            //
            // | retard  | verts | rouges |
            // |---------|-------|--------|
            // | aucun   | 50    | 0      |
            // | 0 ms    | 18    | **32** |
            // | 1 ms    | 0     | **50** |
            // | 2 ms    | 0     | **50** |
            //
            // Zéro milliseconde — *un point de reprise en plus* pour
            // l'ordonnanceur, pas une microseconde d'horloge — fait déjà tomber
            // les deux tiers des tours, et le rouge obtenu est mot pour mot
            // celui de la CI : `Navigated(https://portal.example.com/tarifs)`
            // là où le test attend un `Document`. Avec le rendez-vous,
            // cinquante tours verts à chacun de ces retards et jusqu'à 50 ms.
            //
            // Donc ces deux tests ne passaient pas, ils avaient de la chance —
            // et charger la machine ne le montre même pas (cinquante tours
            // verts à une charge moyenne de 90). Le produit n'a jamais été en
            // cause, il est vérifié contre un vrai Chrome juste en dessous ;
            // c'est le faux qui ne reproduisait pas l'ordre dont l'adaptateur
            // dépend.
            //
            // Et seulement quand une interception est réellement armée pour
            // cette navigation : sans `document`, aucun `requestPaused` n'a été
            // posé, `paused` est faux et la navigation répond tout de suite.
            if request["method"] == "Page.navigate" {
                let unpaused = {
                    let state = state.lock().unwrap_or_else(|e| e.into_inner());
                    Arc::clone(&state.unpaused)
                };
                // `notify_one` et non `notify_waiters` : le permis est conservé
                // quand personne n'attend encore, donc aucun réveil ne peut se
                // perdre entre le relâchement du verrou et l'attente. Jamais un
                // `sleep` — un délai qui « suffit » est la panne qu'on répare.
                while state.lock().unwrap_or_else(|e| e.into_inner()).paused {
                    unpaused.notified().await;
                }
            }
            let Some(result) = answer else {
                // Hang: the adapter's deadline has to be what ends this.
                tokio::time::sleep(Duration::from_secs(5)).await;
                return;
            };
            let frame = json!({ "id": request["id"], "result": result });
            if conn.send(Message::text(frame.to_string())).await.is_err() {
                return;
            }
            // Chromium's events are unbidden and this is the fake's only way
            // to be unbidden too: a command that *causes* one carries it. The
            // ack causing the next frame is what makes a screencast a stream
            // rather than a single picture — a pump that stopped after one
            // frame would pass a test that emitted one.
            for event in events {
                if conn.send(Message::text(event.to_string())).await.is_err() {
                    return;
                }
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
            "Browser.grantPermissions" if on_browser => json!({}),
            "Network.setCookies" if on_page => json!({}),
            "Network.getAllCookies" if on_page => json!({ "cookies": state.cookies }),
            "Page.enable" if on_page => json!({}),
            "Page.addScriptToEvaluateOnNewDocument" if on_page => json!({ "identifier": "1" }),
            "Emulation.setUserAgentOverride"
            | "Emulation.setLocaleOverride"
            | "Emulation.setTimezoneOverride"
            | "Emulation.setDeviceMetricsOverride"
            | "Emulation.setGeolocationOverride"
                if on_page =>
            {
                json!({})
            }
            "Page.startScreencast" | "Page.stopScreencast" | "Page.screencastFrameAck"
                if on_page =>
            {
                json!({})
            }
            "Fetch.enable" | "Fetch.disable" | "Fetch.continueWithAuth" if on_page => json!({}),
            // La réponse à la requête en attente : c'est *elle* qui laisse
            // `Page.navigate` revenir, exactement comme sur le vrai protocole.
            // Les trois méthodes sont là parce que l'adaptateur en choisit une
            // selon ce qu'il a décidé : `continueResponse` pour une page,
            // `fulfillRequest` pour le placeholder d'un document pris ou
            // refusé, `continueRequest` pour une pause au stade requête.
            "Fetch.continueRequest" | "Fetch.continueResponse" | "Fetch.fulfillRequest"
                if on_page =>
            {
                state.paused = false;
                state.unpaused.notify_one();
                json!({})
            }
            "Fetch.getResponseBody" if on_page => {
                let body = state
                    .document
                    .as_ref()
                    .map(|(_, _, bytes)| BASE64.encode(bytes))
                    .unwrap_or_default();
                json!({ "body": body, "base64Encoded": true })
            }
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
                    let (kind, key) = state
                        .captcha
                        .clone()
                        .unwrap_or_else(|| (String::new(), String::new()));
                    json!({ "result": { "type": "object",
                        "value": [state.page.0, state.page.1, kind, key] } })
                } else if expression.contains("createElement('textarea')") {
                    // L'injection : le jeton est dans l'expression, échappé.
                    let token = expression
                        .split("token = \"")
                        .nth(1)
                        .and_then(|rest| rest.split('"').next())
                        .unwrap_or_default()
                        .to_owned();
                    state.injected = Some(token);
                    json!({ "result": { "type": "boolean", "value": true } })
                } else if expression.contains("innerText") {
                    json!({ "result": { "type": "string", "value": "Book a trip" } })
                } else {
                    json!({ "result": { "type": "boolean", "value": !expression.contains("#missing") } })
                }
            }
            other => panic!("the adapter sent {other} on {path}"),
        })
    }

    /// What a command makes the browser say afterwards, unprompted.
    fn events_for(request: &Value, state: &mut FakeState) -> Vec<Value> {
        match request["method"].as_str().unwrap_or_default() {
            // One frame per ack, so the stream sustains itself for as long as
            // the pump keeps acking — and stops the moment it stops.
            "Page.startScreencast" | "Page.screencastFrameAck" => vec![json!({
                "method": "Page.screencastFrame",
                "params": { "data": BASE64.encode(FAKE_JPEG), "sessionId": 1 },
            })],
            // The paused response, as Chromium hands it over: headers first,
            // body only if somebody asks.
            "Fetch.enable" => {
                let mut events = Vec::new();
                if state.demands_auth {
                    events.push(json!({
                        "method": "Fetch.authRequired",
                        "params": {
                            "requestId": "interception-job-1.0",
                            "resourceType": "Document",
                            "authChallenge": { "source": "Proxy", "origin": "http://gate:7000",
                                               "scheme": "basic", "realm": "proxy" },
                        },
                    }));
                }
                let Some((content_type, disposition, bytes)) = state.document.clone() else {
                    return events;
                };
                let mut headers = vec![json!({ "name": "Content-Type", "value": content_type })];
                if let Some(disposition) = disposition {
                    headers.push(json!({
                        "name": "Content-Disposition", "value": disposition,
                    }));
                }
                headers.push(json!({
                    "name": "Content-Length",
                    "value": state.declared_length.unwrap_or(bytes.len()).to_string(),
                }));
                // L'interception est armée à partir d'ici, et c'est ce qui
                // retiendra le prochain `Page.navigate` : voir le rendez-vous
                // dans `serve`.
                state.paused = true;
                events.push(json!({
                    "method": "Fetch.requestPaused",
                    "params": {
                        "requestId": "interception-1",
                        "resourceType": "Document",
                        "responseStatusCode": 200,
                        "responseHeaders": headers,
                    },
                }));
                events
            }
            _ => Vec::new(),
        }
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
                // The disguise and the emulation, on the tab's own socket and
                // before anything navigates. `Page.enable` is not decoration:
                // measured 2026-09-10, the script below is silently inert
                // without it. See `stealth_script` and `Tab::dressed`.
                "Page.enable",
                "Page.addScriptToEvaluateOnNewDocument",
                "Emulation.setUserAgentOverride",
                "Emulation.setLocaleOverride",
                "Emulation.setTimezoneOverride",
                "Emulation.setDeviceMetricsOverride",
                "Emulation.setGeolocationOverride",
                "Network.setCookies",
                // **Une fois, à l'ouverture de l'onglet, et plus jamais.** La
                // v2 l'envoyait avant chaque `Page.navigate` sur une socket à
                // elle, suivi d'un `Fetch.disable` ; la v3 n'a qu'une session
                // d'interception, celle qui porte déjà l'habillage, parce que
                // deux sessions `Fetch` sur une cible se disputent le même
                // `requestPaused` — et l'authentification de proxy en voulait
                // une deuxième. Voir `fetch_patterns`.
                "Fetch.enable",
                "Page.navigate",
                "Runtime.evaluate", // location.href
                "Runtime.evaluate", // the wall and captcha check
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
        assert_eq!(paths[2], "/devtools/page/target1");
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
        assert_eq!(
            p.inner.fleet.endpoints[0].tokens.available_permits(),
            DEFAULT_MAX_TABS
        );

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
            vec![Url::parse(&format!("http://localhost:{}", chrome.addr.port())).unwrap()],
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

    // -- narration ----------------------------------------------------------------

    #[derive(Default)]
    struct Narration {
        started: Vec<TaskRef>,
        steps: Vec<StepReport>,
        frames: Vec<Vec<u8>>,
        finished: Vec<(TaskRef, StepOutcome)>,
    }

    /// An observer that writes everything down, and whose answer to « is
    /// anybody watching? » a test can change mid-task.
    #[derive(Default)]
    struct Recorder {
        log: Mutex<Narration>,
        watching: AtomicBool,
    }

    impl Recorder {
        fn log(&self) -> std::sync::MutexGuard<'_, Narration> {
            self.log.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn kinds(&self) -> Vec<&'static str> {
            self.log().steps.iter().map(|step| step.kind).collect()
        }
    }

    impl BrowserObserver for Recorder {
        fn task_started(&self, task: &TaskRef, _at: chrono::DateTime<Utc>) {
            self.log().started.push(task.clone());
        }
        fn step_done(&self, _task: &TaskRef, step: &StepReport, _at: chrono::DateTime<Utc>) {
            self.log().steps.push(step.clone());
        }
        fn frame(&self, _task: &TaskRef, jpeg: &[u8], _at: chrono::DateTime<Utc>) {
            self.log().frames.push(jpeg.to_vec());
        }
        fn wants_frames(&self, _task: &TaskRef) -> bool {
            self.watching.load(Ordering::Acquire)
        }
        fn task_finished(&self, task: &TaskRef, outcome: &StepOutcome, _at: chrono::DateTime<Utc>) {
            self.log().finished.push((task.clone(), outcome.clone()));
        }
    }

    /// A task is one tab's life, told in order: it starts when the tab opens,
    /// every step is named by its variant and nothing else, and it ends when
    /// the tab closes.
    #[tokio::test]
    async fn a_task_is_narrated_from_the_tab_it_opens_to_the_tab_it_closes() {
        let chrome = FakeChrome::start().await;
        let seen = Arc::new(Recorder::default());
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_observer(Arc::clone(&seen) as Arc<dyn BrowserObserver>);
        let s = session(&p).await;

        // A refused address, before any tab: no task, so nothing is narrated.
        // The narration is a tab's life and this never reached one.
        let _ = p
            .act(
                &s,
                BrowserStep::Goto(&Url::parse("http://10.0.0.1/admin").unwrap()),
            )
            .await
            .expect_err("vetoed");
        assert!(
            seen.log().started.is_empty(),
            "a vetoed address opened a tab"
        );

        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();
        p.act(&s, BrowserStep::Text("#panel")).await.unwrap();
        let _ = p
            .act(&s, BrowserStep::Click("#missing"))
            .await
            .expect_err("no such element");
        p.act(&s, BrowserStep::Goto(&blank_page())).await.unwrap();

        let log = seen.log();
        assert_eq!(log.started.len(), 1, "one tab, one task");
        assert_eq!(log.started[0].provider, "chrome");
        assert_eq!(log.started[0].context, s.binding.external_id);
        assert_eq!(log.started[0].employee_id, s.employee_id);
        drop(log);

        // The names are `BrowserStep::name`'s, lower-case, and the park is not
        // among them: it is the end of the task, not a step of it.
        assert_eq!(seen.kinds(), ["goto", "text", "click"]);
        let log = seen.log();
        assert_eq!(log.steps[0].url.as_deref(), Some(site("/login").as_str()));
        assert_eq!(log.steps[1].url, None, "only a goto carries a URL");
        assert_eq!(log.steps[0].outcome, StepOutcome::Ok);
        assert_eq!(
            log.steps[2].outcome,
            StepOutcome::Failed {
                code: NO_SUCH_ELEMENT
            },
            "our selector missing is a failure, not a refusal"
        );
        assert_eq!(log.finished.len(), 1);
        assert_eq!(log.finished[0].0.task_id, log.started[0].task_id);
    }

    /// A wall ends the task as a refusal, and the tab with it.
    #[tokio::test]
    async fn a_wall_finishes_the_task_as_a_refusal() {
        let chrome = FakeChrome::start().await;
        chrome.state().page = ("Just a moment...".to_owned(), 200);
        let seen = Arc::new(Recorder::default());
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_observer(Arc::clone(&seen) as Arc<dyn BrowserObserver>);
        let s = session(&p).await;
        let _ = p
            .act(&s, BrowserStep::Goto(&site("/login")))
            .await
            .expect_err("a wall");

        let log = seen.log();
        assert_eq!(
            log.steps[0].outcome,
            StepOutcome::Refused {
                code: BLOCKED_BY_SITE
            }
        );
        assert_eq!(
            log.finished[0].1,
            StepOutcome::Refused {
                code: BLOCKED_BY_SITE
            },
            "the task ends on what stopped it"
        );
    }

    // -- the live view --------------------------------------------------------------

    /// A screencast starts because somebody is watching and stops because
    /// nobody is — and nothing is encoded when nobody ever was.
    #[tokio::test]
    async fn frames_flow_only_while_somebody_is_watching() {
        let chrome = FakeChrome::start().await;
        let seen = Arc::new(Recorder::default());
        seen.watching.store(true, Ordering::Release);
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_observer(Arc::clone(&seen) as Arc<dyn BrowserObserver>);
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();

        assert!(
            eventually(|| chrome.methods().iter().any(|m| m == "Page.startScreencast")).await,
            "nobody started filming for a watcher"
        );
        assert!(
            eventually(|| !seen.log().frames.is_empty()).await,
            "no frame reached the observer"
        );
        // The bytes are handed over as they arrived, decoded and not touched.
        assert_eq!(seen.log().frames[0], FAKE_JPEG);
        // Acked, or Chromium sends exactly one frame and then stops.
        assert!(
            chrome
                .methods()
                .iter()
                .any(|m| m == "Page.screencastFrameAck")
        );

        // Nobody is watching any more: the stream stops on its own, without a
        // step to prompt it.
        seen.watching.store(false, Ordering::Release);
        assert!(
            eventually(|| chrome.methods().iter().any(|m| m == "Page.stopScreencast")).await,
            "the pump kept filming for nobody"
        );

        // Disarm: a browser nobody ever watched never asks Chromium to encode
        // anything at all.
        let quiet = FakeChrome::start().await;
        let unwatched = Arc::new(Recorder::default());
        let q = quiet
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_observer(Arc::clone(&unwatched) as Arc<dyn BrowserObserver>);
        let qs = session(&q).await;
        q.act(&qs, BrowserStep::Goto(&site("/login")))
            .await
            .unwrap();
        assert!(
            !quiet.methods().iter().any(|m| m == "Page.startScreencast"),
            "{:?}",
            quiet.methods()
        );
        assert!(unwatched.log().frames.is_empty());
    }

    // -- the disguise and the profile -------------------------------------------------

    /// A profile a test writes, for a context that has one.
    struct FixedProfiles(BrowserProfile);

    #[async_trait]
    impl BrowserProfiles for FixedProfiles {
        async fn profile_for(&self, _ctx: &str) -> Result<BrowserProfile, ProviderError> {
            Ok(self.0.clone())
        }
    }

    /// The script is installed on the tab **before** anything navigates, and
    /// it says the things a naïve detector reads.
    #[tokio::test]
    async fn the_stealth_script_is_installed_before_the_first_navigation() {
        let chrome = FakeChrome::start().await;
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();

        let order = chrome.methods();
        let installed = order
            .iter()
            .position(|m| m == "Page.addScriptToEvaluateOnNewDocument")
            .expect("no stealth script");
        let navigated = order
            .iter()
            .position(|m| m == "Page.navigate")
            .expect("no navigation");
        assert!(installed < navigated, "{order:?}");

        let source =
            chrome.frames("Page.addScriptToEvaluateOnNewDocument")[0].1["params"]["source"]
                .as_str()
                .expect("a source")
                .to_owned();
        for claim in [
            "'webdriver', false",
            "'languages'",
            "PluginArray.prototype",
            "MimeTypeArray.prototype",
            "window.chrome",
            "toDataURL",
            "37445",
            "37446",
        ] {
            assert!(source.contains(claim), "the script never mentions {claim}");
        }

        // The UA is the binary's own, minus the token every detector reads.
        let ua = chrome.frames("Emulation.setUserAgentOverride")[0].1["params"]["userAgent"]
            .as_str()
            .expect("a user agent")
            .to_owned();
        assert!(!ua.contains("HeadlessChrome"), "{ua}");
        assert!(ua.contains("Chrome/152.0.7258.67"), "{ua}");
        // Disarm: the fake really did advertise the headless token, so the
        // assertion above is about the adapter and not about an empty string.
        assert!(FAKE_HEADLESS_UA.contains("HeadlessChrome"));
    }

    /// The noise is stable for one context and different for another — the two
    /// halves of « a fleet of real laptops », and the easy one to get wrong is
    /// the first.
    #[test]
    fn the_fingerprint_is_stable_per_context_and_not_shared_between_two() {
        let profile = BrowserProfile::default();
        assert_eq!(
            stealth_script("ctx-ada", &profile),
            stealth_script("ctx-ada", &profile),
            "the same seat changed machine between two tasks"
        );
        assert_ne!(
            seed_of("ctx-ada"),
            seed_of("ctx-grace"),
            "two seats share a canvas hash"
        );
    }

    /// The five `Emulation.*` commands carry the profile's values, and a
    /// position also buys the permission that makes it readable.
    #[tokio::test]
    async fn the_five_emulation_commands_carry_the_profile() {
        let chrome = FakeChrome::start().await;
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_profiles(Arc::new(FixedProfiles(BrowserProfile {
                locale: "de-DE".to_owned(),
                timezone: "Europe/Berlin".to_owned(),
                viewport: (390, 844, true),
                geolocation: Some((52.52, 13.405)),
            })));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();

        let params = |method: &str| chrome.frames(method)[0].1["params"].clone();
        assert_eq!(params("Emulation.setLocaleOverride")["locale"], "de-DE");
        assert_eq!(
            params("Emulation.setTimezoneOverride")["timezoneId"],
            "Europe/Berlin"
        );
        let metrics = params("Emulation.setDeviceMetricsOverride");
        assert_eq!(metrics["width"], 390);
        assert_eq!(metrics["height"], 844);
        assert_eq!(metrics["mobile"], true);
        assert_eq!(metrics["deviceScaleFactor"], 2, "a phone at scale 1");
        let position = params("Emulation.setGeolocationOverride");
        assert_eq!(position["latitude"], 52.52);
        assert_eq!(position["longitude"], 13.405);
        let ua = params("Emulation.setUserAgentOverride");
        assert_eq!(ua["acceptLanguage"], "de-DE,de;q=0.9,en;q=0.8");
        assert_eq!(ua["platform"], "Linux armv81", "a phone on x86_64");
        assert_eq!(
            chrome.frames("Browser.grantPermissions")[0].1["params"]["permissions"],
            json!(["geolocation"])
        );

        // Disarm: the default profile is French, on a desktop, nowhere — and
        // asks for no permission at all, because there is no position to read.
        let plain = FakeChrome::start().await;
        let d = plain.browser(Arc::new(MemoryCookieJar::new()));
        let ds = session(&d).await;
        d.act(&ds, BrowserStep::Goto(&site("/login")))
            .await
            .unwrap();
        let params = |method: &str| plain.frames(method)[0].1["params"].clone();
        assert_eq!(params("Emulation.setLocaleOverride")["locale"], "fr-FR");
        assert_eq!(
            params("Emulation.setTimezoneOverride")["timezoneId"],
            "Europe/Paris"
        );
        assert_eq!(params("Emulation.setDeviceMetricsOverride")["width"], 1366);
        assert_eq!(
            params("Emulation.setGeolocationOverride"),
            json!({}),
            "no position is « unavailable », not 0,0"
        );
        assert!(plain.frames("Browser.grantPermissions").is_empty());
    }

    // -- a navigation that answers with a file ----------------------------------------

    #[tokio::test]
    async fn a_navigation_whose_answer_is_not_a_page_is_a_document() {
        let chrome = FakeChrome::start().await;
        chrome.state().document = Some((
            "application/pdf".to_owned(),
            Some("attachment; filename=\"../../tarifs 2026.pdf\"".to_owned()),
            b"%PDF-1.4 fake".to_vec(),
        ));
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;

        let outcome = p
            .act(&s, BrowserStep::Goto(&site("/tarifs")))
            .await
            .expect("a document is not an error");
        match outcome {
            BrowserOutcome::Document {
                content_type,
                filename,
                bytes,
            } => {
                assert_eq!(content_type, "application/pdf");
                // The path components a counterparty put in the name are gone
                // on this side already; `effects` cuts them again.
                assert_eq!(filename.as_deref(), Some("tarifs 2026.pdf"));
                assert_eq!(bytes, b"%PDF-1.4 fake");
            }
            other => panic!("{other:?}"),
        }
        // The tab is still a tab: the paused request was answered with a page
        // of our own, so a later step has something to stand on.
        assert_eq!(p.open_tabs(), 1);
        let fulfilled = chrome.frames("Fetch.fulfillRequest");
        assert_eq!(fulfilled.len(), 1);
        assert_eq!(fulfilled[0].1["params"]["responseCode"], 200);

        // Disarm: an ordinary page is not a document, and the interception
        // lets it through untouched.
        chrome.state().document = None;
        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap(),
            BrowserOutcome::Navigated(site("/login"))
        );
    }

    #[tokio::test]
    async fn a_document_over_the_ceiling_is_refused_before_it_crosses_the_socket() {
        let chrome = FakeChrome::start().await;
        chrome.state().document = Some(("text/csv".to_owned(), None, b"nom,adresse\n".to_vec()));
        chrome.state().declared_length = Some(MAX_DOCUMENT + 1);
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;

        let err = p
            .act(&s, BrowserStep::Goto(&site("/export")))
            .await
            .expect_err("too big");
        assert_eq!(err.code(), TOO_LARGE);
        assert!(!err.is_retryable(), "the export will be the same size");
        assert!(
            chrome.frames("Fetch.getResponseBody").is_empty(),
            "the body crossed the socket anyway"
        );
        assert_eq!(
            chrome.frames("Fetch.fulfillRequest").len(),
            1,
            "a refused document still has to leave a page in the tab"
        );

        // Disarm: the same document without the declared length comes back.
        chrome.state().declared_length = None;
        assert!(matches!(
            p.act(&s, BrowserStep::Goto(&site("/export")))
                .await
                .unwrap(),
            BrowserOutcome::Document { .. }
        ));
    }

    /// The list is short on purpose: a JSON API and a plain-text page are
    /// *readable*, and turning them into files would take a working read away.
    #[test]
    fn only_the_three_families_an_employee_actually_meets_are_documents() {
        assert!(is_a_document("application/pdf", None));
        assert!(is_a_document("text/csv; charset=utf-8", None));
        assert!(is_a_document(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            None
        ));
        assert!(is_a_document(
            "application/octet-stream",
            Some("attachment; filename=x.bin")
        ));
        // A shrug without an « attachment » beside it is a badly configured
        // server, not a download.
        assert!(!is_a_document("application/octet-stream", None));
        assert!(!is_a_document("text/html; charset=utf-8", None));
        assert!(!is_a_document("application/json", None));
        assert!(!is_a_document("image/png", Some("attachment")));
    }

    // -- le proxy ---------------------------------------------------------------------

    /// Le proxy d'un contexte, écrit par un test.
    struct FixedProxy(Option<ProxyConfig>);

    #[async_trait]
    impl Proxies for FixedProxy {
        async fn proxy_for(&self, _ctx: &str) -> Result<Option<ProxyConfig>, ProviderError> {
            Ok(self.0.clone())
        }
    }

    /// Un port qui refuse : la ligne ne se lit pas, et l'onglet s'ouvre quand
    /// même — par l'adresse de la machine.
    struct BrokenProxies;

    #[async_trait]
    impl Proxies for BrokenProxies {
        async fn proxy_for(&self, _ctx: &str) -> Result<Option<ProxyConfig>, ProviderError> {
            Err(ProviderError::timeout())
        }
    }

    fn proxy(credentials: Option<(&str, &str)>) -> ProxyConfig {
        ProxyConfig {
            server: "http://gate.fournisseur.example:7000".to_owned(),
            bypass: Some("<-loopback>;*.interne.example".to_owned()),
            credentials: credentials.map(|(user, password)| (user.to_owned(), password.to_owned())),
        }
    }

    /// **Le proxy est un paramètre du contexte**, avec son bypass, et il n'y a
    /// pas de drapeau de processus à changer pour ça.
    #[tokio::test]
    async fn the_proxy_and_its_bypass_reach_the_browser_context() {
        let chrome = FakeChrome::start().await;
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_proxies(Arc::new(FixedProxy(Some(proxy(None)))));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();

        let created = chrome.frames("Target.createBrowserContext")[0].1["params"].clone();
        assert_eq!(
            created["proxyServer"],
            "http://gate.fournisseur.example:7000"
        );
        assert_eq!(created["proxyBypassList"], "<-loopback>;*.interne.example");

        // Désarmée deux fois : sans proxy le paramètre n'est pas là du tout —
        // et un port qui **échoue** est un onglet qui s'ouvre quand même, ce
        // qui est la moitié qu'on ne voit pas sinon.
        for proxies in [
            Arc::new(NoProxies) as Arc<dyn Proxies>,
            Arc::new(BrokenProxies),
        ] {
            let plain = FakeChrome::start().await;
            let d = plain
                .browser(Arc::new(MemoryCookieJar::new()))
                .with_proxies(proxies);
            let ds = session(&d).await;
            d.act(&ds, BrowserStep::Goto(&site("/login")))
                .await
                .expect("a tab opens without a proxy");
            let created = plain.frames("Target.createBrowserContext")[0].1["params"].clone();
            assert_eq!(
                created,
                json!({}),
                "a context was given a proxy it has none"
            );
        }
    }

    /// `Fetch.authRequired` reçoit les identifiants **ouverts** — c'est la
    /// seule forme que `continueWithAuth` accepte — et le motif au stade
    /// requête n'est là que quand il y a des identifiants à fournir.
    #[tokio::test]
    async fn the_proxy_credentials_answer_the_auth_challenge_and_nothing_else() {
        let chrome = FakeChrome::start().await;
        chrome.state().demands_auth = true;
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_proxies(Arc::new(FixedProxy(Some(proxy(Some((
                "orizn-eu",
                "s3cr3t-de-passage",
            )))))));
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&site("/login"))).await.unwrap();

        assert!(
            eventually(|| !chrome.frames("Fetch.continueWithAuth").is_empty()).await,
            "the challenge was never answered: {:?}",
            chrome.methods()
        );
        let answer =
            chrome.frames("Fetch.continueWithAuth")[0].1["params"]["authChallengeResponse"].clone();
        assert_eq!(answer["response"], "ProvideCredentials");
        assert_eq!(answer["username"], "orizn-eu");
        assert_eq!(answer["password"], "s3cr3t-de-passage");

        // Les motifs : le stade requête est **acheté** par les identifiants et
        // par rien d'autre. Mesuré le 2026-09-10 — sans lui, `authRequired`
        // n'arrive jamais et le 407 revient en réponse en attente.
        let patterns = chrome.frames("Fetch.enable")[0].1["params"].clone();
        assert_eq!(patterns["handleAuthRequests"], true);
        assert_eq!(
            patterns["patterns"],
            json!([
                { "requestStage": "Request", "resourceType": "Document" },
                { "requestStage": "Response", "resourceType": "Document" },
            ])
        );

        // Désarmée : un proxy sans identifiants n'achète pas le stade requête,
        // et un défi qui arrive quand même est refusé par le défaut de la pile
        // réseau plutôt que par une invention de notre part.
        let plain = FakeChrome::start().await;
        plain.state().demands_auth = true;
        let d = plain
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_proxies(Arc::new(FixedProxy(Some(proxy(None)))));
        let ds = session(&d).await;
        d.act(&ds, BrowserStep::Goto(&site("/login")))
            .await
            .unwrap();
        let patterns = plain.frames("Fetch.enable")[0].1["params"].clone();
        assert_eq!(patterns["handleAuthRequests"], false);
        assert_eq!(
            patterns["patterns"],
            json!([{ "requestStage": "Response", "resourceType": "Document" }])
        );
        assert!(
            eventually(|| !plain.frames("Fetch.continueWithAuth").is_empty()).await,
            "{:?}",
            plain.methods()
        );
        assert_eq!(
            plain.frames("Fetch.continueWithAuth")[0].1["params"]["authChallengeResponse"]["response"],
            "Default"
        );
    }

    /// **Une seule session `Fetch` par onglet, comptée.** C'est le bug que ce
    /// chantier prévoyait : deux pompes sur la même cible se volent le même
    /// `requestPaused`, et la v2 en montait une par navigation.
    #[tokio::test]
    async fn one_tab_enables_fetch_exactly_once_however_many_navigations() {
        let chrome = FakeChrome::start().await;
        let p = chrome.browser(Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;
        for path in ["/login", "/account", "/tarifs"] {
            p.act(&s, BrowserStep::Goto(&site(path))).await.unwrap();
        }
        assert_eq!(
            chrome.frames("Page.navigate").len(),
            3,
            "the three navigations did not happen"
        );
        assert_eq!(
            chrome.frames("Fetch.enable").len(),
            1,
            "a second interception session was opened: {:?}",
            chrome.methods()
        );
        assert!(
            chrome.frames("Fetch.disable").is_empty(),
            "the one session was turned off under the tab"
        );
        // Et elle est sur la socket de l'onglet, celle qui porte l'habillage —
        // pas sur une deuxième connexion à la même cible.
        let (path, _) = chrome.frames("Fetch.enable")[0].clone();
        assert_eq!(path, "/devtools/page/target1");

        // Un deuxième onglet a la sienne, et une seule aussi.
        let other = session(&p).await;
        p.act(&other, BrowserStep::Goto(&site("/login")))
            .await
            .unwrap();
        assert_eq!(chrome.frames("Fetch.enable").len(), 2);
    }

    // -- le captcha ---------------------------------------------------------------------

    /// Un solveur écrit par un test : il rend un jeton, ou il refuse.
    struct FakeSolver(Mutex<Vec<Challenge>>, Option<String>);

    #[async_trait]
    impl CaptchaSolver for FakeSolver {
        async fn solve(&self, challenge: &Challenge) -> Result<String, ProviderError> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(challenge.clone());
            match &self.1 {
                Some(token) => Ok(token.clone()),
                None => Err(ProviderError::Terminal {
                    code: crate::captcha::CAPTCHA_UNSOLVED,
                }),
            }
        }
    }

    /// Sans solveur branché, un défi est `captcha` — **pas** `blocked_by_site`.
    /// La distinction est ce qu'un opérateur lit pour savoir s'il y a quelque
    /// chose à acheter.
    #[tokio::test]
    async fn a_challenge_without_a_solver_is_captcha_and_not_blocked_by_site() {
        let chrome = FakeChrome::start().await;
        let seen = Arc::new(Recorder::default());
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_observer(Arc::clone(&seen) as Arc<dyn BrowserObserver>);
        let s = session(&p).await;

        for kind in ["recaptcha2", "turnstile", "hcaptcha"] {
            chrome.state().captcha = Some((kind.to_owned(), "6LfD3PIbAAAAAJs".to_owned()));
            // Et le titre d'un mur **par-dessus** : une page Turnstile porte les
            // deux, et c'est le défi qui gagne parce qu'il dit quoi faire.
            chrome.state().page = ("Just a moment...".to_owned(), 200);
            let err = p
                .act(&s, BrowserStep::Goto(&site("/login")))
                .await
                .expect_err("a challenge");
            assert_eq!(err.code(), CAPTCHA, "{kind}");
            assert!(!err.is_retryable(), "a second try has no solver either");
            assert_eq!(p.open_tabs(), 0, "the tab on a challenge is closed");
        }
        assert_eq!(
            seen.log().finished.last().expect("a task").1,
            StepOutcome::Refused { code: CAPTCHA },
            "the task ends on the challenge, as a refusal"
        );

        // Désarmée : le même mur **sans** défi lisible reste `blocked_by_site`,
        // qui est l'issue de ce qu'aucune clé ne franchirait.
        chrome.state().captcha = None;
        let err = p
            .act(&s, BrowserStep::Goto(&site("/login")))
            .await
            .expect_err("a wall");
        assert_eq!(err.code(), BLOCKED_BY_SITE);
        // Et une clé de site vide n'est pas un défi : rien à donner au solveur.
        chrome.state().captcha = Some(("recaptcha2".to_owned(), String::new()));
        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site("/login")))
                .await
                .expect_err("still the wall")
                .code(),
            BLOCKED_BY_SITE
        );
    }

    /// Avec un solveur, le jeton est posé dans le champ que le widget expose et
    /// la navigation se poursuit.
    #[tokio::test]
    async fn a_solved_challenge_posts_its_token_and_the_navigation_carries_on() {
        let chrome = FakeChrome::start().await;
        chrome.state().captcha = Some(("turnstile".to_owned(), "0x4AAA".to_owned()));
        chrome.state().page = ("Just a moment...".to_owned(), 200);
        let solver = Arc::new(FakeSolver(
            Mutex::default(),
            Some("0.jeton-du-defi".to_owned()),
        ));
        let p = chrome
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_solver(Arc::clone(&solver) as Arc<dyn CaptchaSolver>);
        let s = session(&p).await;

        assert_eq!(
            p.act(&s, BrowserStep::Goto(&site("/login")))
                .await
                .expect("the challenge was solved"),
            BrowserOutcome::Navigated(site("/login")),
            "a solved challenge is a navigation, not an error"
        );
        assert_eq!(p.open_tabs(), 1, "the tab survives a solved challenge");

        // Ce que le solveur a reçu : la famille, la clé publique du widget, et
        // l'adresse où l'on a atterri — rien de la page.
        let asked = solver.0.lock().unwrap().clone();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].kind, ChallengeKind::Turnstile);
        assert_eq!(asked[0].site_key, "0x4AAA");
        assert_eq!(asked[0].page_url, site("/login"));
        // Et ce que la page a reçu : le jeton, dans `cf-turnstile-response`.
        assert_eq!(
            chrome.state().injected.as_deref(),
            Some("0.jeton-du-defi"),
            "the token never reached the page"
        );
        let injection = chrome
            .frames("Runtime.evaluate")
            .into_iter()
            .find_map(|(_, frame)| {
                let js = frame["params"]["expression"].as_str()?.to_owned();
                js.contains("createElement('textarea')").then_some(js)
            })
            .expect("no injection");
        assert!(injection.contains("cf-turnstile-response"), "{injection}");

        // Désarmée : un solveur qui refuse rend son code, et l'onglet part.
        let refusing = FakeChrome::start().await;
        refusing.state().captcha = Some(("recaptcha2".to_owned(), "6LfD".to_owned()));
        let r = refusing
            .browser(Arc::new(MemoryCookieJar::new()))
            .with_solver(Arc::new(FakeSolver(Mutex::default(), None)));
        let rs = session(&r).await;
        assert_eq!(
            r.act(&rs, BrowserStep::Goto(&site("/login")))
                .await
                .expect_err("unsolved")
                .code(),
            crate::captcha::CAPTCHA_UNSOLVED
        );
        assert!(refusing.state().injected.is_none());
    }

    // -- la flotte ----------------------------------------------------------------------

    /// Une flotte sur plusieurs faux Chromium.
    fn fleet_of(machines: &[&FakeChrome], max_tabs: usize) -> ChromeBrowser {
        ChromeBrowser::new(
            machines
                .iter()
                .map(|chrome| Url::parse(&format!("http://{}", chrome.addr)).expect("url"))
                .collect(),
            Arc::new(PinnedHost::new(SITE, IpAddr::V4(Ipv4Addr::LOCALHOST))),
            Arc::new(MemoryCookieJar::new()),
        )
        .with_driver(
            CdpWebsocket::new()
                .with_connect_timeout(Duration::from_millis(500))
                .with_command_timeout(Duration::from_millis(300)),
        )
        .with_max_tabs(max_tabs)
        .with_queue_wait(Duration::from_millis(200))
        .with_step_timeout(Duration::from_secs(2))
    }

    /// **Le moins chargé, et par machine.** Le sémaphore est par point : deux
    /// machines à deux onglets portent quatre onglets, et le deuxième onglet va
    /// sur la machine vide plutôt que de remplir la première.
    #[tokio::test]
    async fn the_fleet_fills_the_least_loaded_endpoint_and_counts_tabs_per_machine() {
        let one = FakeChrome::start().await;
        let two = FakeChrome::start().await;
        let p = fleet_of(&[&one, &two], 2);

        let mut sessions = Vec::new();
        for _ in 0..4 {
            sessions.push(session(&p).await);
        }
        for s in &sessions {
            p.act(s, BrowserStep::Goto(&site("/login")))
                .await
                .expect("a tab each");
        }
        assert_eq!(p.open_tabs(), 4, "two machines at two tabs carry four");
        assert_eq!(one.state().targets, 2, "the fleet piled up on one machine");
        assert_eq!(two.state().targets, 2);
        assert_eq!(p.fleet_health(), Some((2, 2)));

        // Le cinquième attend puis revient plus tard : le plafond est par
        // machine, pas par flotte, et deux fois deux font quatre et pas cinq.
        let fifth = session(&p).await;
        let err = p
            .act(&fifth, BrowserStep::Goto(&site("/login")))
            .await
            .expect_err("both machines are full");
        assert!(err.is_retryable(), "{err:?}");
        assert_eq!(one.state().targets + two.state().targets, 4);
    }

    /// Un point malade est sauté, et la tâche qui vit dessus n'y est plus pour
    /// rien : elle reste sur le sien.
    #[tokio::test]
    async fn an_unhealthy_endpoint_is_skipped_and_a_task_stays_on_its_own() {
        let sick = FakeChrome::start().await;
        let well = FakeChrome::start().await;
        let p = fleet_of(&[&sick, &well], 3);

        // Une tâche d'abord, sur le point qui va tomber : la sonde ne l'en
        // délogera pas, parce que l'onglet y est.
        let resident = session(&p).await;
        p.act(&resident, BrowserStep::Goto(&site("/login")))
            .await
            .unwrap();
        assert_eq!(sick.state().targets, 1);

        // Marqué malade à la main : la sonde par défaut dort trente secondes,
        // donc rien ne le remettra debout pendant ce test. La sonde elle-même
        // est éprouvée par le test suivant.
        p.inner.fleet.endpoints[0]
            .healthy
            .store(false, Ordering::Release);
        assert_eq!(p.fleet_health(), Some((2, 1)));

        for _ in 0..3 {
            let s = session(&p).await;
            p.act(&s, BrowserStep::Goto(&site("/login")))
                .await
                .expect("the well one takes them");
        }
        assert_eq!(sick.state().targets, 1, "a sick endpoint took a new tab");
        assert_eq!(well.state().targets, 3);

        // Et l'onglet du résident est toujours sur sa machine : une étape de
        // plus y va, sans en ouvrir un autre ailleurs.
        p.act(&resident, BrowserStep::Location).await.unwrap();
        assert_eq!(sick.state().targets, 1);
        assert_eq!(well.state().targets, 3);
    }

    /// Toute la flotte malade : `Retryable`, et la ligne de journal nomme les
    /// deux nombres — la seule chose qui distingue « pleine » de « tombée ».
    #[tokio::test]
    async fn a_whole_fleet_that_is_down_is_retryable_and_says_how_many() {
        let one = FakeChrome::start().await;
        let two = FakeChrome::start().await;
        let p = fleet_of(&[&one, &two], 3).with_health_probe(Duration::from_millis(20));

        // Une première tâche démarre les sondes ; ensuite les deux machines
        // cessent de répondre à `/json/version` et les sondes le voient.
        let first = session(&p).await;
        p.act(&first, BrowserStep::Goto(&site("/login")))
            .await
            .unwrap();
        one.state().down = true;
        two.state().down = true;
        assert!(
            eventually(|| p.fleet_health() == Some((2, 0))).await,
            "the probes never noticed: {:?}",
            p.fleet_health()
        );

        // **Ce qui distingue « la flotte est tombée » d'un simple échec de
        // transport** : on ne compose *rien*. Un adaptateur sans flotte
        // essaierait, échouerait sur `/json/version` et rendrait lui aussi un
        // `Retryable` — donc `is_retryable()` seul est une assertion aveugle,
        // et c'est le désarmement qui l'a montrée telle. Le compte de requêtes
        // HTTP est la ligne qui mord.
        let dialled = |chrome: &FakeChrome| chrome.state().hosts.len();
        let (before_one, before_two) = (dialled(&one), dialled(&two));
        let s = session(&p).await;
        let started = Instant::now();
        let err = p
            .act(&s, BrowserStep::Goto(&site("/login")))
            .await
            .expect_err("nothing is up");
        assert!(err.is_retryable(), "{err:?}");
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "the task queued on a dead machine instead of being told to come back"
        );
        assert_eq!(
            (dialled(&one), dialled(&two)),
            (before_one, before_two),
            "a dead machine was dialled anyway"
        );
        assert_eq!(one.state().targets, 1, "a dead machine was asked for a tab");
        assert_eq!(two.state().targets, 0);

        // Désarmée : une machine qui revient est reprise sans redémarrage.
        two.state().down = false;
        assert!(
            eventually(|| p.fleet_health() == Some((2, 1))).await,
            "the probe never brought it back"
        );
        p.act(&s, BrowserStep::Goto(&site("/login")))
            .await
            .expect("the healthy one takes it");
        assert_eq!(two.state().targets, 1);
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
        /// What the browser says about itself, asked by the page rather than
        /// by us: every value here is read by the site's own script, in the
        /// document our injected script has already patched.
        async fn probe() -> Html<&'static str> {
            Html(
                "<!doctype html><title>Probe</title>\
                 <div id=\"webdriver\"></div><div id=\"tz\"></div>\
                 <div id=\"plugins\"></div><div id=\"ua\"></div>\
                 <div id=\"languages\"></div><div id=\"gpu\"></div>\
                 <script>\
                 const put = (id, v) => document.getElementById(id).textContent = String(v);\
                 put('webdriver', navigator.webdriver);\
                 put('tz', Intl.DateTimeFormat().resolvedOptions().timeZone);\
                 put('plugins', navigator.plugins.length);\
                 put('ua', navigator.userAgent);\
                 put('languages', navigator.languages.join(','));\
                 try { const gl = document.createElement('canvas').getContext('webgl');\
                   put('gpu', gl.getParameter(37445)); } catch (e) { put('gpu', 'none'); }\
                 </script>",
            )
        }
        /// A tariff, as a supplier actually serves one.
        async fn tarif() -> Response {
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/pdf"),
                    ),
                    (
                        header::CONTENT_DISPOSITION,
                        HeaderValue::from_static("attachment; filename=\"tarifs-2026.pdf\""),
                    ),
                ],
                // Not a real PDF and it does not need to be: the adapter files
                // bytes, it does not parse them.
                b"%PDF-1.4 tarifs".as_slice(),
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
            .route("/wall", get(wall))
            .route("/probe", get(probe))
            .route("/tarifs.pdf", get(tarif));
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        addr
    }

    fn real_browser(cdp: Url, jar: Arc<dyn CookieJar>) -> ChromeBrowser {
        ChromeBrowser::new(
            vec![cdp],
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

    /// **The disguise, measured on the browser rather than on the frame we
    /// sent.** The page asks the questions itself, in its own script, in a
    /// document our injected script has already been through — which is the
    /// only place the answers mean anything.
    ///
    /// The disarm is two sources rather than two runs: `/json/version` is the
    /// same binary answering about itself over HTTP, and it still says
    /// `HeadlessChrome`. So the page's `navigator.userAgent` not saying it is
    /// the adapter's doing and not the browser's.
    #[tokio::test]
    async fn a_real_chromium_does_not_announce_itself_as_a_robot() {
        let Some(cdp) = real_chrome() else { return };
        let addr = real_site().await;
        let p = real_browser(cdp.clone(), Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;
        p.act(
            &s,
            BrowserStep::Goto(&Url::parse(&format!("http://{addr}/probe")).unwrap()),
        )
        .await
        .expect("navigate");

        assert_eq!(
            text(&p, &s, "#webdriver").await.unwrap(),
            "false",
            "navigator.webdriver is what every naive detector reads first"
        );
        assert_eq!(
            text(&p, &s, "#tz").await.unwrap(),
            "Europe/Paris",
            "the default profile is a French seat, not a UTC container"
        );
        assert_eq!(
            text(&p, &s, "#languages").await.unwrap(),
            "fr-FR,fr,en",
            "the injected list, not the `acceptLanguage` header's q-values"
        );
        assert_ne!(text(&p, &s, "#plugins").await.unwrap(), "0");
        let page_ua = text(&p, &s, "#ua").await.unwrap();
        assert!(!page_ua.contains("HeadlessChrome"), "{page_ua}");
        // **The assertion that proves the injected script ran at all.**
        // `UNMASKED_VENDOR_WEBGL` reads `null` on an unpatched Chromium — the
        // extension is not enabled — so a vendor from our own table is
        // something only the script could have produced. Measured: with
        // `Page.enable` missing this read `null` while every other assertion
        // above still passed, because `navigator.webdriver` is already false
        // under `--headless=new` and the PDF plugins are already there.
        let gpu = text(&p, &s, "#gpu").await.unwrap();
        assert!(
            GPUS.iter().any(|(vendor, _)| *vendor == gpu),
            "the stealth script never ran: WebGL vendor is {gpu}"
        );

        // **Le garde « ce Chromium est bien sans tête » a été retiré, et ce
        // qu'il coûte est écrit ici.**
        //
        // Il lisait le `User-Agent` que le binaire annonce sur
        // `/json/version` et exigeait qu'il porte `HeadlessChrome`. C'est vrai
        // de Google Chrome lancé en `--headless=new`, sur lequel il a été
        // écrit, et **faux de `chromedp/headless-shell`**, qui est le binaire
        // de la CI et de la production : mesuré le 2026-09-10 (run siglair
        // 34467985232, et à la main sur le VPS), sa version 151 rend
        // `Mozilla/5.0 (X11; Linux x86_64) … Chrome/151.0.7922.109 Safari/537.36`,
        // sans jeton. Un binaire sans tête qui ne le dit pas faisait échouer le
        // garde, pas le produit.
        //
        // Ce qu'on perd : la détection du cas « quelqu'un a pointé ces tests
        // sur un Chrome avec fenêtre », où les signaux propres de la page ne
        // prouveraient rien. Ce qu'on garde, et qui suffit : l'assertion WebGL
        // ci-dessus. Un Chrome avec fenêtre rend le vrai vendeur de la machine
        // (« Google Inc. (Apple) » sur ce portable), jamais une chaîne de
        // notre table — donc elle rougit exactement dans le cas que le garde
        // surveillait, et pour la bonne raison.

        // And a profile is a profile: a second seat in Auckland reads
        // Auckland, so the timezone above is the override and not the clock.
        let elsewhere = real_browser(
            Url::parse(&std::env::var("BROWSER_CDP_URL").unwrap()).unwrap(),
            Arc::new(MemoryCookieJar::new()),
        )
        .with_profiles(Arc::new(FixedProfiles(BrowserProfile {
            timezone: "Pacific/Auckland".to_owned(),
            ..BrowserProfile::default()
        })));
        let es = session(&elsewhere).await;
        elsewhere
            .act(
                &es,
                BrowserStep::Goto(&Url::parse(&format!("http://{addr}/probe")).unwrap()),
            )
            .await
            .expect("navigate");
        assert_eq!(
            text(&elsewhere, &es, "#tz").await.unwrap(),
            "Pacific/Auckland"
        );
        elsewhere.release(&es.binding).await.unwrap();
        p.release(&s.binding).await.unwrap();
    }

    /// A PDF served by a real site, through a real Chromium: a document and
    /// not a navigation, with the bytes the site actually sent.
    #[tokio::test]
    async fn a_real_chromium_brings_a_pdf_back_as_a_document() {
        let Some(cdp) = real_chrome() else { return };
        let addr = real_site().await;
        let p = real_browser(cdp, Arc::new(MemoryCookieJar::new()));
        let s = session(&p).await;

        let outcome = p
            .act(
                &s,
                BrowserStep::Goto(&Url::parse(&format!("http://{addr}/tarifs.pdf")).unwrap()),
            )
            .await
            .expect("a PDF is not a failed navigation");
        match outcome {
            BrowserOutcome::Document {
                content_type,
                filename,
                bytes,
            } => {
                assert_eq!(content_type, "application/pdf");
                assert_eq!(filename.as_deref(), Some("tarifs-2026.pdf"));
                assert_eq!(bytes, b"%PDF-1.4 tarifs");
            }
            other => panic!("{other:?}"),
        }
        // The tab survived it: the placeholder page is a page, and a step
        // after a document still has somewhere to stand.
        assert_eq!(p.open_tabs(), 1);

        // Disarm: an HTML page on the same site is still a navigation.
        assert!(matches!(
            p.act(
                &s,
                BrowserStep::Goto(&Url::parse(&format!("http://{addr}/login")).unwrap()),
            )
            .await
            .unwrap(),
            BrowserOutcome::Navigated(_)
        ));
        p.release(&s.binding).await.unwrap();
    }

    /// Un proxy HTTP qui **sert la page lui-même** plutôt que de la relayer,
    /// et qui réclame une authentification Basic quand on le lui demande.
    ///
    /// ponytail: pas de relais, pas de `CONNECT`, pas de TLS. La question à
    /// laquelle ce faux répond est « Chromium a-t-il envoyé la requête *par
    /// là*, et avec quels identifiants ? » — et servir la réponse soi-même y
    /// répond aussi bien que la relayer, en trente lignes au lieu de deux
    /// cents. La montée, si un jour on veut mesurer une chaîne complète :
    /// relayer, et gérer `CONNECT` pour du HTTPS.
    struct FakeProxy {
        addr: SocketAddr,
        /// Chaque requête vue : `(ligne de requête, en-tête Proxy-Authorization)`.
        seen: Arc<Mutex<Vec<ProxyHit>>>,
    }

    impl FakeProxy {
        async fn start(demands_auth: bool) -> Self {
            // Toutes les interfaces, annoncé à `site_host()` : c'est *Chromium*
            // qui compose ici, et en CI il est dans un conteneur où
            // `127.0.0.1` est lui-même et pas le runner. Même règle que
            // `real_site`, pour la même raison — un `bind((site_host(), 0))`
            // marchait par accident tant que l'adresse annoncée était la boucle
            // locale.
            let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind");
            let addr = SocketAddr::new(site_host(), listener.local_addr().expect("addr").port());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let served = Arc::clone(&seen);
            tokio::spawn(async move {
                while let Ok((mut io, _)) = listener.accept().await {
                    let seen = Arc::clone(&served);
                    tokio::spawn(async move {
                        let mut head = [0u8; 4096];
                        let n = io.read(&mut head).await.unwrap_or(0);
                        let head = String::from_utf8_lossy(&head[..n]).to_string();
                        let request_line = head.lines().next().unwrap_or_default().to_owned();
                        let authorization = head.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("proxy-authorization")
                                .then(|| value.trim().to_owned())
                        });
                        seen.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push((request_line, authorization.clone()));
                        let response = if demands_auth && authorization.is_none() {
                            "HTTP/1.1 407 Proxy Authentication Required\r\n\
                             Proxy-Authenticate: Basic realm=\"fixture\"\r\n\
                             Content-Length: 0\r\nProxy-Connection: close\r\n\r\n"
                                .to_owned()
                        } else {
                            let body = "<!doctype html><title>Through the proxy</title>\
                                        <p id=\"who\">the proxy answered</p>";
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )
                        };
                        let _ = io.write_all(response.as_bytes()).await;
                        let _ = io.shutdown().await;
                    });
                }
            });
            Self { addr, seen }
        }

        fn requests(&self) -> Vec<ProxyHit> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    /// Le site que le faux proxy sert : un nom que Chromium ne résout jamais
    /// lui-même, puisque c'est le proxy qui s'en charge.
    const PROXIED: &str = "proxied.example.com";

    /// Une requête arrivée au faux proxy : sa ligne de requête, et son en-tête
    /// `Proxy-Authorization` s'il en portait un.
    type ProxyHit = (String, Option<String>);

    fn proxied_url() -> Url {
        Url::parse(&format!("http://{PROXIED}/tarifs")).expect("url")
    }

    fn browser_through(cdp: Url, proxy: ProxyConfig) -> ChromeBrowser {
        ChromeBrowser::new(
            vec![cdp],
            Arc::new(PinnedHost::new(PROXIED, site_host())),
            Arc::new(MemoryCookieJar::new()),
        )
        .with_proxies(Arc::new(FixedProxy(Some(proxy))))
    }

    /// **Le vrai Chromium sort par le proxy du contexte, et l'authentification
    /// passe par `Fetch`.** Les deux moitiés de la v3 côté proxy, mesurées sur
    /// le navigateur plutôt que sur la trame qu'on lui a envoyée.
    #[tokio::test]
    async fn a_real_chromium_leaves_by_the_context_proxy_and_authenticates_to_it() {
        let Some(cdp) = real_chrome() else { return };
        let proxy = FakeProxy::start(true).await;
        let p = browser_through(
            cdp,
            ProxyConfig {
                server: format!("http://{}", proxy.addr),
                // `<-loopback>` retire l'exception implicite qui ne proxifie
                // pas la boucle locale. **Remesuré le 2026-09-10 sur Chrome
                // 152.0.7977.83, et la mesure contredit la note précédente :
                // sans lui le test passe quand même**, parce que la
                // destination de ce test est un *nom* — `proxied.example.com`,
                // que le proxy résout et que la troisième assertion vérifie en
                // forme absolue — et jamais une adresse de boucle. L'exception
                // implicite ne l'a donc jamais concerné.
                //
                // Il reste posé pour la raison qui devient vraie le jour où un
                // test proxifie une destination locale, et cette raison n'est
                // plus « le site est sur la boucle locale » : depuis que les
                // faux s'annoncent à `site_host()`, l'adresse peut ne pas être
                // une boucle du tout, et alors la négation ne retire rien.
                bypass: Some("<-loopback>".to_owned()),
                credentials: Some(("orizn-eu".to_owned(), "s3cr3t-de-passage".to_owned())),
            },
        );
        let s = session(&p).await;
        p.act(&s, BrowserStep::Goto(&proxied_url()))
            .await
            .expect("the navigation went through the proxy");
        assert_eq!(text(&p, &s, "#who").await.unwrap(), "the proxy answered");

        // Ce que le proxy a vu, et **ce que la mesure a corrigé** (2026-09-10,
        // Chrome 152.0.7977.83) : la première requête n'est pas le `GET` qu'on
        // attendait, c'est un `CONNECT proxied.example.com:443` — la tentative
        // HTTPS-first du navigateur, elle aussi proxifiée. C'est *sur ce
        // `CONNECT`* que le 407 tombe et que `Fetch.authRequired` se déclenche ;
        // quand Chromium retombe sur `http://`, les identifiants sont déjà en
        // cache. Il passe aussi des `CONNECT www.google.com:443` de son cru
        // (ses sondes de connectivité) par le même proxy, ce qu'il faut savoir
        // avant de facturer des octets à un client au gigaoctet.
        //
        // Donc les trois assertions sont : la requête du site est arrivée là en
        // **forme absolue** (adressée au proxy, pas au site), quelque chose y
        // est arrivé **sans** identifiants (le défi a bien eu lieu), et les
        // identifiants ouverts ont suivi.
        let requests = proxy.requests();
        assert!(
            requests
                .iter()
                .any(|(line, _)| line == &format!("GET http://{PROXIED}/tarifs HTTP/1.1")),
            "the navigation did not reach the proxy in absolute form: {requests:?}"
        );
        assert!(
            requests.iter().any(|(_, auth)| auth.is_none()),
            "nothing was ever challenged, so nothing proves the auth round trip: {requests:?}"
        );
        let expected = format!("Basic {}", BASE64.encode("orizn-eu:s3cr3t-de-passage"));
        assert!(
            requests
                .iter()
                .any(|(_, auth)| auth.as_deref() == Some(expected.as_str())),
            "the credentials never reached the proxy: {requests:?}"
        );
        p.release(&s.binding).await.unwrap();

        // Désarmée : **sans** identifiants, le même proxy refuse et la
        // navigation échoue par un code nommé. Donc l'aller-retour ci-dessus
        // est bien l'authentification et pas un proxy complaisant.
        let refusing = FakeProxy::start(true).await;
        let d = browser_through(
            Url::parse(&std::env::var("BROWSER_CDP_URL").unwrap()).unwrap(),
            ProxyConfig {
                server: format!("http://{}", refusing.addr),
                // Même remarque qu'au-dessus : pas ce qui route cette
                // navigation, et son sens dépend de ce que `site_host()` rend.
                bypass: Some("<-loopback>".to_owned()),
                credentials: None,
            },
        );
        let ds = session(&d).await;
        // **Ce que devient un 407 sans rien pour y répondre n'est pas une
        // promesse de ce produit, et l'affirmer coûtait un déploiement.**
        // Mesuré le 2026-09-10 : Chrome 152 en `--headless=new` rend une
        // erreur de navigation, `chromedp/headless-shell` 151 — le binaire de
        // la CI et de la production — rend la page d'erreur du proxy comme une
        // page ordinaire, donc un `Navigated`. Les deux sont des lectures
        // défendables d'un défi auquel personne ne peut répondre, et aucune
        // n'est notre décision.
        //
        // Ce que ce test doit tenir, et qui est vrai des deux côtés : **rien
        // n'invente d'identifiants.** Sans `credentials`, l'adaptateur n'arme
        // pas le motif au stade requête, ne voit aucun `authRequired`, et ne
        // peut donc rien envoyer — un `Authorization` chez le proxy voudrait
        // dire qu'il en a fabriqué, ou repris ceux d'un autre locataire.
        let outcome = d.act(&ds, BrowserStep::Goto(&proxied_url())).await;
        assert!(
            refusing.requests().iter().all(|(_, auth)| auth.is_none()),
            "credentials appeared from nowhere ({outcome:?}): {:?}",
            refusing.requests()
        );
        assert!(
            !refusing.requests().is_empty(),
            "the proxy was never reached, so nothing was proved: {outcome:?}"
        );
        d.release(&ds.binding).await.unwrap();
    }

    /// Un proxy qui n'existe pas : une **erreur de navigation nommée**, pas un
    /// panic et pas une page vide qui se lirait comme un site muet.
    #[tokio::test]
    async fn a_real_chromium_names_the_failure_of_a_proxy_that_is_not_there() {
        let Some(cdp) = real_chrome() else { return };
        // Un port qu'on vient d'ouvrir puis de fermer : rien n'écoute là, et
        // rien ne s'y installera pendant le test.
        // Toutes les interfaces, pour que le port soit libre *partout* et pas
        // seulement sur celle qu'on annonce : l'adresse donnée à Chromium plus
        // bas est `site_host()`, et en CI ce n'est pas la boucle locale.
        let closed = {
            let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let p = browser_through(
            cdp,
            ProxyConfig {
                server: format!("http://{}:{closed}", site_host()),
                // Idem : la destination est un nom, et l'échec mesuré ici est
                // celui du proxy, pas celui d'une exception de boucle locale.
                bypass: Some("<-loopback>".to_owned()),
                credentials: None,
            },
        );
        let s = session(&p).await;
        let err = p
            .act(&s, BrowserStep::Goto(&proxied_url()))
            .await
            .expect_err("nothing is listening on that proxy");
        assert_eq!(err.code(), NAVIGATION_FAILED, "{err:?}");
        // **Et l'onglet reste**, ce qui est la règle de `tab_survives` et non
        // un oubli : `navigation_failed` est une erreur sur *notre* adresse, et
        // la page est toujours là pour l'étape suivante — celle où le modèle
        // essaie autre chose, ou celle où un opérateur répare la ligne du
        // proxy. Un proxy mort n'est pas une raison de perdre la session.
        assert_eq!(p.open_tabs(), 1);
        p.release(&s.binding).await.unwrap();
        assert_eq!(p.open_tabs(), 0, "release left a target behind");

        // Désarmée : le même Chromium, sans proxy, atteint le site servi par
        // l'axum de `real_site` — donc l'échec ci-dessus est le proxy.
        let addr = real_site().await;
        let plain = real_browser(
            Url::parse(&std::env::var("BROWSER_CDP_URL").unwrap()).unwrap(),
            Arc::new(MemoryCookieJar::new()),
        );
        let ps = session(&plain).await;
        plain
            .act(
                &ps,
                BrowserStep::Goto(&Url::parse(&format!("http://{addr}/login")).unwrap()),
            )
            .await
            .expect("no proxy, no problem");
        plain.release(&ps.binding).await.unwrap();
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
