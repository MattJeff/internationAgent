//! Le proxy d'un locataire : l'adresse par laquelle ses onglets sortent, et
//! les identifiants qui l'ouvrent, scellés.
//!
//! L'autre moitié de [`Proxies`], comme [`crate::cookie_jar`] est l'autre
//! moitié de `CookieJar` et [`crate::browser_profile`] celle de
//! `BrowserProfiles` : `browser_chrome.rs` tient un identifiant de contexte
//! (`provider = 'chrome'`, `external_id = ctx-<tag>`) et rien d'autre ; c'est
//! ici qu'on remonte à l'employé, donc au locataire, donc à sa ligne de
//! `browser_proxies` (migration 0098).
//!
//! # Ce qui est du logiciel et ce qui est une facture
//!
//! `docs/BROWSER.md` § v3 : nous construisons la **prise**, le client apporte
//! la **ressource**. Ce module ne loue aucune adresse IP, n'ouvre aucun compte
//! et ne connaît le nom d'aucun fournisseur de proxy — pas même dans une
//! constante. Un locataire sans ligne ici sort par l'adresse du VPS, ce qui est
//! l'état de départ de tout le monde et n'a rien changé depuis la v2.
//!
//! # La vérification n'a pas d'URL en dur, et c'est délibéré
//!
//! [`check`] navigue vers un service d'écho d'IP **que le client nomme**. Il
//! n'y a pas de défaut : écrire `https://api.ipify.org` dans ce fichier ferait
//! de chaque vérification une requête vers un tiers que personne n'a choisi,
//! portant l'adresse de sortie du client. Sans `echo_url`, la route le dit et
//! ne vérifie rien.
//!
//! **Ce que [`check`] prouve, et ce qu'il ne prouve pas.** Il ouvre une
//! connexion HTTP *depuis ce processus* à travers le proxy du locataire : il
//! prouve donc l'adresse, le port, les identifiants et l'adresse de sortie —
//! c'est-à-dire les quatre choses qui se trompent en pratique quand on recopie
//! une ligne depuis la console d'un fournisseur. Il ne prouve pas que Chromium
//! l'honore ; ça, c'est
//! `browser_chrome::tests::the_proxy_and_its_bypass_reach_the_browser_context`
//! et le test contre un vrai Chrome à côté, et c'est la place d'une assertion,
//! pas d'une route.

use agentos_providers::browser_chrome::{Proxies, ProxyConfig};
use agentos_providers::secrets::{Envelope, LocalEnvelopeSecretStore};
use agentos_providers::{ProviderError, Secret};
use agentos_store::db::{Db, StoreError, TenantTx};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use agentos_domain::ids::TenantId;

/// Seules les lignes `chrome` portent un contexte de ce module.
const PROVIDER: &str = agentos_providers::browser_chrome::PROVIDER;

/// Les schémas que `Target.createBrowserContext.proxyServer` accepte, et que
/// la contrainte de la migration 0098 redit en SQL. Deux endroits, exprès :
/// un `INSERT` direct ne doit pas pouvoir y déposer autre chose non plus.
const SCHEMES: &[&str] = &["http", "https", "socks4", "socks5", "socks5h"];

/// Plafond d'une vérification. Un proxy résidentiel lent est un proxy
/// résidentiel ; un proxy qui met plus de vingt secondes à rendre une adresse
/// IP est un proxy qu'il faut savoir tout de suite.
const CHECK_TIMEOUT: Duration = Duration::from_secs(20);

/// Combien d'octets d'un service d'écho on lit avant d'abandonner. Un écho
/// rend une adresse ou un petit JSON ; au-delà, c'est une page d'erreur du
/// proxy ou un portail captif.
const ECHO_MAX: usize = 4096;

/// Une ligne, telle que la console la lit. **Sans mot de passe** : il n'y a pas
/// de champ pour, et c'est le type qui l'empêche plutôt qu'une discipline de
/// sérialisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub url: String,
    pub has_credentials: bool,
    pub bypass: Option<String>,
    pub checked_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

/// Ce qu'une vérification a vu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// L'adresse que le service d'écho nous a renvoyée : l'adresse de sortie.
    pub ip: String,
    pub took_ms: u64,
}

/// Pourquoi un geste sur le proxy n'a pas eu lieu.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// Pas `http://hote:port` ni `socks5://hote:port`.
    #[error("url: {0}")]
    BadUrl(String),
    /// Le locataire n'a pas de proxy.
    #[error("this tenant has no browser proxy")]
    NoProxy,
    /// Aucun service d'écho fourni : rien n'est vérifié, et c'est dit.
    #[error(
        "no echo service was given: send {{\"echo_url\": \"…\"}} — this deployment ships no \
         third-party address of its own, so without one nothing is checked"
    )]
    NoEcho,
    /// La vérification n'a pas abouti. Le champ est un code stable, jamais un
    /// message du proxy : `proxy_unreachable`, `no_ip_in_echo`,
    /// `socks_not_checked`.
    #[error("the proxy did not answer: {0}")]
    CheckFailed(&'static str),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Le proxy n'a pas répondu, ou a refusé les identifiants.
pub const PROXY_UNREACHABLE: &str = "proxy_unreachable";
/// Le service d'écho a répondu, et rien dans sa réponse n'est une adresse IP.
pub const NO_IP_IN_ECHO: &str = "no_ip_in_echo";
/// Un proxy SOCKS ne se vérifie pas par cette route.
pub const SOCKS_NOT_CHECKED: &str = "socks_not_checked";

/// L'espace de noms du scellé. `browser://<locataire>/proxy`, à côté du pot de
/// cookies (`browser://<locataire>/<employé>`) : `proxy` n'est pas un UUID
/// d'employé, donc les deux ne peuvent pas se recouvrir.
fn context(tenant: TenantId) -> String {
    format!("browser://{}/proxy", tenant.as_uuid())
}

/// `url` telle que la colonne l'accepte : un schéma de la liste, un hôte, et
/// rien d'autre — pas de chemin, pas de requête, **pas d'identifiants dedans**,
/// qui seraient un mot de passe dans une colonne en clair.
fn vet(raw: &str) -> Result<String, Refusal> {
    let url = url::Url::parse(raw).map_err(|err| Refusal::BadUrl(format!("not a URL ({err})")))?;
    if !SCHEMES.contains(&url.scheme()) {
        return Refusal::BadUrl(format!("scheme must be one of {}", SCHEMES.join(", "))).into_err();
    }
    if url.host_str().is_none() {
        return Refusal::BadUrl("no host".to_owned()).into_err();
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Refusal::BadUrl(
            "no credentials in the URL: send them as `username` and `password`, so the password \
             is sealed rather than stored in a text column"
                .to_owned(),
        )
        .into_err();
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Refusal::BadUrl("host and port only, no path".to_owned()).into_err();
    }
    // Re-rendu depuis `Url` : la forme normalisée est celle que la contrainte
    // SQL et Chromium lisent tous les deux, et `Url` a déjà retiré le `/` final
    // pour rien.
    Ok(
        format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default())
            + &url
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default(),
    )
}

/// Sucre pour `vet`, qui ne rend jamais de succès sur ses branches d'erreur.
trait IntoErr {
    fn into_err<T>(self) -> Result<T, Refusal>;
}

impl IntoErr for Refusal {
    fn into_err<T>(self) -> Result<T, Refusal> {
        Err(self)
    }
}

// ---------------------------------------------------------------------------
// Les gestes, sous le locataire
// ---------------------------------------------------------------------------

/// Les cinq colonnes que [`get`] lit, dans l'ordre. Nommé pour la raison de
/// `routes::browser::TaskRow` : sqlx rend un tuple, et un tuple de cinq
/// `Option` est illisible à la relecture comme au clippy.
type ProxyRow = (
    String,
    Option<Vec<u8>>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<String>,
);

/// La ligne du locataire, ou rien.
pub async fn get(tx: &mut TenantTx<'_>) -> Result<Option<Row>, StoreError> {
    let row: Option<ProxyRow> = sqlx::query_as(
        "SELECT url, sealed_credentials, bypass, checked_at, last_error \
               FROM browser_proxies",
    )
    .fetch_optional(&mut ***tx)
    .await?;
    Ok(
        row.map(|(url, sealed, bypass, checked_at, last_error)| Row {
            url,
            has_credentials: sealed.is_some(),
            bypass,
            checked_at,
            last_error,
        }),
    )
}

/// Poser ou remplacer le proxy du locataire.
///
/// `username`/`password` absents : la ligne perd ses identifiants, parce que
/// « ce proxy n'en demande plus » est un état qu'il faut pouvoir écrire. Un
/// `PUT` est un remplacement, pas une retouche.
pub async fn set(
    tx: &mut TenantTx<'_>,
    cipher: &LocalEnvelopeSecretStore,
    url: &str,
    credentials: Option<(&str, &str)>,
    bypass: Option<&str>,
) -> Result<Row, Refusal> {
    let url = vet(url)?;
    let tenant = tx.tenant_id();
    let sealed = match credentials {
        // `utilisateur:mot de passe`, la forme de `Proxy-Authorization` et
        // celle que `Fetch.continueWithAuth` recompose. Un `:` dans le nom
        // d'utilisateur n'existe pas en Basic — la RFC l'interdit — donc le
        // premier `:` sépare sans ambiguïté.
        Some((username, password)) => Some(
            cipher
                .seal_in(
                    tenant,
                    &context(tenant),
                    &Secret::new(format!("{username}:{password}")),
                )?
                .to_bytes(),
        ),
        None => None,
    };
    sqlx::query(
        "INSERT INTO browser_proxies (tenant_id, url, sealed_credentials, bypass) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id) DO UPDATE \
            SET url = excluded.url, sealed_credentials = excluded.sealed_credentials, \
                bypass = excluded.bypass, checked_at = NULL, last_error = NULL",
    )
    .bind(tenant.as_uuid())
    .bind(&url)
    .bind(sealed.as_deref())
    .bind(bypass)
    .execute(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    get(tx).await?.ok_or(Refusal::NoProxy)
}

/// Retirer le proxy : le locataire sort de nouveau par l'adresse de la machine.
/// Idempotent — `false` veut dire « il n'y en avait pas », qui est l'état voulu.
pub async fn clear(tx: &mut TenantTx<'_>) -> Result<bool, StoreError> {
    // Le `WHERE` est redondant sous la RLS `force` — la politique le pose déjà —
    // et il est là quand même : `crates/app/tests/scoped_deletes.rs` interdit un
    // `DELETE` sans prédicat dans tout le dépôt, parce qu'un `DELETE FROM
    // tenants` écrit par distraction a coûté une journée. La barre est basse
    // exprès, et la respecter coûte huit caractères.
    let done = sqlx::query("DELETE FROM browser_proxies WHERE tenant_id = $1")
        .bind(tx.tenant_id().as_uuid())
        .execute(&mut ***tx)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Sortir par le proxy du locataire et demander son adresse à `echo_url`.
///
/// Le verdict est écrit sur la ligne (`checked_at`, `last_error`) dans la même
/// transaction, pour que la console montre la dernière vérification comme
/// `tenant_domains` montre la dernière relecture.
pub async fn check(
    tx: &mut TenantTx<'_>,
    cipher: &LocalEnvelopeSecretStore,
    echo_url: Option<&str>,
) -> Result<Checked, Refusal> {
    let Some(echo_url) = echo_url.filter(|raw| !raw.trim().is_empty()) else {
        return Err(Refusal::NoEcho);
    };
    let echo = url::Url::parse(echo_url)
        .map_err(|err| Refusal::BadUrl(format!("echo_url: not a URL ({err})")))?;
    if !matches!(echo.scheme(), "http" | "https") {
        return Err(Refusal::BadUrl("echo_url: http(s) only".to_owned()));
    }

    let tenant = tx.tenant_id();
    let row: Option<(String, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT url, sealed_credentials FROM browser_proxies")
            .fetch_optional(&mut ***tx)
            .await
            .map_err(StoreError::from)?;
    let (url, sealed) = row.ok_or(Refusal::NoProxy)?;

    let outcome = probe(cipher, tenant, &url, sealed.as_deref(), echo).await;
    let failure = match &outcome {
        Ok(_) => None,
        Err(Refusal::CheckFailed(code)) => Some(*code),
        // Une erreur qui n'est pas un verdict sur le proxy (un scellé qui ne
        // s'ouvre pas) n'écrit rien sur la ligne : elle ne dit rien du proxy.
        Err(_) => return outcome,
    };
    sqlx::query("UPDATE browser_proxies SET checked_at = now(), last_error = $1")
        .bind(failure)
        .execute(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
    outcome
}

/// Un `GET` à travers le proxy, et l'adresse qu'on lit dans la réponse.
async fn probe(
    cipher: &LocalEnvelopeSecretStore,
    tenant: TenantId,
    url: &str,
    sealed: Option<&[u8]>,
    echo: url::Url,
) -> Result<Checked, Refusal> {
    if url.starts_with("socks") {
        // Honnête plutôt que silencieux : le client HTTP de ce dépôt est
        // construit sans le greffon SOCKS de `reqwest`, et l'activer tirerait
        // une caisse de plus dans l'arbre pour une route de diagnostic. Chromium
        // parle SOCKS ; c'est la vérification qui ne sait pas, et elle le dit.
        return Err(Refusal::CheckFailed(SOCKS_NOT_CHECKED));
    }
    let mut proxy =
        reqwest::Proxy::all(url).map_err(|_| Refusal::CheckFailed(PROXY_UNREACHABLE))?;
    if let Some(sealed) = sealed {
        let envelope = Envelope::from_bytes(sealed)?;
        let opened = cipher.open_in(tenant, &context(tenant), &envelope)?;
        let (username, password) = opened
            .expose_for_transport()
            .split_once(':')
            .map(|(user, secret)| (user.to_owned(), secret.to_owned()))
            .ok_or(Refusal::CheckFailed(PROXY_UNREACHABLE))?;
        // Le mot de passe entre ici et ne ressort d'aucun `Debug` :
        // `reqwest::Proxy` n'en imprime pas, et rien de cette fonction ne le
        // formate.
        proxy = proxy.basic_auth(&username, &password);
    }
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(CHECK_TIMEOUT)
        .build()
        .map_err(|_| Refusal::CheckFailed(PROXY_UNREACHABLE))?;

    let started = Instant::now();
    let response = client
        .get(echo)
        .send()
        .await
        .map_err(|_| Refusal::CheckFailed(PROXY_UNREACHABLE))?;
    if !response.status().is_success() {
        return Err(Refusal::CheckFailed(PROXY_UNREACHABLE));
    }
    let body = response
        .text()
        .await
        .map_err(|_| Refusal::CheckFailed(PROXY_UNREACHABLE))?;
    let ip = first_ip(&body).ok_or(Refusal::CheckFailed(NO_IP_IN_ECHO))?;
    Ok(Checked {
        ip,
        took_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// La première adresse IP du corps d'un écho.
///
/// ponytail: un balayage de jetons plutôt qu'un parseur, parce que les services
/// d'écho rendent trois choses — `1.2.3.4`, `{"ip":"1.2.3.4"}`, ou une page —
/// et que `IpAddr::from_str` est le seul juge dont on ait besoin des trois
/// côtés. Les quatre premiers kilo-octets suffisent : un écho qui a besoin de
/// plus n'est pas un écho.
fn first_ip(body: &str) -> Option<String> {
    let head = &body[..body.len().min(ECHO_MAX)];
    head.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == ':'))
        .find_map(|token| token.parse::<IpAddr>().ok().map(|ip| ip.to_string()))
}

// ---------------------------------------------------------------------------
// Le port
// ---------------------------------------------------------------------------

/// Le proxy, lu par identifiant de contexte, ouvert avec le chiffre du
/// déploiement.
pub struct SealedProxies {
    db: Db,
    cipher: Arc<LocalEnvelopeSecretStore>,
}

impl SealedProxies {
    /// Un par déploiement ; `cipher` est [`crate::identity::envelope`]'s.
    pub fn new(db: Db, cipher: Arc<LocalEnvelopeSecretStore>) -> Self {
        Self { db, cipher }
    }
}

#[async_trait]
impl Proxies for SealedProxies {
    async fn proxy_for(&self, ctx: &str) -> Result<Option<ProxyConfig>, ProviderError> {
        // `admin_tx_bypassing_rls`, l'argument de 0095 et de `cookie_jar` : la
        // recherche par `(provider, external_id)` précède le locataire. Ce que
        // la RLS aurait garanti, l'AAD le garantit — le scellé d'un voisin ne
        // s'ouvre pas sous ce locataire-ci.
        let mut tx = self
            .db
            .admin_tx_bypassing_rls()
            .await
            .map_err(|_| ProviderError::timeout())?;
        let row = sqlx::query_as::<_, (Uuid, String, Option<Vec<u8>>, Option<String>)>(
            "SELECT p.tenant_id, p.url, p.sealed_credentials, p.bypass \
               FROM employee_resources r \
               JOIN browser_proxies p ON p.tenant_id = r.tenant_id \
              WHERE r.provider = $1 AND r.external_id = $2",
        )
        .bind(PROVIDER)
        .bind(ctx)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ProviderError::timeout())?;
        let _ = tx.rollback().await;

        let Some((tenant, url, sealed, bypass)) = row else {
            return Ok(None);
        };
        let tenant = TenantId::from_uuid(tenant);
        let credentials = match sealed {
            None => None,
            Some(sealed) => {
                // Un scellé qui ne s'ouvre plus — clé maître tournée sans la
                // fenêtre, ligne abîmée — est un proxy **sans identifiants**,
                // pas un onglet mort : le proxy refusera, ce qui est visible et
                // nommé, là où une exception ici tuerait le tour.
                let opened = Envelope::from_bytes(&sealed)
                    .and_then(|envelope| self.cipher.open_in(tenant, &context(tenant), &envelope));
                match opened {
                    Ok(secret) => secret
                        .expose_for_transport()
                        .split_once(':')
                        .map(|(user, password)| (user.to_owned(), password.to_owned())),
                    Err(err) => {
                        tracing::warn!(
                            ctx,
                            code = err.code(),
                            "the sealed proxy credentials do not open; going out unauthenticated"
                        );
                        None
                    }
                }
            }
        };
        Ok(Some(ProxyConfig {
            server: url,
            bypass,
            credentials,
        }))
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn cipher(key: &str) -> Arc<LocalEnvelopeSecretStore> {
        Arc::new(LocalEnvelopeSecretStore::new(
            Sha256::digest(key.as_bytes()).into(),
        ))
    }

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the proxy is a table");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// Un locataire, un employé, et sa ressource `browser` liée à `chrome`.
    async fn seed(db: &Db) -> (TenantId, String) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = agentos_domain::ids::EmployeeId::new_v7(now);
        let ctx = format!("ctx-{}", employee.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'proxy-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'ada', 'ada', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO employee_resources \
                 (employee_id, step, tenant_id, state, provider, external_id) \
             VALUES ($1, 'browser', $2, 'ready', 'chrome', $3)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(&ctx)
        .execute(&mut *tx)
        .await
        .expect("resource");
        tx.commit().await.expect("commit");
        (tenant, ctx)
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete");
        tx.commit().await.expect("commit");
    }

    /// La forme de l'URL est refusée des deux côtés, et surtout les
    /// identifiants dedans — qui seraient un mot de passe en clair.
    #[test]
    fn the_url_is_a_host_and_a_port_and_never_a_credential() {
        assert_eq!(
            vet("http://gate.example.com:7000").unwrap(),
            "http://gate.example.com:7000"
        );
        assert_eq!(
            vet("socks5://gate.example.com:1080").unwrap(),
            "socks5://gate.example.com:1080"
        );
        // Le `/` final que `Url` ajoute ne survit pas à la normalisation.
        assert_eq!(
            vet("http://gate.example.com/").unwrap(),
            "http://gate.example.com"
        );
        for bad in [
            "ftp://gate.example.com",
            "http://user:pass@gate.example.com:7000",
            "http://gate.example.com/rotate",
            "http://gate.example.com?session=7",
            "not a url",
        ] {
            assert!(vet(bad).is_err(), "{bad} was accepted");
        }
    }

    /// Ce qu'un service d'écho rend, sous ses trois formes.
    #[test]
    fn an_ip_is_read_out_of_whatever_the_echo_answered() {
        assert_eq!(first_ip("203.0.113.7\n").as_deref(), Some("203.0.113.7"));
        assert_eq!(
            first_ip("{\"ip\":\"203.0.113.7\",\"country\":\"FR\"}").as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            first_ip("<html><body>Your IP is 2001:db8::1 today</body></html>").as_deref(),
            Some("2001:db8::1")
        );
        // Une page d'erreur de proxy n'est pas une adresse, et le dire est le
        // point : `no_ip_in_echo` est un verdict différent d'un proxy muet.
        assert_eq!(first_ip("<h1>407 Proxy Authentication Required</h1>"), None);
    }

    /// L'aller-retour complet, le scellement, le contexte, et le retrait —
    /// chacun avec son désarmement.
    #[tokio::test]
    async fn the_proxy_is_sealed_under_the_tenant_and_read_back_by_context() {
        let Some(db) = db().await else { return };
        let (tenant, ctx) = seed(&db).await;
        let port = SealedProxies::new(db.clone(), cipher("master"));

        assert!(
            port.proxy_for(&ctx).await.unwrap().is_none(),
            "a tenant with no row goes out by the machine's address"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let row = set(
            &mut tx,
            &cipher("master"),
            "http://gate.example.com:7000",
            Some(("orizn-eu", "s3cr3t-de-passage")),
            Some("<-loopback>"),
        )
        .await
        .expect("set");
        tx.commit().await.expect("commit");
        assert_eq!(row.url, "http://gate.example.com:7000");
        assert!(row.has_credentials);
        assert_eq!(row.bypass.as_deref(), Some("<-loopback>"));
        assert_eq!(row.checked_at, None);

        // Le port le rend ouvert, parce que `Fetch.continueWithAuth` n'accepte
        // rien d'autre.
        let config = port.proxy_for(&ctx).await.unwrap().expect("a proxy");
        assert_eq!(config.server, "http://gate.example.com:7000");
        assert_eq!(config.bypass.as_deref(), Some("<-loopback>"));
        assert_eq!(
            config.credentials,
            Some(("orizn-eu".to_owned(), "s3cr3t-de-passage".to_owned()))
        );
        // Et son `Debug` ne le dit pas, ce qui est la seule ligne de défense
        // contre un `tracing::debug!(?config)` écrit un soir de garde.
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("has_credentials: true"), "{rendered}");

        // Scellé : la colonne n'a pas le mot de passe.
        let mut tx = db.admin_tx_bypassing_rls().await.unwrap();
        let (stored,): (Vec<u8>,) =
            sqlx::query_as("SELECT sealed_credentials FROM browser_proxies WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            !stored.windows(6).any(|w| w == b"s3cr3t"),
            "the password is in the column in the clear"
        );

        // Sous `browser://<locataire>/proxy` et rien d'autre : ni sous un autre
        // locataire, ni sous le contexte du pot de cookies.
        let envelope = Envelope::from_bytes(&stored).expect("an envelope");
        let other = TenantId::new_v7(Utc::now());
        assert!(
            cipher("master")
                .open_in(other, &context(other), &envelope)
                .is_err(),
            "another tenant opened it"
        );
        assert!(
            cipher("master")
                .open_in(
                    tenant,
                    &format!("browser://{}/ada", tenant.as_uuid()),
                    &envelope
                )
                .is_err(),
            "the cookie jar's namespace opened it"
        );
        assert!(
            cipher("master")
                .open_in(tenant, &context(tenant), &envelope)
                .is_ok(),
            "the disarm: the right context opens it"
        );

        // Une clé maître qui a tourné : un proxy sans identifiants, pas un
        // onglet mort.
        let rotated = SealedProxies::new(db.clone(), cipher("another"));
        let config = rotated
            .proxy_for(&ctx)
            .await
            .unwrap()
            .expect("still a proxy");
        assert_eq!(config.credentials, None);

        // Un `PUT` sans identifiants les retire, et le retrait vide la ligne.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let row = set(
            &mut tx,
            &cipher("master"),
            "http://autre.example.com:8000",
            None,
            None,
        )
        .await
        .expect("set");
        assert!(!row.has_credentials);
        assert!(clear(&mut tx).await.expect("clear"));
        assert!(
            !clear(&mut tx).await.expect("clear again"),
            "not idempotent"
        );
        assert!(get(&mut tx).await.expect("get").is_none());
        tx.commit().await.expect("commit");
        assert!(port.proxy_for(&ctx).await.unwrap().is_none());

        drop_tenant(&db, tenant).await;
    }

    /// **La RLS mord** : la ligne d'un locataire n'est ni lue ni écrasée par un
    /// autre, et le scellé du premier ne s'ouvre pas sous le second.
    #[tokio::test]
    async fn a_neighbour_sees_no_proxy_and_cannot_open_the_one_next_door() {
        let Some(db) = db().await else { return };
        let (a, _) = seed(&db).await;
        let (b, _) = seed(&db).await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        set(
            &mut tx,
            &cipher("master"),
            "http://gate-a.example.com:7000",
            Some(("a", "mot-de-passe-de-a")),
            None,
        )
        .await
        .expect("set");
        tx.commit().await.expect("commit");

        // B ne voit rien, ne supprime rien, et pose la sienne sans toucher à A.
        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        assert!(get(&mut tx).await.expect("get").is_none());
        assert!(!clear(&mut tx).await.expect("clear"));
        set(
            &mut tx,
            &cipher("master"),
            "http://gate-b.example.com:7000",
            None,
            None,
        )
        .await
        .expect("set");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let row = get(&mut tx).await.expect("get").expect("still there");
        assert_eq!(row.url, "http://gate-a.example.com:7000");
        assert!(row.has_credentials, "the neighbour overwrote the row");
        tx.rollback().await.expect("rollback");

        // Le désarmement de la RLS : sous une transaction d'administration, les
        // deux lignes sont là — donc l'absence vue par B est bien la politique
        // et pas une base vide.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let (seen,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM browser_proxies WHERE tenant_id = ANY($1)")
                .bind(vec![a.as_uuid(), b.as_uuid()])
                .fetch_one(&mut *tx)
                .await
                .expect("count");
        assert_eq!(seen, 2);
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    /// Sans service d'écho, rien n'est vérifié — et c'est **dit**, pas
    /// silencieusement réussi.
    #[tokio::test]
    async fn a_check_without_an_echo_service_verifies_nothing_and_says_so() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");

        // Sans ligne : `no_proxy` avant même la question de l'écho... non :
        // l'écho est vérifié d'abord, parce que c'est une erreur de l'appelant.
        assert!(matches!(
            check(&mut tx, &cipher("master"), None).await,
            Err(Refusal::NoEcho)
        ));
        assert!(matches!(
            check(&mut tx, &cipher("master"), Some("   ")).await,
            Err(Refusal::NoEcho)
        ));
        assert!(matches!(
            check(
                &mut tx,
                &cipher("master"),
                Some("https://echo.example.com/ip")
            )
            .await,
            Err(Refusal::NoProxy)
        ));

        // Un proxy SOCKS est refusé par un code nommé plutôt que par un
        // échec réseau qu'on aurait pris pour un proxy en panne.
        set(
            &mut tx,
            &cipher("master"),
            "socks5://gate.example.com:1080",
            None,
            None,
        )
        .await
        .expect("set");
        let err = check(
            &mut tx,
            &cipher("master"),
            Some("https://echo.example.com/ip"),
        )
        .await
        .expect_err("socks");
        assert!(matches!(err, Refusal::CheckFailed(SOCKS_NOT_CHECKED)));
        // Et le verdict est sur la ligne, pas seulement dans la réponse.
        let row = get(&mut tx).await.expect("get").expect("a row");
        assert!(row.checked_at.is_some());
        assert_eq!(row.last_error.as_deref(), Some(SOCKS_NOT_CHECKED));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }
}
