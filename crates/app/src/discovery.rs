//! Le flux d'annuaires : les pages qu'un locataire fait relire chaque jour, et
//! ce que chacune a rendu.
//!
//! # Pourquoi un flux d'annuaires et pas un import
//!
//! Mesuré le 2026-09-21 : la liste importée (1 300 contacts Apollo) était une
//! liste de CTO d'éditeurs de logiciels, et le siège commercial a refusé les
//! cinq inscrits du jour, à raison — « aucun tunnel de réservation chez eux ».
//! Une liste achetée est une liste de *personnes* triées par titre ; les
//! acheteurs d'Orizn sont des *sociétés* d'un métier — voyagistes, OTA,
//! assureurs voyage, compagnies, TMC — et ces sociétés sont dans des annuaires
//! publics : adhérents d'une fédération, agences accréditées, membres d'une
//! chambre. [`crate::prospects::discover`] lit une telle page et range ce qui
//! y est imprimé ; jusqu'ici un opérateur devait le faire, page par page,
//! chaque matin. Une [`Source`] par annuaire (`discovery_sources`, `0113`) et
//! la boucle `loops::discovery` le font à sa place, **une fois par jour UTC au
//! plus**, au premier tick à partir de `hour` (défaut [`DEFAULT_HOUR`], 7 h,
//! une heure avant le flux des séquences pour que ce que l'annuaire rend ce
//! matin soit ce que la séquence inscrit ce matin). `read_on` est le dernier
//! jour lu et l'UPDATE qui le pose est la réclamation elle-même
//! ([`claim`]), la forme de `sequences.fed_on`.
//!
//! Un import se rejoue quand la liste change ; un annuaire *est* la liste qui
//! change — des membres arrivent, d'autres ferment — et le relire chaque jour
//! est ce qui fait que les nouveaux entrent sans qu'on y pense. Ce que la page
//! a déjà rendu ne coûte rien à relire : les deux clés naturelles de
//! `prospects` rendent la seconde lecture vide.
//!
//! # Le budget est celui de `discover`, et il n'est pas contourné
//!
//! `max_new_contacts_per_day` est lu par `Effects::discover_prospects` dans
//! les quatre couches du siège et dépensé contre tout contact que l'entreprise
//! a pris ce jour-là, par n'importe quelle porte. La boucle ne lit pas ce
//! nombre et n'en tient pas un second : elle appelle la même fonction, avec le
//! siège de la source, et quand le budget est atteint la page dit « limit
//! spent », la source note `N added, budget reached` et attend demain. Les
//! sources passent dans l'ordre de `created_at` — la première posée passe la
//! première, donc le fondateur choisit qui mange le budget en choisissant
//! l'ordre de pose, et rien d'autre. Stocker l'adresse de quelqu'un est
//! traiter sa donnée personnelle ; ce plafond est une borne légale, et deux
//! chemins vers la même table ne doivent pas en avoir chacun une copie.
//!
//! # Pourquoi `other` est refusé
//!
//! Un annuaire vaut par le segment qu'il nourrit : les comptes qu'il crée
//! portent ce segment, le flux d'une séquence les choisit par lui, et le siège
//! commercial reproduit sur chacun le tunnel de réservation de son objectif
//! (`vertical::segment_column` : `airline`, `ota`, `corporate_travel`,
//! `insurer`, `cruise`). Un compte rangé sous `other` n'est choisi par aucun
//! flux et le siège n'y trouve rien à reproduire — c'est une ligne que
//! personne ne lira. `tmc` et `relocation` restent admis : ce sont des métiers
//! nommés, à défaut d'un objectif qui les travaille aujourd'hui.
//!
//! # `robots.txt` : jamais un hôte qui nous refuse
//!
//! Ni `browser_http` ni le navigateur Chromium ne lisent `robots.txt`, et
//! l'en-tête du premier dit pourquoi : *un employé d'une personne lisant une
//! page qu'on lui a demandée n'est pas un crawler*, et il demande qu'on ne
//! l'ajoute pas en silence. Une boucle qui relit la même page chaque matin
//! **est** la chose que cet argument exclut, et `proof_of_need` le nomme :
//! « le jour où un appelant boucle sur une liste, la lecture de robots.txt lui
//! appartient, à côté de la boucle ». La voici. [`robots_permits`] lit
//! `/robots.txt` de l'hôte par `Effects::read_page` — le même jeton
//! `BrowserRead`, la même Gate, la même ligne d'audit qu'une page — et
//! [`robots_allows`] applique le groupe `User-agent: *` selon RFC 9309 : la
//! règle la plus longue gagne, `Allow` gagne à longueur égale. Elle est lue à
//! la pose (une source refusée n'est pas posée) **et** à chaque lecture (un
//! site peut nous refuser demain). Un `robots.txt` absent ou en 4xx autorise ;
//! un hôte qui ne répond pas n'autorise rien ce jour-là.
//!
//! # Trois échecs, puis `stalled`
//!
//! Une source dont la lecture échoue trois jours de suite — refusée par la
//! Gate, par `robots.txt`, ou illisible — passe `last_outcome` en
//! [`STALLED`] et n'est plus relue jusqu'à ce qu'on la repose (`remove` +
//! `add`). Trois et pas un : un résolveur peut lâcher une lecture, un site
//! peut être en maintenance un matin. Trois et pas l'infini : une page qui
//! refuse trois matins de suite a déménagé, ou nous refuse, et la relire
//! chaque jour serait le crawler que nous disons ne pas être — et une ligne
//! d'audit `browser_read` refusée par jour, pour toujours. Reposer est le
//! geste d'un humain qui a regardé la page.

use agentos_domain::action::Domain;
use agentos_domain::ids::EmployeeId;
use agentos_providers::ProviderError;
use agentos_store::db::{StoreError, TenantTx};
use chrono::{DateTime, NaiveDate, Timelike as _, Utc};
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::effects::{BrowserRead, EffectError, Effects, Subject};
use crate::gate::Authorized;
use crate::prospects::{Report, SEGMENTS};
use crate::turn::{WHOLE_PAGE, page_at};

/// L'heure UTC à partir de laquelle une source est lue, quand la pose n'en dit
/// pas : 7 h, une heure avant `sequence::DEFAULT_HOUR`.
pub const DEFAULT_HOUR: u8 = 7;

/// Combien de jours consécutifs sans lecture avant [`STALLED`].
pub const MAX_FAILURES: i16 = 3;

/// Le `last_outcome` d'une source que la boucle ne relit plus.
pub const STALLED: &str = "stalled";

/// Le `last_outcome` d'une source dont l'hôte nous refuse.
pub const ROBOTS_REFUSED: &str = "robots refused";

/// Une ligne de `discovery_sources`, telle que les colonnes la portent.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Source {
    pub id: Uuid,
    pub url: String,
    pub host: String,
    pub segment: String,
    pub country: Option<String>,
    pub employee_id: Uuid,
    pub hour: i16,
    pub read_on: Option<NaiveDate>,
    pub pages_read: i32,
    pub contacts_added: i32,
    pub failures: i16,
    pub last_outcome: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Ce qu'une pose dit.
#[derive(Debug, Clone, Copy)]
pub struct NewSource<'a> {
    pub url: &'a str,
    pub segment: &'a str,
    pub country: Option<&'a str>,
    pub employee_id: EmployeeId,
    pub hour: u8,
}

/// Pourquoi une source est refusée.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{0}")]
    BadUrl(String),
    #[error(
        "`other` is refused: an annuaire is worth the segment it feeds, and the sales seat \
         has nothing to reproduce from a company filed under `other`"
    )]
    OtherSegment,
    #[error("`segment` is one of {SEGMENTS:?}, minus `other`")]
    BadSegment,
    #[error("`country` is an ISO 3166-1 alpha-2 code")]
    BadCountry,
    #[error("`hour` is 0 to 23, UTC")]
    BadHour,
    #[error("no such employee in this company")]
    NoSuchSeat,
    #[error("host {0} is already on this company's list")]
    DuplicateHost(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for SourceError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(StoreError::from(err))
    }
}

/// Les refus qui ne coûtent ni une transaction ni une page : l'URL, le
/// segment, le pays, l'heure. Rend l'URL et l'hôte sur lequel la Gate statue.
pub fn check(new: &NewSource<'_>) -> Result<(Url, Domain, Option<String>), SourceError> {
    let (url, domain) = page_at(new.url).map_err(SourceError::BadUrl)?;
    if new.segment == "other" {
        return Err(SourceError::OtherSegment);
    }
    if !SEGMENTS.contains(&new.segment) {
        return Err(SourceError::BadSegment);
    }
    let country = match new.country.map(str::trim).filter(|c| !c.is_empty()) {
        None => None,
        Some(raw) => {
            let code = raw.to_ascii_uppercase();
            if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(SourceError::BadCountry);
            }
            Some(code)
        }
    };
    if new.hour > 23 {
        return Err(SourceError::BadHour);
    }
    Ok((url, domain, country))
}

/// Poser une source. `read_on` reste vide : le premier jour lu est le premier
/// tick à partir de `hour` — aujourd'hui si elle n'est pas passée, sinon
/// demain — parce qu'un annuaire, contrairement à un flux, ne dépense rien
/// que `discover` ne compte lui-même.
pub async fn add(tx: &mut TenantTx<'_>, new: &NewSource<'_>) -> Result<Source, SourceError> {
    let (url, domain, country) = check(new)?;
    let seat: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM employees WHERE id = $1 AND lifecycle = 'active')",
    )
    .bind(new.employee_id.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;
    if !seat {
        return Err(SourceError::NoSuchSeat);
    }
    // Asked before the INSERT rather than read off the constraint: a unique
    // violation aborts the transaction, and the caller still has a robots.txt
    // verdict to roll back on. The constraint stays underneath for the race.
    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM discovery_sources WHERE host = $1)")
            .bind(domain.as_str())
            .fetch_one(&mut ***tx)
            .await?;
    if taken {
        return Err(SourceError::DuplicateHost(domain.as_str().to_owned()));
    }
    let inserted = sqlx::query_as::<_, Source>(
        "INSERT INTO discovery_sources \
             (id, tenant_id, url, host, segment, country, employee_id, hour) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING id, url, host, segment, country, employee_id, hour, read_on, \
                   pages_read, contacts_added, failures, last_outcome, created_at",
    )
    .bind(Uuid::now_v7())
    .bind(tx.tenant_id().as_uuid())
    .bind(url.as_str())
    .bind(domain.as_str())
    .bind(new.segment)
    .bind(country)
    .bind(new.employee_id.as_uuid())
    .bind(i16::from(new.hour))
    .fetch_one(&mut ***tx)
    .await;
    match inserted {
        Ok(source) => Ok(source),
        Err(sqlx::Error::Database(err))
            if err.constraint() == Some("discovery_sources_one_per_host") =>
        {
            Err(SourceError::DuplicateHost(domain.as_str().to_owned()))
        }
        Err(err) => Err(err.into()),
    }
}

/// Les sources de ce locataire, dans l'ordre où la boucle les sert.
pub async fn list(tx: &mut TenantTx<'_>) -> Result<Vec<Source>, StoreError> {
    Ok(sqlx::query_as::<_, Source>(
        "SELECT id, url, host, segment, country, employee_id, hour, read_on, \
                pages_read, contacts_added, failures, last_outcome, created_at \
           FROM discovery_sources ORDER BY created_at, id",
    )
    .fetch_all(&mut ***tx)
    .await?)
}

/// Retirer une source. [`StoreError::NotFound`] hors du locataire. Les comptes
/// et contacts qu'elle a créés restent : ils sont à l'entreprise, pas à la page.
pub async fn remove(tx: &mut TenantTx<'_>, id: Uuid) -> Result<(), StoreError> {
    let n = sqlx::query("DELETE FROM discovery_sources WHERE id = $1")
        .bind(id)
        .execute(&mut ***tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Réclamer la lecture du jour : pose `read_on` si la source est due — pas
/// encore lue ce jour UTC, `hour` passée, pas `stalled` — et rend la ligne.
/// `None` sinon, y compris quand un autre tick vient de la réclamer : l'UPDATE
/// est la réclamation, et le second ne touche aucune ligne.
pub async fn claim(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<Source>, StoreError> {
    Ok(sqlx::query_as::<_, Source>(
        "UPDATE discovery_sources SET read_on = $2 \
          WHERE id = $1 AND (read_on IS NULL OR read_on < $2) AND hour <= $3 \
            AND last_outcome IS DISTINCT FROM $4 \
         RETURNING id, url, host, segment, country, employee_id, hour, read_on, \
                   pages_read, contacts_added, failures, last_outcome, created_at",
    )
    .bind(id)
    .bind(now.date_naive())
    .bind(i16::try_from(now.hour()).unwrap_or(i16::MAX))
    .bind(STALLED)
    .fetch_optional(&mut ***tx)
    .await?)
}

/// Ce qu'une lecture a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// La page a été lue ; `added` contacts créés, et le plafond du jour
    /// atteint ou non.
    Read { added: usize, budget_reached: bool },
    /// La page n'a pas été lue, et pourquoi — en nos mots, jamais ceux du site.
    Failed(String),
}

impl Outcome {
    /// Ce que [`Report`] a compté, en une phrase de nos propres nombres.
    #[must_use]
    pub fn of(report: &Report) -> Self {
        Self::Read {
            added: report.contacts_created,
            // La phrase de `prospects::discover` quand `max_new_contacts_per_day`
            // est dépensé — la nôtre, pas un mot de la page.
            budget_reached: report
                .refused
                .iter()
                .any(|line| line.starts_with("the daily new-contact limit")),
        }
    }
}

/// Écrire l'issue de la lecture réclamée par [`claim`] : les compteurs, et
/// `last_outcome` — [`STALLED`] au [`MAX_FAILURES`]-ième échec consécutif.
pub async fn record(tx: &mut TenantTx<'_>, id: Uuid, outcome: &Outcome) -> Result<(), StoreError> {
    match outcome {
        Outcome::Read {
            added,
            budget_reached,
        } => {
            let line = if *budget_reached {
                format!("{added} added, budget reached")
            } else {
                format!("{added} added")
            };
            sqlx::query(
                "UPDATE discovery_sources \
                    SET pages_read = pages_read + 1, contacts_added = contacts_added + $2, \
                        failures = 0, last_outcome = $3 \
                  WHERE id = $1",
            )
            .bind(id)
            .bind(i32::try_from(*added).unwrap_or(i32::MAX))
            .bind(line)
            .execute(&mut ***tx)
            .await?;
        }
        Outcome::Failed(why) => {
            sqlx::query(
                "UPDATE discovery_sources \
                    SET failures = failures + 1, \
                        last_outcome = CASE WHEN failures + 1 >= $3 THEN $4 ELSE $2 END \
                  WHERE id = $1",
            )
            .bind(id)
            .bind(why)
            .bind(MAX_FAILURES)
            .bind(STALLED)
            .execute(&mut ***tx)
            .await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

/// Lire `/robots.txt` de l'hôte de `url` et dire si la page peut être lue.
///
/// Par [`Effects::read_page`], donc sous le même jeton et la même ligne
/// d'audit qu'une page. `Ok(true)` quand le fichier manque ou répond 4xx (RFC
/// 9309 §2.3.1.3 : sans restriction) ; `Err` quand l'hôte ne répond pas —
/// on ne lit pas un site qu'on n'a pas pu interroger.
pub async fn robots_permits<A: Subject<Of = BrowserRead>>(
    effects: &Effects,
    ok: Authorized<A>,
    url: &Url,
) -> Result<bool, EffectError> {
    let mut robots = url.clone();
    robots.set_path("/robots.txt");
    robots.set_query(None);
    robots.set_fragment(None);
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    match effects.read_page(ok, &robots, WHOLE_PAGE).await {
        Ok(text) => Ok(robots_allows(text.expose_for_parsing(), &target)),
        // 404, 403, « pas une page », « pas de body » : pas de robots.txt.
        Err(EffectError::Provider(ProviderError::Terminal { .. })) => Ok(true),
        Err(err) => Err(err),
    }
}

/// RFC 9309 sur le groupe `User-agent: *` : parmi les règles `Allow` et
/// `Disallow` dont le motif correspond à `path`, la plus longue gagne, et
/// `Allow` gagne à longueur égale. Un fichier sans groupe `*` autorise tout.
///
/// ponytail: le groupe `*` seulement. Le navigateur n'annonce pas de jeton
/// produit qu'un site pourrait nommer, et un site qui refuse tout le monde
/// nous refuse.
#[must_use]
pub fn robots_allows(robots: &str, path: &str) -> bool {
    let mut in_star = false;
    let mut after_rules = false;
    let mut best: Option<(usize, bool)> = None;
    for raw in robots.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let (field, value) = (field.trim().to_ascii_lowercase(), value.trim());
        match field.as_str() {
            "user-agent" => {
                // Une ligne `User-agent` après des règles ouvre un groupe neuf.
                if after_rules {
                    in_star = false;
                    after_rules = false;
                }
                in_star |= value == "*";
            }
            "allow" | "disallow" => {
                after_rules = true;
                if !in_star || value.is_empty() {
                    continue;
                }
                if pattern_matches(value, path) {
                    let allow = field == "allow";
                    let better = match best {
                        None => true,
                        Some((len, was_allow)) => {
                            value.len() > len || (value.len() == len && allow && !was_allow)
                        }
                    };
                    if better {
                        best = Some((value.len(), allow));
                    }
                }
            }
            _ => {}
        }
    }
    best.is_none_or(|(_, allow)| allow)
}

/// Un motif de `robots.txt` : préfixe, `*` pour n'importe quoi, `$` final
/// pour « et rien après ».
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let mut parts = pattern.split('*');
    let head = parts.next().unwrap_or_default();
    let Some(mut rest) = path.strip_prefix(head) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return !anchored || rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    if anchored {
        rest.ends_with(last)
    } else {
        rest.contains(last)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_store::db::Db;
    use chrono::TimeDelta;

    use super::*;

    /// **La règle la plus longue gagne, `Allow` gagne à longueur égale, et un
    /// fichier sans groupe `*` n'interdit rien.**
    #[test]
    fn robots_are_read_as_rfc_9309_reads_them() {
        assert!(robots_allows("", "/members"));
        assert!(robots_allows(
            "User-agent: googlebot\nDisallow: /",
            "/members"
        ));
        assert!(!robots_allows("User-agent: *\nDisallow: /", "/members"));
        assert!(!robots_allows(
            "User-agent: *\nDisallow: /members",
            "/members/2026"
        ));
        assert!(robots_allows(
            "User-agent: *\nDisallow: /private",
            "/members"
        ));
        assert!(robots_allows("User-agent: *\nDisallow:", "/members"));
        // Plus longue gagne : `/members/` est interdit, `/members/public` permis.
        let mixed = "User-agent: *\nDisallow: /members/\nAllow: /members/public";
        assert!(!robots_allows(mixed, "/members/2026"));
        assert!(robots_allows(mixed, "/members/public/2026"));
        // À longueur égale, `Allow`.
        assert!(robots_allows(
            "User-agent: *\nDisallow: /a\nAllow: /a",
            "/a"
        ));
        // Le groupe `*` partagé avec un autre agent, et fermé par le suivant.
        let groups = "User-agent: a\nUser-agent: *\nDisallow: /x\n\nUser-agent: b\nDisallow: /";
        assert!(!robots_allows(groups, "/x"));
        assert!(robots_allows(groups, "/y"));
        // Jokers et ancre.
        assert!(!robots_allows(
            "User-agent: *\nDisallow: /*.pdf$",
            "/list/a.pdf"
        ));
        assert!(robots_allows(
            "User-agent: *\nDisallow: /*.pdf$",
            "/list/a.pdfx"
        ));
        assert!(!robots_allows(
            "User-agent: *\nDisallow: /*/print",
            "/a/b/print?x"
        ));
        assert!(!robots_allows(
            "User-agent: *\nDisallow: /members$",
            "/members"
        ));
        assert!(robots_allows(
            "User-agent: *\nDisallow: /members$",
            "/members/"
        ));
        // Commentaires et casse.
        assert!(!robots_allows(
            "USER-AGENT: * # tous\nDISALLOW: /m # rien",
            "/m"
        ));
    }

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; discovery tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed(db: &Db) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("disc-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");
        (tenant, employee)
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    fn source<'a>(url: &'a str, segment: &'a str, employee: EmployeeId) -> NewSource<'a> {
        NewSource {
            url,
            segment,
            country: None,
            employee_id: employee,
            hour: DEFAULT_HOUR,
        }
    }

    /// **`other` est refusé avec son motif, un hôte ne se pose qu'une fois, et
    /// les refus de forme ne coûtent pas une ligne.**
    #[tokio::test]
    async fn other_and_a_second_page_of_the_same_host_are_refused() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tx");

        let err = add(
            &mut tx,
            &source("https://ectaa.org/members", "other", employee),
        )
        .await
        .expect_err("other");
        assert!(matches!(err, SourceError::OtherSegment), "{err}");
        assert!(err.to_string().contains("nothing to reproduce"), "{err}");
        for (new, want) in [
            (
                source("https://ectaa.org/members", "cruise_line", employee),
                "segment",
            ),
            (source("ectaa.org/members", "ota", employee), "url"),
            (
                NewSource {
                    hour: 24,
                    ..source("https://ectaa.org/members", "ota", employee)
                },
                "hour",
            ),
            (
                NewSource {
                    country: Some("France"),
                    ..source("https://ectaa.org/members", "ota", employee)
                },
                "country",
            ),
            (
                source(
                    "https://ectaa.org/members",
                    "ota",
                    EmployeeId::new_v7(Utc::now()),
                ),
                "employee",
            ),
        ] {
            let err = add(&mut tx, &new).await.expect_err(want);
            assert!(err.to_string().contains(want), "{want}: {err}");
        }
        assert!(list(&mut tx).await.expect("list").is_empty());

        let first = add(
            &mut tx,
            &NewSource {
                country: Some("be"),
                ..source("https://ectaa.org/members?page=1", "ota", employee)
            },
        )
        .await
        .expect("first");
        assert_eq!(first.host, "ectaa.org");
        assert_eq!(first.country.as_deref(), Some("BE"), "upper-cased");
        assert_eq!(first.hour, i16::from(DEFAULT_HOUR));
        assert!(first.read_on.is_none(), "never read");
        let err = add(
            &mut tx,
            &source("https://ectaa.org/partners", "tmc", employee),
        )
        .await
        .expect_err("same host");
        assert!(
            matches!(err, SourceError::DuplicateHost(ref h) if h == "ectaa.org"),
            "{err}"
        );
        assert_eq!(list(&mut tx).await.expect("list").len(), 1);

        remove(&mut tx, first.id).await.expect("remove");
        assert!(matches!(
            remove(&mut tx, first.id).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// **Une réclamation par jour, pas avant l'heure, et plus du tout après
    /// trois échecs.**
    #[tokio::test]
    async fn a_source_is_claimed_once_a_day_from_its_hour_and_stalls_after_three_failures() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let source = add(
            &mut tx,
            &NewSource {
                hour: 9,
                ..source("https://ectaa.org/members", "ota", employee)
            },
        )
        .await
        .expect("add");
        let today = Utc::now().date_naive();
        let at = |day: NaiveDate, h: u32| day.and_hms_opt(h, 0, 0).expect("time").and_utc();

        assert!(
            claim(&mut tx, source.id, at(today, 8))
                .await
                .expect("claim")
                .is_none(),
            "before the hour"
        );
        let claimed = claim(&mut tx, source.id, at(today, 9))
            .await
            .expect("claim")
            .expect("at the hour");
        assert_eq!(claimed.read_on, Some(today));
        assert!(
            claim(&mut tx, source.id, at(today, 23))
                .await
                .expect("claim")
                .is_none(),
            "once a day"
        );
        record(
            &mut tx,
            source.id,
            &Outcome::Read {
                added: 4,
                budget_reached: true,
            },
        )
        .await
        .expect("record");
        let read = &list(&mut tx).await.expect("list")[0];
        assert_eq!(
            (read.pages_read, read.contacts_added, read.failures),
            (1, 4, 0)
        );
        assert_eq!(
            read.last_outcome.as_deref(),
            Some("4 added, budget reached")
        );

        // Three mornings of refusal: the first two are named, the third stalls.
        for day in 1..=3 {
            let when = at(today + TimeDelta::days(day), 9);
            assert!(
                claim(&mut tx, source.id, when)
                    .await
                    .expect("claim")
                    .is_some()
            );
            record(
                &mut tx,
                source.id,
                &Outcome::Failed(ROBOTS_REFUSED.to_owned()),
            )
            .await
            .expect("record");
            let now = &list(&mut tx).await.expect("list")[0];
            let want = if day < 3 { ROBOTS_REFUSED } else { STALLED };
            assert_eq!(now.last_outcome.as_deref(), Some(want), "day {day}");
            assert_eq!(i64::from(now.failures), day);
        }
        assert!(
            claim(&mut tx, source.id, at(today + TimeDelta::days(4), 9))
                .await
                .expect("claim")
                .is_none(),
            "stalled: not claimed again"
        );
        // A success resets the count, so three failures means three in a row.
        record(
            &mut tx,
            source.id,
            &Outcome::Read {
                added: 0,
                budget_reached: false,
            },
        )
        .await
        .expect("record");
        let reset = &list(&mut tx).await.expect("list")[0];
        assert_eq!(
            (reset.failures, reset.last_outcome.as_deref()),
            (0, Some("0 added"))
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }
}
