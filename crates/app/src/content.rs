//! **La boucle de citation** : les questions qu'on veut gagner, ce qu'un moteur
//! répond aujourd'hui, et ce qu'il manque à notre contenu pour y être.
//!
//! `docs/ROADMAP_CROISSANCE.md` § 2.1 et `docs/CONTENU.md`. La thèse, en une
//! phrase : quand un développeur demande à un modèle *« comment vérifier par
//! API si un passeport permet d'entrer quelque part »*, la réponse cite deux ou
//! trois produits, et y être vaut plus qu'une campagne. C'est le seul canal où
//! un petit acteur bat un gros à budget égal — et personne ne sait encore
//! l'acheter, donc la seule chose qui le rend gouvernable est **une mesure**.
//!
//! # Ce que ce module mesure, et ce qu'il refuse de mesurer
//!
//! Ce qui suit est la partie la plus importante du fichier, parce que la
//! tentation est d'écrire « on mesure si ChatGPT nous cite » et de livrer
//! quelque chose qui ne le fait pas.
//!
//! ## Mesurable aujourd'hui, et mesuré
//!
//! **Une page de résultats servie publiquement, sans compte.** Un moteur qui
//! rend ses résultats en HTML à un simple `GET` est lisible par
//! [`Effects::read_page`], comme n'importe quelle page publique, avec le même
//! jeton, le même contrôle de portée et la même ligne d'audit qu'une lecture de
//! site de prospect. On y lit : sommes-nous cités, à quel rang, et qui l'est à
//! notre place.
//!
//! [`Engine::DuckDuckGoLite`] est le seul moteur livré, et le choix est
//! **daté et vérifié le 2026-09-11** : `lite.duckduckgo.com/robots.txt` et
//! `html.duckduckgo.com/robots.txt` répondent tous deux `User-agent: *` /
//! `Allow: /`, là où `duckduckgo.com/robots.txt` interdit `/lite` et `/html`
//! sur son propre hôte. On lit l'hôte qui l'autorise, et pas l'autre.
//!
//! ## Non mesurable, et pourquoi — un par un
//!
//! | moteur | pourquoi pas |
//! |---|---|
//! | **ChatGPT, Claude, Gemini (l'interface de chat)** | La réponse n'existe que derrière un compte. La lire demanderait de se connecter avec des identifiants et d'automatiser une session — ce que les conditions d'utilisation de chacun interdisent explicitement. Ce module ne le fait pas et n'expose aucun moyen de le faire. |
//! | **Google, Bing, Brave, Mojeek, Startpage** | Pas de compte à franchir, mais leur `robots.txt` refuse `/search` (vérifié le 2026-09-11 sur les cinq). Un refus écrit par le site est un refus, même quand rien ne l'applique techniquement. |
//! | **Les API de recherche payantes** (Serper, SerpAPI, Brave Search API) | Elles rendraient Google et Bing mesurables pour quelques dizaines de dollars par mois. C'est **le chemin d'extension évident** le jour où le fondateur décide de dépenser ; il n'est pas codé ici parce que rien dans ce dépôt n'appelle un service payant sans qu'on l'ait décidé. |
//!
//! Ce qui reste donc, et qui est réel : **un moteur**. Une mesure sur un moteur
//! n'est pas la citation par un modèle — c'est son meilleur indicateur
//! disponible gratuitement, parce que ce que les modèles citent sort en grande
//! partie de ce que les moteurs classent. Le dire autrement serait vendre une
//! mesure qu'on ne fait pas.
//!
//! # Où est la Gate
//!
//! [`measure`] ne lit rien lui-même : il fait émettre un jeton
//! [`BrowserRead`] par la [`PolicyGate`] pour le principal que l'`Effects`
//! porte, puis passe par [`Effects::read_page`]. Un siège sans `Channel::Web`
//! ne mesure pas, et le refus est une ligne d'audit comme les autres — c'est la
//! forme que `proof_of_need::Browse` a déjà.
//!
//! # Le texte d'un étranger
//!
//! [`Citation::excerpt`] porte **les mots de la page de résultats** : les titres
//! et résumés que le moteur affiche. Ce ne sont pas les nôtres. Le scan est fait
//! en Rust ici et rien de ce qui remonte à un modèle n'est de la prose
//! recopiée — sauf `excerpt`, qui l'est par construction, et que toute surface
//! qui le rend doit traiter comme tel. C'est la même frontière que
//! [`Effects::read_page`] pose avec `Untrusted`.
//!
//! # Pas de génération de texte
//!
//! [`brief`] rend une **structure** : ce que les pages citées couvrent, ce
//! qu'elles ne couvrent pas, qui dépasser, et l'angle — un enum à trois
//! valeurs, choisi par une règle sur le rang. Le texte est écrit par un
//! employé, avec son modèle, et atterrit dans `content_drafts`. Rien ici
//! n'écrit une phrase à publier.
//!
//! # Ce qui sort d'ici, et ce que ça ne prétend pas être
//!
//! [`propose`] est le **chemin A** de `docs/CONTENU.md` § 5 : l'article devient
//! un fichier Markdown sur une branche à lui, dans le dépôt qui sert le site du
//! client, et une pull request demande à une personne de le lire. Le dépôt et
//! la branche sont une ressource d'un siège ([`repos`]), jamais une variable
//! d'environnement — deux clients ont deux dépôts, et c'est la Gate qui statue,
//! pour un siège nommé, à chacun des trois appels.
//!
//! **Ouvrir une pull request n'est pas publier.** `state` passe à `proposed` ;
//! `published` continue de vouloir dire *quelqu'un a vu l'article à cette
//! adresse*, et `url` reste une adresse constatée que personne d'autre qu'un
//! humain n'écrit. `migrations/0102` porte l'argument entier, y compris les
//! trois façons de se passer d'un état de plus et pourquoi aucune ne tient.
//!
//! Le chemin B — un domaine web à nous — n'est pas ici et n'est pas commencé.
//! Publier dix clients sur un domaine à nous serait une ferme de contenu, et
//! le § 5 explique pourquoi c'est un refus et pas un manque.

use agentos_domain::action::{Domain, McpTool};
use agentos_domain::ids::Slug;
use agentos_store::db::{StoreError, TenantTx};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;
use uuid::Uuid;

use crate::effects::{BrowserRead, EffectError, Effects, McpCall};
use crate::gate::{Denied, PolicyGate};
use crate::turn::WHOLE_PAGE;

// ---------------------------------------------------------------------------
// Le vocabulaire
// ---------------------------------------------------------------------------

/// D'où vient une question.
///
/// Une liste fermée en Rust et pas un `CHECK` en base — `0100` argumente — mais
/// une liste quand même : sans elle la colonne accepte n'importe quoi et cesse
/// de dire quoi que ce soit. `Customer` vaut dix `Founder` : c'est une question
/// que quelqu'un a réellement posée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Le fondateur l'a écrite.
    Founder,
    /// Relevée dans les suggestions d'un moteur.
    SearchSuggest,
    /// Un client l'a posée.
    Customer,
}

impl Source {
    /// Ce qui est écrit en base.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Founder => "founder",
            Self::SearchSuggest => "search_suggest",
            Self::Customer => "customer",
        }
    }

    /// L'inverse. `None` pour tout le reste — une provenance inventée est
    /// refusée à la porte plutôt qu'écrite et découverte six mois plus tard.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        [Self::Founder, Self::SearchSuggest, Self::Customer]
            .into_iter()
            .find(|source| source.as_str() == raw)
    }
}

/// Un moteur dont la page de résultats est lisible sans compte.
///
/// **Une seule variante, et c'est un fait mesuré, pas un début.** Les docs du
/// module nomment les autres candidats et la raison de chacun. Un enum plutôt
/// qu'une chaîne parce que [`measure`] doit savoir construire une URL et lire
/// une mise en page, et ces deux choses sont propres au moteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// `lite.duckduckgo.com/lite/` — la page de résultats sans script, dix
    /// résultats, chacun rendu comme trois lignes de tableau : le rang et le
    /// titre, le résumé, puis l'hôte affiché.
    ///
    /// Autorisé par son `robots.txt` (vérifié le 2026-09-11, voir les docs du
    /// module), servi en HTML pur — donc lisible même par `HttpBrowser`, ce qui
    /// rend la mesure possible sur un déploiement sans Chromium.
    DuckDuckGoLite,
}

impl Engine {
    /// Tous les moteurs mesurables de ce déploiement.
    pub const ALL: &'static [Self] = &[Self::DuckDuckGoLite];

    /// Ce qui est écrit dans `content_citations.engine`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuckDuckGoLite => "duckduckgo_lite",
        }
    }

    /// L'inverse d'[`Self::as_str`].
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.as_str() == raw)
    }

    /// L'hôte à lire. C'est aussi le domaine que la Gate doit autoriser.
    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::DuckDuckGoLite => "lite.duckduckgo.com",
        }
    }

    /// Le domaine du jeton.
    ///
    /// `expect` parce que [`Self::host`] est une constante de ce fichier :
    /// une variante dont l'hôte ne passe pas `Domain::parse` est un bug de
    /// compilation qu'on n'a pas su exprimer, pas une erreur d'exécution.
    #[must_use]
    pub fn domain(self) -> Domain {
        Domain::parse(self.host()).expect("l'hôte d'un moteur est un domaine")
    }

    /// La page de résultats pour cette question.
    ///
    /// `Url::parse_with_params` fait l'encodage : une question porte des
    /// espaces, des accents et des points d'interrogation, et un `format!`
    /// aurait produit une URL fausse au premier « comment vérifier ? ».
    #[must_use]
    pub fn results_url(self, question: &str) -> Url {
        match self {
            Self::DuckDuckGoLite => {
                Url::parse_with_params("https://lite.duckduckgo.com/lite/", &[("q", question)])
                    .expect("une base constante et un paramètre encodé")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// La mesure
// ---------------------------------------------------------------------------

/// Ce qu'un moteur répondait à un instant donné.
///
/// Une ligne de `content_citations`, avant qu'elle soit une ligne.
#[derive(Debug, Clone, Serialize)]
pub struct Citation {
    /// [`Engine::as_str`]. Une `String` et pas un `&'static str` pour une seule
    /// raison : une mesure relue en base est aussi une `Citation` — c'est ce qui
    /// permet à [`brief`] de travailler sur une ligne déjà écrite plutôt que sur
    /// une lecture fraîche.
    pub engine: String,
    pub checked_at: DateTime<Utc>,
    /// Un de nos domaines apparaît-il dans les résultats.
    pub cited: bool,
    /// À partir de 1. `None` quand on n'y est pas — jamais 0.
    pub rank: Option<i32>,
    /// Les hôtes rendus par le moteur, dans son ordre, le nôtre compris.
    pub competitors: Vec<String>,
    /// **Les mots de la page de résultats** : titres et résumés, dans l'ordre,
    /// plafonnés. La prose d'un étranger — voir les docs du module.
    pub excerpt: String,
}

/// Assez pour les dix résultats d'une page avec leurs résumés ; assez peu pour
/// qu'une année de mesures quotidiennes sur cent questions tienne dans quelques
/// dizaines de mégaoctets.
const EXCERPT_CAP: usize = 2_000;

/// Ce qui peut empêcher une mesure.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError {
    /// Ce locataire n'a aucun domaine enregistré, donc la question « sommes-nous
    /// cités » n'a pas de sujet.
    ///
    /// Refusé plutôt que répondu `cited: false`, qui serait une mesure fausse
    /// écrite dans une table en ajout seul — et donc un point du graphe qu'on
    /// ne peut plus retirer.
    #[error("ce locataire n'a aucun domaine : rien à chercher dans les résultats")]
    NoDomainOfOurs,
    #[error(transparent)]
    Denied(#[from] Denied),
    #[error(transparent)]
    Effect(#[from] EffectError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl MeasureError {
    /// Le vocabulaire fermé qu'une route rend en `code`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoDomainOfOurs => "no_domain_of_ours",
            Self::Denied(_) => "denied",
            Self::Effect(err) => err.code(),
            Self::Store(_) => "store_unavailable",
        }
    }
}

/// **La mesure.** Poser la question au moteur, et lire ce qu'il rend.
///
/// Le jeton est émis ici, pour le principal que l'`Effects` porte — et pas reçu
/// en argument : un appelant qui apparie un jeton et un principal est un
/// appelant qui peut les apparier mal (`Effects::new` le dit en toutes
/// lettres). Le seul domaine qu'un jeton d'ici nomme est celui du moteur.
///
/// `ours` est un argument et pas une lecture faite ici, parce qu'`Effects` ne
/// prête pas sa base : la transaction appartient à l'appelant, qui l'a déjà
/// ouverte pour retrouver la question. [`our_domains`] est la lecture à lui
/// donner.
pub async fn measure(
    effects: &Effects,
    gate: &PolicyGate,
    ours: &[String],
    question: &str,
    engine: Engine,
) -> Result<Citation, MeasureError> {
    measure_page(effects, gate, ours, &engine.results_url(question), engine).await
}

/// [`measure`], l'URL déjà construite.
///
/// Séparée pour une seule raison, et elle est bonne : un faux moteur servi sur
/// le port qu'un test a obtenu du système ne peut pas être atteint par
/// [`Engine::results_url`], qui ne connaît pas de port. Le test de bout en bout
/// entre par ici, et [`Engine::results_url`] a le sien.
async fn measure_page(
    effects: &Effects,
    gate: &PolicyGate,
    ours: &[String],
    url: &Url,
    engine: Engine,
) -> Result<Citation, MeasureError> {
    if ours.is_empty() {
        return Err(MeasureError::NoDomainOfOurs);
    }

    let token = gate
        .authorize(
            effects.principal(),
            BrowserRead {
                domain: engine.domain(),
            },
        )
        .await?;
    let page = effects.read_page(token, url, WHOLE_PAGE).await?;

    // Le texte sort de son enveloppe ici et nulle part ailleurs : ce qui en
    // ressort est un `Citation` fait de nos compteurs et d'un extrait plafonné.
    Ok(read_results(
        &page.into_inner_for_rendering(),
        ours,
        engine,
        Utc::now(),
    ))
}

/// Les domaines de ce locataire — ce que « nous » veut dire dans une mesure.
///
/// C'est `content_repos.site`, **les sites où ce locataire publie**, et
/// surtout pas `tenant_domains`, qui est la rotation des domaines d'**envoi
/// d'e-mail**. La lecture d'avant était celle-là et elle rendait la boucle
/// juste et fausse à la fois : pour Orizn elle donnait `agents.getorizn.com`
/// et `agent.oriznapi.uk`, jamais `visa.orizn.app`, donc le site du client
/// pouvait sortir premier et la mesure annonçait qu'il n'était pas cité.
/// `migrations/0106` porte l'argument entier, dont celui qui tranche : un
/// domaine d'envoi non vérifié interdit à un siège de s'y asseoir, un domaine
/// de site n'a rien à vérifier, et les deux ne peuvent donc pas partager une
/// colonne `status`.
///
/// Vide quand aucun dépôt ne déclare son site : [`measure`] rend alors
/// [`MeasureError::NoDomainOfOurs`], un refus lisible plutôt qu'une mesure
/// fausse.
pub async fn our_domains(tx: &mut TenantTx<'_>) -> Result<Vec<String>, StoreError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT site FROM content_repos WHERE site IS NOT NULL")
            .fetch_all(&mut ***tx)
            .await?;
    Ok(rows.into_iter().map(|(domain,)| domain).collect())
}

/// Un résultat, tel que la page l'a rendu.
#[derive(Debug)]
struct Hit {
    host: String,
    /// Titre puis résumé, sur une ligne.
    blurb: String,
}

/// **Le scan, en Rust, de la page de résultats.**
///
/// Pur : c'est ce qui rend la mesure testable sans réseau, et c'est aussi ce qui
/// fait qu'aucun modèle n'a jamais à lire une page de résultats pour en tirer un
/// rang.
///
/// # La mise en page, et le plafond de cette lecture
///
/// `lite.duckduckgo.com` rend chaque résultat comme trois `<tr>`, que
/// l'extracteur de texte de `browser_http` sépare en trois lignes :
///
/// ```text
/// 2. Visa Requirements API — 47 362 paires, 15 langues | Orizn
/// REST API for visa requirements: 47,362 pairs, 199 passports…
/// visa.orizn.app
/// ```
///
/// Donc : une ligne qui commence par `N.` ouvre un résultat, une ligne qui est
/// un hôte seul le referme, et ce qu'il y a entre les deux est le résumé.
///
/// **Le plafond est nommé** : un résumé dont le premier caractère est le rang
/// suivant suivi d'un point ouvrirait un faux résultat. C'est pour ça que les
/// rangs doivent se suivre — `N` n'est accepté que s'il vaut le nombre de
/// résultats déjà lus plus un. Ce qui reste possible est un résumé commençant
/// exactement par le rang attendu ; on n'en a pas vu, et le jour où ça arrive
/// la mesure de cette question-là est basse d'un cran, pas fausse ailleurs.
///
/// **Un résultat dont la ligne d'hôte n'est pas reconnue garde sa place et perd
/// son nom** : le rang suivant le referme, et il entre dans `competitors` avec
/// un hôte vide. C'est volontaire, et c'est le seul sens conservateur — le
/// laisser tomber remonterait notre rang d'un cran pour une page qui, elle, est
/// bien devant nous. Le dernier résultat, lui, est abandonné : rien ne le
/// referme, donc on ne sait pas s'il existe.
fn read_results(
    text: &str,
    ours: &[String],
    engine: Engine,
    checked_at: DateTime<Utc>,
) -> Citation {
    let mut hits: Vec<Hit> = Vec::new();
    let mut open: Option<Hit> = None;

    for line in text.lines() {
        if let Some(title) = numbered(line, hits.len() + usize::from(open.is_some()) + 1) {
            if let Some(previous) = open.take() {
                hits.push(previous);
            }
            open = Some(Hit {
                host: String::new(),
                blurb: title.to_owned(),
            });
            continue;
        }
        let Some(hit) = open.as_mut() else { continue };
        if let Some(host) = display_host(line) {
            hit.host = host;
            hits.push(open.take().expect("on vient de l'emprunter"));
        } else if hit.blurb.len() < EXCERPT_CAP {
            hit.blurb.push(' ');
            hit.blurb.push_str(line);
        }
    }
    // `open` est abandonné ici : un dernier résultat sans ligne d'hôte n'est pas
    // un résultat, parce qu'on ne sait pas qui est cité — et c'est la seule
    // chose que cette fonction mesure.

    let rank = hits
        .iter()
        .position(|hit| ours.iter().any(|mine| covers(&hit.host, mine)))
        .map(|index| i32::try_from(index).unwrap_or(i32::MAX).saturating_add(1));

    let mut excerpt = String::new();
    for hit in &hits {
        if excerpt.len() >= EXCERPT_CAP {
            break;
        }
        excerpt.push_str(&hit.blurb);
        excerpt.push('\n');
    }
    truncate_on_char(&mut excerpt, EXCERPT_CAP);

    Citation {
        engine: engine.as_str().to_owned(),
        checked_at,
        cited: rank.is_some(),
        rank,
        competitors: hits.into_iter().map(|hit| hit.host).collect(),
        excerpt,
    }
}

/// `"2. Un titre"` → `Some("Un titre")`, mais seulement si `2` est le rang
/// attendu. Voir le plafond nommé dans [`read_results`].
fn numbered(line: &str, expected: usize) -> Option<&str> {
    let (number, rest) = line.split_once('.')?;
    (number.parse::<usize>().ok()? == expected).then(|| rest.trim_start())
}

/// `"visa.orizn.app/docs"` → `Some("visa.orizn.app")`, `"REST API for visas"` →
/// `None`.
///
/// La règle : aucun blanc **dans l'hôte**, au moins deux étiquettes, un TLD
/// alphabétique d'au moins deux lettres. C'est, mot pour mot, la forme que
/// `tenant_domains_domain_shape` impose en base — donc ce qui est reconnu ici
/// est ce qui peut être à nous.
///
/// **Le blanc se cherche avant la première barre, pas sur la ligne entière**, et
/// la différence a été mesurée le 2026-09-12 sur « how do I check visa
/// requirements by API » : `lite.duckduckgo.com` y affichait
/// `zylalabs.com/api-marketplace/top-search/visa requirements` — un chemin qui
/// porte l'espace de la requête. La ligne entière portait donc un blanc, l'hôte
/// n'était pas reconnu, le résultat partait sans hôte (voir [`read_results`]) et
/// **notre rang descendait d'un cran** : 4 au lieu de 3, avec une chaîne vide en
/// troisième concurrent et dans l'`outrank` du brief. Une ligne de prose, elle,
/// est toujours refusée : son premier segment porte le blanc de la phrase.
fn display_host(line: &str) -> Option<String> {
    let lowered = line.trim().split('/').next()?.to_ascii_lowercase();
    if lowered.is_empty() || lowered.chars().any(char::is_whitespace) {
        return None;
    }
    let host = lowered.strip_prefix("www.").unwrap_or(lowered.as_str());
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    if !labels.iter().all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    let tld = labels.last()?;
    (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())).then(|| host.to_owned())
}

/// Un hôte est-il à nous : lui-même, ou n'importe quoi en dessous. La règle de
/// `allowed_domains` (`crates/domain/src/policy.rs`), pour que « notre
/// domaine » veuille dire la même chose ici et dans la Gate.
fn covers(host: &str, ours: &str) -> bool {
    host == ours || host.ends_with(&format!(".{ours}"))
}

/// Tronque sur une frontière de caractère. `String::truncate` panique au milieu
/// d'un `—`, et une page de résultats en porte.
fn truncate_on_char(text: &mut String, max: usize) {
    if let Some((cut, _)) = text.char_indices().nth(max) {
        text.truncate(cut);
    }
}

// ---------------------------------------------------------------------------
// Le brief
// ---------------------------------------------------------------------------

/// Les facettes qu'un développeur vérifie avant d'écrire une ligne contre une
/// API, et les mots par lesquels une page les couvre.
///
/// **Une liste fermée, courte, et c'est le sujet du brief.** L'alternative
/// aurait été de demander à un modèle « que couvrent ces pages » — ce qui est
/// exactement ce que `Effects::discover_prospects` refuse de faire avec une
/// page d'étranger, et pour la même raison : la page choisirait les critères.
///
/// Les mots sont en anglais parce que les pages citées le sont ; le nom de la
/// facette est en français parce que c'est un employé qui le lit.
const FACETS: &[(&str, &[&str])] = &[
    (
        "prix",
        &["pricing", "price", "free tier", "gratuit", "tarif"],
    ),
    (
        "couverture",
        &["passport", "destination", "countries", "pairs", "coverage"],
    ),
    (
        "fraîcheur",
        &["updated", "daily", "real-time", "realtime", "last update"],
    ),
    ("authentification", &["api key", "token", "oauth", "auth"]),
    (
        "limites",
        &["rate limit", "quota", "requests per", "throttl"],
    ),
    ("exemple", &["curl", "example", "sdk", "sample", "snippet"]),
    ("langues", &["language", "languages", "i18n", "locale"]),
    ("fiabilité", &["sla", "uptime", "status page", "support"]),
];

/// L'angle que le brief donne, choisi par le rang et par rien d'autre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Angle {
    /// Pas cités. Le chemin le moins cher est ce que personne ne couvre.
    Uncovered,
    /// Cités, mais pas en tête. Approfondir ce que ceux du dessus survolent.
    Outrank,
    /// En tête. Tenir, et ne pas réécrire ce qui marche.
    Hold,
}

/// Ce qu'un employé doit couvrir pour répondre mieux que ce qui est cité.
///
/// **Une structure, pas un texte.** C'est l'employé qui écrit, avec son modèle,
/// et ce qu'il écrit atterrit dans `content_drafts`.
#[derive(Debug, Clone, Serialize)]
pub struct Brief {
    pub question: String,
    pub angle: Angle,
    /// Les facettes que les pages citées couvrent déjà. Les répéter ne gagne
    /// rien.
    pub covered: Vec<&'static str>,
    /// Celles qu'aucune ne couvre. C'est là qu'est la place.
    pub missing: Vec<&'static str>,
    /// Les hôtes à dépasser : ceux qui sont devant nous, ou les trois premiers
    /// quand nous ne sommes nulle part.
    pub outrank: Vec<String>,
}

/// Ce que le brief promet de nommer quand nous ne sommes pas cités.
const OUTRANK_WHEN_ABSENT: usize = 3;

/// Le brief d'une question, à la lumière d'une mesure.
///
/// Pure, et sans base : un brief se recalcule à partir d'une ligne de
/// `content_citations` déjà écrite, ce qui est la raison pour laquelle il n'a
/// pas de table (`migrations/0100` le dit).
///
/// # Ce que cette fonction voit, et ce qu'elle ne voit pas
///
/// Elle lit `excerpt` — les titres et résumés que le moteur affiche — et **pas
/// les pages citées elles-mêmes**. Un résumé de deux lignes sous-estime ce
/// qu'une page couvre, donc `missing` est optimiste : il nomme ce qui n'est pas
/// *mis en avant*, ce qui est une information différente de « absent », et
/// souvent la plus utile des deux pour écrire un titre. L'extension évidente —
/// un `read_page` par page citée — est un appel réseau par concurrent et par
/// mesure ; elle attend qu'on ait une raison de la payer.
#[must_use]
pub fn brief(question: &str, citation: &Citation) -> Brief {
    let haystack = citation.excerpt.to_lowercase();
    let (covered, missing): (Vec<_>, Vec<_>) = FACETS
        .iter()
        .partition(|(_, needles)| needles.iter().any(|needle| haystack.contains(needle)));

    let angle = match citation.rank {
        None => Angle::Uncovered,
        Some(1) => Angle::Hold,
        Some(_) => Angle::Outrank,
    };
    let ahead = match citation.rank {
        // Le rang est à partir de 1 et l'index à partir de 0 : ceux devant nous
        // sont les `rank - 1` premiers.
        Some(rank) => usize::try_from(rank).unwrap_or(0).saturating_sub(1),
        None => OUTRANK_WHEN_ABSENT,
    };

    Brief {
        question: question.to_owned(),
        angle,
        covered: covered.iter().map(|(name, _)| *name).collect(),
        missing: missing.iter().map(|(name, _)| *name).collect(),
        outrank: citation.competitors.iter().take(ahead).cloned().collect(),
    }
}

// ---------------------------------------------------------------------------
// Où la question vit déjà
// ---------------------------------------------------------------------------

/// Ce qu'une dernière mesure dit d'une question, réduit à ce que [`places`] lit.
///
/// Pas un [`Citation`] : ni l'extrait, ni le moteur, ni l'heure ne servent ici,
/// et les tirer pour cent questions serait deux cents kilo-octets d'extraits
/// relus pour compter des hôtes.
#[derive(Debug, Clone)]
pub struct Seen {
    pub question: String,
    /// Étions-nous dans ces résultats-là.
    pub cited: bool,
    /// Les hôtes rendus par le moteur, dans son ordre.
    pub competitors: Vec<String>,
}

/// Un hôte qui revient dans les résultats de nos questions.
///
/// **Ce n'est pas une cible de lien, et le mot est choisi.** Un `Place` dit
/// *où la question vit déjà* : un forum, un comparatif, un annuaire, ou un
/// concurrent. Ce qu'on en fait est une décision humaine, et `docs/CONTENU.md`
/// § 9 dit lesquelles de ces décisions sont honnêtes.
#[derive(Debug, Clone, Serialize)]
pub struct Place {
    pub host: String,
    /// Sur combien de nos questions cet hôte sort dans les résultats.
    pub questions: usize,
    /// Le meilleur rang qu'il y tienne, toutes questions confondues. À partir
    /// de 1, comme [`Citation::rank`].
    pub best_rank: i32,
    /// Celles de ces questions où **nous ne sommes nulle part**. C'est la seule
    /// liste actionnable de la structure : un hôte qui répond à cinq de nos
    /// questions sans nous est un endroit où la réponse existe et où la nôtre
    /// n'existe pas. Vide quand on est déjà cité partout où il l'est.
    pub without_us: Vec<String>,
}

/// Ce qu'une lecture rend au plus. Une page de résultats porte une dizaine
/// d'hôtes ; cent questions en portent donc jusqu'à mille, dont la queue est
/// faite d'hôtes vus une fois. Le tri met les récurrents devant, et la coupe
/// garde la réponse lisible par un humain — qui est le seul à pouvoir en faire
/// quelque chose.
const PLACES_CAP: usize = 50;

/// **Où la question vit déjà**, à partir des mesures qu'on a déjà.
///
/// Pure, sans réseau et sans source nouvelle : tout ce qu'elle lit a été écrit
/// par [`read_results`] à partir de la seule page de résultats que ce dépôt a le
/// droit de lire. Un hôte de plus dans cette liste ne coûte donc rien qu'une
/// mesure n'ait déjà payé.
///
/// # Ce qu'elle dit, et surtout ce qu'elle ne dit pas
///
/// Elle dit *qui sort quand on pose nos questions*. Elle ne dit **pas** qui
/// nous cite, ni qui cite un concurrent : un lien entrant ne se lit pas dans
/// une page de résultats, et rien de gratuit ne le rend. `docs/CONTENU.md` § 9
/// nomme les fournisseurs qui le vendent et dit pourquoi aucun n'est appelé.
///
/// Nos propres sites sont retirés — par [`covers`], la règle de la Gate, pour
/// que « à nous » veuille dire la même chose ici qu'à la mesure. Un hôte vide
/// (un résultat dont la ligne d'hôte n'a pas été reconnue, voir
/// [`read_results`]) est sauté : il tient une place dans un rang, il n'est pas
/// un endroit.
#[must_use]
pub fn places(seen: &[Seen], ours: &[String]) -> Vec<Place> {
    let mut by_host: BTreeMap<String, Place> = BTreeMap::new();

    for row in seen {
        // Un même hôte peut sortir deux fois sur une question ; il ne la compte
        // qu'une, au meilleur de ses deux rangs.
        let mut counted: BTreeSet<&str> = BTreeSet::new();
        for (index, host) in row.competitors.iter().enumerate() {
            if host.is_empty() || ours.iter().any(|mine| covers(host, mine)) {
                continue;
            }
            let rank = i32::try_from(index).unwrap_or(i32::MAX).saturating_add(1);
            let place = by_host.entry(host.clone()).or_insert_with(|| Place {
                host: host.clone(),
                questions: 0,
                best_rank: rank,
                without_us: Vec::new(),
            });
            place.best_rank = place.best_rank.min(rank);
            if counted.insert(host.as_str()) {
                place.questions += 1;
                if !row.cited {
                    place.without_us.push(row.question.clone());
                }
            }
        }
    }

    let mut places: Vec<Place> = by_host.into_values().collect();
    // Le plus utile d'abord : là où on manque le plus souvent, puis là où
    // l'hôte revient le plus, puis là où il est le mieux placé. Le nom tranche
    // les égalités, pour que deux lectures des mêmes mesures rendent deux fois
    // la même liste.
    places.sort_by(|a, b| {
        b.without_us
            .len()
            .cmp(&a.without_us.len())
            .then(b.questions.cmp(&a.questions))
            .then(a.best_rank.cmp(&b.best_rank))
            .then(a.host.cmp(&b.host))
    });
    places.truncate(PLACES_CAP);
    places
}

// ---------------------------------------------------------------------------
// Les questions
// ---------------------------------------------------------------------------

/// Les questions qu'on veut gagner.
pub mod questions {
    use super::{DateTime, Serialize, Source, StoreError, TenantTx, Utc, Uuid};

    /// Une ligne de `content_questions`.
    #[derive(Debug, Clone, Serialize, sqlx::FromRow)]
    pub struct Question {
        pub id: Uuid,
        pub question: String,
        pub locale: String,
        pub source: String,
        pub weight: i32,
        pub created_at: DateTime<Utc>,
    }

    /// Ajouter une question. Idempotent sur `(question, locale)` : rejouer
    /// l'ajout rend la ligne existante plutôt que d'en faire une deuxième, pour
    /// que la série de mesures reste accrochée à une seule.
    ///
    /// **`DO NOTHING` et pas `DO UPDATE`, et ce n'est pas un détail de SQL.**
    /// Un `ON CONFLICT DO UPDATE` réclame le droit d'`UPDATE` sur la table, que
    /// `0100` ne donne pas — délibérément : une question ne se modifie pas sous
    /// la série qui pend dessous. Le coût est réel et nommé : rejouer l'ajout
    /// avec un autre `weight` ou une autre `source` **ne les change pas**.
    /// Personne n'en a eu besoin ; le jour où ça arrive, c'est une route de
    /// repondération et un grant d'`UPDATE` sur ces deux colonnes, pas un
    /// upsert qui ouvre la table entière.
    pub async fn add(
        tx: &mut TenantTx<'_>,
        question: &str,
        locale: &str,
        source: Source,
        weight: i32,
    ) -> Result<Question, StoreError> {
        let tenant = tx.tenant_id();
        let inserted: Option<Question> = sqlx::query_as(
            "INSERT INTO content_questions \
                 (id, tenant_id, question, locale, source, weight, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (tenant_id, question, locale) DO NOTHING \
             RETURNING id, question, locale, source, weight, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(question)
        .bind(locale)
        .bind(source.as_str())
        .bind(weight)
        .bind(Utc::now())
        .fetch_optional(&mut ***tx)
        .await?;
        if let Some(row) = inserted {
            return Ok(row);
        }
        // Le conflit : la ligne existe déjà, et c'est elle la réponse. Le
        // `WHERE` n'a pas besoin du locataire — la policy RLS le pose.
        let row = sqlx::query_as(
            "SELECT id, question, locale, source, weight, created_at \
               FROM content_questions WHERE question = $1 AND locale = $2",
        )
        .bind(question)
        .bind(locale)
        .fetch_one(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// Les questions de ce locataire, les plus lourdes d'abord.
    pub async fn list(tx: &mut TenantTx<'_>) -> Result<Vec<Question>, StoreError> {
        let rows = sqlx::query_as(
            "SELECT id, question, locale, source, weight, created_at \
               FROM content_questions \
              ORDER BY weight DESC, created_at ASC",
        )
        .fetch_all(&mut ***tx)
        .await?;
        Ok(rows)
    }

    /// Retirer une question, et avec elle ses mesures et ses brouillons — la
    /// cascade est dans `0100`. `false` quand ce locataire n'en a pas.
    pub async fn remove(tx: &mut TenantTx<'_>, id: Uuid) -> Result<bool, StoreError> {
        let gone: Option<(Uuid,)> =
            sqlx::query_as("DELETE FROM content_questions WHERE id = $1 RETURNING id")
                .bind(id)
                .fetch_optional(&mut ***tx)
                .await?;
        Ok(gone.is_some())
    }
}

// ---------------------------------------------------------------------------
// Les mesures, une fois écrites
// ---------------------------------------------------------------------------

/// La série dans le temps. En ajout seul, comme la table.
pub mod citations {
    use super::{Citation, DateTime, Seen, Serialize, StoreError, TenantTx, Utc, Uuid};

    /// Une ligne de `content_citations`, telle qu'on la relit.
    #[derive(Debug, Clone, Serialize, sqlx::FromRow)]
    pub struct Measured {
        pub id: Uuid,
        pub question_id: Uuid,
        pub checked_at: DateTime<Utc>,
        pub engine: String,
        pub cited: bool,
        pub rank: Option<i32>,
        pub competitors: serde_json::Value,
        pub excerpt: String,
    }

    /// Une mesure relue est une mesure, et [`super::brief`] ne fait pas la
    /// différence : c'est ce qui rend un brief recalculable des mois après la
    /// lecture, et c'est pourquoi le brief n'a pas de table.
    ///
    /// `competitors` est du `jsonb` qu'on a écrit nous-mêmes comme un tableau de
    /// chaînes ; une ligne dont ce ne serait pas le cas rend une liste vide
    /// plutôt que de faire tomber la lecture — le rang, lui, est une colonne à
    /// part et reste juste.
    impl From<Measured> for Citation {
        fn from(row: Measured) -> Self {
            Self {
                engine: row.engine,
                checked_at: row.checked_at,
                cited: row.cited,
                rank: row.rank,
                competitors: serde_json::from_value(row.competitors).unwrap_or_default(),
                excerpt: row.excerpt,
            }
        }
    }

    /// Classer une mesure. Il n'y a pas de verbe pour la reprendre : `0100` ne
    /// donne à `app_role` ni `update` ni `delete` sur cette table.
    pub async fn record(
        tx: &mut TenantTx<'_>,
        question_id: Uuid,
        citation: &Citation,
    ) -> Result<Uuid, StoreError> {
        let tenant = tx.tenant_id();
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO content_citations \
                 (id, tenant_id, question_id, checked_at, engine, cited, rank, competitors, excerpt) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(question_id)
        .bind(citation.checked_at)
        .bind(&citation.engine)
        .bind(citation.cited)
        .bind(citation.rank)
        .bind(serde_json::json!(citation.competitors))
        .bind(&citation.excerpt)
        .execute(&mut ***tx)
        .await?;
        Ok(id)
    }

    /// La série d'une question sur une fenêtre, du plus récent au plus ancien.
    pub async fn list(
        tx: &mut TenantTx<'_>,
        question_id: Uuid,
        days: i64,
    ) -> Result<Vec<Measured>, StoreError> {
        let since = Utc::now() - chrono::Duration::days(days);
        let rows = sqlx::query_as(
            "SELECT id, question_id, checked_at, engine, cited, rank, competitors, excerpt \
               FROM content_citations \
              WHERE question_id = $1 AND checked_at >= $2 \
              ORDER BY checked_at DESC",
        )
        .bind(question_id)
        .bind(since)
        .fetch_all(&mut ***tx)
        .await?;
        Ok(rows)
    }

    /// La dernière mesure d'une question, tous moteurs confondus. Ce que
    /// `content_briefs_get` lit pour bâtir un brief.
    pub async fn latest(
        tx: &mut TenantTx<'_>,
        question_id: Uuid,
    ) -> Result<Option<Measured>, StoreError> {
        let row = sqlx::query_as(
            "SELECT id, question_id, checked_at, engine, cited, rank, competitors, excerpt \
               FROM content_citations \
              WHERE question_id = $1 \
              ORDER BY checked_at DESC LIMIT 1",
        )
        .bind(question_id)
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// **La dernière mesure de chaque question**, réduite à ce que
    /// [`super::places`] lit.
    ///
    /// Un `DISTINCT ON` et pas une boucle de [`latest`] : la question posée est
    /// « qu'est-ce qui revient d'une question à l'autre », donc un aller-retour
    /// par question serait N requêtes pour une réponse qui n'existe qu'en les
    /// réunissant. Les colonnes lourdes — `excerpt` surtout — ne sont pas
    /// tirées ; le brief les lit, pas les endroits.
    ///
    /// Une question jamais mesurée n'a pas de ligne et n'apparaît pas. C'est le
    /// même sens que `content_briefs_get` : sans mesure, il n'y a rien à dire.
    pub async fn last_seen(tx: &mut TenantTx<'_>) -> Result<Vec<Seen>, StoreError> {
        let rows: Vec<(String, bool, serde_json::Value)> = sqlx::query_as(
            "SELECT DISTINCT ON (c.question_id) q.question, c.cited, c.competitors \
               FROM content_citations c \
               JOIN content_questions q ON q.id = c.question_id \
              ORDER BY c.question_id, c.checked_at DESC",
        )
        .fetch_all(&mut ***tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(question, cited, competitors)| Seen {
                question,
                cited,
                // Même règle qu'au-dessus : un `jsonb` qui ne serait pas le
                // tableau qu'on a écrit rend une liste vide, pas une panne.
                competitors: serde_json::from_value(competitors).unwrap_or_default(),
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Les brouillons
// ---------------------------------------------------------------------------

/// Ce qu'on écrit pour répondre.
pub mod drafts {
    use super::{DateTime, Serialize, StoreError, TenantTx, Utc, Uuid};

    /// Une ligne de `content_drafts`.
    #[derive(Debug, Clone, Serialize, sqlx::FromRow)]
    pub struct Draft {
        pub id: Uuid,
        pub question_id: Uuid,
        pub title: String,
        pub body: String,
        pub state: String,
        pub url: Option<String>,
        /// Où une personne **relit** : la pull request ouverte par
        /// [`super::propose`]. Nulle tant que personne n'a proposé, et jamais
        /// confondue avec `url` — l'une est l'adresse d'une relecture, l'autre
        /// celle d'un article en ligne. `migrations/0102` argumente.
        pub review_url: Option<String>,
        pub created_at: DateTime<Utc>,
        pub published_at: Option<DateTime<Utc>>,
    }

    /// Les colonnes qu'une révision réécrit. `url` présent veut dire publié —
    /// c'est le seul chemin vers `state = 'published'`, parce que `0100` refuse
    /// un publié sans adresse ni date.
    #[derive(Debug, Clone)]
    pub struct Revision<'a> {
        pub title: &'a str,
        pub body: &'a str,
        /// L'adresse **constatée**. Rien dans ce dépôt ne publie ; c'est la
        /// personne qui a publié qui l'écrit. `docs/CONTENU.md` § « ce qui
        /// manque ».
        pub url: Option<&'a str>,
    }

    /// Ouvrir un brouillon sur une question.
    pub async fn create(
        tx: &mut TenantTx<'_>,
        question_id: Uuid,
        title: &str,
        body: &str,
    ) -> Result<Draft, StoreError> {
        let tenant = tx.tenant_id();
        let row = sqlx::query_as(
            "INSERT INTO content_drafts \
                 (id, tenant_id, question_id, title, body, state, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'draft', $6) \
             RETURNING id, question_id, title, body, state, url, review_url, created_at, published_at",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(question_id)
        .bind(title)
        .bind(body)
        .bind(Utc::now())
        .fetch_one(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// Tous les brouillons de ce locataire, du plus récent au plus ancien.
    pub async fn list(tx: &mut TenantTx<'_>) -> Result<Vec<Draft>, StoreError> {
        let rows = sqlx::query_as(
            "SELECT id, question_id, title, body, state, url, review_url, created_at, published_at \
               FROM content_drafts ORDER BY created_at DESC",
        )
        .fetch_all(&mut ***tx)
        .await?;
        Ok(rows)
    }

    /// Réécrire un brouillon, et éventuellement constater qu'il est publié.
    ///
    /// `published_at` est posé la première fois qu'une adresse arrive et ne
    /// bouge plus : la date de publication d'un article est celle de sa
    /// publication, pas celle de sa dernière correction de typo.
    ///
    /// **Sans adresse, l'état retombe sur ce que la ligne porte déjà**, et pas
    /// sur `draft` : un brouillon dont la pull request est ouverte reste
    /// `proposed` quand on corrige son texte. Le CHECK de `0102` l'exigerait de
    /// toute façon — `proposed` sans `review_url` n'existe pas — mais l'écrire
    /// comme un `CASE` sur la colonne plutôt que comme un argument de plus est
    /// ce qui empêche un appelant de rétrograder une proposition par omission.
    /// Ce que ça ne fait pas, et qui est assumé : la pull request ouverte ne
    /// porte pas la correction, puisque rien ne la repousse. C'est
    /// [`super::propose`] qu'il faut rappeler, et il refuse tant que la
    /// première n'est pas retombée.
    pub async fn update(
        tx: &mut TenantTx<'_>,
        id: Uuid,
        revision: &Revision<'_>,
    ) -> Result<Option<Draft>, StoreError> {
        let row = sqlx::query_as(
            "UPDATE content_drafts \
                SET title = $2, \
                    body = $3, \
                    url = $4, \
                    state = CASE \
                        WHEN $4::text IS NOT NULL THEN 'published' \
                        WHEN review_url IS NOT NULL THEN 'proposed' \
                        ELSE 'draft' END, \
                    published_at = CASE \
                        WHEN $4::text IS NULL THEN NULL \
                        ELSE coalesce(published_at, $5) END \
              WHERE id = $1 \
             RETURNING id, question_id, title, body, state, url, review_url, created_at, published_at",
        )
        .bind(id)
        .bind(revision.title)
        .bind(revision.body)
        .bind(revision.url)
        .bind(Utc::now())
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// **Constater qu'une pull request est ouverte pour ce brouillon.**
    ///
    /// Écrit après que [`super::propose`] a poussé le fichier et ouvert la
    /// demande — donc après trois appels sortis de la machine, et jamais avant.
    /// Une base injoignable ici laisse une pull request ouverte que la table
    /// ignore : c'est le sens conservateur, la pull request est visible chez le
    /// client et un deuxième appel la rouvrirait plutôt que d'écraser un état
    /// qu'on n'a pas su écrire.
    ///
    /// `WHERE state = 'draft'` : seul un brouillon se propose. `None` quand la
    /// ligne n'existe pas **ou** qu'elle n'est plus un brouillon, et c'est
    /// l'appelant qui a déjà lu son état qui sait lequel des deux — voir
    /// [`super::ProposeError::NotADraft`].
    pub async fn propose(
        tx: &mut TenantTx<'_>,
        id: Uuid,
        review_url: &str,
    ) -> Result<Option<Draft>, StoreError> {
        let row = sqlx::query_as(
            "UPDATE content_drafts \
                SET state = 'proposed', review_url = $2 \
              WHERE id = $1 AND state = 'draft' \
             RETURNING id, question_id, title, body, state, url, review_url, created_at, published_at",
        )
        .bind(id)
        .bind(review_url)
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Le dépôt d'un siège
// ---------------------------------------------------------------------------

/// Où le site d'un client est servi, et par quel branchement on y écrit.
///
/// Une ligne de `content_repos`. `migrations/0102` dit pourquoi c'est une table
/// à elle et pas une douzième ligne d'`employee_resources` : la totalité que
/// `agentos_store::employee::load` exige de cette table-là ferait de chaque
/// siège qui en porterait une un employé **corrompu**, et un dépôt n'est de
/// toute façon pas une étape de provisionnement — personne ne l'achète et
/// `release` n'aurait rien à rendre.
pub mod repos {
    use super::{DateTime, Serialize, Slug, StoreError, TenantTx, Utc, Uuid};

    /// Le dépôt d'un siège, tel qu'il est rangé.
    #[derive(Debug, Clone, Serialize, sqlx::FromRow)]
    pub struct Repo {
        pub employee_id: Uuid,
        /// Le handle du branchement MCP — celui qu'un `Action::McpCall` nomme.
        /// La clé étrangère de `0102` garantit qu'il est branché.
        pub server: String,
        /// `propriétaire/nom`.
        pub repo: String,
        /// La branche **qui sert le site** : la cible de la pull request, pas
        /// celle qui porte l'article.
        pub branch: String,
        /// Le dossier que le générateur lit.
        pub folder: String,
        /// **L'hôte public où les articles de ce dépôt ressortent**, p. ex.
        /// `visa.orizn.app`. C'est ce que « nous » veut dire dans une mesure de
        /// citation — voir [`super::our_domains`] et `migrations/0106`.
        /// `None` : ce dépôt pousse toujours ses articles, il ne participe
        /// simplement pas à la réponse d'`our_domains`.
        pub site: Option<String>,
        pub created_at: DateTime<Utc>,
    }

    impl Repo {
        /// `propriétaire`, `nom`. `None` si la ligne ne porte pas la forme que
        /// `content_repos_repo_shape` impose — inatteignable tant que le CHECK
        /// est là, et pas un `expect` pour autant : c'est une donnée de base,
        /// pas une constante de ce fichier.
        #[must_use]
        pub fn owner_and_name(&self) -> Option<(&str, &str)> {
            let (owner, name) = self.repo.split_once('/')?;
            (!owner.is_empty() && !name.is_empty() && !name.contains('/')).then_some((owner, name))
        }

        /// Le handle, en [`Slug`]. `None` pour une ligne qu'`agentos_app::mcp`
        /// ne saurait pas router non plus — il ignore les branchements dont le
        /// handle ne se lit pas.
        #[must_use]
        pub fn handle(&self) -> Option<Slug> {
            Slug::parse(&self.server).ok()
        }
    }

    /// Les dépôts de ce locataire, un par siège qui en a un.
    pub async fn list(tx: &mut TenantTx<'_>) -> Result<Vec<Repo>, StoreError> {
        let rows = sqlx::query_as(
            "SELECT employee_id, server, repo, branch, folder, site, created_at \
               FROM content_repos ORDER BY created_at ASC",
        )
        .fetch_all(&mut ***tx)
        .await?;
        Ok(rows)
    }

    /// Le dépôt d'un siège. `None` : ce siège ne publie nulle part.
    pub async fn of(tx: &mut TenantTx<'_>, employee_id: Uuid) -> Result<Option<Repo>, StoreError> {
        let row = sqlx::query_as(
            "SELECT employee_id, server, repo, branch, folder, site, created_at \
               FROM content_repos WHERE employee_id = $1",
        )
        .bind(employee_id)
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// Attacher un dépôt à un siège, ou remplacer le sien.
    ///
    /// `None` quand rien n'est branché sous ce handle chez ce locataire. La clé
    /// étrangère de `0102` le refuserait aussi — mais elle le refuserait en
    /// `StoreError`, c'est-à-dire en 500 pour un appelant qui a simplement mal
    /// recopié un nom. Une lecture d'abord, et la faute revient à qui peut la
    /// corriger.
    ///
    /// [`StoreError::NotFound`] quand le siège n'est pas celui de ce locataire,
    /// **et cette lecture-là n'est pas une commodité**. La clé étrangère vers
    /// `employees` est vérifiée par Postgres hors de la RLS, donc elle accepte
    /// l'identifiant d'un siège d'en face ; la policy de cette table, elle, ne
    /// regarde que `tenant_id`, que la ligne écrite porte correctement. Sans
    /// cette lecture, un locataire qui a branché un serveur peut écrire une
    /// ligne sur le siège d'un autre — il n'en tirerait rien (la Gate refuse un
    /// employé que sa transaction ne voit pas, `UnknownEmployee`), mais la
    /// ligne occuperait la clé primaire et le vrai propriétaire du siège ne
    /// pourrait plus poser la sienne. C'est la forme d'`employee_resources` et
    /// de toutes les tables pendues à un siège ; ici la lecture coûte une ligne
    /// et referme la question.
    pub async fn set(
        tx: &mut TenantTx<'_>,
        employee_id: Uuid,
        server: &str,
        repo: &str,
        branch: &str,
        folder: &str,
        site: Option<&str>,
    ) -> Result<Option<Repo>, StoreError> {
        // Les deux lectures sont bornées au locataire par la RLS de leur table.
        let seat: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM employees WHERE id = $1")
            .bind(employee_id)
            .fetch_optional(&mut ***tx)
            .await?;
        if seat.is_none() {
            return Err(StoreError::NotFound);
        }
        let bound: Option<(String,)> =
            sqlx::query_as("SELECT server FROM mcp_servers WHERE server = $1")
                .bind(server)
                .fetch_optional(&mut ***tx)
                .await?;
        if bound.is_none() {
            return Ok(None);
        }

        let tenant = tx.tenant_id();
        let row = sqlx::query_as(
            "INSERT INTO content_repos \
                 (employee_id, tenant_id, server, repo, branch, folder, site, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (employee_id) DO UPDATE \
                SET server = excluded.server, repo = excluded.repo, \
                    branch = excluded.branch, folder = excluded.folder, \
                    site = excluded.site \
             RETURNING employee_id, server, repo, branch, folder, site, created_at",
        )
        .bind(employee_id)
        .bind(tenant.as_uuid())
        .bind(server)
        .bind(repo)
        .bind(branch)
        .bind(folder)
        .bind(site)
        .bind(Utc::now())
        .fetch_one(&mut ***tx)
        .await?;
        Ok(Some(row))
    }
}

// ---------------------------------------------------------------------------
// La proposition : un fichier poussé, et une pull request
// ---------------------------------------------------------------------------

/// Les quatre outils de GitHub qu'une proposition prononce, **dans cet
/// ordre**, en orthographe [`Slug`].
///
/// `agentos_app::mcp` replie les `_` d'un nom de la table d'un serveur en `-`
/// (`handle`), donc `create_pull_request` chez GitHub est `create-pull-request`
/// ici. **Cette liste est la surface entière** : `propose` ne prononce rien
/// d'autre, aucune valeur de requête ne l'agrandit, et chacun des quatre passe
/// par la Policy Gate séparément.
///
/// # L'ordre est le mécanisme, pas une habitude
///
/// [`GET_FILE_CONTENTS`] vient **avant** [`CREATE_BRANCH`], et c'est ce qui
/// fait qu'une tentative ratée ne laisse rien chez le client. Republier un
/// article corrigé — même titre, donc même [`file_stem`], donc même chemin —
/// échouait sur `create-or-update-file`, qui veut le `sha` de la version
/// remplacée ; lire ce `sha` en quatrième appel aurait réparé l'échec et gardé
/// la branche orpheline que le deuxième avait déjà créée. Lu en premier, il
/// n'y a rien à nettoyer : ce qui peut manquer manque avant qu'une branche
/// existe.
///
/// # Ce qui n'a pas été vérifié, et ne pouvait pas l'être
///
/// Les quatre noms et la forme de leurs arguments sont ceux que le serveur MCP
/// distant de GitHub publie. **Aucun appel n'a été fait contre le vrai
/// serveur** : il demande un compte GitHub et un passage OAuth, c'est-à-dire
/// exactement ce que ce chantier n'avait pas le droit d'ouvrir. Ce que les
/// tests prouvent est ce que *nous* envoyons, dans quel ordre, et ce que nous
/// faisons de la réponse ; ce qu'ils ne prouvent pas est que GitHub épelle ces
/// quatre outils comme ici. Le jour du premier vrai branchement, un nom faux
/// sort en `unknown_tool` au premier appel, avant qu'un octet soit écrit.
const GET_FILE_CONTENTS: &str = "get-file-contents";
/// Voir [`GET_FILE_CONTENTS`].
const CREATE_BRANCH: &str = "create-branch";
/// Voir [`GET_FILE_CONTENTS`].
const CREATE_OR_UPDATE_FILE: &str = "create-or-update-file";
/// Voir [`GET_FILE_CONTENTS`].
const CREATE_PULL_REQUEST: &str = "create-pull-request";

/// Ce qu'une proposition a produit chez le client.
#[derive(Debug, Clone, Serialize)]
pub struct Proposal {
    /// La branche créée pour cet article, une par brouillon.
    pub branch: String,
    /// Le chemin du fichier écrit, dans le dossier du dépôt.
    pub path: String,
    /// **L'adresse où un humain relit.** Rebâtie à partir de nos propres
    /// chaînes ; voir [`review_url`].
    pub review_url: String,
}

/// Ce qui peut empêcher une proposition.
#[derive(Debug, thiserror::Error)]
pub enum ProposeError {
    /// Ce siège n'a pas de dépôt. Le premier geste est `content_repos_set`.
    #[error("ce siège n'a pas de dépôt : il n'y a nulle part où pousser")]
    NoRepo,
    /// Le brouillon a déjà été proposé, ou il est publié. Porte l'état lu.
    #[error("ce brouillon est {0}, et seul un brouillon se propose")]
    NotADraft(String),
    /// La ligne de `content_repos` ne se lit pas : un `repo` qui n'est pas
    /// `propriétaire/nom`, ou un handle qui n'est pas un [`Slug`]. Les CHECK de
    /// `0102` le rendent inatteignable ; il est nommé plutôt que dépiauté par
    /// un `expect` sur une donnée de base.
    #[error("la ligne de dépôt de ce siège ne se lit pas")]
    MalformedRepo,
    /// GitHub a répondu, et sa réponse dit qu'elle a échoué (`isError`). Porte
    /// l'outil, jamais le message du serveur — c'est la prose d'un étranger.
    #[error("GitHub a refusé {0}")]
    Refused(&'static str),
    /// La pull request est peut-être ouverte, et sa réponse ne porte pas une
    /// adresse qui soit **dans ce dépôt**. Rien n'est écrit en base : aller
    /// voir la branche nommée dans le journal d'audit.
    #[error("la réponse ne porte aucune adresse de pull request dans ce dépôt")]
    NoReviewUrl,
    #[error(transparent)]
    Denied(#[from] Denied),
    #[error(transparent)]
    Effect(#[from] EffectError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl ProposeError {
    /// Le vocabulaire fermé qu'une route rend en `code`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoRepo => "no_repo",
            Self::NotADraft(_) => "not_a_draft",
            Self::MalformedRepo => "repo_malformed",
            Self::Refused(_) => "github_refused",
            Self::NoReviewUrl => "no_review_url",
            Self::Denied(_) => "denied",
            Self::Effect(err) => err.code(),
            Self::Store(_) => "store_unavailable",
        }
    }
}

/// **La proposition.** L'article devient un fichier Markdown sur une branche à
/// lui, et une pull request demande à une personne de le lire.
///
/// # Ce que ça n'est pas
///
/// Ce n'est **pas** une publication, et `content_drafts.state` le dit : la
/// ligne passe à `proposed`, pas à `published`. `url` reste nulle jusqu'à ce
/// qu'une personne constate l'article à une adresse — `migrations/0102`
/// argumente les trois façons de s'en passer et pourquoi aucune ne tient.
///
/// Ce n'est pas non plus un circuit d'approbation de plus. `docs/CONTENU.md`
/// § 5 : *« la revue de code du client est déjà le garde-fou, et une pull
/// request est un brouillon qu'un humain approuve sans que nous ayons à
/// inventer un circuit d'approbation »*. Rien ici ne fusionne, et rien ici ne
/// sait fusionner : les trois outils prononcés n'écrivent que sur une branche
/// que personne d'autre ne lit.
///
/// # Quatre appels, quatre verdicts
///
/// Le jeton est émis ici, pour le principal que l'`Effects` porte, comme
/// [`measure`] — et **quatre fois**, une par outil. Ce n'est pas une économie
/// ratée : un siège à qui la politique donne `create-branch` sans
/// `create-pull-request` doit pouvoir échouer entre les deux, et le journal
/// d'audit doit porter une ligne par chose faite chez le client. Un seul
/// verdict pour quatre gestes serait une décision prise sur un geste qu'elle
/// ne nomme pas.
///
/// # Ce qui reste ouvert quand ça casse au milieu
///
/// **Tout ce qui peut manquer manque avant que rien soit créé.** Les deux
/// refus ordinaires — une politique qui ne nomme pas un outil, un `sha`
/// absent parce que l'article est déjà là — tombent sur le premier appel, qui
/// est une lecture : le dépôt du client est exactement comme avant. C'est ce
/// que l'ordre achète, et c'est la moitié de la réparation de la republication
/// (`docs/CONTENU.md` § 7).
///
/// Reste le cas rare : le réseau meurt entre le deuxième et le quatrième
/// appel. Une branche — et peut-être un fichier — est chez le client, et rien
/// en base. C'est assumé et c'est le sens conservateur : une branche orpheline
/// se supprime d'un clic, là où un `proposed` écrit sans pull request serait
/// un état que personne ne peut plus relire. La branche porte l'identifiant du
/// brouillon, donc on sait toujours de quoi elle est le reste — et rappeler
/// `propose` sur ce brouillon-là sort en `Refused(CREATE_BRANCH)` tant que la
/// branche n'est pas supprimée, parce que GitHub refuse une référence qui
/// existe et que distinguer ce refus-là d'un autre demanderait de lire sa
/// prose. Deux lignes dans le journal d'audit, et un clic.
///
/// ponytail: pas de nettoyage compensatoire. Supprimer la branche demanderait
/// un cinquième outil — donc une ligne de plus dans la politique de chaque
/// siège et dans le plafond de la plateforme, c'est-à-dire un
/// `policy install` chez chaque client — pour rattraper un échec qui ne se
/// produit plus par la voie qu'on sait nommer. Le jour où un journal montre
/// des branches orphelines, c'est `delete-branch` et un cinquième verdict.
///
/// # Republier un article corrigé
///
/// Un fichier qui existe **déjà** à ce chemin — un article fusionné dont un
/// second brouillon reprend le titre — est remplacé, et c'est le premier appel
/// qui le rend possible : [`GET_FILE_CONTENTS`] sur la branche qui sert le
/// site rend le `sha` de la version en place, que `create-or-update-file`
/// exige pour écraser. Pas de fichier là : pas de `sha`, et c'est une
/// création.
///
/// Ce n'est pas un écrasement silencieux, et il faut le dire parce que c'est
/// ce que la version d'avant redoutait : ce qui est écrasé l'est **sur une
/// branche à l'article**, que personne d'autre ne lit, et la pull request
/// montre le diff avec l'ancienne version à la personne qui relit. Un
/// remplacement qui traverse une revue de code n'est pas silencieux.
///
/// ponytail: la Gate statue quatre fois, et `get-file-contents` est une
/// **lecture** — donc `Risk::Read` chez qui le déclare, contrairement aux
/// trois autres. Ça reste un outil de plus à nommer dans la politique d'un
/// siège et dans `docs/orizn-ceiling.json` ; il n'y avait pas de façon de
/// lire ce `sha` sans le demander à GitHub.
pub async fn propose(
    effects: &Effects,
    gate: &PolicyGate,
    repo: &repos::Repo,
    draft: &drafts::Draft,
    now: DateTime<Utc>,
) -> Result<Proposal, ProposeError> {
    if draft.state != "draft" {
        return Err(ProposeError::NotADraft(draft.state.clone()));
    }
    let (owner, name) = repo.owner_and_name().ok_or(ProposeError::MalformedRepo)?;
    let server = repo.handle().ok_or(ProposeError::MalformedRepo)?;

    let branch = article_branch(draft.id);
    let path = format!("{}/{}.md", repo.folder, file_stem(&draft.title, draft.id));

    // **Avant de créer quoi que ce soit.** La branche qui sert le site est la
    // seule où un article fusionné peut être ; la branche de l'article, elle,
    // n'existe pas encore, et c'est exactement le point.
    //
    // `isError` n'est pas une panne ici : GitHub répond 404 pour un fichier
    // absent, ce qui est le cas ordinaire — un premier article. Un refus de
    // lecture pour une autre raison (droits) se lit pareil, et ressort deux
    // appels plus loin en `Refused(CREATE_OR_UPDATE_FILE)` : conservateur, et
    // rien n'a été écrit entre-temps.
    let existing = read_file(
        effects,
        gate,
        &server,
        &json!({
            "owner": owner,
            "repo": name,
            "path": path,
            "ref": repo.branch,
        }),
    )
    .await?;

    call(
        effects,
        gate,
        &server,
        CREATE_BRANCH,
        &json!({
            "owner": owner,
            "repo": name,
            "branch": branch,
            "from_branch": repo.branch,
        }),
    )
    .await?;

    let mut writing = json!({
        "owner": owner,
        "repo": name,
        "branch": branch,
        "path": path,
        "message": format!("Article : {}", draft.title),
        "content": article(&draft.title, &draft.body, now),
    });
    if let Some(sha) = existing {
        // Le seul octet de l'étranger qui survit à tout ce module, et il est
        // contraint à quarante chiffres hexadécimaux — voir `blob_sha`.
        writing["sha"] = Value::String(sha);
    }
    call(effects, gate, &server, CREATE_OR_UPDATE_FILE, &writing).await?;

    let opened = call(
        effects,
        gate,
        &server,
        CREATE_PULL_REQUEST,
        &json!({
            "owner": owner,
            "repo": name,
            "head": branch,
            "base": repo.branch,
            "title": draft.title,
            "body": PULL_REQUEST_BODY,
        }),
    )
    .await?;

    let review_url = review_url(&opened, &repo.repo).ok_or(ProposeError::NoReviewUrl)?;
    Ok(Proposal {
        branch,
        path,
        review_url,
    })
}

/// Ce que la pull request dit d'elle-même, à la personne qui l'ouvre.
///
/// Une constante, et pas une phrase composée : tout ce qu'on pourrait y
/// interpoler — le titre, le brief, l'extrait d'une page de résultats — est
/// soit déjà dans le diff, soit la prose d'un étranger (`Citation::excerpt`).
const PULL_REQUEST_BODY: &str = "Cet article a été écrit par un employé de cette entreprise et poussé par son \
     siège. Rien n'est en ligne tant que cette demande n'est pas fusionnée : la \
     relecture, c'est celle-ci.";

/// Un appel d'outil, derrière la Gate, et la réponse dépliée.
///
/// Le `isError` de MCP est une réponse **réussie** qui dit que l'outil a
/// échoué : le laisser passer ferait ouvrir une pull request sur une branche qui
/// n'existe pas, puis chercher une adresse dans un message d'erreur.
async fn call(
    effects: &Effects,
    gate: &PolicyGate,
    server: &Slug,
    tool: &'static str,
    arguments: &Value,
) -> Result<Value, ProposeError> {
    let named = McpTool::new(
        server.clone(),
        Slug::parse(tool).expect("une constante de ce fichier"),
    );
    let token = gate
        .authorize(effects.principal(), McpCall { tool: named })
        .await?;
    // La réponse est la prose d'un étranger. Ce qui en sort ici est un booléen
    // et, plus bas, un entier — voir [`review_url`].
    let answered = effects
        .call_tool(token, arguments)
        .await?
        .into_inner_for_rendering();
    if answered.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(ProposeError::Refused(tool));
    }
    Ok(answered)
}

/// **Lire le fichier qui est peut-être déjà là**, et n'en garder que le `sha`.
///
/// Un appel derrière la Gate comme [`call`], à ceci près que `isError` n'est
/// pas une erreur : c'est la réponse de GitHub pour un fichier absent, qui est
/// le cas ordinaire. `None` veut donc dire « rien à remplacer », et le seul
/// mensonge possible est d'appeler « absent » un fichier que nos droits ne
/// laissent pas lire — auquel cas l'écriture qui suit refuse, et rien n'a été
/// créé entre les deux.
async fn read_file(
    effects: &Effects,
    gate: &PolicyGate,
    server: &Slug,
    arguments: &Value,
) -> Result<Option<String>, ProposeError> {
    let named = McpTool::new(
        server.clone(),
        Slug::parse(GET_FILE_CONTENTS).expect("une constante de ce fichier"),
    );
    let token = gate
        .authorize(effects.principal(), McpCall { tool: named })
        .await?;
    let answered = effects
        .call_tool(token, arguments)
        .await?
        .into_inner_for_rendering();
    if answered.get("isError").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    Ok(blob_sha(&answered))
}

/// Le `sha` du fichier, tel que GitHub le nomme — **et rien d'autre de sa
/// réponse**.
///
/// C'est la seule valeur de tout ce module qui vienne vraiment d'un étranger :
/// [`review_url`] rebâtit son adresse à partir de nos propres chaînes, et ici
/// c'est impossible, parce qu'un `sha` *est* ce que GitHub a à en dire. Ce qui
/// tient lieu de garde-fou est sa forme, qui ne laisse passer qu'une chose :
/// **quarante chiffres hexadécimaux**, la longueur d'un objet dans un dépôt.
/// Un `sha` faux ne fait pas écrire ailleurs — le chemin et la branche
/// viennent de nous — il fait refuser l'écriture, ce qui sort en `Refused`.
///
/// ponytail: le bloc de texte est reparsé en JSON plutôt que cherché à la
/// sous-chaîne. [`review_url`] cherche, parce qu'elle sait exactement quel
/// préfixe elle veut ; ici la clé `sha` apparaît aussi dans le contenu d'un
/// article qu'un employé aurait écrit, et « la première » serait une règle
/// d'ordre sur du JSON qui n'en promet pas.
fn blob_sha(answer: &Value) -> Option<String> {
    let text = answer.pointer("/content/0/text")?.as_str()?;
    let said: Value = serde_json::from_str(text).ok()?;
    let sha = said.get("sha")?.as_str()?;
    (sha.len() == OBJECT_SHA_DIGITS && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| sha.to_owned())
}

/// La longueur d'un identifiant d'objet, en chiffres hexadécimaux.
const OBJECT_SHA_DIGITS: usize = 40;

/// La branche d'un article : une par brouillon, nommée par lui.
///
/// Pas par le titre : deux brouillons peuvent porter le même, un titre change
/// entre deux tentatives, et une branche dont le nom dépend d'un texte est une
/// branche qu'on ne sait plus retrouver quand le troisième appel a échoué.
fn article_branch(draft: Uuid) -> String {
    format!("article/{}", draft.simple())
}

/// Le nom du fichier, tiré du titre.
///
/// Les lettres et les chiffres restent, tout le reste devient un tiret, et les
/// tirets ne se suivent pas. Vide — un titre qui n'est fait que de ponctuation
/// ou d'emoji — retombe sur l'identifiant du brouillon, qui est toujours un nom
/// de fichier valide.
///
/// ponytail: pas de translittération. « Vérifier » donne `vérifier`, pas
/// `verifier` : c'est de l'UTF-8 valide, git et l'API de GitHub l'acceptent, et
/// tous les générateurs visés servent le fichier. Ce que ça coûte est une URL
/// percent-encodée chez certains hébergeurs. Le jour où ça gêne, c'est une
/// table de translittération ici et rien d'autre à changer.
fn file_stem(title: &str, draft: Uuid) -> String {
    let mut stem = String::new();
    for ch in title.chars().flat_map(char::to_lowercase) {
        if ch.is_alphanumeric() {
            stem.push(ch);
        } else if !stem.ends_with('-') && !stem.is_empty() {
            stem.push('-');
        }
    }
    truncate_on_char(&mut stem, FILE_STEM_CAP);
    let trimmed = stem.trim_end_matches('-');
    if trimmed.is_empty() {
        return draft.simple().to_string();
    }
    trimmed.to_owned()
}

/// De quoi lire le titre dans le nom du fichier, et de quoi tenir dans les 255
/// octets qu'un système de fichiers donne à un segment une fois le dossier et
/// l'extension retirés.
const FILE_STEM_CAP: usize = 80;

/// Le fichier Markdown, en-tête compris.
///
/// L'en-tête YAML est ce qui fait qu'un dossier d'articles est un blog :
/// Jekyll, Hugo, Astro et Next lisent tous les mêmes deux clés, `title` et
/// `date`, et un fichier sans en-tête sort avec le nom du fichier pour titre et
/// aucune date. C'est deux lignes, et sans elles le chemin A ne rend pas un
/// article.
///
/// ponytail: deux clés, pas un gabarit. Un `layout`, des `tags`, une
/// `description` — chaque générateur les épelle autrement, et les deviner pour
/// le compte du client serait écrire dans son dépôt une convention qui n'est pas
/// la sienne. Le jour où un client en veut, c'est une colonne de plus sur
/// `content_repos`.
fn article(title: &str, body: &str, now: DateTime<Utc>) -> String {
    format!(
        "---\ntitle: \"{}\"\ndate: {}\n---\n\n{}\n",
        title.replace('\\', "\\\\").replace('"', "\\\""),
        now.format("%Y-%m-%d"),
        body.trim_end()
    )
}

/// **L'adresse de la relecture, rebâtie plutôt que recopiée.**
///
/// La réponse d'un serveur MCP est la prose d'un étranger, et celle-ci finit
/// dans une colonne qu'une personne va cliquer. Un `html_url` recopié tel quel
/// serait un lien qu'un serveur compromis choisit — la pull request est chez
/// nous, la page où le relecteur se retrouve serait chez lui.
///
/// Donc : on cherche, dans la réponse entière rendue en texte, le préfixe que
/// **nous** avons construit — `https://github.com/<dépôt>/pull/` — et on ne
/// garde que les chiffres qui le suivent. Ce qui en ressort est un entier, et
/// l'adresse est recomposée à partir de nos propres chaînes. Pas un octet de
/// l'étranger ne survit.
///
/// ponytail: une recherche de sous-chaîne sur le JSON rendu, pas un parcours de
/// l'arbre. La réponse de GitHub porte son JSON dans un bloc de texte, donc un
/// parcours devrait de toute façon reparser les blocs ; et ce qui est cherché
/// est assez étroit — notre préfixe exact, suivi de chiffres — pour qu'une
/// correspondance ailleurs dans la réponse désigne la même pull request.
///
/// Ce que ça ne couvre pas, nommé : un GitHub Enterprise servi sur un autre
/// hôte. Ce déploiement ne branche que le serveur distant de github.com
/// (`catalog::CATALOG`), et le jour où une entrée de catalogue en nomme un
/// autre, c'est cet hôte qui devient un champ de `content_repos`.
fn review_url(answer: &Value, repo: &str) -> Option<String> {
    let prefix = format!("https://github.com/{repo}/pull/");
    let rendered = answer.to_string();
    let at = rendered.find(&prefix)? + prefix.len();
    let number: String = rendered[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .take(PULL_REQUEST_DIGITS)
        .collect();
    (!number.is_empty()).then(|| format!("{prefix}{number}"))
}

/// Le plus grand numéro de pull request qu'on accepte de lire. Le dépôt le plus
/// actif de GitHub n'a pas atteint le million ; ce qui compte ici est qu'une
/// suite de chiffres sans fin ne devienne pas une chaîne sans fin.
const PULL_REQUEST_DIGITS: usize = 9;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use agentos_domain::action::Channel;
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::policy::PolicyLimits;
    use agentos_providers::browser::BrowserProvider;
    use agentos_providers::browser_http::{HttpBrowser, PinnedHost};
    use agentos_store::db::Db;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::effects::Ports;
    use crate::gate::Principal;

    /// Une page de résultats à la forme de `lite.duckduckgo.com` : trois lignes
    /// de tableau par résultat, le rang collé au titre.
    fn serp(results: &[(&str, &str, &str)]) -> String {
        let mut html = String::from("<!doctype html><html><body><table border=\"0\">");
        for (index, (title, snippet, host)) in results.iter().enumerate() {
            html.push_str(&format!(
                "<tr><td valign=\"top\">{}.&nbsp;</td>\
                 <td><a class='result-link' href='//duckduckgo.com/l/?uddg=x'>{title}</a></td></tr>\
                 <tr><td>&nbsp;</td><td class='result-snippet'>{snippet}</td></tr>\
                 <tr><td>&nbsp;</td><td><span class='link-text'>{host}</span></td></tr>",
                index + 1
            ));
        }
        html.push_str("</table></body></html>");
        html
    }

    /// Le domaine `ours` au rang 3, deux concurrents devant — et il y est comme
    /// un **sous-domaine**, parce que c'est la forme réelle (`orizn.app` est le
    /// domaine d'envoi, `visa.orizn.app` est le site) et parce que c'est ce qui
    /// fait passer la mesure par [`covers`] plutôt que par une égalité.
    fn three_results(ours: &str) -> String {
        let mine = format!("visa.{ours}");
        serp(&[
            (
                "Visa API by Travel Buddy",
                "Free tier included. JSON endpoints and examples.",
                "travel-buddy.ai/api/",
            ),
            (
                "Post-covid visa requirements API",
                "Real-time visa, entry and vaccination requirements.",
                "visadb.io/api",
            ),
            (
                "Visa Requirements API | Orizn",
                "47,362 pairs across 199 passports.",
                &mine,
            ),
        ])
    }

    // -- le scan, sans base ni réseau ---------------------------------------

    #[test]
    fn le_scan_rend_le_rang_et_les_concurrents() {
        // Le texte que `browser_http::visible_text` produit de `three_results`,
        // écrit ici à la main : ce test-ci mesure le scan, pas l'extracteur.
        let text = "1. Visa API by Travel Buddy\n\
                    Free tier included. JSON endpoints and examples.\n\
                    travel-buddy.ai/api/\n\
                    2. Post-covid visa requirements API\n\
                    Real-time visa, entry and vaccination requirements.\n\
                    visadb.io/api\n\
                    3. Visa Requirements API | Orizn\n\
                    47,362 pairs across 199 passports.\n\
                    visa.orizn.app\n";
        let cited = read_results(
            text,
            &["orizn.app".to_owned()],
            Engine::DuckDuckGoLite,
            Utc::now(),
        );
        assert!(cited.cited);
        assert_eq!(cited.rank, Some(3));
        assert_eq!(
            cited.competitors,
            ["travel-buddy.ai", "visadb.io", "visa.orizn.app"]
        );

        // Le désarmement : la même page, sans nous. Si `cited` était calculé
        // autrement que par la présence d'un de nos domaines, ce test passerait
        // aussi.
        let absent = read_results(
            text,
            &["ailleurs.example".to_owned()],
            Engine::DuckDuckGoLite,
            Utc::now(),
        );
        assert!(!absent.cited);
        assert_eq!(absent.rank, None);
        assert_eq!(absent.competitors.len(), 3);
    }

    /// Une ligne de résumé n'est pas un hôte, et un hôte n'est pas un résumé.
    #[test]
    fn un_resume_qui_ressemble_a_un_hote_nen_est_pas_un() {
        assert_eq!(
            display_host("visa.orizn.app"),
            Some("visa.orizn.app".into())
        );
        assert_eq!(
            display_host("www.oanor.com/api/visa-api"),
            Some("oanor.com".into())
        );
        // Des blancs : c'est une phrase.
        assert_eq!(display_host("REST API for visa requirements"), None);
        // Pas de point, ou un TLD d'une lettre, ou vide.
        assert_eq!(display_host("visa"), None);
        assert_eq!(display_host("e.g"), None);
        assert_eq!(display_host("..."), None);
        // **Un blanc dans le chemin n'est pas un blanc dans l'hôte.** Relevé
        // sur le vrai moteur le 2026-09-12 : la requête affichée entre dans
        // l'adresse, espace compris.
        assert_eq!(
            display_host("zylalabs.com/api-marketplace/top-search/visa requirements"),
            Some("zylalabs.com".into())
        );
        // Et une phrase qui porte une barre reste une phrase : le blanc est
        // avant elle.
        assert_eq!(display_host("Check visa rules and/or entry rules"), None);
    }

    /// **Un hôte non reconnu coûtait un rang.**
    ///
    /// La page mesurée le 2026-09-12 sur « how do I check visa requirements by
    /// API » affichait le troisième résultat comme
    /// `zylalabs.com/api-marketplace/top-search/visa requirements`. La ligne
    /// portait un blanc, l'hôte n'était pas lu, le résultat se refermait sans
    /// nom — et nous sortions 4ᵉ avec une chaîne vide devant nous, qui
    /// remontait telle quelle dans l'`outrank` du brief.
    #[test]
    fn un_hote_dont_le_chemin_porte_un_blanc_reste_un_hote() {
        let text = "1. Global Visa Check API | Zyla API Hub\n\
                    Real-time visa requirements for tourists.\n\
                    zylalabs.com/api-marketplace/global-visa-check\n\
                    2. Best Visa requirements APIs | Zyla API Hub\n\
                    The Global Visa Check is an API.\n\
                    zylalabs.com/api-marketplace/top-search/visa requirements\n\
                    3. Visa Requirements API | Orizn\n\
                    47,362 pairs across 199 passports.\n\
                    visa.orizn.app\n";
        let scanned = read_results(
            text,
            &["orizn.app".to_owned()],
            Engine::DuckDuckGoLite,
            Utc::now(),
        );
        assert_eq!(scanned.rank, Some(3), "{:?}", scanned.competitors);
        assert!(
            !scanned.competitors.iter().any(String::is_empty),
            "un concurrent sans nom est un hôte qu'on n'a pas su lire : {:?}",
            scanned.competitors
        );
        // Et le résumé du deuxième n'a pas avalé sa propre ligne d'adresse.
        assert!(
            !scanned.excerpt.contains("top-search"),
            "l'adresse est restée dans le résumé : {:?}",
            scanned.excerpt
        );
    }

    /// Le rang doit suivre, sinon un résumé numéroté ouvre un faux résultat.
    #[test]
    fn un_rang_hors_sequence_nouvre_rien() {
        let text = "1. Un titre\n\
                    7. ce résumé commence par un chiffre\n\
                    exemple.com\n";
        let scanned = read_results(
            text,
            &["nous.example".to_owned()],
            Engine::DuckDuckGoLite,
            Utc::now(),
        );
        assert_eq!(scanned.competitors, ["exemple.com"]);
        assert!(
            scanned.excerpt.contains("7. ce résumé"),
            "le résumé numéroté doit rester du résumé : {:?}",
            scanned.excerpt
        );
    }

    #[test]
    fn lurl_du_moteur_encode_la_question() {
        let url = Engine::DuckDuckGoLite.results_url("comment vérifier un visa par API ?");
        assert_eq!(url.host_str(), Some("lite.duckduckgo.com"));
        assert_eq!(
            url.query(),
            Some("q=comment+v%C3%A9rifier+un+visa+par+API+%3F")
        );
    }

    // -- le brief ------------------------------------------------------------

    /// **Le brief nomme ce que les pages citées ne couvrent pas.**
    #[test]
    fn le_brief_nomme_ce_qui_manque_aux_pages_citees() {
        let citation = read_results(
            "1. Visa API by Travel Buddy\n\
             Free tier included with pricing per request. JSON example with curl.\n\
             travel-buddy.ai/api/\n\
             2. Orizn\n\
             47,362 pairs.\n\
             visa.orizn.app\n",
            &["orizn.app".to_owned()],
            Engine::DuckDuckGoLite,
            Utc::now(),
        );
        let sheet = brief("visa requirements api", &citation);

        assert_eq!(sheet.angle, Angle::Outrank);
        assert!(sheet.covered.contains(&"prix"), "{:?}", sheet.covered);
        assert!(sheet.covered.contains(&"exemple"), "{:?}", sheet.covered);
        assert!(sheet.covered.contains(&"couverture"), "{:?}", sheet.covered);
        // Aucune des deux pages ne parle de limites de débit ni de SLA : c'est
        // la place, et c'est ce que l'employé doit écrire.
        assert!(sheet.missing.contains(&"limites"), "{:?}", sheet.missing);
        assert!(sheet.missing.contains(&"fiabilité"), "{:?}", sheet.missing);
        // Devant nous : celui-là et lui seul.
        assert_eq!(sheet.outrank, ["travel-buddy.ai"]);

        // Le désarmement : une facette n'est « couverte » que parce que le mot
        // est là. Sans les mots, la même mesure la déclare manquante.
        let silent = Citation {
            excerpt: "Orizn\n".to_owned(),
            ..citation.clone()
        };
        let sheet = brief("visa requirements api", &silent);
        assert!(sheet.missing.contains(&"prix"), "{:?}", sheet.missing);
        assert!(sheet.covered.is_empty(), "{:?}", sheet.covered);
    }

    #[test]
    fn langle_suit_le_rang() {
        let base = read_results(
            "",
            &["nous.example".to_owned()],
            Engine::DuckDuckGoLite,
            Utc::now(),
        );
        let with_rank = |rank: Option<i32>| Citation {
            rank,
            cited: rank.is_some(),
            competitors: vec!["a.example".into(), "b.example".into(), "c.example".into()],
            ..base.clone()
        };
        assert_eq!(brief("q", &with_rank(Some(1))).angle, Angle::Hold);
        assert_eq!(brief("q", &with_rank(Some(4))).angle, Angle::Outrank);
        assert_eq!(brief("q", &with_rank(None)).angle, Angle::Uncovered);
        // Absents, on nomme les trois premiers ; premiers, personne.
        assert_eq!(brief("q", &with_rank(None)).outrank.len(), 3);
        assert!(brief("q", &with_rank(Some(1))).outrank.is_empty());
    }

    /// Les endroits : ce qui revient d'une question à l'autre, ce qui est à
    /// nous et n'est donc pas un endroit, et l'ordre qui met devant celui où
    /// l'on manque le plus.
    #[test]
    fn les_endroits_comptent_les_questions_et_retirent_les_notres() {
        let seen = |question: &str, cited: bool, hosts: &[&str]| Seen {
            question: question.to_owned(),
            cited,
            competitors: hosts.iter().map(|host| (*host).to_owned()).collect(),
        };
        let rows = vec![
            // Absents : le forum et le comparatif comptent contre nous.
            seen("q1", false, &["forum.example", "", "revue.example"]),
            // Absents encore, et le forum revient — cette fois au rang 1.
            seen("q2", false, &["forum.example", "revue.example"]),
            // Cités : le forum est là, mais nous aussi. Il compte une question
            // de plus, pas un manque de plus. Et un doublon ne compte qu'une
            // fois, au meilleur de ses rangs.
            seen(
                "q3",
                true,
                &["blog.nous.example", "revue.example", "revue.example"],
            ),
        ];
        let places = places(&rows, &["nous.example".to_owned()]);

        // Nos propres sites, sous-domaine compris, ne sont pas des endroits ;
        // un hôte vide non plus.
        assert!(
            places
                .iter()
                .all(|place| place.host != "blog.nous.example" && !place.host.is_empty())
        );

        // `forum` manque deux fois, `revue` aussi — égalité ; `revue` sort
        // devant parce qu'il revient sur trois questions contre deux.
        let names: Vec<&str> = places.iter().map(|place| place.host.as_str()).collect();
        assert_eq!(names, vec!["revue.example", "forum.example"]);

        let revue = &places[0];
        assert_eq!(revue.questions, 3, "un doublon ne compte pas deux fois");
        assert_eq!(revue.best_rank, 2);
        assert_eq!(revue.without_us, vec!["q1".to_owned(), "q2".to_owned()]);

        let forum = &places[1];
        assert_eq!(forum.questions, 2);
        assert_eq!(forum.best_rank, 1, "le meilleur rang, pas le dernier vu");

        // Cités partout où l'hôte est : rien à aller chercher.
        let all_cited = places(&[seen("q", true, &["forum.example"])], &[]);
        assert!(all_cited[0].without_us.is_empty());
    }

    // -- de bout en bout, sur un faux moteur servi en local -------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; les tests de contenu veulent un vrai Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// Un locataire, un siège actif, une politique qui autorise le web, un
    /// navigateur provisionné et **un domaine à lui**.
    ///
    /// Le domaine est dérivé du locataire et pas écrit en dur : `tenant_domains`
    /// impose `domain` unique sur toute la base (0093), donc deux tests qui
    /// adoptent `orizn.app` sont deux tests dont le second meurt sur une clé
    /// dupliquée — et la trace accuse le contenu plutôt que la fixture.
    async fn seed(db: &Db) -> (Principal, String) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("geo-{}", employee.as_uuid().simple());
        let domain = format!("{}.example", tenant.as_uuid().simple());

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        install_web_policy(db, tenant, true).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO tenant_domains (tenant_id, domain, provider, status, is_primary) \
             VALUES ($1, $2, 'mock-email', 'verified', true)",
        )
        .bind(tenant.as_uuid())
        .bind(&domain)
        .execute(&mut **tx)
        .await
        .expect("insert domain");
        sqlx::query(
            "INSERT INTO employee_resources \
                 (employee_id, step, tenant_id, state, provider, external_id) \
             VALUES ($1, 'browser', $2, 'ready', 'mock-browser', $3)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(format!("ctx-{}", employee.as_uuid().simple()))
        .execute(&mut **tx)
        .await
        .expect("insert browser resource");
        tx.commit().await.expect("commit resources");

        (Principal::employee(tenant, employee), domain)
    }

    /// La couche du locataire. `web: false` est le désarmement de la Gate.
    async fn install_web_policy(db: &Db, tenant: TenantId, web: bool) {
        let mut allowed_channels = BTreeSet::new();
        if web {
            allowed_channels.insert(Channel::Web);
        }
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                allowed_channels,
                max_turns_per_day: 10,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install policy");
    }

    /// Sert une page unique sur le loopback, comme `effects.rs` le fait.
    async fn static_site(html: String) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let html = html.clone();
                tokio::spawn(async move {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{html}",
                        html.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    /// Les ports de ce déploiement, le navigateur remplacé par un `GET` épinglé
    /// sur le faux moteur.
    fn ports_reading(site: SocketAddr) -> Arc<Ports> {
        let browser: Arc<dyn BrowserProvider> = Arc::new(HttpBrowser::new(Arc::new(
            PinnedHost::new(Engine::DuckDuckGoLite.host(), site.ip()),
        )));
        Arc::new(Ports {
            browser,
            ..crate::mocks::ports()
        })
    }

    /// L'URL du faux moteur : son hôte, le port que le système a donné.
    fn fake_results(site: SocketAddr, question: &str) -> Url {
        let mut url = Engine::DuckDuckGoLite.results_url(question);
        url.set_scheme("http").expect("http");
        url.set_port(Some(site.port())).expect("port");
        url
    }

    /// Déclarer le site d'un locataire, puisque c'est **ça** que `our_domains`
    /// lit — et pas la ligne de `tenant_domains` que [`seed`] pose à côté.
    async fn declare_site(db: &Db, principal: &Principal, site: &str) {
        seed_repo(db, principal, Some(site)).await;
    }

    /// Ce que « nous » veut dire pour ce locataire, lu comme une route le lit.
    async fn ours(db: &Db, tenant: TenantId) -> Vec<String> {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let domains = our_domains(&mut tx).await.expect("our domains");
        tx.commit().await.expect("commit");
        domains
    }

    #[tokio::test]
    async fn la_mesure_lit_le_rang_sur_un_faux_moteur_et_sempile_sans_se_reecrire() {
        let Some(db) = db().await else { return };
        let (principal, domain) = seed(&db).await;
        declare_site(&db, &principal, &format!("visa.{domain}")).await;
        let site = static_site(three_results(&domain)).await;
        let effects = Effects::new(db.clone(), ports_reading(site), principal.clone());
        let gate = PolicyGate::new(db.clone());
        let url = fake_results(site, "visa requirements api");
        let ours = ours(&db, principal.tenant_id).await;
        assert_eq!(
            ours,
            [format!("visa.{domain}")],
            "« nous » est le site déclaré, jamais le domaine d'envoi"
        );

        let citation = measure_page(&effects, &gate, &ours, &url, Engine::DuckDuckGoLite)
            .await
            .expect("la mesure");
        assert!(citation.cited);
        assert_eq!(citation.rank, Some(3));
        assert_eq!(
            citation.competitors,
            [
                "travel-buddy.ai",
                "visadb.io",
                format!("visa.{domain}").as_str()
            ]
        );
        assert!(citation.excerpt.contains("Travel Buddy"));

        // La série s'empile. Deux mesures, deux lignes, et la première est
        // toujours là avec sa valeur.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        let question = questions::add(&mut tx, "visa requirements api", "en", Source::Founder, 5)
            .await
            .expect("add");
        citations::record(&mut tx, question.id, &citation)
            .await
            .expect("record");
        let second = Citation {
            checked_at: citation.checked_at + chrono::Duration::hours(1),
            cited: false,
            rank: None,
            ..citation.clone()
        };
        citations::record(&mut tx, question.id, &second)
            .await
            .expect("record again");
        let series = citations::list(&mut tx, question.id, 30)
            .await
            .expect("list");
        tx.commit().await.expect("commit");

        assert_eq!(series.len(), 2, "une mesure n'écrase pas la précédente");
        assert!(!series[0].cited);
        assert_eq!(
            series[1].rank,
            Some(3),
            "la première mesure a gardé son rang"
        );

        // Le désarmement de l'ajout seul : `app_role` n'a pas le droit de
        // réécrire une mesure. Si le grant de `0100` glissait, ce `UPDATE`
        // passerait.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        let refused = sqlx::query("UPDATE content_citations SET cited = true")
            .execute(&mut **tx)
            .await;
        assert!(
            refused.is_err(),
            "une mesure a pu être réécrite : le grant de 0100 a glissé"
        );
        drop(tx);

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **La même page, sans nous.**
    #[tokio::test]
    async fn la_meme_page_sans_nous_nest_pas_une_citation() {
        let Some(db) = db().await else { return };
        // Le seul changement : le domaine cité au rang 3 n'est pas le nôtre.
        // Rien d'autre ne bouge — même page, même siège, même politique.
        let (principal, domain) = seed(&db).await;
        declare_site(&db, &principal, &format!("visa.{domain}")).await;
        let site = static_site(three_results("quelquun-dautre.example")).await;
        let effects = Effects::new(db.clone(), ports_reading(site), principal.clone());
        let gate = PolicyGate::new(db.clone());

        let citation = measure_page(
            &effects,
            &gate,
            &ours(&db, principal.tenant_id).await,
            &fake_results(site, "visa requirements api"),
            Engine::DuckDuckGoLite,
        )
        .await
        .expect("la mesure");
        assert!(!citation.cited);
        assert_eq!(citation.rank, None);
        assert_eq!(citation.competitors.len(), 3, "les trois sont toujours lus");

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **La Gate mord.** Un siège sans `Channel::Web` ne mesure pas.
    #[tokio::test]
    async fn un_siege_sans_le_web_ne_mesure_pas() {
        let Some(db) = db().await else { return };
        let (principal, domain) = seed(&db).await;
        declare_site(&db, &principal, &format!("visa.{domain}")).await;
        let site = static_site(three_results(&domain)).await;
        let effects = Effects::new(db.clone(), ports_reading(site), principal.clone());
        let gate = PolicyGate::new(db.clone());
        let url = fake_results(site, "visa requirements api");
        let ours = ours(&db, principal.tenant_id).await;

        // Armé : avec le web, la mesure passe.
        measure_page(&effects, &gate, &ours, &url, Engine::DuckDuckGoLite)
            .await
            .expect("avec le web, la mesure passe");

        // Désarmé : on retire le canal, et rien d'autre.
        install_web_policy(&db, principal.tenant_id, false).await;
        let err = measure_page(&effects, &gate, &ours, &url, Engine::DuckDuckGoLite)
            .await
            .expect_err("sans le web, rien ne sort");
        assert!(
            matches!(err, MeasureError::Denied(_)),
            "la Gate doit refuser, et pas le navigateur : {err}"
        );

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **Un domaine d'envoi n'est pas un site, et `our_domains` ne le lit pas.**
    ///
    /// C'est le trou du `docs/CONTENU.md` § 7.3, refermé et tenu ici :
    /// [`seed`] pose une ligne de `tenant_domains` — un domaine **vérifié**,
    /// primaire, celui d'où partent les mails — et ce locataire ne déclare
    /// aucun site. La lecture d'avant (`SELECT domain FROM tenant_domains`)
    /// rendait ce domaine-là et mesurait une question en cherchant l'adresse
    /// d'un expéditeur dans une page de résultats : juste, et faux.
    ///
    /// Ce qui est attendu maintenant est un refus lisible, pas une mesure
    /// basse : un `cited: false` écrit dans une table en ajout seul ne se
    /// retire plus.
    #[tokio::test]
    async fn un_domaine_denvoi_nest_pas_un_site_et_la_mesure_refuse() {
        let Some(db) = db().await else { return };
        let (principal, domain) = seed(&db).await;

        // Le domaine d'envoi est bien là, vérifié, et il ne compte pas.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        let sending: Vec<(String,)> = sqlx::query_as("SELECT domain FROM tenant_domains")
            .fetch_all(&mut **tx)
            .await
            .expect("les domaines d'envoi");
        tx.commit().await.expect("commit");
        assert_eq!(sending, [(domain.clone(),)], "le domaine d'envoi est posé");
        assert!(
            ours(&db, principal.tenant_id).await.is_empty(),
            "un domaine d'envoi s'est glissé dans ce que « nous » veut dire"
        );

        let site = static_site(three_results("personne.example")).await;
        let effects = Effects::new(db.clone(), ports_reading(site), principal.clone());
        let gate = PolicyGate::new(db.clone());
        let err = measure_page(
            &effects,
            &gate,
            &ours(&db, principal.tenant_id).await,
            &fake_results(site, "q"),
            Engine::DuckDuckGoLite,
        )
        .await
        .expect_err("sans site à nous, rien à chercher");
        assert!(matches!(err, MeasureError::NoDomainOfOurs), "{err}");

        // Et le désarmement : un site déclaré, et « nous » veut dire quelque
        // chose — celui-là, et pas le domaine d'envoi.
        declare_site(&db, &principal, "visa.acme-site.example").await;
        assert_eq!(
            ours(&db, principal.tenant_id).await,
            ["visa.acme-site.example"]
        );

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **RLS.** Deux locataires, et aucun ne voit les questions, les mesures ni
    /// les brouillons de l'autre.
    #[tokio::test]
    async fn un_locataire_ne_voit_pas_le_contenu_dun_autre() {
        let Some(db) = db().await else { return };
        let (a, _) = seed(&db).await;
        let (b, _) = seed(&db).await;

        let mut tx = db.tenant_tx(a.tenant_id).await.expect("tenant tx");
        let question = questions::add(
            &mut tx,
            "comment vérifier un visa",
            "fr",
            Source::Customer,
            9,
        )
        .await
        .expect("add");
        citations::record(
            &mut tx,
            question.id,
            &read_results(
                "",
                &["a.example".to_owned()],
                Engine::DuckDuckGoLite,
                Utc::now(),
            ),
        )
        .await
        .expect("record");
        drafts::create(&mut tx, question.id, "Titre", "Corps")
            .await
            .expect("draft");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(b.tenant_id).await.expect("tenant tx");
        assert!(questions::list(&mut tx).await.expect("list").is_empty());
        assert!(
            citations::list(&mut tx, question.id, 30)
                .await
                .expect("list")
                .is_empty()
        );
        assert!(drafts::list(&mut tx).await.expect("list").is_empty());
        // Et il ne peut pas non plus la retirer.
        assert!(
            !questions::remove(&mut tx, question.id)
                .await
                .expect("remove")
        );
        tx.commit().await.expect("commit");

        // Le désarmement : chez lui, tout est là.
        let mut tx = db.tenant_tx(a.tenant_id).await.expect("tenant tx");
        assert_eq!(questions::list(&mut tx).await.expect("list").len(), 1);
        assert_eq!(
            citations::list(&mut tx, question.id, 30)
                .await
                .expect("list")
                .len(),
            1
        );
        assert_eq!(drafts::list(&mut tx).await.expect("list").len(), 1);
        tx.commit().await.expect("commit");

        drop_tenant(&db, a.tenant_id).await;
        drop_tenant(&db, b.tenant_id).await;
    }

    /// Un brouillon devient publié quand une adresse est constatée, et sa date
    /// de publication ne bouge plus.
    #[tokio::test]
    async fn un_brouillon_publie_garde_sa_date() {
        let Some(db) = db().await else { return };
        let (principal, _) = seed(&db).await;
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        let question = questions::add(&mut tx, "q", "fr", Source::Founder, 1)
            .await
            .expect("add");
        let draft = drafts::create(&mut tx, question.id, "Titre", "Corps")
            .await
            .expect("draft");
        assert_eq!(draft.state, "draft");
        assert!(draft.published_at.is_none());

        let published = drafts::update(
            &mut tx,
            draft.id,
            &drafts::Revision {
                title: "Titre",
                body: "Corps",
                url: Some("https://visa.orizn.app/blog/visa-api"),
            },
        )
        .await
        .expect("update")
        .expect("le brouillon existe");
        assert_eq!(published.state, "published");
        let first = published.published_at.expect("publié porte sa date");

        let corrected = drafts::update(
            &mut tx,
            draft.id,
            &drafts::Revision {
                title: "Titre corrigé",
                body: "Corps corrigé",
                url: Some("https://visa.orizn.app/blog/visa-api"),
            },
        )
        .await
        .expect("update")
        .expect("le brouillon existe");
        assert_eq!(
            corrected.published_at,
            Some(first),
            "une typo n'est pas une publication"
        );

        // **Et l'omission dépublie.** C'est la convention de la maison — un
        // `set` efface ce qu'on ne lui redonne pas — mais sur cette
        // colonne-là elle coûte la date à laquelle l'article est entré en
        // ligne, c'est-à-dire le seul instant auquel la série de
        // `content_citations` peut être comparée. Testé parce que la
        // description de `content_drafts_amend` promettait l'inverse jusqu'au
        // 2026-09-12 : « la date de publication est posée la première fois et
        // ne bouge plus » se lisait comme une garantie, et elle ne vaut
        // qu'avec l'`url`.
        let undone = drafts::update(
            &mut tx,
            draft.id,
            &drafts::Revision {
                title: "Titre corrigé",
                body: "Corps corrigé",
                url: None,
            },
        )
        .await
        .expect("update")
        .expect("le brouillon existe");
        assert_ne!(undone.state, "published", "l'omission a laissé un publié");
        assert!(undone.url.is_none());
        assert!(
            undone.published_at.is_none(),
            "la date a survécu à l'effacement de l'adresse qu'elle date"
        );
        tx.commit().await.expect("commit");

        drop_tenant(&db, principal.tenant_id).await;
    }

    // -- la proposition, contre un faux GitHub ------------------------------

    /// Le handle sous lequel les tests d'ici branchent GitHub.
    const HANDLE: &str = "github";

    /// **Un faux GitHub**, au port plutôt qu'au fil.
    ///
    /// `browser_chrome.rs` monte un faux CDP parce que ce qu'il mesure *est* le
    /// protocole. Ici, le protocole est déjà tenu par un serveur MCP en
    /// processus dans les tests de `crate::mcp` — celui-là parle HTTP et construit
    /// ses corps avec les types de `rmcp`. Ce qui n'est tenu nulle part, et que
    /// ce double mesure, est ce que **nous** envoyons : quels outils, dans quel
    /// ordre, avec quels arguments, et ce qu'on fait de la réponse.
    ///
    /// Il ressemble à GitHub sur les deux points qui décident : un outil qu'il
    /// ne connaît pas est un `unknown_tool` terminal, et un outil qui échoue
    /// répond `isError` — une réponse *réussie* qui dit non, ce qui est la
    /// forme de MCP et le piège que `call` existe pour attraper.
    struct FauxGithub {
        seen: std::sync::Mutex<Vec<(String, Value)>>,
        /// L'adresse que la pull request s'attribue. Une chaîne, pour qu'un test
        /// puisse en mettre une qui n'est pas dans le dépôt.
        pull: String,
        /// L'outil qui répondra `isError`, s'il y en a un.
        failing: Option<&'static str>,
        /// Ce que la branche qui sert le site porte déjà à ce chemin : le `sha`
        /// du fichier, ou rien. `None` est un dépôt vide — GitHub répond alors
        /// `isError`, comme pour n'importe quel 404, et c'est le cas ordinaire
        /// d'un premier article.
        holds: Option<&'static str>,
    }

    /// Le `sha` que [`FauxGithub::holding`] rend : quarante chiffres
    /// hexadécimaux, la seule forme que `blob_sha` laisse passer.
    const HELD_SHA: &str = "9f1c0a7b3e5d2f48a6c9b0e1d3f5a7c9b1d3e5f7";

    impl FauxGithub {
        fn new(pull: &str) -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::Mutex::new(Vec::new()),
                pull: pull.to_owned(),
                failing: None,
                holds: None,
            })
        }

        fn refusing(pull: &str, tool: &'static str) -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::Mutex::new(Vec::new()),
                pull: pull.to_owned(),
                failing: Some(tool),
                holds: None,
            })
        }

        /// Un dépôt qui porte **déjà** l'article : le cas de la republication.
        fn holding(pull: &str, sha: &'static str) -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::Mutex::new(Vec::new()),
                pull: pull.to_owned(),
                failing: None,
                holds: Some(sha),
            })
        }

        /// Ce qui a été prononcé, dans l'ordre.
        fn calls(&self) -> Vec<(String, Value)> {
            self.seen.lock().expect("pas empoisonné").clone()
        }

        fn tools(&self) -> Vec<String> {
            self.calls().into_iter().map(|(tool, _)| tool).collect()
        }

        /// Les arguments du n-ième appel.
        fn args(&self, nth: usize) -> Value {
            self.calls()[nth].1.clone()
        }
    }

    /// La forme d'un `CallToolResult` sérialisé : GitHub rend son JSON dans un
    /// bloc de texte, ce qui est exactement ce que `review_url` doit traverser.
    fn tool_result(text: String, is_error: bool) -> Value {
        json!({
            "content": [{ "type": "text", "text": text }],
            "isError": is_error,
        })
    }

    #[async_trait::async_trait]
    impl crate::effects::McpCaller for FauxGithub {
        async fn call(
            &self,
            tool: &McpTool,
            arguments: &Value,
        ) -> Result<agentos_domain::untrusted::Untrusted<Value>, crate::mocks::ProviderError>
        {
            let name = tool.name.as_str().to_owned();
            self.seen
                .lock()
                .expect("pas empoisonné")
                .push((name.clone(), arguments.clone()));

            if ![
                GET_FILE_CONTENTS,
                CREATE_BRANCH,
                CREATE_OR_UPDATE_FILE,
                CREATE_PULL_REQUEST,
            ]
            .contains(&name.as_str())
            {
                return Err(crate::mocks::ProviderError::Terminal {
                    code: "unknown_tool",
                });
            }
            if self.failing == Some(name.as_str()) {
                return Ok(agentos_domain::untrusted::Untrusted::new(tool_result(
                    "Reference already exists".to_owned(),
                    true,
                )));
            }
            // Un fichier absent est un `isError` chez GitHub, pas une panne :
            // c'est ce que `read_file` traduit en « rien à remplacer ».
            if name == GET_FILE_CONTENTS {
                let Some(sha) = self.holds else {
                    return Ok(agentos_domain::untrusted::Untrusted::new(tool_result(
                        "Not Found".to_owned(),
                        true,
                    )));
                };
                return Ok(agentos_domain::untrusted::Untrusted::new(tool_result(
                    json!({ "name": "un-article.md", "sha": sha, "size": 512 }).to_string(),
                    false,
                )));
            }
            let said = if name == CREATE_PULL_REQUEST {
                json!({ "number": 7, "html_url": self.pull, "state": "open" }).to_string()
            } else {
                json!({ "ok": true }).to_string()
            };
            Ok(agentos_domain::untrusted::Untrusted::new(tool_result(
                said, false,
            )))
        }
    }

    /// Les ports de ce déploiement, GitHub remplacé par le double.
    fn ports_calling(github: Arc<FauxGithub>) -> Arc<Ports> {
        Arc::new(Ports {
            mcp: github,
            ..crate::mocks::ports()
        })
    }

    /// La politique d'un siège qui a le droit de prononcer ces outils-là, et
    /// aucun autre. Le désarmement de la Gate est une liste plus courte.
    async fn install_tool_policy(db: &Db, tenant: TenantId, tools: &[&str]) {
        let allowed_mcp_tools = tools
            .iter()
            .map(|tool| {
                McpTool::new(
                    Slug::parse(HANDLE).expect("slug"),
                    Slug::parse(tool).expect("slug"),
                )
            })
            .collect();
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                allowed_mcp_tools,
                max_turns_per_day: 10,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install policy");
    }

    /// Un branchement MCP, et le dépôt d'un siège dessus.
    ///
    /// L'URL est bidon et personne ne la compose : le `Fleet` du processus n'est
    /// pas dans cette boucle, c'est [`FauxGithub`] qui répond. Ce que la ligne
    /// sert ici est la clé étrangère de `0102` — un dépôt ne se pose pas sur un
    /// branchement qui n'existe pas.
    async fn seed_repo(db: &Db, principal: &Principal, site: Option<&str>) -> repos::Repo {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector) \
             VALUES ($1, $2, 'https://api.githubcopilot.com/mcp/', 'public', 'github')",
        )
        .bind(principal.tenant_id.as_uuid())
        .bind(HANDLE)
        .execute(&mut **tx)
        .await
        .expect("insert binding");
        let repo = repos::set(
            &mut tx,
            principal.employee_id.as_uuid(),
            HANDLE,
            "acme/site",
            "main",
            "content/blog",
            site,
        )
        .await
        .expect("set repo")
        .expect("le branchement existe");
        tx.commit().await.expect("commit");
        repo
    }

    /// Un brouillon prêt à être proposé.
    async fn seed_draft(db: &Db, principal: &Principal, title: &str) -> drafts::Draft {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        let question = questions::add(&mut tx, title, "fr", Source::Founder, 1)
            .await
            .expect("add");
        let draft = drafts::create(&mut tx, question.id, title, "Le corps de l'article.")
            .await
            .expect("draft");
        tx.commit().await.expect("commit");
        draft
    }

    // -- le fichier et l'adresse, sans base ni réseau -------------------------

    #[test]
    fn le_nom_du_fichier_sort_du_titre_et_ne_ment_pas_quand_il_ny_en_a_pas() {
        let draft = Uuid::now_v7();
        assert_eq!(
            file_stem("Vérifier un visa par API : le guide", draft),
            "vérifier-un-visa-par-api-le-guide"
        );
        // Les tirets ne se suivent pas, et il n'y en a ni au début ni à la fin.
        assert_eq!(file_stem("  ---  A !!! B  ", draft), "a-b");
        // Un titre sans une seule lettre retombe sur l'identifiant, qui est
        // toujours un nom de fichier.
        assert_eq!(file_stem("!!!", draft), draft.simple().to_string());
        assert_eq!(file_stem("", draft), draft.simple().to_string());
        // Et il tient dans un segment de chemin.
        assert!(file_stem(&"a b ".repeat(200), draft).len() <= FILE_STEM_CAP);
    }

    #[test]
    fn len_tete_porte_le_titre_et_la_date() {
        let when = DateTime::parse_from_rfc3339("2026-09-11T10:00:00Z")
            .expect("date")
            .with_timezone(&Utc);
        let rendered = article("Un \"guide\" du visa", "Le corps.\n\n", when);
        assert_eq!(
            rendered,
            "---\ntitle: \"Un \\\"guide\\\" du visa\"\ndate: 2026-09-11\n---\n\nLe corps.\n"
        );
    }

    /// **L'adresse de relecture est rebâtie, pas recopiée.**
    #[test]
    fn ladresse_de_relecture_ne_suit_pas_un_etranger() {
        let answer =
            |url: &str| tool_result(json!({ "number": 7, "html_url": url }).to_string(), false);

        // Le cas ordinaire : l'adresse ressort, et elle est faite de nos
        // chaînes plus un entier.
        assert_eq!(
            review_url(&answer("https://github.com/acme/site/pull/7"), "acme/site"),
            Some("https://github.com/acme/site/pull/7".to_owned())
        );

        // **Le désarmement.** Un serveur compromis qui renvoie une adresse
        // ailleurs n'envoie personne ailleurs : il n'y a rien à rebâtir.
        assert_eq!(
            review_url(
                &answer("https://github.example/acme/site/pull/7"),
                "acme/site"
            ),
            None
        );
        // Un autre dépôt, même hôte : non plus.
        assert_eq!(
            review_url(&answer("https://github.com/autre/site/pull/7"), "acme/site"),
            None
        );
        // Notre préfixe, suivi de n'importe quoi : ce qui survit est le nombre,
        // et rien d'autre.
        assert_eq!(
            review_url(
                &answer("https://github.com/acme/site/pull/7/../../evil"),
                "acme/site"
            ),
            Some("https://github.com/acme/site/pull/7".to_owned())
        );
        // Notre préfixe sans nombre n'est pas une pull request.
        assert_eq!(
            review_url(
                &answer("https://github.com/acme/site/pull/new"),
                "acme/site"
            ),
            None
        );
    }

    // -- de bout en bout, contre le faux GitHub -------------------------------

    /// **Un article devient un fichier Markdown et une pull request** — et le
    /// brouillon en ressort `proposed`, pas `published`.
    #[tokio::test]
    async fn un_article_devient_un_fichier_et_une_pull_request_sans_etre_publie() {
        let Some(db) = db().await else { return };
        let (principal, _) = seed(&db).await;
        install_tool_policy(
            &db,
            principal.tenant_id,
            &[
                GET_FILE_CONTENTS,
                CREATE_BRANCH,
                CREATE_OR_UPDATE_FILE,
                CREATE_PULL_REQUEST,
            ],
        )
        .await;
        let repo = seed_repo(&db, &principal, None).await;
        let draft = seed_draft(&db, &principal, "Vérifier un visa par API").await;

        let github = FauxGithub::new("https://github.com/acme/site/pull/7");
        let effects = Effects::new(db.clone(), ports_calling(github.clone()), principal.clone());
        let gate = PolicyGate::new(db.clone());
        let when = DateTime::parse_from_rfc3339("2026-09-11T10:00:00Z")
            .expect("date")
            .with_timezone(&Utc);

        let proposal = propose(&effects, &gate, &repo, &draft, when)
            .await
            .expect("la proposition");

        // Quatre outils, dans cet ordre. La lecture vient **avant** la
        // branche : ce qui peut manquer manque avant que rien soit créé.
        assert_eq!(
            github.tools(),
            [
                GET_FILE_CONTENTS,
                CREATE_BRANCH,
                CREATE_OR_UPDATE_FILE,
                CREATE_PULL_REQUEST
            ]
        );

        let branch = format!("article/{}", draft.id.simple());
        let path = "content/blog/vérifier-un-visa-par-api.md";

        // La lecture regarde le chemin de l'article sur la branche qui sert le
        // site — la seule où un article fusionné peut être.
        assert_eq!(github.args(0)["path"], json!(path));
        assert_eq!(github.args(0)["ref"], json!("main"));

        // La branche part de celle qui sert le site, et porte le brouillon.
        assert_eq!(github.args(1)["owner"], json!("acme"));
        assert_eq!(github.args(1)["repo"], json!("site"));
        assert_eq!(github.args(1)["branch"], json!(branch));
        assert_eq!(github.args(1)["from_branch"], json!("main"));

        // Le fichier va dans le dossier du dépôt, sur la branche de l'article,
        // avec son en-tête — et **sans `sha`**, parce qu'il n'y avait rien à
        // remplacer.
        assert_eq!(github.args(2)["path"], json!(path));
        assert_eq!(github.args(2)["branch"], json!(branch));
        assert!(
            github.args(2)["sha"].is_null(),
            "rien n'était là à remplacer"
        );
        let written = github.args(2)["content"]
            .as_str()
            .expect("du texte")
            .to_owned();
        assert!(
            written.starts_with("---\ntitle: \"Vérifier un visa par API\"\ndate: 2026-09-11\n---"),
            "{written:?}"
        );
        assert!(written.contains("Le corps de l'article."), "{written:?}");

        // La demande va de la branche de l'article vers celle qui sert le site.
        assert_eq!(github.args(3)["head"], json!(branch));
        assert_eq!(github.args(3)["base"], json!("main"));

        assert_eq!(proposal.branch, branch);
        assert_eq!(proposal.path, path);
        assert_eq!(proposal.review_url, "https://github.com/acme/site/pull/7");

        // **Et ce n'est pas une publication.**
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tenant tx");
        let proposed = drafts::propose(&mut tx, draft.id, &proposal.review_url)
            .await
            .expect("propose")
            .expect("le brouillon existe");
        assert_eq!(proposed.state, "proposed");
        assert_eq!(
            proposed.review_url.as_deref(),
            Some(proposal.review_url.as_str())
        );
        assert!(
            proposed.url.is_none(),
            "une pull request n'est pas une adresse publique"
        );
        assert!(
            proposed.published_at.is_none(),
            "ni une date de publication"
        );

        // Corriger le texte ne le fait pas retomber en brouillon, et ne
        // republie rien.
        let corrected = drafts::update(
            &mut tx,
            draft.id,
            &drafts::Revision {
                title: "Vérifier un visa par API",
                body: "Le corps, corrigé.",
                url: None,
            },
        )
        .await
        .expect("update")
        .expect("le brouillon existe");
        assert_eq!(corrected.state, "proposed");

        // Un brouillon déjà proposé ne se repropose pas : ni en base…
        assert!(
            drafts::propose(&mut tx, draft.id, "https://github.com/acme/site/pull/8")
                .await
                .expect("propose")
                .is_none()
        );
        // …ni en `CHECK` : « proposé » sans adresse de relecture n'existe pas.
        let refused = sqlx::query("UPDATE content_drafts SET review_url = NULL WHERE id = $1")
            .bind(draft.id)
            .execute(&mut **tx)
            .await;
        assert!(
            refused.is_err(),
            "un `proposed` sans relecture a pu être écrit : le CHECK de 0102 a glissé"
        );
        drop(tx);

        // …et pas davantage dans le moteur, qui lit l'état avant de sortir.
        let err = propose(&effects, &gate, &repo, &corrected, when)
            .await
            .expect_err("un brouillon proposé ne se repropose pas");
        assert!(
            matches!(err, ProposeError::NotADraft(ref state) if state == "proposed"),
            "{err}"
        );
        assert_eq!(github.tools().len(), 4, "rien n'est reparti");

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **La Gate mord, et elle mord avant que quoi que ce soit parte.**
    ///
    /// Deux désarmements, parce qu'ils ne disent pas la même chose : sans aucun
    /// outil, rien ne sort du tout ; avec les trois premiers seulement, la
    /// branche et le fichier existent chez le client et la demande ne s'ouvre
    /// pas — ce qui est précisément pourquoi il y a quatre verdicts et pas un.
    #[tokio::test]
    async fn un_siege_sans_loutil_nouvre_aucune_pull_request() {
        let Some(db) = db().await else { return };
        let (principal, _) = seed(&db).await;
        install_tool_policy(&db, principal.tenant_id, &[]).await;
        let repo = seed_repo(&db, &principal, None).await;
        let draft = seed_draft(&db, &principal, "Un titre").await;
        let gate = PolicyGate::new(db.clone());
        let when = Utc::now();

        let github = FauxGithub::new("https://github.com/acme/site/pull/7");
        let effects = Effects::new(db.clone(), ports_calling(github.clone()), principal.clone());
        let err = propose(&effects, &gate, &repo, &draft, when)
            .await
            .expect_err("sans outil, rien ne part");
        assert!(matches!(err, ProposeError::Denied(_)), "{err}");
        assert!(
            github.calls().is_empty(),
            "la Gate doit refuser avant le port : {:?}",
            github.tools()
        );

        // Armée à moitié : les trois premiers passent, le quatrième est refusé.
        install_tool_policy(
            &db,
            principal.tenant_id,
            &[GET_FILE_CONTENTS, CREATE_BRANCH, CREATE_OR_UPDATE_FILE],
        )
        .await;
        let github = FauxGithub::new("https://github.com/acme/site/pull/7");
        let effects = Effects::new(db.clone(), ports_calling(github.clone()), principal.clone());
        let err = propose(&effects, &gate, &repo, &draft, when)
            .await
            .expect_err("sans le quatrième outil, la demande ne s'ouvre pas");
        assert!(matches!(err, ProposeError::Denied(_)), "{err}");
        assert_eq!(
            github.tools(),
            [GET_FILE_CONTENTS, CREATE_BRANCH, CREATE_OR_UPDATE_FILE]
        );

        // **Et le refus qui ne laisse rien** : sans la lecture, la Gate mord
        // au premier appel, donc aucune branche n'est créée chez le client.
        install_tool_policy(
            &db,
            principal.tenant_id,
            &[CREATE_BRANCH, CREATE_OR_UPDATE_FILE, CREATE_PULL_REQUEST],
        )
        .await;
        let github = FauxGithub::new("https://github.com/acme/site/pull/7");
        let effects = Effects::new(db.clone(), ports_calling(github.clone()), principal.clone());
        let err = propose(&effects, &gate, &repo, &draft, when)
            .await
            .expect_err("sans la lecture, rien ne part");
        assert!(matches!(err, ProposeError::Denied(_)), "{err}");
        assert!(
            github.calls().is_empty(),
            "un refus sur la lecture ne doit rien laisser chez le client : {:?}",
            github.tools()
        );

        // Le désarmement du désarmement : avec les quatre, ça passe.
        install_tool_policy(
            &db,
            principal.tenant_id,
            &[
                GET_FILE_CONTENTS,
                CREATE_BRANCH,
                CREATE_OR_UPDATE_FILE,
                CREATE_PULL_REQUEST,
            ],
        )
        .await;
        let github = FauxGithub::new("https://github.com/acme/site/pull/7");
        let effects = Effects::new(db.clone(), ports_calling(github.clone()), principal.clone());
        propose(&effects, &gate, &repo, &draft, when)
            .await
            .expect("avec les quatre outils, la proposition passe");

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// Un `isError` est une réponse réussie qui dit non : elle arrête la suite
    /// plutôt que d'ouvrir une demande sur une branche qui n'existe pas.
    #[tokio::test]
    async fn un_refus_de_github_arrete_la_suite() {
        let Some(db) = db().await else { return };
        let (principal, _) = seed(&db).await;
        install_tool_policy(
            &db,
            principal.tenant_id,
            &[
                GET_FILE_CONTENTS,
                CREATE_BRANCH,
                CREATE_OR_UPDATE_FILE,
                CREATE_PULL_REQUEST,
            ],
        )
        .await;
        let repo = seed_repo(&db, &principal, None).await;
        let draft = seed_draft(&db, &principal, "Un titre").await;
        let gate = PolicyGate::new(db.clone());

        let github = FauxGithub::refusing("https://github.com/acme/site/pull/7", CREATE_BRANCH);
        let effects = Effects::new(db.clone(), ports_calling(github.clone()), principal.clone());
        let err = propose(&effects, &gate, &repo, &draft, Utc::now())
            .await
            .expect_err("la branche n'a pas été créée");
        assert!(matches!(err, ProposeError::Refused(CREATE_BRANCH)), "{err}");
        assert_eq!(
            github.tools(),
            [GET_FILE_CONTENTS, CREATE_BRANCH],
            "rien n'a suivi"
        );

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **Republier un article corrigé.** Le trou du `docs/CONTENU.md` § 7, et
    /// ses deux moitiés.
    ///
    /// Le chemin exact mesuré la veille : proposer, faire fusionner, puis
    /// proposer un second brouillon **du même titre**. [`file_stem`] rend le
    /// même chemin, la branche part de celle qui sert le site — qui porte
    /// désormais le fichier — et `create-or-update-file` refusait faute de
    /// `sha`, en laissant une branche orpheline chez le client.
    ///
    /// Ce que ce test tient : le `sha` du fichier en place part avec
    /// l'écriture, la pull request s'ouvre, et **la lecture passe avant la
    /// branche** — donc le cas qui échouait n'a plus rien à nettoyer.
    #[tokio::test]
    async fn republier_un_article_corrige_porte_le_sha_de_celui_quil_remplace() {
        let Some(db) = db().await else { return };
        let (principal, _) = seed(&db).await;
        install_tool_policy(
            &db,
            principal.tenant_id,
            &[
                GET_FILE_CONTENTS,
                CREATE_BRANCH,
                CREATE_OR_UPDATE_FILE,
                CREATE_PULL_REQUEST,
            ],
        )
        .await;
        let repo = seed_repo(&db, &principal, None).await;
        // Le même titre que celui qui est déjà fusionné : c'est tout ce qu'il
        // faut pour retomber sur le même chemin.
        let second = seed_draft(&db, &principal, "Vérifier un visa par API").await;
        let gate = PolicyGate::new(db.clone());
        let when = Utc::now();

        let github = FauxGithub::holding("https://github.com/acme/site/pull/9", HELD_SHA);
        let effects = Effects::new(db.clone(), ports_calling(github.clone()), principal.clone());
        let proposal = propose(&effects, &gate, &repo, &second, when)
            .await
            .expect("un article corrigé se repropose");

        assert_eq!(
            github.tools(),
            [
                GET_FILE_CONTENTS,
                CREATE_BRANCH,
                CREATE_OR_UPDATE_FILE,
                CREATE_PULL_REQUEST
            ]
        );
        // Le même chemin qu'avant, et le `sha` de ce qui est là.
        assert_eq!(proposal.path, "content/blog/vérifier-un-visa-par-api.md");
        assert_eq!(github.args(0)["path"], json!(proposal.path));
        assert_eq!(github.args(2)["sha"], json!(HELD_SHA));
        assert_eq!(proposal.review_url, "https://github.com/acme/site/pull/9");

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **Un `sha` est la seule chose qu'on prenne d'un étranger, et sa forme
    /// est le garde-fou.**
    ///
    /// Quarante chiffres hexadécimaux, ou rien. Ce qui est refusé ne fait pas
    /// écrire ailleurs — le chemin et la branche viennent de nous — ça repart
    /// en création, et GitHub refuse ce qu'il a à refuser.
    #[test]
    fn un_sha_qui_nen_est_pas_un_ne_sort_pas_de_la_reponse() {
        let said = |value: serde_json::Value| tool_result(value.to_string(), false);

        assert_eq!(
            blob_sha(&said(json!({ "sha": HELD_SHA }))),
            Some(HELD_SHA.to_owned())
        );
        // Trop court, trop long, pas hexadécimal, pas une chaîne, absent.
        assert_eq!(blob_sha(&said(json!({ "sha": "9f1c0a7b" }))), None);
        assert_eq!(
            blob_sha(&said(json!({ "sha": format!("{HELD_SHA}0") }))),
            None
        );
        assert_eq!(
            blob_sha(&said(
                json!({ "sha": "../../../etc/passwd zzzzzzzzzzzzzzzzzzzzzzz" })
            )),
            None
        );
        assert_eq!(blob_sha(&said(json!({ "sha": 7 }))), None);
        assert_eq!(blob_sha(&said(json!({ "name": "un.md" }))), None);
        // Et une réponse qui n'a pas la forme d'un `CallToolResult`.
        assert_eq!(blob_sha(&json!({ "sha": HELD_SHA })), None);
        assert_eq!(
            blob_sha(&tool_result("pas du JSON".to_owned(), false)),
            None
        );
    }

    /// Un dépôt est une ressource **d'un siège**, et un voisin n'en voit rien.
    #[tokio::test]
    async fn un_depot_appartient_a_un_siege_et_pas_au_voisin() {
        let Some(db) = db().await else { return };
        let (a, _) = seed(&db).await;
        let (b, _) = seed(&db).await;
        let mine = seed_repo(&db, &a, None).await;
        assert_eq!(mine.repo, "acme/site");

        let mut tx = db.tenant_tx(b.tenant_id).await.expect("tenant tx");
        assert!(repos::list(&mut tx).await.expect("list").is_empty());
        assert!(
            repos::of(&mut tx, a.employee_id.as_uuid())
                .await
                .expect("of")
                .is_none()
        );
        // Et il ne peut pas s'en poser un sur le branchement du voisin : rien
        // n'est branché sous ce handle **chez lui**.
        assert!(
            repos::set(
                &mut tx,
                b.employee_id.as_uuid(),
                HANDLE,
                "autre/site",
                "main",
                "content",
                None,
            )
            .await
            .expect("set")
            .is_none()
        );
        tx.commit().await.expect("commit");

        // **Et même branché, il ne peut pas écrire sur le siège d'en face.**
        // La clé étrangère vers `employees` est vérifiée hors de la RLS : sans
        // la lecture que `set` fait, cette ligne passerait, et le vrai
        // propriétaire du siège ne pourrait plus poser la sienne.
        let mut tx = db.tenant_tx(b.tenant_id).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector) \
             VALUES ($1, $2, 'https://api.githubcopilot.com/mcp/', 'public', 'github')",
        )
        .bind(b.tenant_id.as_uuid())
        .bind(HANDLE)
        .execute(&mut **tx)
        .await
        .expect("insert binding");
        let stolen = repos::set(
            &mut tx,
            a.employee_id.as_uuid(),
            HANDLE,
            "voleur/site",
            "main",
            "content",
            None,
        )
        .await;
        assert!(
            matches!(stolen, Err(agentos_store::db::StoreError::NotFound)),
            "un voisin a pu écrire sur le siège d'en face"
        );
        tx.commit().await.expect("commit");

        // Le désarmement : chez lui, il est là, et il se remplace.
        let mut tx = db.tenant_tx(a.tenant_id).await.expect("tenant tx");
        assert_eq!(repos::list(&mut tx).await.expect("list").len(), 1);
        let moved = repos::set(
            &mut tx,
            a.employee_id.as_uuid(),
            HANDLE,
            "acme/nouveau-site",
            "trunk",
            "src/pages/blog",
            Some("blog.acme.example"),
        )
        .await
        .expect("set")
        .expect("le branchement existe");
        assert_eq!(moved.repo, "acme/nouveau-site");
        assert_eq!(moved.site.as_deref(), Some("blog.acme.example"));
        assert_eq!(
            repos::list(&mut tx).await.expect("list").len(),
            1,
            "un siège, un dépôt"
        );
        // Et les formes que `0102` refuse sortent en erreur, pas en ligne.
        assert!(
            repos::set(
                &mut tx,
                a.employee_id.as_uuid(),
                HANDLE,
                "acme/site",
                "main",
                "../../etc",
                None,
            )
            .await
            .is_err(),
            "un dossier qui remonte a été accepté : le CHECK de 0102 a glissé"
        );
        drop(tx);

        drop_tenant(&db, a.tenant_id).await;
        drop_tenant(&db, b.tenant_id).await;
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
}
