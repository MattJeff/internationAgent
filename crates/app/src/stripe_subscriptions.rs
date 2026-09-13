//! Lire chez Stripe le revenu d'abonnement — celui qu'aucune table d'ici ne
//! peut porter — et ne rien lui écrire, jamais.
//!
//! # Le fait mesuré qui commande ce module
//!
//! `crates/app/src/stripe.rs`, une porte plus loin, **règle** une facture que
//! nous avons déjà écrite : une livraison signée nomme
//! `metadata.invoice_number`, la facture de ce numéro existe chez nous, et elle
//! passe à payée. Elle n'en crée aucune, et elle ne le peut pas :
//! `invoices.opportunity_id` est `NOT NULL` (0066) et
//! `opportunities_won_needs_approval` (0011) refuse un `closed_won` sans
//! `approval_id`. **Un euro ne peut pas entrer dans ce registre sans qu'un
//! humain ait approuvé une affaire.**
//!
//! Orizn vend en libre-service. Un abonnement à 49 $ pris par carte à 3 h du
//! matin n'a ni affaire, ni devis, ni approbation, donc pas de facture, donc
//! rien dans `GET /v1/growth`. Ce module est la lecture qui manquait, et
//! `migrations/0108_une_recette_dabonnement_a_sa_propre_cle.sql` argumente la
//! clé qu'elle emploie.
//!
//! **Ce ne sont pas les mêmes euros vus autrement, ce sont deux vérités.** Le
//! registre de factures dit ce que la société a *réclamé* et ce qui est
//! *rentré* dessus ; Stripe dit ce qui *tourne* aujourd'hui. Les mélanger
//! compterait deux fois une entreprise qui fait les deux, et ce dépôt refuse
//! ce mélange partout ailleurs. La route les rend côte à côte, jamais sommés.
//!
//! # Lecture seule, et prouvée trois fois plutôt que promise
//!
//! Le fondateur donnera une **clé restreinte**. C'est une promesse de Stripe,
//! côté Stripe, et elle ne dit rien de ce que ce binaire ferait d'une clé qui
//! ne le serait pas. Alors :
//!
//! 1. **Une seule fonction touche le client HTTP** — [`StripeRead::get`] — et
//!    elle appelle `reqwest::Client::get`. Il n'y a aucune autre méthode dans
//!    ce fichier qui ait accès à `self.http`, donc écrire demanderait d'en
//!    ajouter une.
//! 2. **Un test lit ce fichier** et échoue si `.post(`, `.put(`, `.patch(` ou
//!    `.delete(` y apparaissent
//!    ([`aucune_ecriture_ne_peut_apparaitre_dans_ce_fichier`]). C'est le geste
//!    que `browser_http` fait en prose (« quatre pas servis, le reste refusé »)
//!    rejoué par une assertion.
//! 3. **Le faux Stripe des tests refuse tout ce qui n'est pas un `GET`** et
//!    enregistre la méthode de chaque requête ; les tests affirment que la
//!    liste ne contient que `GET`.
//!
//! Aucun remboursement, aucune annulation, aucune modification d'abonnement
//! n'est atteignable d'ici, même avec une clé secrète complète collée par
//! erreur.
//!
//! # Les deux questions, les deux sources, et pourquoi elles diffèrent
//!
//! * **Ce qui tourne** — `GET /v1/subscriptions` : les abonnements vivants,
//!   leur prix, leur palier. C'est l'état d'aujourd'hui, sans fenêtre.
//! * **Ce qui a bougé** — `GET /v1/events` : les `customer.subscription.created`
//!   et `customer.subscription.deleted` de la fenêtre.
//!
//! Pourquoi pas la même source pour les deux : la liste d'abonnements se filtre
//! sur `created` mais **pas** sur `canceled_at`, donc « qui est parti cette
//! semaine » n'y est pas une question qu'on puisse poser — il faudrait lire
//! tous les abonnements annulés depuis toujours pour en garder trois. Les
//! événements la posent directement. Le prix est qu'ils ne remontent pas plus
//! loin que [`EVENT_RETENTION_DAYS`] : au-delà, [`Subscriptions::started`] et
//! [`Subscriptions::stopped`] sont `None`, **jamais zéro**.
//!
//! # Ce que ce module ne fait pas
//!
//! **Il ne garde rien.** Pas de table de cliché, pas de boucle de
//! rafraîchissement, pas de colonne « lu à ». L'argument est dans l'en-tête de
//! 0108 et il tient en une phrase : un cliché serait un second endroit où
//! « notre recette » peut être vraie.
//!
//! **Il ne convertit aucune monnaie.** Si les abonnements comptés n'emploient
//! pas tous le même code ISO, le MRR total est `None` — la règle de
//! `RevenueView` dans `routes::growth`, et celle de `Ledger` dans `routes::pnl`.
//! Les paliers, eux, gardent chacun le leur : un palier ne somme rien à travers
//! deux codes, il n'en porte qu'un.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use agentos_domain::ids::TenantId;
use agentos_providers::Secret;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::mcp::Credentials;
use crate::model_access::ApiBase;

/// La racine de l'API Stripe. [`StripeRead::with_base_url`] la déplace pour les
/// tests, et pour un déploiement derrière un mandataire de sortie.
pub const API_BASE: &str = "https://api.stripe.com/v1";

/// Plafond dur d'une requête, connexion comprise.
///
/// Dix secondes, et pas les soixante des adaptateurs de fournisseur : cette
/// lecture est **dans le chemin d'un écran**. `GET /v1/growth` fait déjà neuf
/// requêtes Postgres ; un tiers qui met une minute à répondre ne doit pas être
/// une minute d'attente pour quelqu'un qui regarde son entonnoir. Passé ce
/// délai la réponse est `null` et non une erreur — voir [`StripeError`].
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Lignes demandées par page. Le maximum que Stripe accorde.
pub const PAGE_SIZE: usize = 100;

/// Pages lues au plus, par question.
///
/// ponytail : un refus, pas une boucle infinie. Mille abonnements, c'est dix
/// allers-retours dans le chemin d'un écran, et une entreprise qui les dépasse
/// veut un cliché rafraîchi hors du chemin plutôt qu'un écran à trente
/// secondes. Le plafond atteint rend [`StripeError::TooMany`], donc `null` :
/// **sous-compter en silence serait un mensonge, l'absence n'en est pas un.**
pub const MAX_PAGES: usize = 10;

/// Jusqu'où les événements de Stripe remontent.
///
/// Trente jours, la rétention que Stripe annonce pour `GET /v1/events`.
/// Au-delà, ce module ne demande pas — une réponse tronquée par une rétention
/// est un compte faux, et un compte faux est pire qu'un `null`.
///
/// La fenêtre par défaut de `GET /v1/growth` est de trente jours : le cas
/// courant tient, et c'est le seul qu'il fallait faire tenir.
pub const EVENT_RETENTION_DAYS: i64 = 30;

/// Les états d'abonnement qui comptent comme un abonné payant.
///
/// `active` est l'évidence. `past_due` est le choix, et il est discutable dans
/// les deux sens : c'est un abonnement dont un paiement a échoué et que Stripe
/// relance encore. L'exclure ferait *chuter le MRR le jour d'un refus de carte*
/// et remonter trois jours plus tard, ce qu'un fondateur lit comme une
/// résiliation qui n'a pas eu lieu. L'inclure surestime la recette de ceux qui
/// finiront par partir. On inclut, et `unmeasured` le dit.
///
/// Ce qui est dehors : `trialing` (il ne paie pas encore), `paused`,
/// `incomplete`, `incomplete_expired`, `unpaid` et `canceled`.
pub const COUNTED_STATUSES: [&str; 2] = ["active", "past_due"];

/// Pourquoi une lecture n'a rien rendu.
///
/// Quatre codes et pas un de plus : ils existent pour la ligne de journal d'un
/// opérateur, pas pour la réponse. L'écran, lui, ne voit qu'un `null` — un
/// `subscriptions: 0` sur une panne de Stripe serait une faillite affichée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StripeError {
    /// Stripe a refusé la clé : 401 ou 403. Révoquée, expirée, ou restreinte au
    /// point de ne pas lire les abonnements.
    #[error("stripe refused the key")]
    Refused,
    /// Stripe n'a pas répondu, ou a répondu 429 ou 5xx. Réessayable, et
    /// personne ne réessaie ici : l'écran suivant est la nouvelle tentative.
    #[error("stripe did not answer")]
    Unavailable,
    /// Stripe a répondu quelque chose que ce build ne sait pas lire.
    #[error("stripe answered a shape this build cannot read")]
    Unreadable,
    /// Plus d'abonnements que [`MAX_PAGES`] ne peut en lire.
    #[error("more subscriptions than one screen may read")]
    TooMany,
}

impl StripeError {
    /// L'étiquette d'une ligne de journal. Cardinalité fermée.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Refused => "stripe_key_refused",
            Self::Unavailable => "stripe_unavailable",
            Self::Unreadable => "stripe_unreadable",
            Self::TooMany => "stripe_too_many_subscriptions",
        }
    }
}

// ---------------------------------------------------------------------------
// Ce qui est rendu
// ---------------------------------------------------------------------------

/// Un palier, tel que Stripe le nomme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier {
    /// L'identifiant du prix (`price_…`). C'est la seule chose qui identifie un
    /// palier de façon stable : un libellé se réécrit, un montant change.
    pub price_id: String,
    /// `price.nickname`, le nom que l'entreprise a donné à ce prix dans son
    /// tableau de bord. `None` quand personne ne l'a nommé — et alors c'est
    /// `price_id` qui s'affiche, plutôt qu'un « Palier 2 » inventé ici.
    pub label: Option<String>,
    /// Le code ISO de ce prix, en minuscules comme Stripe l'écrit.
    pub currency: String,
    /// Les abonnements comptés qui portent ce prix. **La somme des paliers peut
    /// dépasser [`Subscriptions::subscribers`]** : un abonnement à deux lignes
    /// est un abonné dans deux paliers.
    pub subscribers: i64,
    /// Ce que ce palier rapporte par mois, en unités mineures. `None` quand un
    /// des prix du palier n'a pas de montant unitaire (tarification par paliers
    /// ou à l'usage), parce qu'un montant qu'on ne peut pas lire n'est pas zéro.
    pub mrr_minor: Option<i64>,
}

/// Ce que Stripe dit du revenu récurrent d'une entreprise, à l'instant de la
/// lecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscriptions {
    /// Le revenu mensuel récurrent, en unités mineures. `None` quand les
    /// abonnements comptés n'emploient pas une seule monnaie : rien ici ne somme
    /// à travers deux codes ISO.
    pub mrr_minor: Option<i64>,
    /// La monnaie de [`Self::mrr_minor`], `None` avec lui.
    pub currency: Option<String>,
    /// Les abonnements dans un état de [`COUNTED_STATUSES`].
    pub subscribers: i64,
    /// Les abonnements nés dans la fenêtre. `None` — jamais zéro — quand la
    /// fenêtre déborde [`EVENT_RETENTION_DAYS`].
    pub started: Option<i64>,
    /// Les abonnements résiliés dans la fenêtre, même règle.
    pub stopped: Option<i64>,
    /// `true` quand au moins un montant n'a pas pu être lu : le MRR rendu est
    /// alors un **plancher**. Le drapeau de `GET /v1/pnl` (`cost_is_floor`),
    /// pour la même raison.
    pub mrr_is_floor: bool,
    /// Un palier par prix, le plus gros d'abord.
    pub tiers: Vec<Tier>,
    /// Quand cette lecture a été faite. Elle n'est pas gardée, donc c'est
    /// toujours « il y a un instant » — la colonne existe pour que la console
    /// puisse le dire plutôt que de le laisser croire d'un cliché.
    pub read_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Les formes du fil, telles que Stripe les documente
// ---------------------------------------------------------------------------
//
// Tous les champs sont optionnels ou par défaut : un objet Stripe porte
// cinquante clés dont on en lit six, et un champ qui disparaît d'une version
// d'API ne doit pas rendre la réponse entière illisible. Ce qui est refusé,
// c'est une *enveloppe* qu'on ne sait pas lire, pas un champ manquant.

/// Une page de liste Stripe : `{ "object": "list", "data": [...], "has_more": bool }`.
#[derive(Debug, Deserialize)]
struct Page<T> {
    // `default = "Vec::new"` et non `default` : sur un champ générique, le
    // dérivé de serde exigerait `T: Default`, que les objets Stripe n'ont pas.
    #[serde(default = "Vec::new")]
    data: Vec<T>,
    #[serde(default)]
    has_more: bool,
}

/// Un abonnement, réduit à ce qui sert.
#[derive(Debug, Deserialize)]
struct Subscription {
    id: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    items: Items,
}

/// `subscription.items`, une liste comme les autres.
#[derive(Debug, Default, Deserialize)]
struct Items {
    #[serde(default)]
    data: Vec<Item>,
    /// Un abonnement de plus de dix lignes pagine. Ce module ne va pas chercher
    /// la suite — il marque le MRR comme plancher, ce qui est vrai et coûte une
    /// ligne au lieu d'une seconde boucle de pagination imbriquée.
    #[serde(default)]
    has_more: bool,
}

/// Une ligne d'abonnement.
#[derive(Debug, Deserialize)]
struct Item {
    /// Combien de fois ce prix. Absent sur les prix à l'usage, où il vaut un.
    #[serde(default = "one")]
    quantity: i64,
    price: Option<Price>,
}

/// Le prix d'une ligne.
#[derive(Debug, Deserialize)]
struct Price {
    id: String,
    #[serde(default)]
    currency: String,
    #[serde(default)]
    nickname: Option<String>,
    /// `None` sur une tarification par paliers ou à l'usage : le montant dépend
    /// de la consommation et n'est pas sur le prix.
    #[serde(default)]
    unit_amount: Option<i64>,
    /// `None` sur un prix ponctuel. Un abonnement n'en porte pas, en principe ;
    /// s'il en porte un, il ne rapporte rien de récurrent et ne compte pas.
    #[serde(default)]
    recurring: Option<Recurring>,
}

/// La récurrence d'un prix.
#[derive(Debug, Deserialize)]
struct Recurring {
    /// `day`, `week`, `month` ou `year`.
    #[serde(default)]
    interval: String,
    #[serde(default = "one")]
    interval_count: i64,
}

/// Un événement, réduit au type et à l'objet qu'il porte.
#[derive(Debug, Deserialize)]
struct Event {
    /// Le curseur de pagination des événements, comme `Subscription::id` est
    /// celui des abonnements.
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    data: EventData,
}

#[derive(Debug, Default, Deserialize)]
struct EventData {
    #[serde(default)]
    object: EventObject,
}

#[derive(Debug, Default, Deserialize)]
struct EventObject {
    #[serde(default)]
    id: String,
}

/// Le défaut de `quantity` et d'`interval_count`.
const fn one() -> i64 {
    1
}

/// L'événement d'une souscription qui commence.
const STARTED: &str = "customer.subscription.created";
/// Celui d'une souscription qui s'arrête pour de bon. `updated` ne compte pas :
/// une résiliation programmée en fin de période est un `updated` aujourd'hui et
/// un `deleted` le jour où elle prend effet, et compter le premier ferait partir
/// deux fois quelqu'un qui n'est pas encore parti.
const STOPPED: &str = "customer.subscription.deleted";

// ---------------------------------------------------------------------------
// L'arithmétique, et elle est pure
// ---------------------------------------------------------------------------

/// Ce qu'une ligne rapporte par mois, en unités mineures.
///
/// `None` quand le montant manque, quand l'intervalle n'est pas un des quatre
/// que Stripe emploie, ou quand `interval_count` est absurde — et un `None` ici
/// devient [`Subscriptions::mrr_is_floor`], jamais un zéro.
///
/// Les trois conversions ne sont pas exactes et ne peuvent pas l'être : un
/// abonnement annuel de 1 200 $ ne « fait » pas 100 $ par mois, il fait
/// 1 200 $ une fois. Le douzième est la convention universelle du MRR ; la
/// semaine passe par 52/12 et le jour par 365/12, qui sont les mêmes
/// approximations d'un cran plus fines. L'arrondi est au plus proche, à
/// l'unité mineure, et il est nommé dans `unmeasured`.
fn monthly_minor(unit_amount: i64, quantity: i64, recurring: &Recurring) -> Option<i64> {
    if quantity < 0 || recurring.interval_count <= 0 {
        return None;
    }
    // Numérateur et dénominateur d'un mois, exprimés dans l'unité de
    // l'intervalle. En i128 : 100 000 abonnés d'un prix à 999 999 $ par jour
    // déborderait un i64 avant la division, et un débordement silencieux serait
    // une recette inventée.
    let (numerator, denominator): (i128, i128) = match recurring.interval.as_str() {
        "month" => (1, i128::from(recurring.interval_count)),
        "year" => (1, 12 * i128::from(recurring.interval_count)),
        "week" => (52, 12 * i128::from(recurring.interval_count)),
        "day" => (365, 12 * i128::from(recurring.interval_count)),
        _ => return None,
    };
    let total = i128::from(unit_amount) * i128::from(quantity) * numerator;
    // Arrondi au plus proche, en gardant le signe : un montant négatif n'a rien
    // à faire sur un abonnement, mais une division tronquée vers zéro sur un
    // nombre négatif est le genre de détail qui ne se voit jamais.
    let rounded = if total >= 0 {
        (total + denominator / 2) / denominator
    } else {
        (total - denominator / 2) / denominator
    };
    i64::try_from(rounded).ok()
}

/// Les abonnements et les événements, réduits à ce que l'écran lit.
///
/// Pure et séparée des requêtes pour la raison que `routes::growth::funnel` et
/// `forecast::assemble` donnent des leurs : c'est toute la logique, et les deux
/// pièges qu'elle évite — la monnaie unique, et un abonnement à deux lignes qui
/// serait deux abonnés — ne se voient qu'en la refaisant à la main.
fn summarise(
    subscriptions: &[Subscription],
    events: Option<&[Event]>,
    read_at: DateTime<Utc>,
) -> Subscriptions {
    let mut subscribers = 0_i64;
    let mut is_floor = false;
    let mut currencies: BTreeSet<String> = BTreeSet::new();
    // price_id -> (libellé, monnaie, abonnés, mrr, plancher)
    let mut tiers: BTreeMap<String, (Option<String>, String, i64, i64, bool)> = BTreeMap::new();
    let mut total: i128 = 0;

    for subscription in subscriptions {
        if !COUNTED_STATUSES.contains(&subscription.status.as_str()) {
            continue;
        }
        subscribers += 1;
        // Une facture d'abonnement plus longue qu'une page : ce qu'on a lu est
        // un début, donc le total est un plancher.
        is_floor |= subscription.items.has_more;
        for item in &subscription.items.data {
            let Some(price) = &item.price else {
                is_floor = true;
                continue;
            };
            // Un prix sans récurrence sur un abonnement ne rapporte rien de
            // récurrent : il ne compte ni dans un palier ni dans le total, et
            // il ne rend pas le total plancher non plus.
            let Some(recurring) = &price.recurring else {
                continue;
            };
            let monthly = price
                .unit_amount
                .and_then(|amount| monthly_minor(amount, item.quantity, recurring));
            currencies.insert(price.currency.clone());
            let tier = tiers
                .entry(price.id.clone())
                .or_insert_with(|| (price.nickname.clone(), price.currency.clone(), 0, 0, false));
            tier.2 += 1;
            match monthly {
                Some(minor) => {
                    tier.3 += minor;
                    total += i128::from(minor);
                }
                None => {
                    tier.4 = true;
                    is_floor = true;
                }
            }
        }
    }

    // Une seule monnaie, ou rien : la règle de `RevenueView`, mot pour mot.
    let currency = match currencies.len() {
        1 => currencies.iter().next().cloned(),
        _ => None,
    };
    // Pas de monnaie : pas de montant. C'est le cas d'un locataire sans
    // abonnement compté, et c'est celui d'un registre à deux monnaies — les
    // deux rendent `None` et aucun ne rend zéro.
    let mrr_minor = currency.as_ref().and_then(|_| i64::try_from(total).ok());

    let mut tiers: Vec<Tier> = tiers
        .into_iter()
        .map(
            |(price_id, (label, currency, subscribers, mrr, floor))| Tier {
                price_id,
                label,
                currency,
                subscribers,
                mrr_minor: (!floor).then_some(mrr),
            },
        )
        .collect();
    // Le plus gros d'abord, l'identifiant pour départager : deux appels
    // identiques rendent deux réponses identiques.
    tiers.sort_by(|a, b| {
        b.mrr_minor
            .cmp(&a.mrr_minor)
            .then_with(|| b.subscribers.cmp(&a.subscribers))
            .then_with(|| a.price_id.cmp(&b.price_id))
    });

    // Un identifiant d'abonnement peut apparaître deux fois dans les événements
    // — Stripe rejoue une livraison, et une entreprise qui reprend un abonnement
    // résilié en produit un second `created`. Ce sont des **abonnements** qu'on
    // compte, pas des événements.
    let counted = |kind: &str| {
        events.map(|events| {
            events
                .iter()
                .filter(|event| event.kind == kind)
                .map(|event| event.data.object.id.as_str())
                .collect::<BTreeSet<_>>()
                .len() as i64
        })
    };

    Subscriptions {
        mrr_minor,
        currency,
        subscribers,
        started: counted(STARTED),
        stopped: counted(STOPPED),
        mrr_is_floor: is_floor,
        tiers,
        read_at,
    }
}

// ---------------------------------------------------------------------------
// Le client, et il ne sait que lire
// ---------------------------------------------------------------------------

/// Une clé Stripe, et les deux questions qu'on lui pose.
///
/// Construit par appel plutôt que gardé : la clé vit dans une colonne scellée,
/// s'ouvre le temps d'un écran, et meurt avec ce client. Rien ici n'est un
/// `ProviderBinding` — il n'y a pas de port à deux implémentations, il y a une
/// API et un `GET`. La même raison que `crates/app/src/peer_keys.rs` donne
/// d'un `GET` sortant depuis cette caisse plutôt que derrière un port.
#[derive(Debug)]
pub struct StripeRead {
    http: reqwest::Client,
    base_url: String,
    api_key: Secret,
}

impl StripeRead {
    /// Un client sur la clé d'un locataire.
    ///
    /// Rien n'atteint le réseau ici.
    #[must_use]
    pub fn new(api_key: Secret) -> Self {
        Self {
            // Construit plutôt que `new()`, pour `REQUEST_TIMEOUT` : `reqwest`
            // n'a pas de délai de requête par défaut, et un tiers qui ne répond
            // jamais serait un écran qui ne se charge jamais.
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: API_BASE.to_owned(),
            api_key,
        }
    }

    /// Pointer le client ailleurs. Pour les tests hermétiques.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    /// **La seule fonction de ce fichier qui touche le réseau, et elle fait un
    /// `GET`.**
    ///
    /// C'est la première des trois preuves de l'en-tête : écrire chez Stripe
    /// depuis ce module demanderait d'ajouter une méthode ici, ce qu'un test et
    /// une relecture verraient tous les deux.
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, StripeError> {
        let response = self
            .http
            .get(format!("{}{path}", self.base_url))
            .bearer_auth(self.api_key.expose_for_transport())
            .query(query)
            .send()
            .await
            .map_err(|_| StripeError::Unavailable)?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(StripeError::Refused);
        }
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(StripeError::Unavailable);
        }
        if !status.is_success() {
            return Err(StripeError::Unreadable);
        }
        response.json().await.map_err(|_| StripeError::Unreadable)
    }

    /// Une page après l'autre, jusqu'à [`MAX_PAGES`].
    ///
    /// `starting_after` est le curseur de Stripe : l'identifiant de la dernière
    /// ligne rendue. Une page vide avec `has_more` est une boucle qui ne finit
    /// pas, donc elle finit ici.
    async fn all<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
        id_of: impl Fn(&T) -> &str,
    ) -> Result<Vec<T>, StripeError> {
        let mut out: Vec<T> = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut page_query: Vec<(&str, String)> = query.to_vec();
            page_query.push(("limit", PAGE_SIZE.to_string()));
            if let Some(cursor) = &after {
                page_query.push(("starting_after", cursor.clone()));
            }
            let page: Page<T> = self.get(path, &page_query).await?;
            let last = page.data.last().map(|row| id_of(row).to_owned());
            out.extend(page.data);
            match (page.has_more, last) {
                (true, Some(cursor)) => after = Some(cursor),
                _ => return Ok(out),
            }
        }
        // Le plafond atteint : on a lu mille lignes et il en reste. Refuser
        // plutôt que rendre un compte qu'on sait faux.
        Err(StripeError::TooMany)
    }

    /// Une lecture d'une ligne, pour prouver que la clé lit.
    ///
    /// Ce que `POST /v1/growth/stripe` appelle avant d'écrire quoi que ce soit,
    /// et ce que `POST /v1/model` fait une porte plus loin avec sa propre
    /// sonde : une clé rangée sans être prouvée est un écran qui dit
    /// « connecté » et un `null` le lendemain.
    ///
    /// Ce que ça prouve : cette clé authentifie, et elle a le droit de lire les
    /// abonnements. Ce que ça ne prouve pas : qu'elle soit restreinte, qu'elle
    /// le reste, ni qu'elle lise les événements — `GET /v1/events` est une
    /// permission distincte dans Stripe, et une clé qui n'y a pas droit rend
    /// simplement `started` et `stopped` absents plus tard.
    pub async fn probe(&self) -> Result<(), StripeError> {
        let _: Page<Subscription> = self
            .get("/subscriptions", &[("limit", "1".to_owned())])
            .await?;
        Ok(())
    }

    /// Le revenu d'abonnement, à l'instant présent, et ce qui a bougé depuis
    /// `window_start`.
    ///
    /// Deux requêtes paginées au plus. Les événements ne sont demandés que si la
    /// fenêtre tient dans [`EVENT_RETENTION_DAYS`] ; sinon `started` et
    /// `stopped` sont `None` et aucune requête n'est faite pour eux.
    ///
    /// Une clé qui lit les abonnements mais pas les événements rend la même
    /// chose : le refus des événements n'annule pas la lecture qui a réussi.
    pub async fn read(
        &self,
        window_start: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Subscriptions, StripeError> {
        let mut subscriptions: Vec<Subscription> = Vec::new();
        for status in COUNTED_STATUSES {
            subscriptions.extend(
                self.all::<Subscription>(
                    "/subscriptions",
                    &[("status", status.to_owned())],
                    |row| &row.id,
                )
                .await?,
            );
        }

        let reachable = now - window_start <= chrono::Duration::days(EVENT_RETENTION_DAYS);
        let events = if reachable {
            self.all::<Event>(
                "/events",
                &[
                    ("types[]", STARTED.to_owned()),
                    ("types[]", STOPPED.to_owned()),
                    ("created[gte]", window_start.timestamp().to_string()),
                ],
                // L'identifiant de l'événement, pas celui de l'abonnement : le
                // curseur de Stripe est celui de la ligne rendue.
                |row| &row.id,
            )
            .await
            .ok()
        } else {
            None
        };

        Ok(summarise(&subscriptions, events.as_deref(), now))
    }
}

// ---------------------------------------------------------------------------
// La clé : scellée après preuve, ouverte le temps d'un écran
// ---------------------------------------------------------------------------

/// Le contexte de chiffrement sous lequel la clé Stripe d'un locataire est
/// scellée.
///
/// Un locataire, un compte Stripe, donc l'identifiant du locataire suffit — la
/// forme de `model_access::model_context`, et pour la même raison :
/// `tenant_stripe_access` a une clé primaire d'une colonne précisément pour
/// qu'un second compte ne soit pas représentable.
///
/// Le schéma `stripe://` est le **cinquième** espace de clés du dépôt, après
/// `secret://`, `mcp://`, `model://` et celui de `crate::oauth`. Ce que la
/// disjonction achète, concrètement : les colonnes scellées d'un même locataire
/// sont à un `UPDATE … SELECT` les unes des autres pour qui peut écrire les
/// tables, l'AAD du locataire ne les sépare pas (elles lui appartiennent
/// toutes), et une clé d'API de modèle déplacée dans cette colonne partirait
/// chez Stripe en `Authorization: Bearer`. Le contexte est la seule chose qui
/// l'empêche.
fn stripe_context(tenant_id: TenantId) -> String {
    format!("stripe://{tenant_id}")
}

/// Pourquoi une clé n'a pas été rangée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// Le corps portait une chaîne vide. Un formulaire qui poste `""` pour un
    /// champ qu'on n'a pas touché est la façon la plus courante de ranger une
    /// clé qui n'en est pas une.
    #[error("an empty string is not a key")]
    Blank,
    /// Stripe a refusé, ou n'a pas répondu. La clé n'est **pas** rangée.
    #[error(transparent)]
    Stripe(#[from] StripeError),
    /// Le chiffre n'a pas scellé. Une clé maîtresse absente ou changée.
    #[error("the deployment's cipher refused to seal this key")]
    Cipher,
}

/// Prouver une clé contre Stripe, puis la sceller pour la colonne.
///
/// **L'ordre est la moitié de l'intérêt.** Une clé rangée sans être prouvée est
/// un écran qui dit « connecté » et un `null` le lendemain, et le lendemain
/// personne ne sait si c'est la clé, le réseau ou le code. C'est la discipline
/// de `model_access::connect`, une porte plus loin, avec sa propre sonde.
///
/// Ce que la sonde prouve : cette clé authentifie, et elle lit les abonnements.
/// Ce qu'elle ne prouve pas : qu'elle soit **restreinte**. Rien dans l'API ne
/// dit à un porteur ce que sa clé n'a pas le droit de faire, et une clé secrète
/// complète collée ici passerait la sonde. C'est pour ça que la lecture seule
/// est une propriété de [`StripeRead`] et non une confiance dans la clé.
///
/// `api_base` est `None` en production. Voir `model_access::ApiBase` : ce n'est
/// pas une surface de configuration, c'est ce qui rend cette fonction testable
/// autrement que par une paraphrase d'elle-même.
pub async fn prove_and_seal(
    credentials: &Credentials,
    tenant_id: TenantId,
    api_key: String,
    api_base: ApiBase<'_>,
) -> Result<Vec<u8>, ConnectError> {
    // `String` pris par valeur et jamais rendu : le tampon que le corps de la
    // requête a alloué devient celui que `Secret` efface en mourant. C'est
    // l'argument de `Credentials::seal`, mot pour mot.
    let trimmed = api_key.trim();
    if trimmed.is_empty() {
        return Err(ConnectError::Blank);
    }
    let secret = Secret::new(trimmed);
    let client = match api_base {
        Some(origin) => {
            StripeRead::new(Secret::new(secret.expose_for_transport())).with_base_url(origin)
        }
        None => StripeRead::new(Secret::new(secret.expose_for_transport())),
    };
    client.probe().await?;
    credentials
        .seal_as(tenant_id, &stripe_context(tenant_id), &secret)
        .map_err(|_| ConnectError::Cipher)
}

/// Ouvrir la clé rangée, le temps d'une lecture.
///
/// Le [`Secret`] est un local : il meurt avec le client, qui meurt avec
/// l'écran. Aucune ligne d'audit par lecture — la pose est auditée une fois,
/// et une ligne par chargement d'écran disant « on a ouvert la clé pour faire
/// ce que la ligne suivante décrit » serait du volume sans question derrière.
///
/// `None` : l'enveloppe ne s'ouvre pas sous ce contexte. Une clé maîtresse
/// tournée, une ligne restaurée d'une autre installation, ou un blob déplacé
/// d'une autre colonne scellée. Le seul remède est de recoller la clé, donc
/// l'appelant rend `null` et n'a rien à décider.
#[must_use]
pub fn client_for(
    credentials: &Credentials,
    tenant_id: TenantId,
    sealed: &[u8],
    api_base: ApiBase<'_>,
) -> Option<StripeRead> {
    let key = credentials
        .open_as(tenant_id, &stripe_context(tenant_id), sealed)
        .ok()?;
    let client = StripeRead::new(key);
    Some(match api_base {
        Some(origin) => client.with_base_url(origin),
        None => client,
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    // -- ce que le double ne prouve pas ------------------------------------
    //
    // La liste complète est dans le rapport de ce chantier et dans l'en-tête de
    // `routes::growth`. Ce qui est vrai ici : les formes ci-dessous sont
    // recopiées de la documentation de Stripe, et les trois qui ne le sont pas
    // sont nommées à l'endroit où elles servent.

    /// Un abonnement du fil, dans la forme que Stripe documente.
    fn subscription(id: &str, status: &str, items: Value) -> Value {
        json!({
            "id": id,
            "object": "subscription",
            "status": status,
            "customer": format!("cus_{id}"),
            "items": { "object": "list", "data": items, "has_more": false },
        })
    }

    /// Une ligne d'abonnement mensuelle.
    fn item(price_id: &str, nickname: Option<&str>, amount: Option<i64>, currency: &str) -> Value {
        json!({
            "id": format!("si_{price_id}"),
            "object": "subscription_item",
            "quantity": 1,
            "price": {
                "id": price_id,
                "object": "price",
                "currency": currency,
                "nickname": nickname,
                "unit_amount": amount,
                "recurring": { "interval": "month", "interval_count": 1 },
            },
        })
    }

    fn event(kind: &str, id: &str, subscription_id: &str) -> Value {
        json!({
            "id": id,
            "object": "event",
            "type": kind,
            "created": 1_757_000_000,
            "data": { "object": { "id": subscription_id, "object": "subscription" } },
        })
    }

    // -- l'arithmétique, sans socket ---------------------------------------

    #[test]
    fn un_intervalle_se_ramene_au_mois_et_ce_quon_ne_sait_pas_lire_nest_pas_zero() {
        let monthly = |interval: &str, count: i64| Recurring {
            interval: interval.to_owned(),
            interval_count: count,
        };
        assert_eq!(monthly_minor(4900, 1, &monthly("month", 1)), Some(4900));
        assert_eq!(monthly_minor(4900, 3, &monthly("month", 1)), Some(14_700));
        // Un trimestriel de 150 $ fait 50 $ par mois.
        assert_eq!(monthly_minor(15_000, 1, &monthly("month", 3)), Some(5_000));
        // Un annuel de 1 200 $ fait 100 $ par mois, par convention et pas par
        // égalité — voir `monthly_minor`.
        assert_eq!(monthly_minor(120_000, 1, &monthly("year", 1)), Some(10_000));
        // 52/12 et 365/12, arrondis au plus proche.
        assert_eq!(monthly_minor(1000, 1, &monthly("week", 1)), Some(4333));
        assert_eq!(monthly_minor(100, 1, &monthly("day", 1)), Some(3042));
        // Ce qui n'est pas lisible : un intervalle qu'on ne connaît pas, un
        // compte d'intervalle absurde. Jamais zéro.
        assert_eq!(monthly_minor(4900, 1, &monthly("fortnight", 1)), None);
        assert_eq!(monthly_minor(4900, 1, &monthly("month", 0)), None);
        assert_eq!(monthly_minor(4900, 1, &monthly("month", -1)), None);
        // Pas de débordement silencieux : le produit passe par i128 et le
        // retour refuse ce qui ne tient pas dans un i64.
        assert_eq!(monthly_minor(i64::MAX, 1000, &monthly("day", 1)), None);
    }

    #[test]
    fn seuls_les_etats_comptes_comptent_et_un_abonnement_a_deux_lignes_est_un_abonne() {
        let subscriptions: Vec<Subscription> = serde_json::from_value(json!([
            subscription(
                "sub_1",
                "active",
                json!([item("price_pro", Some("Pro"), Some(4900), "usd")])
            ),
            subscription(
                "sub_2",
                "past_due",
                json!([item("price_pro", Some("Pro"), Some(4900), "usd")])
            ),
            subscription(
                "sub_3",
                "trialing",
                json!([item("price_pro", Some("Pro"), Some(4900), "usd")])
            ),
            subscription(
                "sub_4",
                "canceled",
                json!([item("price_pro", Some("Pro"), Some(4900), "usd")])
            ),
            subscription(
                "sub_5",
                "active",
                json!([
                    item("price_pro", Some("Pro"), Some(4900), "usd"),
                    item("price_seats", Some("Sièges"), Some(1000), "usd"),
                ]),
            ),
        ]))
        .expect("la forme du fil");

        let read = summarise(&subscriptions, None, Utc::now());
        assert_eq!(
            read.subscribers, 3,
            "active et past_due, pas les deux autres"
        );
        assert_eq!(read.mrr_minor, Some(4900 * 3 + 1000));
        assert_eq!(read.currency.as_deref(), Some("usd"));
        assert!(!read.mrr_is_floor);
        // Deux paliers, et la somme de leurs abonnés dépasse le compte total :
        // `sub_5` est un abonné dans les deux.
        assert_eq!(read.tiers.len(), 2);
        assert_eq!(read.tiers[0].price_id, "price_pro");
        assert_eq!(read.tiers[0].label.as_deref(), Some("Pro"));
        assert_eq!(read.tiers[0].subscribers, 3);
        assert_eq!(read.tiers[0].mrr_minor, Some(14_700));
        assert_eq!(read.tiers[1].price_id, "price_seats");
        assert_eq!(read.tiers[1].subscribers, 1);
        assert_eq!(
            read.tiers.iter().map(|t| t.subscribers).sum::<i64>(),
            4,
            "la somme des paliers dépasse le nombre d'abonnés, et c'est voulu"
        );
        // Aucun événement demandé : `None`, jamais zéro.
        assert_eq!(read.started, None);
        assert_eq!(read.stopped, None);
    }

    #[test]
    fn deux_monnaies_rendent_un_mrr_nul_et_des_paliers_qui_gardent_le_leur() {
        let subscriptions: Vec<Subscription> = serde_json::from_value(json!([
            subscription(
                "sub_1",
                "active",
                json!([item("price_usd", None, Some(4900), "usd")])
            ),
            subscription(
                "sub_2",
                "active",
                json!([item("price_eur", None, Some(4900), "eur")])
            ),
        ]))
        .expect("la forme du fil");

        let read = summarise(&subscriptions, None, Utc::now());
        assert_eq!(read.subscribers, 2, "les abonnés se comptent sans monnaie");
        assert_eq!(
            read.mrr_minor, None,
            "rien ne somme à travers deux codes ISO"
        );
        assert_eq!(read.currency, None);
        // Un palier ne somme à travers rien : il garde son code et son montant.
        assert_eq!(read.tiers.len(), 2);
        assert!(read.tiers.iter().all(|tier| tier.mrr_minor == Some(4900)));
        assert_eq!(
            read.tiers
                .iter()
                .map(|tier| tier.currency.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["eur", "usd"])
        );
    }

    #[test]
    fn un_montant_illisible_fait_un_plancher_et_non_un_zero() {
        // Une tarification par paliers : `unit_amount` est nul, le montant
        // dépend de la consommation et n'est pas sur le prix.
        let subscriptions: Vec<Subscription> = serde_json::from_value(json!([
            subscription(
                "sub_1",
                "active",
                json!([item("price_pro", Some("Pro"), Some(4900), "usd")])
            ),
            subscription(
                "sub_2",
                "active",
                json!([item("price_usage", Some("À l'usage"), None, "usd")])
            ),
        ]))
        .expect("la forme du fil");

        let read = summarise(&subscriptions, None, Utc::now());
        assert_eq!(read.subscribers, 2);
        assert_eq!(
            read.mrr_minor,
            Some(4900),
            "ce qu'on sait lire, et pas plus"
        );
        assert!(read.mrr_is_floor, "et on dit que c'est un plancher");
        let usage = read
            .tiers
            .iter()
            .find(|tier| tier.price_id == "price_usage")
            .expect("le palier existe même sans montant");
        assert_eq!(usage.subscribers, 1);
        assert_eq!(usage.mrr_minor, None, "un montant illisible n'est pas zéro");

        // L'autre façon de ne pas tout savoir : un abonnement de plus de dix
        // lignes, dont Stripe ne sert que la première page. Ce module ne va pas
        // chercher la suite, il le dit.
        let tronque: Vec<Subscription> = serde_json::from_value(json!([{
            "id": "sub_9",
            "status": "active",
            "items": {
                "object": "list",
                "has_more": true,
                "data": [item("price_pro", Some("Pro"), Some(4900), "usd")],
            },
        }]))
        .expect("la forme du fil");
        let read = summarise(&tronque, None, Utc::now());
        assert_eq!(read.mrr_minor, Some(4900));
        assert!(
            read.mrr_is_floor,
            "une page de lignes sur deux est un plancher"
        );
    }

    #[test]
    fn les_evenements_comptent_des_abonnements_et_non_des_livraisons() {
        let events: Vec<Event> = serde_json::from_value(json!([
            event(STARTED, "evt_1", "sub_1"),
            // La même souscription rejouée : une livraison de plus, pas un
            // abonné de plus.
            event(STARTED, "evt_2", "sub_1"),
            event(STARTED, "evt_3", "sub_2"),
            event(STOPPED, "evt_4", "sub_9"),
            // Un type qu'on ne compte pas, même s'il porte un abonnement.
            event("customer.subscription.updated", "evt_5", "sub_2"),
        ]))
        .expect("la forme du fil");

        let read = summarise(&[], Some(&events), Utc::now());
        assert_eq!(read.started, Some(2));
        assert_eq!(read.stopped, Some(1));
        assert_eq!(read.subscribers, 0);
        // Aucun abonnement lu : pas de monnaie, donc pas de montant. Un zéro
        // sans monnaie n'est pas un montant, comme dans `RevenueView`.
        assert_eq!(read.mrr_minor, None);
    }

    // -- le fil, contre un faux Stripe -------------------------------------

    /// Ce que le faux Stripe a vu passer.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Seen {
        method: String,
        path: String,
        query: String,
        authorization: String,
    }

    /// Un Stripe de contrebande : une socket de bouclage, les formes de la
    /// documentation, et **un refus de tout ce qui n'est pas un `GET`**.
    struct FakeStripe {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl FakeStripe {
        /// `answers` : (chemin, corps JSON) pour chaque chemin servi. Un chemin
        /// absent rend 404, ce qui est ce que Stripe fait.
        async fn start(status: u16, answers: Vec<(&'static str, Value)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&seen);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let recorded = Arc::clone(&recorded);
                    let answers = answers.clone();
                    tokio::spawn(async move { serve(stream, recorded, status, answers).await });
                }
            });
            Self { addr, seen }
        }

        fn client(&self) -> StripeRead {
            StripeRead::new(Secret::new("rk_test_pas_une_vraie_cle"))
                .with_base_url(format!("http://{}", self.addr))
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().expect("non empoisonné").clone()
        }
    }

    async fn serve(
        mut stream: TcpStream,
        seen: Arc<Mutex<Vec<Seen>>>,
        status: u16,
        answers: Vec<(&'static str, Value)>,
    ) {
        let mut buffer = Vec::new();
        loop {
            let Some(head) = read_head(&mut stream, &mut buffer).await else {
                return;
            };
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or_default().to_owned();
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default().to_owned();
            let target = parts.next().unwrap_or_default();
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let authorization = lines
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_owned())
                })
                .unwrap_or_default();
            seen.lock().expect("non empoisonné").push(Seen {
                method: method.clone(),
                path: path.to_owned(),
                query: query.to_owned(),
                authorization,
            });

            // **Le double refuse d'écrire.** Une clé restreinte le ferait chez
            // Stripe ; ici c'est le test qui le fait, pour que l'apparition
            // d'un `POST` dans ce module soit rouge et non silencieuse.
            let (code, payload) = if method != "GET" {
                (405, json!({ "error": { "message": "read only" } }))
            } else if status != 200 {
                (status, json!({ "error": { "message": "non" } }))
            } else {
                match answers.iter().find(|(route, _)| *route == path) {
                    // Le double filtre sur `status` comme Stripe le fait : sans
                    // ça, les deux requêtes de `COUNTED_STATUSES` reçoivent la
                    // même liste et un abonné est compté deux fois — une
                    // propriété du faux qu'on lirait comme une du produit.
                    Some((_, body)) => (200, by_status(body, query)),
                    None => (404, json!({ "error": { "message": "no such resource" } })),
                }
            };
            let body = serde_json::to_vec(&payload).expect("sérialiser");
            let mut out = format!(
                "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(&body);
            if stream.write_all(&out).await.is_err() {
                return;
            }
        }
    }

    /// La page, réduite aux abonnements de l'état demandé.
    fn by_status(body: &Value, query: &str) -> Value {
        let Some(wanted) = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("status="))
        else {
            return body.clone();
        };
        let mut page = body.clone();
        if let Some(data) = page.get_mut("data").and_then(Value::as_array_mut) {
            data.retain(|row| row["status"] == *wanted);
        }
        page
    }

    /// Les en-têtes d'une requête. Aucun corps n'est lu : un `GET` n'en a pas,
    /// et ce faux serveur n'existe que pour des `GET`.
    async fn read_head(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<String> {
        loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buffer[..at]).into_owned();
                buffer.drain(..at + 4);
                return Some(head);
            }
            let mut chunk = [0_u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn page(data: Value, has_more: bool) -> Value {
        json!({ "object": "list", "url": "/v1/subscriptions", "has_more": has_more, "data": data })
    }

    #[tokio::test]
    async fn une_lecture_ne_fait_que_des_get_et_porte_la_cle_en_bearer() {
        let fake = FakeStripe::start(
            200,
            vec![
                (
                    "/subscriptions",
                    page(
                        json!([subscription(
                            "sub_1",
                            "active",
                            json!([item("price_pro", Some("Pro"), Some(4900), "usd")])
                        )]),
                        false,
                    ),
                ),
                (
                    "/events",
                    page(json!([event(STARTED, "evt_1", "sub_1")]), false),
                ),
            ],
        )
        .await;

        let now = Utc::now();
        let read = fake
            .client()
            .read(now - chrono::Duration::days(29), now)
            .await
            .expect("le faux a répondu");
        assert_eq!(read.subscribers, 1);
        assert_eq!(read.mrr_minor, Some(4900));
        assert_eq!(read.started, Some(1));
        assert_eq!(read.stopped, Some(0));

        let seen = fake.seen();
        assert!(
            seen.iter().all(|request| request.method == "GET"),
            "une écriture est partie vers Stripe : {seen:#?}"
        );
        assert!(
            seen.iter()
                .all(|request| request.authorization == "Bearer rk_test_pas_une_vraie_cle"),
            "la clé voyage en Bearer, une fois par requête"
        );
        // Les deux états demandés, puis les événements avec leur borne.
        let statuses: Vec<&str> = seen
            .iter()
            .filter(|request| request.path == "/subscriptions")
            .map(|request| request.query.as_str())
            .collect();
        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].contains("status=active"), "{statuses:?}");
        assert!(statuses[1].contains("status=past_due"), "{statuses:?}");
        assert!(statuses.iter().all(|query| query.contains("limit=100")));
        let events: Vec<&str> = seen
            .iter()
            .filter(|request| request.path == "/events")
            .map(|request| request.query.as_str())
            .collect();
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("created%5Bgte%5D="), "{events:?}");
        assert!(
            events[0].contains("customer.subscription.created")
                && events[0].contains("customer.subscription.deleted"),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn une_fenetre_plus_longue_que_la_retention_ne_demande_aucun_evenement() {
        let fake = FakeStripe::start(
            200,
            vec![
                ("/subscriptions", page(json!([]), false)),
                (
                    "/events",
                    page(json!([event(STARTED, "evt_1", "sub_1")]), false),
                ),
            ],
        )
        .await;

        let now = Utc::now();
        let read = fake
            .client()
            .read(now - chrono::Duration::days(EVENT_RETENTION_DAYS + 1), now)
            .await
            .expect("le faux a répondu");
        assert_eq!(read.started, None, "hors rétention : absent, pas zéro");
        assert_eq!(read.stopped, None);
        assert!(
            fake.seen().iter().all(|request| request.path != "/events"),
            "aucune requête d'événements n'est partie"
        );
    }

    #[tokio::test]
    async fn une_cle_refusee_est_un_refus_et_une_panne_est_une_absence() {
        for (status, expected) in [
            (401, StripeError::Refused),
            (403, StripeError::Refused),
            (429, StripeError::Unavailable),
            (500, StripeError::Unavailable),
            (400, StripeError::Unreadable),
        ] {
            let fake = FakeStripe::start(status, vec![]).await;
            let now = Utc::now();
            assert_eq!(
                fake.client()
                    .read(now - chrono::Duration::days(7), now)
                    .await,
                Err(expected),
                "status {status}"
            );
            assert_eq!(
                fake.client().probe().await,
                Err(expected),
                "status {status}"
            );
        }
    }

    /// Une clé qui lit les abonnements mais pas les événements : la moitié qui
    /// a marché est rendue, l'autre est `None`.
    #[tokio::test]
    async fn un_refus_sur_les_evenements_nefface_pas_les_abonnements() {
        let fake = FakeStripe::start(
            200,
            // `/events` absent de la table : le faux rend 404, comme Stripe le
            // ferait sur une ressource qu'une clé restreinte ne voit pas.
            vec![(
                "/subscriptions",
                page(
                    json!([subscription(
                        "sub_1",
                        "active",
                        json!([item("price_pro", Some("Pro"), Some(4900), "usd")])
                    )]),
                    false,
                ),
            )],
        )
        .await;

        let now = Utc::now();
        let read = fake
            .client()
            .read(now - chrono::Duration::days(7), now)
            .await
            .expect("les abonnements ont été lus");
        assert_eq!(read.mrr_minor, Some(4900));
        assert_eq!(read.started, None, "l'absence n'est pas zéro");
        assert_eq!(read.stopped, None);
    }

    #[tokio::test]
    async fn plus_dabonnements_que_lecran_nen_peut_lire_est_un_refus_et_non_un_sous_compte() {
        // Toujours `has_more`, et jamais la fin : le plafond est ce qui arrête.
        let fake = FakeStripe::start(
            200,
            vec![(
                "/subscriptions",
                page(
                    json!([subscription(
                        "sub_1",
                        "active",
                        json!([item("price_pro", None, Some(4900), "usd")])
                    )]),
                    true,
                ),
            )],
        )
        .await;

        let now = Utc::now();
        assert_eq!(
            fake.client()
                .read(now - chrono::Duration::days(7), now)
                .await,
            Err(StripeError::TooMany)
        );
        assert_eq!(
            fake.seen()
                .iter()
                .filter(|request| request.path == "/subscriptions")
                .count(),
            MAX_PAGES,
            "le plafond est celui qui est écrit"
        );
    }

    /// La pagination marche, et le curseur est l'identifiant de la dernière
    /// ligne.
    #[tokio::test]
    async fn la_seconde_page_est_demandee_apres_la_derniere_ligne_de_la_premiere() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    // La première page d'abonnements a une suite, la seconde
                    // non ; les événements tiennent en une page.
                    let mut buffer = Vec::new();
                    while let Some(head) = read_head(&mut stream, &mut buffer).await {
                        let line = head.lines().next().unwrap_or_default().to_owned();
                        let target = line.split(' ').nth(1).unwrap_or_default();
                        let (path, query) = target.split_once('?').unwrap_or((target, ""));
                        recorded.lock().expect("non empoisonné").push(Seen {
                            method: line.split(' ').next().unwrap_or_default().to_owned(),
                            path: path.to_owned(),
                            query: query.to_owned(),
                            authorization: String::new(),
                        });
                        let body = if path == "/events" {
                            page(json!([]), false)
                        } else if query.contains("starting_after=sub_1") {
                            page(
                                json!([subscription(
                                    "sub_2",
                                    "active",
                                    json!([item("price_pro", None, Some(1000), "usd")])
                                )]),
                                false,
                            )
                        } else {
                            page(
                                json!([subscription(
                                    "sub_1",
                                    "active",
                                    json!([item("price_pro", None, Some(1000), "usd")])
                                )]),
                                true,
                            )
                        };
                        let body = serde_json::to_vec(&body).expect("sérialiser");
                        let mut out = format!(
                            "HTTP/1.1 200 X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&body);
                        if stream.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let now = Utc::now();
        let read = StripeRead::new(Secret::new("rk_test"))
            .with_base_url(format!("http://{addr}"))
            .read(now - chrono::Duration::days(7), now)
            .await
            .expect("deux pages");
        // Deux pages par état demandé : ce serveur-ci ne filtre pas sur
        // l'état, il pagine — c'est la pagination qu'il est là pour prouver.
        assert_eq!(read.subscribers, 4);
        assert_eq!(read.mrr_minor, Some(4000));
        let asked = seen.lock().expect("non empoisonné").clone();
        assert!(
            asked
                .iter()
                .any(|request| request.query.contains("starting_after=sub_1")),
            "{asked:#?}"
        );
    }

    // -- la clé ------------------------------------------------------------

    /// **Une clé est prouvée avant d'être rangée, et elle n'ouvre que là où
    /// elle a été scellée.**
    ///
    /// Les deux moitiés sont dans le même test parce qu'elles sont la même
    /// promesse vue des deux bouts : ce qui entre est prouvé, ce qui sort est
    /// celui du bon locataire sous le bon contexte.
    #[tokio::test]
    async fn une_cle_est_prouvee_avant_detre_rangee_et_nouvre_que_sous_son_contexte() {
        use agentos_providers::secrets::LocalEnvelopeSecretStore;

        let credentials = Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([4_u8; 32])));
        let tenant = TenantId::new_v7(Utc::now());
        let autre = TenantId::new_v7(Utc::now());

        // Une chaîne vide n'est pas une clé, et ça se voit sans réseau.
        assert_eq!(
            prove_and_seal(&credentials, tenant, "   ".to_owned(), None).await,
            Err(ConnectError::Blank)
        );

        // Stripe refuse : rien n'est scellé, donc rien ne sera rangé.
        let refus = FakeStripe::start(401, vec![]).await;
        let base = format!("http://{}", refus.addr);
        assert_eq!(
            prove_and_seal(
                &credentials,
                tenant,
                "rk_live_fausse".to_owned(),
                Some(&base)
            )
            .await,
            Err(ConnectError::Stripe(StripeError::Refused))
        );
        assert!(
            refus.seen().iter().all(|request| request.method == "GET"),
            "même la sonde ne fait qu'un GET"
        );

        // Stripe accepte : la clé est scellée, et elle rouvre.
        let vrai = FakeStripe::start(200, vec![("/subscriptions", page(json!([]), false))]).await;
        let base = format!("http://{}", vrai.addr);
        let sealed = prove_and_seal(
            &credentials,
            tenant,
            "rk_live_vraie".to_owned(),
            Some(&base),
        )
        .await
        .expect("prouvée");
        assert!(!sealed.is_empty());
        let client = client_for(&credentials, tenant, &sealed, Some(&base)).expect("rouverte");
        assert_eq!(client.probe().await, Ok(()));

        // Pas sous un autre locataire : l'AAD du locataire.
        assert!(client_for(&credentials, autre, &sealed, None).is_none());
        // Et pas depuis une autre colonne scellée du **même** locataire : c'est
        // ce que `stripe://` achète, et l'AAD du locataire ne l'achèterait pas.
        let ailleurs = credentials
            .seal_as(
                tenant,
                &format!("model://{tenant}"),
                &Secret::new("sk-ant-la-cle-du-modele"),
            )
            .expect("scellée ailleurs");
        assert!(
            client_for(&credentials, tenant, &ailleurs, None).is_none(),
            "une clé de modèle déplacée dans la colonne Stripe partirait chez Stripe"
        );
    }

    // -- la preuve écrite ---------------------------------------------------

    /// **Le test qui échoue si une écriture apparaît.**
    ///
    /// Une clé restreinte est une promesse côté Stripe ; ceci est la nôtre,
    /// côté code. Il lit ce fichier et refuse les quatre verbes qui écrivent.
    ///
    /// Ce qu'il ne prouve pas, et il faut le dire ici plutôt qu'ailleurs : il
    /// ne lit que **ce fichier**. Un autre module qui prendrait la même clé
    /// pour écrire ne serait pas vu par lui — c'est pour ça que la clé ne sort
    /// jamais de [`StripeRead`], qui ne l'expose par aucune méthode.
    #[test]
    fn aucune_ecriture_ne_peut_apparaitre_dans_ce_fichier() {
        let source = include_str!("stripe_subscriptions.rs");
        // Les commentaires sont retirés avant la recherche, et c'est nécessaire
        // plutôt que poli : l'en-tête de ce module **cite** les quatre verbes
        // pour dire qu'il ne les emploie pas, et la liste ci-dessous se nomme
        // elle-même. Un verbe dans un commentaire n'écrit rien ; un verbe dans
        // du code, si.
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // Les aiguilles sont **assemblées** et non écrites : `".post("` en
        // toutes lettres ici serait une occurrence de plus dans le code, et ce
        // test échouerait sur lui-même.
        for verb in ["post", "put", "patch", "delete"] {
            for needle in [
                format!(".{verb}("),
                format!("Method::{}", verb.to_uppercase()),
            ] {
                assert!(
                    !code.contains(&needle),
                    "{needle} est apparu dans un module qui ne doit que lire Stripe"
                );
            }
        }
        // Et la garde, désarmée : la recherche voit bien le code, puisqu'elle y
        // trouve le seul verbe que ce module emploie.
        assert!(code.contains(".get("));
    }
}
