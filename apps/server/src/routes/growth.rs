//! `GET /v1/growth` : l'entonnoir de bout en bout, la recette, le coût du
//! modèle, et la cible — c'est-à-dire la seule lecture qui réponde à « est-ce
//! que j'y arrive ».
//!
//! # Pourquoi cette route existe alors que sept autres rendent déjà ces
//! nombres
//!
//! Parce qu'aucune ne les met bout à bout, et que l'information n'est pas dans
//! les nombres : elle est dans les **rapports** entre eux. Le fondateur
//! d'Orizn fait 190 $/mois et veut 1 900 $ en trois à quatre mois. Pour savoir
//! s'il y arrive, il lui faut sept comptes et six divisions. Les sept comptes
//! existaient, éparpillés : [`super::outreach`] rend les approches et les
//! réponses, [`super::quotes`] le registre des devis, [`super::invoices`]
//! celui des factures, [`super::pnl`] ce que chaque siège brûle,
//! [`super::billing`] les jours facturables, [`super::usage`] les jetons. Les
//! six divisions n'existaient nulle part, et une console qui les ferait
//! elle-même les ferait sur sept requêtes dont les fenêtres ne coïncident pas.
//!
//! **Aucune donnée n'est créée ici.** Chaque nombre sort de la table qui en
//! fait foi, et quand une étape n'a pas de table, elle rend `null` — jamais un
//! zéro, qui se lit comme une mesure.
//!
//! # Ce que cette route ne refait pas
//!
//! **Le point mort.** Il est dans [`super::forecast`], avec sa division, ses
//! opérandes nommés un par un et la moyenne des factures encaissées.
//! Le recopier ici serait un deuxième endroit où « combien de factures pour
//! être à l'équilibre » peut être vrai, et ce dépôt a déjà payé ce prix une
//! fois (`docs/ORIZN.md` publiait 76 $/mois en prose). Ce qui est ici est
//! l'autre moitié : ce qui est **arrivé**, pas ce qui arriverait.
//!
//! # Les sept étapes, et d'où sort chacune
//!
//! L'ordre est celui d'un inconnu qui devient un client, et chaque ligne porte
//! son **taux de passage à la suivante** — `count[i+1] / count[i]`, `null`
//! quand le dénominateur est zéro, parce qu'un taux sans dénominateur n'est pas
//! zéro, il n'est pas défini.
//!
//! | étape | table | colonne |
//! |---|---|---|
//! | `prospects_added` | `contacts` (0011) | `created_at` |
//! | `contacted` | `outreach_buckets` (0055) | `contacts_taken`, par jour |
//! | `replied` | `messages` (0080) | un fil, une réponse |
//! | `quotes_issued` | `sales_quotes` (0090) | `issued_at` |
//! | `quotes_accepted` | `sales_quotes` (0090) | `accepted_at` |
//! | `invoices_issued` | `invoices` (0066) | `issued_at` |
//! | `invoices_paid` | `invoices` (0066) | `paid_at` |
//!
//! `contacted` et `replied` sont les définitions d'[`super::outreach`] mot pour
//! mot — `outreach_buckets` est le goulot que les deux chemins d'approche
//! traversent, et un fil entrant est compté une fois. Les reprendre ici plutôt
//! que d'en écrire des variantes est ce qui fait que les deux écrans ne
//! s'opposent pas.
//!
//! **Ce n'est pas une cohorte.** Les sept comptes sont sept mesures de la même
//! fenêtre, pas le suivi des mêmes personnes d'un bout à l'autre : la facture
//! réglée ce mois-ci répond à un devis du mois dernier. Un taux de passage est
//! donc un rapport de débits, pas une probabilité de conversion, et
//! [`UNMEASURED`] le dit dans le corps de la réponse.
//!
//! # La recette, et la monnaie
//!
//! `invoiced_minor` et `collected_minor` sont sur la fenêtre ;
//! `outstanding_minor` est sur **tout le registre**, parce qu'une créance de
//! l'an dernier est toujours due et qu'une fenêtre la ferait disparaître.
//! `mrr_minor` est ce qui a été encaissé sur **trente jours glissants**, quelle
//! que soit la fenêtre demandée : c'est le chiffre que le fondateur appelle
//! « 190 $/mois », et c'est un mois réel plutôt que la fenêtre étirée au
//! trentième.
//!
//! **Ce n'est pas un abonnement.** Rien dans ce schéma ne porte de récurrence —
//! il n'y a pas de table d'abonnements, `billing` compte des jours facturables
//! et refuse d'y coller un prix. `mrr_minor` est donc une recette de trente
//! jours nommée pour ce qu'elle est, et non une projection.
//!
//! Les quatre montants sont `null` ensemble quand le registre emploie **plus
//! d'une monnaie** : `Ledger` (voir [`super::pnl`]) ne somme jamais à travers
//! les codes, et cette route ne le fait pas non plus. Ils sont `null` aussi
//! quand il n'y a aucune facture — un zéro sans monnaie n'est pas un montant,
//! et `Money` lui-même refuse le zéro.
//!
//! # D'où vient un euro
//!
//! Les cinq montants ci-dessus disent **combien**. `attribution` dit **d'où**,
//! et c'est la question que le fondateur pose quand il choisit où doubler son
//! effort : on ne double pas toutes les trois semaines ce qu'on ne sait pas
//! attribuer.
//!
//! La chaîne est celle que le schéma portait déjà, et elle n'a pas été
//! inventée ici : `invoices.opportunity_id` → `opportunities.account_id` →
//! `contacts.account_id`. Le seul anneau qui manquait est le premier — par
//! quelle porte cette adresse est entrée — et c'est
//! `migrations/0107_un_contact_dit_dou_il_vient.sql` qui le pose, sur
//! `contacts`, en deux colonnes : `origin` (`import` ou `discovery`) et
//! `origin_ref` (le fichier, ou l'URL de la page).
//!
//! **Aucun euro n'est réparti.** Une facture réglée est attribuée à
//! l'**ensemble** des origines que ses contacts nomment, pas divisée entre
//! elles : un seau dont la liste `origins` a deux entrées est une chaîne qui se
//! scinde, et rendre « 50 % à l'une, 50 % à l'autre » serait inventer deux
//! chiffres là où il n'y a qu'un fait. Un seau dont la liste est **vide** est
//! une facture dont l'origine est **inconnue** — jamais « organique », qui est
//! un nom de canal et non un aveu.
//!
//! La somme des seaux d'une monnaie est exactement son `collected_minor` : la
//! fenêtre est la même, la table est la même, et un test l'affirme.
//!
//! # Le coût, et pourquoi il est souvent `null`
//!
//! `model_minor` est les jetons de la fenêtre multipliés par le tarif que ce
//! locataire a déclaré sur `POST /v1/model`, en cents de dollar — la même
//! multiplication NUMERIC que [`super::pnl`], pas une seconde copie de
//! l'arithmétique.
//!
//! Il est `null` dans deux cas, et les deux sont la discipline de
//! `agentos_store::model_usage` : **aucun tarif déclaré**, parce qu'un prix
//! qu'on n'a pas dit n'est pas gratuit ; et **le chemin `cli`**, parce qu'un
//! abonnement n'a pas de facture au jeton et que le chiffre existerait
//! arithmétiquement sans vouloir rien dire. C'est le cas d'Orizn aujourd'hui.
//! `agentos_domain::forecast` donne l'argument complet.
//!
//! `per_seat_minor` est `model_minor` divisé par les sièges actifs, et `null`
//! avec lui.
//!
//! # La cible, et le verdict
//!
//! Un entonnoir sans cible ne dit rien : trois réponses est un bon chiffre ou
//! un désastre selon qu'on visait cinq ou cinq cents. `PUT /v1/growth/target`
//! la pose, `migrations/0101` argumente la table.
//!
//! `verdict` est une comparaison de deux rythmes mensuels, tous deux mesurés :
//!
//! * **ce qu'il faut ajouter** — `(cible − mrr) / mois restants` ;
//! * **ce qui a été ajouté** — `mrr` moins ce qui avait été encaissé sur les
//!   trente jours d'avant.
//!
//! Linéaire, sans moyenne géométrique et sans lissage : c'est une division
//! qu'un fondateur refait de tête, et [`verdict`] est pure pour que le test la
//! refasse sans base de données. Les bornes sont à ±10 % du rythme requis, et
//! `no_target` couvre les deux façons de n'avoir rien à comparer — aucune ligne
//! posée, ou une cible libellée dans une monnaie que le registre n'emploie pas.
//!
//! # L'auth et le locataire
//!
//! Celle d'[`super::outreach`] : la clé du locataire par [`Principal`], toutes
//! les lectures sous [`Db::tenant_tx`]. Les neuf tables lues ont RLS `force`,
//! il n'y a aucun `WHERE tenant_id`, et l'entonnoir d'une autre entreprise
//! n'est pas filtré — il est invisible.

use agentos_domain::money::Currency;
use agentos_store::db::{Db, StoreError};
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// Les routes de cette unité.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/growth", get_route(get))
        .route(
            "/v1/growth/target",
            get_route(read_target).put(write_target),
        )
        .with_state(db)
}

/// `?days=N`, défaut [`DEFAULT_DAYS`], au plus [`MAX_DAYS`].
#[derive(Debug, Deserialize)]
struct GrowthQuery {
    days: Option<i64>,
}

const DEFAULT_DAYS: i64 = 30;
/// Un an. Au-delà, un entonnoir ne décrit plus l'entreprise d'aujourd'hui —
/// même borne que `GET /v1/outreach/health`.
const MAX_DAYS: i64 = 365;

/// Le mois que `mrr_minor` compte, et l'unité du rythme du verdict.
///
/// Trente jours glissants et non le mois calendaire : la fenêtre de la route
/// est en jours, la cible est mensuelle, et deux définitions du mois dans une
/// même réponse seraient deux chiffres qui ne se divisent pas.
const MONTH_DAYS: i64 = 30;

// ---------------------------------------------------------------------------
// La réponse
// ---------------------------------------------------------------------------

/// Une étape, et ce qui passe à la suivante.
#[derive(Debug, Serialize)]
struct StageView {
    stage: &'static str,
    /// `null` quand l'étape n'a pas de table qui en fasse foi. Les sept en ont
    /// une aujourd'hui — voir l'en-tête — donc aucune n'est `null` ici ; le
    /// champ est optionnel parce qu'un zéro affiché à la place d'une absence de
    /// mesure est la seule erreur que cet écran ne peut pas rattraper.
    count: Option<i64>,
    /// `count[i+1] / count[i]`, arrondi à quatre décimales. `null` sur la
    /// dernière étape (il n'y a pas de suivante) et `null` quand le
    /// dénominateur est zéro — **pas zéro** : zéro sur quarante est une
    /// mesure, zéro sur zéro n'en est pas une.
    to_next_rate: Option<f64>,
}

/// Les sept étapes, dans l'ordre, telles qu'elles sortent sur le fil.
const STAGES: [&str; 7] = [
    "prospects_added",
    "contacted",
    "replied",
    "quotes_issued",
    "quotes_accepted",
    "invoices_issued",
    "invoices_paid",
];

/// Ce que l'entreprise a facturé, encaissé, et ce qu'on lui doit.
///
/// Les cinq champs sont `null` ensemble : ils n'ont de sens qu'avec une
/// monnaie, et une monnaie n'existe que si le registre n'en emploie qu'une.
#[derive(Debug, Default, Serialize)]
struct RevenueView {
    /// Encaissé sur trente jours glissants. Pas un abonnement — voir l'en-tête.
    mrr_minor: Option<i64>,
    currency: Option<&'static str>,
    /// Émis dans la fenêtre.
    invoiced_minor: Option<i64>,
    /// Encaissé dans la fenêtre.
    collected_minor: Option<i64>,
    /// Dû, sur tout le registre et non sur la fenêtre.
    outstanding_minor: Option<i64>,
}

/// Une porte par laquelle une adresse est entrée, telle que `contacts` la
/// porte depuis `migrations/0107_un_contact_dit_dou_il_vient.sql`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct OriginView {
    /// `import` ou `discovery`. La CHECK de 0107 tient l'ensemble fermé.
    kind: String,
    /// Le nom que l'opérateur a donné à cette source — le fichier, l'URL.
    /// `null` quand la porte est connue et la source anonyme : c'est le cas de
    /// `POST /v1/prospects/import`, qui reçoit un corps `text/csv` sans nom.
    reference: Option<String>,
}

/// Ce qu'une chaîne d'origines a encaissé dans la fenêtre.
///
/// Un seau par **ensemble** d'origines et par monnaie. Les trois formes que
/// prend `origins`, et il n'y en a pas d'autres :
///
/// * **une entrée** — la chaîne est nette, et l'argent a un nom ;
/// * **plusieurs** — elle se scinde : les contacts de ce compte ne sont pas
///   tous entrés par la même porte. Les deux sont rendues et l'argent n'est
///   **pas** réparti entre elles ;
/// * **vide** — aucun contact de ce compte ne dit d'où il vient. C'est
///   **inconnu**, et `unmeasured` dit les trois façons de l'être.
#[derive(Debug, Serialize)]
struct AttributionView {
    origins: Vec<OriginView>,
    /// Celle des factures de ce seau. Jamais sommée à travers les codes ISO,
    /// comme partout ici — d'où un seau par monnaie plutôt qu'un `null`.
    currency: String,
    invoices_paid: i64,
    collected_minor: i64,
}

/// Ce que le modèle a coûté, en cents de dollar.
#[derive(Debug, Default, Serialize)]
struct CostView {
    /// Jetons × tarif déclaré. `null` sans tarif, et `null` sur le chemin
    /// `cli` — voir l'en-tête.
    model_minor: Option<i64>,
    /// `model_minor` par siège actif. `null` avec lui, et `null` sans siège.
    per_seat_minor: Option<i64>,
}

/// La cible telle que le fondateur l'a posée.
#[derive(Debug, Serialize)]
struct TargetView {
    mrr_minor: i64,
    currency: String,
    at: DateTime<Utc>,
    set_at: DateTime<Utc>,
}

/// Quatre mots, et pas un score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    /// Le rythme observé dépasse de plus de 10 % celui qu'il faudrait, ou la
    /// cible est déjà atteinte.
    Ahead,
    /// À ±10 % du rythme requis.
    OnTrack,
    /// En dessous, ou l'échéance est passée sans que la cible soit atteinte.
    Behind,
    /// Rien à comparer : aucune cible posée, ou une cible libellée dans une
    /// monnaie que le registre de ce locataire n'emploie pas.
    NoTarget,
}

/// Ce que ces chiffres ne couvrent pas, une phrase par trou.
///
/// Le motif d'[`super::outreach`] et d'`agentos_eval::cost` : la liste se lit
/// en bas de la réponse, et chaque ligne dit **dans quel sens** elle déplace le
/// chiffre.
const UNMEASURED: &[&str] = &[
    "L'entonnoir n'est pas une cohorte : les sept comptes mesurent la même fenêtre, pas les \
     mêmes personnes. Une facture réglée ce mois-ci répond souvent à un devis du mois dernier, \
     donc un taux de passage est un rapport de débits et non une probabilité de conversion. \
     Sur une entreprise qui accélère, les taux de fin d'entonnoir sont sous-estimés.",
    "contacted compte des créneaux réservés dans outreach_buckets, jamais des envois partis : \
     un fichier exporté et jamais chargé chez le prestataire reste compté. C'est un majorant, \
     et GET /v1/outreach/health est la lecture qui dit ce qui est réellement parti.",
    "replied compte les fils qui nous ont écrit, pas les fils qu'une approche a ouverts : \
     conversations n'a aucune colonne qui nomme l'approche, et une réponse automatique, un \
     message d'absence ou un avis de rebond y ressemblent à une réponse.",
    "quotes_issued et quotes_accepted comptent ce que le système a écrit, et il n'y a qu'une \
     façon d'y entrer : un employé qui propose, avec un jeton de la Policy Gate \
     (agentos_app::effects::propose_quote). Aucune route d'opérateur n'émet de devis et c'est \
     délibéré — voir routes::quotes. Un devis négocié au téléphone et jamais saisi n'y est \
     donc pas, et l'entreprise qui vend ainsi lit deux zéros au milieu de son entonnoir sans \
     que rien ne soit cassé.",
    "outstanding_minor porte tout le registre et non la fenêtre : une créance de l'an dernier \
     y est encore. C'est le seul des cinq montants qui ne se compare pas aux quatre autres.",
    "mrr_minor est une recette de trente jours glissants, pas un abonnement : rien dans ce \
     schéma ne porte de récurrence. Un client qui paie deux fois en un mois le double, et un \
     client qui paie d'avance pour un trimestre le triple.",
    "Les cinq montants sont null ensemble dès que le registre emploie plus d'une monnaie : \
     cette route ne somme jamais à travers les codes ISO, et aucun taux de change n'est \
     fourni. Ils sont null aussi quand il n'existe aucune facture.",
    "attribution ne voit que ce qui est passé par une facture, et une facture exige une affaire \
     closed_won (invoices.opportunity_id, 0066). Un abonnement pris en libre-service sur le site \
     du locataire — une carte, une clé d'API, aucun humain — n'a ni affaire ni devis, donc il \
     n'entre jamais dans invoices et il n'est pas ici. Ces euros-là ne sont pas d'origine \
     inconnue : ils sont hors de cette lecture, et le webhook Stripe (0081) ne fait que régler \
     une facture déjà écrite, jamais en créer une. Une entreprise qui vend en libre-service lit \
     donc une attribution vide sans que rien ne soit cassé.",
    "Une origine est la porte par laquelle une adresse est entrée, pas ce qui l'a convaincue. \
     Un contact importé en mars et converti après un article de septembre porte import, et rien \
     ici ne dit lequel des deux a emporté l'affaire. C'est une attribution au premier contact, \
     et c'est la seule que le schéma puisse prouver.",
    "L'origine est portée par les contacts d'un compte et non par la facture : opportunities \
     n'a aucune colonne qui nomme la personne. Quand les contacts d'un même compte sont entrés \
     par deux portes, origins en a deux et l'argent n'est réparti entre aucune des deux.",
    "Les contacts écrits avant migrations/0107 n'ont pas d'origine et ne peuvent pas en \
     recevoir une rétroactivement. Un seau vide sur une entreprise établie est donc autant une \
     date de mise en service qu'une mesure, et il se lit 'nous ne savons pas' — jamais \
     'organique'.",
    "model_minor est null sans tarif déclaré et sur le chemin cli — un abonnement n'a pas de \
     facture au jeton. Un null n'est jamais une absence de coût : c'est une absence de prix.",
    "model_minor est un plancher quand une partie des appels n'a pas été mesurée par le \
     fournisseur ou quand le tarif déclaré est incomplet. GET /v1/pnl porte les deux drapeaux \
     (complete, cost_is_floor) qui le disent appel par appel.",
    "Le point mort n'est pas ici : GET /v1/forecast le divise, avec ses opérandes nommés un \
     par un. Cette route dit ce qui est arrivé, celle-là ce qui arriverait.",
];

/// Ce que la route rend.
#[derive(Debug, Serialize)]
struct GrowthView {
    days: i64,
    window: WindowView,
    funnel: Vec<StageView>,
    revenue: RevenueView,
    /// D'où viennent les factures réglées de la fenêtre. Voir l'en-tête : la
    /// somme des seaux d'une monnaie est son `collected_minor`.
    attribution: Vec<AttributionView>,
    cost: CostView,
    target: Option<TargetView>,
    verdict: Verdict,
    unmeasured: &'static [&'static str],
}

/// La fenêtre, bornes incluses, en UTC.
#[derive(Debug, Serialize)]
struct WindowView {
    from: NaiveDate,
    to: NaiveDate,
}

// ---------------------------------------------------------------------------
// L'arithmétique, et elle est pure
// ---------------------------------------------------------------------------

/// Les sept lignes, comptes et taux, depuis les sept comptes.
///
/// Pure et séparée du gestionnaire pour la raison que `forecast::assemble`
/// donne de la sienne : c'est toute la logique, elle tient en dix lignes, et un
/// test doit pouvoir la refaire sans Postgres.
fn funnel(counts: [Option<i64>; 7]) -> Vec<StageView> {
    STAGES
        .iter()
        .enumerate()
        .map(|(i, stage)| StageView {
            stage,
            count: counts[i],
            to_next_rate: counts
                .get(i + 1)
                .copied()
                .flatten()
                .zip(counts[i])
                // Zéro au dénominateur : le taux n'est pas zéro, il n'existe
                // pas. C'est la seule division de cette route et c'est la
                // seule façon de s'y tromper.
                .filter(|(_, from)| *from > 0)
                .map(|(to, from)| ((to as f64 / from as f64) * 10_000.0).round() / 10_000.0),
        })
        .collect()
}

/// Le verdict : deux rythmes mensuels, et rien d'autre.
///
/// `mrr` et `previous_mrr` sont ce qui a été encaissé sur les trente derniers
/// jours et sur les trente d'avant. `None` sur l'un des deux — pas de monnaie
/// commune, pas de registre — rend [`Verdict::NoTarget`], parce qu'un verdict
/// sur un chiffre absent serait une opinion.
fn verdict(
    target: Option<&TargetView>,
    mrr: Option<i64>,
    previous_mrr: Option<i64>,
    currency: Option<&str>,
    now: DateTime<Utc>,
) -> Verdict {
    let (Some(target), Some(mrr), Some(previous), Some(currency)) =
        (target, mrr, previous_mrr, currency)
    else {
        return Verdict::NoTarget;
    };
    // Une cible en dollars contre un registre en euros n'est pas un retard,
    // c'est une comparaison qui n'a pas lieu. Aucun taux de change n'est
    // fourni à cette route et en inventer un serait inventer de la recette.
    if target.currency != currency {
        return Verdict::NoTarget;
    }
    // Déjà arrivé. Testé avant l'échéance : une cible atteinte en avance reste
    // atteinte le lendemain de la date, et rendre `behind` à quelqu'un qui a
    // dépassé son objectif serait la seule ligne de cet écran que personne ne
    // croirait.
    if mrr >= target.mrr_minor {
        return Verdict::Ahead;
    }
    let months = (target.at - now).num_seconds() as f64 / (MONTH_DAYS * 86_400) as f64;
    if months <= 0.0 {
        // L'échéance est passée et la cible n'est pas atteinte. Il n'y a plus
        // de rythme à comparer, il y a un fait.
        return Verdict::Behind;
    }
    let required = (target.mrr_minor - mrr) as f64 / months;
    let actual = (mrr - previous) as f64;
    if actual > required * 1.1 {
        Verdict::Ahead
    } else if actual >= required * 0.9 {
        Verdict::OnTrack
    } else {
        Verdict::Behind
    }
}

/// Une ligne d'[`ATTRIBUTION_SQL`] : une facture réglée, et **une** des
/// origines que sa chaîne nomme — `origin` est `null` quand elle n'en nomme
/// aucune, la jointure étant un `LEFT JOIN`.
#[derive(Debug, sqlx::FromRow)]
struct AttributionRow {
    invoice_id: Uuid,
    currency: String,
    amount_minor: i64,
    origin: Option<String>,
    origin_ref: Option<String>,
}

/// Les seaux, depuis les lignes plates de la jointure.
///
/// Pure pour la raison de [`funnel`] et de [`verdict`] : c'est toute la
/// logique, et le piège qu'elle évite ne se voit qu'en la refaisant à la main.
///
/// **Le piège, et c'est le seul de cette section.** La requête rend une ligne
/// par (facture, origine) : un compte dont deux contacts sont entrés par deux
/// portes rend deux lignes pour une facture. Sommer ces lignes-là compterait
/// l'argent deux fois — c'est-à-dire inventerait de la recette à l'endroit
/// exact où cette section existe pour ne pas en inventer. D'où deux passes :
/// une facture d'abord, avec l'**ensemble** de ses origines, les seaux ensuite.
fn attribute(rows: Vec<AttributionRow>) -> Vec<AttributionView> {
    let mut invoices: BTreeMap<Uuid, (String, i64, BTreeSet<OriginView>)> = BTreeMap::new();
    for AttributionRow {
        invoice_id,
        currency,
        amount_minor,
        origin,
        origin_ref,
    } in rows
    {
        let entry = invoices
            .entry(invoice_id)
            .or_insert_with(|| (currency, amount_minor, BTreeSet::new()));
        if let Some(kind) = origin {
            entry.2.insert(OriginView {
                kind,
                reference: origin_ref,
            });
        }
    }

    let mut buckets: BTreeMap<(String, Vec<OriginView>), (i64, i64)> = BTreeMap::new();
    for (currency, amount_minor, origins) in invoices.into_values() {
        let bucket = buckets
            .entry((currency, origins.into_iter().collect()))
            .or_insert((0, 0));
        bucket.0 += 1;
        bucket.1 += amount_minor;
    }

    let mut out: Vec<AttributionView> = buckets
        .into_iter()
        .map(
            |((currency, origins), (invoices_paid, collected_minor))| AttributionView {
                origins,
                currency,
                invoices_paid,
                collected_minor,
            },
        )
        .collect();
    // Le plus gros d'abord : c'est l'ordre dans lequel la question se pose.
    // Les deux départages ensuite, pour que deux appels identiques rendent deux
    // réponses identiques.
    out.sort_by(|a, b| {
        b.collected_minor
            .cmp(&a.collected_minor)
            .then_with(|| a.currency.cmp(&b.currency))
            .then_with(|| a.origins.cmp(&b.origins))
    });
    out
}

// ---------------------------------------------------------------------------
// Les requêtes
// ---------------------------------------------------------------------------
//
// Chaque requête : pas de `WHERE tenant_id` (RLS forcée), `$1` le premier jour,
// `$2` le lendemain du dernier, et le même seau de jour UTC que `pnl.rs` — la
// forme `(ts AT TIME ZONE 'UTC')::date` partout où la colonne est un instant.

/// Les cinq comptes qui sont un `count(*)` daté, dans l'ordre de [`STAGES`]
/// moins les deux d'[`super::outreach`].
const COUNT_SQL: [&str; 5] = [
    "SELECT count(*)::bigint FROM contacts \
      WHERE (created_at AT TIME ZONE 'UTC')::date >= $1 AND (created_at AT TIME ZONE 'UTC')::date < $2",
    "SELECT count(*)::bigint FROM sales_quotes \
      WHERE (issued_at AT TIME ZONE 'UTC')::date >= $1 AND (issued_at AT TIME ZONE 'UTC')::date < $2",
    "SELECT count(*)::bigint FROM sales_quotes \
      WHERE accepted_at IS NOT NULL \
        AND (accepted_at AT TIME ZONE 'UTC')::date >= $1 AND (accepted_at AT TIME ZONE 'UTC')::date < $2",
    "SELECT count(*)::bigint FROM invoices \
      WHERE (issued_at AT TIME ZONE 'UTC')::date >= $1 AND (issued_at AT TIME ZONE 'UTC')::date < $2",
    "SELECT count(*)::bigint FROM invoices \
      WHERE paid_at IS NOT NULL \
        AND (paid_at AT TIME ZONE 'UTC')::date >= $1 AND (paid_at AT TIME ZONE 'UTC')::date < $2",
];

/// Le compteur qu'aucun chemin d'approche ne contourne. `outreach.rs` lit la
/// même table par jour ; ici seul le total compte.
const CONTACTED_SQL: &str = "\
SELECT coalesce(sum(contacts_taken), 0)::bigint \
  FROM outreach_buckets \
 WHERE day >= $1 AND day < $2";

/// Un fil, une réponse. Les canaux et le groupement sont ceux d'`outreach.rs`,
/// repris mot pour mot : deux définitions de « a répondu » sur deux écrans
/// seraient deux chiffres qu'on oppose.
const REPLIED_SQL: &str = "\
SELECT count(DISTINCT conversation_id)::bigint \
  FROM messages \
 WHERE direction = 'inbound' \
   AND channel IN ('email', 'sms', 'whatsapp', 'voice') \
   AND (received_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (received_at AT TIME ZONE 'UTC')::date <  $2";

/// Une ligne par monnaie du registre : la fenêtre, le mois glissant, le mois
/// d'avant, et le dû de toujours. Une seule passe, pour que les cinq montants
/// ne puissent pas venir de cinq lectures décalées.
#[derive(Debug, sqlx::FromRow)]
struct RevenueRow {
    currency: String,
    invoiced: i64,
    collected: i64,
    outstanding: i64,
    mrr: i64,
    previous_mrr: i64,
}

const REVENUE_SQL: &str = "\
SELECT currency, \
       coalesce(sum(amount_minor) FILTER ( \
         WHERE (issued_at AT TIME ZONE 'UTC')::date >= $1 \
           AND (issued_at AT TIME ZONE 'UTC')::date <  $2), 0)::bigint AS invoiced, \
       coalesce(sum(amount_minor) FILTER ( \
         WHERE paid_at IS NOT NULL \
           AND (paid_at AT TIME ZONE 'UTC')::date >= $1 \
           AND (paid_at AT TIME ZONE 'UTC')::date <  $2), 0)::bigint AS collected, \
       coalesce(sum(amount_minor) FILTER (WHERE paid_at IS NULL), 0)::bigint AS outstanding, \
       coalesce(sum(amount_minor) FILTER (WHERE paid_at >= $3), 0)::bigint AS mrr, \
       coalesce(sum(amount_minor) FILTER (WHERE paid_at >= $4 AND paid_at < $3), 0)::bigint \
         AS previous_mrr \
  FROM invoices \
 GROUP BY currency";

/// Les factures réglées de la fenêtre, et les portes par lesquelles les gens de
/// leur compte sont entrés.
///
/// Les trois jointures que le schéma portait déjà, dans l'ordre :
/// `invoices.opportunity_id` (0066, `NOT NULL`), `opportunities.account_id`
/// (0011), `contacts.account_id` (0011). RLS `force` sur les trois tables, donc
/// aucun `WHERE tenant_id` et aucun compte d'une autre entreprise.
///
/// `LEFT JOIN` et non `JOIN` : une facture dont aucun contact ne dit d'où il
/// vient doit sortir d'ici avec une origine nulle, pas disparaître. Une facture
/// qui manque à cette liste serait un euro effacé, et le seau « inconnu » est
/// tout l'intérêt de la lecture.
///
/// `DISTINCT` parce que deux contacts entrés par la même porte avec la même
/// référence sont une porte, pas deux ; [`attribute`] déduplique de toute façon
/// par `BTreeSet`, et le faire ici est une ligne de moins à transporter.
///
/// Les contacts inactifs comptent. Une adresse désactivée par une suppression
/// dit toujours par où son entreprise est entrée, et l'effacer ici ferait
/// passer une facture dans « inconnu » le jour où quelqu'un se désabonne.
const ATTRIBUTION_SQL: &str = "\
SELECT DISTINCT i.id AS invoice_id, i.currency, i.amount_minor, c.origin, c.origin_ref \
  FROM invoices i \
  JOIN opportunities o ON o.id = i.opportunity_id \
  LEFT JOIN contacts c ON c.account_id = o.account_id AND c.origin IS NOT NULL \
 WHERE i.paid_at IS NOT NULL \
   AND (i.paid_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (i.paid_at AT TIME ZONE 'UTC')::date <  $2";

/// Les jetons de la fenêtre au tarif déclaré, en cents.
///
/// La multiplication est celle de `pnl.rs` mot pour mot — `/ 10000` est
/// `/ 1e6` jetons par million fois `× 100` cents par dollar, en un pas NUMERIC
/// exact — et le `GROUP BY` sur les trois colonnes de tarif est ce qui rend la
/// jointure légale ; RLS fait de `tenant_model_access` zéro ou une ligne, donc
/// il sort zéro ou une ligne.
const COST_SQL: &str = "\
SELECT round(( sum(u.input_tokens)      * coalesce(t.usd_per_mtok_input, 0) \
             + sum(u.output_tokens)     * coalesce(t.usd_per_mtok_output, 0) \
             + sum(u.cache_read_tokens) * coalesce(t.usd_per_mtok_cache_read, 0) \
             ) / 10000)::bigint \
  FROM model_usage_daily u \
  LEFT JOIN tenant_model_access t ON true \
 WHERE u.day >= $1 AND u.day < $2 \
 GROUP BY t.usd_per_mtok_input, t.usd_per_mtok_output, t.usd_per_mtok_cache_read";

const ACTIVE_SEATS_SQL: &str = "SELECT count(*)::bigint FROM employees WHERE lifecycle = 'active'";

const TARGET_SQL: &str = "SELECT mrr_minor, currency, at, set_at FROM growth_targets LIMIT 1";

// ---------------------------------------------------------------------------
// GET /v1/growth
// ---------------------------------------------------------------------------

async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<GrowthQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let days = query.days.unwrap_or(DEFAULT_DAYS);
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!(
            "days: between 1 and {MAX_DAYS}"
        )));
    }
    let now = Utc::now();
    let to = now.date_naive();
    let from = to
        .checked_sub_signed(Duration::days(days - 1))
        .unwrap_or(to);
    let end = to.succ_opt().unwrap_or(to);
    let month_ago = now - Duration::days(MONTH_DAYS);
    let two_months_ago = now - Duration::days(2 * MONTH_DAYS);

    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    // Les sept comptes. Les cinq datés d'abord, puis les deux d'`outreach`,
    // remis dans l'ordre de `STAGES` juste après.
    let mut dated = Vec::with_capacity(5);
    for sql in COUNT_SQL {
        let n: i64 = sqlx::query_scalar(sql)
            .bind(from)
            .bind(end)
            .fetch_one(&mut **tx)
            .await
            .map_err(StoreError::from)?;
        dated.push(n);
    }
    let contacted: i64 = sqlx::query_scalar(CONTACTED_SQL)
        .bind(from)
        .bind(end)
        .fetch_one(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    let replied: i64 = sqlx::query_scalar(REPLIED_SQL)
        .bind(from)
        .bind(end)
        .fetch_one(&mut **tx)
        .await
        .map_err(StoreError::from)?;

    let rows: Vec<RevenueRow> = sqlx::query_as(REVENUE_SQL)
        .bind(from)
        .bind(end)
        .bind(month_ago)
        .bind(two_months_ago)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;

    let attribution: Vec<AttributionRow> = sqlx::query_as(ATTRIBUTION_SQL)
        .bind(from)
        .bind(end)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;

    // Le tarif, lu par le même chemin que `GET /v1/model` : c'est lui qui dit
    // si le coût a un prix et si ce prix veut dire quelque chose.
    let connection = agentos_store::model_access::load(&mut tx).await?;
    let cost_minor = match agentos_store::model_access::CostSource::of(connection.as_ref()) {
        // Pas de tarif : le null est celui que `GET /v1/usage` argumente — un
        // prix qu'on n'a pas dit n'est pas gratuit. Chemin `cli` : un
        // abonnement n'a pas de facture au jeton, et `/v1/forecast` refuse le
        // même chiffre pour la même raison.
        agentos_store::model_access::CostSource::NoTariff
        | agentos_store::model_access::CostSource::DeclaredTariffOnCliPath => None,
        agentos_store::model_access::CostSource::DeclaredTariff => {
            sqlx::query_scalar(COST_SQL)
                .bind(from)
                .bind(end)
                .fetch_optional(&mut **tx)
                .await
                .map_err(StoreError::from)?
                // Aucune ligne d'usage dans la fenêtre : un tarif déclaré et
                // zéro jeton coûtent zéro, et celui-là est une mesure.
                .or(Some(0))
        }
    };
    let seats: i64 = sqlx::query_scalar(ACTIVE_SEATS_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(StoreError::from)?;

    let target = read_target_row(&mut tx).await?;
    tx.commit().await?;

    // Une seule monnaie, ou rien. Voir l'en-tête : cette route ne somme pas à
    // travers les codes ISO et ne rend pas un zéro sans monnaie.
    let single = match rows.as_slice() {
        [row] => Some(row),
        _ => None,
    };
    let revenue = single.map_or_else(RevenueView::default, |row| RevenueView {
        mrr_minor: Some(row.mrr),
        // Le code tel que le registre le porte, repassé par `Currency` pour
        // qu'un code qu'on ne sait pas nommer ne sorte pas d'ici.
        currency: row.currency.parse::<Currency>().ok().map(Currency::code),
        invoiced_minor: Some(row.invoiced),
        collected_minor: Some(row.collected),
        outstanding_minor: Some(row.outstanding),
    });

    Ok(axum::Json(GrowthView {
        days,
        window: WindowView { from, to },
        funnel: funnel([
            Some(dated[0]),
            Some(contacted),
            Some(replied),
            Some(dated[1]),
            Some(dated[2]),
            Some(dated[3]),
            Some(dated[4]),
        ]),
        verdict: verdict(
            target.as_ref(),
            revenue.mrr_minor,
            single.map(|row| row.previous_mrr),
            revenue.currency,
            now,
        ),
        cost: CostView {
            model_minor: cost_minor,
            per_seat_minor: cost_minor.filter(|_| seats > 0).map(|cost| cost / seats),
        },
        revenue,
        attribution: attribute(attribution),
        target,
        unmeasured: UNMEASURED,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// GET / PUT /v1/growth/target
// ---------------------------------------------------------------------------

/// La lecture seule de la cible, pour l'écran qui la pose et rien d'autre.
/// `GET /v1/growth` la porte déjà — celle-ci existe pour que le formulaire
/// n'ait pas à lire tout l'entonnoir pour préremplir deux champs.
async fn read_target(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let target = read_target_row(&mut tx).await?;
    tx.rollback().await?;
    Ok(axum::Json(json!({ "target": target })).into_response())
}

async fn read_target_row(
    tx: &mut agentos_store::db::TenantTx<'_>,
) -> Result<Option<TargetView>, StoreError> {
    let row: Option<(i64, String, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(TARGET_SQL)
        .fetch_optional(&mut ***tx)
        .await?;
    Ok(row.map(|(mrr_minor, currency, at, set_at)| TargetView {
        mrr_minor,
        currency,
        at,
        set_at,
    }))
}

/// Ce qu'un `PUT` accepte.
///
/// `currency` est optionnelle et vaut USD : c'est la monnaie dans laquelle le
/// fondateur a énoncé l'objectif (« 190 $, je veux 1 900 $ »), et un champ
/// obligatoire de plus sur un formulaire à deux champs est un champ de plus à
/// remplir de travers. Elle est validée par [`Currency`] et non par le CHECK de
/// la table, pour que l'appelant reçoive une phrase plutôt que le nom d'une
/// contrainte.
#[derive(Debug, Deserialize)]
struct TargetBody {
    mrr_minor: i64,
    currency: Option<String>,
    at: DateTime<Utc>,
}

/// `PUT /v1/growth/target` — le fondateur dit ce qu'il vise, et pour quand.
///
/// Un upsert sur la clé du locataire : une entreprise a une cible, pas un
/// historique d'ambitions (voir `migrations/0101`). Reposer la même cible est
/// donc idempotent à `set_at` près, et c'est `set_at` qui dit depuis quand elle
/// tient.
///
/// **L'échéance peut être dans le passé.** Une cible qu'on a manquée reste ce
/// qu'on avait visé, et refuser de la relire le lendemain de la date serait
/// refuser l'écran exactement le jour où on l'ouvre. `verdict` rend `behind`.
async fn write_target(
    State(db): State<Db>,
    principal: Principal,
    body: Result<axum::Json<TargetBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let axum::Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    if body.mrr_minor <= 0 {
        return Err(ApiError::bad_request(
            "mrr_minor: strictly positive, in minor units. A target of zero is the absence of a \
             target, and the absence of a target is the absence of a row",
        ));
    }
    let currency: Currency = body
        .currency
        .as_deref()
        .unwrap_or("USD")
        .parse()
        .map_err(|_| ApiError::bad_request("currency: an ISO 4217 code this ledger knows"))?;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    sqlx::query(
        "INSERT INTO growth_targets (tenant_id, currency, mrr_minor, at, set_at) \
              VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (tenant_id) DO UPDATE \
            SET currency = excluded.currency, \
                mrr_minor = excluded.mrr_minor, \
                at = excluded.at, \
                set_at = excluded.set_at",
    )
    .bind(principal.tenant_id.as_uuid())
    .bind(currency.code())
    .bind(body.mrr_minor)
    .bind(body.at)
    .execute(&mut **tx)
    .await
    .map_err(StoreError::from)?;
    let target = read_target_row(&mut tx).await?;
    tx.commit().await?;

    Ok(axum::Json(json!({ "target": target })).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;
    use uuid::Uuid;

    use agentos_app::effects::{Effects, QuoteDraft, QuoteIssue};
    use agentos_app::gate::{PolicyGate, Principal as GatePrincipal};
    use agentos_domain::money::Money;
    use std::sync::Arc;

    use super::*;
    use crate::auth::ApiKeys;

    /// Le nom que l'opérateur a donné à la liste dont sort le contact
    /// d'[`une_entreprise`] — c'est-à-dire l'un des cinq fichiers du fondateur,
    /// et la réponse que la lecture doit finir par prononcer.
    const LISTE: &str = "smartlead_getorizn_prospection.csv";

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // -----------------------------------------------------------------------
    // L'arithmétique, sans base
    // -----------------------------------------------------------------------

    /// **Un taux de passage est une division, et le dénominateur zéro n'en est
    /// pas une.** Le piège est de rendre `0.0`, qui se lit « personne n'est
    /// passé » là où la vérité est « personne n'est entré ».
    #[test]
    fn une_etape_non_mesurable_rend_null_et_jamais_zero() {
        let f = funnel([
            Some(40),
            Some(40),
            Some(1),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
        ]);
        assert_eq!(f.len(), 7);
        assert_eq!(f[0].to_next_rate, Some(1.0), "40 approchés sur 40 ajoutés");
        assert_eq!(f[1].to_next_rate, Some(0.025), "1 réponse sur 40 : le mur");
        // Une réponse, zéro devis : un vrai zéro, et il est mesuré.
        assert_eq!(f[2].to_next_rate, Some(0.0));
        // Zéro devis émis : le taux d'acceptation n'est pas nul, il n'existe
        // pas. C'est toute la différence que ce test garde.
        assert_eq!(f[3].to_next_rate, None);
        // La dernière étape n'a pas de suivante.
        assert_eq!(f[6].to_next_rate, None);

        // Et une étape sans table qui en fasse foi rend `null` plutôt qu'un
        // zéro — y compris pour le taux de celle qui la précède, qui perd son
        // numérateur.
        let trou = funnel([Some(10), None, Some(3), None, None, None, None]);
        assert_eq!(trou[1].count, None);
        assert_eq!(
            trou[0].to_next_rate, None,
            "un numérateur absent n'est pas 0"
        );
        assert_eq!(
            trou[1].to_next_rate, None,
            "et un dénominateur absent non plus"
        );
    }

    /// **Le verdict aux trois bornes**, sur la société du fondateur : 190 $ de
    /// mrr, 1 900 $ visés, et un mois exactement pour y arriver. Il faut donc
    /// ajouter 1 710 $ dans le mois.
    #[test]
    fn le_verdict_compare_deux_rythmes_et_pas_deux_totaux() {
        let now = Utc::now();
        let cible = TargetView {
            mrr_minor: 190_000,
            currency: "USD".to_owned(),
            at: now + Duration::days(MONTH_DAYS),
            set_at: now - Duration::days(7),
        };
        let mrr = 19_000;
        // Requis : (190 000 − 19 000) / 1 mois = 171 000 par mois.
        let dit = |ajoute: i64| {
            verdict(
                Some(&cible),
                Some(mrr),
                Some(mrr - ajoute),
                Some("USD"),
                now,
            )
        };
        assert_eq!(dit(200_000), Verdict::Ahead, "plus de 10 % au-dessus");
        assert_eq!(
            dit(171_000),
            Verdict::OnTrack,
            "exactement le rythme requis"
        );
        assert_eq!(dit(160_000), Verdict::OnTrack, "à moins de 10 % en dessous");
        assert_eq!(dit(10_000), Verdict::Behind, "le cas d'Orizn aujourd'hui");
        assert_eq!(dit(0), Verdict::Behind, "rien ajouté ce mois-ci");

        // La cible atteinte l'emporte sur tout rythme, y compris nul.
        assert_eq!(
            verdict(Some(&cible), Some(190_000), Some(190_000), Some("USD"), now),
            Verdict::Ahead
        );
        // L'échéance passée sans la cible est un fait, pas un rythme.
        let echue = TargetView {
            mrr_minor: cible.mrr_minor,
            currency: cible.currency.clone(),
            at: now - Duration::days(1),
            set_at: cible.set_at,
        };
        assert_eq!(
            verdict(Some(&echue), Some(mrr), Some(0), Some("USD"), now),
            Verdict::Behind
        );

        // Et les trois façons de n'avoir rien à comparer.
        assert_eq!(
            verdict(None, Some(mrr), Some(0), Some("USD"), now),
            Verdict::NoTarget
        );
        assert_eq!(
            verdict(Some(&cible), None, None, None, now),
            Verdict::NoTarget,
            "un registre multi-monnaie n'a pas de mrr à comparer"
        );
        assert_eq!(
            verdict(Some(&cible), Some(mrr), Some(0), Some("EUR"), now),
            Verdict::NoTarget,
            "une cible en dollars contre un registre en euros n'est pas un retard"
        );
    }

    /// **Une facture n'est comptée qu'une fois, quel que soit le nombre de
    /// contacts de son compte.**
    ///
    /// C'est le seul piège de cette section et il est silencieux : la jointure
    /// rend une ligne par (facture, origine), et un `sum()` naïf sur ces
    /// lignes-là ferait de 190 $ encaissés 380 $ attribués. Un écran qui
    /// invente de la recette au moment où on lui demande d'où elle vient est
    /// pire que pas d'écran du tout.
    #[test]
    fn une_facture_a_deux_contacts_ne_compte_pas_deux_fois() {
        let facture = Uuid::now_v7();
        let ligne = |origin: Option<&str>, reference: Option<&str>| AttributionRow {
            invoice_id: facture,
            currency: "USD".to_owned(),
            amount_minor: 19_000,
            origin: origin.map(str::to_owned),
            origin_ref: reference.map(str::to_owned),
        };

        // Deux contacts, **une** porte : un seau, une facture, 190 $.
        let net = attribute(vec![
            ligne(Some("import"), Some("getorizn.csv")),
            ligne(Some("import"), Some("getorizn.csv")),
        ]);
        assert_eq!(net.len(), 1);
        assert_eq!(net[0].invoices_paid, 1);
        assert_eq!(net[0].collected_minor, 19_000, "et surtout pas 38 000");
        assert_eq!(net[0].origins.len(), 1);

        // Deux portes : la chaîne se scinde. Les deux sont rendues, dans **un**
        // seau, et l'argent n'est réparti entre aucune des deux — pas de
        // 9 500 $ chacune, qui serait un chiffre que personne n'a mesuré.
        let scindee = attribute(vec![
            ligne(Some("import"), Some("getorizn.csv")),
            ligne(Some("discovery"), Some("https://ectaa.org/members")),
        ]);
        assert_eq!(scindee.len(), 1);
        assert_eq!(scindee[0].invoices_paid, 1);
        assert_eq!(scindee[0].collected_minor, 19_000);
        assert_eq!(scindee[0].origins.len(), 2, "dis-le, et rends les deux");

        // Aucune porte : la liste est **vide**, ce qui se lit « inconnu ». Il
        // n'existe aucun seau « organique » et c'est délibéré.
        let inconnue = attribute(vec![ligne(None, None)]);
        assert_eq!(inconnue.len(), 1);
        assert!(inconnue[0].origins.is_empty());
        assert_eq!(inconnue[0].collected_minor, 19_000);

        // Deux monnaies ne se somment pas : deux seaux, jamais un total.
        let deux = attribute(vec![
            ligne(Some("import"), Some("a.csv")),
            AttributionRow {
                invoice_id: Uuid::now_v7(),
                currency: "EUR".to_owned(),
                amount_minor: 5_000,
                origin: Some("import".to_owned()),
                origin_ref: Some("a.csv".to_owned()),
            },
        ]);
        assert_eq!(deux.len(), 2);
        assert_eq!(deux[0].currency, "USD", "le plus gros d'abord");
        assert_eq!(deux[1].currency, "EUR");

        // Et rien du tout rend rien du tout : pas un seau vide à zéro, qui se
        // lirait comme une mesure.
        assert!(attribute(Vec::new()).is_empty());
    }

    // -----------------------------------------------------------------------
    // Le harnais
    // -----------------------------------------------------------------------

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; a funnel is a SQL question");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");

            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        async fn call(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
            if body.is_some() {
                req = req.header(header::CONTENT_TYPE, "application/json");
            }
            let req = req
                .body(match &body {
                    Some(value) => Body::from(value.to_string()),
                    None => Body::empty(),
                })
                .expect("request");
            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        async fn get(&self, uri: &str, secret: &str) -> (StatusCode, Value) {
            self.call("GET", uri, secret, None).await
        }

        async fn teardown(self) {
            for tenant in [self.a, self.b] {
                let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
                sqlx::query("DELETE FROM tenants WHERE id = $1")
                    .bind(tenant.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .expect("delete tenant");
                tx.commit().await.expect("commit");
            }
        }
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'growth-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// **Une entreprise entière, d'un inconnu à un règlement.**
    ///
    /// Écrite en SQL brut et non par les verbes du store pour une raison :
    /// aucun de ces verbes ne laisse dater le passé, et un entonnoir qui ne
    /// sait mesurer qu'aujourd'hui est un entonnoir qu'on ne peut pas tester.
    /// Les colonnes écrites sont exactement celles que les sept requêtes lisent.
    async fn une_entreprise(db: &Db, tenant: TenantId) -> EmployeeId {
        let seat = EmployeeId::new_v7(Utc::now());
        let account = Uuid::now_v7();
        let contact = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let conversation = Uuid::now_v7();
        let quote = Uuid::now_v7();
        let invoice = Uuid::now_v7();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let t = tenant.as_uuid();

        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'Lena', 'active')",
        )
        .bind(seat.as_uuid())
        .bind(t)
        .bind(format!("lena-{}", seat.as_uuid().simple()))
        .execute(&mut **tx)
        .await
        .expect("employee");

        // 1. Un prospect ajouté.
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Buyer plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(t)
        .bind(format!("buyer-{}.example", account.simple()))
        .execute(&mut **tx)
        .await
        .expect("account");
        // Et son origine, qui est le maillon que `0107` a posé : sans elle, tout
        // ce qui suit se compte et rien ne se remonte.
        sqlx::query(
            "INSERT INTO contacts \
                 (id, tenant_id, account_id, full_name, email, origin, origin_ref) \
             VALUES ($1, $2, $3, 'Ada', $4, 'import', $5)",
        )
        .bind(contact)
        .bind(t)
        .bind(account)
        .bind(format!("ada-{}@buyer.example", contact.simple()))
        .bind(LISTE)
        .execute(&mut **tx)
        .await
        .expect("contact");

        // 2. Un contact réservé — le créneau qu'`outreach::reserve` prend.
        sqlx::query(
            "INSERT INTO outreach_buckets (tenant_id, employee_id, day, contacts_taken) \
             VALUES ($1, $2, current_date, 1)",
        )
        .bind(t)
        .bind(seat.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("bucket");

        // 3. Une réponse : un fil, un message entrant.
        sqlx::query(
            "INSERT INTO conversations (id, tenant_id, employee_id, channel, subject) \
             VALUES ($1, $2, $3, 'email', 'Re: bonjour')",
        )
        .bind(conversation)
        .bind(t)
        .bind(seat.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("conversation");
        sqlx::query(
            "INSERT INTO messages \
                 (id, tenant_id, conversation_id, employee_id, channel, direction, sender, body, \
                  idempotency_key, received_at) \
             VALUES ($1, $2, $3, $4, 'email', 'inbound', 'ada@buyer.example', 'oui', $5, now())",
        )
        .bind(Uuid::now_v7())
        .bind(t)
        .bind(conversation)
        .bind(seat.as_uuid())
        .bind(conversation.to_string())
        .execute(&mut **tx)
        .await
        .expect("message");

        // 3 bis. La séquence qui a écrit à cette personne. Elle ne change aucun
        // des sept comptes et elle n'est pas lue par l'attribution : elle est
        // là pour que la chaîne du test soit celle de la vie — quelqu'un est
        // entré par une liste, une séquence lui a écrit, il a répondu — et non
        // une ligne de `contacts` posée à côté d'une facture.
        let sequence = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO sequences (id, tenant_id, name, steps) \
             VALUES ($1, $2, $3, '[]'::jsonb)",
        )
        .bind(sequence)
        .bind(t)
        .bind(format!("relance-{}", sequence.simple()))
        .execute(&mut **tx)
        .await
        .expect("sequence");
        sqlx::query(
            "INSERT INTO sequence_runs \
                 (id, tenant_id, sequence_id, contact_id, employee_id, conversation_id, state) \
             VALUES ($1, $2, $3, $4, $5, $6, 'replied')",
        )
        .bind(Uuid::now_v7())
        .bind(t)
        .bind(sequence)
        .bind(contact)
        .bind(seat.as_uuid())
        .bind(conversation)
        .execute(&mut **tx)
        .await
        .expect("sequence run");

        // 4 et 5. Un devis émis, et accepté.
        sqlx::query(
            "INSERT INTO opportunities \
                 (id, tenant_id, account_id, stage, currency, value_minor, approval_id, closed_at) \
             VALUES ($1, $2, $3, 'closed_won', 'USD', 19000, $4, now())",
        )
        .bind(opportunity)
        .bind(t)
        .bind(account)
        .bind(Uuid::now_v7())
        .execute(&mut **tx)
        .await
        .expect("opportunity");
        sqlx::query(
            "INSERT INTO sales_quotes \
                 (id, tenant_id, opportunity_id, issued_by, currency, amount_minor, memo, \
                  valid_until, accepted_at) \
             VALUES ($1, $2, $3, $4, 'USD', 19000, 'un mois', now() + interval '30 days', now())",
        )
        .bind(quote)
        .bind(t)
        .bind(opportunity)
        .bind(seat.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("quote");

        // 6 et 7. Une facture émise, et réglée.
        sqlx::query(
            "INSERT INTO invoices \
                 (id, tenant_id, opportunity_id, issued_by, currency, amount_minor, memo, \
                  number, paid_at) \
             VALUES ($1, $2, $3, $4, 'USD', 19000, 'un mois', 1, now())",
        )
        .bind(invoice)
        .bind(t)
        .bind(opportunity)
        .bind(seat.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("invoice");

        tx.commit().await.expect("commit");
        seat
    }

    /// **La couture que ce chantier existe pour fermer : un devis proposé par
    /// un employé apparaît dans l'entonnoir.**
    ///
    /// Les deux étapes du milieu — `quotes_issued` et `quotes_accepted` — ont
    /// compté zéro quoi que fasse l'entreprise tant que rien ne pouvait créer un
    /// devis : les tables, le SQL, le PDF et trois outils de lecture existaient,
    /// et aucun chemin d'écriture. `UNMEASURED` le disait dans le corps de la
    /// réponse.
    ///
    /// Ce test mesure l'avant et l'après du même entonnoir, sur la même
    /// entreprise, dans la même fenêtre. Rien n'est inséré en SQL au milieu :
    /// c'est `agentos_app::effects::Effects::propose_quote` qui écrit, derrière
    /// un jeton que la Policy Gate a frappé pour ce siège — donc ce qui est
    /// affirmé ici est le chemin entier, du refus possible jusqu'au compte.
    #[tokio::test]
    async fn un_devis_propose_par_un_employe_fait_avancer_lentonnoir() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (seat, opportunity) = un_siege_et_une_affaire(&h.db, h.a).await;

        // Avant : l'étape existe, elle est mesurée, et elle vaut zéro.
        let (status, avant) = h.get("/v1/growth", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{avant}");
        assert_eq!(avant["funnel"][3]["stage"], "quotes_issued");
        assert_eq!(
            avant["funnel"][3]["count"], 0,
            "un vrai zéro mesuré, et pas une absence de table"
        );

        let principal = GatePrincipal::employee(h.a, seat);
        let effects = Effects::new(
            h.db.clone(),
            Arc::new(agentos_app::mocks::ports()),
            principal.clone(),
        );
        let token = PolicyGate::new(h.db.clone())
            .authorize(
                &principal,
                QuoteIssue {
                    amount: Money::new(19_000, Currency::Usd).expect("non nul"),
                },
            )
            .await
            .expect("la couche du locataire ouvre Channel::Email");
        effects
            .propose_quote(
                token,
                &QuoteDraft {
                    opportunity_id: opportunity,
                    memo: "Trois mois de veille".to_owned(),
                    valid_until: Utc::now() + Duration::days(30),
                    supersedes: None,
                    lines: Vec::new(),
                },
            )
            .await
            .expect("un employé propose un devis");

        // Après : la quatrième étape compte un, et le taux de la troisième
        // cesse d'être `null` — c'est-à-dire que l'entonnoir cesse d'être coupé
        // en deux à cet endroit.
        let (status, apres) = h.get("/v1/growth", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{apres}");
        assert_eq!(apres["funnel"][3]["count"], 1, "{apres}");
        assert_eq!(
            apres["funnel"][2]["to_next_rate"],
            json!(1.0),
            "une réponse, un devis"
        );
        // Et l'acceptation reste à zéro : c'est un acte d'opérateur, sur
        // `POST /v1/quotes/{id}/accepted`, et cet effet ne le touche pas.
        assert_eq!(apres["funnel"][4]["count"], 0);

        h.teardown().await;
    }

    /// Un siège, un compte, un contact qui a répondu, et une affaire **en
    /// négociation**.
    ///
    /// Pas `closed_won` : un devis est ce qui arrive *avant* la clôture, et une
    /// fixture qui gagnerait l'affaire d'abord testerait le mauvais moment.
    async fn un_siege_et_une_affaire(db: &Db, tenant: TenantId) -> (EmployeeId, Uuid) {
        let seat = EmployeeId::new_v7(Utc::now());
        let account = Uuid::now_v7();
        let conversation = Uuid::now_v7();
        let opportunity = Uuid::now_v7();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let t = tenant.as_uuid();
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'Lena', 'active')",
        )
        .bind(seat.as_uuid())
        .bind(t)
        .bind(format!("lena-{}", seat.as_uuid().simple()))
        .execute(&mut **tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Buyer plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(t)
        .bind(format!("buyer-{}.example", account.simple()))
        .execute(&mut **tx)
        .await
        .expect("account");
        // Une réponse, pour que l'étape qui précède le devis ne soit pas nulle :
        // un taux de passage sans dénominateur n'est pas zéro, il n'existe pas,
        // et c'est lui que l'assertion d'après lit.
        sqlx::query(
            "INSERT INTO conversations (id, tenant_id, employee_id, channel, subject) \
             VALUES ($1, $2, $3, 'email', 'Re: bonjour')",
        )
        .bind(conversation)
        .bind(t)
        .bind(seat.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("conversation");
        sqlx::query(
            "INSERT INTO messages \
                 (id, tenant_id, conversation_id, employee_id, channel, direction, sender, body, \
                  idempotency_key, received_at) \
             VALUES ($1, $2, $3, $4, 'email', 'inbound', 'ada@buyer.example', 'oui', $5, now())",
        )
        .bind(Uuid::now_v7())
        .bind(t)
        .bind(conversation)
        .bind(seat.as_uuid())
        .bind(conversation.to_string())
        .execute(&mut **tx)
        .await
        .expect("message");
        sqlx::query(
            "INSERT INTO opportunities (id, tenant_id, account_id, stage, currency, value_minor) \
             VALUES ($1, $2, $3, 'negotiation', 'USD', 19000)",
        )
        .bind(opportunity)
        .bind(t)
        .bind(account)
        .execute(&mut **tx)
        .await
        .expect("opportunity");
        tx.commit().await.expect("commit");

        // La couche du locataire : le courriel, et rien d'autre. C'est le canal
        // qu'`always_denies(QuoteIssue)` lit — un siège dont une couche le ferme
        // ne peut pas nommer de prix, ce que `crates/app` affirme de son côté.
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &agentos_domain::policy::PolicyLimits {
                allowed_channels: std::collections::BTreeSet::from([
                    agentos_domain::action::Channel::Email,
                ]),
                ..agentos_domain::policy::PolicyLimits::default()
            },
        )
        .await
        .expect("installer la politique");

        (seat, opportunity)
    }

    /// **L'entonnoir de bout en bout**, sur une entreprise fabriquée étape par
    /// étape : sept comptes à un, six taux à un, et la recette qui suit.
    #[tokio::test]
    async fn lentonnoir_compte_les_sept_etapes_et_leurs_taux_de_passage() {
        let Some(h) = Harness::new().await else {
            return;
        };
        une_entreprise(&h.db, h.a).await;

        let (status, body) = h.get("/v1/growth", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let funnel = body["funnel"].as_array().expect("funnel");
        assert_eq!(funnel.len(), 7);
        for (i, stage) in funnel.iter().enumerate() {
            assert_eq!(stage["stage"], STAGES[i]);
            assert_eq!(stage["count"], 1, "étape {} : {stage}", STAGES[i]);
            // Un sur un, sauf la dernière qui n'a pas de suivante.
            assert_eq!(
                stage["to_next_rate"],
                if i == 6 { Value::Null } else { json!(1.0) },
                "taux de {}",
                STAGES[i]
            );
        }

        // La recette suit la facture, et la monnaie est celle du registre.
        assert_eq!(body["revenue"]["currency"], "USD");
        assert_eq!(body["revenue"]["invoiced_minor"], 19_000);
        assert_eq!(body["revenue"]["collected_minor"], 19_000);
        assert_eq!(body["revenue"]["outstanding_minor"], 0);
        assert_eq!(
            body["revenue"]["mrr_minor"], 19_000,
            "190 $ sur trente jours"
        );

        // Aucun tarif déclaré : le coût est absent, et ce n'est pas zéro.
        assert_eq!(body["cost"]["model_minor"], Value::Null);
        assert_eq!(body["cost"]["per_seat_minor"], Value::Null);

        // Aucune cible posée.
        assert_eq!(body["target"], Value::Null);
        assert_eq!(body["verdict"], "no_target");
        assert!(
            !body["unmeasured"]
                .as_array()
                .expect("unmeasured")
                .is_empty()
        );

        h.teardown().await;
    }

    /// **La cible se pose, se relit, et fait basculer le verdict.**
    #[tokio::test]
    async fn une_cible_posee_change_le_verdict_et_ne_sort_pas_du_locataire() {
        let Some(h) = Harness::new().await else {
            return;
        };
        une_entreprise(&h.db, h.a).await;

        // Rien avant qu'on ne pose.
        let (status, body) = h.get("/v1/growth/target", SECRET_A).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["target"], Value::Null);

        // 1 900 $ dans un mois, contre 190 $ encaissés : 1 710 $ à ajouter, et
        // rien n'a été ajouté le mois dernier.
        let at = (Utc::now() + Duration::days(30)).to_rfc3339();
        let (status, body) = h
            .call(
                "PUT",
                "/v1/growth/target",
                SECRET_A,
                Some(json!({ "mrr_minor": 190_000, "at": at })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["target"]["mrr_minor"], 190_000);
        assert_eq!(body["target"]["currency"], "USD");

        let (_, body) = h.get("/v1/growth", SECRET_A).await;
        assert_eq!(body["verdict"], "behind", "190 sur 1900 en un mois");
        assert_eq!(body["target"]["mrr_minor"], 190_000);

        // Une cible atteinte : le verdict bascule sans que rien d'autre bouge.
        let (status, _) = h
            .call(
                "PUT",
                "/v1/growth/target",
                SECRET_A,
                Some(json!({ "mrr_minor": 1_000, "at": at })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = h.get("/v1/growth", SECRET_A).await;
        assert_eq!(body["verdict"], "ahead");

        // Zéro est l'absence de cible, et il se dit plutôt que de s'écrire.
        let (status, _) = h
            .call(
                "PUT",
                "/v1/growth/target",
                SECRET_A,
                Some(json!({ "mrr_minor": 0, "at": at })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // **RLS.** L'autre entreprise ne voit ni la cible ni l'entonnoir : pas
        // filtrés, invisibles.
        let (status, body) = h.get("/v1/growth/target", SECRET_B).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["target"],
            Value::Null,
            "la cible d'autrui est invisible"
        );
        let (_, body) = h.get("/v1/growth", SECRET_B).await;
        for stage in body["funnel"].as_array().expect("funnel") {
            assert_eq!(stage["count"], 0, "{stage}");
        }
        assert_eq!(body["revenue"]["currency"], Value::Null);
        assert_eq!(body["verdict"], "no_target");

        h.teardown().await;
    }

    /// **Un euro remonte jusqu'à sa cause, et un euro sans chaîne se lit
    /// `null` plutôt que d'être rangé au hasard.**
    ///
    /// Les trois faits, sur la même entreprise et dans la même fenêtre :
    ///
    /// 1. une personne entrée par une liste nommée, une séquence qui lui écrit,
    ///    une réponse, une affaire, un devis accepté, une facture réglée — et
    ///    la lecture qui prononce le nom du fichier ;
    /// 2. une seconde facture, réglée elle aussi, dont aucun contact ne dit
    ///    d'où il vient : elle sort dans un seau aux origines **vides**, pas
    ///    dans le premier et pas dans un seau « organique » ;
    /// 3. la somme des seaux est exactement `collected_minor`. C'est
    ///    l'invariant qui rend la section utilisable : une attribution qui ne
    ///    boucle pas sur la recette est une attribution qu'on ne peut pas citer.
    ///
    /// Puis la chaîne se scinde, et les deux origines sortent ensemble sans que
    /// l'argent soit divisé.
    #[tokio::test]
    async fn un_euro_remonte_jusqua_son_origine_et_un_euro_sans_chaine_reste_inconnu() {
        let Some(h) = Harness::new().await else {
            return;
        };
        une_entreprise(&h.db, h.a).await;
        let orpheline = une_facture_sans_origine(&h.db, h.a).await;

        let (status, body) = h.get("/v1/growth", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let seaux = body["attribution"].as_array().expect("attribution");
        assert_eq!(seaux.len(), 2, "{body}");

        // Le plus gros d'abord, et c'est celui qui a un nom.
        assert_eq!(seaux[0]["collected_minor"], 19_000);
        assert_eq!(seaux[0]["invoices_paid"], 1);
        assert_eq!(seaux[0]["currency"], "USD");
        assert_eq!(seaux[0]["origins"][0]["kind"], "import");
        assert_eq!(
            seaux[0]["origins"][0]["reference"], LISTE,
            "la lecture nomme le fichier, pas « une liste »"
        );

        // Et celui qui n'en a pas : une liste vide, et surtout pas un seau
        // nommé qui aurait rangé cet euro quelque part.
        assert_eq!(seaux[1]["collected_minor"], orpheline);
        assert_eq!(
            seaux[1]["origins"],
            json!([]),
            "inconnu se dit en ne disant rien, jamais « organique »"
        );

        // L'invariant : les seaux bouclent sur la recette de la fenêtre.
        let somme: i64 = seaux
            .iter()
            .map(|seau| seau["collected_minor"].as_i64().expect("un montant"))
            .sum();
        assert_eq!(
            somme, body["revenue"]["collected_minor"],
            "la somme des origines est l'encaissé de la fenêtre, sans reste"
        );
        let factures: i64 = seaux
            .iter()
            .map(|seau| seau["invoices_paid"].as_i64().expect("un compte"))
            .sum();
        assert_eq!(
            factures, body["funnel"][6]["count"],
            "et autant de factures que la septième étape en compte"
        );

        // **La chaîne se scinde.** Un second contact au même compte, entré par
        // l'autre porte : la facture porte désormais deux origines, dans un
        // seul seau, et son montant ne bouge pas d'un cent.
        un_second_contact_decouvert(&h.db, h.a).await;
        let (_, body) = h.get("/v1/growth", SECRET_A).await;
        let seaux = body["attribution"].as_array().expect("attribution");
        assert_eq!(seaux.len(), 2, "{body}");
        assert_eq!(seaux[0]["collected_minor"], 19_000, "toujours 190 $");
        assert_eq!(seaux[0]["invoices_paid"], 1);
        let origines = seaux[0]["origins"].as_array().expect("origins");
        assert_eq!(origines.len(), 2, "les deux, et pas la moitié de chacune");
        assert_eq!(origines[0]["kind"], "discovery");
        assert_eq!(origines[1]["kind"], "import");

        // Et l'invariant tient encore : rien n'a été inventé en route.
        let somme: i64 = seaux
            .iter()
            .map(|seau| seau["collected_minor"].as_i64().expect("un montant"))
            .sum();
        assert_eq!(somme, body["revenue"]["collected_minor"]);

        // **RLS.** L'attribution d'autrui n'est pas filtrée, elle est invisible.
        let (_, body) = h.get("/v1/growth", SECRET_B).await;
        assert_eq!(body["attribution"], json!([]));

        h.teardown().await;
    }

    /// Un second compte, une affaire, une facture réglée — et **personne** dont
    /// on sache d'où il vient. C'est le cas ordinaire d'une base écrite avant
    /// `0107`, et le cas qu'il ne faut ranger nulle part.
    ///
    /// Rend le montant, pour que l'assertion ne le réécrive pas.
    async fn une_facture_sans_origine(db: &Db, tenant: TenantId) -> i64 {
        const MONTANT: i64 = 7_000;
        let seat = EmployeeId::new_v7(Utc::now());
        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let t = tenant.as_uuid();
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'Sam', 'active')",
        )
        .bind(seat.as_uuid())
        .bind(t)
        .bind(format!("sam-{}", seat.as_uuid().simple()))
        .execute(&mut **tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Orphan plc', $3, 'ota', 'FR')",
        )
        .bind(account)
        .bind(t)
        .bind(format!("orphan-{}.example", account.simple()))
        .execute(&mut **tx)
        .await
        .expect("account");
        // Un contact bien réel, et sans origine : la colonne existe, personne
        // ne l'a remplie, et c'est très exactement « on ne sait pas ».
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, account_id, full_name, email) \
             VALUES ($1, $2, $3, 'Noa', $4)",
        )
        .bind(Uuid::now_v7())
        .bind(t)
        .bind(account)
        .bind(format!("noa-{}@orphan.example", account.simple()))
        .execute(&mut **tx)
        .await
        .expect("contact");
        sqlx::query(
            "INSERT INTO opportunities \
                 (id, tenant_id, account_id, stage, currency, value_minor, approval_id, closed_at) \
             VALUES ($1, $2, $3, 'closed_won', 'USD', $4, $5, now())",
        )
        .bind(opportunity)
        .bind(t)
        .bind(account)
        .bind(MONTANT)
        .bind(Uuid::now_v7())
        .execute(&mut **tx)
        .await
        .expect("opportunity");
        sqlx::query(
            "INSERT INTO invoices \
                 (id, tenant_id, opportunity_id, issued_by, currency, amount_minor, memo, \
                  number, paid_at) \
             VALUES ($1, $2, $3, $4, 'USD', $5, 'un mois', 2, now())",
        )
        .bind(Uuid::now_v7())
        .bind(t)
        .bind(opportunity)
        .bind(seat.as_uuid())
        .bind(MONTANT)
        .execute(&mut **tx)
        .await
        .expect("invoice");
        tx.commit().await.expect("commit");
        MONTANT
    }

    /// Une seconde personne au compte d'[`une_entreprise`], trouvée sur une
    /// page d'annuaire. Le compte a maintenant deux portes et une seule
    /// facture : c'est la scission.
    async fn un_second_contact_decouvert(db: &Db, tenant: TenantId) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO contacts \
                 (id, tenant_id, account_id, full_name, email, origin, origin_ref) \
             SELECT $1, $2, a.id, '', $3, 'discovery', 'https://ectaa.org/members' \
               FROM accounts a WHERE a.legal_name = 'Buyer plc'",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(format!("info-{}@buyer.example", id.simple()))
        .execute(&mut **tx)
        .await
        .expect("contact découvert");
        tx.commit().await.expect("commit");
    }

    /// La fenêtre est bornée des deux côtés, et le dire est moins cher qu'un
    /// `count(*)` sur dix ans.
    #[tokio::test]
    async fn la_fenetre_est_bornee() {
        let Some(h) = Harness::new().await else {
            return;
        };
        for bad in [
            "/v1/growth?days=0",
            "/v1/growth?days=366",
            "/v1/growth?days=x",
        ] {
            let (status, _) = h.get(bad, SECRET_A).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }
        let (status, body) = h.get("/v1/growth?days=7", SECRET_A).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["days"], 7);
        h.teardown().await;
    }
}
