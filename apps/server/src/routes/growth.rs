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
    "quotes_issued et quotes_accepted ne se remplissent que depuis Rust : il n'existe aucune \
     route qui émette un devis (voir routes::quotes), donc un devis négocié hors du système \
     n'y est pas. Une entreprise qui vend au téléphone lit deux zéros au milieu de son \
     entonnoir sans que rien ne soit cassé.",
    "outstanding_minor porte tout le registre et non la fenêtre : une créance de l'an dernier \
     y est encore. C'est le seul des cinq montants qui ne se compare pas aux quatre autres.",
    "mrr_minor est une recette de trente jours glissants, pas un abonnement : rien dans ce \
     schéma ne porte de récurrence. Un client qui paie deux fois en un mois le double, et un \
     client qui paie d'avance pour un trimestre le triple.",
    "Les cinq montants sont null ensemble dès que le registre emploie plus d'une monnaie : \
     cette route ne somme jamais à travers les codes ISO, et aucun taux de change n'est \
     fourni. Ils sont null aussi quand il n'existe aucune facture.",
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

    use super::*;
    use crate::auth::ApiKeys;

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
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, account_id, full_name, email) \
             VALUES ($1, $2, $3, 'Ada', $4)",
        )
        .bind(contact)
        .bind(t)
        .bind(account)
        .bind(format!("ada-{}@buyer.example", contact.simple()))
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
