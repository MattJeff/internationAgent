//! `/v1/quotes` : le fondateur lit ce qui a été proposé, et dit ce que le client
//! en a répondu.
//!
//! `migrations/0090_un_devis_est_un_document_revisable.sql` argumente les
//! tables, `agentos_store::quotes` est le SQL et `agentos_app::quote_document`
//! écrit le PDF. Ceci est la seule surface qui lit l'un ou l'autre, et la seule
//! qui écrit `accepted_at` et `declined_at`.
//!
//! # Il n'y a pas de `POST /v1/quotes`, et c'est le même refus que
//! `routes::invoices`
//!
//! **La seule façon qu'un devis existe est qu'un employé le propose**, avec un
//! jeton que la Policy Gate a émis pour lui — la forme exacte est dans le
//! rapport de cette vague, à poser dans `agentos_app::effects` à côté de
//! `issue_invoice`. Une route d'opérateur qui émettrait serait une seconde voie
//! sans décision derrière elle : un document commercial parti au nom de
//! l'entreprise, indiscernable dans la table d'un document qu'un employé était
//! autorisé à envoyer. `work_items` a accepté exactement cette ambiguïté et l'a
//! payée avec la colonne `posted_by` de `0064` ; cette table la refuse d'entrée.
//!
//! Le coût est réel et il est nommé : tant que l'effet n'est pas écrit, le
//! registre ne se remplit que depuis Rust. Le point d'accès qui masquerait cela
//! est celui que ce module refuse d'être.
//!
//! # Pourquoi la réponse du client est un acte d'opérateur, jamais d'employé
//!
//! Rien dans ce processus n'observe un accord. Un client qui dit oui le dit au
//! téléphone, dans un courriel, ou en signant — et aucun des trois n'arrive ici
//! comme un fait mesuré. Il est **affirmé**, et la séparation des tâches est
//! celle que `POST /v1/invoices/{id}/paid` a déjà argumentée : le siège qui a
//! proposé le devis ne doit pas être la chose qui déclare qu'il a été accepté.
//! Un employé qui pourrait accepter ses propres devis a un pipeline impeccable
//! et pas un client.
//!
//! C'est aussi pourquoi il n'y a pas d'`ActionKind::QuoteAccepted` :
//! l'autorité est la même que celle qui écrit les chartes et les cadences — une
//! clé d'API, pas un principal sur lequel la gate statue.
//!
//! **Le jour où une signature électronique arrive**, l'écrivain de ces deux
//! colonnes n'est toujours pas un employé : c'est un webhook, comme Stripe
//! écrit `paid_at` aujourd'hui (`agentos_app::stripe`). L'entrée `docusign` de
//! `agentos_app::catalog` est le connecteur, et ce que la table gagne ce
//! jour-là est une colonne `accepted_source` — parce que « qui l'a dit » aura
//! deux réponses pour la première fois.
//!
//! # Ce que ce module ne fait pas encore, et où c'est dû
//!
//! Le journal, lui, est écrit depuis le 2026-09-11 : `AuditKind::QuoteAnswered`,
//! dans la transaction qui répond, avec `{"quote_id": …, "answer":
//! "accepted"|"declined", "source": "operator"}` — la forme exacte du payload
//! de `paid`. La colonne reste la trace inaltérable que `0090` garantit ; la
//! ligne d'audit est ce qui rend la décision visible depuis `GET /v1/events`.

use agentos_domain::revenue::QuoteId;
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::Db;
use agentos_store::quotes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// Les routes de cette unité. Fusionnées dans le routeur d'API, donc elles
/// héritent de l'authentification, de la limite de débit et de la couche
/// d'idempotence de `with_api_stack`.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/quotes", get(register))
        .route("/v1/quotes/{id}/accepted", post(accepted))
        .route("/v1/quotes/{id}/declined", post(declined))
        .with_state(db)
}

/// Un devis, tel que le fondateur le relit.
///
/// Le montant est rendu en unités mineures et en code plutôt que formaté, pour
/// la raison de `routes::invoices` : un chiffre mis en forme est une décision de
/// présentation, et ce point d'accès rapporte ce qu'il a mesuré.
#[derive(Serialize)]
struct QuoteView {
    id: Uuid,
    /// L'affaire chiffrée. Pas nécessairement gagnée : un devis vient avant.
    opportunity_id: Uuid,
    /// Le siège qui a proposé.
    issued_by: Uuid,
    /// 1 pour un original, +1 par révision.
    version: i32,
    /// Le devis que celui-ci remplace, et c'est ce qui en fait une révision.
    supersedes_quote_id: Option<Uuid>,
    amount_minor: u64,
    currency: &'static str,
    memo: String,
    issued_at: DateTime<Utc>,
    /// **Jusqu'à quand l'offre tient.** La mention qu'une facture n'a pas.
    valid_until: DateTime<Utc>,
    /// Vrai quand `valid_until` est passé. Calculé à la lecture et jamais
    /// stocké — voir `0090` : une colonne d'état serait fausse pendant
    /// l'intervalle où elle compte, c'est à dire entre la péremption et le
    /// passage du balai qui l'écrirait.
    expired: bool,
    accepted_at: Option<DateTime<Utc>>,
    declined_at: Option<DateTime<Utc>>,
    lines: Vec<LineView>,
}

/// Une ligne du document. Les colonnes de `invoice_lines`, parce que c'est la
/// même arithmétique — voir `agentos_store::quotes`.
#[derive(Serialize)]
struct LineView {
    description: String,
    amount_minor: i64,
    tax_rate_bp: Option<i32>,
}

impl QuoteView {
    fn of(quote: quotes::Quote, now: DateTime<Utc>) -> Self {
        // Before the row is taken apart: `is_expired_at` borrows it, and the
        // fields below move out of it.
        let expired = quote.is_expired_at(now);
        Self {
            id: quote.id.as_uuid(),
            opportunity_id: quote.opportunity_id,
            issued_by: quote.issued_by.as_uuid(),
            version: quote.version,
            supersedes_quote_id: quote.supersedes_quote_id.map(|id| id.as_uuid()),
            amount_minor: quote.amount.minor(),
            currency: quote.amount.currency().code(),
            memo: quote.memo,
            issued_at: quote.issued_at,
            valid_until: quote.valid_until,
            expired,
            accepted_at: quote.accepted_at,
            declined_at: quote.declined_at,
            lines: quote
                .lines
                .into_iter()
                .map(|line| LineView {
                    description: line.description,
                    amount_minor: line.amount_minor,
                    tax_rate_bp: line.tax_rate_bp,
                })
                .collect(),
        }
    }
}

/// La taille d'une page quand l'appelant n'en demande pas. Le chiffre de
/// `routes::employees`, et son argument : ce qu'on fait défiler une fois.
const DEFAULT_LIMIT: i64 = 50;

/// La plus grande page qu'on construise, quel que soit le `limit` demandé.
///
/// Deux cents, et le plafond n'est pas celui de la base : le premier lecteur de
/// cette route est un outil MCP, donc une page est un contexte de modèle. Un
/// devis et ses lignes coûtent quelques centaines de jetons, et deux cents
/// devis sont déjà l'essentiel de ce qu'un tour peut dépenser sur un appel.
const MAX_LIMIT: i64 = 200;

/// La fenêtre et la coupe. `deny_unknown_fields` parce qu'un `state` mal
/// orthographié ne doit pas passer pour « pas de filtre » : la mauvaise réponse
/// serait une liste **plus longue** qui a l'air juste.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    /// `open`, `lapsed`, `accepted` ou `declined` — voir `quotes::State`, qui
    /// possède les quatre mots et argumente pourquoi ils partitionnent.
    #[serde(default)]
    state: Option<String>,
    /// Le dernier `id` de la page précédente.
    #[serde(default)]
    after: Option<Uuid>,
    /// Combien de devis rendre, plafonné à [`MAX_LIMIT`].
    #[serde(default)]
    limit: Option<i64>,
}

/// `GET /v1/quotes` — une page de ce que cette entreprise a proposé, le plus
/// récent d'abord.
///
/// Les versions remplacées comprises, et sans filtre **par défaut**, pour la
/// raison de `GET /v1/invoices` : la question qu'on ouvre ceci pour poser n'est
/// pas « quel est le prix » — c'est « qu'est-ce qu'on leur a proposé, et
/// qu'est-ce qu'ils ont dit ». Une liste qui cacherait les versions mortes
/// répondrait à la première question deux fois et à la seconde pas du tout ;
/// `supersedes_quote_id` est là pour que le lecteur reconstitue les chaînes.
/// `state` est le choix de l'appelant, pas l'avis de cette route.
///
/// `outstanding_minor` n'existe pas ici, et c'est délibéré : un devis n'est dû
/// par personne. Additionner des offres donnerait un chiffre qui ressemble à un
/// carnet de commandes et qui n'en est pas un — une offre non acceptée n'est pas
/// une créance, et une acceptée n'en est pas une non plus tant qu'elle n'est pas
/// facturée. `GET /v1/invoices` est l'endroit où ce total a un sens. **Et c'est
/// aussi pourquoi la pagination est sans danger ici** : il n'y a aucun total à
/// rétrécir avec la page.
///
/// `limit` est ramené dans les bornes plutôt que refusé, le choix de
/// `routes::employees` : une demande trop grande reçoit quand même une page et
/// un `next_after`, donc rien n'est perdu. Un `limit` qui n'est pas un nombre
/// reste un 400 — celui de serde, et c'est le refus utile.
async fn register(
    State(db): State<Db>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let state = match page.state.as_deref() {
        None => None,
        Some(text) => Some(quotes::State::parse(text).ok_or_else(|| {
            ApiError::bad_request(
                "state: one of \"open\", \"lapsed\", \"accepted\", \"declined\", or absent for all",
            )
        })?),
    };
    let limit = page.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    // Une seule horloge pour la page : celle qui décide `lapsed` en SQL est
    // celle qui calcule `expired` ci-dessous, sinon une ligne rendue par le
    // filtre pourrait se faire contredire par son propre champ.
    let now = Utc::now();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let all = quotes::register(
        &mut tx,
        state,
        page.after.map(QuoteId::from_uuid),
        limit,
        now,
    )
    .await?;
    tx.rollback().await?;

    // Seule une page pleine peut avoir une suite. Une page courte termine la
    // marche sans coûter un aller-retour de plus pour l'apprendre.
    let next_after = (all.len() as i64 == limit)
        .then(|| all.last().map(|last| last.id.as_uuid()))
        .flatten();

    Ok(Json(json!({
        "quotes": all
            .into_iter()
            .map(|quote| QuoteView::of(quote, now))
            .collect::<Vec<_>>(),
        "next_after": next_after,
    }))
    .into_response())
}

/// `POST /v1/quotes/{id}/accepted` — le client a dit oui.
///
/// Pas de corps. L'instant est celui du serveur et non de l'appelant, comme
/// pour `POST /v1/invoices/{id}/paid` : une date fournie serait la première
/// chose à être fausse, il faudrait une règle sur jusqu'où elle peut remonter,
/// et — ici, c'est plus grave qu'une facture — **une date antidatée
/// ressusciterait un devis périmé**, puisque la validité est comparée à cet
/// instant précis.
///
/// 404 pour quatre raisons, et une seule réponse, ce qui est délibéré : le
/// devis n'est pas à cette entreprise, il n'existe pas, il a déjà reçu une
/// réponse, ou **il est périmé**. Les deux premières sont le silence habituel de
/// RLS, la troisième est quelqu'un qui arrive second, et la quatrième est celle
/// qui compte : une offre qui a expiré n'est plus faite, et l'acceptation ne se
/// rattrape pas — elle se réémet, avec une nouvelle validité que quelqu'un
/// choisit. Le `detail` le dit, parce que c'est la seule des quatre sur
/// laquelle l'appelant peut agir.
async fn accepted(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    answer(db, principal, id, true).await
}

/// `POST /v1/quotes/{id}/declined` — le client a dit non.
///
/// Mêmes quatre refus, et le même argument sur la péremption : refuser une
/// offre qui n'était déjà plus faite enregistrerait un refus de quelque chose
/// qui n'était pas sur la table.
///
/// Un refus n'est pas une perte. La suite normale est une révision — une
/// nouvelle ligne qui nomme celle-ci — et c'est `agentos_store::quotes::revise`,
/// derrière la gate, comme la proposition elle-même.
async fn declined(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    answer(db, principal, id, false).await
}

/// Le corps des deux voies ci-dessus.
///
/// Une fonction et pas deux copies : les quatre refus sont une seule phrase, et
/// deux copies seraient deux endroits où elle peut dériver — celui des quatre
/// qu'on oublierait de recopier étant justement la péremption, qui est le seul
/// qui n'existe pas sur une facture.
async fn answer(
    db: Db,
    principal: Principal,
    id: Uuid,
    accept: bool,
) -> Result<Response, ApiError> {
    let now = Utc::now();
    let quote = QuoteId::from_uuid(id);
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let recorded = if accept {
        quotes::accept(&mut tx, quote, now).await?
    } else {
        quotes::decline(&mut tx, quote, now).await?
    };
    if !recorded {
        // Annulée plutôt que validée : rien n'a été écrit, et une connexion du
        // pool repart délibérément.
        tx.rollback().await?;
        return Err(ApiError::not_found().with_detail(
            "no live quote by that id in this company: it does not exist, it has already been \
             answered, it has been superseded by a later version, or its validity has run out. \
             An offer that has lapsed is re-issued, not back-dated",
        ));
    }
    // La ligne de journal que ce module devait depuis le 2026-09-06, et qui
    // manquait pour une raison d'organisation, pas de conception : la variante
    // vivait dans le fichier d'un autre chantier. Même forme que le règlement
    // d'une facture, et même transaction que la réponse elle-même — un devis
    // accepté sans trace est une décision que `GET /v1/events` ne montre pas,
    // alors que c'est exactement l'écran où l'on cherche « qu'a fait
    // l'entreprise aujourd'hui ».
    let mut row = AuditEvent::new(principal.actor.clone(), AuditKind::QuoteAnswered, now);
    row.payload = json!({
        "quote_id": id,
        "answer": if accept { "accepted" } else { "declined" },
        "source": "operator",
    });
    audit::append(&mut tx, &row).await?;
    tx.commit().await?;

    Ok(Json(json!({
        "id": id,
        "state": if accept { "accepted" } else { "declined" },
        "at": now,
    }))
    .into_response())
}
