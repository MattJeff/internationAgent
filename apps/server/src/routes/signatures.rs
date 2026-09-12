//! `/v1/signatures` : mettre un document devant quelqu'un pour qu'il le signe,
//! et constater qu'il l'a fait.
//!
//! `migrations/0105_une_signature_est_un_constat.sql` porte la table,
//! `agentos_app::signature` porte l'argument entier et
//! `agentos_app::effects::Effects::send_for_signature` porte l'effet. Ceci est
//! la surface, et elle n'ajoute que deux choses : **qui prépare** et **qui
//! constate**.
//!
//! # Il n'y a pas de route qui envoie, et c'est toute la conception
//!
//! Trois routes, et aucune des trois ne parle au prestataire.
//! `POST /v1/signatures` fait statuer la Policy Gate pour un siège nommé, ce qui
//! pour un `Action::ContractSign` rend **toujours** une demande d'approbation —
//! `domain::policy::evaluate` n'a aucune condition sur ce bras. Ce qui envoie
//! est `POST /v1/approvals/{id}/approve`, après qu'une personne a cliqué, et
//! c'est le second bras de cette route à avoir un exécuteur ; le premier est le
//! paiement.
//!
//! L'alternative — un point d'accès d'opérateur qui enverrait le pli — serait
//! une deuxième porte vers un engagement de la société sans décision derrière
//! elle : exactement ce que `routes::quotes` refuse d'être pour l'émission d'un
//! devis et `routes::invoices` pour l'émission d'une facture.
//!
//! # Pourquoi le constat est un geste d'opérateur, et ce qu'il ne peut pas
//! mentir
//!
//! `POST /v1/signatures/{id}/signed` est une clé d'opérateur, pour l'argument de
//! `POST /v1/invoices/{id}/paid` : rien dans ce processus n'observe une
//! signature, et le siège qui a demandé le pli ne doit pas être ce qui déclare
//! qu'il a été signé.
//!
//! Ce que cette route ne peut pas faire, et la contrainte est en base plutôt
//! qu'ici : **écrire « signé » sans exemplaire exécuté.** `0105` lie `signed_at`
//! et `executed_name` par un CHECK, et refuse que cet exemplaire soit le
//! document qu'on a envoyé. Le corps de la requête ne porte donc pas une date —
//! l'instant est celui du serveur, comme pour une facture encaissée — mais le
//! **nom d'un fichier du classeur**, déposé avant par `POST /v1/files`.
//! Déclarer une signature demande d'avoir les octets signés.
//!
//! Le jour où DocuSign Connect pousse la complétion, l'écrivain change et rien
//! d'autre : `0105` dit ce que la table gagne ce jour-là, et pourquoi ce webhook
//! n'est pas encore là (le nom de l'en-tête de signature, jamais lu sur une
//! livraison réelle, faute de compte).

use agentos_app::gate::{PolicyGate, Principal as GatePrincipal};
use agentos_app::signature::{self, PrepareError, envelopes};
use agentos_domain::ids::EmployeeId;
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError};
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// L'état partagé : la base pour la table, la gate pour le verdict d'une
/// signature. Pas de ports et pas de flotte — rien ici n'appelle un
/// prestataire ; l'envoi vit dans `routes::approvals`, qui en a déjà.
#[derive(Clone)]
pub struct Signatures {
    pub db: Db,
    pub gate: PolicyGate,
}

/// Les routes de cette unité. Fusionnées dans le routeur d'API, donc elles
/// héritent de l'authentification, de la limite de débit et de la couche
/// d'idempotence de `with_api_stack`.
pub fn router(state: Signatures) -> Router {
    Router::new()
        .route("/v1/signatures", get(register))
        .route("/v1/signatures", post(request))
        .route("/v1/signatures/{id}/signed", post(signed))
        .with_state(state)
}

/// `GET /v1/signatures` — le registre des plis, le plus récent d'abord.
///
/// Pas de pagination, la même question ouverte que `files::index` : un client
/// signe des contrats à la main, pas par milliers. Le jour où un locataire en a
/// mille, c'est un `LIMIT` ici et un `after` dans le schéma de l'outil.
async fn register(
    State(state): State<Signatures>,
    principal: Principal,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows = envelopes::list(&mut tx).await?;
    tx.rollback().await?;
    Ok(Json(json!({ "envelopes": rows })))
}

/// Ce qu'on demande.
#[derive(Debug, Deserialize)]
struct Requested {
    /// Le siège pour lequel la Gate statue. Le locataire vient du credential,
    /// l'employé du corps — la forme de `routes::approvals` et de
    /// `routes::content`.
    employee_id: Uuid,
    /// La phrase que la personne lira dans sa file d'approbation, et sur
    /// laquelle le hachage de l'action est pris. Ce n'est pas une décoration :
    /// `routes::approvals` refuse une approbation dont l'action restituée ne
    /// redonne pas le même hachage.
    title: String,
    /// L'adresse à qui on demande de signer.
    signatory: String,
    /// Le branchement MCP du prestataire — `docusign` au catalogue. Il vient de
    /// `integrations_list`.
    server: String,
    /// Le document, par son nom dans le classeur. Il vient de `files_list`.
    document_name: String,
}

/// `POST /v1/signatures` — préparer un pli, et le poser dans la file d'une
/// personne.
///
/// Ne renvoie **jamais** un pli parti : ce que la Gate rend pour un
/// `Action::ContractSign` est une demande d'approbation, sans condition. La
/// réponse est donc `202` avec l'identifiant de l'approbation à approuver.
async fn request(
    State(state): State<Signatures>,
    principal: Principal,
    body: Result<Json<Requested>, JsonRejection>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    let gate_principal = GatePrincipal {
        // Du credential. Jamais du chemin, jamais du corps.
        tenant_id: principal.tenant_id,
        employee_id: EmployeeId::from_uuid(body.employee_id),
        actor: principal.actor.clone(),
    };
    let envelope = signature::prepare(
        &state.db,
        &state.gate,
        &gate_principal,
        &signature::Request {
            employee_id: EmployeeId::from_uuid(body.employee_id),
            title: body.title,
            signatory: body.signatory,
            server: body.server,
            document_name: body.document_name,
        },
    )
    .await
    .map_err(prepare_failed)?;

    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(json!({
            "envelope": envelope,
            // Ce qu'il reste à faire, nommé : sans ce clic, rien ne part.
            "awaiting_approval_id": envelope.approval_id.to_string(),
        })),
    ))
}

/// Ce qu'on constate.
#[derive(Debug, Deserialize)]
struct Signed {
    /// **L'exemplaire exécuté**, par son nom dans le classeur. Déposé avant par
    /// `POST /v1/files`, et il ne peut pas être le document qu'on a envoyé —
    /// `0105` le refuse.
    executed_name: String,
}

/// `POST /v1/signatures/{id}/signed` — le pli est revenu signé, et voici
/// l'exemplaire.
///
/// Pas de date dans le corps, pour l'argument de `POST /v1/invoices/{id}/paid` :
/// l'instant est celui du serveur, et une date fournie par l'appelant serait la
/// première chose à être fausse.
///
/// 404 couvre quatre refus, et c'est délibéré — la forme de `paid` : le pli
/// n'est pas à cette entreprise, il n'existe pas, il n'est jamais parti, ou il
/// est déjà signé. Aucun des quatre ne doit devenir un oracle sur les plis du
/// voisin. 400 est réservé à la seule faute actionnable : le fichier n'est pas
/// dans le classeur, ou c'est le document d'origine.
async fn signed(
    State(state): State<Signatures>,
    principal: Principal,
    Path(id): Path<Uuid>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let marked = envelopes::mark_signed(&mut tx, id, &body.executed_name, now)
        .await
        .map_err(constraint_failed);
    let marked = match marked {
        Ok(row) => row,
        Err(err) => {
            tx.rollback().await?;
            return Err(err);
        }
    };
    let Some(envelope) = marked else {
        // Rien n'a été écrit ; une connexion du pot repart délibérément.
        tx.rollback().await?;
        return Err(ApiError::not_found()
            .with_detail("no envelope by that id in this company is out for signature"));
    };

    // La même transaction que la colonne, pour que le journal et la table ne
    // puissent pas être en désaccord sur ce qui a été signé. `source` a la forme
    // exacte du payload de `invoice_paid`, parce que la question qu'il répond est
    // la même : qui l'a dit.
    let mut row = AuditEvent::new(principal.actor.clone(), AuditKind::ContractSigned, now);
    row.payload = json!({
        "envelope_id": id,
        "provider_envelope_id": envelope.provider_envelope_id,
        "executed_name": envelope.executed_name,
        "source": "operator",
    });
    audit::append(&mut tx, &row).await?;
    tx.commit().await?;

    Ok(Json(json!({ "envelope": envelope })))
}

/// Une contrainte de base qui parle de la requête, pas de la machine.
///
/// Deux traductions et rien d'autre, la forme de `routes::content` : les deux
/// fautes qu'un appelant peut réellement commettre ici sortiraient sinon en
/// 500 « nous avons cassé ».
fn constraint_failed(err: StoreError) -> ApiError {
    if let StoreError::Database(inner) = &err
        && let Some(db) = inner.as_database_error()
    {
        if db.is_foreign_key_violation() {
            return ApiError::bad_request(
                "no document by that name in this company's classeur; deposit it first with POST /v1/files",
            );
        }
        if db
            .constraint()
            .is_some_and(|name| name == "signature_envelopes_copy_is_not_the_original")
        {
            return ApiError::bad_request(
                "the executed copy cannot be the document that was sent out",
            );
        }
    }
    err.into()
}

fn prepare_failed(err: PrepareError) -> ApiError {
    match err {
        // L'escalade **n'est pas** dans ce bras : `signature::prepare` la lit
        // comme le succès qu'elle est. Ce qui arrive ici est un vrai refus — la
        // société est arrêtée, le siège n'est pas actif, il n'existe pas.
        PrepareError::Denied(denied) => denied.into(),
        PrepareError::NoDocument => ApiError::bad_request(
            "no document by that name in this company's classeur; deposit it first with POST /v1/files",
        ),
        PrepareError::NotEscalated => ApiError::conflict(
            "signature_not_escalated",
            "the gate did not escalate this signature to a human, so nothing was prepared",
        ),
        PrepareError::Store(err) => constraint_failed(err),
    }
}
