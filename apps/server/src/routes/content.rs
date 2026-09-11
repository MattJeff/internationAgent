//! `/v1/content` : les questions qu'on veut gagner, ce qu'un moteur y répond
//! aujourd'hui, le brief qui en sort, et ce qu'on écrit pour y répondre.
//!
//! `agentos_app::content` porte la thèse, la mesure et ses limites ;
//! `migrations/0100_une_question_merite_une_reponse.sql` porte les tables ;
//! `docs/CONTENU.md` porte la boucle entière. Ce module est la surface, et il
//! n'ajoute qu'une chose au-dessus d'elles : **qui mesure**.
//!
//! # `POST /v1/content/questions/{id}/measure` nomme un siège, et ce n'est pas
//! une décoration
//!
//! Mesurer, c'est lire une page publique, et une lecture de page est un
//! [`ActionKind::BrowserRead`] sur lequel la Policy Gate statue — pour un
//! **employé**, jamais pour une clé d'API. Le corps porte donc `employee_id`,
//! et la même forme que `routes::approvals` : le locataire vient du credential,
//! l'employé du corps, et le jeton est émis pour la paire. Un siège dont la
//! politique n'a pas `Channel::Web` ne mesure pas, et le refus est une ligne
//! d'`audit_log` comme les autres.
//!
//! L'alternative — une route d'opérateur qui lirait la page « au nom du
//! locataire » — aurait été une deuxième porte vers le web sans décision
//! derrière elle, exactement ce que `routes::quotes` refuse d'être pour
//! l'émission d'un devis.
//!
//! # Il n'y a pas de route qui publie
//!
//! `PUT /v1/content/drafts/{id}` accepte une `url`, et cette URL est
//! **constatée** : c'est la personne qui a publié qui l'écrit. Rien dans ce
//! dépôt ne pousse un texte nulle part. `docs/CONTENU.md` § « ce qui manque
//! pour publier » nomme les deux chemins possibles et dit pourquoi aucun n'est
//! codé.
//!
//! [`ActionKind::BrowserRead`]: agentos_domain::action::ActionKind::BrowserRead

use agentos_app::content::{self, Engine, MeasureError, Source, citations, drafts, questions};
use agentos_app::effects::{Effects, Ports};
use agentos_app::gate::{PolicyGate, Principal as GatePrincipal};
use agentos_domain::ids::EmployeeId;
use agentos_store::db::Db;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// L'état partagé des routes : la base pour les tables, la gate pour le verdict
/// d'une mesure, et les ports du processus pour le navigateur qui la fait.
///
/// `ports` est celui que `main` a construit — le même que chaque tour emprunte.
/// Une deuxième instance ici serait un deuxième navigateur, avec son propre pot
/// de cookies et son propre proxy, pour le même employé.
#[derive(Clone)]
pub struct Content {
    pub db: Db,
    pub gate: PolicyGate,
    pub ports: Arc<Ports>,
}

/// Les routes de cette unité. Fusionnées dans le routeur d'API, donc elles
/// héritent de l'authentification, de la limite de débit et de la couche
/// d'idempotence de `with_api_stack`.
pub fn router(state: Content) -> Router {
    Router::new()
        .route("/v1/content/questions", get(list_questions))
        .route("/v1/content/questions", post(add_question))
        .route("/v1/content/questions/{id}", delete(remove_question))
        .route("/v1/content/questions/{id}/measure", post(measure))
        .route("/v1/content/citations", get(list_citations))
        .route("/v1/content/briefs", get(get_brief))
        .route("/v1/content/drafts", get(list_drafts))
        .route("/v1/content/drafts", post(add_draft))
        .route("/v1/content/drafts/{id}", put(revise_draft))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Les questions
// ---------------------------------------------------------------------------

async fn list_questions(
    State(state): State<Content>,
    principal: Principal,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows = questions::list(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(json!({ "questions": rows })))
}

/// Une question à gagner.
#[derive(Debug, Deserialize)]
struct NewQuestion {
    question: String,
    /// `fr`, `en`, … La même question en deux langues est deux lignes : les
    /// pages citées ne sont pas les mêmes.
    locale: String,
    /// `founder`, `search_suggest` ou `customer`.
    source: String,
    /// Combien elle compte. 1 par défaut.
    #[serde(default = "one")]
    weight: i32,
}

const fn one() -> i32 {
    1
}

async fn add_question(
    State(state): State<Content>,
    principal: Principal,
    body: Result<Json<NewQuestion>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    if body.question.trim().is_empty() {
        return Err(ApiError::bad_request("question: empty"));
    }
    let source = Source::parse(&body.source).ok_or_else(|| {
        ApiError::bad_request("source: expected one of founder, search_suggest, customer")
    })?;

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row = questions::add(
        &mut tx,
        body.question.trim(),
        &body.locale,
        source,
        body.weight,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "question": row }))).into_response())
}

async fn remove_question(
    State(state): State<Content>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let gone = questions::remove(&mut tx, id).await?;
    tx.commit().await?;
    if gone {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found())
    }
}

// ---------------------------------------------------------------------------
// La mesure
// ---------------------------------------------------------------------------

/// Qui mesure, et sur quoi.
#[derive(Debug, Deserialize)]
struct Measure {
    /// Le siège à qui la lecture est attribuée. Du corps, jamais du chemin —
    /// voir les docs du module.
    employee_id: Uuid,
    /// `duckduckgo_lite`. La liste est [`Engine::ALL`].
    engine: String,
}

async fn measure(
    State(state): State<Content>,
    principal: Principal,
    Path(id): Path<Uuid>,
    body: Result<Json<Measure>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let engine = Engine::parse(&body.engine).ok_or_else(|| {
        ApiError::bad_request("engine: the only engine this deployment can read is duckduckgo_lite")
    })?;

    // Tout ce que la lecture a besoin de savoir, lu d'un coup — la transaction
    // est rendue avant que la gate ouvre la sienne, comme `routes::approvals`.
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let asked = questions::list(&mut tx)
        .await?
        .into_iter()
        .find(|row| row.id == id);
    let ours = content::our_domains(&mut tx).await?;
    tx.commit().await?;
    let Some(asked) = asked else {
        return Err(ApiError::not_found());
    };

    // Le locataire vient du credential ; l'employé du corps. Un employé d'un
    // autre locataire n'existe simplement pas dans cette transaction, donc la
    // gate refuse.
    let gate_principal = GatePrincipal {
        tenant_id: principal.tenant_id,
        employee_id: EmployeeId::from_uuid(body.employee_id),
        actor: principal.actor.clone(),
    };
    let effects = Effects::new(state.db.clone(), state.ports.clone(), gate_principal);
    let citation = content::measure(&effects, &state.gate, &ours, &asked.question, engine)
        .await
        .map_err(measure_failed)?;

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let recorded = citations::record(&mut tx, asked.id, &citation).await?;
    tx.commit().await?;

    Ok(Json(json!({ "id": recorded, "citation": citation })))
}

/// Le moteur n'a pas répondu, ou n'avait pas le droit d'être lu.
const ENGINE_UNREADABLE: &str = "engine_unreadable";
/// Ce locataire n'a aucun domaine, donc « sommes-nous cités » n'a pas de sujet.
const NO_DOMAIN_OF_OURS: &str = "no_domain_of_ours";

fn measure_failed(err: MeasureError) -> ApiError {
    match err {
        MeasureError::Denied(denied) => denied.into(),
        MeasureError::Store(err) => err.into(),
        MeasureError::NoDomainOfOurs => ApiError::conflict(
            NO_DOMAIN_OF_OURS,
            "this tenant has no domain of its own, so there is nothing to look for",
        ),
        // Le mot du port, comme `routes::approvals` le rend pour un paiement :
        // un opérateur qui lit ce 502 et un opérateur qui lit le journal lisent
        // la même chaîne.
        MeasureError::Effect(err) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            ENGINE_UNREADABLE,
            "the engine's results page could not be read",
        )
        .with_extension("engine_error", json!(err.code())),
    }
}

// ---------------------------------------------------------------------------
// La série, et le brief
// ---------------------------------------------------------------------------

/// La fenêtre d'une lecture de série.
#[derive(Debug, Deserialize)]
struct Window {
    question_id: Uuid,
    /// Jours comptés à rebours depuis maintenant. 30 par défaut, 366 au plus —
    /// les bornes de `routes::pnl`, pour qu'un opérateur n'ait pas deux règles
    /// à retenir.
    days: Option<i64>,
}

impl Window {
    fn days(&self) -> Result<i64, ApiError> {
        match self.days {
            None => Ok(30),
            Some(days) if (1..=366).contains(&days) => Ok(days),
            Some(_) => Err(ApiError::bad_request("days: expected 1..=366")),
        }
    }
}

async fn list_citations(
    State(state): State<Content>,
    principal: Principal,
    window: Result<Query<Window>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(window) = window.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let days = window.days()?;
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows = citations::list(&mut tx, window.question_id, days).await?;
    tx.commit().await?;
    Ok(Json(json!({ "citations": rows })))
}

/// De quelle question on veut le brief.
#[derive(Debug, Deserialize)]
struct Asked {
    question_id: Uuid,
}

/// Le brief d'une question, bâti sur sa **dernière** mesure.
///
/// Une lecture et pas une écriture : un brief n'a pas de table parce qu'il est
/// une fonction pure d'une question et d'une mesure, toutes deux stockées. Voir
/// `migrations/0100`.
///
/// 409 quand rien n'a encore été mesuré, et pas un brief vide : un brief sans
/// mesure dirait « tout manque », ce qui est vrai de toute page jamais lue et
/// n'aide personne à écrire.
async fn get_brief(
    State(state): State<Content>,
    principal: Principal,
    asked: Result<Query<Asked>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(asked) = asked.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let question = questions::list(&mut tx)
        .await?
        .into_iter()
        .find(|row| row.id == asked.question_id);
    let latest = citations::latest(&mut tx, asked.question_id).await?;
    tx.commit().await?;

    let Some(question) = question else {
        return Err(ApiError::not_found());
    };
    let Some(latest) = latest else {
        return Err(ApiError::conflict(
            "never_measured",
            "this question has never been measured, so there is nothing to write against",
        ));
    };
    let brief = content::brief(&question.question, &content::Citation::from(latest));
    Ok(Json(json!({ "brief": brief })))
}

// ---------------------------------------------------------------------------
// Les brouillons
// ---------------------------------------------------------------------------

async fn list_drafts(
    State(state): State<Content>,
    principal: Principal,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows = drafts::list(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(json!({ "drafts": rows })))
}

/// Un brouillon ouvert sur une question.
#[derive(Debug, Deserialize)]
struct NewDraft {
    question_id: Uuid,
    title: String,
    /// Le texte, écrit par un employé avec son modèle. Rien ici ne l'engendre.
    body: String,
}

async fn add_draft(
    State(state): State<Content>,
    principal: Principal,
    body: Result<Json<NewDraft>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row = drafts::create(&mut tx, body.question_id, &body.title, &body.body)
        .await
        // Une question qui n'est pas à ce locataire n'existe pas dans cette
        // transaction, donc la clé étrangère tombe : c'est un 404, pas un 500.
        .map_err(|_| ApiError::not_found())?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "draft": row }))).into_response())
}

/// La révision d'un brouillon. `url` présent veut dire publié.
#[derive(Debug, Deserialize)]
struct Revise {
    title: String,
    body: String,
    /// L'adresse **constatée** de la publication. Rien dans ce dépôt ne publie ;
    /// c'est la personne qui l'a fait qui l'écrit ici.
    #[serde(default)]
    url: Option<String>,
}

async fn revise_draft(
    State(state): State<Content>,
    principal: Principal,
    Path(id): Path<Uuid>,
    body: Result<Json<Revise>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row = drafts::update(
        &mut tx,
        id,
        &drafts::Revision {
            title: &body.title,
            body: &body.body,
            url: body.url.as_deref(),
        },
    )
    .await?;
    tx.commit().await?;
    row.map(|row| Json(json!({ "draft": row })))
        .ok_or_else(ApiError::not_found)
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use chrono::Utc;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; ces routes sont une question SQL");
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
            let state = Content {
                db: db.clone(),
                gate: PolicyGate::new(db.clone()),
                ports: Arc::new(agentos_app::mocks::ports()),
            };

            Some(Self {
                app: crate::with_api_stack(
                    router(state),
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
            let builder = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
            let req = match body {
                Some(body) => builder
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
                None => builder.body(Body::empty()).expect("request"),
            };
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(format!("content-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// La boucle sans le réseau : une question, un brouillon, une publication
    /// constatée — et le voisin ne voit rien de tout ça.
    #[tokio::test]
    async fn une_question_un_brouillon_une_publication_et_le_voisin_ne_voit_rien() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h
            .call(
                "POST",
                "/v1/content/questions",
                SECRET_A,
                Some(json!({
                    "question": "how do I check visa requirements by API",
                    "locale": "en",
                    "source": "customer",
                    "weight": 9
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let question_id = body["question"]["id"].as_str().expect("id").to_owned();

        // Rejouer l'ajout rend la même ligne, pas une deuxième.
        let (_, again) = h
            .call(
                "POST",
                "/v1/content/questions",
                SECRET_A,
                Some(json!({
                    "question": "how do I check visa requirements by API",
                    "locale": "en",
                    "source": "founder"
                })),
            )
            .await;
        assert_eq!(again["question"]["id"].as_str(), Some(question_id.as_str()));

        // Une provenance inventée est refusée à la porte.
        let (status, _) = h
            .call(
                "POST",
                "/v1/content/questions",
                SECRET_A,
                Some(json!({ "question": "q", "locale": "fr", "source": "devinée" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Rien n'a été mesuré : le brief le dit plutôt que d'inventer.
        let (status, _) = h
            .call(
                "GET",
                &format!("/v1/content/briefs?question_id={question_id}"),
                SECRET_A,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Un brouillon, puis sa publication constatée.
        let (status, body) = h
            .call(
                "POST",
                "/v1/content/drafts",
                SECRET_A,
                Some(json!({
                    "question_id": question_id,
                    "title": "Checking visa requirements by API",
                    "body": "…"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let draft_id = body["draft"]["id"].as_str().expect("id").to_owned();
        assert_eq!(body["draft"]["state"], "draft");

        let (status, body) = h
            .call(
                "PUT",
                &format!("/v1/content/drafts/{draft_id}"),
                SECRET_A,
                Some(json!({
                    "title": "Checking visa requirements by API",
                    "body": "…",
                    "url": "https://visa.example.com/blog/visa-api"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["draft"]["state"], "published");
        assert!(body["draft"]["published_at"].is_string());

        // **Le désarmement.** Le voisin, avec sa propre clé, ne voit rien et ne
        // peut rien retirer.
        let (_, body) = h.call("GET", "/v1/content/questions", SECRET_B, None).await;
        assert_eq!(body["questions"].as_array().map(Vec::len), Some(0));
        let (_, body) = h.call("GET", "/v1/content/drafts", SECRET_B, None).await;
        assert_eq!(body["drafts"].as_array().map(Vec::len), Some(0));
        let (status, _) = h
            .call(
                "DELETE",
                &format!("/v1/content/questions/{question_id}"),
                SECRET_B,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Et chez lui, tout est là.
        let (_, body) = h.call("GET", "/v1/content/questions", SECRET_A, None).await;
        assert_eq!(body["questions"].as_array().map(Vec::len), Some(1));
        let (status, _) = h
            .call(
                "DELETE",
                &format!("/v1/content/questions/{question_id}"),
                SECRET_A,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        h.teardown().await;
    }

    /// Un moteur que ce déploiement ne sait pas lire est refusé avant qu'une
    /// page soit demandée — et la fenêtre d'une série a des bornes.
    #[tokio::test]
    async fn un_moteur_inconnu_et_une_fenetre_hors_bornes_sont_refuses() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (_, body) = h
            .call(
                "POST",
                "/v1/content/questions",
                SECRET_A,
                Some(json!({ "question": "q", "locale": "fr", "source": "founder" })),
            )
            .await;
        let question_id = body["question"]["id"].as_str().expect("id").to_owned();

        let (status, _) = h
            .call(
                "POST",
                &format!("/v1/content/questions/{question_id}/measure"),
                SECRET_A,
                Some(json!({ "employee_id": Uuid::now_v7(), "engine": "chatgpt" })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "un moteur qu'on ne sait pas lire est refusé, pas tenté"
        );

        let (status, _) = h
            .call(
                "GET",
                &format!("/v1/content/citations?question_id={question_id}&days=900"),
                SECRET_A,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Le désarmement : la même lecture dans les bornes répond.
        let (status, body) = h
            .call(
                "GET",
                &format!("/v1/content/citations?question_id={question_id}&days=7"),
                SECRET_A,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["citations"].as_array().map(Vec::len), Some(0));

        h.teardown().await;
    }
}
