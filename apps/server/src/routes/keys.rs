//! `/v1/keys` : la clé qu'un locataire émet **pour lui-même**.
//!
//! `routes::platform` émet déjà des clés, et n'est pas ce module : cette
//! surface-là est celle du fournisseur, autorisée par une classe de credential
//! (`AGENTOS_PLATFORM_KEYS`) qu'aucun client ne détient, et elle nomme le
//! locataire dans le corps. Ici le locataire ne se nomme pas — il vient du
//! credential présenté, comme sur toutes les autres routes de cette pile — et
//! c'est toute la différence : personne ne peut émettre une clé chez autrui,
//! parce que la route ne sait pas dire « chez autrui ».
//!
//! Ce qu'on achète en l'ouvrant : le fondateur branche son Claude Code sur
//! `POST /v1/mcp/server` depuis la console, en un bouton, au lieu d'écrire au
//! fournisseur pour obtenir une clé. Voir `docs/MCP_SERVEUR.md` §2.
//!
//! # L'étiquette porte le rôle, donc l'étiquette est gardée
//!
//! `routes::approvals::held_role` lit le rôle d'un credential **à même son
//! étiquette** : une clé étiquetée `approver` décide les approbations que la
//! Gate classe sous ce rôle. Sur la surface du fournisseur c'est acceptable —
//! qui détient la clé de plateforme peut déjà tout. Ici, non : sans garde,
//! n'importe quelle session de console s'émettrait une clé `approver` et
//! approuverait ses propres paiements, ce qui est exactement le contournement
//! que `routes::accounts` refuse en disant qu'une session ne porte aucun rôle.
//!
//! Donc : une étiquette qui nomme un rôle n'est émise que par un appelant qui
//! **tient déjà ce rôle**, lu par la même fonction que les approbations. Et le
//! préfixe des sessions est refusé, parce qu'une étiquette `session-…` est une
//! identité de personne, pas un nom de clé.
//!
//! # Les sessions de console ne sont pas dans la liste
//!
//! [`visible`] les retire des trois routes. Deux raisons, et la seconde est la
//! vraie : elles ne sont pas des clés d'intégration (personne ne les a écrites
//! ni ne les collera ailleurs), et une console qui les afficherait offrirait un
//! bouton « Retirer » qui déconnecte la personne qui clique — ou quelqu'un
//! d'autre. Se déconnecter reste `DELETE /v1/accounts/session`, qui
//! s'authentifie avec le jeton qu'il détruit.

use agentos_domain::ids::Slug;
use agentos_store::api_keys::{ApiKeyRecord, SESSION_LABEL_PREFIX};
use agentos_store::db::{Db, StoreError};
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Json, Router, response::Result as AxumResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::routes::approvals::held_role;

/// Ce que cette unité tient : la base, et la clé de hachage du déploiement — la
/// même qu'`auth::Keyring`, parce que deux dérivations feraient un déploiement
/// qui émet des clés qu'il ne sait pas vérifier.
#[derive(Clone)]
pub struct KeysState {
    db: Db,
    hasher: agentos_app::api_keys::Hasher,
}

/// Les trois verbes. À monter **dans** `with_api_stack`, comme toute route de
/// locataire : c'est cet étage qui établit le `Principal` dont le tenant sort.
pub fn router(db: Db, hasher: agentos_app::api_keys::Hasher) -> Router {
    Router::new()
        .route("/v1/keys", post(issue).get(list))
        .route("/v1/keys/{id}", delete(revoke))
        .with_state(KeysState { db, hasher })
}

/// Le nom par défaut, qui est aussi celui que la console propose.
const DEFAULT_LABEL: &str = "claude-code";

/// Les étiquettes qui ne sont pas qu'un nom.
///
/// `agentos_app::gate::APPROVER_ROLE` et `routes::approvals::CAPABILITY_ROLE`
/// sont les deux littéraux qui valent `approver` aujourd'hui, tous deux privés
/// à leur module. Une liste ici plutôt qu'un import : ce qu'on garde n'est pas
/// « la constante de la Gate », c'est « un mot qu'une étiquette ne peut pas
/// prendre sans le tenir », et un rôle ajouté ailleurs s'ajoute ici.
const ROLE_LABELS: &[&str] = &["approver"];

// ---------------------------------------------------------------------------
// Émettre
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IssueRequest {
    #[serde(default)]
    label: Option<String>,
}

/// La seule réponse de ce module qui porte un secret, et elle le porte une fois.
///
/// Il n'y a pas de `GET` qui le rende, rien qui le recalcule — le digest est à
/// sens unique — et aucun autre champ de ce fichier ne le sérialise. Qui le
/// perd en émet une autre et retire celle-ci.
#[derive(Serialize)]
struct IssuedBody {
    id: Uuid,
    label: String,
    /// **Montré exactement une fois.**
    secret: String,
    created_at: chrono::DateTime<Utc>,
}

/// `POST /v1/keys` — une clé de ce locataire, pour ce locataire.
async fn issue(
    State(state): State<KeysState>,
    principal: Principal,
    body: Result<Json<IssueRequest>, JsonRejection>,
) -> AxumResult<Response, ApiError> {
    // Un corps absent est un corps vide : `{}` et rien du tout demandent la
    // même chose, et un 400 sur « rien » serait un bouton qui ne marche pas.
    let label = match body {
        Ok(Json(request)) => checked_label(request.label.as_deref(), &principal)?,
        Err(JsonRejection::MissingJsonContentType(_) | JsonRejection::BytesRejection(_)) => {
            checked_label(None, &principal)?
        }
        Err(err) => return Err(ApiError::bad_request(err.body_text())),
    };

    let now = Utc::now();
    // L'acteur de la trace est celui du credential présenté, tel quel : le
    // journal du locataire doit dire quelle clé en a émis une autre.
    let issued = agentos_app::api_keys::issue(
        &state.db,
        &state.hasher,
        principal.tenant_id,
        &label,
        &principal.actor,
        now,
    )
    .await
    .map_err(|err| match err {
        StoreError::Conflict(_) => ApiError::conflict(
            "key_label_exists",
            "this tenant already has a key with that label",
        ),
        err => ApiError::from(err),
    })?;

    // L'id et l'étiquette. Le secret est dans la réponse et dans aucune ligne
    // de journal — c'est ce que cherche `apps/server/tests/platform_signup.rs`
    // sur l'autre surface, et la même règle vaut ici.
    tracing::info!(
        key_id = %issued.id,
        tenant_id = %principal.tenant_id.as_uuid(),
        label = %issued.label,
        by = %principal.actor.label(),
        "tenant issued its own api key"
    );

    Ok((
        StatusCode::CREATED,
        Json(IssuedBody {
            id: issued.id,
            label: issued.label,
            // Le seul appel du binaire qui sorte le texte clair, et il part
            // droit dans le champ qu'on sérialise.
            secret: issued.secret.expose_for_transport().to_owned(),
            created_at: now,
        }),
    )
        .into_response())
}

/// L'étiquette demandée, si l'appelant a le droit de la porter.
///
/// `Slug::parse` et pas du texte libre, pour la raison de
/// `routes::platform::key_label` : c'est ce qu'on tape pour retrouver la clé à
/// retirer, et `Claude Code ` contre `claude-code` est une façon de retirer la
/// mauvaise.
fn checked_label(raw: Option<&str>, principal: &Principal) -> Result<String, ApiError> {
    let raw = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_LABEL);
    let label = Slug::parse(raw)
        .map_err(|err| ApiError::bad_request(format!("label: {err}")))?
        .as_str()
        .to_owned();

    if label.starts_with(SESSION_LABEL_PREFIX) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "label_reserved",
            "this label prefix belongs to console sessions",
        )
        .with_detail(
            "Une étiquette `session-…` est l'identité d'une personne connectée, pas le nom d'une \
             clé d'intégration. Choisissez un autre nom.",
        ));
    }

    if ROLE_LABELS.contains(&label.as_str()) && held_role(&principal.actor) != Some(label.as_str())
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "role_required",
            "this credential does not hold the role that label would carry",
        )
        .with_detail(
            "L'étiquette d'une clé EST son rôle : `routes::approvals::held_role` la lit telle \
             quelle. Émettre celle-ci donnerait à la nouvelle clé un rôle que l'appelant n'a pas.",
        ));
    }

    Ok(label)
}

// ---------------------------------------------------------------------------
// Lister et retirer
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct KeyBody {
    id: Uuid,
    label: String,
    created_at: chrono::DateTime<Utc>,
}

/// Les clés d'intégration de ce locataire — jamais les sessions, jamais un
/// digest, jamais un secret.
async fn visible(state: &KeysState, principal: &Principal) -> Result<Vec<ApiKeyRecord>, ApiError> {
    Ok(agentos_app::api_keys::list(&state.db, principal.tenant_id)
        .await?
        .into_iter()
        .filter(|record| !record.label.starts_with(SESSION_LABEL_PREFIX))
        .collect())
}

/// `GET /v1/keys` — des ids, des noms, des dates.
async fn list(
    State(state): State<KeysState>,
    principal: Principal,
) -> AxumResult<Json<serde_json::Value>, ApiError> {
    let keys: Vec<KeyBody> = visible(&state, &principal)
        .await?
        .into_iter()
        .map(|record| KeyBody {
            id: record.id,
            label: record.label,
            created_at: record.created_at,
        })
        .collect();
    Ok(Json(json!({ "keys": keys })))
}

/// `DELETE /v1/keys/{id}` — la clé cesse de marcher à la requête suivante.
///
/// L'appartenance est vérifiée **avant** la suppression, et pas après en lisant
/// le tenant que `api_keys::revoke` rend : ce tenant-là arrive une fois la ligne
/// déjà détruite, ce qui ferait de ce 403 le constat d'une suppression
/// inter-locataires. Deux requêtes, donc, et la première est celle que `GET`
/// fait déjà.
///
/// `404` pour une clé qui n'est pas à nous, exactement comme pour une qui
/// n'existe pas : la distinction n'est utile qu'à qui sonde.
async fn revoke(
    State(state): State<KeysState>,
    principal: Principal,
    id: Result<Path<Uuid>, PathRejection>,
) -> AxumResult<Response, ApiError> {
    let Path(id) = id.map_err(|err| ApiError::bad_request(err.body_text()))?;

    if !visible(&state, &principal)
        .await?
        .iter()
        .any(|record| record.id == id)
    {
        return Err(ApiError::not_found());
    }

    agentos_app::api_keys::revoke(&state.db, id, &principal.actor, Utc::now()).await?;

    tracing::info!(
        key_id = %id,
        tenant_id = %principal.tenant_id.as_uuid(),
        by = %principal.actor.label(),
        "tenant revoked its own api key"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_store::audit::AuditActor;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::MAX_BODY_BYTES;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY};

    const OPS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const APPROVER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Un locataire, deux clés d'environnement : une ordinaire et une qui porte
    /// le rôle d'approbation. La seconde est ce qui désarme la garde.
    struct Harness {
        app: Router,
        db: Db,
        tenant: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL est absent ; /v1/keys écrit dans `api_keys`");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let tenant = TenantId::new_v7(Utc::now());
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'keys-test')")
                .bind(tenant.as_uuid())
                .bind(tenant.as_uuid().to_string())
                .execute(&mut *tx)
                .await
                .expect("insert tenant");
            tx.commit().await.expect("commit");

            let keys = ApiKeys::parse(&format!(
                "ops:{tenant}:{OPS},approver:{tenant}:{APPROVER}",
                tenant = tenant.as_uuid()
            ))
            .expect("keyring");
            let hasher = agentos_app::api_keys::Hasher::from_master_key(TEST_MASTER_KEY);

            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone(), hasher),
                    db.clone(),
                    Keyring::new(keys, db.clone(), TEST_MASTER_KEY),
                ),
                db,
                tenant,
            })
        }

        async fn send(
            &self,
            method: &str,
            path: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut request = HttpRequest::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
            if body.is_some() {
                request = request.header(header::CONTENT_TYPE, "application/json");
            }
            let request = request
                .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
                .expect("request");
            let response = self.app.clone().oneshot(request).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }
    }

    /// Le tour complet : la clé émise ouvre la porte, elle est dans la liste, la
    /// liste ne porte pas de secret, et le retrait la referme.
    #[tokio::test]
    async fn an_issued_key_opens_the_door_and_the_listing_never_carries_a_secret() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h
            .send(
                "POST",
                "/v1/keys",
                OPS,
                Some(json!({"label": "claude-code"})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let secret = body["secret"].as_str().expect("un secret").to_owned();
        let id = body["id"].as_str().expect("un id").to_owned();
        assert_eq!(body["label"], "claude-code");
        assert!(body["created_at"].is_string());

        // La porte : la clé toute neuve s'authentifie sur cette route-ci, qui
        // est derrière le même `require_api_key` que toutes les autres.
        let (status, listed) = h.send("GET", "/v1/keys", &secret, None).await;
        assert_eq!(status, StatusCode::OK, "{listed}");

        let rendered = listed.to_string();
        assert!(
            !rendered.contains(&secret),
            "la liste a rendu un secret : {rendered}"
        );
        assert!(
            !rendered.contains("secret"),
            "la liste a un champ secret : {rendered}"
        );
        assert!(
            listed["keys"]
                .as_array()
                .expect("keys")
                .iter()
                .any(|key| key["id"] == id.as_str()),
        );

        let (status, _) = h.send("DELETE", &format!("/v1/keys/{id}"), OPS, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Retirée veut dire retirée à la requête suivante, sans redémarrage.
        let (status, _) = h.send("GET", "/v1/keys", &secret, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// L'étiquette est le rôle, donc l'étiquette est gardée — et la garde est
    /// désarmée par l'appelant qui tient déjà ce rôle.
    #[tokio::test]
    async fn a_label_that_would_usurp_a_role_is_refused() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h
            .send("POST", "/v1/keys", OPS, Some(json!({"label": "approver"})))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["code"], "role_required");

        let (status, body) = h
            .send(
                "POST",
                "/v1/keys",
                OPS,
                Some(json!({"label": "session-deadbeef"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["code"], "label_reserved");

        // Le désarmement : la clé qui tient `approver` peut en émettre une.
        // Sans cette moitié, la garde pourrait refuser tout le monde.
        let (status, body) = h
            .send(
                "POST",
                "/v1/keys",
                APPROVER,
                Some(json!({"label": "approver"})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    /// Une session de console n'est ni listée ni retirable ici : elle se ferme
    /// par `DELETE /v1/accounts/session`, avec le jeton qu'elle détruit.
    #[tokio::test]
    async fn a_console_session_is_neither_listed_nor_revocable_here() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let session = agentos_app::api_keys::issue(
            &h.db,
            &agentos_app::api_keys::Hasher::from_master_key(TEST_MASTER_KEY),
            h.tenant,
            &agentos_store::api_keys::session_label(Uuid::now_v7()),
            &AuditActor::System,
            Utc::now(),
        )
        .await
        .expect("session");

        let (status, listed) = h.send("GET", "/v1/keys", OPS, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !listed.to_string().contains(&session.id.to_string()),
            "la session est dans la liste : {listed}"
        );

        let (status, _) = h
            .send("DELETE", &format!("/v1/keys/{}", session.id), OPS, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Le tenant vient du credential et de nulle part ailleurs : la clé d'un
    /// autre locataire n'est ni visible ni retirable.
    #[tokio::test]
    async fn another_tenants_key_is_not_found() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let other = TenantId::new_v7(Utc::now());
        let mut tx = h.db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'keys-test-other')")
            .bind(other.as_uuid())
            .bind(other.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");

        let theirs = agentos_app::api_keys::issue(
            &h.db,
            &agentos_app::api_keys::Hasher::from_master_key(TEST_MASTER_KEY),
            other,
            "claude-code",
            &AuditActor::System,
            Utc::now(),
        )
        .await
        .expect("issue");

        let (status, _) = h
            .send("DELETE", &format!("/v1/keys/{}", theirs.id), OPS, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Et la preuve que le 404 n'est pas celui d'une route absente : la même
        // clé, retirée par son propre locataire, s'en va.
        assert!(
            agentos_app::api_keys::revoke(&h.db, theirs.id, &AuditActor::System, Utc::now())
                .await
                .is_ok()
        );
    }
}
