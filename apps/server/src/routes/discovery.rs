//! `/v1/discovery/sources` : les annuaires qu'un locataire fait relire chaque
//! jour — poser, relire, retirer.
//!
//! La moitié employé est `agentos_app::discovery` et `loops::discovery`. Il
//! n'y a **pas** de route « lire maintenant » : c'est `POST
//! /v1/prospects/discover`, qui existe déjà et prend le même jeton. Une
//! source est une promesse de lecture quotidienne, et c'est la boucle qui la
//! tient.
//!
//! # Poser une source lit une page
//!
//! `POST` nomme un siège, comme `prospects_discover`, parce que poser vérifie
//! `robots.txt` de l'hôte — une lecture sur laquelle la Gate statue pour un
//! employé, jamais pour une clé d'API. Un siège sans le canal `web` est un 403
//! `channel_not_allowed` avant qu'aucune ligne soit écrite ; un hôte qui nous
//! refuse est un 422 `robots_refused`, et la ligne n'est pas écrite non plus.
//! La ligne est insérée *avant* la lecture, dans la même transaction, pour
//! que l'unicité de l'hôte soit jugée par la contrainte sans qu'une page ait
//! été chargée pour rien ; un refus défait la transaction.
//!
//! Même auth que [`super::prospects`] : la clé du locataire, sous
//! `with_api_stack`, donc RLS sur tout ce que ces handlers lisent.

use std::sync::Arc;

use agentos_app::discovery::{self, DEFAULT_HOUR, NewSource, Source, SourceError};
use agentos_app::effects::{BrowserRead, Effects, Ports};
use agentos_app::gate::{PolicyGate, Principal as GatePrincipal};
use agentos_domain::ids::EmployeeId;
use agentos_store::db::{Db, StoreError};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::{ApiError, JsonBody};

pub fn router(db: Db, gate: PolicyGate, ports: Arc<Ports>) -> Router {
    Router::new()
        .route("/v1/discovery/sources", get(list).post(add))
        .route("/v1/discovery/sources/{id}", delete(remove))
        .with_state(Sources { db, gate, ports })
}

/// La base pour la table, la gate pour le verdict d'une lecture, et les
/// ports du processus pour le navigateur qui la fait — le même `Arc` que
/// `routes::prospects`, pour la même raison.
#[derive(Clone)]
struct Sources {
    db: Db,
    gate: PolicyGate,
    ports: Arc<Ports>,
}

#[derive(Deserialize)]
struct NewSourceBody {
    url: String,
    segment: String,
    country: Option<String>,
    employee_id: Uuid,
    hour: Option<u8>,
}

/// `GET /v1/discovery/sources` — chaque annuaire, dans l'ordre où la boucle
/// les sert, avec ses compteurs et sa dernière issue.
async fn list(
    State(state): State<Sources>,
    principal: Principal,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let sources: Vec<Source> = discovery::list(&mut tx).await?;
    tx.rollback().await?;
    Ok(Json(json!({ "sources": sources })))
}

/// `POST /v1/discovery/sources` — 201 avec la ligne ; 400 `bad_segment` pour
/// `other` (le motif dans `detail`) ou un segment inconnu ; 400 pour la forme ;
/// 404 siège inconnu ici ; 409 `duplicate_host` ; 403 de la Gate ; 422
/// `robots_refused` ; 502 `directory_unreadable` si `robots.txt` n'a pas pu
/// être demandé.
async fn add(
    State(state): State<Sources>,
    principal: Principal,
    JsonBody(body): JsonBody<NewSourceBody>,
) -> Result<Response, ApiError> {
    let new = NewSource {
        url: &body.url,
        segment: &body.segment,
        country: body.country.as_deref(),
        employee_id: EmployeeId::from_uuid(body.employee_id),
        hour: body.hour.unwrap_or(DEFAULT_HOUR),
    };
    // Les refus de forme avant la Gate, qui coûte une décision.
    let (url, domain, _) = discovery::check(&new).map_err(refused)?;

    let gate_principal = GatePrincipal {
        tenant_id: principal.tenant_id,
        employee_id: new.employee_id,
        actor: principal.actor.clone(),
    };
    let effects = Effects::new(state.db.clone(), state.ports.clone(), gate_principal);
    let token = state
        .gate
        .authorize(effects.principal(), BrowserRead { domain })
        .await?;

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let source = discovery::add(&mut tx, &new).await.map_err(refused)?;
    match discovery::robots_permits(&effects, token, &url).await {
        Ok(true) => {}
        Ok(false) => {
            tx.rollback().await?;
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "robots_refused",
                "this host's robots.txt refuses that page",
            ));
        }
        Err(err) => {
            tx.rollback().await?;
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "directory_unreadable",
                "the host's robots.txt could not be read",
            )
            .with_extension("browser_error", json!(err.code())));
        }
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "source": source }))).into_response())
}

/// `DELETE /v1/discovery/sources/{id}` — 204 ; 404 hors du locataire. Les
/// comptes et contacts que la source a créés restent.
async fn remove(
    State(state): State<Sources>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    discovery::remove(&mut tx, id)
        .await
        .map_err(|err| match err {
            StoreError::NotFound => ApiError::not_found().with_detail("no such source"),
            other => ApiError::from(other),
        })?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn refused(err: SourceError) -> ApiError {
    match err {
        SourceError::OtherSegment | SourceError::BadSegment => {
            ApiError::new(StatusCode::BAD_REQUEST, "bad_segment", "unknown segment")
                .with_detail(err.to_string())
        }
        SourceError::BadUrl(_) | SourceError::BadCountry | SourceError::BadHour => {
            ApiError::bad_request(err.to_string())
        }
        SourceError::NoSuchSeat => ApiError::not_found().with_detail(err.to_string()),
        SourceError::DuplicateHost(_) => {
            ApiError::conflict("duplicate_host", "this host is already on the list")
                .with_detail(err.to_string())
        }
        SourceError::Store(err) => ApiError::from(err),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentos_app::mocks::MockBrowser;
    use agentos_domain::ids::TenantId;
    use agentos_domain::message::Channel;
    use agentos_domain::policy::PolicyLimits;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::Utc;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET: &str = "cccccccccccccccccccccccccccccccc";

    struct Harness {
        app: Router,
        db: Db,
        tenant: TenantId,
        browser: Arc<MockBrowser>,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let tenant = TenantId::new_v7(Utc::now());
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'discovery')")
                .bind(tenant.as_uuid())
                .bind(tenant.as_uuid().to_string())
                .execute(&mut *tx)
                .await
                .expect("tenant");
            tx.commit().await.expect("commit");
            let keys =
                ApiKeys::parse(&format!("ops:{}:{SECRET}", tenant.as_uuid())).expect("keyring");
            let browser = Arc::new(MockBrowser::new());
            let ports = Arc::new(Ports {
                browser: browser.clone(),
                ..agentos_app::mocks::ports()
            });
            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone(), PolicyGate::new(db.clone()), ports),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                tenant,
                browser,
            })
        }

        async fn send(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {SECRET}"));
            let req = match body {
                Some(body) => req
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string())),
                None => req.body(Body::empty()),
            }
            .expect("request");
            let res = self.app.clone().oneshot(req).await.expect("response");
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .expect("body");
            let json = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).expect("json")
            };
            (status, json)
        }

        async fn seat(&self, web: bool) -> Uuid {
            let id = Uuid::now_v7();
            let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 VALUES ($1, $2, $3, 'lena', 'active')",
            )
            .bind(id)
            .bind(self.tenant.as_uuid())
            .bind(format!("lena-{}", id.simple()))
            .execute(&mut *tx)
            .await
            .expect("employee");
            sqlx::query(
                "INSERT INTO employee_resources \
                     (employee_id, step, tenant_id, state, provider, external_id) \
                 VALUES ($1, 'browser', $2, 'ready', 'mock-browser', $3)",
            )
            .bind(id)
            .bind(self.tenant.as_uuid())
            .bind(format!("ctx-{}", id.simple()))
            .execute(&mut *tx)
            .await
            .expect("browser resource");
            tx.commit().await.expect("commit");
            agentos_store::policy::install(
                &self.db,
                self.tenant,
                agentos_store::policy::Scope::Tenant,
                &PolicyLimits {
                    allowed_channels: BTreeSet::from([if web {
                        Channel::Web
                    } else {
                        Channel::Email
                    }]),
                    max_new_contacts_per_day: 5,
                    ..PolicyLimits::default()
                },
            )
            .await
            .expect("policy");
            id
        }

        async fn teardown(self) {
            let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(self.tenant.as_uuid())
                .execute(&mut *tx)
                .await
                .expect("delete tenant");
            tx.commit().await.expect("commit");
        }
    }

    /// **`other` est refusé avec son motif, un hôte ne se pose qu'une fois, un
    /// hôte qui nous refuse ne se pose pas, et un siège sans `web` ne pose
    /// rien.** Ce qui est posé se relit et se retire.
    #[tokio::test]
    async fn a_source_is_posed_once_per_host_and_never_on_a_host_that_refuses_us() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let seat = h.seat(true).await;
        let body = |url: &str, segment: &str| json!({ "url": url, "segment": segment, "employee_id": seat, "country": "fr" });

        let (status, answer) = h
            .send(
                "POST",
                "/v1/discovery/sources",
                Some(body("https://ectaa.org/members", "other")),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert_eq!(answer["code"], "bad_segment", "{answer}");
        assert!(
            answer["detail"]
                .as_str()
                .is_some_and(|d| d.contains("nothing to reproduce")),
            "{answer}"
        );
        assert!(h.browser.log().is_empty(), "no page for a refused form");

        // robots.txt shuts the door: 422, nothing written, only robots.txt read.
        h.browser
            .set_text("body", &["User-agent: *\nDisallow: /members"]);
        let (status, answer) = h
            .send(
                "POST",
                "/v1/discovery/sources",
                Some(body("https://ectaa.org/members", "ota")),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert_eq!(answer["code"], "robots_refused", "{answer}");
        let (_, listed) = h.send("GET", "/v1/discovery/sources", None).await;
        assert_eq!(
            listed["sources"].as_array().map(Vec::len),
            Some(0),
            "{listed}"
        );

        // Open: 201, and the row reads back with the posed country and hour.
        h.browser
            .set_text("body", &["User-agent: *\nDisallow: /private"]);
        let (status, answer) = h
            .send(
                "POST",
                "/v1/discovery/sources",
                Some(body("https://ectaa.org/members", "ota")),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        assert_eq!(answer["source"]["host"], "ectaa.org", "{answer}");
        assert_eq!(answer["source"]["country"], "FR", "{answer}");
        assert_eq!(answer["source"]["hour"], 7, "{answer}");
        assert!(answer["source"]["read_on"].is_null(), "{answer}");
        let id = answer["source"]["id"].as_str().expect("id").to_owned();

        // The same host again, another page: 409, before robots.txt is asked.
        let before = h.browser.log().len();
        let (status, answer) = h
            .send(
                "POST",
                "/v1/discovery/sources",
                Some(body("https://ectaa.org/partners", "tmc")),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert_eq!(answer["code"], "duplicate_host", "{answer}");
        assert_eq!(h.browser.log().len(), before);

        // A seat without the web channel: the Gate says so, nothing is written.
        let mute = h.seat(false).await;
        let (status, answer) = h
            .send(
                "POST",
                "/v1/discovery/sources",
                Some(json!({ "url": "https://fidi.org/members", "segment": "relocation", "employee_id": mute })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
        assert_eq!(answer["code"], "channel_not_allowed", "{answer}");

        let (_, listed) = h.send("GET", "/v1/discovery/sources", None).await;
        assert_eq!(
            listed["sources"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
        let (status, _) = h
            .send("DELETE", &format!("/v1/discovery/sources/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = h
            .send("DELETE", &format!("/v1/discovery/sources/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        h.teardown().await;
    }
}
