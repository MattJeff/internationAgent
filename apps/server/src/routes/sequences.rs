//! `/v1/sequences` : le fondateur définit une séquence, y inscrit un contact,
//! et relit où chacun en est.
//!
//! La moitié employé est `agentos_app::sequence` et `loops::sequence` ; le
//! réveil est celui de `loops::initiative`. Il n'y a **pas** de route d'envoi
//! ni de route « avancer maintenant » : un pas `email` réserve une promesse et
//! le siège écrit le mail lui-même derrière la Gate. Une route qui forcerait un
//! pas serait un second chemin d'envoi sous un autre nom.
//!
//! Même auth que [`super::outreach`] : la clé du locataire, sous
//! `with_api_stack`, donc RLS sur tout ce que ces handlers lisent.

use agentos_app::sequence::{self, DefineError, EnrollError, Step};
use agentos_domain::ids::{EmployeeId, SequenceId};
use agentos_store::db::{Db, StoreError};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/sequences", get(list).post(define))
        .route("/v1/sequences/{id}", axum::routing::delete(archive))
        .route("/v1/sequences/{id}/enroll", post(enroll))
        .route("/v1/sequences/{id}/runs", get(runs))
        .with_state(db)
}

#[derive(Deserialize)]
struct NewSequence {
    name: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Enrollment {
    contact_id: Uuid,
    employee_id: Uuid,
}

/// `POST /v1/sequences` — 201 `{id}`, ou 400 avec le motif de validation.
async fn define(
    State(db): State<Db>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<NewSequence>,
) -> Result<Response, ApiError> {
    if body.name.trim().is_empty() || body.name.trim().chars().count() > 200 {
        return Err(ApiError::bad_request("`name` is 1 to 200 characters"));
    }
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let id = sequence::define(&mut tx, &body.name, &body.steps)
        .await
        .map_err(|err| match err {
            DefineError::Invalid(why) => ApiError::bad_request(why.to_string()),
            DefineError::NameTaken => ApiError::conflict(
                "name_taken",
                "a live sequence of this company already has this name",
            ),
            DefineError::Store(err) => ApiError::from(err),
        })?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id.as_uuid() }))).into_response())
}

/// `GET /v1/sequences` — toutes, vivantes d'abord.
async fn list(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let all = sequence::list(&mut tx).await?;
    tx.rollback().await?;
    Ok(Json(json!({ "sequences": all })).into_response())
}

/// `DELETE /v1/sequences/{id}` — archive. 404 hors du locataire ou déjà
/// archivée ; les runs en cours finissent.
async fn archive(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    sequence::archive(&mut tx, SequenceId::from_uuid(id))
        .await
        .map_err(|err| match err {
            StoreError::NotFound => ApiError::not_found().with_detail("no such live sequence"),
            other => ApiError::from(other),
        })?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /v1/sequences/{id}/enroll` — 201 `{run_id}` ; 409 déjà inscrit ; 403
/// adresse suppressée ; 404 séquence, contact ou siège inconnus ici.
async fn enroll(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
    crate::error::JsonBody(body): crate::error::JsonBody<Enrollment>,
) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let run = sequence::enroll(
        &mut tx,
        SequenceId::from_uuid(id),
        body.contact_id,
        EmployeeId::from_uuid(body.employee_id),
        Utc::now(),
    )
    .await
    .map_err(|err| match err {
        EnrollError::NotFound(what) => {
            ApiError::not_found().with_detail(format!("no such {what} in this company"))
        }
        EnrollError::Suppressed => ApiError::new(
            StatusCode::FORBIDDEN,
            "suppressed",
            "this address has asked to be left alone",
        ),
        EnrollError::AlreadyActive => ApiError::conflict(
            "already_enrolled",
            "this contact is already in this sequence",
        ),
        EnrollError::Store(err) => ApiError::from(err),
    })?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "run_id": run.as_uuid() })),
    )
        .into_response())
}

/// `GET /v1/sequences/{id}/runs` — chaque contact inscrit et où il en est.
async fn runs(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let all = sequence::runs(&mut tx, SequenceId::from_uuid(id)).await?;
    tx.rollback().await?;
    Ok(Json(json!({ "runs": all })).into_response())
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY};

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        lena: Uuid,
        paul: Uuid,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the sequence routes need a database");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let a = TenantId::new_v7(Utc::now());
            let b = TenantId::new_v7(Utc::now());
            let (lena, paul) = (Uuid::now_v7(), Uuid::now_v7());
            let account = Uuid::now_v7();
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin");
            for tenant in [a, b] {
                sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'sequences')")
                    .bind(tenant.as_uuid())
                    .bind(tenant.as_uuid().to_string())
                    .execute(&mut *tx)
                    .await
                    .expect("tenant");
            }
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 VALUES ($1, $2, 'lena', 'lena', 'active')",
            )
            .bind(lena)
            .bind(a.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("employee");
            sqlx::query(
                "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
                 VALUES ($1, $2, 'Prospect', $3, 'airline', 'FR')",
            )
            .bind(account)
            .bind(a.as_uuid())
            .bind(format!("{}.example", account.simple()))
            .execute(&mut *tx)
            .await
            .expect("account");
            sqlx::query(
                "INSERT INTO contacts (id, tenant_id, account_id, full_name, email) \
                 VALUES ($1, $2, $3, 'Paul', $4)",
            )
            .bind(paul)
            .bind(a.as_uuid())
            .bind(account)
            .bind(format!("paul@{}.example", account.simple()))
            .execute(&mut *tx)
            .await
            .expect("contact");
            tx.commit().await.expect("commit");
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
                    Keyring::new(keys, db.clone(), TEST_MASTER_KEY),
                ),
                db,
                a,
                lena,
                paul,
            })
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header("idempotency-key", Uuid::now_v7().to_string());
            let req = match &body {
                Some(body) => req
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string())),
                None => req.body(Body::empty()),
            }
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
    }

    /// **Define, enroll, read back, archive — and every refusal has its
    /// status.** One test, because each step needs the one before it.
    #[tokio::test]
    async fn the_founder_defines_a_sequence_and_enrolls_a_contact() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let steps = json!([
            {"kind": "email", "brief": "introduce us"},
            {"kind": "wait", "hours": 72},
            {"kind": "branch", "on": "opened", "then": 3, "otherwise": 4},
            {"kind": "email", "brief": "offer a call"},
            {"kind": "email", "brief": "a shorter subject line"},
        ]);

        // 400 with the reason: a wait of zero hours.
        let (status, body) = h
            .send(
                "POST",
                "/v1/sequences",
                SECRET_A,
                Some(json!({"name": "bad", "steps": [{"kind": "email", "brief": "x"}, {"kind": "wait", "hours": 0}]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["detail"].as_str().unwrap_or("").contains("step 1"),
            "{body}"
        );

        let (status, body) = h
            .send(
                "POST",
                "/v1/sequences",
                SECRET_A,
                Some(json!({"name": "intro", "steps": steps})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = body["id"].as_str().expect("id").to_owned();

        let (status, body) = h.send("GET", "/v1/sequences", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["sequences"][0]["id"], id);
        assert_eq!(
            body["sequences"][0]["steps"], steps,
            "steps round-trip as posted"
        );
        let (_, theirs) = h.send("GET", "/v1/sequences", SECRET_B, None).await;
        assert!(
            theirs["sequences"].as_array().expect("list").is_empty(),
            "RLS"
        );

        let enrol = json!({"contact_id": h.paul, "employee_id": h.lena});
        let (status, body) = h
            .send(
                "POST",
                &format!("/v1/sequences/{id}/enroll"),
                SECRET_A,
                Some(enrol.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let run_id = body["run_id"].as_str().expect("run_id").to_owned();
        let (status, body) = h
            .send(
                "POST",
                &format!("/v1/sequences/{id}/enroll"),
                SECRET_A,
                Some(enrol.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, _) = h
            .send(
                "POST",
                &format!("/v1/sequences/{id}/enroll"),
                SECRET_B,
                Some(enrol.clone()),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "the other company's sequence"
        );

        let (status, body) = h
            .send("GET", &format!("/v1/sequences/{id}/runs"), SECRET_A, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["runs"][0]["id"], run_id);
        assert_eq!(body["runs"][0]["state"], "active");
        assert_eq!(body["runs"][0]["step"], 0);

        // Suppressed: 403, once the slot is free.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        sqlx::query("UPDATE sequence_runs SET state = 'stopped', stop_reason = 'max_touches'")
            .execute(&mut **tx)
            .await
            .expect("free");
        sqlx::query(
            "INSERT INTO suppressions (id, tenant_id, channel, address, reason) \
             SELECT $1, $2, 'email', email, 'opt_out' FROM contacts WHERE id = $3",
        )
        .bind(Uuid::now_v7())
        .bind(h.a.as_uuid())
        .bind(h.paul)
        .execute(&mut **tx)
        .await
        .expect("suppress");
        tx.commit().await.expect("commit");
        let (status, body) = h
            .send(
                "POST",
                &format!("/v1/sequences/{id}/enroll"),
                SECRET_A,
                Some(enrol),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (status, _) = h
            .send("DELETE", &format!("/v1/sequences/{id}"), SECRET_B, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "not theirs to archive");
        let (status, _) = h
            .send("DELETE", &format!("/v1/sequences/{id}"), SECRET_A, None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = h.send("GET", "/v1/sequences", SECRET_A, None).await;
        assert!(!body["sequences"][0]["archived_at"].is_null(), "{body}");
    }
}
