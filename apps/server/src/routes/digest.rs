//! `GET /v1/digest?day=YYYY-MM-DD` : la journée d'une société, en une lecture.
//!
//! Le calcul est [`agentos_app::digest::compute`] ; ici il n'y a que l'auth
//! d'`health` — la clé du locataire par [`Principal`], toutes les lectures sous
//! [`Db::tenant_tx`] — et le jour, `aujourd'hui` UTC par défaut. Le même
//! objet, en HTML, part au fondateur à 18 h par `loops::digest`.

use agentos_app::digest;
use agentos_store::db::Db;
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{NaiveDate, Utc};
use serde::Deserialize;

use crate::auth::Principal;
use crate::error::ApiError;

/// Ce module.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/digest", get_route(get))
        .with_state(db)
}

#[derive(Debug, Deserialize)]
struct DayQuery {
    day: Option<NaiveDate>,
}

/// `GET /v1/digest`.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<DayQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let now = Utc::now();
    let day = query.day.unwrap_or_else(|| now.date_naive());
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let digest = digest::compute(&mut tx, day, now).await?;
    tx.rollback().await?;
    Ok(axum::Json(digest).into_response())
}

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

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; a digest is a SQL question");
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

        async fn digest(&self, secret: &str, uri: &str) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .body(Body::empty())
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'digest-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Une réponse entrante par e-mail, reçue maintenant, sur un siège neuf.
    async fn reply(db: &Db, tenant: TenantId) {
        let employee = EmployeeId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("employee");
        let thread = agentos_app::inbound::conversation_for(
            &mut tx,
            employee,
            agentos_domain::message::Channel::Email,
            "paul",
            None,
            Utc::now(),
        )
        .await
        .expect("thread");
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, conversation_id, employee_id, channel, \
                                   direction, sender, subject, body, idempotency_key) \
             VALUES ($1, $2, $3, $4, 'email', 'inbound', 'paul@prospect.example', \
                     'Re: Bonjour', 'oui', $5)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(thread.as_uuid())
        .bind(employee.as_uuid())
        .bind(Uuid::now_v7().to_string())
        .execute(&mut **tx)
        .await
        .expect("reply");
        tx.commit().await.expect("commit");
    }

    /// **200, du JSON, le jour d'aujourd'hui par défaut — et l'autre
    /// locataire voit zéro.**
    #[tokio::test]
    async fn the_route_renders_todays_digest_and_the_other_tenant_sees_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };
        reply(&h.db, h.a).await;

        let (status, body) = h.digest(SECRET_A, "/v1/digest").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["day"], Utc::now().date_naive().to_string());
        assert_eq!(body["replies"].as_array().map(Vec::len), Some(1), "{body}");
        assert_eq!(body["replies"][0]["subject"], "Re: Bonjour");
        assert_eq!(body["health"]["turns_attempted_today"], 0);

        let (status, body) = h.digest(SECRET_B, "/v1/digest").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["replies"].as_array().map(Vec::len), Some(0), "{body}");

        // Hier, et un jour qui n'en est pas un.
        let (status, body) = h.digest(SECRET_A, "/v1/digest?day=2000-01-01").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["day"], "2000-01-01");
        assert_eq!(body["replies"].as_array().map(Vec::len), Some(0));
        let (status, _) = h.digest(SECRET_A, "/v1/digest?day=hier").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = h
            .digest("cccccccccccccccccccccccccccccccc", "/v1/digest")
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        h.teardown().await;
    }
}
