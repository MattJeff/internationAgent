//! `GET /v1/employees/{id}/turns`: what an autonomous employee has consumed
//! today.
//!
//! # Why an endpoint at all
//!
//! The turn budget is the ceiling that stops an employee waking on a cadence
//! from billing model tokens forever (see [`agentos_store::turns`]). A ceiling
//! nobody can read is a ceiling nobody can set: the first question after
//! "why has this employee gone quiet?" is "how many turns did it have and how
//! many has it used", and answering it by opening psql against production means
//! it does not get answered.
//!
//! It also answers the opposite question — an employee that is *fine* but
//! close to its cap, which is the moment to raise the budget rather than after
//! it has already stopped.
//!
//! # The numbers come from the same two places the enforcement does
//!
//! `max_turns_per_day` is read through [`agentos_store::policy::load`], so it
//! is the **intersected** platform ∧ tenant ∧ role ∧ employee value — the same
//! number `store::turns::reserve` measures against, not the employee layer's
//! own row. An operator reading a limit here that a team layer has since
//! tightened would be reading a lie.
//!
//! `turns_taken` comes out of the bucket the reservation locks. Together they
//! are consistent by construction, because there is only one of each.
//!
//! # The day
//!
//! UTC, because that is the day the ledger keys on. See the module docs of
//! [`agentos_store::turns`] for why it is UTC and not a tenant-local midnight;
//! the short version is that the spend ledger already keys on UTC and one
//! employee must not have two "todays".
//!
//! # The tenant
//!
//! From [`Principal`], i.e. from the API key. An employee id belonging to
//! another tenant is invisible to RLS and answered **404** — not 403, which
//! would confirm the id exists.

use agentos_domain::ids::EmployeeId;
use agentos_domain::policy::turns_remaining;
use agentos_store::db::{Db, StoreError};
use agentos_store::{policy, turns};
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{NaiveDate, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before this handler.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/employees/{id}/turns", get_route(get))
        .with_state(db)
}

/// What one employee has consumed today, and what it has left.
#[derive(Debug, Serialize)]
struct TurnsView {
    employee_id: Uuid,
    /// The UTC day these numbers describe. Named in the response so nobody has
    /// to guess which midnight the counter resets at.
    day: NaiveDate,
    /// Turns started today. A turn is counted when it *starts*, so one that
    /// crashed halfway is in here — which is the point of reserving rather
    /// than counting, and would be invisible if this field were derived from
    /// completed runs.
    turns_taken: u32,
    /// The intersected ceiling: platform ∧ tenant ∧ team ∧ employee, not the
    /// employee layer's own row.
    max_turns_per_day: u32,
    turns_remaining: u32,
    /// `true` when the employee has stopped for the day. It resumes on its own
    /// at the next UTC midnight; no operator action is needed to restart it,
    /// only to give it more room.
    exhausted: bool,
}

/// `GET /v1/employees/{id}/turns`.
///
/// 200 with `turns_taken: 0` is the ordinary answer for an employee that has
/// not woken yet — there is no bucket row until the first reservation, and
/// "nothing consumed" is a fact rather than a missing resource. The 404 is for
/// an employee that does not exist *in this tenant*.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let employee_id = EmployeeId::from_uuid(id);
    let day = Utc::now().date_naive();

    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    // Existence first, so an unknown id is a 404 rather than a policy load
    // failure that reads like a server fault. No `WHERE tenant_id`: RLS adds
    // it, and a hand-written filter would be a second place to forget it.
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM employees WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    if exists.is_none() {
        tx.rollback().await?;
        return Err(ApiError::not_found());
    }

    let policy = policy::load(&mut tx, employee_id).await.map_err(|err| {
        // The detail stays server-side, as everywhere else on this surface:
        // the caller gets a code, the operator gets the layer and the row.
        tracing::error!(
            employee_id = %id,
            error = %err,
            "the stored policy could not be loaded, so this employee's turn \
             budget cannot be stated"
        );
        ApiError::internal()
    })?;
    let turns_taken = turns::taken_today(&mut tx, employee_id, day).await?;
    tx.rollback().await?;

    let remaining = turns_remaining(&policy, turns_taken);
    Ok(Json(TurnsView {
        employee_id: id,
        day,
        turns_taken,
        max_turns_per_day: policy.limits().max_turns_per_day,
        turns_remaining: remaining,
        exhausted: remaining == 0,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::{EffectivePolicy, PolicyLimits};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
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
                eprintln!("SKIP: DATABASE_URL is unset; turn routes need a real Postgres");
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
                app: crate::with_api_stack(router(db.clone()), db.clone(), keys),
                db,
                a,
                b,
            })
        }

        async fn get(&self, uri: &str, secret: &str) -> (StatusCode, Value) {
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'turns-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn employee(db: &Db, tenant: TenantId, slug: &str) -> Uuid {
        let id = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    /// This tenant's turn budget, as a `tenant` policy layer.
    ///
    /// It used to be the *platform* layer, replaced per test and guarded by a
    /// mutex, because that is the layer with nothing above it to inherit from.
    /// It no longer has to be: `store::policy::install` maintains one platform
    /// ceiling for the whole database and widens it rather than replacing it,
    /// so a test writes the number it cares about into its own tenant's layer
    /// and the intersection takes the minimum. No global row, no lock, no
    /// teardown that deletes the layer another test is mid-request on.
    async fn turn_budget(db: &Db, tenant: TenantId, turns: i32) {
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                max_turns_per_day: u32::try_from(turns).expect("non-negative"),
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the turn budget");
    }

    /// Burn `n` turns the way the initiative loop will: through the reserving
    /// path, not by writing the bucket by hand.
    async fn burn(db: &Db, tenant: TenantId, id: Uuid, n: u32) {
        let limits = PolicyLimits {
            max_turns_per_day: u32::MAX,
            ..PolicyLimits::default()
        };
        let policy =
            EffectivePolicy::try_new(&limits, &limits, &limits, &limits).expect("coherent");
        for _ in 0..n {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            turns::reserve(
                &mut tx,
                EmployeeId::from_uuid(id),
                Utc::now().date_naive(),
                &policy,
            )
            .await
            .expect("reserve");
            tx.commit().await.expect("commit");
        }
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_operator_can_see_what_an_employee_has_consumed_today() {
        let Some(h) = Harness::new().await else {
            return;
        };
        turn_budget(&h.db, h.a, 5).await;
        let id = employee(&h.db, h.a, "lena").await;

        // Nothing consumed yet: a real answer, not a 404.
        let (status, body) = h.get(&format!("/v1/employees/{id}/turns"), SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["turns_taken"], 0);
        assert_eq!(body["max_turns_per_day"], 5);
        assert_eq!(body["turns_remaining"], 5);
        assert_eq!(body["exhausted"], false);
        assert_eq!(body["day"], Utc::now().date_naive().to_string());

        // After four turns the operator can see the employee is nearly out —
        // which is the moment to act, rather than after it has stopped.
        burn(&h.db, h.a, id, 4).await;
        let (_, body) = h.get(&format!("/v1/employees/{id}/turns"), SECRET_A).await;
        assert_eq!(body["turns_taken"], 4);
        assert_eq!(body["turns_remaining"], 1);
        assert_eq!(body["exhausted"], false);

        // And once it is out, that it stopped for a reason.
        burn(&h.db, h.a, id, 1).await;
        let (_, body) = h.get(&format!("/v1/employees/{id}/turns"), SECRET_A).await;
        assert_eq!(body["turns_taken"], 5);
        assert_eq!(body["turns_remaining"], 0);
        assert_eq!(body["exhausted"], true);

        h.teardown().await;
    }

    #[tokio::test]
    async fn another_tenants_employee_is_a_404_not_a_403() {
        let Some(h) = Harness::new().await else {
            return;
        };
        turn_budget(&h.db, h.a, 5).await;
        let id = employee(&h.db, h.a, "lena").await;
        burn(&h.db, h.a, id, 2).await;

        // B holds a valid credential and the real id, and still learns nothing:
        // a 403 would confirm the employee exists.
        let (status, _) = h.get(&format!("/v1/employees/{id}/turns"), SECRET_B).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // An id nobody owns reads identically.
        let (status, _) = h
            .get(&format!("/v1/employees/{}/turns", Uuid::now_v7()), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        h.teardown().await;
    }
}
