//! `GET /v1/inventory/stranded`: what a terminated employee is still being
//! billed for.
//!
//! # Why an endpoint at all
//!
//! [`agentos_store::provisioning::stranded`] has answered this question since
//! the termination sweeper was written, and nobody has ever read it, because
//! reading it means opening psql against production. A billing leak that is
//! only visible to someone who already suspects it is not visible.
//!
//! The rows are the ones the sweeper deliberately gives up on.
//! `release_not_supported` is structural — Resend's sending domain is shared
//! across the tenant, so its adapter refuses on purpose and will refuse
//! identically forever — and retrying a structural refusal on every tick burns
//! a provider call and re-fires an alert for the life of the deployment. So the
//! sweeper stops, and the resource stays real, and stays billed, until a human
//! goes and cancels it.
//!
//! That is what shapes the response: **every field here is something the human
//! needs to do the cancelling.** The provider to log into, the external id to
//! paste into it, the employee it belonged to, and the reason the machine could
//! not do it. A list of counts would tell an operator that four things are
//! leaking without telling them what to click, which is the same as telling
//! them nothing.
//!
//! # Not the store's `stranded()`
//!
//! ponytail: the query is written here rather than calling
//! [`agentos_store::provisioning::stranded`], and that is a duplication with a
//! reason. `Stranded` carries no timestamp, so it cannot answer "how long",
//! and it paginates by `LIMIT` over an `updated_at` order, which a concurrent
//! release re-sorts underneath a client walking it. Both are fixed by widening
//! `Stranded` and its query — one struct, two fields, a keyset — at which point
//! this handler becomes a `map` over it. That is a `crates/store` change this
//! unit does not own. Until then, `WHERE` clause parity with the store is the
//! thing to keep: terminated employee, provider and external id both present.

use agentos_store::db::{Db, StoreError};
use axum::Json;
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// Page size when the caller does not ask for one.
const DEFAULT_LIMIT: i64 = 50;

/// Largest page we will build, however big a `limit` the caller sends.
const MAX_LIMIT: i64 = 200;

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before this handler.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/inventory/stranded", get_route(list_stranded))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One row exactly as the query selects it.
#[derive(Debug, FromRow)]
struct StrandedRow {
    employee_id: Uuid,
    employee_slug: String,
    step: String,
    provider: String,
    external_id: String,
    state: String,
    last_error: Option<String>,
    updated_at: DateTime<Utc>,
}

/// One resource a human has to go and cancel.
#[derive(Debug, Serialize)]
struct StrandedView {
    employee_id: Uuid,
    /// The handle an operator recognises. The uuid is for the API; the slug is
    /// for the person reading the page.
    employee_slug: String,
    step: String,
    /// Who to log into.
    provider: String,
    /// **What to cancel there.** The one field that makes the row actionable.
    external_id: String,
    /// Where the resource row got stuck: `failed` after a refused release,
    /// `ready` if nothing ever tried.
    state: String,
    /// Why the last release did not happen, verbatim from the adapter. A
    /// `release_not_supported` here means no retry will ever fix it.
    reason: Option<String>,
    /// When we last learned this row was still out there — the failed release,
    /// or the provisioning that bought it if a release was never attempted.
    ///
    /// Not "when the employee was terminated": there is no `terminated_at`
    /// column, and `employees.updated_at` moves every time a *sibling* step is
    /// released, so it would drift for reasons that have nothing to do with
    /// this row. This timestamp is per-row and means what it says.
    stranded_since: DateTime<Utc>,
    /// The same thing as a number, because "how bad is this" is the question
    /// being asked and nobody wants to subtract timestamps by hand.
    stranded_for_seconds: i64,
    /// The `after` cursor that resumes the walk from just past this row.
    cursor: String,
}

/// Keyset pagination over `employee_resources`' primary key.
///
/// `after` is `"<employee_id>:<step>"`, which is that key, so the order is
/// total and a page boundary can fall mid-employee without losing or repeating
/// a row. Ordering by `updated_at` — the obvious choice, and what the store's
/// query does — would be re-sorted under a walking client by any release
/// attempt that touches a row it has already passed.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    /// The `cursor` of the last row of the previous page.
    #[serde(default)]
    after: Option<String>,
    /// How many rows to return, capped at [`MAX_LIMIT`].
    #[serde(default)]
    limit: Option<i64>,
}

/// `"<uuid>:<step>"` — the shape [`StrandedView::cursor`] hands out.
fn cursor(employee_id: Uuid, step: &str) -> String {
    format!("{employee_id}:{step}")
}

/// Split a cursor back into the two halves the keyset compares against.
fn parse_cursor(after: &str) -> Result<(Uuid, String), ApiError> {
    let (id, step) = after
        .split_once(':')
        .ok_or_else(|| ApiError::bad_request("after: expected \"<employee_id>:<step>\""))?;
    let id: Uuid = id
        .parse()
        .map_err(|_| ApiError::bad_request("after: the employee id is not a uuid"))?;
    Ok((id, step.to_owned()))
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /v1/inventory/stranded` — this tenant's leaking resources.
///
/// 200 with an empty list is the healthy answer and the common one. There is no
/// 404 here: "nothing is stranded" is a fact about the tenant, not a missing
/// resource.
async fn list_stranded(
    State(db): State<Db>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let limit = page.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let after = page.after.as_deref().map(parse_cursor).transpose()?;
    let (after_id, after_step) = match after {
        Some((id, step)) => (Some(id), Some(step)),
        None => (None, None),
    };

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    // No `WHERE tenant_id` and that is not an oversight: RLS adds it, and a
    // hand-written filter here would be a second place for it to be forgotten.
    //
    // `provider IS NOT NULL AND external_id IS NOT NULL` is what "still held"
    // means — `Employee::release` clears the binding on a successful release,
    // so an employee whose resources all came back has no rows here at all.
    let rows: Vec<StrandedRow> = sqlx::query_as(
        "SELECT r.employee_id, e.slug AS employee_slug, r.step, r.provider, \
                r.external_id, r.state, r.last_error, r.updated_at \
           FROM employee_resources r \
           JOIN employees e ON e.id = r.employee_id \
          WHERE e.lifecycle = 'terminated' \
            AND r.provider IS NOT NULL \
            AND r.external_id IS NOT NULL \
            AND ($1::uuid IS NULL \
                 OR (r.employee_id, r.step) > ($1::uuid, $2::text)) \
          ORDER BY r.employee_id, r.step \
          LIMIT $3",
    )
    .bind(after_id)
    .bind(after_step)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::from)?;
    tx.rollback().await?;

    let now = Utc::now();
    let stranded: Vec<StrandedView> = rows
        .into_iter()
        .map(|row| StrandedView {
            cursor: cursor(row.employee_id, &row.step),
            stranded_for_seconds: (now - row.updated_at).num_seconds().max(0),
            employee_id: row.employee_id,
            employee_slug: row.employee_slug,
            step: row.step,
            provider: row.provider,
            external_id: row.external_id,
            state: row.state,
            reason: row.last_error,
            stranded_since: row.updated_at,
        })
        .collect();

    // Only a full page can have a successor. A short page ends the walk without
    // costing the client one more round trip to discover that.
    let next_after = (stranded.len() as i64 == limit)
        .then(|| stranded.last().map(|last| last.cursor.clone()))
        .flatten();

    Ok(Json(json!({ "stranded": stranded, "next_after": next_after })).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
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
        /// `None` when there is no database. The whole contract of this
        /// endpoint is RLS plus a keyset over a real index; mocking that mocks
        /// the test.
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; inventory routes need a real Postgres");
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

        /// GET as `secret`'s tenant. `secret: None` sends no credential at all.
        async fn get(&self, uri: &str, secret: Option<&str>) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder().method("GET").uri(uri);
            if let Some(secret) = secret {
                req = req.header(header::AUTHORIZATION, format!("Bearer {secret}"));
            }
            let req = req.body(Body::empty()).expect("request");

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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'inventory-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Plant an employee in a given lifecycle. Written in SQL rather than
    /// driven through the domain because the fixture these tests need is a
    /// *shape of rows*, and eleven provisioning steps of ceremony to reach it
    /// would be testing the provisioner.
    async fn employee(db: &Db, tenant: TenantId, slug: &str, lifecycle: &str) -> Uuid {
        let id = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, $4)",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(slug)
        .bind(lifecycle)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    /// Plant one resource row. `binding: None` is a released resource: the
    /// provider and external id are gone, exactly as `Employee::release` leaves
    /// them.
    async fn resource(
        db: &Db,
        tenant: TenantId,
        employee_id: Uuid,
        step: &str,
        binding: Option<(&str, &str)>,
        last_error: Option<&str>,
    ) {
        let (provider, external_id) = match binding {
            Some((provider, external_id)) => (Some(provider), Some(external_id)),
            None => (None, None),
        };
        let state = if last_error.is_some() {
            "failed"
        } else {
            "ready"
        };
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employee_resources \
               (employee_id, step, tenant_id, state, provider, external_id, last_error) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(employee_id)
        .bind(step)
        .bind(tenant.as_uuid())
        .bind(state)
        .bind(provider)
        .bind(external_id)
        .bind(last_error)
        .execute(&mut **tx)
        .await
        .expect("insert resource");
        tx.commit().await.expect("commit");
    }

    fn rows(page: &Value) -> &Vec<Value> {
        page["stranded"].as_array().expect("stranded")
    }

    // -- auth ---------------------------------------------------------------

    /// The stack answers before the handler does, so an unauthenticated caller
    /// never reaches a `tenant_tx` and never learns whether anything leaks.
    #[tokio::test]
    async fn no_credential_is_a_401_before_the_handler_runs() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, problem) = h.get("/v1/inventory/stranded", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem["code"], "unauthenticated");
        assert_eq!(problem["stranded"], Value::Null, "the handler ran anyway");

        let (status, _) = h
            .get("/v1/inventory/stranded", Some("wrong-secret-wrong-secret"))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        h.teardown().await;
    }

    // -- isolation ----------------------------------------------------------

    #[tokio::test]
    async fn a_tenant_never_sees_another_tenants_stranded_resources() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let mine = employee(&h.db, h.a, "lena", "terminated").await;
        resource(
            &h.db,
            h.a,
            mine,
            "phone",
            Some(("twilio", "PN-aaa")),
            Some("release_not_supported"),
        )
        .await;

        let theirs = employee(&h.db, h.b, "raj", "terminated").await;
        resource(
            &h.db,
            h.b,
            theirs,
            "phone",
            Some(("twilio", "PN-bbb")),
            Some("release_not_supported"),
        )
        .await;

        let (status, page) = h.get("/v1/inventory/stranded", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rows(&page).len(), 1);
        assert_eq!(rows(&page)[0]["external_id"], "PN-aaa");

        let (status, page) = h.get("/v1/inventory/stranded", Some(SECRET_B)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rows(&page).len(), 1, "B sees exactly its own: {page}");
        assert_eq!(rows(&page)[0]["external_id"], "PN-bbb");
        assert!(
            !page.to_string().contains("PN-aaa"),
            "A's external id leaked into B's page: {page}"
        );

        h.teardown().await;
    }

    // -- the row is actionable ----------------------------------------------

    /// The point of the endpoint: what comes back is enough to go and cancel
    /// the thing, without a second lookup.
    #[tokio::test]
    async fn a_row_carries_what_an_operator_needs_to_cancel_it() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let id = employee(&h.db, h.a, "ines", "terminated").await;
        resource(
            &h.db,
            h.a,
            id,
            "email_domain",
            Some(("resend", "dom_42")),
            Some("release_not_supported: the sending domain is shared across the tenant"),
        )
        .await;

        let (status, page) = h.get("/v1/inventory/stranded", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        let row = rows(&page)[0].clone();

        assert_eq!(row["employee_id"], id.to_string());
        assert_eq!(row["employee_slug"], "ines", "the uuid alone is not a name");
        assert_eq!(row["step"], "email_domain");
        assert_eq!(row["provider"], "resend");
        assert_eq!(row["external_id"], "dom_42", "nothing to cancel: {row}");
        assert_eq!(row["state"], "failed");
        assert!(
            row["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("release_not_supported"),
            "the reason a retry will not help is missing: {row}"
        );
        assert!(row["stranded_since"].is_string());
        assert!(
            row["stranded_for_seconds"].as_i64().expect("seconds") >= 0,
            "{row}"
        );

        h.teardown().await;
    }

    /// Nothing held means nothing listed — otherwise the page fills with
    /// employees that cost nothing and the four that do get lost in them.
    #[tokio::test]
    async fn an_employee_whose_resources_were_all_released_does_not_appear() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let clean = employee(&h.db, h.a, "theo", "terminated").await;
        resource(&h.db, h.a, clean, "phone", None, None).await;
        resource(&h.db, h.a, clean, "email_domain", None, None).await;

        // ... and a live employee still holding everything is not stranded
        // either: it is working.
        let live = employee(&h.db, h.a, "mira", "active").await;
        resource(&h.db, h.a, live, "phone", Some(("twilio", "PN-live")), None).await;

        let (status, page) = h.get("/v1/inventory/stranded", Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rows(&page), &Vec::<Value>::new(), "{page}");
        assert_eq!(page["next_after"], Value::Null);

        h.teardown().await;
    }

    // -- pagination ---------------------------------------------------------

    /// A client walking the list must not lose a row because somebody
    /// terminated an employee mid-walk, and must not see one twice. The keyset
    /// is over the primary key, so an insert lands in its own place rather than
    /// shifting an offset.
    #[tokio::test]
    async fn the_walk_is_stable_when_rows_are_inserted_underneath_it() {
        let Some(h) = Harness::new().await else {
            return;
        };

        // Two employees, two stranded steps each. Ids are v7, so "first" and
        // "second" are also their sort order.
        let first = employee(&h.db, h.a, "aa", "terminated").await;
        let second = employee(&h.db, h.a, "bb", "terminated").await;
        for id in [first, second] {
            for (step, ext) in [("email_domain", "dom"), ("phone", "PN")] {
                resource(
                    &h.db,
                    h.a,
                    id,
                    step,
                    Some(("resend", &format!("{ext}-{id}"))),
                    Some("release_not_supported"),
                )
                .await;
            }
        }

        let (status, page1) = h
            .get("/v1/inventory/stranded?limit=2", Some(SECRET_A))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rows(&page1).len(), 2);
        let next = page1["next_after"]
            .as_str()
            .expect("a full page has a cursor")
            .to_owned();

        // Insert a *new* stranded employee between the two reads. Its id sorts
        // after both, so it must appear later in the walk and must not disturb
        // what is already behind the cursor.
        let latecomer = employee(&h.db, h.a, "zz", "terminated").await;
        resource(
            &h.db,
            h.a,
            latecomer,
            "phone",
            Some(("twilio", "PN-late")),
            Some("release_not_supported"),
        )
        .await;

        let mut seen: Vec<String> = rows(&page1)
            .iter()
            .map(|r| r["cursor"].as_str().expect("cursor").to_owned())
            .collect();
        let mut next = Some(next);
        while let Some(c) = next {
            let (status, page) = h
                .get(
                    &format!("/v1/inventory/stranded?limit=2&after={c}"),
                    Some(SECRET_A),
                )
                .await;
            assert_eq!(status, StatusCode::OK);
            seen.extend(
                rows(&page)
                    .iter()
                    .map(|r| r["cursor"].as_str().expect("cursor").to_owned()),
            );
            next = page["next_after"].as_str().map(str::to_owned);
        }

        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "a row was returned twice: {seen:?}"
        );
        assert_eq!(
            seen.len(),
            5,
            "four original rows plus the latecomer, none lost: {seen:?}"
        );
        assert!(
            seen.contains(&cursor(latecomer, "phone")),
            "the row inserted mid-walk was skipped: {seen:?}"
        );
        assert!(seen.iter().is_sorted(), "the walk is not ordered: {seen:?}");

        // A junk cursor is the caller's mistake, not a 500.
        for bad in ["not-a-cursor", "not-a-uuid:phone"] {
            let (status, _) = h
                .get(
                    &format!("/v1/inventory/stranded?after={bad}"),
                    Some(SECRET_A),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {bad}");
        }
        let (status, _) = h
            .get("/v1/inventory/stranded?limit=abc", Some(SECRET_A))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        h.teardown().await;
    }
}
