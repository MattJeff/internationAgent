//! `/v1/employees`: create, read, list, suspend, terminate.
//!
//! # Creation is an acceptance, not a provisioning run
//!
//! The previous design called eleven external APIs *inside* the HTTP handler.
//! A client waited forty seconds holding a connection, a pool slot and a
//! transaction; a timeout anywhere in the middle left a half-built employee
//! that nobody was driving, and a retry started the whole thing again from
//! zero — buying a second phone number on the way.
//!
//! So [`create`] writes three things in one transaction — the employee row, its
//! eleven `pending` resource rows, and one outbox event — and answers **202
//! Accepted**. Nothing external is touched. The provisioning loop picks the
//! event up and converges the employee, at its own pace, with its own leases
//! and its own crash-safety. The client gets its id in single-digit
//! milliseconds and can watch the steps land through [`get`].
//!
//! `Idempotency-Key` is **required** here, and that is the difference between
//! "accepted" being safe and being a duplicate-employee generator: without a
//! key, a client that retries a request whose response it never saw creates a
//! second employee with a second set of resources. The layer in `main.rs` does
//! the replaying; this module only insists that the header is there, because
//! the layer treats a missing key as "the caller does not want idempotency" —
//! a reasonable default for the API as a whole, and the wrong one for the one
//! endpoint that mints billable resources.
//!
//! # Reads say what is actually true
//!
//! [`get`] renders every resource's real state, including
//! [`ResourceState::PendingExternal`] with its `poll_ref` and `expected_by`. A
//! step waiting on a Twilio regulatory bundle or a WhatsApp sender review
//! renders as exactly that, never as a green check — the whole point of the
//! state existing. `health` is [`Employee::health`], derived from the eleven
//! rows on every read; the `employees.health` column is never read back,
//! because a worker that finishes a step does not update it and it therefore
//! goes stale within seconds of being written.
//!
//! # The tenant
//!
//! Every handler takes its tenant from [`Principal`], i.e. from the API key,
//! and opens a `tenant_tx` with it. Nothing reads a tenant from a body or a
//! path. An id belonging to another tenant is invisible to RLS, surfaces as
//! [`StoreError::NotFound`], and is answered **404** — not 403, which would
//! confirm the id exists.

use agentos_domain::action::Domain;
use agentos_domain::employee::{Employee, Health, Lifecycle, ProviderBinding, ResourceState, Step};
use agentos_domain::ids::{EmployeeId, Slug};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::outbox::{self, NewEvent};
use agentos_store::{employee as employee_store, employee::StoredEmployee};
use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get as get_route, post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// One `employees` row as [`list`] selects it: id, slug, lifecycle, created_at,
/// updated_at.
type SummaryRow = (Uuid, String, String, DateTime<Utc>, DateTime<Utc>);

/// Page size when the caller does not ask for one.
const DEFAULT_LIMIT: i64 = 50;

/// Largest page we will build, however big a `limit` the caller sends.
const MAX_LIMIT: i64 = 200;

/// The `aggregate_type` every event in this module is filed under.
pub const AGGREGATE: &str = "employee";

/// The event the provisioning loop waits for. Its payload carries nothing the
/// loop cannot re-read from the database — the id is the message.
pub const CREATED_EVENT: &str = "employee.created";

/// The event a lifecycle move is filed under. `main.rs` registers the outbox
/// handlers by these names, so they are built here rather than spelled twice.
pub fn lifecycle_event(to: Lifecycle) -> String {
    format!("{AGGREGATE}.{}", to.as_str())
}

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack`.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/employees", post(create).get(list))
        .route("/v1/employees/{id}", get_route(get))
        .route("/v1/employees/{id}/suspend", post(suspend))
        .route("/v1/employees/{id}/terminate", post(terminate))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The create body. `deny_unknown_fields` so a client that misspells a field
/// finds out now rather than wondering why it had no effect.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEmployee {
    /// Becomes the local part of the address and the employee's handle.
    slug: String,
    /// The sending/receiving domain, e.g. `agents.example.com`.
    domain: String,
}

/// One resource, rendered honestly.
///
/// `state` is flattened, so [`ResourceState`]'s own tagged representation is
/// what reaches the wire: a `pending_external` row arrives as
/// `{"state":"pending_external","poll_ref":…,"expected_by":…}` and there is no
/// way to render one without them.
#[derive(Debug, Serialize)]
struct ResourceView<'a> {
    step: Step,
    #[serde(flatten)]
    state: &'a ResourceState,
    /// The provider we are billed by, once something has been bought.
    provider: Option<&'a str>,
    /// Its id at that provider.
    external_id: Option<&'a str>,
    updated_at: DateTime<Utc>,
}

/// An employee as the API renders it.
#[derive(Debug, Serialize)]
struct EmployeeView<'a> {
    id: Uuid,
    slug: &'a str,
    domain: &'a str,
    address: String,
    did: &'a str,
    lifecycle: Lifecycle,
    /// Derived from the resource map on every read; never the stored column.
    health: Health,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    resources: Vec<ResourceView<'a>>,
    /// Steps whose `expected_by` has passed. Empty is the normal case; a
    /// non-empty list is somebody's morning.
    overdue: Vec<Step>,
}

impl<'a> EmployeeView<'a> {
    fn of(employee: &'a Employee, now: DateTime<Utc>) -> Self {
        Self {
            id: employee.id().as_uuid(),
            slug: employee.slug().as_str(),
            domain: employee.domain().as_str(),
            address: employee.address().to_string(),
            did: employee.did(),
            lifecycle: employee.lifecycle(),
            health: employee.health(),
            created_at: employee.created_at(),
            updated_at: employee.updated_at(),
            resources: employee
                .resources()
                .iter()
                .map(|(step, status)| ResourceView {
                    step: *step,
                    state: status.state(),
                    provider: status.binding().map(ProviderBinding::provider),
                    external_id: status.binding().map(ProviderBinding::external_id),
                    updated_at: status.updated_at(),
                })
                .collect(),
            overdue: employee.overdue(now),
        }
    }
}

/// One row of the list. Deliberately thinner than [`EmployeeView`].
///
/// ponytail: no `health` here. Health is derived from eleven resource rows, and
/// the stored `employees.health` column goes stale the moment a worker finishes
/// a step without touching the aggregate — rendering it would be a green check
/// for something that may not have happened. A page of thirty employees is
/// thirty aggregate loads, which is not what a list endpoint should cost. The
/// upgrade, when a console actually needs it, is one grouped query over
/// `employee_resources`; that duplicates `Step::is_blocking` in SQL, so it
/// needs to be worth it first.
#[derive(Debug, Serialize)]
struct EmployeeSummary {
    id: Uuid,
    slug: String,
    lifecycle: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Keyset pagination. Ids are UUIDv7, so `id > after` is "created after".
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    /// The last id of the previous page.
    #[serde(default)]
    after: Option<Uuid>,
    /// How many rows to return, capped at [`MAX_LIMIT`].
    #[serde(default)]
    limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/employees` — accept an employee and hand it to the provisioner.
///
/// **202, never 201.** The employee exists, but nothing it needs to do its job
/// does yet; a 201 would be telling the client its resource is ready.
async fn create(
    State(db): State<Db>,
    principal: Principal,
    headers: HeaderMap,
    body: Result<Json<CreateEmployee>, JsonRejection>,
) -> Result<Response, ApiError> {
    // The layer in main.rs replays a repeated key. It cannot invent one, and a
    // create without a key is a duplicate employee waiting for a retry.
    if !headers.contains_key("idempotency-key") {
        return Err(ApiError::bad_request(
            "POST /v1/employees requires an Idempotency-Key header",
        ));
    }

    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let slug =
        Slug::parse(&body.slug).map_err(|err| ApiError::bad_request(format!("slug: {err}")))?;
    let domain = Domain::parse(&body.domain)
        .map_err(|err| ApiError::bad_request(format!("domain: {err}")))?;

    let now = Utc::now();
    let employee = Employee::new(
        EmployeeId::new_v7(now),
        principal.tenant_id,
        slug,
        domain,
        now,
    );

    // One transaction: the row, its eleven pending resources, and the event
    // that makes somebody go and provision them. A subscriber can never see the
    // event for an employee that was rolled back, and an employee can never
    // exist with nobody coming for it.
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    employee_store::insert(&mut tx, &employee).await?;
    outbox::enqueue(
        &mut tx,
        &NewEvent {
            payload: json!({
                "employee_id": employee.id().as_uuid(),
                "slug": employee.slug().as_str(),
                "domain": employee.domain().as_str(),
            }),
            // At most one creation event per employee, whatever the caller
            // retries.
            dedupe_key: Some(format!("created:{}", employee.id().as_uuid())),
            ..NewEvent::new(AGGREGATE, employee.id().as_uuid(), CREATED_EVENT)
        },
        now,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        employee_id = %employee.id(),
        tenant_id = %principal.tenant_id,
        "employee accepted; provisioning is the loop's problem now"
    );

    Ok((StatusCode::ACCEPTED, Json(EmployeeView::of(&employee, now))).into_response())
}

/// `GET /v1/employees/{id}` — lifecycle, derived health, and all eleven steps.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let employee = load(&db, &principal, EmployeeId::from_uuid(id))
        .await?
        .employee;
    Ok(Json(EmployeeView::of(&employee, Utc::now())).into_response())
}

/// `GET /v1/employees` — this tenant's employees, oldest first.
async fn list(
    State(db): State<Db>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let limit = page.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    // No `WHERE tenant_id` and that is not an oversight: RLS adds it, and a
    // hand-written filter here would be a second place for it to be forgotten.
    let rows: Vec<SummaryRow> = sqlx::query_as(
        "SELECT id, slug, lifecycle, created_at, updated_at \
           FROM employees \
          WHERE ($1::uuid IS NULL OR id > $1) \
          ORDER BY id \
          LIMIT $2",
    )
    .bind(page.after)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::from)?;
    tx.rollback().await?;

    let employees: Vec<EmployeeSummary> = rows
        .into_iter()
        .map(
            |(id, slug, lifecycle, created_at, updated_at)| EmployeeSummary {
                id,
                slug,
                lifecycle,
                created_at,
                updated_at,
            },
        )
        .collect();

    // Only a full page can have a successor. A short page ends the walk without
    // costing the client one more round trip to discover that.
    let next_after = (employees.len() as i64 == limit)
        .then(|| employees.last().map(|last| last.id))
        .flatten();

    Ok(Json(json!({ "employees": employees, "next_after": next_after })).into_response())
}

/// `POST /v1/employees/{id}/suspend` — pause an employee without releasing
/// anything it owns.
async fn suspend(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    set_lifecycle(
        &db,
        &principal,
        EmployeeId::from_uuid(id),
        Lifecycle::Suspended,
    )
    .await
}

/// `POST /v1/employees/{id}/terminate` — end of life.
///
/// Absorbing: nothing transitions out of `terminated`, so a later suspend is a
/// 409 rather than a quiet no-op. Releasing the resources it still holds is the
/// event handler's job, not this handler's — cancelling a phone number is a
/// provider call, and provider calls do not happen in HTTP handlers.
async fn terminate(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    set_lifecycle(
        &db,
        &principal,
        EmployeeId::from_uuid(id),
        Lifecycle::Terminated,
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Read one employee, or 404. The tenant comes from the credential, so an id
/// from another tenant is simply not there.
async fn load(db: &Db, principal: &Principal, id: EmployeeId) -> Result<StoredEmployee, ApiError> {
    let mut tx: TenantTx<'_> = db.tenant_tx(principal.tenant_id).await?;
    let stored = employee_store::load(&mut tx, id).await;
    tx.rollback().await?;
    Ok(stored?)
}

/// Move the lifecycle, record the move, and answer with the new state.
///
/// The version read by `load` is quoted by `update`, so two operators racing a
/// suspend and a terminate produce one winner and one 409 rather than a lost
/// write.
async fn set_lifecycle(
    db: &Db,
    principal: &Principal,
    id: EmployeeId,
    to: Lifecycle,
) -> Result<Response, ApiError> {
    let now = Utc::now();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    let StoredEmployee {
        mut employee,
        version,
    } = employee_store::load(&mut tx, id).await?;
    let from = employee.lifecycle();
    employee.set_lifecycle(to, now).map_err(|err| {
        tracing::info!(%id, %err, "refused an illegal lifecycle transition");
        ApiError::conflict(
            "illegal_lifecycle",
            "the employee cannot move to that lifecycle from where it is",
        )
    })?;

    let next_version = employee_store::update(&mut tx, &employee, version).await?;
    // Re-asserting a lifecycle is legal and writes nothing interesting, but it
    // still bumps the version — so the dedupe key names the version and the
    // event fans out exactly once per write.
    outbox::enqueue(
        &mut tx,
        &NewEvent {
            payload: json!({
                "employee_id": id.as_uuid(),
                "from": from.as_str(),
                "to": to.as_str(),
            }),
            dedupe_key: Some(format!("lifecycle:{}:{next_version}", id.as_uuid())),
            ..NewEvent::new(AGGREGATE, id.as_uuid(), lifecycle_event(to))
        },
        now,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(%id, %from, %to, "lifecycle changed");
    Ok(Json(EmployeeView::of(&employee, now)).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_store::db::Db;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The router under its real middleware stack. Testing the handlers bare
    /// would test everything except the idempotency layer, which is half of
    /// what this unit's contract is about.
    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        /// `None` when there is no database. These tests are about rows in
        /// Postgres — RLS, a unique constraint, an idempotency record — and a
        /// mock of those is a mock of the test.
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; employee routes need a real Postgres");
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

        /// Send a request as `secret`'s tenant. `key` is the `Idempotency-Key`.
        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            key: Option<&str>,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
            if let Some(key) = key {
                req = req.header("idempotency-key", key);
            }
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

        async fn count_employees(&self, tenant: TenantId) -> i64 {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let n = sqlx::query_scalar("SELECT count(*) FROM employees")
                .fetch_one(&mut **tx)
                .await
                .expect("count");
            tx.rollback().await.expect("rollback");
            n
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'routes-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    fn body(slug: &str) -> Value {
        json!({"slug": slug, "domain": "agents.example.com"})
    }

    /// A fresh key. Keys are scoped per tenant *and* per endpoint, but tests in
    /// one process share a database, so they still have to be distinct.
    fn key(label: &str) -> String {
        format!("{label}-{}", Uuid::now_v7())
    }

    // -- create ------------------------------------------------------------

    /// The retry story, end to end: one employee, one recorded 202, and a
    /// different body under the same key is the client's bug rather than a
    /// second employee.
    #[tokio::test]
    async fn the_same_key_creates_one_employee_and_replays_its_202() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let k = key("create");

        let (status, first) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_A,
                Some(&k),
                Some(body("lena")),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "creation is accepted, not created: {first}"
        );
        assert!(first["id"].is_string());

        let (status, replay) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_A,
                Some(&k),
                Some(body("lena")),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(replay, first, "the replay must be the recorded response");
        assert_eq!(
            h.count_employees(h.a).await,
            1,
            "the key created two employees"
        );

        // Same key, different body: never a replay, and never a create.
        let (status, _) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_A,
                Some(&k),
                Some(body("raj")),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(h.count_employees(h.a).await, 1);

        h.teardown().await;
    }

    #[tokio::test]
    async fn a_create_without_an_idempotency_key_is_refused() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, problem) = h
            .send("POST", "/v1/employees", SECRET_A, None, Some(body("nils")))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            problem["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("Idempotency-Key"),
            "the caller has to be told which header is missing: {problem}"
        );
        assert_eq!(
            h.count_employees(h.a).await,
            0,
            "a refused create wrote a row"
        );

        h.teardown().await;
    }

    /// The regression this endpoint exists for: the old code provisioned inline
    /// and the employee did not exist until the last of eleven provider calls
    /// came back, so a client that followed the id it had just been given got a
    /// 404 for the whole forty-second window.
    #[tokio::test]
    async fn the_employee_is_readable_as_provisioning_the_instant_the_202_lands() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, created) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_A,
                Some(&key("observable")),
                Some(body("ines")),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let id = created["id"].as_str().expect("id").to_owned();

        let (status, employee) = h
            .send("GET", &format!("/v1/employees/{id}"), SECRET_A, None, None)
            .await;

        assert_eq!(status, StatusCode::OK, "the id we were just handed 404'd");
        assert_eq!(employee["lifecycle"], "draft");
        assert_eq!(employee["health"], "provisioning");
        assert_eq!(employee["address"], "ines@agents.example.com");

        let resources = employee["resources"].as_array().expect("resources");
        assert_eq!(
            resources.len(),
            Step::ALL.len(),
            "all eleven steps are reported"
        );
        assert!(
            resources.iter().all(|r| r["state"] == "pending"),
            "nothing has been provisioned yet, so nothing may claim to be: {employee}"
        );
        assert_eq!(employee["overdue"], json!([]));

        // And exactly one event is waiting for the provisioning loop.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox_events WHERE event_type = 'employee.created'",
        )
        .fetch_one(&mut **tx)
        .await
        .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!(events, 1);

        h.teardown().await;
    }

    #[tokio::test]
    async fn a_body_the_domain_types_refuse_is_a_400() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for bad in [
            json!({"slug": "a", "domain": "agents.example.com"}),
            json!({"slug": "Not A Slug", "domain": "agents.example.com"}),
            json!({"slug": "lena", "domain": "localhost"}),
            json!({"slug": "lena", "domain": "10.0.0.1"}),
            json!({"slug": "lena"}),
            json!({"slug": "lena", "domain": "agents.example.com", "tenant_id": "…"}),
        ] {
            let (status, _) = h
                .send(
                    "POST",
                    "/v1/employees",
                    SECRET_A,
                    Some(&key("bad")),
                    Some(bad.clone()),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {bad}");
        }
        assert_eq!(h.count_employees(h.a).await, 0);

        h.teardown().await;
    }

    #[tokio::test]
    async fn a_duplicate_slug_in_one_tenant_is_a_409() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for (expected, key_label) in [(StatusCode::ACCEPTED, "one"), (StatusCode::CONFLICT, "two")]
        {
            let (status, _) = h
                .send(
                    "POST",
                    "/v1/employees",
                    SECRET_A,
                    Some(&key(key_label)),
                    Some(body("kim")),
                )
                .await;
            assert_eq!(status, expected);
        }

        // ... but the slug is only taken inside its tenant.
        let (status, _) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_B,
                Some(&key("other-tenant")),
                Some(body("kim")),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);

        h.teardown().await;
    }

    // -- reads -------------------------------------------------------------

    /// 404 rather than 403: a 403 tells a prober that the id exists.
    #[tokio::test]
    async fn another_tenants_employee_is_not_found_rather_than_forbidden() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (_, created) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_A,
                Some(&key("isolation")),
                Some(body("mira")),
            )
            .await;
        let id = created["id"].as_str().expect("id").to_owned();

        for (method, uri) in [
            ("GET", format!("/v1/employees/{id}")),
            ("POST", format!("/v1/employees/{id}/suspend")),
            ("POST", format!("/v1/employees/{id}/terminate")),
        ] {
            let (status, problem) = h.send(method, &uri, SECRET_B, None, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
            assert_eq!(problem["code"], "not_found");
        }

        // And B's list does not mention it either.
        let (status, page) = h.send("GET", "/v1/employees", SECRET_B, None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["employees"], json!([]));

        h.teardown().await;
    }

    /// A step waiting on a Twilio bundle must say so, with the handle to chase
    /// it by — the one thing the old status endpoint rendered as a green check.
    #[tokio::test]
    async fn a_step_waiting_on_a_provider_reports_its_poll_ref_and_deadline() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (_, created) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_A,
                Some(&key("external")),
                Some(body("sam")),
            )
            .await;
        let id = EmployeeId::from_uuid(created["id"].as_str().expect("id").parse().expect("uuid"));

        // Drive the phone step the way the provisioning engine would.
        let expected_by = DateTime::from_timestamp(1_900_000_000, 0).expect("timestamp");
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let StoredEmployee {
            mut employee,
            version,
        } = employee_store::load(&mut tx, id).await.expect("load");
        employee
            .set_resource(Step::Phone, ResourceState::Provisioning, Utc::now())
            .expect("provisioning");
        employee
            .set_resource(
                Step::Phone,
                ResourceState::PendingExternal {
                    poll_ref: "BU-review-42".to_owned(),
                    expected_by,
                },
                Utc::now(),
            )
            .expect("pending external");
        employee_store::update(&mut tx, &employee, version)
            .await
            .expect("update");
        tx.commit().await.expect("commit");

        let (status, view) = h
            .send(
                "GET",
                &format!("/v1/employees/{}", id.as_uuid()),
                SECRET_A,
                None,
                None,
            )
            .await;

        assert_eq!(status, StatusCode::OK);
        let phone = view["resources"]
            .as_array()
            .expect("resources")
            .iter()
            .find(|r| r["step"] == "phone")
            .expect("phone")
            .clone();
        assert_eq!(phone["state"], "pending_external");
        assert_eq!(phone["poll_ref"], "BU-review-42");
        assert_eq!(phone["expected_by"], json!(expected_by));
        assert_ne!(view["health"], "online", "a waiting employee is not online");

        h.teardown().await;
    }

    #[tokio::test]
    async fn the_list_is_tenant_scoped_and_pages() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for slug in ["one", "two", "three"] {
            let (status, _) = h
                .send(
                    "POST",
                    "/v1/employees",
                    SECRET_A,
                    Some(&key(slug)),
                    Some(body(slug)),
                )
                .await;
            assert_eq!(status, StatusCode::ACCEPTED);
        }
        h.send(
            "POST",
            "/v1/employees",
            SECRET_B,
            Some(&key("stranger")),
            Some(body("stranger")),
        )
        .await;

        let (status, first) = h
            .send("GET", "/v1/employees?limit=2", SECRET_A, None, None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["employees"].as_array().expect("page").len(), 2);

        let cursor = first["next_after"]
            .as_str()
            .expect("a full page has a cursor");
        let (status, second) = h
            .send(
                "GET",
                &format!("/v1/employees?limit=2&after={cursor}"),
                SECRET_A,
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let rest = second["employees"].as_array().expect("page");
        assert_eq!(rest.len(), 1, "three of ours, and none of B's");
        assert_eq!(second["next_after"], Value::Null, "the walk ends");

        // Every slug is ours; B's employee never appears.
        let mut seen: Vec<&str> = first["employees"]
            .as_array()
            .expect("page")
            .iter()
            .chain(rest)
            .map(|e| e["slug"].as_str().expect("slug"))
            .collect();
        seen.sort_unstable();
        assert_eq!(seen, ["one", "three", "two"]);

        let (status, _) = h
            .send("GET", "/v1/employees?limit=abc", SECRET_A, None, None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        h.teardown().await;
    }

    // -- lifecycle ---------------------------------------------------------

    #[tokio::test]
    async fn suspend_and_terminate_move_the_lifecycle_and_terminate_is_absorbing() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (_, created) = h
            .send(
                "POST",
                "/v1/employees",
                SECRET_A,
                Some(&key("lifecycle")),
                Some(body("theo")),
            )
            .await;
        let id = created["id"].as_str().expect("id").to_owned();

        // Draft cannot be suspended — only Active can.
        let (status, _) = h
            .send(
                "POST",
                &format!("/v1/employees/{id}/suspend"),
                SECRET_A,
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Activate it the way the provisioning engine does, then suspend.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let StoredEmployee {
            mut employee,
            version,
        } = employee_store::load(&mut tx, EmployeeId::from_uuid(id.parse().expect("uuid")))
            .await
            .expect("load");
        employee
            .set_lifecycle(Lifecycle::Active, Utc::now())
            .expect("activate");
        employee_store::update(&mut tx, &employee, version)
            .await
            .expect("update");
        tx.commit().await.expect("commit");

        let (status, view) = h
            .send(
                "POST",
                &format!("/v1/employees/{id}/suspend"),
                SECRET_A,
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["lifecycle"], "suspended");
        assert_ne!(
            view["health"], "online",
            "a suspended employee is never online"
        );

        // Suspending twice is a no-op, not a 409.
        let (status, _) = h
            .send(
                "POST",
                &format!("/v1/employees/{id}/suspend"),
                SECRET_A,
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        let (status, view) = h
            .send(
                "POST",
                &format!("/v1/employees/{id}/terminate"),
                SECRET_A,
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["lifecycle"], "terminated");

        // Nothing comes back from terminated.
        let (status, problem) = h
            .send(
                "POST",
                &format!("/v1/employees/{id}/suspend"),
                SECRET_A,
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(problem["code"], "illegal_lifecycle");

        h.teardown().await;
    }

    #[tokio::test]
    async fn an_unknown_or_unparseable_id_is_never_a_500() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, _) = h
            .send(
                "GET",
                &format!("/v1/employees/{}", Uuid::now_v7()),
                SECRET_A,
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = h
            .send("GET", "/v1/employees/not-a-uuid", SECRET_A, None, None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        h.teardown().await;
    }
}
