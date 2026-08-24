//! The human approval queue, and the two buttons on it.
//!
//! ```text
//! GET  /v1/approvals              the queue: pending, oldest first
//! GET  /v1/approvals/{id}         one item, decided or not
//! POST /v1/approvals/{id}/approve redeem it
//! POST /v1/approvals/{id}/deny    refuse it
//! ```
//!
//! # Why `approve` takes the action in its body
//!
//! The failure this endpoint exists to prevent is not "somebody approved the
//! wrong thing", it is "somebody approved *this* thing and something else was
//! executed". So the approver does not press a button next to an id — it
//! restates the action it is approving, and [`PolicyGate::redeem_approval`]
//! re-hashes that restatement against the hash filed when the approval was
//! requested. Approve "$100 to supplier A" and the body says supplier B, and
//! the redemption is refused with `approval_action_mismatch`.
//!
//! Defaulting the body to the stored action would make the comparison a
//! tautology: the hash would be re-derived from the same row it is compared
//! against, and the endpoint would authorise by id alone. The body is therefore
//! required, and it is the only reason this route is not two lines long.
//!
//! # Four eyes, and the role
//!
//! Two checks stand between a request and its approval, both before the gate is
//! called:
//!
//! * **The approver is not the requester.** `requested_by` was recorded when the
//!   approval was filed; the caller's own [`AuditActor::label`] must differ. An
//!   agent that can approve its own payments has an approval workflow in name
//!   only.
//! * **The approver holds the role the approval demands.** `required_role`
//!   travels on the approval (`approver`, `reconciler`, …).
//!
//! ponytail: the caller's role *is* its API-key label, because the label is the
//! only attested attribute a credential carries in this build — there is no
//! `roles` table and `auth.rs` is not this unit's file. A key labelled
//! `approver` may decide approvals that require `approver`, and nothing else.
//! When identities grow roles, [`held_role`] is the one function that changes.
//!
//! # What approving does not do
//!
//! It does not perform the effect. `agentos-providers` is deliberately not a
//! dependency of this binary, so no route here can reach an
//! [`Effects`](agentos_app::effects::Effects) façade — approving mints the
//! [`Authorized`](agentos_app::gate::Authorized) token, spends the nonce, and
//! reports the decision id. The token is dropped here on purpose: it is the
//! seam an executor plugs into, and inventing an outbox event that no handler
//! reads would be scaffolding, not a feature.
//!
//! Denying is the mirror: one guarded `UPDATE` off `pending`, one audit row, in
//! one transaction. After it the nonce can never be spent — the gate's own
//! redemption predicate requires `state = 'pending'` — which is what "the
//! action never executes" means at this layer.

use agentos_app::gate::{PolicyGate, Principal as GatePrincipal};
use agentos_domain::action::Action;
use agentos_domain::ids::{ApprovalId, EmployeeId};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// Everything the queue shows about an approval, plus a `WHERE`.
///
/// A macro over `concat!` rather than a `format!`: sqlx 0.9 refuses a SQL string
/// that was built at runtime, and a compile-time concatenation is the honest
/// answer rather than an assertion that this one is fine. The column list exists
/// once, so the queue and the single-item read cannot drift apart.
///
/// Note what is *not* in it: the nonce. It lives in the same jsonb envelope as
/// these columns and it is a bearer credential, so it is never selected into a
/// type that derives [`Serialize`] — see [`Decidable`], which reads it and is
/// not serialisable.
macro_rules! view_sql {
    ($tail:literal) => {
        concat!(
            "SELECT id, state, employee_id, action_kind, \
                    action->'action'         AS action, \
                    reason                   AS summary, \
                    risk, \
                    action->>'requested_by'  AS requested_by, \
                    action->>'required_role' AS required_role, \
                    requested_at, expires_at, decided_at, decided_by \
               FROM approvals ",
            $tail
        )
    };
}

/// The routes' shared state: a database for the queue, a gate for the verdict.
#[derive(Clone)]
pub struct Approvals {
    db: Db,
    gate: PolicyGate,
}

/// Mount the approval routes.
pub fn router(db: Db, gate: PolicyGate) -> Router {
    Router::new()
        .route("/v1/approvals", get(list))
        .route("/v1/approvals/{id}", get(one))
        .route("/v1/approvals/{id}/approve", post(approve))
        .route("/v1/approvals/{id}/deny", post(deny))
        .with_state(Approvals { db, gate })
}

// ---------------------------------------------------------------------------
// The queue
// ---------------------------------------------------------------------------

/// One approval, as a human sees it.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct ApprovalView {
    id: Uuid,
    /// `pending`, `redeemed` or `denied`.
    state: String,
    employee_id: Option<Uuid>,
    action_kind: String,
    /// The exact action that was filed — what an approver echoes back to
    /// [`approve`].
    action: Option<Value>,
    /// The gate's one-line rendering of it. Display only.
    summary: Option<String>,
    risk: Option<String>,
    requested_by: Option<String>,
    required_role: Option<String>,
    requested_at: DateTime<Utc>,
    /// After this, no approval of it is possible. Shown because a queue that
    /// hides the deadline is a queue that fills up with dead work.
    expires_at: Option<DateTime<Utc>>,
    decided_at: Option<DateTime<Utc>>,
    decided_by: Option<String>,
}

/// The pending queue for this tenant, oldest first.
///
/// Tenant scoping is [`Db::tenant_tx`] and nothing else: there is no
/// `WHERE tenant_id = …` to forget, because row-level security is applied to
/// the transaction rather than to the statement.
async fn list(
    State(state): State<Approvals>,
    principal: Principal,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows: Vec<ApprovalView> = sqlx::query_as(view_sql!(
        "WHERE state = 'pending' ORDER BY requested_at, id"
    ))
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::from)?;
    tx.commit().await?;

    Ok(Json(json!({ "approvals": rows })))
}

/// One approval, whatever state it is in. A decided one still answers, because
/// "what happened to my request?" is the second question anybody asks.
async fn one(
    State(state): State<Approvals>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalView>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row: Option<ApprovalView> = sqlx::query_as(view_sql!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.commit().await?;

    row.map(Json).ok_or_else(ApiError::not_found)
}

// ---------------------------------------------------------------------------
// Deciding
// ---------------------------------------------------------------------------

/// The parts of an approval that decide whether this caller may decide it, plus
/// the nonce.
///
/// Deliberately not [`Serialize`], and deliberately not merged with
/// [`ApprovalView`]: `nonce` must not be one careless `Json(row)` away from the
/// agent that asked for the approval.
#[derive(sqlx::FromRow)]
struct Decidable {
    employee_id: Option<Uuid>,
    /// Empty when the envelope has no such key — which never equals a caller's
    /// label, so an approval nobody can be shown to have requested is one
    /// nobody is refused for having requested.
    requested_by: String,
    /// Empty when absent, which no label matches, so a malformed approval is
    /// undecidable rather than decidable by anyone.
    required_role: String,
    nonce: String,
}

/// Load the decision-relevant half of an approval. No `state` filter: whether
/// the approval is still spendable is [`PolicyGate::redeem_approval`]'s
/// question, and asking it here too would be a second vocabulary for
/// "already decided".
async fn decidable(tx: &mut TenantTx<'_>, id: Uuid) -> Result<Option<Decidable>, ApiError> {
    sqlx::query_as(
        "SELECT employee_id, \
                coalesce(action->>'requested_by', '')  AS requested_by, \
                coalesce(action->>'required_role', '') AS required_role, \
                coalesce(action->>'nonce', '')         AS nonce \
           FROM approvals WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(|err| ApiError::from(StoreError::from(err)))
}

fn forbidden(code: &'static str, title: &'static str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, code, title)
}

/// The role this credential holds. See the module docs: it is the key's label.
fn held_role(actor: &AuditActor) -> Option<&str> {
    match actor {
        AuditActor::Operator(label) => Some(label),
        // An employee or the system holding a human approval role would defeat
        // the point of asking a human.
        AuditActor::Employee(_) | AuditActor::System => None,
    }
}

/// Both checks that precede any decision, approve or deny.
///
/// `four_eyes` is off for a deny: refusing your own request is a cancellation,
/// and there is no self-dealing to prevent in it.
fn may_decide(principal: &Principal, row: &Decidable, four_eyes: bool) -> Result<(), ApiError> {
    if held_role(&principal.actor) != Some(row.required_role.as_str()) {
        return Err(forbidden(
            "role_required",
            "this credential does not hold the role this approval requires",
        ));
    }
    if four_eyes && principal.actor.label() == row.requested_by {
        return Err(forbidden(
            "self_approval",
            "an approval may not be granted by whoever requested it",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// approve
// ---------------------------------------------------------------------------

/// What the approver says it is approving. See the module docs on why this is
/// required rather than defaulted from the row.
#[derive(Debug, Deserialize)]
struct Approve {
    action: Action,
}

/// Spend the approval on the action in the body.
async fn approve(
    State(state): State<Approvals>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Json(body): Json<Approve>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row = decidable(&mut tx, id).await?;
    // The gate opens its own transaction; this one has nothing left to hold.
    tx.commit().await?;

    let Some(row) = row else {
        return Err(ApiError::not_found());
    };
    may_decide(&principal, &row, true)?;

    // `employee_id` is nullable in the schema, and every approval this
    // workspace files names one. A row that does not cannot be attributed, and
    // the gate rules on an employee — so it is refused rather than guessed at.
    let Some(employee_id) = row.employee_id else {
        return Err(ApiError::conflict(
            "approval_has_no_employee",
            "this approval names no employee and cannot be redeemed here",
        ));
    };

    let gate_principal = GatePrincipal {
        // From the credential. Never from the path, never from the row.
        tenant_id: principal.tenant_id,
        employee_id: EmployeeId::from_uuid(employee_id),
        actor: principal.actor.clone(),
    };
    let authorized = state
        .gate
        .redeem_approval(
            &gate_principal,
            ApprovalId::from_uuid(id),
            &row.nonce,
            body.action,
        )
        .await?;

    Ok(Json(json!({
        "id": id.to_string(),
        "state": "redeemed",
        "decision_id": authorized.decision_id().as_uuid().to_string(),
    })))
}

// ---------------------------------------------------------------------------
// deny
// ---------------------------------------------------------------------------

/// Why it was refused. Optional, and worth writing.
#[derive(Debug, Deserialize)]
struct Deny {
    #[serde(default)]
    note: Option<String>,
}

/// Refuse the approval. The nonce is never spendable again.
async fn deny(
    State(state): State<Approvals>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Json(body): Json<Deny>,
) -> Result<Json<Value>, ApiError> {
    let now = Utc::now();
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;

    let Some(row) = decidable(&mut tx, id).await? else {
        return Err(ApiError::not_found());
    };
    may_decide(&principal, &row, false)?;

    let decided_by = principal.actor.label();
    let refused: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE approvals \
            SET state = 'denied', decided_at = $2, decided_by = $3, decision_note = $4 \
          WHERE id = $1 AND state = 'pending' \
        RETURNING id",
    )
    .bind(id)
    .bind(now)
    .bind(&decided_by)
    .bind(body.note.as_deref())
    .fetch_optional(&mut **tx)
    .await
    .map_err(StoreError::from)?;

    if refused.is_none() {
        // The row exists — `decidable` just read it — so it was decided by
        // somebody else first.
        return Err(ApiError::conflict(
            "approval_already_decided",
            "this approval has already been decided",
        ));
    }

    // Same transaction as the UPDATE: a refusal nobody recorded is a refusal
    // nobody can be shown to have made.
    audit::append(
        &mut tx,
        &AuditEvent {
            employee_id: row.employee_id.map(EmployeeId::from_uuid),
            payload: json!({
                "approval_id": id.to_string(),
                "outcome": "denied",
                "requested_by": row.requested_by,
                "note": body.note,
            }),
            ..AuditEvent::new(principal.actor.clone(), AuditKind::ApprovalDecided, now)
        },
    )
    .await?;
    tx.commit().await?;

    Ok(Json(json!({ "id": id.to_string(), "state": "denied" })))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::gate::Denied;
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use axum::middleware::from_fn_with_state;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{ApiKeys, require_api_key};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_SECRET: &str = "fedcba9876543210fedcba9876543210";

    // -- fixtures ----------------------------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; approval routes need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one active employee.
    async fn seed(db: &Db) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("u32-{}", employee.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        // A policy that grants nothing. The gate reads its policy out of the
        // database now, and a tenant with no layer at all is refused before the
        // rule is reached — which would make every "pending approval" below a
        // `broken_policy` instead.
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &agentos_domain::policy::PolicyLimits::default(),
        )
        .await
        .expect("install the policy");

        (tenant, employee)
    }

    /// Contracts always need a human, whatever the policy says — so a policy
    /// that grants nothing is enough to file one, and the fixture cannot
    /// accidentally be testing a spend limit.
    fn contract(title: &str) -> Action {
        Action::ContractSign {
            title: title.to_owned(),
        }
    }

    /// File a real approval by asking the gate for something it has to escalate.
    async fn file(gate: &PolicyGate, principal: &GatePrincipal, action: &Action) -> ApprovalId {
        match gate.authorize(principal, action.clone()).await {
            Err(Denied::PendingApproval(id)) => id,
            other => panic!("expected a pending approval, got {other:?}"),
        }
    }

    fn mount(db: &Db, gate: &PolicyGate, keys: ApiKeys) -> Router {
        router(db.clone(), gate.clone()).layer(from_fn_with_state(keys, require_api_key))
    }

    /// One authenticated request. `body` `None` means GET.
    async fn call(
        app: &Router,
        uri: &str,
        secret: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let req = HttpRequest::builder()
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {secret}"));
        let req = match &body {
            Some(body) => req
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => req.method("GET").body(Body::empty()),
        }
        .expect("request");

        let response = app.clone().oneshot(req).await.expect("service");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The keyring for one tenant, with `label` as the caller's role.
    fn keys(tenant: TenantId, label: &str, secret: &str) -> ApiKeys {
        ApiKeys::parse(&format!("{label}:{}:{secret}", tenant.as_uuid())).expect("keyring")
    }

    async fn state_of(db: &Db, tenant: TenantId, id: ApprovalId) -> String {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let state: String = sqlx::query_scalar("SELECT state FROM approvals WHERE id = $1")
            .bind(id.as_uuid())
            .fetch_one(&mut **tx)
            .await
            .expect("read state");
        tx.commit().await.expect("commit");
        state
    }

    // -- the queue ---------------------------------------------------------

    #[tokio::test]
    async fn the_queue_is_tenant_scoped_and_oldest_first() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (mine, my_employee) = seed(&db).await;
        let (theirs, their_employee) = seed(&db).await;

        let me = GatePrincipal::employee(mine, my_employee);
        let first = file(&gate, &me, &contract("first")).await;
        let second = file(&gate, &me, &contract("second")).await;
        let hidden = file(
            &gate,
            &GatePrincipal::employee(theirs, their_employee),
            &contract("not yours"),
        )
        .await;

        let app = mount(&db, &gate, keys(mine, "approver", SECRET));
        let (status, body) = call(&app, "/v1/approvals", SECRET, None).await;

        assert_eq!(status, StatusCode::OK);
        let queue = body["approvals"].as_array().expect("a list");
        let ids: Vec<&str> = queue
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(
            ids,
            vec![
                first.as_uuid().to_string().as_str(),
                second.as_uuid().to_string().as_str()
            ],
            "oldest first, and only this tenant's"
        );

        // The queue is what a human reads, so the summary and the deadline are
        // both on it.
        assert_eq!(queue[0]["summary"], json!("sign contract \"first\""));
        assert_eq!(queue[0]["action_kind"], json!("contract_sign"));
        assert_eq!(queue[0]["required_role"], json!("approver"));
        assert!(queue[0]["expires_at"].is_string(), "{:?}", queue[0]);

        // And the nonce is not, anywhere.
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        let nonce: String =
            sqlx::query_scalar("SELECT action->>'nonce' FROM approvals WHERE id = $1")
                .bind(first.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("nonce");
        tx.commit().await.expect("commit");
        assert!(
            !body.to_string().contains(&nonce),
            "the queue leaked a nonce"
        );

        // The other tenant's item is invisible, not merely unlisted: naming it
        // directly is a 404.
        let (status, _) = call(
            &app,
            &format!("/v1/approvals/{}", hidden.as_uuid()),
            SECRET,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // -- approve -----------------------------------------------------------

    /// The headline: the human approved one action, the body names another, and
    /// the approval is refused *and survives*.
    #[tokio::test]
    async fn approving_a_mutated_action_is_refused_and_approving_twice_fails() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (tenant, employee) = seed(&db).await;
        let approved = contract("supply agreement with A");
        let id = file(&gate, &GatePrincipal::employee(tenant, employee), &approved).await;

        let app = mount(&db, &gate, keys(tenant, "approver", SECRET));
        let uri = format!("/v1/approvals/{}/approve", id.as_uuid());

        // Same kind, same id, same nonce — a different action.
        let (status, body) = call(
            &app,
            &uri,
            SECRET,
            Some(json!({ "action": contract("supply agreement with B") })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], json!("approval_action_mismatch"));
        assert_eq!(
            state_of(&db, tenant, id).await,
            "pending",
            "a refused swap must not burn the approval"
        );

        // The real thing goes through.
        let (status, body) = call(&app, &uri, SECRET, Some(json!({ "action": approved }))).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(body["state"], json!("redeemed"));
        assert!(body["decision_id"].is_string(), "{body:?}");
        assert_eq!(state_of(&db, tenant, id).await, "redeemed");

        // Once.
        let (status, body) = call(&app, &uri, SECRET, Some(json!({ "action": approved }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], json!("approval_already_decided"));
    }

    #[tokio::test]
    async fn an_expired_approval_cannot_be_approved() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (tenant, employee) = seed(&db).await;
        let action = contract("late");
        let id = file(&gate, &GatePrincipal::employee(tenant, employee), &action).await;

        // Fast-forward rather than wait 24 hours for the TTL.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("expire");
        tx.commit().await.expect("commit");

        let app = mount(&db, &gate, keys(tenant, "approver", SECRET));
        let (status, body) = call(
            &app,
            &format!("/v1/approvals/{}/approve", id.as_uuid()),
            SECRET,
            Some(json!({ "action": action })),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], json!("approval_expired"));
        assert_eq!(state_of(&db, tenant, id).await, "pending");
    }

    /// Four eyes, from both sides: the wrong role cannot decide at all, and the
    /// requester cannot approve itself even holding the right one.
    #[tokio::test]
    async fn a_requester_cannot_approve_itself_and_the_wrong_role_cannot_decide() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (tenant, employee) = seed(&db).await;
        let action = contract("self service");

        // Filed by the human whose key is labelled `approver`, so `requested_by`
        // is exactly the label that key presents.
        let id = file(
            &gate,
            &GatePrincipal::operator(tenant, employee, "approver"),
            &action,
        )
        .await;
        let uri = format!("/v1/approvals/{}/approve", id.as_uuid());
        let body = json!({ "action": action });

        let app = mount(&db, &gate, keys(tenant, "approver", SECRET));
        let (status, answer) = call(&app, &uri, SECRET, Some(body.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(answer["code"], json!("self_approval"));

        // A different human, but the key is labelled `ops`: no role, no verdict.
        let app = mount(&db, &gate, keys(tenant, "ops", OTHER_SECRET));
        let (status, answer) = call(&app, &uri, OTHER_SECRET, Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(answer["code"], json!("role_required"));

        assert_eq!(state_of(&db, tenant, id).await, "pending");
    }

    // -- deny --------------------------------------------------------------

    #[tokio::test]
    async fn a_deny_is_recorded_and_the_action_never_executes() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (tenant, employee) = seed(&db).await;
        let action = contract("a deal we will not sign");
        let id = file(&gate, &GatePrincipal::employee(tenant, employee), &action).await;

        let app = mount(&db, &gate, keys(tenant, "approver", SECRET));
        let (status, body) = call(
            &app,
            &format!("/v1/approvals/{}/deny", id.as_uuid()),
            SECRET,
            Some(json!({ "note": "the terms are wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(body["state"], json!("denied"));

        // The decision is on the record, with a decider and a note.
        let (status, view) = call(
            &app,
            &format!("/v1/approvals/{}", id.as_uuid()),
            SECRET,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["state"], json!("denied"));
        assert_eq!(view["decided_by"], json!("operator:approver"));
        assert!(view["decided_at"].is_string(), "{view:?}");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let (kind, payload): (String, Value) = sqlx::query_as(
            "SELECT action_kind, payload FROM audit_log \
              WHERE employee_id = $1 ORDER BY occurred_at DESC, id DESC LIMIT 1",
        )
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("audit row");
        // Nothing was ever allowed for this employee: the gate never ruled
        // `allow`, because the nonce was never spendable after the refusal.
        let allowed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE employee_id = $1 AND decision = 'allow'",
        )
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("count");
        tx.commit().await.expect("commit");

        assert_eq!(kind, "approval_decided");
        assert_eq!(payload["outcome"], json!("denied"));
        assert_eq!(payload["note"], json!("the terms are wrong"));
        assert_eq!(allowed, 0);

        // And it stays refused: the nonce is dead.
        let (status, answer) = call(
            &app,
            &format!("/v1/approvals/{}/approve", id.as_uuid()),
            SECRET,
            Some(json!({ "action": action })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(answer["code"], json!("approval_already_decided"));
        assert_eq!(state_of(&db, tenant, id).await, "denied");
    }
}
