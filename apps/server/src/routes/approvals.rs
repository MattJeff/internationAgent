//! The human approval queue, and the two buttons on it.
//!
//! ```text
//! GET  /v1/approvals                    the queue: pending, oldest first
//! GET  /v1/approvals/{id}               one item, decided or not
//! POST /v1/approvals/{id}/approve       redeem it
//! POST /v1/approvals/{id}/deny          refuse it
//!
//! GET  /v1/capability-requests          what employees keep being refused
//! POST /v1/capability-requests/decide   answer one
//! ```
//!
//! # The two halves, and why the second one is here
//!
//! The first four routes are one direction: *the employee wants to do a thing
//! the policy says needs a human, so a human presses a button and the thing
//! happens.* The last two are the other direction, and until this wave it did
//! not exist — an employee that discovers it is **missing a capability** was
//! refused by the gate, wrote a sentence in its answer that nobody read, and
//! tried again tomorrow.
//!
//! They share a file because they share the surface a human looks at, the role
//! that credential must hold, and [`held_role`]. They share nothing else, and
//! the difference is the whole of the second half's safety: an approval mints an
//! [`Authorized`](agentos_app::gate::Authorized) and releases an effect, while a
//! capability decision **releases nothing** and changes no policy. See
//! [`decide_capability`].
//!
//! # Why `approve` takes the action in its body
//!
//! The failure this endpoint exists to prevent is not "somebody approved the
//! wrong thing", it is "somebody approved *this* thing and something else was
//! executed". So the approver does not press a button next to an id — it
//! restates the action it is approving, and [`PolicyGate::redeem_approval`]
//! re-hashes that restatement against the hash filed when the approval was
//! requested. Approve a contract titled A and the body names B, and the
//! redemption is refused with `approval_action_mismatch`.
//!
//! # And it does not hold for a payment, which is the one that moves money
//!
//! This paragraph used to say "approve $100 to supplier A and the body says
//! supplier B". **That is false, and it was false in the direction that
//! matters.** The hash is taken over the `Action`, and
//! `Action::PaymentCreate` carries `amount` and nothing else — no payee. Two
//! payments to two different counterparties for the same amount hash
//! identically, so restating one as the other is refused by nothing. The
//! founder's queue shows `pay €500.00` for the same reason: no payee was ever
//! filed to show.
//!
//! The absence is itself deliberate and argued at `Action::PaymentCreate`: the
//! gate rules on "may this seat move this much", never on "to whom". That is
//! coherent for a policy engine and incoherent for a human approval queue, and
//! nobody had written the second half down.
//!
//! Both tests guarding this ceremony are blind to it by construction — one
//! mutates a contract's *title* and one a payment's *amount*, and both of those
//! **are** in the action. Neither mutates a payee, and neither can. The fix is
//! a payee on the action and a test that approves toward A and presents B.
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
//! # Why there is no "where did this come from" on the queue
//!
//! The obvious missing field on [`ApprovalView`] is provenance: *this request
//! was built from a page your employee read*. It is missing because it has one
//! possible value. Every arm of `policy::evaluate` that answers
//! `RequireApproval` is `Risk::High`, and the taint wire refuses a high-risk
//! action from untrusted input before an approval is filed — so a tainted row
//! cannot exist. The four call sites that file approvals outside the gate —
//! `agentos_app::provisioning` and the three in `crate::loops::provisioning` —
//! compose their text from step names and employee ids, never from a document.
//! `agentos_app::gate`'s `an_untrusted_turn_puts_no_line_in_the_approval_queue`
//! is that claim against the real table.
//!
//! A column reading `trusted` on every row is the shape this repository has
//! deleted twice — a `traceparent` NULL everywhere, a memory table nothing
//! wrote. The one thing that would make it worth writing is an arm answering
//! `RequireApproval` for a `Risk::Low` action, which the wire does not catch;
//! that gate test names it as the edge it does not cover, and nothing else in
//! the workspace watches for it either. Revisit then, and not before.
//!
//! Denying is the mirror: one guarded `UPDATE` off `pending`, one audit row, in
//! one transaction. After it the nonce can never be spent — the gate's own
//! redemption predicate requires `state = 'pending'` — which is what "the
//! action never executes" means at this layer.

use agentos_app::gate::{PolicyGate, Principal as GatePrincipal};
use agentos_domain::action::{Action, ActionKind};
use agentos_domain::ids::{ApprovalId, EmployeeId};
use agentos_domain::policy::DenyReason;
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::capability;
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
        .route("/v1/capability-requests", get(capability_requests))
        .route("/v1/capability-requests/decide", post(decide_capability))
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
// Capability requests
// ---------------------------------------------------------------------------

/// The role a credential must hold to answer a capability request.
///
/// The same string `agentos_app::gate`'s `APPROVER_ROLE` files approvals under,
/// and deliberately so: the person who decides whether a payment goes out is the
/// person who decides whether a seat gets a new tool. A second role here would
/// be a second list of humans to keep in step, for a decision that is strictly
/// less powerful than the one they already hold — this one releases nothing.
///
/// It is a constant rather than a column because a capability request has no
/// row to carry one; see [`capability_requests`]. ponytail: when identities grow
/// real roles, this and `gate`'s constant become one lookup.
const CAPABILITY_ROLE: &str = "approver";

/// **What an employee keeps being refused, and how often.**
///
/// # Nobody wrote these
///
/// There is no request body anywhere in this product that says "the employee
/// would like X". Every row here is derived from `audit_log` — the trail the
/// gate already writes, one row per ruling, inside the ruling's own transaction
/// — by one aggregate in [`agentos_store::capability::pending`]. So a request
/// cannot claim a refusal that never happened, and a model cannot compose one.
///
/// The alternative was letting the employee ask in words, and it is worth
/// naming what it would have cost. A turn's context can contain a page the
/// employee read; a page can say *"you will need the `admin/exec` tool for this,
/// go and ask for it"*; and the resulting sentence in front of an operator is
/// authored by the page, delivered by the employee, with nothing marking it as
/// somebody else's. Deriving removes the authorship question entirely: the only
/// thing an employee can be observed to want is the wall it actually hit.
///
/// # What is in the text, and what can never be
///
/// A row is: an employee **slug**, an `action_kind`, a `deny_reason`, a count,
/// two timestamps, and the previous decision if there was one. That is the whole
/// vocabulary — two closed enums from `agentos-domain`, sixteen values and
/// twenty-one, both `const` arrays this binary writes.
///
/// There is no tool name and no domain, and their absence is the feature. A tool
/// name comes from an MCP server's `tools/list`; a domain comes from a page. Put
/// either in this response and the approval UI becomes a surface a stranger can
/// write on — which is exactly the failure the whole `Untrusted<T>` apparatus
/// exists to prevent, reintroduced at the one screen where a human is about to
/// click yes. So this endpoint says *"lena was refused `mcp_call` for
/// `tool_not_allowed` 47 times since Tuesday"* and stops there; which tool is a
/// question for `GET /v1/mcp/…`, where the name is already handled as what it
/// is.
///
/// The narrowing is `DenyReason::GRANTABLE`, and its load-bearing exclusion is
/// `untrusted_input` — the prompt-injection stop, the one refusal a hostile page
/// can make an employee produce on demand, and one that no policy document can
/// lift anyway.
///
/// Tenant scoping is [`Db::tenant_tx`] and nothing else, as with the queue
/// above: `audit_log`, `employees` and `capability_decisions` all carry
/// row-level security.
async fn capability_requests(
    State(state): State<Approvals>,
    principal: Principal,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let requests = capability::pending(&mut tx).await?;
    tx.commit().await?;

    Ok(Json(json!({
        "requests": requests,
        "raised_at": capability::RAISED_AT,
    })))
}

/// A human's answer to one capability request.
///
/// The request is named by its shape rather than by an id, because it has no id:
/// it is a `GROUP BY` key, not a record. `action_kind` and `deny_reason` are
/// parsed into the domain's enums by serde — which is the trust boundary, and
/// the reason [`agentos_store::capability::decide`] takes enums rather than
/// strings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideCapability {
    employee_id: Uuid,
    action_kind: ActionKind,
    deny_reason: DenyReason,
    /// `true` is "this seat should have it", `false` is "it should not".
    granted: bool,
    /// The operator's own sentence, for the next operator. Optional and worth
    /// writing.
    #[serde(default)]
    note: Option<String>,
}

/// **Answer a capability request — and change no policy doing it.**
///
/// # What this does
///
/// One row in `capability_decisions`, one `capability_decided` row in
/// `audit_log`, one transaction. That is all of it.
///
/// # What it does not do, and why it must not
///
/// It does not touch `policy_layers`. `routes::companies` states the arithmetic
/// this rests on: an absent layer inherits, so writing a layer where none
/// existed takes the effective policy from `above ∧ above` to `above ∧ new` and
/// **cannot widen anything** — while *replacing* a layer has no such property,
/// because the new layer is not intersected with the old one.
///
/// Every remedy a capability request asks for is the second kind. "Add this tool
/// to `allowed_mcp_tools`" on a seat that already has a layer naming some tools
/// is precisely the write that widens an intersection; so is raising a cap, so
/// is adding a channel. There is no version of this endpoint that applies the
/// fix and keeps the rule that nothing widens an effective policy — so it does
/// not apply the fix.
///
/// What it leaves to do by hand is therefore the honest half of the feature, and
/// the response says so in as many words: `agentos-server policy install
/// --tenant … [--role … | --employee …] layer.json`, on the operator's own
/// database credential. That is the same trade
/// `agentos_store::revenue::set_prospect_flow` makes for a prospect's selectors
/// and for the same reason — the write that matters is an operator's act, proved
/// by a credential no employee and no HTTP caller holds.
///
/// A grant that nobody installs is not lost, either: the employee keeps being
/// refused, and after `RAISED_AT` more refusals the request comes back with its
/// old decision attached. An unimplemented promise is visible rather than
/// filed away.
///
/// # Four eyes is deliberately absent
///
/// `approve` refuses a caller whose label equals the approval's `requested_by`,
/// because an agent that approves its own payments has an approval workflow in
/// name only. Here there is no requester: nobody asked, the trail did. There is
/// no self-dealing available and so nothing to check — and inventing a
/// `requested_by` for a derived row would be a fact about a person that no
/// person is behind.
///
/// # Refusals
///
/// | | |
/// |---|---|
/// | the credential does not hold `approver` | `403 role_required` |
/// | this tenant's trail has no such refusal | `404` |
///
/// The 404 is one `EXISTS` in the store's `INSERT … SELECT … WHERE EXISTS`, and
/// it is doing two jobs at once: it refuses a decision about a refusal that
/// never happened, and — because it reads `audit_log` through this tenant's own
/// transaction — it is what stops an operator recording a decision about another
/// company's employee. Both come out as "there is no such request", which is the
/// truthful answer to each.
async fn decide_capability(
    State(state): State<Approvals>,
    principal: Principal,
    Json(body): Json<DecideCapability>,
) -> Result<Json<Value>, ApiError> {
    if held_role(&principal.actor) != Some(CAPABILITY_ROLE) {
        return Err(forbidden(
            "role_required",
            "this credential does not hold the role a capability decision requires",
        ));
    }

    let now = Utc::now();
    let employee_id = EmployeeId::from_uuid(body.employee_id);
    let outcome = if body.granted {
        capability::Outcome::Granted
    } else {
        capability::Outcome::Refused
    };
    let decided_by = principal.actor.label();

    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let recorded = capability::decide(
        &mut tx,
        employee_id,
        body.action_kind,
        body.deny_reason,
        outcome,
        &decided_by,
        body.note.as_deref(),
        now,
    )
    .await?;

    if !recorded {
        return Err(ApiError::not_found());
    }

    // Same transaction as the row: a decision nobody recorded is a decision
    // nobody can be shown to have made. `note` is the operator's own text, from
    // an authenticated body — the only free prose anywhere in this feature.
    audit::append(
        &mut tx,
        &AuditEvent {
            employee_id: Some(employee_id),
            payload: json!({
                "action_kind": body.action_kind.as_str(),
                "deny_reason": body.deny_reason.code(),
                "outcome": outcome.as_str(),
                "note": body.note,
            }),
            ..AuditEvent::new(principal.actor.clone(), AuditKind::CapabilityDecided, now)
        },
    )
    .await?;
    tx.commit().await?;

    let mut answer = json!({
        "employee_id": body.employee_id.to_string(),
        "action_kind": body.action_kind.as_str(),
        "deny_reason": body.deny_reason.code(),
        "outcome": outcome.as_str(),
        "widened": false,
    });
    if body.granted {
        answer["remaining"] = json!(format!(
            "Nothing has been widened. Install the layer that grants it, on the operator's \
             own DATABASE_URL: `agentos-server policy install --tenant {} [--role <name> | \
             --employee {}] layer.json`. Until then this employee is still refused, and the \
             request will come back.",
            principal.tenant_id.as_uuid(),
            body.employee_id
        ));
    }
    Ok(Json(answer))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::gate::Denied;
    use agentos_domain::ids::{Slug, TenantId};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use axum::middleware::from_fn_with_state;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{ApiKeys, require_api_key};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_SECRET: &str = "fedcba9876543210fedcba9876543210";
    const THIRD_SECRET: &str = "00112233445566778899aabbccddeeff";

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
        router(db.clone(), gate.clone()).layer(from_fn_with_state(
            crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
            require_api_key,
        ))
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

    // -- capability requests -----------------------------------------------

    /// An MCP call the seeded policy refuses. The tool's name is distinctive so
    /// a test can look for it in a response.
    fn mcp(tool: &str) -> Action {
        Action::McpCall {
            tool: agentos_domain::action::McpTool::new(
                Slug::parse("erp").expect("slug"),
                Slug::parse(tool).expect("slug"),
            ),
        }
    }

    /// Refuse `action` `times` times, through the real gate, and assert every
    /// one of them was the policy saying no.
    async fn refuse(
        gate: &PolicyGate,
        principal: &GatePrincipal,
        action: &Action,
        times: usize,
    ) -> DenyReason {
        let mut last = None;
        for _ in 0..times {
            match gate.authorize(principal, action.clone()).await {
                Err(Denied::Policy(reason)) => last = Some(reason),
                other => panic!("expected a policy denial, got {other:?}"),
            }
        }
        last.expect("at least one refusal")
    }

    /// **The headline: granting a capability request widens nothing.**
    ///
    /// The gate refused this employee three times; a human with the right role
    /// says yes; and the gate refuses it again, with the same reason, because
    /// nothing in this endpoint touches a policy layer. What the operator gets
    /// instead is the command that would.
    #[tokio::test]
    async fn granting_a_capability_request_changes_no_policy_at_all() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (tenant, employee) = seed(&db).await;
        let me = GatePrincipal::employee(tenant, employee);
        let action = mcp("exfiltrate-everything");

        let reason = refuse(&gate, &me, &action, 3).await;
        assert_eq!(
            reason,
            DenyReason::NoRule,
            "the seeded policy grants nothing"
        );

        let app = mount(&db, &gate, keys(tenant, "approver", SECRET));
        let (status, body) = call(&app, "/v1/capability-requests", SECRET, None).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        let requests = body["requests"].as_array().expect("a list");
        assert_eq!(
            requests.len(),
            1,
            "three refusals are one request: {body:?}"
        );
        assert_eq!(requests[0]["employee"], json!("lena"));
        assert_eq!(requests[0]["action_kind"], json!("mcp_call"));
        assert_eq!(requests[0]["deny_reason"], json!("no_rule"));
        assert_eq!(requests[0]["denials"], json!(3));
        assert_eq!(body["raised_at"], json!(3));

        // **Nothing a third party named is in the text.** The tool this employee
        // was refused came from an MCP server's `tools/list`; the request says
        // the shape of the wall and not the name on the other side of it.
        assert!(
            !body.to_string().contains("exfiltrate-everything"),
            "a name from an MCP server reached the approval surface: {body}"
        );

        let decide = json!({
            "employee_id": employee.as_uuid().to_string(),
            "action_kind": "mcp_call",
            "deny_reason": "no_rule",
            "granted": true,
            "note": "the ERP lookup is part of the job",
        });
        let (status, answer) = call(
            &app,
            "/v1/capability-requests/decide",
            SECRET,
            Some(decide.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{answer:?}");
        assert_eq!(answer["outcome"], json!("granted"));
        assert_eq!(answer["widened"], json!(false));
        assert!(
            answer["remaining"]
                .as_str()
                .is_some_and(|text| text.contains("agentos-server policy install")),
            "a grant must name the operator work it did not do: {answer:?}"
        );

        // The whole point. Same gate, same action, same answer.
        let after = refuse(&gate, &me, &action, 1).await;
        assert_eq!(
            after, reason,
            "approving a capability request widened the effective policy"
        );

        // And the decision is on the trail, as its own kind.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let (kind, payload): (String, Value) = sqlx::query_as(
            "SELECT action_kind, payload FROM audit_log \
              WHERE action_kind = 'capability_decided' AND employee_id = $1",
        )
        .bind(employee.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("the capability decision was not audited");
        tx.commit().await.expect("commit");
        assert_eq!(kind, "capability_decided");
        assert_eq!(payload["outcome"], json!("granted"));
        assert_eq!(payload["note"], json!("the ERP lookup is part of the job"));

        // One refusal since the decision is under the bar, so the queue is
        // quiet — and it will speak again after two more.
        let (_, body) = call(&app, "/v1/capability-requests", SECRET, None).await;
        assert_eq!(
            body["requests"].as_array().expect("a list").len(),
            0,
            "a decided request must leave the queue: {body:?}"
        );
        refuse(&gate, &me, &action, 2).await;
        let (_, body) = call(&app, "/v1/capability-requests", SECRET, None).await;
        let requests = body["requests"].as_array().expect("a list");
        assert_eq!(requests.len(), 1, "three more refusals reopen it: {body:?}");
        assert_eq!(requests[0]["denials"], json!(3));
        assert_eq!(requests[0]["decided"], json!("granted"));
    }

    /// **The hard constraint, at the surface an operator actually holds.**
    ///
    /// A key for one company can neither see nor decide another company's
    /// request, and the wrong role decides nothing at all.
    #[tokio::test]
    async fn one_tenant_can_neither_read_nor_decide_another_tenants_request() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (mine, _my_employee) = seed(&db).await;
        let (theirs, their_employee) = seed(&db).await;

        refuse(
            &gate,
            &GatePrincipal::employee(theirs, their_employee),
            &mcp("their-tool"),
            4,
        )
        .await;

        // Their own operator sees it.
        let theirs_app = mount(&db, &gate, keys(theirs, "approver", OTHER_SECRET));
        let (_, body) = call(&theirs_app, "/v1/capability-requests", OTHER_SECRET, None).await;
        assert_eq!(body["requests"].as_array().expect("a list").len(), 1);

        // Mine sees nothing, and naming their employee outright is a 404 —
        // invisible, not merely unlisted.
        let app = mount(&db, &gate, keys(mine, "approver", SECRET));
        let (status, body) = call(&app, "/v1/capability-requests", SECRET, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["requests"].as_array().expect("a list").is_empty(),
            "another company's requests are in this queue: {body:?}"
        );

        let poach = json!({
            "employee_id": their_employee.as_uuid().to_string(),
            "action_kind": "mcp_call",
            "deny_reason": "no_rule",
            "granted": true,
        });
        let (status, _) = call(
            &app,
            "/v1/capability-requests/decide",
            SECRET,
            Some(poach.clone()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a tenant decided another tenant's capability request"
        );

        // And theirs is untouched by the attempt — not silenced, not decided.
        let (_, body) = call(&theirs_app, "/v1/capability-requests", OTHER_SECRET, None).await;
        let requests = body["requests"].as_array().expect("a list");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["decided"], json!(null), "{body:?}");

        // A key that holds no approver role decides nothing, in its own tenant
        // or anywhere else.
        let ops = mount(&db, &gate, keys(theirs, "ops", THIRD_SECRET));
        let (status, answer) = call(
            &ops,
            "/v1/capability-requests/decide",
            THIRD_SECRET,
            Some(poach),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(answer["code"], json!("role_required"));
    }

    /// **A refusal no policy can lift cannot be decided, even by name.**
    ///
    /// `untrusted_input` is the prompt-injection stop and the one deny reason a
    /// page the employee read can provoke on demand — so it is outside
    /// `DenyReason::GRANTABLE`, and there is no request behind it to answer.
    /// That it never reaches the *queue* either is asserted one layer down, in
    /// `agentos_store::capability`'s
    /// `the_taint_stop_and_a_denylisted_domain_never_reach_the_queue`, against
    /// rows in exactly the shape `PolicyGate` writes: provoking a real taint
    /// refusal needs a policy that *allows* a high-risk action, which is a
    /// fixture about spend limits rather than about this endpoint.
    #[tokio::test]
    async fn a_refusal_a_hostile_page_can_provoke_cannot_be_granted() {
        let Some(db) = db().await else { return };
        let gate = PolicyGate::new(db.clone());
        let (tenant, employee) = seed(&db).await;
        let app = mount(&db, &gate, keys(tenant, "approver", SECRET));

        for (kind, reason) in [
            (ActionKind::PaymentCreate, DenyReason::UntrustedInput),
            (ActionKind::BrowserRead, DenyReason::DomainDenied),
            (ActionKind::CharterSet, DenyReason::SelfDirection),
        ] {
            // The refusals are real and on the trail — written here rather than
            // provoked, because each of the three needs a different policy to
            // reach. So the only thing standing between this operator and a
            // recorded grant is `DenyReason::grantable`.
            for i in 0..5 {
                let mut tx = db.tenant_tx(tenant).await.expect("tx");
                audit::append(
                    &mut tx,
                    &AuditEvent {
                        employee_id: Some(employee),
                        decision: Some(agentos_domain::policy::Decision::Deny { reason }),
                        ..AuditEvent::new(
                            AuditActor::Employee(employee),
                            AuditKind::Action(kind),
                            Utc::now() - chrono::TimeDelta::minutes(i),
                        )
                    },
                )
                .await
                .expect("append");
                tx.commit().await.expect("commit");
            }

            let (status, body) = call(
                &app,
                "/v1/capability-requests/decide",
                SECRET,
                Some(json!({
                    "employee_id": employee.as_uuid().to_string(),
                    "action_kind": kind.as_str(),
                    "deny_reason": reason.code(),
                    "granted": true,
                })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{} was recorded as granted by a human: {body:?}",
                reason.code()
            );
        }

        // Nor is any of them in the queue a human reads.
        let (_, body) = call(&app, "/v1/capability-requests", SECRET, None).await;
        assert!(
            body["requests"].as_array().expect("a list").is_empty(),
            "a refusal no policy can lift reached the approval queue: {body:?}"
        );

        // Nothing was written for any of them.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM capability_decisions WHERE employee_id = $1")
                .bind(employee.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("count");
        tx.commit().await.expect("commit");
        assert_eq!(rows, 0);
    }
}
