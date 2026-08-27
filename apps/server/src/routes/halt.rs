//! `/v1/halt`: stop the whole company, and let it go again.
//!
//! **The call this exists for is somebody saying "stop everything, now".**
//! Before this file the answer was a loop over `POST /v1/employees/{id}/suspend`
//! in an order nobody had chosen, which is not an answer: the first seat
//! suspended can still be woken by the last one that has not been, an approval
//! filed this morning is still clickable, and a turn already inside a model call
//! is still going to spend its twenty tool calls on the way out.
//!
//! # What a customer is promised, exactly
//!
//! Three sentences, and the third one is a refusal to lie:
//!
//! 1. **No new turn starts.** `agentos_app::model_access::connected` reads the
//!    halt before a turn is reserved, so a stopped company thinks about nothing
//!    and is billed for nothing. Its outbox rows are not claimed at all
//!    (`agentos_store::outbox::claim_except`), so nothing waiting is lost and
//!    nothing burns an attempt.
//! 2. **No effect reaches the world.** `agentos_app::gate::PolicyGate` reads the
//!    halt before it reads any policy, and every effect in the workspace needs a
//!    token only that gate can mint. There is no second door.
//! 3. **What is already in flight is not recalled, and cannot be.** A message
//!    handed to Resend is gone; there is no API for un-sending it and this
//!    product will not pretend otherwise. What is bounded is how long that
//!    window is: at most one already-dispatched provider call per employee, and
//!    the provider clients time out at sixty seconds
//!    (`crates/providers/src/email_resend.rs`, `telephony_twilio.rs`,
//!    `browser_browserbase.rs`). A turn already inside a model call keeps
//!    thinking until its own 120-second deadline and then stops, having been
//!    refused at every tool call it tried on the way.
//!
//! So: **nothing new after the commit; sixty seconds of tail.** That is the
//! number to say out loud, and it is a ceiling rather than a measurement.
//!
//! # What a halt deliberately does not stop
//!
//! **Receiving.** The inbound loop keeps fetching mail and landing it in
//! `messages`, and the turns it queues wait in the outbox until the release.
//! Stopping ingestion would mean a stopped company losing its customers' email,
//! which is worse than the thing the halt is for, and reading is not acting —
//! the same asymmetry `agentos_app::effects::Effects::opted_out` is argued from.
//!
//! **Provisioning.** `apps/server/src/loops/provisioning.rs` converges an
//! employee somebody already asked for towards mailboxes and phone numbers, with
//! no policy gate anywhere on its path. It is not covered here, and the honest
//! reason is that half-covering it is worse than not: interrupting convergence
//! leaves resources bought and unbound, which is what
//! `GET /v1/inventory/stranded` exists to find. Stopping it properly means a
//! resumable state machine that knows how to be paused, and that is not this
//! unit.
//!
//! # Who may throw it
//!
//! A human, and the audit row names them. That is not enforced by a role check
//! here — it is enforced by there being nothing for an employee to reach it
//! with. No `Action` variant rules on a halt, so `PolicyGate` cannot mint a
//! token for one; `Effects` exposes no method; `agentos_store::halt` is called
//! from exactly two readers and this one writer; and every HTTP caller is an
//! operator API key (`crate::auth`), never a seat. A tenant cannot halt another
//! tenant because the write goes through `tenant_tx` and `company_halts` has RLS
//! forced with `with check` — Postgres refuses it, not a handler.
//!
//! # Why the release is not a widening
//!
//! It deletes one row. No `policy_layers` row is written by either verb, so the
//! effective policy after a release is the same four rows it was before the
//! halt — there is no saved copy to restore wrong and no path by which coming
//! back up grants anything that was not already granted. That property is why
//! the halt is its own table rather than an empty tenant policy layer, and
//! `migrations/0045_company_halt.sql` argues it in full.

use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::Db;
use agentos_store::halt::{self, Halt};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiError;

/// The two states, as the payload of a [`AuditKind::CompanyHaltChanged`] row
/// spells them. Constants because the halt row is deleted on release and these
/// strings are then the only record of the direction it moved.
const RUNNING: &str = "running";
const HALTED: &str = "halted";

/// This unit's routes. Merged into the API router, so auth is already in front.
///
/// One path and three verbs, and the shape is the argument: a halt is a
/// *resource that exists or does not*, not a field with a boolean in it. `POST`
/// creates it, `DELETE` removes it, `GET` says whether it is there. A
/// `PUT /v1/halt {"halted": false}` would make "stop the company" and "start it
/// again" the same call with a different body, which is one typo away from the
/// wrong one.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/halt", get(status).post(place).delete(release))
        .with_state(db)
}

/// Why the company is being stopped.
///
/// Required, and there is no default. The reason is the entire evidentiary
/// value of the row — it is shown to every refusal, copied into the audit trail,
/// and read back out at the post-mortem — and a handler that invented one would
/// be putting words in an operator's mouth about an emergency.
#[derive(Deserialize)]
struct HaltRequest {
    reason: String,
}

/// `GET /v1/halt` — is this company stopped, and what has it refused.
///
/// The count is the answer to "what did not happen while we were down", and it
/// is here rather than on a reporting endpoint because it is the sentence that
/// follows the switch's own state in the same breath. It is derived from
/// `audit_log`, not from a counter, so it cannot drift from the rows it counts.
async fn status(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let halt = halt::halted(&mut tx).await?;
    let refused = match &halt {
        Some(halt) => Some(halt::refused_since(&mut tx, halt.halted_at).await?),
        None => None,
    };
    tx.rollback().await?;

    Ok(Json(view(halt.as_ref(), refused)).into_response())
}

/// `POST /v1/halt` — stop everything.
///
/// 409 when the company is already stopped, and deliberately not a quiet 200:
/// the second caller's reason is *not* recorded (the row cannot be updated, see
/// the migration), so answering "fine" would tell them their sentence is the one
/// on the record when the first caller's is. Two people reaching for the same
/// switch in the same minute is exactly when that matters.
async fn place(
    State(db): State<Db>,
    principal: Principal,
    Json(body): Json<HaltRequest>,
) -> Result<Response, ApiError> {
    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::bad_request(
            "say why the company is being stopped; the reason is shown on every refusal \
             and read back at the post-mortem",
        ));
    }

    let now = Utc::now();
    let who = principal.actor.label();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    let Some(halt) = halt::place(&mut tx, reason, &who, now).await? else {
        return Err(ApiError::conflict(
            "already_halted",
            "this company is already stopped; release it before stopping it for another reason",
        ));
    };

    // Same transaction as the row it describes, so the trail can never claim a
    // halt the table does not have — nor miss one it does. This is the row that
    // answers "who stopped us and when" after the `company_halts` row has been
    // deleted by the release.
    audit::append(
        &mut tx,
        &AuditEvent {
            payload: json!({
                "from": RUNNING,
                "to": HALTED,
                "reason": halt.reason,
            }),
            ..AuditEvent::new(principal.actor.clone(), AuditKind::CompanyHaltChanged, now)
        },
    )
    .await?;
    tx.commit().await?;

    // `error!` and not `info!`. Every employee in this company has just stopped
    // working, and the one thing worse than a company that will not stop is a
    // company that stopped without anyone noticing it had.
    tracing::error!(
        tenant_id = %principal.tenant_id.as_uuid(),
        actor = %who,
        reason = %halt.reason,
        "the company has been STOPPED: no turn will start and no effect will be authorised \
         until DELETE /v1/halt"
    );
    Ok(Json(view(Some(&halt), Some(0))).into_response())
}

/// `DELETE /v1/halt` — let it run again.
///
/// 409 when it was not stopped, for the same reason `POST` is: "released" and
/// "was never halted" are different facts, and an operator who believes they
/// just restarted a company that was running all along is an operator who will
/// stop looking for the real problem.
async fn release(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let now = Utc::now();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    let Some(lifted) = halt::release(&mut tx).await? else {
        return Err(ApiError::conflict(
            "not_halted",
            "this company is not stopped",
        ));
    };
    // Counted before the commit, inside the transaction that deletes the row, so
    // the number covers exactly the window the halt was up and cannot include a
    // refusal from after it came down.
    let refused = halt::refused_since(&mut tx, lifted.halted_at).await?;

    // Names what it released, not just that it released something. The
    // `company_halts` row is about to stop existing, so without these three
    // fields the trail would record a release with no reference to what it
    // released — and "when did we come back, and from what" would be a join
    // against ordering.
    audit::append(
        &mut tx,
        &AuditEvent {
            payload: json!({
                "from": HALTED,
                "to": RUNNING,
                "halt_reason": lifted.reason,
                "halted_by": lifted.halted_by,
                "halted_at": lifted.halted_at,
                "refused_while_halted": refused,
            }),
            ..AuditEvent::new(principal.actor.clone(), AuditKind::CompanyHaltChanged, now)
        },
    )
    .await?;
    tx.commit().await?;

    tracing::warn!(
        tenant_id = %principal.tenant_id.as_uuid(),
        actor = %principal.actor.label(),
        refused_while_halted = refused,
        "the company is running again"
    );
    Ok(Json(json!({
        "halted": false,
        "released_at": now,
        "was_halted_by": lifted.halted_by,
        "was_halted_at": lifted.halted_at,
        "was_halted_for": lifted.reason,
        "refused_while_halted": refused,
    }))
    .into_response())
}

/// One shape for `GET` and `POST`, so a client branches on `halted` and finds
/// the same field names either way.
fn view(halt: Option<&Halt>, refused: Option<i64>) -> serde_json::Value {
    match halt {
        Some(halt) => json!({
            "halted": true,
            "reason": halt.reason,
            "halted_by": halt.halted_by,
            "halted_at": halt.halted_at,
            "refused_while_halted": refused,
        }),
        None => json!({ "halted": false }),
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Two companies behind two keys, under the real middleware stack.
    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the halt route needs a real Postgres");
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

        async fn send(
            &self,
            method: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri("/v1/halt")
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

        /// Every `company_halt_changed` row for a tenant, oldest first.
        async fn trail(&self, tenant: TenantId) -> Vec<(String, Value)> {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tx");
            let rows = sqlx::query_as(
                "SELECT actor, payload FROM audit_log \
                  WHERE action_kind = 'company_halt_changed' ORDER BY occurred_at, id",
            )
            .fetch_all(&mut **tx)
            .await
            .expect("read the trail");
            tx.rollback().await.expect("rollback");
            rows
        }
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'halt-routes-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// The whole switch, in the order an operator uses it — and the audit trail
    /// that has to survive the row being deleted.
    #[tokio::test]
    async fn the_switch_goes_both_ways_and_names_the_human_both_times() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["halted"], json!(false));

        let (status, body) = h
            .send("POST", SECRET_A, Some(json!({"reason": "the CFO called"})))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["halted"], json!(true));
        assert_eq!(body["reason"], json!("the CFO called"));
        assert_eq!(
            body["halted_by"],
            json!("operator:ops-a"),
            "the row names the key that threw it, never the secret"
        );

        let (status, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["halted"], json!(true));
        assert_eq!(body["refused_while_halted"], json!(0));

        let (status, body) = h.send("DELETE", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["halted"], json!(false));
        assert_eq!(body["was_halted_for"], json!("the CFO called"));

        let (status, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["halted"], json!(false), "{body}");

        // The `company_halts` row is gone. The trail is not, and it is the only
        // thing left that can answer "who stopped us, when, and why".
        let trail = h.trail(h.a).await;
        assert_eq!(trail.len(), 2, "one row per direction: {trail:?}");
        assert_eq!(trail[0].0, "operator:ops-a");
        assert_eq!(trail[0].1["to"], json!("halted"));
        assert_eq!(trail[0].1["reason"], json!("the CFO called"));
        assert_eq!(trail[1].0, "operator:ops-a");
        assert_eq!(trail[1].1["to"], json!("running"));
        assert_eq!(
            trail[1].1["halt_reason"],
            json!("the CFO called"),
            "the release names what it released; the row it released is deleted"
        );
    }

    /// **A tenant cannot stop another tenant, over HTTP.**
    ///
    /// The gate-level test proves the ruling; this proves the door. There is no
    /// tenant in the path and none in the body — the only tenant this handler
    /// can name is the one on the credential — and `company_halts` has RLS
    /// forced with `with check`, so even a handler that tried could not file a
    /// row wearing somebody else's id.
    #[tokio::test]
    async fn one_company_s_key_cannot_stop_another_company() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, _) = h
            .send("POST", SECRET_A, Some(json!({"reason": "mine"})))
            .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = h.send("GET", SECRET_B, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["halted"],
            json!(false),
            "the neighbour is running and cannot even see the halt: {body}"
        );

        // And B cannot release what A placed — from B there is nothing there.
        let (status, body) = h.send("DELETE", SECRET_B, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], json!("not_halted"));

        let (status, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(
            body["halted"],
            json!(true),
            "A is still stopped, whatever B did: {status} {body}"
        );
        assert_eq!(h.trail(h.b).await.len(), 0, "and B's trail is empty");
    }

    /// The switch refuses to lie about what it did: a second halt does not
    /// overwrite the first operator's reason, and releasing a running company
    /// is not reported as a release.
    #[tokio::test]
    async fn re_halting_and_releasing_nothing_are_both_conflicts() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.send("DELETE", SECRET_A, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], json!("not_halted"));

        h.send("POST", SECRET_A, Some(json!({"reason": "first"})))
            .await;
        let (status, body) = h
            .send("POST", SECRET_A, Some(json!({"reason": "second"})))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], json!("already_halted"));

        let (_, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(
            body["reason"],
            json!("first"),
            "the first operator's sentence is the one on the record"
        );
    }

    /// A halt with no reason is refused, because the reason is the whole
    /// evidentiary value of the row.
    #[tokio::test]
    async fn a_halt_without_a_reason_is_refused() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for body in [json!({"reason": ""}), json!({"reason": "   "})] {
            let (status, answer) = h.send("POST", SECRET_A, Some(body.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body} -> {answer}");
        }
        let (_, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(body["halted"], json!(false), "and nothing was stopped");
    }
}
