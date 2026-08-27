//! `/v1/halt`: stop the whole company, and let it go again. `/v1/window`: say
//! in advance when it stops by itself.
//!
//! **The two are one feature.** An operating window that has run out is a halt
//! — `agentos_store::halt::halted` reports it as one — so everything the next
//! seventy lines promise about a halt is promised about a window that ended,
//! by the same code, with nothing added. What differs is the sentence a founder
//! reads back and the verb that ends it: a halt is released, a window is
//! extended. `migrations/0054_operating_window.sql` argues why that is one
//! mechanism rather than two, and the short version is that "everywhere a stop
//! is respected" is a list of five call sites in three crates that has already
//! been out of date once.
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
//! # It stops receiving too, and this paragraph used to say otherwise
//!
//! It said: *the inbound loop keeps fetching mail and landing it in `messages`,
//! and the turns it queues wait in the outbox until the release.* **That has not
//! been true since the halt moved onto the `tenants` driver.** A stopped tenant
//! offers no seat, so `agentos_store::outbox::claim_of` returns none of its
//! rows — and receiving is two claims off that one function, so the stop lands
//! twice:
//!
//! 1. the **raw delivery** the edge stored (`routes::webhooks::RAW_AGGREGATE`),
//!    which the general poller would turn into a notice;
//! 2. the **notice** (`agentos_app::inbound::NOTICE_AGGREGATE`), which the
//!    inbound loop would turn into a `messages` row.
//!
//! `loops::inbound`'s `a_stop_defers_receiving_at_both_gates_and_the_release_drains_it`
//! asserts all of it against a database, including that fixing only the second
//! gate would change nothing: no notice is ever written while the first is
//! deferred.
//!
//! **The argument the old paragraph made is still right, and it is why this one
//! exists rather than a deletion.** Losing a stopped company's customer email
//! would be worse than the thing the halt is for, and reading is not acting —
//! the same asymmetry `agentos_app::effects::Effects::opted_out` is argued from.
//! What was wrong was the tense: that is what *should* happen, and it is not
//! what the code does.
//!
//! ## What is actually at risk, which is less than it sounds and not nothing
//!
//! Nothing is lost on our side and no attempt is burned. `POST /v1/webhooks/…`
//! is a route, not a claim, so the delivery is durable in `outbox_events` the
//! moment the signature checks out, halt or no halt; both rows then wait at
//! `attempt_count = 0` and the release makes them due at once. A halt cannot
//! dead-letter mail.
//!
//! What waits **at the provider** is the part that was never ours. The webhook
//! carries an envelope — message id, from, to — and
//! `agentos_app::inbound::ingest_email` fetches the body and the attachment
//! bytes afterwards, in phase two. So the exposure of a halt is exactly the
//! provider's retention:
//!
//! * **Attachments: one hour, known.** `download_url` dies an hour after it is
//!   minted, and `ingest_email` already lands the message without them and logs
//!   a warning. Any halt longer than an hour loses a stopped company's
//!   attachments, today, silently apart from that line.
//! * **Bodies: unknown, and not knowable from this binary.**
//!
//! ## FOUNDER'S QUESTION, LEFT OPEN
//!
//! **How long does Resend keep an inbound message we have not fetched?** That
//! number is the whole decision and nothing in this process can read it:
//!
//! * If it is comfortably longer than a halt ever lasts, this paragraph is the
//!   end of it — the deferral is harmless and the halt is simpler for covering
//!   everything.
//! * If it is short, the code has to hold the old promise, and the shape of
//!   that fix is known and is **not** a one-line one. Both claims come off
//!   `claim_of`, whose halt clause is deliberately on the tenant driver rather
//!   than on the rows ("same refusal, one join earlier"), and the general
//!   poller's partition mixes rows that must keep waiting (`conversation`
//!   turns, `employee.terminated`) with the `webhook` rows that must not. So it
//!   means teaching the hottest statement in the system which aggregate types a
//!   stop does not stop, *inside* the per-tenant `LIMIT` — outside it, a
//!   tenant's backlog of deferred turns starves the exempt rows behind it — and
//!   re-measuring the plan that `claim_of` documents.
//!
//! Do not half-do it. Exempting the notice claim alone is a change with no
//! effect at all, and it would read like a fix.
//!
//! # What a halt deliberately does not stop
//!
//! **Finishing a convergence that had already started.**
//! `apps/server/src/loops/provisioning.rs` converges an employee somebody
//! already asked for towards mailboxes and phone numbers, with no policy gate
//! anywhere on its path. This paragraph used to say the whole loop was
//! uncovered, on the grounds that half-covering it is worse than not:
//! interrupting a convergence leaves resources bought and unbound, which is what
//! `GET /v1/inventory/stranded` exists to find, and stopping it properly means a
//! resumable state machine that knows how to be paused.
//!
//! That argument is sound and it only ever covered half the ground. *Not
//! starting* a convergence is not *interrupting* one, and it strands nothing,
//! because there is nothing yet to strand. So the loop's claim now skips a
//! stopped company's rows that have not begun — `pending`, `failed`, and a
//! `pending_external` wait nothing on our side can move — and still claims the
//! one row that has: a `provisioning` row whose lease lapsed is a provider call
//! whose outcome nobody knows, and the only reconciler of one is inside
//! `converge`. `CLAIM_SQL`'s doc comment carries the table.
//!
//! What moved this over the line is that the ceiling of the old argument was
//! crossed without anybody touching it: it was written when a halt was rare,
//! short, and placed by a human who was coming back to lift it. Since
//! `migrations/0054_operating_window.sql` a company stops **by itself, on a
//! date, and may stay stopped for weeks**. "We buy anyway during a halt" was an
//! hour's tolerance; it had become a recurring invoice.
//!
//! Still uncovered, and named rather than implied: an employee exempted for its
//! one lapsed lease has all eleven of its steps converged, pending ones
//! included, because `converge` takes an employee and not a step list. That last
//! gap *is* the resumable state machine, and it is still not this unit.
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
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
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
///
/// `/v1/window` is here rather than in a unit of its own because an exhausted
/// window *is* a halt — `agentos_store::halt::halted` returns one — so the two
/// paths write the same audit kind, are read back by the same `GET /v1/halt`,
/// and would otherwise be two files that have to be edited together.
///
/// It is a `PUT` and it has no `DELETE`, unlike the halt above, and the
/// asymmetry is the feature: a window can be replaced but not removed, so there
/// is no verb here that makes a stopped company run again without leaving a row
/// saying when its new time runs out.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/halt", get(status).post(place).delete(release))
        .route("/v1/window", put(set_window))
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
    // Read whether or not the company is stopped, and in the same transaction:
    // a founder looking at a running company needs to know it has eleven hours
    // left rather more than one looking at a stopped one needs to know it ran
    // out. This is the only place the number is visible before it bites.
    let window = halt::window(&mut tx).await?;
    tx.rollback().await?;

    Ok(Json(view(halt.as_ref(), refused, window)).into_response())
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
    let window = halt::window(&mut tx).await?;

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
    Ok(Json(view(Some(&halt), Some(0), window)).into_response())
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
        // "no halt to release" and not "not stopped", because since 0054 the
        // second sentence can be false while this branch is taken: a company
        // whose operating window ran out is stopped, and there is no
        // `company_halts` row to delete. Telling that operator their company is
        // running would send them looking for a problem that is a date.
        return Err(ApiError::conflict(
            "not_halted",
            "this company has no operator halt to release",
        )
        .with_detail(
            "nothing was released. If the company is nonetheless stopped, its operating window \
             has ended — GET /v1/halt shows the date, and PUT /v1/window gives it more time",
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
///
/// `window_ends_at` is on both branches and is `null` when nobody has answered
/// step 8 for this company. It is beside `halted` rather than under it because
/// the two are independent: a running company can have a window, and a stopped
/// one can be stopped by its window, by an operator, or by both — in which case
/// `reason` is the operator's, and this field is still the date to read.
fn view(
    halt: Option<&Halt>,
    refused: Option<i64>,
    window: Option<DateTime<Utc>>,
) -> serde_json::Value {
    match halt {
        Some(halt) => json!({
            "halted": true,
            "reason": halt.reason,
            "halted_by": halt.halted_by,
            "halted_at": halt.halted_at,
            "refused_while_halted": refused,
            "window_ends_at": window,
        }),
        None => json!({ "halted": false, "window_ends_at": window }),
    }
}

/// How long the agents run. **Step 8 of the entry journey, and until now it had
/// no implementation at all** — a company created this morning ran until
/// somebody noticed, taking turns on the customer's own model with the
/// customer's own credential, because no code anywhere had been told to stop.
///
/// An instant, not a duration. The founder's screen offers "2 days / 1 week /
/// 1 month"; turning that into a timestamp is arithmetic somebody has to do
/// once, and doing it here would mean this handler deciding what a month is —
/// and then `halt::halted`, the outbox claim and every future reader deciding
/// it again, from a start date none of them can see.
#[derive(Deserialize)]
struct WindowRequest {
    ends_at: DateTime<Utc>,
}

/// A window has to end in the future, wherever it is being written.
///
/// **Shared by the two doors on purpose**, and it is one function rather than
/// two copies of the sentence because they must not drift: `PUT /v1/window`
/// moves an existing company's window and `POST /v1/companies` writes a new
/// company's first one, and "in the past" has to mean the same thing to both.
/// The second was written months after the first, which is exactly how a rule
/// that lives in two places ends up meaning two things.
///
/// A window in the past is an instant stop with nobody's sentence attached to
/// it, and the product has a verb for stopping now that insists on the
/// sentence. Refused in the routes rather than in the store, where there is no
/// operator left to tell — see `halt::set_window`.
pub(crate) fn must_end_in_the_future(
    ends_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if ends_at <= now {
        return Err(ApiError::bad_request(
            "an operating window has to end in the future; a date in the past would stop the \
             company immediately with no reason recorded. To stop it now, POST /v1/halt with the \
             reason",
        ));
    }
    Ok(())
}

/// `PUT /v1/window` — say when this company's agents stop.
///
/// Idempotent by shape: the same body twice leaves the same row, and a
/// different body replaces it. There is no `POST`/`DELETE` pair here because
/// there is nothing to conflict over — a window is a setting, not evidence of
/// an emergency, and 0054 argues the difference where the `UPDATE` grant is.
///
/// # It cannot widen anything, and that is structural
///
/// The only thing this writes is `company_windows`. It cannot touch
/// `company_halts`, so no window — however far in the future — lifts an
/// operator's stop; `halt::halted` prefers the operator's row when both exist,
/// and `crates/store/src/halt.rs` holds it to that. And a company with no row
/// here behaves exactly as it did before this feature shipped, so the whole
/// feature can only ever *add* a stop.
///
/// # Two questions this does not answer, on purpose
///
/// **There is no default.** A missing or absent window is not filled in with
/// "one month" by this handler or by anything below it, because the number
/// would be a price and a promise chosen by whoever wrote the line: too short
/// and a paying company stops in the night, too long and the runaway is merely
/// slower. The entry journey has to ask.
///
/// **Extending a window that already ran out restarts the company**, here and
/// with one call, and whether that is right is a founder's decision rather than
/// a handler's. The safe alternative is to make a lapsed company need the same
/// deliberate two steps a halted one needs; the argument against is that a
/// customer who has just paid for another month should not need a second call
/// to get what they paid for. Nothing downstream depends on which way it goes:
/// `halt::halted` reads whatever row is here.
async fn set_window(
    State(db): State<Db>,
    principal: Principal,
    Json(body): Json<WindowRequest>,
) -> Result<Response, ApiError> {
    let now = Utc::now();
    must_end_in_the_future(body.ends_at, now)?;

    let who = principal.actor.label();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let previous = halt::set_window(&mut tx, body.ends_at, &who, now).await?;

    // Same transaction as the row, same kind as the switch. `company_windows`
    // is one row that is overwritten, so this trail is the only thing that can
    // ever answer "who gave this company another month, and when" — and it
    // shares `company_halt_changed` with the switch because choosing when a
    // company stops is the same *kind* of fact as stopping it, not a
    // configuration change. `/v1/autonomy` should count it with the one and not
    // with the spend-cap tweaks.
    audit::append(
        &mut tx,
        &AuditEvent {
            payload: json!({
                "window_ends_at": body.ends_at,
                "previous_window_ends_at": previous,
            }),
            ..AuditEvent::new(principal.actor.clone(), AuditKind::CompanyHaltChanged, now)
        },
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        tenant_id = %principal.tenant_id.as_uuid(),
        actor = %who,
        window_ends_at = %body.ends_at,
        "this company's agents will stop when its operating window ends"
    );
    Ok(Json(json!({
        "window_ends_at": body.ends_at,
        "previous_window_ends_at": previous,
    }))
    .into_response())
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
                // A `Keyring`, not the bare `ApiKeys` this used to pass:
                // `waveJ-j1` made the environment keyring one half of a
                // resolver whose other half is the `api_keys` table. These
                // tests only ever present env keys, so the table half is never
                // reached — but it has to exist, because the type is what
                // proves every authenticated path can see both.
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

        async fn send(
            &self,
            method: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            self.send_to(method, "/v1/halt", secret, body).await
        }

        async fn send_to(
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

    /// An instant `offset` from now, truncated to the microsecond Postgres
    /// stores — so a timestamp that goes out in a request body and comes back
    /// out of the database compares equal to itself.
    fn instant(offset: chrono::Duration) -> chrono::DateTime<Utc> {
        use chrono::SubsecRound;
        (Utc::now() + offset).trunc_subsecs(6)
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

    // -- the operating window ----------------------------------------------

    /// **Step 8 of the entry journey, end to end**: choose how long the agents
    /// run, read it back, and watch the company stop by itself when the time is
    /// up — with a sentence that is not the emergency one.
    ///
    /// The middle assertion is the whole product claim: nothing is called at the
    /// deadline, no loop ticks, no row is written. `halt::halted` simply starts
    /// answering differently, and every reader of it — the gate, the turn's
    /// pre-flight check, the outbox claim — refuses from that instant.
    #[tokio::test]
    async fn a_window_is_chosen_read_back_and_stops_the_company_by_itself() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["window_ends_at"],
            Value::Null,
            "no default duration is invented for a company nobody has answered step 8 for"
        );

        let ends_at = instant(chrono::Duration::days(30));
        let (status, body) = h
            .send_to(
                "PUT",
                "/v1/window",
                SECRET_A,
                Some(json!({"ends_at": ends_at})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["previous_window_ends_at"], Value::Null);

        let (_, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(
            body["halted"],
            json!(false),
            "a month in hand is not a stop: {body}"
        );
        assert_eq!(body["window_ends_at"], json!(ends_at));

        // The clock runs out. Nothing else happens — this moves the row rather
        // than waiting a month, and that is the only thing it fakes.
        let past = instant(-chrono::Duration::minutes(1));
        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        halt::set_window(&mut tx, past, "operator:ops-a", Utc::now())
            .await
            .expect("set");
        tx.commit().await.expect("commit");

        let (status, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["halted"],
            json!(true),
            "the company stopped with nobody touching it: {body}"
        );
        assert_eq!(
            body["halted_by"],
            json!("operator:ops-a"),
            "and the stop names the human who chose the window, not `system`"
        );
        let reason = body["reason"].as_str().expect("a reason");
        assert!(
            reason.contains("operating window") && reason.contains("nobody stopped it"),
            "a founder must read this as a schedule, not an emergency: {reason}"
        );

        // The switch's own verb is honest about what it did not do. Telling this
        // operator "this company is not stopped" would send them looking for a
        // problem that is a date.
        let (status, body) = h.send("DELETE", SECRET_A, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], json!("not_halted"));
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|d| d.contains("PUT /v1/window")),
            "and it names the verb that would help: {body}"
        );
    }

    /// **A window can only ever add a stop.** It cannot lift an operator's halt
    /// however wide it is, it cannot be set into the past, and one company's
    /// window is invisible to another.
    ///
    /// Three refusals in one test because they are one property: nothing here
    /// widens. The first is the constraint the whole feature turns on — a
    /// schedule must never be able to restart a company a human stopped, nor
    /// replace that human's sentence with its own.
    #[tokio::test]
    async fn a_window_never_widens_and_never_crosses_a_tenant() {
        let Some(h) = Harness::new().await else {
            return;
        };

        h.send("POST", SECRET_A, Some(json!({"reason": "the CFO called"})))
            .await;

        let wide_open = instant(chrono::Duration::days(365));
        let (status, body) = h
            .send_to(
                "PUT",
                "/v1/window",
                SECRET_A,
                Some(json!({"ends_at": wide_open})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (_, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(
            body["halted"],
            json!(true),
            "a year of window does not lift an emergency stop: {body}"
        );
        assert_eq!(
            body["reason"],
            json!("the CFO called"),
            "and the operator's own sentence is still the one on the record"
        );
        assert_eq!(body["window_ends_at"], json!(wide_open));

        // A window in the past would be a stop with nobody's reason on it.
        // `POST /v1/halt` is the verb that stops now, and it insists on one.
        let (status, body) = h
            .send_to(
                "PUT",
                "/v1/window",
                SECRET_A,
                Some(json!({"ends_at": instant(-chrono::Duration::seconds(1))})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // B cannot reach into A. There is no tenant in the path and none in the
        // body, and `company_windows` has RLS forced with `with check`.
        let (status, body) = h
            .send_to(
                "PUT",
                "/v1/window",
                SECRET_B,
                Some(json!({"ends_at": instant(chrono::Duration::days(2))})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, body) = h.send("GET", SECRET_A, None).await;
        assert_eq!(
            body["window_ends_at"],
            json!(wide_open),
            "A's window is untouched by B's: {body}"
        );

        // One `company_halt_changed` row per window write, in A's trail and in
        // B's, and neither in the other's. `company_windows` is overwritten in
        // place, so this trail is the only thing that can say who gave which
        // company more time.
        let trail = h.trail(h.a).await;
        assert_eq!(trail.len(), 2, "the halt and the window: {trail:?}");
        assert_eq!(trail[1].0, "operator:ops-a");
        assert_eq!(trail[1].1["window_ends_at"], json!(wide_open));
        assert_eq!(trail[1].1["previous_window_ends_at"], Value::Null);
        assert_eq!(h.trail(h.b).await.len(), 1, "and B's write is B's alone");
    }
}
