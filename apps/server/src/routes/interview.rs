//! `/v1/interview` — the guided conversation that finishes a company.
//!
//! `POST /v1/companies` stands the org chart up and `POST /v1/model` connects
//! the founder's own model. Neither of them says what any of those seats is
//! *for*, and after both of them `employee_charters` is empty.
//!
//! So "what is missing" has two halves and this unit is honest about which one it
//! owns. **Which job a seat holds** is a closed choice among the roles this build
//! has, it is not derivable from an org chart, and a model must not make it —
//! `PUT /v1/employees/{id}/initiative` owns it and [`NO_CHARTER`] says so.
//! **What that job should aim at** is prose, it is what an
//! `Objective`'s `gaps()` has always been a list of questions about, and it is
//! this unit's whole subject: the founder says it in words instead of
//! hand-writing a tagged JSON objective per seat.
//!
//! # Nothing here is new. Two things are joined
//!
//! The questions already existed: every role pack has a `Gap` enum whose
//! `question()` is *the question to put to the person who set the objective*,
//! and `Objective::gaps()` already returns them in a stable order.
//! `Charter::open_questions` is that list, taken apart.
//!
//! The door already existed: `PUT /v1/employees/{id}/initiative` takes a typed
//! objective and puts every field through its constructor —
//! [`CountryCode::parse`](agentos_app::rolepack::CountryCode::parse),
//! [`Money::new`](agentos_domain::money::Money::new), the [`Segment`] table.
//! This unit reuses that route's own [`ObjectiveBody`] rather than growing a
//! second reader for the same objective, and that reuse is the security
//! property: **a value the interview writes is a value the operator could have
//! typed into `PUT` by hand, because it goes through the identical
//! deserialiser and the identical constructors.**
//!
//! What is added between them is one model call that turns prose into candidate
//! values, and a filter that decides which candidates are even offered to the
//! constructors.
//!
//! # Where the model stops being trusted, exactly
//!
//! ```text
//!   founder's prose ── operator input, trusted ──► one gated, metered turn
//!                                                          │
//!                                       a String, and only ever a String
//!                                                          ▼
//!                             `candidate()`: keys the objective actually has,
//!                                            and only the ones still unset
//!                                                          ▼
//!                             `ObjectiveBody` (deny_unknown_fields, tag `role`
//!                                            supplied by us, never by it)
//!                                                          ▼
//!                             `into_charter()`: CountryCode::parse, Money::new,
//!                                            Currency, Segment — the constructors
//!                                                          ▼
//!                             `Charter::save`, in the operator's transaction
//! ```
//!
//! The founder's prose is operator input and is trusted, so it travels as a
//! `Context::with_task` message exactly as `Charter::brief` does — which
//! already carries the operator's own `what`, `requirements` and `destinations`
//! into every turn. **That trust does not survive the model.** What comes back
//! is a proposal in the same sense a tool call is a proposal, and it is treated
//! with the same suspicion: it is parsed, filtered, re-parsed through the
//! constructors, and thrown away whole if any of that fails.
//!
//! There is no `#[derive(Deserialize)]` on any `Objective` here and none was
//! needed. `Charter::objective_json` and [`ObjectiveBody`] are the same wire
//! shape — that is stated on both — so the current objective can be shown to
//! the model, merged into, and read back through the constructors without a
//! third spelling existing anywhere.
//!
//! # What an answer cannot do
//!
//! **Reach another company.** The employee comes from the path, is loaded in a
//! `tenant_tx` under RLS, and an id this tenant cannot see is a 404. The tenant
//! is [`Principal::tenant_id`], never a body field.
//!
//! **Widen a policy.** The only writes are to `employee_charters.objective`. A
//! gap whose remedy is a policy layer — today exactly
//! [`rolepack_sales::Gap::Channel`](agentos_app::rolepack_sales::Gap) — is
//! reported with `answerable: false` and no answer can close it. See
//! `Charter::open_questions`.
//!
//! **Change an answer nobody asked about.** `candidate` keeps a proposed key
//! only if the stored objective *has* that key and its value is still unset.
//! `segment` is never a gap and is always a non-empty string in the column, so
//! a seller cannot be re-segmented by a sentence about something else; a key the
//! objective does not have is not in the column at all and is refused before
//! `deny_unknown_fields` gets a second chance at it.
//!
//! **Set a charter itself.** `turn::UNSERVED` names `ActionKind::CharterSet` as
//! *the one kind that must not become a tool*, and this turn is offered no tools
//! at all — `with_proposable` is called with the empty set, which replaces even
//! the `UNCHARTERED` floor `SystemPrompt::new` starts from. The model produces a
//! string. The **route** produces the charter, on the operator's authority, in
//! the operator's own transaction, which is the same authority `PUT
//! /v1/employees/{id}/initiative` has always written a charter on.
//!
//! # Who does the asking, and why it is the employee with the hole
//!
//! The turn is the employee's own: its policy decides the model, its
//! `max_turns_per_day` pays for it, and `model_usage` books the tokens against
//! it. That is `Stage::Clarify` used as it was written — an employee that cannot
//! plan has one job, which is to ask.
//!
//! Two alternatives were considered and rejected.
//!
//! *An onboarding-assistant seat.* It would need a role pack, a policy layer, a
//! charter and a budget, all so that a seat could exist to fill in other seats'
//! charters — and `docs/ORIZN.md` spends a section arguing that the one seat at
//! the root of the chart must **not** get a budget, because a budget there buys
//! "a language model answering on the founder's behalf". An interviewer is that
//! same seat wearing a different hat.
//!
//! *The `direction` seat.* Zero turns by design, `UNCHARTERED`, a sink and not a
//! relay. Giving it the interview would be giving it exactly the budget that
//! document refuses.
//!
//! # All the questions at once, one answer at a time
//!
//! `GET /v1/interview` is tenant-wide: one request returns every open question
//! on every seat, in `gaps()` order, and that is the whole questionnaire on one
//! screen. Five round trips to build one form is five things a front end has to
//! orchestrate and one of which can fail, leaving a half-questionnaire and a
//! founder who does not know it.
//!
//! `POST /v1/employees/{id}/interview` is per seat, and that is deliberate the
//! other way. The extraction turn is billed to a seat, and there is no seat that
//! owns "the company" — see above. And a single blob answered by a single call
//! is a sentence about sales that can land in the finance charter; with the seat
//! in the path, the target objective is something the model is shown and never
//! chooses.

use std::sync::Arc;

use agentos_app::effects::{Effects, Ports};
use agentos_app::gate::{PolicyGate, Principal as ActingAs};
use agentos_app::mcp::Credentials;
use agentos_app::mocks::{Llm, LlmBackend};
use agentos_app::turn::{Budgets, Context, Turn};
use agentos_app::vertical::{Charter, CharterError, Question};
use agentos_domain::action::ActionKind;
use agentos_domain::ids::EmployeeId;
use agentos_domain::policy::model_for;
use agentos_store::db::{Db, StoreError};
use agentos_store::model_usage::{self, Consumed};
use agentos_store::policy::PolicyLoadError;
use agentos_store::turns::{self, TurnBudgetError};
use agentos_store::{employee as employee_store, policy as policy_store};
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get as get_route, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::routes::initiative::ObjectiveBody;
use crate::routes::teams;

/// How long one extraction may take before the token is fired.
///
/// Shorter than a working turn's deadline on purpose: a person is holding the
/// connection open, and this turn calls no tool, reads no page and sends no
/// mail — it is one completion of a few hundred tokens. A model that has not
/// answered in this long is not about to.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// What the interview turn is for, in the model's own opening message.
///
/// A message and not part of the prefix, for the reason `Charter::brief` gives
/// about plans: the prefix is the bytes that are identical for every turn this
/// employee takes, and the cache breakpoint sits at its end. Putting a
/// once-per-onboarding instruction in there would move that breakpoint for every
/// ordinary turn as well.
const INTERVIEW_BRIEF: &str = "\
You are being interviewed about your own objective, by the person who employs \
you. They have been asked the questions below and have answered in their own \
words. Your only job this turn is to write down what they said, in the shape \
the objective is stored in.

Reply with one JSON object and nothing else: no prose, no explanation, no code \
fence. Its keys must be keys of the objective you were shown, and only ones \
whose value is currently empty, null or zero. Give a key only if the person \
actually answered it — omit anything they did not say, and never invent a \
plausible value for a question they skipped.

You are not deciding anything. Every value you write is checked against the \
same parsers the person's own typing would go through, and one they refuse \
throws away the whole object and puts the question back to them. A country is \
a two-letter ISO-3166 code, a currency a three-letter ISO-4217 code, a price \
is minor units plus that currency, and a count is a positive whole number.

Whether the answer is a good one is not your call either: whether the named \
accounts fit the segment, whether the number is realistic, whether the plan \
makes sense — the person who employs you decided that, and leaving a key out \
because you disagree is inventing a refusal. The only thing you may leave out \
is a value that is not an answer to the question at all. Never reply with \
prose instead of the object.";

/// Everything this route needs beyond the database.
///
/// Deliberately the union of `routes::model`'s `ModelWiring` and the gate and
/// ports a turn runs through — because this route does both things: it reads the
/// tenant's proven model connection, and it takes a turn.
#[derive(Clone)]
pub struct InterviewState {
    db: Db,
    /// The process-wide gate. Wired into the turn even though this turn is
    /// offered no tools: there is one `Turn` type in this workspace and it is
    /// always built with the gate, so an edit that later gives the interview a
    /// tool finds the gate already in front of it rather than absent.
    gate: PolicyGate,
    /// The same ports every other turn acts through, for the same reason.
    ports: Arc<Ports>,
    /// The host's own client, handed to `model_access::for_turn` so it can
    /// decide whether this tenant's connection is allowed to use it.
    host: Arc<dyn Llm>,
    backend: LlmBackend,
    /// The cipher the tenant's proven key was sealed with. Since
    /// `0050_tenant_model_key` the credential itself is a column on
    /// `tenant_model_access`, so this is a master key and not a place to look.
    credentials: Credentials,
}

/// This unit's routes. Merged into the API router, so auth, the rate limit and
/// the idempotency layer are already in front of it.
pub fn router(
    db: Db,
    gate: PolicyGate,
    ports: Arc<Ports>,
    host: Arc<dyn Llm>,
    backend: LlmBackend,
    credentials: Credentials,
) -> Router {
    Router::new()
        .route("/v1/interview", get_route(questionnaire))
        .route("/v1/employees/{id}/interview", post(answer))
        .with_state(InterviewState {
            db,
            gate,
            ports,
            host,
            backend,
            credentials,
        })
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The `POST` body: what the founder said, in their own words.
///
/// `deny_unknown_fields`, so a client that sends `objective` or `role` here —
/// trying to set a value directly rather than say one — is told this is not that
/// endpoint. `PUT /v1/employees/{id}/initiative` is that endpoint and always was.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerBody {
    /// Prose. Operator input, and therefore trusted — see the module docs for
    /// where that trust stops.
    answer: String,
    /// Which open question the prose answers — a [`Question::code`] off
    /// `GET /v1/interview`, or absent when the founder is just talking.
    ///
    /// The console asks one question at a time and the founder skips freely,
    /// so "what is the most you will pay per unit?" on screen and the first
    /// open gap in `gaps()` order are routinely different questions. Without
    /// this the model was handed all thirty-five and left to guess which one
    /// a sentence about hosting subscriptions was for; it guessed prose, and
    /// the founder was told to say it again. A code that names no open
    /// question is ignored rather than refused — the answer is still worth
    /// reading, only the emphasis is lost.
    question: Option<String>,
}

/// One seat's open questions.
#[derive(Debug, Serialize)]
struct SeatView {
    employee_id: Uuid,
    /// The handle an operator recognises.
    slug: String,
    /// `employee_charters.role`, as stored. `None` is a seat nobody has given a
    /// job yet, and its one question is [`NO_CHARTER`].
    role: Option<String>,
    /// What is still missing, in `gaps()` order. Empty means this seat can be
    /// planned.
    questions: Vec<Question>,
    /// The objective as it stands, through its constructors —
    /// [`Charter::objective_json`], the same shape `POST` echoes back. What
    /// the founder has already said, so an answered question does not simply
    /// vanish from the screen on the next reload: the value it produced is
    /// here to read back. Absent for a seat with no charter or an unreadable
    /// one.
    #[serde(skip_serializing_if = "Option::is_none")]
    objective: Option<Value>,
    /// Set when the stored objective does not read back through its
    /// constructors, in which case there are no questions to ask about it and
    /// the remedy is a `PUT` to `/initiative`. `CharterError::code`.
    #[serde(skip_serializing_if = "Option::is_none")]
    unreadable: Option<&'static str>,
}

/// One thing the model proposed that this system would not take.
///
/// The `why` can contain the model's own words — `BadCountry` renders what it
/// was given. That is why this is a 200 body and never an [`ApiError`] detail:
/// `error.rs` reserves `detail` for input *the caller* controls, and this is
/// input the model produced. The founder needs to see it, because "it read your
/// answer as Germanie and Germanie is not a country code" is the sentence that
/// tells them how to answer again.
#[derive(Debug, Serialize)]
struct Refusal {
    field: String,
    why: String,
}

/// What one answered question came to.
#[derive(Debug, Serialize)]
struct AnswerView {
    employee_id: Uuid,
    role: &'static str,
    /// Whether the charter changed. `false` with a non-empty `refused` is the
    /// interesting case: the model proposed something the constructors would not
    /// build, so nothing was written and the questions below are unchanged.
    accepted: bool,
    /// The objective's keys this answer filled.
    filled: Vec<String>,
    /// What was proposed and thrown away.
    refused: Vec<Refusal>,
    /// What is still open, recomputed from what is now stored.
    questions: Vec<Question>,
    /// The objective as it now stands, read back through the constructors.
    objective: Value,
}

/// The one question a seat with no charter has, and the only question in this
/// unit that no role pack wrote.
///
/// **A seat with no charter is the state `POST /v1/companies` leaves every
/// employee in.** That route stands up the tenant, the layers, the teams and the
/// people; it writes no `employee_charters` row, because which job a seat does is
/// not derivable from an org chart — `sdr` is a slug, and the six roles are a
/// closed list a person picks from.
///
/// So this route lists those seats rather than omitting them, and that is the
/// whole reason it reads `employees` and joins the charters rather than the other
/// way round. A questionnaire that answered `{"seats": []}` for a company nobody
/// has chartered would be saying *nothing is missing* about the state where
/// everything is.
///
/// `answerable: false`, and not because the answer is hard. **No prose closes
/// this and none should**: a model choosing which of six jobs a colleague holds
/// is `turn::UNSERVED`'s `CharterSet` argument exactly — "authority that comes
/// from the org chart … never proposed by a model that would be asserting the
/// reporting line rather than obeying it". The remedy is the endpoint that has
/// always owned it, and the role list lives there and only there.
const NO_CHARTER: Question = Question {
    code: "role",
    ask: "this seat has no job yet. Say which of the roles this build has it wears, with PUT \
          /v1/employees/{id}/initiative — its `role` tag is that list, and it sets the cadence \
          the seat wakes on at the same time. The questions about what the seat should aim at \
          appear here once it has one.",
    answerable: false,
};

// ---------------------------------------------------------------------------
// The filter
// ---------------------------------------------------------------------------

/// Whether this value is one `gaps()` would call missing.
///
/// **This is `gaps()`'s condition, written once over JSON instead of six times
/// over six structs.** Every objective in the workspace tests exactly this:
/// `String::trim().is_empty()`, `u32 == 0`, `Option::is_none` (and, where the
/// inner value is a string, blank), and `Vec::iter().all(is_blank)` — which is
/// `true` for an empty vector, as `all` is. Compare
/// `rolepack::Objective::gaps`, `rolepack_sales::Objective::gaps` and the four
/// in `rolepack_service`.
///
/// An object that is present is *set*: `max_unit_price` is the only object in
/// any objective and a price that is there is a price that was stated.
fn unset(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty(),
        Value::Number(number) => number.as_u64() == Some(0),
        Value::Array(items) => items.iter().all(unset),
        _ => false,
    }
}

/// Reduce what the model proposed to what an operator could have typed.
///
/// Two rules, and they are the whole of it:
///
/// 1. **The key must be one the stored objective has.** `Charter::objective_json`
///    writes every field of the role's objective, present ones and null ones
///    alike, so "not in the base" means "not part of this job". `role` is not in
///    any base either, which is why the tag cannot be proposed.
/// 2. **Its stored value must still be unset.** An answered field is not a
///    question, and a proposal that changes one is the model asserting rather
///    than transcribing. `segment` is never a gap and is always a non-empty
///    string, so this is what makes a seller unre-segmentable by a sentence.
///
/// Returns the keys to merge and the refusals to report. Nothing here parses a
/// value — that is the constructors' job and it happens one hop later, so this
/// function has no second opinion about what a country is.
fn candidate(
    base: &Map<String, Value>,
    proposal: Map<String, Value>,
    rewriting: Option<&str>,
) -> (Vec<(String, Value)>, Vec<Refusal>) {
    let mut kept = Vec::new();
    let mut refused = Vec::new();
    for (key, value) in proposal {
        match base.get(&key) {
            None => refused.push(Refusal {
                why: format!(
                    "`{key}` is not part of this employee's objective, so nothing it says can be \
                     written there"
                ),
                field: key,
            }),
            // The one key the console named as being changed goes through set.
            Some(stored) if !unset(stored) && rewriting != Some(key.as_str()) => {
                refused.push(Refusal {
                    why: format!(
                        "`{key}` was already answered, and this interview only asks about what \
                         is missing; name it as the question to change it"
                    ),
                    field: key,
                });
            }
            Some(_) => kept.push((key, value)),
        }
    }
    (kept, refused)
}

/// The whole frontier, in one function: **the model proposed, the constructors
/// decide.**
///
/// `Some` is a charter that came out the far side of
/// [`ObjectiveBody::into_charter`] — `CountryCode::parse`, `Money::new`,
/// `Currency`, `Segment` — together with the keys it filled. `None` is a
/// proposal that did not, and the refusals say which part of it and why.
///
/// Extracted from the handler and not inlined in it, because everything
/// interesting this route claims is a claim about this function and none of it
/// needs a Postgres, an HTTP request or a model to check.
///
/// **All or nothing.** One value the constructors will not build throws the
/// whole object away and the questions come back unchanged, which costs the
/// founder a second turn when four answers were good and one was not.
///
/// ponytail: that is the honest simple version. The alternative is dropping the
/// named field and retrying, which means reading the field's name back out of a
/// formatted message — stringly-typed, and wrong the first time somebody rewords
/// `initiative::field`. Give `into_charter` a typed error the day this costs a
/// real founder a real minute.
fn apply(
    role: &'static str,
    base: &Map<String, Value>,
    proposal: Map<String, Value>,
    rewriting: Option<&str>,
) -> (Option<(Charter, Vec<String>)>, Vec<Refusal>) {
    let (kept, mut refused) = candidate(base, proposal, rewriting);
    if kept.is_empty() {
        return (None, refused);
    }

    let filled: Vec<String> = kept.iter().map(|(key, _)| key.clone()).collect();
    let mut merged = base.clone();
    merged.extend(kept);
    // **The tag is ours.** `ObjectiveBody` is `#[serde(tag = "role")]` and the
    // role comes from the loaded charter, so no reply can move an objective from
    // one pack to another — the shape it is read as is the shape this seat
    // already had.
    merged.insert("role".to_owned(), json!(role));

    // The same deserialiser and the same constructors `PUT /initiative` uses.
    // `deny_unknown_fields` is the second net under `candidate`'s first, and
    // `into_charter` is where `CountryCode::parse` refuses "Germanie".
    match serde_json::from_value::<ObjectiveBody>(Value::Object(merged))
        .map_err(|err| ApiError::bad_request(err.to_string()))
        .and_then(ObjectiveBody::into_charter)
    {
        Ok(charter) => (Some((charter, filled)), refused),
        Err(err) => {
            refused.push(Refusal {
                field: filled.join(", "),
                why: err
                    .detail()
                    .unwrap_or("that objective cannot be read")
                    .to_owned(),
            });
            (None, refused)
        }
    }
}

/// The first 300 characters of what the model said, for a refusal the founder
/// reads. Whole characters, not bytes: a cut inside an accent is a panic.
fn excerpt(reply: &str) -> String {
    let mut out: String = reply.chars().take(300).collect();
    if reply.chars().count() > 300 {
        out.push('…');
    }
    out
}

/// The model's reply as a JSON object, or `None`.
///
/// Forgiving about what surrounds the object and about nothing inside it: a
/// model that answers with a code fence or a sentence of preamble has still
/// answered, and re-asking the founder over a pair of backticks would cost them
/// a turn and a minute. A reply with no object in it, or one that is not an
/// object, is a refusal — there is nothing to be forgiving *about*.
fn object_in(reply: &str) -> Option<Map<String, Value>> {
    let start = reply.find('{')?;
    let end = reply.rfind('}')?;
    if end < start {
        return None;
    }
    match serde_json::from_str(&reply[start..=end]) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /v1/interview` — every open question in this company, by seat.
///
/// **Every employee, not every charter.** A seat nobody has chartered is the one
/// this list most needs to show, because it is the state a company is in the
/// moment `POST /v1/companies` returns — see [`NO_CHARTER`].
///
/// ponytail: not paginated, unlike `GET /v1/employees`. An org chart is capped
/// at `teams::MAX_ROWS` and a seat carries at most five short questions, so the
/// whole questionnaire is one small page — and half a questionnaire is worse
/// than none, because the founder cannot tell it is half.
async fn questionnaire(
    State(state): State<InterviewState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    // No `WHERE tenant_id`: RLS is forced on both tables and a hand-written
    // filter here would be a second place for it to be forgotten. Ordered by
    // slug so the questionnaire reads the same way twice.
    let rows: Vec<(Uuid, String, Option<String>, Option<Value>)> = sqlx::query_as(
        "SELECT e.id, e.slug, c.role, c.objective \
           FROM employees e \
           LEFT JOIN employee_charters c ON c.employee_id = e.id \
          ORDER BY e.slug",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::from)?;
    tx.rollback().await?;

    let seats: Vec<SeatView> = rows
        .into_iter()
        .map(|(employee_id, slug, role, objective)| {
            let (Some(role), Some(objective)) = (role, objective) else {
                return SeatView {
                    employee_id,
                    slug,
                    role: None,
                    questions: vec![NO_CHARTER],
                    objective: None,
                    unreadable: None,
                };
            };
            // A charter that will not parse is the operator's problem to see,
            // not a 500 — the same call `GET /v1/employees/{id}/initiative`
            // makes about the same column.
            match Charter::of(&role, &objective) {
                Ok(charter) => SeatView {
                    employee_id,
                    slug,
                    role: Some(role),
                    questions: charter.open_questions(),
                    objective: Some(charter.objective_json()),
                    unreadable: None,
                },
                Err(err) => {
                    tracing::error!(%employee_id, code = err.code(), "unreadable charter");
                    SeatView {
                        employee_id,
                        slug,
                        role: Some(role),
                        questions: Vec::new(),
                        objective: None,
                        unreadable: Some(err.code()),
                    }
                }
            }
        })
        .collect();

    Ok(Json(json!({ "seats": seats })).into_response())
}

/// `POST /v1/employees/{id}/interview` — one seat, one prose answer.
///
/// The order below is load-bearing and it is the initiative poller's order, for
/// the poller's reasons: **everything that can refuse the turn is asked before a
/// turn is reserved**, because `store::turns` has no release verb and a budget
/// you can get back by failing is the path a crash loop rides.
async fn answer(
    State(state): State<InterviewState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    body: Result<Json<AnswerBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let said = body.answer.trim().to_owned();
    if said.is_empty() {
        return Err(ApiError::bad_request(
            "`answer` is blank; GET /v1/interview asks the questions, this endpoint takes the \
             reply to them",
        ));
    }

    let employee_id = EmployeeId::from_uuid(id);
    let now = Utc::now();

    // --- Everything a turn needs, in one read. -----------------------------
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let stored = employee_store::load(&mut tx, employee_id).await?;
    let charter = Charter::load(&mut tx, employee_id)
        .await
        .map_err(charter_error)?
        .ok_or_else(|| {
            ApiError::not_found().with_detail(
                "this employee has no charter, so there is nothing to interview about; set one \
                 with PUT /v1/employees/{id}/initiative",
            )
        })?;
    let policy = policy_store::load(&mut tx, employee_id)
        .await
        .map_err(unreadable_policy)?;
    // The proof half only: this read decides whether a turn may happen at all,
    // and `for_turn` below reads the row again — in the transaction that
    // reserves the turn — for the credential that pays for it.
    let access = agentos_app::model_access::connected(&mut tx)
        .await
        .map_err(no_model)?
        .access;
    tx.rollback().await?;

    let role = charter.role();
    let base = match charter.objective_json() {
        Value::Object(map) => map,
        // `objective_json` is a `json!({...})` literal in every arm.
        other => {
            tracing::error!(%id, role, ?other, "an objective serialised as something else");
            return Err(ApiError::internal());
        }
    };

    // A key already answered, named by the console: the founder is changing
    // it, in the same words and through the same constructors. This is the one
    // case `candidate` lets a set key through — without it, "change it with
    // PUT /initiative" meant rewriting the whole objective to fix one word.
    let rewriting: Option<&str> = body
        .question
        .as_deref()
        .filter(|key| base.get(*key).is_some_and(|value| !unset(value)));

    // Nothing to ask is not an error, and answering it is not a turn. A founder
    // who sends one answer too many gets the finished objective back and pays
    // nothing for it. Unless they are changing a value, which is a turn.
    let questions = charter.open_questions();
    if rewriting.is_none() && !questions.iter().any(|question| question.answerable) {
        return Ok(Json(AnswerView {
            employee_id: id,
            role,
            accepted: false,
            filled: Vec::new(),
            refused: Vec::new(),
            questions,
            objective: Value::Object(base),
        })
        .into_response());
    }

    // The model question, before the reservation: an employee whose policy
    // permits no model cannot take this turn or any other, so it must not spend
    // one finding out.
    let preferred = charter.model();
    let Some(model) = model_for(Some(&policy), preferred) else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "no_model_permitted",
            "this employee's policy permits no model",
        )
        .with_detail(format!(
            "role {role} asked for {preferred} and `allowed_models` intersected to the empty set; \
             grant one in a policy layer"
        )));
    };

    // --- One turn out of this employee's day, committed on its own. --------
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    turns::reserve(&mut tx, employee_id, now.date_naive(), &policy)
        .await
        .map_err(over_budget)?;
    let (llm, _access) = agentos_app::model_access::for_turn(
        &mut tx,
        &state.credentials,
        &state.host,
        state.backend,
        // `None` is the real API. See `agentos_app::model_access::ApiBase`.
        None,
    )
    .await
    .map_err(no_model)?;
    tx.commit().await?;
    tracing::debug!(%id, role, path = %access.path, running = %model, "interview turn");

    // --- The turn. --------------------------------------------------------
    //
    // The employee's own identity and its own role briefing, so the cached
    // prefix is the bytes its ordinary turns already carry — but built here
    // rather than through `Charter::system_prompt`, because that one also
    // applies the pack's proposable set and this turn must have none.
    //
    // `with_proposable` on an empty set **replaces** the floor, which
    // `SystemPrompt::new` starts at `UNCHARTERED` — the internal channel. So
    // this is not "the pack offers nothing", it is "nothing at all is offered",
    // and it is the reason the gate is never consulted below: there is no
    // proposal for it to rule on.
    let prompt = agentos_app::prompt::SystemPrompt::new(format!(
        "You are {}, an AI employee at {}. You answer from {}.\n\n{}",
        stored.employee.slug(),
        stored.employee.domain(),
        stored.employee.address(),
        charter.briefing(),
    ))
    .with_proposable(std::iter::empty::<ActionKind>());

    let acting = ActingAs::employee(principal.tenant_id, employee_id);
    let turn = Turn::new(
        llm,
        state.gate.clone(),
        Effects::new(state.db.clone(), state.ports.clone(), acting),
        prompt,
        model.as_str(),
        stored.employee.address().to_string(),
    )
    // **Exactly one round trip, and therefore no tool call.**
    //
    // `Budgets::check` is the one checkpoint and it runs before every model
    // call *and* before every tool call. `max_turns: 1` permits the first
    // completion and refuses everything after it — including a tool, because by
    // the time the loop reaches one the turn is already spent and `check`
    // refuses with `max_turns`. A model that tried to keep talking is stopped
    // rather than indulged.
    //
    // `max_tool_calls` is deliberately left at its default and **must not be
    // set to 0**: the same checkpoint reads `spent.tool_calls >= max_tool_calls`
    // before the model call, so a zero there refuses the completion itself with
    // `max_tool_calls` — a turn that never happened, reported as a tool budget.
    // The tools are withheld by `with_proposable` above, which is where
    // withholding a tool belongs.
    .with_budgets(Budgets {
        max_turns: 1,
        ..Budgets::default()
    });

    // Ours first, then what the founder said. Both are `with_task`: the
    // objective and the questions are this system's own, and the prose is the
    // operator's own words about their own business — the same trust
    // `Charter::brief` gives `objective.what` on every turn this employee takes.
    let answering = body.question.as_deref().and_then(|code| {
        questions
            .iter()
            .find(|question| question.answerable && question.code == code)
    });
    let asked: Vec<&str> = questions
        .iter()
        .filter(|question| question.answerable && answering.is_none_or(|q| q.code != question.code))
        .map(|question| question.ask)
        .collect();
    // The question on screen first and alone, when the console says which one
    // it was; the rest stay listed because an answer can close two at once
    // ("5,000 units at 2 euros") and the model may only fill what was said.
    let questions_task = match (rewriting, answering) {
        (Some(key), _) => format!(
            "The value they are changing — this once, give `{key}` its new value even though \
             it is already set, and only that key. They typed their answer into the field \
             for `{key}`, so it is the new value unless it is plainly about something \
             else:\n\n- `{key}`, currently {}\n\nThe open questions, for context — fill \
             one only if the answer plainly says so:\n\n- {}",
            base[key],
            asked.join("\n- "),
        ),
        (None, Some(question)) => format!(
            "The question they were answering:\n\n- {}\n\nThey typed their answer into the \
             field for that question, so it is the answer to it unless it is plainly about \
             something else; a short answer (\"month\", \"EUR\", one name) is still an \
             answer.\n\nThe other open questions, for context — fill one only if the answer \
             plainly says so:\n\n- {}",
            question.ask,
            asked.join("\n- "),
        ),
        (None, None) => format!("The questions they were asked:\n\n- {}", asked.join("\n- ")),
    };
    let context = Context::new()
        .with_task(INTERVIEW_BRIEF)
        .with_task(format!(
            "The objective as it stands:\n\n{}\n\n{questions_task}",
            serde_json::to_string_pretty(&Value::Object(base.clone()))
                .unwrap_or_else(|_| "{}".to_owned()),
        ))
        .with_task(format!("What they answered:\n\n{said}"));

    let cancel = CancellationToken::new();
    let deadline = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            tokio::time::sleep(DEADLINE).await;
            cancel.cancel();
        }
    });
    let outcome = turn.run(context, &cancel).await;
    deadline.abort();

    // --- The bill, whichever way it went. ---------------------------------
    //
    // Before the reply is read and before any refusal is returned. A turn that
    // blew its deadline still paid for the calls it made, and a ledger that
    // reads low is wrong in the direction that flatters the number.
    let (usage, turns_taken) = match &outcome {
        Ok(finished) => (finished.usage, finished.turns),
        Err(failed) => (failed.usage, failed.turns),
    };
    if turns_taken > 0 {
        let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
        model_usage::record(
            &mut tx,
            employee_id,
            Utc::now().date_naive(),
            Consumed::reported(
                turns_taken,
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_tokens,
            ),
        )
        .await?;
        tx.commit().await?;
    }

    let finished = outcome.map_err(|failed| {
        let code = failed.error.code();
        tracing::warn!(%id, role, code, "the interview turn did not finish");
        // The code is a closed vocabulary and the founder is the one reading
        // this; the two they can act on get a sentence, the rest get the word.
        let detail = match code {
            "cli_not_logged_in" => "the claude binary behind this company's connection has no \
                                    session: paste the token from `claude setup-token` at step 1"
                .to_owned(),
            "rate_limited" => match failed.error.retry_after() {
                Some(after) => format!(
                    "the subscription's ceiling; it lifts in {} minutes",
                    after.as_secs().div_ceil(60)
                ),
                None => code.to_owned(),
            },
            other => other.to_owned(),
        };
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "interview_turn_failed",
            "this employee's model did not answer",
        )
        .with_detail(detail)
    })?;

    // --- The model proposed. Now the constructors decide. ------------------
    let Some(proposal) = object_in(&finished.reply) else {
        return Ok(Json(AnswerView {
            employee_id: id,
            role,
            accepted: false,
            filled: Vec::new(),
            refused: vec![Refusal {
                field: String::new(),
                // The model's own words, because the founder is the one who
                // can tell whether it misread them or overstepped.
                why: format!(
                    "the model did not answer with a JSON object, so there was nothing to \
                     read an objective out of; say it again. It said: \"{}\"",
                    excerpt(&finished.reply)
                ),
            }],
            questions,
            objective: Value::Object(base),
        })
        .into_response());
    };

    let (built, mut refused) = apply(role, &base, proposal, rewriting);
    // `{}` is the model obeying "omit anything they did not say": the answer
    // did not answer the question. Nothing was refused, so without this line
    // the founder would read "nothing was written" and no reason.
    if built.is_none() && refused.is_empty() {
        // The founder retries and the diary says nothing; this is the one
        // place the reply itself is worth a debug line, and truncated.
        tracing::debug!(
            %id,
            role,
            question = ?body.question,
            reply = %finished.reply.chars().take(300).collect::<String>(),
            "the interview's proposal was empty"
        );
        let said = finished.reply.trim();
        let why = if said == "{}" {
            "the employee found nothing in that answer that fits the question, so it wrote \
             nothing; answer the question as it is asked"
                .to_owned()
        } else {
            format!(
                "the employee wrote nothing, and said why: \"{}\"",
                excerpt(said.trim_start_matches("{}").trim())
            )
        };
        refused.push(Refusal {
            field: String::new(),
            why,
        });
    }
    let Some((charter, filled)) = built else {
        tracing::info!(
            %id,
            role,
            refused = refused.len(),
            "the interview's proposal was not written"
        );
        return Ok(Json(AnswerView {
            employee_id: id,
            role,
            accepted: false,
            filled: Vec::new(),
            refused,
            questions,
            objective: Value::Object(base),
        })
        .into_response());
    };

    // --- The write, on the operator's authority. ---------------------------
    //
    // Not the model's, and not through a tool. `turn::UNSERVED` says
    // `ActionKind::CharterSet` is the one kind that must not become a tool; this
    // is the operator's own transaction, the same one `PUT /initiative` commits.
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    charter
        .save(&mut tx, employee_id, now)
        .await
        .map_err(|err| {
            tracing::error!(%id, code = err.code(), error = %err, "could not save the charter");
            ApiError::internal()
        })?;
    // And the record of it, in the same transaction — `routes::teams::record`,
    // the same helper and the same `AuditKind::PolicyChanged` every other
    // operator write in this surface uses, with `decision_id: None` because no
    // Policy Gate ruling authorised this: an operator's key acted directly.
    //
    // `PUT /v1/employees/{id}/initiative` writes no such row and does not need
    // one — `0018_charter.sql` calls a charter operator configuration rather
    // than a record of anything that happened. **This is the case that
    // differs**, and it is the whole reason the row exists: a model was between
    // the person and the value. The row says which seat, which model, which keys
    // the answer filled and which were thrown away, so "when did this objective
    // become DE, and did anybody type that" has an answer.
    //
    // The founder's prose is deliberately not in it, and neither are the values
    // the model proposed. The ones that survived *are* the objective and can be
    // read off the column; the ones that did not are, by construction, whatever
    // a language model said, and an audit column is not the place to accumulate
    // that. What is here is field names, which are ours.
    teams::record(
        &mut tx,
        &principal.actor,
        Some(employee_id),
        json!({
            "event": "interview_answer",
            "role": role,
            "model": model.as_str(),
            "filled": filled,
            "refused": refused.iter().map(|refusal| &refusal.field).collect::<Vec<_>>(),
        }),
        now,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(%id, role, filled = ?filled, "an interview answer was written down");

    Ok(Json(AnswerView {
        employee_id: id,
        role,
        accepted: true,
        filled,
        refused,
        // Recomputed from the charter that was just built, which is the charter
        // that was just written: the founder sees what is left without a second
        // request.
        questions: charter.open_questions(),
        objective: charter.objective_json(),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A charter that will not read back. 409 and not 500: nothing is wrong with
/// this server, and the remedy is a `PUT` the operator can make.
fn charter_error(err: CharterError) -> ApiError {
    match err {
        CharterError::Unavailable(inner) => inner.into(),
        CharterError::Corrupt(field) => ApiError::new(
            StatusCode::CONFLICT,
            "corrupt_charter",
            "this employee's stored objective cannot be read back",
        )
        .with_detail(format!(
            "{field} does not parse through the constructor it came in through; restate the \
             objective with PUT /v1/employees/{{id}}/initiative"
        )),
    }
}

/// A policy that will not load. Never a 500 with nothing in it: every variant
/// names a document somebody has to fix, and the one that is not the operator's
/// at all — no platform ceiling — is the same `409 no_platform_policy`
/// `routes::companies` and `/readyz` already give.
fn unreadable_policy(err: PolicyLoadError) -> ApiError {
    tracing::error!(error = %err, "an interview could not read a policy");
    match err {
        PolicyLoadError::NoPlatformLayer => ApiError::new(
            StatusCode::CONFLICT,
            "no_platform_policy",
            "this deployment has no platform ceiling",
        )
        .with_detail("install one with `agentos-server policy install --ceiling`"),
        // Ours to fix, and the row that broke is on the log line above. See
        // `error.rs` rule 1 on why none of it is in the body.
        _ => ApiError::internal(),
    }
}

/// No model connection, or none this turn may use. The same shape `GET
/// /v1/model` gives, and it names the call that fixes it.
fn no_model(err: agentos_app::model_access::NoModel) -> ApiError {
    tracing::info!(error = %err, "an interview could not reach a model");
    ApiError::new(
        StatusCode::CONFLICT,
        "no_model_connected",
        "this tenant has no model to think with",
    )
    .with_detail("POST /v1/model with an Anthropic API key, then try the interview again")
}

/// The employee has no turn to spend. Not the founder's mistake and not a
/// failure: `store::turns` already raised the operator alert, and this resumes
/// on its own at UTC midnight.
fn over_budget(err: TurnBudgetError) -> ApiError {
    match err {
        TurnBudgetError::Store(inner) => inner.into(),
        TurnBudgetError::NoBudget => ApiError::new(
            StatusCode::CONFLICT,
            "no_turn_budget",
            "this employee is allowed no turns at all",
        )
        .with_detail(
            "its effective policy sets max_turns_per_day to 0, so it cannot be interviewed; \
             widen a policy layer or set its objective with PUT \
             /v1/employees/{id}/initiative",
        ),
        TurnBudgetError::Exhausted { .. } => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "turn_budget_exhausted",
            "this employee has used today's turns",
        )
        .with_detail("the budget resets at UTC midnight"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::rolepack;
    use agentos_app::rolepack_sales::{self, Segment};
    use agentos_app::rolepack_service;
    use agentos_domain::money::{Currency, Money};
    use agentos_domain::policy::PolicyLimits;

    use super::*;

    // -----------------------------------------------------------------------
    // Six empty objectives, one per role
    // -----------------------------------------------------------------------

    /// A pack whose limits permit no channel at all, so
    /// `RolePack::approach_channel` is `None` for every segment. This is the
    /// shape a `docs/orizn-roles/*.json` layer with `allowed_channels: []`
    /// produces, and it is what makes `Gap::Channel` reachable.
    fn muted_seller() -> rolepack_sales::RolePack {
        rolepack_sales::RolePack::sales_development().with_limits(PolicyLimits::default())
    }

    fn empty(role: &str) -> Charter {
        match role {
            "international-buyer" => Charter::Purchasing {
                pack: rolepack::RolePack::international_buyer(),
                objective: rolepack::Objective {
                    what: String::new(),
                    quantity: 0,
                    max_unit_price: None,
                    delivery_country: None,
                    requirements: Vec::new(),
                },
            },
            "sales-development" => Charter::Sales {
                pack: rolepack_sales::RolePack::sales_development(),
                objective: rolepack_sales::Objective {
                    segment: Segment::Airline,
                    market: None,
                    target_accounts: Vec::new(),
                },
            },
            rolepack_service::CUSTOMER_SUCCESS => Charter::Support {
                objective: rolepack_service::Support {
                    product: String::new(),
                    first_response_hours: 0,
                    escalate_to: None,
                },
            },
            rolepack_service::GROWTH => Charter::Growth {
                objective: rolepack_service::Growth {
                    topic: String::new(),
                    market: None,
                    measure: None,
                },
            },
            rolepack_service::FINANCE => Charter::Finance {
                objective: rolepack_service::Books {
                    period: String::new(),
                    currency: None,
                    obligations: Vec::new(),
                },
            },
            rolepack_service::ENTRY_REQUIREMENTS => Charter::EntryRequirements {
                objective: rolepack_service::Corridors {
                    destinations: String::new(),
                    passports: Vec::new(),
                    max_age_days: 0,
                },
            },
            other => panic!("no such role: {other}"),
        }
    }

    const ROLES: [&str; 6] = [
        "international-buyer",
        "sales-development",
        rolepack_service::CUSTOMER_SUCCESS,
        rolepack_service::GROWTH,
        rolepack_service::FINANCE,
        rolepack_service::ENTRY_REQUIREMENTS,
    ];

    fn base_of(charter: &Charter) -> Map<String, Value> {
        match charter.objective_json() {
            Value::Object(map) => map,
            other => panic!("an objective serialised as {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // `unset` is `gaps()`, written once over JSON
    // -----------------------------------------------------------------------

    /// The claim `candidate` rests on, for all six roles at once: **a key the
    /// stored objective leaves unset is a key `gaps()` is asking about, and
    /// there are exactly as many of each.**
    ///
    /// This is the test that fails when somebody adds a field to an objective
    /// and forgets that `gaps()` decides what an interview may fill. Nothing
    /// here lists a field name — the counts come from the packs themselves — so
    /// a seventh role is covered the moment it is added to `ROLES`.
    ///
    /// Mutated to check it bites: making `unset` answer `false` for an empty
    /// array — `Value::Array(items) => items.iter().all(unset)` to
    /// `Value::Array(_) => false` — fails as
    /// `international-buyer: 5 open questions but 4 unset keys in the stored
    /// objective`, because `requirements` is a gap and stopped reading as one.
    #[test]
    fn every_unset_key_is_a_gap_and_every_gap_is_an_unset_key() {
        for role in ROLES {
            let charter = empty(role);
            let base = base_of(&charter);
            let unset_keys: Vec<&String> = base
                .iter()
                .filter(|(_, value)| unset(value))
                .map(|(key, _)| key)
                .collect();
            // `answerable` only: `Gap::Channel` is a gap with no key, which is
            // the whole reason it carries the flag.
            let asked = charter
                .open_questions()
                .into_iter()
                .filter(|question| question.answerable)
                .count();
            assert_eq!(
                asked,
                unset_keys.len(),
                "{role}: {asked} open questions but {} unset keys in the stored objective \
                 ({unset_keys:?})",
                unset_keys.len(),
            );
            assert!(asked > 0, "{role}: an empty objective must ask something");
        }
    }

    /// And the other direction: an objective with nothing missing has no
    /// questions and no unset keys, so an interview against it can fill
    /// nothing.
    #[test]
    fn a_complete_objective_asks_nothing_and_offers_no_key_to_fill() {
        let charter = Charter::Sales {
            pack: rolepack_sales::RolePack::sales_development(),
            objective: rolepack_sales::Objective {
                segment: Segment::Airline,
                market: Some(rolepack::CountryCode::parse("de").expect("de")),
                target_accounts: vec!["Lufthansa".to_owned()],
            },
        };
        assert!(charter.open_questions().is_empty());

        let base = base_of(&charter);
        assert!(base.values().all(|value| !unset(value)), "{base:?}");

        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"market": "fr", "target_accounts": ["Air France"]})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );
        assert!(
            built.is_none(),
            "an answered objective must not be rewritten"
        );
        assert_eq!(refused.len(), 2, "{refused:?}");
        for refusal in &refused {
            assert!(refusal.why.contains("already answered"), "{}", refusal.why);
        }

        // Unless the console named the key being changed: that one goes
        // through set, and only that one — through the same constructor, so
        // "Germanie" is refused here exactly as it is on an open question.
        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"market": "fr", "target_accounts": ["Air France"]})
                .as_object()
                .expect("an object")
                .clone(),
            Some("market"),
        );
        let (rewritten, filled) = built.expect("the named key is rewritten");
        assert_eq!(filled, vec!["market".to_owned()]);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0].field, "target_accounts");
        match rewritten {
            Charter::Sales { objective, .. } => {
                assert_eq!(
                    objective.market.map(|c| c.to_string()),
                    Some("FR".to_owned())
                );
                assert_eq!(objective.target_accounts, vec!["Lufthansa".to_owned()]);
            }
            other => panic!("the role is ours, not the model's: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // The frontier: the model proposes, the constructor decides
    // -----------------------------------------------------------------------

    /// **The test this whole unit exists for.** The model reads "we are selling
    /// into Germany" and proposes `"Germanie"`. `CountryCode::parse` refuses it,
    /// nothing is built, and the question is still open.
    ///
    /// Mutated to check it bites: deleting the length-and-alphabetic guard from
    /// `CountryCode::parse`, which is the concrete form of the
    /// `#[derive(Deserialize)]` `0018_charter.sql` forbids — a value reaching
    /// the column past the parser that exists to refuse it. It fails at
    ///
    /// ```text
    /// panicked at apps/server/src/routes/interview.rs:
    /// a country the model invented must not become a charter
    /// ```
    ///
    /// which is this test asserting that nothing but the constructor is doing
    /// the refusing.
    #[test]
    fn a_country_the_model_invented_does_not_become_a_charter() {
        let charter = empty("sales-development");
        let base = base_of(&charter);

        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"market": "Germanie", "target_accounts": ["Lufthansa"]})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );

        assert!(
            built.is_none(),
            "a country the model invented must not become a charter"
        );
        let why = &refused.last().expect("a refusal").why;
        assert!(
            why.contains("market"),
            "the refusal must name the field: {why}"
        );
        assert!(
            why.contains("Germanie"),
            "the founder cannot re-answer a question without seeing what was read: {why}"
        );

        // And the good answer, through the same door, so the refusal above is
        // about the value and not about the path.
        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"market": "de", "target_accounts": ["Lufthansa"]})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );
        assert!(refused.is_empty(), "{refused:?}");
        let (built, filled) = built.expect("a charter");
        assert_eq!(filled, ["market", "target_accounts"]);
        assert!(built.open_questions().is_empty());
        // Normalised by the constructor, not stored as typed.
        assert_eq!(built.objective_json()["market"], json!("DE"));
    }

    /// `Money::new` refuses zero, so a price the model rounded away is not a
    /// budget. Same shape as the country: nothing written, question open.
    #[test]
    fn a_price_of_zero_does_not_become_a_budget() {
        let charter = empty("international-buyer");
        let base = base_of(&charter);

        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"max_unit_price": {"minor": 0, "currency": "USD"}})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );
        assert!(built.is_none(), "zero is not a ceiling per unit");
        assert!(
            refused
                .last()
                .expect("a refusal")
                .why
                .contains("max_unit_price"),
            "{refused:?}"
        );

        // The same field, through the same door, with a real price.
        let (built, _) = apply(
            charter.role(),
            &base,
            json!({"max_unit_price": {"minor": 1_200, "currency": "usd"}})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );
        let (built, _) = built.expect("a charter");
        assert_eq!(
            built.objective_json()["max_unit_price"],
            json!({"minor": 1_200, "currency": "USD"}),
            "the currency comes back through `Currency`, uppercased"
        );
        // And it really is a `Money`, not a number that survived.
        let Charter::Purchasing { objective, .. } = built else {
            panic!("the role changed");
        };
        assert_eq!(
            objective.max_unit_price,
            Some(Money::new(1_200, Currency::Usd).expect("non-zero"))
        );
    }

    /// A currency the model spelled out is refused by `Currency` itself, which
    /// is the one place the list of codes lives.
    #[test]
    fn a_currency_in_words_does_not_become_a_currency() {
        let charter = empty(rolepack_service::FINANCE);
        let base = base_of(&charter);
        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"period": "Q3 2026", "currency": "dollars", "obligations": ["VAT"]})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );
        assert!(built.is_none());
        assert!(
            refused.last().expect("a refusal").why.contains("currency"),
            "{refused:?}"
        );
    }

    // -----------------------------------------------------------------------
    // What a proposal may not reach
    // -----------------------------------------------------------------------

    /// The three keys a reply must not be able to use, in one test: a field this
    /// objective does not have, the `role` tag, and a field that is already
    /// answered.
    ///
    /// `segment` is the one that matters. It is never a `Gap`, it decides what
    /// being wrong costs a prospect, and it is the only field of any objective
    /// that is *always* set — so it is the field a sentence about something else
    /// could otherwise re-task a seller with.
    ///
    /// Mutated to check it bites: changing `candidate`'s `base.get(&key)` arms
    /// so a missing key is kept rather than refused — `None => kept.push(...)`.
    /// It fails at
    ///
    /// ```text
    /// panicked at apps/server/src/routes/interview.rs:
    /// the one real answer still lands
    /// ```
    ///
    /// and the failure is exactly the point: `allowed_channels` reaches
    /// `ObjectiveBody`, `deny_unknown_fields` refuses the **whole body**, and
    /// the one good answer in it is lost with the rest. Both nets hold — nothing
    /// is written either way — but only the first one keeps the founder's real
    /// answer and tells them which key was dropped.
    #[test]
    fn a_proposal_reaches_no_key_the_interview_did_not_ask_about() {
        let charter = empty("sales-development");
        let base = base_of(&charter);

        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({
                "segment": "insurer",
                "role": "finance",
                "allowed_channels": ["email", "voice"],
                "market": "de"
            })
            .as_object()
            .expect("an object")
            .clone(),
            None,
        );

        let (built, filled) = built.expect("the one real answer still lands");
        assert_eq!(filled, ["market"], "only the gap was filled");
        assert_eq!(
            built.role(),
            "sales-development",
            "the tag is ours, so a reply cannot move an objective between packs"
        );
        let Charter::Sales { objective, .. } = &built else {
            panic!("the role changed");
        };
        assert_eq!(
            objective.segment,
            Segment::Airline,
            "an answered field must survive a proposal about it"
        );

        let names: Vec<&str> = refused.iter().map(|r| r.field.as_str()).collect();
        assert!(names.contains(&"segment"), "{names:?}");
        assert!(names.contains(&"role"), "{names:?}");
        assert!(
            names.contains(&"allowed_channels"),
            "a key this objective does not have must not be written: {names:?}"
        );
        assert!(
            refused
                .iter()
                .find(|r| r.field == "allowed_channels")
                .expect("the policy key")
                .why
                .contains("not part of this employee's objective"),
        );
    }

    /// A reply that is only keys nobody asked about writes nothing at all —
    /// not an empty update, not a touched `updated_at`.
    #[test]
    fn a_proposal_with_nothing_askable_in_it_builds_no_charter() {
        let charter = empty(rolepack_service::GROWTH);
        let base = base_of(&charter);
        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"max_turns_per_day": 200})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );
        assert!(built.is_none());
        assert_eq!(refused.len(), 1);
    }

    // -----------------------------------------------------------------------
    // The gap no answer may close
    // -----------------------------------------------------------------------

    /// The sales channel gap is reported so a person can act on it, and is
    /// marked unanswerable so nothing tries to act on it here. Its remedy is a
    /// policy layer, and widening a policy is the one thing this route must
    /// never do.
    ///
    /// Mutated to check it bites: changing `Question::blocked` to
    /// `Question::asked` in `Charter::open_questions` fails at
    /// `the channel gap is not an objective field and no answer may close it`.
    #[test]
    fn the_channel_gap_is_asked_and_is_not_answerable() {
        let charter = Charter::Sales {
            pack: muted_seller(),
            objective: rolepack_sales::Objective {
                segment: Segment::Airline,
                market: Some(rolepack::CountryCode::parse("de").expect("de")),
                target_accounts: vec!["Lufthansa".to_owned()],
            },
        };

        let questions = charter.open_questions();
        assert_eq!(questions.len(), 1, "{questions:?}");
        assert_eq!(questions[0].code, "channel");
        assert!(
            !questions[0].answerable,
            "the channel gap is not an objective field and no answer may close it"
        );

        // And there is no key for it, so even a proposal naming it is refused
        // by `candidate` before anything else looks at it.
        let base = base_of(&charter);
        assert!(!base.contains_key("channel"));
        let (built, refused) = apply(
            charter.role(),
            &base,
            json!({"channel": "voice"})
                .as_object()
                .expect("an object")
                .clone(),
            None,
        );
        assert!(built.is_none());
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].field, "channel");
    }

    /// The same seat with a channel it may use asks nothing, so the flag is
    /// about the policy and not about the segment.
    #[test]
    fn a_seller_with_a_permitted_channel_has_no_channel_gap() {
        let charter = Charter::Sales {
            pack: rolepack_sales::RolePack::sales_development(),
            objective: rolepack_sales::Objective {
                segment: Segment::Airline,
                market: Some(rolepack::CountryCode::parse("de").expect("de")),
                target_accounts: vec!["Lufthansa".to_owned()],
            },
        };
        assert!(charter.open_questions().is_empty());
    }

    // -----------------------------------------------------------------------
    // Reading the reply
    // -----------------------------------------------------------------------

    /// A fenced object is still an answer; prose is not.
    #[test]
    fn the_reply_is_read_out_of_whatever_the_model_wrapped_it_in() {
        assert_eq!(
            object_in("```json\n{\"market\": \"de\"}\n```"),
            Some(
                json!({"market": "de"})
                    .as_object()
                    .expect("an object")
                    .clone()
            )
        );
        assert_eq!(
            object_in("Sure! Here you go:\n{\"market\": \"de\"}\nHope that helps."),
            Some(
                json!({"market": "de"})
                    .as_object()
                    .expect("an object")
                    .clone()
            )
        );
        assert_eq!(object_in("I could not tell what they meant."), None);
        assert_eq!(object_in("[\"de\"]"), None, "an array is not an objective");
        assert_eq!(object_in("{not json}"), None);
    }

    // -----------------------------------------------------------------------
    // The route, against a real Postgres and a scripted model
    // -----------------------------------------------------------------------
    //
    // Its own database — `crate::tests::own_database` says why: this test
    // installs a **platform ceiling**, which is a global singleton, and two
    // tests doing that in one binary is a coin flip over which one the other is
    // asserting on.

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use agentos_app::mocks::{LlmRequest, LlmResponse, ProviderError, Usage};
    use agentos_domain::action::Domain;
    use agentos_domain::employee::{Employee, Lifecycle};
    use agentos_domain::ids::{Slug, TenantId};
    use agentos_store::employee as employee_store;
    use agentos_store::policy as policy_store_mod;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use tower::ServiceExt;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A model that says what the test told it to, in order.
    ///
    /// Hand-rolled rather than `ScriptedLlm`, because `apps/server` may not
    /// depend on `agentos-providers` — see that crate's `Cargo.toml`, which
    /// keeps `async-trait` in dev-dependencies for exactly this.
    struct Script {
        replies: Mutex<VecDeque<String>>,
        /// Every prompt the route built, oldest first — system and messages
        /// rendered with `Debug`, which is enough to assert a sentence is in
        /// there and in which order.
        seen: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl Llm for Script {
        async fn complete(&self, request: LlmRequest) -> Result<LlmResponse, ProviderError> {
            self.seen
                .lock()
                .expect("not poisoned")
                .push(format!("{}\n{:?}", request.system, request.messages));
            let said = self
                .replies
                .lock()
                .expect("not poisoned")
                .pop_front()
                .expect("the interview asked the model more times than the test scripted");
            Ok(LlmResponse::text(said, Usage::default()))
        }
    }

    struct Harness {
        app: Router,
        db: Db,
        admin_url: String,
        database: String,
        seller: Uuid,
        /// A seat in the same company that nobody has given a job — the state
        /// `POST /v1/companies` leaves every employee in.
        uncharted: Uuid,
        stranger: Uuid,
        /// What the scripted model was shown — see [`Script::seen`].
        prompts: Arc<Mutex<Vec<String>>>,
    }

    impl Harness {
        /// A tenant with a ceiling, a connected model, and one seller whose
        /// objective names a segment and nothing else — which is what
        /// `POST /v1/companies` leaves behind.
        async fn new(script: Vec<&str>) -> Option<Self> {
            let (db, admin_url, database) = crate::tests::own_database("interview").await?;
            let now = Utc::now();

            let a = TenantId::new_v7(now);
            let b = TenantId::new_v7(now);
            for tenant in [a, b] {
                policy_store_mod::create_tenant(
                    &db,
                    tenant,
                    &tenant.as_uuid().to_string(),
                    "interview-test",
                )
                .await
                .expect("create tenant");
            }
            // The ceiling. Without one `policy::load` is `NoPlatformLayer` and
            // no employee anywhere may take a turn — which is the deployment's
            // safe direction and would make this test assert nothing.
            policy_store_mod::install_ceiling(
                &db,
                &policy_store_mod::default_ceiling(),
                "interview-test",
            )
            .await
            .expect("install ceiling");

            // `books` sorts before `sdr`, and the questionnaire is ordered by
            // slug — so the uncharted seat is first in every assertion below.
            let uncharted = Self::hire(&db, a, "books").await;
            let seller = Self::hire(&db, a, "sdr").await;
            let stranger = Self::hire(&db, b, "sdr").await;

            // Whose model this thinks with. `ModelPath::Cli` is "this host's
            // model", and this host's is `Script` — legal because the backend
            // below is `LlmBackend::Mock`, which is not a bill of ours.
            let mut tx = db.tenant_tx(a).await.expect("tenant tx");
            agentos_store::model_access::save(
                &mut tx,
                &agentos_domain::model_access::ModelAccess {
                    path: agentos_domain::model_access::ModelPath::Cli,
                    model: agentos_domain::policy::ModelId::Opus5,
                    verified_at: now,
                },
                // `cli`: no credential, and 0050's CHECK insists there is none.
                None,
                now,
            )
            .await
            .expect("connect the model");
            // And the charter a fresh company has: a segment, and two holes.
            empty("sales-development")
                .save(&mut tx, EmployeeId::from_uuid(seller), now)
                .await
                .expect("save the charter");
            tx.commit().await.expect("commit");

            let keys = crate::auth::ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");

            let prompts: Arc<Mutex<Vec<String>>> = Arc::default();
            let llm: Arc<dyn Llm> = Arc::new(Script {
                replies: Mutex::new(script.into_iter().map(str::to_owned).collect()),
                seen: Arc::clone(&prompts),
            });
            let app = crate::with_api_stack(
                router(
                    db.clone(),
                    PolicyGate::new(db.clone()),
                    Arc::new(agentos_app::mocks::ports()),
                    llm,
                    LlmBackend::Mock,
                    agentos_app::mcp::Credentials::from_master_key("test-master-key"),
                ),
                db.clone(),
                crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
            );

            Some(Self {
                app,
                db,
                admin_url,
                database,
                seller,
                uncharted,
                stranger,
                prompts,
            })
        }

        /// The last prompt the model was shown.
        fn last_prompt(&self) -> String {
            self.prompts
                .lock()
                .expect("not poisoned")
                .last()
                .cloned()
                .expect("the model was asked at least once")
        }

        async fn hire(db: &Db, tenant: TenantId, slug: &str) -> Uuid {
            let now = Utc::now();
            let id = EmployeeId::new_v7(now);
            let mut employee = Employee::new(
                id,
                tenant,
                Slug::parse(slug).expect("slug"),
                Domain::parse("example.test").expect("domain"),
                now,
            );
            employee
                .set_lifecycle(Lifecycle::Active, now)
                .expect("draft -> active");
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            employee_store::insert(&mut tx, &employee)
                .await
                .expect("insert employee");
            tx.commit().await.expect("commit");
            id.as_uuid()
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
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
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

        /// What is in the column right now, read past every handler.
        async fn stored(&self, employee: Uuid) -> Value {
            let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
            let objective: Value = sqlx::query_scalar(
                "SELECT objective FROM employee_charters WHERE employee_id = $1",
            )
            .bind(employee)
            .fetch_one(&mut *tx)
            .await
            .expect("the charter row");
            tx.commit().await.expect("commit");
            objective
        }

        /// Turns booked against this employee today.
        async fn turns_taken(&self, employee: Uuid) -> i32 {
            let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
            let taken: Option<i32> = sqlx::query_scalar(
                "SELECT turns_taken FROM turn_buckets \
                  WHERE employee_id = $1 AND day = current_date",
            )
            .bind(employee)
            .fetch_optional(&mut *tx)
            .await
            .expect("the turn bucket");
            tx.commit().await.expect("commit");
            taken.unwrap_or(0)
        }

        /// Every `interview_answer` payload for this employee, oldest first.
        async fn audit(&self, employee: Uuid) -> Vec<Value> {
            let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
            let rows: Vec<Value> = sqlx::query_scalar(
                "SELECT payload FROM audit_log \
                  WHERE employee_id = $1 AND payload ->> 'event' = 'interview_answer' \
                  ORDER BY occurred_at, id",
            )
            .bind(employee)
            .fetch_all(&mut *tx)
            .await
            .expect("the audit rows");
            tx.commit().await.expect("commit");
            rows
        }

        async fn teardown(self) {
            crate::tests::drop_database(self.db, self.admin_url, self.database).await;
        }
    }

    /// The whole interview, over HTTP: the questionnaire, a bad answer that
    /// writes nothing, and a good one that does.
    ///
    /// **The refusal half is the half that matters.** The model is scripted to
    /// answer `"Germanie"` — which is what a model does with "we're selling into
    /// Germany" — and the assertions are that the column is byte-identical
    /// afterwards, that the questions did not move, and that the founder was
    /// nevertheless charged for the turn, because the tokens were really spent.
    ///
    /// Mutated twice to check it bites.
    ///
    /// Deleting the `turns::reserve` call, so the turn is taken and not paid
    /// for:
    ///
    /// ```text
    /// assertion `left == right` failed:
    /// a turn that was spent is a turn that was charged, refusal or not
    ///   left: 0
    ///  right: 1
    /// ```
    ///
    /// Replacing the `apply` call with a straight merge of the model's object
    /// into the objective — no `candidate`, no refusals, everything the model
    /// said written as it said it:
    ///
    /// ```text
    /// panicked at apps/server/src/routes/interview.rs: a reason
    /// ```
    ///
    /// which is the `refused[0].why` this route promises the founder, absent
    /// because nothing was refused.
    ///
    /// And a third, on the questionnaire: turning the `LEFT JOIN` back into a
    /// `JOIN`, so only chartered seats are listed:
    ///
    /// ```text
    /// assertion `left == right` failed: every employee, not every charter
    ///   left: 1
    ///  right: 2
    /// ```
    ///
    /// A company nobody has chartered would then be told its questionnaire is
    /// empty, which is the most misleading answer this route could give.
    #[tokio::test]
    async fn a_founder_is_asked_answers_in_prose_and_the_constructors_decide() {
        let Some(h) = Harness::new(vec![
            // 1. the model hears Germany and writes Germanie.
            r#"{"market": "Germanie", "target_accounts": ["Lufthansa"]}"#,
            // 2. the founder says it again; this time it writes a code.
            "```json\n{\"market\": \"de\", \"target_accounts\": [\"Lufthansa\", \"Condor\"]}\n```",
        ])
        .await
        else {
            return;
        };

        // --- the questionnaire ---------------------------------------------
        let (status, seen) = h.send("GET", "/v1/interview", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{seen}");
        let seats = seen["seats"].as_array().expect("seats");
        assert_eq!(seats.len(), 2, "every employee, not every charter: {seen}");

        // The seat nobody chartered is the one this list most needs to show —
        // it is what `POST /v1/companies` leaves behind, and omitting it would
        // answer "nothing is missing" about the state where everything is.
        assert_eq!(seats[0]["employee_id"], json!(h.uncharted.to_string()));
        assert_eq!(seats[0]["role"], Value::Null, "{seen}");
        assert_eq!(seats[0]["questions"][0]["code"], json!("role"));
        assert_eq!(
            seats[0]["questions"][0]["answerable"],
            json!(false),
            "no prose picks which of six jobs a colleague holds: {seen}"
        );

        assert_eq!(seats[1]["employee_id"], json!(h.seller.to_string()));
        assert_eq!(seats[1]["role"], json!("sales-development"));
        let codes: Vec<&str> = seats[1]["questions"]
            .as_array()
            .expect("questions")
            .iter()
            .map(|q| q["code"].as_str().expect("a code"))
            .collect();
        assert_eq!(
            codes,
            ["market", "target_accounts"],
            "the order is `gaps()`'s: {seen}"
        );
        assert!(
            seats[1]["questions"][0]["ask"]
                .as_str()
                .expect("a question")
                .contains("which market"),
            "the question is the pack's own: {seen}"
        );

        // --- a blank answer costs nothing ----------------------------------
        let uri = format!("/v1/employees/{}/interview", h.seller);
        let (status, _) = h
            .send("POST", &uri, SECRET_A, Some(json!({"answer": "   "})))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            h.turns_taken(h.seller).await,
            0,
            "a blank answer is not a turn"
        );

        // --- the model's mistake is not written -----------------------------
        let before = h.stored(h.seller).await;
        let (status, refused) = h
            .send(
                "POST",
                &uri,
                SECRET_A,
                Some(json!({"answer": "We're going after German carriers — Lufthansa first."})),
            )
            .await;
        // A refused proposal is a 200, exactly as a refused key is on
        // `POST /v1/model`: the request was well formed and this is the result.
        assert_eq!(status, StatusCode::OK, "{refused}");
        assert_eq!(refused["accepted"], json!(false), "{refused}");
        assert_eq!(refused["filled"], json!([]), "{refused}");
        let why = refused["refused"][0]["why"].as_str().expect("a reason");
        assert!(why.contains("market"), "{why}");
        assert!(
            why.contains("Germanie"),
            "the founder must see what was read: {why}"
        );
        assert_eq!(
            h.stored(h.seller).await,
            before,
            "a refused proposal must leave the column untouched"
        );
        let still: Vec<&str> = refused["questions"]
            .as_array()
            .expect("questions")
            .iter()
            .map(|q| q["code"].as_str().expect("a code"))
            .collect();
        assert_eq!(still, ["market", "target_accounts"], "{refused}");
        assert_eq!(
            h.turns_taken(h.seller).await,
            1,
            "a turn that was spent is a turn that was charged, refusal or not"
        );

        // --- and the answer that survives ----------------------------------
        let (status, done) = h
            .send(
                "POST",
                &uri,
                SECRET_A,
                Some(json!({"answer": "Germany — DE. Lufthansa and Condor."})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["accepted"], json!(true), "{done}");
        assert_eq!(done["filled"], json!(["market", "target_accounts"]));
        assert_eq!(done["questions"], json!([]), "nothing is open now: {done}");
        assert_eq!(
            done["objective"],
            json!({
                "segment": "airline",
                "market": "DE",
                "target_accounts": ["Lufthansa", "Condor"]
            }),
            "the segment survived and the country came back normalised"
        );
        assert_eq!(h.stored(h.seller).await, done["objective"]);
        assert_eq!(h.turns_taken(h.seller).await, 2);

        // --- and the questionnaire agrees -----------------------------------
        let (_, seen) = h.send("GET", "/v1/interview", SECRET_A, None).await;
        assert_eq!(seen["seats"][1]["questions"], json!([]), "{seen}");
        assert_eq!(
            seen["seats"][1]["objective"], done["objective"],
            "what was answered is read back, so a reload does not lose it: {seen}"
        );
        assert!(
            seen["seats"][0]["objective"].is_null(),
            "a seat with no charter has no objective to show: {seen}"
        );

        // --- one audit row, for the one answer that was written -------------
        //
        // One and not two: the refused proposal changed nothing, so there is
        // nothing for a trail of changes to say about it. What it cost is in
        // `turn_buckets` and `model_usage`, above.
        let trail = h.audit(h.seller).await;
        assert_eq!(trail.len(), 1, "{trail:?}");
        assert_eq!(trail[0]["role"], json!("sales-development"));
        assert_eq!(trail[0]["filled"], json!(["market", "target_accounts"]));
        // The **role's** model, intersected with the policy — not the one the
        // tenant proved when it connected. `POST /v1/model` proved
        // `claude-opus-5`; the sales pack asks for its own and the ceiling
        // permits it, so that is what the interview ran and that is what the
        // trail says. `agentos_domain::policy::model_for` owns that choice, and
        // this asserts the interview did not grow a second opinion about it.
        assert_eq!(
            trail[0]["model"],
            json!(
                Charter::Sales {
                    pack: rolepack_sales::RolePack::sales_development(),
                    objective: rolepack_sales::Objective {
                        segment: Segment::Airline,
                        market: None,
                        target_accounts: Vec::new(),
                    },
                }
                .model()
                .as_str()
            )
        );
        // Not the founder's sentence, and not what the model said it meant.
        let rendered = trail[0].to_string();
        assert!(!rendered.contains("Condor"), "{rendered}");
        assert!(!rendered.contains("Germany"), "{rendered}");

        h.teardown().await;
    }

    /// A seat with no charter is a 404 and not a turn: there is no objective, so
    /// there is nothing to ask about, and `PUT /v1/employees/{id}/initiative` is
    /// what the questionnaire told the founder to call.
    /// The console asks one question at a time and lets the founder skip, so
    /// the question on screen is routinely not the first open gap. When the
    /// body says which one it was, the model is told that one first and alone;
    /// the others stay listed for context. A code that names nothing open is
    /// ignored, not refused.
    #[tokio::test]
    async fn the_question_on_screen_is_the_one_the_model_is_told_first() {
        let Some(h) = Harness::new(vec!["{}", "{}", "{}"]).await else {
            return;
        };
        let uri = format!("/v1/employees/{}/interview", h.seller);

        let (status, _) = h
            .send(
                "POST",
                &uri,
                SECRET_A,
                Some(json!({"answer": "Lufthansa and Condor.", "question": "target_accounts"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let prompt = h.last_prompt();
        let first = prompt
            .find("The question they were answering:")
            .expect("the named question leads: {prompt}");
        let named = prompt
            .find("which accounts should be worked")
            .expect("its wording is there: {prompt}");
        let others = prompt
            .find("The other open questions")
            .expect("the rest follow: {prompt}");
        let other = prompt
            .find("which market are we selling into?")
            .expect("and are listed: {prompt}");
        assert!(
            first < named && named < others && others < other,
            "{prompt}"
        );
        assert!(
            !prompt.contains("The questions they were asked:"),
            "one heading, not both: {prompt}"
        );

        // A code that is not an open question of this seat: the plain list.
        let (status, _) = h
            .send(
                "POST",
                &uri,
                SECRET_A,
                Some(json!({"answer": "Germany.", "question": "delivery_country"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(h.last_prompt().contains("The questions they were asked:"));

        // And no code at all, as before.
        let (status, _) = h
            .send("POST", &uri, SECRET_A, Some(json!({"answer": "Germany."})))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(h.last_prompt().contains("The questions they were asked:"));
        assert_eq!(h.turns_taken(h.seller).await, 3);
    }

    #[tokio::test]
    async fn a_seat_with_no_job_cannot_be_interviewed_about_one() {
        let Some(h) = Harness::new(Vec::new()).await else {
            return;
        };

        let (status, body) = h
            .send(
                "POST",
                &format!("/v1/employees/{}/interview", h.uncharted),
                SECRET_A,
                Some(json!({"answer": "close the books every quarter, in euros"})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(
            body["detail"]
                .as_str()
                .expect("a detail")
                .contains("initiative"),
            "the 404 names the endpoint that fixes it: {body}"
        );
        assert_eq!(h.turns_taken(h.uncharted).await, 0);

        h.teardown().await;
    }

    /// Another company's employee is a 404, and no turn is spent finding out.
    ///
    /// The id is real and the charter is not — the seat belongs to tenant B and
    /// the key is tenant A's. RLS is what makes it invisible; this route never
    /// reads a tenant from a body.
    #[tokio::test]
    async fn an_answer_cannot_reach_another_company() {
        let Some(h) = Harness::new(Vec::new()).await else {
            return;
        };

        let (status, body) = h
            .send(
                "POST",
                &format!("/v1/employees/{}/interview", h.stranger),
                SECRET_A,
                Some(json!({"answer": "sell to airlines in Germany"})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(h.turns_taken(h.stranger).await, 0);

        // And the questionnaire shows tenant A's seat only.
        let (_, seen) = h.send("GET", "/v1/interview", SECRET_A, None).await;
        let seats = seen["seats"].as_array().expect("seats");
        assert_eq!(
            seats.len(),
            2,
            "tenant A's two seats and neither of B's: {seen}"
        );
        assert_eq!(seats[1]["employee_id"], json!(h.seller.to_string()));

        h.teardown().await;
    }
}
