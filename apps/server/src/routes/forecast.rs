//! `GET /v1/forecast?days=N`: **what this company will get through in the next
//! N days, and what it will bill.**
//!
//! # The screen this answers, and the number it refuses to print
//!
//! At the end of setup the founder picks a stretch of time — two days, a week, a
//! month — and goes live. What he asked for beside that picker was *"a % of
//! estimated success for the company"*. This endpoint does not return one, and
//! that is a decision rather than an omission.
//!
//! A success percentage is not measurable here. There is no population of
//! companies that have run on this to sample from, the first ones are N=1, and
//! the figure would sit on the same screen as `agentos_domain::forecast::RECORDED`
//! — three numbers that cost a live run and are pinned against a digest that goes
//! red when the company they measured changes. One invented number beside
//! measured ones does not merely mislead about itself; it makes a reader discount
//! the ones that are real. `crates/eval/src/cost.rs` exists because that already
//! happened once in this repository, in prose, and cost a published figure its
//! truth.
//!
//! What is returned instead is **effort**: how many turns the cadences produce
//! over the window, how many model calls that is, how many people may lawfully be
//! approached, and — only on the metered path — what it bills. A quote, not a
//! promise. It is also the more useful thing commercially: a buyer at $2–5k a
//! month is deciding whether the throughput is worth it, and a probability
//! answers a question he did not ask.
//!
//! # It reads this tenant's company, not the fixture
//!
//! `agentos_eval::cost` prices Orizn out of `docs/orizn-roles/*.json`. This
//! prices **the seats of the tenant holding the API key**: their employees, their
//! cadences, their intersected policies and the model each one would actually
//! run. The arithmetic is not copied — `agentos_domain::forecast::Sample::usd` is
//! the one multiplication and both callers go through it, because two places
//! computing one bill is two places that drift.
//!
//! Every resolution below is the running system's own, reused rather than
//! restated: [`plan_of`] and [`model_for`] are the same functions
//! `loops::initiative::assignment_for` calls in the same order, so a seat this
//! endpoint forecasts at zero is a seat that loop will refuse a turn for the same
//! reason and with the same words.
//!
//! # Turns come from the cadence, and that is the whole difference
//!
//! `max_turns_per_day` is a **ceiling**, and `agentos_eval::cost` says so in its
//! own uncertainties: an employee with nothing to do reserves nothing. Billing a
//! window at the ceiling would produce a number no company ever reaches.
//!
//! `employee_initiative.interval_secs` is the rate. An employee wakes every
//! interval, `Cadence::advance` measures the next deadline from take-up so a
//! missed slot is missed rather than owed, and jitter only ever delays. So
//! `days × 86400 ÷ interval` is the number of wakes, capped by the turn budget —
//! an upper bound, but a tight one, and it is derived from a row this deployment
//! holds rather than from a ceiling nobody types with a forecast in mind. An
//! employee with **no** schedule row never self-starts at all, and this endpoint
//! says so per seat rather than quietly counting it.
//!
//! # The regime decides whether dollars are even the right unit
//!
//! A tenant on [`ModelPath::ApiKey`] pays per token and a bill is what they want.
//! A tenant on [`ModelPath::Cli`] runs the host's `claude` under a subscription,
//! where **no per-token invoice exists**: the currency is a monthly seat and the
//! binding constraint is throughput. A dollar figure there is the metered-API
//! reading of an unmetered run — arithmetic that looks like a measurement — so
//! `cost_usd` is `null` on that path and the model-call figure is what a plan is
//! sized against. `rate_card`'s own docs carry the argument.
//!
//! # What is deliberately not here
//!
//! Anything a caller could aim at another tenant. There is no employee id in the
//! query and no `WHERE tenant_id` in the SQL: every read runs on
//! [`Db::tenant_tx`] under forced RLS, so another company's seats are invisible
//! rather than filtered.
//!
//! [`ModelPath::ApiKey`]: agentos_domain::model_access::ModelPath::ApiKey
//! [`ModelPath::Cli`]: agentos_domain::model_access::ModelPath::Cli

use agentos_app::vertical::Charter;
use agentos_domain::employee::Lifecycle;
use agentos_domain::forecast::{FLOOR_CALLS_PER_TURN, Sample, spread};
use agentos_domain::ids::EmployeeId;
use agentos_domain::model_access::ModelPath;
use agentos_domain::policy::{ModelId, model_for};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::{model_access, policy as policy_store};
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::loops::initiative::plan_of;

/// This unit's routes. Merged into the API router, so auth, the rate limit and
/// the idempotency layer are already in front of it.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/forecast", get_route(get))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------

/// Seconds in a day, for turning a cadence into a rate.
const SECONDS_PER_DAY: u64 = 86_400;

/// The longest window this endpoint will answer for.
///
/// A quarter, and the bound is about the *inputs* rather than about the
/// arithmetic — which is linear and would happily multiply by ten years.
/// Everything feeding a figure below has a shorter shelf life than that: the
/// rate card was read on one day, `claude-sonnet-5`'s introductory price expires
/// on 2026-08-31, a model snapshot moves behind an unchanged name, and the
/// samples are three passes of one afternoon. Quoting a year would be quoting
/// those four as if they were stable, which is the exact failure
/// `crates/eval/src/cost.rs` was written to end.
///
/// It also covers everything the founder actually asked for: two days, a week, a
/// month.
const MAX_DAYS: u32 = 90;

/// `?days=`.
#[derive(Debug, Deserialize)]
pub struct ForecastQuery {
    /// How long the company runs. Required, and deliberately: there is no
    /// honest default. Substituting thirty would answer a question the caller
    /// did not ask with a number they would read as theirs.
    days: Option<u32>,
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// One figure with its assumptions on both sides of it.
///
/// Four numbers and not one, for the reason `agentos_eval::cost::headline`
/// publishes three: a reserved turn makes between one and `Budgets::max_turns`
/// model calls, so any point inside that is a choice. Publishing the middle
/// alone is how `docs/ORIZN.md` came to print a floor as an estimate.
#[derive(Debug, Serialize)]
struct Range {
    /// Every turn answered in one round trip. The cheapest arithmetic the
    /// system can produce, and not a prediction of anything.
    floor: f64,
    /// The smallest of the recorded runs.
    low: f64,
    /// The largest of them.
    high: f64,
    /// Every turn running the loop to `Budgets::max_turns`. Read off that type,
    /// so a budget change moves this rather than leaving it a fiction.
    ceiling: f64,
}

/// One seat, and what it will do with the window.
#[derive(Debug, Serialize)]
struct Seat {
    employee_id: Uuid,
    slug: String,
    /// What a turn would actually run: the charter's preference, bounded by the
    /// intersected policy, through [`model_for`] — the one function that answers
    /// this in the workspace. `null` when the seat takes no turn.
    model: Option<ModelId>,
    /// How often it wakes, from its own `employee_initiative` row. `null` means
    /// it has none and never starts anything by itself.
    cadence_secs: Option<u64>,
    /// The intersected ceiling — platform ∧ tenant ∧ role ∧ employee — not the
    /// employee layer's own row.
    max_turns_per_day: u32,
    /// Turns over the window: the wakes the cadence produces, capped by the
    /// budget above.
    turns: u64,
    /// People this seat may lawfully approach for the first time over the
    /// window. See [`Forecast::new_contacts_ceiling`].
    new_contacts_ceiling: u64,
    /// Why this seat forecasts zero, in the same words the initiative loop would
    /// record. `null` when it is working.
    no_turns_because: Option<String>,
}

/// What the endpoint answers.
#[derive(Debug, Serialize)]
struct Forecast {
    /// The window, echoed, so nobody has to remember what they asked.
    days: u32,
    /// `api_key` or `cli` — which decides whether dollars mean anything.
    regime: ModelPath,
    /// What that regime means for the figures below, in one sentence.
    regime_note: &'static str,
    /// Reserved turns across every seat over the window.
    turns: u64,
    /// Model calls those turns make.
    model_calls: Range,
    /// What they bill, in USD. **`null` under `cli`**, where there is no
    /// per-token invoice to compute and a number would be a fiction with a
    /// currency symbol on it.
    cost_usd: Option<Range>,
    /// The most people this company may approach for the first time over the
    /// window, summed over the seats that can act.
    ///
    /// **A legal frontier, not a throughput target.** `max_new_contacts_per_day`
    /// is the cap the gate refuses an approach against; it is not a quota to
    /// fill and nothing here predicts how much of it gets used. A seat that
    /// takes no turn contributes zero because it approaches nobody.
    new_contacts_ceiling: u64,
    /// Every seat, working or not.
    seats: Vec<Seat>,
    /// **What this forecast does not know.** Read before quoting anything above.
    bounds: Vec<&'static str>,
}

// ---------------------------------------------------------------------------
// The bounds
// ---------------------------------------------------------------------------

/// The uncertainties every forecast carries, whatever the tenant.
///
/// Returned to the caller rather than kept in a doc comment, and that is the
/// point: `agentos_eval::cost` prints its `unmeasured` list beside its figures
/// on the same screen, and a forecast that dropped the list on the way through
/// HTTP would be a cleaner-looking version of the same lie. The first entry is
/// the one this endpoint adds by existing.
const BOUNDS: &[&str] = &[
    "the token counts are another company's. `agentos_domain::forecast::RECORDED` \
     is three passes of Orizn's own dry run, measured through `claude-opus-5` on the local \
     `claude` CLI. Your charters render a different prefix and your seats may run a different \
     model, so the per-call token figures are borrowed rather than yours — the largest \
     uncertainty in everything above, and it stays until your own company has been run and \
     counted",
    "turns are what the cadence produces, not what the work needs. An employee with nothing \
     due still wakes and still reserves its slot, and one whose action the gate refuses spends \
     the turn anyway. Nothing here says a turn produced anything",
    "±20% on every token count. There is no tokenizer in this workspace; `scoping::tokens` is \
     characters over a divisor and has never been checked against a real one",
    "prompt caching is not priced, and it only ever lowers the bill. `llm_anthropic` puts a \
     `cache_control` breakpoint on the system block and a prefix re-sent inside the window \
     bills at a tenth, so every dollar figure above is the uncached ceiling of its own row",
    "a new model snapshot can ship behind an unchanged model name. It moves every figure above \
     and no test in this workspace can see it happen",
    "`claude-sonnet-5` bills an introductory $2.00/$10.00 per million through 2026-08-31 \
     rather than the $3.00/$15.00 the rate card uses, so a seat on Sonnet is cheaper than \
     quoted until then. The standard rate is used deliberately: a bill quoted at a price with \
     days left on it is how a figure goes stale in public",
    "turns started by an incoming email, an A2A request or a webhook are not counted at all. \
     This is self-started work, because a cadence is a row this deployment holds and an \
     arrival rate is not",
];

/// The extra sentence a subscription earns.
const SUBSCRIPTION_BOUND: &str = "you are on this host's `claude` CLI, where no per-token invoice exists: the currency is a \
     monthly seat and the binding constraint is throughput. That is why `cost_usd` is null — a \
     dollar figure here would be the metered-API reading of an unmetered run. `model_calls` is \
     the figure a plan is sized against, and whether its terms permit an unattended fleet is a \
     question about that contract rather than about tokens";

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

/// `GET /v1/forecast?days=N`.
///
/// 404 when no model is connected, with the same detail `GET /v1/model` gives:
/// an unconnected tenant's employees cannot take a turn at all, so there is
/// nothing to forecast and a page of zeroes would read like a broken company
/// rather than a missing step.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<ForecastQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let days = match query.days {
        Some(days) if (1..=MAX_DAYS).contains(&days) => days,
        _ => {
            return Err(ApiError::bad_request(format!(
                "`days` is required and must be between 1 and {MAX_DAYS}. There is no default: \
                 the window is the question, and substituting one would answer a different one"
            )));
        }
    };

    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    // Whose credential a turn would be billed to, and by what path. Before the
    // seats, because it decides whether any of them can take a turn at all.
    // `.access`: the proof half. The sealed credential comes back in the same
    // row and is dropped here — a forecast reads which path pays, never what
    // pays.
    let Some(access) = model_access::load(&mut tx).await?.map(|c| c.access) else {
        tx.rollback().await?;
        return Err(ApiError::not_found().with_detail(
            "no model is connected for this tenant, so none of its employees can take a turn and \
             there is nothing to forecast. POST /v1/model with an Anthropic API key, or with \
             this host's claude CLI",
        ));
    };

    // Terminated employees are left out: that lifecycle is absorbing, so they
    // are gone rather than idle, and listing them forever is noise on a screen
    // whose whole job is "what will this company do". Draft and suspended seats
    // ARE listed, at zero, because a founder who has just built a company wants
    // to see the seat he has not released yet.
    //
    // No `WHERE tenant_id`: RLS is forced on both tables, and a hand-written
    // predicate would be a second place to forget it.
    //
    // ponytail: one query for the roster, then two reads per seat. A company is
    // a handful of employees, so this is a handful of round trips on a screen
    // shown once. If a tenant ever has hundreds, batch the policy and charter
    // loads — do not cache this, it is a reading of rows as they are now.
    let rows: Vec<(Uuid, String, Option<i64>, String)> = sqlx::query_as(
        "SELECT e.id, e.slug, i.interval_secs, e.lifecycle \
           FROM employees e \
           LEFT JOIN employee_initiative i ON i.employee_id = e.id \
          WHERE e.lifecycle <> $1::text \
          ORDER BY e.slug",
    )
    .bind(Lifecycle::Terminated.as_str())
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::from)?;

    let mut seats = Vec::with_capacity(rows.len());
    for (id, slug, interval_secs, lifecycle) in rows {
        seats.push(seat(&mut tx, id, slug, interval_secs, &lifecycle, days).await);
    }

    // Read-only, and awaited rather than dropped so the pooled connection goes
    // back deliberately.
    tx.rollback().await?;

    Ok(axum::Json(assemble(days, access.path, seats)).into_response())
}

/// One seat, resolved exactly as `loops::initiative` resolves it before a turn.
///
/// The cascade below is that function's own order, and the order is the answer:
/// each step is a reason the loop would refuse this employee a turn, so the seat
/// that comes out of it forecasts zero for the same cause and in the same words
/// the loop would record.
async fn seat(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    slug: String,
    interval_secs: Option<i64>,
    lifecycle: &str,
    days: u32,
) -> Seat {
    let employee_id = EmployeeId::from_uuid(id);
    let cadence_secs = interval_secs.and_then(|secs| u64::try_from(secs).ok());

    // Every early return is a seat that takes no turn. `zero` is what says so
    // once, so a branch added later cannot forget to blank the numbers.
    let zero = |why: String, model: Option<ModelId>, max_turns_per_day: u32| Seat {
        employee_id: id,
        slug: slug.clone(),
        model,
        cadence_secs,
        max_turns_per_day,
        turns: 0,
        new_contacts_ceiling: 0,
        no_turns_because: Some(why),
    };

    // 1. Lifecycle, first and separately from everything else — the same
    //    ordering `domain::initiative::initiative` argues for. A suspended
    //    employee whose deadline has passed must read as stopped, not as due.
    if lifecycle != Lifecycle::Active.as_str() {
        return zero(
            format!("this employee is {lifecycle}, and only an active one may act"),
            None,
            0,
        );
    }

    // 2. The cadence. No row, no self-started turn, ever — and this is the
    //    commonest reason a company that looks staffed does nothing.
    let Some(cadence_secs) = cadence_secs.filter(|secs| *secs > 0) else {
        return zero(
            "this employee has no cadence, so it never wakes on its own. \
             PUT /v1/employees/{id}/initiative sets one"
                .to_owned(),
            None,
            0,
        );
    };

    // 3. The policy. `assignment_for` tolerates an unreadable one and
    //    `reserve_a_turn` then refuses the turn outright, so the honest
    //    forecast for it is zero rather than a 500 that loses the other seats.
    let policy = match policy_store::load(tx, employee_id).await {
        Ok(policy) => policy,
        Err(err) => {
            tracing::warn!(employee_id = %id, error = %err, "no usable policy for this seat");
            return zero(
                "this employee's policy could not be loaded, so no turn can be reserved for it"
                    .to_owned(),
                None,
                0,
            );
        }
    };
    let limits = policy.limits();
    let max_turns_per_day = limits.max_turns_per_day;

    // 4. The charter. `Ok(None)` is an employee nobody has told what to do — a
    //    supported state, and `Outcome::NoCharter`.
    let charter = match Charter::load(tx, employee_id).await {
        Ok(Some(charter)) => charter,
        Ok(None) => {
            return zero(
                "this employee has no charter, so the loop has nothing to start it on".to_owned(),
                None,
                max_turns_per_day,
            );
        }
        Err(err) => {
            return zero(
                format!("this employee's charter could not be read ({})", err.code()),
                None,
                max_turns_per_day,
            );
        }
    };

    // 5. The gaps question, before any model call — `assignment_for` asks it in
    //    this position and answers `Outcome::Clarify`. A seat waiting on an
    //    answer takes no turn, and forecasting turns for it would be forecasting
    //    a company that is stopped.
    if let Err(question) = plan_of(&charter) {
        return zero(
            format!("its charter has an unanswered question: {question}"),
            None,
            max_turns_per_day,
        );
    }

    // 6. And the model. No fallback: `model_for` returns `None` for an empty
    //    intersection rather than choosing, because the expensive model would be
    //    a bill nobody authorised and the cheap one a policy nobody wrote.
    let Some(model) = model_for(Some(&policy), charter.model()) else {
        return zero(
            format!(
                "role {} asked for {} and `allowed_models` intersected to the empty set, so it \
                 cannot take a turn at all",
                charter.role(),
                charter.model(),
            ),
            None,
            max_turns_per_day,
        );
    };

    // The window, in turns. Computed over the whole window rather than per day
    // and multiplied: a seven-hour cadence is 3.43 wakes a day, and flooring
    // that daily would lose three turns a week to arithmetic.
    let wakes = u64::from(days) * SECONDS_PER_DAY / cadence_secs;
    let budget = u64::from(max_turns_per_day) * u64::from(days);
    let turns = wakes.min(budget);

    if turns == 0 {
        return zero(
            if budget == 0 {
                "its turn budget is zero, so it may not act on its own initiative".to_owned()
            } else {
                format!("its cadence is longer than the {days}-day window, so it never comes round")
            },
            Some(model),
            max_turns_per_day,
        );
    }

    Seat {
        employee_id: id,
        slug,
        model: Some(model),
        cadence_secs: Some(cadence_secs),
        max_turns_per_day,
        turns,
        // The legal frontier, over the window. Not bounded by `turns` on
        // purpose: a turn may approach more than one person through the
        // ordinary `send_email` path, so the daily cap is the only honest
        // ceiling and taking the minimum with turns would understate what the
        // policy permits.
        new_contacts_ceiling: u64::from(limits.max_new_contacts_per_day) * u64::from(days),
        no_turns_because: None,
    }
}

/// The seats, summed into the answer.
///
/// Split out from the handler because it is the whole arithmetic and it is pure:
/// `the_bill_is_the_sum_of_the_seats_and_the_cli_gets_no_bill` can put a company
/// through it without a database, which is what lets the money be checked by
/// hand against the rate card rather than only end to end.
fn assemble(days: u32, path: ModelPath, seats: Vec<Seat>) -> Forecast {
    let turns: u64 = seats.iter().map(|seat| seat.turns).sum();
    let ceiling_calls_per_turn = f64::from(agentos_app::turn::Budgets::default().max_turns);

    // Model calls: one number times a rate, over the same three samples the
    // dollars use, so the two rows cannot disagree about which run they came
    // from.
    let calls = |rate: f64| (turns as f64 * rate).round();
    let (calls_low, calls_high) = spread(|s| calls(s.calls_per_turn));
    let model_calls = Range {
        floor: calls(FLOOR_CALLS_PER_TURN),
        low: calls_low,
        high: calls_high,
        ceiling: calls(ceiling_calls_per_turn),
    };

    // The bill: a sum over seats, each at its own model's rates. Not the summed
    // turn count multiplied once — that was right while one model served every
    // seat and is a category error now, and it is the mistake
    // `agentos_eval::cost::company_usd` was rewritten to stop making.
    let company = |sample: Sample, rate: f64| {
        cents(
            seats
                .iter()
                .filter_map(|seat| Some((seat.model?, seat.turns)))
                .map(|(model, turns)| sample.usd(model, rate, turns as f64))
                .sum(),
        )
    };
    // `None` on the CLI path, and the arithmetic is simply not run. A
    // subscription has no per-token invoice to compute — see the module docs
    // and `rate_card`. The number would exist arithmetically and mean nothing.
    let cost_usd = (!path.is_host()).then(|| {
        let (low, high) = spread(|s| company(s, s.calls_per_turn));
        Range {
            floor: spread(|s| company(s, FLOOR_CALLS_PER_TURN)).0,
            low,
            high,
            ceiling: spread(|s| company(s, ceiling_calls_per_turn)).1,
        }
    });

    let mut bounds = BOUNDS.to_vec();
    if path.is_host() {
        bounds.push(SUBSCRIPTION_BOUND);
    }

    Forecast {
        days,
        regime: path,
        regime_note: match path {
            ModelPath::ApiKey => {
                "every token below is billed to the key this tenant connected, at published list \
                 prices"
            }
            ModelPath::Cli => {
                "this tenant runs the host's claude CLI on a subscription, so the unit is \
                 throughput and not money"
            }
        },
        turns,
        model_calls,
        cost_usd,
        new_contacts_ceiling: seats.iter().map(|seat| seat.new_contacts_ceiling).sum(),
        seats,
        bounds,
    }
}

/// Dollars, to the cent.
///
/// Two decimals and no more. The token counts behind this carry ±20%, so a
/// third would be precision the inputs do not have — and rounding here rather
/// than in a front end means every reader of this endpoint gets the same figure.
fn cents(usd: f64) -> f64 {
    (usd * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agentos_app::rolepack_service;
    use agentos_domain::forecast::{RECORDED, rate_card};
    use agentos_domain::ids::TenantId;
    use agentos_domain::initiative::Cadence;
    use agentos_domain::model_access::ModelAccess;
    use agentos_domain::policy::PolicyLimits;
    use agentos_store::initiative as initiative_store;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use chrono::Utc;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    /// A working seat, with the numbers stated rather than derived, so a test
    /// below can do the arithmetic by hand.
    fn working(slug: &str, model: ModelId, turns: u64, contacts: u64) -> Seat {
        Seat {
            employee_id: Uuid::now_v7(),
            slug: slug.to_owned(),
            model: Some(model),
            cadence_secs: Some(3_600),
            max_turns_per_day: 24,
            turns,
            new_contacts_ceiling: contacts,
            no_turns_because: None,
        }
    }

    /// **The bill is a sum over seats at their own models, and a subscription
    /// gets none at all.**
    ///
    /// Both halves in one test because they are the same claim from two sides:
    /// the arithmetic is per seat, and whether it is published at all is per
    /// regime.
    #[test]
    fn the_bill_is_the_sum_of_the_seats_and_the_cli_gets_no_bill() {
        let seats = vec![
            working("sdr", ModelId::Haiku45, 100, 5),
            working("books", ModelId::Opus5, 10, 0),
        ];
        let metered = assemble(7, ModelPath::ApiKey, seats);

        assert_eq!(metered.turns, 110);
        assert_eq!(metered.new_contacts_ceiling, 5);

        // By hand, off the sample the low end came from, at that sample's own
        // rate. If this drifts, something has stopped pricing seats separately.
        let bill = metered.cost_usd.expect("an api-key tenant gets a bill");
        let by_hand = |sample: Sample| {
            let seat = |model: ModelId, turns: f64| {
                let (per_m_in, per_m_out) = rate_card(model);
                sample.calls_per_turn
                    * turns
                    * (sample.input_tokens_per_call * per_m_in
                        + sample.output_tokens_per_call * per_m_out)
                    / 1_000_000.0
            };
            seat(ModelId::Haiku45, 100.0) + seat(ModelId::Opus5, 10.0)
        };
        let hand: Vec<f64> = RECORDED.iter().map(|s| by_hand(*s)).collect();
        let lo = hand.iter().cloned().fold(f64::MAX, f64::min);
        let hi = hand.iter().cloned().fold(f64::MIN, f64::max);
        assert!((bill.low - cents(lo)).abs() < 1e-9, "{bill:?}");
        assert!((bill.high - cents(hi)).abs() < 1e-9, "{bill:?}");

        // And the range is stated the right way round, which is the property
        // `docs/ORIZN.md` published a floor as an estimate for want of.
        assert!(bill.floor <= bill.low, "{bill:?}");
        assert!(bill.low <= bill.high, "{bill:?}");
        assert!(bill.high <= bill.ceiling, "{bill:?}");
        assert!(
            bill.ceiling > bill.floor * 9.0,
            "the ceiling is ten calls a turn against the floor's one; {bill:?}"
        );

        // The same company on a subscription: same work, no invoice.
        let subscribed = assemble(
            7,
            ModelPath::Cli,
            vec![
                working("sdr", ModelId::Haiku45, 100, 5),
                working("books", ModelId::Opus5, 10, 0),
            ],
        );
        assert!(
            subscribed.cost_usd.is_none(),
            "a dollar figure for a tenant with no per-token invoice is a fiction"
        );
        assert_eq!(
            subscribed.model_calls.high, metered.model_calls.high,
            "the throughput is the same company either way"
        );
        assert!(
            subscribed.bounds.contains(&SUBSCRIPTION_BOUND),
            "the caller is not told why the money is missing"
        );
        assert!(!metered.bounds.contains(&SUBSCRIPTION_BOUND));
    }

    /// A seat that takes no turn contributes nothing to any figure — including
    /// the contact ceiling, because it approaches nobody.
    #[test]
    fn a_seat_that_never_wakes_costs_nothing_and_approaches_nobody() {
        let stopped = Seat {
            model: None,
            turns: 0,
            new_contacts_ceiling: 0,
            no_turns_because: Some("no cadence".to_owned()),
            ..working("idle", ModelId::Fable5, 0, 0)
        };
        let alone = assemble(7, ModelPath::ApiKey, vec![stopped]);

        assert_eq!(alone.turns, 0);
        assert_eq!(alone.new_contacts_ceiling, 0);
        assert_eq!(alone.model_calls.ceiling, 0.0);
        let bill = alone.cost_usd.expect("still metered");
        assert_eq!(bill.high, 0.0, "an idle company bills nothing");

        // And adding it to a working company changes no figure at all.
        let busy = assemble(
            7,
            ModelPath::ApiKey,
            vec![working("sdr", ModelId::Opus5, 50, 3)],
        );
        let both = assemble(
            7,
            ModelPath::ApiKey,
            vec![
                working("sdr", ModelId::Opus5, 50, 3),
                Seat {
                    model: None,
                    turns: 0,
                    new_contacts_ceiling: 0,
                    no_turns_because: Some("no cadence".to_owned()),
                    ..working("idle", ModelId::Fable5, 0, 0)
                },
            ],
        );
        assert_eq!(
            both.cost_usd.expect("metered").high,
            busy.cost_usd.expect("metered").high,
            "a seat with no model must not be priced at one"
        );
        assert_eq!(both.turns, busy.turns);
    }

    /// The list of what this does not know travels with the answer.
    ///
    /// Not decoration: `agentos_eval::cost` prints its uncertainties beside its
    /// figures, and a forecast that dropped them on the way through HTTP would
    /// be a tidier version of the same lie.
    #[test]
    fn the_answer_carries_what_it_does_not_know() {
        let forecast = assemble(
            2,
            ModelPath::ApiKey,
            vec![working("sdr", ModelId::Opus5, 8, 2)],
        );
        assert!(forecast.bounds.len() >= 7, "{:?}", forecast.bounds);
        // The one this endpoint adds by existing, and the one a reader most
        // needs: these token counts were measured on somebody else's company.
        assert!(
            forecast
                .bounds
                .iter()
                .any(|bound| bound.contains("another company")),
            "the borrowed token counts are not declared"
        );
        assert!(
            forecast.bounds.iter().any(|bound| bound.contains("±20%")),
            "the estimator's bound is not declared"
        );
        // And nothing anywhere claims a chance of success.
        let body = serde_json::to_string(&forecast).expect("serialize");
        for banned in ["success", "probability", "likelihood", "confidence"] {
            assert!(
                !body.contains(banned),
                "this endpoint published a `{banned}` figure, which nobody has measured"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Against a real database: the seats, the isolation, and the refusals
    // -----------------------------------------------------------------------

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// An hour, which at `days=2` is 48 wakes — exactly the turn budget below,
    /// so the two bounds meet and either one moving is visible.
    const HOURLY: u64 = 3_600;

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the forecast route needs a real Postgres");
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

        /// The tenant has connected a model. Written through the store the
        /// connect route writes through, so the row is the one production reads.
        async fn connect(&self, tenant: TenantId, path: ModelPath) {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            model_access::save(
                &mut tx,
                &ModelAccess {
                    path,
                    model: ModelId::Opus5,
                    verified_at: Utc::now(),
                },
                // A stand-in envelope for the `api_key` path: 0050's CHECK is a
                // biconditional, so a row on that path has to carry one. Never
                // opened — this route reads `path`, never a credential.
                (path == ModelPath::ApiKey).then_some(&b"sealed-fixture"[..]),
                Utc::now(),
            )
            .await
            .expect("save the connection");
            tx.commit().await.expect("commit");
        }

        /// This tenant's limits, as a `tenant` policy layer — the same shape
        /// `routes::turns`'s tests use, and for the same reason: the platform
        /// ceiling is one row for the whole database and must not be rewritten
        /// under a test running beside this one.
        async fn limits(&self, tenant: TenantId, turns: u32, contacts: u32) {
            policy_store::install(
                &self.db,
                tenant,
                policy_store::Scope::Tenant,
                &PolicyLimits {
                    max_turns_per_day: turns,
                    max_new_contacts_per_day: contacts,
                    allowed_models: ModelId::ALL.into_iter().collect(),
                    ..PolicyLimits::default()
                },
            )
            .await
            .expect("install the tenant layer");
        }

        /// One seat: a row, optionally a charter, optionally a cadence.
        async fn hire(
            &self,
            tenant: TenantId,
            slug: &str,
            lifecycle: Lifecycle,
            charter: Option<Charter>,
            cadence_secs: Option<u64>,
        ) -> Uuid {
            let id = Uuid::now_v7();
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 VALUES ($1, $2, $3, $3, $4::text)",
            )
            .bind(id)
            .bind(tenant.as_uuid())
            .bind(slug)
            .bind(lifecycle.as_str())
            .execute(&mut **tx)
            .await
            .expect("insert employee");
            if let Some(charter) = charter {
                charter
                    .save(&mut tx, EmployeeId::from_uuid(id), Utc::now())
                    .await
                    .expect("save the charter");
            }
            if let Some(secs) = cadence_secs {
                initiative_store::set(
                    &mut tx,
                    EmployeeId::from_uuid(id),
                    Cadence::every(Duration::from_secs(secs)).expect("cadence"),
                    Utc::now(),
                )
                .await
                .expect("set the cadence");
            }
            tx.commit().await.expect("commit");
            id
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'forecast-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// A charter with nothing missing, so `plan_of` answers with a plan.
    fn answered() -> Charter {
        Charter::Support {
            objective: rolepack_service::Support {
                product: "the entry-requirements API".to_owned(),
                first_response_hours: 8,
                escalate_to: Some("founder".to_owned()),
            },
        }
    }

    /// The same charter with the product left blank — one of
    /// `rolepack_service::Support::gaps`, which makes `plan_of` a question.
    fn unanswered() -> Charter {
        Charter::Support {
            objective: rolepack_service::Support {
                product: String::new(),
                first_response_hours: 0,
                escalate_to: None,
            },
        }
    }

    fn seat_named<'a>(body: &'a Value, slug: &str) -> &'a Value {
        body["seats"]
            .as_array()
            .expect("seats")
            .iter()
            .find(|seat| seat["slug"] == slug)
            .unwrap_or_else(|| panic!("no seat named {slug} in {body}"))
    }

    // -----------------------------------------------------------------------

    /// **The screen.** A founder asks what two days will do and gets his own
    /// company's answer — and another tenant holding a valid key gets his own,
    /// which is empty.
    #[tokio::test]
    async fn a_founder_sees_his_own_company_and_never_another_tenants() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.connect(h.a, ModelPath::ApiKey).await;
        h.connect(h.b, ModelPath::ApiKey).await;
        h.limits(h.a, 24, 5).await;
        // **Two seats, and the two bounds bind in opposite directions.** A slow
        // one whose cadence runs out before its budget does, and a fast one
        // whose budget stops it long before its cadence would. If both numbers
        // agreed, an endpoint that quoted the turn budget as the forecast — the
        // ceiling `agentos_eval::cost` warns about — would pass this test.
        h.hire(
            h.a,
            "slow",
            Lifecycle::Active,
            Some(answered()),
            Some(2 * HOURLY),
        )
        .await;
        h.hire(h.a, "fast", Lifecycle::Active, Some(answered()), Some(300))
            .await;

        let (status, body) = h.get("/v1/forecast?days=2", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        assert_eq!(body["days"], 2);
        assert_eq!(body["regime"], "api_key");
        // 12 wakes a day against a budget of 24: the cadence binds.
        assert_eq!(seat_named(&body, "slow")["turns"], 24, "{body}");
        // 288 wakes a day against the same budget: the budget binds.
        assert_eq!(seat_named(&body, "fast")["turns"], 48, "{body}");
        assert_eq!(body["turns"], 72, "{body}");
        // The floor is one model call per turn, by definition.
        assert_eq!(body["model_calls"]["floor"], 72.0);
        assert_eq!(body["model_calls"]["ceiling"], 720.0, "ten calls a turn");
        // The legal frontier, over the window: 5 a day, two days, two seats.
        // Not the turn count, which is an order of magnitude larger.
        assert_eq!(body["new_contacts_ceiling"], 20, "{body}");

        let seat = seat_named(&body, "slow");
        assert!(seat["model"].is_string(), "{seat}");
        assert_eq!(seat["cadence_secs"], 7_200);
        assert_eq!(seat["max_turns_per_day"], 24);
        assert_eq!(seat["no_turns_because"], Value::Null, "{seat}");

        // A bill, and a range stated the right way round.
        let bill = &body["cost_usd"];
        let f = |key: &str| bill[key].as_f64().unwrap_or_else(|| panic!("{bill}"));
        assert!(f("floor") > 0.0, "{bill}");
        assert!(f("floor") <= f("low") && f("low") <= f("high") && f("high") <= f("ceiling"));

        // B holds a valid credential, a connected model and no employees. It
        // sees its own empty company — never A's seat.
        let (status, theirs) = h.get("/v1/forecast?days=2", SECRET_B).await;
        assert_eq!(status, StatusCode::OK, "{theirs}");
        assert_eq!(theirs["turns"], 0);
        assert_eq!(theirs["seats"].as_array().expect("seats").len(), 0);
        assert!(
            !theirs.to_string().contains("slow"),
            "another tenant's seat leaked into this forecast: {theirs}"
        );

        h.teardown().await;
    }

    /// **Every reason the initiative loop would refuse a turn shows up as a
    /// zero with the reason attached**, rather than as turns the company will
    /// never take.
    ///
    /// This is the difference between a forecast and a ceiling, and each arm is
    /// a state a real company is in five minutes after it is built.
    #[tokio::test]
    async fn every_seat_the_loop_would_refuse_is_reported_at_zero_with_its_reason() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.connect(h.a, ModelPath::ApiKey).await;
        h.limits(h.a, 24, 5).await;

        h.hire(
            h.a,
            "works",
            Lifecycle::Active,
            Some(answered()),
            Some(HOURLY),
        )
        .await;
        // Chartered, scheduled — and its charter asks a question, so the loop
        // answers `Outcome::Clarify` and spends nothing.
        h.hire(
            h.a,
            "asking",
            Lifecycle::Active,
            Some(unanswered()),
            Some(HOURLY),
        )
        .await;
        // Chartered and scheduled and not released: only an active employee acts.
        h.hire(
            h.a,
            "drafted",
            Lifecycle::Draft,
            Some(answered()),
            Some(HOURLY),
        )
        .await;
        // Chartered, active, and nobody gave it a rhythm.
        h.hire(
            h.a,
            "unscheduled",
            Lifecycle::Active,
            Some(answered()),
            None,
        )
        .await;
        // Scheduled, active, and nobody told it what it is for.
        h.hire(h.a, "aimless", Lifecycle::Active, None, Some(HOURLY))
            .await;

        let (status, body) = h.get("/v1/forecast?days=2", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // One working seat out of five, and the totals count only it.
        assert_eq!(body["turns"], 48, "{body}");
        assert_eq!(body["new_contacts_ceiling"], 10, "{body}");
        assert_eq!(body["seats"].as_array().expect("seats").len(), 5);

        for (slug, expected) in [
            ("asking", "unanswered question"),
            ("drafted", "draft"),
            ("unscheduled", "no cadence"),
            ("aimless", "no charter"),
        ] {
            let seat = seat_named(&body, slug);
            assert_eq!(seat["turns"], 0, "{seat}");
            assert_eq!(seat["new_contacts_ceiling"], 0, "{seat}");
            let why = seat["no_turns_because"].as_str().unwrap_or_default();
            assert!(
                why.contains(expected),
                "{slug} says {why:?}, which does not name why the loop refuses it"
            );
        }
        assert_eq!(seat_named(&body, "works")["no_turns_because"], Value::Null);

        h.teardown().await;
    }

    /// A subscription gets throughput and no invoice, and an unconnected tenant
    /// is told to connect rather than shown a page of zeroes.
    #[tokio::test]
    async fn a_subscription_gets_no_invoice_and_an_unconnected_tenant_gets_a_next_step() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.limits(h.a, 24, 5).await;
        h.hire(
            h.a,
            "support",
            Lifecycle::Active,
            Some(answered()),
            Some(HOURLY),
        )
        .await;

        // Nothing connected yet. The employees cannot take a turn at all, so
        // zeroes would read like a broken company rather than a missing step.
        let (status, body) = h.get("/v1/forecast?days=7", SECRET_A).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(
            body["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("POST /v1/model"),
            "{body}"
        );

        // On the host's CLI: same work, and no money at all.
        h.connect(h.a, ModelPath::Cli).await;
        let (status, body) = h.get("/v1/forecast?days=7", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["regime"], "cli");
        assert_eq!(
            body["cost_usd"],
            Value::Null,
            "a per-token bill for a subscription is a fiction: {body}"
        );
        assert!(body["model_calls"]["high"].as_f64().expect("calls") > 0.0);
        assert!(
            body["bounds"]
                .as_array()
                .expect("bounds")
                .iter()
                .any(|bound| bound.as_str().unwrap_or_default().contains("monthly seat")),
            "the caller is not told why there is no bill: {body}"
        );

        h.teardown().await;
    }

    /// The window is the question, so it is required and bounded — never
    /// defaulted, and never extrapolated past the shelf life of its own inputs.
    #[tokio::test]
    async fn the_window_is_required_and_bounded() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.connect(h.a, ModelPath::ApiKey).await;

        for uri in [
            "/v1/forecast",
            "/v1/forecast?days=0",
            "/v1/forecast?days=91",
            "/v1/forecast?days=a-week",
        ] {
            let (status, body) = h.get(uri, SECRET_A).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} answered {body}");
        }

        // The three the founder actually names all work.
        for days in [2, 7, 30] {
            let (status, body) = h.get(&format!("/v1/forecast?days={days}"), SECRET_A).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["days"], days);
        }

        h.teardown().await;
    }
}
