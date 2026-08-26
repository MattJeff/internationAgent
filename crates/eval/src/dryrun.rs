//! **The dry run.** Orizn, stood up for real, working against the real model.
//!
//! ```sh
//! createdb orizn_dryrun                 # EMPTY, and a new one for every run
//! DATABASE_URL=postgres://postgres:postgres@localhost:5443/orizn_dryrun \
//!   cargo run -p agentos-eval --features live-orizn -- --dry-run 3
//! ```
//!
//! Everything else in this crate measures a pure function or asks the model
//! five one-shot questions. This asks the only question none of them can: put
//! an employee in a company, give it a real objective, and let it take real
//! turns — what does it actually *do*?
//!
//! # Why a feature and not a runtime skip
//!
//! `scripts/test.sh`'s guard 2 fails the build when a test prints `SKIP:`,
//! because ~34 tests in this workspace skip themselves without a database and a
//! green run of nothing is the one failure mode nobody notices. This needs a
//! database *and* a logged-in `claude` binary *and* about ten minutes, so it
//! opts out of the default build entirely — `#[cfg(feature = "live-orizn")]`
//! means it is **absent** rather than present and quietly passing. Same shape,
//! same reasoning, as `crates/app`'s `live-orizn` feature.
//!
//! # What is real here and what is not
//!
//! Real: the tenant, the ceiling and the five role layers, read from
//! `docs/orizn-ceiling.json` and `docs/orizn-roles/*.json` — the operator's own
//! documents, through `store::policy`'s own installers. Real: the org chart,
//! from `docs/orizn-org.json`. Real: the provisioning engine, the Policy Gate,
//! `app::turn::Turn`, and the model.
//!
//! Not real, and named so nobody has to guess: the org chart is applied through
//! `store::org` rather than through `POST /v1/org`, because that route lives in
//! a binary crate with no library target and copying it here would be a second
//! copy of the company to keep in step. Every row it writes is written here.
//! The providers behind `Effects` are mocks — email, telephony, browser,
//! payments — which is the point: the model is the part that has never been
//! exercised.
//!
//! # What it records, and why that is the deliverable
//!
//! Not a score. A transcript: every tool the model reached for, the arguments
//! it passed, and what the gate said back — plus a tally of everything that
//! went wrong, because a dry run that reports "it worked" has not been looked
//! at hard enough. `Turn` hands a refusal back to the model as a failed tool
//! result rather than raising, so the failures are *in* the transcript and this
//! module's whole job is to not throw them away.
//!
//! # Structural, and sampled. They are not the same thing and are not mixed
//!
//! For a year this was a transcript somebody read and wrote prose about, so two
//! runs a week apart could not be compared and nothing recorded what a good run
//! looked like. [`verdict`] is the fix, and the split it draws is the whole
//! idea:
//!
//! * **Structural** — [`Truth::Correct`], and the process exits non-zero. The
//!   loop ran; at least one turn survived the shim; a tool was called; every
//!   tool call except the ones the budget cut off got a ruling. None of these is
//!   a fact about the model. A turn that produces zero tool calls in nine
//!   attempts is not a sample, it is a broken system — that was true three days
//!   ago and nothing automated noticed.
//! * **Sampled** — [`Truth::Characterises`], reported and never gated. How many
//!   calls a turn took, how many tokens they weighed, what that comes to a
//!   month, and **how often the shim dropped a call**. A threshold on any of
//!   these is a threshold on a coin flip, and a flaky test is a deleted test.
//!
//! The shim's failure rate began on the structural side and was moved, which is
//! worth stating because it is the mistake this split is easiest to make.
//! `cli_not_json` is a documented, expected behaviour of `llm_cli` — its own
//! module docs put a number on it, and `toolchoice::Chose::Malformed` already
//! reports shim failures as a figure rather than gating on one. Gating on it
//! would have contradicted a decision this repository had already taken, and
//! would have made a contended laptop look like a broken employee OS. What
//! survived onto the structural side is the weaker, true claim: **something has
//! to have run**, or the averages are arithmetic over calls that never returned.
//! Only [`Ran::intact`] turns are billed, for the same reason.
//!
//! The sampled half is printed a second time as a `RECORD` block, ready to paste
//! into [`crate::cost::RECORDED`] beside the digest that says which company it
//! measured. That is the only route a live number takes into this repository —
//! and it is withheld entirely when a structural row failed.
//!
//! # `Failed` carries no transcript, so the transcript is taken upstream
//!
//! `Turn::run`'s error carries the bill and not the conversation, so a run
//! killed by its budget would report tokens and no story — and a runaway
//! employee is exactly the run whose story matters. So [`Recorder`] wraps the
//! `Llm` and keeps every request and every response. What it sees is a superset
//! of `Finished::messages` and it survives every error path.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentos_app::effects::Effects;
use agentos_app::gate::{PolicyGate, Principal};
use agentos_app::provisioning::{EngineConfig, ProvisioningEngine};
use agentos_app::turn::{Context, Turn};
use agentos_app::vertical::Charter;
use agentos_app::{inbound, mocks};
use agentos_domain::action::Domain;
use agentos_domain::employee::{Employee, Lifecycle};
use agentos_domain::ids::{EmployeeId, Slug, TenantId};
use agentos_domain::money::{Currency, Money};
use agentos_providers::ProviderError;
use agentos_providers::llm::{Content, Llm, LlmRequest, LlmResponse, Message, Usage};
use agentos_providers::llm_cli::CliLlm;
use agentos_store::db::Db;
use agentos_store::{employee as employee_store, org, policy, spend};
use async_trait::async_trait;
use chrono::Utc;
use tokio_util::sync::CancellationToken;

use crate::cost::{self, Sample, TURN_BRIEF, charters, limits};
use crate::scoping::{Weighed, weigh};
use crate::{Row, Surface, Truth};

/// Passed to the CLI untouched. Same default as the held-out set.
pub use crate::toolchoice::DEFAULT_MODEL;

/// A mock deployment's envelope key. Real crypto over a throwaway key: the
/// identity step seals a private key with it and would otherwise not run.
const MASTER_KEY: &str = "dryrun-master-key-0123456789abcdef";

// ---------------------------------------------------------------------------
// The model, with a tape recorder on it
// ---------------------------------------------------------------------------

/// One round trip to the model, kept whole.
struct Call {
    /// Wall clock, which is a product decision and not a footnote: a turn that
    /// takes ninety seconds is a different product from one that takes three.
    elapsed: Duration,
    /// The schemas this call was offered — the taint wire's output, per call.
    offered: Vec<String>,
    /// What the prompt weighs under `scoping`'s estimator. The CLI's own
    /// numbers cannot answer this: it reports its *own* system prompt.
    weighed: Weighed,
    /// The last message that went in. Carries the previous call's tool results,
    /// which is how the gate's answers get into the transcript.
    last_in: Option<Message>,
    /// The model's turn, or the provider code that came back instead.
    out: Result<LlmResponse, &'static str>,
}

/// A [`Llm`] that keeps the tape. Everything else is [`CliLlm`]'s.
struct Recorder {
    inner: CliLlm,
    calls: Mutex<Vec<Call>>,
}

#[async_trait]
impl Llm for Recorder {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, ProviderError> {
        let offered = req.tools.iter().map(|tool| tool.name.clone()).collect();
        let weighed = weigh(&req);
        let last_in = req.messages.last().cloned();

        let started = Instant::now();
        let out = self.inner.complete(req).await;

        self.calls.lock().expect("recorder").push(Call {
            elapsed: started.elapsed(),
            offered,
            weighed,
            last_in,
            out: out.clone().map_err(|err| err.code()),
        });
        out
    }
}

// ---------------------------------------------------------------------------
// The company
// ---------------------------------------------------------------------------

/// One row of `docs/orizn-org.json`, plus what this seat is being asked to do.
struct Seat {
    /// Team slug, `role_name` and role pack name — one string, see the runbook.
    team: &'static str,
    /// The employee slug seated in it.
    head: &'static str,
    /// The team's human-readable name.
    name: &'static str,
    /// The title on the reporting line.
    title: &'static str,
    /// `true` for the seat every other seat reports to.
    root: bool,
}

/// The chart, in `docs/orizn-org.json`'s order. Every row's `reports_to` is
/// `founder`, which is the whole shape of Orizn's chart.
const SEATS: &[Seat] = &[
    Seat {
        team: "direction",
        head: "founder",
        name: "Direction",
        title: "CEO / founder",
        root: true,
    },
    Seat {
        team: "sales-development",
        head: "sdr",
        name: "Commercial",
        title: "Sales Development",
        root: false,
    },
    Seat {
        team: "customer-success",
        head: "support",
        name: "Clients",
        title: "Customer Success",
        root: false,
    },
    Seat {
        team: "growth",
        head: "acquisition",
        name: "Growth",
        title: "Head of Growth",
        root: false,
    },
    Seat {
        team: "finance",
        head: "books",
        name: "Finance",
        title: "Finance",
        root: false,
    },
];

/// The company, once it is standing.
struct Company {
    db: Db,
    tenant: TenantId,
    /// `(slug, employee id, team id)`, in [`SEATS`] order.
    seats: Vec<(&'static str, EmployeeId, uuid::Uuid)>,
}

impl Company {
    fn id_of(&self, head: &str) -> EmployeeId {
        self.seats
            .iter()
            .find(|(slug, ..)| *slug == head)
            .map(|(_, id, _)| *id)
            .expect("a seat this document defines")
    }
}

/// What the two unique-constraint panics in [`stand_up`] actually mean.
///
/// **Found by running the dry run three times, which nobody had ever done.**
/// This module's own doc comment used to promise that re-running against the
/// same database "adds a company rather than replacing one". It does not, and it
/// cannot, for two independent reasons:
///
/// * `tenants.slug` is UNIQUE and the slug is `orizn`, from the runbook;
/// * the mock providers mint sequential external ids — `dom_0001`,
///   `PN0000000000000001` — from **process-local** state, so a second
///   invocation mints the same ids and collides on
///   `employee_resources_provider_external_id_key`.
///
/// The second is not fixable here and should not be: the mocks are correct to be
/// deterministic, and a dry run that renamed its own seats to dodge a constraint
/// would be measuring a company nobody deployed. So the requirement is a fresh
/// database per invocation, and this string is what says so at the moment it
/// matters instead of a `Conflict(...)` forty frames down.
const EMPTY_DATABASE: &str = "this needs an EMPTY database and this one already holds a dry run — \
     `createdb orizn_dryrun_2` and point DATABASE_URL at it. Two runs cannot share \
     a database: the tenant slug is unique and the mock providers mint the same \
     external ids in every process";

/// Steps 2 through 6 of `docs/ORIZN.md`, in order, against a real database.
async fn stand_up(db: Db) -> Company {
    let now = Utc::now();
    let tenant = TenantId::new_v7(now);
    let domain = Domain::parse("agents.orizn.app").expect("the org document's domain");

    // 2. the ceiling. Before this the gate refuses everything, which is the
    //    safe direction and the first thing an operator sees.
    policy::install_ceiling(&db, &limits("orizn-ceiling.json"), "orizn dry run")
        .await
        .expect("install the ceiling");

    // 3. the tenant — and the active policy version its layers hang off.
    policy::create_tenant(&db, tenant, "orizn", "Orizn")
        .await
        .expect(EMPTY_DATABASE);

    // 4. the org chart. `POST /v1/org`'s two passes: every seat before any
    //    line, because a `reports_to` must name a head of this same document.
    let mut seats = Vec::new();
    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
    for seat in SEATS {
        let slug = Slug::parse(seat.team).expect("team slug");
        let team_id = org::create_team(&mut tx, &slug, seat.name)
            .await
            .expect("create team");
        let head = Slug::parse(seat.head).expect("head slug");
        let employee = Employee::new(EmployeeId::new_v7(now), tenant, head, domain.clone(), now);
        employee_store::insert(&mut tx, &employee)
            .await
            .expect("hire the head");
        org::set_member(&mut tx, employee.id(), team_id, None)
            .await
            .expect("seat the head");
        seats.push((seat.head, employee.id(), team_id));
    }
    let root = seats
        .iter()
        .zip(SEATS)
        .find(|(_, seat)| seat.root)
        .map(|((_, id, _), _)| *id)
        .expect("a chart has a root");
    for ((_, id, _), seat) in seats.iter().zip(SEATS) {
        let manager = (!seat.root).then_some(root);
        org::set_position(&mut tx, *id, Some(seat.title), manager)
            .await
            .expect("draw the reporting line");
    }
    tx.commit().await.expect("commit the chart");

    // The provisioning loop's work, in this process: converge every resource,
    // then draft → active. An employee the gate refuses every action for is a
    // row, not a seat.
    let engine = ProvisioningEngine::new(
        db.clone(),
        mocks::adapters(MASTER_KEY),
        EngineConfig::default(),
    );
    for (_, id, _) in &seats {
        engine.converge(tenant, *id).await.expect(EMPTY_DATABASE);
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let stored = employee_store::load(&mut tx, *id).await.expect("load");
        let mut employee = stored.employee;
        employee
            .set_lifecycle(Lifecycle::Active, Utc::now())
            .expect("draft -> active");
        employee_store::update(&mut tx, &employee, stored.version)
            .await
            .expect("activate");
        tx.commit().await.expect("commit activation");
    }

    // 5. the five role layers, one document and one policy version each.
    for seat in SEATS {
        policy::install_layer(
            &db,
            tenant,
            policy::Scope::Role(seat.team),
            &limits(&format!("orizn-roles/{}.json", seat.team)),
            "orizn dry run",
        )
        .await
        .unwrap_or_else(|err| panic!("install the {} layer: {err}", seat.team));
    }

    // 6. the two rows a spend row does not give finance. Without both, a
    //    payment passes the gate and is refused at the reservation.
    let finance = seats
        .iter()
        .find(|(slug, ..)| *slug == "books")
        .expect("the finance seat");
    let usd = |minor| Money::new(minor, Currency::Usd).expect("usd");
    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
    org::set_budget(&mut tx, finance.2, usd(100_000))
        .await
        .expect("team budget");
    spend::set_caps(
        &mut tx,
        finance.1,
        spend::SpendCaps::new(
            usd(100_000),
            usd(50_000),
            std::num::NonZeroU32::new(2).expect("two"),
        )
        .expect("caps"),
    )
    .await
    .expect("spend caps");
    tx.commit().await.expect("commit finance");

    Company { db, tenant, seats }
}

// ---------------------------------------------------------------------------
// One run
// ---------------------------------------------------------------------------

/// What one seat's turn came to.
struct Ran {
    seat: &'static str,
    role: &'static str,
    /// `Ok` is the stop reason; `Err` is the code that ended it early.
    ended: Result<&'static str, String>,
    usage: Usage,
    wall: Duration,
    calls: Vec<Call>,
}

/// Assemble one employee exactly as `loops::initiative::take_turn` does, and
/// run it.
///
/// The one difference from the running system is the vertical step, which is
/// omitted: it needs a sourcing round or a sales pipeline in the database, and
/// what it contributes to the turn is one extra trusted sentence. Everything
/// that decides what the employee may *do* — principal, gate, effects, prompt,
/// schemas — is the same call in the same order.
async fn take_turn(company: &Company, seat: &'static str, charter: &Charter, model: &str) -> Ran {
    let employee_id = company.id_of(seat);
    let principal = Principal::employee(company.tenant, employee_id);

    let mut tx = company
        .db
        .tenant_tx(company.tenant)
        .await
        .expect("tenant tx");
    let stored = employee_store::load(&mut tx, employee_id)
        .await
        .expect("load the seat");
    // Through the store and back, because the objective's JSON round trip is
    // a seam the model's behaviour rests on and a struct literal would skip it.
    charter
        .save(&mut tx, employee_id, Utc::now())
        .await
        .expect("save the charter");
    let charter = Charter::load(&mut tx, employee_id)
        .await
        .expect("load the charter")
        .expect("a charter was just saved");
    let colleagues = inbound::colleagues(&mut tx, employee_id)
        .await
        .expect("the roster");
    let policy = policy::load(&mut tx, employee_id).await.ok();
    tx.commit().await.expect("commit the charter");

    let identity = format!(
        "You are {}, an AI employee of Orizn. Your address is {}.",
        stored.employee.slug().as_str(),
        stored.employee.address()
    );
    let prompt = charter.system_prompt(&identity);
    let prompt = match &policy {
        // No MCP server is bound — Orizn binds none — so the inventory is
        // empty and the policy is what withholds `call_mcp_tool`.
        Some(policy) => prompt.with_mcp_tools(policy, Vec::new()),
        None => prompt,
    }
    .with_colleagues(colleagues);

    let llm = Arc::new(Recorder {
        inner: CliLlm::new(),
        calls: Mutex::new(Vec::new()),
    });
    let turn = Turn::new(
        llm.clone(),
        PolicyGate::new(company.db.clone()),
        Effects::new(
            company.db.clone(),
            Arc::new(mocks::ports()),
            principal.clone(),
        ),
        principal,
        prompt,
        model,
        stored.employee.address().to_string(),
    );

    let context = Context::new()
        .with_task(TURN_BRIEF)
        .with_task(charter.brief());

    let started = Instant::now();
    let outcome = turn.run(context, &CancellationToken::new()).await;
    let wall = started.elapsed();

    let (ended, usage) = match outcome {
        Ok(finished) => (Ok(finished.stop_reason.code()), finished.usage),
        Err(failed) => (Err(failed.error.to_string()), failed.usage),
    };

    let calls = std::mem::take(&mut *llm.calls.lock().expect("recorder"));

    Ran {
        seat,
        role: charter.role(),
        ended,
        usage,
        wall,
        calls,
    }
}

// ---------------------------------------------------------------------------
// What went wrong, counted
// ---------------------------------------------------------------------------

/// A failure mode, as it appears in a tool result.
///
/// The strings are `app::turn`'s own: `propose` builds the first five and the
/// gate and the effects build the last two. Matching on them rather than
/// re-deriving means a wording change shows up here as an unclassified row
/// instead of as a silent zero.
fn classify(result: &str) -> &'static str {
    if result.ends_with(": no such tool") {
        "invented a tool that does not exist"
    } else if result.contains(": arguments are not ") {
        "tool call with the wrong argument shape"
    } else if result.contains(" is not an address") {
        "email address that does not parse"
    } else if result.starts_with("to: ") || result.starts_with("kind: ") {
        "colleague slug or errand that does not resolve"
    } else if result.starts_with("server: ") || result.starts_with("tool: ") {
        "mcp server or tool name that does not parse"
    } else if result.starts_with("currency: ") || result.starts_with("amount: ") {
        "payment amount or currency that does not parse"
    } else if let Some(rest) = result.strip_prefix("denied (") {
        coded("gate refused", rest.split(')').next().unwrap_or(rest))
    } else if let Some(rest) = result.strip_prefix("failed (") {
        coded("effect failed", rest.split(')').next().unwrap_or(rest))
    } else {
        "unclassified failure"
    }
}

/// The deny, effect and provider codes are a closed vocabulary but not a
/// `'static` one at this distance, so a tally line is interned. Bounded by the
/// number of codes, which is a few dozen.
///
/// ponytail: `Box::leak` over a `HashMap<String, usize>` tally. The tally is
/// `&'static str` because every other line in it is a literal, and one map
/// would be the whole reporting path rewritten to save a kilobyte.
fn coded(what: &str, code: &str) -> &'static str {
    Box::leak(format!("{what}: {code}").into_boxed_str())
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// Print one run's tape, turn by turn, and tally what went wrong.
fn report_run(ran: &Ran, failures: &mut Vec<&'static str>) {
    println!(
        "\n  ── {} ({}) ──────────────────────────────────────────",
        ran.seat, ran.role
    );

    for (i, call) in ran.calls.iter().enumerate() {
        // The previous call's tool results arrive as this call's last message.
        if i > 0
            && let Some(message) = &call.last_in
        {
            for block in &message.content {
                match block {
                    Content::ToolResult {
                        content, is_error, ..
                    } => {
                        if *is_error {
                            failures.push(classify(content));
                        }
                        println!(
                            "        {} {}",
                            if *is_error { "✗" } else { "←" },
                            first_line(content, 160)
                        );
                    }
                    Content::Text { text } => {
                        println!("        ⟦framed⟧ {}", first_line(text, 120));
                    }
                    Content::ToolUse { .. } => {}
                }
            }
        }

        let w = call.weighed;
        println!(
            "    call {}  {:>5.1}s  prompt≈{} tok (sys {} + tools {} + msgs {})  offered [{}]",
            i + 1,
            call.elapsed.as_secs_f64(),
            w.total(),
            w.system,
            w.tools,
            w.messages,
            call.offered.join(", ")
        );

        match &call.out {
            Err(code) => {
                failures.push(coded("the model call itself failed", code));
                println!("      ! the provider returned {code} — this run ends here");
            }
            Ok(response) => {
                let mut acted = false;
                let mut narrated = false;
                for block in &response.content {
                    match block {
                        // Whole and unclipped, one key per line. A clipped
                        // argument list hides exactly the fields that go
                        // wrong — the first thing this run caught was a
                        // colleague's address invented at the end of a long
                        // `body`, which a 300-character clip cut off.
                        Content::ToolUse { name, input, .. } => {
                            acted = true;
                            println!("      → {name}");
                            for line in serde_json::to_string_pretty(input)
                                .unwrap_or_else(|_| input.to_string())
                                .lines()
                            {
                                println!("        {line}");
                            }
                        }
                        // Whole, not clipped to a line. What the model *said*
                        // when it declined to act is the finding, and a first
                        // line would report a decision without its reason.
                        Content::Text { text } => {
                            // The failure mode this dry run exists to catch,
                            // and the one that hides best: the model writes a
                            // complete, well-formed tool call **inside** the
                            // `text` field of `llm_cli`'s JSON contract. The
                            // shim parses it as prose, the turn ends
                            // `end_turn`, nothing happens — and the transcript
                            // reads like an employee that thought carefully.
                            // Nothing else here would have counted it as more
                            // than "no action".
                            if text.contains("{\"tool\":") {
                                narrated = true;
                            }
                            print!("{}", quoted(text));
                        }
                        Content::ToolResult { .. } => {}
                    }
                }
                if narrated {
                    failures.push("wrote the tool call as prose instead of calling it");
                } else if !acted && i == 0 {
                    failures.push("the whole turn was one message and no action");
                }
            }
        }
    }

    match &ran.ended {
        Ok(stop) => println!(
            "    ended {stop} · {} model calls · {:.1}s wall · in {} out {} cache_read {}",
            ran.calls.len(),
            ran.wall.as_secs_f64(),
            ran.usage.input_tokens,
            ran.usage.output_tokens,
            ran.usage.cache_read_tokens
        ),
        Err(err) => {
            failures.push("the run ended on a budget or a provider error");
            println!(
                "    ENDED EARLY: {err} · {} model calls · {:.1}s wall",
                ran.calls.len(),
                ran.wall.as_secs_f64()
            );
        }
    }
}

/// The model's own words, whole, indented so they cannot be mistaken for ours.
fn quoted(text: &str) -> String {
    text.trim()
        .lines()
        .map(|line| format!("      » {line}\n"))
        .collect()
}

/// One line of a possibly-multi-line string, clipped.
fn first_line(text: &str, max: usize) -> String {
    let line = text.trim().lines().next().unwrap_or("").trim();
    if line.chars().count() <= max {
        return line.to_owned();
    }
    format!("{}…", line.chars().take(max).collect::<String>())
}

// ---------------------------------------------------------------------------
// The gate: structural, and sampled
// ---------------------------------------------------------------------------

impl Ran {
    /// Tool calls the model proposed across this turn.
    fn proposed(&self) -> usize {
        self.calls
            .iter()
            .filter_map(|call| call.out.as_ref().ok())
            .flat_map(|response| &response.content)
            .filter(|block| matches!(block, Content::ToolUse { .. }))
            .count()
    }

    /// The ones proposed in the **last** model call, which the loop never got to
    /// answer because the turn ended there.
    ///
    /// `Turn::attempt` checks the budget before each tool call and returns from
    /// inside the loop, so an over-budget run drops the whole final call's
    /// results. Subtracting these is what makes the ruling check a claim about
    /// the wiring rather than about how a run happened to end.
    fn unanswered(&self) -> usize {
        self.calls
            .last()
            .and_then(|call| call.out.as_ref().ok())
            .map(|response| {
                response
                    .content
                    .iter()
                    .filter(|block| matches!(block, Content::ToolUse { .. }))
                    .count()
            })
            .unwrap_or_default()
    }

    /// Tool results that came back and were shown to the model. The gate's own
    /// answers: `Turn` hands a refusal back as a failed tool result rather than
    /// raising, so a denial counts here exactly like an allow.
    fn ruled(&self) -> usize {
        self.calls
            .iter()
            .filter_map(|call| call.last_in.as_ref())
            .flat_map(|message| &message.content)
            .filter(|block| matches!(block, Content::ToolResult { .. }))
            .count()
    }

    /// Model calls that came back as a provider or shim error.
    fn provider_errors(&self) -> usize {
        self.calls.iter().filter(|call| call.out.is_err()).count()
    }

    /// Did this turn get all the way through without the provider or the shim
    /// dropping a call?
    ///
    /// **Only intact turns are billed**, and that is not fastidiousness. A turn
    /// that died on `cli_not_json` still has a prompt that was sent and a
    /// completion that never came, so averaging it in reports input tokens
    /// nobody answered and divides real output by calls that returned nothing —
    /// arithmetic that looks exactly like a measurement. `llm_cli`'s own docs
    /// call the shim lossy and put a number on it, so this is expected
    /// behaviour to *report*, never numbers to fold in.
    fn intact(&self) -> bool {
        self.provider_errors() == 0 && !self.calls.is_empty()
    }
}

/// One pass reduced to the three numbers the bill is made of, over its
/// [`Ran::intact`] turns alone.
///
/// `None` when the pass had no intact turn — nothing to bill, and the structural
/// row that says so has already failed.
fn sample(pass: &[Ran]) -> Option<Sample> {
    let billed: Vec<&Ran> = pass.iter().filter(|ran| ran.intact()).collect();
    let calls = billed.iter().map(|ran| ran.calls.len()).sum::<usize>();
    if calls == 0 {
        return None;
    }
    let prompt: usize = billed
        .iter()
        .flat_map(|ran| ran.calls.iter())
        .map(|call| call.weighed.total())
        .sum();
    let output: u64 = billed.iter().map(|ran| ran.usage.output_tokens).sum();
    Some(Sample {
        calls_per_turn: calls as f64 / billed.len() as f64,
        input_tokens_per_call: prompt as f64 / calls as f64,
        output_tokens_per_call: output as f64 / calls as f64,
    })
}

/// Smallest and largest of a slice of floats — the spread, which is the whole
/// reason a dry run is three passes and not one.
///
/// Empty gives `(MAX, MIN)`, which is nonsense on purpose: it can only happen
/// when no pass produced a sample, and every caller checks that first rather
/// than printing a zero that reads like a measurement.
fn spread(values: &[f64]) -> (f64, f64) {
    values
        .iter()
        .fold((f64::MAX, f64::MIN), |(lo, hi), &v| (lo.min(v), hi.max(v)))
}

/// **What the run said, split into what is pass/fail and what is a sample.**
///
/// The four [`Truth::Correct`] rows are properties of the wiring: a broken
/// system fails them and a merely disappointing model does not. Everything else
/// is [`Truth::Characterises`] — reported, spread across passes, never gated.
/// See this module's docs for the argument.
fn verdict(passes: &[Vec<Ran>], failures: &[&'static str]) -> Surface {
    let runs: Vec<&Ran> = passes.iter().flatten().collect();
    let turns = runs.len();
    let mut rows = Vec::new();

    // --- structural: the loop ran ------------------------------------------
    let ran = runs.iter().filter(|r| !r.calls.is_empty()).count();
    rows.push(
        Row::ok(
            "every turn reached the model",
            format!("{ran}/{turns} turns made at least one call"),
            Truth::Correct,
        )
        .gated(ran == turns && turns > 0),
    );

    // --- structural: something survived to be measured ----------------------
    // **Not "no call failed".** That was the first version of this row and it
    // was wrong, because it contradicted a decision this repository had already
    // made: `llm_cli`'s own docs call the shim lossy and put a number on it, and
    // `toolchoice::Chose::Malformed` reports shim failures as a figure rather
    // than gating on them. A `cli_not_json` is a measurement of the shim, so it
    // is characterised on the row below. What IS structural is that at least one
    // turn survived — a run where the shim ate every call measured nothing at
    // all, and its averages would be arithmetic over calls that never returned.
    let calls: usize = runs.iter().map(|r| r.calls.len()).sum();
    let broken: usize = runs.iter().map(|r| r.provider_errors()).sum();
    let intact = runs.iter().filter(|r| r.intact()).count();
    rows.push(
        Row::ok(
            "some turn ran without a shim failure",
            format!("{intact}/{turns} turns intact, and only those are billed"),
            Truth::Correct,
        )
        .gated(intact > 0),
    );

    // --- structural: it acted ------------------------------------------------
    // **The row that would have caught the three-day-old bug.** Zero tool calls
    // across a whole dry run is not a shy model, it is a system that cannot act:
    // the schemas never arrived, or the shim ate them, or the policy withheld
    // every one. Gated at the run and not per turn, because one quiet turn is a
    // sample and a silent run is not.
    let proposed: usize = runs.iter().map(|r| r.proposed()).sum();
    let acted = runs.iter().filter(|r| r.proposed() > 0).count();
    rows.push(
        Row::ok(
            "the employees called tools",
            format!("{proposed} calls, from {acted}/{turns} turns"),
            Truth::Correct,
        )
        .gated(proposed > 0),
    );

    // --- structural: the gate answered --------------------------------------
    let ruled: usize = runs.iter().map(|r| r.ruled()).sum();
    let cut_off: usize = runs.iter().map(|r| r.unanswered()).sum();
    rows.push(
        Row::ok(
            "…and every one of them got a ruling",
            format!(
                "{ruled} rulings for {} answerable calls",
                proposed - cut_off
            ),
            Truth::Correct,
        )
        .gated(ruled == proposed - cut_off)
        .note("allow and deny both count: a refusal comes back as a failed tool result"),
    );

    // --- sampled: how many calls a turn takes -------------------------------
    let samples: Vec<Sample> = passes.iter().filter_map(|pass| sample(pass)).collect();
    let per_turn: Vec<f64> = samples.iter().map(|s| s.calls_per_turn).collect();
    let (lo, hi) = spread(&per_turn);
    rows.push(
        Row::ok(
            "model calls per intact turn",
            if samples.is_empty() {
                "nothing to bill".to_owned()
            } else {
                format!("{lo:.2}–{hi:.2} over {} pass(es)", samples.len())
            },
            Truth::Characterises,
        )
        .note("`docs/ORIZN.md` billed 1.00, which is the floor of a range that ends at 10"),
    );

    // --- sampled: what a call weighs ----------------------------------------
    let (in_lo, in_hi) = spread(
        &samples
            .iter()
            .map(|s| s.input_tokens_per_call)
            .collect::<Vec<_>>(),
    );
    let (out_lo, out_hi) = spread(
        &samples
            .iter()
            .map(|s| s.output_tokens_per_call)
            .collect::<Vec<_>>(),
    );
    rows.push(
        Row::ok(
            "tokens per model call",
            if samples.is_empty() {
                "nothing to weigh".to_owned()
            } else {
                format!("in {in_lo:.0}–{in_hi:.0}, out {out_lo:.0}–{out_hi:.0}")
            },
            Truth::Characterises,
        )
        .note("input by `scoping::tokens` over OUR bytes, not the CLI's — it bills its own prefix"),
    );

    // --- sampled: the money -------------------------------------------------
    let day = f64::from(cost::turns_per_day());
    let bill: Vec<f64> = samples.iter().map(|s| s.measured_usd(day)).collect();
    let (bill_lo, bill_hi) = spread(&bill);
    let floor = spread(
        &samples
            .iter()
            .map(|s| s.monthly_usd(cost::FLOOR_CALLS_PER_TURN, day))
            .collect::<Vec<_>>(),
    )
    .0;
    let ceiling = spread(
        &samples
            .iter()
            .map(|s| s.monthly_usd(cost::ceiling_calls_per_turn(), day))
            .collect::<Vec<_>>(),
    )
    .1;
    rows.push(
        Row::ok(
            "…which comes to, a month",
            if samples.is_empty() {
                "no sample".to_owned()
            } else {
                format!("${bill_lo:.0}–${bill_hi:.0}  (floor ${floor:.0}, ceiling ${ceiling:.0})")
            },
            Truth::Characterises,
        )
        .note(format!(
            "at {day} reserved turns a day, from docs/orizn-roles/*.json; arithmetic in `cost.rs`"
        )),
    );

    // --- sampled: the shim, and what went wrong -----------------------------
    // Reported and not gated, for the reason the structural row above gives.
    // `llm_cli` is a documented lossy shim and this is its rate on this run —
    // the number an operator needs to decide whether the dry run is telling
    // them about their company or about the local binary.
    rows.push(
        Row::ok(
            "…the rest died at the shim",
            format!(
                "{broken} of {calls} model calls, {} turns lost",
                turns - intact
            ),
            Truth::Characterises,
        )
        .note(
            "`llm_cli` is lossy by construction and says so; the production path is llm_anthropic",
        ),
    );
    rows.push(Row::ok(
        "failures classified",
        format!("{} across {turns} turns", failures.len()),
        Truth::Characterises,
    ));
    let mut walls: Vec<f64> = runs
        .iter()
        .flat_map(|r| r.calls.iter())
        .map(|c| c.elapsed.as_secs_f64())
        .collect();
    walls.sort_by(f64::total_cmp);
    rows.push(Row::ok(
        "wall clock per model call",
        if walls.is_empty() {
            "no call completed".to_owned()
        } else {
            format!(
                "median {:.1}s, slowest {:.1}s",
                walls[walls.len() / 2],
                walls.last().copied().unwrap_or_default()
            )
        },
        Truth::Characterises,
    ));

    Surface {
        name: "orizn (dry run)",
        method: "a real company in a real database, worked by the real model through the local \
                 `claude` CLI",
        rows,
        unmeasured: vec![
            "whether the work was any GOOD. Every row above is about whether the machinery \
             turned; whether the email was worth sending is a human reading the transcript",
            "the model. A new snapshot behind the same name moves every sampled row and no pin \
             in this repository can see it happen",
            "the vertical step, omitted here because it needs a sourcing round or a pipeline in \
             the database — one extra trusted sentence the real turn carries and this does not",
            "everything the mocks stand in for: email, telephony, browser, payments. A tool call \
             that the gate allowed and a mock accepted is not a tool call that worked",
        ],
    }
}

/// The sampled half again, in the shape [`crate::cost::RECORDED`] takes.
///
/// Paste it **with** the digest, never without: a sample and a digest from
/// different runs is the exact lie this whole mechanism exists to stop.
///
/// **Withheld when a structural row failed**, and that is the join between the
/// two halves of this module. A run in which two of four model calls timed out
/// still produces averages, and they look exactly like measurements — an input
/// figure over prompts nobody answered and an output figure divided by calls
/// that returned nothing. Printing them next to the word `paste` is how a bad
/// number gets into `cost.rs`, so the structural rows decide whether there is
/// anything here worth recording.
fn record(passes: &[Vec<Ran>], structurally_sound: bool) {
    println!("\n─────────────────────────────────────────────────────────────");
    if !structurally_sound {
        println!(
            "NO RECORD — a structural check failed, so this run measured a broken system\n\n  \
             The numbers above are still printed, because a broken run is a finding. They are \
             not\n  offered for pasting: an average over model calls that never returned is \
             arithmetic,\n  not a measurement. Fix what failed, run again."
        );
        return;
    }
    println!("RECORD — paste into crates/eval/src/cost.rs, both parts together\n");
    println!("pub const RECORDED: &[Sample] = &[");
    for pass in passes {
        let Some(s) = sample(pass) else { continue };
        println!(
            "    Sample {{ calls_per_turn: {:.2}, input_tokens_per_call: {:.1}, \
             output_tokens_per_call: {:.1} }},",
            s.calls_per_turn, s.input_tokens_per_call, s.output_tokens_per_call
        );
    }
    println!("];");
    println!("pub const DIGEST: &str = \"{}\";", cost::digest());
}

/// Every failure, and how often — the part of this report that is the point.
fn report_failures(failures: &[&'static str], runs: usize) {
    println!("\n─────────────────────────────────────────────────────────────");
    println!("WHAT WENT WRONG — {} across {runs} runs\n", failures.len());
    if failures.is_empty() {
        println!(
            "  Nothing was classified as a failure. That is a claim about the classifier as \
             much\n  as about the model — read the transcript above before believing it."
        );
        return;
    }
    let mut sorted: Vec<&&str> = failures.iter().collect();
    sorted.sort_unstable();
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i;
        while j < sorted.len() && sorted[j] == sorted[i] {
            j += 1;
        }
        println!("  {:>3}×  {}", j - i, sorted[i]);
        i = j;
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Stand Orizn up, work it `runs` times, and print what happened.
///
/// Returns whether the **structural** rows passed — see [`verdict`]. `false` is
/// an exit code, because a run in which nothing called a tool is a broken system
/// and a report nobody reads is how it stayed broken for three days.
///
/// **An empty database per invocation, and that is not negotiable** — see
/// [`EMPTY_DATABASE`] for the two constraints that make it so. Passes *within*
/// one invocation share a company, which is the point: it is the same seats
/// taking a second and third turn.
///
/// `runs` is the number of passes, and **three is the smallest useful number**:
/// one run of a language model is an anecdote, and every sampled row above is
/// printed as a spread across passes rather than as a figure.
pub async fn run(model: &str, runs: usize) -> bool {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        println!(
            "DATABASE_URL is unset. This stands a real company up in a real database:\n  \
             DATABASE_URL=postgres://postgres:postgres@localhost:5432/orizn_dryrun \\\n    \
             cargo run -p agentos-eval --features live-orizn -- --dry-run 3"
        );
        return false;
    };
    let db = Db::connect(&url).await.expect("connect to DATABASE_URL");
    db.migrate().await.expect("migrate");

    println!("─────────────────────────────────────────────────────────────");
    println!("DRY RUN — Orizn, {runs} pass(es), {model} via the local `claude` CLI");
    println!("Real: the ceiling, the tenant, the org chart, five role layers, the");
    println!("provisioning engine, the Policy Gate, the turn loop, the model.");
    println!("Mock: email, telephony, browser, payments — everything but the model.");
    println!(
        "Company digest {} — what these numbers are about.",
        cost::digest()
    );

    let company = stand_up(db).await;
    let charters = charters();
    println!(
        "\nStood up: {} seats, {} of them given an objective.",
        company.seats.len(),
        charters.len()
    );

    let mut passes: Vec<Vec<Ran>> = Vec::new();
    let mut failures = Vec::new();
    for pass in 1..=runs {
        println!("\n═══ pass {pass}/{runs} ═══");
        let mut this = Vec::new();
        for (seat, charter) in &charters {
            let ran = take_turn(&company, seat, charter, model).await;
            report_run(&ran, &mut failures);
            this.push(ran);
        }
        passes.push(this);
    }

    report_failures(&failures, passes.iter().flatten().count());

    let surface = verdict(&passes, &failures);
    println!("\n{}", crate::render(std::slice::from_ref(&surface)));
    let sound = surface.passed();
    record(&passes, sound);
    sound
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The gate's own gate, and it needs no model, no database and no `claude`
// binary — [`verdict`] is a pure function of a recorded tape. Which is the
// point: the half of a live measurement that can be tested deterministically is
// the half that decides pass from fail, and it is tested here.

#[cfg(test)]
mod tests {
    use agentos_providers::llm::{Message, Role};
    use serde_json::json;

    use super::*;

    fn weighed() -> Weighed {
        Weighed {
            system: 1_000,
            tools: 800,
            messages: 200,
        }
    }

    fn call(last_in: Option<Message>, out: Result<LlmResponse, &'static str>) -> Call {
        Call {
            elapsed: Duration::from_secs(3),
            offered: vec!["send_email".to_owned()],
            weighed: weighed(),
            last_in,
            out,
        }
    }

    fn asked(id: &str) -> LlmResponse {
        LlmResponse::tool_use(
            id,
            "send_email",
            json!({"to": "a@b.example"}),
            Usage::new(0, 40, 0),
        )
    }

    fn answered(id: &str) -> Message {
        Message::new(Role::User, vec![Content::tool_result(id, "queued")])
    }

    fn said() -> LlmResponse {
        LlmResponse::text("done", Usage::new(0, 40, 0))
    }

    fn ran(calls: Vec<Call>) -> Ran {
        Ran {
            seat: "sdr",
            role: "sales-development",
            ended: Ok("end_turn"),
            usage: Usage::new(0, 40 * calls.len() as u64, 0),
            wall: Duration::from_secs(10),
            calls,
        }
    }

    /// One tool asked for, one ruling back, one prose reply. The shape a working
    /// turn has, and every structural row passes on it.
    fn healthy() -> Ran {
        ran(vec![
            call(Some(Message::user("go")), Ok(asked("t1"))),
            call(Some(answered("t1")), Ok(said())),
        ])
    }

    fn structural(surface: &Surface) -> Vec<&Row> {
        surface
            .rows
            .iter()
            .filter(|row| row.truth == Truth::Correct)
            .collect()
    }

    #[test]
    fn a_working_run_passes_every_structural_check_and_gates_no_number() {
        let surface = verdict(&[vec![healthy(), healthy()]], &[]);
        assert!(
            surface.passed(),
            "{}",
            crate::render(std::slice::from_ref(&surface))
        );
        assert_eq!(
            structural(&surface).len(),
            4,
            "four structural rows, no more"
        );
        // And not one of the sampled rows is gated, however the numbers came
        // out. A threshold on a sample is a flaky build.
        assert!(
            surface
                .rows
                .iter()
                .filter(|row| row.truth == Truth::Characterises)
                .all(|row| row.ok)
        );
    }

    /// **The failure this whole mechanism was built for.** Nine turns of
    /// well-written prose and no tool call is not a shy model, it is a system
    /// that cannot act — and for three days nothing automated noticed.
    #[test]
    fn a_run_that_called_nothing_fails_and_names_the_row() {
        let quiet = ran(vec![call(Some(Message::user("go")), Ok(said()))]);
        let surface = verdict(&[vec![quiet]], &[]);
        assert!(!surface.passed());
        let report = crate::render(&[surface]);
        assert!(report.contains("the employees called tools"), "{report}");
        assert!(report.contains("0 calls, from 0/1 turns"), "{report}");
    }

    /// A turn that never reached the model at all — the database refused, the
    /// budget was already spent — is not a sample of anything.
    #[test]
    fn a_turn_that_never_reached_the_model_fails() {
        let surface = verdict(&[vec![healthy(), ran(Vec::new())]], &[]);
        assert!(!surface.passed());
        assert!(crate::render(&[surface]).contains("1/2 turns made at least one call"));
    }

    /// A shim failure alongside a turn that worked is **reported and not
    /// gated** — `llm_cli` is lossy by construction — but the broken turn is
    /// kept out of the numbers, or the input figure counts a prompt nobody
    /// answered and the output figure divides by a call that returned nothing.
    #[test]
    fn a_shim_failure_is_characterised_and_never_billed() {
        let broke = ran(vec![call(Some(Message::user("go")), Err("cli_not_json"))]);
        let pass = vec![healthy(), broke];
        let surface = verdict(std::slice::from_ref(&pass), &[]);
        assert!(
            surface.passed(),
            "{}",
            crate::render(std::slice::from_ref(&surface))
        );
        let report = crate::render(&[surface]);
        assert!(report.contains("1/2 turns intact"), "{report}");
        assert!(
            report.contains("1 of 3 model calls, 1 turns lost"),
            "{report}"
        );

        // And the sample is the healthy turn alone: two calls, not three.
        let s = sample(&pass).expect("one intact turn");
        assert!((s.calls_per_turn - 2.0).abs() < 1e-9);
        assert!((s.input_tokens_per_call - 2_000.0).abs() < 1e-9);
    }

    /// But a run where the shim ate **every** call measured nothing at all, and
    /// that is structural: there is no intact turn to average.
    #[test]
    fn a_run_the_shim_ate_entirely_fails() {
        let broke = ran(vec![call(Some(Message::user("go")), Err("cli_not_json"))]);
        let surface = verdict(&[vec![broke]], &[]);
        assert!(!surface.passed());
        let report = crate::render(&[surface]);
        assert!(report.contains("0/1 turns intact"), "{report}");
        assert!(report.contains("nothing to bill"), "{report}");
    }

    /// A tool call whose result never came back means the loop dropped a ruling
    /// on the floor, which no amount of model behaviour can cause.
    #[test]
    fn a_ruling_that_never_came_back_fails() {
        let dropped = ran(vec![
            call(Some(Message::user("go")), Ok(asked("t1"))),
            call(Some(Message::user("go on")), Ok(said())),
        ]);
        let surface = verdict(&[vec![dropped]], &[]);
        assert!(!surface.passed());
        assert!(crate::render(&[surface]).contains("0 rulings for 1 answerable calls"));
    }

    /// …but a tool call the **budget** cut off is not a dropped ruling. The loop
    /// checks its budget before each tool call and returns from inside the final
    /// model call, so those results were never owed. Without this subtraction
    /// every over-budget run would fail a structural check for behaving exactly
    /// as designed.
    #[test]
    fn a_tool_call_the_budget_cut_off_is_not_a_dropped_ruling() {
        let mut cut = ran(vec![
            call(Some(Message::user("go")), Ok(asked("t1"))),
            call(Some(answered("t1")), Ok(asked("t2"))),
        ]);
        cut.ended = Err("max_tool_calls".to_owned());
        let surface = verdict(&[vec![cut]], &[]);
        assert!(
            surface.passed(),
            "{}",
            crate::render(std::slice::from_ref(&surface))
        );
        assert!(crate::render(&[surface]).contains("1 rulings for 1 answerable calls"));
    }

    /// The sampled half is an average per pass, and a pass that made no call has
    /// no sample rather than a zero — a zero would drag a spread toward a run
    /// that never happened.
    #[test]
    fn a_pass_with_no_model_call_contributes_no_sample() {
        assert!(sample(&[ran(Vec::new())]).is_none());
        assert!(sample(&[]).is_none());

        let s = sample(&[healthy()]).expect("two calls");
        assert!((s.calls_per_turn - 2.0).abs() < 1e-9);
        assert!((s.input_tokens_per_call - 2_000.0).abs() < 1e-9);
        // 80 output tokens over two calls.
        assert!((s.output_tokens_per_call - 40.0).abs() < 1e-9);
    }

    /// Spread over passes, not over turns: the run reports a range because one
    /// run of a language model is an anecdote.
    #[test]
    fn the_sampled_rows_report_a_spread_across_passes() {
        let quiet = ran(vec![call(Some(Message::user("go")), Ok(asked("t1")))]);
        let surface = verdict(&[vec![healthy()], vec![quiet]], &[]);
        let report = crate::render(&[surface]);
        assert!(report.contains("1.00–2.00 over 2 pass(es)"), "{report}");
    }
}
