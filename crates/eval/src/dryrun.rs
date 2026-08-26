//! **The dry run.** Orizn, stood up for real, working against the real model.
//!
//! ```sh
//! createdb r1app                       # any empty database will do
//! DATABASE_URL=postgres://postgres:postgres@localhost:5443/r1app \
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
use agentos_app::{inbound, mocks, rolepack, rolepack_sales, rolepack_service};
use agentos_domain::action::Domain;
use agentos_domain::employee::{Employee, Lifecycle};
use agentos_domain::ids::{EmployeeId, Slug, TenantId};
use agentos_domain::money::{Currency, Money};
use agentos_domain::policy::PolicyLimits;
use agentos_providers::ProviderError;
use agentos_providers::llm::{Content, Llm, LlmRequest, LlmResponse, Message, Usage};
use agentos_providers::llm_cli::CliLlm;
use agentos_store::db::Db;
use agentos_store::{employee as employee_store, org, policy, spend};
use async_trait::async_trait;
use chrono::Utc;
use tokio_util::sync::CancellationToken;

use crate::scoping::{Weighed, weigh};

/// Passed to the CLI untouched. Same default as the held-out set.
pub use crate::toolchoice::DEFAULT_MODEL;

/// A mock deployment's envelope key. Real crypto over a throwaway key: the
/// identity step seals a private key with it and would otherwise not run.
const MASTER_KEY: &str = "dryrun-master-key-0123456789abcdef";

/// What `docs/ORIZN.md` derives from `scoping.rs`, so the measurement has
/// something to disagree with. Input tokens per model call at ten staff.
const PREDICTED_TOKENS_PER_CALL: usize = 4_639;

/// The rate card, from `docs/ORIZN.md`. The one thing here that comes from
/// outside this repository.
const USD_PER_M_INPUT: f64 = 5.0;
const USD_PER_M_OUTPUT: f64 = 25.0;

/// Orizn's reserved turns per day, summed over the five seats — the column
/// `docs/ORIZN.md` bills.
const TURNS_PER_DAY: f64 = 66.0;

/// What `docs/ORIZN.md` budgets, at one model call per reserved turn.
const PREDICTED_USD_PER_MONTH: f64 = 76.0;

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

/// `docs/`, from `crates/eval/`.
fn docs(file: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(file)
}

/// One of the operator's policy documents, as the installer reads it.
fn limits(file: &str) -> PolicyLimits {
    let path = docs(file);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path:?}: {err}"));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("{path:?}: {err}"))
}

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
        .expect("create the tenant");

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
        engine
            .converge(tenant, *id)
            .await
            .expect("converge the seat");
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
// The objectives
// ---------------------------------------------------------------------------

/// The charters these seats are given, in the operator's words.
///
/// **Written once and not touched again.** Tuning a briefing until the run
/// looks good is how a dry run stops being evidence; if one of these produces a
/// bad turn, the bad turn is the finding.
fn charters() -> Vec<(&'static str, Charter)> {
    vec![
        (
            "sdr",
            Charter::Sales {
                pack: rolepack_sales::RolePack::sales_development(),
                objective: rolepack_sales::Objective {
                    segment: rolepack_sales::Segment::Airline,
                    market: Some(rolepack::CountryCode::parse("de").expect("country")),
                    target_accounts: vec![
                        "Condor".to_owned(),
                        "Eurowings".to_owned(),
                        "Lufthansa".to_owned(),
                    ],
                },
            },
        ),
        (
            "support",
            Charter::Support {
                objective: rolepack_service::Support {
                    product: "the Orizn entry-requirements API".to_owned(),
                    first_response_hours: 8,
                    escalate_to: Some("founder".to_owned()),
                },
            },
        ),
        (
            "books",
            Charter::Finance {
                objective: rolepack_service::Books {
                    period: "2026-08".to_owned(),
                    currency: Some(Currency::Usd),
                    obligations: vec![
                        "settle the approved hosting invoice INV-4471 from acme-cloud for \
                         USD 240.00 against PO-889"
                            .to_owned(),
                        "reconcile the August card statement".to_owned(),
                    ],
                },
            },
        ),
    ]
}

/// What a self-started turn is, in the model's terms.
///
/// A verbatim copy of `apps/server/src/loops/initiative.rs`'s `TURN_BRIEF`, a
/// private const in a binary crate with no library target. Copied rather than
/// paraphrased: a dry run that sends different bytes from the running system is
/// measuring a company nobody deployed. If the original moves, this moves.
const TURN_BRIEF: &str = "Nobody has written to you. Your working rhythm has come round, so this \
                          turn is yours to spend on your own objective. You have been here before \
                          and the plan below does not know it: start by finding out where you \
                          actually got to — read your own conversations, notes and records — then \
                          advance the earliest stage that is not finished. One turn is not the \
                          whole plan. Do the next real piece of work, finish it, and write down \
                          what you did. If a stage is blocked on somebody else, say so and move to \
                          what is not blocked rather than waiting inside this turn.";

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

/// The cost and the clock, measured against what `docs/ORIZN.md` predicts.
fn report_cost(runs: &[Ran]) {
    let calls: Vec<&Call> = runs.iter().flat_map(|ran| ran.calls.iter()).collect();
    if calls.is_empty() {
        println!("\nNo model call completed, so there is nothing to bill.");
        return;
    }

    let n = calls.len() as f64;
    let prompt_tokens: usize = calls.iter().map(|call| call.weighed.total()).sum();
    let per_call = prompt_tokens as f64 / n;
    let output: u64 = runs.iter().map(|ran| ran.usage.output_tokens).sum();
    let per_call_out = output as f64 / n;
    let calls_per_turn = n / runs.len() as f64;

    let mut walls: Vec<f64> = calls.iter().map(|c| c.elapsed.as_secs_f64()).collect();
    walls.sort_by(f64::total_cmp);
    let median = walls[walls.len() / 2];
    let slowest = walls.last().copied().unwrap_or_default();

    let monthly = |tokens: f64, rate: f64| {
        tokens * calls_per_turn * TURNS_PER_DAY * 30.0 * rate / 1_000_000.0
    };
    let projected = monthly(per_call, USD_PER_M_INPUT) + monthly(per_call_out, USD_PER_M_OUTPUT);

    println!("\n─────────────────────────────────────────────────────────────");
    println!("COST — measured against what docs/ORIZN.md predicts\n");
    println!(
        "  prompt tokens per model call   {per_call:>8.0}   predicted {PREDICTED_TOKENS_PER_CALL} \
         ({:+.0}%)",
        (per_call / PREDICTED_TOKENS_PER_CALL as f64 - 1.0) * 100.0
    );
    println!("  output tokens per model call   {per_call_out:>8.0}   assumed 600 in the runbook");
    println!(
        "  model calls per reserved turn  {calls_per_turn:>8.2}   the runbook's table is the \
         floor at 1.00"
    );
    println!(
        "  projected                      ${projected:>7.2}/mo  budgeted ${PREDICTED_USD_PER_MONTH:.0}/mo \
         at {TURNS_PER_DAY:.0} turns a day"
    );
    println!(
        "\n  The prompt token count is `scoping::tokens`, a ±20% estimator over the bytes we \
         send.\n  It is NOT what the CLI reported: the CLI bills its own system prompt, its own \
         tool\n  schemas and its own cache, so its `input_tokens` is a number about the CLI. \
         The\n  production path is `llm_anthropic`, which sends exactly the bytes weighed here."
    );

    println!("\nWALL CLOCK\n");
    println!("  per model call   median {median:.1}s   slowest {slowest:.1}s");
    let per_run: Vec<f64> = runs.iter().map(|ran| ran.wall.as_secs_f64()).collect();
    println!(
        "  per turn         mean {:.1}s over {} runs",
        per_run.iter().sum::<f64>() / per_run.len() as f64,
        per_run.len()
    );
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
/// One database per invocation is the caller's business: this writes a tenant
/// with a fresh id every time, so re-running against the same database adds a
/// company rather than replacing one.
pub async fn run(model: &str, runs: usize) {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        println!(
            "DATABASE_URL is unset. This stands a real company up in a real database:\n  \
             DATABASE_URL=postgres://postgres:postgres@localhost:5432/orizn_dryrun \\\n    \
             cargo run -p agentos-eval --features live-orizn -- --dry-run"
        );
        return;
    };
    let db = Db::connect(&url).await.expect("connect to DATABASE_URL");
    db.migrate().await.expect("migrate");

    println!("─────────────────────────────────────────────────────────────");
    println!("DRY RUN — Orizn, {runs} pass(es), {model} via the local `claude` CLI");
    println!("Real: the ceiling, the tenant, the org chart, five role layers, the");
    println!("provisioning engine, the Policy Gate, the turn loop, the model.");
    println!("Mock: email, telephony, browser, payments — everything but the model.");

    let company = stand_up(db).await;
    let charters = charters();
    println!(
        "\nStood up: {} seats, {} of them given an objective.",
        company.seats.len(),
        charters.len()
    );

    let mut all = Vec::new();
    let mut failures = Vec::new();
    for pass in 1..=runs {
        println!("\n═══ pass {pass}/{runs} ═══");
        for (seat, charter) in &charters {
            let ran = take_turn(&company, seat, charter, model).await;
            report_run(&ran, &mut failures);
            all.push(ran);
        }
    }

    report_failures(&failures, all.len());
    report_cost(&all);
}
