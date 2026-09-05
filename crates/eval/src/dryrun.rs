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
//! **And guard 2 would not in fact have caught this crate**, which is worth
//! saying rather than leaving as an argument that reads stronger than it is:
//! the `SKIP:` grep lives inside `scripts/test.sh`'s per-package loop, and
//! `agentos-eval` is run *after* that loop, on its own line, with neither
//! `--nocapture` nor a `tee`. A runtime skip written here would print into a
//! terminal nothing reads. That does not weaken the choice — a module needing
//! ten minutes and a paid model must be absent from a default build whether or
//! not anything would have noticed it passing quietly — it just means the
//! guard doing the work is `crates/app`'s, where the same shape really is
//! under the grep, and this crate is following it on the argument rather than
//! on the enforcement.
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
//! # The seller works a prospect, and for a while it did not
//!
//! [`take_turn`] used to omit the vertical step with a comment saying it needed
//! "a sourcing round or a sales pipeline in the database". That was true when
//! `loops::initiative` answered a sales charter with `return None`; it stopped
//! being true when `vertical::selling_turn` was dispatched for real, and nothing
//! here noticed. **Every sample recorded before 2026-08-26 measured a seller
//! that took an ordinary conversational turn** — and the transcript of one is
//! worth reading, because the model works it out: nine model calls, seven of
//! them `read_page` against `orizn.app`, and a closing paragraph explaining that
//! the evidence stage is "structurally blocked" because no tool it has reaches
//! an airline.
//!
//! So [`stand_up`] now seeds a prospect with a **confirmed** flow, [`vertical`]
//! runs before the model exactly as `loops::initiative::vertical_step` does, and
//! the seller's own numbers are reported on a row of their own — a turn that
//! runs somebody's booking flow twice and files a finding before it thinks is a
//! different shape of turn from a buyer's, and an average over both hides it.
//!
//! Four constraints made that seeding narrow, and all four are deliberate:
//! `proof_of_need::Flow` carries a private seal, so it cannot be built by hand
//! and has to come through `Flow::confirmed`; `app_role` is granted no INSERT on
//! `prospect_flows`, so the row goes in on an admin connection through
//! `revenue::set_prospect_flow`; `confirmed_by` must be set or `Flow::confirmed`
//! refuses the row; and `MockBrowser`'s page map is empty, so the panel read
//! comes back `no_such_element` unless the fixture puts an element there. Not
//! one of them is worked around here — see [`crate::cost::Prospect`], which owns
//! what is seeded and is inside [`crate::cost::digest`] because of it.
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

use agentos_app::effects::{Effects, Ports};
use agentos_app::gate::{PolicyGate, Principal};
use agentos_app::proof_of_need::Prober;
use agentos_app::provisioning::{EngineConfig, ProvisioningEngine};
use agentos_app::revenue::Seller;
use agentos_app::turn::{Context, Turn};
use agentos_app::vertical::{self, Charter};
use agentos_app::{inbound, mocks};
use agentos_domain::action::Domain;
use agentos_domain::employee::{Employee, Lifecycle};
use agentos_domain::ids::{EmployeeId, Slug, TenantId};
use agentos_providers::ProviderError;
use agentos_providers::llm::{Content, Llm, LlmRequest, LlmResponse, Message, Usage};
use agentos_providers::llm_cli::CliLlm;
use agentos_store::db::Db;
use agentos_store::{employee as employee_store, org, policy, revenue, spend};
use async_trait::async_trait;
use chrono::Utc;
use tokio_util::sync::CancellationToken;

use crate::cost::{self, PROSPECT, Sample, TURN_BRIEF, charters, limits};
use crate::scoping::{Weighed, weigh};
use crate::{Row, Surface, Truth};

/// The production resolution, re-used rather than restated: a seat's role pack
/// names a model and its policy bounds it.
use agentos_domain::policy::model_for;

/// A mock deployment's envelope key. Real crypto over a throwaway key: the
/// identity step seals a private key with it and would otherwise not run.
const MASTER_KEY: &str = "dryrun-master-key-0123456789abcdef";

/// What `scoping.rs` predicts one model call weighs, so the measurement has
/// something to disagree with. Input tokens at ten staff, and it is the **first**
/// round trip of a turn — `scoping.rs` lists "growth WITHIN a run" as one of the
/// things it does not measure, which is precisely the term [`report_rounds`]
/// fills in.
///
/// It lives here and not in [`crate::cost`] on purpose: `cost.rs` holds the rate
/// card and the arithmetic that turns tokens into money, and this is neither. It
/// is a prediction by another suite in this same crate, kept next to the run that
/// checks it.
///
/// **It has moved three times and a copy of it in `docs/ORIZN.md` did not.**
/// 4,639 when the tenant's whole MCP inventory sat in the prefix; 4,611 once
/// `SystemPrompt::with_mcp_tools` scoped it to the employee's policy; **4,701**
/// since the catalogue grew `read_page` and `brief_direct_reports`. Run
/// `cargo run -p agentos-eval` — no key, no network — and if its
/// `app::prompt (cost)` row disagrees with this number, that row is right.
const PREDICTED_TOKENS_PER_CALL: f64 = 4_701.0;

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

impl Call {
    /// Generated tokens, as the provider reported them. A call that failed
    /// generated nothing we were billed for, so it is a real zero — and every
    /// average over these has to say whether it counted the zeros, for the
    /// reason [`Ran::intact`] gives one screen down.
    fn output(&self) -> u64 {
        self.out.as_ref().map_or(0, |out| out.usage.output_tokens)
    }

    /// Did this round ask for a tool, or only talk?
    ///
    /// This is the whole question behind "how many model calls does a turn
    /// take". A round that calls a tool is the loop earning its cost: something
    /// happened, its result came back, and the next round is reading it. A round
    /// that produces prose and is followed by another round is a thought, billed
    /// at five times the input rate.
    fn acted(&self) -> bool {
        self.out.as_ref().is_ok_and(|out| {
            out.content
                .iter()
                .any(|block| matches!(block, Content::ToolUse { .. }))
        })
    }
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
    /// The mock providers, **built once and shared by every turn**.
    ///
    /// It used to be `mocks::ports()` called per turn, which was equivalent
    /// while nothing in a turn had state worth keeping. The browser does:
    /// `MockBrowser`'s page map is what makes a probe find something rather
    /// than error, and its step log is the only record of what the vertical
    /// actually did with somebody's booking flow — the model's own tool calls
    /// are in the transcript, and the prober's are not.
    ports: Arc<Ports>,
    /// The same browser again, by its own type, for [`mocks::MockBrowser::log`].
    browser: Arc<mocks::MockBrowser>,
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

/// Steps 2 through 6 of `docs/ORIZN.md`, in order, against a real database —
/// and then `passes` prospects for the seller to work, one per pass.
async fn stand_up(db: Db, passes: usize) -> Company {
    let now = Utc::now();
    let tenant = TenantId::new_v7(now);
    let domain = Domain::parse("agents.orizn.app").expect("the org document's domain");

    // 2. the ceiling. Before this the gate refuses everything, which is the
    //    safe direction and the first thing an operator sees.
    policy::install_ceiling(&db, &limits("orizn-ceiling.json"), "orizn dry run")
        .await
        .expect("install the ceiling");

    // 3. the tenant — and the active policy version its layers hang off.
    //
    // `"orizn"` is a literal and `tenants.slug` is UNIQUE, which is one of the
    // two reasons a second `--dry-run` against the same database cannot start.
    // See [`run`]: the fix is an empty database, not a unique slug here — the
    // other collision is downstream in provisioning and making this one unique
    // only moves the panic.
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
    //
    // # The stop is not on this path, and that is not a hole
    //
    // `converge` is called directly, so `loops::provisioning`'s `CLAIM_SQL` —
    // and with it `not_stopped!`, the company halt and the operating window —
    // never runs here. Somebody will notice that and ask whether a dry run
    // provisions a company an operator stopped. Three independent answers, and
    // the first is the one that settles it:
    //
    // * **There is no stopped company to skip.** This function does not take a
    //   company, it *builds* the one it measures: the tenant id is minted at
    //   the top of this function and the row created at step 3, in a database
    //   this module refuses to share (`EMPTY_DATABASE`), and nothing writes
    //   `company_halts` or `company_windows`. A dry run cannot be pointed at a
    //   halted tenant the way the loop can.
    // * **Nothing is bought.** These eleven steps call `mocks::adapters`, so a
    //   converge that ran for a stopped company would spend nothing, reach
    //   nobody, and hold no resource anyone is billed for.
    // * **The stop still bites where it decides anything.** `PolicyGate` reads
    //   `halt::halted` before any policy and `model_access::connected` reads it
    //   before a turn is reserved — every turn `take_turn` takes goes through
    //   both. A halt thrown while a dry run is in flight stops the actions and
    //   the model calls, which is the half of a dry run that costs money.
    //
    // And it could not simply be moved into `converge` either: `CLAIM_SQL`
    // exempts the lapsed-lease row from the stop on purpose, because `converge`
    // is the only thing in this workspace that closes an orphaned provider
    // intent. A halt check inside the engine would strand exactly the row that
    // exemption exists to rescue. The stop belongs to the claim, and the claim
    // is what a dry run deliberately stands in for.
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

    // **Both amounts read off `docs/orizn-roles/finance.json`, not typed here.**
    //
    // They used to be `usd_minor(100_000)` and `usd_minor(50_000)` — a second
    // copy of the finance layer's own `max_per_day` and `max_per_transaction`,
    // typed out fifteen lines under the loop that installs that very layer from
    // the file. No assertion could sensibly have been put on that copy: this
    // module is behind `--features live-orizn`, so `scripts/test.sh` never
    // *runs* a line of it, and a test written in here would be a test that
    // never runs. A number the suite cannot see is not made safe by an
    // assertion the suite cannot see either; it is made safe by not existing
    // twice.
    //
    // The half of that sentence about *compiling* was true when it was written
    // and is not any more, and closing it was the point: `scripts/test.sh` now
    // ends with a second `cargo clippy --workspace --all-targets
    // --all-features`, so this module is type-checked and linted on every run
    // while still executing nothing. What that buys is a rename underneath it
    // failing the build. What it still cannot buy is an assertion, because
    // checking is not running — so the argument above stands unchanged.
    //
    // Read from the document, the numbers are covered by what already guards
    // that document: `cost::digest` hashes every byte of every file in
    // `docs/orizn-roles/`, and `eval::tests::every_correctness_check_passes`
    // fails when the hash leaves `cost::DIGEST` behind — in the default build.
    // And the dry run now measures the company `docs/ORIZN.md` describes even
    // when somebody edits that document, which is the point of reading it.
    let caps = limits("orizn-roles/finance.json")
        .spend
        .expect("finance is the only one of the five role layers that carries a spend row");
    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
    org::set_budget(&mut tx, finance.2, caps.max_per_day())
        .await
        .expect("team budget");
    spend::set_caps(
        &mut tx,
        finance.1,
        spend::SpendCaps::new(
            caps.max_per_day(),
            caps.max_per_transaction(),
            // The third number is *not* derived, and `docs/ORIZN.md` says why in
            // as many words: "`daily_transactions: 2` is not a redundant copy of
            // the money caps". It is the count that keeps binding on a day of
            // three $10 payments, which the money caps never notice.
            std::num::NonZeroU32::new(2).expect("two"),
        )
        .expect("caps"),
    )
    .await
    .expect("spend caps");
    tx.commit().await.expect("commit finance");

    // 7. and the seller's prospects — not a step in `docs/ORIZN.md` because the
    //    operator's step is `agentos-server import` against a list this
    //    repository does not ship, followed by `agentos-server flow set` /
    //    `flow confirm` per prospect. Same rows, written the same way: two on
    //    the application's credential and one on the operator's.
    let sdr = seats
        .iter()
        .find(|(slug, ..)| *slug == "sdr")
        .expect("the sales seat")
        .1;
    for nth in 1..=passes {
        seed_prospect(&db, tenant, sdr, nth).await;
    }

    // The browser the vertical will actually drive, with the prospect's panel on
    // it. One instance for the whole run: `mocks::ports()` mints a fresh
    // `MockBrowser` every call, and a page set on one of those is invisible to
    // the next.
    let browser = Arc::new(mocks::MockBrowser::new());
    // One entry, and `set_text`'s last entry repeats — so both runs of the flow
    // read the same thing, which is what `proof_of_need`'s two-run bar is
    // looking for. A second, different entry here is how a flaky widget is
    // spelled, and it would measure `Checked::NotReproducible` instead.
    browser.set_text(PROSPECT.panel, &[PROSPECT.says]);
    let ports = Arc::new(Ports {
        browser: browser.clone(),
        ..mocks::ports()
    });

    Company {
        db,
        tenant,
        seats,
        ports,
        browser,
    }
}

/// One prospect the seller can honestly work: an account, a person at it, and a
/// booking flow with a human's name on it.
///
/// **Three writes and two connections**, and the split is the product's rather
/// than this fixture's. The account and the contact are ordinary application
/// rows and go in on a tenant transaction. The flow does not:
/// `migrations/0032_prospect_flows.sql` grants `app_role` no INSERT and no
/// UPDATE on `prospect_flows` at all, because an employee that could write that
/// table could aim a selector at any element on a domain its policy lets it read
/// and then produce a screenshotted, reproducible finding about whatever that
/// element happened to say. Writing one is an operator's act proved by the
/// operator's own database credential — `agentos-server flow set` / `flow
/// confirm` — and [`revenue::set_prospect_flow`] is the same pair of functions
/// that verb calls. A fixture that wrote this row as the application would be
/// asserting a privilege the product deliberately withholds.
///
/// `confirm_prospect_flow` is not decoration either. `set_prospect_flow` always
/// writes an **unconfirmed** row — and re-writing a confirmed one revokes the
/// confirmation, in a trigger — while `proof_of_need::Flow::confirmed` refuses a
/// row nobody put a name on. Skip the second call and this seeds a prospect the
/// seller correctly skips, and the dry run goes back to measuring nothing while
/// looking like it measured something.
async fn seed_prospect(db: &Db, tenant: TenantId, sdr: EmployeeId, nth: usize) {
    let domain = PROSPECT.domain(nth);
    let contact = PROSPECT.contact(nth);
    let account = uuid::Uuid::now_v7();

    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
    revenue::insert_account(
        &mut tx,
        account,
        &revenue::NewAccount {
            legal_name: PROSPECT.name,
            domain: &domain,
            // `charters()` sells to `Segment::Airline`, and
            // `vertical::segment_column` maps that to this string. A different
            // one here is an empty queue, which reads as no work.
            segment: "airline",
            // The objective's market. Nothing filters on it — the queue is by
            // segment — but a prospect in the wrong country is a fixture that
            // does not match the briefing the model is reading.
            country: "DE",
            employee_id: Some(sdr),
            location: None,
            website: None,
        },
    )
    .await
    .expect(EMPTY_DATABASE);
    revenue::insert_contact(
        &mut tx,
        uuid::Uuid::now_v7(),
        &revenue::NewContact {
            account_id: account,
            full_name: "Head of Digital",
            email: Some(&contact),
            phone: None,
            role: Some("Head of Digital"),
            language: Some("de"),
            is_primary: true,
            // B2B prospecting in the EU needs one, recorded per person. The
            // column has a CHECK; this is the value the importer writes.
            lawful_basis: "legitimate_interest",
            // `None`, and it is the difference between a first touch and a
            // chase: `vertical::due_chase` asks for contacts with at least one
            // touch already, and `prospects::import` primes this column on every
            // row it lands. A date here would put a person nobody has written to
            // at the head of the follow-up queue.
            next_follow_up_at: None,
        },
    )
    .await
    .expect("the prospect's contact");
    // Committed before the flow, not after: the flow is written on a different
    // connection and its composite foreign key has to be able to see the
    // account.
    tx.commit().await.expect("commit the prospect");

    let entry = format!("https://{domain}{}", PROSPECT.entry_path);
    revenue::set_prospect_flow(
        db,
        tenant,
        account,
        &revenue::NewProspectFlow {
            entry_url: &entry,
            passport_field: PROSPECT.passport_field,
            destination_field: PROSPECT.destination_field,
            date_field: Some(PROSPECT.date_field),
            submit: Some(PROSPECT.submit),
            panel: PROSPECT.panel,
        },
    )
    .await
    .expect("write the prospect's flow");
    let confirmed =
        revenue::confirm_prospect_flow(db, tenant, account, "orizn dry run", Utc::now())
            .await
            .expect("confirm the prospect's flow");
    assert!(
        confirmed,
        "the flow was written and then not found to confirm"
    );
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
    /// What the vertical did before the model was asked anything, for the one
    /// charter that has one.
    vertical: Option<Vertical>,
}

/// The vertical half of a turn: what it came to, and what it touched.
///
/// Kept beside the model's tape rather than folded into it because they are
/// different measurements. Every [`Call`] above is a round trip to a language
/// model; none of this is. A selling turn runs somebody else's booking flow
/// twice, takes a screenshot, files a row and attempts an email **before** the
/// first token is generated, and a report that only counted model calls would
/// price that work at zero.
struct Vertical {
    /// `Sold::code`, `Chased::outcome.code`, or the error's code — a closed
    /// vocabulary either way.
    outcome: &'static str,
    /// Did a finding reach a row a human can read?
    filed: bool,
    /// Every browser step the prober ran, in order, as the mock logged it.
    /// Empty for a chase, which never opens their page — deliberately.
    steps: Vec<String>,
    /// The trusted sentence the model was handed, if there was one.
    note: Option<String>,
}

/// Assemble one employee exactly as `loops::initiative::take_turn` does, and
/// run it — **vertical included**.
///
/// Everything that decides what the employee may *do* — principal, gate,
/// effects, prompt, schemas — is the same call in the same order, and the
/// vertical now runs before the model in the same place `vertical_step` runs it,
/// out of the same `Effects` the turn is built on.
///
/// Two differences from `apps/server` remain and neither can be closed from
/// here. `assignment_for` resolves the seller's work **before** the turn is
/// reserved, so a seller with nothing due costs nothing; this has no reservation
/// to be before, so [`vertical`] reads the same two queues inside the turn and a
/// `None` is reported rather than skipped. And a vertical that fails is logged
/// and swallowed there, where the employee still has a turn worth taking; here
/// it is counted as a failure, because a dry run that quietly degraded to an
/// ordinary turn is exactly how the seller went unmeasured for three days.
async fn take_turn(
    company: &Company,
    seat: &'static str,
    charter: &Charter,
    model: Option<&str>,
) -> Ran {
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

    // **The seam this dry run exists to work.** `apps/server` does exactly this
    // and the numbers below are worthless if the dry run does something else:
    // the pack proposes, the policy layer decides, and what the CLI is handed is
    // the intersection. `--model` overrides every seat at once, which is how you
    // score the same company on one model rather than on the five it runs.
    let preferred = charter.model();
    let model = model.map_or_else(
        || {
            model_for(policy.as_ref(), preferred)
                .unwrap_or_else(|| {
                    panic!(
                        "{seat}: `allowed_models` intersected to the empty set, so this seat \
                         cannot take a turn — see docs/orizn-roles/*.json"
                    )
                })
                .as_str()
                .to_owned()
        },
        ToOwned::to_owned,
    );

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

    let effects = Effects::new(company.db.clone(), company.ports.clone(), principal.clone());

    // The vertical, before the model and never instead of it — the same order
    // `loops::initiative::take_turn` uses, and the reason a selling turn's
    // opening message is a report of work already done rather than an
    // instruction to go and do it.
    let started = Instant::now();
    let vertical = vertical(
        company,
        &effects,
        &principal,
        &stored.employee.address().to_string(),
        &charter,
    )
    .await;

    let llm = Arc::new(Recorder {
        inner: CliLlm::new(),
        calls: Mutex::new(Vec::new()),
    });
    let turn = Turn::new(
        llm.clone(),
        PolicyGate::new(company.db.clone()),
        effects,
        prompt,
        model.as_str(),
        stored.employee.address().to_string(),
    );

    // The vertical's note goes after the plan, exactly as it does in the running
    // system, and it is ours as thoroughly as the plan is: parsed addresses,
    // closed reason codes, and not one byte of the prospect's page.
    let mut context = Context::new()
        .with_task(TURN_BRIEF)
        .with_task(charter.brief());
    if let Some(note) = vertical.as_ref().and_then(|ran| ran.note.clone()) {
        context = context.with_task(note);
    }

    let outcome = turn.run(context, &CancellationToken::new()).await;
    // **From before the vertical**, so this is what an operator waits: a selling
    // turn that runs somebody's booking flow twice before it thinks is slower
    // than a turn that only thinks, and a clock started after the probe would
    // report the two as the same product.
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
        vertical,
    }
}

// ---------------------------------------------------------------------------
// The vertical, before the model
// ---------------------------------------------------------------------------

/// `loops::initiative::vertical_step`, for the charter that has one.
///
/// A copy and not a call, for the reason `TURN_BRIEF` *used* to be a copy: it
/// lives in a binary crate with no library target. `TURN_BRIEF` stopped being
/// one — it moved to `agentos_app::brief` when `toolchoice`'s pin needed to hash
/// it — and this could follow it the day something needs to. Nothing does: a
/// digest of prose is a thing the eval wants, a digest of a scheduling branch is
/// not. What is *not* copied is any part of
/// the decision — [`vertical::due_chase`] and [`vertical::due_prospect`] are the
/// same two queries `sales_work_for` asks in the same order, and
/// [`vertical::selling_turn`] and [`vertical::chasing_turn`] are the same two
/// entry points. Everything that decides what happens to a prospect is in
/// `crates/app`, where both callers can reach it.
///
/// **The chase is asked first**, which is `sales_work_for`'s order and its
/// argument: it is a promise already made, and it is the cheaper turn by a wide
/// margin — a probe is two full runs of somebody else's booking flow plus a
/// screenshot, a chase is one email built from our own columns.
///
/// The four service charters have no vertical operation to call — there is no
/// `vertical::support_turn` — so they take the ordinary turn they always took.
async fn vertical(
    company: &Company,
    effects: &Effects,
    principal: &Principal,
    address: &str,
    charter: &Charter,
) -> Option<Vertical> {
    let Charter::Sales { pack, objective } = charter else {
        return None;
    };
    let now = Utc::now();

    let mut tx = company
        .db
        .tenant_tx(company.tenant)
        .await
        .expect("tenant tx");
    let chase = vertical::due_chase(&mut tx, objective, now)
        .await
        .expect("read the follow-up queue");
    let prospect = match chase {
        Some(_) => None,
        None => vertical::due_prospect(&mut tx, objective, now)
            .await
            .expect("read the prospect queue"),
    };
    // Read-only, and rolled back before a page of the prospect's is loaded: the
    // check is several seconds of somebody else's website and a pooled
    // connection held across it is a connection held across their latency.
    let _ = tx.rollback().await;

    // Both branches build one, and the suppression list is loaded rather than
    // defaulted in either: `vertical::suppression_for` asks the schema's own
    // `SECURITY DEFINER` lookup — the only reader that can see a *global*
    // opt-out, which the per-tenant RLS policy hides from an ordinary SELECT —
    // and fails closed. An empty one here would be a fixture quietly granting
    // itself permission to write to somebody who said no.
    let seller = |suppression| {
        Seller::new(
            PolicyGate::new(company.db.clone()),
            effects.clone(),
            principal.clone(),
            address.to_owned(),
            suppression,
        )
    };

    if let Some(chase) = chase {
        let seller = seller(vertical::suppression_for(&company.db, principal, &chase.to).await);
        return Some(
            match vertical::chasing_turn(&company.db, &seller, principal, &chase, now).await {
                Ok(chased) => Vertical {
                    outcome: chased.outcome.code(),
                    filed: false,
                    // Empty, and it is an assertion rather than an omission: a
                    // chase re-asserts nothing about the prospect's product, so
                    // it opens no page. A step here would be the one mistake in
                    // this job that cannot be walked back.
                    steps: Vec::new(),
                    note: Some(chased.note()),
                },
                Err(err) => Vertical {
                    outcome: coded("the chase did not run", &err.to_string()),
                    filed: false,
                    steps: Vec::new(),
                    note: None,
                },
            },
        );
    }

    // **Reported, never silent.** `assignment_for` answers this with
    // `Outcome::NoWork` and spends no turn, which is right there. Here it means
    // the fixture failed: [`stand_up`] seeded one prospect per pass, so a seller
    // with nothing due has a flow nobody confirmed, a segment nobody imported
    // into, or an account something already filed evidence against — and a
    // `None` returned quietly would be indistinguishable from a service charter
    // that simply has no vertical, which is exactly how this went unnoticed
    // before.
    let Some(prospect) = prospect else {
        return Some(Vertical {
            outcome: "no_work",
            filed: false,
            steps: Vec::new(),
            note: None,
        });
    };
    // The employee's own browser context, as provisioning left it. A `Prober`
    // takes the session rather than looking one up — a browser context is a
    // provisioned resource — so this is where the two meet.
    let session = effects
        .browser_session()
        .await
        .expect("provisioning left this seller a browser context");
    let seller = seller(vertical::suppression_for(&company.db, principal, &prospect.to).await);
    let prober = Prober::new(
        company.db.clone(),
        PolicyGate::new(company.db.clone()),
        effects.clone(),
        principal.clone(),
        session,
    );

    // Everything the mock browser did during the probe, and nothing it did
    // before: the model's `read_page` calls run through the same instance.
    let before = company.browser.log().len();
    let worked = vertical::selling_turn(
        &company.db,
        &prober,
        &seller,
        principal,
        pack,
        objective,
        &prospect,
        now,
    )
    .await;
    let mut log = company.browser.log();
    let steps = log.split_off(before);

    Some(match worked {
        Ok(worked) => Vertical {
            outcome: worked.sold.code(),
            filed: worked.filed.is_some(),
            steps,
            note: Some(worked.note()),
        },
        Err(err) => Vertical {
            outcome: coded("the sales vertical did not run", err.code()),
            filed: false,
            steps,
            note: None,
        },
    })
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
        // Two cases under one heading, because the sentence is deliberately one
        // sentence: `Turn::propose` answers a name outside this turn's offer
        // exactly as it answers a name nobody has ever heard of, so that a
        // refusal cannot be read as "that exists, but not for you". A counter
        // here that split them would be an existence oracle with a report.
        "asked for a tool it was not offered"
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

    // The vertical first, because it happened first — and because it is the
    // half of a selling turn that no `Call` below can show. The steps are the
    // prober's, in order, as the mock browser logged them: this is the only
    // record of what was done to somebody else's booking page.
    if let Some(vertical) = &ran.vertical {
        println!(
            "    vertical  {} · finding {} · {} browser step(s)",
            vertical.outcome,
            if vertical.filed { "filed" } else { "none" },
            vertical.steps.len()
        );
        for step in &vertical.steps {
            println!("        · {step}");
        }
        match &vertical.note {
            Some(note) => println!("      ⟦trusted note⟧ {}", first_line(note, 200)),
            None => {
                failures.push("the vertical did not run and the seller fell back to talking");
                println!("      ! no note: this turn had no vertical half after all");
            }
        }
    }

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
            "    call {}  {:>5.1}s  prompt≈{} tok (sys {} + tools {} + msgs {})  out {} tok  \
             offered [{}]",
            i + 1,
            call.elapsed.as_secs_f64(),
            w.total(),
            w.system,
            w.tools,
            w.messages,
            call.output(),
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
///
/// An iterator rather than a slice so the same arithmetic answers "this pass"
/// and "this pass's seller", which are two different questions with the same
/// three numbers. See the seller's own row in [`verdict`].
fn sample<'a>(turns: impl Iterator<Item = &'a Ran>) -> Option<Sample> {
    let billed: Vec<&Ran> = turns.filter(|ran| ran.intact()).collect();
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
    let samples: Vec<Sample> = passes
        .iter()
        .filter_map(|pass| sample(pass.iter()))
        .collect();
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
        .note(if samples.is_empty() {
            "input by `scoping::tokens` over OUR bytes, not the CLI's — it bills its own prefix"
                .to_owned()
        } else {
            // The prediction is a ten-employee fixture with an MCP server bound
            // and Orizn binds none, so measuring UNDER it is the expected
            // direction. Printed as a percentage because the sign is the
            // finding: `docs/ORIZN.md` billed the input side pessimistically
            // and the output side out of thin air, and only one of those two
            // errors was in the operator's favour.
            format!(
                "input by `scoping::tokens` over OUR bytes, not the CLI's; \
                 {:+.0}%–{:+.0}% against `scoping`'s {PREDICTED_TOKENS_PER_CALL:.0} at ten staff",
                (in_lo / PREDICTED_TOKENS_PER_CALL - 1.0) * 100.0,
                (in_hi / PREDICTED_TOKENS_PER_CALL - 1.0) * 100.0,
            )
        }),
    );

    // --- sampled: the money -------------------------------------------------
    // A sum over seats, each at its own model's rates — `cost::company_usd` owns
    // that arithmetic and this row is a reader of it. It used to be one
    // multiplication by the summed turn budget, which was right while one model
    // served every seat and is a category error now.
    let day = f64::from(cost::turns_per_day());
    let bill: Vec<f64> = samples.iter().map(|s| cost::measured_usd(*s)).collect();
    let (bill_lo, bill_hi) = spread(&bill);
    let floor = spread(
        &samples
            .iter()
            .map(|s| cost::company_usd(*s, cost::FLOOR_CALLS_PER_TURN))
            .collect::<Vec<_>>(),
    )
    .0;
    let ceiling = spread(
        &samples
            .iter()
            .map(|s| cost::company_usd(*s, cost::ceiling_calls_per_turn()))
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
            "at {day} reserved turns a day across {}, from docs/orizn-roles/*.json; \
             arithmetic in `cost.rs`",
            cost::seats()
                .iter()
                .filter(|s| s.turns > 0)
                .map(|s| format!("{} on {}", s.role, s.model))
                .collect::<Vec<_>>()
                .join(", ")
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
    // --- sampled: the seller on its own -------------------------------------
    // **The row this dry run grew a vertical for.** A selling turn runs
    // somebody's booking flow twice, files a finding and attempts an email
    // before the model generates its first token, and then opens with a report
    // of work already done rather than a plan to go and do it. That is a
    // different shape of turn from a buyer's, and averaging the two hides
    // exactly the thing the change was made to see.
    //
    // Characterised, like every other number here, and it must be: a seller that
    // asked for three calls where a supporter asked for six is a sample from a
    // model, not a property of this code. What IS structural about the seller is
    // already covered — its turn reached the model, it called tools, and every
    // call got a ruling, on the four rows above.
    let selling: Vec<Sample> = passes
        .iter()
        .filter_map(|pass| sample(pass.iter().filter(|ran| ran.vertical.is_some())))
        .collect();
    let (sell_lo, sell_hi) = spread(&selling.iter().map(|s| s.calls_per_turn).collect::<Vec<_>>());
    let filed = runs
        .iter()
        .filter(|r| r.vertical.as_ref().is_some_and(|v| v.filed))
        .count();
    let probes: usize = runs
        .iter()
        .filter_map(|r| r.vertical.as_ref())
        .map(|v| v.steps.len())
        .sum();
    rows.push(
        Row::ok(
            "the selling turn on its own",
            if selling.is_empty() {
                "no seller took a turn with a vertical half".to_owned()
            } else {
                format!(
                    "{sell_lo:.2}–{sell_hi:.2} model calls, {filed} finding(s) filed, {probes} \
                     browser step(s)",
                )
            },
            Truth::Characterises,
        )
        .note(
            "the browser steps are the prober's and happened before the first token; the model \
             calls are what it did afterwards, having been told what it found",
        ),
    );
    let outcomes: Vec<&str> = runs
        .iter()
        .filter_map(|r| r.vertical.as_ref())
        .map(|v| v.outcome)
        .collect();
    rows.push(
        Row::ok(
            "…and what the vertical came to",
            if outcomes.is_empty() {
                "no vertical ran".to_owned()
            } else {
                outcomes.join(", ")
            },
            Truth::Characterises,
        )
        .note(
            "`sent` is what this row said `contact_budget_exhausted` for as long as \
             docs/orizn-roles/sales-development.json carried `max_new_contacts_per_day: 0`. The \
             operator raised it to five on 2026-08-26 and the approach goes out — five being \
             what one founder can read in a day, which is the binding constraint while the \
             queue is loaded into Smartlead by hand. `did not run: no_rule` is the third thing \
             this row can say and it is never a boundary: it means the seller could not probe \
             at all, and the one way to earn it is an empty `allowed_domains`, because `Prober` \
             types into the prospect's form and typing is a write",
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
            "the BUYER's vertical — and it is in no figure above either, which this line used to \
             get backwards. `vertical::purchasing_turn` needs `suppliers` rows to canvass, then an \
             open `rfqs` row and `quotes` against it to compare, and no charter here is a buyer's. \
             There is also nothing to seed them WITH: every writer of `suppliers`, \
             `supplier_contacts` and `quotes` in this workspace lives inside a `mod tests`, and \
             no CLI verb or route creates one — where the seller had `agentos-server flow set` \
             and `revenue::set_prospect_flow` to copy, the buyer's ingest half does not exist. \
             What is NOT true is that the seat is billed: `cost::seats()` reads \
             `docs/orizn-roles/*.json` and there is no `international-buyer.json`, so \
             `cost::preference`'s buyer arm is as dead as its `engineering` one and the seat \
             contributes exactly $0. `docs/ORIZN.md` says why, in a section called `the pack Orizn \
             does not need`: Orizn sources nothing, so a purchasing round seeded here would be \
             invented suppliers quoting invented prices, and the number it produced would be about \
             a company nobody deployed. What DOES work the buy side is \
             `apps/server/tests/sourcing_e2e.rs` — the real binary, a real database, a whole \
             round on a scripted model — and `vertical.rs`'s own database-backed tests of \
             `purchasing_turn`. So what nothing covers is a real model taking a purchasing turn, \
             not the vertical itself. The seller's vertical is run",
            "`growth`, which IS priced and is worked nowhere — the shape the line above wrongly \
             attributed to the buyer. `docs/orizn-roles/growth.json` reserves 10 of the 66 \
             reserved turns a day the bill is summed over, on `claude-sonnet-5`, and \
             `cost::charters()` charters `sdr`, `support` and `books` only. So growth's share of \
             every dollar figure here is those three seats' tokens multiplied by growth's turn \
             budget, and `rolepack_service::RolePack::growth()`'s own prompt and plan have never \
             been weighed by anything. `direction` is the honest neighbour: no charter and no \
             turns, so it contributes nothing to extrapolate",
            "whether one seeded prospect is a pipeline. The seller works a real flow through the \
             real prober, and it works the same one shape every pass: a confirmed flow, a panel \
             that reproduces, no MCP authority. Nothing here samples a flaky widget, a bot \
             challenge, or a prospect whose page was fixed between passes",
            "the gate's reach on a real prospect. `docs/orizn-ceiling.json` allows exactly one \
             domain and `docs/ORIZN.md` says that is where a prospect list would be added, so the \
             seeded prospect lives under `orizn.app`. What is measured is the probe; whether this \
             operator has granted a real airline's domain is a ceiling change nobody has made",
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
        let Some(s) = sample(pass.iter()) else {
            continue;
        };
        println!(
            "    Sample {{ calls_per_turn: {:.2}, input_tokens_per_call: {:.1}, \
             output_tokens_per_call: {:.1} }},",
            s.calls_per_turn, s.input_tokens_per_call, s.output_tokens_per_call
        );
    }
    println!("];");
    println!("pub const DIGEST: &str = \"{}\";", cost::digest());
}

/// **The per-round picture.** `scoping.rs` weighs the *first* round trip of a
/// turn and lists "growth WITHIN a run" as the largest thing nobody has numbers
/// for. This is that number.
///
/// One row per round *index*, across every turn that got that far, because the
/// per-turn average hides the only thing worth knowing: round 1 is a fixed
/// prefix and a two-paragraph brief, and round 10 is that same prefix plus nine
/// rounds of transcript the loop resends in full. A turn averaging 2.5 rounds
/// does not cost 2.5 one-round turns, and the `msgs` column is why.
///
/// Measured across three passes: the prefix (`sys` + `tools`) holds near 2,500
/// tokens while `msgs` climbs 589 → 3,902, so the growth is entirely history and
/// the fixed part is entirely cacheable. `app::turn`'s
/// `each_round_extends_the_previous_prompt_instead_of_rewriting_it` is what
/// keeps it that way on the production path.
///
/// `acted` is the other half, and the one that says whether a round was work: a
/// round that asks for a tool is the loop earning its cost, and a round that
/// only talks is a thought. `out` averages **only calls that came back**, for
/// [`Ran::intact`]'s reason — a provider error contributes a zero that looks
/// exactly like a short answer — so `died` is printed beside it rather than
/// folded into it.
fn report_rounds(passes: &[Vec<Ran>]) {
    let runs: Vec<&Ran> = passes.iter().flatten().collect();
    let depth = runs.iter().map(|ran| ran.calls.len()).max().unwrap_or(0);
    if depth == 0 {
        return;
    }

    println!("\n─────────────────────────────────────────────────────────────");
    println!("PER ROUND — what the calls-per-turn multiplier actually buys\n");
    println!("  round  turns   prompt≈   of which msgs     out   acted   died   median wall");
    for round in 0..depth {
        let calls: Vec<&Call> = runs.iter().filter_map(|ran| ran.calls.get(round)).collect();
        let returned: Vec<&&Call> = calls.iter().filter(|c| c.out.is_ok()).collect();
        let n = calls.len() as f64;
        let mut walls: Vec<f64> = calls.iter().map(|c| c.elapsed.as_secs_f64()).collect();
        walls.sort_by(f64::total_cmp);
        println!(
            "  {:>5}  {:>5}  {:>8.0}  {:>14.0}  {:>6}  {:>3}/{:<3}  {:>4}  {:>9.1}s",
            round + 1,
            calls.len(),
            calls.iter().map(|c| c.weighed.total()).sum::<usize>() as f64 / n,
            calls.iter().map(|c| c.weighed.messages).sum::<usize>() as f64 / n,
            if returned.is_empty() {
                "—".to_owned()
            } else {
                format!(
                    "{:.0}",
                    returned.iter().map(|c| c.output()).sum::<u64>() as f64 / returned.len() as f64
                )
            },
            calls.iter().filter(|c| c.acted()).count(),
            calls.len(),
            calls.len() - returned.len(),
            walls[walls.len() / 2],
        );
    }

    // Where the output actually went, which is the line that decides whether the
    // loop is working or thinking. On the CLI shim the model's whole reply is
    // one JSON object, so a round that acted spent its output on a tool's
    // arguments — an email body is work — and a round that did not spent it on
    // prose. Only rounds that came back, again: averaging a rejected call's zero
    // into the prose figure understates the exact quantity this split exists to
    // expose, and the first version of this line did, by 40%.
    let (acted, idle): (Vec<&Call>, Vec<&Call>) = runs
        .iter()
        .flat_map(|ran| ran.calls.iter())
        .filter(|c| c.out.is_ok())
        .partition(|c| c.acted());
    let mean = |group: &[&Call]| {
        if group.is_empty() {
            return 0.0;
        }
        group.iter().map(|c| c.output()).sum::<u64>() as f64 / group.len() as f64
    };
    println!(
        "\n  output on the {:>2} rounds that called a tool     {:>6.0} tok/call — arguments, and \
         arguments are work",
        acted.len(),
        mean(&acted)
    );
    println!(
        "  output on the {:>2} rounds that only wrote prose  {:>6.0} tok/call — a thought, billed \
         at 5× the input rate",
        idle.len(),
        mean(&idle)
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
/// Returns whether the **structural** rows passed — see [`verdict`]. `false` is
/// an exit code, because a run in which nothing called a tool is a broken system
/// and a report nobody reads is how it stayed broken for three days.
///
/// **One empty database per invocation, and it is not a preference.** This used
/// to say re-running "adds a company rather than replacing one", which is what
/// a fresh `TenantId` every time looks like it should buy. It does not: the
/// second invocation panics `Conflict("tenants_slug_key")` on the literal slug
/// `"orizn"`, and making *that* unique only moves the panic one step to
/// `Conflict("employee_resources_provider_external_id_key")` in provisioning,
/// because the mock adapters derive an external id from the employee slug and
/// this document seats the same five slugs every time. [`EMPTY_DATABASE`] is
/// the message a caller gets when they forget.
///
/// It is worth naming rather than shrugging at, because of what this instrument
/// is for. A model is a sample: one dry run is one draw, and the only question
/// it can settle — did a change move anything? — needs two. Whoever compares
/// them has to remember `createdb` in between or the second run dies in the
/// first three seconds, with a Postgres constraint name for a message.
/// `--dry-run` is the deliverable here, so:
///
/// ```sh
/// createdb before && createdb after
/// ```
///
/// ponytail: two `createdb`s, not a per-run namespace. Threading a run id
/// through the tenant slug, the five employee slugs and whatever the mock
/// adapters key on is a change to the *company being stood up* to work around a
/// habit, and this run's whole claim is that it stands up the real one.
///
/// Passes *within* one invocation share a company, which is the point: it is the
/// same seats taking a second and third turn.
///
/// `runs` is the number of passes, and **three is the smallest useful number**:
/// one run of a language model is an anecdote, and every sampled row above is
/// printed as a spread across passes rather than as a figure.
pub async fn run(model: Option<&str>, runs: usize) -> bool {
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
    println!(
        "DRY RUN — Orizn, {runs} pass(es), {} via the local `claude` CLI",
        model.map_or_else(|| "each seat's own model".to_owned(), ToOwned::to_owned)
    );
    println!("Real: the ceiling, the tenant, the org chart, five role layers, the");
    println!("provisioning engine, the Policy Gate, the turn loop, the model.");
    println!("Mock: email, telephony, browser, payments — everything but the model.");
    println!(
        "Company digest {} — what these numbers are about.",
        cost::digest()
    );

    let company = stand_up(db, runs).await;
    let charters = charters();
    println!(
        "\nStood up: {} seats, {} of them given an objective, and {runs} prospect(s) under {} \
         with a confirmed booking flow — one per pass, because a filed finding takes an account \
         out of the queue for good.",
        company.seats.len(),
        charters.len(),
        PROSPECT.zone,
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
    report_rounds(&passes);

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
            vertical: None,
        }
    }

    /// The same turn with a vertical half in front of it.
    fn sold(calls: Vec<Call>) -> Ran {
        Ran {
            vertical: Some(Vertical {
                outcome: "refused",
                filed: true,
                steps: vec!["ctx-1 goto https://prospect-1.orizn.app/booking/entry".to_owned()],
                note: Some("their flow was run twice and it reproduced".to_owned()),
            }),
            ..ran(calls)
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

    /// **A rejected call generated nothing, and must not be averaged as if it
    /// generated a short answer.**
    ///
    /// [`report_rounds`] splits output tokens by whether the round asked for a
    /// tool, and that split is the evidence for where a turn's output goes. The
    /// first version of it counted provider errors as prose rounds of zero
    /// tokens, which understated the prose figure by 40% on a run where four of
    /// nine silent rounds were `cli_not_json` — the split then said the opposite
    /// of what the transcript said.
    #[test]
    fn a_call_that_never_returned_is_neither_work_nor_prose() {
        let died = call(None, Err("cli_not_json"));
        assert!(!died.acted(), "a call that failed asked for nothing");
        assert_eq!(died.output(), 0, "nothing was generated to bill");

        let acted = call(None, Ok(asked("t1")));
        assert!(acted.acted());
        assert_eq!(acted.output(), 40);

        let prose = call(None, Ok(said()));
        assert!(!prose.acted(), "a text-only round is a thought, not work");
        assert_eq!(prose.output(), 40);

        // The distinction the report rests on: `died` and `prose` both return
        // false from `acted`, so only `out.is_ok()` separates them — which is
        // why every average in `report_rounds` filters on it first.
        assert!(died.out.is_err() && prose.out.is_ok());

        // And it runs. `report_rounds` indexes turns of unequal depth and takes
        // a median of each round's wall clocks, so an off-by-one there is an
        // index panic — at the very end of a run that took fifteen minutes and
        // real money, after the transcript is printed and before it is gated.
        // Ragged depths, a turn that died on its first call, and no turns at all.
        report_rounds(&[vec![
            ran(vec![
                call(None, Ok(asked("t1"))),
                call(Some(answered("t1")), Ok(said())),
                call(None, Err("cli_not_json")),
            ]),
            ran(vec![call(None, Err("cli_not_json"))]),
            ran(vec![]),
        ]]);
        report_rounds(&[]);
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
        let s = sample(pass.iter()).expect("one intact turn");
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
        assert!(sample([ran(Vec::new())].iter()).is_none());
        assert!(sample(std::iter::empty()).is_none());

        let s = sample([healthy()].iter()).expect("two calls");
        assert!((s.calls_per_turn - 2.0).abs() < 1e-9);
        assert!((s.input_tokens_per_call - 2_000.0).abs() < 1e-9);
        // 80 output tokens over two calls.
        assert!((s.output_tokens_per_call - 40.0).abs() < 1e-9);
    }

    /// **The seller is reported on its own, and it is never gated.**
    ///
    /// The row exists because a turn that runs somebody's booking flow twice
    /// before it thinks is a different shape of turn from one that only thinks,
    /// and the pass average hides it. What it must NOT become is a threshold: a
    /// seller taking one model call where a supporter took six is a sample from
    /// a model, and a threshold on a sample is a flaky build.
    #[test]
    fn the_seller_is_reported_apart_from_the_seats_that_only_talked() {
        // One seller with a vertical, one seat without. The pass average is 1.5
        // calls a turn; the seller's own figure is 1.00, and both are printed.
        let pass = vec![
            sold(vec![call(Some(Message::user("go")), Ok(asked("t1")))]),
            healthy(),
        ];
        let surface = verdict(std::slice::from_ref(&pass), &[]);
        assert!(
            surface.passed(),
            "{}",
            crate::render(std::slice::from_ref(&surface))
        );
        let report = crate::render(&[surface]);
        assert!(report.contains("1.50–1.50 over 1 pass(es)"), "{report}");
        assert!(
            report.contains("1.00–1.00 model calls, 1 finding(s) filed, 1 browser step(s)"),
            "{report}"
        );
        assert!(report.contains("refused"), "{report}");

        // And a run with no seller at all says so rather than printing a zero
        // that reads like a measurement.
        let quiet = crate::render(&[verdict(&[vec![healthy()]], &[])]);
        assert!(
            quiet.contains("no seller took a turn with a vertical half"),
            "{quiet}"
        );
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
