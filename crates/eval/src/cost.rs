//! **What Orizn costs a month, computed once, from a run that happened.**
//!
//! # The problem this module exists for
//!
//! `docs/ORIZN.md` published **≈$76 a month**. It was arithmetic over three
//! numbers: 4,639 input tokens per model call, an assumed 600 output tokens, and
//! **one model call per reserved turn**. The first was measured by
//! [`crate::scoping`] and then moved; the second was a guess; the third was the
//! *floor* of a range that runs to ten, quoted as if it were an estimate. When
//! somebody finally ran the thing and counted, all three were wrong in the same
//! direction and the honest figure was several times what the document said.
//!
//! None of that was a bug. It is what happens when a number is typed into prose:
//! prose cannot be re-run, so it is right on the day it is written and drifts
//! silently forever after. This module is the fix, and it is small:
//!
//! * the arithmetic is [`Sample::monthly_usd`], one function, unit-tested;
//! * the inputs are [`RECORDED`] — the samples a real `--dry-run` printed;
//! * the turns column is read out of `docs/orizn-roles/*.json`, the operator's
//!   own documents, rather than restated;
//! * and [`headline`] is the sentence. `docs/ORIZN.md` must contain it
//!   **verbatim**, which is what the `the runbook quotes this measurement` row
//!   below gates on. Change the measurement and the document goes red until
//!   somebody pastes the new sentence in. There is no second copy to forget.
//!
//! # A range, not a point
//!
//! `max_turns_per_day` counts *reserved turns*; one reserved turn makes between
//! one and [`Budgets::max_turns`] = ten model calls, each re-sending the whole
//! prefix. So the bill is a range an order of magnitude wide and any point
//! estimate inside it is a choice. The document used to publish the floor
//! without saying so. [`headline`] publishes all three: the floor, what was
//! measured, and the ceiling.
//!
//! # Why the numbers are recorded and not asserted
//!
//! A live run is a sample from a model. A threshold test on a sample is a flaky
//! test, and a flaky test gets deleted — so nothing here asserts that the bill is
//! under anything. What is gated is the same thing [`crate::toolchoice`] gates:
//! **the question these numbers answered**. [`DIGEST`] pins the three charters'
//! rendered prompts, their plans, the turn brief and the five operator documents.
//! Edit any of them and this suite goes red with *"the recorded run measured a
//! different company"*, which is true, and the fix is to re-run `--dry-run` and
//! re-paste. The deterministic half's job is to **invalidate** the live numbers,
//! never to fabricate them.
//!
//! # What is not in here
//!
//! Prompt caching, which lowers it; the provisioning loop's own model calls,
//! which raise it; and the difference between the `claude` CLI shim the dry run
//! drives and `llm_anthropic`, which is the production path. All three are in
//! `unmeasured` below with the direction they move the number.

use std::path::PathBuf;

use agentos_app::rolepack;
use agentos_app::turn::Budgets;
use agentos_app::vertical::Charter;
use agentos_app::{rolepack_sales, rolepack_service};
use agentos_domain::money::Currency;
use agentos_domain::policy::{EffectivePolicy, ModelId, PolicyLimits, model_for};
use agentos_domain::untrusted::TrustLabel;
use sha2::{Digest, Sha256};

use crate::{Row, Surface, Truth};

// ---------------------------------------------------------------------------
// The rate card and the two ends of the range
// ---------------------------------------------------------------------------

/// USD per million tokens, in and out, for one model.
///
/// **The one thing in this crate that comes from outside the repository**, and
/// it is now four rows rather than one because seats no longer share a model.
/// Published Anthropic first-party API list prices, read 2026-08-26:
///
/// | model | in | out |
/// |---|---|---|
/// | `claude-haiku-4-5` | $1.00 | $5.00 |
/// | `claude-sonnet-5` | $3.00 | $15.00 |
/// | `claude-opus-5` | $5.00 | $25.00 |
/// | `claude-fable-5` | $10.00 | $50.00 |
///
/// Every row is sourced. Nothing here is interpolated, averaged or guessed: a
/// model with no published price would have no arm below and the build would
/// stop, which is the same reason `ModelId` is a closed enum.
///
/// # Two things these prices are not
///
/// **They are not what a subscription costs.** Under the local `claude` CLI —
/// which is what `--dry-run` and `--live` actually drive — no per-token invoice
/// exists at all: the currency is a monthly seat and the binding constraint is
/// *throughput*, not dollars. Every figure this module publishes is therefore
/// the metered-API reading of a run that was not metered. See the `unmeasured`
/// entry that says so.
///
/// **They are not the price on the day.** `claude-sonnet-5` is at an
/// introductory $2.00/$10.00 through 2026-08-31, so the three seats on Sonnet
/// bill about a third less than the arithmetic below says until then. The
/// standard rate is used deliberately: a bill quoted at a rate that expires in
/// five days is the kind of number `docs/ORIZN.md` published once already.
pub const fn rate_card(model: ModelId) -> (f64, f64) {
    match model {
        ModelId::Haiku45 => (1.0, 5.0),
        ModelId::Sonnet5 => (3.0, 15.0),
        ModelId::Opus5 => (5.0, 25.0),
        ModelId::Fable5 => (10.0, 50.0),
    }
}

/// Days billed. A month, rounded the way an operator budgets one.
const DAYS: f64 = 30.0;

/// The floor: every reserved turn answered in a single round trip. This is what
/// `docs/ORIZN.md` published as its estimate, and it is the cheapest arithmetic
/// the system can produce rather than a prediction of anything.
pub const FLOOR_CALLS_PER_TURN: f64 = 1.0;

/// The ceiling: every reserved turn running the loop to its budget.
///
/// Read off [`Budgets`] rather than written down, because a budget change that
/// did not move this number would make the range a fiction.
pub fn ceiling_calls_per_turn() -> f64 {
    f64::from(Budgets::default().max_turns)
}

// ---------------------------------------------------------------------------
// What one run measured
// ---------------------------------------------------------------------------

/// One pass of the dry run, reduced to the three numbers the bill is made of.
///
/// Input tokens are `scoping::tokens` over the bytes **we** send — not the CLI's
/// `input_tokens`, which bills the CLI's own system prompt and cache and is
/// therefore a number about the CLI. Output tokens are the CLI's, because there
/// is nothing else: the completion has not been weighed by anything of ours.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Model calls per reserved turn. Between 1 and [`ceiling_calls_per_turn`].
    pub calls_per_turn: f64,
    /// Prompt tokens per model call, by `scoping::tokens` (±20%).
    pub input_tokens_per_call: f64,
    /// Completion tokens per model call, as the CLI reported them.
    pub output_tokens_per_call: f64,
}

impl Sample {
    /// Dollars a month for **one seat**, at `calls_per_turn` model calls for
    /// each of `turns_per_day` reserved turns, billed at `model`'s rates.
    ///
    /// The whole arithmetic, in one place, so that nothing anywhere else has to
    /// restate it. Linear in every argument, which is what
    /// `the_arithmetic_is_one_multiplication_anybody_can_redo` checks.
    ///
    /// `model` is the seat's, not [`Sample::model`]: the token counts come from
    /// the recorded run and the *price* comes from whatever that seat runs
    /// today. Those are two different facts and conflating them is how a
    /// per-seat bill would silently stay a single-model one.
    pub fn monthly_usd(self, model: ModelId, calls_per_turn: f64, turns_per_day: f64) -> f64 {
        let (per_m_in, per_m_out) = rate_card(model);
        let calls = calls_per_turn * turns_per_day * DAYS;
        calls * (self.input_tokens_per_call * per_m_in + self.output_tokens_per_call * per_m_out)
            / 1_000_000.0
    }

    /// The whole company for a month, at the rate this sample actually ran at:
    /// every seat at its own model, its own turn budget, summed.
    ///
    /// **This is the function the old `measured_usd(turns_per_day)` became.**
    /// The old one took the sum of the turn budgets and multiplied once, which
    /// was exactly right while one model served every seat and is a category
    /// error now: five seats on three models is five multiplications, and the
    /// mix is most of the answer.
    pub fn company_usd(self, calls_per_turn: f64) -> f64 {
        seats()
            .iter()
            .map(|seat| self.monthly_usd(seat.model, calls_per_turn, f64::from(seat.turns)))
            .sum()
    }

    /// The same, at the calls-per-turn this sample recorded.
    pub fn measured_usd(self) -> f64 {
        self.company_usd(self.calls_per_turn)
    }
}

/// **The record.** One entry per pass of `--dry-run`, pasted from what it
/// printed under `RECORD`.
///
/// Three, not one: one run of a language model is an anecdote, and the spread
/// between these is itself a finding — see the row that prints it.
/// `one_run_is_an_anecdote` refuses to let this shrink below three.
///
/// **Re-paste these together with [`DIGEST`], never separately.** A sample and a
/// digest that came from different runs is exactly the lie this module was built
/// to stop.
/// Recorded 2026-08-26, `claude-opus-5` through the local `claude` CLI, three
/// separate invocations of `--dry-run 1` against three empty databases. All
/// three passed every structural row; the spread below is what one language
/// model does with the same three briefings on the same afternoon.
///
/// # These counts are from one model, and the bill is now priced on four
///
/// Every figure here was sampled when every seat ran `claude-opus-5`, because
/// that is what every seat ran. The *prices* [`Sample::company_usd`] multiplies
/// them by are now each seat's own — but how many calls a turn takes is a fact
/// about how a model plans, and the token counts move with the tokenizer, so a
/// seat on Sonnet or Haiku would produce different numbers here.
///
/// There is deliberately no `model` field on [`Sample`] recording which one it
/// came from: a pass covers three seats, they no longer share a model, and a
/// single-model field on a mixed sample would be a lie with a type on it. What
/// carries the invalidation instead is [`DIGEST`], which now hashes each seat's
/// model — so moving one turns this block red with *"the recorded run measured
/// a different company"*, which is precisely what would have happened.
///
/// # These three predate `MAX_THINKING_TOKENS=0` and are due a re-measure
///
/// **`output_tokens_per_call` below is high, and by a term the production path
/// does not have.** They were recorded while `llm_cli` still let the CLI run
/// with extended thinking on and dropped [`LlmRequest::max_tokens`] on the floor.
/// `llm_anthropic::body` sends no `thinking` field and does send `max_tokens`, so
/// production generates no thinking tokens at all — and thinking is billed as
/// output, which is four fifths of the bill these numbers produce.
///
/// The size of it, measured the same day: on one fixed prompt, six reps each,
/// **1,443 output tokens per call with thinking against 486 without**. Three
/// `--dry-run 3` passes after the switch landed came in at **767–1,163** output
/// tokens per call — *below the bottom of the 1,800–3,833 range recorded here*.
/// A single sdr call in the run that motivated the fix returned **12,850** output
/// tokens against a request for 4,096.
///
/// So [`headline`] is currently an over-estimate on its largest term, and
/// `docs/ORIZN.md` quotes it. Left standing rather than hand-edited, because a
/// sample is a thing a run printed and editing one by hand is how this file stops
/// meaning anything — the [`DIGEST`] pairing exists for exactly that reason. It
/// wants one honest measurement pass, `RECORD` pasted whole, and this section
/// deleted.
///
/// **[`DIGEST`] is stale too, and independently.** `the company those runs
/// measured` fails as of this writing, reporting `3a520bfd534b083b`: the
/// `orizn.app` rename edited all five documents [`digest`] hashes after this pin
/// was taken. That is the mechanism working — it is supposed to go red when the
/// company moves under a recorded number — but it means the pin and the samples
/// are now stale for two unrelated reasons at once. One `--dry-run 3`, one
/// `RECORD` block pasted whole, clears both; neither clears alone.
pub const RECORDED: &[Sample] = &[
    Sample {
        calls_per_turn: 2.00,
        input_tokens_per_call: 2_987.5,
        output_tokens_per_call: 2_468.0,
    },
    Sample {
        calls_per_turn: 2.50,
        input_tokens_per_call: 3_482.0,
        output_tokens_per_call: 3_832.8,
    },
    Sample {
        calls_per_turn: 4.00,
        input_tokens_per_call: 3_280.5,
        output_tokens_per_call: 1_800.0,
    },
];

/// Digest of everything the recorded runs were measured against. See
/// [`digest`], and the module docs for why this is the load-bearing part.
pub const DIGEST: &str = "574ecc743e6919dd";

// ---------------------------------------------------------------------------
// The company, as the operator wrote it down
// ---------------------------------------------------------------------------

/// `docs/`, from `crates/eval/`.
pub fn docs(file: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(file)
}

/// One of the operator's policy documents, as the installer reads it.
pub fn limits(file: &str) -> PolicyLimits {
    let path = docs(file);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path:?}: {err}"));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("{path:?}: {err}"))
}

/// Every role layer in `docs/orizn-roles/`, by file name, sorted.
///
/// Read off the directory rather than from a list written here, so that adding a
/// team to Orizn cannot leave a stale copy of the payroll in this file.
fn role_layers() -> Vec<(String, String)> {
    let dir = docs("orizn-roles");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("{dir:?}: {err}"))
        .map(|entry| {
            let path = entry.expect("a directory entry").path();
            let raw =
                std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path:?}: {err}"));
            (
                path.file_name()
                    .expect("a file")
                    .to_string_lossy()
                    .into_owned(),
                raw,
            )
        })
        .collect();
    out.sort();
    out
}

/// One priced seat: a role, its turn budget, and the model it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    /// The role layer's file stem, which is the role name.
    pub role: String,
    /// `max_turns_per_day` from that layer.
    pub turns: u32,
    /// What `model_for` gives that role under that layer.
    pub model: ModelId,
}

/// Which model each role *asks* for, off its own pack.
///
/// Not a table of names and models — a table of names and **packs**, so the
/// model itself is still read from the one place that owns it. A role layer
/// whose name matches no pack is an employee nobody chartered, which is
/// [`ModelId::UNCHARTERED`]; `every_priced_seat_has_a_pack_or_no_turns` is what
/// stops that being a silent mispricing rather than the honest zero it is for
/// `direction`.
fn preference(role: &str) -> Option<ModelId> {
    Some(match role {
        "international-buyer" => rolepack::RolePack::international_buyer().model(),
        "sales-development" => rolepack_sales::RolePack::sales_development().model(),
        rolepack_service::CUSTOMER_SUCCESS => {
            rolepack_service::RolePack::customer_success().model()
        }
        rolepack_service::GROWTH => rolepack_service::RolePack::growth().model(),
        rolepack_service::FINANCE => rolepack_service::RolePack::finance().model(),
        rolepack_service::ENTRY_REQUIREMENTS => {
            rolepack_service::RolePack::entry_requirements().model()
        }
        _ => return None,
    })
}

/// **The payroll, priced.** One entry per role layer in `docs/orizn-roles/`,
/// carrying the two numbers the bill is made of.
///
/// Read off the operator's own documents rather than restated here, exactly as
/// the turns column always was — and the model comes out of the same documents
/// by the same rule the running system uses: [`model_for`] over the pack's
/// preference and the intersected layer. A seat priced by any other rule would
/// be a seat this deployment does not have.
///
/// The ceiling stands in for the platform, tenant and employee layers because
/// Orizn writes only two of the four; that is stated rather than hidden, and it
/// is the same shape `apps/server/tests/orizn.rs` installs.
pub fn seats() -> Vec<Seat> {
    let ceiling = limits("orizn-ceiling.json");
    role_layers()
        .iter()
        .map(|(name, raw)| {
            let role = name.strip_suffix(".json").unwrap_or(name).to_owned();
            let layer: PolicyLimits =
                serde_json::from_str(raw).unwrap_or_else(|err| panic!("{name}: {err}"));
            let policy = EffectivePolicy::try_new(&ceiling, &ceiling, &layer, &ceiling)
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            let preferred = preference(&role).unwrap_or(ModelId::UNCHARTERED);
            let model = model_for(Some(&policy), preferred).unwrap_or_else(|| {
                panic!(
                    "{name}: the ceiling and this role layer intersect `allowed_models` to \
                     nothing, so this seat could not take a turn"
                )
            });
            Seat {
                role,
                turns: layer.max_turns_per_day,
                model,
            }
        })
        .collect()
}

/// Orizn's reserved turns a day: the sum of the five role layers.
///
/// **This is the column `docs/ORIZN.md` billed when every seat ran one model**,
/// and it is no longer sufficient on its own — the bill is now a sum over
/// [`seats`], because turns at $1/M and turns at $5/M are not the same turn.
/// It survives as the headline's denominator and as the thing the runbook's
/// turn table is checked against. `direction`'s zero is a real zero and
/// contributes nothing, which is the runbook's whole argument for that seat.
pub fn turns_per_day() -> u32 {
    seats().iter().map(|seat| seat.turns).sum()
}

// ---------------------------------------------------------------------------
// The charters the dry run works, and the pin over them
// ---------------------------------------------------------------------------

/// What a self-started turn is, in the model's terms.
///
/// A verbatim copy of `apps/server/src/loops/initiative.rs`'s `TURN_BRIEF`, a
/// private const in a binary crate with no library target. Copied rather than
/// paraphrased: a dry run that sends different bytes from the running system is
/// measuring a company nobody deployed. If the original moves, this moves — and
/// [`DIGEST`] is what says the recorded numbers moved with it.
pub const TURN_BRIEF: &str = "Nobody has written to you. Your working rhythm has come round, so \
                              this turn is yours to spend on your own objective. You have been \
                              here before and the plan below does not know it: start by finding \
                              out where you actually got to — read your own conversations, notes \
                              and records — then advance the earliest stage that is not finished. \
                              One turn is not the whole plan. Do the next real piece of work, \
                              finish it, and write down what you did. If a stage is blocked on \
                              somebody else, say so and move to what is not blocked rather than \
                              waiting inside this turn.";

/// The charters these seats are given, in the operator's words.
///
/// **Written once and not touched again.** Tuning a briefing until the run looks
/// good is how a dry run stops being evidence; if one of these produces a bad
/// turn, the bad turn is the finding. Editing one is allowed — it just moves
/// [`digest`] and invalidates [`RECORDED`], which is the point.
pub fn charters() -> Vec<(&'static str, Charter)> {
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

/// A stand-in for the employee's own name and address, so the digest is a
/// function of the charters and not of a `uuid` minted at run time.
///
/// The real identity is built in `dryrun::take_turn` from the seat's own row and
/// differs by a handful of tokens; nothing about the bill turns on it.
const PIN_IDENTITY: &str = "You are seat, an AI employee of Orizn. Your address is \
                            seat@agents.orizn.app.";

/// First 16 hex characters of the SHA-256 of everything the recorded run was
/// measured against: the turn brief, each charter's rendered system prompt at
/// both trust levels, each charter's plan, and the five operator documents.
///
/// # The models are in here now, and they were the gap
///
/// This function's own docs used to end *"and the model, which is the one input
/// to a live measurement that nothing in this repository can pin at all"*. That
/// was true while the model came from `AGENTOS_LLM` — a process-wide string set
/// outside the workspace, which no digest could reach. It is now a property of
/// each role pack and each operator document, both of which are in the
/// repository, so the sentence is simply false and the hash covers it.
///
/// That matters more than it sounds. A recorded bill is arithmetic over token
/// counts sampled from a model; changing which model a seat runs changes both
/// the price *and* the sample, and nothing about the prompts would move to show
/// it. Re-pointing `finance` at Sonnet without this would leave [`RECORDED`]
/// looking fresh while every figure it feeds was about a company that no longer
/// exists.
///
/// # What it still does not cover
///
/// The colleague roster and the employee's own address, both of which come out
/// of the database at run time; `crates/eval/src/scoping.rs` owns the roster's
/// size and it is bounded by the team. And the *snapshot* behind a model name —
/// a new one shipped under `claude-opus-5` moves every figure here and no test
/// can see it happen.
pub fn digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(TURN_BRIEF.as_bytes());
    // Every seat's model, in `seats()` order — which is `role_layers()` order,
    // which is sorted by file name.
    for seat in seats() {
        hasher.update(seat.role.as_bytes());
        hasher.update(seat.model.as_str().as_bytes());
    }
    for (seat, charter) in charters() {
        hasher.update(seat.as_bytes());
        hasher.update(charter.role().as_bytes());
        hasher.update(charter.model().as_str().as_bytes());
        let prompt = charter.system_prompt(PIN_IDENTITY);
        hasher.update(prompt.render(TrustLabel::Trusted).as_bytes());
        hasher.update(prompt.render(TrustLabel::Untrusted).as_bytes());
        hasher.update(charter.brief().as_bytes());
    }
    for file in ["orizn-ceiling.json", "orizn-org.json"] {
        let path = docs(file);
        hasher.update(
            std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("{path:?}: {err}"))
                .as_bytes(),
        );
    }
    for (name, raw) in role_layers() {
        hasher.update(name.as_bytes());
        hasher.update(raw.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// The sentence
// ---------------------------------------------------------------------------

/// Smallest and largest of a projection over [`RECORDED`].
fn spread(of: impl Fn(Sample) -> f64) -> (f64, f64) {
    RECORDED.iter().fold((f64::MAX, f64::MIN), |(lo, hi), &s| {
        (lo.min(of(s)), hi.max(of(s)))
    })
}

/// The seat mix, as a phrase: `3 on claude-sonnet-5, 1 on claude-opus-5, …`,
/// cheapest model first and seats that take no turns left out.
///
/// In the headline because it is most of the answer. The same turn count on
/// Haiku and on Fable differ by a factor of ten, so a bill quoted without the
/// mix is a number whose largest input is invisible.
fn mix() -> String {
    let seats = seats();
    ModelId::ALL
        .into_iter()
        .filter_map(|model| {
            let n = seats
                .iter()
                .filter(|s| s.model == model && s.turns > 0)
                .count();
            (n > 0).then(|| format!("{n} on {model}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// **The one sentence, and `docs/ORIZN.md` must contain it verbatim.**
///
/// Three figures and their assumptions, because a point estimate is how $76 got
/// published: what the recorded runs cost at the rate they actually ran, the
/// floor at one model call per reserved turn, and the ceiling at
/// [`Budgets::max_turns`]. Plus the seat mix, which is new and is the reason the
/// figures moved.
pub fn headline() -> String {
    let turns = f64::from(turns_per_day());
    let (lo, hi) = spread(Sample::measured_usd);
    let (floor, _) = spread(|s| s.company_usd(FLOOR_CALLS_PER_TURN));
    let (_, ceiling) = spread(|s| s.company_usd(ceiling_calls_per_turn()));
    format!(
        "${lo:.0}–${hi:.0} a month over {} measured runs at {turns} reserved turns a day \
         ({}); ${floor:.0} floor at {FLOOR_CALLS_PER_TURN:.2} model calls per turn, \
         ${ceiling:.0} ceiling at {:.2}",
        RECORDED.len(),
        mix(),
        ceiling_calls_per_turn(),
    )
}

/// The same load, priced in requests instead of dollars.
///
/// **The figure to carry to a subscription**, where tokens are not what runs
/// out. Metered pricing and a subscription bound the same system with different
/// resources, and the arithmetic above answers only the first — so an operator
/// who reads `$303–$560` and concludes the CLI backend is free has not
/// converted the constraint, they have dropped it.
///
/// The spread is the point. Calls per turn varied 2× across the recorded runs,
/// so this is a range and not a rate, and the wide end is what a plan has to
/// absorb. It is also a *daily* figure against limits usually stated per
/// rolling window: a company whose seats all fall due together spends its
/// allowance in one hour and idles for the rest, which is a scheduling
/// property and not a budget one.
pub fn calls_per_day() -> (f64, f64) {
    let turns = f64::from(turns_per_day());
    spread(|s| s.calls_per_turn * turns)
}

/// [`calls_per_day`] as the sentence a subscription is sized against.
pub fn throughput_headline() -> String {
    let (lo, hi) = calls_per_day();
    let turns = turns_per_day();
    format!(
        "{lo:.0}–{hi:.0} model calls a day at {turns} reserved turns, over {} measured runs — \
         the figure a subscription is bounded by, where the bill is not",
        RECORDED.len(),
    )
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

/// Everything about the bill that can be checked without a model.
pub fn evaluate() -> Surface {
    let mut rows = Vec::new();

    // --- 1. the number ------------------------------------------------------
    // Characterised, and it can be nothing else: it is arithmetic over a sample
    // from a model. A pass/fail on it would be a threshold on a coin flip.
    rows.push(
        Row::ok(
            "the same load, priced in requests",
            throughput_headline(),
            Truth::Characterises,
        )
        .note(
            "The bill above is metered API pricing. Driving the local `claude` binary under a \
             subscription bills nothing per token, and this is the resource that runs out \
             instead. Whether a plan permits an unattended fleet is a question about its terms, \
             not about tokens.",
        ),
    );
    rows.push(
        Row::ok("Orizn's monthly bill", headline(), Truth::Characterises).note(
            "a range because a reserved turn is 1–10 model calls; the floor alone is what \
               this document used to publish as an estimate",
        ),
    );

    // --- 1b. the seat mix, which is now half the arithmetic -----------------
    // Read off the operator's documents and the role packs by the same rule the
    // running system uses, so this row is what `apps/server` would resolve for
    // each of these employees and not a summary somebody typed.
    rows.push(Row::ok(
        "what each seat thinks with",
        seats()
            .iter()
            .map(|s| format!("{} {} ({} turns)", s.role, s.model, s.turns))
            .collect::<Vec<_>>()
            .join(", "),
        Truth::Characterises,
    ));

    // --- 2. the input that made it a range ----------------------------------
    let (calls_lo, calls_hi) = spread(|s| s.calls_per_turn);
    let mean = RECORDED.iter().map(|s| s.calls_per_turn).sum::<f64>() / RECORDED.len() as f64;
    rows.push(
        Row::ok(
            "model calls per reserved turn",
            format!(
                "{mean:.2} mean, {calls_lo:.2}–{calls_hi:.2} over {} runs",
                RECORDED.len()
            ),
            Truth::Characterises,
        )
        .note("the runbook assumed 1.00 and called it the table; it is the bottom of the range"),
    );

    // --- 3. and the tokens --------------------------------------------------
    let (in_lo, in_hi) = spread(|s| s.input_tokens_per_call);
    let (out_lo, out_hi) = spread(|s| s.output_tokens_per_call);
    rows.push(
        Row::ok(
            "tokens per model call",
            format!("in {in_lo:.0}–{in_hi:.0} (±20% estimator), out {out_lo:.0}–{out_hi:.0}"),
            Truth::Characterises,
        )
        .note("input by `scoping::tokens` over the bytes we send; output as the CLI reported it"),
    );

    // --- 4. one run is an anecdote ------------------------------------------
    // Structural, and the only thing in this file that is a property of the
    // *method* rather than of the model: a bill quoted off a single sample has
    // no spread to report, and every figure above would be a point estimate
    // wearing a range's clothes.
    let enough = RECORDED.len() >= 3;
    rows.push(
        Row::ok(
            "runs behind the figures above",
            format!("{} passes of `--dry-run`", RECORDED.len()),
            Truth::Correct,
        )
        .gated(enough),
    );

    // --- 5. the pin ---------------------------------------------------------
    // `toolchoice`'s mechanism, applied to the run instead of to five prompts.
    let now = digest();
    let unchanged = now == DIGEST;
    rows.push(
        Row::ok(
            "the company those runs measured",
            if unchanged {
                now.clone()
            } else {
                format!("CHANGED to {now}")
            },
            Truth::Correct,
        )
        .gated(unchanged)
        .note(if unchanged {
            "charters, turn brief and the five operator documents, unchanged since the run"
        } else {
            "every figure above is now stale — re-run `--dry-run 3` and re-paste both"
        }),
    );

    // --- 6. and the document ------------------------------------------------
    // **The row that stops the runbook lying again.** `docs/ORIZN.md` does not
    // get to hold its own copy of the number; it holds the string this function
    // produced, and this fails until it does.
    let path = docs("ORIZN.md");
    let runbook = std::fs::read_to_string(&path).unwrap_or_default();
    let quoted = runbook.contains(&headline());
    rows.push(
        Row::ok(
            "the runbook quotes this measurement",
            if quoted {
                "docs/ORIZN.md, verbatim".to_owned()
            } else {
                format!("STALE — docs/ORIZN.md does not contain: {}", headline())
            },
            Truth::Correct,
        )
        .gated(quoted),
    );

    Surface {
        name: "orizn (bill)",
        method: "one arithmetic function over samples a live `--dry-run` recorded; the runbook \
                 quotes it verbatim",
        rows,
        unmeasured: vec![
            "prompt caching, which lowers it. `llm_anthropic` puts a `cache_control` breakpoint \
             on the system block; a prefix re-sent inside the window bills at a tenth. Nothing \
             here prices that, so every figure above is the uncached ceiling of its own row",
            "the provisioning loop's own model calls, which raise it. The dry run stands the \
             company up before it starts counting",
            "the shim. `--dry-run` drives the local `claude` CLI, which renders tool schemas into \
             the prompt and demands JSON back — so the output-token figure is a completion the \
             production path (`llm_anthropic`) would not have produced",
            "whether 30 days is a month an operator recognises, and whether every reserved turn \
             is taken. The turns column is a CEILING on turns, not a forecast of them: an \
             employee with nothing to do reserves nothing and bills nothing",
            "the model, twice over. Which model each seat runs IS pinned now — it is in the \
             digest — but every token count above was sampled from `claude-opus-5`, and a \
             seat moved to Sonnet or Haiku will plan differently and tokenize differently. \
             The prices below those seats are right and the counts they multiply are borrowed. \
             And a new snapshot shipped behind an unchanged model name moves everything and \
             no test can see it happen",
            "the subscription, which is the regime the measurement was taken in. `--dry-run` \
             drives the local `claude` CLI, where there is no per-token invoice at all: the \
             currency is a monthly seat and the binding constraint is throughput. Every figure \
             above is the metered-API reading of an unmetered run — right for the deployment \
             that pays per token, and the wrong unit entirely for the one that does not",
            "the introductory rate. `claude-sonnet-5` bills $2.00/$10.00 per million through \
             2026-08-31 rather than the $3.00/$15.00 `rate_card` uses, so the three Sonnet \
             seats are cheaper than this until then. Quoting the introductory number would be \
             publishing a figure with five days left on it",
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The bill, by hand: one turn a day, one call each, a round million input
    /// tokens and nothing out, on Opus, is 30 × $5 = $150. If this ever
    /// disagrees, the arithmetic has grown a term nobody can check.
    #[test]
    fn the_arithmetic_is_one_multiplication_anybody_can_redo() {
        let round = Sample {
            calls_per_turn: 1.0,
            input_tokens_per_call: 1_000_000.0,
            output_tokens_per_call: 0.0,
        };
        assert!((round.monthly_usd(ModelId::Opus5, 1.0, 1.0) - 150.0).abs() < 1e-9);
        // And output is priced five times higher, which is the rate card.
        let out = Sample {
            input_tokens_per_call: 0.0,
            output_tokens_per_call: 1_000_000.0,
            ..round
        };
        assert!((out.monthly_usd(ModelId::Opus5, 1.0, 1.0) - 750.0).abs() < 1e-9);
        // Linear in calls per turn: this is the whole reason the range is a
        // range, and a non-linear term here would make the ceiling a guess.
        assert!(
            (round.monthly_usd(ModelId::Opus5, 2.0, 1.0)
                - 2.0 * round.monthly_usd(ModelId::Opus5, 1.0, 1.0))
            .abs()
                < 1e-9
        );
    }

    /// **The per-seat claim.** The same seat, the same turns, the same sample,
    /// priced on four models, is four different bills in the published ratios —
    /// and the ratios are the rate card, so a row typed wrong shows up here.
    #[test]
    fn the_bill_follows_the_seats_model_and_not_a_single_rate() {
        let seat = Sample {
            calls_per_turn: 1.0,
            input_tokens_per_call: 1_000_000.0,
            output_tokens_per_call: 1_000_000.0,
        };
        let on = |model| seat.monthly_usd(model, 1.0, 1.0);
        // $6, $18, $30, $60 per call-day; ×30 days.
        assert!((on(ModelId::Haiku45) - 180.0).abs() < 1e-9);
        assert!((on(ModelId::Sonnet5) - 540.0).abs() < 1e-9);
        assert!((on(ModelId::Opus5) - 900.0).abs() < 1e-9);
        assert!((on(ModelId::Fable5) - 1_800.0).abs() < 1e-9);
        // Strictly increasing along `ModelId`'s order, which is what makes
        // `model_for`'s cheapest-first fallback a cost guarantee rather than an
        // implementation detail.
        for pair in ModelId::ALL.windows(2) {
            assert!(
                on(pair[0]) < on(pair[1]),
                "{} is not cheaper than {}: `ModelId`'s ordering is not the price list",
                pair[0],
                pair[1]
            );
        }
    }

    /// The company bill is the sum of its seats, each at its own model — not the
    /// summed turn budget multiplied once. That distinction is the whole change
    /// and it is worth an assertion that would fail if somebody collapsed it
    /// back.
    #[test]
    fn the_company_bill_is_a_sum_over_seats_not_one_multiplication() {
        let sample = RECORDED[0];
        let by_hand: f64 = seats()
            .iter()
            .map(|seat| {
                sample.monthly_usd(seat.model, sample.calls_per_turn, f64::from(seat.turns))
            })
            .sum();
        assert!((sample.measured_usd() - by_hand).abs() < 1e-9);

        // And the seats really do differ, or the sum proves nothing. Orizn runs
        // Sonnet seats and an Opus seat side by side.
        let working: Vec<ModelId> = seats()
            .iter()
            .filter(|s| s.turns > 0)
            .map(|s| s.model)
            .collect();
        assert!(
            working.iter().any(|m| *m != working[0]),
            "every working seat runs {}, so this suite is not measuring a mix",
            working[0]
        );

        // The old arithmetic — one model for everybody — is strictly more
        // expensive, which is the finding this whole change is about.
        let all_opus: f64 = seats()
            .iter()
            .map(|seat| {
                sample.monthly_usd(ModelId::Opus5, sample.calls_per_turn, f64::from(seat.turns))
            })
            .sum();
        assert!(
            by_hand < all_opus,
            "the seat mix costs {by_hand:.2}, one-model-for-everybody costs {all_opus:.2}"
        );
    }

    /// A role layer with turns and no pack would be priced at
    /// `ModelId::UNCHARTERED` — the cheapest model there is — which is right for
    /// an employee nobody chartered and a silent under-estimate for one whose
    /// pack simply is not wired in here. `direction` is the honest case: no
    /// pack, no turns, no contribution.
    #[test]
    fn every_priced_seat_has_a_pack_or_no_turns() {
        for seat in seats() {
            assert!(
                preference(&seat.role).is_some() || seat.turns == 0,
                "{} reserves {} turns a day and matches no role pack, so its model is a \
                 guess rather than a reading",
                seat.role,
                seat.turns
            );
        }
    }

    /// The floor is below what was measured and the ceiling above it, for every
    /// recorded run. Not a fact about the model — a fact about the range being
    /// stated the right way round.
    #[test]
    fn every_measurement_sits_inside_its_own_range() {
        for sample in RECORDED {
            let floor = sample.company_usd(FLOOR_CALLS_PER_TURN);
            let ceiling = sample.company_usd(ceiling_calls_per_turn());
            let measured = sample.measured_usd();
            assert!(
                floor <= measured && measured <= ceiling,
                "{measured:.2} is outside {floor:.2}..{ceiling:.2}, so {sample:?} claims a \
                 turn made fewer than one model call or more than its budget"
            );
        }
    }

    /// One run of a language model is an anecdote. This is the only structural
    /// claim this file makes about the measurement rather than about the money.
    #[test]
    fn one_run_is_an_anecdote() {
        assert!(
            RECORDED.len() >= 3,
            "a spread needs three runs; there are {}",
            RECORDED.len()
        );
        assert!(RECORDED.iter().all(|s| s.calls_per_turn >= 1.0));
    }

    /// The turns column comes out of the operator's own documents, and
    /// `direction`'s zero is one of them.
    #[test]
    fn the_turns_column_is_read_and_not_restated() {
        assert!(turns_per_day() > 0);
        assert_eq!(limits("orizn-roles/direction.json").max_turns_per_day, 0);
        assert_eq!(
            turns_per_day(),
            role_layers()
                .iter()
                .map(|(_, raw)| serde_json::from_str::<PolicyLimits>(raw)
                    .expect("a role layer")
                    .max_turns_per_day)
                .sum::<u32>()
        );
    }

    /// A pin that moves on its own is a broken clock; a pin that never moves is
    /// not a pin.
    #[test]
    fn the_digest_is_stable_and_covers_the_charters() {
        assert_eq!(digest(), digest());
        assert_eq!(digest().len(), 16);
        // It is a function of the charters: two different seats' briefings are
        // in there, so a fixture with one charter would hash differently.
        assert_eq!(charters().len(), 3);
        // And of the seats' models, which is the claim this file's docs used to
        // say was impossible. Same seats, one model moved, different digest.
        let baseline = digest();
        assert_ne!(
            baseline,
            {
                let mut hasher = Sha256::new();
                hasher.update(TURN_BRIEF.as_bytes());
                for seat in seats() {
                    hasher.update(seat.role.as_bytes());
                    // One seat pretending to run something else.
                    hasher.update(ModelId::Fable5.as_str().as_bytes());
                }
                hasher
                    .finalize()
                    .iter()
                    .take(8)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            },
            "the digest does not depend on which model a seat runs"
        );
    }

    /// The reason this module exists. If it fails, `docs/ORIZN.md` is quoting a
    /// bill that no run produced — which is the exact state it was found in.
    #[test]
    fn the_runbook_quotes_the_measurement_verbatim() {
        let runbook = std::fs::read_to_string(docs("ORIZN.md")).expect("the runbook");
        assert!(
            runbook.contains(&headline()),
            "docs/ORIZN.md does not contain the measured sentence. Paste this into it:\n\n  \
             {}\n",
            headline()
        );
    }
}
