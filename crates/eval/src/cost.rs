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
use agentos_domain::policy::PolicyLimits;
use agentos_domain::untrusted::TrustLabel;
use sha2::{Digest, Sha256};

use crate::{Row, Surface, Truth};

// ---------------------------------------------------------------------------
// The rate card and the two ends of the range
// ---------------------------------------------------------------------------

/// USD per million input tokens for `claude-opus-5`. The one number in this
/// crate that comes from outside the repository.
pub const USD_PER_M_INPUT: f64 = 5.0;

/// USD per million output tokens for the same model.
pub const USD_PER_M_OUTPUT: f64 = 25.0;

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
    /// Dollars a month, at `calls_per_turn` model calls for each of
    /// `turns_per_day` reserved turns.
    ///
    /// The whole arithmetic, in one place, so that nothing anywhere else has to
    /// restate it. Linear in every argument, which is what
    /// `the_arithmetic_is_one_multiplication_anybody_can_redo` checks.
    pub fn monthly_usd(self, calls_per_turn: f64, turns_per_day: f64) -> f64 {
        let calls = calls_per_turn * turns_per_day * DAYS;
        calls
            * (self.input_tokens_per_call * USD_PER_M_INPUT
                + self.output_tokens_per_call * USD_PER_M_OUTPUT)
            / 1_000_000.0
    }

    /// Dollars a month at the rate this sample actually ran at.
    pub fn measured_usd(self, turns_per_day: f64) -> f64 {
        self.monthly_usd(self.calls_per_turn, turns_per_day)
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
pub const DIGEST: &str = "c0c742c04ada7fb1";

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

/// Orizn's reserved turns a day: the sum of the five role layers.
///
/// **This is the column `docs/ORIZN.md` bills, read from the documents that set
/// it** rather than restated as a constant. `direction`'s zero is a real zero
/// and contributes nothing, which is the runbook's whole argument for that seat.
pub fn turns_per_day() -> u32 {
    role_layers()
        .iter()
        .map(|(name, raw)| {
            let limits: PolicyLimits =
                serde_json::from_str(raw).unwrap_or_else(|err| panic!("{name}: {err}"));
            limits.max_turns_per_day
        })
        .sum()
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
/// # What it does not cover, deliberately
///
/// The colleague roster and the employee's own address, both of which come out
/// of the database at run time; `crates/eval/src/scoping.rs` owns the roster's
/// size and it is bounded by the team. And the model, which is the one input to
/// a live measurement that nothing in this repository can pin at all.
pub fn digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(TURN_BRIEF.as_bytes());
    for (seat, charter) in charters() {
        hasher.update(seat.as_bytes());
        hasher.update(charter.role().as_bytes());
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

/// **The one sentence, and `docs/ORIZN.md` must contain it verbatim.**
///
/// Three figures and their assumptions, because a point estimate is how $76 got
/// published: what the recorded runs cost at the rate they actually ran, the
/// floor at one model call per reserved turn, and the ceiling at
/// [`Budgets::max_turns`].
pub fn headline() -> String {
    let turns = f64::from(turns_per_day());
    let (lo, hi) = spread(|s| s.measured_usd(turns));
    let (floor, _) = spread(|s| s.monthly_usd(FLOOR_CALLS_PER_TURN, turns));
    let (_, ceiling) = spread(|s| s.monthly_usd(ceiling_calls_per_turn(), turns));
    format!(
        "${lo:.0}–${hi:.0} a month over {} measured runs at {turns} reserved turns a day; \
         ${floor:.0} floor at {FLOOR_CALLS_PER_TURN:.2} model calls per turn, ${ceiling:.0} \
         ceiling at {:.2}",
        RECORDED.len(),
        ceiling_calls_per_turn(),
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
        Row::ok("Orizn's monthly bill", headline(), Truth::Characterises).note(
            "a range because a reserved turn is 1–10 model calls; the floor alone is what \
               this document used to publish as an estimate",
        ),
    );

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
            "the model. Which model the numbers were sampled from is not in the digest, because \
             nothing in this repository can pin one — a new snapshot behind the same name moves \
             every figure above and no test can see it happen",
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
    /// tokens and nothing out, is 30 × $5 = $150. If this ever disagrees, the
    /// arithmetic has grown a term nobody can check.
    #[test]
    fn the_arithmetic_is_one_multiplication_anybody_can_redo() {
        let round = Sample {
            calls_per_turn: 1.0,
            input_tokens_per_call: 1_000_000.0,
            output_tokens_per_call: 0.0,
        };
        assert!((round.measured_usd(1.0) - 150.0).abs() < 1e-9);
        // And output is priced five times higher, which is the rate card.
        let out = Sample {
            input_tokens_per_call: 0.0,
            output_tokens_per_call: 1_000_000.0,
            ..round
        };
        assert!((out.measured_usd(1.0) - 750.0).abs() < 1e-9);
        // Linear in calls per turn: this is the whole reason the range is a
        // range, and a non-linear term here would make the ceiling a guess.
        assert!((round.monthly_usd(2.0, 1.0) - 2.0 * round.monthly_usd(1.0, 1.0)).abs() < 1e-9);
    }

    /// The floor is below what was measured and the ceiling above it, for every
    /// recorded run. Not a fact about the model — a fact about the range being
    /// stated the right way round.
    #[test]
    fn every_measurement_sits_inside_its_own_range() {
        let turns = f64::from(turns_per_day());
        for sample in RECORDED {
            let floor = sample.monthly_usd(FLOOR_CALLS_PER_TURN, turns);
            let ceiling = sample.monthly_usd(ceiling_calls_per_turn(), turns);
            let measured = sample.measured_usd(turns);
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
