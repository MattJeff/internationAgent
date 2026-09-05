//! **What a stretch of time costs, and how much work fits in it.**
//!
//! # Why this is here and not in `agentos_eval::cost`
//!
//! It was there, all of it, and that was right while exactly one caller existed:
//! a measurement crate pricing one company — Orizn — out of that company's own
//! operator documents. There are two callers now. `apps/server`'s `/v1/forecast`
//! answers the same question for **the tenant that asks**, off its own seats, its
//! own models and its own cadences, and it cannot reach `agentos-eval` — that
//! crate reads `docs/orizn-*.json` off the filesystem at run time and depends on
//! the whole workspace to do it. A server that depended on the harness measuring
//! it would be backwards.
//!
//! So the arithmetic moved down to the crate both can see, and only the
//! arithmetic did. What stayed in `agentos_eval::cost` is everything specific to
//! Orizn: which seats it has, what its charters say, the digest that pins them,
//! and the sentence `docs/ORIZN.md` quotes verbatim.
//!
//! **The point of the move is that there is still one copy.** Two places
//! computing the same bill is two places that drift, and this repository has
//! already paid for that once: `docs/ORIZN.md` published $76 a month, in prose,
//! and prose cannot be re-run. A second implementation in a route handler would
//! be the same mistake with a JSON content type.
//!
//! # What this module refuses to compute
//!
//! **A probability that a company succeeds.** It was asked for and it is not
//! here. There is no population of companies that have run on this to sample, the
//! first ones will be N=1, and a percentage with no measurement behind it sitting
//! beside [`RECORDED`] — which cost a live run and is pinned against a digest —
//! would make a reader doubt the figures that are real. What is here instead is
//! effort: what the seats will get through, and what that bills.
//!
//! Everything below is linear and every input is either measured, read from the
//! tenant's own rows, or a structural bound. Nothing is interpolated.

use crate::policy::ModelId;

// ---------------------------------------------------------------------------
// The rate card
// ---------------------------------------------------------------------------

/// USD per million tokens, in and out, for one model.
///
/// **The one thing in this crate that comes from outside the repository.**
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
/// stop, which is the same reason [`ModelId`] is a closed enum.
///
/// # Two things these prices are not
///
/// **They are not what a subscription costs.** Under the local `claude` CLI —
/// which is what `--dry-run` and `--live` actually drive, and what
/// [`ModelPath::Cli`] means for a tenant — no per-token invoice exists at all:
/// the currency is a monthly seat and the binding constraint is *throughput*,
/// not dollars. Every figure this module produces is therefore the metered-API
/// reading of a run that may not be metered, and the caller has to know which
/// regime it is in before it prints a dollar sign. `/v1/forecast` reads
/// [`ModelAccess::path`] for exactly that reason and returns no money at all on
/// the CLI path.
///
/// **They are not the price on the day.** `claude-sonnet-5` is at an
/// introductory $2.00/$10.00 through 2026-08-31, so a seat on Sonnet bills about
/// a third less than the arithmetic here says until then. The standard rate is
/// used deliberately: a bill quoted at a rate that expires in days is the kind
/// of number `docs/ORIZN.md` published once already.
///
/// [`ModelPath::Cli`]: crate::model_access::ModelPath::Cli
/// [`ModelAccess::path`]: crate::model_access::ModelAccess::path
pub const fn rate_card(model: ModelId) -> (f64, f64) {
    match model {
        ModelId::Haiku45 => (1.0, 5.0),
        ModelId::Sonnet5 => (3.0, 15.0),
        ModelId::Opus5 => (5.0, 25.0),
        ModelId::Fable5 => (10.0, 50.0),
    }
}

/// Days in a billed month. A month, rounded the way an operator budgets one.
///
/// `agentos_eval::cost` uses it for its monthly headline. `/v1/forecast` takes
/// its *window* from the caller and never stretches tokens to thirtieths — the
/// founder who asks for two days is answered in two days — but the one figure
/// that is monthly by contract, the infrastructure price the caller passes as
/// `infra_usd_per_month`, is prorated over the window through this constant,
/// because a monthly price has no other honest reading in a two-day window.
pub const MONTH_DAYS: f64 = 30.0;

/// The floor: every reserved turn answered in a single round trip.
///
/// This is what `docs/ORIZN.md` published as its estimate, and it is the
/// cheapest arithmetic the system can produce rather than a prediction of
/// anything. The ceiling is `agentos_app::turn::Budgets::max_turns` and is read
/// off that type by both callers rather than written down here, because a budget
/// change that did not move the ceiling would make the range a fiction.
pub const FLOOR_CALLS_PER_TURN: f64 = 1.0;

// ---------------------------------------------------------------------------
// What one run measured
// ---------------------------------------------------------------------------

/// One pass of the dry run, reduced to the three numbers the bill is made of.
///
/// Input tokens are `agentos_eval::scoping::tokens` over the bytes **we** send —
/// not the CLI's `input_tokens`, which bills the CLI's own system prompt and
/// cache and is therefore a number about the CLI. Output tokens are the CLI's,
/// because there is nothing else: the completion has not been weighed by
/// anything of ours.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Model calls per reserved turn. Between [`FLOOR_CALLS_PER_TURN`] and
    /// `Budgets::max_turns`.
    pub calls_per_turn: f64,
    /// Prompt tokens per model call, by `scoping::tokens` (±20%).
    pub input_tokens_per_call: f64,
    /// Completion tokens per model call, as the CLI reported them.
    pub output_tokens_per_call: f64,
}

impl Sample {
    /// **The whole arithmetic, in one place.** Dollars for `turns` reserved
    /// turns, at `calls_per_turn` model calls each, billed at `model`'s rates.
    ///
    /// Linear in every argument, which is what
    /// `the_arithmetic_is_one_multiplication_anybody_can_redo` checks — and
    /// which is the reason the floor and the ceiling are honest ends of a range
    /// rather than two more guesses.
    ///
    /// `model` is the seat's, not the sample's: the token counts come from the
    /// recorded run and the *price* comes from whatever that seat runs today.
    /// Those are two different facts and conflating them is how a per-seat bill
    /// silently stays a single-model one.
    ///
    /// `turns` is a count over whatever window the caller cares about — thirty
    /// days of a turn budget for `agentos_eval::cost`, a founder's two days for
    /// `/v1/forecast`. The function does not know which and does not need to.
    pub fn usd(self, model: ModelId, calls_per_turn: f64, turns: f64) -> f64 {
        self.usd_at(rate_card(model), calls_per_turn, turns)
    }

    /// The same multiplication at rates the caller names — `(USD per million
    /// in, USD per million out)` — rather than the rate card's.
    ///
    /// This is where [`Sample::usd`] lands, and it is public for one caller:
    /// `/v1/forecast` pricing a window at the tariff the tenant declared on
    /// their own Anthropic contract, which primes the rate card. The arithmetic
    /// is not repeated there; only the pair of rates changes.
    pub fn usd_at(self, (per_m_in, per_m_out): (f64, f64), calls_per_turn: f64, turns: f64) -> f64 {
        let calls = calls_per_turn * turns;
        calls * (self.input_tokens_per_call * per_m_in + self.output_tokens_per_call * per_m_out)
            / 1_000_000.0
    }
}

/// **The record.** One entry per pass of `--dry-run`, pasted from what it
/// printed under `RECORD`.
///
/// Three, not one: one run of a language model is an anecdote, and the spread
/// between these is itself a finding. `agentos_eval::cost`'s
/// `one_run_is_an_anecdote` refuses to let this shrink below three.
///
/// **Re-paste these together with `agentos_eval::cost::DIGEST`, never
/// separately.** A sample and a digest that came from different runs is exactly
/// the lie that mechanism was built to stop, and the samples living in a
/// different crate from the digest does not soften it — it is now possible to
/// edit this array without opening the file that pins what it measured. The
/// digest still fails the suite when the *company* changes; nothing but this
/// paragraph stops a hand-typed sample.
///
/// Recorded 2026-08-26, each seat on its own model through the local `claude`
/// CLI, one invocation of `--dry-run 3` against an empty database. All nine
/// turns reached the model, all nine were intact, and every structural row
/// passed.
///
/// # These are Orizn's numbers, and a second tenant borrows them
///
/// They were measured against one company's charters, one company's operator
/// documents and one model — `claude-opus-5` through the CLI shim. `/v1/forecast`
/// multiplies them by *another* tenant's seats, because there is nothing else to
/// multiply: no other company has been run and counted. That transfer is the
/// largest uncertainty in any forecast this workspace produces and the route
/// states it to the caller in as many words rather than burying it here.
pub const RECORDED: &[Sample] = &[
    Sample {
        calls_per_turn: 8.00,
        input_tokens_per_call: 7361.0,
        output_tokens_per_call: 437.0,
    },
    Sample {
        calls_per_turn: 7.33,
        input_tokens_per_call: 7486.3,
        output_tokens_per_call: 530.2,
    },
    Sample {
        calls_per_turn: 8.00,
        input_tokens_per_call: 7135.7,
        output_tokens_per_call: 371.4,
    },
];

/// Smallest and largest of a projection over [`RECORDED`].
///
/// Shared rather than written twice, for the reason the whole module is shared:
/// a headline and a route that disagreed about which end of the spread they were
/// quoting would be two different claims wearing one number.
pub fn spread(of: impl Fn(Sample) -> f64) -> (f64, f64) {
    spread_of(RECORDED, of)
}

/// [`spread`] over any samples — split out so the fold can be tested on data
/// whose extremes are not at the ends, whatever shape [`RECORDED`] has today.
fn spread_of(samples: &[Sample], of: impl Fn(Sample) -> f64) -> (f64, f64) {
    samples.iter().fold((f64::MAX, f64::MIN), |(lo, hi), &s| {
        (lo.min(of(s)), hi.max(of(s)))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The bill, by hand: one turn, one call, a round million input tokens and
    /// nothing out, on Opus, is $5. If this ever disagrees, the arithmetic has
    /// grown a term nobody can check.
    #[test]
    fn the_arithmetic_is_one_multiplication_anybody_can_redo() {
        let round = Sample {
            calls_per_turn: 1.0,
            input_tokens_per_call: 1_000_000.0,
            output_tokens_per_call: 0.0,
        };
        assert!((round.usd(ModelId::Opus5, 1.0, 1.0) - 5.0).abs() < 1e-9);
        // And output is priced five times higher, which is the rate card.
        let out = Sample {
            input_tokens_per_call: 0.0,
            output_tokens_per_call: 1_000_000.0,
            ..round
        };
        assert!((out.usd(ModelId::Opus5, 1.0, 1.0) - 25.0).abs() < 1e-9);

        // Linear in calls per turn AND in turns, separately. The first is why
        // the floor/ceiling range is a range; the second is why a two-day
        // window and a thirty-day one come out of the same function.
        assert!(
            (round.usd(ModelId::Opus5, 2.0, 1.0) - 2.0 * round.usd(ModelId::Opus5, 1.0, 1.0)).abs()
                < 1e-9
        );
        assert!(
            (round.usd(ModelId::Opus5, 1.0, 7.0) - 7.0 * round.usd(ModelId::Opus5, 1.0, 1.0)).abs()
                < 1e-9
        );
        // A window of nothing costs nothing. Not a triviality: it is what makes
        // a seat that never wakes contribute a real zero to a company's bill
        // rather than a rounding artefact.
        assert_eq!(round.usd(ModelId::Opus5, 1.7, 0.0), 0.0);

        // A declared pair of rates goes through the same multiplication: $7 a
        // million in, on a million in, is $7 — and the rate card is not consulted.
        assert!((round.usd_at((7.0, 0.0), 1.0, 1.0) - 7.0).abs() < 1e-9);
        assert!(
            (round.usd(ModelId::Opus5, 1.0, 1.0)
                - round.usd_at(rate_card(ModelId::Opus5), 1.0, 1.0))
            .abs()
                < 1e-9,
            "`usd` is `usd_at` at the rate card, not a second copy"
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
        let on = |model| seat.usd(model, 1.0, 1.0);
        assert!((on(ModelId::Haiku45) - 6.0).abs() < 1e-9);
        assert!((on(ModelId::Sonnet5) - 18.0).abs() < 1e-9);
        assert!((on(ModelId::Opus5) - 30.0).abs() < 1e-9);
        assert!((on(ModelId::Fable5) - 60.0).abs() < 1e-9);
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

    /// A spread needs something to spread over, and it must be the real ends —
    /// not the first and last entry, which is the bug this shape invites.
    #[test]
    fn the_spread_is_the_smallest_and_largest_and_not_the_first_and_last() {
        assert!(RECORDED.len() >= 3, "a spread needs three runs");

        let (lo, hi) = spread(|s| s.calls_per_turn);
        assert!(lo <= hi);
        for sample in RECORDED {
            assert!(sample.calls_per_turn >= lo && sample.calls_per_turn <= hi);
        }
        // And no recorded turn claims fewer model calls than the floor.
        assert!(lo >= FLOOR_CALLS_PER_TURN);

        // The fold itself, on data whose extremes sit in the middle: a
        // first/last implementation returns (3.0, 4.0) here and is wrong twice.
        let sample = |calls_per_turn| Sample {
            calls_per_turn,
            input_tokens_per_call: 1.0,
            output_tokens_per_call: 1.0,
        };
        let middle = [sample(3.0), sample(1.0), sample(9.0), sample(4.0)];
        assert_eq!(spread_of(&middle, |s| s.calls_per_turn), (1.0, 9.0));
    }
}
