//! Does the psyche predict a supplier's real behaviour better than the
//! supplier's own claim?
//!
//! **That comparison is the whole evaluation.** A learned expectation that
//! predicts worse than the brochure is not a weak feature, it is a liability
//! with a maintenance cost, and the only responsible thing to do with it is
//! delete it. So every series here is scored twice — once for
//! [`Expectation`], once for a predictor that simply believes `claimed`
//! forever — and the two numbers are printed side by side.
//!
//! # Method: fixtures, measured against the eventual truth
//!
//! [`Expectation::observe`] takes its clock as a parameter and has no
//! randomness, so a series replays bit for bit. The metric is **one-step-ahead
//! absolute error**: before each observation, ask both predictors what the next
//! delivery will be; after it, record how far each was wrong. Mean over the
//! series. This is what a buyer actually experiences — every delivery is a
//! prediction they made a plan against.
//!
//! # Where the ground truth comes from. Read this before believing a number.
//!
//! **The observations are the truth for their series, by construction.** Given
//! `[22, 24, 23]`, "which predictor was closer" is arithmetic, not opinion.
//! That part is [`Truth::Correct`].
//!
//! **The series themselves are hand-written archetypes, not real supplier
//! data.** We have no delivery history. So:
//!
//! * The **per-archetype verdicts are meaningful and are asserted**: on a
//!   supplier who is consistently eight days late, a learner that does not
//!   beat the brochure is broken, and that is true whatever the real world
//!   looks like.
//! * The **aggregate is a characterisation and is labelled as one**, because it
//!   is a weighted average over a mix of archetypes nobody has measured. If
//!   real suppliers are 90% `HONEST`, the aggregate below is flattering by a
//!   wide margin.
//!
//! The archetypes were chosen so the suite can *lose*. A corpus of nothing but
//! liars would let any learner look brilliant; [`Series::HONEST`] and
//! [`Series::ERRATIC`] are the two where the psyche is expected to be *worse*
//! than the claim, and they carry the tightest bars in the file. An eval you
//! cannot fail is a slogan.

use agentos_domain::psyche::expectation::{Dimension, Expectation, Reliability};
use chrono::{DateTime, TimeZone, Utc};

use crate::{Row, Surface, Truth};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// What this archetype must produce, or the psyche is not earning its keep.
#[derive(Debug, Clone, Copy)]
enum Bar {
    /// The claim is a lie and the learner has to notice: its error must be at
    /// most this fraction of the claim's.
    BeatsClaim(f64),
    /// The claim is honest, or nothing is predictable. The learner cannot win
    /// and must not lose badly: its error may be at most this multiple of the
    /// claim's.
    NoWorseThan(f64),
}

/// One counterparty's stated claim and what actually happened.
struct Series {
    name: &'static str,
    dimension: Dimension,
    claimed: f64,
    observed: &'static [f64],
    bar: Bar,
}

impl Series {
    /// The textbook case: they say fifteen days and it is always twenty-odd.
    /// A learner that cannot beat the brochure here has no reason to exist.
    const CONSISTENTLY_LATE: Series = Series {
        name: "consistently-late",
        dimension: Dimension::LeadTimeDays,
        claimed: 15.0,
        observed: &[22.0, 24.0, 23.0, 23.0, 22.0, 23.0, 24.0],
        bar: Bar::BeatsClaim(0.6),
    };

    /// **The adversarial one.** They said twenty days and they mean it; the
    /// spread is ordinary noise. The claim is the best predictor available and
    /// the psyche cannot beat it — it can only pay to learn what it was already
    /// told. The bar measures how much that costs.
    const HONEST: Series = Series {
        name: "honest",
        dimension: Dimension::LeadTimeDays,
        claimed: 20.0,
        observed: &[19.0, 21.0, 20.0, 20.0, 21.0, 19.0, 20.0],
        bar: Bar::NoWorseThan(1.35),
    };

    /// Randomly ten to fifty days. Nothing predicts this, and the failure mode
    /// to guard against is a learner that chases the last datapoint and ends up
    /// worse than a constant. The precision gain is what stops it.
    const ERRATIC: Series = Series {
        name: "erratic",
        dimension: Dimension::LeadTimeDays,
        claimed: 30.0,
        observed: &[10.0, 50.0, 12.0, 48.0, 15.0, 45.0, 18.0],
        bar: Bar::NoWorseThan(1.20),
    };

    /// They were honest, then the factory moved. Four ordinary deliveries, then
    /// a permanent step to forty days.
    const REGIME_CHANGE: Series = Series {
        name: "regime-change",
        dimension: Dimension::LeadTimeDays,
        claimed: 15.0,
        observed: &[15.0, 15.0, 16.0, 15.0, 40.0, 42.0, 41.0, 40.0, 41.0],
        bar: Bar::BeatsClaim(0.95),
    };

    /// Quietly getting worse every month, two days at a time. Nobody
    /// re-negotiates a lead time; it just drifts.
    const CREEP: Series = Series {
        name: "optimistic-creep",
        dimension: Dimension::LeadTimeDays,
        claimed: 30.0,
        observed: &[32.0, 34.0, 36.0, 38.0, 40.0, 42.0, 44.0],
        bar: Bar::BeatsClaim(0.9),
    };

    /// A second dimension, so [`Dimension::scale`] — the calibration knob the
    /// whole module hangs on — is exercised by something other than days.
    /// They open 13-15% above where they settle and claim their first price is
    /// their best.
    const OPENS_HIGH: Series = Series {
        name: "opens-high-bps",
        dimension: Dimension::PriceDeltaBps,
        claimed: 0.0,
        observed: &[1400.0, 1200.0, 1500.0, 1300.0, 1450.0],
        bar: Bar::BeatsClaim(0.7),
    };

    const ALL: [Series; 6] = [
        Series::CONSISTENTLY_LATE,
        Series::HONEST,
        Series::ERRATIC,
        Series::REGIME_CHANGE,
        Series::CREEP,
        Series::OPENS_HIGH,
    ];
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// What one series cost each predictor.
struct Scored {
    /// Mean absolute one-step-ahead error of [`Expectation`].
    psyche_mae: f64,
    /// Mean absolute error of believing `claimed` forever.
    claim_mae: f64,
    /// What the psyche predicts for the *next* interaction, after the series.
    final_prediction: f64,
    reliability: Reliability,
    met_bar: bool,
}

fn at(step: usize) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + (step as i64) * 86_400, 0)
        .single()
        .expect("valid instant")
}

/// Replay a series against both predictors.
///
/// The prediction is read *before* the observation is folded in, which is the
/// only ordering that is not cheating: a predictor allowed to see the value
/// first scores zero on everything.
fn score(series: &Series) -> Scored {
    let mut learned = Expectation::with_claim(series.dimension, series.claimed)
        .expect("fixture claim is a finite, in-range number");
    let (mut psyche, mut claim) = (0.0f64, 0.0f64);

    for (step, &observed) in series.observed.iter().enumerate() {
        let predicted = learned.expected().expect("seeded with a claim");
        psyche += (observed - predicted).abs();
        claim += (observed - series.claimed).abs();
        learned
            .observe(observed, at(step))
            .expect("fixture observation is finite and in range");
    }

    let n = series.observed.len() as f64;
    let (psyche_mae, claim_mae) = (psyche / n, claim / n);
    // The same arithmetic either way. Two variants because `BeatsClaim(0.6)`
    // and `NoWorseThan(1.35)` say opposite things to a reader, and a bar whose
    // direction you have to work out is a bar somebody sets backwards.
    let (Bar::BeatsClaim(ratio) | Bar::NoWorseThan(ratio)) = series.bar;
    let met_bar = psyche_mae <= claim_mae * ratio;

    Scored {
        psyche_mae,
        claim_mae,
        final_prediction: learned.expected().expect("seeded with a claim"),
        reliability: learned.reliability(),
        met_bar,
    }
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

/// Run every series and report.
pub fn evaluate() -> Surface {
    let scored: Vec<(&Series, Scored)> = Series::ALL.iter().map(|s| (s, score(s))).collect();
    let n = scored.len();

    let mut rows = Vec::new();

    // --- the one that can fail the build ------------------------------------
    let met = scored.iter().filter(|(_, s)| s.met_bar).count();
    let missed: Vec<&str> = scored
        .iter()
        .filter(|(_, s)| !s.met_bar)
        .map(|(series, _)| series.name)
        .collect();
    rows.push(
        Row::ok(
            "each archetype meets its bar",
            if missed.is_empty() {
                format!("{met}/{n}")
            } else {
                format!("{met}/{n} — missed: {}", missed.join(", "))
            },
            Truth::Correct,
        )
        .gated(missed.is_empty()),
    );

    // --- the headline comparison --------------------------------------------
    // A ratio, not a mean of the errors: the series are in days and in basis
    // points, and averaging those together produces a number with no unit and
    // no meaning. `psyche_mae / claim_mae` is dimensionless per series, so the
    // mean of it says one thing — how much closer than the brochure, typically.
    let ratio: f64 = scored
        .iter()
        .map(|(_, s)| s.psyche_mae / s.claim_mae)
        .sum::<f64>()
        / n as f64;
    let beats = scored
        .iter()
        .filter(|(_, s)| s.psyche_mae < s.claim_mae)
        .count();
    rows.push(
        Row::ok(
            "beats the supplier's own claim",
            format!(
                "{beats}/{n} series — error is {:.0}% of the claim's",
                ratio * 100.0
            ),
            Truth::Characterises,
        )
        .note("the mix of archetypes is invented; read the per-series rows, not this average"),
    );

    // --- what learning costs when the supplier was telling the truth --------
    let honest = scored
        .iter()
        .find(|(s, _)| s.name == Series::HONEST.name)
        .map(|(_, s)| s)
        .expect("HONEST is in ALL");
    let overhead = (honest.psyche_mae / honest.claim_mae - 1.0) * 100.0;
    rows.push(
        Row::ok(
            "cost of learning on an honest supplier",
            format!(
                "+{overhead:.0}% error ({:.2} vs {:.2} days)",
                honest.psyche_mae, honest.claim_mae
            ),
            Truth::Characterises,
        )
        .note("the psyche is worse than the brochure here, and always will be — this is the price"),
    );

    // --- the finding that matters most --------------------------------------
    // This row is why the drift detector exists. Precision-weighting divides
    // the learning rate by the variance, and a regime change is exactly the
    // event that spikes it — so the gain used to collapse at the moment the
    // belief most needed to move, and the prediction froze 17 days short.
    //
    // A two-sided CUSUM on clamped, slack-adjusted surprise now tells a drift
    // from noise and lifts the weighting while the misses keep pointing the
    // same way. The remaining gap is not the old bug: the detector spends
    // three observations becoming convinced, deliberately, so that one
    // container stuck in a port cannot buy a regime change — and this series
    // only offers five after the jump. A real relationship offers more.
    // `crates/domain/src/psyche/expectation.rs` has the tests that pin both
    // directions.
    let regime = scored
        .iter()
        .find(|(s, _)| s.name == Series::REGIME_CHANGE.name)
        .map(|(_, s)| s)
        .expect("REGIME_CHANGE is in ALL");
    let truth_now = Series::REGIME_CHANGE
        .observed
        .last()
        .copied()
        .expect("non-empty");
    let stuck = truth_now - regime.final_prediction;
    rows.push(
        Row::ok(
            "after a regime change, the belief reaches",
            format!(
                "{:.1} days while reality is {truth_now:.0} ({stuck:+.0} out)",
                regime.final_prediction
            ),
            Truth::Characterises,
        )
        .note(
            "was +17 out before the drift detector; the rest is the three observations \
             it spends refusing to mistake one outlier for a change",
        ),
    );

    // --- the qualitative output a buyer actually reads ----------------------
    // Consistently late is *predictable*: you can plan around a supplier who is
    // always eight days over. Randomly late is not, and separating those two is
    // the entire reason variance is tracked. `optimistic-creep` lands on
    // "erratic" because a steady trend looks like spread to a variance
    // estimator — see the note.
    let labelled_right = scored.iter().all(|(series, s)| {
        let want = match series.name {
            "erratic" | "regime-change" | "optimistic-creep" => Reliability::Erratic,
            _ => Reliability::Predictable,
        };
        s.reliability == want
    });
    rows.push(
        Row::ok(
            "reliability separates tight from wild",
            if labelled_right {
                format!("{n}/{n} archetypes labelled as specified")
            } else {
                "BROKEN".to_owned()
            },
            Truth::Correct,
        )
        .gated(labelled_right)
        .note("a steady drift reads as Erratic: Welford cannot tell a trend from noise"),
    );

    Surface {
        name: "psyche::expectation",
        method: "replayed series; prediction error against the eventual truth, vs believing the claim",
        rows,
        unmeasured: vec![
            "everything against REAL supplier delivery data — there is none in this workspace, \
             so every series above is a hand-written archetype",
            "the mix: what fraction of real suppliers are honest vs late vs erratic. The \
             aggregate row is meaningless until somebody knows this",
            "whether Dimension::scale() is calibrated for any actual trade (3.0 days, 200 bps \
             are guesses in the source, and the report inherits them)",
            "beliefs.rs, forgetting.rs, links.rs — the rest of the psyche is untouched here",
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The scorer must read the prediction before folding the observation in.
    /// If it ever reads it after, every error collapses towards zero and the
    /// whole suite passes vacuously — the single most likely way this file
    /// becomes a lie.
    #[test]
    fn the_scorer_does_not_let_an_observation_predict_itself() {
        let series = Series {
            name: "step",
            dimension: Dimension::LeadTimeDays,
            claimed: 0.0,
            observed: &[100.0],
            bar: Bar::NoWorseThan(1.0),
        };
        let scored = score(&series);
        // One observation, predicted from a claim of zero: the error is the
        // whole 100. A scorer peeking would report 0.
        assert!(
            (scored.psyche_mae - 100.0).abs() < 1e-9,
            "{}",
            scored.psyche_mae
        );
        assert!((scored.claim_mae - 100.0).abs() < 1e-9);
    }

    /// The baseline has to be the claim and nothing cleverer, or the comparison
    /// is against a straw man.
    #[test]
    fn the_baseline_is_a_constant_at_the_claim() {
        let scored = score(&Series::CONSISTENTLY_LATE);
        // |22-15| + |24-15| + … over seven deliveries, by hand: 56 / 7.
        assert!(
            (scored.claim_mae - 8.0).abs() < 1e-9,
            "{}",
            scored.claim_mae
        );
    }

    /// A learner that beats the brochure on the honest supplier would mean the
    /// bar is upside down and the suite is measuring nothing.
    #[test]
    fn the_honest_supplier_is_a_series_the_psyche_loses() {
        let scored = score(&Series::HONEST);
        assert!(
            scored.psyche_mae > scored.claim_mae,
            "HONEST stopped being adversarial: psyche {} vs claim {}",
            scored.psyche_mae,
            scored.claim_mae
        );
    }
}
