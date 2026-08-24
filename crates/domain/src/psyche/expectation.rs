//! P3 — learned expectation and prediction error (Rescorla-Wagner + Welford).
//!
//! This is the accumulator that turns thousands of dull interactions into the
//! only asset a purchasing agent really owns: *what this counterparty actually
//! does, as opposed to what it says it does.*
//!
//! ```text
//!   supplier Z claims a 15-day lead time      -> Expectation::with_claim(15.0)
//!   deliveries land at 22, 24, 23, 23 days    -> observe(...)
//!   expected() converges on ~23, claim_gap() = +8, reliability() = Predictable
//! ```
//!
//! Two mechanisms, both ported from MPCP (`mpcp.py`), both textbook:
//!
//! * **Rescorla-Wagner (1972)** — `expected += rate * (observed - expected)`.
//!   Learning is proportional to surprise, so habituation is not a patch: the
//!   hundredth on-time delivery moves nothing, the first late one moves a lot.
//! * **Welford's online variance** — how *reliable* the counterparty is. A
//!   supplier that is consistently eight days late is more usable than one that
//!   is randomly zero to thirty days late, and only the variance tells them
//!   apart. Welford is used rather than the naive sum-of-squares because the
//!   naive form loses catastrophic precision on a large mean (see the
//!   `welford_survives_a_large_offset` test).
//! * **Precision-weighted gain (Feldman & Friston)** — the learning rate is
//!   scaled by `1 / (1 + K · variance)`, so one datapoint from an erratic
//!   counterparty moves the belief less than one datapoint from a metronome.
//!
//! # The governing invariant
//!
//! Everything here is READ-ONLY advice for *tone and prioritisation*: what to
//! propose, whom to chase first, how to phrase it. None of it may ever be an
//! input to [`crate::policy::evaluate`]. A frustrated or a surprised agent must
//! be allowed exactly the same set of actions as a calm one — the moment an
//! expectation can widen a permission, the Policy Gate stops being a pure
//! function of the policy and the action, and the safety story is gone.
//!
//! # Determinism
//!
//! No clock is read here (`now` is a parameter), there is no randomness, and
//! the book is a [`BTreeMap`], so iteration and serialization are byte-stable.
//! Non-finite floats cannot enter the state: they are rejected at `observe`,
//! and deserialization funnels through a validating wire type.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::Slug;
use crate::money::{Money, MoneyError};

// ---------------------------------------------------------------------------
// Constants — ported from mpcp.py, see the module fidelity notes
// ---------------------------------------------------------------------------

/// Rescorla-Wagner learning rate (`TAUX_PRED` in mpcp.py, line 342).
///
/// ~3 observations to cover most of the gap, ~8 to converge. Fast enough that a
/// supplier who changes behaviour is believed within a quarter, slow enough
/// that one freak customs delay does not rewrite the file.
pub const LEARNING_RATE: f64 = 0.3;

/// Floor on the salience of a fully predicted event (`SURPRISE_MIN`, line 343).
///
/// An expected problem is still a problem: a delay you saw coming still costs
/// you the same three weeks. Surprise drives *learning*, not the whole of
/// impact, so a routine observation keeps half its weight downstream.
pub const SURPRISE_FLOOR: f64 = 0.5;

/// Precision gain (`K_PRECISION`, line 347): `precision = 1 / (1 + K · var)`.
pub const K_PRECISION: f64 = 1.0;

/// Normalised variance above which a counterparty is *erratic*
/// (`SEUIL_VERIF_VAR`, line 388).
pub const ERRATIC_VARIANCE: f64 = 0.5;

/// Observations required before judging reliability at all (`N_VERIF`, line 389).
pub const MIN_OBSERVATIONS: u32 = 3;

/// Largest magnitude an observation may carry. Well beyond any real lead time,
/// latency or basis-point delta, and small enough that `m2` cannot overflow
/// `f64` however long the series runs.
pub const MAX_OBSERVATION: f64 = 1e9;

// ---------------------------------------------------------------------------
// Dimension
// ---------------------------------------------------------------------------

/// What is being predicted about a counterparty.
///
/// Every dimension is a plain scalar quantity — days, hours, basis points,
/// percent. Money is deliberately absent: amounts are [`Money`] everywhere else
/// in this crate and must never become `f64`. To learn a pricing habit, feed
/// [`Dimension::PriceDeltaBps`] with [`price_delta_bps`], which does the
/// integer arithmetic on minor units and yields a dimensionless ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    /// Days between order confirmation and goods actually available.
    LeadTimeDays,
    /// Signed basis points between the opening quote and the price finally
    /// agreed. Positive means they opened high.
    PriceDeltaBps,
    /// Hours between our message and their reply, on one channel.
    ResponseLatencyHours,
    /// Percent below the published MOQ they have actually accepted.
    MoqFlexibilityPct,
    /// Percent of a shipment rejected at incoming inspection.
    DefectRatePct,
}

impl Dimension {
    /// Every dimension, so a new variant cannot be added without a test seeing it.
    pub const ALL: [Dimension; 5] = [
        Dimension::LeadTimeDays,
        Dimension::PriceDeltaBps,
        Dimension::ResponseLatencyHours,
        Dimension::MoqFlexibilityPct,
        Dimension::DefectRatePct,
    ];

    /// One *notable* unit of this dimension: the deviation a buyer would
    /// actually remark on.
    ///
    /// This is the calibration knob of the module. MPCP could skip it because
    /// its observations were polarities in `[-1, 1]`, where "one unit" is
    /// self-evident; days and basis points have no such natural scale, so
    /// surprise and variance are divided by it before being compared to
    /// MPCP's thresholds. Tune per trade — three days is notable for air
    /// freight and noise for sea freight.
    pub const fn scale(self) -> f64 {
        match self {
            Dimension::LeadTimeDays => 3.0,
            Dimension::PriceDeltaBps => 200.0,
            Dimension::ResponseLatencyHours => 4.0,
            Dimension::MoqFlexibilityPct => 10.0,
            Dimension::DefectRatePct => 1.0,
        }
    }

    /// Human-readable unit, for phrasing a message or a log line.
    pub const fn unit(self) -> &'static str {
        match self {
            Dimension::LeadTimeDays => "days",
            Dimension::PriceDeltaBps => "bps",
            Dimension::ResponseLatencyHours => "hours",
            Dimension::MoqFlexibilityPct | Dimension::DefectRatePct => "%",
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can be wrong with an observation or a stored expectation.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ExpectationError {
    /// NaN or ±infinity. Rejected at the boundary: one of these inside the
    /// state would poison the mean, the variance and every future update.
    #[error("observation must be a finite number")]
    NotFinite,
    /// Finite but absurd — almost certainly a unit mix-up upstream.
    #[error("observation {0} is outside ±{MAX_OBSERVATION}")]
    OutOfRange(f64),
    /// Persisted state that does not satisfy Welford's invariants.
    #[error("stored expectation is inconsistent")]
    Corrupt,
}

// ---------------------------------------------------------------------------
// Prediction error
// ---------------------------------------------------------------------------

/// What one observation told us, measured *before* the belief was updated.
///
/// Returned by [`Expectation::observe`] so a caller can treat a shocking
/// datapoint differently from a routine one — escalate it, mention it in the
/// reply, bump the supplier up the review queue. It never authorises anything.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PredictionError {
    /// The value just observed.
    pub observed: f64,
    /// What we expected before seeing it.
    pub expected_before: f64,
    /// `observed - expected_before`. Signed: positive means worse-than-expected
    /// on every dimension here (later, dearer, slower, more defects).
    pub surprise: f64,
    /// Salience in `[SURPRISE_FLOOR, 1]`:
    /// `SURPRISE_FLOOR + (1 - SURPRISE_FLOOR) · min(1, |surprise| / scale)`.
    /// Ported from `poids_surprise` (mpcp.py line 650).
    pub weight: f64,
    /// True when nothing was known: no prior observation and no stated claim.
    /// The expectation simply adopts the observation, and `surprise` is `0.0`
    /// rather than a fabricated error against a made-up prior.
    pub first_contact: bool,
}

// ---------------------------------------------------------------------------
// Reliability
// ---------------------------------------------------------------------------

/// How predictable a counterparty is on one dimension — the distinction a
/// buyer actually acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reliability {
    /// Fewer than [`MIN_OBSERVATIONS`]. Not "reliable", not "erratic": unknown.
    Unknown,
    /// Tight spread. Whatever they do, they do it every time — you can plan
    /// around it, even if what they do is arrive eight days late.
    Predictable,
    /// Wide spread. The mean is not a plan; buffer for the tail or dual-source.
    Erratic,
}

// ---------------------------------------------------------------------------
// Expectation
// ---------------------------------------------------------------------------

/// A learned belief about one counterparty on one dimension.
///
/// Serializes as a flat JSON object and rehydrates through a validating wire
/// type, so a corrupt or non-finite blob cannot be loaded into memory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ExpectationWire")]
pub struct Expectation {
    dimension: Dimension,
    /// Rescorla-Wagner associative strength, in the dimension's own units.
    expected: f64,
    /// Welford running mean of the raw observations.
    mean: f64,
    /// Welford `M2`: the running sum of squared deviations from the mean.
    m2: f64,
    n: u32,
    /// What the counterparty says about itself, if it ever said. Kept forever:
    /// `expected - claimed` is the number a buyer wants on the screen.
    claimed: Option<f64>,
    first_observed_at: Option<DateTime<Utc>>,
    last_observed_at: Option<DateTime<Utc>>,
}

/// Deserialization funnel — the only way a stored blob becomes an
/// [`Expectation`], so persisted NaN/infinity or a bogus `n`/`m2` pair is an
/// error rather than a silently poisoned belief.
#[derive(Deserialize)]
struct ExpectationWire {
    dimension: Dimension,
    expected: f64,
    mean: f64,
    m2: f64,
    n: u32,
    claimed: Option<f64>,
    first_observed_at: Option<DateTime<Utc>>,
    last_observed_at: Option<DateTime<Utc>>,
}

impl TryFrom<ExpectationWire> for Expectation {
    type Error = ExpectationError;

    fn try_from(w: ExpectationWire) -> Result<Self, Self::Error> {
        for value in [w.expected, w.mean, w.m2] {
            if !value.is_finite() {
                return Err(ExpectationError::NotFinite);
            }
        }
        if let Some(claimed) = w.claimed
            && !claimed.is_finite()
        {
            return Err(ExpectationError::NotFinite);
        }
        // M2 is a sum of squares: never negative, and always zero before the
        // second observation.
        if w.m2 < 0.0 || (w.n < 2 && w.m2 != 0.0) {
            return Err(ExpectationError::Corrupt);
        }
        Ok(Expectation {
            dimension: w.dimension,
            expected: w.expected,
            mean: w.mean,
            m2: w.m2,
            n: w.n,
            claimed: w.claimed,
            first_observed_at: w.first_observed_at,
            last_observed_at: w.last_observed_at,
        })
    }
}

impl Expectation {
    /// A belief about a counterparty we know nothing about. The first
    /// observation is adopted wholesale rather than being averaged against a
    /// fictitious prior of zero.
    pub const fn new(dimension: Dimension) -> Self {
        Expectation {
            dimension,
            expected: 0.0,
            mean: 0.0,
            m2: 0.0,
            n: 0,
            claimed: None,
            first_observed_at: None,
            last_observed_at: None,
        }
    }

    /// A belief seeded with what the counterparty *claims* — the quoted lead
    /// time, the published MOQ, the promised response time.
    ///
    /// This is the interesting constructor: the claim is a real prediction, so
    /// the very first delivery produces a real, signed prediction error against
    /// it, and [`Expectation::claim_gap`] is thereafter the distance between
    /// the brochure and reality.
    pub fn with_claim(dimension: Dimension, claimed: f64) -> Result<Self, ExpectationError> {
        check(claimed)?;
        Ok(Expectation {
            expected: claimed,
            claimed: Some(claimed),
            ..Expectation::new(dimension)
        })
    }

    /// Record what the counterparty now claims, without disturbing anything
    /// learned. Only an untouched belief takes the claim as its expectation.
    pub fn record_claim(&mut self, claimed: f64) -> Result<(), ExpectationError> {
        check(claimed)?;
        self.claimed = Some(claimed);
        if self.n == 0 {
            self.expected = claimed;
        }
        Ok(())
    }

    /// Fold in one observation and return what it told us.
    ///
    /// Order matters and follows mpcp.py (lines 628-651, then 862-869): the
    /// prediction error and the precision-weighted gain are read from the state
    /// *before* the update, then Welford runs, then Rescorla-Wagner. Reading
    /// precision after the update would let an observation vouch for itself.
    ///
    /// `now` is a parameter and never `Utc::now()`, so a replay of the same
    /// series produces the same state bit for bit.
    pub fn observe(
        &mut self,
        observed: f64,
        now: DateTime<Utc>,
    ) -> Result<PredictionError, ExpectationError> {
        check(observed)?;

        let first_contact = self.n == 0 && self.claimed.is_none();
        let expected_before = self.expected;
        let surprise = if first_contact {
            0.0
        } else {
            observed - expected_before
        };
        let weight = if first_contact {
            1.0
        } else {
            SURPRISE_FLOOR
                + (1.0 - SURPRISE_FLOOR) * (surprise.abs() / self.dimension.scale()).min(1.0)
        };
        // P5 Feldman-Friston: adaptive gain ∝ 1/variance. While ignorant
        // (`precision()` is None) we learn at the full rate.
        let gain = LEARNING_RATE * self.precision().unwrap_or(1.0);

        // Welford, exactly as in mpcp.py `_welford` — the running mean is
        // updated first and the M2 increment multiplies the deviation from the
        // *old* mean by the deviation from the *new* one.
        self.n += 1;
        let delta = observed - self.mean;
        self.mean += delta / f64::from(self.n);
        self.m2 += delta * (observed - self.mean);

        // Rescorla-Wagner.
        self.expected = if first_contact {
            observed
        } else {
            expected_before + gain * surprise
        };

        self.first_observed_at.get_or_insert(now);
        self.last_observed_at = Some(now);

        debug_assert!(self.expected.is_finite() && self.mean.is_finite() && self.m2.is_finite());
        Ok(PredictionError {
            observed,
            expected_before,
            surprise,
            weight,
            first_contact,
        })
    }

    /// What the next interaction is predicted to bring. `None` until something
    /// is known — no observation and no claim means no prediction, rather than
    /// a confident zero.
    pub fn expected(&self) -> Option<f64> {
        (self.n > 0 || self.claimed.is_some()).then_some(self.expected)
    }

    /// What this observation *would* be worth, without recording it. Same
    /// formula as [`PredictionError::weight`]; useful to triage an inbound
    /// message before deciding to act on it.
    pub fn surprise_of(&self, observed: f64) -> Result<f64, ExpectationError> {
        check(observed)?;
        match self.expected() {
            None => Ok(0.0),
            Some(expected) => Ok(observed - expected),
        }
    }

    /// Arithmetic mean of the raw observations (Welford). `None` before the
    /// first one.
    pub fn mean(&self) -> Option<f64> {
        (self.n > 0).then_some(self.mean)
    }

    /// Population variance of the observations, `M2 / n`.
    ///
    /// `None` below two observations: one datapoint has no spread, and
    /// reporting `0.0` there would claim perfect reliability from a single
    /// lucky delivery. MPCP stores the same population form (`var += (d·d' -
    /// var)/n`, line 869), which is algebraically `M2/n`.
    pub fn variance(&self) -> Option<f64> {
        (self.n >= 2).then(|| self.m2 / f64::from(self.n))
    }

    /// Standard deviation, in the dimension's own units — the "± 4 days" a
    /// buyer puts in the plan.
    pub fn std_dev(&self) -> Option<f64> {
        self.variance().map(f64::sqrt)
    }

    /// Feldman-Friston precision in `(0, 1]`: `1 / (1 + K · var / scale²)`.
    ///
    /// `None` until there is a variance to speak of, which is what stops a
    /// first observation from pretending to be certain.
    pub fn precision(&self) -> Option<f64> {
        self.variance().map(|var| {
            let scale = self.dimension.scale();
            1.0 / (1.0 + K_PRECISION * var / (scale * scale))
        })
    }

    /// Consistently-late versus randomly-late.
    pub fn reliability(&self) -> Reliability {
        if self.n < MIN_OBSERVATIONS {
            return Reliability::Unknown;
        }
        let scale = self.dimension.scale();
        match self.variance() {
            Some(var) if var / (scale * scale) <= ERRATIC_VARIANCE => Reliability::Predictable,
            _ => Reliability::Erratic,
        }
    }

    /// How far reality sits from the counterparty's own claim, in the
    /// dimension's units: positive means worse than advertised. `None` if they
    /// never claimed anything, or we have never checked.
    pub fn claim_gap(&self) -> Option<f64> {
        match (self.claimed, self.n) {
            (Some(claimed), n) if n > 0 => Some(self.expected - claimed),
            _ => None,
        }
    }

    /// What the counterparty states about itself, if anything.
    pub const fn claimed(&self) -> Option<f64> {
        self.claimed
    }

    /// Number of observations folded in.
    pub const fn observations(&self) -> u32 {
        self.n
    }

    /// The dimension this belief is about.
    pub const fn dimension(&self) -> Dimension {
        self.dimension
    }

    /// When this belief was first and last touched — a belief nobody has fed in
    /// two years is stale, whatever its precision says.
    pub const fn first_observed_at(&self) -> Option<DateTime<Utc>> {
        self.first_observed_at
    }

    /// See [`Expectation::first_observed_at`].
    pub const fn last_observed_at(&self) -> Option<DateTime<Utc>> {
        self.last_observed_at
    }
}

/// Reject anything that would poison the running statistics.
fn check(value: f64) -> Result<(), ExpectationError> {
    if !value.is_finite() {
        return Err(ExpectationError::NotFinite);
    }
    if value.abs() > MAX_OBSERVATION {
        return Err(ExpectationError::OutOfRange(value));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Money -> observation
// ---------------------------------------------------------------------------

/// Signed basis points between an opening quote and the price finally agreed:
/// `+1400` means they opened 14% above where they landed.
///
/// The single sanctioned bridge from [`Money`] into this module. Both sides
/// stay integer minor units until the very last division, and the result is a
/// dimensionless ratio — not an amount — so no money is ever represented as a
/// float.
pub fn price_delta_bps(quoted: Money, agreed: Money) -> Result<f64, MoneyError> {
    if quoted.currency() != agreed.currency() {
        return Err(MoneyError::CurrencyMismatch {
            left: quoted.currency(),
            right: agreed.currency(),
        });
    }
    // `Money` is non-zero and unsigned, so the divisor is strictly positive and
    // the i128 difference cannot overflow.
    let delta = i128::from(quoted.minor()) - i128::from(agreed.minor());
    Ok((delta * 10_000) as f64 / agreed.minor() as f64)
}

// ---------------------------------------------------------------------------
// Book
// ---------------------------------------------------------------------------

/// Every learned expectation, keyed by counterparty and then dimension.
///
/// [`BTreeMap`] rather than `HashMap` on purpose: iteration order and JSON key
/// order are part of the state's identity here, and a replay must reproduce the
/// same bytes. Both key types serialize as strings, so the whole book is plain
/// JSON.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExpectationBook {
    counterparties: BTreeMap<Slug, BTreeMap<Dimension, Expectation>>,
}

impl ExpectationBook {
    /// An agent that has met nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold in one observation, creating the belief if this is a first contact.
    pub fn observe(
        &mut self,
        counterparty: &Slug,
        dimension: Dimension,
        observed: f64,
        now: DateTime<Utc>,
    ) -> Result<PredictionError, ExpectationError> {
        check(observed)?;
        self.entry(counterparty, dimension).observe(observed, now)
    }

    /// Record what a counterparty claims about itself on one dimension.
    pub fn record_claim(
        &mut self,
        counterparty: &Slug,
        dimension: Dimension,
        claimed: f64,
    ) -> Result<(), ExpectationError> {
        check(claimed)?;
        self.entry(counterparty, dimension).record_claim(claimed)
    }

    /// The belief about one counterparty on one dimension, if any exists.
    pub fn get(&self, counterparty: &Slug, dimension: Dimension) -> Option<&Expectation> {
        self.counterparties.get(counterparty)?.get(&dimension)
    }

    /// Everything known about one counterparty, in dimension order.
    pub fn counterparty(
        &self,
        counterparty: &Slug,
    ) -> impl Iterator<Item = (Dimension, &Expectation)> {
        self.counterparties
            .get(counterparty)
            .into_iter()
            .flat_map(|by_dim| by_dim.iter().map(|(d, e)| (*d, e)))
    }

    /// Every belief, in a stable (counterparty, dimension) order.
    pub fn iter(&self) -> impl Iterator<Item = (&Slug, Dimension, &Expectation)> {
        self.counterparties
            .iter()
            .flat_map(|(slug, by_dim)| by_dim.iter().map(move |(dim, exp)| (slug, *dim, exp)))
    }

    /// How many beliefs are stored.
    pub fn len(&self) -> usize {
        self.counterparties.values().map(BTreeMap::len).sum()
    }

    /// Whether the agent has learned anything at all.
    pub fn is_empty(&self) -> bool {
        self.counterparties.values().all(BTreeMap::is_empty)
    }

    fn entry(&mut self, counterparty: &Slug, dimension: Dimension) -> &mut Expectation {
        self.counterparties
            .entry(counterparty.clone())
            .or_default()
            .entry(dimension)
            .or_insert_with(|| Expectation::new(dimension))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::money::Currency;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid timestamp")
    }

    fn slug(s: &str) -> Slug {
        Slug::parse(s).expect("valid slug")
    }

    fn close(left: f64, right: f64) {
        assert!(
            (left - right).abs() < 1e-9,
            "expected {right}, got {left} (diff {})",
            (left - right).abs()
        );
    }

    /// Textbook Rescorla-Wagner: with a constant reinforcer the associative
    /// strength closes a fixed fraction of the remaining gap each trial, so
    /// V_k = λ - (λ - V_0)·(1 - α)^k. Supplier claims 15 days, always takes 23.
    /// Variance is zero throughout, so precision is 1 and the gain is exactly
    /// LEARNING_RATE — the trajectory is the pure textbook one.
    #[test]
    fn rescorla_wagner_follows_the_textbook_trajectory() {
        let mut exp = Expectation::with_claim(Dimension::LeadTimeDays, 15.0).unwrap();
        let lambda = 23.0;
        let v0 = 15.0;

        for k in 1..=10_i32 {
            exp.observe(lambda, at(i64::from(k))).unwrap();
            let textbook = lambda - (lambda - v0) * (1.0 - LEARNING_RATE).powi(k);
            close(exp.expected().unwrap(), textbook);
        }
        // ...and the concrete first steps, so a change of constant is loud.
        let mut exp = Expectation::with_claim(Dimension::LeadTimeDays, 15.0).unwrap();
        close(exp.observe(23.0, at(1)).unwrap().surprise, 8.0);
        close(exp.expected().unwrap(), 17.4);
        exp.observe(23.0, at(2)).unwrap();
        close(exp.expected().unwrap(), 19.08);
        exp.observe(23.0, at(3)).unwrap();
        close(exp.expected().unwrap(), 20.256);
        // The claim said 15, reality says ~20 and climbing to 23.
        close(exp.claim_gap().unwrap(), 5.256);
    }

    /// Surprise shrinks as the belief converges: that is habituation, falling
    /// out of the update rule rather than being patched on.
    #[test]
    fn habituation_falls_out_of_the_update_rule() {
        let mut exp = Expectation::with_claim(Dimension::LeadTimeDays, 15.0).unwrap();
        let mut previous = f64::INFINITY;
        let first_weight = exp.observe(23.0, at(0)).unwrap().weight;
        for k in 1..=8 {
            let pe = exp.observe(23.0, at(k)).unwrap();
            assert!(pe.surprise.abs() < previous, "surprise did not shrink");
            previous = pe.surprise.abs();
        }
        // A routine observation keeps SURPRISE_FLOOR of its weight, never zero:
        // an expected delay is still a delay.
        let pe = exp.observe(23.0, at(9)).unwrap();
        assert!(pe.weight >= SURPRISE_FLOOR);
        assert!(pe.weight < first_weight * 0.7);
        // A genuinely shocking datapoint saturates the weight.
        let shock = exp.observe(60.0, at(10)).unwrap();
        close(shock.weight, 1.0);
        assert!(shock.surprise > 35.0);
    }

    /// Known-answer set: 2,4,4,4,5,5,7,9 has mean 5 and population variance 4.
    #[test]
    fn welford_matches_the_hand_computed_variance() {
        let mut exp = Expectation::new(Dimension::DefectRatePct);
        for (i, x) in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0].iter().enumerate() {
            exp.observe(*x, at(i as i64)).unwrap();
        }
        close(exp.mean().unwrap(), 5.0);
        close(exp.variance().unwrap(), 4.0);
        close(exp.std_dev().unwrap(), 2.0);
        assert_eq!(exp.observations(), 8);
    }

    /// Why Welford exists: the naive sum-of-squares formula catastrophically
    /// cancels on a large mean. Same dataset shifted by 5e8 must give the same
    /// variance; the naive computation does not.
    #[test]
    fn welford_survives_a_large_offset() {
        let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0].map(|x| x + 5e8);
        let mut exp = Expectation::new(Dimension::DefectRatePct);
        for (i, x) in data.iter().enumerate() {
            exp.observe(*x, at(i as i64)).unwrap();
        }
        // Welford keeps ~8 significant digits of the variance on a mean of
        // 5e8; the naive form below keeps none of them.
        assert!((exp.variance().unwrap() - 4.0).abs() < 1e-4);

        let n = data.len() as f64;
        let sum: f64 = data.iter().sum();
        let sum_sq: f64 = data.iter().map(|x| x * x).sum();
        let naive = sum_sq / n - (sum / n) * (sum / n);
        assert!(
            (naive - 4.0).abs() > 0.1,
            "naive formula unexpectedly accurate ({naive}); the Welford test has lost its point"
        );
    }

    /// The distinction a buyer acts on: consistently eight days late beats
    /// randomly zero-to-thirty, even though both average out badly.
    #[test]
    fn consistent_beats_erratic() {
        let mut steady = Expectation::with_claim(Dimension::LeadTimeDays, 15.0).unwrap();
        let mut erratic = Expectation::with_claim(Dimension::LeadTimeDays, 15.0).unwrap();
        for (i, (s, e)) in [
            (23.0, 8.0),
            (23.0, 38.0),
            (24.0, 9.0),
            (23.0, 40.0),
            (23.0, 5.0),
            (24.0, 39.0),
        ]
        .iter()
        .enumerate()
        {
            steady.observe(*s, at(i as i64)).unwrap();
            erratic.observe(*e, at(i as i64)).unwrap();
        }

        // Both are late on average, to a comparable degree...
        assert!((steady.mean().unwrap() - erratic.mean().unwrap()).abs() < 2.0);
        // ...but only one of them is a plan.
        assert_eq!(steady.reliability(), Reliability::Predictable);
        assert_eq!(erratic.reliability(), Reliability::Erratic);
        assert!(steady.precision().unwrap() > 0.9);
        assert!(erratic.precision().unwrap() < 0.05);
        assert!(steady.std_dev().unwrap() < 1.0);
        assert!(erratic.std_dev().unwrap() > 10.0);

        // P5: the erratic supplier's next datapoint moves the belief far less
        // than the steady one's, because it carries far less information.
        let (before_s, before_e) = (steady.expected().unwrap(), erratic.expected().unwrap());
        steady.observe(30.0, at(9)).unwrap();
        erratic.observe(30.0, at(9)).unwrap();
        let moved_s = (steady.expected().unwrap() - before_s).abs();
        let moved_e = (erratic.expected().unwrap() - before_e).abs();
        assert!(
            moved_s > moved_e * 3.0,
            "precision-weighted gain not applied: {moved_s} vs {moved_e}"
        );
    }

    #[test]
    fn a_first_observation_does_not_pretend_to_have_precision() {
        let mut exp = Expectation::new(Dimension::ResponseLatencyHours);
        assert_eq!(exp.expected(), None);
        assert_eq!(exp.reliability(), Reliability::Unknown);

        let pe = exp.observe(6.0, at(0)).unwrap();
        assert!(pe.first_contact);
        close(pe.surprise, 0.0); // no prior existed; do not invent an error
        close(pe.weight, 1.0); // ...but it is entirely new information
        close(exp.expected().unwrap(), 6.0); // adopted wholesale
        assert_eq!(exp.variance(), None);
        assert_eq!(exp.std_dev(), None);
        assert_eq!(exp.precision(), None);
        assert_eq!(exp.reliability(), Reliability::Unknown);

        exp.observe(6.0, at(1)).unwrap();
        assert_eq!(exp.variance(), Some(0.0));
        assert_eq!(exp.reliability(), Reliability::Unknown); // still under MIN_OBSERVATIONS
        exp.observe(6.0, at(2)).unwrap();
        assert_eq!(exp.reliability(), Reliability::Predictable);
    }

    /// A stated claim *is* a prediction, so the first delivery against it is a
    /// real prediction error rather than a first contact.
    #[test]
    fn a_claim_is_a_prediction() {
        let mut exp = Expectation::with_claim(Dimension::LeadTimeDays, 15.0).unwrap();
        assert_eq!(exp.expected(), Some(15.0));
        assert_eq!(exp.claim_gap(), None); // never checked yet
        let pe = exp.observe(23.0, at(0)).unwrap();
        assert!(!pe.first_contact);
        close(pe.surprise, 8.0);
        assert!(exp.claim_gap().unwrap() > 0.0);
    }

    /// Re-quoting the same lead time must not wipe what was learned.
    #[test]
    fn a_later_claim_does_not_reset_learning() {
        let mut exp = Expectation::new(Dimension::LeadTimeDays);
        exp.observe(23.0, at(0)).unwrap();
        exp.observe(23.0, at(1)).unwrap();
        let learned = exp.expected().unwrap();
        exp.record_claim(15.0).unwrap();
        close(exp.expected().unwrap(), learned);
        close(exp.claim_gap().unwrap(), learned - 15.0);
    }

    #[test]
    fn non_finite_and_absurd_observations_are_rejected() {
        let mut exp = Expectation::new(Dimension::LeadTimeDays);
        exp.observe(20.0, at(0)).unwrap();
        exp.observe(24.0, at(1)).unwrap();
        let before = exp.clone();

        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(exp.observe(bad, at(2)), Err(ExpectationError::NotFinite));
            assert_eq!(exp.surprise_of(bad), Err(ExpectationError::NotFinite));
        }
        assert!(matches!(
            exp.observe(1e300, at(2)),
            Err(ExpectationError::OutOfRange(_))
        ));
        assert!(matches!(
            Expectation::with_claim(Dimension::LeadTimeDays, f64::NAN),
            Err(ExpectationError::NotFinite)
        ));
        // A rejected observation changes nothing at all.
        assert_eq!(exp, before);
        assert!(exp.expected().unwrap().is_finite());
        assert!(exp.variance().unwrap().is_finite());
    }

    #[test]
    fn deserialization_rejects_a_poisoned_blob() {
        // serde_json writes non-finite floats as null, which f64 refuses.
        let poisoned = r#"{"dimension":"lead_time_days","expected":null,"mean":5.0,"m2":1.0,
            "n":3,"claimed":null,"first_observed_at":null,"last_observed_at":null}"#;
        assert!(serde_json::from_str::<Expectation>(poisoned).is_err());

        // n < 2 cannot have accumulated any M2.
        let corrupt = r#"{"dimension":"lead_time_days","expected":5.0,"mean":5.0,"m2":9.0,
            "n":1,"claimed":null,"first_observed_at":null,"last_observed_at":null}"#;
        assert!(serde_json::from_str::<Expectation>(corrupt).is_err());

        let negative = r#"{"dimension":"lead_time_days","expected":5.0,"mean":5.0,"m2":-1.0,
            "n":4,"claimed":null,"first_observed_at":null,"last_observed_at":null}"#;
        assert!(serde_json::from_str::<Expectation>(negative).is_err());
    }

    #[test]
    fn replay_is_bit_for_bit_deterministic() {
        let series = [
            ("shenzhen-widgets", Dimension::LeadTimeDays, 23.0),
            ("acme-fasteners", Dimension::PriceDeltaBps, 1400.0),
            ("shenzhen-widgets", Dimension::ResponseLatencyHours, 2.0),
            ("shenzhen-widgets", Dimension::LeadTimeDays, 25.0),
            ("acme-fasteners", Dimension::LeadTimeDays, 12.0),
            ("shenzhen-widgets", Dimension::LeadTimeDays, 22.0),
        ];
        let build = || {
            let mut book = ExpectationBook::new();
            book.record_claim(&slug("shenzhen-widgets"), Dimension::LeadTimeDays, 15.0)
                .unwrap();
            for (i, (name, dim, value)) in series.iter().enumerate() {
                book.observe(&slug(name), *dim, *value, at(i as i64))
                    .unwrap();
            }
            book
        };
        let a = build();
        let b = build();
        assert_eq!(a, b);

        let json_a = serde_json::to_string(&a).unwrap();
        let json_b = serde_json::to_string(&b).unwrap();
        assert_eq!(json_a, json_b, "serialization is not byte-stable");

        // Round-trip through the wire type reproduces the same state.
        let rehydrated: ExpectationBook = serde_json::from_str(&json_a).unwrap();
        assert_eq!(rehydrated, a);
        assert_eq!(serde_json::to_string(&rehydrated).unwrap(), json_a);

        // Ordering is by key, not by insertion.
        let keys: Vec<_> = a.iter().map(|(s, d, _)| (s.as_str(), d)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(a.len(), 4);
        assert!(!a.is_empty());
    }

    #[test]
    fn book_keeps_counterparties_and_dimensions_apart() {
        let mut book = ExpectationBook::new();
        assert!(book.is_empty());
        let z = slug("supplier-z");
        let y = slug("supplier-y");

        book.record_claim(&z, Dimension::LeadTimeDays, 15.0)
            .unwrap();
        for i in 0..6 {
            book.observe(&z, Dimension::LeadTimeDays, 23.0, at(i))
                .unwrap();
            book.observe(&y, Dimension::LeadTimeDays, 15.0, at(i))
                .unwrap();
            book.observe(&z, Dimension::ResponseLatencyHours, 30.0, at(i))
                .unwrap();
        }

        let z_lead = book.get(&z, Dimension::LeadTimeDays).unwrap();
        assert!(z_lead.claim_gap().unwrap() > 6.0); // claims 15, real ~23
        close(
            book.get(&y, Dimension::LeadTimeDays)
                .unwrap()
                .mean()
                .unwrap(),
            15.0,
        );
        assert_eq!(book.get(&y, Dimension::ResponseLatencyHours), None);
        assert_eq!(book.counterparty(&z).count(), 2);
        assert_eq!(book.counterparty(&slug("nobody")).count(), 0);
    }

    #[test]
    fn price_delta_is_computed_on_minor_units() {
        let quoted = Money::new(11_400, Currency::Usd).unwrap();
        let agreed = Money::new(10_000, Currency::Usd).unwrap();
        close(price_delta_bps(quoted, agreed).unwrap(), 1400.0);
        close(
            price_delta_bps(agreed, quoted).unwrap(),
            -1_228.070_175_438_596_5,
        );
        assert!(matches!(
            price_delta_bps(quoted, Money::new(10_000, Currency::Eur).unwrap()),
            Err(MoneyError::CurrencyMismatch { .. })
        ));

        // "Supplier X usually opens 14% above their final price."
        let mut exp = Expectation::new(Dimension::PriceDeltaBps);
        for i in 0..6 {
            exp.observe(price_delta_bps(quoted, agreed).unwrap(), at(i))
                .unwrap();
        }
        close(exp.expected().unwrap(), 1400.0);
        assert_eq!(exp.reliability(), Reliability::Predictable);
    }

    #[test]
    fn every_dimension_has_a_usable_scale() {
        for dim in Dimension::ALL {
            assert!(dim.scale() > 0.0 && dim.scale().is_finite());
            assert!(!dim.unit().is_empty());
            let mut exp = Expectation::new(dim);
            exp.observe(1.0, at(0)).unwrap();
            exp.observe(2.0, at(1)).unwrap();
            assert!(exp.precision().unwrap() > 0.0);
        }
    }

    proptest::proptest! {
        /// Whatever the series, the state stays finite and the variance stays
        /// non-negative — no accumulated NaN, no negative M2.
        #[test]
        fn state_stays_finite_and_variance_non_negative(
            values in proptest::collection::vec(-1e6f64..1e6f64, 1..64)
        ) {
            let mut exp = Expectation::new(Dimension::LeadTimeDays);
            for (i, v) in values.iter().enumerate() {
                exp.observe(*v, at(i as i64)).unwrap();
            }
            proptest::prop_assert!(exp.expected().unwrap().is_finite());
            proptest::prop_assert!(exp.mean().unwrap().is_finite());
            if let Some(var) = exp.variance() {
                proptest::prop_assert!(var >= 0.0 && var.is_finite());
                let precision = exp.precision().unwrap();
                proptest::prop_assert!(precision > 0.0 && precision <= 1.0);
            }
            // The mean always sits inside the observed range.
            let lo = values.iter().cloned().fold(f64::INFINITY, f64::min);
            let hi = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            proptest::prop_assert!(exp.mean().unwrap() >= lo - 1e-6);
            proptest::prop_assert!(exp.mean().unwrap() <= hi + 1e-6);
        }
    }
}
