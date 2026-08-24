//! Relational trust: links built and broken, one per counterparty.
//!
//! Port of MPCP's `liens` (`mpcp.py`: `LIEN_DELTAS`, `_bouger_lien` inside
//! `ingest`, `_appraisal`), retargeted to suppliers.
//!
//! # What the model says
//!
//! * **Trust is earned, never assigned.** [`TrustLink::confidence`] starts at
//!   [`BASE_CONFIDENCE`] and only ever moves through [`TrustLedger::record`].
//!   There is no setter, and no constructor that takes a confidence.
//! * **A built link absorbs a first blow.** The shock absorber
//!   ([`SHOCK_ABSORBER`], MPCP `AMORTI_LIEN = 0.85`) is a Bayesian prior: three
//!   years of on-time deliveries are evidence, and one bad shipment does not
//!   erase them. Each blow weakens the absorber for the next one, so doubt
//!   installs itself and *then* kills.
//! * **Breakage needs something to break.** A collapse only marks a rupture if
//!   the confidence was actually built ([`BREAKABLE_FROM`], MPCP
//!   `CONFIANCE_BRISABLE = 0.6`) — this is Berg's trust-game asymmetry: a cold
//!   counterparty cannot betray you.
//! * **Betrayal by someone close hits twice as hard.** [`Appraisal`] weighs the
//!   *same* event by the standing of the relationship: ×2 from a close partner,
//!   ×0.5 from one already distrusted ("that figures"), ×1.5 for unexpected
//!   decency from a distrusted one. This is Kahneman–Tversky loss aversion
//!   (λ≈2) applied relationally, and it is MPCP's `_appraisal` unchanged.
//! * **Breakage is structural.** [`TrustLink::broken_at`] is set once and never
//!   cleared: a scar, not a mood. Later kept promises still raise confidence,
//!   but the link stays visibly broken and can never read as `Close` again.
//!
//! # Where this may and may not be used
//!
//! Trust ranks the queue and colours the wording. It is never an input to
//! [`crate::policy::evaluate`]. A supplier at 0.95 gets no permission a
//! supplier at 0.05 lacks.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::Slug;

// ---------------------------------------------------------------------------
// Constants — all carried over from mpcp.py unchanged
// ---------------------------------------------------------------------------

/// Confidence of a counterparty never dealt with (MPCP `A_PRIORI_FACTION[0]`,
/// the neutral prior; the faction bias above it is not ported).
pub const BASE_CONFIDENCE: f64 = 0.5;

/// Confidence gained by a kept promise (MPCP `LIEN_DELTAS["objectif_atteint"]`).
pub const KEPT_PROMISE_DELTA: f64 = 0.10;

/// Confidence lost by a broken commitment (MPCP `LIEN_DELTAS["contrainte_violee"]`).
pub const BROKEN_COMMITMENT_DELTA: f64 = -0.25;

/// Confidence lost by a recurring fault (MPCP `LIEN_DELTAS["erreur_repetee"]`).
pub const REPEATED_FAULT_DELTA: f64 = -0.10;

/// Prior resistance of a built link (MPCP `AMORTI_LIEN`). At 0.95 confidence a
/// weight-3 blow wounds without breaking; the *second* one breaks.
pub const SHOCK_ABSORBER: f64 = 0.85;

/// Single-event confidence drop that marks a rupture (MPCP `SEUIL_BRISURE`).
pub const BREAK_DROP: f64 = 0.2;

/// Confidence below which nothing can be broken (MPCP `CONFIANCE_BRISABLE`).
pub const BREAKABLE_FROM: f64 = 0.6;

/// Confidence at or above which a counterparty counts as close (MPCP `_appraisal`).
pub const CLOSE_FROM: f64 = 0.65;

/// Confidence at or below which a counterparty counts as distrusted (MPCP `_appraisal`).
pub const WARY_UNDER: f64 = 0.35;

/// Largest accepted event weight (MPCP clamps `poids` to `0..=10`).
pub const MAX_WEIGHT: f64 = 10.0;

/// Felt weight of a bad event from a close counterparty (MPCP `_appraisal`,
/// Kahneman–Tversky λ≈2).
pub const APPRAISAL_CLOSE_BAD: f64 = 2.0;

/// Felt weight of a bad event from an already-distrusted counterparty.
pub const APPRAISAL_WARY_BAD: f64 = 0.5;

/// Felt weight of a good event from an already-distrusted counterparty.
pub const APPRAISAL_WARY_GOOD: f64 = 1.5;

fn clamp01(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Whether an event is good or bad news about the counterparty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    /// The counterparty did well by us.
    Good,
    /// The counterparty did badly by us.
    Bad,
}

/// A recorded fact about a counterparty that moves trust.
///
/// These are *facts*, not feelings: each one corresponds to something the store
/// can point at — a delivery receipt, a quote, a purchase order line. Trust
/// cannot be moved by anything else, which is what stops a mood from becoming a
/// judgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustEvent {
    /// A commitment was honoured: delivered on the promised date, at the quoted
    /// price, to the agreed spec. MPCP `objectif_atteint`.
    PromiseKept,
    /// An agreed term was violated: price moved after the purchase order, spec
    /// silently substituted, an accepted order never shipped. MPCP
    /// `contrainte_violee`.
    CommitmentBroken,
    /// A fault we have already seen from them happened again: late once more,
    /// same defect again, same missing document again. MPCP `erreur_repetee`.
    FaultRepeated,
}

impl TrustEvent {
    /// The unweighted confidence increment, straight from MPCP `LIEN_DELTAS`.
    pub const fn delta(self) -> f64 {
        match self {
            Self::PromiseKept => KEPT_PROMISE_DELTA,
            Self::CommitmentBroken => BROKEN_COMMITMENT_DELTA,
            Self::FaultRepeated => REPEATED_FAULT_DELTA,
        }
    }

    /// Good or bad news.
    pub const fn polarity(self) -> Polarity {
        match self {
            Self::PromiseKept => Polarity::Good,
            Self::CommitmentBroken | Self::FaultRepeated => Polarity::Bad,
        }
    }
}

// ---------------------------------------------------------------------------
// Appraisal
// ---------------------------------------------------------------------------

/// How a counterparty currently stands, for tone and prioritisation only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// Confidence at or above [`CLOSE_FROM`], and never broken.
    Close,
    /// Neither close nor distrusted — including everyone never dealt with.
    Neutral,
    /// Confidence at or below [`WARY_UNDER`].
    Wary,
}

/// The felt weight of one event, given the history with its counterparty.
///
/// MPCP's `_appraisal`: the impact of an event emerges from the relationship,
/// read from state and never from text. A late delivery from a three-year
/// partner is not the same event as one from a stranger.
///
/// This is a *felt weight*. It scales how loudly the event should be reported
/// and how high it should sit in the queue. It does **not** scale the
/// confidence movement — MPCP applies it to the emotional charge, not to
/// `d_lien`, and doubling it into the confidence update would double-count
/// against the shock absorber. And it is never, ever an input to authorisation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Appraisal {
    /// Where the counterparty stands right now.
    pub standing: Standing,
    /// Whether the link has ever been broken. Permanent.
    pub broken: bool,
    /// Multiplier on the felt weight of the event: 1.0 when the relationship
    /// says nothing.
    pub factor: f64,
}

impl Appraisal {
    /// Weigh an event against a link. `None` is a counterparty never dealt
    /// with, which weighs neutrally.
    pub fn of(link: Option<&TrustLink>, polarity: Polarity) -> Self {
        let standing = link.map_or(Standing::Neutral, TrustLink::standing);
        let broken = link.is_some_and(TrustLink::is_broken);
        let factor = match (polarity, standing) {
            (Polarity::Bad, Standing::Close) => APPRAISAL_CLOSE_BAD,
            (Polarity::Bad, Standing::Wary) => APPRAISAL_WARY_BAD,
            (Polarity::Good, Standing::Wary) => APPRAISAL_WARY_GOOD,
            _ => 1.0,
        };
        Self {
            standing,
            broken,
            factor,
        }
    }
}

// ---------------------------------------------------------------------------
// TrustLink
// ---------------------------------------------------------------------------

/// A rehydration of a stored link produced values outside the model.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// Stored confidence was not a finite number in `0.0..=1.0`.
    #[error("stored confidence must be finite and within 0.0..=1.0, got {got}")]
    Confidence {
        /// The rejected value, rendered.
        got: String,
    },
}

/// Serialised shape of a [`TrustLink`], so that rehydrating from a database row
/// still goes through validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkWire {
    confidence: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broken_at: Option<DateTime<Utc>>,
}

/// Trust in one counterparty.
///
/// Confidence lives in `0.0..=1.0` and moves only through
/// [`TrustLedger::record`]. There is deliberately no way to set it: what an
/// agent believes about a supplier has to be the arithmetic of what that
/// supplier did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "LinkWire", into = "LinkWire")]
pub struct TrustLink {
    confidence: f64,
    broken_at: Option<DateTime<Utc>>,
}

impl Default for TrustLink {
    /// A counterparty we have never dealt with: [`BASE_CONFIDENCE`], intact.
    fn default() -> Self {
        Self {
            confidence: BASE_CONFIDENCE,
            broken_at: None,
        }
    }
}

impl TrustLink {
    /// Current confidence, in `0.0..=1.0`.
    pub const fn confidence(&self) -> f64 {
        self.confidence
    }

    /// When the link broke, if it ever did. Never cleared.
    pub const fn broken_at(&self) -> Option<DateTime<Utc>> {
        self.broken_at
    }

    /// Whether this link has ever been broken.
    pub const fn is_broken(&self) -> bool {
        self.broken_at.is_some()
    }

    /// Where the counterparty stands.
    ///
    /// A broken link can never read [`Standing::Close`] again, however many
    /// good deliveries follow: the scar caps it at [`Standing::Neutral`]. That
    /// is the one deviation from MPCP here, where breakage instead freezes the
    /// slow social repair that this port does not carry.
    pub fn standing(&self) -> Standing {
        match self.confidence {
            c if c >= CLOSE_FROM && !self.is_broken() => Standing::Close,
            c if c <= WARY_UNDER => Standing::Wary,
            _ => Standing::Neutral,
        }
    }

    /// Move confidence by one weighted event. See [`TrustLedger::record`].
    fn apply(&mut self, event: TrustEvent, weight: f64, now: DateTime<Utc>) -> LinkChange {
        // MPCP frontier handling: NaN neutralises to 1.0, negatives forbidden,
        // ceiling at 10 — a weight is a magnitude, never a sign flip.
        let weight = if weight.is_nan() {
            1.0
        } else {
            weight.clamp(0.0, MAX_WEIGHT)
        };
        let before = self.confidence;
        let mut increment = event.delta() * weight;

        if increment < 0.0 {
            // Prior resistance (Bayes): built attachment absorbs the isolated
            // blow, only accumulation undoes it — then the avalanche, since each
            // blow weakens the resistance to the next.
            increment *= 1.0 - SHOCK_ABSORBER * (before - BASE_CONFIDENCE).max(0.0) * 2.0;
        }

        self.confidence = clamp01(before + increment);

        let broke = before - self.confidence > BREAK_DROP
            && before >= BREAKABLE_FROM
            && self.broken_at.is_none();
        if broke {
            self.broken_at = Some(now);
        }

        LinkChange {
            event,
            before,
            after: self.confidence,
            broke,
        }
    }
}

impl TryFrom<LinkWire> for TrustLink {
    type Error = LinkError;

    fn try_from(wire: LinkWire) -> Result<Self, Self::Error> {
        if !wire.confidence.is_finite() || !(0.0..=1.0).contains(&wire.confidence) {
            return Err(LinkError::Confidence {
                got: wire.confidence.to_string(),
            });
        }
        Ok(Self {
            confidence: wire.confidence,
            broken_at: wire.broken_at,
        })
    }
}

impl From<TrustLink> for LinkWire {
    fn from(link: TrustLink) -> Self {
        Self {
            confidence: link.confidence,
            broken_at: link.broken_at,
        }
    }
}

/// What one recorded event did to a link — the oplog entry, and the only way
/// confidence is ever observed to move.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LinkChange {
    /// The event that was recorded.
    pub event: TrustEvent,
    /// Confidence before it.
    pub before: f64,
    /// Confidence after it.
    pub after: f64,
    /// Whether this event broke the link. True at most once per link.
    pub broke: bool,
}

// ---------------------------------------------------------------------------
// TrustLedger
// ---------------------------------------------------------------------------

/// Every trust link the agent holds, keyed by supplier handle.
///
/// Backed by a [`BTreeMap`], so iteration, serialisation and every derived
/// output are in handle order regardless of insertion order. Two agents fed the
/// same events in the same order hold byte-identical ledgers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrustLedger {
    links: BTreeMap<Slug, TrustLink>,
}

impl TrustLedger {
    /// An agent that has dealt with nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// The link with one counterparty, if any event has ever been recorded
    /// against it.
    pub fn get(&self, counterparty: &Slug) -> Option<&TrustLink> {
        self.links.get(counterparty)
    }

    /// Confidence in one counterparty, [`BASE_CONFIDENCE`] for a stranger.
    pub fn confidence(&self, counterparty: &Slug) -> f64 {
        self.get(counterparty)
            .map_or(BASE_CONFIDENCE, TrustLink::confidence)
    }

    /// Weigh a hypothetical event against the current relationship, for tone
    /// and prioritisation. Reads nothing but state; changes nothing.
    pub fn appraise(&self, counterparty: &Slug, polarity: Polarity) -> Appraisal {
        Appraisal::of(self.get(counterparty), polarity)
    }

    /// Record a fact about a counterparty and move its confidence.
    ///
    /// `weight` is the magnitude of the fact — a 40-day slip is not a 2-day
    /// slip — clamped to `0.0..=`[`MAX_WEIGHT`], with `NaN` neutralised to 1.0.
    /// `now` is passed in, never read: the ledger is replayable.
    ///
    /// A link is created at [`BASE_CONFIDENCE`] the first time a counterparty
    /// is recorded against, so a first event moves it from neutral, not from
    /// nothing.
    pub fn record(
        &mut self,
        counterparty: &Slug,
        event: TrustEvent,
        weight: f64,
        now: DateTime<Utc>,
    ) -> LinkChange {
        let link = match self.links.entry(counterparty.clone()) {
            Entry::Occupied(slot) => slot.into_mut(),
            Entry::Vacant(slot) => slot.insert(TrustLink::default()),
        };
        link.apply(event, weight, now)
    }

    /// Every link, in handle order.
    pub fn iter(&self) -> impl Iterator<Item = (&Slug, &TrustLink)> {
        self.links.iter()
    }

    /// Counterparties whose link has been broken, in handle order. Membership
    /// here is permanent.
    pub fn broken(&self) -> impl Iterator<Item = &Slug> {
        self.links
            .iter()
            .filter(|(_, link)| link.is_broken())
            .map(|(handle, _)| handle)
    }

    /// Counterparties ranked most trusted first, ties broken by handle so the
    /// order is total and stable. This is the prioritisation surface: whom to
    /// ask first, never whom to allow.
    pub fn ranked(&self) -> Vec<(&Slug, &TrustLink)> {
        let mut out: Vec<_> = self.links.iter().collect();
        // Confidence is always finite here (validated on construction and on
        // rehydration), so a total_cmp on it is a total order.
        out.sort_by(|(a_handle, a), (b_handle, b)| {
            b.confidence
                .total_cmp(&a.confidence)
                .then_with(|| a_handle.cmp(b_handle))
        });
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use proptest::prelude::*;

    fn handle(s: &str) -> Slug {
        Slug::parse(s).expect("test handle")
    }

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 12, 0, 0).unwrap()
    }

    /// Feed n kept promises to build a link up.
    fn build(ledger: &mut TrustLedger, who: &Slug, n: usize) {
        for _ in 0..n {
            ledger.record(who, TrustEvent::PromiseKept, 1.0, at(1));
        }
    }

    #[test]
    fn a_stranger_sits_at_the_neutral_prior() {
        let ledger = TrustLedger::new();
        let who = handle("acme-forge");
        assert_eq!(ledger.get(&who), None);
        assert_eq!(ledger.confidence(&who), BASE_CONFIDENCE);
        assert_eq!(
            ledger.appraise(&who, Polarity::Bad).standing,
            Standing::Neutral
        );
    }

    #[test]
    fn trust_cannot_be_assigned_only_earned() {
        // The only public constructors produce the neutral prior; the only way
        // to move confidence is to record a fact.
        assert_eq!(TrustLink::default().confidence(), BASE_CONFIDENCE);
        let mut ledger = TrustLedger::new();
        let who = handle("acme-forge");
        build(&mut ledger, &who, 3);
        assert!((ledger.confidence(&who) - 0.8).abs() < 1e-12);
    }

    #[test]
    fn a_corrupt_stored_confidence_is_rejected() {
        let bad = r#"{"confidence": 1.4}"#;
        assert!(serde_json::from_str::<TrustLink>(bad).is_err());
        let nan = r#"{"confidence": null}"#;
        assert!(serde_json::from_str::<TrustLink>(nan).is_err());
        let good = r#"{"confidence": 0.75}"#;
        let link: TrustLink = serde_json::from_str(good).unwrap();
        assert_eq!(link.confidence(), 0.75);
        assert!(!link.is_broken());
    }

    #[test]
    fn kept_promises_build_and_saturate_at_one() {
        let mut ledger = TrustLedger::new();
        let who = handle("acme-forge");
        build(&mut ledger, &who, 40);
        assert_eq!(ledger.confidence(&who), 1.0);
        assert!(!ledger.get(&who).unwrap().is_broken());
    }

    #[test]
    fn breaking_requires_having_been_built() {
        // A stranger who violates a contract on day one collapses to the floor
        // but breaks nothing: there was no trust to betray (Berg asymmetry).
        let mut cold = TrustLedger::new();
        let who = handle("cold-supplier");
        let change = cold.record(&who, TrustEvent::CommitmentBroken, 3.0, at(1));
        assert_eq!(change.after, 0.0);
        assert!(change.before - change.after > BREAK_DROP);
        assert!(!change.broke, "a cold link cannot be broken");
        assert!(!cold.get(&who).unwrap().is_broken());

        // The same violation from a partner we built up does break.
        let mut warm = TrustLedger::new();
        let partner = handle("warm-supplier");
        build(&mut warm, &partner, 3); // 0.8
        let change = warm.record(&partner, TrustEvent::CommitmentBroken, 3.0, at(2));
        assert!(change.broke, "a built link must break");
        assert_eq!(warm.get(&partner).unwrap().broken_at(), Some(at(2)));
    }

    #[test]
    fn the_shock_absorber_wounds_first_and_kills_second() {
        // MPCP's own calibration note for AMORTI_LIEN = 0.85: at 0.95 a
        // weight-3 blow wounds (-0.18) without breaking; the SECOND one breaks.
        // A 0.95 link, reached the only legitimate way: build to saturation,
        // then absorb one small fault.
        let mut link = TrustLink::default();
        for _ in 0..5 {
            link.apply(TrustEvent::PromiseKept, 1.0, at(1));
        }
        let first = link.apply(TrustEvent::FaultRepeated, 1.0, at(1));
        assert!(first.before > 0.9);

        let hit1 = link.apply(TrustEvent::CommitmentBroken, 3.0, at(2));
        assert!(
            !hit1.broke,
            "one blow must not undo a long relationship, dropped {}",
            hit1.before - hit1.after
        );
        let hit2 = link.apply(TrustEvent::CommitmentBroken, 3.0, at(3));
        assert!(hit2.broke, "the second blow must break: doubt then kills");
    }

    #[test]
    fn a_slow_decline_erodes_without_breaking() {
        // "la trahison a froid ne brise rien": confidence that has already sunk
        // below BREAKABLE_FROM can fall further but never registers a rupture.
        let mut link = TrustLink::default();
        let mut broke_any = false;
        for _ in 0..30 {
            broke_any |= link.apply(TrustEvent::FaultRepeated, 1.0, at(1)).broke;
        }
        assert!(!broke_any);
        assert_eq!(link.confidence(), 0.0);
        assert!(!link.is_broken());
    }

    #[test]
    fn breakage_is_structural_and_not_re_earnable() {
        let mut ledger = TrustLedger::new();
        let who = handle("was-a-partner");
        build(&mut ledger, &who, 3);
        let broke = ledger.record(&who, TrustEvent::CommitmentBroken, 3.0, at(2));
        assert!(broke.broke);
        let broken_at = ledger.get(&who).unwrap().broken_at();

        // One good delivery does not undo it. Nor do twenty.
        build(&mut ledger, &who, 1);
        assert!(ledger.get(&who).unwrap().is_broken());
        build(&mut ledger, &who, 20);
        assert_eq!(ledger.confidence(&who), 1.0);
        let link = ledger.get(&who).unwrap();
        assert!(link.is_broken(), "the scar must stay visible");
        assert_eq!(link.broken_at(), broken_at, "breakage date is immutable");
        assert_eq!(
            link.standing(),
            Standing::Neutral,
            "a broken link never reads Close again"
        );
        assert_eq!(ledger.broken().collect::<Vec<_>>(), vec![&who]);

        // And it can only be broken once.
        let again = ledger.record(&who, TrustEvent::CommitmentBroken, 3.0, at(5));
        assert!(!again.broke);
        assert_eq!(ledger.get(&who).unwrap().broken_at(), broken_at);
    }

    #[test]
    fn proximity_weighting_is_exactly_two() {
        let mut ledger = TrustLedger::new();
        let close = handle("three-year-partner");
        let stranger = handle("first-order");
        let wary = handle("known-slipper");

        build(&mut ledger, &close, 2); // 0.7 -> Close
        ledger.record(&wary, TrustEvent::FaultRepeated, 2.0, at(1)); // 0.3 -> Wary

        let bad_from_close = ledger.appraise(&close, Polarity::Bad);
        let bad_from_stranger = ledger.appraise(&stranger, Polarity::Bad);
        let bad_from_wary = ledger.appraise(&wary, Polarity::Bad);

        assert_eq!(bad_from_close.standing, Standing::Close);
        assert_eq!(bad_from_stranger.standing, Standing::Neutral);
        assert_eq!(bad_from_wary.standing, Standing::Wary);

        assert_eq!(bad_from_stranger.factor, 1.0);
        assert_eq!(bad_from_close.factor, 2.0);
        assert!(
            (bad_from_close.factor - 2.0 * bad_from_stranger.factor).abs() < f64::EPSILON,
            "a late delivery from a three-year partner must weigh exactly twice a stranger's"
        );
        assert_eq!(bad_from_wary.factor, 0.5, "that figures");

        // Unexpected decency from a distrusted supplier is worth noticing.
        assert_eq!(ledger.appraise(&wary, Polarity::Good).factor, 1.5);
        assert_eq!(ledger.appraise(&close, Polarity::Good).factor, 1.0);
        assert_eq!(ledger.appraise(&stranger, Polarity::Good).factor, 1.0);
    }

    #[test]
    fn appraisal_does_not_move_confidence() {
        // The felt weight is a read. Reading it a hundred times changes nothing.
        let mut ledger = TrustLedger::new();
        let who = handle("acme-forge");
        build(&mut ledger, &who, 2);
        let before = serde_json::to_string(&ledger).unwrap();
        for _ in 0..100 {
            ledger.appraise(&who, Polarity::Bad);
            ledger.appraise(&who, Polarity::Good);
        }
        assert_eq!(serde_json::to_string(&ledger).unwrap(), before);
    }

    #[test]
    fn weight_frontiers_are_neutralised() {
        // NaN weight -> 1.0 (MPCP), negative -> 0.0 (a weight never flips sign),
        // absurd -> MAX_WEIGHT.
        let mut nan = TrustLink::default();
        let mut one = TrustLink::default();
        nan.apply(TrustEvent::PromiseKept, f64::NAN, at(1));
        one.apply(TrustEvent::PromiseKept, 1.0, at(1));
        assert_eq!(nan.confidence(), one.confidence());

        let mut negative = TrustLink::default();
        let change = negative.apply(TrustEvent::CommitmentBroken, -5.0, at(1));
        assert_eq!(change.after, BASE_CONFIDENCE);

        let mut huge = TrustLink::default();
        let mut capped = TrustLink::default();
        huge.apply(TrustEvent::CommitmentBroken, f64::INFINITY, at(1));
        capped.apply(TrustEvent::CommitmentBroken, MAX_WEIGHT, at(1));
        assert_eq!(huge.confidence(), capped.confidence());
    }

    #[test]
    fn counterparty_order_never_changes_an_observable_output() {
        let events = [
            (handle("zeta-metals"), TrustEvent::PromiseKept),
            (handle("alpha-tools"), TrustEvent::CommitmentBroken),
            (handle("mid-cast"), TrustEvent::FaultRepeated),
            (handle("zeta-metals"), TrustEvent::PromiseKept),
            (handle("alpha-tools"), TrustEvent::PromiseKept),
        ];

        let mut forward = TrustLedger::new();
        for (who, event) in &events {
            forward.record(who, *event, 1.0, at(1));
        }
        // Same per-counterparty sequences, different interleaving of suppliers.
        let mut interleaved = TrustLedger::new();
        for (who, event) in [&events[1], &events[4], &events[0], &events[3], &events[2]] {
            interleaved.record(who, *event, 1.0, at(1));
        }

        assert_eq!(forward, interleaved);
        assert_eq!(
            serde_json::to_string(&forward).unwrap(),
            serde_json::to_string(&interleaved).unwrap()
        );
        assert_eq!(
            forward.ranked().iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            interleaved
                .ranked()
                .iter()
                .map(|(h, _)| *h)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            forward.iter().map(|(h, _)| h).collect::<Vec<_>>(),
            vec![
                &handle("alpha-tools"),
                &handle("mid-cast"),
                &handle("zeta-metals")
            ]
        );
    }

    #[test]
    fn ranking_is_total_even_on_ties() {
        let mut ledger = TrustLedger::new();
        for who in ["b-supplier", "a-supplier", "c-supplier"] {
            ledger.record(&handle(who), TrustEvent::PromiseKept, 1.0, at(1));
        }
        let ranked: Vec<_> = ledger
            .ranked()
            .into_iter()
            .map(|(h, _)| h.as_str().to_owned())
            .collect();
        assert_eq!(ranked, vec!["a-supplier", "b-supplier", "c-supplier"]);
    }

    // -- properties ---------------------------------------------------------

    fn any_event() -> impl Strategy<Value = TrustEvent> {
        prop_oneof![
            Just(TrustEvent::PromiseKept),
            Just(TrustEvent::CommitmentBroken),
            Just(TrustEvent::FaultRepeated),
        ]
    }

    fn any_run() -> impl Strategy<Value = Vec<(TrustEvent, f64)>> {
        proptest::collection::vec((any_event(), 0.0f64..=12.0), 0..80)
    }

    proptest! {
        /// No sequence of ordinary events can drive confidence outside 0..=1.
        #[test]
        fn confidence_stays_in_bounds(run in any_run()) {
            let mut ledger = TrustLedger::new();
            let who = handle("prop-supplier");
            for (event, weight) in run {
                let change = ledger.record(&who, event, weight, at(1));
                prop_assert!(change.after.is_finite());
                prop_assert!((0.0..=1.0).contains(&change.after));
                prop_assert!((0.0..=1.0).contains(&ledger.confidence(&who)));
            }
        }

        /// Replay: the same sequence yields the same state, bit for bit.
        #[test]
        fn replay_is_bit_identical(run in any_run()) {
            let who = handle("prop-supplier");
            let play = |run: &[(TrustEvent, f64)]| {
                let mut ledger = TrustLedger::new();
                let changes: Vec<_> = run
                    .iter()
                    .map(|(event, weight)| ledger.record(&who, *event, *weight, at(1)))
                    .collect();
                (serde_json::to_string(&ledger).unwrap(), changes)
            };
            prop_assert_eq!(play(&run), play(&run));
        }

        /// Breakage is one-way: it is never observed to un-break.
        #[test]
        fn breakage_is_monotonic(run in any_run()) {
            let mut ledger = TrustLedger::new();
            let who = handle("prop-supplier");
            let mut seen_broken = false;
            let mut breaks = 0;
            for (event, weight) in run {
                breaks += usize::from(ledger.record(&who, event, weight, at(1)).broke);
                seen_broken |= ledger.get(&who).unwrap().is_broken();
                prop_assert_eq!(ledger.get(&who).unwrap().is_broken(), seen_broken);
            }
            prop_assert!(breaks <= 1);
        }

        /// Nothing can break a link that never rose to BREAKABLE_FROM.
        #[test]
        fn a_never_built_link_never_breaks(run in proptest::collection::vec(
            (prop_oneof![Just(TrustEvent::CommitmentBroken), Just(TrustEvent::FaultRepeated)],
             0.0f64..=12.0), 0..80))
        {
            let mut ledger = TrustLedger::new();
            let who = handle("prop-supplier");
            for (event, weight) in run {
                prop_assert!(!ledger.record(&who, event, weight, at(1)).broke);
            }
            prop_assert!(!ledger.get(&who).is_some_and(TrustLink::is_broken));
        }
    }
}
