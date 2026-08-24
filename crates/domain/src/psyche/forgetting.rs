//! Differentiated forgetting — the mechanism that stops the supplier book from
//! burning down.
//!
//! Ported from the `OUBLI` / "pardon" chantier of MPCP (`mpcp.py` lines 180-197,
//! 1442-1458, 1366-1382, 640-651). That project's long run produced a *dystopia*
//! at day 43 — 23 outcasts out of 30, median friction 0.99, the village
//! effectively dead — for exactly one reason: **nothing forgot**. The same seed
//! with differentiated forgetting produced a functioning village at day 36 with
//! friction 0.06.
//!
//! A purchasing agent has the identical failure mode. Every supplier eventually
//! disappoints once. Without forgetting the agent accumulates a permanent
//! grievance against every counterparty it has ever dealt with and ends up
//! unable to buy anything.
//!
//! Three volets are ported here:
//!
//! 1. **Affective fade, differentiated by provenance.** A trace that nothing
//!    revives pales. FIRST-HAND experience stops at an imprescriptible floor
//!    ([`MISTRUST_FLOOR`], 0.4 — MPCP's `OUBLI_PLANCHER_VECU`): the legitimate
//!    cold grudge survives forever. HEARSAY fades all the way to zero. What you
//!    witnessed yourself outranks what you were told, permanently.
//! 2. **Sanction fatigue.** A transgression you already PREDICTED stops being
//!    outrageous (Rescorla-Wagner: `surprise = observed - expectation`, and the
//!    outrage weight floors at [`SURPRISE_MIN`]). This is what stops the agent
//!    re-litigating a known flaw at every single interaction. Expectations
//!    themselves extinguish towards zero, so the immunity is never permanent —
//!    a supplier that reforms becomes sanctionable again.
//! 3. **Allostatic recovery.** The resting friction set-point drifts back down
//!    on its own. MPCP calls this *"LE verrou racine"*: without it nothing ever
//!    pushed the set-point below its own baseline and chronic stress ratcheted
//!    for life.
//!
//! # The governing invariant
//!
//! **This module influences TONE and PRIORITISATION. It must NEVER influence
//! AUTHORISATION.** Nothing here may be fed into [`crate::policy::evaluate`].
//! A [`Stance`] may decide whom to chase first, how firmly to phrase a chaser,
//! or whether to ask for a second quote — it may never widen a permission or
//! change a limit. MPCP states the same rule for itself: *"l'identité ne colore
//! QUE le ressenti, jamais la dynamique"*.
//!
//! # Determinism
//!
//! [`Ledger::decay`] is a pure function of the elapsed [`Duration`] handed to
//! it. Nothing in this file reads a clock, and every collection is a
//! [`BTreeMap`], so iteration order is the key order and replay is exact.

use std::collections::BTreeMap;

use chrono::Duration;
use serde::{Deserialize, Serialize};

use crate::ids::Slug;

/// Seconds in one MPCP *derive* period, the step at which the engine ages its
/// state. MPCP: `OUBLI_DELAI = 900` ticks *"(3 j)"* gives 300 ticks/day, and
/// `PERIODE_DERIVE = 5` ticks gives 60 derives/day — 1440 real seconds each.
pub const DERIVE_SECONDS: i64 = 1_440;

/// Derive periods a trace must sit unrevived before it starts to fade.
/// MPCP `OUBLI_DELAI` (900 ticks = 3 days).
pub const GRACE_DERIVES: u64 = 180;

/// Strength lost per derive period once the grace window has passed.
/// MPCP `OUBLI_PAS = 0.0005` — 0.03/day, so 1.0 -> 0.4 in twenty days.
pub const FADE_PER_DERIVE: f64 = 0.0005;

/// The imprescriptible floor under first-hand experience. MPCP
/// `OUBLI_PLANCHER_VECU = 0.4`: *"le vecu direct ne s'oublie jamais sous la
/// mefiance"*. Kept unchanged.
pub const MISTRUST_FLOOR: f64 = 0.4;

/// Ceiling on a trace that has only ever been reported to us. MPCP
/// `CONF_CAP_OUIDIRE = 0.45`: *"jamais vecu en direct -> jamais une certitude"*.
pub const HEARSAY_CAP: f64 = 0.45;

/// Floor on the outrage weight of a fully predicted event. MPCP
/// `SURPRISE_MIN = 0.5`: a real stressor still stresses when it was expected;
/// surprise drives *learning*, not the whole of the felt impact.
pub const SURPRISE_MIN: f64 = 0.5;

/// Rescorla-Wagner learning rate for expectations. MPCP `TAUX_PRED = 0.3`
/// (~3 events to converge).
pub const LEARNING_RATE: f64 = 0.3;

/// Multiplicative extinction of expectations per derive period. MPCP
/// `RAPPEL_ATTENTES = 0.001`: *"sans ca la fatigue de sanction etait une
/// immunite PERMANENTE"*.
pub const EXTINCTION_PER_DERIVE: f64 = 0.001;

/// Allostatic recovery of the resting friction set-point, per derive period.
/// MPCP `RAPPEL_BASELINE_FRICTION = 0.001` (0.06/day).
pub const FRICTION_RECOVERY_PER_DERIVE: f64 = 0.001;

/// Net grudge at which a counterparty is treated as hostile. MPCP
/// `SEUIL_CONFRONTATION = 0.4`.
pub const HOSTILITY_THRESHOLD: f64 = 0.4;

/// Cap on summed excess, MPCP `min(2.0, sum(...))` at `mpcp.py:1299`.
pub const GRUDGE_CAP: f64 = 2.0;

/// How we came to hold a trace.
///
/// The ordering is load-bearing: `FirstHand > Hearsay`, so re-recording a
/// reported grievance you then witness yourself upgrades it permanently and it
/// gains the imprescriptible floor. It never downgrades.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Someone told us. Fades to zero.
    Hearsay,
    /// We observed it ourselves. Fades only to [`MISTRUST_FLOOR`].
    FirstHand,
}

/// Which way a trace points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sentiment {
    /// They let us down.
    Adverse,
    /// They came through.
    Favourable,
}

impl Sentiment {
    /// Observed polarity for the Rescorla-Wagner update (`pol_obs` in MPCP).
    const fn polarity(self) -> f64 {
        match self {
            Self::Adverse => -1.0,
            Self::Favourable => 1.0,
        }
    }
}

/// What a trace is about: a counterparty and the thing they did.
///
/// `topic` is the MPCP event *type* (`"lead-time-miss"`, `"price-hike"`,
/// `"short-shipped"`) and `counterparty` the *subject*; together they form
/// MPCP's `f"{type}|{sujet}"` prediction cue, which is why sanction fatigue is
/// per-topic: a supplier who is reliably late is not also excused for
/// short-shipping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TraceKey {
    /// Who.
    pub counterparty: Slug,
    /// What kind of thing they did.
    pub topic: Slug,
}

impl TraceKey {
    /// A key from its two parts.
    pub const fn new(counterparty: Slug, topic: Slug) -> Self {
        Self {
            counterparty,
            topic,
        }
    }
}

/// One remembered thing about one counterparty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    /// Adverse or favourable.
    pub sentiment: Sentiment,
    /// First-hand or hearsay; only ever upgrades.
    pub provenance: Provenance,
    /// How strongly it is held, in `0.0..=1.0`.
    pub strength: f64,
    /// Rescorla-Wagner expectation for this cue, in `-1.0..=1.0`.
    pub expectation: f64,
    /// Derive periods since the last time this trace was revived.
    pub idle_derives: u64,
}

/// How the agent currently reads a counterparty. Advisory only — see the
/// governing invariant in the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stance {
    /// Net goodwill past the threshold: chase them last, they deliver.
    Trusted,
    /// Nothing much either way.
    Neutral,
    /// A first-hand grievance at or above the mistrust floor survives. The cold
    /// grudge — forgiveness is not amnesia.
    Wary,
    /// Net grudge past the threshold.
    Hostile,
}

/// The forgetting ledger for one agent.
///
/// Construct with [`Ledger::new`]. [`Ledger::without_forgetting`] freezes all
/// three volets and reproduces the pre-pardon MPCP engine — it exists so the
/// dystopia can be replayed and compared, not because anyone should run it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ledger {
    traces: BTreeMap<TraceKey, Trace>,
    resting_friction: f64,
    forgetting: bool,
    /// Elapsed seconds not yet worth a whole derive period. Carried so that
    /// many small [`Ledger::decay`] calls age the state as much as one big one.
    residue_seconds: i64,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledger {
    /// An empty ledger that forgets.
    pub const fn new() -> Self {
        Self {
            traces: BTreeMap::new(),
            resting_friction: 0.0,
            forgetting: true,
            residue_seconds: 0,
        }
    }

    /// An empty ledger that never forgets — the pre-pardon engine, for replay
    /// and for the dystopia comparison test. Do not ship this.
    pub const fn without_forgetting() -> Self {
        Self {
            traces: BTreeMap::new(),
            resting_friction: 0.0,
            forgetting: false,
            residue_seconds: 0,
        }
    }

    /// Record an observation and return its **outrage weight** in
    /// `SURPRISE_MIN..=1.0`.
    ///
    /// This is sanction fatigue (MPCP `mpcp.py:640-651`): the weight is
    /// `SURPRISE_MIN + (1 - SURPRISE_MIN) * min(1, |observed - expectation|)`.
    /// A first contact is fully surprising and weighs 1.0; a transgression the
    /// agent already expected weighs the floor. Callers should use the weight
    /// to decide how much *tone* the event earns — not whether it is allowed.
    ///
    /// A trace of the opposite sentiment on the same key is eroded rather than
    /// stacked (MPCP `mpcp.py:631-640`), which is what lets a supplier redeem
    /// itself by delivering.
    pub fn record(&mut self, key: TraceKey, sentiment: Sentiment, provenance: Provenance) -> f64 {
        let trace = self.traces.entry(key).or_insert(Trace {
            sentiment,
            provenance,
            strength: 0.0,
            expectation: 0.0,
            idle_derives: 0,
        });

        let surprise = sentiment.polarity() - trace.expectation;
        let weight = SURPRISE_MIN + (1.0 - SURPRISE_MIN) * surprise.abs().min(1.0);

        trace.expectation = (trace.expectation + LEARNING_RATE * surprise).clamp(-1.0, 1.0);
        trace.provenance = trace.provenance.max(provenance);
        trace.idle_derives = 0;

        let cap = match trace.provenance {
            Provenance::FirstHand => 1.0,
            Provenance::Hearsay => HEARSAY_CAP,
        };

        if trace.sentiment == sentiment {
            trace.strength = (trace.strength + weight).min(cap);
        } else {
            trace.strength -= weight;
            if trace.strength <= 0.0 {
                trace.sentiment = sentiment;
                trace.strength = (-trace.strength).min(cap);
            }
        }

        weight
    }

    /// Age the whole ledger by `elapsed`.
    ///
    /// Pure function of the duration handed in: no clock is read, and the
    /// remainder below one derive period is carried, so `decay(30 days)` and
    /// thirty `decay(1 day)` calls land in the same place.
    ///
    /// Negative durations are treated as zero — time does not run backwards and
    /// a clock skew must not resurrect a grudge.
    pub fn decay(&mut self, elapsed: Duration) {
        if !self.forgetting {
            return;
        }

        let total = self
            .residue_seconds
            .saturating_add(elapsed.num_seconds().max(0));
        let steps = total / DERIVE_SECONDS;
        self.residue_seconds = total % DERIVE_SECONDS;
        if steps == 0 {
            return;
        }
        let steps = steps.unsigned_abs();
        let steps_f = steps as f64;

        // Volet 3 — allostatic recovery of the resting set-point.
        self.resting_friction =
            (self.resting_friction - steps_f * FRICTION_RECOVERY_PER_DERIVE).max(0.0);

        // Volet 2 — Rescorla-Wagner extinction. Stepped exactly as MPCP steps
        // it rather than closed-form, so no transcendental function sits in the
        // replay path. Bails out once the factor is below f64 resolution: any
        // expectation is <= 1.0, so the difference is unrepresentable anyway.
        let mut retention = 1.0_f64;
        for _ in 0..steps {
            retention *= 1.0 - EXTINCTION_PER_DERIVE;
            if retention < f64::EPSILON {
                retention = 0.0;
                break;
            }
        }

        // Volet 1 — differentiated affective fade.
        for trace in self.traces.values_mut() {
            let before = trace.idle_derives;
            trace.idle_derives = before.saturating_add(steps);
            let fading = trace.idle_derives.saturating_sub(before.max(GRACE_DERIVES));
            if fading > 0 {
                let floor = match trace.provenance {
                    Provenance::FirstHand => MISTRUST_FLOOR,
                    Provenance::Hearsay => 0.0,
                };
                // `floor.min(strength)` so the floor can only ever stop a fade,
                // never raise a trace that erosion already pushed below it.
                trace.strength = (trace.strength - fading as f64 * FADE_PER_DERIVE)
                    .max(floor.min(trace.strength));
            }
            trace.expectation *= retention;
        }
    }

    /// The trace for a key, if one is held.
    pub fn trace(&self, key: &TraceKey) -> Option<&Trace> {
        self.traces.get(key)
    }

    /// Summed adverse strength *in excess of the mistrust floor*, capped at
    /// [`GRUDGE_CAP`].
    ///
    /// MPCP `mpcp.py:1299`: only the excess beyond 0.4 counts, so the
    /// imprescriptible grudges left behind by forgetting keep their meaning
    /// without ever adding up to hostility.
    pub fn grudge(&self, counterparty: &Slug) -> f64 {
        self.excess(counterparty, Sentiment::Adverse)
    }

    /// The same sum over favourable traces (MPCP `cro_pos`, `mpcp.py:1302`).
    pub fn goodwill(&self, counterparty: &Slug) -> f64 {
        self.excess(counterparty, Sentiment::Favourable)
    }

    fn excess(&self, counterparty: &Slug, sentiment: Sentiment) -> f64 {
        self.traces
            .iter()
            .filter(|(key, trace)| {
                &key.counterparty == counterparty && trace.sentiment == sentiment
            })
            .map(|(_, trace)| (trace.strength - MISTRUST_FLOOR).max(0.0))
            .sum::<f64>()
            .min(GRUDGE_CAP)
    }

    /// How to *read* this counterparty. Advisory: tone and ordering only.
    pub fn stance(&self, counterparty: &Slug) -> Stance {
        let net = self.grudge(counterparty) - self.goodwill(counterparty);
        if net >= HOSTILITY_THRESHOLD {
            Stance::Hostile
        } else if net <= -HOSTILITY_THRESHOLD {
            Stance::Trusted
        } else if self.traces.iter().any(|(key, trace)| {
            &key.counterparty == counterparty
                && trace.sentiment == Sentiment::Adverse
                && trace.strength >= MISTRUST_FLOOR
        }) {
            Stance::Wary
        } else {
            Stance::Neutral
        }
    }

    /// The current resting friction set-point, in `0.0..=1.0`.
    pub const fn resting_friction(&self) -> f64 {
        self.resting_friction
    }

    /// Push the resting set-point up. Chronic real stress dominates recovery;
    /// [`Ledger::decay`] walks it back down.
    pub fn add_strain(&mut self, amount: f64) {
        self.resting_friction = (self.resting_friction + amount.max(0.0)).clamp(0.0, 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slug(raw: &str) -> Slug {
        Slug::parse(raw).expect("test slug")
    }

    fn key(counterparty: &str, topic: &str) -> TraceKey {
        TraceKey::new(slug(counterparty), slug(topic))
    }

    const SUPPLIERS: [&str; 6] = [
        "acme-tooling",
        "beihai-plastics",
        "cortez-castings",
        "delta-fasteners",
        "eastport-resins",
        "fujin-bearings",
    ];
    const GRIEVANCES: [&str; 3] = ["lead-time-miss", "price-hike", "short-shipped"];

    /// Runs the same disappointment sequence on the ledger it is handed and
    /// reports how many suppliers ended up hostile.
    fn run_disappointments(ledger: &mut Ledger) -> usize {
        for topic in GRIEVANCES {
            for supplier in SUPPLIERS {
                ledger.record(
                    key(supplier, topic),
                    Sentiment::Adverse,
                    Provenance::FirstHand,
                );
            }
            ledger.decay(Duration::days(10));
        }
        ledger.decay(Duration::days(60));

        SUPPLIERS
            .into_iter()
            .filter(|s| ledger.stance(&slug(s)) == Stance::Hostile)
            .count()
    }

    /// THE deliverable: MPCP's day-43 dystopia in miniature, and its cure.
    ///
    /// Identical sequence, identical order, only the forgetting gate differs.
    /// Without it every counterparty in the book ends hostile and the agent has
    /// nobody left to buy from. With it, nobody does.
    #[test]
    fn forgetting_is_what_separates_the_dystopia_from_a_working_supplier_book() {
        let mut dystopia = Ledger::without_forgetting();
        let mut cured = Ledger::new();

        let hostile_without = run_disappointments(&mut dystopia);
        let hostile_with = run_disappointments(&mut cured);

        assert_eq!(
            hostile_without,
            SUPPLIERS.len(),
            "with nothing forgetting, the whole supplier book should burn"
        );
        assert_eq!(
            hostile_with, 0,
            "differentiated forgetting must keep the book usable"
        );

        // Forgiveness is not amnesia: the first-hand grudge survives as cold
        // mistrust, it simply stops compounding into hostility.
        for supplier in SUPPLIERS {
            assert_eq!(cured.stance(&slug(supplier)), Stance::Wary);
            assert!((cured.grudge(&slug(supplier)) - 0.0).abs() < f64::EPSILON);
        }
        assert!(dystopia.grudge(&slug(SUPPLIERS[0])) > 1.0);
    }

    #[test]
    fn first_hand_experience_never_fades_below_the_floor() {
        let mut ledger = Ledger::new();
        let k = key("acme-tooling", "lead-time-miss");
        ledger.record(k.clone(), Sentiment::Adverse, Provenance::FirstHand);
        assert!((ledger.trace(&k).unwrap().strength - 1.0).abs() < f64::EPSILON);

        ledger.decay(Duration::days(10_000));
        assert!((ledger.trace(&k).unwrap().strength - MISTRUST_FLOOR).abs() < f64::EPSILON);
    }

    #[test]
    fn hearsay_fades_all_the_way_to_zero() {
        let mut ledger = Ledger::new();
        let k = key("acme-tooling", "lead-time-miss");
        ledger.record(k.clone(), Sentiment::Adverse, Provenance::Hearsay);
        assert!((ledger.trace(&k).unwrap().strength - HEARSAY_CAP).abs() < f64::EPSILON);

        ledger.decay(Duration::days(100));
        assert_eq!(ledger.trace(&k).unwrap().strength, 0.0);
    }

    #[test]
    fn witnessing_it_yourself_outranks_being_told_forever() {
        let mut ledger = Ledger::new();
        let k = key("acme-tooling", "lead-time-miss");
        ledger.record(k.clone(), Sentiment::Adverse, Provenance::Hearsay);
        ledger.record(k.clone(), Sentiment::Adverse, Provenance::FirstHand);
        // A later report does not downgrade what we saw.
        ledger.record(k.clone(), Sentiment::Adverse, Provenance::Hearsay);
        assert_eq!(ledger.trace(&k).unwrap().provenance, Provenance::FirstHand);

        ledger.decay(Duration::days(1_000));
        assert!((ledger.trace(&k).unwrap().strength - MISTRUST_FLOOR).abs() < f64::EPSILON);
    }

    #[test]
    fn a_predicted_transgression_weighs_less_than_a_surprising_one() {
        let mut ledger = Ledger::new();
        let k = key("acme-tooling", "lead-time-miss");

        let first = ledger.record(k.clone(), Sentiment::Adverse, Provenance::FirstHand);
        let second = ledger.record(k.clone(), Sentiment::Adverse, Provenance::FirstHand);
        assert!(
            (first - 1.0).abs() < f64::EPSILON,
            "first contact is a surprise"
        );
        assert!(second < first, "the second time is less outrageous");

        let mut last = second;
        for _ in 0..20 {
            let w = ledger.record(k.clone(), Sentiment::Adverse, Provenance::FirstHand);
            assert!(w <= last + f64::EPSILON);
            last = w;
        }
        assert!(
            last < SURPRISE_MIN + 0.05,
            "a fully predicted flaw should sit at the outrage floor, got {last}"
        );

        // Sanction fatigue is per-cue: a different flaw is still a surprise.
        let other = ledger.record(
            key("acme-tooling", "short-shipped"),
            Sentiment::Adverse,
            Provenance::FirstHand,
        );
        assert!((other - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sanction_immunity_is_not_permanent() {
        let mut ledger = Ledger::new();
        let k = key("acme-tooling", "lead-time-miss");
        for _ in 0..20 {
            ledger.record(k.clone(), Sentiment::Adverse, Provenance::FirstHand);
        }
        assert!(ledger.trace(&k).unwrap().expectation < -0.9);

        // MPCP S4: expectations extinguish, so a reformed supplier that slips
        // again is fully sanctionable.
        ledger.decay(Duration::days(200));
        assert!(ledger.trace(&k).unwrap().expectation.abs() < 0.01);
        let weight = ledger.record(k.clone(), Sentiment::Adverse, Provenance::FirstHand);
        assert!(weight > 0.99, "outrage did not come back, got {weight}");
    }

    #[test]
    fn the_resting_point_drifts_back() {
        let mut ledger = Ledger::new();
        ledger.add_strain(0.9);
        ledger.decay(Duration::days(5));
        let after_five = ledger.resting_friction();
        assert!(
            after_five < 0.9 - 0.2,
            "no allostatic recovery: {after_five}"
        );
        ledger.decay(Duration::days(100));
        assert_eq!(ledger.resting_friction(), 0.0);
    }

    #[test]
    fn a_ledger_that_never_forgets_is_frozen() {
        let mut ledger = Ledger::without_forgetting();
        let k = key("acme-tooling", "lead-time-miss");
        ledger.record(k.clone(), Sentiment::Adverse, Provenance::Hearsay);
        ledger.add_strain(0.9);
        let before = ledger.clone();
        ledger.decay(Duration::days(10_000));
        assert_eq!(ledger, before);
    }

    #[test]
    fn decay_is_a_pure_function_of_the_elapsed_time_handed_in() {
        let seed = || {
            let mut l = Ledger::new();
            l.add_strain(0.8);
            l.record(
                key("acme-tooling", "lead-time-miss"),
                Sentiment::Adverse,
                Provenance::FirstHand,
            );
            l.record(
                key("beihai-plastics", "price-hike"),
                Sentiment::Adverse,
                Provenance::Hearsay,
            );
            l
        };

        // Same call sequence, twice: bit-identical.
        let mut a = seed();
        let mut b = seed();
        for _ in 0..7 {
            a.decay(Duration::minutes(1_000));
            b.decay(Duration::minutes(1_000));
        }
        assert_eq!(a, b);

        // Sub-period remainders are carried, so chunking barely matters: seven
        // 1000-minute steps land where one 7000-minute step does. (Floating
        // point addition is not associative, hence the tolerance rather than
        // equality — the point under test is that nothing reads a clock.)
        let mut whole = seed();
        whole.decay(Duration::minutes(7_000));
        for (chunked, single) in a.traces.values().zip(whole.traces.values()) {
            assert!((chunked.strength - single.strength).abs() < 1e-9);
            assert!((chunked.expectation - single.expectation).abs() < 1e-9);
            assert_eq!(chunked.idle_derives, single.idle_derives);
        }
        assert!((a.resting_friction() - whole.resting_friction()).abs() < 1e-9);

        // Time does not run backwards.
        let mut back = seed();
        let frozen = back.clone();
        back.decay(Duration::days(-30));
        assert_eq!(back, frozen);
    }

    #[test]
    fn delivering_erodes_the_grudge() {
        let mut ledger = Ledger::new();
        let supplier = slug("acme-tooling");
        for topic in GRIEVANCES {
            ledger.record(
                key("acme-tooling", topic),
                Sentiment::Adverse,
                Provenance::FirstHand,
            );
        }
        assert_eq!(ledger.stance(&supplier), Stance::Hostile);

        for topic in GRIEVANCES {
            ledger.record(
                key("acme-tooling", topic),
                Sentiment::Favourable,
                Provenance::FirstHand,
            );
        }
        assert_ne!(ledger.stance(&supplier), Stance::Hostile);
    }

    #[test]
    fn a_supplier_that_delivers_becomes_trusted() {
        let mut ledger = Ledger::new();
        let supplier = slug("fujin-bearings");
        for topic in ["on-time", "spec-clean"] {
            ledger.record(
                key("fujin-bearings", topic),
                Sentiment::Favourable,
                Provenance::FirstHand,
            );
        }
        assert_eq!(ledger.stance(&supplier), Stance::Trusted);
        assert_eq!(ledger.stance(&slug("nobody-known")), Stance::Neutral);
    }
}
