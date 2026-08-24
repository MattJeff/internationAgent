//! When an employee is allowed to act on its own.
//!
//! Until now a turn happened only because something arrived — an email, an A2A
//! request, a webhook. That was the throttle, and it was a good one: no traffic,
//! no cost. An employee hired with an objective sat there.
//!
//! This module is the other half. It answers one question, purely:
//! *may this employee start a turn of its own right now?* It does not decide
//! what the employee should do — that is the role pack's `plan`, recomputed per
//! turn and stored nowhere — and it does not decide whether the employee can
//! afford to, which is the turn budget in [`crate::policy`].
//!
//! # Why the schedule is stored rather than computed
//!
//! The obvious design is `last_acted_at + cadence <= now`. It is wrong in a way
//! that only shows up in production: an employee suspended for a week comes back
//! owing a week of turns, and every employee created in the same import is due
//! in the same instant forever. Storing an explicit `next_at` that is **set from
//! `now` when the turn is taken up** makes the schedule a promise about the
//! future rather than a debt from the past. A missed slot is missed, not queued.
//!
//! Taking the turn up is also what writes the new deadline, in the same
//! statement, which is what the outbox poller does with its retry backoff and
//! for the same reason. A schedule that only moved on success would leave a
//! crashed turn permanently due, and the loop would pick it up again at once.
//!
//! That is the difference between a cron and "do it again in a while", and for
//! an employee the second is what anyone actually means. Nobody wants the
//! purchasing agent to do eight hours of thinking at once because the server was
//! down.
//!
//! # Jitter is an argument, not a call to a random number generator
//!
//! Ten employees created by one script share a creation timestamp, so they share
//! every subsequent deadline, and they hit the model provider together forever.
//! The fix is to spread the first schedule — but this crate has no `rand` and
//! should not grow one, because a pure function that reaches for entropy cannot
//! be tested by stating what it returns. So [`Cadence::advance`] takes the
//! offset as a parameter and the caller draws it.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::employee::Lifecycle;

/// Nothing is allowed to act more often than this, whatever a policy says.
///
/// A platform floor rather than a default: a cadence is operator input, and an
/// operator who types `1s` has made a mistake that costs money every second
/// until someone notices. Five minutes is far below any real employee's useful
/// rhythm and far above the rate at which a mistake becomes expensive.
pub const MIN_INTERVAL: Duration = Duration::from_secs(300);

/// The ceiling, so a cadence cannot silently mean "never".
///
/// Thirty days. An operator who wants an employee to stop should suspend it —
/// that is what [`Lifecycle::Suspended`] is for, it is visible in the employee
/// list, and it does not look like a working employee that happens to be quiet.
pub const MAX_INTERVAL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Why a cadence was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CadenceError {
    /// Below [`MIN_INTERVAL`].
    #[error("cadence is faster than the {} second floor", MIN_INTERVAL.as_secs())]
    TooFast,
    /// Above [`MAX_INTERVAL`].
    #[error("cadence is slower than the {} day ceiling", MAX_INTERVAL.as_secs() / 86_400)]
    TooSlow,
}

impl CadenceError {
    /// Stable, low-cardinality metric label.
    pub const fn code(self) -> &'static str {
        match self {
            CadenceError::TooFast => "cadence_too_fast",
            CadenceError::TooSlow => "cadence_too_slow",
        }
    }
}

/// How often an employee wakes up to work on its own objective.
///
/// No `Deserialize`: a derived one would rebuild a cadence of one second from a
/// row or a request body, which is exactly the value [`Cadence::every`] exists
/// to refuse. It serialises — writing is safe, reading is where an invariant is
/// lost — and comes back through the constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Cadence {
    #[serde(rename = "interval_secs", serialize_with = "as_secs")]
    interval: Duration,
}

fn as_secs<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_secs())
}

impl Cadence {
    /// A cadence, or the reason this one is not allowed.
    pub fn every(interval: Duration) -> Result<Self, CadenceError> {
        if interval < MIN_INTERVAL {
            return Err(CadenceError::TooFast);
        }
        if interval > MAX_INTERVAL {
            return Err(CadenceError::TooSlow);
        }
        Ok(Self { interval })
    }

    /// The interval itself.
    pub const fn interval(self) -> Duration {
        self.interval
    }

    /// The next deadline, measured from `from` — the instant the turn was taken
    /// up — and never from the deadline that was missed.
    ///
    /// **Taken up, not finished**, and the difference matters exactly once: if
    /// the schedule only moved when a turn *succeeded*, a turn that panicked
    /// would leave the employee permanently due and the loop would take it up
    /// again immediately, forever. Advancing at claim time makes a crashed turn
    /// cost one missed slot, which is the same thing every other missed slot
    /// costs. The price is that a turn lasting a noticeable fraction of the
    /// cadence shortens the gap after it; turns are minutes and cadences are
    /// hours, so that is a rounding error rather than a trade.
    ///
    /// `offset` spreads employees that would otherwise share a schedule; pass
    /// `Duration::ZERO` when that does not matter, which in a test is always.
    ///
    /// Saturating: a clock far enough in the future to overflow a `DateTime`
    /// should produce the latest representable instant, not a panic in a loop
    /// that runs unattended.
    pub fn advance(self, from: DateTime<Utc>, offset: Duration) -> DateTime<Utc> {
        let step = chrono::Duration::from_std(self.interval + offset)
            .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX / 1_000));
        from.checked_add_signed(step)
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

/// What the scheduler should do with one employee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initiative {
    /// Start a turn.
    Due,
    /// Not yet; this is when.
    NotYet {
        /// The stored deadline, unchanged.
        at: DateTime<Utc>,
    },
    /// This employee may not act at all, whatever the clock says.
    Barred {
        /// The lifecycle that barred it, for the metric label.
        lifecycle: Lifecycle,
    },
}

impl Initiative {
    /// Stable, low-cardinality metric label.
    pub const fn code(self) -> &'static str {
        match self {
            Initiative::Due => "due",
            Initiative::NotYet { .. } => "not_yet",
            Initiative::Barred { .. } => "barred",
        }
    }

    /// Convenience for the claim predicate.
    pub const fn is_due(self) -> bool {
        matches!(self, Initiative::Due)
    }
}

/// May this employee start a turn of its own?
///
/// Lifecycle is checked **first and separately** from the clock, and that
/// ordering is the point rather than a style preference. A terminated employee
/// whose deadline has passed must read as barred, not as due — this codebase has
/// already been bitten once by a released row landing in a state that a claim
/// predicate still matched, and the fix both times is to make the lifecycle
/// question impossible to skip.
///
/// [`Lifecycle::Active`] is the only lifecycle that may act. `Draft` has not
/// been released to work yet, `Suspended` is an operator saying stop, and
/// `Terminated` is absorbing.
pub fn initiative(lifecycle: Lifecycle, next_at: DateTime<Utc>, now: DateTime<Utc>) -> Initiative {
    if lifecycle != Lifecycle::Active {
        return Initiative::Barred { lifecycle };
    }
    if next_at > now {
        return Initiative::NotYet { at: next_at };
    }
    Initiative::Due
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("timestamp")
    }

    fn cadence(secs: u64) -> Cadence {
        Cadence::every(Duration::from_secs(secs)).expect("cadence")
    }

    #[test]
    fn a_cadence_cannot_be_faster_than_the_floor_or_slower_than_the_ceiling() {
        assert_eq!(
            Cadence::every(Duration::from_secs(1)),
            Err(CadenceError::TooFast),
            "an operator typo must not cost money every second"
        );
        assert_eq!(
            Cadence::every(MIN_INTERVAL).map(Cadence::interval),
            Ok(MIN_INTERVAL),
            "the floor itself is allowed"
        );
        assert_eq!(
            Cadence::every(MAX_INTERVAL + Duration::from_secs(1)),
            Err(CadenceError::TooSlow),
            "a cadence must not be a disguised way to say never"
        );
    }

    #[test]
    fn only_an_active_employee_may_act_on_its_own() {
        // The clock says yes for every one of these. Lifecycle must still win,
        // including for Terminated, which is the case that has bitten before.
        let past = at(0);
        let now = at(1_000);
        for barred in [
            Lifecycle::Draft,
            Lifecycle::Suspended,
            Lifecycle::Terminated,
        ] {
            assert_eq!(
                initiative(barred, past, now),
                Initiative::Barred { lifecycle: barred },
                "{barred:?} must never be due"
            );
        }
        assert_eq!(initiative(Lifecycle::Active, past, now), Initiative::Due);
    }

    #[test]
    fn a_deadline_in_the_future_is_not_yet_and_the_exact_instant_is_due() {
        let now = at(1_000);
        assert_eq!(
            initiative(Lifecycle::Active, at(1_001), now),
            Initiative::NotYet { at: at(1_001) }
        );
        assert_eq!(
            initiative(Lifecycle::Active, now, now),
            Initiative::Due,
            "the boundary is inclusive; a deadline that has arrived has arrived"
        );
    }

    #[test]
    fn a_missed_slot_is_missed_rather_than_owed() {
        // The property the whole module exists for. An employee suspended for a
        // week, or a server down for a week, must not come back owing a week of
        // turns: the next deadline is measured from when the turn actually
        // finished, never from the deadline it blew through.
        let hourly = cadence(3_600);
        let deadline_it_missed = at(0);
        let finally_taken_up_at = at(7 * 24 * 3_600);

        let next = hourly.advance(finally_taken_up_at, Duration::ZERO);

        assert_eq!(next, at(7 * 24 * 3_600 + 3_600));
        assert!(
            next > finally_taken_up_at,
            "a backlog would put the next deadline in the past and spin"
        );
        assert_eq!(
            initiative(Lifecycle::Active, next, finally_taken_up_at),
            Initiative::NotYet { at: next },
            "and the employee is immediately not-due, rather than owing 168 turns"
        );
        let _ = deadline_it_missed;
    }

    #[test]
    fn jitter_separates_employees_that_would_otherwise_share_a_schedule() {
        // Ten employees created by one import share a timestamp. Without the
        // offset they share every deadline after it, forever, and hit the model
        // provider in a block.
        let hourly = cadence(3_600);
        let created = at(0);

        let deadlines: Vec<_> = (0..10)
            .map(|i| hourly.advance(created, Duration::from_secs(i * 17)))
            .collect();

        let mut unique = deadlines.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), deadlines.len(), "all ten must differ");
        assert!(
            deadlines.iter().all(|d| *d >= at(3_600)),
            "jitter only ever delays; it must never pull a turn earlier than the cadence"
        );
    }

    #[test]
    fn advancing_past_the_end_of_time_saturates_instead_of_panicking() {
        // This loop runs unattended. A clock skew that overflows a DateTime must
        // not be the thing that takes the process down.
        assert_eq!(
            cadence(3_600).advance(DateTime::<Utc>::MAX_UTC, Duration::ZERO),
            DateTime::<Utc>::MAX_UTC
        );
    }

    #[test]
    fn a_cadence_serialises_as_seconds_and_has_no_deserialize() {
        // The absence is the point: a derived Deserialize would rebuild a
        // one-second cadence straight from a row or a request body, past the
        // constructor that exists to refuse it. If someone adds one, this test
        // will not catch it -- but the comment on the type will be a lie, so
        // this asserts the shape the constructor is the only door to.
        let json = serde_json::to_value(cadence(3_600)).expect("serialize");
        assert_eq!(json, serde_json::json!({ "interval_secs": 3_600 }));
    }
}
