//! The psyche's wire: the one observation this codebase can honestly make, and
//! the one decision it is allowed to change.
//!
//! `agentos_domain::psyche` is a set of accumulators that take facts as
//! parameters and read no clock. `agentos_store::psyche` is the log they fold
//! over. This module is the only thing that connects the two to something that
//! ships.
//!
//! # What is observed, and what is not
//!
//! An [`Expectation`] is *observed* against *claimed* in natural units, and a
//! dimension fed by anything other than the thing it names is worse than a
//! dimension left empty — the belief would converge, look confident, and be
//! about something else. So exactly one dimension is wired:
//!
//! | Dimension | Source in this codebase | Wired |
//! |---|---|---|
//! | [`Dimension::ResponseLatencyHours`] | the gap between our outbound message on a thread and their next inbound one — both rows exist in `messages`, both timestamps are ours | **yes** |
//! | `Dimension::LeadTimeDays` | `quotes.lead_time_days` is what a supplier *claims*. Nothing in this workspace records a delivery: no production caller writes `purchase_orders` or `shipments`, so the observed half does not exist | no |
//! | `Dimension::PriceDeltaBps` | needs a quoted price and an *agreed* one. Only the quote exists; nothing records what was finally paid | no |
//! | `Dimension::MoqFlexibilityPct` | `quotes` has no MOQ column — see `vertical::answers`, which fills `moq` with `NonZeroU32::MIN` because there is nothing to read | no |
//! | `Dimension::DefectRatePct` | needs an incoming inspection. There is no inspection anywhere in this product | no |
//!
//! `supplier_observations` is the one that came off this list.
//! `store::sourcing::close_expired_rounds` writes `quote_returned` /
//! `quote_missed` as it closes a round, so the reputation view has a feed, and
//! `vertical::answers` is what drives it on the production path. Nothing is
//! written from *here*, and that is still right: this module is about the
//! psyche's expectations, and an observation is the sourcing round's own
//! record of who answered.
//!
//! # The governing invariant
//!
//! **Nothing here may reach an authorisation.** No value in this module is an
//! input to `domain::policy::evaluate`, to `PolicyGate::decide` or to any
//! `Authorized<A>`; the only thing that leaves is a sentence in the note the
//! employee reads before it thinks. `docs/PSYCHE_PORT.md` §0 asks for one grep
//! in CI to keep it that way, "in the PR that gives the psyche its first
//! production caller". This is that PR, and the grep is
//! [`tests::nothing_psyche_derived_can_reach_an_authorisation`] — a test rather
//! than a shell line, so it runs wherever the suite runs.
//!
//! # Determinism, and where forgetting runs
//!
//! Nothing is cached. [`standing`] folds the episode log every time it is
//! asked, so the expectation and the [`Ledger`] are a pure function of
//! `(the rows, now)` — the same log read twice at the same instant produces the
//! same belief, bit for bit.
//!
//! That is also **where forgetting runs**, and it is the reproducible half of
//! the choice. A [`Ledger`] persisted in a table and decayed by a scheduler
//! ends up in a state that depends on when the scheduler happened to fire,
//! which no log can reproduce; a ledger replayed over the real gaps between
//! real observations, and then aged once more over the silence since the last
//! one, depends on nothing else. `Ledger::decay` is already a pure function of
//! the [`chrono::Duration`] handed to it and carries its sub-period remainder,
//! which is exactly what makes the replay exact.

use agentos_domain::ids::{ConversationId, EmployeeId};
use agentos_domain::psyche::expectation::{Dimension, Expectation, PredictionError, Reliability};
use agentos_domain::psyche::forgetting::{Ledger, Provenance, Sentiment, Stance, TraceKey};
use agentos_domain::psyche::links::BASE_CONFIDENCE;
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::psyche::{self as psyche_store, Episode, NewEpisode, TrustLink};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use uuid::{NoContext, Timestamp, Uuid};

/// The only dimension with an honest observed source in this codebase. See the
/// table in the module docs for the four that do not have one.
pub const OBSERVED: Dimension = Dimension::ResponseLatencyHours;

/// `psyche_episodes.dimension` for [`OBSERVED`]. The serialised spelling of the
/// enum variant, so the column and the domain cannot drift apart silently.
pub const DIMENSION_KEY: &str = "response_latency_hours";

/// `psyche_episodes.kind`: they answered something we sent.
pub const REPLY_RECEIVED: &str = "reply_received";

/// The [`TraceKey`] topic. MPCP keys sanction fatigue per `(type, subject)`, so
/// a counterparty that is reliably slow to answer stops being outrageous about
/// *that* without being excused for anything else.
const TOPIC: &str = "reply-latency";

/// The counterparty half of the [`TraceKey`].
///
/// A constant, and it costs nothing: [`standing`] builds one [`Ledger`] per
/// counterparty out of that counterparty's own rows, so the key is already
/// narrowed by the query. The alternative — slugifying an email address —
/// would be a lossy second identity for the same party, and
/// `a@x.example`/`a@x-example` would share it.
const SUBJECT: &str = "counterparty";

/// Episodes folded per read.
///
/// ponytail: the belief is over the most recent `HISTORY` exchanges, not over
/// all of them. Bounded because the fold is on a read path; five hundred
/// exchanges with one contact is years of correspondence. If a relationship
/// ever outgrows it, the upgrade is a stored checkpoint plus the tail — not a
/// bigger number.
const HISTORY: i64 = 500;

/// `psyche_episodes_counterparty_nonempty` is `length between 1 and 200`, and
/// `inbound::contact_of` truncates at 320. Truncating again here is what stops
/// a hostile `From` header from failing an inbound landing on a CHECK.
const MAX_COUNTERPARTY: usize = 200;

/// The counterparty key these tables are written and read under.
///
/// Lower-cased and bounded. `inbound::contact_of` already lower-cases, and
/// `EmailAddress` lower-cases its local part and its domain, so an address we
/// wrote to and the same address writing back land on one key.
pub fn key(raw: &str) -> String {
    raw.trim()
        .to_lowercase()
        .chars()
        .take(MAX_COUNTERPARTY)
        .collect()
}

fn trace_key() -> TraceKey {
    TraceKey::new(
        agentos_domain::ids::Slug::parse(SUBJECT).expect("SUBJECT is a literal slug"),
        agentos_domain::ids::Slug::parse(TOPIC).expect("TOPIC is a literal slug"),
    )
}

// ---------------------------------------------------------------------------
// What the employee is told
// ---------------------------------------------------------------------------

/// One employee's picture of one counterparty, folded from the log at `now`.
///
/// Advisory, all of it. It decides whom to chase and how to phrase it; it
/// decides nothing about what is allowed.
#[derive(Debug, Clone)]
pub struct Standing {
    /// The key this was read under — an address, lower-cased.
    pub counterparty: String,
    /// How long they take to answer us, learned. `Reliability::Unknown` until
    /// there are [`MIN_OBSERVATIONS`](agentos_domain::psyche::expectation::MIN_OBSERVATIONS)
    /// replies, and *unknown is not slow*.
    pub latency: Expectation,
    /// How the forgetting ledger reads them, after decay.
    pub stance: Stance,
    /// When we started waiting on this reply, if we are.
    pub awaiting_reply_since: Option<DateTime<Utc>>,
    /// The last time they said anything at all.
    pub last_heard_from_at: Option<DateTime<Utc>>,
}

impl Standing {
    /// How long past their own habit this silence has run, or `None`.
    ///
    /// `None` covers three different things and deliberately does not
    /// distinguish them here: we are not waiting, we have no rhythm to compare
    /// against, or the wait is still ordinary. Only the first is visible in the
    /// note.
    ///
    /// # Why the allowance is theirs and not a constant
    ///
    /// This is the whole point of the accumulator. A contact that answers in
    /// four hours every time is late at ten; one that answers in four days is
    /// not late at ten, and chasing them there is how a supplier learns we
    /// cannot count. `expected + 2·std_dev` is the plan a buyer would actually
    /// make, floored at one [`Dimension::scale`] so a metronome is not chased
    /// twenty minutes over.
    pub fn overdue_by(&self, now: DateTime<Utc>) -> Option<TimeDelta> {
        let since = self.awaiting_reply_since?;
        // Unknown is unknown. Two replies are not a rhythm, and inventing one
        // here would make the first chase land on the counterparties we know
        // least about.
        if self.latency.reliability() == Reliability::Unknown {
            return None;
        }
        let expected = self.latency.expected()?;
        let spread = self.latency.std_dev().unwrap_or(0.0);
        let allowance = (expected + 2.0 * spread).max(OBSERVED.scale());
        let waited = hours_between(since, now)?;
        (waited > allowance).then(|| hours(waited - allowance))
    }

    /// The line the employee reads about this counterparty.
    ///
    /// **Ours, all of it.** An address that has been through
    /// `EmailAddress::parse` or `inbound::contact_of`, two floats and a closed
    /// enum. Not one byte a counterparty wrote is in it, which is what keeps
    /// `vertical::Ran::note`'s claim to be trusted by construction true.
    pub fn chase_line(&self, now: DateTime<Utc>) -> String {
        let waited = self
            .awaiting_reply_since
            .and_then(|since| hours_between(since, now))
            .unwrap_or(0.0);

        let habit = match (self.latency.expected(), self.latency.reliability()) {
            (Some(expected), Reliability::Predictable) => {
                format!("they usually answer in about {expected:.0}h")
            }
            (Some(expected), Reliability::Erratic) => format!(
                "their replies average {expected:.0}h and scatter by ±{:.0}h",
                self.latency.std_dev().unwrap_or(0.0)
            ),
            _ => format!(
                "{} replies on record — no rhythm yet, so this is not late, it is unknown",
                self.latency.observations()
            ),
        };

        let verdict = match self.overdue_by(now) {
            Some(over) => format!(" — {:.0}h past that. Worth a chaser.", over.num_hours()),
            None => " — still inside it. Leave them alone.".to_owned(),
        };

        format!(
            "  {} — {waited:.0}h of silence, {habit}{verdict}",
            self.counterparty
        )
    }
}

// ---------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------

/// Fold one counterparty's episodes into what they mean at `now`.
///
/// Pure: the only inputs are the rows and the instant. `episodes` arrives
/// newest-first, the order `psyche_store::episodes_about` guarantees, and is
/// replayed oldest-first because Rescorla-Wagner is not commutative.
fn fold(episodes: &[Episode], now: DateTime<Utc>) -> (Expectation, Ledger) {
    let mut latency = Expectation::new(OBSERVED);
    let mut ledger = Ledger::new();
    let mut clock: Option<DateTime<Utc>> = None;

    for episode in episodes.iter().rev() {
        let Some(observed) = observed_hours(episode) else {
            continue;
        };
        // Forgetting, volet by volet, over the real gap between two real
        // observations. This is the tick, and the log is the schedule.
        if let Some(previous) = clock {
            ledger.decay(episode.observed_at - previous);
        }
        clock = Some(episode.observed_at);

        // An out-of-range value cannot enter the accumulators — the domain
        // refuses it — and one bad row must not truncate the replay.
        let Ok(error) = latency.observe(observed, episode.observed_at) else {
            continue;
        };
        if let Some(sentiment) = sentiment(&error) {
            ledger.record(trace_key(), sentiment, provenance(episode));
        }
    }

    // ...and once more for the silence since the last observation, so a
    // relationship nobody has fed in a year is faded by the time it is read
    // rather than by the time somebody remembers to run a job.
    if let Some(last) = clock {
        ledger.decay(now - last);
    }

    (latency, ledger)
}

/// The observation this episode carries, if it carries one for [`OBSERVED`].
fn observed_hours(episode: &Episode) -> Option<f64> {
    if episode.dimension.as_deref() != Some(DIMENSION_KEY) {
        return None;
    }
    episode
        .detail
        .get("observed_hours")
        .and_then(Value::as_f64)
        .filter(|hours| hours.is_finite())
}

/// Which way this reply points, or `None` for an ordinary one.
///
/// Strict on purpose. A reply is a grievance only when it is a full
/// [`Dimension::scale`] *slower* than we had learned to expect from this
/// counterparty, and a credit only when it is that much faster. Everything
/// inside the band is a normal Tuesday and records no trace at all — a ledger
/// that files every message as evidence is a ledger that means nothing. A first
/// contact records nothing either: there was no expectation to miss.
fn sentiment(error: &PredictionError) -> Option<Sentiment> {
    if error.first_contact {
        return None;
    }
    let scale = OBSERVED.scale();
    if error.surprise > scale {
        Some(Sentiment::Adverse)
    } else if error.surprise < -scale {
        Some(Sentiment::Favourable)
    } else {
        None
    }
}

/// Did we watch it, or were we told?
///
/// Always [`Provenance::FirstHand`] today: every episode this module writes is
/// a message that arrived in our own mailbox, and `reported_by` is `None` for
/// all of them. The branch stays because the column exists and a colleague's
/// account of a supplier is the obvious next writer — and because
/// `forgetting.rs` fades the two differently on purpose.
fn provenance(episode: &Episode) -> Provenance {
    if episode.reported_by.is_some() {
        Provenance::Hearsay
    } else {
        Provenance::FirstHand
    }
}

fn hours_between(from: DateTime<Utc>, to: DateTime<Utc>) -> Option<f64> {
    let elapsed = to - from;
    // Time does not run backwards. A negative gap is a clock skew or an
    // out-of-order delivery, and neither is an observation about anybody.
    (elapsed >= TimeDelta::zero()).then(|| elapsed.num_milliseconds() as f64 / 3_600_000.0)
}

fn hours(count: f64) -> TimeDelta {
    TimeDelta::milliseconds((count * 3_600_000.0) as i64)
}

/// A UUIDv7 stamped at the instant the episode describes, not at the instant the
/// row is written.
///
/// `NewEpisode::id` says "stamped at `observed_at`" and this is what makes that
/// true. `episodes_about` orders by `observed_at DESC, id DESC` precisely
/// because a v7 sorts by its stamp, so an id off the wall clock would break ties
/// by when a webhook happened to be drained — which is a fact about our poller
/// and not about the counterparty.
fn episode_id(observed_at: DateTime<Utc>) -> Uuid {
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        // Pre-epoch has no v7 representation, so it clamps — the same thing
        // `ids::uuid_v7_at` does, and no real observation is there anyway.
        u64::try_from(observed_at.timestamp()).unwrap_or(0),
        observed_at.timestamp_subsec_nanos(),
    ))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// What this employee has learned about one counterparty.
///
/// Recomputed per call and stored nowhere. `psyche_expectations` is
/// deliberately not written: see the module notes at the bottom of this file.
pub async fn standing(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
    now: DateTime<Utc>,
) -> Result<Standing, StoreError> {
    let counterparty = key(counterparty);
    let episodes = psyche_store::episodes_about(tx, employee_id, &counterparty, HISTORY).await?;
    let (latency, ledger) = fold(&episodes, now);
    let link = psyche_store::trust_for(tx, employee_id, &counterparty).await?;

    Ok(Standing {
        stance: ledger.stance(&trace_key().counterparty),
        awaiting_reply_since: link.as_ref().and_then(|l| l.awaiting_reply_since),
        last_heard_from_at: link.as_ref().and_then(|l| l.last_heard_from_at),
        counterparty,
        latency,
    })
}

/// Everyone this employee is waiting on, oldest wait first.
///
/// The order is the store's — `gone_quiet` sorts by `awaiting_reply_since` and
/// breaks ties on the counterparty — so the chase list is the same queue every
/// run. Whether each of them is actually *late* is [`Standing::overdue_by`],
/// and that is the per-counterparty judgement a constant deadline cannot make.
///
/// ponytail: one `standing` query pair per counterparty we are waiting on. That
/// is a handful of rows by construction — it is the list of open questions, not
/// the address book. Batch it into a single `counterparty = ANY($1)` fold when a
/// profile says a turn is spending its time here.
pub async fn chase_list(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    now: DateTime<Utc>,
) -> Result<Vec<Standing>, StoreError> {
    let waiting = psyche_store::gone_quiet(tx, employee_id, now).await?;
    let mut out = Vec::with_capacity(waiting.len());
    for quiet in waiting {
        out.push(standing(tx, employee_id, &quiet.counterparty, now).await?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// What just moved the relationship's clock.
enum Contact {
    /// We wrote to them and the provider took it.
    WeWrote(DateTime<Utc>),
    /// They said something.
    TheyAnswered(DateTime<Utc>),
}

/// Read-modify-write of the one relationship row.
///
/// The read is not an optimisation. `save_trust` is a whole-row upsert, so
/// writing "we are waiting" without it would overwrite a trust value and its
/// evidence with a prior — and the CHECK that makes an unsupported trust
/// unwritable would not notice, because a prior is exactly what it permits.
///
/// A row created here holds [`BASE_CONFIDENCE`] and cites nothing, which is the
/// only trust value this module is entitled to: `links.rs` moves trust on
/// `PromiseKept` / `CommitmentBroken` / `FaultRepeated`, and none of those three
/// has an event in this codebase — a reply to an email is not a promise kept.
///
/// `counterparty` is expected to have been through [`key`] already. An empty one
/// writes nothing rather than failing `psyche_trust`'s length CHECK: both
/// callers sit on a path where an error is somebody's mail or somebody's RFQ,
/// and a relationship with nobody is not worth either.
async fn touch(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
    contact: Contact,
) -> Result<(), StoreError> {
    if counterparty.is_empty() {
        return Ok(());
    }
    // No clock is read here either: the instant comes off the event, so a row
    // written from a replayed log carries the timestamp of the thing that
    // happened rather than of the replay.
    let (Contact::WeWrote(at) | Contact::TheyAnswered(at)) = contact;

    let existing = psyche_store::trust_for(tx, employee_id, counterparty).await?;
    let mut link = existing.unwrap_or_else(|| TrustLink {
        employee_id,
        counterparty: counterparty.to_owned(),
        trust: BASE_CONFIDENCE,
        prior_trust: BASE_CONFIDENCE,
        evidence_count: 0,
        last_evidence_episode_id: None,
        broken_at: None,
        broken_experienced: None,
        last_heard_from_at: None,
        awaiting_reply_since: None,
        updated_at: at,
    });
    link.updated_at = at;

    match contact {
        // `or`, not `=`: the wait started with the first letter. A second RFQ
        // to somebody already silent does not reset how long they have been
        // silent, which is the number the chase list is ordered on.
        Contact::WeWrote(_) => link.awaiting_reply_since = link.awaiting_reply_since.or(Some(at)),
        Contact::TheyAnswered(_) => {
            link.awaiting_reply_since = None;
            link.last_heard_from_at = Some(at);
        }
    }

    psyche_store::save_trust(tx, &link).await
}

/// Record that we have written to this counterparty and are waiting on them.
///
/// The only durable trace that an RFQ went to a particular address: `rfqs` does
/// not record who was asked, and no `messages` row is written for an outbound
/// RFQ. Nothing about trust is claimed — see [`touch`].
pub async fn awaiting_reply(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
    sent_at: DateTime<Utc>,
) -> Result<(), StoreError> {
    touch(
        tx,
        employee_id,
        &key(counterparty),
        Contact::WeWrote(sent_at),
    )
    .await
}

/// Fold one reply into what this employee knows about one counterparty.
///
/// `we_wrote_at` is the timestamp of **our** last message on the same thread,
/// when the message before theirs was ours, and `they_replied_at` is when this
/// one arrived. Both are rows in `messages`; the difference is the thing
/// `Dimension::ResponseLatencyHours` names, in the unit it names it in, and it
/// is not a proxy for anything.
///
/// # Answering and being measured are two different things
///
/// The wait is cleared **whenever they speak**, before any of the measuring —
/// and that ordering is load-bearing rather than tidy. An outbound RFQ writes
/// no `messages` row at all (see `sourcing::Buyer::issue_rfq`), so a supplier
/// answering one is precisely the case where `we_wrote_at` is `None`. Clearing
/// the wait only on the measurable path would leave every supplier who ever
/// answered an RFQ on the chase list forever, which is the exact opposite of
/// what the chase list is for.
///
/// Returns the prediction error the reply carried, or `None` when there was
/// nothing honest to *measure* — no message of ours to measure against, an
/// unnameable counterparty, a gap that runs backwards, or a value the domain
/// refuses. **Never an error the caller has to handle as a judgement**: a
/// psyche that cannot decide what a message means still has to let the message
/// land, and the caller is `inbound::land`, where an error is a dead-lettered
/// email.
///
/// The episode is written in the caller's transaction on purpose, so the
/// observation and the message it was measured from commit together or not at
/// all. `psyche_episodes` is append-only, so a redelivery must not reach this —
/// `inbound::land` calls it on the insert path only, exactly as it appends its
/// audit row.
pub async fn observe_reply(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
    conversation_id: ConversationId,
    channel: &str,
    we_wrote_at: Option<DateTime<Utc>>,
    they_replied_at: DateTime<Utc>,
) -> Result<Option<PredictionError>, StoreError> {
    let counterparty = key(counterparty);
    // A `From` header of nothing but whitespace parses to an empty key, and
    // `psyche_episodes_counterparty_nonempty` would refuse it — which inside
    // `land`'s transaction means a hostile header can dead-letter somebody's
    // mail. Refused here instead: an observation about nobody is not an
    // observation, and neither is a wait.
    if counterparty.is_empty() {
        return Ok(None);
    }

    // They spoke. See the doc comment on why this is unconditional.
    touch(
        tx,
        employee_id,
        &counterparty,
        Contact::TheyAnswered(they_replied_at),
    )
    .await?;

    let Some(observed) = we_wrote_at.and_then(|ours| hours_between(ours, they_replied_at)) else {
        return Ok(None);
    };

    let episodes = psyche_store::episodes_about(tx, employee_id, &counterparty, HISTORY).await?;
    let (mut latency, _) = fold(&episodes, they_replied_at);
    let Ok(error) = latency.observe(observed, they_replied_at) else {
        return Ok(None);
    };

    psyche_store::record_episode(
        tx,
        &NewEpisode {
            id: episode_id(they_replied_at),
            employee_id,
            counterparty: counterparty.clone(),
            kind: REPLY_RECEIVED.to_owned(),
            dimension: Some(DIMENSION_KEY.to_owned()),
            polarity: match sentiment(&error) {
                Some(Sentiment::Adverse) => -1,
                Some(Sentiment::Favourable) => 1,
                None => 0,
            },
            // `PredictionError::weight` is in `[SURPRISE_FLOOR, 1]`, inside the
            // column's `(0, 10]`.
            weight: error.weight,
            // The column is MPCP's dimensionless prediction error and its CHECK
            // is `[-2, 2]`; ours is in hours and does not fit. Normalised by the
            // dimension's scale and clamped, so what is stored is what the
            // column says it is. The exact hours are in `detail`, where the
            // audit reads them.
            surprise: Some((error.surprise / OBSERVED.scale()).clamp(-2.0, 2.0)),
            // We watched it arrive.
            reported_by: None,
            conversation_id: Some(conversation_id),
            amount: None,
            detail: json!({
                "observed_hours": observed,
                "expected_hours": error.expected_before,
                "first_contact": error.first_contact,
                "regime_change": error.regime_change,
                // The dimension is "on one channel", and a contact key is an
                // address or a number, so one key is already one channel. Kept
                // so a later reader does not have to trust that sentence.
                "channel": channel,
            }),
            observed_at: they_replied_at,
        },
    )
    .await?;

    Ok(Some(error))
}

// ---------------------------------------------------------------------------
// What is deliberately still unwired, and why
// ---------------------------------------------------------------------------
//
// `psyche_expectations` — not written. Its columns are MPCP's *sign-valued*
// model: `expectation` is CHECKed to `[-1, 1]` and `surprise_mean` /
// `surprise_var` are a Welford over `|surprise|`. The domain deliberately ships
// the magnitude-valued replacement `docs/PSYCHE_PORT.md` §5.2 argues for — the
// expectation is in hours, the Welford is over the raw observations, and there
// are two CUSUM accumulators and a `claimed` the table has no column for. "23
// hours" does not fit `[-1, 1]`, so writing it would mean either a lie about
// the units or a migration; folding the episodes costs neither and cannot
// disagree with the log it came from. The table's own header makes the same
// argument about `precision`.
//
// `psyche_beliefs` / `psyche_belief_episodes` — not written. `beliefs.rs`
// consolidates `N_CONSOLIDATION = 3` concordant episodes about one subject into
// a durable belief, and the only subject with three concordant episodes here is
// "slow to answer", which is the expectation restated. A belief that adds no
// information is a second place for the same fact to be wrong. The genealogy
// tables are ready for the first belief that is *not* a restatement — a lead
// time missed, a spec substituted — which needs the events the table above says
// do not exist.
//
// `links.rs` / the `trust` column — read and preserved, never moved.
// `TrustEvent` is `PromiseKept`, `CommitmentBroken`, `FaultRepeated`; each one
// is a commitment whose fulfilment we watched. There is no purchase order, no
// shipment and no inspection in this product, so there is no honest event to
// feed it. What this module writes to `psyche_trust` is two timestamps —
// "we are waiting since" and "they last spoke at" — and it leaves `trust` on its
// prior, which is precisely what `psyche_trust_needs_evidence` permits and what
// an opinion with no evidence behind it should look like.

#[cfg(test)]
mod tests {
    use super::*;
    use agentos_domain::psyche::expectation::MIN_OBSERVATIONS;

    const T0: i64 = 1_700_000_000;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(T0 + secs, 0).expect("valid timestamp")
    }

    /// One stored episode carrying one latency observation.
    fn episode(hours: f64, observed_at: DateTime<Utc>) -> Episode {
        Episode {
            id: Uuid::now_v7(),
            kind: REPLY_RECEIVED.to_owned(),
            dimension: Some(DIMENSION_KEY.to_owned()),
            polarity: 0,
            weight: 1.0,
            surprise: Some(0.0),
            reported_by: None,
            conversation_id: None,
            amount: None,
            detail: json!({ "observed_hours": hours }),
            observed_at,
        }
    }

    /// `episodes_about` hands them back newest-first; `fold` has to replay them
    /// the other way or Rescorla-Wagner is fitting the tape backwards.
    fn log(series: &[(f64, i64)]) -> Vec<Episode> {
        let mut rows: Vec<Episode> = series
            .iter()
            .map(|(hours, secs)| episode(*hours, at(*secs)))
            .collect();
        rows.reverse();
        rows
    }

    /// **The invariant, as a test rather than as a line of CI.**
    ///
    /// `docs/PSYCHE_PORT.md` §0 asks for exactly this and names the trap: the
    /// original version of the grep read `policy.rs` alone, and `ActionCtx` —
    /// the place someone would actually put a mood — lives in `action.rs`.
    ///
    /// Three files beyond the two it names, and each earns its place:
    ///
    /// * `app/src/gate.rs` mints every `Authorized<A>` in the workspace. The
    ///   constructor is private to it, so an authorisation the psyche coloured
    ///   would have to be minted here.
    /// * `app/src/sourcing.rs` is where the temptation actually is. `shortlist`
    ///   argues at length that preferring the supplier you already trust is how
    ///   you stop learning about the others; this is that argument, executable.
    /// * `app/src/effects.rs` is the far side of the gate — the only place a
    ///   token is spent.
    ///
    /// `vertical.rs` is deliberately *not* in the list: it is the read site, and
    /// what it may do with what it reads is bounded by the three files above
    /// being clean.
    ///
    /// A negative grep is crude, and that is the point: it cannot be defeated by
    /// a clever type, and it fails on the *import*, long before anything is read
    /// from it.
    #[test]
    fn nothing_psyche_derived_can_reach_an_authorisation() {
        let sources = [
            (
                "domain/src/policy.rs",
                include_str!("../../domain/src/policy.rs"),
            ),
            (
                "domain/src/action.rs",
                include_str!("../../domain/src/action.rs"),
            ),
            ("app/src/gate.rs", include_str!("gate.rs")),
            ("app/src/sourcing.rs", include_str!("sourcing.rs")),
            ("app/src/effects.rs", include_str!("effects.rs")),
        ];
        // The module path, plus every domain type it could arrive as. Two
        // near-misses are absent on purpose, and both are host facts rather
        // than psyche: `TrustLabel` is taint and belongs in all five files, and
        // `ContactStanding` is "have we dealt with them before", which the gate
        // is entitled to and which is why the needle is not `Standing`. Anything
        // out of this module arrives through the path and is caught by the
        // first entry.
        let banned = [
            "psyche",
            "Expectation",
            "Reliability",
            "Stance",
            "Ledger",
            "TrustLink",
            "mood",
            "Mood",
        ];

        for (name, source) in sources {
            for needle in banned {
                assert!(
                    !source.contains(needle),
                    "{name} mentions `{needle}`. The psyche colours tone and \
                     prioritisation and must never reach an authorisation — see \
                     docs/PSYCHE_PORT.md §0."
                );
            }
        }
    }

    /// Reliability is `Unknown` until there is evidence, and unknown must never
    /// read as "slow": that is what stops the first chaser landing on the
    /// counterparties we know least about.
    #[test]
    fn unknown_is_not_slow() {
        let mut waiting = Standing {
            counterparty: "ap@supplier.example".to_owned(),
            latency: fold(&log(&[]), at(0)).0,
            stance: Stance::Neutral,
            awaiting_reply_since: Some(at(0)),
            last_heard_from_at: None,
        };
        assert_eq!(waiting.latency.reliability(), Reliability::Unknown);
        assert_eq!(waiting.latency.expected(), None);
        // A fortnight of silence from a stranger is still not evidence.
        assert_eq!(waiting.overdue_by(at(14 * 86_400)), None);
        assert!(
            waiting
                .chase_line(at(14 * 86_400))
                .contains("no rhythm yet")
        );

        // One reply short of the threshold: still unknown, still not chased.
        let short: Vec<(f64, i64)> = (0..MIN_OBSERVATIONS - 1)
            .map(|i| (2.0, i64::from(i) * 86_400))
            .collect();
        waiting.latency = fold(&log(&short), at(0)).0;
        assert_eq!(waiting.latency.reliability(), Reliability::Unknown);
        assert_eq!(waiting.overdue_by(at(14 * 86_400)), None);
    }

    /// The decision the psyche is wired to change: the same silence is late for
    /// one counterparty and ordinary for another, because the allowance is
    /// theirs.
    #[test]
    fn the_allowance_is_the_counterpartys_own_habit() {
        let prompt = Standing {
            counterparty: "fast@supplier.example".to_owned(),
            latency: fold(&log(&[(2.0, 0), (2.0, 1), (3.0, 2), (2.0, 3)]), at(4)).0,
            stance: Stance::Neutral,
            awaiting_reply_since: Some(at(0)),
            last_heard_from_at: None,
        };
        let slow = Standing {
            counterparty: "slow@supplier.example".to_owned(),
            latency: fold(&log(&[(70.0, 0), (72.0, 1), (68.0, 2), (71.0, 3)]), at(4)).0,
            stance: Stance::Neutral,
            ..prompt.clone()
        };

        // Twenty-four hours of silence.
        let now = at(24 * 3_600);
        assert!(
            prompt.overdue_by(now).is_some(),
            "a contact that answers in two hours is late after a day"
        );
        assert!(
            slow.overdue_by(now).is_none(),
            "a contact that answers in three days is not late after one"
        );
        assert!(prompt.chase_line(now).contains("Worth a chaser"));
        assert!(slow.chase_line(now).contains("Leave them alone"));
    }

    /// Forgetting runs on the log, and the log alone. Same rows, same `now`:
    /// the identical ledger. A later `now`: a faded one.
    #[test]
    fn forgetting_runs_on_replay_and_is_reproducible() {
        // Four replies that are each a full scale slower than the last, so the
        // ledger has an adverse trace to fade.
        let rows = log(&[(2.0, 0), (12.0, 3_600), (30.0, 7_200), (60.0, 10_800)]);

        let (_, first) = fold(&rows, at(10_800));
        let (_, again) = fold(&rows, at(10_800));
        assert_eq!(first, again, "the same log at the same instant must replay");

        let trace = first
            .trace(&trace_key())
            .expect("a run of slower-than-expected replies leaves a trace");
        assert_eq!(trace.sentiment, Sentiment::Adverse);
        assert!(trace.strength > 0.0);

        // Two hundred days later, nobody has written. Decay ran without anybody
        // scheduling it, and stopped at the imprescriptible floor because we
        // watched it happen ourselves.
        let (_, faded) = fold(&rows, at(10_800 + 200 * 86_400));
        let after = faded.trace(&trace_key()).expect("the trace survives");
        assert!(
            after.strength < trace.strength,
            "nothing faded: {} then {}",
            trace.strength,
            after.strength
        );
        assert!(
            after.strength >= agentos_domain::psyche::forgetting::MISTRUST_FLOOR - f64::EPSILON,
            "first-hand experience must not fade below the floor"
        );
        // ...and reading it a third time at the same later instant is the same
        // faded ledger, which a scheduler-driven one could not promise.
        assert_eq!(faded, fold(&rows, at(10_800 + 200 * 86_400)).1);
    }

    /// A row that is not about this dimension, or that carries no number, is
    /// skipped rather than folded as a zero.
    #[test]
    fn a_row_that_is_not_an_observation_is_not_folded_as_one() {
        let mut noise = episode(0.0, at(0));
        noise.dimension = Some("lead_time_days".to_owned());
        let mut empty = episode(0.0, at(1));
        empty.detail = json!({ "note": "they called" });

        let (latency, _) = fold(&[empty, noise], at(2));
        assert_eq!(latency.observations(), 0);
        assert_eq!(latency.expected(), None);
    }

    /// The key the two ends of the wire agree on.
    #[test]
    fn the_counterparty_key_is_bounded_and_case_folded() {
        assert_eq!(key("  AP@Supplier.Example "), "ap@supplier.example");
        let hostile = "a".repeat(400);
        assert_eq!(key(&hostile).chars().count(), MAX_COUNTERPARTY);
    }

    // -----------------------------------------------------------------------
    // Through the real path
    // -----------------------------------------------------------------------
    //
    // Real Postgres or nothing. Every claim below is a claim about what
    // `inbound::land` writes and what RLS hides, and a mock would assert that
    // the mock works.

    use agentos_domain::ids::TenantId;
    use agentos_domain::message::{CanonicalMessage, Channel, Direction, ProviderRef};
    use agentos_domain::untrusted::Untrusted;
    use agentos_store::db::Db;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; psyche wiring tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    const SUPPLIER: &str = "ap@shenzhen-brakes.example";

    async fn seed(db: &Db) -> (TenantId, EmployeeId) {
        let tenant = TenantId::new_v7(Utc::now());
        let employee = EmployeeId::new_v7(Utc::now());
        let label = format!("psyche-wire-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'Lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");
        (tenant, employee)
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    /// One round trip on a thread: we write, they answer `hours` later, and the
    /// answer goes in through [`crate::inbound::land`] — the production door,
    /// not a direct call to [`observe_reply`].
    async fn exchange(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        contact: &str,
        we_wrote_at: DateTime<Utc>,
        hours: f64,
    ) {
        let they_replied_at = we_wrote_at + super::hours(hours);
        deliver(
            db,
            tenant,
            employee,
            contact,
            Some(we_wrote_at),
            they_replied_at,
        )
        .await;
    }

    /// Land one inbound message, with our own message on the thread first when
    /// `we_wrote_at` is `Some`.
    ///
    /// `None` is the RFQ case and it is not an edge: `Buyer::issue_rfq` writes
    /// no `messages` row, so a supplier answering one arrives on a thread where
    /// nothing of ours was ever recorded.
    async fn deliver(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        contact: &str,
        we_wrote_at: Option<DateTime<Utc>>,
        they_replied_at: DateTime<Utc>,
    ) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let conversation = crate::inbound::conversation_for(
            &mut tx,
            employee,
            Channel::Email,
            contact,
            None,
            we_wrote_at.unwrap_or(they_replied_at),
        )
        .await
        .expect("conversation");

        // Our message, exactly as `main.rs::record_reply` writes one — including
        // its `ON CONFLICT DO NOTHING`, so re-running an exchange is the
        // redelivery it is meant to be rather than a unique violation.
        if let Some(sent_at) = we_wrote_at {
            sqlx::query(
                "INSERT INTO messages \
                     (id, tenant_id, conversation_id, employee_id, channel, direction, sender, \
                      subject, body, trust_label, idempotency_key, received_at, created_at) \
                 VALUES ($1, $2, $3, $4, 'email', 'outbound', 'lena@agents.example', NULL, \
                         'hello', 'trusted', $5, $6, $6) \
                 ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(tenant.as_uuid())
            .bind(conversation.as_uuid())
            .bind(employee.as_uuid())
            .bind(format!("out:{contact}:{}", sent_at.timestamp_millis()))
            .bind(sent_at)
            .execute(&mut **tx)
            .await
            .expect("record our message");
        }

        let provider_message_id = ProviderRef::new(format!(
            "msg-{}-{}",
            contact,
            they_replied_at.timestamp_millis()
        ));
        let message = CanonicalMessage {
            tenant_id: tenant,
            employee_id: employee,
            conversation_id: conversation,
            idempotency_key: CanonicalMessage::dedupe_key(
                employee,
                Channel::Email,
                &provider_message_id,
            ),
            provider_message_id,
            channel: Channel::Email,
            direction: Direction::Inbound,
            received_at: they_replied_at,
            from: Untrusted::new(contact.to_owned()),
            subject: None,
            body_text: Untrusted::new("re: your RFQ".to_owned()),
            attachments: Vec::new(),
        };
        crate::inbound::land(&mut tx, &message, they_replied_at)
            .await
            .expect("land");
        tx.commit().await.expect("commit exchange");
    }

    /// **The end-to-end claim.** A supplier answering an email — through
    /// `inbound::land`, which is the only door inbound mail has — moves a
    /// learned expectation, and the belief cites the thread it came out of.
    #[tokio::test]
    async fn a_real_reply_moves_the_expectation_through_the_real_path() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;
        let t0 = at(0);

        // Nothing is known before anybody writes. Not "fast", not "slow".
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let cold = standing(&mut tx, lena, SUPPLIER, t0)
            .await
            .expect("standing");
        assert_eq!(cold.latency.observations(), 0);
        assert_eq!(cold.latency.expected(), None);
        assert_eq!(cold.latency.reliability(), Reliability::Unknown);
        tx.rollback().await.expect("rollback");

        // Four exchanges, a day apart, answered in about six hours each.
        for (day, hours) in [(0, 6.0), (1, 7.0), (2, 6.0), (3, 5.0)] {
            exchange(&db, tenant, lena, SUPPLIER, at(day * 86_400), hours).await;
        }

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let learned = standing(&mut tx, lena, SUPPLIER, at(4 * 86_400))
            .await
            .expect("standing");
        assert_eq!(learned.latency.observations(), 4);
        let expected = learned.latency.expected().expect("observed");
        assert!(
            (5.0..=7.5).contains(&expected),
            "the belief did not converge on what they actually do: {expected}"
        );
        assert_eq!(learned.latency.reliability(), Reliability::Predictable);
        // They answered, so nobody is waiting on them.
        assert_eq!(learned.awaiting_reply_since, None);
        assert_eq!(
            learned.last_heard_from_at,
            Some(at(3 * 86_400) + hours(5.0))
        );

        // And the provenance survives: every episode names the thread it was
        // measured on, which is what makes "why do you chase them at ten
        // hours?" answerable in eighteen months.
        let episodes = psyche_store::episodes_about(&mut tx, lena, SUPPLIER, HISTORY)
            .await
            .expect("episodes");
        assert_eq!(episodes.len(), 4);
        for episode in &episodes {
            assert_eq!(episode.kind, REPLY_RECEIVED);
            assert_eq!(episode.dimension.as_deref(), Some(DIMENSION_KEY));
            assert!(episode.conversation_id.is_some(), "no thread to cite");
            assert!(episode.reported_by.is_none(), "we watched this ourselves");
            let stored = episode.surprise.expect("a surprise was measured");
            assert!(
                (-2.0..=2.0).contains(&stored),
                "the column is [-2, 2] and holds {stored}"
            );
        }
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// The decision, end to end: the same silence, two suppliers, two answers —
    /// and the difference comes from what each of them has actually done.
    #[tokio::test]
    async fn the_chase_list_is_the_counterpartys_own_record() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;
        let prompt = "quotes@prompt-forge.example";
        let slow = "quotes@slow-mill.example";

        // Ten days apart, because the slow one takes three of them to answer and
        // an exchange that has not finished is not an exchange: `land` measures
        // a reply against *our* last message, and only when ours was the last
        // thing said.
        for day in 0..4 {
            exchange(&db, tenant, lena, prompt, at(day * 10 * 86_400), 2.0).await;
            exchange(&db, tenant, lena, slow, at(day * 10 * 86_400), 70.0).await;
        }

        // An RFQ goes out to both — the write `open_the_round` makes.
        let sent = at(40 * 86_400);
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        for supplier in [prompt, slow] {
            awaiting_reply(&mut tx, lena, supplier, sent)
                .await
                .expect("awaiting");
        }
        tx.commit().await.expect("commit");

        // A day of silence later.
        let now = sent + TimeDelta::days(1);
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let waiting = chase_list(&mut tx, lena, now).await.expect("chase list");
        assert_eq!(waiting.len(), 2, "both are owed an answer");

        let overdue: Vec<&str> = waiting
            .iter()
            .filter(|s| s.overdue_by(now).is_some())
            .map(|s| s.counterparty.as_str())
            .collect();
        assert_eq!(
            overdue,
            vec![prompt],
            "a day is late for a two-hour supplier and ordinary for a three-day one"
        );

        // Nothing about trust was invented on the way: the link is its prior,
        // which is exactly what `psyche_trust_needs_evidence` permits.
        let link = psyche_store::trust_for(&mut tx, lena, prompt)
            .await
            .expect("trust")
            .expect("a row was written");
        assert_eq!(link.evidence_count, 0);
        assert_eq!(link.trust, link.prior_trust);
        assert_eq!(link.last_evidence_episode_id, None);
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// One tenant's psyche is invisible to another, asked for by the same
    /// employee id and the same counterparty with no tenant filter in sight.
    #[tokio::test]
    async fn one_tenants_psyche_is_invisible_to_another() {
        let Some(db) = db().await else { return };
        let (mine, lena) = seed(&db).await;
        let (theirs, _) = seed(&db).await;

        for day in 0..4 {
            exchange(&db, mine, lena, SUPPLIER, at(day * 86_400), 6.0).await;
        }
        let mut tx = db.tenant_tx(mine).await.expect("tenant tx");
        awaiting_reply(&mut tx, lena, SUPPLIER, at(9 * 86_400))
            .await
            .expect("awaiting");
        tx.commit().await.expect("commit");

        let now = at(10 * 86_400);
        let mut tx = db.tenant_tx(mine).await.expect("tenant tx");
        assert_eq!(
            standing(&mut tx, lena, SUPPLIER, now)
                .await
                .expect("standing")
                .latency
                .observations(),
            4
        );
        assert_eq!(
            chase_list(&mut tx, lena, now).await.expect("chase").len(),
            1
        );
        tx.rollback().await.expect("rollback");

        let mut tx = db.tenant_tx(theirs).await.expect("tenant tx");
        let neighbour = standing(&mut tx, lena, SUPPLIER, now)
            .await
            .expect("standing");
        assert_eq!(neighbour.latency.observations(), 0);
        assert_eq!(neighbour.latency.expected(), None);
        assert_eq!(neighbour.awaiting_reply_since, None);
        assert!(
            chase_list(&mut tx, lena, now)
                .await
                .expect("chase")
                .is_empty()
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, mine).await;
        drop_tenant(&db, theirs).await;
    }

    /// **Answering takes them off the list, measured or not.**
    ///
    /// The RFQ case, and the one that would rot quietly: `Buyer::issue_rfq`
    /// writes no `messages` row, so a supplier answering an RFQ arrives on a
    /// thread with nothing of ours to measure against. If the wait were cleared
    /// only where a latency could be computed, every supplier who ever answered
    /// an RFQ would sit on the chase list forever and the note would tell the
    /// employee to harass the ones who *did* reply.
    #[tokio::test]
    async fn a_supplier_who_answers_an_rfq_comes_off_the_chase_list() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;
        let sent = at(0);

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        awaiting_reply(&mut tx, lena, SUPPLIER, sent)
            .await
            .expect("awaiting");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(
            chase_list(&mut tx, lena, sent + TimeDelta::days(1))
                .await
                .expect("chase")
                .len(),
            1
        );
        tx.rollback().await.expect("rollback");

        // They answer. No message of ours on the thread, so nothing is measured.
        deliver(
            &db,
            tenant,
            lena,
            SUPPLIER,
            None,
            sent + TimeDelta::hours(30),
        )
        .await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let after = standing(&mut tx, lena, SUPPLIER, sent + TimeDelta::days(2))
            .await
            .expect("standing");
        assert_eq!(after.awaiting_reply_since, None, "still being chased");
        assert_eq!(after.last_heard_from_at, Some(sent + TimeDelta::hours(30)));
        assert_eq!(
            after.latency.observations(),
            0,
            "a reply with nothing to measure against must not invent a latency"
        );
        assert!(
            chase_list(&mut tx, lena, sent + TimeDelta::days(2))
                .await
                .expect("chase")
                .is_empty()
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// A `From` header the psyche cannot name must not cost anybody their mail.
    ///
    /// Both psyche tables CHECK `length(counterparty) between 1 and 200`, and
    /// the write is inside `land`'s transaction — so an unnameable sender that
    /// reached the INSERT would fail the landing and dead-letter a real message.
    /// The two hostile shapes are a header of pure whitespace and one four
    /// hundred characters long.
    #[tokio::test]
    async fn a_sender_the_psyche_cannot_name_still_gets_its_mail_delivered() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;

        for hostile in ["   ", &"z".repeat(380)] {
            exchange(&db, tenant, lena, hostile, at(0), 6.0).await;
        }

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        // The long one is nameable once bounded, and is observed under the
        // bounded key.
        let long = key(&"z".repeat(380));
        assert_eq!(long.chars().count(), MAX_COUNTERPARTY);
        assert_eq!(
            standing(&mut tx, lena, &long, at(86_400))
                .await
                .expect("standing")
                .latency
                .observations(),
            1
        );
        // The whitespace sender is unnameable, so it is the *only* one of the
        // two that left no episode behind.
        let episodes: i64 = sqlx::query_scalar("SELECT count(*) FROM psyche_episodes")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(episodes, 1, "an observation about nobody was recorded");
        // ...and both messages landed regardless, which is the point.
        let landed: i64 =
            sqlx::query_scalar("SELECT count(*) FROM messages WHERE direction = 'inbound'")
                .fetch_one(&mut **tx)
                .await
                .expect("count");
        assert_eq!(
            landed, 2,
            "a header the psyche cannot name cost us a message"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// A redelivered webhook is one message arriving twice, not a supplier who
    /// answered twice. `land` writes the episode on the insert path only, for
    /// the same reason it writes its audit row there.
    #[tokio::test]
    async fn a_redelivered_message_does_not_teach_the_agent_anything() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;
        exchange(&db, tenant, lena, SUPPLIER, at(0), 6.0).await;

        // The same provider id, the same everything: `dedupe_key` is pure, so
        // this is the redelivery.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let before = psyche_store::episodes_about(&mut tx, lena, SUPPLIER, HISTORY)
            .await
            .expect("episodes");
        tx.rollback().await.expect("rollback");
        assert_eq!(before.len(), 1);

        exchange(&db, tenant, lena, SUPPLIER, at(0), 6.0).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let after = psyche_store::episodes_about(&mut tx, lena, SUPPLIER, HISTORY)
            .await
            .expect("episodes");
        tx.rollback().await.expect("rollback");
        assert_eq!(after, before, "a redelivery moved the belief");

        drop_tenant(&db, tenant).await;
    }
}
