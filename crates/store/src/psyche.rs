//! Persistence for what one employee has learned about one counterparty.
//!
//! The port of MPCP's memory layer (`etat["journal"]`, `["liens"]`,
//! `["croyances"]`, `["attentes"]`, `["precision"]`) onto Postgres. Read
//! `migrations/0009_psyche.sql` alongside this file: most of the guarantees are
//! in the schema, and this module is the narrow door onto them.
//!
//! **The observations are the source of truth.** [`record_episode`] writes an
//! observation that can never be edited or deleted afterwards. Everything
//! derived from observations — a trust value, a consolidated belief — has to
//! cite them, and the database refuses the write otherwise: a trust score with
//! `evidence_count = 0` must equal its prior, and a belief with no rows in
//! `psyche_belief_episodes` fails at COMMIT. That is what makes "why do you
//! open 12% below their ask with this supplier?" answerable eighteen months
//! later with a list of dated facts instead of a float.
//!
//! **Per tenant and per employee.** Every key starts `(tenant_id,
//! employee_id)`. Lena's opinion of a factory is not Alex's, they are colleagues
//! at the same company, and collapsing the two would destroy the only thing
//! worth accumulating. RLS gives the tenant boundary; `employee_id` in the key
//! gives the other one.
//!
//! **This data colours tone and priority, never authorisation.** Nothing here
//! is an input to `domain::policy::evaluate()`. A frustrated agent and a calm
//! one are allowed exactly the same actions; the psyche decides what to
//! propose, whom to chase first, and how to phrase it. MPCP states the same
//! rule for itself — *"l'identité ne colore QUE le ressenti, jamais la
//! dynamique"*.
//!
//! **Deliberately not ported here:** theory of mind, repression, narrative
//! themes, and travelling gossip. A B2B purchasing agent has no use for a model
//! of what the supplier thinks we think.
//!
//! The types below mirror the rows rather than the domain. `agentos_domain`'s
//! psyche aggregates land in a sibling unit; this module deliberately does not
//! guess at their field names, so the mapping is one small conversion at
//! integration rather than a schema built around a guess.
//!
//! Two consequences of the append-only rule that surprise people:
//!
//! * `psyche_episodes` has **no foreign key to `tenants`**, exactly like
//!   `audit_log`. Cascading would make deleting a tenant a way to delete the
//!   evidence, and the append-only trigger would refuse the cascade anyway. So
//!   dropping a tenant leaves its episodes behind, on purpose.
//! * [`consolidate_belief`] writes the belief and its genealogy in one
//!   transaction. The "has evidence" check is a DEFERRED constraint trigger, so
//!   a caller who bypasses this module and writes a bare belief gets the error
//!   from `commit()`, not from the INSERT.

use std::str::FromStr;

use agentos_domain::ids::{ConversationId, EmployeeId};
use agentos_domain::money::{Currency, Money};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

/// The row said something the domain cannot represent — a currency code that no
/// longer parses, an amount that is not a `Money`. Same spelling as
/// `employee.rs` uses, for the same reason: it is neither a driver failure nor a
/// missing row.
fn corrupt(what: impl Into<String>) -> StoreError {
    StoreError::Database(sqlx::Error::Decode(
        format!("corrupt psyche row: {}", what.into()).into(),
    ))
}

/// `Money` counts in `u64`, Postgres in `i64`. An observed amount past
/// `i64::MAX` is not a real quote, and saturating keeps the record writable
/// rather than losing the whole observation to an overflow.
fn to_i64(minor: u64) -> i64 {
    i64::try_from(minor).unwrap_or(i64::MAX)
}

fn to_money(minor: Option<i64>, currency: Option<String>) -> Result<Option<Money>, StoreError> {
    match (minor, currency) {
        (None, None) => Ok(None),
        (Some(minor), Some(code)) => {
            let currency = Currency::from_str(&code)
                .map_err(|e| corrupt(format!("currency {code:?}: {e}")))?;
            let minor = u64::try_from(minor).map_err(|_| corrupt("negative amount_minor"))?;
            Money::new(minor, currency)
                .map(Some)
                .map_err(|e| corrupt(format!("amount: {e}")))
        }
        // The schema forbids this pair; if it is on disk, something wrote around
        // the CHECK and the amount is unnameable.
        (minor, currency) => Err(corrupt(format!(
            "half an amount (minor={minor:?}, currency={currency:?})"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Episodes
// ---------------------------------------------------------------------------

/// One observation, on its way to storage. MPCP's `journal` entry.
#[derive(Debug, Clone)]
pub struct NewEpisode {
    /// App-minted UUIDv7, stamped at `observed_at`.
    pub id: Uuid,
    /// Whose experience this is.
    pub employee_id: EmployeeId,
    /// Stable key for the other party: a supplier code, a normalised domain.
    pub counterparty: String,
    /// The domain's event vocabulary: `quote_received`, `commitment_kept`,
    /// `lead_time_missed`.
    pub kind: String,
    /// Which learned dimension this feeds, if any. Matches
    /// [`Expectation::dimension`].
    pub dimension: Option<String>,
    /// MPCP `polarite`: `-1`, `0` or `+1`. Zero is a real, neutral contact.
    pub polarity: i16,
    /// MPCP `poids`: weight against a routine event (`1.0`). Must be in
    /// `(0, 10]`.
    pub weight: f64,
    /// MPCP's signed Rescorla-Wagner surprise *at the time*: observed polarity
    /// minus the expectation held before this episode. Stored rather than
    /// recomputed so the learning curve stays replayable.
    pub surprise: Option<f64>,
    /// MPCP `par`: who reported it. `None` means we experienced it directly,
    /// and that difference is evidence, not metadata.
    pub reported_by: Option<String>,
    /// The thread it came out of, for citation.
    pub conversation_id: Option<ConversationId>,
    /// The observed amount when the observation is about money — a quoted
    /// price, a settled price, a penalty.
    pub amount: Option<Money>,
    /// Structured detail: promised vs actual days, channel, incoterm.
    pub detail: serde_json::Value,
    /// Injected clock. Never `now()`.
    pub observed_at: DateTime<Utc>,
}

/// An observation as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Episode {
    /// Row id; what [`consolidate_belief`] cites.
    pub id: Uuid,
    /// See [`NewEpisode::kind`].
    pub kind: String,
    /// See [`NewEpisode::dimension`].
    pub dimension: Option<String>,
    /// See [`NewEpisode::polarity`].
    pub polarity: i16,
    /// See [`NewEpisode::weight`].
    pub weight: f64,
    /// See [`NewEpisode::surprise`].
    pub surprise: Option<f64>,
    /// See [`NewEpisode::reported_by`].
    pub reported_by: Option<String>,
    /// See [`NewEpisode::conversation_id`].
    pub conversation_id: Option<Uuid>,
    /// See [`NewEpisode::amount`].
    pub amount: Option<Money>,
    /// See [`NewEpisode::detail`].
    pub detail: serde_json::Value,
    /// See [`NewEpisode::observed_at`].
    pub observed_at: DateTime<Utc>,
}

/// One `psyche_episodes` row in SELECT order.
type EpisodeRow = (
    Uuid,
    String,
    Option<String>,
    i16,
    f64,
    Option<f64>,
    Option<String>,
    Option<Uuid>,
    Option<i64>,
    Option<String>,
    serde_json::Value,
    DateTime<Utc>,
);

/// Append an observation. There is no update and no delete: `app_role` lacks
/// the privilege and a trigger refuses the statement even for a superuser.
pub async fn record_episode(tx: &mut TenantTx<'_>, episode: &NewEpisode) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO psyche_episodes \
           (id, tenant_id, employee_id, counterparty, kind, dimension, polarity, weight, \
            surprise, reported_by, conversation_id, amount_minor, currency, detail, observed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(episode.id)
    .bind(tx.tenant_id().as_uuid())
    .bind(episode.employee_id.as_uuid())
    .bind(&episode.counterparty)
    .bind(&episode.kind)
    .bind(&episode.dimension)
    .bind(episode.polarity)
    .bind(episode.weight)
    .bind(episode.surprise)
    .bind(&episode.reported_by)
    .bind(episode.conversation_id.map(|c| c.as_uuid()))
    .bind(episode.amount.map(|m| to_i64(m.minor())))
    .bind(episode.amount.map(|m| m.currency().code()))
    .bind(&episode.detail)
    .bind(episode.observed_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// This employee's timeline with one counterparty, newest first.
///
/// Ties on `observed_at` break on `id`, which is UUIDv7 and therefore ordered
/// by mint time: same inputs, same order, every run.
pub async fn episodes_about(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
    limit: i64,
) -> Result<Vec<Episode>, StoreError> {
    let rows: Vec<EpisodeRow> = sqlx::query_as(
        "SELECT id, kind, dimension, polarity, weight, surprise, reported_by, \
                conversation_id, amount_minor, currency, detail, observed_at \
         FROM psyche_episodes \
         WHERE employee_id = $1 AND counterparty = $2 \
         ORDER BY observed_at DESC, id DESC \
         LIMIT $3",
    )
    .bind(employee_id.as_uuid())
    .bind(counterparty)
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(Episode {
                id: row.0,
                kind: row.1,
                dimension: row.2,
                polarity: row.3,
                weight: row.4,
                surprise: row.5,
                reported_by: row.6,
                conversation_id: row.7,
                amount: to_money(row.8, row.9)?,
                detail: row.10,
                observed_at: row.11,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

/// MPCP's `lien`: trust in one counterparty, built and broken by episodes.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustLink {
    /// Whose trust this is.
    pub employee_id: EmployeeId,
    /// Who it is in.
    pub counterparty: String,
    /// MPCP `confiance`, in `[0, 1]`.
    pub trust: f64,
    /// MPCP `_confiance_initiale`: what the link was worth before evidence.
    /// `0.5` for a stranger. With `evidence_count == 0` the database requires
    /// `trust == prior_trust`.
    pub prior_trust: f64,
    /// How many episodes have moved it.
    pub evidence_count: i32,
    /// The episode that last moved it. Must be an episode this employee
    /// recorded about this same counterparty — a composite foreign key, so
    /// citing another supplier's evidence is not a mistake anyone can make.
    pub last_evidence_episode_id: Option<Uuid>,
    /// MPCP `brise_le`: when a *built* trust fell off a cliff. A break is a
    /// dated fact, not merely a low number.
    pub broken_at: Option<DateTime<Utc>>,
    /// MPCP `brise_vecu`: whether we watched it happen or heard about it.
    pub broken_experienced: Option<bool>,
    /// The last time they said anything to us.
    pub last_heard_from_at: Option<DateTime<Utc>>,
    /// When we started waiting on a reply, if we are. `None` means the ball is
    /// not in their court — this is what [`gone_quiet`] reads.
    pub awaiting_reply_since: Option<DateTime<Utc>>,
    /// Injected clock.
    pub updated_at: DateTime<Utc>,
}

/// One `psyche_trust` row in SELECT order.
type TrustRow = (
    f64,
    f64,
    i32,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<bool>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

/// Write a trust link.
///
/// Returns [`StoreError::Conflict`] on the CHECK constraints, which is where
/// the interesting failures live: trust that has moved off its prior without an
/// `evidence_count`, or a `last_evidence_episode_id` naming an episode about
/// someone else. Both are "an opinion nothing supports", and both are refused
/// by Postgres rather than by a code review.
pub async fn save_trust(tx: &mut TenantTx<'_>, link: &TrustLink) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO psyche_trust \
           (tenant_id, employee_id, counterparty, trust, prior_trust, evidence_count, \
            last_evidence_episode_id, broken_at, broken_experienced, last_heard_from_at, \
            awaiting_reply_since, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (tenant_id, employee_id, counterparty) DO UPDATE SET \
           trust = excluded.trust, \
           prior_trust = excluded.prior_trust, \
           evidence_count = excluded.evidence_count, \
           last_evidence_episode_id = excluded.last_evidence_episode_id, \
           broken_at = excluded.broken_at, \
           broken_experienced = excluded.broken_experienced, \
           last_heard_from_at = excluded.last_heard_from_at, \
           awaiting_reply_since = excluded.awaiting_reply_since, \
           updated_at = excluded.updated_at",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(link.employee_id.as_uuid())
    .bind(&link.counterparty)
    .bind(link.trust)
    .bind(link.prior_trust)
    .bind(link.evidence_count)
    .bind(link.last_evidence_episode_id)
    .bind(link.broken_at)
    .bind(link.broken_experienced)
    .bind(link.last_heard_from_at)
    .bind(link.awaiting_reply_since)
    .bind(link.updated_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// This employee's trust in one counterparty. `None` means no dealings yet —
/// which is not the same as distrust, and the caller must not conflate them.
pub async fn trust_for(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
) -> Result<Option<TrustLink>, StoreError> {
    let row: Option<TrustRow> = sqlx::query_as(
        "SELECT trust, prior_trust, evidence_count, last_evidence_episode_id, broken_at, \
                broken_experienced, last_heard_from_at, awaiting_reply_since, updated_at \
         FROM psyche_trust WHERE employee_id = $1 AND counterparty = $2",
    )
    .bind(employee_id.as_uuid())
    .bind(counterparty)
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row.map(|r| TrustLink {
        employee_id,
        counterparty: counterparty.to_owned(),
        trust: r.0,
        prior_trust: r.1,
        evidence_count: r.2,
        last_evidence_episode_id: r.3,
        broken_at: r.4,
        broken_experienced: r.5,
        last_heard_from_at: r.6,
        awaiting_reply_since: r.7,
        updated_at: r.8,
    }))
}

/// One [`gone_quiet`] row in SELECT order.
type QuietRow = (String, DateTime<Utc>, Option<DateTime<Utc>>, f64);

/// A relationship where we are waiting and they have not answered.
#[derive(Debug, Clone, PartialEq)]
pub struct QuietCounterparty {
    /// Who has gone quiet.
    pub counterparty: String,
    /// Since when we have been waiting.
    pub awaiting_reply_since: DateTime<Utc>,
    /// The last time they said anything at all.
    pub last_heard_from_at: Option<DateTime<Utc>>,
    /// What we still think of them. A supplier we trust who has gone quiet is a
    /// different follow-up from one we do not.
    pub trust: f64,
}

/// Counterparties this employee has been waiting on since before `cutoff`.
///
/// The chase list. Ordered oldest-wait first, ties on `counterparty`, so the
/// same state yields the same queue every time — a psyche that reprioritises
/// at random is not replayable. Rides the partial index
/// `psyche_trust_quiet_idx`.
///
/// `cutoff` is passed in rather than computed from a clock in here, for the
/// same reason the domain takes `now` as a parameter.
pub async fn gone_quiet(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    cutoff: DateTime<Utc>,
) -> Result<Vec<QuietCounterparty>, StoreError> {
    let rows: Vec<QuietRow> = sqlx::query_as(
        "SELECT counterparty, awaiting_reply_since, last_heard_from_at, trust \
         FROM psyche_trust \
         WHERE employee_id = $1 \
           AND awaiting_reply_since IS NOT NULL \
           AND awaiting_reply_since < $2 \
         ORDER BY awaiting_reply_since, counterparty",
    )
    .bind(employee_id.as_uuid())
    .bind(cutoff)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(counterparty, awaiting_reply_since, last_heard_from_at, trust)| QuietCounterparty {
                counterparty,
                awaiting_reply_since,
                last_heard_from_at,
                trust,
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// Beliefs — NOT WIRED
// ---------------------------------------------------------------------------
//
// Nothing outside `#[cfg(test)]` calls [`consolidate_belief`] or
// [`beliefs_about`], and `psyche_beliefs` / `psyche_belief_episodes` are
// therefore tables nothing writes. That is a decision rather than an oversight
// and the argument is written down once, in `agentos_app::psyche`'s closing
// section: the only subject with three concordant episodes in this product is
// "slow to answer", which is the expectation restated, and a belief that adds
// no information is a second place for the same fact to be wrong.
//
// Kept because the genealogy is the expensive half and it is correct: the
// deferred trigger that refuses a belief with no founding episodes is what
// makes "why do you open 12% below their ask?" answerable eighteen months
// later. Wire this the day an employee observes something that is *not* a
// restatement — a lead time missed, a spec substituted.

/// MPCP's `croyance`: what repeated episodes of one polarity consolidated into.
#[derive(Debug, Clone, PartialEq)]
pub struct Belief {
    /// App-minted UUIDv7. Ignored when the `(counterparty, topic, polarity)`
    /// belief already exists — MPCP merges into it rather than accumulating
    /// duplicates — so read the id back with [`beliefs_about`].
    pub id: Uuid,
    /// Whose belief this is.
    pub employee_id: EmployeeId,
    /// Who it is about.
    pub counterparty: String,
    /// What it is about: `price_padding`, `lead_time_optimism`,
    /// `answers_fast_on_whatsapp`. MPCP's `sujet`, minus the counterparty.
    pub topic: String,
    /// `-1` or `+1`. MPCP never consolidates a neutral belief.
    pub polarity: i16,
    /// MPCP `force`, in `(0, 1]`.
    pub strength: f64,
    /// MPCP `formee_le`.
    pub formed_at: DateTime<Utc>,
    /// MPCP `ravivee_le`: last time an episode refreshed it. Drives affective
    /// forgetting — a conviction nothing renews pales.
    pub refreshed_at: DateTime<Utc>,
    /// MPCP `vecu`: at least one founding episode was lived, not reported.
    pub from_experience: bool,
}

/// One [`beliefs_about`] row in SELECT order: the belief's columns, then its
/// genealogy aggregated in the same query.
type BeliefRow = (
    Uuid,
    String,
    i16,
    f64,
    DateTime<Utc>,
    DateTime<Utc>,
    bool,
    Vec<Uuid>,
);

/// A belief together with the observations it stands on.
#[derive(Debug, Clone, PartialEq)]
pub struct BeliefRecord {
    /// The belief.
    pub belief: Belief,
    /// Every founding episode, ascending by id. Never empty: the schema makes
    /// an unsupported belief unwritable.
    pub founding_episodes: Vec<Uuid>,
}

/// Consolidate `founding` episodes into a belief, or refresh an existing one.
///
/// Mirrors MPCP's sleep-consolidation step: repeated episodes of one polarity
/// about one subject compress into a durable belief, and the belief outlives
/// them. Two deliberate differences from `mpcp.py`, both for audit:
///
/// * MPCP keeps only the eight most recent source refs (`refs[-8:]`). We keep
///   every one. Rows are cheap; a genealogy that loses its tail is not.
/// * `strength`, `polarity` and `N_CONSOLIDATION` are the domain's business.
///   This function stores what it is handed and enforces only the rule that
///   cannot live anywhere else: **no belief without evidence.**
///
/// `founding` must be non-empty, and every id must be an episode *this*
/// employee recorded about *this* counterparty; anything else is
/// [`StoreError::NotFound`] and nothing is written. Cited episodes already on
/// the belief are ignored rather than duplicated, so re-consolidating is
/// idempotent.
pub async fn consolidate_belief(
    tx: &mut TenantTx<'_>,
    belief: &Belief,
    founding: &[Uuid],
) -> Result<(), StoreError> {
    if founding.is_empty() {
        return Err(StoreError::NotFound);
    }

    // Check before writing, so a caller citing an episode that is not theirs
    // gets NotFound here rather than a deferred trigger firing at commit() with
    // the transaction already half-written.
    let resolved: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT id) FROM psyche_episodes \
         WHERE id = ANY($1) AND employee_id = $2 AND counterparty = $3",
    )
    .bind(founding)
    .bind(belief.employee_id.as_uuid())
    .bind(&belief.counterparty)
    .fetch_one(&mut ***tx)
    .await?;
    if resolved != founding.len() as i64 {
        return Err(StoreError::NotFound);
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO psyche_beliefs \
           (id, tenant_id, employee_id, counterparty, topic, polarity, strength, \
            formed_at, refreshed_at, from_experience) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (tenant_id, employee_id, counterparty, topic, polarity) DO UPDATE SET \
           strength = excluded.strength, \
           refreshed_at = excluded.refreshed_at, \
           from_experience = psyche_beliefs.from_experience OR excluded.from_experience \
         RETURNING id",
    )
    .bind(belief.id)
    .bind(tx.tenant_id().as_uuid())
    .bind(belief.employee_id.as_uuid())
    .bind(&belief.counterparty)
    .bind(&belief.topic)
    .bind(belief.polarity)
    .bind(belief.strength)
    .bind(belief.formed_at)
    .bind(belief.refreshed_at)
    .bind(belief.from_experience)
    .fetch_one(&mut ***tx)
    .await?;

    // `INSERT ... SELECT FROM psyche_episodes` rather than from the array: the
    // employee_id and counterparty written into the genealogy come from the
    // episode row itself, so they cannot disagree with it.
    sqlx::query(
        "INSERT INTO psyche_belief_episodes \
           (belief_id, episode_id, tenant_id, employee_id, counterparty) \
         SELECT $1, e.id, $2, e.employee_id, e.counterparty \
         FROM psyche_episodes e \
         WHERE e.id = ANY($3) AND e.employee_id = $4 AND e.counterparty = $5 \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(founding)
    .bind(belief.employee_id.as_uuid())
    .bind(&belief.counterparty)
    .execute(&mut ***tx)
    .await?;

    Ok(())
}

/// Every belief this employee holds about one counterparty, each with its
/// genealogy.
///
/// One query, not one per belief: provenance that costs a round trip is
/// provenance nobody reads. Ordered by `(topic, polarity)` and the episode ids
/// ascending, so two runs over the same rows produce byte-identical output.
pub async fn beliefs_about(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
) -> Result<Vec<BeliefRecord>, StoreError> {
    let rows: Vec<BeliefRow> = sqlx::query_as(
        "SELECT b.id, b.topic, b.polarity, b.strength, b.formed_at, b.refreshed_at, \
                b.from_experience, \
                coalesce(array_agg(e.episode_id ORDER BY e.episode_id) \
                         FILTER (WHERE e.episode_id IS NOT NULL), '{}') \
         FROM psyche_beliefs b \
         LEFT JOIN psyche_belief_episodes e ON e.belief_id = b.id \
         WHERE b.employee_id = $1 AND b.counterparty = $2 \
         GROUP BY b.id \
         ORDER BY b.topic, b.polarity",
    )
    .bind(employee_id.as_uuid())
    .bind(counterparty)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| BeliefRecord {
            belief: Belief {
                id: r.0,
                employee_id,
                counterparty: counterparty.to_owned(),
                topic: r.1,
                polarity: r.2,
                strength: r.3,
                formed_at: r.4,
                refreshed_at: r.5,
                from_experience: r.6,
            },
            founding_episodes: r.7,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Expectations — NOT WIRED
// ---------------------------------------------------------------------------
//
// Nothing outside `#[cfg(test)]` calls [`save_expectation`] or
// [`expectations_about`]; `psyche_expectations` is a table nothing writes. The
// argument is in `agentos_app::psyche`'s closing section and it is about units,
// not about effort: this schema is MPCP's *sign-valued* model — `expectation`
// is CHECKed to `[-1, 1]` and the Welford runs over `|surprise|` — while the
// domain ships the magnitude-valued replacement `docs/PSYCHE_PORT.md` §5.2
// argues for, whose expectation is in hours. "23 hours" does not fit
// `[-1, 1]`, so writing here would mean either a lie about the units or a
// migration. The app folds the episodes instead, which costs neither and
// cannot disagree with the log it came from.

/// MPCP's `attente` (Rescorla-Wagner) plus its `precision` (Welford), for one
/// `(counterparty, dimension)`.
///
/// This is the table that pays for the system. "Their quotes land 14% above
/// where they settle" and "they claim 15 days, the median is 23" are both an
/// expectation plus a running variance of how wrong it has been.
///
/// Note what is *not* here: `precision` itself. MPCP computes it as
/// `1 / (1 + K_PRECISION * var)`, and a derived value in a column is a value
/// that eventually disagrees with what it was derived from. The domain computes
/// it from [`Expectation::surprise_var`].
#[derive(Debug, Clone, PartialEq)]
pub struct Expectation {
    /// Whose expectation.
    pub employee_id: EmployeeId,
    /// About whom.
    pub counterparty: String,
    /// About what: `price`, `lead_time`, `response_latency`, `quality`.
    pub dimension: String,
    /// MPCP's R-W expectation in `[-1, 1]`, moved by
    /// `attente + TAUX_PRED * surprise` and pulled back toward zero by
    /// extinction.
    pub expectation: f64,
    /// Welford running mean of `|surprise|`.
    pub surprise_mean: f64,
    /// Welford running variance of `|surprise|`. Precision is
    /// `1 / (1 + K * var)` of this: an erratic counterparty moves us less.
    pub surprise_var: f64,
    /// Welford's `n`, and the evidence counter. With zero observations the
    /// database requires the other three to be zero.
    pub observations: i32,
    /// Injected clock.
    pub updated_at: DateTime<Utc>,
}

/// Write one expectation. Upsert on `(counterparty, dimension)`.
pub async fn save_expectation(
    tx: &mut TenantTx<'_>,
    expectation: &Expectation,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO psyche_expectations \
           (tenant_id, employee_id, counterparty, dimension, expectation, \
            surprise_mean, surprise_var, observations, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (tenant_id, employee_id, counterparty, dimension) DO UPDATE SET \
           expectation = excluded.expectation, \
           surprise_mean = excluded.surprise_mean, \
           surprise_var = excluded.surprise_var, \
           observations = excluded.observations, \
           updated_at = excluded.updated_at",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(expectation.employee_id.as_uuid())
    .bind(&expectation.counterparty)
    .bind(&expectation.dimension)
    .bind(expectation.expectation)
    .bind(expectation.surprise_mean)
    .bind(expectation.surprise_var)
    .bind(expectation.observations)
    .bind(expectation.updated_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// Everything this employee predicts about one counterparty, ordered by
/// dimension.
pub async fn expectations_about(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    counterparty: &str,
) -> Result<Vec<Expectation>, StoreError> {
    let rows: Vec<(String, f64, f64, f64, i32, DateTime<Utc>)> = sqlx::query_as(
        "SELECT dimension, expectation, surprise_mean, surprise_var, observations, updated_at \
         FROM psyche_expectations \
         WHERE employee_id = $1 AND counterparty = $2 \
         ORDER BY dimension",
    )
    .bind(employee_id.as_uuid())
    .bind(counterparty)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(dimension, expectation, surprise_mean, surprise_var, observations, updated_at)| {
                Expectation {
                    employee_id,
                    counterparty: counterparty.to_owned(),
                    dimension,
                    expectation,
                    surprise_mean,
                    surprise_var,
                    observations,
                    updated_at,
                }
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use agentos_domain::ids::TenantId;

    /// Real Postgres or nothing. Every claim in this module is a claim about
    /// SQL — RLS policies, CHECK constraints, deferred triggers — and a mock
    /// would assert that the mock works.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; psyche tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    const T0: i64 = 1_700_000_000;
    const DAY: i64 = 86_400;
    const SUPPLIER: &str = "shenzhen-brakes";

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'psyche test')")
            .bind(tenant.as_uuid())
            .bind(format!("psyche-{}", tenant.as_uuid()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn new_employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    /// Cascades to trust, beliefs, genealogy and expectations. **Not** to
    /// episodes: they have no foreign key to `tenants`, deliberately, so the
    /// observations survive a tenant delete exactly as `audit_log` rows do.
    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    fn episode(employee_id: EmployeeId, id_secs: i64, polarity: i16) -> NewEpisode {
        NewEpisode {
            id: Uuid::now_v7(),
            employee_id,
            counterparty: SUPPLIER.to_owned(),
            kind: "lead_time_missed".to_owned(),
            dimension: Some("lead_time".to_owned()),
            polarity,
            weight: 1.0,
            surprise: Some(-0.7),
            reported_by: None,
            conversation_id: None,
            amount: Some(Money::from_major(14_200, Currency::Usd).expect("money")),
            detail: serde_json::json!({ "promised_days": 15, "actual_days": 23 }),
            observed_at: at(T0 + id_secs),
        }
    }

    fn belief(employee_id: EmployeeId, id: Uuid) -> Belief {
        Belief {
            id,
            employee_id,
            counterparty: SUPPLIER.to_owned(),
            topic: "lead_time_optimism".to_owned(),
            polarity: -1,
            strength: 0.75,
            formed_at: at(T0 + 3 * DAY),
            refreshed_at: at(T0 + 3 * DAY),
            from_experience: true,
        }
    }

    /// A settled link with three founding observations behind it.
    async fn seed_relationship(
        db: &Db,
        tenant: TenantId,
        employee_id: EmployeeId,
        trust: f64,
    ) -> Vec<Uuid> {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let mut ids = Vec::new();
        for i in 0..3 {
            let e = episode(employee_id, i, -1);
            ids.push(e.id);
            record_episode(&mut tx, &e).await.expect("record episode");
        }
        save_trust(
            &mut tx,
            &TrustLink {
                employee_id,
                counterparty: SUPPLIER.to_owned(),
                trust,
                prior_trust: 0.5,
                evidence_count: 3,
                last_evidence_episode_id: Some(ids[2]),
                broken_at: None,
                broken_experienced: None,
                last_heard_from_at: Some(at(T0 + 2)),
                awaiting_reply_since: None,
                updated_at: at(T0 + 3),
            },
        )
        .await
        .expect("save trust");
        tx.commit().await.expect("commit");
        ids
    }

    /// Nothing written by one tenant is reachable by another, on any of the
    /// five tables — asked for by primary key, with no tenant filter in the SQL.
    #[tokio::test]
    async fn every_psyche_table_is_invisible_across_tenants() {
        let Some(db) = db().await else { return };
        let mine = new_tenant(&db).await;
        let theirs = new_tenant(&db).await;
        let lena = new_employee(&db, mine, "lena").await;

        let episodes = seed_relationship(&db, mine, lena, 0.2).await;
        let belief_id = Uuid::now_v7();
        let mut tx = db.tenant_tx(mine).await.expect("tenant tx");
        consolidate_belief(&mut tx, &belief(lena, belief_id), &episodes)
            .await
            .expect("consolidate");
        save_expectation(
            &mut tx,
            &Expectation {
                employee_id: lena,
                counterparty: SUPPLIER.to_owned(),
                dimension: "lead_time".to_owned(),
                expectation: -0.6,
                surprise_mean: 0.4,
                surprise_var: 0.09,
                observations: 3,
                updated_at: at(T0 + 3),
            },
        )
        .await
        .expect("save expectation");
        tx.commit().await.expect("commit");

        // Ours is there.
        let mut tx = db.tenant_tx(mine).await.expect("tenant tx");
        assert_eq!(
            episodes_about(&mut tx, lena, SUPPLIER, 10)
                .await
                .expect("episodes")
                .len(),
            3
        );
        assert!(
            trust_for(&mut tx, lena, SUPPLIER)
                .await
                .expect("trust")
                .is_some()
        );
        assert_eq!(
            beliefs_about(&mut tx, lena, SUPPLIER)
                .await
                .expect("beliefs")
                .len(),
            1
        );
        assert_eq!(
            expectations_about(&mut tx, lena, SUPPLIER)
                .await
                .expect("expectations")
                .len(),
            1
        );
        tx.rollback().await.expect("rollback");

        // The neighbour, using the same API and the same ids, sees nothing —
        // and an unfiltered count over each table is zero.
        let mut tx = db.tenant_tx(theirs).await.expect("tenant tx");
        assert!(
            episodes_about(&mut tx, lena, SUPPLIER, 10)
                .await
                .expect("episodes")
                .is_empty()
        );
        assert!(
            trust_for(&mut tx, lena, SUPPLIER)
                .await
                .expect("trust")
                .is_none()
        );
        assert!(
            beliefs_about(&mut tx, lena, SUPPLIER)
                .await
                .expect("beliefs")
                .is_empty()
        );
        assert!(
            expectations_about(&mut tx, lena, SUPPLIER)
                .await
                .expect("expectations")
                .is_empty()
        );
        for table in [
            "psyche_episodes",
            "psyche_trust",
            "psyche_beliefs",
            "psyche_belief_episodes",
            "psyche_expectations",
        ] {
            let visible: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                    .fetch_one(&mut **tx)
                    .await
                    .expect("count");
            assert_eq!(visible, 0, "{table} leaked rows across tenants");
        }
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, mine).await;
        drop_tenant(&db, theirs).await;
    }

    /// The point of the whole unit: two colleagues, one supplier, two different
    /// relationships. Lena has been burned; Alex has not, and must not inherit
    /// her caution as though it were a company fact.
    #[tokio::test]
    async fn two_employees_hold_independent_views_of_the_same_supplier() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = new_employee(&db, tenant, "lena").await;
        let alex = new_employee(&db, tenant, "alex").await;

        let lena_episodes = seed_relationship(&db, tenant, lena, 0.15).await;

        // Alex has one good dealing and nothing else.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let mut good = episode(alex, 10, 1);
        good.kind = "commitment_kept".to_owned();
        good.surprise = Some(0.4);
        let good_id = good.id;
        record_episode(&mut tx, &good).await.expect("record");
        save_trust(
            &mut tx,
            &TrustLink {
                employee_id: alex,
                counterparty: SUPPLIER.to_owned(),
                trust: 0.62,
                prior_trust: 0.5,
                evidence_count: 1,
                last_evidence_episode_id: Some(good_id),
                broken_at: None,
                broken_experienced: None,
                last_heard_from_at: Some(at(T0 + 10)),
                awaiting_reply_since: None,
                updated_at: at(T0 + 10),
            },
        )
        .await
        .expect("save trust");
        // ...and Lena consolidated a belief Alex has no reason to hold.
        consolidate_belief(&mut tx, &belief(lena, Uuid::now_v7()), &lena_episodes)
            .await
            .expect("consolidate");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let hers = trust_for(&mut tx, lena, SUPPLIER)
            .await
            .expect("lena trust")
            .expect("present");
        let his = trust_for(&mut tx, alex, SUPPLIER)
            .await
            .expect("alex trust")
            .expect("present");
        assert!(
            hers.trust < 0.2 && his.trust > 0.6,
            "same supplier, same tenant, one opinion: {} vs {}",
            hers.trust,
            his.trust
        );
        assert_eq!(hers.evidence_count, 3);
        assert_eq!(his.evidence_count, 1);

        // Beliefs and episodes are hers alone.
        assert_eq!(
            beliefs_about(&mut tx, lena, SUPPLIER).await.unwrap().len(),
            1
        );
        assert!(
            beliefs_about(&mut tx, alex, SUPPLIER)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            episodes_about(&mut tx, lena, SUPPLIER, 10)
                .await
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            episodes_about(&mut tx, alex, SUPPLIER, 10)
                .await
                .unwrap()
                .len(),
            1
        );

        // And the observation round-trips exactly, money included.
        let latest = &episodes_about(&mut tx, alex, SUPPLIER, 1).await.unwrap()[0];
        assert_eq!(latest.id, good_id);
        assert_eq!(
            latest.amount,
            Some(Money::from_major(14_200, Currency::Usd).unwrap())
        );
        assert_eq!(latest.detail["actual_days"], serde_json::json!(23));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// A belief whose founding episodes can be rewritten is a rumour with a
    /// timestamp. Both the privilege and the trigger are checked, because
    /// either one alone can be undone by a later migration.
    #[tokio::test]
    async fn an_episode_cannot_be_updated_or_deleted() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = new_employee(&db, tenant, "lena").await;
        let episodes = seed_relationship(&db, tenant, lena, 0.2).await;

        // Even as the connecting superuser, and even in a transaction that is
        // thrown away afterwards.
        for op in [
            "UPDATE psyche_episodes SET polarity = 1 WHERE id = $1",
            "DELETE FROM psyche_episodes WHERE id = $1",
        ] {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let err = sqlx::query(op)
                .bind(episodes[0])
                .execute(&mut *tx)
                .await
                .expect_err("psyche_episodes must be append-only");
            assert!(
                err.to_string().contains("append-only"),
                "expected the append-only trigger for `{op}`, got: {err}"
            );
            tx.rollback().await.expect("rollback");
        }

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        for verb in ["UPDATE", "DELETE"] {
            let granted: bool =
                sqlx::query_scalar("SELECT has_table_privilege('app_role', 'psyche_episodes', $1)")
                    .bind(verb)
                    .fetch_one(&mut *tx)
                    .await
                    .expect("privilege check");
            assert!(!granted, "app_role must not hold {verb} on psyche_episodes");
        }
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// Three ways to write a conviction nothing supports, all refused.
    #[tokio::test]
    async fn a_belief_cannot_be_written_without_its_episodes() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = new_employee(&db, tenant, "lena").await;
        let alex = new_employee(&db, tenant, "alex").await;
        let episodes = seed_relationship(&db, tenant, lena, 0.2).await;

        // 1. Citing nothing at all.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert!(matches!(
            consolidate_belief(&mut tx, &belief(lena, Uuid::now_v7()), &[]).await,
            Err(StoreError::NotFound)
        ));
        // 2. Citing a colleague's evidence. Lena saw it; Alex did not.
        assert!(matches!(
            consolidate_belief(&mut tx, &belief(alex, Uuid::now_v7()), &episodes).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");

        // 3. Going around this module entirely: a bare INSERT with no
        //    genealogy. The deferred trigger fires at COMMIT, so the whole
        //    transaction is lost rather than the belief surviving alone.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO psyche_beliefs \
               (id, tenant_id, employee_id, counterparty, topic, polarity, strength, \
                formed_at, refreshed_at, from_experience) \
             VALUES ($1, $2, $3, $4, 'fabricated', -1, 1.0, $5, $5, true)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(lena.as_uuid())
        .bind(SUPPLIER)
        .bind(at(T0))
        .execute(&mut **tx)
        .await
        .expect("the INSERT itself is allowed; the commit is not");
        let err = tx
            .commit()
            .await
            .expect_err("an unsupported belief must not commit");
        assert!(
            err.to_string().contains("no founding episodes"),
            "expected the evidence trigger, got: {err}"
        );

        // 4. ...and the genealogy cannot be deleted out from under a belief
        //    that survives.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let real = belief(lena, Uuid::now_v7());
        consolidate_belief(&mut tx, &real, &episodes)
            .await
            .expect("consolidate");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let stored = &beliefs_about(&mut tx, lena, SUPPLIER).await.unwrap()[0];
        assert_eq!(stored.founding_episodes.len(), 3);
        let mut sorted = episodes.clone();
        sorted.sort();
        assert_eq!(
            stored.founding_episodes, sorted,
            "genealogy must be complete"
        );
        sqlx::query("DELETE FROM psyche_belief_episodes WHERE belief_id = $1")
            .bind(stored.belief.id)
            .execute(&mut **tx)
            .await
            .expect("delete is allowed; the commit is not");
        let err = tx
            .commit()
            .await
            .expect_err("stripping a live belief's evidence must not commit");
        assert!(
            err.to_string().contains("no founding episodes"),
            "expected the evidence trigger, got: {err}"
        );

        // 5. And a trust value off its prior with no evidence behind it.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = save_trust(
            &mut tx,
            &TrustLink {
                employee_id: alex,
                counterparty: SUPPLIER.to_owned(),
                trust: 0.05,
                prior_trust: 0.5,
                evidence_count: 0,
                last_evidence_episode_id: None,
                broken_at: None,
                broken_experienced: None,
                last_heard_from_at: None,
                awaiting_reply_since: None,
                updated_at: at(T0),
            },
        )
        .await
        .expect_err("unsupported trust must not be writable");
        assert!(
            err.to_string().contains("psyche_trust_needs_evidence"),
            "expected the evidence CHECK, got: {err}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// The chase list. A supplier we are waiting on since before the deadline is
    /// found; one that answered, and one nobody is waiting on, are not.
    #[tokio::test]
    async fn the_quiet_counterparty_query_finds_a_stalled_relationship() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = new_employee(&db, tenant, "lena").await;
        let alex = new_employee(&db, tenant, "alex").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        // stalled: asked 9 days ago, silence. answered: asked, then replied.
        // patient: asked 1 day ago, not yet late.
        for (name, awaiting) in [
            ("stalled-forge", Some(at(T0 - 9 * DAY))),
            ("answered-mill", None),
            ("patient-press", Some(at(T0 - DAY))),
        ] {
            save_trust(
                &mut tx,
                &TrustLink {
                    employee_id: lena,
                    counterparty: name.to_owned(),
                    trust: 0.5,
                    prior_trust: 0.5,
                    evidence_count: 0,
                    last_evidence_episode_id: None,
                    broken_at: None,
                    broken_experienced: None,
                    last_heard_from_at: Some(at(T0 - 30 * DAY)),
                    awaiting_reply_since: awaiting,
                    updated_at: at(T0),
                },
            )
            .await
            .expect("save trust");
        }
        // Alex is waiting on the same supplier, and it is his problem, not hers.
        save_trust(
            &mut tx,
            &TrustLink {
                employee_id: alex,
                counterparty: "stalled-forge".to_owned(),
                trust: 0.5,
                prior_trust: 0.5,
                evidence_count: 0,
                last_evidence_episode_id: None,
                broken_at: None,
                broken_experienced: None,
                last_heard_from_at: None,
                awaiting_reply_since: Some(at(T0 - 40 * DAY)),
                updated_at: at(T0),
            },
        )
        .await
        .expect("save trust");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let quiet = gone_quiet(&mut tx, lena, at(T0 - 7 * DAY))
            .await
            .expect("gone quiet");
        assert_eq!(
            quiet
                .iter()
                .map(|q| q.counterparty.as_str())
                .collect::<Vec<_>>(),
            vec!["stalled-forge"],
            "only the relationship past the deadline is stalled"
        );
        assert_eq!(quiet[0].awaiting_reply_since, at(T0 - 9 * DAY));
        assert_eq!(quiet[0].last_heard_from_at, Some(at(T0 - 30 * DAY)));

        // A later deadline sweeps up the one that is merely recent, oldest wait
        // first — the order a chase list is worked in, and stable across runs.
        let quiet = gone_quiet(&mut tx, lena, at(T0)).await.expect("gone quiet");
        assert_eq!(
            quiet
                .iter()
                .map(|q| q.counterparty.as_str())
                .collect::<Vec<_>>(),
            vec!["stalled-forge", "patient-press"]
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// Welford's counter is the evidence rule for expectations: with nothing
    /// observed, the row is the null prior and nothing else.
    #[tokio::test]
    async fn an_expectation_nobody_has_tested_cannot_hold_a_value() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = new_employee(&db, tenant, "lena").await;

        let untested = Expectation {
            employee_id: lena,
            counterparty: SUPPLIER.to_owned(),
            dimension: "price".to_owned(),
            expectation: -0.8,
            surprise_mean: 0.0,
            surprise_var: 0.0,
            observations: 0,
            updated_at: at(T0),
        };

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = save_expectation(&mut tx, &untested)
            .await
            .expect_err("an untested expectation must not be writable");
        assert!(
            err.to_string()
                .contains("psyche_expectations_needs_observations"),
            "expected the observations CHECK, got: {err}"
        );
        tx.rollback().await.expect("rollback");

        // The same numbers, once three observations stand behind them.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        save_expectation(
            &mut tx,
            &Expectation {
                observations: 3,
                surprise_mean: 0.42,
                surprise_var: 0.09,
                ..untested
            },
        )
        .await
        .expect("supported expectation");
        let stored = expectations_about(&mut tx, lena, SUPPLIER)
            .await
            .expect("read back");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].observations, 3);
        assert_eq!(stored[0].surprise_var, 0.09);
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }
}
