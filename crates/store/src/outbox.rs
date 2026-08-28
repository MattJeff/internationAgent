//! The transactional outbox. This is the message bus.
//!
//! There is no broker. An event is a row written by the same `COMMIT` that
//! wrote the state change it describes, and the transport is
//! `FOR UPDATE SKIP LOCKED` — which is why [`enqueue`] takes a [`TenantTx`]
//! rather than a [`Db`](crate::db::Db). You cannot enqueue outside a
//! transaction, so "we updated the row but the notification never went out" is
//! not a failure mode that exists here.
//!
//! # The loop
//!
//! ```text
//! business tx:  UPDATE employees ... ; enqueue(...) ; COMMIT
//! poller tx:    claim(limit) ; COMMIT          <- short, just takes the work
//!    handler:   ...do the side effect...
//! poller tx:    mark_done | mark_failed ; COMMIT
//! ```
//!
//! [`claim`] deliberately commits before the handler runs. `SKIP LOCKED` only
//! excludes other pollers for as long as the claiming transaction is open, so
//! it alone would let a second poller grab the row the instant the first one
//! commits. What actually keeps the row to one worker is that the same `UPDATE`
//! that claims it also pushes `available_at` into the future — so a claim is a
//! lease with a deadline, and a poller that dies mid-handler loses the row back
//! to the pool automatically once the backoff expires. No liveness protocol, no
//! heartbeat, no reaper.
//!
//! # Two things the schema does not have, and how they work anyway
//!
//! `0001_core.sql` is owned by another unit and is checksummed by sqlx once
//! applied, so this module works with the columns that exist:
//!
//! * **Dedupe.** There is no `dedupe_key` column to put a
//!   `UNIQUE (aggregate_type, aggregate_id, event_type, dedupe_key)` on. But
//!   there is already a unique index on `id` — the primary key — so when a
//!   caller supplies a dedupe key the id *is* the dedupe tuple, hashed:
//!   `md5(tenant : aggregate_type : aggregate_id : event_type : dedupe_key)`.
//!   A retried business transaction computes the same id and collides with
//!   itself, and `ON CONFLICT` turns that into a no-op. Same guarantee, same
//!   index, zero DDL.
//!
//! * **Dead-lettering.** There is no `dead_lettered_at` column either, and it
//!   would be redundant: [`claim`] only ever selects rows with
//!   `attempt_count < MAX_ATTEMPTS`, so exhausting the attempts *is* the
//!   dead-letter state. Nothing has to move the row anywhere. [`dead_letters`]
//!   is the same predicate read back for whoever is on call.
//!
//! # Nothing deletes a row, and only one of the two piles costs anything
//!
//! There is no prune, no sweep, no `pg_cron`, and no `DELETE FROM
//! outbox_events` outside test fixtures. A row lives as long as its tenant does.
//! Two populations grow without a ceiling, and they are not the same problem:
//!
//! * **Published rows.** Both partial indexes are predicated on
//!   `published_at IS NULL`, so a published row leaves them the moment
//!   [`mark_done`] commits — the heap keeps it, no reader looks. Measured
//!   on PostgreSQL 17: **500 000 published rows, 94 MB, and neither [`claim_of`]
//!   nor `loops::outbox::lag_secs` moves at all** — 0.7 ms and 0.2 ms, the same
//!   as an empty table. This pile is disk and nothing else, and disk is the
//!   cheapest thing in this system. **It is not a defect and it is not urgent.**
//!
//! * **Parked rows** — [`park`], or eight failed attempts. `published_at` stays
//!   NULL, so they stay *in* the index, and nothing moves `available_at`, so
//!   they sort at the head of their tenant's range and every claim walked past
//!   every one of them. That one was real, it was the same shape `0046` exists
//!   to prevent — one customer's rows becoming every customer's latency — and
//!   `migrations/0057_outbox_claimable.sql` has the numbers and the fix.
//!
//! ## FOUNDER'S QUESTION, LEFT OPEN: how long may a published row be deleted?
//!
//! Not asked here because nothing needs the answer yet — the measurement above
//! is why this file has no retention constant to be wrong about. If disk ever
//! becomes the reason, the number is **not** an engineering choice, and the
//! constraint that decides it is [`enqueue`]'s:
//!
//! > the id of a deduped event is `md5(tenant : aggregate : type : dedupe_key)`,
//! > so the row *is* the dedupe record. Delete it and a re-delivery of the same
//! > event inserts a fresh row and the side effect happens a second time.
//!
//! So the retention floor is **how long a provider may re-deliver**, and every
//! provider that reaches this table has its own answer:
//! `routes::webhooks` keys on `<provider>:<delivery id>`, and
//! `apps/server/src/routes/halt.rs` is already holding an unanswered question
//! about Resend's retention for the same reason. One number, two decisions.
//! Until somebody has it, deleting a published row is trading a duplicate side
//! effect — a second email to a customer, a second model call on their key —
//! for disk. `audit_log` keeps the history either way; it is append-only, has no
//! foreign key to `tenants`, and is not what this table is for.
//!
//! Whoever eventually runs it is *not* a loop in `apps/server/src/loops/`. A
//! sweep by age reads no policy and takes nothing from anybody, so putting it
//! behind the emergency stop and the operating window would only raise the
//! question of whether a stopped company's disk keeps growing — a question
//! nobody has to answer if the sweep never asks. A migration cannot do it
//! either; it runs once. That leaves `pg_cron` or a cron'd `psql`, which is
//! where a `DELETE ... WHERE published_at < now() - <the number>` belongs the
//! day the number exists.
//!
//! Parked rows are a different question and the answer is already no: a dead
//! letter is an effect that was supposed to happen and did not, and
//! [`requeue_dead_letters`] is the way back. Deleting one destroys the only
//! record that anything is owed. It leaves the *index* now, not the table.
//!
//! # Clocks
//!
//! Every function takes `now`. Nothing here calls `now()` in SQL or
//! `Utc::now()` in Rust, so the backoff schedule is testable by advancing an
//! argument instead of sleeping through it.

use agentos_domain::ids::TenantId;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row, postgres::PgRow};
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

/// How many times a single event may be handed to a handler before it stops
/// being retried and becomes a dead letter.
///
/// With the schedule in [`claim`] the eighth attempt lands roughly two hours
/// after the first, which is long enough to ride out a provider outage and
/// short enough that a genuinely poisoned event reaches a human the same day.
/// `migrations/0057_outbox_claimable.sql` spells this number a second time, in
/// the predicate of the index [`claim_of`] reads, and an applied migration is
/// immutable — so raising it needs a new migration too. Nothing goes *wrong* if
/// somebody forgets: the claim keeps returning the right rows, it just stops
/// being able to use the index and walks every dead letter in the deployment
/// again. `a_tenants_dead_letters_are_not_scanned_by_every_claim` is what turns
/// that back into a failure somebody sees.
///
/// **Two statements read that index, not one.** `apps/server`'s
/// `loops::outbox::lag_secs` binds this same constant against the same
/// predicate, so forgetting the migration costs `/readyz` a sequential scan on
/// every probe of every replica as well — measured, and guarded by
/// `dead_letters_do_not_cost_the_readiness_probe` beside it.
pub const MAX_ATTEMPTS: i32 = 8;

/// The floor under a claim's `available_at`, in seconds: how long a claimed
/// event is guaranteed to stay off the queue before any other poller may take
/// it.
///
/// # The bug it closes
///
/// The backoff *is* the lease — see [`claim`] — and on the first attempt the
/// backoff was `2^0 = 1` second times a jitter factor in `[0.5, 1.5)`: between
/// half a second and a second and a half. One of the rows in this table is a
/// requested agent turn, and `apps/server`'s `TURN_DEADLINE` gives a turn **120
/// seconds**. So a second replica reclaimed the row about a second into a
/// two-minute turn and took the same turn again: two model calls billed to the
/// customer's own key for one event, with nothing failed, nothing denied and no
/// row out of place. The only trace is the bill. This is not hypothetical
/// either — [`POLLER_HEADROOM`] sizes this very query for four replicas.
///
/// # Added to the backoff, not `greatest`-ed with it
///
/// `greatest(120s, 2^n)` is the obvious spelling and it deletes the schedule it
/// is protecting. [`MAX_ATTEMPTS`] is 8, so the largest exponential term an
/// event ever reaches is `2^7 = 128` seconds: seven of the eight attempts would
/// land on *exactly* 120, with no growth and — worse — **no jitter**, which is
/// the property that stops a thousand events queued by one provider outage from
/// coming back as one herd. Adding keeps every property the schedule had. Still
/// jittered, still doubling, still capped (now at `120s + 1h`), and never
/// shorter than the work it protects.
///
/// # One number for every event type, deliberately
///
/// The outbox also carries mail, webhooks and provisioning, whose handlers are
/// nowhere near two minutes, and a lease per event type would let each of them
/// retry sooner. It would also have to be *updated by whoever adds the next
/// event type*, and the failure of forgetting is silent: it is this exact
/// double-charge, back again, on the row nobody thought about. A single global
/// floor cannot be forgotten. What it costs is that every retry of every kind is
/// two minutes later than it was, and that eight attempts now take about twenty
/// minutes rather than four — which this table wanted anyway; see
/// [`requeue_dead_letters`] on how little four minutes is worth to a tenant who
/// is still pasting in an API key.
///
// ponytail: the ceiling is a poller holding many leases at once.
// `apps/server/src/loops/outbox.rs` claims a batch of 32 and runs one tenant's
// events one after another, so a tenant that fills a batch alone can still have
// its last event's lease expire while its first event is running. The upgrade is
// to make this an argument each poller sizes from its own batch shape rather
// than a constant; it is the same double-run one order of magnitude rarer, and
// a floor that covers the common case is not the place to solve it.
pub const LEASE_SECS: i64 = 120;

/// The key the W3C `traceparent` is carried under inside `payload`.
///
/// It rides in the payload rather than in a column of its own so that it
/// survives every hop without the schema having to know about tracing.
pub const TRACEPARENT_KEY: &str = "traceparent";

/// An event about to be written, before it has an id or a tenant.
///
/// Fields are public and there is no builder: this is a bag of arguments that
/// crosses exactly one function boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent {
    /// The kind of thing the event is about (`employee`, `approval`, ...).
    pub aggregate_type: String,
    /// The id of that thing.
    pub aggregate_id: Uuid,
    /// What happened (`employee.provisioned`, `approval.granted`, ...).
    pub event_type: String,
    /// Makes [`enqueue`] idempotent. `Some(k)` means "this event, for this
    /// aggregate, for this reason, at most once" — a business transaction that
    /// is retried after a serialization failure enqueues once in total.
    ///
    /// `None` means every call inserts a new row, which is what you want for
    /// genuinely repeatable events (a nightly digest, a manual resend).
    pub dedupe_key: Option<String>,
    /// The body. Should be a JSON object; anything else still works but gets
    /// wrapped when a traceparent has to be attached.
    pub payload: Value,
    /// W3C `traceparent` of the transaction that produced the event, so the
    /// asynchronous handler continues the caller's trace rather than starting
    /// an orphan one.
    pub traceparent: Option<String>,
}

impl NewEvent {
    /// An event with an empty payload, no dedupe key and no trace context.
    /// Set the remaining fields directly.
    pub fn new(
        aggregate_type: impl Into<String>,
        aggregate_id: Uuid,
        event_type: impl Into<String>,
    ) -> Self {
        Self {
            aggregate_type: aggregate_type.into(),
            aggregate_id,
            event_type: event_type.into(),
            dedupe_key: None,
            payload: json!({}),
            traceparent: None,
        }
    }

    /// The payload as it will be stored: the caller's body with the
    /// traceparent folded in.
    fn stored_payload(&self) -> Value {
        let Some(traceparent) = &self.traceparent else {
            return self.payload.clone();
        };
        let mut payload = self.payload.clone();
        match payload.as_object_mut() {
            Some(map) => {
                map.insert(TRACEPARENT_KEY.to_owned(), json!(traceparent));
                payload
            }
            // A non-object payload has nowhere to put a key. Losing the trace
            // context is worse than nesting the body one level.
            None => json!({ TRACEPARENT_KEY: traceparent, "data": payload }),
        }
    }
}

/// A claimed event, ready to be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEvent {
    /// Primary key. Pass it to [`mark_done`] / [`mark_failed`].
    pub id: Uuid,
    /// Which tenant the effect belongs to. The poller is cross-tenant, so the
    /// handler has to re-scope itself with this before touching anything else.
    pub tenant_id: TenantId,
    /// The kind of thing the event is about.
    pub aggregate_type: String,
    /// The id of that thing.
    pub aggregate_id: Uuid,
    /// What happened.
    pub event_type: String,
    /// The body, including [`TRACEPARENT_KEY`] if one was supplied.
    pub payload: Value,
    /// How many times this event has been claimed, including this claim. Starts
    /// at 1.
    pub attempt_count: i32,
    /// When this claim's lease expires and the event becomes claimable again.
    pub available_at: DateTime<Utc>,
    /// Whatever the last failed handler reported.
    pub last_error: Option<String>,
}

impl OutboxEvent {
    fn from_row(row: &PgRow) -> Self {
        Self {
            id: row.get("id"),
            tenant_id: TenantId::from_uuid(row.get("tenant_id")),
            aggregate_type: row.get("aggregate_type"),
            aggregate_id: row.get("aggregate_id"),
            event_type: row.get("event_type"),
            payload: row.get("payload"),
            attempt_count: row.get("attempt_count"),
            available_at: row.get("available_at"),
            last_error: row.get("last_error"),
        }
    }

    /// The W3C `traceparent` this event was enqueued with, if any. Set it as
    /// the parent context before handling so the async work joins the trace
    /// that caused it.
    pub fn traceparent(&self) -> Option<&str> {
        self.payload.get(TRACEPARENT_KEY)?.as_str()
    }

    /// True once this event has burned through [`MAX_ATTEMPTS`] and will never
    /// be claimed again.
    pub fn is_dead_lettered(&self) -> bool {
        self.attempt_count >= MAX_ATTEMPTS
    }
}

/// Write an event **inside the business transaction that caused it**.
///
/// The tenant comes from the transaction, not from the caller, so an event
/// cannot be filed against the wrong one.
///
/// Returns the id of the event that is now in the table — which, when
/// `dedupe_key` is set and the same event was already enqueued, is the id of
/// the *original* row. Enqueueing twice is a no-op that reports success,
/// because the caller's question is "is this event queued", not "did I insert
/// it".
pub async fn enqueue(
    tx: &mut TenantTx<'_>,
    event: &NewEvent,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    let tenant_id = tx.tenant_id();

    // When a dedupe key is present the id is derived from the dedupe tuple, so
    // the primary key does the deduplicating. `md5(text)::uuid` is exact — 32
    // hex characters is precisely a uuid — and the tenant is part of the input,
    // so two tenants can never collide with each other.
    //
    // ON CONFLICT DO UPDATE, not DO NOTHING: DO NOTHING returns no row, and we
    // need to give the caller the winning id. Setting the id to itself is the
    // cheapest legal no-op update.
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO outbox_events \
             (id, tenant_id, aggregate_type, aggregate_id, event_type, payload, \
              created_at, available_at) \
         VALUES ( \
             CASE WHEN $7::text IS NULL THEN $1::uuid \
                  ELSE md5($2::uuid::text || ':' || $3::text || ':' || $4::uuid::text \
                           || ':' || $5::text || ':' || $7::text)::uuid \
             END, \
             $2::uuid, $3::text, $4::uuid, $5::text, $6::jsonb, \
             $8::timestamptz, $8::timestamptz) \
         ON CONFLICT (id) DO UPDATE SET id = outbox_events.id \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id.as_uuid())
    .bind(&event.aggregate_type)
    .bind(event.aggregate_id)
    .bind(&event.event_type)
    .bind(event.stored_payload())
    .bind(event.dedupe_key.as_deref())
    .bind(now)
    .fetch_one(&mut ***tx)
    .await?;

    Ok(id)
}

/// Take up to `limit` due events, across every tenant.
///
/// Runs on a connection from
/// [`admin_tx_bypassing_rls`](crate::db::Db::admin_tx_bypassing_rls) — draining
/// every tenant's effects is the poller's entire job, and RLS would hide all of
/// them. Pass `&mut *tx`.
///
/// One statement does three things, and it has to be one statement:
///
/// * `FOR UPDATE SKIP LOCKED` — concurrent pollers step over each other's
///   in-flight rows instead of blocking on them, so adding a poller adds
///   throughput rather than contention.
/// * `attempt_count + 1` — counted at claim time, not at failure time, so a
///   worker that is *killed* mid-handler still burns an attempt. Counting on
///   failure would let a poison event that segfaults the handler retry forever.
/// * `available_at` pushed out by [`LEASE_SECS`] **plus** an exponential
///   backoff with jitter — the lease. `2^attempt` seconds, capped at an hour,
///   multiplied by a random factor in `[0.5, 1.5)` so that a thousand events
///   queued by one outage do not come back in a thundering herd, all of it on
///   top of a floor long enough to outlast the longest handler this table
///   feeds. [`LEASE_SECS`] argues why the two terms are added rather than
///   `greatest`-ed.
///
/// Rows that have reached [`MAX_ATTEMPTS`] are not selected. See
/// [`dead_letters`].
///
// ponytail: the table's `lease_owner` / `lease_until` columns stay NULL.
// `available_at` already *is* the lease and it expires on its own, so a second
// copy of the same fact could only ever disagree with it. Populate them if a
// dashboard ever needs to name which worker holds a row — nothing here reads
// them.
pub async fn claim(
    conn: &mut PgConnection,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<OutboxEvent>, StoreError> {
    claim_of(conn, Aggregates::All, limit, now).await
}

/// [`claim`], minus one aggregate type.
///
/// This exists because a second poller exists. `outbox_events` is shared by
/// every kind of asynchronous work, but not every kind is drained by the same
/// loop: inbound webhook notices have their own poller with its own batch size,
/// because one of them is two provider round trips and thirty-two of them is a
/// minute. That poller filters its claim on `aggregate_type`; **this one has to
/// filter too, or the two are not disjoint** — the general poller would claim a
/// notice, find no handler registered for it, and burn one of its eight
/// attempts. Eight polls later a customer's email is a dead letter that nobody
/// asked for.
///
/// `None` claims everything, which is what a deployment running a single poller
/// wants.
///
/// # A stopped company's rows are not claimed at all
///
/// Both spellings skip any tenant that is stopped — a row in `company_halts`,
/// or a `company_windows` row whose `ends_at` has passed, which is the same
/// refusal by the same argument (`migrations/0054_operating_window.sql`). The
/// **not** in "not claimed" is the whole point: a deferred row burns no
/// attempt, so a halt costs the customer nothing. Refusing the work inside the
/// handler instead would look identical for four minutes and then destroy
/// everything — `attempt_count` is incremented *at claim time*, the backoff is
/// `2^n` seconds, and eight of those is about five minutes. Any halt longer
/// than a coffee break would dead-letter every turn the company had pending,
/// and the release would come back to an empty queue and a customer's
/// unanswered mail in `dead_letters`. That is the exact failure this function's
/// own doc-comment above already describes for the notice poller, arriving by a
/// second road.
///
/// So the rows wait, in order, and the release makes them all due at once. This
/// is also what stops the one un-gated real-world effect the drain performs —
/// `employee.terminated`, whose handler cancels mailboxes and phone numbers at
/// the providers with no [`crate::audit`] decision behind it — from running
/// while a company is stopped. `PolicyGate` cannot refuse that one, because it
/// never asks it.
///
/// The poller connects as the owning role and drains every tenant by
/// definition, so this reads across tenants exactly as the surrounding query
/// does. The correlated `tenant_id` is what keeps one company's halt to one
/// company's rows.
pub async fn claim_except(
    conn: &mut PgConnection,
    skip_aggregate: Option<&str>,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<OutboxEvent>, StoreError> {
    let filter = skip_aggregate.map_or(Aggregates::All, Aggregates::Except);
    claim_of(conn, filter, limit, now).await
}

/// Which aggregate types a poller is willing to take.
///
/// Two pollers share `outbox_events` and neither may take the other's rows —
/// see [`claim_except`] for what a stolen row costs. The enum rather than two
/// `Option<&str>` arguments because `Only` and `Except` are the two halves of
/// one partition and a caller that passes both has written a bug the type can
/// refuse.
#[derive(Debug, Clone, Copy)]
pub enum Aggregates<'a> {
    /// Everything. A deployment running one poller.
    All,
    /// Everything but this aggregate type — the general poller.
    Except(&'a str),
    /// Only this aggregate type — a specialised poller.
    Only(&'a str),
}

/// How many batches' worth of one tenant's queue the claim looks at.
///
/// Fairness needs at most `limit` rows per tenant: one claim never returns more
/// than that, so a deeper look could not change who gets a seat. What the extra
/// depth buys is **concurrent pollers**. Two replicas claiming at the same
/// instant against one busy tenant both want a full batch out of the same rows,
/// and `SKIP LOCKED` can only step over the first poller's locks onto rows the
/// candidate set actually contains. At 1 the second replica would come back
/// empty — a throughput cliff that appears the day someone adds a pod.
///
/// [`crate::initiative::claim_due`] is the same query shape over
/// `employee_initiative` and reads this rather than declaring a second four:
/// the number answers "how many replicas may fill a batch from one tenant", and
/// a deployment does not run two different counts of itself.
///
/// ponytail: four, so four replicas can each fill a batch from a single tenant
/// before the fifth comes back short. The ceiling is real and it is a *rate*
/// limit, not a correctness one — nothing is lost, the next tick takes it. The
/// upgrade, if a deployment ever runs more pollers than this, is to raise the
/// number; it costs one index range scan of `limit` more rows per tenant per
/// tick, against an index that exists for exactly this scan.
pub(crate) const POLLER_HEADROOM: i64 = 4;

/// [`claim`], restricted to one side of the aggregate partition.
///
/// # Round-robin, and why FIFO was the wrong queue discipline
///
/// `outbox_events` is one queue for every tenant, and the claim used to order it
/// `available_at, id` across all of them. Nothing leaks that way and no lock is
/// held — and a customer's employees still stop working because another customer
/// is busy. There is no bound on what one tenant may enqueue, this drains 32 at
/// a time, and `apps/server`'s handlers run one after another with a turn
/// costing up to `TURN_DEADLINE`. One prospect import is measured in hours of
/// other people's latency, and it shows up as nothing at all: no error, no
/// denial, no row out of place. At this product's price that is the same size of
/// failure as a leak, and it is the one no test in the workspace was making —
/// every isolation test here proves a *table* hides.
///
/// So: **every tenant is offered a seat before any tenant is offered a second
/// one.** `tenants` drives the selection, one `LATERAL` per tenant takes that
/// tenant's oldest due rows, `row_number()` numbers the seats within a tenant,
/// and the outer order is seat-first. A tenant with nothing due contributes
/// nothing and costs one index probe. A tenant alone on the deployment still
/// fills the whole batch — round-robin is not equal shares of a queue nobody
/// else is using.
///
/// The lateral is capped, so the scan is `tenants × limit × POLLER_HEADROOM`
/// index entries at worst and not the whole backlog. `0046_outbox_fair_claim`
/// is the index it reads, and argues why it is a second one rather than a
/// widened `outbox_events_due_idx`.
///
/// # `shortlist`, and why the lock is not taken in the lateral
///
/// Two spellings were measured against 100 000 due rows across 52 tenants,
/// because both are correct and one of them is expensive in a way the plan does
/// not advertise:
///
/// * `FOR UPDATE SKIP LOCKED` **inside the lateral** needs no shortlist at all
///   and no headroom — the skip happens per tenant, so a second poller reads
///   deeper into the index by itself. It also takes a row lock on every
///   candidate: `tenants × limit` tuple writes to claim `limit` rows, which at
///   fifty busy tenants is a fiftyfold write amplification on the hottest
///   statement in the system.
/// * Locking **once, over a shortlist**, takes exactly `limit` locks. Without
///   the shortlist the planner joins 6 400 candidates to the table and picks a
///   hash join over a **sequential scan of the whole queue** — the one plan
///   this change must not produce. Cutting the candidates down to
///   `limit × POLLER_HEADROOM` first turns that into a nested loop on the
///   primary key.
///
/// The second, therefore. Measured: index scans throughout, 32 rows locked,
/// ~7 ms against that backlog, and no plan node that grows with the queue.
///
/// # The rest of the statement, unchanged and still load-bearing
///
/// * `FOR UPDATE SKIP LOCKED` — concurrent pollers step over each other's
///   in-flight rows instead of blocking on them. It sits on the `due` CTE
///   rather than on `seated` because PostgreSQL will not lock a select that
///   has a window function in it.
/// * **The due-ness predicate is repeated inside `due`, and deleting it as a
///   duplicate re-opens a double-charge.** `seated` reads `outbox_events`
///   *unlocked*, under the statement's snapshot; `due` is the only node that
///   takes a lock. When a row it reaches has meanwhile been claimed and
///   committed by another poller, `SKIP LOCKED` does not skip it — nothing
///   holds it any more — and PostgreSQL's `READ COMMITTED` recheck
///   (`EvalPlanQual`) walks to the new row version and re-runs *only the quals
///   present under the `LockRows` node*. With the join condition alone, `e.id =
///   c.id` still holds on the new version and the row is claimed a second time,
///   inside a lease that has just been pushed 120 seconds out. Measured, not
///   argued: two sessions, ten due rows, the second session's snapshot taken
///   before the first committed — every one of the first session's five rows
///   came back to the second as well, with `attempt_count = 2`. In
///   `apps/server`'s two-poller test that is 24 of 60 events handled twice, 2.2
///   ms apart, and one of the rows in this table is `agent.turn.requested`: a
///   model call the customer is billed for. Repeating the three columns here
///   makes the recheck evaluate them against the version actually locked, and
///   the second poller reads past to the next rows instead. The `seated` copy
///   still earns its place — it is what the index scan in the lateral uses, and
///   removing it would shortlist the whole table.
/// * `AS MATERIALIZED` on **every** CTE, and it is not a hint. Written the
///   obvious way — `WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED LIMIT $n)` —
///   the subplan can be re-executed per outer row, and each re-execution steps
///   over whichever rows a *concurrent* poller holds locked right then, so the
///   UPDATE touches the union rather than `$n` rows. The rows stay disjoint
///   between pollers, so nothing is handled twice; what breaks is the bound.
///   A poller that claims 16 with a limit of 10 has silently stopped bounding
///   its own batch, which is the only thing standing between one tick and the
///   whole table. A single-session test returns exactly `$n` and proves
///   nothing: the initiative loop's two-poller test caught the same query shape
///   claiming 13, then 16, against a limit of 10.
/// * `attempt_count + 1` — counted at claim time, so a worker that is *killed*
///   mid-handler still burns an attempt.
/// * `available_at` pushed out by [`LEASE_SECS`] plus an exponential backoff
///   with jitter — the lease, which expires by itself. The floor is what makes
///   it a lease rather than a coin toss: without it the first claim held the row
///   for about a second against a handler that may run for two minutes.
pub async fn claim_of(
    conn: &mut PgConnection,
    aggregates: Aggregates<'_>,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<OutboxEvent>, StoreError> {
    let (only, except) = match aggregates {
        Aggregates::All => (None, None),
        Aggregates::Except(kind) => (None, Some(kind)),
        Aggregates::Only(kind) => (Some(kind), None),
    };

    let rows = sqlx::query(CLAIM_SQL)
        .bind(now)
        .bind(MAX_ATTEMPTS)
        .bind(limit)
        .bind(only)
        .bind(except)
        .bind(POLLER_HEADROOM)
        .bind(LEASE_SECS)
        .fetch_all(&mut *conn)
        .await?;

    Ok(rows.iter().map(OutboxEvent::from_row).collect())
}

/// The statement [`claim_of`] runs, lifted out of it so a test can `EXPLAIN` the
/// bytes that actually ship rather than a second copy of them that is free to
/// drift. `claim_of`'s doc comment is the argument for every clause in it.
///
/// The bytes are unchanged by `0057`; what changed is the index underneath the
/// `seated` lateral, which is now `outbox_events_claimable_idx` and no longer
/// contains a dead letter. `a_tenants_dead_letters_are_not_scanned_by_every_claim`
/// is the test this constant exists for.
pub(crate) const CLAIM_SQL: &str = {
    // MATERIALIZED, and it is not a hint. Written the obvious way —
    // `WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED LIMIT $n)` — the
    // subplan can be re-executed per outer row, and each re-execution
    // steps over whichever rows a *concurrent* poller holds locked right
    // then, so the UPDATE touches the union rather than `$n` rows. The
    // rows stay disjoint between pollers, so nothing is handled twice;
    // what breaks is the bound. A poller that claims 16 with a limit of
    // 10 has silently stopped bounding its own batch, which is the only
    // thing standing between one tick and the whole table.
    //
    // A single-session test returns exactly `$n` and proves nothing. The
    // initiative loop's two-poller test caught the same query shape
    // claiming 13, then 16, against a limit of 10.
    // **The halt sits on the driver, not on the rows**, and that is a
    // better place than the one it was written in. `claim_except` used to
    // filter `NOT EXISTS (… company_halts h WHERE h.tenant_id =
    // outbox_events.tenant_id)` per candidate row; here the query is driven
    // by `tenants`, so a stopped company never becomes a seat at all and
    // its rows are never read. Same refusal, one join earlier.
    //
    // It still DEFERS rather than refuses, which is the whole point:
    // `attempt_count` is incremented at claim time (see `claim_of`'s docs
    // below), so a halt that let the poller claim and reject would burn
    // eight attempts and dead-letter every pending piece of the customer's
    // work — an emergency stop destroying exactly what it exists to
    // protect. Not selecting the row costs it nothing.
    //
    // **The second predicate is the same refusal, and it is the one place
    // in the workspace where a window had to be spelled out.** Every other
    // reader of a stop calls `halt::halted`, which reports an exhausted
    // operating window as a halt and needed no edit
    // (`migrations/0054_operating_window.sql` argues why). This query
    // cannot: it is cross-tenant SQL driven by `tenants`, with a clock the
    // caller injects, so it reads the row itself against `$1` rather than
    // the `now()` that function uses. The two must agree, and the cost of
    // them disagreeing is stated exactly by the paragraph above — a company
    // whose month ran out would have every queued piece of its work claimed,
    // refused by the gate, and dead-lettered inside five minutes. A window
    // ending is not a reason to destroy the mail.
    //
    // FOUNDER'S QUESTION, LEFT OPEN: these rows then wait forever, because
    // a window that ended has no release verb the way a halt does. Deferred
    // is the conservative half — nothing is lost and extending the window
    // drains them all — but "what happens to a finished company's queue"
    // is a product decision (drain once? export? expire?) and this file
    // will not invent one.
    //
    // The two clauses are now `crate::not_stopped!`, pasted here at compile
    // time from `crate::halt` — same tokens, same plan, one definition. The
    // paragraph above explains why this query cannot simply call
    // `halt::halted`; the macro is what stops the workaround being copied a
    // fourth time by hand.
    //
    // **`e.attempt_count < $2::int` in the lateral stopped being a filter and
    // became an index predicate**, and that is the whole of
    // `migrations/0057_outbox_claimable.sql`: dead letters are not in
    // `outbox_events_claimable_idx` at all, so the claim no longer walks past
    // every one a tenant ever produced. The clause reads the same; what
    // changed is underneath it.
    //
    // A partial index is only usable when the planner can *prove* the query
    // implies its predicate, and about a parameter it can prove that only from
    // the parameter's value — that is, from a **custom** plan. Measured on
    // PostgreSQL 17 against 200 000 parked rows: eight consecutive executions
    // of the prepared statement at `plan_cache_mode = auto`, all eight custom,
    // all eight on the index, ~1 ms. PostgreSQL never reaches for the generic
    // plan here because it costs so much more — but what "more" means is worth
    // writing down, since nothing in this process would report it: forced
    // generic, the same statement takes **3 141 ms** and removes 200 095 rows
    // by filter *per tenant*. `plan_cache_mode` on this connection is not a
    // tuning knob, it is a cliff.
    concat!(
        "WITH seated AS MATERIALIZED ( \
             SELECT q.id, q.available_at, q.seat \
               FROM tenants t \
               CROSS JOIN LATERAL ( \
                   SELECT top.id, top.available_at, \
                          row_number() OVER (ORDER BY top.available_at, top.id) AS seat \
                     FROM (SELECT e.id, e.available_at \
                             FROM outbox_events e \
                            WHERE e.tenant_id = t.id \
                              AND e.published_at IS NULL \
                              AND e.available_at <= $1::timestamptz \
                              AND e.attempt_count < $2::int \
                              AND ($4::text IS NULL OR e.aggregate_type = $4::text) \
                              AND ($5::text IS NULL OR e.aggregate_type <> $5::text) \
                            ORDER BY e.available_at, e.id \
                            LIMIT $3::bigint * $6::bigint) top \
               ) q \
              WHERE ",
        crate::not_stopped!("t.id"),
        " \
         ), shortlist AS MATERIALIZED ( \
             SELECT id, seat, available_at FROM seated \
              ORDER BY seat, available_at, id \
              LIMIT $3::bigint * $6::bigint \
         ), due AS MATERIALIZED ( \
             SELECT e.id \
               FROM shortlist c JOIN outbox_events e ON e.id = c.id \
              WHERE e.published_at IS NULL \
                AND e.available_at <= $1::timestamptz \
                AND e.attempt_count < $2::int \
              ORDER BY c.seat, c.available_at, c.id \
                FOR UPDATE OF e SKIP LOCKED \
              LIMIT $3::bigint) \
         UPDATE outbox_events AS e \
         SET attempt_count = e.attempt_count + 1, \
             available_at = $1::timestamptz \
                 + interval '1 second' * $7::bigint \
                 + least(interval '1 second' \
                         * power(2::double precision, e.attempt_count::double precision), \
                         interval '1 hour') \
                   * (0.5 + random()) \
         WHERE e.id IN (SELECT id FROM due) \
         RETURNING e.id, e.tenant_id, e.aggregate_type, e.aggregate_id, e.event_type, \
                   e.payload, e.attempt_count, e.available_at, e.last_error",
    )
};

/// The handler succeeded. The event is published and never claimed again.
///
/// `AND published_at IS NULL` makes this safe to call twice only in the sense
/// that the second call reports [`StoreError::NotFound`] rather than silently
/// re-publishing — if you see that, two workers handled the same event and the
/// side effect happened twice.
pub async fn mark_done(
    conn: &mut PgConnection,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let done = sqlx::query(
        "UPDATE outbox_events SET published_at = $2, last_error = NULL \
         WHERE id = $1 AND published_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    if done.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// The handler failed. Record why.
///
/// Nothing is rescheduled here: [`claim`] already set the backoff and already
/// burned the attempt, so an event whose handler fails is retried whether or
/// not anyone remembers to call this. What this adds is the error text, which
/// is the only thing that makes a dead letter diagnosable.
pub async fn mark_failed(
    conn: &mut PgConnection,
    id: Uuid,
    last_error: &str,
) -> Result<(), StoreError> {
    let updated = sqlx::query(
        "UPDATE outbox_events SET last_error = $2 WHERE id = $1 AND published_at IS NULL",
    )
    .bind(id)
    .bind(last_error)
    .execute(&mut *conn)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Prefix on a [`park`] reason meaning: **no operator verb can change this
/// answer, so do not hand it back.** [`requeue_dead_letters`] skips these.
///
/// One constant rather than a pattern each side guesses at, and it lives here
/// because this is where it is read. The only writer today is
/// `apps/server/src/main.rs`'s `on_turn`, for a turn that exhausted
/// `app::turn::Budgets` — a hardcoded `Default` that the workspace's one
/// `with_budgets` call site only ever *narrows*, so a revival is arithmetically
/// certain to spend `max_turns` model calls and reach the same number.
///
/// **A reason is not this unless the *code* says so, not the situation.** A bad
/// API key and a policy that permits no model are both terminal and neither is
/// this: an operator fixes them by connecting a model or writing a layer, which
/// are precisely the two verbs that call [`requeue_dead_letters`]. The test is
/// not "can this attempt succeed", it is "is there anything an operator could
/// do that would make it succeed" — and if a turn budget ever becomes something
/// policy can raise, whatever verb raises it is the one that should revive these
/// rows, targeted, rather than this marker coming off.
///
/// It reads as prose on purpose: it is the first thing on the line an operator
/// sees in [`dead_letters`], and it is the sentence that tells them retrying by
/// hand is not the answer.
pub const UNREMEDIABLE: &str = "unremediable: ";

/// The handler failed in a way no retry can change. Stop, without losing it.
///
/// The third answer, between [`mark_done`] and [`mark_failed`]. `mark_failed`
/// records the reason and lets [`claim`] hand the row back seven more times;
/// this records the reason and burns the attempt counter, so the row is a dead
/// letter on the *first* attempt instead of the eighth. Same visibility —
/// [`dead_letters`] selects on exactly this predicate — minus seven attempts
/// that were arithmetically certain to end here anyway.
///
/// ponytail: burning the attempt counter *is* the dead-letter state. This table
/// has no `dead_lettered_at` column and both [`claim`] and [`dead_letters`]
/// filter on `attempt_count`, so a park is one `UPDATE`: the row stays,
/// unpublished, with the reason attached, and no poller picks it up again.
/// `greatest` because a park must never *lower* an attempt count.
///
/// Not a one-way door — unless the reason starts with [`UNREMEDIABLE`].
/// [`requeue_dead_letters`] is the operator's verb for giving a parked row its
/// attempts back once whatever made it impossible — the employee that was never
/// hired, the address nobody owns — has been fixed.
///
/// This used to be spelled privately in `apps/server/src/loops/inbound.rs`, and
/// then the outbox poller needed the same three-way decision. One spelling,
/// beside the `attempt_count` predicate it has to agree with — the same
/// argument [`claim_of`] settled for the two claims.
pub async fn park(conn: &mut PgConnection, id: Uuid, why: &str) -> Result<(), StoreError> {
    let parked = sqlx::query(
        "UPDATE outbox_events \
            SET last_error = $2, attempt_count = greatest(attempt_count, $3::int) \
          WHERE id = $1 AND published_at IS NULL",
    )
    .bind(id)
    .bind(why)
    .bind(MAX_ATTEMPTS)
    .execute(&mut *conn)
    .await?;

    if parked.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Events that exhausted [`MAX_ATTEMPTS`] and are no longer being retried.
///
/// Not a separate table and not a separate flag — the same predicate [`claim`]
/// filters on, read back. Poll it from an alert, because a dead letter is a
/// side effect that was supposed to happen and never did.
pub async fn dead_letters(
    conn: &mut PgConnection,
    limit: i64,
) -> Result<Vec<OutboxEvent>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, aggregate_type, aggregate_id, event_type, \
                payload, attempt_count, available_at, last_error \
         FROM outbox_events \
         WHERE published_at IS NULL AND attempt_count >= $1::int \
         ORDER BY available_at, id LIMIT $2::bigint",
    )
    .bind(MAX_ATTEMPTS)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows.iter().map(OutboxEvent::from_row).collect())
}

/// Give this tenant's dead letters their attempts back.
///
/// # Why this verb has to exist at all
///
/// Because until it did, [`dead_letters`] was a one-way door. Nothing in the
/// workspace ever wrote `attempt_count = 0`, so a row that burned its eight
/// attempts was never claimed again by anything, ever — and the only handler
/// that reads it is a human with `psql`.
///
/// That is the right shape for a poisoned payload. It is the wrong shape for the
/// failure that actually produces dead letters in this product: a tenant who
/// receives mail *before* connecting a model. `apps/server/src/main.rs` turns
/// `NoModel` into a `String` and hands it to the retry channel, so eight
/// attempts — about two minutes, per [`claim`]'s schedule — pass before anybody
/// has finished pasting an API key. Every one of those messages is then a mail
/// the customer's employees will never answer, on a system whose entire premise
/// is that they do.
///
/// # It is untargeted except for one exclusion
///
/// This requeues *every* exhausted event the tenant has, not the ones that died
/// of `NoModel`. The alternative — deciding, per row, whether the operator's fix
/// addresses the reason it died — means pattern-matching a human sentence that
/// any refactor is free to reword, and a filter of that shape that silently
/// stops matching is worse than no filter: the symptom is the same permanent
/// silence this function exists to end.
///
/// The one exception is [`UNREMEDIABLE`], and it inverts that argument rather
/// than ignoring it. It is an **exclusion**, not an inclusion, so its failure
/// mode is the safe one: a marker that stopped matching would revive the row and
/// let it repark, which is exactly the behaviour of the day before this existed,
/// not a new permanent silence. And it is a constant this module owns, shared
/// with the one writer, rather than a sentence read back by guesswork.
///
/// # Why an exclusion is needed at all
///
/// Because the "returns to exactly where it was" bound this function used to
/// claim is not true of every terminal failure. It is true of a poisoned
/// payload, which fails again in microseconds. It is **false** of a turn that
/// exhausted `app::turn::Budgets` — those are a hardcoded `Default` that no
/// operator lever raises, so reviving one buys `max_turns` fresh model calls, on
/// the customer's own key, to arrive at the identical number and park again. And
/// the trigger is not the rare deliberate act the paragraph above assumed:
/// `policy::activate` runs on every `install_layer` and every `rollback_layer`,
/// which is once per step of onboarding. Nothing converged and every pass was
/// billed.
///
/// So a writer that knows no operator verb can change its answer says so, and
/// this leaves the row where it is: still unpublished, still in
/// [`dead_letters`], still carrying the reason — visible and free, instead of
/// invisible and expensive. What it costs is that a turn which genuinely needs a
/// bigger budget stays stuck; it was stuck before too, because there is no lever
/// to unstick it, and the row naming its ceiling is what tells an operator one
/// has to be built.
///
/// # What it does not touch
///
/// `published_at`, because an event that was published is done and replaying it
/// would be the side effect happening twice. And `last_error`, which stays until
/// something succeeds: erasing it here would hide, from the operator reading
/// [`dead_letters`] tomorrow, why the row was ever stuck. [`mark_done`] is what
/// clears it, and only after the handler actually worked.
///
/// Returns how many rows were revived, so a caller can say nothing at all when
/// the answer is zero.
///
// ponytail: this is a sequential scan **once the pile is large, and an index
// scan until then** — which is the half the note above this one was missing, and
// it is the half that decides. Re-measured on PostgreSQL 17, median of three,
// one tenant's dead letters, each run rolled back:
//
//     dead letters   table            requeue
//     -------------------------------------------
//                5   500 105 rows       0.1 ms   <- Index Scan, outbox_events_due_idx
//          100 000   100 100 rows     2 867 ms   <- Seq Scan
//          200 000   200 100 rows     4 753 ms
//          500 000   500 100 rows    13 191 ms
//        1 000 000  1 000 100 rows    41 675 ms
//
// The first row is the case that actually happens on every `install_layer`,
// every `rollback_layer` and every `POST /v1/model`: a handful of dead letters
// in a table of any size at all. It costs nothing, and half a million *published*
// rows beside them cost nothing either — `outbox_events_due_idx` is partial on
// `published_at IS NULL`, so the statement never sees them. So indexing is not
// the upgrade for the same reason twice: the reachable case is already indexed,
// and the expensive case is expensive because it updates 100 000 of 100 100 rows,
// which no index makes cheaper.
//
// **The ceiling is not slowness, it is `REQUEST_TIMEOUT`.** Both callers run
// inside an HTTP request that `apps/server/src/main.rs` gives 30 seconds, and the
// table above crosses it somewhere around three quarters of a million. What
// happens then is not a slow success: the layer answers 408, the handler future
// is dropped, the transaction rolls back — and the transaction is the one holding
// the *credential*. `POST /v1/model` would fail to connect a model because of the
// mail that is waiting for the model, every retry would redo the same work and
// fail the same way, and the verb that exists to unstick a tenant would be the
// thing keeping it stuck. That is a real cliff and it is worth knowing it is at
// ~750 000 rather than "eventually".
//
// FOUNDER'S QUESTION, LEFT OPEN, AND DELIBERATELY NOT ANSWERED HERE: bounding
// this to the oldest `n` is the way out, and `n` is not an engineering choice.
// Today the contract is "everything comes back"; bounded, it becomes "some of it
// came back and you have to run the verb again", and neither caller can say so —
// `connect` and `activate` both *log* the count and hand back an answer about a
// credential or a policy version, so a partial revival would be invisible to the
// person who has to repeat it. So the number and its telling are one decision:
// how many, and where does the operator read "500 of 100 000"? Nothing is near
// the cliff (the largest pile this deployment could hold is one parked row per
// unanswerable message), so this ships unbounded and measured rather than bounded
// and guessed.
pub async fn requeue_dead_letters(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    // No `WHERE tenant_id`: RLS is forced on `outbox_events` and this is a
    // `TenantTx`, so the tenant filter is the database's. That also means this
    // cannot revive another tenant's stuck mail, which a `Db`-level verb taking
    // a tenant id could have been talked into.
    //
    // `coalesce` because a dead letter may carry no reason at all — a row that
    // simply burned its eight attempts against an unreachable provider — and
    // `starts_with(NULL, …)` is NULL, which under `NOT` would quietly exclude
    // every one of them. Those are the rows this function was written for.
    let revived = sqlx::query(REQUEUE_SQL)
        .bind(now)
        .bind(MAX_ATTEMPTS)
        .bind(UNREMEDIABLE)
        .execute(&mut ***tx)
        .await?;

    Ok(revived.rows_affected())
}

/// The statement [`requeue_dead_letters`] runs, lifted out of it so a test can
/// `EXPLAIN` the bytes that actually ship rather than a second copy of them that
/// is free to drift. [`CLAIM_SQL`] is the same lifting for the same reason.
///
/// **There is no `WHERE tenant_id` in it and there must not be**, which is what
/// makes the index this reads a non-obvious one: the tenant qual is row-level
/// security's, added to the plan rather than to the text, so anybody reading
/// this string alone sees a whole-table update and anybody reading the plan sees
/// a tenant-leading one. `migrations/0060_outbox_parked_by_tenant.sql` is that
/// index, and `revival_does_not_walk_another_tenants_dead_letters` is the test
/// this constant exists for.
const REQUEUE_SQL: &str = "UPDATE outbox_events SET attempt_count = 0, available_at = $1 \
                           WHERE published_at IS NULL AND attempt_count >= $2::int \
                             AND NOT starts_with(coalesce(last_error, ''), $3)";

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::TimeDelta;
    use sqlx::{Postgres, Transaction};
    use tokio::sync::{Barrier, Mutex};

    use super::*;
    use crate::db::Db;

    /// `claim` and `dead_letters` are cross-tenant by design — that is the
    /// poller's whole job — so a test that claims sees rows written by any
    /// other test running at the same time, whatever tenant they belong to.
    /// cargo runs tests in parallel, so every test in this module that writes
    /// to `outbox_events` takes this first and they go one at a time.
    static OUTBOX_LOCK: Mutex<()> = Mutex::const_new(());

    /// This module's own database. [`crate::db::private_db`] is the mechanism.
    ///
    /// [`OUTBOX_LOCK`] and [`clear_outbox`] below are what this module used to
    /// rely on instead, and the argument they rest on — everyone else's events
    /// are stamped `Utc::now()`, [`claim`] only takes rows whose `available_at`
    /// has passed, so at [`T0`] somebody else's event is not merely irrelevant,
    /// it is unclaimable — is true, and it covers [`claim`] exactly.
    ///
    /// It does not cover [`dead_letters`], which has no time predicate at all:
    /// `published_at IS NULL AND attempt_count >= MAX_ATTEMPTS`, every tenant,
    /// any age. That is correct — an operator alerts on the whole queue — and it
    /// means `a_permanently_failing_handler_backs_off_then_dead_letters`'
    /// `assert_eq!(dead.len(), 1)` is an assertion about the **whole database**.
    /// It found three: the inbound loop's tests were running on the shared
    /// database and ticking their poller to exhaustion, which is what a dead
    /// letter is. That loop now takes its own database too, but the assertion
    /// was one exhausted event away from breaking again from any direction, and
    /// a test that owns a global claim needs to own the database it claims from.
    ///
    /// The lock and the scoped clear stay: the tests in *this* module still run
    /// in parallel against this one database.
    async fn db() -> Option<Db> {
        crate::db::private_db("storeoutbox").await
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    const T0: i64 = 1_700_000_000;

    /// The name every tenant this module creates carries, so [`clear_outbox`]
    /// is a scoped statement rather than a wipe.
    const TENANT_SLUG: &str = "outbox-store-";

    /// A committed tenant to hang events off. Returns its id.
    async fn seed_tenant(db: &Db, label: &str) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("{TENANT_SLUG}{label}-{}", tenant.as_uuid()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit tenant");
        tenant
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

    /// Clear what a previously crashed run of **this module** left behind, so
    /// the cross-tenant reads below see only what this test wrote. Events
    /// cascade from the tenant that owns them.
    ///
    /// This used to be `DELETE FROM outbox_events` with no `WHERE`, under RLS
    /// bypass, which deleted the events of every other test in the crate that
    /// happened to be mid-assertion. What makes the narrower statement enough
    /// is that these tests claim at [`T0`] — 2023 — while everyone else's
    /// events are stamped `Utc::now()`, and `claim` only selects rows whose
    /// `available_at` has already passed. Somebody else's event is not merely
    /// irrelevant here, it is unclaimable.
    async fn clear_outbox(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE slug LIKE $1 || '%'")
            .bind(TENANT_SLUG)
            .execute(&mut *tx)
            .await
            .expect("clear outbox");
        tx.commit().await.expect("commit clear");
    }

    /// Enqueue in its own committed tenant transaction, the way a caller does.
    async fn enqueue_committed(
        db: &Db,
        tenant: TenantId,
        event: &NewEvent,
        now: DateTime<Utc>,
    ) -> Uuid {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let id = enqueue(&mut tx, event, now).await.expect("enqueue");
        tx.commit().await.expect("commit");
        id
    }

    fn event(n: usize) -> NewEvent {
        let mut e = NewEvent::new("employee", Uuid::now_v7(), "employee.provisioned");
        e.payload = json!({ "n": n });
        e
    }

    /// `rows` due events for one tenant, in one statement.
    ///
    /// [`enqueue_committed`] is the honest path and every other test uses it;
    /// this one exists because
    /// [`a_claim_that_lands_mid_statement_is_not_handed_out_twice`] needs a few
    /// thousand rows and a few thousand round trips is a slow test rather than
    /// a careful one. Same columns [`enqueue`] writes, defaults for the rest.
    async fn seed_due(db: &Db, tenant: TenantId, rows: i64, now: DateTime<Utc>) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO outbox_events \
                 (id, tenant_id, aggregate_type, aggregate_id, event_type, payload, \
                  created_at, available_at) \
             SELECT gen_random_uuid(), $1, 'employee', gen_random_uuid(), \
                    'employee.provisioned', '{}'::jsonb, $2, $2 \
               FROM generate_series(1, $3::bigint)",
        )
        .bind(tenant.as_uuid())
        .bind(now)
        .bind(rows)
        .execute(&mut *tx)
        .await
        .expect("seed");
        tx.commit().await.expect("commit seed");
    }

    /// `rows` dead letters for one tenant, exactly as [`park`] leaves them:
    /// unpublished, `attempt_count` burnt out, and `available_at` *not moved* —
    /// which is why they sort ahead of everything claimable in the same tenant.
    ///
    /// One statement for the same reason [`seed_due`] is one: the point of the
    /// test below is a few thousand of these.
    async fn seed_parked(db: &Db, tenant: TenantId, rows: i64, now: DateTime<Utc>) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO outbox_events \
                 (id, tenant_id, aggregate_type, aggregate_id, event_type, payload, \
                  created_at, available_at, attempt_count, last_error) \
             SELECT gen_random_uuid(), $1, 'employee', gen_random_uuid(), \
                    'employee.provisioned', '{}'::jsonb, $2, $2 - g * interval '1 second', \
                    $4::int, 'this employee''s policy permits no model at all' \
               FROM generate_series(1, $3::bigint) g",
        )
        .bind(tenant.as_uuid())
        .bind(now)
        .bind(rows)
        .bind(MAX_ATTEMPTS)
        .execute(&mut *tx)
        .await
        .expect("seed parked");
        tx.commit().await.expect("commit parked seed");
    }

    /// Give the planner statistics before asserting on a plan.
    ///
    /// The two tests below assert *which index* the planner reaches for, and a
    /// planner with no statistics is a planner reading a different table. This
    /// module shares one private database across all of its tests, so by the
    /// time either of them runs `outbox_events` carries whatever `pg_statistic`
    /// rows the last autovacuum happened to write — and everybody else here
    /// stamps `Utc::now()` while these two seed at [`T0`], 2023. The stale
    /// histogram then says almost nothing satisfies `available_at <= T0`,
    /// `outbox_events_due_idx` costs out as a near-empty range scan, and the
    /// claim plans onto it and throws the 5 000 dead letters away by hand:
    /// `Rows Removed by Filter: 5000`, which is the exact failure these tests
    /// exist to catch, produced by the fixture instead of by the code.
    ///
    /// Whether that happens depends on autovacuum's naptime against the run, so
    /// it was red about one full run in three, green in isolation every time,
    /// and green again on a re-run — the worst shape a guard can have, because
    /// the next reader's first move is to re-run it. Reproduced deterministically
    /// by seeding `now()`-stamped rows, `ANALYZE`, deleting them and seeding
    /// this fixture: red every time, and green every time with the line below.
    ///
    /// Production never asks the question this way. `outbox_events` is written
    /// continuously, so its statistics are the ones the planner ought to have,
    /// and this is what puts the test in that position rather than in one no
    /// deployment is ever in.
    async fn analyze_outbox(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("ANALYZE outbox_events")
            .execute(&mut *tx)
            .await
            .expect("analyze outbox_events");
        // Committed rather than rolled back: `pg_statistic` rows are ordinary
        // rows, and a rollback would take the statistics out again with them.
        tx.commit().await.expect("commit analyze");
    }

    /// **A tenant's dead letters must cost the claim nothing, and until
    /// `0057_outbox_claimable` they cost it everything.**
    ///
    /// `park` burns the attempt counter and leaves `published_at` NULL and
    /// `available_at` where it was, so a parked row stays inside the partial
    /// index the claim scans, at the *head* of its tenant's range — and nothing
    /// in this repository has ever deleted a row from `outbox_events`. With
    /// `attempt_count` a mere filter, every claim walked past every dead letter
    /// the deployment had ever produced, four times a second, forever. Measured
    /// at 26 ms per claim against one tenant holding 100 000 of them, which is
    /// `0046`'s own failure — one customer's rows becoming every customer's
    /// latency — reached by the road `0046` explicitly ruled out on the grounds
    /// that dead letters were "a bounded population". `outbox::park` and
    /// `main.rs`'s `Failure::Terminal` are what unbounded them.
    ///
    /// This asserts the plan rather than a duration, because a duration is a
    /// flaky test on a laptop and the plan is the thing that regressed. Three
    /// assertions, each of which was watched go red against a deliberate break,
    /// and no two of them catch the same one:
    ///
    /// * **the plan names `outbox_events_claimable_idx` somewhere.** Red when
    ///   the index's predicate and [`MAX_ATTEMPTS`] part company — the planner
    ///   can no longer prove the index applies and silently drops it, and this
    ///   is the only thing in the workspace that would notice, because an
    ///   applied migration cannot follow a Rust constant. Deliberately weak
    ///   about *which* node: both the `seated` lateral and the `due` recheck can
    ///   read that index, and pinning the assertion to one of them means pinning
    ///   it to a plan shape the planner is free to change.
    /// * **`Rows Removed by Filter` stays near zero rather than near
    ///   [`PARKED`].** This is the one that measures the actual complaint — work
    ///   done per claim, not index names — and it is red when the index is
    ///   widened back to `published_at IS NULL` alone, which the first assertion
    ///   happily passes.
    /// * **exactly the rows under the cap come back.** Red when the cap in the
    ///   lateral moves, which the first two both pass: a `<=` accepts the dead
    ///   letters instead of filtering them, so nothing is *removed by filter*
    ///   and the `due` recheck still reads the index.
    ///
    /// It runs [`CLAIM_SQL`] itself, not a copy: a test that measures a second
    /// spelling of the query measures nothing about the first.
    #[tokio::test]
    async fn a_tenants_dead_letters_are_not_scanned_by_every_claim() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "parked-scan").await;

        /// Enough that walking them is unmistakable in the plan, few enough
        /// that one INSERT is instant.
        const PARKED: i64 = 5_000;

        seed_parked(&db, tenant, PARKED, at(T0 - 1)).await;
        // One claimable row, behind all of them in `available_at` order.
        seed_due(&db, tenant, 1, at(T0)).await;
        analyze_outbox(&db).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        // ANALYZE runs the UPDATE for real, so this transaction is rolled back
        // rather than committed. Same seven binds as [`claim_of`]: the statement
        // under test is the constant the poller ships, not a copy of it.
        //
        // `AssertSqlSafe`, and the audit is that both halves are compile-time
        // constants of this module — a literal `EXPLAIN` prefix and
        // [`CLAIM_SQL`]. No value reaches the string.
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) {CLAIM_SQL}"
        )))
        .bind(at(T0))
        .bind(MAX_ATTEMPTS)
        .bind(32_i64)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(POLLER_HEADROOM)
        .bind(LEASE_SECS)
        .fetch_all(&mut *tx)
        .await
        .expect("explain the claim");
        tx.rollback().await.expect("rollback the explained claim");

        let plan = plan.join("\n");
        assert!(
            plan.contains("outbox_events_claimable_idx"),
            "the claim no longer reads the index that excludes dead letters. A \
             partial index is dropped by the planner the moment it can no longer \
             prove the query implies the predicate — which is what happens when \
             MAX_ATTEMPTS and 0057's `attempt_count < 8` stop agreeing — and the \
             fallback is silent and correct and slow. Plan:\n{plan}"
        );

        // Every `Rows Removed by Filter` in the plan, summed. Zero nodes is
        // fine; what must not happen is a node that threw away the parked rows,
        // because throwing them away means it read them first.
        let discarded: i64 = plan
            .split("Rows Removed by Filter: ")
            .skip(1)
            .map(|tail| {
                tail.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("0")
                    .parse::<i64>()
                    .unwrap_or(0)
            })
            .sum();
        assert!(
            discarded < PARKED / 10,
            "the claim discarded {discarded} rows to find one; {PARKED} dead \
             letters are being read on every claim. Plan:\n{plan}"
        );

        // And the cap still sits where it is supposed to. The two assertions
        // above are both about the *plan*, and a plan can be perfect about rows
        // the claim should not have been offered in the first place — a `<=` in
        // the lateral reads the index, filters nothing, and hands back five
        // thousand dead letters. A row one attempt short of the cap is what
        // pins the boundary from the other side.
        seed_due(&db, tenant, 1, at(T0 + 1)).await;
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "UPDATE outbox_events SET attempt_count = $2 \
              WHERE tenant_id = $1 AND available_at = $3",
        )
        .bind(tenant.as_uuid())
        .bind(MAX_ATTEMPTS - 1)
        .bind(at(T0 + 1))
        .execute(&mut *tx)
        .await
        .expect("age the last row");
        tx.commit().await.expect("commit");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim(&mut tx, 32, at(T0 + 2)).await.expect("claim");
        tx.commit().await.expect("commit claim");
        assert_eq!(
            claimed.len(),
            2,
            "exactly the two rows under the cap are claimable; {PARKED} at the \
             cap are not, and a row at MAX_ATTEMPTS - 1 still is"
        );

        drop_tenant(&db, tenant).await;
    }

    /// **The other half of `attempt_count`, and `0057` took its index away.**
    ///
    /// [`requeue_dead_letters`] asks `attempt_count >= MAX_ATTEMPTS` — exactly
    /// what `outbox_events_claimable_idx` excludes — inside a [`TenantTx`],
    /// which is what makes it a *tenant-leading* read even though
    /// [`REQUEUE_SQL`] contains no `tenant_id`: row-level security puts the qual
    /// in the plan rather than in the text. `0057` dropped the only index that
    /// led with `tenant_id`, so the fallback is `outbox_events_due_idx` — every
    /// tenant's unpublished rows, with this tenant's filtered out of them.
    ///
    /// `0057` did look at this reader and measured it at 2.2 s unchanged, in the
    /// shape where one tenant holds 100 000 of 100 100 rows and the statement
    /// updates nearly everything it touches. The shape that runs is the other
    /// one: `store::policy::activate` calls this on every `install_layer`, and
    /// `POST /v1/companies` installs one per role — so the tenant doing it is
    /// nearly always the one with **no** dead letters, and every row it examines
    /// belongs to somebody else. Measured at 59 ms against 100 000 parked rows
    /// owned by another tenant, against 0.10 ms before `0057`.
    ///
    /// So the assertion is the one that measures the complaint — rows read to
    /// find this tenant's — and not an index name. It goes red three ways and
    /// they are the three that matter: `0060`'s index missing, its predicate and
    /// [`MAX_ATTEMPTS`] parting company so the planner drops it, and anybody
    /// widening it back to `published_at IS NULL` alone.
    ///
    /// It EXPLAINs [`REQUEUE_SQL`] itself, not a copy, for
    /// [`a_tenants_dead_letters_are_not_scanned_by_every_claim`]'s reason.
    #[tokio::test]
    async fn revival_does_not_walk_another_tenants_dead_letters() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;

        /// Enough that walking them is unmistakable in the plan, few enough that
        /// one INSERT is instant.
        const PARKED: i64 = 5_000;

        // The customer who never connected a model.
        let noisy = seed_tenant(&db, "parked-noisy").await;
        seed_parked(&db, noisy, PARKED, at(T0)).await;
        // The customer being onboarded: live mail, no dead letters, and about to
        // have a policy layer installed.
        let onboarding = seed_tenant(&db, "parked-onboarding").await;
        seed_due(&db, onboarding, 5, at(T0)).await;
        // Unlike the claim's, this call is **not** proven by a mutation: removing
        // it leaves this test green against every stale-statistics fixture that
        // was tried, including one that forces `n_distinct(tenant_id) = 1`.
        // `outbox_events_tenant_parked_idx` leads with the qual's own column and
        // holds only parked rows, so nothing costed out cheaper than it. Kept
        // anyway, and the distinction matters: this is a *precondition*, not a
        // second assertion — it asserts nothing, and it removes a class of
        // nondeterminism that the identically shaped test above was measured
        // suffering from. Deleting it would leave two guards of the same shape
        // disagreeing about what they need to be true before they measure.
        analyze_outbox(&db).await;

        // As the tenant, not as admin: the qual under test is RLS's, and
        // `admin_tx_bypassing_rls` would remove the very thing being measured.
        //
        // ANALYZE runs the UPDATE for real, so this transaction is rolled back.
        // `AssertSqlSafe`, and the audit is that both halves are compile-time
        // constants of this module — a literal `EXPLAIN` prefix and
        // [`REQUEUE_SQL`]. No value reaches the string.
        let mut tx = db.tenant_tx(onboarding).await.expect("tenant tx");
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) {REQUEUE_SQL}"
        )))
        .bind(at(T0))
        .bind(MAX_ATTEMPTS)
        .bind(UNREMEDIABLE)
        .fetch_all(&mut **tx)
        .await
        .expect("explain the revival");
        tx.rollback().await.expect("rollback the explained revival");

        let plan = plan.join("\n");
        let discarded: i64 = plan
            .split("Rows Removed by Filter: ")
            .skip(1)
            .map(|tail| {
                tail.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("0")
                    .parse::<i64>()
                    .unwrap_or(0)
            })
            .sum();
        assert!(
            discarded < PARKED / 10,
            "reviving a tenant with no dead letters read {discarded} rows that \
             are not its own; another tenant's {PARKED} parked rows are being \
             walked on every `install_layer`. Plan:\n{plan}"
        );

        drop_tenant(&db, noisy).await;
        drop_tenant(&db, onboarding).await;
    }

    // -- enqueue ----------------------------------------------------------

    /// The invariant the outbox exists for: a business transaction that is
    /// retried — because it deadlocked, because the pod restarted, because a
    /// client resent the request — must not enqueue the side effect twice.
    #[tokio::test]
    async fn a_retried_transaction_enqueues_exactly_once() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        let tenant = seed_tenant(&db, "dedupe").await;

        let mut e = NewEvent::new("approval", Uuid::now_v7(), "approval.granted");
        e.dedupe_key = Some("approval-42".to_owned());
        e.payload = json!({ "amount_minor": 1234 });

        // Same event, three separate committed transactions.
        let first = enqueue_committed(&db, tenant, &e, at(T0)).await;
        let second = enqueue_committed(&db, tenant, &e, at(T0 + 5)).await;
        let third = enqueue_committed(&db, tenant, &e, at(T0 + 9)).await;

        assert_eq!(first, second, "a retry must not mint a second event");
        assert_eq!(first, third);

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .expect("count");
        // The first insert's timestamp survives; the retries did not rewrite it.
        let created: DateTime<Utc> =
            sqlx::query_scalar("SELECT created_at FROM outbox_events WHERE id = $1")
                .bind(first)
                .fetch_one(&mut *tx)
                .await
                .expect("created_at");
        tx.rollback().await.expect("rollback");

        assert_eq!(rows, 1);
        assert_eq!(created, at(T0));

        drop_tenant(&db, tenant).await;
    }

    /// Without a dedupe key every call is a new event — a resend is a resend.
    #[tokio::test]
    async fn enqueue_without_a_dedupe_key_is_not_deduplicated() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        let tenant = seed_tenant(&db, "nodedupe").await;

        let e = NewEvent::new("employee", Uuid::now_v7(), "employee.digest");
        let a = enqueue_committed(&db, tenant, &e, at(T0)).await;
        let b = enqueue_committed(&db, tenant, &e, at(T0)).await;

        assert_ne!(a, b);
        drop_tenant(&db, tenant).await;
    }

    /// Two tenants using the same dedupe key are two different events. The
    /// tenant is part of the hashed tuple, so this cannot collide.
    #[tokio::test]
    async fn dedupe_keys_do_not_collide_across_tenants() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        let a = seed_tenant(&db, "dedupe-a").await;
        let b = seed_tenant(&db, "dedupe-b").await;

        let aggregate = Uuid::now_v7();
        let mut e = NewEvent::new("approval", aggregate, "approval.granted");
        e.dedupe_key = Some("same-key".to_owned());

        let in_a = enqueue_committed(&db, a, &e, at(T0)).await;
        let in_b = enqueue_committed(&db, b, &e, at(T0)).await;

        assert_ne!(in_a, in_b);
        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    // -- concurrency -------------------------------------------------------

    /// Two pollers, genuinely in parallel on two runtime threads, with the
    /// claiming transactions held open at the same time — which is the only
    /// arrangement in which `SKIP LOCKED` can be observed to do anything. If
    /// the two transactions were serialised the test would pass even with the
    /// clause deleted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_pollers_never_claim_the_same_row() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "concurrent").await;

        const EVENTS: usize = 40;
        for n in 0..EVENTS {
            enqueue_committed(&db, tenant, &event(n), at(T0)).await;
        }

        // Both tasks open a transaction, wait for the other to be ready, claim,
        // then wait again before committing. The second barrier is what forces
        // the row locks to overlap.
        let ready = Arc::new(Barrier::new(2));
        let claimed = Arc::new(Barrier::new(2));

        // Half the queue each. A limit of EVENTS would let whichever poller
        // wins the race take the lot and leave the other with nothing — correct
        // behaviour, but it proves nothing about SKIP LOCKED.
        const BATCH: i64 = (EVENTS / 2) as i64;

        let poller = |db: Db, ready: Arc<Barrier>, claimed: Arc<Barrier>| async move {
            let mut tx: Transaction<'_, Postgres> =
                db.admin_tx_bypassing_rls().await.expect("admin tx");
            ready.wait().await;
            let got = claim(&mut tx, BATCH, at(T0)).await.expect("claim");
            claimed.wait().await;
            tx.commit().await.expect("commit");
            got
        };

        let a = tokio::spawn(poller(db.clone(), ready.clone(), claimed.clone()));
        let b = tokio::spawn(poller(db.clone(), ready, claimed));
        let (a, b) = (a.await.expect("poller a"), b.await.expect("poller b"));

        let ids_a: std::collections::HashSet<Uuid> = a.iter().map(|e| e.id).collect();
        let ids_b: std::collections::HashSet<Uuid> = b.iter().map(|e| e.id).collect();

        // Neither poller blocked, and neither got a row the other had.
        assert!(
            ids_a.is_disjoint(&ids_b),
            "the same event was claimed twice: {:?}",
            &ids_a & &ids_b
        );
        // Both filled their batch — so the second poller was not blocked behind
        // the first one's locks, it stepped over them onto other rows.
        assert_eq!(ids_a.len(), BATCH as usize);
        assert_eq!(ids_b.len(), BATCH as usize);
        // Nothing was dropped on the floor, and nothing was handed out twice.
        assert_eq!(ids_a.len() + ids_b.len(), EVENTS);

        // A third poller at the same instant gets nothing: the claim pushed
        // every row's availability past `now`.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let leftovers = claim(&mut tx, 100, at(T0)).await.expect("claim again");
        tx.rollback().await.expect("rollback");
        assert!(
            leftovers.is_empty(),
            "a claimed row must not be re-claimable"
        );

        drop_tenant(&db, tenant).await;
    }

    /// **The test above cannot catch a double claim, and for four months there
    /// was one.**
    ///
    /// It holds both claiming transactions open across the claim, which is the
    /// one arrangement where `SKIP LOCKED` is doing the work: the second poller
    /// meets a lock that is still held and steps over it. That is a real
    /// arrangement and worth asserting — and it is not the one the poller runs
    /// in. [`claim`] commits *before* the handler, so in production the first
    /// poller's lock is gone within milliseconds, and `SKIP LOCKED` has nothing
    /// left to skip. From there the lease is the only thing holding the row,
    /// and the lease is a column the second poller has to actually re-read.
    ///
    /// It did not. `seated` reads `outbox_events` unlocked under the
    /// statement's snapshot; `due` is the only node that locks, and it joined on
    /// `e.id = c.id` and nothing else. When PostgreSQL's `READ COMMITTED`
    /// recheck walked to the version the first poller had just committed, the
    /// only qual under `LockRows` was that join — which still held — so the row
    /// was claimed a second time, `attempt_count` went straight to 2, and both
    /// pollers ran the handler. Measured in `apps/server`'s two-poller test at
    /// 24 of 60 events, the two claims 2.2 ms apart, inside a 120-second lease.
    /// One of the rows in this table is `agent.turn.requested`.
    ///
    /// # Why this is not a race the test hopes to win
    ///
    /// The window is "after the second poller's snapshot, before its first row
    /// lock", and in the statement that window is a whole phase: `seated` and
    /// `shortlist` are both `MATERIALIZED` and both complete before `due` takes
    /// a lock. So it is widened on purpose rather than raced for. Two claims
    /// start together on the barrier; the big one shortlists
    /// `SLOW * POLLER_HEADROOM` rows and spends about eight milliseconds
    /// sorting them before it locks anything, and the small one takes its rows
    /// and *commits* inside that — one or two milliseconds. The asymmetry of
    /// the two limits is what orders the three events, so nothing here depends
    /// on a sleep being long enough.
    ///
    /// It is still an interleaving and not a proof. Two orderings assert
    /// nothing — the small claim committing *after* the big one has locked the
    /// rows, and the big one finishing first and leaving the small one's
    /// `FAST * POLLER_HEADROOM`-deep window with nothing due — and neither is a
    /// failure. Measured against the unfixed query, one round bites a little
    /// over half the time on this machine, which is why the interleaving is run
    /// [`ROUNDS`] times: the run as a whole then bit 60 times in 60, against 4
    /// in 60 for `apps/server`'s two-poller test, which is the same defect seen
    /// from the far end of a poll loop. On the fixed query: 0 red in 120.
    ///
    /// [`ROUNDS`]: a_claim_that_lands_mid_statement_is_not_handed_out_twice
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_claim_that_lands_mid_statement_is_not_handed_out_twice() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "midstatement").await;

        // `SLOW * POLLER_HEADROOM` rows go through a sort before the first lock
        // is taken; that sort is the window. Every round consumes what it
        // claims — a claimed row is leased two minutes out — so the pool has to
        // cover all of them with slack for the small claim to have something
        // due after the big one has taken its thousand.
        const SLOW: i64 = 1_000;
        const FAST: i64 = 8;
        const ROUNDS: i64 = 5;
        const ROWS: i64 = (SLOW + FAST) * ROUNDS + 500;
        seed_due(&db, tenant, ROWS, at(T0)).await;

        for round in 0..ROUNDS {
            // Both transactions are open before either claims, so the barrier
            // releases two statements and not two connection handshakes.
            let ready = Arc::new(Barrier::new(2));
            let slow = tokio::spawn({
                let db = db.clone();
                let ready = ready.clone();
                async move {
                    let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
                    ready.wait().await;
                    let got = claim(&mut tx, SLOW, at(T0)).await.expect("slow claim");
                    tx.commit().await.expect("commit slow");
                    got
                }
            });

            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            ready.wait().await;
            // Into the big claim's sort rather than alongside its snapshot:
            // level, the small claim can reach `due` first, and then it is the
            // big one that meets a held lock — which is the case the test above
            // already covers.
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            let fast = claim(&mut tx, FAST, at(T0)).await.expect("fast claim");
            tx.commit().await.expect("commit fast");

            let slow = slow.await.expect("slow poller");

            // The fingerprint, and it does not depend on which poller won: a
            // row handed out twice comes back to the second claimer with the
            // first claimer's increment already on it.
            let twice: Vec<Uuid> = slow
                .iter()
                .chain(fast.iter())
                .filter(|e| e.attempt_count != 1)
                .map(|e| e.id)
                .collect();
            assert!(
                twice.is_empty(),
                "round {round}: {} rows came back already claimed — the lock \
                 re-read a version somebody else had leased: {twice:?}",
                twice.len()
            );

            let ids_slow: std::collections::HashSet<Uuid> = slow.iter().map(|e| e.id).collect();
            let ids_fast: std::collections::HashSet<Uuid> = fast.iter().map(|e| e.id).collect();
            assert!(
                ids_slow.is_disjoint(&ids_fast),
                "round {round}: the same event was claimed by both pollers: {:?}",
                &ids_slow & &ids_fast
            );
            // Deliberately no assertion that either batch came back full. The
            // small claim only looks `FAST * POLLER_HEADROOM` rows deep, so an
            // ordering in which the big claim commits first leaves it nothing
            // due and it correctly returns none — that is a round that asserted
            // nothing, which is why there are several.
            // `two_concurrent_pollers_never_claim_the_same_row` is where the
            // batch bound is asserted, from an arrangement that controls it.
        }

        drop_tenant(&db, tenant).await;
    }

    /// **One company's backlog must not decide when another company's work
    /// starts.**
    ///
    /// This is not a leak and it is not a lock: two tenants that never see a
    /// byte of each other's data still share one queue, and the claim used to
    /// order it `available_at, id` across every tenant at once. So the position
    /// of a customer's event in the queue is a function of *how busy the other
    /// customers are*, and there is no ceiling on that — the backlog one tenant
    /// can enqueue is unbounded, while the poller drains a batch of 32 with the
    /// handlers running one after another, each of them up to `TURN_DEADLINE`.
    /// A tenant paying three thousand dollars a month can watch its single
    /// inbound email sit unclaimed for hours because somebody else imported a
    /// prospect list.
    ///
    /// The numbers below are deliberately the smallest that make the point:
    /// one tenant with more due events than a batch holds, another with one,
    /// enqueued *after*. Under a FIFO claim the second tenant is not in the
    /// batch at all. What the claim owes it is a seat, not a place in line.
    #[tokio::test]
    async fn one_tenants_backlog_does_not_push_another_tenant_out_of_the_batch() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let busy = seed_tenant(&db, "fair-busy").await;
        let quiet = seed_tenant(&db, "fair-quiet").await;

        const BATCH: i64 = 8;
        const BACKLOG: usize = 40;

        for n in 0..BACKLOG {
            enqueue_committed(&db, busy, &event(n), at(T0)).await;
        }
        // One event, enqueued a second later, so FIFO puts it behind all forty.
        let waiting = enqueue_committed(&db, quiet, &event(0), at(T0 + 1)).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim(&mut tx, BATCH, at(T0 + 2)).await.expect("claim");
        tx.commit().await.expect("commit");

        let ids: Vec<Uuid> = claimed.iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), BATCH as usize, "the batch is still bounded");
        assert!(
            ids.contains(&waiting),
            "the quiet tenant's only event was not claimed: one tenant's backlog \
             decides when another tenant's company gets to act"
        );
        // And the busy tenant is not punished for being busy — it still fills
        // everything the other tenants left. Fair is round-robin, not equal
        // shares of a queue nobody else is using.
        assert_eq!(
            claimed.iter().filter(|e| e.tenant_id == busy).count(),
            BATCH as usize - 1
        );

        drop_tenant(&db, busy).await;
        drop_tenant(&db, quiet).await;
    }

    /// Two pollers, one table. The general one must leave the specialised
    /// one's rows alone — it has no handler for them, so claiming one burns an
    /// attempt off somebody's inbound email for nothing.
    #[tokio::test]
    async fn an_excluded_aggregate_is_left_for_its_own_poller() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "excluded").await;

        let mine = enqueue_committed(&db, tenant, &event(1), at(T0)).await;
        let theirs = {
            let mut e = NewEvent::new("inbound", Uuid::now_v7(), "email.received");
            e.payload = json!({ "provider_message_id": "email_1" });
            enqueue_committed(&db, tenant, &e, at(T0)).await
        };

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim_except(&mut tx, Some("inbound"), 10, at(T0))
            .await
            .expect("claim");
        tx.commit().await.expect("commit");

        let ids: Vec<Uuid> = claimed.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![mine], "the other poller's row was taken");

        // And it is untouched: no attempt burned, still due at the same instant.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let attempts: i32 =
            sqlx::query_scalar("SELECT attempt_count FROM outbox_events WHERE id = $1")
                .bind(theirs)
                .fetch_one(&mut *tx)
                .await
                .expect("attempt_count");
        // An unfiltered claim still sees it, which is what makes the filter the
        // thing under test rather than an artefact of the row being invisible.
        let unfiltered = claim(&mut tx, 10, at(T0)).await.expect("claim");
        tx.rollback().await.expect("rollback");

        assert_eq!(attempts, 0, "an excluded row must not be leased");
        assert_eq!(
            unfiltered.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![theirs]
        );

        drop_tenant(&db, tenant).await;
    }

    /// **Two pollers must not take the same turn, and the lease is the only
    /// thing stopping them.**
    ///
    /// `apps/server` puts a requested agent turn in this table and gives it
    /// `TURN_DEADLINE` — 120 seconds — to finish, and [`claim`] deliberately
    /// commits before the handler runs, so once the claiming transaction is gone
    /// `available_at` is the whole of what holds the row. Until [`LEASE_SECS`]
    /// existed the first claim pushed it out by `2^0` seconds times a jitter
    /// factor — between half a second and a second and a half. A second replica
    /// therefore took the row about a second into the turn and ran the same turn
    /// again, on the customer's own model key, for one event. No error, no
    /// denial, no row out of place; the only trace is a bill that is twice what
    /// it should be.
    ///
    /// So this asserts two claims of one row while a turn is in flight, not a
    /// number of seconds: a **second poller on its own committed transaction**,
    /// coming back empty at every instant the first one may still be thinking.
    /// And then finding the row again once no turn could still be running,
    /// because a lease that does not expire is a queue that loses work.
    #[tokio::test]
    async fn a_second_poller_cannot_reclaim_an_event_while_the_first_is_still_handling_it() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "lease").await;

        let id = enqueue_committed(&db, tenant, &event(1), at(T0)).await;

        // Replica A claims and commits, which is exactly what
        // `loops::outbox::tick` does before it calls the first handler. From
        // here on nothing but `available_at` is between this row and anyone
        // else, and A is going to be busy for `TURN_DEADLINE`.
        let mut a = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let taken = claim(&mut a, 10, at(T0)).await.expect("claim");
        a.commit().await.expect("commit the lease");
        assert_eq!(taken.iter().map(|e| e.id).collect::<Vec<_>>(), vec![id]);

        // Replica B, across the whole window A's turn may occupy. Three seconds
        // rather than one: the old backoff was jittered up to 1.5s, so at one
        // second this would have been a coin toss instead of a failure.
        for elapsed in [3, 30, LEASE_SECS - 1, LEASE_SECS] {
            let mut b = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let stolen = claim(&mut b, 10, at(T0 + elapsed)).await.expect("claim");
            b.rollback().await.expect("rollback");
            assert!(
                stolen.is_empty(),
                "a second poller reclaimed the event {elapsed}s into a turn that \
                 gets {LEASE_SECS}s: both replicas run it, and the customer is \
                 billed twice on their own model key for one event"
            );
        }

        // A lease, not a grave. A replica that died mid-turn must not take the
        // event with it, so past the floor plus its backoff the row is due again.
        let mut c = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let back = claim(&mut c, 10, at(T0 + LEASE_SECS + 2))
            .await
            .expect("claim");
        c.rollback().await.expect("rollback");
        assert_eq!(
            back.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![id],
            "the lease never expired: a poller that dies mid-handler takes the \
             event with it and the side effect never happens"
        );

        drop_tenant(&db, tenant).await;
    }

    // -- backoff and dead-lettering ---------------------------------------

    /// A handler that never succeeds must not spin. Each claim waits longer
    /// than the last, and after `MAX_ATTEMPTS` the event stops being claimed
    /// at all and shows up as a dead letter instead.
    #[tokio::test]
    async fn a_permanently_failing_handler_backs_off_then_dead_letters() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "backoff").await;

        let id = enqueue_committed(&db, tenant, &event(1), at(T0)).await;

        let mut now = at(T0);
        let mut delays = Vec::new();

        for attempt in 1..=MAX_ATTEMPTS {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let batch = claim(&mut tx, 10, now).await.expect("claim");
            assert_eq!(batch.len(), 1, "attempt {attempt} should have claimed");
            let claimed = &batch[0];
            assert_eq!(claimed.id, id);
            assert_eq!(claimed.attempt_count, attempt);

            // Still due at this instant? Then the backoff did not happen.
            let immediate = claim(&mut tx, 10, now).await.expect("claim again");
            assert!(immediate.is_empty(), "attempt {attempt} did not back off");

            // The handler fails, as it will every time.
            mark_failed(&mut tx, id, &format!("boom {attempt}"))
                .await
                .expect("mark failed");
            tx.commit().await.expect("commit");

            delays.push(claimed.available_at - now);

            // Skip ahead past the backoff instead of sleeping through it.
            now += TimeDelta::hours(2);
        }

        // `LEASE_SECS`, then 2^(attempt-1) seconds with jitter in [0.5, 1.5),
        // the exponential capped at an hour. The floor is *added* to the
        // backoff rather than max'd with it exactly so that this assertion
        // still has a schedule to make: `greatest(120s, 2^n)` would flatten
        // seven of these eight to precisely 120 and take the jitter with them.
        let floor = LEASE_SECS as f64;
        for (i, delay) in delays.iter().enumerate() {
            let base = 2f64.powi(i as i32).min(3600.0);
            let secs = delay.as_seconds_f64();
            assert!(
                secs >= floor + base * 0.5 && secs < floor + base * 1.5,
                "attempt {} backed off {secs}s, expected [{}, {})",
                i + 1,
                floor + base * 0.5,
                floor + base * 1.5
            );
        }
        // It really did grow, and the growth is measured *above* the lease —
        // that part is the backoff, the floor below it is the turn it protects.
        // The first wait is about a second of it and the last is over a minute.
        // (Jitter overlaps between adjacent attempts, so compare the ends.)
        let backoff_of = |d: &TimeDelta| d.as_seconds_f64() - floor;
        assert!(
            backoff_of(&delays[delays.len() - 1]) > backoff_of(&delays[0]) * 10.0,
            "backoff did not grow: {delays:?}"
        );

        // Attempts are spent. No poller will ever pick it up again...
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let after = claim(&mut tx, 10, now + TimeDelta::days(365))
            .await
            .expect("claim");
        assert!(after.is_empty(), "an exhausted event must not be claimed");

        // ...but it is visible to whoever is on call, with the reason attached.
        let dead = dead_letters(&mut tx, 10).await.expect("dead letters");
        tx.rollback().await.expect("rollback");

        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].id, id);
        assert!(dead[0].is_dead_lettered());
        assert_eq!(dead[0].last_error.as_deref(), Some("boom 8"));

        drop_tenant(&db, tenant).await;
    }

    /// **A dead letter can be claimed again, and only by its own tenant.**
    ///
    /// The half of the fix that is not about credentials: before
    /// [`requeue_dead_letters`], a message that arrived while a tenant had no
    /// model connected was gone for good, because the eight attempts run out in
    /// about two minutes and nobody pastes an API key that fast.
    ///
    /// Three properties, and the third is the one a `WHERE tenant_id` somebody
    /// forgot would break: a published event is not resurrected, a live event is
    /// not disturbed, and another tenant's dead letter stays dead.
    #[tokio::test]
    async fn a_requeued_dead_letter_is_claimed_again_and_only_the_tenants_own() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let mine = seed_tenant(&db, "requeue-mine").await;
        let theirs = seed_tenant(&db, "requeue-theirs").await;

        // One of mine dies, one of mine is published, one of mine is healthy,
        // and one of theirs dies.
        let stuck = enqueue_committed(&db, mine, &event(1), at(T0)).await;
        let published = enqueue_committed(&db, mine, &event(2), at(T0)).await;
        let healthy = enqueue_committed(&db, mine, &event(3), at(T0)).await;
        let not_mine = enqueue_committed(&db, theirs, &event(4), at(T0)).await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        for id in [stuck, not_mine] {
            sqlx::query("UPDATE outbox_events SET attempt_count = $2 WHERE id = $1")
                .bind(id)
                .bind(MAX_ATTEMPTS)
                .execute(&mut *admin)
                .await
                .expect("exhaust");
        }
        mark_done(&mut admin, published, at(T0 + 1))
            .await
            .expect("publish");
        sqlx::query("UPDATE outbox_events SET attempt_count = $2 WHERE id = $1")
            .bind(published)
            .bind(MAX_ATTEMPTS)
            .execute(&mut *admin)
            .await
            .expect("exhaust the published one too");
        mark_failed(&mut admin, stuck, "no model is connected")
            .await
            .expect("mark failed");
        admin.commit().await.expect("commit");

        // The customer connects a model.
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        let revived = requeue_dead_letters(&mut tx, at(T0 + 2))
            .await
            .expect("requeue");
        tx.commit().await.expect("commit");
        assert_eq!(revived, 1, "one dead letter, not the published one");

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed: Vec<Uuid> = claim(&mut admin, 10, at(T0 + 3))
            .await
            .expect("claim")
            .iter()
            .map(|e| e.id)
            .collect();
        assert!(claimed.contains(&stuck), "the mail is deliverable again");
        assert!(claimed.contains(&healthy), "and so is everything else");
        assert!(
            !claimed.contains(&published),
            "a published event stays done"
        );
        assert!(!claimed.contains(&not_mine), "another tenant's stays dead");

        // The reason it was stuck survives the requeue, for whoever is reading
        // `dead_letters` output from yesterday.
        let reason: Option<String> =
            sqlx::query_scalar("SELECT last_error FROM outbox_events WHERE id = $1")
                .bind(stuck)
                .fetch_one(&mut *admin)
                .await
                .expect("last_error");
        assert_eq!(reason.as_deref(), Some("no model is connected"));
        admin.rollback().await.expect("rollback");

        // And it is idempotent: nothing is exhausted any more.
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        assert_eq!(
            requeue_dead_letters(&mut tx, at(T0 + 4))
                .await
                .expect("again"),
            0
        );
        tx.commit().await.expect("commit");

        drop_tenant(&db, mine).await;
        drop_tenant(&db, theirs).await;
    }

    /// **The exclusion, and the thing it must not have become.**
    ///
    /// [`UNREMEDIABLE`] exists because one terminal cause has no operator
    /// remedy: a turn that exhausted `app::turn::Budgets`, which is a hardcoded
    /// `Default` nothing raises. Reviving one buys `max_turns` model calls to
    /// reach the identical number, and both callers of
    /// [`requeue_dead_letters`] are untargeted — `policy::activate` runs on
    /// every `install_layer` — so it was billed once per policy write forever.
    ///
    /// Two rows, and the *second* is the one that catches the dangerous
    /// mistake. A predicate that excluded everything — `starts_with` against a
    /// NULL `last_error` is NULL, and `NOT NULL` is NULL, which drops the row —
    /// would turn this verb back into the one-way door it was written to
    /// replace, and every assertion about the marked row would still pass. So a
    /// plain dead letter with no reason at all comes back in the same call.
    #[tokio::test]
    async fn an_unremediable_dead_letter_is_left_where_it_is_and_the_others_still_come_back() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "unremediable").await;

        let ceiling = enqueue_committed(&db, tenant, &event(1), at(T0)).await;
        let ordinary = enqueue_committed(&db, tenant, &event(2), at(T0)).await;
        // No reason at all: a row that simply burned eight attempts. This is
        // the `coalesce` in the predicate, and it is a real state — `claim`
        // hands a row back seven times whatever the handler said.
        let silent = enqueue_committed(&db, tenant, &event(3), at(T0)).await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        park(
            &mut admin,
            ceiling,
            &format!("{UNREMEDIABLE}the turn hit a ceiling: max_turns"),
        )
        .await
        .expect("park the blown ceiling");
        park(&mut admin, ordinary, "no model is connected")
            .await
            .expect("park the ordinary one");
        sqlx::query("UPDATE outbox_events SET attempt_count = $2 WHERE id = $1")
            .bind(silent)
            .bind(MAX_ATTEMPTS)
            .execute(&mut *admin)
            .await
            .expect("exhaust without a reason");
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let revived = requeue_dead_letters(&mut tx, at(T0 + 2))
            .await
            .expect("requeue");
        tx.commit().await.expect("commit");
        assert_eq!(
            revived, 2,
            "the two remediable dead letters did not both come back; an exclusion that \
             excludes everything is the one-way door this verb replaced"
        );

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed: Vec<Uuid> = claim(&mut admin, 10, at(T0 + 3))
            .await
            .expect("claim")
            .iter()
            .map(|e| e.id)
            .collect();
        assert!(claimed.contains(&ordinary), "a named reason still revives");
        assert!(
            claimed.contains(&silent),
            "and so does a row with no reason"
        );
        assert!(
            !claimed.contains(&ceiling),
            "a turn parked on a ceiling no operator can raise was handed back; the poller \
             will spend the whole budget again to park it a second time"
        );

        // Still a dead letter, still carrying its reason: the operator who has
        // to decide whether a bigger budget is worth building reads it here.
        let dead = dead_letters(&mut admin, 10).await.expect("dead letters");
        let row = dead
            .iter()
            .find(|row| row.id == ceiling)
            .expect("the parked turn vanished from the dead-letter queue");
        assert!(
            row.last_error
                .as_deref()
                .is_some_and(|why| why.contains("max_turns")),
            "the row no longer names the ceiling that stopped it: {:?}",
            row.last_error
        );
        admin.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// The ordinary path: claim, succeed, and it is gone for good.
    #[tokio::test]
    async fn mark_done_publishes_once_and_only_once() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "done").await;

        let id = enqueue_committed(&db, tenant, &event(1), at(T0)).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let batch = claim(&mut tx, 10, at(T0)).await.expect("claim");
        assert_eq!(batch.len(), 1);
        mark_done(&mut tx, id, at(T0 + 1)).await.expect("mark done");

        // A second worker reporting the same success means the effect ran
        // twice; it must not be silently absorbed.
        assert!(matches!(
            mark_done(&mut tx, id, at(T0 + 2)).await,
            Err(StoreError::NotFound)
        ));

        // Published rows are invisible to the poller forever after.
        let after = claim(&mut tx, 10, at(T0 + 100_000)).await.expect("claim");
        tx.commit().await.expect("commit");
        assert!(after.is_empty());

        drop_tenant(&db, tenant).await;
    }

    // -- tracing -----------------------------------------------------------

    #[tokio::test]
    async fn the_traceparent_rides_along_with_the_event() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let tenant = seed_tenant(&db, "trace").await;

        const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut e = event(1);
        e.traceparent = Some(TRACEPARENT.to_owned());
        enqueue_committed(&db, tenant, &e, at(T0)).await;

        // A payload that is not an object still keeps its trace context.
        let mut scalar = NewEvent::new("employee", Uuid::now_v7(), "employee.pinged");
        scalar.payload = json!("just a string");
        scalar.traceparent = Some(TRACEPARENT.to_owned());
        enqueue_committed(&db, tenant, &scalar, at(T0)).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let batch = claim(&mut tx, 10, at(T0)).await.expect("claim");
        tx.rollback().await.expect("rollback");

        assert_eq!(batch.len(), 2);
        for claimed in &batch {
            assert_eq!(claimed.traceparent(), Some(TRACEPARENT));
        }
        // The object payload kept its own keys alongside.
        let with_object = batch
            .iter()
            .find(|e| e.event_type == "employee.provisioned")
            .expect("object payload event");
        assert_eq!(with_object.payload["n"], json!(1));
        // The scalar one was nested rather than dropped.
        let with_scalar = batch
            .iter()
            .find(|e| e.event_type == "employee.pinged")
            .expect("scalar payload event");
        assert_eq!(with_scalar.payload["data"], json!("just a string"));

        drop_tenant(&db, tenant).await;
    }

    /// An event with no traceparent has none — the key is absent, not null.
    #[tokio::test]
    async fn an_event_without_trace_context_reports_none() {
        let e = event(1);
        assert!(e.stored_payload().get(TRACEPARENT_KEY).is_none());
    }

    // -- isolation ---------------------------------------------------------

    /// The poller is cross-tenant, but ordinary tenant code is not: RLS still
    /// applies to the outbox, so one tenant cannot read another's pending
    /// effects.
    #[tokio::test]
    async fn a_tenant_cannot_see_another_tenants_pending_events() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        let a = seed_tenant(&db, "iso-a").await;
        let b = seed_tenant(&db, "iso-b").await;

        let in_b = enqueue_committed(&db, b, &event(1), at(T0)).await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE id = $1")
            .bind(in_b)
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!(visible, 0);

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    // -- the company-wide stop ---------------------------------------------

    /// **A stopped company's work waits; it is not destroyed.**
    ///
    /// This is the test that stands between a halt and a support incident.
    /// `attempt_count` is incremented *at claim time* and `MAX_ATTEMPTS` is 8,
    /// so refusing this work inside the handler instead — which is what
    /// `PolicyGate` alone would do — looks identical for about five minutes and
    /// then dead-letters every turn the company had pending. Any halt longer
    /// than a coffee break would come back to an empty queue and a customer's
    /// unanswered mail in [`dead_letters`].
    ///
    /// So the assertion is not merely "it was not claimed": it is **the attempt
    /// counter did not move**, which is the difference between deferred and
    /// destroyed.
    #[tokio::test]
    async fn a_stopped_company_s_events_wait_and_burn_no_attempt() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let stopped = seed_tenant(&db, "halt-stopped").await;
        let running = seed_tenant(&db, "halt-running").await;

        let waiting = enqueue_committed(&db, stopped, &event(1), at(T0)).await;
        enqueue_committed(&db, running, &event(2), at(T0)).await;

        let mut tx = db.tenant_tx(stopped).await.expect("tenant tx");
        crate::halt::place(&mut tx, "stop everything", "operator:ops", at(T0))
            .await
            .expect("place")
            .expect("it was running");
        tx.commit().await.expect("commit halt");

        // The poller drains every tenant. It sees one of these two.
        let mut conn = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim(&mut conn, 10, at(T0 + 1)).await.expect("claim");
        conn.commit().await.expect("commit claim");

        assert_eq!(
            claimed.len(),
            1,
            "only the running company's row: {claimed:?}"
        );
        assert_eq!(
            claimed[0].tenant_id, running,
            "and it is the one that was not stopped"
        );

        // The load-bearing half: the deferred row is untouched, so the halt
        // costs the customer nothing and there is nothing to replay.
        let mut conn = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let (attempts, available): (i32, DateTime<Utc>) =
            sqlx::query_as("SELECT attempt_count, available_at FROM outbox_events WHERE id = $1")
                .bind(waiting)
                .fetch_one(&mut *conn)
                .await
                .expect("read the deferred row");
        conn.commit().await.expect("commit read");
        assert_eq!(attempts, 0, "a deferred row burns no attempt");
        assert_eq!(
            available,
            at(T0),
            "and its backoff was not pushed out either: it is due the instant the \
             company is released"
        );

        // Released: the same row is claimed, in the state it was left in.
        let mut tx = db.tenant_tx(stopped).await.expect("tenant tx");
        crate::halt::release(&mut tx)
            .await
            .expect("release")
            .expect("it was halted");
        tx.commit().await.expect("commit release");

        // Claimed at the same instant as the first claim, so the running
        // company's row — pushed `LEASE_SECS` plus its own backoff out by the
        // claim that took it — is deterministically not due and this assertion
        // is about the deferred row alone.
        let mut conn = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let after = claim(&mut conn, 10, at(T0 + 1)).await.expect("claim");
        conn.commit().await.expect("commit claim");
        assert_eq!(
            after.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![waiting],
            "the release resumes exactly the work that was waiting"
        );
        assert_eq!(
            after[0].attempt_count, 1,
            "and it is on its FIRST attempt, not its second: the halt cost it nothing"
        );

        drop_tenant(&db, stopped).await;
        drop_tenant(&db, running).await;
    }

    /// **A company whose operating window ran out defers its queue too**, and a
    /// company still inside its window is not touched.
    ///
    /// The same support incident as the test above, arriving by the one door
    /// that had to be opened by hand. Every other reader of a stop asks
    /// `halt::halted`, which reports an exhausted window as a halt and needed no
    /// edit; this query cannot, because it is cross-tenant and runs on the
    /// clock its caller injects. So the predicate is written here against `$1`,
    /// and if it is ever dropped a company whose month ended has every queued
    /// piece of its work claimed, refused by the gate, and dead-lettered inside
    /// five minutes — the customer's unanswered mail destroyed by a schedule.
    ///
    /// Both tenants have a window, and that is the half that makes the test
    /// worth writing: one ended a second before the claim, one has an hour
    /// left. A predicate that skipped every tenant with a window at all, or one
    /// that compared against the wall clock instead of `$1`, would fail here and
    /// pass a test with only the expired one in it.
    #[tokio::test]
    async fn a_company_out_of_time_defers_its_queue_and_burns_no_attempt() {
        let Some(db) = db().await else { return };
        let _guard = OUTBOX_LOCK.lock().await;
        clear_outbox(&db).await;
        let expired = seed_tenant(&db, "window-expired").await;
        let inside = seed_tenant(&db, "window-inside").await;

        let waiting = enqueue_committed(&db, expired, &event(1), at(T0)).await;
        enqueue_committed(&db, inside, &event(2), at(T0)).await;

        set_window_committed(&db, expired, at(T0)).await;
        set_window_committed(&db, inside, at(T0 + 3600)).await;

        let mut conn = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let claimed = claim(&mut conn, 10, at(T0 + 1)).await.expect("claim");
        conn.commit().await.expect("commit claim");

        assert_eq!(
            claimed.len(),
            1,
            "only the company with time left: {claimed:?}"
        );
        assert_eq!(claimed[0].tenant_id, inside);

        let mut conn = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let (attempts, available): (i32, DateTime<Utc>) =
            sqlx::query_as("SELECT attempt_count, available_at FROM outbox_events WHERE id = $1")
                .bind(waiting)
                .fetch_one(&mut *conn)
                .await
                .expect("read the deferred row");
        conn.commit().await.expect("commit read");
        assert_eq!(attempts, 0, "a deferred row burns no attempt");
        assert_eq!(available, at(T0), "and its backoff was not pushed out");

        // Given more time, the same row is claimed in the state it was left in.
        // Extending is the window's only release verb — there is no
        // `DELETE /v1/window`, by 0054.
        set_window_committed(&db, expired, at(T0 + 7200)).await;
        let mut conn = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let after = claim(&mut conn, 10, at(T0 + 1)).await.expect("claim");
        conn.commit().await.expect("commit claim");
        assert_eq!(
            after.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![waiting],
            "more time resumes exactly the work that was waiting"
        );
        assert_eq!(
            after[0].attempt_count, 1,
            "on its FIRST attempt: running out of time cost it nothing"
        );

        drop_tenant(&db, expired).await;
        drop_tenant(&db, inside).await;
    }

    async fn set_window_committed(db: &Db, tenant: TenantId, ends_at: DateTime<Utc>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        crate::halt::set_window(&mut tx, ends_at, "operator:ops", at(T0))
            .await
            .expect("set the window");
        tx.commit().await.expect("commit window");
    }
}
