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
pub const MAX_ATTEMPTS: i32 = 8;

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
/// * `available_at` pushed out by an exponential backoff with jitter — the
///   lease. `2^attempt` seconds, capped at an hour, multiplied by a random
///   factor in `[0.5, 1.5)` so that a thousand events queued by one outage do
///   not come back in a thundering herd.
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
    claim_except(conn, None, limit, now).await
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
pub async fn claim_except(
    conn: &mut PgConnection,
    skip_aggregate: Option<&str>,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<OutboxEvent>, StoreError> {
    let rows = sqlx::query(
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
        "WITH due AS MATERIALIZED ( \
             SELECT id FROM outbox_events \
             WHERE published_at IS NULL \
               AND available_at <= $1::timestamptz \
               AND attempt_count < $2::int \
               AND ($4::text IS NULL OR aggregate_type <> $4::text) \
             ORDER BY available_at, id \
             FOR UPDATE SKIP LOCKED \
             LIMIT $3::bigint) \
         UPDATE outbox_events AS e \
         SET attempt_count = e.attempt_count + 1, \
             available_at = $1::timestamptz \
                 + least(interval '1 second' \
                         * power(2::double precision, e.attempt_count::double precision), \
                         interval '1 hour') \
                   * (0.5 + random()) \
         WHERE e.id IN (SELECT id FROM due) \
         RETURNING e.id, e.tenant_id, e.aggregate_type, e.aggregate_id, e.event_type, \
                   e.payload, e.attempt_count, e.available_at, e.last_error",
    )
    .bind(now)
    .bind(MAX_ATTEMPTS)
    .bind(limit)
    .bind(skip_aggregate)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows.iter().map(OutboxEvent::from_row).collect())
}

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

        // 2^(attempt-1) seconds with jitter in [0.5, 1.5), capped at an hour.
        for (i, delay) in delays.iter().enumerate() {
            let base = 2f64.powi(i as i32).min(3600.0);
            let secs = delay.as_seconds_f64();
            assert!(
                secs >= base * 0.5 && secs < base * 1.5,
                "attempt {} backed off {secs}s, expected [{}, {})",
                i + 1,
                base * 0.5,
                base * 1.5
            );
        }
        // It really did grow — the first wait is about a second, the last is
        // minutes. (Jitter overlaps between adjacent attempts, so compare ends.)
        assert!(
            delays[delays.len() - 1] > delays[0] * 10,
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
}
