//! The inbound loop: stored webhook notices become agent turns.
//!
//! ```text
//! admin tx:   claim(BATCH, now) ; COMMIT        <- cross-tenant, SKIP LOCKED
//!   per notice:
//!     InboundJob::from_event                     <- unusable payload -> park
//!     ingest_email                               <- fetch body, then bytes, then land
//!     admin tx:  mark_done | mark_failed | park ; COMMIT
//! sleep(IDLE) unless the batch came back full
//! ```
//!
//! # Why this is a second poller and not a handler in the outbox one
//!
//! Everything else in `outbox_events` is a side effect we decided to perform.
//! A row with `aggregate_type = 'inbound'` is the opposite: it is work someone
//! else handed us, its slow half is two provider round trips, and its failure
//! modes are somebody else's ("the body is not there yet"). Draining it on its
//! own claim keeps a Resend outage from sitting in front of a queue of
//! approvals — and keeps this loop's batch size tunable against attachment
//! downloads rather than against sending SMS.
//!
//! The claim is filtered on `aggregate_type`, so the two pollers take disjoint
//! rows and `SKIP LOCKED` does the rest.
//!
//! # Two phases, and the hour that runs out
//!
//! [`ingest_email`] is the phase-two half described in [`agentos_app::inbound`]:
//! metadata is all the webhook carried, the body is fetched here, and the
//! attachment bytes are fetched **immediately after** the body because the
//! provider's `download_url` dies an hour after it is minted. This loop's job
//! is to not add latency in front of that — which is why the claim commits
//! before the fetch and the batch is small.
//!
//! # A message is never dropped
//!
//! Three outcomes, and only one of them stops:
//!
//! * **landed** — `mark_done`, and the `messages` row plus its
//!   `agent.turn.requested` event committed together inside `ingest_email`.
//! * **retryable** (the provider has not materialised the message yet, a 5xx, a
//!   serialization failure) — `mark_failed` records why and the claim's own
//!   backoff hands the row back later.
//! * **terminal** (a payload no build can turn into a job, an address nobody
//!   owns, a body that will not normalise) — [parked][park]: the error is
//!   written down and the attempt counter is burned out, so the row stays in
//!   `outbox_events`, unpublished, and surfaces in
//!   [`outbox::dead_letters`](agentos_store::outbox::dead_letters) for whoever
//!   is on call. Retrying it forever would spin; deleting it would lose a
//!   customer's email.
//!
//! # Exactly once, across a restart
//!
//! The claim commits before the ingest runs, so a pod killed mid-drain loses
//! its lease rather than its work: the row becomes claimable again once the
//! backoff expires, and the second ingest finds the message already landed and
//! re-reads the *same* turn event instead of queueing a second one. Both
//! guards are `agentos_app::inbound`'s and both key on the same dedupe key.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use agentos_app::effects::Ports;
use agentos_app::inbound::{
    BlobStore, InboundError, InboundJob, Landed, NOTICE_AGGREGATE, ingest_email,
};
use agentos_domain::ids::TenantId;
use agentos_store::db::{Db, StoreError};
use agentos_store::outbox::{self, MAX_ATTEMPTS, OutboxEvent};
use chrono::{DateTime, Utc};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

/// Notices taken per claim.
///
/// Deliberately smaller than the outbox poller's: one notice is a body fetch
/// plus every attachment, so a batch is seconds rather than milliseconds, and a
/// lease held longer than the backoff is a row two workers both think they own.
const BATCH: i64 = 8;

/// How long to wait after finding nothing to do. This is the delay between a
/// webhook being accepted and the agent waking up, so it is short.
const IDLE: Duration = Duration::from_millis(250);

/// Drain inbound notices until `cancel` fires.
///
/// Spawn one per replica; two on the same database is a supported configuration
/// and the reason the claim is `SKIP LOCKED`.
pub async fn run(db: Db, ports: Arc<Ports>, blobs: Arc<dyn BlobStore>, cancel: CancellationToken) {
    let pump = db.clone();
    drain(
        &pump,
        &move |job: InboundJob| {
            let (db, ports, blobs) = (db.clone(), ports.clone(), blobs.clone());
            // The provider is reached through `agentos_app`, never named here:
            // this crate does not depend on `agentos-providers` on purpose.
            async move { ingest_email(&db, &*ports.email, &*blobs, &job, Utc::now()).await }
        },
        cancel,
    )
    .await;
}

/// The loop itself, over whatever turns a claimed job into a landed message.
///
/// ponytail: `ingest` is a generic rather than `Ports` inlined into the loop so
/// that the claim/park/retry decisions can be tested without a live Resend —
/// and because this crate cannot name `EmailProvider` to write a double against
/// it. There is exactly one production implementation and it is in [`run`].
async fn drain<H, F>(db: &Db, ingest: &H, cancel: CancellationToken)
where
    H: Fn(InboundJob) -> F,
    F: Future<Output = Result<Landed, InboundError>>,
{
    tracing::info!("inbound loop started");

    loop {
        let claimed = match tick(db, ingest, Utc::now()).await {
            Ok(claimed) => claimed,
            Err(err) => {
                // Unreachable database or a lost race. Both are survivable by
                // waiting, which is what the sleep below does; exiting would
                // take inbound mail down with the blip.
                tracing::error!(error = %err, "inbound claim failed");
                0
            }
        };

        // Finish the batch we already leased, then stop. Anything still queued
        // is still queued — it is a row, not in-memory state.
        if cancel.is_cancelled() {
            break;
        }
        // A full batch means there is more waiting right now.
        if claimed == BATCH as usize {
            continue;
        }

        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }

    tracing::info!("inbound loop stopped");
}

/// One pass: claim a batch of notices and ingest them. Returns how many were
/// claimed, so the caller can tell a drained queue from a busy one.
async fn tick<H, F>(db: &Db, ingest: &H, now: DateTime<Utc>) -> Result<usize, StoreError>
where
    H: Fn(InboundJob) -> F,
    F: Future<Output = Result<Landed, InboundError>>,
{
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let batch = claim_notices(&mut tx, BATCH, now).await?;
    // Before the first fetch, always: `SKIP LOCKED` only hides a row while the
    // claiming transaction is open, and holding one across a provider call is
    // holding a row lock across the internet.
    tx.commit().await?;

    for event in &batch {
        // `instrument`, not an entered guard: a guard held across an await
        // decorates whatever task the executor resumes next.
        let span = tracing::info_span!(
            "inbound_notice",
            event_id = %event.id,
            tenant_id = %event.tenant_id,
            attempt = event.attempt_count,
            traceparent = event.traceparent().unwrap_or_default(),
        );
        handle(db, ingest, event, now).instrument(span).await;
    }
    Ok(batch.len())
}

/// Ingest one claimed notice and record what became of it.
async fn handle<H, F>(db: &Db, ingest: &H, event: &OutboxEvent, now: DateTime<Utc>)
where
    H: Fn(InboundJob) -> F,
    F: Future<Output = Result<Landed, InboundError>>,
{
    let job = match InboundJob::from_event(event) {
        Ok(job) => job,
        // No retry will make this payload parse. Somebody has to look at it.
        Err(err) => {
            tracing::error!(code = err.code(), error = %err, "unusable inbound notice parked");
            return record(db, event, Outcome::Park(err.to_string()), now).await;
        }
    };

    let outcome = match ingest(job).await {
        Ok(landed) => {
            tracing::info!(
                message_id = %landed.message_id,
                conversation_id = %landed.conversation_id,
                turn_event_id = %landed.turn_event_id,
                duplicate = landed.duplicate,
                "inbound message landed"
            );
            Outcome::Done
        }
        Err(err) if err.is_retryable() => {
            tracing::warn!(code = err.code(), error = %err, "inbound ingest will be retried");
            Outcome::Retry(err.to_string())
        }
        Err(err) => {
            tracing::error!(code = err.code(), error = %err, "inbound notice parked");
            Outcome::Park(err.to_string())
        }
    };
    record(db, event, outcome, now).await;
}

/// What the loop decided about one notice. The `String` is the reason, written
/// to `last_error` for whoever reads it back — never third-party text: every
/// [`InboundError`] renders from a fixed set of authored messages.
enum Outcome {
    /// It landed. Publish the event.
    Done,
    /// Try again on the claim's own backoff.
    Retry(String),
    /// It will never land. Keep the row and stop retrying it.
    Park(String),
}

/// Write the outcome down, in its own short transaction.
///
/// Failing to record is logged and swallowed: the row keeps its lease and comes
/// back, which for a landed message is a duplicate ingest that
/// `agentos_app::inbound` already collapses. Stopping the loop over bookkeeping
/// would be the more expensive mistake.
async fn record(db: &Db, event: &OutboxEvent, outcome: Outcome, now: DateTime<Utc>) {
    let mut tx = match db.admin_tx_bypassing_rls().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(error = %err, event_id = %event.id, "no connection to record outcome");
            return;
        }
    };

    let written = match outcome {
        Outcome::Done => outbox::mark_done(&mut tx, event.id, now).await,
        Outcome::Retry(why) => outbox::mark_failed(&mut tx, event.id, &why).await,
        Outcome::Park(why) => park(&mut tx, event.id, &why).await,
    };
    if let Err(err) = written.and(tx.commit().await.map_err(StoreError::from)) {
        tracing::error!(error = %err, event_id = %event.id, "inbound outcome was not recorded");
    }
}

/// Stop retrying a notice without losing it.
///
/// ponytail: burning the attempt counter *is* the dead-letter state — see
/// [`agentos_store::outbox`], which has no `dead_lettered_at` column and filters
/// on `attempt_count` in both [`claim`](outbox::claim) and
/// [`dead_letters`](outbox::dead_letters). So a park is one `UPDATE`: the row
/// stays, unpublished, with the reason attached, and no poller will pick it up
/// again. `greatest` because a park must never *lower* an attempt count.
async fn park(conn: &mut PgConnection, id: Uuid, why: &str) -> Result<(), StoreError> {
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

/// Take up to `limit` due **inbound notices**, across every tenant.
///
/// The body is [`agentos_store::outbox::claim`] with one extra predicate, and it
/// is here rather than there because `agentos_store` belongs to another unit.
/// ponytail: the moment a third caller wants a filtered claim, this becomes
/// `outbox::claim_of(conn, aggregate_type, limit, now)` and this function goes
/// away. Until then, one query beats an edit to a file six agents are in.
///
/// Everything the predicate keeps is load-bearing: `FOR UPDATE SKIP LOCKED` so
/// pollers take disjoint rows, `attempt_count + 1` at *claim* time so a worker
/// killed mid-ingest still burns an attempt, and `available_at` pushed out by an
/// exponential backoff with jitter — the lease, which expires on its own.
async fn claim_notices(
    conn: &mut PgConnection,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<OutboxEvent>, StoreError> {
    let rows = sqlx::query(
        "UPDATE outbox_events AS e \
         SET attempt_count = e.attempt_count + 1, \
             available_at = $1::timestamptz \
                 + least(interval '1 second' \
                         * power(2::double precision, e.attempt_count::double precision), \
                         interval '1 hour') \
                   * (0.5 + random()) \
         WHERE e.id IN ( \
             SELECT id FROM outbox_events \
             WHERE aggregate_type = $4::text \
               AND published_at IS NULL \
               AND available_at <= $1::timestamptz \
               AND attempt_count < $2::int \
             ORDER BY available_at, id \
             FOR UPDATE SKIP LOCKED \
             LIMIT $3::bigint) \
         RETURNING e.id, e.tenant_id, e.aggregate_type, e.aggregate_id, e.event_type, \
                   e.payload, e.attempt_count, e.available_at, e.last_error",
    )
    .bind(now)
    .bind(MAX_ATTEMPTS)
    .bind(limit)
    .bind(NOTICE_AGGREGATE)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows.iter().map(event_from_row).collect())
}

/// `OutboxEvent` has public fields but no public row constructor, so the claim
/// above rebuilds one. Column names match the `RETURNING` list.
fn event_from_row(row: &PgRow) -> OutboxEvent {
    OutboxEvent {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::inbound::{TURN_EVENT, contact_of, conversation_for, land};
    use agentos_domain::ids::EmployeeId;
    use agentos_domain::message::{CanonicalMessage, Channel, Direction, ProviderRef};
    use agentos_domain::untrusted::Untrusted;
    use agentos_store::outbox::NewEvent;
    use chrono::TimeDelta;
    use serde_json::{Value, json};
    use tokio::sync::Mutex;

    use super::*;

    /// The claim is cross-tenant — that is the poller's whole job — so a test
    /// that ticks can see notices another test queued. `cargo test` runs them in
    /// parallel, so everything here goes one at a time.
    static INBOUND_LOCK: Mutex<()> = Mutex::const_new(());

    /// The event type `agentos_app::inbound::record_notice` writes.
    ///
    /// Spelled out rather than imported: it is
    /// `agentos_providers::email::InboundNotice::EVENT`, and this crate does not
    /// depend on `agentos-providers` by design. `InboundJob::from_event` is the
    /// thing that checks it, so a drift here fails these tests loudly.
    const NOTICE_EVENT: &str = "email.received";

    const SENDER: &str = "Accounts <AP@Supplier.example>";

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the inbound loop needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one employee, and a clean slate of inbound notices so a
    /// previously crashed run cannot be claimed by this one.
    async fn seed(db: &Db) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("loop-inbound-{}", tenant.as_uuid().simple());

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM outbox_events WHERE aggregate_type = $1")
            .bind(NOTICE_AGGREGATE)
            .execute(&mut *tx)
            .await
            .expect("clear notices");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
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

    /// One verified webhook, stored the way `record_notice` stores it.
    async fn deliver_webhook(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        provider_message_id: &str,
        payload: Value,
        now: DateTime<Utc>,
    ) -> Uuid {
        let key = CanonicalMessage::dedupe_key(
            employee,
            Channel::Email,
            &ProviderRef::new(provider_message_id),
        );
        let event = NewEvent {
            aggregate_type: NOTICE_AGGREGATE.to_owned(),
            aggregate_id: employee.as_uuid(),
            event_type: NOTICE_EVENT.to_owned(),
            dedupe_key: Some(key.as_str().to_owned()),
            payload,
            traceparent: None,
        };

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let id = outbox::enqueue(&mut tx, &event, now)
            .await
            .expect("enqueue notice");
        tx.commit().await.expect("commit notice");
        id
    }

    fn notice_payload(provider_message_id: &str, now: DateTime<Utc>) -> Value {
        json!({
            "channel": "email",
            "provider_message_id": provider_message_id,
            "from": SENDER,
            "received_at": now,
        })
    }

    /// Stands in for `ingest_email`: everything after the provider round trip,
    /// which is the part this loop is responsible for not duplicating. It calls
    /// the same `conversation_for` + `land` the real one does, so the dedupe
    /// under test is the production dedupe.
    async fn land_job(
        db: &Db,
        job: InboundJob,
        now: DateTime<Utc>,
    ) -> Result<Landed, InboundError> {
        let from = Untrusted::new(SENDER.to_owned());
        let mut tx = db.tenant_tx(job.tenant_id).await?;
        let conversation_id = conversation_for(
            &mut tx,
            job.employee_id,
            Channel::Email,
            &contact_of(&from),
            None,
            now,
        )
        .await?;

        let message = CanonicalMessage {
            tenant_id: job.tenant_id,
            employee_id: job.employee_id,
            conversation_id,
            idempotency_key: job.dedupe_key(),
            provider_message_id: job.provider_message_id.clone(),
            channel: Channel::Email,
            direction: Direction::Inbound,
            received_at: now,
            from,
            subject: None,
            body_text: Untrusted::new("the body the webhook did not carry".to_owned()),
            attachments: vec![],
        };
        let landed = land(&mut tx, &message, now).await?;
        tx.commit().await?;
        Ok(landed)
    }

    async fn count(db: &Db, tenant: TenantId, sql: &'static str) -> i64 {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let n: i64 = sqlx::query_scalar(sql)
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.commit().await.expect("commit read");
        n
    }

    async fn messages(db: &Db, tenant: TenantId) -> i64 {
        count(db, tenant, "SELECT count(*) FROM messages").await
    }

    async fn turns(db: &Db, tenant: TenantId) -> i64 {
        count(
            db,
            tenant,
            "SELECT count(*) FROM outbox_events WHERE event_type = 'agent.turn.requested'",
        )
        .await
    }

    /// The stored notice as an operator would read it back.
    async fn notice_row(db: &Db, id: Uuid) -> (i32, Option<String>, Option<DateTime<Utc>>) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let row = sqlx::query_as(
            "SELECT attempt_count, last_error, published_at FROM outbox_events WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .expect("read notice");
        tx.rollback().await.expect("rollback");
        row
    }

    // -- one webhook, however many deliveries -------------------------------

    /// The chaos case every provider produces: the same webhook, three times.
    /// One row to claim, one message, one turn.
    #[tokio::test]
    async fn three_deliveries_of_one_webhook_produce_exactly_one_turn() {
        let Some(db) = db().await else { return };
        let _guard = INBOUND_LOCK.lock().await;
        let (tenant, employee) = seed(&db).await;
        let now = Utc::now();

        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(
                deliver_webhook(
                    &db,
                    tenant,
                    employee,
                    "email_1",
                    notice_payload("email_1", now),
                    now,
                )
                .await,
            );
        }
        assert_eq!(ids[0], ids[1], "redelivery must not mint a second notice");
        assert_eq!(ids[0], ids[2]);

        let ingest = |job| land_job(&db, job, now);
        assert_eq!(tick(&db, &ingest, now).await.expect("tick"), 1);

        assert_eq!(messages(&db, tenant).await, 1, "exactly one message");
        assert_eq!(turns(&db, tenant).await, 1, "exactly one agent turn");
        assert_eq!(
            count(&db, tenant, "SELECT count(*) FROM conversations").await,
            1
        );

        // Published, and gone from every future claim.
        let (_, error, published) = notice_row(&db, ids[0]).await;
        assert!(published.is_some(), "a landed notice must be published");
        assert_eq!(error, None);
        assert_eq!(
            tick(&db, &ingest, now + TimeDelta::days(1))
                .await
                .expect("tick"),
            0
        );
    }

    // -- failures that must not lose a message ------------------------------

    /// Two shapes of "this will never normalise": a payload no build can turn
    /// into a job, and an ingest that fails terminally. Both keep the row.
    #[tokio::test]
    async fn a_normalization_failure_parks_the_notice_instead_of_losing_it() {
        let Some(db) = db().await else { return };
        let _guard = INBOUND_LOCK.lock().await;
        let (tenant, employee) = seed(&db).await;
        let now = Utc::now();

        // No `provider_message_id`: `InboundJob::from_event` refuses it.
        let unusable = deliver_webhook(
            &db,
            tenant,
            employee,
            "email_bad",
            json!({ "channel": "email" }),
            now,
        )
        .await;
        // A notice that parses but cannot be landed.
        let unroutable = deliver_webhook(
            &db,
            tenant,
            employee,
            "email_2",
            notice_payload("email_2", now),
            now,
        )
        .await;

        let ingest = |_: InboundJob| async { Err(InboundError::UnknownRecipient) };
        assert_eq!(tick(&db, &ingest, now).await.expect("tick"), 2);

        for (id, what) in [(unusable, "unusable payload"), (unroutable, "unroutable")] {
            let (attempts, error, published) = notice_row(&db, id).await;
            assert!(published.is_none(), "{what}: parking is not publishing");
            assert!(
                attempts >= MAX_ATTEMPTS,
                "{what}: a parked notice must not be claimed again"
            );
            assert!(
                error.is_some_and(|err| !err.is_empty()),
                "{what}: park without a reason is a mystery at 3am"
            );
        }

        // Nothing landed, nothing woke the agent, and nothing is retried —
        // not now, not in a year.
        assert_eq!(messages(&db, tenant).await, 0);
        assert_eq!(turns(&db, tenant).await, 0);
        assert_eq!(
            tick(&db, &ingest, now + TimeDelta::days(365))
                .await
                .expect("tick"),
            0
        );

        // But it is still there, and it is on somebody's dead-letter list.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let dead = outbox::dead_letters(&mut tx, 100).await.expect("dead");
        tx.rollback().await.expect("rollback");
        let parked: Vec<Uuid> = dead.iter().map(|e| e.id).collect();
        assert!(parked.contains(&unusable), "{parked:?}");
        assert!(parked.contains(&unroutable), "{parked:?}");
    }

    /// The two-phase reality: the webhook beats its own body. That is a retry,
    /// not a park, and the message lands when the provider catches up.
    #[tokio::test]
    async fn a_body_that_is_not_there_yet_is_retried_not_parked() {
        let Some(db) = db().await else { return };
        let _guard = INBOUND_LOCK.lock().await;
        let (tenant, employee) = seed(&db).await;
        let now = Utc::now();

        let id = deliver_webhook(
            &db,
            tenant,
            employee,
            "email_3",
            notice_payload("email_3", now),
            now,
        )
        .await;

        let too_early = |_: InboundJob| async { Err(InboundError::NotReady) };
        assert_eq!(tick(&db, &too_early, now).await.expect("tick"), 1);

        let (attempts, error, published) = notice_row(&db, id).await;
        assert!(published.is_none());
        assert!(attempts < MAX_ATTEMPTS, "a retry must not burn the counter");
        assert!(error.is_some(), "the reason belongs in last_error");
        assert_eq!(turns(&db, tenant).await, 0);

        // Immediately due again? Then the backoff did not happen.
        assert_eq!(tick(&db, &too_early, now).await.expect("tick"), 0);

        // The body catches up; the same notice is still queued.
        let later = now + TimeDelta::hours(2);
        let ingest = |job| land_job(&db, job, later);
        assert_eq!(tick(&db, &ingest, later).await.expect("tick"), 1);
        assert_eq!(messages(&db, tenant).await, 1);
        assert_eq!(turns(&db, tenant).await, 1);
        assert!(notice_row(&db, id).await.2.is_some());
    }

    /// A pod killed between landing a message and publishing its notice. The
    /// lease expires, the notice is claimed again, and the second ingest must
    /// find the message rather than write a second turn.
    #[tokio::test]
    async fn a_restart_mid_drain_does_not_duplicate_turns() {
        let Some(db) = db().await else { return };
        let _guard = INBOUND_LOCK.lock().await;
        let (tenant, employee) = seed(&db).await;
        let now = Utc::now();

        let id = deliver_webhook(
            &db,
            tenant,
            employee,
            "email_4",
            notice_payload("email_4", now),
            now,
        )
        .await;

        // Lands the message, then "dies" before the outcome is recorded.
        let handle = &db;
        let killed = move |job: InboundJob| async move {
            land_job(handle, job, now).await?;
            Err::<Landed, _>(InboundError::NotReady)
        };
        assert_eq!(tick(&db, &killed, now).await.expect("tick"), 1);

        assert_eq!(messages(&db, tenant).await, 1);
        assert_eq!(turns(&db, tenant).await, 1);
        let first_turn: Uuid = {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let turn = sqlx::query_scalar(
                "SELECT id FROM outbox_events WHERE event_type = $1 ORDER BY created_at LIMIT 1",
            )
            .bind(TURN_EVENT)
            .fetch_one(&mut **tx)
            .await
            .expect("turn id");
            tx.commit().await.expect("commit read");
            turn
        };
        assert!(notice_row(&db, id).await.2.is_none(), "not published yet");

        // The replacement pod picks the notice back up once the lease expires.
        let later = now + TimeDelta::hours(2);
        let ingest = |job| land_job(&db, job, later);
        assert_eq!(tick(&db, &ingest, later).await.expect("tick"), 1);

        assert_eq!(
            messages(&db, tenant).await,
            1,
            "the message was written twice"
        );
        assert_eq!(turns(&db, tenant).await, 1, "the agent was woken twice");
        assert!(notice_row(&db, id).await.2.is_some());

        // And it is the *same* turn, not a second one that happens to be alone.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let still: Uuid = sqlx::query_scalar("SELECT id FROM outbox_events WHERE event_type = $1")
            .bind(TURN_EVENT)
            .fetch_one(&mut **tx)
            .await
            .expect("turn id");
        tx.commit().await.expect("commit read");
        assert_eq!(still, first_turn);
    }

    // -- shutdown -----------------------------------------------------------

    /// The loop drains what is queued and then stops on the token, promptly —
    /// not on the next poll interval, and not never.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_loop_drains_then_stops_on_the_token() {
        let Some(db) = db().await else { return };
        let _guard = INBOUND_LOCK.lock().await;
        let (tenant, employee) = seed(&db).await;

        const NOTICES: i64 = 12; // more than one BATCH, so the fast path runs
        let now = Utc::now();
        for n in 0..NOTICES {
            let id = format!("email_drain_{n}");
            deliver_webhook(&db, tenant, employee, &id, notice_payload(&id, now), now).await;
        }

        let cancel = CancellationToken::new();
        let loops = tokio::spawn({
            let (db, cancel) = (db.clone(), cancel.clone());
            async move {
                drain(&db, &|job| land_job(&db, job, Utc::now()), cancel).await;
            }
        });

        // Wait for the queue to drain rather than for a duration.
        let drained = tokio::time::timeout(Duration::from_secs(20), async {
            while turns(&db, tenant).await < NOTICES {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        assert!(drained.is_ok(), "the loop did not drain the queue");
        assert_eq!(messages(&db, tenant).await, NOTICES);

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), loops)
            .await
            .expect("the token must stop the loop")
            .expect("the loop panicked");

        // A clean stop leaves nothing claimed-but-unpublished behind.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox_events \
              WHERE aggregate_type = $1 AND published_at IS NULL",
        )
        .bind(NOTICE_AGGREGATE)
        .fetch_one(&mut *tx)
        .await
        .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!(pending, 0);
    }
}
