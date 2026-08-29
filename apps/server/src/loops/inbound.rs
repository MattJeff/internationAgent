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
//! ## What that filter costs, because no index carries it
//!
//! `aggregate_type` is a **filter**, not an index key. `outbox_events_claimable_idx`
//! is `(tenant_id, available_at, id) where published_at is null and attempt_count < 8`
//! — see `0057` — so `claim_of`'s inner `LIMIT` is a limit on *matching* rows, and
//! collecting `BATCH` inbound rows means walking that tenant's whole claimable
//! range until they turn up. When there are none, it walks all of it and returns
//! nothing. **The cost of this loop's tick is the size of the *other* poller's
//! backlog**, which is `0046`'s own failure — one population's rows becoming
//! another reader's latency — arriving through the one door neither `0046` nor
//! `0057` looked at, because the discriminating column is in neither index.
//!
//! Measured, PostgreSQL 17, one tenant, 123 420 events, median of five, the
//! claim returning zero rows every time:
//!
//! ```text
//! claimable rows of the other type   this loop's claim   the outbox poller's
//! -----------------------------------------------------------------------------
//!                              0            0.077 ms            0.063 ms
//!                            100            0.082 ms            0.188 ms
//!                          1 000            0.388 ms            0.293 ms
//!                         10 000            3.31  ms            0.294 ms
//!                        100 000           29.6   ms            0.368 ms
//! ```
//!
//! The asymmetry is the whole finding: the outbox poller is flat because its own
//! rows are the majority and it fills a batch immediately, and this loop — the
//! one deliberately ticking fastest, `IDLE` is 250 ms — pays for a queue it
//! does not own. Four replicas at 100 000 claimable rows is 0.5 s of database
//! time a second spent finding nothing.
//!
//! **Not closed here, and the number that says when to.** `attempt_count < 8`
//! bounds how long anything stays claimable — eight attempts under
//! `outbox::LEASE_SECS` plus the exponential is about twenty minutes — so
//! the claimable population is bounded by *throughput*, not by uptime, and it
//! does not grow with a seventeen-day run. At the deployed cadence
//! (`docs/orizn-roles/*.json`: 66 turns a day across five seats, five events a
//! turn) seventeen days is 5 610 events *in total*, and the worst reachable
//! burst is `outbox::requeue_dead_letters`, which zeroes every dead letter of a
//! tenant in one unbounded statement — a company that sat a fortnight with no
//! model connected parks about 1 100 turn events, and the operator connecting a
//! key makes all of them claimable at once. That is 0.4 ms a tick, not 30.
//!
//! So this is a note and not a migration. The index that closes it the day a
//! tenant really does hold five figures of claimable work is narrow — it carries
//! inbound rows only, so it is written once per notice and never for the events
//! that are the other 95 %:
//!
//! ```sql
//! create index outbox_events_inbound_claimable_idx
//!   on outbox_events (tenant_id, available_at, id)
//!   where published_at is null and attempt_count < 8
//!     and aggregate_type = 'inbound';
//! ```
//!
//! Built on the same fixture — 100 000 claimable rows, three of them inbound —
//! the claim goes from **27.2 ms to 0.110 ms** and the plan becomes an
//! `Index Only Scan using outbox_events_inbound_claimable_idx`, which is the
//! proof that the table above is about this column and not about the row count.
//! It is usable only from a **custom** plan, for the reason `claim_of` already
//! sets out at length about `attempt_count`: the predicate reaches the planner as
//! `($4 IS NULL OR aggregate_type = $4)` and only a bound value folds it.
//! `plan_cache_mode` is a cliff there too.
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
use agentos_app::inbound::{InboundError, InboundJob, Landed, NOTICE_AGGREGATE, ingest_email};
use agentos_store::db::{Db, StoreError};
use agentos_store::outbox::{self, Aggregates, OutboxEvent};
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

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
pub async fn run(db: Db, ports: Arc<Ports>, cancel: CancellationToken) {
    let pump = db.clone();
    drain(
        &pump,
        &move |job: InboundJob| {
            let (db, ports) = (db.clone(), ports.clone());
            // No blob store is threaded through here any more. Attachments are
            // filed into `agentos_app::files`, whose adapter is per-tenant —
            // and this loop is not: it drains every company's notices, so the
            // only place that can bind the classeur to a company is
            // `ingest_email`, which holds `job.tenant_id`.
            //
            // The provider is reached through `agentos_app`, never named here:
            // this crate does not depend on `agentos-providers` on purpose.
            async move { ingest_email(&db, &*ports.email, &job, Utc::now()).await }
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
        // `outbox::park`, not a private copy: the outbox poller makes the same
        // three-way decision now, and two spellings of one `UPDATE` is how the
        // claim got fixed in one loop and not the other.
        Outcome::Park(why) => outbox::park(&mut tx, event.id, &why).await,
    };
    if let Err(err) = written.and(tx.commit().await.map_err(StoreError::from)) {
        tracing::error!(error = %err, event_id = %event.id, "inbound outcome was not recorded");
    }
}

/// Take up to `limit` due **inbound notices**, across every tenant.
///
/// One line, and it used to be a copy of [`agentos_store::outbox::claim`] with
/// one predicate changed. That copy's own note said it should become
/// `outbox::claim_of` the moment a third caller wanted a filtered claim; what
/// actually forced it was not a third caller but a **fix that had to land in
/// both**. The shared claim is now round-robin over tenants rather than
/// first-in-first-out over the whole queue — see [`agentos_store::outbox::claim_of`]
/// for why a FIFO queue shared by paying customers is a customer whose company
/// stops because another customer is busy — and a second spelling of it here
/// would have been the inbound half of that bug, left in place, with a comment
/// on it saying the two were the same query.
///
/// Everything the old copy's docstring argued for is still argued, in the one
/// place the SQL now lives: `FOR UPDATE SKIP LOCKED`, `attempt_count + 1` at
/// claim time, the jittered backoff that is the lease, and `AS MATERIALIZED` on
/// every CTE.
async fn claim_notices(
    conn: &mut PgConnection,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<OutboxEvent>, StoreError> {
    outbox::claim_of(conn, Aggregates::Only(NOTICE_AGGREGATE), limit, now).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::inbound::{TURN_EVENT, contact_of, conversation_for, land};
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::message::{CanonicalMessage, Channel, Direction, ProviderRef};
    use agentos_domain::untrusted::Untrusted;
    use agentos_store::outbox::{MAX_ATTEMPTS, NewEvent};
    use chrono::TimeDelta;
    use serde_json::{Value, json};
    use tokio::sync::Mutex;
    use uuid::Uuid;

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

    /// This module's own database — see [`private_db`](crate::loops::private_db),
    /// which is the answer for all four loops and which the other three already
    /// take.
    ///
    /// This one was left on the suite's database, and the bill was not paid
    /// here. These tests tick a poller until its notices exhaust their
    /// attempts, which is the point of two of them — and an exhausted,
    /// unpublished event is a **dead letter**, which
    /// `agentos_store::outbox::dead_letters` reads across every tenant, because
    /// alerting on your own tenant's dead letters is not a thing an operator
    /// does.
    /// `store::outbox`'s `a_permanently_failing_handler_backs_off_then_dead_letters`
    /// asserts there is exactly one in the queue and found three, in a package
    /// that had never heard of the inbound loop.
    ///
    /// The `DELETE FROM outbox_events WHERE aggregate_type = $1` in [`seed`]
    /// below is the other half of why: it has a `WHERE`, so
    /// `crates/app/tests/scoped_deletes.rs` passes it, and it still reaches
    /// every tenant's notices. On a database of our own that is exactly what we
    /// mean; on a shared one it was deleting rows out from under whoever else
    /// was mid-assertion.
    async fn db() -> Option<Db> {
        crate::loops::private_db("inbound").await
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

    // -- the stop ------------------------------------------------------------

    /// **A stop stops receiving too, at both gates, and this is what
    /// `routes::halt` now says.**
    ///
    /// That module promised the opposite for four waves — "the inbound loop
    /// keeps fetching mail and landing it in `messages`" — and the promise was
    /// never true after `claim_of` moved the halt onto the `tenants` driver. A
    /// stopped tenant offers no seat, so *none* of its rows are claimed, and
    /// the notice partition is not exempt from that.
    ///
    /// Both gates, because receiving is two claims and stopping either one
    /// stops the mail:
    ///
    /// * the **raw delivery** (`webhooks::RAW_AGGREGATE`) the edge stored, which
    ///   the general poller claims and turns into a notice;
    /// * the **notice** (`NOTICE_AGGREGATE`) this loop claims and turns into a
    ///   `messages` row.
    ///
    /// Fixing only the second one would change nothing at all — no notice is
    /// ever written while the first is deferred — which is the thing a reader
    /// of that paragraph most needs to be told.
    ///
    /// **What this asserts is that nothing is lost, not that nothing waits.**
    /// No attempt is burned, neither row is a dead letter, and the release
    /// drains both. What the release cannot recover is the part that was never
    /// ours: the body and the attachments are at the provider until phase two
    /// fetches them, and `routes::halt` carries the founder's question about how
    /// long they stay there.
    #[tokio::test]
    async fn a_stop_defers_receiving_at_both_gates_and_the_release_drains_it() {
        use crate::routes::webhooks::{RAW_AGGREGATE, received_event};

        let Some(db) = db().await else { return };
        let _guard = INBOUND_LOCK.lock().await;
        let (tenant, employee) = seed(&db).await;
        let now = Utc::now();

        // Gate one: what `POST /v1/webhooks/{provider}` stores. The edge writes
        // this whatever the halt says — it is a route, not a claim — so the
        // envelope is durable here and the deferral starts at the poller.
        let raw = {
            let event = NewEvent {
                aggregate_type: RAW_AGGREGATE.to_owned(),
                aggregate_id: Uuid::nil(),
                event_type: received_event("resend"),
                dedupe_key: Some(format!("resend:evt_{}", tenant.as_uuid().simple())),
                payload: json!({ "provider": "resend", "body": "{}" }),
                traceparent: None,
            };
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let id = outbox::enqueue(&mut tx, &event, now)
                .await
                .expect("enqueue raw delivery");
            tx.commit().await.expect("commit raw delivery");
            id
        };
        // Gate two: the notice that gate one would have produced.
        let notice = deliver_webhook(
            &db,
            tenant,
            employee,
            "email_halted",
            notice_payload("email_halted", now),
            now,
        )
        .await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        agentos_store::halt::place(&mut tx, "the CFO called", "operator:ops", now)
            .await
            .expect("place")
            .expect("the tenant was running");
        tx.commit().await.expect("commit halt");

        // Neither poller sees the tenant at all.
        let ingest = |job| land_job(&db, job, now);
        assert_eq!(
            tick(&db, &ingest, now).await.expect("tick"),
            0,
            "the notice claim is driven by `tenants` and a stopped tenant offers no seat"
        );
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let general = outbox::claim_except(&mut tx, Some(NOTICE_AGGREGATE), 32, now)
            .await
            .expect("claim");
        tx.rollback().await.expect("rollback");
        assert!(
            general.iter().all(|event| event.tenant_id != tenant),
            "the raw delivery is deferred by the same clause, one step earlier"
        );
        assert_eq!(messages(&db, tenant).await, 0, "so nothing lands");

        // Deferred, which is the half that makes it survivable: no attempt was
        // burned, so a halt of any length costs the queue nothing.
        for (id, what) in [(raw, "the raw delivery"), (notice, "the notice")] {
            let (attempts, error, published) = notice_row(&db, id).await;
            assert_eq!(attempts, 0, "{what} burned an attempt while nobody ran it");
            assert_eq!(error, None, "{what} recorded a failure that never happened");
            assert!(
                published.is_none(),
                "{what} was published by a stopped company"
            );
        }
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let dead = outbox::dead_letters(&mut tx, 100).await.expect("dead");
        tx.rollback().await.expect("rollback");
        assert!(
            dead.iter().all(|event| event.tenant_id != tenant),
            "a stop must never dead-letter a customer's mail"
        );

        // And the release makes them due at once, in our own database. Nothing
        // here can say the same about the body still sitting at the provider.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        agentos_store::halt::release(&mut tx)
            .await
            .expect("release")
            .expect("it was stopped");
        tx.commit().await.expect("commit release");

        assert_eq!(
            tick(&db, &ingest, now).await.expect("tick"),
            1,
            "the release has to drain the mail the halt deferred"
        );
        assert_eq!(messages(&db, tenant).await, 1);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let general = outbox::claim_except(&mut tx, Some(NOTICE_AGGREGATE), 32, now)
            .await
            .expect("claim");
        tx.rollback().await.expect("rollback");
        assert!(
            general.iter().any(|event| event.id == raw),
            "and the raw delivery with it"
        );
    }

    // -- concurrency --------------------------------------------------------

    /// **Two pollers, and the bound is the thing under test.**
    ///
    /// [`claim_notices`]' docstring says every part of its predicate is
    /// load-bearing and names `FOR UPDATE SKIP LOCKED` first. `SKIP LOCKED` is
    /// not what this asserts, because `SKIP LOCKED` was never the part that
    /// broke: `agentos_store::initiative::claim_due` documents the same query
    /// shape claiming 13 and then 16 employees against a limit of 10, with the
    /// two claims **disjoint** throughout. A non-correlated
    /// `WHERE id IN (SELECT … ORDER BY … FOR UPDATE SKIP LOCKED LIMIT $n)` may
    /// be planned as a subplan that is re-executed per outer row, and each
    /// re-execution steps over whatever the *other* poller holds locked right
    /// then — so the `UPDATE` touches the union of those sets rather than `$n`
    /// rows. `agentos_store::outbox::claim_except` and
    /// `agentos_store::initiative::claim_due` both spell the selection
    /// `WITH due AS MATERIALIZED (…)` for exactly this; **this one did not**,
    /// which is what this test was written against and what
    /// [`claim_notices`] now does too.
    ///
    /// The bound is what a notice claim can least afford to lose. `BATCH` is 8
    /// because one notice is a body fetch plus every attachment, and the module
    /// says so in as many words: "a lease held longer than the backoff is a row
    /// two workers both think they own". A poller that leases 24 has silently
    /// stopped bounding the batch it will hold leases across — which is
    /// precisely what this asserts and what widening the `LIMIT` by three makes
    /// it report.
    ///
    /// Two pollers claim *repeatedly and unsynchronised*, which is the only
    /// arrangement that reaches it. One barrier-synchronised claim each cannot:
    /// the inner subquery only returns a different set when the other session's
    /// lock set changes **between two re-executions of the same statement**, so
    /// the other poller has to be taking and releasing locks throughout, which
    /// is what a running loop does and what a single held claim does not. That
    /// is why this is a race with a deadline rather than two barriers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_pollers_each_claim_no_more_than_their_batch() {
        let Some(db) = db().await else { return };
        let _guard = INBOUND_LOCK.lock().await;
        let (tenant, employee) = seed(&db).await;

        // Far more than the two pollers can drain in the window, so a claim that
        // comes back short is a bound and not an empty queue.
        const NOTICES: usize = 600;
        const LIMIT: i64 = BATCH;
        let now = Utc::now();
        for n in 0..NOTICES {
            let id = format!("email_bound_{n}");
            deliver_webhook(&db, tenant, employee, &id, notice_payload(&id, now), now).await;
        }

        /// Claim in a tight loop until `deadline`, and report the largest batch
        /// any one statement came back with.
        async fn hammer(db: Db, now: DateTime<Utc>, deadline: tokio::time::Instant) -> usize {
            let mut worst = 0;
            while tokio::time::Instant::now() < deadline {
                let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
                // **The plan is forced, and forcing it is the honest half of
                // this test.** Postgres 17 costs this statement into a
                // `Hash Semi Join` on the row counts these tests leave behind,
                // and a hashed subquery runs once — so the bound holds today for
                // a reason that is not in the SQL. `SET LOCAL
                // enable_hashjoin/mergejoin/hashagg = off` makes the planner
                // pick the other legal plan for the *same statement*: a
                // `Nested Loop Semi Join` with the `LIMIT`-ed, `SKIP LOCKED`
                // subquery on the **inner** side, re-executed per outer row.
                // `EXPLAIN` on the unmodified production text produces exactly
                // that plan on this schema, so nothing here is a test-only
                // query — the planner may choose it on its own the first time
                // the statistics move. A `WITH … AS MATERIALIZED` selection is
                // bounded under every plan, which is why all three claims are
                // now spelled that way and why these knobs stay: they keep the
                // guard honest if somebody ever unspells one.
                for guc in [
                    "SET LOCAL enable_hashjoin = off",
                    "SET LOCAL enable_mergejoin = off",
                    "SET LOCAL enable_hashagg = off",
                ] {
                    sqlx::query(guc).execute(&mut *tx).await.expect("plan knob");
                }
                let got = claim_notices(&mut tx, LIMIT, now).await.expect("claim");
                tx.commit().await.expect("commit");
                worst = worst.max(got.len());
                if got.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            worst
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let a = tokio::spawn(hammer(db.clone(), now, deadline));
        let b = tokio::spawn(hammer(db.clone(), now, deadline));
        let (a, b) = (a.await.expect("poller a"), b.await.expect("poller b"));

        // Neither was starved, so the assertion below is about the LIMIT and
        // not about an empty queue.
        assert!(a > 0 && b > 0, "a poller never claimed anything: {a}, {b}");
        assert!(
            a as i64 <= LIMIT && b as i64 <= LIMIT,
            "a claim leased more than its batch: {a} and {b} against a limit of {LIMIT}"
        );
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
