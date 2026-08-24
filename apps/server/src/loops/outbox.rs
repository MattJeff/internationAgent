//! The outbox poller. This is what replaces the broker.
//!
//! ```text
//! admin tx:   claim(BATCH, now) ; COMMIT      <- cross-tenant, takes the lease
//!   per event:
//!     tenant tx:  handler(event, tx) ; mark_done ; COMMIT
//!     on failure: admin tx ; mark_failed ; COMMIT
//! sleep(IDLE) unless the batch came back full
//! ```
//!
//! Everything interesting about *claiming* — `FOR UPDATE SKIP LOCKED`, the
//! exponential backoff with jitter, the attempt counter that dead-letters a
//! poison message instead of spinning on it — lives in
//! [`agentos_store::outbox`] and is one SQL statement there. This module is the
//! part that cannot be SQL: pick a handler, give it a transaction, decide what
//! the outcome means.
//!
//! # Two transactions, and which work goes in which
//!
//! The claim commits before any handler runs. It has to: `SKIP LOCKED` only
//! hides a row for as long as the claiming transaction is open, so holding it
//! across a handler would mean holding a row lock across a network call to a
//! provider. What keeps the row to one worker instead is that the claim pushed
//! `available_at` into the future — a lease that expires by itself, so a poller
//! that dies mid-handler hands the row back without a reaper.
//!
//! The handler then runs in a **tenant** transaction, not the admin one. The
//! poller is cross-tenant by nature, but the work it dispatches is not: opening
//! `tenant_tx(event.tenant_id)` puts `app.tenant_id` back in place so a handler
//! reads and writes under row-level security exactly like a request handler
//! does. `mark_done` runs inside that same transaction — `app_role` has UPDATE
//! on `outbox_events` and the row is the tenant's own — so the effect's
//! bookkeeping and its state change commit together or not at all.
//!
//! Delivery is at-least-once, and that is the honest ceiling: a process killed
//! between a provider accepting an email and the `COMMIT` will send it twice.
//! Handlers are expected to be idempotent (`provider_intents` exists for
//! exactly this). Exactly-once would need the provider to be in the
//! transaction, which it is not.
//!
//! # Clock
//!
//! [`tick`] takes `now` rather than reading the clock, so the backoff schedule
//! is testable by advancing an argument instead of sleeping through two hours
//! of it. [`run`] is the only thing here that calls `Utc::now`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use agentos_app::inbound::NOTICE_AGGREGATE;
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::outbox::{self, MAX_ATTEMPTS, OutboxEvent};
use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

/// Events taken per claim.
///
/// Small enough that a slow handler does not sit on a lease it will not get to
/// before the backoff expires, big enough that a busy queue is not one round
/// trip per event.
const BATCH: i64 = 32;

/// How long to wait after finding nothing to do.
///
/// This is the tail latency of every asynchronous effect in the system, so it
/// is short. It is also the poll rate against Postgres when the queue is empty,
/// which is one indexed lookup — cheaper than maintaining a `LISTEN`.
const IDLE: Duration = Duration::from_millis(250);

/// What a handler returns. `Err` is the text that lands in `last_error`, so
/// write it for the person reading a dead letter at 3am.
pub type Handled<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// One event type's side effect.
///
/// It is handed the event and a transaction already scoped to the event's
/// tenant. Whatever it writes commits together with the event being marked
/// published, so a handler does not have to think about partial failure — it
/// either returns `Ok` and everything lands, or returns `Err` and nothing does
/// and the event is retried.
///
/// A handler must not commit or roll back the transaction; that is the loop's
/// decision, and the type does not let it anyway.
// ponytail: a boxed closure rather than a trait. There is no state to hang off
// an implementor that a capture cannot hold, and a trait with no
// implementations is a vocabulary nobody asked for.
#[allow(clippy::type_complexity)]
pub type Handler =
    Arc<dyn for<'a, 'tx> Fn(&'a OutboxEvent, &'a mut TenantTx<'tx>) -> Handled<'a> + Send + Sync>;

/// The dispatch table, keyed by `event_type`.
///
/// An event whose type is not in here is *failed*, not skipped: a deploy that
/// forgets to register a handler is a side effect that silently never happens,
/// and the retry-then-dead-letter path is the one that gets somebody paged.
#[derive(Clone, Default)]
pub struct Handlers(HashMap<String, Handler>);

impl Handlers {
    /// Register `handler` for `event_type`, replacing any previous one.
    pub fn on(mut self, event_type: impl Into<String>, handler: Handler) -> Self {
        self.0.insert(event_type.into(), handler);
        self
    }
}

impl std::fmt::Debug for Handlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Handlers").field(&self.0.keys()).finish()
    }
}

/// Drain the outbox until `cancel` fires.
///
/// Spawn one per replica. Two of them on the same database is a supported
/// configuration and the reason the claim is `SKIP LOCKED`: they take disjoint
/// batches instead of blocking on each other.
pub async fn run(db: Db, handlers: Handlers, cancel: CancellationToken) {
    let handlers = Arc::new(handlers);
    tracing::info!("outbox poller started");

    loop {
        let drained = match tick(&db, &handlers, Utc::now()).await {
            Ok(drained) => drained,
            Err(err) => {
                // The database is unreachable or the claim lost a race. Both
                // are transient and both are survivable by waiting, which is
                // what the sleep below does. Exiting would take the queue down
                // with the blip.
                tracing::error!(error = %err, "outbox claim failed");
                0
            }
        };

        // A full batch means there is more work right now; go straight back
        // round rather than adding IDLE to a backlog's drain time.
        if drained == BATCH as usize {
            if cancel.is_cancelled() {
                break;
            }
            continue;
        }

        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }

    tracing::info!("outbox poller stopped");
}

/// One pass: claim a batch and handle it. Returns how many events were claimed.
///
/// Handlers run one after another. ponytail: a batch of 32 sequential handlers
/// is a few seconds, and the events in one batch frequently touch the same
/// employee, so concurrency here would buy latency and pay for it in write
/// conflicts. The upgrade, when a single tenant's fan-out justifies it, is a
/// `JoinSet` with a semaphore — not a second poller, which already works.
async fn tick(db: &Db, handlers: &Handlers, now: DateTime<Utc>) -> Result<usize, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    // Everything except the inbound loop's rows. The two pollers share one
    // table and only one of them has handlers for a webhook notice; claiming
    // another poller's row burns an attempt off it for nothing, and eight of
    // those is a customer's email in the dead-letter list. See
    // [`outbox::claim_except`].
    let batch = outbox::claim_except(&mut tx, Some(NOTICE_AGGREGATE), BATCH, now).await?;
    // Commit the lease before the first handler runs. See the module docs.
    tx.commit().await?;

    for event in &batch {
        // `instrument`, not `span.enter()`: a guard held across an await is on
        // whatever task the executor resumes next.
        let span = tracing::info_span!(
            "outbox_event",
            event_id = %event.id,
            tenant_id = %event.tenant_id,
            event_type = %event.event_type,
            attempt = event.attempt_count,
            // Carried in the payload rather than a column so it survives every
            // hop; this is where async work rejoins the caller's trace.
            traceparent = event.traceparent().unwrap_or_default(),
        );
        handle(db, handlers, event).instrument(span).await;
    }
    Ok(batch.len())
}

/// Dispatch one claimed event and record what happened.
async fn handle(db: &Db, handlers: &Handlers, event: &OutboxEvent) {
    let Some(handler) = handlers.0.get(&event.event_type) else {
        fail(db, event, "no handler is registered for this event type").await;
        return;
    };

    // Back under RLS: the poller is cross-tenant, the handler is not.
    let mut tx = match db.tenant_tx(event.tenant_id).await {
        Ok(tx) => tx,
        Err(err) => {
            fail(db, event, &format!("no tenant transaction: {err}")).await;
            return;
        }
    };

    let Err(why) = handler(event, &mut tx).await else {
        // Publishing the event is part of the handler's own transaction, so
        // "the effect happened" and "the event is done" cannot disagree.
        // `&mut tx` auto-derefs TenantTx -> Transaction -> PgConnection: this
        // is the tenant's own connection, still inside their transaction.
        if let Err(err) = outbox::mark_done(&mut tx, event.id, Utc::now()).await {
            let _ = tx.rollback().await;
            fail(db, event, &format!("could not publish: {err}")).await;
            return;
        }
        if let Err(err) = tx.commit().await {
            // Nothing was written. The lease expires and someone retries; this
            // is the at-least-once seam and the handler is idempotent.
            tracing::warn!(error = %err, "handler committed nothing; will retry");
        }
        return;
    };

    let _ = tx.rollback().await;
    fail(db, event, &why).await;
}

/// Record why an attempt failed, and shout if it was the last one.
///
/// Nothing is rescheduled here — the claim already burned the attempt and
/// already set the backoff, so an event is retried whether or not this
/// succeeds. What this adds is the error text, which is the only thing that
/// makes a dead letter diagnosable.
async fn fail(db: &Db, event: &OutboxEvent, why: &str) {
    if event.is_dead_lettered() {
        // The claim that produced this event was the last one it will ever
        // get. Nothing moves the row; it just stops being selected.
        tracing::error!(
            error = why,
            attempts = event.attempt_count,
            aggregate_type = %event.aggregate_type,
            aggregate_id = %event.aggregate_id,
            "outbox event dead-lettered; this side effect will not happen"
        );
    } else {
        tracing::warn!(
            error = why,
            attempt = event.attempt_count,
            "outbox event failed"
        );
    }

    let mut tx = match db.admin_tx_bypassing_rls().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(error = %err, "could not record an outbox failure");
            return;
        }
    };
    if let Err(err) = outbox::mark_failed(&mut tx, event.id, why).await {
        tracing::error!(error = %err, "could not record an outbox failure");
        return;
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(error = %err, "could not record an outbox failure");
    }
}

/// How far behind the poller is: the age of the oldest event that is due and
/// still unpublished, in seconds. `0` when the queue is drained.
///
/// This is the number `/readyz` needs. A queue quietly falling behind looks
/// exactly like a healthy system from the outside — requests are accepted, 200s
/// come back — right up until someone asks why the emails never arrived.
///
/// Only counts events that are *due*: an event deliberately backed off to five
/// minutes from now is not lag, it is the backoff working.
///
/// And only events that will actually be claimed again. A dead letter is
/// unpublished forever and its `available_at` is forever in the past, so
/// counting one would make this number climb without bound and never come
/// back down — one poison message would take every replica out of rotation,
/// permanently, and no amount of draining would fix it. Lag is "the poller is
/// behind"; a dead letter is "this effect will never happen", which is a
/// different question with a different answer, and
/// [`outbox::dead_letters`](agentos_store::outbox::dead_letters) is what
/// answers it. Alert on that; do not fail readiness on it.
pub async fn lag_secs(db: &Db) -> Result<i64, StoreError> {
    // Cross-tenant: the backlog is not any one tenant's.
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let lag: Option<i64> = sqlx::query_scalar(
        "SELECT max(extract(epoch FROM now() - available_at))::bigint \
           FROM outbox_events \
          WHERE published_at IS NULL \
            AND available_at <= now() \
            AND attempt_count < $1::int",
    )
    .bind(MAX_ATTEMPTS)
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(lag.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use agentos_domain::ids::TenantId;
    use agentos_store::outbox::{MAX_ATTEMPTS, NewEvent};
    use chrono::TimeDelta;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    /// The poller is cross-tenant by design, so a test that runs it sees every
    /// other test's events too. cargo runs tests in parallel; these go one at a
    /// time.
    static OUTBOX_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    const EVENT: &str = "employee.provisioned";

    /// An empty outbox, held exclusively until the returned guard is dropped.
    ///
    /// The guard comes back with the handle rather than being taken separately,
    /// because the truncate below is inside the critical section: a test taking
    /// the lock second would otherwise delete the running test's events.
    ///
    /// `None` when there is no database. These tests are worthless against a
    /// mock — the thing under test is `SKIP LOCKED` — so they skip loudly.
    async fn db() -> Option<(Db, tokio::sync::MutexGuard<'static, ()>)> {
        let guard = OUTBOX_LOCK.lock().await;
        let db = crate::loops::private_db("outbox").await?;
        // Anything a previously crashed run left behind would be claimed by the
        // loop under test. The database is this module's own, so the blast
        // radius is already empty — the predicate is here anyway, because an
        // unscoped DELETE in a test is the bug even when today's blast radius
        // happens to be empty, and `crates/app/tests/scoped_deletes.rs` is what
        // keeps that true. Events cascade from the tenant that owns them.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE slug LIKE 'outbox-loop-%'")
            .execute(&mut *tx)
            .await
            .expect("clear outbox");
        tx.commit().await.expect("commit");
        Some((db, guard))
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("loop-{}", tenant.as_uuid()))
            .bind("outbox loop")
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    async fn enqueue(db: &Db, tenant: TenantId, n: usize, now: DateTime<Utc>) -> Uuid {
        let mut event = NewEvent::new("employee", Uuid::now_v7(), EVENT);
        event.payload = json!({ "n": n });
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let id = outbox::enqueue(&mut tx, &event, now)
            .await
            .expect("enqueue");
        tx.commit().await.expect("commit");
        id
    }

    /// Every event this handler sees, in order.
    type Seen = Arc<Mutex<Vec<Uuid>>>;

    /// A handler that records the event and succeeds.
    fn recorder(seen: &Seen) -> Handler {
        let seen = seen.clone();
        Arc::new(move |event: &OutboxEvent, _tx: &mut TenantTx<'_>| {
            let seen = seen.clone();
            let id = event.id;
            Box::pin(async move {
                seen.lock().expect("lock").push(id);
                Ok(())
            })
        })
    }

    fn ids(seen: &Seen) -> Vec<Uuid> {
        seen.lock().expect("lock").clone()
    }

    async fn published(db: &Db, id: Uuid) -> bool {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let done: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT published_at FROM outbox_events WHERE id = $1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .expect("published_at");
        tx.rollback().await.expect("rollback");
        done.is_some()
    }

    /// Poll until `seen` has `want` events, or give up. Returns whether it did.
    async fn wait_for(seen: &Seen, want: usize) -> bool {
        for _ in 0..200 {
            if seen.lock().expect("lock").len() >= want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    // -- concurrency -------------------------------------------------------

    /// Two pollers against one queue. The claim is `SKIP LOCKED`, so they take
    /// disjoint work — the failure this rules out is the expensive one: the
    /// same email sent twice because two replicas grabbed the same row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_pollers_never_handle_the_same_event() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let tenant = seed_tenant(&db).await;

        const EVENTS: usize = 60;
        let now = Utc::now();
        let mut queued = Vec::new();
        for n in 0..EVENTS {
            queued.push(enqueue(&db, tenant, n, now).await);
        }

        // One shared record, so a duplicate shows up as a duplicate no matter
        // which poller produced it.
        let seen: Seen = Arc::default();
        let cancel = CancellationToken::new();
        let a = tokio::spawn(run(
            db.clone(),
            Handlers::default().on(EVENT, recorder(&seen)),
            cancel.clone(),
        ));
        let b = tokio::spawn(run(
            db.clone(),
            Handlers::default().on(EVENT, recorder(&seen)),
            cancel.clone(),
        ));

        assert!(wait_for(&seen, EVENTS).await, "the queue never drained");
        cancel.cancel();
        a.await.expect("poller a");
        b.await.expect("poller b");

        let handled = ids(&seen);
        let unique: std::collections::HashSet<Uuid> = handled.iter().copied().collect();
        assert_eq!(
            unique.len(),
            handled.len(),
            "an event was handled twice: {handled:?}"
        );
        assert_eq!(unique.len(), EVENTS, "an event was never handled");
        for id in &queued {
            assert!(unique.contains(id));
            assert!(published(&db, *id).await, "a handled event stayed pending");
        }

        drop_tenant(&db, tenant).await;
    }

    // -- failure -----------------------------------------------------------

    /// A handler that never succeeds must not spin: each attempt waits longer
    /// than the last, and after `MAX_ATTEMPTS` the event stops being claimed
    /// and becomes a dead letter with its reason attached.
    ///
    /// Drives [`tick`] directly with an advancing clock. Running [`run`] would
    /// mean sleeping through the real backoff, which reaches two hours.
    #[tokio::test]
    async fn a_failing_handler_backs_off_and_then_dead_letters() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let tenant = seed_tenant(&db).await;

        let attempts: Seen = Arc::default();
        let counter = attempts.clone();
        let handlers = Handlers::default().on(
            EVENT,
            Arc::new(move |event: &OutboxEvent, _tx: &mut TenantTx<'_>| {
                let counter = counter.clone();
                let id = event.id;
                Box::pin(async move {
                    counter.lock().expect("lock").push(id);
                    Err("the provider said no".to_owned())
                })
            }),
        );

        let mut now = Utc::now();
        let id = enqueue(&db, tenant, 1, now).await;

        for attempt in 1..=MAX_ATTEMPTS {
            assert_eq!(
                tick(&db, &handlers, now).await.expect("tick"),
                1,
                "attempt {attempt} should have claimed the event"
            );
            // Immediately again, at the same instant: if it is claimable now,
            // the backoff did not happen and this loop is a hot loop.
            assert_eq!(
                tick(&db, &handlers, now).await.expect("tick"),
                0,
                "attempt {attempt} did not back off"
            );
            // Skip past the backoff rather than sleeping through it.
            now += TimeDelta::hours(2);
        }

        assert_eq!(ids(&attempts).len(), MAX_ATTEMPTS as usize);

        // Attempts spent. No poller will ever pick it up again, even a year on.
        assert_eq!(
            tick(&db, &handlers, now + TimeDelta::days(365))
                .await
                .expect("tick"),
            0,
            "an exhausted event must not be claimed"
        );
        assert_eq!(
            ids(&attempts).len(),
            MAX_ATTEMPTS as usize,
            "the handler ran after the event was dead"
        );

        // ...but it is visible to whoever is on call, with the reason.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let dead = outbox::dead_letters(&mut tx, 10).await.expect("dead");
        tx.rollback().await.expect("rollback");
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].id, id);
        assert_eq!(dead[0].last_error.as_deref(), Some("the provider said no"));
        assert!(!published(&db, id).await);

        drop_tenant(&db, tenant).await;
    }

    /// An event type nobody registered is a failure, not a silent skip — the
    /// side effect is just as missing either way, and only one of the two gets
    /// anybody paged.
    #[tokio::test]
    async fn an_unhandled_event_type_fails_rather_than_vanishing() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let tenant = seed_tenant(&db).await;

        let now = Utc::now();
        let id = enqueue(&db, tenant, 1, now).await;
        assert_eq!(tick(&db, &Handlers::default(), now).await.expect("tick"), 1);

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let (last_error, published_at): (Option<String>, Option<DateTime<Utc>>) =
            sqlx::query_as("SELECT last_error, published_at FROM outbox_events WHERE id = $1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .expect("row");
        tx.rollback().await.expect("rollback");

        assert!(published_at.is_none(), "it must not count as published");
        assert!(
            last_error.unwrap_or_default().contains("no handler"),
            "the reason must say what is missing"
        );

        drop_tenant(&db, tenant).await;
    }

    // -- durability --------------------------------------------------------

    /// Restarting the process must not resend anything. `published_at` is the
    /// memory, and it was committed in the handler's own transaction.
    #[tokio::test]
    async fn a_published_event_is_not_reprocessed_after_a_restart() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let tenant = seed_tenant(&db).await;

        let now = Utc::now();
        let id = enqueue(&db, tenant, 1, now).await;

        let first: Seen = Arc::default();
        let cancel = CancellationToken::new();
        let poller = tokio::spawn(run(
            db.clone(),
            Handlers::default().on(EVENT, recorder(&first)),
            cancel.clone(),
        ));
        assert!(wait_for(&first, 1).await, "the event was never handled");
        cancel.cancel();
        poller.await.expect("poller");
        assert_eq!(ids(&first), vec![id]);
        assert!(published(&db, id).await);

        // A brand new poller, as after a deploy. Far enough in the future that
        // every lease from the first one has long expired, so "it did not run
        // again" cannot be an artefact of the backoff.
        let second: Seen = Arc::default();
        let handlers = Handlers::default().on(EVENT, recorder(&second));
        assert_eq!(
            tick(&db, &handlers, now + TimeDelta::days(30))
                .await
                .expect("tick"),
            0
        );
        assert!(ids(&second).is_empty(), "the effect happened twice");

        drop_tenant(&db, tenant).await;
    }

    // -- lag ---------------------------------------------------------------

    /// The number `/readyz` reports. A backlog is invisible from the outside
    /// unless something publishes it.
    #[tokio::test]
    async fn lag_reports_the_age_of_the_oldest_due_event() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let tenant = seed_tenant(&db).await;

        assert_eq!(lag_secs(&db).await.expect("lag"), 0, "an empty queue is 0");

        // Two events, one much older. The lag is the older one's age.
        let now = Utc::now();
        enqueue(&db, tenant, 1, now - TimeDelta::seconds(30)).await;
        let stale = enqueue(&db, tenant, 2, now - TimeDelta::seconds(600)).await;

        let lag = lag_secs(&db).await.expect("lag");
        assert!(
            (595..=630).contains(&lag),
            "expected roughly 600s of lag, got {lag}"
        );

        // Draining the queue clears it...
        let seen: Seen = Arc::default();
        let handlers = Handlers::default().on(EVENT, recorder(&seen));
        assert_eq!(tick(&db, &handlers, Utc::now()).await.expect("tick"), 2);
        assert_eq!(lag_secs(&db).await.expect("lag"), 0);
        assert!(published(&db, stale).await);

        // ...and an event deliberately backed off into the future is not lag,
        // it is the backoff working.
        enqueue(&db, tenant, 3, now + TimeDelta::hours(1)).await;
        assert_eq!(lag_secs(&db).await.expect("lag"), 0);

        // Nor is a dead letter. Its `available_at` is in the past and always
        // will be, so counting it would take this replica — and every other
        // one — out of rotation forever over a single poison message, with no
        // way back. It is an alert (`outbox::dead_letters`), not a readiness
        // signal.
        let poisoned = enqueue(&db, tenant, 4, now - TimeDelta::hours(3)).await;
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("UPDATE outbox_events SET attempt_count = $2 WHERE id = $1")
            .bind(poisoned)
            .bind(MAX_ATTEMPTS)
            .execute(&mut *tx)
            .await
            .expect("exhaust the attempts");
        tx.commit().await.expect("commit");
        assert_eq!(
            lag_secs(&db).await.expect("lag"),
            0,
            "a dead letter must not read as a poller that is behind"
        );

        drop_tenant(&db, tenant).await;
    }
}
