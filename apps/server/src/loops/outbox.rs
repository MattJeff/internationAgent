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
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
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
pub type Handled<'a> = Pin<Box<dyn Future<Output = Result<(), Failure>> + Send + 'a>>;

/// Why a handler did not finish, and whether trying again could change that.
///
/// # The question this type exists to let a handler answer
///
/// This loop used to take a bare `String`, so every failure meant one thing:
/// eight attempts and a dead letter. That is right for a database that blinked
/// and wrong — arithmetically, not arguably — for a failure that is a property
/// of the *bytes*. A stored webhook body that is not JSON is not JSON on the
/// eighth read either; a policy that intersects to no permitted model at all
/// permits no model at all seven retries later. Those rows still had to be
/// retried, because the only word a handler had for "stop" was `Ok`, and `Ok`
/// throws the event away in silence.
///
/// So there are two words now, and neither of them is `Ok`. Both end in the
/// same place an operator already looks — `outbox::dead_letters` — and the
/// difference is only whether seven attempts happen first. [`Terminal`] is not
/// a quieter failure than [`Retry`]; it is the same failure, arrived at
/// honestly.
///
/// [`Terminal`]: Failure::Terminal
/// [`Retry`]: Failure::Retry
///
/// # `From<String>` is `Retry`
///
/// Deliberately: `?` on a `map_err(|e| format!(…))` keeps meaning what it
/// always meant, so nothing becomes terminal by being left alone. A handler has
/// to *say* that retrying cannot work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Trying again could work: the store blinked, the provider was overloaded,
    /// a lease expired. The claim's backoff hands the row back.
    Retry(String),

    /// Trying again cannot work — the same input will fail the same way. The
    /// row is parked: kept, unpublished, with this reason on it, and dead-lettered
    /// on this attempt rather than the eighth.
    ///
    /// Reversible by hand: `outbox::requeue_dead_letters` gives a tenant's
    /// parked rows their attempts back, which is what an operator runs after
    /// fixing whatever made the event impossible.
    Terminal(String),
}

impl Failure {
    /// The reason, for `last_error`. Never third-party text.
    fn why(&self) -> &str {
        match self {
            Failure::Retry(why) | Failure::Terminal(why) => why,
        }
    }
}

impl From<String> for Failure {
    fn from(why: String) -> Self {
        Failure::Retry(why)
    }
}

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

/// How many tenants' work this poller runs at once.
///
/// **One, until this constant existed, and that was a cross-tenant outage with
/// no error in it.** The batch used to be handled with a plain `for` loop, on
/// the argument that "a batch of 32 sequential handlers is a few seconds". That
/// was true when every handler was a database write. It stopped being true when
/// `agent.turn.requested` joined the table: a turn is a model call and
/// `TURN_DEADLINE` is 120 seconds, so a full batch is up to an hour of one
/// replica doing nothing else. Every tenant behind the first one in that batch
/// waits — for work that has nothing to do with them, on a customer's own
/// inbound email, with no denial, no failure and nothing in the trail that says
/// why. At two to five thousand dollars a month that is the same size of failure
/// as a leak. `agentos_store::outbox::claim_of` made the *queue order* fair;
/// this is what stops one tenant's turn from holding the worker.
///
/// **Concurrent across tenants, sequential within one.** That keeps the reason
/// the loop was sequential in the first place, and it was a good reason: the
/// events in one batch frequently touch the same employee, and running those
/// against each other buys latency and pays for it in write conflicts. Two
/// different companies have no rows in common by construction.
///
/// ponytail: four, and the ceiling is the connection pool — `Db::connect` opens
/// sixteen for the whole process, one turn holds its handler's transaction open
/// for its whole length and takes a second for the knowledge recall, and the
/// other three loops and every HTTP handler draw from the same sixteen. Four is
/// what leaves room for them. Raise it and raise `max_connections` in the same
/// commit, or the symptom is a pool acquire timeout that looks like a database
/// problem and is not.
const MAX_CONCURRENT_TENANTS: usize = 4;

/// One pass: claim a batch and handle it. Returns how many events were claimed.
///
/// One task per tenant in the batch, that tenant's events in order inside it,
/// at most [`MAX_CONCURRENT_TENANTS`] running at once. The pass does not return
/// until every one of them has finished, which is what keeps the next claim from
/// overlapping the last — see [`run`].
async fn tick(db: &Db, handlers: &Arc<Handlers>, now: DateTime<Utc>) -> Result<usize, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    // Everything except the inbound loop's rows. The two pollers share one
    // table and only one of them has handlers for a webhook notice; claiming
    // another poller's row burns an attempt off it for nothing, and eight of
    // those is a customer's email in the dead-letter list. See
    // [`outbox::claim_except`].
    let batch = outbox::claim_except(&mut tx, Some(NOTICE_AGGREGATE), BATCH, now).await?;
    // Commit the lease before the first handler runs. See the module docs.
    tx.commit().await?;
    let claimed = batch.len();

    // Grouped rather than sorted: a `HashMap` keyed on the tenant keeps each
    // tenant's events in the order the claim returned them, which is the order
    // they were enqueued in, and that ordering is the whole of what "sequential
    // within a tenant" has to preserve.
    let mut by_tenant: HashMap<agentos_domain::ids::TenantId, Vec<OutboxEvent>> = HashMap::new();
    for event in batch {
        by_tenant.entry(event.tenant_id).or_default().push(event);
    }

    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_TENANTS));
    let mut running = JoinSet::new();
    for events in by_tenant.into_values() {
        let db = db.clone();
        let handlers = Arc::clone(handlers);
        let permits = Arc::clone(&permits);
        running.spawn(async move {
            // Taken inside the task rather than before the spawn, so the queue
            // of waiting tenants is the semaphore's and not this function's.
            // `expect`: the semaphore is never closed, it is dropped with this
            // pass.
            let _permit = permits.acquire_owned().await.expect("never closed");
            for event in &events {
                // `instrument`, not `span.enter()`: a guard held across an await
                // is on whatever task the executor resumes next.
                let span = tracing::info_span!(
                    "outbox_event",
                    event_id = %event.id,
                    tenant_id = %event.tenant_id,
                    event_type = %event.event_type,
                    attempt = event.attempt_count,
                    // Carried in the payload rather than a column so it survives
                    // every hop; this is where async work rejoins the caller's
                    // trace.
                    traceparent = event.traceparent().unwrap_or_default(),
                );
                handle(&db, &handlers, event).instrument(span).await;
            }
        });
    }

    // Drained rather than abandoned. A pass that returned early would let the
    // next claim run beside handlers that are still going, and the batch bound
    // this loop is built around would stop bounding anything.
    while let Some(finished) = running.join_next().await {
        if let Err(err) = finished {
            // A handler panicked. `handle` itself cannot — every failure path in
            // it records and returns — so this is a bug in a registered handler,
            // and the event is left to its lease rather than taking the poller
            // down with it.
            tracing::error!(error = %err, "an outbox handler task panicked; its events keep their lease");
        }
    }
    Ok(claimed)
}

/// Dispatch one claimed event and record what happened.
async fn handle(db: &Db, handlers: &Handlers, event: &OutboxEvent) {
    let Some(handler) = handlers.0.get(&event.event_type) else {
        // Retryable on purpose, and it is the one unregistered case that is:
        // the row may have been written by a newer build than the one draining
        // it, and a rolling deploy is exactly the window where retrying works.
        fail(
            db,
            event,
            &Failure::Retry("no handler is registered for this event type".to_owned()),
        )
        .await;
        return;
    };

    // Back under RLS: the poller is cross-tenant, the handler is not.
    let mut tx = match db.tenant_tx(event.tenant_id).await {
        Ok(tx) => tx,
        Err(err) => {
            fail(db, event, &format!("no tenant transaction: {err}").into()).await;
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
            fail(db, event, &format!("could not publish: {err}").into()).await;
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
/// Nothing is rescheduled here for a [`Failure::Retry`] — the claim already
/// burned the attempt and already set the backoff, so an event is retried
/// whether or not this succeeds. What this adds is the error text, which is the
/// only thing that makes a dead letter diagnosable.
///
/// A [`Failure::Terminal`] *is* rescheduled here, to never: the attempt counter
/// is burned out in one `UPDATE` so the row becomes a dead letter now instead
/// of after seven more attempts that cannot end differently. If that `UPDATE`
/// fails the row keeps its ordinary backoff and is merely retried, which is the
/// old behaviour and the safe direction to fall back in.
async fn fail(db: &Db, event: &OutboxEvent, failure: &Failure) {
    let why = failure.why();
    let terminal = matches!(failure, Failure::Terminal(_));
    if event.is_dead_lettered() || terminal {
        // The claim that produced this event was the last one it will ever
        // get — either because it burned the eighth attempt, or because the
        // handler said no attempt can work and the `park` below burns the rest.
        // Same line for both: an operator reading it has the same job.
        tracing::error!(
            error = why,
            attempts = event.attempt_count,
            terminal,
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
    let written = if terminal {
        outbox::park(&mut tx, event.id, why).await
    } else {
        outbox::mark_failed(&mut tx, event.id, why).await
    };
    if let Err(err) = written {
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
///
/// And only tenants the poller is willing to serve, which is the same argument
/// a second time and cost more to find. `outbox::claim_of` refuses a **stopped**
/// company's rows at the `tenants` driver — an operator's halt, or an operating
/// window whose `ends_at` has passed — so those rows are due, unclaimed and
/// perfectly healthy for as long as the stop lasts. Counting them made
/// `MAX_OUTBOX_LAG_SECS` a five-minute fuse on the *whole deployment*: one
/// customer pressing stop, or one month running out on schedule, and every
/// replica leaves the load balancer for every other customer. A stop is a
/// customer asking us to wait; it is not this process falling behind.
///
/// **This is a third reader of the halt** — after `outbox::claim_of` and
/// `initiative::claim_due`, both of which had to be corrected separately — and
/// it is spelled out here rather than delegated to `halt::halted` for the same
/// reason `claim_of` spells it: that function answers for one tenant on a
/// `TenantTx`, and this is one aggregate over every tenant at once. The clause
/// has to stay in step with `claim_of`'s, and
/// `a_stopped_company_is_not_a_poller_that_is_behind` is what notices if it
/// does not.
pub async fn lag_secs(db: &Db) -> Result<i64, StoreError> {
    // Cross-tenant: the backlog is not any one tenant's.
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let lag: Option<i64> = sqlx::query_scalar(
        "SELECT max(extract(epoch FROM now() - e.available_at))::bigint \
           FROM outbox_events e \
          WHERE e.published_at IS NULL \
            AND e.available_at <= now() \
            AND e.attempt_count < $1::int \
            AND NOT EXISTS (SELECT 1 FROM company_halts h \
                             WHERE h.tenant_id = e.tenant_id) \
            AND NOT EXISTS (SELECT 1 FROM company_windows w \
                             WHERE w.tenant_id = e.tenant_id \
                               AND w.ends_at <= now())",
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

    /// The follow-on effect the handler in
    /// [`a_poller_killed_mid_handler_loses_the_row_and_not_the_work`] enqueues
    /// before it dies. Its own event type, so counting it is a scoped read.
    const KILLED_EVENT: &str = "employee.killed-mid-handler";

    /// What every tenant this module seeds is called, and the only thing
    /// [`db`]'s cleanup is allowed to remove.
    ///
    /// **One constant, read by both**, because the two used to be two literals
    /// and they had drifted: [`seed_tenant`] wrote `loop-<uuid>` and the cleanup
    /// deleted `outbox-loop-%`, which matches nothing a run of this module has
    /// ever written. The cleanup therefore deleted no rows, silently, while
    /// reading as a protection — see
    /// [`the_startup_cleanup_removes_what_this_module_seeded`] for the failure
    /// it is there to stop.
    const TENANT_SLUG: &str = "outbox-loop-";

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
        sqlx::query("DELETE FROM tenants WHERE slug LIKE $1")
            .bind(format!("{TENANT_SLUG}%"))
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
            .bind(format!("{TENANT_SLUG}{}", tenant.as_uuid()))
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

    // -- the fixture itself ------------------------------------------------

    /// **The cleanup in [`db`] has to match the seeder in [`seed_tenant`], and
    /// for a while it did not.**
    ///
    /// It looked for `outbox-loop-%` and nothing had ever written that prefix,
    /// so it deleted nothing. What it exists to delete is a *crashed* run's
    /// rows: this module's poller is cross-tenant — [`run`] claims by
    /// `published_at IS NULL`, never by tenant — so an `employee.provisioned`
    /// row left behind by a run that was killed mid-test is claimed by the very
    /// next test's poller and counted as its own. That is
    /// [`two_pollers_never_handle_the_same_event`] failing with sixty-one
    /// events, or [`a_poller_killed_mid_handler_loses_the_row_and_not_the_work`]
    /// seeing a stranger's id, in a run where nothing is wrong — and the failure
    /// names neither the crash nor the cleanup.
    ///
    /// So the assertion is on the fixture: seed the way every test seeds, take
    /// the fixture again the way a fresh `cargo test` does, and the row is gone.
    #[tokio::test]
    async fn the_startup_cleanup_removes_what_this_module_seeded() {
        let Some((first, guard)) = db().await else {
            return;
        };
        let tenant = seed_tenant(&first).await;
        // The lock, not the database: `db` takes it again below and it is not
        // reentrant. Dropping it here is what makes the second call the
        // "previous run crashed and left this behind" case.
        drop(first);
        drop(guard);

        let Some((again, _guard)) = db().await else {
            return;
        };
        let mut tx = again.admin_tx_bypassing_rls().await.expect("admin tx");
        let survived: Option<String> = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .expect("read the tenant back");
        tx.rollback().await.expect("rollback");

        assert_eq!(
            survived, None,
            "the startup cleanup left a tenant this module seeded behind, so it \
             deletes nothing a crashed run wrote and every event under that \
             tenant is still claimable by the next test's poller"
        );
    }

    // -- concurrency -------------------------------------------------------

    /// Two pollers against one queue. The claim is `SKIP LOCKED`, so they take
    /// disjoint work — the failure this rules out is the expensive one: the
    /// same email sent twice because two replicas grabbed the same row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    /// **KNOWN FLAKY — measured at ~6.7%, and the measurement is the point.**
    ///
    /// On 2026-08-28 this failed a full-suite run with `left: 60, right: 67`:
    /// sixty events, sixty unique ids, and seven handled a second time. Isolated
    /// on an idle machine it fails about one run in fifteen, so it is not
    /// contention — and it is **not new**: 4 red in 60 at `cc73243`, before that
    /// day's waves touched this loop, against 1 in 17 after. Same rate.
    ///
    /// Two things worth keeping from working that out. The first attempt read
    /// 20/20 green and concluded the regression was absent; at a true rate of
    /// 6.7% a clean run of twenty happens 29% of the time, so that proved
    /// nothing. And a run of this test that finishes in under a tenth of a
    /// second has almost certainly *skipped* — `db()` returns early and reports
    /// `ok` when the database is unreachable, and the database it wants is
    /// derived (`private_db("outbox")`), not the one in `DATABASE_URL`. Count
    /// the tables in the derived database before believing a green run.
    ///
    /// What makes seven duplicates surprising rather than merely racy:
    /// [`claim`](agentos_store::outbox::claim) commits *before* the handler
    /// runs, so `SKIP LOCKED` protects nothing once that transaction closes.
    /// What keeps a row to one worker is the same `UPDATE` pushing
    /// `available_at` a `LEASE_SECS` into the future — a lease of two minutes,
    /// against handlers that return instantly in a test lasting about a second.
    /// A second claim inside that window should be impossible. It happens
    /// anyway, and until somebody explains why, the honest reading is that
    /// either this test manufactures duplicates the queue does not have, or an
    /// `agent.turn.requested` can be handled twice — which is the customer
    /// billed twice for one event, the outage `main.rs` asserts against at
    /// compile time.
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

    /// **One company's event must not hold another company's event.**
    ///
    /// [`MAX_CONCURRENT_TENANTS`] shipped with no test at all, and its own
    /// doc-comment states the outage it exists to end: `agent.turn.requested`
    /// is in this table, a turn runs up to `TURN_DEADLINE`, and a batch of 32
    /// drained by a plain `for` loop is an hour of every tenant behind the
    /// first one waiting on work that is not theirs — with no error, no denial
    /// and nothing in the trail. `outbox::claim_of` made the *queue order*
    /// fair; only this constant stops one tenant's handler from holding the
    /// worker.
    ///
    /// A counter cannot catch that, which is why there was no test worth
    /// writing until this shape existed: the sequential drain starts every
    /// tenant too, just later, so "both handlers ran" passes either way. So the
    /// assertion is a **rendezvous** — two tenants, one event each, and a
    /// handler that does not return until the *other* tenant's handler has also
    /// started. Under a sequential drain the first handler waits for a second
    /// that cannot begin, the pass never ends, and the timeout is the failure
    /// this test exists to report.
    ///
    /// Ported from `loops::initiative`'s
    /// `one_tenants_turn_does_not_hold_another_tenants_turn`, deliberately in
    /// the same shape: the two loops make the same promise with the same
    /// semaphore.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_tenants_event_does_not_hold_another_tenants_event() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let first = seed_tenant(&db).await;
        let second = seed_tenant(&db).await;

        let now = Utc::now();
        enqueue(&db, first, 1, now).await;
        enqueue(&db, second, 2, now).await;

        // Two arrivals, so neither handler can finish until both have started.
        let gate = Arc::new(tokio::sync::Barrier::new(2));
        let seen: Seen = Arc::default();
        let recorder = seen.clone();
        let handlers = Handlers::default().on(
            EVENT,
            Arc::new(move |event: &OutboxEvent, _tx: &mut TenantTx<'_>| {
                let gate = gate.clone();
                let recorder = recorder.clone();
                let id = event.id;
                Box::pin(async move {
                    recorder.lock().expect("lock").push(id);
                    gate.wait().await;
                    Ok(())
                })
            }),
        );

        // Generous: this is not a latency assertion, it is the difference
        // between "both handlers are in flight" and "one of them can never
        // start".
        let pass =
            tokio::time::timeout(Duration::from_secs(20), tick(&db, &Arc::new(handlers), now))
                .await;

        let claimed = pass
            .expect(
                "the pass never finished: one tenant's handler is holding the other's, so a \
                 batch of fair seats is still drained one company at a time and every \
                 company after the first waits out TURN_DEADLINE for work that is not theirs",
            )
            .expect("tick");
        assert_eq!(claimed, 2, "both tenants' events were claimed");
        assert_eq!(
            ids(&seen).len(),
            2,
            "both handlers started, which is what let the rendezvous complete"
        );

        drop_tenant(&db, first).await;
        drop_tenant(&db, second).await;
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
                    Err(Failure::Retry("the provider said no".to_owned()))
                })
            }),
        );

        let mut now = Utc::now();
        let id = enqueue(&db, tenant, 1, now).await;

        for attempt in 1..=MAX_ATTEMPTS {
            assert_eq!(
                tick(&db, &Arc::new(handlers.clone()), now)
                    .await
                    .expect("tick"),
                1,
                "attempt {attempt} should have claimed the event"
            );
            // Immediately again, at the same instant: if it is claimable now,
            // the backoff did not happen and this loop is a hot loop.
            assert_eq!(
                tick(&db, &Arc::new(handlers.clone()), now)
                    .await
                    .expect("tick"),
                0,
                "attempt {attempt} did not back off"
            );
            // Skip past the backoff rather than sleeping through it.
            now += TimeDelta::hours(2);
        }

        assert_eq!(ids(&attempts).len(), MAX_ATTEMPTS as usize);

        // Attempts spent. No poller will ever pick it up again, even a year on.
        assert_eq!(
            tick(&db, &Arc::new(handlers.clone()), now + TimeDelta::days(365))
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
        assert_eq!(
            tick(&db, &Arc::new(Handlers::default()), now)
                .await
                .expect("tick"),
            1
        );

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

    /// A handler that says "no retry can change this" is believed **once**, and
    /// the row is a dead letter on attempt one instead of attempt eight.
    ///
    /// The other half of this is
    /// [`a_permanently_failing_handler_backs_off_then_dead_letters`], which
    /// still runs a [`Failure::Retry`] handler the full [`MAX_ATTEMPTS`] times.
    /// Both have to stay green: the pair is what says the loop distinguishes
    /// the two rather than having collapsed one into the other.
    #[tokio::test]
    async fn a_terminal_failure_is_dead_lettered_on_the_first_attempt() {
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
                    Err(Failure::Terminal("these bytes will never parse".to_owned()))
                })
            }),
        );

        let now = Utc::now();
        let id = enqueue(&db, tenant, 1, now).await;
        assert_eq!(
            tick(&db, &Arc::new(handlers.clone()), now)
                .await
                .expect("tick"),
            1
        );
        assert_eq!(ids(&attempts).len(), 1, "the handler ran once");

        // Not seven more times, at any point ever. This is the whole change:
        // `mark_failed` here would leave the row claimable and the assertion
        // below would find a handler that ran twice.
        for skip in [TimeDelta::hours(2), TimeDelta::days(365)] {
            assert_eq!(
                tick(&db, &Arc::new(handlers.clone()), now + skip)
                    .await
                    .expect("tick"),
                0,
                "a parked event must not be claimed again"
            );
        }
        assert_eq!(
            ids(&attempts).len(),
            1,
            "the handler ran again after saying no attempt can work"
        );

        // **And it is not swallowed.** A `Failure::Terminal` that returned `Ok`
        // would publish the row, empty `dead_letters`, and produce a system
        // that looks perfectly healthy while dropping the event — which is the
        // failure this whole change exists to avoid making. Every assertion
        // below is against that, not against the retry count.
        assert!(!published(&db, id).await, "a parked event must not publish");
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let dead = outbox::dead_letters(&mut tx, 10).await.expect("dead");
        tx.rollback().await.expect("rollback");
        assert_eq!(dead.len(), 1, "a parked event has to be visible on call");
        assert_eq!(dead[0].id, id);
        assert_eq!(
            dead[0].last_error.as_deref(),
            Some("these bytes will never parse"),
            "and it has to say why, or the dead letter is a mystery"
        );
        assert!(
            dead[0].attempt_count >= MAX_ATTEMPTS,
            "parking is spelled by burning the counter; {} attempts",
            dead[0].attempt_count
        );

        drop_tenant(&db, tenant).await;
    }

    /// **The crash window, killed for real.**
    ///
    /// This module's whole argument for committing the claim before the handler
    /// runs is that "a poller that dies mid-handler hands the row back without a
    /// reaper" — the lease is `available_at`, and it expires by itself. Nothing
    /// asserted it. Every failure test above returns `Err` from a handler that
    /// ran to completion, which exercises `mark_failed` and not the case where
    /// the process is simply gone.
    ///
    /// So the tick is aborted while the handler is awaiting, and three separate
    /// things are checked, because the module claims all three:
    ///
    /// * **Nothing is lost.** The row is still there, unpublished, and claimable
    ///   again once the backoff it was leased under expires.
    /// * **Nothing half-lands.** `mark_done` runs inside the handler's own
    ///   tenant transaction — "the effect's bookkeeping and its state change
    ///   commit together or not at all" — so the row this handler wrote before
    ///   dying must not be in the database.
    /// * **The attempt was burned at claim time, not at failure time.** That is
    ///   what stops a poison event that kills its worker from retrying forever,
    ///   and it is the one property a killed worker can prove and a returning
    ///   handler cannot: nobody called `mark_failed` here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_poller_killed_mid_handler_loses_the_row_and_not_the_work() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let id = enqueue(&db, tenant, 1, now).await;

        // Writes something inside the handler's transaction, says so, and then
        // never comes back — the pod killed between the provider accepting the
        // work and the COMMIT.
        let entered = Arc::new(tokio::sync::Notify::new());
        let handlers = Handlers::default().on(EVENT, {
            let entered = entered.clone();
            Arc::new(move |event: &OutboxEvent, tx: &mut TenantTx<'_>| {
                let entered = entered.clone();
                let aggregate = event.aggregate_id;
                Box::pin(async move {
                    // A side effect of the handler's own, in the handler's own
                    // transaction: the follow-on event a real handler enqueues.
                    let mut effect = NewEvent::new("employee", aggregate, KILLED_EVENT);
                    effect.dedupe_key = Some("killed-mid-handler".to_owned());
                    outbox::enqueue(tx, &effect, Utc::now())
                        .await
                        .expect("the handler's own write");
                    entered.notify_one();
                    std::future::pending().await
                })
            })
        });

        let killed = tokio::spawn({
            let (db, handlers) = (db.clone(), handlers.clone());
            async move { tick(&db, &Arc::new(handlers.clone()), now).await }
        });
        entered.notified().await;
        killed.abort();
        let _ = killed.await;
        // **An aborted task is a weaker kill than a dead pod, and the gap has to
        // be closed before anything is asserted.** A `kill -9` closes the socket
        // and Postgres rolls the transaction back at once; dropping the future
        // only hands the connection back to sqlx's pool, which issues the
        // `ROLLBACK` on a background task — so for a moment the handler's
        // uncommitted insert is still there, holding a row lock, and the
        // `DELETE FROM tenants` at the end of this test blocks on it. Waiting
        // for the session to leave `idle in transaction` is the in-process
        // stand-in for the socket closing.
        let idle = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
                let stuck: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_stat_activity \
                      WHERE datname = current_database() \
                        AND state = 'idle in transaction' \
                        AND pid <> pg_backend_pid()",
                )
                .fetch_one(&mut *tx)
                .await
                .expect("count");
                tx.rollback().await.expect("rollback");
                if stuck == 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            idle.is_ok(),
            "the dead worker's transaction never rolled back"
        );

        // The claim committed on its own, so the attempt is spent and the lease
        // is in the future — whatever the handler did or did not do.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let (attempts, error, published_at, available): (
            i32,
            Option<String>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        ) = sqlx::query_as(
            "SELECT attempt_count, last_error, published_at, available_at \
               FROM outbox_events WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .expect("the event is still there");
        // Nothing wrote a reason, because nothing was alive to write one.
        let orphaned: i64 =
            sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE event_type = $1")
                .bind(KILLED_EVENT)
                .fetch_one(&mut *tx)
                .await
                .expect("count");
        tx.rollback().await.expect("rollback");

        assert_eq!(attempts, 1, "the attempt must be burned at claim time");
        assert_eq!(error, None, "nobody was alive to call mark_failed");
        assert!(published_at.is_none(), "a dead handler did not publish");
        assert!(available > now, "the claim did not lease the row forward");
        assert_eq!(
            orphaned, 0,
            "the dead handler's write survived its own transaction"
        );

        // And once the lease expires the row comes back to whoever asks, with
        // no reaper having run and no operator having touched anything.
        let seen: Seen = Arc::default();
        let recovered = Handlers::default().on(EVENT, recorder(&seen));
        assert_eq!(
            tick(&db, &Arc::new(recovered.clone()), now + TimeDelta::hours(2))
                .await
                .expect("tick"),
            1,
            "the row never came back to the pool"
        );
        assert_eq!(ids(&seen), vec![id]);
        assert!(published(&db, id).await, "the retry did not finish it");

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
            tick(&db, &Arc::new(handlers.clone()), now + TimeDelta::days(30))
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
        assert_eq!(
            tick(&db, &Arc::new(handlers.clone()), Utc::now())
                .await
                .expect("tick"),
            2
        );
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

    /// **Nor is a company that asked us to stop, and this one is worse than a
    /// poison message because it is not a fault at all.**
    ///
    /// The test above already argues the shape: a row that no poller will ever
    /// claim is not lag, because `/readyz` fails on lag and a number that
    /// climbs without bound takes **every replica** out of rotation with no way
    /// back. It made that argument about dead letters and stopped there.
    ///
    /// `outbox::claim_of` refuses a stopped tenant's rows *at the driver*, so
    /// they sit due and unclaimed for exactly as long as the halt lasts — and
    /// `MAX_OUTBOX_LAG_SECS` is five minutes. So one customer pressing stop with
    /// anything queued used to un-ready the whole deployment, for every other
    /// customer, until they pressed start again.
    ///
    /// And the halt is the *mild* half. `company_windows` reaches the same
    /// refusal by the same clause (`migrations/0054_operating_window.sql`), and
    /// a window ending is not an emergency — it is a month running out on
    /// schedule, on a company nobody is watching. There is no release verb for
    /// it either.
    ///
    /// Both are asserted here because they are two rows and one predicate, and
    /// `claim_of` is where that predicate lives: this is a third reader of it
    /// and the only reason it is allowed to be one is that it must answer the
    /// same question — *would the poller take this row?* — across every tenant
    /// at once, which no per-tenant `halt::halted` can do.
    #[tokio::test]
    async fn a_stopped_company_is_not_a_poller_that_is_behind() {
        let Some((db, _guard)) = db().await else {
            return;
        };
        let now = Utc::now();

        for (label, stop) in [("halt", false), ("window", true)] {
            let tenant = seed_tenant(&db).await;
            enqueue(&db, tenant, 1, now - TimeDelta::seconds(600)).await;
            let lag = lag_secs(&db).await.expect("lag");
            assert!(
                lag > crate::MAX_OUTBOX_LAG_SECS,
                "{label}: the row has to be un-ready *before* the stop, or this proves \
                 nothing: {lag}s"
            );

            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            if stop {
                agentos_store::halt::set_window(
                    &mut tx,
                    now - TimeDelta::days(1),
                    "operator:ops",
                    now,
                )
                .await
                .expect("set_window");
            } else {
                agentos_store::halt::place(&mut tx, "the CFO called", "operator:ops", now)
                    .await
                    .expect("place")
                    .expect("the tenant was running");
            }
            tx.commit().await.expect("commit the stop");

            // The poller will not take this row, so it is not the poller being
            // behind. It is a customer who asked us to wait.
            assert_eq!(
                lag_secs(&db).await.expect("lag"),
                0,
                "{label}: one stopped company took every replica out of the load balancer"
            );

            // And the deferral is genuinely a deferral: nothing published it,
            // nothing burned an attempt, and lifting the stop makes it lag
            // again — which is what says this hid a row rather than lost one.
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            if stop {
                agentos_store::halt::set_window(
                    &mut tx,
                    now + TimeDelta::days(1),
                    "operator:ops",
                    now,
                )
                .await
                .expect("extend");
            } else {
                agentos_store::halt::release(&mut tx)
                    .await
                    .expect("release")
                    .expect("it was stopped");
            }
            tx.commit().await.expect("commit the release");
            assert!(
                lag_secs(&db).await.expect("lag") > crate::MAX_OUTBOX_LAG_SECS,
                "{label}: the release has to give the backlog back"
            );

            drop_tenant(&db, tenant).await;
        }
    }
}
