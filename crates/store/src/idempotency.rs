//! Request-replay records: run a keyed request once, return the same answer
//! forever after.
//!
//! The whole module is three statements against `idempotency_records`, whose
//! primary key `(tenant_id, scope, key)` does all the real work. `scope` is the
//! endpoint the key was issued for — the column is named `scope` because it
//! also separates API replays from [`IdempotencyKey::for_step`] replays that
//! happen to share a key string, and the argument here is called `endpoint`
//! because that is what an HTTP caller has in hand.
//!
//! The protocol is three calls:
//!
//! ```text
//! match idempotency::begin(&mut tx, "POST /employees", &key, &hash).await? {
//!     Begin::Execute      => { /* commit tx, do the work, then complete() */ }
//!     Begin::Replay(r)    => return r,          // do NOT re-execute
//!     Begin::InFlight     => return 409/retry,  // someone else is executing
//! }
//! ```
//!
//! **Commit the transaction that returned [`Begin::Execute`] before doing the
//! work.** The `in_flight` row is the claim; if it is still uncommitted while
//! the handler runs, a concurrent request blocks on it instead of being told to
//! come back later, and nothing is recovered if the handler dies.
//!
//! Three things are worth stating plainly, because each one is a bug someone
//! has shipped before:
//!
//! * **Same key, different body is a conflict, not a replay.** Returning the
//!   first response to a second, different request is silent data loss. The
//!   stored `request_hash` is compared before anything else, in every state.
//! * **The race is arbitrated by the unique index, not by a read-then-write.**
//!   `INSERT ... ON CONFLICT DO NOTHING` is atomic, and Postgres makes the
//!   loser of a race *wait* on the winner's speculative insertion, so by the
//!   time the loser looks the winner's row is either committed (→
//!   [`Begin::InFlight`]) or gone (→ the key is free and the loser retries).
//!   No advisory locks, no `SELECT ... FOR UPDATE`, no double execution.
//! * **The hash is the caller's to compute.** This crate stores an opaque
//!   string; hashing a request body is not a database concern, and `sha2` is
//!   not a dependency here.
//!
//! ponytail: `expires_at` is left NULL — no TTL sweeper. A handler that dies
//! between `begin` and `complete`/`release` wedges its key until someone
//! deletes the row. Add a sweeper (`DELETE ... WHERE state = 'in_flight' AND
//! created_at < now() - interval`) the first time that actually happens.

use agentos_domain::ids::IdempotencyKey;
use serde_json::Value;

use crate::db::{StoreError, TenantTx};

/// The recorded outcome of a request that already ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredResponse {
    /// HTTP status the original request produced.
    pub status: u16,
    /// Response body, as stored.
    pub body: Value,
}

/// What the caller should do with this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begin {
    /// This caller owns the key: commit, execute, then call
    /// [`complete`] (or [`release`] if the work failed).
    Execute,
    /// The request already ran. Return this and execute nothing.
    Replay(StoredResponse),
    /// Another request holds the key and has not finished. The caller should
    /// wait and retry, or answer 409 — it must not execute.
    InFlight,
}

/// `(request_hash, state, status_code, response)` as stored.
type Record = (Option<String>, String, Option<i32>, Option<Value>);

/// Claim `key` for `endpoint`, or discover that it is already spoken for.
///
/// `request_hash` is any stable digest of the request body. Presenting a
/// different hash for a key that already exists is [`StoreError::Conflict`] —
/// the caller's 409 — whatever state the record is in.
///
/// Returns [`StoreError::Serialization`] in the one pathological case: the
/// racing winner rolled back twice while we were looking. Retry the
/// transaction.
pub async fn begin(
    tx: &mut TenantTx<'_>,
    endpoint: &str,
    key: &IdempotencyKey,
    request_hash: &str,
) -> Result<Begin, StoreError> {
    let tenant = tx.tenant_id().as_uuid();

    // Twice, because between the failed insert and the select the winner may
    // have rolled back and taken its row with it, freeing the key again.
    for _ in 0..2 {
        let claimed = sqlx::query(
            "INSERT INTO idempotency_records (tenant_id, scope, key, request_hash, state) \
             VALUES ($1, $2, $3, $4, 'in_flight') \
             ON CONFLICT (tenant_id, scope, key) DO NOTHING",
        )
        .bind(tenant)
        .bind(endpoint)
        .bind(key.as_str())
        .bind(request_hash)
        .execute(&mut ***tx)
        .await?
        .rows_affected();

        if claimed == 1 {
            return Ok(Begin::Execute);
        }

        let existing: Option<Record> = sqlx::query_as(
            "SELECT request_hash, state, status_code, response FROM idempotency_records \
             WHERE tenant_id = $1 AND scope = $2 AND key = $3",
        )
        .bind(tenant)
        .bind(endpoint)
        .bind(key.as_str())
        .fetch_optional(&mut ***tx)
        .await?;

        let Some((stored_hash, state, status, body)) = existing else {
            continue;
        };

        if stored_hash.as_deref() != Some(request_hash) {
            return Err(StoreError::conflict(
                "idempotency key reused with a different request body",
            ));
        }

        return Ok(match (state.as_str(), status, body) {
            ("done", Some(status), Some(body)) => Begin::Replay(StoredResponse {
                // status_code is only ever written by `complete`, from a u16.
                status: status as u16,
                body,
            }),
            _ => Begin::InFlight,
        });
    }

    Err(StoreError::Serialization)
}

/// Record the response for a key this caller claimed with [`Begin::Execute`].
///
/// Only moves an `in_flight` record to `done`; anything else — the row was
/// released, the tenant is gone, another writer already recorded a response —
/// is a [`StoreError::Conflict`] rather than a silent overwrite of an answer
/// someone may already have been given.
pub async fn complete(
    tx: &mut TenantTx<'_>,
    endpoint: &str,
    key: &IdempotencyKey,
    status: u16,
    body: &Value,
) -> Result<(), StoreError> {
    let updated = sqlx::query(
        "UPDATE idempotency_records \
         SET state = 'done', status_code = $4, response = $5, updated_at = now() \
         WHERE tenant_id = $1 AND scope = $2 AND key = $3 AND state = 'in_flight'",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(endpoint)
    .bind(key.as_str())
    .bind(i32::from(status))
    .bind(body)
    .execute(&mut ***tx)
    .await?
    .rows_affected();

    if updated == 1 {
        Ok(())
    } else {
        Err(StoreError::conflict("idempotency_records.state"))
    }
}

/// Give the key back after a failed attempt, so the client can retry it.
///
/// Deletes only an `in_flight` record: a recorded response is never withdrawn.
pub async fn release(
    tx: &mut TenantTx<'_>,
    endpoint: &str,
    key: &IdempotencyKey,
) -> Result<(), StoreError> {
    sqlx::query(
        "DELETE FROM idempotency_records \
         WHERE tenant_id = $1 AND scope = $2 AND key = $3 AND state = 'in_flight'",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(endpoint)
    .bind(key.as_str())
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::db::Db;

    const ENDPOINT: &str = "POST /v1/employees";

    /// Connect and migrate, or `None` when there is no database to talk to.
    /// The thing under test is a unique index and Postgres' speculative-insert
    /// waiting; a mock would prove nothing, so we skip loudly instead.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; store tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A committed tenant of its own, so tests can run repeatedly and in
    /// parallel without seeing each other's keys.
    async fn seed(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'idempotency test')")
            .bind(tenant.as_uuid())
            .bind(format!("idem-{}", tenant.as_uuid()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit seed");
        tenant
    }

    /// Cascades to `idempotency_records`, so every row this test made goes too.
    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    fn key() -> IdempotencyKey {
        IdempotencyKey::from_client(&format!("k-{}", uuid::Uuid::now_v7())).expect("valid key")
    }

    /// The happy path: claim, record, and then every replay of the same body
    /// gets the stored answer back without executing anything.
    #[tokio::test]
    async fn same_key_same_body_replays_the_stored_response() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;
        let key = key();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            begin(&mut tx, ENDPOINT, &key, "hash-a").await.unwrap(),
            Begin::Execute
        );
        // Mid-flight, before the response exists: not a replay, not executable.
        assert_eq!(
            begin(&mut tx, ENDPOINT, &key, "hash-a").await.unwrap(),
            Begin::InFlight
        );
        complete(&mut tx, ENDPOINT, &key, 201, &json!({"id": "emp_1"}))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            begin(&mut tx, ENDPOINT, &key, "hash-a").await.unwrap(),
            Begin::Replay(StoredResponse {
                status: 201,
                body: json!({"id": "emp_1"}),
            })
        );
        // Recording a second response for a settled key is refused rather than
        // overwriting an answer the client already has.
        assert!(matches!(
            complete(&mut tx, ENDPOINT, &key, 500, &json!({"oops": true})).await,
            Err(StoreError::Conflict(_))
        ));
        tx.rollback().await.unwrap();

        drop_tenant(&db, tenant).await;
    }

    /// The reason the hash is stored at all: reusing a key for a different body
    /// must not hand back the first request's answer.
    #[tokio::test]
    async fn same_key_different_body_is_a_conflict() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;
        let key = key();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        begin(&mut tx, ENDPOINT, &key, "hash-a").await.unwrap();
        complete(&mut tx, ENDPOINT, &key, 200, &json!({"ok": true}))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        for state in ["done", "in_flight"] {
            let mut tx = db.tenant_tx(tenant).await.expect("tx");
            match begin(&mut tx, ENDPOINT, &key, "hash-b").await {
                Err(StoreError::Conflict(msg)) => {
                    assert!(msg.contains("different request body"), "{msg}");
                }
                other => panic!("expected a conflict while {state}, got {other:?}"),
            }
            // Rewind to in_flight for the second pass: the check must not
            // depend on the record having settled.
            sqlx::query(
                "UPDATE idempotency_records SET state = 'in_flight', status_code = NULL, \
                 response = NULL WHERE tenant_id = $1 AND scope = $2 AND key = $3",
            )
            .bind(tenant.as_uuid())
            .bind(ENDPOINT)
            .bind(key.as_str())
            .execute(&mut **tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        drop_tenant(&db, tenant).await;
    }

    /// Two genuinely simultaneous transactions, same key. Exactly one may
    /// execute; the loser must be told to wait, and there must be one row.
    ///
    /// This is the test that would catch a read-then-write implementation:
    /// both sides would read "no record", both would insert, and both would
    /// charge the customer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_simultaneous_requests_produce_exactly_one_executor() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;
        let key = key();

        // Each task opens its own transaction on its own connection and commits
        // immediately, which is what the protocol tells callers to do. The
        // loser blocks inside `begin` on the winner's speculative insert until
        // that commit lands.
        async fn attempt(db: &Db, tenant: TenantId, key: &IdempotencyKey) -> Begin {
            let mut tx = db.tenant_tx(tenant).await.expect("tx");
            let outcome = begin(&mut tx, ENDPOINT, key, "hash-a")
                .await
                .expect("begin");
            tx.commit().await.expect("commit");
            outcome
        }

        // Spawned onto two worker threads, not just two futures on one: the
        // insert that loses has to block on the winner's uncommitted row for
        // real.
        let (a, b) = (db.clone(), db.clone());
        let (ka, kb) = (key.clone(), key.clone());
        let first = tokio::spawn(async move { attempt(&a, tenant, &ka).await });
        let second = tokio::spawn(async move { attempt(&b, tenant, &kb).await });
        let (first, second) = (first.await.unwrap(), second.await.unwrap());

        let mut outcomes = [first, second];
        outcomes.sort_by_key(|o| matches!(o, Begin::InFlight));
        assert_eq!(
            outcomes,
            [Begin::Execute, Begin::InFlight],
            "exactly one caller may execute"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM idempotency_records WHERE tenant_id = $1 AND key = $2",
        )
        .bind(tenant.as_uuid())
        .bind(key.as_str())
        .fetch_one(&mut **tx)
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(rows, 1);

        drop_tenant(&db, tenant).await;
    }

    /// A failed handler hands the key back, and the next attempt executes for
    /// real instead of inheriting a wedged `in_flight` row.
    #[tokio::test]
    async fn release_frees_the_key_but_never_a_recorded_response() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;
        let key = key();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        begin(&mut tx, ENDPOINT, &key, "hash-a").await.unwrap();
        release(&mut tx, ENDPOINT, &key).await.unwrap();
        // Free again — and free for a different body, since nothing ran.
        assert_eq!(
            begin(&mut tx, ENDPOINT, &key, "hash-b").await.unwrap(),
            Begin::Execute
        );
        complete(&mut tx, ENDPOINT, &key, 200, &json!({"ok": true}))
            .await
            .unwrap();

        // A settled record is not withdrawable.
        release(&mut tx, ENDPOINT, &key).await.unwrap();
        assert!(matches!(
            begin(&mut tx, ENDPOINT, &key, "hash-b").await.unwrap(),
            Begin::Replay(_)
        ));
        tx.rollback().await.unwrap();

        drop_tenant(&db, tenant).await;
    }

    /// The key namespace is per endpoint: the same client key on two routes is
    /// two independent records.
    #[tokio::test]
    async fn the_same_key_on_another_endpoint_is_a_different_record() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;
        let key = key();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        begin(&mut tx, ENDPOINT, &key, "hash-a").await.unwrap();
        assert_eq!(
            begin(&mut tx, "POST /v1/payments", &key, "hash-b")
                .await
                .unwrap(),
            Begin::Execute
        );
        tx.rollback().await.unwrap();

        drop_tenant(&db, tenant).await;
    }
}
