//! Durable A2A tasks.
//!
//! The A2A server SDK ships an in-memory task store, and its own doc comment
//! says the contents do not survive a restart. That is the wrong default for
//! anything a *peer agent* holds an identifier for: the peer keeps its task id
//! across our deploy, and after a restart `GetTask` starts answering
//! `TASK_NOT_FOUND` for work we really did. So the task lives in Postgres,
//! behind the same row-level security as everything else in this crate.
//!
//! # This module does not know what a task is
//!
//! The row is `(id, tenant, employee, version, jsonb)` and the jsonb is opaque
//! here. That is deliberate: `agentos-store` does not depend on the A2A crates,
//! so the protocol types cannot leak into the storage layer and a protocol
//! version bump cannot force a migration. `crates/app/src/a2a.rs` owns the
//! mapping to and from `a2a::Task`.
//!
//! # Filtering
//!
//! [`list`] filters on the document (`task->>'contextId'`,
//! `task->'status'->>'state'`) rather than on copies of those values in their
//! own columns. Two spellings of the same fact drift; one does not.

use agentos_domain::ids::EmployeeId;
use serde_json::Value;

use crate::db::{StoreError, TenantTx};

/// The default page size when a caller asks for none. Matches the SDK's
/// in-memory store so a client sees the same window from either.
pub const DEFAULT_PAGE_SIZE: i64 = 50;

/// One stored task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    /// The A2A task id.
    pub id: String,
    /// Bumped on every [`update`]. A change counter, not a lock — the SDK's
    /// `TaskStore` never passes an expected version in, so there is nothing to
    /// compare against.
    pub version: i64,
    /// The whole task document, as the protocol layer serialised it.
    pub task: Value,
}

/// What [`list`] selects. Every field narrows; `None` narrows nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskQuery<'a> {
    /// Only tasks in this conversation.
    pub context_id: Option<&'a str>,
    /// Only tasks in this protocol state, matched against
    /// `task->'status'->>'state'` verbatim.
    pub state: Option<&'a str>,
    /// Rows to skip. Offset paging, because the SDK's page token is an opaque
    /// string it expects to hand back unchanged.
    ///
    /// ponytail: offset paging is O(offset) and can skip or repeat a row when
    /// the set changes underneath the cursor. Both are acceptable for a task
    /// list a peer polls; swap in keyset paging on `id` when a tenant has
    /// enough tasks to notice.
    pub offset: i64,
    /// At most this many rows. `None` means [`DEFAULT_PAGE_SIZE`].
    pub limit: Option<i64>,
}

/// One page of [`list`], plus the size of the whole match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPage {
    /// The rows in this page, ordered by id — which is UUIDv7 for tasks we
    /// minted, so ordering by it is ordering by creation time.
    pub rows: Vec<TaskRow>,
    /// How many rows matched, ignoring `offset` and `limit`.
    pub total: i64,
}

/// Store a task that does not exist yet.
///
/// `tenant_id` comes off the transaction, never from the caller; RLS's
/// `WITH CHECK` would reject anything else anyway. A duplicate id surfaces as
/// [`StoreError::Conflict`], which is the honest answer to "a peer asked us to
/// create a task we already have".
pub async fn create(
    tx: &mut TenantTx<'_>,
    employee_id: Option<EmployeeId>,
    id: &str,
    task: &Value,
) -> Result<i64, StoreError> {
    sqlx::query(
        "INSERT INTO a2a_tasks (id, tenant_id, employee_id, version, task) \
         VALUES ($1, $2, $3, 1, $4)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id.map(|e| e.as_uuid()))
    .bind(task)
    .execute(&mut ***tx)
    .await?;

    Ok(1)
}

/// Replace a task's document and bump its version. Returns the new version.
///
/// [`StoreError::NotFound`] when there is no such task *in this tenant* — RLS
/// makes "someone else's task" and "no task" the same answer, on purpose.
pub async fn update(tx: &mut TenantTx<'_>, id: &str, task: &Value) -> Result<i64, StoreError> {
    let version: Option<i64> = sqlx::query_scalar(
        "UPDATE a2a_tasks SET task = $2, version = version + 1, updated_at = now() \
         WHERE id = $1 RETURNING version",
    )
    .bind(id)
    .bind(task)
    .fetch_optional(&mut ***tx)
    .await?;

    version.ok_or(StoreError::NotFound)
}

/// One task, or `None`.
pub async fn get(tx: &mut TenantTx<'_>, id: &str) -> Result<Option<TaskRow>, StoreError> {
    let row: Option<(String, i64, Value)> =
        sqlx::query_as("SELECT id, version, task FROM a2a_tasks WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut ***tx)
            .await?;

    Ok(row.map(|(id, version, task)| TaskRow { id, version, task }))
}

/// One page of this tenant's tasks, plus the total that matched.
///
/// The count and the page are one statement — a window function over the
/// filtered set — so a task created between them cannot make the total
/// disagree with the page.
pub async fn list(tx: &mut TenantTx<'_>, query: &TaskQuery<'_>) -> Result<TaskPage, StoreError> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).max(1);
    let rows: Vec<(String, i64, Value, i64)> = sqlx::query_as(
        "SELECT id, version, task, count(*) OVER () AS total FROM a2a_tasks \
          WHERE ($1::text IS NULL OR task ->> 'contextId' = $1) \
            AND ($2::text IS NULL OR task -> 'status' ->> 'state' = $2) \
          ORDER BY id \
          OFFSET $3 LIMIT $4",
    )
    .bind(query.context_id)
    .bind(query.state)
    .bind(query.offset.max(0))
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    // An empty page carries no window value, so the total has to be recovered
    // separately — but only in that case, which is the cheap one.
    let total = match rows.first() {
        Some(&(_, _, _, total)) => total,
        None => count(tx, query).await?,
    };

    Ok(TaskPage {
        rows: rows
            .into_iter()
            .map(|(id, version, task, _)| TaskRow { id, version, task })
            .collect(),
        total,
    })
}

/// How many tasks match, ignoring paging. Only called when the page came back
/// empty, because otherwise the window function already answered it.
async fn count(tx: &mut TenantTx<'_>, query: &TaskQuery<'_>) -> Result<i64, StoreError> {
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM a2a_tasks \
          WHERE ($1::text IS NULL OR task ->> 'contextId' = $1) \
            AND ($2::text IS NULL OR task -> 'status' ->> 'state' = $2)",
    )
    .bind(query.context_id)
    .bind(query.state)
    .fetch_one(&mut ***tx)
    .await?;

    Ok(total)
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::db::Db;

    /// Connect and migrate, or `None` when there is no database to talk to.
    /// The module is SQL and RLS; a mock would prove nothing.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; a2a store tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let label = format!("a2a-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit seed");
        tenant
    }

    fn task(id: &str, context: &str, state: &str) -> Value {
        json!({
            "id": id,
            "contextId": context,
            "status": { "state": state },
        })
    }

    #[tokio::test]
    async fn a_task_round_trips_and_versions_on_update() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;
        let id = Uuid::now_v7().to_string();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let version = create(
            &mut tx,
            None,
            &id,
            &task(&id, "ctx-1", "TASK_STATE_SUBMITTED"),
        )
        .await
        .expect("create");
        assert_eq!(version, 1);

        let version = update(&mut tx, &id, &task(&id, "ctx-1", "TASK_STATE_COMPLETED"))
            .await
            .expect("update");
        assert_eq!(version, 2, "every write bumps the counter");

        let row = get(&mut tx, &id).await.expect("get").expect("present");
        assert_eq!(row.version, 2);
        assert_eq!(row.task["status"]["state"], json!("TASK_STATE_COMPLETED"));
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn updating_a_task_that_is_not_ours_is_not_found() {
        let Some(db) = db().await else { return };
        let mine = seed(&db).await;
        let theirs = seed(&db).await;
        let id = Uuid::now_v7().to_string();

        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        create(&mut tx, None, &id, &task(&id, "ctx", "TASK_STATE_WORKING"))
            .await
            .expect("create");
        tx.commit().await.expect("commit");

        // Same id, different tenant: the row exists, and the policy makes it
        // invisible rather than editable.
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        assert!(get(&mut tx, &id).await.expect("get").is_none());
        assert!(matches!(
            update(&mut tx, &id, &task(&id, "ctx", "TASK_STATE_COMPLETED")).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn list_filters_on_the_document_and_pages() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        for (context, state) in [
            ("ctx-a", "TASK_STATE_WORKING"),
            ("ctx-a", "TASK_STATE_COMPLETED"),
            ("ctx-b", "TASK_STATE_WORKING"),
        ] {
            let id = Uuid::now_v7().to_string();
            create(&mut tx, None, &id, &task(&id, context, state))
                .await
                .expect("create");
        }

        let all = list(&mut tx, &TaskQuery::default()).await.expect("list");
        assert_eq!(all.total, 3);
        assert_eq!(all.rows.len(), 3);

        let by_context = list(
            &mut tx,
            &TaskQuery {
                context_id: Some("ctx-a"),
                ..TaskQuery::default()
            },
        )
        .await
        .expect("list");
        assert_eq!(by_context.total, 2);

        let by_state = list(
            &mut tx,
            &TaskQuery {
                state: Some("TASK_STATE_WORKING"),
                ..TaskQuery::default()
            },
        )
        .await
        .expect("list");
        assert_eq!(by_state.total, 2);

        // A page smaller than the match still reports the whole match, so a
        // caller can build a page token from it.
        let page = list(
            &mut tx,
            &TaskQuery {
                limit: Some(2),
                ..TaskQuery::default()
            },
        )
        .await
        .expect("list");
        assert_eq!((page.rows.len(), page.total), (2, 3));

        // ...and past the end the total is still right, which is the case the
        // window function alone cannot answer.
        let past_end = list(
            &mut tx,
            &TaskQuery {
                offset: 10,
                ..TaskQuery::default()
            },
        )
        .await
        .expect("list");
        assert_eq!((past_end.rows.len(), past_end.total), (0, 3));

        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn a_task_id_the_peer_chose_cannot_be_unbounded() {
        let Some(db) = db().await else { return };
        let tenant = seed(&db).await;
        let huge = "x".repeat(201);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let err = create(
            &mut tx,
            None,
            &huge,
            &task(&huge, "ctx", "TASK_STATE_WORKING"),
        )
        .await;
        assert!(
            err.is_err(),
            "a 201-character task id must not reach the table"
        );
        tx.rollback().await.expect("rollback");
    }
}
