//! `work_items`: the shared board, in SQL and with no opinion about it.
//!
//! `migrations/0061_work_items.sql` carries the argument for why the row has
//! four fields that matter and not fourteen. This module is the four statements
//! underneath it: put one down, read the whole board, read one seat's open
//! items, change the half of a row that is allowed to change.
//!
//! # Why the tenant is never a parameter
//!
//! Every function here takes a [`TenantTx`] and nothing else, for
//! [`crate::halt`]'s reason: the tenant is the one `SET LOCAL app.tenant_id` on
//! that transaction, and a `tenant_id` argument beside it would be a second
//! answer to a question that already has one.
//!
//! # Why the order is spelled out here rather than left to the caller
//!
//! `ordinal asc nulls last, created_at asc` appears in both reads and nowhere
//! else. It is the founder's ranking, and a caller that sorted its own copy
//! would be a second ranking — the failure `0061`'s header calls two answers to
//! one question. The employee's brief and the founder's screen show the same
//! list in the same order because it is one `ORDER BY`.

use chrono::{DateTime, Utc};
use sqlx::Row;

use agentos_domain::ids::{EmployeeId, WorkItemId};

use crate::db::{StoreError, TenantTx};

/// One row of `work_items`.
///
/// `title` is a plain `String` here and is wrapped by
/// [`agentos_app::backlog`](../../agentos_app/backlog/index.html) on the way to
/// a turn, not here: this crate speaks SQL and the trust boundary is a decision
/// about a *reader*, taken where the reader is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The item.
    pub id: WorkItemId,
    /// What to do, in one line.
    pub title: String,
    /// Who is holding it. `None` is the shared board.
    pub assignee_id: Option<EmployeeId>,
    /// Where the founder put it. `None` is unranked — see the migration.
    pub ordinal: Option<i64>,
    /// When it stopped being work. `None` is open.
    pub closed_at: Option<DateTime<Utc>>,
    /// When it was written down.
    pub created_at: DateTime<Utc>,
}

/// The columns, in one spelling, so the four statements below cannot disagree
/// about what a row is.
///
/// Interpolated, so every statement here goes through `sqlx::AssertSqlSafe`.
/// **The audit that asks for is this sentence**, and it is the same one
/// [`crate::outbox`]'s plan assertions make: both halves are compile-time
/// constants of this module. Nothing a caller passes reaches the string — every
/// value is a bind parameter — so there is no input for an injection to arrive
/// on.
const COLUMNS: &str = "id, title, assignee_id, ordinal, closed_at, created_at";

/// The founder's ranking. See the module docs for why it is written once.
const ORDER: &str = "ORDER BY ordinal ASC NULLS LAST, created_at ASC";

/// One row, decoded. By reference so both `Vec` reads can name it in a `map`.
fn row_of(row: &sqlx::postgres::PgRow) -> Item {
    Item {
        id: WorkItemId::from_uuid(row.get("id")),
        title: row.get("title"),
        assignee_id: row
            .get::<Option<uuid::Uuid>, _>("assignee_id")
            .map(EmployeeId::from_uuid),
        ordinal: row.get("ordinal"),
        closed_at: row.get("closed_at"),
        created_at: row.get("created_at"),
    }
}

/// Put one item on the board.
///
/// `assignee` is `None` for an item nobody has been given yet, which is what
/// makes this a board rather than one list per seat.
///
/// The id is the caller's, not this function's: nothing in this crate reads the
/// clock (see [`agentos_domain::ids`]), and a caller that already holds the id
/// can write it into an audit row in the same transaction.
///
/// # Why the `EXISTS` clause is not what the foreign key already does
///
/// `work_items.assignee_id references employees (id)` is checked by Postgres as
/// the table's *owner*, which walks past row-level security — so the constraint
/// alone accepts any employee uuid in the whole deployment. Two things then go
/// wrong at once: the insert succeeding is an existence oracle for another
/// company's employee id, and the row it writes is a cross-tenant reference, so
/// terminating B's employee mutates A's board through `on delete set null`.
///
/// The `EXISTS` runs inside *this* transaction, where `employees` is already
/// confined by the policy, so an assignee that is not this company's makes the
/// `SELECT` produce no row and this return [`StoreError::NotFound`] — the same
/// silence a read of somebody else's item keeps.
pub async fn post(
    tx: &mut TenantTx<'_>,
    id: WorkItemId,
    title: &str,
    assignee: Option<EmployeeId>,
) -> Result<Item, StoreError> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO work_items (id, tenant_id, title, assignee_id) \
         SELECT $1, $2, $3, $4 \
          WHERE $4::uuid IS NULL OR EXISTS (SELECT 1 FROM employees WHERE id = $4) \
         RETURNING {COLUMNS}"
    )))
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(title)
    .bind(assignee.map(|e| e.as_uuid()))
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;
    Ok(row_of(&row))
}

/// Every item on this company's board, open and closed, in the founder's order.
///
/// ponytail: no pagination and no `closed` filter. A board is a thing a human
/// types into by hand; give this a window the day one has enough rows for the
/// answer not to fit on a screen.
pub async fn board(tx: &mut TenantTx<'_>) -> Result<Vec<Item>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM work_items {ORDER}"
    )))
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows.iter().map(row_of).collect())
}

/// What one seat still has to do, in the founder's order.
///
/// **Assigned items only.** An item with no assignee is on the board and is
/// nobody's; it is deliberately not offered to every employee at once, because
/// two employees shown the same unassigned item would both do it and nothing
/// here claims. Assigning is the founder's verb — `PUT /v1/work/{id}` — and
/// that is the whole of what "shared" means today.
pub async fn open_for(
    tx: &mut TenantTx<'_>,
    assignee: EmployeeId,
) -> Result<Vec<Item>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM work_items \
         WHERE assignee_id = $1 AND closed_at IS NULL {ORDER}"
    )))
    .bind(assignee.as_uuid())
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows.iter().map(row_of).collect())
}

/// Replace the mutable half of one item: who has it, where it sits, whether it
/// is done.
///
/// **Replace, not merge**, and all three at once. A merge needs a way to say
/// "leave this alone" that is different from "set this to null" — `assignee:
/// null` has to mean *put it back on the board* — and the two spellings of
/// absent are the classic way to unassign somebody by forgetting a field. So
/// the caller sends the whole mutable state and this writes the whole mutable
/// state.
///
/// `title` is **not** here and cannot be changed. An item whose words changed is
/// a different item, and an employee that read one sentence off its brief this
/// morning and a different one this afternoon under the same id has no way to
/// notice.
///
/// `closed` is a boolean and `closed_at` is a timestamp: closing an item that is
/// already closed keeps the first instant rather than moving it, so "when did
/// this stop being work" survives a client that re-sends the same body.
///
/// [`StoreError::NotFound`] when there is no such item, when it belongs to
/// somebody else, or when the assignee does — the `EXISTS` clause is [`post`]'s
/// and carries [`post`]'s argument. The three are indistinguishable on purpose
/// and are the same silence every other read here keeps.
pub async fn amend(
    tx: &mut TenantTx<'_>,
    id: WorkItemId,
    assignee: Option<EmployeeId>,
    ordinal: Option<i64>,
    closed: bool,
    now: DateTime<Utc>,
) -> Result<Item, StoreError> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE work_items SET \
           assignee_id = $2, \
           ordinal = $3, \
           closed_at = CASE WHEN $4 THEN COALESCE(closed_at, $5) ELSE NULL END \
         WHERE id = $1 \
           AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM employees WHERE id = $2)) \
         RETURNING {COLUMNS}"
    )))
    .bind(id.as_uuid())
    .bind(assignee.map(|e| e.as_uuid()))
    .bind(ordinal)
    .bind(closed)
    .bind(now)
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;
    Ok(row_of(&row))
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use chrono::SubsecRound;

    use super::*;
    use crate::db::Db;

    async fn fixture() -> Option<(Db, TenantId, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the work board needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let a = seed_tenant(&db).await;
        let b = seed_tenant(&db).await;
        Some((db, a, b))
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'board test')")
            .bind(tenant_id.as_uuid())
            .bind(format!("brd-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");
        tenant_id
    }

    async fn seed_employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .bind(slug)
        .execute(&mut *admin)
        .await
        .expect("insert employee");
        admin.commit().await.expect("commit");
        id
    }

    /// The three failures `0061`'s header names, in one run: an item survives
    /// the transaction that wrote it, two seats read one ordered board, and the
    /// order is the founder's rather than the arrival order.
    #[tokio::test]
    async fn an_item_outlives_its_writer_and_the_founder_owns_the_order() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        let ada = seed_employee(&db, tenant, "ada-board").await;
        let bob = seed_employee(&db, tenant, "bob-board").await;
        let now = Utc::now().trunc_subsecs(6);

        // Written in one transaction…
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let first = post(
            &mut tx,
            WorkItemId::new_v7(now),
            "chase the tariff code",
            Some(ada),
        )
        .await
        .expect("post");
        let second = post(
            &mut tx,
            WorkItemId::new_v7(now),
            "answer the customs email",
            Some(ada),
        )
        .await
        .expect("post");
        let loose = post(&mut tx, WorkItemId::new_v7(now), "nobody's yet", None)
            .await
            .expect("post");
        tx.commit().await.expect("commit");

        // …and read back in another, which is the whole of failure 1.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let mine = open_for(&mut tx, ada).await.expect("open");
        assert_eq!(
            mine.iter().map(|i| i.id).collect::<Vec<_>>(),
            vec![first.id, second.id],
            "both survived the transaction that wrote them, in arrival order while unranked"
        );
        assert!(
            open_for(&mut tx, bob).await.expect("open").is_empty(),
            "an item assigned to one seat is not offered to another"
        );
        assert!(
            !mine.iter().any(|i| i.id == loose.id),
            "an unassigned item is on the board and is nobody's — see `open_for`"
        );

        // Failure 3: the founder reorders, and the order he wrote is the order
        // the employee reads.
        amend(&mut tx, second.id, Some(ada), Some(1), false, now)
            .await
            .expect("rank");
        assert_eq!(
            open_for(&mut tx, ada)
                .await
                .expect("open")
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![second.id, first.id],
            "a ranked item comes before an unranked one, whatever order they arrived in"
        );

        // Failure 2: the founder moves an item between two seats without
        // rewriting it, which is what one shared board buys over two lists.
        amend(&mut tx, first.id, Some(bob), None, false, now)
            .await
            .expect("reassign");
        assert_eq!(
            open_for(&mut tx, bob)
                .await
                .expect("open")
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![first.id],
            "the same item, the same id, a different seat"
        );

        // Closing is idempotent on the instant, so a client that re-sends the
        // same body does not move "when did this stop being work".
        let closed = amend(&mut tx, second.id, Some(ada), Some(1), true, now)
            .await
            .expect("close");
        let again = amend(
            &mut tx,
            second.id,
            Some(ada),
            Some(1),
            true,
            now + chrono::Duration::hours(1),
        )
        .await
        .expect("close again");
        assert_eq!(closed.closed_at, again.closed_at, "the first instant wins");
        assert!(
            !open_for(&mut tx, ada)
                .await
                .expect("open")
                .iter()
                .any(|i| i.id == second.id),
            "a closed item is not work any more"
        );
        assert_eq!(
            board(&mut tx).await.expect("board").len(),
            3,
            "…and is still on the board: closing is not forgetting"
        );
        tx.rollback().await.expect("rollback");
    }

    /// One company's board is invisible to another, and the isolation is
    /// asserted **from the catalogue** and not only from behaviour.
    ///
    /// `SET LOCAL ROLE app_role` is already bound by `enable` alone, so a test
    /// that only reads across two tenant transactions passes on a table whose
    /// owner — the role every migration and every cross-tenant loop connects as
    /// — can still read every company's work. `relforcerowsecurity` is the only
    /// thing that says otherwise.
    #[tokio::test]
    async fn a_board_is_one_company_s_and_the_catalogue_says_so() {
        let Some((db, a, b)) = fixture().await else {
            return;
        };
        let now = Utc::now().trunc_subsecs(6);
        let ada = seed_employee(&db, a, "ada-isolated").await;

        let mut tx = db.tenant_tx(a).await.expect("tx a");
        let mine = post(&mut tx, WorkItemId::new_v7(now), "A's work", Some(ada))
            .await
            .expect("post");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(b).await.expect("tx b");
        assert!(
            board(&mut tx).await.expect("board").is_empty(),
            "B must not see A's board"
        );
        // …and cannot put A's employee on its own board. The foreign key is
        // checked as the table's owner and would have accepted this; the
        // `EXISTS` clause inside this transaction is what refuses it. Without
        // it, terminating A's employee would mutate B's board.
        assert!(
            matches!(
                post(&mut tx, WorkItemId::new_v7(now), "do B's work", Some(ada)).await,
                Err(StoreError::NotFound)
            ),
            "an assignee from another company must be refused, not filed"
        );
        assert!(
            matches!(
                amend(&mut tx, mine.id, None, Some(0), true, now).await,
                Err(StoreError::NotFound)
            ),
            "B must not be able to close A's work either — and cannot tell it exists"
        );
        tx.rollback().await.expect("rollback");

        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = 'work_items'::regclass",
        )
        .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
        .await
        .expect("catalogue");
        assert!(enabled, "work_items has row-level security enabled");
        assert!(
            forced,
            "…and forced, or the owning role reads every company's board"
        );

        // And no DELETE, which is the grant the migration argues for: a closed
        // item is the record that somebody asked for something.
        let deletable: bool =
            sqlx::query_scalar("SELECT has_table_privilege('app_role', 'work_items', 'DELETE')")
                .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
                .await
                .expect("privilege");
        assert!(
            !deletable,
            "app_role must not be able to delete work: closing is a column, forgetting is not a verb"
        );
    }
}
