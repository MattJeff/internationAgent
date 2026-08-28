//! `work_items`: the shared board, in SQL and with no opinion about it.
//!
//! `migrations/0061_work_items.sql` carries the argument for why the row has
//! four fields that matter and not fourteen. This module is the statements
//! underneath it: put one down, read the whole board, read one seat's open
//! items, read the ones nobody holds, take one, say one is done, and change the
//! half of a row an operator is allowed to change.
//!
//! # Two surfaces, and why the split is where it is
//!
//! [`post`] and [`amend`] are the founder's — he assigns anyone, ranks anything
//! and reopens what he likes. [`claim`] and [`close`] are an employee's, and
//! each carries its whole authority in its own `WHERE`: you may take what
//! nobody holds, and you may finish what is yours. Neither reads the org chart,
//! and neither has a lease — [`claim`] says why at length.
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
    /// Who wrote it down. `None` is an operator through `POST /v1/work` — see
    /// `migrations/0064_work_items_posted_by.sql` for why that is the honest
    /// value rather than a uuid somebody invented.
    pub posted_by: Option<EmployeeId>,
    /// When it stopped being work. `None` is open.
    pub closed_at: Option<DateTime<Utc>>,
    /// When it was written down.
    pub created_at: DateTime<Utc>,
}

/// The longest title `work_items_title_shape` accepts, named once so nothing
/// upstream invents a second number.
///
/// It is **characters**, because the constraint is `char_length(btrim(title))`
/// and a byte count would refuse titles Postgres accepts. A caller that checks
/// this before writing turns a model's over-long line into a tool result it can
/// shorten; without the check it is a `23514` out of the driver, which
/// `StoreError` classifies as `Database`, which ends the turn.
pub const MAX_TITLE: usize = 200;

/// The columns, in one spelling, so the four statements below cannot disagree
/// about what a row is.
///
/// Interpolated, so every statement here goes through `sqlx::AssertSqlSafe`.
/// **The audit that asks for is this sentence**, and it is the same one
/// [`crate::outbox`]'s plan assertions make: both halves are compile-time
/// constants of this module. Nothing a caller passes reaches the string — every
/// value is a bind parameter — so there is no input for an injection to arrive
/// on.
const COLUMNS: &str = "id, title, assignee_id, ordinal, posted_by, closed_at, created_at";

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
        posted_by: row
            .get::<Option<uuid::Uuid>, _>("posted_by")
            .map(EmployeeId::from_uuid),
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
///
/// `posted_by` carries the identical clause for the identical reason. Nothing
/// reachable today puts a payload in it — an employee's own id comes off
/// `Effects`, and `POST /v1/work` passes `None` — but it is the same foreign
/// key checked by the same owning role, so the same uuid from the same wrong
/// company would file the same cross-tenant reference. A guard on one of two
/// identical columns is a guard somebody will assume covers both.
///
/// **Both disjunctions are parenthesised**, and that is not style: `AND` binds
/// tighter than `OR`, so dropping the brackets makes the first clause read
/// `$4 IS NULL OR (EXISTS(..) AND ($5 IS NULL OR EXISTS(..)))` — still valid
/// SQL, still filtering something, and it accepts any assignee at all whenever
/// `$4` is null. The tests below exercise each column separately.
pub async fn post(
    tx: &mut TenantTx<'_>,
    id: WorkItemId,
    title: &str,
    assignee: Option<EmployeeId>,
    posted_by: Option<EmployeeId>,
) -> Result<Item, StoreError> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO work_items (id, tenant_id, title, assignee_id, posted_by) \
         SELECT $1, $2, $3, $4, $5 \
          WHERE ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM employees WHERE id = $4)) \
            AND ($5::uuid IS NULL OR EXISTS (SELECT 1 FROM employees WHERE id = $5)) \
         RETURNING {COLUMNS}"
    )))
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(title)
    .bind(assignee.map(|e| e.as_uuid()))
    .bind(posted_by.map(|e| e.as_uuid()))
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
/// **Assigned items only**, and [`unclaimed`] is the other half. This used to
/// carry the argument for why nothing showed an employee the unassigned items —
/// *"two employees shown the same unassigned item would both do it and nothing
/// here claims"* — and the second clause is what changed: [`claim`] is one
/// conditional `UPDATE`, so exactly one of two employees reaching for the same
/// item gets it and the other is told so. The first clause was never the
/// objection on its own.
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

/// The pool: open work nobody is holding, in the founder's order.
///
/// **Not scoped to a team, a line or a poster, and that is a decision.** The
/// only writer that can leave `assignee_id` null is `POST /v1/work` — an
/// employee filing through `Effects::post_work` must name itself or a direct
/// report, and there is deliberately no spelling of *nobody* — so every row this
/// returns is the founder's own undecided work. He wrote it without saying who
/// does it; inventing a team boundary here would be answering, on his behalf,
/// the exact question he declined to answer.
///
/// It also costs nothing to widen, because it cannot be filled from a turn: the
/// flooding the org-chart guard bounds one function over is unreachable here,
/// and the titles are the company's own rather than a colleague's. They are
/// still wrapped [`Untrusted`](agentos_domain::untrusted::Untrusted) on the way
/// to a brief, for the reason `agentos_app::backlog` gives: the wrapper is
/// unconditional so that nobody ever has to decide it is safe to drop.
///
/// ponytail: unbounded and unpaginated, like [`board`]. The number this needs is
/// a `LIMIT` on what one brief may be shown, and it belongs beside the one
/// `loops::initiative::waiting` already has an open question about — one answer
/// for both lists, not two.
pub async fn unclaimed(tx: &mut TenantTx<'_>) -> Result<Vec<Item>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM work_items \
         WHERE assignee_id IS NULL AND closed_at IS NULL {ORDER}"
    )))
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows.iter().map(row_of).collect())
}

/// Take one unheld item. `false` is somebody else got there first.
///
/// # Why there is no lease, no deadline and no number
///
/// `crate::outbox` and `crate::initiative` both claim with a lease, and the
/// difference is not that this is smaller: it is that **somebody is owed an
/// outbox event**. A queued email must be sent whether or not the worker that
/// picked it up survives, so the row has to come back to the pool on its own,
/// and a duration is the price of that. Nobody is owed a work item. If whoever
/// took it does nothing, the item sits there, visible on `GET /v1/work` with an
/// assignee and a `created_at`, and the founder reassigns it with
/// `PUT /v1/work/{id}` — a verb that already exists and is already his.
///
/// And a lease here would be **worse than none**, which is the half of the
/// argument that decides it. Its duration would be a number nobody has: an
/// outbox lease can be short because the retry is idempotent on a key, while the
/// work behind an item is arbitrary and keyed by nothing. An item that expired
/// out from under an employee halfway through emailing a broker would be handed
/// to a second employee who emails the broker again — which is the double-work
/// claiming exists to prevent, reintroduced by the mechanism meant to prevent
/// it. There is no duration that is right for "chase the tariff code".
///
/// The one automatic return that *is* wanted already exists and is not this
/// function's: `on delete set null` on `assignee_id`, which puts a terminated
/// employee's work back on the board — `0061` argues it.
///
/// # Why one statement is the whole of the mutual exclusion
///
/// `Db::tenant_tx` sets no isolation level, so this runs at PostgreSQL's default
/// **read committed**. Two employees reaching for one item serialise on the row
/// lock, and the loser's `WHERE` is then re-evaluated against the *committed*
/// version, which now has an assignee — so it matches nothing and this returns
/// `false`. That is a fact about `tenant_tx` and not about the statement: under
/// repeatable read the same statement would raise `40001` instead, which is a
/// different answer to give a model.
///
/// `closed_at IS NULL` is in the `WHERE` beside the assignee and is not
/// redundant with it: an item the founder closed while it sat unassigned is not
/// work any more, and claiming it would put a finished job back in somebody's
/// brief.
///
/// `EXISTS` on the claimant for [`post`]'s reason — the foreign key is checked
/// as the table's owner and walks past the policy — and it matters more here
/// than there: an `assignee_id` from another company puts the item on nobody's
/// board and arms `on delete set null` from a tenant that cannot see it.
pub async fn claim(
    tx: &mut TenantTx<'_>,
    id: WorkItemId,
    who: EmployeeId,
) -> Result<bool, StoreError> {
    let taken = sqlx::query(
        "UPDATE work_items SET assignee_id = $2 \
          WHERE id = $1 \
            AND assignee_id IS NULL \
            AND closed_at IS NULL \
            AND EXISTS (SELECT 1 FROM employees WHERE id = $2)",
    )
    .bind(id.as_uuid())
    .bind(who.as_uuid())
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(taken == 1)
}

/// Say one item is done. `false` is "that is not yours", which is also what a
/// caller gets for an item that does not exist.
///
/// # Only the assignee, and deliberately not whoever posted it
///
/// Closing asserts *this got done*, and that is a claim only the seat that did
/// it can make. A manager that filed work for a report and could close it would
/// be signing off work it did not see; the founder, who does need to close other
/// people's items, has `PUT /v1/work/{id}` and an operator key — a different
/// surface for a different authority, which is the whole shape of this table.
///
/// So there is no org-chart read here at all. `assignee_id = $2` is the entire
/// rule, and it is the same silence every other read keeps: not yours, not
/// there and never existed are one answer.
///
/// **Closing is one-way from a turn.** Nothing here reopens, and that asymmetry
/// is not an oversight: an employee that could reopen could argue with the
/// founder's decision that something was finished, and the founder can reopen
/// through `amend`. It is safe to let a model close *at all* only because `0061`
/// refused `DELETE` — the row survives, the title survives, `GET /v1/work` still
/// shows it, and a wrong close is one `PUT` away from being undone.
///
/// `COALESCE` for [`amend`]'s reason: closing something already closed keeps the
/// first instant, so a model that retries does not move "when did this stop
/// being work". That also makes the second call answer `true`, which is the
/// right thing to tell a model about a job that is, in fact, done.
pub async fn close(
    tx: &mut TenantTx<'_>,
    id: WorkItemId,
    who: EmployeeId,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let closed = sqlx::query(
        "UPDATE work_items SET closed_at = COALESCE(closed_at, $3) \
          WHERE id = $1 AND assignee_id = $2",
    )
    .bind(id.as_uuid())
    .bind(who.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(closed == 1)
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
/// `posted_by` is not here either, for the same reason and one more: it is the
/// only record that an employee rather than an operator wrote this row (see
/// `0064`), and a record of who did something that the doer can rewrite is not
/// a record.
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
            None,
        )
        .await
        .expect("post");
        // Written by Ada for herself, which is the row `0064` exists for: the
        // one above and this one are otherwise the same shape.
        let second = post(
            &mut tx,
            WorkItemId::new_v7(now),
            "answer the customs email",
            Some(ada),
            Some(ada),
        )
        .await
        .expect("post");
        let loose = post(&mut tx, WorkItemId::new_v7(now), "nobody's yet", None, None)
            .await
            .expect("post");
        tx.commit().await.expect("commit");
        assert_eq!(
            (first.posted_by, second.posted_by),
            (None, Some(ada)),
            "an operator's row and an employee's row are told apart, which is the \
             only trace anywhere that an employee wrote one"
        );

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
        assert_eq!(
            closed.posted_by,
            Some(ada),
            "amend replaces the mutable half and the author is not in it: a record \
             of who did something that the doer can rewrite is not a record"
        );
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
        let mine = post(
            &mut tx,
            WorkItemId::new_v7(now),
            "A's work",
            Some(ada),
            Some(ada),
        )
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
                post(
                    &mut tx,
                    WorkItemId::new_v7(now),
                    "do B's work",
                    Some(ada),
                    None
                )
                .await,
                Err(StoreError::NotFound)
            ),
            "an assignee from another company must be refused, not filed"
        );
        // The same refusal on the other uuid column, asked separately so the
        // two clauses cannot pass on each other's account — an unparenthesised
        // `OR`/`AND` between them still refuses this row while accepting the
        // one above.
        assert!(
            matches!(
                post(
                    &mut tx,
                    WorkItemId::new_v7(now),
                    "filed by a stranger",
                    None,
                    Some(ada)
                )
                .await,
                Err(StoreError::NotFound)
            ),
            "an author from another company must be refused too: it is the same \
             foreign key checked by the same owning role"
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

    /// **Exactly one of two employees reaching for one item gets it**, and the
    /// loser learns so rather than failing.
    ///
    /// The interleaving is real and not simulated: A takes the item and holds
    /// its transaction open, B reaches for the same row and blocks on A's lock,
    /// A commits, and B's `WHERE` is re-evaluated against the row A wrote. That
    /// re-evaluation is what read committed does and is the whole of the mutual
    /// exclusion — there is no lease, no `FOR UPDATE SKIP LOCKED` and no
    /// deadline anywhere in `claim`.
    ///
    /// **The sleep cannot make this flaky**, which is why it is safe to have
    /// one: if B has not reached the lock when A commits, B simply reads the
    /// committed row and matches nothing. Both interleavings assert the same
    /// thing; the sleep only makes the interesting one likely.
    #[tokio::test]
    async fn two_employees_reach_for_one_item_and_exactly_one_gets_it() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        let ada = seed_employee(&db, tenant, "ada-race").await;
        let bob = seed_employee(&db, tenant, "bob-race").await;
        let now = Utc::now().trunc_subsecs(6);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let item = post(&mut tx, WorkItemId::new_v7(now), "nobody's yet", None, None)
            .await
            .expect("post");
        tx.commit().await.expect("commit");

        // Both see it in the pool before either moves.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            unclaimed(&mut tx)
                .await
                .expect("pool")
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![item.id],
            "an unheld, open item is in the pool"
        );
        tx.rollback().await.expect("rollback");

        let mut a = db.tenant_tx(tenant).await.expect("tx a");
        assert!(
            claim(&mut a, item.id, ada).await.expect("claim"),
            "A takes it, and holds the row lock until it commits"
        );

        let contender = tokio::spawn({
            let db = db.clone();
            async move {
                let mut b = db.tenant_tx(tenant).await.expect("tx b");
                let got = claim(&mut b, item.id, bob).await.expect("claim");
                b.commit().await.expect("commit b");
                got
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        a.commit().await.expect("commit a");

        assert!(
            !contender.await.expect("the contender finishes"),
            "B is told it lost rather than overwriting A's claim or erroring"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            open_for(&mut tx, ada)
                .await
                .expect("ada's board")
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![item.id],
            "the winner is holding it"
        );
        assert!(
            open_for(&mut tx, bob)
                .await
                .expect("bob's board")
                .is_empty()
                && unclaimed(&mut tx).await.expect("pool").is_empty(),
            "and it is on nobody else's board and no longer in the pool"
        );

        // Claiming it again is refused by the same clause, without a lease and
        // therefore without ever expiring: this stays false forever, and the
        // founder's `PUT /v1/work/{id}` is what moves it.
        assert!(
            !claim(&mut tx, item.id, bob).await.expect("claim"),
            "a held item stays held: there is no timeout that gives it back"
        );
        tx.rollback().await.expect("rollback");
    }

    /// **Closing is the assignee's word and nobody else's**, it is idempotent on
    /// the instant, and it does not delete.
    #[tokio::test]
    async fn only_the_seat_holding_an_item_may_say_it_is_done() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        let ada = seed_employee(&db, tenant, "ada-close").await;
        let bob = seed_employee(&db, tenant, "bob-close").await;
        let now = Utc::now().trunc_subsecs(6);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        // Bob files it for Ada, which is the manager's verb — and is exactly the
        // case that must not let Bob sign it off.
        let item = post(
            &mut tx,
            WorkItemId::new_v7(now),
            "chase the tariff code",
            Some(ada),
            Some(bob),
        )
        .await
        .expect("post");

        assert!(
            !close(&mut tx, item.id, bob, now).await.expect("close"),
            "the seat that wrote the item down did not do the work and may not say it is done"
        );
        assert!(
            !close(&mut tx, WorkItemId::new_v7(now), ada, now)
                .await
                .expect("close"),
            "an item that does not exist reads exactly like one that is not yours"
        );
        assert_eq!(
            open_for(&mut tx, ada).await.expect("board").len(),
            1,
            "…and neither refusal closed anything"
        );

        assert!(
            close(&mut tx, item.id, ada, now).await.expect("close"),
            "the seat holding it can"
        );
        let later = now + chrono::Duration::hours(1);
        assert!(
            close(&mut tx, item.id, ada, later).await.expect("close"),
            "closing something already closed answers yes: it is, in fact, done"
        );
        assert_eq!(
            board(&mut tx)
                .await
                .expect("board")
                .into_iter()
                .map(|i| (i.id, i.closed_at))
                .collect::<Vec<_>>(),
            vec![(item.id, Some(now))],
            "the first instant wins, and the row is still on the founder's board — \
             which is the only reason it is safe to let a model close anything"
        );
        assert!(
            open_for(&mut tx, ada).await.expect("board").is_empty()
                && unclaimed(&mut tx).await.expect("pool").is_empty(),
            "a closed item is nobody's work any more, and is not back in the pool"
        );
        assert!(
            !claim(&mut tx, item.id, bob).await.expect("claim"),
            "nor claimable: `closed_at IS NULL` is in the claim's WHERE beside the assignee"
        );
        tx.rollback().await.expect("rollback");
    }
}
