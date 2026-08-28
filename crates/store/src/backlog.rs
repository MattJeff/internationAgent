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
/// ponytail: still unbounded here, and the one answer this asked for now exists
/// one layer up. `loops::initiative::MAX_LINES` is the number, it covers this
/// list and [`open_for`] and the diary alike — one answer for all three, as this
/// comment asked — and it lives at the reader rather than in the SQL because the
/// bound is a fact about what a *prompt* may cost, not about what a board holds:
/// at `agentos_eval::scoping::tokens` a line of this list is 16–39 tokens, of
/// which 15 are the bullet and the uuid before the founder has typed a word.
///
/// This function has exactly one reader — `agentos_app::backlog`, on the way to
/// a brief — and no HTTP route calls it. A previous version of this sentence
/// said `GET /v1/work` "reads the same rows onto a screen and must not be cut",
/// and that was an argument for keeping the read whole which the route does not
/// support: `GET /v1/work` calls [`board`], which is `SELECT … FROM work_items`
/// with no `WHERE` at all. Different rows, different function. The reason to
/// keep *this* read whole is the one above it and nothing else.
///
/// Keeping the read whole is also what pays for the notice. A `LIMIT` returns
/// twenty rows and no way to say there are two hundred, and a list that is
/// silently short is the thing being fixed.
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
/// The one automatic return that *is* wanted is [`unassign_all`], and it is a
/// statement rather than a foreign key. `0061` says `on delete set null` puts a
/// terminated employee's work back on the board; it does not, because nothing
/// deletes an employee — see that function and `migrations/0068`.
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

/// Put back on the board everything one seat was holding. Returns how many rows
/// moved.
///
/// # This is the statement `0061` said was a foreign key
///
/// `0061` argues, in as many words, that `on delete set null` on `assignee_id`
/// is what "puts the item back on the board unassigned" when somebody leaves.
/// **The action never fires**, because nothing in this workspace deletes an
/// employee: termination is a column, `UPDATE employees SET lifecycle =
/// 'terminated'`, and `employees` has no DELETE path at all. So the item kept an
/// assignee that would never take another turn — invisible to
/// [`open_for`], which is only ever asked about an employee that is *due*, and
/// invisible to [`unclaimed`], which wants `assignee_id IS NULL`. It read
/// "assigned" on `GET /v1/work` and appeared in no brief ever again. The
/// migration's prose cannot be corrected — it has been applied and sqlx
/// checksums it — so `migrations/0068` is where it is contradicted.
///
/// `closed_at IS NULL`, and it is the whole of the clause that matters.
/// [`close`] can only be reached by the assignee, so a closed item's
/// `assignee_id` is the only record of **who did it**; blanking it would erase
/// that to no purpose, because a finished item is not work waiting for somebody.
///
/// `posted_by` is deliberately not touched. It is a register of who wrote the
/// row down, not a claim on it — `0064` says so and [`amend`] refuses to move it
/// for the same reason. Whoever filed the work still filed it after they left.
///
/// Called by `routes::employees::set_lifecycle` **in the transaction that writes
/// the lifecycle**, so an employee is never terminated in a committed state
/// where it still holds work. Termination only: a suspension is reversible and
/// `POST /v1/employees/{id}/suspend` is documented as pausing a seat "without
/// releasing anything it owns" — taking its board away and handing it out would
/// make the two verbs the same one.
///
/// # Why only this table, when nine columns have the same dead action
///
/// `employees` is referenced with `on delete set null` from `a2a_tasks`, `rfqs`,
/// `negotiations`, `purchase_orders`, `accounts`, `opportunities`,
/// `opportunity_events`, `proof_of_need_attempts` and both of `work_items`' own
/// columns. Every one of those actions is as dead as this one was, and only this
/// one was a defect — because `assignee_id IS NULL` is the sole place in the
/// schema where *nobody holds this* is a state something **reads**, in
/// [`unclaimed`]. Everywhere else the column is provenance or ownership, NULL
/// means "nobody, and nobody will", and blanking it would destroy a record
/// without handing the work to anyone. Redistributing those needs a rule the
/// founder has not written; this needed no rule at all, because 0061 had already
/// written it.
pub async fn unassign_all(tx: &mut TenantTx<'_>, who: EmployeeId) -> Result<u64, StoreError> {
    let moved = sqlx::query(
        "UPDATE work_items SET assignee_id = NULL \
          WHERE assignee_id = $1 AND closed_at IS NULL",
    )
    .bind(who.as_uuid())
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use chrono::SubsecRound;
    use uuid::Uuid;

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

    /// **[`claim`]'s docs say the mutual exclusion is read committed and that
    /// repeatable read would answer `40001` instead. Both halves are asked here
    /// rather than believed.**
    ///
    /// The claim above it is a claim about a *setting*, not about the statement,
    /// and it is the kind that is true when it is written and false later
    /// without a line of this file changing: `default_transaction_isolation` is
    /// a `postgresql.conf` line, a `PGOPTIONS` in a deployment unit, an `ALTER
    /// DATABASE … SET`. So the level is read back from the transaction
    /// [`crate::db::Db::tenant_tx`] actually hands out — `SHOW
    /// transaction_isolation`, on the connection, inside the transaction — and
    /// not deduced from the absence of a `SET` in `tenant_tx`.
    ///
    /// # What the second half is worth knowing
    ///
    /// `tenant_tx` pins no isolation level, and that is not an omission with no
    /// consequence: it means the level is whatever the deployment's default is,
    /// and this statement's *answer to the caller changes with it*. At read
    /// committed the loser is told `false` — "somebody else has it", which is a
    /// sentence a model can act on. Turn the same deployment's default up to
    /// repeatable read and the identical call raises `40001`, which
    /// [`StoreError`] classifies as [`StoreError::Serialization`] and which
    /// ends the turn that made it. Nothing in this crate would report that
    /// change; the second half of this test is what does.
    ///
    /// It is reached by connecting a second [`Db`] to the same database with
    /// `options=-c default_transaction_isolation=repeatable read`, which is
    /// exactly how an operator would do it, rather than by issuing a `SET` the
    /// product never issues. That also proves the first half from the other
    /// side: `tenant_tx` inherits the default, so a doctored default arrives
    /// intact.
    ///
    /// # The interleaving is waited for rather than slept through
    ///
    /// [`the sibling test`](two_employees_reach_for_one_item_and_exactly_one_gets_it)
    /// sleeps 150 ms and says — correctly — that the sleep cannot make it flaky,
    /// because both interleavings assert the same thing. That is true of the
    /// `false` and false of the `40001`: repeatable read only raises it when the
    /// loser's **snapshot predates the winner's commit**, and a contender that
    /// arrived late reads the assigned row and answers `false` like everybody
    /// else. So this one does not sleep — it asks PostgreSQL whether the
    /// contender is blocked yet, through [`crate::db::wait_until_blocked`], and
    /// commits the winner only once it is. A run in which the arrangement did
    /// not happen fails there, saying so, instead of passing quietly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_exclusion_is_read_committed_and_repeatable_read_would_change_the_answer() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        let ada = seed_employee(&db, tenant, "ada-isolation").await;
        let bob = seed_employee(&db, tenant, "bob-isolation").await;
        let now = Utc::now().trunc_subsecs(6);

        // The premise, read from the transaction the product hands out.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let level: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut **tx)
            .await
            .expect("show transaction_isolation");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            level, "read committed",
            "`claim`'s exclusion is read committed re-evaluating the loser's \
             WHERE against the committed row. This deployment is at `{level}`, \
             where the same call answers a model something else entirely — see \
             the second half of this test for what."
        );

        // -- read committed: the loser blocks, then is told it lost -----------
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let item = post(&mut tx, WorkItemId::new_v7(now), "nobody's yet", None, None)
            .await
            .expect("post");
        tx.commit().await.expect("commit");

        let mut a = db.tenant_tx(tenant).await.expect("tx a");
        assert!(
            claim(&mut a, item.id, ada).await.expect("claim"),
            "A takes it, and holds the row lock until it commits"
        );
        let (lost, held_by) = contend(&db, tenant, item.id, bob, a).await;
        assert!(
            matches!(lost, Ok(false)),
            "at read committed the loser is told it lost, and that is a sentence \
             an employee can act on: {lost:?}"
        );
        assert_eq!(held_by, Some(ada), "the winner is still holding it");

        // -- repeatable read: the identical call raises 40001 -----------------
        let strict = repeatable_read_db().await;
        let mut tx = strict.tenant_tx(tenant).await.expect("tx");
        let level: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut **tx)
            .await
            .expect("show transaction_isolation");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            level, "repeatable read",
            "the second half of this test needs a connection that is actually at \
             repeatable read; `tenant_tx` inherits the default and this one did not \
             arrive"
        );

        let mut tx = strict.tenant_tx(tenant).await.expect("tx");
        let second = post(
            &mut tx,
            WorkItemId::new_v7(now),
            "also nobody's",
            None,
            None,
        )
        .await
        .expect("post");
        tx.commit().await.expect("commit");

        let mut a = strict.tenant_tx(tenant).await.expect("tx a");
        assert!(
            claim(&mut a, second.id, ada).await.expect("claim"),
            "A takes the second item too"
        );
        let (lost, held_by) = contend(&strict, tenant, second.id, bob, a).await;
        assert!(
            matches!(lost, Err(StoreError::Serialization)),
            "under repeatable read the same call cannot answer `false` — the row \
             it selected under its own snapshot was updated underneath it, so \
             PostgreSQL raises 40001 and the caller gets a retryable error \
             instead of an answer. `claim`'s docs say so and this is the proof; \
             what came back was {lost:?}"
        );
        assert_eq!(
            held_by,
            Some(ada),
            "…and the item is still A's: the loser changed nothing either way"
        );
    }

    /// Reach for `item` as `who` on a second connection while `winner` still
    /// holds it, wait until that reach is genuinely blocked, then let the winner
    /// commit. Returns what the loser was told, and who ends up holding the row.
    ///
    /// Both halves of the test above need exactly this and differ only in which
    /// [`Db`] they are given, which is the whole point: the statement, the
    /// interleaving and the assertions are identical, and the isolation level is
    /// the only thing that moves.
    async fn contend(
        db: &Db,
        tenant: TenantId,
        item: WorkItemId,
        who: EmployeeId,
        winner: TenantTx<'_>,
    ) -> (Result<bool, StoreError>, Option<EmployeeId>) {
        let (send_pid, pid) = tokio::sync::oneshot::channel();
        let loser = tokio::spawn({
            let db = db.clone();
            async move {
                let mut b = db.tenant_tx(tenant).await.expect("tx b");
                // Read before the statement that blocks: a blocked backend
                // reports nothing until it is unblocked.
                let backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut **b)
                    .await
                    .expect("backend pid");
                send_pid
                    .send(backend)
                    .expect("the test is waiting for this");
                let got = claim(&mut b, item, who).await;
                // A 40001 aborts the transaction, and a COMMIT on an aborted
                // transaction is a rollback wearing the wrong name.
                match &got {
                    Ok(_) => b.commit().await.expect("commit b"),
                    Err(_) => b.rollback().await.expect("rollback b"),
                }
                got
            }
        });

        crate::db::wait_until_blocked(db, pid.await.expect("the contender's pid")).await;
        winner.commit().await.expect("commit the winner");
        let got = loser.await.expect("the contender finishes");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let holder: Option<Uuid> =
            sqlx::query_scalar("SELECT assignee_id FROM work_items WHERE id = $1")
                .bind(item.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("read the assignee back");
        tx.rollback().await.expect("rollback");
        (got, holder.map(EmployeeId::from_uuid))
    }

    /// The same database, on a connection whose **default** isolation level is
    /// `repeatable read` — the shape an operator's `postgresql.conf` or
    /// `PGOPTIONS` has, rather than a `SET` this product never issues.
    ///
    /// Percent-encoded because sqlx decodes the query value before handing it to
    /// the startup packet: this arrives at the server as
    /// `-c default_transaction_isolation=repeatable\ read`, and the backslash is
    /// how libpq's options string escapes a space *inside* a value. Without it
    /// the connection fails with `invalid value for parameter`.
    async fn repeatable_read_db() -> Db {
        let url = std::env::var("DATABASE_URL").expect("`fixture` already checked this");
        let sep = if url.contains('?') { '&' } else { '?' };
        Db::connect(&format!(
            "{url}{sep}options=-c%20default_transaction_isolation%3Drepeatable%5C%20read"
        ))
        .await
        .expect("connect at repeatable read")
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
