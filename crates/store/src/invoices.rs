//! `invoices`: the register of what the company is owed, in SQL and with no
//! opinion about it.
//!
//! `migrations/0066_invoices.sql` carries the argument for why an invoice is an
//! `ActionKind`, why it may only bill a deal somebody won, why it is immutable
//! once issued and why a settlement is declared by an operator. This module is
//! the three statements underneath it: issue one, read the register, and record
//! that the money arrived.
//!
//! # Why the tenant is never a parameter
//!
//! Every function here takes a [`TenantTx`] and nothing else, for
//! [`crate::backlog`]'s reason: the tenant is the one `SET LOCAL app.tenant_id`
//! on that transaction, and a `tenant_id` argument beside it would be a second
//! answer to a question that already has one.
//!
//! # The `WHERE` in [`issue`] is the ceiling, and it is not what the foreign key
//! does
//!
//! `invoices_opportunity_fk` is checked by Postgres as the table's *owner*,
//! which walks past row-level security, and it says only that the deal exists
//! inside this tenant. It has nothing to say about the deal's **stage**, and the
//! stage is the whole bound: `AND o.stage = 'closed_won'` is what makes
//! "invoice a stranger" unrepresentable rather than merely discouraged, because
//! `opportunities_won_needs_approval` (0011) refuses that stage without an
//! `approval_id`. So every row this function can write sits behind a human who
//! approved the commercial terms it bills.
//!
//! It is one conjunct and it is load-bearing. `an_invoice_cannot_be_issued_
//! against_a_deal_nobody_won` is the test, and it asserts the refusal rather
//! than the acceptance — a `WHERE` that has stopped filtering still returns rows
//! for the happy case.
//!
//! # Why [`declare_paid`] is an `UPDATE` with two conditions and no read first
//!
//! `WHERE id = $1 AND paid_at IS NULL`, and the count of affected rows is the
//! answer. Reading the row and then writing it would leave a window for two
//! operators clicking at once to both believe they were the one who settled it;
//! one statement cannot. The `paid_at IS NULL` conjunct is the app's half of
//! irreversibility — the database's half is the `invoices_are_issued_once`
//! trigger, which refuses the same write even from a psql prompt, and neither is
//! redundant: the trigger raises where this returns `false`, and a caller that
//! wants to say "somebody already recorded that" needs the `false`.

use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::PgRow;

use agentos_domain::ids::{EmployeeId, InvoiceId};
use agentos_domain::money::{Currency, Money};

use crate::db::{StoreError, TenantTx};

/// One row of `invoices`.
///
/// `memo` is a plain `String` here and is wrapped by its reader if it has one,
/// not here: this crate speaks SQL and the trust boundary is a decision about a
/// *reader*, taken where the reader is. Same split
/// [`crate::backlog::Item::title`] makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// The invoice.
    pub id: InvoiceId,
    /// The won deal it bills.
    pub opportunity_id: uuid::Uuid,
    /// The seat that issued it.
    pub issued_by: EmployeeId,
    /// What is owed. One value rather than a pair, because a figure without its
    /// currency is not an amount — see [`row_of`], which refuses rather than
    /// guesses.
    pub amount: Money,
    /// What it is for, in one line.
    pub memo: String,
    pub issued_at: DateTime<Utc>,
    /// When somebody declared the money had arrived. `None` is outstanding.
    pub paid_at: Option<DateTime<Utc>>,
}

/// The columns, in one spelling, so the statements below cannot disagree about
/// what a row is.
///
/// Interpolated, so every statement here goes through `sqlx::AssertSqlSafe`.
/// **The audit that asks for is this sentence**, and it is [`crate::backlog`]'s:
/// both halves are compile-time constants of this module, nothing a caller
/// passes reaches the string — every value is a bind parameter — so there is no
/// input for an injection to arrive on.
const COLUMNS: &str =
    "id, opportunity_id, issued_by, currency, amount_minor, memo, issued_at, paid_at";

/// One row, decoded.
///
/// **Fails rather than defaults on a currency it does not know.** The table's
/// `invoices_currency_iso` CHECK admits any three capitals, and `Currency` is a
/// closed enum; a row written by a psql prompt in a currency this build has
/// never heard of is a figure nobody can read back, and answering it with a
/// guess would be reporting a number in the wrong money. `StoreError::Conflict`
/// rather than `Database`, because the row and this build disagree — nothing is
/// broken and nothing will fix itself on a retry.
fn row_of(row: &PgRow) -> Result<Invoice, StoreError> {
    let code: String = row.get("currency");
    let currency: Currency = code.parse().map_err(|_| {
        StoreError::conflict(format!("invoice currency {code:?} is not one of ours"))
    })?;
    let minor: i64 = row.get("amount_minor");
    let minor = u64::try_from(minor)
        .map_err(|_| StoreError::conflict("invoice amount is negative".to_owned()))?;
    let amount = Money::new(minor, currency)
        .map_err(|err| StoreError::conflict(format!("invoice amount is not money: {err}")))?;

    Ok(Invoice {
        id: InvoiceId::from_uuid(row.get("id")),
        opportunity_id: row.get("opportunity_id"),
        issued_by: EmployeeId::from_uuid(row.get("issued_by")),
        amount,
        memo: row.get("memo"),
        issued_at: row.get("issued_at"),
        paid_at: row.get("paid_at"),
    })
}

/// Issue one invoice against a deal this company won.
///
/// The id is the caller's, not this function's: nothing in this crate reads the
/// clock (see [`agentos_domain::ids`]), and a caller that already holds the id
/// can write it into an audit row in the same transaction.
///
/// [`StoreError::NotFound`] when the opportunity is not this company's or is not
/// `closed_won` — deliberately the same silence for both, because
/// distinguishing them would make this an existence oracle for another company's
/// deal ids. See the module docs for why that conjunct is the ceiling.
pub async fn issue(
    tx: &mut TenantTx<'_>,
    id: InvoiceId,
    opportunity_id: uuid::Uuid,
    issued_by: EmployeeId,
    amount: Money,
    memo: &str,
) -> Result<Invoice, StoreError> {
    let minor = i64::try_from(amount.minor())
        .map_err(|_| StoreError::conflict("invoice amount does not fit a bigint".to_owned()))?;

    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO invoices \
             (id, tenant_id, opportunity_id, issued_by, currency, amount_minor, memo) \
         SELECT $1, $2, $3, $4, $5, $6, $7 \
          WHERE EXISTS ( \
                SELECT 1 FROM opportunities o \
                 WHERE o.id = $3 AND o.stage = 'closed_won' \
          ) \
         RETURNING {COLUMNS}"
    )))
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(opportunity_id)
    .bind(issued_by.as_uuid())
    .bind(amount.currency().code())
    .bind(minor)
    .bind(memo)
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;

    row_of(&row)
}

/// Record that the money arrived.
///
/// `true` when this call is the one that settled it; `false` when the invoice
/// does not exist, is another company's, or was already settled. Those three are
/// one answer on purpose — the first two are RLS's usual silence and the third
/// is not an error, it is somebody being second.
///
/// See the module docs: one statement, no read first, and the trigger underneath
/// refuses the same write from anywhere this function is not.
pub async fn declare_paid(
    tx: &mut TenantTx<'_>,
    id: InvoiceId,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let settled = sqlx::query("UPDATE invoices SET paid_at = $2 WHERE id = $1 AND paid_at IS NULL")
        .bind(id.as_uuid())
        .bind(now)
        .execute(&mut ***tx)
        .await?
        .rows_affected();
    Ok(settled == 1)
}

/// The register: every invoice this company has issued, oldest first.
///
/// Settled ones included, for `crate::backlog`'s and `crate::calendar::diary`'s
/// reason: what somebody wants at the end of a month is what is outstanding
/// *and* what came in, and a list that hid the second half would make the first
/// look like nothing had happened.
///
/// ponytail: no pagination, no window, and no `outstanding()` beside it. A
/// register is a thing a human reads; add the filter the day one has enough rows
/// for the scan to show up in a plan — `invoices_outstanding_idx` is already
/// there for it.
pub async fn register(tx: &mut TenantTx<'_>) -> Result<Vec<Invoice>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM invoices ORDER BY issued_at ASC, id ASC"
    )))
    .fetch_all(&mut ***tx)
    .await?;
    rows.iter().map(row_of).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use agentos_domain::ids::TenantId;
    use uuid::Uuid;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the invoice register needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant, an employee, an account and one opportunity at `stage`.
    ///
    /// The opportunity is inserted directly rather than through
    /// `crate::revenue`, because what these tests are about is the stage
    /// conjunct in [`issue`] and a helper that could only produce won deals
    /// would make the refusal untestable.
    async fn seed(db: &Db, stage: &str) -> (TenantId, EmployeeId, Uuid) {
        let tenant = TenantId::new_v7(Utc::now());
        let employee = EmployeeId::new_v7(Utc::now());
        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, 'Acme', $2)")
            .bind(tenant.as_uuid())
            .bind(format!("acme-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'Lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Buyer plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("buyer-{}.example", account.simple()))
        .execute(&mut *tx)
        .await
        .expect("account");
        // `closed_won` needs a closing date and an approval; `qualified` needs
        // neither. Both columns are set unconditionally so the two fixtures
        // differ in exactly one value — the stage — which is what these tests
        // are about.
        sqlx::query(
            "INSERT INTO opportunities \
                 (id, tenant_id, account_id, stage, currency, value_minor, approval_id, closed_at) \
             VALUES ($1, $2, $3, $4, 'EUR', 120000, $5, now())",
        )
        .bind(opportunity)
        .bind(tenant.as_uuid())
        .bind(account)
        .bind(stage)
        .bind(Uuid::now_v7())
        .execute(&mut *tx)
        .await
        .expect("opportunity");
        tx.commit().await.expect("commit the fixture");

        (tenant, employee, opportunity)
    }

    fn eur(minor: u64) -> Money {
        Money::new(minor, Currency::Eur).expect("nonzero")
    }

    /// The happy path, and the two facts a register has to keep: the amount
    /// comes back in the currency it went in, and a fresh invoice is
    /// outstanding.
    #[tokio::test]
    async fn a_won_deal_can_be_invoiced_and_comes_back_outstanding() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let id = InvoiceId::new_v7(Utc::now());
        let issued = issue(&mut tx, id, opportunity, employee, eur(120_000), "March")
            .await
            .expect("issue against a won deal");
        tx.commit().await.expect("commit");

        assert_eq!(issued.amount, eur(120_000));
        assert_eq!(issued.amount.currency(), Currency::Eur);
        assert_eq!(issued.issued_by, employee);
        assert_eq!(issued.paid_at, None, "a fresh invoice is outstanding");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let register = register(&mut tx).await.expect("read the register");
        tx.rollback().await.expect("rollback");
        assert_eq!(register, vec![issued]);
    }

    /// **The ceiling.** The stage conjunct in [`issue`] is what stops an
    /// employee billing a party the company never sold anything to, so the
    /// assertion is on the refusal — a `WHERE` that has stopped filtering still
    /// returns a row for the test above.
    #[tokio::test]
    async fn an_invoice_cannot_be_issued_against_a_deal_nobody_won() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "negotiation").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let refused = issue(
            &mut tx,
            InvoiceId::new_v7(Utc::now()),
            opportunity,
            employee,
            eur(120_000),
            "March",
        )
        .await;
        tx.rollback().await.expect("rollback");

        assert!(
            matches!(refused, Err(StoreError::NotFound)),
            "a deal that is not closed_won must not be invoiceable, got {refused:?}"
        );
    }

    /// A settlement is declared once and never withdrawn, and the second
    /// declarer is told it was not them.
    #[tokio::test]
    async fn a_settlement_is_declared_once() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        issue(&mut tx, id, opportunity, employee, eur(120_000), "March")
            .await
            .expect("issue");
        tx.commit().await.expect("commit");

        let now = Utc::now();
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            declare_paid(&mut tx, id, now).await.expect("declare"),
            "the first declaration settles it"
        );
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            !declare_paid(&mut tx, id, now + chrono::TimeDelta::days(1))
                .await
                .expect("declare again"),
            "a settlement is not re-dated"
        );
        let register = register(&mut tx).await.expect("read");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            register[0].paid_at.map(|at| at.timestamp_micros()),
            Some(now.timestamp_micros()),
            "the first instant is the one that stands"
        );
    }

    /// **The immutability, asserted from the catalogue rather than from
    /// behaviour.**
    ///
    /// `app_role` may write `paid_at` and no other column. A behavioural test
    /// would need a connection as `app_role`, which no fixture here opens — and
    /// the privilege is the mechanism, so reading it is reading the thing
    /// itself. `0011`'s grants are checked the same way nowhere, which is why
    /// this is worth the eight lines.
    #[tokio::test]
    async fn an_issued_invoice_cannot_be_rewritten() {
        let Some(db) = db().await else { return };
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let writable: Vec<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.column_privileges \
              WHERE table_name = 'invoices' AND grantee = 'app_role' \
                AND privilege_type = 'UPDATE' \
              ORDER BY column_name",
        )
        .fetch_all(&mut *tx)
        .await
        .expect("read the column privileges");
        let table_wide: Vec<String> = sqlx::query_scalar(
            "SELECT privilege_type::text FROM information_schema.table_privileges \
              WHERE table_name = 'invoices' AND grantee = 'app_role' \
              ORDER BY privilege_type",
        )
        .fetch_all(&mut *tx)
        .await
        .expect("read the table privileges");
        tx.rollback().await.expect("rollback");

        assert_eq!(
            writable,
            vec!["paid_at".to_owned()],
            "an issued invoice has exactly one writable column"
        );
        assert_eq!(
            table_wide,
            vec!["INSERT".to_owned(), "SELECT".to_owned()],
            "no table-wide UPDATE and no DELETE on the register"
        );
    }

    /// The braces the grant cannot supply: a settlement is not withdrawn even by
    /// the owner, which is the role every migration and every cross-tenant loop
    /// connects as.
    #[tokio::test]
    async fn the_owner_cannot_withdraw_a_settlement_either() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        issue(&mut tx, id, opportunity, employee, eur(120_000), "March")
            .await
            .expect("issue");
        declare_paid(&mut tx, id, Utc::now()).await.expect("settle");
        tx.commit().await.expect("commit");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let undone = sqlx::query("UPDATE invoices SET paid_at = NULL WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await;
        assert!(
            undone.is_err(),
            "the owner must not be able to return a settled invoice to the unpaid list"
        );
        let _ = tx.rollback().await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let rewritten = sqlx::query("UPDATE invoices SET amount_minor = 1 WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await;
        assert!(
            rewritten.is_err(),
            "the owner must not be able to rewrite an issued amount"
        );
        let _ = tx.rollback().await;
    }
}
