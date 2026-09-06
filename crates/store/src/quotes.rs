//! The quote register: what was offered, at which version, and what they said.
//!
//! `migrations/0090_un_devis_est_un_document_revisable.sql` argues the tables
//! and this is the SQL. [`agentos_app::quote_document`] renders the PDF and
//! `apps/server/src/routes/quotes.rs` is the only surface that reads either.
//!
//! # This is not [`crate::sourcing`]'s `quotes`, and the name is the whole
//! confusion worth clearing up once
//!
//! `0007_sourcing.sql` has a table called `quotes`: an offer a **supplier**
//! makes us against a request for prices. This module is the other direction —
//! the offer **we** make a prospect — and its table is `sales_quotes` for
//! exactly that reason. Two documents pointing opposite ways do not share a
//! table, a policy or a reader.
//!
//! # Three things it does that [`crate::invoices`] does not
//!
//! Written on the invoice register's model, and different in three places, each
//! of which is a function below rather than a comment:
//!
//! * **It expires.** [`accept`] refuses a quote whose `valid_until` has passed,
//!   in the same statement that writes the answer, so there is no window
//!   between reading the validity and acting on it. There is no `expired`
//!   column and no sweep — see the migration for why a stored state would be
//!   wrong exactly when it matters.
//! * **It has no number.** A quote is not a piece of accounting, so nothing
//!   here claims a counter, nothing serialises per company, and the pair a
//!   human cites is `(id, version)`.
//! * **It is revised.** [`revise`] writes a **new row** pointing at the old one
//!   through `supersedes_quote_id`; nothing overwrites what went out. The chain
//!   is linear because `sales_quotes_one_revision_per_quote_idx` refuses a
//!   second revision of the same version, and [`live`] is the anti-join that
//!   reads the end of it.
//!
//! # Why [`Line`] is `crate::invoices`'s and not a second struct
//!
//! Because it is the same line. `sales_quote_lines` has the columns of
//! `invoice_lines`, in the same order, with the same meaning — and the point of
//! that is arithmetic: the total of an accepted quote is *the same computation*
//! as the total of the invoice that bills it, so
//! `agentos_app::invoice_document::ventilate` is called once and by both. A
//! `QuoteLine` struct identical to `Line` would be a second type whose only
//! function is to be converted into the first, and the day the two drifted
//! apart would be the day a customer got an invoice a centime off the quote
//! they signed.

use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::PgRow;

use agentos_domain::ids::EmployeeId;
use agentos_domain::money::{Currency, Money};
use agentos_domain::revenue::QuoteId;

use crate::db::{StoreError, TenantTx};
use crate::invoices::Line;

/// One row of `sales_quotes`, with its lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub id: QuoteId,
    /// The deal it prices. Not required to be won — that is the whole point:
    /// a quote comes *before* the close.
    pub opportunity_id: uuid::Uuid,
    /// The seat that proposed it.
    pub issued_by: EmployeeId,
    /// The total offered. The lines, when there are any, sum to it.
    pub amount: Money,
    /// What is being offered, in one line.
    pub memo: String,
    /// 1 for an original, +1 per revision.
    pub version: i32,
    /// The quote this one replaces. `Some` *is* what makes this row a revision.
    pub supersedes_quote_id: Option<QuoteId>,
    pub issued_at: DateTime<Utc>,
    /// **How long the offer stands.** The one mention an invoice does not have,
    /// and the guard [`accept`] reads.
    pub valid_until: DateTime<Utc>,
    /// When an operator recorded that the prospect said yes.
    pub accepted_at: Option<DateTime<Utc>>,
    /// When an operator recorded that they said no.
    pub declined_at: Option<DateTime<Utc>>,
    /// What the document is made of, in the document's order.
    pub lines: Vec<Line>,
}

impl Quote {
    /// Has the offer run out at `now`?
    ///
    /// A method and not a column: see the migration. Nothing branches on this
    /// except a reader deciding what to show — [`accept`]'s refusal is in SQL,
    /// where no snapshot can go stale between the read and the write.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.valid_until <= now
    }

    /// Has anybody answered it?
    pub const fn is_answered(&self) -> bool {
        self.accepted_at.is_some() || self.declined_at.is_some()
    }
}

/// Everything one proposal needs, in one value. [`crate::invoices::Draft`]'s
/// shape and its argument.
#[derive(Debug, Clone)]
pub struct Draft<'a> {
    /// The caller's, so it can be written into an audit row in the same
    /// transaction. Nothing in this crate reads the clock.
    pub id: QuoteId,
    /// The deal being priced.
    pub opportunity_id: uuid::Uuid,
    /// The seat proposing.
    pub issued_by: EmployeeId,
    /// The total offered.
    pub amount: Money,
    /// What it is for, in one line.
    pub memo: &'a str,
    /// **When the offer runs out.** No default and no term invented here: how
    /// long a company stands behind a price is a commercial decision, and the
    /// nearest thing to a default — thirty days — is a convention of one
    /// country's habit rather than a fact about software. `0090`'s
    /// `sales_quotes_validity_is_a_future` refuses one already in the past.
    pub valid_until: DateTime<Utc>,
    /// What the document is made of. Empty is allowed and means the `memo` is
    /// the whole description, exactly as on an invoice.
    pub lines: &'a [Line],
}

/// The columns, in one spelling, so the statements below cannot disagree about
/// what a row is.
///
/// Interpolated, so every statement here goes through `sqlx::AssertSqlSafe`.
/// The audit that asks for is [`crate::invoices`]': both halves are
/// compile-time constants of this module, nothing a caller passes reaches the
/// string — every value is a bind parameter — so there is no input for an
/// injection to arrive on.
const COLUMNS: &str = "id, opportunity_id, issued_by, currency, amount_minor, memo, version, \
                       supersedes_quote_id, issued_at, valid_until, accepted_at, declined_at";

/// One row, decoded.
///
/// Fails rather than defaults on a currency it does not know, for
/// [`crate::invoices`]' reason: a figure in a money this build cannot name is
/// not a figure anybody can read back.
fn row_of(row: &PgRow, lines: Vec<Line>) -> Result<Quote, StoreError> {
    let code: String = row.get("currency");
    let currency: Currency = code
        .parse()
        .map_err(|_| StoreError::conflict(format!("quote currency {code:?} is not one of ours")))?;
    let minor: i64 = row.get("amount_minor");
    let minor = u64::try_from(minor)
        .map_err(|_| StoreError::conflict("quote amount is negative".to_owned()))?;
    let amount = Money::new(minor, currency)
        .map_err(|err| StoreError::conflict(format!("quote amount is not money: {err}")))?;
    let supersedes: Option<uuid::Uuid> = row.get("supersedes_quote_id");

    Ok(Quote {
        id: QuoteId::from_uuid(row.get("id")),
        opportunity_id: row.get("opportunity_id"),
        issued_by: EmployeeId::from_uuid(row.get("issued_by")),
        amount,
        memo: row.get("memo"),
        version: row.get("version"),
        supersedes_quote_id: supersedes.map(QuoteId::from_uuid),
        issued_at: row.get("issued_at"),
        valid_until: row.get("valid_until"),
        accepted_at: row.get("accepted_at"),
        declined_at: row.get("declined_at"),
        lines,
    })
}

fn line_of(row: &PgRow) -> Line {
    Line {
        description: row.get("description"),
        amount_minor: row.get("amount_minor"),
        tax_rate_bp: row.get("tax_rate_bp"),
    }
}

/// The arithmetic both write paths share: the lines must sum to the head.
///
/// `0090`'s deferred constraint trigger refuses the same thing at COMMIT, and
/// the two are not redundant — the trigger's error belongs to the transaction,
/// this one belongs to the caller who got the arithmetic wrong, and it names
/// both figures. [`crate::invoices::issue`] makes the identical pair.
fn lines_total(amount: Money, lines: &[Line]) -> Result<i64, StoreError> {
    let minor = i64::try_from(amount.minor())
        .map_err(|_| StoreError::conflict("quote amount does not fit a bigint".to_owned()))?;
    if !lines.is_empty() {
        let total = lines
            .iter()
            .try_fold(0i64, |acc, line| acc.checked_add(line.amount_minor))
            .ok_or_else(|| StoreError::conflict("the quote lines overflow a bigint".to_owned()))?;
        if total != minor {
            return Err(StoreError::conflict(format!(
                "the lines total {total} but the quote offers {minor}"
            )));
        }
    }
    Ok(minor)
}

/// Put a first version in front of a prospect.
///
/// [`StoreError::NotFound`] when the opportunity is not this company's — RLS's
/// usual silence, and deliberately not an existence oracle for another
/// company's deal ids.
///
/// **No stage conjunct**, and that is the difference from
/// [`crate::invoices::issue`], which demands `closed_won`. A quote is what
/// happens *before* a deal is won; requiring a stage here would make the
/// document unwritable at the only moment it is useful.
pub async fn propose(tx: &mut TenantTx<'_>, draft: Draft<'_>) -> Result<Quote, StoreError> {
    let minor = lines_total(draft.amount, draft.lines)?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO sales_quotes \
             (tenant_id, id, opportunity_id, issued_by, currency, amount_minor, memo, \
              version, valid_until) \
         SELECT $1, $2, $3, $4, $5, $6, $7, 1, $8 \
           FROM opportunities o WHERE o.id = $3 \
         RETURNING {COLUMNS}"
    )))
    .bind(tx.tenant_id().as_uuid())
    .bind(draft.id.as_uuid())
    .bind(draft.opportunity_id)
    .bind(draft.issued_by.as_uuid())
    .bind(draft.amount.currency().code())
    .bind(minor)
    .bind(draft.memo)
    .bind(draft.valid_until)
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;

    write_lines(tx, draft.id, draft.lines).await?;
    row_of(&row, draft.lines.to_vec())
}

/// Re-price: a new document that says which one it replaces.
///
/// # Nothing about the old row moves, and that is the point
///
/// The version being replaced keeps its amount, its lines, its validity and its
/// answer if it had one. What supersedes it is a **link from the new row**, so
/// "what did we offer them in March" has an answer in September. `0090`'s
/// `sales_quotes_are_revised_never_edited` is the trigger that makes that
/// structural rather than a habit of this function.
///
/// `version` is read from the superseded row and incremented in the same
/// statement, so two revisions racing cannot both claim the same number — and
/// the unique index refuses the second of them outright, which is the stronger
/// of the two guards.
///
/// [`StoreError::NotFound`] when the quote is not this company's or does not
/// exist. [`StoreError::Conflict`] when it has already been revised: one live
/// document per chain, `sales_quotes_one_revision_per_quote_idx`.
///
/// **A refused quote may be revised, and so may a live one.** An accepted one
/// may not — re-pricing what somebody agreed to is a new negotiation, not a
/// correction, and the guard below is where that is said.
pub async fn revise(
    tx: &mut TenantTx<'_>,
    supersedes: QuoteId,
    draft: Draft<'_>,
) -> Result<Quote, StoreError> {
    let minor = lines_total(draft.amount, draft.lines)?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO sales_quotes \
             (tenant_id, id, opportunity_id, issued_by, currency, amount_minor, memo, \
              version, supersedes_quote_id, valid_until) \
         SELECT $1, $2, prev.opportunity_id, $4, $5, $6, $7, prev.version + 1, prev.id, $8 \
           FROM sales_quotes prev \
          WHERE prev.id = $3 AND prev.accepted_at IS NULL \
         RETURNING {COLUMNS}"
    )))
    .bind(tx.tenant_id().as_uuid())
    .bind(draft.id.as_uuid())
    .bind(supersedes.as_uuid())
    .bind(draft.issued_by.as_uuid())
    .bind(draft.amount.currency().code())
    .bind(minor)
    .bind(draft.memo)
    .bind(draft.valid_until)
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;

    write_lines(tx, draft.id, draft.lines).await?;
    row_of(&row, draft.lines.to_vec())
}

/// The lines, in the order the caller gave them, which is the document's.
///
/// One statement per line rather than an unnest, [`crate::invoices`]' reason:
/// a handful of lines already inside the caller's transaction, and readable
/// SQL. `position` is the index, so two lines cannot claim the same place.
async fn write_lines(tx: &mut TenantTx<'_>, id: QuoteId, lines: &[Line]) -> Result<(), StoreError> {
    for (index, line) in lines.iter().enumerate() {
        let position = i32::try_from(index + 1)
            .map_err(|_| StoreError::conflict("that is not a quote, it is a book".to_owned()))?;
        sqlx::query(
            "INSERT INTO sales_quote_lines \
                 (tenant_id, quote_id, position, description, amount_minor, tax_rate_bp) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tx.tenant_id().as_uuid())
        .bind(id.as_uuid())
        .bind(position)
        .bind(&line.description)
        .bind(line.amount_minor)
        .bind(line.tax_rate_bp)
        .execute(&mut ***tx)
        .await?;
    }
    Ok(())
}

/// They said yes, at `now`.
///
/// `true` when this call is the one that recorded it; `false` for every reason
/// it could not be. **The four refusals are one answer on purpose**, and only
/// one of them is unusual:
///
/// * the quote is not this company's, or does not exist — RLS's usual silence;
/// * it was already answered, either way — somebody being second, which is not
///   an error;
/// * **it has expired** — `valid_until <= now`, compared in the statement that
///   writes, so nothing can lapse between the check and the write;
/// * it has been superseded — accepting v1 after v2 went out would bind this
///   company to a price it has already withdrawn, and the anti-join is what
///   says so.
///
/// The expiry is the one worth spelling out, because it is the reason this is
/// not an `UPDATE ... WHERE id = $1`. A quote that lapsed at noon and is
/// accepted at one o'clock is not a formality: it is an offer the company is no
/// longer making, and the remedy is [`revise`], which produces a document with
/// a new validity that somebody deliberately chose.
pub async fn accept(
    tx: &mut TenantTx<'_>,
    id: QuoteId,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    answer(tx, "accepted_at", id, now).await
}

/// They said no, at `now`. Same four refusals as [`accept`], and for the same
/// reasons — including the expiry: declining an offer that had already lapsed
/// records a refusal of something that was not on the table.
pub async fn decline(
    tx: &mut TenantTx<'_>,
    id: QuoteId,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    answer(tx, "declined_at", id, now).await
}

/// The one statement both answers are.
///
/// `column` is one of two literals named by this module and never by a caller,
/// which is the whole of what `AssertSqlSafe` is being asserted about here —
/// the same sentence [`COLUMNS`] carries. Writing it twice instead would be two
/// places for the four refusals to drift apart, and the fourth of them (the
/// anti-join) is exactly the one somebody would forget to copy.
async fn answer(
    tx: &mut TenantTx<'_>,
    column: &'static str,
    id: QuoteId,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let answered = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE sales_quotes SET {column} = $2 \
          WHERE id = $1 \
            AND accepted_at IS NULL AND declined_at IS NULL \
            AND valid_until > $2 \
            AND NOT EXISTS (SELECT 1 FROM sales_quotes q WHERE q.supersedes_quote_id = $1)"
    )))
    .bind(id.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(answered == 1)
}

/// Every quote on one deal, oldest version first.
///
/// The whole chain, revisions and refusals included, because that is the
/// question somebody opens this on: not "what is the price" — that is [`live`]
/// — but "what have we offered these people, and what did they say". A list
/// that hid the superseded versions would answer the first question twice and
/// the second one not at all.
pub async fn for_opportunity(
    tx: &mut TenantTx<'_>,
    opportunity_id: uuid::Uuid,
) -> Result<Vec<Quote>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sales_quotes WHERE opportunity_id = $1 ORDER BY version, id"
    )))
    .bind(opportunity_id)
    .fetch_all(&mut ***tx)
    .await?;
    with_lines(tx, rows).await
}

/// Every quote this company has written, newest first.
///
/// ponytail: no pagination and no filter. A register is a thing a human reads;
/// add the window the day one has enough rows for the scan to show up in a
/// plan — `sales_quotes_opportunity_idx` is already there for the per-deal cut.
pub async fn register(tx: &mut TenantTx<'_>) -> Result<Vec<Quote>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sales_quotes ORDER BY issued_at DESC, id DESC"
    )))
    .fetch_all(&mut ***tx)
    .await?;
    with_lines(tx, rows).await
}

/// The end of every chain on one deal: the versions nothing supersedes.
///
/// Usually one row. It is a `Vec` and not an `Option` because one deal may
/// carry two independent chains — a quote for the platform and a quote for the
/// migration are two offers, not two versions of one — and collapsing them here
/// would silently return whichever the planner reached first.
pub async fn live(
    tx: &mut TenantTx<'_>,
    opportunity_id: uuid::Uuid,
) -> Result<Vec<Quote>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sales_quotes q \
          WHERE q.opportunity_id = $1 \
            AND NOT EXISTS (SELECT 1 FROM sales_quotes n WHERE n.supersedes_quote_id = q.id) \
          ORDER BY q.version, q.id"
    )))
    .bind(opportunity_id)
    .fetch_all(&mut ***tx)
    .await?;
    with_lines(tx, rows).await
}

/// One document by id, with its lines. `None` is RLS's usual silence for "not
/// this company's" as much as for "no such row".
pub async fn find(tx: &mut TenantTx<'_>, id: QuoteId) -> Result<Option<Quote>, StoreError> {
    let Some(row) = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sales_quotes WHERE id = $1"
    )))
    .bind(id.as_uuid())
    .fetch_optional(&mut ***tx)
    .await?
    else {
        return Ok(None);
    };
    let lines = sqlx::query(
        "SELECT description, amount_minor, tax_rate_bp FROM sales_quote_lines \
          WHERE quote_id = $1 ORDER BY position",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut ***tx)
    .await?
    .iter()
    .map(line_of)
    .collect();
    row_of(&row, lines).map(Some)
}

/// Attach the lines to a set of rows, in one extra statement rather than one
/// per row. RLS already scopes the read to the tenant.
async fn with_lines(tx: &mut TenantTx<'_>, rows: Vec<PgRow>) -> Result<Vec<Quote>, StoreError> {
    let mut lines: std::collections::HashMap<uuid::Uuid, Vec<Line>> =
        std::collections::HashMap::new();
    for row in sqlx::query(
        "SELECT quote_id, description, amount_minor, tax_rate_bp \
           FROM sales_quote_lines ORDER BY quote_id, position",
    )
    .fetch_all(&mut ***tx)
    .await?
    .iter()
    {
        lines
            .entry(row.get("quote_id"))
            .or_default()
            .push(line_of(row));
    }

    rows.iter()
        .map(|row| {
            let id: uuid::Uuid = row.get("id");
            row_of(row, lines.remove(&id).unwrap_or_default())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use agentos_domain::ids::{InvoiceId, TenantId};
    use agentos_domain::money::Currency;
    use chrono::TimeDelta;
    use uuid::Uuid;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the quote register needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant, an employee, an account and one opportunity at `stage`.
    ///
    /// Inserted directly rather than through `crate::revenue`, for
    /// `crate::invoices`' reason: what one of these tests is about is the
    /// `closed_won` conjunct on the *invoice* side, and a helper that could
    /// only make won deals would make the quote-before-the-close case
    /// unwritable.
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

    /// Two lines that sum to 120000: a licence and a discount, the shape
    /// `crate::invoices`' own fixture uses so the two documents are comparable.
    fn lines() -> Vec<Line> {
        vec![
            Line {
                description: "Licence".to_owned(),
                amount_minor: 125_000,
                tax_rate_bp: Some(2000),
            },
            Line {
                description: "Remise".to_owned(),
                amount_minor: -5_000,
                tax_rate_bp: Some(2000),
            },
        ]
    }

    fn draft<'a>(
        opportunity: Uuid,
        employee: EmployeeId,
        amount: Money,
        valid_until: DateTime<Utc>,
        lines: &'a [Line],
    ) -> Draft<'a> {
        Draft {
            id: QuoteId::new_v7(Utc::now()),
            opportunity_id: opportunity,
            issued_by: employee,
            amount,
            memo: "Plateforme, année 1",
            valid_until,
            lines,
        }
    }

    /// **An offer that has run out is not an offer.**
    ///
    /// The expiry is compared in the statement that writes, so this test also
    /// says the thing a `SELECT` then an `UPDATE` could not: nothing lapses
    /// between the check and the write, because there is only one.
    ///
    /// And the refusal is not a hint — the row is untouched afterwards, so a
    /// caller that ignored the `false` still has no accepted quote.
    #[tokio::test]
    async fn an_expired_quote_cannot_be_accepted() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "negotiation").await;
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let all = lines();
        let live_quote = propose(
            &mut tx,
            draft(
                opportunity,
                employee,
                eur(120_000),
                now + TimeDelta::days(30),
                &all,
            ),
        )
        .await
        .expect("a quote that is still good");
        let lapsed = propose(
            &mut tx,
            draft(
                opportunity,
                employee,
                eur(90_000),
                // Valid, but only until a second from now: the row is legal at
                // insert (`sales_quotes_validity_is_a_future`) and stale by the
                // time it is answered, which is the state a stored `expired`
                // flag would be wrong about.
                now + TimeDelta::seconds(1),
                &[],
            ),
        )
        .await
        .expect("a quote with a short fuse");

        assert!(!lapsed.is_expired_at(now));
        assert!(lapsed.is_expired_at(now + TimeDelta::seconds(2)));

        // An hour later. The short one is refused; the thirty-day one is not,
        // so the refusal is the validity and not something about this deal.
        let then = now + TimeDelta::hours(1);
        assert!(
            !decline(&mut tx, lapsed.id, then).await.expect("decline"),
            "an offer that has lapsed cannot be refused either"
        );
        assert!(
            !accept(&mut tx, lapsed.id, then).await.expect("accept"),
            "an offer that has lapsed cannot be accepted"
        );
        assert!(
            accept(&mut tx, live_quote.id, then)
                .await
                .expect("accept the live one")
        );

        // And nothing moved on the refused row.
        let reread = find(&mut tx, lapsed.id).await.expect("read").expect("row");
        assert_eq!(reread.accepted_at, None);
        assert_eq!(reread.declined_at, None);
        assert!(!reread.is_answered());

        tx.rollback().await.expect("rollback");
    }

    /// **A revision does not lose the version it replaces.**
    ///
    /// The old row keeps its amount, its lines and its refusal; the new one
    /// carries the link and the next version number. `live` reads the end of
    /// the chain, `for_opportunity` reads the whole of it, and the second
    /// revision of an already-revised quote is refused so the chain cannot
    /// fork.
    #[tokio::test]
    async fn a_revision_keeps_the_version_it_replaces() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "negotiation").await;
        let now = Utc::now();
        let horizon = now + TimeDelta::days(30);

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let all = lines();
        let first = propose(
            &mut tx,
            draft(opportunity, employee, eur(120_000), horizon, &all),
        )
        .await
        .expect("v1");
        assert_eq!(first.version, 1);
        assert_eq!(first.supersedes_quote_id, None);

        // They say no. That is not a loss, and it does not stop a re-price.
        assert!(decline(&mut tx, first.id, now).await.expect("decline"));

        let cheaper = [Line {
            description: "Licence (remisée)".to_owned(),
            amount_minor: 99_000,
            tax_rate_bp: Some(2000),
        }];
        let second = revise(
            &mut tx,
            first.id,
            draft(opportunity, employee, eur(99_000), horizon, &cheaper),
        )
        .await
        .expect("v2");
        assert_eq!(second.version, 2);
        assert_eq!(second.supersedes_quote_id, Some(first.id));
        assert_eq!(second.opportunity_id, first.opportunity_id);

        // The whole point: v1 is still exactly what went out in March.
        let kept = find(&mut tx, first.id).await.expect("read").expect("row");
        assert_eq!(kept.amount, eur(120_000));
        assert_eq!(kept.lines, all);
        assert_eq!(kept.version, 1);
        assert!(kept.declined_at.is_some(), "and it still says they refused");

        // The two reads say different, correct things.
        let chain = for_opportunity(&mut tx, opportunity).await.expect("chain");
        assert_eq!(
            chain.iter().map(|q| q.version).collect::<Vec<_>>(),
            vec![1, 2]
        );
        let ends = live(&mut tx, opportunity).await.expect("live");
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].id, second.id);

        // A quote nobody has answered cannot be revised twice either, and an
        // accepted one cannot be revised at all.
        assert!(accept(&mut tx, second.id, now).await.expect("accept"));
        let after = revise(
            &mut tx,
            second.id,
            draft(opportunity, employee, eur(70_000), horizon, &[]),
        )
        .await;
        assert!(
            matches!(after, Err(StoreError::NotFound)),
            "re-pricing what they agreed to is a new negotiation: {after:?}"
        );

        // **Last, because it poisons the transaction, and that is the point.**
        // Forking v1 a second time is refused by
        // `sales_quotes_one_revision_per_quote_idx` — a unique index, so the
        // loser's statement aborts rather than returning no row, which is
        // exactly the mechanism that makes two concurrent revisers unable to
        // both win. Nothing may run after it but the rollback.
        let forked = revise(
            &mut tx,
            first.id,
            draft(opportunity, employee, eur(80_000), horizon, &[]),
        )
        .await;
        assert!(
            matches!(
                forked,
                Err(StoreError::Conflict(_) | StoreError::Database(_))
            ),
            "a second revision of one version forks the chain: {forked:?}"
        );

        tx.rollback().await.expect("rollback");
    }

    /// **The total of an accepted quote is the total the invoice bills.**
    ///
    /// Not "a number a test copied from one to the other": the same lines are
    /// written to both documents, and the assertion is that the two heads and
    /// the two line sets are equal after a round trip through two different
    /// tables. That is the property `0090` exists for — before it, an invoice's
    /// total was whatever the closing employee typed, and nothing on file said
    /// otherwise.
    #[tokio::test]
    async fn the_invoice_bills_the_total_of_the_accepted_quote() {
        let Some(db) = db().await else { return };
        // `closed_won`, because the invoice half demands it. The quote half
        // does not, which is the difference this fixture cannot show and
        // `an_expired_quote_cannot_be_accepted` does — its deal is in
        // `negotiation` and its quotes are written anyway.
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let all = lines();
        let quote = propose(
            &mut tx,
            draft(
                opportunity,
                employee,
                eur(120_000),
                now + TimeDelta::days(15),
                &all,
            ),
        )
        .await
        .expect("propose");
        assert!(accept(&mut tx, quote.id, now).await.expect("accept"));

        let accepted = find(&mut tx, quote.id).await.expect("read").expect("row");
        assert!(accepted.accepted_at.is_some());

        // The invoice is built **from the accepted row**, not from the caller's
        // memory of it.
        let invoice = crate::invoices::issue(
            &mut tx,
            crate::invoices::Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: accepted.opportunity_id,
                issued_by: accepted.issued_by,
                amount: accepted.amount,
                memo: &accepted.memo,
                due_at: None,
                lines: &accepted.lines,
            },
        )
        .await
        .expect("issue");

        assert_eq!(invoice.amount, accepted.amount);
        assert_eq!(invoice.lines, accepted.lines);
        // And the arithmetic agrees line for line, which is what makes the two
        // documents the same offer rather than two figures that match today.
        let quoted: i64 = accepted.lines.iter().map(|l| l.amount_minor).sum();
        let billed: i64 = invoice.lines.iter().map(|l| l.amount_minor).sum();
        assert_eq!(quoted, billed);
        assert_eq!(
            u64::try_from(billed).expect("positive"),
            invoice.amount.minor()
        );

        tx.rollback().await.expect("rollback");
    }

    /// The lines total the head, refused here with both figures and refused
    /// again by `0090`'s deferred trigger at COMMIT.
    #[tokio::test]
    async fn quote_lines_that_do_not_add_up_are_refused() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "negotiation").await;
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");

        let wrong = [Line {
            description: "Licence".to_owned(),
            amount_minor: 100_000,
            tax_rate_bp: None,
        }];
        let refused = propose(
            &mut tx,
            draft(
                opportunity,
                employee,
                eur(120_000),
                Utc::now() + TimeDelta::days(30),
                &wrong,
            ),
        )
        .await;
        assert!(
            matches!(refused, Err(StoreError::Conflict(ref message))
                if message.contains("100000") && message.contains("120000")),
            "{refused:?}"
        );

        tx.rollback().await.expect("rollback");
    }
}
