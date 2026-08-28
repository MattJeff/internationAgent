//! `invoices`: the register of what the company is owed, in SQL and with no
//! opinion about it.
//!
//! `migrations/0066_invoices.sql` carries the argument for why an invoice is an
//! `ActionKind`, why it may only bill a deal somebody won, why it is immutable
//! once issued and why a settlement is declared by an operator;
//! `migrations/0071_an_invoice_needs_a_number.sql` carries the argument for the
//! four things it takes to be a document somebody may legally issue — a
//! gap-free number, lines that total it, a due date, and a credit note for when
//! it was wrong. This module is the statements underneath both: issue one,
//! withdraw one, read the register, and record that the money arrived.
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
//! # The number, and why it is allocated in the same statement as the row
//!
//! `migrations/0071_an_invoice_needs_a_number.sql` carries the argument for why
//! a Postgres sequence is the wrong primitive (it is exempt from rollback, so a
//! rolled-back issue takes a number with it and leaves a hole). What is left is
//! a counter row bumped by the issuing transaction, and this module's half of
//! that is one decision:
//!
//! **the bump and the insert are one statement**, a CTE whose counter arm is
//! itself guarded by the `closed_won` check. So a refused issue does not touch
//! the counter *at all* — not even for the length of a transaction somebody
//! might commit anyway. Two statements would have made gap-freeness depend on
//! every caller remembering to roll back, and "the next caller will remember"
//! is the assumption `0056_one_open_round_per_employee` was written to delete.
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
//!
//! # The hole this module leaves open: a credit note has no author
//!
//! [`issue`] records the seat that raised the demand in `issued_by`.
//! [`credit`] records nobody: the column is NULL on a credit note by
//! construction — 0071's `invoices_issuer_or_correction` makes the two answers
//! exclusive — and there is no second column naming the operator instead. So
//! the register can say a demand was withdrawn, for how much and why, and
//! cannot say **who** withdrew it.
//!
//! It is a gap in the audit trail and not in the arithmetic: the amount, the
//! reason, the moment and the document corrected are all on the row, and
//! `POST /v1/invoices/{id}/credit` still requires an operator key to reach
//! [`credit`] at all — so *some* operator authorised it, and the separation of
//! duties that route argues for is intact. What is missing is only **which**.
//!
//! And the identity is not unavailable, which is what makes this a hole rather
//! than a constraint: the route has a `Principal` in hand and passes only its
//! `tenant_id` down. Closing it is a column and a parameter, not a redesign.
//! It is named here rather than half-answered with whichever seat happened to
//! be nearby — writing a *seat* into `issued_by` on a credit note would make
//! the row indistinguishable from an invoice, which is exactly what 0071's
//! `invoices_issuer_or_correction` refuses.

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
    /// **The number a human quotes**, gap-free inside this company. Allocated by
    /// the counter row and never by a sequence; see the module docs and 0071.
    pub number: i64,
    /// The won deal it bills.
    pub opportunity_id: uuid::Uuid,
    /// The seat that issued it, and `None` on a credit note: withdrawing a
    /// demand is an operator's act, not an employee's. 0071's
    /// `invoices_issuer_or_correction` makes the two answers exclusive, so this
    /// is `Some` exactly when [`Invoice::corrects_invoice_id`] is `None`.
    pub issued_by: Option<EmployeeId>,
    /// What is owed. One value rather than a pair, because a figure without its
    /// currency is not an amount — see [`row_of`], which refuses rather than
    /// guesses.
    ///
    /// **Positive on a credit note too.** The sign is carried by
    /// [`Invoice::corrects_invoice_id`], not by the figure; see 0071.
    pub amount: Money,
    /// What it is for, in one line — or, on a credit note, why it was issued.
    pub memo: String,
    /// The invoice this one corrects. `Some` *is* what makes this row a credit
    /// note: there is no `kind` column, because a second column that has to
    /// agree with this one is a second place for the truth to be.
    pub corrects_invoice_id: Option<InvoiceId>,
    pub issued_at: DateTime<Utc>,
    /// When payment is due. `None` is "no date was agreed" — this workspace
    /// invents no payment term.
    pub due_at: Option<DateTime<Utc>>,
    /// When somebody declared the money had arrived. `None` is outstanding.
    pub paid_at: Option<DateTime<Utc>>,
    /// What the document is made of, in the document's order. Empty is allowed
    /// and means the `memo` is the whole description.
    pub lines: Vec<Line>,
}

/// One line of a document.
///
/// No currency: a line is denominated in its invoice's, so a line in another
/// one is unrepresentable rather than refused. No position either — the order
/// of this `Vec` *is* the order of the document, and a field beside it would be
/// a second answer to the same question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// What it is for. 1..=200 characters, `invoices_memo_shape`'s bound.
    pub description: String,
    /// Signed minor units, in the invoice's currency: a discount is a negative
    /// line. Zero is refused. The lines must total the head exactly, which
    /// 0071's deferred constraint trigger checks at commit.
    pub amount_minor: i64,
    /// **The founder's question, and the only place it can be asked.** The tax
    /// rate on this line in basis points (2000 is 20%), or `None` when nobody
    /// has said — which is every row this workspace writes today, because a
    /// rate is a fact about a jurisdiction and a company, not about software.
    ///
    /// Nothing here multiplies it by anything: the rounding rule is
    /// jurisdictional too. See 0071's column comment.
    pub tax_rate_bp: Option<i32>,
}

/// Everything one issue needs, in one value.
///
/// A struct rather than eight parameters, and the grouping is the argument for
/// it: these are the fields of one document, and a caller that has to keep
/// `amount` and `lines` in the same order as `memo` and `due_at` is a caller
/// that will one day swap two of them.
#[derive(Debug, Clone)]
pub struct Draft<'a> {
    /// The caller's, not this module's: nothing in this crate reads the clock,
    /// and a caller that already holds the id can write it into an audit row in
    /// the same transaction.
    pub id: InvoiceId,
    /// The won deal this bills.
    pub opportunity_id: uuid::Uuid,
    /// The seat asking to be paid.
    pub issued_by: EmployeeId,
    /// The total demanded. The lines, if there are any, must sum to it.
    pub amount: Money,
    /// What it is for, in one line.
    pub memo: &'a str,
    /// When payment is due, if a term was agreed. **No default**: see 0071.
    pub due_at: Option<DateTime<Utc>>,
    /// What the document is made of. Empty is allowed.
    pub lines: &'a [Line],
}

/// The columns, in one spelling, so the statements below cannot disagree about
/// what a row is.
///
/// Interpolated, so every statement here goes through `sqlx::AssertSqlSafe`.
/// **The audit that asks for is this sentence**, and it is [`crate::backlog`]'s:
/// both halves are compile-time constants of this module, nothing a caller
/// passes reaches the string — every value is a bind parameter — so there is no
/// input for an injection to arrive on.
const COLUMNS: &str = "id, number, opportunity_id, issued_by, currency, amount_minor, memo, \
                       corrects_invoice_id, issued_at, due_at, paid_at";

/// One row, decoded.
///
/// **Fails rather than defaults on a currency it does not know.** The table's
/// `invoices_currency_iso` CHECK admits any three capitals, and `Currency` is a
/// closed enum; a row written by a psql prompt in a currency this build has
/// never heard of is a figure nobody can read back, and answering it with a
/// guess would be reporting a number in the wrong money. `StoreError::Conflict`
/// rather than `Database`, because the row and this build disagree — nothing is
/// broken and nothing will fix itself on a retry.
fn row_of(row: &PgRow, lines: Vec<Line>) -> Result<Invoice, StoreError> {
    let code: String = row.get("currency");
    let currency: Currency = code.parse().map_err(|_| {
        StoreError::conflict(format!("invoice currency {code:?} is not one of ours"))
    })?;
    let minor: i64 = row.get("amount_minor");
    let minor = u64::try_from(minor)
        .map_err(|_| StoreError::conflict("invoice amount is negative".to_owned()))?;
    let amount = Money::new(minor, currency)
        .map_err(|err| StoreError::conflict(format!("invoice amount is not money: {err}")))?;

    let issued_by: Option<uuid::Uuid> = row.get("issued_by");
    let corrects: Option<uuid::Uuid> = row.get("corrects_invoice_id");

    Ok(Invoice {
        id: InvoiceId::from_uuid(row.get("id")),
        number: row.get("number"),
        opportunity_id: row.get("opportunity_id"),
        issued_by: issued_by.map(EmployeeId::from_uuid),
        amount,
        memo: row.get("memo"),
        corrects_invoice_id: corrects.map(InvoiceId::from_uuid),
        issued_at: row.get("issued_at"),
        due_at: row.get("due_at"),
        paid_at: row.get("paid_at"),
        lines,
    })
}

/// The counter arm both write paths share, as one CTE.
///
/// `$1` is the tenant. It is written once here rather than twice below because
/// the two statements must not be able to disagree about how a number is
/// claimed: the whole gap-free property is this expression. The `guard`
/// interpolated into the `WHERE` is the caller's refusal condition — the
/// counter is bumped **only** if the document is going to be written, so a
/// refused issue leaves no hole even in a transaction somebody then commits.
///
/// Interpolated, and the audit that asks for is [`COLUMNS`]': both halves are
/// compile-time constants of this module and no caller's value reaches the
/// string.
fn claim_a_number(guard: &str) -> String {
    format!(
        "INSERT INTO invoice_counters (tenant_id, last_number) \
         SELECT $1, 1 WHERE EXISTS ({guard}) \
             ON CONFLICT (tenant_id) DO UPDATE \
                SET last_number = invoice_counters.last_number + 1 \
          RETURNING last_number"
    )
}

fn line_of(row: &PgRow) -> Line {
    Line {
        description: row.get("description"),
        amount_minor: row.get("amount_minor"),
        tax_rate_bp: row.get("tax_rate_bp"),
    }
}

/// Issue one invoice against a deal this company won.
///
/// [`StoreError::NotFound`] when the opportunity is not this company's or is not
/// `closed_won` — deliberately the same silence for both, because
/// distinguishing them would make this an existence oracle for another company's
/// deal ids. See the module docs for why that conjunct is the ceiling, and why
/// the number is claimed inside the same statement it guards.
///
/// [`StoreError::Conflict`] when the lines do not total the amount. The
/// database refuses that too — 0071's deferred constraint trigger — and the two
/// are not redundant: the trigger fires at COMMIT, where the error belongs to
/// the transaction rather than to the caller who got the arithmetic wrong.
pub async fn issue(tx: &mut TenantTx<'_>, draft: Draft<'_>) -> Result<Invoice, StoreError> {
    let minor = i64::try_from(draft.amount.minor())
        .map_err(|_| StoreError::conflict("invoice amount does not fit a bigint".to_owned()))?;
    if !draft.lines.is_empty() {
        let total = draft
            .lines
            .iter()
            .try_fold(0i64, |acc, line| acc.checked_add(line.amount_minor))
            .ok_or_else(|| {
                StoreError::conflict("the invoice lines overflow a bigint".to_owned())
            })?;
        if total != minor {
            return Err(StoreError::conflict(format!(
                "the lines total {total} but the invoice demands {minor}"
            )));
        }
    }

    let counter =
        claim_a_number("SELECT 1 FROM opportunities o WHERE o.id = $3 AND o.stage = 'closed_won'");
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "WITH claimed AS ({counter}) \
         INSERT INTO invoices \
             (tenant_id, id, opportunity_id, issued_by, number, currency, amount_minor, memo, due_at) \
         SELECT $1, $2, $3, $4, claimed.last_number, $5, $6, $7, $8 FROM claimed \
         RETURNING {COLUMNS}"
    )))
    .bind(tx.tenant_id().as_uuid())
    .bind(draft.id.as_uuid())
    .bind(draft.opportunity_id)
    .bind(draft.issued_by.as_uuid())
    .bind(draft.amount.currency().code())
    .bind(minor)
    .bind(draft.memo)
    .bind(draft.due_at)
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;

    write_lines(tx, draft.id, draft.lines).await?;
    row_of(&row, draft.lines.to_vec())
}

/// The lines, in the order the caller gave them, which is the document's.
///
/// One statement per line rather than an array unnest: an invoice has a handful
/// of lines and they are already inside the caller's transaction, so the round
/// trips are free and the SQL is readable. `position` is the index and not a
/// field on [`Line`], so two lines cannot claim the same place.
async fn write_lines(
    tx: &mut TenantTx<'_>,
    id: InvoiceId,
    lines: &[Line],
) -> Result<(), StoreError> {
    for (index, line) in lines.iter().enumerate() {
        let position = i32::try_from(index + 1)
            .map_err(|_| StoreError::conflict("that is not an invoice, it is a book".to_owned()))?;
        sqlx::query(
            "INSERT INTO invoice_lines \
                 (tenant_id, invoice_id, position, description, amount_minor, tax_rate_bp) \
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

/// Withdraw part or all of an issued invoice: a credit note.
///
/// **This is the remedy 0066's immutability argument leaned on and did not
/// have.** An issued invoice is not editable, so a wrong figure is corrected by
/// a second document that says so — one that carries its own number out of the
/// same run, and that neither hides the original nor pretends it never went
/// out.
///
/// `issued_by` is deliberately not a parameter: a credit note is written by an
/// operator, not by a seat. See 0071, and `routes::invoices` for the separation
/// of duties argument it inherits from `paid_at`.
///
/// `amount_minor` is in **the corrected invoice's currency**, and there is no
/// [`Money`] parameter for the same reason [`Line`] has no currency column: a
/// credit note is denominated by the document it corrects and nothing else, so
/// a currency here would be a second answer that could disagree with the first.
/// The currency comes back on the returned row.
///
/// [`StoreError::NotFound`] when the invoice is not this company's, does not
/// exist, is itself a credit note, or is smaller than the amount being credited
/// — one silence for all four, RLS's usual. [`StoreError::Conflict`] when it
/// already has one: 0071 allows exactly one credit note per invoice and the
/// unique index is what makes two concurrent callers unable to over-credit
/// between each other's snapshots.
pub async fn credit(
    tx: &mut TenantTx<'_>,
    id: InvoiceId,
    corrects: InvoiceId,
    amount_minor: u64,
    memo: &str,
) -> Result<Invoice, StoreError> {
    let minor = i64::try_from(amount_minor)
        .map_err(|_| StoreError::conflict("credit amount does not fit a bigint".to_owned()))?;
    if minor == 0 {
        // `invoices_amount_positive` would refuse it anyway; this is the error
        // the caller can read.
        return Err(StoreError::conflict(
            "a credit note for nothing is a letter".to_owned(),
        ));
    }

    // The guard reads the invoice being corrected, and both conjuncts are load
    // bearing: `corrects_invoice_id IS NULL` refuses a credit note of a credit
    // note, and `amount_minor >= $4` is what stops a receivable being credited
    // past zero. Both read an **immutable** row, so no concurrent write can
    // invalidate the answer between here and the insert — and a second credit
    // note against the same invoice is refused by the unique index rather than
    // by a sum somebody read too early.
    let counter = claim_a_number(
        "SELECT 1 FROM invoices t \
          WHERE t.id = $3 AND t.corrects_invoice_id IS NULL AND t.amount_minor >= $4",
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "WITH claimed AS ({counter}) \
         INSERT INTO invoices \
             (tenant_id, id, opportunity_id, corrects_invoice_id, number, currency, amount_minor, memo) \
         SELECT $1, $2, t.opportunity_id, t.id, claimed.last_number, t.currency, $4, $5 \
           FROM invoices t, claimed WHERE t.id = $3 \
         RETURNING {COLUMNS}"
    )))
    .bind(tx.tenant_id().as_uuid())
    .bind(id.as_uuid())
    .bind(corrects.as_uuid())
    .bind(minor)
    .bind(memo)
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;

    row_of(&row, Vec::new())
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
    let settled = sqlx::query(
        "UPDATE invoices SET paid_at = $2 \
          WHERE id = $1 AND paid_at IS NULL AND corrects_invoice_id IS NULL",
    )
    .bind(id.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(settled == 1)
}

/// The register: every document this company has issued, in the order of its
/// run.
///
/// Settled ones included, for `crate::backlog`'s and `crate::calendar::diary`'s
/// reason: what somebody wants at the end of a month is what is outstanding
/// *and* what came in, and a list that hid the second half would make the first
/// look like nothing had happened. **Credit notes included too**, and a reader
/// that nets them has to say so — `GET /v1/invoices` is the one that does.
///
/// `ORDER BY number` rather than 0066's `issued_at, id`, and it is the same
/// order with one fewer way to be wrong: `issued_at` is `now()`, which is the
/// *transaction's* start, so two overlapping issues can carry timestamps in the
/// opposite order to the numbers they were given. The run is the order the
/// customer's copies are in, and it needs no tie-break because it is unique.
///
/// ponytail: no pagination, no window, and no `outstanding()` beside it. A
/// register is a thing a human reads; add the filter the day one has enough rows
/// for the scan to show up in a plan — `invoices_outstanding_idx` is already
/// there for it.
pub async fn register(tx: &mut TenantTx<'_>) -> Result<Vec<Invoice>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM invoices ORDER BY number ASC"
    )))
    .fetch_all(&mut ***tx)
    .await?;

    // Every line of every document this company holds, in one statement rather
    // than one per invoice: RLS already scopes it to the tenant, and the
    // register is read whole or not at all.
    let mut lines: std::collections::HashMap<uuid::Uuid, Vec<Line>> =
        std::collections::HashMap::new();
    for row in sqlx::query(
        "SELECT invoice_id, description, amount_minor, tax_rate_bp \
           FROM invoice_lines ORDER BY invoice_id, position",
    )
    .fetch_all(&mut ***tx)
    .await?
    .iter()
    {
        lines
            .entry(row.get("invoice_id"))
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

    /// A second deal in a company that already has one, at `stage`.
    ///
    /// Its own account, so it shares nothing with the first but the tenant —
    /// which is the only thing the tests that use it are about.
    async fn another_deal(db: &Db, tenant: TenantId, stage: &str) -> Uuid {
        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Other plc', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("other-{}.example", account.simple()))
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
        tx.commit().await.expect("commit");
        opportunity
    }

    fn eur(minor: u64) -> Money {
        Money::new(minor, Currency::Eur).expect("nonzero")
    }

    /// One ordinary draft: 1200 EUR, no term, no lines. The tests that are
    /// about a term or a line say so by overriding one field of it.
    fn march(id: InvoiceId, opportunity: Uuid, employee: EmployeeId) -> Draft<'static> {
        Draft {
            id,
            opportunity_id: opportunity,
            issued_by: employee,
            amount: eur(120_000),
            memo: "March",
            due_at: None,
            lines: &[],
        }
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
        let issued = issue(&mut tx, march(id, opportunity, employee))
            .await
            .expect("issue against a won deal");
        tx.commit().await.expect("commit");

        assert_eq!(issued.amount, eur(120_000));
        assert_eq!(issued.amount.currency(), Currency::Eur);
        assert_eq!(issued.issued_by, Some(employee));
        assert_eq!(issued.number, 1, "a company's first invoice is number one");
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
            march(InvoiceId::new_v7(Utc::now()), opportunity, employee),
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
        issue(&mut tx, march(id, opportunity, employee))
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
        issue(&mut tx, march(id, opportunity, employee))
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

    // -----------------------------------------------------------------------
    // The number
    // -----------------------------------------------------------------------

    /// **The property 0071 exists for, under real concurrency and not in
    /// theory.**
    ///
    /// Two transactions on two connections issue at the same instant. The
    /// assertion that matters is the middle one: while the first holds the
    /// counter row, the second is **still running** — it is waiting on a lock
    /// rather than reading a number the first one is also going to use. A
    /// `bigserial` would let both through immediately, both numbers would be
    /// handed out, and this test would fail on `is_finished()` long before it
    /// got to compare 1 and 2.
    #[tokio::test]
    async fn two_issues_at_once_take_two_numbers_and_skip_none() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;

        let mut first = db.tenant_tx(tenant).await.expect("tx");
        let one = issue(
            &mut first,
            march(InvoiceId::new_v7(Utc::now()), opportunity, employee),
        )
        .await
        .expect("the first issue");
        assert_eq!(one.number, 1);

        let elsewhere = db.clone();
        let second = tokio::spawn(async move {
            let mut tx = elsewhere.tenant_tx(tenant).await.expect("tx");
            let issued = issue(
                &mut tx,
                march(InvoiceId::new_v7(Utc::now()), opportunity, employee),
            )
            .await
            .expect("the second issue");
            tx.commit().await.expect("commit");
            issued.number
        });

        // Long enough that a second issuer which was *not* serialised would
        // have finished: the first transaction has not committed, so the only
        // way to still be running is to be waiting for the counter row.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !second.is_finished(),
            "the second issue must wait for the first transaction to end, not take a number beside it"
        );

        first.commit().await.expect("commit the first");
        assert_eq!(
            second.await.expect("join the second issuer"),
            2,
            "the second issuer takes the number after the first, with nothing between them"
        );
    }

    /// **What a sequence cannot do.** A rolled-back issue gives its number
    /// back, and the next document takes it: 1 is issued exactly once.
    #[tokio::test]
    async fn a_rolled_back_issue_gives_its_number_back() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let doomed = issue(
            &mut tx,
            march(InvoiceId::new_v7(Utc::now()), opportunity, employee),
        )
        .await
        .expect("issue");
        assert_eq!(doomed.number, 1);
        tx.rollback().await.expect("rollback");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let kept = issue(
            &mut tx,
            march(InvoiceId::new_v7(Utc::now()), opportunity, employee),
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit");

        assert_eq!(
            kept.number, 1,
            "the number a rolled-back issue took must come back; a sequence would have started at 2"
        );
    }

    /// **A refusal claims nothing, even from a caller that commits anyway.**
    ///
    /// This is why the counter arm is a CTE inside the insert rather than a
    /// statement before it: with two statements, gap-freeness would depend on
    /// every caller remembering to roll back a refusal, and this test would go
    /// red on the one that forgot.
    #[tokio::test]
    async fn a_refused_issue_claims_no_number_even_when_the_caller_commits() {
        let Some(db) = db().await else { return };
        let (tenant, employee, won) = seed(&db, "closed_won").await;
        let lost = another_deal(&db, tenant, "negotiation").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let refused = issue(
            &mut tx,
            march(InvoiceId::new_v7(Utc::now()), lost, employee),
        )
        .await;
        assert!(matches!(refused, Err(StoreError::NotFound)), "{refused:?}");
        // The mistake this design has to survive: the caller commits regardless.
        tx.commit()
            .await
            .expect("commit a transaction that wrote nothing");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let first = issue(&mut tx, march(InvoiceId::new_v7(Utc::now()), won, employee))
            .await
            .expect("issue");
        tx.commit().await.expect("commit");

        assert_eq!(
            first.number, 1,
            "a refused issue must not consume a number, committed or not"
        );
    }

    /// The counter may only advance by one, and that is the only hole
    /// `invoices_tenant_number_key` cannot see: winding it *back* produces a
    /// duplicate the index refuses, winding it *forward* produces a gap only
    /// this trigger refuses. Asserted against the owner, which no GRANT binds.
    #[tokio::test]
    async fn a_counter_cannot_be_wound_forward() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        issue(
            &mut tx,
            march(InvoiceId::new_v7(Utc::now()), opportunity, employee),
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let jumped =
            sqlx::query("UPDATE invoice_counters SET last_number = 100 WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .execute(&mut *tx)
                .await;
        assert!(
            jumped.is_err(),
            "a counter wound forward is a gap nothing else can see"
        );
        let _ = tx.rollback().await;
    }

    /// **The columns 0071 adds are immutable because 0066's trigger is an
    /// expression**, and this asserts it rather than trusting the sentence.
    /// Both are the right answer: a number and a due date are part of the
    /// document the customer is holding, and the remedy for a wrong one is the
    /// credit note below, not an edit.
    #[tokio::test]
    async fn the_number_and_the_due_date_are_part_of_the_issued_document() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let issued = issue(
            &mut tx,
            Draft {
                due_at: Some(Utc::now() + chrono::TimeDelta::days(30)),
                ..march(id, opportunity, employee)
            },
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit");
        assert!(issued.due_at.is_some(), "the term the caller gave is kept");

        // Asserted on the *message*, not merely on `is_err`: two of these would
        // also fail a CHECK constraint, and a test that cannot tell the two
        // apart would stay green the day the trigger stops covering a column.
        for attack in [
            "UPDATE invoices SET number = 99 WHERE id = $1",
            "UPDATE invoices SET due_at = now() + interval '1 day' WHERE id = $1",
            "UPDATE invoices SET corrects_invoice_id = id WHERE id = $1",
        ] {
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            let refused = sqlx::query(attack)
                .bind(id.as_uuid())
                .execute(&mut *tx)
                .await
                .expect_err("an issued document is not rewritten")
                .to_string();
            assert!(
                refused.contains("only paid_at may be written"),
                "`{attack}` must be refused by invoices_are_issued_once, got: {refused}"
            );
            let _ = tx.rollback().await;
        }
    }

    // -----------------------------------------------------------------------
    // The lines
    // -----------------------------------------------------------------------

    /// A document made of lines, read back in the document's order — and the
    /// tax rate arriving as `None`, which is what every row this workspace
    /// writes carries until the founder says otherwise.
    #[tokio::test]
    async fn a_document_is_made_of_lines_in_order() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());
        let lines = vec![
            Line {
                description: "Two seats, March".to_owned(),
                amount_minor: 130_000,
                tax_rate_bp: None,
            },
            Line {
                description: "Introductory discount".to_owned(),
                amount_minor: -10_000,
                tax_rate_bp: None,
            },
        ];

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let issued = issue(
            &mut tx,
            Draft {
                lines: &lines,
                ..march(id, opportunity, employee)
            },
        )
        .await
        .expect("issue with lines");
        tx.commit().await.expect("commit");
        assert_eq!(issued.lines, lines);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let register = register(&mut tx).await.expect("read");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            register[0].lines, lines,
            "the order the caller gave is the order the document keeps"
        );
        assert_eq!(
            register[0].lines[0].tax_rate_bp, None,
            "no rate is invented anywhere in this workspace"
        );
    }

    /// **The lines total the document**, refused twice: by this crate before
    /// anything is written, and by the database at COMMIT for anybody who is
    /// not this crate.
    ///
    /// The second half is also what stops a line being *added* to an issued
    /// document: the sum already matched, so one more makes it stop matching.
    #[tokio::test]
    async fn lines_that_do_not_total_the_document_are_refused_twice() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());
        let short = vec![Line {
            description: "Two seats, March".to_owned(),
            amount_minor: 119_999,
            tax_rate_bp: None,
        }];

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let refused = issue(
            &mut tx,
            Draft {
                lines: &short,
                ..march(id, opportunity, employee)
            },
        )
        .await;
        assert!(
            matches!(refused, Err(StoreError::Conflict(_))),
            "the store must not write a document whose lines disagree with it, got {refused:?}"
        );
        tx.rollback().await.expect("rollback");

        // And from outside this crate: an invoice with no lines, given one that
        // does not total it. The trigger is deferred, so the refusal lands on
        // COMMIT rather than on the INSERT — which is the whole point of it
        // being deferred, and is why this asserts on the commit.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let bare = issue(&mut tx, march(id, opportunity, employee))
            .await
            .expect("issue");
        tx.commit().await.expect("commit");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO invoice_lines (tenant_id, invoice_id, position, description, amount_minor) \
             VALUES ($1, $2, 1, 'a line nobody agreed', 5)",
        )
        .bind(tenant.as_uuid())
        .bind(bare.id.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("a deferred constraint lets the statement through");
        assert!(
            tx.commit().await.is_err(),
            "a document whose lines do not total it must not commit"
        );
    }

    // -----------------------------------------------------------------------
    // The credit note
    // -----------------------------------------------------------------------

    /// **The remedy 0066's immutability argument leaned on and did not have.**
    ///
    /// The credit note takes the next number out of the same run, carries no
    /// issuer because an operator wrote it, and does not remove the invoice
    /// from the register — a document that went out stays out.
    #[tokio::test]
    async fn an_invoice_is_corrected_by_a_credit_note_out_of_the_same_run() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        issue(&mut tx, march(id, opportunity, employee))
            .await
            .expect("issue");
        let note = credit(
            &mut tx,
            InvoiceId::new_v7(Utc::now()),
            id,
            20_000,
            "Two seats were never provisioned",
        )
        .await
        .expect("credit");
        tx.commit().await.expect("commit");

        assert_eq!(note.number, 2, "one run, both documents");
        assert_eq!(note.corrects_invoice_id, Some(id));
        assert_eq!(
            note.issued_by, None,
            "a credit note is an operator's act, not a seat's"
        );
        assert_eq!(
            note.amount,
            eur(20_000),
            "the figure is positive; the sign is the pointer"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let register = register(&mut tx).await.expect("read");
        assert_eq!(
            register.len(),
            2,
            "the invoice is not removed by being corrected"
        );

        // A credit note is not settled: nothing here moves money the other way.
        assert!(
            !declare_paid(&mut tx, note.id, Utc::now())
                .await
                .expect("declare"),
            "a credit note has no settlement to declare"
        );
        tx.rollback().await.expect("rollback");
    }

    /// One credit note per invoice, never for more than it says, and never of
    /// a credit note — and the run keeps no hole where the refusals were.
    #[tokio::test]
    async fn a_credit_note_cannot_exceed_the_invoice_or_be_issued_twice() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        issue(&mut tx, march(id, opportunity, employee))
            .await
            .expect("issue");
        tx.commit().await.expect("commit");

        // More than the invoice says.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let too_much = credit(&mut tx, InvoiceId::new_v7(Utc::now()), id, 120_001, "oops").await;
        assert!(
            matches!(too_much, Err(StoreError::NotFound)),
            "a receivable cannot be credited past zero, got {too_much:?}"
        );
        tx.rollback().await.expect("rollback");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let note = credit(
            &mut tx,
            InvoiceId::new_v7(Utc::now()),
            id,
            120_000,
            "all of it",
        )
        .await
        .expect("credit");
        tx.commit().await.expect("commit");

        // A second one, and a credit note of a credit note.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let twice = credit(&mut tx, InvoiceId::new_v7(Utc::now()), id, 1, "again").await;
        assert!(
            matches!(twice, Err(StoreError::Conflict(_))),
            "an invoice is credited once, got {twice:?}"
        );
        tx.rollback().await.expect("rollback");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let recursive = credit(
            &mut tx,
            InvoiceId::new_v7(Utc::now()),
            note.id,
            1,
            "a credit note of a credit note",
        )
        .await;
        assert!(
            matches!(recursive, Err(StoreError::NotFound)),
            "a credit note is not itself creditable, got {recursive:?}"
        );
        tx.rollback().await.expect("rollback");

        // Two refusals and a rollback later, the run has no hole in it.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let next = issue(
            &mut tx,
            march(InvoiceId::new_v7(Utc::now()), opportunity, employee),
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit");
        assert_eq!(next.number, 3, "1 invoice, 2 credit note, 3 invoice");
    }

    /// **The seam three new tables put under an old statement: a company can
    /// still be deleted.**
    ///
    /// `DELETE FROM tenants` now walks a self-referencing foreign key, a
    /// counter row and a line table. What this proves is the **cascade**: all
    /// three go, and nothing blocks the statement.
    ///
    /// It proves nothing about `invoice_lines_total_the_document`, and an
    /// earlier version of this comment claimed it did — that the deferred
    /// trigger fired at COMMIT after the invoice had gone and answered
    /// correctly because both its reads came back NULL together. `pg_trigger`
    /// refutes that: `tgtype = 5` is ROW + AFTER + INSERT and nothing else, so
    /// a DELETE fires this trigger **zero times**. There is no arm to
    /// exercise, and that absence is *why* the cascade is free — not a
    /// comparison that happens to agree.
    ///
    /// Nothing else in this workspace covers the cascade: the fixtures that
    /// drop a tenant hold no invoices, and the tests that hold invoices drop
    /// no tenant.
    #[tokio::test]
    async fn a_company_with_documents_can_still_be_deleted() {
        let Some(db) = db().await else { return };
        let (tenant, employee, opportunity) = seed(&db, "closed_won").await;
        let id = InvoiceId::new_v7(Utc::now());
        let lines = vec![Line {
            description: "Two seats, March".to_owned(),
            amount_minor: 120_000,
            tax_rate_bp: None,
        }];

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        issue(
            &mut tx,
            Draft {
                lines: &lines,
                ..march(id, opportunity, employee)
            },
        )
        .await
        .expect("issue");
        credit(
            &mut tx,
            InvoiceId::new_v7(Utc::now()),
            id,
            20_000,
            "two seats were never provisioned",
        )
        .await
        .expect("credit");
        tx.commit().await.expect("commit");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("a company is deleted with its register");
        tx.commit()
            .await
            .expect("and the deferred line check does not block the cascade at COMMIT");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM invoices WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("count");
        let counters: i64 =
            sqlx::query_scalar("SELECT count(*) FROM invoice_counters WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!((left, counters), (0, 0), "nothing of the company is left");
    }
}
