//! Persistence for the seller vertical: prospect accounts, the humans at them,
//! the findings we can prove about their product, the deals that follow, and
//! the suppression list that outranks all of it.
//!
//! The schema is in `migrations/0011_revenue.sql` and carries the rules; this
//! module is the thin, typed way to reach it. It is deliberately the same
//! module `sourcing.rs` is, one vertical over — same [`TenantTx`], same money
//! discipline, same "the constraint is the enforcement" habit. Four things are
//! worth knowing before reading further.
//!
//! **No query in this file filters on `tenant_id`.** Not one. Every function
//! takes a [`TenantTx`], which has already set `app.tenant_id`, so the
//! row-level security policies do the filtering. A `WHERE tenant_id = $n` here
//! would be a second, weaker copy of a rule the database already enforces.
//!
//! **Suppression is not checked here, and that is the point.** There is no
//! `is_suppressed()` for a caller to forget. Writing an active [`NewContact`]
//! whose address is on the list, or recording an outbound
//! [`Event`] against one, fails in Postgres with
//! [`RevenueError::Suppressed`] — including when the person opted out globally
//! through a different tenant, which this tenant cannot see and does not need
//! to. [`suppress`] deactivates the matching contacts as it writes.
//!
//! The daily volume cap is **not** implemented here. That is
//! `max_new_contacts_per_day` in the policy tables, and a second mechanism for
//! the same rule is how two mechanisms disagree; [`new_contacts_since`] is the
//! count that field is compared against.
//!
//! **Evidence is written once and never again.** [`insert_evidence`] is the
//! only way in and there is no way out: `app_role` holds no UPDATE or DELETE on
//! the table and a trigger refuses both regardless of privilege. A finding is a
//! factual claim about someone else's product; one that can be edited after it
//! was sent is not a finding. Every column that makes it reproducible is NOT
//! NULL, so an unreproducible finding cannot be stored, let alone sent.
//! `observed_claim` is the prospect's own text, and being in our database does
//! not make it ours — it stays `Untrusted<T>` on the way to a model or a human.
//!
//! **Every check is recorded, not only the ones that found something.**
//! [`record_attempt`] files one row per proof-of-need check whatever it came to
//! — evidence, agreement, unreadable, not-reproducible, blocked — so how often
//! the reproducibility bar suppresses a real finding is a SELECT over
//! `proof_of_need_suppression` and not an opinion. `0015_proof_of_need.sql`
//! carries the rules; `agentos_app::proof_of_need` carries how to read the
//! number.
//!
//! **A prospect's booking flow is written by a human and only read by the
//! application.** `0032_prospect_flows.sql` grants `app_role` no INSERT and no
//! UPDATE on `prospect_flows`, so [`set_prospect_flow`] and
//! [`confirm_prospect_flow`] are the only two functions in this file that take
//! an admin transaction. A selector decides which element on somebody else's
//! page a claim gets made about; see [`set_prospect_flow`] for why that is not
//! a thing an employee may write.
//!
//! **Money is [`Money`] on the way in and on the way out**, never a bare
//! integer: minor units plus a currency, converted at the boundary.
//!
//! ponytail: ids are plain [`Uuid`] here rather than domain newtypes, exactly
//! as in `sourcing.rs`; when the revenue id types land in the domain crate
//! these signatures take them and nothing else changes. Stage and segment are
//! `&str` for the same reason — the CHECK constraints in the migration are the
//! authority, and the domain enums map onto them with `as_str()`.

use agentos_domain::ids::{EmployeeId, TenantId};
use agentos_domain::money::{Currency, Money, MoneyError};
use chrono::{DateTime, NaiveDate, Utc};
use uuid::Uuid;

use crate::db::{Db, StoreError, TenantTx};

/// SQLSTATE raised by the suppression triggers in `0011_revenue.sql`. Nothing
/// else in the workspace raises it.
const SQLSTATE_SUPPRESSED: &str = "P0002";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a revenue read or write failed.
#[derive(Debug, thiserror::Error)]
pub enum RevenueError {
    /// The database said no. Includes `NotFound` for a row that does not exist
    /// *or* belongs to another tenant — RLS makes those indistinguishable, on
    /// purpose.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// This person is on the suppression list, for this tenant or globally.
    /// Raised by the database, not by a check in this file, so there is no
    /// path around it.
    #[error("suppressed: {0}")]
    Suppressed(String),

    /// An amount that does not fit a Postgres `bigint`, in either direction.
    #[error("amount does not fit in a bigint")]
    AmountOutOfRange,

    /// A zero amount, or a stored currency code this system does not know.
    #[error(transparent)]
    Money(#[from] MoneyError),
}

impl From<sqlx::Error> for RevenueError {
    // Suppression first, because it is the one error a caller must be able to
    // act on differently; everything else routes through StoreError so 23505 /
    // 40001 / RowNotFound keep their meaning.
    fn from(err: sqlx::Error) -> Self {
        let suppressed = err
            .as_database_error()
            .and_then(|e| e.code())
            .is_some_and(|code| code == SQLSTATE_SUPPRESSED);
        if suppressed {
            return Self::Suppressed(err.to_string());
        }
        Self::Store(err.into())
    }
}

/// `Money` -> `bigint`.
fn minor_of(amount: Money) -> Result<i64, RevenueError> {
    i64::try_from(amount.minor()).map_err(|_| RevenueError::AmountOutOfRange)
}

/// `bigint` + currency code -> `Money`.
fn money_of(minor: i64, code: &str) -> Result<Money, RevenueError> {
    let minor = u64::try_from(minor).map_err(|_| RevenueError::AmountOutOfRange)?;
    Ok(Money::new(minor, code.parse::<Currency>()?)?)
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

/// A prospect company to create.
#[derive(Debug, Clone, Copy)]
pub struct NewAccount<'a> {
    /// Registered name, as it will appear on a contract.
    pub legal_name: &'a str,
    /// Registrable domain, lower case — the identity of a prospect, and where
    /// its booking flow lives. Unique per tenant, never globally: two customers
    /// may both be prospecting the same airline.
    pub domain: &'a str,
    /// `airline`, `ota`, `corporate_travel`, `tmc`, `insurer`, `cruise`,
    /// `relocation`, `other`.
    pub segment: &'a str,
    /// ISO 3166-1 alpha-2, upper case. `ZZ` when nobody knows — see
    /// `0033_prospect_listing.sql` for why an importer writes that rather than
    /// guessing at `Mandaluyong, Philippines`.
    pub country: &'a str,
    /// The employee working it.
    pub employee_id: Option<EmployeeId>,
    /// Where the source list says they are, in the source list's own words.
    /// Free text; [`Self::country`] is the typed half and is not derived from
    /// this. `0033_prospect_listing.sql`.
    pub location: Option<&'a str>,
    /// Their site as the source list spells it, scheme and `www.` and all.
    /// [`Self::domain`] is the derived identity; this is the input it was
    /// derived from, kept because the derivation is lossy.
    pub website: Option<&'a str>,
}

/// Create an account in the `candidate` state.
pub async fn insert_account(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    account: &NewAccount<'_>,
) -> Result<(), RevenueError> {
    sqlx::query(
        "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country, employee_id, \
                               location, website) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(account.legal_name)
    .bind(account.domain)
    .bind(account.segment)
    .bind(account.country)
    .bind(account.employee_id.map(|e| e.as_uuid()))
    .bind(account.location)
    .bind(account.website)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// What an idempotent write did, so a caller that runs a list twice can say so
/// rather than guess from a rows-affected count.
///
/// [`upsert_account`] never answers [`Upserted::Suppressed`]: a company is not a
/// person and cannot opt out. Only [`upsert_contact`] can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upserted {
    /// The row was not there and now is.
    Created(Uuid),
    /// The natural key was already taken. **Nothing was written** — no column
    /// was refreshed from the new values, deliberately: re-running an import is
    /// a no-op and never a silent edit to a row somebody has since worked.
    Existing(Uuid),
    /// This address is on the suppression list, for this tenant or globally, so
    /// no contact row was written and no inactive one was woken up.
    Suppressed,
}

impl Upserted {
    /// The row's id, when there is one.
    pub const fn id(self) -> Option<Uuid> {
        match self {
            Self::Created(id) | Self::Existing(id) => Some(id),
            Self::Suppressed => None,
        }
    }
}

/// Create an account, or find the one that already holds this domain.
///
/// The idempotent twin of [`insert_account`], for loading a list that will be
/// loaded again. The natural key is `(tenant_id, domain)` — the same unique
/// constraint `0011_revenue.sql` already carries, so this is that rule being
/// *used* rather than a second copy of it.
pub async fn upsert_account(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    account: &NewAccount<'_>,
) -> Result<Upserted, RevenueError> {
    let created: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country, employee_id, \
                               location, website) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (tenant_id, domain) DO NOTHING \
         RETURNING id",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(account.legal_name)
    .bind(account.domain)
    .bind(account.segment)
    .bind(account.country)
    .bind(account.employee_id.map(|e| e.as_uuid()))
    .bind(account.location)
    .bind(account.website)
    .fetch_optional(&mut ***tx)
    .await?;

    if let Some(id) = created {
        return Ok(Upserted::Created(id));
    }

    // Two statements rather than one CTE: the second only runs on the second
    // import of a row, and `WHERE domain = $1` under RLS is the same lookup the
    // conflict just did.
    let existing: Uuid = sqlx::query_scalar("SELECT id FROM accounts WHERE domain = $1")
        .bind(account.domain)
        .fetch_one(&mut ***tx)
        .await?;
    Ok(Upserted::Existing(existing))
}

/// A prospect, as a search returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    /// Account id.
    pub id: Uuid,
    /// Registered name.
    pub legal_name: String,
    /// Registrable domain.
    pub domain: String,
    /// Vertical segment.
    pub segment: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
    /// `candidate` or `qualified`.
    pub state: String,
}

/// Accounts in one segment that we have not proved anything about yet, oldest
/// first.
///
/// This is the queue that starts the pipeline: the mechanism this vertical is
/// built around is running a passport/destination pair through a prospect's own
/// booking flow and observing what it says, and this is the list of prospects
/// nobody has done that for. Existing customers and disqualified accounts are
/// excluded here rather than by the caller.
pub async fn accounts_without_evidence(
    tx: &mut TenantTx<'_>,
    segment: &str,
    limit: i64,
) -> Result<Vec<AccountSummary>, RevenueError> {
    let rows: Vec<(Uuid, String, String, String, String, String)> = sqlx::query_as(
        "SELECT a.id, a.legal_name, a.domain, a.segment, a.country, a.state \
           FROM accounts a \
          WHERE a.segment = $1 \
            AND a.state IN ('candidate', 'qualified') \
            AND NOT EXISTS (SELECT 1 FROM evidence e WHERE e.account_id = a.id) \
          ORDER BY a.created_at, a.id \
          LIMIT $2",
    )
    .bind(segment)
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, legal_name, domain, segment, country, state)| AccountSummary {
                id,
                legal_name,
                domain,
                segment,
                country,
                state,
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// Prospect flows
// ---------------------------------------------------------------------------

/// One prospect's booking page, as a human wrote it down.
///
/// The schema and the argument are in `0032_prospect_flows.sql`. Three things
/// are worth knowing here.
///
/// **It is a row, not a `Flow`.** `agentos_app::proof_of_need::Flow` is the
/// value a probe runs on and it carries a private seal;
/// `Flow::confirmed` is the only thing that turns one of these into one, and it
/// refuses a row where [`ProspectFlow::confirmed_by`] is `None`. So the
/// confirmation bar is enforced once, in the app crate, rather than half here
/// and half there — the same discipline as suppression, which this file
/// deliberately does not check either.
///
/// **`prospect` and `domain` are joined, not stored.** They are
/// `accounts.legal_name` and `accounts.domain`. A flow does not get its own copy
/// of where a prospect lives.
///
/// **Deliberately not `Deserialize`.** These selectors decide which element on
/// somebody else's page a claim will be made about; a struct that can be parsed
/// from JSON is a struct that will one day be parsed from model output.
/// `FromRow` is not the same door: it needs a Postgres row, and the only query
/// that produces one is [`next_flow_to_probe`], three functions down.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ProspectFlow {
    /// The account this is the flow for.
    pub account_id: Uuid,
    /// `accounts.legal_name`, joined.
    pub prospect: String,
    /// `accounts.domain`, joined. The registrable domain the gate rules on.
    pub domain: String,
    /// The page the check starts on.
    pub entry_url: String,
    /// CSS selector of the passport / nationality field.
    pub passport_field: String,
    /// CSS selector of the destination field.
    pub destination_field: String,
    /// CSS selector of the travel-date field, when the flow has one.
    pub date_field: Option<String>,
    /// CSS selector of their "check requirements" button. Never a booking or
    /// payment submit; see the migration.
    pub submit: Option<String>,
    /// CSS selector of the element that displays the answer.
    pub panel: String,
    /// The human who opened the page and checked these selectors point at what
    /// they say. `None` is nobody having done that yet.
    pub confirmed_by: Option<String>,
    /// When they said so.
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// The selectors an operator writes. Everything else on the row is derived.
#[derive(Debug, Clone, Copy)]
pub struct NewProspectFlow<'a> {
    /// Absolute `https://` URL on the account's own domain.
    pub entry_url: &'a str,
    /// CSS selector of the passport / nationality field.
    pub passport_field: &'a str,
    /// CSS selector of the destination field.
    pub destination_field: &'a str,
    /// CSS selector of the travel-date field, when the flow has one.
    pub date_field: Option<&'a str>,
    /// CSS selector of their "check requirements" button.
    pub submit: Option<&'a str>,
    /// CSS selector of the element that displays the answer.
    pub panel: &'a str,
}

/// Write one prospect's selectors, unconfirmed.
///
/// **An admin transaction, and the only two functions in this file that take
/// one.** `0032_prospect_flows.sql` grants `app_role` no INSERT and no UPDATE
/// here, so this cannot run under [`Db::tenant_tx`] — deliberately. An employee
/// that could write this table could point a selector at any element on a domain
/// its policy lets it read, and then produce a screenshotted, reproducible
/// finding about whatever that element happened to say. Writing a flow is an
/// operator's act, proved by the operator's own database credential, exactly as
/// `agentos-server policy` is.
///
/// A wrong `tenant_id` is not a write into somebody else's tenant: the composite
/// foreign key to `accounts (tenant_id, id)` addresses an account that is simply
/// not there, and this returns [`StoreError`]'s wrapping of that.
///
/// **It always writes an unconfirmed row**, and re-writing a confirmed one
/// revokes the confirmation — in the application here and in a trigger there, so
/// it is also true of a `psql` session. The value of a confirmation is that a
/// named human looked at *these exact selectors*.
pub async fn set_prospect_flow(
    db: &Db,
    tenant_id: TenantId,
    account_id: Uuid,
    flow: &NewProspectFlow<'_>,
) -> Result<(), RevenueError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    sqlx::query(
        "INSERT INTO prospect_flows (account_id, tenant_id, entry_url, passport_field, \
                                     destination_field, date_field, submit, panel) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (account_id) DO UPDATE SET \
           entry_url = excluded.entry_url, \
           passport_field = excluded.passport_field, \
           destination_field = excluded.destination_field, \
           date_field = excluded.date_field, \
           submit = excluded.submit, \
           panel = excluded.panel, \
           confirmed_by = NULL, \
           confirmed_at = NULL",
    )
    .bind(account_id)
    .bind(tenant_id.as_uuid())
    .bind(flow.entry_url)
    .bind(flow.passport_field)
    .bind(flow.destination_field)
    .bind(flow.date_field)
    .bind(flow.submit)
    .bind(flow.panel)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record that `who` opened the page and checked these selectors.
///
/// `false` when there is no flow for that account in that tenant. An admin
/// transaction for [`set_prospect_flow`]'s reason.
pub async fn confirm_prospect_flow(
    db: &Db,
    tenant_id: TenantId,
    account_id: Uuid,
    who: &str,
    at: DateTime<Utc>,
) -> Result<bool, RevenueError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let done = sqlx::query(
        "UPDATE prospect_flows SET confirmed_by = $3, confirmed_at = $4 \
          WHERE account_id = $1 AND tenant_id = $2",
    )
    .bind(account_id)
    .bind(tenant_id.as_uuid())
    .bind(who)
    .bind(at)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    tx.commit().await?;
    Ok(done)
}

/// The next prospect in one segment that has a flow written down and nothing
/// proved about it yet, oldest account first.
///
/// [`accounts_without_evidence`] is the same queue without the flow, and this is
/// not a replacement for it: that one answers "who have we not proved anything
/// about", which is a pipeline question, and this answers "who can be probed
/// right now", which is a scheduling one.
///
/// **It does not filter on the confirmation, and that is the point.** An
/// unconfirmed flow at the head of the queue comes back from here and is refused
/// by `Flow::confirmed` with the account named, so the operator is told which
/// prospect is waiting on them. Filtering here would make the same row disappear
/// instead, which is the silent skip this whole mechanism exists to avoid — and
/// it would put the confirmation bar in two places, one of which would
/// eventually be the one that got relaxed.
pub async fn next_flow_to_probe(
    tx: &mut TenantTx<'_>,
    segment: &str,
) -> Result<Option<ProspectFlow>, RevenueError> {
    // `FromRow`, so the eleven columns are matched by name rather than by
    // position: the two joined ones are aliased to the fields they fill, and
    // adding a column here cannot silently shift the rest by one.
    let row: Option<ProspectFlow> = sqlx::query_as(
        "SELECT f.account_id, a.legal_name AS prospect, a.domain AS domain, f.entry_url, \
                f.passport_field, f.destination_field, f.date_field, f.submit, f.panel, \
                f.confirmed_by, f.confirmed_at \
           FROM prospect_flows f \
           JOIN accounts a ON a.id = f.account_id \
          WHERE a.segment = $1 \
            AND a.state IN ('candidate', 'qualified') \
            AND NOT EXISTS (SELECT 1 FROM evidence e WHERE e.account_id = a.id) \
          ORDER BY a.created_at, a.id \
          LIMIT 1",
    )
    .bind(segment)
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row)
}

/// One prospect's flow, by account, whether or not it is anybody's turn.
///
/// [`next_flow_to_probe`] answers "who is next" and is the operator's queue —
/// it orders, it skips accounts that already have evidence, and it takes one.
/// This answers "what about *this* one", which is what a seller's turn needs
/// once its own selection has already picked the account: asking the queue
/// again would re-apply an ordering the caller has already resolved and could
/// hand back a different prospect than the one being worked.
///
/// Deliberately the same projection, aliases included, so both callers hand
/// [`ProspectFlow`] to the same constructor and neither can see a column the
/// other cannot. Confirmation is **not** filtered here: an unconfirmed row is a
/// row, and refusing it is `Flow::confirmed`'s job — a reader that silently
/// returned `None` for one would make "no flow written" and "written but nobody
/// looked" the same answer, and they call for different things from an
/// operator.
pub async fn flow_of(
    tx: &mut TenantTx<'_>,
    account_id: Uuid,
) -> Result<Option<ProspectFlow>, RevenueError> {
    let row: Option<ProspectFlow> = sqlx::query_as(
        "SELECT f.account_id, a.legal_name AS prospect, a.domain AS domain, f.entry_url, \
                f.passport_field, f.destination_field, f.date_field, f.submit, f.panel, \
                f.confirmed_by, f.confirmed_at \
           FROM prospect_flows f \
           JOIN accounts a ON a.id = f.account_id \
          WHERE f.account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row)
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

/// A human at a prospect.
///
/// `email` must be lower case and `phone` E.164; the table has CHECKs saying
/// so, because the suppression lookup is an equality test and a normalisation
/// nobody enforces is a normalisation that eventually does not happen.
#[derive(Debug, Clone, Copy)]
pub struct NewContact<'a> {
    /// The account they work at.
    pub account_id: Uuid,
    /// Their name.
    pub full_name: &'a str,
    /// Lower-case email.
    pub email: Option<&'a str>,
    /// E.164 phone.
    pub phone: Option<&'a str>,
    /// Job title.
    pub role: Option<&'a str>,
    /// BCP-47 tag; which language this human is written to in.
    pub language: Option<&'a str>,
    /// Whether they are the main line into the account.
    pub is_primary: bool,
    /// `legitimate_interest`, `consent` or `contract`. B2B prospecting in the
    /// EU still needs a lawful basis, and it is recorded per person.
    pub lawful_basis: &'a str,
    /// When to chase them.
    pub next_follow_up_at: Option<DateTime<Utc>>,
}

/// Create a contact.
///
/// Returns [`RevenueError::Suppressed`] if this address is on the suppression
/// list for this tenant or globally — enforced by a trigger, so re-adding an
/// opted-out person is impossible rather than discouraged.
pub async fn insert_contact(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    contact: &NewContact<'_>,
) -> Result<(), RevenueError> {
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, account_id, full_name, email, phone, role, \
                               language, is_primary, lawful_basis, next_follow_up_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(contact.account_id)
    .bind(contact.full_name)
    .bind(contact.email)
    .bind(contact.phone)
    .bind(contact.role)
    .bind(contact.language)
    .bind(contact.is_primary)
    .bind(contact.lawful_basis)
    .bind(contact.next_follow_up_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// Create a contact, or find the one that already holds this address — and
/// skip it, silently and without waking it, if it has opted out.
///
/// The idempotent twin of [`insert_contact`], for loading a list that will be
/// loaded again. Two things are different from its twin and both are the point:
///
/// **The natural key is the address.** `contacts_email_key unique (tenant_id,
/// email)` in `0011_revenue.sql` is the rule, and the reason it is the right key
/// is written there: two rows for one address is one row that dodges the
/// suppression cascade. So this reuses it rather than inventing a key beside it.
///
/// **A suppressed address answers [`Upserted::Suppressed`] instead of
/// [`RevenueError::Suppressed`].** A list of a thousand people that dies on the
/// one who opted out is a list nobody imports, and the pressure that creates is
/// pressure to skip the check. The check is not skipped and it is not weakened:
/// `revenue_suppression_of` is called **inside the INSERT**, in the same
/// statement and the same snapshot, so there is still no moment where a caller
/// holds an answer it could act on separately — this module still exposes no
/// `is_suppressed()` — and the BEFORE trigger on `contacts` is still there
/// behind it, refusing an active suppressed row whatever this statement thinks.
/// An address that is on the list is never inserted and an inactive row for it
/// is never touched, so an import cannot re-activate an opt-out.
pub async fn upsert_contact(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    contact: &NewContact<'_>,
) -> Result<Upserted, RevenueError> {
    // One statement, three facts: what this insert wrote, what was already
    // there before it, and whether the address is suppressed. The subqueries run
    // in the statement's own snapshot, so `existing` cannot see the row the CTE
    // just wrote.
    let (created, existing, suppressed): (Option<Uuid>, Option<Uuid>, bool) = sqlx::query_as(
        "WITH ins AS ( \
           INSERT INTO contacts (id, tenant_id, account_id, full_name, email, phone, role, \
                                 language, is_primary, lawful_basis, next_follow_up_at) \
           SELECT $1::uuid, $2::uuid, $3::uuid, $4::text, $5::text, $6::text, $7::text, \
                  $8::text, $9::boolean, $10::text, $11::timestamptz \
            WHERE revenue_suppression_of($5::text, $6::text) IS NULL \
           ON CONFLICT (tenant_id, email) DO NOTHING \
           RETURNING id \
         ) \
         SELECT (SELECT id FROM ins), \
                (SELECT id FROM contacts WHERE email = $5::text), \
                revenue_suppression_of($5::text, $6::text) IS NOT NULL",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(contact.account_id)
    .bind(contact.full_name)
    .bind(contact.email)
    .bind(contact.phone)
    .bind(contact.role)
    .bind(contact.language)
    .bind(contact.is_primary)
    .bind(contact.lawful_basis)
    .bind(contact.next_follow_up_at)
    .fetch_one(&mut ***tx)
    .await?;

    // Suppression outranks "already there": both can be true of the same row,
    // and which one a report should say is not a close call.
    if suppressed {
        Ok(Upserted::Suppressed)
    } else if let Some(id) = created {
        Ok(Upserted::Created(id))
    } else if let Some(id) = existing {
        Ok(Upserted::Existing(id))
    } else {
        // Nothing written, nothing there, nobody suppressed: the only way here
        // is a race with a concurrent insert of the same address, which is that
        // insert's row and not this caller's business.
        Err(StoreError::NotFound.into())
    }
}

/// A contact who is due to be chased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueContact {
    /// Contact id.
    pub id: Uuid,
    /// The account they work at.
    pub account_id: Uuid,
    /// Their name.
    pub full_name: String,
    /// Lower-case email, if we have one.
    pub email: Option<String>,
    /// E.164 phone, if we have one.
    pub phone: Option<String>,
    /// Which language to write in.
    pub language: Option<String>,
    /// When we last touched them, if we ever did.
    pub last_contacted_at: Option<DateTime<Utc>>,
    /// The follow-up date that has come round.
    pub next_follow_up_at: DateTime<Utc>,
    /// How many touches have actually gone out to this person — see
    /// `0036_contact_touches.sql`. Always below the `max_touches` the caller
    /// asked for, because that is the filter that produced this row.
    pub touch_count: i32,
}

/// Active contacts whose next message is due at or before `as_of`, most overdue
/// first, restricted to those who have had `touches` messages already.
///
/// Suppressed people cannot appear: a suppression deactivates the contact rows
/// it names, and the partial index this reads is `WHERE active`. Neither can
/// somebody who replied — `app::inbound::land` clears `next_follow_up_at` when a
/// contact writes back, and this reads `IS NOT NULL`.
///
/// # Why the range, and why the caller owns both ends
///
/// **Two different questions share this queue**, and they differ only in whether
/// a first message counts.
///
/// * `app::queue`'s CSV export wants everybody with a message due, including
///   somebody the importer scheduled and nobody has ever written to —
///   `0..MAX_TOUCHES`.
/// * `app::vertical::due_chase` wants only people who did not answer, so a first
///   touch is not its work — `1..MAX_TOUCHES`. Without the lower bound it
///   starves: `prospects::import` writes `next_follow_up_at = now` on every row
///   it lands, so the most-overdue end of this queue is 1,615 people nobody has
///   written to, and a bounded scan never reaches the handful who are actually
///   being chased.
///
/// Both ends are the caller's for the same reason: `MAX_TOUCHES` lives in
/// `agentos_app::revenue` beside the `Sequence` that enforces the same rule in
/// memory, and two copies of a limit is how the two come to disagree.
pub async fn contacts_due_for_follow_up(
    tx: &mut TenantTx<'_>,
    as_of: DateTime<Utc>,
    limit: i64,
    touches: std::ops::Range<i64>,
) -> Result<Vec<DueContact>, RevenueError> {
    type Row = (
        Uuid,
        Uuid,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
        i32,
    );

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, account_id, full_name, email, phone, language, last_contacted_at, \
                next_follow_up_at, touch_count \
           FROM contacts \
          WHERE active AND next_follow_up_at IS NOT NULL AND next_follow_up_at <= $1 \
            AND touch_count >= $3 AND touch_count < $4 \
          ORDER BY next_follow_up_at, id \
          LIMIT $2",
    )
    .bind(as_of)
    .bind(limit)
    .bind(touches.start)
    .bind(touches.end)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                account_id,
                full_name,
                email,
                phone,
                language,
                last_contacted_at,
                next_follow_up_at,
                touch_count,
            )| DueContact {
                id,
                account_id,
                full_name,
                email,
                phone,
                language,
                last_contacted_at,
                next_follow_up_at,
                touch_count,
            },
        )
        .collect())
}

/// **They answered. Stop chasing them.**
///
/// Clears `next_follow_up_at` for every active contact with this address, which
/// is what takes them out of [`contacts_due_for_follow_up`] for good. It is
/// `Ended::Replied` made durable, in the only sense anything asks about: the
/// in-memory `Sequence` that knows the reason is rebuilt from nothing every
/// turn, so the reason has nowhere to live and nothing to tell.
///
/// Keyed on the **address** rather than on a contact id because the caller is
/// `app::inbound::land`, and what an inbound email carries is an address. RLS
/// scopes it to the tenant, and `contacts_email_key` is unique per tenant, so
/// this touches at most one row.
///
/// Returns how many rows it stopped, so a caller can log the interesting case
/// and stay silent about the ordinary one — most inbound mail is from somebody
/// nobody is chasing.
///
/// Not a suppression: they replied, they did not opt out. An opt-out is
/// [`suppress`], which deactivates the row by trigger.
pub async fn stop_follow_up(tx: &mut TenantTx<'_>, email: &str) -> Result<u64, RevenueError> {
    Ok(sqlx::query(
        "UPDATE contacts SET next_follow_up_at = NULL, updated_at = now() \
          WHERE email = $1 AND active AND next_follow_up_at IS NOT NULL",
    )
    .bind(email)
    .execute(&mut ***tx)
    .await?
    .rows_affected())
}

/// Move a contact through the follow-up queue: they were touched at
/// `contacted_at`, chase them again at `next_follow_up_at`.
///
/// Refuses an inactive contact — `NotFound`, the same answer as a contact
/// belonging to another tenant, because the caller may do the same thing with
/// both. A contact who has opted out is inactive, and the trigger on the table
/// refuses this write regardless, so there are two locks on the same door.
///
/// **`touch_count` goes up here, and here only.** This statement is what "we
/// have just written to this person" means in this schema, and every path that
/// writes to somebody runs it: the selling turn's first approach, the chase, and
/// `app::queue::record_queued` on the CSV export. Counting in the callers
/// instead would be three counters and a fourth caller that forgets — and the
/// one that forgets is the one that mails a stranger a fourth time. See
/// `0036_contact_touches.sql`.
pub async fn mark_contacted(
    tx: &mut TenantTx<'_>,
    contact_id: Uuid,
    contacted_at: DateTime<Utc>,
    next_follow_up_at: Option<DateTime<Utc>>,
) -> Result<(), RevenueError> {
    let affected = sqlx::query(
        "UPDATE contacts \
            SET last_contacted_at = $2, next_follow_up_at = $3, \
                touch_count = touch_count + 1, updated_at = now() \
          WHERE id = $1 AND active",
    )
    .bind(contact_id)
    .bind(contacted_at)
    .bind(next_follow_up_at)
    .execute(&mut ***tx)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(StoreError::NotFound.into());
    }
    Ok(())
}

/// How many contacts this tenant has added since `since`.
///
/// The number `max_new_contacts_per_day` is compared against. It lives in the
/// policy tables and is enforced by the gate; this is only the count, so that
/// the cap is measured against the database rather than against whatever a
/// process remembers.
pub async fn new_contacts_since(
    tx: &mut TenantTx<'_>,
    since: DateTime<Utc>,
) -> Result<i64, RevenueError> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM contacts WHERE created_at >= $1")
        .bind(since)
        .fetch_one(&mut ***tx)
        .await?;
    Ok(count)
}

/// How many contacts this tenant has **written to** since `since`.
///
/// The twin of [`new_contacts_since`], and it answers a different question: that
/// one counts people added, this one counts people approached. The gate spends
/// `max_new_contacts_per_day` at the moment an email is authorised, which works
/// while sending is what this system does. It is not what it does before
/// 2026-09-01 — `agentos_app::queue` produces a file for a human to upload, and
/// the gate never sees it — so the budget for that path is measured here, off
/// the column [`mark_contacted`] writes.
///
/// ponytail: no index on `last_contacted_at`; this is a count over one tenant's
/// contacts and a sequential scan of a few thousand rows costs less than a
/// fourth index on the table. Add `contacts (tenant_id, last_contacted_at)` if a
/// tenant's list ever reaches six figures.
pub async fn contacted_since(
    tx: &mut TenantTx<'_>,
    since: DateTime<Utc>,
) -> Result<i64, RevenueError> {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM contacts WHERE last_contacted_at >= $1")
            .bind(since)
            .fetch_one(&mut ***tx)
            .await?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A finding about a prospect's own product.
///
/// Every field that makes it reproducible is required, and the table repeats
/// that in NOT NULL constraints: what was checked ([`Self::passport_country`],
/// [`Self::destination_country`]), where ([`Self::source_url`]), when
/// ([`Self::checked_at`]), what their product said
/// ([`Self::observed_claim`]), what the answer actually is
/// ([`Self::correct_claim`]) and how to see it again
/// ([`Self::reproduction`]). There is no constructor that takes a conclusion
/// without its evidence, and once written a row cannot be changed.
#[derive(Debug, Clone, Copy)]
pub struct NewEvidence<'a> {
    /// The prospect this is about.
    pub account_id: Uuid,
    /// The employee who ran the check.
    pub employee_id: Option<EmployeeId>,
    /// `missing_visa_info`, `wrong_requirement`, `stale_rule`,
    /// `missing_transit_visa`, `wrong_passport_validity`,
    /// `wrong_document_list`, `wrong_cost`, `wrong_processing_time`.
    pub kind: &'a str,
    /// Passport country used, ISO 3166-1 alpha-2.
    pub passport_country: &'a str,
    /// Destination country used, ISO 3166-1 alpha-2.
    pub destination_country: &'a str,
    /// Travel date used, when the answer depends on one.
    pub travel_date: Option<NaiveDate>,
    /// The page or endpoint where it was observed.
    pub source_url: &'a str,
    /// How to run the check again, in enough detail that someone at the
    /// prospect can follow it.
    pub reproduction: &'a str,
    /// Screenshot or capture, by reference.
    pub artifact_ref: Option<&'a str>,
    /// What their product said, verbatim. Third-party text.
    pub observed_claim: &'a str,
    /// What the requirement actually is.
    pub correct_claim: &'a str,
    /// The government or IATA page that says so.
    pub authority_url: Option<&'a str>,
    /// When it was observed.
    pub checked_at: DateTime<Utc>,
    /// The subject line this finding came to, when it is one that may be
    /// asserted to the prospect at all.
    ///
    /// `agentos_app::vertical::Approach::new`'s output, and `None` is that
    /// constructor answering `None` — a finding resting on our own row rather
    /// than on the prospect's page is filed and handed to a human. See
    /// `0035_evidence_opener.sql`; the export selects on this column, so the
    /// decision is stored rather than recomputed.
    pub opener_subject: Option<&'a str>,
    /// The body, and it travels with [`Self::opener_subject`] — the table's
    /// `evidence_opener_pair` CHECK refuses one without the other.
    pub opener_body: Option<&'a str>,
}

/// File a finding. Append-only: there is no update and no delete.
pub async fn insert_evidence(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    evidence: &NewEvidence<'_>,
) -> Result<(), RevenueError> {
    sqlx::query(
        "INSERT INTO evidence (id, tenant_id, account_id, employee_id, kind, passport_country, \
                               destination_country, travel_date, source_url, reproduction, \
                               artifact_ref, observed_claim, correct_claim, authority_url, \
                               checked_at, opener_subject, opener_body) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(evidence.account_id)
    .bind(evidence.employee_id.map(|e| e.as_uuid()))
    .bind(evidence.kind)
    .bind(evidence.passport_country)
    .bind(evidence.destination_country)
    .bind(evidence.travel_date)
    .bind(evidence.source_url)
    .bind(evidence.reproduction)
    .bind(evidence.artifact_ref)
    .bind(evidence.observed_claim)
    .bind(evidence.correct_claim)
    .bind(evidence.authority_url)
    .bind(evidence.checked_at)
    .bind(evidence.opener_subject)
    .bind(evidence.opener_body)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// One row of the export, as the tables hold it.
///
/// The raw materials for an `agentos_app::queue::Ready` and nothing more: this
/// crate knows no `Approach` and no `Recipient`, so the mapping — including the
/// evidence bar the types enforce — is `agentos_app::queue::due`'s job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queueable {
    /// The `contacts` row `mark_contacted` will mark.
    pub contact_id: Uuid,
    /// Lower-case, and never NULL here — the query requires one.
    pub email: String,
    /// First and last joined, which is `''` for the `info@` inboxes that are
    /// most of the founder's lists.
    pub full_name: String,
    /// E.164, when the import could store one.
    pub phone: Option<String>,
    /// `accounts.legal_name` — the export's `company_name`.
    pub company_name: String,
    /// `accounts.website`, as the founder's list spells it.
    pub website: Option<String>,
    /// `accounts.location`, verbatim.
    pub location: Option<String>,
    /// The stored opener's subject. Never NULL — the query requires one.
    pub opener_subject: String,
    /// The stored opener's body.
    pub opener_body: String,
    /// `evidence.checked_at`: when the claim in that opener was last known
    /// good.
    pub known_good_at: DateTime<Utc>,
}

/// Everyone who is due, whose account carries a fresh sendable finding, and the
/// opener that finding came to.
///
/// The join `agentos_app::queue` needs and the reason `0035_evidence_opener.sql`
/// exists. Three predicates, and each is somewhere else's rule repeated rather
/// than invented:
///
/// * **due and active** — the same `WHERE` as
///   [`contacts_due_for_follow_up`], including the half a suppression sets
///   (`active = false` *and* `next_follow_up_at = NULL`, in one statement).
/// * **`opener_subject is not null`** — `Approach::new` refused the findings
///   that rest on our own row, and that refusal was stored. See the migration.
/// * **`checked_at >= fresh_since`** — the caller passes
///   `now - MAX_FINDING_AGE`. A claim of the form *"on this date your page did
///   this, here is how to see it again"* that has gone stale is the one mistake
///   in this job that cannot be walked back, so the export applies the same bar
///   `vertical::follow_up` applies to a kept `Approach`.
///
/// Newest finding per account, and one row per contact: an account with three
/// mailboxes yields three rows carrying the same opener, which is
/// [`vertical::follow_up`](agentos_app)'s campaign shape and what the founder's
/// lists actually look like.
///
/// No `WHERE tenant_id`: RLS adds it, and a hand-written filter here would be a
/// second place for it to be forgotten.
///
/// # `FOR UPDATE OF c SKIP LOCKED`, and it is not decoration
///
/// The caller marks every row this returns as contacted and commits, in the
/// transaction this read happens in. Two of those running at once would both
/// read the same due contacts — a plain `SELECT` takes no lock — and the second
/// `mark_contacted` would simply queue behind the first's row lock and then
/// succeed, because the row is still `active`. Same prospect, two files, one
/// cold email sent twice. That is the failure this whole vertical is arranged
/// around, and it costs one clause to remove: the rows are locked as they are
/// read, and a concurrent export skips them rather than waiting for them, which
/// is right — they are already in somebody's file.
///
/// Only `c` is locked. `accounts` and `evidence` are read here and written
/// nowhere on this path, and `evidence` is append-only anyway.
pub async fn queueable(
    tx: &mut TenantTx<'_>,
    as_of: DateTime<Utc>,
    fresh_since: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<Queueable>, RevenueError> {
    type Row = (
        Uuid,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        DateTime<Utc>,
    );

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT c.id, c.email, c.full_name, c.phone, \
                a.legal_name, a.website, a.location, \
                e.opener_subject, e.opener_body, e.checked_at \
           FROM contacts c \
           JOIN accounts a ON a.id = c.account_id \
           JOIN LATERAL ( \
                  SELECT opener_subject, opener_body, checked_at \
                    FROM evidence \
                   WHERE account_id = c.account_id \
                     AND opener_subject IS NOT NULL \
                     AND checked_at >= $2 \
                   ORDER BY checked_at DESC, id \
                   LIMIT 1 \
                ) e ON true \
          WHERE c.active \
            AND c.email IS NOT NULL \
            AND c.next_follow_up_at IS NOT NULL \
            AND c.next_follow_up_at <= $1 \
          ORDER BY c.next_follow_up_at, c.id \
          LIMIT $3 \
            FOR UPDATE OF c SKIP LOCKED",
    )
    .bind(as_of)
    .bind(fresh_since)
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                contact_id,
                email,
                full_name,
                phone,
                company_name,
                website,
                location,
                opener_subject,
                opener_body,
                known_good_at,
            )| Queueable {
                contact_id,
                email,
                full_name,
                phone,
                company_name,
                website,
                location,
                opener_subject,
                opener_body,
                known_good_at,
            },
        )
        .collect())
}

/// Which of these addresses are on a suppression list, global one included.
///
/// The batch twin of `agentos_app::vertical::suppression_for`, and it asks the
/// same question of the same function for the same reason: `suppressions` is
/// under the ordinary per-tenant RLS policy, so a plain `SELECT` over it cannot
/// see a **global** suppression at all. `revenue_suppression_of` is
/// `SECURITY DEFINER` and takes no tenant argument, which is what makes it the
/// only correct reader.
///
/// One round trip rather than one per address, and it **fails loudly** rather
/// than per-address closed: the caller is one transaction that is about to mark
/// forty people contacted, and the right answer to "the suppression list would
/// not answer" there is to export nobody, not to export the rest.
pub async fn suppressed_among(
    tx: &mut TenantTx<'_>,
    addresses: &[String],
) -> Result<Vec<String>, RevenueError> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let found: Vec<String> = sqlx::query_scalar(
        "SELECT a FROM unnest($1::text[]) AS a \
          WHERE revenue_suppression_of(a, null::text) IS NOT NULL",
    )
    .bind(addresses)
    .fetch_all(&mut ***tx)
    .await?;
    Ok(found)
}

/// A stored finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Evidence id.
    pub id: Uuid,
    /// The prospect it is about.
    pub account_id: Uuid,
    /// What kind of error it is.
    pub kind: String,
    /// Passport country checked.
    pub passport_country: String,
    /// Destination country checked.
    pub destination_country: String,
    /// Travel date checked, if any.
    pub travel_date: Option<NaiveDate>,
    /// Where it was observed.
    pub source_url: String,
    /// How to see it again.
    pub reproduction: String,
    /// Screenshot or capture reference.
    pub artifact_ref: Option<String>,
    /// Their text, verbatim. Third-party content — wrap it before it reaches a
    /// model or a template.
    pub observed_claim: String,
    /// What the requirement actually is.
    pub correct_claim: String,
    /// The authority for that.
    pub authority_url: Option<String>,
    /// When it was observed.
    pub checked_at: DateTime<Utc>,
}

/// Findings about one account, newest first.
pub async fn evidence_for_account(
    tx: &mut TenantTx<'_>,
    account_id: Uuid,
    limit: i64,
) -> Result<Vec<Finding>, RevenueError> {
    type Row = (
        Uuid,
        String,
        String,
        String,
        Option<NaiveDate>,
        String,
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        DateTime<Utc>,
    );

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, kind, passport_country, destination_country, travel_date, source_url, \
                reproduction, artifact_ref, observed_claim, correct_claim, authority_url, \
                checked_at \
           FROM evidence \
          WHERE account_id = $1 \
          ORDER BY checked_at DESC, id \
          LIMIT $2",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                kind,
                passport_country,
                destination_country,
                travel_date,
                source_url,
                reproduction,
                artifact_ref,
                observed_claim,
                correct_claim,
                authority_url,
                checked_at,
            )| Finding {
                id,
                account_id,
                kind,
                passport_country,
                destination_country,
                travel_date,
                source_url,
                reproduction,
                artifact_ref,
                observed_claim,
                correct_claim,
                authority_url,
                checked_at,
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// Proof-of-need attempts: the misses, filed next to the hits
// ---------------------------------------------------------------------------

/// One proof-of-need check, whatever it came to.
///
/// [`insert_evidence`] records the checks that produced a finding. This records
/// **all** of them, so "how often does the two-run bar suppress a real finding"
/// is a query over `proof_of_need_suppression` rather than a guess. Same idea as
/// [`Observation::QuoteMissed`](crate::sourcing::Observation::QuoteMissed) one
/// vertical over: a miss nobody wrote down is a miss nobody can argue with.
///
/// No field carries a byte the prospect's page wrote. The classification is
/// ours; the verbatim quote belongs on the evidence row, when there is one.
#[derive(Debug, Clone, Copy)]
pub struct NewAttempt<'a> {
    /// Registrable domain of the prospect, lower case. The key
    /// `accounts.domain` is unique on, and not a foreign key — see the migration.
    pub prospect_domain: &'a str,
    /// The employee that ran the check.
    pub employee_id: Option<EmployeeId>,
    /// `evidence`, `agrees`, `unreadable`, `not_reproducible`, `blocked`,
    /// `truth_stale` or `error`. In `agentos-app` this is `Checked::code()`.
    pub outcome: &'a str,
    /// The sub-reason. Required for `not_reproducible` and `error`, refused for
    /// everything else — the table repeats that in a CHECK, for writers that do
    /// not come through here.
    pub detail: Option<&'a str>,
    /// Passport country used, ISO 3166-1 alpha-2.
    pub passport_country: &'a str,
    /// Destination country used, ISO 3166-1 alpha-2.
    pub destination_country: &'a str,
    /// Travel date used.
    pub travel_date: NaiveDate,
    /// When the check ran.
    pub checked_at: DateTime<Utc>,
}

/// File one attempt. Append-only: `app_role` holds no UPDATE and no DELETE.
pub async fn record_attempt(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    attempt: &NewAttempt<'_>,
) -> Result<(), RevenueError> {
    sqlx::query(
        "INSERT INTO proof_of_need_attempts \
             (id, tenant_id, prospect_domain, employee_id, outcome, detail, passport_country, \
              destination_country, travel_date, checked_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(attempt.prospect_domain)
    .bind(attempt.employee_id.map(|e| e.as_uuid()))
    .bind(attempt.outcome)
    .bind(attempt.detail)
    .bind(attempt.passport_country)
    .bind(attempt.destination_country)
    .bind(attempt.travel_date)
    .bind(attempt.checked_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Opportunities
// ---------------------------------------------------------------------------

/// A deal to open.
#[derive(Debug, Clone, Copy)]
pub struct NewOpportunity {
    /// The prospect.
    pub account_id: Uuid,
    /// The employee working it.
    pub employee_id: Option<EmployeeId>,
    /// The finding that opened it. Optional in the schema; in this vertical it
    /// is the normal case.
    pub evidence_id: Option<Uuid>,
    /// Annual contract value.
    pub value: Money,
    /// When the deal was last touched. Usually "now"; a parameter so a backfill
    /// does not look like a burst of activity.
    pub last_activity_at: DateTime<Utc>,
    /// The agreed next step, if there is one.
    pub next_step_at: Option<DateTime<Utc>>,
    /// Expected close date.
    pub expected_close_on: Option<NaiveDate>,
}

/// Open a deal in the `discovery` stage.
pub async fn insert_opportunity(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    opportunity: &NewOpportunity,
) -> Result<(), RevenueError> {
    sqlx::query(
        "INSERT INTO opportunities (id, tenant_id, account_id, employee_id, evidence_id, \
                                    currency, value_minor, last_activity_at, next_step_at, \
                                    expected_close_on) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(opportunity.account_id)
    .bind(opportunity.employee_id.map(|e| e.as_uuid()))
    .bind(opportunity.evidence_id)
    .bind(opportunity.value.currency().code())
    .bind(minor_of(opportunity.value)?)
    .bind(opportunity.last_activity_at)
    .bind(opportunity.next_step_at)
    .bind(opportunity.expected_close_on)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// Attach the human approval that authorised this deal's commercial terms.
///
/// The only way a deal ever reaches `closed_won`: the table CHECKs for this
/// column on that transition, so an agent that invents a discount to close does
/// not create an obligation, it gets a constraint violation. Pricing, SLAs and
/// coverage promises are `RequireApproval` decisions upstream; this is where the
/// decision lands.
pub async fn attach_approval(
    tx: &mut TenantTx<'_>,
    opportunity_id: Uuid,
    approval_id: Uuid,
) -> Result<(), RevenueError> {
    let affected =
        sqlx::query("UPDATE opportunities SET approval_id = $2, updated_at = now() WHERE id = $1")
            .bind(opportunity_id)
            .bind(approval_id)
            .execute(&mut ***tx)
            .await?
            .rows_affected();

    if affected == 0 {
        return Err(StoreError::NotFound.into());
    }
    Ok(())
}

/// What a prospect pushed back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Objection {
    /// Too expensive.
    Price,
    /// Not enough countries, languages or document types.
    Coverage,
    /// They doubt the data is right.
    Accuracy,
    /// They think they can build it.
    BuildVsBuy,
    /// They already buy this from someone.
    Incumbent,
    /// Not this quarter.
    Timing,
    /// Legal, procurement or security review.
    Legal,
    /// They do not believe they have the problem.
    NoNeed,
}

impl Objection {
    /// As the table stores it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Objection::Price => "price",
            Objection::Coverage => "coverage",
            Objection::Accuracy => "accuracy",
            Objection::BuildVsBuy => "build_vs_buy",
            Objection::Incumbent => "incumbent",
            Objection::Timing => "timing",
            Objection::Legal => "legal",
            Objection::NoNeed => "no_need",
        }
    }
}

/// One thing that happened on a deal.
///
/// Every variant carries what makes it auditable, the same way
/// `sourcing::Observation` does: outreach names the person it went to, a shared
/// finding names the evidence row it is, an objection names what was objected
/// to. The table repeats each rule in a CHECK, for writers that do not come
/// through this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// We contacted them, leading with a finding when there was one.
    OutreachSent {
        /// Who it went to.
        contact_id: Uuid,
        /// The finding it led with.
        evidence_id: Option<Uuid>,
    },
    /// They answered.
    ReplyReceived {
        /// Who answered.
        contact_id: Uuid,
    },
    /// A call took place.
    CallHeld {
        /// Who we spoke to.
        contact_id: Uuid,
    },
    /// A meeting took place.
    MeetingHeld {
        /// Who we met.
        contact_id: Uuid,
    },
    /// A finding was put in front of them.
    EvidenceShared {
        /// Who saw it.
        contact_id: Uuid,
        /// Which finding. Not optional: a claim without its source is a pitch.
        evidence_id: Uuid,
    },
    /// A proposal went out. Commercial terms belong to a human decision; the
    /// approval is on the opportunity.
    ProposalSent {
        /// Who received it.
        contact_id: Uuid,
    },
    /// They pushed back.
    ObjectionRaised {
        /// What they pushed back on.
        objection: Objection,
    },
    /// We answered the objection.
    ObjectionAnswered {
        /// What was answered.
        objection: Objection,
    },
    /// The deal moved. `close_reason` is required by the table when moving to
    /// `closed_lost`, and `closed_won` additionally requires the opportunity to
    /// already carry the approval that authorised its terms.
    StageChanged {
        /// The stage moved to.
        to: &'a str,
        /// Why, when it is a loss.
        close_reason: Option<&'a str>,
    },
    /// They asked not to be contacted. Record it, then call [`suppress`] — this
    /// event is the history, the suppression is the enforcement.
    OptOutReceived {
        /// Who asked.
        contact_id: Uuid,
    },
    /// The follow-up deadline passed with nothing back.
    NoResponse {
        /// Who did not answer.
        contact_id: Uuid,
    },
}

impl<'a> Event<'a> {
    /// `(kind, contact_id, evidence_id, objection, to_stage, close_reason)` as
    /// the table stores them.
    #[allow(clippy::type_complexity)]
    const fn parts(
        self,
    ) -> (
        &'static str,
        Option<Uuid>,
        Option<Uuid>,
        Option<&'static str>,
        Option<&'a str>,
        Option<&'a str>,
    ) {
        match self {
            Event::OutreachSent {
                contact_id,
                evidence_id,
            } => (
                "outreach_sent",
                Some(contact_id),
                evidence_id,
                None,
                None,
                None,
            ),
            Event::ReplyReceived { contact_id } => {
                ("reply_received", Some(contact_id), None, None, None, None)
            }
            Event::CallHeld { contact_id } => {
                ("call_held", Some(contact_id), None, None, None, None)
            }
            Event::MeetingHeld { contact_id } => {
                ("meeting_held", Some(contact_id), None, None, None, None)
            }
            Event::EvidenceShared {
                contact_id,
                evidence_id,
            } => (
                "evidence_shared",
                Some(contact_id),
                Some(evidence_id),
                None,
                None,
                None,
            ),
            Event::ProposalSent { contact_id } => {
                ("proposal_sent", Some(contact_id), None, None, None, None)
            }
            Event::ObjectionRaised { objection } => (
                "objection_raised",
                None,
                None,
                Some(objection.as_str()),
                None,
                None,
            ),
            Event::ObjectionAnswered { objection } => (
                "objection_answered",
                None,
                None,
                Some(objection.as_str()),
                None,
                None,
            ),
            Event::StageChanged { to, close_reason } => {
                ("stage_changed", None, None, None, Some(to), close_reason)
            }
            Event::OptOutReceived { contact_id } => {
                ("opt_out_received", Some(contact_id), None, None, None, None)
            }
            Event::NoResponse { contact_id } => {
                ("no_response", Some(contact_id), None, None, None, None)
            }
        }
    }
}

/// An event to record against a deal.
#[derive(Debug, Clone, Copy)]
pub struct NewEvent<'a> {
    /// The deal it happened on.
    pub opportunity_id: Uuid,
    /// The employee involved.
    pub employee_id: Option<EmployeeId>,
    /// What happened.
    pub event: Event<'a>,
    /// The message it came from or went out as. The prose stays in `messages`,
    /// where it keeps its trust label.
    pub message_id: Option<Uuid>,
    /// When it happened.
    pub occurred_at: DateTime<Utc>,
}

/// Append an event and move the deal's clock, in one statement.
///
/// One statement is the point, exactly as in `sourcing::record_round`: the
/// event, the activity timestamp and the stage transition are a single fact.
/// Writing the event and then updating the opportunity would leave a window in
/// which a deal that was just touched still looks cold — and that window is
/// precisely what [`cold_opportunities`] reports on.
///
/// The `from_stage` written for a [`Event::StageChanged`] is read in the same
/// snapshot as the update, so it is the stage the deal was actually in.
///
/// Returns [`RevenueError::Suppressed`] if the event is an outbound touch
/// against a suppressed or deactivated contact, and `NotFound` if the
/// opportunity does not exist or belongs to another tenant.
pub async fn record_event(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    event: &NewEvent<'_>,
) -> Result<(), RevenueError> {
    let (kind, contact_id, evidence_id, objection, to_stage, close_reason) = event.event.parts();

    let _: (Uuid,) = sqlx::query_as(
        "WITH before AS ( \
             SELECT stage FROM opportunities WHERE id = $3 \
         ), touched AS ( \
             UPDATE opportunities \
                SET stage = coalesce($7::text, stage), \
                    close_reason = coalesce($8::text, close_reason), \
                    closed_at = CASE WHEN $7::text IN ('closed_won', 'closed_lost') \
                                     THEN $9::timestamptz ELSE closed_at END, \
                    last_activity_at = greatest(last_activity_at, $9::timestamptz), \
                    updated_at = now() \
              WHERE id = $3 \
          RETURNING id \
         ) \
         INSERT INTO opportunity_events \
             (id, tenant_id, opportunity_id, contact_id, employee_id, kind, from_stage, \
              to_stage, objection, message_id, evidence_id, occurred_at) \
         SELECT $1, $2, $3, $4::uuid, $5::uuid, $6::text, \
                CASE WHEN $7::text IS NOT NULL THEN before.stage END, $7::text, $10::text, \
                $11::uuid, $12::uuid, $9::timestamptz \
           FROM before, touched \
         RETURNING id",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(event.opportunity_id)
    .bind(contact_id)
    .bind(event.employee_id.map(|e| e.as_uuid()))
    .bind(kind)
    .bind(to_stage)
    .bind(close_reason)
    .bind(event.occurred_at)
    .bind(objection)
    .bind(event.message_id)
    .bind(evidence_id)
    .fetch_one(&mut ***tx)
    .await?;

    Ok(())
}

/// A deal, as the pipeline shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineEntry {
    /// Opportunity id.
    pub id: Uuid,
    /// The prospect.
    pub account_id: Uuid,
    /// Registered name of the prospect.
    pub legal_name: String,
    /// The employee working it.
    pub employee_id: Option<EmployeeId>,
    /// Annual contract value.
    pub value: Money,
    /// The finding that opened it, if there was one.
    pub evidence_id: Option<Uuid>,
    /// When it was last touched.
    pub last_activity_at: DateTime<Utc>,
    /// The agreed next step.
    pub next_step_at: Option<DateTime<Utc>>,
}

/// Open deals in one stage, biggest first.
pub async fn pipeline(
    tx: &mut TenantTx<'_>,
    stage: &str,
) -> Result<Vec<PipelineEntry>, RevenueError> {
    type Row = (
        Uuid,
        Uuid,
        String,
        Option<Uuid>,
        String,
        i64,
        Option<Uuid>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    );

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT o.id, o.account_id, a.legal_name, o.employee_id, o.currency, o.value_minor, \
                o.evidence_id, o.last_activity_at, o.next_step_at \
           FROM opportunities o \
           JOIN accounts a ON a.id = o.account_id \
          WHERE o.stage = $1 \
          ORDER BY o.value_minor DESC, o.id",
    )
    .bind(stage)
    .fetch_all(&mut ***tx)
    .await?;

    rows.into_iter()
        .map(
            |(
                id,
                account_id,
                legal_name,
                employee_id,
                currency,
                value_minor,
                evidence_id,
                last_activity_at,
                next_step_at,
            )| {
                Ok(PipelineEntry {
                    id,
                    account_id,
                    legal_name,
                    employee_id: employee_id.map(EmployeeId::from_uuid),
                    value: money_of(value_minor, &currency)?,
                    evidence_id,
                    last_activity_at,
                    next_step_at,
                })
            },
        )
        .collect()
}

/// A deal that has gone quiet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdOpportunity {
    /// Opportunity id.
    pub id: Uuid,
    /// The prospect.
    pub account_id: Uuid,
    /// The employee working it, if they are still employed.
    pub employee_id: Option<EmployeeId>,
    /// Which stage it went quiet in.
    pub stage: String,
    /// Annual contract value.
    pub value: Money,
    /// The last thing that happened.
    pub last_activity_at: DateTime<Utc>,
    /// The next step that was agreed and did not happen, if there was one.
    pub next_step_at: Option<DateTime<Utc>>,
}

/// Open deals with no activity since `idle_since`, longest-silent first.
///
/// The threshold is a parameter rather than a constant in SQL, so the caller's
/// clock and the caller's definition of "cold" are the ones that decide — and
/// so this is testable without waiting. Closed deals are never cold; they are
/// finished.
pub async fn cold_opportunities(
    tx: &mut TenantTx<'_>,
    idle_since: DateTime<Utc>,
) -> Result<Vec<ColdOpportunity>, RevenueError> {
    type Row = (
        Uuid,
        Uuid,
        Option<Uuid>,
        String,
        String,
        i64,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    );

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, account_id, employee_id, stage, currency, value_minor, last_activity_at, \
                next_step_at \
           FROM opportunities \
          WHERE stage NOT IN ('closed_won', 'closed_lost') AND last_activity_at < $1 \
          ORDER BY last_activity_at, id",
    )
    .bind(idle_since)
    .fetch_all(&mut ***tx)
    .await?;

    rows.into_iter()
        .map(
            |(
                id,
                account_id,
                employee_id,
                stage,
                currency,
                value_minor,
                last_activity_at,
                next_step_at,
            )| {
                Ok(ColdOpportunity {
                    id,
                    account_id,
                    employee_id: employee_id.map(EmployeeId::from_uuid),
                    stage,
                    value: money_of(value_minor, &currency)?,
                    last_activity_at,
                    next_step_at,
                })
            },
        )
        .collect()
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

/// Which address was suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// An email address, lower case.
    Email,
    /// A phone number, E.164.
    Phone,
}

impl Channel {
    /// As the table stores it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Channel::Email => "email",
            Channel::Phone => "phone",
        }
    }
}

/// How far a suppression reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// This tenant must not contact them again.
    Tenant,
    /// **Nobody** must contact them again — the person asked to be removed
    /// entirely. Binds every tenant, and is readable by none of them: the check
    /// happens inside the database.
    Global,
}

impl Scope {
    /// As the table stores it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::Tenant => "tenant",
            Scope::Global => "global",
        }
    }
}

/// An opt-out to record.
#[derive(Debug, Clone, Copy)]
pub struct NewSuppression<'a> {
    /// Email or phone.
    pub channel: Channel,
    /// The address, normalised: lower-case email or E.164 phone. The table has
    /// a CHECK, because a suppression stored in a different shape from the
    /// contact it should match is a suppression that does not fire.
    pub address: &'a str,
    /// `opt_out`, `complaint`, `bounce`, `legal_request`, `do_not_contact`.
    pub reason: &'a str,
    /// Tenant-wide or global.
    pub scope: Scope,
    /// The contact row who asked, when we know which one they were.
    pub contact_id: Option<Uuid>,
    /// The legal record: "replied STOP", a ticket reference, ...
    pub note: Option<&'a str>,
    /// When they asked.
    pub suppressed_at: DateTime<Utc>,
}

/// Record an opt-out.
///
/// Idempotent: recording the same opt-out twice is not an error a caller should
/// have to handle, and an opt-out that errors on the retry is an opt-out that
/// gets dropped by a retrying caller.
///
/// Writing this row also deactivates every matching contact — in this tenant,
/// or in every tenant when [`Scope::Global`] — in the same statement, by
/// trigger. After it returns, that person cannot be added, reactivated, or sent
/// anything.
pub async fn suppress(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    suppression: &NewSuppression<'_>,
) -> Result<(), RevenueError> {
    sqlx::query(
        "INSERT INTO suppressions (id, tenant_id, scope, channel, address, reason, contact_id, \
                                   note, suppressed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT ON CONSTRAINT suppressions_address_key DO NOTHING",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(suppression.scope.as_str())
    .bind(suppression.channel.as_str())
    .bind(suppression.address)
    .bind(suppression.reason)
    .bind(suppression.contact_id)
    .bind(suppression.note)
    .bind(suppression.suppressed_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use agentos_domain::ids::TenantId;
    use chrono::TimeDelta;

    /// Every table the seller vertical adds — `0011_revenue.sql`,
    /// `0015_proof_of_need.sql` and `0032_prospect_flows.sql`. A table that
    /// joins the vertical and not this array is a table whose RLS nobody
    /// checked.
    const REVENUE_TABLES: [&str; 8] = [
        "accounts",
        "contacts",
        "evidence",
        "opportunities",
        "opportunity_events",
        "suppressions",
        "proof_of_need_attempts",
        "prospect_flows",
    ];

    /// Connect and migrate, or `None` when there is no database.
    ///
    /// The thing under test here is Postgres — its RLS engine, its triggers,
    /// its CHECK constraints — so a mock would test nothing. Without
    /// `DATABASE_URL` these skip loudly.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; revenue tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed_tenant(db: &Db, label: &str) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("{label}-{}", tenant.as_uuid()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit seed");
        tenant
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn eur(minor: u64) -> Money {
        Money::new(minor, Currency::Eur).expect("non-zero")
    }

    /// Ids of one fully populated revenue graph.
    struct Graph {
        account: Uuid,
        contact: Uuid,
        evidence: Uuid,
        opportunity: Uuid,
    }

    /// One row in every revenue table. `email` is per-graph so two tenants can
    /// hold the same company without colliding on a globally suppressed
    /// address in tests that do not mean to.
    async fn seed_graph(tx: &mut TenantTx<'_>, now: DateTime<Utc>, email: &str) -> Graph {
        let g = Graph {
            account: Uuid::now_v7(),
            contact: Uuid::now_v7(),
            evidence: Uuid::now_v7(),
            opportunity: Uuid::now_v7(),
        };

        insert_account(
            tx,
            g.account,
            &NewAccount {
                legal_name: "Deutsche Lufthansa AG",
                domain: "lufthansa.com",
                segment: "airline",
                country: "DE",
                employee_id: None,
                location: None,
                website: None,
            },
        )
        .await
        .expect("account");

        insert_contact(
            tx,
            g.contact,
            &NewContact {
                account_id: g.account,
                full_name: "Anke Vogel",
                email: Some(email),
                phone: Some("+4915112345678"),
                role: Some("Head of Digital"),
                language: Some("de"),
                is_primary: true,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: Some(now + TimeDelta::days(3)),
            },
        )
        .await
        .expect("contact");

        insert_evidence(
            tx,
            g.evidence,
            &NewEvidence {
                account_id: g.account,
                employee_id: None,
                kind: "wrong_requirement",
                passport_country: "FR",
                destination_country: "VN",
                travel_date: Some(now.date_naive() + TimeDelta::days(1)),
                source_url: "https://www.lufthansa.com/de/en/flight-search",
                reproduction: "Book CDG->SGN, passenger nationality France, \
                               step 3 shows 'No visa required'.",
                artifact_ref: Some("s3://orizn-evidence/lh-fr-vn.png"),
                observed_claim: "No visa required for this destination.",
                correct_claim: "French passport holders need an e-visa for Vietnam; \
                                the 45-day exemption does not apply to this itinerary.",
                authority_url: Some("https://evisa.gov.vn/"),
                checked_at: now,
                // A `wrong_requirement` rests on our own row, so
                // `Approach::new` refuses it and nothing is stored — see
                // `0035_evidence_opener.sql`. `queueable` has its own test.
                opener_subject: None,
                opener_body: None,
            },
        )
        .await
        .expect("evidence");

        insert_opportunity(
            tx,
            g.opportunity,
            &NewOpportunity {
                account_id: g.account,
                employee_id: None,
                evidence_id: Some(g.evidence),
                value: eur(4_800_000),
                last_activity_at: now,
                next_step_at: Some(now + TimeDelta::days(2)),
                expected_close_on: Some(now.date_naive() + TimeDelta::days(60)),
            },
        )
        .await
        .expect("opportunity");

        record_event(
            tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: g.opportunity,
                employee_id: None,
                event: Event::OutreachSent {
                    contact_id: g.contact,
                    evidence_id: Some(g.evidence),
                },
                message_id: None,
                occurred_at: now,
            },
        )
        .await
        .expect("outreach event");

        g
    }

    // -- tenant isolation ---------------------------------------------------

    /// The premise of every other test: one tenant's revenue data is not merely
    /// filtered out of another tenant's queries, it is invisible to them.
    #[tokio::test]
    async fn every_revenue_table_isolates_tenants() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let a = seed_tenant(&db, "revenue-iso-a").await;
        let b = seed_tenant(&db, "revenue-iso-b").await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now, "anke.iso.a@lufthansa.test").await;
        suppress(
            &mut tx,
            Uuid::now_v7(),
            &NewSuppression {
                channel: Channel::Email,
                address: "gone.iso.a@lufthansa.test",
                reason: "opt_out",
                scope: Scope::Tenant,
                contact_id: None,
                note: None,
                suppressed_at: now,
            },
        )
        .await
        .expect("suppression");
        tx.commit().await.expect("commit graph");

        // Outside the tenant transaction, because `app_role` may not write this
        // table at all — see `set_prospect_flow`. Without a row here the count
        // below would pass on an empty table and prove nothing.
        set_prospect_flow(
            &db,
            a,
            graph.account,
            &NewProspectFlow {
                entry_url: "https://lufthansa.com/entry",
                passport_field: "#passport",
                destination_field: "#destination",
                date_field: None,
                submit: None,
                panel: "#visa-info",
            },
        )
        .await
        .expect("flow");

        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        for table in REVENUE_TABLES {
            let (enabled, forced, policies): (bool, bool, i64) = sqlx::query_as(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                        (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) \
                   FROM pg_class c \
                  WHERE c.relname = $1 AND c.relnamespace = 'public'::regnamespace",
            )
            .bind(table)
            .fetch_one(&mut **tx)
            .await
            .expect("rls introspection");
            assert!(enabled, "{table} must have row level security enabled");
            assert!(forced, "{table} must FORCE row level security");
            assert_eq!(policies, 1, "{table} must carry exactly one policy");

            // Table names come from a const array, not from anything a caller
            // supplies; a bound parameter cannot name a relation.
            let count_sql = format!("SELECT count(*) FROM {table}");
            let visible: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(count_sql))
                .fetch_one(&mut **tx)
                .await
                .expect("count");
            assert_eq!(visible, 0, "tenant B must not see any row in {table}");
        }

        // And the store API agrees, asked by primary key.
        assert!(
            accounts_without_evidence(&mut tx, "airline", 10)
                .await
                .expect("segment")
                .is_empty()
        );
        assert!(
            contacts_due_for_follow_up(&mut tx, now + TimeDelta::days(365), 10, 0..3)
                .await
                .expect("due")
                .is_empty()
        );
        assert!(
            evidence_for_account(&mut tx, graph.account, 10)
                .await
                .expect("evidence")
                .is_empty()
        );
        assert!(
            pipeline(&mut tx, "discovery")
                .await
                .expect("pipeline")
                .is_empty()
        );
        assert!(
            cold_opportunities(&mut tx, now + TimeDelta::days(365))
                .await
                .expect("cold")
                .is_empty()
        );
        assert_eq!(new_contacts_since(&mut tx, now).await.expect("count"), 0);

        // Tenant B may not reach tenant A's rows by pointing at them either:
        // referential integrity is checked by the system and does NOT go
        // through RLS, so the composite keys are what stop it.
        let err = insert_contact(
            &mut tx,
            Uuid::now_v7(),
            &NewContact {
                account_id: graph.account,
                full_name: "Interloper",
                email: Some("interloper@example.test"),
                phone: None,
                role: None,
                language: None,
                is_primary: false,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: None,
            },
        )
        .await
        .expect_err("cross-tenant account reference must fail");
        assert!(
            format!("{err}").contains("contacts_account_fk"),
            "expected the composite fk to reject it, got: {err}"
        );
        tx.rollback().await.expect("rollback");

        // Tenant A still sees its own.
        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        assert_eq!(
            evidence_for_account(&mut tx, graph.account, 10)
                .await
                .expect("evidence")
                .len(),
            1
        );
        assert_eq!(pipeline(&mut tx, "discovery").await.expect("pipe").len(), 1);
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    /// **The application cannot write a selector.**
    ///
    /// This is the grant that makes the whole confirmation bar mean anything.
    /// An employee that could write `prospect_flows` could aim a selector at any
    /// element on a domain its policy already lets it read, sign the row with a
    /// name, and then produce a screenshotted, reproducible finding about
    /// whatever that element happened to say — with the allowlist and the
    /// two-run bar both satisfied, because both are downstream of the selector
    /// being right. So `0032_prospect_flows.sql` revokes INSERT and UPDATE from
    /// `app_role`, and the only writer is an operator with the database
    /// credential.
    ///
    /// Asserted against Postgres rather than against the migration text: a
    /// `grant` somebody adds later has to fail here, and reading the SQL file
    /// would not notice.
    #[tokio::test]
    async fn the_application_role_cannot_write_a_prospects_selectors() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db, "revenue-flow-grants").await;

        // An account and nothing else: `seed_graph` would file evidence against
        // it, and `next_flow_to_probe` is the queue of prospects we have not
        // proved anything about yet.
        let account = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        insert_account(
            &mut tx,
            account,
            &NewAccount {
                legal_name: "Deutsche Lufthansa AG",
                domain: "lufthansa.com",
                segment: "airline",
                country: "DE",
                employee_id: None,
                location: None,
                website: None,
            },
        )
        .await
        .expect("account");
        tx.commit().await.expect("commit account");

        set_prospect_flow(
            &db,
            tenant,
            account,
            &NewProspectFlow {
                entry_url: "https://lufthansa.com/entry",
                passport_field: "#passport",
                destination_field: "#destination",
                date_field: None,
                submit: None,
                panel: "#visa-info",
            },
        )
        .await
        .expect("the operator may write one");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        // Reading is granted: this is how `next_flow_to_probe` works at all.
        assert!(
            next_flow_to_probe(&mut tx, "airline")
                .await
                .expect("read")
                .is_some()
        );

        // Writing is not, in either direction.
        let inserted = sqlx::query(
            "INSERT INTO prospect_flows (account_id, tenant_id, entry_url, passport_field, \
                                         destination_field, panel) \
             VALUES ($1, $2, 'https://lufthansa.com/x', '#a', '#b', '#c')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .execute(&mut **tx)
        .await
        .expect_err("app_role has no INSERT here");
        assert!(
            format!("{inserted}").contains("permission denied"),
            "expected a privilege error, got: {inserted}"
        );
        tx.rollback().await.expect("rollback");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let updated = sqlx::query("UPDATE prospect_flows SET panel = '#anything'")
            .execute(&mut **tx)
            .await
            .expect_err("app_role has no UPDATE here either");
        assert!(
            format!("{updated}").contains("permission denied"),
            "expected a privilege error, got: {updated}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// Two customers may both be prospecting the same airline. Each holds its
    /// own account for it, neither can see the other's, and the uniqueness that
    /// keeps one tenant's data tidy is not a uniqueness across tenants.
    #[tokio::test]
    async fn two_tenants_hold_the_same_company_as_separate_accounts() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let a = seed_tenant(&db, "revenue-same-a").await;
        let b = seed_tenant(&db, "revenue-same-b").await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let theirs = seed_graph(&mut tx, now, "anke.same.a@lufthansa.test").await;
        // The same domain twice in one tenant is a duplicate, and refused.
        let err = insert_account(
            &mut tx,
            Uuid::now_v7(),
            &NewAccount {
                legal_name: "Lufthansa (dup)",
                domain: "lufthansa.com",
                segment: "airline",
                country: "DE",
                employee_id: None,
                location: None,
                website: None,
            },
        )
        .await
        .expect_err("one account per domain per tenant");
        assert!(
            matches!(&err, RevenueError::Store(StoreError::Conflict(c)) if c == "accounts_domain_key"),
            "expected the per-tenant domain key, got {err:?}"
        );
        tx.commit().await.expect("commit a");

        // Tenant B holds the same company, with its own id and its own view.
        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        let mine = seed_graph(&mut tx, now, "anke.same.b@lufthansa.test").await;
        assert_ne!(mine.account, theirs.account);
        let found = accounts_without_evidence(&mut tx, "ota", 10)
            .await
            .expect("segment");
        assert!(found.is_empty(), "wrong segment");
        let pipe = pipeline(&mut tx, "discovery").await.expect("pipeline");
        assert_eq!(pipe.len(), 1, "only tenant B's own deal");
        assert_eq!(pipe[0].id, mine.opportunity);
        assert_eq!(pipe[0].value, eur(4_800_000));
        assert_eq!(pipe[0].legal_name, "Deutsche Lufthansa AG");
        tx.commit().await.expect("commit b");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    // -- suppression --------------------------------------------------------

    /// The table that must never be wrong. An opted-out person cannot be
    /// re-added, cannot be reactivated, and cannot be sent anything — and every
    /// refusal comes from the database, not from a check a future caller could
    /// forget to write.
    ///
    /// A failed statement poisons its transaction, so each attempt gets its own
    /// and the setup is committed once up front.
    #[tokio::test]
    async fn a_suppressed_contact_cannot_be_contacted_again() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "revenue-suppress").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now, "anke.sup@lufthansa.test").await;

        // Before any of that, the follow-up loop works: they are due, chasing
        // them moves the date, and the queue respects the new one.
        let due = contacts_due_for_follow_up(&mut tx, now + TimeDelta::days(4), 10, 0..3)
            .await
            .expect("due");
        assert_eq!(due.len(), 1, "seeded three days out");
        mark_contacted(&mut tx, graph.contact, now, Some(now + TimeDelta::days(7)))
            .await
            .expect("chase");
        assert!(
            contacts_due_for_follow_up(&mut tx, now + TimeDelta::days(4), 10, 0..3)
                .await
                .expect("due")
                .is_empty(),
            "chasing them moved the date out"
        );
        let rescheduled = contacts_due_for_follow_up(&mut tx, now + TimeDelta::days(8), 10, 0..3)
            .await
            .expect("due");
        assert_eq!(rescheduled.len(), 1);
        assert_eq!(rescheduled[0].last_contacted_at, Some(now));

        // They ask to be removed. Email and phone are separate addresses;
        // suppressing either is enough, because it is the person who asked.
        for (channel, address) in [
            (Channel::Email, "anke.sup@lufthansa.test"),
            (Channel::Phone, "+4915112345678"),
        ] {
            suppress(
                &mut tx,
                Uuid::now_v7(),
                &NewSuppression {
                    channel,
                    address,
                    reason: "opt_out",
                    scope: Scope::Tenant,
                    contact_id: Some(graph.contact),
                    note: Some("replied: please remove me"),
                    suppressed_at: now,
                },
            )
            .await
            .expect("suppression");
        }

        // 1. The existing contact was deactivated by the write itself, so they
        //    have already dropped out of the follow-up queue.
        assert!(
            contacts_due_for_follow_up(&mut tx, now + TimeDelta::days(365), 10, 0..3)
                .await
                .expect("due")
                .is_empty(),
            "a suppressed contact must not be due for anything"
        );
        // Nor can they be chased directly: an inactive contact is not there to
        // be marked as contacted.
        let err = mark_contacted(&mut tx, graph.contact, now, Some(now))
            .await
            .expect_err("a suppressed contact cannot be chased");
        assert!(matches!(err, RevenueError::Store(StoreError::NotFound)));

        // 2. Recording the same opt-out twice is a no-op, not an error: one
        //    that fails on retry is one a retrying caller drops.
        suppress(
            &mut tx,
            Uuid::now_v7(),
            &NewSuppression {
                channel: Channel::Phone,
                address: "+4915112345678",
                reason: "do_not_contact",
                scope: Scope::Tenant,
                contact_id: None,
                note: None,
                suppressed_at: now,
            },
        )
        .await
        .expect("re-recording an opt-out must be idempotent");

        // 3. Recording that they opted out is still possible: the suppression
        //    stops us contacting them, not us remembering that they asked.
        record_event(
            &mut tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: graph.opportunity,
                employee_id: None,
                event: Event::OptOutReceived {
                    contact_id: graph.contact,
                },
                message_id: None,
                occurred_at: now + TimeDelta::hours(1),
            },
        )
        .await
        .expect("recording the opt-out itself must stay possible");

        // A second airline, for the "cannot be re-added anywhere" case below.
        let second_account = Uuid::now_v7();
        insert_account(
            &mut tx,
            second_account,
            &NewAccount {
                legal_name: "Eurowings GmbH",
                domain: "eurowings.com",
                segment: "airline",
                country: "DE",
                employee_id: None,
                location: None,
                website: None,
            },
        )
        .await
        .expect("account");
        tx.commit().await.expect("commit setup");

        // 4. They cannot be added again — not under a new id, not at another
        //    account.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = insert_contact(
            &mut tx,
            Uuid::now_v7(),
            &NewContact {
                account_id: second_account,
                full_name: "Anke Vogel",
                email: Some("anke.sup@lufthansa.test"),
                phone: None,
                role: None,
                language: Some("de"),
                is_primary: false,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: Some(now),
            },
        )
        .await
        .expect_err("a suppressed address must not be insertable as a target");
        assert!(
            matches!(err, RevenueError::Suppressed(_)),
            "expected the suppression trigger to fire, got {err:?}"
        );
        tx.rollback().await.expect("rollback");

        // 5. Nor reactivated in place.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = sqlx::query("UPDATE contacts SET active = true WHERE id = $1")
            .bind(graph.contact)
            .execute(&mut **tx)
            .await
            .expect_err("a suppressed contact must not be reactivated");
        assert_eq!(
            err.as_database_error().and_then(|e| e.code()).as_deref(),
            Some(SQLSTATE_SUPPRESSED)
        );
        tx.rollback().await.expect("rollback");

        // 6. And no outbound touch can be recorded against them, on any
        //    channel, however the caller reaches the table.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = record_event(
            &mut tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: graph.opportunity,
                employee_id: None,
                event: Event::OutreachSent {
                    contact_id: graph.contact,
                    evidence_id: Some(graph.evidence),
                },
                message_id: None,
                occurred_at: now + TimeDelta::hours(2),
            },
        )
        .await
        .expect_err("outreach to a suppressed contact must fail");
        assert!(
            matches!(err, RevenueError::Suppressed(_)),
            "expected the suppression trigger to fire, got {err:?}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// A person who asked to be removed entirely is removed from every tenant —
    /// including tenants that cannot see the suppression, and tenants that did
    /// not exist when it was recorded. Enforcement without disclosure: one
    /// customer's opt-out list is not another customer's lead list.
    #[tokio::test]
    async fn a_global_suppression_binds_every_tenant() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let a = seed_tenant(&db, "revenue-global-a").await;
        let b = seed_tenant(&db, "revenue-global-b").await;
        // A distinct address per run: the row outlives the tenants, by design.
        let address = format!("removed-{}@lufthansa.test", Uuid::now_v7());

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now, &address).await;
        // They first opt out of this tenant's outreach, then ask to be removed
        // everywhere. The second request must not vanish into the first: the
        // table takes no UPDATEs, so `scope` is part of the key and the
        // escalation is a new row rather than a discarded duplicate.
        for scope in [Scope::Tenant, Scope::Global] {
            suppress(
                &mut tx,
                Uuid::now_v7(),
                &NewSuppression {
                    channel: Channel::Email,
                    address: &address,
                    reason: "legal_request",
                    scope,
                    contact_id: Some(graph.contact),
                    note: Some("art. 21 objection, remove everywhere"),
                    suppressed_at: now,
                },
            )
            .await
            .expect("suppression");
        }
        let recorded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM suppressions WHERE address = $1 AND scope = 'global'",
        )
        .bind(&address)
        .fetch_one(&mut **tx)
        .await
        .expect("count");
        assert_eq!(recorded, 1, "the escalation to global was recorded");
        tx.commit().await.expect("commit a");

        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        // Tenant B cannot read the suppression...
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM suppressions")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(visible, 0, "a global opt-out must not leak across tenants");

        // ...and is bound by it anyway.
        let account = Uuid::now_v7();
        insert_account(
            &mut tx,
            account,
            &NewAccount {
                legal_name: "Deutsche Lufthansa AG",
                domain: "lufthansa.com",
                segment: "airline",
                country: "DE",
                employee_id: None,
                location: None,
                website: None,
            },
        )
        .await
        .expect("account");
        let err = insert_contact(
            &mut tx,
            Uuid::now_v7(),
            &NewContact {
                account_id: account,
                full_name: "Anke Vogel",
                email: Some(&address),
                phone: None,
                role: None,
                language: None,
                is_primary: true,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: None,
            },
        )
        .await
        .expect_err("a global opt-out binds a tenant that cannot see it");
        assert!(
            matches!(err, RevenueError::Suppressed(_)),
            "expected the suppression trigger to fire, got {err:?}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    /// The batch lookup the export hands to `agentos_app::queue::plan`, and the
    /// property that makes it worth having: it sees a **global** suppression,
    /// which the per-tenant RLS policy hides from an ordinary `SELECT` over
    /// this table.
    ///
    /// This is tested here rather than through the route because the route
    /// cannot make it bite: recording an opt-out deactivates the contact rows it
    /// names, so a suppressed person never reaches the queue at all. That is the
    /// database being the lock and this being the third one — which is the shape
    /// you want a legal boundary in, and it is also why a test that only asserts
    /// "the address is not in the file" would pass with this call deleted. What
    /// this asserts is that the value handed to `plan` is a real list and not an
    /// empty one.
    #[tokio::test]
    async fn the_export_lookup_sees_a_suppression_the_table_hides() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let a = seed_tenant(&db, "revenue-among-a").await;
        let b = seed_tenant(&db, "revenue-among-b").await;
        let stopped = format!("stopped-{}@example.test", Uuid::now_v7());
        let fine = format!("fine-{}@example.test", Uuid::now_v7());

        // Recorded by A, globally.
        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        suppress(
            &mut tx,
            Uuid::now_v7(),
            &NewSuppression {
                channel: Channel::Email,
                address: &stopped,
                reason: "legal_request",
                scope: Scope::Global,
                contact_id: None,
                note: None,
                suppressed_at: now,
            },
        )
        .await
        .expect("suppression");
        tx.commit().await.expect("commit");

        // Read by B, which cannot see the row and is bound by it anyway.
        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM suppressions")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(visible, 0, "a global opt-out must not leak across tenants");

        let found = suppressed_among(&mut tx, &[stopped.clone(), fine.clone()])
            .await
            .expect("lookup");
        assert_eq!(
            found,
            vec![stopped],
            "the export's suppression list must carry the opted-out address and \
             only it"
        );

        // And an empty batch is one fewer round trip, not one more.
        assert!(
            suppressed_among(&mut tx, &[])
                .await
                .expect("lookup")
                .is_empty(),
            "an empty export asks the suppression list nothing"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    // -- evidence -----------------------------------------------------------

    /// A finding that can be edited after it was sent is not evidence, and an
    /// opt-out that can be edited away is not an opt-out. Both halves of the
    /// guarantee, for both tables: the trigger, which binds even the owner, and
    /// the privileges, which the application actually runs under.
    #[tokio::test]
    async fn evidence_and_suppressions_cannot_be_updated_or_deleted() {
        let Some(db) = db().await else { return };

        // Neither table has a foreign key to `tenants` — that is the point, an
        // opt-out outlives the tenant that recorded it — so these rows need no
        // tenant to exist, and no tenant deletion can take them away.
        const SEED: [(&str, &str); 2] = [
            (
                "evidence",
                "INSERT INTO evidence (id, tenant_id, account_id, kind, passport_country, \
                                       destination_country, source_url, reproduction, \
                                       observed_claim, correct_claim, checked_at) \
                 VALUES ($1, $2, $2, 'stale_rule', 'FR', 'VN', 'https://x.test', \
                         'search CDG->SGN', 'no visa required', 'e-visa required', now())",
            ),
            (
                "suppressions",
                "INSERT INTO suppressions (id, tenant_id, channel, address, reason) \
                 VALUES ($1, $2, 'email', 'gone@example.test', 'opt_out')",
            ),
        ];

        for (table, seed) in SEED {
            // `WHERE tenant_id = $1`, though the transaction is rolled back and
            // the statement is expected to fail before it touches anything: the
            // trigger is `for each row`, so the row it fires on is the one this
            // loop just seeded either way, and an unscoped `DELETE` in a test is
            // a line somebody copies into a test that is not rolled back.
            // `crates/app/tests/scoped_deletes.rs` is what stops that.
            for op in [
                "UPDATE {} SET tenant_id = tenant_id WHERE tenant_id = $1",
                "DELETE FROM {} WHERE tenant_id = $1",
            ] {
                // Whole thing in one rolled-back transaction, as `postgres`:
                // the trigger has to bind the owner too, because a GRANT never
                // does. Table names come from a const array here, not from a
                // caller; a bound parameter cannot name a relation.
                let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
                let tenant = Uuid::now_v7();
                sqlx::query(sqlx::AssertSqlSafe(seed.to_owned()))
                    .bind(Uuid::now_v7())
                    .bind(tenant)
                    .execute(&mut *tx)
                    .await
                    .expect("seed row");

                let statement = op.replace("{}", table);
                let err = sqlx::query(sqlx::AssertSqlSafe(statement.clone()))
                    .bind(tenant)
                    .execute(&mut *tx)
                    .await
                    .expect_err("append-only");
                assert!(
                    err.to_string().contains("append-only"),
                    "expected the append-only trigger for `{statement}`, got: {err}"
                );
                tx.rollback().await.expect("rollback");
            }
        }

        // ... and the app role cannot even attempt it: no privilege to revoke a
        // trigger's way around.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        for table in ["evidence", "suppressions"] {
            for verb in ["UPDATE", "DELETE"] {
                let granted: bool =
                    sqlx::query_scalar("SELECT has_table_privilege('app_role', $1, $2)")
                        .bind(table)
                        .bind(verb)
                        .fetch_one(&mut *tx)
                        .await
                        .expect("privilege");
                assert!(!granted, "app_role must not hold {verb} on {table}");
            }
            let granted: bool =
                sqlx::query_scalar("SELECT has_table_privilege('app_role', $1, 'INSERT')")
                    .bind(table)
                    .fetch_one(&mut *tx)
                    .await
                    .expect("privilege");
            assert!(granted, "app_role must be able to append to {table}");
        }
        tx.rollback().await.expect("rollback");
    }

    /// What a finding has to carry to be one at all: the pair that was checked,
    /// where, when, what their product said, what the answer is, and how to see
    /// it again. A row missing any of that is not stored, so it can never be
    /// sent.
    #[tokio::test]
    async fn a_finding_that_cannot_be_reproduced_cannot_be_stored() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "revenue-evidence").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now, "anke.ev@lufthansa.test").await;

        let found = evidence_for_account(&mut tx, graph.account, 10)
            .await
            .expect("evidence");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, graph.evidence);
        assert_eq!(found[0].passport_country, "FR");
        assert_eq!(found[0].destination_country, "VN");
        assert_eq!(
            found[0].observed_claim,
            "No visa required for this destination."
        );
        assert!(found[0].reproduction.contains("CDG->SGN"));
        assert_eq!(found[0].checked_at, now);

        // Bypassing `NewEvidence` reaches the NOT NULL that says the same
        // thing: no reproduction, no finding.
        let err = sqlx::query(
            "INSERT INTO evidence (id, tenant_id, account_id, kind, passport_country, \
                                   destination_country, source_url, observed_claim, \
                                   correct_claim, checked_at) \
             VALUES ($1, $2, $3, 'stale_rule', 'FR', 'VN', 'https://x.test', 'a', 'b', now())",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(graph.account)
        .execute(&mut **tx)
        .await
        .expect_err("a finding with no reproduction must be refused");
        assert!(
            format!("{err}").contains("reproduction"),
            "expected the NOT NULL on reproduction, got: {err}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    /// The queue the pipeline starts from: prospects in a segment that nobody
    /// has proved anything about yet. An account stops appearing the moment it
    /// has one finding, which is what stops two employees checking the same
    /// airline twice.
    #[tokio::test]
    async fn the_segment_queue_skips_accounts_that_already_have_evidence() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "revenue-queue").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        // seed_graph's airline already has a finding.
        seed_graph(&mut tx, now, "anke.q@lufthansa.test").await;

        let unchecked = Uuid::now_v7();
        let disqualified = Uuid::now_v7();
        let ota = Uuid::now_v7();
        for (id, name, domain, segment) in [
            (unchecked, "Air France", "airfrance.fr", "airline"),
            (disqualified, "Tiny Charter", "tinycharter.test", "airline"),
            (ota, "Bookings BV", "bookings.test", "ota"),
        ] {
            insert_account(
                &mut tx,
                id,
                &NewAccount {
                    legal_name: name,
                    domain,
                    segment,
                    country: "FR",
                    employee_id: None,
                    location: None,
                    website: None,
                },
            )
            .await
            .expect("account");
        }
        sqlx::query("UPDATE accounts SET state = 'disqualified' WHERE id = $1")
            .bind(disqualified)
            .execute(&mut **tx)
            .await
            .expect("disqualify");

        let queue = accounts_without_evidence(&mut tx, "airline", 10)
            .await
            .expect("queue");
        assert_eq!(
            queue.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![unchecked],
            "only the unchecked, still-open airline"
        );
        assert_eq!(queue[0].legal_name, "Air France");

        // File a finding against it and it leaves the queue.
        insert_evidence(
            &mut tx,
            Uuid::now_v7(),
            &NewEvidence {
                account_id: unchecked,
                employee_id: None,
                kind: "missing_transit_visa",
                passport_country: "IN",
                destination_country: "US",
                travel_date: None,
                source_url: "https://wwws.airfrance.fr/booking",
                reproduction: "Search BOM->YYZ via CDG, Indian passport: no US transit \
                               visa warning at any step.",
                artifact_ref: None,
                observed_claim: "No documents required beyond a valid passport.",
                correct_claim: "An Indian national transiting the US needs a C-1 transit visa.",
                authority_url: Some("https://travel.state.gov/"),
                checked_at: now,
                opener_subject: None,
                opener_body: None,
            },
        )
        .await
        .expect("evidence");
        assert!(
            accounts_without_evidence(&mut tx, "airline", 10)
                .await
                .expect("queue")
                .is_empty()
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    // -- cold deals ---------------------------------------------------------

    /// The sweep finds the deal that went quiet, and only that one: not the one
    /// that was touched this morning, and not the one that is closed. Recording
    /// an event moves the clock in the same statement, so a deal that was just
    /// touched can never be reported as cold.
    #[tokio::test]
    async fn the_cold_sweep_finds_a_stalled_deal() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let cutoff = now - TimeDelta::days(14);
        let tenant = seed_tenant(&db, "revenue-cold").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now, "anke.cold@lufthansa.test").await;

        // Two more deals on two more prospects: one silent for a month, one
        // that will be closed.
        let stalled = Uuid::now_v7();
        let closed = Uuid::now_v7();
        for (opp, name, domain, last_activity) in [
            (
                stalled,
                "Expedia Group",
                "expedia.test",
                now - TimeDelta::days(30),
            ),
            (closed, "Navan Inc", "navan.test", now - TimeDelta::days(40)),
        ] {
            let account = Uuid::now_v7();
            insert_account(
                &mut tx,
                account,
                &NewAccount {
                    legal_name: name,
                    domain,
                    segment: "ota",
                    country: "US",
                    employee_id: None,
                    location: None,
                    website: None,
                },
            )
            .await
            .expect("account");
            insert_opportunity(
                &mut tx,
                opp,
                &NewOpportunity {
                    account_id: account,
                    employee_id: None,
                    evidence_id: None,
                    value: eur(1_200_000),
                    last_activity_at: last_activity,
                    next_step_at: None,
                    expected_close_on: None,
                },
            )
            .await
            .expect("opportunity");
        }

        // Both are cold right now; the fresh one is not.
        let cold = cold_opportunities(&mut tx, cutoff).await.expect("sweep");
        assert_eq!(
            cold.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![closed, stalled],
            "longest-silent first, and the deal touched today is not in it"
        );

        // Closing one takes it out of the sweep — a finished deal is not cold.
        // `closed_won` would need the approval that authorised its terms; this
        // one is simply lost, and says why.
        record_event(
            &mut tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: closed,
                employee_id: None,
                event: Event::StageChanged {
                    to: "closed_lost",
                    close_reason: Some("went with incumbent"),
                },
                message_id: None,
                occurred_at: now,
            },
        )
        .await
        .expect("close");

        let cold = cold_opportunities(&mut tx, cutoff).await.expect("sweep");
        assert_eq!(cold.len(), 1, "only the stalled deal");
        assert_eq!(cold[0].id, stalled);
        assert_eq!(cold[0].stage, "discovery");
        assert_eq!(cold[0].value, eur(1_200_000));
        assert_eq!(cold[0].last_activity_at, now - TimeDelta::days(30));

        // Touching the stalled deal moves its clock, in the same statement that
        // records the touch.
        record_event(
            &mut tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: stalled,
                employee_id: None,
                event: Event::ObjectionRaised {
                    objection: Objection::BuildVsBuy,
                },
                message_id: None,
                occurred_at: now,
            },
        )
        .await
        .expect("objection");
        assert!(
            cold_opportunities(&mut tx, cutoff)
                .await
                .expect("sweep")
                .is_empty(),
            "a deal touched today is not cold"
        );

        // The stage transition recorded where it came from, in the same
        // snapshot as the update.
        let (from_stage, to_stage): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT from_stage, to_stage FROM opportunity_events \
              WHERE opportunity_id = $1 AND kind = 'stage_changed'",
        )
        .bind(closed)
        .fetch_one(&mut **tx)
        .await
        .expect("stage event");
        assert_eq!(from_stage.as_deref(), Some("discovery"));
        assert_eq!(to_stage.as_deref(), Some("closed_lost"));

        // A deal is won once a human has approved its terms, and only then.
        attach_approval(&mut tx, graph.opportunity, Uuid::now_v7())
            .await
            .expect("approval");
        record_event(
            &mut tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: graph.opportunity,
                employee_id: None,
                event: Event::StageChanged {
                    to: "closed_won",
                    close_reason: None,
                },
                message_id: None,
                occurred_at: now,
            },
        )
        .await
        .expect("close won");
        assert!(
            pipeline(&mut tx, "discovery")
                .await
                .expect("pipeline")
                .iter()
                .all(|o| o.id != graph.opportunity)
        );

        // Without that approval it is refused: an agent that invents a discount
        // to close would have created an obligation, and instead gets a
        // constraint violation. This one goes last — a failed statement poisons
        // the transaction.
        let err = record_event(
            &mut tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: stalled,
                employee_id: None,
                event: Event::StageChanged {
                    to: "closed_won",
                    close_reason: None,
                },
                message_id: None,
                occurred_at: now,
            },
        )
        .await
        .expect_err("closing won without an approval must fail");
        assert!(
            format!("{err}").contains("opportunities_won_needs_approval"),
            "expected the approval CHECK, got: {err}"
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// An event against a deal this tenant cannot see is NotFound, not an
    /// orphan row: the CTEs match nothing and the INSERT has nothing to select
    /// from.
    #[tokio::test]
    async fn an_event_against_an_unknown_deal_is_not_found() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "revenue-notfound").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = record_event(
            &mut tx,
            Uuid::now_v7(),
            &NewEvent {
                opportunity_id: Uuid::now_v7(),
                employee_id: None,
                event: Event::ObjectionRaised {
                    objection: Objection::Price,
                },
                message_id: None,
                occurred_at: now,
            },
        )
        .await
        .expect_err("unknown opportunity");
        assert!(
            matches!(err, RevenueError::Store(StoreError::NotFound)),
            "expected NotFound, got {err:?}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }
}
