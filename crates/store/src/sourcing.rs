//! Persistence for the buyer vertical: suppliers, RFQs, quotes, negotiations,
//! purchase orders, shipments.
//!
//! The schema is in `migrations/0007_sourcing.sql` and carries most of the
//! rules; this module is the thin, typed way to reach it. Three things are
//! worth knowing before reading further.
//!
//! **No query in this file filters on `tenant_id`.** Not one. Every function
//! takes a [`TenantTx`], which has already set `app.tenant_id`, so the row-level
//! security policies do the filtering. A `WHERE tenant_id = $n` here would be a
//! second, weaker copy of a rule the database already enforces — and the day
//! someone forgets to write it, the policy is still there.
//!
//! **Money is [`Money`] on the way in and on the way out**, never a bare
//! integer: minor units plus a currency, converted at the boundary. A quote's
//! currency is pinned to its RFQ's currency by a composite foreign key, which
//! is what makes [`live_quotes`]' ordering meaningful — comparing landed prices
//! across currencies is not a ranking.
//!
//! **Reputation is not stored.** [`record_observation`] writes evidence, each
//! row tied to the RFQ or purchase order it happened on, and [`reputation`]
//! reads an aggregate view over that evidence. There is no reputation column to
//! set, so there is no way to assert a supplier is reliable without a record of
//! them being reliable. [`reputation`] returns `None` for a supplier with no
//! observations, because "no data" is an answer and `0%` is a different one.
//!
//! The responsiveness half of that evidence — `quote_returned` and
//! `quote_missed` — has exactly one writer, [`close_expired_rounds`], and it
//! writes both at the same moment for the same reason: an RFQ round is the only
//! event that produces a signal for every supplier it touched, and it produces
//! it when the round ends rather than when an answer lands. Recording the
//! answers as they arrive and the silences separately would be two clocks, and
//! the silences would be the clock nobody wound.
//!
//! ponytail: ids are plain [`Uuid`] here rather than domain newtypes. The
//! sourcing id types live in the domain crate's own unit; when they land, these
//! signatures take them and nothing else changes. Writes for
//! `supplier_contacts` and `shipments` are likewise absent — the tables, their
//! constraints and their indexes exist, and the units that own contact
//! discovery and logistics ingest can add the six-line insert they need.

use agentos_domain::ids::EmployeeId;
use agentos_domain::money::{Currency, Money, MoneyError};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a sourcing read or write failed.
#[derive(Debug, thiserror::Error)]
pub enum SourcingError {
    /// The database said no. Includes `NotFound` for a row that does not exist
    /// *or* belongs to another tenant — RLS makes those indistinguishable, on
    /// purpose.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// An amount that does not fit a Postgres `bigint`, in either direction.
    #[error("amount does not fit in a bigint")]
    AmountOutOfRange,

    /// A currency mismatch, a zero amount, or a stored currency code this
    /// system does not know.
    #[error(transparent)]
    Money(#[from] MoneyError),
}

impl From<sqlx::Error> for SourcingError {
    // Routed through StoreError so 23505 / 40001 / RowNotFound keep their
    // meaning instead of collapsing into one opaque driver error.
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

/// `Money` -> `bigint`.
fn minor_of(amount: Money) -> Result<i64, SourcingError> {
    i64::try_from(amount.minor()).map_err(|_| SourcingError::AmountOutOfRange)
}

/// An optional add-on cost, which must be in the same currency as the line it
/// is added to. Absent means zero, the one place a zero amount is legitimate:
/// `Money` cannot represent it, and "no freight charge" is not a payment.
fn addon_minor(amount: Option<Money>, expected: Currency) -> Result<i64, SourcingError> {
    match amount {
        None => Ok(0),
        Some(a) if a.currency() == expected => minor_of(a),
        Some(a) => Err(MoneyError::CurrencyMismatch {
            left: expected,
            right: a.currency(),
        }
        .into()),
    }
}

/// `bigint` + currency code -> `Money`.
fn money_of(minor: i64, code: &str) -> Result<Money, SourcingError> {
    let minor = u64::try_from(minor).map_err(|_| SourcingError::AmountOutOfRange)?;
    Ok(Money::new(minor, code.parse::<Currency>()?)?)
}

// ---------------------------------------------------------------------------
// Suppliers
// ---------------------------------------------------------------------------

/// A supplier to create.
#[derive(Debug, Clone, Copy)]
pub struct NewSupplier<'a> {
    /// Registered name, as it will appear on a purchase order.
    pub legal_name: &'a str,
    /// ISO 3166-1 alpha-2, upper case.
    pub country: &'a str,
    /// Product categories this supplier sells; the buyer's search key.
    pub categories: &'a [String],
    /// Optional homepage.
    pub website: Option<&'a str>,
}

/// Create a supplier in the `candidate` state.
pub async fn insert_supplier(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    supplier: &NewSupplier<'_>,
) -> Result<(), SourcingError> {
    sqlx::query(
        "INSERT INTO suppliers (id, tenant_id, legal_name, country, categories, website) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(supplier.legal_name)
    .bind(supplier.country)
    .bind(supplier.categories)
    .bind(supplier.website)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// What a supplier search returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplierSummary {
    /// Supplier id.
    pub id: Uuid,
    /// Registered name.
    pub legal_name: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
    /// Every category this supplier sells, not just the one searched for.
    pub categories: Vec<String>,
    /// `candidate` or `active`; suspended and blocked suppliers never appear.
    pub state: String,
}

/// Suppliers that sell one category, optionally narrowed to one country,
/// name-ordered.
///
/// Suspended and blocked suppliers are excluded here rather than by the caller:
/// a blocked supplier that shows up in a search is a blocked supplier someone
/// will eventually send an RFQ to.
///
/// `country` is the **supplier's** country and it is optional because half the
/// callers do not have one. A buying objective states where the goods must
/// *arrive* (`rolepack::Objective::delivery_country`) and says nothing about
/// where they come from — an international buyer that searched only the
/// delivery country would be a domestic buyer. `None` therefore means "any
/// origin", and the category predicate still rides `suppliers_categories_idx`,
/// the GIN index, so dropping the country narrows the plan rather than
/// widening it to a scan.
pub async fn find_suppliers(
    tx: &mut TenantTx<'_>,
    country: Option<&str>,
    category: &str,
) -> Result<Vec<SupplierSummary>, SourcingError> {
    let rows: Vec<(Uuid, String, String, Vec<String>, String)> = sqlx::query_as(
        "SELECT id, legal_name, country, categories, state \
           FROM suppliers \
          WHERE ($1::text IS NULL OR country = $1) \
            AND categories @> array[$2::text] \
            AND state IN ('candidate', 'active') \
          ORDER BY legal_name, id",
    )
    .bind(country)
    .bind(category)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, legal_name, country, categories, state)| SupplierSummary {
                id,
                legal_name,
                country,
                categories,
                state,
            },
        )
        .collect())
}

/// One contact at a supplier that could be written to.
///
/// `email` is the column as stored, not a parsed address: `supplier_contacts`
/// has no `CHECK` on the shape of it, and a store that returned only the rows
/// it could parse would silently drop a supplier whose address has a typo. The
/// caller parses, and reports what will not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplierContact {
    /// Which supplier this human works for.
    pub supplier_id: Uuid,
    /// Their name, for the operator reading a report about them.
    pub full_name: String,
    /// The address, as stored.
    pub email: String,
    /// Whether they are the designated contact. At most one active contact per
    /// supplier can be — `supplier_contacts_primary_key`.
    pub is_primary: bool,
    /// Why this address must not be written to, if it must not: `opt_out`,
    /// `complaint`, `bounce`, `legal_request`, `do_not_contact`.
    ///
    /// **Returned rather than filtered.** A suppressed contact is not the same
    /// as an absent one — one is a firm that asked us to stop and the other is
    /// a supplier nobody ever recorded an address for — and only the caller can
    /// report the difference.
    pub suppressed: Option<String>,
}

/// The emailable contacts for these suppliers, **best first within each
/// supplier**, each carrying its suppression status.
///
/// One query for the whole shortlist rather than one per supplier: an RFQ round
/// is tens of suppliers, and `= ANY($1)` over
/// `supplier_contacts_supplier_idx` is one round trip where a loop is tens.
///
/// The order is `(supplier_id, is_primary DESC, full_name, id)` and every key
/// is a column, so the first row for a supplier is the same row on every
/// replica and on every replay. That matters because the caller writes to the
/// first one and only the first one — see `app::sourcing::recipients`.
///
/// # Two layers of "do not write to this person", both already here
///
/// `active = false` is the row-level one — somebody left the company, or the
/// row is stale — and it is applied in the `WHERE`. A supplier whose every
/// contact is deactivated comes back with no rows at all, which the caller
/// reports rather than skips.
///
/// The address-level one is `suppressions` from `0011_revenue.sql`, read
/// through `revenue_suppression_of`. That function is `security definer` for a
/// reason worth knowing: a `scope = 'global'` opt-out binds every tenant and is
/// readable by none of them, so the check has to happen inside the database. Its
/// `revenue_` prefix names the migration it was born in, not the vertical it
/// governs — the table has no vertical column, and a supplier who says "stop
/// emailing me" has said the same sentence as a prospect who does. **Do not add
/// a purchasing suppression list beside it**: a second place for that sentence
/// to have been recorded is the same as not having recorded it.
///
/// `lower(email)` because `suppressions_address_normalised` stores addresses
/// folded, and the check between the two is an equality test.
pub async fn supplier_contacts(
    tx: &mut TenantTx<'_>,
    supplier_ids: &[Uuid],
) -> Result<Vec<SupplierContact>, SourcingError> {
    let rows: Vec<(Uuid, String, String, bool, Option<String>)> = sqlx::query_as(
        "SELECT c.supplier_id, c.full_name, c.email, c.is_primary, \
                revenue_suppression_of(lower(c.email), NULL) \
           FROM supplier_contacts c \
          WHERE c.supplier_id = ANY($1) \
            AND c.active \
            AND c.email IS NOT NULL \
          ORDER BY c.supplier_id, c.is_primary DESC, c.full_name, c.id",
    )
    .bind(supplier_ids)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(supplier_id, full_name, email, is_primary, suppressed)| SupplierContact {
                supplier_id,
                full_name,
                email,
                is_primary,
                suppressed,
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// RFQs
// ---------------------------------------------------------------------------

/// A request for quotation to create.
#[derive(Debug, Clone, Copy)]
pub struct NewRfq<'a> {
    /// The employee running this sourcing round.
    pub employee_id: Option<EmployeeId>,
    /// Human-readable summary.
    pub title: &'a str,
    /// The category matched against [`NewSupplier::categories`].
    pub product_category: &'a str,
    /// How many, in `unit`.
    pub quantity: i64,
    /// `pcs`, `kg`, `m`, ... A quantity without a unit is a number two parties
    /// read differently.
    pub unit: &'a str,
    /// Incoterm requested, if the buyer is dictating one.
    pub incoterm: Option<&'a str>,
    /// ISO 3166-1 alpha-2 delivery destination.
    pub destination_country: &'a str,
    /// Every quote against this RFQ must be denominated in this currency.
    pub currency: Currency,
    /// Optional target unit price, in `currency`.
    pub target_unit_price: Option<Money>,
    /// When the RFQ stops accepting quotes.
    pub closes_at: Option<DateTime<Utc>>,
}

/// Create an RFQ in the `open` state.
pub async fn insert_rfq(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    rfq: &NewRfq<'_>,
) -> Result<(), SourcingError> {
    let target = match rfq.target_unit_price {
        None => None,
        Some(a) if a.currency() == rfq.currency => Some(minor_of(a)?),
        Some(a) => {
            return Err(MoneyError::CurrencyMismatch {
                left: rfq.currency,
                right: a.currency(),
            }
            .into());
        }
    };

    sqlx::query(
        "INSERT INTO rfqs (id, tenant_id, employee_id, title, product_category, quantity, unit, \
                           incoterm, destination_country, currency, target_unit_price_minor, \
                           closes_at, state) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'open')",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(rfq.employee_id.map(|e| e.as_uuid()))
    .bind(rfq.title)
    .bind(rfq.product_category)
    .bind(rfq.quantity)
    .bind(rfq.unit)
    .bind(rfq.incoterm)
    .bind(rfq.destination_country)
    .bind(rfq.currency.code())
    .bind(target)
    .bind(rfq.closes_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// The round an employee already has running, as the buyer needs to read it
/// back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRfq {
    /// RFQ id — the key [`live_quotes`] takes.
    pub id: Uuid,
    /// How many units were asked for.
    pub quantity: i64,
    /// The one currency every quote against it is denominated in.
    pub currency: Currency,
    /// The Incoterm the RFQ dictated, if it dictated one. A quote that names
    /// no term of its own was answering on this one.
    pub incoterm: Option<String>,
}

/// The open RFQ this employee is running, most recent first.
///
/// **This is what stops an RFQ going out twice.** A sourcing round stores no
/// cursor and no workflow row — see `app::vertical` — so the only thing that
/// distinguishes "nobody has been asked yet" from "we asked on Tuesday and
/// nobody has answered" is whether an open `rfqs` row exists. The buyer reads
/// this before deciding, and an employee that has one is past asking.
///
/// One row, not all of them: an employee runs one objective, and the plan
/// `RolePack::plan` recomputes is that objective's. A second open round for the
/// same employee is an operator having re-chartered mid-round, and the newest
/// is the one the current objective belongs to.
pub async fn open_rfq(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
) -> Result<Option<OpenRfq>, SourcingError> {
    let row: Option<(Uuid, i64, String, Option<String>)> = sqlx::query_as(
        "SELECT id, quantity, currency, incoterm \
           FROM rfqs \
          WHERE employee_id = $1 AND state = 'open' \
          ORDER BY created_at DESC, id DESC \
          LIMIT 1",
    )
    .bind(employee_id.as_uuid())
    .fetch_optional(&mut ***tx)
    .await?;

    let Some((id, quantity, currency, incoterm)) = row else {
        return Ok(None);
    };
    Ok(Some(OpenRfq {
        id,
        quantity,
        currency: currency.parse::<Currency>()?,
        incoterm,
    }))
}

/// Write down which suppliers an RFQ actually went to.
///
/// **The one fact about a round that cannot be recomputed later.**
/// [`find_suppliers`] is a live query — a supplier added, deactivated,
/// re-categorised or newly suppressed after the letter went out changes its
/// answer — so "who did we ask" either gets written at the moment of asking or
/// it is gone. It was never written, and that is the whole reason
/// `quote_missed` had no writer: [`close_expired_rounds`] subtracts the answers
/// from the recipients, and with no recipients there is nothing to subtract
/// from.
///
/// # Why `negotiations` and not a table of its own
///
/// Because that table already *is* this fact. `unique (tenant_id, rfq_id,
/// supplier_id)` is one row per supplier per RFQ; `reply_due_at` is, in the
/// migration's own words, "when the party we are waiting on owes us an answer";
/// and `negotiations_awaiting_reply_idx` is a partial index on exactly that
/// predicate. A negotiation needs no quote to exist — `quote_id` is nullable
/// and `round_count` defaults to zero — because being owed a first answer is
/// the state the row starts in. A new `rfq_recipients` table would have been
/// the same three columns, a second RLS block and a second set of grants.
///
/// # Matching addresses back to suppliers
///
/// The caller holds `EmailAddress`es, because everything from
/// `app::sourcing::recipients` down through `shortlist` is keyed by address.
/// [`EmailAddress`](agentos_domain::action::EmailAddress) lower-cases what it
/// parses and `supplier_contacts.email` is free text, so the join is on
/// `lower(email)` — the same folding [`supplier_contacts`] already uses for its
/// suppression check.
///
/// `DISTINCT`, because one supplier with two contact rows on the same address
/// was still asked once. Two *different* suppliers sharing an address were both
/// asked by the one letter, and both get a row: that is what happened.
pub async fn record_rfq_recipients(
    tx: &mut TenantTx<'_>,
    rfq_id: Uuid,
    employee_id: Option<EmployeeId>,
    addresses: &[String],
    reply_due_at: DateTime<Utc>,
) -> Result<usize, SourcingError> {
    let folded: Vec<String> = addresses
        .iter()
        .map(|address| address.to_ascii_lowercase())
        .collect();

    let supplier_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT c.supplier_id \
           FROM supplier_contacts c \
          WHERE c.active AND lower(c.email) = ANY($1)",
    )
    .bind(&folded)
    .fetch_all(&mut ***tx)
    .await?;

    for supplier_id in &supplier_ids {
        open_negotiation(
            tx,
            Uuid::now_v7(),
            rfq_id,
            *supplier_id,
            None,
            employee_id,
            reply_due_at,
        )
        .await?;
    }
    Ok(supplier_ids.len())
}

/// What closing one round came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedRound {
    /// The round that ended.
    pub rfq_id: Uuid,
    /// Recipients who answered it, at any point before it was swept.
    pub quotes_returned: usize,
    /// Recipients who never did.
    pub quotes_missed: usize,
}

/// End every round of `employee_id`'s that is past its own deadline, and file
/// the responsiveness evidence for it.
///
/// # When is a round over
///
/// At `rfqs.closes_at`, which the schema has always carried and nothing has
/// ever read. Not at the first answer, not when a human orders, not after some
/// count of cadences: the RFQ told the supplier when quoting shut, and that
/// sentence is the only deadline both sides agreed on.
///
/// **Silence is measured when the round is swept, not at the deadline.** A
/// supplier who answers on day 9 of an 8-day window has answered; recording
/// them as silent would be exactly the wrong number the evidence log exists to
/// prevent, and the reputation that is supposed to say "asking them buys no
/// quote" would say it about a firm that quoted. So the question this asks per
/// recipient is `EXISTS (a quote from them on this RFQ)` and never
/// `received_at <= closes_at`. Their answer was late, which is a thing about
/// this round; it is not silence, which is a thing about the supplier.
///
/// # Idempotence
///
/// The state flip is first and is the guard: `state = 'open'` is in the
/// `WHERE`, so a second pass over the same round updates no rows, returns no
/// ids and writes no observations. Both statements are the caller's one
/// transaction, so a crash between them files nothing and leaves the round
/// open for the next cadence. Concurrent turns for one employee serialise on
/// the `rfqs` row lock and the loser re-evaluates the qual and finds `closed`.
///
/// A round with no `closes_at` is never swept. "No deadline" is not "over".
///
/// # This is also what un-strands the employee
///
/// `app::vertical` reads an open `rfqs` row as "we have asked and are waiting",
/// and nothing ever cleared it — so an employee whose RFQ nobody answered
/// waited for that answer forever, every cadence, with no way back to
/// `Stage::Rfq`. Closing the round is what returns them to a fresh one, which
/// is why this runs at the top of a purchasing turn rather than in a sweep of
/// its own.
///
// ponytail: the round's `negotiations` rows keep whatever state they have.
// Nothing reads `negotiations_awaiting_reply` yet; the unit that builds the
// stalled-negotiation sweep gets to decide there whether a supplier who
// answered is `awaiting_buyer` or the thread is `abandoned`, and inventing that
// answer here to satisfy a reader that does not exist is a guess in a state
// column.
pub async fn close_expired_rounds(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    now: DateTime<Utc>,
) -> Result<Vec<ClosedRound>, SourcingError> {
    let closed: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE rfqs \
            SET state = 'closed', updated_at = now() \
          WHERE employee_id = $1 \
            AND state = 'open' \
            AND closes_at IS NOT NULL \
            AND closes_at <= $2 \
      RETURNING id",
    )
    .bind(employee_id.as_uuid())
    .bind(now)
    .fetch_all(&mut ***tx)
    .await?;

    let mut rounds = Vec::with_capacity(closed.len());
    for rfq_id in closed {
        // One row per recipient, saying whether anything ever came back. The
        // set is `negotiations`, not `quotes`: a supplier who never answered
        // has no quote row to be found by, which is the whole difficulty.
        let recipients: Vec<(Uuid, bool)> = sqlx::query_as(
            "SELECT n.supplier_id, \
                    EXISTS (SELECT 1 FROM quotes q \
                             WHERE q.rfq_id = n.rfq_id AND q.supplier_id = n.supplier_id) \
               FROM negotiations n \
              WHERE n.rfq_id = $1 \
              ORDER BY n.supplier_id",
        )
        .bind(rfq_id)
        .fetch_all(&mut ***tx)
        .await?;

        let mut round = ClosedRound {
            rfq_id,
            quotes_returned: 0,
            quotes_missed: 0,
        };
        for (supplier_id, answered) in recipients {
            let observation = if answered {
                round.quotes_returned += 1;
                Observation::QuoteReturned { rfq_id }
            } else {
                round.quotes_missed += 1;
                Observation::QuoteMissed { rfq_id }
            };
            record_observation(tx, Uuid::now_v7(), supplier_id, observation, now).await?;
        }
        rounds.push(round);
    }
    Ok(rounds)
}

// ---------------------------------------------------------------------------
// Quotes
// ---------------------------------------------------------------------------

/// A supplier's quote against an RFQ.
///
/// Every amount is in the same currency, and that currency must be the RFQ's;
/// the composite foreign key in the migration rejects anything else.
#[derive(Debug, Clone, Copy)]
pub struct NewQuote<'a> {
    /// The RFQ being answered.
    pub rfq_id: Uuid,
    /// Who is quoting.
    pub supplier_id: Uuid,
    /// Price for one `unit` of the RFQ.
    pub unit_price: Money,
    /// How many units this price is good for.
    pub quantity: i64,
    /// Freight, if quoted separately.
    pub freight: Option<Money>,
    /// Import duties, if quoted separately.
    pub duties: Option<Money>,
    /// Anything else the supplier itemised.
    pub other_fees: Option<Money>,
    /// Quoted lead time.
    pub lead_time_days: Option<i32>,
    /// Incoterm the price is quoted on.
    pub incoterm: Option<&'a str>,
    /// When the quote stops being a promise. Not optional: a quote without an
    /// expiry is a price nobody committed to.
    pub valid_until: DateTime<Utc>,
}

/// Record a received quote.
pub async fn insert_quote(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    quote: &NewQuote<'_>,
) -> Result<(), SourcingError> {
    let currency = quote.unit_price.currency();

    sqlx::query(
        "INSERT INTO quotes (id, tenant_id, rfq_id, supplier_id, currency, unit_price_minor, \
                             quantity, freight_minor, duties_minor, other_fees_minor, \
                             lead_time_days, incoterm, valid_until) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(quote.rfq_id)
    .bind(quote.supplier_id)
    .bind(currency.code())
    .bind(minor_of(quote.unit_price)?)
    .bind(quote.quantity)
    .bind(addon_minor(quote.freight, currency)?)
    .bind(addon_minor(quote.duties, currency)?)
    .bind(addon_minor(quote.other_fees, currency)?)
    .bind(quote.lead_time_days)
    .bind(quote.incoterm)
    .bind(quote.valid_until)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// One comparable quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveQuote {
    /// Quote id.
    pub id: Uuid,
    /// Who quoted.
    pub supplier_id: Uuid,
    /// Price for one unit.
    pub unit_price: Money,
    /// Units quoted for.
    pub quantity: i64,
    /// `unit_price * quantity + freight + duties + other fees`, computed by the
    /// database from the columns beside it so it cannot drift from them.
    pub landed_total: Money,
    /// Quoted lead time.
    pub lead_time_days: Option<i32>,
    /// The Incoterm this price is quoted on, if the supplier named one.
    ///
    /// Returned rather than assumed, because it is the one field that decides
    /// how much of the landed cost is *not* in the quoted price. A caller that
    /// defaulted every quote to the RFQ's term would compare an EXW price
    /// against a DDP price and pick the wrong supplier — see
    /// `app::sourcing::landed_cost`. `None` really is "they did not say", and
    /// the RFQ's own term is the honest fallback for that.
    pub incoterm: Option<String>,
    /// When the quote arrived. The opening edge of its validity window: the
    /// closing one is `valid_until` and the column pair is what
    /// `domain::sourcing::Quote::live_at` is checked against.
    pub received_at: DateTime<Utc>,
    /// When this stops being a live quote.
    pub valid_until: DateTime<Utc>,
}

/// Quotes for one RFQ that are still standing at `as_of`, cheapest landed
/// total first.
///
/// Excludes withdrawn, rejected and expired quotes. The expiry cutoff is a
/// parameter rather than `now()` so the caller's clock is the one that decides
/// — and so this is testable without waiting.
pub async fn live_quotes(
    tx: &mut TenantTx<'_>,
    rfq_id: Uuid,
    as_of: DateTime<Utc>,
) -> Result<Vec<LiveQuote>, SourcingError> {
    type Row = (
        Uuid,
        Uuid,
        String,
        i64,
        i64,
        i64,
        Option<i32>,
        Option<String>,
        DateTime<Utc>,
        DateTime<Utc>,
    );

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, supplier_id, currency, unit_price_minor, quantity, landed_total_minor, \
                lead_time_days, incoterm, received_at, valid_until \
           FROM quotes \
          WHERE rfq_id = $1 AND state = 'received' AND valid_until > $2 \
          ORDER BY landed_total_minor, id",
    )
    .bind(rfq_id)
    .bind(as_of)
    .fetch_all(&mut ***tx)
    .await?;

    rows.into_iter()
        .map(
            |(
                id,
                supplier_id,
                currency,
                unit_minor,
                quantity,
                landed,
                lead_time_days,
                incoterm,
                received_at,
                valid_until,
            )| {
                Ok(LiveQuote {
                    id,
                    supplier_id,
                    unit_price: money_of(unit_minor, &currency)?,
                    quantity,
                    landed_total: money_of(landed, &currency)?,
                    lead_time_days,
                    incoterm,
                    received_at,
                    valid_until,
                })
            },
        )
        .collect()
}

// ---------------------------------------------------------------------------
// Negotiations
// ---------------------------------------------------------------------------

/// Who spoke in a negotiation round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    /// Us.
    Buyer,
    /// Them.
    Supplier,
}

impl Party {
    const fn as_str(self) -> &'static str {
        match self {
            Party::Buyer => "buyer",
            Party::Supplier => "supplier",
        }
    }

    /// After this party speaks, we are waiting on the other one.
    const fn awaiting_state(self) -> &'static str {
        match self {
            Party::Buyer => "awaiting_supplier",
            Party::Supplier => "awaiting_buyer",
        }
    }
}

/// Open a negotiation thread with one supplier over one RFQ.
///
/// `reply_due_at` is not optional. A negotiation with no deadline is one that
/// goes quiet and is never noticed; the table has a CHECK saying the same
/// thing, and [`negotiations_awaiting_reply`] is what notices.
pub async fn open_negotiation(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    rfq_id: Uuid,
    supplier_id: Uuid,
    quote_id: Option<Uuid>,
    employee_id: Option<EmployeeId>,
    reply_due_at: DateTime<Utc>,
) -> Result<(), SourcingError> {
    sqlx::query(
        "INSERT INTO negotiations \
             (id, tenant_id, rfq_id, supplier_id, quote_id, employee_id, state, reply_due_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'awaiting_supplier', $7)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(rfq_id)
    .bind(supplier_id)
    .bind(quote_id)
    .bind(employee_id.map(|e| e.as_uuid()))
    .bind(reply_due_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// One exchange in a negotiation: the structured residue of a message.
///
/// The prose itself stays in `messages`, where it keeps its trust label. What
/// lands here is only what was offered.
#[derive(Debug, Clone, Copy)]
pub struct NewRound<'a> {
    /// The thread this belongs to.
    pub negotiation_id: Uuid,
    /// Who spoke.
    pub party: Party,
    /// The message this was extracted from, if there was one.
    pub message_id: Option<Uuid>,
    /// Price offered or asked, per unit.
    pub unit_price: Option<Money>,
    /// Quantity the offer is for.
    pub quantity: Option<i64>,
    /// Lead time offered.
    pub lead_time_days: Option<i32>,
    /// Incoterm offered.
    pub incoterm: Option<&'a str>,
    /// When it happened.
    pub occurred_at: DateTime<Utc>,
    /// When the *other* party now owes an answer.
    pub reply_due_at: DateTime<Utc>,
}

/// Append a round and move the negotiation's clock, in one statement.
///
/// One statement is the point: the round, the round counter, the state flip and
/// the new deadline are a single fact. Writing the round and then updating the
/// negotiation would leave a window in which a supplier has replied but we are
/// still counted as waiting on them — and that window is exactly what
/// [`negotiations_awaiting_reply`] reports on.
///
/// The round number is assigned by the database from the negotiation's own
/// counter, so two concurrent writers cannot both mint round 3: the second
/// blocks on the first's row lock and gets 4. Returns it.
pub async fn record_round(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    round: &NewRound<'_>,
) -> Result<i32, SourcingError> {
    let (currency, unit_minor) = match round.unit_price {
        Some(price) => (Some(price.currency().code()), Some(minor_of(price)?)),
        None => (None, None),
    };

    let (round_no,): (i32,) = sqlx::query_as(
        "WITH advanced AS ( \
             UPDATE negotiations \
                SET round_count = round_count + 1, \
                    last_round_at = $9, \
                    state = $10, \
                    reply_due_at = $11, \
                    updated_at = now() \
              WHERE id = $3 \
          RETURNING round_count \
         ) \
         INSERT INTO negotiation_rounds \
             (id, tenant_id, negotiation_id, round_no, party, message_id, currency, \
              unit_price_minor, quantity, lead_time_days, incoterm, occurred_at) \
         SELECT $1, $2, $3, advanced.round_count, $4, $5, $6, $7, $8, $12, $13, $9 \
           FROM advanced \
         RETURNING round_no",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(round.negotiation_id)
    .bind(round.party.as_str())
    .bind(round.message_id)
    .bind(currency)
    .bind(unit_minor)
    .bind(round.quantity)
    .bind(round.occurred_at)
    .bind(round.party.awaiting_state())
    .bind(round.reply_due_at)
    .bind(round.lead_time_days)
    .bind(round.incoterm)
    .fetch_one(&mut ***tx)
    .await?;

    Ok(round_no)
}

/// A negotiation where the supplier owes us an answer and is late.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalledNegotiation {
    /// Negotiation id.
    pub id: Uuid,
    /// The RFQ under negotiation.
    pub rfq_id: Uuid,
    /// The supplier who has gone quiet.
    pub supplier_id: Uuid,
    /// The employee running it, if they are still employed.
    pub employee_id: Option<EmployeeId>,
    /// The deadline that has passed.
    pub reply_due_at: DateTime<Utc>,
    /// When we last heard anything, if we ever did.
    pub last_round_at: Option<DateTime<Utc>>,
    /// Rounds exchanged so far.
    pub round_count: i32,
}

/// Negotiations whose supplier reply was due before `as_of`, most overdue
/// first.
///
/// Served by a partial index on `(tenant_id, reply_due_at) WHERE state =
/// 'awaiting_supplier'`, so this stays a small range scan no matter how many
/// concluded negotiations pile up behind it.
pub async fn negotiations_awaiting_reply(
    tx: &mut TenantTx<'_>,
    as_of: DateTime<Utc>,
) -> Result<Vec<StalledNegotiation>, SourcingError> {
    type Row = (
        Uuid,
        Uuid,
        Uuid,
        Option<Uuid>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        i32,
    );

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, rfq_id, supplier_id, employee_id, reply_due_at, last_round_at, round_count \
           FROM negotiations \
          WHERE state = 'awaiting_supplier' AND reply_due_at < $1 \
          ORDER BY reply_due_at, id",
    )
    .bind(as_of)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, rfq_id, supplier_id, employee_id, reply_due_at, last_round_at, round_count)| {
                StalledNegotiation {
                    id,
                    rfq_id,
                    supplier_id,
                    employee_id: employee_id.map(EmployeeId::from_uuid),
                    reply_due_at,
                    last_round_at,
                    round_count,
                }
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// Purchase orders
// ---------------------------------------------------------------------------

/// A purchase order to issue.
#[derive(Debug, Clone, Copy)]
pub struct NewPurchaseOrder<'a> {
    /// Buyer-facing PO number; unique per tenant.
    pub po_number: &'a str,
    /// Who we are buying from.
    pub supplier_id: Uuid,
    /// The RFQ this came out of, if any.
    pub rfq_id: Option<Uuid>,
    /// The quote being accepted, if any.
    pub quote_id: Option<Uuid>,
    /// The employee issuing it.
    pub employee_id: Option<EmployeeId>,
    /// The human approval that authorised the spend. `None` only when the
    /// amount was under the auto-approval threshold.
    pub approval_id: Option<Uuid>,
    /// Agreed unit price.
    pub unit_price: Money,
    /// Units ordered.
    pub quantity: i64,
    /// Agreed freight, if separate.
    pub freight: Option<Money>,
    /// Agreed duties, if separate.
    pub duties: Option<Money>,
    /// Incoterm agreed.
    pub incoterm: Option<&'a str>,
    /// When it was sent to the supplier.
    pub issued_at: DateTime<Utc>,
}

/// Record an issued purchase order and return its total.
pub async fn insert_purchase_order(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    po: &NewPurchaseOrder<'_>,
) -> Result<Money, SourcingError> {
    let currency = po.unit_price.currency();

    let (total,): (i64,) = sqlx::query_as(
        "INSERT INTO purchase_orders \
             (id, tenant_id, po_number, supplier_id, rfq_id, quote_id, employee_id, approval_id, \
              currency, unit_price_minor, quantity, freight_minor, duties_minor, incoterm, \
              state, issued_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'issued', $15) \
         RETURNING total_minor",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(po.po_number)
    .bind(po.supplier_id)
    .bind(po.rfq_id)
    .bind(po.quote_id)
    .bind(po.employee_id.map(|e| e.as_uuid()))
    .bind(po.approval_id)
    .bind(currency.code())
    .bind(minor_of(po.unit_price)?)
    .bind(po.quantity)
    .bind(addon_minor(po.freight, currency)?)
    .bind(addon_minor(po.duties, currency)?)
    .bind(po.incoterm)
    .bind(po.issued_at)
    .fetch_one(&mut ***tx)
    .await?;

    money_of(total, currency.code())
}

// ---------------------------------------------------------------------------
// Reputation: evidence in, aggregate out
// ---------------------------------------------------------------------------

/// One thing that actually happened with a supplier.
///
/// Every variant carries the row that proves it. There is no
/// `Observation::Good`, and no constructor that takes a score — a reputation
/// nobody can assert is a reputation nobody can inflate. The table repeats the
/// rule in a CHECK, for writers that do not come through this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// They answered an RFQ.
    QuoteReturned {
        /// The RFQ they answered.
        rfq_id: Uuid,
    },
    /// They ignored an RFQ.
    QuoteMissed {
        /// The RFQ they ignored.
        rfq_id: Uuid,
    },
    /// Goods arrived by the agreed date.
    DeliveryOnTime {
        /// The order that arrived.
        purchase_order_id: Uuid,
    },
    /// Goods arrived late.
    DeliveryLate {
        /// The order that was late.
        purchase_order_id: Uuid,
    },
    /// Goods passed inspection.
    QualityAccepted {
        /// The order inspected.
        purchase_order_id: Uuid,
    },
    /// Goods failed inspection.
    QualityRejected {
        /// The order inspected.
        purchase_order_id: Uuid,
    },
    /// A commercial dispute was raised.
    Dispute {
        /// The order disputed.
        purchase_order_id: Uuid,
    },
}

impl Observation {
    /// `(kind, rfq_id, purchase_order_id)` as the table stores them.
    const fn parts(self) -> (&'static str, Option<Uuid>, Option<Uuid>) {
        match self {
            Observation::QuoteReturned { rfq_id } => ("quote_returned", Some(rfq_id), None),
            Observation::QuoteMissed { rfq_id } => ("quote_missed", Some(rfq_id), None),
            Observation::DeliveryOnTime { purchase_order_id } => {
                ("delivery_on_time", None, Some(purchase_order_id))
            }
            Observation::DeliveryLate { purchase_order_id } => {
                ("delivery_late", None, Some(purchase_order_id))
            }
            Observation::QualityAccepted { purchase_order_id } => {
                ("quality_accepted", None, Some(purchase_order_id))
            }
            Observation::QualityRejected { purchase_order_id } => {
                ("quality_rejected", None, Some(purchase_order_id))
            }
            Observation::Dispute { purchase_order_id } => {
                ("dispute", None, Some(purchase_order_id))
            }
        }
    }
}

/// File one piece of evidence about a supplier.
pub async fn record_observation(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    supplier_id: Uuid,
    observation: Observation,
    observed_at: DateTime<Utc>,
) -> Result<(), SourcingError> {
    let (kind, rfq_id, purchase_order_id) = observation.parts();

    sqlx::query(
        "INSERT INTO supplier_observations \
             (id, tenant_id, supplier_id, kind, rfq_id, purchase_order_id, observed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(tx.tenant_id().as_uuid())
    .bind(supplier_id)
    .bind(kind)
    .bind(rfq_id)
    .bind(purchase_order_id)
    .bind(observed_at)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// A supplier's record, recomputed from its observations on every read.
///
/// The rates are whole-number percentages and are `None` where the denominator
/// is zero. No float ever enters a supplier's score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reputation {
    /// Who this is about.
    pub supplier_id: Uuid,
    /// How many observations back it. Never zero: see [`reputation`].
    pub observation_count: i64,
    /// RFQs answered.
    pub quotes_returned: i64,
    /// RFQs ignored.
    pub quotes_missed: i64,
    /// Deliveries on time.
    pub delivered_on_time: i64,
    /// Deliveries late.
    pub delivered_late: i64,
    /// Inspections passed.
    pub quality_accepted: i64,
    /// Inspections failed.
    pub quality_rejected: i64,
    /// Disputes raised.
    pub disputes: i64,
    /// On-time deliveries as a percentage of deliveries.
    pub on_time_rate_pct: Option<i32>,
    /// RFQs answered as a percentage of RFQs sent.
    pub response_rate_pct: Option<i32>,
    /// Inspections passed as a percentage of inspections.
    pub quality_rate_pct: Option<i32>,
    /// The most recent observation.
    pub last_observed_at: DateTime<Utc>,
}

/// Read a supplier's reputation, or `None` if nothing has been observed.
///
/// `None` is the honest answer for a supplier with no history, and it is one a
/// stored column defaulting to zero could never give: it would say "0% on
/// time", which is a claim, not an absence.
pub async fn reputation(
    tx: &mut TenantTx<'_>,
    supplier_id: Uuid,
) -> Result<Option<Reputation>, SourcingError> {
    type Row = (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        Option<i32>,
        Option<i32>,
        Option<i32>,
        DateTime<Utc>,
    );

    let row: Option<Row> = sqlx::query_as(
        "SELECT observation_count, quotes_returned, quotes_missed, delivered_on_time, \
                delivered_late, quality_accepted, quality_rejected, disputes, \
                on_time_rate_pct, response_rate_pct, quality_rate_pct, last_observed_at \
           FROM supplier_reputation \
          WHERE supplier_id = $1",
    )
    .bind(supplier_id)
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row.map(
        |(
            observation_count,
            quotes_returned,
            quotes_missed,
            delivered_on_time,
            delivered_late,
            quality_accepted,
            quality_rejected,
            disputes,
            on_time_rate_pct,
            response_rate_pct,
            quality_rate_pct,
            last_observed_at,
        )| Reputation {
            supplier_id,
            observation_count,
            quotes_returned,
            quotes_missed,
            delivered_on_time,
            delivered_late,
            quality_accepted,
            quality_rejected,
            disputes,
            on_time_rate_pct,
            response_rate_pct,
            quality_rate_pct,
            last_observed_at,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use agentos_domain::ids::TenantId;
    use chrono::TimeDelta;

    /// Every table `0007_sourcing.sql` adds.
    const SOURCING_TABLES: [&str; 9] = [
        "suppliers",
        "supplier_contacts",
        "rfqs",
        "quotes",
        "negotiations",
        "negotiation_rounds",
        "purchase_orders",
        "shipments",
        "supplier_observations",
    ];

    /// Connect and migrate, or `None` when there is no database.
    ///
    /// The thing under test here is Postgres — its RLS engine, its CHECK
    /// constraints, its generated columns — so a mock would test nothing.
    /// Without `DATABASE_URL` these skip loudly.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; sourcing tests need a real Postgres");
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

    fn usd(minor: u64) -> Money {
        Money::new(minor, Currency::Usd).expect("non-zero")
    }

    /// Ids of one fully populated sourcing graph.
    struct Graph {
        supplier: Uuid,
        rfq: Uuid,
        quote: Uuid,
        negotiation: Uuid,
        purchase_order: Uuid,
    }

    /// One row in every sourcing table, written through the public API where
    /// there is one and raw SQL where there is not.
    async fn seed_graph(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Graph {
        let g = Graph {
            supplier: Uuid::now_v7(),
            rfq: Uuid::now_v7(),
            quote: Uuid::now_v7(),
            negotiation: Uuid::now_v7(),
            purchase_order: Uuid::now_v7(),
        };

        insert_supplier(
            tx,
            g.supplier,
            &NewSupplier {
                legal_name: "Shenzhen Fasteners Ltd",
                country: "CN",
                categories: &["fasteners".to_owned(), "hardware".to_owned()],
                website: None,
            },
        )
        .await
        .expect("supplier");

        sqlx::query(
            "INSERT INTO supplier_contacts (id, tenant_id, supplier_id, full_name, email, is_primary) \
             VALUES ($1, $2, $3, 'Wei Zhang', 'wei@example.test', true)",
        )
        .bind(Uuid::now_v7())
        .bind(tx.tenant_id().as_uuid())
        .bind(g.supplier)
        .execute(&mut ***tx)
        .await
        .expect("contact");

        insert_rfq(
            tx,
            g.rfq,
            &NewRfq {
                employee_id: None,
                title: "M6 bolts, 10k",
                product_category: "fasteners",
                quantity: 10_000,
                unit: "pcs",
                incoterm: Some("FOB"),
                destination_country: "DE",
                currency: Currency::Usd,
                target_unit_price: Some(usd(12)),
                closes_at: Some(now + TimeDelta::days(7)),
            },
        )
        .await
        .expect("rfq");

        insert_quote(
            tx,
            g.quote,
            &NewQuote {
                rfq_id: g.rfq,
                supplier_id: g.supplier,
                unit_price: usd(11),
                quantity: 10_000,
                freight: Some(usd(40_000)),
                duties: None,
                other_fees: None,
                lead_time_days: Some(21),
                incoterm: Some("FOB"),
                valid_until: now + TimeDelta::days(14),
            },
        )
        .await
        .expect("quote");

        open_negotiation(
            tx,
            g.negotiation,
            g.rfq,
            g.supplier,
            Some(g.quote),
            None,
            now + TimeDelta::days(2),
        )
        .await
        .expect("negotiation");

        record_round(
            tx,
            Uuid::now_v7(),
            &NewRound {
                negotiation_id: g.negotiation,
                party: Party::Buyer,
                message_id: None,
                unit_price: Some(usd(10)),
                quantity: Some(10_000),
                lead_time_days: Some(21),
                incoterm: Some("FOB"),
                occurred_at: now,
                reply_due_at: now + TimeDelta::days(2),
            },
        )
        .await
        .expect("round");

        insert_purchase_order(
            tx,
            g.purchase_order,
            &NewPurchaseOrder {
                po_number: "PO-1",
                supplier_id: g.supplier,
                rfq_id: Some(g.rfq),
                quote_id: Some(g.quote),
                employee_id: None,
                approval_id: None,
                unit_price: usd(10),
                quantity: 10_000,
                freight: Some(usd(40_000)),
                duties: None,
                incoterm: Some("FOB"),
                issued_at: now,
            },
        )
        .await
        .expect("purchase order");

        sqlx::query(
            "INSERT INTO shipments (id, tenant_id, purchase_order_id, carrier, mode, state, eta) \
             VALUES ($1, $2, $3, 'Maersk', 'sea', 'in_transit', $4)",
        )
        .bind(Uuid::now_v7())
        .bind(tx.tenant_id().as_uuid())
        .bind(g.purchase_order)
        .bind((now + TimeDelta::days(30)).date_naive())
        .execute(&mut ***tx)
        .await
        .expect("shipment");

        record_observation(
            tx,
            Uuid::now_v7(),
            g.supplier,
            Observation::DeliveryOnTime {
                purchase_order_id: g.purchase_order,
            },
            now,
        )
        .await
        .expect("observation");

        g
    }

    // -- tenant isolation ---------------------------------------------------

    /// The premise of every other test: one tenant's sourcing data is not
    /// merely filtered out of another tenant's queries, it is invisible to
    /// them. Asked for by primary key, with no tenant predicate in the SQL.
    #[tokio::test]
    async fn every_sourcing_table_isolates_tenants() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let a = seed_tenant(&db, "sourcing-iso-a").await;
        let b = seed_tenant(&db, "sourcing-iso-b").await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;
        tx.commit().await.expect("commit graph");

        // Every table, and RLS actually switched on for each: a policy on a
        // table with RLS disabled is decorative.
        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        for table in SOURCING_TABLES {
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

        // The reputation view aggregates another tenant's evidence, so it is
        // the one place a missing `security_invoker` would leak silently.
        let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM supplier_reputation")
            .fetch_one(&mut **tx)
            .await
            .expect("count view");
        assert_eq!(leaked, 0, "supplier_reputation must not cross tenants");

        // And the store API agrees, asked by primary key.
        assert!(
            find_suppliers(&mut tx, Some("CN"), "fasteners")
                .await
                .expect("search")
                .is_empty()
        );
        assert!(
            live_quotes(&mut tx, graph.rfq, now)
                .await
                .expect("quotes")
                .is_empty()
        );
        assert!(
            negotiations_awaiting_reply(&mut tx, now + TimeDelta::days(365))
                .await
                .expect("stalled")
                .is_empty()
        );
        assert_eq!(
            reputation(&mut tx, graph.supplier).await.expect("rep"),
            None
        );
        tx.rollback().await.expect("rollback");

        // Tenant A still sees its own.
        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let found = find_suppliers(&mut tx, Some("CN"), "fasteners")
            .await
            .expect("search");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, graph.supplier);
        assert_eq!(found[0].categories, vec!["fasteners", "hardware"]);
        // ... and not for a category it does not sell, or another country.
        assert!(
            find_suppliers(&mut tx, Some("CN"), "castings")
                .await
                .expect("search")
                .is_empty()
        );
        assert!(
            find_suppliers(&mut tx, Some("VN"), "fasteners")
                .await
                .expect("search")
                .is_empty()
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    /// A quote in tenant A must not be filable against tenant B's RFQ. Foreign
    /// key checks are performed by the system and do NOT go through RLS, so
    /// without `tenant_id` in the key this would succeed and produce a row
    /// nobody can see.
    #[tokio::test]
    async fn a_quote_cannot_reference_another_tenants_rfq() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let a = seed_tenant(&db, "sourcing-fk-a").await;
        let b = seed_tenant(&db, "sourcing-fk-b").await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let their = seed_graph(&mut tx, now).await;
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        let mine = seed_graph(&mut tx, now).await;
        let err = insert_quote(
            &mut tx,
            Uuid::now_v7(),
            &NewQuote {
                rfq_id: their.rfq,
                supplier_id: mine.supplier,
                unit_price: usd(1),
                quantity: 1,
                freight: None,
                duties: None,
                other_fees: None,
                lead_time_days: None,
                incoterm: None,
                valid_until: now + TimeDelta::days(1),
            },
        )
        .await
        .expect_err("cross-tenant rfq reference must fail");
        assert!(
            format!("{err}").contains("quotes_rfq_fk"),
            "expected the composite fk to reject it, got: {err}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    // -- live quotes --------------------------------------------------------

    /// The cheapest quote in the table is expired, so the cheapest *live* quote
    /// is the second one. A comparison that forgets expiry recommends a price
    /// no supplier will honour — and it recommends it first, because expired
    /// quotes are exactly the stale-cheap ones.
    #[tokio::test]
    async fn an_expired_quote_is_excluded_from_the_live_comparison() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "sourcing-live").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;

        // Three more suppliers, three more quotes on the same RFQ.
        let cheap_expired = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let dear = Uuid::now_v7();

        for (id, name) in [
            (cheap_expired, "Expired Metals"),
            (mid, "Mid Metals"),
            (dear, "Dear Metals"),
        ] {
            insert_supplier(
                &mut tx,
                id,
                &NewSupplier {
                    legal_name: name,
                    country: "CN",
                    categories: &["fasteners".to_owned()],
                    website: None,
                },
            )
            .await
            .expect("supplier");
        }

        let quotes = [
            // Cheapest landed by a mile, and dead an hour ago.
            (cheap_expired, 5u64, 0u64, now - TimeDelta::hours(1)),
            // Unit price beats `dear`, but freight makes it the more expensive
            // landed — which is the whole reason the ordering is on the
            // generated landed column and not on unit price.
            (mid, 9, 200_000, now + TimeDelta::days(1)),
            (dear, 10, 10_000, now + TimeDelta::days(1)),
        ];
        for (supplier_id, unit, freight, valid_until) in quotes {
            insert_quote(
                &mut tx,
                Uuid::now_v7(),
                &NewQuote {
                    rfq_id: graph.rfq,
                    supplier_id,
                    unit_price: usd(unit),
                    quantity: 10_000,
                    freight: Money::new(freight, Currency::Usd).ok(),
                    duties: None,
                    other_fees: None,
                    lead_time_days: Some(30),
                    incoterm: None,
                    valid_until,
                },
            )
            .await
            .expect("quote");
        }

        let live = live_quotes(&mut tx, graph.rfq, now).await.expect("live");
        let suppliers: Vec<Uuid> = live.iter().map(|q| q.supplier_id).collect();

        assert!(
            !suppliers.contains(&cheap_expired),
            "an expired quote must not be comparable, however cheap"
        );
        // seeded quote: 11 * 10_000 + 40_000 = 150_000
        // dear:         10 * 10_000 + 10_000 = 110_000
        // mid:           9 * 10_000 + 200_000 = 290_000
        assert_eq!(suppliers, vec![dear, graph.supplier, mid]);
        assert_eq!(live[0].landed_total, usd(110_000));
        assert_eq!(live[0].unit_price, usd(10));
        assert_eq!(live[2].landed_total, usd(290_000));

        // The two columns a landed-cost comparison cannot be built without: the
        // term the price is quoted on, and the instant the window opened. The
        // seeded quote named FOB and these three named nothing — which is a
        // different answer from "FOB", and the reason the field is an `Option`
        // rather than a default filled in here.
        let seeded = live
            .iter()
            .find(|q| q.supplier_id == graph.supplier)
            .expect("the seeded quote is standing");
        assert_eq!(seeded.incoterm.as_deref(), Some("FOB"));
        assert_eq!(live[0].incoterm, None);
        assert!(
            live.iter().all(|q| q.received_at <= q.valid_until),
            "a quote cannot have arrived after it expired: {live:?}"
        );

        // One second past its expiry the cheapest is gone; one second before,
        // it leads. The boundary is the cutoff, not a rounding.
        let earlier = live_quotes(&mut tx, graph.rfq, now - TimeDelta::hours(2))
            .await
            .expect("live");
        assert_eq!(earlier[0].supplier_id, cheap_expired);

        // A withdrawn quote is out too, expiry or not.
        sqlx::query("UPDATE quotes SET state = 'withdrawn' WHERE supplier_id = $1")
            .bind(dear)
            .execute(&mut **tx)
            .await
            .expect("withdraw");
        let after = live_quotes(&mut tx, graph.rfq, now).await.expect("live");
        assert_eq!(
            after.iter().map(|q| q.supplier_id).collect::<Vec<_>>(),
            vec![graph.supplier, mid]
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    // -- reputation ---------------------------------------------------------

    /// Three ways to write a reputation nothing supports, all refused: no
    /// observations at all, an observation with no evidence attached, and a
    /// direct write to the derived view.
    #[tokio::test]
    async fn a_reputation_cannot_be_written_without_its_observations() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "sourcing-rep").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let blank = Uuid::now_v7();
        insert_supplier(
            &mut tx,
            blank,
            &NewSupplier {
                legal_name: "Brand New Trading Co",
                country: "VN",
                categories: &["fasteners".to_owned()],
                website: None,
            },
        )
        .await
        .expect("supplier");

        // 1. No evidence, no reputation — not a zeroed one.
        assert_eq!(reputation(&mut tx, blank).await.expect("rep"), None);

        // 2. The view is not writable. It aggregates, so Postgres refuses the
        //    write outright, and app_role holds no INSERT on it either.
        let err = sqlx::query(
            "INSERT INTO supplier_reputation (tenant_id, supplier_id, observation_count) \
             VALUES ($1, $2, 999)",
        )
        .bind(tenant.as_uuid())
        .bind(blank)
        .execute(&mut **tx)
        .await
        .expect_err("the view must not be writable");
        // SQLSTATE, not the sentence. `contains("view")` passed here for a year
        // and then failed the first time this ran against a server whose
        // `lc_messages` is not English — "ne peut pas insérer dans la vue" is
        // the *same refusal*, correctly given, reported as a test failure.
        // `55000` is object_not_in_prerequisite_state, which is what Postgres
        // raises for a write to a view with no INSTEAD OF trigger behind it,
        // and it is never translated. (Not `0A000`: that is what the class of
        // error *sounds* like, and asserting it fails against a real server —
        // which is how this line was arrived at.) The same argument, at more
        // length, is in `audit.rs`.
        let sqlstate = err
            .as_database_error()
            .and_then(|e| e.code())
            .unwrap_or_default()
            .into_owned();
        assert_eq!(
            sqlstate, "55000",
            "expected the write to the view to be refused with 55000, got: {err}"
        );
        tx.rollback().await.expect("rollback");

        // 3. An observation with no evidence row behind it is not an
        //    observation. Bypassing the `Observation` enum reaches the CHECK.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;
        let err = sqlx::query(
            "INSERT INTO supplier_observations (id, tenant_id, supplier_id, kind) \
             VALUES ($1, $2, $3, 'delivery_on_time')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(graph.supplier)
        .execute(&mut **tx)
        .await
        .expect_err("an unevidenced observation must be refused");
        assert!(
            format!("{err}").contains("supplier_observations_evidence"),
            "expected the evidence CHECK to fire, got: {err}"
        );
        tx.rollback().await.expect("rollback");

        // 4. With evidence, the numbers are exactly the observations and
        //    nothing else — recomputed, never stored.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;
        for (n, observation) in [
            Observation::DeliveryLate {
                purchase_order_id: graph.purchase_order,
            },
            Observation::QualityAccepted {
                purchase_order_id: graph.purchase_order,
            },
            Observation::QuoteReturned { rfq_id: graph.rfq },
            Observation::QuoteMissed { rfq_id: graph.rfq },
        ]
        .into_iter()
        .enumerate()
        {
            record_observation(
                &mut tx,
                Uuid::now_v7(),
                graph.supplier,
                observation,
                now + TimeDelta::minutes(n as i64 + 1),
            )
            .await
            .expect("observation");
        }

        let rep = reputation(&mut tx, graph.supplier)
            .await
            .expect("rep")
            .expect("evidence exists");
        // seed_graph already filed one delivery_on_time.
        assert_eq!(rep.observation_count, 5);
        assert_eq!(rep.delivered_on_time, 1);
        assert_eq!(rep.delivered_late, 1);
        assert_eq!(rep.on_time_rate_pct, Some(50));
        assert_eq!(rep.response_rate_pct, Some(50));
        // One inspection, passed: 100%. Nothing disputed: no denominator
        // anywhere makes a rate up out of thin air.
        assert_eq!(rep.quality_rate_pct, Some(100));
        assert_eq!(rep.disputes, 0);
        assert_eq!(rep.last_observed_at, now + TimeDelta::minutes(4));

        // And the evidence cannot be quietly removed either: app_role holds no
        // DELETE on any sourcing table, so an inconvenient observation stays.
        sqlx::query("DELETE FROM suppliers WHERE id = $1")
            .bind(graph.supplier)
            .execute(&mut **tx)
            .await
            .expect_err("app_role must not delete suppliers");
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    // -- stalled negotiations ----------------------------------------------

    /// The sweep finds the supplier who has gone quiet past their deadline, and
    /// only them: not the one whose deadline is still in the future, and not
    /// the one who has already replied.
    #[tokio::test]
    async fn the_deadline_query_finds_a_stalled_negotiation() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "sourcing-stall").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;

        // seed_graph's negotiation is due in two days and we are waiting on
        // them: not yet stalled.
        assert!(
            negotiations_awaiting_reply(&mut tx, now)
                .await
                .expect("sweep")
                .is_empty()
        );

        // Two more suppliers on the same RFQ, one overdue, one who replied.
        let stalled_supplier = Uuid::now_v7();
        let replied_supplier = Uuid::now_v7();
        for (id, name) in [
            (stalled_supplier, "Quiet Works"),
            (replied_supplier, "Prompt Works"),
        ] {
            insert_supplier(
                &mut tx,
                id,
                &NewSupplier {
                    legal_name: name,
                    country: "CN",
                    categories: &["fasteners".to_owned()],
                    website: None,
                },
            )
            .await
            .expect("supplier");
        }

        let stalled = Uuid::now_v7();
        open_negotiation(
            &mut tx,
            stalled,
            graph.rfq,
            stalled_supplier,
            None,
            None,
            now - TimeDelta::days(3),
        )
        .await
        .expect("stalled negotiation");

        let replied = Uuid::now_v7();
        open_negotiation(
            &mut tx,
            replied,
            graph.rfq,
            replied_supplier,
            None,
            None,
            now - TimeDelta::days(3),
        )
        .await
        .expect("replied negotiation");

        // Both are overdue right now.
        let overdue = negotiations_awaiting_reply(&mut tx, now)
            .await
            .expect("sweep");
        assert_eq!(
            overdue.iter().map(|n| n.id).collect::<Vec<_>>(),
            vec![stalled, replied]
        );

        // The supplier answers one of them. Recording the round flips the
        // state and moves the deadline in the same statement, so the sweep can
        // never see a replied negotiation as still waiting.
        let round_no = record_round(
            &mut tx,
            Uuid::now_v7(),
            &NewRound {
                negotiation_id: replied,
                party: Party::Supplier,
                message_id: None,
                unit_price: Some(usd(9)),
                quantity: Some(10_000),
                lead_time_days: Some(28),
                incoterm: Some("FOB"),
                occurred_at: now - TimeDelta::hours(1),
                reply_due_at: now + TimeDelta::days(2),
            },
        )
        .await
        .expect("round");
        assert_eq!(round_no, 1, "the database assigns the round number");

        let overdue = negotiations_awaiting_reply(&mut tx, now)
            .await
            .expect("sweep");
        assert_eq!(overdue.len(), 1, "only the quiet supplier is stalled");
        let found = &overdue[0];
        assert_eq!(found.id, stalled);
        assert_eq!(found.supplier_id, stalled_supplier);
        assert_eq!(found.rfq_id, graph.rfq);
        assert_eq!(found.reply_due_at, now - TimeDelta::days(3));
        assert_eq!(found.last_round_at, None);
        assert_eq!(found.round_count, 0);

        // An abandoned negotiation stops being chased.
        sqlx::query("UPDATE negotiations SET state = 'abandoned' WHERE id = $1")
            .bind(stalled)
            .execute(&mut **tx)
            .await
            .expect("abandon");
        assert!(
            negotiations_awaiting_reply(&mut tx, now)
                .await
                .expect("sweep")
                .is_empty()
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    /// Round numbers come from the negotiation's counter, so an appended round
    /// cannot silently overwrite or duplicate an earlier one.
    #[tokio::test]
    async fn rounds_are_numbered_by_the_database() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "sourcing-rounds").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;

        // seed_graph already recorded round 1 from the buyer.
        for (n, party) in [
            (2, Party::Supplier),
            (3, Party::Buyer),
            (4, Party::Supplier),
        ] {
            let round_no = record_round(
                &mut tx,
                Uuid::now_v7(),
                &NewRound {
                    negotiation_id: graph.negotiation,
                    party,
                    message_id: None,
                    unit_price: Some(usd(10 - n as u64)),
                    quantity: Some(10_000),
                    lead_time_days: None,
                    incoterm: None,
                    occurred_at: now + TimeDelta::hours(n),
                    reply_due_at: now + TimeDelta::days(2),
                },
            )
            .await
            .expect("round");
            assert_eq!(round_no, n as i32);
        }

        // A round against a negotiation this tenant cannot see is NotFound, not
        // an orphan row: the CTE's UPDATE matches nothing and the INSERT has
        // nothing to select from.
        let err = record_round(
            &mut tx,
            Uuid::now_v7(),
            &NewRound {
                negotiation_id: Uuid::now_v7(),
                party: Party::Buyer,
                message_id: None,
                unit_price: None,
                quantity: None,
                lead_time_days: None,
                incoterm: None,
                occurred_at: now,
                reply_due_at: now + TimeDelta::days(1),
            },
        )
        .await
        .expect_err("unknown negotiation");
        assert!(
            matches!(err, SourcingError::Store(StoreError::NotFound)),
            "expected NotFound, got {err:?}"
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    // -- money --------------------------------------------------------------

    /// Currency is not a decoration on a number. A quote answers its RFQ in the
    /// RFQ's currency or not at all, and add-on costs are in the same currency
    /// as the line they are added to.
    #[tokio::test]
    async fn money_cannot_be_mixed_across_currencies() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "sourcing-money").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;

        // Freight in EUR on a USD quote: caught in Rust, before SQL.
        let err = insert_quote(
            &mut tx,
            Uuid::now_v7(),
            &NewQuote {
                rfq_id: graph.rfq,
                supplier_id: graph.supplier,
                unit_price: usd(10),
                quantity: 1,
                freight: Money::new(100, Currency::Eur).ok(),
                duties: None,
                other_fees: None,
                lead_time_days: None,
                incoterm: None,
                valid_until: now + TimeDelta::days(1),
            },
        )
        .await
        .expect_err("mixed currency");
        assert!(matches!(
            err,
            SourcingError::Money(MoneyError::CurrencyMismatch { .. })
        ));

        // A whole quote in the wrong currency: caught by the composite FK,
        // because the RFQ's currency is part of the key.
        let err = insert_quote(
            &mut tx,
            Uuid::now_v7(),
            &NewQuote {
                rfq_id: graph.rfq,
                supplier_id: graph.supplier,
                unit_price: Money::new(1_000, Currency::Jpy).expect("non-zero"),
                quantity: 1,
                freight: None,
                duties: None,
                other_fees: None,
                lead_time_days: None,
                incoterm: None,
                valid_until: now + TimeDelta::days(1),
            },
        )
        .await
        .expect_err("wrong currency for this rfq");
        assert!(
            format!("{err}").contains("quotes_rfq_fk"),
            "expected the rfq currency fk to reject it, got: {err}"
        );

        tx.rollback().await.expect("rollback");

        // The purchase order's total is computed by the database from its
        // parts, so it cannot disagree with them.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let graph = seed_graph(&mut tx, now).await;
        let total = insert_purchase_order(
            &mut tx,
            Uuid::now_v7(),
            &NewPurchaseOrder {
                po_number: "PO-2",
                supplier_id: graph.supplier,
                rfq_id: Some(graph.rfq),
                quote_id: None,
                employee_id: None,
                approval_id: None,
                unit_price: usd(250),
                quantity: 400,
                freight: Some(usd(9_000)),
                duties: Some(usd(1_000)),
                incoterm: Some("DDP"),
                issued_at: now,
            },
        )
        .await
        .expect("purchase order");
        assert_eq!(total, usd(250 * 400 + 9_000 + 1_000));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    // -- closing a round ---------------------------------------------------

    /// One supplier, reachable, on this tenant.
    async fn seed_supplier(tx: &mut TenantTx<'_>, name: &str, email: &str) -> Uuid {
        let supplier = Uuid::now_v7();
        insert_supplier(
            tx,
            supplier,
            &NewSupplier {
                legal_name: name,
                country: "DE",
                categories: &["fasteners".to_owned()],
                website: None,
            },
        )
        .await
        .expect("supplier");

        sqlx::query(
            "INSERT INTO supplier_contacts (id, tenant_id, supplier_id, full_name, email, is_primary) \
             VALUES ($1, $2, $3, 'Sales', $4, true)",
        )
        .bind(Uuid::now_v7())
        .bind(tx.tenant_id().as_uuid())
        .bind(supplier)
        .bind(email)
        .execute(&mut ***tx)
        .await
        .expect("contact");
        supplier
    }

    /// `(quotes_returned, quotes_missed)` for one supplier, out of the view.
    async fn responsiveness(tx: &mut TenantTx<'_>, supplier: Uuid) -> (i64, i64) {
        reputation(tx, supplier)
            .await
            .expect("reputation")
            .map_or((0, 0), |rep| (rep.quotes_returned, rep.quotes_missed))
    }

    /// **The observation `quote_missed` had no writer for.**
    ///
    /// Three suppliers are asked. One answers inside the window, one answers
    /// after it — day 9 of an 8-day round — and one never answers at all. The
    /// round closes and files exactly three observations: two `quote_returned`
    /// and one `quote_missed`. The late answer is an answer, because the thing
    /// the reputation is asked is "does writing to them buy a quote", and it
    /// bought one.
    ///
    /// Then the pass runs twice more and files nothing, because a reputation
    /// that decays for a bookkeeping reason is worse than no reputation.
    #[tokio::test]
    async fn a_closing_round_files_one_observation_per_recipient_and_never_twice() {
        let Some(db) = db().await else { return };
        let now = at(1_800_000_000);
        let tenant = seed_tenant(&db, "sourcing-close").await;

        let employee = EmployeeId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'Lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *admin)
        .await
        .expect("insert employee");
        admin.commit().await.expect("commit employee");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let prompt = seed_supplier(&mut tx, "Prompt Works", "sales@prompt.example").await;
        let late = seed_supplier(&mut tx, "Late Works", "sales@late.example").await;
        let silent = seed_supplier(&mut tx, "Quiet Works", "sales@quiet.example").await;

        let rfq = Uuid::now_v7();
        let closes_at = now + TimeDelta::days(8);
        insert_rfq(
            &mut tx,
            rfq,
            &NewRfq {
                employee_id: Some(employee),
                title: "M6 bolts, 10k",
                product_category: "fasteners",
                quantity: 10_000,
                unit: "pcs",
                incoterm: Some("DDP"),
                destination_country: "DE",
                currency: Currency::Usd,
                target_unit_price: Some(usd(12)),
                closes_at: Some(closes_at),
            },
        )
        .await
        .expect("rfq");

        // Who was asked. The middle address is upper-cased on purpose:
        // `EmailAddress` folds what it parses and the contact column is free
        // text, so the join has to fold too or a supplier silently drops out of
        // its own round.
        let asked = record_rfq_recipients(
            &mut tx,
            rfq,
            Some(employee),
            &[
                "sales@prompt.example".to_owned(),
                "SALES@LATE.EXAMPLE".to_owned(),
                "sales@quiet.example".to_owned(),
            ],
            closes_at,
        )
        .await
        .expect("recipients");
        assert_eq!(asked, 3, "every address matched a supplier");

        for (supplier, received_at) in [
            (prompt, now + TimeDelta::days(2)),
            (late, closes_at + TimeDelta::days(1)),
        ] {
            let quote = Uuid::now_v7();
            insert_quote(
                &mut tx,
                quote,
                &NewQuote {
                    rfq_id: rfq,
                    supplier_id: supplier,
                    unit_price: usd(11),
                    quantity: 10_000,
                    freight: None,
                    duties: None,
                    other_fees: None,
                    lead_time_days: Some(21),
                    incoterm: Some("DDP"),
                    valid_until: closes_at + TimeDelta::days(30),
                },
            )
            .await
            .expect("quote");
            // `received_at` defaults to now(); pin it so "late" is a fact in
            // the row and not a fact about when this test ran.
            sqlx::query("UPDATE quotes SET received_at = $2 WHERE id = $1")
                .bind(quote)
                .bind(received_at)
                .execute(&mut **tx)
                .await
                .expect("backdate");
        }

        // A round that is still open is not over, whatever else is true.
        assert!(
            close_expired_rounds(&mut tx, employee, now + TimeDelta::days(3))
                .await
                .expect("sweep")
                .is_empty(),
            "a round swept before its own deadline"
        );
        for supplier in [prompt, late, silent] {
            assert_eq!(responsiveness(&mut tx, supplier).await, (0, 0));
        }

        // Past the deadline: the round ends and the evidence is filed.
        let closed = close_expired_rounds(&mut tx, employee, closes_at + TimeDelta::days(2))
            .await
            .expect("sweep");
        assert_eq!(
            closed,
            vec![ClosedRound {
                rfq_id: rfq,
                quotes_returned: 2,
                quotes_missed: 1,
            }]
        );
        assert_eq!(responsiveness(&mut tx, prompt).await, (1, 0));
        assert_eq!(
            responsiveness(&mut tx, late).await,
            (1, 0),
            "answering after the window is answering; only silence is silence"
        );
        assert_eq!(responsiveness(&mut tx, silent).await, (0, 1));

        let state: String = sqlx::query_scalar("SELECT state FROM rfqs WHERE id = $1")
            .bind(rfq)
            .fetch_one(&mut **tx)
            .await
            .expect("state");
        assert_eq!(state, "closed", "the open row is what strands the employee");

        // Twice more, at two different instants. A round closes once.
        for extra in [3, 40] {
            assert!(
                close_expired_rounds(&mut tx, employee, closes_at + TimeDelta::days(extra))
                    .await
                    .expect("sweep")
                    .is_empty()
            );
        }
        assert_eq!(responsiveness(&mut tx, prompt).await, (1, 0));
        assert_eq!(responsiveness(&mut tx, late).await, (1, 0));
        assert_eq!(
            responsiveness(&mut tx, silent).await,
            (0, 1),
            "the pass ran three times and this supplier missed one round"
        );

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }
}
