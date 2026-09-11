//! `/v1/invoices`: the founder's half of the register — read what is owed, and
//! say when it arrived.
//!
//! `migrations/0066_invoices.sql` argues for the table and
//! [`agentos_store::invoices`] is the SQL. This is the only surface that reads
//! either, and the only one that writes `paid_at`.
//!
//! # There is no `POST /v1/invoices`, and that is the design
//!
//! `routes::work` and `routes::calendar` both let an operator create the thing
//! their internal tool is about, because a work item and an appointment are
//! things a founder writes down. An invoice is not: **the only way one exists is
//! `Effects::issue_invoice`, holding a token the Policy Gate minted for an
//! employee.** So issuing leaves a `provider_call_attempted` row linked to the
//! ruling that permitted it, every time, with no second path that does not.
//!
//! An operator route here would be that second path — a demand for money with no
//! decision behind it, indistinguishable in the table from one an employee was
//! authorised to make. `work_items` accepted exactly that ambiguity and paid for
//! it with `0064`'s `posted_by` column; this table declines it up front.
//!
//! `invoices.issued_by` stopped being NOT NULL in
//! `migrations/0071_an_invoice_needs_a_number.sql` and this paragraph did not
//! weaken: the null is not "an operator issued this", it is "this row is a
//! credit note", which `invoices_issuer_or_correction` makes the *same* fact
//! rather than a second one. Issuing is still an employee's only.
//!
//! The cost is real and is the founder's to switch on: until the `issue_invoice`
//! tool row lands in `agentos_app::turn::catalogue` — written out there
//! verbatim, unapplied, because it moves two pinned digests — no employee can
//! reach the effect from a turn, so the register fills only from Rust. The
//! endpoint that would paper over that is the one this module refuses to be.
//!
//! # The mentions an invoice must carry, and where they are refused
//!
//! A French invoice is a regulated document: the issuer's legal identity, the
//! breakdown by VAT rate, and what is owed for paying late. `0087` puts those
//! on `tenants`, `PUT /v1/invoices/issuer` writes them, and
//! [`refuse_without_mentions`] is the one list of what is missing.
//!
//! **The refusal sits on the surfaces that emit a document**, not on
//! `agentos_store::invoices::issue`. That is a deliberate line and it is the
//! same one `paid` draws: the store function is what every fixture in this
//! workspace uses to put a row in the register, and a register row is not a
//! document. What must never leave the building is a **PDF** without its
//! mentions, and there are exactly two paths that produce one —
//! `POST /v1/invoices/{id}/credit`, which refuses here with the missing
//! mentions named, and `Effects::issue_invoice`, whose transaction is in
//! `agentos_app::effects` and is not this module's to change. Until that second
//! path carries the same check, `agentos_app::invoice_document` renders its
//! document with `FACTURE NON CONFORME` and the list across the top, so an
//! unissuable invoice is never mistaken for an issuable one.
//!
//! And the paragraph above still holds: **there is no `POST /v1/invoices`** to
//! put the check on. An operator route that issued would be the second path
//! with no ruling behind it that this module exists to refuse; the check
//! belongs to whatever issues, not to a new way of issuing.
//!
//! # Why `paid` is an operator's and never an employee's
//!
//! Nothing in this process can call a bank or a PSP, so "it was paid" is not
//! observed here, it is asserted. The seat that issued an invoice must not be
//! the thing that records the money arriving — an employee that could settle its
//! own receivables has a clean ledger and no revenue — so the assertion comes
//! from the same authority that writes charters and cadences: an API key, not a
//! principal the gate rules on.
//!
//! That is also why there is no `ActionKind::InvoicePaid`. The Stripe webhook
//! writes `paid_at` now (`agentos_app::stripe`), and the writer is still not an
//! employee.
//!
//! # No `paid_by`, and an audit row after all
//!
//! No column: `routes::work`'s reason before `0064` holds for the column, since
//! every writer of `paid_at` holds an operator key or is the webhook. The audit
//! row is the thing this module used to refuse and now writes, because the
//! argument for refusing it stopped being true the day Stripe wrote one:
//! `AuditKind::InvoicePaid` exists, the Stripe path files it with the event id,
//! and a register with two ways to be settled and a trail that shows only one
//! of them answers "who said this was paid" with a shrug for exactly the
//! settlements a person asserted by hand. So `paid` writes the same kind, with
//! the key's principal as actor and `"source": "operator"` in the payload
//! where Stripe's says `"stripe"` — and only on the call that settled, so a
//! replay that `declare_paid` reports as `false` leaves no second row.

use agentos_domain::ids::InvoiceId;
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::Db;
use agentos_store::invoices::{self, Issuer};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the rate
/// limit and the idempotency layer from `with_api_stack`.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/invoices", get(register))
        .route("/v1/invoices/issuer", get(read_issuer).put(write_issuer))
        .route("/v1/invoices/{id}/paid", post(paid))
        .route("/v1/invoices/{id}/credit", post(credit))
        .with_state(db)
}

/// One invoice, as the founder reads it back.
///
/// The amount is split back into minor units and a code rather than rendered,
/// for `routes::billing`'s reason one product along: a formatted figure is a
/// presentation decision, and this endpoint reports what it measured.
#[derive(Serialize)]
struct InvoiceView {
    id: Uuid,
    /// The number a customer quotes, gap-free inside this company.
    number: i64,
    /// The won deal it bills.
    opportunity_id: Uuid,
    /// The seat that issued it, and null on a credit note — those are written
    /// by an operator, not by a seat.
    issued_by: Option<Uuid>,
    /// Set on a credit note, and it *is* what makes this row one: the invoice
    /// this document withdraws part or all of.
    corrects_invoice_id: Option<Uuid>,
    /// Positive on a credit note too. The direction is `corrects_invoice_id`.
    amount_minor: u64,
    currency: &'static str,
    memo: String,
    issued_at: DateTime<Utc>,
    /// When payment is due. Null when no term was agreed; this product invents
    /// none.
    due_at: Option<DateTime<Utc>>,
    /// When somebody declared the money had arrived. Null is outstanding.
    paid_at: Option<DateTime<Utc>>,
    lines: Vec<LineView>,
}

/// One line of a document.
///
/// `tax_rate_bp` is reported and never used: nothing in this product multiplies
/// a rate by an amount, because whether tax rounds per line or per band is a
/// jurisdiction's rule and a total computed by the wrong one is worse than no
/// total. See `migrations/0071_an_invoice_needs_a_number.sql`.
#[derive(Serialize)]
struct LineView {
    description: String,
    amount_minor: i64,
    tax_rate_bp: Option<i32>,
}

impl From<invoices::Invoice> for InvoiceView {
    fn from(invoice: invoices::Invoice) -> Self {
        Self {
            id: invoice.id.as_uuid(),
            number: invoice.number,
            opportunity_id: invoice.opportunity_id,
            issued_by: invoice.issued_by.map(|seat| seat.as_uuid()),
            corrects_invoice_id: invoice.corrects_invoice_id.map(|id| id.as_uuid()),
            amount_minor: invoice.amount.minor(),
            currency: invoice.amount.currency().code(),
            memo: invoice.memo,
            issued_at: invoice.issued_at,
            due_at: invoice.due_at,
            paid_at: invoice.paid_at,
            lines: invoice
                .lines
                .into_iter()
                .map(|line| LineView {
                    description: line.description,
                    amount_minor: line.amount_minor,
                    tax_rate_bp: line.tax_rate_bp,
                })
                .collect(),
        }
    }
}

/// Page size when the caller does not ask for one. `routes::employees`' number,
/// and its argument: a page a person scrolls once.
const DEFAULT_LIMIT: i64 = 50;

/// Largest page we will build, however big a `limit` the caller sends.
///
/// Two hundred and not two thousand, and the ceiling is not the database's: the
/// first reader of this route is an MCP tool, so a page is a model's context. A
/// register of invoices with their lines runs a few hundred tokens per document,
/// and two hundred of them is already most of what a turn can afford to spend on
/// one call.
const MAX_LIMIT: i64 = 200;

/// The window and the cut. `deny_unknown_fields` so a caller who misspells
/// `state` finds out now rather than wondering why nothing was filtered — the
/// failure mode that matters here, because the wrong answer is a *longer* list
/// that looks right.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    /// `outstanding` or `paid`. Absent is the whole register, credit notes
    /// included — see `invoices::State`, which owns the two words.
    #[serde(default)]
    state: Option<String>,
    /// The `number` of the last invoice on the previous page. The number and not
    /// the id, because the number is the order.
    #[serde(default)]
    after: Option<i64>,
    /// How many documents to return, capped at [`MAX_LIMIT`].
    #[serde(default)]
    limit: Option<i64>,
}

/// `GET /v1/invoices` — one page of what this company has issued, oldest first.
///
/// Settled and outstanding together **by default**, for `GET /v1/work`'s and
/// `GET /v1/calendar`'s reason: what somebody wants at the end of a month is
/// what is outstanding *and* what came in, and a list that hid the second half
/// would make the first look like nothing had happened. `state=outstanding`
/// exists for the other question — *who do I chase* — and it is a caller's
/// choice rather than this route's opinion.
///
/// `outstanding_minor` is a sum per currency and not one number, because there
/// is no exchange rate in this workspace and there must not be one — the same
/// refusal `SpendLimits` makes by rejecting mixed currencies outright. **It is
/// computed over the whole register on every page**, not over the rows returned:
/// a total that shrank as you paged would be a wrong number wearing the right
/// name, and the wrong number here is the one somebody puts in a forecast.
///
/// `limit` is clamped rather than refused, `routes::employees`' choice: an
/// over-large ask still gets a page and a `next_after`, so nothing is lost and
/// the caller finds out by walking. A `limit` that is not a number is still a
/// 400 — that is serde's, and it is the useful one.
async fn register(
    State(db): State<Db>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let state = match page.state.as_deref() {
        None => None,
        Some(text) => Some(invoices::State::parse(text).ok_or_else(|| {
            ApiError::bad_request("state: one of \"outstanding\", \"paid\", or absent for both")
        })?),
    };
    let limit = page.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let all = invoices::register(&mut tx, state, page.after, limit).await?;
    let outstanding = invoices::outstanding(&mut tx).await?;
    tx.rollback().await?;

    // Only a full page can have a successor. A short page ends the walk without
    // costing the client one more round trip to discover that.
    let next_after = (all.len() as i64 == limit)
        .then(|| all.last().map(|last| last.number))
        .flatten();

    Ok(Json(json!({
        "invoices": all.into_iter().map(InvoiceView::from).collect::<Vec<_>>(),
        "outstanding_minor": outstanding,
        "next_after": next_after,
    }))
    .into_response())
}

/// `POST /v1/invoices/{id}/paid` — the money arrived.
///
/// No body. The instant is the server's, not the caller's, and that is the
/// decision rather than an omission: a caller-supplied date would be the first
/// thing to be wrong, it would need a rule about how far back it may reach, and
/// `0066` has no value-date column for it to mean. When a PSP webhook brings a
/// real value date it brings the column with it.
///
/// 404 when the invoice is not this company's, does not exist, **or was already
/// settled**. The three are one answer on purpose: the first two are RLS's usual
/// silence, and the third is somebody being second — a settlement is declared
/// once and is never withdrawn or re-dated, which `0066`'s trigger enforces
/// underneath this and `invoices::declare_paid`'s `WHERE` reports as `false`.
async fn paid(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let now = Utc::now();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let settled = invoices::declare_paid(&mut tx, InvoiceId::from_uuid(id), now).await?;
    if !settled {
        // Rolled back rather than committed: nothing was written, and a pooled
        // connection goes back deliberately.
        tx.rollback().await?;
        return Err(
            ApiError::not_found().with_detail("no outstanding invoice by that id in this company")
        );
    }
    // The same kind and the same transaction as the Stripe path's row, so the
    // trail and the column cannot disagree about whether this settled.
    let mut row = AuditEvent::new(principal.actor.clone(), AuditKind::InvoicePaid, now);
    row.payload = json!({ "invoice_id": id, "source": "operator" });
    audit::append(&mut tx, &row).await?;
    tx.commit().await?;

    Ok(Json(json!({ "id": id, "state": "paid" })).into_response())
}

/// Longest `memo` `invoices_memo_shape` accepts, in characters.
///
/// Restated here rather than read off the table, and the restatement is what the
/// test below pins — `routes::work::MAX_TITLE`'s argument: the alternative is a
/// round trip to `information_schema` per request to learn a number that changes
/// in a migration. If it ever moves, this constant moves with it in the same
/// commit.
const MAX_MEMO: usize = 200;

/// What a credit note says. The currency is not in it: a credit note is
/// denominated by the invoice it corrects, so a second answer here could only
/// disagree with the first.
#[derive(serde::Deserialize)]
struct CreditBody {
    /// In the corrected invoice's currency, and no larger than it.
    amount_minor: u64,
    /// Why. One line, 1..=200 characters, `invoices_memo_shape`'s bound.
    memo: String,
}

/// `POST /v1/invoices/{id}/credit` — withdraw part or all of an issued invoice.
///
/// # Why this one *is* an operator's route when `POST /v1/invoices` is not
///
/// The module docs above refuse an operator route that **issues**, because a
/// demand for money with no ruling behind it is indistinguishable in the table
/// from one an employee was authorised to make. A credit note is the other
/// direction and the argument does not transfer: it creates no obligation on
/// anybody, it only withdraws one this company already made.
///
/// What *does* transfer is `paid_at`'s separation of duties, and it is the
/// reason this is not an `ActionKind`: **the seat that issues an invoice must
/// not be the thing that can erase it.** An employee able to credit its own
/// receivables has a clean ledger and no revenue, and nobody reading the
/// register would see the difference. So the authority here is the same one
/// that records a settlement — an API key, not a principal the gate rules on —
/// and `invoices.issued_by` is null on the row that results, which 0071's
/// `invoices_issuer_or_correction` makes exactly equivalent to "this is a
/// credit note".
///
/// 404 when the invoice is not this company's, does not exist, is itself a
/// credit note, or is smaller than the amount being withdrawn. 409 when it has
/// already been credited: 0071 allows one credit note per invoice, and that is
/// a unique index rather than a check somebody reads too early — two callers
/// crediting at the same instant cannot both win.
async fn credit(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Json(body): Json<CreditBody>,
) -> Result<Response, ApiError> {
    // Both ends of `invoices_memo_shape`, and it has to be both, before a number
    // is claimed. Left to the `CHECK`, a blank line or a 201-character sentence
    // arrives as a `23514` in `StoreError::Database` and comes out of `ApiError`
    // as a **500** — "we broke" — for a body the founder fixes by shortening a
    // sentence. `char_length` is what the constraint counts, so `chars()` is
    // what this counts; `.len()` would refuse a 70-character Japanese memo.
    // Trimmed here as well as measured, for `PgCalendar::book`'s reason: the
    // `CHECK` measures `btrim(memo)` and the column would otherwise store the
    // untrimmed one.
    let memo = body.memo.trim();
    if memo.is_empty() || memo.chars().count() > MAX_MEMO {
        return Err(ApiError::bad_request(
            "a credit note needs a memo of 1 to 200 characters: it is the one line that says why \
             a demand this company already made is being withdrawn",
        ));
    }

    let note = InvoiceId::new_v7(Utc::now());
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    // Before a number is claimed: a credit note is a document that leaves the
    // building, so it carries the same obligatory mentions as the demand it
    // withdraws. See [`refuse_without_mentions`].
    if let Some(refusal) = refuse_without_mentions(&mut tx).await? {
        tx.rollback().await?;
        return Err(refusal);
    }
    let written = invoices::credit(
        &mut tx,
        note,
        InvoiceId::from_uuid(id),
        body.amount_minor,
        memo,
    )
    .await;
    // The document, in the same transaction as the number — the invoice's own
    // rule (`Effects::issue_invoice`), and a credit note is a document the
    // customer receives too: `credit-note-<number>.pdf`, saying which invoice
    // it corrects.
    let written = match written {
        Ok(issued) => agentos_app::invoice_document::file(&mut tx, &issued)
            .await
            .map(|_| issued),
        Err(err) => Err(err),
    };
    match written {
        Ok(issued) => {
            tx.commit().await?;
            Ok(Json(InvoiceView::from(issued)).into_response())
        }
        Err(err) => {
            // Rolled back rather than dropped: a refused credit note must take
            // the number it would have claimed with it, which is the whole
            // point of claiming it in the same statement.
            tx.rollback().await?;
            Err(match err {
                agentos_store::db::StoreError::NotFound => ApiError::not_found()
                    .with_detail("no invoice by that id in this company that can be credited"),
                other => ApiError::from(other),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// The issuer's obligatory mentions
// ---------------------------------------------------------------------------

/// `409` naming every obligatory mention this company has not written down, or
/// `None` when it may issue.
///
/// **The refusal is here and not in [`agentos_store::invoices::issue`]**, and
/// the line is drawn at the surface that emits rather than at the SQL: the store
/// function is the one thing every fixture in this workspace uses to put a row
/// in the register, and a company whose invoices are not issuable is not a
/// company whose *register* is unreadable. What must not happen is a **document
/// leaving the building** without its mentions, and the two paths that produce
/// one are `Effects::issue_invoice` and this module's credit note.
///
/// The names are `agentos_store::invoices`' constants — the field names, not a
/// sentence — so a console can map each one to the input its operator has to
/// fill. A `detail` that said "some mentions are missing" would be a 409 nobody
/// can act on.
async fn refuse_without_mentions(
    tx: &mut agentos_store::db::TenantTx<'_>,
) -> Result<Option<ApiError>, ApiError> {
    let missing = invoices::issuer(tx).await?.missing_mentions();
    if missing.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        ApiError::conflict(
            "issuer_mentions_missing",
            "this company cannot issue an invoice yet",
        )
        .with_detail(format!(
            "a French invoice must carry these mentions of its issuer and this company has not \
             recorded them: {}. Write them with PUT /v1/invoices/issuer.",
            missing.join(", ")
        ))
        .with_extension("missing", json!(missing)),
    ))
}

/// The letterhead, on the wire. Every field is optional here and obligatory in
/// [`Issuer::missing_mentions`]: the refusal is one list, written once, so a
/// `PUT` that would store an unissuable letterhead fails with the same `detail`
/// the credit note would have produced later.
#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssuerBody {
    #[serde(default)]
    legal_form: Option<String>,
    #[serde(default)]
    postal_address: Option<String>,
    #[serde(default)]
    siren: Option<String>,
    #[serde(default)]
    rcs_city: Option<String>,
    #[serde(default)]
    vat_number: Option<String>,
    /// Basis points, `2000` for 20 %. Never `0`: a company outside VAT sends
    /// `vat_exemption_reason` instead, which is 0087's CHECK and this product's
    /// whole position on the question.
    #[serde(default)]
    vat_rate_bp: Option<i32>,
    #[serde(default)]
    vat_exemption_reason: Option<String>,
    #[serde(default)]
    late_penalty_rate_bp: Option<i32>,
}

impl IssuerBody {
    fn into_issuer(self, name: String) -> Issuer {
        let trimmed = |field: Option<String>| {
            field
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        Issuer {
            name,
            legal_form: trimmed(self.legal_form),
            address: trimmed(self.postal_address),
            siren: trimmed(self.siren),
            rcs_city: trimmed(self.rcs_city),
            vat_number: trimmed(self.vat_number),
            vat_rate_bp: self.vat_rate_bp,
            vat_exemption_reason: trimmed(self.vat_exemption_reason),
            late_penalty_rate_bp: self.late_penalty_rate_bp,
        }
    }
}

impl From<Issuer> for IssuerBody {
    fn from(issuer: Issuer) -> Self {
        Self {
            legal_form: issuer.legal_form,
            postal_address: issuer.address,
            siren: issuer.siren,
            rcs_city: issuer.rcs_city,
            vat_number: issuer.vat_number,
            vat_rate_bp: issuer.vat_rate_bp,
            vat_exemption_reason: issuer.vat_exemption_reason,
            late_penalty_rate_bp: issuer.late_penalty_rate_bp,
        }
    }
}

/// `GET /v1/invoices/issuer` — the letterhead as it stands, and what is missing
/// from it.
async fn read_issuer(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let issuer = invoices::issuer(&mut tx).await?;
    tx.rollback().await?;
    let missing = issuer.missing_mentions();
    Ok(Json(json!({
        "name": issuer.name,
        "issuer": IssuerBody::from(issuer),
        "missing": missing,
    }))
    .into_response())
}

/// `PUT /v1/invoices/issuer` — write this company's obligatory mentions.
///
/// A whole replacement, `agentos_store::invoices::set_issuer`'s rule: these
/// fields are one letterhead and a patch is how a company keeps claiming a VAT
/// number it no longer has. The name is not in the body — it is `tenants.name`,
/// which this route may not rewrite; a company that renamed itself did so
/// through the surface that owns its identity.
///
/// Refused with the mentions named when the result would not be issuable, which
/// is the same refusal [`refuse_without_mentions`] makes and the reason a
/// half-filled letterhead cannot be stored and discovered a month later on a
/// document a customer already has.
async fn write_issuer(
    State(db): State<Db>,
    principal: Principal,
    Json(body): Json<IssuerBody>,
) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let name = invoices::issuer(&mut tx).await?.name;
    let issuer = body.into_issuer(name);

    // 0087 refuses these two at the database and would surface a `23514` as a
    // 500 — "we broke" — for a body the founder fixes by deleting a field.
    if issuer.vat_rate_bp.is_some() && issuer.vat_exemption_reason.is_some() {
        tx.rollback().await?;
        return Err(ApiError::bad_request(
            "a company either charges VAT at a rate or says why it does not; sending both leaves \
             the document with two answers to the same question",
        ));
    }
    if issuer.vat_rate_bp.is_some() && issuer.vat_number.is_none() {
        tx.rollback().await?;
        return Err(ApiError::bad_request(
            "a company that charges VAT has an intra-community VAT number, and an invoice must \
             print it",
        ));
    }
    let missing = issuer.missing_mentions();
    if !missing.is_empty() {
        tx.rollback().await?;
        return Err(ApiError::conflict(
            "issuer_mentions_missing",
            "this letterhead would not be issuable",
        )
        .with_detail(format!(
            "a French invoice must carry these mentions of its issuer and this body does not \
             supply them: {}",
            missing.join(", ")
        ))
        .with_extension("missing", json!(missing)));
    }

    invoices::set_issuer(&mut tx, &issuer).await?;
    tx.commit().await?;
    Ok(
        Json(json!({ "issuer": IssuerBody::from(issuer), "missing": Vec::<&str>::new() }))
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::money::{Currency, Money};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY};

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Two companies behind two keys, under the real middleware stack.
    /// `routes::calendar`'s harness, and the second company is the point: a
    /// register another tenant can settle is not a register.
    struct Harness {
        app: Router,
        a: TenantId,
    }

    impl Harness {
        async fn new(db: &Db) -> Self {
            let a = new_tenant(db).await;
            let b = new_tenant(db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            // `b` is not kept: what the second company is for is its *key*,
            // which the tests use to prove that another tenant's register is
            // invisible and unsettleable. Holding its id would be a field
            // nothing reads.
            let _ = b;
            Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    Keyring::new(keys, db.clone(), TEST_MASTER_KEY),
                ),
                a,
            }
        }

        async fn send(&self, method: &str, uri: &str, secret: &str) -> (StatusCode, Value) {
            self.send_body(method, uri, secret, Body::empty()).await
        }

        /// The same request with a JSON body, for the one route that takes one.
        async fn send_json(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Value,
        ) -> (StatusCode, Value) {
            self.send_body(method, uri, secret, Body::from(body.to_string()))
                .await
        }

        async fn send_body(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Body,
        ) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", Uuid::now_v7().to_string())
                .body(body)
                .expect("request");
            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }
    }

    /// A company that may issue: with the mentions `0087` makes obligatory,
    /// because every test below that emits a document would otherwise be
    /// testing the refusal. The one that *is* about the refusal wipes them
    /// again — see [`wipe_mentions`].
    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO tenants \
                 (id, slug, name, legal_form, postal_address, siren, rcs_city, vat_number, \
                  vat_rate_bp, late_penalty_rate_bp) \
             VALUES ($1, $2, 'invoice-routes-test', 'SAS', '1 rue du Test, 75001 Paris', \
                     '123456789', 'Paris', 'FR12123456789', 2000, 1200)",
        )
        .bind(tenant.as_uuid())
        .bind(tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Put a company back where `0087` found it: no mentions at all.
    async fn wipe_mentions(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "UPDATE tenants SET legal_form = NULL, postal_address = NULL, siren = NULL, \
                                rcs_city = NULL, vat_number = NULL, vat_rate_bp = NULL, \
                                vat_exemption_reason = NULL, late_penalty_rate_bp = NULL \
              WHERE id = $1",
        )
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("wipe");
        tx.commit().await.expect("commit");
    }

    /// One issued invoice for `tenant`, through the same store call the gated
    /// effect uses — there is no operator route that issues, and that absence is
    /// the module's design rather than a gap in this fixture.
    async fn issued(db: &Db, tenant: TenantId) -> InvoiceId {
        let employee = EmployeeId::new_v7(Utc::now());
        let account = Uuid::now_v7();
        let opportunity = Uuid::now_v7();
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, 'Lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        // The whole uuid and not a prefix of it: a v7's leading hex digits are
        // the clock, so two seats minted in the same second inside one test
        // collided on `employees_tenant_slug_key`.
        .bind(format!("lena-{}", employee.as_uuid().simple()))
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
             VALUES ($1, $2, $3, 'closed_won', 'EUR', 120000, $4, now())",
        )
        .bind(opportunity)
        .bind(tenant.as_uuid())
        .bind(account)
        .bind(Uuid::now_v7())
        .execute(&mut *tx)
        .await
        .expect("opportunity");
        tx.commit().await.expect("commit the deal");

        let id = InvoiceId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        invoices::issue(
            &mut tx,
            invoices::Draft {
                id,
                opportunity_id: opportunity,
                issued_by: employee,
                amount: Money::new(120_000, Currency::Eur).expect("nonzero"),
                memo: "March",
                due_at: None,
                lines: &[invoices::Line {
                    description: "One month of the service".to_owned(),
                    amount_minor: 120_000,
                    // The founder's, and null until they say: see 0071.
                    tax_rate_bp: None,
                }],
            },
        )
        .await
        .expect("issue");
        tx.commit().await.expect("commit the invoice");
        id
    }

    /// **The encashment, end to end, and the two things that must not happen
    /// after it**: it cannot be declared twice, and another company cannot
    /// declare it at all.
    #[tokio::test]
    async fn a_settlement_is_declared_once_and_only_by_the_company_that_is_owed() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the register needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let invoice = issued(&db, h.a).await;
        let uri = format!("/v1/invoices/{}/paid", invoice.as_uuid());

        let (status, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["invoices"].as_array().expect("array").len(), 1);
        assert_eq!(body["invoices"][0]["paid_at"], Value::Null);
        assert_eq!(body["outstanding_minor"]["EUR"], json!(120_000));

        // Another company's key: the same silence a request for an invoice that
        // does not exist gets, because under RLS the two are the same fact.
        let (status, _) = h.send("POST", &uri, SECRET_B).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // And it saw nothing either.
        let (_, theirs) = h.send("GET", "/v1/invoices", SECRET_B).await;
        assert!(theirs["invoices"].as_array().expect("array").is_empty());

        let (status, body) = h.send("POST", &uri, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], json!("paid"));

        // Twice is not a second settlement. Same code as "no such invoice", on
        // purpose: both mean "there is no outstanding invoice here to settle".
        let (status, _) = h.send("POST", &uri, SECRET_A).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // One `invoice_paid` row, from the key that settled it, naming the
        // operator as its source — and one after the replay, because the row
        // rides the call `declare_paid` answered `true` to and no other.
        let mut tx = db.tenant_tx(h.a).await.expect("tx");
        let rows: Vec<(String, Value)> = sqlx::query_as(
            "SELECT actor, payload FROM audit_log WHERE action_kind = 'invoice_paid' \
             ORDER BY occurred_at, id",
        )
        .fetch_all(&mut **tx)
        .await
        .expect("read the trail");
        tx.rollback().await.expect("rollback");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, "operator:ops-a");
        assert_eq!(rows[0].1["source"], json!("operator"));
        assert_eq!(rows[0].1["invoice_id"], json!(invoice.as_uuid()));

        let (_, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        assert_ne!(body["invoices"][0]["paid_at"], Value::Null);
        assert_eq!(
            body["outstanding_minor"].as_object().expect("object").len(),
            0,
            "a settled invoice is not owed"
        );
        // The register still shows it: what came in is half of what a founder
        // reads at the end of a month.
        assert_eq!(body["invoices"].as_array().expect("array").len(), 1);
    }

    /// **A memo this table will not take is the caller's mistake, not ours.**
    ///
    /// `credit` puts `memo` straight into `invoices` and `invoices_memo_shape`
    /// is `char_length(btrim(memo)) between 1 and 200`. Left to the `CHECK`, a
    /// blank line or a 201-character sentence arrives as a `23514` in
    /// [`StoreError::Database`], which [`ApiError`] answers **500** — "we
    /// broke" — for a body the founder fixes by shortening a sentence. It is
    /// the defect `routes::work` found on `title` and
    /// `agentos_app::calendar` found on `subject`, on the third column of the
    /// same shape.
    ///
    /// The last assertion is the half a length check alone would not prove:
    /// a refused memo must not have claimed a number, or the run this table
    /// exists to keep gap-free acquires a hole for every typo.
    #[tokio::test]
    async fn a_credit_note_memo_the_table_will_not_take_is_a_400_and_not_a_500() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the register needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let invoice = issued(&db, h.a).await;
        let uri = format!("/v1/invoices/{}/credit", invoice.as_uuid());

        for memo in ["", "   ", &"x".repeat(201)] {
            let (status, problem) = h
                .send_json(
                    "POST",
                    &uri,
                    SECRET_A,
                    json!({"amount_minor": 1, "memo": memo}),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a memo of {} characters answered {status}: {problem}",
                memo.chars().count()
            );
        }

        // …and the longest one the table does take still lands.
        let (status, note) = h
            .send_json(
                "POST",
                &uri,
                SECRET_A,
                json!({"amount_minor": 1, "memo": "m".repeat(200)}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "200 characters is the bound: {note}"
        );
        assert_eq!(
            note["number"],
            json!(2),
            "the three refusals took no number with them: a run with a gap in it is the \
             failure 0071 exists to prevent"
        );
    }

    /// **The correction, end to end**: what the founder can do about an invoice
    /// that went out wrong, now that editing it is still impossible.
    ///
    /// Four refusals and one acceptance, and the interesting one is the last:
    /// crediting twice is a 409 rather than a second document, because 0071
    /// makes it a unique index instead of a sum somebody read too early.
    #[tokio::test]
    async fn a_credit_note_withdraws_part_of_a_demand_and_nets_the_register() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the register needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let invoice = issued(&db, h.a).await;
        let uri = format!("/v1/invoices/{}/credit", invoice.as_uuid());

        // The invoice as issued: number one of this company's run, with the one
        // line it is made of and no tax rate on it.
        let (_, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        assert_eq!(body["invoices"][0]["number"], json!(1));
        assert_eq!(
            body["invoices"][0]["lines"][0]["amount_minor"],
            json!(120_000)
        );
        assert_eq!(body["invoices"][0]["lines"][0]["tax_rate_bp"], Value::Null);
        assert_eq!(body["invoices"][0]["due_at"], Value::Null);

        // Another company cannot credit what it was never owed.
        let (status, _) = h
            .send_json(
                "POST",
                &uri,
                SECRET_B,
                json!({"amount_minor": 1, "memo": "theirs"}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Nor can this one credit more than it asked for.
        let (status, _) = h
            .send_json(
                "POST",
                &uri,
                SECRET_A,
                json!({"amount_minor": 120_001, "memo": "too much"}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, note) = h
            .send_json(
                "POST",
                &uri,
                SECRET_A,
                json!({"amount_minor": 20_000, "memo": "Two seats were never provisioned"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{note}");
        assert_eq!(note["number"], json!(2), "one run, both documents");
        assert_eq!(note["corrects_invoice_id"], json!(invoice.as_uuid()));
        assert_eq!(
            note["issued_by"],
            Value::Null,
            "a credit note is an operator's act, not a seat's"
        );

        let (_, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        assert_eq!(
            body["invoices"].as_array().expect("array").len(),
            2,
            "a corrected invoice is not removed; the correction sits beside it"
        );
        assert_eq!(
            body["outstanding_minor"]["EUR"],
            json!(100_000),
            "what is owed is what was demanded less what was withdrawn"
        );

        // Twice is a conflict and not a second document.
        let (status, _) = h
            .send_json(
                "POST",
                &uri,
                SECRET_A,
                json!({"amount_minor": 1, "memo": "again"}),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // And the run has no hole where the three refusals were: the next
        // document this company issues is number three.
        let next = issued(&db, h.a).await;
        let (_, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        let numbers: Vec<_> = body["invoices"]
            .as_array()
            .expect("array")
            .iter()
            .map(|invoice| invoice["number"].clone())
            .collect();
        assert_eq!(numbers, vec![json!(1), json!(2), json!(3)]);
        let _ = next;

        // --- and the window, on the one fixture that has all three shapes ----
        //
        // Here rather than in a test of its own: a filter is only interesting
        // against a register that holds something it must *leave out*, and the
        // three documents above are exactly that — two demands and a credit
        // note. A fixture built for the window alone would have been a second
        // copy of this one with the interesting row missing.
        let total = body["outstanding_minor"].clone();

        let (_, owed) = h
            .send("GET", "/v1/invoices?state=outstanding", SECRET_A)
            .await;
        let cut: Vec<_> = owed["invoices"]
            .as_array()
            .expect("array")
            .iter()
            .map(|invoice| invoice["number"].clone())
            .collect();
        assert_eq!(
            cut,
            vec![json!(1), json!(3)],
            "a credit note is owed by nobody and has no business in this cut"
        );
        assert_eq!(
            owed["outstanding_minor"], total,
            "the total is the register's, not the page's — it must not move with the filter"
        );

        // The arm filters rather than falling through to "no filter", which is
        // the way a `CASE` over a parameter fails quietly.
        let (_, paid) = h.send("GET", "/v1/invoices?state=paid", SECRET_A).await;
        assert!(
            paid["invoices"].as_array().expect("array").is_empty(),
            "nobody has settled anything in this company: {paid}"
        );

        // One document per page, walked by number, and the total holds all the
        // way down.
        let mut walked = Vec::new();
        let mut uri = "/v1/invoices?limit=1".to_owned();
        loop {
            let (_, page) = h.send("GET", &uri, SECRET_A).await;
            assert_eq!(page["outstanding_minor"], total, "the total shrank: {page}");
            let rows = page["invoices"].as_array().expect("array");
            walked.extend(rows.iter().map(|invoice| invoice["number"].clone()));
            assert!(walked.len() <= 3, "the cursor is looping: {walked:?}");
            let Some(after) = page["next_after"].as_i64() else {
                break;
            };
            uri = format!("/v1/invoices?limit=1&after={after}");
        }
        assert_eq!(walked, numbers, "the walk and the whole register disagree");

        // A `state` this route does not know is a 400 and never a silent
        // "no filter", which would answer a question nobody asked with a
        // longer list that looks right.
        let (status, refused) = h.send("GET", "/v1/invoices?state=late", SECRET_A).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    }

    /// **A company with no letterhead may not emit a document**, and the refusal
    /// names every mention it is missing rather than saying "invalid".
    ///
    /// The whole round trip: refused, refused again on a half-filled `PUT`,
    /// accepted on a complete one, and only then does a document leave.
    #[tokio::test]
    async fn a_document_is_refused_until_the_issuer_mentions_are_written_down() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the register needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let invoice = issued(&db, h.a).await;
        let uri = format!("/v1/invoices/{}/credit", invoice.as_uuid());
        wipe_mentions(&db, h.a).await;

        let all = json!([
            "legal_form",
            "postal_address",
            "siren",
            "rcs_city",
            "vat_rate_bp_or_vat_exemption_reason",
            "late_penalty_rate_bp",
        ]);

        // The register still reads — a company that cannot issue is not a
        // company whose books are sealed — and says what it is missing.
        let (status, body) = h.send("GET", "/v1/invoices/issuer", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["missing"], all);

        let (status, problem) = h
            .send_json(
                "POST",
                &uri,
                SECRET_A,
                json!({"amount_minor": 1, "memo": "trop tard"}),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{problem}");
        assert_eq!(problem["code"], json!("issuer_mentions_missing"));
        assert_eq!(problem["missing"], all, "{problem}");
        let detail = problem["detail"].as_str().expect("a detail");
        for mention in all.as_array().expect("array") {
            assert!(
                detail.contains(mention.as_str().expect("a name")),
                "the detail does not name {mention}: {detail}"
            );
        }

        // The refusal took no number with it: the run is still at two.
        let (_, body) = h.send("GET", "/v1/invoices", SECRET_A).await;
        assert_eq!(body["invoices"].as_array().expect("array").len(), 1);

        // A half letterhead is refused by the same list, so it cannot be stored
        // and discovered later on a document a customer already has.
        let (status, problem) = h
            .send_json(
                "PUT",
                "/v1/invoices/issuer",
                SECRET_A,
                json!({"legal_form": "SAS", "siren": "123456789"}),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{problem}");
        assert_eq!(
            problem["missing"],
            json!([
                "postal_address",
                "rcs_city",
                "vat_rate_bp_or_vat_exemption_reason",
                "late_penalty_rate_bp",
            ])
        );

        // Nor may it claim a rate with no intra-community number, which 0087
        // refuses at the database and this refuses first, as a 400 rather than
        // as the 500 a `23514` would have been.
        let (status, _) = h
            .send_json(
                "PUT",
                "/v1/invoices/issuer",
                SECRET_A,
                json!({
                    "legal_form": "SAS",
                    "postal_address": "1 rue du Test",
                    "siren": "123456789",
                    "rcs_city": "Paris",
                    "vat_rate_bp": 2000,
                    "late_penalty_rate_bp": 1200,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A company outside VAT completes its letterhead with a sentence and
        // not with a zero: `vat_rate_bp` stays absent.
        let complete = json!({
            "legal_form": "SAS",
            "postal_address": "1 rue du Test, 75001 Paris",
            "siren": "123456789",
            "rcs_city": "Paris",
            "vat_exemption_reason": "TVA non applicable, art. 293 B du CGI",
            "late_penalty_rate_bp": 1200,
        });
        let (status, body) = h
            .send_json("PUT", "/v1/invoices/issuer", SECRET_A, complete)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["missing"], json!([]));
        assert_eq!(body["issuer"]["vat_rate_bp"], Value::Null);

        // And now the document leaves.
        let (status, note) = h
            .send_json(
                "POST",
                &uri,
                SECRET_A,
                json!({"amount_minor": 1, "memo": "avec les mentions"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{note}");
        assert_eq!(note["number"], json!(2), "the refusals took no number");
    }
}
