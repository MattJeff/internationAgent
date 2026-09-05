//! `GET /v1/accounting/export?days=N&journal=invoices|spend|usage`: the books
//! [`super::pnl`] aggregates, one CSV line per movement, for a human
//! accountant's tool.
//!
//! # Why a CSV beside the JSON
//!
//! The finance pack answers the founder — `/v1/invoices`, `/v1/pnl`,
//! `/v1/billing` — and every one of them is JSON with the arithmetic already
//! done. An accountant has none of those tools and does the arithmetic
//! themselves, in a spreadsheet or a ledger package, from one line per
//! movement. So this is the same matter as `pnl`, **read line by line instead of
//! aggregated**, and the one requirement that matters is [`super::billing`]'s:
//! *a customer who cannot verify an invoice pays it once*. Summed over the same
//! window, the lines of a journal give exactly the figures `/v1/pnl` reports —
//! same window parser ([`PnlQuery`]), same UTC calendar-day bucketing, same
//! `Money` — and the test that counts is the one that sums the CSV and
//! compares.
//!
//! # The three journals
//!
//! * `invoices` — every document (invoice or credit note) **issued or paid in
//!   the window**. A document issued before the window and paid inside it is a
//!   line here, because its amount is in `pnl`'s `invoices_paid`; the reader
//!   sums by `issued_on` for what was issued and by `paid_on` for what was
//!   collected. A credit note carries the number of the invoice it corrects and
//!   lands on that invoice's seat, as `pnl` lands it.
//! * `spend` — every reservation whose day is in the window, in all three
//!   states. `released` is a line too — it is a movement the reader may want
//!   to see — but it is money nobody moved, and `pnl` does not count it. The
//!   store carries no counterparty or purpose on a reservation (`0003`), so
//!   there is no such column rather than an empty one.
//! * `usage` — one line per seat and day from `model_usage_daily`, with the
//!   cost at the declared tariff. **Empty without a tariff, never zero**:
//!   `0024`'s rule, unknown is not free. With a partial tariff the figure is a
//!   floor, exactly as `pnl` computes it (`coalesce(rate, 0)`).
//!
//! # Amounts
//!
//! Decimal text, never a float: `1200.00` from [`Money`]'s own rendering, so
//! the CSV and the JSON cannot disagree about where the point goes. The usage
//! cost is the one figure that is not a `Money`: `pnl` rounds a seat's whole
//! window to the cent *once*, so a line here carries the **exact** product
//! (`tokens × rate / 1e6`, trailing zeros trimmed) and the reader who sums the
//! lines and rounds once gets `pnl`'s cents. Rounding each line would not add
//! up — two half-cents are one cent, not two.
//!
//! # The cells, and the trust boundary in them
//!
//! RFC 4180 by hand ([`cell`]): a cell holding a quote, a comma or a line break
//! is quoted and its quotes doubled. And every cell is **neutralised against
//! formula injection**: a spreadsheet that opens this file executes a cell
//! beginning with `=`, `+`, `-`, `@`, tab or CR, so a buyer whose legal name is
//! `=HYPERLINK(...)` would run in the accountant's tool. Such a cell gets a
//! leading apostrophe, which every spreadsheet reads as "text". A buyer's legal
//! name is third-party text and crosses this file as [`Untrusted`], leaving the
//! wrapper in exactly one place, [`text`], where that escaping is the answer.

use agentos_domain::money::Money;
use agentos_domain::untrusted::Untrusted;
use agentos_store::db::{Db, StoreError};
use agentos_store::model_access::{self, CostSource};
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::NaiveDate;
use serde::Deserialize;
use uuid::Uuid;

use super::pnl::{PnlQuery, money};
use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/accounting/export", get_route(export))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The query
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Journal {
    Invoices,
    Spend,
    Usage,
}

impl Journal {
    fn name(self) -> &'static str {
        match self {
            Journal::Invoices => "invoices",
            Journal::Spend => "spend",
            Journal::Usage => "usage",
        }
    }
}

/// [`PnlQuery`]'s window plus the journal. Spelled out rather than flattened:
/// `serde(flatten)` over a query string loses the integer typing of `days`.
#[derive(Debug, Deserialize)]
struct ExportQuery {
    journal: Journal,
    days: Option<i64>,
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
}

// ---------------------------------------------------------------------------
// The cells
// ---------------------------------------------------------------------------

/// One RFC 4180 cell, neutralised against formula injection. See the module
/// docs for why every cell, not only the hostile ones: a number never begins
/// with one of those characters, so it costs nothing, and a rule with no
/// exceptions has no cell somebody forgot.
fn cell(raw: &str) -> String {
    let guarded = if raw.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{raw}")
    } else {
        raw.to_owned()
    };
    if guarded.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// The one place third-party text leaves its wrapper on this path. The
/// destination is a data cell, never an instruction slot, and [`cell`] is the
/// escaping.
fn text(untrusted: Untrusted<String>) -> String {
    cell(&untrusted.into_inner_for_rendering())
}

fn line(cells: &[String]) -> String {
    let mut out = cells.join(",");
    out.push_str("\r\n");
    out
}

/// `1200.00` — [`Money`]'s `EUR 1200.00` without the code, which has its own
/// column.
fn amount(money: Money) -> String {
    let rendered = money.to_string();
    rendered
        .split_once(' ')
        .map_or(rendered.clone(), |(_, figure)| figure.to_owned())
}

/// A NUMERIC's text with its trailing zeros trimmed, two decimals at least:
/// `0.0057000000` → `0.0057`, `3.0000000000` → `3.00`.
fn decimal(numeric: &str) -> String {
    match numeric.split_once('.') {
        Some((int, frac)) => format!("{int}.{:0<2}", frac.trim_end_matches('0')),
        None => format!("{numeric}.00"),
    }
}

fn date(day: Option<NaiveDate>) -> String {
    day.map(|d| d.to_string()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The journals
// ---------------------------------------------------------------------------
//
// Every statement: no `WHERE tenant_id` (RLS), `$1` the first day, `$2` the
// day after the last, and timestamps bucketed by UTC calendar day as `pnl`
// buckets them — that is what makes the sums equal.

#[derive(Debug, sqlx::FromRow)]
struct InvoiceLine {
    number: i64,
    credit_note: bool,
    issued_on: NaiveDate,
    due_on: Option<NaiveDate>,
    paid_on: Option<NaiveDate>,
    account: String,
    currency: String,
    amount_minor: i64,
    corrects_invoice_number: Option<i64>,
    issued_by: Option<String>,
}

const INVOICES_HEADER: &str = "number,type,issued_on,due_on,paid_on,account,currency,amount,corrects_invoice_number,issued_by";

/// Issued or paid in the window; a credit note's seat is its invoice's, as
/// `pnl::CREDIT_NOTES_SQL` attributes it.
const INVOICES_SQL: &str = "\
SELECT i.number, \
       i.corrects_invoice_id IS NOT NULL       AS credit_note, \
       (i.issued_at AT TIME ZONE 'UTC')::date  AS issued_on, \
       (i.due_at AT TIME ZONE 'UTC')::date     AS due_on, \
       (i.paid_at AT TIME ZONE 'UTC')::date    AS paid_on, \
       a.legal_name                            AS account, \
       i.currency, i.amount_minor, \
       o.number                                AS corrects_invoice_number, \
       e.slug                                  AS issued_by \
  FROM invoices i \
  JOIN opportunities op ON op.id = i.opportunity_id \
  JOIN accounts a ON a.id = op.account_id \
  LEFT JOIN invoices o ON o.id = i.corrects_invoice_id \
  LEFT JOIN employees e ON e.id = coalesce(i.issued_by, o.issued_by) \
 WHERE ((i.issued_at AT TIME ZONE 'UTC')::date >= $1 AND (i.issued_at AT TIME ZONE 'UTC')::date < $2) \
    OR ((i.paid_at   AT TIME ZONE 'UTC')::date >= $1 AND (i.paid_at   AT TIME ZONE 'UTC')::date < $2) \
 ORDER BY i.number";

#[derive(Debug, sqlx::FromRow)]
struct SpendLine {
    day: NaiveDate,
    employee: String,
    currency: String,
    amount_minor: i64,
    state: String,
    reservation_id: Uuid,
}

const SPEND_HEADER: &str = "day,employee,currency,amount,state,reservation_id";

const SPEND_SQL: &str = "\
SELECT r.day, e.slug AS employee, r.currency, r.amount_minor, r.state, r.id AS reservation_id \
  FROM spend_reservations r \
  JOIN employees e ON e.id = r.employee_id \
 WHERE r.day >= $1 AND r.day < $2 \
 ORDER BY r.day, e.slug, r.created_at, r.id";

#[derive(Debug, sqlx::FromRow)]
struct UsageLine {
    day: NaiveDate,
    employee: String,
    calls: i64,
    calls_unmetered: i64,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_tokens: i64,
    /// The exact product as NUMERIC text; see the module docs on rounding.
    cost_usd: String,
}

const USAGE_HEADER: &str =
    "day,employee,calls,calls_unmetered,tokens_input,tokens_output,tokens_cache_read,cost_usd";

/// `pnl::USAGE_SQL`'s arithmetic per row and unrounded: `/ 1000000` is tokens
/// per million, `round(…, 10)` only fixes the scale of the text.
const USAGE_SQL: &str = "\
SELECT u.day, e.slug AS employee, \
       u.calls, u.calls_unmetered, u.input_tokens, u.output_tokens, u.cache_read_tokens, \
       round(( u.input_tokens      * coalesce(t.usd_per_mtok_input, 0) \
             + u.output_tokens     * coalesce(t.usd_per_mtok_output, 0) \
             + u.cache_read_tokens * coalesce(t.usd_per_mtok_cache_read, 0) \
             ) / 1000000, 10)::text AS cost_usd \
  FROM model_usage_daily u \
  JOIN employees e ON e.id = u.employee_id \
  LEFT JOIN tenant_model_access t ON true \
 WHERE u.day >= $1 AND u.day < $2 \
 ORDER BY u.day, e.slug";

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

/// `GET /v1/accounting/export?journal=…&days=N`.
///
/// 200 with the header line alone for a tenant that moved nothing: an empty
/// journal is a fact, and a file with a header is what the tool expects.
async fn export(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<ExportQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let window = PnlQuery {
        days: query.days,
        from: query.from,
        to: query.to,
    }
    .resolve()?;
    let (from, end) = (window.from, window.end());

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let mut out = String::new();
    match query.journal {
        Journal::Invoices => {
            out.push_str(INVOICES_HEADER);
            out.push_str("\r\n");
            let rows: Vec<InvoiceLine> = sqlx::query_as(INVOICES_SQL)
                .bind(from)
                .bind(end)
                .fetch_all(&mut **tx)
                .await
                .map_err(StoreError::from)?;
            for row in rows {
                let figure = money(&row.currency, row.amount_minor)?;
                out.push_str(&line(&[
                    cell(&row.number.to_string()),
                    cell(if row.credit_note {
                        "credit_note"
                    } else {
                        "invoice"
                    }),
                    cell(&row.issued_on.to_string()),
                    cell(&date(row.due_on)),
                    cell(&date(row.paid_on)),
                    text(Untrusted::new(row.account)),
                    cell(&row.currency),
                    cell(&amount(figure)),
                    cell(
                        &row.corrects_invoice_number
                            .map(|n| n.to_string())
                            .unwrap_or_default(),
                    ),
                    cell(&row.issued_by.unwrap_or_default()),
                ]));
            }
        }
        Journal::Spend => {
            out.push_str(SPEND_HEADER);
            out.push_str("\r\n");
            let rows: Vec<SpendLine> = sqlx::query_as(SPEND_SQL)
                .bind(from)
                .bind(end)
                .fetch_all(&mut **tx)
                .await
                .map_err(StoreError::from)?;
            for row in rows {
                let figure = money(&row.currency, row.amount_minor)?;
                out.push_str(&line(&[
                    cell(&row.day.to_string()),
                    cell(&row.employee),
                    cell(&row.currency),
                    cell(&amount(figure)),
                    cell(&row.state),
                    cell(&row.reservation_id.to_string()),
                ]));
            }
        }
        Journal::Usage => {
            out.push_str(USAGE_HEADER);
            out.push_str("\r\n");
            let priced =
                CostSource::of(model_access::load(&mut tx).await?.as_ref()) != CostSource::NoTariff;
            let rows: Vec<UsageLine> = sqlx::query_as(USAGE_SQL)
                .bind(from)
                .bind(end)
                .fetch_all(&mut **tx)
                .await
                .map_err(StoreError::from)?;
            for row in rows {
                out.push_str(&line(&[
                    cell(&row.day.to_string()),
                    cell(&row.employee),
                    cell(&row.calls.to_string()),
                    cell(&row.calls_unmetered.to_string()),
                    cell(&row.input_tokens.to_string()),
                    cell(&row.output_tokens.to_string()),
                    cell(&row.cache_read_tokens.to_string()),
                    cell(&if priced {
                        decimal(&row.cost_usd)
                    } else {
                        String::new()
                    }),
                ]));
            }
        }
    }
    tx.rollback().await?;

    let disposition = format!(
        "attachment; filename=\"{}-{}-{}.csv\"",
        query.journal.name(),
        window.from,
        window.to
    );
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_owned()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        out,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use agentos_domain::ids::InvoiceId;
    use agentos_store::invoices::{self, Draft};
    use agentos_store::model_usage::{self, Consumed};
    use agentos_store::spend::{self, SpendCaps};
    use axum::http::StatusCode;
    use chrono::{Duration, Utc};
    use serde_json::{Value, json};

    use super::super::pnl::tests::{Harness, SECRET_A, SECRET_B, employee, eur, won_deal};
    use super::*;

    /// The hostile buyer: a formula, a quoted comma pair and a line break.
    const HOSTILE: &str = "=HYPERLINK(\"http://evil\")\n\"a\",\"b\"";

    #[test]
    fn a_cell_is_escaped_and_a_formula_is_neutralised() {
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("1200.00"), "1200.00");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("two\nlines"), "\"two\nlines\"");
        assert_eq!(cell("=1+1"), "'=1+1");
        assert_eq!(cell("+1"), "'+1");
        assert_eq!(cell("-1"), "'-1");
        assert_eq!(cell("@SUM"), "'@SUM");
        assert_eq!(cell("\tx"), "'\tx");
        assert_eq!(cell("\rx"), "\"'\rx\"");
        assert_eq!(
            cell(HOSTILE),
            "\"'=HYPERLINK(\"\"http://evil\"\")\n\"\"a\"\",\"\"b\"\"\""
        );
        assert_eq!(decimal("0.0057000000"), "0.0057");
        assert_eq!(decimal("3.0000000000"), "3.00");
        assert_eq!(decimal("0.1000000000"), "0.10");
        assert_eq!(decimal("12"), "12.00");
        assert_eq!(amount(eur(120_050)), "1200.50");
    }

    /// RFC 4180 back the other way, enough to read what [`export`] writes.
    fn parse(csv: &str) -> Vec<Vec<String>> {
        let (mut rows, mut row, mut cell) = (Vec::new(), Vec::new(), String::new());
        let mut quoted = false;
        let mut chars = csv.chars().peekable();
        while let Some(c) = chars.next() {
            if quoted {
                if c != '"' {
                    cell.push(c);
                } else if chars.peek() == Some(&'"') {
                    chars.next();
                    cell.push('"');
                } else {
                    quoted = false;
                }
            } else {
                match c {
                    '"' => quoted = true,
                    ',' => row.push(std::mem::take(&mut cell)),
                    '\r' => {}
                    '\n' => {
                        row.push(std::mem::take(&mut cell));
                        rows.push(std::mem::take(&mut row));
                    }
                    _ => cell.push(c),
                }
            }
        }
        assert!(cell.is_empty() && row.is_empty(), "the file ends in CRLF");
        rows
    }

    /// `1200.50` → 120050, for a two-decimal currency.
    fn minor(figure: &str) -> i64 {
        figure.replace('.', "").parse().expect("decimal text")
    }

    /// An exact decimal scaled to ten places, so lines can be summed without
    /// a float and rounded once to the cent.
    fn tenths(figure: &str) -> i128 {
        let (int, frac) = figure.split_once('.').unwrap_or((figure, ""));
        let int: i128 = int.parse().expect("integer part");
        let frac: i128 = format!("{frac:0<10}").parse().expect("fraction");
        int * 10_i128.pow(10) + frac
    }

    fn cents(tenths: i128) -> i64 {
        i64::try_from((tenths + 50_000_000) / 100_000_000).expect("cents")
    }

    fn column<'a>(rows: &'a [Vec<String>], header: &[String], name: &str) -> Vec<&'a str> {
        let i = header
            .iter()
            .position(|h| h == name)
            .unwrap_or_else(|| panic!("column {name} in {header:?}"));
        rows.iter().map(|r| r[i].as_str()).collect()
    }

    fn pnl_minor(body: &Value, ledger: &str) -> i64 {
        body["totals"][ledger]["amounts"]["EUR"]["minor"]
            .as_i64()
            .unwrap_or(0)
    }

    /// Two invoices (one collected), a credit note, three spends (settled,
    /// outstanding, released), two days of usage at a tariff that prices a
    /// day below the cent — and each journal, read back, foots to `/v1/pnl`
    /// over the same window. The buyer's name is hostile and comes out inert.
    #[tokio::test]
    async fn each_journal_reads_back_and_foots_to_the_pnl() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;
        let deal = won_deal(&h.db, h.a, HOSTILE).await;
        let now = Utc::now();
        let today = now.date_naive();
        let yesterday = today - Duration::days(1);

        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        // 1900 tokens × 3 USD/Mtok = 0.0057 USD a day: each day rounds to a
        // cent on its own, the two together round to one.
        for day in [yesterday, today] {
            model_usage::record(&mut tx, lena, day, Consumed::reported(2, 1_900, 0, 0))
                .await
                .expect("record");
        }
        let paid = invoices::issue(
            &mut tx,
            Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: deal,
                issued_by: lena,
                amount: eur(120_050),
                memo: "onboarding",
                due_at: Some(now + Duration::days(30)),
                lines: &[],
            },
        )
        .await
        .expect("issue");
        assert!(
            invoices::declare_paid(&mut tx, paid.id, paid.issued_at)
                .await
                .expect("paid")
        );
        let wrong = invoices::issue(
            &mut tx,
            Draft {
                id: InvoiceId::new_v7(now),
                opportunity_id: deal,
                issued_by: lena,
                amount: eur(30_000),
                memo: "a mistake",
                due_at: None,
                lines: &[],
            },
        )
        .await
        .expect("issue");
        invoices::credit(&mut tx, InvoiceId::new_v7(now), wrong.id, 30_000, "undone")
            .await
            .expect("credit");
        spend::set_caps(
            &mut tx,
            lena,
            SpendCaps::new(eur(100_000), eur(50_000), NonZeroU32::new(10).expect("ten"))
                .expect("caps"),
        )
        .await
        .expect("caps");
        let settled = spend::reserve(&mut tx, lena, today, eur(10_000))
            .await
            .expect("reserve");
        spend::settle(&mut tx, &settled).await.expect("settle");
        spend::reserve(&mut tx, lena, yesterday, eur(5_000))
            .await
            .expect("reserve");
        let released = spend::reserve(&mut tx, lena, today, eur(7_000))
            .await
            .expect("reserve");
        spend::release(&mut tx, &released).await.expect("release");
        tx.commit().await.expect("commit");

        // Before a tariff: the usage journal prices nothing, and says so by
        // saying nothing.
        let (status, _, csv) = h
            .get_raw("/v1/accounting/export?days=2&journal=usage", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{csv}");
        let rows = parse(&csv);
        assert_eq!(rows.len(), 3, "{csv}");
        assert!(
            column(&rows[1..], &rows[0], "cost_usd")
                .iter()
                .all(|c| c.is_empty()),
            "unknown is not zero: {csv}"
        );

        let (status, body) = h
            .call(
                "POST",
                "/v1/model",
                SECRET_A,
                Some(json!({"path": "cli", "usd_per_mtok_input": 3, "usd_per_mtok_output": 15, "usd_per_mtok_cache_read": 0.3})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, pnl) = h.call("GET", "/v1/pnl?days=2", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{pnl}");

        // invoices
        let (status, headers, csv) = h
            .get_raw("/v1/accounting/export?days=2&journal=invoices", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{csv}");
        assert_eq!(headers["content-type"], "text/csv; charset=utf-8");
        assert_eq!(
            headers["content-disposition"],
            format!("attachment; filename=\"invoices-{yesterday}-{today}.csv\"")
        );
        assert!(csv.ends_with("\r\n"), "RFC 4180 line ends");
        assert!(
            csv.contains("\"'=HYPERLINK(\"\"http://evil\"\")\n\"\"a\"\",\"\"b\"\"\""),
            "the hostile name is quoted, doubled and neutralised: {csv}"
        );
        let rows = parse(&csv);
        let (header, lines) = (&rows[0], &rows[1..]);
        assert_eq!(header.join(","), INVOICES_HEADER);
        assert_eq!(lines.len(), 3, "{csv}");
        assert_eq!(column(lines, header, "number"), ["1", "2", "3"]);
        assert_eq!(
            column(lines, header, "type"),
            ["invoice", "invoice", "credit_note"]
        );
        assert_eq!(
            column(lines, header, "account"),
            vec![format!("'{HOSTILE}"); 3],
            "the apostrophe survives the read, the rest is the name verbatim"
        );
        assert_eq!(column(lines, header, "issued_by"), ["lena"; 3]);
        assert_eq!(
            column(lines, header, "corrects_invoice_number"),
            ["", "", "2"]
        );
        assert_eq!(
            column(lines, header, "amount"),
            ["1200.50", "300.00", "300.00"]
        );
        assert_eq!(column(lines, header, "currency"), ["EUR"; 3]);
        assert_eq!(
            lines[0][3],
            (now + Duration::days(30)).date_naive().to_string()
        );
        assert_eq!(
            column(lines, header, "paid_on"),
            [today.to_string(), String::new(), String::new()]
        );
        let sum = |pick: &dyn Fn(&[String]) -> bool| -> i64 {
            lines.iter().filter(|l| pick(l)).map(|l| minor(&l[7])).sum()
        };
        let in_window = |d: &str| !d.is_empty() && d >= yesterday.to_string().as_str();
        assert_eq!(
            sum(&|l| l[1] == "invoice" && in_window(&l[2])),
            pnl_minor(&pnl, "invoices_issued")
        );
        assert_eq!(
            sum(&|l| l[1] == "invoice" && in_window(&l[4])),
            pnl_minor(&pnl, "invoices_paid")
        );
        assert_eq!(
            sum(&|l| l[1] == "credit_note" && in_window(&l[2])),
            pnl_minor(&pnl, "credit_notes")
        );
        assert_eq!(
            pnl["totals"]["invoices_issued"]["count"], 2,
            "the seed is what pnl sees"
        );

        // spend
        let (status, headers, csv) = h
            .get_raw("/v1/accounting/export?days=2&journal=spend", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{csv}");
        assert_eq!(
            headers["content-disposition"],
            format!("attachment; filename=\"spend-{yesterday}-{today}.csv\"")
        );
        let rows = parse(&csv);
        let (header, lines) = (&rows[0], &rows[1..]);
        assert_eq!(header.join(","), SPEND_HEADER);
        assert_eq!(lines.len(), 3, "released is a line too: {csv}");
        assert_eq!(
            column(lines, header, "day")[0],
            yesterday.to_string(),
            "ordered by day"
        );
        assert_eq!(column(lines, header, "employee"), ["lena"; 3]);
        assert_eq!(
            column(lines, header, "reservation_id")[2],
            released.id().to_string()
        );
        let by_state = |state: &str| -> i64 {
            lines
                .iter()
                .filter(|l| l[4] == state)
                .map(|l| minor(&l[3]))
                .sum()
        };
        assert_eq!(by_state("reserved"), pnl_minor(&pnl, "spend_reserved"));
        assert_eq!(by_state("settled"), pnl_minor(&pnl, "spend_settled"));
        assert_eq!(by_state("released"), 7_000);
        assert_eq!(pnl_minor(&pnl, "spend_settled"), 10_000);

        // usage
        let (status, _, csv) = h
            .get_raw("/v1/accounting/export?days=2&journal=usage", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{csv}");
        let rows = parse(&csv);
        let (header, lines) = (&rows[0], &rows[1..]);
        assert_eq!(header.join(","), USAGE_HEADER);
        assert_eq!(lines.len(), 2, "{csv}");
        assert_eq!(
            column(lines, header, "day"),
            [yesterday.to_string(), today.to_string()]
        );
        assert_eq!(column(lines, header, "cost_usd"), ["0.0057"; 2]);
        let total = |name: &str| -> i64 {
            column(lines, header, name)
                .iter()
                .map(|c| c.parse::<i64>().expect("integer"))
                .sum()
        };
        for (csv_name, pnl_name) in [
            ("calls", "calls"),
            ("calls_unmetered", "calls_unmetered"),
            ("tokens_input", "tokens_input"),
            ("tokens_output", "tokens_output"),
            ("tokens_cache_read", "tokens_cache_read"),
        ] {
            assert_eq!(total(csv_name), pnl["totals"][pnl_name], "{csv_name}");
        }
        assert_eq!(total("tokens_input"), 3_800);
        let exact: i128 = column(lines, header, "cost_usd")
            .iter()
            .map(|c| tenths(c))
            .sum();
        assert_eq!(
            cents(exact),
            pnl["totals"]["cost_usd"]["minor"],
            "the lines summed and rounded once are pnl's cents; rounded each they would be two"
        );
        assert_eq!(pnl["totals"]["cost_usd"]["minor"], 1);

        // Yesterday alone holds the outstanding spend and one day of usage,
        // and no invoice.
        let (_, _, csv) = h
            .get_raw(
                &format!("/v1/accounting/export?from={yesterday}&to={yesterday}&journal=invoices"),
                SECRET_A,
            )
            .await;
        assert_eq!(parse(&csv).len(), 1, "header only: {csv}");

        // The window and the journal refuse nonsense.
        for bad in [
            "/v1/accounting/export?days=0&journal=spend",
            "/v1/accounting/export?days=2&from=2026-01-01&journal=spend",
            "/v1/accounting/export?days=2",
            "/v1/accounting/export?days=2&journal=ledger",
        ] {
            let (status, _, _) = h.get_raw(bad, SECRET_A).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }

        // Tenant B holds a valid key and every journal is a header.
        for journal in ["invoices", "spend", "usage"] {
            let (status, _, csv) = h
                .get_raw(
                    &format!("/v1/accounting/export?days=2&journal={journal}"),
                    SECRET_B,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{csv}");
            assert_eq!(parse(&csv).len(), 1, "{journal}: {csv}");
        }

        h.teardown().await;
    }
}
