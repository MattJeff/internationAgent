//! `GET /v1/billing`: **the basis of the invoice, and not the invoice.**
//!
//! # What it returns, and the number it refuses to print
//!
//! Counts of billable days: how many seat-days and how many connector-days this
//! tenant accumulated in the window, with the evidence under both. **There is no
//! money anywhere in this response**, and that is a decision rather than an
//! omission.
//!
//! A price is not a measurement. The rate card for this product — what a seat
//! costs, what a connector costs, where the tiers break, what a first-year
//! discount looks like — belongs to whoever signs the contracts, it changes per
//! deal, and it is not derivable from any row in this database. Printing a dollar
//! figure here would mean either hard-coding a tariff that is stale the week
//! after it is written, or inventing one. [`super::forecast`] refuses a success
//! percentage for the same reason and `agentos_store::model_usage` refuses a cost
//! per token for the same reason again: **this repository reports what it
//! measured and stops.**
//!
//! So the split is clean. This endpoint answers *how much service did we
//! provide*, which is a fact with a trail under it. Multiplying it by a tariff is
//! a commercial act performed somewhere that knows the contract.
//!
//! # And it moves no money
//!
//! Nothing here talks to a payment provider. `/v1/webhooks/stripe` exists, and
//! what it does is verify a signature and store the raw delivery — it has no
//! billing logic and gains none from this unit. Counting and collecting are two
//! jobs, and the one that can be re-run against an append-only trail a year later
//! is this one.
//!
//! # Never a token
//!
//! `GET /v1/usage` reports tokens, and those are the **customer's**: they connect
//! their own key through `POST /v1/model` and the tokens land on their own
//! Anthropic invoice. That is what makes a flat infrastructure price honest, and
//! it is why [`agentos_store::billing`] cannot reach a token column even by
//! accident. Read the two endpoints side by side and the split is the product:
//! `usage` is their bill from Anthropic, this is ours.
//!
//! # What makes it checkable line by line
//!
//! A customer who cannot verify an invoice pays it once. So the same rows are
//! reported three ways and the reader can cross-foot them:
//!
//! * `days` has **one entry per day of the window**, zeroes included, so a gap is
//!   visible as a zero rather than as a missing line somebody has to notice.
//! * `employees` and `connectors` name every subject that was billed at all, with
//!   its day count and the first and last day it appeared.
//! * `employee_days` and `connector_days` are the totals.
//!
//! All three are folded in Rust from one `SELECT`, so `employee_days` equals the
//! sum of the `employees` column *and* the sum of the per-day column, by
//! construction rather than by luck. A second SQL aggregate would be a second
//! place for the definition of "billable" to live.
//!
//! What every line is named by is a slug — `lena`, `github` — because that is
//! what the customer typed and therefore what they can check against their own
//! memory. `agentos_store::billing::BilledDay` argues why it is also the only
//! safe thing to put on a document a human forwards.
//!
//! # The window and the tenant
//!
//! `?from=` and `?to=` are [`super::autonomy`]'s [`Window`], not a copy, so a
//! month means the same month here as it does in `/v1/usage` and `/v1/autonomy`.
//! Reading them together is the point.
//!
//! The tenant comes from the API key. `audit_log` and `employees` both carry
//! forced row-level security, so another tenant's invoice is not filtered out —
//! it does not exist to be summed.
//!
//! # `GET /v1/billing/worked-seats`: the same trail, read as a price position
//!
//! `/v1/billing` is the meter. Its sibling is the sentence we are willing to
//! print on a contract: **a provisioned seat that has never passed the gate
//! costs nothing.** It answers, for one month, how many seats exist and how many
//! of them decided anything at all, allowed or refused.
//!
//! It lives in this file rather than a module of its own because the two are one
//! definition read at two altitudes, and the failure mode of splitting them is
//! the one that matters commercially: an invoice and a sales page that disagree
//! about whether a seat did something. See [`worked_seats`] for why a refusal
//! counts, and [`resolve_month`] for why the window is a month and not
//! [`Window`].

use std::collections::BTreeMap;

use agentos_store::billing::{self, BilledDay};
use agentos_store::db::Db;
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{DateTime, Datelike, Days, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};

use super::autonomy::{Window, WindowQuery};
use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/billing", get_route(get))
        // Beside `/v1/billing` and not in a module of its own, because the two
        // read the same trail and answer the same question at two altitudes:
        // that one is the meter, this one is the position — *we bill the seat
        // that worked*. Splitting them would let the definition of "a seat did
        // something" drift between the invoice and the sales page.
        .route("/v1/billing/worked-seats", get_route(worked_seats))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// One day of the window. Present even when both counts are zero — a day nobody
/// was billed for is a line on the invoice saying so, not a line that is absent
/// and has to be inferred.
#[derive(Debug, Serialize)]
struct DayLine {
    day: NaiveDate,
    /// Seats that could act on this day.
    employees: usize,
    /// MCP bindings that were configured on this day.
    connectors: usize,
}

/// One subject's contribution, so the customer can find *which* seat or
/// connector a total came from.
///
/// `first_day` and `last_day` are the ends of what was billed **inside the
/// window**, not the subject's whole history — an invoice for August must not
/// quote a date in July, or the reader has to work out which of the two numbers
/// the window applies to.
#[derive(Debug, Serialize)]
struct SubjectLine {
    /// The employee's slug or the connector's handle.
    subject: String,
    /// Days billed in this window. Not necessarily contiguous: a suspension
    /// leaves a hole, and `first_day`/`last_day` show where to look for it.
    days: usize,
    first_day: NaiveDate,
    last_day: NaiveDate,
}

/// What the endpoint answers. No amount, no currency, no rate — see the module
/// docs.
#[derive(Debug, Serialize)]
struct BillingView {
    /// Inclusive, UTC.
    from: NaiveDate,
    /// Inclusive, UTC.
    to: NaiveDate,
    /// The sum of the `employees` column of `days`, and of the `days` column of
    /// `employees`. Both, necessarily — they are the same rows.
    employee_days: usize,
    /// The same, for connectors.
    connector_days: usize,
    /// One line per day of the window, in order.
    days: Vec<DayLine>,
    /// Every seat billed at all in the window, busiest first.
    employees: Vec<SubjectLine>,
    /// Every connector billed at all in the window, busiest first.
    connectors: Vec<SubjectLine>,
}

// ---------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------

/// Per-subject accumulation. A `BTreeMap` so the ties in the sort below break on
/// the name and two identical windows produce byte-identical invoices — an
/// invoice whose line order wobbles between renders is one somebody diffs and
/// mistrusts.
type Subjects = BTreeMap<String, SubjectLine>;

/// Count one billed day against one subject.
fn tally(subjects: &mut Subjects, row: &BilledDay) {
    subjects
        .entry(row.subject.clone())
        .and_modify(|line| {
            line.days += 1;
            // The rows arrive `ORDER BY day`, so this is the running maximum.
            line.last_day = row.day;
        })
        .or_insert_with(|| SubjectLine {
            subject: row.subject.clone(),
            days: 1,
            first_day: row.day,
            last_day: row.day,
        });
}

/// Most days first, then alphabetically — the order an operator scans for "who
/// is costing me the most", with a deterministic tie-break.
fn ranked(subjects: Subjects) -> Vec<SubjectLine> {
    let mut lines: Vec<SubjectLine> = subjects.into_values().collect();
    lines.sort_by(|a, b| b.days.cmp(&a.days).then_with(|| a.subject.cmp(&b.subject)));
    lines
}

/// Every day in `[from, to]`, inclusive.
///
/// `Window::resolve` has already refused `from > to` and anything wider than a
/// year, so this terminates; the `checked_add` is there because `NaiveDate` has
/// an end and a saturating loop would be an infinite one.
fn days_of(window: Window) -> impl Iterator<Item = NaiveDate> {
    std::iter::successors(Some(window.from), |day| day.checked_add_days(Days::new(1)))
        .take_while(move |day| *day <= window.to)
}

/// `GET /v1/billing?from=…&to=…`.
///
/// 200 with zeroes is the ordinary answer for a tenant that had nothing running:
/// "you owe nothing for August" is a fact and an invoice line, not a 404.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<WindowQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let window = Window::resolve(&query)?;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let rows = billing::billed_days(&mut tx, window.from, window.to).await?;
    tx.rollback().await?;

    let mut employees = Subjects::new();
    let mut connectors = Subjects::new();
    let mut per_day: BTreeMap<NaiveDate, (usize, usize)> = BTreeMap::new();

    for row in &rows {
        let slot = per_day.entry(row.day).or_default();
        // Two meters, both bound into the query from this crate's own constants,
        // so there is no third value for the `else` to swallow.
        if row.meter == billing::EMPLOYEE {
            slot.0 += 1;
            tally(&mut employees, row);
        } else {
            slot.1 += 1;
            tally(&mut connectors, row);
        }
    }

    let days: Vec<DayLine> = days_of(window)
        .map(|day| {
            let (employees, connectors) = per_day.get(&day).copied().unwrap_or_default();
            DayLine {
                day,
                employees,
                connectors,
            }
        })
        .collect();

    Ok(axum::Json(BillingView {
        from: window.from,
        to: window.to,
        // Summed off `days` rather than counted off `rows`, so the headline is
        // literally the column beneath it added up. If they could ever differ
        // the invoice would be unarguable in the wrong direction.
        employee_days: days.iter().map(|line| line.employees).sum(),
        connector_days: days.iter().map(|line| line.connectors).sum(),
        days,
        employees: ranked(employees),
        connectors: ranked(connectors),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// GET /v1/billing/worked-seats
// ---------------------------------------------------------------------------

/// `?month=2026-09`. Absent means the month that is running.
///
/// Un mois et pas la [`Window`] d'à côté, délibérément : c'est la période sur
/// laquelle un contrat se facture, et laisser choisir des bornes libres
/// inviterait à découper la fenêtre jusqu'à ce que le nombre de sièges
/// travaillés tombe. `/v1/billing` garde la fenêtre libre parce que c'est un
/// compteur qu'on interroge, pas une position de prix.
#[derive(Debug, Deserialize)]
struct MonthQuery {
    month: Option<String>,
}

/// Un siège qui a travaillé, et ce qu'il a fait.
#[derive(Debug, Serialize)]
struct SeatLine {
    employee_id: String,
    /// Le slug — voir [`agentos_store::billing::Seat`].
    name: String,
    /// La première décision du mois. Toujours présente ici : un siège sans
    /// première décision n'est pas dans cette liste, c'est la définition même.
    first_decision_at: DateTime<Utc>,
    /// Permises **et** refusées.
    decisions: i64,
}

/// L'écart entre ce qui existe et ce qui a servi.
#[derive(Debug, Serialize)]
struct WorkedSeatsView {
    /// `YYYY-MM`, réécrit depuis ce qui a été résolu — pas l'écho de la requête.
    /// Un mois par défaut doit se lire dans la réponse.
    month: String,
    /// Les sièges qui existent.
    provisioned: usize,
    /// Ceux qui ont passé la gate au moins une fois. `provisioned - worked` est
    /// ce que ce produit ne facture pas.
    worked: usize,
    /// Les sièges travaillés, les plus actifs d'abord.
    seats: Vec<SeatLine>,
}

/// Le mois, en `[since, until)`.
///
/// La borne haute est exclusive et calculée en ajoutant un mois plutôt qu'en
/// comptant des jours : février et les années bissextiles sont le genre de
/// détail qui rend une facture fausse une fois tous les quatre ans, ce qui est
/// précisément la fréquence à laquelle personne ne le remarque.
fn resolve_month(raw: Option<&str>) -> Result<(String, DateTime<Utc>, DateTime<Utc>), ApiError> {
    let bad = || ApiError::bad_request("month: expected YYYY-MM");
    let today = Utc::now().date_naive();
    let (year, month) = match raw {
        None => (today.year(), today.month()),
        Some(text) => {
            let (year, month) = text.split_once('-').ok_or_else(bad)?;
            let year: i32 = year.parse().map_err(|_| bad())?;
            let month: u32 = month.parse().map_err(|_| bad())?;
            (year, month)
        }
    };
    let first = NaiveDate::from_ymd_opt(year, month, 1).ok_or_else(bad)?;
    let next = match month {
        12 => NaiveDate::from_ymd_opt(year + 1, 1, 1),
        _ => NaiveDate::from_ymd_opt(year, month + 1, 1),
    }
    .ok_or_else(bad)?;

    Ok((
        format!("{year:04}-{month:02}"),
        first.and_time(NaiveTime::MIN).and_utc(),
        next.and_time(NaiveTime::MIN).and_utc(),
    ))
}

/// `GET /v1/billing/worked-seats?month=…` — **on ne facture que le siège qui a
/// travaillé.**
///
/// # La position, et pourquoi elle est déjà mesurée
///
/// Un siège provisionné qui n'a jamais passé la gate ne coûte rien. Ce n'est pas
/// une remise commerciale accordée après coup, c'est une lecture du journal : la
/// gate écrit une ligne par décision, permise comme refusée, depuis
/// `0001_core.sql`. Il n'y a rien à instrumenter, donc rien qui puisse manquer
/// le jour où quelqu'un oublie d'appeler un compteur.
///
/// # Refusé compte
///
/// Un employé dont toutes les tentatives ont été refusées a consommé le
/// système, et le dire autrement serait une facture qui récompense une
/// configuration cassée. L'argument complet est sur
/// [`agentos_store::billing::seats`].
///
/// # `provisioned` et `worked` sortent de la même liste
///
/// Une requête, deux lectures. Un second `SELECT count(*) FROM employees`
/// donnerait un `provisioned` qui peut, un jour, ne plus être le dénominateur de
/// `worked` — et l'écart entre les deux nombres est exactement l'argument de
/// vente.
async fn worked_seats(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<MonthQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let (month, since, until) = resolve_month(query.month.as_deref())?;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let seats = billing::seats(&mut tx, since, until).await?;
    tx.rollback().await?;

    let lines: Vec<SeatLine> = seats
        .iter()
        .filter_map(|seat| {
            // `first_decision_at` est présent si et seulement si le siège a
            // décidé quelque chose, donc ce `?` *est* le filtre « travaillé » —
            // il n'y a pas de second critère à garder d'accord avec le SQL.
            Some(SeatLine {
                employee_id: seat.employee_id.to_string(),
                name: seat.name.clone(),
                first_decision_at: seat.first_decision_at?,
                decisions: seat.decisions,
            })
        })
        .collect();

    Ok(axum::Json(WorkedSeatsView {
        month,
        provisioned: seats.len(),
        worked: lines.len(),
        seats: lines,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::action::ActionKind;
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::policy::{Decision, DenyReason};
    use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
    use agentos_store::model_usage::{self, Consumed};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; billing routes need a real Postgres");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");

            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        async fn get(&self, uri: &str, secret: &str) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .body(Body::empty())
                .expect("request");
            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// A seat that goes active, exactly as the hire path and the activation
        /// handler write it between them.
        async fn hire(&self, tenant: TenantId, slug: &str, when: DateTime<Utc>) -> EmployeeId {
            let id = EmployeeId::new_v7(Utc::now());
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 VALUES ($1, $2, $3, $3, 'active')",
            )
            .bind(id.as_uuid())
            .bind(tenant.as_uuid())
            .bind(slug)
            .execute(&mut **tx)
            .await
            .expect("insert employee");
            for event in [
                AuditEvent {
                    employee_id: Some(id),
                    ..AuditEvent::new(AuditActor::System, AuditKind::EmployeeCreated, when)
                },
                AuditEvent {
                    employee_id: Some(id),
                    payload: json!({ "from": "draft", "to": "active" }),
                    ..AuditEvent::new(
                        AuditActor::System,
                        AuditKind::EmployeeLifecycleChanged,
                        when,
                    )
                },
            ] {
                audit::append(&mut tx, &event).await.expect("append");
            }
            tx.commit().await.expect("commit");
            id
        }

        /// Une décision de la gate sur un siège, comme `app::gate` l'écrit :
        /// une ligne, quel qu'ait été le verdict.
        async fn decide(
            &self,
            tenant: TenantId,
            slug: &str,
            decision: Decision,
            when: DateTime<Utc>,
        ) {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            let employee: uuid::Uuid =
                sqlx::query_scalar("SELECT id FROM employees WHERE slug = $1")
                    .bind(slug)
                    .fetch_one(&mut **tx)
                    .await
                    .expect("employee");
            audit::append(
                &mut tx,
                &AuditEvent {
                    employee_id: Some(EmployeeId::from_uuid(employee)),
                    decision: Some(decision),
                    ..AuditEvent::new(
                        AuditActor::System,
                        AuditKind::Action(ActionKind::EmailSend),
                        when,
                    )
                },
            )
            .await
            .expect("append");
            tx.commit().await.expect("commit");
        }

        /// One MCP administrative act, as `routes::mcp::record` writes it.
        async fn mcp(&self, tenant: TenantId, event: &str, server: &str, when: DateTime<Utc>) {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            audit::append(
                &mut tx,
                &AuditEvent {
                    payload: json!({ "event": event, "server": server }),
                    ..AuditEvent::new(AuditActor::System, AuditKind::PolicyChanged, when)
                },
            )
            .await
            .expect("append");
            tx.commit().await.expect("commit");
        }

        async fn teardown(self) {
            for tenant in [self.a, self.b] {
                let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
                sqlx::query("DELETE FROM tenants WHERE id = $1")
                    .bind(tenant.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .expect("delete tenant");
                tx.commit().await.expect("commit");
            }
        }
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'billing-route')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    fn line<'a>(body: &'a Value, meter: &str, subject: &str) -> Option<&'a Value> {
        body[meter]
            .as_array()?
            .iter()
            .find(|line| line["subject"] == subject)
    }

    // -----------------------------------------------------------------------

    /// The invoice cross-foots: the headline, the per-day column and the
    /// per-subject column are three readings of one set of rows, and a customer
    /// who adds any of them up has to get the same answer.
    #[tokio::test]
    async fn the_totals_are_the_columns_beneath_them_added_up() {
        let Some(h) = Harness::new().await else {
            return;
        };
        // One clock reading for the whole test. Two would let a UTC midnight
        // fall between them and shift the window under the fixtures, which is
        // the classic date-test flake: green all day, red at 00:00.
        let now = Utc::now();
        let today = now.date_naive();
        let start = now - Duration::days(4);

        h.hire(h.a, "lena", start).await;
        h.hire(h.a, "mo", start + Duration::days(2)).await;
        h.mcp(h.a, "mcp.server.declared", "github", start).await;

        let from = start.date_naive();
        let (status, body) = h
            .get(&format!("/v1/billing?from={from}&to={today}"), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let days = body["days"].as_array().expect("days");
        assert_eq!(
            days.len(),
            5,
            "one line per day of the window, zeroes and all"
        );

        let summed: i64 = days.iter().map(|d| d["employees"].as_i64().unwrap()).sum();
        assert_eq!(body["employee_days"].as_i64(), Some(summed));
        let per_subject: i64 = body["employees"]
            .as_array()
            .expect("employees")
            .iter()
            .map(|s| s["days"].as_i64().unwrap())
            .sum();
        assert_eq!(
            body["employee_days"].as_i64(),
            Some(per_subject),
            "the headline must equal the per-subject column: {body}"
        );

        // 5 days of lena + 3 of mo.
        assert_eq!(body["employee_days"], 8);
        assert_eq!(line(&body, "employees", "lena").expect("lena")["days"], 5);
        assert_eq!(line(&body, "employees", "mo").expect("mo")["days"], 3);
        // Busiest first, so the seat driving the bill is the first line.
        assert_eq!(body["employees"][0]["subject"], "lena");

        assert_eq!(body["connector_days"], 5);
        assert_eq!(
            line(&body, "connectors", "github").expect("github")["days"],
            5
        );

        h.teardown().await;
    }

    /// **The commercial constraint, asserted on the wire.** No amount, no
    /// currency, no rate — and no token, however many the seats burned.
    ///
    /// The banned words are checked against the whole serialised body, the same
    /// way `super::forecast` checks that it never claims a chance of success:
    /// a field somebody adds later is caught by the shape of the document
    /// rather than by a reviewer noticing.
    #[tokio::test]
    async fn the_invoice_quotes_no_price_and_counts_no_token() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let now = Utc::now();
        let today = now.date_naive();
        let yesterday = (now - Duration::days(1)).date_naive();
        let lena = h.hire(h.a, "lena", now - Duration::days(1)).await;

        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        model_usage::record(
            &mut tx,
            lena,
            today,
            Consumed::reported(4_000, 900_000_000, 50_000_000, 12_000_000),
        )
        .await
        .expect("record");
        tx.commit().await.expect("commit");

        let (status, body) = h
            .get(
                &format!("/v1/billing?from={yesterday}&to={today}"),
                SECRET_A,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["employee_days"], 2,
            "the seat-days are still the seat-days"
        );

        let rendered = body.to_string().to_lowercase();
        for banned in [
            "usd",
            "cost",
            "price",
            "amount",
            "currency",
            "cents",
            "rate",
            "token",
            "invoice",
            "total_due",
        ] {
            assert!(
                !rendered.contains(banned),
                "`{banned}` appeared in a billing basis that must carry no tariff \
                 and no model usage: {body}"
            );
        }

        h.teardown().await;
    }

    /// **The hard constraint.** B holds a valid credential and gets its own
    /// invoice, which is empty — A's seats are not filtered out of it, they are
    /// invisible to it.
    #[tokio::test]
    async fn another_tenants_invoice_is_invisible_rather_than_filtered() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let now = Utc::now();
        let today = now.date_naive();
        let start = now - Duration::days(3);
        let from = start.date_naive();
        h.hire(h.a, "lena", start).await;
        h.mcp(h.a, "mcp.server.declared", "github", start).await;

        let window = format!("/v1/billing?from={from}&to={today}");
        let (status, body) = h.get(&window, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["employee_days"], 4);
        assert_eq!(body["connector_days"], 4);

        let (status, body) = h.get(&window, SECRET_B).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["employee_days"], 0);
        assert_eq!(body["connector_days"], 0);
        assert!(line(&body, "employees", "lena").is_none(), "{body}");
        assert!(line(&body, "connectors", "github").is_none(), "{body}");
        // And a tenant with nothing gets a real invoice of zeroes, not a 404:
        // "you owe nothing" is an answer. Asked with no window at all, so this
        // is also the check that the default is `autonomy`'s thirty days and
        // not a second opinion about what "recently" means.
        let (_, body) = h.get("/v1/billing", SECRET_B).await;
        assert_eq!(body["days"].as_array().expect("days").len(), 30);
        assert_eq!(body["employee_days"], 0);

        h.teardown().await;
    }

    /// **La position de prix, sur le fil.** Deux sièges provisionnés, un seul
    /// qui a tenté quelque chose — et ce qu'il a tenté a été refusé.
    ///
    /// Le siège refusé est le cas qui décide de la définition : s'il ne comptait
    /// pas, la facture récompenserait une configuration cassée, et un locataire
    /// qui interdit tout à un employé le ferait tourner gratuitement.
    #[tokio::test]
    async fn a_seat_that_only_ever_got_refused_still_worked_and_a_silent_one_did_not() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let now = Utc::now();
        h.hire(h.a, "lena", now).await;
        h.hire(h.a, "mo", now).await;
        // `mo` ne fait rien du tout. `lena` se fait refuser deux fois et
        // autoriser une : trois décisions, aucune n'ayant rien produit de plus
        // qu'une ligne dans le journal.
        for decision in [
            Decision::Deny {
                reason: DenyReason::ToolNotAllowed,
            },
            Decision::Deny {
                reason: DenyReason::ToolNotAllowed,
            },
            Decision::Allow,
        ] {
            h.decide(h.a, "lena", decision, now).await;
        }

        let month = format!("{:04}-{:02}", now.year(), now.month());
        let (status, body) = h
            .get(&format!("/v1/billing/worked-seats?month={month}"), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["month"], month);
        assert_eq!(body["provisioned"], 2, "{body}");
        assert_eq!(
            body["worked"], 1,
            "a seat that never passed the gate costs nothing: {body}"
        );

        let seats = body["seats"].as_array().expect("seats");
        assert_eq!(seats.len(), 1, "{body}");
        assert_eq!(seats[0]["name"], "lena");
        assert_eq!(
            seats[0]["decisions"], 3,
            "allowed and refused both consumed the system: {body}"
        );
        assert!(seats[0]["first_decision_at"].is_string(), "{body}");
        assert!(
            !body.to_string().contains("\"mo\""),
            "the silent seat is counted in `provisioned` and billed nowhere: {body}"
        );

        // Un mois où il ne s'est rien passé : les sièges existent toujours, et
        // aucun n'a travaillé. C'est la fenêtre qui filtre, et elle filtre.
        let (status, body) = h
            .get("/v1/billing/worked-seats?month=1999-01", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["provisioned"], 2, "{body}");
        assert_eq!(body["worked"], 0, "{body}");

        // Le siège de A est invisible pour B, pas filtré.
        let (_, body) = h.get("/v1/billing/worked-seats", SECRET_B).await;
        assert_eq!(body["provisioned"], 0, "{body}");

        for bad in [
            "/v1/billing/worked-seats?month=2026",
            "/v1/billing/worked-seats?month=2026-13",
            "/v1/billing/worked-seats?month=2026-09-01",
            "/v1/billing/worked-seats?month=septembre",
        ] {
            let (status, _) = h.get(bad, SECRET_A).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} was accepted");
        }

        h.teardown().await;
    }

    /// The window is [`super::super::autonomy`]'s, so this invoice and
    /// `/v1/usage` cover the same days when asked the same question.
    #[tokio::test]
    async fn the_window_is_validated_the_same_way_usage_validates_it() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.hire(h.a, "lena", Utc::now() - Duration::days(1)).await;

        let today = Utc::now().date_naive();
        let (status, body) = h
            .get(&format!("/v1/billing?from={today}&to={today}"), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["from"], today.to_string());
        assert_eq!(body["to"], today.to_string());
        assert_eq!(body["employee_days"], 1, "`to` is inclusive");

        for bad in [
            "/v1/billing?from=2026-08-02&to=2026-08-01",
            "/v1/billing?from=2020-01-01&to=2026-01-01",
            "/v1/billing?from=not-a-date",
        ] {
            let (status, _) = h.get(bad, SECRET_A).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} was accepted");
        }

        h.teardown().await;
    }
}
