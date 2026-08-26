//! `POST /v1/employees/{id}/queue/export`: the file the founder uploads.
//!
//! [`agentos_app::queue`] shipped with ten unit tests, a compile-fail case and
//! no caller. This is the caller, and there is exactly one of it, because the
//! module's own rule leaves room for exactly one shape:
//!
//! > **Commit `record_queued` before writing the file.**
//!
//! A cadence cannot honour that. A `Lead` it built would live in one process's
//! memory, so marking a prospect contacted for it records a person as approached
//! who was never approached — the one bookkeeping error in this vertical that
//! costs a real prospect. So the export is a **pull**: [`queue::plan`], `record_queued`
//! and [`queue::csv`] run in one transaction, and that transaction commits before the
//! bytes leave the process, in the same request that hands them to the person
//! who will upload them.
//!
//! # `POST`, and it is not a matter of taste
//!
//! This marks up to forty strangers as contacted and moves their follow-up
//! clocks three days out. Running it twice returns two different files; the
//! second is usually empty, which is the point. That is a write, and a `GET`
//! that writes is a `GET` some proxy, link-prefetcher, browser or retry policy
//! will eventually run for you — spending the founder's day of prospects on
//! nobody. The `Accept`-shaped thing about it, that a file comes back, is not
//! evidence about the verb.
//!
//! It carries no request body on purpose: everything the export needs is
//! already a stored value. A body would be a second place to write a limit.
//!
//! # The lost response, which is the interesting failure
//!
//! The rows are marked and the bytes are built in one transaction, so those two
//! cannot disagree. What can still happen is that the transaction commits and
//! the **response** never arrives — the client disconnects, the proxy times out.
//! Then forty people are marked contacted and nobody has the file.
//!
//! That is the failure the module chooses, and this follows it rather than
//! arguing: mark-then-send loses an opener for `FOLLOW_UP_AFTER` (72 hours), send-then-
//! mark mails a stranger the same cold email twice. A prospect who gets that
//! reports it, and a sending domain does not recover from that on a schedule.
//! One is three days of silence for forty prospects; the other is the reputation
//! of the only domain the company sends on.
//!
//! **But it is recoverable, and that is why the response is JSON.** The API
//! stack already replays a keyed request from a stored record —
//! `main::replay_idempotent` — and it records **only** JSON responses, because
//! the column is `jsonb`. A `text/csv` body would be released rather than
//! recorded, so a retry would re-run the handler and get the *empty* file the
//! second run correctly produces, and the lost openers would stay lost. Sent as
//! `{"queued": n, "csv": "…"}` under an `Idempotency-Key`, a retry replays the
//! exact same bytes. The founder's command is:
//!
//! ```text
//! curl -sX POST -H "Authorization: Bearer $KEY" \
//!      -H "Idempotency-Key: $(uuidgen)" \
//!      "$HOST/v1/employees/$ID/queue/export" | jq -r .csv > leads.csv
//! ```
//!
//! Reuse that key to retry. A new key is a new day's export.
//!
//! # Every refusal the send path applies
//!
//! None of them is re-derived here — a second place to write a limit is one
//! place to forget to tighten it. [`queue::plan`] applies all four, from values this
//! handler only fetches:
//!
//! * **Suppression** — [`queue::suppression`], through the schema's own
//!   `SECURITY DEFINER` lookup, which is the only reader that can see a
//!   *global* suppression. The database says it twice more: an opt-out
//!   deactivates the contact rows it names *and* clears their
//!   `next_follow_up_at`, and [`queue::due`] filters on both.
//! * **`max_new_contacts_per_day` minus today** — the limit through
//!   [`policy::load`], so it is the intersected platform ∧ tenant ∧ team ∧
//!   employee number the gate itself enforces, and not the role pack's shipped
//!   `0` nor an employee layer a team has since tightened. Today's spend
//!   through [`contacted_since`](agentos_store::revenue::contacted_since) from
//!   UTC midnight, which is the column `record_queued` writes and the same day
//!   boundary the turn ledger keys on.
//! * **`may_propose(EmailSend)` and `Channel::Email`** — the sales role pack's,
//!   carrying those loaded limits.
//!
//! And one the send path has no need of, because it never holds a claim for
//! longer than a turn: **`MAX_FINDING_AGE` on the opener**. A file is uploaded
//! by hand a day later; the sentence in it names a date and says *"here is how
//! to see it again"*. [`queue::due`] applies the bar in SQL, on the same
//! `checked_at` `vertical::follow_up` measures.
//!
//! # The tenant, and the employee
//!
//! From [`Principal`], i.e. from the API key, never from the path. The employee
//! id in the path selects *whose limits* — it is not an authorisation and it
//! cannot widen anything. Another tenant's employee is invisible to RLS and
//! answered **404**, not 403, which would confirm the id exists.
//!
//! The export itself is tenant-wide rather than per-employee: `contacts` are not
//! assigned to an employee, `contacted_since` counts the tenant's day, and the
//! founder has one seller. If a second one is ever hired, the two would share
//! one budget through this route — the fix is a `WHERE a.employee_id = $n` in
//! [`queueable`](agentos_store::revenue::queueable), and it is not written
//! because a column nobody fills makes every export empty.
//!
//! # An empty export is a 200
//!
//! With the header row, `queued: 0`. Nothing is wrong with a quiet morning: no
//! finding was fresh, or yesterday spent the budget, or the operator has not
//! raised it off `0` yet. A 404 would say the resource does not exist and a 4xx
//! would say the founder made a mistake, and neither is true. The header row is
//! there because Smartlead's importer needs one to map columns, so an empty file
//! that still loads is worth more than an empty body.
//!
//! # September
//!
//! The Smartlead sink is `POST /api/v1/campaigns/{id}/leads` and it is **not
//! built** — the founder has not decided the campaign id, paused-versus-active,
//! or what to do about `first_name`. When it lands it is a second function over
//! the same `&[Lead]` slice this handler already holds, called from the same
//! place, inside the same transaction. See [`agentos_app::queue`]'s module docs
//! for its shape and [`export`] for the one line that changes here.

use agentos_app::queue;
use agentos_app::rolepack_sales::RolePack;
use agentos_domain::ids::EmployeeId;
use agentos_store::db::{Db, StoreError};
use agentos_store::policy;
use agentos_store::revenue as revenue_store;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::{DateTime, Timelike, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// How many due prospects are looked at before the budget is applied.
///
/// ponytail: a constant, not a query parameter. It bounds the *scan*, not the
/// export — [`queue::plan`] truncates to `max_new_contacts_per_day` afterwards
/// — and it only has to stay comfortably above any budget an operator would
/// set, so that a run of suppressed addresses at the front of the queue cannot
/// starve a file. The founder's whole list is 1,133 distinct people. Raise it
/// the day a tenant's daily budget is within an order of magnitude of it.
const SCANNED: i64 = 500;

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, and where the replay in the
/// module docs happens.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/employees/{id}/queue/export", post(export))
        .with_state(db)
}

/// What came back, and enough to know why it was that size.
#[derive(Debug, Serialize)]
struct Export {
    employee_id: Uuid,
    /// How many prospects are in the file, and how many were just marked
    /// contacted. The same number by construction — they are the same slice.
    queued: u32,
    /// What was left of `max_new_contacts_per_day` when this ran. `0` with an
    /// empty file is an operator who has not raised the limit, which is the
    /// ordinary reason a new deployment exports nothing; it reads very
    /// differently from a budget that was there and found nobody.
    budget: u32,
    /// How many the tenant had already written to today, before this call.
    spent_today: u32,
    /// RFC 4180, CRLF, ten columns. Empty of rows is still a header.
    csv: String,
}

/// `POST /v1/employees/{id}/queue/export`.
///
/// One transaction, and it is the whole point — see the module docs. Read the
/// candidates, read the suppression list, read today's spend, [`queue::plan`],
/// [`queue::record_queued`], [`queue::csv`], commit, answer.
///
/// **Where the September sink goes:** beside the `csv(&leads)` line, over the
/// same `leads`, before this same commit. Nothing above it moves.
async fn export(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let employee_id = EmployeeId::from_uuid(id);
    let now = Utc::now();

    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    // Existence first, so an unknown id is a 404 rather than a policy load
    // failure that reads like a server fault. No `WHERE tenant_id`: RLS adds
    // it, and a hand-written filter would be a second place to forget it.
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM employees WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    if exists.is_none() {
        tx.rollback().await?;
        return Err(ApiError::not_found());
    }

    // The intersected ceiling — platform ∧ tenant ∧ team ∧ employee — and the
    // same value the gate measures a real send against. Not the employee
    // layer's own row, which a team may since have tightened.
    let policy = policy::load(&mut tx, employee_id).await.map_err(|err| {
        // The detail stays server-side, as everywhere else on this surface.
        tracing::error!(
            employee_id = %id,
            error = %err,
            "the stored policy could not be loaded, so nothing may be exported"
        );
        ApiError::internal()
    })?;
    // **Replaced, not intersected**, and `with_limits` is documented as exactly
    // this: "a provisioner that has intersected tenant and employee layers hands
    // the result back here". The pack's shipped numbers are the defaults for an
    // employee nobody has provisioned — `max_new_contacts_per_day: 0`, cold
    // outreach off — and intersecting them would take the minimum with that `0`
    // and make every export empty forever, which is the one thing an operator
    // raising the limit is trying to stop. What is *not* lost by replacing is
    // any refusal: the loaded value is the narrower one on every allowlist,
    // including `allowed_channels`, so a tenant that names no email channel
    // exports nobody. `may_propose(EmailSend)` is the pack's own and is not a
    // limit at all, so it survives untouched.
    let pack = RolePack::sales_development().with_limits(policy.limits().clone());

    let ready = queue::due(&mut tx, now, SCANNED).await.map_err(refused)?;
    let suppression = queue::suppression(&mut tx, &ready).await.map_err(refused)?;

    // Today's spend off the column `record_queued` writes, from UTC midnight —
    // the day the turn and spend ledgers already key on, so one employee never
    // has two todays. Passing `0` here would turn a daily limit into a per-run
    // one, which is the same number meaning something else.
    let spent_today = u32::try_from(
        revenue_store::contacted_since(&mut tx, midnight(now))
            .await
            .map_err(refused)?,
    )
    .unwrap_or(u32::MAX);

    let leads = queue::plan(ready, &pack, &suppression, spent_today);
    // Before the bytes, in the same transaction as the bytes. The order is the
    // module's and the argument is in this one's docs.
    queue::record_queued(&mut tx, &leads, now)
        .await
        .map_err(refused)?;
    let csv = queue::csv(&leads);
    let queued = u32::try_from(leads.len()).unwrap_or(u32::MAX);

    tx.commit().await?;

    tracing::info!(
        employee_id = %id,
        queued,
        spent_today,
        suppressed = suppression.len(),
        "an operator pulled the outreach queue"
    );

    Ok(Json(Export {
        employee_id: id,
        queued,
        budget: pack
            .limits()
            .max_new_contacts_per_day
            .saturating_sub(spent_today),
        spent_today,
        csv,
    })
    .into_response())
}

/// The revenue store's vocabulary, on this one path.
///
/// ponytail: a function here and not a `From` impl in `error.rs`. This is the
/// only route that touches `RevenueError` — a blanket conversion would be a
/// decision made once for every future caller by the first one, and the
/// interesting arm below is interesting *because* of what this path is doing.
///
/// Whatever it answers, the transaction is dropped un-committed, so nobody was
/// marked and no bytes were handed over. That is the property worth keeping:
/// this route has no half-way.
fn refused(err: revenue_store::RevenueError) -> ApiError {
    match err {
        revenue_store::RevenueError::Store(err) => ApiError::from(err),
        // Somebody replied STOP between the read at the top of this transaction
        // and the mark at the bottom, and the database refused the write —
        // `mark_contacted` answers `NotFound` for an inactive contact and the
        // trigger refuses it underneath. Rolling the whole export back is the
        // right answer rather than exporting the rest: the rest were already
        // marked in this same transaction, and committing that without the
        // bytes is the error this route exists to avoid. Run it again and they
        // are simply gone from the queue.
        revenue_store::RevenueError::Suppressed(_) => ApiError::conflict(
            "suppressed_during_export",
            "a prospect opted out while the export was being built; run it again",
        ),
        other => {
            tracing::error!(error = %other, "the outreach queue could not be built");
            ApiError::internal()
        }
    }
}

/// The start of `now`'s UTC day.
///
/// UTC and not a tenant-local midnight, for the reason
/// [`agentos_store::turns`] gives: the ledgers already key on it, and an
/// employee with two todays has two budgets.
fn midnight(now: DateTime<Utc>) -> DateTime<Utc> {
    now.with_hour(0)
        .and_then(|t| t.with_minute(0))
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        // Unreachable: every one of those is in range for any `DateTime<Utc>`,
        // and a UTC day has no DST gap to fall into. The fallback counts the
        // last 24 hours, which is a wider window and therefore a smaller
        // export — the safe direction.
        .unwrap_or(now - chrono::TimeDelta::days(1))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::queue::COLUMNS;
    use agentos_domain::action::Channel;
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::PolicyLimits;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header as http_header};
    use chrono::TimeDelta;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The founder's real file, as `agentos_app::queue`'s own tests use it: the
    /// header, a plain row, a row whose `company_name` contains a comma, and a
    /// row that is not ASCII. The assertion that this route hands back *that*
    /// shape is the only one that matters to the person uploading it.
    const REAL: &str =
        include_str!("../../../../crates/app/tests/fixtures/smartlead_getorizn_prospection.csv");

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the queue route needs a real Postgres");
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
                app: crate::with_api_stack(router(db.clone()), db.clone(), keys),
                db,
                a,
                b,
            })
        }

        async fn export(&self, employee: Uuid, secret: &str) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method("POST")
                .uri(format!("/v1/employees/{employee}/queue/export"))
                .header(http_header::AUTHORIZATION, format!("Bearer {secret}"))
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'queue-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn employee(db: &Db, tenant: TenantId, slug: &str) -> Uuid {
        let id = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    /// What an operator writes to turn cold outreach on: a channel the seller
    /// may use, and a number of strangers a day.
    ///
    /// The tenant layer rather than the platform one, for the reason
    /// `routes::turns`'s tests give: the intersection takes the minimum, so a
    /// test writes its own tenant's row and needs no global lock. `Email` is
    /// spelled here because `PolicyLimits::default()` grants **no** channel and
    /// the intersection would then permit none — which is the fail-closed
    /// direction and is also what an unconfigured tenant really gets.
    async fn contact_budget(db: &Db, tenant: TenantId, per_day: u32) {
        policy::install(
            db,
            tenant,
            policy::Scope::Tenant,
            &PolicyLimits {
                max_new_contacts_per_day: per_day,
                allowed_channels: [Channel::Email].into_iter().collect(),
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the contact budget");
    }

    /// One row of the founder's file, become the rows the export reads back:
    /// an account, a contact due now, and an `evidence` row carrying the opener
    /// its finding came to.
    ///
    /// The opener goes in through `insert_evidence`, which is the only writer of
    /// that column in the workspace — the same call `vertical::file_finding`
    /// makes with a real `Evidence` in hand.
    async fn seed_row(
        db: &Db,
        tenant: TenantId,
        row: &str,
        subject: &str,
        body: &str,
        checked_at: DateTime<Utc>,
    ) -> (Uuid, String) {
        let values = split_row(row);
        assert_eq!(values.len(), 8, "the founder's file has eight columns");
        let account = Uuid::now_v7();
        let contact = Uuid::now_v7();
        let now = Utc::now();
        // What the importer writes: the two name columns joined and trimmed,
        // which for every row of the founder's lists is the empty string.
        let full_name = format!("{} {}", values[1].trim(), values[2].trim())
            .trim()
            .to_owned();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        revenue_store::insert_account(
            &mut tx,
            account,
            &revenue_store::NewAccount {
                legal_name: &values[3],
                // Unique per seeded row, and not the website's host: two rows of
                // one fixture must not collide on `accounts_domain_key`.
                domain: &format!("{}.example", account.simple()),
                segment: "insurer",
                country: "ZZ",
                employee_id: None,
                location: Some(&values[7]),
                website: Some(&values[5]),
            },
        )
        .await
        .expect("account");
        revenue_store::insert_contact(
            &mut tx,
            contact,
            &revenue_store::NewContact {
                account_id: account,
                full_name: &full_name,
                email: Some(&values[0]),
                phone: None,
                role: None,
                language: None,
                is_primary: false,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: Some(now),
            },
        )
        .await
        .expect("contact");
        revenue_store::insert_evidence(
            &mut tx,
            Uuid::now_v7(),
            &revenue_store::NewEvidence {
                account_id: account,
                employee_id: None,
                kind: "missing_visa_info",
                passport_country: "FR",
                destination_country: "VN",
                travel_date: None,
                source_url: "https://example.com/booking",
                reproduction: "1. open the page\n2. enter FR → VN",
                artifact_ref: None,
                observed_claim: "(their panel displayed nothing for this pair)",
                correct_claim: "not established, and not needed",
                authority_url: None,
                checked_at,
                opener_subject: Some(subject),
                opener_body: Some(body),
            },
        )
        .await
        .expect("evidence");
        tx.commit().await.expect("commit");

        (contact, values[0].clone())
    }

    /// Split one RFC 4180 line — the fixture needs it, because
    /// `"Faye (Zenner, Inc.)"` is a quoted field with a comma in it.
    fn split_row(line: &str) -> Vec<String> {
        let mut fields = vec![String::new()];
        let mut quoted = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    chars.next();
                    fields.last_mut().expect("field").push('"');
                }
                '"' => quoted = !quoted,
                ',' if !quoted => fields.push(String::new()),
                _ => fields.last_mut().expect("field").push(c),
            }
        }
        fields
    }

    fn csv_of(body: &Value) -> String {
        body["csv"].as_str().expect("a csv string").to_owned()
    }

    /// What an export with no rows in it is, and what every export starts with.
    fn header() -> String {
        format!("{}\r\n", COLUMNS.join(","))
    }

    // -----------------------------------------------------------------------

    /// The one that matters to the person uploading the file: his own rows go
    /// in, his own bytes come out, with the two custom variables appended.
    #[tokio::test]
    async fn the_export_is_the_founders_own_column_shape() {
        let Some(h) = Harness::new().await else {
            return;
        };
        contact_budget(&h.db, h.a, 10).await;
        let id = employee(&h.db, h.a, "seller").await;

        let rows: Vec<&str> = REAL.lines().skip(1).collect();
        assert_eq!(rows.len(), 3, "the fixture holds three real rows");
        for row in &rows {
            seed_row(&h.db, h.a, row, "s", "b", Utc::now()).await;
        }

        let (status, body) = h.export(id, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["queued"], 3);

        let csv = csv_of(&body);
        assert!(
            csv.starts_with(&header()),
            "the header is the founder's own eight columns plus the two \
             Smartlead custom variables: {csv}"
        );
        assert_eq!(
            csv.matches("\r\n").count(),
            4,
            "CRLF, and one terminator per row plus the header: {csv:?}"
        );
        for row in rows {
            assert!(
                csv.contains(&format!("{row},s,b\r\n")),
                "a row of the founder's file must come back out of the export \
                 unchanged, with the opener appended and nothing else touched. \
                 wanted {row:?} in:\n{csv}"
            );
        }

        h.teardown().await;
    }

    /// An empty queue is a fact about a quiet morning, not a mistake the caller
    /// made. It still loads into Smartlead, because it still has a header.
    #[tokio::test]
    async fn an_empty_queue_is_a_200_with_a_header() {
        let Some(h) = Harness::new().await else {
            return;
        };
        contact_budget(&h.db, h.a, 10).await;
        let id = employee(&h.db, h.a, "seller").await;

        let (status, body) = h.export(id, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["queued"], 0);
        assert_eq!(csv_of(&body), header());

        h.teardown().await;
    }

    /// The founder will run it twice. `record_queued` committed in the first
    /// call is what stops the second one exporting the same person again — and
    /// it is the `contacts` table doing it, not a file this route remembers.
    #[tokio::test]
    async fn running_it_twice_does_not_export_the_same_prospect_twice() {
        let Some(h) = Harness::new().await else {
            return;
        };
        contact_budget(&h.db, h.a, 10).await;
        let id = employee(&h.db, h.a, "seller").await;
        let row = REAL.lines().nth(1).expect("a real row");
        let (_, address) = seed_row(&h.db, h.a, row, "s", "b", Utc::now()).await;

        let (_, first) = h.export(id, SECRET_A).await;
        assert_eq!(first["queued"], 1);
        assert!(csv_of(&first).contains(&address));

        let (status, second) = h.export(id, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(
            second["queued"], 0,
            "the prospect was queued once and must not come back until \
             FOLLOW_UP_AFTER has passed"
        );
        assert_eq!(csv_of(&second), header());
        // And the first run is visible as spend, so a second run cannot be
        // handed the whole day's budget again.
        assert_eq!(second["spent_today"], 1);

        h.teardown().await;
    }

    /// A file the founder uploads *is* a send, with the safety checks a day
    /// later and a system boundary away. Both refusals bite here.
    #[tokio::test]
    async fn a_suppressed_address_and_an_over_budget_day_both_bite() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = employee(&h.db, h.a, "seller").await;
        let rows: Vec<&str> = REAL.lines().skip(1).collect();

        let mut seeded = Vec::new();
        for row in &rows {
            seeded.push(seed_row(&h.db, h.a, row, "s", "b", Utc::now()).await);
        }
        let (stopped_contact, stopped) = seeded[0].clone();

        // One of the three replied STOP.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        revenue_store::suppress(
            &mut tx,
            Uuid::now_v7(),
            &revenue_store::NewSuppression {
                scope: revenue_store::Scope::Tenant,
                channel: revenue_store::Channel::Email,
                address: &stopped,
                reason: "opt_out",
                contact_id: Some(stopped_contact),
                note: Some("replied STOP"),
                suppressed_at: Utc::now(),
            },
        )
        .await
        .expect("suppress");
        tx.commit().await.expect("commit");

        // Cold outreach off, which is what `sales_development()` ships and what
        // an operator's layer says until they change it. Three prospects are
        // due and the file is still empty.
        contact_budget(&h.db, h.a, 0).await;
        let (status, body) = h.export(id, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["queued"], 0, "an unraised budget is an empty file");
        assert_eq!(body["budget"], 0);

        // Raised to one: the budget truncates the queue to one row, and the
        // suppressed address is not it.
        //
        // **Which lock that is** — the database's, and it is worth saying,
        // because deleting `plan`'s own suppression filter leaves this test
        // green. Recording the opt-out above set `active = false` and
        // `next_follow_up_at = NULL` on that contact in the same statement, and
        // `queueable` filters on both, so the address never reaches `plan` at
        // all and cannot spend a slot a contactable one wanted. `plan`'s filter
        // and `queue::suppression` are the third lock, and no data on this path
        // can get past the first two to exercise them —
        // `revenue::tests::the_export_lookup_sees_a_suppression_the_table_hides`
        // is what holds the lookup itself honest, and
        // `queue::tests::a_suppressed_address_cannot_reach_the_export` is what
        // holds the filter honest.
        contact_budget(&h.db, h.a, 1).await;
        let (_, body) = h.export(id, SECRET_A).await;
        assert_eq!(body["queued"], 1, "the contact budget caps the queue");
        let csv = csv_of(&body);
        assert!(
            !csv.contains(&stopped),
            "an opted-out address must not be in the bytes the founder \
             uploads: {csv}"
        );

        // The day is now spent, so the two remaining prospects wait for
        // tomorrow rather than for a second run.
        let (_, body) = h.export(id, SECRET_A).await;
        assert_eq!(body["queued"], 0);
        assert_eq!(body["spent_today"], 1);
        assert_eq!(body["budget"], 0);

        h.teardown().await;
    }

    /// A claim of the form "on this date your page did this, here is how to see
    /// it again" that has gone stale is the one mistake in this job that cannot
    /// be walked back. The export applies the same bar `follow_up` does.
    #[tokio::test]
    async fn a_stale_finding_is_not_exported() {
        let Some(h) = Harness::new().await else {
            return;
        };
        contact_budget(&h.db, h.a, 10).await;
        let id = employee(&h.db, h.a, "seller").await;
        let row = REAL.lines().nth(1).expect("a real row");
        seed_row(
            &h.db,
            h.a,
            row,
            "s",
            "b",
            Utc::now() - TimeDelta::days(8), // MAX_FINDING_AGE is seven.
        )
        .await;

        let (status, body) = h.export(id, SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["queued"], 0,
            "a finding older than MAX_FINDING_AGE has no business being \
             re-asserted to a prospect a day after this file is uploaded"
        );

        h.teardown().await;
    }

    /// B holds a valid credential and A's real employee id, and learns nothing.
    /// A 403 would confirm the employee exists; the prospects are not even
    /// reachable, because RLS never shows them.
    #[tokio::test]
    async fn another_tenants_key_gets_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };
        contact_budget(&h.db, h.a, 10).await;
        contact_budget(&h.db, h.b, 10).await;
        let id = employee(&h.db, h.a, "seller").await;
        let row = REAL.lines().nth(1).expect("a real row");
        let (_, address) = seed_row(&h.db, h.a, row, "s", "b", Utc::now()).await;

        let (status, body) = h.export(id, SECRET_B).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // An id nobody owns reads identically.
        let (status, _) = h.export(Uuid::now_v7(), SECRET_A).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // And B's own export is empty rather than A's: the employee id is not
        // the thing that scopes the data, the credential is.
        let theirs = employee(&h.db, h.b, "seller").await;
        let (status, body) = h.export(theirs, SECRET_B).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["queued"], 0);
        assert!(!csv_of(&body).contains(&address));

        // A's prospect is untouched by all of that and still exportable.
        let (_, body) = h.export(id, SECRET_A).await;
        assert_eq!(body["queued"], 1);

        h.teardown().await;
    }

    /// The lost response, made recoverable. Same key, same bytes — which only
    /// works because the body is JSON: `main::record` releases a key whose
    /// response is not, and a re-run would hand back the empty file the second
    /// run correctly produces.
    #[tokio::test]
    async fn a_retry_under_one_key_replays_the_same_file() {
        let Some(h) = Harness::new().await else {
            return;
        };
        contact_budget(&h.db, h.a, 10).await;
        let id = employee(&h.db, h.a, "seller").await;
        let row = REAL.lines().nth(1).expect("a real row");
        seed_row(&h.db, h.a, row, "s", "b", Utc::now()).await;

        let key = Uuid::now_v7().to_string();
        let send = |key: String| {
            let app = h.app.clone();
            async move {
                let req = HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/v1/employees/{id}/queue/export"))
                    .header(http_header::AUTHORIZATION, format!("Bearer {SECRET_A}"))
                    .header("idempotency-key", key)
                    .body(Body::empty())
                    .expect("request");
                let response = app.oneshot(req).await.expect("service");
                let status = response.status();
                let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
                    .await
                    .expect("body");
                let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                (status, value)
            }
        };

        let (status, first) = send(key.clone()).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["queued"], 1);

        // The response the founder never received, handed back intact.
        let (status, replay) = send(key).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(csv_of(&replay), csv_of(&first));

        h.teardown().await;
    }
}
