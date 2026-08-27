//! `GET /v1/usage`: what the employees actually consumed, in tokens.
//!
//! # Why this endpoint exists
//!
//! [`super::autonomy`] answers "how much of the work did the agents do". This
//! answers the question that always follows it — "and what did that cost" — and
//! the two are deliberately the same shape over the same window, because the
//! only interesting reading is the pair. `migrations/0024_model_usage.sql` and
//! [`agentos_store::model_usage`] carry the argument for the table; this is the
//! operator's way in, and until it existed the answer lived in log lines and a
//! process-local counter that drops the tenant.
//!
//! # The three disciplines this surface inherits
//!
//! **Tokens, not money.** There is no cost figure here and no price anywhere in
//! this repository. A price per million tokens is a fact with a source and a
//! date; a price table in a repository is stale the day after it is written, and
//! the real number depends on a contract this schema has never seen. A cost
//! nobody can trace is worse than a missing one, so this endpoint reports the
//! measurement and stops. The migration's last section is the full argument.
//!
//! **Unknown is not zero.** A call the provider did not meter is counted in
//! `calls` and in `calls_unmetered`, and contributes nothing to the token
//! figures. So `tokens_measured` is a **floor** whenever `complete` is `false`,
//! and `complete` is in every rollup precisely so that nobody quotes the floor
//! as the total by accident. A response with `calls: 40, calls_unmetered: 40,
//! tokens_measured: 0` says "forty calls happened and nobody told us what they
//! cost" — which is a different sentence from "forty calls cost nothing", and
//! the whole table exists to keep them different.
//!
//! **Said is not did.** `runs_unbacked` counts the self-started runs that ended
//! with prose and nothing the Policy Gate ruled on, and `unbacked_chars` is how
//! much prose that was. Both are in the rollup because they answer the question
//! that hangs off every token figure here — *and what did it buy* — for the one
//! case where the answer is nothing and the transcript says otherwise. They are
//! a measurement, not an accusation: an employee with nothing due says so and is
//! counted too, which is why there are two numbers rather than a flag. See
//! [`agentos_store::model_usage`] for the whole argument, including what it
//! cannot do.
//!
//! **This is a floor in a second way, too.** A turn that did not finish records
//! nothing at all: `Turn::run` drops its `Spent` when it returns `TurnError`, so
//! the calls a blown budget or a deadline already paid for are invisible here.
//! `GET /v1/employees/{id}/turns` counts turns that *started*, which is the
//! cross-check — see [`agentos_store::model_usage`] for the upgrade path.
//!
//! # The window and the tenant
//!
//! `?from=` and `?to=` are parsed by [`super::autonomy`]'s own [`Window`], not
//! by a copy: the two endpoints have to agree about what "the last 30 days"
//! means or reading them together is misleading.
//!
//! The tenant comes from [`Principal`], i.e. from the API key. `model_usage_daily`
//! has RLS forced, so there is no `WHERE tenant_id` here for anyone to forget
//! and another tenant's bill is not merely unlisted — it is invisible.

use agentos_store::db::{Db, StoreError};
use agentos_store::model_usage::Consumed;
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::NaiveDate;
use serde::Serialize;
use uuid::Uuid;

use super::autonomy::{Window, WindowQuery};
use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/usage", get_route(get))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// One employee's consumption over the window, or the tenant's total, with the
/// two derived figures spelled out beside the counts they come from.
///
/// `pub(super)` so [`super::reports`] renders a report's tokens with this rather
/// than a copy. "What did it burn" is one fact and it has one JSON shape; two
/// structs would eventually disagree about whether `complete` is in it, and
/// `complete` is the field that stops somebody quoting a floor as a total.
#[derive(Debug, Serialize)]
pub(super) struct Rollup {
    #[serde(flatten)]
    consumed: Consumed,
    /// Every token anybody reported. A **floor** when `complete` is false.
    tokens_measured: i64,
    /// `true` when every call in this window reported what it cost. Check this
    /// before quoting `tokens_measured` anywhere.
    complete: bool,
}

impl From<Consumed> for Rollup {
    fn from(consumed: Consumed) -> Self {
        Self {
            consumed,
            tokens_measured: consumed.tokens_measured(),
            complete: consumed.is_complete(),
        }
    }
}

/// One row of [`ROLLUP_SQL`].
///
/// `#[sqlx(flatten)]` so the column list lives in exactly one struct —
/// [`Consumed`], in the store crate beside the writer — and the query, the JSON
/// and the arithmetic cannot disagree about what a column is called.
#[derive(Debug, sqlx::FromRow)]
struct RollupRow {
    employee_id: Uuid,
    slug: Option<String>,
    #[sqlx(flatten)]
    consumed: Consumed,
}

/// One employee, named so an operator does not have to resolve UUIDs by hand.
#[derive(Debug, Serialize)]
struct EmployeeRollup {
    employee_id: Uuid,
    /// `None` only if the employee row went away under a ledger row that
    /// outlived it; the FK cascades, so in practice this is always filled.
    slug: Option<String>,
    #[serde(flatten)]
    rollup: Rollup,
}

/// What the endpoint answers.
#[derive(Debug, Serialize)]
struct UsageView {
    /// Inclusive, UTC.
    from: NaiveDate,
    /// Inclusive, UTC.
    to: NaiveDate,
    /// Every employee's consumption, summed. `complete` here is `false` if *any*
    /// employee had an unmetered call, which is the conservative reading.
    tenant: Rollup,
    /// Per employee, most expensive first.
    employees: Vec<EmployeeRollup>,
}

// ---------------------------------------------------------------------------
// The query
// ---------------------------------------------------------------------------

/// One row per employee that consumed anything in the window.
///
/// No `WHERE tenant_id`: `model_usage_daily` carries the `tenant_isolation`
/// policy, forced, so the tenant predicate is the policy rather than a filter
/// each reader has to remember. `sum(...)::bigint` because `sum()` over `bigint`
/// is `numeric` in Postgres, and this crate has no decimal type.
///
/// `JOIN` and not `LEFT JOIN`, unlike [`super::autonomy`]'s rollup: the ledger's
/// FK cascades from `employees`, so a row whose employee is gone does not exist.
/// The slug is still `Option` in [`RollupRow`] because the column is nullable in
/// principle and a strict decode would be a 500 over a cosmetic field.
const ROLLUP_SQL: &str = "\
SELECT u.employee_id, \
       e.slug, \
       sum(u.calls)::bigint             AS calls, \
       sum(u.calls_unmetered)::bigint   AS calls_unmetered, \
       sum(u.input_tokens)::bigint      AS input_tokens, \
       sum(u.output_tokens)::bigint     AS output_tokens, \
       sum(u.cache_read_tokens)::bigint AS cache_read_tokens, \
       sum(u.runs_unbacked)::bigint     AS runs_unbacked, \
       sum(u.unbacked_chars)::bigint    AS unbacked_chars \
  FROM model_usage_daily u \
  JOIN employees e ON e.id = u.employee_id \
 WHERE u.day >= $1 AND u.day < $2 \
 GROUP BY u.employee_id, e.slug \
 ORDER BY sum(u.input_tokens + u.output_tokens + u.cache_read_tokens) DESC, e.slug";

/// `GET /v1/usage?from=…&to=…`.
///
/// 200 with zeroes is the ordinary answer for a tenant whose employees consumed
/// nothing in the window — "no activity" is a fact, not a missing resource — and
/// `complete` is `true` there, because a window with no calls in it has no
/// unknown calls in it either.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<WindowQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let window = Window::resolve(&query)?;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let rows: Vec<RollupRow> = sqlx::query_as(ROLLUP_SQL)
        .bind(window.from)
        .bind(window.end())
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.rollback().await?;

    let mut tenant = Consumed::default();
    let mut employees = Vec::with_capacity(rows.len());
    for row in rows {
        tenant.add(&row.consumed);
        employees.push(EmployeeRollup {
            employee_id: row.employee_id,
            slug: row.slug,
            rollup: Rollup::from(row.consumed),
        });
    }

    Ok(axum::Json(UsageView {
        from: window.from,
        to: window.to,
        tenant: Rollup::from(tenant),
        employees,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_store::model_usage;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use chrono::Utc;
    use serde_json::Value;
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
                eprintln!("SKIP: DATABASE_URL is unset; usage routes need a real Postgres");
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
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// Consume tokens the way a turn does: through the real writer, not by
        /// writing the ledger by hand.
        async fn spend(&self, tenant: TenantId, employee: EmployeeId, consumed: Consumed) {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            model_usage::record(&mut tx, employee, Utc::now().date_naive(), consumed)
                .await
                .expect("record");
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'usage-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
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
        tx.commit().await.expect("commit");
        id
    }

    /// The row for one employee, out of the response body.
    fn row(body: &Value, id: EmployeeId) -> Option<&Value> {
        body["employees"]
            .as_array()?
            .iter()
            .find(|row| row["employee_id"] == id.as_uuid().to_string())
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_operator_can_see_what_each_employee_consumed() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;
        let mo = employee(&h.db, h.a, "mo").await;

        // Nothing yet: a real answer with zeroes, not a 404, and `complete` —
        // a window with no calls has no unknown calls either.
        let (status, body) = h.get("/v1/usage", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["tenant"]["calls"], 0);
        assert_eq!(body["tenant"]["complete"], true);
        assert_eq!(body["employees"].as_array().expect("array").len(), 0);

        h.spend(h.a, lena, Consumed::reported(2, 50_000, 3_000, 120_000))
            .await;
        h.spend(h.a, mo, Consumed::reported(1, 900, 40, 0)).await;

        let (_, body) = h.get("/v1/usage", SECRET_A).await;
        let lena_row = row(&body, lena).expect("lena is listed");
        assert_eq!(lena_row["slug"], "lena");
        assert_eq!(lena_row["calls"], 2);
        assert_eq!(lena_row["input_tokens"], 50_000);
        assert_eq!(lena_row["output_tokens"], 3_000);
        assert_eq!(lena_row["cache_read_tokens"], 120_000);
        assert_eq!(lena_row["tokens_measured"], 173_000);
        assert_eq!(lena_row["complete"], true);

        // Mo's is Mo's, and the busiest employee is listed first — which is the
        // one an operator is looking for.
        assert_eq!(row(&body, mo).expect("mo is listed")["calls"], 1);
        assert_eq!(body["employees"][0]["slug"], "lena");

        // And the tenant total is the sum, not a separately computed number.
        assert_eq!(body["tenant"]["calls"], 3);
        assert_eq!(body["tenant"]["tokens_measured"], 173_940);
        assert_eq!(body["tenant"]["complete"], true);

        h.teardown().await;
    }

    /// The discipline that matters: a call nobody metered reads as unknown, not
    /// as free. Zero is a lie that averages well.
    #[tokio::test]
    async fn a_call_the_provider_did_not_meter_is_not_a_call_that_cost_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lossy = employee(&h.db, h.a, "lossy").await;
        let idle = employee(&h.db, h.a, "idle").await;

        // Four turns against a backend that reported nothing — the CLI adapter,
        // or a provider that omitted the block.
        h.spend(h.a, lossy, Consumed::reported(4, 0, 0, 0)).await;
        // And an employee that took one turn which really did report, so the two
        // rows differ in the ledger and not only in the story.
        h.spend(h.a, idle, Consumed::reported(1, 10, 2, 0)).await;

        let (_, body) = h.get("/v1/usage", SECRET_A).await;
        let lossy_row = row(&body, lossy).expect("listed despite no tokens");
        assert_eq!(lossy_row["calls"], 4, "the calls happened and are recorded");
        assert_eq!(lossy_row["calls_unmetered"], 4);
        assert_eq!(lossy_row["tokens_measured"], 0);
        assert_eq!(
            lossy_row["complete"], false,
            "four calls of unknown cost must not read as four free calls"
        );

        let idle_row = row(&body, idle).expect("listed");
        assert_eq!(idle_row["calls_unmetered"], 0);
        assert_eq!(idle_row["complete"], true);

        // One unmetered call anywhere makes the tenant total a floor, which is
        // the conservative reading and the one a public claim has to use.
        assert_eq!(body["tenant"]["calls"], 5);
        assert_eq!(body["tenant"]["calls_unmetered"], 4);
        assert_eq!(body["tenant"]["tokens_measured"], 12);
        assert_eq!(body["tenant"]["complete"], false);

        h.teardown().await;
    }

    #[tokio::test]
    async fn another_tenants_bill_is_invisible_rather_than_filtered() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let theirs = employee(&h.db, h.a, "lena").await;
        h.spend(h.a, theirs, Consumed::reported(3, 1_000, 200, 0))
            .await;

        // B holds a valid credential and could name A's employee; the endpoint
        // never looks at a caller-supplied id, and RLS means there is nothing
        // for it to look at.
        let (status, body) = h.get("/v1/usage", SECRET_B).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["tenant"]["calls"], 0);
        assert_eq!(body["employees"].as_array().expect("array").len(), 0);
        assert!(row(&body, theirs).is_none(), "{body}");

        h.teardown().await;
    }

    /// The window is [`super::super::autonomy`]'s, so the two endpoints can be
    /// read side by side. This is the check that they still share it.
    #[tokio::test]
    async fn the_window_is_validated_the_same_way_autonomy_validates_it() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;
        h.spend(h.a, lena, Consumed::reported(1, 5, 1, 0)).await;

        let today = Utc::now().date_naive();
        let (status, body) = h
            .get(&format!("/v1/usage?from={today}&to={today}"), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["from"], today.to_string());
        assert_eq!(body["to"], today.to_string());
        assert_eq!(body["tenant"]["calls"], 1, "`to` is inclusive");

        // Backwards, and far too wide, are both refusals rather than nonsense.
        let (status, _) = h
            .get("/v1/usage?from=2026-08-02&to=2026-08-01", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = h
            .get("/v1/usage?from=2020-01-01&to=2026-01-01", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = h.get("/v1/usage?from=not-a-date", SECRET_A).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A window before the employee ever ran is empty rather than absent.
        let (status, body) = h
            .get("/v1/usage?from=2026-01-01&to=2026-01-31", SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["tenant"]["calls"], 0);

        h.teardown().await;
    }
}
