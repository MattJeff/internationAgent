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
//! **Tokens, not money.** There is no cost figure here, and no price is ever
//! applied to a customer that the customer did not declare. A price per million
//! tokens is a fact with a source and a date; a price table in a repository is
//! stale the day after it is written, and the real number depends on a contract
//! this schema has never seen. A cost nobody can trace is worse than a missing
//! one, so this endpoint reports the measurement and stops. The migration's
//! last section is the full argument.
//!
//! The one price table this repository does hold is
//! `agentos_domain::forecast::rate_card` — list prices read on a named day,
//! used to put a dollar sign on the *measured* Orizn run in `docs/ORIZN.md` and
//! as `/v1/forecast`'s fallback when a tenant has declared nothing, labelled
//! `cost_source: "rate_card"` so nobody mistakes it for their contract. A
//! declared tariff always wins over it. This paragraph used to say "no price
//! anywhere in this repository", which was false for as long as `rate_card`
//! existed, and a sentence a `grep` refutes is the kind this file exists to
//! avoid.
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
        .route("/v1/usage/models", get_route(by_model))
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
// `GET /v1/usage/models`
// ---------------------------------------------------------------------------

/// Default and maximum for `?days=`, the same shape [`super::outreach`]'s
/// health window has and for the same reason: a window with no default is a
/// query string every caller has to get right, and one with no maximum is a
/// full-table scan anybody can ask for.
const MODELS_DEFAULT_DAYS: i64 = 7;

/// Ninety days. Longer than the question — "did the routing change anything" is
/// answered by a week — and short enough that the scan is bounded.
const MODELS_MAX_DAYS: i64 = 90;

/// `?days=N`, 1..=90, default 7.
#[derive(Debug, serde::Deserialize)]
struct DaysQuery {
    days: Option<i64>,
}

/// One model's share of the window.
///
/// **`calls` and not `turns`**, and the difference is not pedantry: this ledger
/// counts model round trips — `Finished::turns` is round trips, and one
/// `Turn::run` makes between one and `Budgets::max_turns` of them — while no
/// column in this schema counts runs. A field called `turns` here would be a
/// number a reader divides the bill by to get an answer an order of magnitude
/// wrong. When a run counter exists it arrives as a column and then as a field,
/// not as a rename.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct ModelRow {
    /// The model string as it was billed. Empty for rows written before
    /// `migrations/0097` — nobody wrote it down, and it is shown as its own
    /// line rather than distributed over the models that *were* named.
    model: String,
    calls: i64,
    input_tokens: i64,
    /// `cache_read_tokens`, named for what it is to a reader: input the prefix
    /// cache served, billed by Anthropic at a tenth of fresh input.
    cached_tokens: i64,
    output_tokens: i64,
}

/// What the endpoint answers.
#[derive(Debug, Serialize)]
struct ByModelView {
    /// The window asked for, in days back from today inclusive.
    days: i64,
    /// Biggest consumer first, because alphabetical is not a question anybody
    /// has about a bill.
    by_model: Vec<ModelRow>,
}

/// One row per model this tenant billed anything to in the window.
///
/// No `WHERE tenant_id`: `model_usage_daily` carries `tenant_isolation`,
/// forced, so the tenant predicate is the policy rather than a filter each
/// reader has to remember. `sum(...)::bigint` because `sum()` over `bigint` is
/// `numeric` in Postgres and this crate has no decimal type.
const BY_MODEL_SQL: &str = "\
SELECT model, \
       sum(calls)::bigint             AS calls, \
       sum(input_tokens)::bigint      AS input_tokens, \
       sum(cache_read_tokens)::bigint AS cached_tokens, \
       sum(output_tokens)::bigint     AS output_tokens \
  FROM model_usage_daily \
 WHERE day >= $1 \
 GROUP BY model \
 ORDER BY sum(input_tokens + output_tokens + cache_read_tokens) DESC, model";

/// `GET /v1/usage/models?days=N` — **what the per-turn routing actually
/// changed.**
///
/// `agentos_app::model_choice` picks a model per turn from a table of rules,
/// and a table of rules is an argument. This is the evidence: how many calls
/// went to the cheap model, how much of the input the prefix cache served, and
/// whether the expensive model is where the judgement is. It is deliberately a
/// *reading* and not a forecast, and it holds no money — the module docs above
/// carry that argument in full and it is not weakened by there being three
/// models in the answer instead of one.
///
/// The window is `days` days back from today **inclusive**, so `days=1` is
/// today. Same auth as `/v1/outreach`: the tenant is the API key's, and RLS
/// makes another tenant's mix invisible rather than merely unlisted.
async fn by_model(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<DaysQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let days = query.days.unwrap_or(MODELS_DEFAULT_DAYS);
    if !(1..=MODELS_MAX_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!(
            "days: between 1 and {MODELS_MAX_DAYS}"
        )));
    }
    let since = chrono::Utc::now().date_naive() - chrono::Duration::days(days - 1);

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let by_model: Vec<ModelRow> = sqlx::query_as(BY_MODEL_SQL)
        .bind(since)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.rollback().await?;

    Ok(axum::Json(ByModelView { days, by_model }).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::policy::ModelId;
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
            self.spend_on(tenant, employee, ModelId::Opus5, consumed)
                .await;
        }

        /// The same, on a named model. Since `0097` a seat's day is one row per
        /// model, and `/v1/usage/models` is the only reader that cares which.
        async fn spend_on(
            &self,
            tenant: TenantId,
            employee: EmployeeId,
            model: ModelId,
            consumed: Consumed,
        ) {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            model_usage::record(&mut tx, employee, Utc::now().date_naive(), model, consumed)
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

    /// **`GET /v1/usage/models` : ce que le routage par tour a changé.**
    ///
    /// Un siège, une journée, deux modèles — ce qui était impossible à écrire
    /// avant `0097` et impossible à lire avant cette route. Le test couvre les
    /// trois choses qu'une route de mesure peut rater : la somme par modèle, le
    /// locataire d'à côté, et la fenêtre.
    #[tokio::test]
    async fn la_route_des_modeles_separe_ce_quun_siege_a_depense_sur_chacun() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena").await;

        // Rien encore : une vraie réponse vide, pas un 404.
        let (status, body) = h.get("/v1/usage/models", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["days"], 7);
        assert_eq!(body["by_model"].as_array().expect("array").len(), 0);

        // Une journée d'un seul siège, sur deux modèles : huit réveils de rythme
        // qui n'ont rien trouvé, et deux tours qui ont écrit.
        h.spend_on(
            h.a,
            lena,
            ModelId::Haiku45,
            Consumed::reported(8, 40_000, 400, 300_000),
        )
        .await;
        h.spend_on(
            h.a,
            lena,
            ModelId::Sonnet5,
            Consumed::reported(2, 15_000, 900, 60_000),
        )
        .await;

        let (status, body) = h.get("/v1/usage/models?days=1", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["days"], 1);
        let rows = body["by_model"].as_array().expect("array");
        assert_eq!(rows.len(), 2, "{body}");
        // Le plus gros consommateur d'abord, et c'est Haiku : le tri est sur les
        // jetons et non sur le nom, sinon `claude-haiku-4-5` serait premier par
        // hasard alphabétique et la garde ne prouverait rien.
        assert_eq!(rows[0]["model"], "claude-haiku-4-5");
        assert_eq!(rows[0]["calls"], 8);
        assert_eq!(rows[0]["input_tokens"], 40_000);
        assert_eq!(rows[0]["cached_tokens"], 300_000);
        assert_eq!(rows[0]["output_tokens"], 400);
        assert_eq!(rows[1]["model"], "claude-sonnet-5");
        assert_eq!(rows[1]["calls"], 2);

        // Et le total de `/v1/usage` ne bouge pas d'un jeton : la même journée,
        // resommée. C'est ce qui dit que la quatrième colonne de clé a coupé la
        // ligne en deux sans en perdre la moitié.
        let (_, usage) = h.get("/v1/usage", SECRET_A).await;
        assert_eq!(usage["tenant"]["calls"], 10);
        assert_eq!(usage["tenant"]["input_tokens"], 55_000);
        assert_eq!(usage["tenant"]["cache_read_tokens"], 360_000);

        // Le locataire d'à côté lit des zéros, et il ne lit pas « pas de
        // permission » : il ne sait pas que ces lignes existent.
        let (status, theirs) = h.get("/v1/usage/models?days=1", SECRET_B).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(theirs["by_model"].as_array().expect("array").len(), 0);

        // `days` a un défaut, un maximum et refuse zéro.
        for refused in ["?days=0", "?days=-3", "?days=91"] {
            let (status, _) = h.get(&format!("/v1/usage/models{refused}"), SECRET_A).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{refused} devrait être refusé"
            );
        }
        let (status, _) = h.get("/v1/usage/models?days=90", SECRET_A).await;
        assert_eq!(status, StatusCode::OK);

        h.teardown().await;
    }

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
