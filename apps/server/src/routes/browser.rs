//! `GET /v1/browser/*` : ce que Browserbase montre dans son tableau de bord,
//! lu chez nous — le journal des tâches, la vue en direct d'un employé, le
//! résumé du jour.
//!
//! Tout vient de [`Journal`], le lecteur du port `BrowserObserver`
//! (`agentos_app::browser_journal`) : `tasks` et `summary` lisent la table
//! `browser_tasks` (0096) sous le locataire de [`Principal`] — RLS `force`,
//! aucun `WHERE tenant_id` —, `live` s'abonne au canal d'images de l'employé.
//!
//! # La vue en direct est un abonnement, pas une lecture
//!
//! `GET /v1/browser/live/{employee_id}` tient la connexion ouverte et relaie
//! chaque image que l'adaptateur capture. C'est **cette connexion** qui allume
//! le screencast : `Journal::wants_frames` est « au moins un abonné », et le
//! récepteur vit dans le corps de la réponse — quand le client ferme, le
//! récepteur tombe, le compte redescend à zéro, l'adaptateur cesse de
//! capturer. Rien à démarrer, rien à arrêter, rien à fuir.
//!
//! Un lecteur en retard (le canal a quatre places) saute les images perdues et
//! reprend : c'est `Lagged`, filtré et non fatal. Le `: ping` toutes les 15 s
//! est ce qui tient un proxy éveillé sur une tâche qui réfléchit entre deux
//! étapes.
//!
//! # Le 404
//!
//! Un employé d'un autre locataire n'existe pas ici : `live` le cherche dans
//! `employees` sous le locataire avant de s'abonner, sinon un appelant
//! pourrait regarder l'écran d'un employé dont il devine l'identifiant. Même
//! réponse qu'un employé inexistant, exprès (`ApiError::not_found`).

use std::sync::Arc;
use std::time::Duration;

use agentos_app::browser_journal::{Journal, Live};
use agentos_domain::ids::EmployeeId;
use agentos_store::db::{Db, StoreError};
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// Ce que les quatre routes partagent.
#[derive(Clone)]
pub struct BrowserState {
    pub db: Db,
    pub journal: Arc<Journal>,
    /// [`crate::config::Config::browser_js`], le même booléen que `/readyz`.
    pub browser_js: bool,
}

pub fn router(state: BrowserState) -> Router {
    Router::new()
        .route("/v1/browser/tasks", get_route(list))
        .route("/v1/browser/tasks/{id}", get_route(one))
        .route("/v1/browser/live/{employee_id}", get_route(live))
        .route("/v1/browser/summary", get_route(summary))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListQuery {
    employee_id: Option<Uuid>,
    limit: Option<i64>,
}

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

#[derive(Debug, Serialize)]
struct TaskView {
    id: Uuid,
    employee_id: Uuid,
    provider: String,
    context: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    /// `running` tant que `ended_at` est nul ; sinon la chaîne de la table,
    /// `ok` | `refused:<code>` | `failed:<code>`.
    outcome: String,
    /// `[{ kind, url, outcome, took_ms, at }]`, tel qu'écrit par le journal.
    steps: serde_json::Value,
    frames_sent: i32,
}

type TaskRow = (
    Uuid,
    Uuid,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<String>,
    serde_json::Value,
    i32,
);

/// `$1` nul = tout le journal du locataire. sqlx 0.9 refuse une chaîne
/// composée, donc les colonnes sont écrites deux fois, dans le même ordre que
/// [`TaskRow`].
const LIST_SQL: &str = "\
SELECT id, employee_id, provider, context, started_at, ended_at, outcome, steps, frames_sent \
  FROM browser_tasks \
 WHERE $1::uuid IS NULL OR employee_id = $1 \
 ORDER BY started_at DESC LIMIT $2";

const ONE_SQL: &str = "\
SELECT id, employee_id, provider, context, started_at, ended_at, outcome, steps, frames_sent \
  FROM browser_tasks WHERE id = $1";

fn view(row: TaskRow) -> TaskView {
    let (id, employee_id, provider, context, started_at, ended_at, outcome, steps, frames_sent) =
        row;
    TaskView {
        id,
        employee_id,
        provider,
        context,
        started_at,
        ended_at,
        outcome: outcome.unwrap_or_else(|| "running".to_owned()),
        steps,
        frames_sent,
    }
}

async fn list(
    State(state): State<BrowserState>,
    principal: Principal,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::bad_request(format!(
            "limit: between 1 and {MAX_LIMIT}"
        )));
    }
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let rows: Vec<TaskRow> = sqlx::query_as(LIST_SQL)
        .bind(query.employee_id)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.commit().await?;
    Ok(axum::Json(serde_json::json!({
        "tasks": rows.into_iter().map(view).collect::<Vec<_>>(),
    }))
    .into_response())
}

async fn one(
    State(state): State<BrowserState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row: Option<TaskRow> = sqlx::query_as(ONE_SQL)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.commit().await?;
    Ok(axum::Json(view(row.ok_or_else(ApiError::not_found)?)).into_response())
}

// ---------------------------------------------------------------------------
// The live view
// ---------------------------------------------------------------------------

/// `: ping` — assez court pour un proxy, assez long pour ne pas être du bruit.
const PING: Duration = Duration::from_secs(15);

async fn live(
    State(state): State<BrowserState>,
    principal: Principal,
    Path(employee_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let known: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM employees WHERE id = $1")
        .bind(employee_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.commit().await?;
    if known.is_none() {
        return Err(ApiError::not_found());
    }

    // The subscription lives in the body; the body lives as long as the client
    // reads. That is the whole on/off switch of the screencast.
    let receiver = state.journal.subscribe(EmployeeId::from_uuid(employee_id));
    let events = BroadcastStream::new(receiver).filter_map(|item| match item {
        Ok(Live::Frame(jpeg)) => Some(Ok::<_, std::convert::Infallible>(
            Event::default().event("frame").data(BASE64.encode(&*jpeg)),
        )),
        Ok(Live::Task {
            task_id,
            state,
            outcome,
        }) => Some(Ok(Event::default().event("task").data(
            serde_json::json!({ "task_id": task_id, "state": state, "outcome": outcome })
                .to_string(),
        ))),
        // Behind by more than four frames: the next one is the current one.
        Err(_lagged) => None,
    });
    Ok(Sse::new(events)
        .keep_alive(KeepAlive::new().interval(PING).text("ping"))
        .into_response())
}

// ---------------------------------------------------------------------------
// The summary
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct SummaryView {
    /// Tâches commencées aujourd'hui (jour UTC), finies ou non.
    tasks_today: i64,
    refused_today: i64,
    failed_today: i64,
    /// Tâches où un mur a été rencontré, à une étape ou à la fin.
    blocked_by_site_today: i64,
    browser_js: bool,
}

/// Le même seau de jour UTC que `pnl.rs` et `outreach.rs`.
const SUMMARY_SQL: &str = "\
SELECT count(*), \
       count(*) FILTER (WHERE outcome LIKE 'refused:%'), \
       count(*) FILTER (WHERE outcome LIKE 'failed:%'), \
       count(*) FILTER (WHERE outcome = 'refused:blocked_by_site' \
                           OR steps @> '[{\"outcome\":\"refused:blocked_by_site\"}]') \
  FROM browser_tasks \
 WHERE (started_at AT TIME ZONE 'UTC')::date = (now() AT TIME ZONE 'UTC')::date";

async fn summary(
    State(state): State<BrowserState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let (tasks_today, refused_today, failed_today, blocked_by_site_today): (i64, i64, i64, i64) =
        sqlx::query_as(SUMMARY_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(StoreError::from)?;
    tx.commit().await?;
    Ok(axum::Json(SummaryView {
        tasks_today,
        refused_today,
        failed_today,
        blocked_by_site_today,
        browser_js: state.browser_js,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::browser_journal::{BrowserObserver as _, StepOutcome, StepReport, TaskRef};
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Harness {
        app: Router,
        db: Db,
        journal: Arc<Journal>,
        a: TenantId,
        b: TenantId,
        seat_a: EmployeeId,
        seat_b: EmployeeId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the journal is a table");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let seat_a = employee(&db, a, "lena").await;
            let seat_b = employee(&db, b, "otto").await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            let journal = Journal::new(db.clone());
            Some(Self {
                app: crate::with_api_stack(
                    router(BrowserState {
                        db: db.clone(),
                        journal: journal.clone(),
                        browser_js: false,
                    }),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                journal,
                a,
                b,
                seat_a,
                seat_b,
            })
        }

        async fn raw(&self, uri: &str, secret: &str) -> Response {
            let req = HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .body(Body::empty())
                .expect("request");
            self.app.clone().oneshot(req).await.expect("service")
        }

        async fn get(&self, uri: &str, secret: &str) -> (StatusCode, Value) {
            let response = self.raw(uri, secret).await;
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// Une tâche entière, narrée et écrite.
        async fn narrate(
            &self,
            seat: EmployeeId,
            steps: &[(&'static str, StepOutcome)],
            end: StepOutcome,
        ) -> TaskRef {
            let task = task(seat);
            let now = Utc::now();
            self.journal.task_started(&task, now);
            for (kind, outcome) in steps {
                let report = StepReport {
                    kind,
                    url: (*kind == "goto").then(|| "https://portal.example.com/".to_owned()),
                    outcome: outcome.clone(),
                    took: Duration::from_millis(12),
                };
                self.journal.step_done(&task, &report, now);
            }
            self.journal.task_finished(&task, &end, now);
            self.settle().await;
            task
        }

        /// Le journal écrit hors du fil de la requête : attendre qu'il ait fini.
        async fn settle(&self) {
            self.journal.flush().await;
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

    fn task(seat: EmployeeId) -> TaskRef {
        TaskRef {
            task_id: Uuid::now_v7(),
            employee_id: seat,
            context: "ctx-test".to_owned(),
            provider: "chrome",
        }
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'browser-test')")
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

    /// Le journal se lit par son locataire, dans sa forme, et pas par le voisin.
    #[tokio::test]
    async fn the_journal_is_read_in_its_shape_and_by_its_tenant_only() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let done = h
            .narrate(
                h.seat_a,
                &[
                    ("goto", StepOutcome::Ok),
                    ("fill", StepOutcome::Failed { code: "no_element" }),
                ],
                StepOutcome::Failed { code: "no_element" },
            )
            .await;
        // A second, still running: started only.
        let running = task(h.seat_a);
        h.journal.task_started(&running, Utc::now());
        h.settle().await;

        let (status, body) = h
            .get(
                &format!("/v1/browser/tasks?employee_id={}", h.seat_a),
                SECRET_A,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let tasks = body["tasks"].as_array().expect("tasks");
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0]["id"], running.task_id.to_string(), "newest first");
        assert_eq!(tasks[0]["outcome"], "running");
        assert_eq!(tasks[0]["ended_at"], Value::Null);
        assert_eq!(tasks[1]["id"], done.task_id.to_string());
        assert_eq!(tasks[1]["employee_id"], h.seat_a.to_string());
        assert_eq!(tasks[1]["provider"], "chrome");
        assert_eq!(tasks[1]["context"], "ctx-test");
        assert_eq!(tasks[1]["outcome"], "failed:no_element");
        assert_eq!(tasks[1]["frames_sent"], 0);
        assert!(tasks[1]["ended_at"].is_string());
        let steps = tasks[1]["steps"].as_array().expect("steps");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["kind"], "goto");
        assert_eq!(steps[0]["url"], "https://portal.example.com/");
        assert_eq!(steps[0]["outcome"], "ok");
        assert_eq!(steps[0]["took_ms"], 12);
        assert!(steps[0]["at"].is_string());
        assert_eq!(steps[1]["url"], Value::Null);

        // Without the filter, the tenant's whole journal; with a bad limit, 400.
        let (_, body) = h.get("/v1/browser/tasks", SECRET_A).await;
        assert_eq!(body["tasks"].as_array().unwrap().len(), 2);
        let (_, body) = h.get("/v1/browser/tasks?limit=1", SECRET_A).await;
        assert_eq!(body["tasks"].as_array().unwrap().len(), 1);
        let (status, _) = h.get("/v1/browser/tasks?limit=201", SECRET_A).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // One task, and the neighbour's 404 — by id and by employee filter.
        let (status, body) = h
            .get(&format!("/v1/browser/tasks/{}", done.task_id), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "failed:no_element");
        let (status, _) = h
            .get(&format!("/v1/browser/tasks/{}", done.task_id), SECRET_B)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, body) = h
            .get(
                &format!("/v1/browser/tasks?employee_id={}", h.seat_a),
                SECRET_B,
            )
            .await;
        assert_eq!(body["tasks"].as_array().unwrap().len(), 0);

        h.journal
            .task_finished(&running, &StepOutcome::Ok, Utc::now());
        h.settle().await;
        h.teardown().await;
    }

    /// La connexion est l'abonnement : ouverte, `wants_frames` dit vrai et
    /// l'image poussée arrive en `event: frame` ; fermée, il dit faux.
    #[tokio::test]
    async fn the_live_view_relays_a_frame_and_is_the_switch() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let task = task(h.seat_a);
        assert!(!h.journal.wants_frames(&task));

        let response = h
            .raw(&format!("/v1/browser/live/{}", h.seat_a), SECRET_A)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("text/event-stream")),
            "{:?}",
            response.headers()
        );
        assert!(
            h.journal.wants_frames(&task),
            "the open connection is the switch"
        );

        h.journal.task_started(&task, Utc::now());
        h.journal.frame(&task, b"\xFF\xD8\xFFjpeg", Utc::now());

        let mut body = response.into_body().into_data_stream();
        let mut text = String::new();
        while !text.contains("event: frame") {
            let chunk = body
                .next()
                .await
                .expect("the stream is open")
                .expect("a chunk");
            text.push_str(std::str::from_utf8(&chunk).expect("utf-8"));
        }
        assert!(text.starts_with("event: task\ndata: {"), "{text}");
        assert!(
            text.contains(&format!("\"task_id\":\"{}\"", task.task_id)),
            "{text}"
        );
        assert!(text.contains("\"state\":\"started\""), "{text}");
        assert!(
            text.contains(&format!(
                "event: frame\ndata: {}\n\n",
                BASE64.encode(b"\xFF\xD8\xFFjpeg")
            )),
            "{text}"
        );

        drop(body);
        assert!(
            !h.journal.wants_frames(&task),
            "closing the connection is the other half"
        );

        // The neighbour's employee is not a screen this key may watch.
        let (status, _) = h
            .get(&format!("/v1/browser/live/{}", h.seat_b), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        h.journal.task_finished(&task, &StepOutcome::Ok, Utc::now());
        h.settle().await;
        h.teardown().await;
    }

    /// Le résumé compte les issues du jour, et le mur où qu'il soit.
    #[tokio::test]
    async fn the_summary_counts_the_outcomes_of_the_day() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.narrate(h.seat_a, &[("goto", StepOutcome::Ok)], StepOutcome::Ok)
            .await;
        h.narrate(
            h.seat_a,
            &[(
                "goto",
                StepOutcome::Refused {
                    code: "blocked_by_site",
                },
            )],
            StepOutcome::Refused {
                code: "blocked_by_site",
            },
        )
        .await;
        // A wall met at a step, on a task that then failed for another reason.
        h.narrate(
            h.seat_a,
            &[
                (
                    "goto",
                    StepOutcome::Refused {
                        code: "blocked_by_site",
                    },
                ),
                ("goto", StepOutcome::Ok),
            ],
            StepOutcome::Failed { code: "timeout" },
        )
        .await;
        h.narrate(
            h.seat_a,
            &[("goto", StepOutcome::Ok)],
            StepOutcome::Failed { code: "no_element" },
        )
        .await;
        h.narrate(h.seat_b, &[("goto", StepOutcome::Ok)], StepOutcome::Ok)
            .await;

        let (status, body) = h.get("/v1/browser/summary", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            serde_json::json!({
                "tasks_today": 4,
                "refused_today": 1,
                "failed_today": 2,
                "blocked_by_site_today": 2,
                "browser_js": false,
            })
        );
        let (_, body) = h.get("/v1/browser/summary", SECRET_B).await;
        assert_eq!(body["tasks_today"], 1);
        assert_eq!(body["blocked_by_site_today"], 0);

        h.teardown().await;
    }
}
