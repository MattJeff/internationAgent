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
//!
//! # Le proxy (v3) — quatre routes, et un mot de passe qui ne ressort jamais
//!
//! | Route | Réponse |
//! |---|---|
//! | `GET /v1/browser/proxy` | 200 `{url, has_credentials, bypass, checked_at, last_error}` ; 404 `no_proxy` |
//! | `PUT /v1/browser/proxy {url, username?, password?, bypass?}` | 200 la ligne |
//! | `DELETE /v1/browser/proxy` | 204, y compris quand il n'y en avait pas |
//! | `POST /v1/browser/proxy/check {echo_url}` | 200 `{ip, took_ms}` ; 400 `no_echo_url` ; 422 le code nommé |
//!
//! **Le mot de passe n'a pas de chemin de retour.** Il entre dans le corps d'un
//! `PUT`, il est scellé à la ligne suivante sous `browser://<locataire>/proxy`
//! (`agentos_app::browser_proxy`), et il ne ressort ni de [`ProxyView`] — qui
//! n'a pas de champ pour, c'est le type qui l'empêche — ni d'une ligne de
//! journal : les `tracing::info!` d'ici nomment l'URL et un booléen, et le
//! rejet d'un corps mal formé est rendu avec un **texte fixe** plutôt qu'avec
//! le message de serde, qui cite parfois la valeur qu'il n'a pas comprise.
//! `the_proxy_password_never_appears_in_a_response_or_a_log` capture tout ce
//! que `tracing` émet pendant les quatre routes et y cherche les octets.
//!
//! Ces routes sont **la prise, pas la ressource** : ce déploiement ne loue
//! aucune adresse IP et n'écrit l'URL d'aucun tiers en dur, service d'écho
//! compris — voir `agentos_app::browser_proxy` sur pourquoi `echo_url` n'a pas
//! de défaut.

use std::sync::Arc;
use std::time::Duration;

use agentos_app::browser_journal::{Journal, Live};
use agentos_app::browser_proxy::{self, Refusal};
use agentos_app::identity::LocalEnvelopeSecretStore;
use agentos_domain::ids::EmployeeId;
use agentos_store::db::{Db, StoreError};
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get as get_route, post};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// Ce que les routes partagent.
#[derive(Clone)]
pub struct BrowserState {
    pub db: Db,
    pub journal: Arc<Journal>,
    /// [`crate::config::Config::browser_js`], le même booléen que `/readyz`.
    pub browser_js: bool,
    /// Le chiffre du déploiement, pour sceller et ouvrir les identifiants du
    /// proxy. Le même que celui que `SealedProxies` tient de l'autre côté :
    /// deux instances dérivées de la même clé maître, comme partout ailleurs.
    pub cipher: Arc<LocalEnvelopeSecretStore>,
}

pub fn router(state: BrowserState) -> Router {
    Router::new()
        .route("/v1/browser/tasks", get_route(list))
        .route("/v1/browser/tasks/{id}", get_route(one))
        .route("/v1/browser/live/{employee_id}", get_route(live))
        .route("/v1/browser/summary", get_route(summary))
        .route(
            "/v1/browser/proxy",
            get_route(proxy_get).put(proxy_put).delete(proxy_delete),
        )
        .route("/v1/browser/proxy/check", post(proxy_check))
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
// Le proxy
// ---------------------------------------------------------------------------

/// La ligne sur le fil. **Aucun champ pour le mot de passe** : `has_credentials`
/// est tout ce qu'un lecteur obtient, et c'est le type qui le garantit plutôt
/// qu'une discipline de sérialisation qu'on oublierait au prochain champ.
#[derive(Debug, Serialize)]
struct ProxyView {
    url: String,
    has_credentials: bool,
    bypass: Option<String>,
    checked_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

impl From<browser_proxy::Row> for ProxyView {
    fn from(row: browser_proxy::Row) -> Self {
        Self {
            url: row.url,
            has_credentials: row.has_credentials,
            bypass: row.bypass,
            checked_at: row.checked_at,
            last_error: row.last_error,
        }
    }
}

/// Pas de `Debug`, exprès : un des champs est un mot de passe.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyBody {
    url: String,
    username: Option<String>,
    password: Option<String>,
    bypass: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckBody {
    echo_url: Option<String>,
}

fn no_proxy() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "no_proxy",
        "this tenant has no browser proxy",
    )
}

/// Un refus de `browser_proxy`, en statut et en code.
fn refused(err: Refusal) -> ApiError {
    match err {
        Refusal::BadUrl(detail) => {
            ApiError::new(StatusCode::BAD_REQUEST, "bad_url", "not a proxy address")
                .with_detail(detail)
        }
        Refusal::NoProxy => no_proxy(),
        Refusal::NoEcho => ApiError::new(
            StatusCode::BAD_REQUEST,
            "no_echo_url",
            "no echo service was given",
        )
        .with_detail(Refusal::NoEcho.to_string()),
        // 422 et le code nommé : le proxy est une ressource du client, donc
        // « il ne répond pas » est un fait sur ce qu'il a acheté et non une
        // panne de ce déploiement. Le code est le nôtre et jamais le message
        // du proxy, qui est du texte d'un tiers.
        Refusal::CheckFailed(code) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            "the proxy did not answer",
        ),
        Refusal::Provider(err) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            err.code(),
            "the sealed credentials could not be used",
        ),
        Refusal::Store(err) => ApiError::from(err),
    }
}

async fn proxy_get(
    State(state): State<BrowserState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row = browser_proxy::get(&mut tx).await?;
    tx.rollback().await?;
    match row {
        Some(row) => Ok((StatusCode::OK, axum::Json(ProxyView::from(row))).into_response()),
        None => Err(no_proxy()),
    }
}

async fn proxy_put(
    State(state): State<BrowserState>,
    principal: Principal,
    body: Result<axum::Json<ProxyBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    // Un texte fixe : le message de serde cite parfois la valeur qu'il n'a pas
    // comprise, et l'une des valeurs de ce corps est un mot de passe.
    let axum::Json(body) = body.map_err(|_| {
        ApiError::bad_request(
            "body must be {\"url\": \"http://host:port\", \"username\"?, \"password\"?, \"bypass\"?}",
        )
    })?;
    // Les deux moitiés ou aucune : un nom d'utilisateur sans mot de passe est
    // une ligne à moitié écrite, et `Proxy-Authorization` en veut deux.
    let credentials = match (&body.username, &body.password) {
        (Some(username), Some(password)) => Some((username.as_str(), password.as_str())),
        (None, None) => None,
        _ => {
            return Err(ApiError::bad_request(
                "username and password go together: send both, or neither",
            ));
        }
    };
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let row = browser_proxy::set(
        &mut tx,
        &state.cipher,
        &body.url,
        credentials,
        body.bypass.as_deref(),
    )
    .await
    .map_err(refused)?;
    tx.commit().await?;
    tracing::info!(
        tenant_id = %principal.tenant_id,
        url = %row.url,
        has_credentials = row.has_credentials,
        "browser proxy set"
    );
    Ok((StatusCode::OK, axum::Json(ProxyView::from(row))).into_response())
}

async fn proxy_delete(
    State(state): State<BrowserState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let had = browser_proxy::clear(&mut tx).await?;
    tx.commit().await?;
    // 204 dans les deux cas : l'appelant demande un état — « ce locataire n'a
    // pas de proxy » — et l'état est vrai. La même règle que le contrat de
    // `release` des fournisseurs.
    tracing::info!(tenant_id = %principal.tenant_id, had, "browser proxy cleared");
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn proxy_check(
    State(state): State<BrowserState>,
    principal: Principal,
    body: Option<axum::Json<CheckBody>>,
) -> Result<Response, ApiError> {
    let echo_url = body.and_then(|axum::Json(body)| body.echo_url);
    let mut tx = state.db.tenant_tx(principal.tenant_id).await?;
    let checked = browser_proxy::check(&mut tx, &state.cipher, echo_url.as_deref()).await;
    // Le verdict est écrit sur la ligne même quand il est mauvais, donc la
    // transaction se valide dans les deux cas — sauf si rien n'a été tenté.
    let checked = match checked {
        Ok(checked) => {
            tx.commit().await?;
            checked
        }
        Err(err @ (Refusal::NoEcho | Refusal::BadUrl(_) | Refusal::NoProxy)) => {
            tx.rollback().await?;
            return Err(refused(err));
        }
        Err(err) => {
            tx.commit().await?;
            return Err(refused(err));
        }
    };
    tracing::info!(
        tenant_id = %principal.tenant_id,
        ip = %checked.ip,
        took_ms = checked.took_ms,
        "browser proxy checked"
    );
    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({ "ip": checked.ip, "took_ms": checked.took_ms })),
    )
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
    use serde_json::json;
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt as _;

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
                        cipher: agentos_app::identity::envelope(crate::auth::TEST_MASTER_KEY),
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

        /// N'importe quelle méthode, avec ou sans corps.
        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
            let body = match body {
                Some(json) => {
                    req = req.header(header::CONTENT_TYPE, "application/json");
                    Body::from(json.to_string())
                }
                None => Body::empty(),
            };
            let response = self
                .app
                .clone()
                .oneshot(req.body(body).expect("request"))
                .await
                .expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
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

    // -- le proxy ----------------------------------------------------------------

    /// Tout ce que `tracing` émet pendant un appel, champs compris, rendu en
    /// texte — pour y chercher des octets qui ne doivent pas y être. La même
    /// couche que `routes::domain`, écrite deux fois parce que les deux modules
    /// de test ne se voient pas.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<String>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            use std::fmt::Write as _;
            struct Render<'a>(&'a mut String);
            impl tracing::field::Visit for Render<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    let _ = write!(self.0, "{}={:?} ", field.name(), value);
                }
            }
            let mut out = self.0.lock().expect("not poisoned");
            let _ = write!(out, "[{}] ", event.metadata().target());
            event.record(&mut Render(&mut out));
            out.push('\n');
        }
    }

    /// Les quatre routes dans leur forme exacte, la RLS entre deux locataires,
    /// et **le mot de passe qui ne ressort ni d'une réponse ni d'un journal**.
    #[tokio::test]
    async fn the_proxy_password_never_appears_in_a_response_or_a_log() {
        const PASSWORD: &str = "s3cr3t-de-passage-7f3a";
        let Some(h) = Harness::new().await else {
            return;
        };
        let captured = Captured::default();
        let _log =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));

        // Rien : 404 nommé, des deux côtés.
        let (status, body) = h.get("/v1/browser/proxy", SECRET_A).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], "no_proxy");
        // Et un `DELETE` sur rien est quand même 204 : l'appelant demande un
        // état, et l'état est déjà vrai.
        let (status, _) = h.send("DELETE", "/v1/browser/proxy", SECRET_A, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Une adresse mal formée, et surtout : les identifiants dans l'URL.
        for bad in [
            "gate.example.com:7000",
            "ftp://gate.example.com",
            &format!("http://orizn:{PASSWORD}@gate.example.com:7000"),
            "http://gate.example.com:7000/rotate",
        ] {
            let (status, body) = h
                .send(
                    "PUT",
                    "/v1/browser/proxy",
                    SECRET_A,
                    Some(json!({ "url": bad })),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{bad} was accepted: {body}"
            );
            assert_eq!(body["code"], "bad_url");
        }
        // Une moitié d'identifiants n'est pas un identifiant.
        let (status, body) = h
            .send(
                "PUT",
                "/v1/browser/proxy",
                SECRET_A,
                Some(json!({ "url": "http://gate.example.com:7000", "username": "orizn" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Posé, avec ses identifiants et son bypass.
        let (status, body) = h
            .send(
                "PUT",
                "/v1/browser/proxy",
                SECRET_A,
                Some(json!({
                    "url": "http://gate.example.com:7000",
                    "username": "orizn-eu",
                    "password": PASSWORD,
                    "bypass": "<-loopback>",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            json!({
                "url": "http://gate.example.com:7000",
                "has_credentials": true,
                "bypass": "<-loopback>",
                "checked_at": null,
                "last_error": null,
            }),
            "the shape on the wire, and no field for the password"
        );

        // Relu à l'identique, et invisible au voisin.
        let (status, again) = h.get("/v1/browser/proxy", SECRET_A).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again, body);
        let (status, _) = h.get("/v1/browser/proxy", SECRET_B).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the neighbour saw it");
        // Et le voisin ne l'efface pas non plus.
        h.send("DELETE", "/v1/browser/proxy", SECRET_B, None).await;
        let (status, _) = h.get("/v1/browser/proxy", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "the neighbour deleted it");

        // La vérification : sans service d'écho, rien n'est vérifié et on le
        // dit — il n'y a pas d'URL de tiers en dur dans ce dépôt.
        let (status, body) = h
            .send("POST", "/v1/browser/proxy/check", SECRET_A, Some(json!({})))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "no_echo_url");
        // Avec un écho, mais un proxy qui n'existe pas : le code nommé, et le
        // verdict reste sur la ligne pour la console.
        let (status, body) = h
            .send(
                "POST",
                "/v1/browser/proxy/check",
                SECRET_A,
                Some(json!({ "echo_url": "http://echo.invalid/ip" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["code"], agentos_app::browser_proxy::PROXY_UNREACHABLE);
        let (_, body) = h.get("/v1/browser/proxy", SECRET_A).await;
        assert!(body["checked_at"].is_string(), "{body}");
        assert_eq!(
            body["last_error"],
            agentos_app::browser_proxy::PROXY_UNREACHABLE
        );

        // Retiré : 204, et il n'y a plus rien.
        let (status, _) = h.send("DELETE", "/v1/browser/proxy", SECRET_A, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = h.get("/v1/browser/proxy", SECRET_A).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // **La garde.** La capture a bien vu quelque chose — sinon elle ne
        // prouve rien — et le mot de passe n'y est pas.
        let log = captured.0.lock().expect("not poisoned").clone();
        assert!(
            log.contains("browser proxy set"),
            "the capture saw nothing, so it proves nothing:\n{log}"
        );
        assert!(
            log.contains("gate.example.com"),
            "the capture saw no URL either:\n{log}"
        );
        assert!(
            !log.contains(PASSWORD),
            "the password reached a log line:\n{log}"
        );
        assert!(
            !log.contains("orizn-eu"),
            "the username reached a log line:\n{log}"
        );

        h.teardown().await;
    }
}
