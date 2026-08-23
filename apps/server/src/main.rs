//! One binary: the HTTP control plane plus three tokio loops
//! (provisioning, outbox, inbound). No separate worker binaries.
//!
//! # The middleware stack, and why the order is the order
//!
//! Defined once, in [`with_outer_stack`] and [`with_api_stack`], because a
//! stack assembled per-router is a stack that is missing a layer on one router.
//!
//! ```text
//! request-id → trace → body limit → timeout → auth → rate limit → idempotency
//! ```
//!
//! * **request-id first** so every log line below it, including the trace
//!   layer's own, carries the same id. An id minted after tracing is an id
//!   that is not on the line you are reading.
//! * **body limit before timeout** so a 10 GB upload is refused on the first
//!   chunk instead of being read for thirty seconds and then refused.
//! * **auth before rate limit** because the rate limit is *per tenant*, and
//!   there is no tenant until the key has been checked. The other order gives
//!   an unauthenticated caller a way to consume a tenant's budget.
//! * **idempotency last**, i.e. innermost, so a replayed request is answered
//!   without running the handler but *after* it has been authenticated and
//!   counted. An idempotency layer above auth would let anyone read back
//!   another tenant's stored response.
//!
//! `/livez` and `/readyz` sit outside the API stack: a probe that needs a
//! credential is a probe that reports an outage the day the keyring is
//! misconfigured.

mod auth; // U30
mod config; // U30
mod error; // U30
mod loops; // U35 U36 U37
mod routes; // U31 U32 U33 U34

use std::collections::HashMap;
use std::future::IntoFuture;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentos_domain::ids::{IdempotencyKey, TenantId};
use agentos_store::db::Db;
use agentos_store::idempotency::{self, Begin};
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::auth::{ApiKeys, Principal};
use crate::config::{Config, ConfigError};
use crate::error::ApiError;

/// Largest request body we will read. Bigger than any control-plane payload
/// and smaller than anything that could exhaust memory.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Wall clock a handler gets before the client is answered 408.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests per tenant per [`RATE_WINDOW`].
const RATE_LIMIT: u32 = 600;

/// The rate limiter's window.
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// How long in-flight requests get to finish after SIGTERM before we stop
/// waiting. Must be under the orchestrator's own grace period (Kubernetes
/// defaults to 30s) or the pod is killed mid-drain and the deadline never
/// applies.
const DRAIN_DEADLINE: Duration = Duration::from_secs(20);

/// Oldest unpublished outbox event we will still call "ready", in seconds.
/// Beyond it the poller is wedged and this replica should stop taking work.
const MAX_OUTBOX_LAG_SECS: i64 = 300;

/// Why the process could not start or could not keep running.
#[derive(Debug, thiserror::Error)]
enum BootError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("database: {0}")]
    Store(#[from] agentos_store::db::StoreError),
    #[error("listener: {0}")]
    Io(#[from] std::io::Error),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Printed as well as traced: a configuration failure happens before
            // the subscriber exists, and the operator is reading a terminal or
            // a crash-loop log, not a structured sink.
            eprintln!("agentos-server: refusing to start: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Everything that can fail before there is a server.
///
/// The runtime is built by hand rather than with `#[tokio::main]` so that a
/// configuration error costs no threads and produces no half-initialised
/// tracing subscriber.
fn run() -> Result<(), BootError> {
    let config = Config::from_env()?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.rust_log))
        .json()
        .init();
    config.warn_about_mocks();
    tracing::info!(?config, "starting");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve_until_signal(config))
}

async fn serve_until_signal(config: Config) -> Result<(), BootError> {
    let db = Db::connect(&config.database_url).await?;
    db.migrate().await?;

    // ponytail: U35–U37 spawn their loops here, and their JoinHandles belong in
    // the drain below so a SIGTERM stops them too. Nothing to spawn yet.

    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(bind = %config.bind, "listening");

    serve(
        listener,
        app(db, config.api_keys.clone()),
        shutdown_signal(),
        DRAIN_DEADLINE,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/// The whole HTTP surface.
fn app(db: Db, keys: ApiKeys) -> Router {
    // ponytail: U31–U34 `.merge()` their routers into `api`, above the
    // `with_api_stack` call so they inherit it. Nothing else to do here.
    let api = with_api_stack(
        Router::new().route("/v1/whoami", get(whoami)),
        db.clone(),
        keys,
    );

    let health = Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .with_state(db);

    with_outer_stack(health.merge(api))
}

/// request-id → trace → body limit → timeout. Applies to health probes too:
/// a probe still wants a request id, and a probe that hangs should time out.
fn with_outer_stack(router: Router) -> Router {
    router.layer(
        ServiceBuilder::new()
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            .layer(PropagateRequestIdLayer::x_request_id())
            .layer(TraceLayer::new_for_http())
            .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            )),
    )
}

/// auth → rate limit → idempotency. Everything that needs to know who is
/// calling, in the order it can know it.
fn with_api_stack(router: Router, db: Db, keys: ApiKeys) -> Router {
    router.layer(
        ServiceBuilder::new()
            .layer(from_fn_with_state(keys, auth::require_api_key))
            .layer(from_fn_with_state(RateLimiter::default(), rate_limit))
            .layer(from_fn_with_state(db, replay_idempotent)),
    )
}

/// Which tenant this key speaks for.
///
/// The one endpoint this unit owns, and it earns its place twice: it is how an
/// operator confirms a newly issued key works, and it is the assertion that
/// the tenant a caller acts as comes from the credential — nothing in the
/// request can change this answer.
async fn whoami(principal: Principal) -> Json<Value> {
    Json(json!({
        "tenant_id": principal.tenant_id.as_uuid().to_string(),
        "actor": principal.actor.label(),
    }))
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// Liveness: the process is running and the runtime is scheduling.
///
/// Unconditional on purpose. Conflating it with readiness is how a pod that is
/// merely waiting on a slow database gets killed and restarted into the same
/// slow database, except now with a cold pool.
async fn livez() -> &'static str {
    "ok"
}

/// Readiness: this replica can usefully take traffic *right now*.
///
/// Two questions, both answerable in one round trip: can we get a connection,
/// and is the outbox draining? A wedged outbox means side effects are being
/// accepted and not performed, which is worse than refusing the request.
async fn readyz(State(db): State<Db>) -> Response {
    // Cross-tenant by nature: the poller's backlog is not any one tenant's.
    let mut tx = match db.admin_tx_bypassing_rls().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::warn!(error = %err, "not ready: no database connection");
            return not_ready("database").into_response();
        }
    };

    let lag: Option<i64> = match sqlx::query_scalar(
        "SELECT max(extract(epoch FROM now() - available_at))::bigint \
           FROM outbox_events \
          WHERE published_at IS NULL AND available_at <= now()",
    )
    .fetch_one(&mut *tx)
    .await
    {
        Ok(lag) => lag,
        Err(err) => {
            tracing::warn!(error = %err, "not ready: outbox query failed");
            return not_ready("database").into_response();
        }
    };

    let lag = lag.unwrap_or(0);
    if lag > MAX_OUTBOX_LAG_SECS {
        tracing::warn!(lag_secs = lag, "not ready: the outbox is not draining");
        return not_ready("outbox_lag").into_response();
    }

    (
        StatusCode::OK,
        Json(json!({"ready": true, "outbox_lag_secs": lag})),
    )
        .into_response()
}

fn not_ready(reason: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        reason,
        "this replica is not ready",
    )
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// A fixed-window counter per tenant.
///
/// ponytail: fixed window, in memory, one mutex. Two known ceilings, both
/// acceptable today: a tenant can send 2× the limit across a window boundary,
/// and the budget is per replica rather than per cluster. The upgrade is a
/// Postgres or Redis token bucket keyed on tenant — worth it when either the
/// burst or the replica count starts mattering, not before. The mutex is only
/// ever held for a few map operations and never across an `await`.
#[derive(Clone, Default)]
struct RateLimiter(Arc<Mutex<HashMap<TenantId, (Instant, u32)>>>);

impl RateLimiter {
    /// `true` if this request fits in the tenant's budget.
    fn allow(&self, tenant_id: TenantId) -> bool {
        let now = Instant::now();
        let mut windows = match self.0.lock() {
            Ok(windows) => windows,
            // A panicked holder left the map intact — this is a counter, not
            // an invariant. Refusing traffic because of it would be worse.
            Err(poisoned) => poisoned.into_inner(),
        };

        let (started, count) = windows.entry(tenant_id).or_insert((now, 0));
        if now.duration_since(*started) >= RATE_WINDOW {
            *started = now;
            *count = 0;
        }
        *count += 1;
        *count <= RATE_LIMIT
    }
}

async fn rate_limit(
    State(limiter): State<RateLimiter>,
    principal: Principal,
    req: Request,
    next: Next,
) -> Response {
    if limiter.allow(principal.tenant_id) {
        return next.run(req).await;
    }
    tracing::warn!(tenant_id = %principal.tenant_id, "tenant is over its request budget");
    ApiError::too_many_requests().into_response()
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

/// Run a keyed request once; answer every repeat from the record.
///
/// Only engages for mutating methods carrying an `Idempotency-Key` header —
/// a GET is already idempotent, and a POST without a key is the caller saying
/// it does not want this.
///
/// The claim is committed *before* the handler runs, exactly as
/// `store::idempotency` requires: an uncommitted claim makes a concurrent
/// request block on a row lock instead of being told the key is in flight.
async fn replay_idempotent(State(db): State<Db>, req: Request, next: Next) -> Response {
    let is_mutating = !matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    );
    let key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let (Some(raw_key), true) = (key, is_mutating) else {
        return next.run(req).await;
    };
    let key = match IdempotencyKey::from_client(&raw_key) {
        Ok(key) => key,
        Err(err) => {
            return ApiError::bad_request(format!("Idempotency-Key: {err}")).into_response();
        }
    };

    // The tenant, from the credential — so one tenant's key cannot collide
    // with, or read back, another's.
    let Some(principal) = req.extensions().get::<Principal>().cloned() else {
        tracing::error!("idempotency layer is mounted above the auth layer");
        return ApiError::internal().into_response();
    };

    // The endpoint is part of the key's identity: the same client key against
    // two endpoints is two requests.
    let endpoint = format!("{} {}", req.method(), req.uri().path());

    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => return ApiError::bad_request(err.to_string()).into_response(),
    };
    let hash = digest(&bytes);

    let mut tx = match db.tenant_tx(principal.tenant_id).await {
        Ok(tx) => tx,
        Err(err) => return ApiError::from(err).into_response(),
    };
    let begun = match idempotency::begin(&mut tx, &endpoint, &key, &hash).await {
        Ok(begun) => begun,
        Err(err) => return ApiError::from(err).into_response(),
    };
    // Committed before the handler runs, not after: see the doc comment.
    if let Err(err) = tx.commit().await {
        return ApiError::from(err).into_response();
    }

    match begun {
        Begin::Replay(stored) => {
            tracing::info!(%endpoint, "replaying a recorded response");
            (
                StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK),
                Json(stored.body),
            )
                .into_response()
        }
        Begin::InFlight => ApiError::conflict(
            "idempotency_in_flight",
            "an identical request is still running",
        )
        .into_response(),
        Begin::Execute => {
            let response = next
                .run(Request::from_parts(parts, Body::from(bytes)))
                .await;
            record(&db, principal.tenant_id, &endpoint, &key, response).await
        }
    }
}

/// Store the response against the key, or give the key back.
///
/// A 5xx releases the key: the client is meant to retry a 500, and a retry
/// that replays the 500 forever is worse than no idempotency at all. A
/// response that is not JSON is also released — the record column is `jsonb`,
/// and storing a placeholder would replay a body that is not the body.
async fn record(
    db: &Db,
    tenant_id: TenantId,
    endpoint: &str,
    key: &IdempotencyKey,
    response: Response,
) -> Response {
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));

    let (parts, body) = response.into_parts();
    let bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, "could not buffer a response to record it");
            return ApiError::internal().into_response();
        }
    };

    let stored: Option<Value> = if status.is_server_error() || !is_json {
        None
    } else {
        serde_json::from_slice(&bytes).ok()
    };

    let mut tx = match db.tenant_tx(tenant_id).await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(error = %err, "could not record an idempotent response");
            return Response::from_parts(parts, Body::from(bytes));
        }
    };
    let written = match &stored {
        Some(body) => idempotency::complete(&mut tx, endpoint, key, status.as_u16(), body).await,
        None => idempotency::release(&mut tx, endpoint, key).await,
    };
    if let Err(err) = written.and(tx.commit().await) {
        // The response still goes back; the client got its answer. What is
        // lost is the ability to replay it, which is worth a loud line.
        tracing::error!(error = %err, %endpoint, "idempotency record was not written");
    }

    Response::from_parts(parts, Body::from(bytes))
}

/// A stable digest of a request body.
///
/// ponytail: `DefaultHasher`, because `sha2` is not a dependency of this crate
/// and adding one for a change-detector is not worth it. It answers "is this
/// the same body?" and nothing else — it is never a security decision, and a
/// caller can only collide with its own key in its own tenant. Swap it for
/// SHA-256 the moment this crate has a hash for another reason.
fn digest(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// Resolves on SIGTERM (the orchestrator) or SIGINT (a human).
async fn shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                // Without SIGTERM we still have SIGINT; never returning from
                // this branch is correct, the other one is still live.
                Err(err) => {
                    tracing::error!(error = %err, "cannot listen for SIGTERM");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = interrupt => tracing::info!("SIGINT: draining"),
            () = terminate => tracing::info!("SIGTERM: draining"),
        }
    }

    #[cfg(not(unix))]
    {
        interrupt.await;
        tracing::info!("interrupt: draining");
    }
}

/// Serve until `shutdown` fires, then finish in-flight requests — but for no
/// longer than `drain`.
///
/// The deadline is the point: `with_graceful_shutdown` alone waits for the
/// last connection *forever*, so one slow client turns a rolling deploy into a
/// stuck one, and the orchestrator ends up sending SIGKILL — which drops every
/// in-flight request, including the ones that would have finished.
async fn serve<F>(
    listener: TcpListener,
    app: Router,
    shutdown: F,
    drain: Duration,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let (fired_tx, fired_rx) = oneshot::channel();
    let server = tokio::spawn(
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.await;
                let _ = fired_tx.send(());
            })
            .into_future(),
    );

    // Err means the server ended before any signal — the sender was dropped.
    // Either way the next step is the same: wait for the task, bounded.
    let _ = fired_rx.await;

    match tokio::time::timeout(drain, server).await {
        Ok(Ok(served)) => served,
        Ok(Err(join)) => Err(std::io::Error::other(join)),
        Err(_) => {
            tracing::warn!(
                drain_secs = drain.as_secs(),
                "drain deadline exceeded; abandoning in-flight requests"
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::post;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn keyring() -> (TenantId, ApiKeys) {
        let tenant = TenantId::from_uuid(Uuid::from_u128(42));
        let raw = format!("ops:{}:{SECRET}", tenant.as_uuid());
        (tenant, ApiKeys::parse(&raw).expect("valid"))
    }

    // -- the stack ---------------------------------------------------------

    /// The 401 has to come from the layer, not from a handler that remembered
    /// to check — so the route under test would panic if it were ever reached.
    #[tokio::test]
    async fn an_unauthenticated_request_never_reaches_a_handler() {
        async fn unreachable_handler() -> &'static str {
            panic!("the handler ran without a credential")
        }

        let (_, keys) = keyring();
        let router = Router::new().route("/employees/{id}", post(unreachable_handler));
        let app = with_outer_stack(router.layer(from_fn_with_state(keys, auth::require_api_key)));

        let response = app
            .oneshot(
                HttpRequest::post("/employees/e7cf")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("service");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // And the id it was minted with came back out, so an operator can grep
        // for the refusal.
        assert!(response.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused() {
        // The handler reads the body, because that is when the limit bites for
        // a request that lies about its length.
        let app = with_outer_stack(
            Router::new().route("/echo", post(|body: axum::body::Bytes| async move { body })),
        );

        let oversized = vec![0_u8; MAX_BODY_BYTES + 1];
        for declared in [true, false] {
            let mut req = HttpRequest::post("/echo");
            if declared {
                req = req.header(header::CONTENT_LENGTH, oversized.len());
            }
            let response = app
                .clone()
                .oneshot(req.body(Body::from(oversized.clone())).expect("request"))
                .await
                .expect("service");

            assert_eq!(
                response.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "declared content-length: {declared}"
            );
        }
    }

    #[tokio::test]
    async fn livez_answers_without_a_credential_or_a_database() {
        let response = with_outer_stack(Router::new().route("/livez", get(livez)))
            .oneshot(HttpRequest::get("/livez").body(Body::empty()).unwrap())
            .await
            .expect("service");

        assert_eq!(response.status(), StatusCode::OK);
    }

    // -- rate limiting -----------------------------------------------------

    #[test]
    fn the_budget_is_per_tenant_and_resets() {
        let limiter = RateLimiter::default();
        let a = TenantId::from_uuid(Uuid::from_u128(1));
        let b = TenantId::from_uuid(Uuid::from_u128(2));

        for i in 0..RATE_LIMIT {
            assert!(limiter.allow(a), "request {i} should fit");
        }
        assert!(!limiter.allow(a), "one past the budget is refused");
        assert!(
            limiter.allow(b),
            "one tenant must not spend another's budget"
        );

        // Rewind A's window by hand rather than sleeping a minute.
        {
            let mut windows = limiter.0.lock().expect("lock");
            let entry = windows.get_mut(&a).expect("A has a window");
            entry.0 = Instant::now() - RATE_WINDOW;
        }
        assert!(limiter.allow(a), "a new window starts a new budget");
    }

    // -- shutdown ----------------------------------------------------------

    /// The claim: a request that is already running when SIGTERM arrives gets
    /// to finish. A server that closed its connections on the signal would
    /// answer this one with a dropped socket.
    #[tokio::test]
    async fn a_signal_drains_in_flight_requests() {
        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();

        let app = Router::new().route(
            "/slow",
            get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "finished"
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(serve(
            listener,
            app,
            async move {
                let _ = shutdown_rx.await;
            },
            DRAIN_DEADLINE,
        ));

        // Get a request in flight...
        let mut socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        socket
            .write_all(b"GET /slow HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        while started.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // ...then pull the plug underneath it.
        shutdown_tx.send(()).expect("signal");

        let mut answer = String::new();
        socket.read_to_string(&mut answer).await.expect("read");
        assert!(
            answer.contains("200 OK") && answer.contains("finished"),
            "the in-flight request was cut off: {answer:?}"
        );

        server
            .await
            .expect("server task")
            .expect("server ended cleanly");
    }

    /// And the deadline is real: a request that outlasts it does not hold the
    /// process open.
    #[tokio::test]
    async fn the_drain_deadline_is_enforced() {
        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();

        let app = Router::new().route(
            "/forever",
            get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(600)).await;
                    "never"
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(serve(
            listener,
            app,
            async move {
                let _ = shutdown_rx.await;
            },
            Duration::from_millis(200),
        ));

        let mut socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        socket
            .write_all(b"GET /forever HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .expect("write");
        while started.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        shutdown_tx.send(()).expect("signal");

        // Without the deadline this would sit here for ten minutes.
        let ended = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve() must return once the deadline passes");
        assert!(ended.expect("task").is_ok());
    }

    // -- idempotency -------------------------------------------------------

    #[test]
    fn the_digest_changes_with_the_body() {
        assert_eq!(digest(b"{\"a\":1}"), digest(b"{\"a\":1}"));
        assert_ne!(digest(b"{\"a\":1}"), digest(b"{\"a\":2}"));
    }

    /// Needs a real Postgres: the whole point of the layer is the row it
    /// writes, and a mock of that row would be a mock of the test.
    #[tokio::test]
    async fn a_repeated_key_replays_instead_of_re_running() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the idempotency layer needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        // A tenant to own the records, and a key that names it.
        let tenant = TenantId::new_v7(chrono::Utc::now());
        let label = format!("srv-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");

        let keys = ApiKeys::parse(&format!("ops:{}:{SECRET}", tenant.as_uuid())).expect("keyring");
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = runs.clone();

        let app = with_api_stack(
            Router::new().route(
                "/things",
                post(move || {
                    let counter = counter.clone();
                    async move {
                        let n = counter.fetch_add(1, Ordering::SeqCst);
                        (StatusCode::CREATED, Json(json!({"run": n})))
                    }
                }),
            ),
            db.clone(),
            keys,
        );

        let send = |body: &'static str| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        HttpRequest::post("/things")
                            .header(header::AUTHORIZATION, format!("Bearer {SECRET}"))
                            .header("idempotency-key", "abcdefgh-0001")
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(body))
                            .expect("request"),
                    )
                    .await
                    .expect("service");
                let status = response.status();
                let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
                    .await
                    .expect("body");
                (status, serde_json::from_slice::<Value>(&bytes).ok())
            }
        };

        let first = send("{\"name\":\"a\"}").await;
        assert_eq!(first.0, StatusCode::CREATED);
        assert_eq!(first.1, Some(json!({"run": 0})));

        // Same key, same body: the stored answer, and the handler stays put.
        let replay = send("{\"name\":\"a\"}").await;
        assert_eq!(replay, first, "the replay must be byte-identical");
        assert_eq!(runs.load(Ordering::SeqCst), 1, "the handler ran twice");

        // Same key, different body: a client bug, and never a replay.
        let (status, _) = send("{\"name\":\"b\"}").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // A key too short to be unique is a 400, not a silent pass-through.
        let response = app
            .clone()
            .oneshot(
                HttpRequest::post("/things")
                    .header(header::AUTHORIZATION, format!("Bearer {SECRET}"))
                    .header("idempotency-key", "short")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("service");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
