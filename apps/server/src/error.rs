//! One error type for the whole HTTP surface, rendered as RFC 9457
//! `application/problem+json`.
//!
//! Two rules, and they are the whole module:
//!
//! 1. **Nothing a handler failed with is echoed to the caller.** Not the sqlx
//!    error, not the constraint name, not the policy limits the action broke.
//!    The client gets a status, a stable `code`, and a title. The operator gets
//!    the same `code` plus the real cause, on a `tracing` event, at the moment
//!    the error is constructed. That split is why the [`From`] impls log: the
//!    log line is the last place the detail exists.
//! 2. **`code` is a closed vocabulary.** It is `&'static str`, so it cannot be
//!    a formatted message, so a dashboard keyed on it cannot silently stop
//!    counting because somebody reworded a sentence.
//!
//! `detail` exists for the cases where the caller genuinely needs to know what
//! *they* did wrong — a malformed idempotency key, a body that is not JSON.
//! It is never filled from a server-side error.

use agentos_app::gate::Denied;
use agentos_store::db::StoreError;
use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

/// The `type` URI prefix. Relative-resolved against the API's own docs; RFC
/// 9457 allows a relative URI, and a real page is better than `about:blank`.
const TYPE_PREFIX: &str = "/problems/";

/// One failed request.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    /// Stable machine-readable code. Low cardinality, safe to put on a metric.
    code: &'static str,
    /// Short human title. Never contains anything server-side.
    title: &'static str,
    /// Optional caller-facing explanation of what *the caller* got wrong.
    detail: Option<String>,
    /// RFC 9457 extension members.
    extra: Map<String, Value>,
}

impl ApiError {
    /// Build an error. `code` and `title` must be literals — see the module
    /// docs on why the vocabulary is closed.
    pub fn new(status: StatusCode, code: &'static str, title: &'static str) -> Self {
        Self {
            status,
            code,
            title,
            detail: None,
            extra: Map::new(),
        }
    }

    /// Add a caller-facing explanation. **Only for input the caller controls.**
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add one RFC 9457 extension member.
    #[must_use]
    pub fn with_extension(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_owned(), value);
        self
    }

    // -- the shorthands the route units reach for -------------------------
    //
    // Constructed here rather than in four route modules so that four units
    // cannot invent four spellings of "not found".

    /// 400: the request body or parameters are not usable.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", "malformed request").with_detail(detail)
    }

    /// 401: no usable credential was presented.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "a valid API key is required",
        )
    }

    /// 404: no such resource in this tenant. Indistinguishable from "exists,
    /// but belongs to someone else", deliberately.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "no such resource")
    }

    /// 409: the request collides with state that already exists.
    pub fn conflict(code: &'static str, title: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, code, title)
    }

    /// 429: this tenant is over its request budget.
    pub fn too_many_requests() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests for this tenant",
        )
    }

    /// 500: we broke. Nothing about how.
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = self.extra;
        body.insert(
            "type".to_owned(),
            json!(format!("{TYPE_PREFIX}{}", self.code)),
        );
        body.insert("title".to_owned(), json!(self.title));
        body.insert("status".to_owned(), json!(self.status.as_u16()));
        body.insert("code".to_owned(), json!(self.code));
        if let Some(detail) = self.detail {
            body.insert("detail".to_owned(), json!(detail));
        }

        let mut response = (self.status, Json(Value::Object(body))).into_response();
        // Json() sets application/json; RFC 9457 wants problem+json, and some
        // clients switch parsers on it.
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

impl From<StoreError> for ApiError {
    /// The database's vocabulary, translated once.
    ///
    /// [`StoreError::Serialization`] is a 503 rather than a 500 because it is
    /// the one failure that is *known* to succeed on retry — a client that
    /// retries a 500 is guessing, a client that retries a 503 was told to.
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::NotFound => Self::not_found(),
            StoreError::Conflict(what) => {
                // The constraint name is an internal detail; the operator gets
                // it, the caller gets the code.
                tracing::warn!(conflict = %what, "request lost a uniqueness race");
                Self::conflict("conflict", "the request conflicts with existing state")
            }
            StoreError::Serialization => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "serialization_failure",
                "the transaction was aborted; retry",
            ),
            StoreError::Database(err) => {
                tracing::error!(error = %err, "database error");
                Self::internal()
            }
        }
    }
}

impl From<Denied> for ApiError {
    /// The Policy Gate's refusal, rendered without its reasoning.
    ///
    /// `code` carries the gate's own stable reason — `daily_limit`,
    /// `channel_not_allowed` — which is what an operator needs to answer "why
    /// was this refused?". What never crosses is the *shape* of the policy:
    /// the caps, the thresholds, the intersected layers. Telling an agent
    /// exactly which limit it hit is telling it exactly how to stay under one.
    ///
    /// ponytail: `PendingApproval` is a 403 with an `approval_id` extension
    /// rather than a 202. It is not "accepted", nothing is queued, and a
    /// problem+json body under a 2xx confuses every client library. Revisit if
    /// the API grows a polling endpoint that wants a Location header.
    fn from(denied: Denied) -> Self {
        let code = denied.code();
        match denied {
            Denied::Unavailable(err) => err.into(),
            Denied::BrokenPolicy(err) => {
                // Fails closed, and loudly: an incoherent policy is an operator
                // emergency, not a client mistake.
                tracing::error!(error = %err, "policy layers do not intersect coherently");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    code,
                    "the configured policy cannot be evaluated",
                )
            }
            Denied::UnknownEmployee => Self::not_found(),
            Denied::PendingApproval(id) => Self::new(
                StatusCode::FORBIDDEN,
                code,
                "a human approval is required before this action can run",
            )
            .with_extension("approval_id", json!(id.as_uuid().to_string())),
            Denied::NotActive(_) | Denied::Policy(_) | Denied::Redemption(_) => {
                Self::new(StatusCode::FORBIDDEN, code, "the action was not permitted")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::ApprovalId;
    use agentos_domain::policy::DenyReason;
    use axum::body::to_bytes;
    use uuid::Uuid;

    use super::*;

    /// `(status, content-type, body)`.
    async fn render(err: ApiError) -> (StatusCode, String, Value) {
        let response = err.into_response();
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (
            status,
            content_type,
            serde_json::from_slice(&bytes).expect("problem+json"),
        )
    }

    #[tokio::test]
    async fn a_problem_document_carries_the_code_and_nothing_else() {
        let (status, content_type, body) = render(ApiError::not_found()).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(content_type, "application/problem+json");
        assert_eq!(body["status"], json!(404));
        assert_eq!(body["code"], json!("not_found"));
        assert_eq!(body["type"], json!("/problems/not_found"));
        assert_eq!(body["detail"], Value::Null, "no detail was set");
    }

    #[tokio::test]
    async fn a_database_error_never_reaches_the_caller() {
        let err = ApiError::from(StoreError::Conflict("employees_tenant_slug_key".to_owned()));
        let (status, _, body) = render(err).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], json!("conflict"));
        let rendered = body.to_string();
        assert!(
            !rendered.contains("employees_tenant_slug_key"),
            "the constraint name is an internal detail: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_retryable_abort_is_a_503_not_a_500() {
        let (status, _, body) = render(StoreError::Serialization.into()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["code"], json!("serialization_failure"));
    }

    #[tokio::test]
    async fn a_denial_carries_its_reason_code_but_not_the_policy() {
        let (status, _, body) = render(Denied::Policy(DenyReason::DailyLimit).into()).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body["code"],
            json!(DenyReason::DailyLimit.code()),
            "the operator needs the reason code"
        );
        // The caller is told it was refused, not what the ceiling is.
        assert_eq!(body["title"], json!("the action was not permitted"));
        assert_eq!(body["detail"], Value::Null);
    }

    #[tokio::test]
    async fn a_pending_approval_names_the_approval() {
        let id = ApprovalId::from_uuid(Uuid::nil());
        let (status, _, body) = render(Denied::PendingApproval(id).into()).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], json!("pending_approval"));
        assert_eq!(body["approval_id"], json!(id.as_uuid().to_string()));
    }

    #[tokio::test]
    async fn an_unknown_employee_is_a_404_not_a_403() {
        // Otherwise "403" versus "404" tells an unauthenticated prober which
        // employee ids exist.
        let (status, _, _) = render(Denied::UnknownEmployee.into()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
