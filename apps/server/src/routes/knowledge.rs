//! `POST /v1/knowledge/documents`: put a document where the employee can find
//! it.
//!
//! # The one thing this route is really for
//!
//! It is a small handler — parse, chunk, embed, insert — and the only line in
//! it that matters is `trust: TrustLabel::Untrusted`.
//!
//! A document is the one kind of third-party text in this system that does not
//! reach the model on the turn that received it. An email is verified, framed
//! and answered in one flow, with the provenance right there in the request. A
//! document is accepted on Tuesday and retrieved into a prompt on Friday, on a
//! turn that never saw this request, past every check applied here. By then the
//! only thing that still knows where the bytes came from is the row — so the
//! answer is written into the row, now, at the boundary, and not guessed at
//! later. That is the same rule `agentos_app::inbound` follows for a message
//! and its attachments, spelled the same way, into a column with the same name
//! and the same vocabulary.
//!
//! And it is `Untrusted` even for an operator with a valid API key, which is
//! worth saying out loud because it looks over-strict. An operator uploading a
//! document is almost always a *forwarder*: the supplier's price list, the
//! customer's specification, the partner's contract, the PDF somebody emailed
//! and an admin dragged into the console. Nothing at this boundary can separate
//! "the handbook we wrote" from "a stranger's document our admin forwarded",
//! and the failure mode of guessing wrong is a stranger writing the employee's
//! briefing. So the route does not guess.
//!
//! What that label does *not* do is decide whether a turn retrieving the
//! document is tainted — that happens unconditionally, for a reason that has
//! nothing to do with this route and everything to do with who chooses the
//! search query. `crates/app/src/knowledge.rs` has the argument.
//!
//! # Not idempotency-keyed, unlike `POST /v1/employees`
//!
//! Creating an employee buys phone numbers, so a retry without a key is a
//! duplicate somebody pays for. Ingest has no such edge: the normalised text is
//! checksummed and a re-ingest of the same bytes returns the existing source
//! with `reused: true` and writes nothing. The dedupe is the idempotency, it is
//! keyed on the content rather than on the client remembering a header, and it
//! is answered 200 rather than 201 so a caller can tell.
//!
//! # No search endpoint
//!
//! ponytail: retrieval happens on the turn, from `knowledge::recall`, and there
//! is no customer asking to run a query by hand. `GET /v1/knowledge/search`
//! when somebody needs to debug what an employee can see — it is ten lines and
//! the store already does the work.

use agentos_app::knowledge::{Document, Embedder, Format, KnowledgeError, Scope, ingest};
use agentos_domain::ids::EmployeeId;
use agentos_domain::untrusted::TrustLabel;
use agentos_store::db::{Db, StoreError, TenantTx};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// The database and the embedder this deployment's credentials selected.
///
/// The embedder arrives from `main.rs` rather than being built here for the
/// same reason every other adapter does: `config.rs` is the one place that
/// reads the environment, and an ingest route that picked its own embedder
/// would be a second answer to "which model is this deployment on" — which is
/// a question the `model` column on every chunk has to have exactly one answer
/// to.
#[derive(Clone)]
pub struct KnowledgeState {
    db: Db,
    embedder: Embedder,
}

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is where
/// the 401 for a missing credential comes from, well before this handler, and
/// the 1 MB body cap comes from `with_outer_stack` outside that.
pub fn router(db: Db, embedder: Embedder) -> Router {
    Router::new()
        .route("/v1/knowledge/documents", post(create_document))
        .with_state(KnowledgeState { db, embedder })
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The ingest body. `deny_unknown_fields` so a client that misspells a field
/// finds out now rather than wondering why it had no effect — and, here, so
/// that a client cannot try to send a `trust` field and be quietly ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDocument {
    /// Scope the document to one employee. Absent and with no `team_id` makes
    /// it company-wide, which is the right default for a handbook and the wrong
    /// one for a sprint board.
    #[serde(default)]
    employee_id: Option<Uuid>,
    /// Scope the document to one team, by `teams.id`. Its members retrieve it;
    /// a sibling team does not.
    ///
    /// Two optional fields rather than one tagged object because that is what
    /// the three-way choice looks like on the wire, and sending both is a 400 —
    /// see [`scope_of`]. Absent from an old client's body means company-wide,
    /// which is exactly what that client used to get.
    #[serde(default)]
    team_id: Option<Uuid>,
    /// Where it came from, for citation.
    #[serde(default)]
    uri: Option<String>,
    /// Human label.
    #[serde(default)]
    title: Option<String>,
    /// `text` or `markdown`. Defaults to `text`; anything else is a 400 rather
    /// than a silent fall back, because Markdown headings are chunk boundaries
    /// and getting that wrong degrades retrieval invisibly.
    #[serde(default)]
    format: Format,
    /// The document, already decoded to UTF-8. PDF is out of scope — see
    /// `agentos_app::knowledge`.
    text: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `POST /v1/knowledge/documents` — chunk, embed and store one document.
///
/// **201 when something was written, 200 when this exact text was already on
/// file.** The body says which either way, so a client that does not care can
/// treat both as success and one that is reconciling can tell.
async fn create_document(
    State(KnowledgeState { db, embedder }): State<KnowledgeState>,
    principal: Principal,
    body: Result<Json<NewDocument>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let scope = scope_of(&mut tx, &body).await?;

    let document = Document {
        scope,
        uri: body.uri.as_deref(),
        title: body.title.as_deref(),
        format: body.format,
        // **The line this route exists for.** Not a parameter, not a default,
        // not inferred from the credential: see the module docs.
        trust: TrustLabel::Untrusted,
        text: &body.text,
    };

    // Whichever `EMBEDDER_API_KEY` selected. Unset is the deterministic hash —
    // no key, no network, no spend — so ingest works on a laptop and in CI
    // exactly as it does in a deployment, and `AGENTOS_ALLOW_MOCKS` is what a
    // deployment has to say out loud to run on it. The choice is `Config`'s and
    // arrives here already made.
    let ingested = ingest(&mut tx, &embedder, &document)
        .await
        .map_err(ingest_failed)?;
    tx.commit().await?;

    tracing::info!(
        tenant_id = %principal.tenant_id,
        source_id = %ingested.source_id,
        chunks = ingested.chunks,
        reused = ingested.reused,
        // Who can retrieve it, in the log line that records it arriving. The
        // dedupe path returns an existing source and does not re-scope it, so
        // this says what was *asked for*; the row is the answer either way.
        scope = ?scope,
        "document ingested as untrusted"
    );

    let status = if ingested.reused {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(json!({
            "source_id": ingested.source_id,
            "chunks": ingested.chunks,
            "reused": ingested.reused,
            // Echoed rather than assumed. A caller reconciling what an employee
            // can see should be able to read the provenance off the response
            // instead of trusting a sentence in the docs.
            "trust_label": "untrusted",
        })),
    )
        .into_response())
}

/// Turn the body's two optional ids into the one scope the document gets.
///
/// Three answers and a refusal. Both ids set is a 400 rather than a precedence
/// rule, because a precedence rule is a silent decision about who can read a
/// document — a caller that meant one of them should be told which one it did
/// not get.
///
/// Either id belonging to another tenant is a 404, never a 403: invisible under
/// RLS is the same answer as absent, the same rule as `routes::employees`. It is
/// load-bearing beyond tidiness here, because the scope is a retrieval key. A
/// document filed against a team or an employee this tenant does not have is a
/// document no query in this tenant ever asks for — stored, billed for, and
/// permanently unretrievable.
async fn scope_of(tx: &mut TenantTx<'_>, body: &NewDocument) -> Result<Scope, ApiError> {
    match (body.employee_id, body.team_id) {
        (None, None) => Ok(Scope::Company),
        (Some(employee), None) => Ok(Scope::Employee(EmployeeId::from_uuid(
            known(tx, "SELECT id FROM employees WHERE id = $1", employee).await?,
        ))),
        (None, Some(team)) => Ok(Scope::Team(
            known(tx, "SELECT id FROM teams WHERE id = $1", team).await?,
        )),
        (Some(_), Some(_)) => Err(ApiError::bad_request(
            "employee_id and team_id: a document belongs to the company, to one team, \
             or to one employee — pick one",
        )),
    }
}

/// `id`, if this tenant has a row with it. [`ApiError::not_found`] otherwise.
///
/// `sql` is one of two string literals in the match above and never comes from
/// input; there is nothing here for a caller to steer.
async fn known(tx: &mut TenantTx<'_>, sql: &'static str, id: Uuid) -> Result<Uuid, ApiError> {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(StoreError::from)?
        .ok_or_else(ApiError::not_found)
}

/// The ingest vocabulary, translated once.
fn ingest_failed(err: KnowledgeError) -> ApiError {
    match err {
        KnowledgeError::Store(err) => err.into(),
        // The caller's mistake, and the one message here that names what they
        // sent: a document that is whitespace once normalised would store a
        // source with no chunks, which is a row that can never be retrieved and
        // can never be re-ingested either.
        KnowledgeError::Empty => {
            ApiError::bad_request("text: the document is empty once whitespace is normalised")
        }
        // Unreachable while the only embedder is the local one, and a 503
        // rather than a 500 for when that stops being true: an embedding
        // backend having a bad minute is precisely the failure a client should
        // retry.
        KnowledgeError::Embed(err) => {
            tracing::error!(error = %err, "the embedder refused a document");
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "embedder_unavailable",
                "the document could not be embedded; retry",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::knowledge::{Recall, recall};
    use agentos_domain::ids::TenantId;
    use agentos_domain::untrusted::Untrusted;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use chrono::Utc;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    /// Long enough for `ApiKeys::MIN_SECRET_LEN`, and distinct per tenant.
    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The exact token no embedder places usefully, and the reason the
    /// full-text leg exists.
    const SKU: &str = "BRK-4471-XZ";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        /// `None` when there is no database. What this endpoint is for is a row
        /// with a provenance column and an RLS-scoped retrieval over it;
        /// mocking that mocks the test.
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; knowledge routes need a real Postgres");
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
                    router(db.clone(), Embedder::default()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        /// POST a document as `secret`'s tenant. `secret: None` sends no
        /// credential at all.
        async fn post(&self, body: Value, secret: Option<&str>) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder()
                .method("POST")
                .uri("/v1/knowledge/documents")
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(secret) = secret {
                req = req.header(header::AUTHORIZATION, format!("Bearer {secret}"));
            }
            let req = req.body(Body::from(body.to_string())).expect("request");

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

        /// What this tenant's employee would actually retrieve for `question`.
        async fn recalled(&self, tenant: TenantId, question: &str) -> Vec<String> {
            let question = Untrusted::new(question.to_owned());
            let recalled = recall(
                &self.db,
                &Embedder::default(),
                tenant,
                &Recall::new(&question, None),
            )
            .await;
            assert!(!recalled.unavailable(), "the store was not reachable");
            recalled
                .hits()
                .iter()
                .map(|hit| hit.content.expose_for_parsing().clone())
                .collect()
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'knowledge-route-test')")
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

    async fn team(db: &Db, tenant: TenantId, slug: &str) -> Uuid {
        let id = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query("INSERT INTO teams (id, tenant_id, slug, name) VALUES ($1, $2, $3, $3)")
            .bind(id)
            .bind(tenant.as_uuid())
            .bind(slug)
            .execute(&mut **tx)
            .await
            .expect("insert team");
        tx.commit().await.expect("commit");
        id
    }

    fn handbook(whose: &str) -> Value {
        json!({
            "title": "Handbook",
            "uri": "https://example.test/handbook.md",
            "format": "markdown",
            "text": format!(
                "# Spare parts\n\nReplacement caliper, part {SKU}, ships from the {whose} \
                 warehouse with a fourteen day lead time."
            ),
        })
    }

    // -- auth ---------------------------------------------------------------

    /// The stack answers before the handler does, so an unauthenticated caller
    /// never reaches a `tenant_tx` and never writes a row.
    #[tokio::test]
    async fn no_credential_is_a_401_before_the_handler_runs() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, problem) = h.post(handbook("alpha"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem["code"], "unauthenticated");
        assert_eq!(problem["source_id"], Value::Null, "the handler ran anyway");

        let (status, _) = h
            .post(handbook("alpha"), Some("wrong-secret-wrong-secret"))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        assert!(h.recalled(h.a, SKU).await.is_empty(), "a row was written");

        h.teardown().await;
    }

    // -- the label ----------------------------------------------------------

    /// **The claim this route exists for.** An accepted document is on file as
    /// untrusted, from the moment it arrives, whoever uploaded it.
    #[tokio::test]
    async fn an_uploaded_document_is_recorded_as_untrusted_and_is_retrievable() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert!(body["chunks"].as_u64().expect("chunks") >= 1);
        assert_eq!(body["reused"], json!(false));
        assert_eq!(body["trust_label"], json!("untrusted"));

        // The column, not the response: the response is a claim about the row
        // and the row is what Friday's retrieval reads.
        let source_id: Uuid = body["source_id"]
            .as_str()
            .expect("source_id")
            .parse()
            .expect("uuid");
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let label: String =
            sqlx::query_scalar("SELECT trust_label FROM knowledge_sources WHERE id = $1")
                .bind(source_id)
                .fetch_one(&mut **tx)
                .await
                .expect("read the label");
        tx.rollback().await.expect("rollback");
        assert_eq!(label, "untrusted");

        // And it is genuinely reachable from a turn, which is the only reason
        // to have stored it.
        let hits = h.recalled(h.a, SKU).await;
        assert!(
            hits.iter().any(|text| text.contains(SKU)),
            "the document was stored but cannot be retrieved: {hits:?}"
        );

        h.teardown().await;
    }

    // -- isolation ----------------------------------------------------------

    /// Two tenants, the same part number, the same words. Only the isolation
    /// separates them, so a leak looks like a hit rather than an error.
    #[tokio::test]
    async fn a_tenant_never_retrieves_another_tenants_document() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, _) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = h.post(handbook("beta"), Some(SECRET_B)).await;
        assert_eq!(status, StatusCode::CREATED);

        for (tenant, mine, theirs) in [(h.a, "alpha", "beta"), (h.b, "beta", "alpha")] {
            let hits = h.recalled(tenant, SKU).await;
            assert!(!hits.is_empty(), "{mine} retrieved nothing");
            for text in &hits {
                assert!(text.contains(mine));
                assert!(
                    !text.contains(theirs),
                    "{theirs}'s document was retrieved by {mine}: {text}"
                );
            }
        }

        h.teardown().await;
    }

    /// An employee id belonging to somebody else is a 404, and nothing is
    /// written — otherwise the document would be filed against a scope no query
    /// in this tenant ever passes, and be stored yet unretrievable forever.
    #[tokio::test]
    async fn an_employee_id_from_another_tenant_is_a_404() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let theirs = employee(&h.db, h.b, "raj").await;
        let mut body = handbook("alpha");
        body["employee_id"] = json!(theirs.to_string());

        let (status, problem) = h.post(body, Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(problem["code"], "not_found");
        assert!(h.recalled(h.a, SKU).await.is_empty(), "a row was written");

        // The same id from its own tenant is accepted, so the 404 above is the
        // isolation and not a blanket refusal of the field.
        let mut body = handbook("beta");
        body["employee_id"] = json!(theirs.to_string());
        let (status, _) = h.post(body, Some(SECRET_B)).await;
        assert_eq!(status, StatusCode::CREATED);

        h.teardown().await;
    }

    // -- scope --------------------------------------------------------------

    /// The three-way choice on the wire: absent is the company, `team_id` is a
    /// team, `employee_id` is one employee, and both together is a refusal
    /// rather than a precedence rule nobody would have guessed.
    #[tokio::test]
    async fn a_document_belongs_to_the_company_a_team_or_an_employee_and_says_which() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let engineering = team(&h.db, h.a, "engineering").await;
        let mut body = handbook("alpha");
        body["team_id"] = json!(engineering.to_string());

        let (status, created) = h.post(body, Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");

        // The columns, because the columns are what retrieval reads.
        let source_id: Uuid = created["source_id"]
            .as_str()
            .expect("source_id")
            .parse()
            .expect("uuid");
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        let scope: (Option<Uuid>, Option<Uuid>) =
            sqlx::query_as("SELECT employee_id, team_id FROM knowledge_sources WHERE id = $1")
                .bind(source_id)
                .fetch_one(&mut **tx)
                .await
                .expect("read the scope");
        tx.rollback().await.expect("rollback");
        assert_eq!(scope, (None, Some(engineering)));

        // Both ids is a 400 and writes nothing.
        let mut both = handbook("alpha two");
        both["team_id"] = json!(engineering.to_string());
        both["employee_id"] = json!(employee(&h.db, h.a, "ada").await.to_string());
        let (status, problem) = h.post(both, Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(problem["code"], "bad_request");

        h.teardown().await;
    }

    /// A team id from another tenant is a 404 for the same reason an employee
    /// id from another tenant is: a document filed against a scope no query in
    /// this tenant ever passes is stored, billed for, and unretrievable.
    #[tokio::test]
    async fn a_team_id_from_another_tenant_is_a_404() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let theirs = team(&h.db, h.b, "engineering").await;
        let mut body = handbook("alpha");
        body["team_id"] = json!(theirs.to_string());

        let (status, problem) = h.post(body, Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(problem["code"], "not_found");
        assert!(h.recalled(h.a, SKU).await.is_empty(), "a row was written");

        h.teardown().await;
    }

    /// The same bytes under two scopes are two documents. The route's half of
    /// the dedupe-laundering fix: a 201 rather than a 200-with-`reused`, so a
    /// caller filing a team copy of the handbook is told it filed something.
    #[tokio::test]
    async fn the_same_bytes_under_a_different_scope_are_created_not_reused() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let engineering = team(&h.db, h.a, "engineering").await;
        let (status, company) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED);

        let mut scoped = handbook("alpha");
        scoped["team_id"] = json!(engineering.to_string());
        let (status, team_copy) = h.post(scoped, Some(SECRET_A)).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "the team copy was deduped into the company row: {team_copy}"
        );
        assert_eq!(team_copy["reused"], json!(false));
        assert_ne!(team_copy["source_id"], company["source_id"]);

        h.teardown().await;
    }

    // -- the ordinary mistakes ---------------------------------------------

    #[tokio::test]
    async fn the_same_document_twice_is_stored_once() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, first) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED);

        // Byte-different, same document: the whitespace an exporter changes on
        // a whim.
        let mut again = handbook("alpha");
        again["text"] = json!(format!(
            "  {}  \n\n",
            again["text"].as_str().expect("text").replace('\n', "\r\n")
        ));

        let (status, second) = h.post(again, Some(SECRET_A)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a re-ingest did not create: {second}"
        );
        assert_eq!(second["reused"], json!(true));
        assert_eq!(second["source_id"], first["source_id"]);
        assert_eq!(second["chunks"], json!(0));

        h.teardown().await;
    }

    #[tokio::test]
    async fn a_document_with_nothing_in_it_is_a_400() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for body in [
            json!({ "text": "   \n\n\t\n" }),
            // A misspelled field is the caller's problem now rather than a
            // silently ignored title later.
            json!({ "text": "hello", "titel": "Handbook" }),
            // And a format nobody implements is not quietly `text`.
            json!({ "text": "hello", "format": "pdf" }),
            json!({ "title": "Handbook" }),
        ] {
            let (status, problem) = h.post(body.clone(), Some(SECRET_A)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {body}");
            assert_eq!(problem["code"], "bad_request");
        }

        h.teardown().await;
    }
}
