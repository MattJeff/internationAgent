//! `/v1/files`: le classeur — file a document, see what is filed, get one back.
//!
//! `migrations/0067_files.sql` argues for the table and [`agentos_app::files`]
//! for the port. This is the only *HTTP* surface that reaches either, and the
//! only one a person writes through. It is no longer the only writer:
//! `agentos_app::inbound::ingest_email` deposits every email attachment it
//! fetches, under the derived name `blob_key` returns, which is what made
//! attachments durable and readable at all.
//!
//! # Why the bytes travel as base64 inside JSON
//!
//! `routes::queue`'s argument, and it decides this the same way. The API stack's
//! `replay_idempotent` layer records **`jsonb` responses only**: a raw
//! `application/octet-stream` body would be released rather than recorded, so a
//! retried upload would re-run the handler — and here the second run is refused
//! by the primary key, which would turn a lost response into a permanent
//! failure the caller cannot fix without inventing a new name. Sent and returned
//! as JSON under an `Idempotency-Key`, a retry replays the exact same answer.
//!
//! The price is written down rather than discovered: base64 is 4/3, and
//! `MAX_BODY_BYTES` is 1 MiB for every route in this API, so **the largest file
//! this endpoint accepts is about 768 KiB**. `0067` says what raising it costs
//! and where the number lives.
//!
//! # Why nothing here echoes the declared content type
//!
//! [`Deposit::content_type`] is a string somebody typed beside their own bytes.
//! Serving it back as a response `Content-Type` header would let a depositor
//! choose how a browser treats their own upload — `text/html` and a script tag
//! is the whole attack, and it is served from this deployment's origin. So the
//! declared type comes back as **a field in a JSON body**, which is data, and
//! the response's own content type is always `application/json`. The base64 is
//! not obfuscation; it is what keeps the bytes a value rather than a document.
//!
//! # Why the name is a query parameter and not a path segment
//!
//! A name is text a counterparty may have typed and `0067` deliberately allows
//! `/` in it — the name is never parsed and never becomes a path, which is what
//! choosing `bytea` over a directory tree bought. A path segment would have to
//! be percent-escaped by every caller and would silently 404 on the one
//! character most likely to appear in a filename. One query parameter, one
//! decoding, no ambiguity.
//!
//! # Why `POST` goes through the port and the index does not
//!
//! [`deposit`] calls [`Files::put`] and [`content`] calls [`Files::get`],
//! because "keep these bytes" and "give them back" are the two verbs that have
//! to land in our table or in a customer's own store depending on nothing but a
//! connection setting. [`index`] reads `files` directly, and that asymmetry is
//! the port's boundary rather than a shortcut — the same one `routes::calendar`
//! and `routes::work` draw. *Everything this company holds, on one screen* is
//! this internal tool's own administration surface, and it survives a connected
//! adapter because the row stays ours when only the bytes move.
//!
//! # What is deliberately not here
//!
//! **No `DELETE`.** `0067` withholds the grant and argues both sides at length,
//! including the one `0061` did not have: somebody's right to demand erasure is
//! real, and it is exercised by a person at a psql prompt rather than by a
//! request. The migration lists the exact four things a route would need first.
//!
//! **No `PUT`.** There is no UPDATE grant either. A second deposit under a name
//! this company has used is a 409, which is the whole of "first write wins".
//!
//! **No `deposited_by` and no audit row.** `routes::calendar`'s reason, and it
//! has to be restated because the premise moved: it used to be "every writer
//! holds an operator API key, so the column would be the same string on every
//! row", and there are now two kinds of writer — this route, and the inbound
//! loop. The conclusion survives because **the name already answers it**.
//! Anything under `inbound/` was deposited by `ingest_email` and nothing else
//! writes that prefix **by convention and not by enforcement** — nothing in
//! `deposit` refuses a caller-supplied name beginning `inbound/`, and the
//! argument for having no `deposited_by` column leans on that convention
//! rather than on a guard. The guard is one line in `deposit` the day the
//! convention is worth enforcing. Anything outside the prefix came through
//! here. A column would be a
//! second answer to a question the primary key already answers, which is the
//! shape `0067` refuses for a uuid beside the name. The inbound half is
//! attributable further than a column would reach anyway:
//! `messages.attachments[].blob` joins the file to the message, which carries
//! the sender, the thread and the time, and *that* row already has its audit
//! trail. `AuditKind` stays closed.

use agentos_app::files::{Files, FilesError, PgFiles};
use agentos_store::db::{Db, StoreError};
use agentos_store::files;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the rate
/// limit, the 1 MiB body limit and the idempotency layer from `with_api_stack` —
/// which is also why [`Files::put`] carries no idempotency key of its own.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/files", get(index).post(deposit))
        .route("/v1/files/content", get(content))
        .with_state(db)
}

/// Longest `name` and `content_type` the table accepts, in characters.
///
/// One number for two columns because `files_name_shape` and
/// `files_content_type_shape` are the same constraint written twice. Restated
/// here rather than read off the table, and the restatement is what the test
/// below pins — `routes::work::MAX_TITLE`'s argument: the alternative is a round
/// trip to `information_schema` per request to learn a number that changes in a
/// migration. If it ever moves, this constant moves with it in the same commit.
const MAX_FIELD: usize = 200;

/// A document somebody is filing.
#[derive(Deserialize)]
struct Deposit {
    /// What to file it under, and the only address it will have. Bounded by the
    /// table, not here.
    name: String,
    /// What the depositor says the bytes are. Recorded, never verified, and
    /// never echoed as a response header — see the module docs.
    content_type: String,
    /// The bytes, base64 (standard alphabet, padded). See the module docs for
    /// why they travel this way and what it costs.
    content: String,
}

/// Which document to fetch.
#[derive(Deserialize)]
struct ByName {
    /// The name it was filed under, exactly.
    name: String,
}

/// One line of the index: everything except the bytes.
#[derive(Serialize)]
struct FiledView {
    name: String,
    /// What the depositor said it is. An assertion, and it is labelled as one in
    /// the schema rather than in this struct.
    content_type: String,
    size: i64,
    /// SHA-256 of the content, hex, so a founder can compare it with
    /// `sha256sum` on the file they uploaded.
    digest: String,
    created_at: DateTime<Utc>,
}

impl From<files::Filed> for FiledView {
    fn from(filed: files::Filed) -> Self {
        Self {
            name: filed.name,
            content_type: filed.content_type,
            size: filed.size,
            digest: hex(&filed.digest),
            created_at: filed.created_at,
        }
    }
}

/// `GET /v1/files` — everything this company holds, newest first, without bytes.
///
/// No filter and no window, for `GET /v1/calendar`'s reason: what somebody opens
/// this on is "what have we been sent", and the bytes are deliberately absent
/// because an index that carried them would be one query materialising every
/// document the company has.
async fn index(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let filed = files::index(&mut tx).await?;
    tx.rollback().await?;

    Ok(Json(json!({
        "files": filed.into_iter().map(FiledView::from).collect::<Vec<_>>(),
    }))
    .into_response())
}

/// `GET /v1/files/content?name=…` — one document, as it was filed.
///
/// **This is the verb the product did not have.** `knowledge` could tell you
/// what a document said, approximately, in the pieces a similarity search chose.
/// Nothing could give you the contract.
///
/// The digest travels beside the bytes so the caller can check the round trip
/// itself. It has already been checked here — [`Files::get`] verifies before it
/// returns — and a second check by whoever asked is not redundant: this one
/// proves the store is intact, theirs proves the wire was.
async fn content(
    State(db): State<Db>,
    principal: Principal,
    Query(which): Query<ByName>,
) -> Result<Response, ApiError> {
    let classeur = PgFiles::new(db, principal.tenant_id);
    let kept = classeur.get(&which.name).await.map_err(refusal)?;
    let bytes = kept.bytes.into_inner_for_rendering();

    Ok(Json(json!({
        "name": which.name,
        // Unwrapped here and nowhere else, which is the reviewable moment the
        // `Untrusted` wrapper exists to create. It becomes a JSON string in a
        // JSON body: data, never a header and never a rendered document.
        "content_type": kept.content_type.into_inner_for_rendering(),
        "size": bytes.len(),
        "digest": hex(&kept.digest),
        "content": B64.encode(&bytes),
    }))
    .into_response())
}

/// `POST /v1/files` — file one document.
///
/// 409 when this company has already used the name: first write wins, and there
/// is no overwrite anywhere in this feature. 400 for base64 that is not base64,
/// which is a mistake in a field the caller controls and is nothing to keep
/// quiet about.
async fn deposit(
    State(db): State<Db>,
    principal: Principal,
    Json(body): Json<Deposit>,
) -> Result<Response, ApiError> {
    // All three ends of `files_name_shape` and `files_content_type_shape`, and
    // it has to be all three. Refusing only the empty one left the rest to the
    // `CHECK`s, which arrive as a `23514` in `StoreError::Database` and come out
    // of `ApiError` as a **500** — "we broke" — for a name the caller fixes by
    // shortening it or retyping it without the newline they pasted in.
    // `char_length` is what the constraints count, so `chars()` is what this
    // counts; `.len()` would refuse a 70-character Japanese filename.
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > MAX_FIELD || name.contains(char::is_control) {
        return Err(ApiError::bad_request(
            "a file needs a name of 1 to 200 characters with no control characters in it: it is \
             the only address it will have, and there is no id beside it",
        ));
    }
    let content_type = body.content_type.trim();
    if content_type.is_empty()
        || content_type.chars().count() > MAX_FIELD
        || content_type.contains(char::is_control)
    {
        return Err(ApiError::bad_request(
            "`content_type` is 1 to 200 characters with no control characters in it: it is what \
             the depositor says the bytes are, and nothing else records it",
        ));
    }
    let bytes = B64.decode(body.content.as_bytes()).map_err(|_| {
        // The decoder's own message is not echoed: it names an offset in the
        // caller's payload, which is content this deployment does not put in an
        // error body or a log line.
        ApiError::bad_request("`content` must be base64 (standard alphabet, padded)")
    })?;
    if bytes.is_empty() {
        return Err(ApiError::bad_request(
            "a file needs bytes: a zero-byte document is not a document, and every empty file \
             in a deployment would share one digest",
        ));
    }

    let classeur = PgFiles::new(db, principal.tenant_id);
    let filed = classeur
        .put(name, content_type, &bytes)
        .await
        .map_err(refusal)?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "name": name,
            "size": filed.size,
            // The whole of "as it is, verifiably": compare this against
            // `sha256sum` on the file you uploaded.
            "digest": hex(&filed.digest),
            "created_at": filed.created_at,
        })),
    )
        .into_response())
}

/// A classeur refusing, in the four ways a classeur can refuse.
///
/// [`FilesError::Corrupt`] is a 500 and says so without saying anything else:
/// the caller asked for a file this deployment cannot hand back intact, which is
/// our failure and not theirs, and the two digests are already on a log line for
/// whoever operates it. A connected store's [`FilesError::Provider`] is not
/// reachable today and is mapped rather than left to a `_` arm, so the day one
/// exists this compiles into a 502 rather than a 500 that blames us for
/// somebody else's outage.
fn refusal(err: FilesError) -> ApiError {
    match err {
        FilesError::Corrupt => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "file_corrupt",
            "the stored file does not match its digest and was not returned",
        ),
        FilesError::Unavailable(StoreError::NotFound) => {
            ApiError::not_found().with_detail("no file by that name in this company")
        }
        FilesError::Unavailable(other) => ApiError::from(other),
        FilesError::Provider(err) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "file_store_unavailable",
            "the connected file store refused",
        )
        .with_detail(err.code()),
    }
}

/// A digest as hex, for a JSON field. The only rendering of one in this module.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use serde_json::Value;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY};

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Two companies behind two keys, under the real middleware stack — so the
    /// idempotency layer this port leans on instead of carrying a key of its own
    /// is actually in the path.
    /// No tenant id is kept: unlike `routes::calendar`'s harness this one never
    /// seeds an employee, because a file belongs to the company and to no seat.
    /// That absence is the per-tenant/per-seat split `agentos_app::files` argues,
    /// visible in the test fixture.
    struct Harness {
        app: Router,
    }

    impl Harness {
        async fn new(db: &Db) -> Self {
            let a = new_tenant(db).await;
            let b = new_tenant(db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    Keyring::new(keys, db.clone(), TEST_MASTER_KEY),
                ),
            }
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header("idempotency-key", Uuid::now_v7().to_string());
            let req = match &body {
                Some(body) => req
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string())),
                None => req.body(Body::empty()),
            }
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
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'files-routes-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// **"Keep the signed contract, as it is", over HTTP**: bytes no text column
    /// could hold go in, the same bytes come back out, the digest matches at
    /// both ends, and the name they were filed under is the only thing anybody
    /// had to remember.
    #[tokio::test]
    async fn the_founder_files_a_contract_and_gets_those_exact_bytes_back() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the classeur needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;

        // A NUL, a lone 0xff, a bare continuation byte: a `text` column refuses
        // the first outright and mangles the rest.
        let contract: Vec<u8> = vec![0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0xfe, 0x80, 0x0a];
        let encoded = B64.encode(&contract);

        let (status, filed) = h
            .send(
                "POST",
                "/v1/files",
                SECRET_A,
                Some(json!({
                    "name": "signed/Acme MSA (countersigned).pdf",
                    "content_type": "application/pdf",
                    "content": encoded,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{filed}");
        assert_eq!(filed["size"], contract.len());
        let deposited_digest = filed["digest"].as_str().expect("digest").to_owned();

        let (status, back) = h
            .send(
                "GET",
                "/v1/files/content?name=signed%2FAcme%20MSA%20(countersigned).pdf",
                SECRET_A,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{back}");
        assert_eq!(
            B64.decode(back["content"].as_str().expect("content"))
                .expect("base64"),
            contract,
            "these bytes, unchanged: the entire point of the feature"
        );
        assert_eq!(
            back["digest"].as_str().expect("digest"),
            deposited_digest,
            "the digest at the deposit is the digest at the read"
        );
        assert_eq!(back["content_type"], "application/pdf");

        let (status, listed) = h.send("GET", "/v1/files", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        let index = listed["files"].as_array().expect("files");
        assert_eq!(index.len(), 1);
        assert_eq!(index[0]["name"], "signed/Acme MSA (countersigned).pdf");
        assert!(
            index[0].get("content").is_none(),
            "the index must not carry the bytes"
        );

        // **First write wins.** With no UPDATE grant and no upsert anywhere, a
        // second deposit under one name is the only way a contract could have
        // been replaced, and it is refused.
        let (status, refused) = h
            .send(
                "POST",
                "/v1/files",
                SECRET_A,
                Some(json!({
                    "name": "signed/Acme MSA (countersigned).pdf",
                    "content_type": "application/pdf",
                    "content": B64.encode(b"a different contract under the same name"),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");

        let (status, still) = h
            .send(
                "GET",
                "/v1/files/content?name=signed%2FAcme%20MSA%20(countersigned).pdf",
                SECRET_A,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            B64.decode(still["content"].as_str().expect("content"))
                .expect("base64"),
            contract,
            "…and the original is still the original"
        );

        // A name nobody filed is a 404, and so is one filed by somebody else —
        // see the isolation test below for why those must be one answer.
        let (status, _) = h
            .send("GET", "/v1/files/content?name=nothing", SECRET_A, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The three refusals the handler makes before the port is reached.
        for (label, body) in [
            (
                "no name",
                json!({"name": "  ", "content_type": "application/pdf", "content": "AAAA"}),
            ),
            (
                "no declared type",
                json!({"name": "x.pdf", "content_type": "", "content": "AAAA"}),
            ),
            (
                "not base64",
                json!({"name": "y.pdf", "content_type": "application/pdf", "content": "!!!!"}),
            ),
            (
                "no bytes",
                json!({"name": "z.pdf", "content_type": "application/pdf", "content": ""}),
            ),
        ] {
            let (status, refused) = h.send("POST", "/v1/files", SECRET_A, Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {refused}");
        }
    }

    /// **A name this table will not take is the caller's mistake, not ours.**
    ///
    /// `POST` already refuses a blank name and a blank `content_type` here
    /// rather than at the table, so the rest of `files_name_shape` and
    /// `files_content_type_shape` has to be refused here too. Left to the
    /// `CHECK`, a 201-character name — or one with a newline in it, which is
    /// what a filename pasted out of a terminal carries — arrives as a `23514`
    /// in [`StoreError::Database`], which [`ApiError`] answers **500**: "we
    /// broke", for a body the caller fixes by shortening or retyping a name.
    ///
    /// The constraint is not hypothetical from this side either:
    /// `agentos_app::inbound::ingest_email` names these two by name as the
    /// reason it classifies an attachment failure rather than propagating it.
    /// That is the other writer; this is the one with a caller to answer.
    #[tokio::test]
    async fn a_name_or_a_type_the_table_will_not_take_is_a_400_and_not_a_500() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the classeur needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let content = B64.encode(b"the bytes are never the problem here");

        for (label, name, content_type) in [
            (
                "a name past the bound",
                "x".repeat(201),
                "text/plain".to_owned(),
            ),
            // Not a curiosity: a filename pasted out of a terminal or lifted
            // from a mail header carries these, and `files_name_shape` refuses
            // them by regex rather than by length.
            (
                "a name with a newline in it",
                "in\nvoice.pdf".to_owned(),
                "text/plain".to_owned(),
            ),
            ("a type past the bound", "y.pdf".to_owned(), "z".repeat(201)),
            (
                "a type with a control character",
                "w.pdf".to_owned(),
                "text/plain\u{7f}".to_owned(),
            ),
        ] {
            let (status, problem) = h
                .send(
                    "POST",
                    "/v1/files",
                    SECRET_A,
                    Some(json!({
                        "name": name,
                        "content_type": content_type,
                        "content": content,
                    })),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{label} answered {status}: {problem}"
            );
        }

        // …and the longest pair the table does take still lands, so the guard
        // above is the constraint's bound and not a tighter one somebody
        // invented beside it.
        let (status, filed) = h
            .send(
                "POST",
                "/v1/files",
                SECRET_A,
                Some(json!({
                    "name": "n".repeat(200),
                    "content_type": "t".repeat(200),
                    "content": content,
                })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "200 characters is the bound: {filed}"
        );
    }

    /// A classeur is one company's, and "not yours" is spelled exactly like
    /// "does not exist".
    ///
    /// The second half is the point: a 409 where another company had used the
    /// name, or a 404 that differed from "not found", would make this endpoint a
    /// way to ask a competitor whether they hold a contract with a given name.
    #[tokio::test]
    async fn one_company_s_documents_and_no_oracle_about_anybody_else_s() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the classeur needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;

        let (status, _) = h
            .send(
                "POST",
                "/v1/files",
                SECRET_A,
                Some(json!({
                    "name": "contract.pdf",
                    "content_type": "application/pdf",
                    "content": B64.encode(b"A's signed contract"),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, listed) = h.send("GET", "/v1/files", SECRET_B, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            listed["files"].as_array().expect("files").is_empty(),
            "B must not see A's classeur"
        );

        let (status, _) = h
            .send("GET", "/v1/files/content?name=contract.pdf", SECRET_B, None)
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a file of A's must read to B exactly like a file nobody filed"
        );

        // …and B filing under the same name succeeds, which is the same
        // statement from the writing side: a 409 here would answer the question
        // the 404 above refuses to answer.
        let (status, mine) = h
            .send(
                "POST",
                "/v1/files",
                SECRET_B,
                Some(json!({
                    "name": "contract.pdf",
                    "content_type": "application/pdf",
                    "content": B64.encode(b"B's own contract"),
                })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "two companies own their own namespaces: {mine}"
        );

        let (status, a_still) = h
            .send("GET", "/v1/files/content?name=contract.pdf", SECRET_A, None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            B64.decode(a_still["content"].as_str().expect("content"))
                .expect("base64"),
            b"A's signed contract".to_vec(),
            "and A's document is untouched by B having used the name"
        );
    }
}
