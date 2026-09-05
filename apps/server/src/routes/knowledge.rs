//! `/v1/knowledge`: put a document where the employee can find it, then read
//! back what was put there.
//!
//! Three routes and one asymmetry worth naming up front. `POST
//! /v1/knowledge/documents` writes; `GET /v1/knowledge/documents` lists what was
//! written; `GET /v1/knowledge/search` runs the *same* retrieval a turn runs.
//! For a long time only the first existed, which meant a document filed under a
//! scope nobody queries — a team the employee is not on, an employee that is not
//! the one asking — was stored, indexed, billed for and never retrieved, and the
//! only evidence of any of it was a `source_id` in a response body. The two
//! reads are what make that visible.
//!
//! # The one thing the ingest route is really for
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
//! # The search endpoint is `recall`, not a second retrieval
//!
//! [`search`] calls `agentos_app::knowledge::recall` — the identical function
//! the turn loop calls, with the identical bounds — and does nothing else. That
//! is the point of the route rather than an implementation detail: the question
//! it answers is *what would this employee actually retrieve*, and an answer
//! computed by a second query is an answer that stops matching the first one at
//! the next fix to either. Same scope predicate, same one-model binding, same
//! word-only leg when the embedder is a hash, same two-second budget.
//!
//! It follows that this route inherits `recall`'s honesty problem and has to
//! pass it on. On a deployment with no `EMBEDDER_API_KEY` the vector leg is not
//! run at all, so an empty result means *no document contained these words* and
//! not *the company has nothing on this* — `RECALLED_BRIEF` says exactly that to
//! the model, and `ranked_by` in the response body says it to the person.
//!
//! # Two rules the reads do not get to bend
//!
//! **Retrieved text is `Untrusted`, and the wire says so on every passage.**
//! A person reading a search result is not a prompt, so the content comes back
//! in clear — the same call `routes::desk` makes for a colleague's message. What
//! travels with it is the label: `trust` on every hit, hard-coded rather than
//! read off `knowledge_sources.trust_label`, because retrieval is untrusted for
//! a reason no column can answer. `crates/app/src/knowledge.rs` has the
//! argument; briefly, the *selection* is steered by whoever wrote the query. The
//! listing's `trust` is the opposite kind of value — it is the column, the audit
//! record of what arrived — and the two are deliberately not the same field
//! computed twice.
//!
//! **Another tenant's row is invisible, not forbidden.** RLS supplies that for
//! the listing and the search without either writing a `tenant_id` predicate. It
//! is only spelled out for `employee_id` on [`search`], which is an id a caller
//! hands us: one belonging to somebody else is a 404, exactly as it is on the
//! ingest path, and never a 403 that would confirm the id exists.
//!
//! # What is deliberately not here
//!
//! **No `DELETE`.** `routes::files` refuses the same verb for the same reason
//! and `0067` writes the argument out; the knowledge tables add one of their
//! own. A chunk that has been retrieved is quoted, by `chunk_id` and `ordinal`,
//! in the context of turns that are already recorded — deleting the row turns
//! those citations into dangling references and makes an audit of what an
//! employee was told unreadable. So erasure here is a retention decision (hard
//! delete or tombstone? what happens to the turns that cite it? who may ask?)
//! and not a handler, and a document filed under the wrong scope is fixed by
//! filing it under the right one: the dedupe key includes the scope, so the
//! re-ingest creates rather than reuses. The stale row costs storage until
//! somebody at a psql prompt removes it, which is the honest price of not
//! guessing at the four questions above.
//!
//! **No `GET /v1/knowledge/documents/{id}` returning the text.** Getting the
//! exact bytes back is `routes::files` — *le classeur* keeps, this unit indexes
//! in order to find again, and a second full-text read here would be a second
//! answer to "what did we file". The listing carries a chunk count so the
//! founder can see a document is there and how much of it there is; the passages
//! themselves come back from [`search`], which is where the trust label and the
//! scope are enforced.
//!
//! **No pagination on [`search`].** It is a top-k over a fused ranking, and an
//! `after` cursor over one is a promise the ranking cannot keep — page two of a
//! score-ordered result is not stable across the ingest that happens between the
//! two requests. `limit` is the whole control, capped at [`MAX_HITS`], and the
//! default is [`RECALL_LIMIT`] because five is what the employee gets.

use agentos_app::knowledge::{
    Document, Embedder, Format, KnowledgeError, RECALL_LIMIT, RECALL_TIMEOUT, Recall, Scope,
    ingest, recall,
};
use agentos_domain::ids::EmployeeId;
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_store::db::{Db, StoreError, TenantTx};
use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
        .route(
            "/v1/knowledge/documents",
            post(create_document).get(list_documents),
        )
        .route("/v1/knowledge/search", get(search))
        .with_state(KnowledgeState { db, embedder })
}

/// Page size when the caller does not ask for one. Same numbers as
/// `routes::employees`, because a founder walking two listings should not have
/// to learn two page sizes.
const DEFAULT_LIMIT: i64 = 50;

/// Largest page we will build, however big a `limit` the caller sends.
const MAX_LIMIT: i64 = 200;

/// Largest top-k [`search`] will ask `recall` for.
///
/// Ten times what a turn takes, and bounded for the same reason the turn's is:
/// every hit is a chunk of document text on the wire, and the useful operator
/// question ("would this employee find it?") is answered by the first few.
const MAX_HITS: i64 = 50;

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

/// One `knowledge_sources` row as [`list_documents`] selects it: id,
/// employee_id, team_id, title, uri, kind, trust_label, chunk count, created_at.
type SummaryRow = (
    Uuid,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    String,
    String,
    i64,
    DateTime<Utc>,
);

/// Keyset pagination, spelled exactly as `routes::employees` spells it. Ids are
/// UUIDv7, so `id > after` is "filed after".
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    /// The last id of the previous page.
    #[serde(default)]
    after: Option<Uuid>,
    /// How many rows to return, capped at [`MAX_LIMIT`].
    #[serde(default)]
    limit: Option<i64>,
}

/// One filed document, **without its text**.
///
/// The omission is the design. A listing is a screen a founder scrolls, and a
/// knowledge source is a whole handbook; returning the content would put
/// megabytes of third-party text on a route whose job is to say what exists.
/// `chunks` is the honest stand-in — it is what the document cost to index and
/// what it can contribute to a turn — and the passages themselves come back one
/// query at a time from [`search`], where the trust label travels with them.
#[derive(Debug, Serialize)]
struct DocumentSummary {
    id: Uuid,
    /// `company`, `team` or `employee`, derived from the two columns below so a
    /// reader does not have to know that "both NULL" is the company.
    scope: &'static str,
    /// Set when `scope` is `employee`; the same field the ingest body takes, so
    /// a listing row round-trips into a re-file.
    employee_id: Option<Uuid>,
    /// Set when `scope` is `team`.
    team_id: Option<Uuid>,
    title: Option<String>,
    uri: Option<String>,
    /// The `kind` column, which is what `POST`'s `format` recorded.
    format: String,
    /// How many chunks this document was split into — how much of a turn it can
    /// occupy, and a zero here would mean a source that can never be retrieved.
    chunks: i64,
    /// **Off the `trust_label` column**, not a constant: this is the provenance
    /// record `0017` exists for, and reading it back is the point. Every row
    /// says `untrusted` today because no ingest path in this workspace writes
    /// anything else — which is a fact about the code, and this field is where a
    /// reader would see it stop being true.
    trust: String,
    created_at: DateTime<Utc>,
}

/// The [`search`] query string. `deny_unknown_fields` for the ingest body's
/// reason: a misspelled `employee_id` would silently widen the scope of the
/// search rather than narrow it, which is the one mistake this route exists to
/// make visible.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchQuery {
    /// What to look for. Passed to `recall` as the counterparty's words are —
    /// it truncates, parses it into a `tsquery` and embeds it, and nothing here
    /// renders it.
    q: String,
    /// **Whose eyes.** Absent is the operator-side "everything this tenant has",
    /// which is the widest scope and answers a different question; an employee
    /// id answers *would this seat find it*, which is the question a document
    /// filed under the wrong scope fails.
    #[serde(default)]
    employee_id: Option<Uuid>,
    /// Top-k, defaulting to [`RECALL_LIMIT`] and capped at [`MAX_HITS`].
    #[serde(default)]
    limit: Option<i64>,
}

/// One retrieved passage, as a person reads it.
#[derive(Debug, Serialize)]
struct HitView {
    /// The document. Matches a `DocumentSummary::id` from the listing, which is
    /// how "why did it not find my file" gets answered.
    source_id: Uuid,
    chunk_id: Uuid,
    /// Position in the document. `knowledge:<source_id>#<ordinal>` is the
    /// citation a turn carries for this exact passage.
    ordinal: i32,
    /// Comparable within this result set and meaningless outside it.
    score: f64,
    /// The passage. In clear, because the reader is a person and not a prompt —
    /// `Untrusted` serialises transparently, exactly as `routes::desk` sends a
    /// colleague's message.
    content: Untrusted<String>,
    /// Always `untrusted`, and **not** read off the source row. See the module
    /// docs: a passage is chosen by whoever wrote `q`, so no column can make it
    /// trusted. Do not feed it back into a prompt.
    trust: &'static str,
}

// ---------------------------------------------------------------------------
// Handlers
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

/// `GET /v1/knowledge/documents` — what this tenant has filed, oldest first.
///
/// **No text, and paged.** See [`DocumentSummary`] for the first and
/// `routes::employees` for the second: same `after`/`limit`/`next_after`
/// vocabulary, same "only a full page can have a successor" rule, so a founder
/// who has walked one listing has walked this one.
///
/// The question it is really answering is *what did I file and who can read
/// it*. Before this route the answer lived in a `source_id` the client may not
/// have kept, and a document scoped to a team nobody is on looked exactly like
/// one the whole company reads.
async fn list_documents(
    State(KnowledgeState { db, .. }): State<KnowledgeState>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let limit = page.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    // No `WHERE tenant_id`, and that is not an oversight: RLS adds it, and a
    // hand-written filter here would be a second place for it to be forgotten.
    // Another tenant's document is absent from this page rather than refused.
    //
    // The chunk count is a correlated subquery rather than a `GROUP BY`, and it
    // is cheap for the same reason: `knowledge_chunks_source_idx` is
    // `(source_id, ordinal)`, so it is one index-only count per row of a page
    // that is at most `MAX_LIMIT` long, and a `LEFT JOIN ... GROUP BY` would
    // have to aggregate before it could apply the keyset limit.
    let rows: Vec<SummaryRow> = sqlx::query_as(
        "SELECT s.id, s.employee_id, s.team_id, s.title, s.uri, s.kind, s.trust_label, \
                (SELECT count(*) FROM knowledge_chunks c WHERE c.source_id = s.id), \
                s.created_at \
           FROM knowledge_sources s \
          WHERE ($1::uuid IS NULL OR s.id > $1) \
          ORDER BY s.id \
          LIMIT $2",
    )
    .bind(page.after)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::from)?;
    tx.rollback().await?;

    let documents: Vec<DocumentSummary> = rows
        .into_iter()
        .map(
            |(id, employee_id, team_id, title, uri, format, trust, chunks, created_at)| {
                DocumentSummary {
                    id,
                    scope: match (employee_id, team_id) {
                        (Some(_), _) => "employee",
                        (None, Some(_)) => "team",
                        (None, None) => "company",
                    },
                    employee_id,
                    team_id,
                    title,
                    uri,
                    format,
                    chunks,
                    trust,
                    created_at,
                }
            },
        )
        .collect();

    let next_after = (documents.len() as i64 == limit)
        .then(|| documents.last().map(|last| last.id))
        .flatten();

    Ok(Json(json!({ "documents": documents, "next_after": next_after })).into_response())
}

/// `GET /v1/knowledge/search` — run the employee's own retrieval, by hand.
///
/// One call to `agentos_app::knowledge::recall` and nothing else, which is the
/// whole design: see the module docs for why a second implementation would be
/// two answers to one question. What that inherits, and what a caller has to
/// know:
///
/// * **The scope is `employee_id`'s, resolved now.** Which team a seat is on is
///   read out of `team_memberships` by the query itself, so this says what that
///   seat would retrieve *this minute* rather than what it was entitled to when
///   the document was filed.
/// * **`ranked_by` is not decoration.** Without an embedding credential the
///   vector leg is not run, so an empty `hits` means no document contained these
///   words — not that the company has nothing on the subject. A person reading
///   an empty result needs told which of those two it is.
/// * **503, never an empty 200, when the store could not be searched.** `recall`
///   is infallible by signature and folds a dead database, a timeout and a
///   refused embedding call into one `unavailable` flag — deliberately, because
///   a turn must answer the customer either way. A person asking "can my
///   employee find this?" must not be told "no" by a failure, so the flag
///   becomes a status code here. It is `knowledge_unavailable` and not the
///   ingest path's `embedder_unavailable` because at this point nobody knows
///   which leg failed, and a code that named the embedder would be inventing
///   that detail.
async fn search(
    State(KnowledgeState { db, embedder }): State<KnowledgeState>,
    principal: Principal,
    query: Result<Query<SearchQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    if query.q.trim().is_empty() {
        return Err(ApiError::bad_request(
            "q: a search needs something to search for",
        ));
    }
    let limit = query.limit.unwrap_or(RECALL_LIMIT).clamp(1, MAX_HITS);

    // An employee id from another tenant is a 404 and not an empty result set,
    // for `scope_of`'s reason pointed the other way: an unknown id would
    // silently mean "no documents", which is indistinguishable from the answer
    // a correct id gives when the scope is wrong — and telling those two apart
    // is the entire reason this route exists.
    let employee_id = match query.employee_id {
        None => None,
        Some(id) => {
            let mut tx = db.tenant_tx(principal.tenant_id).await?;
            let found = known(&mut tx, "SELECT id FROM employees WHERE id = $1", id).await;
            tx.rollback().await?;
            Some(EmployeeId::from_uuid(found?))
        }
    };

    // Untrusted because it is: the words are the caller's, and `recall` parses
    // them rather than rendering them. The wrapper costs nothing and keeps this
    // call site identical to the turn's.
    let question = Untrusted::new(query.q);
    let recalled = recall(
        &db,
        &embedder,
        principal.tenant_id,
        &Recall {
            question: &question,
            employee_id,
            limit,
            timeout: RECALL_TIMEOUT,
        },
    )
    .await;

    if recalled.unavailable() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "knowledge_unavailable",
            "the document store could not be searched; retry",
        ));
    }

    let hits: Vec<HitView> = recalled
        .hits()
        .iter()
        .map(|hit| HitView {
            source_id: hit.source_id,
            chunk_id: hit.chunk_id,
            ordinal: hit.ordinal,
            score: hit.score,
            content: hit.content.clone(),
            // A constant, not a column. The module docs argue it.
            trust: "untrusted",
        })
        .collect();

    Ok(Json(json!({
        "hits": hits,
        // What actually ranked these, from the one function that knows.
        "ranked_by": if embedder.is_semantic() { "words_and_meaning" } else { "words" },
    }))
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
    use agentos_domain::ids::TenantId;
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

        /// GET `uri` as `secret`'s tenant.
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

    /// Put `employee` on `team`. The retrieval predicate reads this table at
    /// query time, so a team-scoped document is only reachable through a row
    /// here.
    async fn join_team(db: &Db, tenant: TenantId, employee: Uuid, team: Uuid) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO team_memberships (tenant_id, employee_id, team_id) VALUES ($1, $2, $3)",
        )
        .bind(tenant.as_uuid())
        .bind(employee)
        .bind(team)
        .execute(&mut **tx)
        .await
        .expect("insert membership");
        tx.commit().await.expect("commit");
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

    // -- reading it back ----------------------------------------------------

    /// The listing walks by cursor and never carries a document's text.
    ///
    /// Both halves matter. The paging is `routes::employees`' contract — a full
    /// page has a successor, a short one ends the walk — and the absence of the
    /// content is what keeps a screen listing a hundred handbooks from being a
    /// hundred handbooks on the wire.
    #[tokio::test]
    async fn the_listing_pages_by_cursor_and_never_carries_the_text() {
        let Some(h) = Harness::new().await else {
            return;
        };

        for whose in ["alpha one", "alpha two", "alpha three"] {
            let (status, _) = h.post(handbook(whose), Some(SECRET_A)).await;
            assert_eq!(status, StatusCode::CREATED);
        }

        let mut seen: Vec<String> = Vec::new();
        let mut uri = "/v1/knowledge/documents?limit=2".to_owned();
        for _ in 0..4 {
            let (status, page) = h.get(&uri, SECRET_A).await;
            assert_eq!(status, StatusCode::OK, "{page}");
            let documents = page["documents"].as_array().expect("documents").clone();

            for document in &documents {
                // Never the text, on any row, at any page size.
                assert_eq!(document["text"], Value::Null, "{document}");
                assert_eq!(document["content"], Value::Null, "{document}");
                // What a founder needs instead: what it is, who it is for, how
                // much of it there is, and where it came from.
                assert_eq!(document["scope"], json!("company"));
                assert_eq!(document["format"], json!("markdown"));
                assert_eq!(document["title"], json!("Handbook"));
                assert_eq!(document["uri"], json!("https://example.test/handbook.md"));
                assert!(document["chunks"].as_i64().expect("chunks") >= 1);
                assert!(document["created_at"].is_string());
                seen.push(document["id"].as_str().expect("id").to_owned());
            }

            match page["next_after"].as_str() {
                Some(after) => {
                    assert_eq!(documents.len(), 2, "a cursor on a short page: {page}");
                    uri = format!("/v1/knowledge/documents?limit=2&after={after}");
                }
                None => break,
            }
        }

        assert_eq!(
            seen.len(),
            3,
            "the walk did not see every document: {seen:?}"
        );
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "a document was returned twice: {seen:?}");

        let (status, problem) = h.get("/v1/knowledge/documents?limit=abc", SECRET_A).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");

        h.teardown().await;
    }

    /// The trust label a founder reads off the listing is the column, and the
    /// column is `untrusted` — for a document this tenant's own operator filed
    /// with a valid key.
    #[tokio::test]
    async fn the_listing_reports_the_trust_label_that_was_recorded() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, created) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, page) = h.get("/v1/knowledge/documents", SECRET_A).await;
        assert_eq!(status, StatusCode::OK);
        let documents = page["documents"].as_array().expect("documents");
        assert_eq!(documents.len(), 1, "{page}");
        assert_eq!(documents[0]["id"], created["source_id"]);
        assert_eq!(documents[0]["trust"], json!("untrusted"));

        h.teardown().await;
    }

    /// A search finds the document that was just filed, says the passage is not
    /// to be trusted, and says what ranked it.
    ///
    /// The last field is the one that is easy to leave out: this build has no
    /// embedding credential, so an empty result means *no document contained
    /// these words* rather than *the company has nothing on this*, and a person
    /// reading the result has to be told which.
    #[tokio::test]
    async fn a_search_finds_a_filed_document_and_flags_it_untrusted() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, created) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, found) = h
            .get(&format!("/v1/knowledge/search?q={SKU}"), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK, "{found}");
        assert_eq!(found["ranked_by"], json!("words"));

        let hits = found["hits"].as_array().expect("hits");
        assert_eq!(hits.len(), 1, "{found}");
        assert_eq!(hits[0]["source_id"], created["source_id"]);
        assert_eq!(hits[0]["trust"], json!("untrusted"));
        assert_eq!(hits[0]["ordinal"], json!(0));
        assert!(
            hits[0]["content"].as_str().expect("content").contains(SKU),
            "{found}"
        );

        // The same search from the other tenant, on the same words, comes back
        // empty rather than refused: another tenant's document is invisible.
        let (status, none) = h
            .get(&format!("/v1/knowledge/search?q={SKU}"), SECRET_B)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(none["hits"].as_array().expect("hits").is_empty(), "{none}");

        // A search for nothing is the caller's mistake, not an empty page.
        let (status, problem) = h.get("/v1/knowledge/search?q=%20", SECRET_A).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");

        h.teardown().await;
    }

    /// **The bug this pair of routes exists for.** A document filed to one team
    /// is stored, indexed and billed for, and the employee on another team never
    /// sees it — which used to be invisible from outside and is now two calls.
    #[tokio::test]
    async fn a_team_document_does_not_come_back_for_another_teams_employee() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let engineering = team(&h.db, h.a, "engineering").await;
        let sales = team(&h.db, h.a, "sales").await;
        let ada = employee(&h.db, h.a, "ada").await;
        let raj = employee(&h.db, h.a, "raj").await;
        join_team(&h.db, h.a, ada, engineering).await;
        join_team(&h.db, h.a, raj, sales).await;

        let mut body = handbook("alpha");
        body["team_id"] = json!(engineering.to_string());
        let (status, created) = h.post(body, Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");

        // It is on file, plainly, and the listing says whose it is.
        let (status, page) = h.get("/v1/knowledge/documents", SECRET_A).await;
        assert_eq!(status, StatusCode::OK);
        let documents = page["documents"].as_array().expect("documents");
        assert_eq!(documents[0]["scope"], json!("team"));
        assert_eq!(documents[0]["team_id"], json!(engineering.to_string()));

        // Engineering finds it; sales does not; the operator-wide search does.
        for (who, expected) in [(ada, 1), (raj, 0)] {
            let (status, found) = h
                .get(
                    &format!("/v1/knowledge/search?q={SKU}&employee_id={who}"),
                    SECRET_A,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{found}");
            assert_eq!(
                found["hits"].as_array().expect("hits").len(),
                expected,
                "employee {who} saw the wrong thing: {found}"
            );
        }

        let (status, found) = h
            .get(&format!("/v1/knowledge/search?q={SKU}"), SECRET_A)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            found["hits"].as_array().expect("hits").len(),
            1,
            "the tenant-wide search lost a document it is entitled to: {found}"
        );

        h.teardown().await;
    }

    /// Searching as somebody else's employee is a 404, not a 403 and not an
    /// empty result — an empty result is what a *correct* id gives when the
    /// scope is wrong, and telling those two apart is the point of the route.
    #[tokio::test]
    async fn searching_as_another_tenants_employee_is_a_404() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, _) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED);

        let theirs = employee(&h.db, h.b, "raj").await;
        let (status, problem) = h
            .get(
                &format!("/v1/knowledge/search?q={SKU}&employee_id={theirs}"),
                SECRET_A,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{problem}");
        assert_eq!(problem["code"], json!("not_found"));

        // And a misspelled parameter is refused rather than silently widening
        // the search to the whole tenant.
        let (status, problem) = h
            .get(
                &format!("/v1/knowledge/search?q={SKU}&employe_id={theirs}"),
                SECRET_A,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");

        h.teardown().await;
    }

    /// A search that could not reach the store is a 503, and the listing beside
    /// it is unaffected.
    ///
    /// `recall` is infallible by signature: it folds a dead database, a timeout
    /// and a refused embedding call into one `unavailable` flag, because a turn
    /// must answer the customer either way. A person asking "can my employee
    /// find this?" must not be told "no" by a failure, so the flag has to become
    /// a status code — this asserts that it does.
    ///
    /// The failure is manufactured by holding every connection in the pool,
    /// which is what a database having a bad minute looks like from inside this
    /// process. It costs `RECALL_TIMEOUT` in wall clock and needs no provider
    /// dependency — `agentos-providers` is deliberately absent from this crate,
    /// so a failing embedder cannot be constructed here at all.
    #[tokio::test]
    async fn a_search_that_cannot_reach_the_store_is_a_503_and_not_an_empty_page() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, _) = h.post(handbook("alpha"), Some(SECRET_A)).await;
        assert_eq!(status, StatusCode::CREATED);

        // Every connection `Db::connect` allows, held open. `recall` opens its
        // own and waits; the listing is asked before the pool is taken.
        let (status, page) = h.get("/v1/knowledge/documents", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{page}");

        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(h.db.tenant_tx(h.a).await.expect("tenant tx"));
        }

        let (status, problem) = h
            .get(&format!("/v1/knowledge/search?q={SKU}"), SECRET_A)
            .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a failed search answered as if the store were empty: {problem}"
        );
        assert_eq!(problem["code"], json!("knowledge_unavailable"));

        for tx in held {
            tx.rollback().await.expect("rollback");
        }
        h.teardown().await;
    }
}
