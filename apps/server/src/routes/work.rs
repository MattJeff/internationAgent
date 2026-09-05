//! `/v1/work`: the founder's half of the shared board — write it down, see it,
//! rank it.
//!
//! `migrations/0061_work_items.sql` argues for the table and
//! [`agentos_app::backlog`] for the port. This is the only surface that writes
//! either today.
//!
//! # Why `POST` goes through the port and the other two do not
//!
//! [`post`] calls [`Backlog::post`], because "put this on the board" is the verb
//! that has to land in *our* table or in a customer's Jira depending on nothing
//! but a connection setting, and a route that reached past the port would be one
//! more call site to rewrite the day that setting exists.
//!
//! [`board`] and [`amend`] read and write `work_items` directly, and that
//! asymmetry is the port's boundary rather than a shortcut. Ranking and
//! assigning are not trait methods: a company on Jira ranks and assigns *in
//! Jira*, and a port verb for it would make every future adapter fake an
//! ordering beside the customer's real one. So they are the internal tool's own
//! administration surface, exactly as `POST /v1/knowledge/documents` is.
//!
//! # What is recorded, and what still is not
//!
//! **`posted_by`, and still no audit row.** This paragraph used to say the
//! column was not worth having, on the grounds that every writer here holds an
//! operator API key and the answer would be the same string on every row — and
//! it named the change that would make it worth having: the one that gives an
//! *employee* a way to post. That change happened (`add_work_item`,
//! `Effects::post_work`), so the column exists, `0064` carries the argument, and
//! **this surface always writes null**, which is what "an operator, through the
//! API" honestly looks like.
//!
//! No audit row still, and now for a stronger reason than "one writer": posting
//! is not an `Action`, nothing rules on it, and `AuditKind`'s rows are rulings.
//! A row there for a decision nobody made would be worse than the gap.
//! `0037`'s `prospect_flow_proposals` leaves the same field out for its own
//! version of the first reason.

use agentos_app::backlog::{Backlog, BacklogError, PgBacklog};
use agentos_domain::ids::{EmployeeId, WorkItemId};
use agentos_store::backlog;
use agentos_store::db::{Db, StoreError};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack` — which is also
/// why [`Backlog::post`] carries no idempotency key of its own.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/work", get(board).post(post))
        .route("/v1/work/{id}", put(amend))
        .with_state(db)
}

/// Longest title `work_items_title_shape` accepts, in characters.
///
/// Restated here rather than read off the table, and the restatement is what the
/// test below pins: the alternative is a round trip to `information_schema` per
/// request to learn a number that changes in a migration. If it ever moves, this
/// constant moves with it in the same commit.
const MAX_TITLE: usize = 200;

/// A new item.
#[derive(Deserialize)]
struct NewItem {
    /// What to do, in one line. 1 to 200 characters, as the table demands.
    title: String,
    /// Who does it. Absent or null is the shared board.
    #[serde(default)]
    assignee_id: Option<Uuid>,
}

/// The mutable half of an item, whole.
///
/// **Replace, not merge** — see [`agentos_store::backlog::amend`]. Every field
/// is written on every call, so `assignee_id: null` puts an item back on the
/// board and omitting it does the same thing. There is no spelling of "leave
/// this alone", because the two spellings of absent are how somebody gets
/// unassigned by a client that forgot a field.
#[derive(Deserialize)]
struct Amendment {
    /// Who has it now. Null is the shared board.
    #[serde(default)]
    assignee_id: Option<Uuid>,
    /// Where it sits in the founder's order. Null is unranked, which sorts
    /// after everything ranked.
    #[serde(default)]
    ordinal: Option<i64>,
    /// Is it done. Required: this is the field the call is usually about, and a
    /// default would silently reopen an item somebody only meant to re-rank.
    closed: bool,
}

/// One item, as the founder reads it back.
#[derive(Serialize)]
struct ItemView {
    id: Uuid,
    title: String,
    assignee_id: Option<Uuid>,
    ordinal: Option<i64>,
    /// Who wrote it: an employee's id, or null for this endpoint's own writes.
    ///
    /// The reader `0064` exists for. A board now mixes rows the founder typed
    /// with rows a model filed through `add_work_item`, the text is otherwise
    /// indistinguishable, and nothing else anywhere records the difference —
    /// posting is not an `Action`, so there is no audit row to cross-check.
    posted_by: Option<Uuid>,
    /// The thread a third party's message opened it from, or null for an item
    /// somebody typed — `migrations/0080` is where that distinction lives.
    conversation_id: Option<Uuid>,
    closed_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

impl From<backlog::Item> for ItemView {
    fn from(item: backlog::Item) -> Self {
        Self {
            id: item.id.as_uuid(),
            title: item.title,
            assignee_id: item.assignee_id.map(|e| e.as_uuid()),
            ordinal: item.ordinal,
            posted_by: item.posted_by.map(|e| e.as_uuid()),
            conversation_id: item.conversation_id.map(|c| c.as_uuid()),
            closed_at: item.closed_at,
            created_at: item.created_at,
        }
    }
}

/// `GET /v1/work` — the whole board, in the order the employees read it.
///
/// Open and closed together, and no filter: what a founder wants to know at the
/// top of the week is what is outstanding *and* what got done, and a board that
/// hid the second half would make the first look like nothing had happened.
async fn board(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let items = backlog::board(&mut tx).await?;
    tx.rollback().await?;

    Ok(Json(json!({
        "items": items.into_iter().map(ItemView::from).collect::<Vec<_>>(),
    }))
    .into_response())
}

/// `POST /v1/work` — write one down.
///
/// 404 when `assignee_id` is not an employee of this company, which is the same
/// answer a request naming an employee that does not exist gets. Under RLS the
/// two are indistinguishable and must stay that way — see
/// [`agentos_store::backlog::post`].
async fn post(
    State(db): State<Db>,
    principal: Principal,
    Json(body): Json<NewItem>,
) -> Result<Response, ApiError> {
    let title = body.title.trim();
    // Both ends of `work_items_title_shape`, and it has to be both. Refusing
    // only the empty one left the other to the `CHECK`, which arrives as a
    // `23514` in `StoreError::Database` and comes out of `ApiError` as a **500**
    // — "we broke" — for a body the founder fixes by shortening a sentence.
    // `char_length` is what the constraint counts, so `chars()` is what this
    // counts; `.len()` would refuse a 70-character Japanese title.
    if title.is_empty() || title.chars().count() > MAX_TITLE {
        return Err(ApiError::bad_request(
            "an item needs a title of 1 to 200 characters: it is the sentence an employee \
             reads off its brief",
        ));
    }

    let board = PgBacklog::new(db, principal.tenant_id);
    let id = board
        // `None` for the author, and it is the value this surface always
        // passes: every writer here holds an operator API key, and `0064` calls
        // null exactly that rather than inventing an employee to blame.
        .post(title, body.assignee_id.map(EmployeeId::from_uuid), None)
        .await
        .map_err(refusal)?;

    Ok((StatusCode::CREATED, Json(json!({ "id": id.as_uuid() }))).into_response())
}

/// `PUT /v1/work/{id}` — who has it, where it sits, whether it is done.
///
/// **This is the endpoint the founder reorders with**, and until it existed
/// there was nowhere in this product to say *this before that*: the operator
/// surfaces were approve/refuse (`/v1/approvals`), a cadence
/// (`/v1/employees/{id}/initiative`) and a CSV export (`/v1/…/queue/export`).
async fn amend(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Json(body): Json<Amendment>,
) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let item = backlog::amend(
        &mut tx,
        WorkItemId::from_uuid(id),
        body.assignee_id.map(EmployeeId::from_uuid),
        body.ordinal,
        body.closed,
        Utc::now(),
    )
    .await
    .map_err(|err| match err {
        StoreError::NotFound => ApiError::not_found(),
        other => ApiError::from(other),
    })?;
    tx.commit().await?;

    Ok(Json(ItemView::from(item)).into_response())
}

/// A board refusing, in the two ways a board can refuse.
///
/// [`StoreError::NotFound`] out of the port is an assignee this company does not
/// have — the item has no id yet, so it cannot be the other kind of not-found —
/// and everything else is ours to own. A connected board's
/// [`BacklogError::Provider`] is not reachable today and is mapped rather than
/// left to a `_` arm, so the day one exists this compiles into a 502 rather
/// than into a 500 that blames us for somebody else's outage.
fn refusal(err: BacklogError) -> ApiError {
    match err {
        BacklogError::Unavailable(StoreError::NotFound) => ApiError::not_found()
            .with_detail("no such employee in this company to give the work to"),
        BacklogError::Unavailable(other) => ApiError::from(other),
        BacklogError::Provider(err) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "board_unavailable",
            "the connected work board refused",
        )
        .with_detail(err.code()),
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY};

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Two companies behind two keys, under the real middleware stack — so the
    /// idempotency layer this port leans on instead of carrying a key of its own
    /// is actually in the path.
    struct Harness {
        app: Router,
        a: TenantId,
    }

    impl Harness {
        async fn new(db: &Db) -> Self {
            // B exists only behind `SECRET_B`: every assertion about it is
            // "what can this key see", which is the question the isolation is
            // about.
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
                a,
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
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'work-routes-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn new_employee(db: &Db, tenant: TenantId, slug: &str) -> Uuid {
        let id = Uuid::now_v7();
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(format!("{slug}-{}", &id.simple().to_string()[..8]))
        .bind(slug)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    fn ids(board: &Value) -> Vec<String> {
        board["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["id"].as_str().expect("id").to_owned())
            .collect()
    }

    /// **The third failure `0061` names, over HTTP**: before this endpoint there
    /// was nowhere in this product for a founder to say *this before that*.
    ///
    /// One run: write two items down, watch them come back in arrival order,
    /// rank the second one first, hand one to another seat, close one and find
    /// it still on the board.
    #[tokio::test]
    async fn the_founder_writes_work_down_ranks_it_and_closes_it() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the work board needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let ada = new_employee(&db, h.a, "ada").await;
        let bob = new_employee(&db, h.a, "bob").await;

        let (status, first) = h
            .send(
                "POST",
                "/v1/work",
                SECRET_A,
                Some(json!({ "title": "chase the tariff code", "assignee_id": ada })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        let (_, second) = h
            .send(
                "POST",
                "/v1/work",
                SECRET_A,
                Some(json!({ "title": "answer the customs email", "assignee_id": ada })),
            )
            .await;
        let (first, second) = (
            first["id"].as_str().expect("id").to_owned(),
            second["id"].as_str().expect("id").to_owned(),
        );

        let (status, board) = h.send("GET", "/v1/work", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            ids(&board),
            vec![first.clone(), second.clone()],
            "unranked items come back in the order they arrived"
        );

        // The reordering. This is the verb the product did not have.
        let (status, ranked) = h
            .send(
                "PUT",
                &format!("/v1/work/{second}"),
                SECRET_A,
                Some(json!({ "assignee_id": ada, "ordinal": 1, "closed": false })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{ranked}");
        let (_, board) = h.send("GET", "/v1/work", SECRET_A, None).await;
        assert_eq!(
            ids(&board),
            vec![second.clone(), first.clone()],
            "a ranked item comes before an unranked one whatever order they arrived in"
        );

        // The same item, a different seat — which is what one shared board buys
        // over one list per employee.
        let (status, moved) = h
            .send(
                "PUT",
                &format!("/v1/work/{first}"),
                SECRET_A,
                Some(json!({ "assignee_id": bob, "ordinal": null, "closed": false })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            moved["assignee_id"].as_str(),
            Some(bob.to_string().as_str())
        );

        // Closing is a column, not a delete.
        let (_, closed) = h
            .send(
                "PUT",
                &format!("/v1/work/{second}"),
                SECRET_A,
                Some(json!({ "assignee_id": ada, "ordinal": 1, "closed": true })),
            )
            .await;
        assert!(!closed["closed_at"].is_null(), "{closed}");
        let (_, board) = h.send("GET", "/v1/work", SECRET_A, None).await;
        assert_eq!(
            ids(&board).len(),
            2,
            "a closed item is still on the board: the founder needs to see what got done"
        );
    }

    /// **A title this table will not take is the caller's mistake, not ours.**
    ///
    /// `POST` already refuses an empty title here rather than at the table, so
    /// the other end of `work_items_title_shape` has to be refused here too:
    /// left to the `CHECK`, a 201-character title comes back as a `23514` in
    /// [`StoreError::Database`], which [`ApiError`] answers **500** — "we
    /// broke" — for a body the founder can fix by shortening a sentence. Both
    /// ends of one constraint, one answer.
    #[tokio::test]
    async fn a_title_the_table_will_not_take_is_a_400_and_not_a_500() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the work board needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;

        for title in ["", "   ", &"x".repeat(201)] {
            let (status, problem) = h
                .send(
                    "POST",
                    "/v1/work",
                    SECRET_A,
                    Some(json!({ "title": title })),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a title of {} characters answered {status}: {problem}",
                title.chars().count()
            );
        }

        // …and the longest one the table does take still lands.
        let (status, _) = h
            .send(
                "POST",
                "/v1/work",
                SECRET_A,
                Some(json!({ "title": "x".repeat(200) })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "200 characters is the bound");
    }

    /// A board is one company's, and an assignee is too.
    ///
    /// The second half is the one a foreign key cannot make: `references
    /// employees (id)` is checked as the table's owner and would happily accept
    /// another company's seat, which is both an existence oracle and a row whose
    /// `on delete set null` fires from a tenant that cannot see it.
    #[tokio::test]
    async fn one_company_s_board_and_one_company_s_seats() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the work board needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let ada = new_employee(&db, h.a, "ada").await;

        let (_, mine) = h
            .send(
                "POST",
                "/v1/work",
                SECRET_A,
                Some(json!({ "title": "A's work", "assignee_id": ada })),
            )
            .await;
        let mine = mine["id"].as_str().expect("id").to_owned();

        let (status, board) = h.send("GET", "/v1/work", SECRET_B, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ids(&board).is_empty(), "B must not see A's board");

        let (status, _) = h
            .send(
                "PUT",
                &format!("/v1/work/{mine}"),
                SECRET_B,
                Some(json!({ "assignee_id": null, "ordinal": 0, "closed": true })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "B must not be able to close A's work, nor learn that it exists"
        );

        let (status, refused) = h
            .send(
                "POST",
                "/v1/work",
                SECRET_B,
                Some(json!({ "title": "do B's work", "assignee_id": ada })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an assignee from another company is refused, not filed: {refused}"
        );

        let (status, _) = h
            .send(
                "POST",
                "/v1/work",
                SECRET_A,
                Some(json!({ "title": "   " })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an item with no title is a blank line on a board and in a prompt"
        );
    }
}
