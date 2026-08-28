//! `/v1/calendar`: the founder's half of the diary — promise a moment, see what
//! has been promised.
//!
//! `migrations/0063_appointments.sql` argues for the table and
//! [`agentos_app::calendar`] for the port. This is the only surface that writes
//! either today.
//!
//! # Why `POST` goes through the port and `GET` does not
//!
//! [`book`] calls [`Calendar::book`], because "block this hour" is the verb that
//! has to land in *our* table or in a customer's Google Calendar depending on
//! nothing but a connection setting, and a route that reached past the port
//! would be one more call site to rewrite the day that setting exists.
//!
//! [`diary`] reads `appointments` directly, and that asymmetry is the port's
//! boundary rather than a shortcut — the same one `routes::work` draws. One
//! seat's outstanding promises is a port verb because a connected diary has an
//! answer to it; *every seat in the company, rung and outstanding, on one
//! screen* is this internal tool's own administration surface, exactly as
//! `GET /v1/work` is.
//!
//! # Why the employee is in the body here and nowhere else
//!
//! [`agentos_app::calendar::Calendar::book`] deliberately has no employee
//! argument, so that an employee holding one can only promise its own time. This
//! route names an employee in its body and builds a [`PgCalendar`] around it,
//! and that is not a hole in the argument: the caller holds an operator API key,
//! it is the same authority that already writes charters and cadences, and it is
//! not a principal the gate rules on. What keeps it inside its own company is
//! `agentos_store::calendar::book`'s `EXISTS`, which the foreign key alone would
//! not — see that function's docs.
//!
//! # What is deliberately not here
//!
//! **No cancellation.** `rang_at` written before the instant is a cancellation
//! and the grant allows the UPDATE; nothing has asked for the route, so there
//! isn't one. It is one statement the day somebody does.
//!
//! **No `booked_by` and no audit row.** `routes::work`'s reason, unchanged:
//! every writer here holds an operator key, so the answer would be the same
//! string on every row, and `AuditKind` is a closed vocabulary whose widening
//! belongs in the change that gives an *employee* a way to book.

use agentos_app::calendar::{Calendar, CalendarError, PgCalendar};
use agentos_domain::ids::EmployeeId;
use agentos_store::calendar;
use agentos_store::db::{Db, StoreError};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the rate
/// limit and the idempotency layer from `with_api_stack` — which is also why
/// [`Calendar::book`] carries no idempotency key of its own.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/calendar", get(diary).post(book))
        .with_state(db)
}

/// A moment somebody is promising.
#[derive(Deserialize)]
struct NewAppointment {
    /// Whose moment. Required: there is no shared appointment — see
    /// `migrations/0063_appointments.sql`.
    employee_id: Uuid,
    /// The instant, as RFC 3339 with an offset.
    at: DateTime<Utc>,
    /// **Whose Tuesday**: an IANA zone name. Required, with no default, because
    /// a default would be the server's and the server's zone is nobody's. The
    /// instant above is what fires; this is what the promise meant, and it is
    /// what the moment is said back in.
    at_zone: String,
    /// What the moment is about, in one line. Bounded by the table, not here.
    subject: String,
}

/// One appointment, as the founder reads it back.
#[derive(Serialize)]
struct AppointmentView {
    id: Uuid,
    employee_id: Uuid,
    /// The instant.
    at: DateTime<Utc>,
    at_zone: String,
    /// [`AppointmentView::at`] as it was promised: wall time in `at_zone`.
    local_time: String,
    subject: String,
    /// When it stopped being a promise. Null is still ahead; earlier than `at`
    /// is a cancellation, and later is **the hour having come round** — which is
    /// not the same as it having been kept. Read `outcome` for that.
    rang_at: Option<DateTime<Utc>>,
    /// What became of it, in `0072`'s vocabulary. `turn` is the only value that
    /// says something actually happened; `no_charter`, `no_model`, `clarify`,
    /// `no_work`, `over_budget`, `unreadable_charter` and `error` each name a
    /// reason the hour came round and nothing was done, and every one of them is
    /// something to go and fix. `cancelled` is a seat that left.
    ///
    /// **Null beside a non-null `rang_at` means nobody ever said**: the claim
    /// consumed the promise, and the process that was going to record the
    /// outcome did not get there. Not a synonym for success — see `0072` for why
    /// it is this way round and not the other.
    outcome: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<calendar::Appointment> for AppointmentView {
    fn from(appointment: calendar::Appointment) -> Self {
        Self {
            id: appointment.id.as_uuid(),
            employee_id: appointment.employee_id.as_uuid(),
            at: appointment.at,
            at_zone: appointment.zone,
            local_time: appointment.local_time,
            subject: appointment.subject,
            rang_at: appointment.rang_at,
            outcome: appointment.outcome,
            created_at: appointment.created_at,
        }
    }
}

/// `GET /v1/calendar` — every moment this company has promised, soonest first.
///
/// Rung and outstanding together, and no filter, for `GET /v1/work`'s reason:
/// what a founder wants at the top of the week is what is coming *and* what was
/// kept, and a diary that hid the second half would make the first look like
/// nothing had happened.
async fn diary(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let appointments = calendar::diary(&mut tx).await?;
    tx.rollback().await?;

    Ok(Json(json!({
        "appointments": appointments
            .into_iter()
            .map(AppointmentView::from)
            .collect::<Vec<_>>(),
    }))
    .into_response())
}

/// `POST /v1/calendar` — promise one moment.
///
/// **This is the verb the product did not have.** Until this endpoint existed
/// the only two things that could reach an employee were somebody else's email
/// and an interval with a five-minute floor; there was no way anywhere in this
/// system to say *at three o'clock on Tuesday*.
///
/// 404 when `employee_id` is not an employee of this company, which is the same
/// answer a request naming an employee that does not exist gets — under RLS the
/// two are indistinguishable and must stay that way. 400 for a zone no tzdata
/// knows, which is a typo in a field the caller controls and is nothing to keep
/// quiet about.
async fn book(
    State(db): State<Db>,
    principal: Principal,
    Json(body): Json<NewAppointment>,
) -> Result<Response, ApiError> {
    let subject = body.subject.trim();
    if subject.is_empty() {
        return Err(ApiError::bad_request(
            "an appointment needs a subject: it is the sentence the employee reads when the \
             moment arrives",
        ));
    }

    let seat = PgCalendar::new(
        db,
        principal.tenant_id,
        EmployeeId::from_uuid(body.employee_id),
    );
    let id = seat
        .book(body.at, &body.at_zone, subject)
        .await
        .map_err(refusal)?;

    Ok((StatusCode::CREATED, Json(json!({ "id": id.as_uuid() }))).into_response())
}

/// A diary refusing, in the three ways a diary can refuse.
///
/// [`StoreError::NotFound`] out of the port is an employee this company does not
/// have — the appointment has no id yet, so it cannot be the other kind of
/// not-found. A connected diary's [`CalendarError::Provider`] is not reachable
/// today and is mapped rather than left to a `_` arm, so the day one exists this
/// compiles into a 502 rather than into a 500 that blames us for somebody else's
/// outage.
fn refusal(err: CalendarError) -> ApiError {
    match err {
        // 400 rather than the 500 this used to be: the handler checked for an
        // empty subject and nothing checked the other end, so a caller's long
        // sentence hit `appointments_subject_shape` and came back as our fault.
        CalendarError::SubjectShape => ApiError::bad_request(
            "`subject` is 1 to 200 characters: it is the one line the employee reads when the \
             moment arrives, not the briefing",
        ),
        CalendarError::UnknownZone => ApiError::bad_request(
            "`at_zone` must be an IANA time zone name, like `Europe/Vienna`: it is whose \
             clock the promise was made against, and there is no default because the \
             server's zone is nobody's",
        ),
        CalendarError::Unavailable(StoreError::NotFound) => {
            ApiError::not_found().with_detail("no such employee in this company to promise for")
        }
        CalendarError::Unavailable(other) => ApiError::from(other),
        CalendarError::Provider(err) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "calendar_unavailable",
            "the connected calendar refused",
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'calendar-routes-test')")
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

    /// **"I will call you back on Tuesday at three", over HTTP**, and the half
    /// of it that is not the instant: the same instant promised to two people in
    /// two countries comes back as two different sentences, each in the words
    /// its own promise was made in.
    #[tokio::test]
    async fn the_founder_promises_an_hour_and_it_says_itself_back_in_its_own_zone() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the diary needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let ada = new_employee(&db, h.a, "ada").await;

        let (status, first) = h
            .send(
                "POST",
                "/v1/calendar",
                SECRET_A,
                Some(json!({
                    "employee_id": ada,
                    "at": "2026-09-01T13:00:00Z",
                    "at_zone": "Europe/Vienna",
                    "subject": "call back about the tariff code",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{first}");

        let (status, _) = h
            .send(
                "POST",
                "/v1/calendar",
                SECRET_A,
                Some(json!({
                    "employee_id": ada,
                    // The same instant, promised to somebody in Tokyo.
                    "at": "2026-09-01T13:00:00Z",
                    "at_zone": "Asia/Tokyo",
                    "subject": "call back about the freight quote",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, diary) = h.send("GET", "/v1/calendar", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        let said_back: Vec<&str> = diary["appointments"]
            .as_array()
            .expect("appointments")
            .iter()
            .map(|a| a["local_time"].as_str().expect("local_time"))
            .collect();
        assert_eq!(
            said_back,
            vec!["2026-09-01 15:00", "2026-09-01 22:00"],
            "one instant, two promises, two sentences: this is the whole reason \
             `at_zone` is a column"
        );
        assert!(
            diary["appointments"][0]["rang_at"].is_null(),
            "nothing has rung yet"
        );

        // A zone nobody has is a 400 naming the field, not a 404 and not a 500.
        let (status, refused) = h
            .send(
                "POST",
                "/v1/calendar",
                SECRET_A,
                Some(json!({
                    "employee_id": ada,
                    "at": "2026-09-01T13:00:00Z",
                    "at_zone": "Mars/Olympus",
                    "subject": "ring at a time nobody has",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");

        let (status, _) = h
            .send(
                "POST",
                "/v1/calendar",
                SECRET_A,
                Some(json!({
                    "employee_id": ada,
                    "at": "2026-09-01T13:00:00Z",
                    "at_zone": "Europe/Vienna",
                    "subject": "   ",
                })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an appointment with no subject is a blank line in a brief"
        );
    }

    /// A diary is one company's, and so is the seat a moment is promised for.
    ///
    /// The second half is the one a foreign key cannot make, and on this table
    /// it is not merely an existence oracle: an appointment filed against
    /// another company's employee is a way to make that employee take a turn at
    /// an hour you chose.
    #[tokio::test]
    async fn one_company_s_diary_and_one_company_s_seats() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the diary needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let h = Harness::new(&db).await;
        let ada = new_employee(&db, h.a, "ada").await;

        let (status, _) = h
            .send(
                "POST",
                "/v1/calendar",
                SECRET_A,
                Some(json!({
                    "employee_id": ada,
                    "at": "2026-09-01T13:00:00Z",
                    "at_zone": "Europe/Paris",
                    "subject": "A's call",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, diary) = h.send("GET", "/v1/calendar", SECRET_B, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            diary["appointments"]
                .as_array()
                .expect("appointments")
                .is_empty(),
            "B must not see A's diary"
        );

        let (status, refused) = h
            .send(
                "POST",
                "/v1/calendar",
                SECRET_B,
                Some(json!({
                    "employee_id": ada,
                    "at": "2026-09-01T13:00:00Z",
                    "at_zone": "Europe/Paris",
                    "subject": "wake A's employee at an hour I chose",
                })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a seat from another company is refused, not filed: {refused}"
        );
    }
}
