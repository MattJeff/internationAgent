//! **La page de réservation** : un inconnu reçoit un lien, choisit une heure,
//! et l'employé est réveillé à cette heure-là avec le fil. Remplace Calendly.
//!
//! Tout existait sauf la porte. Le calendrier promet une heure et est réveillé
//! par elle (`0063`, `agentos_store::calendar`) ; une promesse sait nommer le
//! fil qu'elle concerne (`0082`) ; un tiers entre dans le système par
//! `inbound::conversation_for` et un message `Untrusted`, jamais comme une
//! action de l'employé. Ce module est la porte, et rien d'autre : deux routes
//! publiques et une bascule privée.
//!
//! # L'étage sans credential, et ce qu'il refuse
//!
//! `GET`/`POST /book/{domain}/{slug}` sont montées à côté de `well_known`, hors
//! de `with_api_stack`, parce qu'un prospect n'a pas de clé. Ce que ça oblige :
//!
//! * **Le siège doit avoir ouvert sa page** — `employees.booking_open`
//!   (`0083`), `false` sur toute ligne jusqu'à `PUT /v1/employees/{id}/booking`.
//!   Un couple `(domain, slug)` inconnu et un siège fermé passent par le même
//!   `SELECT` et sortent par le même `404` : la page ne confirme jamais qu'un
//!   siège existe.
//! * **Le seul SQL qui traverse les locataires est la résolution** — un
//!   `SELECT` sur `employees` par `admin_tx_bypassing_rls`, comme
//!   `routes::a2a::discover`. Une fois le locataire connu, tout le reste passe
//!   par `Db::tenant_tx`, et le formulaire d'un tiers ne peut écrire que chez
//!   l'entreprise dont il tient le lien.
//! * **Un refus de créneau est une seule phrase**, quelle qu'en soit la raison
//!   — passé, hors horizon, heure fermée, zone inconnue, déjà promis. Un
//!   message qui distinguerait « déjà pris » de « trop tard » est un moyen de
//!   lire l'agenda d'un siège une heure à la fois.
//!
//! # Ce que le `POST` écrit, dans une transaction
//!
//! Le fil du tiers (`Channel::Web`, clé `(employé, canal, adresse)`), un
//! message entrant `untrusted` dont le corps est le motif — stocké, jamais
//! rendu, jamais dans un sujet — et la promesse calendrier avec le fil dessus.
//! Le sujet est le nôtre, construit comme `follow_up::subject` : un mot à nous
//! et l'adresse masquée. **Pas de gate et pas d'`Authorized`** : l'employé n'a
//! rien proposé, c'est un atterrissage, et la ligne d'audit porte l'acteur
//! `system` comme dans `inbound::land` — `routes::autonomy` ne compte que les
//! `decision = 'allow'`, et un atterrissage n'en a pas. Pas de tour enfilé non
//! plus, au contraire de `land` : le réveil, c'est l'heure promise.
//!
//! # Abus
//!
//! Le limiteur de `main.rs` est à clé de locataire et ne peut pas vivre ici.
//! Ce module a le sien : une fenêtre fixe par siège et par adresse transmise
//! (`X-Forwarded-For`, que seul l'ingress écrit), le corps borné, un champ
//! caché qui doit rester vide et dont le remplissage vaut un `200` sans
//! écriture, et l'email validé par le même `EmailAddress::parse` que l'inbound.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentos_app::inbound;
use agentos_domain::action::EmailAddress;
use agentos_domain::ids::{AppointmentId, EmployeeId, TenantId};
use agentos_domain::message::{CanonicalMessage, Channel, ProviderRef};
use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
use agentos_store::calendar;
use agentos_store::db::{Db, StoreError, TenantTx};
use axum::extract::rejection::FormRejection;
use axum::extract::{DefaultBodyLimit, Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{DateTime, Datelike, NaiveDateTime, TimeDelta, Timelike, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

/// How far ahead a stranger may book.
///
/// ponytail: a constant, not a per-seat setting. Thirty days is what
/// "recently" means everywhere else in this product, pointed forwards.
pub const BOOKING_HORIZON: TimeDelta = TimeDelta::days(30);

/// The hours a stranger may pick, in the zone they picked: 9:00 up to but not
/// including 18:00, Monday to Friday.
///
/// ponytail: one range for every seat. A per-seat opening-hours column is the
/// upgrade, the day a tenant runs a seat on another continent than its own.
const OPEN_HOURS: std::ops::Range<u32> = 9..18;

/// What one booking occupies, for the collision check against the seat's
/// outstanding promises.
const SLOT: TimeDelta = TimeDelta::hours(1);

/// The longest reason the form accepts, in characters.
const MAX_REASON: usize = 240;

/// The longest name the form accepts, in characters.
const MAX_NAME: usize = 80;

/// The zones the `<select>` offers. Short on purpose: a list of six hundred is
/// a page nobody scrolls, and the server still asks `zone_is_real` because a
/// form is text anybody can post.
const ZONES: [&str; 12] = [
    "Europe/Paris",
    "Europe/London",
    "Europe/Berlin",
    "Europe/Madrid",
    "Europe/Rome",
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Australia/Sydney",
    "UTC",
];

/// Submissions per key — a seat, or a forwarded address — per [`RATE_WINDOW`].
///
/// ponytail: an in-memory fixed window, the same shape as `main.rs`'s tenant
/// limiter and with the same ceiling: one process. A second replica has its
/// own counter, so a fleet allows `replicas ×` this. Move it to the ingress
/// the day there is one.
const RATE_LIMIT: u32 = 10;
const RATE_WINDOW: Duration = Duration::from_secs(600);

/// A form is five short fields; anything past this is not a person.
const MAX_BODY: usize = 4 * 1024;

/// The route's state: the pool and the abuse counter.
#[derive(Clone)]
pub struct Booking {
    db: Db,
    windows: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

impl Booking {
    /// `true` if one more submission under `key` fits in the window.
    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut windows = match self.windows.lock() {
            Ok(windows) => windows,
            Err(poisoned) => poisoned.into_inner(),
        };
        let (started, count) = windows.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(*started) >= RATE_WINDOW {
            *started = now;
            *count = 0;
        }
        *count += 1;
        *count <= RATE_LIMIT
    }
}

/// The public pair. Sans credential — see the module docs.
pub fn public_router(db: Db) -> Router {
    Router::new()
        .route("/book/{domain}/{slug}", get(page).post(submit))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(Booking {
            db,
            windows: Arc::default(),
        })
}

/// The switch. An operator's act, on the keyed tier.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/employees/{id}/booking", put(set_open))
        .with_state(db)
}

/// The one line the promise carries: our word and the masked address.
/// `follow_up::subject`'s shape, so a booked hour and a chase read alike in a
/// diary, and for the same reason nothing the stranger typed is in it.
fn subject(contact: &str) -> String {
    format!("booking · {}", inbound::masked_contact(contact))
        .chars()
        .take(calendar::MAX_SUBJECT)
        .collect()
}

// ---------------------------------------------------------------------------
// The switch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Open {
    open: bool,
}

async fn set_open(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Json(body): Json<Open>,
) -> Result<Response, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let changed =
        sqlx::query("UPDATE employees SET booking_open = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(body.open)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::from)?
            .rows_affected();
    if changed == 0 {
        tx.rollback().await?;
        return Err(ApiError::not_found());
    }
    tx.commit().await?;
    Ok(Json(json!({ "id": id, "open": body.open })).into_response())
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

/// Why a submission was not taken, and the one page each answer renders.
///
/// Every variant is our words. Nothing the stranger typed is ever echoed, so
/// there is no HTML to escape here — that is a property of the pages, not of a
/// helper.
enum Refused {
    /// No such page: unknown couple, or a seat that has not opened.
    NotFound,
    /// A field is missing or misshapen. Names the field, never the diary.
    Form(&'static str),
    /// The moment cannot be booked. One sentence for every reason.
    Slot,
    /// Over the window.
    Busy,
    /// The database did not answer.
    Unavailable,
}

impl From<StoreError> for Refused {
    fn from(err: StoreError) -> Self {
        tracing::error!(error = %err, "the booking page could not reach the store");
        Refused::Unavailable
    }
}

impl From<inbound::InboundError> for Refused {
    fn from(err: inbound::InboundError) -> Self {
        tracing::error!(error = %err, "the booking page could not open the thread");
        Refused::Unavailable
    }
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        let (status, text) = match self {
            Refused::NotFound => (StatusCode::NOT_FOUND, "There is no page here."),
            Refused::Form(field) => (StatusCode::BAD_REQUEST, field),
            Refused::Slot => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "That moment cannot be booked. Please go back and pick another.",
            ),
            Refused::Busy => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests. Please try again later.",
            ),
            Refused::Unavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong on our side. Please try again later.",
            ),
        };
        (status, Html(wrap(&format!("<p>{text}</p>")))).into_response()
    }
}

/// The document around one body. No script, no stylesheet, nothing fetched.
fn wrap(body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width\">\
         <title>Book a moment</title></head><body><main>{body}</main></body></html>"
    )
}

/// The form. Static: the couple in the URL is neither echoed nor confirmed.
fn form_page() -> String {
    let zones: String = ZONES
        .iter()
        .map(|zone| format!("<option>{zone}</option>"))
        .collect();
    wrap(&format!(
        "<h1>Book a moment</h1><form method=\"post\">\
         <p><label>Your name <input name=\"name\" required maxlength=\"{MAX_NAME}\"></label></p>\
         <p><label>Your email <input name=\"email\" type=\"email\" required></label></p>\
         <p><label>When <input name=\"at\" type=\"datetime-local\" required></label></p>\
         <p><label>Time zone <select name=\"zone\">{zones}</select></label></p>\
         <p><label>What it is about <textarea name=\"reason\" required \
         maxlength=\"{MAX_REASON}\"></textarea></label></p>\
         <div hidden aria-hidden=\"true\"><label>Website \
         <input name=\"website\" tabindex=\"-1\" autocomplete=\"off\"></label></div>\
         <p><button>Book</button></p></form>"
    ))
}

/// What a taken booking — and a honeypot — is told. Deliberately the same
/// page, and deliberately without the hour: a bot that fills the hidden field
/// learns nothing from the answer, and a page that echoed the hour would have
/// a stranger's text on it.
fn booked_page() -> String {
    wrap(
        "<h1>Booked</h1><p>Thank you. The moment is in the diary, and you will hear from us then.</p>",
    )
}

/// `(domain, slug)` → the seat, if it has opened its page. Across tenants,
/// because there is no credential to scope by — `routes::a2a::discover`'s
/// exception, one row wide. Two open seats on one couple — two tenants
/// claiming one domain — is nobody's page rather than the older one's.
async fn resolve(db: &Db, domain: &str, slug: &str) -> Result<(TenantId, EmployeeId), Refused> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT id, tenant_id FROM employees \
          WHERE spec ->> 'domain' = $1 AND slug = $2 \
            AND booking_open AND lifecycle = 'active' \
          LIMIT 2",
    )
    .bind(domain)
    .bind(slug)
    .fetch_all(&mut *tx)
    .await
    .map_err(StoreError::from)?;
    let _ = tx.rollback().await;
    match rows.as_slice() {
        [(id, tenant)] => Ok((TenantId::from_uuid(*tenant), EmployeeId::from_uuid(*id))),
        _ => Err(Refused::NotFound),
    }
}

async fn page(
    State(state): State<Booking>,
    Path((domain, slug)): Path<(String, String)>,
) -> Response {
    match resolve(&state.db, &domain, &slug).await {
        Ok(_) => Html(form_page()).into_response(),
        Err(refused) => refused.into_response(),
    }
}

/// What `<form method="post">` sends. `website` is the honeypot.
#[derive(Deserialize)]
struct BookingForm {
    name: String,
    email: String,
    at: String,
    zone: String,
    reason: String,
    #[serde(default)]
    website: String,
}

/// `<input type="datetime-local">`'s value, with or without seconds.
fn parse_local(raw: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M")
        .or_else(|_| NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S"))
        .ok()
}

/// The first hop the ingress wrote, if it wrote one. Absent, the seat key
/// alone bounds the window.
fn forwarded_for(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .split(',')
        .next()
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty())
}

async fn submit(
    State(state): State<Booking>,
    Path((domain, slug)): Path<(String, String)>,
    headers: HeaderMap,
    form: Result<Form<BookingForm>, FormRejection>,
) -> Response {
    match book(&state, &domain, &slug, &headers, form).await {
        Ok(page) => page,
        Err(refused) => refused.into_response(),
    }
}

async fn book(
    state: &Booking,
    domain: &str,
    slug: &str,
    headers: &HeaderMap,
    form: Result<Form<BookingForm>, FormRejection>,
) -> Result<Response, Refused> {
    // The seat first, so a closed one is a 404 whatever the body says.
    let (tenant, employee) = resolve(&state.db, domain, slug).await?;
    let by_ip = forwarded_for(headers).is_some_and(|ip| !state.allow(&format!("ip:{ip}")));
    if !state.allow(&format!("seat:{employee}")) || by_ip {
        return Err(Refused::Busy);
    }
    let Form(form) = form.map_err(|_| Refused::Form("The form could not be read."))?;
    if !form.website.is_empty() {
        // A bot. Told what a person is told, and nothing is written.
        return Ok(Html(booked_page()).into_response());
    }
    let email = EmailAddress::parse(&form.email)
        .map_err(|_| Refused::Form("Please give a valid email address."))?;
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(Refused::Form("Please give your name."));
    }
    let reason = form.reason.trim();
    if reason.is_empty() || reason.chars().count() > MAX_REASON {
        return Err(Refused::Form(
            "Please say what it is about, in a few words.",
        ));
    }
    // The picked hour, in the picked zone. Everything below is one answer.
    if !ZONES.contains(&form.zone.as_str()) {
        return Err(Refused::Slot);
    }
    let local = parse_local(&form.at).ok_or(Refused::Slot)?;
    if !OPEN_HOURS.contains(&local.hour()) || local.weekday().number_from_monday() > 5 {
        return Err(Refused::Slot);
    }

    let now = Utc::now();
    let contact = email.to_string();
    let mut tx = state.db.tenant_tx(tenant).await?;
    let placed = place(
        &mut tx, employee, local, &form.zone, name, &contact, reason, now,
    )
    .await;
    match placed {
        Ok(()) => {
            tx.commit().await?;
            Ok(Html(booked_page()).into_response())
        }
        Err(refused) => {
            // Rolled back rather than dropped, for `PgCalendar::book`'s reason.
            let _ = tx.rollback().await;
            Err(refused)
        }
    }
}

/// The checks that need the database, then the three writes. One transaction,
/// the caller's.
#[allow(clippy::too_many_arguments)]
async fn place(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    local: NaiveDateTime,
    zone: &str,
    name: &str,
    contact: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<(), Refused> {
    if !calendar::zone_is_real(tx, zone).await? {
        return Err(Refused::Slot);
    }
    // Postgres is the only tzdata this deployment has — see
    // `agentos_store::calendar`'s module docs. A wall time in a zone becomes
    // an instant here, where the CHECK on the row uses the same tables.
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT $1::timestamp AT TIME ZONE $2")
        .bind(local)
        .bind(zone)
        .fetch_one(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
    if at <= now || at > now + BOOKING_HORIZON {
        return Err(Refused::Slot);
    }
    let taken = calendar::upcoming(tx, employee)
        .await?
        .iter()
        .any(|promised| (promised.at - at).abs() < SLOT);
    if taken {
        return Err(Refused::Slot);
    }

    // The thread, the message, the promise. The message row is `land`'s
    // insert without the turn: the wake is the hour, not the arrival.
    let conversation =
        inbound::conversation_for(tx, employee, Channel::Web, contact, None, now).await?;
    let id = AppointmentId::new_v7(now);
    let provider_ref = ProviderRef::new(id.as_uuid().to_string());
    let key = CanonicalMessage::dedupe_key(employee, Channel::Web, &provider_ref);
    let message_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO messages \
             (id, tenant_id, conversation_id, employee_id, channel, direction, sender, \
              recipients, provider_message_id, body, attachments, trust_label, \
              idempotency_key, received_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, 'inbound', $6, '[]'::jsonb, $7, $8, '[]'::jsonb, \
                 'untrusted', $9, $10, $10)",
    )
    .bind(message_id)
    .bind(tx.tenant_id().as_uuid())
    .bind(conversation.as_uuid())
    .bind(employee.as_uuid())
    .bind(Channel::Web.as_str())
    // Third-party text into text columns: storage, not rendering. The sender
    // is spelled the way `inbound::contact_of` parses it back.
    .bind(format!("{name} <{contact}>"))
    .bind(provider_ref.as_str())
    .bind(reason)
    .bind(key.as_str())
    .bind(now)
    .execute(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    sqlx::query("UPDATE conversations SET last_message_at = $2, updated_at = $2 WHERE id = $1")
        .bind(conversation.as_uuid())
        .bind(now)
        .execute(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
    // `system`, as in `land`: nobody ruled on anything, and `routes::autonomy`
    // counts a landing against nobody's initiative.
    audit::append(
        tx,
        &AuditEvent {
            employee_id: Some(employee),
            conversation_id: Some(conversation),
            payload: json!({
                "channel": Channel::Web.as_str(),
                "message_id": message_id,
                "from": contact,
                "appointment": id.as_uuid(),
            }),
            ..AuditEvent::new(AuditActor::System, AuditKind::MessageReceived, now)
        },
    )
    .await?;
    calendar::book_on(
        tx,
        id,
        employee,
        at,
        zone,
        &subject(contact),
        Some(conversation),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DOMAIN: &str = "agents.example.com";
    const REASON: &str = "pricing for 40 seats, and the visa data question";

    struct Harness {
        db: Db,
        public: Router,
        api: Router,
        a: TenantId,
        b: TenantId,
        lena: EmployeeId,
        slug: String,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the booking page needs a real Postgres");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let (lena, slug) = new_employee(&db, a).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            Some(Self {
                public: public_router(db.clone()),
                api: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
                lena,
                slug,
            })
        }

        async fn get(&self, domain: &str, slug: &str) -> (StatusCode, String) {
            let req = HttpRequest::builder()
                .uri(format!("/book/{domain}/{slug}"))
                .body(Body::empty())
                .expect("request");
            read(self.public.clone().oneshot(req).await.expect("service")).await
        }

        async fn post(&self, slug: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
            let body: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("{k}={}", v.replace(' ', "+")))
                .collect();
            let req = HttpRequest::builder()
                .method("POST")
                .uri(format!("/book/{DOMAIN}/{slug}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.join("&")))
                .expect("request");
            read(self.public.clone().oneshot(req).await.expect("service")).await
        }

        async fn set_open(&self, secret: &str, open: bool) -> StatusCode {
            let req = HttpRequest::builder()
                .method("PUT")
                .uri(format!("/v1/employees/{}/booking", self.lena.as_uuid()))
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "open": open }).to_string()))
                .expect("request");
            self.api
                .clone()
                .oneshot(req)
                .await
                .expect("service")
                .status()
        }

        async fn diary(&self, tenant: TenantId) -> Vec<calendar::Appointment> {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tx");
            let all = calendar::upcoming(&mut tx, self.lena)
                .await
                .expect("upcoming");
            tx.rollback().await.expect("rollback");
            all
        }

        async fn scalar<T>(&self, tenant: TenantId, sql: &'static str) -> T
        where
            T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
        {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tx");
            let value = sqlx::query_scalar(sql)
                .bind(self.lena.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("scalar");
            tx.rollback().await.expect("rollback");
            value
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

    async fn read(response: Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'booking-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// An active seat with a domain in its spec, closed as every seat starts.
    async fn new_employee(db: &Db, tenant: TenantId) -> (EmployeeId, String) {
        let id = EmployeeId::new_v7(Utc::now());
        // The tail of a v7 uuid is random; its head is the millisecond, which
        // two tests in one process share — and `(domain, slug)` is the page's
        // whole key.
        let slug = format!("lena-{}", &id.as_uuid().simple().to_string()[24..]);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle, spec) \
             VALUES ($1, $2, $3, 'lena', 'active', $4)",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(&slug)
        .bind(json!({ "domain": DOMAIN }))
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        (id, slug)
    }

    /// `days` ahead, pushed to the next weekday, at `hour` o'clock local.
    fn slot(days: i64, hour: u32) -> String {
        let mut day = Utc::now().date_naive() + TimeDelta::days(days);
        // A past day stays where it is: a weekend in the past is refused too.
        while days >= 0 && day.weekday().number_from_monday() > 5 {
            day += TimeDelta::days(1);
        }
        format!("{day}T{hour:02}:00")
    }

    fn fields<'a>(at: &'a str, zone: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("name", "Paul Prospect"),
            ("email", "Paul@Prospect.example"),
            ("at", at),
            ("zone", zone),
            ("reason", REASON),
            ("website", ""),
        ]
    }

    /// **The door, end to end.** Closed and absent are one 404; the operator
    /// opens it; a form books a masked promise on the stranger's thread with
    /// the reason on the thread and nowhere else; every bad slot is one 422;
    /// a bot gets a 200 and writes nothing; the other company sees nothing.
    #[tokio::test]
    async fn a_stranger_books_an_hour_and_the_seat_is_woken_by_it() {
        let Some(h) = Harness::new().await else {
            return;
        };

        // --- Closed and unknown answer the same thing.
        let closed = h.get(DOMAIN, &h.slug).await;
        let unknown = h.get(DOMAIN, "nobody").await;
        assert_eq!(closed.0, StatusCode::NOT_FOUND, "{}", closed.1);
        assert_eq!(
            closed, unknown,
            "a closed seat must not read as an existing one"
        );
        let (status, _) = h.post(&h.slug, &fields(&slot(3, 10), "Europe/Paris")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "closed means closed to POST too"
        );

        // --- B cannot open A's seat; A can.
        assert_eq!(h.set_open(SECRET_B, true).await, StatusCode::NOT_FOUND);
        assert_eq!(h.get(DOMAIN, &h.slug).await.0, StatusCode::NOT_FOUND);
        assert_eq!(h.set_open(SECRET_A, true).await, StatusCode::OK);
        let (status, page) = h.get(DOMAIN, &h.slug).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("<form method=\"post\">"), "{page}");
        assert!(page.contains("datetime-local") && page.contains("Europe/Paris"));
        assert!(
            !page.contains("<script") && !page.contains("<link"),
            "{page}"
        );
        assert!(!page.contains(&h.slug), "the page does not echo the couple");

        // --- A valid form: one promise, one message, one masked subject.
        let when = slot(3, 10);
        let (status, page) = h.post(&h.slug, &fields(&when, "Europe/Paris")).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let diary = h.diary(h.a).await;
        assert_eq!(diary.len(), 1);
        let promised = &diary[0];
        assert_eq!(promised.subject, "booking · p…@prospect.example");
        assert!(
            !promised.subject.contains("pricing"),
            "the reason never reaches a subject"
        );
        assert_eq!(promised.zone, "Europe/Paris");
        assert_eq!(promised.local_time, when.replace('T', " "));
        let thread = promised
            .conversation_id
            .expect("the promise names the thread");
        let (channel, body, trust, sender): (String, String, String, String) = {
            let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
            let row = sqlx::query_as(
                "SELECT channel, body, trust_label, sender FROM messages \
                  WHERE conversation_id = $1 AND direction = 'inbound'",
            )
            .bind(thread.as_uuid())
            .fetch_one(&mut **tx)
            .await
            .expect("one inbound message");
            tx.rollback().await.expect("rollback");
            row
        };
        assert_eq!(
            (channel.as_str(), body.as_str(), trust.as_str()),
            ("web", REASON, "untrusted")
        );
        assert_eq!(sender, "Paul Prospect <paul@prospect.example>");

        // --- Landed, not acted: `system` in the trail, nothing in autonomy.
        let actors: Vec<(String, String)> = {
            let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
            let rows = audit::trail_for_employee(&mut tx, h.lena, 10)
                .await
                .expect("trail");
            tx.rollback().await.expect("rollback");
            rows.into_iter().map(|r| (r.action_kind, r.actor)).collect()
        };
        assert_eq!(
            actors,
            vec![("message_received".to_owned(), "system".to_owned())]
        );
        let taken: i64 = h
            .scalar(
                h.a,
                "SELECT coalesce(sum(actions_taken), 0)::bigint \
                   FROM employee_autonomy_daily WHERE employee_id = $1",
            )
            .await;
        assert_eq!(taken, 0, "a booking is nobody's action");

        // --- Every bad slot is the same sentence.
        for (at, zone, why) in [
            (when.clone(), "Europe/Paris".to_owned(), "already promised"),
            (slot(-1, 10), "Europe/Paris".to_owned(), "in the past"),
            (slot(40, 10), "Europe/Paris".to_owned(), "past the horizon"),
            (
                slot(4, 20),
                "Europe/Paris".to_owned(),
                "outside opening hours",
            ),
            (slot(4, 10), "Mars/Olympus_Mons".to_owned(), "no such zone"),
            (
                "not-a-date".to_owned(),
                "Europe/Paris".to_owned(),
                "not a date",
            ),
        ] {
            let (status, page) = h.post(&h.slug, &fields(&at, &zone)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{why}: {page}");
            assert!(page.contains("cannot be booked"), "{why}: {page}");
        }
        let (status, _) = h
            .post(
                &h.slug,
                &[
                    ("name", "x"),
                    ("email", "nope"),
                    ("at", &slot(4, 10)),
                    ("zone", "UTC"),
                    ("reason", "hi"),
                ],
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an address the inbound would refuse"
        );
        assert_eq!(h.diary(h.a).await.len(), 1, "none of those wrote anything");

        // --- The honeypot: a 200 a bot cannot tell apart, and no row.
        let later = slot(5, 11);
        let mut bot = fields(&later, "UTC");
        bot.retain(|(k, _)| *k != "website");
        bot.push(("website", "http://spam.example"));
        let (status, page) = h.post(&h.slug, &bot).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("Booked"), "{page}");
        assert_eq!(h.diary(h.a).await.len(), 1);

        // --- The other company: no promise, no thread, no message.
        assert!(h.diary(h.b).await.is_empty());
        let threads: i64 = h
            .scalar(
                h.b,
                "SELECT count(*) FROM conversations WHERE employee_id = $1",
            )
            .await;
        assert_eq!(threads, 0);

        // --- Closed again, and the door is gone.
        assert_eq!(h.set_open(SECRET_A, false).await, StatusCode::OK);
        assert_eq!(h.get(DOMAIN, &h.slug).await, closed);

        h.teardown().await;
    }

    /// The window: one seat, [`RATE_LIMIT`] submissions, then 429 — refused
    /// ones included, since a refusal costs the same lookup.
    #[tokio::test]
    async fn a_seat_takes_so_many_submissions_and_then_says_later() {
        let Some(h) = Harness::new().await else {
            return;
        };
        assert_eq!(h.set_open(SECRET_A, true).await, StatusCode::OK);
        let past = slot(-1, 10);
        for _ in 0..RATE_LIMIT {
            let (status, _) = h.post(&h.slug, &fields(&past, "UTC")).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        }
        let (status, _) = h.post(&h.slug, &fields(&past, "UTC")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(h.diary(h.a).await.is_empty());
        h.teardown().await;
    }

    #[test]
    fn the_subject_is_ours_and_masked() {
        assert_eq!(
            subject("paul@prospect.example"),
            "booking · p…@prospect.example"
        );
        assert!(subject(&"a".repeat(400)).chars().count() <= calendar::MAX_SUBJECT);
    }
}
