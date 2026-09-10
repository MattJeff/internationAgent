//! `GET /v1/outreach?days=N` : combien d'inconnus ont été approchés, et combien
//! ont répondu.
//!
//! # Pourquoi cette route existe alors que l'écran d'accueil affiche déjà des
//! compteurs
//!
//! Un fondateur paie 5 000 $/mois pour qu'une entreprise travaille, et le seul
//! chiffre qui lui dit si elle travaille est celui-là. Ce que les surfaces
//! existantes rendent est de l'administration : [`super::autonomy`] compte les
//! décisions et qui les a prises, [`super::pnl`] compte ce que chaque siège a
//! brûlé et encaissé, [`super::turns`] compte le budget du jour. Aucune ne dit
//! si quelqu'un a été approché. Les quatre nombres existaient déjà, chacun dans
//! sa table, et rien ne les mettait côte à côte.
//!
//! # D'où vient chaque nombre, et pourquoi celui-là
//!
//! ## `approached` — `outreach_buckets.contacts_taken`
//!
//! Il y avait deux sources possibles et elles ne disent pas la même chose.
//!
//! * `contacts.last_contacted_at`, écrite par `revenue::mark_contacted`, donc
//!   par `app::queue::record_queued`. C'est **une colonne mutable**, pas un
//!   événement : réécrire à la même personne demain efface son passage
//!   d'aujourd'hui. Une série par jour bâtie dessus se réécrit derrière le
//!   lecteur — le graphe de la semaine dernière change quand on relance
//!   quelqu'un ce matin. Inutilisable pour un historique.
//! * `outreach_buckets`, écrite par [`agentos_store::outreach::reserve`]. Une
//!   ligne par `(locataire, siège, jour)`, un entier qui ne redescend jamais —
//!   `0055_outreach_budget.sql` refuse le `DELETE` à `app_role` et il n'existe
//!   aucun verbe de libération. C'est le **goulot** des deux chemins
//!   d'approche : `app::gate` y réserve un inconnu à la fois sur le chemin
//!   d'envoi (`crates/app/src/gate.rs:1285`) et [`super::queue`] y réserve le
//!   fichier entier sur le chemin d'export (`routes/queue.rs:400`).
//!
//! Donc `outreach_buckets`, et le `day` est déjà une `date` UTC : aucune
//! conversion de fuseau ne s'interpose entre le compteur et le graphe.
//!
//! ## `replied` — un message entrant sur un fil, compté une fois par fil
//!
//! `messages.direction = 'inbound'` sur un canal tourné vers l'extérieur, groupé
//! par `conversation_id` : un fil qui écrit trois fois lundi est **une**
//! réponse, le jour de la première. C'est ce qui fait que `sum(by_day.replied)`
//! égale `replied`, ce qu'une console vérifie en premier.
//!
//! ## `booked` — la page de réservation, et elle seule
//!
//! `appointments` a trois écrivains et deux d'entre eux ne sont pas des
//! rendez-vous : `app::follow_up::schedule` y pose une *relance* et
//! `app::calendar` y pose ce que le siège veut. Le seul qui signifie « un
//! inconnu a pris une heure » est [`super::booking`], et il se reconnaît sans
//! ambiguïté : c'est le seul endroit du dépôt qui ouvre un fil
//! `Channel::Web`. La jointure sur `conversations.channel = 'web'` est ce
//! filtre, et pas une heuristique sur le sujet.
//!
//! ## `suppressed` — `suppressions`
//!
//! Table en ajout seul (`0011_revenue.sql`), une ligne par adresse retirée.
//! La vague précédente y a branché le désabonnement un clic
//! (`0085_un_desabonnement_est_une_adresse.sql`) et `inbound::land` y écrit un
//! « STOP » reçu.
//!
//! # `unmeasured`, qui n'est pas décoratif
//!
//! `crates/eval/src/cost.rs` pose la règle : ce dépôt ne publie pas un chiffre
//! sans dire ce qu'il ne couvre pas. Quatre nombres sortent d'ici et aucun n'est
//! ce que son nom laisse croire — `approached` compte des créneaux réservés et
//! non des envois partis, `replied` ne sait pas distinguer une réponse d'un
//! rebond. [`UNMEASURED`] le dit, une phrase par trou, dans le corps de la
//! réponse plutôt que dans une documentation que personne n'ouvre.
//!
//! # La fenêtre et le locataire
//!
//! `?days=N` est le sucre de [`PnlQuery`], repris tel quel plutôt que recopié :
//! le défaut (30 jours), le maximum (366) et le refus de `days=0` sont ceux de
//! [`super::autonomy`], et cette page se lit à côté de `/v1/pnl`. `to` est
//! **inclusif**, et `by_day` porte une ligne par jour de la fenêtre, zéros
//! compris — un trou dans un graphe est une information, pas une absence.
//!
//! Le locataire vient de [`Principal`]. Les cinq tables lues ont toutes RLS
//! `force` : il n'y a aucun `WHERE tenant_id`, et les chiffres d'une autre
//! entreprise ne sont pas filtrés, ils sont invisibles.

use std::collections::BTreeMap;

use agentos_store::db::{Db, StoreError};
use agentos_store::traces;
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use super::pnl::PnlQuery;
use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/outreach", get_route(get))
        .route("/v1/outreach/health", get_route(health))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct WindowView {
    /// Inclusif, UTC.
    from: NaiveDate,
    /// Inclusif, UTC.
    to: NaiveDate,
}

/// Un jour de la fenêtre. Présent même à zéro.
#[derive(Debug, Serialize)]
struct DayView {
    day: NaiveDate,
    approached: i64,
    replied: i64,
}

/// Ce que la route répond.
#[derive(Debug, Serialize)]
struct OutreachView {
    window: WindowView,
    /// Somme de `by_day[].approached`, par construction.
    approached: i64,
    /// Somme de `by_day[].replied`, par construction.
    replied: i64,
    booked: i64,
    suppressed: i64,
    /// Une ligne par jour de la fenêtre, du plus ancien au plus récent.
    by_day: Vec<DayView>,
    unmeasured: &'static [&'static str],
}

/// Ce que ces quatre nombres ne couvrent pas, une phrase par trou.
///
/// Chacune est un fait sur une table de ce dépôt, pas une précaution de style,
/// et chacune dit **dans quel sens** elle déplace le chiffre. Le motif est celui
/// de `agentos_eval::cost` : la liste se lit en bas de la réponse, là où le
/// lecteur arrive de toute façon.
const UNMEASURED: &[&str] = &[
    "approached compte des créneaux réservés, jamais rendus : un fichier exporté puis \
     jamais chargé chez le prestataire, ou un envoi que la plateforme refuse, reste compté. \
     C'est un majorant des personnes réellement écrites.",
    "Sur le chemin du fichier, une relance prend un créneau comme une première approche \
     (`revenue::queueable` sert tout contact dont `touch_count < 3`), alors que le chemin \
     d'envoi direct ne facture qu'un contact neuf. approached n'est donc pas un compte \
     d'inconnus dès qu'un export a tourné.",
    "replied ne distingue pas une vraie réponse d'une réponse automatique, d'un message \
     d'absence ou d'un avis de rebond qui atterrit dans la même boîte.",
    "replied compte les fils qui nous ont écrit, pas les fils qu'une approche a ouverts : \
     `conversations` n'a aucune colonne qui nomme l'approche, donc un fournisseur qui \
     répond à un appel d'offres est dedans.",
    "Une réponse à la liste que le fondateur charge à la main chez le prestataire \
     n'apparaît que si elle revient par un webhook que ce système ingère : rien de ce que \
     le prestataire envoie n'écrit de message sortant ici.",
    "Un fil compté une fois le jour de sa première réponse dans la fenêtre est compté à \
     nouveau dans la fenêtre suivante s'il réécrit.",
    "booked ne compte que les heures prises sur la page de réservation : une heure \
     convenue dans un fil et posée à l'agenda par le siège n'y est pas, et un rendez-vous \
     pris n'est pas un rendez-vous tenu — rien ici ne lit `appointments.rang_at`.",
    "suppressed compte les lignes que ce locataire a écrites : un rebond n'y figure que si \
     la liste du prestataire a été rapprochée (`queue::reconcile_opt_outs`), et le motif \
     (opt-out, plainte, rebond) n'est pas ventilé.",
];

// ---------------------------------------------------------------------------
// The queries
// ---------------------------------------------------------------------------
//
// Chaque requête : pas de `WHERE tenant_id` (RLS forcée), `$1` le premier jour,
// `$2` le lendemain du dernier, et le même seau de jour UTC que `pnl.rs` — la
// forme `(ts AT TIME ZONE 'UTC')::date` partout où la colonne est un instant.

/// Le compteur qu'aucun chemin d'approche ne contourne, et il est déjà par jour.
const APPROACHED_SQL: &str = "\
SELECT day, sum(contacts_taken)::bigint AS n \
  FROM outreach_buckets \
 WHERE day >= $1 AND day < $2 \
 GROUP BY day";

/// Un fil, une réponse, le jour de la première.
///
/// Les canaux sont ceux qui portent un tiers. `internal` est une conversation
/// entre deux de nos sièges et `a2a` est un agent qui appelle, ni l'un ni
/// l'autre n'est quelqu'un qui répond à une approche. `web` est tenu dehors
/// aussi : c'est la page de réservation, qui écrit un message entrant à chaque
/// prise d'heure, et ce serait compter le même acte dans `replied` et dans
/// `booked`.
const REPLIED_SQL: &str = "\
SELECT first_day AS day, count(*)::bigint AS n \
  FROM ( \
        SELECT conversation_id, \
               min((received_at AT TIME ZONE 'UTC')::date) AS first_day \
          FROM messages \
         WHERE direction = 'inbound' \
           AND channel IN ('email', 'sms', 'whatsapp', 'voice') \
           AND (received_at AT TIME ZONE 'UTC')::date >= $1 \
           AND (received_at AT TIME ZONE 'UTC')::date <  $2 \
         GROUP BY conversation_id \
       ) t \
 GROUP BY first_day";

/// Les heures prises sur la page de réservation, datées de la prise et non de
/// l'heure promise : la question est « qu'est-ce qui s'est passé cette
/// semaine », pas « qu'y a-t-il à l'agenda ».
const BOOKED_SQL: &str = "\
SELECT count(*)::bigint \
  FROM appointments a \
  JOIN conversations c ON c.id = a.conversation_id \
 WHERE c.channel = 'web' \
   AND (a.created_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (a.created_at AT TIME ZONE 'UTC')::date <  $2";

const SUPPRESSED_SQL: &str = "\
SELECT count(*)::bigint \
  FROM suppressions \
 WHERE (suppressed_at AT TIME ZONE 'UTC')::date >= $1 \
   AND (suppressed_at AT TIME ZONE 'UTC')::date <  $2";

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<PnlQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let window = query.resolve()?;
    let (from, end) = (window.from, window.end());

    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    let mut days: BTreeMap<NaiveDate, (i64, i64)> = BTreeMap::new();
    // Une ligne par jour, zéros compris, semée avant les requêtes : un trou dans
    // un graphe est une information et non un jour manquant.
    let mut day = from;
    while day < end {
        days.insert(day, (0, 0));
        day = day.checked_add_signed(Duration::days(1)).unwrap_or(end);
    }

    for (sql, first) in [(APPROACHED_SQL, true), (REPLIED_SQL, false)] {
        let rows: Vec<(NaiveDate, i64)> = sqlx::query_as(sql)
            .bind(from)
            .bind(end)
            .fetch_all(&mut **tx)
            .await
            .map_err(StoreError::from)?;
        for (day, n) in rows {
            // `or_default` plutôt qu'un `expect` : la fenêtre borne les deux
            // requêtes, mais un jour hors carte serait un zéro affiché et non
            // une panique en production.
            let slot = days.entry(day).or_default();
            let counter = if first { &mut slot.0 } else { &mut slot.1 };
            *counter = counter.saturating_add(n);
        }
    }

    let mut totals: [i64; 2] = [0, 0];
    for (sql, slot) in [(BOOKED_SQL, 0), (SUPPRESSED_SQL, 1)] {
        totals[slot] = sqlx::query_scalar(sql)
            .bind(from)
            .bind(end)
            .fetch_one(&mut **tx)
            .await
            .map_err(StoreError::from)?;
    }
    tx.commit().await?;

    let by_day: Vec<DayView> = days
        .into_iter()
        .map(|(day, (approached, replied))| DayView {
            day,
            approached,
            replied,
        })
        .collect();

    Ok(axum::Json(OutreachView {
        window: WindowView {
            from: window.from,
            to: window.to,
        },
        approached: by_day.iter().map(|d| d.approached).sum(),
        replied: by_day.iter().map(|d| d.replied).sum(),
        booked: totals[0],
        suppressed: totals[1],
        by_day,
        unmeasured: UNMEASURED,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// GET /v1/outreach/health — la santé du domaine d'envoi
// ---------------------------------------------------------------------------
//
// Six comptes depuis `now - days` et deux taux, lus par
// `agentos_store::traces::health` : envoyé, livré, ouvert, cliqué depuis
// `messages` et `message_events` (0091), rebondi et plainte depuis
// `suppressions` (0011). Les taux sont en **pour mille sur `sent`**, parce que
// c'est l'unité des seuils que Google et Yahoo publient pour un expéditeur en
// masse (0,3 % de plaintes = 3 ‰) et qu'un pourcentage à deux décimales se lit
// mal ; `0` quand rien n'est parti, jamais une division par zéro.
//
// `days` est un entier de jours et non la fenêtre de `PnlQuery` : ici la
// question est « depuis quand » sur des instants, pas « quels jours » sur des
// dates, et une borne à 365 suffit à un domaine — les traces de plus d'un an
// ne disent rien de sa réputation d'aujourd'hui.

/// `?days=N`, défaut [`HEALTH_DEFAULT_DAYS`], au plus [`HEALTH_MAX_DAYS`].
#[derive(Debug, Deserialize)]
struct HealthQuery {
    days: Option<i64>,
}

const HEALTH_DEFAULT_DAYS: i64 = 30;
const HEALTH_MAX_DAYS: i64 = 365;

#[derive(Debug, Serialize)]
struct HealthView {
    days: i64,
    sent: u32,
    delivered: u32,
    opened: u32,
    clicked: u32,
    bounced: u32,
    complained: u32,
    /// `complained * 1000 / sent`, deux décimales ; `0` si rien n'est parti.
    complaint_rate_per_mille: f64,
    /// `bounced * 1000 / sent`, deux décimales ; `0` si rien n'est parti.
    bounce_rate_per_mille: f64,
}

/// `n` pour mille de `sent`, arrondi à deux décimales.
fn per_mille(n: u32, sent: u32) -> f64 {
    match sent {
        0 => 0.0,
        sent => (f64::from(n) * 1000.0 / f64::from(sent) * 100.0).round() / 100.0,
    }
}

async fn health(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<HealthQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let days = query.days.unwrap_or(HEALTH_DEFAULT_DAYS);
    if !(1..=HEALTH_MAX_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!(
            "days: between 1 and {HEALTH_MAX_DAYS}"
        )));
    }
    let since = Utc::now() - Duration::days(days);

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let health = traces::health(&mut tx, since).await?;
    tx.commit().await?;

    Ok(axum::Json(HealthView {
        days,
        sent: health.sent,
        delivered: health.delivered,
        opened: health.opened,
        clicked: health.clicked,
        bounced: health.bounced,
        complained: health.complained,
        complaint_rate_per_mille: per_mille(health.complained, health.sent),
        bounce_rate_per_mille: per_mille(health.bounced, health.sent),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use chrono::{TimeZone, Utc};
    use serde_json::Value;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
        seat_a: EmployeeId,
        seat_b: EmployeeId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; these four numbers are a SQL question");
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

            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
                seat_a,
                seat_b,
            })
        }

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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'outreach-test')")
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

    /// Ce que `outreach::reserve` laisse derrière lui, écrit à la main pour
    /// pouvoir dater un jour passé — la fonction, elle, ne connaît qu'aujourd'hui.
    async fn approached(db: &Db, tenant: TenantId, seat: EmployeeId, day: NaiveDate, n: i32) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO outreach_buckets (tenant_id, employee_id, day, contacts_taken) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant.as_uuid())
        .bind(seat.as_uuid())
        .bind(day)
        .bind(n)
        .execute(&mut **tx)
        .await
        .expect("bucket");
        tx.commit().await.expect("commit");
    }

    /// Un fil ouvert sur un canal, rendu pour que les messages s'y accrochent.
    async fn thread(db: &Db, tenant: TenantId, seat: EmployeeId, channel: &str) -> Uuid {
        let id = Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO conversations (id, tenant_id, employee_id, channel) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(seat.as_uuid())
        .bind(channel)
        .execute(&mut **tx)
        .await
        .expect("conversation");
        tx.commit().await.expect("commit");
        id
    }

    async fn inbound(
        db: &Db,
        tenant: TenantId,
        seat: EmployeeId,
        conversation: Uuid,
        channel: &str,
        day: NaiveDate,
    ) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO messages \
                 (id, tenant_id, conversation_id, employee_id, channel, direction, sender, \
                  idempotency_key, received_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'inbound', 'stranger@example.com', $6, $7, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(conversation)
        .bind(seat.as_uuid())
        .bind(channel)
        .bind(Uuid::now_v7().to_string())
        .bind(noon(day))
        .execute(&mut **tx)
        .await
        .expect("message");
        tx.commit().await.expect("commit");
    }

    /// Une heure prise sur la page de réservation : l'`appointments` que
    /// `routes::booking` écrit, reconnaissable à son fil `web`.
    async fn booked(
        db: &Db,
        tenant: TenantId,
        seat: EmployeeId,
        conversation: Uuid,
        day: NaiveDate,
    ) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO appointments \
                 (id, tenant_id, employee_id, at, at_zone, subject, conversation_id, created_at) \
             VALUES ($1, $2, $3, $4, 'Europe/Paris', 'booking · s***@example.com', $5, $4)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(seat.as_uuid())
        .bind(noon(day))
        .bind(conversation)
        .execute(&mut **tx)
        .await
        .expect("appointment");
        tx.commit().await.expect("commit");
    }

    async fn suppressed(db: &Db, tenant: TenantId, address: &str, day: NaiveDate) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO suppressions \
                 (id, tenant_id, scope, channel, address, reason, suppressed_at) \
             VALUES ($1, $2, 'tenant', 'email', $3, 'opt_out', $4)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(address)
        .bind(noon(day))
        .execute(&mut **tx)
        .await
        .expect("suppression");
        tx.commit().await.expect("commit");
    }

    fn noon(day: NaiveDate) -> chrono::DateTime<Utc> {
        Utc.from_utc_datetime(&day.and_hms_opt(12, 0, 0).expect("noon"))
    }

    fn day_of(body: &Value, day: NaiveDate) -> (i64, i64) {
        let line = body["by_day"]
            .as_array()
            .unwrap_or_else(|| panic!("by_day in {body}"))
            .iter()
            .find(|line| line["day"] == Value::String(day.to_string()))
            .unwrap_or_else(|| panic!("{day} in {body}"));
        (
            line["approached"].as_i64().expect("approached"),
            line["replied"].as_i64().expect("replied"),
        )
    }

    /// **La fenêtre est inclusive aux deux bouts et `by_day` porte une ligne par
    /// jour, y compris les jours vides.**
    ///
    /// Un `?days=5` avec de l'activité au premier et au dernier jour seulement :
    /// si la borne haute était exclusive, le dernier jour disparaîtrait et le
    /// fondateur lirait « rien aujourd'hui » un matin où quinze inconnus ont été
    /// écrits. Si les jours creux étaient omis, le graphe se refermerait sur
    /// lui-même et deux jours d'arrêt ressembleraient à deux jours pleins.
    #[tokio::test]
    async fn la_fenetre_est_inclusive_et_by_day_a_une_ligne_par_jour_meme_vide() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let today = Utc::now().date_naive();
        let first = today - Duration::days(4);

        approached(&h.db, h.a, h.seat_a, first, 7).await;
        approached(&h.db, h.a, h.seat_a, today, 15).await;
        let fil = thread(&h.db, h.a, h.seat_a, "email").await;
        inbound(&h.db, h.a, h.seat_a, fil, "email", first).await;
        // Le même fil réécrit le dernier jour : une réponse, pas deux.
        inbound(&h.db, h.a, h.seat_a, fil, "email", today).await;

        let (status, body) = h.get("/v1/outreach?days=5", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        assert_eq!(body["window"]["from"], Value::String(first.to_string()));
        assert_eq!(body["window"]["to"], Value::String(today.to_string()));
        assert_eq!(
            body["by_day"].as_array().expect("by_day").len(),
            5,
            "une ligne par jour de la fenêtre, creux compris: {body}"
        );

        assert_eq!(day_of(&body, first), (7, 1), "le premier jour est dedans");
        assert_eq!(day_of(&body, today), (15, 0), "le dernier jour aussi");
        for gap in 1..=3 {
            assert_eq!(
                day_of(&body, first + Duration::days(gap)),
                (0, 0),
                "un jour creux est une ligne à zéro: {body}"
            );
        }

        // Les totaux sont la somme des lignes, sinon la console affiche deux
        // vérités sur le même écran.
        assert_eq!(body["approached"], Value::from(22));
        assert_eq!(body["replied"], Value::from(1));
        assert!(
            !body["unmeasured"]
                .as_array()
                .expect("unmeasured")
                .is_empty(),
            "aucun chiffre ne se publie ici sans ce qu'il ne mesure pas"
        );

        h.teardown().await;
    }

    /// **Un locataire ne voit que ses chiffres**, et sur les quatre à la fois.
    ///
    /// B travaille toute la semaine ; A n'a rien fait. A doit lire quatre zéros
    /// — pas les siens plus une partie de ceux de B, et pas une erreur non plus,
    /// qui serait déjà l'aveu que quelque chose existe à côté.
    #[tokio::test]
    async fn un_locataire_ne_voit_que_ses_chiffres() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let today = Utc::now().date_naive();

        approached(&h.db, h.b, h.seat_b, today, 11).await;
        let repondu = thread(&h.db, h.b, h.seat_b, "email").await;
        inbound(&h.db, h.b, h.seat_b, repondu, "email", today).await;
        let reserve = thread(&h.db, h.b, h.seat_b, "web").await;
        booked(&h.db, h.b, h.seat_b, reserve, today).await;
        suppressed(&h.db, h.b, "leaver@example.com", today).await;

        let (status, mine) = h.get("/v1/outreach?days=7", SECRET_B).await;
        assert_eq!(status, StatusCode::OK, "{mine}");
        assert_eq!(mine["approached"], Value::from(11));
        assert_eq!(mine["replied"], Value::from(1));
        assert_eq!(mine["booked"], Value::from(1));
        assert_eq!(mine["suppressed"], Value::from(1));

        let (status, theirs) = h.get("/v1/outreach?days=7", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{theirs}");
        for field in ["approached", "replied", "booked", "suppressed"] {
            assert_eq!(
                theirs[field],
                Value::from(0),
                "{field} du voisin visible: {theirs}"
            );
        }
        assert!(
            theirs["by_day"]
                .as_array()
                .expect("by_day")
                .iter()
                .all(|line| line["approached"] == 0 && line["replied"] == 0),
            "{theirs}"
        );

        h.teardown().await;
    }

    /// **`days` a un défaut, un maximum, et refuse zéro.**
    ///
    /// Le défaut est celui de `/v1/pnl` parce que les deux pages se lisent côte
    /// à côte. Zéro est refusé plutôt que rendu vide : une fenêtre sans jour
    /// répondrait « personne n'a été approché » à une question qui n'a pas été
    /// posée. Le maximum borne la table la plus grosse du déploiement.
    #[tokio::test]
    async fn days_a_un_defaut_un_maximum_et_refuse_zero() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.get("/v1/outreach", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["by_day"].as_array().expect("by_day").len(),
            30,
            "le défaut est celui de /v1/pnl: {body}"
        );

        let (status, body) = h.get("/v1/outreach?days=1", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["by_day"].as_array().expect("by_day").len(), 1);
        assert_eq!(body["window"]["from"], body["window"]["to"]);

        for refused in ["?days=0", "?days=-3", "?days=367"] {
            let (status, body) = h.get(&format!("/v1/outreach{refused}"), SECRET_A).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{refused} devrait être refusé: {body}"
            );
        }

        let (status, body) = h.get("/v1/outreach?days=366", SECRET_A).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "366 est le maximum, pas 365: {body}"
        );

        h.teardown().await;
    }

    /// **Ce que `replied` et `booked` refusent de compter.**
    ///
    /// Le fil interne entre deux sièges et l'appel d'agent à agent sont des
    /// messages entrants comme les autres dans `messages` ; ce ne sont pas des
    /// inconnus qui répondent. Et une promesse de relance posée par
    /// `app::follow_up` est une ligne d'`appointments` sans fil `web` : la
    /// compter ferait grimper `booked` chaque fois que l'entreprise se promet de
    /// relancer quelqu'un, c'est-à-dire à chaque envoi.
    #[tokio::test]
    async fn le_bruit_interne_n_est_ni_une_reponse_ni_un_rendez_vous() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let today = Utc::now().date_naive();

        for channel in ["internal", "a2a", "web"] {
            let fil = thread(&h.db, h.a, h.seat_a, channel).await;
            inbound(&h.db, h.a, h.seat_a, fil, channel, today).await;
        }
        // Une relance promise sur un fil e-mail : `appointments`, sans `web`.
        let relance = thread(&h.db, h.a, h.seat_a, "email").await;
        booked(&h.db, h.a, h.seat_a, relance, today).await;

        let (status, body) = h.get("/v1/outreach?days=2", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["replied"], Value::from(0), "{body}");
        assert_eq!(body["booked"], Value::from(0), "{body}");

        h.teardown().await;
    }

    /// Un mail sortant e-mail, comme `follow_up::sent` l'écrit, daté d'un jour.
    async fn outbound(
        db: &Db,
        tenant: TenantId,
        seat: EmployeeId,
        conversation: Uuid,
        provider_message_id: &str,
        day: NaiveDate,
    ) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO messages \
                 (id, tenant_id, conversation_id, employee_id, channel, direction, sender, \
                  provider_message_id, trust_label, idempotency_key, received_at, created_at) \
             VALUES ($1, $2, $3, $4, 'email', 'outbound', '', $5, 'trusted', $6, $7, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(conversation)
        .bind(seat.as_uuid())
        .bind(provider_message_id)
        .bind(format!("sent:{provider_message_id}"))
        .bind(noon(day))
        .execute(&mut **tx)
        .await
        .expect("message");
        tx.commit().await.expect("commit");
    }

    /// **`/v1/outreach/health` : six comptes, deux taux en pour mille, et le
    /// locataire d'à côté lit des zéros.** `days` a un défaut, un maximum de
    /// 365 et refuse zéro — les deux bornes vérifiées mordantes le 2026-09-10
    /// (`HEALTH_MAX_DAYS = 366` fait passer `?days=366` et rougit le test).
    #[tokio::test]
    async fn la_sante_du_domaine_compte_et_taux_en_pour_mille() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let today = Utc::now().date_naive();
        let fil = thread(&h.db, h.a, h.seat_a, "email").await;
        // Quatre envoyés, dont un hors fenêtre de 7 jours.
        for (id, day) in [
            ("h_1", today),
            ("h_2", today),
            ("h_3", today),
            ("h_old", today - Duration::days(40)),
        ] {
            outbound(&h.db, h.a, h.seat_a, fil, id, day).await;
        }
        {
            let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
            for (kind, id, event) in [
                ("delivered", "h_1", "e1"),
                ("delivered", "h_2", "e2"),
                ("opened", "h_1", "e3"),
                ("clicked", "h_1", "e4"),
            ] {
                let signal = traces::Signal {
                    kind,
                    provider_message_id: id,
                    link: (kind == "clicked").then_some("https://x.example"),
                    occurred_at: noon(today),
                };
                assert!(
                    traces::record(&mut tx, "resend", signal, event)
                        .await
                        .expect("record")
                );
            }
            tx.commit().await.expect("commit");
        }
        // Un rebond permanent et une plainte, comme `inbound::record_refusal`
        // les écrit ; un opt-out, qui n'est ni l'un ni l'autre.
        {
            let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
            for (address, reason) in [
                ("bounced@x.example", "bounce"),
                ("angry@x.example", "complaint"),
                ("gone@x.example", "opt_out"),
            ] {
                sqlx::query(
                    "INSERT INTO suppressions \
                         (id, tenant_id, scope, channel, address, reason, suppressed_at) \
                     VALUES ($1, $2, 'tenant', 'email', $3, $4, $5)",
                )
                .bind(Uuid::now_v7())
                .bind(h.a.as_uuid())
                .bind(address)
                .bind(reason)
                .bind(noon(today))
                .execute(&mut **tx)
                .await
                .expect("suppression");
            }
            tx.commit().await.expect("commit");
        }

        let (status, body) = h.get("/v1/outreach/health?days=7", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["days"], Value::from(7));
        assert_eq!(body["sent"], Value::from(3), "{body}");
        assert_eq!(body["delivered"], Value::from(2), "{body}");
        assert_eq!(body["opened"], Value::from(1), "{body}");
        assert_eq!(body["clicked"], Value::from(1), "{body}");
        assert_eq!(body["bounced"], Value::from(1), "{body}");
        assert_eq!(body["complained"], Value::from(1), "{body}");
        assert_eq!(
            body["complaint_rate_per_mille"],
            Value::from(333.33),
            "{body}"
        );
        assert_eq!(body["bounce_rate_per_mille"], Value::from(333.33), "{body}");

        // Le défaut et les bornes.
        let (status, body) = h.get("/v1/outreach/health", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["days"], Value::from(30));
        assert_eq!(body["sent"], Value::from(3), "{body}");
        let (status, body) = h.get("/v1/outreach/health?days=365", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["sent"], Value::from(4), "{body}");
        for refused in ["?days=0", "?days=-1", "?days=366", "?days=x"] {
            let (status, body) = h
                .get(&format!("/v1/outreach/health{refused}"), SECRET_A)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}: {body}");
        }

        // Le voisin lit des zéros, et des taux à zéro sans division.
        let (status, body) = h.get("/v1/outreach/health?days=7", SECRET_B).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["sent"], Value::from(0), "{body}");
        assert_eq!(body["complaint_rate_per_mille"], Value::from(0.0), "{body}");

        h.teardown().await;
    }

    /// Les deux taux, sur des comptes posés à la main : 1 plainte et 2 rebonds
    /// sur 8 envoyés font 125 ‰ et 250 ‰ ; 1 sur 3 arrondit à 333,33.
    #[test]
    fn les_taux_sont_en_pour_mille_sur_les_envoyes() {
        assert_eq!(per_mille(1, 8), 125.0);
        assert_eq!(per_mille(2, 8), 250.0);
        assert_eq!(per_mille(1, 3), 333.33);
        assert_eq!(per_mille(0, 3), 0.0);
        assert_eq!(per_mille(3, 0), 0.0, "rien de parti : zéro, pas NaN");
    }
}
