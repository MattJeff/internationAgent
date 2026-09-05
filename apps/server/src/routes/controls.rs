//! `GET /v1/controls`: what bounds each seat, and the stop button — one read.
//!
//! A customer at 5K$/month is afraid of two things: that it costs without a
//! limit, and that it cannot be stopped. Both were already answered — the gate
//! intersects four layers (`store::policy::load`), money is reserved before it
//! moves (`store::spend`), `/v1/halt` stops everything — but reading the answer
//! took six routes: `/v1/halt`, `/v1/employees/{id}/turns`,
//! `/v1/employees/{id}/spend-caps?currency=…` per currency, the role layer,
//! the team, the window. This is the same rows, on one page, with no new number
//! and no new write.
//!
//! Three things a reader gets that the six routes did not say together:
//!
//! * **which layer set each cap.** `load` takes the minimum of four layers and
//!   forgets which one it came from; `load_layers` is the same read with the
//!   last line left off, so this page can say `"set_by": "role"` — or, when
//!   several written layers hold the same number, `"tightest_of": [...]` and
//!   nothing invented. An inherited layer never appears: it did not set
//!   anything.
//! * **`acts_on_its_own`** in clear. `max_turns_per_day: 0` is the default and
//!   means "may not act until somebody says so" (README, § turn budget); a
//!   founder should not have to know that to read it.
//! * **the path to stop**, as a string to copy: `"stop": "POST /v1/halt"`.
//!
//! Every `levers[*].route` names a route mounted in `main.rs`, and the test
//! below mounts those routers and asks for each path, so a lever that stops
//! existing turns the test red rather than the page into a lie.

use std::collections::{BTreeMap, BTreeSet};

use agentos_domain::ids::EmployeeId;
use agentos_domain::message::Channel;
use agentos_domain::money::{Currency, Money};
use agentos_domain::policy::{PolicyLimits, SpendLimits, turns_remaining};
use agentos_store::db::{Db, StoreError};
use agentos_store::policy::{self, Layers};
use agentos_store::{halt, outreach, spend, turns};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use axum::{Json, Router};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/controls", get_route(get))
        .with_state(db)
}

const STOP: &str = "POST /v1/halt";
const RELEASE: &str = "DELETE /v1/halt";

/// Each limit on this page and the route that moves it. Read from the routers
/// in `main.rs`, not invented — `every_lever_is_a_mounted_route` checks.
const LEVERS: &[(&str, &str)] = &[
    ("halt", STOP),
    ("halt", RELEASE),
    ("window", "PUT /v1/window"),
    ("max_turns_per_day", "PUT /v1/policy/roles/{role}"),
    ("max_new_contacts_per_day", "PUT /v1/policy/roles/{role}"),
    ("allowed_channels", "PUT /v1/policy/roles/{role}"),
    ("spend_limits", "PUT /v1/policy/roles/{role}"),
    ("team.role", "PUT /v1/teams/{team_id}/policy-role"),
    ("spend_caps", "PUT /v1/employees/{id}/spend-caps"),
    ("lifecycle", "POST /v1/employees/{id}/suspend"),
    ("lifecycle", "POST /v1/employees/{id}/resume"),
];

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct HaltView {
    halted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    stop: &'static str,
    release: &'static str,
}

/// One effective limit and the written layer that holds it — or the layers
/// that tie for it. Exactly one of the two fields is present.
#[derive(Debug, Serialize)]
struct Bound<T> {
    value: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_by: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tightest_of: Option<Vec<&'static str>>,
}

fn bound<T: Clone + PartialEq>(
    layers: &Layers,
    effective: &T,
    pick: impl Fn(&PolicyLimits) -> &T,
) -> Bound<T> {
    let holders: Vec<&'static str> = layers
        .written()
        .filter(|(_, limits)| pick(limits) == effective)
        .map(|(layer, _)| layer.as_str())
        .collect();
    let value = effective.clone();
    match holders.as_slice() {
        [one] => Bound {
            value,
            set_by: Some(one),
            tightest_of: None,
        },
        // Empty for a set-valued cap is honest too: the intersection of two
        // partial overlaps is a set no single layer wrote.
        _ => Bound {
            value,
            set_by: None,
            tightest_of: Some(holders),
        },
    }
}

#[derive(Debug, Serialize)]
struct TeamView {
    id: Uuid,
    slug: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct SpendCapView {
    currency: Currency,
    daily_total: Option<Money>,
    per_transaction: Option<Money>,
    daily_transactions: Option<u32>,
    reserved_today_minor: u64,
}

#[derive(Debug, Serialize)]
struct SeatView {
    employee_id: Uuid,
    slug: String,
    display_name: String,
    lifecycle: String,
    team: Option<TeamView>,
    acts_on_its_own: bool,
    max_turns_per_day: Bound<u32>,
    turns_taken_today: u32,
    turns_remaining: u32,
    max_new_contacts_per_day: Bound<u32>,
    contacts_taken_today: u32,
    allowed_channels: Bound<BTreeSet<Channel>>,
    spend_limits: Bound<Option<SpendLimits>>,
    spend_caps: Vec<SpendCapView>,
}

#[derive(Debug, Default, Serialize)]
struct Totals {
    daily_total_minor: u64,
    reserved_today_minor: u64,
}

#[derive(Debug, Serialize)]
struct Lever {
    limit: &'static str,
    route: &'static str,
}

#[derive(Debug, Serialize)]
struct ControlsView {
    day: NaiveDate,
    halt: HaltView,
    window_ends_at: Option<DateTime<Utc>>,
    seats: Vec<SeatView>,
    totals: BTreeMap<Currency, Totals>,
    levers: Vec<Lever>,
}

// ---------------------------------------------------------------------------
// The queries — no `WHERE tenant_id`: RLS adds it on all three tables.
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct SeatRow {
    id: Uuid,
    slug: String,
    display_name: String,
    lifecycle: String,
    team_id: Option<Uuid>,
    team_slug: Option<String>,
    team_name: Option<String>,
}

const SEATS_SQL: &str = "\
SELECT e.id, e.slug, e.display_name, e.lifecycle, \
       t.id AS team_id, t.slug AS team_slug, t.name AS team_name \
  FROM employees e \
  LEFT JOIN team_memberships m ON m.employee_id = e.id \
  LEFT JOIN teams t ON t.id = m.team_id \
 ORDER BY e.id";

/// Every (seat, currency) that has a cap **or** has reserved something today —
/// `reports.rs` makes the same `UNION` for the same reason: either join alone
/// silently drops one of the two.
const HELD_SQL: &str = "\
WITH held AS ( \
        SELECT employee_id, currency FROM spend_caps \
  UNION SELECT employee_id, currency FROM spend_buckets WHERE day = $1) \
SELECT h.employee_id, h.currency, coalesce(b.reserved_minor, 0) AS reserved_minor \
  FROM held h \
  LEFT JOIN spend_buckets b \
    ON b.employee_id = h.employee_id AND b.currency = h.currency AND b.day = $1 \
 ORDER BY h.employee_id, h.currency";

fn opaque(employee_id: Uuid, what: &str, err: impl std::fmt::Display) -> ApiError {
    // The detail stays server-side, as on `/v1/employees/{id}/turns`: the
    // caller gets a code, the operator gets the row.
    tracing::error!(employee_id = %employee_id, error = %err, "{what}");
    ApiError::internal()
}

async fn get(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let day = Utc::now().date_naive();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    let halt = halt::halted(&mut tx).await?;
    let window_ends_at = halt::window(&mut tx).await?;
    let rows: Vec<SeatRow> = sqlx::query_as(SEATS_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    let held: Vec<(Uuid, String, i64)> = sqlx::query_as(HELD_SQL)
        .bind(day)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;

    let mut seats = Vec::with_capacity(rows.len());
    let mut totals: BTreeMap<Currency, Totals> = BTreeMap::new();
    for row in rows {
        let id = EmployeeId::from_uuid(row.id);
        let layers = policy::load_layers(&mut tx, id)
            .await
            .map_err(|err| opaque(row.id, "the stored policy could not be loaded", err))?;
        let effective = layers
            .effective()
            .map_err(|err| opaque(row.id, "the stored policy could not be loaded", err))?;
        let limits = effective.limits();
        let turns_taken = turns::taken_today(&mut tx, id, day).await?;
        let contacts_taken = outreach::taken_today(&mut tx, id, day).await?;

        let mut spend_caps = Vec::new();
        for (_, code, reserved) in held.iter().filter(|(who, _, _)| *who == row.id) {
            let currency: Currency = code
                .parse()
                .map_err(|err| opaque(row.id, "spend row in an unknown currency", err))?;
            let caps = spend::caps(&mut tx, id, currency).await?;
            let reserved = u64::try_from(*reserved).unwrap_or(0);
            let total = totals.entry(currency).or_default();
            total.reserved_today_minor = total.reserved_today_minor.saturating_add(reserved);
            total.daily_total_minor = total
                .daily_total_minor
                .saturating_add(caps.map_or(0, |c| c.daily_total().minor()));
            spend_caps.push(SpendCapView {
                currency,
                daily_total: caps.map(|c| c.daily_total()),
                per_transaction: caps.map(|c| c.per_transaction()),
                daily_transactions: caps.map(|c| c.daily_transactions().get()),
                reserved_today_minor: reserved,
            });
        }

        seats.push(SeatView {
            employee_id: row.id,
            slug: row.slug,
            display_name: row.display_name,
            lifecycle: row.lifecycle,
            team: match (row.team_id, row.team_slug, row.team_name) {
                (Some(id), Some(slug), Some(name)) => Some(TeamView { id, slug, name }),
                _ => None,
            },
            acts_on_its_own: limits.max_turns_per_day > 0,
            max_turns_per_day: bound(&layers, &limits.max_turns_per_day, |l| &l.max_turns_per_day),
            turns_taken_today: turns_taken,
            turns_remaining: turns_remaining(&effective, turns_taken),
            max_new_contacts_per_day: bound(&layers, &limits.max_new_contacts_per_day, |l| {
                &l.max_new_contacts_per_day
            }),
            contacts_taken_today: contacts_taken,
            allowed_channels: bound(&layers, &limits.allowed_channels, |l| &l.allowed_channels),
            spend_limits: bound(&layers, &limits.spend, |l| &l.spend),
            spend_caps,
        });
    }
    tx.rollback().await?;

    Ok(Json(ControlsView {
        day,
        halt: match halt {
            Some(h) => HaltView {
                halted: true,
                since: Some(h.halted_at),
                by: Some(h.halted_by),
                reason: Some(h.reason),
                stop: STOP,
                release: RELEASE,
            },
            None => HaltView {
                halted: false,
                since: None,
                by: None,
                reason: None,
                stop: STOP,
                release: RELEASE,
            },
        },
        window_ends_at,
        seats,
        totals,
        levers: LEVERS
            .iter()
            .map(|(limit, route)| Lever { limit, route })
            .collect(),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use agentos_domain::ids::{Slug, TenantId};
    use agentos_store::org;
    use agentos_store::policy::Scope;
    use agentos_store::spend::SpendCaps;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the controls route needs a real Postgres");
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

            // The routers every lever points at, so the levers test asks the
            // real thing and not a list.
            let routes = router(db.clone())
                .merge(super::super::halt::router(db.clone()))
                .merge(super::super::spend::router(db.clone()))
                .merge(super::super::teams::router(db.clone()))
                .merge(super::super::policy::router(db.clone()))
                .merge(super::super::employees::router(db.clone()));
            Some(Self {
                app: crate::with_api_stack(
                    routes,
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        async fn call(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header("idempotency-key", Uuid::now_v7().to_string());
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'controls-test')")
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

    fn limits(turns: u32, contacts: u32) -> PolicyLimits {
        PolicyLimits {
            max_turns_per_day: turns,
            max_new_contacts_per_day: contacts,
            ..PolicyLimits::default()
        }
    }

    /// Two seats. The tenant allows 10 turns and 20 contacts; the sales team's
    /// role layer squeezes turns to 3; Lena's own layer squeezes contacts to 4;
    /// Marc has a layer of his own that says 0 turns.
    struct Company {
        lena: Uuid,
        marc: Uuid,
        sales: Uuid,
    }

    async fn company(h: &Harness) -> Company {
        policy::install(&h.db, h.a, Scope::Tenant, &limits(10, 20))
            .await
            .expect("tenant layer");
        policy::install(&h.db, h.a, Scope::Role("sales"), &limits(3, 20))
            .await
            .expect("role layer");
        let lena = employee(&h.db, h.a, "lena").await;
        let marc = employee(&h.db, h.a, "marc").await;
        policy::install(
            &h.db,
            h.a,
            Scope::Employee(EmployeeId::from_uuid(lena)),
            &limits(10, 4),
        )
        .await
        .expect("lena's layer");
        policy::install(
            &h.db,
            h.a,
            Scope::Employee(EmployeeId::from_uuid(marc)),
            &limits(0, 20),
        )
        .await
        .expect("marc's layer");

        let mut tx = h.db.tenant_tx(h.a).await.expect("tx");
        let sales = org::create_team(&mut tx, &Slug::parse("sales").expect("slug"), "Sales")
            .await
            .expect("team");
        org::set_member(&mut tx, EmployeeId::from_uuid(lena), sales, None)
            .await
            .expect("member");
        org::set_policy_role(&mut tx, sales, "sales")
            .await
            .expect("policy role");
        spend::set_caps(
            &mut tx,
            EmployeeId::from_uuid(lena),
            SpendCaps::new(
                Money::new(50_00, Currency::Usd).expect("money"),
                Money::new(10_00, Currency::Usd).expect("money"),
                NonZeroU32::new(5).expect("non-zero"),
            )
            .expect("caps"),
        )
        .await
        .expect("set caps");
        tx.commit().await.expect("commit");
        Company { lena, marc, sales }
    }

    fn seat(body: &Value, id: Uuid) -> &Value {
        body["seats"]
            .as_array()
            .expect("seats")
            .iter()
            .find(|s| s["employee_id"] == json!(id))
            .expect("the seat is listed")
    }

    #[tokio::test]
    async fn each_cap_names_the_layer_that_set_it_and_zero_turns_is_said_in_clear() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let c = company(&h).await;

        let (status, body) = h.call("GET", "/v1/controls", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["halt"]["halted"], json!(false));
        assert_eq!(body["halt"]["stop"], json!("POST /v1/halt"));
        assert_eq!(body["seats"].as_array().expect("seats").len(), 2);

        let lena = seat(&body, c.lena);
        assert_eq!(lena["team"]["id"], json!(c.sales));
        assert_eq!(lena["acts_on_its_own"], json!(true));
        assert_eq!(lena["max_turns_per_day"]["value"], json!(3));
        assert_eq!(
            lena["max_turns_per_day"]["set_by"],
            json!("role"),
            "the sales layer is the only one saying 3: {lena}"
        );
        assert_eq!(lena["max_new_contacts_per_day"]["value"], json!(4));
        assert_eq!(
            lena["max_new_contacts_per_day"]["set_by"],
            json!("employee"),
            "{lena}"
        );
        assert_eq!(lena["turns_taken_today"], json!(0));
        assert_eq!(lena["turns_remaining"], json!(3));
        assert_eq!(lena["contacts_taken_today"], json!(0));
        assert_eq!(lena["spend_caps"][0]["currency"], json!("USD"));
        assert_eq!(lena["spend_caps"][0]["daily_total"]["minor"], json!(5000));
        assert_eq!(lena["spend_caps"][0]["reserved_today_minor"], json!(0));
        assert_eq!(body["totals"]["USD"]["daily_total_minor"], json!(5000));
        assert_eq!(body["totals"]["USD"]["reserved_today_minor"], json!(0));

        let marc = seat(&body, c.marc);
        assert_eq!(marc["team"], Value::Null);
        assert_eq!(marc["max_turns_per_day"]["value"], json!(0));
        assert_eq!(marc["max_turns_per_day"]["set_by"], json!("employee"));
        assert_eq!(marc["acts_on_its_own"], json!(false));
        // Nobody but the tenant and the platform wrote Marc's contact cap, and
        // the fixture writes the platform as the same number: a tie, named.
        assert_eq!(marc["max_new_contacts_per_day"]["value"], json!(20));
        assert!(
            marc["max_new_contacts_per_day"]["tightest_of"]
                .as_array()
                .is_some_and(|l| l.contains(&json!("tenant"))),
            "{marc}"
        );

        h.teardown().await;
    }

    #[tokio::test]
    async fn after_the_switch_the_page_says_stopped_by_whom_and_since_when() {
        let Some(h) = Harness::new().await else {
            return;
        };
        company(&h).await;

        let (status, _) = h
            .call(
                "POST",
                "/v1/halt",
                SECRET_A,
                Some(json!({"reason": "the CFO called"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = h.call("GET", "/v1/controls", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["halt"]["halted"], json!(true));
        assert_eq!(body["halt"]["by"], json!("operator:ops-a"));
        assert_eq!(body["halt"]["reason"], json!("the CFO called"));
        assert!(body["halt"]["since"].is_string(), "{body}");
        assert_eq!(body["halt"]["release"], json!("DELETE /v1/halt"));

        h.teardown().await;
    }

    /// Every route the page hands a founder is one the routers mount: a GET on
    /// it comes back as anything but "no such path".
    #[tokio::test]
    async fn every_lever_is_a_mounted_route() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let c = company(&h).await;

        let (_, body) = h.call("GET", "/v1/controls", SECRET_A, None).await;
        let levers = body["levers"].as_array().expect("levers");
        assert_eq!(levers.len(), LEVERS.len());
        for lever in levers {
            let route = lever["route"].as_str().expect("route");
            let (_, path) = route.split_once(' ').expect("METHOD /path");
            let path = path
                .replace("{id}", &c.lena.to_string())
                .replace("{team_id}", &c.sales.to_string())
                .replace("{role}", "sales");
            let (status, _) = h.call("GET", &path, SECRET_A, None).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{route} is on the page but not in the router"
            );
        }

        h.teardown().await;
    }

    #[tokio::test]
    async fn another_tenant_sees_none_of_it() {
        let Some(h) = Harness::new().await else {
            return;
        };
        company(&h).await;

        let (status, body) = h.call("GET", "/v1/controls", SECRET_B, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["seats"], json!([]));
        assert_eq!(body["totals"], json!({}));
        assert_eq!(body["halt"]["halted"], json!(false));

        h.teardown().await;
    }
}
