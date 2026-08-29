//! `/v1/employees/{id}/initiative`: what an employee does when nobody has
//! written to it, and how often.
//!
//! Two verbs and one resource. `PUT` says "this is your objective and this is
//! how often you work on it"; `GET` answers the three questions an operator
//! actually has — is it working, when does it next act, and if it is not
//! working, what does it need from me.
//!
//! The two halves land in two tables and that is not an accident:
//! `employee_charters` is *what* the employee was hired to do and
//! `employee_initiative` is *when* it acts on it. An employee can be chartered
//! and unscheduled, which is every employee that answers its mail and starts
//! nothing on its own. This endpoint is the one place that writes both, because
//! an operator setting an employee going means both at once.
//!
//! # A cadence outside the bounds is refused, never clamped
//!
//! [`Cadence::every`] has a floor of five minutes and a ceiling of thirty days.
//! An operator who sends `interval_secs: 1` has made a mistake that costs money
//! every second until somebody notices, and one who sends a year has made an
//! employee that looks like it works and does not. Clamping either answers 200
//! to a request that did not happen: the row would say five minutes and the
//! operator would believe it said one second. So both are a 400 carrying the
//! reason, the floor and the ceiling, and nothing is written.
//!
//! # The objective is re-parsed, not deserialised
//!
//! Every field goes through the constructor it belongs to —
//! [`CountryCode::parse`], [`Money::new`], the [`Segment`] table — so a country
//! called `"Germany"` or a price of zero is a 400 that names the field rather
//! than a row nobody can plan from. That is the same rule
//! [`Charter::load`](agentos_app::vertical::Charter) follows reading the column
//! back, and for the same reason: a derived `Deserialize` walks straight past
//! the validation those types exist to do.
//!
//! # The plan is rendered, not stored
//!
//! `GET` recomputes the role pack's plan from the stored objective every time.
//! It is pure and cheap, and it is the fastest way for an operator to find out
//! that the objective they just set has a hole in it — the response says
//! `clarify` and asks the question, in the same round trip, instead of the
//! operator discovering it a cadence later.

use std::time::Duration;

use agentos_app::rolepack::{self, CountryCode};
use agentos_app::rolepack_sales::{self, Segment};
use agentos_app::rolepack_service;
use agentos_app::vertical::Charter;
use agentos_domain::employee::Lifecycle;
use agentos_domain::ids::{EmployeeId, Slug};
use agentos_domain::initiative::{Cadence, MAX_INTERVAL, MIN_INTERVAL};
use agentos_domain::money::{Currency, Money};
use agentos_store::db::Db;
use agentos_store::initiative::{self, Schedule};
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::loops::initiative::plan_of;

/// This unit's routes. Merged into the API router, so it inherits auth, the rate
/// limit and the idempotency layer from `with_api_stack`.
pub fn router(db: Db) -> Router {
    Router::new()
        .route(
            "/v1/employees/{id}/initiative",
            get_route(get).put(set_initiative),
        )
        .with_state(db)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The `PUT` body.
///
/// **A replacement, not a patch.** Both fields are required, because the two
/// halves only mean anything together: a cadence without an objective is an
/// employee that wakes up with nothing to do, and an objective without a cadence
/// is one that never wakes up. `deny_unknown_fields` so a client that misspells
/// `interval_secs` finds out now rather than wondering why nothing changed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetInitiative {
    /// How often the employee acts on its own, in seconds.
    interval_secs: u64,
    /// What it is acting on. Tagged by `role`.
    objective: ObjectiveBody,
}

/// The objective, tagged by role.
///
/// No two roles' objectives share a field — one is a purchase, one a sales
/// beat, one a support queue, one a content brief, one a period close, one a
/// repository — so this is a tagged union rather than a struct where most
/// columns are null for any given employee. The tags are the role packs' own `name()`s,
/// and they have to stay that way: `Charter::role` writes one of these strings
/// into `employee_charters.role` and `Charter::of` reads it back.
///
/// Every value here is still a `String` or a number: turning them into
/// [`CountryCode`], [`Money`], [`Currency`] and [`Segment`] is
/// [`ObjectiveBody::into_charter`]'s job, and it is where a bad one becomes a
/// 400 that names itself.
#[derive(Debug, Deserialize)]
#[serde(tag = "role", deny_unknown_fields)]
pub(crate) enum ObjectiveBody {
    #[serde(rename = "international-buyer")]
    Purchasing {
        /// Everything defaults, because an operator really can say "a few
        /// thousand of those, cheap" — and the answer to that is a question, not
        /// a rejection. `gaps()` is what turns the holes into the question, and
        /// it can only do that if the incomplete objective is storable.
        #[serde(default)]
        what: String,
        #[serde(default)]
        quantity: u32,
        #[serde(default)]
        max_unit_price: Option<PriceBody>,
        #[serde(default)]
        delivery_country: Option<String>,
        #[serde(default)]
        requirements: Vec<String>,
    },
    #[serde(rename = "sales-development")]
    Sales {
        /// Not optional: the segment is a closed enum and decides what being
        /// wrong costs the prospect, which is the whole of the sales argument.
        segment: String,
        #[serde(default)]
        market: Option<String>,
        #[serde(default)]
        target_accounts: Vec<String>,
    },
    #[serde(rename = "customer-success")]
    Support {
        #[serde(default)]
        product: String,
        #[serde(default)]
        first_response_hours: u32,
        /// Who a ticket goes to when it stops being this employee's. Optional
        /// here and a `Gap` there: an operator who has not decided yet gets the
        /// question back, not a rejection.
        #[serde(default)]
        escalate_to: Option<String>,
    },
    #[serde(rename = "growth")]
    Growth {
        #[serde(default)]
        topic: String,
        #[serde(default)]
        market: Option<String>,
        #[serde(default)]
        measure: Option<String>,
    },
    #[serde(rename = "finance")]
    Finance {
        #[serde(default)]
        period: String,
        /// An ISO-4217 code. Parsed through [`Currency`] itself, so `"dollars"`
        /// is a 400 naming the field rather than a period nobody can
        /// denominate.
        #[serde(default)]
        currency: Option<String>,
        #[serde(default)]
        obligations: Vec<String>,
    },
    #[serde(rename = "entry-requirements")]
    EntryRequirements {
        #[serde(default)]
        destinations: String,
        #[serde(default)]
        passports: Vec<String>,
        /// How stale a rule may get before it is due, in days. `u32` and not
        /// `Option<u32>` to match `Support::first_response_hours`: zero is the
        /// value that means nobody said, and it is a `Gap` rather than a 400,
        /// because an operator who has not picked a freshness bar gets the
        /// question back and not a rejection.
        #[serde(default)]
        max_age_days: u32,
    },
    #[serde(rename = "engineering")]
    Engineering {
        #[serde(default)]
        repository: String,
        /// The command that proves a change works. Optional here and a `Gap`
        /// there, for `escalate_to`'s reason: an operator who has not decided
        /// gets the question back, not a rejection. There is no `country()` and
        /// no other parse on any field of this variant — the argument is on
        /// `rolepack_service::Changes`, and it is `Corridors`' argument.
        #[serde(default)]
        checks: Option<String>,
        #[serde(default)]
        reviewer: Option<String>,
    },
    #[serde(rename = "managing")]
    Managing {
        /// What the team exists to get done. Empty here and a `Gap` there, like
        /// every other role's headline field.
        #[serde(default)]
        mission: String,
        /// Which role each direct report is meant to hold, by slug. Empty is
        /// the default and a legitimate answer — see `rolepack_service::Seats`
        /// for why this is the one headline field that is *not* a gap.
        ///
        /// A plain `BTreeMap<String, String>` on the wire and parsed through
        /// `Slug` and `Charter::vacant` below, which is this enum's own rule:
        /// every value here is a string until `into_charter` turns it into the
        /// type that validates it.
        #[serde(default)]
        seats: std::collections::BTreeMap<String, String>,
    },
}

/// Minor units and an ISO-4217 code — the shape `Money` serialises as, so what
/// comes back out of `GET` is what goes into `PUT`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PriceBody {
    minor: u64,
    currency: String,
}

impl ObjectiveBody {
    /// Every value, through the constructor it belongs to.
    ///
    /// `pub(crate)` for `routes::interview`, which reads a *model's* proposal
    /// through this exact function rather than growing a second one. That reuse
    /// is the whole security property there: a value the interview writes is a
    /// value an operator could have typed into `PUT` by hand, because it came in
    /// through the same deserialiser and the same `CountryCode::parse`,
    /// `Money::new`, `Currency` and `Segment`.
    pub(crate) fn into_charter(self) -> Result<Charter, ApiError> {
        match self {
            ObjectiveBody::Purchasing {
                what,
                quantity,
                max_unit_price,
                delivery_country,
                requirements,
            } => Ok(Charter::Purchasing {
                pack: rolepack::RolePack::international_buyer(),
                objective: rolepack::Objective {
                    what,
                    quantity,
                    max_unit_price: max_unit_price.map(PriceBody::into_money).transpose()?,
                    delivery_country: country("delivery_country", delivery_country)?,
                    requirements,
                },
            }),
            ObjectiveBody::Sales {
                segment,
                market,
                target_accounts,
            } => Ok(Charter::Sales {
                pack: rolepack_sales::RolePack::sales_development(),
                objective: rolepack_sales::Objective {
                    segment: parse_segment(&segment)?,
                    market: country("market", market)?,
                    target_accounts,
                },
            }),
            ObjectiveBody::Support {
                product,
                first_response_hours,
                escalate_to,
            } => Ok(Charter::Support {
                objective: rolepack_service::Support {
                    product,
                    first_response_hours,
                    escalate_to,
                },
            }),
            ObjectiveBody::Growth {
                topic,
                market,
                measure,
            } => Ok(Charter::Growth {
                objective: rolepack_service::Growth {
                    topic,
                    market: country("market", market)?,
                    measure,
                },
            }),
            ObjectiveBody::Finance {
                period,
                currency,
                obligations,
            } => Ok(Charter::Finance {
                objective: rolepack_service::Books {
                    period,
                    currency: parse_currency(currency)?,
                    obligations,
                },
            }),
            // No `country()` on either field, unlike every other objective with
            // a place in it: `Corridors` is prose by construction, because the
            // visa tools take ISO-3166 alpha-3 and `CountryCode` is alpha-2, and
            // because "the Schengen area" is a real answer to "which
            // destinations". The argument is on the type.
            ObjectiveBody::EntryRequirements {
                destinations,
                passports,
                max_age_days,
            } => Ok(Charter::EntryRequirements {
                objective: rolepack_service::Corridors {
                    destinations,
                    passports,
                    max_age_days,
                },
            }),
            ObjectiveBody::Engineering {
                repository,
                checks,
                reviewer,
            } => Ok(Charter::Engineering {
                objective: rolepack_service::Changes {
                    repository,
                    checks,
                    reviewer,
                },
            }),
            ObjectiveBody::Managing { mission, seats } => {
                let mut table = std::collections::BTreeMap::new();
                for (report, role) in seats {
                    let slug = Slug::parse(&report).map_err(|err| {
                        ApiError::bad_request(format!("seats: {report:?} is not a slug ({err})"))
                    })?;
                    // The same refusal `vertical::seats_objective` makes when
                    // the row is read back, here so an operator learns it while
                    // they are watching rather than from a manager's turn that
                    // quietly skipped a seat. Purchasing and sales are the two
                    // that cannot be created empty — `Charter::vacant` says why.
                    if Charter::vacant(&role).is_none() {
                        return Err(ApiError::bad_request(format!(
                            "seats: {role:?} is not a role a manager can create an empty seat                              for; charter that employee directly"
                        )));
                    }
                    table.insert(slug, role);
                }
                Ok(Charter::Managing {
                    objective: rolepack_service::Seats {
                        mission,
                        seats: table,
                    },
                })
            }
        }
    }
}

impl PriceBody {
    fn into_money(self) -> Result<Money, ApiError> {
        // `Currency` is `Deserialize` with an uppercase rename, which is the one
        // place its spelling lives; going through it keeps this from becoming a
        // second list of currency codes.
        let currency: Currency = serde_json::from_value(json!(self.currency.to_uppercase()))
            .map_err(|_| field("max_unit_price.currency", "not an ISO-4217 code we support"))?;
        Money::new(self.minor, currency)
            .map_err(|err| field("max_unit_price.minor", err.to_string()))
    }
}

/// An ISO-4217 code, through [`Currency`]'s own `FromStr` — the one place its
/// spelling lives, exactly as [`PriceBody::into_money`] goes through its
/// `Deserialize` rather than growing a second list of codes.
fn parse_currency(raw: Option<String>) -> Result<Option<Currency>, ApiError> {
    raw.map(|raw| {
        raw.to_uppercase()
            .parse::<Currency>()
            .map_err(|_| field("currency", "not an ISO-4217 code we support"))
    })
    .transpose()
}

fn country(name: &'static str, raw: Option<String>) -> Result<Option<CountryCode>, ApiError> {
    raw.map(|raw| CountryCode::parse(&raw))
        .transpose()
        .map_err(|err| field(name, err.to_string()))
}

/// Matched against `Segment::ALL` rather than a second copy of the five names,
/// so a sixth segment cannot be added without this finding it.
fn parse_segment(raw: &str) -> Result<Segment, ApiError> {
    Segment::ALL
        .into_iter()
        .find(|segment| segment.code() == raw)
        .ok_or_else(|| {
            field(
                "segment",
                format!(
                    "unknown segment; expected one of {}",
                    Segment::ALL
                        .iter()
                        .map(|s| s.code())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })
}

/// A 400 that names the field the caller got wrong. Only ever built from input
/// the caller controls — see `error.rs` on why `detail` is never server-side.
fn field(name: &str, why: impl Into<String>) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "objective_field",
        "that objective cannot be read",
    )
    .with_detail(format!("{name}: {}", why.into()))
}

/// One step of the recomputed plan.
#[derive(Debug, Serialize)]
struct TaskView {
    /// Where in the role's sequence this sits: `discover`, `rfq`, `approach`, …
    stage: &'static str,
    /// What to do. Ours, built from the operator's own objective.
    instruction: String,
}

/// An employee's initiative, as the API renders it.
#[derive(Debug, Serialize)]
struct InitiativeView {
    employee_id: Uuid,
    /// Flattened, so the cadence renders as the domain type serialises it:
    /// `"interval_secs": 3600`. One spelling, not two.
    #[serde(flatten)]
    cadence: Cadence,
    /// When it may next act. Already includes the jitter that keeps employees
    /// scheduled together from staying in lockstep.
    next_at: DateTime<Utc>,
    /// `due`, `not_yet` or `barred` — the domain's own answer to "may this
    /// employee act right now", evaluated against this instant.
    status: &'static str,
    /// Why it is barred, when it is. `barred` always means this is not `active`.
    lifecycle: Lifecycle,
    /// When it was last taken up, and how many times. Claims, not turns: a
    /// worker killed mid-turn still counts here, which is what makes the pair
    /// below readable.
    last_claimed_at: Option<DateTime<Utc>>,
    claims: i64,
    /// What the poller decided about **the beat `last_claimed_at` names**:
    /// `turn`, `clarify`, `no_charter`, `unreadable_charter`, `no_model`,
    /// `no_work`, `over_budget`, `error`.
    ///
    /// `null` with `claims: 0` is an employee that has never acted. **`null`
    /// with `claims` above zero is a beat that produced nothing** — running
    /// right now, or gone with the worker that took it, told apart by how long
    /// ago `last_claimed_at` was. It is never the beat before this one: the
    /// claim clears these two columns, and `agentos_store::initiative::claim_due`
    /// carries the argument.
    ///
    /// This used to read "a `claims` that climbs while `last_outcome` stays put
    /// is something dying", and that sentence needed two reads a cadence apart
    /// to say anything at all — while `no_charter` legitimately stays put
    /// forever. One read answers it now.
    last_outcome: Option<String>,
    /// The detail behind it — for `clarify`, the question waiting on an answer.
    /// Cleared with the code, so it never explains an outcome that is gone.
    last_detail: Option<String>,
    /// Which role's objective this employee carries, if any.
    role: Option<&'static str>,
    /// The plan, recomputed now. `None` when there is no charter or it cannot be
    /// worked as stated — in which case `clarify` says what is missing.
    plan: Option<Vec<TaskView>>,
    /// The question this objective needs answered before any plan exists.
    clarify: Option<String>,
}

impl InitiativeView {
    fn of(schedule: &Schedule, charter: Option<&Charter>, now: DateTime<Utc>) -> Self {
        let mut view = Self {
            employee_id: schedule.employee_id.as_uuid(),
            cadence: schedule.cadence,
            next_at: schedule.next_at,
            status: schedule.initiative(now).code(),
            lifecycle: schedule.lifecycle,
            last_claimed_at: schedule.last_claimed_at,
            claims: schedule.claims,
            last_outcome: schedule.last_outcome.clone(),
            last_detail: schedule.last_detail.clone(),
            role: charter.map(Charter::role),
            plan: None,
            clarify: None,
        };

        // The same answer the poller acts on, from the same function — two
        // copies of "is this objective workable" would be two copies that
        // disagree, and the operator would be reading the one that is wrong.
        if let Some(charter) = charter {
            match plan_of(charter) {
                Ok(tasks) => {
                    view.plan = Some(
                        tasks
                            .into_iter()
                            .map(|(stage, instruction)| TaskView { stage, instruction })
                            .collect(),
                    );
                }
                Err(question) => view.clarify = Some(question),
            }
        }
        view
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `PUT /v1/employees/{id}/initiative` — set the cadence and the objective.
///
/// One transaction: the charter and the schedule land together, so an employee
/// can never be woken up on a cadence for an objective that was rolled back.
///
/// Setting a cadence **moves the next deadline** to one interval from now. An
/// operator who shortens a cadence means sooner, and a deadline left where it
/// was would keep them waiting out the old interval to find out it worked.
async fn set_initiative(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
    body: Result<Json<SetInitiative>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    // Refused, not clamped. See the module docs.
    let cadence = Cadence::every(Duration::from_secs(body.interval_secs)).map_err(|err| {
        tracing::info!(%id, interval_secs = body.interval_secs, code = err.code(), "cadence refused");
        ApiError::new(
            StatusCode::BAD_REQUEST,
            err.code(),
            "the cadence is outside the platform's floor and ceiling",
        )
        .with_detail(err.to_string())
        .with_extension("min_interval_secs", json!(MIN_INTERVAL.as_secs()))
        .with_extension("max_interval_secs", json!(MAX_INTERVAL.as_secs()))
    })?;
    let charter = body.objective.into_charter()?;

    let now = Utc::now();
    let employee_id = EmployeeId::from_uuid(id);
    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    // **The schedule first, and the order is load-bearing.** `initiative::set`
    // selects the employee under RLS, so an id this tenant cannot see is a
    // `NotFound` — a 404, never a 403. `Charter::save` cannot make that check:
    // its foreign key to `employees` is verified by Postgres as the table owner,
    // which RLS does not apply to, so on its own it would happily file a charter
    // against another tenant's employee. Running it second means the 404 has
    // already aborted the transaction.
    initiative::set(&mut tx, employee_id, cadence, now).await?;
    charter
        .save(&mut tx, employee_id, now)
        .await
        .map_err(|err| {
            tracing::error!(%id, code = err.code(), error = %err, "could not save the charter");
            ApiError::internal()
        })?;
    let schedule = initiative::get(&mut tx, employee_id).await?;
    tx.commit().await?;

    tracing::info!(
        %id,
        tenant_id = %principal.tenant_id,
        interval_secs = cadence.interval().as_secs(),
        role = charter.role(),
        "initiative set"
    );
    Ok(Json(InitiativeView::of(&schedule, Some(&charter), now)).into_response())
}

/// `GET /v1/employees/{id}/initiative` — the cadence, the next deadline, what
/// happened last time, and the plan as it stands right now.
///
/// 404 when the employee has no initiative set, does not exist, or belongs to
/// another tenant. Those are indistinguishable on purpose.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let employee_id = EmployeeId::from_uuid(id);
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let schedule = initiative::get(&mut tx, employee_id).await;
    // Read whatever charter there is even when the schedule is missing, so the
    // borrow ends before the `?` below unwinds the transaction.
    let charter = match &schedule {
        Ok(_) => Charter::load(&mut tx, employee_id)
            .await
            .unwrap_or_else(|err| {
                // A charter that will not parse is the operator's problem to see,
                // not a 500: the schedule is real and the rest of the answer is
                // useful. `last_outcome` already carries `unreadable_charter` if the
                // poller has been round since.
                tracing::error!(%id, code = err.code(), error = %err, "unreadable charter");
                None
            }),
        Err(_) => None,
    };
    tx.rollback().await?;

    Ok(Json(InitiativeView::of(&schedule?, charter.as_ref(), Utc::now())).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;
    // One lock for the whole table: `loops::initiative`'s tests clear
    // `employee_initiative` globally, because the claim they exercise is
    // cross-tenant. Without this, a poller test running in parallel deletes the
    // schedule a route test just created and the 200 becomes a 404.
    use crate::loops::initiative::tests::LOOP_LOCK;

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
                eprintln!("SKIP: DATABASE_URL is unset; initiative routes need a real Postgres");
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
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
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
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
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

        async fn employee(&self, tenant: TenantId, slug: &str) -> Uuid {
            let id = Uuid::now_v7();
            let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 VALUES ($1, $2, $3, $3, 'active')",
            )
            .bind(id)
            .bind(tenant.as_uuid())
            .bind(format!("{slug}-{id}"))
            .execute(&mut *tx)
            .await
            .expect("insert employee");
            tx.commit().await.expect("commit");
            id
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'routes-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    fn buying(interval_secs: u64) -> Value {
        json!({
            "interval_secs": interval_secs,
            "objective": {
                "role": "international-buyer",
                "what": "anodised aluminium enclosures",
                "quantity": 5000,
                "max_unit_price": {"minor": 1200, "currency": "USD"},
                "delivery_country": "DE",
                "requirements": ["6063-T5"]
            }
        })
    }

    #[tokio::test]
    async fn an_operator_sets_a_cadence_and_an_objective_and_reads_both_back() {
        let _guard = LOOP_LOCK.lock().await;
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = h.employee(h.a, "lena").await;
        let uri = format!("/v1/employees/{id}/initiative");

        let (status, set) = h.send("PUT", &uri, SECRET_A, Some(buying(3_600))).await;
        assert_eq!(status, StatusCode::OK, "{set}");
        assert_eq!(set["interval_secs"], json!(3_600));
        assert_eq!(
            set["status"],
            json!("not_yet"),
            "a fresh schedule is not due"
        );
        assert_eq!(set["claims"], json!(0));
        assert_eq!(set["role"], json!("international-buyer"));

        // The plan is recomputed, in order, and carries the operator's words.
        let plan = set["plan"]
            .as_array()
            .expect("a complete objective has a plan");
        assert_eq!(plan[0]["stage"], json!("discover"));
        assert_eq!(plan[plan.len() - 1]["stage"], json!("order"));
        assert!(
            plan[0]["instruction"]
                .as_str()
                .expect("instruction")
                .contains("anodised aluminium enclosures")
        );
        assert!(set["clarify"].is_null());

        // ...and reads back identically, charter included.
        let (status, read) = h.send("GET", &uri, SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(read["interval_secs"], set["interval_secs"]);
        assert_eq!(read["next_at"], set["next_at"]);
        assert_eq!(read["role"], set["role"]);
        assert_eq!(read["plan"], set["plan"]);

        h.teardown().await;
    }

    /// The one thing this endpoint must not do quietly.
    #[tokio::test]
    async fn a_cadence_outside_the_bounds_is_refused_rather_than_clamped() {
        let _guard = LOOP_LOCK.lock().await;
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = h.employee(h.a, "raj").await;
        let uri = format!("/v1/employees/{id}/initiative");

        h.send("PUT", &uri, SECRET_A, Some(buying(3_600))).await;

        for (secs, code) in [
            (1, "cadence_too_fast"),
            (MIN_INTERVAL.as_secs() - 1, "cadence_too_fast"),
            (MAX_INTERVAL.as_secs() + 1, "cadence_too_slow"),
            (365 * 24 * 3_600, "cadence_too_slow"),
        ] {
            let (status, body) = h.send("PUT", &uri, SECRET_A, Some(buying(secs))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{secs}s: {body}");
            assert_eq!(body["code"], json!(code), "{body}");
            // The bounds come back, so the operator can fix it without guessing.
            assert_eq!(body["min_interval_secs"], json!(MIN_INTERVAL.as_secs()));
            assert_eq!(body["max_interval_secs"], json!(MAX_INTERVAL.as_secs()));
        }

        // And nothing was written: the hourly cadence is still hourly, not a
        // clamped five minutes and not a clamped thirty days.
        let (_, read) = h.send("GET", &uri, SECRET_A, None).await;
        assert_eq!(read["interval_secs"], json!(3_600));

        // The boundaries themselves are legal.
        for secs in [MIN_INTERVAL.as_secs(), MAX_INTERVAL.as_secs()] {
            let (status, body) = h.send("PUT", &uri, SECRET_A, Some(buying(secs))).await;
            assert_eq!(status, StatusCode::OK, "{secs}s should be legal: {body}");
        }

        h.teardown().await;
    }

    /// An objective with holes in it is stored and answered with the question,
    /// in the same round trip. The operator finds out now rather than a cadence
    /// later, and the employee will not guess in the meantime.
    #[tokio::test]
    async fn an_incomplete_objective_comes_back_as_a_question_rather_than_a_plan() {
        let _guard = LOOP_LOCK.lock().await;
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = h.employee(h.a, "ines").await;
        let uri = format!("/v1/employees/{id}/initiative");

        let (status, body) = h
            .send(
                "PUT",
                &uri,
                SECRET_A,
                Some(json!({
                    "interval_secs": 3_600,
                    "objective": {"role": "sales-development", "segment": "airline"}
                })),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["plan"].is_null(), "gaps must not produce a plan");
        let question = body["clarify"].as_str().expect("a question");
        assert!(question.contains("which market"), "{question}");
        assert!(question.contains("which accounts"), "{question}");

        h.teardown().await;
    }

    /// **Every role pack is hirable through this endpoint.** A pack the API
    /// cannot name is a pack no employee can be assigned, and this workspace
    /// has had five of those.
    ///
    /// One `PUT` per role, each read back: the tag reaches the right
    /// [`Charter`], the `role` string survives `employee_charters`' CHECK, and
    /// the plan comes back recomputed from the stored objective with the
    /// operator's own words in it.
    #[tokio::test]
    async fn every_role_pack_can_be_hired_for_and_read_back() {
        let _guard = LOOP_LOCK.lock().await;
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = h.employee(h.a, "polyglot").await;
        let uri = format!("/v1/employees/{id}/initiative");

        for (objective, role, first_stage, must_say) in [
            (
                buying(3_600)["objective"].clone(),
                "international-buyer",
                "discover",
                "anodised aluminium enclosures",
            ),
            (
                json!({"role": "sales-development", "segment": "airline",
                       "market": "FR", "target_accounts": ["Air France"]}),
                "sales-development",
                "research",
                "Air France",
            ),
            (
                json!({"role": "customer-success", "product": "the Orizn visa API",
                       "first_response_hours": 4, "escalate_to": "the on-call engineer"}),
                "customer-success",
                "triage",
                "the Orizn visa API",
            ),
            (
                json!({"role": "growth", "topic": "visa requirements by passport",
                       "market": "FR", "measure": "organic signups"}),
                "growth",
                "research",
                "visa requirements by passport",
            ),
            (
                json!({"role": "finance", "period": "2026-08", "currency": "eur",
                       "obligations": ["the VAT return"]}),
                "finance",
                "reconcile",
                "2026-08",
            ),
        ] {
            let (status, body) = h
                .send(
                    "PUT",
                    &uri,
                    SECRET_A,
                    Some(json!({"interval_secs": 3_600, "objective": objective})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{role}: {body}");
            assert_eq!(body["role"], json!(role), "{body}");

            let (_, read) = h.send("GET", &uri, SECRET_A, None).await;
            assert_eq!(read["role"], json!(role), "{role} did not come back");
            assert!(read["clarify"].is_null(), "{role}: {read}");
            let plan = read["plan"].as_array().expect("a complete objective plans");
            assert_eq!(plan[0]["stage"], json!(first_stage), "{role}: {read}");
            assert!(
                plan.iter().any(|task| task["instruction"]
                    .as_str()
                    .is_some_and(|text| text.contains(must_say))),
                "{role}'s plan lost the operator's own words: {read}"
            );
        }

        h.teardown().await;
    }

    /// A field that is present and wrong is the operator's typo, and the 400 has
    /// to say which one it was.
    #[tokio::test]
    async fn a_body_no_role_answers_to_is_a_400_that_says_which_field() {
        let _guard = LOOP_LOCK.lock().await;
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = h.employee(h.a, "nils").await;
        let uri = format!("/v1/employees/{id}/initiative");

        for (objective, detail) in [
            (
                json!({"role": "international-buyer", "delivery_country": "Germany"}),
                "delivery_country",
            ),
            (
                json!({"role": "sales-development", "segment": "railway"}),
                "segment",
            ),
            (
                json!({"role": "international-buyer",
                       "max_unit_price": {"minor": 0, "currency": "USD"}}),
                "max_unit_price.minor",
            ),
            (json!({"role": "growth", "market": "France"}), "market"),
            (
                json!({"role": "finance", "currency": "dollars"}),
                "currency",
            ),
        ] {
            let (status, body) = h
                .send(
                    "PUT",
                    &uri,
                    SECRET_A,
                    Some(json!({"interval_secs": 3_600, "objective": objective})),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["code"], json!("objective_field"), "{body}");
            assert!(
                body["detail"].as_str().unwrap_or_default().contains(detail),
                "expected the detail to name {detail}: {body}"
            );
        }

        // A role nothing answers to, and a misspelled field, are both refused by
        // the tagged shape itself rather than stored and puzzled over later.
        for objective in [
            json!({"role": "poet"}),
            json!({"role": "international-buyer", "quantitiy": 5000}),
        ] {
            let (status, body) = h
                .send(
                    "PUT",
                    &uri,
                    SECRET_A,
                    Some(json!({"interval_secs": 3_600, "objective": objective})),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }

        h.teardown().await;
    }

    /// 404, not 403: whether another tenant's employee exists is not this
    /// caller's business. And nothing is written for it either — the charter
    /// save runs second precisely because its foreign key does not see RLS.
    #[tokio::test]
    async fn another_tenants_employee_is_not_found_and_gets_no_charter() {
        let _guard = LOOP_LOCK.lock().await;
        let Some(h) = Harness::new().await else {
            return;
        };
        let theirs = h.employee(h.b, "theirs").await;
        let uri = format!("/v1/employees/{theirs}/initiative");

        let (status, _) = h.send("PUT", &uri, SECRET_A, Some(buying(3_600))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = h.send("GET", &uri, SECRET_A, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Nothing landed in either table under the attacker's tenant.
        let mut tx = h.db.admin_tx_bypassing_rls().await.expect("admin tx");
        let charters: i64 =
            sqlx::query_scalar("SELECT count(*) FROM employee_charters WHERE employee_id = $1")
                .bind(theirs)
                .fetch_one(&mut *tx)
                .await
                .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!(charters, 0, "a refused PUT must not leave a charter behind");

        // The owner can still do both, so the 404 is the policy and not a
        // broken route.
        let (status, _) = h.send("PUT", &uri, SECRET_B, Some(buying(3_600))).await;
        assert_eq!(status, StatusCode::OK);

        h.teardown().await;
    }

    /// An employee nobody has given a cadence has no initiative to read.
    #[tokio::test]
    async fn an_employee_with_no_cadence_is_not_found() {
        let _guard = LOOP_LOCK.lock().await;
        let Some(h) = Harness::new().await else {
            return;
        };
        let id = h.employee(h.a, "quiet").await;

        for target in [id.to_string(), Uuid::now_v7().to_string()] {
            let (status, _) = h
                .send(
                    "GET",
                    &format!("/v1/employees/{target}/initiative"),
                    SECRET_A,
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }

        h.teardown().await;
    }
}
