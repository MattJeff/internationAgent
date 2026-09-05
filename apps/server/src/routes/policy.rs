//! `/v1/policy/roles/{role}`: reading and **replacing** one role layer, over
//! HTTP, without the operator's database credential.
//!
//! Until this module there was no route that could change a limit. `POST
//! /v1/companies` may *create* a role layer where none exists and answers `409
//! role_layer_exists` for one that is already there; `routes/teams.rs` moves a
//! pointer at a `role_name` and writes no cap at all; everything else was
//! `agentos-server policy install --tenant … --role …` on `DATABASE_URL`. A
//! console cannot hold that credential, so a console could stand a company up
//! exactly once and never tune it again.
//!
//! # The invariant this route guarantees
//!
//! > **A successful `PUT` replaces a role layer with one contained in the layer
//! > it displaces.** Every cap no higher, every allowlist no wider, every
//! > permission flag no more permissive, every denylist no shorter. Therefore
//! > the effective policy of every employee under that role, and of every other
//! > employee in the deployment, is the same or narrower after the call than
//! > before it.
//!
//! The second sentence follows from the first because `EffectivePolicy::try_new`
//! is `PolicyLimits::intersect` three times and intersection is monotone in each
//! argument: swapping one of its four arguments for a value contained in it
//! cannot enlarge the result. So it is enough to bound the *stored row* — there
//! is no need to reason about the ceiling, the tenant layer, or the other
//! employees at all.
//!
//! # How, mechanically
//!
//! Three parts, and the third is the one that makes the first two true.
//!
//! **1. Comparison against the parent, by the loader's own arithmetic.** The
//! handler reads the layer that is there and asks
//! [`PolicyLimits::narrows`](agentos_domain::policy::PolicyLimits::narrows),
//! which is spelled `old ∧ new == new` using the same `intersect` the gate runs.
//! It is not a field-by-field comparison written here, deliberately: a
//! hand-written one is the thing that silently answers "contained" about a limit
//! nobody taught it, and that answer is in the permissive direction. `intersect`
//! destructures every field with no `..`, so a new limit is a compile error
//! there before it is a hole here.
//!
//! Not a forced intersection at write, either, although that would also be safe.
//! Storing `old ∧ new` when the caller asked for `new` means a console can send
//! a widening body, get a `200`, and read back something it did not write —
//! a limit that appears to have moved and did not. A widening is a **named
//! refusal**, `409 policy_widens`, listing nothing but the fact.
//!
//! **2. It refuses to create.** A `PUT` for a role with no layer is `404`, not
//! an insert. Creating one is safe arithmetic — an absent layer inherits the one
//! above, so `above ∧ above` becomes `above ∧ new` — but it is `POST
//! /v1/companies`'s job, because that route knows the org chart and can refuse
//! the team with no layer. Here it would also mean a misspelled role name
//! silently writes limits nothing reads, and tells the caller it tightened
//! something. So there is still exactly one door that creates a role layer and
//! now exactly one that replaces one.
//!
//! **3. The read and the write are one transaction, under one lock.** The check
//! is worth nothing if the layer it compared against is not the layer being
//! displaced. `policy::lock_for_write` is a transaction-scoped advisory lock on
//! the tenant, taken before the read; two consoles tightening the same role in
//! the same second are serialised, and the second one compares against what the
//! first actually wrote. Without it both compare against the same old layer and
//! the loser's narrowing is undone by the winner's — a widening in effect, with
//! two `200`s and nothing in either response to say so. The audit row is
//! appended inside that transaction too, so a limit that changed without a trail
//! is a limit that did not change.
//!
//! # What is still not here, and why
//!
//! **The platform ceiling.** Its row belongs to no tenant and binds every other
//! one, so a route authorised by one tenant's key must not write it. That
//! argument is `crate::policy`'s and it is unchanged: the ceiling stays behind
//! `DATABASE_URL`. This route cannot reach it — `policy::role_layer` pins
//! `v.tenant_id = $1`, so a `GET` here never renders the ceiling even when the
//! tenant has no layer of its own, and `0006_policy.sql`'s `WITH CHECK` refuses
//! the write underneath.
//!
//! **The tenant and employee layers.** Both are defensible under exactly the
//! argument above — the check is arithmetic and does not care which of the four
//! arguments it bounds — and neither is built, because nothing asks for them
//! yet. The employee scope in particular has never had a door, and the day
//! something mints a per-seat token it is the one an employee would hold. When
//! there is a caller, the handler below is the same handler with a different
//! `Scope`.
//!
//! **A rollback.** `agentos-server policy rollback --tenant …` removes a layer,
//! and removing one widens — `store::policy::rollback_layer` says so. It stays
//! on the credential that is allowed to widen.

use agentos_domain::ids::Slug;
use agentos_domain::policy::PolicyLimits;
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::policy::{self, Installed, Scope};
use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::Principal;
use crate::error::ApiError;

/// This unit's routes. Merged into the API router, so it inherits auth, the
/// rate limit and the idempotency layer from `with_api_stack`.
pub fn router(db: Db) -> Router {
    Router::new()
        .route(
            "/v1/policy/roles/{role}",
            get(get_role_layer).put(put_role_layer),
        )
        .with_state(db)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One role's stored limits, exactly as written — **not** the intersection the
/// gate enforces.
///
/// The difference matters to whoever reads this and it is the reason there is no
/// second field holding the effective policy: an operator editing a layer needs
/// to see the document they are editing, and a body that showed both would make
/// "which of these do I `PUT` back" a question. What the gate actually enforces
/// for a given seat is a different question about a different subject — an
/// employee, not a role — and `GET /v1/turns` and the gate's own refusals are
/// where it is answered.
#[derive(Debug, Serialize)]
struct LayerView {
    role: String,
    limits: PolicyLimits,
}

/// What a replacement did.
#[derive(Debug, Serialize)]
struct InstalledView {
    role: String,
    /// The `policy_versions` row now active. Present either way — a replay that
    /// changed nothing still names the version that is binding, and it is what
    /// `agentos-server policy rollback --tenant …` would flip away from.
    version: uuid::Uuid,
    /// `false` when the layer already said exactly this, which is what a replay
    /// says. Nothing was written and no audit row was appended, because nobody
    /// changed a limit.
    installed: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /v1/policy/roles/{role}` — this tenant's role layer, as stored.
///
/// `404` when the role has no layer of its own, and that is the honest answer
/// rather than an inherited one: an absent layer inherits the layer above at
/// *load* time, so rendering the tenant layer or the platform ceiling here would
/// make "this role has no limits written" and "this role has limits identical to
/// the ceiling" the same response — and the whole point of the `PUT` beside it
/// is that those two are different. `store::policy::role_layer` is the reader
/// that keeps the distinction, and it pins `v.tenant_id = $1` as well as
/// relying on row-level security, because `0006_policy.sql` lets every tenant
/// *read* the platform rows so the loader can find the ceiling.
async fn get_role_layer(
    State(db): State<Db>,
    principal: Principal,
    Path(role): Path<String>,
) -> Result<Response, ApiError> {
    let role = parse_role(&role)?;
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let found = read_layer(&mut tx, &role).await;
    tx.rollback().await?;

    let limits = found?.ok_or_else(ApiError::not_found)?;
    Ok(Json(LayerView { role, limits }).into_response())
}

/// `PUT /v1/policy/roles/{role}` — replace one role layer with a narrower one.
///
/// The body is a **whole layer document**, byte-identical to what
/// `agentos-server policy install --tenant … --role …` takes in a file and to
/// one value of `POST /v1/companies`' `roles` map, parsed by the one function
/// all three share. That function is stricter than `deny_unknown_fields` in both
/// directions and for the same reason: an unknown field would be dropped and
/// leave the layer short a limit, and a *missing* field is not "leave it alone"
/// — `PolicyLimits` is `#[serde(default)]` and its default grants nothing, so
/// `{"max_turns_per_day": 30}` looks like an edit and is a total replacement
/// that costs the seat its channels, its domains and its model. Both are a `400`
/// naming the fields, before anything is read from the database.
///
/// The refusals, in the order they can happen:
///
/// | | |
/// |---|---|
/// | the role name is not a slug | `400` |
/// | the body is not a whole layer document | `400`, naming what is missing or unknown |
/// | the role has no layer to replace | `404`, naming `POST /v1/companies` |
/// | the stored layer no longer decodes | `409 role_layer_unreadable` |
/// | the body is not contained in the stored layer | `409 policy_widens` |
/// | the body names a currency the rest of the active policy does not | `409 policy_currency` |
///
/// `200` either way on success, with `installed: false` when the layer already
/// said exactly this — which is what makes a replay a repair, the same rule
/// `Installed::Unchanged` gives the CLI and `POST /v1/companies`.
async fn put_role_layer(
    State(db): State<Db>,
    principal: Principal,
    Path(role): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(document) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let role = parse_role(&role)?;
    // The identical rule `agentos-server policy install` applies to a file, from
    // the same function, for the reason `crate::policy::parse_limits` argues.
    let limits = crate::policy::parse_limits(&document).map_err(ApiError::bad_request)?;

    let now = Utc::now();
    let mut tx = db.tenant_tx(principal.tenant_id).await?;

    // Before the read, not after it: what this handler decides is only true of
    // the row it is about to displace if nothing displaces it in between. Every
    // early return below drops `tx`, which rolls it back and releases the lock.
    policy::lock_for_write(&mut tx).await?;

    let current = read_layer(&mut tx, &role).await?.ok_or_else(|| {
        ApiError::not_found().with_detail(format!(
            "this company has no limits written for the role {role}, and this route replaces a \
             layer rather than creating one. Creating the first layer for a role is `POST \
             /v1/companies`, which can refuse a team that has none — a check this route cannot \
             make. If {role} is a typo, note that a layer written under a role name no team \
             points at binds nobody."
        ))
    })?;

    // **The invariant, in one line, by the loader's own arithmetic.** See this
    // module's header for why it is this and not a comparison written here.
    let narrows = limits.narrows(&current).map_err(|err| {
        ApiError::conflict("policy_currency", "this layer cannot be intersected")
            .with_extension("role", json!(role))
            .with_detail(format!(
                "{err}. The layer that is stored and the one you sent are denominated \
                 differently, so neither is narrower than the other — there is no exchange rate \
                 in this product and there must not be one. Nothing was written."
            ))
    })?;
    if !narrows {
        return Err(ApiError::conflict(
            "policy_widens",
            "this layer is not contained in the one it would replace",
        )
        .with_extension("role", json!(role))
        .with_detail(format!(
            "A route authorised by a tenant's API key may only tighten. Every cap must be no \
             higher, every allowlist no wider, every permission flag no more permissive, and \
             `denied_domains` no shorter — a lower layer may add a block and never remove one. \
             `GET /v1/policy/roles/{role}` returns the layer you are replacing; send it back with \
             the values you want lowered. Widening is a new policy version on the operator's own \
             database credential: `agentos-server policy install --tenant {} --role {role} \
             <layer.json>`. Nothing was written.",
            principal.tenant_id.as_uuid()
        )));
    }

    let label = format!(
        "role layer {role} from PUT /v1/policy/roles by {}",
        // The key's label, never its secret.
        principal.actor.label()
    );
    let installed = policy::install_layer_tx(&mut tx, Scope::Role(&role), &limits, &label)
        .await
        .map_err(|err| match err {
            // The store's message already names both currencies and says what
            // installing it would have done; wrapping it would bury that.
            StoreError::Conflict(refusal) => {
                ApiError::conflict("policy_currency", "this layer cannot be intersected")
                    .with_detail(refusal)
                    .with_extension("role", json!(role))
            }
            err => ApiError::from(err),
        })?;

    // In the same transaction as the write, so a limit that changed without a
    // trail is a limit that did not change. `AuditKind::PolicyChanged` and
    // `decision_id: None`, matching `routes::spend` and `routes::teams`: an
    // operator's key acting directly, with no Policy Gate ruling behind it.
    //
    // Not on `Unchanged`, because nobody changed anything and a row claiming
    // otherwise is the trail lying in the direction that costs an investigation.
    if matches!(installed, Installed::Version(_)) {
        audit::append(
            &mut tx,
            &AuditEvent {
                payload: json!({
                    "event": "policy.role_layer_replaced",
                    "role": role,
                    "version": installed.version(),
                    // What it was, so an operator answering "who lowered this
                    // and from what" has one row to read rather than two
                    // versions to diff.
                    "from": current,
                    "to": limits,
                }),
                ..AuditEvent::new(principal.actor.clone(), AuditKind::PolicyChanged, now)
            },
        )
        .await?;
    }
    tx.commit().await?;

    Ok(Json(InstalledView {
        role,
        version: installed.version(),
        installed: matches!(installed, Installed::Version(_)),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// A role name is a slug, because it is also a team slug and a role pack's name
/// — `docs/ORIZN.md` argues those three should be one string. Refusing here
/// means a path segment that could never have matched a layer says so instead of
/// answering `404` for a second reason.
fn parse_role(raw: &str) -> Result<String, ApiError> {
    Slug::parse(raw)
        .map(|slug| slug.as_str().to_owned())
        .map_err(|err| ApiError::bad_request(format!("{raw:?}: {err}")))
}

/// The stored layer, or the named refusal for one that no longer decodes.
///
/// A row that does not parse must not read as `None`: `None` here means "nothing
/// is written", and the `PUT` would then have nothing to compare against — which
/// is the one way a widening could get past the check. Repairing a corrupt layer
/// is `policy install`'s job, which replaces one deliberately. Same rule and
/// same code as `routes::companies`' reader, which refuses it for the mirror
/// reason.
async fn read_layer(tx: &mut TenantTx<'_>, role: &str) -> Result<Option<PolicyLimits>, ApiError> {
    policy::role_layer(tx, role).await.map_err(|err| {
        ApiError::conflict(
            "role_layer_unreadable",
            "this company has a stored layer for that role that no longer decodes",
        )
        .with_extension("role", json!(role))
        .with_detail(format!(
            "{err}. Nothing was written. Replace it deliberately with `agentos-server policy \
             install --tenant … --role {role} <layer.json>`."
        ))
    })
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_store::policy::Installed;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY};

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The layer every test in this module starts from: room to move in each of
    /// the four kinds of field, so a narrowing and a widening are both one edit
    /// away.
    fn base_layer() -> Value {
        json!({
            "spend": null,
            "allowed_channels": ["email", "internal"],
            "allowed_calling_codes": [],
            "allowed_domains": ["example.com"],
            "denied_domains": [],
            "allowed_mcp_tools": [],
            "allowed_a2a_peers": [],
            "allowed_models": ["claude-haiku-4-5", "claude-sonnet-5"],
            "max_new_contacts_per_day": 100,
            "max_turns_per_day": 100,
            "allow_file_upload": false,
            "allow_credential_change": false,
            "allow_data_delete": false,
            "allow_lead_upload": false
        })
    }

    /// [`base_layer`] with one field replaced. Every case below is one number or
    /// one list away from the fixture, so what the test is about is the diff.
    fn layer_with(field: &str, value: Value) -> Value {
        let mut layer = base_layer();
        layer[field] = value;
        layer
    }

    /// This module's own database, and it needs one for the reason
    /// `routes::companies`' test gives: the platform ceiling is
    /// `tenant_id IS NULL`, one row for the whole database, and installing it
    /// into the shared one is a collision with whatever else is asserting on it.
    ///
    /// Returns an app, the database, and a tenant with a `sales` role layer
    /// already written. A second tenant holds a key and nothing else.
    async fn fixture(suffix: &str) -> Option<(Router, Db, TenantId)> {
        let db = crate::loops::private_db(suffix).await?;
        policy::install_ceiling(&db, &policy::default_ceiling(), "policy route tests")
            .await
            .expect("install a ceiling");

        let a = TenantId::new_v7(Utc::now());
        let b = TenantId::new_v7(Utc::now());
        let slug = format!("co-{}", &a.as_uuid().simple().to_string()[..12]);
        policy::create_tenant(&db, a, &slug, "First")
            .await
            .expect("tenant");

        let limits: PolicyLimits =
            serde_json::from_value(base_layer()).expect("the fixture is a whole layer");
        policy::install_layer(&db, a, Scope::Role("sales"), &limits, "fixture")
            .await
            .expect("write the layer the tests replace");

        let keys = ApiKeys::parse(&format!(
            "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
            a.as_uuid(),
            b.as_uuid()
        ))
        .expect("keyring");
        let app = crate::with_api_stack(
            router(db.clone()),
            db.clone(),
            Keyring::new(keys, db.clone(), TEST_MASTER_KEY),
        );
        Some((app, db, a))
    }

    async fn call(
        app: &Router,
        method: &str,
        secret: &str,
        role: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let req = HttpRequest::builder()
            .method(method)
            .uri(format!("/v1/policy/roles/{role}"))
            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .expect("request");
        let response = app.clone().oneshot(req).await.expect("service");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// What is actually stored, read the way the loader reads it — not the way
    /// the route reports it. Every assertion about "nothing was written" goes
    /// through this, because a handler that returns the right status and writes
    /// anyway is the failure the status alone cannot see.
    async fn stored(db: &Db, tenant: TenantId, role: &str) -> Option<PolicyLimits> {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let found = policy::role_layer(&mut tx, role).await.expect("decodes");
        tx.rollback().await.expect("rollback");
        found
    }

    /// **A layer that only tightens is written, and it is what comes back.**
    ///
    /// Three fields move: a cap down, an allowlist to a subset, and a *denylist
    /// grown* — which is the direction a containment check gets backwards if it
    /// treats every set as a subset.
    #[tokio::test]
    async fn a_layer_that_tightens_is_installed() {
        let Some((app, db, tenant)) = fixture("policy_tighten").await else {
            return;
        };

        let mut tighter = base_layer();
        tighter["max_turns_per_day"] = json!(40);
        tighter["allowed_models"] = json!(["claude-haiku-4-5"]);
        tighter["denied_domains"] = json!(["spam.example.com"]);

        let (status, body) = call(&app, "PUT", SECRET_A, "sales", Some(&tighter)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["installed"], json!(true), "{body}");
        assert!(
            body["version"].is_string(),
            "the binding version is named: {body}"
        );

        let now = stored(&db, tenant, "sales").await.expect("a layer");
        assert_eq!(
            serde_json::to_value(&now).expect("serialises"),
            tighter,
            "what is stored is what was sent, field for field — not the intersection of it \
             with the old layer, which would be a 200 for a body nobody could read back"
        );

        // A replay changes nothing and says so, which is what makes re-running a
        // provisioning script safe. Same rule as `Installed::Unchanged`.
        let (status, replay) = call(&app, "PUT", SECRET_A, "sales", Some(&tighter)).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["installed"], json!(false), "{replay}");
        assert_eq!(
            replay["version"], body["version"],
            "no new version: {replay}"
        );
    }

    /// **A layer that widens anything is refused by name, and writes nothing.**
    ///
    /// The route's whole reason to exist is that this cannot be a 200. Each case
    /// is one field over the stored layer and nothing else, so a check that
    /// covered three of the four kinds of field would fail here rather than pass
    /// on the strength of the others.
    #[tokio::test]
    async fn a_layer_that_widens_is_refused_and_nothing_is_written() {
        let Some((app, db, tenant)) = fixture("policy_widen").await else {
            return;
        };
        let before = stored(&db, tenant, "sales")
            .await
            .expect("the fixture layer");

        let wider = [
            // A cap raised.
            (
                "a turn budget above the stored one",
                layer_with("max_turns_per_day", json!(500)),
            ),
            // An allowlist gaining an entry the stored layer does not name.
            (
                "a model the stored layer does not permit",
                layer_with(
                    "allowed_models",
                    json!(["claude-haiku-4-5", "claude-opus-5"]),
                ),
            ),
            // A permission switched on.
            (
                "data deletion switched on",
                layer_with("allow_data_delete", json!(true)),
            ),
            // Spend where the stored layer permits none — `None` means *may not
            // spend*, so this is the widest single edit on the surface.
            (
                "spending where the stored layer permits none",
                layer_with(
                    "spend",
                    json!({
                        "max_per_transaction": {"minor": 1000, "currency": "USD"},
                        "max_per_day": {"minor": 2000, "currency": "USD"},
                        "approval_above": {"minor": 500, "currency": "USD"}
                    }),
                ),
            ),
        ];

        for (what, body) in wider {
            let (status, refused) = call(&app, "PUT", SECRET_A, "sales", Some(&body)).await;
            assert_eq!(status, StatusCode::CONFLICT, "{what}: {refused}");
            assert_eq!(
                refused["code"],
                json!("policy_widens"),
                "{what} must be refused by this arm and not by a currency clash or a 500: \
                 {refused}"
            );
            assert_eq!(
                stored(&db, tenant, "sales").await.as_ref(),
                Some(&before),
                "{what}: the refusal says nothing was written"
            );
        }

        // And a *denylist* shortened, which is the same escalation spelled the
        // other way: the layer is otherwise identical and an employee can reach
        // a host it could not.
        let denied = layer_with("denied_domains", json!(["spam.example.com"]));
        let (status, ok) = call(&app, "PUT", SECRET_A, "sales", Some(&denied)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "adding a block is a narrowing: {ok}"
        );
        let (status, refused) = call(&app, "PUT", SECRET_A, "sales", Some(&base_layer())).await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(
            refused["code"],
            json!("policy_widens"),
            "dropping a denied domain lets an employee reach a host it could not: {refused}"
        );
    }

    /// **A role with no layer is a 404, and the route does not create one.**
    ///
    /// Both halves matter. The status is the tenant's own answer for a role
    /// nobody wrote limits for — including the one that is a typo — and the
    /// second assertion is what makes it a refusal rather than an oversight: a
    /// `PUT` that fell through to an insert here would write limits nothing
    /// reads and tell the caller it had tightened something.
    #[tokio::test]
    async fn a_role_with_no_layer_is_not_created_by_a_put() {
        let Some((app, db, tenant)) = fixture("policy_absent").await else {
            return;
        };

        let (status, refused) = call(&app, "PUT", SECRET_A, "salse", Some(&base_layer())).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
        assert_eq!(
            stored(&db, tenant, "salse").await,
            None,
            "a PUT for a role with no layer must not be the thing that creates one"
        );
        // The `GET` beside it answers the same way, so a console that reads
        // before it writes never sees an inherited layer it did not write.
        let (status, missing) = call(&app, "GET", SECRET_A, "salse", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
    }

    /// **A second console cannot decide from a layer the first one is in the
    /// middle of replacing.**
    ///
    /// The race, made deterministic rather than fired off and hoped for. Two
    /// requests handed to `tokio::join!` do **not** reliably overlap — measured,
    /// not assumed: the second one here ran entirely after the first had
    /// committed, so the test was green with the lock deleted. A concurrency test
    /// that cannot go red is worse than none.
    ///
    /// So the first writer is the test itself, holding the transaction open at
    /// exactly the point a handler holds it — lock taken, old layer read, nothing
    /// written yet — while a real request goes through the router beside it. The
    /// two bodies are deliberately *incomparable*: one lowers the turn budget,
    /// the other lowers the contact budget, and neither is contained in the
    /// other. So the second writer must be refused **if and only if** it compared
    /// against what the first one wrote.
    ///
    /// Both assertions go red without `policy::lock_for_write`. The request would
    /// not wait, and having read the layer before the commit it would find its
    /// own body contained in it, write, and answer `200` — with the first
    /// writer's tightening gone and nobody told.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_writer_cannot_decide_from_a_layer_being_replaced() {
        let Some((app, db, tenant)) = fixture("policy_race").await else {
            return;
        };
        let fewer_turns: PolicyLimits =
            serde_json::from_value(layer_with("max_turns_per_day", json!(10))).expect("a layer");
        let fewer_contacts = layer_with("max_new_contacts_per_day", json!(10));

        // The first console: it has the lock and has read, and has not written.
        let mut first = db.tenant_tx(tenant).await.expect("tenant tx");
        policy::lock_for_write(&mut first).await.expect("lock");
        let seen = policy::role_layer(&mut first, "sales")
            .await
            .expect("decodes")
            .expect("the fixture layer");
        assert!(fewer_turns.narrows(&seen).expect("same currency"));

        // The second console, as a real request on another thread.
        let waiting = tokio::spawn(async move {
            call(&app, "PUT", SECRET_A, "sales", Some(&fewer_contacts)).await
        });
        // Long enough for a request that is not blocked to have finished: the
        // whole round trip is single-digit milliseconds against a local Postgres.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !waiting.is_finished(),
            "the second writer read and decided while the first held the lock, so its answer is \
             about a layer that is being replaced underneath it"
        );

        // The first console writes its narrowing and commits, releasing the lock.
        policy::install_layer_tx(&mut first, Scope::Role("sales"), &fewer_turns, "first")
            .await
            .expect("write");
        first.commit().await.expect("commit");

        let (status, refused) = waiting.await.expect("the second request");
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the second writer compared against the layer the first one wrote, not the one it \
             read before waiting: {refused}"
        );
        assert_eq!(refused["code"], json!("policy_widens"), "{refused}");

        // And the first writer's tightening is intact and whole — a lost update
        // looks exactly like the second body being here instead.
        assert_eq!(
            stored(&db, tenant, "sales").await,
            Some(fewer_turns),
            "the surviving layer is the one that was committed, entire"
        );
    }

    /// **A `GET` renders this tenant's own layer and never the platform
    /// ceiling.**
    ///
    /// The ceiling is `tenant_id IS NULL` and every tenant may *read* it —
    /// `0006_policy.sql` opens that door on purpose, because the loader needs
    /// the ceiling to intersect with. So "the reader is confined by RLS" is not
    /// enough here and `role_layer` pins `v.tenant_id = $1` as well. The second
    /// tenant holds a key, has never written a layer, and must get a 404 for the
    /// same role name rather than the ceiling's numbers or the first tenant's.
    #[tokio::test]
    async fn a_get_never_renders_the_ceiling_or_another_tenants_layer() {
        let Some((app, _db, _tenant)) = fixture("policy_read").await else {
            return;
        };

        let (status, mine) = call(&app, "GET", SECRET_A, "sales", None).await;
        assert_eq!(status, StatusCode::OK, "{mine}");
        assert_eq!(mine["limits"], base_layer(), "the layer as stored: {mine}");
        // Asserting on the *difference* from the ceiling is what makes this
        // about the ceiling rather than about equality with a fixture.
        let ceiling = serde_json::to_value(policy::default_ceiling()).expect("serialises");
        assert_ne!(mine["limits"], ceiling, "{mine}");

        let (status, theirs) = call(&app, "GET", SECRET_B, "sales", None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a tenant with no layer of its own inherits at load time and has nothing to read \
             here — rendering the ceiling would make `no layer` and `a layer equal to the \
             ceiling` the same response: {theirs}"
        );
        let rendered = theirs.to_string();
        assert!(
            !rendered.contains("max_turns_per_day"),
            "no part of any layer crosses into a tenant that wrote none: {rendered}"
        );
    }

    /// **A body that omits a field is a 400 before anything is read.**
    ///
    /// `PolicyLimits` is `#[serde(default)]` and its default grants nothing, so
    /// `{"max_turns_per_day": 30}` would deserialise into a layer that costs the
    /// seat its channels, its domains and its model — and it would *pass* the
    /// containment check, because losing everything is a narrowing. The refusal
    /// is not about safety, it is about the caller having meant it.
    #[tokio::test]
    async fn a_partial_document_is_refused_rather_than_read_as_an_edit() {
        let Some((app, db, tenant)) = fixture("policy_partial").await else {
            return;
        };
        let before = stored(&db, tenant, "sales").await;

        let (status, refused) = call(
            &app,
            "PUT",
            SECRET_A,
            "sales",
            Some(&json!({"max_turns_per_day": 30})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(stored(&db, tenant, "sales").await, before);

        // And an unknown field, which serde would otherwise drop — leaving the
        // layer short whatever the caller meant to write.
        let (status, refused) = call(
            &app,
            "PUT",
            SECRET_A,
            "sales",
            Some(&layer_with("max_turns_per_dya", json!(30))),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(stored(&db, tenant, "sales").await, before);
    }

    /// **A limit does not change without a row saying who changed it.**
    ///
    /// Appended in the write's own transaction, so there is no window in which
    /// the layer moved and the trail did not — and deliberately *not* appended
    /// on a replay or a refusal, because a trail with an entry for every attempt
    /// cannot answer "what is this seat allowed to do, and since when".
    #[tokio::test]
    async fn the_trail_and_the_write_are_one_transaction() {
        let Some((app, db, tenant)) = fixture("policy_trail").await else {
            return;
        };
        let count = |db: Db| async move {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let n: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM audit_log WHERE action_kind = 'policy_changed' \
                   AND payload->>'event' = 'policy.role_layer_replaced'",
            )
            .fetch_one(&mut **tx)
            .await
            .expect("count");
            tx.rollback().await.expect("rollback");
            n
        };
        assert_eq!(count(db.clone()).await, 0);

        let tighter = layer_with("max_turns_per_day", json!(7));
        let (status, ok) = call(&app, "PUT", SECRET_A, "sales", Some(&tighter)).await;
        assert_eq!(status, StatusCode::OK, "{ok}");
        assert_eq!(count(db.clone()).await, 1);

        let (status, replay) = call(&app, "PUT", SECRET_A, "sales", Some(&tighter)).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["installed"], json!(false));
        assert_eq!(
            count(db.clone()).await,
            1,
            "a replay changed no limit, so the trail must not claim one changed"
        );

        let (status, refused) = call(
            &app,
            "PUT",
            SECRET_A,
            "sales",
            Some(&layer_with("max_turns_per_day", json!(99))),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(count(db).await, 1);
    }

    /// The store's split holds its own promise: `install_layer_tx` writes into
    /// the caller's transaction and nothing survives a rollback.
    ///
    /// It is the property the audit row rests on — "appended in the same
    /// transaction" is worth nothing if the layer commits on its own — and it is
    /// not visible through the route, which always commits.
    #[tokio::test]
    async fn a_layer_written_into_a_rolled_back_transaction_is_not_written() {
        let Some((_app, db, tenant)) = fixture("policy_rollback").await else {
            return;
        };
        let before = stored(&db, tenant, "sales")
            .await
            .expect("the fixture layer");

        let limits: PolicyLimits =
            serde_json::from_value(layer_with("max_turns_per_day", json!(1))).expect("a layer");
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let installed =
            policy::install_layer_tx(&mut tx, Scope::Role("sales"), &limits, "rolled back")
                .await
                .expect("write");
        assert!(matches!(installed, Installed::Version(_)));
        tx.rollback().await.expect("rollback");

        assert_eq!(stored(&db, tenant, "sales").await, Some(before));
    }
}
