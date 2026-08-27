//! `POST /v1/companies` — a whole company, standing, from one call.
//!
//! `docs/ORIZN.md` is nine steps and step 5 carries the sentence **"this part is
//! not an HTTP call"**. That sentence is the reason nothing downstream of it has
//! a client: a product whose entry journey is *name the project, connect the
//! server, describe what it does, then pick tools, employees, models, budget* is
//! a product that cannot ship an entry journey while its third step is a shell
//! on the database box. This module is that step, and the four either side of
//! it, behind one request.
//!
//! # Why one call and not four
//!
//! [`routes::teams::apply_org`](super::teams::apply_org) already argues it for
//! its own document and the argument transfers whole: the seven-row table was
//! twenty calls with no transaction across them, and the failure was not "the
//! call failed" but *a company half-built in a way an operator can neither read
//! nor safely retry*. A company is that failure one level up. Four calls —
//! tenant, layers, chart, budgets — have four places to stop, and three of the
//! four resulting states are worse than nothing:
//!
//! | died after | what is standing |
//! |---|---|
//! | the tenant | a tenant with no employees. Harmless. |
//! | the layers | limits and nobody to bind. **Harmless — and this is why they go first.** |
//! | the chart | employees. On whatever limits happen to exist. |
//!
//! The third row is the one that matters and it is the whole reason for the
//! order below. **The layers are written before the chart, always.** An absent
//! role layer inherits the layer above it (`store::policy::load`), so a company
//! that got its org chart and not its limits is a company whose every seat runs
//! on the platform ceiling — the widest thing in the deployment — with nothing
//! anywhere reporting that it happened. Reverse the two and the same crash
//! leaves rows that grant nobody anything, because there is no *body* yet.
//!
//! # What is atomic, and what is deliberately not
//!
//! **Atomic:** the tenant row and its first `policy_versions` row
//! (`store::policy::create_tenant`, one transaction, and the pair is an
//! invariant — a tenant with no active version has *invisible* layers). Each
//! role layer, individually: one new version, the previous one intact behind it.
//! The whole org chart plus this route's own audit row, in one `TenantTx`.
//!
//! **Not atomic:** the call. There are `2 + roles` commit points and no
//! transaction spans them, because [`agentos_store::policy::install_layer`]
//! mints one version per layer by design and folding five layers into one
//! version would delete `policy rollback --tenant`'s meaning — "undo the
//! customer-success change" is a per-layer sentence. `docs/ORIZN.md` §5 already
//! made this trade for the shell loop and made it for the failure that actually
//! happens: **a re-run repairs rather than duplicating.**
//!
//! So the guarantee is not atomicity, it is *convergence*, and it is bought with
//! keys the caller chose rather than with a header:
//!
//! * the tenant is `Principal::tenant_id` — never a body field, so there is no
//!   uuid a caller can name and re-running cannot address a second tenant;
//! * a role layer is its `role_name`, and an identical one is
//!   [`Installed::Unchanged`](agentos_store::policy::Installed::Unchanged) —
//!   no row, no version;
//! * a team is its slug and an employee is its slug, which is `apply_org`'s own
//!   idempotence and the reason neither endpoint wants an `Idempotency-Key`.
//!
//! Replay any prefix and the second run finishes it. That is asserted, from a
//! call cut in the middle, by `apps/server/tests/orizn.rs`.
//!
//! # What is not in this call, and will not be
//!
//! **The ceiling.** It is the most dangerous document in the system and it is
//! the one thing here that belongs to *no tenant* — `tenant_id IS NULL`, which
//! `0006_policy.sql`'s WITH CHECK makes unwritable from any tenant transaction.
//! A route that installed one would open an admin transaction on the strength of
//! a credential meaning "I am tenant X" and write a row binding every *other*
//! tenant: `apps::server::policy` calls that a privilege escalation with a JSON
//! body and it is right. There is no `ceiling` field, and `deny_unknown_fields`
//! means a caller who sends one is told so rather than ignored.
//!
//! **And it does not fall back to [`policy::default_ceiling`].** That function
//! exists and is deliberately chosen to be defensible *as a policy* — but it is
//! 200 turns a day, 50 new contacts a day and a $100 band nobody looks at, and
//! Orizn's runbook ceiling is 30, 20 and **$1**. A route that installed the
//! default when none was present would hand every company created through it a
//! ceiling six times wider than the one the runbook argues for, silently, as the
//! consequence of a field somebody left out. That is precisely the shape of
//! failure the layer-completeness rule exists to refuse, one level up. So: **no
//! ceiling is a refusal**, `409 no_platform_policy`, naming the command — the
//! same answer `/readyz` and the boot warning already give, on the surface an
//! operator is now looking at.
//!
//! **A limit, after the first one.** See [`create_company`]: this route may
//! *create* a role layer and may never *replace* one.
//!
//! # What it may not do that `routes::teams` may not do either
//!
//! No spend row. `PUT /v1/teams/{id}/budget` and `PUT /v1/employees/{id}/spend-caps`
//! stay separate calls and step 6 of the runbook stays two lines, because a
//! budget is the thing that moves money and `org::reserve` reads the *absence*
//! of one as "may not spend". A company that stands up unable to pay anybody is
//! the correct company to stand up.

use std::collections::BTreeMap;

use agentos_domain::ids::Slug;
use agentos_domain::policy::PolicyLimits;
use agentos_store::db::{Db, StoreError};
use agentos_store::policy::{self, Installed, Scope};
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::Principal;
use crate::error::ApiError;
use crate::routes::teams::{self, OrgChart};

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/companies", post(create_company))
        .with_state(db)
}

/// A company: who it is, who works there, and what they may do.
///
/// The three role-layer documents of `docs/ORIZN.md` — the ceiling, the org
/// chart and the role layers — minus the ceiling, which is the deployment's and
/// not a company's. `org` is `docs/orizn-org.json` verbatim and `roles` is
/// `docs/orizn-roles/` keyed by filename, so the runbook's own files are this
/// body with two lines of shell around them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewCompany {
    /// The handle this deployment refers to the company by, on the `tenants`
    /// row. Matched against an existing tenant rather than written over one —
    /// see [`create_company`].
    slug: String,
    /// The company as a person writes it: "Orizn".
    name: String,
    /// The org chart, exactly as `POST /v1/org` takes it.
    org: OrgChart,
    /// One complete [`PolicyLimits`] per `role_name`, keyed by the name — which
    /// is the team slug, which is the role pack's name, which `docs/ORIZN.md`
    /// argues at length should be one string.
    ///
    /// **Complete, not a patch.** Every value goes through the same
    /// completeness rule `agentos-server policy install` applies to a file, and
    /// for the same reason: `PolicyLimits` is `#[serde(default)]` and its
    /// default grants nothing, so `{"max_turns_per_day": 30}` looks like an edit
    /// and is a total replacement that costs the seat its channels, its domains
    /// and its model. A `Value` and not a `PolicyLimits` precisely so the
    /// omission is still visible here; by the time it is a struct it is a zero.
    roles: BTreeMap<String, Value>,
}

/// What one role layer's install did.
#[derive(Debug, Serialize)]
struct LayerView {
    role: String,
    /// The `policy_versions` row now active. Present either way — a re-apply
    /// that changed nothing still names the version that is binding.
    version: uuid::Uuid,
    /// `false` when the layer already said exactly this, which is what every
    /// commit point after the first says on a replay.
    installed: bool,
}

/// `POST /v1/companies` — the runbook's steps 3, 4 and 5, in that order and in
/// one request.
///
/// # The empty seat, made impossible rather than documented
///
/// `docs/ORIZN.md` spends a section on why `direction` exists with zero turns
/// and no channel, and the argument is not about the founder: **an absent role
/// layer inherits the layer above it**, so a team pointed at a `role_name`
/// nobody wrote limits for runs on the ceiling. Leave `direction` out and the
/// seat at the *root* of the org chart — the one every head reports to — quietly
/// becomes the most permissive employee in the company.
///
/// That is a documented trap in the shell version, where the loop over
/// `docs/orizn-roles/*.json` and the org chart are two unrelated commands and
/// nothing compares them. Here they arrive together, so it is not a trap: **every
/// `team` named in `org.rows` must have an entry in `roles`**, checked against
/// the body before a single row is written, refused by name. There is nothing
/// to remember and no way to be told later.
///
/// It is stated as a rule about teams rather than a special case for
/// `direction`, because `direction` is not special — `upsert_team` writes
/// `team_policy.role_name = slug` for a team it creates, so *any* row whose slug
/// has no layer is the same failure wearing a different name.
///
/// ponytail: checked against the document, not against `team_policy`. They agree
/// for every team this call creates, which is the case this route is for. A team
/// that predates the call and was repointed by hand with `PUT …/policy-role`
/// could name a third `role_name` — and would produce exactly the same company
/// the runbook produces from the same content, which is the bar. Read the
/// pointers back if that ever stops being true.
///
/// # It creates limits and never changes them
///
/// A role that already has a layer **different** from the one in the body is
/// `409 role_layer_exists`, naming the role and the command that edits one.
/// Identical is fine and writes nothing, which is what makes a replay a repair.
///
/// This is the line that keeps two sentences true that this repository leans on.
/// `routes/teams.rs` says a route moves a pointer and never a cap, "because two
/// places to write a limit is one place to forget to tighten" — still true, in
/// the sense that matters: there remains exactly one way to *change* a limit,
/// `agentos-server policy install`, on the operator's own database credential.
/// And `apps/server/src/policy.rs` warns that "the key is the operator" is one
/// variable wide: the day something mints a per-seat token, a policy route
/// becomes an employee rewriting its own limits up to its tenant's. Not this
/// one. For a company that is standing, every role already has a layer and this
/// route can only refuse.
///
/// **The arithmetic underneath, which is why creating is safe and replacing is
/// not.** An absent layer inherits, so the effective policy before an install is
/// `above ∧ above` and after it is `above ∧ new`; `EffectivePolicy::try_new`
/// takes the minimum of every cap and the intersection of every allowlist, so
/// the second is contained in the first, field by field. **Writing a layer where
/// none existed cannot widen anything.** Replacing one has no such property —
/// the new layer is not intersected with the old — which is exactly the
/// authority `install_layer` has and this route does not.
///
/// # The refusals, and none of them is a 500
///
/// | | |
/// |---|---|
/// | no platform ceiling installed | `409 no_platform_policy`, naming the command |
/// | a `roles` entry missing a field | `400`, naming the fields, before any write |
/// | a team in `org.rows` with no layer | `400`, naming the teams, before any write |
/// | this tenant is a different company | `409 tenant_mismatch` — the wrong API key |
/// | a role layer exists and differs | `409 role_layer_exists`, naming the role |
///
/// Everything above the tenant row is a pure read of the body, so the common
/// mistakes cost nothing and leave nothing.
///
/// 202 when it hired somebody, 200 when it did not — `apply_org`'s rule, for
/// `apply_org`'s reason: a replay that changed nothing has nothing outstanding.
async fn create_company(
    State(db): State<Db>,
    principal: Principal,
    body: Result<Json<NewCompany>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    // --- everything that can be decided from the body, before any write -----
    let slug = Slug::parse(&body.slug)
        .map_err(|err| ApiError::bad_request(format!("slug: {err}")))?
        .as_str()
        .to_owned();
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name: must not be blank"));
    }
    if body.roles.is_empty() {
        return Err(ApiError::bad_request(
            "roles: a company with no role layers is a company whose every seat runs on the \
             platform ceiling, because an absent layer inherits the one above it",
        ));
    }

    // The identical rule `agentos-server policy install` applies to a file, from
    // the same function — see `crate::policy::parse_limits`. An omitted field is
    // DENY and not "leave it alone", and this is the only place that can still
    // tell the two apart.
    let roles: BTreeMap<String, PolicyLimits> = body
        .roles
        .iter()
        .map(|(role, document)| {
            let role = Slug::parse(role)
                .map_err(|err| ApiError::bad_request(format!("roles: {role:?}: {err}")))?
                .as_str()
                .to_owned();
            let limits = crate::policy::parse_limits(document)
                .map_err(|err| ApiError::bad_request(format!("roles.{role}: {err}")))?;
            Ok((role, limits))
        })
        .collect::<Result<_, ApiError>>()?;

    // **The empty seat.** Every team must have limits written for it, because
    // the one that does not is the widest employee in the company.
    let unlimited: Vec<&str> = body
        .org
        .rows
        .iter()
        .map(|row| row.team.as_str())
        .filter(|team| !roles.contains_key(*team))
        .collect();
    if !unlimited.is_empty() {
        return Err(ApiError::bad_request(format!(
            "roles: no layer for {}. A team whose role_name has no layer INHERITS the layer \
             above it, so these seats would run on the platform ceiling — and the seat at the \
             root of the chart is the one that would end up most permissive. Write a layer for \
             every team, including the ones that are meant to permit nothing: `direction` in \
             docs/orizn-roles/ is every field present and every one of them empty.",
            unlimited.join(", ")
        )));
    }

    // --- the deployment has to have a ceiling before any of this binds ------
    //
    // Fail-closed either way: with no platform layer `policy::load` answers
    // `NoPlatformLayer` and the gate refuses every action, so skipping this
    // check would build a company that cannot act rather than one that can act
    // freely. It is here so the operator is told *now*, by the surface they are
    // holding, instead of debugging `broken_policy` on a company they thought
    // they had stood up.
    if !policy::platform_ceiling_installed(&db).await? {
        return Err(ApiError::conflict(
            "no_platform_policy",
            "this deployment has no platform ceiling, so every action would be denied",
        )
        .with_detail(
            "Install one first: `agentos-server policy install docs/orizn-ceiling.json`, on the \
             operator's own DATABASE_URL. The ceiling belongs to no tenant and is deliberately \
             not writable over HTTP — a route authorised by one tenant's key must not write a row \
             that binds every other tenant. This route will not install a default one either: \
             the shipped default is wider than any runbook ceiling and a company that got it \
             because a field was missing is the failure this whole surface refuses.",
        ));
    }

    // --- 1. the tenant row, which is this key's own and nobody else's -------
    let tenant = principal.tenant_id;
    let now = Utc::now();
    adopt_or_create_tenant(&db, &principal, &slug, name).await?;

    // --- 2. the limits, BEFORE anybody exists to be bound by them -----------
    let mut layers = Vec::with_capacity(roles.len());
    for (role, limits) in &roles {
        if let Some(existing) = read_role_layer(&db, &principal, role).await?
            && existing != *limits
        {
            return Err(ApiError::conflict(
                "role_layer_exists",
                "this company already has limits written for that role, and they are not these",
            )
            .with_extension("role", json!(role))
            .with_detail(format!(
                "`POST /v1/companies` may write a role layer that does not exist yet — which can \
                 only narrow, because an absent layer inherits the one above it — and may not \
                 replace one, which could widen. Changing {role}'s limits is a new policy \
                 version and an undo: `agentos-server policy install --tenant {} --role {role} \
                 <layer.json>`, reversible with `agentos-server policy rollback --tenant {}`.",
                tenant.as_uuid(),
                tenant.as_uuid(),
            )));
        }

        let label = format!("role layer {role} from POST /v1/companies by {}", {
            // The key's label, never its secret: `AuditActor::Operator` holds
            // the `label` half of `label:tenant:secret` and nothing else, and
            // this string lands in a column an operator reads back.
            principal.actor.label()
        });
        let installed = policy::install_layer(&db, tenant, Scope::Role(role), limits, &label)
            .await
            .map_err(|err| match err {
                // Two currencies cannot be intersected, and the store's message
                // already names both and says what installing it would have
                // done. Wrapping it would bury the useful half.
                StoreError::Conflict(refusal) => {
                    ApiError::conflict("policy_currency", "this layer cannot be intersected")
                        .with_detail(refusal)
                        .with_extension("role", json!(role))
                }
                err => ApiError::from(err),
            })?;
        layers.push(LayerView {
            role: role.clone(),
            version: installed.version(),
            installed: matches!(installed, Installed::Version(_)),
        });
    }

    // --- 3. the org chart, and this route's record of the whole act ---------
    //
    // One transaction for both, so a company whose chart committed and whose
    // audit row did not is not reachable. The chart is `apply_org`'s own code
    // path — same refusals, same `org.applied` row, same idempotence on slugs.
    let mut tx = db.tenant_tx(tenant).await?;
    let chart = teams::apply_org_chart(&mut tx, &principal.actor, &body.org, now).await?;
    let hired = teams::hired_slugs(&chart);
    teams::record(
        &mut tx,
        &principal.actor,
        None,
        json!({
            "event": "company.created",
            "slug": slug,
            "name": name,
            "roles": layers,
            "rows": chart.len(),
            "hired": hired,
        }),
        now,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        tenant_id = %tenant,
        slug = %slug,
        roles = layers.len(),
        rows = chart.len(),
        hired = hired.len(),
        "company created"
    );

    let status = if hired.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((
        status,
        Json(json!({
            "tenant_id": tenant.as_uuid(),
            "slug": slug,
            "name": name,
            "roles": layers,
            "chart": chart,
        })),
    )
        .into_response())
}

/// The `tenants` row for the tenant **this key already speaks for** — found, or
/// created.
///
/// # Why a route may create this at all
///
/// `store::policy::create_tenant` argues that tenant creation "has no principal
/// but the operator", and that is true of the *command*, which takes a uuid from
/// a shell. It is not true here and the difference is the whole justification:
/// the id is [`Principal::tenant_id`], which came out of `AGENTOS_API_KEYS` —
/// a static keyring the operator wrote before the process booted, with no route
/// anywhere that mints an entry. **There is no uuid a caller can name.** A key
/// for tenant X can bring exactly tenant X into existence, and a key for a
/// tenant that already exists brings nothing.
///
/// So this is not the escalation `apps/server/src/policy.rs` refuses. That one
/// is about the *platform* layer, whose row belongs to no tenant and binds every
/// other one. This row belongs to the caller and binds nobody else.
///
/// What it buys is a defect `docs/ORIZN.md` already lists under "what this
/// document knows it does not do": skip the tenant row and `POST /v1/org`
/// answers **`500 internal`** with an opaque body, and the cause is a foreign
/// key in the server log. The document's suggested fix is a pre-flight that
/// answers 400 instead. Creating the row is strictly better than a 400 and it is
/// the same act the operator would have performed.
///
/// # It adopts and it does not rename
///
/// An existing tenant is used as it stands. Renaming somebody's company as a
/// side effect of a replay is the kind of surprise `apply_org` refuses for
/// deleted rows and it is refused here — but a **mismatch is not ignored**
/// either: a body that says it is building "acme" against a tenant that is
/// "orizn" is almost always the wrong API key in the terminal, and silently
/// building Acme's org chart inside Orizn is not recoverable by re-running
/// anything. `409 tenant_mismatch`, before a single row is written.
///
/// The insert races with itself — two replays in flight both read no row — and
/// the loser gets a unique violation, which is read as "somebody else created
/// it" and falls through to the same success. That is what convergence means
/// when there is no lock to take.
async fn adopt_or_create_tenant(
    db: &Db,
    principal: &Principal,
    slug: &str,
    name: &str,
) -> Result<(), ApiError> {
    // RLS confines this to the caller's own row, so "not visible" and "does not
    // exist" are the same answer — which is the point of both.
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let existing: Option<(String, String)> =
        sqlx::query_as("SELECT slug, name FROM tenants WHERE id = $1")
            .bind(principal.tenant_id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(StoreError::from)?;
    tx.rollback().await?;

    if let Some((found_slug, found_name)) = existing {
        if found_slug != slug {
            return Err(ApiError::conflict(
                "tenant_mismatch",
                "this API key already speaks for a different company",
            )
            .with_extension("slug", json!(found_slug))
            .with_detail(format!(
                "The key names a tenant whose slug is {found_slug:?} ({found_name:?}) and this \
                 body says {slug:?}. Nothing was written. Standing a company up does not rename \
                 one, and building this chart inside that company is not something re-running \
                 anything would undo — check which key is in your terminal."
            )));
        }
        return Ok(());
    }

    match policy::create_tenant(db, principal.tenant_id, slug, name).await {
        Ok(_) => Ok(()),
        // Somebody won the race, or the *slug* is taken by another tenant. The
        // first is success; the second is a genuine collision and the caller
        // has to pick another handle. They are told apart by re-reading our own
        // row, which RLS makes visible only if it is ours.
        Err(StoreError::Conflict(what)) => {
            let mut tx = db.tenant_tx(principal.tenant_id).await?;
            let ours: Option<String> = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
                .bind(principal.tenant_id.as_uuid())
                .fetch_optional(&mut **tx)
                .await
                .map_err(StoreError::from)?;
            tx.rollback().await?;
            match ours {
                Some(found) if found == slug => Ok(()),
                _ => Err(ApiError::conflict(
                    "tenant_slug_taken",
                    "another company in this deployment already uses that slug",
                )
                .with_detail(format!("{what}. Pick another `slug`; nothing was written."))),
            }
        }
        Err(err) => Err(err.into()),
    }
}

/// This tenant's stored role layer for `role`, if it has written one.
///
/// A row this deployment cannot decode is a `409` and not a `None`: `None` here
/// reads as "nothing is written", which would let this route install over limits
/// it could not see. Repairing a corrupt layer is `policy install`'s job, which
/// replaces one deliberately.
async fn read_role_layer(
    db: &Db,
    principal: &Principal,
    role: &str,
) -> Result<Option<PolicyLimits>, ApiError> {
    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let found = policy::role_layer(&mut tx, role).await;
    tx.rollback().await?;
    found.map_err(|err| {
        ApiError::conflict(
            "role_layer_unreadable",
            "this company has a stored layer for that role that no longer decodes",
        )
        .with_extension("role", json!(role))
        .with_detail(format!(
            "{err}. Nothing was written. Replace it deliberately with `agentos-server policy \
             install --tenant {} --role {role} <layer.json>`.",
            principal.tenant_id.as_uuid()
        ))
    })
}
