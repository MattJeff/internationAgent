//! `agentos-server policy` — every row that decides what an employee may do,
//! written and undone without a database console.
//!
//! The gate is fail-closed: with no `platform` layer `store::policy::load`
//! answers `NoPlatformLayer`, every action for every tenant is denied, `main`
//! warns at boot and `/readyz` refuses. Everything about that was already true
//! and visible. What did not exist was a way to *fix* it — when this module was
//! written no route wrote `policy_layers` at all — so a fresh install could not
//! be made to work without hand-written SQL. This is that missing half.
//!
//! One route writes `policy_layers` now: `POST /v1/companies`, and only where
//! the tenant has no such layer (`409 role_layer_exists` otherwise). "Both
//! arguments survived, and it turned out they were about *replacing*" below is
//! the whole story; the sentence above is kept in the past tense rather than
//! deleted because it is why this module exists.
//!
//! Four verbs, and each closes a step `docs/ORIZN.md` used to have to spell as
//! `psql`:
//!
//! | verb | the row nothing else wrote when this was written |
//! |---|---|
//! | `install <ceiling.json>` | the platform ceiling |
//! | `new-tenant <slug> <name>` | the `tenants` row **and** its active `policy_versions` row |
//! | `install --tenant … [--role …\|--employee …] <layer.json>` | a tenant, role or employee layer |
//! | `rollback [--tenant …]` | the undo for either |
//!
//! # Why a subcommand and not a route
//!
//! A route would be reachable, scriptable and consistent with the rest of this
//! server, and it is still the wrong shape here.
//!
//! **Every route in this binary derives its tenant from the API key.** That is
//! the whole authorisation model: `auth::require_api_key` turns a bearer token
//! into a `Principal { tenant_id }`, `Db::tenant_tx` pins the transaction to it,
//! and RLS enforces it in Postgres. The platform layer belongs to *no tenant* —
//! `tenant_id IS NULL`, deliberately, and `0006_policy.sql`'s WITH CHECK clause
//! makes it unwritable from any tenant transaction. So a route that installed
//! one would have to open an admin transaction on the strength of a credential
//! that means "I am tenant X", and the write it performs binds every *other*
//! tenant. That is a privilege escalation with a JSON body, and the mitigation
//! would have to be a second class of credential — a platform key, its own
//! keyring, its own rotation story, its own 401 path, and a new way to be
//! misconfigured on a surface that is by definition internet-reachable. The
//! honest version of "authorise a platform write" is not a header. It is
//! "prove you are the operator", and the proof this deployment already has is
//! the database credential.
//!
//! **That second class of credential now exists, and the ceiling is still not a
//! route.** `AGENTOS_PLATFORM_KEYS` and `crate::routes::platform` were built for
//! the one platform write that could not stay in a shell — issuing a customer's
//! first API key, because a customer filling in a form cannot ssh anywhere. Every
//! cost this paragraph listed was paid: a second keyring, a second 401 path, a
//! second way to be misconfigured. What did not change is which side of the line
//! the *ceiling* falls on, and the reason is not that no principal could be
//! authenticated for it:
//!
//! * **Issuing a key cannot widen anything.** The row it writes is a credential
//!   for one tenant, bounded by exactly the policy that tenant already had. The
//!   ceiling is the only row in this schema that makes *every* tenant able to do
//!   more, and rolling one back is the one operation in this file that genuinely
//!   widens.
//! * **A ceiling is a document, not a call.** `install` reads a JSON file and
//!   refuses one that omits a field, because an omitted field is DENY and not
//!   "leave it alone" — see [`parse_limits_document`]. That check exists where an
//!   operator's *file* is read, and a route would be a second place for the
//!   belief it refuses.
//!
//! So the widest thing this deployment can do stays behind the credential that
//! is hardest to hold and impossible to hold by accident. If a hosted control
//! plane ever needs to widen a customer's ceiling without shell access, the
//! principal to build it on is `auth::PlatformPrincipal` and the function is
//! [`policy::install_ceiling`] — but read the two bullets above before deciding
//! that is what is wanted.
//!
//! **A subcommand runs on exactly that credential.** `DATABASE_URL`, an admin
//! transaction, no new authorisation concept, and nothing added to the HTTP
//! surface for an attacker to find. It is the same shape as `doctor`, for the
//! same reason.
//!
//! The real cost of a subcommand is that it is one more thing to forget, and
//! forgetting it is the failure this exists to prevent. That cost is paid down
//! rather than argued away: the boot warning and `/readyz`'s 503 both name this
//! command, and `doctor` reports the missing ceiling as MISSING with the command
//! to run. An operator who forgets is told, three times, in the three places
//! they are already looking.
//!
//! What a route would add, if one is ever wanted: a hosted control plane where
//! the *vendor* — not a tenant — widens the ceiling for a customer without shell
//! access to the box. Build it when there is a platform principal to
//! authenticate, and build it on `store::policy::install_ceiling`, which is
//! where the interesting half already lives.
//!
//! # The tenant, role and employee layers: also a subcommand, but not for the reason above
//!
//! The escalation argument does not carry down here, and pretending it does
//! would be dishonest. A tenant layer belongs *to a tenant*, and a tenant is
//! exactly what an API key proves: `auth::require_api_key` yields a `Principal`,
//! `Db::tenant_tx` pins the transaction, `0006_policy.sql`'s WITH CHECK pins the
//! row. A route under `/v1/policy/…` would write only rows the caller already
//! owns. Nor would it be a new *class* of authority: the same key already hires
//! employees through `POST /v1/org`, hands a team a daily budget through
//! `PUT /v1/teams/{id}/budget` and hands a seat its spend caps — and a budget is
//! a thing that moves money, which a policy layer on its own is not. And it
//! could not widen: every layer it wrote would still be an argument to
//! `EffectivePolicy::try_new`, which takes the minimum of every cap and the
//! intersection of every allowlist, under a ceiling no key can reach.
//!
//! So a route is *defensible* here. It is still not what this builds, for two
//! reasons that are about this repository rather than about authorisation.
//!
//! **One place to write a limit.** `routes/teams.rs` argues it at length and
//! `docs/TEAMS.md` §2 repeats it: a team's endpoint moves a *pointer* at a
//! `role_name` and never a cap, "because two places to write a limit is one
//! place to forget to tighten". That sentence is load-bearing — it is why
//! `POST /v1/org` can take a 500-row document from one call without being a
//! second gate. Adding `PUT /v1/policy/role/{name}` would make it false on the
//! same surface, and the module that argues hardest against it is the one an
//! operator reads next.
//!
//! **The premise the route would rest on is one variable wide.** "The key is the
//! operator" held because `AGENTOS_API_KEYS` was a static, operator-written
//! keyring: there was no route that minted a key, so no employee held one. The
//! day one does — a self-service console, a per-seat token — a route here
//! becomes an employee that can rewrite its own employee layer up to its
//! tenant's, which is every grant its colleagues have. A subcommand keeps
//! working through that change without anybody noticing it had to.
//!
//! *That day half-arrived with `0044_api_keys`, and the premise survives on a
//! narrower reason.* There is now a route that mints a key — but it is
//! `POST /v1/platform/keys`, it is authorised by a principal that is not a
//! tenant, and what it mints is a **tenant** credential with exactly the
//! authority `AGENTOS_API_KEYS` always granted. No employee holds one, because
//! nothing an employee can reach can issue one: a tenant's own key presented to
//! that route is a 401, which is the property `routes::platform` exists to keep.
//! The premise fails the day a key is minted *per seat*, and the sentence above
//! is still the reason not to.
//!
//! What the route would buy, concretely, is a tenant who is *not* the operator:
//! somebody who holds an API key and no shell. This deployment has no such
//! person — the runbook's operator exports `DATABASE_URL` and `KEY` in the same
//! terminal — so the route would be a second door to a room with one occupant.
//! Build it the day the tenant and the operator are two people, build it on
//! `store::policy::install_layer` (which is already tenant-scoped, runs under
//! RLS and refuses a tenant it cannot see), and give another tenant's id the
//! repository's 404 rather than a 403, for the reason `routes/teams.rs` gives.
//!
//! # Both arguments survived, and it turned out they were about *replacing*
//!
//! `routes::companies` writes role layers over HTTP. That is not this module
//! changing its mind; it is the two objections above being read more carefully
//! than they were written, because both of them are objections to a **`PUT`**.
//!
//! An absent layer inherits the layer above (`store::policy::load` substitutes
//! rather than defaulting), so the effective policy before an install is
//! `above ∧ above` and after it is `above ∧ new`, and
//! `EffectivePolicy::try_new` takes the minimum of every cap and the
//! intersection of every allowlist. **Writing a layer where none existed is
//! contained in what was already permitted, field by field** — it cannot widen
//! even the *stored* row, let alone the ruling. Replacing one has no such
//! property: the incoming layer is not intersected with the one it displaces,
//! so `PUT /v1/policy/role/{name}` really is a way to raise a cap over HTTP and
//! this module was right to refuse it.
//!
//! So `POST /v1/companies` may create a role layer and answers
//! `409 role_layer_exists` for one that is already there and says something
//! else. Both sentences above stay true on that line:
//!
//! * **"Two places to write a limit is one place to forget to tighten."** There
//!   is still one place to *change* a limit, and it is this command. A route
//!   that can only ever narrow-from-inheritance is not a second place to forget,
//!   because there is nothing there yet to forget to tighten.
//! * **"The premise is one variable wide."** The day something mints a per-seat
//!   token, that token finds every role layer of a live company already written
//!   and gets a `409`. It cannot rewrite its own limits up to its tenant's,
//!   which is the escalation this module names — and it never could, since the
//!   *employee* scope has no door at all.
//!
//! What is still only here: the platform ceiling (whose row belongs to no tenant
//! and binds every other one — there is a platform principal now, and the two
//! bullets at the top of this module are why the ceiling did not follow the
//! keyring onto it), and every *edit* to a layer that exists. [`rollback_layer`]
//! too:
//! a rollback removes a layer, and removing one is the one operation in this
//! file that genuinely widens.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentos_domain::ids::{EmployeeId, Slug, TenantId};
use agentos_domain::policy::PolicyLimits;
use agentos_store::db::{Db, StoreError};
use agentos_store::policy::{self, Installed, Scope};
use uuid::Uuid;

/// Printed on anything this module does not understand. It is also the whole
/// documentation of the command that an operator will actually read.
const USAGE: &str = "\
usage: agentos-server policy install [ceiling.json]
       agentos-server policy new-tenant <slug> <name> [--id <uuid>]
       agentos-server policy install --tenant <uuid> [--role <name> | --employee <uuid>] <layer.json>
       agentos-server policy rollback [--tenant <uuid>]

  install                 make a platform policy ceiling active. With no file,
                          installs the documented default.
  new-tenant              create a tenant and the active policy version its
                          layers hang off. `--id` names the uuid your
                          AGENTOS_API_KEYS entry already carries.
  install --tenant        make one tenant / role / employee layer active. No
                          --role and no --employee is the tenant's own layer.
  rollback [--tenant]     make the previous ceiling, or the tenant's previous
                          policy version, active again.

Re-installing the same thing changes nothing and says so. Every one of these
reads DATABASE_URL and nothing else: writing a limit is proved by the operator's
own database credential, never by an API key. See this module's docs for why.";

/// Which layer a `policy install --tenant …` is writing, with its arguments
/// owned — [`Scope`] borrows, and the strings here come out of `args`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopeArg {
    Tenant,
    Role(String),
    Employee(EmployeeId),
}

impl ScopeArg {
    fn as_scope(&self) -> Scope<'_> {
        match self {
            ScopeArg::Tenant => Scope::Tenant,
            ScopeArg::Role(name) => Scope::Role(name),
            ScopeArg::Employee(id) => Scope::Employee(*id),
        }
    }

    /// How the version label and the success line name this layer.
    fn describe(&self) -> String {
        match self {
            ScopeArg::Tenant => "tenant layer".to_owned(),
            ScopeArg::Role(name) => format!("role layer {name}"),
            ScopeArg::Employee(id) => format!("employee layer {}", id.as_uuid()),
        }
    }
}

/// What is printed after an install, because a ceiling is the one setting an
/// operator has to be told is not a recommendation.
const CAVEAT: &str = "\
This is a CEILING: the widest anything in this deployment may be, not a
recommendation. Every tenant, team and employee layer intersects with it and can
only narrow it — and a tenant that has written no layer of its own runs on
exactly these numbers. To widen it, save the JSON above, edit it, and run
`agentos-server policy install <file>`. To undo, `agentos-server policy rollback`.";

/// Run the subcommand and exit non-zero on anything that did not happen.
///
/// A runtime of its own, current-thread: this is one command with three round
/// trips, and a worker pool for that is a worker pool that starts before the
/// argument parse has decided whether there is anything to do.
pub fn main(args: &[String]) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("agentos-server policy: could not start a tokio runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args)) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        // The usage text is already a whole sentence about this command;
        // prefixing it reads like an error inside an error.
        Err(err) if err.starts_with("usage:") => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("agentos-server policy: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The command, as a value rather than a process exit — so the argument parsing
/// and the messages are testable without a database or a `std::process::exit`.
async fn run(args: &[String]) -> Result<String, String> {
    let verbs: Vec<&str> = args.iter().map(String::as_str).collect();
    match verbs.as_slice() {
        ["install"] => install(&database_url()?, None).await,
        // A bare path is the ceiling; anything starting with `-` is the layer
        // form and falls to the arm below. A file whose name begins with a dash
        // is not a case worth a `--` separator.
        ["install", file] if !file.starts_with('-') => {
            install(&database_url()?, Some(Path::new(file))).await
        }
        ["install", rest @ ..] if !rest.is_empty() => {
            let (tenant, scope, file) = parse_layer_args(rest)?;
            install_layer(&database_url()?, tenant, &scope, &file).await
        }
        ["new-tenant", rest @ ..] if !rest.is_empty() => {
            let (id, slug, name) = parse_new_tenant_args(rest)?;
            new_tenant(&database_url()?, id, &slug, &name).await
        }
        ["rollback"] => rollback(&database_url()?).await,
        ["rollback", "--tenant", id] => rollback_layer(&database_url()?, tenant_id(id)?).await,
        // Including the empty case: `agentos-server policy` on its own is
        // somebody asking what this does.
        _ => Err(USAGE.to_owned()),
    }
}

/// A uuid an operator typed, or the usage text — never a connection attempt.
fn tenant_id(raw: &str) -> Result<TenantId, String> {
    Uuid::parse_str(raw)
        .map(TenantId::from_uuid)
        .map_err(|err| format!("--tenant {raw:?} is not a uuid: {err}\n\n{USAGE}"))
}

/// The argument after the flag at `args[i]`. Every flag this command has takes
/// a value, so "the next argument exists and is not itself a flag" is one check
/// rather than three — and `--tenant --role sales` failing here is better than
/// a tenant id of `"--role"`.
fn flag_value<'a>(args: &[&'a str], i: usize) -> Result<&'a str, String> {
    args.get(i + 1)
        .copied()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| format!("{} needs a value.\n\n{USAGE}", args[i]))
}

/// `--tenant <uuid> [--role <name> | --employee <uuid>] <layer.json>`, in any
/// order, because an operator who puts the file first is not making a mistake.
///
/// Pure, and separated from [`install_layer`] for exactly that: the shape of
/// these flags is the half of this command that is worth testing without a
/// database, and the half a typo lands in.
fn parse_layer_args(args: &[&str]) -> Result<(TenantId, ScopeArg, PathBuf), String> {
    let mut tenant: Option<TenantId> = None;
    let mut scope: Option<ScopeArg> = None;
    let mut file: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i];
        let mut narrow = |candidate: ScopeArg| -> Result<(), String> {
            if scope.is_some() {
                // A layer is one row. `--role x --employee y` is two different
                // rows and there is no way to guess which was meant.
                return Err(format!(
                    "--role and --employee name two different layers; install them one at a \
                     time.\n\n{USAGE}"
                ));
            }
            scope = Some(candidate);
            Ok(())
        };

        match flag {
            "--tenant" => {
                tenant = Some(tenant_id(flag_value(args, i)?)?);
                i += 2;
            }
            "--role" => {
                let name = Slug::parse(flag_value(args, i)?)
                    .map_err(|err| format!("--role: {err}\n\n{USAGE}"))?
                    .as_str()
                    .to_owned();
                narrow(ScopeArg::Role(name))?;
                i += 2;
            }
            "--employee" => {
                let raw = flag_value(args, i)?;
                let id = Uuid::parse_str(raw)
                    .map(EmployeeId::from_uuid)
                    .map_err(|err| format!("--employee {raw:?} is not a uuid: {err}\n\n{USAGE}"))?;
                narrow(ScopeArg::Employee(id))?;
                i += 2;
            }
            _ if flag.starts_with('-') => return Err(USAGE.to_owned()),
            _ => {
                if file.is_some() {
                    return Err(format!(
                        "one layer document per install; got {flag:?} as well.\n\n{USAGE}"
                    ));
                }
                file = Some(PathBuf::from(flag));
                i += 1;
            }
        }
    }

    // No `--role` and no `--employee` is the tenant's own layer, which is the
    // only scope with nothing to name.
    Ok((
        tenant.ok_or_else(|| USAGE.to_owned())?,
        scope.unwrap_or(ScopeArg::Tenant),
        file.ok_or_else(|| {
            format!("a layer document is required; there is no default layer.\n\n{USAGE}")
        })?,
    ))
}

/// `<slug> <name> [--id <uuid>]`.
///
/// The id is optional and minted when absent — but the runbook always supplies
/// it, because `AGENTOS_API_KEYS=label:tenant-uuid:secret` is read at boot and a
/// uuid this command invented afterwards is a uuid nobody's key names.
fn parse_new_tenant_args(args: &[&str]) -> Result<(TenantId, String, String), String> {
    let (positional, id) = match args {
        [rest @ .., "--id", raw] => (rest, tenant_id(raw)?),
        // No `--id`: v7, so a directory of tenants sorts by when it was created.
        _ => (args, TenantId::new_v7(chrono::Utc::now())),
    };
    let [slug, name] = positional else {
        return Err(USAGE.to_owned());
    };
    // A slug, not free text: it is the handle every other document in this
    // deployment refers to the company by, and `Slug::parse` is what the rest of
    // the system means by one.
    let slug = Slug::parse(slug)
        .map_err(|err| format!("slug: {err}\n\n{USAGE}"))?
        .as_str()
        .to_owned();
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("name: must not be blank.\n\n{USAGE}"));
    }
    Ok((id, slug, name.to_owned()))
}

fn database_url() -> Result<String, String> {
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| {
            "DATABASE_URL is not set. This command writes the ceiling with the operator's own \
             database credentials — that is its whole authorisation story."
                .to_owned()
        })
}

/// Install the default ceiling, or the one in `path`.
///
/// **It does not migrate.** The server applies migrations at boot and takes an
/// advisory lock doing it; a second migration path that runs from a CLI is a
/// second thing that can be halfway through when the first starts. The order is
/// boot (which migrates, warns, and reports not-ready), then this.
async fn install(url: &str, path: Option<&Path>) -> Result<String, String> {
    let (limits, label) = match path {
        None => (policy::default_ceiling(), "default ceiling".to_owned()),
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|err| format!("{}: {err}", path.display()))?;
            // Every constructor in the domain is a checked one, so this rejects
            // an incoherent ceiling — an approval threshold above the
            // per-transaction cap, a zero amount, a domain that is not a host —
            // before a row is written rather than on every load afterwards.
            let limits =
                parse_limits_document(&raw).map_err(|err| format!("{}: {err}", path.display()))?;
            (limits, path.display().to_string())
        }
    };

    let db = connect(url).await?;
    let installed = policy::install_ceiling(&db, &limits, &label)
        .await
        .map_err(|err| store_error("could not install the ceiling", err))?;
    let json = serde_json::to_string_pretty(&limits).expect("PolicyLimits serialises");

    Ok(match installed {
        Installed::Version(id) => format!(
            "installed platform ceiling {id} ({label}).\n\n{json}\n\n{CAVEAT}\n\n\
             /readyz will report ready on the next probe; no restart is needed — the gate reads \
             the ceiling per decision."
        ),
        // Not an error, and not silent either: re-running the install is what a
        // provisioning script does on every deploy, and "nothing changed" is the
        // answer that makes that safe.
        Installed::Unchanged(id) => format!(
            "unchanged: platform ceiling {id} ({label}) already says exactly this. \
             Nothing was written and no new version was created.\n\n{json}"
        ),
    })
}

async fn rollback(url: &str) -> Result<String, String> {
    let db = connect(url).await?;
    match policy::rollback_ceiling(&db).await {
        Ok(version) => Ok(format!(
            "rolled back: platform ceiling {version} is active again. The version it replaced is \
             still in `policy_versions` — rolling back twice returns to it."
        )),
        // The one refusal worth spelling out: rolling back the only ceiling
        // there has ever been would leave the deployment denying every action,
        // which is not what anybody means by "undo".
        Err(agentos_store::db::StoreError::NotFound) => Err(
            "there is no earlier platform ceiling to roll back to. Rolling back the first one \
             would leave this deployment with no ceiling at all, which denies every action for \
             every tenant — install a corrected ceiling instead:\n\n  \
             agentos-server policy install corrected.json"
                .to_owned(),
        ),
        Err(err) => Err(store_error("could not roll back", err)),
    }
}

// ---------------------------------------------------------------------------
// A layer document
// ---------------------------------------------------------------------------

/// Every field of `PolicyLimits`, by the name serde gives it.
///
/// Kept honest by `every_field_of_policy_limits_is_named_here`, which asks
/// serde for the list instead of trusting this one.
const LAYER_FIELDS: [&str; 14] = [
    "spend",
    "allowed_channels",
    "allowed_calling_codes",
    "allowed_domains",
    "denied_domains",
    "allowed_mcp_tools",
    "allowed_a2a_peers",
    "allowed_models",
    "max_new_contacts_per_day",
    "max_turns_per_day",
    "allow_file_upload",
    "allow_credential_change",
    "allow_data_delete",
    "allow_lead_upload",
];

/// One ceiling or one layer, parsed — and **refused if it is not complete**.
///
/// # The trap this exists for
///
/// `PolicyLimits` is `#[serde(default)]`, and its `Default` grants *nothing*:
/// no channels, no domains, no tools, no turns, no spend. That is exactly right
/// for the type — a layer somebody forgot to fill in must not be the layer that
/// opens the gate — and it makes a hand-written document lethal in a way that
/// reads as harmless. `{"max_turns_per_day": 30}` looks like an edit and is a
/// total replacement: the role that receives it may no longer browse, because
/// the layers *intersect* and an empty allowlist is
/// `DenyReason::NoRule`, not "inherit". The employee keeps working, keeps
/// answering, and has silently lost the web. Nothing errors. `docs/ORIZN.md`
/// records this as the failure worth preventing and it is right.
///
/// The domain already chose the shape that avoids it: there is no "inherit"
/// marker and every layer restates the grants it wants to keep (see the
/// `ponytail:` note on `PolicyLimits`). This is that decision enforced at the
/// only place it can be — where an operator's file is read, because it is the
/// only place that can still tell *absent* from *deliberately empty*. By the
/// time the row exists they are the same row.
///
/// So: every field, every time. `"allowed_domains": []` is accepted and means
/// deny — a finance seat with no bank portal, a chair with no channel at all
/// are both real. Omitting it is refused. A misspelled field is refused too,
/// under the same rule from the other side: serde would drop `max_turns_per_dya`
/// silently and the layer would be short one grant, so the unknown key is
/// reported *before* the missing one it stands in for.
///
/// ponytail: no `--force`. The escape hatch is typing the field, which is the
/// thing we want typed; a flag would be the thing that gets pasted into the
/// deploy script once and never removed.
fn parse_limits_document(raw: &str) -> Result<PolicyLimits, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|err| format!("not JSON: {err}"))?;
    parse_limits(&value)
}

/// [`parse_limits_document`] minus the file, so a layer that arrives inside a
/// larger JSON body gets the identical rule.
///
/// **Split for `POST /v1/companies`, and the sharing is the point.** That route
/// carries one of these per role, and a second parser there would be a second
/// place for "an omitted field means inherit" to be true — which is the exact
/// belief this function exists to refuse. Every argument in
/// [`parse_limits_document`]'s docs is an argument about this body; the wrapper
/// above only owns "the bytes were not JSON", which is a thing a file can be
/// and a `serde_json::Value` cannot.
pub(crate) fn parse_limits(value: &serde_json::Value) -> Result<PolicyLimits, String> {
    let object = value
        .as_object()
        .ok_or("a policy layer is a JSON object of limits")?;

    let unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !LAYER_FIELDS.contains(key))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "unknown field(s) {}: serde would drop them and the layer would be short a limit. \
             The fields are: {}",
            unknown.join(", "),
            LAYER_FIELDS.join(", ")
        ));
    }

    let missing: Vec<&str> = LAYER_FIELDS
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "this document omits {}, and an omitted field is not \"leave it alone\" — the layers \
             intersect, so it is DENY. An empty allowlist is `no_rule`, a missing spend block is \
             \"may not spend\" and a missing turn budget is an employee that never wakes. Write \
             the value you mean, including `[]` and `null` where you mean nothing. The quickest \
             complete starting point is what `agentos-server policy install` prints back: it is a \
             whole layer, and every layer here is a whole layer.",
            missing.join(", ")
        ));
    }

    // Every constructor in the domain is a checked one, so this rejects an
    // incoherent layer — an approval threshold above the per-transaction cap, a
    // zero amount, a domain that is not a host — before a row is written rather
    // than on every load afterwards.
    serde_json::from_value(value.clone()).map_err(|err| format!("not a policy layer: {err}"))
}

// ---------------------------------------------------------------------------
// A tenant, and the layers it writes for itself
// ---------------------------------------------------------------------------

/// `policy new-tenant` — the tenant row **and** the active policy version its
/// layers hang off, in one transaction.
///
/// Both, because the pair is the invariant: a tenant with no active version has
/// invisible layers. `store::policy::create_tenant` is where the argument lives
/// and where the two rows are written together; this is the door.
async fn new_tenant(url: &str, tenant: TenantId, slug: &str, name: &str) -> Result<String, String> {
    let db = connect(url).await?;
    let version = policy::create_tenant(&db, tenant, slug, name)
        .await
        .map_err(|err| match err {
            // The slug or the id is taken. Both are worth naming, because the
            // second one is the interesting case: an operator re-running the
            // command with the same `--id` after a half-finished setup.
            StoreError::Conflict(what) => format!(
                "a tenant with this id or slug already exists ({what}). \
                 `new-tenant` creates; it does not adopt."
            ),
            err => store_error("could not create the tenant", err),
        })?;
    let id = tenant.as_uuid();

    Ok(format!(
        "created tenant {slug} ({name}) as {id}, with active policy version {version}.\n\n\
         That version is empty on purpose: a tenant with no layer of its own inherits the \
         platform ceiling, which is the widest it can be and still bounded. Narrow it with\n\n  \
         agentos-server policy install --tenant {id} tenant-layer.json\n\n\
         The API key that speaks for this tenant must carry exactly this id:\n\n  \
         AGENTOS_API_KEYS=\"ops:{id}:$KEY\"\n\n\
         A key naming a tenant with no row is a 500 from the first write that hits the foreign \
         key, so check it before `POST /v1/org`."
    ))
}

/// `policy install --tenant …` — one tenant, role or employee layer, as a new
/// active version of this tenant's policy.
async fn install_layer(
    url: &str,
    tenant: TenantId,
    scope: &ScopeArg,
    path: &Path,
) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let limits = parse_limits_document(&raw).map_err(|err| format!("{}: {err}", path.display()))?;

    let what = scope.describe();
    let label = format!("{what} from {}", path.display());
    let db = connect(url).await?;
    let installed = policy::install_layer(&db, tenant, scope.as_scope(), &limits, &label)
        .await
        .map_err(|err| match err {
            // The tenant row, which is the one thing this cannot invent: the id
            // came from an operator's shell and the useful answer names it.
            StoreError::NotFound => format!(
                "no tenant {} in this database. Create it — and the policy version its layers \
                 hang off — with:\n\n  agentos-server policy new-tenant <slug> <name> --id {}",
                tenant.as_uuid(),
                tenant.as_uuid()
            ),
            // The currency guard's message already names both currencies and
            // what installing it would have done; wrapping it would bury that.
            StoreError::Conflict(refusal) => refusal,
            err => store_error(&format!("could not install the {what}"), err),
        })?;
    let json = serde_json::to_string_pretty(&limits).expect("PolicyLimits serialises");
    let id = tenant.as_uuid();

    Ok(match installed {
        Installed::Version(version) => format!(
            "installed {what} for tenant {id} as policy version {version}.\n\n{json}\n\n\
             This layer can only NARROW: the gate intersects platform ∧ tenant ∧ role ∧ \
             employee, taking the minimum of every cap and the intersection of every allowlist, \
             so a number here that is wider than the ceiling is dead rather than dangerous — and \
             an entry the ceiling does not list is unreachable. Read the result back with \
             `GET /v1/employees/{{id}}/turns` or in the audit trail; the gate picks it up on the \
             next action, not the next deploy.\n\n\
             To undo: agentos-server policy rollback --tenant {id}"
        ),
        // Same reason as the ceiling's: re-running the install is what a
        // provisioning script does on every deploy, and "nothing changed" is
        // the answer that makes that safe. Here it is also what makes a
        // half-applied set of role layers repairable by running the whole set
        // again.
        Installed::Unchanged(version) => format!(
            "unchanged: the {what} in policy version {version} already says exactly this. \
             Nothing was written and no new version was created.\n\n{json}"
        ),
    })
}

/// `policy rollback --tenant …` — this tenant's previous policy version, active
/// again.
async fn rollback_layer(url: &str, tenant: TenantId) -> Result<String, String> {
    let db = connect(url).await?;
    let id = tenant.as_uuid();
    match policy::rollback_layer(&db, tenant).await {
        Ok(version) => Ok(format!(
            "rolled back: tenant {id} is on policy version {version} again. The version it \
             replaced is still in `policy_versions` — rolling back twice returns to it.\n\n\
             A rollback WIDENS, which is what an undo is: the layer it removes was a narrowing. \
             It cannot widen past the platform ceiling, which no tenant version can reach."
        )),
        // Unlike the ceiling's rollback, reaching the bottom here is not
        // dangerous — a tenant with no layers inherits the ceiling. It is still
        // worth a sentence, because "nothing happened" is the answer an operator
        // will otherwise assume was a success.
        Err(StoreError::NotFound) => Err(format!(
            "tenant {id} has no earlier policy version to roll back to — either it has never had \
             a layer installed, or this is a tenant id with no row. `agentos-server policy \
             new-tenant` creates the first version; `policy install --tenant {id}` creates the \
             rest."
        )),
        Err(err) => Err(store_error("could not roll back", err)),
    }
}

/// Open the pool, or say which string failed to open it — never the string
/// itself, which carries the password.
async fn connect(url: &str) -> Result<Db, String> {
    Db::connect(url)
        .await
        .map_err(|err| format!("cannot connect to the database in DATABASE_URL: {err}"))
}

/// One database failure this command will meet on its very first run, answered
/// with the fix instead of the SQLSTATE.
///
/// `42P01` is "relation does not exist", which here means the migrations have
/// not run — and they run at boot, not from here (see [`install`]). An operator
/// who reads `relation "policy_layers" does not exist` goes looking for a broken
/// build; the sentence below sends them to the thing that creates it.
fn store_error(doing: &str, err: agentos_store::db::StoreError) -> String {
    let missing_table = matches!(
        &err,
        agentos_store::db::StoreError::Database(err)
            if err.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref()
                == Some("42P01")
    );
    if missing_table {
        return "this database has no policy tables yet. The migrations run when the server \
                boots: start agentos-server once — it will warn that there is no ceiling and \
                report not-ready — then run this."
            .to_owned();
    }
    format!("{doing}: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| (*s).to_owned()).collect()
    }

    /// No database is touched before the arguments make sense, and the failure
    /// for a typo is the usage text rather than a connection error.
    #[tokio::test]
    async fn an_unknown_verb_is_the_usage_text_and_never_a_connection() {
        for bad in [vec![], args(&["insatll"]), args(&["rollback", "v1"])] {
            let err = run(&bad).await.expect_err("should not run");
            assert!(err.contains("usage:"), "{err}");
        }
    }

    /// The JSON an install prints is the file a wider install takes back: an
    /// operator's only path to a bigger ceiling is to edit what was printed, so
    /// a representation that does not round-trip is a dead end they discover
    /// after typing the numbers.
    #[test]
    fn the_printed_ceiling_is_a_file_this_command_accepts() {
        let default = policy::default_ceiling();
        let json = serde_json::to_string_pretty(&default).expect("serialises");
        let back: PolicyLimits = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, default);

        // And the checked constructors are on the way in: an approval threshold
        // above the per-transaction cap is refused here, not at the gate.
        let broken = json.replace("\"minor\": 10000", "\"minor\": 900000");
        assert!(
            serde_json::from_str::<PolicyLimits>(&broken).is_err(),
            "an incoherent ceiling must not parse"
        );

        // And it is a document this command accepts, which is the round trip
        // that matters: `parse_limits_document` demands every field, so a
        // printed ceiling that lost one would be a dead end.
        parse_limits_document(&json).expect("what we print, we must accept");
    }

    /// [`LAYER_FIELDS`] is a hand-written list guarding a `#[serde(default)]`
    /// struct, which is the shape that rots: add a limit to `PolicyLimits` and
    /// the guard silently stops requiring it, so the first document written
    /// after that grants nothing for the new field and nobody is told.
    ///
    /// So the list is asked of serde rather than trusted. This is the test that
    /// turns "we added a limit" into a red build here instead of a quiet zero in
    /// a role layer three months later.
    #[test]
    fn every_field_of_policy_limits_is_named_in_the_completeness_guard() {
        let json = serde_json::to_value(PolicyLimits::default()).expect("serialises");
        let mut serialised: Vec<&str> = json
            .as_object()
            .expect("a struct")
            .keys()
            .map(String::as_str)
            .collect();
        serialised.sort_unstable();

        let mut named = LAYER_FIELDS.to_vec();
        named.sort_unstable();

        assert_eq!(
            serialised, named,
            "LAYER_FIELDS must name every field of PolicyLimits, exactly once"
        );
    }

    /// **The trap `docs/ORIZN.md` exists to prevent, in one assertion.**
    ///
    /// An operator who writes what looks like an edit gets a total replacement,
    /// because `PolicyLimits` is `#[serde(default)]` and its default grants
    /// nothing. The layer below is a plausible thing to type and it silently
    /// costs the role its channels, its domains and its spend. It must not be
    /// accepted, and the refusal must name the fields rather than say "invalid".
    #[test]
    fn a_layer_document_that_omits_a_field_is_refused_by_name() {
        let err = parse_limits_document(r#"{"max_turns_per_day": 30}"#)
            .expect_err("an incomplete layer must not become a row");
        for field in LAYER_FIELDS {
            if field == "max_turns_per_day" {
                continue;
            }
            assert!(err.contains(field), "the refusal must name {field}: {err}");
        }
        assert!(
            err.contains("DENY"),
            "and say what the omission means: {err}"
        );

        // A misspelling is the same failure wearing a hat: serde would drop the
        // key and the layer would be short a limit, so it is reported as the
        // unknown field it is before the missing one it stands in for.
        let complete = serde_json::to_string(&PolicyLimits::default()).expect("serialises");
        let typo = complete.replace("max_turns_per_day", "max_turns_per_dya");
        let err = parse_limits_document(&typo).expect_err("a dropped key is a lost limit");
        assert!(err.contains("max_turns_per_dya"), "{err}");

        // Deliberately empty is not the same as absent, and this is the whole
        // reason the check is on the document rather than on the values: a
        // finance seat with no bank portal and a chair with no channel at all
        // are both real, and both are `[]` written on purpose.
        let deny_everything = parse_limits_document(&complete).expect("empty on purpose is fine");
        assert_eq!(deny_everything, PolicyLimits::default());
    }

    /// The flags, without a database. `--tenant` is the only required one; the
    /// scope defaults to the tenant's own layer because that is the one scope
    /// with nothing to name.
    #[test]
    fn the_layer_flags_name_exactly_one_layer() {
        let tenant = Uuid::now_v7();
        let id = tenant.to_string();
        let employee = Uuid::now_v7().to_string();

        let parse = |raw: &[&str]| parse_layer_args(raw);
        let expect = |raw: &[&str], scope: ScopeArg| {
            let (got_tenant, got_scope, file) = parse(raw).expect("should parse");
            assert_eq!(got_tenant.as_uuid(), tenant);
            assert_eq!(got_scope, scope);
            assert_eq!(file, PathBuf::from("layer.json"));
        };

        expect(&["--tenant", &id, "layer.json"], ScopeArg::Tenant);
        expect(
            &["--tenant", &id, "--role", "sales-development", "layer.json"],
            ScopeArg::Role("sales-development".to_owned()),
        );
        // Order is the operator's business, not ours.
        expect(
            &["layer.json", "--role", "growth", "--tenant", &id],
            ScopeArg::Role("growth".to_owned()),
        );
        expect(
            &["--tenant", &id, "--employee", &employee, "layer.json"],
            ScopeArg::Employee(EmployeeId::from_uuid(
                Uuid::parse_str(&employee).expect("uuid"),
            )),
        );

        // Two scopes is two rows and there is no way to guess which was meant.
        let both = parse(&[
            "--tenant",
            &id,
            "--role",
            "finance",
            "--employee",
            &employee,
            "f",
        ])
        .expect_err("two layers");
        assert!(both.contains("one at a time"), "{both}");

        // A flag that swallowed the next flag as its value is the failure worth
        // catching: `--tenant --role sales` must not become a tenant called
        // "--role".
        for bad in [
            vec!["--tenant"],
            vec!["--tenant", "--role", "sales", "f"],
            vec!["--tenant", "not-a-uuid", "f"],
            // No document, and there is no default layer to fall back on.
            vec!["--tenant", &id],
            vec!["--tenant", &id, "one.json", "two.json"],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn new_tenant_takes_a_slug_a_name_and_optionally_the_key_s_uuid() {
        let id = Uuid::now_v7();
        let (got, slug, name) =
            parse_new_tenant_args(&["orizn", "Orizn", "--id", &id.to_string()]).expect("parses");
        assert_eq!(got.as_uuid(), id);
        assert_eq!((slug.as_str(), name.as_str()), ("orizn", "Orizn"));

        // Without `--id` one is minted, because a scratch deployment should not
        // have to invent a uuid before it can start.
        let (minted, _, _) = parse_new_tenant_args(&["orizn", "Orizn"]).expect("parses");
        assert_ne!(minted.as_uuid(), id);

        for bad in [
            vec!["orizn"],
            vec!["Not A Slug", "Orizn"],
            vec!["orizn", "   "],
            vec!["orizn", "Orizn", "--id", "nope"],
        ] {
            assert!(parse_new_tenant_args(&bad).is_err(), "{bad:?}");
        }
    }

    // -- the whole sequence, from an empty database -------------------------

    use agentos_domain::action::{
        Action, ActionCtx, Actor, Channel, ContactStanding, Domain, EmailAddress,
    };
    use agentos_domain::money::{Currency, Money};
    use agentos_domain::policy::{Decision, DenyReason, SpendLimits, evaluate, turns_remaining};
    use agentos_domain::untrusted::TrustLabel;

    fn usd(minor: u64) -> Money {
        Money::new(minor, Currency::Usd).expect("non-zero")
    }

    fn domain(raw: &str) -> Domain {
        Domain::parse(raw).expect("a host")
    }

    /// Write one layer document where the command will read it. Serialised from
    /// the type rather than hand-written, so every field is present — which is
    /// also what [`parse_limits_document`] is about to insist on.
    fn document(dir: &Path, name: &str, limits: &PolicyLimits) -> PathBuf {
        let path = dir.join(format!("{name}.json"));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(limits).expect("serialises"),
        )
        .expect("write the layer document");
        path
    }

    /// **`docs/ORIZN.md`, executed — the three steps that used to be `psql`.**
    ///
    /// Empty database → ceiling → tenant (and the policy version nothing else
    /// created) → tenant layer → role layer → employee layer → an action that
    /// could not even be *ruled on* before is now allowed, and one the employee
    /// layer took away comes back on rollback.
    ///
    /// It drives the command's own functions rather than the store's, because
    /// the thing being tested is the operator's path: the document parse, the
    /// refusals, the messages and the order. `run` itself is not called only
    /// because it reads `DATABASE_URL` from the process environment, and this
    /// test owns a database of its own precisely so it does not have to fight
    /// another test over one.
    #[tokio::test]
    async fn the_whole_sequence_from_an_empty_database() {
        let Some((db, admin_url, database)) = crate::tests::own_database("policy_seq").await else {
            return;
        };
        let (base_url, _) = admin_url.rsplit_once('/').expect("admin url has a path");
        let url = format!("{base_url}/{database}");

        let dir = std::env::temp_dir().join(format!("policy-seq-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        // The ceiling Orizn's runbook argues for, in miniature.
        let ceiling = PolicyLimits {
            spend: Some(
                SpendLimits::try_new(usd(50_000), usd(200_000), usd(100)).expect("coherent"),
            ),
            allowed_channels: [Channel::Email, Channel::Internal, Channel::Web].into(),
            allowed_domains: [domain("orizn.app")].into(),
            max_new_contacts_per_day: 20,
            max_turns_per_day: 30,
            ..PolicyLimits::default()
        };

        let now = chrono::Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let browse = Action::BrowserRead {
            domain: domain("docs.orizn.app"),
        };
        let email = Action::EmailSend {
            to: EmailAddress::parse("buyer@orizn.app").expect("address"),
        };
        let ctx = ActionCtx {
            trust: TrustLabel::Trusted,
            contact: ContactStanding::Known,
            ..ActionCtx::new(Actor::new(tenant, employee), now)
        };

        // --- 1. an empty database rules on nothing at all ------------------
        //
        // `platform_ceiling_installed` is the predicate `/readyz` answers with
        // (`policy::CEILING_EXISTS_SQL`), so this *is* the probe, minus the
        // HTTP that `main`'s own test already covers.
        assert!(
            !policy::platform_ceiling_installed(&db)
                .await
                .expect("probe"),
            "a fresh database has no ceiling and /readyz must be red"
        );

        // --- 2. the ceiling ------------------------------------------------
        let said = install(&url, Some(&document(&dir, "ceiling", &ceiling)))
            .await
            .expect("install the ceiling");
        assert!(said.contains("installed platform ceiling"), "{said}");
        assert!(
            policy::platform_ceiling_installed(&db)
                .await
                .expect("probe"),
            "/readyz has to be green on the ceiling alone"
        );

        // --- 3. the tenant, and the policy version nothing else created ----
        let said = new_tenant(&url, tenant, "orizn", "Orizn")
            .await
            .expect("create the tenant");
        assert!(said.contains(&tenant.as_uuid().to_string()), "{said}");
        assert!(
            said.contains("active policy version"),
            "the operator has to be told the version exists, because its absence is silent: {said}"
        );

        // The seat those layers will apply to. `POST /v1/org` is what mints one
        // in the runbook; this test is about the policy rows, so the row is
        // written directly and nothing about it is asserted.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'sdr', 'sdr', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert the employee");
        tx.commit().await.expect("commit");

        // And a seat pointing at the role layer this test is about to write.
        // Not decoration: a role layer reaches an employee through
        // `team_policy` and through nothing else, so an employee with no seat
        // sees no role layer at all and the assertions below would be reading
        // the tenant's numbers while claiming to read the role's. This used to
        // be bought by passing the role name to `load`, an argument that has
        // since been deleted because no production caller ever passed one.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let desk = agentos_store::org::create_team(
            &mut tx,
            &agentos_domain::ids::Slug::parse("sdr").expect("slug"),
            "SDR",
        )
        .await
        .expect("create the team");
        agentos_store::org::set_member(&mut tx, employee, desk, None)
            .await
            .expect("seat the employee");
        agentos_store::org::set_policy_role(&mut tx, desk, "sales-development")
            .await
            .expect("point the team at the role layer");
        tx.commit().await.expect("commit the seat");

        // --- 4, 5, 6. the three layers no route and no command used to write -
        let ruling = async |db: &Db, action: &Action| {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let loaded = policy::load(&mut tx, employee).await;
            tx.rollback().await.expect("rollback");
            loaded.map(|effective| (evaluate(&effective, action, &ctx), effective))
        };

        let tenant_layer = PolicyLimits {
            spend: Some(
                SpendLimits::try_new(usd(50_000), usd(100_000), usd(100)).expect("coherent"),
            ),
            // `Web` kept: this layer narrows spending and nothing else about
            // reach, and browsing is a channel now — dropping it here would
            // have made the tenant layer the thing that took the web away and
            // hidden the employee layer's mistake below.
            allowed_channels: [Channel::Email, Channel::Internal, Channel::Web].into(),
            ..ceiling.clone()
        };
        install_layer(
            &url,
            tenant,
            &ScopeArg::Tenant,
            &document(&dir, "tenant", &tenant_layer),
        )
        .await
        .expect("the tenant layer");

        let role_layer = PolicyLimits {
            spend: None,
            max_new_contacts_per_day: 0,
            ..tenant_layer.clone()
        };
        install_layer(
            &url,
            tenant,
            &ScopeArg::Role("sales-development".to_owned()),
            &document(&dir, "role", &role_layer),
        )
        .await
        .expect("the role layer");

        // **The claim, taken while it is still true.** An action that could not
        // be ruled on before step 2 is now allowed — and browsing is the
        // specimen because it is the one this sequence's own layers go on to
        // take away. It is asserted here, after the role layer, rather than
        // after the employee layer below: reading is a channel now, so the
        // "mistake" that layer makes costs the web as well as email, and
        // asserting `Allow` afterwards would have been asserting that the
        // mistake did not happen.
        let (allowed, _) = ruling(&db, &browse).await.expect("a policy exists now");
        assert_eq!(
            allowed,
            Decision::Allow,
            "reading our own docs was `broken_policy` before step 2 and must be Allow now"
        );

        // The employee layer tightens two things, and the second one is the
        // mistake an operator makes: a restated turn budget that quietly drops
        // a channel. Both are asserted below, and the rollback is the fix.
        let employee_layer = PolicyLimits {
            allowed_channels: [Channel::Internal].into(),
            max_turns_per_day: 5,
            ..role_layer.clone()
        };
        install_layer(
            &url,
            tenant,
            &ScopeArg::Employee(employee),
            &document(&dir, "employee", &employee_layer),
        )
        .await
        .expect("the employee layer");

        // --- and what the mistake cost -------------------------------------
        //
        // Two channels, not one. Restating `[Channel::Internal]` to tighten a
        // turn budget drops email *and* the web, and the second is the one an
        // operator would not think of as a channel at all — which is exactly
        // why it is asserted here, one line above the column that explains it.
        let (after_the_mistake, effective) = ruling(&db, &browse).await.expect("a policy");
        assert_eq!(
            after_the_mistake,
            Decision::Deny {
                reason: DenyReason::ChannelNotAllowed
            },
            "the employee layer kept only the internal channel, so it cannot browse"
        );
        // Every layer bound, and the tightest one won each column.
        assert_eq!(effective.limits().max_turns_per_day, 5);
        assert_eq!(turns_remaining(&effective, 5), 0);
        assert_eq!(effective.limits().max_new_contacts_per_day, 0);
        assert!(
            effective.limits().spend.is_none(),
            "the role layer permits no spending, and no lower layer can put it back"
        );
        assert_eq!(
            effective.limits().allowed_channels,
            [Channel::Internal].into(),
            "web came from the ceiling and email from the tenant; the employee layer kept neither"
        );

        // --- applying the same layer twice is not a change ------------------
        let before: Vec<Uuid> = active_versions(&db, tenant).await;
        let said = install_layer(
            &url,
            tenant,
            &ScopeArg::Role("sales-development".to_owned()),
            &document(&dir, "role", &role_layer),
        )
        .await
        .expect("the same role layer again");
        assert!(said.contains("unchanged"), "{said}");
        assert_eq!(
            active_versions(&db, tenant).await,
            before,
            "re-applying a layer must not mint a version"
        );

        // --- the undo ------------------------------------------------------
        let (denied, _) = ruling(&db, &email).await.expect("a policy");
        assert_eq!(
            denied,
            Decision::Deny {
                reason: DenyReason::ChannelNotAllowed
            },
            "the employee layer took email away, which is the trap this is about"
        );

        let said = rollback_layer(&url, tenant).await.expect("roll it back");
        assert!(said.contains("rolled back"), "{said}");
        let (restored, effective) = ruling(&db, &email).await.expect("a policy");
        assert_eq!(
            restored,
            Decision::Allow,
            "rollback has to change the gate's ruling, not just a row"
        );
        assert_eq!(effective.limits().max_turns_per_day, 30);
        assert_eq!(
            active_versions(&db, tenant).await.len(),
            1,
            "a rollback is a pointer flip"
        );

        // --- and a second currency is refused, naming both ------------------
        let euros = PolicyLimits {
            spend: Some(
                SpendLimits::try_new(
                    Money::new(10_000, Currency::Eur).expect("money"),
                    Money::new(40_000, Currency::Eur).expect("money"),
                    Money::new(100, Currency::Eur).expect("money"),
                )
                .expect("coherent"),
            ),
            ..role_layer.clone()
        };
        let refusal = install_layer(
            &url,
            tenant,
            &ScopeArg::Role("finance".to_owned()),
            &document(&dir, "euros", &euros),
        )
        .await
        .expect_err("EUR under a USD ceiling");
        assert!(
            refusal.contains("EUR") && refusal.contains("USD"),
            "the refusal must name both currencies: {refusal}"
        );

        // --- and a tenant id with no row says how to make one ---------------
        let ghost = install_layer(
            &url,
            TenantId::new_v7(chrono::Utc::now()),
            &ScopeArg::Tenant,
            &document(&dir, "tenant", &tenant_layer),
        )
        .await
        .expect_err("no such tenant");
        assert!(ghost.contains("new-tenant"), "{ghost}");

        let _ = std::fs::remove_dir_all(&dir);
        crate::tests::drop_database(db, admin_url, database).await;
    }

    /// This tenant's active policy versions. The `tenant_id` predicate is not
    /// redundant with RLS: `0006_policy.sql` deliberately lets every tenant
    /// *read* the platform rows, because the loader needs the ceiling.
    async fn active_versions(db: &Db, tenant: TenantId) -> Vec<Uuid> {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let ids =
            sqlx::query_scalar("SELECT id FROM policy_versions WHERE active AND tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_all(&mut **tx)
                .await
                .expect("read versions");
        tx.rollback().await.expect("rollback");
        ids
    }
}
