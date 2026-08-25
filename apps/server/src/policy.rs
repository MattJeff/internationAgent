//! `agentos-server policy install` / `policy rollback` — the platform ceiling,
//! installed and undone without a database console.
//!
//! The gate is fail-closed: with no `platform` layer `store::policy::load`
//! answers `NoPlatformLayer`, every action for every tenant is denied, `main`
//! warns at boot and `/readyz` refuses. Everything about that was already true
//! and visible. What did not exist was a way to *fix* it — no route writes
//! `policy_layers` at all — so a fresh install could not be made to work without
//! hand-written SQL. This is that missing half.
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

use std::path::Path;
use std::process::ExitCode;

use agentos_domain::policy::PolicyLimits;
use agentos_store::db::Db;
use agentos_store::policy::{self, Installed};

/// Printed on anything this module does not understand. It is also the whole
/// documentation of the command that an operator will actually read.
const USAGE: &str = "\
usage: agentos-server policy install [ceiling.json]
       agentos-server policy rollback

  install   make a platform policy ceiling active. With no file, installs the
            documented default. Re-running the same ceiling changes nothing.
  rollback  make the previous ceiling active again.

Both read DATABASE_URL and nothing else.";

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
        ["install", file] => install(&database_url()?, Some(Path::new(file))).await,
        ["rollback"] => rollback(&database_url()?).await,
        // Including the empty case: `agentos-server policy` on its own is
        // somebody asking what this does.
        _ => Err(USAGE.to_owned()),
    }
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
            let limits: PolicyLimits = serde_json::from_str(&raw)
                .map_err(|err| format!("{}: not a policy ceiling: {err}", path.display()))?;
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
    }
}
