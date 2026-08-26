//! `agentos-server flow` — the selectors on one prospect's booking page, and
//! the name of the human who opened it.
//!
//! `agentos_app::proof_of_need` runs a passport/destination pair through a
//! prospect's own booking flow and writes down what it said. It needs a `Flow`:
//! an entry URL and five CSS selectors. Nothing in this product produced one
//! outside tests, and `loops/initiative.rs` said so in the comment where the
//! sales employee's turn should have been.
//!
//! # Why the selectors are typed by a person
//!
//! A selector that matches **nothing** is safe: it comes back
//! `NO_SUCH_ELEMENT`, the check fails loudly and no claim is made. A selector
//! that matches the **wrong element** is not, and nothing downstream can catch
//! it — both runs read the same wrong element, both agree byte for byte, the
//! reproducibility bar is satisfied, a screenshot is taken, and an email goes out
//! telling an airline that its checkout said something a cookie banner said.
//! That email names a date and lists the steps to see it again, so a prospect who
//! follows them and sees something else has been sent, in writing, a false
//! statement about their own product.
//!
//! So the thing this command records is not "these are the selectors". It is
//! **somebody opened the page and checked**, which is why there are two verbs
//! rather than one: [`set`](run) writes the selectors and always leaves the row
//! unconfirmed, and `confirm` puts a name on it. Editing a selector revokes the
//! confirmation — here, and in a trigger in `0032_prospect_flows.sql`, so it is
//! also true of a `psql` session.
//!
//! # Why a subcommand and not a route
//!
//! `apps/server/src/policy.rs` argues this at length and every line of it
//! applies. The short version, plus the one part that is stronger here:
//! `0032_prospect_flows.sql` grants `app_role` no INSERT and no UPDATE on this
//! table, so there is no path from the running server to a row in it at all. An
//! employee that could write a flow could point a selector at any element on a
//! domain its policy already lets it read, and then produce a screenshotted,
//! reproducible finding about whatever that element happened to say — the
//! confirmation bar and the browser allowlist would both be satisfied. Writing a
//! flow is an operator's act, and the proof this deployment has that you are the
//! operator is `DATABASE_URL`.
//!
//! # What it does not do
//!
//! It does not check that the selectors are right. It cannot: that is what the
//! person named in `--by` is for.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentos_domain::ids::TenantId;
use agentos_store::db::Db;
use agentos_store::revenue::{self, NewProspectFlow, RevenueError};
use chrono::Utc;
use uuid::Uuid;

/// Printed on anything this module does not understand, and the whole of the
/// documentation an operator will actually read.
const USAGE: &str = "\
usage: agentos-server flow set --tenant <uuid> --account <uuid> <flow.json>
       agentos-server flow confirm --tenant <uuid> --account <uuid> --by <name>

  set        write the selectors for one prospect's booking page. The row is
             always left UNCONFIRMED, and re-writing a confirmed one revokes
             the confirmation: the point of a confirmation is that somebody
             looked at these exact selectors.
  confirm    record that <name> opened the page and checked that each selector
             points at what it says. Nothing probes a prospect's flow until
             this has been run for it.

The document is a JSON object:

  {
    \"entry_url\":         \"https://book.example.com/entry-requirements\",
    \"passport_field\":    \"#passport\",
    \"destination_field\": \"#destination\",
    \"date_field\":        \"#travel-date\",
    \"submit\":            \"#check\",
    \"panel\":             \"#visa-info\"
  }

`date_field` and `submit` may be omitted when the flow has neither. `submit` is
their CHECK REQUIREMENTS button and never a booking or payment submit; nothing
in this system can tell those apart. `entry_url` must be https and on the
account's own domain. `panel` is the element that displays the answer: point it
at the answer widget, not at a container with a clock in it — a selector wide
enough to catch a timestamp is wide enough to catch the wrong sentence.

Both verbs read DATABASE_URL and nothing else: writing a selector is proved by
the operator's own database credential, never by an API key. See this module's
docs for why.";

/// What is printed after a confirm, because this is the one field in the
/// product whose value is entirely that a person vouched for it.
const CAVEAT: &str = "\
This is a CONFIRMATION, not a save. It says you opened the page and checked that
each selector points at the element it claims to. Nothing else in this system
can check that: a selector aimed at the wrong element still resolves, still reads
the same text on both runs, still passes the reproducibility bar and still gets
screenshotted into an email that tells this company what its own checkout said.
If you did not look, run `flow set` again to clear this.";

/// The document. `deny_unknown_fields` because a mistyped key here is a selector
/// silently missing from a probe, and `panel` spelled `pannel` would leave the
/// row with an empty answer widget the constraint would then reject with a
/// constraint name instead of a sentence.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    entry_url: String,
    passport_field: String,
    destination_field: String,
    #[serde(default)]
    date_field: Option<String>,
    #[serde(default)]
    submit: Option<String>,
    panel: String,
}

/// Run the subcommand and exit non-zero on anything that did not happen.
///
/// A current-thread runtime, for `policy::main`'s reason: this is one command
/// with two round trips.
pub fn main(args: &[String]) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("agentos-server flow: could not start a tokio runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args)) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(err) if err.starts_with("usage:") => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("agentos-server flow: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The command as a value rather than a process exit, so the argument parsing
/// and the messages are testable without a database.
async fn run(args: &[String]) -> Result<String, String> {
    let verbs: Vec<&str> = args.iter().map(String::as_str).collect();
    match verbs.as_slice() {
        ["set", rest @ ..] if !rest.is_empty() => {
            let (tenant, account, file) = parse_set_args(rest)?;
            set(&database_url()?, tenant, account, &file).await
        }
        ["confirm", rest @ ..] if !rest.is_empty() => {
            let (tenant, account, who) = parse_confirm_args(rest)?;
            confirm(&database_url()?, tenant, account, &who).await
        }
        _ => Err(USAGE.to_owned()),
    }
}

/// A uuid an operator typed, or the usage text — never a connection attempt.
fn uuid_arg(flag: &str, raw: &str) -> Result<Uuid, String> {
    Uuid::parse_str(raw).map_err(|err| format!("{flag} {raw:?} is not a uuid: {err}\n\n{USAGE}"))
}

/// The argument after the flag at `args[i]`. Every flag here takes a value, so
/// `--account --by ines` failing is better than an account id of `"--by"`.
fn flag_value<'a>(args: &[&'a str], i: usize) -> Result<&'a str, String> {
    args.get(i + 1)
        .copied()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| format!("{} needs a value.\n\n{USAGE}", args[i]))
}

/// `--tenant <uuid> --account <uuid> <flow.json>`, in any order.
fn parse_set_args(args: &[&str]) -> Result<(TenantId, Uuid, PathBuf), String> {
    let mut tenant: Option<TenantId> = None;
    let mut account: Option<Uuid> = None;
    let mut file: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i];
        match flag {
            "--tenant" => {
                tenant = Some(TenantId::from_uuid(uuid_arg(flag, flag_value(args, i)?)?));
                i += 2;
            }
            "--account" => {
                account = Some(uuid_arg(flag, flag_value(args, i)?)?);
                i += 2;
            }
            _ if flag.starts_with('-') => return Err(USAGE.to_owned()),
            _ => {
                if file.is_some() {
                    return Err(format!(
                        "one flow document per prospect; got {flag:?} as well.\n\n{USAGE}"
                    ));
                }
                file = Some(PathBuf::from(flag));
                i += 1;
            }
        }
    }

    Ok((
        tenant.ok_or_else(|| USAGE.to_owned())?,
        account.ok_or_else(|| USAGE.to_owned())?,
        file.ok_or_else(|| {
            format!("a flow document is required; there is no default flow.\n\n{USAGE}")
        })?,
    ))
}

/// `--tenant <uuid> --account <uuid> --by <name>`, in any order.
fn parse_confirm_args(args: &[&str]) -> Result<(TenantId, Uuid, String), String> {
    let mut tenant: Option<TenantId> = None;
    let mut account: Option<Uuid> = None;
    let mut who: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i];
        match flag {
            "--tenant" => {
                tenant = Some(TenantId::from_uuid(uuid_arg(flag, flag_value(args, i)?)?));
                i += 2;
            }
            "--account" => {
                account = Some(uuid_arg(flag, flag_value(args, i)?)?);
                i += 2;
            }
            "--by" => {
                who = Some(flag_value(args, i)?.trim().to_owned());
                i += 2;
            }
            _ => return Err(USAGE.to_owned()),
        }
    }

    let who = who.filter(|name| !name.is_empty()).ok_or_else(|| {
        format!(
            "--by is required and is a person's name. A confirmation whose author is \"\" is a \
             confirmation nobody made.\n\n{USAGE}"
        )
    })?;
    Ok((
        tenant.ok_or_else(|| USAGE.to_owned())?,
        account.ok_or_else(|| USAGE.to_owned())?,
        who,
    ))
}

/// Parse the document. Separated from [`set`] because the shape of it is the
/// half worth testing without a database, and the half a typo lands in.
fn parse_document(raw: &str) -> Result<Document, String> {
    serde_json::from_str(raw).map_err(|err| format!("not a flow document: {err}"))
}

async fn set(url: &str, tenant: TenantId, account: Uuid, path: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let doc = parse_document(&raw).map_err(|err| format!("{}: {err}", path.display()))?;

    let db = connect(url).await?;
    revenue::set_prospect_flow(
        &db,
        tenant,
        account,
        &NewProspectFlow {
            entry_url: &doc.entry_url,
            passport_field: &doc.passport_field,
            destination_field: &doc.destination_field,
            date_field: doc.date_field.as_deref(),
            submit: doc.submit.as_deref(),
            panel: &doc.panel,
        },
    )
    .await
    .map_err(|err| write_error(tenant, account, err))?;

    Ok(format!(
        "wrote the flow for account {account} from {}.\n\n\
         It is UNCONFIRMED, so nothing will probe it. Open {} and check that each selector \
         points at what it says, then:\n\n  \
         agentos-server flow confirm --tenant {} --account {account} --by <your name>",
        path.display(),
        doc.entry_url,
        tenant.as_uuid(),
    ))
}

async fn confirm(url: &str, tenant: TenantId, account: Uuid, who: &str) -> Result<String, String> {
    let db = connect(url).await?;
    let found = revenue::confirm_prospect_flow(&db, tenant, account, who, Utc::now())
        .await
        .map_err(|err| write_error(tenant, account, err))?;

    if !found {
        return Err(format!(
            "no flow for account {account} in tenant {}. Write one first:\n\n  \
             agentos-server flow set --tenant {} --account {account} <flow.json>",
            tenant.as_uuid(),
            tenant.as_uuid(),
        ));
    }

    Ok(format!(
        "{who} confirmed the flow for account {account}.\n\n{CAVEAT}"
    ))
}

/// The one message worth writing by hand: an account id that is not in this
/// tenant. The composite foreign key is what refuses it, and the operator's
/// answer is a different uuid rather than a different command.
fn write_error(tenant: TenantId, account: Uuid, err: RevenueError) -> String {
    let foreign_key = matches!(
        &err,
        RevenueError::Store(agentos_store::db::StoreError::Database(err))
            if err.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref()
                == Some("23503")
    );
    if foreign_key {
        return format!(
            "there is no account {account} in tenant {}. A flow belongs to a prospect; \
             `accounts.id` is the uuid to pass, and `accounts.domain` is where the flow's \
             entry URL has to be.",
            tenant.as_uuid()
        );
    }
    format!("could not write the flow for account {account}: {err}")
}

fn database_url() -> Result<String, String> {
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| {
            "DATABASE_URL is not set. This command writes a selector with the operator's own \
             database credentials — that is its whole authorisation story."
                .to_owned()
        })
}

/// Connect. It does not migrate, for `policy`'s reason: the server applies
/// migrations at boot under an advisory lock, and a second migration path that
/// runs from a CLI is a second thing that can be halfway through when the first
/// starts.
async fn connect(url: &str) -> Result<Db, String> {
    Db::connect(url)
        .await
        .map_err(|err| format!("could not connect to the database: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The two verbs, and everything else comes back with the usage text.
    ///
    /// The argument parse happens before [`database_url`], so none of these
    /// opens a connection to find out that it was not a command — which is also
    /// why this test needs no database.
    #[tokio::test]
    async fn anything_that_is_not_one_of_the_two_verbs_is_the_usage_text() {
        for bad in [vec![], args(&["show"]), args(&["set"]), args(&["confirm"])] {
            let err = run(&bad).await.expect_err("not a command");
            assert!(err.starts_with("usage:"), "{bad:?} -> {err}");
        }

        // A flag with no value says which flag, and then the usage text: a
        // tenant id of `"--account"` is worse than a refusal.
        let err = run(&args(&["set", "--tenant", "--account", "x"]))
            .await
            .expect_err("--tenant ate a flag");
        assert!(err.starts_with("--tenant needs a value"), "{err}");
        assert!(err.contains("usage: agentos-server flow"), "{err}");
    }

    /// `--by` is the whole point of the confirm verb, so an empty one is not a
    /// confirmation with a blank field, it is not a confirmation.
    #[test]
    fn a_confirmation_needs_a_person() {
        let err = parse_confirm_args(&[
            "--tenant",
            "0198f2a4-0000-7000-8000-000000000001",
            "--account",
            "0198f2a4-0000-7000-8000-000000000002",
            "--by",
            "   ",
        ])
        .expect_err("a blank name");
        assert!(err.contains("--by is required"), "{err}");

        let (_, _, who) = parse_confirm_args(&[
            "--by",
            "Mathis",
            "--tenant",
            "0198f2a4-0000-7000-8000-000000000001",
            "--account",
            "0198f2a4-0000-7000-8000-000000000002",
        ])
        .expect("in any order");
        assert_eq!(who, "Mathis");
    }

    /// A misspelled key is a selector missing from a probe. serde would drop it
    /// silently; `deny_unknown_fields` is what makes it a message.
    #[test]
    fn a_misspelled_selector_key_is_refused_rather_than_dropped() {
        let err = parse_document(
            r##"{"entry_url":"https://x.example/e","passport_field":"#p",
                "destination_field":"#d","pannel":"#v"}"##,
        )
        .expect_err("pannel");
        assert!(err.contains("pannel"), "{err}");

        // And the two optional ones really are optional.
        let doc = parse_document(
            r##"{"entry_url":"https://x.example/e","passport_field":"#p",
                "destination_field":"#d","panel":"#v"}"##,
        )
        .expect("a flow with no date field and no submit");
        assert_eq!(doc.date_field, None);
        assert_eq!(doc.submit, None);
    }
}
