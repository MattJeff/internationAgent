//! `agentos-server import` — the founder's prospect lists, become rows.
//!
//! The whole command is [`agentos_app::prospects::import`]; this is argument
//! parsing, one transaction, and a report. Read that module for what an import
//! does, what it refuses, and what it cannot store. Read this one for why it is
//! a subcommand.
//!
//! # Why a subcommand and not a route
//!
//! [`crate::policy`] argues the general case at length and half of it applies
//! here. Not the escalation half: `accounts` and `contacts` are tenant rows,
//! `Db::tenant_tx` pins them, RLS enforces it, and a route under `/v1/...` would
//! write only rows the caller already owns. So the objection that kills a policy
//! route does not kill this one.
//!
//! Three other things do.
//!
//! **The files are on the founder's laptop.** That is the fact that decides it.
//! A route means uploading them: a multipart body nothing else in this API
//! takes, a size limit to pick, a temporary file on a server that has no reason
//! to hold 1,600 people's contact details for even a minute, and a second copy
//! of a list whose canonical home is a directory on a Mac. A subcommand reads
//! the file where it already is, over a connection the operator already has.
//!
//! **An API key is not the right proof for a bulk write.** Every route here
//! derives its tenant from a bearer token, and `AGENTOS_API_KEYS` is a static
//! operator-written keyring — so today the key *is* the operator and a route
//! would be defensible. The day it is not, a route that writes a thousand
//! contacts and sets them all due for outreach is the most valuable endpoint in
//! the binary to steal. `DATABASE_URL` keeps working through that change.
//!
//! **This is not a thing that happens on a schedule.** It is a person, once per
//! list, watching the report — the counts of what could not be stored are the
//! output, and a 200 with a JSON body is a worse place to read them than a
//! terminal.
//!
//! What would change the answer: a hosted console where the founder is not the
//! operator and drags a CSV into a browser. Build it then, on
//! `agentos_app::prospects::import`, which is a library function taking a
//! `&str` precisely so that the route is a body reader and nothing else.
//!
//! # `--dry-run`
//!
//! Not a luxury. The first run of this command writes a four-figure number of
//! rows into tables that have been empty in production since they were created,
//! and every judgement it makes — which domain identifies an account, which
//! rows are refused, how many phone numbers are dropped — is in the report it
//! prints either way. `--dry-run` rolls the transaction back instead of
//! committing it, so the report can be read before it is true.

use std::path::Path;
use std::process::ExitCode;

use agentos_app::prospects::{self, ImportError, List, Report, UNKNOWN_COUNTRY};
use agentos_domain::ids::TenantId;
use agentos_store::db::Db;
use chrono::Utc;
use uuid::Uuid;

/// Printed on anything this module does not understand, and the whole
/// documentation of the command an operator will actually read.
const USAGE: &str = "\
usage: agentos-server import --tenant <uuid> --segment <name> [--country <XX>] [--dry-run] <file.csv>...

  --tenant     whose pipeline these prospects join.
  --segment    airline | ota | corporate_travel | tmc | insurer | cruise |
               relocation | other. Not guessed from the filename.
  --country    ISO 3166-1 alpha-2 for every account in these files. Right for a
               single-country list (--country PH over the DMW file); leave it
               out for a worldwide one and each account keeps its location
               string with country ZZ.
  --dry-run    do everything, print the report, commit nothing.

Files are Smartlead exports: email,first_name,last_name,company_name,
phone_number,website,linkedin_profile,location. Several files in one run are
one transaction, and running the same file twice writes nothing the second
time. Reads DATABASE_URL and nothing else.";

/// Run the subcommand and exit non-zero on anything that did not happen.
///
/// A current-thread runtime, like `policy`: one command, a few hundred round
/// trips, and a worker pool for that starts threads before the argument parse
/// has decided there is anything to do.
pub fn main(args: &[String]) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("agentos-server import: could not start a tokio runtime: {err}");
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
            eprintln!("agentos-server import: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The command as a value rather than a process exit, so the parsing and the
/// messages are testable without a database.
async fn run(args: &[String]) -> Result<String, String> {
    let parsed = parse(args)?;
    let url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .ok_or(
            "DATABASE_URL is not set. This command writes a tenant's prospects with the \
             operator's own database credentials — that is its whole authorisation story.",
        )?;

    // Read every file before opening a transaction: a typo in the last path
    // should not leave the first list half-imported, and reading is free.
    let mut files = Vec::new();
    for path in &parsed.files {
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("{}: {err}", Path::new(path).display()))?;
        files.push((path.clone(), text));
    }

    let db = Db::connect(&url)
        .await
        .map_err(|err| format!("cannot connect to the database in DATABASE_URL: {err}"))?;
    let mut tx = db
        .tenant_tx(parsed.tenant)
        .await
        .map_err(|err| store_error("could not open a transaction", &err))?;

    let list = List {
        segment: &parsed.segment,
        country: &parsed.country,
        employee_id: None,
    };
    let now = Utc::now();
    let mut out = String::new();
    let mut total = Report::default();

    for (path, text) in &files {
        let report = prospects::import(&mut tx, &list, text, now)
            .await
            .map_err(|err| import_error(path, &err))?;
        out.push_str(&format!("{path}\n{}\n\n", indent(&report.summary())));
        total.rows += report.rows;
        total.accounts_created += report.accounts_created;
        total.contacts_created += report.contacts_created;
    }

    if parsed.dry_run {
        tx.rollback()
            .await
            .map_err(|err| format!("could not roll back: {err}"))?;
        out.push_str(&format!(
            "DRY RUN: nothing was written. {} accounts and {} contacts would be created from \
             {} rows.",
            total.accounts_created, total.contacts_created, total.rows
        ));
    } else {
        tx.commit()
            .await
            .map_err(|err| format!("could not commit: {err}"))?;
        out.push_str(&format!(
            "committed: {} accounts and {} contacts created from {} rows.",
            total.accounts_created, total.contacts_created, total.rows
        ));
        // Only when there are new people to say it about: "they are due now"
        // after a run that created nobody is a sentence about the last run.
        if total.contacts_created > 0 {
            out.push_str(
                " The new contacts are due for follow-up now; `max_new_contacts_per_day` \
                 meters them out, and it ships at 0.",
            );
        } else {
            out.push_str(" Everything in these files was already on file.");
        }
    }
    Ok(out)
}

/// The arguments, owned, after they have all been understood.
#[derive(Debug, PartialEq, Eq)]
struct Parsed {
    tenant: TenantId,
    segment: String,
    country: String,
    dry_run: bool,
    files: Vec<String>,
}

/// Hand-rolled, like `policy`'s: four flags and a list of paths, and the
/// workspace has no argument-parsing dependency to reach for.
fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut tenant = None;
    let mut segment = None;
    let mut country = UNKNOWN_COUNTRY.to_owned();
    let mut dry_run = false;
    let mut files = Vec::new();

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = |name: &str| {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value\n\n{USAGE}"))
        };
        match arg.as_str() {
            "--tenant" => {
                let raw = value("--tenant")?;
                tenant = Some(TenantId::from_uuid(Uuid::parse_str(&raw).map_err(
                    |err| format!("--tenant {raw:?} is not a uuid: {err}\n\n{USAGE}"),
                )?));
            }
            "--segment" => segment = Some(value("--segment")?),
            "--country" => country = value("--country")?.to_ascii_uppercase(),
            "--dry-run" => dry_run = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}\n\n{USAGE}"));
            }
            path => files.push(path.to_owned()),
        }
    }

    let tenant = tenant.ok_or_else(|| USAGE.to_owned())?;
    let segment = segment.ok_or_else(|| USAGE.to_owned())?;
    if files.is_empty() {
        return Err(USAGE.to_owned());
    }
    Ok(Parsed {
        tenant,
        segment,
        country,
        dry_run,
        files,
    })
}

/// The import's own errors, with the fix rather than the SQLSTATE.
fn import_error(path: &str, err: &ImportError) -> String {
    match err {
        ImportError::Store(agentos_store::revenue::RevenueError::Store(err)) => {
            store_error(&format!("{path}: could not write"), err)
        }
        other => format!("{path}: {other}"),
    }
}

/// The two database failures this command meets on a fresh install, answered
/// with the fix. `42P01` is "no such relation" — the migrations run at boot, not
/// from here — and `42703` is "no such column", which for this command means
/// 0033_prospect_listing.sql has not been applied by a boot yet.
fn store_error(doing: &str, err: &agentos_store::db::StoreError) -> String {
    let code = match err {
        agentos_store::db::StoreError::Database(err) => err
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(|code| code.into_owned()),
        _ => None,
    };
    if matches!(code.as_deref(), Some("42P01" | "42703")) {
        return "this database is missing the revenue tables or the columns \
                0033_prospect_listing.sql adds. The migrations run when the server boots: \
                start agentos-server once, then run this."
            .to_owned();
    }
    format!("{doing}: {err}")
}

/// Two spaces on every line, so one run over five files reads as five blocks.
fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| (*s).to_owned()).collect()
    }

    const TENANT: &str = "01920000-0000-7000-8000-000000000001";

    /// No database is touched before the arguments make sense.
    #[tokio::test]
    async fn an_incomplete_command_is_the_usage_text_and_never_a_connection() {
        let bad = [
            vec![],
            args(&["list.csv"]),
            args(&["--tenant", TENANT, "list.csv"]),
            args(&["--tenant", TENANT, "--segment", "other"]),
            args(&["--tenant", "not-a-uuid", "--segment", "other", "list.csv"]),
            args(&["--segment", "other", "--tenant"]),
            args(&["--tenant", TENANT, "--segment", "other", "-x", "list.csv"]),
        ];
        for bad in bad {
            let err = run(&bad).await.expect_err("should not run");
            assert!(
                err.contains("usage:") || err.contains("is not a uuid"),
                "{err}"
            );
        }
    }

    #[test]
    fn the_country_defaults_to_unknown_and_is_upper_cased() {
        let parsed = parse(&args(&[
            "--tenant",
            TENANT,
            "--segment",
            "relocation",
            "a.csv",
            "b.csv",
        ]))
        .expect("parse");
        assert_eq!(parsed.country, UNKNOWN_COUNTRY);
        assert_eq!(parsed.files, ["a.csv", "b.csv"]);
        assert!(!parsed.dry_run);

        let parsed = parse(&args(&[
            "--tenant",
            TENANT,
            "--segment",
            "other",
            "--country",
            "ph",
            "--dry-run",
            "a.csv",
        ]))
        .expect("parse");
        assert_eq!(parsed.country, "PH");
        assert!(parsed.dry_run);
    }
}
