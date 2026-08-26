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
//! **somebody opened the page and checked**, which is why `set` and `confirm`
//! are two verbs rather than one: [`set`](run) writes the selectors and always
//! leaves the row unconfirmed, and `confirm` puts a name on it. Editing a
//! selector revokes the confirmation — here, and in a trigger in
//! `0032_prospect_flows.sql`, so it is also true of a `psql` session.
//!
//! # `review` and `promote` are the same act, done once for many prospects
//!
//! Typing five selectors per prospect is linear in a human's time and there are
//! about 1,615 prospects. So an employee reads the page and files a proposal —
//! `agentos_app::flow_proposal`, `0037_prospect_flow_proposals.sql` — and these
//! two verbs are how a person turns a batch of proposals into confirmed flows:
//! `review` prints what is waiting, `promote` runs `set` and `confirm` over the
//! accounts you name.
//!
//! **`promote` is `confirm`.** Not a relative of it, not a bulk variant with its
//! own rules: it calls the same two store functions on the same admin
//! transaction and prints the same [`CAVEAT`]. What a batch buys is that the
//! reviewer reads five selectors instead of composing them, which is a glance at
//! a page they had to open anyway. What it must never buy is a lower bar, and
//! the way that is kept true is that there is no second write path into
//! `prospect_flows` for anybody to audit separately.
//!
//! It also grants nothing else. A promoted flow whose host is not on
//! `allowed_domains` will not probe, because the prober *types* into the form;
//! see [`NOT_GRANTED`], which every promotion prints, and `docs/ORIZN.md`.
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
usage: agentos-server flow set     --tenant <uuid> --account <uuid> <flow.json>
       agentos-server flow confirm --tenant <uuid> --account <uuid> --by <name>
       agentos-server flow review  --tenant <uuid>
       agentos-server flow promote --tenant <uuid> --by <name> (--all | <uuid>...)

  set        write the selectors for one prospect's booking page. The row is
             always left UNCONFIRMED, and re-writing a confirmed one revokes
             the confirmation: the point of a confirmation is that somebody
             looked at these exact selectors.
  confirm    record that <name> opened the page and checked that each selector
             points at what it says. Nothing probes a prospect's flow until
             this has been run for it.
  review     print every proposal an employee has filed that no human has
             confirmed yet: the page to open and the selectors to check on it.
             Reads nothing else and writes nothing.
  promote    do `set` and `confirm` for each named account from its proposal,
             or for every reviewable one with --all. It is `confirm`, in bulk,
             with the same meaning and the same caveat.

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

Every verb reads DATABASE_URL and nothing else: writing a selector is proved by
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
        ["review", rest @ ..] if !rest.is_empty() => {
            let tenant = parse_review_args(rest)?;
            review(&database_url()?, tenant).await
        }
        ["promote", rest @ ..] if !rest.is_empty() => {
            let (tenant, who, which) = parse_promote_args(rest)?;
            promote(&database_url()?, tenant, &who, &which).await
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

/// `--tenant <uuid>`, and nothing else. A review that took a filter would be a
/// review that could hide a prospect from the person reviewing.
fn parse_review_args(args: &[&str]) -> Result<TenantId, String> {
    match args {
        ["--tenant", raw] => Ok(TenantId::from_uuid(uuid_arg("--tenant", raw)?)),
        _ => Err(USAGE.to_owned()),
    }
}

/// Which accounts a promotion is for.
///
/// `--all` is spelled rather than implied by an empty list, because "promote
/// everything you have" and "I forgot to say which" are the same command line
/// otherwise, and one of them confirms selectors nobody read.
#[derive(Debug, PartialEq, Eq)]
enum Which {
    /// Every proposal `flow review` would print.
    All,
    /// These accounts, in the order the operator typed them.
    These(Vec<Uuid>),
}

/// `--tenant <uuid> --by <name>` and then either `--all` or one or more account
/// uuids, in any order.
fn parse_promote_args(args: &[&str]) -> Result<(TenantId, String, Which), String> {
    let mut tenant: Option<TenantId> = None;
    let mut who: Option<String> = None;
    let mut all = false;
    let mut accounts: Vec<Uuid> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let flag = args[i];
        match flag {
            "--tenant" => {
                tenant = Some(TenantId::from_uuid(uuid_arg(flag, flag_value(args, i)?)?));
                i += 2;
            }
            "--by" => {
                who = Some(flag_value(args, i)?.trim().to_owned());
                i += 2;
            }
            "--all" => {
                all = true;
                i += 1;
            }
            _ if flag.starts_with('-') => return Err(USAGE.to_owned()),
            _ => {
                accounts.push(uuid_arg("account", flag)?);
                i += 1;
            }
        }
    }

    // The same sentence `confirm` uses, because this is the same act.
    let who = who.filter(|name| !name.is_empty()).ok_or_else(|| {
        format!(
            "--by is required and is a person's name. A confirmation whose author is \"\" is a \
             confirmation nobody made.\n\n{USAGE}"
        )
    })?;
    let tenant = tenant.ok_or_else(|| USAGE.to_owned())?;

    match (all, accounts.is_empty()) {
        (true, true) => Ok((tenant, who, Which::All)),
        (false, false) => Ok((tenant, who, Which::These(accounts))),
        (true, false) => Err(format!(
            "--all and a list of accounts are two different commands; pick one.\n\n{USAGE}"
        )),
        (false, true) => Err(format!(
            "name the accounts to promote, or say --all. Promoting nothing is not the same as \
             promoting everything, and this command will not guess which you meant.\n\n{USAGE}"
        )),
    }
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

// ---------------------------------------------------------------------------
// Review and promote
// ---------------------------------------------------------------------------

/// What a proposal is worth, in one sentence, printed under every review.
///
/// It is the second half of [`CAVEAT`] and it is here rather than there because
/// this is where the reviewing happens: `review` is the screen somebody looks at
/// before they type a name, and the thing they most need to be told is that the
/// scan had no idea what any of these elements *are*.
const SCANNED: &str = "\
These selectors were found by a scan, not by anybody looking. The scan matched a
vocabulary against each element's `id` and `name` — it did not read the page, it
cannot tell a passport field from a promo-code field that happens to be called
one, and a page that wanted to be probed against the wrong element would name it
accordingly. That is the whole of what `--by` is for: open the page, paste each
selector into `document.querySelector`, and look at what lights up.";

/// The thing promotion deliberately does not do, printed after every one.
const NOT_GRANTED: &str = "\
Promoting a flow does not put its host on `allowed_domains`. Reading a page needs
no entry there, but a probe *types* into the prospect's form and that is a
`BrowserWrite`, so a flow whose host is not on the seller's write list is a flow
that will not probe — it will be refused with the domain named. Add the host with
`agentos-server policy` when you mean to, deliberately and per host. See
docs/ORIZN.md.";

/// Every proposal on file for this tenant, and the confirmation state of the
/// flow each one would become.
async fn proposals(db: &Db, tenant: TenantId) -> Result<Vec<revenue::FlowProposal>, String> {
    let mut tx = db
        .tenant_tx(tenant)
        .await
        .map_err(|err| format!("could not read this tenant: {err}"))?;
    let found = revenue::flow_proposals(&mut tx)
        .await
        .map_err(|err| format!("could not read the proposals: {err}"));
    // Read-only: the commit is the rollback that does not log.
    let _ = tx.commit().await;
    found
}

/// One proposal, as somebody about to check it needs to see it.
///
/// Everything printed here is either ours or a token
/// `agentos_app::flow_proposal::Selector::parse` accepted: `legal_name` is the
/// founder's own text or a domain we derived, `entry_url` is a parsed `Url`, and
/// a selector is one ASCII identifier. So there is no byte in this that could
/// carry a terminal escape, a newline or a second line pretending to be a
/// prospect — which is a property of the grammar in
/// `0037_prospect_flow_proposals.sql`, not a thing this function checks.
fn render(proposal: &revenue::FlowProposal) -> String {
    let fields = [
        ("passport_field", proposal.passport_field.as_deref(), true),
        (
            "destination_field",
            proposal.destination_field.as_deref(),
            true,
        ),
        ("date_field", proposal.date_field.as_deref(), false),
        ("submit", proposal.submit.as_deref(), false),
        ("panel", proposal.panel.as_deref(), true),
    ];
    let mut out = format!(
        "{} — account {}\n  open  {}\n",
        proposal.prospect, proposal.account_id, proposal.entry_url
    );
    for (name, selector, required) in fields {
        let value = match (selector, required) {
            (Some(selector), _) => selector.to_owned(),
            // The two the schema lets a flow do without.
            (None, false) => "(none found; a flow may have neither)".to_owned(),
            // The three `prospect_flows` requires, so promotion refuses this
            // proposal until somebody writes it with `flow set`.
            (None, true) => "NOT FOUND — this proposal cannot be promoted as it is".to_owned(),
        };
        out.push_str(&format!("  {name:<18}{value}\n"));
    }
    out.push_str(&format!(
        "  proposed by {} at {}\n",
        proposal.proposed_by,
        proposal.proposed_at.to_rfc3339()
    ));
    out
}

/// Print every proposal nobody has confirmed yet.
async fn review(url: &str, tenant: TenantId) -> Result<String, String> {
    let db = connect(url).await?;
    let all = proposals(&db, tenant).await?;
    let waiting: Vec<&revenue::FlowProposal> = all
        .iter()
        .filter(|proposal| proposal.confirmed_by.is_none())
        .collect();

    if waiting.is_empty() {
        return Ok(format!(
            "no proposal is waiting for a human in tenant {}. {} on file, all of them already \
             confirmed.\n\nAn employee files these with its `propose_flow` tool; a prospect it \
             has never looked at has nothing here.",
            tenant.as_uuid(),
            all.len()
        ));
    }

    let mut out = format!(
        "{} proposal(s) waiting for a human, oldest prospect first.\n\n",
        waiting.len()
    );
    for proposal in &waiting {
        out.push_str(&render(proposal));
        out.push('\n');
    }
    out.push_str(SCANNED);
    out.push_str(&format!(
        "\n\nWhen you have checked them:\n\n  \
         agentos-server flow promote --tenant {} --by <your name> --all\n\n\
         or name the accounts you checked instead of --all. {NOT_GRANTED}",
        tenant.as_uuid()
    ));
    Ok(out)
}

/// The three columns `prospect_flows` has NOT NULL, as a promotable flow or the
/// sentence saying which one is missing.
///
/// Deliberately not a `TryFrom`: the failure is a message an operator acts on,
/// and the two optional columns are optional in both tables, so nothing is
/// invented for them here either.
fn promotable(proposal: &revenue::FlowProposal) -> Result<NewProspectFlow<'_>, String> {
    let missing = |name: &str| {
        format!(
            "the scan found no {name}, and `prospect_flows` has no row without one. Write this \
             prospect's flow with `flow set` instead"
        )
    };
    // In the order somebody reads them, so the message names the first gap.
    let passport = proposal
        .passport_field
        .as_deref()
        .ok_or_else(|| missing("passport_field"))?;
    let destination = proposal
        .destination_field
        .as_deref()
        .ok_or_else(|| missing("destination_field"))?;
    let panel = proposal.panel.as_deref().ok_or_else(|| missing("panel"))?;

    Ok(NewProspectFlow {
        entry_url: &proposal.entry_url,
        passport_field: passport,
        destination_field: destination,
        // The two `prospect_flows` also lets be null. Nothing is invented for a
        // flow that has neither, in either table.
        date_field: proposal.date_field.as_deref(),
        submit: proposal.submit.as_deref(),
        panel,
    })
}

/// Write and confirm a proposal for each account named, one at a time.
///
/// # Why a loop of two statements and not one transaction
///
/// Because the two statements are [`set`] and [`confirm`] exactly as an operator
/// would run them by hand, and reusing them is what makes a batch promotion
/// provably the same act as a single confirmation — same UPSERT, same
/// re-confirmation trigger, same admin credential, no second write path into
/// `prospect_flows` for anybody to audit separately. What a batch is, here, is
/// one human's attention spent once instead of N times; it is not a new kind of
/// authority and it must not become one.
///
/// So a batch is **not atomic**, and the failure that buys is the good one: an
/// interrupted run leaves the prospects it got to confirmed and the rest exactly
/// as they were, and re-running it is a no-op for the first group — the UPSERT
/// writes the same selectors, which the trigger in `0032_prospect_flows.sql`
/// sees as no change at all. One prospect's refusal never costs the other 200.
async fn promote(url: &str, tenant: TenantId, who: &str, which: &Which) -> Result<String, String> {
    let db = connect(url).await?;
    let all = proposals(&db, tenant).await?;

    // `--all` means "everything `flow review` just showed you", which is the
    // list this operator has actually looked at. A named account is promoted
    // whatever state it is in, because naming it is the operator saying so.
    let chosen: Vec<&revenue::FlowProposal> = match which {
        Which::All => all
            .iter()
            .filter(|proposal| proposal.confirmed_by.is_none())
            .collect(),
        Which::These(accounts) => accounts
            .iter()
            .filter_map(|id| all.iter().find(|proposal| proposal.account_id == *id))
            .collect(),
    };

    if let Which::These(accounts) = which {
        let missing: Vec<String> = accounts
            .iter()
            .filter(|id| !all.iter().any(|proposal| proposal.account_id == **id))
            .map(Uuid::to_string)
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "no employee has proposed a flow for {}. Nothing was promoted — a batch that \
                 silently skipped an account you named is a batch you would think you had \
                 confirmed.\n\n  agentos-server flow review --tenant {}",
                missing.join(", "),
                tenant.as_uuid()
            ));
        }
    }

    if chosen.is_empty() {
        return Ok(format!(
            "nothing to promote in tenant {}: every proposal on file is already confirmed.",
            tenant.as_uuid()
        ));
    }

    let mut done = 0usize;
    let mut refused: Vec<String> = Vec::new();
    let mut out = String::new();
    for proposal in chosen {
        let flow = match promotable(proposal) {
            Ok(flow) => flow,
            Err(why) => {
                refused.push(format!(
                    "{} ({}): {why}",
                    proposal.prospect, proposal.account_id
                ));
                continue;
            }
        };
        revenue::set_prospect_flow(&db, tenant, proposal.account_id, &flow)
            .await
            .map_err(|err| write_error(tenant, proposal.account_id, err))?;
        revenue::confirm_prospect_flow(&db, tenant, proposal.account_id, who, Utc::now())
            .await
            .map_err(|err| write_error(tenant, proposal.account_id, err))?;
        done += 1;
        // What was confirmed, printed after it was: the operator has the row
        // they just vouched for in their scrollback, in the bytes that went in.
        out.push_str(&render(proposal));
        out.push('\n');
    }

    let mut report = format!("{who} confirmed {done} flow(s).\n\n{out}");
    if !refused.is_empty() {
        report.push_str(&format!(
            "Not promoted, and still waiting:\n  {}\n\n",
            refused.join("\n  ")
        ));
    }
    report.push_str(CAVEAT);
    report.push_str("\n\n");
    report.push_str(NOT_GRANTED);
    Ok(report)
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

    fn proposal() -> revenue::FlowProposal {
        revenue::FlowProposal {
            account_id: Uuid::nil(),
            prospect: "Deutsche Lufthansa AG".to_owned(),
            domain: "lufthansa.com".to_owned(),
            entry_url: "https://book.lufthansa.com/entry".to_owned(),
            passport_field: Some("#pp".to_owned()),
            destination_field: Some("#dest".to_owned()),
            date_field: None,
            submit: None,
            panel: Some("#visa-result".to_owned()),
            proposed_by: "ada".to_owned(),
            proposed_at: Utc::now(),
            confirmed_by: None,
        }
    }

    /// **A batch is one human's attention spent once, not a looser rule.** So
    /// the two ways of saying "which prospects" are both explicit, and every
    /// other spelling is a refusal rather than a default — "promote everything"
    /// and "I forgot to say which" are one command line apart, and one of them
    /// puts a name on selectors nobody read.
    #[test]
    fn a_batch_promotion_will_not_guess_which_prospects_it_is_for() {
        let uuid = "0198f2a4-0000-7000-8000-000000000002";
        let by = [
            "--tenant",
            "0198f2a4-0000-7000-8000-000000000001",
            "--by",
            "Mathis",
        ];

        let (_, who, which) =
            parse_promote_args(&[by.as_slice(), &["--all"]].concat()).expect("--all is a list");
        assert_eq!(who, "Mathis");
        assert_eq!(which, Which::All);

        let (_, _, which) =
            parse_promote_args(&[by.as_slice(), &[uuid]].concat()).expect("one account");
        assert_eq!(which, Which::These(vec![uuid.parse().expect("uuid")]));

        // Neither: refused, and the message says why rather than promoting
        // nothing quietly.
        let err = parse_promote_args(&by).expect_err("no accounts and no --all");
        assert!(err.contains("Promoting nothing is not the same"), "{err}");

        // Both: two different commands.
        let err = parse_promote_args(&[by.as_slice(), &["--all", uuid]].concat())
            .expect_err("--all and a list");
        assert!(err.contains("two different commands"), "{err}");

        // And it is a confirmation, so it needs the same person `confirm` does.
        let err =
            parse_promote_args(&["--tenant", "0198f2a4-0000-7000-8000-000000000001", "--all"])
                .expect_err("nobody confirmed it");
        assert!(err.contains("--by is required"), "{err}");
    }

    /// A proposal missing one of the three columns `prospect_flows` has NOT NULL
    /// is refused **by the name of the column**, because the operator's next
    /// move is `flow set` for that one field and a constraint name would not
    /// tell them which.
    ///
    /// The two that are optional in both tables stay optional: nothing is
    /// invented for a flow that has no date and no submit.
    #[test]
    fn a_proposal_missing_a_required_selector_is_refused_by_name() {
        let complete = proposal();
        let flow = promotable(&complete).expect("three of three");
        assert_eq!(flow.passport_field, "#pp");
        assert_eq!(flow.date_field, None);
        assert_eq!(flow.submit, None);

        for (name, break_it) in [
            ("passport_field", 0usize),
            ("destination_field", 1),
            ("panel", 2),
        ] {
            let mut incomplete = proposal();
            match break_it {
                0 => incomplete.passport_field = None,
                1 => incomplete.destination_field = None,
                _ => incomplete.panel = None,
            }
            let err = promotable(&incomplete).expect_err("a NOT NULL column");
            assert!(err.contains(name), "expected {name} named, got: {err}");
            assert!(err.contains("flow set"), "{err}");

            // And the review says the same thing in the same place, so nobody
            // types a name for a row that cannot be written.
            let shown = render(&incomplete);
            assert!(shown.contains("cannot be promoted"), "{shown}");
        }
    }

    /// What the reviewer is shown is what they have to check: the page to open
    /// and one selector per role, each of them one token they can paste into
    /// `document.querySelector`.
    #[test]
    fn a_review_shows_the_page_and_every_selector_on_it() {
        let shown = render(&proposal());
        assert!(
            shown.contains("https://book.lufthansa.com/entry"),
            "{shown}"
        );
        assert!(shown.contains("Deutsche Lufthansa AG"), "{shown}");
        for selector in ["#pp", "#dest", "#visa-result"] {
            assert!(shown.contains(selector), "{selector} missing from {shown}");
        }
        // The two a flow may do without say so rather than looking broken.
        assert!(shown.contains("a flow may have neither"), "{shown}");
        // Who looked, and it is a slug: this line can never be read as a name
        // somebody put on a confirmation.
        assert!(shown.contains("proposed by ada"), "{shown}");
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
