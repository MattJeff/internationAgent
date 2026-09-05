//! `agentos-server doctor` — answers "what do I still need to make this work?"
//! without booting the server and watching what breaks.
//!
//! # Three outcomes, and why there are exactly three
//!
//! * **OK** — nothing to do.
//! * **MISSING** — something the operator can fix, named, with where to get it.
//! * **PENDING EXTERNAL** — something a third party owes us. A Twilio
//!   regulatory bundle in human review is not a failure, it is a wait, and a
//!   tool that reports the two the same way is a tool that trains operators to
//!   ignore it.
//!
//! Only MISSING is a non-zero exit.
//!
//! # The list of required variables is not in this file
//!
//! [`crate::config`] is the one list. Restating it here would make two lists,
//! and the second one is always the stale one. So [`inspect`] *asks*
//! `Config::parse` what is missing: parse, record whatever it names, stub that
//! variable, parse again. The loop ends when the configuration is complete or
//! when a stub fails to move it forward. A variable added to `config.rs`
//! tomorrow shows up here with no edit — only its "where to get it" hint is
//! local, and an unknown variable gets a hint that points at `config.rs`.
//!
//! # Nothing here spends money or sends anything
//!
//! The live credential checks are authenticated `GET`s against an endpoint
//! that lists things: a doctor that sends an email or buys a number is a
//! footgun. The Anthropic key is checked for presence and shape only — a live
//! check there costs a token, and shape catches the realistic mistake (pasting
//! the wrong secret) anyway.
//!
//! ponytail: the GET is `curl` over a config file on stdin, not an HTTP
//! client. The binary has no HTTP dependency and must not grow one for a
//! diagnostic; stdin rather than argv because argv is world-readable in `ps`,
//! and a credential on a shared box is a credential. No curl, no network, no
//! verdict — the check says "not verified" rather than inventing one.
//!
//! **No value read from the environment is ever printed**, not truncated and
//! not masked: a masked key in a screenshot is still a leak vector, and the
//! only rule that survives contact with people is "never".

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use agentos_app::mocks::LlmBackend;
use sqlx::postgres::PgPoolOptions;

use crate::config::{Config, ConfigError};

/// The value a missing variable is stubbed with while [`inspect`] walks the
/// rest of the list. Never printed, never used to connect to anything.
const STUB: &str = "set-by-agentos-doctor";

/// How long a live credential check gets before it is "not verified".
const PROBE_SECS: u32 = 10;

/// The adapters this build can talk to for real, and where their credential
/// comes from.
///
/// Which of them are *mocked* is not decided here — `config.rs` decides that
/// and reports it in [`Config::mock_adapters`], so this table cannot disagree
/// with the boot guard. It only carries the human half: where an operator gets
/// the credential, and what a free authenticated GET against that provider
/// looks like.
const PROVIDERS: [(&str, &str, &str); 4] = [
    ("email", "EMAIL_API_KEY", "resend.com -> API Keys"),
    (
        "telephony",
        "TELEPHONY_API_KEY",
        "console.twilio.com -> Account SID and Auth Token, as `ACxxx:token`",
    ),
    (
        "browser",
        "BROWSER_API_KEY",
        "browserbase.com -> Settings, as `project-id:api-key`",
    ),
    (
        "embedder",
        "EMBEDDER_API_KEY",
        "the customer's own OpenAI key — we never supply the model, and the model name is not \
         configurable because the HNSW index is partial on it",
    ),
];

/// What running on the hash embedder actually costs, in words an operator can
/// act on.
///
/// The generic mock line in [`providers`] says "no message it accepts leaves
/// this process", which is true of the mailbox and false of this one: the hash
/// embedder embeds, stores and searches perfectly well — it simply has no
/// opinion about meaning. That difference earns its own sentence, because *an
/// employee that never finds its documents* is a thing somebody will otherwise
/// debug for a day.
///
/// It was a `PERMANENT_MOCK` pushed unconditionally onto every report, back
/// when no credential could change it and adding `EMBEDDER_API_KEY` to
/// [`PROVIDERS`] would have turned a MOCK verdict green while a SHA-256 hash
/// went on running. `EMBEDDER_API_KEY` selects a real client now, so this is
/// the mock half of an ordinary row rather than a standing footnote.
const EMBEDDER_MOCK_DETAIL: &str = "\
MOCK — a SHA-256 hash (`mock-sha256-1536`), not semantics. Retrieval therefore runs on word \
matching alone: an employee finds a document that repeats the words of the question and finds \
nothing otherwise, which on an inbound email is most of the time. Set EMBEDDER_API_KEY for the \
real thing — and note that documents already ingested keep the model they were embedded under, \
so they have to be ingested again to be findable.";

/// The port with no adapter, said out loud once per report.
///
/// Not a [`PROVIDERS`] row: those have a credential that makes them real and a
/// mock that answers meanwhile, and this has neither — there is no
/// `PaymentProvider` in this workspace to configure, so there is no variable to
/// name and nothing an operator can set. That is why the status is OK rather
/// than MISSING: MISSING means *you can fix this*, and a line that says "fix
/// the unfixable" on every report forever is a line operators learn to skip.
///
/// It is here at all because the absence is now observable from outside — an
/// approved `payment_create` answers `501 no_payment_rail` — and a diagnostic
/// that cannot explain an error code the server actually returns is a
/// diagnostic somebody debugs around.
const NO_PAYMENT_RAIL_DETAIL: &str = "\
NONE — no payment provider is bound (`NotConfigured`), and no credential binds one: this \
workspace has not chosen a PSP, which is SPEC §13's open decision. Everything up to the money is \
live — the gate rules, the approval queues, a human approves — and `POST /v1/approvals/{id}/\
approve` on a payment then answers `501 no_payment_rail` and leaves the approval PENDING, so it \
is still spendable the day a rail exists. /readyz reports the same fact as `payment_rail: false`.";

/// Every migration this binary carries, so "are the migrations applied?" is
/// answered against the build rather than against a directory listing that may
/// not be next to the binary.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// One of the three verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Nothing to do.
    Ok,
    /// The operator has to set or fix something. The only non-zero exit.
    Missing,
    /// Somebody outside this deployment owes us an answer. Waiting is the
    /// correct action, so it is not a failure.
    PendingExternal,
}

impl Status {
    /// The rendered tag, brackets included so the column is scannable.
    const fn label(self) -> &'static str {
        match self {
            Self::Ok => "[OK]",
            Self::Missing => "[MISSING]",
            Self::PendingExternal => "[PENDING EXTERNAL]",
        }
    }
}

/// One line of the report.
#[derive(Debug)]
pub struct Check {
    /// What was checked — a variable name, an adapter, a subsystem.
    pub name: String,
    /// The verdict.
    pub status: Status,
    /// What to do about it. Never contains a value read from the environment.
    pub detail: String,
}

/// Everything the doctor found, in the order it found it.
#[derive(Debug, Default)]
pub struct Report {
    /// The lines.
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, name: impl Into<String>, status: Status, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }

    /// Whether the process should exit zero.
    ///
    /// Pending-external is deliberately not a failure: a bundle in review will
    /// clear on its own, and exiting non-zero for it is what makes an operator
    /// stop reading the output.
    pub fn ok(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|check| check.status == Status::Missing)
    }

    /// The whole report as text. Returned rather than printed so a test can
    /// assert on it — including asserting that a secret is not in it.
    pub fn render(&self) -> String {
        let width = self
            .checks
            .iter()
            .map(|check| check.name.len())
            .max()
            .unwrap_or(0);

        let mut out = String::from("agentos doctor\n\n");
        for check in &self.checks {
            out.push_str(&format!(
                "{:<18} {:<width$}  {}\n",
                check.status.label(),
                check.name,
                check.detail
            ));
        }
        out.push('\n');
        out.push_str(if self.ok() {
            "Nothing is missing.\n"
        } else {
            "Something is missing. Every MISSING line above names what to set.\n"
        });
        out
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run every check, print the report, and exit non-zero only on MISSING.
///
/// The one place in this module that reads the process environment; everything
/// below takes a lookup closure, which is also how the tests avoid
/// `std::env::set_var` (unsafe in edition 2024, and process-global in every
/// edition).
pub fn main() -> ExitCode {
    let get = |var: &str| {
        std::env::var(var)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };

    let mut report = inspect(&get);

    // Only with a real URL: the stub is not a database, and a doctor that
    // tries to connect to it reports a fake outage on top of a real gap.
    if let Some(url) = get("DATABASE_URL") {
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => report
                .checks
                .extend(runtime.block_on(postgres(&url)).checks),
            Err(err) => report.push(
                "postgres",
                Status::Missing,
                format!("could not start a tokio runtime to check it: {err}"),
            ),
        }
    }

    print!("{}", report.render());
    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// The environment, derived from config.rs
// ---------------------------------------------------------------------------

/// Everything that can be decided without touching the database.
pub fn inspect(get: &dyn Fn(&str) -> Option<String>) -> Report {
    let mut report = Report::default();
    let mut stubs: HashMap<&'static str, &'static str> = HashMap::new();
    let mut refuses_to_boot = false;

    let config = loop {
        let stubbed = stubs.clone();
        let look = |var: &str| {
            stubbed
                .get(var)
                .map(|value| (*value).to_owned())
                .or_else(|| get(var))
        };
        match Config::parse(look) {
            Ok(config) => break Some(config),
            Err(ConfigError::Missing { var }) => {
                report.push(var, Status::Missing, format!("not set — {}", hint(var)));
                // A second stub for the same variable means `Config::parse` is
                // not converging; stop rather than spin.
                if stubs.insert(var, STUB).is_some() {
                    break None;
                }
            }
            Err(ConfigError::MocksNotAllowed { .. }) => {
                // Reported as the `boot` check below, not here: the operator
                // wants the whole picture, and this error hides every check
                // that comes after it in `Config::parse`.
                refuses_to_boot = true;
                if stubs.insert("AGENTOS_ALLOW_MOCKS", "1").is_some() {
                    break None;
                }
            }
            // Invalid values and malformed lists carry their own message, and
            // there is no safe placeholder for a value we cannot parse — so
            // this one stops the walk instead of guessing.
            Err(err) => {
                report.push("environment", Status::Missing, err.to_string());
                break None;
            }
        }
    };
    let Some(config) = config else {
        return report;
    };

    if report.checks.is_empty() {
        report.push(
            "environment",
            Status::Ok,
            "every required variable is set and well-formed",
        );
    }

    // None of the three is required to boot, and each empty one is an outage
    // that looks like a bug: no keyring at all answers every request 401, and an
    // empty webhook registry means no provider callback is registered *here*.
    //
    // "*here*" is load-bearing since `0053_webhook_endpoints`. This whole module
    // reads the environment and nothing else — that is its contract, it runs
    // before `Config::from_env` can fail and it never opens a connection — so it
    // cannot see the `webhook_endpoints` rows that are the other half of the
    // answer. A `Missing` on that row therefore means "the environment
    // registers nobody", not "no mail can arrive", and the message says so.
    //
    // `AGENTOS_API_KEYS` alone being empty is NOT reported as missing any more,
    // and that is the point of `0044_api_keys`: a control plane holds only a
    // platform key and issues every tenant credential over HTTP. What is worth
    // reporting is having neither, because then nothing can authenticate and
    // nothing can issue a key to change that.
    let keyless = config.api_keys.is_empty() && config.platform_keys.is_empty();
    report.push(
        "AGENTOS_API_KEYS",
        if keyless { Status::Missing } else { Status::Ok },
        if keyless {
            "not set, and neither is AGENTOS_PLATFORM_KEYS — every request is answered 401 and \
             no key can be issued to change that. Set it to `label:tenant-uuid:secret[,…]`."
                .to_owned()
        } else {
            format!("{} key(s) configured", config.api_keys.len())
        },
    );
    report.push(
        "AGENTOS_PLATFORM_KEYS",
        if keyless { Status::Missing } else { Status::Ok },
        if config.platform_keys.is_empty() {
            "not set — POST /v1/platform/tenants is answered 401, so nobody can sign up and no \
             API key can be issued or revoked without a redeploy. Set it to `label:secret`."
                .to_owned()
        } else {
            format!("{} platform key(s) configured", config.platform_keys.len())
        },
    );
    report.push(
        "AGENTOS_WEBHOOK_SECRETS",
        if config.webhooks.is_empty() {
            Status::Missing
        } else {
            Status::Ok
        },
        if config.webhooks.is_empty() {
            "not set — no provider callback is registered in the environment. Set it to \
             `provider:tenant-uuid:signing-secret[,…]`, from the provider's webhook page. This \
             check reads the environment only: a deployment whose customers are registered in \
             `webhook_endpoints` (POST /v1/platform/webhooks) receives mail with this unset."
                .to_owned()
        } else {
            format!(
                "callbacks accepted for: {}",
                config
                    .webhooks
                    .iter()
                    .map(|hook| hook.provider.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    );

    // The same one-line inventory the server logs at boot, on whichever verdict
    // applies. It rides along rather than taking a line of its own because it
    // is not a thing that can be *missing*: on a box with nothing set it would
    // be a green check on a page of red ones, which is the reading this tool
    // exists to prevent.
    let adapters = config.adapter_summary();
    if refuses_to_boot {
        report.push(
            "boot",
            Status::Missing,
            format!(
                "the server would REFUSE to start: {} would run as mocks. Set the credentials \
                 named below, or AGENTOS_ALLOW_MOCKS=1 if this is a development box. \
                 Adapters would be: {adapters}",
                config.mock_adapters.join(", ")
            ),
        );
    } else if config.allow_mocks {
        report.push(
            "boot",
            Status::Ok,
            format!(
                "the server would start — with AGENTOS_ALLOW_MOCKS=1, which must not be set in \
                 any environment that matters. Adapters: {adapters}"
            ),
        );
    } else {
        report.push(
            "boot",
            Status::Ok,
            format!("the server would start. Adapters: {adapters}"),
        );
    }

    // `refuses_to_boot` means the *stub* set AGENTOS_ALLOW_MOCKS, not the
    // operator. Without this, a completely unconfigured box would be told its
    // mocks are fine — which is the one thing this whole tool exists to stop.
    let blessed = config.allow_mocks && !refuses_to_boot;

    providers(&config, blessed, get, &mut report);
    let (status, detail) = llm(&config, blessed, get);
    report.push("llm", status, detail);

    report
}

/// Where to get the thing, for the variables we have something useful to say
/// about. The fallback is the point: an unknown variable is a variable
/// `config.rs` grew after this table was written, and pointing at the one list
/// beats pretending to know.
fn hint(var: &str) -> &'static str {
    match var {
        "PUBLIC_HOST" => {
            "the origin this deployment is reachable at, e.g. https://agents.example.com. \
             Providers deliver callbacks here, so a guess means callbacks land nowhere."
        }
        "AGENT_EMAIL_DOMAIN" => {
            "the domain employee addresses are minted under, e.g. agents.example.com. \
             It must be a sending domain you have verified with the email provider."
        }
        "DATABASE_URL" => "postgres://user:password@host:5432/agentos",
        "AGENTOS_MASTER_KEY" => {
            "32 random bytes, base64: `openssl rand -base64 32`. It decrypts every stored \
             provider secret — back it up before you use it, because losing it loses them."
        }
        "ANTHROPIC_API_KEY" => "console.anthropic.com -> API keys",
        _ => "see apps/server/src/config.rs, which is the one list of what this server reads",
    }
}

// ---------------------------------------------------------------------------
// Provider adapters
// ---------------------------------------------------------------------------

/// Which adapters are real, which are mocks, and — for the real ones — whether
/// the provider still accepts the credential.
fn providers(
    config: &Config,
    blessed: bool,
    get: &dyn Fn(&str) -> Option<String>,
    report: &mut Report,
) {
    for (adapter, var, source) in PROVIDERS {
        let mocked = config.mock_adapters.contains(&adapter);
        if mocked && blessed {
            report.push(
                adapter,
                Status::Ok,
                if adapter == "embedder" {
                    // A different failure from the others, and the difference is
                    // what an operator goes looking for. See the constant.
                    EMBEDDER_MOCK_DETAIL.to_owned()
                } else {
                    format!(
                        "MOCK — this adapter does nothing real and no message it accepts leaves \
                         this process. Set {var} for the real thing ({source})."
                    )
                },
            );
        } else if mocked {
            report.push(
                adapter,
                Status::Missing,
                format!("{var} is not set — {source}"),
            );
        } else {
            let (status, detail) = credential(adapter, var, get);
            report.push(adapter, status, format!("REAL — {var} is set; {detail}"));
        }
    }

    // Unconditional, and independent of `blessed`: this one is not a mock and
    // no credential moves it. See the constant.
    report.push("payments", Status::Ok, NO_PAYMENT_RAIL_DETAIL);
}

/// A live check that costs nothing and changes nothing: one authenticated GET
/// against an endpoint that lists things.
fn credential(
    adapter: &str,
    var: &'static str,
    get: &dyn Fn(&str) -> Option<String>,
) -> (Status, String) {
    let Some(secret) = get(var) else {
        // `config.rs` only calls an adapter real when its variable is set, so
        // this is unreachable through `providers` — and an unreachable arm
        // that unwraps is an unreachable arm that panics one refactor later.
        return (Status::Ok, "not verified".to_owned());
    };

    match adapter {
        "email" => match curl_quote(&secret) {
            None => (
                Status::Missing,
                format!(
                    "{var} contains a control character — re-copy it from {source}",
                    source = "resend.com"
                ),
            ),
            Some(key) => classify(
                "api.resend.com",
                curl_status(
                    "https://api.resend.com/domains",
                    &format!("header = \"Authorization: Bearer {key}\""),
                ),
            ),
        },
        "telephony" => {
            // Twilio authenticates with the account SID and the auth token
            // together, so the one variable carries both.
            let Some((sid, _)) = secret.split_once(':') else {
                return (
                    Status::Missing,
                    format!(
                        "{var} must be `ACxxxxxxxx:auth_token` — console.twilio.com shows both"
                    ),
                );
            };
            match (curl_quote(&secret), curl_quote(sid)) {
                (Some(user), Some(sid)) => classify(
                    "api.twilio.com",
                    curl_status(
                        &format!("https://api.twilio.com/2010-04-01/Accounts/{sid}.json"),
                        &format!("user = \"{user}\""),
                    ),
                ),
                _ => (
                    Status::Missing,
                    format!(
                        "{var} contains a control character — re-copy it from console.twilio.com"
                    ),
                ),
            }
        }
        // **Not probed, and that is a rule rather than an omission.** Nothing in
        // this workspace spends a customer's model key, and `doctor` is a
        // command an operator runs repeatedly — a `GET /v1/models` here would be
        // a request on their account every time. The first ingest is where a bad
        // key surfaces, and it surfaces well: a 401 maps to
        // `Terminal { code: "unauthorized" }`, which is not retried and names
        // itself.
        "embedder" => (
            Status::Ok,
            format!(
                "not verified here: {var} is the customer's own key and nothing in this binary \
                 spends it to check. A bad one is reported by the first ingest as `unauthorized`."
            ),
        ),
        // Browserbase's only free authenticated GET is a project listing, and
        // it is per-project rather than per-account: a wrong project id with a
        // right key looks the same as the reverse. Reporting "not verified" is
        // better than teaching an operator to rotate a key that was fine.
        //
        // ponytail: add the probe the day someone is actually burned by a bad
        // browser credential — the adapter's first `ensure_context` says so
        // clearly enough, and unlike email or telephony it costs nothing to
        // discover late.
        _ => (
            Status::Ok,
            format!(
                "not verified here: {var} is checked by the first provisioning step that uses it"
            ),
        ),
    }
}

/// Turn an HTTP status into a verdict.
///
/// Only an explicit rejection is MISSING. A 500 or an unreachable host is the
/// provider's bad day or the operator's coffee shop wifi, and reporting either
/// as a missing credential sends them to rotate a key that was fine.
fn classify(host: &str, status: Option<u16>) -> (Status, String) {
    match status {
        Some(code) if (200..300).contains(&code) => {
            (Status::Ok, format!("{host} accepted it (HTTP {code})"))
        }
        Some(code @ (401 | 403)) => (
            Status::Missing,
            format!(
                "{host} REJECTED it (HTTP {code}) — the credential is set but not valid; issue a new one"
            ),
        ),
        Some(code) => (
            Status::Ok,
            format!("not verified: {host} answered HTTP {code}"),
        ),
        None => (
            Status::Ok,
            format!(
                "not verified: no authenticated GET could be made to {host} (no curl, or no network)"
            ),
        ),
    }
}

/// Escape a value for a curl config file, or refuse it.
///
/// A control character could close the quoted string and add a directive of
/// its own — `output`, say, or another `url`. A credential with one in it is a
/// paste accident, not an attack, but the answer is the same either way.
fn curl_quote(value: &str) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One authenticated GET. `None` means no answer, which is not the same as a
/// rejection — see [`classify`].
///
/// The credential goes in over stdin. Passing it as an argument would put it
/// in `ps` output for every user on the box.
fn curl_status(url: &str, credential: &str) -> Option<u16> {
    let mut child = Command::new("curl")
        .arg("--config")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // `request = "GET"` is belt and braces: nothing here should ever be able
    // to become a send or a purchase, however this string is edited later.
    let config = format!(
        "url = \"{url}\"\n\
         {credential}\n\
         request = \"GET\"\n\
         silent\n\
         output = \"/dev/null\"\n\
         write-out = \"%{{http_code}}\"\n\
         max-time = {PROBE_SECS}\n"
    );
    child.stdin.take()?.write_all(config.as_bytes()).ok()?;

    let output = child.wait_with_output().ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

fn llm(config: &Config, blessed: bool, get: &dyn Fn(&str) -> Option<String>) -> (Status, String) {
    match config.llm {
        LlmBackend::Mock if blessed => (
            Status::Ok,
            "MOCK — every employee answers with one canned sentence that says so. \
             Set AGENTOS_LLM=anthropic for real inference."
                .to_owned(),
        ),
        LlmBackend::Mock => (
            Status::Missing,
            "AGENTOS_LLM is unset, and the default is a scripted mock. Set AGENTOS_LLM=anthropic \
             with ANTHROPIC_API_KEY (console.anthropic.com -> API keys), or =cli, or \
             AGENTOS_ALLOW_MOCKS=1 if a canned reply is what you want."
                .to_owned(),
        ),
        LlmBackend::Cli => match which("claude", get) {
            Some(path) => (
                Status::Ok,
                format!(
                    "AGENTOS_LLM=cli — real inference through `{}`. Testing only: it has no API \
                     key and no usage accounting.",
                    path.display()
                ),
            ),
            None => (
                Status::Missing,
                "AGENTOS_LLM=cli but `claude` is not an executable on PATH — install the Claude \
                 Code CLI, or set AGENTOS_LLM=anthropic"
                    .to_owned(),
            ),
        },
        // Presence and shape, never a call: verifying this key costs a token,
        // and the realistic mistake is pasting the wrong secret, which shape
        // catches for free.
        //
        // **And since 0041 this key can no longer serve a tenant**, which is the
        // more useful thing to say. Every turn runs on the credential the tenant
        // connected through `POST /v1/model`, and a tenant on the `cli` path — the
        // one that spends whatever this host has — is refused outright when this
        // host's model is a key we pay for. So a correctly shaped key here is a
        // key that is now doing nothing, and an operator who thinks it is
        // powering their fleet has the wrong picture of their own bill.
        LlmBackend::Anthropic => match config.anthropic_api_key.as_deref() {
            Some(key) if key.starts_with("sk-ant-") => (
                Status::Ok,
                "AGENTOS_LLM=anthropic, key present and correctly shaped. Not called: a live \
                 check would cost a token. NOTE: no tenant can spend this key — every turn runs \
                 on the credential its tenant connected with POST /v1/model, and the `cli` path \
                 is refused while this key is configured, because we never provide the model."
                    .to_owned(),
            ),
            Some(_) => (
                Status::Missing,
                format!(
                    "{} is set but does not look like an Anthropic key — they begin `sk-ant-`. \
                     console.anthropic.com -> API keys",
                    LlmBackend::API_KEY_VAR
                ),
            ),
            None => (
                Status::Missing,
                format!(
                    "AGENTOS_LLM=anthropic but {} is not set — console.anthropic.com -> API keys",
                    LlmBackend::API_KEY_VAR
                ),
            ),
        },
    }
}

/// `which`, without shelling out to it.
fn which(binary: &str, get: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    get("PATH")?
        .split(':')
        .map(|dir| Path::new(dir).join(binary))
        .find(|path| executable(path))
}

fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

// ---------------------------------------------------------------------------
// Postgres
// ---------------------------------------------------------------------------

/// Reachability, schema, pgvector, and whatever is waiting on a third party.
///
/// Read-only by construction: it opens one connection and runs four `select`s.
/// It does **not** call `Db::migrate` — a diagnostic that changes the schema
/// is a diagnostic nobody can run against production.
async fn postgres(url: &str) -> Report {
    let mut report = Report::default();

    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(PROBE_SECS.into()))
        .connect(url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => {
            report.push(
                "postgres",
                Status::Missing,
                format!(
                    "cannot connect: {err}. DATABASE_URL must point at a running Postgres with \
                     pgvector available."
                ),
            );
            return report;
        }
    };
    report.push("postgres", Status::Ok, "reachable");

    // Applied against the migrations this binary carries, so the answer is
    // about this build rather than about whatever is in a directory next door.
    let applied: Vec<i64> = sqlx::query_scalar("select version from _sqlx_migrations")
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
    let pending = MIGRATOR
        .iter()
        .filter(|migration| !applied.contains(&migration.version))
        .count();
    report.push(
        "migrations",
        Status::Ok,
        if pending == 0 {
            // This build's count, not the row count: a database migrated by a
            // newer build has rows this binary has never heard of, and saying
            // "all 9 applied" about six migrations is a lie that reads fine.
            format!(
                "all {} this build carries are applied",
                MIGRATOR.iter().count()
            )
        } else {
            // Not MISSING: the server applies them itself on the next boot.
            format!("{pending} not applied yet; the server applies them at boot")
        },
    );

    let (installed, available): (bool, bool) = sqlx::query_as(
        "select exists (select 1 from pg_extension where extname = 'vector'), \
                exists (select 1 from pg_available_extensions where name = 'vector')",
    )
    .fetch_one(&pool)
    .await
    .unwrap_or((false, false));
    report.push(
        "pgvector",
        if installed || available {
            Status::Ok
        } else {
            Status::Missing
        },
        match (installed, available) {
            (true, _) => "installed",
            (false, true) => "available but not installed; migration 0004 creates it",
            (false, false) => {
                "not available on this server — knowledge retrieval cannot work and migration \
                 0004 will fail. Install pgvector (docker: pgvector/pgvector, RDS: enable the \
                 vector extension)."
            }
        },
    );

    // The one check that can be green on every other line and still mean
    // "this deployment refuses to do anything": with no platform ceiling the
    // gate denies every action for every tenant, and a doctor that says
    // "Nothing is missing" to that is the exact failure this tool exists to
    // prevent.
    //
    // The predicate is `store::policy`'s own, verbatim, because a diagnostic
    // that can disagree with the loader it reports on is worse than no
    // diagnostic. Skipped rather than guessed when the query fails: on an
    // un-migrated database the table does not exist, and the migrations line
    // above already says so.
    if let Ok(installed) = sqlx::query_scalar::<_, bool>(agentos_store::policy::CEILING_EXISTS_SQL)
        .fetch_one(&pool)
        .await
    {
        report.push(
            "policy ceiling",
            if installed {
                Status::Ok
            } else {
                Status::Missing
            },
            if installed {
                "an active platform layer exists; the gate has a ceiling to enforce"
            } else {
                "none — the gate is fail-closed, so EVERY action is denied with \
                 `no_platform_policy` and /readyz reports not-ready. Install one with \
                 `agentos-server policy install` (DATABASE_URL and nothing else; no restart \
                 needed afterwards)."
            },
        );
    }

    // The whole reason PENDING EXTERNAL exists: a number waiting on a Twilio
    // regulatory bundle is a wait, and an operator told it is a failure goes
    // looking for a bug that is not there.
    if let Ok(waiting) = sqlx::query_scalar::<_, i64>(
        "select count(*) from employee_resources where state = 'pending_external'",
    )
    .fetch_one(&pool)
    .await
    {
        report.push(
            "provisioning",
            if waiting == 0 {
                Status::Ok
            } else {
                Status::PendingExternal
            },
            if waiting == 0 {
                "no step is waiting on a third party".to_owned()
            } else {
                format!(
                    "{waiting} provisioning step(s) waiting on a third party (a regulatory \
                     bundle in review, a domain being verified). Nothing to fix — wait, or chase \
                     the provider. `GET /v1/employees` shows which."
                )
            },
        );
    }

    report
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TENANT: &str = "00000000-0000-0000-0000-000000000001";
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn lookup(env: HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |var: &str| env.get(var).map(|value| (*value).to_owned())
    }

    /// The state an operator is actually in on day one: they cloned the repo
    /// and ran the binary. Every line has to be actionable, and the exit code
    /// has to be non-zero or a CI gate built on it is decorative.
    #[test]
    fn nothing_configured_is_missing_everywhere_and_exits_non_zero() {
        let report = inspect(&lookup(HashMap::new()));

        assert!(!report.checks.is_empty());
        // One exemption, and it is the one the rule was always about.
        // `Status::Missing` means "the operator has to set or fix something",
        // and `payments` has nothing to set: no `PaymentProvider` exists in
        // this workspace and no variable binds one, so MISSING would send
        // somebody looking for a credential that has not been invented. That
        // is the exact argument that used to exempt the embedder — until
        // `EMBEDDER_API_KEY` started selecting a real client, at which point it
        // became an ordinary row and an unconfigured one ordinary MISSING. The
        // day a PSP is chosen, `payments` makes the same move.
        for check in report
            .checks
            .iter()
            .filter(|check| check.name != "payments")
        {
            assert_eq!(
                check.status,
                Status::Missing,
                "{} reported {:?} with nothing configured",
                check.name,
                check.status
            );
            // MISSING has to say what to do; a bare "not set" is what makes a
            // doctor useless.
            assert!(
                check.detail.len() > 20,
                "{} says only {:?}",
                check.name,
                check.detail
            );
        }
        assert!(!report.ok(), "{}", report.render());

        // And the variables it names come from config.rs, not from this file.
        let rendered = report.render();
        for var in ["PUBLIC_HOST", "DATABASE_URL", "AGENTOS_MASTER_KEY"] {
            assert!(rendered.contains(var), "{rendered}");
        }
    }

    /// A development box is a legitimate state, not a broken one — but it must
    /// never be quiet about it.
    #[test]
    fn allowed_mocks_are_ok_and_say_loudly_that_they_are_mocks() {
        let report = inspect(&lookup(HashMap::from([
            ("PUBLIC_HOST", "https://agents.example.com"),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com"),
            ("DATABASE_URL", "postgres://localhost/agentos"),
            ("AGENTOS_MASTER_KEY", "not-a-real-key"),
            ("AGENTOS_ALLOW_MOCKS", "1"),
            (
                "AGENTOS_API_KEYS",
                "ops:00000000-0000-0000-0000-000000000001:0123456789abcdef0123456789abcdef",
            ),
            (
                "AGENTOS_WEBHOOK_SECRETS",
                "email:00000000-0000-0000-0000-000000000001:whsec_x",
            ),
        ])));
        let rendered = report.render();

        for adapter in ["email", "telephony", "browser", "embedder", "llm"] {
            let check = report
                .checks
                .iter()
                .find(|check| check.name == adapter)
                .unwrap_or_else(|| panic!("no {adapter} check in\n{rendered}"));
            assert_eq!(check.status, Status::Ok, "{adapter}: {rendered}");
            assert!(
                check.detail.contains("MOCK") || check.detail.contains("mock"),
                "{adapter} does not say it is a mock: {:?}",
                check.detail
            );
        }
        assert!(report.ok(), "{rendered}");
        // And the boot verdict is the one the operator asked for.
        assert!(rendered.contains("AGENTOS_ALLOW_MOCKS=1"), "{rendered}");

        // The port that is not a mock and not fixable, named anyway: an
        // operator who reads `no_payment_rail` off an approval must be able to
        // find out here what it means, without it failing the run.
        let payments = report
            .checks
            .iter()
            .find(|check| check.name == "payments")
            .unwrap_or_else(|| panic!("no payments check in\n{rendered}"));
        assert_eq!(payments.status, Status::Ok, "{rendered}");
        assert!(
            payments.detail.contains("no_payment_rail"),
            "the doctor must name the code the API returns: {:?}",
            payments.detail
        );
    }

    #[test]
    fn a_mock_without_permission_is_missing_and_the_boot_line_says_so() {
        let report = inspect(&lookup(HashMap::from([
            ("PUBLIC_HOST", "https://agents.example.com"),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com"),
            ("DATABASE_URL", "postgres://localhost/agentos"),
            ("AGENTOS_MASTER_KEY", "not-a-real-key"),
        ])));

        let boot = report
            .checks
            .iter()
            .find(|check| check.name == "boot")
            .expect("a boot verdict");
        assert_eq!(boot.status, Status::Missing);
        assert!(boot.detail.contains("REFUSE"), "{:?}", boot.detail);
        assert!(!report.ok());
    }

    /// A masked key in a screenshot is still a leak vector, so nothing read
    /// from the environment is printed at all.
    #[test]
    fn no_secret_reaches_the_output() {
        let report = inspect(&lookup(HashMap::from([
            ("PUBLIC_HOST", "https://agents.example.com"),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com"),
            (
                "DATABASE_URL",
                "postgres://postgres:hunter2@localhost/agentos",
            ),
            ("AGENTOS_MASTER_KEY", "master-hunter2"),
            ("AGENTOS_LLM", "anthropic"),
            ("ANTHROPIC_API_KEY", "sk-ant-hunter2"),
            ("AGENTOS_ALLOW_MOCKS", "1"),
            (
                "AGENTOS_API_KEYS",
                "ops:00000000-0000-0000-0000-000000000001:0123456789abcdef0123456789abcdef",
            ),
            (
                "AGENTOS_WEBHOOK_SECRETS",
                "email:00000000-0000-0000-0000-000000000001:whsec_hunter2",
            ),
        ])));

        let rendered = report.render();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(!rendered.contains("sk-ant"), "{rendered}");
        assert!(!rendered.contains("whsec"), "{rendered}");
        // It is still a useful report.
        assert!(rendered.contains("anthropic"), "{rendered}");
        assert!(
            rendered.contains(TENANT) || rendered.contains("email"),
            "{rendered}"
        );
    }

    #[test]
    fn a_misshapen_anthropic_key_is_caught_without_calling_anthropic() {
        let report = inspect(&lookup(HashMap::from([
            ("PUBLIC_HOST", "https://agents.example.com"),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com"),
            ("DATABASE_URL", "postgres://localhost/agentos"),
            ("AGENTOS_MASTER_KEY", "not-a-real-key"),
            ("AGENTOS_LLM", "anthropic"),
            ("ANTHROPIC_API_KEY", "sk-proj-wrong-vendor"),
            ("AGENTOS_ALLOW_MOCKS", "1"),
        ])));

        let llm = report
            .checks
            .iter()
            .find(|check| check.name == "llm")
            .expect("an llm verdict");
        assert_eq!(llm.status, Status::Missing);
        assert!(llm.detail.contains("sk-ant-"), "{:?}", llm.detail);
    }

    /// The distinction the whole tool exists for: a bundle in human review is
    /// a wait, and a wait exits zero.
    #[test]
    fn a_pending_external_condition_exits_zero() {
        let mut report = Report::default();
        report.push("postgres", Status::Ok, "reachable");
        report.push(
            "provisioning",
            Status::PendingExternal,
            "1 step waiting on a regulatory bundle",
        );

        assert!(report.ok());
        assert!(report.render().contains("[PENDING EXTERNAL]"));
        assert!(report.render().contains("Nothing is missing"));

        // And one MISSING anywhere flips it.
        report.push("email", Status::Missing, "EMAIL_API_KEY is not set");
        assert!(!report.ok());
    }

    #[test]
    fn a_credential_with_a_newline_never_reaches_a_curl_config() {
        assert_eq!(curl_quote("re_live_key").as_deref(), Some("re_live_key"));
        assert_eq!(curl_quote("a\"b\\c").as_deref(), Some("a\\\"b\\\\c"));
        assert_eq!(curl_quote("re_key\noutput = \"/etc/passwd\""), None);
    }

    #[test]
    fn a_rejected_credential_is_missing_but_an_unreachable_provider_is_not() {
        assert_eq!(classify("api.resend.com", Some(200)).0, Status::Ok);
        assert_eq!(classify("api.resend.com", Some(401)).0, Status::Missing);
        assert_eq!(classify("api.resend.com", Some(403)).0, Status::Missing);
        // The provider's bad day is not the operator's missing key.
        assert_eq!(classify("api.resend.com", Some(503)).0, Status::Ok);
        assert_eq!(classify("api.resend.com", None).0, Status::Ok);
    }

    #[test]
    fn a_missing_claude_binary_is_reported_rather_than_discovered_at_the_first_turn() {
        let report = inspect(&lookup(HashMap::from([
            ("PUBLIC_HOST", "https://agents.example.com"),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com"),
            ("DATABASE_URL", "postgres://localhost/agentos"),
            ("AGENTOS_MASTER_KEY", "not-a-real-key"),
            ("AGENTOS_LLM", "cli"),
            ("AGENTOS_ALLOW_MOCKS", "1"),
            ("PATH", "/nonexistent-doctor-path"),
        ])));

        let llm = report
            .checks
            .iter()
            .find(|check| check.name == "llm")
            .expect("an llm verdict");
        assert_eq!(llm.status, Status::Missing);
        assert!(llm.detail.contains("claude"), "{:?}", llm.detail);
    }
}
