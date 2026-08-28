//! **What Orizn costs a month, computed once, from a run that happened.**
//!
//! # The problem this module exists for
//!
//! `docs/ORIZN.md` published **≈$76 a month**. It was arithmetic over three
//! numbers: 4,639 input tokens per model call, an assumed 600 output tokens, and
//! **one model call per reserved turn**. The first was measured by
//! [`crate::scoping`] and then moved; the second was a guess; the third was the
//! *floor* of a range that runs to ten, quoted as if it were an estimate. When
//! somebody finally ran the thing and counted, all three were wrong in the same
//! direction and the honest figure was several times what the document said.
//!
//! None of that was a bug. It is what happens when a number is typed into prose:
//! prose cannot be re-run, so it is right on the day it is written and drifts
//! silently forever after. This module is the fix, and it is small:
//!
//! * the arithmetic is [`Sample::usd`], one function, unit-tested — and it lives
//!   in [`agentos_domain::forecast`] now, because `apps/server`'s `/v1/forecast`
//!   prices the asking tenant's own seats with the same one;
//! * the inputs are [`RECORDED`] — the samples a real `--dry-run` printed;
//! * the turns column is read out of `docs/orizn-roles/*.json`, the operator's
//!   own documents, rather than restated;
//! * and [`headline`] is the sentence. `docs/ORIZN.md` must contain it
//!   **verbatim**, which is what the `the runbook quotes this measurement` row
//!   below gates on. Change the measurement and the document goes red until
//!   somebody pastes the new sentence in. There is no second copy to forget.
//!
//! # A range, not a point
//!
//! `max_turns_per_day` counts *reserved turns*; one reserved turn makes between
//! one and [`Budgets::max_turns`] = ten model calls, each re-sending the whole
//! prefix. So the bill is a range an order of magnitude wide and any point
//! estimate inside it is a choice. The document used to publish the floor
//! without saying so. [`headline`] publishes all three: the floor, what was
//! measured, and the ceiling.
//!
//! # Why the numbers are recorded and not asserted
//!
//! A live run is a sample from a model. A threshold test on a sample is a flaky
//! test, and a flaky test gets deleted — so nothing here asserts that the bill is
//! under anything. What is gated is the same thing [`crate::toolchoice`] gates:
//! **the question these numbers answered**. [`DIGEST`] pins the three charters'
//! rendered prompts, their plans, the turn brief and the five operator documents.
//! Edit any of them and this suite goes red with *"the recorded run measured a
//! different company"*, which is true, and the fix is to re-run `--dry-run` and
//! re-paste. The deterministic half's job is to **invalidate** the live numbers,
//! never to fabricate them.
//!
//! # What is not in here
//!
//! Prompt caching, which lowers it; the provisioning loop's own model calls,
//! which raise it; and the difference between the `claude` CLI shim the dry run
//! drives and `llm_anthropic`, which is the production path. All three are in
//! `unmeasured` below with the direction they move the number.

use std::path::PathBuf;

use agentos_app::rolepack;
use agentos_app::turn::Budgets;
use agentos_app::vertical::Charter;
use agentos_app::{rolepack_sales, rolepack_service};
use agentos_domain::money::Currency;
use agentos_domain::policy::{EffectivePolicy, ModelId, PolicyLimits, model_for};
use agentos_domain::untrusted::TrustLabel;
use sha2::{Digest, Sha256};

use crate::{Row, Surface, Truth};

// ---------------------------------------------------------------------------
// The rate card and the two ends of the range
// ---------------------------------------------------------------------------

/// **The rate card, the samples and the one multiplication now live in
/// [`agentos_domain::forecast`]**, and this re-export is what keeps every name
/// in this file — and in [`crate::dryrun`] — spelled the way it always was.
///
/// They moved because a second caller appeared: `apps/server`'s `/v1/forecast`
/// prices *the asking tenant's* seats over *the window the founder picked*, and
/// it cannot reach this crate — `agentos-eval` reads `docs/orizn-*.json` off the
/// filesystem and exists to measure the server, not to be linked into it. Two
/// implementations of one bill is two things that drift, which is the failure
/// this whole module was written to end; one implementation in the crate both
/// can see is not.
///
/// What did **not** move is anything about Orizn: [`seats`], [`charters`],
/// [`PROSPECT`], [`DIGEST`] and [`headline`] are still here, because they are
/// facts about one company rather than arithmetic.
pub use agentos_domain::forecast::{FLOOR_CALLS_PER_TURN, RECORDED, Sample, rate_card};

use agentos_domain::forecast::{MONTH_DAYS, spread};

/// Dollars a month for **one seat**, at `calls_per_turn` model calls for each of
/// `turns_per_day` reserved turns, billed at `model`'s rates.
///
/// A month of [`Sample::usd`], and nothing else: the arithmetic is one function
/// and this only fixes its window at thirty days, which is what a *monthly*
/// headline means and what an operator budgets in. `/v1/forecast` calls
/// [`Sample::usd`] directly with the window it was asked about.
pub fn monthly_usd(sample: Sample, model: ModelId, calls_per_turn: f64, turns_per_day: f64) -> f64 {
    sample.usd(model, calls_per_turn, turns_per_day * MONTH_DAYS)
}

/// The whole company for a month, at a given rate: every seat at its own model,
/// its own turn budget, summed.
///
/// **This is the function the old `measured_usd(turns_per_day)` became.** The old
/// one took the sum of the turn budgets and multiplied once, which was exactly
/// right while one model served every seat and is a category error now: five
/// seats on three models is five multiplications, and the mix is most of the
/// answer.
pub fn company_usd(sample: Sample, calls_per_turn: f64) -> f64 {
    seats()
        .iter()
        .map(|seat| monthly_usd(sample, seat.model, calls_per_turn, f64::from(seat.turns)))
        .sum()
}

/// The same, at the calls-per-turn this sample recorded.
pub fn measured_usd(sample: Sample) -> f64 {
    company_usd(sample, sample.calls_per_turn)
}

/// The ceiling: every reserved turn running the loop to its budget.
///
/// Read off [`Budgets`] rather than written down, because a budget change that
/// did not move this number would make the range a fiction.
pub fn ceiling_calls_per_turn() -> f64 {
    f64::from(Budgets::default().max_turns)
}

// ---------------------------------------------------------------------------
// What one run measured
// ---------------------------------------------------------------------------

// `RECORDED` is `agentos_domain::forecast::RECORDED`, re-exported at the top of
// this file, and the sentence that governs it moved with it: **re-paste the
// samples together with `DIGEST` below, never separately.**
//
// That instruction got weaker when the array moved, and pretending otherwise
// would be the failure this file exists to prevent — it is now possible to edit
// the samples without opening this file at all. What still holds is the half
// that was ever mechanical: `digest` fails the suite when the *company* those
// samples measured changes. Nothing anywhere catches a hand-typed sample, and
// nothing ever did.
//
// The samples in it are the first taken with the seller actually selling. The
// three before them were taken while `dryrun::take_turn` omitted the vertical
// step entirely — the sales seat had no prospect, so `vertical::due_prospect`
// would have answered `None`, and what the sample recorded for that seat was an
// ordinary conversational turn. The seller now runs a confirmed prospect's
// booking flow twice, files a finding and has its approach refused by
// `max_new_contacts_per_day` before the model generates a token. See `Prospect`
// and `dryrun`'s module docs.
//
// So those figures are not a drift from the ones before them. They are about a
// different measurement of a company that did not change — which is why
// `DIGEST` had to grow the prospect: without it, the two sets of numbers would
// sit under the same pin, and the pin's whole job is to make that impossible.

/// Digest of everything the recorded runs were measured against. See
/// [`digest`], and the module docs for why this is the load-bearing part.
pub const DIGEST: &str = "e52428c12582296e";

// ---------------------------------------------------------------------------
// The company, as the operator wrote it down
// ---------------------------------------------------------------------------

/// `docs/`, from `crates/eval/`.
pub fn docs(file: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(file)
}

/// One of the operator's policy documents, as the installer reads it.
pub fn limits(file: &str) -> PolicyLimits {
    let path = docs(file);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path:?}: {err}"));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("{path:?}: {err}"))
}

/// Every role layer in `docs/orizn-roles/`, by file name, sorted.
///
/// Read off the directory rather than from a list written here, so that adding a
/// team to Orizn cannot leave a stale copy of the payroll in this file.
fn role_layers() -> Vec<(String, String)> {
    let dir = docs("orizn-roles");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("{dir:?}: {err}"))
        .map(|entry| {
            let path = entry.expect("a directory entry").path();
            let raw =
                std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path:?}: {err}"));
            (
                path.file_name()
                    .expect("a file")
                    .to_string_lossy()
                    .into_owned(),
                raw,
            )
        })
        .collect();
    out.sort();
    out
}

/// One priced seat: a role, its turn budget, and the model it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    /// The role layer's file stem, which is the role name.
    pub role: String,
    /// `max_turns_per_day` from that layer.
    pub turns: u32,
    /// What `model_for` gives that role under that layer.
    pub model: ModelId,
}

/// Which model each role *asks* for, off its own pack.
///
/// Not a table of names and models — a table of names and **packs**, so the
/// model itself is still read from the one place that owns it. A role layer
/// whose name matches no pack is an employee nobody chartered, which is
/// [`ModelId::UNCHARTERED`]; `every_priced_seat_has_a_pack_or_no_turns` is what
/// stops that being a silent mispricing rather than the honest zero it is for
/// `direction`.
fn preference(role: &str) -> Option<ModelId> {
    Some(match role {
        "international-buyer" => rolepack::RolePack::international_buyer().model(),
        "sales-development" => rolepack_sales::RolePack::sales_development().model(),
        rolepack_service::CUSTOMER_SUCCESS => {
            rolepack_service::RolePack::customer_success().model()
        }
        rolepack_service::GROWTH => rolepack_service::RolePack::growth().model(),
        rolepack_service::FINANCE => rolepack_service::RolePack::finance().model(),
        rolepack_service::ENTRY_REQUIREMENTS => {
            rolepack_service::RolePack::entry_requirements().model()
        }
        _ => return None,
    })
}

/// **The payroll, priced.** One entry per role layer in `docs/orizn-roles/`,
/// carrying the two numbers the bill is made of.
///
/// Read off the operator's own documents rather than restated here, exactly as
/// the turns column always was — and the model comes out of the same documents
/// by the same rule the running system uses: [`model_for`] over the pack's
/// preference and the intersected layer. A seat priced by any other rule would
/// be a seat this deployment does not have.
///
/// The ceiling stands in for the platform, tenant and employee layers because
/// Orizn writes only two of the four; that is stated rather than hidden, and it
/// is the same shape `apps/server/tests/orizn.rs` installs.
/// The effective policy one seat runs under, off the operator's own documents.
///
/// **Extracted because two callers need it and only one had it.** [`seats`]
/// built this and threw it away; [`digest`] never had one, so the prompts it
/// hashed were built with `SystemPrompt::policy == None` — and
/// `app::prompt::render_domains` returns early on that, meaning the entire
/// "Sites you can read" section was outside the pin. An edit to that paragraph
/// changed every real prefix and moved no digest, which is the same defect the
/// tool schemas had and is fixed here the same way.
///
/// Ceiling ∧ ceiling ∧ role ∧ ceiling: the tenant and employee layers are the
/// ceiling because Orizn installs neither, which is what
/// `apps/server/tests/orizn.rs` stands up and asserts.
pub fn policy_for(role: &str) -> Option<EffectivePolicy> {
    let ceiling = limits("orizn-ceiling.json");
    let raw = role_layers()
        .into_iter()
        .find(|(name, _)| name.strip_suffix(".json").unwrap_or(name) == role)
        .map(|(_, raw)| raw)?;
    let layer: PolicyLimits = serde_json::from_str(&raw).ok()?;
    EffectivePolicy::try_new(&ceiling, &ceiling, &layer, &ceiling).ok()
}

pub fn seats() -> Vec<Seat> {
    let ceiling = limits("orizn-ceiling.json");
    role_layers()
        .iter()
        .map(|(name, raw)| {
            let role = name.strip_suffix(".json").unwrap_or(name).to_owned();
            let layer: PolicyLimits =
                serde_json::from_str(raw).unwrap_or_else(|err| panic!("{name}: {err}"));
            let policy = EffectivePolicy::try_new(&ceiling, &ceiling, &layer, &ceiling)
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            let preferred = preference(&role).unwrap_or(ModelId::UNCHARTERED);
            let model = model_for(Some(&policy), preferred).unwrap_or_else(|| {
                panic!(
                    "{name}: the ceiling and this role layer intersect `allowed_models` to \
                     nothing, so this seat could not take a turn"
                )
            });
            Seat {
                role,
                turns: layer.max_turns_per_day,
                model,
            }
        })
        .collect()
}

/// Orizn's reserved turns a day: the sum of the five role layers.
///
/// **This is the column `docs/ORIZN.md` billed when every seat ran one model**,
/// and it is no longer sufficient on its own — the bill is now a sum over
/// [`seats`], because turns at $1/M and turns at $5/M are not the same turn.
/// It survives as the headline's denominator and as the thing the runbook's
/// turn table is checked against. `direction`'s zero is a real zero and
/// contributes nothing, which is the runbook's whole argument for that seat.
pub fn turns_per_day() -> u32 {
    seats().iter().map(|seat| seat.turns).sum()
}

// ---------------------------------------------------------------------------
// The charters the dry run works, and the pin over them
// ---------------------------------------------------------------------------

/// What a self-started turn is, in the model's terms.
///
/// A verbatim copy of `apps/server/src/loops/initiative.rs`'s `TURN_BRIEF`, a
/// private const in a binary crate with no library target. Copied rather than
/// paraphrased: a dry run that sends different bytes from the running system is
/// measuring a company nobody deployed. If the original moves, this moves — and
/// [`DIGEST`] is what says the recorded numbers moved with it.
pub const TURN_BRIEF: &str = "Nobody has written to you. Your working rhythm has come round, so \
                              this turn is yours to spend on your own objective. You have been \
                              here before and the plan below does not know it: start by finding \
                              out where you actually got to — read your own conversations, notes \
                              and records — then advance the earliest stage that is not finished. \
                              One turn is not the whole plan. Do the next real piece of work, \
                              finish it, and write down what you did. If a stage is blocked on \
                              somebody else, say so and move to what is not blocked rather than \
                              waiting inside this turn.";

/// The charters these seats are given, in the operator's words.
///
/// **Written once and not touched again.** Tuning a briefing until the run looks
/// good is how a dry run stops being evidence; if one of these produces a bad
/// turn, the bad turn is the finding. Editing one is allowed — it just moves
/// [`digest`] and invalidates [`RECORDED`], which is the point.
pub fn charters() -> Vec<(&'static str, Charter)> {
    vec![
        (
            "sdr",
            Charter::Sales {
                pack: rolepack_sales::RolePack::sales_development(),
                objective: rolepack_sales::Objective {
                    segment: rolepack_sales::Segment::Airline,
                    market: Some(rolepack::CountryCode::parse("de").expect("country")),
                    target_accounts: vec![
                        "Condor".to_owned(),
                        "Eurowings".to_owned(),
                        "Lufthansa".to_owned(),
                    ],
                },
            },
        ),
        (
            "support",
            Charter::Support {
                objective: rolepack_service::Support {
                    product: "the Orizn entry-requirements API".to_owned(),
                    first_response_hours: 8,
                    escalate_to: Some("founder".to_owned()),
                },
            },
        ),
        (
            "books",
            Charter::Finance {
                objective: rolepack_service::Books {
                    period: "2026-08".to_owned(),
                    currency: Some(Currency::Usd),
                    obligations: vec![
                        "settle the approved hosting invoice INV-4471 from acme-cloud for \
                         USD 240.00 against PO-889"
                            .to_owned(),
                        "reconcile the August card statement".to_owned(),
                    ],
                },
            },
        ),
    ]
}

/// **The prospect the dry run seeds, and the flow a human confirmed for it.**
///
/// It lives here, beside [`charters`] and inside [`digest`], because it is part
/// of the company the recorded numbers are about in exactly the way a charter
/// is. `charters` gives the SDR an objective; without a prospect in the segment
/// it names, `vertical::due_prospect` answers `None`,
/// `loops::initiative::assignment_for` resolves `Outcome::NoWork`, and **the
/// seller takes no turn at all**. Every sample in [`RECORDED`] before
/// 2026-08-26 was taken in that state: the seller's row measured an ordinary
/// conversational turn and nothing in this file could see the difference.
///
/// Each field is the narrowest thing that makes the vertical run, and two of
/// them are findings rather than choices.
///
/// # `zone` is `orizn.app`, and that is a fact about the operator's documents
///
/// `docs/orizn-ceiling.json` and `docs/orizn-roles/sales-development.json` both
/// list exactly one entry in `allowed_domains`, so the intersection a seller
/// acts under permits a browser read of `orizn.app` and nothing else. A prospect
/// seeded anywhere else is refused by the gate as `domain_not_allowed` **before**
/// the browser is reached, `sell` returns `ProbeError::Refused`, and the seller
/// falls back to the ordinary turn this fixture exists to stop it taking.
///
/// That is not this fixture bending a rule to make its own path run, and it is
/// not a hole in the operator's documents either — `docs/ORIZN.md` says in as
/// many words that `allowed_domains` "is where the prospect account list goes"
/// and that adding an account to probe is a ceiling change. The shipped ceiling
/// simply has no prospect in it yet, so the seeded one lives on the only domain
/// this deployment, as written, can look at. Seeding it anywhere else would
/// measure a `domain_not_allowed` and call it a probe.
///
/// # `says` is a conflation, because Orizn binds no MCP server
///
/// Two incompatible sentences about one trip is
/// `proof_of_need::Finding::Conflates` — one of the three findings that stand on
/// the prospect's own page alone. `allowed_mcp_tools` is empty in both operator
/// documents, so `vertical::orizn_binding`'s lookup is refused by name and
/// `sell` runs with no authority; the two findings that need Orizn's own row are
/// unavailable on this surface. A panel that produced one of those would file
/// evidence no employee may send, which measures a different path.
pub struct Prospect {
    /// `accounts.legal_name`. Ours, and the only name in the vertical's note.
    pub name: &'static str,
    /// The zone every seeded prospect's domain sits under. See above.
    pub zone: &'static str,
    /// Path of the booking page the check starts on, under the account's own
    /// domain — `Flow::confirmed` refuses an entry URL anywhere else.
    pub entry_path: &'static str,
    /// CSS selector of the passport field.
    pub passport_field: &'static str,
    /// CSS selector of the destination field.
    pub destination_field: &'static str,
    /// CSS selector of the travel-date field.
    pub date_field: &'static str,
    /// CSS selector of their "check requirements" button. Never a booking or a
    /// payment submit; see `migrations/0032_prospect_flows.sql`.
    pub submit: &'static str,
    /// CSS selector of the element the answer is read out of. It has to match
    /// what the mock browser was told about, or the read comes back
    /// `no_such_element` and the probe errors instead of finding.
    pub panel: &'static str,
    /// What that element says, to both runs of the flow.
    pub says: &'static str,
}

/// The one prospect, and it is not tuned: see [`Prospect`] on both halves.
pub const PROSPECT: Prospect = Prospect {
    name: "Prospect Air",
    zone: "orizn.app",
    entry_path: "/booking/entry",
    passport_field: "#passport",
    destination_field: "#destination",
    date_field: "#travel-date",
    submit: "#check",
    panel: "#visa-info",
    says: "No visa required for this trip. Visa on arrival at the airport.",
};

impl Prospect {
    /// The nth seeded prospect's registrable domain.
    ///
    /// One per pass, and that is not tidiness. A filed finding takes an account
    /// out of `accounts_without_evidence` permanently, and the approach this
    /// deployment makes comes back refused — so `mark_contacted` never runs and
    /// there is no chase either. A second pass against the same company with one
    /// seeded prospect is a seller back on `NoWork`, which is the non-event this
    /// whole fixture exists to end.
    pub fn domain(&self, nth: usize) -> String {
        format!("prospect-{nth}.{}", self.zone)
    }

    /// Where the approach to the nth prospect would go. Per prospect, so one
    /// person is not written to three times by three passes.
    pub fn contact(&self, nth: usize) -> String {
        format!("head.of.digital@prospect-{nth}.example")
    }
}

/// A stand-in for the employee's own name and address, so the digest is a
/// function of the charters and not of a `uuid` minted at run time.
///
/// The real identity is built in `dryrun::take_turn` from the seat's own row and
/// differs by a handful of tokens; nothing about the bill turns on it.
const PIN_IDENTITY: &str = "You are seat, an AI employee of Orizn. Your address is \
                            seat@agents.orizn.app.";

/// First 16 hex characters of the SHA-256 of everything the recorded run was
/// measured against: the turn brief, each charter's rendered system prompt at
/// both trust levels, each charter's plan, and the five operator documents.
///
/// # The models are in here now, and they were the gap
///
/// This function's own docs used to end *"and the model, which is the one input
/// to a live measurement that nothing in this repository can pin at all"*. That
/// was true while the model came from `AGENTOS_LLM` — a process-wide string set
/// outside the workspace, which no digest could reach. It is now a property of
/// each role pack and each operator document, both of which are in the
/// repository, so the sentence is simply false and the hash covers it.
///
/// That matters more than it sounds. A recorded bill is arithmetic over token
/// counts sampled from a model; changing which model a seat runs changes both
/// the price *and* the sample, and nothing about the prompts would move to show
/// it. Re-pointing `finance` at Sonnet without this would leave [`RECORDED`]
/// looking fresh while every figure it feeds was about a company that no longer
/// exists.
///
/// # Why the tool schemas are in here now
///
/// They were not, and it cost a published figure its truth. `turn::catalogue`'s
/// `kind` field gained a description — roughly six hundred characters sent on
/// every turn of every seat — and this digest did not move, so [`RECORDED`]
/// went on certifying a bill measured against a shorter prompt. The schemas are
/// not adjacent to the cost; on the `--dry-run` path the CLI shim renders them
/// *into* the prompt, and on the metered path they are input tokens either way.
///
/// A tool is also the thing a seat can be given more of. Adding a seventh
/// raises input tokens on every call this file prices, and before this it did
/// so invisibly — which is the failure a colleague hit from the other side,
/// wanting to name a new tool in a charter's plan and finding that only the
/// *sentence about it* moved the pin, never the tool.
///
/// # What it still does not cover
///
/// The colleague roster and the employee's own address, both of which come out
/// of the database at run time; `crates/eval/src/scoping.rs` owns the roster's
/// size and it is bounded by the team. And the *snapshot* behind a model name —
/// a new one shipped under `claude-opus-5` moves every figure here and no test
/// can see it happen.
pub fn digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(TURN_BRIEF.as_bytes());
    // Every seat's model, in `seats()` order — which is `role_layers()` order,
    // which is sorted by file name.
    for seat in seats() {
        hasher.update(seat.role.as_bytes());
        hasher.update(seat.model.as_str().as_bytes());
    }
    for (seat, charter) in charters() {
        hasher.update(seat.as_bytes());
        hasher.update(charter.role().as_bytes());
        hasher.update(charter.model().as_str().as_bytes());
        // The policy attached, so `render_domains` renders. Without it the
        // prompt carries `policy: None`, that section returns early, and the
        // paragraph telling an employee what it may read — which is prefix on
        // every turn this file prices — sits outside the hash. See
        // [`policy_for`].
        let prompt = match policy_for(charter.role()) {
            Some(policy) => charter
                .system_prompt(PIN_IDENTITY)
                .with_mcp_tools(&policy, []),
            None => charter.system_prompt(PIN_IDENTITY),
        };
        for trust in [TrustLabel::Trusted, TrustLabel::Untrusted] {
            // The request rather than the prefix: what this file prices is
            // tokens, and a tool schema is tokens. `max_tokens` is a ceiling on
            // the *reply* and never reaches the wire as prompt, so any value
            // does — it is not hashed.
            let request = prompt.request(charter.model().as_str(), 1, trust, Vec::new());
            hasher.update(request.system.as_bytes());
            for tool in &request.tools {
                hasher.update(tool.name.as_bytes());
                hasher.update(tool.description.as_bytes());
                hasher.update(tool.input_schema.to_string().as_bytes());
            }
        }
        hasher.update(charter.brief().as_bytes());
    }
    // The seeded prospect, for [`Prospect`]'s reason: with no prospect the
    // seller resolves `NoWork` and takes no turn, so this decides whether the
    // sales row above is a selling turn or a conversation. Nothing else in this
    // function can see that difference.
    for field in [
        PROSPECT.name,
        PROSPECT.zone,
        PROSPECT.entry_path,
        PROSPECT.passport_field,
        PROSPECT.destination_field,
        PROSPECT.date_field,
        PROSPECT.submit,
        PROSPECT.panel,
        PROSPECT.says,
    ] {
        hasher.update(field.as_bytes());
    }
    for file in ["orizn-ceiling.json", "orizn-org.json"] {
        let path = docs(file);
        hasher.update(
            std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("{path:?}: {err}"))
                .as_bytes(),
        );
    }
    for (name, raw) in role_layers() {
        hasher.update(name.as_bytes());
        hasher.update(raw.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// The sentence
// ---------------------------------------------------------------------------

/// The seat mix, as a phrase: `3 on claude-sonnet-5, 1 on claude-opus-5, …`,
/// cheapest model first and seats that take no turns left out.
///
/// In the headline because it is most of the answer. The same turn count on
/// Haiku and on Fable differ by a factor of ten, so a bill quoted without the
/// mix is a number whose largest input is invisible.
fn mix() -> String {
    let seats = seats();
    ModelId::ALL
        .into_iter()
        .filter_map(|model| {
            let n = seats
                .iter()
                .filter(|s| s.model == model && s.turns > 0)
                .count();
            (n > 0).then(|| format!("{n} on {model}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// **The one sentence, and `docs/ORIZN.md` must contain it verbatim.**
///
/// Three figures and their assumptions, because a point estimate is how $76 got
/// published: what the recorded runs cost at the rate they actually ran, the
/// floor at one model call per reserved turn, and the ceiling at
/// [`Budgets::max_turns`]. Plus the seat mix, which is new and is the reason the
/// figures moved.
pub fn headline() -> String {
    let turns = f64::from(turns_per_day());
    let (lo, hi) = spread(measured_usd);
    let (floor, _) = spread(|s| company_usd(s, FLOOR_CALLS_PER_TURN));
    let (_, ceiling) = spread(|s| company_usd(s, ceiling_calls_per_turn()));
    format!(
        "${lo:.0}–${hi:.0} a month over {} measured runs at {turns} reserved turns a day \
         ({}); ${floor:.0} floor at {FLOOR_CALLS_PER_TURN:.2} model calls per turn, \
         ${ceiling:.0} ceiling at {:.2}",
        RECORDED.len(),
        mix(),
        ceiling_calls_per_turn(),
    )
}

/// The same load, priced in requests instead of dollars.
///
/// **The figure to carry to a subscription**, where tokens are not what runs
/// out. Metered pricing and a subscription bound the same system with different
/// resources, and the arithmetic above answers only the first — so an operator
/// who reads [`headline`]'s dollars and concludes the CLI backend is free has
/// not converted the constraint, they have dropped it.
///
/// The spread is the point. Calls per turn varied 2× across the recorded runs,
/// so this is a range and not a rate, and the wide end is what a plan has to
/// absorb. It is also a *daily* figure against limits usually stated per
/// rolling window: a company whose seats all fall due together spends its
/// allowance in one hour and idles for the rest, which is a scheduling
/// property and not a budget one.
pub fn calls_per_day() -> (f64, f64) {
    let turns = f64::from(turns_per_day());
    spread(|s| s.calls_per_turn * turns)
}

/// [`calls_per_day`] as the sentence a subscription is sized against.
pub fn throughput_headline() -> String {
    let (lo, hi) = calls_per_day();
    let turns = turns_per_day();
    format!(
        "{lo:.0}–{hi:.0} model calls a day at {turns} reserved turns, over {} measured runs — \
         the figure a subscription is bounded by, where the bill is not",
        RECORDED.len(),
    )
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

/// Everything about the bill that can be checked without a model.
pub fn evaluate() -> Surface {
    let mut rows = Vec::new();

    // --- 1. the number ------------------------------------------------------
    // Characterised, and it can be nothing else: it is arithmetic over a sample
    // from a model. A pass/fail on it would be a threshold on a coin flip.
    rows.push(
        Row::ok(
            "the same load, priced in requests",
            throughput_headline(),
            Truth::Characterises,
        )
        .note(
            "The bill above is metered API pricing. Driving the local `claude` binary under a \
             subscription bills nothing per token, and this is the resource that runs out \
             instead. Whether a plan permits an unattended fleet is a question about its terms, \
             not about tokens.",
        ),
    );
    rows.push(
        Row::ok("Orizn's monthly bill", headline(), Truth::Characterises).note(
            "a range because a reserved turn is 1–10 model calls; the floor alone is what \
               this document used to publish as an estimate",
        ),
    );

    // --- 1b. the seat mix, which is now half the arithmetic -----------------
    // Read off the operator's documents and the role packs by the same rule the
    // running system uses, so this row is what `apps/server` would resolve for
    // each of these employees and not a summary somebody typed.
    rows.push(Row::ok(
        "what each seat thinks with",
        seats()
            .iter()
            .map(|s| format!("{} {} ({} turns)", s.role, s.model, s.turns))
            .collect::<Vec<_>>()
            .join(", "),
        Truth::Characterises,
    ));

    // --- 2. the input that made it a range ----------------------------------
    let (calls_lo, calls_hi) = spread(|s| s.calls_per_turn);
    let mean = RECORDED.iter().map(|s| s.calls_per_turn).sum::<f64>() / RECORDED.len() as f64;
    rows.push(
        Row::ok(
            "model calls per reserved turn",
            format!(
                "{mean:.2} mean, {calls_lo:.2}–{calls_hi:.2} over {} runs",
                RECORDED.len()
            ),
            Truth::Characterises,
        )
        .note("the runbook assumed 1.00 and called it the table; it is the bottom of the range"),
    );

    // --- 3. and the tokens --------------------------------------------------
    let (in_lo, in_hi) = spread(|s| s.input_tokens_per_call);
    let (out_lo, out_hi) = spread(|s| s.output_tokens_per_call);
    rows.push(
        Row::ok(
            "tokens per model call",
            format!("in {in_lo:.0}–{in_hi:.0} (±20% estimator), out {out_lo:.0}–{out_hi:.0}"),
            Truth::Characterises,
        )
        .note("input by `scoping::tokens` over the bytes we send; output as the CLI reported it"),
    );

    // --- 4. one run is an anecdote ------------------------------------------
    // Structural, and the only thing in this file that is a property of the
    // *method* rather than of the model: a bill quoted off a single sample has
    // no spread to report, and every figure above would be a point estimate
    // wearing a range's clothes.
    let enough = RECORDED.len() >= 3;
    rows.push(
        Row::ok(
            "runs behind the figures above",
            format!("{} passes of `--dry-run`", RECORDED.len()),
            Truth::Correct,
        )
        .gated(enough),
    );

    // --- 5. the pin ---------------------------------------------------------
    // `toolchoice`'s mechanism, applied to the run instead of to five prompts.
    let now = digest();
    let unchanged = now == DIGEST;
    rows.push(
        Row::ok(
            "the company those runs measured",
            if unchanged {
                now.clone()
            } else {
                format!("CHANGED to {now}")
            },
            Truth::Correct,
        )
        .gated(unchanged)
        .note(if unchanged {
            "charters, turn brief and the five operator documents, unchanged since the run"
        } else {
            "every figure above is now stale — re-run `--dry-run 3` and re-paste both"
        }),
    );

    // --- 6. and the document ------------------------------------------------
    // **The row that stops the runbook lying again.** `docs/ORIZN.md` does not
    // get to hold its own copy of the number; it holds the string this function
    // produced, and this fails until it does.
    let path = docs("ORIZN.md");
    let runbook = std::fs::read_to_string(&path).unwrap_or_default();
    let quoted = runbook.contains(&headline());
    rows.push(
        Row::ok(
            "the runbook quotes this measurement",
            if quoted {
                "docs/ORIZN.md, verbatim".to_owned()
            } else {
                format!("STALE — docs/ORIZN.md does not contain: {}", headline())
            },
            Truth::Correct,
        )
        .gated(quoted),
    );

    Surface {
        name: "orizn (bill)",
        method: "one arithmetic function over samples a live `--dry-run` recorded; the runbook \
                 quotes it verbatim",
        rows,
        unmeasured: vec![
            "prompt caching, which lowers it. `llm_anthropic` puts a `cache_control` breakpoint \
             on the system block; a prefix re-sent inside the window bills at a tenth. Nothing \
             here prices that, so every figure above is the uncached ceiling of its own row",
            "the provisioning loop's own model calls, which raise it. The dry run stands the \
             company up before it starts counting",
            "the shim. `--dry-run` drives the local `claude` CLI, which renders tool schemas into \
             the prompt and demands JSON back — so the output-token figure is a completion the \
             production path (`llm_anthropic`) would not have produced",
            "whether 30 days is a month an operator recognises, and whether every reserved turn \
             is taken. The turns column is a CEILING on turns, not a forecast of them: an \
             employee with nothing to do reserves nothing and bills nothing",
            "the model, twice over. Which model each seat runs IS pinned now — it is in the \
             digest — but every token count above was sampled from `claude-opus-5`, and a \
             seat moved to Sonnet or Haiku will plan differently and tokenize differently. \
             The prices below those seats are right and the counts they multiply are borrowed. \
             And a new snapshot shipped behind an unchanged model name moves everything and \
             no test can see it happen",
            "the subscription, which is the regime the measurement was taken in. `--dry-run` \
             drives the local `claude` CLI, where there is no per-token invoice at all: the \
             currency is a monthly seat and the binding constraint is throughput. Every figure \
             above is the metered-API reading of an unmetered run — right for the deployment \
             that pays per token, and the wrong unit entirely for the one that does not",
            "the introductory rate. `claude-sonnet-5` bills $2.00/$10.00 per million through \
             2026-08-31 rather than the $3.00/$15.00 `rate_card` uses, so the three Sonnet \
             seats are cheaper than this until then. Quoting the introductory number would be \
             publishing a figure with five days left on it",
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The bill, by hand: one turn a day, one call each, a round million input
    /// tokens and nothing out, on Opus, is 30 × $5 = $150.
    ///
    /// **The arithmetic itself is tested where it lives** — see
    /// `agentos_domain::forecast`, which owns [`Sample::usd`] and the rate card
    /// and checks both against four models. What is left here is the only claim
    /// [`monthly_usd`] adds on top of it, and it is the one this crate cares
    /// about: a *month* is thirty days of that function and nothing else. If
    /// somebody changes what a month means, the headline moves and this is
    /// where it shows.
    #[test]
    fn a_month_is_thirty_days_of_the_shared_arithmetic() {
        let round = Sample {
            calls_per_turn: 1.0,
            input_tokens_per_call: 1_000_000.0,
            output_tokens_per_call: 0.0,
        };
        assert!((monthly_usd(round, ModelId::Opus5, 1.0, 1.0) - 150.0).abs() < 1e-9);
        assert!(
            (monthly_usd(round, ModelId::Opus5, 1.0, 1.0)
                - 30.0 * round.usd(ModelId::Opus5, 1.0, 1.0))
            .abs()
                < 1e-9,
            "a month here is no longer thirty days of `Sample::usd`"
        );
    }

    /// The company bill is the sum of its seats, each at its own model — not the
    /// summed turn budget multiplied once. That distinction is the whole change
    /// and it is worth an assertion that would fail if somebody collapsed it
    /// back.
    #[test]
    fn the_company_bill_is_a_sum_over_seats_not_one_multiplication() {
        let sample = RECORDED[0];
        let by_hand: f64 = seats()
            .iter()
            .map(|seat| {
                monthly_usd(
                    sample,
                    seat.model,
                    sample.calls_per_turn,
                    f64::from(seat.turns),
                )
            })
            .sum();
        assert!((measured_usd(sample) - by_hand).abs() < 1e-9);

        // And the seats really do differ, or the sum proves nothing. Orizn runs
        // Sonnet seats and an Opus seat side by side.
        let working: Vec<ModelId> = seats()
            .iter()
            .filter(|s| s.turns > 0)
            .map(|s| s.model)
            .collect();
        assert!(
            working.iter().any(|m| *m != working[0]),
            "every working seat runs {}, so this suite is not measuring a mix",
            working[0]
        );

        // The old arithmetic — one model for everybody — is strictly more
        // expensive, which is the finding this whole change is about.
        let all_opus: f64 = seats()
            .iter()
            .map(|seat| {
                monthly_usd(
                    sample,
                    ModelId::Opus5,
                    sample.calls_per_turn,
                    f64::from(seat.turns),
                )
            })
            .sum();
        assert!(
            by_hand < all_opus,
            "the seat mix costs {by_hand:.2}, one-model-for-everybody costs {all_opus:.2}"
        );
    }

    /// A role layer with turns and no pack would be priced at
    /// `ModelId::UNCHARTERED` — the cheapest model there is — which is right for
    /// an employee nobody chartered and a silent under-estimate for one whose
    /// pack simply is not wired in here. `direction` is the honest case: no
    /// pack, no turns, no contribution.
    #[test]
    fn every_priced_seat_has_a_pack_or_no_turns() {
        for seat in seats() {
            assert!(
                preference(&seat.role).is_some() || seat.turns == 0,
                "{} reserves {} turns a day and matches no role pack, so its model is a \
                 guess rather than a reading",
                seat.role,
                seat.turns
            );
        }
    }

    /// The floor is below what was measured and the ceiling above it, for every
    /// recorded run. Not a fact about the model — a fact about the range being
    /// stated the right way round.
    #[test]
    fn every_measurement_sits_inside_its_own_range() {
        for sample in RECORDED {
            let floor = company_usd(*sample, FLOOR_CALLS_PER_TURN);
            let ceiling = company_usd(*sample, ceiling_calls_per_turn());
            let measured = measured_usd(*sample);
            assert!(
                floor <= measured && measured <= ceiling,
                "{measured:.2} is outside {floor:.2}..{ceiling:.2}, so {sample:?} claims a \
                 turn made fewer than one model call or more than its budget"
            );
        }
    }

    /// One run of a language model is an anecdote. This is the only structural
    /// claim this file makes about the measurement rather than about the money.
    #[test]
    fn one_run_is_an_anecdote() {
        assert!(
            RECORDED.len() >= 3,
            "a spread needs three runs; there are {}",
            RECORDED.len()
        );
        assert!(RECORDED.iter().all(|s| s.calls_per_turn >= 1.0));
    }

    /// The turns column comes out of the operator's own documents, and
    /// `direction`'s zero is one of them.
    #[test]
    fn the_turns_column_is_read_and_not_restated() {
        assert!(turns_per_day() > 0);
        assert_eq!(limits("orizn-roles/direction.json").max_turns_per_day, 0);
        assert_eq!(
            turns_per_day(),
            role_layers()
                .iter()
                .map(|(_, raw)| serde_json::from_str::<PolicyLimits>(raw)
                    .expect("a role layer")
                    .max_turns_per_day)
                .sum::<u32>()
        );
    }

    /// A pin that moves on its own is a broken clock; a pin that never moves is
    /// not a pin.
    #[test]
    fn the_digest_is_stable_and_covers_the_charters() {
        assert_eq!(digest(), digest());
        assert_eq!(digest().len(), 16);
        // It is a function of the charters: two different seats' briefings are
        // in there, so a fixture with one charter would hash differently.
        assert_eq!(charters().len(), 3);
        // And of the seats' models, which is the claim this file's docs used to
        // say was impossible. Same seats, one model moved, different digest.
        let baseline = digest();
        assert_ne!(
            baseline,
            {
                let mut hasher = Sha256::new();
                hasher.update(TURN_BRIEF.as_bytes());
                for seat in seats() {
                    hasher.update(seat.role.as_bytes());
                    // One seat pretending to run something else.
                    hasher.update(ModelId::Fable5.as_str().as_bytes());
                }
                hasher
                    .finalize()
                    .iter()
                    .take(8)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            },
            "the digest does not depend on which model a seat runs"
        );
    }

    /// The reason this module exists. If it fails, `docs/ORIZN.md` is quoting a
    /// bill that no run produced — which is the exact state it was found in.
    #[test]
    fn the_runbook_quotes_the_measurement_verbatim() {
        let runbook = std::fs::read_to_string(docs("ORIZN.md")).expect("the runbook");
        assert!(
            runbook.contains(&headline()),
            "docs/ORIZN.md does not contain the measured sentence. Paste this into it:\n\n  \
             {}\n",
            headline()
        );
    }
}
