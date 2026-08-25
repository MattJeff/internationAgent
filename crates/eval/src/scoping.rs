//! Does scoping an employee to its own team actually save tokens?
//!
//! # The claim, and why it was worth checking
//!
//! The whole hierarchy — team-scoped documents, per-employee threads, one
//! charter each — is justified in `app::knowledge`'s module docs by an
//! arithmetic argument: *"every turn pays for the context it carries"*, so an
//! employee that can see the whole company pays for the whole company, every
//! turn, forever. Nobody had put a number on it. This suite does.
//!
//! # What it found
//!
//! **The line was flat above the tenth employee, and the flatness was not
//! scoping's doing.** The context moved once, between two employees and ten, for
//! the only N-shaped reason there was: the employee's own *team* filling its
//! five recall slots. Past that it did not move again, because
//! [`RECALL_LIMIT`] is a constant with no company in it.
//!
//! **It sloped for one revision, and the slope has been scoped away.** When the
//! prefix began naming the tenant's MCP inventory the context went 4188 → 4639 →
//! 4863 tokens at 2, 10 and 50 employees, and every token of that growth was the
//! inventory: per tenant, filtered by risk and by nothing else. It now reads
//! **4188 → 4611 → 4611**, because
//! [`agentos_app::prompt::SystemPrompt::with_mcp_tools`] takes the employee's
//! [`EffectivePolicy`] and names the tools `allowed_mcp_tools` lets it call —
//! 105 → 105 → 105 tokens of prefix, against 105 → 133 → 357 for the same
//! inventory named to everybody. The colleague roster contributes 137 → 191 →
//! 191: it saturates with the employee's own team and then stops, which is what
//! it was designed to do and what
//! `the_roster_costs_the_same_in_a_company_of_fifty_as_in_one_of_ten` gates on.
//!
//! **No new mechanism came out of that.** The scope is not "the role" and not
//! "the team" as a thing this file invented: it is
//! [`PolicyLimits::allowed_mcp_tools`], intersected across platform ∧ tenant ∧
//! role ∧ employee, which the gate already enforces on every `McpCall` — and
//! whose `role` layer *is* the employee's team (`domain::org::Team::limits`,
//! capped at `Team::MAX_TOOLS_PER_EMPLOYEE`). Naming what is callable was
//! already the correct rule and was simply unwired. What is left sloping is the
//! deployment where an operator writes one tenant-wide allowlist and no team
//! layer: the row `…the same inventory with no policy scope` prices exactly
//! that, and there the slope is honest — those employees really may call all of
//! it, and a prefix that hid it would be hiding a capability rather than saving
//! a token.
//!
//! The tool catalogue is still five entries no matter how many MCP servers a
//! tenant binds, which is the collapsed `call_mcp_tool` doing its job — fewer
//! once the employee's role floor has narrowed it, which is a function of the
//! job and not of the payroll either.
//!
//! So the cost premise, taken literally, is **false**: scoping the corpus saves
//! nothing worth measuring whenever the employee's own scope holds five or more
//! matches, which is every corpus worth scoping. Retrieval is a fixed top-k, so
//! it is a fixed token budget whether it reaches one team or the whole tenant.
//! `app::knowledge`'s docs already concede this in prose ("the saving in bytes
//! is zero"); the row below is the number, and the number's **sign is
//! negative** — in this fixture the unscoped turn is the cheaper one, because
//! the other teams' passages are shorter. Which is the point: at a fixed top-k
//! the bill is set by whose prose fills the slots and not by whose slots they
//! are. What scoping buys is the *composition* of those five — a slot holding
//! the sales strategy is a slot not holding the answer — and that is a quality
//! argument, not a cost one.
//!
//! # The finding that mattered more than the flat line, and what came of it
//!
//! The previous revision of this file said the flat line was uninformative,
//! because it was flat for the wrong reason: the company was **absent** from the
//! prefix, not scoped out of it. No production path called
//! [`agentos_app::prompt::SystemPrompt::with_mcp_tools`], nothing named the
//! colleagues `message_colleague` takes as a free string, and the prediction
//! recorded here was that the first feature to put a company-shaped list in the
//! prefix would be the one that made the line slope.
//!
//! **Both are wired now**, and the prediction was half right, which is the
//! interesting half:
//!
//! * The **MCP inventory** is per *tenant*, so it sloped exactly as predicted
//!   and by roughly the predicted amount. What made it stop is not a second
//!   scoping mechanism but the rule the gate was already applying to the calls
//!   themselves: an employee is told about the tools its policy lets it call,
//!   asked through `policy::evaluate_mcp_call` rather than restated. The
//!   `Inventory::McpUnscoped` row below is the same measurement it always was,
//!   kept as the counterfactual — every employee paying for every server the
//!   company binds, on every turn.
//! * The **colleague roster** never did, and that was the design constraint it
//!   was built under. It is the employee's manager, its direct reports and its
//!   team-mates — `inbound::colleagues`, ruled on by `inbound::may_message` — so
//!   it is bounded by the team and not by the payroll. `Inventory::Unscoped`
//!   below is the counterfactual: the same roster with no join to
//!   `team_memberships`, which is what a company-wide list would have cost.
//!
//! The gap between each of those rows and its counterfactual is the whole
//! argument for scoping, stated in tokens, and it is the argument the *corpus*
//! row could never make — because retrieval is a fixed top-k and a fixed top-k
//! cannot slope, while a list of names is linear in what it lists. Scoping saves
//! nothing on documents and everything here. Both lists arrived at the same
//! bound the same way, too: by asking the rule that already decides whether the
//! thing may be reached, instead of writing a second rule about what may be
//! named.
//!
//! [`agentos_app::prompt::SystemPrompt::with_credential`] is still called by
//! nobody, and deliberately: no tool in `turn::catalogue` takes a credential,
//! `SecretStore` has no verb that enumerates one, and the only ref production
//! writes per employee is a provisioning canary. Its own doc comment carries the
//! three reasons.
//!
//! # Assertions are on shape, numbers are on the page
//!
//! Nothing here asserts "under 4,312 tokens". A reworded briefing would break
//! such a test and teach nobody anything. What is asserted is that neither list
//! in the prefix moves with company size while its unscoped twin does — for the
//! inventory as a *byte-identical prefix* across 2, 10 and 50 employees, which
//! is the strongest form the claim takes — that an untrusted turn is offered
//! strictly fewer tools, and that the corpus scoping saves less than one
//! passage. What is **characterised** rather than asserted is the total, which
//! still steps once between two employees and ten, and both counterfactuals.
//!
//! Every figure printed is an estimate with a stated error bound; every property
//! asserted is a comparison between two contexts weighed by the same estimator,
//! where that error cancels.

use std::collections::BTreeSet;

use agentos_app::knowledge::RECALL_LIMIT;
use agentos_app::prompt::Relation;
use agentos_app::rolepack::{CountryCode, Objective, RolePack};
use agentos_app::turn::{Context, tools_for};
use agentos_app::vertical::Charter;
use agentos_domain::action::{ActionKind, McpTool, Risk};
use agentos_domain::ids::Slug;
use agentos_domain::money::{Currency, Money};
use agentos_domain::policy::{EffectivePolicy, PolicyLimits};
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use agentos_providers::llm::{Content, LlmRequest, Message};

use crate::{Row, Surface, Truth};

// ---------------------------------------------------------------------------
// The approximation
// ---------------------------------------------------------------------------

/// Characters of a word that fit in one token.
///
/// BPE merges English into roughly four-character pieces and swallows the
/// leading space with them, which is why whitespace costs nothing below.
const WORD_CHARS_PER_TOKEN: usize = 4;

/// Characters of punctuation that fit in one token.
///
/// Lower, because `{"`, `":` and `"},` are each one token to a real tokenizer
/// but none of them is a word. Two is what keeps a JSON schema from being
/// counted a character at a time, which is the failure mode a single
/// chars-per-token ratio has on exactly the content this suite weighs most.
const MARK_CHARS_PER_TOKEN: usize = 2;

/// Tokens, approximately, with no tokenizer and no network.
///
/// # The approximation
///
/// Runs of alphanumerics cost `ceil(len / 4)`, runs of anything else cost
/// `ceil(len / 2)`, whitespace is free. It is content-aware on purpose: a flat
/// chars-per-token ratio is right for prose and wrong for JSON by a factor
/// approaching two, and half of what a turn is billed for here *is* JSON —
/// which is precisely the misreport a byte count would have produced.
///
/// # The error bound
///
/// **±20%, and unverified against a real tokenizer** — there is none in this
/// workspace (`crates/providers` counts the tokens a provider *reports*, in
/// `llm::Usage`, and never estimates one) and there is no network to ask. The
/// calibration available is the repo's own: `knowledge::CHUNK_CHARS` documents
/// 1200 characters as "roughly 300 tokens", i.e. 4.0 chars/token for prose, and
/// `the_estimator_agrees_with_the_number_this_repo_already_wrote_down` holds
/// this function to within 20% of it on real fixture prose. On JSON it lands
/// near 2.5 chars/token, which is the band a BPE tokenizer lands in for
/// punctuation-dense text. Multibyte characters inside words are undercounted:
/// `⟦UNTRUSTED⟧` is billed as roughly one token per character where a byte-level
/// fallback would charge more.
///
/// # Why the bound does not reach the assertions
///
/// Every property this suite gates on is a comparison of two contexts weighed
/// by this same function — flat versus sloped, trusted versus untrusted, one
/// company size against another. A systematic factor cancels in all of them.
/// The absolute figures in the report carry the ±20%; the pass/fail does not.
pub fn tokens(text: &str) -> usize {
    let mut total = 0usize;
    let mut run = 0usize;
    let mut word = false;

    for ch in text.chars() {
        let space = ch.is_whitespace();
        let alnum = ch.is_alphanumeric();
        if space || alnum != word {
            total += cost(run, word);
            run = 0;
            word = alnum;
        }
        if !space {
            run += 1;
        }
    }
    total + cost(run, word)
}

const fn cost(run: usize, word: bool) -> usize {
    if word {
        run.div_ceil(WORD_CHARS_PER_TOKEN)
    } else {
        run.div_ceil(MARK_CHARS_PER_TOKEN)
    }
}

/// What one request costs, split the way a reader asks about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Weighed {
    /// The rendered system prompt: rules, identity, briefing, inventory.
    pub system: usize,
    /// The tool schemas, as the JSON they are serialised into.
    pub tools: usize,
    /// The conversation: brief, plan, fenced message, fenced passages.
    pub messages: usize,
}

impl Weighed {
    /// Everything the turn is billed for before the model says a word.
    pub const fn total(self) -> usize {
        self.system + self.tools + self.messages
    }
}

/// Weigh a request as the provider will bill it: prompt, schemas, messages.
///
/// The tools go through `serde_json` because that is what leaves the process —
/// counting `ToolDef`'s fields as three strings would miss the braces, and the
/// braces are most of a JSON Schema.
pub fn weigh(request: &LlmRequest) -> Weighed {
    Weighed {
        system: tokens(&request.system),
        tools: request
            .tools
            .iter()
            .map(|tool| tokens(&serde_json::to_string(tool).unwrap_or_default()))
            .sum(),
        messages: request.messages.iter().map(message).sum(),
    }
}

fn message(message: &Message) -> usize {
    message
        .content
        .iter()
        .map(|block| match block {
            Content::Text { text } => tokens(text),
            Content::ToolUse { name, input, .. } => tokens(name) + tokens(&input.to_string()),
            Content::ToolResult { content, .. } => tokens(content),
        })
        .sum()
}

// ---------------------------------------------------------------------------
// A company
// ---------------------------------------------------------------------------

/// The company sizes measured. Two is a founder and a hire; fifty is the point
/// at which "it knows the whole company" would stop being a figure of speech.
pub const SIZES: [usize; 3] = [2, 10, 50];

/// Employees per team. Five is what makes fifty employees ten teams, which is
/// the number that has to appear in a prefix for the slope to be visible.
const TEAM_SIZE: usize = 5;

/// MCP tools each team's server declares. Three is modest — one ERP server is
/// forty, as `app::turn`'s docs point out.
const TOOLS_PER_SERVER: usize = 3;

/// One passage as the store holds it: `knowledge::CHUNK_CHARS` is 1200, and a
/// chunk shorter than that would flatter every number in this file.
///
/// Two documents, not one, alternating by team. Scoping's whole premise is that
/// another team's documents are *different* documents — a fixture where every
/// team writes the same runbook would make "the unscoped turn costs the same"
/// true by construction and prove nothing. These differ in topic and in length,
/// so the comparison in the report is between genuinely different five-slot
/// fills.
fn passage(team: usize, ordinal: usize) -> String {
    if team % 2 == 1 {
        return format!(
            "Team {team} pipeline notes, section {ordinal}. A prospect that has not replied to \
             three touches over eleven working days is closed as unresponsive and not \
             re-approached inside the quarter, because a fourth touch converts at a rate \
             indistinguishable from zero and costs the sender's reputation with the domain. \
             Discounting below the published rate card needs a named reason recorded against \
             the opportunity — volume, a multi-year term, or a reference agreement we actually \
             intend to use — and a discount granted without one is reversed at renewal, which \
             is a worse conversation than the one avoided. Trials run fourteen days from the \
             first successful API call and not from the day the contract was signed, because a \
             customer that has not integrated has not evaluated anything. Where a prospect asks \
             for a feature we do not have, the answer names the gap plainly and offers the date \
             we expect it rather than a maybe, and the date goes on the roadmap or the answer \
             is that we are not building it."
        );
    }
    format!(
        "Team {team} runbook, section {ordinal}. Payment terms with a supplier we have not \
         traded with before are 30% on order and 70% against the bill of lading, and nobody \
         may vary that without a human approving it in writing. A quotation is not comparable \
         until it names a currency, a quantity, an Incoterm and a validity date; a quotation \
         missing any of the four goes back to the supplier with the gap named rather than \
         being ranked against complete ones. Lead time is measured from the day the deposit \
         clears, not from the day the order is placed, and a supplier quoting from order date \
         is asked to restate. Certificates are verified against the issuing body's own \
         register and never against a PDF the supplier attached, because a PDF is a claim \
         about a certificate and not a certificate. Where the landed cost of two quotations \
         is within three percent, the round is decided on lead time and on whether the \
         supplier answered the last round at all, and the reasoning is written down in the \
         thread so the next round does not relitigate it. Samples are paid for only where \
         the tooling is genuinely bespoke; a stock item offered as a paid sample is a \
         supplier testing whether we read our own policy."
    )
}

/// A tenant with `employees` employees, spread over teams of [`TEAM_SIZE`],
/// each team with its own documents, its own objective and its own bound
/// server.
///
/// A struct with one field rather than three, because everything else about a
/// company that this measurement can see is a function of how many people are
/// in it — which is the claim under test, stated as a type.
#[derive(Debug, Clone, Copy)]
pub struct Company {
    /// How many employees. See [`SIZES`].
    pub employees: usize,
}

impl Company {
    /// Teams, rounded up: a company of two is one team.
    pub const fn teams(self) -> usize {
        self.employees.div_ceil(TEAM_SIZE)
    }

    /// Every chunk in the company's store, as `(team, text)`. Each employee
    /// contributes two passages of its own work, which is deliberately mean:
    /// it puts a two-person company *below* the top-k bound, so the one place
    /// this measurement can slope is visible rather than padded away.
    fn corpus(self) -> Vec<(usize, String)> {
        (0..self.employees)
            .flat_map(|who| {
                let team = who / TEAM_SIZE;
                [
                    (team, passage(team, who * 2)),
                    (team, passage(team, who * 2 + 1)),
                ]
            })
            .collect()
    }

    /// The chunks this employee's retrieval competes over, best-first.
    ///
    /// `Reach::Company` is not "the same documents and then some". Five slots
    /// contested by ten teams do not go to team zero because team zero was
    /// inserted first — a similarity search has no such loyalty — so the
    /// unscoped candidate list is taken one team at a time. That is what makes
    /// the comparison in the report mean anything: an unscoped turn carries
    /// four *other* teams' passages, and the bill barely notices — in this
    /// fixture it goes down, because those passages are shorter.
    fn candidates(self, reach: Reach) -> Vec<String> {
        let corpus = self.corpus();
        match reach {
            // Employee zero, so team zero. Which team an employee is on is a
            // join in the real query and a constant here.
            Reach::Team => corpus
                .into_iter()
                .filter_map(|(team, text)| (team == 0).then_some(text))
                .collect(),
            Reach::Company => {
                let mut out = Vec::with_capacity(corpus.len());
                for depth in 0.. {
                    let round: Vec<String> = (0..self.teams())
                        .filter_map(|team| {
                            corpus
                                .iter()
                                .filter(|(owner, _)| *owner == team)
                                .nth(depth)
                                .map(|(_, text)| text.clone())
                        })
                        .collect();
                    if round.is_empty() {
                        break;
                    }
                    out.extend(round);
                }
                out
            }
        }
    }

    /// **The roster, scoped the way production scopes it.** Employee zero, who
    /// heads team zero: its manager one team up, and the rest of team zero
    /// answering to it.
    ///
    /// The bound is [`TEAM_SIZE`] and there is no `self.employees` past that
    /// `min` — which is the entire point of the row it feeds. It saturates
    /// between two employees and ten for the same reason the recall does, and
    /// then it stops, at fifty as at ten. `inbound::colleagues` gets the same
    /// shape from `team_memberships`; this is what that costs in the prefix.
    fn roster(self) -> Vec<(Slug, Relation)> {
        let slug = |s: &str| Slug::parse(s).expect("fixture slug");
        // A manager exists at every company size above one, and there is
        // exactly one of them: the line is one link, never a walk.
        let mut out = vec![(slug("ceo"), Relation::Manager)];
        out.extend(
            (1..self.employees.min(TEAM_SIZE))
                .map(|who| (slug(&format!("employee-{who}")), Relation::Report)),
        );
        out
    }

    /// The roster with the join to `team_memberships` taken out: everybody.
    ///
    /// The thing that must not be built, priced. One name per employee in the
    /// tenant, in every employee's prefix, on every turn — which is where the
    /// bill stops being linear in headcount and starts being quadratic in it.
    fn payroll(self) -> Vec<(Slug, Relation)> {
        let slug = |s: &str| Slug::parse(s).expect("fixture slug");
        (1..self.employees)
            .map(|who| (slug(&format!("employee-{who}")), Relation::TeamMate))
            .collect()
    }

    /// **The allowlist, scoped the way the policy stack scopes it.** Team
    /// zero's server, because employee zero is on team zero.
    ///
    /// This is not a new mechanism invented for the measurement: an employee's
    /// `role` policy layer is its *team* (`domain::org::Team::limits`), and a
    /// team's `allowed_mcp_tools` is capped at `Team::MAX_TOOLS_PER_EMPLOYEE`.
    /// So the shape here — one team's server, whatever the tenant has bound —
    /// is what an operator writing a team layer produces, and the reason the
    /// row it feeds is flat is the same reason the roster's is: there is no
    /// `self.employees` in it.
    ///
    /// One `PolicyLimits` in all four positions because intersecting a layer
    /// with itself is a no-op, and the shape of the stack is `store::policy`'s
    /// claim rather than this file's.
    fn allowlist(self) -> EffectivePolicy {
        self.policy(
            self.inventory()
                .into_iter()
                .map(|(tool, _)| tool)
                .filter(|tool| tool.server.as_str() == "team-0-erp"),
        )
    }

    /// The same allowlist with the team layer taken out: everything the tenant
    /// has bound, granted to everybody.
    ///
    /// The counterfactual, and it is also the *literal* previous behaviour of
    /// this prefix — before `with_mcp_tools` consulted a policy, every employee
    /// was told about every bound tool whether it could call it or not. The row
    /// it feeds is therefore the same measurement the `Inventory::Unscoped` row
    /// used to be, kept so the saving has a number rather than a claim.
    fn tenant_wide(self) -> EffectivePolicy {
        self.policy(self.inventory().into_iter().map(|(tool, _)| tool))
    }

    fn policy(self, tools: impl IntoIterator<Item = McpTool>) -> EffectivePolicy {
        let limits = PolicyLimits {
            allowed_mcp_tools: tools.into_iter().collect(),
            ..Default::default()
        };
        EffectivePolicy::try_new(&limits, &limits, &limits, &limits)
            .expect("four identical layers, and no spend limits to reconcile")
    }

    /// What the tenant's MCP fleet holds: one server per team, three tools
    /// each, the last of them destructive so the taint filter has something to
    /// take away.
    fn inventory(self) -> Vec<(McpTool, Risk)> {
        let slug = |s: &str| Slug::parse(s).expect("fixture slug");
        (0..self.teams())
            .flat_map(|team| {
                (0..TOOLS_PER_SERVER).map(move |tool| {
                    (
                        McpTool::new(
                            slug(&format!("team-{team}-erp")),
                            slug(&format!("record-lookup-{tool}")),
                        ),
                        if tool == TOOLS_PER_SERVER - 1 {
                            Risk::High
                        } else {
                            Risk::Low
                        },
                    )
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// One employee's turn
// ---------------------------------------------------------------------------

/// How wide the retrieval reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// This employee's own team, which is what `knowledge::retrieve` does.
    Team,
    /// The whole tenant: the counterfactual the scoping argument is against.
    Company,
}

/// What the prefix names about the company around this employee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inventory {
    /// Neither: the prefix before either feature was wired. Kept as the
    /// baseline, because "what did this cost us" needs a before.
    Bare,
    /// **What production does now.** The MCP tools this employee's policy lets
    /// it call, filtered by risk on top of that, plus its own roster — manager,
    /// direct reports, team-mates, and nobody else. Both lists are scoped by
    /// the same thing the runtime rules with, one by `policy::evaluate_mcp_call`
    /// and the other by `inbound::may_message`.
    Named,
    /// The counterfactual the roster was built to avoid: the same prefix with
    /// every employee in the tenant named instead of one team's worth. Nothing
    /// builds this; it is here so the saving has a number rather than a claim.
    Unscoped,
    /// The inventory without the roster. Not a shape anything ships — it exists
    /// so the two terms can be told apart, because "the prefix grew" is not a
    /// finding until you can say *which* of them grew.
    McpOnly,
    /// The counterfactual for the *other* list: every tool the tenant has bound,
    /// named to an employee that may call three of them, and no roster.
    ///
    /// This is what the prefix did before `with_mcp_tools` took a policy, so the
    /// row it feeds is both the counterfactual and the changelog. It is also
    /// what an operator gets today by writing one tenant-wide allowlist and no
    /// team layer — in which case the slope is real and correct, because those
    /// employees really may call all of it.
    McpUnscoped,
}

/// The counterparty's message. One real supplier email, because the turn's
/// weight is dominated by what it is answering and a one-line fixture would
/// flatter every total here.
const INBOUND: &str = "from: sales@nordmetall.example\nsubject: Re: RFQ-2214 — stainless \
fasteners\n\nDear Purchasing,\n\nThank you for the enquiry. We can offer DIN 933 hexagon \
head screws in A4-80 stainless at EUR 0.184 per unit for 50,000 pieces, EXW Duisburg, \
validity 30 days from today. Lead time is 26 working days from receipt of the deposit. \
Our minimum order for this grade is 25,000 pieces. Payment terms are 40% on order and the \
balance before despatch. Certificates 3.1 to EN 10204 are included; the mill test reports \
are issued per batch. We can quote FCA Rotterdam separately if that suits your forwarder \
better — please confirm the Incoterm you want us to hold the price against.\n\nKind \
regards,\nAnja Vogt";

/// One buyer's turn, assembled the way `apps/server/src/main.rs` assembles one.
///
/// The order and the pieces are that handler's, not this file's invention:
/// standing brief, then the plan from the charter, then the message fenced,
/// then whatever the store returned fenced by the same `render_fenced`. What is
/// deliberately missing is the server's own `TURN_BRIEF`, a private const in
/// the binary crate — a constant, and a constant cannot slope, which is why its
/// absence changes nothing this suite claims. It is in `unmeasured` anyway.
///
/// The retrieval is the one step not run against the real query: there is no
/// database in a deterministic suite. What stands in for it is the bound that
/// the flat-line claim actually rests on — `LIMIT RECALL_LIMIT` — applied to
/// the chunks `Reach` says the employee is entitled to. The *selection* inside
/// that bound belongs to `knowledge::retrieve` and to the Postgres test
/// `scoping_pays_for_itself_and_here_is_the_number`; this measures what k
/// passages cost, which is the part that goes on the bill.
pub fn assemble(company: Company, reach: Reach, inventory: Inventory) -> LlmRequest {
    let charter = buyer();
    let prompt = match inventory {
        Inventory::Bare => charter.system_prompt(IDENTITY),
        // The two builders `apps/server/src/main.rs` and the initiative loop
        // both call, in the order they call them.
        Inventory::Named => charter
            .system_prompt(IDENTITY)
            .with_mcp_tools(&company.allowlist(), company.inventory())
            .with_colleagues(company.roster()),
        Inventory::Unscoped => charter
            .system_prompt(IDENTITY)
            .with_mcp_tools(&company.allowlist(), company.inventory())
            .with_colleagues(company.payroll()),
        Inventory::McpOnly => charter
            .system_prompt(IDENTITY)
            .with_mcp_tools(&company.allowlist(), company.inventory()),
        // The whole tenant's inventory, which is what a prefix built without
        // the policy named — the argument of `with_mcp_tools` is the only
        // difference between this and the row above it.
        Inventory::McpUnscoped => charter
            .system_prompt(IDENTITY)
            .with_mcp_tools(&company.tenant_wide(), company.inventory()),
    };

    let inbound = Untrusted::new(INBOUND.to_owned());
    let mut context = Context::new()
        .with_task(charter.brief())
        .with_untrusted(&inbound, "message-1");

    let recalled = company
        .candidates(reach)
        .into_iter()
        .take(RECALL_LIMIT.unsigned_abs() as usize);
    for (ordinal, text) in recalled.enumerate() {
        context =
            context.with_untrusted(&Untrusted::new(text), &format!("knowledge:doc-{ordinal}#0"));
    }

    prompt.request(
        MODEL,
        MAX_TOKENS,
        context.trust(),
        context.messages().to_vec(),
    )
}

const MODEL: &str = "claude-opus-5";
const MAX_TOKENS: u32 = 4_096;
const IDENTITY: &str =
    "You are lena, an AI employee at fabrikam.example. You answer from lena@fabrikam.example.";

/// The floor the weighed employee actually carries: a buyer's `proposable` set.
///
/// `tools_for` narrows by trust *and* by the employee's role pack, so a caller
/// has to say whose schemas it is measuring. It is the buyer's here because
/// `assemble` builds a `Charter::Purchasing` — measuring some other pack's
/// schemas against that request would be measuring two employees.
fn floor() -> BTreeSet<ActionKind> {
    RolePack::international_buyer().proposable().clone()
}

/// The employee being weighed: a fully specified objective, so the plan is the
/// six-stage one rather than the one-line "go and ask".
fn buyer() -> Charter {
    Charter::Purchasing {
        pack: RolePack::international_buyer(),
        objective: Objective {
            what: "A4-80 stainless hexagon head screws, DIN 933, M8x40".to_owned(),
            quantity: 50_000,
            max_unit_price: Some(Money::new(21, Currency::Eur).expect("a non-zero price")),
            delivery_country: Some(CountryCode::parse("de").expect("a country")),
            requirements: vec![
                "EN 10204 3.1 mill certificate per batch".to_owned(),
                "REACH declaration".to_owned(),
            ],
        },
    }
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

/// What one more employee costs a company, per day, in tokens.
///
/// `max_turns_per_day` counts *reserved turns* — one `Turn::run` each, see
/// `agentos_store::turns` — and a run makes between one and
/// `app::turn::Budgets::max_turns` model calls, every one of them re-sending
/// the prefix. So this is the floor: the number an operator gets if every turn
/// is answered in a single round trip. Ten times it is the ceiling.
///
/// [`Inventory::Named`] because that is what production sends — and it is why
/// this stopped being a single number: see the row it feeds.
pub fn per_day(company: Company) -> usize {
    let turns = RolePack::international_buyer().limits().max_turns_per_day as usize;
    weigh(&assemble(company, Reach::Team, Inventory::Named)).total() * turns
}

/// Everything measured about what an employee's context costs.
pub fn evaluate() -> Surface {
    let mut rows = Vec::new();

    let at = |inventory: Inventory| -> Vec<Weighed> {
        SIZES
            .iter()
            .map(|&employees| weigh(&assemble(Company { employees }, Reach::Team, inventory)))
            .collect()
    };
    let join = |weighed: &[Weighed], of: fn(Weighed) -> usize| -> String {
        weighed
            .iter()
            .map(|w| of(*w).to_string())
            .collect::<Vec<_>>()
            .join(" → ")
    };

    // --- 1. does the context grow with the company? -------------------------
    // **It does now**, and this row is the one that changed. Naming the tenant's
    // MCP inventory put a company-shaped term in the prefix, which is exactly
    // what the previous revision of this file predicted would happen to whatever
    // got wired first. It is characterised rather than gated because there is no
    // pass/fail here to state honestly: the number is the finding.
    let shipped = at(Inventory::Named);
    rows.push(
        Row::ok(
            "one turn's context at 2 / 10 / 50 staff",
            format!(
                "{} tok  (prompt {} + schemas {} + context {})",
                join(&shipped, Weighed::total),
                shipped[0].system,
                shipped[0].tools,
                shipped[0].messages,
            ),
            Truth::Characterises,
        )
        .note(
            "flat again above ten: the rows below say which terms saturate on their own \
               and which one had to be scoped",
        ),
    );

    // The prefix before either builder was wired. Not a row of its own — the
    // page has a line budget and "what it used to cost" is history rather than
    // measurement — but it is the zero the two rows below are measured from, and
    // `the_context_does_not_grow_with_the_company_around_it` still asserts that
    // this half is flat.
    let bare = at(Inventory::Bare);

    // --- 2. what does scoping the corpus save? ------------------------------
    // The headline, and it is not the one the hierarchy was sold on. Top-k is a
    // fixed budget: widening the reach from one team to the whole tenant
    // changes which five passages arrive, never how many.
    let biggest = Company {
        employees: SIZES[SIZES.len() - 1],
    };
    let scoped = weigh(&assemble(biggest, Reach::Team, Inventory::Bare));
    let unscoped = weigh(&assemble(biggest, Reach::Company, Inventory::Bare));
    // A passage is the unit the budget is denominated in, so "less than one"
    // is the honest way to say "nothing" without pinning a token count that a
    // reworded fixture would move.
    let saves_nothing = unscoped.messages.abs_diff(scoped.messages) < tokens(&passage(0, 0));
    rows.push(
        Row::ok(
            "…and scoping the corpus saves",
            format!(
                // Signed, and it comes out negative: the unscoped turn is
                // *cheaper*, because the other teams' passages happen to be
                // shorter. Printing a magnitude would have shown a reassuring
                // zero over a saving that runs the wrong way.
                "{:+} tok of {} — top-k is {RECALL_LIMIT} at every corpus size",
                unscoped.messages as isize - scoped.messages as isize,
                scoped.messages,
            ),
            Truth::Correct,
        )
        .gated(saves_nothing)
        .note("scoping can COST tokens: the sign is set by whose prose is longer, not by scope"),
    );

    // --- 3. the term that used to slope: the tenant's MCP inventory ---------
    // **The row this change was made to be able to print.** The inventory is
    // still per tenant; what the prefix names out of it is what this employee's
    // policy lets it call — `allowed_mcp_tools`, intersected across the four
    // layers, asked through the same `policy::evaluate_mcp_call` the gate rules
    // with. That set is the employee's team's, so it has no company size in it,
    // exactly like the roster below.
    let mcp = at(Inventory::McpOnly);
    let last = SIZES.len() - 1;
    let inventory_cost = |weighed: &[Weighed], i: usize| weighed[i].system - bare[i].system;
    let bounded = inventory_cost(&mcp, last) == inventory_cost(&mcp, last - 1);
    rows.push(
        Row::ok(
            "…of which the MCP inventory",
            format!(
                "{} tok of prefix as 2 staff become 50 (+{})",
                SIZES
                    .iter()
                    .enumerate()
                    .map(|(i, _)| inventory_cost(&mcp, i).to_string())
                    .collect::<Vec<_>>()
                    .join(" → "),
                inventory_cost(&mcp, last) - inventory_cost(&mcp, 0),
            ),
            Truth::Correct,
        )
        .gated(bounded)
        .note(
            "O(what this employee may call), not O(servers bound): `allowed_mcp_tools`, \
               which the gate already rules with. The row below is the same list unscoped",
        ),
    );

    // --- 3d. what the unscoped version cost ---------------------------------
    // The same inventory named to everybody, which is what this prefix did
    // before `with_mcp_tools` asked the gate. Characterised rather than gated:
    // it is a counterfactual, and it is also what an operator still gets by
    // writing one tenant-wide allowlist and no team layer — in which case the
    // slope is honest, because those employees really may call all of it.
    let everything = at(Inventory::McpUnscoped);
    rows.push(Row::ok(
        "…the same inventory with no policy scope",
        format!(
            "{} tok — +{} on every prefix at 50 staff, and linear in servers bound",
            SIZES
                .iter()
                .enumerate()
                .map(|(i, _)| inventory_cost(&everything, i).to_string())
                .collect::<Vec<_>>()
                .join(" → "),
            inventory_cost(&everything, last) - inventory_cost(&mcp, last),
        ),
        Truth::Characterises,
    ));

    // --- 3b. the term that does not: the colleague roster -------------------
    // **The row this feature was built to be able to print.** It saturates
    // between two employees and ten — the employee's own team filling up, the
    // same shape as the recall — and then stops. Fifty employees, ten teams, and
    // an employee is told about the same handful of people it was told about at
    // ten, because `inbound::colleagues` is a join on `team_memberships` and
    // there is no company size anywhere in it.
    let roster: Vec<usize> = SIZES
        .iter()
        .enumerate()
        .map(|(i, _)| shipped[i].system - mcp[i].system)
        .collect();
    let flat = roster[last] == roster[last - 1];
    rows.push(
        Row::ok(
            "…and of which the colleague roster",
            format!(
                "{} tok of prefix — manager, reports, team-mates, nobody else",
                roster
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(" → "),
            ),
            Truth::Correct,
        )
        .gated(flat)
        .note(
            "O(team). The gate is the whole point: a roster that sloped would make the bill \
               quadratic in headcount, because every employee pays for it every turn",
        ),
    );

    // --- 3c. what the unscoped version would have cost ----------------------
    // The counterfactual, priced. This is the same feature with the join to
    // `team_memberships` taken out — one line per employee in the tenant — and
    // it is the number that makes "do not list every employee" an argument
    // rather than a preference.
    let payroll = at(Inventory::Unscoped);
    rows.push(
        Row::ok(
            "…the same roster with no team join",
            format!(
                "{} tok — +{} on every prefix at 50 staff, and linear from there",
                SIZES
                    .iter()
                    .enumerate()
                    .map(|(i, _)| (payroll[i].system - mcp[i].system).to_string())
                    .collect::<Vec<_>>()
                    .join(" → "),
                (payroll[last].system - mcp[last].system) - roster[last],
            ),
            Truth::Characterises,
        )
        .note(
            "×50 employees ×their turns a day: the term scoping actually removes, unlike \
               the corpus, where top-k had already removed it",
        ),
    );

    // --- 4. what taint filtering costs ---------------------------------------
    let schema = |trust| -> usize {
        tools_for(trust, &floor())
            .iter()
            .map(|tool| tokens(&serde_json::to_string(tool).unwrap_or_default()))
            .sum()
    };
    let (trusted, untrusted) = (schema(TrustLabel::Trusted), schema(TrustLabel::Untrusted));
    let narrower = untrusted < trusted
        && tools_for(TrustLabel::Untrusted, &floor()).len()
            < tools_for(TrustLabel::Trusted, &floor()).len();
    rows.push(
        Row::ok(
            "an untrusted turn is offered less schema",
            format!(
                "{untrusted} vs {trusted} tok ({} tools vs {})",
                tools_for(TrustLabel::Untrusted, &floor()).len(),
                tools_for(TrustLabel::Trusted, &floor()).len(),
            ),
            Truth::Correct,
        )
        .gated(narrower),
    );

    // --- 5. the number an operator asks for ----------------------------------
    // One number again. It stopped being one when the prefix started naming the
    // tenant's whole inventory, and it is one again for the same reason the
    // roster never broke it: both lists are now scoped by the rule the runtime
    // enforces, so neither has the payroll in it. Measured from ten, where the
    // recall has already saturated.
    let day = per_day(biggest);
    let at_ten = per_day(Company { employees: 10 });
    rows.push(
        Row::ok(
            "one more employee costs, per day",
            format!(
                "{day} tok at 10 staff and at 50, at {} turns",
                RolePack::international_buyer().limits().max_turns_per_day
            ),
            Truth::Correct,
        )
        .gated(day == at_ten)
        .note(
            "a floor: one model call per reserved turn, and a run may make ten. What \
               makes it flat is that neither list in the prefix is a function of headcount",
        ),
    );

    Surface {
        name: "app::prompt (cost)",
        method: "real assembly, companies of 2/10/50; tokens by a stated ±20% estimator, not bytes",
        rows,
        unmeasured: vec![
            "the tokenizer. There is none in this workspace and no network — every absolute \
             figure above is `scoping::tokens`, ±20%, unverified against a real one",
            "three trusted paragraphs the real path adds and this one cannot reach: the server's \
             TURN_BRIEF, the initiative loop's, and `knowledge::RECALLED_BRIEF` — two private \
             consts in a binary crate and one private to `app`. The floor above is short by \
             them, and all three are constants, which cannot slope",
            "whether a real tenant's allowlist is team-shaped. The fixture grants one team's \
             server in the role layer, which is the shape `domain::org::Team` produces and \
             caps; an operator who writes one tenant-wide layer instead gets the row above \
             it, honestly, because those employees really may call all of it. Nothing in \
             this workspace writes `allowed_mcp_tools` — `store::policy::default_ceiling` \
             grants none — so which of the two a deployment gets is an operator's decision \
             and not a measurement",
            "the roster's SHAPE, only its size. Whether an employee is told about the right \
             colleagues is `inbound::colleagues`' own claim and it needs Postgres — \
             `a_roster_is_the_line_and_the_team_and_stops_two_links_away` owns it. This file \
             weighs a fixture roster of the size the real query returns and asserts nothing \
             about whose names are in it",
            "what a hire costs. Adding somebody to a team invalidates that team's cached \
             prefixes exactly once, and the row above prices the steady state rather than the \
             transition. One uncached prefix per team-mate per hire, against a cache read on \
             every other turn — but there is no rate card here to turn that into money",
            "growth WITHIN a run: the loop re-sends a growing history up to `Budgets::max_turns`, \
             and only the first round trip is weighed here",
            "cache reads, counted at full price like `Budgets::max_tokens` counts them. The money \
             is cheaper by the cache-read rate, and no rate card lives in this workspace",
            "whether five passages are the right five. That is retrieval quality, it needs \
             Postgres and judgement, and `knowledge`'s own DB test owns it",
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The estimator's only external anchor, and it is this repo's own:
    /// `knowledge::CHUNK_CHARS` documents 1200 characters as "roughly 300
    /// tokens". A fixture passage is that size and that kind of prose, so if
    /// this function disagrees with the number the codebase already wrote down,
    /// one of the two is wrong and a reader deserves to be told which.
    #[test]
    fn the_estimator_agrees_with_the_number_this_repo_already_wrote_down() {
        let text = passage(0, 0);
        let chars = text.chars().count();
        let per_token = chars as f64 / tokens(&text) as f64;
        assert!(
            (3.2..=4.8).contains(&per_token),
            "{per_token:.2} chars/token on prose; the repo's own figure is 4.0 and the \
             stated bound is ±20%"
        );
    }

    /// JSON is not prose and must not be counted as if it were — that is the
    /// misreport the whole content-aware rule exists to avoid.
    #[test]
    fn json_costs_more_per_character_than_prose_does() {
        let schemas =
            serde_json::to_string(&tools_for(TrustLabel::Trusted, &floor())).expect("json");
        let json = schemas.chars().count() as f64 / tokens(&schemas) as f64;
        let prose = passage(0, 0).chars().count() as f64 / tokens(&passage(0, 0)) as f64;
        assert!(json < prose, "{json:.2} vs {prose:.2} chars/token");
        assert!((2.0..=3.5).contains(&json), "{json:.2} chars/token on JSON");
    }

    /// Monotone, and free where a tokenizer is free. A counter that could go
    /// down when text is added would break every comparison in the suite.
    #[test]
    fn adding_text_never_lowers_the_count() {
        assert_eq!(tokens(""), 0);
        assert_eq!(tokens("   \n\t "), 0);
        let base = tokens(INBOUND);
        assert!(tokens(&format!("{INBOUND} and one more clause")) > base);
    }

    /// The claim this suite was built for, and now the **baseline** rather than
    /// the headline: with nothing about the company named in the prefix, past
    /// the point where an employee's own team fills its recall slots the company
    /// around it costs nothing. Not "under N tokens" — a reworded briefing must
    /// not fail this.
    ///
    /// It is still worth asserting, because it is what says the growth measured
    /// in `the_mcp_inventory_is_the_term_that_grows_with_the_company` comes from
    /// the inventory and not from something that was always there.
    ///
    /// The one step that does exist, between two employees and ten, is the
    /// top-k filling up. It is bounded by [`RECALL_LIMIT`] passages, so the
    /// second assertion is the real statement of the property: whatever growth
    /// there is has a constant ceiling and no company size in it.
    #[test]
    fn the_context_does_not_grow_with_the_company_around_it() {
        let weighed: Vec<Weighed> = SIZES
            .iter()
            .map(|&employees| {
                weigh(&assemble(
                    Company { employees },
                    Reach::Team,
                    Inventory::Bare,
                ))
            })
            .collect();
        let (small, mid, large) = (weighed[0], weighed[1], weighed[2]);
        assert_eq!(
            mid, large,
            "five times the company for the same work cost more: {weighed:?}"
        );
        let ceiling = RECALL_LIMIT.unsigned_abs() as usize * tokens(&passage(0, 0));
        assert!(
            large.total() - small.total() < ceiling,
            "the growth below saturation is not bounded by the top-k budget: {weighed:?}"
        );
        // And the corpus really did grow underneath it, or the fixture proves
        // nothing at all.
        assert!(
            Company { employees: 50 }.corpus().len() > Company { employees: 2 }.corpus().len() * 10
        );
    }

    /// The uncomfortable half. Widening the retrieval from one team to the
    /// whole tenant is not measurably cheaper, because top-k is a fixed budget
    /// — so the arithmetic the hierarchy was justified by does not hold, and
    /// saying so is worth more than a green test that never asked.
    ///
    /// "Less than one passage" rather than "exactly equal": the five slots come
    /// back full either way, and which team's prose fills them moves the count
    /// by a handful of tokens. Pinning that handful would be pinning the
    /// fixture's wording.
    #[test]
    fn scoping_the_corpus_saves_less_than_one_passage() {
        let company = Company { employees: 50 };
        let scoped = weigh(&assemble(company, Reach::Team, Inventory::Bare));
        let unscoped = weigh(&assemble(company, Reach::Company, Inventory::Bare));
        assert!(
            unscoped.messages.abs_diff(scoped.messages) < tokens(&passage(0, 0)),
            "if these ever differ by a whole passage, retrieval stopped being a fixed \
             top-k and the cost argument for scoping has become true — rewrite this \
             module's docs. scoped {scoped:?}, unscoped {unscoped:?}"
        );
        // The counterfactual has to be a different set of documents, or this
        // measures nothing: an unscoped turn holds four other teams' passages.
        assert_ne!(
            company.candidates(Reach::Team)[..RECALL_LIMIT.unsigned_abs() as usize],
            company.candidates(Reach::Company)[..RECALL_LIMIT.unsigned_abs() as usize]
        );
        assert_eq!(scoped.system, unscoped.system);
    }

    /// **The assertion this task exists for**, and it is a property rather
    /// than a number: a tenant that binds nine more servers does not enlarge the
    /// prefix of an employee that may not call them. Not "grows slowly" —
    /// byte-identical, at 2, 10 and 50 employees.
    ///
    /// `McpOnly`, so the roster is not in the comparison and what is left is the
    /// inventory alone. The fixture binds one server per team, so the tenant's
    /// inventory really is ten times bigger at fifty employees than at two —
    /// asserted below, or this compares two prefixes that were the same anyway.
    #[test]
    fn the_prefix_does_not_grow_when_the_tenant_binds_servers_this_employee_cannot_use() {
        let prefix = |employees: usize| {
            assemble(Company { employees }, Reach::Team, Inventory::McpOnly).system
        };
        let smallest = prefix(SIZES[0]);
        for &employees in &SIZES[1..] {
            assert_eq!(
                smallest,
                prefix(employees),
                "{employees} employees' worth of bound servers changed a prefix that may \
                 reach one team's"
            );
        }

        // The fixture is not vacuous in either direction: the tenant's
        // inventory grows tenfold across that range, and the employee's own
        // allowlist does not move at all.
        let inventory = |employees: usize| Company { employees }.inventory().len();
        assert_eq!(inventory(SIZES[SIZES.len() - 1]), inventory(SIZES[0]) * 10);
        // And what the prefix names is what the gate would allow — the same
        // question `with_mcp_tools` asks, asked here about the whole inventory
        // of the biggest company, in both directions.
        let company = Company { employees: 50 };
        let allowlist = company.allowlist();
        for (tool, risk) in company.inventory() {
            let named = smallest.contains(&tool.to_string());
            let callable = agentos_domain::policy::evaluate_mcp_call(&allowlist, &tool).is_allow();
            // The taint filter comes first and this turn is untrusted, so a
            // high-risk tool is absent whatever the policy says — the policy
            // narrows on top of that filter and never widens it.
            assert_eq!(
                named,
                callable && !risk.is_high(),
                "{tool} is named={named} but callable={callable} at risk {risk:?}"
            );
        }
    }

    /// The counterfactual, and the reason the row above is worth printing: the
    /// same prefix built without the policy *does* slope, so the flat line is
    /// the scoping's doing and not the fixture's.
    #[test]
    fn the_unscoped_inventory_still_grows_with_the_company() {
        let unscoped = |employees: usize| {
            weigh(&assemble(
                Company { employees },
                Reach::Team,
                Inventory::McpUnscoped,
            ))
        };
        // Ten and fifty, not two and fifty: at ten the recall has already
        // saturated, so anything that moves from here is the prefix and only
        // the prefix.
        let (small, large) = (unscoped(10), unscoped(50));
        assert!(
            large.system > small.system,
            "naming the tenant's whole inventory did not cost more in a bigger tenant, \
             which would mean the fixture binds nothing"
        );
        // It is the prefix that grew and nothing else: the schemas stay four
        // entries however many servers a tenant binds, which is the collapsed
        // `call_mcp_tool` doing its job.
        assert_eq!(small.tools, large.tools);
        assert_eq!(small.messages, large.messages);
    }

    /// Taint filtering is a saving as well as a control, and the saving is real
    /// but small — the point of the row is the strict inequality, not the size.
    #[test]
    fn an_untrusted_turn_is_offered_strictly_fewer_tools_and_fewer_tokens() {
        let schema = |trust| -> usize {
            tools_for(trust, &floor())
                .iter()
                .map(|tool| tokens(&serde_json::to_string(tool).expect("json")))
                .sum()
        };
        assert!(
            tools_for(TrustLabel::Untrusted, &floor()).len()
                < tools_for(TrustLabel::Trusted, &floor()).len()
        );
        assert!(schema(TrustLabel::Untrusted) < schema(TrustLabel::Trusted));
    }

    /// **The assertion the colleague roster was built to be able to pass.**
    ///
    /// Measured from ten upwards, where the recall has already saturated, so
    /// anything that moves is the prefix and only the prefix. Between ten
    /// employees and fifty the roster contributes **nothing**: an employee is
    /// told about its manager, its reports and its team-mates, and there are the
    /// same number of those in a company of fifty as in a company of ten.
    ///
    /// Stated as `Named - McpOnly` rather than as a token count, because the
    /// number would move with a reworded heading and the property would not. If
    /// this ever fails, somebody has put a query with no join to
    /// `team_memberships` behind `inbound::colleagues`, and the company's bill
    /// has become quadratic in its headcount.
    #[test]
    fn the_roster_costs_the_same_in_a_company_of_fifty_as_in_one_of_ten() {
        let roster_cost = |employees: usize| {
            let company = Company { employees };
            weigh(&assemble(company, Reach::Team, Inventory::Named)).system
                - weigh(&assemble(company, Reach::Team, Inventory::McpOnly)).system
        };
        assert_eq!(roster_cost(10), roster_cost(50));
        assert!(
            roster_cost(10) > 0,
            "the fixture names no colleagues at all"
        );

        // And the counterfactual really is different, or the row above is
        // comparing a thing to itself: an unscoped roster costs strictly more,
        // and costs more the bigger the company gets.
        let payroll = |employees: usize| {
            weigh(&assemble(
                Company { employees },
                Reach::Team,
                Inventory::Unscoped,
            ))
            .system
        };
        assert!(payroll(50) > payroll(10));
        assert!(
            payroll(50) - payroll(10)
                > weigh(&assemble(
                    Company { employees: 50 },
                    Reach::Team,
                    Inventory::Named
                ))
                .system
                    - weigh(&assemble(
                        Company { employees: 10 },
                        Reach::Team,
                        Inventory::Named
                    ))
                    .system,
            "the unscoped roster did not slope harder than the scoped one, so this \
             fixture is not measuring the thing scoping removes"
        );
    }

    /// What an operator asks, and the answer is one number again.
    ///
    /// It stopped being one when the prefix began naming the tenant's whole
    /// inventory. Both lists in the prefix are now scoped by the rule the
    /// runtime enforces — `evaluate_mcp_call` for the tools,
    /// `inbound::may_message` for the people — so neither has the payroll in it
    /// and the marginal employee costs the same in a company of fifty as in one
    /// of ten.
    ///
    /// If this fails, some list in the prefix has become a function of headcount
    /// again, and the company's token bill has gone quadratic in it.
    #[test]
    fn the_marginal_cost_of_one_more_employee_does_not_depend_on_the_payroll() {
        let ten = per_day(Company { employees: 10 });
        let fifty = per_day(Company { employees: 50 });
        assert!(ten > 0);
        assert_eq!(ten, fifty);
        // And the employee is still told about the tools it can reach, or this
        // is flat because the feature was removed rather than scoped.
        let request = assemble(Company { employees: 50 }, Reach::Team, Inventory::Named);
        assert!(request.system.contains("team-0-erp/record-lookup-0"));
    }

    /// A turn that has read a supplier's email and five documents is untrusted,
    /// or the schemas measured above are the wrong ones.
    #[test]
    fn the_assembled_turn_is_untrusted_the_way_a_real_one_is() {
        let request = assemble(Company { employees: 10 }, Reach::Team, Inventory::Named);
        assert_eq!(
            request.tools.len(),
            tools_for(TrustLabel::Untrusted, &floor()).len()
        );
        assert!(!request.tools.iter().any(|tool| tool.name == "pay"));
        // The roster survives the taint, and it has to: `message_colleague` is
        // Low precisely so a turn holding a stranger's text can raise it.
        assert!(request.system.contains("Colleagues you can reach"));
    }
}
