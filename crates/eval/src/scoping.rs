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
//! **The line is flat above the tenth employee, and the flatness is not
//! scoping's doing.** The context moves once, between two employees and ten,
//! and the reason is the only N-shaped term there is: the employee's own *team*
//! filling its five recall slots. Past that it does not move again — a company
//! of fifty bills the same turn as a company of ten. So the growth that exists
//! is bounded by [`RECALL_LIMIT`] passages, a constant with no company in it,
//! and it is a function of your team rather than of the payroll.
//!
//! Everything else is flat by construction and would be flat at any company
//! size: the tool catalogue is four entries no matter how many MCP servers a
//! tenant binds, and the prefix is the employee's own identity in front of a
//! `&'static str` briefing shared by everyone wearing the role.
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
//! # The finding that matters more than the flat line
//!
//! There is exactly one input to the prefix that is company-wide rather than
//! employee-wide: [`agentos_app::prompt::SystemPrompt::with_mcp_tools`], fed from
//! `mcp::Fleet::inventory`, which is per **tenant**. It is filtered by
//! [`Risk`] and by nothing else — not by team, not by role. Wire it and the
//! prefix acquires a term linear in what the whole company has bound, paid by
//! every employee on every turn. The row measures that slope.
//!
//! And it is **not wired**. No production path calls `with_mcp_tools` or
//! `with_credential`: `apps/server/src/main.rs:879` and
//! `apps/server/src/loops/initiative.rs:575` build the prompt from
//! `Charter::system_prompt` and stop. So today's employee is never told which
//! servers exist (the exact guessing failure `app::prompt`'s docs say was
//! "fixed elsewhere"), never told which credentials it holds, and — the same
//! shape again — never told which colleagues exist, though `message_colleague`
//! takes a colleague's slug as a free string.
//!
//! That is what makes the flat line uninformative as a defence of the design.
//! It is flat because the company is absent, not because it was scoped. The
//! first feature that puts a company-shaped list in the prefix is the one that
//! will need scoping, and the numbers below say what it will cost.
//!
//! # Assertions are on shape, numbers are on the page
//!
//! Nothing here asserts "under 4,312 tokens". A reworded briefing would break
//! such a test and teach nobody anything. What is asserted is that the total
//! does not move with company size, that an untrusted turn is offered strictly
//! fewer tools, and that the per-employee daily cost is independent of how many
//! employees there already are. Every figure printed is an estimate with a
//! stated error bound; every property asserted is a comparison between two
//! contexts weighed by the same estimator, where that error cancels.

use agentos_app::knowledge::RECALL_LIMIT;
use agentos_app::rolepack::{CountryCode, Objective, RolePack};
use agentos_app::turn::{Context, tools_for};
use agentos_app::vertical::Charter;
use agentos_domain::action::{McpTool, Risk};
use agentos_domain::ids::Slug;
use agentos_domain::money::{Currency, Money};
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

/// Whether the tenant's MCP inventory is named in the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inventory {
    /// What production does: `with_mcp_tools` is never called, so the model is
    /// told nothing about connected systems.
    AsShipped,
    /// What `app::prompt`'s docs describe: the tenant's whole bound inventory,
    /// filtered by risk and by nothing else.
    Named,
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
        Inventory::AsShipped => charter.system_prompt(IDENTITY),
        Inventory::Named => charter
            .system_prompt(IDENTITY)
            .with_mcp_tools(company.inventory()),
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
pub fn per_day(company: Company) -> usize {
    let turns = RolePack::international_buyer().limits().max_turns_per_day as usize;
    weigh(&assemble(company, Reach::Team, Inventory::AsShipped)).total() * turns
}

/// Everything measured about what an employee's context costs.
pub fn evaluate() -> Surface {
    let mut rows = Vec::new();

    // --- 1. does the context grow with the company? -------------------------
    // It moves once and then stops, and the step is the employee's own team
    // filling its five recall slots — a `min(matches, RECALL_LIMIT)` with no
    // company size in it. The gate is on the saturated half, because that is
    // where the claim lives: past your own team, more colleagues cost nothing.
    let shipped: Vec<Weighed> = SIZES
        .iter()
        .map(|&employees| {
            weigh(&assemble(
                Company { employees },
                Reach::Team,
                Inventory::AsShipped,
            ))
        })
        .collect();
    let saturated = shipped[shipped.len() - 1] == shipped[shipped.len() - 2];
    rows.push(
        Row::ok(
            "one turn's context at 2 / 10 / 50 staff",
            format!(
                "{} tok  (prompt {} + schemas {} + context {})",
                shipped
                    .iter()
                    .map(|w| w.total().to_string())
                    .collect::<Vec<_>>()
                    .join(" → "),
                shipped[0].system,
                shipped[0].tools,
                shipped[0].messages,
            ),
            Truth::Correct,
        )
        .gated(saturated)
        .note("one step, as the employee's own TEAM fills five recall slots; then nothing"),
    );

    // --- 2. what does scoping the corpus save? ------------------------------
    // The headline, and it is not the one the hierarchy was sold on. Top-k is a
    // fixed budget: widening the reach from one team to the whole tenant
    // changes which five passages arrive, never how many.
    let biggest = Company {
        employees: SIZES[SIZES.len() - 1],
    };
    let scoped = weigh(&assemble(biggest, Reach::Team, Inventory::AsShipped));
    let unscoped = weigh(&assemble(biggest, Reach::Company, Inventory::AsShipped));
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

    // --- 3. the one company-wide input, and the slope it would have ---------
    let slope: Vec<usize> = SIZES
        .iter()
        .map(|&employees| {
            weigh(&assemble(
                Company { employees },
                Reach::Team,
                Inventory::Named,
            ))
            .system
        })
        .collect();
    rows.push(
        Row::ok(
            "MCP inventory in the prefix, if wired",
            format!(
                "{} → {} tok as 2 staff become 50 (+{})",
                slope[0],
                slope[slope.len() - 1],
                slope[slope.len() - 1] - slope[0],
            ),
            Truth::Characterises,
        )
        .note("per tenant, filtered by risk and by nothing else — and no production path calls it"),
    );

    // --- 4. what taint filtering costs ---------------------------------------
    let schema = |trust| -> usize {
        tools_for(trust)
            .iter()
            .map(|tool| tokens(&serde_json::to_string(tool).unwrap_or_default()))
            .sum()
    };
    let (trusted, untrusted) = (schema(TrustLabel::Trusted), schema(TrustLabel::Untrusted));
    let narrower = untrusted < trusted
        && tools_for(TrustLabel::Untrusted).len() < tools_for(TrustLabel::Trusted).len();
    rows.push(
        Row::ok(
            "an untrusted turn is offered less schema",
            format!(
                "{untrusted} vs {trusted} tok ({} tools vs {})",
                tools_for(TrustLabel::Untrusted).len(),
                tools_for(TrustLabel::Trusted).len(),
            ),
            Truth::Correct,
        )
        .gated(narrower),
    );

    // --- 5. the number an operator asks for ----------------------------------
    let day = per_day(biggest);
    let bounded = per_day(Company { employees: 10 }) == day;
    rows.push(
        Row::ok(
            "one more employee costs, per day",
            format!(
                "{day} tok at {} turns, whatever the company size",
                RolePack::international_buyer().limits().max_turns_per_day
            ),
            Truth::Correct,
        )
        .gated(bounded)
        .note("a floor: one model call per reserved turn, and a run may make ten"),
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
            "what a colleague roster would cost, because there is none. `message_colleague` takes \
             a slug the model was never told, and the fix that worked for MCP names — name the \
             inventory in the prefix — is exactly the O(company) term scoping would then have to \
             pay for. That is the first feature that will make this line slope",
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
        let schemas = serde_json::to_string(&tools_for(TrustLabel::Trusted)).expect("json");
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

    /// **The claim this suite exists for**, asserted as a shape rather than as
    /// a number: past the point where an employee's own team fills its recall
    /// slots, the company around it costs nothing. Not "under N tokens" — a
    /// reworded briefing must not fail this.
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
                    Inventory::AsShipped,
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
        let scoped = weigh(&assemble(company, Reach::Team, Inventory::AsShipped));
        let unscoped = weigh(&assemble(company, Reach::Company, Inventory::AsShipped));
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

    /// The one company-wide input there is. It slopes, it is filtered by risk
    /// alone, and every employee in the tenant pays for all of it.
    #[test]
    fn the_mcp_inventory_is_the_term_that_does_grow_with_the_company() {
        // Ten and fifty, not two and fifty: at ten the recall has already
        // saturated, so anything that moves from here is the prefix and only
        // the prefix.
        let small = weigh(&assemble(
            Company { employees: 10 },
            Reach::Team,
            Inventory::Named,
        ));
        let large = weigh(&assemble(
            Company { employees: 50 },
            Reach::Team,
            Inventory::Named,
        ));
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
            tools_for(trust)
                .iter()
                .map(|tool| tokens(&serde_json::to_string(tool).expect("json")))
                .sum()
        };
        assert!(tools_for(TrustLabel::Untrusted).len() < tools_for(TrustLabel::Trusted).len());
        assert!(schema(TrustLabel::Untrusted) < schema(TrustLabel::Trusted));
    }

    /// The operator's number has to be a property of the employee, not of the
    /// payroll — otherwise "what does one more cost" has no answer. Measured
    /// from ten upwards, where the recall has saturated and the only remaining
    /// variable would be company size itself.
    #[test]
    fn the_marginal_cost_of_one_more_employee_does_not_depend_on_the_others() {
        let ten = per_day(Company { employees: 10 });
        assert_eq!(ten, per_day(Company { employees: 50 }));
        assert!(ten > 0);
    }

    /// A turn that has read a supplier's email and five documents is untrusted,
    /// or the schemas measured above are the wrong ones.
    #[test]
    fn the_assembled_turn_is_untrusted_the_way_a_real_one_is() {
        let request = assemble(Company { employees: 10 }, Reach::Team, Inventory::AsShipped);
        assert_eq!(request.tools.len(), tools_for(TrustLabel::Untrusted).len());
        assert!(!request.tools.iter().any(|tool| tool.name == "pay"));
    }
}
