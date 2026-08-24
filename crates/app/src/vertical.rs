//! The wire between a role and the work: what an employee was hired to do, and
//! which vertical operation that makes due right now.
//!
//! Everything either side of this module already existed and nothing joined
//! them. [`crate::sourcing`] and [`crate::revenue`] were complete, tested and
//! called by nobody; [`crate::rolepack::RolePack::plan`] turned an
//! [`Objective`](crate::rolepack::Objective) into an ordered `Vec<Task>` that
//! nothing read. This module is the sentence in between: **the role pack's plan
//! decides the stage, and the stage names the vertical operation.**
//!
//! # A vertical operation is not an `Action`
//!
//! There were two shapes to choose from and the choice is the content of this
//! unit, so it is argued here rather than in a commit message.
//!
//! *(i)* Every vertical operation becomes an [`Action`](agentos_domain::action::Action)
//! variant: `Action::IssueRfq { … }`, ruled on by the gate, performed through
//! [`Effects`](crate::effects::Effects) holding an `Authorized<IssueRfq>`. It is
//! the consistent answer, and it is wrong for two reasons that compound.
//!
//! The first is arithmetic, and [`crate::turn`] already wrote it down: a tool
//! catalogue past roughly seventy entries is a model picking the almost-right
//! one, and `catalogue` is a fixed-size array precisely so that a fourth entry
//! has to be argued for. Purchasing alone is six stages; sales is six more.
//! Verticalising them is twelve tool schemas for two roles, and the next two
//! roles are twelve more.
//!
//! The second is worse and is about where the blast radius actually is.
//! `issue_rfq` is N × [`Action::EmailSend`](agentos_domain::action::Action) and
//! nothing else. An `Action::IssueRfq` would be one gate decision covering N
//! recipients — so the per-recipient contact budget, the channel allowlist and
//! the suppression list would all have to be re-implemented *inside* the
//! operation, next to the copies that already live in
//! `domain::policy::evaluate`. The gate would rule once on a thing whose cost is
//! the sum of N things it did not see. Today
//! [`Buyer::issue_rfq`](crate::sourcing::Buyer::issue_rfq) authorises each
//! address on its own and returns one outcome per supplier, which is why a
//! campaign that runs out of contact budget half way comes back loudly rather
//! than quietly shrinking.
//!
//! *(ii)* — what is built here — is that a vertical operation **composes
//! existing actions**. The model is never offered an "issue RFQ" tool. The role
//! pack's plan decides that an RFQ is the next step, and the operation runs as a
//! sequence of individually-authorised effects. The gate rules on each email,
//! which is where the money and the blast radius are, and the tool catalogue
//! stays at three.
//!
//! What (ii) gives up is that the *model* cannot ask for a vertical operation.
//! That is the point. The model does the language — the RFQ's prose, the
//! qualification judgement, the reply to a supplier — and the role pack decides
//! the stage. An employee that could choose between forty verticalised tools is
//! an employee whose job description is a dropdown.
//!
//! # No vertical operation reaches a provider without a token
//!
//! Nothing in this module touches a provider. It calls
//! [`Buyer`](crate::sourcing::Buyer), [`Seller`](crate::revenue::Seller) and
//! [`Prober`](crate::proof_of_need::Prober), each of which gates its own
//! subject and hands the resulting `Authorized<A>` to
//! [`Effects`](crate::effects::Effects) — which accepts nothing else, by
//! construction, and `tests/ui/effects_bare_action.rs` is that claim checked by
//! rustc. Adding a vertical here cannot open a second path, because there is no
//! provider handle in scope to open one with.
//!
//! # The evidence bar is a type, not a rule
//!
//! [`Prober::check`](crate::proof_of_need::Prober::check) runs a prospect's flow
//! **twice** and yields an [`Evidence`] only when the two runs agree byte for
//! byte. That suppression is the design: an unreproduced claim about another
//! company's product is a false statement about their product.
//!
//! So on this path outreach does not merely *discourage* an unevidenced
//! approach — it cannot spell one. [`Approach`] wraps the message and its only
//! constructor takes an `&Evidence`; `Evidence` in turn carries a private
//! zero-sized seal and can be built nowhere but `proof_of_need.rs`, by the
//! function that made the observation twice. There is no `Deserialize`, no
//! public constructor and no `Default` on either. Approaching a prospect this
//! employee has no reproduced finding about is a program that does not compile —
//! see `tests/ui/vertical_approach_without_evidence.rs`.
//!
//! # Resuming, without a scheduler
//!
//! An RFQ goes out today and is answered in three days. A turn cannot block on
//! that, and nothing here does: [`purchase`] sends and returns.
//!
//! What brings the vertical back is the machinery that already exists.
//! The supplier's reply is an inbound email; [`crate::inbound::land`] writes the
//! `messages` row and enqueues one `agent.turn.requested` outbox event, exactly
//! once, keyed on the message's idempotency key. The outbox poller dispatches
//! it, the turn recomputes the *same* plan — [`RolePack::plan`](crate::rolepack::RolePack::plan)
//! is pure — and the only thing that has changed is the material: there are
//! quotes now. [`due`] therefore answers [`Stage::Negotiate`](crate::rolepack::Stage)
//! where the previous turn was answered [`Stage::Rfq`](crate::rolepack::Stage).
//!
//! **Progress is the material, not a stored cursor.** There is no workflow row,
//! no state column and no timer, because there is nothing for them to hold that
//! the quotes and the sequences do not already say. A crash between the RFQ and
//! the reply costs nothing: the plan is recomputed and the round is re-read.

use agentos_domain::action::{ActionKind, Channel, EmailAddress};
use agentos_domain::ids::EmployeeId;
use agentos_domain::money::{Currency, Money};
use agentos_domain::untrusted::TrustLabel;
use agentos_store::db::{StoreError, TenantTx};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::prompt::SystemPrompt;
use crate::proof_of_need::{Answer, Checked, Evidence, Flow, Probe, ProbeError, Prober};
use crate::revenue::{Seller, Sequence};
use crate::rolepack::{self, CountryCode};
use crate::rolepack_sales::{self, Segment};
use crate::sourcing::{self, Buyer, Divergence, Fx, Landed, Lane, Quote, QuoteError, Reputation};

// ---------------------------------------------------------------------------
// The charter
// ---------------------------------------------------------------------------

/// Why a charter could not be read.
#[derive(Debug, thiserror::Error)]
pub enum CharterError {
    /// The database was unreachable, or the row was not there.
    #[error(transparent)]
    Unavailable(#[from] StoreError),

    /// The stored objective does not parse back through the constructors it
    /// came in through. Names the field, because that is the only thing an
    /// operator can act on.
    #[error("the stored charter is not readable: {0}")]
    Corrupt(&'static str),
}

impl CharterError {
    /// Stable, low-cardinality metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            CharterError::Unavailable(_) => "unavailable",
            CharterError::Corrupt(_) => "corrupt_charter",
        }
    }
}

/// What one employee was hired to do: a role pack, and the objective it was
/// given.
///
/// This is the value the whole module turns into work, and it is deliberately a
/// closed enum rather than a trait. A role is data — three sets, a
/// [`PolicyLimits`](agentos_domain::policy::PolicyLimits) and a `&'static str`,
/// see [`crate::rolepack`] — and the two packs have no shared supertype because
/// their objectives and their [`Stage`](crate::rolepack::Stage) sequences are
/// genuinely different. A trait here would be one method per pack with a
/// different return type, which is a match written badly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Charter {
    /// Sourcing physical goods overseas.
    Purchasing {
        /// The role, with whatever limits a provisioner narrowed it to.
        pack: rolepack::RolePack,
        /// What is being bought.
        objective: rolepack::Objective,
    },
    /// Selling the visa-data API.
    Sales {
        /// The role, with whatever limits a provisioner narrowed it to.
        pack: rolepack_sales::RolePack,
        /// Who is being sold to.
        objective: rolepack_sales::Objective,
    },
}

impl Charter {
    /// The role's handle, and the `role` column. Display and metrics.
    pub const fn role(&self) -> &'static str {
        match self {
            Charter::Purchasing { pack, .. } => pack.name(),
            Charter::Sales { pack, .. } => pack.name(),
        }
    }

    /// The stable, cacheable prompt fragment for this role.
    pub const fn briefing(&self) -> &'static str {
        match self {
            Charter::Purchasing { pack, .. } => pack.briefing(),
            Charter::Sales { pack, .. } => pack.briefing(),
        }
    }

    /// The system prompt for an employee wearing this charter.
    ///
    /// `identity` is the employee's own name, domain and address — ours, from
    /// our own configuration. It goes *before* the briefing so that the briefing,
    /// which is byte-identical for every employee wearing the role, sits at the
    /// end of the prefix where the cache breakpoint is.
    pub fn system_prompt(&self, identity: &str) -> SystemPrompt {
        SystemPrompt::new(format!("{identity}\n\n{}", self.briefing()))
    }

    /// The plan, rendered as the turn's task.
    ///
    /// This is the half of the wire the model sees: [`RolePack::plan`](crate::rolepack::RolePack::plan)
    /// is a pure function of the objective, recomputed every turn and stored
    /// nowhere, and it lands in the conversation as a *message* — after the
    /// cache breakpoint, never in the briefing, because it varies per objective.
    pub fn brief(&self) -> String {
        let steps: Vec<String> = match self {
            Charter::Purchasing { pack, objective } => pack
                .plan(objective)
                .iter()
                .map(|task| format!("{}: {}", task.stage, task.instruction))
                .collect(),
            Charter::Sales { pack, objective } => pack
                .plan(objective)
                .iter()
                .map(|task| format!("{}: {}", task.stage, task.instruction))
                .collect(),
        };
        format!(
            "Your standing objective, as a plan. Work it in order; a stage you cannot finish is \
             something to report, not something to skip.\n\n{}",
            steps.join("\n\n")
        )
    }

    /// Write it down, replacing whatever this employee was chartered for
    /// before.
    ///
    /// One charter per employee: re-assigning is an update, because an employee
    /// wearing two roles has two action allowlists and every question about it
    /// gets two answers.
    pub async fn save(
        &self,
        tx: &mut TenantTx<'_>,
        employee_id: EmployeeId,
        now: DateTime<Utc>,
    ) -> Result<(), CharterError> {
        sqlx::query(
            "INSERT INTO employee_charters \
                 (employee_id, tenant_id, role, objective, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $5) \
             ON CONFLICT (employee_id) DO UPDATE SET \
               role = excluded.role, \
               objective = excluded.objective, \
               updated_at = excluded.updated_at",
        )
        .bind(employee_id.as_uuid())
        .bind(tx.tenant_id().as_uuid())
        .bind(self.role())
        .bind(self.objective_json())
        .bind(now)
        .execute(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
        Ok(())
    }

    /// Read it back, through the constructors the values came in through.
    ///
    /// `None` is an employee that answers its mail and has no standing
    /// objective, which is what every employee was before this table existed.
    /// That is a supported state, not a missing row: the turn falls back to
    /// exactly the behaviour it had.
    pub async fn load(
        tx: &mut TenantTx<'_>,
        employee_id: EmployeeId,
    ) -> Result<Option<Self>, CharterError> {
        let row: Option<(String, Value)> =
            sqlx::query_as("SELECT role, objective FROM employee_charters WHERE employee_id = $1")
                .bind(employee_id.as_uuid())
                .fetch_optional(&mut ***tx)
                .await
                .map_err(StoreError::from)?;

        let Some((role, objective)) = row else {
            return Ok(None);
        };

        // The `employee_charters_role` CHECK is this list; a role outside it
        // cannot be written, so reaching the `_` arm means the constraint and
        // this match have drifted.
        match role.as_str() {
            "international-buyer" => Ok(Some(Charter::Purchasing {
                pack: rolepack::RolePack::international_buyer(),
                objective: buying_objective(&objective)?,
            })),
            "sales-development" => Ok(Some(Charter::Sales {
                pack: rolepack_sales::RolePack::sales_development(),
                objective: sales_objective(&objective)?,
            })),
            _ => Err(CharterError::Corrupt("role")),
        }
    }

    /// The objective as it is stored. Our own words about our own business —
    /// not one byte here is a counterparty's.
    fn objective_json(&self) -> Value {
        match self {
            Charter::Purchasing { objective, .. } => json!({
                "what": objective.what,
                "quantity": objective.quantity,
                "max_unit_price": objective.max_unit_price.map(|price| json!({
                    "minor": price.minor(),
                    "currency": price.currency().code(),
                })),
                "delivery_country": objective.delivery_country.as_ref().map(CountryCode::as_str),
                "requirements": objective.requirements,
            }),
            Charter::Sales { objective, .. } => json!({
                "segment": objective.segment.code(),
                "market": objective.market.as_ref().map(CountryCode::as_str),
                "target_accounts": objective.target_accounts,
            }),
        }
    }
}

/// A buying objective, re-parsed rather than deserialised.
///
/// Every field goes back through the door it came in through —
/// [`CountryCode::parse`], [`Money::new`], `u32::try_from`. A derived
/// `Deserialize` would rebuild a country code of `"germany"` or a zero price
/// straight out of the column, which is exactly what those constructors exist to
/// refuse.
fn buying_objective(raw: &Value) -> Result<rolepack::Objective, CharterError> {
    let max_unit_price = match raw.get("max_unit_price") {
        None | Some(Value::Null) => None,
        Some(price) => {
            let minor = price
                .get("minor")
                .and_then(Value::as_u64)
                .ok_or(CharterError::Corrupt("max_unit_price.minor"))?;
            let currency: Currency = price
                .get("currency")
                .and_then(Value::as_str)
                .ok_or(CharterError::Corrupt("max_unit_price.currency"))?
                .parse()
                .map_err(|_| CharterError::Corrupt("max_unit_price.currency"))?;
            Some(Money::new(minor, currency).map_err(|_| CharterError::Corrupt("max_unit_price"))?)
        }
    };

    let delivery_country = match raw.get("delivery_country") {
        None | Some(Value::Null) => None,
        Some(country) => Some(
            CountryCode::parse(
                country
                    .as_str()
                    .ok_or(CharterError::Corrupt("delivery_country"))?,
            )
            .map_err(|_| CharterError::Corrupt("delivery_country"))?,
        ),
    };

    Ok(rolepack::Objective {
        what: raw
            .get("what")
            .and_then(Value::as_str)
            .ok_or(CharterError::Corrupt("what"))?
            .to_owned(),
        quantity: raw
            .get("quantity")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(CharterError::Corrupt("quantity"))?,
        max_unit_price,
        delivery_country,
        requirements: strings(raw.get("requirements"))
            .ok_or(CharterError::Corrupt("requirements"))?,
    })
}

/// A sales objective, re-parsed rather than deserialised. Same reasoning as
/// [`buying_objective`].
fn sales_objective(raw: &Value) -> Result<rolepack_sales::Objective, CharterError> {
    let code = raw
        .get("segment")
        .and_then(Value::as_str)
        .ok_or(CharterError::Corrupt("segment"))?;
    let segment = Segment::ALL
        .into_iter()
        .find(|segment| segment.code() == code)
        .ok_or(CharterError::Corrupt("segment"))?;

    let market = match raw.get("market") {
        None | Some(Value::Null) => None,
        Some(market) => Some(
            CountryCode::parse(market.as_str().ok_or(CharterError::Corrupt("market"))?)
                .map_err(|_| CharterError::Corrupt("market"))?,
        ),
    };

    Ok(rolepack_sales::Objective {
        segment,
        market,
        target_accounts: strings(raw.get("target_accounts"))
            .ok_or(CharterError::Corrupt("target_accounts"))?,
    })
}

/// A JSON array of strings, or nothing.
fn strings(raw: Option<&Value>) -> Option<Vec<String>> {
    raw?.as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

// ---------------------------------------------------------------------------
// Purchasing
// ---------------------------------------------------------------------------

/// What the buyer has in front of it this turn.
///
/// Everything here is *material*, and material is the whole of the resume
/// mechanism: quotes are in this round because inbound landed the supplier's
/// replies days after the RFQ went out, and their presence is what moves the
/// plan on. Nothing stores which stage was reached, because nothing needs to.
pub struct Round<'a> {
    /// Qualified suppliers, each with whatever the store has observed about it.
    /// `None` is a supplier with no record — the honest answer, and not the same
    /// as a bad one.
    pub candidates: &'a [(EmailAddress, Option<Reputation>)],
    /// Quotes that are still standing. An expired one cannot be spelled: see
    /// [`Quote::live_at`].
    pub quotes: &'a [Quote<'a>],
    /// The freight lane the comparison normalises onto.
    pub lane: &'a Lane,
    /// The exchange rates the caller supplies. There is no rate in the domain
    /// and there must not be one.
    pub fx: &'a Fx,
}

/// What one purchasing turn came to.
#[derive(Debug)]
pub enum Bought {
    /// The objective cannot be sourced as stated. Nobody is contacted; the
    /// instruction is the question to put to the operator who set it.
    Clarify(String),
    /// An RFQ went out. One outcome per supplier on the shortlist, in order,
    /// including the ones the gate refused.
    Asked {
        /// Who was asked, after [`shortlist`](crate::sourcing::shortlist)
        /// dropped the suppliers that never answer.
        asking: Vec<EmailAddress>,
        /// What each address came to.
        outcomes: Vec<sourcing::Contacted>,
    },
    /// The quotes were normalised onto one lane and compared.
    Compared {
        /// Cheapest landed total first.
        landed: Vec<Landed>,
        /// Where the suppliers disagree, and by how much. An RFQ fan-out pays
        /// for N answers; this is what is left after the sort key.
        divergences: Vec<Divergence>,
    },
    /// The plan's due stage is not a vertical operation — it is reading,
    /// judging, or a human's signature — so this turn is the model's.
    Model(rolepack::Stage),
    /// The role may not propose the action the stage needs. Upstream of the
    /// gate, which would refuse it too.
    Forbidden(ActionKind),
}

/// Which stage of the plan is a vertical operation with the material at hand.
///
/// Pure, and separate from [`purchase`] so the answer can be asserted on without
/// a database. It walks the plan **in the plan's own order** and stops at the
/// first stage that can actually run: the role pack decides the sequence, the
/// material decides how far along it this turn is.
///
/// Discovery, qualification, sampling and ordering are absent on purpose. The
/// first two are reading and judging — the model's work, through the turn's own
/// three tools — and the last two end at a human: a sample costs money and an
/// order is an [`Action::ContractSign`](agentos_domain::action::Action) the gate
/// escalates unconditionally.
pub fn due(plan: &[rolepack::Task], round: &Round<'_>) -> rolepack::Stage {
    plan.iter()
        .map(|task| task.stage)
        .find(|stage| match stage {
            // A plan containing `Clarify` contains nothing else.
            rolepack::Stage::Clarify => true,
            // Someone to ask, and nothing back from them yet.
            rolepack::Stage::Rfq => !round.candidates.is_empty() && round.quotes.is_empty(),
            // Answers are in.
            rolepack::Stage::Negotiate => !round.quotes.is_empty(),
            rolepack::Stage::Discover
            | rolepack::Stage::Qualify
            | rolepack::Stage::Sample
            | rolepack::Stage::Order => false,
        })
        // No candidates and no quotes: there is nobody to write to yet, which is
        // the discovery the model does.
        .unwrap_or(rolepack::Stage::Discover)
}

/// Run the purchasing vertical for whichever stage the plan makes due.
///
/// `rfq` is the model's language — the letter a supplier reads. Who receives it
/// is not: the shortlist comes off the evidence and the plan, and every address
/// on it is authorised on its own by the gate inside
/// [`Buyer::issue_rfq`](crate::sourcing::Buyer::issue_rfq).
///
/// **This never waits.** An RFQ sent here is answered in days; the function
/// returns as soon as the provider has the messages, and the answers arrive as
/// inbound email that wakes a later turn. See the module docs.
pub async fn purchase(
    buyer: &Buyer,
    pack: &rolepack::RolePack,
    objective: &rolepack::Objective,
    round: &Round<'_>,
    rfq: &sourcing::Outreach,
    trust: TrustLabel,
) -> Result<Bought, QuoteError> {
    let plan = pack.plan(objective);
    let stage = due(&plan, round);

    match stage {
        rolepack::Stage::Clarify => Ok(Bought::Clarify(
            plan.iter()
                .find(|task| task.stage == stage)
                .map_or_else(String::new, |task| task.instruction.clone()),
        )),

        rolepack::Stage::Rfq => {
            // Upstream of the gate, never instead of it: a role that has no
            // business writing to strangers is stopped before an address is
            // even chosen, and the gate would refuse each one anyway.
            if !pack.may_propose(ActionKind::EmailSend) {
                return Ok(Bought::Forbidden(ActionKind::EmailSend));
            }
            let asking = sourcing::shortlist(round.candidates);
            let outcomes = buyer.issue_rfq(&asking, rfq, trust).await;
            Ok(Bought::Asked { asking, outcomes })
        }

        rolepack::Stage::Negotiate => {
            let landed = sourcing::rank(round.quotes, round.lane, round.fx)?;
            let divergences = sourcing::disagreement(&landed);
            Ok(Bought::Compared {
                landed,
                divergences,
            })
        }

        other => Ok(Bought::Model(other)),
    }
}

// ---------------------------------------------------------------------------
// Sales
// ---------------------------------------------------------------------------

/// An approach message, and the proof that there is something honest to say.
///
/// **The evidence bar, as a type.** The tuple field is private and
/// [`Approach::new`] is the only constructor, so an `Approach` cannot exist
/// without an [`Evidence`] — which itself carries a private zero-sized seal and
/// can be built nowhere but `proof_of_need.rs`, by
/// [`Prober::check`](crate::proof_of_need::Prober::check), and only when the
/// prospect's own flow said the same thing to two identical runs.
///
/// So "we approached a prospect about a finding we could not reproduce" is not a
/// review item on this path. It is a program that does not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approach(crate::revenue::Outreach);

impl Approach {
    /// Render the approach from a reproduced finding.
    ///
    /// Not one byte of the prospect's page is in it.
    /// [`Evidence::claim_line`](crate::proof_of_need::Evidence::claim_line) is
    /// built from our own configuration, the probe inputs and two parsed enums,
    /// and [`Evidence::steps`](crate::proof_of_need::Evidence) is the plan we
    /// ran, also ours. The verbatim panel text stays an
    /// [`Untrusted`](agentos_domain::untrusted::Untrusted) on the evidence, for
    /// a human to attach if they want to.
    ///
    /// `opt_out` is the plain way out that every approach carries — an
    /// operator's sentence, not a model's.
    pub fn new(evidence: &Evidence, opt_out: &str) -> Self {
        let steps: Vec<String> = evidence
            .steps
            .iter()
            .enumerate()
            .map(|(n, step)| format!("{}. {step}", n + 1))
            .collect();

        Self(crate::revenue::Outreach {
            subject: format!(
                "{}: what your entry-requirements step shows for {} → {}",
                evidence.prospect, evidence.probe.passport, evidence.probe.destination
            ),
            body: format!(
                "{}\n\nHow to see it again:\n{}\n\n{opt_out}",
                evidence.claim_line(),
                steps.join("\n"),
            ),
        })
    }

    /// The message, for [`Seller::touch`](crate::revenue::Seller::touch).
    pub const fn message(&self) -> &crate::revenue::Outreach {
        &self.0
    }
}

/// One prospect, and the pair we put through its flow.
pub struct Prospect<'a> {
    /// The flow an operator configured. Every selector in it is ours.
    pub flow: &'a Flow,
    /// The passport, destination and date to check.
    pub probe: &'a Probe,
    /// The authoritative answer to compare against, with its provenance.
    pub authority: &'a Answer,
    /// The touch sequence for the person being approached. Advanced only by a
    /// touch that actually went out.
    pub sequence: &'a mut Sequence,
}

/// What one sales turn came to.
#[derive(Debug)]
pub enum Sold {
    /// The objective cannot be worked as stated — including "no channel this
    /// segment is reachable on is permitted for this employee". Nobody is
    /// approached.
    Clarify(String),
    /// The role may approach this segment, but not on a channel this vertical
    /// can send on. Email is the only one it knows; a voice-only employee needs
    /// a person to make the call.
    WrongChannel(Option<Channel>),
    /// The role may not propose the action the stage needs.
    Forbidden(ActionKind),
    /// The check produced no finding, and the outcome says which of the five
    /// reasons it was. Never [`Checked::Evidence`] — that arm is the one below.
    NoFinding(Checked),
    /// A reproduced finding, and what the approach came to.
    Approached {
        /// The finding, for filing.
        evidence: Box<Evidence>,
        /// What the touch came to: sent, suppressed, not due, or refused.
        outcome: crate::revenue::Contacted,
    },
}

/// Run the sales vertical: check the prospect's flow, and approach only if
/// there is something reproducible to say.
///
/// The plan's order is [`Stage::Evidence`](crate::rolepack_sales::Stage) before
/// [`Stage::Approach`](crate::rolepack_sales::Stage), and the type system agrees
/// with it: the second half of this function needs an `&Evidence` that only the
/// first half can produce.
///
/// The approach is authorised as **untrusted**. The message contains none of the
/// prospect's bytes — see [`Approach::new`] — but the decision to write to this
/// person came from reading their site, and labelling that trusted would be a
/// laundering step that costs nothing to avoid: an email is low-risk, so the
/// gate grants `Authorized<Untrusted<EmailSend>>` for it either way, and the
/// reply that gets recorded is marked for what it is.
pub async fn sell(
    prober: &Prober,
    seller: &Seller,
    pack: &rolepack_sales::RolePack,
    objective: &rolepack_sales::Objective,
    prospect: Prospect<'_>,
    opt_out: &str,
    now: DateTime<Utc>,
) -> Result<Sold, ProbeError> {
    let plan = pack.plan(objective);

    // A plan containing `Clarify` contains nothing else. This is also where an
    // employee with no permitted channel for this segment stops: `plan` folds
    // that into `Gap::Channel` rather than quietly picking another channel.
    if let Some(task) = plan
        .iter()
        .find(|task| task.stage == rolepack_sales::Stage::Clarify)
    {
        return Ok(Sold::Clarify(task.instruction.clone()));
    }

    // The pack's own preference order, already intersected with what the policy
    // layer permits. Email is the only channel this vertical can send on.
    let channel = pack.approach_channel(objective.segment);
    if channel != Some(Channel::Email) {
        return Ok(Sold::WrongChannel(channel));
    }
    if !pack.may_propose(ActionKind::EmailSend) {
        return Ok(Sold::Forbidden(ActionKind::EmailSend));
    }

    // `Stage::Evidence`. Five of the six outcomes carry no evidence, and that is
    // the design rather than a gap in it.
    let evidence = match prober
        .check(prospect.flow, prospect.probe, prospect.authority, now)
        .await?
    {
        Checked::Evidence(found) => found,
        barren => return Ok(Sold::NoFinding(barren)),
    };

    // `Stage::Approach`, and it is unreachable above this line: `Approach::new`
    // takes the `&Evidence` that only the match arm above can bind.
    let outcome = seller
        .touch(
            prospect.sequence,
            Approach::new(&evidence, opt_out).message(),
            TrustLabel::Untrusted,
            now,
        )
        .await;

    Ok(Sold::Approached { evidence, outcome })
}

/// Follow up the same finding with everyone who owns the surface it is about.
///
/// One reproduced finding, several people at that account — the product owner,
/// their lead, the person who answered last time. [`Seller::campaign`](crate::revenue::Seller::campaign)
/// authorises each address on its own and [`Sequence::due`](crate::revenue::Sequence)
/// meters the spacing, so a follow-up that is too soon comes back `NotDue`
/// rather than going out.
///
/// It takes an [`Approach`], so a follow-up is subject to exactly the same
/// evidence bar as the first touch.
pub async fn follow_up(
    seller: &Seller,
    sequences: &mut [Sequence],
    approach: &Approach,
    now: DateTime<Utc>,
) -> Vec<crate::revenue::Contacted> {
    seller
        .campaign(sequences, approach.message(), TrustLabel::Untrusted, now)
        .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use agentos_domain::action::Domain;
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::PolicyLimits;
    use agentos_domain::sourcing as buying;
    use agentos_domain::untrusted::Untrusted;
    use agentos_providers::browser::{BrowserSession, MockBrowser};
    use agentos_providers::email::MockEmailProvider;
    use agentos_providers::{ProviderBinding, ProviderError};
    use agentos_store::db::Db;
    use async_trait::async_trait;
    use chrono::{NaiveDate, TimeDelta};
    use url::Url;

    use super::*;
    use crate::effects::{Effects, Ports};
    use crate::gate::{Authorized, PolicyBook, PolicyGate, Principal};
    use crate::proof_of_need::{Browse, Claim, PanelReader};
    use crate::revenue::{Contacted, Suppression};

    // -- doubles -----------------------------------------------------------

    /// Answers with scripted panel texts, in order; the last one repeats
    /// forever. Two different entries is how a flaky flow is spelled — and a
    /// flaky flow is the case this module must not send an email about.
    struct ScriptedPanel(Vec<String>, std::sync::Mutex<usize>);

    impl ScriptedPanel {
        fn always(text: &str) -> Arc<Self> {
            Arc::new(Self(vec![text.to_owned()], std::sync::Mutex::new(0)))
        }

        fn flaky(first: &str, then: &str) -> Arc<Self> {
            Arc::new(Self(
                vec![first.to_owned(), then.to_owned()],
                std::sync::Mutex::new(0),
            ))
        }
    }

    #[async_trait]
    impl PanelReader for ScriptedPanel {
        async fn read(
            &self,
            _ok: Authorized<Browse>,
            _session: &BrowserSession,
            _selector: &str,
        ) -> Result<Untrusted<String>, ProviderError> {
            let mut reads = self.1.lock().expect("poisoned");
            let text = self.0[(*reads).min(self.0.len() - 1)].clone();
            *reads += 1;
            Ok(Untrusted::new(text))
        }
    }

    // -- fixtures ----------------------------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; vertical tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed(db: &Db) -> Principal {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("vert-{}", employee.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        Principal::employee(tenant, employee)
    }

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(y, m, d)
            .expect("date")
            .and_hms_opt(9, 0, 0)
            .expect("time")
            .and_utc()
    }

    fn address(raw: &str) -> EmailAddress {
        EmailAddress::parse(raw).expect("address")
    }

    fn buying_objective_value() -> rolepack::Objective {
        rolepack::Objective {
            what: "anodised aluminium enclosures".to_owned(),
            quantity: 5_000,
            max_unit_price: Some(Money::from_major_str("3.40", Currency::Usd).expect("amount")),
            delivery_country: Some(CountryCode::parse("de").expect("country")),
            requirements: vec!["6063-T5 aluminium".to_owned(), "RoHS".to_owned()],
        }
    }

    fn sales_objective_value() -> rolepack_sales::Objective {
        rolepack_sales::Objective {
            segment: Segment::Airline,
            market: Some(CountryCode::parse("fr").expect("country")),
            target_accounts: vec!["Air France".to_owned()],
        }
    }

    fn rfq() -> sourcing::Outreach {
        sourcing::Outreach {
            subject: "RFQ: 5000 anodised aluminium enclosures".to_owned(),
            body: "Please quote unit price, MOQ, lead time, Incoterm and validity.".to_owned(),
        }
    }

    /// A gate whose platform layer is `limits`. The layers intersect, so this is
    /// the widest thing any employee under it can be granted.
    fn gate(db: &Db, limits: PolicyLimits) -> PolicyGate {
        PolicyGate::new(db.clone(), PolicyBook::new(limits))
    }

    fn email_ports(email: Arc<MockEmailProvider>) -> Arc<Ports> {
        Arc::new(Ports {
            email,
            ..crate::mocks::ports()
        })
    }

    // -- the charter -------------------------------------------------------

    #[tokio::test]
    async fn a_charter_round_trips_through_the_constructors_it_came_in_through() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;

        for charter in [
            Charter::Purchasing {
                pack: rolepack::RolePack::international_buyer(),
                objective: buying_objective_value(),
            },
            Charter::Sales {
                pack: rolepack_sales::RolePack::sales_development(),
                objective: sales_objective_value(),
            },
        ] {
            let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
            charter
                .save(&mut tx, principal.employee_id, Utc::now())
                .await
                .expect("save");
            let read = Charter::load(&mut tx, principal.employee_id)
                .await
                .expect("load")
                .expect("a charter was written");
            tx.commit().await.expect("commit");

            assert_eq!(read, charter, "the objective did not survive the column");
            assert_eq!(read.role(), charter.role());
            // The plan is a pure function of the objective, so a charter that
            // round-tripped plans the same way.
            assert_eq!(read.brief(), charter.brief());
        }

        // One charter per employee: the second save replaced the first.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM employee_charters WHERE employee_id = $1")
                .bind(principal.employee_id.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("count");
        tx.commit().await.expect("commit");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn an_employee_with_no_charter_is_a_supported_state() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let none = Charter::load(&mut tx, principal.employee_id)
            .await
            .expect("load");
        tx.commit().await.expect("commit");
        assert!(none.is_none());
    }

    /// A stored objective is re-parsed, not deserialised. A country code the
    /// constructor would refuse must not come back out of the column.
    #[test]
    fn a_corrupt_objective_is_named_rather_than_guessed_at() {
        assert!(matches!(
            buying_objective(&json!({
                "what": "widgets", "quantity": 10, "max_unit_price": null,
                "delivery_country": "germany", "requirements": []
            })),
            Err(CharterError::Corrupt("delivery_country"))
        ));
        assert!(matches!(
            buying_objective(&json!({ "quantity": 10, "requirements": [] })),
            Err(CharterError::Corrupt("what"))
        ));
        assert!(matches!(
            sales_objective(&json!({ "segment": "railway", "target_accounts": [] })),
            Err(CharterError::Corrupt("segment"))
        ));
        assert_eq!(
            CharterError::Corrupt("what").code(),
            "corrupt_charter",
            "the metric label is stable"
        );
    }

    // -- which stage is due ------------------------------------------------

    /// The resume mechanism, as a pure function. Nothing stores where the
    /// sourcing round got to: the material says.
    #[test]
    fn the_material_decides_which_stage_of_the_plan_is_due() {
        let pack = rolepack::RolePack::international_buyer();
        let objective = buying_objective_value();
        let plan = pack.plan(&objective);
        let lane = Lane::new(Currency::Eur);
        let fx = Fx::new(Currency::Eur);

        // Day one: nobody found yet. The model goes looking.
        let empty = Round {
            candidates: &[],
            quotes: &[],
            lane: &lane,
            fx: &fx,
        };
        assert_eq!(due(&plan, &empty), rolepack::Stage::Discover);

        // Day two: candidates qualified, no answers yet. Ask them.
        let candidates = [(address("sales@supplier.example"), None)];
        let asked = Round {
            candidates: &candidates,
            ..empty
        };
        assert_eq!(due(&plan, &asked), rolepack::Stage::Rfq);

        // Day five: the replies landed as inbound email, which is the only
        // thing that changed. No timer, no stored cursor, no scheduler.
        //
        // (`Quote` borrows a domain quote, so the "quotes exist" case is
        // asserted through the same predicate `due` reads.)
        assert!(
            asked.quotes.is_empty(),
            "the RFQ turn ends without an answer, which is the point"
        );

        // An under-specified objective replaces the whole sequence.
        let vague = rolepack::Objective {
            max_unit_price: None,
            ..buying_objective_value()
        };
        assert_eq!(
            due(&pack.plan(&vague), &asked),
            rolepack::Stage::Clarify,
            "a plan containing Clarify contains nothing else"
        );
    }

    // -- purchasing --------------------------------------------------------

    /// The whole purchasing wire: a charter, a plan, and N gated emails.
    #[tokio::test]
    async fn an_rfq_goes_out_per_supplier_and_the_turn_does_not_wait_for_a_quote() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let email = Arc::new(MockEmailProvider::new());
        let effects = Effects::new(db.clone(), email_ports(email.clone()), principal.clone());
        let pack = rolepack::RolePack::international_buyer();
        let buyer = Buyer::new(
            gate(&db, pack.limits().clone()),
            effects,
            principal,
            "lena@fabrikam.example",
        );

        let candidates = [
            (address("a@supplier.example"), None),
            (address("b@supplier.example"), None),
        ];
        let lane = Lane::new(Currency::Eur);
        let fx = Fx::new(Currency::Eur);
        let round = Round {
            candidates: &candidates,
            quotes: &[],
            lane: &lane,
            fx: &fx,
        };

        let bought = purchase(
            &buyer,
            &pack,
            &buying_objective_value(),
            &round,
            &rfq(),
            TrustLabel::Trusted,
        )
        .await
        .expect("no ranking happened, so nothing could fail");

        let Bought::Asked { asking, outcomes } = bought else {
            panic!("the plan should have made Rfq due: {bought:?}");
        };
        assert_eq!(asking.len(), 2, "no reputation, so nobody is dropped");
        assert_eq!(outcomes.len(), 2, "one outcome per supplier, always");
        assert!(outcomes.iter().all(sourcing::Contacted::is_sent));
        assert_eq!(email.sent_count(), 2);
    }

    /// A quote as a supplier sent it: a price with a window on it.
    fn quoted(unit_minor: u64, lead_time_days: u32) -> buying::Quote {
        buying::Quote {
            rfq_id: buying::RfqId::new_v7(at(2026, 1, 1)),
            supplier_id: buying::SupplierId::new_v7(at(2026, 1, 1)),
            unit_price: Money::new(unit_minor, Currency::Eur).expect("nonzero"),
            moq: NonZeroU32::new(100).expect("nonzero"),
            lead_time_days,
            valid_from: at(2026, 1, 1),
            valid_until: at(2026, 12, 1),
            // DDP: the seller pays every leg, so the comparison is the goods
            // value and nothing this test has to model.
            incoterm: sourcing::Incoterm::Ddp,
            sample: buying::SampleAvailability::Free,
        }
    }

    /// Three days later the answers land as inbound email, which is the only
    /// thing that changed — and the same plan now compares instead of asking.
    /// Nothing waited, nothing was stored, and comparing is not an outreach.
    #[tokio::test]
    async fn quotes_arriving_days_later_make_the_same_plan_compare_instead_of_ask() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let email = Arc::new(MockEmailProvider::new());
        let effects = Effects::new(db.clone(), email_ports(email.clone()), principal.clone());
        let pack = rolepack::RolePack::international_buyer();
        let buyer = Buyer::new(
            gate(&db, pack.limits().clone()),
            effects,
            principal,
            "lena@fabrikam.example",
        );

        let (cheap, dear) = (quoted(600, 20), quoted(900, 45));
        let now = at(2026, 3, 1);
        let quotes = [
            Quote::live_at(&cheap, address("a@supplier.example"), 5_000, now).expect("live"),
            Quote::live_at(&dear, address("b@supplier.example"), 5_000, now).expect("live"),
        ];
        // The same suppliers are still on the list; the material that moved the
        // plan on is the quotes, not a cursor anybody wrote down.
        let candidates = [
            (address("a@supplier.example"), None),
            (address("b@supplier.example"), None),
        ];
        let lane = Lane::new(Currency::Eur);
        let fx = Fx::new(Currency::Eur);
        let round = Round {
            candidates: &candidates,
            quotes: &quotes,
            lane: &lane,
            fx: &fx,
        };

        assert_eq!(
            due(&pack.plan(&buying_objective_value()), &round),
            rolepack::Stage::Negotiate,
            "quotes in hand and the plan is still asking for them"
        );

        let bought = purchase(
            &buyer,
            &pack,
            &buying_objective_value(),
            &round,
            &rfq(),
            TrustLabel::Trusted,
        )
        .await
        .expect("both quotes are in the comparison currency");

        let Bought::Compared {
            landed,
            divergences,
        } = bought
        else {
            panic!("the plan should have made Negotiate due: {bought:?}");
        };
        assert_eq!(landed.len(), 2);
        assert_eq!(
            landed[0].supplier,
            address("a@supplier.example"),
            "cheapest landed total first"
        );
        // What the fan-out bought beyond a sort key: the two ends of the gap.
        assert_eq!(divergences.len(), 2, "{divergences:?}");
        assert_eq!(divergences[0].field, sourcing::Comparable::LandedTotal);
        assert_eq!(divergences[1].field, sourcing::Comparable::LeadTimeDays);

        assert_eq!(
            email.sent_count(),
            0,
            "comparing quotes re-asked the suppliers"
        );
    }

    /// An objective nobody can source does not become two emails to strangers.
    #[tokio::test]
    async fn an_under_specified_objective_never_reaches_a_supplier() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let email = Arc::new(MockEmailProvider::new());
        let effects = Effects::new(db.clone(), email_ports(email.clone()), principal.clone());
        let pack = rolepack::RolePack::international_buyer();
        let buyer = Buyer::new(
            gate(&db, pack.limits().clone()),
            effects,
            principal,
            "lena@fabrikam.example",
        );

        let candidates = [(address("a@supplier.example"), None)];
        let lane = Lane::new(Currency::Eur);
        let fx = Fx::new(Currency::Eur);
        let round = Round {
            candidates: &candidates,
            quotes: &[],
            lane: &lane,
            fx: &fx,
        };
        let vague = rolepack::Objective {
            delivery_country: None,
            ..buying_objective_value()
        };

        let bought = purchase(&buyer, &pack, &vague, &round, &rfq(), TrustLabel::Trusted)
            .await
            .expect("nothing ranked");
        assert!(matches!(bought, Bought::Clarify(_)), "{bought:?}");
        assert_eq!(email.sent_count(), 0, "a guess got emailed to a supplier");
    }

    /// The gate is the load-bearing refusal, and it is inside the vertical.
    /// A policy layer with no email channel produces refusals per supplier and
    /// no provider call at all.
    #[tokio::test]
    async fn an_employee_whose_policy_forbids_the_channel_sends_nothing_through_the_vertical() {
        let Some(db) = db().await else { return };
        let principal = seed(&db).await;
        let email = Arc::new(MockEmailProvider::new());
        let effects = Effects::new(db.clone(), email_ports(email.clone()), principal.clone());
        let pack = rolepack::RolePack::international_buyer();
        // Everything the buyer's role grants, except a way to speak.
        let muted = PolicyLimits {
            allowed_channels: BTreeSet::new(),
            ..pack.limits().clone()
        };
        let buyer = Buyer::new(
            gate(&db, muted),
            effects,
            principal,
            "lena@fabrikam.example",
        );

        let candidates = [
            (address("a@supplier.example"), None),
            (address("b@supplier.example"), None),
        ];
        let lane = Lane::new(Currency::Eur);
        let fx = Fx::new(Currency::Eur);
        let round = Round {
            candidates: &candidates,
            quotes: &[],
            lane: &lane,
            fx: &fx,
        };

        let bought = purchase(
            &buyer,
            &pack,
            &buying_objective_value(),
            &round,
            &rfq(),
            TrustLabel::Trusted,
        )
        .await
        .expect("nothing ranked");

        let Bought::Asked { outcomes, .. } = bought else {
            panic!("expected an attempt per supplier: {bought:?}");
        };
        assert!(
            outcomes.iter().all(|outcome| !outcome.is_sent()),
            "the gate let a vertical operation past a channel it forbids"
        );
        assert_eq!(
            email.sent_count(),
            0,
            "no Authorized<EmailSend> was minted, so the provider was never called"
        );
    }

    // -- sales -------------------------------------------------------------

    fn flow() -> Flow {
        Flow {
            prospect: "Airline Example".to_owned(),
            domain: Domain::parse("book.airline.example").expect("domain"),
            entry: Url::parse("https://book.airline.example/entry").expect("url"),
            passport_field: "#passport".to_owned(),
            destination_field: "#destination".to_owned(),
            date_field: Some("#travel-date".to_owned()),
            submit: Some("#check".to_owned()),
            panel: "#visa-info".to_owned(),
        }
    }

    fn probe() -> Probe {
        Probe {
            passport: CountryCode::parse("FR").expect("country"),
            destination: CountryCode::parse("VN").expect("country"),
            travel_date: NaiveDate::from_ymd_opt(2026, 8, 24).expect("date"),
        }
    }

    fn authority(now: DateTime<Utc>) -> Answer {
        Answer {
            requirement: Claim::VisaRequired,
            source: "orizn:requirements/v1".to_owned(),
            retrieved_at: now - TimeDelta::hours(2),
            effective_from: Some(NaiveDate::from_ymd_opt(2025, 3, 1).expect("date")),
        }
    }

    struct SalesDesk {
        prober: Prober,
        seller: Seller,
        email: Arc<MockEmailProvider>,
    }

    /// A sales employee that may read the prospect's domain and write to
    /// anybody — so a refusal below is the evidence bar and never a policy.
    async fn sales_desk(db: &Db, panels: Arc<ScriptedPanel>, limits: PolicyLimits) -> SalesDesk {
        let principal = seed(db).await;
        let email = Arc::new(MockEmailProvider::new());
        let ports = Arc::new(Ports {
            email: email.clone(),
            browser: Arc::new(MockBrowser::new()),
            ..crate::mocks::ports()
        });
        let effects = Effects::new(db.clone(), ports, principal.clone());
        let session = BrowserSession {
            employee_id: principal.employee_id,
            binding: ProviderBinding {
                provider: "mock-browser".to_owned(),
                external_id: "ctx-1".to_owned(),
            },
            user_data_dir: None,
        };

        SalesDesk {
            prober: Prober::new(
                db.clone(),
                gate(db, limits.clone()),
                effects.clone(),
                principal.clone(),
                panels,
                session,
            ),
            seller: Seller::new(
                gate(db, limits),
                effects,
                principal,
                "ines@orizn.example",
                Suppression::new(),
            ),
            email,
        }
    }

    /// Everything the sales path needs granted: the prospect's domain, email,
    /// and an outreach budget.
    fn permissive() -> PolicyLimits {
        PolicyLimits {
            allowed_domains: BTreeSet::from([
                Domain::parse("book.airline.example").expect("domain")
            ]),
            allowed_channels: BTreeSet::from([Channel::Email]),
            max_new_contacts_per_day: 10,
            ..PolicyLimits::default()
        }
    }

    /// The bar, end to end: their flow says the same wrong thing twice, so
    /// there is a finding and it goes out.
    #[tokio::test]
    async fn a_reproduced_finding_becomes_one_approach() {
        let Some(db) = db().await else { return };
        let now = at(2026, 8, 23);
        let desk = sales_desk(
            &db,
            ScriptedPanel::always("No visa required for this trip."),
            permissive(),
        )
        .await;

        let pack = rolepack_sales::RolePack::sales_development().with_limits(permissive());
        let mut sequence = Sequence::new(address("head.of.digital@airline.example"));

        let sold = sell(
            &desk.prober,
            &desk.seller,
            &pack,
            &sales_objective_value(),
            Prospect {
                flow: &flow(),
                probe: &probe(),
                authority: &authority(now),
                sequence: &mut sequence,
            },
            "Reply STOP and I will not write again.",
            now,
        )
        .await
        .expect("the check reached an outcome");

        let Sold::Approached { evidence, outcome } = sold else {
            panic!("a reproducible contradiction should have been sent: {sold:?}");
        };
        assert!(matches!(outcome, Contacted::Sent { .. }), "{outcome:?}");
        assert_eq!(desk.email.sent_count(), 1);
        assert_eq!(sequence.touches().len(), 1);

        // The message is built from the finding and from nothing they wrote.
        let approach = Approach::new(&evidence, "Reply STOP and I will not write again.");
        assert!(approach.message().body.contains("Airline Example"));
        assert!(approach.message().body.contains("How to see it again"));
        assert!(
            !approach
                .message()
                .body
                .contains("No visa required for this trip."),
            "the prospect's own page text reached the message: {}",
            approach.message().body
        );
    }

    /// The property the whole sales vertical exists to have: a flow that says
    /// two different things to two identical runs produces no approach.
    #[tokio::test]
    async fn outreach_with_no_reproducible_evidence_does_not_happen() {
        let Some(db) = db().await else { return };
        let now = at(2026, 8, 23);
        let desk = sales_desk(
            &db,
            // Same page, different answer. Nobody can reproduce this, including
            // them, so there is nothing honest to send.
            ScriptedPanel::flaky(
                "No visa required for this trip.",
                "A visa is required in advance.",
            ),
            permissive(),
        )
        .await;

        let pack = rolepack_sales::RolePack::sales_development().with_limits(permissive());
        let mut sequence = Sequence::new(address("head.of.digital@airline.example"));

        let sold = sell(
            &desk.prober,
            &desk.seller,
            &pack,
            &sales_objective_value(),
            Prospect {
                flow: &flow(),
                probe: &probe(),
                authority: &authority(now),
                sequence: &mut sequence,
            },
            "Reply STOP.",
            now,
        )
        .await
        .expect("the check reached an outcome");

        assert!(
            matches!(sold, Sold::NoFinding(Checked::NotReproducible(_))),
            "{sold:?}"
        );
        assert_eq!(
            desk.email.sent_count(),
            0,
            "an unreproduced claim about another company's product went out"
        );
        assert!(sequence.touches().is_empty(), "the sequence was advanced");
    }

    /// The role pack's channel decision, upstream of the gate. An employee with
    /// no permitted channel for this segment never even browses the prospect.
    #[tokio::test]
    async fn a_role_pack_with_no_permitted_channel_cannot_approach_through_the_vertical() {
        let Some(db) = db().await else { return };
        let now = at(2026, 8, 23);
        let desk = sales_desk(
            &db,
            ScriptedPanel::always("No visa required for this trip."),
            permissive(),
        )
        .await;

        let muted = PolicyLimits {
            allowed_channels: BTreeSet::new(),
            ..permissive()
        };
        let pack = rolepack_sales::RolePack::sales_development().with_limits(muted);
        assert_eq!(pack.approach_channel(Segment::Airline), None);

        let mut sequence = Sequence::new(address("head.of.digital@airline.example"));
        let sold = sell(
            &desk.prober,
            &desk.seller,
            &pack,
            &sales_objective_value(),
            Prospect {
                flow: &flow(),
                probe: &probe(),
                authority: &authority(now),
                sequence: &mut sequence,
            },
            "Reply STOP.",
            now,
        )
        .await
        .expect("no check ran");

        assert!(matches!(sold, Sold::Clarify(_)), "{sold:?}");
        assert_eq!(desk.email.sent_count(), 0);

        // A voice-only employee reaches an airline — but not through this
        // vertical, which only knows how to write.
        let voice_only = PolicyLimits {
            allowed_channels: BTreeSet::from([Channel::Voice]),
            ..permissive()
        };
        let pack = rolepack_sales::RolePack::sales_development().with_limits(voice_only);
        let sold = sell(
            &desk.prober,
            &desk.seller,
            &pack,
            &sales_objective_value(),
            Prospect {
                flow: &flow(),
                probe: &probe(),
                authority: &authority(now),
                sequence: &mut sequence,
            },
            "Reply STOP.",
            now,
        )
        .await
        .expect("no check ran");
        assert!(
            matches!(sold, Sold::WrongChannel(Some(Channel::Voice))),
            "{sold:?}"
        );
        assert_eq!(desk.email.sent_count(), 0);
    }
}
