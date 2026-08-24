//! Teams and sections: an owner for the `role` layer of the policy stack.
//!
//! One tenant runs several teams at once — purchasing, sales, regulatory
//! watch, support. They share a tenant, a database and a runtime, and the only
//! thing that keeps them from colliding is that each one owns a policy layer
//! and a tool allowlist of its own. This module is that ownership, and nothing
//! more: no new policy mechanism, no second evaluator. A [`Team`] holds a
//! [`PolicyLimits`] and hands it to [`EffectivePolicy::try_new`] as the `role`
//! argument, exactly where `crates/store/src/policy.rs` already looks for it.
//!
//! Three rules carry over from [`crate::policy`] and are not re-litigated here:
//!
//! * **Lower layers only tighten.** Every combination in this file goes
//!   through [`EffectivePolicy`], so a team physically cannot widen its
//!   tenant, and a section cannot widen its team.
//! * **An absent layer inherits the layer above.** An employee in no team gets
//!   `None` from [`role_layer`], which the caller resolves to the tenant
//!   layer — never `PolicyLimits::default()`, which grants nothing and would
//!   turn "this team wrote no rule" into "this team may do nothing".
//! * **A named team that does not exist is an error, not an absent layer.**
//!   Silently dropping a membership would drop the restriction it carries.
//!
//! # Why an employee may belong to several teams, and what that costs it
//!
//! It may. A support employee covering two product lines is the ordinary case,
//! and forbidding it would push people into inventing a third team that is the
//! union of two — which is the escalation this design exists to prevent.
//!
//! The price is that memberships **intersect**, never union: an employee in
//! purchasing and sales may do what *both* teams allow, which for disjoint
//! tool allowlists is nothing at all. That is the safe direction and it is
//! deliberate. Joining a second team is a way to lose reach, never to gain it.
//!
//! # The tool ceiling is a type error, not a convention
//!
//! A sibling project measured the ceiling in practice: past roughly 73 tools
//! the model stops choosing well — it hesitates between two neighbours, picks
//! the almost-right one, or redoes by hand what a tool covered. The failure
//! mode is not an exception, it is a quietly worse employee. So the allowlist
//! is per team, [`Team::MAX_TOOLS_PER_EMPLOYEE`] is checked at construction,
//! and the count is readable via [`Team::tool_count`]. Because memberships
//! intersect, a team that is under the ceiling keeps every one of its members
//! under it too, however many teams the company grows.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::McpTool;
use crate::ids::{EmployeeId, Slug, TenantId};
use crate::money::{Currency, Money};
use crate::policy::{EffectivePolicy, PolicyError, PolicyLimits, SpendLimits};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an org structure is not usable.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OrgError {
    #[error(
        "team {team} allows {count} tools but one employee may carry at most {ceiling}: split the team or drop {} tool(s)",
        count.saturating_sub(*ceiling)
    )]
    ToolCeilingExceeded {
        team: Slug,
        /// How many tools the team's allowlist actually holds.
        count: usize,
        /// [`Team::MAX_TOOLS_PER_EMPLOYEE`].
        ceiling: usize,
    },

    /// Two amounts that have to be compared are in different currencies. There
    /// is no exchange rate in the domain and there must not be one.
    #[error("mixed currencies: {left} and {right}")]
    CurrencyMismatch { left: Currency, right: Currency },

    #[error(
        "team budget {cap} is spent: {} minor units already gone today, {requested} requested",
        spent.map_or(0, Money::minor)
    )]
    TeamBudgetExhausted {
        cap: Money,
        /// What the team had already spent. `None` when the request alone is
        /// larger than the team's whole day — `Money` cannot be zero.
        spent: Option<Money>,
        requested: Money,
    },

    #[error("employee {employee} is a member of team {team}, which this tenant does not have")]
    UnknownTeam { employee: EmployeeId, team: Slug },

    #[error("team {team} has no section {section}")]
    UnknownSection { team: Slug, section: Slug },

    #[error(transparent)]
    Policy(#[from] PolicyError),
}

// ---------------------------------------------------------------------------
// Intersection
// ---------------------------------------------------------------------------

/// The stricter of two layers.
///
/// ponytail: `PolicyLimits::intersect` is private to `policy.rs`, and
/// [`EffectivePolicy`] is the public door onto the very same operation. The
/// intersection is idempotent and commutative field by field, so `(a, b, a, b)`
/// is exactly `a ∧ b`. Reusing it means a team layer can never drift from the
/// rule the gate itself applies — the alternative is a second copy of the
/// intersection here, which is precisely how a widening bug gets in. Upgrade
/// path: make `PolicyLimits::intersect` `pub` and call it directly.
fn intersect(a: &PolicyLimits, b: &PolicyLimits) -> Result<PolicyLimits, OrgError> {
    Ok(EffectivePolicy::try_new(a, b, a, b)?.limits().clone())
}

/// Same-currency minimum. Callers check the currency first.
fn min_money(a: Money, b: Money) -> Money {
    if a.minor() <= b.minor() { a } else { b }
}

// ---------------------------------------------------------------------------
// TeamBudget
// ---------------------------------------------------------------------------

/// What the whole team may spend in a day.
///
/// Distinct from the per-employee caps in [`SpendLimits`] and enforced
/// separately, because they answer different questions. The employee cap stops
/// *one* employee spending too much; the team budget stops *the team* spending
/// too much, which two employees each staying politely under their own cap will
/// otherwise do. A team budget is therefore never the sum of its members' caps
/// — it is a ceiling over the lot of them, and the sum is expected to exceed it.
///
/// No clock: the caller supplies the day's running total, exactly as
/// [`crate::action::ActionCtx::spent_today`] does for the per-employee gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamBudget {
    per_day: Money,
}

impl TeamBudget {
    pub const fn per_day(per_day: Money) -> Self {
        Self { per_day }
    }

    pub const fn cap(self) -> Money {
        self.per_day
    }

    /// Charge `amount` against the team's day, given what the team has already
    /// spent today. Returns the team's new running total.
    ///
    /// Overflow is reported as exhaustion: a total that does not fit in `u64`
    /// is over any cap that does.
    pub fn charge(self, spent_today: Option<Money>, amount: Money) -> Result<Money, OrgError> {
        let cap = self.per_day;
        for other in [Some(amount), spent_today].into_iter().flatten() {
            if other.currency() != cap.currency() {
                return Err(OrgError::CurrencyMismatch {
                    left: cap.currency(),
                    right: other.currency(),
                });
            }
        }
        let exhausted = || OrgError::TeamBudgetExhausted {
            cap,
            spent: spent_today,
            requested: amount,
        };
        let total = match spent_today {
            None => amount,
            Some(spent) => spent.checked_add(amount).map_err(|_| exhausted())?,
        };
        if total.minor() > cap.minor() {
            return Err(exhausted());
        }
        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Team
// ---------------------------------------------------------------------------

/// A named unit inside a tenant, and the owner of the `role` policy layer.
///
/// Not `Serialize`/`Deserialize` on purpose: a derived `Deserialize` would
/// rebuild a team straight from JSON and skip the tool ceiling, which is the
/// one invariant this type exists to hold. Persistence rebuilds it through
/// [`Team::try_new`] like everybody else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    tenant: TenantId,
    name: Slug,
    limits: PolicyLimits,
    budget: Option<TeamBudget>,
    /// Section name -> that section's layer, **already** intersected with the
    /// team's. Narrowing happens once, at construction, so a section can never
    /// be read back wider than the team it belongs to.
    sections: BTreeMap<Slug, PolicyLimits>,
}

impl Team {
    /// The most tools one employee may carry.
    ///
    /// 73 was measured elsewhere as the point where a catalogue starts making
    /// the model worse, so a single team gets comfortably less than half of a
    /// budget that was already at its limit. This is a ceiling on what one
    /// employee reads before its first token, not a database quota.
    pub const MAX_TOOLS_PER_EMPLOYEE: usize = 32;

    /// Build a team. Fails when the allowlist is over the ceiling, when the
    /// budget and the spend limits name different currencies, or when the
    /// limits themselves are incoherent.
    ///
    /// A budget also clamps the *per-employee* caps in `limits`: one employee
    /// may never be allowed a day larger than the team's whole day. The
    /// team-wide check in [`TeamBudget::charge`] is still required — clamping
    /// bounds one employee, it says nothing about two.
    pub fn try_new(
        tenant: TenantId,
        name: Slug,
        limits: PolicyLimits,
        budget: Option<TeamBudget>,
    ) -> Result<Self, OrgError> {
        let count = limits.allowed_mcp_tools.len();
        if count > Self::MAX_TOOLS_PER_EMPLOYEE {
            return Err(OrgError::ToolCeilingExceeded {
                team: name,
                count,
                ceiling: Self::MAX_TOOLS_PER_EMPLOYEE,
            });
        }

        let mut limits = limits;
        if let (Some(budget), Some(spend)) = (budget, limits.spend) {
            let cap = budget.cap();
            if spend.currency() != cap.currency() {
                return Err(OrgError::CurrencyMismatch {
                    left: spend.currency(),
                    right: cap.currency(),
                });
            }
            // min preserves `approval_above <= per_transaction <= per_day`.
            limits.spend = Some(SpendLimits::try_new(
                min_money(spend.max_per_transaction(), cap),
                min_money(spend.max_per_day(), cap),
                min_money(spend.approval_above(), cap),
            )?);
        }

        Ok(Self {
            tenant,
            name,
            limits,
            budget,
            sections: BTreeMap::new(),
        })
    }

    /// Declare a subdivision: a region, a product line, a market.
    ///
    /// `narrowing` is `None` for a section that exists as a label and restricts
    /// nothing yet — it inherits the team, because an empty [`PolicyLimits`]
    /// there would mean "this section may do nothing".
    pub fn with_section(
        mut self,
        name: Slug,
        narrowing: Option<&PolicyLimits>,
    ) -> Result<Self, OrgError> {
        let layer = match narrowing {
            None => self.limits.clone(),
            Some(n) => intersect(&self.limits, n)?,
        };
        self.sections.insert(name, layer);
        Ok(self)
    }

    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub const fn name(&self) -> &Slug {
        &self.name
    }

    /// The team's `role` layer: the third argument to
    /// [`EffectivePolicy::try_new`].
    pub const fn limits(&self) -> &PolicyLimits {
        &self.limits
    }

    pub const fn budget(&self) -> Option<TeamBudget> {
        self.budget
    }

    /// The team's tool allowlist. Never larger than
    /// [`Team::MAX_TOOLS_PER_EMPLOYEE`].
    pub const fn tools(&self) -> &BTreeSet<McpTool> {
        &self.limits.allowed_mcp_tools
    }

    /// How much of the ceiling this team has spent. The measurement the
    /// 73-tool lesson asks for.
    pub fn tool_count(&self) -> usize {
        self.limits.allowed_mcp_tools.len()
    }

    pub fn sections(&self) -> impl Iterator<Item = &Slug> {
        self.sections.keys()
    }

    /// The layer that applies to a member of this team, in the given section.
    pub fn layer_for(&self, section: Option<&Slug>) -> Result<&PolicyLimits, OrgError> {
        match section {
            None => Ok(&self.limits),
            Some(s) => self
                .sections
                .get(s)
                .ok_or_else(|| OrgError::UnknownSection {
                    team: self.name.clone(),
                    section: s.clone(),
                }),
        }
    }
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

/// One employee's place in one team, optionally narrowed to a section.
///
/// Plain data with no invariant of its own — it is checked against the teams it
/// names in [`role_layer`], which is the only place both halves are present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub employee: EmployeeId,
    pub team: Slug,
    pub section: Option<Slug>,
}

impl Membership {
    pub const fn new(employee: EmployeeId, team: Slug, section: Option<Slug>) -> Self {
        Self {
            employee,
            team,
            section,
        }
    }
}

/// The `role` layer for one employee: the intersection of every team it belongs
/// to, each already narrowed by its section.
///
/// `Ok(None)` means the employee is in no team — an **absent** layer, which the
/// caller resolves by inheriting the tenant's, never by substituting
/// `PolicyLimits::default()`.
///
/// Teams belonging to another tenant are not considered, so a membership can
/// never reach across the tenant boundary; it reports [`OrgError::UnknownTeam`]
/// instead.
pub fn role_layer(
    tenant: TenantId,
    employee: EmployeeId,
    teams: &[Team],
    memberships: &[Membership],
) -> Result<Option<PolicyLimits>, OrgError> {
    let mut effective: Option<PolicyLimits> = None;

    for m in memberships.iter().filter(|m| m.employee == employee) {
        let team = teams
            .iter()
            .find(|t| t.tenant == tenant && t.name == m.team)
            .ok_or_else(|| OrgError::UnknownTeam {
                employee,
                team: m.team.clone(),
            })?;
        let layer = team.layer_for(m.section.as_ref())?;
        effective = Some(match effective {
            None => layer.clone(),
            // Intersection, never union: a second team is never a way in.
            Some(prev) => intersect(&prev, layer)?,
        });
    }

    Ok(effective)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{
        Action, ActionCtx, Actor, CallingCode, Channel, ContactStanding, Domain, TrustLabel,
    };
    use crate::money::Currency::{Eur, Usd};
    use crate::policy::{Decision, evaluate};
    use chrono::{DateTime, Utc};
    use proptest::prelude::*;

    fn slug(s: &str) -> Slug {
        Slug::parse(s).unwrap()
    }

    fn domain(s: &str) -> Domain {
        Domain::parse(s).unwrap()
    }

    fn usd(minor: u64) -> Money {
        Money::new(minor, Usd).unwrap()
    }

    fn tool(server: &str, name: &str) -> McpTool {
        McpTool::new(slug(server), slug(name))
    }

    fn tenant() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::from_u128(1))
    }

    fn employee(n: u128) -> EmployeeId {
        EmployeeId::from_uuid(uuid::Uuid::from_u128(n))
    }

    fn spend(tx: u64, day: u64, approval: u64) -> Option<SpendLimits> {
        Some(SpendLimits::try_new(usd(tx), usd(day), usd(approval)).unwrap())
    }

    /// A tenant layer wide enough that every team below it is visibly tighter.
    fn tenant_layer() -> PolicyLimits {
        PolicyLimits {
            spend: spend(50_000, 200_000, 10_000),
            allowed_channels: [Channel::Email, Channel::Whatsapp, Channel::Voice]
                .into_iter()
                .collect(),
            allowed_calling_codes: [CallingCode::new(1).unwrap(), CallingCode::new(86).unwrap()]
                .into_iter()
                .collect(),
            allowed_domains: [domain("alibaba.com"), domain("crm.example.com")]
                .into_iter()
                .collect(),
            denied_domains: BTreeSet::new(),
            allowed_mcp_tools: [
                tool("erp", "lookup"),
                tool("erp", "write-note"),
                tool("crm", "lookup"),
                tool("crm", "log-call"),
            ]
            .into_iter()
            .collect(),
            allowed_a2a_peers: BTreeSet::new(),
            max_new_contacts_per_day: 100,
            allow_file_upload: true,
            allow_credential_change: false,
            allow_data_delete: false,
        }
    }

    fn purchasing() -> PolicyLimits {
        PolicyLimits {
            allowed_channels: [Channel::Email, Channel::Whatsapp].into_iter().collect(),
            allowed_domains: [domain("alibaba.com")].into_iter().collect(),
            allowed_mcp_tools: [tool("erp", "lookup"), tool("erp", "write-note")]
                .into_iter()
                .collect(),
            max_new_contacts_per_day: 25,
            ..tenant_layer()
        }
    }

    fn sales() -> PolicyLimits {
        PolicyLimits {
            // No spending at all: a sales team does not buy things.
            spend: None,
            allowed_channels: [Channel::Email, Channel::Voice].into_iter().collect(),
            allowed_domains: [domain("crm.example.com")].into_iter().collect(),
            allowed_mcp_tools: [tool("crm", "lookup"), tool("crm", "log-call")]
                .into_iter()
                .collect(),
            max_new_contacts_per_day: 60,
            ..tenant_layer()
        }
    }

    fn team(name: &str, limits: PolicyLimits, budget: Option<TeamBudget>) -> Team {
        Team::try_new(tenant(), slug(name), limits, budget).expect("a valid team")
    }

    // -- the tool ceiling --------------------------------------------------

    #[test]
    fn exceeding_the_tool_ceiling_is_refused_at_construction_and_names_the_count() {
        let over = Team::MAX_TOOLS_PER_EMPLOYEE + 3;
        let limits = PolicyLimits {
            allowed_mcp_tools: (0..over)
                .map(|i| tool("erp", &format!("t{i:02}")))
                .collect(),
            ..PolicyLimits::default()
        };

        let err = Team::try_new(tenant(), slug("everything"), limits, None).unwrap_err();
        assert_eq!(
            err,
            OrgError::ToolCeilingExceeded {
                team: slug("everything"),
                count: over,
                ceiling: Team::MAX_TOOLS_PER_EMPLOYEE,
            }
        );

        // The message a human reads has to carry the number, not just a verdict.
        let text = err.to_string();
        assert!(text.contains(&over.to_string()), "{text}");
        assert!(
            text.contains(&Team::MAX_TOOLS_PER_EMPLOYEE.to_string()),
            "{text}"
        );

        // Exactly at the ceiling is fine; the ceiling is a maximum, not a bound.
        let exact = PolicyLimits {
            allowed_mcp_tools: (0..Team::MAX_TOOLS_PER_EMPLOYEE)
                .map(|i| tool("erp", &format!("t{i:02}")))
                .collect(),
            ..PolicyLimits::default()
        };
        let t = team("exact", exact, None);
        assert_eq!(t.tool_count(), Team::MAX_TOOLS_PER_EMPLOYEE);
    }

    #[test]
    fn no_employee_can_carry_more_tools_than_the_teams_it_joined() {
        // The reason the per-team check is enough: memberships intersect, so
        // the employee's set is a subset of the smallest team's.
        let teams = [
            team("purchasing", purchasing(), None),
            team("sales", sales(), None),
        ];
        let ms = [
            Membership::new(employee(2), slug("purchasing"), None),
            Membership::new(employee(2), slug("sales"), None),
        ];
        let layer = role_layer(tenant(), employee(2), &teams, &ms)
            .unwrap()
            .unwrap();

        assert!(layer.allowed_mcp_tools.len() <= Team::MAX_TOOLS_PER_EMPLOYEE);
        for t in &teams {
            assert!(layer.allowed_mcp_tools.len() <= t.tool_count());
        }
    }

    // -- memberships -------------------------------------------------------

    #[test]
    fn an_employee_in_two_teams_gets_the_intersection_not_the_union() {
        let teams = [
            team("purchasing", purchasing(), None),
            team("sales", sales(), None),
        ];
        let ms = [
            Membership::new(employee(2), slug("purchasing"), None),
            Membership::new(employee(2), slug("sales"), None),
        ];

        let both = role_layer(tenant(), employee(2), &teams, &ms)
            .unwrap()
            .unwrap();

        // The purchasing tools and the sales tools are disjoint, so belonging to
        // both is not a way to hold all four. It is a way to hold none.
        assert!(both.allowed_mcp_tools.is_empty());
        // Email is the only channel both teams grant; voice and whatsapp are not.
        assert_eq!(both.allowed_channels, [Channel::Email].into());
        // Sales permits no spending, so the pair permits none either.
        assert!(both.spend.is_none());
        // Domains likewise: neither team's site survives the other.
        assert!(both.allowed_domains.is_empty());
        assert!(both.max_new_contacts_per_day <= 25);

        // And each team on its own is unaffected by the other's existence.
        let only_purchasing = role_layer(tenant(), employee(2), &teams, &ms[..1])
            .unwrap()
            .unwrap();
        assert_eq!(only_purchasing.allowed_mcp_tools.len(), 2);
        assert!(only_purchasing.spend.is_some());
    }

    #[test]
    fn an_employee_in_no_team_has_an_absent_layer_not_an_empty_one() {
        let teams = [team("purchasing", purchasing(), None)];
        let ms = [Membership::new(employee(7), slug("purchasing"), None)];

        // Somebody else's membership is not this employee's.
        assert_eq!(
            role_layer(tenant(), employee(2), &teams, &ms).unwrap(),
            None
        );
    }

    #[test]
    fn a_membership_cannot_reach_a_team_in_another_tenant() {
        let foreign = Team::try_new(
            TenantId::from_uuid(uuid::Uuid::from_u128(99)),
            slug("purchasing"),
            purchasing(),
            None,
        )
        .unwrap();
        let ms = [Membership::new(employee(2), slug("purchasing"), None)];

        // Not "absent, so inherit the tenant" — that would silently drop the
        // restriction the membership was carrying.
        assert_eq!(
            role_layer(tenant(), employee(2), &[foreign], &ms),
            Err(OrgError::UnknownTeam {
                employee: employee(2),
                team: slug("purchasing"),
            })
        );
    }

    // -- sections ----------------------------------------------------------

    #[test]
    fn a_section_narrows_and_cannot_widen() {
        let greedy = PolicyLimits {
            spend: spend(999_999, 999_999, 999_999),
            allowed_channels: [
                Channel::Email,
                Channel::Sms,
                Channel::Whatsapp,
                Channel::Voice,
            ]
            .into_iter()
            .collect(),
            allowed_domains: [domain("alibaba.com"), domain("anything.example.com")]
                .into_iter()
                .collect(),
            allowed_mcp_tools: [tool("erp", "lookup"), tool("crm", "log-call")]
                .into_iter()
                .collect(),
            max_new_contacts_per_day: 10_000,
            allow_credential_change: true,
            ..purchasing()
        };

        let t = team("purchasing", purchasing(), None)
            .with_section(slug("eu"), Some(&greedy))
            .unwrap()
            .with_section(
                slug("apac"),
                Some(&PolicyLimits {
                    max_new_contacts_per_day: 5,
                    ..purchasing()
                }),
            )
            .unwrap()
            .with_section(slug("unassigned"), None)
            .unwrap();

        // The greedy section got nothing it asked for beyond the team.
        let eu = t.layer_for(Some(&slug("eu"))).unwrap();
        assert!(is_tighter_than(eu, t.limits()), "{eu:?}");
        assert_eq!(eu.max_new_contacts_per_day, 25);
        assert_eq!(eu.allowed_channels, purchasing().allowed_channels);
        assert_eq!(eu.allowed_domains, [domain("alibaba.com")].into());
        assert_eq!(eu.allowed_mcp_tools, [tool("erp", "lookup")].into());
        assert!(!eu.allow_credential_change);
        assert_eq!(eu.spend.unwrap().max_per_day(), usd(200_000));

        // A real narrowing does take effect.
        let apac = t.layer_for(Some(&slug("apac"))).unwrap();
        assert_eq!(apac.max_new_contacts_per_day, 5);

        // A section that restricts nothing inherits the team, it does not
        // collapse to `PolicyLimits::default()`.
        assert_eq!(t.layer_for(Some(&slug("unassigned"))).unwrap(), t.limits());
        assert_ne!(
            t.layer_for(Some(&slug("unassigned"))).unwrap(),
            &PolicyLimits::default()
        );

        // No section: the team layer itself.
        assert_eq!(t.layer_for(None).unwrap(), t.limits());

        // A section nobody declared is an error, not a wider layer.
        assert_eq!(
            t.layer_for(Some(&slug("latam"))),
            Err(OrgError::UnknownSection {
                team: slug("purchasing"),
                section: slug("latam"),
            })
        );

        let names: Vec<&Slug> = t.sections().collect();
        assert_eq!(names, [&slug("apac"), &slug("eu"), &slug("unassigned")]);
    }

    // -- the team budget ---------------------------------------------------

    #[test]
    fn a_team_budget_is_not_the_sum_of_the_employee_caps_and_is_enforced_separately() {
        // Each employee may spend 5_000 per day. Two of them, so the caps sum to
        // 10_000 — but the team's day is 8_000, and that is the number that
        // decides, which is the entire point of having it.
        let per_employee = PolicyLimits {
            spend: spend(5_000, 5_000, 5_000),
            ..purchasing()
        };
        let budget = TeamBudget::per_day(usd(8_000));
        let t = team("purchasing", per_employee, Some(budget));

        let caps_sum = t.limits().spend.unwrap().max_per_day().minor() * 2;
        assert_eq!(caps_sum, 10_000);
        assert_ne!(caps_sum, budget.cap().minor());

        // The per-employee gate is blind to the team: it allows both payments,
        // because each employee's own ledger is empty.
        let policy = EffectivePolicy::try_new(
            &tenant_layer(),
            &tenant_layer(),
            t.limits(),
            &PolicyLimits {
                spend: spend(5_000, 5_000, 5_000),
                ..tenant_layer()
            },
        )
        .unwrap();
        let pay = Action::PaymentCreate { amount: usd(4_500) };
        for who in [employee(2), employee(3)] {
            let ctx = ActionCtx {
                trust: TrustLabel::Trusted,
                contact: ContactStanding::Known,
                ..ActionCtx::new(Actor::new(tenant(), who), at(1_700_000_000))
            };
            assert_eq!(evaluate(&policy, &pay, &ctx), Decision::Allow);
        }

        // The team budget is what catches the second one.
        let after_first = budget.charge(None, usd(4_500)).unwrap();
        assert_eq!(after_first, usd(4_500));
        assert_eq!(
            budget.charge(Some(after_first), usd(4_500)),
            Err(OrgError::TeamBudgetExhausted {
                cap: usd(8_000),
                spent: Some(usd(4_500)),
                requested: usd(4_500),
            })
        );
        // Exactly on the cap is still fine; one minor unit over is not.
        assert_eq!(
            budget.charge(Some(after_first), usd(3_500)).unwrap(),
            usd(8_000)
        );
        assert!(budget.charge(Some(after_first), usd(3_501)).is_err());

        // A ledger in another currency is a mismatch, never a free pass.
        assert_eq!(
            budget.charge(Some(Money::new(1, Eur).unwrap()), usd(1)),
            Err(OrgError::CurrencyMismatch {
                left: Usd,
                right: Eur
            })
        );
        // Overflow reads as exhaustion, not as a wrap.
        assert!(matches!(
            budget.charge(Some(usd(u64::MAX)), usd(u64::MAX)),
            Err(OrgError::TeamBudgetExhausted { .. })
        ));
    }

    #[test]
    fn a_budget_smaller_than_the_employee_cap_clamps_the_employee_cap() {
        // One employee must never be handed a day bigger than the team's day.
        let t = team(
            "purchasing",
            PolicyLimits {
                spend: spend(50_000, 200_000, 10_000),
                ..purchasing()
            },
            Some(TeamBudget::per_day(usd(3_000))),
        );
        let clamped = t.limits().spend.unwrap();
        assert_eq!(clamped.max_per_day(), usd(3_000));
        assert_eq!(clamped.max_per_transaction(), usd(3_000));
        assert_eq!(clamped.approval_above(), usd(3_000));

        // And the clamp is still a tightening of the tenant, not a widening.
        assert!(is_tighter_than(t.limits(), &tenant_layer()));
    }

    #[test]
    fn a_budget_in_the_wrong_currency_is_refused_at_construction() {
        assert_eq!(
            Team::try_new(
                tenant(),
                slug("purchasing"),
                purchasing(),
                Some(TeamBudget::per_day(Money::new(9_000, Eur).unwrap())),
            ),
            Err(OrgError::CurrencyMismatch {
                left: Usd,
                right: Eur
            })
        );
    }

    // -- the property: a team cannot widen its tenant ----------------------

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    /// Field by field, with no `..`: adding a field to `PolicyLimits` breaks
    /// this and the property below stops being a half-truth.
    fn is_tighter_than(inner: &PolicyLimits, outer: &PolicyLimits) -> bool {
        let PolicyLimits {
            spend,
            allowed_channels,
            allowed_calling_codes,
            allowed_domains,
            denied_domains,
            allowed_mcp_tools,
            allowed_a2a_peers,
            max_new_contacts_per_day,
            allow_file_upload,
            allow_credential_change,
            allow_data_delete,
        } = inner;

        let spend_ok = match (spend, outer.spend) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(i), Some(o)) => {
                i.currency() == o.currency()
                    && i.max_per_transaction().minor() <= o.max_per_transaction().minor()
                    && i.max_per_day().minor() <= o.max_per_day().minor()
                    && i.approval_above().minor() <= o.approval_above().minor()
            }
        };

        spend_ok
            && allowed_channels.is_subset(&outer.allowed_channels)
            && allowed_calling_codes.is_subset(&outer.allowed_calling_codes)
            && allowed_domains.is_subset(&outer.allowed_domains)
            && denied_domains.is_superset(&outer.denied_domains)
            && allowed_mcp_tools.is_subset(&outer.allowed_mcp_tools)
            && allowed_a2a_peers.is_subset(&outer.allowed_a2a_peers)
            && *max_new_contacts_per_day <= outer.max_new_contacts_per_day
            && (!*allow_file_upload || outer.allow_file_upload)
            && (!*allow_credential_change || outer.allow_credential_change)
            && (!*allow_data_delete || outer.allow_data_delete)
    }

    fn universe() -> (Vec<Channel>, Vec<CallingCode>, Vec<Domain>, Vec<McpTool>) {
        (
            vec![
                Channel::Email,
                Channel::Sms,
                Channel::Whatsapp,
                Channel::Voice,
            ],
            vec![
                CallingCode::new(1).unwrap(),
                CallingCode::new(33).unwrap(),
                CallingCode::new(86).unwrap(),
            ],
            vec![
                domain("alibaba.com"),
                domain("crm.example.com"),
                domain("banking.example.com"),
            ],
            vec![
                tool("erp", "lookup"),
                tool("erp", "write-note"),
                tool("crm", "lookup"),
                tool("crm", "log-call"),
            ],
        )
    }

    fn any_spend() -> impl Strategy<Value = Option<SpendLimits>> {
        proptest::option::of(
            (1u64..100_000, 1u64..100_000, 1u64..100_000).prop_map(|(a, b, c)| {
                let mut v = [a, b, c];
                v.sort_unstable();
                SpendLimits::try_new(usd(v[1]), usd(v[2]), usd(v[0]))
                    .expect("ordered by construction")
            }),
        )
    }

    fn any_limits() -> impl Strategy<Value = PolicyLimits> {
        let (channels, codes, domains, tools) = universe();
        (
            any_spend(),
            proptest::sample::subsequence(channels.clone(), 0..=channels.len()),
            proptest::sample::subsequence(codes.clone(), 0..=codes.len()),
            proptest::sample::subsequence(domains.clone(), 0..=domains.len()),
            proptest::sample::subsequence(domains.clone(), 0..=domains.len()),
            proptest::sample::subsequence(tools.clone(), 0..=tools.len()),
            proptest::sample::subsequence(domains.clone(), 0..=domains.len()),
            0u32..500,
            any::<(bool, bool, bool)>(),
        )
            .prop_map(
                |(spend, ch, cc, ad, dd, mcp, peers, contacts, (upload, cred, del))| PolicyLimits {
                    spend,
                    allowed_channels: ch.into_iter().collect(),
                    allowed_calling_codes: cc.into_iter().collect(),
                    allowed_domains: ad.into_iter().collect(),
                    denied_domains: dd.into_iter().collect(),
                    allowed_mcp_tools: mcp.into_iter().collect(),
                    allowed_a2a_peers: peers.into_iter().collect(),
                    max_new_contacts_per_day: contacts,
                    allow_file_upload: upload,
                    allow_credential_change: cred,
                    allow_data_delete: del,
                },
            )
    }

    fn any_budget() -> impl Strategy<Value = Option<TeamBudget>> {
        proptest::option::of((1u64..100_000).prop_map(|m| TeamBudget::per_day(usd(m))))
    }

    proptest! {
        /// Whatever a team writes in its layer, and whatever a section writes
        /// under it, the stack that reaches the gate is never wider than the
        /// tenant's. Random layers, not chosen ones.
        #[test]
        fn a_team_can_never_widen_its_tenant(
            tenant_limits in any_limits(),
            team_limits in any_limits(),
            section_limits in any_limits(),
            budget in any_budget(),
        ) {
            let t = Team::try_new(tenant(), slug("under-test"), team_limits, budget)
                .expect("universe is far under the tool ceiling")
                .with_section(slug("region"), Some(&section_limits))
                .expect("single currency");

            // The team's own layer, once it is a layer in the stack.
            let stacked = EffectivePolicy::try_new(
                &tenant_limits,
                &tenant_limits,
                t.limits(),
                &tenant_limits,
            )
            .expect("single currency")
            .limits()
            .clone();
            prop_assert!(
                is_tighter_than(&stacked, &tenant_limits),
                "team widened the tenant:\n  tenant {tenant_limits:?}\n  got {stacked:?}"
            );

            // The section, likewise — and tighter than the team as well.
            let section = t.layer_for(Some(&slug("region"))).unwrap();
            prop_assert!(is_tighter_than(section, t.limits()));
            let stacked_section = EffectivePolicy::try_new(
                &tenant_limits,
                &tenant_limits,
                section,
                &tenant_limits,
            )
            .expect("single currency")
            .limits()
            .clone();
            prop_assert!(is_tighter_than(&stacked_section, &tenant_limits));

            // A budget only ever removes spending room.
            if let (Some(b), Some(before)) = (t.budget(), t.limits().spend) {
                prop_assert!(before.max_per_day().minor() <= b.cap().minor());
            }
        }

        /// Two teams: the employee's layer is tighter than *each* of them, so
        /// a second membership is never a way to gain anything.
        #[test]
        fn a_second_team_never_widens_the_first(
            a in any_limits(),
            b in any_limits(),
        ) {
            let teams = [
                Team::try_new(tenant(), slug("alpha"), a, None).unwrap(),
                Team::try_new(tenant(), slug("beta"), b, None).unwrap(),
            ];
            let ms = [
                Membership::new(employee(2), slug("alpha"), None),
                Membership::new(employee(2), slug("beta"), None),
            ];

            let both = role_layer(tenant(), employee(2), &teams, &ms)
                .expect("single currency")
                .expect("two memberships");

            for t in &teams {
                prop_assert!(
                    is_tighter_than(&both, t.limits()),
                    "membership widened {}:\n  team {:?}\n  got {both:?}",
                    t.name(),
                    t.limits()
                );
            }
        }
    }
}
