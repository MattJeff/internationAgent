//! A tenant-owned pool of numbers, and the rule that routes an inbound call
//! back to the employee who already owns that relationship.
//!
//! # Why a pool exists
//!
//! One regulated FR number per employee means up to one hundred French
//! regulatory bundles, each needing a French address and a proof of address
//! dated within three months, each reviewed by a human. That cost is
//! provider-independent — it is the regulator's, not Twilio's. Five to ten
//! shared numbers with per-employee routing removes more work than any vendor
//! switch, which is why pooling is what makes onboarding a hundred employees
//! possible at all rather than a way to shave the bill.
//!
//! A US number needs no bundle, and a dedicated number is a better identity
//! where it is free, so pooling is a [`NumberStrategy`], not a replacement.
//! Both strategies answer the same contract: the employee has a number to send
//! from, and an inbound message reaches exactly one employee.
//!
//! # The pattern this generalises
//!
//! `Step::Whatsapp` already routes every employee to one verified company
//! sender (`WHATSAPP_ROUTING` in `agentos-app::provisioning`). This module is
//! that decision widened from one shared sender to N pooled numbers, and it
//! keeps the same shape: the tenant owns the resource, the employee holds an
//! [`Allocation`] onto it, and the employee id — never the bare number — is
//! what makes two employees on one number distinguishable.
//!
//! # The hard half: inbound
//!
//! Outbound is trivial: an employee sends from the number it is allocated to.
//! Inbound is the design. A supplier that has been talking to Lena must keep
//! reaching Lena, because Lena holds the trust link, the learned expectations
//! and the beliefs-with-provenance about *that* supplier (see
//! [`crate::psyche::links`]) and Alex holds none of them. Routing the supplier
//! to Alex silently discards the accumulated relationship. Counterparty
//! affinity is therefore a correctness requirement, and
//! [`route_inbound`] enumerates its outcomes instead of returning an `Option`
//! that a caller could `unwrap_or_default` into a lost conversation.
//!
//! Nothing here reads a clock or does I/O: `now` is a parameter, so a decision
//! can be replayed from stored rows and must come out identical.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::E164;
use crate::ids::EmployeeId;
use crate::sourcing::CountryCode;

// ---------------------------------------------------------------------------
// Strategy
// ---------------------------------------------------------------------------

/// How a deployment gets numbers for its employees.
///
/// This is a per-region operational decision, not a per-employee one, and it is
/// deliberately not derived from the region here: which countries demand a
/// bundle is the provider's opinion and it changes monthly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumberStrategy {
    /// One number bought per employee. Right where a number is cheap and
    /// unregulated (US): a dedicated identity with no routing ambiguity at all.
    Dedicated,
    /// Employees share a small tenant-owned pool and are routed by
    /// counterparty. Right where each number costs a human-reviewed bundle.
    Pooled,
}

impl NumberStrategy {
    /// Stable wire/storage spelling of the variant.
    pub const fn as_str(&self) -> &'static str {
        match self {
            NumberStrategy::Dedicated => "dedicated",
            NumberStrategy::Pooled => "pooled",
        }
    }

    /// Read one back out of storage.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "dedicated" => Some(NumberStrategy::Dedicated),
            "pooled" => Some(NumberStrategy::Pooled),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// Where a number's regulatory paperwork has got to.
///
/// A number whose bundle is still in review is not usable yet, and that is a
/// state rather than an error: it is a normal wait measured in days, and the
/// employees who need it are not broken, they are early. It mirrors
/// [`crate::employee::ResourceState::PendingExternal`] field for field so the
/// store layer can carry one into the other without inventing anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BundleState {
    /// Usable now: either no bundle was required, or it was approved.
    Ready,
    /// A regulatory bundle is with a human reviewer.
    InReview {
        /// Provider-side handle to poll (bundle sid, review id).
        poll_ref: String,
        /// After this instant the wait is overdue and needs a human of ours.
        expected_by: DateTime<Utc>,
    },
}

/// One number the **tenant** owns, that up to `capacity` employees share.
///
/// The number belongs to the tenant and not to any employee: that is the whole
/// point, and it is why release is a tenant decision and never a side effect of
/// offboarding one employee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolNumber {
    /// The number itself.
    pub number: E164,
    /// The country it was bought in, which is what decides whether it needed a
    /// bundle at all.
    pub region: CountryCode,
    /// Whether the paperwork lets us use it yet.
    pub state: BundleState,
    /// How many employees may share it. `0` is legal and means *drained*: the
    /// number keeps serving the conversations already on it, and takes no new
    /// employee. That is how a number is retired without cutting live threads.
    pub capacity: u16,
}

impl PoolNumber {
    /// Whether this number can carry traffic today.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, BundleState::Ready)
    }

    /// Whether a bundle has been in review longer than promised, i.e. the wait
    /// has stopped being normal and needs somebody to chase it.
    pub fn overdue(&self, now: DateTime<Utc>) -> bool {
        match &self.state {
            BundleState::Ready => false,
            BundleState::InReview { expected_by, .. } => now > *expected_by,
        }
    }
}

/// An employee placed onto one pooled number.
///
/// At most one per (employee, region) — an employee with two French numbers has
/// two French identities, which is exactly the confusion the pool exists to
/// avoid. [`allocate`] enforces it by being idempotent per region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    /// Who is routed here.
    pub employee: EmployeeId,
    /// The pooled number they send from and receive on.
    pub number: E164,
    /// Region of that number, denormalised so region rules need no join.
    pub region: CountryCode,
    /// When the placement was made.
    pub allocated_at: DateTime<Utc>,
}

/// The routing memory: on this pooled number, this counterparty belongs to this
/// employee.
///
/// One row per (pooled number, counterparty). It is what keeps a supplier
/// talking to the same employee across months, and therefore what keeps the
/// psyche's trust links and expectations pointed at the relationship that
/// actually earned them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterpartyAffinity {
    /// The pooled number the two of them talk on.
    pub number: E164,
    /// The far end: the supplier, the carrier, the customer.
    pub counterparty: E164,
    /// The employee that owns this relationship.
    pub employee: EmployeeId,
    /// When the relationship was first seen on this number.
    pub established_at: DateTime<Utc>,
    /// Last time a message flowed. The primary arbitration key.
    pub last_used_at: DateTime<Utc>,
}

impl CounterpartyAffinity {
    /// The row a first contact creates.
    pub fn first_contact(
        number: E164,
        counterparty: E164,
        employee: EmployeeId,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            number,
            counterparty,
            employee,
            established_at: now,
            last_used_at: now,
        }
    }

    /// The same row with its recency refreshed, for the caller to persist.
    ///
    /// `max` rather than assignment: a redelivered or out-of-order webhook
    /// carries an older `now`, and letting it rewind recency would let a stale
    /// event flip the arbitration below.
    fn touched(&self, now: DateTime<Utc>) -> Self {
        Self {
            last_used_at: self.last_used_at.max(now),
            ..self.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// Inbound routing
// ---------------------------------------------------------------------------

/// Where one inbound message on a pooled number goes.
///
/// Every outcome is named, including the two that are not "deliver it": an
/// ambiguity a human may want to know about, and a misconfiguration. Neither is
/// a silent drop and neither is a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// This counterparty already talks to this employee here. `affinity` is the
    /// stored row with its recency refreshed — persist it.
    Established {
        /// The winning relationship, touched at `now`.
        affinity: CounterpartyAffinity,
    },
    /// Nobody on this number has spoken to this counterparty before. `affinity`
    /// is the row to persist, which is what makes the choice stick.
    FirstContact {
        /// The relationship being created, established at `now`.
        affinity: CounterpartyAffinity,
    },
    /// More than one employee holds an affinity with this counterparty on this
    /// number. Arbitrated by the rule documented on [`route_inbound`]; the
    /// message is delivered, and the contention is reported rather than hidden.
    Ambiguous {
        /// The winner, touched at `now`.
        affinity: CounterpartyAffinity,
        /// The employees that lost, most-recent-first. Never empty, never
        /// contains the winner.
        contended_with: Vec<EmployeeId>,
    },
    /// No employee is allocated to this number. The message cannot be
    /// delivered, and that is a misconfiguration to surface, not a drop: a
    /// number is answering that nobody is behind.
    Unallocated,
}

impl RoutingDecision {
    /// The employee to deliver to, if there is one.
    pub fn employee(&self) -> Option<EmployeeId> {
        match self {
            RoutingDecision::Established { affinity }
            | RoutingDecision::FirstContact { affinity }
            | RoutingDecision::Ambiguous { affinity, .. } => Some(affinity.employee),
            RoutingDecision::Unallocated => None,
        }
    }
}

/// Decide which employee an inbound message on `pool_number` belongs to.
///
/// Pure: same inputs, same decision, whatever order the rows arrive in. The
/// caller may hand over every affinity and allocation it has; rows for other
/// numbers are filtered out here rather than trusted to have been.
///
/// # The rules, in order
///
/// 1. **A live affinity wins.** An affinity is live only while its employee
///    still holds an allocation on this number. A stale row — the employee was
///    moved to another number, or left — is ignored, because routing to an
///    employee who no longer answers here is a drop wearing continuity's
///    clothes. Falling through to rule 2 is the honest outcome.
/// 2. **Ambiguity is arbitrated by a total order on the rows' own fields**,
///    never by position in the slice: most recently used first, then the
///    *oldest* `established_at` (the original relationship outranks the
///    latecomer that happened to reply last), then the lowest [`EmployeeId`].
///    Uuids give the last key a total order, so there is no tie left to break
///    and no input ordering can change the answer.
/// 3. **First contact goes to the least-loaded allocated employee**: fewest
///    affinities on this number, ties to the lowest [`EmployeeId`]. Least-loaded
///    rather than round-robin because round-robin needs a cursor, and a cursor
///    is state that has to be stored, replicated and replayed; the affinity
///    table already counts, and counting it is deterministic under replay.
/// 4. **Nobody allocated is [`RoutingDecision::Unallocated`]**, never a default
///    employee.
pub fn route_inbound(
    pool_number: &E164,
    from: &E164,
    affinities: &[CounterpartyAffinity],
    allocations: &[Allocation],
    now: DateTime<Utc>,
) -> RoutingDecision {
    let here: BTreeSet<EmployeeId> = allocations
        .iter()
        .filter(|a| &a.number == pool_number)
        .map(|a| a.employee)
        .collect();

    let mut live: Vec<&CounterpartyAffinity> = affinities
        .iter()
        .filter(|a| &a.number == pool_number && &a.counterparty == from)
        .filter(|a| here.contains(&a.employee))
        .collect();
    // Rule 2: a total order on the row's own fields.
    live.sort_by(|a, b| {
        b.last_used_at
            .cmp(&a.last_used_at)
            .then(a.established_at.cmp(&b.established_at))
            .then(a.employee.cmp(&b.employee))
    });

    if let Some((winner, rest)) = live.split_first() {
        let contended_with: Vec<EmployeeId> = rest
            .iter()
            .map(|a| a.employee)
            .filter(|e| *e != winner.employee)
            .collect();
        let affinity = winner.touched(now);
        return if contended_with.is_empty() {
            RoutingDecision::Established { affinity }
        } else {
            RoutingDecision::Ambiguous {
                affinity,
                contended_with,
            }
        };
    }

    // Rule 3: least loaded on this number, then lowest id.
    let load = |employee: EmployeeId| {
        affinities
            .iter()
            .filter(|a| &a.number == pool_number && a.employee == employee)
            .count()
    };
    match here.into_iter().min_by_key(|e| (load(*e), *e)) {
        Some(employee) => RoutingDecision::FirstContact {
            affinity: CounterpartyAffinity::first_contact(
                pool_number.clone(),
                from.clone(),
                employee,
                now,
            ),
        },
        // Rule 4.
        None => RoutingDecision::Unallocated,
    }
}

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

/// Why an employee could not be placed on a number.
///
/// The three are deliberately distinct, because they need three different
/// humans: a full pool needs a buyer, a pool in review needs patience, an empty
/// pool needs whoever configured the tenant.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PoolError {
    /// Every ready number in the region is at capacity. **Not a failure**: it
    /// is the signal to buy another number, which is another bundle and
    /// therefore a wait of days. Surfacing it as an error would tell an
    /// operator to retry, which cannot help.
    #[error("{region} pool is full: {employees} employees on {numbers} numbers")]
    Full {
        /// Region asked for.
        region: CountryCode,
        /// Ready numbers in it.
        numbers: usize,
        /// Employees already on them.
        employees: usize,
    },
    /// The region has numbers, but every one of them is still in regulatory
    /// review. Nothing is wrong; nothing can be done either.
    #[error("{region} pool has no approved number yet")]
    AwaitingBundle {
        /// Region asked for.
        region: CountryCode,
        /// The soonest any of them is expected to clear.
        soonest: DateTime<Utc>,
    },
    /// The region has no numbers at all. This is the broken pool: somebody
    /// pointed a tenant at a region nobody ever bought into.
    #[error("no numbers in the {0} pool")]
    Empty(CountryCode),
}

/// Place `employee` on a number in `region`.
///
/// Idempotent, like every `ensure_*` in this system: an employee that already
/// holds an allocation in this region gets it back unchanged, so re-running
/// provisioning never moves a live relationship onto a different number.
///
/// Otherwise it picks the ready number with the **fewest employees on it**,
/// ties to the lowest number lexicographically. Spreading rather than packing:
/// capacity is already paid for, and one number carrying every employee makes
/// that number a single point of failure for the whole tenant. Both keys come
/// off the rows themselves, so the choice does not depend on slice order.
///
/// Capacity is a hard ceiling — a number at capacity is not a candidate, so it
/// cannot be exceeded by any sequence of calls that persists what it returns.
pub fn allocate(
    employee: EmployeeId,
    region: CountryCode,
    pool: &[PoolNumber],
    allocations: &[Allocation],
    now: DateTime<Utc>,
) -> Result<Allocation, PoolError> {
    if let Some(existing) = allocations
        .iter()
        .find(|a| a.employee == employee && a.region == region)
    {
        return Ok(existing.clone());
    }

    let in_region: Vec<&PoolNumber> = pool.iter().filter(|n| n.region == region).collect();
    if in_region.is_empty() {
        return Err(PoolError::Empty(region));
    }

    let load = |number: &E164| allocations.iter().filter(|a| &a.number == number).count();
    let ready: Vec<&PoolNumber> = in_region.iter().copied().filter(|n| n.is_ready()).collect();

    let pick = ready
        .iter()
        .copied()
        .filter(|n| load(&n.number) < usize::from(n.capacity))
        .min_by(|a, b| {
            load(&a.number)
                .cmp(&load(&b.number))
                .then_with(|| a.number.cmp(&b.number))
        });

    match pick {
        Some(number) => Ok(Allocation {
            employee,
            number: number.number.clone(),
            region,
            allocated_at: now,
        }),
        None if ready.is_empty() => Err(PoolError::AwaitingBundle {
            region,
            soonest: in_region
                .iter()
                .filter_map(|n| match &n.state {
                    BundleState::InReview { expected_by, .. } => Some(*expected_by),
                    BundleState::Ready => None,
                })
                .min()
                .unwrap_or(now),
        }),
        None => Err(PoolError::Full {
            region,
            numbers: ready.len(),
            employees: ready.iter().map(|n| load(&n.number)).sum(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use proptest::prelude::*;
    use uuid::Uuid;

    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    /// Employees numbered so their id order is their argument order.
    fn emp(n: u8) -> EmployeeId {
        EmployeeId::from_uuid(Uuid::from_bytes([n; 16]))
    }

    fn num(raw: &str) -> E164 {
        E164::parse(raw).unwrap()
    }

    fn fr() -> CountryCode {
        CountryCode::parse("FR").unwrap()
    }

    fn pooled(raw: &str, capacity: u16) -> PoolNumber {
        PoolNumber {
            number: num(raw),
            region: fr(),
            state: BundleState::Ready,
            capacity,
        }
    }

    fn alloc(employee: EmployeeId, raw: &str) -> Allocation {
        Allocation {
            employee,
            number: num(raw),
            region: fr(),
            allocated_at: at(0),
        }
    }

    fn affinity(
        raw: &str,
        counterparty: &str,
        employee: EmployeeId,
        established: i64,
        used: i64,
    ) -> CounterpartyAffinity {
        CounterpartyAffinity {
            number: num(raw),
            counterparty: num(counterparty),
            employee,
            established_at: at(established),
            last_used_at: at(used),
        }
    }

    const POOL: &str = "+33755000001";
    const SUPPLIER: &str = "+33612345678";

    // -- routing -----------------------------------------------------------

    #[test]
    fn an_established_affinity_wins_whatever_the_order() {
        let allocations = [alloc(emp(1), POOL), alloc(emp(2), POOL)];
        let mut affinities = vec![
            affinity(POOL, "+33699999999", emp(2), 0, 900),
            affinity(POOL, SUPPLIER, emp(1), 10, 20),
            affinity("+33755000002", SUPPLIER, emp(2), 0, 999),
        ];

        for _ in 0..affinities.len() {
            affinities.rotate_left(1);
            let decision = route_inbound(
                &num(POOL),
                &num(SUPPLIER),
                &affinities,
                &allocations,
                at(100),
            );
            match decision {
                RoutingDecision::Established { affinity } => {
                    assert_eq!(affinity.employee, emp(1));
                    // Recency refreshed for the caller to persist.
                    assert_eq!(affinity.last_used_at, at(100));
                    assert_eq!(affinity.established_at, at(10));
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_replayed_older_event_does_not_rewind_recency() {
        let allocations = [alloc(emp(1), POOL)];
        let affinities = [affinity(POOL, SUPPLIER, emp(1), 10, 500)];

        let decision = route_inbound(
            &num(POOL),
            &num(SUPPLIER),
            &affinities,
            &allocations,
            at(100),
        );
        assert_eq!(decision.employee(), Some(emp(1)));
        match decision {
            RoutingDecision::Established { affinity } => {
                assert_eq!(affinity.last_used_at, at(500));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_affinity_whose_employee_left_the_number_is_not_live() {
        // Lena's affinity is stale: she is on another number now.
        let allocations = [alloc(emp(2), POOL), alloc(emp(1), "+33755000002")];
        let affinities = [affinity(POOL, SUPPLIER, emp(1), 0, 900)];

        let decision = route_inbound(
            &num(POOL),
            &num(SUPPLIER),
            &affinities,
            &allocations,
            at(100),
        );
        assert!(matches!(decision, RoutingDecision::FirstContact { .. }));
        assert_eq!(decision.employee(), Some(emp(2)));
    }

    #[test]
    fn first_contact_goes_to_the_least_loaded_and_is_stable_on_replay() {
        let allocations = [
            alloc(emp(1), POOL),
            alloc(emp(2), POOL),
            alloc(emp(3), POOL),
        ];
        let affinities = [
            affinity(POOL, "+33600000001", emp(1), 0, 0),
            affinity(POOL, "+33600000002", emp(1), 0, 0),
            affinity(POOL, "+33600000003", emp(3), 0, 0),
            // Another number's traffic must not count as load here.
            affinity("+33755000002", "+33600000004", emp(2), 0, 0),
        ];

        let first = route_inbound(
            &num(POOL),
            &num(SUPPLIER),
            &affinities,
            &allocations,
            at(100),
        );
        assert_eq!(
            first.employee(),
            Some(emp(2)),
            "emp(2) carries nothing here"
        );

        // Same inputs replayed, same decision — including the row to persist.
        let again = route_inbound(
            &num(POOL),
            &num(SUPPLIER),
            &affinities,
            &allocations,
            at(100),
        );
        assert_eq!(first, again);
    }

    #[test]
    fn first_contact_ties_break_to_the_lowest_employee_id() {
        let allocations = [alloc(emp(9), POOL), alloc(emp(4), POOL)];
        let decision = route_inbound(&num(POOL), &num(SUPPLIER), &[], &allocations, at(100));
        assert_eq!(decision.employee(), Some(emp(4)));
    }

    #[test]
    fn contention_is_arbitrated_by_recency_not_by_row_order() {
        let allocations = [alloc(emp(1), POOL), alloc(emp(2), POOL)];
        let mut affinities = vec![
            affinity(POOL, SUPPLIER, emp(1), 0, 10),
            affinity(POOL, SUPPLIER, emp(2), 5, 90),
        ];

        for _ in 0..2 {
            affinities.rotate_left(1);
            match route_inbound(
                &num(POOL),
                &num(SUPPLIER),
                &affinities,
                &allocations,
                at(100),
            ) {
                RoutingDecision::Ambiguous {
                    affinity,
                    contended_with,
                } => {
                    assert_eq!(affinity.employee, emp(2), "most recent wins");
                    assert_eq!(contended_with, vec![emp(1)]);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn equal_recency_goes_to_the_older_relationship_then_the_lower_id() {
        let allocations = [
            alloc(emp(1), POOL),
            alloc(emp(2), POOL),
            alloc(emp(3), POOL),
        ];
        let affinities = [
            affinity(POOL, SUPPLIER, emp(3), 5, 90),
            // Same recency, older relationship.
            affinity(POOL, SUPPLIER, emp(2), 1, 90),
            affinity(POOL, SUPPLIER, emp(1), 7, 90),
        ];
        assert_eq!(
            route_inbound(
                &num(POOL),
                &num(SUPPLIER),
                &affinities,
                &allocations,
                at(100)
            )
            .employee(),
            Some(emp(2)),
        );

        // Every key equal: the id is the last, total tie-break.
        let dead_heat = [
            affinity(POOL, SUPPLIER, emp(3), 5, 90),
            affinity(POOL, SUPPLIER, emp(1), 5, 90),
        ];
        assert_eq!(
            route_inbound(
                &num(POOL),
                &num(SUPPLIER),
                &dead_heat,
                &allocations,
                at(100)
            )
            .employee(),
            Some(emp(1)),
        );
    }

    #[test]
    fn a_duplicated_row_for_one_employee_is_not_contention() {
        let allocations = [alloc(emp(1), POOL)];
        let affinities = [
            affinity(POOL, SUPPLIER, emp(1), 0, 10),
            affinity(POOL, SUPPLIER, emp(1), 0, 20),
        ];
        assert!(matches!(
            route_inbound(
                &num(POOL),
                &num(SUPPLIER),
                &affinities,
                &allocations,
                at(100)
            ),
            RoutingDecision::Established { .. }
        ));
    }

    #[test]
    fn a_number_nobody_is_allocated_to_is_a_misconfiguration_not_a_drop() {
        let allocations = [alloc(emp(1), "+33755000002")];
        let decision = route_inbound(
            &num(POOL),
            &num(SUPPLIER),
            &[affinity(POOL, SUPPLIER, emp(1), 0, 10)],
            &allocations,
            at(100),
        );
        assert_eq!(decision, RoutingDecision::Unallocated);
        assert_eq!(decision.employee(), None);
    }

    // -- allocation --------------------------------------------------------

    #[test]
    fn allocation_is_idempotent_per_region() {
        let pool = [pooled(POOL, 10), pooled("+33755000002", 10)];
        let existing = alloc(emp(1), "+33755000002");
        let got = allocate(
            emp(1),
            fr(),
            &pool,
            std::slice::from_ref(&existing),
            at(500),
        )
        .unwrap();
        assert_eq!(got, existing, "re-provisioning must not move a live number");
    }

    #[test]
    fn allocation_spreads_and_is_order_independent() {
        let mut pool = vec![pooled(POOL, 5), pooled("+33755000002", 5)];
        let allocations = [alloc(emp(1), POOL)];
        for _ in 0..2 {
            pool.rotate_left(1);
            let got = allocate(emp(2), fr(), &pool, &allocations, at(1)).unwrap();
            assert_eq!(got.number, num("+33755000002"));
        }

        // Equal load: lowest number wins.
        let empty = vec![pooled("+33755000002", 5), pooled(POOL, 5)];
        assert_eq!(
            allocate(emp(2), fr(), &empty, &[], at(1)).unwrap().number,
            num(POOL)
        );
    }

    #[test]
    fn capacity_cannot_be_exceeded() {
        let pool = [pooled(POOL, 2)];
        let mut allocations: Vec<Allocation> = Vec::new();
        for n in 1..=2 {
            allocations.push(allocate(emp(n), fr(), &pool, &allocations, at(n.into())).unwrap());
        }
        assert_eq!(allocations.len(), 2);

        let err = allocate(emp(3), fr(), &pool, &allocations, at(3)).unwrap_err();
        assert_eq!(
            err,
            PoolError::Full {
                region: fr(),
                numbers: 1,
                employees: 2
            }
        );
    }

    #[test]
    fn a_drained_number_takes_nobody_new() {
        let pool = [pooled(POOL, 0)];
        assert!(matches!(
            allocate(emp(1), fr(), &pool, &[], at(1)),
            Err(PoolError::Full { .. })
        ));
    }

    #[test]
    fn full_awaiting_and_empty_are_three_different_problems() {
        let reviewing = PoolNumber {
            state: BundleState::InReview {
                poll_ref: "BU123".into(),
                expected_by: at(9_000),
            },
            ..pooled(POOL, 5)
        };

        // Nothing bought: broken.
        assert_eq!(
            allocate(emp(1), fr(), &[], &[], at(1)).unwrap_err(),
            PoolError::Empty(fr())
        );
        // Bought, not approved: a wait, and it says how long.
        assert_eq!(
            allocate(emp(1), fr(), std::slice::from_ref(&reviewing), &[], at(1)).unwrap_err(),
            PoolError::AwaitingBundle {
                region: fr(),
                soonest: at(9_000)
            }
        );
        assert!(!reviewing.is_ready());
        assert!(!reviewing.overdue(at(8_999)));
        assert!(reviewing.overdue(at(9_001)));
        // Approved and full: buy another.
        assert!(matches!(
            allocate(
                emp(2),
                fr(),
                &[pooled(POOL, 1)],
                &[alloc(emp(1), POOL)],
                at(1)
            ),
            Err(PoolError::Full { .. })
        ));
    }

    #[test]
    fn another_regions_numbers_are_not_candidates() {
        let us = PoolNumber {
            number: num("+13105550100"),
            region: CountryCode::parse("US").unwrap(),
            ..pooled(POOL, 5)
        };
        assert_eq!(
            allocate(emp(1), fr(), &[us], &[], at(1)).unwrap_err(),
            PoolError::Empty(fr())
        );
    }

    #[test]
    fn strategy_round_trips() {
        for s in [NumberStrategy::Dedicated, NumberStrategy::Pooled] {
            assert_eq!(NumberStrategy::parse(s.as_str()), Some(s));
        }
        assert_eq!(NumberStrategy::parse("shared"), None);
    }

    // -- purity ------------------------------------------------------------

    proptest! {
        /// Routing is a function of the *set* of rows, never of their order:
        /// any permutation of the inputs yields the identical decision.
        #[test]
        fn routing_is_a_pure_function_of_its_inputs(
            rows in prop::collection::vec((1u8..=4, 0i64..50, 0i64..50, 0u8..3), 0..12),
            allocated in prop::collection::vec(1u8..=4, 0..5),
            rot in 0usize..12,
        ) {
            let counterparties = ["+33612345678", "+33698765432", "+33600000000"];
            let allocations: Vec<Allocation> =
                allocated.iter().map(|e| alloc(emp(*e), POOL)).collect();
            let affinities: Vec<CounterpartyAffinity> = rows
                .iter()
                .map(|(e, est, used, cp)| {
                    affinity(POOL, counterparties[usize::from(*cp)], emp(*e), *est, *est + *used)
                })
                .collect();

            let expected = route_inbound(
                &num(POOL), &num(SUPPLIER), &affinities, &allocations, at(100),
            );

            let mut shuffled = affinities.clone();
            let len = shuffled.len();
            if len > 0 {
                shuffled.rotate_left(rot % len);
                shuffled.reverse();
            }
            let mut allocs = allocations.clone();
            allocs.reverse();

            prop_assert_eq!(
                route_inbound(&num(POOL), &num(SUPPLIER), &shuffled, &allocs, at(100)),
                expected
            );
        }
    }
}
