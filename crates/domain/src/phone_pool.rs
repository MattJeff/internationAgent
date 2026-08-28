//! Which way a deployment gets numbers for its employees.
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
//! # Why the pool's own rules are not in this crate
//!
//! They used to be: this module carried `PoolNumber`, `Allocation`,
//! `CounterpartyAffinity`, `PoolError`, and pure `allocate` / `route_inbound`
//! functions over slices of them, with a proptest asserting the decisions did
//! not depend on row order. Nothing outside `#[cfg(test)]` ever called any of
//! it, and the reason is structural rather than an oversight: **both decisions
//! have to be atomic against concurrent workers, so both are made by the
//! database.**
//!
//! * Allocation is `agentos_store::phone_pool::allocate_atomic`, whose
//!   `number_allocations_live_employee_region_key` refuses a second live seat
//!   even to a worker that raced past a pure check. A `Vec<Allocation>` read a
//!   moment earlier cannot make that promise.
//! * Inbound routing is `agentos_app::inbound::resolve_phone_recipient`, one
//!   `ORDER BY` over `employee_resources` joined to `conversations`. The
//!   affinity it reads is the `conversations` row the landing transaction has
//!   already written, so there is no second table to keep in step — which is
//!   the other half of why the pure version never shipped. (That lander is
//!   itself waiting on a telephony ingest; see its own NOT WIRED note. It is
//!   still the one the pool's routing goes through.)
//!
//! The pure functions were deleted along with a `counterparty_affinity` table
//! nothing writes. Their arguments live on where the shipped code makes the
//! same decisions; the tie-breaks are documented on
//! `resolve_phone_recipient` and on `allocate_atomic`.

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_round_trips() {
        for s in [NumberStrategy::Dedicated, NumberStrategy::Pooled] {
            assert_eq!(NumberStrategy::parse(s.as_str()), Some(s));
        }
        assert_eq!(NumberStrategy::parse("shared"), None);
    }
}
