//! Pooled phone numbers: the slot an employee occupies, giving it back, and
//! the two questions an operator asks about the pool.
//!
//! # Why a pool
//!
//! `Step::Phone` buys one number per employee. In France that is one regulated
//! bundle per employee — a French address and a proof of address under three
//! months, reviewed by a human — so onboarding a hundred employees means a
//! hundred human reviews. That cost is the same at Twilio, at Telnyx and
//! anywhere else, because it is the regulator's cost and not the vendor's. A
//! tenant that owns five numbers and routes a hundred employees over them pays
//! it five times.
//!
//! So a pooled number is **owned by the tenant**, and an employee is
//! *allocated* onto it. Both models stay: a US number needs no bundle and a
//! dedicated identity is better there. Pooling is a strategy, not a
//! replacement, and both satisfy the same contract — a `phone` resource that is
//! `Ready` with a binding, released idempotently on termination.
//!
//! # The pattern is `Step::Whatsapp`, generalised
//!
//! One verified company WhatsApp sender already carries many employees
//! (`provisioning.rs`, `WHATSAPP_ROUTING`), and its routing address carries the
//! employee id so that two employees on one sender cannot collide on
//! `employee_resources`' unique `(provider, external_id)` index. A pooled slot
//! is spelled the same way, for the same reason, and gains a second one:
//!
//! ```text
//! provider    = "phone-pool"
//! external_id = "+33757590001/018f2c…-employee-uuid"
//! ```
//!
//! **That encoding is what makes releasing a slot safe.** `release_step` hands
//! `external_id` straight to `TelephonyProvider::release`, which is
//! `DELETE IncomingPhoneNumbers/{sid}` — and the one thing this unit must never
//! do is delete a number four colleagues are still working on. A slot's
//! external id is not a sid and can never name one, so the delete cannot
//! resolve; and `ProvisioningEngine::release_step`, which is the path a
//! termination actually takes, short-circuits the provider call entirely for a
//! binding [`is_pooled`] answers for. The number is the tenant's property, and
//! no employee leaving is an instruction to give it back.
//!
//! This module used to carry a second releaser, `release_slot`, saying the same
//! thing one level up. Nothing outside `#[cfg(test)]` ever called it — the
//! engine's own path both frees the `number_allocations` row and clears the
//! binding in one commit, which `release_slot` could not do because it never
//! knew the region — so it is gone rather than kept as a plausible-looking
//! alternative for somebody to wire by mistake.
//!
//! # Where the pool itself is written down
//!
//! In `phone_numbers`, the table `0010_phone_pool.sql` created for it, read by
//! [`numbers`]. **Not in configuration and not in this process's memory**: the
//! numbers a tenant owns are a per-tenant fact, and a per-tenant fact behind a
//! deploy is a fact one replica can hold a stale copy of. Reading it inside the
//! request's own [`TenantTx`] costs one indexed query over five to ten rows and
//! removes the staleness question instead of answering it.
//!
//! Do not confuse the two tables this module touches. `phone_numbers` is what
//! an **operator** put in the shared pool — the tenant owns it. A number
//! `Step::Phone` bought for one employee lives in `employee_resources` under
//! the provider that sold it, and is that employee's alone. `employee_resources`
//! rows with `provider = "phone-pool"` are the third thing: a *seat* on a number
//! from the first table, which is what [`occupancy`] counts.
//!
//! # Inbound routing is not here
//!
//! A supplier texts the shared number. Which employee gets it? The one that
//! supplier has been talking to, always: since wave 8 an employee holds trust
//! links, learned expectations and beliefs with provenance about *that*
//! counterparty ([`agentos_domain::psyche`]), and a colleague holds none of
//! them. Routing the supplier elsewhere silently throws the relationship away.
//!
//! That rule lives in [`crate::inbound::resolve_phone_recipient`], which is what
//! [`crate::inbound::land_inbound_text`] calls — read that function's own
//! NOT WIRED note before assuming a message reaches either of them today. This
//! module had a `route_inbound` of its own that said the same thing and that
//! nothing outside `#[cfg(test)]` ever called, not even the lander. It was not
//! merely redundant — it was **narrower**: two queries instead of one,
//! `step = 'phone'` hard-coded so a pooled WhatsApp slot could not route at all,
//! `provider = 'phone-pool'` so a dedicated number could not either, and no
//! `state = 'ready'` filter, so a released slot still counted. It is deleted;
//! the argument for the tie-breaks lives on `resolve_phone_recipient`.
//!
//! What is left here is the operator's view of the same fact: [`affinities`]
//! lists who currently holds which counterparty on which number, including the
//! rows that are no longer routable, and [`reassign`] moves one deliberately.

use std::collections::BTreeMap;

use agentos_domain::action::E164;
use agentos_domain::employee::ProviderBinding;
use agentos_domain::ids::EmployeeId;
use agentos_domain::message::Channel;
use agentos_store::db::{StoreError, TenantTx};
// The pool's own storage. Re-exported rather than restated so a caller that
// registers a number and a caller that lists one share one vocabulary.
pub use agentos_store::phone_pool::{NewNumber, NumberState, register};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

// The server crate deliberately cannot name `agentos-providers`, and a pooled
// number has a region for the same reason a bought one does. Re-exported here
// rather than restated, so there is one `Region` in the workspace.
pub use agentos_providers::telephony::Region;

/// Provider name on a pooled slot binding.
///
/// Deliberately not [`agentos_providers::telephony::PROVIDER`]: a slot is not a
/// resource at Twilio, it is a routing fact about a number that already exists.
/// Anything that treats this string as a sid — a release, a reconcile, a
/// billing export — finds a value that cannot be one.
pub const PHONE_POOL: &str = "phone-pool";

/// Separates the number from the employee id inside a slot's external id.
const SLOT_SEP: char = '/';

/// The two channels that ride a phone number. `voice` has no
/// [`agentos_domain::message::CanonicalMessage`] yet, so it has no conversation
/// row to carry an affinity.
const PHONE_CHANNELS: [&str; 2] = [Channel::Sms.as_str(), Channel::Whatsapp.as_str()];

// ---------------------------------------------------------------------------
// The slot binding
// ---------------------------------------------------------------------------

/// The binding an allocated employee holds for its pooled number.
///
/// `"+33757590001/018f…"`. The employee id is in there so that ten employees on
/// one number are ten distinct rows under
/// `employee_resources_provider_external_id_key`, and so that no slot's
/// external id can ever be mistaken for the number's own provider id.
pub fn slot_binding(number: &E164, employee_id: EmployeeId) -> ProviderBinding {
    ProviderBinding::new(
        PHONE_POOL,
        format!("{}{SLOT_SEP}{}", number.as_str(), employee_id.as_uuid()),
    )
}

/// Is this `phone` binding a pooled slot, or a number of this employee's own?
pub fn is_pooled(binding: &ProviderBinding) -> bool {
    binding.provider() == PHONE_POOL
}

/// The number half of a slot's external id, or `None` if it is not one.
///
/// Only `#[cfg(test)]` reads it, and deliberately: it is [`slot_binding`]'s
/// inverse, and the encoding test at the bottom of this file is what proves the
/// two agree. Production never needs to take a slot id apart — the SQL that
/// wants the number half spells `split_part(external_id, '/', 1)` inline,
/// because it needs it as a column and not as a value. Delete both halves of
/// the round trip together, or neither.
pub fn slot_number(binding: &ProviderBinding) -> Option<E164> {
    if !is_pooled(binding) {
        return None;
    }
    let (number, _) = binding.external_id().split_once(SLOT_SEP)?;
    E164::parse(number).ok()
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// Whether a number needed a regulatory bundle, and where that bundle got to.
///
/// The state an operator is actually asking about when they open the pool page:
/// a number sitting in [`Regulatory::Pending`] is a number nobody can be
/// allocated to yet, and the reason a French rollout is stuck.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "regulatory", rename_all = "snake_case")]
pub enum Regulatory {
    /// The region sells numbers with no bundle at all — US, CA.
    NotRequired,
    /// A bundle was approved and this number rests on it. One bundle serves
    /// every number in the pool, which is the entire point of the pool.
    Approved {
        /// The provider's bundle id, for the operator to look up.
        bundle: String,
    },
    /// Filed and waiting on a human at the regulator. No number is buyable in
    /// this region until it clears, and none should be advertised as usable.
    Pending {
        /// The provider's bundle id, for the operator to chase.
        bundle: String,
    },
}

/// One number the tenant owns and routes employees over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolNumber {
    number: E164,
    region: Region,
    state: NumberState,
    regulatory: Regulatory,
    capacity: u32,
}

impl PoolNumber {
    /// Declare a number. `region` is an ISO 3166-1 alpha-2 country.
    ///
    /// `capacity` is a real operational limit, not a formality: a shared number
    /// carries a shared rate limit and a shared reputation at the carrier, and
    /// an operator who puts sixty employees on one DID discovers both at once.
    pub fn new(number: E164, region: &str, capacity: u32) -> Self {
        Self {
            number,
            region: Region::new(region),
            state: NumberState::Active,
            regulatory: Regulatory::NotRequired,
            capacity,
        }
    }

    /// The number itself.
    pub const fn number(&self) -> &E164 {
        &self.number
    }

    /// The country it was bought in, e.g. `FR`.
    pub fn region_str(&self) -> &str {
        self.region.as_str()
    }

    /// Where the number is in its regulatory life.
    ///
    /// The field that decides whether an employee can be put on it *today*, and
    /// it is not the same question as [`PoolNumber::regulatory`]: a number can
    /// rest on an approved bundle and still be [`NumberState::Suspended`]
    /// because somebody is draining it before giving it back.
    pub const fn state(&self) -> NumberState {
        self.state
    }

    /// Whether an employee can be allocated onto it right now.
    pub fn allocatable(&self) -> bool {
        self.state == NumberState::Active
    }

    /// Its regulatory standing.
    pub const fn regulatory(&self) -> &Regulatory {
        &self.regulatory
    }

    /// How many employees may share it.
    pub const fn capacity(&self) -> u32 {
        self.capacity
    }
}

/// Every number **this** tenant owns, lowest number first.
///
/// The tenant is the transaction's, never an argument: `TenantTx` has already
/// set `app.tenant_id`, so RLS is what scopes this and there is no predicate
/// here for anybody to forget. That is also why one tenant cannot name
/// another's number through `/v1/pool/numbers/{id}` — the row is not merely
/// unlisted, it is invisible.
///
/// `released` numbers are left out: they went back to the provider and are not
/// the tenant's any more. `suspended` ones stay, because they are still owned,
/// still billed, and still carrying the employees already on them — a pool page
/// that hid them would hide the reason a rollout is stuck.
pub async fn numbers(tx: &mut TenantTx<'_>) -> Result<Vec<PoolNumber>, StoreError> {
    let rows: Vec<(String, String, String, i32, Option<String>)> = sqlx::query_as(
        "SELECT e164, region, state, capacity, bundle_ref \
           FROM phone_numbers \
          WHERE state <> 'released' \
          ORDER BY e164",
    )
    .fetch_all(&mut ***tx)
    .await?;

    rows.into_iter()
        .map(|(e164, region, state, capacity, bundle_ref)| {
            let number = E164::parse(&e164)
                .map_err(|err| StoreError::Database(sqlx::Error::Decode(Box::new(err))))?;
            // `phone_numbers_state_check` makes the fallback unreachable; a row
            // that got past it is corrupt, and reading it as suspended keeps an
            // unknown state out of the allocatable set rather than into it.
            let state = NumberState::parse(&state).unwrap_or(NumberState::Suspended);
            Ok(PoolNumber {
                number,
                region: Region::new(&region),
                state,
                regulatory: regulatory_of(state, bundle_ref),
                // `phone_numbers_capacity_positive` makes the fallback
                // unreachable; zero is the drained reading, which takes nobody
                // new, and is the safe way to misread a corrupt row.
                capacity: u32::try_from(capacity).unwrap_or(0),
            })
        })
        .collect()
}

/// What `state` and `bundle_ref` together say about the paperwork.
///
/// No bundle recorded means the region sold the number without one — US, CA —
/// which is [`Regulatory::NotRequired`] and not a missing field. A bundle plus
/// any state short of `active` is a bundle nobody has cleared yet.
fn regulatory_of(state: NumberState, bundle_ref: Option<String>) -> Regulatory {
    match bundle_ref {
        None => Regulatory::NotRequired,
        Some(bundle) if state == NumberState::Active => Regulatory::Approved { bundle },
        Some(bundle) => Regulatory::Pending { bundle },
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a pool operation did not happen.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// The database said no.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// The employee named does not hold a slot on that number, so routing a
    /// counterparty to it would route to a number the employee cannot send
    /// from. Refused rather than allocated-on-the-fly: allocation is
    /// provisioning's job and it costs a `Ready` resource row.
    #[error("employee is not allocated to that pooled number")]
    NotAllocated,

    /// Nothing currently reaches that counterparty on that number, so there is
    /// no affinity to move. See [`reassign`] on why one is not invented.
    #[error("no affinity for that counterparty on that number")]
    NoAffinity,
}

// ---------------------------------------------------------------------------
// Occupancy
// ---------------------------------------------------------------------------

/// One employee allocated to a pooled number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Occupant {
    /// The employee holding the slot.
    pub employee_id: Uuid,
    /// The handle an operator recognises.
    pub slug: String,
    /// `active`, `suspended`, `terminated`. A slot held by a non-active
    /// employee is capacity that is spent but not working.
    pub lifecycle: String,
}

/// Who is on each pooled number, keyed by the number.
///
/// One query for the whole tenant: a pool is a handful of numbers and grouping
/// in memory beats a round trip per number. Numbers with nobody on them do not
/// appear — they are in the [`Pool`] with an empty entry, which is exactly how
/// the endpoint can show a number that has lost its last employee and is still
/// the tenant's.
pub async fn occupancy(
    tx: &mut TenantTx<'_>,
) -> Result<BTreeMap<String, Vec<Occupant>>, StoreError> {
    // No `WHERE tenant_id`: RLS adds it, and a hand-written copy is a second
    // place for it to be forgotten.
    let rows: Vec<(String, Uuid, String, String)> = sqlx::query_as(
        "SELECT split_part(r.external_id, $2, 1) AS number, r.employee_id, e.slug, e.lifecycle \
           FROM employee_resources r \
           JOIN employees e ON e.id = r.employee_id \
          WHERE r.step = 'phone' AND r.provider = $1 AND r.external_id IS NOT NULL \
          ORDER BY number, e.slug",
    )
    .bind(PHONE_POOL)
    .bind(SLOT_SEP.to_string())
    .fetch_all(&mut ***tx)
    .await?;

    let mut by_number: BTreeMap<String, Vec<Occupant>> = BTreeMap::new();
    for (number, employee_id, slug, lifecycle) in rows {
        by_number.entry(number).or_default().push(Occupant {
            employee_id,
            slug,
            lifecycle,
        });
    }
    Ok(by_number)
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Who a counterparty currently reaches, and on which number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Affinity {
    /// The `conversations` row this is read from. Also the page cursor.
    pub conversation_id: Uuid,
    /// The pooled number the owning employee is allocated to.
    pub number: String,
    /// The supplier, as `conversations.external_ref` holds it.
    pub counterparty: String,
    /// `sms` or `whatsapp`.
    pub channel: String,
    /// Who it reaches.
    pub employee_id: Uuid,
    /// Who it reaches, readably.
    pub employee_slug: String,
    /// That employee's lifecycle.
    pub employee_lifecycle: String,
    /// **Whether a message arriving now would actually land here.** False for a
    /// suspended or terminated employee: the affinity is kept as the record of
    /// the relationship, but nothing routes to somebody who cannot answer, and
    /// a `false` here is an operator's cue to [`reassign`] it.
    pub routable: bool,
    /// When the relationship started.
    pub since: DateTime<Utc>,
    /// When it was last alive.
    pub last_message_at: Option<DateTime<Utc>>,
}

/// One affinity row in SELECT order: conversation id, number, counterparty,
/// channel, employee id, slug, lifecycle, created_at, last_message_at.
type AffinityRow = (
    Uuid,
    String,
    String,
    String,
    Uuid,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

/// Every counterparty→employee affinity on this tenant's pooled numbers.
///
/// Keyset over the conversation id — a v7 uuid, so the order is total and
/// insertions land in their own place rather than shifting a page boundary
/// under a client that is walking the list.
pub async fn affinities(
    tx: &mut TenantTx<'_>,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<Affinity>, StoreError> {
    let rows: Vec<AffinityRow> = sqlx::query_as(
        "SELECT c.id, split_part(r.external_id, $2, 1) AS number, c.external_ref, c.channel, \
                c.employee_id, e.slug, e.lifecycle, c.created_at, c.last_message_at \
           FROM conversations c \
           JOIN employees e ON e.id = c.employee_id \
           JOIN employee_resources r \
             ON r.employee_id = c.employee_id AND r.step = 'phone' \
          WHERE c.channel = ANY($1) \
            AND c.external_ref IS NOT NULL \
            AND r.provider = $3 \
            AND ($4::uuid IS NULL OR c.id > $4::uuid) \
          ORDER BY c.id \
          LIMIT $5",
    )
    .bind(PHONE_CHANNELS.as_slice())
    .bind(SLOT_SEP.to_string())
    .bind(PHONE_POOL)
    .bind(after)
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                conversation_id,
                number,
                counterparty,
                channel,
                employee_id,
                employee_slug,
                employee_lifecycle,
                since,
                last_message_at,
            )| Affinity {
                conversation_id,
                number,
                counterparty,
                channel,
                employee_id,
                employee_slug,
                routable: employee_lifecycle == "active",
                employee_lifecycle,
                since,
                last_message_at,
            },
        )
        .collect())
}

/// What a reassignment moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reassigned {
    /// The conversations that changed hands. More than one when two employees
    /// were both talking to this supplier — the ambiguity the arbitration rule
    /// papered over, now resolved on purpose.
    pub conversations: Vec<Uuid>,
    /// Who held them before. Empty is impossible: [`PoolError::NoAffinity`]
    /// comes first.
    pub from: Vec<Uuid>,
}

/// Point a counterparty at a different employee, deliberately.
///
/// # Why this moves the rows rather than adding one
///
/// Affinity is decided by the *oldest* conversation, so writing a new
/// conversation for the new owner would lose to the old one and the
/// reassignment would silently not take effect. Moving `conversations.employee_id`
/// moves the relationship itself, thread and history together, and the same
/// arbitration query then answers with the new owner. `messages.employee_id` is
/// left alone: who actually sent each message is a fact, and rewriting it would
/// forge the record.
///
/// Every conversation this counterparty holds with any slot holder on `number`
/// moves, so the ambiguous case — two employees, one supplier, one number —
/// ends up unambiguous instead of half-moved.
///
/// # What does not move
///
/// The psyche. Trust links, expectations and beliefs are keyed by employee and
/// stay with the employee that earned them, so a reassignment hands the new
/// owner the conversation and none of the accumulated judgement about the
/// counterparty. That is the real cost of this endpoint and the reason it is a
/// gated, audited action rather than a routing heuristic that could fire on its
/// own.
///
/// The caller must hold an `Authorized<Action>` before calling this — the HTTP
/// route is where the gate is consulted, in the same shape as
/// `routes/approvals.rs`.
pub async fn reassign(
    tx: &mut TenantTx<'_>,
    number: &E164,
    counterparty: &str,
    to: EmployeeId,
    now: DateTime<Utc>,
) -> Result<Reassigned, PoolError> {
    // The target must already be on this number. Otherwise the supplier reaches
    // an employee that cannot reply from the number they dialled.
    let allocated: Option<Uuid> = sqlx::query_scalar(
        "SELECT employee_id FROM employee_resources \
          WHERE employee_id = $1 AND step = 'phone' AND provider = $2 \
            AND external_id = $3 || $4 || $1::text",
    )
    .bind(to.as_uuid())
    .bind(PHONE_POOL)
    .bind(number.as_str())
    .bind(SLOT_SEP.to_string())
    .fetch_optional(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    if allocated.is_none() {
        return Err(PoolError::NotAllocated);
    }

    let moved: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE conversations c \
            SET employee_id = $1, updated_at = $5 \
           FROM employee_resources r \
          WHERE r.employee_id = c.employee_id \
            AND r.step = 'phone' AND r.provider = $2 \
            AND split_part(r.external_id, $6, 1) = $3 \
            AND c.external_ref = $4 \
            AND c.channel = ANY($7) \
            AND c.employee_id <> $1 \
        RETURNING c.id, r.employee_id",
    )
    .bind(to.as_uuid())
    .bind(PHONE_POOL)
    .bind(number.as_str())
    .bind(counterparty)
    .bind(now)
    .bind(SLOT_SEP.to_string())
    .bind(PHONE_CHANNELS.as_slice())
    .fetch_all(&mut ***tx)
    .await
    .map_err(StoreError::from)?;

    if moved.is_empty() {
        // Either nobody talks to this counterparty on this number, or the
        // target already owns every such thread. The second is not an error to
        // the caller's intent, but it is not a change either, and a route that
        // reports "moved 0" as success is a route that hides a typo'd number.
        return Err(PoolError::NoAffinity);
    }

    let mut from: Vec<Uuid> = moved.iter().map(|(_, owner)| *owner).collect();
    from.sort_unstable();
    from.dedup();
    Ok(Reassigned {
        conversations: moved.into_iter().map(|(id, _)| id).collect(),
        from,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::action::Domain;
    use agentos_domain::employee::{Employee, ResourceState, Step};
    use agentos_domain::ids::{Slug, TenantId};
    use agentos_store::db::Db;
    use agentos_store::employee as employee_store;

    use super::*;

    const NUMBER: &str = "+33757590001";
    const SUPPLIER: &str = "+33612345678";

    /// Put a number in the tenant's shared pool, the way the operator route
    /// does. `external_id` is unique per call because
    /// `phone_numbers_provider_external_id_key` is global and these tests share
    /// a database with every previous run.
    async fn add_pool_number(db: &Db, tenant: TenantId, e164: &str, capacity: i32) {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        register(
            &mut tx,
            &NewNumber {
                provider: "twilio".to_owned(),
                external_id: format!("PN-pool-{}", Uuid::now_v7()),
                e164: E164::parse(e164).expect("e164"),
                region: "FR".to_owned(),
                state: NumberState::Active,
                capacity,
                bundle_ref: Some("BU-fr-1".to_owned()),
            },
            Utc::now(),
        )
        .await
        .expect("register");
        tx.commit().await.expect("commit");
    }

    /// Real Postgres or nothing: every claim here is about rows.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; pool_ops needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'pool-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    fn number() -> E164 {
        E164::parse(NUMBER).expect("e164")
    }

    /// An active employee holding a pooled slot on [`NUMBER`].
    ///
    /// Built through the domain rather than as raw SQL: `employee_store::load`
    /// insists on all eleven resource rows, and the aggregate is what puts them
    /// there.
    async fn allocate(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let now = Utc::now();
        let id = EmployeeId::new_v7(now);
        let mut employee = Employee::new(
            id,
            tenant,
            Slug::parse(slug).expect("slug"),
            Domain::parse("agents.example.com").expect("domain"),
            now,
        );
        employee
            .set_lifecycle(agentos_domain::employee::Lifecycle::Active, now)
            .expect("activate");
        employee
            .bind(Step::Phone, slot_binding(&number(), id), now)
            .expect("bind slot");
        employee
            .set_resource(Step::Identity, ResourceState::Provisioning, now)
            .and_then(|()| employee.set_resource(Step::Identity, ResourceState::Ready, now))
            .expect("identity ready");
        employee
            .set_resource(Step::Phone, ResourceState::Provisioning, now)
            .and_then(|()| employee.set_resource(Step::Phone, ResourceState::Ready, now))
            .expect("phone ready");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        employee_store::insert(&mut tx, &employee)
            .await
            .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    async fn terminate(db: &Db, tenant: TenantId, id: EmployeeId) {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        sqlx::query("UPDATE employees SET lifecycle = 'terminated' WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&mut **tx)
            .await
            .expect("terminate");
        tx.commit().await.expect("commit");
    }

    /// A conversation with `SUPPLIER`, created `age_seconds` ago.
    async fn talk(db: &Db, tenant: TenantId, employee: EmployeeId, age_seconds: i64) -> Uuid {
        let id = Uuid::now_v7();
        let when = Utc::now() - chrono::TimeDelta::seconds(age_seconds);
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO conversations \
                 (id, tenant_id, employee_id, channel, external_ref, created_at, updated_at) \
             VALUES ($1, $2, $3, 'sms', $4, $5, $5)",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid())
        .bind(SUPPLIER)
        .bind(when)
        .execute(&mut **tx)
        .await
        .expect("insert conversation");
        tx.commit().await.expect("commit");
        id
    }

    /// Who a conversation row belongs to now. The thread *is* the routing, so
    /// this is what a reassignment has to have changed.
    async fn owner_of(db: &Db, tenant: TenantId, conversation: Uuid) -> Uuid {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let owner: Uuid = sqlx::query_scalar("SELECT employee_id FROM conversations WHERE id = $1")
            .bind(conversation)
            .fetch_one(&mut **tx)
            .await
            .expect("owner");
        tx.rollback().await.expect("rollback");
        owner
    }

    // -- the encoding ------------------------------------------------------

    /// Two employees on one number are two distinct external ids, so the
    /// unique index does not collide them — and neither half can be read as a
    /// provider sid.
    #[test]
    fn a_slot_id_carries_the_employee_and_is_not_a_sid() {
        let now = Utc::now();
        let (a, b) = (EmployeeId::new_v7(now), EmployeeId::new_v7(now));
        let (left, right) = (slot_binding(&number(), a), slot_binding(&number(), b));

        assert_ne!(left.external_id(), right.external_id());
        assert_eq!(slot_number(&left).as_ref(), Some(&number()));
        assert_eq!(slot_number(&right).as_ref(), Some(&number()));
        assert!(is_pooled(&left));

        // A Twilio sid is `PN` + 32 hex. A slot id cannot be mistaken for one,
        // which is what makes a stray `release` a 404 instead of a deletion.
        assert!(left.external_id().starts_with('+'));
        assert!(left.external_id().contains(SLOT_SEP));

        let dedicated = ProviderBinding::new("twilio", "PN0000000000000001");
        assert!(!is_pooled(&dedicated));
        assert_eq!(slot_number(&dedicated), None);
    }

    /// The load is a per-tenant read, and it is RLS that scopes it: the same
    /// E.164 registered by two tenants is two rows, and neither sees the other's.
    #[tokio::test]
    async fn the_pool_load_is_scoped_by_the_transactions_tenant() {
        let Some(db) = db().await else { return };
        let (mine, theirs) = (new_tenant(&db).await, new_tenant(&db).await);
        add_pool_number(&db, mine, NUMBER, 10).await;
        add_pool_number(&db, mine, "+33757590002", 5).await;
        add_pool_number(&db, theirs, NUMBER, 1).await;

        let mut tx = db.tenant_tx(mine).await.expect("tx");
        let ours = numbers(&mut tx).await.expect("numbers");
        tx.rollback().await.expect("rollback");
        // Lowest number first, and only ours.
        assert_eq!(
            ours.iter().map(PoolNumber::capacity).collect::<Vec<_>>(),
            vec![10, 5]
        );

        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        let hers = numbers(&mut tx).await.expect("numbers");
        tx.rollback().await.expect("rollback");
        assert_eq!(hers.len(), 1, "another tenant's numbers leaked: {hers:?}");
        assert_eq!(hers[0].capacity(), 1);
    }

    /// A number given back is not the tenant's; one being drained still is.
    #[tokio::test]
    async fn a_released_number_leaves_the_pool_and_a_suspended_one_does_not() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        add_pool_number(&db, tenant, NUMBER, 10).await;
        add_pool_number(&db, tenant, "+33757590002", 10).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let ids: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, e164 FROM phone_numbers ORDER BY e164")
                .fetch_all(&mut **tx)
                .await
                .expect("ids");
        for (id, e164) in &ids {
            let state = if e164 == NUMBER {
                NumberState::Suspended
            } else {
                NumberState::Released
            };
            agentos_store::phone_pool::set_state(&mut tx, *id, state, Utc::now())
                .await
                .expect("set state");
        }
        let pool = numbers(&mut tx).await.expect("numbers");
        tx.rollback().await.expect("rollback");

        assert_eq!(pool.len(), 1, "{pool:?}");
        assert_eq!(pool[0].number().as_str(), NUMBER);
        assert_eq!(pool[0].state(), NumberState::Suspended);
        assert!(
            !pool[0].allocatable(),
            "a number being drained still takes new employees"
        );
        // Still bought, still not cleared: the bundle reads as pending again.
        assert_eq!(
            pool[0].regulatory(),
            &Regulatory::Pending {
                bundle: "BU-fr-1".to_owned()
            }
        );
    }

    // -- affinity, as an operator sees it -----------------------------------

    /// Where an inbound message *lands* is `inbound::resolve_phone_recipient`'s
    /// question and it has its own test. This one is about the other half: the
    /// row an operator has to look at afterwards. A terminated employee's
    /// affinity is kept — it is the record of who knew whom, and the input to
    /// every handover decision — and it reads as un-routable, which is the
    /// prompt to hand it over deliberately rather than let it rot.
    #[tokio::test]
    async fn a_terminated_employees_affinity_is_kept_and_reads_as_un_routable() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = allocate(&db, tenant, "lena").await;
        talk(&db, tenant, lena, 365 * 24 * 3600).await;

        terminate(&db, tenant, lena).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let rows = affinities(&mut tx, None, 50).await.expect("affinities");
        tx.rollback().await.expect("rollback");

        let orphaned = rows
            .iter()
            .find(|row| row.employee_id == lena.as_uuid())
            .expect("the terminated employee's affinity was deleted");
        assert!(
            !orphaned.routable,
            "a terminated employee reads as routable"
        );
        assert_eq!(orphaned.number, NUMBER);
        assert_eq!(orphaned.counterparty, SUPPLIER);
    }

    /// Reassigning moves the thread itself, and there is nothing left to move
    /// the second time.
    #[tokio::test]
    async fn a_reassignment_moves_the_thread_and_only_once() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = allocate(&db, tenant, "lena").await;
        let alex = allocate(&db, tenant, "alex").await;
        let held = talk(&db, tenant, lena, 90 * 24 * 3600).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let moved = reassign(&mut tx, &number(), SUPPLIER, alex, Utc::now())
            .await
            .expect("reassign");
        tx.commit().await.expect("commit");

        assert_eq!(moved.conversations, vec![held], "the thread did not move");
        assert_eq!(moved.from, vec![lena.as_uuid()]);
        // The thread *is* the routing — `resolve_phone_recipient` reads
        // `conversations.employee_id` — so moving the row is what makes the next
        // message land on Alex, and this is the row.
        assert_eq!(owner_of(&db, tenant, held).await, alex.as_uuid());

        // Nothing left to move the second time: the endpoint says so rather
        // than reporting a successful no-op.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let repeat = reassign(&mut tx, &number(), SUPPLIER, alex, Utc::now()).await;
        tx.rollback().await.expect("rollback");
        assert!(matches!(repeat, Err(PoolError::NoAffinity)), "{repeat:?}");
    }

    /// An employee that is not on the number cannot be given its suppliers.
    #[tokio::test]
    async fn reassigning_to_an_employee_off_the_number_is_refused() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let lena = allocate(&db, tenant, "lena").await;
        let outsider = allocate(&db, tenant, "mira").await;
        let held = talk(&db, tenant, lena, 3600).await;

        // Mira is taken off the number, so she is no longer reachable on it.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        sqlx::query("DELETE FROM employee_resources WHERE employee_id = $1 AND step = 'phone'")
            .bind(outsider.as_uuid())
            .execute(&mut **tx)
            .await
            .expect("take mira off the number");
        let refused = reassign(&mut tx, &number(), SUPPLIER, outsider, Utc::now()).await;
        tx.commit().await.expect("commit");

        assert!(
            matches!(refused, Err(PoolError::NotAllocated)),
            "{refused:?}"
        );
        assert_eq!(
            owner_of(&db, tenant, held).await,
            lena.as_uuid(),
            "a refused reassignment moved something"
        );
    }

    /// RLS, not a `WHERE` clause we might forget: another tenant's slots and
    /// affinities are not merely unlisted, they are invisible.
    #[tokio::test]
    async fn one_tenants_pool_is_invisible_to_another() {
        let Some(db) = db().await else { return };
        let (mine, theirs) = (new_tenant(&db).await, new_tenant(&db).await);
        let ours = allocate(&db, mine, "lena").await;
        let hers = allocate(&db, theirs, "raj").await;
        talk(&db, mine, ours, 60).await;
        talk(&db, theirs, hers, 60).await;

        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        let seats = occupancy(&mut tx).await.expect("occupancy");
        let rows = affinities(&mut tx, None, 50).await.expect("affinities");
        tx.rollback().await.expect("rollback");

        assert_eq!(seats[NUMBER].len(), 1);
        assert_eq!(seats[NUMBER][0].employee_id, hers.as_uuid());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].employee_id, hers.as_uuid());
    }
}
