//! The daily cold-outreach budget: how many strangers an employee may reach.
//!
//! The third of this workspace's three daily ceilings, and the last one to get a
//! ledger. [`crate::turns`] bounds how often an employee acts; [`crate::spend`]
//! bounds what it may pay; this bounds whose inbox it may arrive in for the
//! first time. It is the one of the three an operator answers for in front of a
//! supervisory authority, which is why it is the one that could least afford to
//! be counted rather than reserved.
//!
//! # What it fixes, and it was two things
//!
//! Both were reproduced deterministically before this module existed —
//! `0055_outreach_budget.sql` writes them out, and the tests below hold them
//! open by hand rather than racing a scheduler.
//!
//! * `app::gate::PolicyGate::contacts` reads the day's count as an **unlocked
//!   aggregate over `audit_log`**, and the write that follows it is
//!   `audit::append` — an INSERT into an append-only log with no unique index
//!   and no counter row. Two decisions read `1 of 2`, both are allowed, both
//!   append: three strangers on a ceiling of two.
//! * `routes::queue::export` never reaches the gate on the file path. Its
//!   counter is `revenue::contacted_since`, read unlocked, and the selection
//!   under it takes `FOR UPDATE OF c SKIP LOCKED` — so two exports get
//!   **disjoint** prospects, neither ever blocks, and both take the whole day.
//!
//! Neither counter can be locked: an aggregate over an append-only log has no
//! row to lock, and neither does a `count(*)` over `contacts`. A counter row is
//! the only shape that serialises them, and [`reserve`] is that row's one verb.
//!
//! # Reserved, not counted, and the shape is [`crate::turns`]'s
//!
//! `INSERT … ON CONFLICT DO UPDATE SET contacts_taken = outreach_buckets
//! .contacts_taken RETURNING contacts_taken`. The no-op assignment is what makes
//! it a lock: `DO NOTHING` returns no row to a concurrent inserter and takes no
//! lock at all, which is the race in the first place. The ceiling is compared
//! **after** that statement and the increment is written before the caller's
//! transaction commits, so no second decision can read the count in between.
//!
//! # It only ever refuses more
//!
//! Both counters above keep running. That is not caution, it is the deployment
//! day: a bucket created at noon starts at zero while the trail already holds
//! this morning's strangers, so a bucket that *replaced* the aggregate would
//! hand every tenant a fresh allowance the afternoon the migration lands. Side
//! by side, the day's refusal is the strictest of the two and nothing widens.
//!
//! Sequentially the bucket and the old aggregate agree exactly —
//! [`tests::the_bucket_and_the_audit_aggregate_count_the_same_set`] walks the
//! same sequence past both and compares them at every step. Where they differ,
//! the bucket is the larger number, and it is larger by exactly the concurrent
//! decisions the aggregate could not see.
//!
//! **Over sending actions.** The aggregate is the wider set and stays wider:
//! `app::gate::counterparty` files an A2A peer under the same key, because the
//! trail has to record who called, while `evaluate`'s A2A arm asks
//! `allowed_a2a_peers` and never the ceiling. So the gate charges this ledger
//! for the actions `domain::policy::spends_contact_budget` names — the ones the
//! ceiling actually rules on — and a peer advances the aggregate alone. Charging
//! it here as well was a refusal nobody wrote: it closed the whole A2A
//! endpoint, inbound included — outright on the two role packs that ship
//! `max_new_contacts_per_day: 0`, and partway through the day on the three that
//! ship `5`, `5` and `20`.
//!
//! # The warming schedule, which is a second narrowing and never a ramp
//!
//! `0070_outreach_warmup` added the other half of the ceiling: the number an
//! operator wrote is where a seat *lands*, and [`warmup_release`] is how much of
//! it today releases, given the sending domain's age and what the trail says
//! about how our mail is received.
//!
//! **It cannot widen anything and the shape is why.** `effective = min(written,
//! released)`, computed here, off an `EffectivePolicy` that
//! `agentos_domain::policy::warmup_allowance` has already taken the same `min`
//! against. A seat written down as five takes five however old and however clean
//! the domain is. What moves is the floor coming up towards that number, never
//! the number.
//!
//! **A tenant with no `outreach_warmup` row is untouched by all of it.** That is
//! this module's own deployment-day argument, applied to itself: a narrowing
//! that switched on for everybody the afternoon it landed would cut a running
//! business to one stranger a day with nobody having asked.
//!
//! ## The state of the ramp, said out loud: wired, and enrolled by nobody
//!
//! `outreach_warmup` has **no production writer, by design**. `0070` revokes
//! `insert` from `app_role` and says why in as many words — "no route today,
//! deliberately … enrolling a tenant is a deployment decision an operator makes
//! once, in `admin_tx_bypassing_rls`" — and the only `INSERT` anywhere in this
//! tree outside the migration is under `#[cfg(test)]`, here and in `app::gate`.
//! So [`warmup_release`] reads `None` for every tenant and every seat takes
//! exactly the number an operator wrote.
//!
//! Read the direction before reading it as a bug: an unenrolled tenant is
//! **unnarrowed**, not held at one stranger a day. What is absent is the
//! enrolment, which is three lines of SQL in a runbook. What is *not* absent is
//! the measurement it feeds: the numerator (`audit_log` rows of kind
//! `mail_refused`) is written in production by `app::inbound::record_refusal`
//! on every verified provider refusal, and the denominator by [`reserve`]
//! itself. The ramp is plumbed; nobody is plugged into it.
//!
//! The half that was genuinely invisible is the enrolled one, and it is the
//! reason [`ceiling`] exists. For a tenant an operator does enrol,
//! `Deliverability::Unknown` holds every seat at `WARMUP_FLOOR` — one stranger
//! a day, follow-ups included — **indefinitely**, because the only thing that
//! lifts `Unknown` without an operator is an observed refusal and whether the
//! provider endpoint is subscribed to `email.bounced` is a checkbox no code
//! here can read. Until [`ceiling`] there was no way to ask that question
//! without attempting a send: the only page that answers "what bounds this
//! seat" showed the number an operator wrote, so a seller releasing one of five
//! looked exactly like a seller allowed five. A founder at 5 000 $/month found
//! out on the ninth day, by counting nine emails.
//!
//! # Which day
//!
//! UTC, `now.date_naive()`, the same day the other two ledgers key on. The
//! argument is [`crate::turns`]'s and it has not changed: there is no
//! `tenants.timezone` column, and an employee whose ledgers roll at different
//! instants has two todays.
//!
//! # No release verb
//!
//! [`crate::spend`] has one because a payment can fail at the provider and the
//! money demonstrably did not move. Nothing here is like that. A reserved
//! contact is a *decision to approach a stranger* that was made, ruled on and
//! written to `audit_log`; the old counter charges it whether or not the send
//! then succeeded, so handing the slot back would free something the trail still
//! shows as spent — and it is the exact path a retry loop would ride to mail one
//! stranger repeatedly. `app::queue::push` already picked this direction for
//! this vertical: marked-and-not-written-to is the survivable error, and
//! written-to-twice is what a sending domain does not recover from.

use agentos_domain::ids::EmployeeId;
use agentos_domain::policy::{Deliverability, EffectivePolicy, warmup_allowance};
use chrono::{NaiveDate, TimeDelta};
use thiserror::Error;

use crate::db::{StoreError, TenantTx};

/// Why an approach was refused.
///
/// Three refusals rather than one, and each is a different remedy.
/// [`Self::NoBudget`] is a policy nobody wrote and [`Self::Exhausted`] is a
/// policy doing its job — [`crate::turns`]'s distinction, unchanged.
/// [`Self::Warming`] is neither: the policy is right and the sending domain is
/// not ready, so the only thing an operator could widen is the one number that
/// would not help.
#[derive(Debug, Error)]
pub enum ContactBudgetError {
    /// The intersected policy allows this employee no cold outreach at all.
    /// Fails closed by design — `PolicyLimits::default()` is zero, so cold
    /// outreach is something an operator turns on rather than something a
    /// deployment starts with.
    ///
    /// This used to add "and every role pack in `docs/` ships zero", which is
    /// not true of any version of this tree: two of the five do (`direction`,
    /// `growth`), two ship `5` and one ships `20`. The default is what fails
    /// closed; the packs are an operator's answer and they vary.
    ///
    /// The message names the **one gesture that lifts it**, because a refusal
    /// that only states its own existence is how a seat stays dead for a week.
    /// The route is the one `/v1/controls` lists as this limit's lever; the
    /// clause after it is not decoration, it is who is allowed to make the
    /// gesture — see `app::rolepack_sales`, which ships this zero on purpose.
    #[error(
        "no contact budget: the effective policy allows 0 new contacts per day. \
         To lift it: PUT /v1/policy/roles/{{role}} with `max_new_contacts_per_day` \
         above zero, by somebody who can answer for the lawful basis of \
         approaching a stranger"
    )]
    NoBudget,

    /// Today's strangers are used up. It resumes on its own at UTC midnight.
    #[error("daily budget of {limit} new contacts is already used up ({taken} taken)")]
    Exhausted {
        /// The ceiling.
        limit: u32,
        /// What the bucket held.
        taken: u32,
    },

    /// The operator's ceiling was not what refused. This tenant is enrolled in
    /// the warming schedule (`migrations/0070_outreach_warmup.sql`) and today
    /// releases only part of the number they wrote — either because the sending
    /// domain is young, or because its deliverability cannot be read at all.
    ///
    /// **A third refusal rather than a second `Exhausted`, and the reason is the
    /// remedy.** The two above share one: an operator raising
    /// `max_new_contacts_per_day`. This one is refused *under* that number —
    /// `warmup_allowance` returns the `min` of the schedule and it — so raising
    /// it does nothing, and reporting this as `Exhausted` would send somebody to
    /// widen a limit on a domain the trail has just called unhealthy. It maps to
    /// its own [`DenyReason`](agentos_domain::policy::DenyReason), which is not
    /// grantable for the same reason.
    #[error(
        "the sending domain is warming: {allowed} of this seat's {written} new contacts a day \
         are released today ({taken} taken)"
    )]
    Warming {
        /// What the schedule and the measurement released today.
        allowed: u32,
        /// What the operator wrote. Always `>= allowed`.
        written: u32,
        /// What the bucket held.
        taken: u32,
    },

    /// The database said no.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for ContactBudgetError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

impl ContactBudgetError {
    /// Stable, low-cardinality metric label.
    pub const fn code(&self) -> &'static str {
        match self {
            ContactBudgetError::NoBudget => "no_contact_budget",
            ContactBudgetError::Exhausted { .. } => "contact_budget_exhausted",
            ContactBudgetError::Warming { .. } => "sending_domain_warming",
            ContactBudgetError::Store(_) => "unavailable",
        }
    }
}

/// Take up to `want` of today's strangers, or refuse. **Returns how many were
/// granted, which is never more than `want` and never zero.**
///
/// Call it in the transaction that records the approach — the gate's audit row,
/// the export's `record_queued` — and before anything leaves the process. The
/// bucket row stays locked until that transaction commits, so between the
/// comparison and the increment nobody else can reserve against the same day.
///
/// The ceiling is not a `u32` parameter. It is read out of an
/// [`EffectivePolicy`], which can only be produced by `EffectivePolicy::try_new`
/// — the one intersection of platform ∧ tenant ∧ role ∧ employee — so a caller
/// cannot inflate the cap the way it could with a bare number, and this module
/// does not re-derive it. The tenant likewise comes from `tx`, which is the only
/// thing row-level security honours anyway.
///
/// # A partial grant, and why this one is not all-or-nothing
///
/// [`crate::turns`] reserves one turn and [`crate::spend`] reserves one amount,
/// so neither has anything to be partial about. This has two callers wanting two
/// sizes: the gate asks for exactly one stranger, and an export asks for the
/// file it has just built. Refusing a file of forty because thirty-eight fit
/// would cost the founder a morning and would not protect anybody — the ceiling
/// is a ceiling on people written to, not on requests. So the grant is
/// `min(want, headroom)` and the caller truncates to it. Asking for one and
/// getting one back is the same statement `turns::reserve` makes.
///
/// `want == 0` is `Ok(0)` and touches nothing: an export with an empty queue
/// must not leave a bucket row behind, for the same reason an employee with no
/// budget must not.
pub async fn reserve(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
    policy: &EffectivePolicy,
    want: u32,
) -> Result<u32, ContactBudgetError> {
    if want == 0 {
        return Ok(0);
    }
    let tenant = tx.tenant_id().as_uuid();
    // ponytail: read inline rather than through a `contacts_remaining` twin of
    // `policy::turns_remaining`. That function earns its place by being called
    // from a route as well as from the ledger; this subtraction has one caller
    // and a second spelling of a limit is how two spellings come to disagree.
    let limit = policy.limits().max_new_contacts_per_day;
    if limit == 0 {
        return Err(ContactBudgetError::NoBudget);
    }

    // Create-if-missing *and* lock, in one statement. `DO UPDATE` with a no-op
    // assignment is what makes it a lock: `DO NOTHING` returns no row to a
    // concurrent inserter and takes no lock, which is the race this module
    // exists to close. RETURNING yields the count as of the lock.
    let taken: i32 = sqlx::query_scalar(
        "INSERT INTO outreach_buckets (tenant_id, employee_id, day) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id, employee_id, day) DO UPDATE SET \
           contacts_taken = outreach_buckets.contacts_taken \
         RETURNING contacts_taken",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .fetch_one(&mut ***tx)
    .await?;

    // -- everything from here to COMMIT runs under that row lock --

    let taken = u32::try_from(taken).unwrap_or(u32::MAX);

    // The second narrowing, and it is only ever a narrowing. `None` is a tenant
    // with no `outreach_warmup` row — the ramp is not installed for them and
    // their day is exactly what it was before `0070` existed.
    //
    // `.min(limit)` is redundant: `warmup_allowance` already returns the `min`
    // of the schedule and this same number, off the same `EffectivePolicy`.
    // Kept because the two are independently tested — `agentos_domain`'s
    // `the_warmup_never_returns_more_than_the_operator_wrote` sweeps the pure
    // function, and this line means a caller that got handed a larger number by
    // any route still cannot spend it. One lock at each end of the same claim.
    let allowed = match warmup_release(tx, day, policy).await? {
        None => limit,
        Some(release) => release.min(limit),
    };

    let granted = want.min(allowed.saturating_sub(taken));

    // **Every truncation is logged, not only the one that refuses the batch
    // whole.** This used to sit inside the `granted == 0` arm below, which is
    // the rarest case: an export that asks for forty and is granted one takes
    // the `Ok` path, the caller shortens its file to one, and until now nothing
    // anywhere recorded that thirty-nine people were not written to. That is
    // the silent ceiling this workspace refuses — and it is the *normal* case
    // for an enrolled tenant, not the exceptional one, because
    // `warmup_allowance` holds an unmeasured domain at `WARMUP_FLOOR`.
    //
    // Counts only, never an address. `allowed` against `written` is which wall
    // it was: below it, the warming schedule; equal to it, the number the
    // operator wrote and already knows about.
    if granted < want {
        tracing::info!(
            want,
            granted,
            allowed,
            written = limit,
            taken,
            "an outreach batch was cut to what today's ceiling leaves"
        );
    }

    if granted == 0 {
        // Which of the two refused is [`why`]'s question and not this
        // function's — the page that displays the wall asks the same function,
        // so the refusal and the display cannot come to disagree.
        //
        // `want >= 1` here (`want == 0` returned at the top), so `granted == 0`
        // means `taken >= allowed` and `why` is never `None`. `unwrap_or` and
        // not a panic: the fallback is the refusal this branch used to build by
        // hand.
        //
        // The log for this is the one above, which has already fired:
        // `granted == 0` is `granted < want` for every `want >= 1`. A second
        // line here would double-log the same event.
        return Err(
            why(limit, allowed, taken).unwrap_or(ContactBudgetError::Exhausted { limit, taken })
        );
    }

    sqlx::query(
        "UPDATE outreach_buckets SET contacts_taken = contacts_taken + $4, updated_at = now() \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3",
    )
    .bind(tenant)
    .bind(employee_id.as_uuid())
    .bind(day)
    .bind(i32::try_from(granted).unwrap_or(i32::MAX))
    .execute(&mut ***tx)
    .await?;

    Ok(granted)
}

/// Which wall this seat is against today, or `None` when a stranger still fits
/// under the number an operator wrote.
///
/// **One classifier, two readers.** [`reserve`] raises what it returns and
/// [`ceiling`] displays it without taking anything, so `GET /v1/controls` and
/// the gate's own refusal cannot come to name different walls for the same
/// seat. A limit enforced in one spelling and displayed in another is the
/// failure this workspace keeps closing; this is that closure for the third
/// ledger.
///
/// The order of the arms is the order of the remedies, and each is a different
/// human doing a different thing:
///
/// 1. **nothing written** — an operator raises `max_new_contacts_per_day`, and
///    [`ContactBudgetError::NoBudget`]'s own message names the route;
/// 2. **written but not released** — nobody raises anything; the sending domain
///    is young, or its deliverability cannot be read, and the answer is a
///    dashboard or a wait. `<` and not `<=`, and that is the whole of it: when
///    the schedule released everything the operator wrote, the operator's
///    number is genuinely the wall and raising it genuinely helps, so that case
///    must fall through to the third arm. `<=` here swallows the ordinary
///    refusal whole — including for the tenants that are not enrolled, where
///    `effective` is `written` by construction — and
///    `a_tenant_with_no_warmup_row_has_exactly_the_day_it_had_before` is the
///    line that catches it;
/// 3. **released and used up** — it resumes on its own at UTC midnight.
const fn why(written: u32, effective: u32, taken: u32) -> Option<ContactBudgetError> {
    if written == 0 {
        Some(ContactBudgetError::NoBudget)
    } else if effective < written {
        Some(ContactBudgetError::Warming {
            allowed: effective,
            written,
            taken,
        })
    } else if taken >= effective {
        Some(ContactBudgetError::Exhausted {
            limit: written,
            taken,
        })
    } else {
        None
    }
}

/// Today's ceiling for one seat, read rather than taken.
#[derive(Debug)]
pub struct ContactCeiling {
    /// What today releases: `min(max_new_contacts_per_day, warmup_release)`,
    /// and exactly the written number for a tenant with no `outreach_warmup`
    /// row. Never more than the written number — see
    /// `agentos_domain::policy::warmup_allowance`.
    pub effective: u32,
    /// Why [`Self::effective`] is not the written number, or why today is used
    /// up under it. [`None`] when a stranger still fits.
    pub why: Option<ContactBudgetError>,
}

/// What [`reserve`] would answer right now, without reserving anything.
///
/// **The read half of the ledger.** A ceiling nobody can read is a ceiling a
/// founder discovers on the ninth day by counting nine emails, and until this
/// existed the only page that answers "what bounds this seat" could show the
/// number an operator *wrote* and had no way to show that the warming schedule
/// releases one of it.
///
/// `taken` is passed in rather than read here: the caller already has it from
/// [`taken_today`], and a second query for the same number is a second chance
/// for a page to disagree with itself.
///
/// **It takes no lock and must not decide a send.** [`reserve`] is the only
/// thing that may, and it re-reads all of this under the bucket's row lock —
/// what this returns is a photograph, true when it was taken.
pub async fn ceiling(
    tx: &mut TenantTx<'_>,
    day: NaiveDate,
    policy: &EffectivePolicy,
    taken: u32,
) -> Result<ContactCeiling, StoreError> {
    let written = policy.limits().max_new_contacts_per_day;
    // Nothing written releases nothing, whatever the two counts under
    // `warmup_release` say. `reserve` short-circuits on the same line.
    if written == 0 {
        return Ok(ContactCeiling {
            effective: 0,
            why: why(0, 0, taken),
        });
    }
    let effective = match warmup_release(tx, day, policy).await? {
        None => written,
        Some(release) => release.min(written),
    };
    Ok(ContactCeiling {
        effective,
        why: why(written, effective, taken),
    })
}

/// When this tenant's sending domain started warming, or [`None`] for a tenant
/// the schedule is not installed for.
///
/// **[`None`] is the answer for every tenant in this deployment**, and it is a
/// fact about the schedule rather than about the tenant — see the module
/// header. A reader needs it because "the ramp released everything" and "there
/// is no ramp" are otherwise the same silence: both leave [`ContactCeiling`]'s
/// `why` empty, and only one of them is a promise that the number an operator
/// wrote is the number that applies.
pub async fn warming_since(tx: &mut TenantTx<'_>) -> Result<Option<NaiveDate>, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT warming_started_on FROM outreach_warmup")
            .fetch_optional(&mut ***tx)
            .await?,
    )
}

/// What the warming schedule releases for this tenant on `day`, or `None` when
/// the tenant is not enrolled in one.
///
/// **The measured half of the cold-contact ceiling.** `docs/ORIZN.md` asks for a
/// number that moves as the sending domain ages, and says in the same breath
/// that there is no measurement of deliverability to move it against. This is
/// that measurement, assembled out of rows that already exist, plus the one
/// fact no row could hold — see `migrations/0070_outreach_warmup.sql`.
///
/// # What is actually being measured, and by whom it is written
///
/// Two counts, both tenant-scoped by row-level security rather than by a
/// predicate, over the same window ([`Deliverability::WINDOW_DAYS`]):
///
/// * **the denominator** is `sum(outreach_buckets.contacts_taken)` — strangers
///   this tenant was cleared to approach. Written by `reserve` above, from its
///   two production callers: `app::gate::PolicyGate::take_contact` on the
///   sending path and `routes::queue::export` on the file path;
/// * **the numerator** is `audit_log` rows of kind `mail_refused` whose payload
///   says `permanent`. Written by `app::inbound::record_refusal`, reached from
///   `main::on_webhook` when a verified provider delivery parses as
///   [`Refusal`](agentos_providers::email::Refusal) — a spam complaint, which is
///   always permanent, or a bounce the provider itself called permanent. Soft
///   bounces are counted as evidence that the channel works and not as evidence
///   against the domain: a full mailbox is not a reputation event.
///
/// `suppressions` was the other candidate for the numerator and was not taken.
/// It holds the same complaints, but it also holds `opt_out` rows from the STOP
/// reply path and rows an operator may add by hand, its writes are conditional
/// on the address parsing, and its rows are keyed by address rather than by
/// event — the same person refusing twice is one row. The trail counts events,
/// which is what a rate needs.
///
/// # The count that is not a rate: has a refusal ever arrived at all
///
/// The third read is `count(*)` over every `mail_refused` row this tenant has,
/// with no window and no `permanent` filter, and it exists because of the
/// question `app::inbound::record_refusal` leaves open: nothing in this process
/// can see whether the provider endpoint is subscribed to `email.bounced` and
/// `email.complained`. If it is not, the numerator above is permanently zero and
/// a two-valued measure would read a broken webhook as a spotless domain.
///
/// So one refusal, ever, of any severity, is what proves the channel exists —
/// and the operator's `refusal_events_confirmed_at` is the other way to prove
/// it, for a tenant whose list is genuinely clean enough never to have bounced.
/// Neither, and the reading is [`Deliverability::Unknown`], which releases the
/// floor and nothing more.
///
/// # The measurement is the domain's and the enforcement is the seat's
///
/// ponytail: what this returns is compared against **one employee's** bucket, so
/// a tenant with three outbound seats can put three times the schedule on one
/// sending domain. That is a real gap and it is named rather than closed: it is
/// strictly narrower than the day those seats have without this function at all,
/// so it cannot make anything worse, and the alternative was worse in a way this
/// schema argues against elsewhere. A tenant-wide allowance needs a tenant-keyed
/// counter, and `outreach_buckets` is keyed `(tenant, employee, day)` on
/// purpose — `0055` says a ledger coarser than its limit "refuses an employee for
/// what a colleague did", which is what a shared allowance over per-seat ceilings
/// produces. The upgrade path, the day a tenant really does run several cold
/// seats: a tenant-keyed row plus `pg_advisory_xact_lock` before the bucket
/// upsert, in `reserve`, taken in that order.
///
/// The measurement above stays tenant-wide either way and that is not the same
/// compromise — a reputation belongs to the domain, so both counts must span
/// every seat that sends from it. Three seats that between them over-send show up
/// in the rate and put all three back on the floor. Late, but not never.
async fn warmup_release(
    tx: &mut TenantTx<'_>,
    day: NaiveDate,
    policy: &EffectivePolicy,
) -> Result<Option<u32>, StoreError> {
    // One row per tenant and RLS picks it. No enrolment, no narrowing: the
    // tenant's day is what it was before this existed, which is `0055`'s
    // deployment-day argument and not an opinion about their deliverability.
    let Some((started_on, confirmed)): Option<(NaiveDate, bool)> = sqlx::query_as(
        "SELECT warming_started_on, refusal_events_confirmed_at IS NOT NULL FROM outreach_warmup",
    )
    .fetch_optional(&mut ***tx)
    .await?
    else {
        return Ok(None);
    };

    let since = day - TimeDelta::days(Deliverability::WINDOW_DAYS);
    // Both windows start at the same midnight, so the two counts are over the
    // same days and the rate between them means something.
    let since_start = since.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();

    let approaches: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(contacts_taken), 0)::bigint FROM outreach_buckets WHERE day >= $1",
    )
    .bind(since)
    .fetch_one(&mut ***tx)
    .await?;

    // One statement for both counts: they read the same rows and a second query
    // is a second chance for them to disagree about which rows those are.
    let (refusals, ever): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE occurred_at >= $1 AND payload->>'permanent' = 'true'), \
                count(*) \
           FROM audit_log WHERE action_kind = 'mail_refused'",
    )
    .bind(since_start)
    .fetch_one(&mut ***tx)
    .await?;

    let measured = Deliverability::measure(
        u64::try_from(approaches).unwrap_or(0),
        u64::try_from(refusals).unwrap_or(u64::MAX),
        confirmed || ever > 0,
    );
    // A count that will not fit is read in the direction that narrows: no
    // approaches at all is `Unknown`, and unreadably many refusals is
    // `Unhealthy`. Both release the floor.

    Ok(Some(warmup_allowance(
        policy,
        (day - started_on).num_days(),
        measured,
    )))
}

/// How many strangers this employee has been cleared to reach on `day`. The
/// operator's question, and the tests'.
///
/// Zero for a day with no bucket row, which is the same answer as a bucket at
/// zero and means the same thing.
pub async fn taken_today(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
) -> Result<u32, StoreError> {
    let taken: Option<i32> = sqlx::query_scalar(
        "SELECT contacts_taken FROM outreach_buckets \
         WHERE tenant_id = $1 AND employee_id = $2 AND day = $3",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id.as_uuid())
    .bind(day)
    .fetch_optional(&mut ***tx)
    .await?;

    // CHECKed non-negative in the schema. Clamping to zero if it ever is not
    // reports *less* consumption than happened, which is the direction that does
    // not silently silence an employee on a corrupt row.
    Ok(taken.map_or(0, |t| u32::try_from(t).unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::PolicyLimits;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use super::*;
    use crate::db::Db;

    const DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 28) {
        Some(d) => d,
        None => panic!("valid date"),
    };
    const NEXT_DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 29) {
        Some(d) => d,
        None => panic!("valid date"),
    };

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the outreach ledger needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed(db: &Db, label: &str) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("{label}-{}", tenant.as_uuid()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(label)
        .bind(label)
        .execute(&mut *tx)
        .await
        .expect("insert employee");

        tx.commit().await.expect("commit seed");
        (tenant, employee)
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    /// An already-intersected policy allowing `contacts` strangers per day.
    /// Going through `try_new` is the point: there is no other way to spell an
    /// `EffectivePolicy`, which is what stops a caller inflating the cap.
    fn policy(contacts: u32) -> EffectivePolicy {
        let limits = PolicyLimits {
            max_new_contacts_per_day: contacts,
            ..PolicyLimits::default()
        };
        EffectivePolicy::try_new(&limits, &limits, &limits, &limits).expect("coherent")
    }

    /// Reserve in its own committed transaction, the way a caller would.
    async fn reserve_committed(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        day: NaiveDate,
        policy: &EffectivePolicy,
        want: u32,
    ) -> Result<u32, ContactBudgetError> {
        let mut tx = db.tenant_tx(tenant).await?;
        match reserve(&mut tx, employee, day, policy, want).await {
            Ok(granted) => {
                tx.commit().await?;
                Ok(granted)
            }
            Err(e) => {
                tx.rollback().await?;
                Err(e)
            }
        }
    }

    async fn counted(db: &Db, tenant: TenantId, employee: EmployeeId, day: NaiveDate) -> u32 {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let n = taken_today(&mut tx, employee, day).await.expect("read");
        tx.rollback().await.expect("rollback");
        n
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_employee_with_no_contact_budget_reaches_nobody_and_leaves_no_row() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "nocontacts").await;

        let err = reserve_committed(&db, tenant, employee, DAY, &policy(0), 1)
            .await
            .expect_err("an unconfigured policy allows no cold outreach");
        assert!(matches!(err, ContactBudgetError::NoBudget), "{err}");
        assert_eq!(err.code(), "no_contact_budget");
        assert_eq!(counted(&db, tenant, employee, DAY).await, 0);

        // An empty queue is not a refusal and is not a write either.
        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy(10), 0)
                .await
                .expect("asking for nobody is not an error"),
            0
        );
        assert_eq!(counted(&db, tenant, employee, DAY).await, 0);

        drop_tenant(&db, tenant).await;
    }

    /// The cap holds, a batch is granted what fits rather than refused whole,
    /// and a new UTC day is a fresh bucket with no sweeper.
    #[tokio::test]
    async fn the_days_strangers_run_out_and_the_day_rolls_over() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "exhaust").await;
        let policy = policy(3);

        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy, 1)
                .await
                .expect("the first stranger"),
            1
        );
        // A file of ten against two remaining slots is two, not a refusal.
        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy, 10)
                .await
                .expect("what fits is granted"),
            2
        );
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        let err = reserve_committed(&db, tenant, employee, DAY, &policy, 1)
            .await
            .expect_err("three is the budget");
        assert!(
            matches!(err, ContactBudgetError::Exhausted { limit: 3, taken: 3 }),
            "{err}"
        );
        assert_eq!(err.code(), "contact_budget_exhausted");
        assert_eq!(
            counted(&db, tenant, employee, DAY).await,
            3,
            "a refusal does not advance the ledger"
        );

        // Tomorrow is a new bucket; today's record is untouched, because a
        // consumption ledger is not a gauge.
        assert_eq!(
            reserve_committed(&db, tenant, employee, NEXT_DAY, &policy, 3)
                .await
                .expect("tomorrow is a new day"),
            3
        );
        assert_eq!(counted(&db, tenant, employee, NEXT_DAY).await, 3);
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// **The bug.** Two decisions, one slot left, hand-interleaved so the result
    /// does not depend on the scheduler.
    ///
    /// Against the unlocked `audit_log` aggregate the gate used, the second
    /// transaction reads the count as it stood before the first decision, sees
    /// room, and the day ends at 4 strangers against a ceiling of 3 — every
    /// single run. Reproduced in SQL before this module was written.
    ///
    /// **The timeout is not the assertion that matters, and believing it was
    /// cost a mutation run.** A lock-free implementation blocks here too — on
    /// its own final `UPDATE`, not on the read — so the second task fails to
    /// finish inside 500ms either way and the timeout goes green against a
    /// broken `reserve`. What catches it is the *outcome*: a decision made from
    /// an unlocked read returns `Ok(1)` against a bucket that is already full,
    /// and the day ends at 4. Both assertions stay, because the timeout is what
    /// proves the second decision was genuinely in flight rather than never
    /// started, and the outcome is what proves it was in flight *behind the
    /// lock*.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_decisions_cannot_both_take_the_last_stranger() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "interleave").await;
        let policy = policy(3);

        // Two already taken, committed, so the bucket row exists. Without this
        // the two transactions below would race to *create* the row and Postgres
        // would serialise that on the primary key all by itself — which would
        // let a lock-free implementation pass for the wrong reason.
        reserve_committed(&db, tenant, employee, DAY, &policy, 2)
            .await
            .expect("warm-up");

        // The third stranger: reserved, transaction left open exactly as it
        // would be while the audit row and the send are being written beside it.
        let mut first = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(
            reserve(&mut first, employee, DAY, &policy, 1)
                .await
                .expect("the last slot"),
            1
        );

        // A second decision, concurrently. On its own merit the bucket still
        // says 2 of 3 — that is what makes the race work.
        let second = tokio::spawn({
            let db = db.clone();
            let policy = policy.clone();
            async move {
                let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
                let outcome = reserve(&mut tx, employee, DAY, &policy, 1).await;
                // Commit either way: if the implementation wrongly granted it,
                // the damage must be visible in the bucket rather than rolled
                // back by a tidy test.
                tx.commit().await.expect("commit second");
                outcome
            }
        });

        // It must still be blocked. If `reserve` decided anything here it did so
        // from a bucket it had not locked.
        let mut second = std::pin::pin!(second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut second)
                .await
                .is_err(),
            "the second decision ruled while the first held the bucket"
        );

        first.commit().await.expect("commit first");

        let outcome = second.await.expect("task panicked");
        assert!(
            matches!(
                outcome,
                Err(ContactBudgetError::Exhausted { limit: 3, taken: 3 })
            ),
            "the second decision must be refused, got {outcome:?}"
        );
        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// **The set this charges for is the set the gate always charged for.**
    ///
    /// Not asserted, walked: one sequence of decisions is pushed through the
    /// bucket and through `PolicyGate::contacts`' own SQL — copied verbatim, so
    /// a change to either is a failure here — and the two are compared after
    /// every step. Repeats are free on both sides, yesterday's stranger is free
    /// on both sides, and an action with no counterparty costs nothing on
    /// either. Sequentially they never disagree; the concurrent case above is
    /// the only place they can, and there the bucket is the larger number.
    #[tokio::test]
    async fn the_bucket_and_the_audit_aggregate_count_the_same_set() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "sameset").await;
        let policy = policy(10);
        let noon = DAY.and_hms_opt(12, 0, 0).expect("valid time").and_utc();

        // Yesterday's stranger, in the trail and not in today's count.
        append_allow(
            &db,
            tenant,
            employee,
            Some("old@example.com"),
            noon - chrono::Duration::days(1),
        )
        .await;

        // The sequence, as the gate would see it: two strangers, a repeat of the
        // first, a repeat of yesterday's, a third stranger, and one allowed
        // action that addresses nobody (a payment, `counterparty` = None).
        let script: [(Option<&str>, bool); 6] = [
            (Some("a@example.com"), true),
            (Some("b@example.com"), true),
            (Some("a@example.com"), false),
            (Some("old@example.com"), false),
            (Some("c@example.com"), true),
            (None, false),
        ];

        for (who, is_new) in script {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            // The gate charges exactly when the counterparty is new to the
            // trail. Assert the fixture's own belief against the trail first, so
            // a wrong script cannot make the comparison below pass.
            assert_eq!(
                standing(&mut tx, employee, who, noon).await,
                is_new,
                "the trail disagrees with the script about {who:?}"
            );
            if is_new {
                assert_eq!(
                    reserve(&mut tx, employee, DAY, &policy, 1)
                        .await
                        .expect("within the budget"),
                    1
                );
            }
            tx.commit().await.expect("commit reservation");
            append_allow(&db, tenant, employee, who, noon).await;

            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let aggregate = new_today(&mut tx, employee, noon).await;
            let bucket = taken_today(&mut tx, employee, DAY).await.expect("bucket");
            tx.rollback().await.expect("rollback");
            assert_eq!(
                bucket, aggregate,
                "the bucket and the audit aggregate must count the same strangers after {who:?}"
            );
        }

        assert_eq!(counted(&db, tenant, employee, DAY).await, 3);

        drop_tenant(&db, tenant).await;
    }

    /// A tenant's strangers are its own. RLS, not a WHERE clause somebody adds —
    /// and **forced**, which `SET LOCAL ROLE app_role` alone cannot prove: a
    /// table with `enable` and no `force` is wide open to whoever owns it.
    #[tokio::test]
    async fn one_tenants_outreach_is_invisible_to_another() {
        let Some(db) = db().await else { return };
        let (tenant_a, employee_a) = seed(&db, "tenant-a").await;
        let (tenant_b, _) = seed(&db, "tenant-b").await;

        reserve_committed(&db, tenant_a, employee_a, DAY, &policy(5), 2)
            .await
            .expect("a's strangers");
        assert_eq!(counted(&db, tenant_a, employee_a, DAY).await, 2);
        // B asking about A's employee sees nothing at all.
        assert_eq!(counted(&db, tenant_b, employee_a, DAY).await, 0);

        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = 'outreach_buckets'::regclass",
        )
        .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
        .await
        .expect("catalogue");
        assert!(enabled, "outreach_buckets has row-level security enabled");
        assert!(
            forced,
            "…and forced, or the owning role reads every tenant's cold-outreach ledger"
        );

        drop_tenant(&db, tenant_a).await;
        drop_tenant(&db, tenant_b).await;
    }

    // -- the warming schedule ------------------------------------------------

    /// Enrol a tenant. `admin_tx_bypassing_rls` because `app_role` holds no
    /// INSERT on this table — see `0070` and
    /// [`the_application_may_read_the_warmup_row_and_never_write_it`].
    async fn enrol(db: &Db, tenant: TenantId, started_on: NaiveDate, confirmed: bool) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO outreach_warmup (tenant_id, warming_started_on, \
                                          refusal_events_confirmed_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
               warming_started_on = excluded.warming_started_on, \
               refusal_events_confirmed_at = excluded.refusal_events_confirmed_at",
        )
        .bind(tenant.as_uuid())
        .bind(started_on)
        .bind(confirmed.then(Utc::now))
        .execute(&mut *tx)
        .await
        .expect("enrol");
        tx.commit().await.expect("commit enrolment");
    }

    /// A day's worth of approaches already on the books, so the window has a
    /// denominator without this test having to reserve them through the very
    /// function it is measuring.
    async fn seed_bucket(db: &Db, tenant: TenantId, employee: EmployeeId, day: NaiveDate, n: i32) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO outreach_buckets (tenant_id, employee_id, day, contacts_taken) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid())
        .bind(day)
        .bind(n)
        .execute(&mut *tx)
        .await
        .expect("seed bucket");
        tx.commit().await.expect("commit bucket");
    }

    /// One refusal on the trail, through `crate::audit` and with
    /// [`AuditKind::MailRefused`] rather than the string — so the spelling
    /// `warmup_release` filters on is the one production writes, not a copy of
    /// it that can drift.
    ///
    /// The payload key is the seam this cannot cover on its own: it is written
    /// in `crates/app/src/inbound.rs` and read here, in another crate, with no
    /// shared constant between them. `agentos_app::inbound`'s
    /// `a_recorded_complaint_is_what_the_warming_schedule_reads` drives the real
    /// writer end to end for exactly that reason.
    async fn append_refusal(db: &Db, tenant: TenantId, permanent: bool, at: DateTime<Utc>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        crate::audit::append(
            &mut tx,
            &crate::audit::AuditEvent {
                payload: serde_json::json!({
                    "reason": if permanent { "complaint" } else { "bounce" },
                    "permanent": permanent,
                    "channel": "email",
                }),
                ..crate::audit::AuditEvent::new(
                    crate::audit::AuditActor::System,
                    crate::audit::AuditKind::MailRefused,
                    at,
                )
            },
        )
        .await
        .expect("append refusal");
        tx.commit().await.expect("commit refusal");
    }

    /// **The mutation the founder asked for by name.** A seat written down as
    /// five takes five and never six, whatever the schedule and the measurement
    /// would like — the domain here is four hundred days old with a spotless
    /// window, which is every input that could push the release upward.
    ///
    /// Delete the `min` at the end of `domain::policy::warmup_allowance` and
    /// this reserves fifty. Delete the `.min(limit)` in `reserve` and the domain
    /// still holds the line; delete both and the ceiling is gone.
    ///
    /// The second half matters as much: the refusal that arrives when the day
    /// is spent is `Exhausted` and **not** `Warming`, because the operator's
    /// number is genuinely what refused and raising it genuinely would help.
    #[tokio::test]
    async fn a_tenant_capped_at_five_stays_at_five_however_warm_the_domain_is() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "capfive").await;

        seed_bucket(&db, tenant, employee, DAY - TimeDelta::days(1), 100).await;
        enrol(&db, tenant, DAY - TimeDelta::days(400), true).await;

        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy(5), 50)
                .await
                .expect("a warm domain releases the whole written ceiling"),
            5,
            "the warming schedule wanted 401 and the operator wrote 5"
        );

        let err = reserve_committed(&db, tenant, employee, DAY, &policy(5), 1)
            .await
            .expect_err("the day is spent");
        assert!(
            matches!(err, ContactBudgetError::Exhausted { limit: 5, taken: 5 }),
            "{err}"
        );
        assert_eq!(err.code(), "contact_budget_exhausted");
        assert_eq!(counted(&db, tenant, employee, DAY).await, 5);

        drop_tenant(&db, tenant).await;
    }

    /// **Not knowing is not the same as being fine**, and one complaint puts a
    /// warm domain back on the floor.
    ///
    /// Four properties in one sequence, because they are one story:
    ///
    /// 1. enrolled, four hundred days old, nothing has ever demonstrated that a
    ///    refusal would reach us — the release is the floor, not the ceiling,
    ///    and the refusal names the warming schedule rather than the operator;
    /// 2. a **transient** bounce arrives. It proves the channel exists, which is
    ///    the fact `refusal_events_confirmed_at` otherwise has to assert by
    ///    hand, and the domain is measurable and clean;
    /// 3. so the release is the whole written ceiling;
    /// 4. a **permanent** refusal lands. One in a hundred is 1%, over the 0.3%
    ///    the bulk-sender requirements name, and the release is the floor again.
    ///
    /// Step 3 is what makes step 4 mean something, and it is also the assertion
    /// that fails if the `permanent` filter is dropped: a transient bounce would
    /// then count against the domain and the release would never have risen.
    #[tokio::test]
    async fn an_unmeasurable_domain_sits_on_the_floor_and_a_complaint_puts_it_back() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "unmeasured").await;
        let noon = DAY.and_hms_opt(12, 0, 0).expect("valid").and_utc();

        seed_bucket(&db, tenant, employee, DAY - TimeDelta::days(1), 100).await;
        // Enrolled, old, and *not* confirmed: the founder's checkbox unticked.
        enrol(&db, tenant, DAY - TimeDelta::days(400), false).await;

        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy(5), 5)
                .await
                .expect("the floor is not zero, or nothing could ever be measured"),
            1,
            "a domain nobody can measure gets the floor and not the ceiling"
        );
        let err = reserve_committed(&db, tenant, employee, DAY, &policy(5), 1)
            .await
            .expect_err("the floor is spent");
        assert!(
            matches!(
                err,
                ContactBudgetError::Warming {
                    allowed: 1,
                    written: 5,
                    taken: 1
                }
            ),
            "{err}"
        );
        assert_eq!(err.code(), "sending_domain_warming");

        // A soft bounce: evidence the channel works, and not evidence against
        // the domain. Observation beats the operator's attestation.
        append_refusal(&db, tenant, false, noon).await;
        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy(5), 10)
                .await
                .expect("a measurable, clean domain releases the ceiling"),
            4,
            "one already taken, four left of the written five"
        );

        // And a real one. 1 in 105 is 0.95%, over the threshold. A fresh day,
        // so this is the schedule refusing rather than yesterday's bucket.
        append_refusal(&db, tenant, true, noon).await;
        assert_eq!(
            reserve_committed(&db, tenant, employee, NEXT_DAY, &policy(5), 5)
                .await
                .expect("the floor is still the floor"),
            1,
            "a complained-about domain is back on the floor"
        );
        let err = reserve_committed(&db, tenant, employee, NEXT_DAY, &policy(5), 1)
            .await
            .expect_err("and there is no second one");
        assert!(
            matches!(
                err,
                ContactBudgetError::Warming {
                    allowed: 1,
                    written: 5,
                    taken: 1
                }
            ),
            "{err}"
        );

        drop_tenant(&db, tenant).await;
    }

    /// **The deployment day.** A tenant with no `outreach_warmup` row keeps
    /// exactly the day it had before `0070` existed — even with a trail that
    /// would have condemned it, because nothing measured it and nothing asked.
    ///
    /// This is `0055`'s argument made once more. A narrowing that switched
    /// itself on for every tenant the afternoon it was applied would cut a
    /// running business from five strangers a day to one with nobody having
    /// asked and no line saying why.
    #[tokio::test]
    async fn a_tenant_with_no_warmup_row_has_exactly_the_day_it_had_before() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "unenrolled").await;
        let noon = DAY.and_hms_opt(12, 0, 0).expect("valid").and_utc();

        seed_bucket(&db, tenant, employee, DAY - TimeDelta::days(1), 100).await;
        append_refusal(&db, tenant, true, noon).await;

        assert_eq!(
            reserve_committed(&db, tenant, employee, DAY, &policy(5), 50)
                .await
                .expect("not enrolled, so nothing narrows"),
            5
        );
        let err = reserve_committed(&db, tenant, employee, DAY, &policy(5), 1)
            .await
            .expect_err("the day is spent");
        assert!(
            matches!(err, ContactBudgetError::Exhausted { limit: 5, taken: 5 }),
            "an unenrolled tenant can never be refused for warming: {err}"
        );

        drop_tenant(&db, tenant).await;
    }

    /// The grant in `0070`, proved rather than asserted in a comment.
    ///
    /// These two columns are the only writable thing in this workspace that
    /// could *release* something, so the application reads them and an operator
    /// writes them. The read has to work through RLS and the write has to fail.
    #[tokio::test]
    async fn the_application_may_read_the_warmup_row_and_never_write_it() {
        let Some(db) = db().await else { return };
        let (tenant, _employee) = seed(&db, "readonly").await;
        enrol(&db, tenant, DAY, false).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let seen: Option<NaiveDate> =
            sqlx::query_scalar("SELECT warming_started_on FROM outreach_warmup")
                .fetch_optional(&mut **tx)
                .await
                .expect("the application reads its own row");
        assert_eq!(seen, Some(DAY));

        // Every one of these names its own tenant's row. The privilege check
        // fires before the predicate is ever evaluated, so scoping them changes
        // nothing about what is being proved — and `crates/app/tests/
        // scoped_deletes.rs` is right that an unscoped `DELETE` in a source file
        // is a hazard whatever the author meant by it.
        for statement in [
            "UPDATE outreach_warmup SET refusal_events_confirmed_at = now() \
              WHERE tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid",
            "DELETE FROM outreach_warmup \
              WHERE tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid",
            "INSERT INTO outreach_warmup (tenant_id, warming_started_on) \
             VALUES (nullif(current_setting('app.tenant_id', true), '')::uuid, current_date)",
        ] {
            let refused = sqlx::query(statement).execute(&mut **tx).await;
            assert!(
                refused.is_err(),
                "app_role performed `{statement}`; the warming row is read-only to it"
            );
            // Postgres aborts the transaction on the first refusal, so each
            // statement needs its own. Reopened rather than batched: a test that
            // stops after the first denial would pass with the other two
            // granted.
            tx.rollback().await.expect("rollback");
            tx = db.tenant_tx(tenant).await.expect("tenant tx");
        }
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    // -- the gate's own SQL, borrowed ---------------------------------------

    /// One allowed audit row, exactly as `PolicyGate::finish` would write it.
    async fn append_allow(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        counterparty: Option<&str>,
        at: DateTime<Utc>,
    ) {
        let payload = counterparty.map_or_else(
            || serde_json::json!({}),
            |who| serde_json::json!({ "counterparty": who }),
        );
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, employee_id, actor, action_kind, \
                                    decision, payload, occurred_at) \
             VALUES ($1, $2, $3, 'op', 'email.send', 'allow', $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid())
        .bind(payload)
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("append");
        tx.commit().await.expect("commit audit");
    }

    /// `PolicyGate::contacts`' first return value, verbatim.
    async fn new_today(tx: &mut TenantTx<'_>, employee: EmployeeId, now: DateTime<Utc>) -> u32 {
        let day_start = now
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap_or_default()
            .and_utc();
        let n: i64 = sqlx::query_scalar(
            "WITH seen AS ( \
                 SELECT payload->>'counterparty' AS counterparty, min(occurred_at) AS first_at \
                   FROM audit_log \
                  WHERE employee_id = $1 \
                    AND decision = 'allow' \
                    AND payload->>'counterparty' IS NOT NULL \
                  GROUP BY 1) \
             SELECT count(*) FILTER (WHERE first_at >= $2) FROM seen",
        )
        .bind(employee.as_uuid())
        .bind(day_start)
        .fetch_one(&mut ***tx)
        .await
        .expect("aggregate");
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// `PolicyGate::contacts`' second return value: true when the counterparty
    /// is new to the trail, which is exactly when the gate charges for it.
    async fn standing(
        tx: &mut TenantTx<'_>,
        employee: EmployeeId,
        counterparty: Option<&str>,
        _now: DateTime<Utc>,
    ) -> bool {
        let Some(who) = counterparty else {
            // No counterparty is no charge, whatever the trail says.
            return false;
        };
        let known: Option<bool> = sqlx::query_scalar(
            "SELECT bool_or(payload->>'counterparty' = $2) \
               FROM audit_log \
              WHERE employee_id = $1 \
                AND decision = 'allow' \
                AND payload->>'counterparty' IS NOT NULL",
        )
        .bind(employee.as_uuid())
        .bind(who)
        .fetch_one(&mut ***tx)
        .await
        .expect("standing");
        !known.unwrap_or(false)
    }
}
