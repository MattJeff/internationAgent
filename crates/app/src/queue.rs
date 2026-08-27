//! The seller's output: who to write to today, with what, and the two ways
//! that leaves the building.
//!
//! [`crate::vertical::sell`] ends in [`Seller::touch`](crate::revenue::Seller::touch)
//! — it decides *and* it sends, in one function. That is right when the mailer
//! is ours. It is wrong right now, because it is not: until 2026-09-01 the
//! founder loads Smartlead by hand, so the deliverable is a **file**, and from
//! 2026-09-01 it is an **API call**. Two sinks, one decision.
//!
//! So this module is `sell`'s last step, cut off and turned into a value.
//! Everything before it is unchanged and unduplicated: the authority lookup,
//! the two probe runs, the [`Evidence`](crate::proof_of_need::Evidence), the
//! [`Approach`] rendered from it. What changes is only what happens to the
//! `Approach` — `sell` hands it to a provider, [`plan`] puts it in a [`Lead`].
//!
//! # Where the seam is, and why there
//!
//! **[`plan`] returns `Vec<Lead>` and knows nothing about files or HTTP.** That
//! is the whole boundary. A sink is a plain function over `&[Lead]`, and there
//! are now two of them: [`csv`] and [`push`]. There is still deliberately **no
//! `Sink` trait**, and writing the second one is what proved the point — they
//! share no signature. [`csv`] returns a `String` and cannot fail; [`push`] is
//! `async`, needs the gate and a principal, and returns one
//! [`Contacted`](crate::revenue::Contacted) per recipient. A trait over that
//! pair would have one method neither implements comfortably and a lowest
//! common denominator that hides the gate.
//!
//! What they *do* share is the two arrays: [`Lead::fields`] pairs
//! index-for-index with [`COLUMNS`], and both sinks read exactly that pair —
//! one with commas between the values, one with the names beside them. So both
//! name the same ten things and neither can name an eleventh.
//!
//! **[`plan`] did not move**, and neither did [`csv`], [`record_queued`] or
//! [`COLUMNS`]. The trait the API call lives behind is
//! [`LeadSink`](agentos_providers::leads::LeadSink), in `agentos-providers`,
//! reached through [`crate::effects`] like every other provider.
//!
//! # Nothing reaches a sink that could not be defended
//!
//! A [`Lead`]'s fields are private and [`plan`] is the only thing that builds
//! one. [`plan`] takes [`Ready`], which carries an [`Approach`], whose only
//! constructor takes an `&Evidence`, which carries a private zero-sized seal
//! that only [`Prober::check`](crate::proof_of_need::Prober::check) can mint and
//! only after the prospect's own flow said the same thing to two identical runs.
//!
//! The chain is the existing one and this module adds no second seal to it — a
//! row with no reproduced finding behind it is a program that does not compile,
//! at `tests/ui/queue_lead_without_evidence.rs` and
//! `tests/ui/vertical_approach_without_evidence.rs`. What an `Evidence` *says*
//! is not this module's business: [`Lead`] copies
//! [`Outreach`](crate::revenue::Outreach)'s two rendered strings and never looks
//! inside them, so a finding that changes from "your data is wrong" to "your
//! page is missing a whole category" changes nothing here.
//!
//! # The three refusals, and they are the send path's own
//!
//! An export that skipped these would be worse than no export, because a file
//! the founder uploads *is* a send — with the safety checks a day later and a
//! system boundary away. So [`plan`] applies the same ones
//! [`Seller::touch`](crate::revenue::Seller::touch) and the gate apply, from the
//! same values:
//!
//! 1. **Suppression.** The same [`Suppression`] the [`Seller`](crate::revenue::Seller)
//!    holds — pass `seller.suppression()`. First, before anything else, exactly
//!    as in `touch`. The database says it again and more strongly:
//!    `suppressions_deactivate_contacts` in `0011_revenue.sql` sets both
//!    `active = false` **and** `next_follow_up_at = NULL` on the rows an opt-out
//!    names, in the same statement, and
//!    [`contacts_due_for_follow_up`](agentos_store::revenue::contacts_due_for_follow_up)
//!    filters on both. Deleting either half of that `WHERE` still keeps a
//!    suppressed person out of the queue — which is the shape you want a legal
//!    boundary in, and it is why the check here is a third lock rather than the
//!    only one.
//! 2. **The contact budget.** `max_new_contacts_per_day` off the role pack,
//!    minus what today has already spent. It is a **limit an operator raises**,
//!    so a queue is truncated to it and never padded up to it — and
//!    `sales_development()` ships it at `0`, which makes the honest answer for
//!    an unconfigured employee an empty file.
//! 3. **May this employee send email at all.** [`ActionKind::EmailSend`] must be
//!    proposable and [`Channel::Email`] permitted. The per-segment channel
//!    *choice* stays in [`sell`](crate::vertical::sell), which has the segment;
//!    a Smartlead list is an email list by construction.
//!
//! # Running it twice
//!
//! The founder will. Idempotence is the `contacts` table and not a file this
//! module writes for itself: [`record_queued`] calls
//! [`mark_contacted`](agentos_store::revenue::mark_contacted) with
//! `next_follow_up_at = now + `[`FOLLOW_UP_AFTER`], which is the same spacing
//! [`Sequence::due`](crate::revenue::Sequence) meters, so the second run's
//! [`contacts_due_for_follow_up`](agentos_store::revenue::contacts_due_for_follow_up)
//! does not return them.
//!
//! **Commit [`record_queued`] before writing the file.** Both orders can fail
//! and they fail differently: mark-then-write loses a prospect for three days
//! when the disk is full, write-then-mark mails them twice when the commit is.
//! A prospect who gets the same cold email twice reports it, and a sending
//! domain does not recover from that on a schedule.
//!
//! # Who calls this, and why only one thing can
//!
//! `apps/server/src/routes/queue.rs` — `POST /v1/employees/{id}/queue/export`,
//! and nothing else in the workspace. That rule above admits exactly one shape:
//! the mark has to commit before the bytes exist, so the bytes have to be handed
//! to somebody in the same breath, so the caller has to be a request rather than
//! a cadence. [`crate::vertical::selling_turn`]'s docs make the argument from the
//! other end and name this route.
//!
//! The route holds one transaction across [`due`], [`suppression`], [`plan`],
//! [`record_queued`] and [`csv`], so there is no state in which somebody is
//! marked contacted and the file that says so does not exist. What it hands back
//! is JSON with the CSV in it, so that the API stack's idempotency layer — which
//! stores `jsonb` — can replay the exact bytes of a response that was lost in
//! flight. That is where the residual risk of mark-then-write actually goes.
//!
//! [`due`] is where a [`Ready`] comes from: `contacts` that are due, joined to
//! the opener their account's newest fresh finding came to.
//! [`file_finding`](crate::vertical) stores that opener when the turn renders
//! it; see `0035_evidence_opener.sql` for why it lives on the `evidence` row and
//! not in a queue table.
//!
//! # The September sink: what is built, and what the founder still owes it
//!
//! [`push`] is built and wired; the **adapter behind the trait is not**, and the
//! two open items at the end of this list are why. The shape, from the live tool
//! schemas:
//!
//! * **Endpoint.** `POST /api/v1/campaigns/{campaign_id}/leads`, MCP
//!   `add_leads_to_campaign`. Body is `{ lead_list: [...], settings: {...} }`,
//!   **max 100 leads per request** — so a sink chunks `&[Lead]` by 100.
//! * **Per lead.** `email`, `first_name`, `last_name`, `company_name`,
//!   `phone_number`, `website`, `linkedin_profile`, `location` — the eight
//!   [`COLUMNS`] under the same names — plus `custom_fields: object`, which is
//!   where the last two go: `{"objet_email": …, "angle_email": …}`. There is
//!   also a `company_url` the CSVs do not use; leave it out.
//! * **`settings` is a legal boundary in a JSON object.** It takes
//!   `ignore_global_block_list`, `ignore_unsubscribe_list` and
//!   `ignore_duplicate_leads_in_other_campaign`. **The first two must be sent
//!   `false`, explicitly, never omitted and never `true`** — they are a
//!   documented way to mail someone who opted out, and a default nobody wrote
//!   down is a default that changes. The third is Smartlead's own copy of
//!   [`record_queued`]'s job and should be `false` too, so a duplicate is an
//!   error we see rather than a silent skip.
//! * **Sequences.** `save_campaign_sequences` takes `seq_variants` with
//!   `subject` and `email_body`. The campaign's subject is `{{objet_email}}` and
//!   its body `{{angle_email}}`; both come off the lead's `custom_fields`. The
//!   founder writes that sequence **once**, by hand, and this module never
//!   touches it — `save_campaign_sequences` overwrites live copy for every lead
//!   already in the campaign.
//! * **Credentials.** One `SMARTLEAD_API_KEY`, through
//!   [`crate::secrets`] like every other provider secret, never a literal. It is
//!   account-wide and unscoped: the same key that adds a lead can delete a
//!   campaign, so the sink must only ever call the one endpoint above.
//! * **What the founder has to decide,** and none of it is inferable:
//!   1. **Which `campaign_id`.** There is one campaign per segment already
//!      (`smartlead_associations_ectaa`, `_dmw`, `_fidi`, `_hongkong`,
//!      `_chine`) times two sending domains (`getorizn.com`, `oriznapi.uk`).
//!      The producer has no segment→campaign map and must not guess one.
//!   2. **Whether the sink sends at all, or only stages.** Adding leads to an
//!      *active* campaign starts mailing them on the next schedule tick. Adding
//!      to a paused one does not. Staging into a paused campaign keeps the
//!      human review step that the CSV era had for free.
//!   3. **`first_name` / `last_name` are `required` in the API and empty in
//!      every one of the founder's CSVs** — 0 of 32 ECTAA rows, 0 of 301 DMW
//!      rows have one, because these are `info@`/`contact@` inboxes. Empty
//!      strings are what the CSV upload sends today; whether the API accepts
//!      them is one call to find out, and if it does not the fallback is a
//!      decision about salutation, not a code change.
//!   4. **Which read endpoint lists the people who unsubscribed.**
//!      [`reconcile_opt_outs`] needs one and this codebase does not name it,
//!      because nobody here has looked at the live API — deliberately. It is the
//!      second of the two things an adapter cannot be written without, and it is
//!      the more important one: a campaign that mails is recoverable, an
//!      unsubscribe we never collected is not.
//!
//!      **This one no longer depends on anybody remembering it.**
//!      [`crate::catalog::OptOuts`] is a mandatory field on every catalogue
//!      entry, so a Smartlead connector cannot be added without naming where its
//!      opt-outs come in — and there is no "not wired yet" value to put there.
//!      The endpoint is still missing; what has changed is that the missing
//!      endpoint is now a build failure rather than a thing somebody meant to
//!      ask about. See that enum for where the line "this connector sends" falls
//!      and why the catalogue is what draws it.
//!
//! Items 1 and 4 are what stand between
//! [`LeadSink`](agentos_providers::leads::LeadSink) and a real adapter. Nothing
//! above them is blocked on anything: [`push`] and [`reconcile_opt_outs`] are
//! written, tested against the mock, and reached by
//! `apps/server/src/routes/queue.rs` the moment an operator grants
//! `allow_lead_upload`.
//!
//! # Fields the schema does not have
//!
//! [`Recipient`] takes all eight as strings from whoever loads the list, and
//! `crate::prospects` is now the thing that loads it. Two of them had no column
//! behind them at all; `0033_prospect_listing.sql` gave one of them one.
//!
//! * `location`. `accounts.country` is ISO 3166-1 alpha-2 with a CHECK and the
//!   founder's lists carry `États-Unis`, `Mandaluyong, Philippines`,
//!   `Portugal / Royaume-Uni`. **`accounts.location` now holds that string
//!   verbatim** and `country` is `ZZ` when nobody passed one, so the import
//!   guesses nothing and the export has the founder's own words to put back.
//! * `linkedin_profile`. Still no column anywhere, on `accounts` or `contacts` —
//!   and still no data either: it is empty in all 3,048 rows of every list. The
//!   importer counts any it meets and says so rather than storing it, which is
//!   the signal that this is the day for the migration.
//!
//! One more does not survive, and it is the importer's finding rather than this
//! module's: a `phone_number` that is not E.164 has nowhere to go, because
//! `contacts.phone` has a CHECK that exists so `revenue_suppression_of` can
//! match a number by equality. 584 of the 2,044 numbers in these lists are in
//! some other shape and are not stored. They are still in the CSVs.
//!
//! **Both halves of that rule are enforced now, and neither was when this module
//! was written.** `contacts` had no touch counter, so
//! [`MAX_TOUCHES`](crate::revenue::MAX_TOUCHES) and
//! [`Ended::Replied`](crate::revenue::Ended) were held on a `Sequence` rebuilt
//! empty every turn — a person could be mailed forever, and one who *replied*
//! stayed in the queue. `0036_contact_touches.sql` put `touch_count` on the row
//! and `mark_contacted` increments it, which is the one statement that means "we
//! just wrote to this person" — so the selling turn, the chase and
//! [`record_queued`] all count through it, and the limit bites in the
//! **selection** rather than being discovered after a turn is spent. A reply
//! clears `next_follow_up_at` from `inbound::land`, which is the only door
//! inbound mail has on any channel.
//!
//! The range this module asks for is `0..MAX_TOUCHES` and the chase asks for
//! `1..`, and the difference is not cosmetic: `prospects::import` writes
//! `next_follow_up_at = now` on every row it lands, so the overdue end of that
//! queue is the whole imported list with nobody written to yet. A bounded scan
//! from zero never reaches a real chase.

use std::collections::BTreeSet;

use agentos_domain::action::{ActionKind, Channel, EmailAddress};
use agentos_domain::ids::TenantId;
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::revenue::{self as revenue_store, RevenueError};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::effects::{Effects, EmailSend};
use crate::gate::{PolicyGate, Principal};
use crate::revenue::{Contacted, FOLLOW_UP_AFTER, Outreach, Suppression};
use crate::rolepack_sales::RolePack;
use crate::vertical::Approach;

// ---------------------------------------------------------------------------
// The row shape
// ---------------------------------------------------------------------------

/// The export's columns, in order.
///
/// The first eight are the founder's own file, byte for byte —
/// `crates/app/tests/fixtures/smartlead_getorizn_prospection.csv` is a copy of
/// the real one and a test asserts this array against its header. They are also
/// the eight fields Smartlead substitutes as `{{email}}`, `{{first_name}}`, …
/// and the eight named members of `add_leads_to_campaign`'s lead object.
///
/// The last two are Smartlead custom variables, and they are the founder's own
/// names for them: `smartlead_prospection_contexte.csv` already keys
/// `angle_email` by address. `objet_email` and `angle_email` are exactly
/// [`Outreach::subject`] and [`Outreach::body`] — there is no third string in an
/// [`Approach`] to invent an eleventh column out of.
pub const COLUMNS: [&str; 10] = [
    "email",
    "first_name",
    "last_name",
    "company_name",
    "phone_number",
    "website",
    "linkedin_profile",
    "location",
    "objet_email",
    "angle_email",
];

/// One person on the founder's list, in the shape the list is already in.
///
/// Strings and not parsed types, deliberately, for everything but the address:
/// these are directory values being passed through, and re-deriving `website`
/// from a [`Domain`](agentos_domain::action::Domain) turns
/// `https://safetywing.com` into `https://safetywing.com/`, which is an edit to
/// a file that has to load without editing. The address is an
/// [`EmailAddress`] because that is what the suppression list is keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// The `contacts` row, so [`record_queued`] can mark it.
    pub contact_id: Uuid,
    /// Where the approach goes.
    pub email: EmailAddress,
    /// Empty in every one of the founder's lists so far; these are shared
    /// inboxes.
    pub first_name: String,
    /// See [`Recipient::first_name`].
    pub last_name: String,
    /// How they spell their own name.
    pub company_name: String,
    /// As the list has it, not normalised to E.164 — the CSVs carry
    /// `(632)826-0359` alongside `+441842816600` and Smartlead takes both.
    pub phone_number: String,
    /// Their site, verbatim.
    pub website: String,
    /// No column behind this one; see the module docs.
    pub linkedin_profile: String,
    /// Free text. No column behind this one either.
    pub location: String,
}

/// A prospect the seller could write to today, and the opener it would send.
///
/// The [`Approach`] is the load-bearing half: it cannot exist without a
/// reproduced [`Evidence`](crate::proof_of_need::Evidence), so neither can a
/// [`Lead`].
#[derive(Debug, Clone)]
pub struct Ready {
    /// Who.
    pub who: Recipient,
    /// With what. Get one from
    /// [`Sold::Approached`](crate::vertical::Sold::Approached)'s evidence.
    pub approach: Approach,
}

/// One row of the export.
///
/// Private fields and no public constructor: [`plan`] is the only thing that
/// makes one, and it only makes one out of a [`Ready`]. That is the evidence bar
/// reaching the file — see the module docs.
#[derive(Debug, Clone)]
pub struct Lead {
    who: Recipient,
    opener: Outreach,
}

impl Lead {
    /// The `contacts` row this is about, for [`record_queued`].
    pub const fn contact_id(&self) -> Uuid {
        self.who.contact_id
    }

    /// Where it is going.
    pub const fn email(&self) -> &EmailAddress {
        &self.who.email
    }

    /// The ten values, in [`COLUMNS`] order.
    ///
    /// The one thing both sinks read. A sink that wanted an eleventh value would
    /// have to add it here, next to the column name it needs.
    pub fn fields(&self) -> [String; 10] {
        [
            self.who.email.to_string(),
            self.who.first_name.clone(),
            self.who.last_name.clone(),
            self.who.company_name.clone(),
            self.who.phone_number.clone(),
            self.who.website.clone(),
            self.who.linkedin_profile.clone(),
            self.who.location.clone(),
            self.opener.subject.clone(),
            self.opener.body.clone(),
        ]
    }
}

// ---------------------------------------------------------------------------
// The source
// ---------------------------------------------------------------------------

/// Everyone this tenant could write to right now, with the opener their finding
/// came to.
///
/// [`plan`]'s input, out of the tables. Three rules apply here rather than in
/// [`plan`] because they are the *database's* and a `Vec<Ready>` cannot express
/// them — see
/// [`queueable`](agentos_store::revenue::queueable) for each one; the short
/// version is due-and-active, a stored opener, and
/// [`MAX_FINDING_AGE`](crate::proof_of_need::MAX_FINDING_AGE) on the claim.
/// Everything a *caller* could get wrong stays in [`plan`].
///
/// # Where the openers come from
///
/// [`crate::vertical::file_finding`], and nowhere else. A selling turn renders
/// [`Approach::new`](crate::vertical::Approach::new) from the [`Evidence`] it
/// has and stores it on the same `evidence` row; this reads it back. The
/// evidence bar is unchanged and one link longer — the argument is on
/// `Approach::filed`, which is `pub(crate)` and which this function is the only
/// caller of.
///
/// `limit` bounds the scan, not the export: [`plan`] truncates to the contact
/// budget afterwards. Pass something comfortably above the budget so a run of
/// suppressed addresses cannot starve it.
pub async fn due(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<Ready>, RevenueError> {
    let rows =
        revenue_store::queueable(tx, now, now - crate::proof_of_need::MAX_FINDING_AGE, limit)
            .await?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            // The column has a CHECK and the importer parses, so an address that
            // will not parse is a row written by something that did neither.
            // Skipped rather than failed, exactly as `due_prospect` skips one:
            // one bad address must not cost the founder his morning's file.
            let Ok(email) = EmailAddress::parse(&row.email) else {
                tracing::warn!(
                    contact_id = %row.contact_id,
                    "a contact's address will not parse; it is left out of the export"
                );
                return None;
            };
            // `contacts.full_name` is the import's `"first last"`, trimmed, and
            // empty for the `info@` inboxes that are most of these lists. Split
            // back at the first space so a row of the founder's own file makes
            // the round trip; nothing is invented for a row that has no name,
            // which is what Smartlead's required `first_name` will have to be
            // told about in September.
            let (first_name, last_name) = row
                .full_name
                .split_once(' ')
                .map_or((row.full_name.as_str(), ""), |(a, b)| (a, b));
            Some(Ready {
                who: Recipient {
                    contact_id: row.contact_id,
                    email,
                    first_name: first_name.to_owned(),
                    last_name: last_name.to_owned(),
                    company_name: row.company_name,
                    phone_number: row.phone.unwrap_or_default(),
                    website: row.website.unwrap_or_default(),
                    // No column anywhere, on `accounts` or `contacts`, and no
                    // data either — empty in all 3,048 rows of every list. See
                    // the module docs.
                    linkedin_profile: String::new(),
                    location: row.location.unwrap_or_default(),
                },
                approach: Approach::filed(
                    Outreach {
                        subject: row.opener_subject,
                        body: row.opener_body,
                    },
                    row.known_good_at,
                ),
            })
        })
        .collect())
}

/// The suppression list, for exactly the people about to be exported.
///
/// The batch twin of
/// [`suppression_for`](crate::vertical::suppression_for), through the same
/// `SECURITY DEFINER` lookup for the same reason — a plain `SELECT` over
/// `suppressions` cannot see a **global** suppression at all.
///
/// It differs from that one in how it fails, and deliberately. `suppression_for`
/// judges one address and fails closed by suppressing it, because the cost is
/// one prospect losing a cadence. This is called inside the transaction that is
/// about to mark everybody contacted, so a list that will not answer is an
/// error: export nobody, mark nobody, commit nothing.
pub async fn suppression(
    tx: &mut TenantTx<'_>,
    ready: &[Ready],
) -> Result<Suppression, RevenueError> {
    let addresses: Vec<String> = ready.iter().map(|r| r.who.email.to_string()).collect();
    let mut list = Suppression::new();
    for raw in revenue_store::suppressed_among(tx, &addresses).await? {
        // The lookup echoes back the string it was given, and every one of them
        // came out of an `EmailAddress` a moment ago, so a parse failure here is
        // unreachable rather than optimistic.
        if let Ok(address) = EmailAddress::parse(&raw) {
            list.suppress(address);
        }
    }
    if !list.is_empty() {
        tracing::info!(
            suppressed = list.len(),
            "addresses on the suppression list are left out of the export"
        );
    }
    Ok(list)
}

// ---------------------------------------------------------------------------
// The producer
// ---------------------------------------------------------------------------

/// Decide who is written to today and with what. **The seam.**
///
/// Pure, and it names no sink. See the module docs for the three refusals it
/// applies and why they are the send path's own rather than copies.
///
/// `spent_today` is how much of `max_new_contacts_per_day` today has already
/// used — count it with
/// [`contacted_since`](agentos_store::revenue::contacted_since) from the start
/// of the operator's day. Passing `0` on every run turns a daily limit into a
/// per-run one, which is the same number meaning something else.
pub fn plan(
    ready: Vec<Ready>,
    pack: &RolePack,
    suppression: &Suppression,
    spent_today: u32,
) -> Vec<Lead> {
    if !pack.may_propose(ActionKind::EmailSend)
        || !pack.limits().allowed_channels.contains(&Channel::Email)
    {
        return Vec::new();
    }

    let budget = pack
        .limits()
        .max_new_contacts_per_day
        .saturating_sub(spent_today);

    // ponytail: the within-batch dedupe is belt to the database's braces —
    // `contacts_email_key unique (tenant_id, email)` already makes two rows for
    // one address impossible, so this only catches a caller that assembled
    // `ready` from somewhere else. One line, and the alternative is trusting
    // every future caller.
    let mut seen: BTreeSet<EmailAddress> = BTreeSet::new();

    ready
        .into_iter()
        // First, exactly as in `Seller::touch`. Before the budget too, so a
        // suppressed address cannot spend a slot a contactable one wanted.
        .filter(|ready| !suppression.contains(&ready.who.email))
        .filter(|ready| seen.insert(ready.who.email.clone()))
        .take(budget as usize)
        .map(|ready| Lead {
            opener: ready.approach.message().clone(),
            who: ready.who,
        })
        .collect()
}

/// Everyone in the queue has been written to at `now`; chase them again in
/// [`FOLLOW_UP_AFTER`].
///
/// **Commit this before the file is written.** See the module docs.
///
/// Refuses an inactive contact with
/// [`StoreError::NotFound`](agentos_store::db::StoreError) — which is what a
/// contact suppressed between [`plan`] and here looks like, and the right answer
/// is to abort the whole transaction rather than export the rest.
pub async fn record_queued(
    tx: &mut TenantTx<'_>,
    leads: &[Lead],
    now: DateTime<Utc>,
) -> Result<(), RevenueError> {
    for lead in leads {
        revenue_store::mark_contacted(tx, lead.contact_id(), now, Some(now + FOLLOW_UP_AFTER))
            .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sink: the file the founder loads today
// ---------------------------------------------------------------------------

/// RFC 4180, which is also what the founder's own files are: CRLF line endings,
/// a quoted field only when it needs quoting, and a doubled `"` inside one.
///
/// ponytail: no `csv` crate. This is the writing half of RFC 4180 and it is
/// eight lines; the reading half is where a parser earns its place, and nothing
/// here reads CSV.
pub fn csv(leads: &[Lead]) -> String {
    let mut out = String::new();
    push_row(&mut out, COLUMNS.iter().copied());
    for lead in leads {
        push_row(&mut out, lead.fields().iter().map(String::as_str));
    }
    out
}

// ---------------------------------------------------------------------------
// Sink: the platform call, from 2026-09-01
// ---------------------------------------------------------------------------

/// Hand every lead to the sending platform, one gated call each.
///
/// **The second sink, and [`plan`] did not move.** It reads the same
/// `&[Lead]` [`csv`] reads and the same two arrays [`csv`] reads —
/// [`COLUMNS`] and [`Lead::fields`], zipped, which is literally what
/// `push_row` does five lines further down with a comma instead of an HTTP
/// request. Neither sink can name an eleventh column, because there is one
/// array of names in this workspace and both borrow it.
///
/// There is still no `Sink` trait, and the reason the module docs gave has
/// survived contact: these two functions share no signature. One returns a
/// `String` and cannot fail; this one is `async`, needs the gate, needs a
/// principal, and returns **one outcome per recipient** — the same
/// [`Contacted`] [`Seller::campaign`](crate::revenue::Seller::campaign) returns,
/// deliberately, so that an operator's dashboard counts `sent` / `refused` /
/// the deny code in the same labels whichever sink ran. What they share is the
/// slice, and the slice is the seam.
///
/// # The gate, per prospect, and which budget it spends
///
/// Every lead is authorised on its own as an [`ActionKind::EmailSend`] against
/// its own address — not one ruling for the batch — because that is what makes
/// the counterparty land in the audit payload, and the counterparty *is* the
/// cold-outreach budget: [`PolicyGate`](crate::gate::PolicyGate) derives
/// `new_contacts_today` by aggregating `audit_log` on it. A batch ruling would
/// spend one contact for forty people.
///
/// **So this path spends two different counters and they are not the same
/// number.** Worth stating plainly, because the export path spends only one:
///
/// * [`contacted_since`](agentos_store::revenue::contacted_since) — contacts
///   *written to*, off the `last_contacted_at` column [`record_queued`] writes.
///   This is what [`plan`]'s `spent_today` argument measures and what truncates
///   the queue before anything reaches here.
/// * the gate's own count over `audit_log`, which no `contacts` column feeds and
///   which only ever advances when the gate allows something. The CSV export
///   never touches it — the founder's upload is invisible to the audit trail —
///   so before this sink exists the two disagree by exactly the size of every
///   export ever run.
///
/// Neither of them is
/// [`new_contacts_since`](agentos_store::revenue::new_contacts_since), which
/// counts rows *created* in `contacts` and is what
/// [`crate::prospects::import`] spends. Importing a list and writing to it are
/// two different acts against one number, and this is the one that writes.
///
/// The two counters cannot double-charge one person on one day: `plan` offers
/// nobody twice — `record_queued` moves them out of `queueable` for
/// [`FOLLOW_UP_AFTER`] — and the gate charges only a
/// [`ContactStanding::New`](agentos_domain::action::ContactStanding), so a
/// prospect already in the trail is free forever after. What they *can* do is
/// disagree in the safe direction, and only in it: a tenant that exported forty
/// people this morning has `spent_today = 40` and an audit count of zero, so the
/// afternoon's push is truncated by the larger number. Nothing here re-widens
/// it.
///
/// # Marked before staged, which is the module's rule and not a new one
///
/// The caller commits [`record_queued`] **before** calling this, exactly as it
/// commits before writing the file. That is forced rather than chosen:
/// [`PolicyGate::authorize`](crate::gate::PolicyGate::authorize) opens and
/// commits its own transaction, so no ruling can join the export's, and holding
/// a transaction open across an HTTP call is the thing
/// [`crate::effects`] refuses to do anyway.
///
/// What it costs is unchanged and already argued: a crash between the commit and
/// the platform call loses a prospect for [`FOLLOW_UP_AFTER`]. What it buys is
/// that the reverse — staging first — mails a stranger the same cold email
/// twice, and a sending domain does not recover from that on a schedule.
///
/// A [`Contacted::Refused`] here is that same loss with a reason attached: the
/// person is marked contacted and was not written to. It should be rare, because
/// `plan` already truncated to the budget the gate is about to measure — and
/// when it is not rare it is the two counters above having drifted, which is a
/// number an operator can read off the response rather than a mystery.
pub async fn push(
    gate: &PolicyGate,
    effects: &Effects,
    principal: &Principal,
    leads: &[Lead],
) -> Vec<Contacted> {
    let mut outcomes = Vec::with_capacity(leads.len());

    for lead in leads {
        let to = lead.email().clone();
        // The seam, in one expression: the producer's names against the
        // producer's values. Held in a local because `fields()` returns owned
        // strings and the borrow has to outlive the call.
        let values = lead.fields();
        let row: Vec<(&str, &str)> = COLUMNS
            .iter()
            .copied()
            .zip(values.iter().map(String::as_str))
            .collect();

        // Trusted, and this is the one place it differs from
        // [`crate::vertical::sell`]. That path labels its approach untrusted
        // because the *decision* to write came from reading the prospect's own
        // site inside the same turn. Here the decision was made by a turn that
        // is long over, filed on an `evidence` row, and re-selected by an
        // operator pulling this route — the same authenticated request that
        // authorises the export. A stranger's page cannot reach this call site,
        // and labelling it untrusted anyway would put a taint in the trail that
        // points at nothing.
        let subject = EmailSend { to: to.clone() };
        match gate.authorize(principal, subject).await {
            Ok(ok) => match effects.stage_lead(ok, &row).await {
                Ok(message_id) => outcomes.push(Contacted::Sent { to, message_id }),
                Err(why) => outcomes.push(Contacted::Failed { to, why }),
            },
            Err(why) => outcomes.push(Contacted::Refused { to, why }),
        }
    }

    outcomes
}

/// Bring the platform's unsubscribes home, and make them final.
///
/// **This is the half that makes the send path lawful**, and it is four
/// statements because the schema already does the work. A person who clicks
/// unsubscribe in a campaign mail told *the platform*; nothing about that click
/// reaches `suppressions` unless something goes and asks.
///
/// What one row here does, by trigger, in the same statement
/// (`suppressions_deactivate_contacts` in `0011_revenue.sql`):
///
/// * every matching `contacts` row goes `active = false` **and**
///   `next_follow_up_at = NULL`. So they leave [`queueable`](agentos_store::revenue::queueable)
///   — which filters on both — and they leave it for good;
/// * `mark_contacted` refuses an inactive contact, so even a lead already in a
///   half-built export cannot be marked;
/// * `contacts_reject_suppressed` refuses to insert or reactivate them, so a
///   re-import of the founder's CSV cannot bring them back;
/// * `suppressions` is append-only for everybody including superusers
///   (`suppressions_append_only`), so "for good" is enforced rather than
///   promised.
///
/// # Every channel, not just email
///
/// The row is `channel = 'email'` because an address is what the platform
/// knows, and [`revenue_suppression_of`] matches an email row against an email
/// address only. That would be a hole if the suppression list were the only
/// lock — somebody who unsubscribed by mail could still be called. It is not:
/// the trigger deactivates the **contact**, and `contacts.phone` lives on that
/// same row, so there is no route left to their number either. The contact row
/// is the join every channel goes through, which is why deactivating it is a
/// stronger statement than any per-channel list could be.
///
/// [`Scope::Tenant`](agentos_store::revenue::Scope) and not `Global`: they
/// unsubscribed from *our* campaign, which is a sentence about this tenant.
/// `Global` binds every tenant in the deployment forever and is what a
/// "remove me from everything" request means — a strictly larger claim than the
/// one the click made, and not ours to infer on somebody's behalf.
///
/// # Where it runs, and why not on a cadence
///
/// At the top of the export route, before [`due`] is asked anything. The moment
/// the answer matters is the moment a file is about to be built, and a cadence
/// that ran an hour ago is a cadence that can be an hour wrong — in the
/// direction of mailing somebody who has already asked us not to. Running it
/// here also means the export and the reconcile cannot get out of order,
/// because there is only one order.
///
/// The read happens **outside** any transaction and the writes inside one: a
/// database transaction must not be held open across a call to a third party.
/// A platform that will not answer fails the whole pull rather than exporting
/// against a stale list, which is the same "export nobody, mark nobody, commit
/// nothing" [`suppression`] already chooses.
///
/// Returns how many addresses the platform named — not how many rows were new,
/// because `suppress` is `ON CONFLICT DO NOTHING` and re-recording an opt-out we
/// already hold is the ordinary case rather than a fact worth counting.
pub async fn reconcile_opt_outs(
    db: &Db,
    effects: &Effects,
    tenant: TenantId,
    now: DateTime<Utc>,
) -> Result<usize, RevenueError> {
    let addresses = effects.opted_out().await.map_err(|err| {
        StoreError::conflict(format!(
            "the sending platform's opt-out list could not be read: {err}"
        ))
    })?;
    if addresses.is_empty() {
        return Ok(0);
    }

    let mut tx = db.tenant_tx(tenant).await?;
    let mut recorded = 0;
    for raw in &addresses {
        // Parsed rather than trusted: `suppressions_address_normalised` CHECKs
        // the shape, so an address the platform spells differently would fail
        // the INSERT and take the whole reconcile — and everybody else's
        // opt-out — down with it. `EmailAddress::parse` lower-cases both
        // halves, which is the spelling the column and the lookup agree on.
        let Ok(address) = EmailAddress::parse(raw) else {
            // Not fatal, and loud. One unparseable entry must not cost the
            // other opt-outs their row; it also must not pass silently, because
            // the person behind it is still on the platform's list and no
            // longer on ours.
            tracing::error!(
                "the sending platform named an address we cannot parse; it is NOT suppressed \
                 here and must be recorded by hand"
            );
            continue;
        };
        revenue_store::suppress(
            &mut tx,
            Uuid::now_v7(),
            &revenue_store::NewSuppression {
                scope: revenue_store::Scope::Tenant,
                channel: revenue_store::Channel::Email,
                address: &address.to_string(),
                reason: "opt_out",
                // We know the address, not which `contacts` row it was — and
                // the trigger does not need one: it matches on the address.
                contact_id: None,
                // The legal record of where this came from. This row is the
                // audit line for `Effects::opted_out`, which writes none of its
                // own; see that method.
                note: Some("unsubscribed on the outbound sending platform"),
                suppressed_at: now,
            },
        )
        .await?;
        recorded += 1;
    }
    tx.commit().await?;

    tracing::info!(
        addresses = recorded,
        "the sending platform's unsubscribes are recorded here; those contacts are deactivated \
         on every channel"
    );
    Ok(recorded)
}

fn push_row<'a>(out: &mut String, fields: impl Iterator<Item = &'a str>) {
    for (n, field) in fields.enumerate() {
        if n > 0 {
            out.push(',');
        }
        if field.contains([',', '"', '\n', '\r']) {
            out.push('"');
            for c in field.chars() {
                if c == '"' {
                    out.push('"');
                }
                out.push(c);
            }
            out.push('"');
        } else {
            out.push_str(field);
        }
    }
    out.push_str("\r\n");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::PolicyLimits;
    use agentos_store::db::Db;
    use chrono::TimeDelta;

    use super::*;
    // The seller's own bar on how old a look at a prospect's page may be. Not
    // the authority's bar: that is `MAX_AUTHORITY_AGE`, and it guards a claim
    // nothing in this file may assert.
    use crate::proof_of_need::MAX_FINDING_AGE;

    /// The real thing, copied out of `~/Desktop/VOYAGEURS`: the header, a plain
    /// row, a row whose `company_name` contains a comma, and a row that is not
    /// ASCII. CRLF, no BOM, exactly as the founder's file is.
    const REAL: &str = include_str!("../tests/fixtures/smartlead_getorizn_prospection.csv");

    fn address(raw: &str) -> EmailAddress {
        EmailAddress::parse(raw).expect("address")
    }

    /// The sales pack with cold outreach switched on, which is what an operator
    /// raising `max_new_contacts_per_day` does.
    fn pack(budget: u32) -> RolePack {
        let sales = RolePack::sales_development();
        let limits = PolicyLimits {
            max_new_contacts_per_day: budget,
            ..sales.limits().clone()
        };
        sales.with_limits(limits)
    }

    fn ready(email: &str, company: &str, approach: Approach) -> Ready {
        Ready {
            who: Recipient {
                contact_id: Uuid::now_v7(),
                email: address(email),
                first_name: String::new(),
                last_name: String::new(),
                company_name: company.to_owned(),
                phone_number: String::new(),
                website: String::new(),
                linkedin_profile: String::new(),
                location: String::new(),
            },
            approach,
        }
    }

    // -- the fixture -------------------------------------------------------

    #[test]
    fn the_first_eight_columns_are_the_founders_own_header() {
        let header = REAL.lines().next().expect("header");
        assert_eq!(
            header.split(',').collect::<Vec<_>>(),
            &COLUMNS[..8],
            "the export's first eight columns must be the file the founder \
             already uploads, in order and spelling"
        );
        assert_eq!(
            &COLUMNS[8..],
            ["objet_email", "angle_email"],
            "and the only additions are the two Smartlead custom variables"
        );
    }

    #[test]
    fn the_line_endings_are_the_founders_own() {
        assert!(
            REAL.contains("\r\n"),
            "the fixture lost its CRLF on the way into the repo; the test below \
             would then assert the wrong thing"
        );
        let out = csv(&[]);
        assert_eq!(out, format!("{}\r\n", COLUMNS.join(",")));
    }

    /// Split one RFC 4180 line. Twelve lines because the fixture needs it —
    /// `"Faye (Zenner, Inc.)"` is a quoted field with a comma in it, and a
    /// `split(',')` would call that two columns.
    fn split_row(line: &str) -> Vec<String> {
        let mut fields = vec![String::new()];
        let mut quoted = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    chars.next();
                    fields.last_mut().expect("field").push('"');
                }
                '"' => quoted = !quoted,
                ',' if !quoted => fields.push(String::new()),
                _ => fields.last_mut().expect("field").push(c),
            }
        }
        fields
    }

    /// The strong one: take the founder's own rows, put them through the whole
    /// path, and get the same bytes back in the first eight fields — including
    /// the quoted comma and the CJK.
    #[test]
    fn a_real_row_survives_the_round_trip_byte_for_byte() {
        let rows: Vec<&str> = REAL.lines().skip(1).collect();
        assert_eq!(rows.len(), 3, "the fixture holds three real rows");

        for row in rows {
            let values = split_row(row);
            assert_eq!(values.len(), 8, "the founder's file has eight columns");

            let lead = Lead {
                who: Recipient {
                    contact_id: Uuid::now_v7(),
                    email: address(&values[0]),
                    first_name: values[1].clone(),
                    last_name: values[2].clone(),
                    company_name: values[3].clone(),
                    phone_number: values[4].clone(),
                    website: values[5].clone(),
                    linkedin_profile: values[6].clone(),
                    location: values[7].clone(),
                },
                opener: Outreach {
                    subject: "s".to_owned(),
                    body: "b".to_owned(),
                },
            };

            let rendered = csv(std::slice::from_ref(&lead));
            let line = rendered.lines().nth(1).expect("row");
            assert_eq!(
                line,
                format!("{row},s,b"),
                "a row of the founder's file must come back out of the export \
                 unchanged, with the two custom variables appended and nothing \
                 else touched"
            );
        }
    }

    /// Not an edge case: every opener has the reproduction steps in it, one per
    /// line, so **every** `angle_email` is a multi-line field. A row that broke
    /// across lines would load as several half-rows and the founder would find
    /// out by sending them.
    #[test]
    fn a_multiline_opener_is_one_quoted_field() {
        let out = plan(
            vec![ready("a@example.com", "Co", an_approach())],
            &pack(10),
            &Suppression::new(),
            0,
        );
        let rendered = csv(&out);

        assert_eq!(
            rendered.matches("\r\n").count(),
            2,
            "the header and one row, and the newlines inside the opener are not \
             row terminators"
        );
        assert!(
            rendered.ends_with("again.\"\r\n"),
            "the opener is quoted through to its last character: {rendered}"
        );
    }

    // -- the refusals ------------------------------------------------------

    #[test]
    fn a_suppressed_address_cannot_reach_the_export() {
        let approach = an_approach();
        let out = plan(
            vec![
                ready("stop@example.com", "Stopped Ltd", approach.clone()),
                ready("keep@example.com", "Kept Ltd", approach),
            ],
            &pack(10),
            &Suppression::new().with(address("stop@example.com")),
            0,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].email(), &address("keep@example.com"));
        assert!(
            !csv(&out).contains("stop@example.com"),
            "an opted-out address must not be in the bytes the founder uploads"
        );
    }

    #[test]
    fn the_contact_budget_caps_the_queue() {
        let approach = an_approach();
        let five = || {
            (0..5)
                .map(|n| ready(&format!("p{n}@example.com"), "Co", approach.clone()))
                .collect::<Vec<_>>()
        };

        assert_eq!(plan(five(), &pack(2), &Suppression::new(), 0).len(), 2);

        // The same number, a second run in the same day. A budget that resets
        // per run is a throughput target.
        assert_eq!(plan(five(), &pack(2), &Suppression::new(), 2).len(), 0);

        // The shipped default, which is cold outreach switched off.
        assert_eq!(
            plan(
                five(),
                &RolePack::sales_development(),
                &Suppression::new(),
                0
            )
            .len(),
            0,
            "an employee whose operator has not raised the limit exports nothing"
        );
    }

    #[test]
    fn a_role_that_may_not_send_email_exports_nothing() {
        let sales = RolePack::sales_development();
        let limits = PolicyLimits {
            max_new_contacts_per_day: 10,
            allowed_channels: BTreeSet::new(),
            ..sales.limits().clone()
        };
        let out = plan(
            vec![ready("a@example.com", "Co", an_approach())],
            &sales.with_limits(limits),
            &Suppression::new(),
            0,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn one_address_twice_in_a_batch_is_one_row() {
        let approach = an_approach();
        let out = plan(
            vec![
                ready("dup@example.com", "Co", approach.clone()),
                ready("dup@example.com", "Co GmbH", approach),
            ],
            &pack(10),
            &Suppression::new(),
            0,
        );
        assert_eq!(out.len(), 1);
    }

    // -- idempotence, against the real tables ------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; queue tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let label = format!("queue-{}", tenant.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    /// One account and one contact due now.
    async fn seed_due(tx: &mut TenantTx<'_>, email: &str, now: DateTime<Utc>) -> Uuid {
        let account = Uuid::now_v7();
        let contact = Uuid::now_v7();
        revenue_store::insert_account(
            tx,
            account,
            &revenue_store::NewAccount {
                legal_name: "SafetyWing",
                domain: &format!("{}.example", contact.simple()),
                segment: "insurer",
                country: "US",
                employee_id: None,
                location: None,
                website: None,
            },
        )
        .await
        .expect("account");
        revenue_store::insert_contact(
            tx,
            contact,
            &revenue_store::NewContact {
                account_id: account,
                full_name: "Partnerships",
                email: Some(email),
                phone: None,
                role: None,
                language: Some("en"),
                is_primary: true,
                lawful_basis: "legitimate_interest",
                next_follow_up_at: Some(now),
            },
        )
        .await
        .expect("contact");
        contact
    }

    #[tokio::test]
    async fn running_twice_does_not_export_the_same_prospect_twice() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let email = format!("q{}@example.com", Uuid::now_v7().simple());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let contact = seed_due(&mut tx, &email, now).await;
        tx.commit().await.expect("commit");

        // Run one: the contact is due, so it is exported and recorded.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let due = revenue_store::contacts_due_for_follow_up(
            &mut tx,
            now,
            100,
            0..crate::revenue::MAX_TOUCHES as i64,
        )
        .await
        .expect("due");
        assert!(due.iter().any(|c| c.id == contact), "seeded contact is due");

        let mut candidate = ready(&email, "SafetyWing", an_approach());
        candidate.who.contact_id = contact;
        let leads = plan(vec![candidate], &pack(10), &Suppression::new(), 0);
        assert_eq!(leads.len(), 1);
        record_queued(&mut tx, &leads, now).await.expect("record");
        tx.commit().await.expect("commit");

        // Run two, same day, same clock.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let due = revenue_store::contacts_due_for_follow_up(
            &mut tx,
            now,
            100,
            0..crate::revenue::MAX_TOUCHES as i64,
        )
        .await
        .expect("due");
        assert!(
            !due.iter().any(|c| c.id == contact),
            "the contact was queued once and must not come back due until \
             FOLLOW_UP_AFTER has passed"
        );

        // And the budget knows about it, so a second run cannot spend the day's
        // limit again.
        let spent = revenue_store::contacted_since(&mut tx, now - TimeDelta::hours(1))
            .await
            .expect("spent");
        assert_eq!(spent, 1);
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn a_suppressed_contact_is_not_even_a_candidate() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db).await;
        let now = Utc::now();
        let email = format!("s{}@example.com", Uuid::now_v7().simple());

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let contact = seed_due(&mut tx, &email, now).await;
        revenue_store::suppress(
            &mut tx,
            Uuid::now_v7(),
            &revenue_store::NewSuppression {
                scope: revenue_store::Scope::Tenant,
                channel: revenue_store::Channel::Email,
                address: &email,
                reason: "opt_out",
                contact_id: Some(contact),
                note: Some("replied STOP"),
                suppressed_at: now,
            },
        )
        .await
        .expect("suppress");

        let due = revenue_store::contacts_due_for_follow_up(
            &mut tx,
            now,
            100,
            0..crate::revenue::MAX_TOUCHES as i64,
        )
        .await
        .expect("due");
        assert!(
            !due.iter().any(|c| c.id == contact),
            "an opt-out deactivates the contact, so the queue never sees it"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    // -- the evidence bar --------------------------------------------------

    /// The only way this test module can hold an [`Approach`].
    ///
    /// `Approach::new` takes an `&Evidence`, `Evidence` has a private seal, and
    /// the only thing that mints one is `Prober::check` behind a browser and a
    /// database. So the runtime tests above use `Approach::filed` — the same
    /// `pub(crate)` constructor [`due`] reads a stored opener back through,
    /// unreachable from any crate but this one, which is why it is not the hole.
    /// `tests/ui/queue_lead_without_evidence.rs` is the assertion that the hole
    /// is closed for everybody else.
    ///
    /// It used to be a second constructor behind `#[cfg(test)]`, byte-identical
    /// to this one. Once the export needed a real one, that was two spellings of
    /// the same hole and one of them was load-bearing.
    fn an_approach() -> Approach {
        Approach::filed(
            Outreach {
                subject: "SafetyWing: what your entry-requirements step shows for FRA → VNM"
                    .to_owned(),
                body: "line one\nline two\n\nReply STOP and I will not write again.".to_owned(),
            },
            Utc::now() - MAX_FINDING_AGE / 2,
        )
    }
}
