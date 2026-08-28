//! Le calendrier: the port an employee's diary is reached through, and the one
//! adapter behind it today.
//!
//! # Why this is a port and not three functions on `agentos_store::calendar`
//!
//! [`crate::backlog`]'s argument, and it is *stronger* here rather than merely
//! repeated. A customer whose team already lives in Google Calendar must be able
//! to point its employees at *that* diary, and one that lives in nothing must
//! get one from us — and the difference must be **a connection setting, not a
//! different product**. An employee says "block Tuesday at three"; where the
//! hour is blocked is somebody else's decision, taken once, out of its sight.
//!
//! It is stronger here because a work board is a thing only the company reads,
//! and a diary is a thing the *counterparty* reads. A prospect who accepts an
//! invitation looks at a real calendar; a company that has one and finds its AI
//! employees keeping a second, private, invisible diary beside it has been sold
//! a toy. The day this trait has a Google adapter, every promise an employee
//! makes lands where the humans are already looking — and that day is a
//! constructor, because the seam was built first.
//!
//! # What this port requires of every adapter, and why it is a type
//!
//! **Everything it hands back is [`Untrusted`].** Unconditional, with nothing
//! for an adapter to *declare*, for exactly the reason [`crate::backlog`] gives
//! at length and which this module does not repeat.
//!
//! What it does add is the case that makes the rule concrete. A customer's
//! Calendly page is a door anybody on the internet may walk through: a stranger
//! books a slot and types the "meeting title", and that title is then in an
//! employee's diary. `Untrusted<T>` implements neither `Display` nor `Deref` nor
//! `AsRef<str>`, so there is no ergonomic path from an appointment's subject
//! into a prompt at all — the only exit is `prompt::render_fenced`, where it
//! arrives as quoted material. **A stranger who can book an hour must not
//! thereby be able to write an instruction.**
//!
//! And it must stay that way. A `trusted()` declaration would be a field that
//! **widens**, and the widening here is not theoretical: an adapter author under
//! deadline writes the convenient value for the customer's own corporate
//! calendar, and the customer's own corporate calendar is exactly the one their
//! booking page writes into.
//!
//! The price is the one `apps/server/src/loops/initiative.rs` already names for
//! the board: a turn shown its diary is an untrusted turn, and an untrusted turn
//! is not offered the high-risk schemas.
//!
//! # What this port deliberately does not carry
//!
//! **Cancelling.** `appointments.rang_at` written before the instant is a
//! cancellation — see `migrations/0063_appointments.sql` — and nothing has asked
//! for one. When something does, it is `PUT /v1/calendar/{id}` writing our own
//! table and it is **not** a trait method, for the reason [`crate::backlog`]
//! keeps ranking and assignment off its trait: a company on Google Calendar
//! cancels *in Google Calendar*, and a port verb for it would be a second,
//! losing cancellation beside the customer's real one.
//!
//! **Whose diary it is.** [`Calendar::book`] has no employee argument, and that
//! absence is a security property rather than an ergonomic one — see the
//! section below.
//!
//! **An idempotency key.** [`crate::backlog`]'s argument holds unchanged: the
//! one caller today is behind `apps/server`'s `replay_idempotent` layer, and a
//! key here would be a second lock on a door that has one.
//!
//! # Whose turn an appointment spends, and why it is not an `Action`
//!
//! [`Action`](agentos_domain::action::Action) is how the gate mints the right to
//! perform an effect, and `InternalSend` is in it for a precise reason the
//! `Action` enum states in as many words: waking a colleague **spends that
//! colleague's daily turn budget**. An appointment wakes somebody too, at an
//! hour somebody chose, and it spends a turn out of the same
//! `PolicyLimits::max_turns_per_day` — `loops::initiative::handle` reserves it
//! before the turn runs, on the identical path a cadence turn takes. So the
//! question is real and the analogy is exact.
//!
//! **The gate has nothing to judge here, and it is still not the whole
//! answer.** The backlog's argument was *a task wakes nobody*, and that one is
//! unavailable: an appointment's entire purpose is to wake somebody. This one
//! is that **the somebody is always the booker.** [`PgCalendar`] is built around
//! one seat and [`Calendar::book`] takes no employee, so there is no argument
//! for a caller to put another employee's id in. A `dyn Calendar` can only ever
//! promise a moment of its holder's own time and spend a turn out of its
//! holder's own budget — a budget it can already spend by existing on a cadence,
//! and one the gate is not consulted about there either. What `InternalSend` is
//! gated for is unrepresentable rather than ruled on.
//!
//! So **it is not an [`Action`](agentos_domain::action::Action) today**, and
//! the honest reason is narrower than that argument: *nothing an employee holds can create one.* The only write
//! path is `POST /v1/calendar`, which is an operator with an API key — the same
//! authority that already writes charters and cadences, not a principal the gate
//! rules on — and `agentos_store::calendar::book`'s `EXISTS` is what keeps it
//! inside its own company.
//!
//! **The day an employee can book an hour, it must become one**, and not because
//! the gate acquires a new judgement about whose time is spent.
//! [`ActionKind`](agentos_domain::action::ActionKind) is not only the gate's
//! vocabulary: it is the key
//! [`turn::catalogue`](crate::turn) is written in and the alphabet every role
//! pack's `proposable` set is spelled with. A verb outside it is a verb **no
//! policy layer can withhold from a seat and no role pack can decline** — a
//! finance clerk would hold the same power to promise a stranger an hour as a
//! seller, forever, with nothing able to say no. That is a widening, so the
//! verb arrives with a kind or it does not arrive.
//!
//! # The exact diff for that tool, which this change deliberately does not apply
//!
//! Applying it moves the tool catalogue, which moves
//! `agentos_eval::toolchoice::{TRUSTED_PROMPT, UNTRUSTED_PROMPT}` — digests of
//! the request as sent, whose remeasurement takes a real model call. So
//! everything under the tool is built and the tool is not, and this is what to
//! apply, in this order:
//!
//! 1. `crates/domain/src/action.rs`
//!    * `ActionKind`: add `AppointmentBook` as the sixteenth variant; `ALL`
//!      becomes `[ActionKind; 16]` and gains the entry; `as_str` returns
//!      `"appointment_book"`.
//!    * `Action`: add `AppointmentBook {}` — **a payload-free variant, and the
//!      emptiness is the argument.** Every other variant carries the parsed
//!      subject of its effect; this one's subject is the acting employee, which
//!      is in `Principal` and never in an `Action` (module rule: a variant never
//!      carries a self-description the gate then trusts). The instant is not the
//!      subject either — the gate has no opinion about three o'clock.
//!    * `Action::kind` gains its arm; `Action::risk` returns `Risk::Low`, in
//!      `InternalSend`'s list and for the same reason: what an appointment
//!      *becomes* is a turn whose brief carries the subject fenced, so the
//!      danger is at the reader and is already handled there. `High` would mean
//!      an employee that has just read a supplier's email cannot promise to call
//!      them back, which is the feature.
//!    * `Action::ALL_DISCRIMINANTS: [ActionKind; 16]`.
//! 2. `crates/domain/src/policy.rs`
//!    * `always_denies`: `ActionKind::AppointmentBook => closed(Channel::Internal)`
//!      — an appointment reaches nobody outside the company, which is exactly
//!      what `Channel::Internal` already means, and it is the channel
//!      `turn::UNCHARTERED` leans on.
//!    * `evaluate_rules`: an `Action::AppointmentBook {}` arm, byte-identical to
//!      `Action::InternalSend`'s — `allowed_channels.contains(&Channel::Internal)`
//!      or `DenyReason::ChannelNotAllowed`. No new `DenyReason`, no new
//!      `PolicyLimits` field, and **no migration**: `0006_policy` stores channels
//!      and limits, not action names.
//! 3. `crates/app/src/rolepack*.rs` — add `ActionKind::AppointmentBook` to the
//!    `proposable` set of the packs that should have it, and to the
//!    `not_proposable` half for the rest. The three
//!    `every_kind_is_decided`-style tests fail until every pack has chosen,
//!    which is the point of them.
//! 4. `crates/app/src/turn.rs`
//!    * `catalogue()` becomes `[…; 9]` with one entry: name `"promise_an_hour"`,
//!      `ActionKind::AppointmentBook`, `Risk::Low`, a description saying that
//!      it books a moment of *your own* time, that you will be woken then and
//!      only then, that the zone is required and is the *other* person's, and
//!      that nothing reminds you twice; schema
//!      `{ at: string (RFC 3339), at_zone: string (IANA name), subject: string }`.
//!    * `UNSERVED` stays at 10 and `catalogue_covers_every_proposable_kind`
//!      re-partitions on its own.
//!    * The executor is `Effects`-shaped and reaches [`Calendar::book`] with the
//!      per-turn `PgCalendar` built from the principal's own tenant and employee
//!      — never from the tool's arguments, which is what keeps every sentence
//!      above true.
//! 5. `crates/eval/src/toolchoice.rs` — re-pin `TRUSTED_PROMPT` and
//!    `UNTRUSTED_PROMPT` from a real run. **This is the step that cannot be done
//!    without a model call**, and it is why the four above are written down
//!    rather than applied.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use agentos_domain::ids::{AppointmentId, EmployeeId, TenantId};
use agentos_domain::untrusted::Untrusted;
use agentos_providers::ProviderError;
use agentos_store::calendar;
use agentos_store::db::{Db, StoreError};

/// Why a moment could not be promised or read back.
///
/// The two adapter families [`crate::backlog::BacklogError`] splits on, plus one
/// that is this port's alone.
#[derive(Debug, thiserror::Error)]
pub enum CalendarError {
    /// A connected diary — somebody else's system, over a network.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Our own diary, and our own database.
    #[error(transparent)]
    Unavailable(#[from] StoreError),
    /// The zone the promise was made in is not a name any tzdata knows.
    ///
    /// **Its own arm, and not folded into [`StoreError::NotFound`].** A promise
    /// naming an employee this company does not have and a promise naming a
    /// zone the world does not have are different mistakes: the first is
    /// indistinguishable from "not yours" and must stay silent, and the second
    /// is a typo in a field the caller controls and must say so. It is here
    /// rather than in the store's vocabulary because every adapter has the
    /// question — Google Calendar refuses an unknown zone too.
    #[error("no time zone by that name")]
    UnknownZone,
}

/// One seat's diary: the moments this employee has undertaken.
///
/// Two methods, which is what "promise an hour" needs and no more.
#[async_trait]
pub trait Calendar: Send + Sync {
    /// Promise one moment.
    ///
    /// `at` is the instant and `zone` is **whose Tuesday it is** — an IANA name,
    /// required, with no default, because a missing zone would silently mean the
    /// server's and the server's zone is nobody's.
    /// `migrations/0063_appointments.sql` carries the argument for why the two
    /// are separate facts and why storing only the instant loses the promise.
    ///
    /// There is no employee argument. See the module docs: that absence is what
    /// makes "spend somebody else's turn" unrepresentable rather than merely
    /// refused.
    async fn book(
        &self,
        at: DateTime<Utc>,
        zone: &str,
        subject: &str,
    ) -> Result<AppointmentId, CalendarError>;

    /// What this seat has promised and not yet kept, soonest first.
    ///
    /// [`Untrusted`] per appointment and not per call, so a caller cannot unwrap
    /// the list and keep the subjects — see the module docs for why that
    /// obligation is a type rather than a declaration.
    ///
    /// Each line carries the instant **as it was promised**: local wall time in
    /// the zone the promise was made in. That is the whole reason the zone is a
    /// column, and a caller that re-rendered the instant in UTC would be undoing
    /// it.
    ///
    /// No appointment id in the answer, for
    /// [`Backlog::open_for`](crate::backlog::Backlog::open_for)'s reason: nothing
    /// can yet cancel a moment from inside a turn, so an id here would be a
    /// field with no reader. It grows one in the same change that gives an
    /// employee a way to say "not any more".
    async fn upcoming(&self) -> Result<Vec<Untrusted<String>>, CalendarError>;
}

/// Our own diary: `appointments`, one seat's.
///
/// Built per tenant **and per employee**, where [`crate::backlog::PgBacklog`] is
/// built per tenant only. The extra binding is the module docs' argument made
/// structural: a board is the company's and an item on it can be anybody's, and
/// a diary is one person's and every moment in it is theirs.
///
/// Not a field of [`Ports`](crate::effects::Ports) for `PgBacklog`'s reason:
/// `Ports` is assembled before any tenant is in hand and is shared by all of
/// them, and this is confined to one company by `Db::tenant_tx`'s
/// `SET LOCAL app.tenant_id`.
///
/// FOUNDER'S QUESTION, LEFT OPEN: there is no `calendar_bindings` table and no
/// `match` that chooses between this and a connected diary, because no tenant
/// has one to choose. The selection point is one constructor — whoever builds a
/// `dyn Calendar` — and it is a `match` on a per-tenant row when that row
/// exists, beside `mcp_servers` and shaped like it. Inventing the table now
/// would be inventing a connection setting for a connection nobody has.
pub struct PgCalendar {
    db: Db,
    tenant: TenantId,
    employee: EmployeeId,
}

impl PgCalendar {
    /// Bind the diary to the seat it belongs to.
    pub const fn new(db: Db, tenant: TenantId, employee: EmployeeId) -> Self {
        Self {
            db,
            tenant,
            employee,
        }
    }
}

#[async_trait]
impl Calendar for PgCalendar {
    async fn book(
        &self,
        at: DateTime<Utc>,
        zone: &str,
        subject: &str,
    ) -> Result<AppointmentId, CalendarError> {
        let id = AppointmentId::new_v7(chrono::Utc::now());
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        // Asked before the insert so the caller is told *which* thing it named
        // does not exist. The table's CHECK refuses the same rows and stays for
        // the writer that never comes through here — see
        // `agentos_store::calendar::zone_is_real`.
        if !calendar::zone_is_real(&mut tx, zone).await? {
            // Rolled back rather than dropped: nothing was written, and a pooled
            // connection goes back deliberately.
            let _ = tx.rollback().await;
            return Err(CalendarError::UnknownZone);
        }
        let appointment = calendar::book(&mut tx, id, self.employee, at, zone, subject).await?;
        tx.commit().await?;
        Ok(appointment.id)
    }

    async fn upcoming(&self) -> Result<Vec<Untrusted<String>>, CalendarError> {
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let appointments = calendar::upcoming(&mut tx, self.employee).await?;
        // Rolled back, not committed: a read that took no lock and wrote
        // nothing, exactly as `backlog::PgBacklog::upcoming` and
        // `routes::halt::status` do it.
        tx.rollback().await?;
        Ok(appointments.into_iter().map(line_of).collect())
    }
}

/// One appointment as one line, with the wrapper kept on.
///
/// The instant and the zone are ours — a `to_char` of a column and the column
/// itself — and the subject is not, so the whole line is
/// [`Untrusted`]. `Untrusted::map` is what makes that a fact rather than a
/// convention: the subject never leaves the wrapper to be formatted, the
/// formatting happens inside it.
fn line_of(appointment: calendar::Appointment) -> Untrusted<String> {
    let when = format!("{} {}", appointment.local_time, appointment.zone);
    Untrusted::new(appointment.subject).map(|subject| format!("- {when} — {subject}"))
}
