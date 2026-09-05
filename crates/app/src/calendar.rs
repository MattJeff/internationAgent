//! Le calendrier: the port an employee's diary is reached through, and the one
//! adapter behind it today.
//!
//! # Why this is a port and not free functions on `agentos_store::calendar`
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
//! cancellation — see `migrations/0063_appointments.sql` — and the one thing
//! that asks for it today does it as a store write and **not** as a trait
//! method: a reply landing on a thread settles the follow-up
//! [`crate::follow_up`] promised on it, from `inbound::land`, through
//! `agentos_store::calendar::cancel_for_conversation`. That stays off this
//! trait for the reason [`crate::backlog`] keeps ranking and assignment off
//! its trait: a company on Google Calendar cancels *in Google Calendar*, and a
//! port verb for it would be a second, losing cancellation beside the
//! customer's real one. An operator's cancel, the day one is asked for, is
//! `PUT /v1/calendar/{id}` writing our own table the same way.
//!
//! **Whose diary it is.** [`Calendar::book`] has no employee argument, and that
//! absence is a security property rather than an ergonomic one — see the
//! section below.
//!
//! **An idempotency key.** [`crate::backlog`]'s argument holds unchanged: the
//! one caller today is behind `apps/server`'s `replay_idempotent` layer, and a
//! key here would be a second lock on a door that has one.
//!
//! # Whose turn an appointment spends, and why it IS an `Action`
//!
//! [`Action`](agentos_domain::action::Action) is how the gate mints the right to
//! perform an effect, and `InternalSend` is in it for a precise reason the
//! `Action` enum states in as many words: waking a colleague **spends that
//! colleague's daily turn budget**. An appointment wakes somebody too, at an
//! hour somebody chose, and it spends a turn out of the same
//! `PolicyLimits::max_turns_per_day` — `loops::initiative::handle` reserves it
//! before the turn runs, on the identical path a cadence turn takes.
//!
//! **The gate has nothing to judge about *whose* time is spent**, and that has
//! not changed. The backlog's argument was *a task wakes nobody*, and it is
//! unavailable here: an appointment's entire purpose is to wake somebody. The
//! answer is that **the somebody is always the booker.** [`PgCalendar`] is built
//! around one seat and [`Calendar::book`] takes no employee, so there is no
//! argument for a caller to put another employee's id in. A `dyn Calendar` can
//! only ever promise a moment of its holder's own time and spend a turn out of
//! its holder's own budget — a budget it can already spend by existing on a
//! cadence, and one the gate is not consulted about there either. What
//! `InternalSend` is gated for is unrepresentable rather than ruled on, which is
//! why [`Action::AppointmentBook`](agentos_domain::action::Action::AppointmentBook)
//! carries no payload.
//!
//! **This module used to say "it is not an `Action` today", and the condition it
//! attached to that has now happened.** The reason given was narrow and honest:
//! *nothing an employee holds can create one* — the only write path was
//! `POST /v1/calendar`, an operator with an API key, the same authority that
//! writes charters and cadences and not a principal the gate rules on. Since
//! `turn::catalogue` grew `promise_an_hour`, an employee holds exactly such a
//! thing, so the sentence that followed applies:
//!
//! **The day an employee can book an hour, it must become one**, and not because
//! the gate acquires a new judgement about whose time is spent.
//! [`ActionKind`](agentos_domain::action::ActionKind) is not only the gate's
//! vocabulary: it is the key [`turn::catalogue`](crate::turn) is written in and
//! the alphabet every role pack's `proposable` set is spelled with. A verb
//! outside it is a verb **no policy layer can withhold from a seat and no role
//! pack can decline** — a finance clerk would hold the same power to promise a
//! stranger an hour as a seller, forever, with nothing able to say no. That is a
//! widening, so the verb arrived with a kind.
//!
//! # What that cost, in full, so the next verb can be priced
//!
//! `AppointmentBook` is one of two kinds added on 2026-08-28 (the other is
//! `InvoiceIssue`, added in parallel — both were "the sixteenth" for an hour)
//! [`ActionKind`](agentos_domain::action::ActionKind), and the whole of what it
//! touched is:
//!
//! * `crates/domain/src/action.rs` — the variant, `ALL`, `as_str`,
//!   `Action::AppointmentBook {}`, `kind`, `risk` (`Low`, in `InternalSend`'s
//!   list) and `ALL_DISCRIMINANTS`.
//! * `crates/domain/src/policy.rs` — `spends_contact_budget` (false: it reaches
//!   nobody), `always_denies` (`closed(Channel::Internal)`) and an
//!   `evaluate_rules` arm byte-identical to `InternalSend`'s. **No new
//!   `DenyReason`, no new `PolicyLimits` field, and no migration** —
//!   `0006_policy` stores channels and limits rather than action names, and
//!   `capability_decisions.action_kind` is a bare `text` column with no `CHECK`
//!   enumerating them. That was checked rather than assumed.
//! * `crates/app/src/gate.rs` — `counterparty` returns `None`: nobody is
//!   contacted, so the cold-outreach budget is neither charged nor enlarged.
//! * `crates/app/src/rolepack*.rs` — four packs take it and **two decline it**.
//!   `growth` and `entry-requirements` reach nobody outside the company, so a
//!   promise they could make is a promise to nobody. That split is the proof the
//!   kind was worth minting: it is the first discriminant the four service packs
//!   did not answer identically.
//! * `crates/app/src/turn.rs` — one catalogue row, one `Proposal` arm, one
//!   `propose` arm that parses the instant before the gate, and one `perform`
//!   arm that goes through `gated!` like every other effect.
//! * `crates/app/src/effects.rs` — a payload-free `AppointmentBook` subject
//!   written out rather than produced by the `subject!` macro, and
//!   `Effects::book_hour`, which builds its [`PgCalendar`] from the principal
//!   and never from the tool's arguments. That is what keeps every sentence
//!   above true.
//!
//! What it did **not** touch is the point: no migration, no new deny reason, no
//! new policy field, and no widening — a layer that drops `Channel::Internal`
//! takes the verb away, exactly as it takes `message_colleague` away.
//!
//! One consequence is measured elsewhere and deliberately not settled here.
//! `agentos_eval::toolchoice::{TRUSTED_PROMPT, UNTRUSTED_PROMPT}` are digests of
//! the request as sent, tool schemas included, so this row moved both of them.
//! They are **not** re-pinned in the change that moved them: the pin is the
//! certificate that the recorded tool-choice scores were measured against those
//! bytes, and re-pinning without re-running `cargo run -p agentos-eval -- --live`
//! would silently re-certify every recorded score against a prompt no model was
//! ever shown. The constants and the numbers move together or neither moves.

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
    /// The words of the promise are blank, or longer than the column takes.
    ///
    /// **Its own arm for [`CalendarError::UnknownZone`]'s reason, and it was
    /// found the way that one's sibling was.** `appointments_subject_shape` is
    /// a `CHECK` — `char_length(btrim(subject)) between 1 and 200` — and
    /// nothing above it asked, so an over-long line arrived as
    /// [`StoreError::Database`]: a 500 for the founder's `POST /v1/calendar`,
    /// and, once a turn could reach this port, the *end of the run* for an
    /// employee, because `turn::performed` maps `Unavailable` to
    /// `TurnError::Unavailable`. A model's long sentence would have cost it
    /// every remaining turn of its day.
    ///
    /// It is refused here, at the one place both callers route through, rather
    /// than in each of them: `agentos_store::calendar::MAX_SUBJECT` is the one
    /// number, and the check sits beside [`CalendarError::UnknownZone`]'s for
    /// the same reason — the caller is told *which* thing it named is wrong,
    /// before anything opens a transaction.
    #[error(
        "a subject is 1 to {} characters",
        agentos_store::calendar::MAX_SUBJECT
    )]
    SubjectShape,
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
    ///
    /// `subject` is trimmed and bounded by the adapter — see
    /// [`CalendarError::SubjectShape`] — because the bound is a fact about the
    /// table one adapter writes rather than about the port. A connected diary
    /// with a longer field of its own may say so; what it may not do is let an
    /// unbounded string reach a constraint and take a turn down with it.
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
        // Before the connection is taken, because it needs neither: the bound
        // is the table's own and is named in one place. Trimmed here too, so
        // the row and the sentence the employee is read back carry the string
        // the caller meant — the `CHECK` measures `btrim(subject)` and the
        // column would otherwise store the untrimmed one.
        let subject = subject.trim();
        if subject.is_empty() || subject.chars().count() > calendar::MAX_SUBJECT {
            return Err(CalendarError::SubjectShape);
        }
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
