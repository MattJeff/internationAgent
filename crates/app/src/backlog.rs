//! Le carnet: the port an employee's work board is reached through, and the
//! one adapter behind it today.
//!
//! # Why this is a port and not four functions on `agentos_store::backlog`
//!
//! Because of what the customer is being sold. A company that already runs on
//! Jira must be able to point its employees at *its* board, and a company that
//! runs on nothing must get one from us — and the difference between those two
//! must be **a connection setting, not a different product**. An employee says
//! "put this on the board"; where it lands is somebody else's decision, taken
//! once, out of its sight.
//!
//! That only stays true if the internal tool was built behind the seam from the
//! start. A `store::backlog::post` called directly from a turn is a call site
//! that has to be found and rewritten the day a tenant connects Jira, and by
//! then there are several. So: one trait, one adapter today, the same shape
//! `EmailProvider`, `LeadSink` and [`McpCaller`](crate::effects::McpCaller)
//! already have in this workspace.
//!
//! [`McpCaller`](crate::effects::McpCaller) is the precedent this follows most
//! closely, and for its exact reason: its adapter cannot live in
//! `agentos-providers` either, because it needs things a provider adapter may
//! not see. Here it is [`agentos_store`] — a provider crate speaks HTTP and
//! never SQL — and the day the second adapter is an MCP client the two will sit
//! on either side of this trait, which is the point of writing it now.
//!
//! # What this port requires of every adapter, and why it is a type
//!
//! **Everything it hands back is [`Untrusted`].** That is the whole of the
//! obligation, it is unconditional, and there is deliberately nothing for an
//! adapter to *declare*.
//!
//! `EmailProvider` needed a declaration — `opt_outs`, required, with no default
//! and no value meaning "not wired" — because "where do this vendor's
//! unsubscribes arrive" is a fact about a vendor that no type can express, so
//! the only way to make silence unwritable was a required method returning an
//! enum with no cheap variant.
//!
//! "Who wrote this text" is not like that: this workspace already has a type for
//! it, and [`Untrusted<T>`] deliberately implements neither `Display` nor
//! `Deref` nor `AsRef<str>`, so there is no ergonomic path from an item's title
//! into a prompt at all. Putting the obligation in the return type rather than
//! in a declaration is strictly stronger than `opt_outs` is, because there is no
//! convenient value to write: an adapter cannot claim its board is trustworthy,
//! since the trait gives it nowhere to say so.
//!
//! And it must stay that way. A `trusted()` declaration would be a field that
//! **widens** — an adapter author under deadline writes the convenient value,
//! and a customer's Jira service desk, which anybody with a portal login can
//! file into, becomes a channel that writes instructions straight into an
//! employee's brief. The one adapter here is our own table, and it wrapped from
//! the first day — when its only writer was an operator holding an API key and
//! the wrapper looked like ceremony. **That second writer now exists**
//! ([`Effects::post_work`](crate::effects::Effects::post_work)), so an
//! employee's own words reach a colleague's brief through here, and the wrapper
//! was already where it needed to be rather than being a change somebody had to
//! remember. That is the whole of what writing it early bought, and it is worth
//! saying now that the bill has arrived.
//!
//! The price is real and is named where it is paid, in
//! `apps/server/src/loops/initiative.rs`: a turn shown its board is an untrusted
//! turn, and an untrusted turn is not offered the high-risk schemas.
//!
//! # What this port deliberately does not carry
//!
//! **The founder's ordering, and who an item is assigned to.** Those are
//! `PUT /v1/work/{id}` writing our own table, and they are not trait methods,
//! because a company on Jira ranks and assigns *in Jira*. A port method for it
//! would be a verb every future adapter has to fake against a system that has
//! its own answer — and the fake would be a second, losing ranking beside the
//! customer's real one.
//!
//! **An idempotency key on [`Backlog::post`].** `EmailProvider::send` and
//! `LeadSink::stage` carry one because a retry there mails a stranger twice.
//! A retried post is a duplicate line on a board a human reads, and the one
//! caller today is behind `apps/server`'s `replay_idempotent` layer already, so
//! a key here would be a second lock on a door that has one. Add it when an
//! adapter's own writes are not idempotent and the caller is not a request.

use async_trait::async_trait;

use agentos_domain::ids::{EmployeeId, TenantId, WorkItemId};
use agentos_domain::untrusted::Untrusted;
use agentos_providers::ProviderError;
use agentos_store::backlog;
use agentos_store::db::{Db, StoreError};

/// Why a board could not be read or written.
///
/// Two arms because there are two families of adapter and they fail differently
/// — the same split [`EffectError`](crate::effects::EffectError) makes for the
/// same reason. Squeezing a database failure into a
/// [`ProviderError::Retryable`] would mean inventing a backoff for a transaction
/// that never spoke to a provider.
#[derive(Debug, thiserror::Error)]
pub enum BacklogError {
    /// A connected board — somebody else's system, over a network.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Our own board, and our own database.
    #[error(transparent)]
    Unavailable(#[from] StoreError),
}

/// A board an employee puts work on and takes work off.
///
/// **Five methods, and they are one loop rather than five conveniences**: write
/// it down, see what is yours, see what is nobody's, take one, say it is done.
/// This started at two — the three failures `migrations/0061_work_items.sql`
/// names needed no more while the founder was the only writer and the employee
/// only read. The other three are what "an agent decides, another agent picks it
/// up and finishes it" costs, and no fewer: drop `unclaimed` and there is
/// nothing to pick up, drop `claim` and two employees do it twice, drop `close`
/// and the loop never ends.
///
/// Every one of them is a verb a connected board already has an answer for —
/// create an issue, my issues, unassigned issues, assign to me, transition to
/// done — which is the bar the module docs set for a method being on the port at
/// all. Ranking is still not here, for the same reason it never was.
#[async_trait]
pub trait Backlog: Send + Sync {
    /// Write one item down.
    ///
    /// `assignee` is `None` for an item nobody has been given yet.
    ///
    /// `author` is `None` for an operator writing through `POST /v1/work`, and
    /// `Some` for an employee filing through
    /// [`Effects::post_work`](crate::effects::Effects::post_work). It is a
    /// parameter rather than a constructor field because the two writers share
    /// one board and differ per call, and it is on the trait rather than on
    /// [`PgBacklog`] alone because a board with two classes of writer has the
    /// question whatever system it runs on — an adapter that cannot record it
    /// drops it, and that lost fidelity is a fact about the customer's Jira and
    /// not a hole in ours.
    ///
    /// **Not an authority.** Nothing anywhere reads this to decide anything;
    /// who may file for whom is settled before this is called, against the org
    /// chart as it is at that instant. See `migrations/0064`.
    async fn post(
        &self,
        title: &str,
        assignee: Option<EmployeeId>,
        author: Option<EmployeeId>,
    ) -> Result<WorkItemId, BacklogError>;

    /// What this seat still has to do, in the order the board holds them.
    ///
    /// [`Untrusted`] per item and not per call, so a caller cannot unwrap the
    /// list and keep the titles — see the module docs for why that obligation is
    /// a type rather than a declaration.
    ///
    /// **The id is here now**, and it arrived on the change this method's own
    /// doc predicted: it said an id would be a field with no reader until an
    /// employee could say "done", and [`Backlog::close`] is that. It is outside
    /// the [`Untrusted`] wrapper because it is ours — a uuid this workspace
    /// minted — while the title is the board's.
    async fn open_for(&self, assignee: EmployeeId) -> Result<Vec<Held>, BacklogError>;

    /// Open work nobody is holding, in the same order.
    ///
    /// Not scoped, and `agentos_store::backlog::unclaimed` carries the argument:
    /// the only writer that can leave an item unheld is the founder's
    /// `POST /v1/work`, so this is his undecided work and nobody else's, and a
    /// team boundary here would be answering a question he declined to answer.
    async fn unclaimed(&self) -> Result<Vec<Held>, BacklogError>;

    /// Take one unheld item for this seat. `false` is somebody was faster.
    ///
    /// **No lease, no deadline.** See `agentos_store::backlog::claim`: nobody is
    /// owed a work item the way somebody is owed a queued email, and a lease
    /// whose duration nobody can name would hand a half-done job to a second
    /// employee — the double-work claiming exists to prevent.
    ///
    /// A `bool` rather than an error, because losing a race is an *answer*: two
    /// employees reached for one item, one has it, and the other should look at
    /// the rest of the pool rather than retry.
    async fn claim(&self, item: WorkItemId, who: EmployeeId) -> Result<bool, BacklogError>;

    /// Say one item is done. `false` is "not yours", which is also what an item
    /// that does not exist answers.
    ///
    /// The assignee only — a manager that filed the work may not sign it off,
    /// and the founder who needs to has `PUT /v1/work/{id}`. One way only:
    /// nothing here reopens.
    async fn close(&self, item: WorkItemId, who: EmployeeId) -> Result<bool, BacklogError>;
}

/// What an employee does to an item that already exists.
///
/// Two variants and one type, rather than two methods on
/// [`Effects`](crate::effects::Effects) and two rows in
/// `turn::catalogue`, for [`Errand`](crate::inbound::Errand)'s reason: both take
/// exactly one argument — which item — and differ only in the verb, so one
/// schema with a closed enum costs a model one name to learn instead of two and
/// costs every prompt one description instead of two. A wrong choice between
/// them is not dangerous either: `claim` refuses anything already held and
/// `close` refuses anything not this employee's, so the two cannot be confused
/// into an effect nobody wanted.
///
/// There is deliberately no `Unclaim` and no `Reopen`. Giving work back would
/// let an employee push its own load into every colleague's brief, which is the
/// flooding the org-chart guard on filing exists to bound; reopening would let a
/// model argue with the founder about whether something was finished. Both are
/// `PUT /v1/work/{id}` and both are his.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkAction {
    /// Take an item nobody is holding.
    Claim,
    /// Say an item of this employee's own is done.
    Close,
}

impl WorkAction {
    /// The word the model writes, and the only two it may.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Close => "close",
        }
    }

    /// The model's word, parsed. `None` is anything else.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "claim" => Some(Self::Claim),
            "close" => Some(Self::Close),
            _ => None,
        }
    }
}

/// One line of a board as a turn is allowed to see it: our id, their words.
///
/// A pair rather than two parallel `Vec`s, and a named type rather than a
/// tuple, because the whole point is that the two halves have different
/// provenance and must not be zipped back together by index somewhere down the
/// line.
#[derive(Debug, Clone)]
pub struct Held {
    /// Ours. What [`Backlog::claim`] and [`Backlog::close`] name.
    pub id: WorkItemId,
    /// The board's. Never a `String` on this side of the port.
    pub title: Untrusted<String>,
}

/// Our own board: `work_items`, one company's.
///
/// Built per tenant rather than once at boot, which is why it is not a field of
/// [`Ports`](crate::effects::Ports). `Ports` is assembled before any tenant is
/// in hand and is shared by all of them; a board belongs to exactly one company
/// and is confined to it by `Db::tenant_tx`'s `SET LOCAL app.tenant_id`, which
/// is the same reason [`crate::mcp::Fleet`] is built per tenant and substituted
/// into a per-turn copy of the ports.
///
/// FOUNDER'S QUESTION, LEFT OPEN: there is no `backlog_bindings` table and no
/// `match` that chooses between this and a connected board, because no tenant
/// has one to choose. The selection point is one constructor — whoever builds a
/// `dyn Backlog` — and it is a `match` on a per-tenant row when that row exists,
/// beside `mcp_servers` and shaped like it. Inventing the table now would be
/// inventing a connection setting for a connection nobody has.
pub struct PgBacklog {
    db: Db,
    tenant: TenantId,
}

impl PgBacklog {
    /// Bind the board to the company it belongs to.
    pub const fn new(db: Db, tenant: TenantId) -> Self {
        Self { db, tenant }
    }
}

#[async_trait]
impl Backlog for PgBacklog {
    async fn post(
        &self,
        title: &str,
        assignee: Option<EmployeeId>,
        author: Option<EmployeeId>,
    ) -> Result<WorkItemId, BacklogError> {
        let id = WorkItemId::new_v7(chrono::Utc::now());
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let item = backlog::post(&mut tx, id, title, assignee, author).await?;
        tx.commit().await?;
        Ok(item.id)
    }

    async fn open_for(&self, assignee: EmployeeId) -> Result<Vec<Held>, BacklogError> {
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let items = backlog::open_for(&mut tx, assignee).await?;
        // Rolled back, not committed: a read that took no lock and wrote
        // nothing, exactly as `routes::halt::status` does it.
        tx.rollback().await?;
        Ok(items.into_iter().map(held).collect())
    }

    async fn unclaimed(&self) -> Result<Vec<Held>, BacklogError> {
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let items = backlog::unclaimed(&mut tx).await?;
        tx.rollback().await?;
        Ok(items.into_iter().map(held).collect())
    }

    async fn claim(&self, item: WorkItemId, who: EmployeeId) -> Result<bool, BacklogError> {
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let taken = backlog::claim(&mut tx, item, who).await?;
        // Committed either way: `false` is not a failure, it is the other
        // employee's claim having won, and there is nothing of ours to undo.
        tx.commit().await?;
        Ok(taken)
    }

    async fn close(&self, item: WorkItemId, who: EmployeeId) -> Result<bool, BacklogError> {
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let closed = backlog::close(&mut tx, item, who, chrono::Utc::now()).await?;
        tx.commit().await?;
        Ok(closed)
    }
}

/// One row as the port hands it over: the id kept out of the wrapper because it
/// is ours, the title kept inside because it is not.
fn held(item: backlog::Item) -> Held {
    Held {
        id: item.id,
        title: Untrusted::new(item.title),
    }
}
