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
//! employee's brief. The one adapter here is our own table, whose only writer is
//! an operator holding an API key, and even *that* one wraps: the moment a
//! second writer exists the wrapper is already where it needs to be, rather than
//! being a change somebody has to remember.
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
/// Two methods, which is what the three failures `migrations/0061_work_items.sql`
/// names need and no more.
#[async_trait]
pub trait Backlog: Send + Sync {
    /// Write one item down.
    ///
    /// `assignee` is `None` for an item nobody has been given yet.
    async fn post(
        &self,
        title: &str,
        assignee: Option<EmployeeId>,
    ) -> Result<WorkItemId, BacklogError>;

    /// What this seat still has to do, in the order the board holds them.
    ///
    /// [`Untrusted`] per item and not per call, so a caller cannot unwrap the
    /// list and keep the titles — see the module docs for why that obligation is
    /// a type rather than a declaration.
    ///
    /// No item id in the answer, and that is a decision rather than an
    /// oversight: nothing can yet *close* an item from inside a turn, so an id
    /// here would be a field with no reader. It grows one in the same change
    /// that gives an employee a way to say "done".
    async fn open_for(&self, assignee: EmployeeId) -> Result<Vec<Untrusted<String>>, BacklogError>;
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
    ) -> Result<WorkItemId, BacklogError> {
        let id = WorkItemId::new_v7(chrono::Utc::now());
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let item = backlog::post(&mut tx, id, title, assignee).await?;
        tx.commit().await?;
        Ok(item.id)
    }

    async fn open_for(&self, assignee: EmployeeId) -> Result<Vec<Untrusted<String>>, BacklogError> {
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let items = backlog::open_for(&mut tx, assignee).await?;
        // Rolled back, not committed: a read that took no lock and wrote
        // nothing, exactly as `routes::halt::status` does it.
        tx.rollback().await?;
        Ok(items
            .into_iter()
            .map(|item| Untrusted::new(item.title))
            .collect())
    }
}
