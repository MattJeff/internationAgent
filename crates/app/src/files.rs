//! Le classeur: the port a company's documents are reached through, and the one
//! adapter behind it today.
//!
//! The founder's sentence, which is the whole specification: *"knowledge stores
//! in order to find again; nothing keeps the signed contract, as it is."*
//!
//! # What this is not, said before what it is
//!
//! [`crate::knowledge`] **indexes**. It chunks, embeds, and hands back the
//! passages a similarity search chose. That is the right shape for "what does
//! our shipping policy say" and the wrong shape for a contract: the bytes are
//! not kept, the pieces are the chunker's rather than the document's, and every
//! read is a ranking. A signed contract does not need to resemble anything. It
//! needs to be **those bytes, unchanged, retrievable by the name they were filed
//! under, and impossible to make disappear.**
//!
//! `crate::inbound::BlobStore` **was** the nearest thing that already existed,
//! and it is worth keeping the reason it lost, because from a distance it looked
//! like this module. It has since been deleted and the inbound path deposits
//! here; see the last section.
//!
//! * **It had one method and the method was `put`.** Its own doc said a reader
//!   could be added "against a real object store" when somebody needed one.
//!   Nobody did. So nothing in the workspace could hand an attachment back to
//!   anybody: the bytes went in and there was no `get` anywhere.
//! * **Its only implementation was `InMemoryBlobs`**, a `HashMap` behind a
//!   `Mutex`, and `apps/server/src/main.rs` built *that one* for the running
//!   server. A customer's attachments lived as long as the process and were
//!   gone on the next deploy.
//! * **It could not be given a tenant.** `put(&self, key, content_type, bytes)`
//!   carried the company only inside a formatted string —
//!   `inbound/<tenant>/<message>/<attachment>` — so a Postgres adapter for it
//!   would have had to *parse a tenant out of a key* to know which company's row
//!   to write. That is why the derived-key design could not be given row-level
//!   security, and it is why the merge went in this direction: `BlobStore`
//!   deleted, this port kept. Adding `get` to it would have produced a second,
//!   weaker spelling of this one, with no tenant and therefore no RLS.
//!
//! # Why this is a port and not three functions on `agentos_store::files`
//!
//! [`crate::backlog`]'s argument, unchanged: a customer whose documents already
//! live in their own S3 bucket or their own Drive must be able to point their
//! employees at *that*, and one that has nowhere must get somewhere from us —
//! and the difference must be **a connection setting, not a different product**.
//! There is no cloud account in this deployment and none will be registered, so
//! the adapter today is Postgres. The seam is built now so that the day the
//! second one exists it is a constructor rather than a hunt for call sites.
//!
//! The migration says what that day costs on the schema side: `content` drops
//! its NOT NULL and nothing else moves, because the row is the *catalogue* —
//! name, declared type, size, digest — and only the bytes travel.
//!
//! # What this port requires of every adapter, and why both halves are types
//!
//! **1. Everything it hands back is [`Untrusted`].** Unconditional, with nothing
//! for an adapter to *declare*, for the reason [`crate::backlog`] gives at
//! length and which this module does not repeat.
//!
//! What it adds is that this is the port where the rule is least arguable.
//! A work item's title and an appointment's subject are text somebody typed.
//! **Bytes a counterparty deposited are hostile input in its purest form**:
//! there is no format they are guaranteed to be in, no length a reader can
//! assume, and no honest reading of "what is this" that does not come from the
//! bytes themselves. So [`Kept::bytes`] is `Untrusted<Vec<u8>>` and not
//! `Vec<u8>`, which costs one visible `into_inner_for_rendering` at the one
//! place they leave — and that call is the reviewable moment.
//!
//! Two facts a depositor asserts and nothing verified, both of which stay
//! wrapped:
//!
//! * **The name** is a string somebody else typed. It is never parsed, never
//!   split, and never becomes a path — choosing `bytea` over a directory tree is
//!   what makes that structural rather than careful.
//! * **The declared content type** is an assertion, not a fact. Nothing sniffs
//!   the bytes and nothing checks the claim. `routes::files` therefore never
//!   echoes it as a response `Content-Type`, because a declared type that
//!   becomes a response header is a stranger choosing how a browser executes
//!   their own bytes.
//!
//! And it must stay that way. A `trusted()` declaration would be a field that
//! **widens** — and the widening here writes itself: an adapter author points
//! the port at the customer's own document library, which is exactly the library
//! everyone the customer works with can drop a PDF into.
//!
//! **2. The bytes it returns are the bytes that were deposited, checked rather
//! than asserted.** [`Files::get`] must verify the digest before it returns, and
//! [`FilesError::Corrupt`] is what it owes the caller when it does not match.
//! That obligation is written on the *trait* and not left to [`PgFiles`] on
//! purpose: today's adapter is the one that needs it least — the database
//! refuses a row whose digest does not describe its content — and the next one,
//! which fetches bytes out of somebody else's bucket over somebody else's
//! network, is the one that needs it most. The check is at the seam so that it
//! is already there on the day it starts mattering.
//!
//! # Per company, not per seat
//!
//! [`PgFiles`] is built per tenant, like [`crate::backlog::PgBacklog`] and
//! unlike [`crate::calendar::PgCalendar`], and the split is the one those two
//! already drew. A diary is one person's because every moment in it is a moment
//! *that seat* undertook, and because booking spends that seat's own turn — the
//! absence of an employee argument on `Calendar::book` is what makes spending
//! somebody else's budget unrepresentable.
//!
//! Neither half applies here. A signed contract is not anybody's personal
//! property: the seller was sent it and the finance clerk has to read it, and a
//! store scoped per seat would make that impossible — which is failure 2 of
//! `migrations/0061_work_items.sql`, reintroduced. And nothing in this module
//! wakes anybody or spends anything, so there is no budget for a seat binding to
//! protect. So: one company, one classeur, confined by `Db::tenant_tx`'s
//! `SET LOCAL app.tenant_id` exactly as the board is.
//!
//! Not a field of [`Ports`](crate::effects::Ports) for `PgBacklog`'s reason:
//! `Ports` is assembled before any tenant is in hand and is shared by all of
//! them.
//!
//! FOUNDER'S QUESTION, LEFT OPEN: there is no `file_bindings` table and no
//! `match` choosing between this and a connected store, because no tenant has
//! one to choose. The selection point is one constructor — whoever builds a
//! `dyn Files` — and it is a `match` on a per-tenant row when that row exists,
//! beside `mcp_servers` and shaped like it. Inventing the table now would be
//! inventing a connection setting for a connection nobody has.
//!
//! # What a turn may do with this, which is nothing, and why that is the answer
//!
//! **No `ActionKind`, no `Effects` method, no `turn::catalogue` row, no role
//! pack entry.** There is no path from a turn to this port at all, which is why
//! this module cannot widen an effective policy: widening needs a path.
//!
//! The tension is real and worth naming rather than skipping.
//!
//! * **Depositing** is a verb with no source. A turn produces text, not bytes.
//!   The only bytes an employee could file are ones that arrived as an
//!   attachment, and those are already stored on the way in without anybody
//!   deciding to. A tool for it would be a verb whose argument nothing can
//!   supply.
//! * **Reading** is the one somebody will ask for, and it is the one that bites.
//!   [`turn::visible`](crate::turn) drops every high-risk schema from a turn
//!   holding untrusted content, and `pay` is high-risk. So **the employee that
//!   reads the contract in order to decide whether to pay it is exactly the
//!   employee that can no longer pay** — the case where the filter costs the
//!   most is the case the tool would be built for.
//!
//! That is not an argument for making the read low-risk. It is the filter
//! working: an employee that has just been handed a document a counterparty
//! chose is precisely the employee that should not be moving money without a
//! human in the loop, and the approval path for that already exists. The honest
//! resolution of the tension is that reading a contract and paying it are two
//! turns with a person between them, not one turn with a weaker filter.
//!
//! And a third reason, which is the lazy one and is sufficient on its own: a
//! model cannot do anything with a PDF's bytes. What it can use is the *text*,
//! and [`crate::knowledge`] already puts that in front of a turn, with the taint
//! and the fencing worked out. The verb that does not exist here would have been
//! a second, worse spelling of a verb that does.
//!
//! **THE DAY SOMEBODY WANTS IT ANYWAY**, the constraint is
//! [`crate::calendar`]'s and is not negotiable: it arrives with an
//! [`ActionKind`](agentos_domain::action::ActionKind) or it does not arrive.
//! That enum is not only the gate's vocabulary — it is the key
//! [`turn::catalogue`](crate::turn) is written in and the alphabet every role
//! pack's `proposable` set is spelled with, so a verb outside it is a verb **no
//! policy layer can withhold from a seat and no role pack can decline**: a
//! finance clerk and a seller would hold the same power to pull any document the
//! company has, forever, with nothing able to say no. `calendar.rs` carries the
//! five-step diff such a change takes, step 5 of which is a re-pin of
//! `agentos_eval::toolchoice::{TRUSTED_PROMPT, UNTRUSTED_PROMPT}` from a real
//! model run — **the step nobody in an agent wave may take**, and the reason
//! that row is written down rather than applied. Nothing in this change moves a
//! tool schema, so nothing in this change moves a digest.
//!
//! # What this port deliberately does not carry
//!
//! **Erasure.** `migrations/0067_files.sql` withholds DELETE *and* UPDATE from
//! `app_role` and argues both, including the force on the other side that
//! `0061` did not have: a person's right to demand their data be erased is real.
//! The door stays shut here because erasure is lawful, rare, identified and
//! decided by a human who checked the demand — none of which is a thing a
//! request or a turn should be able to do — and because it remains possible
//! today for the owning credential at a psql prompt, which is the shape that
//! obligation actually has. The migration lists the exact four things that would
//! have to exist before a route could. It would be a route and **never a port
//! method**, for the reason [`crate::backlog`] keeps ranking off its trait: a
//! customer on their own document store erases *there*, and a port verb for it
//! would be a second, losing erasure beside the customer's real one.
//!
//! **Overwriting.** A second deposit under a name a company already used is a
//! conflict, not a merge. First write wins, and there is no spelling of
//! "replace" — which is what makes a filed document immutable at all.
//!
//! **An idempotency key.** [`crate::backlog`]'s argument holds unchanged: the
//! one caller today is behind `apps/server`'s `replay_idempotent` layer, so a
//! key here would be a second lock on a door that has one. The interesting half
//! is that this port needs it *less* than the board does — a retried deposit of
//! the same bytes under the same name is refused by the primary key rather than
//! duplicated.
//!
//! **A listing.** [`agentos_store::files::index`] is read directly by
//! `routes::files`, and that asymmetry is the port's boundary rather than a
//! shortcut — the same one `routes::calendar` and `routes::work` draw. Fetching
//! bytes is a port verb because a connected store is where the bytes would be;
//! *everything this company holds, on one screen* is this internal tool's own
//! administration surface, and it keeps working under a connected adapter
//! precisely because the row stays ours when the bytes leave.
//!
//! # The defect next door, now closed
//!
//! `ingest_email` deposits attachments **here**, and `BlobStore` is deleted. The
//! prediction the previous version of this section made was right in outline and
//! wrong in one place, which is worth recording:
//!
//! 1. It said `BlobStore::put` would take a `TenantId`. It does not — the trait
//!    is gone entirely. A tenant argument would have been the third address for
//!    a company in one call (the argument, the key, and the transaction's
//!    `SET LOCAL`), and the loop that calls it drains *every* tenant, so no
//!    port bound at startup could have been bound to the right one.
//!    `ingest_email` builds a [`PgFiles`] from `job.tenant_id` instead.
//! 2. It said `blob_key`'s output becomes the `name`, unchanged, and that the
//!    conflict a retry raises must be swallowed as success. **Both correct**,
//!    and both are what the code does. The reason the key stays derived changed,
//!    though: it was "this string becomes a path", and under `bytea` nothing
//!    becomes a path. What replaced it is stronger — a sender-chosen name would
//!    let a counterparty **squat** a company's flat first-write-wins namespace.
//! 3. **The failure mode, which was the real content of the warning.** An
//!    attachment larger than the ceiling fails the `files_content_size` CHECK;
//!    a CHECK violation has no SQLSTATE arm in `StoreError::from`, so it arrives
//!    as `StoreError::Database`, which `InboundError::is_retryable` reports as
//!    retryable. Propagating it would make a single oversized attachment into a
//!    message that can never land and a job that retries until it dead-letters.
//!    So the deposit's failure is **classified at the call site and never
//!    propagated**: a conflict is success, and everything else is a
//!    `tracing::warn!` and a message that lands anyway — *"a lost invoice is
//!    bad; losing the email that carried it is worse"*. `is_retryable` is
//!    deliberately **not** touched: the bucket is not made finer, the failure is
//!    simply never turned into an `InboundError`.
//!
//! What that costs, recorded rather than implied: a database failure during a
//! deposit that heals within milliseconds loses that attachment permanently,
//! because the message lands and the next delivery takes the `resume` branch.
//! One that does not heal costs nothing — the landing transaction fails too and
//! the job retries. The race closes by depositing inside the landing transaction
//! behind a SAVEPOINT per attachment, which is nested-transaction machinery
//! `TenantTx` does not expose today.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use agentos_domain::ids::TenantId;
use agentos_domain::untrusted::Untrusted;
use agentos_providers::ProviderError;
use agentos_store::db::{Db, StoreError};
use agentos_store::files;

/// Why a document could not be filed or fetched.
///
/// The two adapter families [`crate::backlog::BacklogError`] splits on, plus one
/// that is this port's alone.
#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    /// A connected store — somebody else's system, over a network.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Our own store, and our own database.
    #[error(transparent)]
    Unavailable(#[from] StoreError),
    /// **The bytes are not the bytes that were deposited.**
    ///
    /// Its own arm and not a [`StoreError`], because it is the one failure that
    /// is not about reaching the store: the store answered, and what it answered
    /// with does not hash to what was recorded. Nothing is retryable about it
    /// and nothing is the caller's fault.
    ///
    /// It carries **no name, no digest and no bytes**. A reader learns that the
    /// file it asked for is not intact and nothing else — the two digests are a
    /// log line for whoever operates the deployment, not a payload for whoever
    /// made the request.
    #[error("the stored bytes do not match their digest")]
    Corrupt,
}

/// One document as it was filed, without its bytes.
///
/// What [`Files::put`] hands back, so a depositor can compare the digest against
/// their own `sha256sum` and know the round trip was lossless. Ours, not a
/// counterparty's: a length we measured and a hash we computed, so neither half
/// is wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposited {
    /// How many bytes were stored.
    pub size: i64,
    /// SHA-256 of them.
    pub digest: [u8; 32],
    /// When it was filed.
    pub created_at: DateTime<Utc>,
}

/// One document, fetched.
///
/// The bytes and the declared type are wrapped and the digest is not, and that
/// line is the whole trust model of this module: we measured the hash, somebody
/// else supplied everything it describes.
#[derive(Debug, Clone)]
pub struct Kept {
    /// What the depositor said these bytes are. An assertion.
    pub content_type: Untrusted<String>,
    /// The bytes, as they were deposited, verified against the digest below
    /// before this value existed.
    pub bytes: Untrusted<Vec<u8>>,
    /// SHA-256 of [`Kept::bytes`], checked and not asserted.
    pub digest: [u8; 32],
}

impl Kept {
    /// Admit bytes only if they hash to the digest that was recorded with them.
    ///
    /// **This is how an adapter discharges obligation 2**, and it is a
    /// constructor rather than four lines each adapter writes for itself so that
    /// there is one comparison to get right and one arm to test. The fields stay
    /// public because readers need them; what this buys is that the second
    /// adapter has somewhere obvious to go, not that the struct is sealed.
    ///
    /// `recorded` is a slice rather than a `[u8; 32]` because it comes out of a
    /// `bytea` column, where a length is a fact about the row and not about the
    /// type. A recorded digest of the wrong length can never equal a SHA-256, so
    /// it fails here rather than needing an arm of its own.
    pub fn verified(
        content_type: String,
        content: Vec<u8>,
        recorded: &[u8],
    ) -> Result<Self, FilesError> {
        let digest = digest_of(&content);
        if recorded != digest {
            // The two digests go to the log and not to the caller. Neither is a
            // secret, but "which bytes changed" is a question for whoever
            // operates the deployment — and the *name* is a counterparty's text
            // that has no business on a log line either, so it is not passed in.
            tracing::error!(
                recorded = %hex(recorded),
                computed = %hex(&digest),
                "a stored file does not match its digest and was not handed back"
            );
            return Err(FilesError::Corrupt);
        }
        Ok(Self {
            content_type: Untrusted::new(content_type),
            bytes: Untrusted::new(content),
            digest,
        })
    }
}

/// A place a company's documents are kept as they are.
///
/// **Two methods, and they are the two halves of "keep this":** put it
/// somewhere, get it back. Everything else a document store could have —
/// listing, renaming, replacing, erasing — is either this internal tool's own
/// administration surface or a verb the module docs argue off the trait.
#[async_trait]
pub trait Files: Send + Sync {
    /// File one document under one name.
    ///
    /// `name` is the address and the only one; there is no id beside it.
    /// `content_type` is what the depositor says the bytes are, recorded and
    /// never verified.
    ///
    /// **A name this company has already used is refused**, as
    /// [`StoreError::Conflict`] through [`FilesError::Unavailable`]. First write
    /// wins: an adapter that overwrote would be answering a question this port
    /// does not ask, and would make every earlier deposit conditional on nobody
    /// reusing its name.
    async fn put(
        &self,
        name: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<Deposited, FilesError>;

    /// The document filed under this name.
    ///
    /// [`StoreError::NotFound`] for a name nobody filed **and** for a name
    /// another company filed — those two are one answer and must stay one, or
    /// this becomes a way to ask a competitor whether they hold a contract with
    /// a given name.
    ///
    /// **An adapter must verify before it returns.** The bytes hash to the
    /// recorded digest or this is [`FilesError::Corrupt`]; see the module docs
    /// for why that obligation is on the trait rather than on the one adapter
    /// that needs it least.
    async fn get(&self, name: &str) -> Result<Kept, FilesError>;
}

/// Our own classeur: `files`, one company's.
///
/// Built per tenant — see the module docs for why that is
/// [`crate::backlog::PgBacklog`]'s shape and not
/// [`crate::calendar::PgCalendar`]'s.
pub struct PgFiles {
    db: Db,
    tenant: TenantId,
}

impl PgFiles {
    /// Bind the classeur to the company it belongs to.
    pub const fn new(db: Db, tenant: TenantId) -> Self {
        Self { db, tenant }
    }
}

#[async_trait]
impl Files for PgFiles {
    async fn put(
        &self,
        name: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<Deposited, FilesError> {
        let digest = digest_of(bytes);
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let filed = files::deposit(&mut tx, name, content_type, bytes, &digest).await?;
        tx.commit().await?;
        Ok(Deposited {
            size: filed.size,
            digest,
            created_at: filed.created_at,
        })
    }

    async fn get(&self, name: &str) -> Result<Kept, FilesError> {
        let mut tx = self.db.tenant_tx(self.tenant).await?;
        let held = files::fetch(&mut tx, name).await?;
        // Rolled back, not committed: a read that took no lock and wrote
        // nothing, exactly as `PgBacklog::open_for` and `PgCalendar::upcoming`
        // do it.
        tx.rollback().await?;

        // The obligation, discharged through the one constructor that discharges
        // it. Nothing on this adapter can reach it today —
        // `files_digest_is_the_content` refuses the row that would trip it — and
        // that is exactly why the check lives at the seam rather than here: the
        // adapter that fetches bytes out of somebody else's bucket is the one
        // that will trip it, and it is already written.
        Kept::verified(held.content_type, held.content, &held.digest)
    }
}

/// SHA-256 of some bytes, in the one spelling both halves of the round trip use.
///
/// A free function rather than a method so that the deposit and the verification
/// cannot drift into two different hashes — which would make every stored digest
/// describe nothing and every verification pass.
pub(crate) fn digest_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A digest as text, for a log line. Never for a response body.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is the one the database computes, or the CHECK and the
    /// verification are two different hashes and neither means anything.
    ///
    /// Asserted against the published SHA-256 of `"abc"` rather than against
    /// another call to `digest_of`, which would only prove the function is
    /// deterministic.
    #[test]
    fn the_digest_is_sha256_and_not_something_that_merely_looks_like_one() {
        assert_eq!(
            hex(&digest_of(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest_of(b"abc").len(),
            32,
            "the column is 32 bytes, checked"
        );
    }

    /// **Bytes that do not match their recorded digest are not handed back.**
    ///
    /// Unit-tested against [`Kept::verified`] and not through [`PgFiles`],
    /// because no test can make this database produce such a row:
    /// `files_digest_is_the_content` refuses it, and dropping the constraint to
    /// stage one would take an `ACCESS EXCLUSIVE` lock on a table other tests in
    /// the same database are using. That is the honest shape of this test rather
    /// than a weaker one — the arm exists for the adapter that fetches bytes
    /// over somebody else's network, and this is the whole of what can be
    /// asserted before that adapter is written.
    #[test]
    fn a_document_whose_bytes_do_not_match_its_digest_is_never_handed_back() {
        let contract = b"the terms as they were signed".to_vec();
        let recorded = digest_of(&contract);

        // One byte different, which is the case a length or a name could not
        // catch: the same size, the same declared type, a different agreement.
        let mut altered = contract.clone();
        altered[4] = b'!';
        assert!(
            matches!(
                Kept::verified("application/pdf".to_owned(), altered, &recorded),
                Err(FilesError::Corrupt)
            ),
            "one changed byte must refuse the whole document"
        );

        // A recorded digest of the wrong length is refused by the same
        // comparison, with no arm of its own.
        assert!(
            matches!(
                Kept::verified("application/pdf".to_owned(), contract.clone(), b"short"),
                Err(FilesError::Corrupt)
            ),
            "a digest that is not 32 bytes cannot describe anything"
        );

        // …and the intact document passes, or the two arms above would be
        // proving that nothing is ever handed back at all.
        let kept = Kept::verified("application/pdf".to_owned(), contract.clone(), &recorded)
            .expect("intact");
        assert_eq!(kept.digest, recorded);
        assert_eq!(kept.bytes.into_inner_for_rendering(), contract);
    }

    /// A file store is only useful if it is byte-exact, so the round trip is
    /// asserted on bytes a text column could not hold at all.
    #[tokio::test]
    async fn a_document_survives_the_port_unchanged_and_a_reader_gets_it_wrapped() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the classeur needs a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        let tenant = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'classeur port test')")
            .bind(tenant.as_uuid())
            .bind(format!("cl-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");

        let classeur = PgFiles::new(db.clone(), tenant);
        // Every byte a `text` column refuses: a NUL, a lone continuation byte,
        // an unpaired surrogate's encoding.
        let contract: Vec<u8> = vec![0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0xfe, 0x80, 0x0a, 0x1b];

        let filed = classeur
            .put("le contrat signé.pdf", "application/pdf", &contract)
            .await
            .expect("put");
        assert_eq!(filed.size, contract.len() as i64);
        assert_eq!(filed.digest, digest_of(&contract));

        let back = classeur.get("le contrat signé.pdf").await.expect("get");
        assert_eq!(back.digest, filed.digest, "checked, not asserted");
        assert_eq!(
            back.bytes.into_inner_for_rendering(),
            contract,
            "these bytes, unchanged: the entire point of the module"
        );

        // A name nobody filed, and a name filed twice.
        assert!(
            matches!(
                classeur.get("nothing by that name").await,
                Err(FilesError::Unavailable(StoreError::NotFound))
            ),
            "an unfiled name is not found"
        );
        let again = classeur
            .put("le contrat signé.pdf", "application/pdf", b"a replacement")
            .await;
        assert!(
            matches!(
                &again,
                Err(FilesError::Unavailable(StoreError::Conflict(_)))
            ),
            "first write wins: {again:?}"
        );
        assert_eq!(
            classeur
                .get("le contrat signé.pdf")
                .await
                .expect("get")
                .bytes
                .into_inner_for_rendering(),
            contract,
            "…and the refused replacement changed nothing"
        );
    }
}
