//! `files`: le classeur, in SQL and with no opinion about it.
//!
//! `migrations/0067_files.sql` carries the argument for why the bytes are a
//! `bytea` in this row rather than a path on a disk or an oid in
//! `pg_largeobject`, why the name is the primary key, and why `app_role` holds
//! neither UPDATE nor DELETE. This module is the three statements underneath it:
//! file one, fetch one by name, list what a company holds.
//!
//! # Why the tenant is never a parameter
//!
//! Every function here takes a [`TenantTx`] and nothing else, for
//! [`crate::backlog`]'s reason: the tenant is the one `SET LOCAL app.tenant_id`
//! on that transaction, and a `tenant_id` argument beside it would be a second
//! answer to a question that already has one.
//!
//! # Why the digest arrives as a parameter and is not computed here
//!
//! This crate speaks SQL. Hashing is a decision about *what was deposited*,
//! taken where the depositor is —
//! [`agentos_app::files`](../../agentos_app/files/index.html) — which is also
//! where it is re-checked on the way out. What stops a caller passing a digest
//! that does not describe the bytes is not a line in this file: it is
//! `files_digest_is_the_content`, which the database evaluates on every write
//! including the ones that never come through here.
//!
//! # Why there is no `overwrite`, no `update` and no `delete`
//!
//! There are no statements for them because there are no grants for them. A
//! second deposit under a name a company already used loses the primary key and
//! arrives as [`StoreError::Conflict`], which is the whole of "first write
//! wins". See `0067`'s header for the argument, and for the four things that
//! would have to exist before an erasure route could.

use chrono::{DateTime, Utc};
use sqlx::Row;

use crate::db::{StoreError, TenantTx};

/// One row of `files` as an index reads it: everything except the bytes.
///
/// `name` and `content_type` are plain `String`s here and are wrapped by
/// [`agentos_app::files`](../../agentos_app/files/index.html) on the way to a
/// reader, not here: this crate speaks SQL, and the trust boundary is a decision
/// about a *reader*, taken where the reader is. Same split
/// [`crate::backlog::Item::title`] and [`crate::calendar::Appointment::subject`]
/// make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filed {
    /// What it was filed under. The address, and text somebody else may have
    /// typed.
    pub name: String,
    /// What the depositor said the bytes are. An assertion, not a fact.
    pub content_type: String,
    /// How many bytes. Ours: `octet_length` of the column, cast to `bigint`
    /// because Postgres answers that function in `int4` — a length this crate
    /// carried as `i64` and read as `INT4` decodes to a driver error rather
    /// than to a wrong number, which is how the cast got here.
    pub size: i64,
    /// SHA-256 of the bytes, 32 of them. Ours, and the database guarantees it
    /// describes the content — see `0067`.
    pub digest: Vec<u8>,
    /// When it was filed.
    pub created_at: DateTime<Utc>,
}

/// One file's bytes, with the two facts a reader needs beside them.
///
/// Deliberately not [`Filed`] plus a `Vec<u8>`: an index of a hundred files must
/// not be a type that could carry a hundred files' bytes, and a fetch of one
/// file has no use for its `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// What the depositor said these bytes are.
    pub content_type: String,
    /// The bytes, as they were deposited.
    pub content: Vec<u8>,
    /// The digest as it was stored, for the caller that re-derives it.
    pub digest: Vec<u8>,
}

/// File one document under one name.
///
/// The digest is the caller's, for the reason in the module docs. The size is
/// not a parameter at all — it is `octet_length` of what was actually written,
/// so nothing can record a length that disagrees with the bytes.
///
/// A name this company has already used loses the primary key and comes back as
/// [`StoreError::Conflict`] carrying `files_pkey`. That is the only way this
/// statement refuses, and it is deliberate: there is no `on conflict do update`
/// here, because that clause is the overwrite `0067` withholds the grant for.
pub async fn deposit(
    tx: &mut TenantTx<'_>,
    name: &str,
    content_type: &str,
    content: &[u8],
    digest: &[u8],
) -> Result<Filed, StoreError> {
    let row = sqlx::query(
        "INSERT INTO files (tenant_id, name, content_type, content, digest) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING name, content_type, octet_length(content)::bigint AS size, digest, created_at",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(name)
    .bind(content_type)
    .bind(content)
    .bind(digest)
    .fetch_one(&mut ***tx)
    .await?;
    Ok(row_of(&row))
}

/// The bytes filed under this name, or [`StoreError::NotFound`].
///
/// Not-found and not-this-company's are the same answer, which is what RLS makes
/// them and what they must stay: a fetch that distinguished them would be a way
/// to ask another company whether they hold a contract with a given name.
pub async fn fetch(tx: &mut TenantTx<'_>, name: &str) -> Result<Content, StoreError> {
    let row = sqlx::query("SELECT content_type, content, digest FROM files WHERE name = $1")
        .bind(name)
        .fetch_optional(&mut ***tx)
        .await?
        .ok_or(StoreError::NotFound)?;
    Ok(Content {
        content_type: row.get("content_type"),
        content: row.get("content"),
        digest: row.get("digest"),
    })
}

/// What this company holds, newest first, without the bytes.
///
/// The bytes are deliberately not selected: an index of a company's whole
/// classeur would otherwise be a single query that materialises every document
/// it has, twice — once in the backend and once in this process — which is the
/// limit `0067` names as the real cost of `bytea`.
///
/// Newest first, and not by name: the question somebody opens this on is "what
/// have we just been sent", and a name is what you use when you already know it.
///
/// ponytail: no `LIMIT` and no pagination, the same open question
/// [`crate::calendar::diary`] leaves — **and its premise has since changed.**
/// This note said a classeur a founder fills by hand is a human-scale set, and
/// that was true while an operator key was the only writer. `ingest_email` now
/// files every inbound attachment here, so the size of this set is chosen by
/// whoever writes to us. The `LIMIT` this read does not have stopped being a
/// tidiness question and became a real one.
pub async fn index(tx: &mut TenantTx<'_>) -> Result<Vec<Filed>, StoreError> {
    let rows = sqlx::query(
        "SELECT name, content_type, octet_length(content)::bigint AS size, digest, created_at \
           FROM files ORDER BY created_at DESC, name ASC",
    )
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows.iter().map(row_of).collect())
}

/// One row, decoded. By reference so both reads can name it in a `map`.
fn row_of(row: &sqlx::postgres::PgRow) -> Filed {
    Filed {
        name: row.get("name"),
        content_type: row.get("content_type"),
        size: row.get("size"),
        digest: row.get("digest"),
        created_at: row.get("created_at"),
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;

    use super::*;
    use crate::db::Db;

    /// SHA-256 without a dependency this crate does not have: the database's
    /// own, which is also the one the CHECK uses.
    async fn sha256(db: &Db, bytes: &[u8]) -> Vec<u8> {
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let digest: Vec<u8> = sqlx::query_scalar("SELECT sha256($1::bytea)")
            .bind(bytes)
            .fetch_one(&mut *admin)
            .await
            .expect("sha256");
        admin.commit().await.expect("commit");
        digest
    }

    async fn fixture() -> Option<(Db, TenantId, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the classeur needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let a = seed_tenant(&db).await;
        let b = seed_tenant(&db).await;
        Some((db, a, b))
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'classeur test')")
            .bind(tenant_id.as_uuid())
            .bind(format!("files-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");
        tenant_id
    }

    /// **The whole of "these bytes, unchanged, found by their name"**: a file
    /// survives the transaction that wrote it, comes back byte-identical, is
    /// listed without its content, and cannot be replaced by a second deposit
    /// under the same name.
    #[tokio::test]
    async fn a_filed_document_comes_back_as_it_went_in_and_cannot_be_replaced() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        // Bytes that are not text and are not valid UTF-8, because "as it is"
        // is a claim about arbitrary bytes and a `text` column could not make
        // it. 0x00 is in here on purpose: it is the byte a `text` column
        // rejects outright.
        let contract: Vec<u8> = vec![0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0xfe, 0x80, 0x0a];
        let digest = sha256(&db, &contract).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let filed = deposit(
            &mut tx,
            "signed/contract v2 (final).pdf",
            "application/pdf",
            &contract,
            &digest,
        )
        .await
        .expect("deposit");
        tx.commit().await.expect("commit");

        assert_eq!(filed.size, contract.len() as i64);
        assert_eq!(filed.digest, digest);

        // Read back in another transaction, which is the whole of "it outlives
        // the process that wrote it".
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let back = fetch(&mut tx, "signed/contract v2 (final).pdf")
            .await
            .expect("fetch");
        assert_eq!(
            back.content, contract,
            "the bytes are the bytes: this is the entire feature"
        );
        assert_eq!(back.content_type, "application/pdf");
        assert_eq!(back.digest, digest);
        assert!(
            matches!(
                fetch(&mut tx, "no such file").await,
                Err(StoreError::NotFound)
            ),
            "a name nobody filed is not found"
        );

        let listed = index(&mut tx).await.expect("index");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "signed/contract v2 (final).pdf");
        assert_eq!(listed[0].size, contract.len() as i64);
        tx.rollback().await.expect("rollback");

        // **First write wins.** A second deposit under the same name is refused
        // rather than merged, which is the only reason the row is immutable at
        // all: `app_role` has no UPDATE, so a conflict that resolved to an
        // upsert is the only way a contract could have been replaced.
        let other: Vec<u8> = b"a different document under the same name".to_vec();
        let other_digest = sha256(&db, &other).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let refused = deposit(
            &mut tx,
            "signed/contract v2 (final).pdf",
            "application/pdf",
            &other,
            &other_digest,
        )
        .await;
        assert!(
            matches!(&refused, Err(StoreError::Conflict(what)) if what == "files_pkey"),
            "a second deposit under one name must be refused: {refused:?}"
        );
        tx.rollback().await.expect("rollback");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            fetch(&mut tx, "signed/contract v2 (final).pdf")
                .await
                .expect("fetch")
                .content,
            contract,
            "…and the original is still the original"
        );
        tx.rollback().await.expect("rollback");
    }

    /// A classeur is one company's, the isolation is asserted **from the
    /// catalogue** and not only from behaviour, and the two constraints that
    /// only a writer bypassing the port can reach are asserted as that writer.
    #[tokio::test]
    async fn a_classeur_is_one_company_s_and_the_catalogue_says_so() {
        let Some((db, a, b)) = fixture().await else {
            return;
        };
        let bytes = b"A's signed contract".to_vec();
        let digest = sha256(&db, &bytes).await;

        let mut tx = db.tenant_tx(a).await.expect("tx a");
        deposit(&mut tx, "contract.pdf", "application/pdf", &bytes, &digest)
            .await
            .expect("deposit");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(b).await.expect("tx b");
        assert!(
            index(&mut tx).await.expect("index").is_empty(),
            "B must not see A's classeur"
        );
        assert!(
            matches!(
                fetch(&mut tx, "contract.pdf").await,
                Err(StoreError::NotFound)
            ),
            "…nor read one of A's files by naming it"
        );
        // And B filing under the same name is not a conflict, because B cannot
        // see that A used it. Two companies own their own namespaces.
        deposit(
            &mut tx,
            "contract.pdf",
            "application/pdf",
            b"B's own contract",
            &sha256(&db, b"B's own contract").await,
        )
        .await
        .expect("B's namespace is B's");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(a).await.expect("tx a");
        assert_eq!(
            fetch(&mut tx, "contract.pdf").await.expect("fetch").content,
            bytes,
            "…and A's file is untouched by B having used the name"
        );
        tx.rollback().await.expect("rollback");

        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = 'files'::regclass",
        )
        .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
        .await
        .expect("catalogue");
        assert!(enabled, "files has row-level security enabled");
        assert!(
            forced,
            "…and forced, or the owning role reads every company's documents"
        );

        // The two grants `0067` withholds, and neither is the one `0061` and
        // `0063` withhold on their own: those two keep UPDATE because each has
        // a state to advance. A file has none, so an UPDATE grant here would be
        // a way to replace a contract and leave a row that looks untouched.
        for verb in ["DELETE", "UPDATE"] {
            let held: bool =
                sqlx::query_scalar("SELECT has_table_privilege('app_role', 'files', $1)")
                    .bind(verb)
                    .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
                    .await
                    .expect("privilege");
            assert!(
                !held,
                "app_role must not hold {verb} on files: a deposited file is a record"
            );
        }

        // The digest CHECK, which is the psql-shaped hole the port cannot close.
        // Written as the owner, bypassing RLS and bypassing the port, which is
        // exactly the writer the constraint exists for: a digest that does not
        // describe the bytes would make every later verification meaningless.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let lied = sqlx::query(
            "INSERT INTO files (tenant_id, name, content_type, content, digest) \
             VALUES ($1, 'lying.pdf', 'application/pdf', $2, sha256('something else'::bytea))",
        )
        .bind(a.as_uuid())
        .bind(&bytes)
        .execute(&mut *admin)
        .await;
        assert!(
            lied.is_err(),
            "a digest that does not describe the bytes must not reach the table"
        );
        drop(admin);

        // …and the ceiling, asserted at the boundary rather than described. One
        // byte over `MAX_BODY_BYTES` is refused; the HTTP layer refuses far
        // less, and this is the writer that never goes through it.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let oversized = sqlx::query(
            "INSERT INTO files (tenant_id, name, content_type, content, digest) \
             VALUES ($1, 'huge.bin', 'application/octet-stream', $2, sha256($2::bytea))",
        )
        .bind(a.as_uuid())
        .bind(vec![0_u8; 1024 * 1024 + 1])
        .execute(&mut *admin)
        .await;
        assert!(
            oversized.is_err(),
            "a bytea larger than the ceiling must not reach the table"
        );
    }
}
