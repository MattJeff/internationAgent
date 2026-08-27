//! `api_keys`: the credentials a customer holds, issued and destroyed without a
//! restart.
//!
//! `0044_api_keys.sql` is the design document; this is the four statements that
//! touch the table. Read the migration first — in particular why the digest is
//! deterministic, why revoking is a DELETE and why `app_role` holds no privilege
//! here at all.
//!
//! # Every function in this module opens an admin transaction, and that is not a
//! shortcut
//!
//! [`lookup`] runs *before there is a tenant*. It is handed a bearer token and
//! its whole job is to answer "whose is this" — so there is no `app.tenant_id`
//! to set, and `Db::tenant_tx` is not merely inconvenient, it is unanswerable.
//! [`issue`], [`revoke`] and [`list`] have a tenant but no privilege: the
//! migration revokes everything on this table from `app_role`, deliberately, so
//! that a tenant transaction which reaches this table dies with `42501` instead
//! of reading digests.
//!
//! # What stops the one query that cannot be RLS-scoped from becoming a door
//!
//! Four things, and they are cheap enough that there is no excuse not to have
//! all four:
//!
//! 1. **The transaction is `READ ONLY`.** Postgres refuses any write in it,
//!    including one a future edit adds three lines down without noticing what
//!    kind of transaction it is in.
//! 2. **The SQL is a `&'static str`.** Nothing from the request reaches the
//!    statement text — the presented token arrives as a bound `bytea`, already
//!    reduced to 32 bytes of HMAC output by `agentos_app::api_keys`, so it is
//!    not even a string by the time it gets here.
//! 3. **The projection is three columns of one table.** No `*`, no join, no
//!    dynamic identifier. Whatever a caller wanted to read through this hole,
//!    the hole is `id, tenant_id, label`.
//! 4. **It returns [`Principal`], not a row.** The type has no other
//!    constructor in this crate, so "the tenant came from the key" is a fact
//!    about the type rather than a discipline in the caller.

use agentos_domain::ids::TenantId;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::audit::{AuditActor, AuditEvent, AuditKind, append_admin};
use crate::db::{Db, StoreError};

/// Who a presented secret turned out to be.
///
/// Deliberately not `Deserialize` and with no public constructor: the only way
/// to obtain one is [`lookup`], which means the only way to obtain one is to
/// present a secret whose HMAC is a row in this table. `apps/server`'s
/// `auth::Principal` is built from this and carries the same property one layer
/// up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The row's `id`. Not the secret, and not derived from it — this is the
    /// handle a revocation names.
    pub key_id: Uuid,
    /// Whose key it is. Comes from the row and from nowhere else.
    pub tenant_id: TenantId,
    /// The key's human name, which becomes the audit actor.
    pub label: String,
}

/// One live key, as an operator sees it. **No digest**: nothing outside this
/// module ever needs the stored bytes, and a struct that carries them is a
/// struct somebody serialises into a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRecord {
    /// The handle [`revoke`] takes.
    pub id: Uuid,
    /// The key's human name.
    pub label: String,
    /// When it was issued.
    pub created_at: DateTime<Utc>,
}

/// Resolve a presented secret's digest to the tenant it speaks for.
///
/// `None` means no live key has this digest — which covers "never existed",
/// "revoked a millisecond ago" and "belongs to a tenant that was deleted", and
/// the caller must not be able to tell those apart.
///
/// # There is no cache, and the window is therefore zero
///
/// One indexed equality on a unique `bytea` per authenticated request. That is a
/// round trip the previous env-var keyring did not pay, and it buys the property
/// this whole wave exists for: the request *after* a `DELETE` commits fails.
/// Not "fails within the TTL" — fails.
///
/// A cache here would have to state its window, and every window is a window in
/// which a key somebody revoked because it was posted publicly still reads their
/// data. If this ever shows up in a profile, the fix is not a TTL: it is
/// `PgPool`'s prepared-statement cache doing its job, a covering index, or
/// pushing authentication to a gateway that shares this table. Measure first —
/// `crates/store/src/db.rs` opens with sixteen connections and this query plans
/// as an index-only scan.
pub async fn lookup(db: &Db, secret_hash: &[u8]) -> Result<Option<Principal>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    // The escape hatch, declawed. See the module docs: this is the one query in
    // the workspace that runs before anybody knows who is asking, so it is the
    // one that must be unable to do anything but read.
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;

    let row = sqlx::query("SELECT id, tenant_id, label FROM api_keys WHERE secret_hash = $1")
        .bind(secret_hash)
        .fetch_optional(&mut *tx)
        .await?;

    // Rolled back rather than committed: nothing was written, and a rollback
    // says so to anybody reading `pg_stat_activity`.
    tx.rollback().await?;

    row.map(|row| {
        Ok::<_, sqlx::Error>(Principal {
            key_id: row.try_get("id")?,
            tenant_id: TenantId::from_uuid(row.try_get("tenant_id")?),
            label: row.try_get("label")?,
        })
    })
    .transpose()
    .map_err(StoreError::from)
}

/// Write one key, and the audit row that outlives it.
///
/// `secret_hash` is the HMAC; the secret itself never reaches this crate — see
/// `agentos_app::api_keys`, which is the only place it exists and hands it to
/// exactly one response body.
///
/// Both statements are in one transaction, which is the whole reason
/// [`append_admin`] exists: `api_keys` rows are deleted on revocation, so the
/// audit row is the only lasting record that this key was ever minted, and a
/// trail that can disagree with the table is not a trail.
///
/// Errors worth matching on:
///
/// * [`StoreError::UnknownTenant`] — no `tenants` row. The tenant is created
///   before its first key, never by this function.
/// * [`StoreError::Conflict`] — `api_keys_tenant_label_key` (this tenant
///   already has a key by that name) or `api_keys_secret_hash_key` (a digest
///   collision, i.e. never).
pub async fn issue(
    db: &Db,
    id: Uuid,
    tenant_id: TenantId,
    label: &str,
    secret_hash: &[u8],
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, label, secret_hash, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(tenant_id.as_uuid())
    .bind(label)
    .bind(secret_hash)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    // The label and the id. Not the digest — a digest in the trail is a digest
    // in every log shipper that reads the trail, and it is the one value an
    // attacker who has the deployment key could test candidates against.
    append_admin(
        &mut tx,
        tenant_id,
        &AuditEvent {
            payload: json!({ "key_id": id.to_string(), "label": label }),
            ..AuditEvent::new(actor.clone(), AuditKind::ApiKeyIssued, now)
        },
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Destroy one key. The next request presenting it is a 401.
///
/// Returns the tenant it belonged to, so a caller can say whose key it just
/// destroyed without having been told — which is what stops a revocation
/// endpoint needing a tenant id in its body.
///
/// [`StoreError::NotFound`] when there is no such row, which is also the answer
/// for "already revoked". Revoking twice is not an error to an operator holding
/// a key id off a screenshot; it is the state they wanted.
pub async fn revoke(
    db: &Db,
    id: Uuid,
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<TenantId, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    // RETURNING, so the DELETE and the "did it exist, and whose was it" are one
    // statement. A SELECT-then-DELETE would race a concurrent revocation into
    // an audit row for a deletion that removed nothing.
    let row = sqlx::query("DELETE FROM api_keys WHERE id = $1 RETURNING tenant_id, label")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;

    let tenant_id = TenantId::from_uuid(row.try_get("tenant_id")?);
    let label: String = row.try_get("label")?;

    append_admin(
        &mut tx,
        tenant_id,
        &AuditEvent {
            payload: json!({ "key_id": id.to_string(), "label": label }),
            ..AuditEvent::new(actor.clone(), AuditKind::ApiKeyRevoked, now)
        },
    )
    .await?;

    tx.commit().await?;
    Ok(tenant_id)
}

/// This tenant's live keys, oldest first. Never the digests.
///
/// The reason it exists: [`revoke`] takes a key id, and the only other place a
/// key id has ever appeared is the response that issued it. An operator whose
/// key has just been posted to a public repository has the secret and not the
/// id, and "which of my keys is this" must be answerable without presenting the
/// stolen key.
pub async fn list(db: &Db, tenant_id: TenantId) -> Result<Vec<ApiKeyRecord>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;

    let rows = sqlx::query(
        "SELECT id, label, created_at FROM api_keys WHERE tenant_id = $1 ORDER BY created_at, id",
    )
    .bind(tenant_id.as_uuid())
    .fetch_all(&mut *tx)
    .await?;

    tx.rollback().await?;

    rows.into_iter()
        .map(|row| {
            Ok(ApiKeyRecord {
                id: row.try_get("id")?,
                label: row.try_get("label")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `api_keys` tests take a database of their own.
    ///
    /// Not for the usual reason (`crate::db::private_db` exists for the one row
    /// that belongs to no tenant) but for a sharper one: [`lookup`] is
    /// **cross-tenant by definition** — it scans `api_keys` with no tenant
    /// predicate at all — so a key another package's test left behind is a key
    /// this module's assertions can see. Every test here still scopes itself to
    /// a tenant it created; the private database is the belt for the one
    /// function that cannot.
    async fn db() -> Option<Db> {
        crate::db::private_db("apikeys").await
    }

    async fn tenant(db: &Db, label: &str) -> TenantId {
        let id = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(id.as_uuid())
            .bind(format!("{label}-{}", id.as_uuid().simple()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        id
    }

    fn actor() -> AuditActor {
        AuditActor::Operator("platform".to_owned())
    }

    /// A digest of this run's own.
    ///
    /// `secret_hash` is unique table-wide — deliberately, see the migration —
    /// and the private database survives between `cargo test` invocations. A
    /// fixed array therefore passes once and then fails every later run on
    /// `api_keys_secret_hash_key`, which is a test that only works against a
    /// clean database and so cannot be re-run while debugging the thing it
    /// caught. Two v7 uuids are 32 bytes and cannot repeat.
    fn digest() -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::now_v7().as_bytes());
        out[16..].copy_from_slice(Uuid::now_v7().as_bytes());
        out
    }

    /// **The revocation test.** Issue, resolve, delete, resolve again.
    #[tokio::test]
    async fn a_revoked_key_stops_resolving_on_the_very_next_lookup() {
        let Some(db) = db().await else { return };
        let tenant = tenant(&db, "revoke").await;
        let id = Uuid::now_v7();
        let digest = digest();

        issue(&db, id, tenant, "ops", &digest, &actor(), Utc::now())
            .await
            .expect("issue");

        let before = lookup(&db, &digest).await.expect("lookup").expect("live");
        assert_eq!(before.tenant_id, tenant);
        assert_eq!(before.key_id, id);
        assert_eq!(before.label, "ops");

        let whose = revoke(&db, id, &actor(), Utc::now()).await.expect("revoke");
        assert_eq!(whose, tenant, "revoke reports whose key it destroyed");

        assert_eq!(
            lookup(&db, &digest).await.expect("lookup"),
            None,
            "the DELETE committed; there is no cache and therefore no window"
        );
        // ...and again, because "already gone" must not be an error a script
        // has to special-case.
        assert!(matches!(
            revoke(&db, id, &actor(), Utc::now()).await,
            Err(StoreError::NotFound)
        ));
    }

    /// A digest that no row carries resolves to nobody — not to the first row,
    /// not to an error that distinguishes "unknown" from "revoked".
    #[tokio::test]
    async fn an_unknown_digest_resolves_to_nobody() {
        let Some(db) = db().await else { return };
        let tenant = tenant(&db, "unknown").await;
        issue(
            &db,
            Uuid::now_v7(),
            tenant,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue");

        assert_eq!(lookup(&db, &digest()).await.expect("lookup"), None);
        assert_eq!(lookup(&db, b"").await.expect("lookup"), None);
    }

    /// **The trail outlives the row.** Revoking deletes the key; the two audit
    /// rows are what remain, and neither carries the digest.
    #[tokio::test]
    async fn issuing_and_revoking_both_leave_a_row_the_delete_cannot_remove() {
        let Some(db) = db().await else { return };
        let tenant = tenant(&db, "trail").await;
        let id = Uuid::now_v7();

        issue(
            &db,
            id,
            tenant,
            "ops-console",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue");
        revoke(&db, id, &actor(), Utc::now()).await.expect("revoke");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let rows: Vec<(String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT actor, action_kind, payload FROM audit_log ORDER BY occurred_at, id",
        )
        .fetch_all(&mut **tx)
        .await
        .expect("trail");
        tx.rollback().await.expect("rollback");

        let kinds: Vec<&str> = rows.iter().map(|r| r.1.as_str()).collect();
        assert_eq!(kinds, vec!["api_key_issued", "api_key_revoked"]);
        for row in &rows {
            assert_eq!(row.0, "operator:platform");
            assert_eq!(row.2["key_id"], json!(id.to_string()));
            assert_eq!(row.2["label"], json!("ops-console"));
            let rendered = row.2.to_string();
            assert!(
                !rendered.contains("secret") && !rendered.contains("hash"),
                "the trail must not carry the digest: {rendered}"
            );
        }
    }

    /// Two tenants may both call a key `ops`; one tenant may not, twice.
    #[tokio::test]
    async fn a_label_is_unique_within_a_tenant_and_not_across_them() {
        let Some(db) = db().await else { return };
        let a = tenant(&db, "labels-a").await;
        let b = tenant(&db, "labels-b").await;

        issue(
            &db,
            Uuid::now_v7(),
            a,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("first");
        issue(
            &db,
            Uuid::now_v7(),
            b,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("another tenant may reuse the name");

        let err = issue(
            &db,
            Uuid::now_v7(),
            a,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect_err("the same tenant may not");
        assert!(
            matches!(&err, StoreError::Conflict(what) if what == "api_keys_tenant_label_key"),
            "got {err:?}"
        );
    }

    /// One digest cannot name two tenants, because the row that would do it
    /// cannot be written.
    #[tokio::test]
    async fn one_digest_cannot_belong_to_two_tenants() {
        let Some(db) = db().await else { return };
        let a = tenant(&db, "dup-a").await;
        let b = tenant(&db, "dup-b").await;
        let digest = digest();

        issue(&db, Uuid::now_v7(), a, "ops", &digest, &actor(), Utc::now())
            .await
            .expect("first");
        let err = issue(&db, Uuid::now_v7(), b, "ops", &digest, &actor(), Utc::now())
            .await
            .expect_err("a second row with the same digest is a coin toss over whose data is read");
        assert!(
            matches!(&err, StoreError::Conflict(what) if what == "api_keys_secret_hash_key"),
            "got {err:?}"
        );
    }

    /// A key for a tenant that does not exist is the named first-run failure,
    /// not an opaque driver error.
    #[tokio::test]
    async fn a_key_for_a_tenant_with_no_row_names_the_tenant() {
        let Some(db) = db().await else { return };
        let ghost = TenantId::new_v7(Utc::now());
        let err = issue(
            &db,
            Uuid::now_v7(),
            ghost,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect_err("no tenants row");
        assert!(
            matches!(&err, StoreError::UnknownTenant(what) if what == "api_keys_tenant_id_fkey"),
            "got {err:?}"
        );
    }

    /// `list` is scoped, ordered, and carries no digest.
    #[tokio::test]
    async fn list_shows_this_tenants_live_keys_and_nobody_elses() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db, "list-mine").await;
        let theirs = tenant(&db, "list-theirs").await;
        let first = Uuid::now_v7();

        issue(&db, first, mine, "first", &digest(), &actor(), Utc::now())
            .await
            .expect("issue");
        issue(
            &db,
            Uuid::now_v7(),
            mine,
            "second",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue");
        issue(
            &db,
            Uuid::now_v7(),
            theirs,
            "hidden",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue");

        let labels: Vec<String> = list(&db, mine)
            .await
            .expect("list")
            .into_iter()
            .map(|key| key.label)
            .collect();
        assert_eq!(labels, vec!["first".to_owned(), "second".to_owned()]);

        revoke(&db, first, &actor(), Utc::now())
            .await
            .expect("revoke");
        let labels: Vec<String> = list(&db, mine)
            .await
            .expect("list")
            .into_iter()
            .map(|key| key.label)
            .collect();
        assert_eq!(
            labels,
            vec!["second".to_owned()],
            "a revoked key is not listed"
        );
    }

    /// **The table is unreachable from a tenant transaction**, which is the
    /// second belt `0044_api_keys.sql` argues for: not "RLS would filter it" but
    /// "the role has no privilege and the statement does not run".
    #[tokio::test]
    async fn a_tenant_transaction_cannot_read_the_table_at_all() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db, "grants").await;
        issue(
            &db,
            Uuid::now_v7(),
            mine,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue");

        let mut tx = db.tenant_tx(mine).await.expect("tenant tx");
        // Its own rows, by its own tenant id, under RLS that would permit them.
        let err = sqlx::query("SELECT count(*) FROM api_keys WHERE tenant_id = $1")
            .bind(mine.as_uuid())
            .fetch_one(&mut **tx)
            .await
            .expect_err("app_role must hold no privilege on api_keys");
        let message = err.to_string();
        assert!(
            message.contains("permission denied"),
            "expected a privilege failure, got: {message}"
        );
        tx.rollback().await.expect("rollback");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        for verb in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            let granted: bool =
                sqlx::query_scalar("SELECT has_table_privilege('app_role', 'api_keys', $1)")
                    .bind(verb)
                    .fetch_one(&mut *tx)
                    .await
                    .expect("privilege check");
            assert!(!granted, "app_role must not hold {verb} on api_keys");
        }
        tx.rollback().await.expect("rollback");
    }

    /// **The isolation itself, tested by taking the first belt off.**
    ///
    /// Every other table in this schema proves tenant isolation by reading it
    /// from a `tenant_tx` and seeing nothing of another tenant's. This one
    /// cannot: `app_role` holds no privilege at all, so the statement fails on
    /// `42501` before a policy is ever consulted — which is stronger, and which
    /// would leave the RLS policy on this table completely untested. A policy
    /// nothing exercises is a policy that can be wrong for years, and the day it
    /// matters is the day somebody adds `grant select` "so a tenant can list its
    /// own keys".
    ///
    /// So the grant is added *inside a transaction that is rolled back*, which
    /// Postgres allows because `GRANT` is transactional, and the isolation is
    /// then asked the ordinary way. Nothing survives the rollback: not the
    /// grant, not the role, not the GUC.
    #[tokio::test]
    async fn the_policy_under_the_missing_grant_still_isolates_tenants() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db, "rls-mine").await;
        let theirs = tenant(&db, "rls-theirs").await;
        issue(
            &db,
            Uuid::now_v7(),
            mine,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue");
        issue(
            &db,
            Uuid::now_v7(),
            theirs,
            "ops",
            &digest(),
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        // The premise: enabled AND forced. Without `force`, the owning role —
        // which is what migrations connect as — walks straight past the policy
        // and every count below would be the wrong kind of right.
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'api_keys'",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("pg_class");
        assert!(enabled && forced, "api_keys needs ENABLE and FORCE");

        // Both halves of the policy, because `using` alone would let a tenant
        // file a row wearing somebody else's id.
        let (using, check): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT qual, with_check FROM pg_policies \
              WHERE tablename = 'api_keys' AND policyname = 'tenant_isolation'",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("pg_policies");
        for (half, sql) in [("using", &using), ("with check", &check)] {
            let sql = sql.as_deref().unwrap_or_default();
            assert!(
                sql.contains("app.tenant_id"),
                "the {half} half must be keyed on the GUC `Db::tenant_tx` sets, got {sql:?}"
            );
        }

        sqlx::query("GRANT SELECT ON api_keys TO app_role")
            .execute(&mut *tx)
            .await
            .expect("a grant is transactional; this one is rolled back below");
        sqlx::query("SET LOCAL ROLE app_role")
            .execute(&mut *tx)
            .await
            .expect("set role");
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(mine.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("set the tenant");

        // No tenant predicate in the SQL at all: the numbers come from the
        // policy or from nowhere.
        let visible: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT tenant_id FROM api_keys")
            .fetch_all(&mut *tx)
            .await
            .expect("scan");
        assert_eq!(
            visible,
            vec![mine.as_uuid()],
            "with a grant in place, one tenant must still see only its own keys"
        );

        tx.rollback().await.expect("rollback");

        // ...and the grant really is gone, or this test just opened the door it
        // was checking.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let granted: bool =
            sqlx::query_scalar("SELECT has_table_privilege('app_role', 'api_keys', 'SELECT')")
                .fetch_one(&mut *tx)
                .await
                .expect("privilege check");
        tx.rollback().await.expect("rollback");
        assert!(!granted, "the rollback must have taken the grant with it");
    }
}
