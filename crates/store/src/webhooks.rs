//! `webhook_endpoints`: which customer a provider callback belongs to, when the
//! deployment serves more than one.
//!
//! `0053_webhook_endpoints.sql` is the design document — why the path is opaque,
//! why the secret is a sealed blob and not a `secret_ref`, why `provider` is
//! checked to one value. This is the two statements that touch the table.
//!
//! # Both functions open an admin transaction, and that is not a shortcut
//!
//! [`lookup`] runs **before there is a tenant**. It is handed one path segment
//! off an unauthenticated request and its whole job is to answer "whose is
//! this", so there is no `app.tenant_id` to set and `Db::tenant_tx` is not
//! merely inconvenient, it is unanswerable. [`register`] has a tenant but no
//! privilege: the migration revokes everything on this table from `app_role`,
//! deliberately, so a tenant transaction that reaches it dies with `42501`
//! instead of reading sealed secrets.
//!
//! This is `api_keys`' situation exactly, and the defences are the same four,
//! because they are cheap enough that there is no excuse for having three:
//!
//! 1. **The lookup transaction is `READ ONLY`.** Postgres refuses any write in
//!    it, including one a future edit adds three lines down without noticing
//!    what kind of transaction it is in.
//! 2. **The SQL is a `&'static str`.** Nothing from the request reaches the
//!    statement text: the path arrives as a bound `text` parameter and the table
//!    itself carries `webhook_endpoints_path_shape`, so a row cannot hold a
//!    string that means anything to a router either.
//! 3. **The projection is three columns of one table.** No `*`, no join, no
//!    dynamic identifier. Whatever a caller wanted out of this hole, the hole is
//!    `tenant_id, provider, sealed_secret`.
//! 4. **It returns [`SealedEndpoint`], not a row** — and the secret in it is
//!    *ciphertext*. This module has no access to `AGENTOS_MASTER_KEY` and could
//!    not open it if it did; the plaintext exists only inside
//!    `agentos_app::webhooks`, for the length of one signature check.
//!
//! There is a fifth that `api_keys` cannot have and this table does: the sealed
//! secret's AAD is `webhook://<tenant>`, bound to the very column this query
//! returns beside it. A row read here and opened as any other tenant fails
//! authentication rather than decrypting — which is the property the
//! RLS-bypassing lookup leans on, since the database is not the thing keeping
//! one tenant out of another's row on this path.

use agentos_domain::ids::TenantId;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::Row;

use crate::audit::{AuditActor, AuditEvent, AuditKind, append_admin};
use crate::db::{Db, StoreError};

/// One registered endpoint, as it sits in the table.
///
/// Deliberately not `Deserialize`, deliberately no `Debug`: the third field is a
/// credential, sealed, and a type that renders is a type somebody logs. The only
/// way to obtain one is [`lookup`], which means the only way to obtain one is to
/// name a path that is a row.
pub struct SealedEndpoint {
    /// Whose deliveries these are. From the row and from nowhere else — never
    /// from the request path, never from the payload.
    pub tenant_id: TenantId,
    /// Which ingest reads the stored delivery. Becomes
    /// `webhook.{provider}.received`.
    pub provider: String,
    /// The signing secret, still sealed. Opened by `agentos_app::webhooks`.
    pub sealed_secret: Vec<u8>,
}

/// Resolve a path segment to the endpoint registered under it.
///
/// `None` means no row — which covers "never registered", "registered under a
/// different path" and "the tenant was deleted a millisecond ago", and the
/// caller must not be able to tell those apart. `routes::webhooks` answers all
/// of them with a 404, before it reads a byte of the body.
///
/// # No cache, and the window is therefore zero
///
/// One primary-key equality per delivery. A cache here would have to state its
/// window, and every window is a window in which an endpoint an operator
/// deleted still accepts a customer's mail. If this ever shows up in a profile
/// the fix is the prepared-statement cache doing its job, not a TTL — the same
/// argument `api_keys::lookup` makes at length, on a path that runs far more
/// often than this one.
pub async fn lookup(db: &Db, path: &str) -> Result<Option<SealedEndpoint>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    // The escape hatch, declawed. See the module docs: this is a query that runs
    // before anybody knows who is asking, so it must be unable to do anything
    // but read.
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;

    let row = sqlx::query(
        "SELECT tenant_id, provider, sealed_secret FROM webhook_endpoints WHERE path = $1",
    )
    .bind(path)
    .fetch_optional(&mut *tx)
    .await?;

    // Rolled back rather than committed: nothing was written, and a rollback
    // says so to anybody reading `pg_stat_activity`.
    tx.rollback().await?;

    row.map(|row| {
        Ok::<_, sqlx::Error>(SealedEndpoint {
            tenant_id: TenantId::from_uuid(row.try_get("tenant_id")?),
            provider: row.try_get("provider")?,
            sealed_secret: row.try_get("sealed_secret")?,
        })
    })
    .transpose()
    .map_err(StoreError::from)
}

/// Register this tenant's endpoint for `provider`, or rotate the secret on the
/// one it already has.
///
/// `path` is used only when the row is new. On a second call for the same
/// `(tenant_id, provider)` the stored path is **kept** and only the sealed
/// secret is replaced, and that is the whole reason the unique constraint
/// exists: rotating a signing secret must not mean re-pasting a URL at the
/// provider, and it must not leave the compromised secret verifying on a second
/// endpoint nobody remembers. Returns the path the caller should hand over —
/// the existing one on a rotation — and whether it *was* a rotation, which the
/// caller cannot work out afterwards and which decides whether an operator is
/// about to paste a new URL or has just changed a secret in place.
///
/// `sealed_secret` is already ciphertext — see `agentos_app::webhooks::register`.
/// The plaintext never reaches this crate, which is why there is nothing here to
/// be careful about.
///
/// The audit row is written in the same transaction, and it is the only lasting
/// record of a rotation: the table keeps one row per `(tenant, provider)` and an
/// UPDATE leaves no trace of the value it replaced. It names the path and the
/// provider and **nothing derived from the secret** — not a prefix, not a
/// length, not a hash.
///
/// [`StoreError::UnknownTenant`] when there is no `tenants` row: an endpoint is
/// registered for a customer that exists, never by this function.
pub async fn register(
    db: &Db,
    tenant_id: TenantId,
    provider: &str,
    path: &str,
    sealed_secret: &[u8],
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<(String, bool), StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    // `RETURNING path`, so "was this new or a rotation" and "which URL do I hand
    // back" are one statement. A SELECT-then-INSERT would race two registrations
    // of one tenant into two live endpoints.
    let stored: String = sqlx::query_scalar(
        "INSERT INTO webhook_endpoints \
           (path, tenant_id, provider, sealed_secret, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $5) \
         ON CONFLICT ON CONSTRAINT webhook_endpoints_tenant_provider_key DO UPDATE \
           SET sealed_secret = excluded.sealed_secret, updated_at = excluded.updated_at \
         RETURNING path",
    )
    .bind(path)
    .bind(tenant_id.as_uuid())
    .bind(provider)
    .bind(sealed_secret)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;

    // The upsert kept a path that is not the one offered, so a row was already
    // there. This is the only moment that fact is knowable — afterwards the
    // table looks identical either way.
    let rotated = stored != path;

    append_admin(
        &mut tx,
        tenant_id,
        &AuditEvent {
            payload: json!({ "path": stored, "provider": provider, "rotated": rotated }),
            ..AuditEvent::new(actor.clone(), AuditKind::WebhookEndpointRegistered, now)
        },
    )
    .await?;

    tx.commit().await?;
    Ok((stored, rotated))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database of its own, for [`lookup`]'s reason rather than the usual one:
    /// it scans `webhook_endpoints` with **no tenant predicate at all**, so a
    /// row another package's test left behind is a row this module's assertions
    /// can see.
    async fn db() -> Option<Db> {
        crate::db::private_db("webhooks").await
    }

    async fn tenant(db: &Db) -> TenantId {
        let id = TenantId::new_v7(Utc::now());
        let label = format!("hook-{}", id.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(id.as_uuid())
            .bind(&label)
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        id
    }

    fn actor() -> AuditActor {
        AuditActor::Operator("platform".to_owned())
    }

    fn path(tag: &str) -> String {
        format!("whe_test_{tag}_{}", uuid::Uuid::now_v7().simple())
    }

    /// The round trip, and the row's tenant is the registered one.
    #[tokio::test]
    async fn a_registered_path_resolves_to_its_own_tenant() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db).await;
        let theirs = tenant(&db).await;
        let (a, b) = (path("mine"), path("theirs"));

        let now = Utc::now();
        let (_, rotated) = register(&db, mine, "email", &a, b"sealed-a", &actor(), now)
            .await
            .expect("register a");
        assert!(!rotated, "a first registration is not a rotation");
        register(&db, theirs, "email", &b, b"sealed-b", &actor(), now)
            .await
            .expect("register b");

        let found = lookup(&db, &a).await.expect("lookup").expect("a row");
        assert_eq!(found.tenant_id, mine);
        assert_ne!(found.tenant_id, theirs);
        assert_eq!(found.sealed_secret, b"sealed-a");

        let found = lookup(&db, &b).await.expect("lookup").expect("a row");
        assert_eq!(found.tenant_id, theirs);
        assert_eq!(found.sealed_secret, b"sealed-b");
    }

    #[tokio::test]
    async fn an_unregistered_path_is_none_and_not_an_error() {
        let Some(db) = db().await else { return };
        assert!(
            lookup(&db, &path("never")).await.expect("lookup").is_none(),
            "an unregistered path must be None, which the route answers 404"
        );
    }

    /// Registering twice rotates in place: one row, the original path, the new
    /// secret. The bite is the second assertion — a second row would be a second
    /// live door holding the secret the operator was replacing.
    #[tokio::test]
    async fn registering_twice_rotates_the_secret_and_keeps_the_path() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db).await;
        let (first, second) = (path("first"), path("second"));

        let now = Utc::now();
        let (a, first_was_rotation) = register(&db, mine, "email", &first, b"old", &actor(), now)
            .await
            .expect("register");
        let (b, second_was_rotation) = register(&db, mine, "email", &second, b"new", &actor(), now)
            .await
            .expect("rotate");

        assert_eq!(a, first);
        assert!(!first_was_rotation);
        assert_eq!(b, first, "a rotation must not move the URL");
        assert!(
            second_was_rotation,
            "the caller was told it created an endpoint when it replaced a secret"
        );

        let found = lookup(&db, &first).await.expect("lookup").expect("a row");
        assert_eq!(found.sealed_secret, b"new", "the secret was not replaced");
        assert!(
            lookup(&db, &second).await.expect("lookup").is_none(),
            "the second path became a live endpoint; the old secret is still \
             verifying somewhere"
        );
    }

    /// The table refuses a path that could make the route ambiguous, or one a
    /// human chose. See `0053`'s argument: guessability is the only separation
    /// left when two tenants share a provider account.
    #[tokio::test]
    async fn a_path_that_is_short_or_not_one_url_segment_is_refused() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db).await;

        for bad in ["email", "a/../b/../../etc", "whe_has a space", "whe_pct%2f"] {
            let err = register(&db, mine, "email", bad, b"sealed", &actor(), Utc::now())
                .await
                .expect_err(&format!("{bad:?} was accepted as a path"));
            assert!(
                matches!(err, StoreError::Database(_)),
                "{bad:?} failed with {err}"
            );
        }
    }

    /// `provider` is checked to the one value `main::handlers` registers a
    /// handler for. Without this an operator can file deliveries under an event
    /// type nothing reads, which is eight retries and a dead letter per message.
    #[tokio::test]
    async fn a_provider_with_no_ingest_is_refused_by_the_table() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db).await;

        register(
            &db,
            mine,
            "telephony",
            &path("tel"),
            b"sealed",
            &actor(),
            Utc::now(),
        )
        .await
        .expect_err("a provider with no reader on the queue was accepted");
    }

    /// The row belongs to a customer that exists.
    #[tokio::test]
    async fn an_endpoint_for_a_tenant_that_does_not_exist_is_refused() {
        let Some(db) = db().await else { return };
        let nobody = TenantId::new_v7(Utc::now());

        let err = register(
            &db,
            nobody,
            "email",
            &path("ghost"),
            b"sealed",
            &actor(),
            Utc::now(),
        )
        .await
        .expect_err("an endpoint was registered for no tenant");
        assert!(matches!(err, StoreError::UnknownTenant(_)), "{err}");
    }

    /// The audit row is the only lasting record of a rotation, and it carries
    /// nothing derived from the secret.
    #[tokio::test]
    async fn the_trail_names_the_path_and_never_the_secret() {
        let Some(db) = db().await else { return };
        let mine = tenant(&db).await;
        let p = path("trail");

        register(
            &db,
            mine,
            "email",
            &p,
            b"super-secret-bytes",
            &actor(),
            Utc::now(),
        )
        .await
        .expect("register");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let rendered: Vec<String> = sqlx::query_scalar(
            "SELECT payload::text FROM audit_log \
              WHERE tenant_id = $1 AND action_kind = 'webhook_endpoint_registered'",
        )
        .bind(mine.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .expect("read trail");
        tx.rollback().await.expect("rollback");

        assert_eq!(rendered.len(), 1, "one registration, one row");
        assert!(rendered[0].contains(&p), "the trail must name the path");
        assert!(
            !rendered[0].contains("super-secret"),
            "the trail carries the secret: {}",
            rendered[0]
        );
    }
}
