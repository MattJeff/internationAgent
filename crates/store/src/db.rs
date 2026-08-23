//! The connection pool and the only two ways to reach it.
//!
//! [`Db`] owns a [`PgPool`] and does not expose it. There is no accessor, no
//! `pub(crate)` leak, no `Deref`. That is the entire security model of this
//! crate in one sentence: a query that forgets its tenant is not a bug you have
//! to catch in review, it is a program that does not compile, because the only
//! public way to obtain a connection is [`Db::tenant_tx`], which sets
//! `app.tenant_id` for the life of the transaction so the row-level security
//! policies in `0001_core.sql` apply.
//!
//! The escape hatch is [`Db::admin_tx_bypassing_rls`], named so that it cannot
//! appear in a diff without someone noticing. Two callers legitimately need it:
//! migrations, and the outbox poller, which is cross-tenant by nature.

use std::ops::{Deref, DerefMut};

use agentos_domain::ids::TenantId;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Transaction};

/// Postgres SQLSTATE for `unique_violation`.
const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";
/// Postgres SQLSTATE for `serialization_failure`.
const SQLSTATE_SERIALIZATION_FAILURE: &str = "40001";
/// Postgres SQLSTATE for `deadlock_detected`; retryable on exactly the same
/// terms as a serialization failure, so it maps to the same variant.
const SQLSTATE_DEADLOCK_DETECTED: &str = "40P01";

/// Everything this crate can fail with.
///
/// Downstream modules match on these variants, so the mapping from Postgres is
/// part of the contract rather than an implementation detail:
///
/// | condition                          | variant         |
/// |------------------------------------|-----------------|
/// | `RowNotFound`                       | [`Self::NotFound`] |
/// | SQLSTATE 23505 unique violation     | [`Self::Conflict`] |
/// | SQLSTATE 40001 / 40P01              | [`Self::Serialization`] |
/// | anything else                       | [`Self::Database`] |
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The row the caller asked for does not exist, or is invisible to this
    /// tenant — RLS makes those two indistinguishable, which is intentional.
    #[error("not found")]
    NotFound,

    /// A uniqueness invariant or an optimistic-lock version check lost a race.
    /// The string names what collided (a constraint name from Postgres, or a
    /// caller-supplied description for a version mismatch).
    #[error("conflict: {0}")]
    Conflict(String),

    /// The transaction was aborted by Postgres and may succeed if retried.
    #[error("serialization failure; retry the transaction")]
    Serialization,

    /// Anything else the driver reported.
    #[error(transparent)]
    Database(sqlx::Error),
}

impl StoreError {
    /// A conflict that Postgres did not report — typically an optimistic-lock
    /// update that matched zero rows.
    pub fn conflict(what: impl Into<String>) -> Self {
        Self::Conflict(what.into())
    }
}

// Written by hand rather than derived with `#[from]`, and the difference
// matters: a derived `From` would make every `?` on a sqlx error produce
// `Database`, so a duplicate-key insert three modules away would surface as an
// opaque driver error and the caller's `match` on `Conflict` would never fire.
// Classifying here means `?` does the right thing everywhere by default.
impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        if matches!(err, sqlx::Error::RowNotFound) {
            return Self::NotFound;
        }
        match err.as_database_error().map(|e| e.code()) {
            Some(Some(code)) => match code.as_ref() {
                SQLSTATE_UNIQUE_VIOLATION => Self::Conflict(
                    err.as_database_error()
                        .and_then(|e| e.constraint())
                        .unwrap_or("unique constraint")
                        .to_owned(),
                ),
                SQLSTATE_SERIALIZATION_FAILURE | SQLSTATE_DEADLOCK_DETECTED => Self::Serialization,
                _ => Self::Database(err),
            },
            _ => Self::Database(err),
        }
    }
}

impl From<sqlx::migrate::MigrateError> for StoreError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::Database(sqlx::Error::from(err))
    }
}

/// A handle to the database. Cheap to clone; clones share one pool.
#[derive(Clone, Debug)]
pub struct Db {
    // Private, and staying private. See the module docs.
    pool: PgPool,
}

impl Db {
    /// Connect to `database_url` and return a pool-backed handle.
    ///
    /// Does not run migrations; call [`Db::migrate`] for that.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Apply every migration in `migrations/` that has not run yet.
    ///
    /// Runs as the connecting role, which must be able to create roles and
    /// tables. Safe to call on every boot; sqlx takes an advisory lock, so
    /// concurrent instances serialise instead of racing.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        // Path is relative to this crate's manifest; the migrations live at the
        // workspace root so every binary in the workspace shares one history.
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Begin a transaction scoped to one tenant. **The only public way to get a
    /// connection.**
    ///
    /// Two statements run before the caller sees the transaction:
    ///
    /// 1. `SET LOCAL ROLE app_role` — without this the whole scheme is
    ///    decorative. RLS does not apply to superusers or to the table owner,
    ///    and deployments routinely connect as `postgres`. Switching to a plain
    ///    role for the duration of the transaction makes the policies bind no
    ///    matter who connected.
    /// 2. `set_config('app.tenant_id', $1, true)` — the `true` is
    ///    transaction-local scope, i.e. the `SET LOCAL` form. Using
    ///    `set_config` rather than literal `SET LOCAL` text is what lets the id
    ///    be a bound parameter instead of string-concatenated SQL.
    ///
    /// Both unwind with the transaction, so a pooled connection is never handed
    /// back still wearing a tenant's identity.
    pub async fn tenant_tx(&self, tenant_id: TenantId) -> Result<TenantTx<'_>, StoreError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("SET LOCAL ROLE app_role")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await?;

        Ok(TenantTx { tx, tenant_id })
    }

    /// Begin a transaction that **sees and can modify every tenant's rows**.
    ///
    /// It does not `SET LOCAL ROLE`, so it runs as the connecting role, and
    /// when that role is a superuser or the table owner, row-level security
    /// does not apply. There is no tenant filter of any kind here — whatever
    /// SQL you write is exactly what runs.
    ///
    /// Legitimate callers: schema migrations, and the outbox poller, which
    /// drains events across all tenants by definition. Everything else wants
    /// [`Db::tenant_tx`]. If you are reaching for this to "just read one row",
    /// you want `tenant_tx`.
    pub async fn admin_tx_bypassing_rls(&self) -> Result<Transaction<'_, Postgres>, StoreError> {
        Ok(self.pool.begin().await?)
    }
}

/// A transaction pinned to one tenant, with `app.tenant_id` already set.
///
/// Derefs to the underlying [`Transaction`], so store modules run queries the
/// ordinary way — `sqlx::query(..).fetch_one(&mut **tx)`.
///
/// Dropping without calling [`TenantTx::commit`] rolls back, per sqlx's normal
/// behaviour; [`TenantTx::rollback`] exists so that discarding work can be
/// deliberate and awaited rather than implicit.
#[derive(Debug)]
pub struct TenantTx<'c> {
    tx: Transaction<'c, Postgres>,
    tenant_id: TenantId,
}

impl TenantTx<'_> {
    /// The tenant every query in this transaction is confined to.
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Commit. Clears `app.tenant_id` and the role along with the transaction.
    pub async fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().await?;
        Ok(())
    }

    /// Discard every statement in this transaction.
    pub async fn rollback(self) -> Result<(), StoreError> {
        self.tx.rollback().await?;
        Ok(())
    }
}

impl<'c> Deref for TenantTx<'c> {
    type Target = Transaction<'c, Postgres>;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for TenantTx<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sqlx::Row;
    use uuid::Uuid;

    /// Connect and migrate, or `None` when there is no database to talk to.
    ///
    /// These tests are worthless against a mock — the thing under test is
    /// Postgres' own RLS engine — so without `DATABASE_URL` they skip loudly
    /// rather than pass quietly or fail the build.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; store tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant plus one employee, committed. Returns the ids.
    async fn seed(db: &Db, label: &str) -> (TenantId, Uuid) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = Uuid::now_v7();
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
        .bind(employee)
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

    #[tokio::test]
    async fn tenant_tx_hides_other_tenants_rows() {
        let Some(db) = db().await else { return };
        let (a, a_employee) = seed(&db, "alpha").await;
        let (b, b_employee) = seed(&db, "beta").await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        assert_eq!(tx.tenant_id(), a);

        // The premise first: if the transaction is running as a superuser or a
        // BYPASSRLS role, every assertion below would pass for the wrong
        // reason. Prove the role actually has RLS applied to it.
        let role: (String, bool, bool) = sqlx::query_as(
            "SELECT current_user::text, rolsuper, rolbypassrls \
             FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&mut **tx)
        .await
        .expect("role introspection");
        assert_eq!(role.0, "app_role", "tenant_tx must SET LOCAL ROLE app_role");
        assert!(!role.1, "app_role must not be a superuser");
        assert!(!role.2, "app_role must not have BYPASSRLS");

        // A's own row is visible.
        let mine: i64 = sqlx::query_scalar("SELECT count(*) FROM employees WHERE id = $1")
            .bind(a_employee)
            .fetch_one(&mut **tx)
            .await
            .expect("count own");
        assert_eq!(mine, 1);

        // B's row is not — asked for by primary key, with no tenant filter in
        // the SQL at all. The zero comes from the policy, not from the query.
        let theirs: i64 = sqlx::query_scalar("SELECT count(*) FROM employees WHERE id = $1")
            .bind(b_employee)
            .fetch_one(&mut **tx)
            .await
            .expect("count other");
        assert_eq!(theirs, 0, "tenant A must not see tenant B's employee");

        // And an unfiltered scan sees only A's tenant_id.
        let tenants: Vec<Uuid> = sqlx::query("SELECT DISTINCT tenant_id FROM employees")
            .fetch_all(&mut **tx)
            .await
            .expect("scan")
            .into_iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(tenants, vec![a.as_uuid()]);

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    #[tokio::test]
    async fn tenant_tx_rollback_leaves_nothing_behind() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "rollback").await;
        let ghost = Uuid::now_v7();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'ghost', 'ghost', 'active')",
        )
        .bind(ghost)
        .bind(tenant.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("insert");
        tx.rollback().await.expect("rollback");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let survived: i64 = sqlx::query_scalar("SELECT count(*) FROM employees WHERE id = $1")
            .bind(ghost)
            .fetch_one(&mut *tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback admin");
        assert_eq!(survived, 0);

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn duplicate_slug_is_a_conflict_not_a_driver_error() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "dup").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err: StoreError = sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'dup', 'dup again', 'active')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .execute(&mut **tx)
        .await
        .expect_err("duplicate slug must fail")
        .into();

        match err {
            StoreError::Conflict(constraint) => {
                assert_eq!(constraint, "employees_tenant_slug_key");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }

        tx.rollback().await.expect("rollback");
        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn audit_log_rejects_update_and_delete() {
        let Some(db) = db().await else { return };
        let tenant = TenantId::new_v7(Utc::now());

        for op in [
            "UPDATE audit_log SET actor = 'tampered' WHERE tenant_id = $1",
            "DELETE FROM audit_log WHERE tenant_id = $1",
        ] {
            // Whole thing inside one transaction that is rolled back, so the
            // append-only row we create to attack does not accumulate.
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query(
                "INSERT INTO audit_log (id, tenant_id, actor, action_kind) \
                 VALUES ($1, $2, 'system', 'test')",
            )
            .bind(Uuid::now_v7())
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("insert audit row");

            let err = sqlx::query(op)
                .bind(tenant.as_uuid())
                .execute(&mut *tx)
                .await
                .expect_err("audit_log must be append-only");
            let msg = err.to_string();
            assert!(
                msg.contains("append-only"),
                "expected the append-only trigger to fire for `{op}`, got: {msg}"
            );

            // The failed statement aborted the transaction; unwind it.
            tx.rollback().await.expect("rollback");
        }

        // ... and the app role cannot even attempt it: no privilege.
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let granted: bool =
            sqlx::query_scalar("SELECT has_table_privilege('app_role', 'audit_log', 'DELETE')")
                .fetch_one(&mut *tx)
                .await
                .expect("privilege check");
        tx.rollback().await.expect("rollback");
        assert!(!granted, "app_role must not hold DELETE on audit_log");
    }
}
