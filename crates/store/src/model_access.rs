//! The tenant's model connection: one row, read on every turn, written once per
//! proof.
//!
//! `migrations/0041_tenant_model_access.sql` carries the argument for the table
//! and `agentos_domain::model_access` for the types. Two things about this
//! module rather than that one:
//!
//! **`load` returns `Option`, and `None` is the answer, not an error.** A tenant
//! with no row is not a failed read — it is a tenant nobody has connected a
//! model for yet, which is the state every tenant is in the moment 0041 lands.
//! Making it an error would put "the first-run step nobody did" and "the
//! database is broken" in the same branch, and the caller has to tell a person
//! which one it was in a five-minute setup flow.
//!
//! **A row this build cannot read is [`StoreError::Conflict`], never a skipped
//! row.** The `path` and `verified_model` columns hold closed enums whose
//! parsers return `None` for anything unknown. Text that does not parse means
//! the database and the binary disagree about what paths or models exist — a
//! rollback to an older build, or a `psql` session — and the safe reading of
//! that is *stop*, because the alternative is treating a connected tenant as
//! unconnected and refusing every one of their turns with a message that names
//! the wrong remedy.
//!
//! There is no `WHERE tenant_id` in either statement. `tenant_model_access` has
//! RLS forced and the policy is `with check` as well as `using`, so the tenant
//! filter is the database's rather than something a reader has to verify is
//! present in every query.

use chrono::{DateTime, Utc};

use agentos_domain::model_access::{ModelAccess, ModelPath};
use agentos_domain::policy::ModelId;

use crate::db::{StoreError, TenantTx};

/// One row of [`tenant_model_access`](self), still as text.
#[derive(Debug, sqlx::FromRow)]
struct Row {
    path: String,
    verified_model: String,
    verified_at: DateTime<Utc>,
}

impl Row {
    /// Parse the closed enums, or refuse. See the module docs for why an
    /// unreadable row is louder than a missing one.
    fn into_access(self) -> Result<ModelAccess, StoreError> {
        let path = ModelPath::parse(&self.path).ok_or_else(|| {
            StoreError::conflict(format!(
                "tenant_model_access.path is {:?}, which this build has no model path for",
                self.path
            ))
        })?;
        let model = ModelId::parse(&self.verified_model).ok_or_else(|| {
            StoreError::conflict(format!(
                "tenant_model_access.verified_model is {:?}, which this build has no model for",
                self.verified_model
            ))
        })?;
        Ok(ModelAccess {
            path,
            model,
            verified_at: self.verified_at,
        })
    }
}

/// This tenant's model connection, or `None` if nobody has connected one.
///
/// Read on the path of every turn, so it is one row by primary key and nothing
/// else. `None` is what makes a tenant a tenant whose employees take no turns —
/// see `agentos_app::model_access::for_turn`, which is the only caller allowed
/// to decide what that means.
pub async fn load(tx: &mut TenantTx<'_>) -> Result<Option<ModelAccess>, StoreError> {
    let row: Option<Row> =
        sqlx::query_as("SELECT path, verified_model, verified_at FROM tenant_model_access")
            .fetch_optional(&mut ***tx)
            .await?;

    row.map(Row::into_access).transpose()
}

/// Record a connection that has just been proven.
///
/// An upsert, because reconnecting with a different key is the only shape of
/// "change my model connection" this product offers — there is no DELETE grant
/// on the table and no verb that would use one.
///
/// **Call this in the same transaction that stored the credential**, never
/// before it. The order is what stops a window where the row claims a proof and
/// the vault holds the previous tenant's key: `agentos_app::model_access::connect`
/// puts the secret first, commits both, and stores nothing at all unless the
/// verification call returned a completion.
pub async fn save(
    tx: &mut TenantTx<'_>,
    access: &ModelAccess,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO tenant_model_access \
           (tenant_id, path, verified_model, verified_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id) DO UPDATE SET \
           path = excluded.path, \
           verified_model = excluded.verified_model, \
           verified_at = excluded.verified_at, \
           updated_at = excluded.updated_at",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(access.path.as_str())
    .bind(access.model.as_str())
    .bind(access.verified_at)
    .bind(now)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use uuid::Uuid;

    use super::*;
    use crate::db::Db;

    /// A database with the migrations applied, and one tenant in it.
    async fn fixture() -> Option<(Db, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; model_access needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        Some((db.clone(), seed_tenant(&db).await))
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'model access test')")
            .bind(tenant_id.as_uuid())
            .bind(format!("ma-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");
        tenant_id
    }

    #[tokio::test]
    async fn an_unconnected_tenant_reads_as_none_and_a_reconnect_replaces_the_row() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        assert_eq!(load(&mut tx).await.expect("load"), None);

        let first = ModelAccess {
            path: ModelPath::ApiKey,
            model: ModelId::Opus5,
            verified_at: now,
        };
        save(&mut tx, &first, now).await.expect("save");
        assert_eq!(load(&mut tx).await.expect("load"), Some(first));

        // Reconnecting on the other path replaces rather than adding: one
        // credential per tenant, enforced by the primary key.
        let second = ModelAccess {
            path: ModelPath::Cli,
            model: ModelId::Haiku45,
            verified_at: now + chrono::Duration::seconds(30),
        };
        save(&mut tx, &second, now).await.expect("save");
        assert_eq!(load(&mut tx).await.expect("load"), Some(second));

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenant_model_access")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(count, 1);
        tx.commit().await.expect("commit");
    }

    /// A row this build cannot read stops the read. See the module docs: the
    /// alternative reads as "nobody connected a model", which is a different
    /// sentence with a different remedy.
    ///
    /// No database, on purpose. [`load`] is `fetch_optional` and then this
    /// function, so the only thing a database adds here is the twenty lines of
    /// `ALTER TABLE … DROP CONSTRAINT` it would take to write a `path` the check
    /// constraint exists to refuse — which would be a test of the belt getting
    /// in the way of the braces.
    #[test]
    fn a_path_or_a_model_this_build_does_not_know_refuses_the_read() {
        let now = Utc::now();
        let row = |path: &str, model: &str| Row {
            path: path.to_owned(),
            verified_model: model.to_owned(),
            verified_at: now,
        };

        assert_eq!(
            row("api_key", "claude-opus-5")
                .into_access()
                .expect("parses"),
            ModelAccess {
                path: ModelPath::ApiKey,
                model: ModelId::Opus5,
                verified_at: now,
            }
        );

        for (path, model, needle) in [
            ("bedrock", "claude-opus-5", "bedrock"),
            ("api_key", "gpt-5", "gpt-5"),
        ] {
            let err = row(path, model).into_access().expect_err("must refuse");
            assert!(
                matches!(&err, StoreError::Conflict(msg) if msg.contains(needle)),
                "{path}/{model}: {err}"
            );
        }
    }

    /// RLS, not a `WHERE` anybody has to remember. Another tenant's connection
    /// is not merely unlisted; it is invisible.
    #[tokio::test]
    async fn one_tenants_connection_is_invisible_to_another() {
        let Some((db, mine)) = fixture().await else {
            return;
        };
        let theirs = seed_tenant(&db).await;

        let now = Utc::now();
        let access = ModelAccess {
            path: ModelPath::ApiKey,
            model: ModelId::Sonnet5,
            verified_at: now,
        };
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        save(&mut tx, &access, now).await.expect("save");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        assert_eq!(load(&mut tx).await.expect("load"), None);
        tx.commit().await.expect("commit");

        // And a tenant cannot file a row wearing somebody else's id: the policy
        // is `with check`, so the INSERT below is refused by the database.
        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        let forged = sqlx::query(
            "INSERT INTO tenant_model_access (tenant_id, path, verified_model, verified_at) \
             VALUES ($1, 'api_key', 'claude-opus-5', now())",
        )
        .bind(mine.as_uuid())
        .execute(&mut **tx)
        .await;
        assert!(forged.is_err(), "with check must refuse a forged tenant_id");
        tx.rollback().await.expect("rollback");

        // The nil employee id is not an employee, which is what keeps the
        // tenant's key out of every offboarding sweep.
        assert_eq!(
            ModelAccess::secret_ref(mine)
                .unwrap()
                .employee_id()
                .as_uuid(),
            Uuid::nil()
        );
    }
}
