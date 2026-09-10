//! Le pot de cookies d'un employé, scellé dans `employee_resources.sealed_cookies`.
//!
//! [`ChromeBrowser`](agentos_providers::browser_chrome::ChromeBrowser) parle
//! cookies en clair — `Network.setCookies` n'accepte rien d'autre — et ne
//! connaît ni le locataire ni la clé maître. Ce module est l'autre moitié :
//! il retrouve la ligne par l'identifiant que le fournisseur tient
//! (`provider = 'chrome'`, `external_id = ctx-<tag>`), y lit le locataire et
//! l'employé, et scelle sous `browser://<locataire>/<employé>` avec le
//! chiffre de [`crate::identity::envelope`] — le même que `mcp://`,
//! `model://` et `webhook://`, pour la raison que ces trois-là donnent : deux
//! chiffres dérivés d'une clé sont deux moitiés qui ne s'ouvrent pas.
//!
//! `admin_tx_bypassing_rls`, argumenté dans la migration 0095 : la recherche
//! précède le locataire. Ce que la RLS aurait garanti, l'AAD le garantit —
//! une enveloppe recopiée sur la ligne d'un autre ne s'ouvre pas.

use std::sync::Arc;

use agentos_domain::ids::{EmployeeId, TenantId};
use agentos_providers::browser_chrome::CookieJar;
use agentos_providers::secrets::{Envelope, LocalEnvelopeSecretStore};
use agentos_providers::{ProviderError, Secret};
use agentos_store::db::Db;
use async_trait::async_trait;
use uuid::Uuid;

/// Only `chrome` rows carry a jar: the other adapters persist their own way.
const PROVIDER: &str = agentos_providers::browser_chrome::PROVIDER;

/// The jar, over the database and the deployment's cipher.
pub struct SealedCookieJar {
    db: Db,
    cipher: Arc<LocalEnvelopeSecretStore>,
}

impl SealedCookieJar {
    /// One per deployment; `cipher` is [`crate::identity::envelope`]'s.
    pub fn new(db: Db, cipher: Arc<LocalEnvelopeSecretStore>) -> Self {
        Self { db, cipher }
    }

    /// The encryption context. A scheme, like the three others, so the key
    /// spaces cannot collide.
    fn context(tenant: TenantId, employee: EmployeeId) -> String {
        format!("browser://{}/{}", tenant.as_uuid(), employee.as_uuid())
    }

    /// The row the provider's id names: who it belongs to and what it holds.
    async fn row(
        &self,
        ctx: &str,
    ) -> Result<Option<(TenantId, EmployeeId, Option<Vec<u8>>)>, ProviderError> {
        let mut tx = self
            .db
            .admin_tx_bypassing_rls()
            .await
            .map_err(|_| ProviderError::timeout())?;
        let row = sqlx::query_as::<_, (Uuid, Uuid, Option<Vec<u8>>)>(
            "SELECT tenant_id, employee_id, sealed_cookies FROM employee_resources \
              WHERE provider = $1 AND external_id = $2",
        )
        .bind(PROVIDER)
        .bind(ctx)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ProviderError::timeout())?;
        let _ = tx.rollback().await;
        Ok(row.map(|(tenant, employee, sealed)| {
            (
                TenantId::from_uuid(tenant),
                EmployeeId::from_uuid(employee),
                sealed,
            )
        }))
    }

    async fn write(&self, ctx: &str, sealed: Option<Vec<u8>>) -> Result<(), ProviderError> {
        let mut tx = self
            .db
            .admin_tx_bypassing_rls()
            .await
            .map_err(|_| ProviderError::timeout())?;
        sqlx::query(
            "UPDATE employee_resources SET sealed_cookies = $3, updated_at = now() \
              WHERE provider = $1 AND external_id = $2",
        )
        .bind(PROVIDER)
        .bind(ctx)
        .bind(sealed)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProviderError::timeout())?;
        tx.commit().await.map_err(|_| ProviderError::timeout())
    }
}

#[async_trait]
impl CookieJar for SealedCookieJar {
    async fn load(&self, ctx: &str) -> Result<Option<Secret>, ProviderError> {
        let Some((tenant, employee, Some(sealed))) = self.row(ctx).await? else {
            return Ok(None);
        };
        // A jar that no longer opens — a master key rotated without the
        // window, a corrupt row — is a logged-out employee, not a broken
        // browser: `None`, and the next close overwrites it.
        let opened = Envelope::from_bytes(&sealed).and_then(|envelope| {
            self.cipher
                .open_in(tenant, &Self::context(tenant, employee), &envelope)
        });
        match opened {
            Ok(secret) => Ok(Some(secret)),
            Err(err) => {
                tracing::warn!(
                    ctx,
                    code = err.code(),
                    "the sealed cookie jar does not open; starting logged out"
                );
                Ok(None)
            }
        }
    }

    async fn save(&self, ctx: &str, cookies: &Secret) -> Result<(), ProviderError> {
        // No row is a context the provisioner has not written yet, or one it
        // has already released: nowhere to put the jar, and nothing to fail.
        let Some((tenant, employee, _)) = self.row(ctx).await? else {
            return Ok(());
        };
        let sealed = self
            .cipher
            .seal_in(tenant, &Self::context(tenant, employee), cookies)?;
        self.write(ctx, Some(sealed.to_bytes())).await
    }

    async fn forget(&self, ctx: &str) -> Result<(), ProviderError> {
        self.write(ctx, None).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sha2::{Digest as _, Sha256};

    use super::*;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the cookie jar needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant, an employee, and its `browser` resource row bound to `chrome`.
    async fn seed(db: &Db) -> (TenantId, EmployeeId, String) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let ctx = format!("ctx-{}", employee.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let label = format!("jar-{}", employee.as_uuid().simple());
        sqlx::query(
            "INSERT INTO tenants (id, slug, name, legal_form, postal_address, siren, \
                                  rcs_city, vat_number, vat_rate_bp, late_penalty_rate_bp) \
             VALUES ($1, $2, $2, 'SAS', '1 rue de la Fixture, 75001 Paris', '552100554', \
                     'Paris', 'FR40552100554', 2000, 1000)",
        )
        .bind(tenant.as_uuid())
        .bind(&label)
        .execute(&mut *tx)
        .await
        .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'ada', 'ada', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO employee_resources \
                 (employee_id, step, tenant_id, state, provider, external_id) \
             VALUES ($1, 'browser', $2, 'ready', 'chrome', $3)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(&ctx)
        .execute(&mut *tx)
        .await
        .expect("resource");
        tx.commit().await.expect("commit");
        (tenant, employee, ctx)
    }

    fn cipher(key: &str) -> Arc<LocalEnvelopeSecretStore> {
        Arc::new(LocalEnvelopeSecretStore::new(
            Sha256::digest(key.as_bytes()).into(),
        ))
    }

    /// The round trip, the sealing, the context, and the forgetting — each
    /// with its disarm.
    #[tokio::test]
    async fn the_jar_is_sealed_under_the_employee_and_forgotten_on_release() {
        let Some(db) = db().await else { return };
        let (tenant, employee, ctx) = seed(&db).await;
        let jar = SealedCookieJar::new(db.clone(), cipher("master"));
        const COOKIES: &str = r#"[{"name":"seat","value":"ada-session-7f3a"}]"#;

        assert!(
            jar.load(&ctx).await.unwrap().is_none(),
            "a fresh context has no jar"
        );
        jar.save(&ctx, &Secret::new(COOKIES)).await.unwrap();
        assert_eq!(
            jar.load(&ctx)
                .await
                .unwrap()
                .expect("saved")
                .expose_for_transport(),
            COOKIES
        );

        // Sealed: the row holds an envelope and not the session id.
        let mut tx = db.admin_tx_bypassing_rls().await.unwrap();
        let (stored,): (Vec<u8>,) =
            sqlx::query_as("SELECT sealed_cookies FROM employee_resources WHERE external_id = $1")
                .bind(&ctx)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            !stored.windows(16).any(|w| w == b"ada-session-7f3a"),
            "stored in the clear"
        );
        let envelope = Envelope::from_bytes(&stored).expect("an envelope");

        // Under `browser://<tenant>/<employee>` and nothing else: the same
        // bytes do not open as another employee's, nor under `mcp://`.
        let other = EmployeeId::new_v7(Utc::now());
        assert!(
            cipher("master")
                .open_in(tenant, &SealedCookieJar::context(tenant, other), &envelope)
                .is_err()
        );
        assert!(
            cipher("master")
                .open_in(tenant, &format!("mcp://{}", employee.as_uuid()), &envelope)
                .is_err()
        );
        assert!(
            cipher("master")
                .open_in(
                    tenant,
                    &SealedCookieJar::context(tenant, employee),
                    &envelope
                )
                .is_ok(),
            "the disarm: the right context opens it"
        );

        // A jar under another master key is a logged-out employee, not an
        // error the turn sees.
        let rotated = SealedCookieJar::new(db.clone(), cipher("another"));
        assert!(rotated.load(&ctx).await.unwrap().is_none());

        // Release forgets; a second forget and a forget of nothing are fine.
        jar.forget(&ctx).await.unwrap();
        assert!(jar.load(&ctx).await.unwrap().is_none());
        jar.forget(&ctx).await.unwrap();
        jar.forget("ctx-never-existed").await.unwrap();
        // And saving under a context nobody provisioned is a no-op, not a row.
        jar.save("ctx-never-existed", &Secret::new("[]"))
            .await
            .unwrap();
        assert!(jar.load("ctx-never-existed").await.unwrap().is_none());
    }
}
