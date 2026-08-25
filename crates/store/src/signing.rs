//! Persistence for employee signing keys: `0014_identity.sql` in Rust.
//!
//! Read the schema comment first; it is the design document. What this module
//! adds is one rule the SQL cannot state on its own.
//!
//! # Two readers, and only one of them can see the private half
//!
//! [`published_keys`] is what the unauthenticated JWKS endpoint calls. Its
//! `SELECT` names `public_key` and nothing else, so `sealed_private_key` is not
//! in the projection, is not in the row type, and is not in any value the
//! handler can reach. "The endpoint must not leak the private key" is therefore
//! not a review obligation about what the handler does with the row — the row
//! does not contain it.
//!
//! [`load`] is the signing path and returns both halves. It is the only
//! function here that touches the sealed column, and what it returns is a blob
//! nobody can read without the master key.
//!
//! # `published_keys` filters on lifecycle, and that is the revocation story
//!
//! A key is published only while its employee is `active`. So suspending an
//! employee withdraws its identity within one HTTP cache lifetime, using the
//! lever an operator already reaches for, and there is no second "revoked"
//! flag to forget to set. It is also the same ordering as the Policy Gate,
//! which refuses a suspended employee before it reads any policy: an employee
//! that may not act should not be one whose signatures still verify.
//!
//! ponytail: no revocation list and no `not_before`. A verifier that fetched
//! the document ten minutes ago still believes the old key, which is exactly
//! the property every JWKS deployment on the internet has. `Cache-Control` on
//! the endpoint is the knob; a CRL is a second source of truth.

use agentos_domain::ids::{EmployeeId, TenantId};

use crate::db::{StoreError, TenantTx};

/// An employee's keypair as stored: one half to publish, one half sealed.
///
/// `sealed_private_key` is the envelope blob from
/// `agentos_providers::secrets::Envelope::to_bytes` and is opaque here — this
/// crate has no cipher and no master key, and that is the point. It cannot
/// accidentally decrypt anything.
///
/// Deliberately not `Serialize`: it carries the sealed half, and a row type
/// that can be serialised is a row type that ends up in a response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKey {
    /// 32 raw Ed25519 bytes. Public.
    pub public_key: Vec<u8>,
    /// The sealed private key. Useless without `AGENTOS_MASTER_KEY`.
    pub sealed_private_key: Vec<u8>,
}

/// Give this employee a keypair if it has none, and report whether one was
/// written.
///
/// `ON CONFLICT DO NOTHING`, and the "do nothing" is the safety property.
/// Overwriting would mint a second identity for an employee that has already
/// published the first one — every signature in flight becomes unverifiable,
/// silently, at whatever moment two boots raced. A caller that genuinely wants
/// a new key deletes the row first, which is a sentence somebody has to write.
///
/// Returns `false` when a key was already there, so an idempotent
/// provisioning step can tell "minted" from "already had one" without a second
/// round trip.
pub async fn ensure(
    tx: &mut TenantTx<'_>,
    tenant_id: TenantId,
    employee_id: EmployeeId,
    key: &StoredKey,
) -> Result<bool, StoreError> {
    let inserted = sqlx::query(
        "INSERT INTO employee_signing_keys \
         (tenant_id, employee_id, public_key, sealed_private_key) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, employee_id) DO NOTHING",
    )
    .bind(tenant_id.as_uuid())
    .bind(employee_id.as_uuid())
    .bind(&key.public_key)
    .bind(&key.sealed_private_key)
    .execute(&mut ***tx)
    .await?
    .rows_affected();

    Ok(inserted == 1)
}

/// Both halves, for signing.
///
/// [`StoreError::NotFound`] when the employee has no key or belongs to another
/// tenant — RLS makes those indistinguishable, deliberately.
pub async fn load(tx: &mut TenantTx<'_>, employee_id: EmployeeId) -> Result<StoredKey, StoreError> {
    let (public_key, sealed_private_key): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT public_key, sealed_private_key FROM employee_signing_keys \
         WHERE employee_id = $1",
    )
    .bind(employee_id.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;

    Ok(StoredKey {
        public_key,
        sealed_private_key,
    })
}

/// The public keys this employee is currently published under.
///
/// **The only query the JWKS endpoint runs.** It selects `public_key` alone —
/// see the module docs — and it returns an empty vector rather than
/// [`StoreError::NotFound`] for an employee with no key or a lifecycle other
/// than `active`, because "this employee publishes no keys" is an answer and
/// not a failure. The caller decides whether that is a 404 or an empty set.
pub async fn published_keys(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
) -> Result<Vec<Vec<u8>>, StoreError> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT k.public_key FROM employee_signing_keys k \
           JOIN employees e ON e.id = k.employee_id \
          WHERE k.employee_id = $1 AND e.lifecycle = 'active' \
          ORDER BY k.created_at, k.public_key",
    )
    .bind(employee_id.as_uuid())
    .fetch_all(&mut ***tx)
    .await?;

    Ok(rows.into_iter().map(|(key,)| key).collect())
}

/// Destroy an employee's key. Offboarding, and rotation's first half.
///
/// Idempotent: deleting a key that is already gone is `Ok(false)`, not an
/// error, on the same reasoning as every `release` in `agentos-providers` — the
/// caller is asserting a desired state, and the state is already true.
pub async fn delete(tx: &mut TenantTx<'_>, employee_id: EmployeeId) -> Result<bool, StoreError> {
    let deleted = sqlx::query("DELETE FROM employee_signing_keys WHERE employee_id = $1")
        .bind(employee_id.as_uuid())
        .execute(&mut ***tx)
        .await?
        .rows_affected();

    Ok(deleted > 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::future::Future;

    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::db::Db;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; signing key storage needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one active employee.
    async fn seed(db: &Db, lifecycle: &str) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let (tenant, employee) = (TenantId::new_v7(now), EmployeeId::new_v7(now));

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().simple().to_string())
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, $4)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid().simple().to_string())
        .bind(lifecycle)
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");

        (tenant, employee)
    }

    fn key(seed: u8) -> StoredKey {
        StoredKey {
            public_key: vec![seed; 32],
            sealed_private_key: vec![seed; 91],
        }
    }

    #[tokio::test]
    async fn a_key_is_written_once_and_never_silently_replaced() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "active").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            ensure(&mut tx, tenant, employee, &key(1))
                .await
                .expect("mint")
        );
        // A second boot, a retried provisioning step, two replicas racing.
        assert!(
            !ensure(&mut tx, tenant, employee, &key(2))
                .await
                .expect("second call")
        );
        assert_eq!(load(&mut tx, employee).await.expect("load"), key(1));
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn the_published_query_cannot_return_the_private_half() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "active").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        ensure(&mut tx, tenant, employee, &key(3))
            .await
            .expect("mint");

        let published = published_keys(&mut tx, employee).await.expect("published");
        assert_eq!(published, vec![vec![3u8; 32]]);
        // The sealed blob is a different length, so "no row here is the sealed
        // half" is checkable rather than a claim about the SQL.
        assert!(published.iter().all(|k| k.len() == 32));
        assert!(!published.contains(&key(3).sealed_private_key));
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn only_an_active_employee_publishes_a_key() {
        let Some(db) = db().await else { return };

        for lifecycle in ["draft", "suspended", "terminated"] {
            let (tenant, employee) = seed(&db, lifecycle).await;
            let mut tx = db.tenant_tx(tenant).await.expect("tx");
            ensure(&mut tx, tenant, employee, &key(4))
                .await
                .expect("mint");

            assert!(
                published_keys(&mut tx, employee)
                    .await
                    .expect("published")
                    .is_empty(),
                "a {lifecycle} employee must not publish a key"
            );
            // The row is still there; the employee can be reactivated and keep
            // its identity rather than being issued a new one.
            assert!(load(&mut tx, employee).await.is_ok());
            tx.commit().await.expect("commit");
        }
    }

    #[tokio::test]
    async fn one_tenant_cannot_read_or_publish_anothers_key() {
        let Some(db) = db().await else { return };
        let (mine, my_employee) = seed(&db, "active").await;
        let (theirs, their_employee) = seed(&db, "active").await;

        for (tenant, employee, seed_byte) in [(mine, my_employee, 5), (theirs, their_employee, 6)] {
            let mut tx = db.tenant_tx(tenant).await.expect("tx");
            ensure(&mut tx, tenant, employee, &key(seed_byte))
                .await
                .expect("mint");
            tx.commit().await.expect("commit");
        }

        // Row-level security, not a WHERE clause: the query below names the
        // other tenant's employee by id and still sees nothing.
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        assert!(matches!(
            load(&mut tx, their_employee).await,
            Err(StoreError::NotFound)
        ));
        assert!(
            published_keys(&mut tx, their_employee)
                .await
                .expect("published")
                .is_empty()
        );
        assert_eq!(load(&mut tx, my_employee).await.expect("mine"), key(5));
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn rotation_is_delete_then_insert_and_deleting_twice_is_fine() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "active").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        ensure(&mut tx, tenant, employee, &key(7))
            .await
            .expect("mint");

        assert!(delete(&mut tx, employee).await.expect("delete"));
        assert!(!delete(&mut tx, employee).await.expect("again"));
        assert!(matches!(
            load(&mut tx, employee).await,
            Err(StoreError::NotFound)
        ));

        // And the slot is free for the new key.
        assert!(
            ensure(&mut tx, tenant, employee, &key(8))
                .await
                .expect("remint")
        );
        assert_eq!(load(&mut tx, employee).await.expect("load"), key(8));
        tx.commit().await.expect("commit");
    }

    /// How long a statement that must be REFUSED is given before we conclude the
    /// database, not the schema, is broken.
    ///
    /// This is the only test here that makes Postgres raise an error, so it is
    /// the only one that can hit the failure mode below. Ten seconds is two
    /// orders of magnitude more than a constraint violation needs.
    const REFUSAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// Run one statement that must be refused, and say which of the two things
    /// went wrong if it is not.
    ///
    /// A bare `.await` here can hang **forever** on a Postgres whose stderr
    /// cannot be written — `log_destination = stderr` with a full disk under the
    /// container's log driver blocks the backend mid-ERROR, so successful
    /// statements return and refused ones never do. That looks exactly like a
    /// missing constraint if you are reading a stalled test run, and it is not.
    /// Reproduce it outside Rust with `psql -c 'select 1/0'`: if that hangs, so
    /// does every refusal, and the box is what needs fixing.
    async fn must_be_refused(fut: impl Future<Output = Result<bool, StoreError>>) {
        match tokio::time::timeout(REFUSAL_TIMEOUT, fut).await {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("the database accepted a row its CHECK constraints forbid"),
            Err(_) => panic!(
                "the database neither accepted nor refused the row within {REFUSAL_TIMEOUT:?}. \
                 This is not a schema failure: a Postgres that cannot write its own stderr \
                 blocks mid-ERROR. Check `psql -c 'select 1/0'` and the host's free disk."
            ),
        }
    }

    #[tokio::test]
    async fn a_key_that_is_not_thirty_two_bytes_is_refused_by_the_database() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "active").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let short = StoredKey {
            public_key: vec![9u8; 31],
            sealed_private_key: vec![9u8; 91],
        };
        must_be_refused(ensure(&mut tx, tenant, employee, &short)).await;
        tx.rollback().await.expect("rollback");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let unsealed = StoredKey {
            public_key: vec![9u8; 32],
            sealed_private_key: Vec::new(),
        };
        must_be_refused(ensure(&mut tx, tenant, employee, &unsealed)).await;
        tx.rollback().await.expect("rollback");

        // Nothing landed.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(matches!(
            load(&mut tx, employee).await,
            Err(StoreError::NotFound)
        ));
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn an_unknown_employee_has_no_key_rather_than_an_error_when_publishing() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "active").await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let ghost = EmployeeId::from_uuid(Uuid::now_v7());
        assert!(
            published_keys(&mut tx, ghost)
                .await
                .expect("published")
                .is_empty()
        );
        assert!(matches!(
            load(&mut tx, ghost).await,
            Err(StoreError::NotFound)
        ));
        tx.commit().await.expect("commit");
    }
}
