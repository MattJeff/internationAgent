//! `console_accounts`: a **person** who may open the console, and the tenant she
//! opens.
//!
//! **The table is `console_accounts`, not `accounts`** — that name has belonged
//! to the seller vertical's CRM since `0011_revenue.sql`, where it means a
//! company we sell *to*. `0089` argues the collision and how it announced
//! itself. This module is still `accounts`, because nothing in Rust collides:
//! the CRM's rows are `crate::revenue`'s.
//!
//! `migrations/0089_une_personne_ouvre_la_console.sql` is the design document —
//! why the digest is a PBKDF2 where [`crate::api_keys`]'s is an HMAC, why the
//! address is unique across the deployment, and why deactivation is a column
//! here and a DELETE there. This is the four statements that touch the table.
//!
//! # The one function that runs before there is a tenant
//!
//! [`credentials`] is handed an email address and its whole job is to answer
//! "whose is this" — exactly the shape [`crate::api_keys::lookup`] has, one
//! layer earlier, and it gets the same four guards for the same reason:
//!
//! 1. **`READ ONLY`.** Postgres refuses any write in that transaction,
//!    including one a later edit adds without noticing what kind of transaction
//!    it is in.
//! 2. **The SQL is a `&'static str`** and the address arrives as a bound
//!    parameter.
//! 3. **The projection is four columns of one table**, and the `deactivated_at`
//!    predicate the whole "a closed account cannot log in" property rests on is
//!    inside that one string — there is no second reader that could forget it.
//! 4. **It returns [`Credentials`]**, which has no public constructor here, so
//!    "the tenant came from the row" is a fact about the type.
//!
//! Everything else in this module opens an admin transaction too, and for the
//! blunter reason: `0089` grants `app_role` a column-level SELECT and nothing
//! else at all, so a tenant transaction reaching this table to write dies with
//! `42501` rather than doing it.

use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use agentos_domain::ids::TenantId;

use crate::api_keys;
use crate::audit::AuditActor;
use crate::db::{Db, StoreError};

/// One person, as the platform surface renders her. **No `password_hash`**:
/// nothing outside the verification path needs the stored bytes, and a struct
/// that carries them is a struct somebody serialises into a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    /// The handle every other call names her by.
    pub id: Uuid,
    /// Whose console she opens. Written at creation by the platform, never by
    /// her.
    pub tenant_id: TenantId,
    /// Normalised: lower-case, trimmed. The `console_accounts_email_is_normalised`
    /// CHECK is what makes that true rather than this sentence.
    pub email: String,
    pub created_at: DateTime<Utc>,
    /// `None` while she may still open a session.
    pub deactivated_at: Option<DateTime<Utc>>,
}

/// What a login attempt needs, and nothing else.
///
/// Deliberately not `Serialize` and with no constructor outside this module: the
/// only way to hold one is [`credentials`], i.e. to have named an address that
/// is a row.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub id: Uuid,
    pub tenant_id: TenantId,
    /// `[version:1][salt:16][derived:32]`. Verified by
    /// `apps/server/src/routes/accounts.rs`, which owns the KDF; this crate has
    /// never hashed anything and does not start here.
    pub password_hash: Vec<u8>,
    /// **Read, not filtered on.** The row comes back whether or not the account
    /// is live, so the caller can spend the KDF before it looks — a query that
    /// filtered here would make a deactivated account answer faster than a live
    /// one with a wrong password, which is a timing oracle for "this address is
    /// one of ours".
    pub deactivated_at: Option<DateTime<Utc>>,
}

/// What a deactivation actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deactivated {
    /// Whose person this was — so a platform operator working from a screenshot
    /// finds out which customer they just locked out.
    pub tenant_id: TenantId,
    /// When. The **first** time, not this call's clock: deactivating twice is
    /// the state the caller wanted and must not rewrite the date.
    pub deactivated_at: DateTime<Utc>,
    /// Whether there was a live console session to destroy, destroyed in this
    /// same commit.
    pub session_revoked: bool,
}

/// File one person. The platform does this; nobody else can.
///
/// `password_hash` is already derived — see the module docs on why this crate
/// never sees a password.
///
/// Errors worth matching on:
///
/// * [`StoreError::UnknownTenant`] — no `tenants` row for `tenant_id`.
/// * [`StoreError::Conflict`] — `console_accounts_email_key`, i.e. that address is
///   already somebody's, possibly somebody else's customer's. `0089` argues why
///   that leak is acceptable on a surface only the vendor can reach.
///
/// No audit row, deliberately, and it is the one place in this workspace where
/// that is the right answer: `api_keys::issue` writes one because revoking
/// **deletes** its row and the trail is all that survives. Nothing deletes an
/// account. `created_at` and `deactivated_at` are the history, in the table that
/// still has it.
pub async fn create(
    db: &Db,
    id: Uuid,
    tenant_id: TenantId,
    email: &str,
    password_hash: &[u8],
    now: DateTime<Utc>,
) -> Result<AccountRecord, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    let row = sqlx::query(
        "INSERT INTO console_accounts (id, tenant_id, email, password_hash, created_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING created_at",
    )
    .bind(id)
    .bind(tenant_id.as_uuid())
    .bind(email)
    .bind(password_hash)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;

    tx.commit().await?;

    Ok(AccountRecord {
        id,
        tenant_id,
        email: email.to_owned(),
        created_at,
        deactivated_at: None,
    })
}

/// Resolve an address to what is needed to check a password.
///
/// `None` is "no row", which the caller must render **identically** to a wrong
/// password — including in how long it took. See
/// `apps/server/src/routes/accounts.rs`, which spends the KDF against a dummy
/// digest on this branch precisely so that it can.
pub async fn credentials(db: &Db, email: &str) -> Result<Option<Credentials>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    // The escape hatch, declawed — the same four guards `api_keys::lookup` has,
    // argued in the module docs.
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;

    let row = sqlx::query(
        "SELECT id, tenant_id, password_hash, deactivated_at FROM console_accounts WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?;

    tx.rollback().await?;

    row.map(|row| {
        Ok::<_, sqlx::Error>(Credentials {
            id: row.try_get("id")?,
            tenant_id: TenantId::from_uuid(row.try_get("tenant_id")?),
            password_hash: row.try_get("password_hash")?,
            deactivated_at: row.try_get("deactivated_at")?,
        })
    })
    .transpose()
    .map_err(StoreError::from)
}

/// Destroy this person's live console session, if she has one.
///
/// Called on the way *in*: `api_keys_tenant_label_key` allows one row per
/// `(tenant, label)`, so logging in twice without this is a `409` rather than a
/// second session. Which is the property being kept — one live token per
/// person, so "she is logged in on some machine we forgot about" is not a
/// state this system can be in.
pub async fn clear_session(
    db: &Db,
    tenant_id: TenantId,
    account_id: Uuid,
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<Option<Uuid>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let revoked = api_keys::revoke_session_in(&mut tx, tenant_id, account_id, actor, now).await?;
    tx.commit().await?;
    Ok(revoked)
}

/// Close one person's access, and take her live token with it **in one commit**.
///
/// This is the revocation that `routes::platform`'s argument depends on, and the
/// single transaction is not tidiness. Two calls — deactivate, then revoke —
/// leave a window in which the account is closed and the token still reads every
/// row of that tenant; if the second call is the one that fails, the window does
/// not close on its own, and nothing anywhere would say so. Postgres either
/// takes both statements or neither.
///
/// Idempotent: `coalesce` keeps the original date, so a second call reports what
/// the first did rather than rewriting when it happened. [`StoreError::NotFound`]
/// only for an id that names nobody.
pub async fn deactivate(
    db: &Db,
    account_id: Uuid,
    actor: &AuditActor,
    now: DateTime<Utc>,
) -> Result<Deactivated, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;

    let row = sqlx::query(
        "UPDATE console_accounts SET deactivated_at = coalesce(deactivated_at, $2) \
          WHERE id = $1 RETURNING tenant_id, deactivated_at",
    )
    .bind(account_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(StoreError::NotFound)?;

    let tenant_id = TenantId::from_uuid(row.try_get("tenant_id")?);
    let deactivated_at: DateTime<Utc> = row.try_get("deactivated_at")?;

    let session_revoked =
        api_keys::revoke_session_in(&mut tx, tenant_id, account_id, actor, now).await?;

    tx.commit().await?;

    Ok(Deactivated {
        tenant_id,
        deactivated_at,
        session_revoked: session_revoked.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database of this module's own, for [`credentials`]'s sake: it scans
    /// `console_accounts` with **no tenant predicate** — that is its whole job — so a
    /// row another package's test left behind is a row these assertions can
    /// see. Same reasoning as `api_keys`, one table over.
    async fn db() -> Option<Db> {
        crate::db::private_db("accounts").await
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

    /// A well-formed digest that is not one: 49 bytes, the shape the CHECK
    /// wants. This crate never derives one, so the tests here do not either.
    fn digest() -> Vec<u8> {
        let mut out = vec![1u8];
        for _ in 0..3 {
            out.extend_from_slice(Uuid::now_v7().as_bytes());
        }
        assert_eq!(out.len(), 49, "the shape `console_accounts` insists on");
        out
    }

    fn email(who: &str) -> String {
        format!("{who}-{}@example.test", Uuid::now_v7().simple())
    }

    /// Issue a session key for this person, the way the login route does.
    async fn open_session(db: &Db, tenant: TenantId, account: Uuid) -> Uuid {
        let id = Uuid::now_v7();
        let mut hash = [0u8; 32];
        hash[..16].copy_from_slice(Uuid::now_v7().as_bytes());
        hash[16..].copy_from_slice(Uuid::now_v7().as_bytes());
        api_keys::issue(
            db,
            id,
            tenant,
            &api_keys::session_label(account),
            &hash,
            &actor(),
            Utc::now(),
        )
        .await
        .expect("issue the session key");
        id
    }

    /// **Two people of two tenants do not see each other.**
    ///
    /// Through `tenant_tx`, which is the transaction every console read runs
    /// in: `SET LOCAL ROLE app_role` plus `app.tenant_id`, so the policy binds.
    /// B counts the table and finds only its own person; A's row is not
    /// "filtered from a list", it does not exist as far as that transaction is
    /// concerned, and neither does an attempt to name it by id.
    ///
    /// Then the second belt, which is the one that is not everywhere: even for
    /// its **own** row, a tenant transaction cannot read `password_hash` at all
    /// — `0089` grants SELECT column by column and leaves that one out, so
    /// Postgres refuses the statement instead of returning something.
    #[tokio::test]
    async fn two_people_of_two_tenants_do_not_see_each_other() {
        let Some(db) = db().await else { return };
        let a = tenant(&db, "alpha").await;
        let b = tenant(&db, "beta").await;

        let anna = create(
            &db,
            Uuid::now_v7(),
            a,
            &email("anna"),
            &digest(),
            Utc::now(),
        )
        .await
        .expect("anna");
        let bruno = create(
            &db,
            Uuid::now_v7(),
            b,
            &email("bruno"),
            &digest(),
            Utc::now(),
        )
        .await
        .expect("bruno");

        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        let mine: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM console_accounts ORDER BY created_at")
                .fetch_all(&mut **tx)
                .await
                .expect("list");
        assert_eq!(mine, vec![bruno.id], "B sees its own person and no other");

        let named: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM console_accounts WHERE id = $1")
                .bind(anna.id)
                .fetch_optional(&mut **tx)
                .await
                .expect("name A's person from B");
        assert_eq!(named, None, "naming the id does not get past the policy");

        // The column-level grant, on B's own row, so RLS is not what refuses.
        let denied = sqlx::query_scalar::<_, Vec<u8>>("SELECT password_hash FROM console_accounts")
            .fetch_all(&mut **tx)
            .await;
        let err = denied.expect_err("app_role must not be able to read a digest");
        assert_eq!(
            err.as_database_error()
                .and_then(sqlx::error::DatabaseError::code),
            Some(std::borrow::Cow::Borrowed("42501")),
            "not filtered — refused: {err}"
        );
        tx.rollback().await.expect("rollback");
    }

    /// **Closing an account takes its live token with it, in one commit.**
    ///
    /// The property the whole session design rests on: a browser holding a
    /// token that was minted before the deactivation stops reading on the very
    /// next request, because there is no row left for it to resolve to. And the
    /// account itself stops answering, which is the half the login route reads.
    #[tokio::test]
    async fn deactivating_a_person_destroys_the_session_she_is_holding() {
        let Some(db) = db().await else { return };
        let t = tenant(&db, "closing").await;
        let addr = email("clara");
        let clara = create(&db, Uuid::now_v7(), t, &addr, &digest(), Utc::now())
            .await
            .expect("clara");
        let key = open_session(&db, t, clara.id).await;

        let before = credentials(&db, &addr).await.expect("read").expect("live");
        assert_eq!(before.tenant_id, t);
        assert_eq!(before.deactivated_at, None);

        let closed = deactivate(&db, clara.id, &actor(), Utc::now())
            .await
            .expect("deactivate");
        assert_eq!(closed.tenant_id, t);
        assert!(closed.session_revoked, "there was a session and it is gone");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let still: Option<Uuid> = sqlx::query_scalar("SELECT id FROM api_keys WHERE id = $1")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await
            .expect("look for the key");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            still, None,
            "the token resolves to nothing on the next call"
        );

        let after = credentials(&db, &addr).await.expect("read").expect("row");
        assert!(
            after.deactivated_at.is_some(),
            "the row stays, named and closed — it is not deleted"
        );

        // Twice is the state the caller wanted, and the date does not move.
        let again = deactivate(&db, clara.id, &actor(), Utc::now())
            .await
            .expect("idempotent");
        assert_eq!(again.deactivated_at, closed.deactivated_at);
        assert!(!again.session_revoked, "there was nothing left to revoke");

        assert!(matches!(
            deactivate(&db, Uuid::now_v7(), &actor(), Utc::now()).await,
            Err(StoreError::NotFound)
        ));
    }

    /// One address is one person, deployment-wide, and one person has at most
    /// one live session.
    #[tokio::test]
    async fn an_address_is_taken_once_and_a_session_is_held_once() {
        let Some(db) = db().await else { return };
        let a = tenant(&db, "onceone").await;
        let b = tenant(&db, "oncetwo").await;
        let addr = email("shared");

        let dana = create(&db, Uuid::now_v7(), a, &addr, &digest(), Utc::now())
            .await
            .expect("dana");
        assert!(
            matches!(
                create(&db, Uuid::now_v7(), b, &addr, &digest(), Utc::now()).await,
                Err(StoreError::Conflict(_))
            ),
            "the same address cannot be two people, even under two tenants"
        );

        // An unknown address resolves to nobody rather than to the first row.
        assert!(
            credentials(&db, &email("nobody"))
                .await
                .expect("read")
                .is_none()
        );

        open_session(&db, a, dana.id).await;
        let cleared = clear_session(&db, a, dana.id, &actor(), Utc::now())
            .await
            .expect("clear");
        assert!(cleared.is_some(), "the first session was there to clear");
        // Clearing again is not an error: it is the ordinary first login.
        assert_eq!(
            clear_session(&db, a, dana.id, &actor(), Utc::now())
                .await
                .expect("clear"),
            None
        );
        // ...and now a second login can mint, which is what `clear_session`
        // buys: without it this is `api_keys_tenant_label_key`.
        open_session(&db, a, dana.id).await;
    }

    /// An account for a tenant that was never created is the first-run mistake,
    /// not a 500. Same variant `api_keys::issue` produces for the same reason.
    #[tokio::test]
    async fn an_account_needs_a_tenant_that_exists() {
        let Some(db) = db().await else { return };
        assert!(matches!(
            create(
                &db,
                Uuid::now_v7(),
                TenantId::new_v7(Utc::now()),
                &email("ghost"),
                &digest(),
                Utc::now(),
            )
            .await,
            Err(StoreError::UnknownTenant(_))
        ));
    }
}
