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
//! appear in a diff without someone noticing. What legitimately needs it is a
//! *shape*, not a list: a loop that is cross-tenant by definition — outbox,
//! inbound, initiative, provisioning, the MCP binder, `/metrics` — a read of
//! the platform policy row, which belongs to no tenant, and the A2A ingress,
//! which has to resolve a tenant *from* the request it is authenticating, and —
//! the same shape, one layer earlier — the `api_keys` lookup, which is handed a
//! bearer token and whose whole job is to say whose it is. [`crate::api_keys`]
//! opens its transaction `READ ONLY` for that reason.
//! `grep -rn admin_tx_bypassing_rls` is the current list; a number here is not,
//! and the one that used to be here said "two callers: migrations, and the
//! outbox poller" while there were seventeen — and migrations was never one of
//! them, because [`Db::migrate`] runs the migrator against the pool and opens
//! no transaction at all.

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
/// Postgres SQLSTATE for `foreign_key_violation`. Only one of these is
/// classified — see [`TENANT_FK_SUFFIX`]; the rest stay [`StoreError::Database`]
/// because every other foreign key in this schema is checked by the handler
/// that owns it before the write, and one arriving here is a real bug.
const SQLSTATE_FOREIGN_KEY_VIOLATION: &str = "23503";

/// The tail every foreign key pointing at `tenants` carries.
///
/// Fifty of them, and Postgres named all fifty: the columns are declared
/// `tenant_id uuid not null references tenants (id)`, so the default
/// `<table>_<column>_fkey` applies without exception. Asked of the schema
/// rather than trusted:
///
/// ```sql
/// SELECT count(*) FROM pg_constraint
///  WHERE contype = 'f' AND confrelid = 'tenants'::regclass;                       -- 50
/// SELECT conname FROM pg_constraint
///  WHERE contype = 'f' AND confrelid = 'tenants'::regclass
///    AND conname NOT LIKE '%\_tenant\_id\_fkey';                                  -- none
/// SELECT conname FROM pg_constraint
///  WHERE contype = 'f' AND confrelid <> 'tenants'::regclass
///    AND conname LIKE '%\_tenant\_id\_fkey';                                      -- none
/// ```
///
/// The suffix is therefore exactly the set of "this row names a tenant that is
/// not there", with no false positives to inherit. A migration that names one
/// of these by hand takes that away, which is what
/// [`every_tenant_foreign_key_is_named_the_way_this_classifier_expects`](tests::every_tenant_foreign_key_is_named_the_way_this_classifier_expects)
/// is for.
const TENANT_FK_SUFFIX: &str = "_tenant_id_fkey";

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

    /// **The tenant every row in this transaction belongs to has no row of its
    /// own.** The string names the table whose foreign key said so.
    ///
    /// This is not a caller's mistake and it is not a bug; it is the first-run
    /// step nobody did. `AGENTOS_API_KEYS` names a tenant uuid, there is no
    /// endpoint that creates a tenant — deliberately, see `README.md` — and
    /// until somebody inserts that row by hand every write in the product fails
    /// on one of fifty foreign keys.
    ///
    /// Its own variant because of what it used to cost: the driver error landed
    /// in [`Self::Database`], came out of the HTTP surface as `500 internal`,
    /// and the only trace of the actual cause was a `foreign key constraint`
    /// line in the server log. An operator reading a 500 has no reason to look
    /// at their `AGENTOS_API_KEYS` — a 500 says *we* broke — so the first hour
    /// goes on the wrong half of the system.
    #[error("no tenants row for this transaction's tenant ({0} refused the write)")]
    UnknownTenant(String),

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
                // Only the tenants key, and only by name. A foreign key on
                // `employees` or `teams` failing means a handler skipped the
                // check it owns, and flattening that into the same answer would
                // tell an operator to go and create a tenant that is already
                // there.
                SQLSTATE_FOREIGN_KEY_VIOLATION
                    if err
                        .as_database_error()
                        .and_then(|e| e.constraint())
                        .is_some_and(|name| name.ends_with(TENANT_FK_SUFFIX)) =>
                {
                    Self::UnknownTenant(
                        err.as_database_error()
                            .and_then(|e| e.constraint())
                            .unwrap_or(TENANT_FK_SUFFIX)
                            .to_owned(),
                    )
                }
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

/// Every migration this build carries.
///
/// A `static` rather than the macro spelled inline in [`Db::migrate`], so
/// [`the_compiled_migrator_matches_the_directory`](tests::the_compiled_migrator_matches_the_directory)
/// is asserting about the object that actually runs and not about a second
/// expansion that happens to agree. `apps/server`'s `doctor` keeps its own for
/// the same reason.
///
/// Path is relative to this crate's manifest; the migrations live at the
/// workspace root so every binary in the workspace shares one history. Adding a
/// file there re-expands this only because `build.rs` says so — read it before
/// deleting it.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

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
        MIGRATOR.run(&self.pool).await?;
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

/// A database of this test module's own, created on first use and migrated.
///
/// # What it is for
///
/// Almost every test in this crate isolates itself by minting a fresh
/// `TenantId`, and RLS makes the rest of the database invisible. That works
/// because every row in this schema belongs to a tenant — with exactly one
/// exception, which the schema itself will tell you:
///
/// ```sql
/// SELECT table_name FROM information_schema.columns
///  WHERE column_name = 'tenant_id' AND is_nullable = 'YES';
/// ```
///
/// `policy_versions` and `policy_layers`. The platform ceiling is
/// `tenant_id IS NULL`, which is one row for the whole database, and there is
/// nothing for a `WHERE tenant_id = $1` to hang off. A test that writes it
/// writes it for every test in every package running beside it, and `cargo
/// test --workspace` runs one process per package against one `DATABASE_URL`.
///
/// So a test whose subject *is* that row takes a database. See
/// [`crate::policy::tests`] for the three failures this was costing.
///
/// # A fresh handle every call, deliberately
///
/// Caching the [`Db`] in a `static` is the obvious optimisation and it does not
/// work: `#[tokio::test]` builds and drops a runtime per test, and a pooled
/// connection belongs to the reactor that opened it. The second test to use a
/// cached pool waits on connections whose runtime is gone and fails with
/// `PoolTimedOut`, nowhere near the cause. Connecting is one round trip and the
/// migrations are a no-op after the first test.
///
/// # Naming
///
/// `<the database in DATABASE_URL>_<suffix>`, which is what makes the cleanup in
/// `scripts/test.sh` work: it drops every database whose name starts with this
/// run's, so these go with it. A fixed prefix would not be collected — and for a
/// long time four harnesses in `apps/server` used one (`readyz_*`, `e2e_*`,
/// `orizn_*`, `srcg_*`), so every interrupted run left a migrated database per
/// test behind and nothing on the machine ever came for them. They derive from
/// `DATABASE_URL` now, through `own_database` and `tests/common/mod.rs`. **This
/// is the rule to copy; the twenty lines below are not the interesting part.**
///
/// # Why a copy
///
/// `apps/server/src/loops/mod.rs` and `crates/app/src/gate.rs` have the same
/// twenty lines, for the same row. Sharing them would mean exporting this from
/// `agentos-store` behind a feature, and cargo unifies the features a
/// dev-dependency turns on with the ones the ordinary dependency gets — so
/// `CREATE DATABASE` would ship in the release binary to save a copy in a test.
/// Not worth it.
#[cfg(test)]
pub(crate) async fn private_db(suffix: &str) -> Option<Db> {
    use sqlx::Connection as _;

    let Ok(url) = std::env::var("DATABASE_URL") else {
        // Named after the caller, because this line is what `scripts/test.sh`'s
        // second guard prints when a run reports success and skipped instead:
        // `sort -u` over one generic message cannot say which module opted out.
        eprintln!("SKIP: DATABASE_URL is unset; the {suffix} tests need a real Postgres");
        return None;
    };

    // `postgres://user:pass@host:port/name`, or the same with `?options`. Split
    // by hand rather than pull in a URL parser for one path segment.
    let (host_part, tail) = url.rsplit_once('/').expect("DATABASE_URL names a database");
    let (base, options) = tail.split_once('?').map_or((tail, ""), |(b, o)| (b, o));
    let name = format!("{base}_{suffix}");
    let mine = if options.is_empty() {
        format!("{host_part}/{name}")
    } else {
        format!("{host_part}/{name}?{options}")
    };

    // Connect first and create only if that fails, so the ordinary path — every
    // call after the first — is one connection and no DDL.
    let db = match Db::connect(&mine).await {
        Ok(db) => db,
        Err(_) => {
            // CREATE DATABASE cannot run inside a transaction block, and `Db`
            // only hands out transactions — deliberately — so this is the one
            // place in the crate that opens a bare connection. It is also why
            // the statement is formatted rather than bound: Postgres takes no
            // parameters in DDL. `AssertSqlSafe` asks for an audit, and the
            // audit is that `name` is DATABASE_URL's own database name with a
            // literal suffix.
            let mut admin = sqlx::PgConnection::connect(&url)
                .await
                .expect("connect to the database DATABASE_URL names");
            // Ignored: two tests reaching here together is a race one of them
            // loses with `duplicate_database`, and losing it is fine — the
            // connect below is the real check.
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
                .execute(&mut admin)
                .await;
            admin.close().await.expect("close");
            Db::connect(&mine).await.expect("connect")
        }
    };

    // Idempotent: after the first test this is a read of `_sqlx_migrations`.
    db.migrate().await.expect("migrate");
    Some(db)
}

/// Block until the backend `pid` is waiting on a lock somebody else holds.
///
/// # Which of this crate's claims this is for
///
/// Four statements in this crate hand work to one worker and not two, and they
/// split in half over exactly this function. [`crate::outbox::claim_of`],
/// [`crate::initiative::claim_due`] and [`crate::calendar::claim_due`] take
/// `FOR UPDATE … SKIP LOCKED`, so a second worker **never** waits — their
/// contention tests assert the opposite of this, that both batches came back
/// full while the other transaction was still open. [`crate::backlog::claim`]
/// has no `SKIP LOCKED` and no lease: the second employee blocks on the row
/// lock, and read committed re-evaluating its `WHERE` against the committed
/// version is the whole of the mutual exclusion. So the wait is not an
/// implementation detail there, it *is* the mechanism, and a test that wants to
/// see it has to know when it has started.
///
/// # Why not a sleep
///
/// A sleep lies in both directions: too short and the contender has not reached
/// the lock, so the test asserts an interleaving it did not create and passes
/// for the wrong reason; too long and every run pays a second for a wait that is
/// over in a millisecond. `pg_blocking_pids` is PostgreSQL's own answer to "is
/// this backend stuck behind another one", so the race can proceed the instant
/// the arrangement it wants actually exists.
///
/// The pid is the contender's own `pg_backend_pid()`, read on its connection
/// *before* it issues the statement that blocks — it can report nothing after.
/// Polled from a third connection, because the two in the race are both busy.
///
/// Panics rather than returning: a contender that never blocks has taken the
/// test's premise away, and a contention test that hangs instead of failing is
/// the difference between a red run and an afternoon.
#[cfg(test)]
pub(crate) async fn wait_until_blocked(db: &Db, pid: i32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let blocked: bool = sqlx::query_scalar("SELECT cardinality(pg_blocking_pids($1)) > 0")
            .bind(pid)
            .fetch_one(&mut *tx)
            .await
            .expect("ask pg_blocking_pids who is waiting");
        tx.rollback().await.expect("rollback the probe");
        if blocked {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "backend {pid} never blocked on anybody's lock. The contention this \
             test is about did not happen, so whatever it asserts next is about \
             an interleaving that was never created."
        );
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
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

    /// **A write against a tenant that has no row is not a driver error.**
    ///
    /// The whole first-run sequence in one test: `AGENTOS_API_KEYS` names a
    /// tenant uuid, nobody inserted the row, and the first thing the product
    /// writes lands on one of fifty foreign keys. That used to arrive as
    /// [`StoreError::Database`] and leave the HTTP surface as `500 internal`
    /// with the cause only in the log.
    #[tokio::test]
    async fn a_write_for_a_tenant_with_no_row_names_the_tenant_not_the_driver() {
        let Some(db) = db().await else { return };

        // A tenant id that is real enough to authenticate with and has no row —
        // which is exactly the state a first install is in.
        let ghost = TenantId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(ghost).await.expect("tenant tx");
        let err = sqlx::query("INSERT INTO teams (id, tenant_id, slug, name) VALUES ($1,$2,$3,$3)")
            .bind(Uuid::now_v7())
            .bind(ghost.as_uuid())
            .bind(format!("ghost-{}", ghost.as_uuid().simple()))
            .execute(&mut **tx)
            .await
            .map(|_| ())
            .expect_err("a tenant with no row cannot own a team");

        assert!(
            matches!(StoreError::from(err), StoreError::UnknownTenant(name) if name == "teams_tenant_id_fkey"),
            "the missing tenant has to be its own variant; as a Database error it renders as a 500"
        );
    }

    /// **The classifier above reads constraint names, so the names are part of
    /// the schema's contract.**
    ///
    /// Asked of `pg_constraint`, not of the migrations: a `.sql` file says what
    /// somebody wrote and this says what Postgres built. The three counts are
    /// the three ways [`TENANT_FK_SUFFIX`] can stop being exactly the set of
    /// "this row names a tenant that is not there" — a hand-named key that
    /// escapes it, a key on another table that accidentally matches it, or the
    /// table being renamed out from under both.
    #[tokio::test]
    async fn every_tenant_foreign_key_is_named_the_way_this_classifier_expects() {
        let Some(db) = db().await else { return };
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        let pattern = format!("%{}", TENANT_FK_SUFFIX.replace('_', "\\_"));

        let missed: Vec<String> = sqlx::query_scalar(
            "SELECT conname::text FROM pg_constraint \
              WHERE contype = 'f' AND confrelid = 'tenants'::regclass \
                AND conname NOT LIKE $1 ORDER BY 1",
        )
        .bind(&pattern)
        .fetch_all(&mut *tx)
        .await
        .expect("query pg_constraint");
        assert!(
            missed.is_empty(),
            "these foreign keys point at `tenants` and do not end in `{TENANT_FK_SUFFIX}`, \
             so a missing tenant still comes out of the API as a 500: {missed:?}"
        );

        let stolen: Vec<String> = sqlx::query_scalar(
            "SELECT conname::text FROM pg_constraint \
              WHERE contype = 'f' AND confrelid <> 'tenants'::regclass \
                AND conname LIKE $1 ORDER BY 1",
        )
        .bind(&pattern)
        .fetch_all(&mut *tx)
        .await
        .expect("query pg_constraint");
        assert!(
            stolen.is_empty(),
            "these foreign keys end in `{TENANT_FK_SUFFIX}` and point somewhere other than \
             `tenants`, so breaking one would tell an operator to create a tenant that \
             already exists: {stolen:?}"
        );

        // A walk that finds nothing satisfies both assertions above forever.
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_constraint \
              WHERE contype = 'f' AND confrelid = 'tenants'::regclass",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("count");
        assert!(
            total >= 50,
            "only {total} foreign keys point at `tenants`; this test is asking the wrong database"
        );

        tx.rollback().await.expect("rollback");
    }

    /// **Every table in the schema is confined, and confined against its owner.**
    ///
    /// Asked of `pg_class` and `pg_policies` rather than of the migrations, for
    /// the reason the foreign-key sweep above is: a `.sql` file says what
    /// somebody wrote, and a later migration can quietly take it back. This
    /// says what Postgres built.
    ///
    /// # The three ways a table stops being confined, and why each is silent
    ///
    /// **No `enable`.** The loud one. Any behavioural test that reads across
    /// tenants catches it.
    ///
    /// **`enable` without `force`.** The quiet one, and the reason this test
    /// reads a catalog instead of writing rows. RLS does not apply to the table
    /// **owner**, and this deployment migrates as `postgres`, which owns every
    /// table here. `Db::tenant_tx` opens with `SET LOCAL ROLE app_role` to stop
    /// being the owner, so a behavioural test through `tenant_tx` passes on a
    /// table with no `force` — it is testing a role that was never the owner in
    /// the first place. What it does not cover is every other way this database
    /// is reached: `psql` on the box, a migration's own `do $$` block, a job
    /// somebody adds next year that forgets the `SET LOCAL ROLE`. `force` is
    /// what makes the policy a property of the table rather than of the
    /// caller's discipline, and only `relforcerowsecurity` can see it.
    ///
    /// **A `USING` with no `WITH CHECK`.** The asymmetric one. `USING` decides
    /// which rows are *visible*; `WITH CHECK` decides which rows may be
    /// *written*. A policy with only the first lets a tenant `INSERT` a row
    /// stamped with somebody else's `tenant_id` — a row it then cannot see,
    /// which is exactly why nobody notices. `0062` exists because that clause
    /// pair was got subtly wrong on two tables that had all three of these.
    ///
    /// One `ALL` policy per table carrying both clauses is the shape the whole
    /// schema uses. A table that deliberately wants a different one — a
    /// narrower `FOR SELECT` policy beside it, as `policy_versions` and
    /// `policy_layers` have since `0062` — keeps its `ALL` policy and adds to
    /// it, so it still passes here.
    #[tokio::test]
    async fn every_table_forces_row_level_security_and_checks_its_writes() {
        let Some(db) = db().await else { return };
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        // `_sqlx_migrations` is the migrator's own bookkeeping: no `tenant_id`,
        // no customer data, and not ours to police.
        let unconfined: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text \
                 || CASE WHEN NOT c.relrowsecurity \
                         THEN ' — no ENABLE ROW LEVEL SECURITY' ELSE '' END \
                 || CASE WHEN c.relrowsecurity AND NOT c.relforcerowsecurity \
                         THEN ' — no FORCE ROW LEVEL SECURITY (the owner bypasses the policy)' \
                         ELSE '' END \
                 || CASE WHEN NOT EXISTS ( \
                        SELECT 1 FROM pg_policies p \
                         WHERE p.schemaname = 'public' AND p.tablename = c.relname \
                           AND p.cmd = 'ALL' \
                           AND p.qual IS NOT NULL AND p.with_check IS NOT NULL) \
                         THEN ' — no ALL policy carrying both USING and WITH CHECK' \
                         ELSE '' END \
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = 'public' AND c.relkind = 'r' \
                AND c.relname <> '_sqlx_migrations' \
                AND (NOT c.relrowsecurity \
                     OR NOT c.relforcerowsecurity \
                     OR NOT EXISTS ( \
                        SELECT 1 FROM pg_policies p \
                         WHERE p.schemaname = 'public' AND p.tablename = c.relname \
                           AND p.cmd = 'ALL' \
                           AND p.qual IS NOT NULL AND p.with_check IS NOT NULL)) \
              ORDER BY 1",
        )
        .fetch_all(&mut *tx)
        .await
        .expect("query pg_class and pg_policies");
        assert!(
            unconfined.is_empty(),
            "these tables do not confine one tenant's rows to that tenant, which is the \
             promise the whole product rests on. Add the missing half in a NEW migration \
             — an applied one cannot be edited: {unconfined:#?}"
        );

        // A view runs with its **owner's** permissions unless it is declared
        // `security_invoker`, and every view here is owned by the role that owns
        // the tables underneath it. So an ordinary view over a confined table is
        // a hole straight through every policy above — the table is forced, the
        // view is queried as `app_role`, and the rows come back anyway. Same
        // class as a missing `force`, one relkind over, and equally invisible to
        // a test that only reads tables.
        let leaky_views: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text \
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = 'public' AND c.relkind IN ('v', 'm') \
                AND coalesce((SELECT option_value \
                                FROM pg_options_to_table(c.reloptions) \
                               WHERE option_name = 'security_invoker'), 'false') <> 'true' \
              ORDER BY 1",
        )
        .fetch_all(&mut *tx)
        .await
        .expect("query pg_class for views");
        assert!(
            leaky_views.is_empty(),
            "these views are not `security_invoker`, so they run as their owner and return \
             every tenant's rows through a table that forces row-level security. Materialised \
             views cannot be `security_invoker` at all and must not be built over tenant \
             data: {leaky_views:?}"
        );

        // Both assertions above are satisfied forever by a database with no
        // tables in it, which is precisely what this test would be asking if it
        // ran before the migrator did.
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = 'public' AND c.relkind = 'r' \
                AND c.relname <> '_sqlx_migrations'",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("count");
        assert!(
            total >= 60,
            "only {total} tables in `public`; this test is asking an unmigrated database"
        );

        tx.rollback().await.expect("rollback");
    }

    /// **A tenant cannot take the platform policy rows away from everybody
    /// else** — the hole `0062` closes.
    ///
    /// `0006_policy.sql` gives `policy_versions` and `policy_layers` a wider
    /// `USING` than `WITH CHECK` so that the rows belonging to no tenant
    /// (`tenant_id IS NULL`) are readable by all of them, and says in a comment
    /// that this makes those rows "read-only to every tenant". It did not.
    /// Postgres checks an UPDATE's `USING` against the **old** row and its
    /// `WITH CHECK` against the **new** one, so rewriting the platform row in
    /// place was refused — but *re-parenting* it satisfied both halves and made
    /// it the tenant's own. Every other tenant then has no ceiling at all,
    /// which is the deployment-wide floor on spend, on outbound contact and on
    /// which models may be called.
    ///
    /// `policy_layers` survived by accident, on the `policy_layers_platform_is_global`
    /// check constraint; `policy_versions` had nothing and this is what it costs
    /// to prove it. Both are asserted, because the constraint is defence in
    /// depth and this test is about the policy.
    #[tokio::test]
    async fn platform_policy_rows_survive_a_tenant_that_wants_them() {
        // A database of its own: the platform rows belong to no tenant, so a
        // test that writes them is not scoped to one and cannot share with a
        // test that is.
        let Some(db) = private_db("platformpolicy").await else {
            return;
        };

        let tenant = TenantId::new_v7(Utc::now());
        let version = Uuid::now_v7();
        let layer = Uuid::now_v7();

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(format!("t-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        // Not active: `policy_versions_one_active_idx` allows one active
        // platform version, and this database's fixtures may already have it.
        sqlx::query(
            "INSERT INTO policy_versions (id, tenant_id, label, active) \
             VALUES ($1, NULL, 'a ceiling somebody installed', false)",
        )
        .bind(version)
        .execute(&mut *admin)
        .await
        .expect("platform version");
        sqlx::query(
            "INSERT INTO policy_layers (id, version_id, tenant_id, layer, max_new_contacts_per_day) \
             VALUES ($1, $2, NULL, 'platform', 5)",
        )
        .bind(layer)
        .bind(version)
        .execute(&mut *admin)
        .await
        .expect("platform layer");
        admin.commit().await.expect("commit");

        // Reading it is the half that must keep working: `policy::load`
        // intersects this ceiling into every tenant's limits on every decision,
        // so a fix that hid it would deny every action in the deployment.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let readable: i64 =
            sqlx::query_scalar("SELECT count(*) FROM policy_versions WHERE id = $1")
                .bind(version)
                .fetch_one(&mut **tx)
                .await
                .expect("read");
        assert_eq!(
            readable, 1,
            "a tenant must still read the platform ceiling; without it `policy::load` \
             answers NoPlatformLayer and every action in the deployment is refused"
        );

        tx.commit().await.expect("commit");

        // And this is the half that must not. Spelled twice as literals rather
        // than once over a `format!`: sqlx only accepts a `&'static str`
        // without an `AssertSqlSafe` audit, and a table name interpolated into
        // a statement is the habit this crate does not want in reach even in a
        // test.
        //
        // A transaction each, because the two tables fail differently.
        // `policy_layers` also carries `policy_layers_platform_is_global`, so
        // it may fail *loudly* on the constraint — which aborts the
        // transaction and would take the other assertion down with it. Either
        // outcome is a pass: what must not happen is a row moving.
        for (table, sql) in [
            (
                "policy_versions",
                "UPDATE policy_versions SET tenant_id = $1 WHERE tenant_id IS NULL",
            ),
            (
                "policy_layers",
                "UPDATE policy_layers SET tenant_id = $1 WHERE tenant_id IS NULL",
            ),
        ] {
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            let stolen = sqlx::query(sql)
                .bind(tenant.as_uuid())
                .execute(&mut **tx)
                .await
                .map_or(0, |done| done.rows_affected());
            assert_eq!(
                stolen, 0,
                "a tenant re-parented {stolen} platform row(s) of `{table}` to itself; \
                 every other tenant in this deployment just lost its policy ceiling"
            );
            let _ = tx.rollback().await;
        }

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let still_platform: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM policy_versions WHERE id = $1 AND tenant_id IS NULL",
        )
        .bind(version)
        .fetch_one(&mut *admin)
        .await
        .expect("read back");
        assert_eq!(
            still_platform, 1,
            "the platform policy version no longer belongs to the platform"
        );
        admin.rollback().await.expect("rollback");
    }

    /// **The migrator this build carries is the directory on disk.**
    ///
    /// # The bug this exists to stop coming back
    ///
    /// `sqlx::migrate!` expands to one `include_str!` per file it finds, and
    /// `include_str!` is the only thing telling cargo to watch anything. A
    /// *new* file is named by no `include_str!`, so cargo re-expands nothing
    /// and [`MIGRATOR`] goes on being yesterday's list. Nothing fails at build
    /// time. What fails is a test three crates away, on a `CHECK` violation or
    /// a missing relation, and the word "migration" appears nowhere in it.
    ///
    /// `crates/store/build.rs` is what makes that impossible, and this is what
    /// makes deleting `build.rs` — four lines whose purpose is invisible —
    /// something you find out about here rather than in an afternoon.
    ///
    /// So: this test cannot fail while `build.rs` is there, and that is the
    /// point rather than a defect. Delete `build.rs`, add a migration, run
    /// `cargo test -p agentos-store`: cargo rebuilds nothing, this binary is
    /// the stale one, and the assertion below is the only thing in the
    /// workspace that says so.
    ///
    /// It costs a directory walk and no database.
    #[test]
    fn the_compiled_migrator_matches_the_directory() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations")
            .canonicalize()
            .expect("the migrations directory is two levels above this crate");

        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .expect("read the migrations directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
            .map(|path| {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .expect("a .sql file has a UTF-8 stem")
                    .to_owned()
            })
            .collect();
        on_disk.sort();

        // The version is the numeric prefix and the description is the rest
        // with underscores turned into spaces — sqlx's own parse, reversed, so
        // the two lists are comparable as the strings a human recognises.
        let mut compiled: Vec<String> = MIGRATOR
            .iter()
            .map(|m| format!("{:04}_{}", m.version, m.description.replace(' ', "_")))
            .collect();
        compiled.sort();

        assert_eq!(
            compiled,
            on_disk,
            "the migrator compiled into this binary is not the {} files in {}. \
             Almost always this means `crates/store/build.rs` is gone: without its \
             `rerun-if-changed`, adding a migration re-expands nothing and the \
             next failure you see will be a constraint violation that never says \
             the word migration.",
            on_disk.len(),
            dir.display()
        );

        // A walk that finds nothing agrees with a migrator that is empty, and
        // the two of them would pass this test forever after somebody moves the
        // directory. A floor, not an equality: adding a migration must not turn
        // a test red for the wrong reason.
        assert!(
            on_disk.len() >= 25,
            "only {} migrations found in {} — this test walked the wrong directory",
            on_disk.len(),
            dir.display()
        );
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
