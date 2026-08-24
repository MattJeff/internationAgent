pub mod inbound;
pub mod initiative; // U37
pub mod outbox; // U36
pub mod provisioning; // U35

/// A database of this module's own, created on first use and migrated.
///
/// # Why the loops cannot share the suite's database
///
/// Every other test in this workspace isolates itself by minting a fresh
/// `TenantId` and asserting through `Db::tenant_tx`, where RLS makes the rest of
/// the database invisible. The four loops above have no such seam, because being
/// cross-tenant *is* what they are: `outbox::tick` claims every tenant's events
/// and burns an attempt off each one it cannot handle, `lag_secs` is a maximum
/// over the whole queue, `provisioning::claim` takes a bounded batch of whoever
/// is stalest — so somebody else's eleven pending rows push this test's out of
/// the window — `claim_releases` *writes* to every tenant it can see, and
/// `initiative::claim_due` takes whoever is due anywhere. There is nothing for a
/// `WHERE tenant_id = $1` to hang off: the assertions are about the global
/// queue, and the loops modify rows they were never told about.
///
/// So these tests need a global queue nobody else is writing to, and in Postgres
/// that is a database. It used to be bought instead with `DELETE FROM tenants`
/// and `DELETE FROM outbox_events` — no `WHERE`, under RLS bypass — which
/// deleted the rows of whatever tests were running beside them, and cost two to
/// six failures per parallel `cargo test` run, in a different set each time.
///
/// The initiative loop needs it for one more reason: its fixture installs a
/// **platform policy layer**, which is `tenant_id IS NULL` and therefore one row
/// for the whole database. On a shared database that replaces the layer other
/// modules are mid-assertion on.
///
/// # A fresh handle every call, deliberately
///
/// Caching the [`Db`](agentos_store::db::Db) in a `static` is the obvious
/// optimisation and it does not work: `#[tokio::test]` builds and drops a
/// runtime per test, and a pooled connection belongs to the reactor that opened
/// it. The second test to use a cached pool waits on connections whose runtime
/// is gone and fails with `PoolTimedOut`, nowhere near the cause. Connecting is
/// one round trip and the migrations are a no-op after the first test.
///
/// # Naming
///
/// `<the database in DATABASE_URL>_<suffix>`, which is what makes the cleanup in
/// `scripts/test.sh` work: it drops every database whose name starts with this
/// run's, so these go with it.
#[cfg(test)]
pub(crate) async fn private_db(suffix: &str) -> Option<agentos_store::db::Db> {
    use agentos_store::db::Db;
    use sqlx::Connection as _;

    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("SKIP: DATABASE_URL is unset; the loops need a real Postgres");
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
