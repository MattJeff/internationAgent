//! Persisting an [`Employee`] and its eleven-row resource map.
//!
//! Three things this module refuses to do quietly.
//!
//! **Lose an update.** `employees.version` is an optimistic lock. [`update`]
//! carries `WHERE version = $expected` and sets `version = version + 1`; zero
//! rows affected means someone else wrote first, and that is a
//! [`StoreError::Conflict`], never a silent no-op. The caller re-[`load`]s and
//! re-applies.
//!
//! **Hand back a half-built aggregate.** The domain guarantees the resource map
//! is total; storage cannot weaken that. [`load`] insists on exactly
//! [`Step::ALL`] rows and errors loudly if the table holds ten of eleven — a
//! partially-provisioned employee that renders as merely "pending" is how a
//! bought phone number becomes invisible.
//!
//! **Drop an external id.** A [`ProviderBinding`] is a thing we are being
//! billed for. It round-trips through `provider` / `external_id`, and a row
//! with one of the pair set and the other null is treated as corruption rather
//! than as "no binding".
//!
//! Health is *not* read back: it is derived by [`Employee::health`]. The column
//! is written anyway, because operators want to filter on it in SQL, and it is
//! ignored on load so it can never disagree with the map.

use agentos_domain::action::Domain;
use agentos_domain::employee::{
    Employee, Lifecycle, ProviderBinding, ResourceState, ResourceStatus, Step,
};
use agentos_domain::ids::{EmployeeId, Slug};
use chrono::{DateTime, Utc};

use crate::db::{StoreError, TenantTx};

/// An employee as it exists in the database, with the version its next
/// [`update`] must quote.
#[derive(Debug, Clone)]
pub struct StoredEmployee {
    /// The aggregate.
    pub employee: Employee,
    /// The row version this employee was read at.
    pub version: i32,
}

/// One `employee_resources` row, in SELECT order: step, state, provider,
/// external_id, poll_ref, expected_by, updated_at.
type ResourceRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

/// The row said something the domain cannot represent. Not a driver failure and
/// not a missing row, so it gets its own loud spelling on top of
/// [`StoreError::Database`].
fn corrupt(what: impl Into<String>) -> StoreError {
    StoreError::Database(sqlx::Error::Decode(
        format!("corrupt employee aggregate: {}", what.into()).into(),
    ))
}

fn parse_lifecycle(raw: &str) -> Result<Lifecycle, StoreError> {
    // Exhaustive rather than a `FromStr` in the domain, which is not mine to
    // add. Keep the spellings in step with `Lifecycle::as_str`.
    match raw {
        "draft" => Ok(Lifecycle::Draft),
        "active" => Ok(Lifecycle::Active),
        "suspended" => Ok(Lifecycle::Suspended),
        "terminated" => Ok(Lifecycle::Terminated),
        other => Err(corrupt(format!("unknown lifecycle {other:?}"))),
    }
}

fn parse_step(raw: &str) -> Result<Step, StoreError> {
    Step::ALL
        .into_iter()
        .find(|step| step.as_str() == raw)
        .ok_or_else(|| corrupt(format!("unknown step {raw:?}")))
}

fn parse_state(
    step: Step,
    raw: &str,
    poll_ref: Option<String>,
    expected_by: Option<DateTime<Utc>>,
) -> Result<ResourceState, StoreError> {
    match raw {
        "pending" => Ok(ResourceState::Pending),
        "provisioning" => Ok(ResourceState::Provisioning),
        "ready" => Ok(ResourceState::Ready),
        "failed" => Ok(ResourceState::Failed),
        "disabled" => Ok(ResourceState::Disabled),
        "pending_external" => match (poll_ref, expected_by) {
            (Some(poll_ref), Some(expected_by)) => Ok(ResourceState::PendingExternal {
                poll_ref,
                expected_by,
            }),
            // Without these two the step is a wait nobody can poll and nobody
            // can escalate, which is exactly the rot `expected_by` exists to
            // prevent.
            _ => Err(corrupt(format!(
                "{step} is pending_external without poll_ref/expected_by"
            ))),
        },
        other => Err(corrupt(format!("{step} has unknown state {other:?}"))),
    }
}

fn parse_binding(
    step: Step,
    provider: Option<String>,
    external_id: Option<String>,
) -> Result<Option<ProviderBinding>, StoreError> {
    match (provider, external_id) {
        (None, None) => Ok(None),
        (Some(provider), Some(external_id)) => {
            Ok(Some(ProviderBinding::new(provider, external_id)))
        }
        // Half a binding is a resource we pay for and cannot name. Refuse.
        (provider, external_id) => Err(corrupt(format!(
            "{step} has a half binding (provider={provider:?}, external_id={external_id:?})"
        ))),
    }
}

/// The domain's `Domain` lives in `spec`; the table has no column for it.
fn spec_of(employee: &Employee) -> serde_json::Value {
    serde_json::json!({ "domain": employee.domain().as_str() })
}

/// Upsert all eleven resource rows.
///
/// `ON CONFLICT DO UPDATE` touches only the columns this module owns —
/// `lease_owner`, `lease_until`, `attempt_count` and `last_error` belong to the
/// provisioning worker and must survive an aggregate save.
///
/// ponytail: eleven round-trips per save. A single `unnest(...)` statement is
/// the upgrade if employee writes ever show up in a profile; they are a
/// once-per-provisioning-step operation today.
async fn save_resources(tx: &mut TenantTx<'_>, employee: &Employee) -> Result<(), StoreError> {
    let tenant_id = tx.tenant_id().as_uuid();
    let employee_id = employee.id().as_uuid();

    for (step, status) in employee.resources() {
        let (poll_ref, expected_by) = match status.state() {
            ResourceState::PendingExternal {
                poll_ref,
                expected_by,
            } => (Some(poll_ref.clone()), Some(*expected_by)),
            ResourceState::Pending
            | ResourceState::Provisioning
            | ResourceState::Ready
            | ResourceState::Failed
            | ResourceState::Disabled => (None, None),
        };

        sqlx::query(
            "INSERT INTO employee_resources \
             (employee_id, step, tenant_id, state, provider, external_id, poll_ref, \
              expected_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (employee_id, step) DO UPDATE SET \
               state = excluded.state, \
               provider = excluded.provider, \
               external_id = excluded.external_id, \
               poll_ref = excluded.poll_ref, \
               expected_by = excluded.expected_by, \
               updated_at = excluded.updated_at",
        )
        .bind(employee_id)
        .bind(step.as_str())
        .bind(tenant_id)
        .bind(status.state().as_str())
        .bind(status.binding().map(ProviderBinding::provider))
        .bind(status.binding().map(ProviderBinding::external_id))
        .bind(poll_ref)
        .bind(expected_by)
        .bind(status.updated_at())
        .execute(&mut ***tx)
        .await?;
    }
    Ok(())
}

/// Write a new employee and its resource map. Returns the initial version.
pub async fn insert(tx: &mut TenantTx<'_>, employee: &Employee) -> Result<i32, StoreError> {
    let version: i32 = sqlx::query_scalar(
        "INSERT INTO employees \
         (id, tenant_id, slug, display_name, lifecycle, health, version, spec, \
          created_at, updated_at) \
         VALUES ($1, $2, $3, $3, $4, $5, 0, $6, $7, $8) \
         RETURNING version",
    )
    .bind(employee.id().as_uuid())
    .bind(employee.tenant_id().as_uuid())
    .bind(employee.slug().as_str())
    .bind(employee.lifecycle().as_str())
    .bind(employee.health().as_str())
    .bind(spec_of(employee))
    .bind(employee.created_at())
    .bind(employee.updated_at())
    .fetch_one(&mut ***tx)
    .await?;

    save_resources(tx, employee).await?;
    Ok(version)
}

/// Read an employee and every one of its resources.
///
/// Errors with [`StoreError::NotFound`] when the row does not exist or belongs
/// to another tenant (RLS makes those indistinguishable, deliberately), and
/// with a decode error when the aggregate is incomplete or unparseable.
pub async fn load(tx: &mut TenantTx<'_>, id: EmployeeId) -> Result<StoredEmployee, StoreError> {
    let (slug, lifecycle, version, spec, created_at, updated_at): (
        String,
        String,
        i32,
        serde_json::Value,
        DateTime<Utc>,
        DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT slug, lifecycle, version, spec, created_at, updated_at \
         FROM employees WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;

    let slug = Slug::parse(&slug).map_err(|e| corrupt(format!("slug: {e}")))?;
    let domain = spec
        .get("domain")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| corrupt("spec has no domain"))?;
    let domain = Domain::parse(domain).map_err(|e| corrupt(format!("domain: {e}")))?;
    let lifecycle = parse_lifecycle(&lifecycle)?;

    let rows: Vec<ResourceRow> = sqlx::query_as(
        "SELECT step, state, provider, external_id, poll_ref, expected_by, updated_at \
         FROM employee_resources WHERE employee_id = $1",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut ***tx)
    .await?;

    // Totality is the aggregate's invariant, so a short read is corruption, not
    // a shrug. `hydrate` would happily fill the gap with `Pending` and hand
    // back an employee that looks merely young instead of broken.
    if rows.len() != Step::ALL.len() {
        return Err(corrupt(format!(
            "{} has {} resource rows, expected {}",
            id.as_uuid(),
            rows.len(),
            Step::ALL.len()
        )));
    }

    let mut resources = Vec::with_capacity(rows.len());
    for (step, state, provider, external_id, poll_ref, expected_by, row_updated_at) in rows {
        let step = parse_step(&step)?;
        let state = parse_state(step, &state, poll_ref, expected_by)?;
        let binding = parse_binding(step, provider, external_id)?;
        resources.push((step, ResourceStatus::new(state, binding, row_updated_at)));
    }

    Ok(StoredEmployee {
        employee: Employee::hydrate(
            id,
            tx.tenant_id(),
            slug,
            domain,
            lifecycle,
            resources,
            created_at,
            updated_at,
        ),
        version,
    })
}

/// Write an employee back, refusing to clobber a concurrent write.
///
/// Returns the new version. A zero-row update is
/// `StoreError::Conflict("employees.version")` and nothing has been written —
/// the resource rows are only touched after the version check passes.
pub async fn update(
    tx: &mut TenantTx<'_>,
    employee: &Employee,
    expected_version: i32,
) -> Result<i32, StoreError> {
    let next: Option<i32> = sqlx::query_scalar(
        "UPDATE employees SET \
           lifecycle = $2, health = $3, spec = $4, updated_at = $5, version = version + 1 \
         WHERE id = $1 AND version = $6 \
         RETURNING version",
    )
    .bind(employee.id().as_uuid())
    .bind(employee.lifecycle().as_str())
    .bind(employee.health().as_str())
    .bind(spec_of(employee))
    .bind(employee.updated_at())
    .bind(expected_version)
    .fetch_optional(&mut ***tx)
    .await?;

    // Someone else bumped the version, or the row is gone/another tenant's.
    // Postgres reports none of that as an error, so the zero-row case is where
    // the lost update is caught.
    let Some(next) = next else {
        return Err(StoreError::conflict("employees.version"));
    };

    save_resources(tx, employee).await?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use uuid::Uuid;

    use super::*;
    use crate::db::Db;

    /// Real Postgres or nothing: every claim here is about SQL.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; store tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Cascades to employees and their resource rows, so every test cleans up
    /// after itself and can be re-run.
    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    const T0: i64 = 1_700_000_000;

    fn draft(tenant: TenantId, slug: &str) -> Employee {
        Employee::new(
            EmployeeId::new_v7(at(T0)),
            tenant,
            Slug::parse(slug).unwrap(),
            Domain::parse("agents.example.com").unwrap(),
            at(T0),
        )
    }

    /// An employee with something interesting in every column that matters: a
    /// bound provider id, a pending-external wait, a disabled channel and a
    /// non-draft lifecycle.
    fn furnished(tenant: TenantId, slug: &str) -> Employee {
        let mut e = draft(tenant, slug);
        for step in Step::ALL {
            e.set_resource(step, ResourceState::Provisioning, at(T0 + 1))
                .unwrap();
        }
        for round in 0..Step::ALL.len() as i64 {
            for step in Step::ALL {
                let _ = e.set_resource(step, ResourceState::Ready, at(T0 + 2 + round));
            }
        }
        e.set_lifecycle(Lifecycle::Active, at(T0 + 20)).unwrap();

        e.bind(
            Step::Phone,
            ProviderBinding::new("twilio", format!("PN-{slug}")),
            at(T0 + 21),
        )
        .unwrap();
        e.bind(
            Step::Wallet,
            ProviderBinding::new("stripe", format!("acct-{slug}")),
            at(T0 + 22),
        )
        .unwrap();

        // whatsapp: ready -> provisioning -> pending_external (the legal path).
        e.set_resource(Step::Whatsapp, ResourceState::Provisioning, at(T0 + 23))
            .unwrap();
        e.set_resource(
            Step::Whatsapp,
            ResourceState::PendingExternal {
                poll_ref: "BU-review-42".to_owned(),
                expected_by: at(T0 + 86_400),
            },
            at(T0 + 24),
        )
        .unwrap();
        e.set_resource(Step::Mcp, ResourceState::Disabled, at(T0 + 25))
            .unwrap();
        e
    }

    #[tokio::test]
    async fn round_trip_preserves_every_resource_binding_and_pending_external() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let original = furnished(tenant, "lena");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(insert(&mut tx, &original).await.expect("insert"), 0);
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let stored = load(&mut tx, original.id()).await.expect("load");
        tx.rollback().await.expect("rollback");

        assert_eq!(stored.version, 0);
        // `Employee` is `PartialEq`, so this covers id, tenant, slug, domain,
        // derived address and did, lifecycle, timestamps, and all eleven
        // resource rows with their bindings — not a hand-picked subset.
        assert_eq!(stored.employee, original);

        // Spelled out anyway for the two that cost money if they are wrong.
        let phone = stored.employee.resource(Step::Phone);
        assert_eq!(phone.binding().unwrap().provider(), "twilio");
        assert_eq!(phone.binding().unwrap().external_id(), "PN-lena");
        assert_eq!(
            stored.employee.resource(Step::Whatsapp).state(),
            &ResourceState::PendingExternal {
                poll_ref: "BU-review-42".to_owned(),
                expected_by: at(T0 + 86_400),
            }
        );
        assert_eq!(
            stored.employee.overdue(at(T0 + 86_401)),
            vec![Step::Whatsapp]
        );

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn a_stale_version_conflicts_and_writes_nothing() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let employee = furnished(tenant, "raj");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        insert(&mut tx, &employee).await.expect("insert");
        tx.commit().await.expect("commit");

        // Writer A wins: suspend the employee at version 0.
        let mut a = employee.clone();
        a.set_lifecycle(Lifecycle::Suspended, at(T0 + 100)).unwrap();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(update(&mut tx, &a, 0).await.expect("update"), 1);
        tx.commit().await.expect("commit");

        // Writer B still holds version 0 and wants the phone released.
        let mut b = employee.clone();
        b.release(Step::Phone, at(T0 + 101));
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        match update(&mut tx, &b, 0).await {
            Err(StoreError::Conflict(what)) => assert_eq!(what, "employees.version"),
            other => panic!("expected a version conflict, got {other:?}"),
        }
        // Commit rather than roll back: rolling back would prove nothing about
        // whether the failed update wrote. The commit makes any write real.
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let stored = load(&mut tx, employee.id()).await.expect("load");
        tx.rollback().await.expect("rollback");

        assert_eq!(stored.version, 1);
        assert_eq!(stored.employee.lifecycle(), Lifecycle::Suspended);
        // B's release never happened; the number is still ours and still named.
        assert_eq!(
            stored
                .employee
                .resource(Step::Phone)
                .binding()
                .map(ProviderBinding::external_id),
            Some("PN-raj")
        );

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn an_employee_missing_a_resource_row_fails_to_load() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let employee = furnished(tenant, "kim");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        insert(&mut tx, &employee).await.expect("insert");
        sqlx::query("DELETE FROM employee_resources WHERE employee_id = $1 AND step = 'vault'")
            .bind(employee.id().as_uuid())
            .execute(&mut **tx)
            .await
            .expect("delete one row");

        let err = load(&mut tx, employee.id())
            .await
            .expect_err("a 10-of-11 aggregate must not load");
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt employee aggregate") && msg.contains("expected 11"),
            "expected a loud totality error, got: {msg}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn a_pending_external_row_without_its_poll_ref_is_corruption() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;
        let employee = furnished(tenant, "ines");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        insert(&mut tx, &employee).await.expect("insert");
        sqlx::query(
            "UPDATE employee_resources SET poll_ref = NULL, expected_by = NULL \
             WHERE employee_id = $1 AND step = 'whatsapp'",
        )
        .bind(employee.id().as_uuid())
        .execute(&mut **tx)
        .await
        .expect("blank the poll ref");

        let err = load(&mut tx, employee.id())
            .await
            .expect_err("an unpollable wait must not load");
        assert!(
            err.to_string().contains("pending_external without"),
            "got: {err}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn another_tenant_cannot_load_or_update_the_employee() {
        let Some(db) = db().await else { return };
        let owner = new_tenant(&db).await;
        let stranger = new_tenant(&db).await;
        let employee = furnished(owner, "nils");

        let mut tx = db.tenant_tx(owner).await.expect("tenant tx");
        insert(&mut tx, &employee).await.expect("insert");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(stranger).await.expect("tenant tx");
        assert!(matches!(
            load(&mut tx, employee.id()).await,
            Err(StoreError::NotFound)
        ));
        // Invisible rows cannot be version-bumped either: zero rows, conflict.
        assert!(matches!(
            update(&mut tx, &employee, 0).await,
            Err(StoreError::Conflict(_))
        ));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, owner).await;
        drop_tenant(&db, stranger).await;
    }

    #[tokio::test]
    async fn a_missing_employee_is_not_found() {
        let Some(db) = db().await else { return };
        let tenant = new_tenant(&db).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let missing = EmployeeId::from_uuid(Uuid::now_v7());
        assert!(matches!(
            load(&mut tx, missing).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }
}
