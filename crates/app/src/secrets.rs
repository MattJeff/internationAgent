//! Resolving a [`SecretRef`] into a [`Secret`], with the two things that make
//! it safe: an ownership check that runs *before* the store is touched, and an
//! audit row for every read.
//!
//! # Why the prefix check is the whole module
//!
//! A `SecretRef` is untrusted input. It arrives as a string in tool arguments,
//! in a document, in model output — anywhere text arrives — and the model can
//! emit any string it likes. [`SecretRef::parse`] already makes path traversal
//! unrepresentable, but it cannot know *who is asking*: a perfectly well-formed
//! `secret://tenant/B/employee/…/stripe-key` is a valid ref, and handing it to
//! the store would read tenant B's credential on tenant A's say-so. One token
//! of model output, one cross-tenant compromise.
//!
//! So [`SecretResolver::resolve`] compares the ref's tenant and employee
//! against the acting [`Principal`] and refuses before any I/O. It does not
//! rely on the store to notice — the local envelope store *does* bind its
//! ciphertexts to the ref's tenant, but a future KMS-less or cache-backed store
//! might not, and "the layer below happens to also check" is not a boundary.
//!
//! # Reading a credential is a security event
//!
//! Every granted read appends one `secret_accessed` audit row, and so does
//! every refusal, because a refused cross-tenant read is the single most
//! interesting line in the trail. The row carries who asked, which ref, when,
//! and the verdict — never the value. The audit row is committed *before* the
//! [`Secret`] is returned, so there is no path on which a caller holds a
//! credential that the trail does not know about.
//!
//! # Holding one for as short as possible
//!
//! [`Secret`] zeroizes on drop, which only helps if it is dropped. Prefer
//! [`SecretResolver::with_secret`], which borrows the value to a closure and
//! drops it at the end of the call, over [`SecretResolver::resolve`], which
//! hands you something you then have to be careful with.

use std::fmt;
use std::sync::Arc;

use agentos_domain::ids::{DecisionId, SecretRef};
use agentos_domain::policy::{Decision, DenyReason};
use agentos_providers::secrets::SecretStore;
use agentos_providers::{ProviderError, Secret};
use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use crate::gate::Principal;

/// Audit payload key holding the ref that was asked for. A ref is public
/// metadata — two UUIDs and a name — so it is safe in the trail, and it is the
/// only thing that makes a refused read investigable.
const SECRET_REF_KEY: &str = "secret_ref";

/// Audit payload key distinguishing *which* half of the prefix did not match.
const DENIED_KEY: &str = "denied";

/// The store's code for "no such secret".
const NOT_FOUND: &str = "secret_not_found";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Which part of the ref did not belong to the caller.
///
/// Both are refusals; they are separated because they mean different things to
/// whoever is paged. [`Mismatch::Tenant`] is someone reaching across a customer
/// boundary — an incident. [`Mismatch::Employee`] is inside one tenant, which
/// is usually our own bug wiring the wrong ref into the wrong employee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// The ref names another tenant.
    Tenant,
    /// The right tenant, another employee.
    Employee,
}

impl Mismatch {
    /// Stable, low-cardinality metric label.
    pub const fn code(self) -> &'static str {
        match self {
            Mismatch::Tenant => "cross_tenant_secret",
            Mismatch::Employee => "cross_employee_secret",
        }
    }
}

/// Why a ref did not produce a secret.
///
/// Codes, not messages: these end up on dashboards, and a reworded string is a
/// panel that quietly stops counting. Nothing here can carry plaintext —
/// [`ProviderError`] is itself only codes.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// **The interesting one.** The ref does not belong to the acting
    /// principal. Refused before the store was touched, and audited.
    #[error("secret ref does not belong to this principal: {}", .0.code())]
    NotYours(Mismatch),

    /// The ref is well formed and owned, and there is nothing at it. Usually
    /// an employee whose provisioning never finished.
    #[error("no such secret")]
    Missing,

    /// The store could not answer. Retryability is on the inner error.
    #[error(transparent)]
    Provider(ProviderError),

    /// The audit row could not be written, so the read did not happen. See
    /// [`SecretResolver::resolve`] for why that is the safe direction.
    #[error(transparent)]
    Unavailable(StoreError),
}

impl SecretError {
    /// Stable, low-cardinality metric label.
    pub fn code(&self) -> &'static str {
        match self {
            SecretError::NotYours(mismatch) => mismatch.code(),
            SecretError::Missing => NOT_FOUND,
            SecretError::Provider(err) => err.code(),
            SecretError::Unavailable(_) => "unavailable",
        }
    }
}

// ---------------------------------------------------------------------------
// The resolver
// ---------------------------------------------------------------------------

/// The only supported way to turn a [`SecretRef`] into a [`Secret`].
///
/// Clone it freely; clones share one pool and one store.
#[derive(Clone)]
pub struct SecretResolver {
    db: Db,
    store: Arc<dyn SecretStore>,
}

// Hand-written: the store is a trait object, and a `Debug` that reached into it
// is a `Debug` that could one day print a cached plaintext.
impl fmt::Debug for SecretResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretResolver")
    }
}

impl SecretResolver {
    /// Wire the resolver to the audit database and the secret store.
    pub fn new(db: Db, store: Arc<dyn SecretStore>) -> Self {
        Self { db, store }
    }

    /// Read the secret at `secret_ref` on behalf of `principal`.
    ///
    /// In order, and the order is the security property:
    ///
    /// 1. **Ownership**, from the ref's own prefix against the principal. No
    ///    I/O has happened yet, so a hostile ref costs a comparison.
    /// 2. **The store.**
    /// 3. **The audit row, committed** — and only then does the value leave
    ///    this function. If the trail cannot be written the read is reported as
    ///    [`SecretError::Unavailable`] and the value is dropped unread by
    ///    anyone: a credential nobody logged is worse than a call that failed.
    ///
    /// ponytail: no lifecycle check. Callers reach this from
    /// [`crate::effects`] holding an `Authorized<_>`, and the Policy Gate
    /// already refused suspended employees before minting it. If a call site
    /// ever resolves a secret outside an authorized effect, that call site is
    /// the bug — not this function.
    pub async fn resolve(
        &self,
        principal: &Principal,
        secret_ref: &SecretRef,
    ) -> Result<Secret, SecretError> {
        let now = Utc::now();

        if let Some(mismatch) = mismatch(principal, secret_ref) {
            self.audit(
                principal,
                secret_ref,
                Decision::Deny {
                    reason: DenyReason::CrossTenantSecret,
                },
                Some(mismatch),
                now,
            )
            .await?;
            return Err(SecretError::NotYours(mismatch));
        }

        let secret = self.store.get(secret_ref).await.map_err(|err| match err {
            ProviderError::Terminal { code } if code == NOT_FOUND => SecretError::Missing,
            other => SecretError::Provider(other),
        })?;

        self.audit(principal, secret_ref, Decision::Allow, None, now)
            .await?;
        Ok(secret)
    }

    /// Resolve, lend the value to `use_it`, and drop it before returning.
    ///
    /// The shape to prefer everywhere: put the plaintext straight into the
    /// header or the client being built and return whatever comes out, so the
    /// [`Secret`] is alive for one expression instead of for the lifetime of
    /// whatever struct someone parked it in.
    ///
    /// ponytail: a synchronous closure. Building a request with a credential is
    /// synchronous; sending it does not need the credential any more. If some
    /// caller genuinely must `.await` while holding the plaintext, give it an
    /// `AsyncFnOnce` overload then — and ask why first.
    pub async fn with_secret<T>(
        &self,
        principal: &Principal,
        secret_ref: &SecretRef,
        use_it: impl FnOnce(&Secret) -> T,
    ) -> Result<T, SecretError> {
        let secret = self.resolve(principal, secret_ref).await?;
        Ok(use_it(&secret))
        // `secret` drops here; `SecretString` zeroizes its buffer.
    }

    /// One row, in its own transaction, committed before the caller is
    /// answered.
    ///
    /// Its own transaction because a secret read has no other database work to
    /// commit with — unlike the gate's ruling, which must land with the
    /// approval or the reservation it made.
    async fn audit(
        &self,
        principal: &Principal,
        secret_ref: &SecretRef,
        decision: Decision,
        mismatch: Option<Mismatch>,
        now: DateTime<Utc>,
    ) -> Result<(), SecretError> {
        let mut tx = self
            .db
            .tenant_tx(principal.tenant_id)
            .await
            .map_err(SecretError::Unavailable)?;

        audit::append(
            &mut tx,
            &secret_event(principal, secret_ref, decision, mismatch, now),
        )
        .await
        .map_err(SecretError::Unavailable)?;

        tx.commit().await.map_err(SecretError::Unavailable)
    }
}

/// Does this ref belong to the principal? `None` when it does.
///
/// The tenant is checked first so the reported code names the outer boundary
/// when both are wrong.
fn mismatch(principal: &Principal, secret_ref: &SecretRef) -> Option<Mismatch> {
    if secret_ref.tenant_id() != principal.tenant_id {
        return Some(Mismatch::Tenant);
    }
    if secret_ref.employee_id() != principal.employee_id {
        return Some(Mismatch::Employee);
    }
    None
}

/// Who, which ref, when, and what was decided. Never the value — there is no
/// field here that could hold one.
fn secret_event(
    principal: &Principal,
    secret_ref: &SecretRef,
    decision: Decision,
    mismatch: Option<Mismatch>,
    now: DateTime<Utc>,
) -> AuditEvent {
    let mut payload = Map::from_iter([(SECRET_REF_KEY.to_owned(), json!(secret_ref.to_string()))]);
    if let Some(mismatch) = mismatch {
        payload.insert(DENIED_KEY.to_owned(), json!(mismatch.code()));
    }

    AuditEvent {
        employee_id: Some(principal.employee_id),
        // The read is its own ruling, so it gets its own id rather than
        // borrowing the gate's. ponytail: when `effects` threads its
        // `Authorized::decision_id` down here, take it as an argument and the
        // trail joins reads to the action that needed them.
        decision_id: Some(DecisionId::new_v7(now)),
        decision: Some(decision),
        payload: Value::Object(payload),
        ..AuditEvent::new(principal.actor.clone(), AuditKind::SecretAccessed, now)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_providers::secrets::MemorySecretStore;
    use agentos_store::audit::AuditRecord;
    use async_trait::async_trait;

    use super::*;

    const PLAINTEXT: &str = "hunter2-correct-horse";

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; secret resolver tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A principal and the ref to its own credential.
    ///
    /// No seeded rows: `audit_log` has no foreign keys, and the store is in
    /// memory.
    fn principal() -> (Principal, SecretRef) {
        let now = Utc::now();
        let (tenant, employee) = (TenantId::new_v7(now), EmployeeId::new_v7(now));
        let secret_ref = SecretRef::new(tenant, employee, "portal-password").expect("valid name");
        (Principal::employee(tenant, employee), secret_ref)
    }

    async fn resolver(db: &Db, seeded: &[&SecretRef]) -> SecretResolver {
        let store = MemorySecretStore::new();
        for r in seeded {
            store.put(r, &Secret::new(PLAINTEXT)).await.expect("put");
        }
        SecretResolver::new(db.clone(), Arc::new(store))
    }

    async fn trail(db: &Db, principal: &Principal) -> Vec<AuditRecord> {
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let rows = audit::trail_for_employee(&mut tx, principal.employee_id, 100)
            .await
            .expect("read trail");
        tx.commit().await.expect("commit read");
        rows
    }

    /// A store that fails the test if it is reached at all.
    struct Tripwire;

    #[async_trait]
    impl SecretStore for Tripwire {
        async fn put(&self, _: &SecretRef, _: &Secret) -> Result<(), ProviderError> {
            unreachable!("the resolver never writes")
        }

        async fn get(&self, secret_ref: &SecretRef) -> Result<Secret, ProviderError> {
            panic!("the resolver reached the store for a ref it must have refused: {secret_ref}")
        }

        async fn delete_prefix(
            &self,
            _: TenantId,
            _: Option<EmployeeId>,
        ) -> Result<usize, ProviderError> {
            unreachable!("the resolver never deletes")
        }
    }

    // -- the tests ---------------------------------------------------------

    #[test]
    fn the_prefix_check_is_pure_and_answers_before_any_io() {
        let (mine, my_ref) = principal();
        let (theirs, their_ref) = principal();

        assert_eq!(mismatch(&mine, &my_ref), None);
        assert_eq!(mismatch(&mine, &their_ref), Some(Mismatch::Tenant));

        // Same tenant, the employee next door.
        let sibling =
            SecretRef::new(mine.tenant_id, theirs.employee_id, "portal-password").expect("valid");
        assert_eq!(mismatch(&mine, &sibling), Some(Mismatch::Employee));
    }

    #[tokio::test]
    async fn a_ref_from_another_tenant_is_refused_before_the_store_and_audited() {
        let Some(db) = db().await else { return };
        let (mine, _) = principal();
        let (_, their_ref) = principal();

        // The store panics if it is consulted, so reaching it fails the test
        // rather than quietly returning someone else's password.
        let resolver = SecretResolver::new(db.clone(), Arc::new(Tripwire));

        let err = resolver
            .resolve(&mine, &their_ref)
            .await
            .expect_err("tenant A may not read tenant B's secret");
        assert!(matches!(err, SecretError::NotYours(Mismatch::Tenant)));
        assert_eq!(err.code(), "cross_tenant_secret");

        // ...and the attempt is on the record.
        let rows = trail(&db, &mine).await;
        assert_eq!(rows.len(), 1, "a refused read is still a security event");
        assert_eq!(rows[0].action_kind, AuditKind::SecretAccessed.as_str());
        assert_eq!(rows[0].decision.as_deref(), Some("deny"));
        assert_eq!(
            rows[0].deny_reason_code.as_deref(),
            Some(DenyReason::CrossTenantSecret.code())
        );
        assert_eq!(rows[0].payload[DENIED_KEY], json!("cross_tenant_secret"));
        assert_eq!(
            rows[0].payload[SECRET_REF_KEY],
            json!(their_ref.to_string())
        );
        assert_eq!(rows[0].actor, mine.actor.label());
    }

    #[tokio::test]
    async fn a_sibling_employees_secret_is_refused_too() {
        let Some(db) = db().await else { return };
        let (mine, _) = principal();
        let sibling = SecretRef::new(
            mine.tenant_id,
            EmployeeId::new_v7(Utc::now()),
            "portal-password",
        )
        .expect("valid");

        let err = SecretResolver::new(db.clone(), Arc::new(Tripwire))
            .resolve(&mine, &sibling)
            .await
            .expect_err("one employee may not read another's credential");
        assert!(matches!(err, SecretError::NotYours(Mismatch::Employee)));
        assert_eq!(trail(&db, &mine).await.len(), 1);
    }

    #[tokio::test]
    async fn every_successful_read_writes_exactly_one_audit_row() {
        let Some(db) = db().await else { return };
        let (mine, my_ref) = principal();
        let resolver = resolver(&db, &[&my_ref]).await;

        let secret = resolver.resolve(&mine, &my_ref).await.expect("my own key");
        assert_eq!(secret.expose_for_transport(), PLAINTEXT);

        let rows = trail(&db, &mine).await;
        assert_eq!(rows.len(), 1, "one read, one row");
        assert_eq!(rows[0].action_kind, AuditKind::SecretAccessed.as_str());
        assert_eq!(rows[0].decision.as_deref(), Some("allow"));
        assert_eq!(rows[0].deny_reason_code, None);
        assert_eq!(rows[0].payload[SECRET_REF_KEY], json!(my_ref.to_string()));
        assert!(rows[0].decision_id.is_some(), "the read is a ruling");

        // Reading the same secret again is a second event, not a cached
        // non-event: the trail counts reads, not distinct secrets.
        resolver.resolve(&mine, &my_ref).await.expect("again");
        assert_eq!(trail(&db, &mine).await.len(), 2);

        // The whole trail, rendered: no plaintext anywhere in it.
        let rendered = format!("{:?}", trail(&db, &mine).await);
        assert!(!rendered.contains(PLAINTEXT), "{rendered}");
    }

    #[tokio::test]
    async fn nothing_that_can_be_printed_contains_the_plaintext() {
        let Some(db) = db().await else { return };
        let (mine, my_ref) = principal();
        let resolver = resolver(&db, &[&my_ref]).await;

        let secret = resolver.resolve(&mine, &my_ref).await.expect("my own key");

        let rendered = format!("{secret:?} {resolver:?}");
        assert!(!rendered.contains(PLAINTEXT), "{rendered}");
        assert!(rendered.contains(Secret::REDACTED), "{rendered}");

        // The one exit is named to be uncomfortable, and it is the only one.
        assert_eq!(secret.expose_for_transport(), PLAINTEXT);
    }

    #[tokio::test]
    async fn a_missing_secret_is_distinguishable_and_not_audited_as_a_read() {
        let Some(db) = db().await else { return };
        let (mine, my_ref) = principal();

        let err = resolver(&db, &[])
            .await
            .resolve(&mine, &my_ref)
            .await
            .expect_err("nothing was ever stored there");
        assert!(matches!(err, SecretError::Missing));

        // ponytail: a miss reveals nothing and is not a read, so it writes no
        // row. Audit it the day someone wants to alert on scanning.
        assert!(trail(&db, &mine).await.is_empty());
    }

    #[tokio::test]
    async fn with_secret_returns_the_closures_value_and_keeps_the_check() {
        let Some(db) = db().await else { return };
        let (mine, my_ref) = principal();
        let (_, their_ref) = principal();
        let resolver = resolver(&db, &[&my_ref]).await;

        // The intended shape: the plaintext goes into the header being built
        // and is dropped before the future resolves.
        let header = resolver
            .with_secret(&mine, &my_ref, |secret| {
                format!("Bearer {}", secret.expose_for_transport())
            })
            .await
            .expect("my own key");
        assert_eq!(header, format!("Bearer {PLAINTEXT}"));

        // The borrow helper is not a way around the ownership check.
        let err = resolver
            .with_secret(&mine, &their_ref, |_| unreachable!("never runs"))
            .await
            .expect_err("still not yours");
        assert!(matches!(err, SecretError::NotYours(Mismatch::Tenant)));
    }
}
