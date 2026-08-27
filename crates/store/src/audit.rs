//! The append-only audit trail.
//!
//! An audit row answers two questions, and the second one is the reason this
//! module exists. *What happened* is easy — every log does that. *Why was it
//! allowed* needs the `decision_id` of the Policy Gate ruling that authorised
//! the effect, written in the same transaction as the effect itself. Without
//! that link a trail tells you a payment went out and leaves you guessing which
//! policy let it.
//!
//! Three deliberate shapes:
//!
//! * **Write typed, read raw.** [`AuditEvent`] is a struct of domain types —
//!   [`ActionKind`], [`Decision`], [`EmployeeId`] — because a row you cannot
//!   delete is a row you cannot correct, so the mistake has to be caught at the
//!   call site. [`AuditRecord`] mirrors the row instead, strings and all: a
//!   reader that refuses to parse a kind written by a newer build would turn a
//!   forward-compatible append into a hard read failure.
//! * **Writes take the caller's [`TenantTx`].** Not a [`crate::db::Db`]. The
//!   audit row must commit or roll back with the thing it describes; a separate
//!   transaction would leave the trail claiming effects that never happened.
//!   `tenant_id` comes from the transaction, so it cannot be passed wrong.
//! * **There is no update and no delete.** Not "there is no function for it" —
//!   `app_role` lacks the privilege and a trigger rejects the statement even
//!   for a superuser (see `0001_core.sql`). The tests below prove both.

use agentos_domain::action::ActionKind;
use agentos_domain::ids::{ConversationId, DecisionId, EmployeeId, TenantId};
use agentos_domain::policy::Decision;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

/// Payload key holding the distributed-trace id.
///
/// `audit_log` has no `trace_id` column and cannot grow one here: sqlx
/// checksums applied migrations, so editing `0001_core.sql` breaks every
/// database that already ran it, and adding `0002` is another unit's file. The
/// id lives in the payload, which is `jsonb` and therefore queryable
/// (`payload ->> 'trace_id'`) and indexable if it ever needs to be.
///
/// ponytail: payload key, not a column. Promote it to a real column with an
/// index in a later migration if trace lookups become a hot path.
const TRACE_ID_KEY: &str = "trace_id";

/// Payload key holding the human-readable summary of a
/// [`Decision::RequireApproval`].
const APPROVAL_SUMMARY_KEY: &str = "approval_summary";

/// The refusal code the Policy Gate writes under `denied` when the whole
/// company is stopped.
///
/// Public and here rather than private in `agentos_app::gate`, because it has
/// two readers in two crates and they must agree on the spelling or the
/// question "what did not happen while we were down" quietly answers zero:
/// `gate` writes it into the payload, and [`crate::halt::refused_since`] counts
/// the rows that carry it. A string constant is the cheapest way to make a
/// rename break the build instead of a report.
pub const COMPANY_HALTED: &str = "company_halted";

// ---------------------------------------------------------------------------
// Who
// ---------------------------------------------------------------------------

/// Who caused the event.
///
/// Stored as one prefixed string rather than a nullable column per principal
/// type, so "the row has an actor" is a `not null` constraint rather than a
/// three-way check nobody writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    /// The employee acted on its own initiative.
    Employee(EmployeeId),
    /// A human did it. The string is whatever the authenticated session
    /// identified them by — free-form because human identity is.
    Operator(String),
    /// A scheduled job, a webhook handler, the outbox poller.
    System,
}

impl AuditActor {
    /// The `actor` column value.
    pub fn label(&self) -> String {
        match self {
            AuditActor::Employee(id) => format!("employee:{}", id.as_uuid()),
            AuditActor::Operator(who) => format!("operator:{who}"),
            AuditActor::System => "system".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// What
// ---------------------------------------------------------------------------

/// What kind of thing happened.
///
/// [`AuditKind::Action`] wraps the gate's own [`ActionKind`] rather than
/// restating it, so the audit vocabulary for actions cannot drift from the
/// vocabulary the Policy Gate rules on. The remaining variants are the events
/// that are not actions: things that happen *to* an employee.
///
/// That sentence is the admission test, and two variants that used to sit here
/// failed it. Both were things the employee *did*, both already had an
/// [`ActionKind`], and neither had a writer:
///
/// * `ApprovalRequested` — `app::gate` writes exactly one row per outcome, and
///   for an escalation that row is `Action(kind)` with `decision =
///   require_approval`, the [`ApprovalReason`](agentos_domain::policy::ApprovalReason)
///   code in `deny_reason_code`, and `approval_id` / `approval_summary` in the
///   payload. A second row would say less (no `decision_id` of its own) and
///   would break the invariant the gate's one `append` call site exists to
///   hold.
/// * `MessageSent` — recorded twice already: the gate's `Action(EmailSend |
///   SmsSend | WhatsappSend | CallPlace | A2aSend)` row carries the ruling that
///   permitted it, and `app::effects` writes [`AuditKind::ProviderCallAttempted`]
///   with the same `decision_id`, the outcome, and the provider's message id.
///
/// [`AuditKind::MessageReceived`] is deliberately *not* symmetric with them: an
/// inbound message is not an action, nothing rules on it, and before
/// `app::inbound::land` wrote this row the trail had no record that a stranger
/// had reached the employee at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// The Policy Gate ruled on an action. Pair it with `decision` and
    /// `decision_id` — an action row with no decision is the exact gap this
    /// module is meant to close.
    Action(ActionKind),
    /// An employee was accepted. Written by `routes::employees::create`, in the
    /// transaction that inserts the row and enqueues its provisioning event.
    EmployeeCreated,
    /// An employee was suspended or terminated. Written by
    /// `routes::employees::set_lifecycle`. The gate refuses a non-active
    /// employee before it reads any policy, so who moved it and when is a
    /// security fact and not an operational one.
    EmployeeLifecycleChanged,
    ResourceStateChanged,
    ApprovalDecided,
    /// A human answered a capability request — see [`crate::capability`].
    /// Written by `routes::approvals::decide_capability`, in the transaction
    /// that writes the `capability_decisions` row.
    ///
    /// Its own kind rather than [`AuditKind::ApprovalDecided`], because the two
    /// are not the same event and the difference is the one somebody will be
    /// checking: an approval decision **released an effect** — an
    /// `Authorized` was minted and a payment moved — while this one released
    /// nothing at all. It is a recorded intention about a policy an operator
    /// still has to install by hand. Sharing a kind would make "how many
    /// approvals did we grant last month" count sentences alongside payments.
    ///
    /// Nor [`AuditKind::PolicyChanged`], for the mirror reason: no policy
    /// changed. That is the whole design of the surface.
    CapabilityDecided,
    /// A message arrived. Written by `app::inbound::land`, in the transaction
    /// that inserts the `messages` row and wakes the agent, so the trail cannot
    /// claim a message the conversation does not have.
    MessageReceived,
    /// An employee signed a payload with its own key. A signature is an
    /// assertion made in the company name, so it leaves a row like any other.
    MessageSigned,
    ProviderCallAttempted,
    SecretAccessed,
    PolicyChanged,
    /// A tenant connected a model — their own API key, or this host's CLI —
    /// and the verification call proved it. Written by
    /// `agentos_app::model_access::connect`, in the transaction that stores the
    /// row, so the trail cannot claim a connection the table does not have.
    ///
    /// Its own kind rather than [`AuditKind::SecretAccessed`], which is a
    /// *read*: this is the one moment in the product where a customer's
    /// credential enters the building, and the question somebody will ask of the
    /// trail six months later — who pointed this company at whose bill, and when
    /// — has no other row that answers it. The payload names the path and the
    /// model that was proven, and never the credential; see that module's
    /// `the_key_reaches_the_vault_and_appears_nowhere_else`.
    ModelConnected,
    /// A human stopped the whole company, or let it run again. Written by
    /// `routes::halt`, in the transaction that inserts or deletes the
    /// `company_halts` row, so the trail cannot claim a halt the table does not
    /// have.
    ///
    /// Its own kind rather than [`AuditKind::PolicyChanged`], and the
    /// distinction is the same one `migrations/0045_company_halt.sql` argues:
    /// a halt is not a permission that changed, it is a lifecycle fact about
    /// the tenant — the twin of [`AuditKind::EmployeeLifecycleChanged`] one
    /// level up. Sharing a kind with policy edits would bury the two rows
    /// anybody actually goes looking for under every spend-cap tweak of the
    /// quarter, and `/v1/autonomy` would count an emergency stop as a
    /// configuration change.
    ///
    /// The payload carries `from` and `to` (`running` / `halted`), the reason,
    /// and — on a release — the reason the original halt was placed for, so one
    /// row answers "what did we come back up from".
    CompanyHaltChanged,
    /// An API key was minted for this tenant. Written by
    /// `agentos_store::api_keys::issue`, in the same admin transaction as the
    /// `api_keys` row.
    ///
    /// **This is the row that makes revocation mean something.** `api_keys`
    /// holds only live keys — revoking is a DELETE, see `0044_api_keys.sql` —
    /// so the question "which keys has this tenant ever had, and who asked for
    /// them" has no other answer. The payload names the key id and the label,
    /// never the secret.
    ApiKeyIssued,
    /// An API key was destroyed. Written by `agentos_store::api_keys::revoke`,
    /// in the same transaction as the DELETE, so the trail cannot claim a
    /// revocation that did not take.
    ApiKeyRevoked,
}

impl AuditKind {
    /// The `action_kind` column value. Low cardinality, stable, greppable.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditKind::Action(kind) => kind.as_str(),
            AuditKind::EmployeeCreated => "employee_created",
            AuditKind::EmployeeLifecycleChanged => "employee_lifecycle_changed",
            AuditKind::ResourceStateChanged => "resource_state_changed",
            AuditKind::ApprovalDecided => "approval_decided",
            AuditKind::CapabilityDecided => "capability_decided",
            AuditKind::MessageReceived => "message_received",
            AuditKind::MessageSigned => "message_signed",
            AuditKind::ProviderCallAttempted => "provider_call_attempted",
            AuditKind::SecretAccessed => "secret_accessed",
            AuditKind::PolicyChanged => "policy_changed",
            AuditKind::ModelConnected => "model_connected",
            AuditKind::CompanyHaltChanged => "company_halt_changed",
            AuditKind::ApiKeyIssued => "api_key_issued",
            AuditKind::ApiKeyRevoked => "api_key_revoked",
        }
    }
}

// ---------------------------------------------------------------------------
// The event
// ---------------------------------------------------------------------------

/// One thing worth remembering.
///
/// Fields are public and most of them are `None`, so build with struct-update
/// syntax rather than a builder nobody asked for:
///
/// ```ignore
/// AuditEvent {
///     employee_id: Some(employee),
///     decision_id: Some(decision_id),
///     decision: Some(decision),
///     ..AuditEvent::new(AuditActor::Employee(employee), AuditKind::Action(kind), now)
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    /// Who caused it.
    pub actor: AuditActor,
    /// What kind of thing it was.
    pub kind: AuditKind,
    /// The employee it concerns, when there is one.
    pub employee_id: Option<EmployeeId>,
    /// The conversation it happened in, when there is one.
    pub conversation_id: Option<ConversationId>,
    /// The Policy Gate ruling that authorised the effect. **This is the field
    /// that makes the trail answer "why".**
    pub decision_id: Option<DecisionId>,
    /// What that ruling was. Split across the `decision` and `deny_reason_code`
    /// columns by [`decision_columns`].
    pub decision: Option<Decision>,
    /// Distributed-trace id, stored in the payload — see [`TRACE_ID_KEY`].
    pub trace_id: Option<String>,
    /// Anything else. Merged into the stored `payload` object; a non-object
    /// value is nested under `data` rather than silently dropped.
    pub payload: Value,
    /// When it happened. Passed in, never read from the clock here.
    pub occurred_at: DateTime<Utc>,
}

impl AuditEvent {
    /// The three fields every event has. Everything else defaults to absent.
    pub fn new(actor: AuditActor, kind: AuditKind, occurred_at: DateTime<Utc>) -> Self {
        Self {
            actor,
            kind,
            employee_id: None,
            conversation_id: None,
            decision_id: None,
            decision: None,
            trace_id: None,
            payload: Value::Object(Map::new()),
            occurred_at,
        }
    }

    /// The `payload` column: the caller's object plus the fields that have no
    /// column of their own.
    fn payload_object(&self) -> Map<String, Value> {
        let mut object = match self.payload.clone() {
            Value::Object(map) => map,
            other => Map::from_iter([("data".to_owned(), other)]),
        };
        if let Some(trace_id) = &self.trace_id {
            object.insert(TRACE_ID_KEY.to_owned(), Value::String(trace_id.clone()));
        }
        if let Some(Decision::RequireApproval { summary, .. }) = &self.decision {
            object.insert(
                APPROVAL_SUMMARY_KEY.to_owned(),
                Value::String(summary.clone()),
            );
        }
        object
    }
}

/// Split a [`Decision`] into the `decision` and `deny_reason_code` columns.
///
/// The second column is named for the deny case but carries the reason code of
/// whichever non-allow answer it was. Leaving it `NULL` for
/// [`Decision::RequireApproval`] would lose *why* a human was asked, and giving
/// approvals their own column means a migration this unit does not own.
fn decision_columns(decision: &Decision) -> (&'static str, Option<&'static str>) {
    match decision {
        Decision::Allow => ("allow", None),
        Decision::Deny { reason } => ("deny", Some(reason.code())),
        Decision::RequireApproval { reason, .. } => ("require_approval", Some(reason.code())),
    }
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// A row as it was stored.
///
/// Deliberately closer to the table than to [`AuditEvent`]: `action_kind`,
/// `decision` and `deny_reason_code` stay strings. A reader that insisted on
/// parsing them into today's enums would fail on a row written by tomorrow's
/// build, and an audit trail that cannot be read is worse than one that is
/// vague.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Row id, UUIDv7.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Employee the event concerns.
    pub employee_id: Option<EmployeeId>,
    /// Conversation it happened in.
    pub conversation_id: Option<ConversationId>,
    /// The Policy Gate ruling that authorised it.
    pub decision_id: Option<DecisionId>,
    /// [`AuditActor::label`] as stored.
    pub actor: String,
    /// [`AuditKind::as_str`] as stored.
    pub action_kind: String,
    /// `allow` / `deny` / `require_approval`, or absent for non-gate events.
    pub decision: Option<String>,
    /// Reason code of a non-allow decision.
    pub deny_reason_code: Option<String>,
    /// Free-form detail, including [`TRACE_ID_KEY`].
    pub payload: Value,
    /// When it happened.
    pub occurred_at: DateTime<Utc>,
}

impl AuditRecord {
    /// The distributed-trace id, if the writer recorded one.
    pub fn trace_id(&self) -> Option<&str> {
        self.payload.get(TRACE_ID_KEY)?.as_str()
    }

    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: TenantId::from_uuid(row.try_get("tenant_id")?),
            employee_id: row
                .try_get::<Option<Uuid>, _>("employee_id")?
                .map(EmployeeId::from_uuid),
            conversation_id: row
                .try_get::<Option<Uuid>, _>("conversation_id")?
                .map(ConversationId::from_uuid),
            decision_id: row
                .try_get::<Option<Uuid>, _>("decision_id")?
                .map(DecisionId::from_uuid),
            actor: row.try_get("actor")?,
            action_kind: row.try_get("action_kind")?,
            decision: row.try_get("decision")?,
            deny_reason_code: row.try_get("deny_reason_code")?,
            payload: row.try_get("payload")?,
            occurred_at: row.try_get("occurred_at")?,
        })
    }
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Append one event, in the caller's transaction. Returns the row id.
///
/// Takes `&mut TenantTx` on purpose: the audit row commits with the effect it
/// describes, or neither happens. `tenant_id` is read off the transaction, so
/// no caller can file an event under the wrong tenant, and RLS's `WITH CHECK`
/// would reject it anyway.
pub async fn append(tx: &mut TenantTx<'_>, event: &AuditEvent) -> Result<Uuid, StoreError> {
    let tenant_id = tx.tenant_id();
    append_admin(&mut *tx, tenant_id, event).await
}

/// [`append`] for a transaction that has no tenant of its own.
///
/// # Why this exists, and why it is not a hole
///
/// One caller: `crate::api_keys`. Issuing and revoking an API key both write
/// `api_keys`, a table `app_role` holds **no** privilege on (`0044_api_keys.sql`
/// argues why), so those two statements can only run in
/// [`Db::admin_tx_bypassing_rls`](crate::db::Db::admin_tx_bypassing_rls) — and
/// the audit row has to commit with them or the trail claims a key that was
/// never minted, which is the one thing [`append`]'s signature exists to
/// prevent.
///
/// The choice was between this and a second `INSERT INTO audit_log` written by
/// hand in another module. A second INSERT is a second place for the payload
/// shape, the `decision_columns` split and the column list to drift, and the
/// drift would be invisible until somebody read the trail. So: one INSERT, two
/// ways to reach a connection, and the tenant passed explicitly because there is
/// nothing to read it off.
///
/// What it costs, stated plainly: a caller of *this* function can file an event
/// under any tenant, because RLS is not there to say no. `append` cannot, and
/// `append` is what every other module in this crate calls. Keep it that way —
/// `grep -rn append_admin` is the list.
pub async fn append_admin(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: TenantId,
    event: &AuditEvent,
) -> Result<Uuid, StoreError> {
    let id = Uuid::now_v7();
    let (decision, deny_reason_code) = match &event.decision {
        Some(decision) => {
            let (decision, code) = decision_columns(decision);
            (Some(decision), code)
        }
        None => (None, None),
    };

    sqlx::query(
        "INSERT INTO audit_log \
         (id, tenant_id, employee_id, conversation_id, decision_id, actor, action_kind, \
          decision, deny_reason_code, payload, occurred_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(id)
    .bind(tenant_id.as_uuid())
    .bind(event.employee_id.map(|e| e.as_uuid()))
    .bind(event.conversation_id.map(|c| c.as_uuid()))
    .bind(event.decision_id.map(|d| d.as_uuid()))
    .bind(event.actor.label())
    .bind(event.kind.as_str())
    .bind(decision)
    .bind(deny_reason_code)
    .bind(Value::Object(event.payload_object()))
    .bind(event.occurred_at)
    .execute(&mut **tx)
    .await?;

    Ok(id)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// One employee's trail, oldest first, capped at `limit` rows.
///
/// There is no `tenant_id` parameter and no tenant predicate in the SQL: the
/// policy on `audit_log` supplies it, so an employee id borrowed from another
/// tenant returns nothing rather than someone else's history.
///
/// ponytail: ordered by `(occurred_at, id)`. Two events sharing a millisecond
/// tie-break on the UUIDv7, which is only weakly ordered inside one tick. If
/// strict intra-millisecond ordering ever matters, give `audit_log` a
/// `bigserial` sequence in a later migration and order on that.
pub async fn trail_for_employee(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    limit: i64,
) -> Result<Vec<AuditRecord>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, employee_id, conversation_id, decision_id, actor, action_kind, \
                decision, deny_reason_code, payload, occurred_at \
         FROM audit_log \
         WHERE employee_id = $1 \
         ORDER BY occurred_at, id \
         LIMIT $2",
    )
    .bind(employee_id.as_uuid())
    .bind(limit)
    .fetch_all(&mut ***tx)
    .await?;

    rows.iter()
        .map(|row| AuditRecord::from_row(row).map_err(StoreError::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use agentos_domain::policy::{ApprovalReason, DenyReason};
    use serde_json::json;

    use super::*;
    use crate::db::Db;

    /// Connect and migrate, or `None` when there is no database.
    ///
    /// The whole module is SQL plus one Postgres trigger; mocking it would
    /// prove nothing, so a missing `DATABASE_URL` skips loudly.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; audit tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    const T0: i64 = 1_700_000_000;

    /// `audit_log` has no foreign key to `tenants` — deleting a tenant must not
    /// delete its trail — so these tests need no seeded rows at all. Every one
    /// of them rolls back, which is the only teardown available for a table
    /// nothing may delete from.
    fn ids() -> (TenantId, EmployeeId) {
        (TenantId::new_v7(at(T0)), EmployeeId::new_v7(at(T0)))
    }

    #[tokio::test]
    async fn append_writes_the_decision_that_authorised_the_effect() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = ids();
        let decision_id = DecisionId::new_v7(at(T0));

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let id = append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(employee),
                decision_id: Some(decision_id),
                decision: Some(Decision::Allow),
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_owned()),
                payload: json!({ "to": "ops@example.com" }),
                ..AuditEvent::new(
                    AuditActor::Employee(employee),
                    AuditKind::Action(ActionKind::EmailSend),
                    at(T0 + 1),
                )
            },
        )
        .await
        .expect("append");

        let trail = trail_for_employee(&mut tx, employee, 10)
            .await
            .expect("read trail");
        assert_eq!(trail.len(), 1);

        let row = &trail[0];
        assert_eq!(row.id, id);
        assert_eq!(row.tenant_id, tenant);
        assert_eq!(row.employee_id, Some(employee));
        assert_eq!(row.actor, format!("employee:{}", employee.as_uuid()));
        assert_eq!(row.action_kind, "email_send");
        assert_eq!(row.decision.as_deref(), Some("allow"));
        assert_eq!(row.deny_reason_code, None);
        // The link that makes the trail answer "why was this allowed?".
        assert_eq!(row.decision_id, Some(decision_id));
        assert_eq!(row.trace_id(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(row.payload["to"], "ops@example.com");
        assert_eq!(row.occurred_at, at(T0 + 1));

        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn a_denied_and_an_escalated_decision_keep_their_reason_codes() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = ids();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(employee),
                decision: Some(Decision::Deny {
                    reason: DenyReason::UntrustedInput,
                }),
                ..AuditEvent::new(
                    AuditActor::System,
                    AuditKind::Action(ActionKind::PaymentCreate),
                    at(T0 + 1),
                )
            },
        )
        .await
        .expect("append deny");

        append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(employee),
                decision: Some(Decision::RequireApproval {
                    reason: ApprovalReason::ContractSignature,
                    summary: "sign the Acme MSA".to_owned(),
                }),
                ..AuditEvent::new(
                    AuditActor::Operator("mel@example.com".to_owned()),
                    AuditKind::Action(ActionKind::ContractSign),
                    at(T0 + 2),
                )
            },
        )
        .await
        .expect("append escalation");

        let trail = trail_for_employee(&mut tx, employee, 10)
            .await
            .expect("read trail");

        assert_eq!(trail[0].decision.as_deref(), Some("deny"));
        assert_eq!(
            trail[0].deny_reason_code.as_deref(),
            Some("untrusted_input")
        );
        assert_eq!(trail[0].actor, "system");

        assert_eq!(trail[1].decision.as_deref(), Some("require_approval"));
        assert_eq!(
            trail[1].deny_reason_code.as_deref(),
            Some("contract_signature")
        );
        assert_eq!(trail[1].actor, "operator:mel@example.com");
        // The one-line summary a human reads, kept because the trail is for
        // humans and it has no column.
        assert_eq!(trail[1].payload[APPROVAL_SUMMARY_KEY], "sign the Acme MSA");

        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn the_trail_reads_back_in_insertion_order_and_only_for_that_employee() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = ids();
        let colleague = EmployeeId::new_v7(at(T0));

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let kinds = [
            AuditKind::EmployeeCreated,
            AuditKind::ResourceStateChanged,
            AuditKind::MessageReceived,
            AuditKind::MessageSigned,
            AuditKind::EmployeeLifecycleChanged,
        ];
        for (tick, kind) in kinds.into_iter().enumerate() {
            append(
                &mut tx,
                &AuditEvent {
                    employee_id: Some(employee),
                    ..AuditEvent::new(AuditActor::System, kind, at(T0 + tick as i64))
                },
            )
            .await
            .expect("append");
        }
        // Someone else's row, interleaved after all of them.
        append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(colleague),
                ..AuditEvent::new(AuditActor::System, AuditKind::MessageReceived, at(T0 + 99))
            },
        )
        .await
        .expect("append colleague");

        let trail = trail_for_employee(&mut tx, employee, 100)
            .await
            .expect("read trail");
        let read_back: Vec<&str> = trail.iter().map(|r| r.action_kind.as_str()).collect();
        assert_eq!(
            read_back,
            kinds.iter().map(|k| k.as_str()).collect::<Vec<_>>()
        );

        // The limit truncates from the oldest end, so a trail read never
        // silently starts in the middle.
        let head = trail_for_employee(&mut tx, employee, 2)
            .await
            .expect("read head");
        assert_eq!(head.len(), 2);
        assert_eq!(head[0].action_kind, "employee_created");

        tx.rollback().await.expect("rollback");
    }

    /// Both halves of the append-only guarantee, from the path the application
    /// actually runs on: `app_role` inside a `tenant_tx`.
    #[tokio::test]
    async fn update_and_delete_are_both_refused() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = ids();

        for statement in [
            "UPDATE audit_log SET actor = 'tampered' WHERE employee_id = $1",
            "DELETE FROM audit_log WHERE employee_id = $1",
        ] {
            // A failed statement poisons the transaction, so each attempt gets
            // its own — and each one is rolled back, because nothing on earth
            // can clean up a committed audit row.
            let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
            append(
                &mut tx,
                &AuditEvent {
                    employee_id: Some(employee),
                    ..AuditEvent::new(AuditActor::System, AuditKind::SecretAccessed, at(T0))
                },
            )
            .await
            .expect("append");

            let err = sqlx::query(statement)
                .bind(employee.as_uuid())
                .execute(&mut **tx)
                .await
                .expect_err("audit_log must be append-only");
            // On the SQLSTATE, never on the message. Postgres translates
            // `permission denied` into the server's `lc_messages` locale, so a
            // text match passes under the C locale our container happens to run
            // and fails on a developer's French or German server — a test that
            // asserts the language of the database rather than its behaviour.
            // `42501` is insufficient_privilege; `P0001` is the raise_exception
            // our append-only trigger uses. Neither is ever translated.
            let sqlstate = err
                .as_database_error()
                .and_then(|e| e.code())
                .unwrap_or_default()
                .into_owned();
            assert!(
                sqlstate == "42501" || sqlstate == "P0001",
                "expected `{statement}` to be refused with 42501 or P0001, \
                 got SQLSTATE {sqlstate}: {err}"
            );

            tx.rollback().await.expect("rollback");
        }
    }

    /// Committing is unavoidable here: an uncommitted row is invisible to every
    /// other transaction anyway, so testing isolation without a commit would
    /// pass for the wrong reason. The row is left behind on purpose — it is
    /// filed under a fresh random tenant that nothing else will ever query, and
    /// there is no DELETE to clean it up with.
    #[tokio::test]
    async fn a_row_is_invisible_outside_its_own_tenant() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = ids();
        let (other_tenant, _) = ids();

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let id = append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(employee),
                ..AuditEvent::new(AuditActor::System, AuditKind::PolicyChanged, at(T0))
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");

        // The neighbouring tenant asks for the row by the employee id it would
        // need to know, and by primary key. Neither query has a tenant
        // predicate; both answers come from the policy.
        let mut tx = db.tenant_tx(other_tenant).await.expect("tenant tx");
        assert!(
            trail_for_employee(&mut tx, employee, 10)
                .await
                .expect("read trail")
                .is_empty()
        );
        let by_id: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE id = $1")
            .bind(id)
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(by_id, 0, "another tenant must not see this row");
        tx.rollback().await.expect("rollback");

        // ... and the owning tenant still does.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let mine = trail_for_employee(&mut tx, employee, 10)
            .await
            .expect("read trail");
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, id);
        tx.rollback().await.expect("rollback");
    }

    #[test]
    fn a_non_object_payload_is_nested_rather_than_dropped() {
        let event = AuditEvent {
            payload: json!("just a string"),
            trace_id: Some("abc".to_owned()),
            ..AuditEvent::new(AuditActor::System, AuditKind::ApprovalDecided, at(T0))
        };
        let object = event.payload_object();

        assert_eq!(object["data"], "just a string");
        assert_eq!(object[TRACE_ID_KEY], "abc");
    }
}
