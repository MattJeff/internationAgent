//! The company-wide stop: one row, three verbs, and no opinion about what it
//! means.
//!
//! `migrations/0045_company_halt.sql` carries the argument for why a halt is a
//! lifecycle fact rather than a policy layer. This module is the SQL underneath
//! it and nothing else — it does not decide what a halt refuses, because the
//! two readers refuse different things and both of them live upstairs:
//!
//! * `agentos_app::gate::PolicyGate` reads it before any policy, so no
//!   [`Authorized`](../../agentos_app/gate/struct.Authorized.html) token is
//!   minted while a company is stopped, and therefore no effect reaches the
//!   world;
//! * `agentos_app::model_access::connected` reads it before a turn is reserved,
//!   so no new turn starts and no model token is billed to a customer who asked
//!   us to stop.
//!
//! # Why the tenant is never a parameter
//!
//! Every function here takes a [`TenantTx`] and nothing else. The tenant is the
//! one `SET LOCAL app.tenant_id` on that transaction, which is what row-level
//! security honours, and adding a `tenant_id: TenantId` argument would create a
//! second answer to a question that already has one — the exact shape of a
//! cross-tenant bug, in the one table where a cross-tenant bug means halting a
//! business that never called us. `crates/store/src/policy.rs::load` deleted a
//! parameter for the same reason.

use chrono::{DateTime, Utc};

use crate::db::{StoreError, TenantTx};

/// A company that has been stopped, as the row records it.
///
/// No `tenant_id` field: the only way to hold one of these is to have read it
/// through a transaction that was already pinned to a tenant, so a copy of the
/// id here would be a value a caller could carry somewhere it does not belong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Halt {
    /// What the human said when they threw the switch.
    pub reason: String,
    /// The API key label that threw it. `operator:<this>` is the matching
    /// `audit_log.actor`.
    pub halted_by: String,
    /// When. The left edge of "what did not happen".
    pub halted_at: DateTime<Utc>,
}

/// Is this company stopped, and if so by whom and why.
///
/// **Read on every gate decision and before every turn, so it is one row by
/// primary key and nothing else.** No cache, deliberately and for the same
/// reason `policy::load` has none: a halt whose effect arrives one cache
/// lifetime late is a halt whose promise cannot be stated in seconds, and the
/// number a customer is told on the phone is the whole product here. Postgres
/// answers a primary-key lookup on a table with one row per company out of
/// shared buffers; the transaction it runs in was being opened anyway.
///
/// `None` means running. There is no third state — see the migration on why
/// there is no `status` column to be half-set.
pub async fn halted(tx: &mut TenantTx<'_>) -> Result<Option<Halt>, StoreError> {
    let row: Option<(String, String, DateTime<Utc>)> =
        sqlx::query_as("SELECT reason, halted_by, halted_at FROM company_halts")
            .fetch_optional(&mut ***tx)
            .await?;

    Ok(row.map(|(reason, halted_by, halted_at)| Halt {
        reason,
        halted_by,
        halted_at,
    }))
}

/// Stop the company. `None` when it was already stopped.
///
/// `ON CONFLICT DO NOTHING`, so a second call changes nothing and says so
/// rather than overwriting the first reason — which matters because the reason
/// is the evidence. Two operators reaching for the switch at once produce one
/// halt and one honest "it was already stopped", never a row whose stated cause
/// is the second caller's guess about the first caller's emergency.
///
/// The caller owes the audit row. It is not written here because this module
/// has no `AuditActor` and inventing one would let a writer be attributed to
/// `system` — and a halt attributed to the system is a halt with no human's
/// name on it, which is the one thing this feature must never produce.
pub async fn place(
    tx: &mut TenantTx<'_>,
    reason: &str,
    halted_by: &str,
    now: DateTime<Utc>,
) -> Result<Option<Halt>, StoreError> {
    let row: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "INSERT INTO company_halts (tenant_id, reason, halted_by, halted_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id) DO NOTHING \
         RETURNING reason, halted_by, halted_at",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(reason)
    .bind(halted_by)
    .bind(now)
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row.map(|(reason, halted_by, halted_at)| Halt {
        reason,
        halted_by,
        halted_at,
    }))
}

/// Let the company run again. `None` when it was not stopped.
///
/// `DELETE ... RETURNING`, so the caller gets the halt it just lifted and can
/// put the original reason and the original operator into the release's audit
/// row. Without that the trail would record a release with no reference to what
/// it released, and "when did we come back up, and from what" would need two
/// queries and a guess about ordering.
///
/// **This widens nothing.** It removes a refusal that sat above the policy and
/// touches no `policy_layers` row, so the effective policy after a release is
/// byte-for-byte the one from before the halt — there is no saved copy to
/// restore wrong. That property is the reason the halt is a separate table at
/// all, and `crates/app/src/gate.rs` asserts it.
pub async fn release(tx: &mut TenantTx<'_>) -> Result<Option<Halt>, StoreError> {
    let row: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "DELETE FROM company_halts WHERE tenant_id = $1 \
         RETURNING reason, halted_by, halted_at",
    )
    .bind(tx.tenant_id().as_uuid())
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row.map(|(reason, halted_by, halted_at)| Halt {
        reason,
        halted_by,
        halted_at,
    }))
}

/// How many decisions this company has had refused since `since`, because it is
/// stopped.
///
/// **The list a customer asks for.** "What did not happen while we were down"
/// is the question after the incident, and the gate already answers it: every
/// refusal it writes for a halt carries `payload->>'denied' = 'company_halted'`
/// in `audit_log`, with the action kind, the counterparty and the employee on
/// the same row. This is the count of them; the rows themselves are already
/// queryable and this module does not need to invent a second reader for them.
///
/// ponytail: a count, not a page of rows. The number is what goes in a
/// `GET /v1/halt` response and what somebody reads down a phone line. Add the
/// paged listing when an operator asks to *see* them — it is a `SELECT` against
/// an index that already exists, and it does not belong in the response that is
/// also the switch's own state.
pub async fn refused_since(tx: &mut TenantTx<'_>, since: DateTime<Utc>) -> Result<i64, StoreError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log \
          WHERE occurred_at >= $1 AND payload->>'denied' = $2",
    )
    .bind(since)
    .bind(crate::audit::COMPANY_HALTED)
    .fetch_one(&mut ***tx)
    .await?;

    Ok(count)
}
