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
//!
//! # The operating window is a halt, and it is here for that reason
//!
//! Step 8 of the entry journey asks how long the agents run. The answer is one
//! `company_windows` row (`migrations/0054_operating_window.sql`) and *no new
//! refusal*: [`halted`] reports an exhausted window as a [`Halt`], so all four
//! readers above and every one added since refuse a company whose time is up
//! without a line of code being added to any of them.
//!
//! The alternative — a window with its own reader list — is the same list this
//! module already has, kept twice. It desynchronised once already:
//! `initiative::claim_due` shipped without the halt check and had to be given
//! one afterwards. A window that travelled by its own road would have needed
//! the same repair on the same day, found by the same accident.

use chrono::{DateTime, SecondsFormat, Utc};

use crate::db::{StoreError, TenantTx};

/// The two clauses a cross-tenant claim recites to skip a stopped company —
/// **written once, here, and pasted by the compiler.**
///
/// [`halted`] is the reader every per-tenant caller uses, and it knows both
/// stops. The claims cannot call it: they are cross-tenant SQL, driven by
/// `tenants` or by a queue table, with a clock the caller injects rather than
/// the `now()` that function reads. So they spell the predicate out — and a
/// predicate spelled out is a predicate that can be spelled out incompletely.
///
/// **That is not hypothetical, it is the local history.** The halt clause
/// landed in [`crate::outbox::claim_of`] while the window clause landed there
/// only, and for a while [`crate::initiative::claim_due`] still claimed the
/// employees of a company whose month had ended and spent their cadence on a
/// refusal. Two sites, one repair, one of them found by accident. A third
/// reciter — `apps/server`'s provisioning claim, which was buying mailboxes and
/// phone numbers for stopped companies — would have been a third chance to get
/// it wrong.
///
/// So the sites now agree by construction. `concat!` runs at compile time, the
/// callers keep `&'static str` SQL and their measured query plans, and there is
/// exactly one place to edit when a fourth way to stop a company is invented.
///
/// # Contract
///
/// * `$tenant` is the SQL expression naming the tenant column in scope —
///   `"t.id"` where `tenants` drives the query, `"r.tenant_id"` where the queue
///   table does. It is a literal because `concat!` takes literals.
/// * **`$1` must be the caller's `now`, as `timestamptz`.** Every claim in this
///   workspace binds it first; a query that renumbers its parameters has to
///   renumber this too, and the compiler will not say so.
/// * The fragment is a bare boolean with no outer parentheses, so it drops into
///   a `WHERE` directly and needs wrapping inside an `OR`.
///
/// # It defers, it does not refuse
///
/// Every caller must *not select* the row rather than claim and reject it. The
/// callers' own docs carry the argument — burnt attempts, dead letters, a spent
/// cadence — and they all reduce to the same property: a row that was never
/// selected was never written, so lifting the stop makes it due again with no
/// intervention and no replay.
#[macro_export]
macro_rules! not_stopped {
    ($tenant:literal) => {
        concat!(
            "NOT EXISTS (SELECT 1 FROM company_halts h WHERE h.tenant_id = ",
            $tenant,
            ") AND NOT EXISTS (SELECT 1 FROM company_windows w WHERE w.tenant_id = ",
            $tenant,
            " AND w.ends_at <= $1::timestamptz)"
        )
    };
}

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
///
/// # An exhausted operating window answers this too
///
/// Two rows can stop a company and this is the only function that knows it: the
/// operator's switch, and the end of the time somebody bought at step 8 of the
/// entry journey. Both come back as a [`Halt`], so every caller — including the
/// ones written before windows existed and the ones written after this comment
/// — refuses both without asking a second question.
///
/// **The switch wins when both apply.** `ORDER BY precedence LIMIT 1` puts the
/// `company_halts` row first, so a company that is inside its window and also
/// under an emergency stop reports the emergency, with the human's own sentence
/// and the instant the switch was thrown. The other order would quietly
/// overwrite an operator's reason with a schedule's, which is the one
/// substitution nobody could detect afterwards.
///
/// **A window never lifts anything.** It can only add the second row to the
/// union; deleting the first is `DELETE /v1/halt` and nothing else. So no value
/// of `ends_at` — future, past, or absurd — can make this function return `None`
/// while a halt is placed. `a_window_cannot_lift_an_operator_s_halt` is that
/// sentence against a database.
///
/// Still one statement and still no cache, for the reason above: the window is
/// a second primary-key lookup inside a `UNION ALL` the planner answers out of
/// the same shared buffers, not a second round trip.
pub async fn halted(tx: &mut TenantTx<'_>) -> Result<Option<Halt>, StoreError> {
    // `now()` rather than an injected clock, and it is the only time in this
    // module. Adding `now: DateTime<Utc>` here would mean threading one through
    // `model_access::connected`, which has none and whose callers have none —
    // four signatures changed so that a test could lie about the time. A test
    // can move `ends_at` instead, which is the same freedom with none of the
    // reach, and `now()` is the transaction's own timestamp, so a single gate
    // decision cannot see the window close halfway through itself.
    let row: Option<(i32, Option<String>, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT 0 AS precedence, reason, halted_by, halted_at FROM company_halts \
         UNION ALL \
         SELECT 1, NULL::text, set_by, ends_at FROM company_windows \
          WHERE ends_at <= now() \
         ORDER BY precedence \
         LIMIT 1",
    )
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row.map(|(_, reason, halted_by, halted_at)| Halt {
        // A null reason is the window, and the absence is the marker on
        // purpose: `company_windows` has no reason column because no human said
        // a sentence at the instant it ran out. See `window_ended` for the one
        // this renders instead, and 0054 for why there is no `kind` column for
        // code to branch on.
        reason: reason.unwrap_or_else(|| window_ended(halted_at)),
        halted_by,
        halted_at,
    }))
}

/// What a founder reads when the company stopped because the time ran out.
///
/// **This sentence is the entire difference between the two stops**, and it is
/// a string rather than a variant because the only consumer of the difference
/// is a person: it travels as `Denied::Halted(reason)` into the `halt_reason`
/// of an HTTP problem document, as `NoModel::CompanyHalted(reason)` into the
/// initiative loop's log line, and into the audit payload. Every one of those
/// is read, none is matched on.
///
/// So it says the two things an emergency stop does not: that nobody pulled a
/// switch, and when the clock ran out. An operator who reads "stopped" and
/// starts looking for the colleague who stopped it is an operator losing an
/// hour to a schedule working correctly.
fn window_ended(ends_at: DateTime<Utc>) -> String {
    format!(
        "the operating window chosen for this company ended at {} — nobody stopped it, \
         the time it was given ran out. Give it more with PUT /v1/window",
        ends_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

/// When this company's agents stop, if somebody has said.
///
/// `None` is a company with no window, which runs exactly as every company did
/// before 0054 — the inheritance that keeps this feature incapable of widening
/// anything. It is not "runs forever by policy", it is "nobody has answered
/// step 8 yet", and the two read the same from here on purpose: there is no
/// default duration in this workspace to distinguish them with.
pub async fn window(tx: &mut TenantTx<'_>) -> Result<Option<DateTime<Utc>>, StoreError> {
    let ends_at: Option<(DateTime<Utc>,)> = sqlx::query_as("SELECT ends_at FROM company_windows")
        .fetch_optional(&mut ***tx)
        .await?;

    Ok(ends_at.map(|(ends_at,)| ends_at))
}

/// Say how long the agents run. Returns the window this replaced, if any.
///
/// The previous `ends_at` comes back because the caller owes an audit row and
/// that row has to say what moved — "the window is now the 30th" is not a fact
/// anybody can check later, and this table keeps no history of its own. It is
/// read in the same statement, from the snapshot before the write, so the pair
/// cannot be two different transactions' worth of truth.
///
/// **No validation here, deliberately.** Whether an `ends_at` in the past is a
/// mistake or an instruction is a question about what an operator meant, and
/// this module has never had an opinion about meaning — `place` does not judge
/// a reason either. `routes::halt::set_window` refuses the past, where the
/// person who typed it is still on the other end of the connection.
///
/// The caller owes the audit row, for the same reason [`place`] does: there is
/// no `AuditActor` here, and inventing one would let this be attributed to
/// `system`.
pub async fn set_window(
    tx: &mut TenantTx<'_>,
    ends_at: DateTime<Utc>,
    set_by: &str,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, StoreError> {
    let previous: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "WITH before AS (SELECT ends_at FROM company_windows WHERE tenant_id = $1), \
              upsert AS ( \
                  INSERT INTO company_windows (tenant_id, ends_at, set_by, set_at) \
                  VALUES ($1, $2, $3, $4) \
                  ON CONFLICT (tenant_id) DO UPDATE \
                      SET ends_at = excluded.ends_at, \
                          set_by  = excluded.set_by, \
                          set_at  = excluded.set_at \
              ) \
         SELECT ends_at FROM before",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(ends_at)
    .bind(set_by)
    .bind(now)
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(previous.map(|(ends_at,)| ends_at))
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

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use chrono::{Duration, SubsecRound};

    use super::*;
    use crate::db::Db;

    async fn fixture() -> Option<(Db, TenantId, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the operating window needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        let a = seed_tenant(&db).await;
        let b = seed_tenant(&db).await;
        Some((db, a, b))
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'window test')")
            .bind(tenant_id.as_uuid())
            .bind(format!("win-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");
        tenant_id
    }

    /// **The whole feature, in the only function that had to learn anything.**
    ///
    /// A window in the future stops nothing — that is the inheritance every
    /// company had before 0054 and the reason this can never widen. A window in
    /// the past is a [`Halt`], reported by the same call every reader already
    /// makes, so `PolicyGate`, `model_access::connected` and both of the gate's
    /// arms refuse without a line being added to any of them.
    ///
    /// The sentence and the name are asserted, not just the `Some`: they are
    /// what a founder reads at 3am, and "stopped" without "because the month you
    /// bought ended" sends somebody looking for a colleague who did nothing.
    #[tokio::test]
    async fn a_window_stops_the_company_when_it_runs_out_and_not_before() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        // Truncated to the microsecond Postgres stores, so a timestamp that
        // round-trips through `timestamptz` comes back equal to itself.
        let now = Utc::now().trunc_subsecs(6);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            halted(&mut tx).await.expect("read").is_none(),
            "a company with no window is a company that runs, exactly as before 0054"
        );
        assert_eq!(window(&mut tx).await.expect("window"), None);

        let open = now + Duration::days(30);
        assert_eq!(
            set_window(&mut tx, open, "operator:ops-a", now)
                .await
                .expect("set"),
            None,
            "there was no window before this one"
        );
        assert_eq!(window(&mut tx).await.expect("window"), Some(open));
        assert!(
            halted(&mut tx).await.expect("read").is_none(),
            "a month in hand is not a stop"
        );

        // The same company, one instant after its window closed. Nothing else
        // changed; nobody called anything.
        let closed = now - Duration::seconds(1);
        assert_eq!(
            set_window(&mut tx, closed, "operator:ops-a", now)
                .await
                .expect("set"),
            Some(open),
            "the write hands back what it replaced, for the audit row"
        );

        let stop = halted(&mut tx).await.expect("read").expect("stopped");
        assert_eq!(
            stop.halted_at, closed,
            "the stop begins where the window ended, so `refused_since` counts from there"
        );
        assert_eq!(
            stop.halted_by, "operator:ops-a",
            "a window-stop names the human who chose it, a month in advance — 0045 refuses \
             a stop attributed to nobody and this keeps that promise"
        );
        assert!(
            stop.reason.contains("operating window"),
            "a founder must be able to tell this from an emergency: {}",
            stop.reason
        );
        assert!(
            stop.reason.contains("nobody stopped it"),
            "and it must say so in words: {}",
            stop.reason
        );
        tx.rollback().await.expect("rollback");
    }

    /// **A window can only ever close. It cannot open, and it cannot re-open.**
    ///
    /// The hard constraint of the feature, asked in the one order that can
    /// break it: an operator stops the company, and then a window is written
    /// that is wide open for a year. If the union in [`halted`] were ordered the
    /// other way, or if `set_window` touched `company_halts` at all, the
    /// company would come back up — and it would come back up reporting a
    /// schedule's sentence in place of the operator's, which is the one
    /// substitution nobody would notice afterwards.
    #[tokio::test]
    async fn a_window_cannot_lift_an_operator_s_halt() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        // Truncated to the microsecond Postgres stores, so a timestamp that
        // round-trips through `timestamptz` comes back equal to itself.
        let now = Utc::now().trunc_subsecs(6);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        place(&mut tx, "the CFO called", "operator:alice", now)
            .await
            .expect("place")
            .expect("not already halted");

        for ends_at in [now + Duration::days(365), now - Duration::days(1)] {
            set_window(&mut tx, ends_at, "operator:bob", now)
                .await
                .expect("set");
            let stop = halted(&mut tx).await.expect("read").expect("still stopped");
            assert_eq!(
                stop.reason, "the CFO called",
                "the operator's own sentence survives a window at {ends_at}"
            );
            assert_eq!(stop.halted_by, "operator:alice");
            assert_eq!(stop.halted_at, now);
        }

        // And releasing the halt does not release the window that outlived it:
        // the second loop iteration left one that had already run out.
        release(&mut tx)
            .await
            .expect("release")
            .expect("was halted");
        let stop = halted(&mut tx)
            .await
            .expect("read")
            .expect("the window is still out of time");
        assert!(
            stop.reason.contains("operating window"),
            "releasing the switch reveals the window underneath, it does not delete it: {}",
            stop.reason
        );
        tx.rollback().await.expect("rollback");
    }

    /// **A tenant cannot see or set another tenant's window**, and the table is
    /// what says so rather than any `WHERE` clause in this module.
    ///
    /// Two halves, and both are needed. The behavioural half proves the
    /// `using`/`with check` policy: B reads nothing of A's and writing B's own
    /// window moves nothing of A's — a missing `with check` would let a handler
    /// file a row wearing a neighbour's id and stop a business on a date it
    /// never agreed to.
    ///
    /// The catalogue half proves `force`, which the behavioural half **cannot**:
    /// `tenant_tx` runs `SET LOCAL ROLE app_role`, and a non-owning role is
    /// bound by `enable` alone. So a migration that forgot `force` would pass
    /// every cross-tenant test in this file and leave the owning role — the one
    /// the outbox and initiative pollers connect as — walking straight past the
    /// policy. Asked of `pg_class` because that is the only place the difference
    /// is visible.
    #[tokio::test]
    async fn a_window_is_invisible_from_another_tenant_and_its_rls_is_forced() {
        let Some((db, a, b)) = fixture().await else {
            return;
        };
        // Truncated to the microsecond Postgres stores, so a timestamp that
        // round-trips through `timestamptz` comes back equal to itself.
        let now = Utc::now().trunc_subsecs(6);
        let ends_at = now + Duration::days(7);

        let mut tx = db.tenant_tx(a).await.expect("tx a");
        set_window(&mut tx, ends_at, "operator:ops-a", now)
            .await
            .expect("set");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(b).await.expect("tx b");
        assert_eq!(
            window(&mut tx).await.expect("window"),
            None,
            "A's window is not visible from B"
        );
        // B writes its own, already expired, and A must not stop.
        set_window(&mut tx, now - Duration::days(1), "operator:ops-b", now)
            .await
            .expect("set");
        assert!(
            halted(&mut tx).await.expect("read").is_some(),
            "B is out of time"
        );
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(a).await.expect("tx a");
        assert_eq!(window(&mut tx).await.expect("window"), Some(ends_at));
        assert!(
            halted(&mut tx).await.expect("read").is_none(),
            "A still has a week, whatever B did to itself"
        );
        tx.rollback().await.expect("rollback");

        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = 'company_windows'::regclass",
        )
        .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
        .await
        .expect("catalogue");
        assert!(enabled, "company_windows has row-level security enabled");
        assert!(
            forced,
            "…and forced, or the role the pollers connect as reads every tenant's window"
        );
    }
}
