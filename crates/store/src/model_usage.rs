//! The token ledger: what the models cost, per employee, per UTC day.
//!
//! Every other cost in this workspace is written down. Payments go through
//! [`crate::spend`], turns through [`crate::turns`], and every effect leaves an
//! audit row. Model tokens — the single largest operating cost of this system —
//! went to a process-local counter that drops the tenant and to two `tracing`
//! lines, and nowhere else. `migrations/0024_model_usage.sql` is the table and
//! the argument; this module is the only thing that writes it.
//!
//! # Where the write happens is the whole design
//!
//! [`record`] is **additive**. It has to be: two model calls with identical
//! usage on the same day are two real calls and must read as two, so there is
//! no idempotency key that could make a second write a no-op without also
//! erasing a real one.
//!
//! Idempotence therefore comes from *where* it is called, not from a key. In
//! `Agent::on_turn` it runs inside the outbox handler's own transaction — the
//! same one that records the reply — so the row exists exactly when the turn
//! committed. There is no state where the reply landed and the tokens did not,
//! and none where one call was counted twice: a redelivered outbox event
//! re-runs the model, and the second row describes a second real call that was
//! really paid for.
//!
//! **The risk that buys, stated plainly: a usage write that fails aborts a turn
//! that would otherwise have committed.** That is deliberate. The alternative —
//! a best-effort write in a transaction of its own, logged and swallowed the way
//! `loops::initiative::record` swallows a lost outcome — loses rows silently,
//! and a silently lost row reads as *lower* consumption. That is the direction
//! that flatters a number this project intends to quote in public, and a
//! bookkeeping failure that quietly improves the figure is the worst of the
//! available failures. A loud one that costs a retried turn is the better trade.
//!
//! # Unknown is not zero
//!
//! `providers::llm::WireUsage` is `#[serde(default)]`, so a response with no
//! usage block parses into three zeroes. The `claude` CLI backend is lossy by
//! construction and says so in its own first paragraph. Neither is a call that
//! cost nothing, and a ledger that records them as zero is a ledger that
//! averages a real bill down towards free.
//!
//! So [`Consumed`] carries `calls_unmetered` beside `calls`, and
//! [`Consumed::reported`] is the single place the judgement is made: **a call
//! that happened and reported no tokens at all is recorded as unmetered, not as
//! free.** Both write sites go through it, so they cannot disagree.
//!
//! ponytail: the ceiling of that rule is that it reads a *batch* of calls, not
//! one. `Finished::usage` is summed across a run, so a run where two calls
//! reported and one did not looks fully metered here and its tokens are a floor
//! by the missing call. In practice every call in one run goes to one backend,
//! which either reports usage or does not, so the mixed case needs a provider
//! that answers inconsistently within a single conversation. The upgrade path,
//! if that ever happens, is a per-call counter on `agentos_app::turn::Spent`
//! incremented where `spent.usage.add(response.usage)` already is — not a
//! change here, which would still only see the sum.
//!
//! # Said is not did
//!
//! The same move as "unknown is not zero", one level up, and it is here for the
//! same reason: it is a judgement about what an empty number means, so it lives
//! in one place with both write sites going through it.
//!
//! A live run produced the case. One support seat wrote 12,682 tokens describing
//! five tickets handled and five emails sent, having called nothing —
//! `tool_calls = 0` was the only thing that distinguished it, and it went to a
//! log line. That is the one failure in this system that looks like success: a
//! denial writes an audit row with a reason, a malformed call is counted in
//! `Finished::malformed_calls`, a provider error is classified and billed, and
//! an employee that did nothing and said it did everything leaves a beautiful
//! transcript and no trace.
//!
//! [`Consumed::unbacked`] is the fix and it is deliberately the *weakest* of the
//! four shapes that were on the table:
//!
//! * **Record the discrepancy** — this. Two columns, no behaviour change, and
//!   the manager's view can rank on them. It cannot stop anything.
//! * **Refuse the note.** A turn with no tool call does not get to write
//!   anything an operator reads as work. Rejected because on the path this
//!   matters — `loops::initiative` — there is no note to refuse: the closing
//!   text is already logged and stored nowhere. On the path where there *is*
//!   one — `Agent::on_turn` — refusing it would delete the reply to a customer's
//!   email, which is the healthy case, not the sick one.
//! * **Make the employee say which.** Require a turn with nothing to do to end
//!   by saying so through the internal channel, so "did nothing and said
//!   nothing" and "did nothing and said so" become different rows. Rejected on
//!   the ground that it *already is* one: a turn that reports through
//!   `message_colleague` has made a tool call and is therefore backed. Adding a
//!   rule would only mean a model that narrates a day it did not have also
//!   declines to file the note, and we would have written a prompt instruction
//!   and called it an invariant.
//! * **Score it in the eval.** `eval::dryrun`'s `verdict` already gates on "the
//!   employees called tools" and should. It tells you about the fleet on the day
//!   somebody ran it; this tells you about Tuesday, per seat, without anybody
//!   running anything.
//!
//! **What it does not do, said plainly: it does not make a model honest, and
//! nothing can.** A model writes what it writes. This makes the record carry
//! both halves — what was said, and whether anything was done — so that a human
//! comparing them sees the gap. It is a fact for a person to read, not a verdict:
//! see [`Consumed::unbacked_chars`] for why there are two columns and not a
//! boolean, and `migrations/0034_unbacked_turns.sql` for why only the
//! self-started turn writes them.
//!
//! # A turn that did not finish is recorded — this section used to say it was
//! not
//!
//! It said: "`Turn::run` returns `TurnError` ... and drops `Spent` with it, so
//! the model calls that run already made are invisible here", called it the
//! largest remaining hole, and said closing it meant carrying `Usage` out of
//! `TurnError`. **That was fixed and this paragraph was not.** `Turn::run`
//! returns `Result<Finished, app::turn::Failed>`, and `Failed` carries `usage`
//! and `turns` beside the error — a wrapper rather than a field on the enum,
//! which is why the public `TurnError` never had to change. Both callers write
//! it: `Agent::on_turn` and `loops::initiative::take_turn` each open a
//! transaction of their own on the failure path, guarded by `failed.turns > 0`,
//! and call [`record`] with [`Consumed::reported`]. A run whose calls all failed
//! before reporting anything therefore lands here as `calls_unmetered`, which is
//! the right answer rather than an absent row.
//!
//! `loops::initiative::a_provider_that_fails_forever_is_bounded_by_the_day_and_billed_for_it`
//! is that path asserted end to end, and it is worth keeping a paragraph
//! because it is the case this table exists for: a model that is down all
//! afternoon costs an employee its whole daily turn budget and every one of
//! those turns is on the bill.
//!
//! # What this ledger still cannot see
//!
//! **A turn that was reserved and never counted, on the inbound path.** The
//! old text offered [`crate::turns::taken_today`] as the cross-check — "a turn
//! is reserved before the model is called, so `turns_taken` counts the runs this
//! table does not" — and that is only true of the initiative loop.
//! `Agent::on_turn` reserves no turn at all: the arrival of the message is the
//! throttle, which `crate::turns` argues for in its own module docs. So
//! `turns_taken` and `calls` count different populations and neither bounds the
//! other. The number to trust for "what did this employee cost today" is this
//! table, and [`Consumed::is_complete`] is what says whether to trust it.
//!
//! **Cache writes are inside `input_tokens`.** `llm_anthropic.rs` folds
//! `cache_creation_input_tokens` in on the way through and `Usage` has no field
//! for it, so there is no column for it here. See decision 2 of the migration.

use agentos_domain::ids::EmployeeId;
use chrono::NaiveDate;
use serde::Serialize;

use crate::db::{StoreError, TenantTx};

/// What a stretch of model calls consumed.
///
/// The same struct is written and read, and the read side's rollup deserialises
/// into it too (`sum(...)::bigint AS <column>`), so the column list exists once
/// and the ledger, the JSON and the arithmetic cannot drift apart.
///
/// `i64` rather than `u64` because that is what the columns are and what sqlx
/// binds; the narrowing happens once, in [`Consumed::reported`], where it can be
/// argued about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct Consumed {
    /// Model round trips. One `Llm::complete` that returned a response is one
    /// call, whether or not it said what it cost.
    pub calls: i64,
    /// Of [`Self::calls`], the ones that came back with no usage figure at all.
    /// They contribute nothing to the token counts below, so those counts are a
    /// **floor** whenever this is non-zero.
    pub calls_unmetered: i64,
    /// Fresh input tokens, billed at full rate. Cache writes are folded in here
    /// by the provider adapter; no separate count reaches this layer.
    pub input_tokens: i64,
    /// Generated tokens.
    pub output_tokens: i64,
    /// Input served from the prefix cache, billed at a fraction of fresh input.
    pub cache_read_tokens: i64,
    /// Runs — one `Turn::run`, not one round trip — that ended with prose and
    /// nothing the gate ruled on. See [`Consumed::unbacked`].
    ///
    /// A subset of [`Self::calls`], constrained as one, because a run that
    /// finished made at least one call.
    pub runs_unbacked: i64,
    /// What those runs said, in characters. **Not a verdict**: this is the
    /// second half of the pair, and the reason [`Self::runs_unbacked`] is not a
    /// boolean. One unbacked run of thirty characters is an employee saying it
    /// had nothing to do; one of twelve thousand is an employee describing a day
    /// of work it did not do, and only a human reading them can say which. This
    /// column exists so that the two are different rows.
    pub unbacked_chars: i64,
}

impl Consumed {
    /// What `calls` model round trips reported between them.
    ///
    /// **A call that happened and reported no tokens at all is unmetered, not
    /// free.** That is the one judgement in this module and it lives here so
    /// that both write sites make it identically. A 200 from a model that read a
    /// prompt necessarily consumed input tokens; three zeroes therefore mean
    /// nobody counted, not that nothing was counted — see the module docs for
    /// the batch-granularity ceiling.
    ///
    /// Saturating **upward** on the `u64` → `i64` narrowing, which is the only
    /// direction worth choosing: clamping down would under-state a bill, and
    /// under-stating is the failure this table exists to end. Nothing real will
    /// reach `i64::MAX` tokens in a day; if it does, the row is wrong in the
    /// direction that makes somebody look.
    pub fn reported(
        calls: u32,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: u64,
    ) -> Self {
        let reported_nothing = input_tokens == 0 && output_tokens == 0 && cache_read_tokens == 0;
        Self {
            calls: i64::from(calls),
            calls_unmetered: if reported_nothing {
                i64::from(calls)
            } else {
                0
            },
            input_tokens: clamp(input_tokens),
            output_tokens: clamp(output_tokens),
            cache_read_tokens: clamp(cache_read_tokens),
            runs_unbacked: 0,
            unbacked_chars: 0,
        }
    }

    /// Say whether this run left anything to check its own account against.
    ///
    /// `ruled` is every proposal the Policy Gate ruled on during the run —
    /// `Finished::ruled_calls`, plus whatever a vertical operation performed
    /// before the model. **Allowed and denied both count**, for the same reason
    /// `Finished::malformed_calls` counts only what never reached the gate: a
    /// refusal is an `audit_log` row, and a row is a thing an operator can hold
    /// the prose up against. Zero of them and there is nothing at all — so the
    /// prose is measured, counted, and left to be read.
    ///
    /// **This is the same judgement [`Self::reported`] makes about tokens, one
    /// level up, and it lives here for the same reason: one place, so two
    /// callers cannot disagree about what an empty turn is.** Unknown is not
    /// zero there; here, *said* is not *did*.
    ///
    /// It does not stop an employee narrating a day it did not have, and nothing
    /// can — a model writes what it writes. It stops the record from carrying
    /// only the half the employee wrote.
    #[must_use]
    pub fn unbacked(mut self, ruled: u32, reply: &str) -> Self {
        if ruled == 0 {
            self.runs_unbacked = 1;
            // Characters, not bytes: see decision 4 of the migration. `trim`
            // because trailing newlines are the provider's, not the employee's.
            // Saturating upward on the narrowing, like `reported`: an absurd
            // length is wrong in the direction that makes somebody look.
            self.unbacked_chars = i64::try_from(reply.trim().chars().count()).unwrap_or(i64::MAX);
        }
        self
    }

    /// Fold another row in. Saturating, because a wrapped total would be a
    /// silently wrong public claim.
    pub fn add(&mut self, other: &Self) {
        self.calls = self.calls.saturating_add(other.calls);
        self.calls_unmetered = self.calls_unmetered.saturating_add(other.calls_unmetered);
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(other.cache_read_tokens);
        self.runs_unbacked = self.runs_unbacked.saturating_add(other.runs_unbacked);
        self.unbacked_chars = self.unbacked_chars.saturating_add(other.unbacked_chars);
    }

    /// Every token anybody told us about, cached or not.
    ///
    /// A **floor** when [`Self::is_complete`] is false: the unmetered calls
    /// contributed nothing to it, and there is no defensible way to fill them
    /// in.
    pub const fn tokens_measured(&self) -> i64 {
        self.input_tokens
            .saturating_add(self.output_tokens)
            .saturating_add(self.cache_read_tokens)
    }

    /// True when every call in this row reported what it cost.
    ///
    /// The question to ask before quoting [`Self::tokens_measured`] anywhere.
    pub const fn is_complete(&self) -> bool {
        self.calls_unmetered == 0
    }
}

/// `u64` → `i64`, saturating up. See [`Consumed::reported`].
fn clamp(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Add one run's consumption to this employee's day.
///
/// Call it in the transaction that commits the turn's own work — see the module
/// docs for why that placement is the whole idempotency story, and what it
/// costs.
///
/// A run with no calls writes nothing: an empty row would claim an employee was
/// billed for a day it never woke on, and "no row" already means "nothing
/// recorded" everywhere else in this schema.
///
/// The tenant comes from `tx`, which is the only thing row-level security
/// honours anyway; there is no tenant parameter to pass wrongly.
pub async fn record(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
    consumed: Consumed,
) -> Result<(), StoreError> {
    if consumed.calls == 0 {
        return Ok(());
    }

    // Additive on conflict, deliberately not idempotent. Two calls that cost the
    // same on the same day are two calls; see the module docs.
    sqlx::query(
        "INSERT INTO model_usage_daily \
           (tenant_id, employee_id, day, calls, calls_unmetered, \
            input_tokens, output_tokens, cache_read_tokens, \
            runs_unbacked, unbacked_chars) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (tenant_id, employee_id, day) DO UPDATE SET \
           calls             = model_usage_daily.calls + excluded.calls, \
           calls_unmetered   = model_usage_daily.calls_unmetered + excluded.calls_unmetered, \
           input_tokens      = model_usage_daily.input_tokens + excluded.input_tokens, \
           output_tokens     = model_usage_daily.output_tokens + excluded.output_tokens, \
           cache_read_tokens = model_usage_daily.cache_read_tokens \
                             + excluded.cache_read_tokens, \
           runs_unbacked     = model_usage_daily.runs_unbacked + excluded.runs_unbacked, \
           unbacked_chars    = model_usage_daily.unbacked_chars + excluded.unbacked_chars, \
           updated_at        = now()",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id.as_uuid())
    .bind(day)
    .bind(consumed.calls)
    .bind(consumed.calls_unmetered)
    .bind(consumed.input_tokens)
    .bind(consumed.output_tokens)
    .bind(consumed.cache_read_tokens)
    .bind(consumed.runs_unbacked)
    .bind(consumed.unbacked_chars)
    .execute(&mut ***tx)
    .await?;

    Ok(())
}

/// What this employee consumed on `day`. The operator's narrowest question.
///
/// All zeroes for a day with no row, which is the same answer as a row of zeroes
/// and means the same thing: nothing was recorded. It does **not** mean no calls
/// were made — see the module docs on turns that did not finish.
pub async fn on_day(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    day: NaiveDate,
) -> Result<Consumed, StoreError> {
    // No `WHERE tenant_id`: RLS adds it, and a hand-written filter would be a
    // second place to forget it.
    let row: Option<Consumed> = sqlx::query_as(
        "SELECT calls, calls_unmetered, input_tokens, output_tokens, cache_read_tokens, \
                runs_unbacked, unbacked_chars \
           FROM model_usage_daily WHERE employee_id = $1 AND day = $2",
    )
    .bind(employee_id.as_uuid())
    .bind(day)
    .fetch_optional(&mut ***tx)
    .await?;

    Ok(row.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use chrono::Utc;

    use super::*;
    use crate::db::Db;

    const DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 23) {
        Some(d) => d,
        None => panic!("valid date"),
    };
    const NEXT_DAY: NaiveDate = match NaiveDate::from_ymd_opt(2026, 8, 24) {
        Some(d) => d,
        None => panic!("valid date"),
    };

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the token ledger needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed_tenant(db: &Db, label: &str) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("{label}-{}", tenant.as_uuid().simple()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit tenant");
        tenant
    }

    async fn seed_employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit employee");
        id
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

    /// Record in its own committed transaction, the way a caller's turn would.
    async fn record_committed(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        day: NaiveDate,
        consumed: Consumed,
    ) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        record(&mut tx, employee, day, consumed)
            .await
            .expect("record");
        tx.commit().await.expect("commit");
    }

    async fn read(db: &Db, tenant: TenantId, employee: EmployeeId, day: NaiveDate) -> Consumed {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let consumed = on_day(&mut tx, employee, day).await.expect("read");
        tx.rollback().await.expect("rollback");
        consumed
    }

    // -- the judgement, with no database -----------------------------------

    /// The distinction the whole table exists for, at the one place it is made.
    #[test]
    fn a_call_nobody_metered_is_not_a_call_that_cost_nothing() {
        // A provider that did not report: the call is on the record, its cost is
        // on the record as unknown, and the tokens stay at zero rather than
        // being invented.
        let unknown = Consumed::reported(3, 0, 0, 0);
        assert_eq!(unknown.calls, 3);
        assert_eq!(unknown.calls_unmetered, 3);
        assert_eq!(unknown.tokens_measured(), 0);
        assert!(
            !unknown.is_complete(),
            "3 calls of unknown cost is not zero"
        );

        // A metered call, even a tiny one, is complete.
        let metered = Consumed::reported(3, 1, 0, 0);
        assert_eq!(metered.calls_unmetered, 0);
        assert!(metered.is_complete());

        // A cache-only read is metered too: it reported something.
        assert!(Consumed::reported(1, 0, 0, 4096).is_complete());

        // No calls at all is neither — it is an employee that did not wake.
        let idle = Consumed::default();
        assert_eq!(idle.calls, 0);
        assert!(idle.is_complete());

        // And the narrowing saturates upward, so an absurd count is loud rather
        // than negative.
        assert_eq!(Consumed::reported(1, u64::MAX, 0, 0).input_tokens, i64::MAX);
    }

    /// **The distinction the two new columns exist for, at the one place it is
    /// made.**
    ///
    /// Three turns that are indistinguishable in every other number this ledger
    /// holds — same calls, same tokens, same absence of an error — and the row
    /// has to tell them apart, because one of them did a day's work, one of them
    /// honestly had nothing to do, and one of them said it did a day's work and
    /// did nothing at all.
    #[test]
    fn a_turn_that_only_talked_is_not_a_turn_that_worked() {
        // What the live run produced: prose describing five tickets and five
        // emails, and not one proposal in front of the gate.
        let narration = "Today I handled five tickets and sent five replies.";
        let told = Consumed::reported(1, 4_000, 3_000, 0).unbacked(0, narration);
        assert_eq!(told.runs_unbacked, 1);
        assert_eq!(told.unbacked_chars, 51);
        // It is still a real, metered, billable call. This is not an error
        // channel and it must not read as one.
        assert_eq!(told.calls, 1);
        assert!(told.is_complete());

        // The same turn, having asked for one thing. Backed, and the columns say
        // nothing — including when the gate REFUSED it, because a refusal is an
        // `audit_log` row and a row is a thing to check the prose against.
        let did = Consumed::reported(1, 4_000, 3_000, 0).unbacked(1, narration);
        assert_eq!(did.runs_unbacked, 0);
        assert_eq!(did.unbacked_chars, 0, "a backed run measures no prose");

        // And the employee that genuinely had nothing to do. Counted, because it
        // called nothing — but thirty characters is not twelve thousand, and the
        // whole reason `unbacked_chars` exists is that this row must not be the
        // same row as the one above. A boolean here would libel it.
        let quiet = Consumed::reported(1, 4_000, 12, 0).unbacked(0, "  Nothing was due today.\n");
        assert_eq!(quiet.runs_unbacked, told.runs_unbacked);
        assert_eq!(quiet.unbacked_chars, 22, "trimmed, and counted in chars");
        assert!(
            quiet.unbacked_chars < told.unbacked_chars,
            "an employee saying it had nothing to do reads the same as one \
             narrating a day it did not have"
        );

        // Characters and not bytes: the same sentence in another script must not
        // rank three times higher for being written in it.
        assert_eq!(
            Consumed::reported(1, 1, 1, 0)
                .unbacked(0, "こんにちは")
                .unbacked_chars,
            5
        );
    }

    #[test]
    fn folding_rows_together_keeps_the_unknown_visible() {
        let mut total = Consumed::reported(2, 100, 20, 0);
        total.add(&Consumed::reported(3, 0, 0, 0));

        assert_eq!(total.calls, 5);
        assert_eq!(total.calls_unmetered, 3);
        assert_eq!(total.tokens_measured(), 120);
        assert!(
            !total.is_complete(),
            "120 tokens over 5 calls is a floor, and the reader has to be told"
        );

        // Two unbacked runs in one window are two runs and both their words. A
        // fold that kept one would make a seat that talks all day look like a
        // seat that did it once.
        total.add(&Consumed::reported(1, 5, 5, 0).unbacked(0, "one"));
        total.add(&Consumed::reported(1, 5, 5, 0).unbacked(0, "two"));
        assert_eq!(total.runs_unbacked, 2);
        assert_eq!(total.unbacked_chars, 6);
    }

    // -- attribution -------------------------------------------------------

    #[tokio::test]
    async fn usage_is_attributed_to_the_employee_that_spent_it() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db, "attr").await;
        let lena = seed_employee(&db, tenant, "lena").await;
        let mo = seed_employee(&db, tenant, "mo").await;

        record_committed(&db, tenant, lena, DAY, Consumed::reported(1, 50, 10, 0)).await;
        record_committed(&db, tenant, lena, DAY, Consumed::reported(2, 30, 4, 900)).await;
        record_committed(&db, tenant, mo, DAY, Consumed::reported(1, 7, 1, 0)).await;

        // Two runs on one day accumulate; they do not overwrite.
        let lena_day = read(&db, tenant, lena, DAY).await;
        assert_eq!(lena_day.calls, 3);
        assert_eq!(lena_day.input_tokens, 80);
        assert_eq!(lena_day.output_tokens, 14);
        assert_eq!(lena_day.cache_read_tokens, 900);
        assert!(lena_day.is_complete());

        // Mo's bill is Mo's.
        assert_eq!(read(&db, tenant, mo, DAY).await.input_tokens, 7);
        // And the day is a real dimension, not decoration.
        assert_eq!(read(&db, tenant, lena, NEXT_DAY).await, Consumed::default());

        drop_tenant(&db, tenant).await;
    }

    /// A tenant's bill is its own. RLS, not a `WHERE` clause somebody adds.
    #[tokio::test]
    async fn one_tenants_usage_is_invisible_to_another() {
        let Some(db) = db().await else { return };
        let a = seed_tenant(&db, "usage-a").await;
        let b = seed_tenant(&db, "usage-b").await;
        let theirs = seed_employee(&db, a, "lena").await;

        record_committed(&db, a, theirs, DAY, Consumed::reported(4, 1_000, 200, 0)).await;
        assert_eq!(read(&db, a, theirs, DAY).await.calls, 4);

        // B, holding A's real employee id, learns nothing at all — not a
        // filtered zero, an invisible row.
        assert_eq!(read(&db, b, theirs, DAY).await, Consumed::default());

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    /// The table is not a thing an operator edits before a board meeting.
    #[tokio::test]
    async fn rls_is_on_forced_and_the_ledger_cannot_be_rewritten_by_hand() {
        let Some(db) = db().await else { return };
        let a = seed_tenant(&db, "rls-a").await;
        let b = seed_tenant(&db, "rls-b").await;
        let theirs = seed_employee(&db, b, "theirs").await;
        record_committed(&db, b, theirs, DAY, Consumed::reported(1, 10, 2, 0)).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let (enabled, forced, policies): (bool, bool, i64) = sqlx::query_as(
            "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                    (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) \
               FROM pg_class c \
              WHERE c.oid = 'model_usage_daily'::regclass",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("pg_class");
        tx.rollback().await.expect("rollback");
        assert!(enabled, "RLS must be enabled on model_usage_daily");
        assert!(
            forced,
            "RLS must be forced, or the table owner walks past it"
        );
        assert_eq!(policies, 1, "exactly one policy, like every other table");

        // A cannot file a row wearing B's id: usage on somebody else's ledger is
        // a bill on somebody else's ledger.
        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let wearing_b = sqlx::query(
            "INSERT INTO model_usage_daily (tenant_id, employee_id, day, calls) \
             VALUES ($1, $2, $3, 1)",
        )
        .bind(b.as_uuid())
        .bind(theirs.as_uuid())
        .bind(DAY)
        .execute(&mut **tx)
        .await;
        assert!(
            wearing_b.is_err(),
            "one tenant must not write a row wearing another's id"
        );
        tx.rollback().await.expect("rollback");

        // And nobody deletes what was spent. The grant is not there, so this
        // fails on privilege rather than on the row being invisible.
        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        let deleted = sqlx::query("DELETE FROM model_usage_daily WHERE employee_id = $1")
            .bind(theirs.as_uuid())
            .execute(&mut **tx)
            .await;
        assert!(
            deleted.is_err(),
            "a consumption ledger you can delete rows from is not one"
        );
        tx.rollback().await.expect("rollback");

        // The row is still there, unchanged.
        assert_eq!(read(&db, b, theirs, DAY).await.calls, 1);

        // The subset invariant is a constraint, not a convention: a row claiming
        // more unknown calls than calls is refused outright.
        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        let impossible = sqlx::query(
            "INSERT INTO model_usage_daily (tenant_id, employee_id, day, calls, calls_unmetered) \
             VALUES ($1, $2, $3, 1, 2)",
        )
        .bind(b.as_uuid())
        .bind(theirs.as_uuid())
        .bind(NEXT_DAY)
        .execute(&mut **tx)
        .await;
        assert!(impossible.is_err(), "unmetered calls are a subset of calls");
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    /// **The B decision, tested.** The write is additive and therefore not
    /// idempotent on its own — so what stops one call being counted twice is
    /// that the row commits with the turn and not before it.
    ///
    /// A rolled-back turn leaves nothing behind: no row, no partial row, and
    /// nothing for a retry to add to a second time. A retry re-runs the model,
    /// and the call it then makes is a real second call that really is paid for.
    #[tokio::test]
    async fn the_ledger_commits_with_the_turn_or_not_at_all() {
        let Some(db) = db().await else { return };
        let tenant = seed_tenant(&db, "atomic").await;
        let employee = seed_employee(&db, tenant, "lena").await;

        // A turn that made its model call and then failed before commit.
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        record(&mut tx, employee, DAY, Consumed::reported(1, 50, 10, 0))
            .await
            .expect("record");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            read(&db, tenant, employee, DAY).await,
            Consumed::default(),
            "an uncommitted turn must leave no bill behind"
        );

        // The retry, which really did call the model again.
        record_committed(&db, tenant, employee, DAY, Consumed::reported(1, 50, 10, 0)).await;
        let after = read(&db, tenant, employee, DAY).await;
        assert_eq!(after.calls, 1, "one committed turn, one call");
        assert_eq!(after.input_tokens, 50);

        // And a genuinely separate second call adds, because it was genuinely
        // paid for. A ledger that deduplicated this would be under-reporting a
        // real bill, which is the failure this table exists to end.
        record_committed(&db, tenant, employee, DAY, Consumed::reported(1, 50, 10, 0)).await;
        assert_eq!(read(&db, tenant, employee, DAY).await.calls, 2);

        drop_tenant(&db, tenant).await;
    }
}
