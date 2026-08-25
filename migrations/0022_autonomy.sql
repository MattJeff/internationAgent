-- 0022_autonomy: how much of the work the agents actually did.
--
-- The claim this project will have to defend in public is "the agents did the
-- work", and the first question anybody asks is "how much did you do
-- yourself?". Every action already writes an audit row and every approval
-- writes another, so the evidence exists; nothing aggregated it, so the honest
-- answer was "we don't know". `employee_autonomy_daily` is the answer.
--
-- Four decisions shape this file.
--
-- 1. IT IS A VIEW OVER THE AUDIT TRAIL, NOT A TABLE. The same discipline
--    `supplier_reputation` applies in 0007_sourcing and for the same reason: a
--    score nobody can write is a score nobody can inflate. The view aggregates,
--    so Postgres refuses an INSERT into it under any privilege, and `app_role`
--    holds SELECT on it and nothing else. There is no nightly recompute to go
--    stale and no column an operator can nudge before a board meeting.
--
--    `security_invoker = true` (PG15+) for the same reason as there, too:
--    without it the view runs as its owner, who bypasses RLS, and one tenant's
--    autonomy figure would be computed over everybody's trail.
--
-- 2. WHEN THE READING IS AMBIGUOUS, THE SMALLER NUMBER WINS. This metric will
--    be used to make a public claim. Every definition below is the one that
--    makes autonomy *lower*: an event that could be read as autonomous or as
--    assisted is counted as assisted, and the percentage is integer division,
--    which truncates downward. A future edit that loosens one of these
--    definitions is loosening a claim, not fixing a bug — say so in the commit
--    message.
--
-- 3. THE FOUR KINDS OF HUMAN INVOLVEMENT ARE NOT AVERAGED TOGETHER. Approving,
--    rejecting, configuring and acting-in-the-agent's-place are four different
--    facts, and one blended "human touches" number flatters whichever of them
--    is cheapest. Each gets its own column. Configuration is counted and then
--    deliberately excluded from the ratio — see the taxonomy below.
--
-- 4. THERE IS NO COST COLUMN, AND THAT IS ON PURPOSE. See the last section.
--
-- ---------------------------------------------------------------------------
-- THE TAXONOMY
-- ---------------------------------------------------------------------------
--
-- Every column is a `count(*) filter (...)` over `audit_log`, so each one names
-- a shape of row that some writer in this workspace actually produces today.
-- The writers are: `agentos_app::gate` (every Policy Gate ruling),
-- `agentos_app::effects` (every provider attempt), `routes::approvals` (a
-- refusal), `routes::teams` and `routes::mcp` (configuration), `routes::pool`
-- (resource moves), `agentos_app::secrets` and `agentos_app::identity`.
--
--   `decision IS NOT NULL`  <=>  the row is a Policy Gate ruling. The gate is
--   the only writer that fills the column, which is what makes the split below
--   exact rather than a guess at `action_kind` spellings.
--
-- ACTIONS TAKEN — `decision = 'allow'`. One row per ruling that permitted an
-- action. Partitioned exhaustively and disjointly into four:
--
--   * `actions_unassisted`  — actor is the employee, no approval was spent.
--     **This is the only bucket that counts as autonomy.**
--   * `human_approved`      — the payload carries an `approval_id` on an
--     `allow` row, which only `PolicyGate::redeem_approval` produces. The gate
--     asked, a person restated the exact action, and said yes.
--   * `operator_initiated`  — actor is an operator and no approval was spent: a
--     human drove the action through the API itself.
--   * `system_initiated`    — actor is `system`: a cadence tick, a webhook
--     handler, the outbox poller.
--
-- INTERVENTIONS — `human_approved + operator_initiated + human_rejected`.
--
--   * `human_rejected` — `action_kind = 'approval_decided'` with
--     `payload->>'outcome' = 'denied'`, written by `routes::approvals::deny`. A
--     rejection is an intervention that produced *no* action, so it is counted
--     here and is NOT in `actions_taken`. It still lands in the ratio's
--     denominator, because a human had to spend attention on it.
--
-- CONFIGURATION — `configuration_changes`, `action_kind = 'policy_changed'`.
-- Setting a policy, wiring an MCP endpoint, moving an employee between teams.
-- **This is setup, not intervention.** It is counted so a reader can see how
-- much of it there was, and it appears in NEITHER the numerator nor the
-- denominator of the ratio. Counting configuration as autonomy — by letting it
-- inflate `actions_taken` — would be the single easiest way to flatter this
-- number, which is why it has its own column and no path into the arithmetic.
--
-- CONTEXT, in neither term — `escalations_raised` (`decision =
-- 'require_approval'`: the gate stopped and asked) and `policy_denied`
-- (`decision = 'deny'`: the policy refused). A policy denial is not a human
-- intervention: the human who wrote the policy is already counted under
-- configuration, and charging them twice for one act would understate autonomy
-- for a reason that is not true.
--
-- THE RATIO
--
--   decisions    = actions_taken + human_rejected
--   autonomy_pct = 100 * actions_unassisted / decisions
--
-- `system_initiated` therefore sits in the denominator and in no numerator. A
-- cron tick is not a human intervening, but it is not the agent choosing to act
-- either, and rule 2 sends every ambiguous case downward. NULL rather than 0
-- when `decisions = 0`, because "no data" is not "0% autonomous".
--
-- ---------------------------------------------------------------------------
-- WHAT THIS TRAIL CANNOT DISTINGUISH TODAY
-- ---------------------------------------------------------------------------
--
-- Read this before quoting the number anywhere.
--
-- a. **Operator-initiated is not the same as operator-as-fallback.** An `allow`
--    row with an operator actor says a human drove the action. Nothing in the
--    trail says whether they did it *because the agent could not* — the real
--    intervention — or because a human simply used the API for something the
--    agent was never asked to do. Both are counted as interventions, which is
--    the strict reading and overstates intervention rather than autonomy.
--
-- b. **"Who" is a credential, not a person.** `AuditActor::Operator(String)`
--    holds the API key's label (`apps/server/src/auth.rs`). Two humans sharing
--    a key are one actor; one human with two keys is two. The trail answers
--    "which credential intervened", never "which human".
--
-- c. **Most configuration leaves no audit row at all.** Only `routes::teams`
--    and `routes::mcp` write `policy_changed`. Setting a charter (0018), a
--    cadence (0020), a psyche, or creating an employee writes nothing —
--    `AuditKind::EmployeeCreated`, `EmployeeLifecycleChanged`,
--    `ApprovalRequested`, `MessageReceived` and `MessageSent` exist in the enum
--    and are never constructed by any writer in this workspace. So
--    `configuration_changes` is a floor, not a count, and the setup effort
--    behind an autonomous-looking employee is largely invisible here.
--
-- d. **An abandoned escalation is silent.** `escalations_raised` minus the
--    approvals and rejections that answered them is work the agent stopped on
--    and nobody ever came back to — but an approval that simply expires writes
--    no row, and the two halves can fall in different days, so the view does
--    not compute that difference and neither should a reader without checking
--    `approvals.state` directly.
--
-- e. **Rulings, not outcomes.** The gate writes one row per `authorize` call,
--    so an agent that retries the same email three times books three actions.
--    A chatty agent scores higher than a careful one. Separately, an authorised
--    action is not a completed one: whether the effect landed is in the
--    `provider_call_attempted` row's `payload->>'outcome'`, which this view
--    does not read.
--
-- f. **Cost is not measured at all.** Token counts come back from the provider
--    (`Usage` in `crates/providers/src/llm.rs`, filled from the Anthropic
--    response in `llm_anthropic.rs`) and are then written to exactly two
--    places: a process-local counter that explicitly drops the tenant
--    (`apps/server/src/metrics.rs`, `record_llm_usage`) and `tracing` log lines
--    (`main.rs`, `loops/initiative.rs`). No table, no audit row, no column
--    anywhere in `migrations/`. There is also no price list in this codebase,
--    so even with tokens a euro figure would need a number nobody could trace.
--    So there is no `cost_minor` column and no revenue-over-cost figure here: a
--    cost nobody can trace is worse than a missing one. Two things must land
--    before one is possible — a `model_usage (tenant_id, employee_id, day,
--    input_tokens, output_tokens, cache_read_tokens)` row written where
--    `finished.usage` is currently logged, and a price table with a source.
--
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- employee_autonomy_daily
-- ---------------------------------------------------------------------------
--
-- Daily grain, because a view takes no parameters and the caller needs a
-- window. Counts sum across days; the ratio does not, so a caller reading more
-- than one day recomputes it from the summed counts with the same expression —
-- `apps/server/src/routes/autonomy.rs` is that caller, and one of its tests
-- asserts the two agree.
--
-- The day is UTC, matching `spend_buckets` and the turn budget: an employee
-- must not have two "todays". `at time zone 'UTC'` rather than a bare `::date`
-- so the answer does not depend on the session's TimeZone.
--
-- Rows with `employee_id IS NULL` — tenant-level configuration, a phone number
-- added to the pool — group under NULL. They belong in a tenant total and to no
-- employee, which is exactly what that grouping gives.
--
-- ponytail: recomputed per query, and the `day` predicate cannot use
-- `audit_log_tenant_time_idx` because it is an expression. Correct, and O(the
-- tenant's trail). If a tenant accumulates enough rows for that to hurt, add an
-- expression index on `(tenant_id, ((occurred_at at time zone 'UTC')::date))`
-- or make this MATERIALIZED and refresh it — the SQL below does not change.

create or replace view employee_autonomy_daily with (security_invoker = true) as
select
  a.tenant_id,
  a.employee_id,
  (a.occurred_at at time zone 'UTC')::date                          as day,

  -- Actions taken: every Policy Gate ruling that permitted an action.
  count(*) filter (where a.decision = 'allow')                      as actions_taken,

  -- ... split four ways, disjointly and exhaustively. `actor` is one of
  -- `employee:<uuid>`, `operator:<label>` or `system` (AuditActor::label), and
  -- the approval branch is taken first, so every `allow` row lands in exactly
  -- one of these. `routes::autonomy` has a test that asserts they re-add.
  count(*) filter (
    where a.decision = 'allow'
      and not a.payload ? 'approval_id'
      and a.actor like 'employee:%')                                as actions_unassisted,

  -- The gate asked and a person said yes. Only `redeem_approval` puts an
  -- `approval_id` on an `allow` row; the request itself is a
  -- `require_approval` row, which is counted below instead.
  count(*) filter (
    where a.decision = 'allow'
      and a.payload ? 'approval_id')                                as human_approved,

  -- A human acting through the API in the agent's place. See note (a).
  count(*) filter (
    where a.decision = 'allow'
      and not a.payload ? 'approval_id'
      and a.actor like 'operator:%')                                as operator_initiated,

  -- A cadence tick, a webhook, the outbox poller. Not a human, not the agent
  -- choosing: in the denominator, in no numerator.
  count(*) filter (
    where a.decision = 'allow'
      and not a.payload ? 'approval_id'
      and a.actor = 'system')                                       as system_initiated,

  -- A person said no. Written by `routes::approvals::deny`, which is the only
  -- writer of `approval_decided`. No action followed, so this is an
  -- intervention that is not in `actions_taken`.
  count(*) filter (
    where a.action_kind = 'approval_decided'
      and a.payload ->> 'outcome' = 'denied')                       as human_rejected,

  -- Context. Neither of these is a human intervention.
  count(*) filter (where a.decision = 'require_approval')           as escalations_raised,
  count(*) filter (where a.decision = 'deny')                       as policy_denied,

  -- Setup, not intervention. Counted, and kept out of the arithmetic.
  count(*) filter (where a.action_kind = 'policy_changed')          as configuration_changes,

  -- The day's own ratio, for reading one day directly. Integer division, so it
  -- truncates downward; NULL when there was nothing to divide by, because "no
  -- data" is not "0% autonomous".
  (100 * count(*) filter (
           where a.decision = 'allow'
             and not a.payload ? 'approval_id'
             and a.actor like 'employee:%')
     / nullif(count(*) filter (
           where a.decision = 'allow'
              or (a.action_kind = 'approval_decided'
                  and a.payload ->> 'outcome' = 'denied')), 0)
  )::int                                                            as autonomy_pct

from audit_log a
group by a.tenant_id, a.employee_id, (a.occurred_at at time zone 'UTC')::date;

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- SELECT and nothing else, exactly as `supplier_reputation`. Even that is
-- belt-and-braces: the view aggregates, so it is not auto-updatable and
-- Postgres rejects a write to it before privileges are ever consulted. An
-- autonomy figure a hand can edit is not a measurement.
--
-- RLS is inherited rather than restated: `audit_log` carries the
-- `tenant_isolation` policy from 0001_core and this view is
-- `security_invoker`, so a tenant reading it sees its own trail and no `WHERE
-- tenant_id` exists here for anyone to forget.

grant select on employee_autonomy_daily to app_role;
