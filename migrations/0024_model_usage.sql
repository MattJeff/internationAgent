-- 0024_model_usage: what the models actually cost, in tokens, per employee.
--
-- Until this file the single largest operating cost of this system was
-- invisible. `Usage` comes back real from the provider
-- (`crates/providers/src/llm_anthropic.rs` fills it from the response body) and
-- landed in exactly two places: a process-local counter that deliberately drops
-- the tenant (`apps/server/src/metrics.rs`) and two `tracing` lines
-- (`apps/server/src/main.rs`, `apps/server/src/loops/initiative.rs`). No table,
-- no audit row — `grep -i token migrations/*.sql` found only prose. So every
-- claim this project could make about its own economics was unsupportable, and
-- `0022_autonomy.sql` says so at length in its note (f). This is the row that
-- note asks for.
--
-- Five decisions shape this file.
--
-- 1. THE GRAIN IS `(tenant_id, employee_id, day)`, WHICH IS THE GRAIN THE
--    AUTONOMY VIEW ALREADY USES. `employee_autonomy_daily` groups on exactly
--    these three columns and `turn_buckets` is keyed on them, so an operator can
--    put "how much did it do by itself" and "what did it burn doing it" beside
--    each other without a join anybody has to reason about. `day` is a UTC date
--    from the same `now.date_naive()` the spend ledger and the turn budget key
--    on: an employee must not have two "todays". The argument for UTC over a
--    tenant-local midnight is in `0016_turn_budget.sql` and is not repeated.
--
-- 2. THE COLUMNS ARE THE COLUMNS `Usage` ACTUALLY HAS, AND NO MORE.
--    `providers::llm::Usage` is three numbers — `input_tokens`,
--    `output_tokens`, `cache_read_tokens`. There is deliberately no
--    `cache_write_tokens` column, because no cache-write count reaches this
--    layer: `llm_anthropic.rs` folds `cache_creation_input_tokens` into
--    `input_tokens` on the way in, with its own note saying why. A column here
--    would therefore be a column that is always zero while the number it names
--    is really being spent, which is the exact failure this whole migration
--    exists to end. Add the column in the same commit that splits the field on
--    `Usage`, or not at all.
--
-- 3. A CALL WHOSE COST NOBODY REPORTED IS NOT A FREE CALL. `calls` counts model
--    round trips; `calls_unmetered` counts the ones that came back without a
--    usage figure. The CLI backend is lossy by construction
--    (`crates/providers/src/llm_cli.rs` says so in its first paragraph), a
--    provider can omit the field, and `WireUsage` is `#[serde(default)]` — so
--    "no usage in the response" arrives here as three zeroes and is
--    indistinguishable from a call that genuinely cost nothing. Zero is a lie
--    that averages well: a day of 40 unmetered calls and a day of 40 free calls
--    are the same row without this column, and one of those days has a bill.
--    So the writer records that the call happened AND that its cost is unknown,
--    and every reader can subtract. `agentos_store::model_usage::Consumed`
--    makes that judgement in one place; see its docs for the ceiling.
--
-- 4. IT IS ADDITIVE, AND THEREFORE IT COMMITS WITH THE WORK IT DESCRIBES. The
--    upsert below ADDS; it is not idempotent and cannot be, because two model
--    calls with identical usage on the same day are two real calls and must
--    read as two. Idempotence comes from WHERE the write happens rather than
--    from a key: `Agent::on_turn` writes it inside the outbox handler's own
--    transaction, the one that also records the reply, so the row exists
--    exactly when the turn committed. There is no state where the reply landed
--    and the tokens did not, and no state where the tokens were counted twice
--    for one call — a redelivered outbox event re-runs the model, and the
--    second row describes a second real call that was really paid for.
--
--    The price of that is stated plainly: a usage write that fails aborts a
--    turn that would otherwise have committed. That is the side of the trade
--    taken on purpose. The other side — a best-effort write in a transaction of
--    its own — loses rows silently, and a silently lost row reads as LOWER
--    consumption, which is the direction that flatters a number this project
--    intends to publish. A loud failure that costs one retried turn beats a
--    quiet one that costs the number its credibility.
--
-- 5. THERE IS NO MONEY IN THIS FILE, AND THAT IS THE POINT. See the last
--    section.

-- ---------------------------------------------------------------------------
-- model_usage_daily
-- ---------------------------------------------------------------------------
--
-- `bigint` throughout, and not `integer`: a single long conversation can read a
-- few hundred thousand cached tokens per turn, an employee takes many turns a
-- day, and a counter that only just fits is a counter somebody widens later
-- after it has already wrapped.
--
-- The FK cascades from `employees`, matching `turn_buckets`. That is a
-- deliberate difference from `audit_log`, which has no FK so that deleting an
-- employee cannot delete its history: this table is a consumption ledger for a
-- live fleet rather than a trail, and it is keyed on the employee, so a row
-- whose employee is gone has no one to attribute to. Nothing in this workspace
-- deletes an employee — termination is a lifecycle, not a DELETE — so the
-- cascade fires only when a tenant is removed entirely.

create table if not exists model_usage_daily (
  tenant_id         uuid        not null references tenants (id) on delete cascade,
  employee_id       uuid        not null references employees (id) on delete cascade,
  -- UTC. Same clock as `turn_buckets.day` and `spend_buckets.day`.
  day               date        not null,

  -- Model round trips. One `Llm::complete` that returned a response is one
  -- call, whether or not it said what it cost.
  calls             bigint      not null default 0,
  -- Of those, the ones that came back with no usage figure. See decision 3.
  -- These contribute NOTHING to the three token columns, so the tokens are a
  -- floor whenever this is non-zero, and a reader can tell.
  calls_unmetered   bigint      not null default 0,

  -- Fresh input, billed at full rate. Cache WRITES are inside this number
  -- already; see decision 2.
  input_tokens      bigint      not null default 0,
  output_tokens     bigint      not null default 0,
  -- Input served from the prefix cache, billed at a fraction of fresh input.
  -- Its own column because folding it into `input_tokens` over-states the cost
  -- of every long conversation, which is the same reason `Usage` splits it.
  cache_read_tokens bigint      not null default 0,

  updated_at        timestamptz not null default now(),

  primary key (tenant_id, employee_id, day),

  -- Last lines of defence. Application arithmetic can be wrong; a negative
  -- count would mean something handed tokens back, and there is no verb that
  -- does. `calls_unmetered <= calls` is the one that keeps the honest reading
  -- honest: unmetered calls are a subset of calls, never a separate population.
  constraint model_usage_daily_nonnegative check (
    calls >= 0 and calls_unmetered >= 0 and input_tokens >= 0
    and output_tokens >= 0 and cache_read_tokens >= 0),
  constraint model_usage_daily_unmetered_subset check (calls_unmetered <= calls)
);

-- ponytail: no index beyond the primary key. Every read is scoped to one tenant
-- by RLS and the PK leads with `tenant_id`, so a window query over one tenant's
-- days is an index scan on that prefix. Add `(tenant_id, day)` the day a tenant
-- has enough employees for the day filter to matter; the SQL does not change.

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, or the owning role walks straight past the
-- policy — and the owning role is what migrations and the outbox poller
-- connect as. `with check` as well as `using`, so a tenant cannot file a row
-- wearing somebody else's id: usage attributed to another tenant's employee
-- would be a way to put a bill on their ledger.

alter table model_usage_daily enable row level security;
alter table model_usage_daily force row level security;
drop policy if exists tenant_isolation on model_usage_daily;
create policy tenant_isolation on model_usage_daily
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- INSERT and UPDATE, because the upsert needs both; no DELETE, for the same
-- reason `turn_buckets` has none. This is the record of what was spent, and a
-- consumption ledger you can delete rows from is not one. There is no HTTP verb
-- that writes this table at all — `GET /v1/usage` is the whole surface — so the
-- only writer is the turn itself, in the transaction that commits the turn.
-- Tenant deletion still cascades, because that runs as the owning role.
grant select, insert, update on model_usage_daily to app_role;
revoke delete on model_usage_daily from app_role;

-- ---------------------------------------------------------------------------
-- WHY THERE IS NO PRICE, AND NO COST COLUMN
-- ---------------------------------------------------------------------------
--
-- A price per million tokens per model is a fact with a source and a date, and
-- it changes. Three things follow, and together they say: not here, not yet.
--
-- a. A PRICE TABLE IN A REPOSITORY IS STALE THE DAY AFTER IT IS WRITTEN. Nobody
--    is paged when a provider reprices, so the number rots silently and the
--    euro figure keeps being quoted. A wrong cost is worse than a missing one,
--    because a missing one asks a question and a wrong one answers it.
--
-- b. THE REAL PRICE IS NOT A FUNCTION OF THIS TABLE ANYWAY. It depends on the
--    contract, the tier, committed-use discounts, and batch versus interactive
--    — none of which is in this schema and none of which the provider response
--    carries. Multiplying tokens by a list price would produce a number that is
--    confidently wrong for every tenant on a negotiated rate.
--
-- c. A COST FIGURE NOBODY CAN TRACE IS WORSE THAN A MISSING ONE, and this table
--    is exactly what makes the traceable version possible later: the tokens are
--    a measurement, the price is an input, and whoever multiplies them can say
--    where the multiplier came from and when they read it. That belongs with
--    the rate card — in billing configuration with an effective date and an
--    owner — not in a migration.
--
-- `0022_autonomy.sql` reached the same conclusion for the same reason and left
-- itself no `cost_minor` column. This file leaves none either. If a later
-- change adds one, the price it uses must carry its source URL and the date it
-- was read, and the documentation must name who is responsible for updating it
-- — and that commit is adding an estimate to a schema of measurements, which is
-- a thing to say out loud in the commit message.
