-- 0020_initiative: when an employee is allowed to act on its own.
--
-- Until now a turn happened only because something arrived — an email, an A2A
-- request, a webhook — and that was the throttle, and a good one: no traffic, no
-- cost. `employee_initiative` is the other half: one row per employee saying how
-- often it wakes up, when it is next due, and what happened the last time it
-- woke.
--
-- It is the schedule and nothing else. **What** the employee does when it wakes
-- is its charter (`0018_charter.sql`, `agentos_app::vertical::Charter`), and the
-- two are deliberately separate tables: an employee can be chartered and not yet
-- scheduled, which is every employee that answers its mail and starts nothing.
--
-- The reasoning behind the schedule itself lives in
-- `crates/domain/src/initiative.rs` and is not repeated here. Three decisions
-- are this file's.
--
-- 1. THE DEADLINE IS STORED, NOT DERIVED. `last_acted_at + cadence <= now()` is
--    the obvious schema and it is wrong in a way that only shows up in
--    production: an employee suspended for a week comes back owing a week of
--    turns, and every employee created by one import is due in the same instant
--    forever. `next_at` is written from the moment the turn is TAKEN UP — by the
--    same statement that takes it up — so a missed slot is missed rather than
--    queued, and a crashed turn costs one slot instead of spinning.
--
-- 2. THE FLOOR AND THE CEILING ARE A CHECK, not only a Rust constructor.
--    `Cadence::every` refuses anything outside [300s, 30d] and the type has no
--    `Deserialize`, so the invariant cannot be lost on the way in through the
--    API. A row is also reachable by psql, though, and a one-second cadence
--    costs money every second until somebody notices. The two numbers below are
--    `MIN_INTERVAL` and `MAX_INTERVAL` written out; the store test
--    `the_row_check_agrees_with_the_domain_floor_and_ceiling` fails if they ever
--    drift apart.
--
-- 3. `last_outcome` IS A CODE AND `last_detail` IS OURS. The poller records what
--    it decided about this employee — `turn`, `clarify`, `no_charter`, `error` —
--    so an operator reading the row can tell "working" from "waiting on me"
--    without reading logs. Neither column ever holds a counterparty's text:
--    `last_detail` is a question this codebase authored or an error this
--    codebase defined. Same rule as `outbox_events.last_error`.
--
-- Replayable: IF NOT EXISTS throughout.

-- ---------------------------------------------------------------------------
-- employee_initiative
-- ---------------------------------------------------------------------------

create table if not exists employee_initiative (
  -- One schedule per employee, so the employee id IS the key. A second row for
  -- the same employee would be a second poller waking it up. Same shape as
  -- `employee_charters`, and for the same reason.
  employee_id     uuid        primary key references employees (id) on delete cascade,
  tenant_id       uuid        not null references tenants (id) on delete cascade,
  -- The cadence, in seconds. `bigint` because 30 days is 2_592_000 and an
  -- `integer` column that only just fits is a column somebody widens later.
  interval_secs   bigint      not null,
  -- The next instant this employee may be taken up. Written by the claim.
  next_at         timestamptz not null,

  -- Bookkeeping: everything an operator needs to answer "is it working?"
  last_claimed_at timestamptz,
  -- Claims, not turns: incremented by the claim itself, so a worker killed
  -- mid-turn still shows up here. The gap between this and the `turn` outcomes
  -- is how often something is dying.
  claims          bigint      not null default 0,
  last_outcome    text,
  last_detail     text,

  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),

  -- See decision 2. 300 = MIN_INTERVAL, 2592000 = MAX_INTERVAL.
  constraint employee_initiative_interval_ck
    check (interval_secs >= 300 and interval_secs <= 2592000)
);

-- The claim's ORDER BY, which is also its WHERE. Cross-tenant on purpose: the
-- poller reads every tenant's rows, so a per-tenant index would not serve it.
create index if not exists employee_initiative_due_idx
  on employee_initiative (next_at);

-- ---------------------------------------------------------------------------
-- The reschedule rule
-- ---------------------------------------------------------------------------
--
-- One definition, because there are two callers: the upsert that schedules an
-- employee's first turn names the interval as a bind parameter, and the claim
-- names it as a column. Written out twice in Rust it would be two copies of a
-- formula, and two copies drift; built by string interpolation it would be
-- dynamic SQL, which sqlx refuses on purpose. So it lives here, next to the
-- CHECK that guards the same numbers.
--
-- In the domain's terms this is `Cadence::advance(from_ts, offset)` with
-- `offset` drawn uniformly from `[0, interval * 0.1)`. The domain deliberately
-- makes the offset an argument rather than reaching for a random number
-- generator — a pure function that draws entropy cannot be tested by stating
-- what it returns — so the caller draws it, and this is the caller. Ten percent
-- of an hourly cadence is six minutes of spread: enough to unstick a batch of
-- employees created by one import, small enough that nobody reading `next_at`
-- wonders whether the cadence is what they set.
--
-- VOLATILE, which is the default and is stated anyway: `random()` must be
-- re-evaluated per row, and a STABLE marking here would give every employee in
-- one claim the same jitter, which is precisely the bug being avoided.

create or replace function employee_initiative_next_at(
  from_ts       timestamptz,
  interval_secs bigint
) returns timestamptz
language sql volatile
as $$
  select from_ts
       + interval '1 second' * interval_secs::double precision * (1.0 + random() * 0.1)
$$;

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core
-- ---------------------------------------------------------------------------
--
-- The poller bypasses this — it runs on `admin_tx_bypassing_rls`, as the outbox
-- poller does, because draining every tenant's schedule is its entire job. That
-- is the documented exception and not a hole: the policy still binds every
-- connection the API serves a request on, which is every connection that takes
-- an operator's word for anything.
--
-- `with check` as well as `using`, so a tenant cannot INSERT a row wearing
-- another tenant's id — a schedule filed against somebody else's employee would
-- be a way to make their employee act.

alter table employee_initiative enable row level security;
alter table employee_initiative force row level security;
drop policy if exists tenant_isolation on employee_initiative;
create policy tenant_isolation on employee_initiative
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- All four, like the other per-employee side tables (`employee_resources`,
-- `employee_charters`): delete so that dropping an employee cascades through
-- this table as the app role rather than failing on a privilege.

grant select, insert, update, delete on employee_initiative to app_role;
