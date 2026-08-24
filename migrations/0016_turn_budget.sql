-- 0016_turn_budget: a ceiling on how often an employee may act at all.
--
-- Every limit before this one is on MONEY or on tool calls WITHIN one turn.
-- `spend_caps` bounds what a payment may be; `Budgets::max_tool_calls` bounds
-- one turn's tool use. Neither is a bound on turns, because until now a turn
-- only happened when a human or a counterparty sent something, and the arrival
-- of a message was the throttle.
--
-- An initiative loop removes that throttle. An employee that wakes on a
-- cadence, thinks, reads and writes without ever proposing a payment trips no
-- existing limit at all while consuming model tokens continuously. This is the
-- bill nobody sees coming, and it is a safety property rather than an
-- optimisation: the ceiling has to exist before autonomous waking is turned on.
--
-- Two decisions, each of them a bug that does not happen:
--
-- 1. THE LIMIT IS A POLICY LAYER COLUMN, NOT A TABLE OF ITS OWN. It goes on
--    `policy_layers` next to `max_new_contacts_per_day`, so it is intersected
--    by the same `EffectivePolicy::try_new` as every other cap — the minimum of
--    platform / tenant / role / employee. A team plugs in at the `role` layer
--    exactly as 0012_org describes and can therefore only ever TIGHTEN it. A
--    separate table would have needed a second intersection, and a second
--    intersection is how a widening bug gets in.
--
-- 2. THE TURN IS RESERVED, NOT COUNTED AFTERWARDS. Same discipline as
--    0003_spend, and the reason is sharper here. The model call is at the TOP
--    of a turn, so it is already paid for by the time anything can crash. A
--    counter incremented on completion means a turn that dies after the model
--    call is free, and a crash-looping employee bills forever under a budget
--    that never advances. Reserving first costs a slot for a turn that never
--    finished — the employee runs out early and stops, visibly — which is the
--    side of the trade that caps the bill.
--
--    There is deliberately NO release verb. `spend` has one because a payment
--    can fail at the provider and the money demonstrably did not move; a turn
--    that started has already spent its tokens, so handing the slot back would
--    be handing back something that was really consumed. It is also the exact
--    path a crash loop would ride: fail late, release, retry, forever.
--
-- WHICH DAY. `day` is a UTC date, from the same `now.date_naive()` the spend
-- ledger keys on. This system is multi-tenant with counterparties in several
-- timezones and there is no `tenants.timezone` column anywhere in the schema,
-- so a local-midnight rollover would have to invent one — and then the turn day
-- and the spend day would roll at different instants for the same employee,
-- which makes "what did it consume today" a question with two answers. One
-- clock, UTC, shared with the money. The cost is that an employee whose
-- operators are in UTC+8 gets its fresh allowance mid-morning rather than at
-- breakfast; the fix, if anyone ever asks, is a tenant timezone applied to BOTH
-- ledgers at once, not to this one.

-- ---------------------------------------------------------------------------
-- The limit, on the layer stack that already exists
-- ---------------------------------------------------------------------------
--
-- Default 0: an employee whose policy nobody wrote may not run a turn on its
-- own initiative. Deny by default, same as every other column here.

alter table policy_layers
  add column if not exists max_turns_per_day integer not null default 0;

do $$
begin
  alter table policy_layers
    add constraint policy_layers_turns_nonneg check (max_turns_per_day >= 0);
exception
  when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- turn_buckets: the contended row. One per employee per UTC day.
-- ---------------------------------------------------------------------------
--
-- Locked with INSERT ... ON CONFLICT DO UPDATE ... RETURNING inside the
-- caller's transaction, exactly like `spend_buckets`: creates the row if
-- missing, takes a row-level write lock either way, and returns the count as of
-- that lock. `DO NOTHING` would return no row to a concurrent inserter and take
-- no lock, which is precisely the race — two wakers both reading "9 turns
-- taken" against a cap of 10 and both proceeding.
--
-- No currency dimension, unlike the spend tables: a turn is not denominated in
-- anything. No `alerted_at` column either, and that is deliberate — the moment
-- an employee becomes exhausted is the single reservation that takes the last
-- slot, and that reservation commits. Exactly-once falls out of the row lock
-- instead of out of a flag that a refusal's rollback would throw away.

create table if not exists turn_buckets (
  tenant_id    uuid        not null references tenants (id) on delete cascade,
  employee_id  uuid        not null references employees (id) on delete cascade,
  -- UTC. See "WHICH DAY" in the header.
  day          date        not null,
  turns_taken  integer     not null default 0,
  updated_at   timestamptz not null default now(),
  primary key (tenant_id, employee_id, day),
  -- Last line of defence. Application arithmetic can be wrong; a negative count
  -- would mean something handed a turn back, and there is no verb that does.
  constraint turn_buckets_nonnegative check (turns_taken >= 0)
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------

alter table turn_buckets enable row level security;
alter table turn_buckets force row level security;
drop policy if exists tenant_isolation on turn_buckets;
create policy tenant_isolation on turn_buckets
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- No DELETE: this is the record of what an employee consumed, and a consumption
-- ledger you can delete rows from is not one. Tenant deletion still cascades,
-- because that runs as the owning role.
grant select, insert, update on turn_buckets to app_role;
revoke delete on turn_buckets from app_role;
