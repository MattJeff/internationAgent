-- 0055_outreach_budget: the third daily ceiling gets a ledger.
--
-- This workspace holds three daily budgets. Two of them are reserved under a
-- row lock and one of them was not:
--
--   turns   0016_turn_budget  turn_buckets   store::turns::reserve
--   money   0003_spend        spend_buckets  store::spend::reserve
--   people  --- nothing ---   ------------   ------------------
--
-- `max_new_contacts_per_day` — how many strangers an employee may reach in one
-- day — was enforced by counting, never by reserving, and it is the one of the
-- three a company answers for in front of a supervisory authority. Exceeding it
-- is not an overspend an operator notices on an invoice; it is a complaint.
--
-- WHAT WAS ACTUALLY BROKEN, both halves reproduced before this file was written
--
-- 1. `app::gate::PolicyGate::contacts` derives the day's count from an
--    UNLOCKED aggregate over `audit_log` (distinct `payload->>'counterparty'`
--    whose `min(occurred_at)` falls today), and the matching "write" is
--    `audit::append` — an INSERT into an append-only log with no unique index
--    and no counter row. Two decisions read `1 of 2`, both are allowed, both
--    append: three strangers on a ceiling of two, every time.
--
-- 2. `routes::queue::export` never reaches the gate on the file path. Its
--    counter is `revenue::contacted_since`, a `count(*)` over
--    `contacts.last_contacted_at`, and it is read unlocked too. The selection
--    underneath it takes `FOR UPDATE OF c SKIP LOCKED`, which is correct and is
--    exactly what defeats the budget: two exports get DISJOINT prospects, so
--    neither ever blocks, both read `0 contacted today`, and both take the whole
--    day's allowance. Four strangers on a ceiling of two.
--
-- Those are two different counters, not one, and neither of them can be locked:
-- an aggregate over an append-only log has no row to lock, and a `count(*)` over
-- `contacts` has none either. A counter row is the only shape that serialises
-- them, and this table is that row.
--
-- WHY IT DOES NOT REPLACE EITHER COUNTER
--
-- It is added BESIDE them and both keep running. A bucket created at noon
-- starts at zero while the trail already holds this morning's strangers, so a
-- bucket that replaced the aggregate would hand a fresh day's allowance to every
-- tenant on the afternoon this migration is applied — a ceiling that WIDENS,
-- which is the one thing a ceiling may never do. Kept side by side, the day's
-- refusal is the strictest of the two, the deployment day is safe, and the old
-- decision is untouched: sequentially the bucket and the aggregate agree exactly
-- (`store::outreach`'s suite proves it against a real database), and where they
-- differ it is the bucket refusing something the aggregate would have allowed to
-- a concurrent twin.
--
-- The dividend is not only the race. The two counters above never saw each
-- other, and `app::queue::push` says so in its own docs: an export marks forty
-- people and the gate's count stays at zero. They share this bucket now, so one
-- ceiling covers both paths instead of one ceiling covering each.
--
-- THE KEY, AND WHY IT IS THE EMPLOYEE
--
-- `(tenant_id, employee_id, day)`, identical to `turn_buckets` and to
-- `spend_buckets` minus the currency. The limit is read by
-- `store::policy::load(tx, employee_id)` — platform ∧ tenant ∧ role ∧ employee —
-- so it is per employee, and a bucket coarser than its limit refuses an employee
-- for what a colleague did. `contacted_since` is tenant-wide and stays that way;
-- it is the coarser of the two and still truncates first, so a per-employee
-- bucket cannot widen the tenant's day.
--
-- WHICH DAY. UTC, `now.date_naive()`, for the reason 0016 already gives at
-- length: there is no `tenants.timezone` column, and an employee whose turn day
-- and contact day roll at different instants has two todays.
--
-- NO RELEASE VERB, deliberately, and the argument is 0016's rather than 0003's.
-- Money has a release because a payment can fail at the provider and the money
-- demonstrably did not move. A reserved contact is a decision to approach a
-- stranger that was made, ruled on, and written to `audit_log` — the old counter
-- charges it whether or not the send succeeded, so a release here would hand
-- back a slot the trail still shows as spent, and it is the exact path a retry
-- loop would ride to mail one stranger repeatedly. `app::queue::push` already
-- chose this direction for this vertical: marked-and-not-written-to is the
-- survivable error, written-to-twice is not.

create table if not exists outreach_buckets (
  tenant_id       uuid        not null references tenants (id) on delete cascade,
  employee_id     uuid        not null references employees (id) on delete cascade,
  -- UTC. See "WHICH DAY" above.
  day             date        not null,
  contacts_taken  integer     not null default 0,
  updated_at      timestamptz not null default now(),
  primary key (tenant_id, employee_id, day),
  -- Last line of defence, same as `turn_buckets`: a negative count would mean
  -- something handed a contact back, and there is no verb that does.
  constraint outreach_buckets_nonnegative check (contacts_taken >= 0)
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------

alter table outreach_buckets enable row level security;
alter table outreach_buckets force row level security;
drop policy if exists tenant_isolation on outreach_buckets;
create policy tenant_isolation on outreach_buckets
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- No DELETE, exactly as `turn_buckets`: this is the record of whom an employee
-- was allowed to approach, and a consumption ledger you can delete rows from is
-- not one. Tenant deletion still cascades, because that runs as the owner.
grant select, insert, update on outreach_buckets to app_role;
revoke delete on outreach_buckets from app_role;
