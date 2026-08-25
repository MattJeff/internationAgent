-- 0018_charter: which role an employee wears, and the objective it was hired
-- for.
--
-- The two role packs (`crates/app/src/rolepack.rs`,
-- `crates/app/src/rolepack_sales.rs`) and the two verticals behind them were
-- complete and unreachable, because nothing in the database said *which* role an
-- employee has. A turn loaded an employee, wrote a generic system prompt, and
-- offered the model three tools. This table is the missing sentence: "this
-- employee is an international buyer, and here is what it is buying."
--
-- `crates/app/src/vertical.rs` reads it, calls `RolePack::plan` on it, and the
-- plan is what decides which vertical operation runs.
--
-- Three decisions.
--
-- 1. ONE CHARTER PER EMPLOYEE, so `employee_id` is the primary key rather than a
--    row among many. An employee wearing two roles has two briefings, two
--    action allowlists and two plans, and every question about it ("may it
--    pay?") gets two answers. Re-assigning is an UPDATE.
--
-- 2. `role` IS THE ROLE PACK'S OWN NAME, checked against the list of packs that
--    exist. `RolePack::name()` returns these exact strings. A row naming a pack
--    this build does not have is a charter nobody can plan, and the CHECK is
--    what turns that from a runtime `None` into a failed write at the moment
--    somebody typos it.
--
-- 3. `objective` IS jsonb AND IS READ BACK THROUGH THE CONSTRUCTORS.
--    `CountryCode::parse`, `Money::new`, `Segment::code` — the same doors the
--    values came in through. There is deliberately no `#[derive(Deserialize)]`
--    on `Objective` anywhere in the workspace: a derived one would rebuild a
--    country code of "germany" or a zero-minor price straight out of this
--    column, past the parsers that exist to refuse them. The column stores what
--    an operator stated; the invariants are re-established on every read.
--
--    Flat columns were the alternative and they are worse here: the two
--    objectives share no field, so one table would be eleven columns of which
--    six are always null, and the CHECK constraint keeping them coherent per
--    role would be the parser, written in SQL, a second time.
--
-- Nothing a counterparty wrote goes in this table. An objective is the
-- operator's own words about their own business.
--
-- Replayable: IF NOT EXISTS / OR REPLACE throughout.

-- ---------------------------------------------------------------------------
-- employee_charters
-- ---------------------------------------------------------------------------

create table if not exists employee_charters (
  employee_id uuid        primary key references employees (id) on delete cascade,
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  -- `RolePack::name()`. See decision 2.
  role        text        not null,
  -- The operator's objective, as `vertical::Charter` writes it. See decision 3.
  objective   jsonb       not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  constraint employee_charters_role check (role in (
    'international-buyer',
    'sales-development'
  ))
);

-- The scheduler's question is "which of this tenant's employees has a charter",
-- which is a tenant scan, not an employee lookup.
create index if not exists employee_charters_tenant_idx
  on employee_charters (tenant_id, role);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core
-- ---------------------------------------------------------------------------

alter table employee_charters enable row level security;
alter table employee_charters force row level security;
drop policy if exists tenant_isolation on employee_charters;
create policy tenant_isolation on employee_charters
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- Read, write and remove: a charter is operator configuration, not a record of
-- anything that happened. Hiring an employee into a different job is an UPDATE
-- and standing it down is a DELETE, and neither is an audit event this table is
-- the trail for — `audit_log` already is.

grant select, insert, update, delete on employee_charters to app_role;
