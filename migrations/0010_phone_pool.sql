-- 0010_phone_pool: numbers belong to the TENANT, employees are allocated onto
-- them.
--
-- WHY THIS TABLE EXISTS AT ALL. `Step::Phone` buys one number per employee.
-- In France that means one regulatory bundle per employee -- a French address
-- and a proof of address dated within three months, reviewed by a human --
-- so onboarding a hundred employees means a hundred human reviews. That cost
-- is provider-independent; switching vendors does not touch it. Five numbers
-- shared by a hundred employees is five bundles. This schema is what makes the
-- French deployment possible, not what makes it cheaper.
--
-- It is the generalisation of the WhatsApp routing rule already in
-- `app::provisioning` ("one verified company sender, employees routed to it"),
-- from one shared sender to N pooled numbers. Same decisions, one mechanism.
--
-- POOLING IS A STRATEGY, NOT A REPLACEMENT. `capacity = 1` is a dedicated
-- number and is the right answer for a US number, which needs no bundle and is
-- better off with an identity of its own. Same table, same contract, one
-- integer apart.
--
-- THE THREE TABLES
--
--   phone_numbers        what the tenant owns. One row per number the provider
--                        has issued to us.
--   number_allocations   which employee is currently reachable on which number.
--                        Live = `released_at IS NULL`.
--   counterparty_affinity  who a given counterparty has been talking to on a
--                        given number. This is the relationship memory, and it
--                        is the reason inbound routing is a correctness
--                        problem rather than a load-balancing one.
--
-- INBOUND ROUTING, WRITTEN DOWN ONCE SO IT IS NOT DECIDED BY ROW ORDER.
-- A supplier texts a shared number. Two rules, in this order:
--
--   1. Affinity. If that counterparty has spoken to this number before, they
--      reach the same employee they reached last time. Not a nicety: since
--      wave 8 the employee holds trust links, learned expectations and beliefs
--      with provenance about THAT counterparty, and a colleague holds none of
--      them. Re-routing silently discards the accumulated relationship, which
--      is the product.
--   2. First contact. No affinity row: the longest-standing live allocation on
--      that number wins -- `ORDER BY allocated_at, employee_id`, both columns
--      immutable, so the rule is total and stable.
--
-- ARBITRATION IS DECIDED BY THE PRIMARY KEY, NOT BY THE APPLICATION. Two
-- employees both talking to one counterparty on one number is a real
-- ambiguity, so `counterparty_affinity` is keyed (tenant, number,
-- counterparty) and can only hold one employee: the incumbent. Whoever spoke
-- first keeps the counterparty for as long as the row lives; a later writer
-- only moves `last_seen`. A tie cannot exist, so no query has to break one.
--
-- AFFINITY OUTLIVES ALLOCATION, deliberately. There is no foreign key from
-- `counterparty_affinity` to `number_allocations`, and releasing an allocation
-- does not touch affinity. Lena can be moved to a different pooled number and
-- the supplier who has her old number still reaches Lena.

-- ---------------------------------------------------------------------------
-- phone_numbers
-- ---------------------------------------------------------------------------

create table if not exists phone_numbers (
  id            uuid        primary key,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  provider      text        not null,
  -- The provider's own id for the number (Twilio SID, Telnyx id, ...).
  external_id   text        not null,
  e164          text        not null,
  -- Where the number is regulated, in the provider crate's `Region`
  -- vocabulary. Text rather than an enum: the set is the world's, not ours.
  region        text        not null,
  -- Regulatory lifecycle. Only 'active' is allocatable, so a number whose
  -- bundle is still with a human reviewer cannot be handed to an employee.
  state         text        not null default 'pending_regulatory',
  -- How many employees may share this number. 1 is the dedicated-number
  -- strategy; a French pooled number is 10-20.
  capacity      integer     not null default 1,
  -- The regulatory bundle this number hangs off, when the region needs one.
  -- A pooled number is owned by the tenant, so unlike the dedicated flow there
  -- is no `employee_resources.poll_ref` for it to live in.
  bundle_ref    text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint phone_numbers_tenant_e164_key unique (tenant_id, e164),
  constraint phone_numbers_capacity_positive check (capacity > 0),
  constraint phone_numbers_state_check
    check (state in ('pending_regulatory', 'active', 'suspended', 'released')),
  -- Same shape `domain::action::E164` enforces, restated here because the
  -- database is also an entry point (migrations, operators, a future importer).
  constraint phone_numbers_e164_shape check (e164 ~ '^\+[1-9][0-9]{0,14}$')
);

-- Global, not tenant-scoped, and matching
-- `employee_resources_provider_external_id_key` in 0001: the same external
-- resource must never be bound twice, and "twice" includes across tenants.
create unique index if not exists phone_numbers_provider_external_id_key
  on phone_numbers (provider, external_id);

-- The target of the composite foreign key below. Carrying (tenant_id, region)
-- into the referencing key is what stops an allocation from claiming a region
-- or a tenant its number does not have -- the alternative is a trigger, or a
-- reviewer noticing.
create unique index if not exists phone_numbers_tenant_id_region_key
  on phone_numbers (tenant_id, id, region);

create index if not exists phone_numbers_pool_idx
  on phone_numbers (tenant_id, region, e164)
  where state = 'active';

-- ---------------------------------------------------------------------------
-- number_allocations
-- ---------------------------------------------------------------------------
--
-- Kept as history rather than deleted on release: `allocated_at` of the live
-- row is the first-contact tie-break, and the released rows are how you answer
-- "who was on +33... in March" after the fact.

create table if not exists number_allocations (
  id            uuid        primary key,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  number_id     uuid        not null references phone_numbers (id) on delete cascade,
  employee_id   uuid        not null references employees (id) on delete cascade,
  -- Denormalised from phone_numbers so the partial unique index below can be
  -- written at all -- an index cannot reach into another table. The composite
  -- foreign key keeps the copy honest.
  region        text        not null,
  allocated_at  timestamptz not null default now(),
  released_at   timestamptz,
  constraint number_allocations_release_after_allocate
    check (released_at is null or released_at >= allocated_at),
  constraint number_allocations_number_fk
    foreign key (tenant_id, number_id, region)
    references phone_numbers (tenant_id, id, region) on delete cascade
);

-- THE invariant: at most one live allocation per employee per region. In the
-- index, not in Rust -- application-enforced uniqueness loses to a race, and
-- `allocate_atomic` deliberately does its pre-check outside any lock on the
-- employee. Two provisioning workers racing on one employee both pass the
-- check and exactly one insert survives this.
create unique index if not exists number_allocations_live_employee_region_key
  on number_allocations (tenant_id, employee_id, region)
  where released_at is null;

-- The occupancy count `allocate_atomic` runs per candidate number, and the
-- first-contact lookup.
create index if not exists number_allocations_live_number_idx
  on number_allocations (number_id, allocated_at, employee_id)
  where released_at is null;

-- ---------------------------------------------------------------------------
-- counterparty_affinity
-- ---------------------------------------------------------------------------

create table if not exists counterparty_affinity (
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  number_id     uuid        not null references phone_numbers (id) on delete cascade,
  -- The other party, in the same vocabulary as `psyche_episodes.counterparty`
  -- (a supplier code, a normalised E.164, a sending domain). Whatever key the
  -- psyche accumulates against is the key inbound must route on, or the
  -- routing and the memory are about different people.
  counterparty  text        not null,
  employee_id   uuid        not null references employees (id) on delete cascade,
  first_seen    timestamptz not null,
  last_seen     timestamptz not null,
  -- One employee per (number, counterparty). See the header: this key IS the
  -- arbitration rule.
  primary key (tenant_id, number_id, counterparty),
  constraint counterparty_affinity_counterparty_nonempty
    check (length(counterparty) between 1 and 200),
  constraint counterparty_affinity_seen_order check (last_seen >= first_seen)
);

-- "Everyone this employee is the incumbent for", newest first: what a handover
-- reads when an employee is retired.
create index if not exists counterparty_affinity_employee_idx
  on counterparty_affinity (tenant_id, employee_id, last_seen desc);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array[
    'phone_numbers', 'number_allocations', 'counterparty_affinity'
  ]
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format(
      'create policy tenant_isolation on %I'
      ' using (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)'
      ' with check (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );
  end loop;
end
$$;

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

grant select, insert, update, delete on
  phone_numbers, number_allocations, counterparty_affinity
  to app_role;
