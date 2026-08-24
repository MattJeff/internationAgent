-- 0012_org: the layer between a tenant and an employee — teams.
--
-- One company runs several teams of AI employees at once: purchasing sourcing
-- suppliers, sales bringing in accounts, later regulatory-watch and support.
-- They share a tenant, a database and a runtime. Until now there was nothing
-- between `tenants` and `employees`, so "the sales team may not spend" and "the
-- purchasing team may not email prospects" had nowhere to live.
--
-- Three decisions, each of them a bug that does not happen:
--
-- 1. THE TEAM DOES NOT GET A POLICY MECHANISM OF ITS OWN. `policy_layers`
--    already intersects platform ∧ tenant ∧ role ∧ employee, and the `role`
--    layer is the seam a team plugs into. `team_policy` below is a *pointer*:
--    it names which `role_name` a team's limits are written under. There is no
--    second set of limit columns, because two places to write a limit is one
--    place to forget to tighten. In particular a team with no matching
--    `policy_layers` row is an ABSENT role layer, which `store::policy::load`
--    resolves by inheriting the tenant's — not by `PolicyLimits::default()`,
--    which grants nothing.
--
-- 2. AN EMPLOYEE IS ON AT MOST ONE TEAM. That is the primary key of
--    `team_memberships`, not a convention. Two teams would mean two role
--    layers, and the loader's "at most one row per layer" would silently pick
--    one of them — a coin-flip between the purchasing budget and the sales
--    budget. The key makes that unrepresentable, and it is also what lets the
--    loader find an employee's team with a single index lookup inside the
--    statement that reads the policy, rather than a second round trip on the
--    hot path of every gate decision.
--
-- 3. THE TEAM BUDGET IS RESERVED, NOT CHECKED. Same discipline as 0003_spend,
--    for the same reason and it is worse here: N employees on one team can each
--    be under their own per-employee cap and jointly blow the team's budget,
--    and every individual decision looks correct in the logs. So
--    `team_spend_buckets` holds ONE row per (tenant, team, day, currency) and
--    every reservation locks it in the caller's transaction — the same
--    transaction that writes the payment intent.
--
-- `sections` are sub-units of a team (EMEA / APAC, tier-1 / tier-2). They carry
-- no policy and no budget on purpose: a section is an org chart, and the moment
-- it gets limits of its own it becomes a fifth policy layer nobody asked for.

-- ---------------------------------------------------------------------------
-- teams
-- ---------------------------------------------------------------------------

create table if not exists teams (
  id          uuid        primary key,
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  slug        text        not null,
  name        text        not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  constraint teams_tenant_slug_key unique (tenant_id, slug),
  -- Target for the composite FKs below, so a child row cannot point at another
  -- tenant's team even if someone forgets the tenant predicate.
  constraint teams_id_tenant_key unique (id, tenant_id)
);

create index if not exists teams_tenant_idx on teams (tenant_id);

-- ---------------------------------------------------------------------------
-- sections
-- ---------------------------------------------------------------------------

create table if not exists sections (
  id          uuid        primary key,
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  team_id     uuid        not null,
  slug        text        not null,
  name        text        not null,
  created_at  timestamptz not null default now(),
  constraint sections_team_slug_key unique (team_id, slug),
  -- Target for team_memberships' section FK.
  constraint sections_id_team_key unique (id, team_id),
  constraint sections_team_fk
    foreign key (team_id, tenant_id) references teams (id, tenant_id) on delete cascade
);

create index if not exists sections_team_idx on sections (tenant_id, team_id);

-- ---------------------------------------------------------------------------
-- team_memberships: one row per employee, and only one
-- ---------------------------------------------------------------------------

create table if not exists team_memberships (
  tenant_id    uuid        not null references tenants (id) on delete cascade,
  employee_id  uuid        not null references employees (id) on delete cascade,
  team_id      uuid        not null,
  -- Optional, and constrained to a section OF THIS TEAM: a membership pointing
  -- at another team's section would be an org chart that reads wrong and
  -- queries wrong. MATCH SIMPLE, so a NULL section skips the check.
  section_id   uuid,
  created_at   timestamptz not null default now(),
  -- See decision 2 in the header. This is also the index the policy loader's
  -- team lookup rides on.
  primary key (tenant_id, employee_id),
  constraint team_memberships_team_fk
    foreign key (team_id, tenant_id) references teams (id, tenant_id) on delete cascade,
  constraint team_memberships_section_fk
    foreign key (section_id, team_id) references sections (id, team_id)
);

-- "who is on this team", the roster query.
create index if not exists team_memberships_team_idx
  on team_memberships (tenant_id, team_id);

-- ---------------------------------------------------------------------------
-- team_policy: which role layer carries this team's limits
-- ---------------------------------------------------------------------------
--
-- Not a copy of the limits. A pointer at the `role` layer in `policy_layers`,
-- which is where `store::policy::load` already reads them and already
-- intersects them with the tenant's — so a team row naming a *wider* number
-- than the tenant's cannot widen anything: the loader takes the minimum.
--
-- Indirect rather than just reusing `teams.slug` so two teams can share one set
-- of limits (purchasing-eu and purchasing-us both under 'purchasing') and so a
-- team can be renamed without silently losing its policy.
--
-- No FK to policy_layers: `role_name` is not unique there (one row per version,
-- and history is kept), and a team may legitimately point at a role nobody has
-- written limits for yet — that is an absent layer, which inherits the tenant's.

create table if not exists team_policy (
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  team_id     uuid        not null,
  role_name   text        not null,
  updated_at  timestamptz not null default now(),
  primary key (tenant_id, team_id),
  constraint team_policy_team_fk
    foreign key (team_id, tenant_id) references teams (id, tenant_id) on delete cascade
);

-- ---------------------------------------------------------------------------
-- team_budgets: configuration. Absence means the team may not spend.
-- ---------------------------------------------------------------------------
--
-- A stored table rather than a parameter to the reservation, for the reason
-- spelled out in 0003_spend: a budget that travels in from the caller is a
-- budget the caller can inflate.

create table if not exists team_budgets (
  tenant_id          uuid        not null references tenants (id) on delete cascade,
  team_id            uuid        not null,
  currency           text        not null,
  daily_total_minor  bigint      not null,
  updated_at         timestamptz not null default now(),
  primary key (tenant_id, team_id, currency),
  constraint team_budgets_positive check (daily_total_minor > 0),
  constraint team_budgets_team_fk
    foreign key (team_id, tenant_id) references teams (id, tenant_id) on delete cascade
);

-- ---------------------------------------------------------------------------
-- team_spend_buckets: the contended row. One per team per day per currency.
-- ---------------------------------------------------------------------------
--
-- The whole point of this unit. Locked with INSERT ... ON CONFLICT DO UPDATE
-- ... RETURNING inside the caller's transaction, exactly like spend_buckets:
-- creates the row if missing, takes a row-level write lock either way, and
-- returns the running total as of that lock.
--
-- No txn_count here: how MANY payments an employee may make is already capped
-- per employee in 0003_spend, and a second count cap with a different scope is
-- a limit whose refusal message nobody can act on.

create table if not exists team_spend_buckets (
  tenant_id       uuid        not null references tenants (id) on delete cascade,
  team_id         uuid        not null,
  day             date        not null,
  currency        text        not null,
  reserved_minor  bigint      not null default 0,
  updated_at      timestamptz not null default now(),
  -- Also the index for "what has this team spent today".
  primary key (tenant_id, team_id, day, currency),
  -- Last line of defence: a negative bucket means a release ran twice, and this
  -- turns silent free money into a failed transaction.
  constraint team_spend_buckets_nonnegative check (reserved_minor >= 0),
  constraint team_spend_buckets_team_fk
    foreign key (team_id, tenant_id) references teams (id, tenant_id) on delete cascade
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array['teams', 'sections', 'team_memberships',
                           'team_policy', 'team_budgets', 'team_spend_buckets']
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

-- Org charts change: teams are dissolved, sections merged, employees moved. The
-- money tables are a ledger and a ledger you can delete rows from is not one.
grant select, insert, update, delete on teams, sections, team_memberships, team_policy
  to app_role;
grant select, insert, update on team_budgets, team_spend_buckets to app_role;
revoke delete on team_budgets, team_spend_buckets from app_role;
