-- 0006_policy: policy gets a home in the database instead of a redeploy.
--
-- Until now `PolicyBook` was a struct handed to the gate at construction: the
-- limits an AI employee operates under were invisible to an operator and could
-- only be changed by shipping a new binary. This migration stores them.
--
-- Three decisions worth stating, because each of them is a bug that did not
-- happen:
--
-- 1. TYPED COLUMNS, NOT A JSONB BLOB. `max_per_transaction_minor bigint` is
--    either present and a number or the row does not go in. A jsonb blob makes
--    `{"max_per_txn": 100}` (note the typo) a policy with *no* transaction cap,
--    and "no cap" is the widest possible reading of a spending limit. A typo
--    must fail loudly at write time, not silently widen a limit at read time.
--
-- 2. LAYERS ARE ROWS, INTERSECTED AT READ TIME. platform / tenant / role /
--    employee. The loader in `store::policy` takes the *minimum* of every
--    numeric cap and the *intersection* of every allowlist, so a tenant row
--    that names a bigger number than the platform row does not get a bigger
--    number — it gets the platform's. The database does not need to enforce
--    that, because there is no read path that skips the intersection.
--
-- 3. THE PLATFORM LAYER IS NOT A TENANT'S TO WRITE. Its rows carry
--    `tenant_id IS NULL`. The RLS policy below lets every tenant *read* them
--    (the loader needs the ceiling) but the WITH CHECK clause compares against
--    `app.tenant_id`, and `NULL = <uuid>` is never true, so no tenant
--    transaction can insert or update a platform row. Only
--    `Db::admin_tx_bypassing_rls` can, which is exactly the operator path.
--
-- Versions exist so a policy change is auditable and reversible: layers hang
-- off a version, one version per scope is active, and rollback is flipping the
-- pointer back. Nothing is ever edited in place, and nothing is deleted.

-- ---------------------------------------------------------------------------
-- policy_versions
-- ---------------------------------------------------------------------------

create table if not exists policy_versions (
  id          uuid        primary key,
  -- NULL means the platform-wide version. Everything else belongs to a tenant.
  tenant_id   uuid        references tenants (id) on delete cascade,
  label       text        not null,
  author      text        not null default 'system',
  note        text,
  active      boolean     not null default false,
  created_at  timestamptz not null default now(),
  -- Target for the composite FK from policy_layers below.
  constraint policy_versions_id_tenant_key unique (id, tenant_id)
);

-- Exactly one active version per scope. The coalesce is what makes it bind for
-- the platform scope too: a plain unique index treats every NULL as distinct,
-- which would allow two active platform versions and a coin-flip for which
-- ceiling applies.
create unique index if not exists policy_versions_one_active_idx
  on policy_versions (coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
  where active;

create index if not exists policy_versions_history_idx
  on policy_versions (tenant_id, created_at desc);

-- ---------------------------------------------------------------------------
-- policy_layers
-- ---------------------------------------------------------------------------

create table if not exists policy_layers (
  id                         uuid        primary key,
  version_id                 uuid        not null references policy_versions (id) on delete cascade,
  -- NULL only for the platform layer; see policy_layers_platform_is_global.
  tenant_id                  uuid        references tenants (id) on delete cascade,
  layer                      text        not null,
  -- The scope this layer applies to: a role name, or an employee. Exactly one
  -- is set, and only for the matching layer.
  role_name                  text,
  employee_id                uuid        references employees (id) on delete cascade,

  -- Spend: four columns, all or nothing. No row means this layer permits no
  -- spending at all, which is also what an absent `spend` means in the domain.
  spend_currency             text,
  max_per_transaction_minor  bigint,
  max_per_day_minor          bigint,
  approval_above_minor       bigint,

  -- Allowlists. Arrays of scalars, not jsonb: every element is validated by the
  -- domain parser on load, and a malformed element fails the load rather than
  -- being skipped.
  allowed_channels           text[]      not null default '{}',
  allowed_calling_codes      integer[]   not null default '{}',
  allowed_domains            text[]      not null default '{}',
  -- Unioned across layers on load, never intersected: a lower layer can always
  -- add a block, never remove one.
  denied_domains             text[]      not null default '{}',
  allowed_mcp_tools          text[]      not null default '{}',
  allowed_a2a_peers          text[]      not null default '{}',

  max_new_contacts_per_day   integer     not null default 0,
  allow_file_upload          boolean     not null default false,
  allow_credential_change    boolean     not null default false,
  allow_data_delete          boolean     not null default false,
  created_at                 timestamptz not null default now(),

  constraint policy_layers_layer
    check (layer in ('platform', 'tenant', 'role', 'employee')),

  -- The platform layer is global; every other layer belongs to a tenant.
  constraint policy_layers_platform_is_global
    check ((layer = 'platform') = (tenant_id is null)),

  -- A scope id on the wrong layer would be a layer that never matches anything
  -- and therefore silently contributes nothing.
  constraint policy_layers_scope
    check (
      case layer
        when 'role'     then role_name is not null and employee_id is null
        when 'employee' then employee_id is not null and role_name is null
        else                 role_name is null and employee_id is null
      end
    ),

  -- A layer belongs to a version of its own scope: a tenant cannot hang its
  -- limits off the platform version. MATCH SIMPLE, so the platform layer's NULL
  -- tenant_id skips the check rather than needing a NULL row to point at.
  constraint policy_layers_version_scope
    foreign key (version_id, tenant_id)
    references policy_versions (id, tenant_id) on delete cascade,

  constraint policy_layers_spend_all_or_nothing
    check (num_nonnulls(spend_currency, max_per_transaction_minor,
                        max_per_day_minor, approval_above_minor) in (0, 4)),

  -- `Money` is a strictly positive u64. Zero or negative here would be a row the
  -- loader cannot turn into a domain type, so it never gets written.
  constraint policy_layers_spend_positive
    check (coalesce(max_per_transaction_minor, 1) > 0
       and coalesce(max_per_day_minor, 1) > 0
       and coalesce(approval_above_minor, 1) > 0),

  constraint policy_layers_contacts_nonneg
    check (max_new_contacts_per_day >= 0)

  -- Deliberately NOT constrained here: approval_above <= max_per_transaction <=
  -- max_per_day. That inequality is `SpendLimits::try_new` in the domain, and it
  -- is checked on every load. Restating it in SQL would give the rule two homes
  -- that can drift apart, and the SQL copy is the one nobody updates.
);

-- One row per scope per version.  NULLS NOT DISTINCT so two platform rows in
-- one version (both scope columns NULL) collide instead of both being loaded.
create unique index if not exists policy_layers_scope_key
  on policy_layers (version_id, layer, role_name, employee_id) nulls not distinct;

create index if not exists policy_layers_version_idx
  on policy_layers (version_id);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core with one addition
-- ---------------------------------------------------------------------------
--
-- USING allows reading the platform rows (tenant_id IS NULL); WITH CHECK does
-- not, so those rows are read-only to every tenant. That asymmetry is the whole
-- "a tenant cannot widen a platform limit" story at the storage layer, and the
-- intersection in the loader is the same story at the read layer.

do $$
declare
  t text;
begin
  foreach t in array array['policy_versions', 'policy_layers']
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format(
      'create policy tenant_isolation on %I'
      ' using (tenant_id is null'
      '        or tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)'
      ' with check (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );
  end loop;
end
$$;

-- No DELETE: policy history is an audit trail. Superseding a version means
-- writing a new one and activating it; tenant deletion still cascades, because
-- that runs as the owning role.
grant select, insert, update on policy_versions, policy_layers to app_role;
revoke delete on policy_versions, policy_layers from app_role;
