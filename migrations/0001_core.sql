-- 0001_core: the whole persistent surface of AgentOS.
--
-- Two rules shape everything below.
--
-- 1. Tenant isolation is a database property, not an application habit. Every
--    tenant-scoped table carries `tenant_id`, has RLS enabled, and has a policy
--    keyed on `current_setting('app.tenant_id', true)`. `Db::tenant_tx` sets
--    that GUC with `SET LOCAL`, so the isolation lives exactly as long as the
--    transaction does.
--
--    THE CATCH, stated loudly because it silently defeats the whole scheme:
--    RLS does not apply to superusers, to roles with BYPASSRLS, or (without
--    FORCE) to the table owner. The migration runs as `postgres`, which owns
--    these tables and is usually a superuser, so a policy alone would protect
--    nothing. We handle it in two places:
--      * here, by creating a plain `app_role` and granting it only the verbs it
--        needs, and by adding FORCE ROW LEVEL SECURITY so ownership is not an
--        escape hatch either;
--      * in `Db::tenant_tx`, which issues `SET LOCAL ROLE app_role` before
--        anything else, so the transaction runs as a role RLS actually binds.
--    `Db::admin_tx_bypassing_rls` deliberately skips that SET ROLE. That is the
--    only path that sees across tenants, and its name says so.
--
--    `app_role` is NOLOGIN by design: it is a hat the connection puts on, not
--    an account. If you deploy with a non-superuser login role, that role must
--    be a member of app_role (`GRANT app_role TO app_login`) for SET ROLE to
--    succeed.
--
-- 2. Primary keys are UUIDv7 minted by the application (`*Id::new_v7(now)`),
--    never by the database. There is no `DEFAULT gen_random_uuid()` anywhere:
--    the id exists in Rust before the row exists in Postgres, which is what
--    lets us build an outbox event and its aggregate in one transaction.
--
-- Everything is written IF NOT EXISTS / DROP-then-CREATE so the file can be
-- replayed against a database that already has some of it.

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------

do $$
begin
  -- Roles are cluster-wide, so this may already exist from another database.
  create role app_role nologin;
exception
  when duplicate_object then null;
end
$$;

grant usage on schema public to app_role;

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------

create table if not exists tenants (
  id          uuid        primary key,
  slug        text        not null unique,
  name        text        not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- employees
-- ---------------------------------------------------------------------------

create table if not exists employees (
  id            uuid        primary key,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  slug          text        not null,
  display_name  text        not null,
  lifecycle     text        not null,
  health        text        not null default 'unknown',
  -- Optimistic locking. Every UPDATE carries `WHERE version = $expected` and
  -- sets `version = version + 1`; zero rows affected is a lost update, which
  -- the store surfaces as StoreError::Conflict.
  version       integer     not null default 0,
  spec          jsonb       not null default '{}'::jsonb,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  -- An employee's slug is its address-local-part: unique per tenant, forever.
  constraint employees_tenant_slug_key unique (tenant_id, slug)
);

create index if not exists employees_tenant_idx on employees (tenant_id);

-- ---------------------------------------------------------------------------
-- employee_resources: one row per provisioning step per employee
-- ---------------------------------------------------------------------------

create table if not exists employee_resources (
  employee_id    uuid        not null references employees (id) on delete cascade,
  step           text        not null,
  tenant_id      uuid        not null references tenants (id) on delete cascade,
  state          text        not null,
  provider       text,
  external_id    text,
  -- Opaque handle for a provider we have to poll rather than be called back by.
  poll_ref       text,
  -- Lease held by whichever worker is currently driving this step.
  lease_owner    uuid,
  lease_until    timestamptz,
  attempt_count  integer     not null default 0,
  last_error     text,
  -- When a `pending_external` step should have resolved; past-due rows get
  -- escalated rather than waited on forever.
  expected_by    timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  primary key (employee_id, step)
);

-- The same external resource must never be bound to two employees. Partial so
-- that steps which have not reached a provider yet (both columns NULL) do not
-- collide with each other.
create unique index if not exists employee_resources_provider_external_id_key
  on employee_resources (provider, external_id)
  where provider is not null and external_id is not null;

create index if not exists employee_resources_lease_idx
  on employee_resources (lease_until)
  where lease_owner is not null;

-- ---------------------------------------------------------------------------
-- conversations / messages
-- ---------------------------------------------------------------------------

create table if not exists conversations (
  id               uuid        primary key,
  tenant_id        uuid        not null references tenants (id) on delete cascade,
  employee_id      uuid        not null references employees (id) on delete cascade,
  channel          text        not null,
  -- Provider-side thread identifier (email thread, Twilio conversation, ...).
  external_ref     text,
  subject          text,
  -- Highest trust label of anything in the thread; joins upward, never down.
  trust_label      text        not null default 'untrusted',
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  last_message_at  timestamptz
);

create index if not exists conversations_employee_idx
  on conversations (employee_id, last_message_at desc);

create table if not exists messages (
  id                   uuid        primary key,
  tenant_id            uuid        not null references tenants (id) on delete cascade,
  conversation_id      uuid        not null references conversations (id) on delete cascade,
  employee_id          uuid        not null references employees (id) on delete cascade,
  channel              text        not null,
  direction            text        not null,
  sender               text        not null,
  recipients           jsonb       not null default '[]'::jsonb,
  provider_message_id  text,
  language             text,
  subject              text,
  body                 text        not null default '',
  structured_data      jsonb,
  attachments          jsonb       not null default '[]'::jsonb,
  trust_label          text        not null default 'untrusted',
  -- Every ingress path computes one; replayed webhooks land on this constraint
  -- instead of duplicating a conversation turn.
  idempotency_key      text        not null,
  received_at          timestamptz not null default now(),
  created_at           timestamptz not null default now(),
  constraint messages_tenant_idempotency_key unique (tenant_id, idempotency_key)
);

create index if not exists messages_conversation_idx
  on messages (conversation_id, received_at);

-- ---------------------------------------------------------------------------
-- approvals
-- ---------------------------------------------------------------------------

create table if not exists approvals (
  id             uuid        primary key,
  tenant_id      uuid        not null references tenants (id) on delete cascade,
  employee_id    uuid        references employees (id) on delete cascade,
  action_kind    text        not null,
  action         jsonb       not null default '{}'::jsonb,
  reason         text,
  risk           text,
  state          text        not null default 'pending',
  -- Money is stored as minor units plus an explicit currency, never as a float
  -- and never as a bare number.
  amount_minor   bigint,
  currency       text,
  requested_at   timestamptz not null default now(),
  expires_at     timestamptz,
  decided_at     timestamptz,
  decided_by     text,
  decision_note  text,
  constraint approvals_amount_positive
    check (amount_minor is null or amount_minor > 0),
  constraint approvals_amount_has_currency
    check ((amount_minor is null) = (currency is null))
);

create index if not exists approvals_pending_idx
  on approvals (tenant_id, requested_at)
  where state = 'pending';

-- ---------------------------------------------------------------------------
-- audit_log: append-only, enforced twice
-- ---------------------------------------------------------------------------
--
-- Deliberately has NO foreign key to tenants. Deleting a tenant must not be a
-- way to delete its audit trail, and ON DELETE CASCADE would make it one.

create table if not exists audit_log (
  id                uuid        primary key,
  tenant_id         uuid        not null,
  employee_id       uuid,
  conversation_id   uuid,
  decision_id       uuid,
  actor             text        not null,
  action_kind       text        not null,
  decision          text,
  deny_reason_code  text,
  payload           jsonb       not null default '{}'::jsonb,
  occurred_at       timestamptz not null default now()
);

create index if not exists audit_log_tenant_time_idx
  on audit_log (tenant_id, occurred_at desc);

-- Belt: the app role simply lacks the privilege (granted below, then revoked).
-- Braces: a trigger, because a future migration that says
-- `GRANT ALL ON ALL TABLES IN SCHEMA public TO app_role` would quietly undo the
-- belt. The trigger also binds superusers, which no GRANT ever does.
create or replace function audit_log_append_only() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_log is append-only; % is not permitted', tg_op
    using errcode = 'restrict_violation';
end
$$;

drop trigger if exists audit_log_append_only on audit_log;
create trigger audit_log_append_only
  before update or delete on audit_log
  for each row execute function audit_log_append_only();

-- ---------------------------------------------------------------------------
-- idempotency_records
-- ---------------------------------------------------------------------------

create table if not exists idempotency_records (
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  key           text        not null,
  -- Distinguishes an API replay from a provisioning-step replay that happen to
  -- share a key string.
  scope         text        not null default 'api',
  -- Hash of the request body: same key + different body is a client bug, and we
  -- want to say so rather than return the first response.
  request_hash  text,
  state         text        not null default 'in_flight',
  status_code   integer,
  response      jsonb,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  expires_at    timestamptz,
  primary key (tenant_id, scope, key)
);

create index if not exists idempotency_records_expiry_idx
  on idempotency_records (expires_at)
  where expires_at is not null;

-- ---------------------------------------------------------------------------
-- outbox_events
-- ---------------------------------------------------------------------------
--
-- Written in the same transaction as the state change it describes; drained by
-- a cross-tenant poller running under admin_tx_bypassing_rls. RLS is still on,
-- so ordinary tenant code cannot read another tenant's pending effects.

create table if not exists outbox_events (
  id              uuid        primary key,
  tenant_id       uuid        not null references tenants (id) on delete cascade,
  aggregate_type  text        not null,
  aggregate_id    uuid        not null,
  event_type      text        not null,
  payload         jsonb       not null default '{}'::jsonb,
  created_at      timestamptz not null default now(),
  available_at    timestamptz not null default now(),
  attempt_count   integer     not null default 0,
  last_error      text,
  published_at    timestamptz,
  lease_owner     uuid,
  lease_until     timestamptz
);

create index if not exists outbox_events_due_idx
  on outbox_events (available_at, id)
  where published_at is null;

-- ---------------------------------------------------------------------------
-- provider_intents
-- ---------------------------------------------------------------------------
--
-- The record that we intended to call a provider, written before the call. It
-- is what makes a crashed side effect discoverable instead of invisible.

create table if not exists provider_intents (
  id               uuid        primary key,
  tenant_id        uuid        not null references tenants (id) on delete cascade,
  employee_id      uuid        references employees (id) on delete cascade,
  provider         text        not null,
  intent_kind      text        not null,
  idempotency_key  text        not null,
  state            text        not null default 'pending',
  request          jsonb       not null default '{}'::jsonb,
  response         jsonb,
  amount_minor     bigint,
  currency         text,
  external_id      text,
  last_error       text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  constraint provider_intents_amount_positive
    check (amount_minor is null or amount_minor > 0),
  constraint provider_intents_amount_has_currency
    check ((amount_minor is null) = (currency is null)),
  -- Replaying the same intent hits this instead of paying twice.
  constraint provider_intents_key unique (tenant_id, provider, idempotency_key)
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

-- tenants is keyed on `id` rather than `tenant_id`; everything else is uniform.
alter table tenants enable row level security;
alter table tenants force row level security;
drop policy if exists tenant_isolation on tenants;
create policy tenant_isolation on tenants
  using (id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (id = nullif(current_setting('app.tenant_id', true), '')::uuid);

do $$
declare
  t text;
begin
  foreach t in array array[
    'employees', 'employee_resources', 'conversations', 'messages',
    'approvals', 'audit_log', 'idempotency_records', 'outbox_events',
    'provider_intents'
  ]
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    -- `nullif(..., '')` keeps an empty GUC from raising a cast error; an unset
    -- GUC yields NULL, the comparison yields NULL, and the row is invisible.
    -- Failing closed is the point.
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
--
-- Enumerated table by table on purpose. `GRANT ... ON ALL TABLES IN SCHEMA
-- public` would also hand app_role write access to _sqlx_migrations, and would
-- re-grant audit_log every time it ran.

grant select, insert, update, delete on
  employees, employee_resources, conversations, messages, approvals,
  idempotency_records, outbox_events, provider_intents
  to app_role;

-- A tenant may read its own row but not invent or delete tenants.
grant select on tenants to app_role;

grant select, insert on audit_log to app_role;
revoke update, delete on audit_log from app_role;
