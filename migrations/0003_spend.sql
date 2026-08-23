-- 0003_spend: the money the agent is allowed to move, and the lock that makes
-- the limit real.
--
-- The bug this schema exists to make impossible: a per-request cap that is
-- CHECKED but not RESERVED. Check-then-act lets ten concurrent requests each
-- read "0 spent today", each conclude they are under the cap, and each pay.
-- Structuring one large payment into many small ones is the attack, and it is
-- indistinguishable from ordinary concurrency.
--
-- The fix is that `spend_buckets` holds ONE row per (tenant, employee, day,
-- currency) and every reservation locks it — `INSERT ... ON CONFLICT DO UPDATE
-- ... RETURNING`, which creates the row if missing and takes a row-level write
-- lock either way, in one statement. Everything after that lock is serialised
-- by Postgres, so read-modify-write on the running total is safe. The lock is
-- taken inside the CALLER's transaction, the same one that writes the payment
-- intent, so a reservation and the payment it authorises commit or vanish
-- together.
--
-- Three counters, three caps, all per currency, because a limit denominated in
-- USD says nothing about a payment in JPY:
--   * reserved_minor  vs daily_total_minor       — how much
--   * txn_count       vs daily_transaction_count — how many
--   * (per reservation)  per_transaction_minor   — how big any single one is
--
-- `spend_reservations` is the outstanding-or-settled record of each one. It
-- exists so `release` can be refused a second time: without a per-reservation
-- state, a double release would decrement the bucket twice and hand back
-- headroom that was never consumed.

-- ---------------------------------------------------------------------------
-- spend_caps: configuration. Absence means "may not spend at all".
-- ---------------------------------------------------------------------------
--
-- Deliberately a stored table rather than a parameter to `reserve`. A cap that
-- travels in from the caller is a cap the caller can inflate; the ledger has to
-- own the number it enforces, and read it inside the reserving transaction.

create table if not exists spend_caps (
  tenant_id                uuid        not null references tenants (id) on delete cascade,
  employee_id              uuid        not null references employees (id) on delete cascade,
  currency                 text        not null,
  daily_total_minor        bigint      not null,
  per_transaction_minor    bigint      not null,
  daily_transaction_count  integer     not null,
  updated_at               timestamptz not null default now(),
  primary key (tenant_id, employee_id, currency),
  constraint spend_caps_positive check (
    daily_total_minor > 0 and per_transaction_minor > 0 and daily_transaction_count > 0
  )
);

-- ---------------------------------------------------------------------------
-- spend_buckets: the contended row. One per employee per day per currency.
-- ---------------------------------------------------------------------------

create table if not exists spend_buckets (
  tenant_id       uuid        not null references tenants (id) on delete cascade,
  employee_id     uuid        not null references employees (id) on delete cascade,
  day             date        not null,
  currency        text        not null,
  -- Everything reserved today and not released, settled included: a settled
  -- payment consumes the cap exactly as much as an outstanding one does.
  reserved_minor  bigint      not null default 0,
  txn_count       integer     not null default 0,
  updated_at      timestamptz not null default now(),
  primary key (tenant_id, employee_id, day, currency),
  -- The last line of defence. Application arithmetic can be wrong; a bucket
  -- that has gone negative means release ran twice, and this turns that from
  -- silent free money into a failed transaction.
  constraint spend_buckets_nonnegative
    check (reserved_minor >= 0 and txn_count >= 0)
);

-- ---------------------------------------------------------------------------
-- spend_reservations
-- ---------------------------------------------------------------------------

create table if not exists spend_reservations (
  id            uuid        primary key,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  employee_id   uuid        not null references employees (id) on delete cascade,
  day           date        not null,
  currency      text        not null,
  amount_minor  bigint      not null,
  state         text        not null default 'reserved',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint spend_reservations_amount_positive check (amount_minor > 0),
  constraint spend_reservations_state
    check (state in ('reserved', 'released', 'settled')),
  -- A reservation without a bucket would be money nobody is counting.
  constraint spend_reservations_bucket_fk
    foreign key (tenant_id, employee_id, day, currency)
    references spend_buckets (tenant_id, employee_id, day, currency)
    on delete cascade
);

create index if not exists spend_reservations_bucket_idx
  on spend_reservations (tenant_id, employee_id, day, currency);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core.
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array['spend_caps', 'spend_buckets', 'spend_reservations']
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

-- No DELETE anywhere: a spend ledger you can delete rows from is not a ledger.
-- Tenant deletion still cascades, because that runs as the owning role.
grant select, insert, update on spend_caps, spend_buckets, spend_reservations
  to app_role;
revoke delete on spend_caps, spend_buckets, spend_reservations from app_role;
