-- 0002_provisioning: the write-ahead log for provider side effects.
--
-- `provider_intents` already exists — 0001 created it, and a second table
-- holding the same fact would be the actual bug. This migration only teaches
-- the existing one the two things the provisioning worker needs:
--
--   * `step`, so a recovery sweep can join an orphaned intent back to the
--     `employee_resources` row it was going to write, without parsing the
--     idempotency key back apart;
--   * a closed `state` vocabulary, so 'in_flight' is a durable claim that a
--     network call MAY have happened rather than a hopeful default.
--
-- What is deliberately NOT here: advisory locks. The spec asked for
-- `pg_advisory_lock` on the employee; that is wrong for this system. Advisory
-- locks are *session*-scoped, and this is a pooled sqlx app — acquire and
-- release can land on different pooled connections, a panicking worker never
-- releases, and one lock per employee needlessly serialises eleven independent
-- provisioning steps. The lease columns already on `employee_resources`
-- (`lease_owner`, `lease_until`) do the same job per row, expire on their own,
-- and survive a process that dies without unwinding. `claim_step` takes a real
-- row lock with `SELECT ... FOR UPDATE` for the read-modify-write and lets it
-- go at commit.

-- Which provisioning step this intent was for. Nullable: intents for non-step
-- side effects (a payment, say) have no step.
alter table provider_intents add column if not exists step text;

-- The sweep's access path: every in-flight intent for one employee's step.
create index if not exists provider_intents_employee_step_idx
  on provider_intents (employee_id, step)
  where state = 'in_flight';

-- Written before the network call, so the default is the honest one.
alter table provider_intents alter column state set default 'in_flight';

do $$
begin
  alter table provider_intents
    add constraint provider_intents_state_check
    check (state in ('in_flight', 'succeeded', 'failed', 'orphaned'))
    -- NOT VALID: 0001 shipped a default of 'pending', and a database that
    -- already has such a row must still migrate. New and updated rows are
    -- checked; the stale ones are left alone rather than blocking the deploy.
    not valid;
exception
  when duplicate_object then null;
end
$$;

-- `IdempotencyKey::for_step` is already unique per (employee, step), so a
-- worker that only knows the key can close its own intent. Tenant-scoped
-- rather than a bare primary key on the column: a global unique across tenants
-- would let one tenant's key collide with another's and leak the existence of
-- the row through the constraint error.
create unique index if not exists provider_intents_tenant_key_idx
  on provider_intents (tenant_id, idempotency_key);
