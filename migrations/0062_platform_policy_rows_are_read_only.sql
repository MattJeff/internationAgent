-- 0062_platform_policy_rows_are_read_only: make 0006's promise true.
--
-- `0006_policy.sql` gave `policy_versions` and `policy_layers` one `ALL` policy
-- with a deliberately asymmetric pair of clauses:
--
--     using      (tenant_id is null or tenant_id = app.tenant_id)
--     with check (tenant_id = app.tenant_id)
--
-- and said, in a comment directly above it:
--
--   > USING allows reading the platform rows (tenant_id IS NULL); WITH CHECK
--   > does not, so those rows are read-only to every tenant.
--
-- The first half is right and the second half is not, because of how Postgres
-- checks an UPDATE: `USING` is applied to the **old** row and `WITH CHECK` to
-- the **new** one. A tenant that rewrites the platform row *in place* is
-- refused, correctly — the new row still has `tenant_id IS NULL` and fails the
-- check. But a tenant that **re-parents** it passes both halves:
--
--     update policy_versions set tenant_id = '<mine>' where tenant_id is null;
--       -- old row: tenant_id is null      -> USING      ok
--       -- new row: tenant_id = mine       -> WITH CHECK ok
--
-- and the platform policy version is now that tenant's private property. Every
-- other tenant's `policy::load` stops finding a ceiling, which is the
-- deployment-wide floor on spend, on outbound contact and on which models may
-- be called. Proven against a real database before this file was written, and
-- `platform_policy_rows_survive_a_tenant_that_wants_them` is it in Rust.
--
-- `policy_layers` survived that only by accident: its `policy_layers_platform_is_global`
-- check constraint pins `layer = 'platform'` to `tenant_id is null`, so the
-- re-parent fails on the constraint rather than on the policy. `policy_versions`
-- has no such column and nothing caught it. Defence in depth is why the damage
-- was one table instead of two; it is not a reason to leave the policy wrong.
--
-- # The fix, and why it is a narrowing and never a widening
--
-- Split the one `ALL` policy into the two statements it was always trying to
-- be: an `ALL` policy that is strictly the tenant's own rows, and a `SELECT`
-- policy that adds the platform rows back for reading only. Permissive policies
-- OR together, so per command:
--
--   SELECT  before: `is null or = mine`   after: `= mine` or `is null`  — same
--   INSERT  before: check `= mine`        after: check `= mine`         — same
--   UPDATE  before: using `is null or = mine`  after: using `= mine`   — NARROWER
--   DELETE  before: using `is null or = mine`  after: using `= mine`   — NARROWER
--
-- Nothing gains a row it could not already reach. `DELETE` is revoked from
-- `app_role` on both tables anyway (0006 keeps the policy history as an audit
-- trail); it is narrowed here too so the grant is the second lock rather than
-- the only one.
--
-- The operator paths that legitimately write a platform row — `policy install`,
-- `install_ceiling`, `rollback_ceiling` in `crates/store/src/policy.rs` — all
-- run in `Db::admin_tx_bypassing_rls` as the connecting superuser, which has
-- `rolbypassrls`, so none of them is affected by anything in this file.
--
-- A new migration rather than an edit to 0006: 0006 has been applied, and sqlx
-- refuses a database whose recorded checksum no longer matches the file.

do $$
declare
  t text;
begin
  foreach t in array array['policy_versions', 'policy_layers']
  loop
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format('drop policy if exists platform_readable on %I', t);

    -- The tenant's own rows, for every command. No `tenant_id is null` here:
    -- that is what let an UPDATE take the platform row's old value.
    execute format(
      'create policy tenant_isolation on %I'
      ' using (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)'
      ' with check (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );

    -- The platform rows, readable by everybody and writable by nobody. `for
    -- select` is the whole enforcement: a `SELECT` policy contributes no
    -- `WITH CHECK`, and Postgres will not consult it for the `USING` half of an
    -- UPDATE or a DELETE either.
    execute format(
      'create policy platform_readable on %I for select using (tenant_id is null)',
      t
    );
  end loop;
end
$$;
