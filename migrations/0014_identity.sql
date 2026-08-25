-- 0014_identity: the Ed25519 keypair that makes an employee verifiable to
-- somebody who has never heard of us.
--
-- WHY THIS EXISTS. An AI employee sends mail, opens A2A sessions and signs
-- requests in a company's name. The counterparty's only question is "is this
-- really Fabrikam's purchasing agent, or a stranger who read the agent card?".
-- Answering it needs a key we hold and a public key they can fetch — and the
-- fetch has to work for a party who has no credential with us, no account, and
-- no prior contact.
--
-- WHY NOT did:web. did:web is a JSON document at a well-known URL over exactly
-- these bytes, so it is a rendering of this table and not a different design.
-- Its Rust toolchain is the problem: `spruceid/didkit` is archived and
-- `spruceid/ssi` is a small crate with a failing docs build, and being the
-- load-bearing user of a dying dependency is worse than the problem it solves.
-- What actually shipped in the market is key discovery at a well-known URL —
-- Cloudflare's Web Bot Auth serves a JWKS and signs with RFC 9421, Entra uses
-- service principals, AWS uses workload identities. So: Ed25519 here, JWKS at
-- `/.well-known/http-message-signatures-directory`, and emitting a
-- `/.well-known/did.json` alias over the same rows stays a function nobody has
-- had to write yet.
--
-- THE ONE DECISION IN THIS SCHEMA. The two halves of a keypair are in one row
-- and are treated as opposites:
--
--   public_key          32 raw bytes. Published to anyone who asks, on an
--                       unauthenticated endpoint, which is its entire purpose.
--   sealed_private_key  the envelope blob from `providers::secrets`: a data key
--                       wrapped under the master key with AAD `tenant={id}`,
--                       and the seed sealed under the data key with AAD the
--                       full SecretRef. Never the raw seed. A dump of this
--                       table without AGENTOS_MASTER_KEY is 32 useless bytes
--                       and a ciphertext, and a row lifted from tenant A into
--                       tenant B's context fails to authenticate rather than
--                       decrypting to A's identity.
--
-- ONE KEY PER EMPLOYEE, which is the primary key rather than a convention. Two
-- live keys would mean a signature could be attributed to either, and every
-- query that publishes "the" key would be picking one by row order.
--
-- ponytail: therefore no rotation overlap window. Rotation today is "replace
-- the row", which invalidates signatures already in flight. The JWKS is an
-- array and the read below is a `SELECT` with no `LIMIT`, so an overlap window
-- is a primary-key change (add `public_key` to it) plus a retention sweep —
-- and nothing above the store moves. Do it when there is a counterparty who
-- would notice, not before.

create table if not exists employee_signing_keys (
  tenant_id           uuid        not null references tenants (id) on delete cascade,
  employee_id         uuid        not null references employees (id) on delete cascade,
  -- Ed25519, fixed by the curve. The check is here rather than in Rust because
  -- a 31-byte "public key" served in a JWKS is a key nobody can verify with,
  -- and the database is the last place that can still refuse it.
  public_key          bytea       not null,
  sealed_private_key  bytea       not null,
  created_at          timestamptz not null default now(),
  primary key (tenant_id, employee_id),
  constraint employee_signing_keys_public_key_len
    check (octet_length(public_key) = 32),
  -- A row whose sealed half is empty is an employee with a published identity
  -- it cannot sign with: it would verify nothing and fail at the worst moment.
  constraint employee_signing_keys_sealed_nonempty
    check (octet_length(sealed_private_key) > 0)
);
-- Two plain foreign keys rather than a composite `(employee_id, tenant_id)`
-- one, matching `employee_resources` in 0001_core: `employees` has no
-- `unique (id, tenant_id)` to point a composite FK at, and adding one to
-- another unit's table to buy a redundant check is not worth the migration.
-- The RLS policy below is what actually keeps the pair honest — a row whose
-- tenant_id is not the session's cannot be written at all.

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------
--
-- Load-bearing here in a way it is not everywhere else: the JWKS endpoint is
-- UNAUTHENTICATED by design, so there is no credential naming a tenant and the
-- handler cannot be trusted to add a `WHERE tenant_id = $1`. It resolves the
-- employee, opens a transaction for THAT tenant, and the policy below is what
-- makes it impossible for the document to contain anyone else's key.

do $$
declare
  t text;
begin
  foreach t in array array['employee_signing_keys']
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

-- Delete is granted: offboarding an employee must be able to destroy its key,
-- and a key that outlives the employee is an identity that can still be
-- impersonated by anyone who reaches the master key. Update is NOT granted —
-- rotation goes through delete-then-insert, so "the key changed" is two
-- statements somebody wrote on purpose rather than one column somebody touched.
grant select, insert, delete on employee_signing_keys to app_role;
revoke update on employee_signing_keys from app_role;
