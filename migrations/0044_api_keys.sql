-- 0044_api_keys: step zero, which until now did not exist.
--
-- `apps/server/src/auth.rs` has always read its keyring out of
-- `AGENTOS_API_KEYS`, and has always said in its own module doc what that cost:
--
--     ponytail: an env-var keyring. […] it has one real ceiling: keys cannot be
--     issued or revoked without a restart. When self-service keys are a
--     requirement, this becomes an `api_keys (tenant_id, label, secret_hash)`
--     table read through `Db::admin_tx_bypassing_rls` […] with an argon2 or HMAC
--     digest instead of the raw secret.
--
-- This is that table. Two things made the ceiling stop being acceptable, and
-- both of them are about having more than one customer:
--
--   1. NOBODY CAN SIGN UP. A key comes from a variable, a variable comes from a
--      deployment, so the first step of the customer journey is an ssh session
--      belonging to us. There is no step zero.
--   2. A STOLEN KEY IS REVOKED BY REDEPLOYING — that is, by interrupting every
--      other customer in order to protect one. At one customer that is
--      invisible. At ten it is an incident per quarter.
--
-- ---------------------------------------------------------------------------
-- WHY THE DIGEST IS AN HMAC AND NOT AN ARGON2
-- ---------------------------------------------------------------------------
--
-- The argument is `crates/app/src/api_keys.rs`, in full. The half that belongs
-- in the schema is the half that shaped these columns:
--
-- * `secret_hash` is a FUNCTION OF THE SECRET ALONE — no per-row salt — which
--   is what lets it carry a unique index and what makes the lookup one indexed
--   equality. That is not an optimisation, it is the only shape that works
--   here: the lookup PRECEDES knowing the tenant, so a salted digest would have
--   to be recomputed against every row in the table on every request, and with
--   argon2 that is 50 ms × rows of CPU that an unauthenticated stranger can
--   spend for us by sending a wrong bearer token.
-- * A deterministic digest is only safe because the secret is not a password.
--   It is 256 bits from the OS CSPRNG, minted by `agentos_app::api_keys::mint`
--   and never chosen by a human. There is no dictionary to precompute and
--   nothing for a stretcher to stretch.
-- * `bytea` and not `text`: the digest is 32 raw bytes, and a hex column is a
--   column somebody compares case-insensitively one day.
--
-- ---------------------------------------------------------------------------
-- WHY `revoked_at` IS NOT A COLUMN
-- ---------------------------------------------------------------------------
--
-- Revoking deletes the row. A `revoked_at timestamptz` would mean every read of
-- this table has to remember `AND revoked_at IS NULL`, and the one that forgets
-- does not fail — it silently un-revokes a stolen key. DELETE cannot be
-- forgotten by a future SELECT.
--
-- What that gives up is the record that the key ever existed, and the record is
-- not given up: `audit_log` carries `api_key_issued` and `api_key_revoked` with
-- the label and the key id, in the same transaction as the INSERT and the
-- DELETE, and `audit_log` is append-only against a trigger that fires for
-- superusers too (`0001_core.sql`). So the history survives in the one table
-- that cannot be rewritten, and the authentication path reads the one table
-- where a present row means a live key.
--
-- ---------------------------------------------------------------------------
-- NO `last_used_at`
-- ---------------------------------------------------------------------------
--
-- It would be an UPDATE on the authentication path of every request — a row
-- lock and a WAL record per call, on the one table every request already reads.
-- "When was this key last used" is `audit_log`, aggregated, off the hot path.

create table if not exists api_keys (
  id           uuid        primary key,

  -- Every key belongs to exactly one tenant, and the tenant is written here at
  -- issue time by something that is not the key. That is the whole reason
  -- `Principal::tenant_id` cannot be influenced by a caller: the row says whose
  -- the key is, and the request says nothing.
  tenant_id    uuid        not null references tenants (id) on delete cascade,

  -- Human name, e.g. `ops-console`. Becomes the audit actor, exactly as the
  -- `label` half of an `AGENTOS_API_KEYS` entry already does — so the trail
  -- reads the same whichever keyring answered.
  label        text        not null,

  -- HMAC-SHA256(deployment key, secret). 32 bytes. The secret itself exists in
  -- exactly one response body, once, and nowhere else in this system.
  --
  -- UNIQUE for two reasons. The obvious one is that the lookup is
  -- `WHERE secret_hash = $1` and wants the index. The load-bearing one is that
  -- two rows with one digest would be one secret that names two tenants, and
  -- `lookup` would have to pick — which is a coin toss deciding whose data a
  -- request reads. A collision here is a 23505 at issue time instead.
  secret_hash  bytea       not null unique,

  created_at   timestamptz not null default now(),

  -- One label per tenant, so `revoke the ops-console key` names one row. Not
  -- global: two customers both calling their key `ops-console` is the normal
  -- case, and a global unique would leak that another tenant got there first.
  constraint api_keys_tenant_label_key unique (tenant_id, label)
);

create index if not exists api_keys_tenant_idx on api_keys (tenant_id);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core — and then a second belt
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, so the owning role that migrations and the
-- cross-tenant loops connect as does not walk past the policy. `with check` as
-- well as `using`, so no row can be filed wearing another tenant's id.
--
-- THEN: no grants at all. `app_role` gets nothing on this table — not SELECT.
-- The two are deliberately redundant and they fail differently, which is the
-- point of having both:
--
--   * the missing grant means a tenant transaction that touches `api_keys` dies
--     with `42501 permission denied for table api_keys`. Loud, immediate, and
--     it names the table.
--   * the policy means that if some future migration grants SELECT "just to
--     list your own keys", the isolation is already there and a tenant still
--     cannot read another tenant's digests.
--
-- The only reader is `agentos_store::api_keys`, which opens
-- `Db::admin_tx_bypassing_rls` because the lookup precedes knowing the tenant
-- and therefore cannot be scoped by a GUC that is not set yet. That module
-- opens the transaction READ ONLY for the lookup, so the escape hatch it is
-- forced to use cannot write even if somebody later adds a statement to it.

alter table api_keys enable row level security;
alter table api_keys force row level security;
drop policy if exists tenant_isolation on api_keys;
create policy tenant_isolation on api_keys
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Stated as a revoke rather than as an absence: `grant all on all tables in
-- schema public to app_role` is one line somebody adds to a later migration to
-- unbreak something, and it would hand every tenant every other tenant's key
-- digests. This makes that line not enough.
revoke all on api_keys from app_role;
