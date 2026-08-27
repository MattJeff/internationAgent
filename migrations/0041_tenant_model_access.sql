-- 0041_tenant_model_access: the tenant's own model, and the proof that it works.
--
-- Until this file, which model an employee thought *with* was a policy question
-- (`0031_policy_models`) and which model the deployment could reach at all was a
-- process-wide environment variable (`AGENTOS_LLM` plus `ANTHROPIC_API_KEY`,
-- read once at boot in `apps/server/src/config.rs`). Between those two there was
-- no row anywhere saying whose credential pays. There did not need to be, as
-- long as the answer was "ours".
--
-- The answer is not ours. The product this schema belongs to sells access to
-- infrastructure and never the model: the customer connects their own key or
-- their own logged-in CLI, and from the first turn onwards every token is billed
-- to them. That sentence is a promise until there is a row per tenant naming the
-- credential and the moment it was proven, and after this migration it is a
-- fact with a primary key.
--
-- WHY THIS IS A TABLE AND NOT SIX COLUMNS ON `policy_layers`
--
-- Because `policy_layers` composes by intersection and this does not compose at
-- all. `agentos_store::policy::load` ANDs platform ∧ tenant ∧ role ∧ employee,
-- allowlists intersect, and empty means deny. Ask that machinery "by what path
-- does this tenant reach a model" and every part of the answer is wrong: there
-- is nothing to intersect ({api_key} ∧ {cli} is empty, and empty denies, so two
-- layers describing the same plumbing differently would stop the tenant
-- thinking), a role cannot sensibly reach a model by a *narrower* path than its
-- tenant, and `verified_at` is a fact this system observed by making a call —
-- not something an operator can type into a layer document. A layer that could
-- assert a key works would be a document that lies for free.
--
-- `crates/domain/src/model_access.rs` carries the same argument in full and is
-- where the types live. What matters here is the consequence: this table can
-- never widen a policy, because nothing in `agentos_domain::policy` reads it.
-- `model_for` still decides which model a turn runs, from the four intersected
-- layers and nothing else.
--
-- ONE ROW PER TENANT
--
-- `tenant_id` is the primary key, not a surrogate with a unique index, because
-- there is one credential per tenant and a schema that can hold two is a schema
-- somebody has to write a tie-break for. Reconnecting is an upsert: the old row
-- is replaced by the newly proven one, in the same transaction that stores the
-- new key, so there is no window where the row names a proof and the vault
-- holds a different credential.
--
-- WHAT IS NOT IN HERE
--
-- a. NO KEY, AND NO POINTER TO ONE. The credential lives in the secret store
--    under a ref *derived* from the tenant id
--    (`agentos_domain::model_access::ModelAccess::secret_ref`), so there is no
--    column an UPDATE can point at another tenant's secret. A stored pointer is
--    a stored mistake; a derived one cannot be edited. The store itself binds
--    the ciphertext to that same ref as AES-GCM additional data, so even a row
--    lifted between tenants decrypts to nothing —
--    `crates/providers/src/secrets.rs` argues that at length.
--
-- b. NO `verified_by` OR REQUEST METADATA. The interesting question about a
--    connection is whether it still works, and the answer to that is a fresh
--    call, not an old row. Who pressed the button is in `audit_log`, which is
--    where the trail belongs — the `model_connected` row written by
--    `agentos_app::model_access` carries it.
--
--    This paragraph used to end "…and where a `secret_accessed` row already
--    lands for every read of the credential". That was false when it was
--    written and it is corrected rather than deleted, because the false half
--    was load-bearing for the argument above it. `SecretResolver` is the only
--    writer of that row and nothing outside `#[cfg(test)]` constructs one; the
--    live read goes straight to the store, and `crates/app/src/model_access.rs`
--    argues on purpose that a row per read would be noise. `SPEC.md` promised
--    the same thing and is now tagged NOT WIRED. So: who connected is on the
--    record, and every *read* after that is not — which is a smaller claim than
--    this file used to make, and the true one.
--
-- c. NO `status` COLUMN. The absence of a row IS "not connected", the same way
--    an empty allowlist IS "denies" one table over. A nullable status invites a
--    row that says `failed`, and a failed connection is a thing this system
--    deliberately does not persist: `Verdict` stores nothing but success, so a
--    stored credential is always one that answered.
--
-- NO BACKFILL, AND THIS ONE IS A DELIBERATE BREAK
--
-- `0031_policy_models` backfilled every existing row with the full model set,
-- because the fleet was already running those models with the operator's
-- consent and leaving the rows empty would have been a silent outage. The
-- opposite reasoning applies here and it lands on the opposite decision. A
-- deployment running today is running on `ANTHROPIC_API_KEY` — *our* key, or at
-- best one key shared by every tenant on the box — and that is precisely the
-- state this migration exists to end. A backfilled row would be this system
-- asserting that a tenant connected a model when no tenant did, and the thing it
-- would assert is the exact arrangement the product says never happens.
--
-- So every tenant is unconnected the moment this lands, and no employee takes a
-- turn until somebody connects one. That is loud, it is one POST per tenant, and
-- it fails in the direction where nobody is billed for anything they did not
-- ask for. `apps/server/src/main.rs` and `apps/server/src/loops/initiative.rs`
-- turn the missing row into the same named, non-retryable turn failure that an
-- empty `allowed_models` already produces — an operator gets one message naming
-- the remedy, not a provider error that reads like an outage.

create table if not exists tenant_model_access (
  tenant_id     uuid        not null primary key
                            references tenants (id) on delete cascade,

  -- `api_key` (the tenant pasted their own) or `cli` (the model comes from this
  -- host, logged in as them). A check constraint rather than an enum type:
  -- `agentos_domain::model_access::ModelPath::parse` is the real gate and
  -- returns None for anything else, so this is the second belt that stops a
  -- `psql` session writing a path no build can read.
  path          text        not null
                            constraint tenant_model_access_path
                            check (path in ('api_key', 'cli')),

  -- The model the ONE verification call actually asked for. A fact about the
  -- credential, never a permission — see the header. Proving one model proves
  -- nothing about the other three, which is why the column names which one.
  verified_model text       not null,

  -- When that call returned a completion. Not null: a row exists only because a
  -- call succeeded, and a nullable column here would be a row that means
  -- "connected, we think".
  verified_at   timestamptz not null,
  updated_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, or the owning role — which is what migrations
-- and the outbox poller connect as — walks straight past the policy. `with
-- check` as well as `using`, so a tenant cannot file a row wearing somebody
-- else's id: a connection attributed to another tenant would point their
-- employees at a credential they never pasted.

alter table tenant_model_access enable row level security;
alter table tenant_model_access force row level security;
drop policy if exists tenant_isolation on tenant_model_access;
create policy tenant_isolation on tenant_model_access
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- SELECT for the turn, INSERT and UPDATE for the upsert that reconnecting is.
--
-- No DELETE, and it is not an oversight. "Disconnect my model" is not a verb
-- this product offers, because the useful shape of that request is *reconnect
-- with a different key*, which is the upsert above. A DELETE grant would also
-- give an employee's compromised path a way to stop the whole tenant thinking
-- with one statement, and the row is cheap to overwrite and impossible to
-- recreate from a backup that never had the key in it anyway. Tenant deletion
-- still cascades, because that runs as the owning role.
grant select, insert, update on tenant_model_access to app_role;
revoke delete on tenant_model_access from app_role;
