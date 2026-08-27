-- 0050_tenant_model_key: the credential moves into the row that claims it.
--
-- `0041_tenant_model_access` said, under WHAT IS NOT IN HERE (a), that the
-- credential lives in the secret store under a derived ref and that the row
-- would therefore never point at a key. That decision was right about *pointers*
-- and wrong about *durability*, and this migration keeps the first half while
-- undoing the second. The reason is one line of wiring:
-- `apps/server/src/main.rs` builds the deployment's only vault with
-- `agentos_app::mocks::secret_store()`, which is a `MemorySecretStore` — a
-- `Mutex<HashMap<..>>` in the server process. There is no other implementation
-- wired anywhere. `LocalEnvelopeSecretStore` exists and encrypts properly, but
-- it holds its rows in a `HashMap` too: it is the cipher, not the storage.
--
-- So since 0041 the only durable half of a connection has been the half with no
-- credential in it, and that asymmetry costs a customer real money in a
-- documented order:
--
--   1. A restart, a crash or a pod replan empties the map. The row still says
--      connected, with a `verified_at`.
--   2. `agentos_app::model_access::connected` reads only the row, so the turn is
--      authorised.
--   3. `apps/server/src/loops/initiative.rs::reserve_a_turn` then COMMITS the
--      reservation, and its own doc says "There is no matching release".
--   4. Only after that does `llm_for` touch the vault and return
--      `NoModel::KeyMissing`.
--   5. Every employee therefore spends its whole `max_turns_per_day` on an empty
--      map, and re-pasting the key does not give the day back. The customer
--      waits for midnight UTC.
--   6. `GET /v1/model` never asked the vault at all, so it answered 200 for a
--      key that no longer existed — against `crates/app/src/model_access.rs`'s
--      stated invariant that "there is no state where the row says connected and
--      the credential does not work".
--
-- With more than one replica it is not even a restart: the key exists only in
-- the process that served the POST, and any other replica's turns fail.
--
-- WHY A COLUMN, AND NOT A DURABLE SECRET STORE
--
-- Because `0040_mcp_credentials` already answered this question for a token, and
-- the answer generalises without a line of new machinery. That migration put
-- `sealed_token bytea` on `mcp_servers` rather than inventing an
-- `employee_secrets` table, on the grounds that `SecretStore` is keyed on a
-- `SecretRef` — `(tenant, employee, name)` — and the thing being sealed has no
-- employee in it. The model credential has exactly the same shape problem, and
-- 0041 papered over it with a *nil* employee uuid: a UUID that names nobody,
-- inside an AAD, forever. `crates/providers/src/secrets.rs::seal_in` was added
-- for precisely this case and names the alternative it rejects.
--
-- A durable `SecretStore` implementation would need its own table, its own RLS
-- policy, its own grants, and a `delete_prefix` whose subtree semantics nothing
-- here wants. This column inherits all four from 0041: the `tenant_isolation`
-- policy covers it on USING and on WITH CHECK exactly as it covers `path`, the
-- existing `grant select, insert, update` covers it, and `on delete cascade` on
-- `tenant_id` disposes of it when the tenant goes.
--
-- WHAT IS IN THE COLUMN
--
-- The envelope blob from `agentos_providers::secrets::Envelope::to_bytes`: a
-- data key wrapped under the deployment's master key with AAD `tenant=<id>`, and
-- the credential sealed under that data key with AAD `model://<tenant>` —
-- the same shape as 0040's `mcp://<tenant>/<server>` and 0014's
-- `employee_signing_keys.sealed_private_key`. A database dump is therefore not a
-- credential leak, and a row lifted into another tenant's context fails to
-- authenticate rather than decrypting to somebody else's key.
--
-- The second AAD is what makes the column safe to *sit next to* a `path`: the
-- scheme `model://` cannot collide with `secret://` or `mcp://`, so a blob
-- copied out of `mcp_servers.sealed_token` into this column opens as nothing.
--
-- No `key_fingerprint`, no `key_last_four`, no `verified_by`. 0040 argues it: a
-- prefix of a credential is a credential, and the only thing a UI needs is "is
-- one set", which `path = 'api_key'` already answers without storing anything
-- derived from the secret.
--
-- WHAT HAPPENS TO THE ROWS THAT ARE ALREADY THERE
--
-- Every `api_key` row that predates this migration is DELETED, and that is the
-- point of the migration rather than a cost of it.
--
-- Such a row asserts a connection whose credential this deployment can no longer
-- produce. The key was only ever in a process map; if the process is still up
-- the tenant is one restart from the outage above, and if it has restarted even
-- once the key is already gone. There is no backfill available and no backfill
-- imaginable — we never kept a copy of the credential we could re-seal, which is
-- exactly the property `NoModel::KeyMissing`'s sentence promises the customer.
--
-- So the choice is between a row that says "connected" and cannot prove it, and
-- no row at all. 0041 already decided what absence means — "the absence of a row
-- IS 'not connected', the same way an empty allowlist IS 'denies'" — and it
-- already chose loud over convenient for the same reason: "a backfilled row would
-- be this system asserting that a tenant connected a model when no tenant did".
-- Deleting is one POST per affected tenant, it produces the message that names
-- the remedy (`NoModel::NotConnected` says "Connect one with POST /v1/model"),
-- and it fails in the direction where nobody spends a turn budget discovering it.
-- Leaving the row would instead reproduce the bug in perpetuity for exactly the
-- tenants this migration is about.
--
-- `cli` rows are KEPT, untouched. A CLI connection never had a credential to
-- lose — `agentos_app::model_access::connect` deliberately drops any key sent on
-- that path — so the row was fully durable before this migration and is fully
-- durable after it. Deleting those would be an outage with no defect behind it.
--
-- THE DELETE IS SELF-CHECKING, WHICH MATTERS UNDER RLS
--
-- `tenant_model_access` has `force row level security`, so the policy binds the
-- table owner too, and a migration role that is neither a superuser nor
-- `BYPASSRLS` sees no rows with `app.tenant_id` unset — the DELETE would then
-- remove nothing and report success. That silent outcome is why the CHECK below
-- is added VALIDATED rather than `NOT VALID`: if any unprovable row survived the
-- DELETE, `ALTER TABLE` scans it, refuses, and the whole migration aborts. The
-- operator gets a failed deploy instead of a table that quietly still lies.
--
-- THE CONSTRAINT IS A BICONDITIONAL, ON PURPOSE
--
-- `path = 'api_key'` if and only if `sealed_key is not null`. Both directions
-- earn their keep:
--
--   * api_key => key present is the invariant this file exists for. After it,
--     `GET /v1/model` answering 200 is honest again *without* the route reading
--     any credential, because the row and the key are one row written by one
--     statement — the "same transaction" 0041 claims for the vault write is,
--     for the first time, actually true.
--   * cli => key absent keeps `connect`'s narrowing enforceable at rest. That
--     function refuses to store a key it never proved
--     (`a_cli_connection_does_not_store_a_key_it_never_tried`); this is the same
--     rule as a table constraint, so a `psql` session cannot leave a credential
--     attached to a path that would never read it.
--
-- The nonempty half is 0014's and 0040's guard, for their reason: a row whose
-- sealed half is present but empty is a connection that believes it has a
-- credential and opens nothing.
--
-- Replayable: `if not exists` on the column, a DELETE predicated on the very
-- NULL the constraint then forbids (so a second run matches nothing), and the
-- duplicate_object catch 0040 uses for the constraint.

-- ---------------------------------------------------------------------------
-- WHAT 0041 SAYS THAT IS NOT TRUE, AND WHY THE CORRECTION IS HERE
-- ---------------------------------------------------------------------------
--
-- `0041`'s decision (b) argues against a `verified_by` column and ends: "…and
-- where a `secret_accessed` row already lands for every read of the
-- credential". That clause is false and always was. `SecretResolver` is the
-- only writer of that row, nothing outside `#[cfg(test)]` constructs one, and
-- `crates/app/src/model_access.rs` argues on purpose that a row per read would
-- be noise. `SPEC.md` promised the same thing and now carries its own NOT WIRED
-- tag.
--
-- **It is corrected here rather than there, and that is the point of this
-- paragraph.** An applied migration is immutable: `sqlx` checksums the file, so
-- editing a comment in `0041` makes every database that already ran it refuse
-- to migrate with `VersionMismatch(41)` — which is exactly what happened, once,
-- and was caught by a test run against a database that was not freshly created.
-- A correction that breaks every existing deployment is not a correction.
--
-- So: the true statement is that who *connected* is on the record, via the
-- `model_connected` audit row, and every *read* after that is not. The rest of
-- 0041's argument stands.
--
alter table tenant_model_access
  add column if not exists sealed_key bytea;

delete from tenant_model_access
 where path = 'api_key'
   and sealed_key is null;

do $$
begin
  alter table tenant_model_access
    add constraint tenant_model_access_key_matches_path
    check (
      (path = 'api_key') = (sealed_key is not null)
      and (sealed_key is null or octet_length(sealed_key) > 0)
    );
exception
  when duplicate_object then null;
end
$$;
