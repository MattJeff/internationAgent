-- 0053_webhook_endpoints: two customers behind one provider account, and their
-- mail does not mix.
--
-- `apps/server/src/routes/webhooks.rs` has carried the ceiling in its own
-- `ponytail:` note since the route was written:
--
--     registrations are process configuration, not a table […] one endpoint per
--     provider per deployment, so a deployment whose tenants each hold their own
--     provider account needs a `webhook_endpoints (path, tenant_id, secret_ref)`
--     table read through `admin_tx_bypassing_rls` — the lookup precedes knowing
--     the tenant, so it cannot be tenant-scoped.
--
-- This is that table. What made the ceiling stop being acceptable is not
-- convenience, it is the order in which it fails:
--
--   1. `Webhooks` is a `HashMap` keyed on the `{provider}` path segment and
--      `main::webhooks` builds it with `.collect()`, so
--      `AGENTOS_WEBHOOK_SECRETS=email:A:s,email:B:s` silently kept the second
--      registration and dropped the first.
--   2. Two tenants behind ONE provider account share ONE signing secret. The
--      signature therefore verifies for both.
--   3. The delivery is filed against whichever tenant survived the collect.
--   4. `crates/app/src/inbound.rs::resolve_recipient` then matches the
--      envelope's local part inside THAT tenant — `SELECT id FROM employees
--      WHERE slug = $1`, in that tenant's transaction. Two customers who both
--      hired a `sales` are not two unlikely customers, they are the first two.
--   5. A conversation, a turn, a draft invoice and a reply. No error anywhere.
--
-- `ConfigError::WebhookProviderTwice` already turned step 1 into a boot refusal,
-- which converts a silent misdelivery into a visible one — at the price of
-- "this deployment serves one tenant per provider", which is not multi-tenancy.
-- That refusal stays (the env map is still a `HashMap` and still collapses); it
-- stops being the whole answer, and its message now names this table.
--
-- ---------------------------------------------------------------------------
-- WHY THE PATH IS OPAQUE AND NOT `/{tenant}/{provider}`
-- ---------------------------------------------------------------------------
--
-- The obvious shape is a two-segment route, `/v1/webhooks/{tenant}/{provider}`,
-- and it was rejected for a reason that only shows up in the case this table
-- exists for.
--
-- When two tenants sit behind one provider account they hold the SAME signing
-- secret. The secret therefore cannot separate them — it authenticates the
-- provider, not the customer. What separates them is the address the provider
-- posts to, and nothing else. Under `/{tenant}/{provider}` that address is
-- derivable: tenant A's own operator knows A's uuid, and B's uuid is the only
-- thing between them and posting a signed, verifiable delivery into B's queue —
-- a uuid that appears in B's own API responses, in support threads and in every
-- audit row either of them can already see. Under an opaque path, A has 128 bits
-- of CSPRNG to guess instead.
--
-- To be exact about the claim, because the overclaim is the dangerous version:
-- **the path is not a credential and is not treated as one.** A delivery is
-- still refused unless the signature verifies. The path is the ADDRESS, and when
-- the authenticator is shared by construction, an unguessable address is
-- strictly better than a derivable one and costs one column.
--
-- The second reason is smaller and still real: a webhook URL is pasted into a
-- third party's dashboard. It lands in their request logs, their delivery
-- history, their support tooling and any screenshot of it. A tenant uuid is our
-- primary key and it correlates a customer across every system that has ever
-- seen it; `whe_…` says nothing.
--
-- The cost of opaque, stated: an operator cannot tell whose endpoint a URL is by
-- reading it. That is what `webhook_endpoints_tenant_provider_key` and the audit
-- row are for — one SELECT answers it, and the URL alone answering it was the
-- property being given up on purpose.
--
-- ---------------------------------------------------------------------------
-- WHY `sealed_secret bytea` AND NOT THE `secret_ref` THE NOTE SKETCHED
-- ---------------------------------------------------------------------------
--
-- Because `0050_tenant_model_key` has already run this experiment and paid for
-- it. A `SecretRef` points into a `SecretStore`, and the only `SecretStore` any
-- deployment wires is `mocks::secret_store()` — a `Mutex<HashMap<..>>` in the
-- server process. A restart would empty it and leave a row here claiming an
-- endpoint whose secret no longer exists, at which point every genuine delivery
-- is answered 401 and the provider retries until it disables the endpoint.
--
-- So the same shape as `mcp_servers.sealed_token` (0040) and
-- `tenant_model_access.sealed_key` (0050): the envelope blob from
-- `agentos_providers::secrets::Envelope::to_bytes`, a data key wrapped under
-- `AGENTOS_MASTER_KEY` with AAD `tenant=<id>` and the secret sealed under that
-- data key with AAD `webhook://<tenant>`.
--
-- The second AAD is the load-bearing half here, more than in either of those.
-- The lookup is by `path` alone and BYPASSES RLS, because it precedes knowing
-- the tenant — so the one thing that must be impossible is for a row to be
-- opened as a tenant other than its own, and that is precisely what this binds.
-- A blob lifted out of another tenant's row opens as nothing; a database dump is
-- not a set of signing secrets. And the `webhook://` scheme cannot collide with
-- `secret://`, `mcp://` or `model://`, so a blob copied out of
-- `mcp_servers.sealed_token` into this column opens as nothing either.
--
-- `<tenant>` and not `<tenant>/<path>`, which was the first draft and was wrong.
-- `webhook_endpoints_tenant_provider_key` gives a tenant exactly one row per
-- provider, so there is no second row of the same tenant to move a blob between
-- — the path in the AAD would defend nothing. What it *would* do is make a
-- rotation, which keeps the stored path on purpose (see the constraint below),
-- seal under a path the row does not have. `0050` seals under `model://<tenant>`
-- for the same reason and this is the same shape.
--
-- No fingerprint, no last-four, no `verified_at`. 0040's argument, unchanged: a
-- prefix of a credential is a credential, and the only question an operator has
-- is "is one set", which the row's existence answers.
--
-- ---------------------------------------------------------------------------
-- WHAT `provider` IS FOR, AND WHY IT IS CHECKED TO ONE VALUE
-- ---------------------------------------------------------------------------
--
-- Once the path is opaque it no longer names the provider, and the handler needs
-- that name: `routes::webhooks::received_event` builds `webhook.{provider}.received`
-- and `main::handlers` registers the outbox handler under exactly that string.
-- An event type with no handler is not skipped — it is retried eight times and
-- dead-lettered, which is a very quiet way to stop receiving a customer's email.
--
-- `check (provider = 'email')` is therefore not a placeholder, it is the pair of
-- the one unconditional `.on(received_event("email"), on_webhook)` in
-- `main::handlers`. There is exactly one wired ingest: `on_webhook` calls
-- `record_raw_email_notice` and parses the body as Resend JSON whatever the
-- provider column says. Telephony has a verifier
-- (`providers::telephony::verify_twilio_signature`) and no reader on the other
-- end of the queue. Widening this CHECK is a migration, and it belongs in the
-- same commit as the handler that makes it true.

create table if not exists webhook_endpoints (
  -- The `{path}` segment of `/v1/webhooks/{path}`. The primary key because it is
  -- what the lookup has and all the lookup has.
  --
  -- The pattern forbids `/`, `%`, `.` and whitespace, so a row can never make
  -- the route ambiguous or carry a traversal string, and the 16-character floor
  -- forbids a hand-typed one: a path somebody chose is a path somebody can
  -- guess, and guessability is the only separation left when two tenants share a
  -- provider account. `agentos_app::webhooks::mint_path` produces `whe_` plus 22
  -- characters of base64url.
  path          text        primary key
                            constraint webhook_endpoints_path_shape
                            check (path ~ '^[A-Za-z0-9_-]{16,64}$'),

  -- Whose deliveries these are. Written here by the platform surface, read by
  -- the ingress, and never influenced by the request: `routes::webhooks` opens
  -- `db.tenant_tx(endpoint.tenant_id)` with this value and the payload's opinion
  -- of its own tenant is ignored, which is the property
  -- `the_tenant_comes_from_the_registration_not_from_the_payload` already pins.
  tenant_id     uuid        not null references tenants (id) on delete cascade,

  -- Which ingest reads the stored row. See the CHECK's argument above.
  provider      text        not null
                            constraint webhook_endpoints_provider_is_wired
                            check (provider = 'email'),

  -- `Envelope::to_bytes`, AAD `webhook://<tenant>`. Nonempty for 0014's
  -- and 0040's reason: a sealed half that is present but empty is an endpoint
  -- that believes it has a secret and opens nothing.
  sealed_secret bytea       not null
                            constraint webhook_endpoints_secret_nonempty
                            check (octet_length(sealed_secret) > 0),

  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),

  -- One endpoint per tenant per provider, which is what makes registering twice
  -- a ROTATION rather than a second live door. `agentos_store::webhooks::register`
  -- upserts on this key and keeps the existing `path`, so replacing a signing
  -- secret does not mean re-pasting a URL at the provider — and, more to the
  -- point, does not leave the compromised secret verifying on an endpoint
  -- nobody remembers.
  constraint webhook_endpoints_tenant_provider_key unique (tenant_id, provider)
);

-- Postgres does not index a foreign key column for you, and `on delete cascade`
-- from `tenants` scans without one. Same line, same reason, as
-- `api_keys_tenant_idx`.
create index if not exists webhook_endpoints_tenant_idx
  on webhook_endpoints (tenant_id);

-- ---------------------------------------------------------------------------
-- Row-level security, and then no grants at all — 0044's shape, 0044's reason
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, so the owning role the migrations and the
-- cross-tenant loops connect as does not walk past the policy. `with check` as
-- well as `using`, so no row can be filed wearing another tenant's id.
--
-- Then: `app_role` gets nothing. Not SELECT. The two are redundant on purpose
-- and they fail differently — a tenant transaction that reaches this table dies
-- with `42501 permission denied for table webhook_endpoints`, naming the table,
-- and if some later migration grants SELECT "just so a tenant can see its own
-- endpoints" the policy is already there and it still cannot see anyone else's
-- sealed secrets.
--
-- The only reader is `agentos_store::webhooks`, which opens
-- `Db::admin_tx_bypassing_rls` because the lookup precedes knowing the tenant
-- and therefore cannot be scoped by a GUC that is not set yet. That module opens
-- the lookup transaction READ ONLY, so the escape hatch it is forced to use
-- cannot write even if somebody later adds a statement to it.

alter table webhook_endpoints enable row level security;
alter table webhook_endpoints force row level security;
drop policy if exists tenant_isolation on webhook_endpoints;
create policy tenant_isolation on webhook_endpoints
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Stated as a revoke rather than as an absence, because `grant all on all tables
-- in schema public to app_role` is one line somebody adds to a later migration
-- to unbreak something. This makes that line not enough.
revoke all on webhook_endpoints from app_role;
