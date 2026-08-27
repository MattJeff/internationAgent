-- 0042_mcp_oauth: a binding may now be obtained by consent instead of a paste.
--
-- `0040_mcp_credentials` gave a binding one sealed string and said the honest
-- thing about the limit: it works for GitHub, whose remote MCP server takes a
-- personal access token, and for nothing else. Notion, Linear, Sentry,
-- Atlassian, Stripe, Cloudflare and everything of Google's are OAuth, so the
-- catalogue could hold exactly one entry and the reason was never the MCP
-- client — `McpServer::bind` sends `Authorization: Bearer <string>` and has no
-- opinion about where the string came from.
--
-- This migration is what makes the string obtainable without a customer going
-- to mint one by hand. Two columns and one table.
--
-- ---------------------------------------------------------------------------
-- mcp_servers: two columns, because an access token expires and a paste does not
-- ---------------------------------------------------------------------------
--
-- 1. NO NEW COLUMN FOR THE ACCESS TOKEN. It goes in `sealed_token`, the column
--    0040 created, under the same AAD, and `Fleet::bind` opens it without
--    knowing which kind it was. That is the whole reason this change is small:
--    OAuth is a way of *obtaining* a bearer token, not a second kind of
--    credential, and a `sealed_oauth_token` beside `sealed_token` would have
--    forked every reader in the subsystem to serve a distinction that does not
--    exist on the wire.
--
-- 2. `sealed_refresh_token` IS A SECOND ENVELOPE, UNDER A DIFFERENT AAD.
--    `mcp-refresh://<tenant>/<server>`, where the access token's is
--    `mcp://<tenant>/<server>` — see `app::oauth::refresh_context`. Two blobs of
--    the same shape in two columns of one row is exactly the situation where a
--    mistyped UPDATE swaps them, and distinct additional data turns that into a
--    `secret_decrypt_failed` at the moment of the swap rather than a 401 from a
--    third party a week later that nobody can trace back to a query.
--
--    NULL means "this binding cannot outlive its access token". Some providers
--    issue no refresh token, and that is a fact about the binding worth being
--    able to represent: it surfaces as an ordinary bind failure when the token
--    dies, not as a silent stop.
--
-- 3. `token_expires_at` IS THE ONLY SCHEDULING STATE, AND IT IS NOT A SCHEDULE.
--    The binder loop in `apps/server/src/routes/mcp.rs` already wakes every five
--    minutes for every tenant; `app::oauth::refresh_due` is a step inside that
--    tick, and this column is what it filters on. There is no `next_refresh_at`,
--    no job row and no second clock — two clocks over one credential is how a
--    token is refreshed by one task while another binds with the copy it read a
--    moment earlier, and the symptom is a 401 that reproduces for nobody.
--
--    NULL is the truthful value for every row written before this migration and
--    for every pasted bearer: those do not expire as far as we know, and the
--    refresh query requires the column to be NOT NULL precisely so that "we were
--    never told" cannot be mistaken for "it expires now".
--
-- 4. STILL NO `token_last_four`, NO FINGERPRINT, NO `granted_scopes`. 0040
--    decision 4 argued the first two and the argument did not change. The third
--    is new and refused for the same reason in a different direction: what a
--    provider granted is *their* record, we would be storing a stale copy of it,
--    and a UI showing "you granted X" from our copy would be reassuring and
--    occasionally wrong. What the customer is owed is the scope string we
--    *asked* for, which is a `const` in the binary and needs no column.

alter table mcp_servers
  add column if not exists sealed_refresh_token bytea,
  add column if not exists token_expires_at timestamptz;

do $$
begin
  alter table mcp_servers
    add constraint mcp_servers_sealed_refresh_token_nonempty
    check (sealed_refresh_token is null or octet_length(sealed_refresh_token) > 0);
exception
  when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- mcp_oauth_flows: the only thing that ties a public callback to a tenant
-- ---------------------------------------------------------------------------
--
-- The provider redirects a *browser* back to us. A browser holds no API key, so
-- `GET /v1/mcp/oauth/callback` is unauthenticated and anybody on the internet
-- can call it. One row in this table is the entire answer to "whose flow is
-- this", and every decision below is about making that answer unforgeable.
--
-- 1. THE PRIMARY KEY IS sha256(state), NOT THE STATE. The `state` parameter is
--    a capability: whoever holds it can complete somebody's connection. It
--    travels in a browser address bar and lands in history, and storing it here
--    would mean read access to this table is the ability to finish any pending
--    flow. Hashing costs nothing — the callback has the raw value and hashes it
--    to look the row up — and it is the same reason a password is not stored.
--
--    32 bytes, checked, because a `bytea` primary key of the wrong length is a
--    row that can never be found and a flow that silently never completes.
--
--    It is keyed GLOBALLY and not per tenant, deliberately: the lookup happens
--    before there is a tenant to scope to. That is the same position
--    `routes::webhooks` is in and it is why `state` needs 256 bits of entropy
--    rather than a sequence.
--
-- 2. `tenant_id` IS READ, NEVER WRITTEN BY THE CALLBACK. It is set by
--    `POST /v1/mcp/oauth/start`, which runs inside a tenant transaction under an
--    API key, and the callback only ever selects it. A tenant in a query string
--    would let a stranger point their own provider account at somebody else's
--    company — every task that tenant runs through the connector executing in
--    the attacker's workspace. `routes::webhooks::Endpoint::tenant_id` carries
--    the same sentence for the same reason.
--
-- 3. `consumed_at` MAKES IT SINGLE USE, AND THE CLAIM IS AN UPDATE.
--    `update … set consumed_at = now() where state_hash = $1 and consumed_at is
--    null returning …` is atomic, so two callbacks racing on one state produce
--    one winner and one 404. The claim commits *before* the token exchange, so a
--    crash mid-exchange cannot leave a replayable state — the cost is that a
--    failed exchange burns the flow and the customer clicks connect again, which
--    is the right direction to be wrong in.
--
--    A row is kept after it is consumed rather than deleted, so that a replay
--    can be *observed* rather than looking identical to an expired one.
--
-- 4. `sealed_verifier` IS THE PKCE HALF, AND IT IS SEALED.
--    `mcp-oauth://<tenant>/<hex state_hash>` is its AAD, which binds it to the
--    one flow it belongs to: a verifier blob copied from another row of this
--    table — same tenant, same connector — does not open. So an attacker who can
--    write here still cannot pair a verifier they know with a state they chose.
--
-- 5. `redirect_uri` IS STORED, NOT REBUILT. RFC 6749 requires the token request
--    to repeat the exact redirect URI the authorization request used, and
--    rebuilding it at the callback means a deployment that changed `PUBLIC_HOST`
--    between the two halves of a flow fails with `invalid_grant` — a provider
--    error message that names nothing on our side. One column, one value, sent
--    twice.
--
-- 6. NO `code` COLUMN AND NO `access_token` COLUMN. The authorization code is
--    used in the same request it arrives in and is never written down. The
--    tokens belong to `mcp_servers`, which is the row that authenticates a
--    binding; putting a copy here would be a second place to leak them from and
--    a second place to forget to delete.

create table if not exists mcp_oauth_flows (
  -- sha256 of the `state` parameter. See decision 1.
  state_hash    bytea       not null,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  -- The catalogue key the flow was started for. TEXT and no foreign key, for
  -- the reason 0040 gives about `mcp_servers.connector`: the catalogue is a
  -- `const` in the binary, not a table.
  connector     text        not null,
  -- The handle the resulting binding will be stored under.
  server        text        not null,
  sealed_verifier bytea     not null,
  redirect_uri  text        not null,
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  consumed_at   timestamptz,
  primary key (state_hash),
  constraint mcp_oauth_flows_state_hash_is_sha256
    check (octet_length(state_hash) = 32),
  constraint mcp_oauth_flows_sealed_verifier_nonempty
    check (octet_length(sealed_verifier) > 0)
);

-- Row-level security, same shape as 0013_mcp. The callback reads this table
-- through `admin_tx_bypassing_rls` — which is legitimate and is the third case
-- of it in this file's subsystem, for the reason `rebind_all` gives: there is no
-- tenant to scope to until the query answers.
alter table mcp_oauth_flows enable row level security;
alter table mcp_oauth_flows force row level security;
drop policy if exists tenant_isolation on mcp_oauth_flows;
create policy tenant_isolation on mcp_oauth_flows
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- SELECT, INSERT and DELETE, and deliberately NOT UPDATE.
--
-- `start` inserts. It also deletes this tenant's own expired rows on the way
-- through, which is why there is no reaper job: the table is written once per
-- connect attempt and a tenant's dead rows are collected the next time that
-- tenant connects anything.
--
-- No UPDATE is the interesting one. Marking a flow consumed is the single-use
-- claim in decision 3, and it happens in the admin transaction only. Withholding
-- the privilege here means the whole tenant-facing surface — every route, every
-- loop, anything holding an API key — structurally cannot un-consume a flow or
-- consume one it did not start. That is the same construction 0013 used when it
-- granted the runtime `select` and nothing else.
grant select, insert, delete on mcp_oauth_flows to app_role;
revoke update on mcp_oauth_flows from app_role;

-- The reaper's predicate and the claim's are both covered: the claim is by
-- primary key, and the delete is `tenant_id = … and expires_at < now()`, which
-- RLS has already narrowed to one tenant's rows. No index — a tenant has a
-- handful of pending flows at a time, and an index on a table that is emptied
-- by its own writer is maintenance for a sequential scan of nothing.
--
-- ponytail: a tenant that starts flows and never finishes them keeps rows until
-- its next successful connect. The ceiling is a few hundred rows per tenant and
-- the upgrade is one `delete … where expires_at < now()` in the binder loop, the
-- day a deployment sees a table worth measuring.
