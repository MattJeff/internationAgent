-- 0013_mcp: where an MCP binding comes from.
--
-- `app::mcp::McpServer::bind` takes a URL, a reach and a map of operator
-- declarations. Until now nothing produced those three things, so the whole
-- client — SSRF check, risk classes, digest pinning — was unreachable code. A
-- binding is per-tenant operator configuration, so it lives here, next to
-- `policy_layers` and `team_policy`, and for the same reasons.
--
-- Four decisions, each of them a bug that does not happen:
--
-- 1. TYPED COLUMNS, NOT A JSONB BLOB. Same argument as 0006_policy, and it is
--    sharper here: `risk` is a *limit*. A jsonb blob makes `{"risc": "read"}`
--    a tool with no declared class, and an undeclared tool is destructive —
--    which fails closed, so the typo would be invisible until an operator
--    wondered why every call wanted a human. A CHECK constraint makes the typo
--    fail at write time, in the operator's face.
--
-- 2. THE DIGEST IS THE OPERATOR'S AND NEVER ADVANCES ON ITS OWN. There is no
--    "refresh the digest" verb and no trigger that recomputes it: a moving
--    baseline turns schema drift into something you have to go hunting for,
--    and an immutable one deletes the attack class instead of detecting it. It
--    is nullable so a tenant can be migrated one tool at a time; null means the
--    class travels with the NAME alone, which is exactly the weakness
--    `app::mcp::Declaration` exists to replace.
--
-- 3. THE RUNTIME MAY READ THIS AND NOTHING ELSE. `grant select` only, like
--    `tenants` in 0001_core. An AI employee that talks an operator into
--    "adding a tool" would otherwise be one INSERT away from binding
--    `http://internal-admin/` — and the SSRF check at bind time is a check on
--    the *address*, not on who wrote the row. Operators write these tables
--    through `Db::admin_tx_bypassing_rls`, which is the operator path.
--
-- 4. `reach` IS PER BINDING AND DEFAULTS TO THE TIGHT ONE. 'public' refuses
--    loopback and RFC 1918; a sidecar MCP server is the only reason to write
--    'private', and writing it is a deliberate act recorded in a row.
--
-- No `enabled` flag: deleting the row is how a binding is turned off, and a
-- second way to mean "off" is a second way to forget one.

-- ---------------------------------------------------------------------------
-- mcp_servers: one bound endpoint per (tenant, handle)
-- ---------------------------------------------------------------------------

create table if not exists mcp_servers (
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  -- The handle an `Action::McpCall` names this server by. A `Slug` in the
  -- domain; TEXT here, and parsed on the way out — a row that does not parse is
  -- a binding that is skipped, not a binding with a mangled name.
  server      text        not null,
  url         text        not null,
  reach       text        not null default 'public',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  primary key (tenant_id, server),
  constraint mcp_servers_reach_known check (reach in ('public', 'private'))
);

-- ---------------------------------------------------------------------------
-- mcp_tool_declarations: what a human vetted, and what they vetted it on
-- ---------------------------------------------------------------------------
--
-- Keyed by tool NAME, because that is what a policy handle is — and pinned by
-- `digest`, because a name is not what an operator actually read. See the
-- `Declaration` docs in `app::mcp`.

create table if not exists mcp_tool_declarations (
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  server      text        not null,
  tool        text        not null,
  risk        text        not null,
  -- SHA-256 of the tool as it was vetted: name, description and input schema,
  -- canonicalised. Exactly 32 bytes or the row does not go in — a truncated
  -- digest that never matches would silently demote every call to "needs a
  -- human", which reads as a policy decision and is not one.
  digest      bytea,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  primary key (tenant_id, server, tool),
  constraint mcp_tool_declarations_risk_known
    check (risk in ('read', 'write', 'destructive')),
  constraint mcp_tool_declarations_digest_is_sha256
    check (digest is null or octet_length(digest) = 32),
  -- Composite, so a declaration cannot point at another tenant's server even if
  -- someone writes the tenant predicate wrong.
  constraint mcp_tool_declarations_server_fk
    foreign key (tenant_id, server) references mcp_servers (tenant_id, server)
    on delete cascade
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array['mcp_servers', 'mcp_tool_declarations']
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

-- Decision 3: read-only to the runtime.
grant select on mcp_servers, mcp_tool_declarations to app_role;
revoke insert, update, delete on mcp_servers, mcp_tool_declarations from app_role;
