-- 0040_mcp_credentials: a binding may now carry a credential.
--
-- `0013_mcp` gave a binding a URL, a reach and a set of tool declarations, and
-- `apps/server/src/routes/mcp.rs` gave an operator a door to write them. What
-- neither gave it was a way to *authenticate*, and that omission is why the
-- whole subsystem could bind exactly one class of server: the ones that need no
-- credential. GitHub's remote MCP server takes a bearer token. So does every
-- other one worth connecting. `McpServer::bind` called
-- `StreamableHttpClientTransport::from_uri`, which sets `auth_header: None`
-- explicitly, so there was no column to add a value to and no value to put in a
-- column.
--
-- One nullable column, and four decisions.
--
-- 1. SEALED, NEVER PLAINTEXT. `sealed_token` is the envelope blob from
--    `agentos_providers::secrets::Envelope::to_bytes` — a data key wrapped
--    under the deployment's master key with AAD `tenant=<id>`, and the token
--    sealed under the data key with AAD `mcp://<tenant>/<server>`. Same cipher
--    and same shape as `employee_signing_keys.sealed_private_key` in
--    0014_identity, for the same reason: a database dump is not a credential
--    leak, and a row lifted into another tenant's context fails to authenticate
--    rather than decrypting to somebody else's token.
--
--    The second AAD is what makes the column safe to *move*: a blob copied from
--    one server handle to another inside one tenant does not open either. That
--    matters because the handle is what selects the URL, so without it a
--    customer could point a credential at an endpoint it was never issued for.
--
-- 2. A COLUMN, NOT A ROW IN `employee_secrets`. There is no such table, and
--    this is not the shape of one. `agentos_providers::secrets::SecretStore` is
--    keyed on a `SecretRef`, which is `(tenant, employee, name)`, and a binding
--    has no employee: `mcp_servers`' primary key is `(tenant_id, server)` and
--    the binder loop reads a whole tenant's configuration with no seat in hand.
--    Inventing a nil employee to fit the key would put a UUID that names nobody
--    into an AAD forever. So the credential lives beside the thing it
--    authenticates, and `LocalEnvelopeSecretStore::seal_in` names the context.
--
-- 3. NULLABLE, AND NULL MEANS NO HEADER. Not "empty header": a
--    `Authorization: Bearer ` with nothing after it is a request a server may
--    answer 401 to for reasons nobody can debug. Every binding written before
--    this migration has one, which is correct — they bind exactly as they did.
--    The nonempty CHECK is the same guard 0014 puts on its sealed column: a row
--    whose sealed half is present but empty is a binding that believes it has a
--    credential and sends nothing.
--
-- 4. NO `token_fingerprint`, NO `token_last_four`, NO `updated_by`. Every one
--    of those is a column whose whole purpose is to be SELECTed into a response
--    so a UI can say "ending in 4f2a". A prefix of a credential is a prefix of
--    a credential; the requirement here is that the value never comes back at
--    all, and the cheapest way to keep a promise about what a SELECT can return
--    is for there to be nothing to return. What a UI actually needs is "is one
--    set", and `sealed_token IS NOT NULL` answers that without storing anything
--    derived from the secret.
--
-- No new GRANT. 0019_mcp_operator_writes already gave `app_role` insert/update/
-- delete on `mcp_servers`, and a column inherits the table's privileges — which
-- is the point of putting it here rather than in a table of its own that would
-- need its own RLS policy, its own grant and its own chance to get one wrong.
-- The `tenant_isolation` policy from 0013 covers this column on USING and on
-- WITH CHECK exactly as it covers `url`.
--
-- ---------------------------------------------------------------------------
-- `connector`: which catalogue entry this binding came from
-- ---------------------------------------------------------------------------
--
-- `agentos_app::catalog` is a `const` array in the binary — deliberately, see
-- its module docs — and it carries a `floor`: the lowest risk class a customer
-- may declare a tool on that connector at. Enforcing the floor means knowing
-- which entry a binding came from, and this column is the only place that can
-- remember it. Deriving it from the URL instead would be a string match against
-- a value the customer supplied, which is the same class of mistake as trusting
-- a server's own tool annotations.
--
-- NO FOREIGN KEY, AND THERE CANNOT BE ONE. The catalogue is code, not a table.
-- So the reader must tolerate a value it does not recognise, and
-- `apps/server/src/routes/mcp.rs` treats an unknown connector as `custom` — a
-- floor of `read`, which is no constraint. That is the fail-*open* direction and
-- it is chosen knowingly: the alternative is that removing an entry from the
-- catalogue in a deploy silently locks every customer out of declaring tools on
-- a binding that still works, and the floor is a coarse guard, not the security
-- boundary. The boundaries are the address check, the digest pin and
-- undeclared-means-destructive, and none of them read this column.
--
-- DEFAULT 'custom' for every row that predates this migration, which is the
-- truthful value: nobody chose a connector for them, so we make no claim about
-- them, which is exactly what `catalog::CUSTOM` means.

alter table mcp_servers
  add column if not exists sealed_token bytea,
  add column if not exists connector text not null default 'custom';

do $$
begin
  alter table mcp_servers
    add constraint mcp_servers_sealed_token_nonempty
    check (sealed_token is null or octet_length(sealed_token) > 0);
exception
  when duplicate_object then null;
end
$$;
