-- Orizn's role layers, and the tenant policy version they hang off.
--
-- This file is SQL and not a `curl` because **no route and no CLI subcommand
-- writes a tenant, role or employee row into `policy_layers`.** The only
-- non-test writer is `agentos-server policy install`, and its layer is
-- hard-coded to `'platform'`. `docs/TEAMS.md` §2 says the same thing and means
-- it: two places to write a limit is one place to forget to tighten.
--
-- Run it once, after `agentos-server policy install docs/orizn-ceiling.json`:
--
--   psql "$DATABASE_URL" -v tenant="'$TENANT_UUID'" -f docs/orizn-policy.sql
--
-- One statement, one transaction. Either the version and all five layers exist
-- or none of them do — a version with three of its five layers is a company
-- where two functions silently inherit the ceiling.
--
-- Re-running it is an error, not an update: `policy_versions_one_active_idx`
-- permits one active version per tenant. To change a number, edit the layer:
--
--   update policy_layers set max_turns_per_day = 40
--    where layer = 'role' and role_name = 'sales-development'
--      and version_id = (select id from policy_versions
--                         where tenant_id = :tenant and active);
--
-- The gate re-reads this table inside every decision's own transaction
-- (`app::gate` -> `store::policy::load`), so the update takes effect on the
-- next action rather than the next deploy.
--
-- ---------------------------------------------------------------------------
-- Why every number here is smaller than the pack's own default
-- ---------------------------------------------------------------------------
--
-- These are role layers under Orizn's ceiling, not the role packs. The packs
-- (`app::rolepack_sales`, `app::rolepack_service`) carry defaults sized for the
-- job in general; these are sized for a company with one seat per function and
-- one founder reading the output. The argument for each is in `docs/ORIZN.md`.
--
-- Three columns are absent from every row and that absence is the control:
--
--   * `allowed_calling_codes` stays `{}` everywhere. Orizn phones nobody. The
--     sales pack lists thirteen calling codes and the ceiling's empty set
--     intersects all of them away before this file is even read.
--   * `allowed_mcp_tools` stays `{}` everywhere, because Orizn has bound no MCP
--     server. When one is bound, its tools go into the ceiling first: a tool
--     named here and not there is a tool no employee can reach.
--   * `allowed_a2a_peers` stays `{}` everywhere. Selling to a company is not
--     talking to its agent.
--
-- `denied_domains` also stays `{}`, and it is the one field that *unions*
-- across layers — so a later row here can add a block, and nothing can remove
-- one.

with version as (
  insert into policy_versions (id, tenant_id, label, author, active)
       values (gen_random_uuid(), :tenant, 'orizn-v1', 'operator', true)
    returning id
),

-- Read this block as the table an operator actually decides on. Every value is
-- at or below the ceiling in `docs/orizn-ceiling.json`; `EffectivePolicy` takes
-- the minimum of each cap and the intersection of each allowlist, so a number
-- written wider than the ceiling would simply be dead rather than dangerous.
layer (
  role_name,
  spend_currency, max_per_transaction_minor, max_per_day_minor, approval_above_minor,
  allowed_channels, allowed_domains,
  max_new_contacts_per_day, max_turns_per_day
) as (values

  -- Direction: a chair, not an employee. Zero turns, no channel, no domain, no
  -- spend. Without this row the seat would inherit the ceiling, because an
  -- absent layer inherits the one above it rather than granting nothing — which
  -- is the one surprise in `store::policy::load` that costs money.
  ('direction',
   null::text, null::bigint, null::bigint, null::bigint,
   '{}'::text[], '{}'::text[],
   0, 0),

  -- Sales development: email out, internal to hand over, our own pages to read.
  -- `max_new_contacts_per_day = 0` is the pack's default and it stays: cold
  -- outreach is off until somebody can answer for the lawful basis. See
  -- docs/ORIZN.md for what raising it commits you to, and to what.
  ('sales-development',
   null, null, null, null,
   '{email,internal}', '{orizn.com}',
   0, 30),

  -- Customer success: not zero contacts, and the difference matters. Standing
  -- is computed from this employee's own *outbound* trail, so the first reply
  -- to somebody who wrote to us first is a new contact as far as the gate is
  -- concerned. Zero would produce a support seat that can only answer people it
  -- has already answered.
  ('customer-success',
   null, null, null, null,
   '{email,internal}', '{orizn.com}',
   20, 20),

  -- Growth: internal only. It has no counterparty — it reads and hands drafts
  -- to a colleague — so the zero here means what it says rather than standing
  -- in for a policy decision, and a runaway growth seat costs tokens and
  -- nothing else.
  ('growth',
   null, null, null, null,
   '{internal}', '{orizn.com}',
   0, 10),

  -- Finance: the only row with spend columns, and the only function that may
  -- propose a payment at all. $500 per transaction (the ceiling restated, so a
  -- future ceiling raise does not lift finance with it), $1,000 a day (half the
  -- ceiling: the structuring stop), and one dollar as the approval threshold,
  -- which is this layer's way of spelling *every payment goes to a person*.
  -- `allowed_domains` is empty on purpose: the only sites finance would want
  -- are the bank and the tax authority, and a role that may not change a
  -- credential cannot log in to either.
  ('finance',
   'USD', 50000, 100000, 100,
   '{email,internal}', '{}',
   5, 6)
)

insert into policy_layers (
  id, version_id, tenant_id, layer, role_name,
  spend_currency, max_per_transaction_minor, max_per_day_minor, approval_above_minor,
  allowed_channels, allowed_domains,
  max_new_contacts_per_day, max_turns_per_day
)
select gen_random_uuid(), version.id, :tenant, 'role', layer.role_name,
       layer.spend_currency, layer.max_per_transaction_minor,
       layer.max_per_day_minor, layer.approval_above_minor,
       layer.allowed_channels, layer.allowed_domains,
       layer.max_new_contacts_per_day, layer.max_turns_per_day
  from version, layer;
