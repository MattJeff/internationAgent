-- 0049_capability_requests: an employee that is missing a tool, and the one row
-- a human writes back.
--
-- The approval half of this product exists: `approvals` binds a human's click to
-- the hash of one action and `PolicyGate::redeem_approval` re-checks it. The
-- other half did not. An employee that discovers it is missing a capability is
-- refused by the gate, writes a sentence in its answer that nobody reads, and
-- tries again tomorrow. This migration is the smallest thing that closes it.
--
-- WHAT IS NOT HERE, AND THAT IS THE DESIGN
--
-- There is no `capability_requests` table. A request is not stored, because a
-- stored request is a request somebody had to *write*, and the only two things
-- that could write one are the employee — which is a model composing a sentence
-- about its own permissions, from a turn whose context may include a page a
-- stranger wrote — or the gate, on the hot path of every refusal.
--
-- A request is instead **derived**, from `audit_log`, which already holds every
-- refusal the gate has ever made: the tenant, the employee, the action kind, the
-- decision and the deny reason code, one row per ruling, append-only, written
-- inside the ruling's own transaction. `crates/store/src/capability.rs` is one
-- aggregate over it. So:
--
--   * a request cannot claim a refusal that did not happen — there is no INSERT
--     in the shape of "I would like X", only a GROUP BY over what the gate did;
--   * an employee that hits the same wall a hundred times produces one row,
--     because grouping is what a GROUP BY does and there is no counter to
--     maintain, no dedupe window, and no state machine;
--   * nothing is written when an employee is denied, so the feature costs the
--     refusal path exactly nothing.
--
-- The table below is therefore only the half that cannot be derived: **what a
-- human decided**. One row per (employee, action kind, deny reason), which is
-- the grouping key of the aggregate — a request has no id of its own because it
-- is a shape, not a record.
--
-- WHAT AN APPROVAL DOES NOT DO
--
-- It does not widen a policy. `apps/server/src/routes/companies.rs` states the
-- arithmetic this rests on: an absent layer inherits, so writing a layer where
-- none existed takes the effective policy from `above ∧ above` to `above ∧ new`
-- and cannot widen anything — while *replacing* a layer has no such property,
-- because the new layer is not intersected with the old one. Every remedy a
-- capability request asks for is the second kind: adding a tool to
-- `allowed_mcp_tools` on a layer that already names some is exactly the write
-- that widens the intersection. So there is no code path from this table to
-- `policy_layers`, and there is no column here that a policy loader reads.
--
-- A granted request is a recorded intention plus the operator command to carry
-- it out, on the operator's own database credential — the same trade
-- `crates/store/src/revenue.rs`'s `set_prospect_flow` makes for selectors, and
-- for the same reason: the write that matters is an operator's act, proved by a
-- credential no employee holds.
--
-- WHY THE APP ROLE MAY WRITE THIS AT ALL
--
-- Because row-level security is what keeps one tenant out of another's, and RLS
-- only binds a role it applies to. Every writer is an HTTP handler and every
-- HTTP caller is an operator key (`apps/server/src/auth.rs`), never a seat: no
-- `Action` variant rules on a capability decision, so `PolicyGate` cannot mint a
-- token for one and `Effects` exposes no method that reaches here.

-- The target of the composite foreign key below, created first because a
-- `references` clause needs its unique index to already exist. `employees.id` is
-- already unique on its own, so this adds no constraint the table did not have —
-- it only makes the pair addressable.
create unique index if not exists employees_tenant_id_key on employees (tenant_id, id);

create table if not exists capability_decisions (
  tenant_id        uuid        not null,
  employee_id      uuid        not null,

  -- `ActionKind::as_str` and `DenyReason::code` — two closed enums, fifteen and
  -- twenty-one values, both written by this binary and never by a counterparty.
  -- That is the containment: the whole vocabulary of a capability request is a
  -- pair drawn from two `const` arrays, so no byte an MCP server or a web page
  -- authored can reach the text a human reads. It is also why there is no
  -- `tool_name` and no `domain` column here — see `capability.rs`.
  action_kind      text        not null,
  deny_reason_code text        not null,

  -- `granted` or `refused`. Both suppress the request until it is hit again;
  -- they differ in what the trail says a human decided, which is the point.
  outcome          text        not null
                               constraint capability_decisions_outcome
                               check (outcome in ('granted', 'refused')),

  -- The API key's label, from `auth::Principal` — the same string that becomes
  -- `operator:<label>` in `audit_log.actor`. Denormalised for the reason
  -- `0045_company_halt.sql` gives: the row answers "who decided this" on its own
  -- from a psql session, without joining a trail of millions.
  decided_by       text        not null
                               constraint capability_decisions_by_not_blank
                               check (length(btrim(decided_by)) > 0),
  decided_at       timestamptz not null default now(),

  -- The operator's own sentence. First-party prose, from an authenticated
  -- request body, exactly like `company_halts.reason` and `approvals`'
  -- `decision_note`. Nothing a model or a counterparty wrote reaches this
  -- column: no code path writes it but the decide handler.
  note             text,

  primary key (tenant_id, employee_id, action_kind, deny_reason_code),

  -- Composite, so the pair is checked by Postgres rather than by a handler: a
  -- decision cannot name an employee of another tenant even if RLS's `with
  -- check` — which only sees `tenant_id` — were satisfied. It needs the unique
  -- index created just above, which `employees` did not have; its primary key is
  -- `id` alone and `(tenant_id, slug)` is the only other unique thing on it.
  constraint capability_decisions_employee_fkey
    foreign key (tenant_id, employee_id) references employees (tenant_id, id)
    on delete cascade
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------
--
-- The hardest constraint on this feature is that an employee must never create,
-- approve or influence a request for another tenant. Two things enforce it and
-- neither is a `WHERE` clause a refactor can drop:
--
--   * this policy, on every statement, for reads and writes alike;
--   * the aggregate in `capability.rs` reads `audit_log` through the same
--     tenant transaction, so the list a tenant can see is bounded by the
--     refusals its own gate made — and the decide handler will not write a row
--     unless that same restricted read finds the refusal it names.
--
-- `force` as well as `enable`, or the owning role walks past it. `with check` as
-- well as `using`, because without it a handler could write a row wearing
-- another company's id.

alter table capability_decisions enable row level security;
alter table capability_decisions force row level security;
drop policy if exists tenant_isolation on capability_decisions;
create policy tenant_isolation on capability_decisions
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- SELECT to show the decision beside the request, INSERT and UPDATE for the
-- upsert that records one. No DELETE: a decision that can be removed is a
-- decision nobody can be shown to have made. Changing your mind is a second
-- decision, which overwrites the row and leaves both in `audit_log` — the same
-- arrangement `0045_company_halt.sql` argues for a halt, read the other way
-- round, because here the current answer is the one the queue has to apply.
grant select, insert, update on capability_decisions to app_role;
revoke delete on capability_decisions from app_role;

-- The aggregate scans denials for one tenant. `audit_log_tenant_time_idx` orders
-- by time and this one narrows to the rows that can possibly be requests, which
-- is a small fraction of a trail dominated by `allow`.
create index if not exists audit_log_denials_idx
  on audit_log (tenant_id, employee_id, action_kind, deny_reason_code)
  where decision = 'deny';
