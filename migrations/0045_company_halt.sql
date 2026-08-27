-- 0045_company_halt: the switch that stops a whole company, and only a human's
-- hand on it.
--
-- Until this file there was no way to stop a company. There was
-- `POST /v1/employees/{id}/suspend`, one seat at a time, and `/v1/autonomy`,
-- which *measures* what the agents did and switches nothing. So "stop
-- everything, now" was a loop over a list, in an order nobody had thought
-- about, while a turn was possibly already in flight — and the first employee
-- suspended could still be woken by the last one that had not been.
--
-- WHY THIS IS NOT A POLICY LAYER
--
-- It is the obvious idea and it is wrong, and this workspace already wrote down
-- why one level down. `crates/app/src/gate.rs` opens its order of operations
-- with:
--
--     1. Lifecycle before policy. A suspended employee is refused before any
--        policy is read. A suspension implemented as "remove its permissions"
--        leaves behind exactly the permissions nobody remembered to remove.
--
-- `max_turns_per_day: 0` on a tenant layer is precisely "remove its
-- permissions", and `docs/ORIZN.md` spends fifty lines on what that zero
-- actually produces on the `direction` seat: not a refusal but a *sink* — a
-- seat that receives and never wakes. That is the correct shape for a chair
-- that was never meant to act. It is the wrong shape for an emergency, because
-- zero turns stops turns and stops nothing else: an approval a human can still
-- click, a queued lead upload, a vertical step the initiative loop already
-- entered, and every `Authorized` an in-flight turn is about to spend all live
-- entirely outside the turn budget.
--
-- Three more reasons, each on its own sufficient:
--
-- a. INSTALLING ONE DESTROYS THE REAL ONE. There is one active tenant layer.
--    Halting by writing an empty layer overwrites the operator's, and releasing
--    the halt means writing the old one back — a *widening* write, performed
--    from a copy, by code that has to remember what the company was allowed to
--    do. The rule this repo enforces everywhere is that a lower layer can only
--    narrow. An arrangement whose release path is a widening write is an
--    arrangement where the bug is a company that comes back with more
--    permissions than it had.
--
-- b. A LAYER CANNOT SAY WHO, WHEN OR WHY. `policy_versions` records that limits
--    changed; it has no column for the person on the phone and no column for
--    the sentence they said. At this price the question after the incident is
--    "who stopped us, when, and what did not happen" — and a layer answers none
--    of the three.
--
-- c. A LAYER IS READ THROUGH `policy::load`, WHICH NEEDS AN EMPLOYEE. Its role
--    layer resolves through `team_memberships`, and the question "is this
--    company stopped" has no employee in it. The halt has to be readable before
--    there is a seat to read it for — which is exactly the moment
--    `agentos_app::model_access::connected` is asked, before a turn is
--    reserved.
--
-- So a halt is not a permission. It is a lifecycle fact about the tenant,
-- the exact twin of `employees.lifecycle = 'suspended'` one level up, and it is
-- read where that one is read: in the gate, before any policy.
--
-- ONE ROW, AND ITS ABSENCE IS THE ANSWER
--
-- `tenant_id` is the primary key. A company is halted or it is not, so there is
-- no `state` column and nothing to tie-break — the same idiom
-- `0041_tenant_model_access` argues at length, for the same reason: a nullable
-- status invites a row that means "halted, we think". Releasing deletes the
-- row. The history lives in `audit_log`, which is append-only and outlives the
-- tenant, and where a `company_halt_changed` row is written in the same
-- transaction as every insert and every delete below.
--
-- NO UPDATE, AND THAT IS THE POINT
--
-- The grant at the bottom is `select, insert, delete`. A halt cannot be edited,
-- because an edited halt is a halt whose stated reason no longer matches the
-- audit row that recorded it — and the reason is the whole evidentiary value of
-- the row. Changing your mind about why is a release and a fresh halt, which is
-- two audit rows and the truth. Re-halting an already-halted company is
-- `ON CONFLICT DO NOTHING`: the first reason stands, and the second call is
-- told it changed nothing rather than silently overwriting the first.
--
-- WHY THE APP ROLE MAY WRITE IT AT ALL
--
-- Because row-level security is what stops one tenant halting another, and RLS
-- only applies to a role it applies to. A write path through
-- `admin_tx_bypassing_rls` would put that guarantee in a `WHERE` clause some
-- future handler forgets; through `tenant_tx` it is `with check` below, and
-- Postgres enforces it whatever the handler believes. What keeps an *employee*
-- off this table is not a grant, it is that there is nothing to reach it with:
-- no `Action` variant rules on a halt, so `PolicyGate` cannot mint a token for
-- one, `Effects` exposes no method, and the only writer in the workspace is an
-- HTTP handler — and every HTTP caller is an operator key
-- (`apps/server/src/auth.rs`), never a seat.

create table if not exists company_halts (
  tenant_id  uuid        not null primary key
                         references tenants (id) on delete cascade,

  -- What the customer said. Not optional and not empty: a halt with no reason
  -- is a halt nobody can explain afterwards, and the one certainty about an
  -- emergency stop is that somebody will ask about it later. It is shown back
  -- by `GET /v1/halt` and copied into the audit row.
  reason     text        not null
                         constraint company_halts_reason_not_blank
                         check (length(btrim(reason)) > 0),

  -- The API key's label, from `auth::Principal` — the same string that becomes
  -- `operator:<label>` in `audit_log.actor`. Denormalised on purpose: the row
  -- has to be able to answer "who did this" on its own, at 3am, from a `psql`
  -- session, without joining a trail that may have millions of rows.
  halted_by  text        not null
                         constraint company_halts_by_not_blank
                         check (length(btrim(halted_by)) > 0),

  -- When the switch was thrown. This is the left edge of "what did not happen":
  -- everything refused for this company between here and the release carries
  -- `payload->>'denied' = 'company_halted'` in `audit_log`.
  halted_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------
--
-- This is the enforcement of the hardest constraint on the feature: **a tenant
-- must never be able to halt another tenant.** Not a `WHERE tenant_id = $1` in
-- a store function, which is a line a refactor can drop — a policy Postgres
-- applies to every statement.
--
-- `force` as well as `enable`, or the owning role walks past it. `with check`
-- as well as `using`, and here that half is the load-bearing one: without it a
-- handler could INSERT a row wearing another company's id and stop a business
-- it has no relationship with.
--
-- It also makes the gate's read safe by construction. `PolicyGate` asks this
-- table inside the decision's own `tenant_tx`, so the only row it can possibly
-- see is its own tenant's, and a halt on one company cannot deny an action for
-- another even if the query were written wrong.

alter table company_halts enable row level security;
alter table company_halts force row level security;
drop policy if exists tenant_isolation on company_halts;
create policy tenant_isolation on company_halts
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- SELECT for the gate and for the turn's own pre-flight check, INSERT to halt,
-- DELETE to release. See the header for why UPDATE is not here.
grant select, insert, delete on company_halts to app_role;
revoke update on company_halts from app_role;
