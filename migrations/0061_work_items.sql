-- 0061_work_items: le carnet — one piece of work that outlives the turn that
-- wrote it down.
--
-- Until now work reached an employee two ways and neither of them kept: its own
-- cadence (`apps/server/src/loops/initiative.rs`, which recomputes
-- `Charter::brief` from scratch every tick and stores nothing) or a message
-- somebody sent it (`apps/server/src/loops/inbound.rs`). Three consequences,
-- each of which this table is the smallest answer to:
--
--   1. **An employee could not put something down and pick it back up.** The
--      only per-employee state that survived a turn boundary was
--      `psyche_*` (who to chase and how to phrase it) and `inbound::unanswered`
--      (questions I asked that nothing has answered) — and the second needs a
--      *colleague*, because `inbound::send` refuses `from == to` so that an
--      employee cannot wake itself forever.
--   2. **Two employees could not share one board.** `a2a_tasks` (0005) is one
--      row per inbound JSON-RPC message with `task jsonb` and no assignee, no
--      claim and no state an employee drives; the internal channel (0028) names
--      its recipient at INSERT and 0028 says in as many words that "nothing
--      records that an order was carried out".
--   3. **The founder could not reorder anything.** He approves or refuses
--      (`approvals`), sets a cadence (`employee_initiative`) and exports a CSV
--      (`routes::queue`). There is no column anywhere in this schema an
--      operator can write to say *this before that*, and `ordinal` below is it.
--
-- ---------------------------------------------------------------------------
-- WHAT A WORK ITEM IS, AND THE FIVE COLUMNS IT IS NOT
-- ---------------------------------------------------------------------------
--
-- A title, who has it, where it sits in the founder's order, and whether it is
-- done. That is the whole row, and the bar for a sixth column is that one of
-- the three failures above stays unfixed without it.
--
-- Deliberately absent, each one a thing Jira has and this is not:
--
--   * **No description.** A title an employee can act on is a title; one that
--     needs a paragraph underneath is two items.
--   * **No due date and no expiry.** There is no number to put in one. An item
--     nobody has done is still wanted, and a row that deleted itself on a date
--     would be the founder's instruction disappearing without anyone deciding.
--   * **No priority enum.** `ordinal` is the priority, it is a total order the
--     founder writes, and a second ranked field would be two answers to one
--     question.
--   * **No status beyond open/closed.** "In progress" is `assignee_id is not
--     null`, and nothing else in this workspace could read a third state.
--   * **No parent, no labels, no estimate.** Nothing reads them.
--
-- ---------------------------------------------------------------------------
-- WHY `ordinal` HAS NO DEFAULT, AND WHY THAT IS THE POINT
-- ---------------------------------------------------------------------------
--
-- It is nullable and nothing invents one. A default would be a number this
-- migration made up — 0, or a max()+1 that silently makes arrival order into
-- priority order and hides the fact that nobody has ranked anything.
--
-- So the read order is `ordinal asc nulls last, created_at asc`: an item the
-- founder has ranked comes first in the order he chose, and everything he has
-- not ranked follows in the order it arrived. `nulls last` and not `nulls
-- first`, because an unranked item is one nobody has said is urgent.
--
-- FOUNDER'S QUESTION, LEFT OPEN: nothing here spaces the integers, so inserting
-- between two adjacent ranks means renumbering by hand through
-- `PATCH /v1/work/{id}`. The fix when that stings is a fractional or gapped
-- rank, and it is a migration on this column alone.
--
-- ---------------------------------------------------------------------------
-- WHY `assignee_id` IS NULLABLE, WHICH IS THE WHOLE OF "SHARED"
-- ---------------------------------------------------------------------------
--
-- A null assignee is an item on the board that is nobody's yet. That single
-- nullable column is the difference between a board and N private lists, and it
-- is what failure 2 above is about: the founder can write down work before he
-- has decided which seat does it, and move it between seats afterwards without
-- rewriting it.
--
-- `on delete set null` and not `cascade`: an employee being terminated must not
-- delete the work it was holding. The item goes back on the board unassigned,
-- which is the correct reading of "the person who had this has left".
--
-- ---------------------------------------------------------------------------
-- CLOSED IS A TIMESTAMP AND THERE IS NO DELETE
-- ---------------------------------------------------------------------------
--
-- `closed_at is null` is open. A timestamp rather than a boolean because "when
-- did this stop being work" is the question a founder asks a week later and a
-- boolean cannot answer it, and it costs the same eight bytes a boolean would
-- round up to anyway.
--
-- `app_role` gets SELECT, INSERT and UPDATE and **no DELETE**, which is the
-- shape `suppressions` (0011) and `prospect_flow_proposals` (0037) already use.
-- The reason, written down because the grant is what enforces it: a closed item
-- is the record that somebody asked for something and it was dealt with.
-- Deleting it destroys the only evidence the request ever existed, and the row
-- it would be deleted by is indistinguishable from the row that would delete an
-- item somebody found inconvenient. Closing is free; forgetting is not offered.

create table if not exists work_items (
  id          uuid        primary key,

  -- Whose board. Written by the caller's transaction and never by the payload,
  -- like every other tenant column here; the policy below is what enforces it.
  tenant_id   uuid        not null references tenants (id) on delete cascade,

  -- What to do, in one line, in the founder's own words.
  --
  -- Trimmed and bounded. The upper bound is 200 and it is borrowed rather than
  -- invented: `a2a_tasks_id_length` (0005) already fixed 200 as this schema's
  -- answer to "how long may a caller-supplied identifier-ish string be", and a
  -- second number here would be a second answer. The floor is what stops an
  -- empty item appearing on a board and in a prompt as a blank line.
  title       text        not null
                          constraint work_items_title_shape
                          check (char_length(btrim(title)) between 1 and 200),

  -- Who is holding it. Null is the shared board — see above.
  assignee_id uuid        references employees (id) on delete set null,

  -- The founder's order. Null is unranked; see above for why there is no
  -- default and what the read order does with it.
  ordinal     bigint,

  -- Null while it is still work.
  closed_at   timestamptz,

  created_at  timestamptz not null default now()
);

-- Postgres does not index a foreign key column for you, and `on delete cascade`
-- from `tenants` scans without one. Same line, same reason, as
-- `webhook_endpoints_tenant_idx` (0053). It is also the index both reads use —
-- the founder's whole board and one employee's open items are each a scan of one
-- tenant's rows, sorted in memory.
--
-- ponytail: no index on `(tenant_id, assignee_id, ordinal) where closed_at is
-- null`. A board is a thing a human types into by hand; add the covering index
-- the day one has enough rows for the sort to show up in a plan.
create index if not exists work_items_tenant_idx
  on work_items (tenant_id);

-- And the second foreign key, for the same reason: `on delete set null` from
-- `employees` scans this table by `assignee_id`, which the index above cannot
-- serve.
create index if not exists work_items_assignee_idx
  on work_items (assignee_id);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, so the owning role the migrations and the
-- cross-tenant loops connect as does not walk past the policy — `enable` alone
-- binds `app_role` and lets the owner read everything, which is exactly the
-- reader an employee's board must not have. `with check` as well as `using`, so
-- no item can be filed wearing another tenant's id.

alter table work_items enable row level security;
alter table work_items force row level security;
drop policy if exists tenant_isolation on work_items;
create policy tenant_isolation on work_items
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- No DELETE. See the header: closing is a column, forgetting is not a verb.
grant select, insert, update on work_items to app_role;
