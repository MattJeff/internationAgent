-- 0025_positions: what a team is for, and who answers to whom.
--
-- 0012_org gave a tenant teams and sections. What it could not express is the
-- org chart an operator actually draws:
--
--   | Fonction              | Responsable     | Mission                        |
--   | Growth                | Head of Growth  | Acquisition, contenu, SEO       |
--
-- Three columns. The first is a `teams` row and already existed. The other two
-- are this migration, and neither of them gets a mechanism of its own.
--
-- 1. THE MISSION IS A COLUMN ON THE TEAM, NOT A TABLE. It is one nullable
--    string per team: what this function is for, in the operator's words. It is
--    never a counterparty's words, and it is never a limit — a mission is
--    prose an employee is told, and every restriction still lives in
--    `policy_layers` where the loader can intersect it. There is no CHECK on
--    the text: the guard is `domain::org::Mission::parse`, which runs on the
--    way in AND on the way back out (`store::org::mission`), exactly as
--    `employee_charters.objective` is re-parsed rather than deserialised. A
--    mission that comes back from this column unparsed is a mission that can
--    say anything.
--
-- 2. A POSITION IS TWO COLUMNS ON THE MEMBERSHIP, NOT A NEW ROW. A membership
--    already says *which team* an employee belongs to and is already unique per
--    employee (`team_memberships`' primary key). A position is that same seat
--    plus the two facts it was missing: what the seat is called (`title` —
--    "Head of Growth", "CFO externalisé") and who the person in it answers to
--    (`reports_to`). A separate `positions` table would be a second
--    employee -> team edge that could disagree with the first one, and the
--    policy loader reads that edge on every gate decision.
--
--    So an employee holds at most one seat, because it is on at most one team.
--    "CEO" is the seat whose `reports_to` is NULL: a seat with nobody above it,
--    not a special kind of row.
--
-- 3. `reports_to` POINTS AT A SEAT, NOT AT AN EMPLOYEE. The foreign key targets
--    `team_memberships (tenant_id, employee_id)` — the primary key of this very
--    table — and it buys three things in one line:
--
--      * a manager is in the same tenant (the tenant_id is in the key), so one
--        company's org chart cannot name another company's staff;
--      * a manager holds a seat, so nobody reports into thin air;
--      * ON DELETE NO ACTION, so removing a head that still has reports FAILS
--        rather than silently leaving them pointing at a seat that is gone.
--        Loud is the whole requirement: an org chart that quietly orphans half
--        a department is worse than one that refuses to change.
--
--    Deleting a *tenant* still works: the cascade removes the reports' rows in
--    the same statement, and a NO ACTION check is made at the end of it.
--
-- 4. A CYCLE IS IMPOSSIBLE, AND THE DATABASE IS WHERE THAT IS TRUE. A CHECK
--    cannot see other rows, so the acyclicity guard is the trigger below: it
--    walks up from the proposed manager and refuses if it arrives back at the
--    employee. In the trigger rather than in the writer, because a rule that
--    lives in one Rust function is a rule the next writer — a fixture, a
--    backfill, a psql session — does not have.
--
--    Reporting to yourself is the one-link case of exactly that, and it is
--    deliberately NOT a separate CHECK constraint: the walk starts at the
--    proposed manager, so a self-reference is caught by the same code, with the
--    same SQLSTATE, and a caller has one refusal to render instead of two.
--
-- WHAT IS DELIBERATELY NOT HERE: any column that grants anything. `reports_to`
-- is not a policy layer, there is no `is_head` flag anybody could read as a
-- permission, and nothing in this file is joined by `store::policy::load`.
-- Seniority decides who may direct whom; it can never decide what a principal
-- may do. See `crates/app/src/vertical.rs` (the delegation section) and
-- `crates/domain/src/org.rs`.
--
-- Replayable: IF NOT EXISTS / OR REPLACE throughout, and the foreign key is
-- added inside a guard because ALTER TABLE ... ADD CONSTRAINT has no
-- IF NOT EXISTS.

-- ---------------------------------------------------------------------------
-- The mission: the third column of the operator's table
-- ---------------------------------------------------------------------------

alter table teams add column if not exists mission text;

-- ---------------------------------------------------------------------------
-- The position: the second column
-- ---------------------------------------------------------------------------

alter table team_memberships add column if not exists title text;
alter table team_memberships add column if not exists reports_to uuid;

do $$
begin
  -- See decision 3. MATCH SIMPLE, so a NULL `reports_to` — the CEO — skips the
  -- check entirely rather than needing an exemption.
  if not exists (select 1 from pg_constraint where conname = 'team_memberships_reports_to_fk') then
    alter table team_memberships
      add constraint team_memberships_reports_to_fk
      foreign key (tenant_id, reports_to)
      references team_memberships (tenant_id, employee_id);
  end if;
end
$$;

-- "who reports to this head", the org-chart query, and the index the foreign
-- key above uses to answer a delete.
create index if not exists team_memberships_reports_to_idx
  on team_memberships (tenant_id, reports_to);

-- ---------------------------------------------------------------------------
-- Acyclicity
-- ---------------------------------------------------------------------------
--
-- One writer per tenant at a time: without the advisory lock two transactions
-- can each walk a chart that does not yet contain the other's new line and both
-- pass, which is precisely how a two-edge cycle gets in. Org charts are written
-- by humans a few times a year, so serialising them costs nothing measurable.
--
-- The depth bound is insurance rather than a rule: the data this trigger
-- protects is a forest, so the walk terminates on its own. It only matters if a
-- cycle ever did get in — then the walk would not terminate, and an infinite
-- loop inside a trigger is a database nobody can write to.

create or replace function team_memberships_reports_to_acyclic() returns trigger
language plpgsql as $$
declare
  closes_loop boolean;
begin
  if new.reports_to is null then
    return new;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 0));

  with recursive up as (
      select new.reports_to as employee_id, 1 as depth
    union all
      select m.reports_to, up.depth + 1
        from team_memberships m
        join up on up.employee_id = m.employee_id
       where m.tenant_id = new.tenant_id
         and m.reports_to is not null
         and up.depth < 64
  )
  select bool_or(employee_id = new.employee_id) into closes_loop from up;

  if coalesce(closes_loop, false) then
    raise exception
      'employee % cannot report to %: that closes a loop in the org chart',
      new.employee_id, new.reports_to
      using errcode = 'ORG01';
  end if;

  return new;
end;
$$;

drop trigger if exists team_memberships_acyclic on team_memberships;
create trigger team_memberships_acyclic
  before insert or update of reports_to on team_memberships
  for each row execute function team_memberships_reports_to_acyclic();

-- ---------------------------------------------------------------------------
-- Grants and row-level security
-- ---------------------------------------------------------------------------
--
-- Nothing to do, and that is the point of putting these columns on tables that
-- already exist: `teams` and `team_memberships` carry ENABLE + FORCE row level
-- security and their `tenant_isolation` policy from 0012_org, and table-level
-- grants cover columns added later. One tenant's org chart is invisible to
-- another for the same reason its teams already were.
