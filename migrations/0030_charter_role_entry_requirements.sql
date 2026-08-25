-- 0030_charter_role_entry_requirements: the company can hire someone to keep
-- the product right.
--
-- Five of the seats in `docs/TEAMS.md` §7 have a role pack and none of them
-- maintains the entry-requirement data itself — which is the thing this company
-- sells. `crates/app/src/rolepack_service.rs` adds
-- `RolePack::entry_requirements`; this is the other half of that sentence,
-- because a role the CHECK refuses is a role no employee can be hired into.
--
-- WHY A NEW FILE RATHER THAN AN EDIT TO 0029
--
-- 0029's own reasoning, unchanged and now demonstrated twice: `sqlx::migrate!`
-- checksums every file it has already applied, so editing 0029_charter_roles.sql
-- would turn every existing database into a migration failure at startup — a
-- schema change delivered as an outage. The constraint is dropped and recreated
-- here, which is also the only form of this change that reads as a diff a year
-- from now.
--
-- WHY THE LIST IS STILL A CHECK AND NOT A LOOKUP TABLE
--
-- 0018's decision 2 and 0029's restatement of it: these strings are
-- `RolePack::name()`, they exist in the *binary*, and a `roles` table would let
-- an operator insert a row naming a pack this build does not have. The failure
-- would then be a charter that saves and cannot load. The list belongs where the
-- deploy is, and a migration is where the deploy is.
--
-- The new name is `rolepack_service::ENTRY_REQUIREMENTS`, and
-- `vertical::Charter::of` is the match that reads it back —
-- `vertical::tests::every_pack_round_trips_through_its_name` is what notices
-- when the three drift apart.
--
-- No data migration: this constraint only ever widens, so every existing row
-- still satisfies it and there is nothing to backfill. Nothing is rewritten
-- either — a widened CHECK is validated against the table, and `employee_charters`
-- has one row per employee.
--
-- Replayable: the drop is IF EXISTS and the constraint is recreated whole.

alter table employee_charters
  drop constraint if exists employee_charters_role;

alter table employee_charters
  add constraint employee_charters_role check (role in (
    'international-buyer',
    'sales-development',
    'customer-success',
    'growth',
    'finance',
    'entry-requirements'
  ));
