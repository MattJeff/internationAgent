-- 0073_charter_role_engineering: the company can hire somebody to write the
-- software.
--
-- `docs/TEAMS.md` §7 draws seven functions and one of them is "Produit et
-- technologie — produit, code, infrastructure, sécurité". Six of the seats in
-- that table have a role pack; the one that touches the code did not, which is
-- the founder's own observation ("on n'a pas d'équipe de développeurs non plus,
-- on en a besoin pour les entreprises") written as a missing row.
-- `crates/app/src/rolepack_service.rs` adds `RolePack::engineering`; this is the
-- other half of that sentence, because a role the CHECK refuses is a role no
-- employee can be hired into.
--
-- WHY A NEW FILE RATHER THAN AN EDIT TO 0030
--
-- 0029's reasoning, restated by 0030 and now demonstrated a third time:
-- `sqlx::migrate!` checksums every file it has already applied, so editing
-- 0030_charter_role_entry_requirements.sql would turn every existing database
-- into a migration failure at startup — a schema change delivered as an outage.
-- The constraint is dropped and recreated here, which is also the only form of
-- this change that reads as a diff a year from now.
--
-- WHY THE LIST IS STILL A CHECK AND NOT A LOOKUP TABLE
--
-- 0018's decision 2, restated by 0029 and 0030: these strings are
-- `RolePack::name()`, they exist in the *binary*, and a `roles` table would let
-- an operator insert a row naming a pack this build does not have. The failure
-- would then be a charter that saves and cannot load. The list belongs where the
-- deploy is, and a migration is where the deploy is.
--
-- WHAT THIS ROW DOES NOT GRANT
--
-- Nothing. A CHECK decides which strings the `role` column accepts and has no
-- opinion about what the seat may do — that is `RolePack::engineering`'s
-- `proposable` set and the four policy layers under it, and the pack ships with
-- an empty `allowed_mcp_tools`, so an employee hired into this role can reach no
-- repository at all until an operator names a tool in a policy layer. Widening
-- this constraint is the narrowest possible change: it makes the seat
-- *expressible*, and every permission it will ever hold is written somewhere
-- else.
--
-- The new name is `rolepack_service::ENGINEERING`, and `vertical::Charter::of`
-- is the match that reads it back —
-- `vertical::tests::every_pack_round_trips_through_its_name` is what notices
-- when the three drift apart.
--
-- No data migration: this constraint only ever widens, so every existing row
-- still satisfies it and there is nothing to backfill. Nothing is rewritten
-- either — a widened CHECK is validated against the table, and
-- `employee_charters` has one row per employee.
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
    'entry-requirements',
    'engineering'
  ));
