-- 0029_charter_roles: three more of the org chart's functions can be hired for.
--
-- `docs/TEAMS.md` §7 draws seven rows and only two of them had a role pack, so
-- `employee_charters_role` listed two names. `crates/app/src/rolepack_service.rs`
-- adds customer success, growth and finance; this is the other half of that
-- sentence, because a role the CHECK refuses is a role no employee can be
-- hired into.
--
-- WHY A NEW FILE RATHER THAN AN EDIT TO 0018
--
-- `sqlx::migrate!` checksums every file it has already applied. Editing
-- 0018_charter.sql would turn every existing database into a migration failure
-- at startup — a schema change delivered as an outage. So the constraint is
-- dropped and recreated here, which is also the only form of this change that
-- can be read as a diff a year from now.
--
-- WHY THE LIST IS STILL A CHECK AND NOT A LOOKUP TABLE
--
-- 0018's decision 2, unchanged: these strings are `RolePack::name()`, they
-- exist in the *binary*, and a `roles` table would let an operator insert a row
-- naming a pack this build does not have. The failure would then be a charter
-- that saves and cannot load — which is exactly the runtime `None` the CHECK
-- exists to turn into a failed write at the moment somebody typos it. The list
-- belongs where the deploy is, and a migration is where the deploy is.
--
-- The three names here are `rolepack_service::CUSTOMER_SUCCESS`, `::GROWTH` and
-- `::FINANCE`, and `vertical::Charter::of` is the match that reads them back.
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
    'finance'
  ));
