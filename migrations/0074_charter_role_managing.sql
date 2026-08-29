-- 0074_charter_role_managing: the company can hire somebody to run the others.
--
-- Every one of the seven roles this CHECK already admits is an individual
-- contributor: a buyer, a seller, and five service seats that each do a job
-- with their own hands. The org chart has had `team_memberships.reports_to`
-- since `0012_org`, `crates/app/src/gate.rs` rules on `Action::CharterSet`
-- against it, and `crates/app/src/vertical.rs::delegate` is the function that
-- re-tasks a report — written, tested, and called by nothing outside its own
-- tests, because there was no seat whose job was to call it.
--
-- `crates/app/src/rolepack_service.rs` adds `RolePack::managing`; this is the
-- other half of that sentence, for the reason 0073 gives: a role the CHECK
-- refuses is a role no employee can be hired into.
--
-- WHY A NEW FILE RATHER THAN AN EDIT TO 0073
--
-- 0029's reasoning, restated by 0030 and 0073 and now a fourth time:
-- `sqlx::migrate!` checksums every file it has already applied, so editing
-- 0073_charter_role_engineering.sql would turn every existing database into a
-- migration failure at startup — a schema change delivered as an outage.
--
-- WHAT THIS ROW DOES NOT GRANT
--
-- Nothing, and here that sentence is worth more than it was in 0073. The
-- dangerous reading of "manager" is *authority over more people than the chart
-- says*, and none of it is in this column. Who a manager may re-task is one
-- link of `team_memberships`, read by the gate in the transaction it rules in;
-- who it may message is `inbound::may_message`; what it may do at all is
-- `RolePack::managing`'s `proposable`, which is one `ActionKind`
-- (`InternalSend`) and does not include `CharterSet` — no role pack lists that
-- one, so no model can propose re-tasking anybody. Widening this constraint
-- makes the seat *expressible* and nothing else.
--
-- And it grants nothing transitively. `vertical::delegate` documents why
-- authority is one link and not a walk: a CEO directs its heads, not the whole
-- company. A manager hired into this role over a manager hired into this role
-- is two links, ruled on separately, each against the chart as it stands.
--
-- The new name is `rolepack_service::MANAGING`, and `vertical::Charter::of` is
-- the match that reads it back —
-- `vertical::tests::every_pack_round_trips_through_its_name` is what notices
-- when the three drift apart.
--
-- No data migration: this constraint only ever widens, so every existing row
-- still satisfies it and there is nothing to backfill.
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
    'engineering',
    'managing'
  ));
