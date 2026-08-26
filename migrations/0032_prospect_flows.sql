-- 0032_prospect_flows: the selectors on a prospect's booking page, and the name
-- of the human who looked at it.
--
-- `crates/app/src/proof_of_need.rs` drives a prospect's own booking flow from a
-- `Flow` — an entry URL and five CSS selectors — and nothing in this product
-- produced one outside tests. `apps/server/src/loops/initiative.rs` said so in
-- the comment where the sales employee's turn should have been: "neither has a
-- table, a route or a config key anywhere in this product". This is the table.
--
-- WHY A HUMAN WRITES THESE AND NOTHING ELSE MAY
--
-- A wrong selector does not fail. `#visa-info` mistyped as `#visa-nfo` comes
-- back NO_SUCH_ELEMENT and is refused loudly — that case is already covered —
-- but a selector pointed at the *wrong element that exists* reads a cookie
-- banner, a footer or a price and produces a confident, reproducible,
-- screenshotted finding about somebody else's product. Both runs agree, because
-- both runs read the same wrong element. The evidence bar cannot tell the
-- difference, and the sentence that goes out says "on this date your checkout
-- said this" with steps to repeat it. That is the one mistake this vertical
-- cannot walk back.
--
-- So the fact this table records is not "these are the selectors". It is
-- **somebody opened the page and checked**. `confirmed_by` is that person's
-- name and `confirmed_at` is when they said so, and `agentos_app::proof_of_need`
-- refuses to build a `Flow` from a row where they are null.
--
-- Four decisions.
--
-- 1. KEYED ON `accounts.id`, AND THE DOMAIN IS NOT COPIED HERE.
--    A prospect is an `accounts` row; its registrable domain is `accounts.domain`
--    and that column is already the identity of a prospect and already unique per
--    tenant. Repeating it here would be a second answer to "where does this
--    prospect live", and the second answer is the one that goes stale. The
--    reader joins. `proof_of_need_attempts` keys on the domain instead and
--    explains why — an attempt must be filable before anybody creates the
--    account row — which is the opposite trade for the opposite reason: a flow
--    that has no account has no prospect to be about.
--
-- 2. EDITING A SELECTOR REVOKES THE CONFIRMATION, IN A TRIGGER.
--    The whole value of `confirmed_by` is that a named human looked at *these
--    exact selectors*. Change one and they did not. The application could do
--    this in its UPSERT and does; the trigger is what makes it true of a `psql`
--    session and of whatever writes this table next. `confirmed_at` alone is not
--    it — a row edited after confirmation would keep a timestamp that means
--    nothing.
--
-- 3. NO PROBE PAIR HERE. Which passport and which destination to put through a
--    flow is a question about entry rules, not about a page's markup, and it
--    changes per check while these selectors change per redeploy. `Probe` stays
--    the caller's.
--
-- 4. `entry_url` IS TEXT AND IS PARSED IN RUST. A `url` type does not exist in
--    stock Postgres and a CHECK regexp for one is a worse parser than `url::Url`
--    wearing a constraint's authority. The scheme is checked here because it is
--    one comparison and an `http://` probe is a credential-free page read over a
--    network anybody can rewrite; that the host is *within the account's domain*
--    is checked in `Flow::confirmed`, where both values are already parsed.
--
-- Replayable: IF NOT EXISTS / OR REPLACE throughout.

-- ---------------------------------------------------------------------------
-- prospect_flows
-- ---------------------------------------------------------------------------

create table if not exists prospect_flows (
  -- One flow per prospect. A second one would be a second answer to "what does
  -- their booking page look like", and nothing downstream could choose.
  account_id         uuid        primary key,
  tenant_id          uuid        not null references tenants (id) on delete cascade,
  -- The page the check starts on. Its host must be within `accounts.domain`;
  -- see decision 4 for where that is enforced.
  entry_url          text        not null,
  -- CSS selectors. The panel is the one that decides what we may claim: point it
  -- at the answer widget, never at a container with a clock in it. See
  -- `proof_of_need`'s module docs on `same_answer` + `both_silent`.
  passport_field     text        not null,
  destination_field  text        not null,
  date_field         text,
  -- Their "check requirements" button, and NEVER a booking or payment submit.
  -- Nothing in the database can tell those apart; the human named in
  -- `confirmed_by` is who owns that call.
  submit             text,
  panel              text        not null,
  -- Who looked at the page, and when they said so. Null is "nobody has", which
  -- is the state a bulk-loaded guess is in.
  confirmed_by       text,
  confirmed_at       timestamptz,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  -- The composite FK, so a flow cannot point at another tenant's account.
  -- `accounts_tenant_id_key` in 0011_revenue.sql is what makes this spellable.
  constraint prospect_flows_account_fk
    foreign key (tenant_id, account_id) references accounts (tenant_id, id)
    on delete cascade,
  -- Both or neither. A `confirmed_by` with no date is a claim nobody can age.
  constraint prospect_flows_confirmation
    check ((confirmed_by is null) = (confirmed_at is null)),
  constraint prospect_flows_confirmed_by_nonempty
    check (confirmed_by is null or length(btrim(confirmed_by)) > 0),
  -- A blank selector matches nothing and would arrive as NO_SUCH_ELEMENT on
  -- every probe forever. Refuse it where it is written instead.
  constraint prospect_flows_selectors_nonempty check (
    length(btrim(passport_field)) > 0
    and length(btrim(destination_field)) > 0
    and length(btrim(panel)) > 0
    and (date_field is null or length(btrim(date_field)) > 0)
    and (submit is null or length(btrim(submit)) > 0)
  ),
  constraint prospect_flows_entry_https check (entry_url like 'https://%')
);

-- ---------------------------------------------------------------------------
-- Editing a selector revokes the confirmation
-- ---------------------------------------------------------------------------
--
-- See decision 2. `is distinct from` over the whole row so a null date_field
-- becoming `#when` counts, which `<>` would not.

create or replace function prospect_flow_reconfirm() returns trigger as $$
begin
  if (new.entry_url, new.passport_field, new.destination_field,
      new.date_field, new.submit, new.panel)
     is distinct from
     (old.entry_url, old.passport_field, old.destination_field,
      old.date_field, old.submit, old.panel)
  then
    new.confirmed_by := null;
    new.confirmed_at := null;
  end if;
  new.updated_at := now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists prospect_flows_reconfirm on prospect_flows;
create trigger prospect_flows_reconfirm
  before update on prospect_flows
  for each row execute function prospect_flow_reconfirm();

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core
-- ---------------------------------------------------------------------------

alter table prospect_flows enable row level security;
alter table prospect_flows force row level security;
drop policy if exists tenant_isolation on prospect_flows;
create policy tenant_isolation on prospect_flows
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- The application reads these and never writes them. Writing one is an
-- operator's act performed with the operator's own database credential —
-- `agentos-server flow set` / `flow confirm`, the same authorisation story as
-- `agentos-server policy`. An employee that could write this table could write
-- itself a selector pointed anywhere on a domain it is allowed to read, which is
-- exactly the loop this design exists to break.
--
-- DELETE is granted so dropping a tenant cascades; UPDATE and INSERT are not.

grant select, delete on prospect_flows to app_role;
revoke insert, update on prospect_flows from app_role;
