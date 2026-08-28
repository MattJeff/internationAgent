-- 0066_invoices: la facturation — the company asks to be paid, and records that
-- it was.
--
-- The buying side of this product runs end to end: `rfqs` → `quotes` →
-- `negotiations` → `purchase_orders` → `shipments` (0007), with
-- `Action::PaymentCreate`, `Effects::pay`, a reservation against `spend_buckets`
-- (0003) and an audit row at the end of it. The selling side stops at
-- `opportunities` (0011). `stage = 'closed_won'` is the last row anything
-- writes: there is no table in this schema that says *you owe us this much*, and
-- none that says *it arrived*. A company that can buy a container of anything
-- and cannot invoice for a month of service is not asymmetric by accident, it is
-- missing its own revenue.
--
-- Three consequences, and this table is the smallest answer to all three:
--
--   1. **Winning a deal produced no obligation.** `opportunities.value_minor` is
--      what somebody *expects* to bill — an annual figure written when the deal
--      opened and never revised against anything issued. Nothing turns it into a
--      demand, so "what are we owed" has no query.
--   2. **Nothing followed an encashment.** `agentos_store::billing` derives what
--      we may charge *a tenant* from `audit_log`, and `routes::billing` refuses
--      on purpose to print a figure — it is the basis of an invoice and says so
--      in its own header. That is Orizn's bill to its customers, computed
--      outside this schema; this table is a *tenant's* bill to *its* customers,
--      and the two are different companies' money. Neither of them had a
--      settlement column anywhere.
--   3. **No seat could be given billing and denied it.** Issuing was not an
--      `ActionKind`, so no role pack could decline it and no policy layer could
--      withhold it. See the section on that below: it is the reason this change
--      touches `crates/domain` at all.
--
-- ---------------------------------------------------------------------------
-- WHY AN INVOICE IS AN `ActionKind` AND A WORK ITEM IS NOT
-- ---------------------------------------------------------------------------
--
-- `0061` and `0063` both argued the other way and both were right about
-- themselves. A work item wakes nobody and nobody is owed anything by it; an
-- appointment's subject is always the seat that booked it, so promising an hour
-- of somebody else's time is unrepresentable rather than refused. Neither is an
-- act performed **outward, in the company's name, with money on it**, and an
-- invoice is all three at once.
--
-- `crates/app/src/calendar.rs` wrote the rule this change obeys, and it is worth
-- restating because it is the whole justification for a sixteenth discriminant:
--
--   > `ActionKind` is not only the gate's vocabulary: it is the key
--   > `turn::catalogue` is written in and the alphabet every role pack's
--   > `proposable` set is spelled with. A verb outside it is a verb no policy
--   > layer can withhold from a seat and no role pack can decline.
--
-- Without the kind, an employee that could reach this table could reach it from
-- every seat in the company, forever, with nothing able to say no — a customer
-- success seat and a finance seat holding identical power to bill a stranger.
-- With it, `rolepack_service::RolePack::finance` lists it and the other five
-- packs in the workspace do not, and that is a decision a test makes somebody
-- take rather than a gap.
--
-- ---------------------------------------------------------------------------
-- THE CEILING: WHAT STOPS A HUNDRED INVOICES, AND WHAT DOES NOT
-- ---------------------------------------------------------------------------
--
-- The buying side is bounded by money: `SpendLimits` has a per-transaction cap,
-- a per-day cap and an approval threshold, and `spend_reservations` holds the
-- headroom while the payment is in flight. **None of that transfers**, and the
-- reason is not that the numbers are different. A spend cap bounds what leaves
-- the company; an invoice is a claim on somebody else, so there is no bucket to
-- draw down and nothing to reserve. Reusing `spend` here would also be a
-- widening in the one direction this workspace refuses everywhere: a layer that
-- raised a purchasing budget would silently raise what the company may bill.
--
-- So the two halves of "a hundred invoices of a thousand euros to strangers" get
-- two different answers, and only one of them is closed.
--
-- **The strangers half is closed, structurally, with no number in it.**
-- `opportunity_id` is NOT NULL and `agentos_store::invoices::issue` inserts only
-- where that opportunity is `closed_won`. A won deal already carries
-- `approval_id` — `opportunities_won_needs_approval` (0011) refuses the
-- transition without one — so **every invoice this schema can hold sits behind a
-- human who approved the commercial terms it bills**. There is no path to
-- invoicing a party the company never sold anything to, and that bound needed
-- nobody to choose a figure.
--
-- **The hundred half is open.** Nothing here caps the amount of one invoice or
-- the number issued in a day. Two real things bound the damage and they are the
-- same two `0063` leans on: each issue spends a turn out of
-- `PolicyLimits::max_turns_per_day`, which an employee runs out of, and a seat
-- whose layer does not list `Channel::Email` cannot issue at all — a company
-- that cannot reach a customer does not bill one, which is the conjunct
-- `domain::policy::evaluate`'s arm reads.
--
-- FOUNDER'S QUESTION, LEFT OPEN: **above what figure does a human sign an
-- invoice?** No number here would be anything but invented, and an invented
-- threshold is worse than none — it reads as a decision somebody took. The
-- answer is one field and one conjunct, and it is deliberately not written:
--
--   * `invoice_approval_above: Option<Money>` in `PolicyLimits`, beside `spend`
--     and **not inside `SpendLimits`**, whose three caps are coherent with each
--     other and have nothing to say about a receivable;
--   * intersected with `min_money` in `PolicyLimits::intersect`, so a lower
--     layer can only ever lower it;
--   * read by `evaluate_rules`' `Action::InvoiceIssue` arm to answer
--     `RequireApproval { reason: ApprovalReason::InvoiceAboveThreshold }`, which
--     is `PaymentCreate`'s shape one field along.
--
-- It is a policy change and not a migration: `0006_policy` stores limits as
-- jsonb, and `PolicyLimits` is `#[serde(default)]`, so a layer written before
-- the field exists reads back as `None` — no threshold, which is where this
-- change leaves it.
--
-- ---------------------------------------------------------------------------
-- AN ISSUED INVOICE IS IMMUTABLE, AND THE GRANT IS WHAT SAYS SO
-- ---------------------------------------------------------------------------
--
-- Accounting has one answer to a wrong invoice and it is not an edit: you issue
-- a credit note. An amount that can be corrected in place is an amount that
-- disagrees with the copy the customer is holding, and the row gives no sign it
-- ever did.
--
-- `0061` refused DELETE to the board and wrote down why. This goes one column
-- further, because an invoice needs exactly one writable field and no others:
--
--   grant select, insert on invoices to app_role;
--   grant update (paid_at) on invoices to app_role;
--
-- A **column-level** UPDATE grant, which this schema has not used before and
-- which is the right primitive here: the amount, the currency, the memo, the
-- opportunity and the issuer are not writable by the role the API connects as,
-- and that is a fact readable out of `information_schema.column_privileges`
-- rather than a rule somebody remembers. `crates/store`'s
-- `an_issued_invoice_cannot_be_rewritten` asserts it from the catalogue.
--
-- The trigger below is the braces, for `audit_log_append_only`'s stated reason:
-- a future migration saying `GRANT ALL ON ALL TABLES IN SCHEMA public TO
-- app_role` would quietly undo the grant, and a trigger also binds superusers,
-- which no GRANT ever does. It refuses two things:
--
--   * **any column but `paid_at` changing.** Written as
--     `to_jsonb(new) - 'paid_at' is distinct from to_jsonb(old) - 'paid_at'`,
--     one expression rather than a column list, so a column a later migration
--     adds is covered the day it is added instead of the day somebody remembers
--     this function exists.
--   * **a settlement being withdrawn or re-dated.** `paid_at` moves from null to
--     an instant exactly once. Money that arrived does not stop having arrived,
--     and an invoice quietly returned to the unpaid list is how a receivable is
--     chased twice — or how one that was never paid disappears from the list.
--
-- **DELETE is refused by the grant and not by the trigger**, which is
-- `work_items` (0061) and `appointments` (0063) exactly, and the reason is
-- mechanical rather than a preference. `tenants` and `opportunities` both reach
-- this table by cascade, those cascades run as the table's *owner*, and a
-- trigger binds the owner — so a `DELETE` arm here would make dropping a company
-- fail on its own receivables. `evidence` and `suppressions` (0011) carry a
-- delete arm precisely because they have no `tenants` reference to cascade from,
-- and 0011 says so in as many words.
--
-- **And nothing this table references may fire a referential UPDATE**, which is
-- the sharper half and is why `issued_by` has no foreign key. `on delete set
-- null` *is* an `UPDATE`, so an employee being removed would rewrite an issued
-- invoice and hit the trigger; `on delete restrict` would make a receivable
-- block the removal of a seat. `audit_log.employee_id` (0001) takes the same
-- trade for the same reason and is likewise a bare uuid.
--
-- ---------------------------------------------------------------------------
-- `paid_at`: WHO DECLARES IT, AND WHY IT IS NOT AN `ActionKind`
-- ---------------------------------------------------------------------------
--
-- Nothing in this process can call a bank or a PSP, so "it was paid" is not
-- something this system observes. Somebody asserts it.
--
-- **An operator, through `POST /v1/invoices/{id}/paid`, and not an employee.**
-- That is the same authority that writes charters, cadences, work items and
-- appointments — an API key, not a principal the gate rules on — and the reason
-- it is not an employee is separation of duties rather than caution: the seat
-- that issues an invoice must not be the thing that records the money arriving,
-- or the only evidence a receivable was settled is written by the thing whose
-- job it was to collect it. An employee that could mark its own invoices paid
-- has a clean ledger and no revenue.
--
-- So there is no `ActionKind::InvoicePaid`, and it is not an omission of the
-- same kind `0063` left open. The day a PSP webhook writes this column —
-- `webhook_endpoints` (0053) already stores raw signed deliveries and has no
-- billing logic — the writer is still not an employee, and what the column gains
-- then is a `paid_source text` beside it, because "who said so" will have two
-- answers for the first time. It has one today.
--
-- **One column, and no value date.** A bank statement distinguishes when the
-- money moved from when somebody noticed; nothing here reads a bank statement,
-- so a second column would be a distinction with one honest value in it. The
-- webhook that brings a value date is the change that adds it.

-- ---------------------------------------------------------------------------
-- WHAT THIS IS NOT: A LEGAL INVOICE
-- ---------------------------------------------------------------------------
--
-- This is a register of demands for money and a record of which were settled. It
-- is deliberately not a document, and the gap is worth naming so nobody
-- discovers it at an audit:
--
--   * **No number.** `id` is a uuid. Most jurisdictions require a gap-free
--     sequence, per company and often per fiscal year, and the shape of it is a
--     legal question with a different answer per country — not a column this
--     migration may guess. It is one `bigint` and one sequence per tenant when
--     somebody knows which rule applies.
--   * **No line items, no tax, no due date, no PDF.** `memo` is one line.
--     A VAT rate is a jurisdiction pair and a date; a due date is a payment
--     term nobody has agreed; a rendered document is a template nobody has
--     written. Each is a table or a column of its own, and none of them is
--     needed to answer "what are we owed" and "did it arrive", which is what
--     was missing.
--   * **Nothing is sent.** Issuing writes a row. Putting the demand in front of
--     the customer is an `Action::EmailSend`, gated and audited as one, and it
--     is deliberately a separate act: an invoice that is recorded and not sent
--     is a mistake somebody can see, and one that is sent and not recorded is
--     not.

create table if not exists invoices (
  id             uuid        primary key,

  -- Whose company. Written by the caller's transaction and never by the
  -- payload, like every other tenant column here; the policy below enforces it.
  tenant_id      uuid        not null references tenants (id) on delete cascade,

  -- The deal this bills. NOT NULL, and the store refuses one that is not
  -- `closed_won` — see the ceiling section above, which is the whole argument
  -- for this column being required.
  opportunity_id uuid        not null,

  -- The seat that issued it, and **a bare uuid on purpose**: see the
  -- immutability section. A foreign key here could only carry `on delete set
  -- null`, which is an `UPDATE` this table's trigger refuses, or `on delete
  -- restrict`, which would make a receivable block the removal of a seat.
  -- `audit_log.employee_id` (0001) is a bare uuid for the same reason and is the
  -- precedent this follows.
  --
  -- NOT NULL, unlike `work_items.posted_by` (0064): there is exactly one write
  -- path — `Effects::issue_invoice`, holding a token the gate minted for an
  -- employee — so there is no "an operator wrote this" value for a null to
  -- stand for. If an operator issue route is ever added, this column acquires
  -- 0064's ambiguity and that migration's argument applies in reverse.
  --
  -- Not a permission: nothing reads it to decide anything, exactly as 0064 says
  -- of `posted_by`. It records who asked to be paid.
  issued_by      uuid        not null,

  -- The amount, as `agentos_domain::money::Money` holds it: minor units plus an
  -- ISO code, the same pair `opportunities`, `quotes` and `spend_caps` store.
  --
  -- **Both columns NOT NULL, and the currency has no default.** An invoice
  -- without an explicit currency is not an invoice with an obvious one, it is a
  -- number somebody will read in whatever they were expecting — and `Money`
  -- itself cannot be built without a `Currency`, so a default here would be a
  -- value no caller in this workspace can produce.
  currency       text        not null
                             constraint invoices_currency_iso
                             check (currency ~ '^[A-Z]{3}$'),

  -- Strictly positive, mirroring `Money::new`, which refuses zero
  -- (`MoneyError::Zero`) and is unsigned. A zero invoice is a letter and a
  -- negative one is a credit note, which is a different document this table does
  -- not hold — see the immutability section.
  amount_minor   bigint      not null
                             constraint invoices_amount_positive
                             check (amount_minor > 0),

  -- What it is for, in one line. Bounded at 200, borrowed rather than invented:
  -- `a2a_tasks_id_length` (0005), `work_items_title_shape` (0061) and
  -- `appointments_subject_shape` (0063) are this schema's one answer to "how
  -- long may a caller-supplied line be". The floor is what stops a blank
  -- description arriving on a demand for money.
  memo           text        not null
                             constraint invoices_memo_shape
                             check (char_length(btrim(memo)) between 1 and 200),

  issued_at      timestamptz not null default now(),

  -- Null is outstanding. Written once, by an operator, and never withdrawn —
  -- see the section above and the trigger below.
  paid_at        timestamptz
                             constraint invoices_paid_after_issue
                             check (paid_at is null or paid_at >= issued_at),

  -- Composite, against `opportunities_tenant_id_key` (0011), so an invoice
  -- cannot name a deal belonging to another company even if somebody knows its
  -- id. `on delete cascade` for the reason the immutability section gives: a
  -- cascade is a DELETE, DELETE is refused by the grant rather than by the
  -- trigger, and the chain `tenants` → `accounts` → `opportunities` has to be
  -- able to run. `app_role` has no DELETE on `accounts` or `opportunities`
  -- (0011), so nothing the API or an employee can do reaches it.
  constraint invoices_opportunity_fk
    foreign key (tenant_id, opportunity_id) references opportunities (tenant_id, id)
    on delete cascade
);

-- The register's own read: what this company is owed, oldest first. Partial on
-- `paid_at is null` because a settled invoice is kept forever and is never
-- outstanding again, so the index that finds receivables must not carry it.
create index if not exists invoices_outstanding_idx
  on invoices (tenant_id, issued_at, id)
  where paid_at is null;

-- Postgres does not index a foreign key column for you, and the cascade from
-- `opportunities` scans this table by it. Same line, same reason, as
-- `work_items_assignee_idx` (0061). It is also the read "what have we billed on
-- this deal".
--
-- There is no index on `issued_by` and there must not be one for a foreign
-- key's sake: it has no foreign key. See the column.
create index if not exists invoices_opportunity_idx
  on invoices (tenant_id, opportunity_id);

-- ---------------------------------------------------------------------------
-- An issued invoice is immutable but for its settlement
-- ---------------------------------------------------------------------------
--
-- See the header. The grant below is the belt; this is the braces, and it binds
-- the owner and superusers, which no GRANT does.

create or replace function invoices_are_issued_once() returns trigger
language plpgsql as $$
begin
  -- Every column but the settlement, in one expression: a column a later
  -- migration adds is covered the day it is added.
  if to_jsonb(new) - 'paid_at' is distinct from to_jsonb(old) - 'paid_at' then
    raise exception 'invoice % is issued; only paid_at may be written', old.id
      using errcode = 'restrict_violation';
  end if;
  if old.paid_at is not null then
    raise exception 'invoice % is already settled; a settlement is not withdrawn or re-dated', old.id
      using errcode = 'restrict_violation';
  end if;
  return new;
end
$$;

drop trigger if exists invoices_are_issued_once on invoices;
create trigger invoices_are_issued_once
  before update on invoices
  for each row execute function invoices_are_issued_once();

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, so the owning role the migrations and the
-- cross-tenant loops connect as does not walk past the policy — `enable` alone
-- binds `app_role` and lets the owner read every company's receivables. `with
-- check` as well as `using`, so no invoice can be filed wearing another
-- company's id: one filed against somebody else's opportunity would be a demand
-- for money issued in a company that did not issue it.
--
-- Nothing here is claimed cross-tenant. Unlike `appointments` (0063) there is no
-- poller: an invoice rings nobody and waits.

alter table invoices enable row level security;
alter table invoices force row level security;
drop policy if exists tenant_isolation on invoices;
create policy tenant_isolation on invoices
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- The column-level UPDATE is the point. See the header at length: an issued
-- invoice has exactly one writable field, and the privilege system is what says
-- so rather than a convention in Rust.

grant select, insert on invoices to app_role;
grant update (paid_at) on invoices to app_role;
revoke delete on invoices from app_role;
