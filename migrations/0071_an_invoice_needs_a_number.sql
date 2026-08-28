-- 0071_an_invoice_needs_a_number: the gap-free number, the lines, the due date
-- and the credit note.
--
-- `0066_invoices` wrote its own gap list under the heading "WHAT THIS IS NOT: A
-- LEGAL INVOICE" — no number, no lines, no tax, no due date, no PDF, nothing
-- sent, and no credit note despite "corrected by a credit note" being the whole
-- argument for the immutability trigger. This migration closes four of them and
-- deliberately closes neither of the other two.
--
-- ---------------------------------------------------------------------------
-- WHY THE NUMBER IS FIRST, AND WHY `bigserial` IS EXACTLY THE WRONG ANSWER
-- ---------------------------------------------------------------------------
--
-- Every other item on that list is a column. This one is a property of
-- *concurrency*, which is why it is written first and why the rest of the
-- migration hangs off the object it introduces.
--
-- A Postgres sequence is non-transactional on purpose: `nextval` is exempt from
-- rollback so that two writers never wait on each other. That is the right
-- trade for a surrogate key and the wrong one here, because the exemption is
-- precisely what puts holes in the run:
--
--     tx A: nextval -> 41   tx B: nextval -> 42
--     tx A: ROLLBACK        tx B: COMMIT
--     -> the register jumps 40, 42, and 41 was never issued to anybody.
--
-- Nobody can tell that story to an inspector, and no amount of care in Rust
-- fixes it — the hole is in the primitive. `serial`, `bigserial`, `GENERATED …
-- AS IDENTITY` and a bare `CREATE SEQUENCE` are the same object underneath and
-- all four are ruled out by the same paragraph.
--
-- What is left is a **counter row**, incremented by the same transaction that
-- writes the invoice:
--
--     INSERT INTO invoice_counters (tenant_id, last_number) VALUES ($1, 1)
--     ON CONFLICT (tenant_id) DO UPDATE SET last_number = … + 1
--     RETURNING last_number
--
-- The row lock that `DO UPDATE` takes is held to end of transaction, so a
-- second issuer of the same company **blocks** rather than skipping ahead, and
-- when the first transaction rolls back the counter rolls back with it and the
-- number it held is handed to the next caller. Gap-free is then not a
-- convention anybody has to remember: it is what the lock does.
--
-- The cost is named rather than hidden: **issuing serialises per company.** Two
-- invoices of one tenant cannot be written at the same instant, and that is not
-- a regression to work around — a gap-free sequence *is* a serialisation, and
-- anything concurrent enough to avoid the wait is something that can skip a
-- number. Companies do not contend with each other: the lock is one row keyed by
-- `tenant_id`.
--
-- `crates/store/src/invoices.rs`'s `two_issues_at_once_take_two_numbers_and_
-- skip_none` runs two real transactions on two real connections and asserts it,
-- with the rolled-back half proving the property a sequence cannot have.
--
-- ### The other half: nothing may allocate outside the counter
--
-- The counter hands out the next number; a unique index is what stops anybody
-- writing a number it did not hand out twice, and the trigger below is what
-- stops the counter itself being wound forward — the one move that makes a hole
-- the unique index cannot see. Rewinding it produces a *duplicate*, which the
-- index refuses; jumping it forward produces a *gap*, which only a trigger
-- comparing `old` to `new` can refuse.
--
-- ### FOUNDER'S QUESTION, LEFT OPEN: what is the series?
--
-- The counter is keyed on `tenant_id` **alone**, so today each company has one
-- continuous run: 1, 2, 3, … forever. That is the coarsest partition there is,
-- and it is the only one that needs no knowledge of the founder's jurisdiction.
-- The finer ones are all facts nobody in this repository can observe:
--
--   * whether the run restarts each fiscal year, and **when that year starts** —
--     it is not January everywhere, and it is a fact about the company's
--     accounts rather than about its software;
--   * whether credit notes are numbered in the same run as invoices or in one
--     of their own — both are ordinary practice;
--   * whether an establishment or a branch gets its own run.
--
-- Each of those is *one column added to this table's primary key* and one more
-- bind in `agentos_store::invoices`; none of them is a rewrite, and none of them
-- disturbs numbers already issued, because a series that changes on a date only
-- ever changes forward. Guessing one here would read as a decision somebody
-- took, and would be wrong in most of the countries this product is sold in.
-- 0066 made the same refusal about a VAT rate and this follows it.

create table if not exists invoice_counters (
  -- One row per company, and the primary key is the whole story: this row is
  -- the lock that serialises issuing, so it must be the *only* row a given
  -- company's issuers contend for.
  tenant_id   uuid   primary key references tenants (id) on delete cascade,

  -- The last number this company issued. The statement that bumps this row
  -- `RETURNING last_number` gets the number it has just claimed, so there is
  -- exactly one reading of this value and no off-by-one for anybody to have an
  -- opinion about: it is what the invoice being written right now will carry.
  last_number bigint not null
                     constraint invoice_counters_start_at_one
                     check (last_number >= 1)
);

-- A counter that can be wound forward is a counter that can put a hole in the
-- run, and `invoices_tenant_number_key` cannot see that one: it refuses a
-- number twice, not a number skipped. So the only legal move on this row is
-- `+1`.
--
-- It binds the owner and superusers, which the column-level GRANT below does
-- not — the same belt/braces split 0066 made for `paid_at`.
create or replace function invoice_counters_advance_by_one() returns trigger
language plpgsql as $$
begin
  if new.tenant_id is distinct from old.tenant_id
     or new.last_number is distinct from old.last_number + 1 then
    raise exception 'the invoice counter moves by one: % to % is not an issue',
      old.last_number, new.last_number
      using errcode = 'restrict_violation';
  end if;
  return new;
end
$$;

drop trigger if exists invoice_counters_advance_by_one on invoice_counters;
create trigger invoice_counters_advance_by_one
  before update on invoice_counters
  for each row execute function invoice_counters_advance_by_one();

alter table invoice_counters enable row level security;
alter table invoice_counters force row level security;
drop policy if exists tenant_isolation on invoice_counters;
create policy tenant_isolation on invoice_counters
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- `update (last_number)` and not a table-wide UPDATE, 0066's primitive one
-- table along: moving a counter row to another company's `tenant_id` would hand
-- that company's next number to this one, and the privilege system is what says
-- it cannot rather than a convention in Rust.
--
-- DELETE is refused, and the cascade from `tenants` still works because a
-- cascade runs as the table's owner — 0061's and 0066's argument, unchanged.
grant select, insert on invoice_counters to app_role;
grant update (last_number) on invoice_counters to app_role;
revoke delete on invoice_counters from app_role;

-- ---------------------------------------------------------------------------
-- The number itself
-- ---------------------------------------------------------------------------
--
-- Added, backfilled and only then made NOT NULL, because a database that
-- already carries invoices must migrate — and a backfill of one distinct value
-- per row is an `UPDATE`, which is the exact statement `invoices_are_issued_
-- once` exists to refuse. The trigger is disabled for the length of the
-- backfill and put back in the same transaction: if anything below fails, the
-- whole migration rolls back and the trigger was never off.
--
-- **The backfill order is `issued_at, id` and it is not a preference.** A number
-- allocated later than another must not be smaller, or the run is chronological
-- for the audit but not for the reader; `id` is a uuid v7 so it breaks ties in
-- issue order too.
alter table invoices add column if not exists number bigint;

alter table invoices disable trigger invoices_are_issued_once;
update invoices i
   set number = ordered.n
  from (select id, row_number() over (partition by tenant_id order by issued_at, id) as n
          from invoices) ordered
 where ordered.id = i.id
   and i.number is null;
alter table invoices enable trigger invoices_are_issued_once;

alter table invoices alter column number set not null;

-- The braces on the counter: a number is unique inside a company, so a caller
-- that bypassed the counter and picked one cannot reuse a number somebody is
-- already holding a copy of. Unique rather than merely indexed — this is a
-- constraint, and 0056 is the precedent for preferring one to a `SELECT`
-- somebody has to remember.
create unique index if not exists invoices_tenant_number_key
  on invoices (tenant_id, number);

-- Seeded from what the backfill just wrote, so the next invoice of an existing
-- company continues its run instead of colliding with row 1.
insert into invoice_counters (tenant_id, last_number)
select tenant_id, max(number) from invoices group by tenant_id
    on conflict (tenant_id) do nothing;

-- ---------------------------------------------------------------------------
-- The due date
-- ---------------------------------------------------------------------------
--
-- Nullable, with **no default term**. "Net 30" is a commercial agreement
-- between two companies, not a fact about software, and a default would quietly
-- put a date on every invoice that nobody agreed to. Null means the demand
-- carries no date — payable on receipt, or whatever the contract this bills
-- says — and it is the caller that supplies one.
--
-- Immutable, by the trigger 0066 wrote as an expression rather than a column
-- list, and that is checked rather than assumed: `a_due_date_is_part_of_the_
-- issued_document` in `crates/store/src/invoices.rs` proves the trigger refuses
-- to move it. It is the right answer for this column. An extension granted
-- afterwards is an agreement about a debt, not a correction to the document the
-- customer is holding — and this table already has one way to say a document
-- was wrong, which is the credit note below.
alter table invoices add column if not exists due_at timestamptz;

alter table invoices drop constraint if exists invoices_due_after_issue;
alter table invoices add constraint invoices_due_after_issue
  check (due_at is null or due_at >= issued_at);

-- ---------------------------------------------------------------------------
-- The credit note
-- ---------------------------------------------------------------------------
--
-- 0066: "an amount that can be corrected in place is an amount that disagrees
-- with the copy the customer is holding" — and then, one paragraph on, "a
-- negative one is a credit note, which is a different document this table does
-- not hold". The immutability argument was leaning on a table that did not
-- exist, so an issued invoice with a wrong figure had no remedy at all.
--
-- **It is a row in this table and not a table of its own**, and the reason is
-- the number. The two documents share one run (see the series question above,
-- which is where the founder may split them), and a run shared across two
-- tables is a uniqueness nothing can enforce — a unique index does not span
-- tables. Sharing the table makes `invoices_tenant_number_key` cover both
-- documents at once, and hands the credit note the whole of 0066's apparatus
-- for free: the same RLS policy, the same immutability trigger, the same
-- refusal of DELETE, the same register read.
--
-- **`corrects_invoice_id IS NOT NULL` is the document kind.** There is no
-- `kind` column, because a second column that must agree with this one is a
-- second place for the truth to be, and the row is immutable so neither can
-- drift. A null pointer is an invoice; a set one is a credit note against the
-- invoice it names.
--
-- The amount stays `> 0` — 0066's `invoices_amount_positive` is untouched, and
-- the sign is carried by the pointer rather than by the figure. That keeps
-- every existing reader honest: a reader that has not been taught about credit
-- notes sums figures that are all still demands, and the one place that nets
-- them (`GET /v1/invoices`'s `outstanding_minor`) does it explicitly.
alter table invoices add column if not exists corrects_invoice_id uuid;

-- The FK target: `(tenant_id, id)`, so a credit note cannot name another
-- company's invoice even if somebody knows its id — the composite trick
-- `invoices_opportunity_fk` already uses against `opportunities`.
create unique index if not exists invoices_tenant_id_key
  on invoices (tenant_id, id);

alter table invoices drop constraint if exists invoices_corrects_fk;
alter table invoices add constraint invoices_corrects_fk
  foreign key (tenant_id, corrects_invoice_id) references invoices (tenant_id, id)
  on delete cascade;

-- **At most one credit note per invoice.** A partial unique index, and it is
-- doing concurrency work rather than tidiness: without it, two callers crediting
-- the same invoice at the same instant both read an uncredited invoice from
-- their own snapshot and both write, and the receivable goes negative. With it
-- the second one blocks on the index and then loses, which is 0056's mechanism
-- exactly ("the loser's INSERT fails, its transaction rolls back").
--
-- The ceiling is real and named: **an invoice cannot be credited twice**, so a
-- correction in instalments is unrepresentable. The upgrade is to drop this
-- index and replace it with a constraint trigger summing the credit notes
-- against the invoice — which is only safe *because* the counter row above
-- already serialises every issue of one company, and that is worth knowing
-- before somebody tries it without one.
create unique index if not exists invoices_one_credit_note_per_invoice_idx
  on invoices (corrects_invoice_id)
  where corrects_invoice_id is not null;

-- A credit note has no `issued_by`, and that is the separation of duties 0066
-- already chose for `paid_at`: forgiving a demand for money is the founder's
-- act, made with an operator key, not an employee's — a seat that could erase
-- its own bad invoices has a clean ledger and nobody the wiser. So `issued_by`
-- loses its NOT NULL and gains a conjunction instead: exactly the invoices have
-- an issuer, exactly the credit notes have a pointer.
--
-- This is 0064's `posted_by` ambiguity arriving as 0066 predicted it would
-- ("if an operator issue route is ever added, this column acquires 0064's
-- ambiguity") — with the sign flipped, because the operator route added here
-- does not issue demands, it withdraws them.
alter table invoices alter column issued_by drop not null;

alter table invoices drop constraint if exists invoices_issuer_or_correction;
alter table invoices add constraint invoices_issuer_or_correction
  check ((issued_by is not null) = (corrects_invoice_id is null));

-- ---------------------------------------------------------------------------
-- The lines
-- ---------------------------------------------------------------------------
--
-- `memo` is one line for the whole document. A line item table is what lets an
-- invoice say what it is made of — and, above all, it is **where a tax rate can
-- be carried at all**, because a rate is per line and not per document.

-- **The primary key is `(invoice_id, position)` and there is no `id` column.**
-- 0001 says of this schema that "there is no `DEFAULT gen_random_uuid()`
-- anywhere: ids are minted by the application", and a line has no identity to
-- mint one for — it is the third line of that invoice and nothing else. A
-- surrogate key here would be a value every caller has to invent and no reader
-- ever uses.
create table if not exists invoice_lines (
  tenant_id      uuid   not null references tenants (id) on delete cascade,

  -- Composite against `invoices_tenant_id_key`, same reason as everywhere else
  -- here. `on delete cascade` so the chain `tenants` → `invoices` → here can
  -- run; DELETE is refused to `app_role` by the grant, not by a trigger, for
  -- 0066's mechanical reason (a trigger binds the owner, and a cascade *is* the
  -- owner).
  invoice_id     uuid   not null,

  -- The order the lines are read in. Explicit rather than "whatever the index
  -- returns": the document the customer holds has an order, and a register that
  -- reprints it in another one is printing a different document.
  position       int    not null
                        constraint invoice_lines_position_positive
                        check (position >= 1),

  -- Bounded at 200, borrowed from `invoices_memo_shape` (0066) rather than
  -- invented, and the floor is what stops a blank line arriving on a demand for
  -- money.
  description    text   not null
                        constraint invoice_lines_description_shape
                        check (char_length(btrim(description)) between 1 and 200),

  -- **No currency column.** The line is denominated in the invoice's currency,
  -- so a line in another currency is unrepresentable rather than refused.
  --
  -- Signed, unlike the head: a discount is a line with a negative amount, and
  -- the document still totals to a positive demand because the head keeps
  -- 0066's `> 0`. Zero is refused for `Money::new`'s reason — a line worth
  -- nothing is a sentence, and the description already carries sentences.
  amount_minor   bigint not null
                        constraint invoice_lines_amount_nonzero
                        check (amount_minor <> 0),

  -- ------------------------------------------------------------------------
  -- FOUNDER'S QUESTION, LEFT OPEN, AND THIS IS THE PLACE IT IS ASKED
  -- ------------------------------------------------------------------------
  --
  -- The tax rate on this line, in basis points: 2000 is 20%, 550 is 5.5%.
  -- Integer rather than a float because money arithmetic does not get a binary
  -- fraction, and basis points because two decimals is what published rates
  -- use.
  --
  -- **NULL by default and NULL on every row this workspace can write today**,
  -- because a rate is not a fact about software. It is a fact about the
  -- founder's company and its customer's country: which regime the company is
  -- in, whether it is registered for the tax at all, whether this customer is
  -- in another member state and the charge reverses onto them, whether the
  -- line is exempt. Nobody here can observe any of that, and a rate written in
  -- this repository would read as a decision somebody took.
  --
  -- So the column is the *form* — an invoice that can carry a tax per line —
  -- and the value is the founder's. What is still missing the day they supply
  -- one is named rather than half-built:
  --
  --   * **the legal mention.** A zero rate under a reverse charge is not the
  --     same document as a zero rate under an exemption, and the difference is
  --     a sentence that must be printed. It is a `text` column beside this one
  --     the day somebody knows which sentences exist.
  --   * **the total.** Nothing in this workspace multiplies this rate by that
  --     amount, and that is deliberate: whether tax is rounded per line or per
  --     rate band, and to which unit, is jurisdictional too, and a total
  --     computed by the wrong rule is worse than no total. The register reports
  --     the rate it was given.
  --
  -- `>= 0` and no upper bound: "not negative" is arithmetic, but "no more than
  -- 100%" would be a claim about tax systems, and this column does not make
  -- claims about tax systems.
  tax_rate_bp    int    constraint invoice_lines_tax_rate_not_negative
                        check (tax_rate_bp is null or tax_rate_bp >= 0),

  constraint invoice_lines_invoice_fk
    foreign key (tenant_id, invoice_id) references invoices (tenant_id, id)
    on delete cascade,

  -- One line per position, so the order is total and a second line cannot hide
  -- behind the first — and it is the primary key rather than a unique
  -- constraint beside one, so it is also the index every read of a document's
  -- lines uses.
  constraint invoice_lines_pkey primary key (invoice_id, position)
);

-- **The lines total the document, and they are checked at commit.**
--
-- Deferred, because the head has to exist before its lines do and each line
-- arrives on its own INSERT: an immediate check would fail on the first line of
-- every two-line invoice. `DEFERRABLE INITIALLY DEFERRED` moves it to the end
-- of the transaction, where the set is complete.
--
-- One trigger, two properties, and the second is the one worth the deferral:
--
--   1. a document whose lines do not add up to what it demands cannot be
--      committed;
--   2. **a line cannot be added to an invoice that already had lines**, in any
--      later transaction, because the sum already matched and one more line
--      makes it stop matching. An issued document does not grow a line, and
--      that falls out of (1) rather than needing its own rule.
--
-- The remaining hole is named: an invoice committed with *no* lines can still
-- be given a set later that totals correctly. Closing it means requiring at
-- least one line on every invoice, which this migration deliberately does not
-- do — 0066's rows have none, and `memo` is the one-line description an invoice
-- with nothing to itemise already carries.
create or replace function invoice_lines_total_the_document() returns trigger
language plpgsql as $$
declare
  head  bigint;
  lines bigint;
begin
  -- Both reads come back NULL together when a tenant is dropped: the cascade
  -- takes the invoice and its lines in one statement and this check runs after
  -- it. So the cascade needs no arm of its own — the comparison below already
  -- calls two NULLs an agreement, and `a_company_with_documents_can_still_be_
  -- deleted` is that case. (A plain `<>` would also let the cascade through,
  -- by answering NULL rather than false; `is distinct from` is here for the
  -- asymmetric case — a head that is gone while a line is not — which
  -- `invoice_lines_invoice_fk` makes unreachable today and a future migration
  -- could make reachable without anybody rereading this function.)
  select amount_minor into head from invoices where id = new.invoice_id;
  select sum(amount_minor) into lines from invoice_lines where invoice_id = new.invoice_id;
  if lines is distinct from head then
    raise exception 'invoice % demands % but its lines total %', new.invoice_id, head, lines
      using errcode = 'restrict_violation';
  end if;
  return null;
end
$$;

drop trigger if exists invoice_lines_total_the_document on invoice_lines;
create constraint trigger invoice_lines_total_the_document
  after insert on invoice_lines
  deferrable initially deferred
  for each row execute function invoice_lines_total_the_document();

alter table invoice_lines enable row level security;
alter table invoice_lines force row level security;
drop policy if exists tenant_isolation on invoice_lines;
create policy tenant_isolation on invoice_lines
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- **No UPDATE at all, not even one column.** 0066 gave the head exactly one
-- writable field because a settlement is a fact that arrives later; a line has
-- no such field — every part of it is the document. So this is 0067's grant
-- (files: no UPDATE, no DELETE) rather than 0066's, and the difference between
-- the two tables is one sentence: an invoice can be paid, a line cannot.
grant select, insert on invoice_lines to app_role;
revoke update, delete on invoice_lines from app_role;
