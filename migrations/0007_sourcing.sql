-- 0007_sourcing: the buyer vertical — suppliers, RFQs, quotes, negotiations,
-- purchase orders, shipments.
--
-- Four decisions shape this file; the rest is bookkeeping.
--
-- 1. TENANT ISOLATION IS A DATABASE PROPERTY, exactly as in 0001_core: every
--    table carries `tenant_id`, enables and FORCEs RLS, and gets the same
--    `tenant_isolation` policy keyed on `app.tenant_id`.
--
--    One thing 0001 did not need and this file does: **foreign keys are
--    composite on `(tenant_id, id)` wherever a row points at another sourcing
--    row.** Referential integrity is checked by the system, and that check does
--    NOT go through RLS — so a plain `quotes.rfq_id -> rfqs(id)` would happily
--    accept a quote in tenant A pointing at tenant B's RFQ, and the row would
--    then be invisible to both. Including `tenant_id` in the key makes a
--    cross-tenant reference a constraint violation rather than a puzzle.
--
-- 2. MONEY IS MINOR UNITS + AN ISO-4217 CODE, never a float, with CHECK
--    constraints on both. A quote's currency is pinned to its RFQ's currency by
--    a composite FK — `order by landed price` across mixed currencies is not a
--    ranking, it is a bug, and the cheapest place to make it impossible is here.
--    `landed_total_minor` is GENERATED ALWAYS ... STORED: it is a function of
--    the columns beside it, so it cannot drift from them, and it is still an
--    ordinary indexable column.
--
-- 3. REPUTATION IS DERIVED, NOT STORED. There is no `reputation` column
--    anywhere. `supplier_observations` holds the evidence — one row per thing
--    that actually happened, each pointing at the RFQ or purchase order it
--    happened on — and `supplier_reputation` is a VIEW that aggregates it.
--    A score nobody can write is a score nobody can inflate: the view has
--    aggregates, so Postgres will not accept an INSERT into it under any
--    privilege, and app_role holds SELECT on it and nothing else. Recomputing
--    is not a batch job, it is the query.
--
--    The view is `security_invoker = true` (PG15+). Without that it would run
--    as its owner — `postgres`, who bypasses RLS — and would be a hole straight
--    through every policy below.
--
-- 4. SUPPLIER TEXT DOES NOT LIVE HERE. A negotiation round links to a row in
--    `messages`, which already carries `trust_label`; copying the supplier's
--    prose into a sourcing table would launder untrusted text into a table
--    nothing treats as untrusted.

-- ---------------------------------------------------------------------------
-- suppliers
-- ---------------------------------------------------------------------------

create table if not exists suppliers (
  id            uuid        primary key,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  legal_name    text        not null,
  -- ISO 3166-1 alpha-2, upper case. Filtered on constantly, so a typed column
  -- with a shape constraint rather than a free-text country name.
  country       text        not null,
  -- The categories this supplier sells. A small, filtered set per supplier, so
  -- a text[] with a GIN index rather than a join table or a jsonb blob:
  -- `categories @> array['fasteners']` is an index scan.
  categories    text[]      not null default '{}',
  website       text,
  state         text        not null default 'candidate',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint suppliers_country_iso check (country ~ '^[A-Z]{2}$'),
  constraint suppliers_state
    check (state in ('candidate', 'active', 'suspended', 'blocked')),
  -- Referenced by the composite FKs described in the header.
  constraint suppliers_tenant_id_key unique (tenant_id, id)
);

-- The buyer's first query: who sells this, in this country.
create index if not exists suppliers_country_idx
  on suppliers (tenant_id, country)
  where state in ('candidate', 'active');

create index if not exists suppliers_categories_idx
  on suppliers using gin (categories);

-- ---------------------------------------------------------------------------
-- supplier_contacts
-- ---------------------------------------------------------------------------

create table if not exists supplier_contacts (
  id           uuid        primary key,
  tenant_id    uuid        not null references tenants (id) on delete cascade,
  supplier_id  uuid        not null,
  full_name    text        not null,
  email        text,
  phone        text,
  role         text,
  -- BCP-47 tag; which language this human is written to in.
  language     text,
  is_primary   boolean     not null default false,
  active       boolean     not null default true,
  created_at   timestamptz not null default now(),
  -- A contact you cannot contact is not a contact.
  constraint supplier_contacts_reachable check (email is not null or phone is not null),
  constraint supplier_contacts_supplier_fk
    foreign key (tenant_id, supplier_id) references suppliers (tenant_id, id)
    on delete cascade
);

-- At most one primary contact per supplier, and only among active ones.
create unique index if not exists supplier_contacts_primary_key
  on supplier_contacts (tenant_id, supplier_id)
  where is_primary and active;

create index if not exists supplier_contacts_supplier_idx
  on supplier_contacts (tenant_id, supplier_id)
  where active;

-- ---------------------------------------------------------------------------
-- rfqs
-- ---------------------------------------------------------------------------

create table if not exists rfqs (
  id                       uuid        primary key,
  tenant_id                uuid        not null references tenants (id) on delete cascade,
  -- The employee running this sourcing round; the RFQ outlives their tenure.
  employee_id              uuid        references employees (id) on delete set null,
  title                    text        not null,
  product_category         text        not null,
  quantity                 bigint      not null,
  -- 'pcs', 'kg', 'm', ... free text, but never null: a quantity without a unit
  -- is a number two parties will read differently.
  unit                     text        not null,
  incoterm                 text,
  destination_country      text        not null,
  -- Every quote against this RFQ is denominated in this currency; see the
  -- composite FK on `quotes`.
  currency                 text        not null,
  target_unit_price_minor  bigint,
  state                    text        not null default 'draft',
  closes_at                timestamptz,
  created_at               timestamptz not null default now(),
  updated_at               timestamptz not null default now(),
  constraint rfqs_quantity_positive check (quantity > 0),
  constraint rfqs_currency_iso check (currency ~ '^[A-Z]{3}$'),
  constraint rfqs_destination_iso check (destination_country ~ '^[A-Z]{2}$'),
  constraint rfqs_target_positive
    check (target_unit_price_minor is null or target_unit_price_minor > 0),
  constraint rfqs_incoterm check (
    incoterm is null or incoterm in
    ('EXW', 'FCA', 'FAS', 'FOB', 'CFR', 'CIF', 'CPT', 'CIP', 'DAP', 'DPU', 'DDP')
  ),
  constraint rfqs_state
    check (state in ('draft', 'open', 'awarded', 'cancelled', 'closed')),
  -- Referenced by quotes/negotiations, currency included so a quote cannot be
  -- filed against this RFQ in a different currency.
  constraint rfqs_tenant_id_key unique (tenant_id, id),
  constraint rfqs_currency_key unique (tenant_id, id, currency)
);

create index if not exists rfqs_open_idx
  on rfqs (tenant_id, closes_at)
  where state = 'open';

-- ---------------------------------------------------------------------------
-- quotes
-- ---------------------------------------------------------------------------

create table if not exists quotes (
  id                  uuid        primary key,
  tenant_id           uuid        not null references tenants (id) on delete cascade,
  rfq_id              uuid        not null,
  supplier_id         uuid        not null,
  currency            text        not null,
  unit_price_minor    bigint      not null,
  quantity            bigint      not null,
  freight_minor       bigint      not null default 0,
  duties_minor        bigint      not null default 0,
  other_fees_minor    bigint      not null default 0,
  -- What the goods actually cost delivered. Derived, so it cannot disagree
  -- with its parts, and stored, so it can be indexed and ordered by.
  landed_total_minor  bigint
    generated always as
      (unit_price_minor * quantity + freight_minor + duties_minor + other_fees_minor)
    stored,
  lead_time_days      integer,
  incoterm            text,
  -- Not null on purpose: a quote with no expiry is a promise no supplier made.
  valid_until         timestamptz not null,
  state               text        not null default 'received',
  received_at         timestamptz not null default now(),
  created_at          timestamptz not null default now(),
  constraint quotes_unit_price_positive check (unit_price_minor > 0),
  constraint quotes_quantity_positive check (quantity > 0),
  constraint quotes_addons_nonnegative check (
    freight_minor >= 0 and duties_minor >= 0 and other_fees_minor >= 0
  ),
  constraint quotes_lead_time_nonnegative
    check (lead_time_days is null or lead_time_days >= 0),
  constraint quotes_currency_iso check (currency ~ '^[A-Z]{3}$'),
  constraint quotes_incoterm check (
    incoterm is null or incoterm in
    ('EXW', 'FCA', 'FAS', 'FOB', 'CFR', 'CIF', 'CPT', 'CIP', 'DAP', 'DPU', 'DDP')
  ),
  constraint quotes_state
    check (state in ('received', 'withdrawn', 'rejected', 'accepted')),
  -- Same tenant AND same currency as the RFQ it answers.
  constraint quotes_rfq_fk
    foreign key (tenant_id, rfq_id, currency) references rfqs (tenant_id, id, currency)
    on delete cascade,
  constraint quotes_supplier_fk
    foreign key (tenant_id, supplier_id) references suppliers (tenant_id, id),
  constraint quotes_tenant_id_key unique (tenant_id, id)
);

-- The comparison query: live quotes for one RFQ, cheapest landed first.
-- `state` is in the partial predicate; `valid_until` cannot be (the cutoff is
-- `now()`, which is not immutable), so expiry is a cheap filter over an
-- already-ordered index scan.
create index if not exists quotes_live_idx
  on quotes (tenant_id, rfq_id, landed_total_minor)
  where state = 'received';

create index if not exists quotes_supplier_idx on quotes (tenant_id, supplier_id);

-- ---------------------------------------------------------------------------
-- negotiations / negotiation_rounds
-- ---------------------------------------------------------------------------

create table if not exists negotiations (
  id            uuid        primary key,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  rfq_id        uuid        not null,
  supplier_id   uuid        not null,
  -- The quote currently on the table, if any.
  quote_id      uuid,
  employee_id   uuid        references employees (id) on delete set null,
  state         text        not null default 'awaiting_supplier',
  -- When the party we are waiting on owes us an answer. The whole point of the
  -- stalled-negotiation sweep, so it is a real timestamptz column, not a field
  -- inside a json document.
  reply_due_at  timestamptz,
  last_round_at timestamptz,
  round_count   integer     not null default 0,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint negotiations_state check (
    state in ('awaiting_supplier', 'awaiting_buyer', 'agreed', 'failed', 'abandoned')
  ),
  -- Waiting on someone with no deadline is how a negotiation goes quiet
  -- forever. If we are waiting, there is a date.
  constraint negotiations_deadline_when_waiting check (
    state not in ('awaiting_supplier', 'awaiting_buyer') or reply_due_at is not null
  ),
  constraint negotiations_rounds_nonnegative check (round_count >= 0),
  constraint negotiations_rfq_fk
    foreign key (tenant_id, rfq_id) references rfqs (tenant_id, id) on delete cascade,
  constraint negotiations_supplier_fk
    foreign key (tenant_id, supplier_id) references suppliers (tenant_id, id),
  constraint negotiations_quote_fk
    foreign key (tenant_id, quote_id) references quotes (tenant_id, id),
  -- One live thread per supplier per RFQ.
  constraint negotiations_rfq_supplier_key unique (tenant_id, rfq_id, supplier_id),
  constraint negotiations_tenant_id_key unique (tenant_id, id)
);

-- The sweep: who owes us a reply and is late.
create index if not exists negotiations_awaiting_reply_idx
  on negotiations (tenant_id, reply_due_at)
  where state = 'awaiting_supplier';

create table if not exists negotiation_rounds (
  id                uuid        primary key,
  tenant_id         uuid        not null references tenants (id) on delete cascade,
  negotiation_id    uuid        not null,
  round_no          integer     not null,
  party             text        not null,
  -- The prose lives in `messages`, with its trust_label attached. This is the
  -- structured residue: what was actually offered.
  message_id        uuid        references messages (id) on delete set null,
  currency          text,
  unit_price_minor  bigint,
  quantity          bigint,
  lead_time_days    integer,
  incoterm          text,
  occurred_at       timestamptz not null default now(),
  constraint negotiation_rounds_party check (party in ('buyer', 'supplier')),
  constraint negotiation_rounds_round_positive check (round_no > 0),
  constraint negotiation_rounds_price_has_currency
    check ((unit_price_minor is null) = (currency is null)),
  constraint negotiation_rounds_price_positive
    check (unit_price_minor is null or unit_price_minor > 0),
  constraint negotiation_rounds_quantity_positive
    check (quantity is null or quantity > 0),
  constraint negotiation_rounds_lead_time_nonnegative
    check (lead_time_days is null or lead_time_days >= 0),
  constraint negotiation_rounds_currency_iso
    check (currency is null or currency ~ '^[A-Z]{3}$'),
  constraint negotiation_rounds_incoterm check (
    incoterm is null or incoterm in
    ('EXW', 'FCA', 'FAS', 'FOB', 'CFR', 'CIF', 'CPT', 'CIP', 'DAP', 'DPU', 'DDP')
  ),
  constraint negotiation_rounds_negotiation_fk
    foreign key (tenant_id, negotiation_id) references negotiations (tenant_id, id)
    on delete cascade,
  -- Replaying a webhook must not invent a second round 3.
  constraint negotiation_rounds_no_key unique (tenant_id, negotiation_id, round_no)
);

-- ---------------------------------------------------------------------------
-- purchase_orders
-- ---------------------------------------------------------------------------

create table if not exists purchase_orders (
  id                uuid        primary key,
  tenant_id         uuid        not null references tenants (id) on delete cascade,
  po_number         text        not null,
  supplier_id       uuid        not null,
  rfq_id            uuid,
  quote_id          uuid,
  employee_id       uuid        references employees (id) on delete set null,
  -- The human decision that let this money leave. Nullable because a PO under
  -- the auto-approval threshold has none, and no FK to `approvals` beyond the
  -- id: an approval is evidence, and evidence does not get cascade-deleted.
  approval_id       uuid,
  currency          text        not null,
  unit_price_minor  bigint      not null,
  quantity          bigint      not null,
  freight_minor     bigint      not null default 0,
  duties_minor      bigint      not null default 0,
  total_minor       bigint
    generated always as (unit_price_minor * quantity + freight_minor + duties_minor)
    stored,
  incoterm          text,
  state             text        not null default 'draft',
  issued_at         timestamptz,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  constraint purchase_orders_unit_price_positive check (unit_price_minor > 0),
  constraint purchase_orders_quantity_positive check (quantity > 0),
  constraint purchase_orders_addons_nonnegative
    check (freight_minor >= 0 and duties_minor >= 0),
  constraint purchase_orders_currency_iso check (currency ~ '^[A-Z]{3}$'),
  constraint purchase_orders_incoterm check (
    incoterm is null or incoterm in
    ('EXW', 'FCA', 'FAS', 'FOB', 'CFR', 'CIF', 'CPT', 'CIP', 'DAP', 'DPU', 'DDP')
  ),
  constraint purchase_orders_state check (
    state in ('draft', 'issued', 'acknowledged', 'shipped', 'received', 'closed', 'cancelled')
  ),
  -- Issued means sent to a supplier; it has a date.
  constraint purchase_orders_issued_at
    check (state in ('draft', 'cancelled') or issued_at is not null),
  constraint purchase_orders_supplier_fk
    foreign key (tenant_id, supplier_id) references suppliers (tenant_id, id),
  constraint purchase_orders_rfq_fk
    foreign key (tenant_id, rfq_id) references rfqs (tenant_id, id),
  constraint purchase_orders_quote_fk
    foreign key (tenant_id, quote_id) references quotes (tenant_id, id),
  constraint purchase_orders_number_key unique (tenant_id, po_number),
  constraint purchase_orders_tenant_id_key unique (tenant_id, id)
);

create index if not exists purchase_orders_supplier_idx
  on purchase_orders (tenant_id, supplier_id, created_at desc);

-- ---------------------------------------------------------------------------
-- shipments
-- ---------------------------------------------------------------------------

create table if not exists shipments (
  id                 uuid        primary key,
  tenant_id          uuid        not null references tenants (id) on delete cascade,
  purchase_order_id  uuid        not null,
  carrier            text,
  tracking_ref       text,
  mode               text,
  state              text        not null default 'booked',
  etd                date,
  eta                date,
  delivered_at       timestamptz,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  constraint shipments_mode
    check (mode is null or mode in ('sea', 'air', 'road', 'rail', 'courier')),
  constraint shipments_state
    check (state in ('booked', 'in_transit', 'customs', 'delivered', 'exception')),
  constraint shipments_delivered_at
    check ((state = 'delivered') = (delivered_at is not null)),
  constraint shipments_po_fk
    foreign key (tenant_id, purchase_order_id) references purchase_orders (tenant_id, id)
    on delete cascade
);

-- Everything still moving, soonest arrival first — the "where is my stuff"
-- query and the late-shipment sweep are the same index.
create index if not exists shipments_in_flight_idx
  on shipments (tenant_id, eta)
  where state in ('booked', 'in_transit', 'customs', 'exception');

create index if not exists shipments_po_idx on shipments (tenant_id, purchase_order_id);

-- ---------------------------------------------------------------------------
-- supplier_observations: the evidence reputation is made of
-- ---------------------------------------------------------------------------
--
-- Every row is one thing that happened, tied to the RFQ or purchase order it
-- happened on. The `evidence` CHECK is the load-bearing part: a delivery or
-- quality observation without a purchase order, or a responsiveness
-- observation without an RFQ, is not an observation — it is an opinion, and the
-- table refuses it.

create table if not exists supplier_observations (
  id                 uuid        primary key,
  tenant_id          uuid        not null references tenants (id) on delete cascade,
  supplier_id        uuid        not null,
  kind               text        not null,
  rfq_id             uuid,
  purchase_order_id  uuid,
  observed_at        timestamptz not null default now(),
  created_at         timestamptz not null default now(),
  constraint supplier_observations_kind check (kind in (
    'quote_returned', 'quote_missed',
    'delivery_on_time', 'delivery_late',
    'quality_accepted', 'quality_rejected',
    'dispute'
  )),
  constraint supplier_observations_evidence check (
    case kind
      when 'quote_returned' then rfq_id is not null
      when 'quote_missed'   then rfq_id is not null
      else purchase_order_id is not null
    end
  ),
  constraint supplier_observations_supplier_fk
    foreign key (tenant_id, supplier_id) references suppliers (tenant_id, id)
    on delete cascade,
  constraint supplier_observations_rfq_fk
    foreign key (tenant_id, rfq_id) references rfqs (tenant_id, id),
  constraint supplier_observations_po_fk
    foreign key (tenant_id, purchase_order_id) references purchase_orders (tenant_id, id)
);

create index if not exists supplier_observations_supplier_idx
  on supplier_observations (tenant_id, supplier_id, observed_at desc);

-- ---------------------------------------------------------------------------
-- supplier_reputation: derived, and derived is all it is
-- ---------------------------------------------------------------------------
--
-- No table, no cached score, no nightly recompute job to go stale. A supplier
-- with no observations does not appear here at all, which is the correct
-- answer to "what is their on-time rate" and one an unwritten default column
-- could never give.
--
-- ponytail: recomputed per query. It aggregates one indexed range per supplier;
-- if a tenant ever accumulates enough observations for that to hurt, make it a
-- MATERIALIZED view and refresh it — the SQL below does not change.

create or replace view supplier_reputation with (security_invoker = true) as
select
  o.tenant_id,
  o.supplier_id,
  count(*)                                                       as observation_count,
  count(*) filter (where o.kind = 'quote_returned')              as quotes_returned,
  count(*) filter (where o.kind = 'quote_missed')                as quotes_missed,
  count(*) filter (where o.kind = 'delivery_on_time')            as delivered_on_time,
  count(*) filter (where o.kind = 'delivery_late')               as delivered_late,
  count(*) filter (where o.kind = 'quality_accepted')            as quality_accepted,
  count(*) filter (where o.kind = 'quality_rejected')            as quality_rejected,
  count(*) filter (where o.kind = 'dispute')                     as disputes,
  -- Integer percentages: no float ever enters a supplier's score. NULL where
  -- there is nothing to divide by, because "no data" is not "0%".
  (100 * count(*) filter (where o.kind = 'delivery_on_time')
     / nullif(count(*) filter (where o.kind in ('delivery_on_time', 'delivery_late')), 0)
  )::int                                                         as on_time_rate_pct,
  (100 * count(*) filter (where o.kind = 'quote_returned')
     / nullif(count(*) filter (where o.kind in ('quote_returned', 'quote_missed')), 0)
  )::int                                                         as response_rate_pct,
  (100 * count(*) filter (where o.kind = 'quality_accepted')
     / nullif(count(*) filter (where o.kind in ('quality_accepted', 'quality_rejected')), 0)
  )::int                                                         as quality_rate_pct,
  max(o.observed_at)                                             as last_observed_at
from supplier_observations o
group by o.tenant_id, o.supplier_id;

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array[
    'suppliers', 'supplier_contacts', 'rfqs', 'quotes', 'negotiations',
    'negotiation_rounds', 'purchase_orders', 'shipments', 'supplier_observations'
  ]
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format(
      'create policy tenant_isolation on %I'
      ' using (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)'
      ' with check (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );
  end loop;
end
$$;

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- No DELETE. A purchase order, a quote or a shipment that can be deleted is a
-- procurement record that can be un-happened; states cover withdrawal and
-- cancellation. Tenant deletion still cascades, because that runs as the owner.

grant select, insert, update on
  suppliers, supplier_contacts, rfqs, quotes, negotiations, negotiation_rounds,
  purchase_orders, shipments, supplier_observations
  to app_role;

revoke delete on
  suppliers, supplier_contacts, rfqs, quotes, negotiations, negotiation_rounds,
  purchase_orders, shipments, supplier_observations
  from app_role;

-- SELECT and nothing else. Even that is belt-and-braces: the view aggregates,
-- so it is not auto-updatable and Postgres rejects writes to it outright.
grant select on supplier_reputation to app_role;
