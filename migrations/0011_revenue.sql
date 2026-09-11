-- 0011_revenue: the seller vertical — prospect accounts, the humans at them,
-- the findings we can prove about their product, and the deals that follow.
--
-- Same shape as 0007_sourcing with prospects instead of suppliers, and the same
-- decisions wherever the shape repeats: tenant isolation is a database
-- property, foreign keys between revenue rows are composite on
-- `(tenant_id, id)`, money is minor units plus an ISO-4217 code with CHECKs on
-- both, and third-party prose is not laundered by being copied into a table
-- that treats it as ours.
--
-- Four things are specific to selling, and they are the whole file.
--
-- 1. THE SUPPRESSION LIST IS THE TABLE THAT MUST NEVER BE WRONG. A person who
--    asked not to be contacted must be impossible to contact again, and
--    "impossible" cannot mean "every future caller remembers to check". So:
--      * `suppressions` is append-only — no UPDATE, no DELETE, for anybody,
--        enforced by a trigger that binds superusers too;
--      * it has NO foreign key to `tenants`, exactly like `audit_log`. An
--        opt-out that a tenant can erase by deleting itself is not an opt-out;
--      * a BEFORE trigger on `contacts` refuses to store an *active* contact
--        whose email or phone is suppressed, and a BEFORE trigger on
--        `opportunity_events` refuses to record an outbound touch against one.
--        Both raise SQLSTATE P0002, which `store::revenue` maps to
--        `RevenueError::Suppressed`;
--      * inserting a suppression deactivates the matching contacts on the spot,
--        so the invariant "no active contact is suppressed" holds from both
--        directions.
--
--    Suppression is per tenant OR global. Global means the person asked to be
--    removed entirely, and it binds every tenant — but it is NOT readable
--    across tenants: the RLS policy is the ordinary per-tenant one, and only
--    the SECURITY DEFINER checker below sees across it. Enforcement without
--    disclosure; one customer's opt-out list is not another customer's lead
--    list.
--
-- 2. EVIDENCE IS APPEND-ONLY AND IMMUTABLE, for the same reason `audit_log` is,
--    and with the same two mechanisms (REVOKE plus a trigger). A finding is a
--    factual claim about another company's product; a finding that can be
--    edited after it was sent is not evidence, it is a draft. Every column that
--    makes a finding reproducible — what was checked, against what, where, when,
--    what their product said, what the right answer is, and how to run it again
--    — is NOT NULL. A row that cannot be reproduced cannot be written.
--
--    `observed_claim` is the prospect's own text, copied verbatim on purpose:
--    it is the quote in the email. It is third-party text and stays
--    `Untrusted<T>` on the Rust side; nothing in this schema makes it ours.
--
-- 3. COMMERCIAL TERMS NEED A HUMAN. `opportunities.approval_id` is the row a
--    person signed, and a CHECK refuses `closed_won` without one. An agent that
--    invents a discount to close a deal has created an obligation; here it
--    instead gets a constraint violation.
--
-- 4. THE SAME COMPANY IS A DIFFERENT ACCOUNT IN EVERY TENANT. `accounts` is
--    unique on `(tenant_id, domain)`, never on `domain`: two customers
--    prospecting Lufthansa hold two unrelated accounts, and neither is visible
--    to the other.
--
-- Replayable: everything is IF NOT EXISTS / OR REPLACE / DROP-then-CREATE.

-- ---------------------------------------------------------------------------
-- accounts
-- ---------------------------------------------------------------------------

create table if not exists accounts (
  id            uuid        primary key,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  legal_name    text        not null,
  -- Registrable domain, lower case. The identity of a prospect: names are
  -- spelled six ways and a booking flow lives at a domain.
  domain        text        not null,
  -- Which of the vertical's segments this is. Airlines carry a legal,
  -- quantifiable cost of being wrong; the rest are ranked below them for a
  -- reason, and the seller filters on this constantly.
  segment       text        not null,
  -- ISO 3166-1 alpha-2, upper case.
  country       text        not null,
  employee_id   uuid        references employees (id) on delete set null,
  state         text        not null default 'candidate',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint accounts_domain_lower check (domain = lower(domain) and domain <> ''),
  constraint accounts_country_iso check (country ~ '^[A-Z]{2}$'),
  constraint accounts_segment check (segment in (
    'airline', 'ota', 'corporate_travel', 'tmc', 'insurer', 'cruise',
    'relocation', 'other'
  )),
  constraint accounts_state check (state in (
    'candidate', 'qualified', 'engaged', 'customer', 'disqualified'
  )),
  -- Per tenant. See decision 4 in the header.
  constraint accounts_domain_key unique (tenant_id, domain),
  constraint accounts_tenant_id_key unique (tenant_id, id)
);

-- "Airlines I have not proved anything about yet" — the work queue that starts
-- the whole pipeline. Disqualified and existing customers are out of it.
create index if not exists accounts_segment_idx
  on accounts (tenant_id, segment, created_at)
  where state in ('candidate', 'qualified');

-- ---------------------------------------------------------------------------
-- contacts
-- ---------------------------------------------------------------------------

create table if not exists contacts (
  id                 uuid        primary key,
  tenant_id          uuid        not null references tenants (id) on delete cascade,
  account_id         uuid        not null,
  full_name          text        not null,
  -- Normalised on the way in so the suppression lookup is an equality test and
  -- not a guess. The CHECK is what makes that true for writers that skip the
  -- store.
  email              text,
  -- E.164.
  phone              text,
  role               text,
  -- BCP-47 tag; which language this human is written to in.
  language           text,
  is_primary         boolean     not null default false,
  active             boolean     not null default true,
  -- GDPR still applies to business contacts, so every approach names its basis.
  -- The daily volume cap is NOT here: it is `max_new_contacts_per_day` in the
  -- policy tables, and a second mechanism for the same rule is how the two
  -- disagree.
  lawful_basis       text        not null default 'legitimate_interest',
  last_contacted_at  timestamptz,
  next_follow_up_at  timestamptz,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  -- A contact you cannot contact is not a contact.
  constraint contacts_reachable check (email is not null or phone is not null),
  constraint contacts_email_lower check (email is null or email = lower(email)),
  constraint contacts_email_shape check (email is null or email ~ '^[^@[:space:]]+@[^@[:space:]]+$'),
  constraint contacts_phone_e164 check (phone is null or phone ~ '^\+[1-9][0-9]{6,14}$'),
  constraint contacts_lawful_basis
    check (lawful_basis in ('legitimate_interest', 'consent', 'contract')),
  constraint contacts_account_fk
    foreign key (tenant_id, account_id) references accounts (tenant_id, id)
    on delete cascade,
  -- One row per human per tenant: two rows for one address is one row that
  -- dodges the suppression cascade.
  constraint contacts_email_key unique (tenant_id, email),
  constraint contacts_tenant_id_key unique (tenant_id, id)
);

-- At most one primary contact per account, and only among active ones.
create unique index if not exists contacts_primary_key
  on contacts (tenant_id, account_id)
  where is_primary and active;

-- The seller's morning query: who is due a follow-up.
create index if not exists contacts_follow_up_idx
  on contacts (tenant_id, next_follow_up_at)
  where active and next_follow_up_at is not null;

create index if not exists contacts_account_idx
  on contacts (tenant_id, account_id)
  where active;

-- Counting today's new contacts against `max_new_contacts_per_day`.
create index if not exists contacts_created_idx on contacts (tenant_id, created_at);

-- ---------------------------------------------------------------------------
-- evidence: what we can prove about their product, and only that
-- ---------------------------------------------------------------------------
--
-- No foreign keys, deliberately, exactly as `audit_log` has none: deleting a
-- prospect — or a tenant — must not be a way to delete a finding. `tenant_id`
-- is still the RLS key, so a finding is visible to exactly one tenant.

create table if not exists evidence (
  id                    uuid        primary key,
  tenant_id             uuid        not null,
  account_id            uuid        not null,
  employee_id           uuid,
  kind                  text        not null,
  -- The query that was run through their own booking flow. Both NOT NULL: a
  -- finding without the pair it was checked with is not reproducible.
  passport_country      text        not null,
  destination_country   text        not null,
  -- The travel date used, when the answer depends on one (it usually does).
  travel_date           date,
  -- Where it was observed and how to see it again.
  source_url            text        not null,
  reproduction          text        not null,
  -- Screenshot / HAR / response body, by reference. The bytes live in object
  -- storage; the claim without them is still reproducible via `reproduction`.
  artifact_ref          text,
  -- THEIR text, verbatim. Third-party content: `Untrusted<T>` in Rust, and
  -- being in this table does not make it ours.
  observed_claim        text        not null,
  -- What the answer actually is, and the government page that says so.
  correct_claim         text        not null,
  authority_url         text,
  -- When it was observed. Not defaulted: a finding stamped with the time it
  -- happened to be inserted is a finding with the wrong date on it.
  checked_at            timestamptz not null,
  created_at            timestamptz not null default now(),
  constraint evidence_kind check (kind in (
    'missing_visa_info', 'wrong_requirement', 'stale_rule', 'missing_transit_visa',
    'wrong_passport_validity', 'wrong_document_list', 'wrong_cost',
    'wrong_processing_time'
  )),
  constraint evidence_passport_iso check (passport_country ~ '^[A-Z]{2}$'),
  constraint evidence_destination_iso check (destination_country ~ '^[A-Z]{2}$'),
  constraint evidence_source_url check (source_url ~ '^https?://'),
  constraint evidence_authority_url
    check (authority_url is null or authority_url ~ '^https?://'),
  constraint evidence_reproduction_nonempty check (length(btrim(reproduction)) > 0),
  constraint evidence_observed_nonempty check (length(btrim(observed_claim)) > 0),
  constraint evidence_correct_nonempty check (length(btrim(correct_claim)) > 0),
  -- Referenced by opportunities and opportunity_events.
  constraint evidence_tenant_id_key unique (tenant_id, id)
);

-- "What have we proved about this account", newest first, and the anti-join
-- behind `accounts_without_evidence`.
create index if not exists evidence_account_idx
  on evidence (tenant_id, account_id, checked_at desc);

-- ---------------------------------------------------------------------------
-- opportunities
-- ---------------------------------------------------------------------------

create table if not exists opportunities (
  id                uuid        primary key,
  tenant_id         uuid        not null references tenants (id) on delete cascade,
  account_id        uuid        not null,
  employee_id       uuid        references employees (id) on delete set null,
  -- The finding that opened it. Nullable, but the whole point of this vertical
  -- is that it usually is not.
  evidence_id       uuid,
  stage             text        not null default 'discovery',
  -- Annual contract value. Minor units plus a code, like everywhere else.
  currency          text        not null,
  value_minor       bigint      not null,
  -- The human decision behind the commercial terms. See decision 3; no FK to
  -- `approvals`, because an approval is evidence and evidence is not cascaded.
  approval_id       uuid,
  -- Bumped by every event. The cold-deal sweep reads exactly this column.
  last_activity_at  timestamptz not null default now(),
  next_step_at      timestamptz,
  expected_close_on date,
  closed_at         timestamptz,
  close_reason      text,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  constraint opportunities_stage check (stage in (
    'discovery', 'qualified', 'evaluation', 'proposal', 'negotiation',
    'closed_won', 'closed_lost'
  )),
  constraint opportunities_currency_iso check (currency ~ '^[A-Z]{3}$'),
  constraint opportunities_value_positive check (value_minor > 0),
  -- A closed deal has a date, and a lost one says why.
  constraint opportunities_closed_at
    check (stage not in ('closed_won', 'closed_lost') or closed_at is not null),
  constraint opportunities_close_reason
    check (stage <> 'closed_lost' or close_reason is not null),
  -- Nobody closes a deal the company did not agree to.
  constraint opportunities_won_needs_approval
    check (stage <> 'closed_won' or approval_id is not null),
  constraint opportunities_account_fk
    foreign key (tenant_id, account_id) references accounts (tenant_id, id)
    on delete cascade,
  constraint opportunities_evidence_fk
    foreign key (tenant_id, evidence_id) references evidence (tenant_id, id),
  constraint opportunities_tenant_id_key unique (tenant_id, id)
);

-- The pipeline review: one stage, biggest first.
create index if not exists opportunities_pipeline_idx
  on opportunities (tenant_id, stage, value_minor desc)
  where stage not in ('closed_won', 'closed_lost');

-- The cold sweep: open deals, longest-silent first.
create index if not exists opportunities_cold_idx
  on opportunities (tenant_id, last_activity_at)
  where stage not in ('closed_won', 'closed_lost');

create index if not exists opportunities_account_idx
  on opportunities (tenant_id, account_id);

-- ---------------------------------------------------------------------------
-- opportunity_events
-- ---------------------------------------------------------------------------
--
-- The structured residue of everything that happened on a deal. The prose stays
-- in `messages`, where it keeps its trust label; `message_id` points at it.
--
-- The CHECKs are the same rule as `supplier_observations_evidence`: every kind
-- carries the row that proves it. Outreach that names no contact is outreach
-- nobody can audit; a shared finding with no evidence id is a claim with no
-- source; an objection with no kind is a mood.

create table if not exists opportunity_events (
  id              uuid        primary key,
  tenant_id       uuid        not null references tenants (id) on delete cascade,
  opportunity_id  uuid        not null,
  contact_id      uuid,
  employee_id     uuid        references employees (id) on delete set null,
  kind            text        not null,
  from_stage      text,
  to_stage        text,
  objection       text,
  message_id      uuid        references messages (id) on delete set null,
  evidence_id     uuid,
  occurred_at     timestamptz not null default now(),
  constraint opportunity_events_kind check (kind in (
    'outreach_sent', 'reply_received', 'call_held', 'meeting_held',
    'evidence_shared', 'proposal_sent', 'objection_raised', 'objection_answered',
    'stage_changed', 'opt_out_received', 'no_response'
  )),
  constraint opportunity_events_objection check (objection is null or objection in (
    'price', 'coverage', 'accuracy', 'build_vs_buy', 'incumbent', 'timing',
    'legal', 'no_need'
  )),
  constraint opportunity_events_stage_change
    check (kind <> 'stage_changed' or (from_stage is not null and to_stage is not null)),
  constraint opportunity_events_objection_kind
    check (kind not in ('objection_raised', 'objection_answered') or objection is not null),
  constraint opportunity_events_has_target
    check (kind not in ('outreach_sent', 'call_held', 'meeting_held', 'evidence_shared',
                        'proposal_sent', 'opt_out_received')
           or contact_id is not null),
  constraint opportunity_events_has_evidence
    check (kind <> 'evidence_shared' or evidence_id is not null),
  constraint opportunity_events_opportunity_fk
    foreign key (tenant_id, opportunity_id) references opportunities (tenant_id, id)
    on delete cascade,
  constraint opportunity_events_contact_fk
    foreign key (tenant_id, contact_id) references contacts (tenant_id, id),
  constraint opportunity_events_evidence_fk
    foreign key (tenant_id, evidence_id) references evidence (tenant_id, id)
);

create index if not exists opportunity_events_timeline_idx
  on opportunity_events (tenant_id, opportunity_id, occurred_at desc);

-- ---------------------------------------------------------------------------
-- suppressions
-- ---------------------------------------------------------------------------
--
-- No FK to `tenants`, and no FK to `contacts`: an opt-out outlives both. See
-- decision 1.

create table if not exists suppressions (
  id             uuid        primary key,
  -- Who recorded it. Not a scope on its own — `scope` is.
  tenant_id      uuid        not null,
  scope          text        not null default 'tenant',
  channel        text        not null,
  -- Normalised the same way `contacts.email` / `contacts.phone` are, because
  -- the check between them is an equality test.
  address        text        not null,
  reason         text        not null,
  -- The contact who asked, when we know which row they were.
  contact_id     uuid,
  -- Free text for the legal record: "replied STOP", ticket reference, ...
  note           text,
  suppressed_at  timestamptz not null default now(),
  constraint suppressions_scope check (scope in ('tenant', 'global')),
  constraint suppressions_channel check (channel in ('email', 'phone')),
  constraint suppressions_reason check (reason in (
    'opt_out', 'complaint', 'bounce', 'legal_request', 'do_not_contact'
  )),
  constraint suppressions_address_normalised check (
    case channel
      when 'email' then address = lower(address) and address ~ '^[^@[:space:]]+@[^@[:space:]]+$'
      else address ~ '^\+[1-9][0-9]{6,14}$'
    end
  ),
  -- Recording the same opt-out twice is not an error the caller should have to
  -- handle; `store::revenue::suppress` says ON CONFLICT DO NOTHING.
  --
  -- `scope` is in the key, and that is load-bearing rather than tidy: this
  -- table takes no UPDATEs, so if the key stopped at `address` then a person
  -- already suppressed for this tenant asking to be removed *everywhere* would
  -- hit ON CONFLICT DO NOTHING and their escalation would be silently dropped.
  -- With scope in the key it is a new row, and the trigger below fires for it.
  --
  -- There is deliberately no cross-tenant unique index on a global address: it
  -- would be an oracle for rows a tenant cannot read.
  constraint suppressions_address_key unique (tenant_id, channel, address, scope)
);

-- The lookup the triggers do, and it must not care whose row it is.
create index if not exists suppressions_address_idx on suppressions (channel, address);

-- ---------------------------------------------------------------------------
-- Suppression enforcement
-- ---------------------------------------------------------------------------
--
-- SECURITY DEFINER so it sees global suppressions recorded by other tenants —
-- that is the entire reason "global" means anything. It takes no tenant
-- parameter: the tenant comes from the GUC that RLS itself uses, so a caller
-- cannot ask about a tenant it is not. With the GUC unset (an admin
-- connection), only global rows apply.

create or replace function revenue_suppression_of(p_email text, p_phone text)
returns text
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select s.reason
    from suppressions s
   where (s.scope = 'global'
          or s.tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
     and ((s.channel = 'email' and s.address = p_email)
          or (s.channel = 'phone' and s.address = p_phone))
   limit 1
$$;

-- P0002 is this schema's "you may not contact this person". `store::revenue`
-- maps it to RevenueError::Suppressed; nothing else in the workspace raises it.
create or replace function contacts_reject_suppressed() returns trigger
language plpgsql as $$
declare
  reason text;
begin
  -- Only active contacts. Deactivating a suppressed contact must stay legal,
  -- or the cascade below could not run.
  if new.active then
    reason := revenue_suppression_of(new.email, new.phone);
    if reason is not null then
      raise exception 'contact % is suppressed (%)', coalesce(new.email, new.phone), reason
        using errcode = 'P0002';
    end if;
  end if;
  return new;
end
$$;

drop trigger if exists contacts_reject_suppressed on contacts;
create trigger contacts_reject_suppressed
  before insert or update on contacts
  for each row execute function contacts_reject_suppressed();

-- The other half: an existing contact row cannot be used as an outreach target.
-- SECURITY DEFINER only to read the contact's own addresses; the tenant filter
-- is `new.tenant_id`, which RLS's WITH CHECK pins to the caller's own tenant.
create or replace function opportunity_events_reject_suppressed() returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  target record;
  reason text;
begin
  if new.contact_id is null
     or new.kind not in ('outreach_sent', 'call_held', 'meeting_held',
                         'evidence_shared', 'proposal_sent') then
    return new;
  end if;

  select c.email, c.phone, c.active into target
    from contacts c
   where c.id = new.contact_id and c.tenant_id = new.tenant_id;
  -- No such contact: the composite foreign key is about to say so.
  if not found then
    return new;
  end if;

  reason := revenue_suppression_of(target.email, target.phone);
  if reason is not null then
    raise exception 'contact % is suppressed (%)', new.contact_id, reason
      using errcode = 'P0002';
  end if;
  if not target.active then
    raise exception 'contact % is not active', new.contact_id
      using errcode = 'P0002';
  end if;
  return new;
end
$$;

drop trigger if exists opportunity_events_reject_suppressed on opportunity_events;
create trigger opportunity_events_reject_suppressed
  before insert on opportunity_events
  for each row execute function opportunity_events_reject_suppressed();

-- Recording an opt-out deactivates the people it names, in the same statement,
-- across every tenant when the scope is global. Application code that has to
-- remember to do this is application code that will one day forget.
create or replace function suppressions_deactivate_contacts() returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  update contacts
     set active = false,
         next_follow_up_at = null,
         updated_at = now()
   where active
     and (new.scope = 'global' or tenant_id = new.tenant_id)
     and ((new.channel = 'email' and email = new.address)
          or (new.channel = 'phone' and phone = new.address));
  return null;
end
$$;

drop trigger if exists suppressions_deactivate_contacts on suppressions;
create trigger suppressions_deactivate_contacts
  after insert on suppressions
  for each row execute function suppressions_deactivate_contacts();

-- ---------------------------------------------------------------------------
-- Immutability: evidence and suppressions
-- ---------------------------------------------------------------------------
--
-- Belt is the GRANT below; braces is this, because a future migration that says
-- `GRANT ALL ON ALL TABLES IN SCHEMA public TO app_role` would undo the belt,
-- and because a trigger also binds superusers, which no GRANT ever does.
--
-- Neither table has a foreign key to `tenants`, so dropping a tenant does not
-- try to delete these rows and does not hit this trigger. That is the same
-- trade `audit_log` makes, for the same reason.

create or replace function revenue_append_only() returns trigger
language plpgsql as $$
begin
  raise exception '% is append-only; % is not permitted', tg_table_name, tg_op
    using errcode = 'restrict_violation';
end
$$;

drop trigger if exists evidence_append_only on evidence;
create trigger evidence_append_only
  before update or delete on evidence
  for each row execute function revenue_append_only();

drop trigger if exists suppressions_append_only on suppressions;
create trigger suppressions_append_only
  before update or delete on suppressions
  for each row execute function revenue_append_only();

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core
-- ---------------------------------------------------------------------------
--
-- `suppressions` included, with the ordinary per-tenant policy: a global
-- suppression binds every tenant through `revenue_suppression_of` without any
-- tenant being able to read it.

do $$
declare
  t text;
begin
  foreach t in array array[
    'accounts', 'contacts', 'evidence', 'opportunities', 'opportunity_events',
    'suppressions'
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
-- No DELETE anywhere: a prospect, a deal or a touch that can be deleted is a
-- commercial record that can be un-happened, and states cover losing and
-- disqualifying. No UPDATE on the three log tables.

grant select, insert, update on accounts, contacts, opportunities to app_role;
grant select, insert on evidence, opportunity_events, suppressions to app_role;

revoke delete on accounts, contacts, opportunities from app_role;
revoke update, delete on evidence, opportunity_events, suppressions from app_role;

grant execute on function revenue_suppression_of(text, text) to app_role;
