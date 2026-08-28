-- 0070_outreach_warmup: the cold-contact ceiling stops being a number somebody
-- edits, and starts being a number that walks — downwards first.
--
-- `docs/ORIZN.md` states the gap this closes, and states it as two halves in
-- this order:
--
--   > The ceiling is a static number in a policy layer; there is no path that
--   > raises it as the domain ages, and no measurement of deliverability to
--   > raise it against.
--
-- The second half is the one that has to be built first. A ramp with no
-- measurement is a number that climbs on its own, which is strictly worse than
-- a number that does not move: the static 5 is at least wrong in a direction
-- somebody chose.
--
-- ---------------------------------------------------------------------------
-- THE THING THIS MUST NOT BE, AND IT IS THE WHOLE DESIGN
-- ---------------------------------------------------------------------------
--
-- **A ramp is a mechanism for widening a policy, and nothing in this workspace
-- may widen a policy.** Allowlists intersect, denylists union, an empty layer
-- denies, and a lower layer only ever narrows — `PolicyLimits::intersect` is
-- `min` and `&&` and there is no other operator in it. A table that let
-- `max_new_contacts_per_day` become 6 when an operator wrote 5 would be the
-- first thing here that unwrote an operator's document, and it would do it
-- from a row an agent's own sending behaviour influences.
--
-- So this is not a ramp on the ceiling. It is a **second narrowing, applied
-- under the first**, and the only thing that ever moves is how much of the
-- operator's own number is released today:
--
--     effective = min(max_new_contacts_per_day, warmup_allowance)
--
-- `min` in that expression is the entire safety argument, and it is the one
-- `agentos_store::outreach::reserve` computes. Whatever this table says, and
-- whatever a measurement says, an employee written down as 5 can never take a
-- sixth stranger — `warmup_allowance` may return a thousand and the `min` is
-- still 5. `agentos_domain::policy`'s
-- `the_warmup_never_returns_more_than_the_operator_wrote` sweeps the whole
-- input space and says so, and `store::outreach`'s
-- `a_tenant_capped_at_five_stays_at_five_however_warm_the_domain_is` says it
-- again against a real database.
--
-- What changes is the *meaning* of the operator's number for an enrolled
-- tenant. It stops being "what this seat sends today" and becomes "what this
-- seat sends once the domain is old enough and healthy enough to carry it".
-- That is the sentence `ORIZN.md` was missing: the founder writes the
-- destination once, and the ramp walks there on its own.
--
-- ---------------------------------------------------------------------------
-- WHY A ROW AT ALL, AND WHY ITS ABSENCE IS NOT A MEASUREMENT
-- ---------------------------------------------------------------------------
--
-- Two inputs, and neither of them exists anywhere in this schema.
--
-- 1. **The domain's age.** Nothing here knows when `agents.example.com` started
--    sending. `min(outreach_buckets.day)` was considered and rejected: that
--    table was created by `0055`, three weeks ago, so it would date every
--    tenant in the deployment from the afternoon that migration landed and
--    would keep being wrong for a tenant that changes sending domain — the one
--    case where a warmup schedule matters most.
--
-- 2. **Whether the deliverability signal arrives at all**, which is the
--    founder's own open question, quoted verbatim in
--    `crates/app/src/inbound.rs::record_refusal`:
--
--      > Is the Resend endpoint actually subscribed to `email.bounced` and
--      > `email.complained`? Which events an endpoint sends is a checkbox in
--      > Resend's dashboard; nothing in this process can read it.
--
--    That is still true. This table does not read the checkbox; it gives the
--    answer a place to live, and — this is the part that matters — makes the
--    unticked box have a **mechanical consequence you can watch** instead of a
--    comment nobody reads. See the column.
--
-- Enrolment is a row, and **no row means the ramp is not installed for this
-- tenant and nothing about their day changes.** That is not "unknown counts as
-- healthy". It is `0055`'s deployment-day argument, made once more: a
-- narrowing that switches itself on for everybody the afternoon it is applied
-- would cut a running business from five strangers a day to one, with no
-- operator having asked for it and no line anywhere saying why. Absence of a
-- row is the status quo — the operator's written ceiling, exactly as today.
--
-- Inside an enrolled tenant, "we cannot see" is a floor and never a pass. That
-- distinction is the whole of it: the ramp declining to exist is not the ramp
-- declaring everything fine.
--
-- ---------------------------------------------------------------------------
-- WHY `app_role` GETS `SELECT` AND NOTHING ELSE
-- ---------------------------------------------------------------------------
--
-- The precedent is `0062`, and the argument is that one's. These two columns
-- are the only writable thing in this workspace that could *release* something,
-- and they sit in a table an agent's own transaction can reach. Even released
-- to the maximum they cannot pass `max_new_contacts_per_day` — the `min`
-- above — so a lying row buys exactly the behaviour the tenant already has
-- without this table, which is the correct blast radius for a lever that
-- points the wrong way. It is still not a lever an employee should be able to
-- pull, and read-only costs nothing: enrolling a tenant is a deployment
-- decision an operator makes once, in `admin_tx_bypassing_rls`, the same way
-- `install_ceiling` writes the platform layer.
--
-- No route today, deliberately: nothing has asked for one, and the `insert`
-- that enrols a tenant is three lines of SQL in a runbook. The day one is
-- wanted, it grants `insert, update` here and answers who may call it.
--
-- ---------------------------------------------------------------------------
-- NO DELETE, and the argument is `0055`'s rather than `0067`'s
-- ---------------------------------------------------------------------------
--
-- `app_role` may not write this table at all, so the interesting question is
-- what an operator's own path may do. Unenrolling is `delete`, and it is the
-- one move here that widens: it takes a tenant from `min(written, allowance)`
-- back to `written` in one statement, with the audit trail saying only that a
-- row went away. `revoke delete` puts that behind the owner, beside every
-- other ledger in this schema — `turn_buckets`, `outreach_buckets`,
-- `work_items`, `suppressions` — none of which lets the app hand back
-- something it consumed. Tenant deletion still cascades, because that runs as
-- the owner.

create table if not exists outreach_warmup (
  -- One row per tenant, and the key is the tenant rather than the employee on
  -- purpose. A ceiling is per seat because a limit is per seat; a **reputation
  -- is per sending domain**, and every seat in a tenant sends from the same
  -- one. So the measurement below is tenant-wide and so is the age.
  --
  -- ponytail: one sending domain per tenant is assumed and not modelled. A
  -- tenant running two domains warms both on the older one's schedule. Add
  -- `domain text` to the key the day a tenant has two, and nothing above this
  -- line changes.
  tenant_id                    uuid        primary key
                                           references tenants (id) on delete cascade,

  -- When this domain started sending, in the operator's own words. The ramp's
  -- coordinate: `day - warming_started_on` in days.
  --
  -- A future date is not refused here — `current_date` is not immutable and
  -- Postgres will not take it in a CHECK — and does not need to be: a negative
  -- age clamps to zero in `agentos_domain::policy::warmup_allowance`, which is
  -- the floor, which is the safe direction.
  --
  -- **Calendar days and not days-on-which-we-sent**, which is the weaker of the
  -- two and is chosen anyway: it is one subtraction against one column, and a
  -- domain that sat idle for four months and comes back is caught by the
  -- measurement on its next reserve rather than by its age. Named as the
  -- residual it is.
  warming_started_on           date        not null,

  -- **The founder's checkbox, given somewhere to be answered.**
  --
  -- NULL means nobody has confirmed that this deployment's provider endpoint is
  -- subscribed to `email.bounced` and `email.complained`. While it is NULL and
  -- no refusal has ever actually been recorded for this tenant, the measurement
  -- is `Deliverability::Unknown` and the ramp holds at its floor — so a tenant
  -- enrolled against an unticked box visibly sits at one stranger a day and
  -- never moves, which is the symptom that sends somebody to the dashboard.
  --
  -- It is an attestation and attestations are wrong sometimes, so it is not the
  -- only way out of `Unknown`: **one recorded refusal, ever, is the stronger
  -- evidence and needs no operator at all.** A `mail_refused` row can only have
  -- been written by `app::inbound::record_refusal`, which only runs on a
  -- verified delivery the provider actually sent. Observation beats
  -- attestation; the attestation exists because a genuinely clean list may
  -- never produce the observation.
  --
  -- What was considered and rejected as evidence: counting `outbox_events` of
  -- type `webhook.email.received`. Every verified delivery is filed there by
  -- `routes::webhooks`, so the rows are real and plentiful — and they prove
  -- only that *an* endpoint exists, never which event types it is subscribed
  -- to. An endpoint wired for `email.received` alone produces exactly the same
  -- evidence as one wired for everything. It answers a question nobody asked.
  refusal_events_confirmed_at  timestamptz,

  updated_at                   timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core. No exceptions.
-- ---------------------------------------------------------------------------

alter table outreach_warmup enable row level security;
alter table outreach_warmup force row level security;
drop policy if exists tenant_isolation on outreach_warmup;
create policy tenant_isolation on outreach_warmup
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Read-only to the application. See the argument above; the writer is an
-- operator in `admin_tx_bypassing_rls`.
grant select on outreach_warmup to app_role;
revoke insert, update, delete on outreach_warmup from app_role;

-- ---------------------------------------------------------------------------
-- The measurement's index
-- ---------------------------------------------------------------------------
--
-- `store::outreach::warmup_release` counts `mail_refused` rows per tenant
-- over a window, and `audit_log`'s two existing indexes cannot serve it:
-- `audit_log_tenant_time_idx` is `(tenant_id, occurred_at)` and does not know
-- about `action_kind`, and `0049`'s is `(tenant_id, employee_id, action_kind,
-- …)` while a refusal carries no `employee_id` — the provider told us about an
-- address, not about a seat — so the column that would have to be the second
-- key part is NULL on every row this query wants.
--
-- Partial, because a refusal is a rare row in a table that grows with every
-- decision the gate makes. The index is the size of the complaints, not the
-- size of the trail.
create index if not exists audit_log_mail_refused_idx
  on audit_log (tenant_id, occurred_at desc)
  where action_kind = 'mail_refused';

-- No index for the denominator. It is `sum(contacts_taken)` over
-- `outreach_buckets` for one tenant across the window, and that table's primary
-- key already leads with `tenant_id`; a tenant's rows number employees × days
-- and the window is thirty of them.
