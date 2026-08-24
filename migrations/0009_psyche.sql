-- 0009_psyche: what one employee has learned about one counterparty.
--
-- This is the port of MPCP's memory layer (mpcp.py: etat["journal"],
-- etat["liens"], etat["croyances"], etat["attentes"], etat["precision"]) to
-- storage. Four tables, one rule holding them together:
--
--   THE OBSERVATIONS ARE THE ONLY SOURCE OF TRUTH. Everything derived from them
--   -- a trust value, a consolidated belief -- must cite the episodes it stands
--   on, and those episodes can never be edited afterwards.
--
-- That is not decoration. The whole point of accumulating a psyche is that in
-- eighteen months someone asks "why does Lena open at 12% below their ask with
-- this supplier?" and the answer is a list of dated observations, not a float
-- somebody once wrote. A belief whose founding episodes can be rewritten is a
-- rumour with a timestamp.
--
-- What is enforced here, rather than in Rust:
--
--   * psyche_episodes is append-only, twice over (privilege + trigger), exactly
--     like audit_log in 0001_core.sql, and for exactly the same reason.
--   * A belief cannot exist without at least one founding episode. Deferred
--     constraint triggers on both sides: you cannot insert a belief and skip
--     the provenance, and you cannot delete the provenance out from under a
--     belief that survives.
--   * A trust value that is not the prior must name the episode that last moved
--     it. `evidence_count = 0` and `trust <> prior_trust` is unwritable.
--   * Provenance cannot cross counterparties. The foreign keys are composite --
--     (id, employee_id, counterparty) -- so an episode about supplier A can
--     never be cited as evidence for a belief about supplier B. This is a
--     schema property, not something a reviewer has to catch.
--
-- PER-TENANT *AND* PER-EMPLOYEE. Every key here starts (tenant_id,
-- employee_id). Two buyers at the same company deal with the same supplier and
-- form different opinions of them, and that difference is the product: Lena has
-- been burned on lead times by this factory, Alex has not, and Alex must not
-- inherit Lena's caution as if it were a company fact. RLS gives us the tenant
-- boundary; employee_id in every primary key gives us the other one.
--
-- WHAT THIS DATA MAY AND MAY NOT DO. It is read to decide what to propose, whom
-- to chase first, and how to phrase it. It is never an input to
-- domain::policy::evaluate(). No column here widens a permission, and none of
-- these tables is joined by the Policy Gate. A frustrated agent and a calm one
-- are allowed exactly the same actions.
--
-- No FK to tenants on psyche_episodes, deliberately, and the reasoning is
-- audit_log's: `ON DELETE CASCADE` would make deleting a tenant a way to delete
-- the observations, and the append-only trigger would in any case refuse the
-- cascade. The derived tables (trust, beliefs, expectations) do cascade -- they
-- are opinions, and opinions are disposable; observations are not.

-- ---------------------------------------------------------------------------
-- psyche_episodes: one observation. Append-only.
-- ---------------------------------------------------------------------------
--
-- MPCP's `journal` entry, minus the parts a purchasing agent has no business
-- keeping (no theory-of-mind attribution, no repression counter, no narrative
-- theme). What survives is the observation itself and what made it land:
-- polarity, weight, and the Rescorla-Wagner surprise measured at the time.

create table if not exists psyche_episodes (
  id               uuid        primary key,
  tenant_id        uuid        not null,
  -- Whose experience this is. Not the tenant's -- see the header.
  employee_id      uuid        not null,
  -- The other party, as a stable key the domain owns the vocabulary for (a
  -- supplier code, a normalised sending domain). Text rather than a FK because
  -- there is no counterparty table in this schema yet, and inventing one here
  -- would be a second unit's migration.
  counterparty     text        not null,
  -- What happened, in the domain's event vocabulary ('quote_received',
  -- 'commitment_kept', 'lead_time_missed', ...). MPCP's `type`.
  kind             text        not null,
  -- Which learned dimension this observation feeds, when it feeds one:
  -- 'price', 'lead_time', 'response_latency', ... Matches
  -- psyche_expectations.dimension. NULL for an episode that moves the
  -- relationship without informing a specific prediction.
  dimension        text,
  -- MPCP `polarite`: -1 / 0 / +1. Zero is a real value (a neutral contact); the
  -- consolidation pass ignores it, which is why beliefs forbid it and this does
  -- not.
  polarity         smallint    not null,
  -- MPCP `poids`: how much this one weighs against a routine event (1.0). A
  -- missed shipment on a critical line is a 3; a mildly late acknowledgement is
  -- a 0.2.
  weight           double precision not null,
  -- MPCP's signed R-W surprise at observation time: observed polarity minus the
  -- expectation held *before* this episode. Stored rather than recomputed, so
  -- replaying the learning curve does not depend on today's expectation. Range
  -- is [-2, 2] because both terms are in [-1, 1].
  surprise         double precision,
  -- MPCP `par`: who reported it. NULL means we experienced it directly. A
  -- colleague's claim about a supplier and our own purchase order are not the
  -- same evidence, and the difference has to survive into the record.
  reported_by      text,
  -- The thread this came out of, for citation. No FK: conversations cascade
  -- from tenants and an observation must outlive that.
  conversation_id  uuid,
  -- The observed amount, when the observation is about money -- a quoted price,
  -- a final price, a penalty. Minor units plus an explicit currency, never a
  -- float, because "quotes 14% high" is only auditable if the two numbers it
  -- came from are exact.
  amount_minor     bigint,
  currency         text,
  -- Everything else the observation carries: promised vs actual days, channel,
  -- incoterm. Structured detail the domain owns.
  detail           jsonb       not null default '{}'::jsonb,
  -- Injected clock, never `now()`: the domain takes `now` as a parameter and
  -- storage must not quietly disagree with it.
  observed_at      timestamptz not null,
  constraint psyche_episodes_polarity_range
    check (polarity in (-1, 0, 1)),
  constraint psyche_episodes_weight_range
    check (weight > 0 and weight <= 10),
  constraint psyche_episodes_surprise_range
    check (surprise is null or (surprise >= -2 and surprise <= 2)),
  constraint psyche_episodes_counterparty_nonempty
    check (length(counterparty) between 1 and 200),
  constraint psyche_episodes_amount_positive
    check (amount_minor is null or amount_minor >= 0),
  constraint psyche_episodes_amount_has_currency
    check ((amount_minor is null) = (currency is null)),
  -- The target of every composite provenance FK below. Redundant with the
  -- primary key on its own, and that is the point: it is what lets Postgres
  -- refuse to cite supplier A's episode as evidence about supplier B.
  constraint psyche_episodes_provenance_key unique (id, employee_id, counterparty)
);

-- The relationship timeline: everything this employee has seen from this
-- counterparty, newest first.
create index if not exists psyche_episodes_counterparty_idx
  on psyche_episodes (tenant_id, employee_id, counterparty, observed_at desc);

-- Belt: app_role has no privilege (granted, then revoked, at the bottom).
-- Braces: a trigger, because a later `GRANT ALL ON ALL TABLES` would undo the
-- belt silently, and because a trigger binds superusers, which no GRANT does.
create or replace function psyche_episodes_append_only() returns trigger
language plpgsql as $$
begin
  raise exception 'psyche_episodes is append-only; % is not permitted', tg_op
    using errcode = 'restrict_violation';
end
$$;

drop trigger if exists psyche_episodes_append_only on psyche_episodes;
create trigger psyche_episodes_append_only
  before update or delete on psyche_episodes
  for each row execute function psyche_episodes_append_only();

-- ---------------------------------------------------------------------------
-- psyche_trust: MPCP's `liens` -- one built/broken trust link per counterparty.
-- ---------------------------------------------------------------------------

create table if not exists psyche_trust (
  tenant_id                uuid        not null references tenants (id) on delete cascade,
  employee_id              uuid        not null references employees (id) on delete cascade,
  counterparty             text        not null,
  -- MPCP `confiance`, clamped to [0, 1].
  trust                    double precision not null,
  -- MPCP `_confiance_initiale`: what this link was worth before any evidence
  -- (0.5 for a stranger). Kept on the row so "unsupported trust" is a CHECK
  -- rather than an application convention.
  prior_trust              double precision not null default 0.5,
  -- How many episodes have moved this link. Zero means untouched prior.
  evidence_count           integer     not null default 0,
  -- The episode that last moved it. Composite FK below: it must be an episode
  -- this employee recorded about *this* counterparty.
  last_evidence_episode_id uuid,
  -- MPCP `brise_le` / `brise_vecu`: when a *built* trust fell off a cliff, and
  -- whether we watched it happen or merely heard about it. A break is a dated
  -- fact, not a low number.
  broken_at                timestamptz,
  broken_experienced       boolean,
  -- The last time they said anything to us, and -- if we are waiting -- when we
  -- started waiting. The second one is what makes "who has gone quiet on me"
  -- a query rather than a hunch.
  last_heard_from_at       timestamptz,
  awaiting_reply_since     timestamptz,
  updated_at               timestamptz not null,
  primary key (tenant_id, employee_id, counterparty),
  constraint psyche_trust_range
    check (trust >= 0 and trust <= 1),
  constraint psyche_trust_prior_range
    check (prior_trust >= 0 and prior_trust <= 1),
  constraint psyche_trust_evidence_count_nonneg
    check (evidence_count >= 0),
  -- No evidence, no opinion: an untouched link is exactly its prior. This is
  -- the constraint that makes a hand-written trust score impossible.
  constraint psyche_trust_needs_evidence
    check (evidence_count > 0 or trust = prior_trust),
  -- ...and a link that claims evidence must name it.
  constraint psyche_trust_cites_its_evidence
    check ((evidence_count = 0) = (last_evidence_episode_id is null)),
  -- A break is an event; it cannot predate the first observation.
  constraint psyche_trust_break_needs_evidence
    check (broken_at is null or evidence_count > 0),
  constraint psyche_trust_break_is_dated
    check ((broken_at is null) = (broken_experienced is null)),
  constraint psyche_trust_counterparty_nonempty
    check (length(counterparty) between 1 and 200),
  constraint psyche_trust_evidence_fk
    foreign key (last_evidence_episode_id, employee_id, counterparty)
    references psyche_episodes (id, employee_id, counterparty)
);

-- "Who has gone quiet on me past this deadline." Partial, because the answer is
-- always a handful of rows out of thousands: only relationships where we are
-- actually waiting on someone qualify.
create index if not exists psyche_trust_quiet_idx
  on psyche_trust (tenant_id, employee_id, awaiting_reply_since)
  where awaiting_reply_since is not null;

-- ---------------------------------------------------------------------------
-- psyche_beliefs + psyche_belief_episodes: MPCP's `croyances`, with genealogy.
-- ---------------------------------------------------------------------------
--
-- MPCP consolidates N episodes of the same polarity about the same subject into
-- one durable belief and lets the episodes fade. Two deviations here, both for
-- audit:
--
--   * MPCP keeps the last 8 source refs (`c["sources"] = (... + refs)[-8:]`).
--     We keep all of them. Rows are cheap; "which observations is this
--     conviction standing on" losing its tail is not.
--   * MPCP's N_CONSOLIDATION = 3 is *not* encoded here. The schema enforces
--     "at least one founding episode" -- the thing that makes an unsupported
--     belief unwritable -- and leaves the tunable threshold to the domain,
--     where it can be changed without a migration.

create table if not exists psyche_beliefs (
  id               uuid        primary key,
  tenant_id        uuid        not null references tenants (id) on delete cascade,
  employee_id      uuid        not null references employees (id) on delete cascade,
  counterparty     text        not null,
  -- What the belief is *about*, in the domain's vocabulary: 'price_padding',
  -- 'lead_time_optimism', 'answers_fast_on_whatsapp'. MPCP's `sujet`, split in
  -- two here because a purchasing agent always has a counterparty and the
  -- queries want it as its own column.
  topic            text        not null,
  -- MPCP forbids consolidating polarity 0: a belief is for or against.
  polarity         smallint    not null,
  -- MPCP `force`, in (0, 1].
  strength         double precision not null,
  -- MPCP `formee_le` / `ravivee_le`. The second drives affective forgetting:
  -- a conviction nothing has refreshed pales.
  formed_at        timestamptz not null,
  refreshed_at     timestamptz not null,
  -- MPCP `vecu`: at least one founding episode was lived directly rather than
  -- reported. Hearsay decays to nothing; direct experience does not.
  from_experience  boolean     not null,
  constraint psyche_beliefs_polarity_range
    check (polarity in (-1, 1)),
  constraint psyche_beliefs_strength_range
    check (strength > 0 and strength <= 1),
  constraint psyche_beliefs_counterparty_nonempty
    check (length(counterparty) between 1 and 200),
  -- MPCP merges into the existing belief of the same (subject, polarity)
  -- instead of accumulating duplicates.
  constraint psyche_beliefs_subject_key
    unique (tenant_id, employee_id, counterparty, topic, polarity),
  -- Target of the composite FK from the provenance table.
  constraint psyche_beliefs_provenance_key unique (id, employee_id, counterparty)
);

create index if not exists psyche_beliefs_counterparty_idx
  on psyche_beliefs (tenant_id, employee_id, counterparty, topic);

-- The genealogy. `employee_id` and `counterparty` are carried so both foreign
-- keys can be composite: the belief and the episode must belong to the same
-- employee AND the same counterparty, or neither key resolves.
create table if not exists psyche_belief_episodes (
  belief_id     uuid        not null,
  episode_id    uuid        not null,
  tenant_id     uuid        not null references tenants (id) on delete cascade,
  employee_id   uuid        not null,
  counterparty  text        not null,
  primary key (belief_id, episode_id),
  constraint psyche_belief_episodes_belief_fk
    foreign key (belief_id, employee_id, counterparty)
    references psyche_beliefs (id, employee_id, counterparty) on delete cascade,
  constraint psyche_belief_episodes_episode_fk
    foreign key (episode_id, employee_id, counterparty)
    references psyche_episodes (id, employee_id, counterparty)
);

create index if not exists psyche_belief_episodes_episode_idx
  on psyche_belief_episodes (episode_id);

-- A belief with no founding episodes is not a weak belief, it is a fabrication.
-- DEFERRABLE INITIALLY DEFERRED because the belief row necessarily exists
-- before its provenance rows can point at it; the check runs at COMMIT, so the
-- pair is atomic and a caller who writes only the belief gets a failed
-- transaction rather than an orphan conviction.
create or replace function psyche_belief_needs_evidence() returns trigger
language plpgsql as $$
declare
  belief uuid;
  founding integer;
begin
  -- Assigned in the body, not in the DECLARE: plpgsql resolves a declaration's
  -- initialiser for both branches at block entry, and `old.belief_id` does not
  -- typecheck against psyche_beliefs' rowtype. In the body the untaken branch
  -- is never planned.
  if tg_op = 'DELETE' then
    belief := old.belief_id;
  else
    belief := new.id;
  end if;
  -- Cascade from the belief itself (or from its tenant): nothing to protect.
  if not exists (select 1 from psyche_beliefs b where b.id = belief) then
    return null;
  end if;
  select count(*) into founding
    from psyche_belief_episodes e where e.belief_id = belief;
  if founding = 0 then
    raise exception 'belief % has no founding episodes; an unsupported belief is not writable',
      belief using errcode = 'check_violation';
  end if;
  return null;
end
$$;

drop trigger if exists psyche_beliefs_require_evidence on psyche_beliefs;
create constraint trigger psyche_beliefs_require_evidence
  after insert or update on psyche_beliefs
  deferrable initially deferred
  for each row execute function psyche_belief_needs_evidence();

-- The other half: you cannot delete the evidence out from under a belief that
-- survives the delete. Without this the invariant is one DELETE away.
drop trigger if exists psyche_belief_episodes_keep_evidence on psyche_belief_episodes;
create constraint trigger psyche_belief_episodes_keep_evidence
  after delete on psyche_belief_episodes
  deferrable initially deferred
  for each row execute function psyche_belief_needs_evidence();

-- ---------------------------------------------------------------------------
-- psyche_expectations: MPCP's `attentes` (Rescorla-Wagner) + `precision`
-- (Welford), one row per (counterparty, dimension).
-- ---------------------------------------------------------------------------
--
-- This is the table that pays for the whole system. "Their quotes come in 14%
-- above where they settle" and "they claim 15 days and the median is 23" are
-- both an expectation plus a running variance of how wrong it has been --
-- MPCP's `1 / (1 + K * var)` precision, computed in the domain from these
-- three numbers rather than stored, so it can never drift from them.

create table if not exists psyche_expectations (
  tenant_id      uuid        not null references tenants (id) on delete cascade,
  employee_id    uuid        not null references employees (id) on delete cascade,
  counterparty   text        not null,
  -- 'price', 'lead_time', 'response_latency', 'quality'. The domain owns the
  -- vocabulary; matches psyche_episodes.dimension.
  dimension      text        not null,
  -- MPCP's R-W expectation in [-1, 1], updated by `attente + TAUX_PRED *
  -- surprise` and pulled back toward 0 by extinction.
  expectation    double precision not null default 0,
  -- Welford's running mean and variance of |surprise|. `surprise_var` is what
  -- precision is 1/(1+K*var) of: a counterparty who is erratic in both
  -- directions has a high variance, and their next data point moves us less.
  surprise_mean  double precision not null default 0,
  surprise_var   double precision not null default 0,
  -- Welford's n. Also the evidence counter: see the CHECK below.
  observations   integer     not null default 0,
  updated_at     timestamptz not null,
  primary key (tenant_id, employee_id, counterparty, dimension),
  constraint psyche_expectations_range
    check (expectation >= -1 and expectation <= 1),
  constraint psyche_expectations_welford_nonneg
    check (surprise_mean >= 0 and surprise_var >= 0 and observations >= 0),
  -- Same rule as trust: with nothing observed, the row is the null prior. An
  -- expectation nobody has ever tested is not an expectation.
  constraint psyche_expectations_needs_observations
    check (observations > 0
           or (expectation = 0 and surprise_mean = 0 and surprise_var = 0)),
  constraint psyche_expectations_counterparty_nonempty
    check (length(counterparty) between 1 and 200)
);

-- (counterparty, dimension) is the primary key's own prefix, so lookups by
-- counterparty and by (counterparty, dimension) both ride it. The extra index
-- is the cross-supplier one: "who is worst on lead time".
create index if not exists psyche_expectations_dimension_idx
  on psyche_expectations (tenant_id, employee_id, dimension, expectation);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array[
    'psyche_episodes', 'psyche_trust', 'psyche_beliefs',
    'psyche_belief_episodes', 'psyche_expectations'
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

grant select, insert, update, delete on
  psyche_trust, psyche_beliefs, psyche_belief_episodes, psyche_expectations
  to app_role;

grant select, insert on psyche_episodes to app_role;
revoke update, delete on psyche_episodes from app_role;
