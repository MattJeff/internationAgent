-- 0013_proof_of_need: every proof-of-need check leaves a row, not only the ones
-- that produced evidence.
--
-- `crates/app/src/proof_of_need.rs` drives a prospect's own booking flow twice
-- and compares the panel byte for byte. Anything that is not a byte-identical
-- repeat yields no evidence — deliberately, and that bar is not moving here or
-- anywhere else. What was missing is the *count*. A true positive suppressed
-- because the prospect's site served graduated friction on run two looked
-- exactly like a flow that is genuinely flaky, and neither was written down at
-- all, so "how often do we suppress a real finding" had no answer but a guess.
--
-- Same idea as `supplier_observations` in 0007_sourcing, one vertical over:
-- write the misses next to the hits and derive the rate rather than storing it.
--
-- Three decisions, and the rest is bookkeeping.
--
-- 1. ONE ROW PER ATTEMPT, INCLUDING THE ATTEMPTS THAT REACHED NOTHING.
--    `outcome` is `Checked::code()` on the Rust side, plus `'error'` for a check
--    that did not reach an outcome at all (the gate refused, or the browser
--    failed). The CHECK below is that enum, written out.
--
-- 2. `detail` IS PAIRED WITH `outcome` BY A CHECK, the same shape as
--    `supplier_observations_evidence`: `'not_reproducible'` and `'error'` carry
--    a sub-reason, and nothing else may. A `not_reproducible` row with no reason
--    on it is precisely the row this migration exists to stop being written.
--
-- 3. NO PROSPECT TEXT LIVES HERE. Not one column holds a byte the prospect's
--    page wrote. A challenge page's wording is a third party's text and copying
--    it into a table nothing treats as untrusted is how `Untrusted<T>` gets
--    laundered; the *classification* is ours, so the classification is what is
--    stored. The verbatim quote already has a home — `evidence.observed_claim`
--    — and it only gets one when there is a finding to attach it to.
--
-- Replayable: IF NOT EXISTS / OR REPLACE throughout.

-- ---------------------------------------------------------------------------
-- proof_of_need_attempts
-- ---------------------------------------------------------------------------

create table if not exists proof_of_need_attempts (
  id                   uuid        primary key,
  tenant_id            uuid        not null references tenants (id) on delete cascade,
  -- Registrable domain, lower case: the same key `accounts.domain` is unique on,
  -- so `join accounts using (tenant_id, domain)` is an equality test.
  --
  -- Deliberately NOT a foreign key. A flow is configured by an operator and can
  -- be probed before anybody creates the account row, and an attempt that cannot
  -- be filed is an attempt that does not get counted — which is the failure this
  -- table exists to fix.
  prospect_domain      text        not null,
  employee_id          uuid        references employees (id) on delete set null,
  outcome              text        not null,
  -- The sub-reason, when the outcome has one. See decision 2.
  detail               text,
  -- The pair that was put through the flow, so a suppressed attempt can be run
  -- again with the same inputs. All three NOT NULL: entry rules are
  -- date-dependent, and an attempt nobody can repeat is not a measurement.
  passport_country     text        not null,
  destination_country  text        not null,
  travel_date          date        not null,
  -- When the check ran. Not defaulted, for the same reason `evidence.checked_at`
  -- is not: a row stamped with the time it happened to be inserted has the wrong
  -- date on it.
  checked_at           timestamptz not null,
  created_at           timestamptz not null default now(),
  constraint proof_of_need_attempts_outcome check (outcome in (
    -- A reproducible discrepancy: evidence was produced.
    'evidence',
    -- Their flow agrees with the authority. A good answer, not a suppression.
    'agrees',
    -- Their flow mentions visas and we could not parse a requirement.
    'unreadable',
    -- The two runs disagreed. `detail` says as much as we could tell.
    'not_reproducible',
    -- A run served what reads as a bot challenge. Evidence about us, not them.
    'blocked',
    -- The authoritative answer was too old to stand behind. No page was loaded.
    'truth_stale',
    -- The check never reached an outcome; `detail` is the error code.
    'error'
  )),
  constraint proof_of_need_attempts_detail check (
    case outcome
      when 'not_reproducible' then detail is not null
      when 'error'            then detail is not null
      else detail is null
    end
  ),
  constraint proof_of_need_attempts_domain_lower
    check (prospect_domain = lower(prospect_domain) and prospect_domain <> ''),
  constraint proof_of_need_attempts_passport_iso
    check (passport_country ~ '^[A-Z]{2}$'),
  constraint proof_of_need_attempts_destination_iso
    check (destination_country ~ '^[A-Z]{2}$'),
  constraint proof_of_need_attempts_detail_nonempty
    check (detail is null or length(btrim(detail)) > 0)
);

-- "What happened the last time we probed this prospect", and the scan behind
-- the view below.
create index if not exists proof_of_need_attempts_domain_idx
  on proof_of_need_attempts (tenant_id, prospect_domain, checked_at desc);

-- ---------------------------------------------------------------------------
-- proof_of_need_suppression: the rate, derived, per prospect
-- ---------------------------------------------------------------------------
--
-- No stored rate and no nightly recompute, exactly as `supplier_reputation`:
-- the number is the query. A prospect that has never been probed does not appear
-- here, which is the correct answer to "what is our suppression rate on them"
-- and one a defaulted column could never give.
--
-- The denominator is the attempts that ACTUALLY REACHED THEIR PAGE.
-- `truth_stale` never loaded one and `error` never got past the gate or the
-- browser, so counting either would dilute the very number an operator is
-- reading. Integer percentage, NULL when there is nothing to divide by, because
-- "not probed" is not "0%".
--
-- ponytail: recomputed per query, over one indexed range per prospect. If a
-- tenant ever probes enough for that to hurt, make it MATERIALIZED and refresh
-- it; the SQL does not change.

create or replace view proof_of_need_suppression with (security_invoker = true) as
select
  a.tenant_id,
  a.prospect_domain,
  count(*)                                                          as attempts,
  count(*) filter (where a.outcome = 'evidence')                    as evidence,
  count(*) filter (where a.outcome = 'agrees')                      as agrees,
  count(*) filter (where a.outcome = 'unreadable')                  as unreadable,
  count(*) filter (where a.outcome = 'blocked')                     as blocked,
  count(*) filter (where a.outcome = 'not_reproducible')            as not_reproducible,
  -- Broken out, because an operator reads the three differently.
  --
  -- `same_answer`: both runs stated the SAME requirement and only the bytes
  -- differed — a timestamp, a rotating banner. This is the one that says the
  -- byte-for-byte bar is costing findings it did not mean to cost. It is a
  -- number to look at, not a licence to compare loosely; nothing downstream
  -- turns it into evidence.
  --
  -- `flow_disagreed`: their flow gave two DIFFERENT requirements to two
  -- identical runs. A real fact about their product, and one we cannot prove.
  --
  -- `undetermined`: the texts differed and we could not classify it. Unknown,
  -- and counted as unknown.
  count(*) filter (where a.outcome = 'not_reproducible' and a.detail = 'same_answer')
                                                                    as same_answer,
  count(*) filter (where a.outcome = 'not_reproducible' and a.detail = 'answers')
                                                                    as flow_disagreed,
  count(*) filter (where a.outcome = 'not_reproducible' and a.detail = 'undetermined')
                                                                    as undetermined,
  count(*) filter (where a.outcome = 'truth_stale')                 as truth_stale,
  count(*) filter (where a.outcome = 'error')                       as errors,
  (100 * count(*) filter (where a.outcome in ('blocked', 'not_reproducible'))
     / nullif(count(*) filter (where a.outcome in (
         'evidence', 'agrees', 'unreadable', 'blocked', 'not_reproducible'
       )), 0)
  )::int                                                            as suppression_rate_pct,
  max(a.checked_at)                                                 as last_checked_at
from proof_of_need_attempts a
group by a.tenant_id, a.prospect_domain;

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core
-- ---------------------------------------------------------------------------

alter table proof_of_need_attempts enable row level security;
alter table proof_of_need_attempts force row level security;
drop policy if exists tenant_isolation on proof_of_need_attempts;
create policy tenant_isolation on proof_of_need_attempts
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- Append-only to the app: a suppression rate the application can edit is a
-- suppression rate that reads however somebody wanted it to read. No trigger to
-- go with the REVOKE, unlike `evidence` — this table DOES have a foreign key to
-- `tenants`, so dropping a tenant must be allowed to cascade through it, and a
-- BEFORE DELETE trigger binds the owner too and would block exactly that.
-- Measurement is not a legal record; the finding it measures already is one.

grant select, insert on proof_of_need_attempts to app_role;
revoke update, delete on proof_of_need_attempts from app_role;

grant select on proof_of_need_suppression to app_role;
