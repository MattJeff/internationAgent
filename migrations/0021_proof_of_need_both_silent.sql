-- 0021_proof_of_need_both_silent: the other half of "the bar is mis-set".
--
-- 0015 broke `not_reproducible` out into three reasons and told an operator to
-- watch `same_answer` — both runs stated the SAME requirement and the
-- byte-for-byte comparison threw the finding away over a clock. That is a
-- suppressed `Finding::Contradicts`, and it is diagnosable.
--
-- The other kind of finding this module makes is `Finding::SaysNothing`, and it
-- was invisible. A panel that says nothing about entry requirements has no
-- requirement to compare, so identical churn around it fell into
-- `undetermined` — pooled with half-loaded widgets and pages we never got. Half
-- the suppression, in the bucket labelled "we do not know". The commercial
-- argument for this whole motion is the suppression rate, so a number that
-- counts half of it is the wrong number to tune a selector against.
--
-- `Divergence::BothSilent` is the fourth reason: BOTH runs came back with text
-- and NEITHER mentioned entry requirements. Named for what was observed. An
-- empty read stays `undetermined`, because a page we never got is not a page
-- that was silent, and sending an operator after a selector for a widget that
-- never rendered is the confidently-wrong answer this schema exists to avoid.
--
-- Nothing about the bar moved: `both_silent` yields no evidence, exactly as
-- `same_answer` yields none. This makes the loss countable, not smaller.
--
-- No change to `proof_of_need_attempts`: `detail` is free text under a
-- non-empty CHECK, so the new code has always been storable.
--
-- WHY A SECOND VIEW RATHER THAN A COLUMN ON `proof_of_need_suppression`.
-- Every migration here is replayable and gets replayed: `scripts/test.sh`
-- applies the whole directory with psql, then each test calls `Db::migrate` and
-- sqlx applies all of them again from an empty `_sqlx_migrations`. A
-- `create or replace view` may APPEND a column but may never shed one, so a
-- 16-column `proof_of_need_suppression` makes 0015's own 15-column
-- `create or replace` fail with 42P16 on the second pass — and 0015 cannot be
-- edited, because sqlx checksums applied migrations. So the fourth reason gets
-- its own view. It answers a different question anyway: 0015's view is "what is
-- our suppression rate on this prospect", this one is "is the bar mis-set on
-- them, counting both kinds of finding". The lasting fix is to stop
-- double-applying in scripts/test.sh, at which point this folds into a column.

-- ---------------------------------------------------------------------------
-- proof_of_need_bar_misset: the two reasons that mean "narrow Flow::panel"
-- ---------------------------------------------------------------------------
--
-- `same_answer` and `both_silent` are the same mistake measured on the two kinds
-- of finding, so `bar_misset` adds them up and that total is the number to
-- watch. Reading `same_answer` alone is reading only the half of the loss that
-- happens to have a requirement in it — and a prospect whose checkout says
-- nothing at all is exactly the prospect this vertical exists to find.
--
-- Same shape as `proof_of_need_suppression`: derived per query, no stored rate,
-- security_invoker so the base table's RLS applies to whoever selects. Joins to
-- it one-to-one on (tenant_id, prospect_domain) — same table, same grouping.

create or replace view proof_of_need_bar_misset with (security_invoker = true) as
select
  a.tenant_id,
  a.prospect_domain,
  -- Both runs stated the same requirement; only the bytes around it moved.
  -- A suppressed "your checkout is wrong".
  count(*) filter (where a.outcome = 'not_reproducible' and a.detail = 'same_answer')
                                                                    as same_answer,
  -- Both runs came back with text and neither mentioned entry requirements.
  -- A suppressed "your checkout says nothing".
  count(*) filter (where a.outcome = 'not_reproducible' and a.detail = 'both_silent')
                                                                    as both_silent,
  -- The one number an operator tunes the panel selector against.
  count(*) filter (
    where a.outcome = 'not_reproducible' and a.detail in ('same_answer', 'both_silent')
  )                                                                 as bar_misset
from proof_of_need_attempts a
group by a.tenant_id, a.prospect_domain;

grant select on proof_of_need_bar_misset to app_role;
