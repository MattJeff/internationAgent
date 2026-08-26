-- 0031_policy_models: which model an employee may think with.
--
-- Every employee in every tenant ran one model, because the model was a
-- process-wide string read from `AGENTOS_LLM` and nothing between the config and
-- the provider could vary it. A seller writing three-paragraph follow-ups and an
-- entry-requirements analyst reasoning about whether a bilateral treaty is a
-- revocable tolerance were billed at identical rates, and the operator had no
-- sentence they could write down to change that.
--
-- This column is that sentence. It is an allowlist and it intersects like the
-- other five: platform ∧ tenant ∧ role ∧ employee, narrowing only. A role pack
-- names the model its job needs; this column bounds what the operator permits;
-- `agentos_domain::policy::model_for` is where the two meet.
--
-- WHY THE BACKFILL IS EVERY MODEL AND THE DEFAULT IS NONE
--
-- Those two look contradictory and are the same decision seen from either side
-- of this migration.
--
-- Forwards, an empty allowlist denies — that is what it means in every other
-- column here, and it has to keep meaning it, because a model list that read as
-- "unconstrained when blank" would be the one allowlist in the table an operator
-- could disable by deleting a line. So `default '{}'`: a layer written after
-- this migration that does not name a model permits none, and
-- `apps/server`'s document loader refuses an incomplete layer document outright
-- rather than letting it through as a total replacement.
--
-- Backwards, the fleet running when this migration lands is *already* running
-- claude-opus-5 on every seat, with the operator's consent in the form of the
-- deployment existing. Leaving those rows empty would intersect to nothing and
-- stop every employee in the deployment at once — a silent repricing to zero,
-- delivered as an outage. So every existing row is backfilled with the full set,
-- which preserves exactly today's behaviour: the pack's preference decides, and
-- narrowing is a thing an operator does on purpose afterwards.
--
-- The backfill is unconditional rather than platform-only because the layers
-- intersect: a platform row naming four models and a tenant row naming none
-- still comes out empty.

alter table policy_layers
  add column allowed_models text[] not null default '{}';

update policy_layers
   set allowed_models = array[
         'claude-haiku-4-5',
         'claude-sonnet-5',
         'claude-opus-5',
         'claude-fable-5'
       ];
