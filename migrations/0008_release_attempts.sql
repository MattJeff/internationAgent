-- 0008_release_attempts: giving a resource back gets its own budget.
--
-- `attempt_count` was spent by both halves of a resource's life: the
-- provisioning worker bumped it on every `claim_step`, and the termination
-- sweep bumped it again on every release attempt. So a phone number that took
-- three attempts to *buy* had three fewer attempts to be *given back* before
-- the sweep gave up and asked a human. Harmless in direction — asking early
-- only costs an operator a glance — but the two counts answer different
-- questions and one column cannot hold both.
--
-- Two columns, because the sweep needs both halves of a backoff: how many
-- times, and how long ago.
alter table employee_resources
  add column if not exists release_attempt_count integer not null default 0,
  -- Nullable on purpose, and NOT backfilled. NULL means "no release has ever
  -- been attempted under the new counter", and the sweep reads it as
  -- `coalesce(release_attempted_at, updated_at)` — so a row that already
  -- exists keeps exactly the backoff it has today (a release refused a second
  -- before this migration is still cold for the same 30s) instead of becoming
  -- instantly claimable. A `default now()` would have done the opposite and
  -- frozen every stranded resource for one retry window at deploy time.
  add column if not exists release_attempted_at timestamptz;

-- Existing rows land on release_attempt_count = 0: a full release budget,
-- which is the honest reading. Whatever attempts they burned were spent under
-- a counter that was measuring something else.
