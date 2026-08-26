-- 0034_unbacked_turns: what a turn said, beside whether it did anything.
--
-- A live run against the real model produced this: one support seat wrote
-- 12,682 tokens describing five tickets handled and five emails sent, having
-- called nothing at all. `tool_calls = 0` was the only thing that distinguished
-- it, it went to a `tracing` line, and nothing was written down anywhere.
--
-- That is the most dangerous failure this system has, because it is the only one
-- that looks like success. Every other failure is loud: a refused action leaves
-- an `audit_log` row with a deny code, a malformed call is counted in
-- `Finished::malformed_calls`, a provider error is classified and billed. An
-- employee that did nothing and said it did everything leaves a beautiful
-- transcript and no trace — and `0024_model_usage.sql` next door already has the
-- shape of the answer.
--
-- 1. THIS IS `calls_unmetered` AGAIN, ONE LEVEL UP. Decision 3 of 0024 says a
--    call whose cost nobody reported is not a free call, and answers it by
--    recording the call AND that its cost is unknown, so every reader can
--    subtract. The same move: record the run AND how much prose it produced with
--    nothing behind it, so an operator can subtract. `runs_unbacked` is a subset
--    counter beside `calls`, exactly as `calls_unmetered` is, and it is
--    CONSTRAINED as one.
--
-- 2. UNBACKED IS A FACT, NOT A VERDICT, AND THE TWO COLUMNS ARE WHY THERE ARE
--    TWO. A run that ended with prose and nothing the gate ruled on is a real,
--    legitimate state: an employee with nothing due says "nothing due" and
--    stops. So one column would be a boolean accusation and this schema refuses
--    to make one. `runs_unbacked` counts the runs; `unbacked_chars` measures what
--    they said. One run and thirty characters is a quiet Tuesday. One run and
--    twelve thousand characters is a story, and it is the operator who reads it
--    as one — this file only makes the two rows different.
--
--    Which is the honest limit, stated once: NOTHING HERE MAKES A MODEL HONEST.
--    It makes the record carry both halves.
--
-- 3. THE PROSE ITSELF IS NOT STORED, AND THAT IS DELIBERATE. The obvious version
--    of "store the fact next to the prose" is a text column. Two reasons not to.
--    Model output is untrusted text by this workspace's own rule
--    (`crates/app/src/turn.rs`'s taint wire, `domain::untrusted`), and every
--    place that holds a counterparty's or a model's words holds them somewhere
--    that says so — `messages`, framed and labelled. And
--    `employee_initiative.last_detail`, the column an operator already reads,
--    holds only text this codebase authored;
--    `apps/server/src/loops/initiative.rs` says so in as many words. A length is
--    a measurement of the prose and carries none of it, so it needs neither.
--    The transcript is in the logs where it always was.
--
-- 4. CHARACTERS, NOT BYTES OR TOKENS. Tokens would need a tokeniser this layer
--    does not have and would make the column model-dependent. Bytes make a reply
--    in Japanese read three times longer than the same reply in English, which
--    is a ranking bug in a column whose only job is ranking.
--
-- 5. ONLY THE SELF-STARTED TURN WRITES IT. `Agent::on_turn` — the inbound path —
--    answers somebody. Its prose IS the deliverable, it is recorded on a
--    conversation, and the person who asked is the check; a turn that replies to
--    a customer without calling a tool is doing its job, and counting it here
--    would bury the real signal under the healthy majority. A turn started by
--    the clock has no counterparty and no artifact: `loops::initiative` logs the
--    closing text and stores it nowhere, precisely because "everything the
--    employee actually did went through `Effects`". When nothing went through
--    `Effects`, that sentence is the bug, and this is where it is written down.

alter table model_usage_daily
  -- Runs — one `Turn::run`, not one model round trip — that ended with prose and
  -- nothing the Policy Gate ruled on: no parseable tool call from the model, and
  -- no vertical operation before it. There is no `audit_log` row from this run
  -- to check its prose against.
  add column if not exists runs_unbacked  bigint not null default 0,
  -- What those runs said, in characters of the closing reply. Not the reply; see
  -- decision 3.
  add column if not exists unbacked_chars bigint not null default 0;

-- Last lines of defence, in the shape 0024 set. A negative count would mean
-- something handed work back, and there is no verb that does.
alter table model_usage_daily
  drop constraint if exists model_usage_daily_unbacked_nonnegative,
  -- An unbacked run is still a run, and a run that finished made at least one
  -- model call. So unbacked runs are a subset of calls, never a separate
  -- population — the same reading `calls_unmetered <= calls` protects.
  drop constraint if exists model_usage_daily_unbacked_subset,
  -- And the pair cannot come apart: characters with no run to attribute them to
  -- would be a number nobody could act on, which is how a column starts lying.
  drop constraint if exists model_usage_daily_unbacked_pair;

alter table model_usage_daily
  add constraint model_usage_daily_unbacked_nonnegative
    check (runs_unbacked >= 0 and unbacked_chars >= 0),
  add constraint model_usage_daily_unbacked_subset
    check (runs_unbacked <= calls),
  add constraint model_usage_daily_unbacked_pair
    check (runs_unbacked > 0 or unbacked_chars = 0);

-- No new grant and no new policy. The columns are on a table that already has
-- RLS enabled and forced, one `tenant_isolation` policy, and
-- `select, insert, update` to `app_role` with `delete` revoked — see 0024. A
-- record of what an employee did not do is exactly as un-deletable as the record
-- of what it spent.
