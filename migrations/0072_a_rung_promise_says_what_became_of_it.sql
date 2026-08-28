-- 0072_a_rung_promise_says_what_became_of_it: `rang_at` alone cannot tell a
-- promise kept late from a promise consumed and never kept, and it has been
-- saying the wrong one of the two.
--
-- 0063 wrote the vocabulary this file is about:
--
--   > `at` is when it was promised and `rang_at` is when it actually rang, and
--   > **the gap between them is the only thing that can say a promise was kept
--   > late.**
--
-- and, two paragraphs on, named the place for the correction before the defect
-- was found: *"the day somebody wants 'did the moment I promised actually
-- produce anything' the place for it is beside `rang_at`"*. This is that column.
-- The reasoning was checked before it was followed and it holds: nothing else in
-- the row can carry the answer, because `at` and `rang_at` are both instants and
-- an instant cannot say *why*.
--
-- ---------------------------------------------------------------------------
-- WHAT WAS ACTUALLY WRONG, WHICH IS MORE THAN A MISSING FIELD
-- ---------------------------------------------------------------------------
--
-- `agentos_store::calendar::claim_due` writes `rang_at` **and commits** before
-- `loops::initiative::assignment_for` has read a charter and before
-- `reserve_a_turn` has taken a turn out of the day. 0063 accepts that for a
-- *crash*, in as many words — "the claim commits before the turn starts, so a
-- worker killed mid-turn costs the appointment rather than spinning on it" —
-- and that trade is still right: a promise that reschedules itself is not a
-- promise, and a lease here would be a number nobody has.
--
-- But every **deterministic** reason not to take the turn consumes the promise
-- on exactly the same path, and those are not crashes. An employee with no
-- charter (`Outcome::NoCharter`), a tenant that has connected no model
-- (`NoModel`), an objective with gaps (`Clarify`), a seller with nobody due
-- (`NoWork`), a seat that has spent its day (`OverBudget`) — each of them ends
-- with `rang_at` written, nothing done, and nothing said. And
-- `loops::initiative::record` wrote nothing at all for an appointment: it
-- returned on `claims.is_none()` at its first line, with an argument on the spot
-- for why `employee_initiative.last_outcome` is the cadence's column and must
-- not be overwritten by a promise. That argument is correct and is untouched
-- here; what was missing is the *other* column it implies.
--
-- The result is worse than losing the information, and this is the sentence that
-- made this file worth writing. The row then reads `rang_at > at`, which **in
-- 0063's own vocabulary means kept, late**. Nothing anywhere said otherwise. The
-- founder read a diary in which a promise that was never kept at all was
-- indistinguishable from one kept four days behind schedule — and the second is
-- a deployment that was down over a weekend, while the first is an employee
-- nobody chartered, which is his to fix and which he was never told about.
--
-- ---------------------------------------------------------------------------
-- WHO WRITES IT, AND IN WHICH TRANSACTION — THE ONLY HARD QUESTION HERE
-- ---------------------------------------------------------------------------
--
-- The claim commits before the turn exists, so an outcome is necessarily
-- written by a *second* transaction, minutes later, and a process killed between
-- the two writes no outcome at all. A column whose absence had to be interpreted
-- would therefore have inherited the whole defect one layer up.
--
-- So the shape is chosen by which way the silence points:
--
--   * **NULL means "it rang, and nothing ever came back."** No default, no
--     backfill, and nothing writes it at claim time. That is precisely the crash
--     0063 accepts, and it is now a state with a name instead of a lie.
--   * **A turn that finished writes `'turn'`, explicitly.** Success is the value
--     that must be *earned*, so no failure to write can ever be mistaken for it.
--
-- The inverse — a `'kept'` default cleared on failure — is the same schema
-- written the fatal way round, and it fails on the day the process dies: every
-- lost turn would file itself as a promise kept. Absence has to mean the
-- unknown, because absence is exactly what a crash produces.
--
-- Rows rung before this migration are all NULL, and that is honest rather than
-- unfortunate: nobody recorded what became of them and nothing can reconstruct
-- it.
--
-- ---------------------------------------------------------------------------
-- A VOCABULARY, NOT A `text`
-- ---------------------------------------------------------------------------
--
-- `outcome` is checked against a closed list, for `0028`'s reason on
-- `messages_internal_kind_values` and against `0020`'s counter-example:
-- `employee_initiative.last_outcome` is an unconstrained `text` whose values
-- live only in a comment, and a column somebody one day compares by equality is
-- a column somebody one day compares to a string that no writer ever writes.
--
-- The nine values are `loops::initiative::Outcome::code`'s eight — the closed
-- vocabulary that column already uses — plus `'cancelled'`, which is 0068's
-- settlement and is not an outcome any turn produces.
--
-- **The ceiling on that, named rather than hidden:** a tenth `Outcome` variant
-- is a compile error in `Outcome::code` and *not* a compile error here, so a new
-- code has to arrive with a migration. `initiative.rs`'s
-- `every_outcome_this_loop_can_reach_is_a_word_the_diary_knows` is what turns
-- that into a red test rather than a swallowed `23514` in production, and
-- `Outcome::code`'s own doc comment says so where somebody adding a variant will
-- read it. A `create type ... as enum` would have the identical property and cost
-- an `alter type` per value; a plain `text` would have neither.
--
-- ---------------------------------------------------------------------------
-- HOW IT COHABITS WITH 0068, AND WHY THAT IS A CONSTRAINT AND NOT A COMMENT
-- ---------------------------------------------------------------------------
--
-- 0068 settles a departed seat's outstanding hours by writing `rang_at`
-- **before** `at`, using 0063's rule that a settled moment settled early is a
-- cancellation. That spelling survives untouched, and the two writers cannot
-- collide: `cancel_outstanding` takes only `rang_at IS NULL` rows and
-- `claim_due` takes only `rang_at IS NULL` rows, so exactly one of them ever
-- reaches a given promise.
--
-- What would have rotted is the *reading*. With this column present and
-- `cancel_outstanding` silent, NULL would have meant "cancelled" **or** "rang
-- and nothing came back", told apart only by comparing two timestamps — which is
-- the same one-comparison-carrying-two-facts defect this file exists to remove.
-- So the cancellation writes `'cancelled'`, and the agreement between the word
-- and the clock is a CHECK rather than a convention:
--
--   * `claim_due` selects `at <= now` and writes `rang_at = now`, so every rung
--     row has `rang_at >= at`.
--   * `cancel_outstanding` selects `at > now` and writes `rang_at = now`, so
--     every cancelled row has `rang_at < at`.
--
-- The two are exhaustive and disjoint, so `(outcome = 'cancelled') = (rang_at <
-- at)` holds in both directions and is the strongest thing that can be said
-- here. It refuses the two rows that would restart the confusion: a cancellation
-- stamped `'turn'` (somebody credited for an hour that never came round) and a
-- rung promise stamped `'cancelled'` (an hour that really happened, erased).
--
-- The third state is untouched and still has no outcome: 0068's overdue promise
-- of a departed seat, which keeps `rang_at IS NULL` on purpose so that nobody is
-- credited with anything. `outcome IS NOT NULL` implies `rang_at IS NOT NULL`,
-- which is the first conjunct below.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS FILE DELIBERATELY DOES NOT DO
-- ---------------------------------------------------------------------------
--
-- **No detail column.** `employee_initiative` has `last_detail` beside
-- `last_outcome` and this has no twin, because the two columns are read by
-- different people for different reasons: an operator debugging a cadence wants
-- the sentence, and the founder reading a diary wants to know whether the hour he
-- was promised happened. The code answers that; the sentence is in the log line
-- `handle` already emits. It is a `text` column beside this one the day somebody
-- reads it, and it needs no thought — which is the test of a thing correctly left
-- out.
--
-- **No index.** Nothing filters or orders on `outcome`. `appointments_due_idx` is
-- partial on `rang_at is null` and never sees a row that has one.
--
-- **No RLS or grant change, and this was checked rather than assumed.** 0063
-- granted `select, insert, update` on the table to `app_role` and its policy
-- carries `using` and `with check` on `tenant_id`; both are table-wide, so a new
-- column is inside them from the moment it exists. There is still no DELETE.
--
-- **Nothing changes about when a promise is consumed.** The claim still writes
-- `rang_at` before the turn and still commits, an appointment still has no lease
-- and no reaper, and a promise still rings exactly once. This file makes the
-- consumption *legible*; it does not make it conditional. Making it conditional
-- is a different change with a real cost — a turn taken before `rang_at` is
-- written is a promise that can ring twice — and nobody has asked for it.

alter table appointments
  add column if not exists outcome text;

-- `do $$ … duplicate_object` for `0028`'s reason: `add constraint` has no
-- `if not exists`, and every migration here is replayable.
do $$
begin
  alter table appointments
    add constraint appointments_outcome_is_a_code
      check (outcome is null
             or outcome in ('turn', 'no_charter', 'unreadable_charter',
                            'no_model', 'clarify', 'no_work', 'over_budget',
                            'error', 'cancelled'));
exception
  when duplicate_object then null;
end
$$;

-- Written as an equality so both halves hold, exactly as
-- `messages_internal_answer_names_its_question` is: a cancellation whose clock
-- says it rang, and a ring whose word says it was cancelled, are both refused.
do $$
begin
  alter table appointments
    add constraint appointments_outcome_agrees_with_the_clock
      check (outcome is null
             or (rang_at is not null
                 and (outcome = 'cancelled') = (rang_at < at)));
exception
  when duplicate_object then null;
end
$$;
