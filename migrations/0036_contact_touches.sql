-- 0036_contact_touches: the touch counter `contacts` never had.
--
-- `agentos_app::revenue::MAX_TOUCHES` is 3 and `Sequence` enforces it — in
-- memory, on a value that is rebuilt from nothing every turn. So the rule held
-- for exactly as long as one process owned one sequence from the first email to
-- the last, and it stops holding the moment a chase is driven off
-- `contacts_due_for_follow_up`: every turn builds a fresh `Sequence`, every
-- fresh `Sequence` has no touches, and every fresh `Sequence` therefore says
-- "due". A chase loop with no persisted counter is a machine for mailing a
-- stranger five times.
--
-- One integer, incremented by `store::revenue::mark_contacted`, which is the
-- one statement in the codebase that means "we have just written to this
-- person" — the selling turn's first touch, the chase, and `queue::record_queued`
-- on the CSV export path all route through it. The queue query filters on it,
-- so the limit bites in the *selection* rather than in the send: a contact who
-- has had their three is not offered, and no turn is spent discovering that.
--
-- Why not a `sequence_ended` column beside it, for `Ended::Replied` and the
-- rest: because nothing reads the reason. The only question anyone asks of this
-- table is "may we write to them again", and `next_follow_up_at IS NULL` already
-- answers it — that is what `inbound::land` now sets when a chased person
-- replies. `touch_count` covers exhaustion, the null covers everything else, and
-- an operator who wants the story has `last_contacted_at`, the audit trail and
-- the thread. Add the reason column the day something branches on it.
--
-- ponytail: no index. `contacts_follow_up_idx` is already the partial index this
-- query rides and `touch_count < 3` is a filter over the handful of rows it
-- returns, not a scan. It also cannot go *in* that index without rebuilding it,
-- which is a lock on a live table for a predicate that removes three rows.

alter table contacts
  add column if not exists touch_count integer not null default 0
    constraint contacts_touch_count_nonneg check (touch_count >= 0);
