-- 0063_appointments: le calendrier — a moment an employee promised, which
-- arrives whether or not anything else is happening.
--
-- Nothing in this schema could promise an hour. `employee_initiative` (0020) is
-- an *interval* with a floor of 300 seconds: it says "every twenty minutes",
-- never "at three o'clock on Tuesday", and its claim deliberately rewrites
-- `next_at` from the moment the turn is taken up, so the phase drifts by design
-- and a wall-clock time is not something it can hold. `contacts.next_follow_up_at`
-- (0011) is the nearest thing to a date in the product and it is a *spacing*
-- written by `queue::FOLLOW_UP_AFTER`, read only as a filter inside a cadence
-- tick — a contact becomes eligible at that instant, and is worked whenever the
-- employee's rhythm next comes round, which may be an hour later.
-- `negotiations.reply_due_at` (0007) is a deadline nobody is woken by.
--
-- Three consequences, and this table is the smallest answer to all three:
--
--   1. **No employee could say "I will call you Tuesday at 15:00".** Every
--      promise about a time was prose in a message body, with nothing behind
--      it. The promise and the mechanism were not the same object, so keeping
--      it depended on a model remembering, next cadence, that it had made one.
--   2. **Nothing could be woken *at* an instant.** The only two doors into a
--      turn are an inbound message (somebody else's clock) and a cadence
--      (an interval). An employee with no cadence at all — chartered but not
--      scheduled, which 0020 says is the ordinary state — could not be reached
--      by the clock in any way.
--   3. **A moment that passed left no trace.** `rang_at` below is the record
--      that a promise was kept, and when.
--
-- ---------------------------------------------------------------------------
-- WHY THIS IS NOT `outbox_events` WITH `available_at` IN THE FUTURE
-- ---------------------------------------------------------------------------
--
-- It is the closest thing already here and it was tried on paper first, because
-- it would have cost nothing: `outbox_events.available_at` is already "not
-- before this instant", `claim_of` already takes a fair, tenant-round-robin,
-- `SKIP LOCKED` batch of whatever is due, and `agent.turn.requested` already
-- runs a whole turn behind it. One line in `outbox::enqueue` — which writes
-- `available_at = now` and nothing else ever sets it — and appointments would
-- exist.
--
-- It is the wrong table for exactly one reason, and the reason is fatal:
-- **`available_at` is a retry backoff, and a backoff moves.** `mark_failed`
-- pushes it out on every failed attempt and `0060`'s unpark pulls it back. An
-- appointment whose turn failed once would silently become an appointment at a
-- different hour, then at another one — a promise that reschedules itself is
-- not a promise. Two lesser reasons point the same way: the timezone the
-- promise was made in would have to live inside a `jsonb` payload, which is the
-- shape `0007` explicitly refused for `reply_due_at`; and the subject is text
-- somebody else typed, where an outbox payload is ours.
--
-- ---------------------------------------------------------------------------
-- WHAT AN APPOINTMENT IS: THREE COLUMNS, AND THE DURATION THAT IS NOT ONE
-- ---------------------------------------------------------------------------
--
-- An instant, the seat that promised it, and one line saying what it is about.
-- That is the whole row, and the bar for a fourth is that one of the three
-- failures above stays unfixed without it.
--
-- **No duration, and this is the deliberate half of "do not build Google
-- Calendar".** A duration buys exactly one thing that an instant does not:
-- refusing a second appointment that overlaps the first. That refusal needs
-- three things this change does not have — a default length for a meeting
-- nobody has chosen, a rule about what overlap means, and a caller who wants to
-- be refused. Two instants never overlap, so an instant needs none of them.
--
-- FOUNDER'S QUESTION, LEFT OPEN: how long is an appointment, and may a second
-- one sit on top of it? The answer is a `during tstzrange` column beside `at`
-- and an `EXCLUDE USING gist (employee_id WITH =, during WITH &&)` — one
-- migration, `btree_gist`, and a number somebody has to choose. Blocking a slot
-- is **not** built here and nothing in this file pretends it is.
--
-- **No attendee, no location, no invitation.** Nothing reads them. An
-- appointment here is not a thing two parties agree to; it is a thing one
-- employee undertakes to do, which is the half a company that runs on AI
-- employees does not have.
--
-- **No `employee_id IS NULL`, unlike `work_items.assignee_id` (0061).** That
-- nullable column is the whole of what makes a board *shared*, and its absence
-- here is the whole of what makes a calendar *personal* — see the section on
-- what an appointment spends, below.
--
-- ---------------------------------------------------------------------------
-- TIME ZONES: THE INSTANT AND THE INTENTION ARE TWO FACTS, SO THEY ARE TWO
-- COLUMNS
-- ---------------------------------------------------------------------------
--
-- This is the decision that makes the table usable or useless, and it is not a
-- technical one.
--
-- `timestamptz` stores an instant. "Tuesday at 15:00" is not an instant, it is
-- an instant **plus whose Tuesday** — and in this product the two are routinely
-- different people. The seller is in Paris, the prospect is in Vienna, the
-- employee writes in the prospect's language, and the sentence it writes is
-- "mardi 15h". Stored as `timestamptz` alone, that row reads `14:00+00` a week
-- later and there is no way to tell whether the promise was 15:00 in Vienna,
-- 15:00 in Paris, or 16:00 somewhere the model guessed. **A row that cannot say
-- the promise back in the words it was made in is not a record of a promise.**
--
-- So: `at` is the instant, and `at_zone` is the intention.
--
--   * **`at` is what fires.** One instant, one `<=` comparison, one plain btree
--     index, and no ambiguity about when the moment arrives. Everything the
--     claim does is on this column and nothing in the claim knows about zones.
--   * **`at_zone` is what it meant.** An IANA name, and it is what the moment
--     is rendered back in — to the employee whose turn it wakes, and to the
--     founder reading the diary.
--
-- The two rejected shapes, both of which look simpler:
--
--   * **`at` alone.** The zone is then held by whoever converted the sentence,
--     which is a model, and it is discarded the instant the row is written. The
--     conversion becomes unauditable at exactly the moment it matters — a call
--     placed at the wrong hour is indistinguishable from a call placed at the
--     right one, because the only record is the instant, and the instant is
--     what is in dispute.
--   * **Local wall time plus a zone, with the instant derived at read time.**
--     `timestamp AT TIME ZONE at_zone` with a *column* as the zone is STABLE,
--     not IMMUTABLE — it cannot be indexed, so the claim's `WHERE ... <= now()`
--     becomes a sequential scan over every future appointment in the
--     deployment. It is also a silent time bomb: a country changing its DST
--     rules moves every stored future appointment by an hour, with no row
--     changed and nobody told.
--
-- **`at_zone` is NOT NULL and has no default, and that is the point of it.**
-- A nullable zone would mean "the server's", and the server's zone is nobody's.
-- Whoever books an appointment has to have answered *whose Tuesday* out loud;
-- there is no spelling of the question that leaves it unanswered.
--
-- The CHECK is against PostgreSQL's own tzdata, for `0020`'s reason: the API
-- validates the name too (`agentos_app::calendar::Calendar::book` refuses an
-- unknown zone with its own error), but a row is also reachable by psql, and a
-- zone that only fails when somebody tries to render it is a promise that
-- breaks at the moment it is read back. `timezone(text, timestamptz)` is
-- IMMUTABLE, so it is legal in a CHECK; it raises rather than returning false
-- on a name tzdata does not know, which is a refusal either way.
--
-- ---------------------------------------------------------------------------
-- `rang_at`: WHAT MAKES A MOMENT ARRIVE, AND WHY IT IS A TIMESTAMP
-- ---------------------------------------------------------------------------
--
-- `rang_at IS NULL` is a promise still outstanding. The claim in
-- `agentos_store::calendar::claim_due` writes it, in the same statement that
-- hands the appointment out, and `apps/server/src/loops/initiative.rs` turns
-- that into a turn.
--
-- **The shape is `employee_initiative`'s claim in every respect but one, and
-- the one is the whole difference between a cadence and an appointment: the
-- cadence claim *advances*, this one *consumes*.** `employee_initiative_next_at`
-- pushes the next deadline a cadence into the future, because a rhythm always
-- has a next beat. An appointment has no next: it is written once, it rings
-- once, and `rang_at` is what stops it ringing twice. There is nothing here to
-- reschedule and no lease, no heartbeat and no reaper — for the same reason the
-- initiative loop needs none: the claim commits before the turn starts, so a
-- worker killed mid-turn costs the appointment rather than spinning on it.
--
-- A timestamp rather than a boolean, and not for `0061`'s "when did this stop
-- being work" reason alone. `at` is when it was promised and `rang_at` is when
-- it actually rang, and **the gap between them is the only thing that can say a
-- promise was kept late.** A boolean cannot, and a deployment that was down
-- from Monday to Thursday is precisely when somebody needs to know.
--
-- FOUNDER'S QUESTION, LEFT OPEN: **how late is too late to keep an
-- appointment?** The claim has no lower bound — `at <= now` and nothing else —
-- so a deployment restarted after a week rings every stale appointment it
-- holds. That is deliberate rather than overlooked: the cutoff is a number, no
-- number here would be anything but invented, and the two things that already
-- bound the damage are real ones — the batch is small, and every ring spends a
-- turn out of `PolicyLimits::max_turns_per_day`, which an employee runs out of.
-- The employee is told both instants and can see for itself that it is four
-- days late. The place for the answer is one more conjunct in `claim_due`'s
-- WHERE.
--
-- Cancelling is `rang_at` written *before* `at`: the moment is settled, and it
-- was settled before it came round. No second column, and no route today —
-- nothing has asked to un-book, and the grant below already allows the UPDATE
-- the day something does.
--
-- ---------------------------------------------------------------------------
-- `on delete cascade`, WHERE 0061 CHOSE `set null`
-- ---------------------------------------------------------------------------
--
-- Opposite answers to what looks like the same question, and the difference is
-- what the row is *for*. A work item is work the company wants done, so an
-- employee leaving must not delete it — it goes back on the board unassigned
-- and somebody else picks it up. An appointment is a moment **this seat**
-- undertook: there is no unassigned appointment, nothing else can keep it, and
-- a row whose only job is to wake an employee that no longer exists is a row
-- that can never do its job. So it goes with the seat.
--
-- `app_role` still gets no DELETE, exactly as `work_items` and `suppressions`
-- (0011) do not: a rung appointment is the record that somebody was promised
-- something and it happened.

create table if not exists appointments (
  id          uuid        primary key,

  -- Whose company. Written by the caller's transaction and never by the
  -- payload, like every other tenant column here; the policy below enforces it.
  tenant_id   uuid        not null references tenants (id) on delete cascade,

  -- Whose moment. NOT NULL — see above — and never taken from a request body
  -- by anything an employee reaches: `agentos_app::calendar::PgCalendar` is
  -- built around one seat and its `book` has no employee argument at all.
  employee_id uuid        not null references employees (id) on delete cascade,

  -- The instant. This is what fires, and the only column the claim reads.
  at          timestamptz not null,

  -- Whose Tuesday. An IANA name, checked against this server's own tzdata.
  -- No default: see above, at length.
  at_zone     text        not null
                          constraint appointments_zone_is_real
                          check (timezone(at_zone, at) is not null),

  -- What the moment is about, in one line, in the words of whoever promised it.
  --
  -- Trimmed and bounded, and the bound is borrowed rather than invented: 200 is
  -- `a2a_tasks_id_length` (0005) and `work_items_title_shape` (0061), which is
  -- this schema's one answer to "how long may a caller-supplied line be". The
  -- floor is what stops a blank line arriving in a brief.
  subject     text        not null
                          constraint appointments_subject_shape
                          check (char_length(btrim(subject)) between 1 and 200),

  -- Null while the moment is still ahead. Written by the claim.
  rang_at     timestamptz,

  created_at  timestamptz not null default now()
);

-- The claim's ORDER BY, which is also its WHERE. Cross-tenant with `tenant_id`
-- leading, because the claim offers every company a seat before any company
-- gets a second one — the same shape `employee_initiative_tenant_due_idx`
-- (0052) has and for the same reason, restated in `claim_due`'s own docs.
--
-- Partial on `rang_at is null`: a rung appointment is kept forever and is never
-- claimable again, so the index that finds due ones must not carry it. This is
-- the index that makes the `DISTINCT ON` below a range scan per tenant instead
-- of a sort of every appointment ever made.
create index if not exists appointments_due_idx
  on appointments (tenant_id, at, id)
  where rang_at is null;

-- Postgres does not index a foreign key column for you, and `on delete cascade`
-- from `employees` scans this table by `assignee`. Same line, same reason, as
-- `work_items_assignee_idx` (0061). It is also the index the diary read uses —
-- one seat's outstanding appointments.
create index if not exists appointments_employee_idx
  on appointments (employee_id, at);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, so the owning role the migrations and the
-- cross-tenant loops connect as does not walk past the policy — `enable` alone
-- binds `app_role` and lets the owner read every company's diary, which is
-- exactly the reader an employee's calendar must not have. `crates/store`'s
-- `a_diary_is_one_company_s_and_the_catalogue_says_so` asserts it from
-- `pg_class.relforcerowsecurity` rather than from behaviour, because a
-- behavioural test passes on a table that only has `enable`.
--
-- `with check` as well as `using`, so no appointment can be filed wearing
-- another company's id — one filed against somebody else's employee would be a
-- way to make their employee act at an hour you chose.
--
-- The claim bypasses this, as the other pollers' claims do, because ringing
-- every company's due appointments is its entire job. That is the documented
-- exception and not a hole: the policy still binds every connection the API
-- serves a request on.

alter table appointments enable row level security;
alter table appointments force row level security;
drop policy if exists tenant_isolation on appointments;
create policy tenant_isolation on appointments
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- No DELETE. See the header: a rung appointment is a record, and cancelling is
-- an UPDATE.
grant select, insert, update on appointments to app_role;
