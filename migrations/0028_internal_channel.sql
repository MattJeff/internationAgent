-- 0028_internal_channel: employees can talk to each other.
--
-- Every channel before this one points outward. An employee could email a
-- supplier, text a customer and call a warehouse, and could not say one word to
-- the colleague at the next desk — so a manager could not give an order, a
-- junior could not ask a question, and nothing could be handed off. The company
-- was a set of agents, not an organisation.
--
-- WHY THERE IS NO `internal_messages` TABLE
--
-- An order, a question, an answer and a handover are four different things, and
-- the obvious reading of that is four tables — or at least one new table with a
-- `kind` column. Neither earns its keep, and the reason is that they differ in
-- almost nothing:
--
--   * addressing        - one employee to one employee     : identical
--   * durability        - a row committed with its wake-up : identical
--   * taint             - carries the sender's trust label : identical
--   * cost              - reserves the recipient's turn    : identical
--   * audit             - one `message_received` row       : identical
--   * delivery          - `outbox` -> `agent.turn.requested` : identical
--   * recording a reply - `on_turn` writes the answer back : identical
--
-- All seven of those are already implemented, once, for messages arriving from
-- outside. A second table means a second copy of the wake path, a second outbox
-- event type, a second handler, and a second place for the trust label to be
-- forgotten. What the four kinds actually differ in is three nullable columns
-- and one derived state, and that is what this migration adds:
--
--   internal_kind             which of the four it is
--   answers_message_id        an ANSWER names the QUESTION it closes
--   handover_conversation_id  a HANDOVER names the thread it moves
--
-- and "unanswered" is not a column at all: a question is outstanding when no
-- message points back at it. A stored `answered_at` would be a second copy of
-- that fact, maintained by the code that writes the answer, and therefore a
-- fact that can be wrong. `NOT EXISTS` cannot be wrong.
--
-- An ORDER carries none of the three: it creates work and expects nothing back,
-- which is exactly what "no reply column" means.
--
-- WHAT IS NOT MODELLED, on purpose
--
--   * Order completion. Nothing records that an order was carried out. The
--     honest state of the art here is that the recipient's turn and its reply
--     are the record; a `done_at` nobody sets is worse than no column.
--   * Group messages, broadcast, cc. One sender, one recipient. A manager
--     addressing a team is N rows, N turns and N budgets, which is what it
--     costs anyway.
--   * Threading of internal messages beyond question->answer. The conversation
--     row already groups a pair's traffic.
--
-- THE CONSTRAINT IS ONE-WAY, and that is deliberate
--
-- `internal_kind IS NOT NULL` implies `channel = 'internal'`, but not the
-- reverse. An employee that takes a turn on an internal message writes its
-- closing prose back onto that conversation through the same `record_reply`
-- every other channel uses, and that outbound row has no kind: it is not an
-- order, a question, an answer or a handover, it is what the employee said it
-- did. Making the implication bidirectional would fail that INSERT with a check
-- violation, which is a constraint enforcing a rule nobody wanted.

-- ---------------------------------------------------------------------------
-- The three columns
-- ---------------------------------------------------------------------------

alter table messages
  add column if not exists internal_kind text;

-- Self-referencing, and `on delete set null` rather than cascade: deleting a
-- question must not delete the answer somebody wrote to it. The answer becomes
-- an orphan that still reads, which is the better of the two losses.
alter table messages
  add column if not exists answers_message_id uuid references messages (id) on delete set null;

alter table messages
  add column if not exists handover_conversation_id uuid
    references conversations (id) on delete set null;

do $$
begin
  alter table messages
    add constraint messages_internal_kind_values
      check (internal_kind is null
             or internal_kind in ('order', 'question', 'answer', 'handover'));
exception
  when duplicate_object then null;
end
$$;

do $$
begin
  alter table messages
    add constraint messages_internal_kind_channel
      check (internal_kind is null or channel = 'internal');
exception
  when duplicate_object then null;
end
$$;

-- An answer names its question and nothing else does; a handover names its
-- thread and nothing else does. Written as equalities so both halves hold: a
-- kind without its target, and a target without its kind, are both refused.
-- On a non-internal row `internal_kind` is NULL, `internal_kind = 'answer'` is
-- NULL, and the whole predicate is NULL, which a CHECK accepts — so this
-- constrains internal rows only, which is all it is about.
do $$
begin
  alter table messages
    add constraint messages_internal_answer_names_its_question
      check ((answers_message_id is not null) = (internal_kind = 'answer'));
exception
  when duplicate_object then null;
end
$$;

do $$
begin
  alter table messages
    add constraint messages_internal_handover_names_its_thread
      check ((handover_conversation_id is not null) = (internal_kind = 'handover'));
exception
  when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- The two indexes the outstanding-question query rides on
-- ---------------------------------------------------------------------------
--
-- "Which questions did I ask that nobody has answered" is an anti-join between
-- these two. Both are partial, so they cost nothing on the overwhelming
-- majority of rows in this table, which are email.
--
-- The asker is `sender` — the employee's slug — and not a column of its own.
-- `messages.employee_id` is the employee the row BELONGS to, which for an
-- arriving message is the recipient; the sender has always been `sender` on
-- every other channel, and a slug is unique per tenant and never changes
-- (`employees_tenant_slug_key`). One spelling of "who wrote this", not two.

create index if not exists messages_internal_questions_idx
  on messages (tenant_id, sender, created_at)
  where internal_kind = 'question';

create index if not exists messages_internal_answers_idx
  on messages (answers_message_id)
  where answers_message_id is not null;

-- No RLS statements: `messages` already has row-level security from
-- 0001_core, and columns inherit it. One tenant's employees cannot see — let
-- alone message — another's, and that is a property of the table rather than
-- of anything this migration or the application does.
