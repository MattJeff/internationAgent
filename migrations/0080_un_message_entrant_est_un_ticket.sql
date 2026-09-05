-- 0080_un_message_entrant_est_un_ticket: a third party wrote to an employee,
-- so something is on the board until somebody says it is dealt with.
--
-- A company pays a helpdesk for exactly one promise: no inbound message is
-- lost. `messages` (0001) keeps the text and `work_items` (0061) keeps the
-- work, and until now nothing joined them — an email landed, a turn was
-- enqueued, and if that turn did not answer, the only trace was a row in the
-- biggest table in the deployment that no board ever showed. `inbound::land`
-- now posts one item, assigned to the employee the message reached, in the
-- transaction that lands the message. That is what makes the promise true:
-- the message and the ticket commit together or not at all.
--
-- ---------------------------------------------------------------------------
-- ONE OPEN ITEM PER CONVERSATION, AND IT IS AN INDEX RATHER THAN A CHECK
-- ---------------------------------------------------------------------------
--
-- A thread with a supplier is one piece of work however many messages it
-- carries. The second email joins the item the first one opened; a closed
-- item followed by a new message opens a new one, because "dealt with" was
-- said about the thread as it was then. Both rules are one partial unique
-- index: `(tenant_id, conversation_id) where closed_at is null`, and the
-- landing writes `ON CONFLICT … DO NOTHING` against it. Two pollers landing
-- two messages of one thread at once serialise on the index — code that
-- `SELECT`ed first would let both through, which is the whole reason this is
-- a constraint and not a branch.
--
-- ---------------------------------------------------------------------------
-- WHY `conversation_id` IS A COLUMN, WHICH 0061 SAID IT WOULD NOT BE
-- ---------------------------------------------------------------------------
--
-- 0061 set the bar for a sixth column at "one of the three failures stays
-- unfixed without it", and none of them needs this. The bar this clears is a
-- different one: the uniqueness above has to name the thread, and there is no
-- other column that can. Nullable, because the founder's own items and an
-- employee's have no thread to name and never will.
--
-- **It is also the record of who wrote the row.** 0064 made `posted_by` null
-- mean "an operator, through the API", and the landing writes null there too
-- — no employee took a turn to file this, and inventing one would be the
-- dishonest uuid 0064 refused to backfill. `conversation_id is not null` is
-- the honest reading instead: a row that names a thread was posted by the
-- thread, by nobody's decision. `audit_events` gets no row of its own for the
-- same reason 0064 gave — nothing ruled on anything — but the
-- `message_received` row the landing already appends, actor `system`, carries
-- the item's id in its payload, so the trail names the ticket without a
-- `system` actor ever counting as an employee's initiative.
--
-- ---------------------------------------------------------------------------
-- WHAT THE TITLE IS NOT
-- ---------------------------------------------------------------------------
--
-- Not the subject and not the body. Those are the sender's words, and a title
-- goes onto a board a human reads and into a brief a model reads. The landing
-- writes the channel, the counterparty masked to a first character and a
-- domain, and the date — nothing a stranger chose reaches the column whole.
--
-- `on delete set null` and not `cascade`: a conversation only goes when its
-- tenant does, which takes the item with it anyway; the action is spelled out
-- so that a future `DELETE` on a thread cannot silently erase the record that
-- somebody wrote in on it. No index on the column alone: the partial index
-- serves the one read that exists, and the only scan the action would need is
-- the tenant cascade, which is already a full scan of this table.

alter table work_items
  add column if not exists conversation_id uuid references conversations (id) on delete set null;

create unique index if not exists work_items_one_open_per_conversation
  on work_items (tenant_id, conversation_id)
  where closed_at is null;
