-- 0054_operating_window: how long the agents run, and the fact that running out
-- of time is a stop rather than a new kind of refusal.
--
-- Step 8 of the entry journey is "choose how long the agents run — 2 days, one
-- week, one month". Nothing in this schema implemented it. A company created
-- today ran forever: the initiative loop kept taking turns, every turn called
-- the customer's own model on the customer's own credential, and no code path
-- anywhere had been told to stop. That is the most expensive defect this
-- product can have, because the bill it runs up is not ours.
--
-- WHY THIS IS NOT A SECOND KIND OF STOP
--
-- The obvious shape is a `windows` table plus a check wherever it matters, and
-- it is wrong for one reason that outweighs all the arguments for it: *wherever
-- it matters* is a list, and a list has to be kept. There are four readers of
-- `company_halts` today — `PolicyGate::decide`, its approval-redemption arm,
-- `agentos_app::model_access::connected`, and `outbox::claim_of` — and they do
-- not resemble each other, do not live in one crate, and were not added at the
-- same time. A second mechanism means finding all four again, and finding them
-- again *every time a fifth appears*. The fifth is `initiative::claim_due`,
-- which was written without the halt check and is being given one right now:
-- that is the list desynchronising, observed, in this workspace, this week.
--
-- So an exhausted window IS a halt. `agentos_store::halt::halted` reports it,
-- with the same `Halt` shape and through the same call, and every reader that
-- already respects a stop respects a window for free — with no edit, no new
-- call site, and no chance of being the one that was forgotten.
--
-- WHAT DISTINGUISHES THE TWO IS THE SENTENCE, NOT THE MECHANISM
--
-- A founder reading "your company stopped" must be able to tell "we hit the end
-- of the month you paid for" from "somebody pulled the emergency switch". Those
-- are not the same news. `company_halts.reason` is the operator's own words;
-- this table has no reason column at all, and its absence is what the reader
-- keys on — `halted` renders the sentence itself, naming the instant the window
-- closed. There is deliberately no marker column and no enum: the only consumer
-- of the difference is a human reading a string, and a code path that branched
-- on it would be a second mechanism arriving by the back door.
--
-- `set_by` carries the human, and that is not decoration. 0045 refuses to let a
-- halt be attributed to `system`, on the grounds that a halt with nobody's name
-- on it is the one thing this feature must never produce — and a window keeps
-- that promise exactly: the person who chose "one month" a month ago is the
-- person who stopped the company today. The name was recorded in advance.
--
-- A WINDOW CANNOT LIFT A HALT, AND THE TABLE IS WHY
--
-- The two rows live apart and only `DELETE /v1/halt` deletes a halt. Writing a
-- window — any window, however far in the future — cannot remove a
-- `company_halts` row, and `halted` prefers that row when both exist, so an
-- emergency stop keeps its own reason and its own timestamp while a window is
-- still open underneath it. `crates/store/src/halt.rs` tests both halves.
--
-- The direction of the whole feature is one-way: with no row here a company
-- runs exactly as it does today, and every row that can exist here can only add
-- a stop. There is no value of `ends_at` that grants anything, which is the
-- property `migrations/0045_company_halt.sql` argues for the halt and the
-- reason this is a table beside it rather than a policy layer beneath it.
--
-- NO DEFAULT DURATION, AND THAT IS A DECISION LEFT OPEN ON PURPOSE
--
-- `ends_at` is `not null` with no default, and no code in this workspace
-- invents one. A default here would be a price and a promise chosen by whoever
-- typed the migration: too short and a paying company stops in the night, too
-- long and the runaway this file exists to prevent is merely slower. The entry
-- journey asks the question; until it is answered for a given company there is
-- no row, and no row means today's behaviour. See
-- `apps/server/src/routes/halt.rs::set_window` for the second question this
-- feature raises and does not answer.

create table if not exists company_windows (
  tenant_id  uuid        not null primary key
                         references tenants (id) on delete cascade,

  -- When the agents stop. From this instant `halt::halted` reports a stop for
  -- this tenant and every reader of it refuses, exactly as for a halt.
  --
  -- An instant and not a duration: "one month" has no meaning without the
  -- moment it is counted from, and a `days` column would make every reader
  -- redo that arithmetic — four chances to disagree about what a month is.
  -- The entry journey turns the founder's choice into a timestamp once.
  ends_at    timestamptz not null,

  -- The API key label of the human who chose it, same string and same source as
  -- `company_halts.halted_by` — it becomes this stop's `halted_by`, so a
  -- window-stop names a person for the same reason a halt does.
  set_by     text        not null
                         constraint company_windows_by_not_blank
                         check (length(btrim(set_by)) > 0),

  -- When the choice was made. `ends_at` says when it runs out; this says when
  -- somebody decided, which is the other half of "who did this to us".
  set_at     timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0045. No exceptions.
-- ---------------------------------------------------------------------------
--
-- Same hardest constraint, one word changed: **a tenant must never be able to
-- set another tenant's window.** Without `with check` a handler could file a
-- row wearing a neighbour's id and stop a business on a date it never agreed
-- to; without `force` the owning role walks past the policy entirely, and
-- `halted` — read through `tenant_tx` on every gate decision — would answer
-- with whichever company's row it found first.
--
-- `crates/store/src/halt.rs`'s
-- `a_window_is_invisible_from_another_tenant_and_its_rls_is_forced` is this
-- paragraph against a real database, and it fails if either line below is
-- dropped — the behavioural half catches the policy, and the `pg_class` half
-- catches `force`, which no cross-tenant test can see.

alter table company_windows enable row level security;
alter table company_windows force row level security;
drop policy if exists tenant_isolation on company_windows;
create policy tenant_isolation on company_windows
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- UPDATE is granted here and is not on `company_halts`, and the difference is
-- real rather than an oversight. A halt's reason is *evidence* — the sentence
-- an operator said during an emergency — so editing it would make the row
-- disagree with the audit entry that recorded it. A window is a *setting*: the
-- founder who bought one month and then buys a second is not rewriting history,
-- they are making a new choice, and the history of those choices is the
-- `company_halt_changed` rows `routes::halt` writes in the same transaction.
--
-- No DELETE. Removing a window is the one write in this feature that would make
-- a stopped company run again *by forgetting why it stopped*, with no row left
-- to say a window was ever chosen. Extending is the same intent with the
-- evidence intact, so extending is the only spelling.
grant select, insert, update on company_windows to app_role;
revoke delete on company_windows from app_role;
