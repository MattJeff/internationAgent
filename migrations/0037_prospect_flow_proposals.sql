-- 0037_prospect_flow_proposals: what the employee thinks a prospect's booking
-- form looks like, in a table it is allowed to write.
--
-- `0032_prospect_flows.sql` took INSERT and UPDATE on `prospect_flows` away from
-- `app_role` and gave the confirmation to a named human, and the argument it
-- made is still the whole of why this vertical can be sold: a selector aimed at
-- the wrong element that *exists* produces a reproducible, screenshotted,
-- repeatable-by-the-recipient finding about somebody else's checkout, and
-- nothing downstream can tell that from a real one. That bar does not move here
-- and this migration does not touch a single grant on that table.
--
-- What it costs is the founder's time, linearly: ~1,615 prospects, five CSS
-- selectors each, typed by a human who has opened the page and read the DOM.
-- The gain available is the difference between **writing** five selectors and
-- **reading** five, because reading five is a glance at a page the reviewer had
-- to open anyway.
--
-- So: the employee proposes into this table, a human promotes out of it with
-- `agentos-server flow promote`, and promotion is an ordinary
-- `set_prospect_flow` + `confirm_prospect_flow` on the operator's own database
-- credential. There is no new write path into `prospect_flows` at all.
--
-- FIVE DECISIONS.
--
-- 1. NOTHING HERE CAN SPELL A CONFIRMATION.
--    There is no `confirmed_by` column and no `confirmed_at` column. Not
--    nullable ones — absent ones. A table `app_role` can UPDATE and that has a
--    column meaning "a human vouched for this" is one UPDATE away from an
--    employee vouching for itself, and no CHECK constraint can tell a real name
--    from a plausible one. The only representation of "somebody looked" in this
--    schema stays where 0032 put it, on a table the application cannot write.
--
--    `proposed_by` is a `uuid` referencing `employees`, and that is the same
--    decision seen from the other side: the column that says who produced this
--    row cannot hold a person's name, because it can only hold a machine's id.
--    A reader who wants to know whether a human was involved does not have to
--    read the value — the *type* answers.
--
-- 2. THE SELECTOR SHAPE IS A CHECK, NOT A CONVENTION.
--    Every selector here matches `^#[A-Za-z_][A-Za-z0-9_-]{0,63}$` — a `#`, then
--    one ASCII identifier. That is a decision about what a *page* is allowed to
--    put in one of our columns, and the reason it is stated as a regexp rather
--    than left to the application is the reason 0032's re-confirmation trigger
--    exists: `agentos_app::flow_proposal` refuses the same shape at the boundary
--    and this makes it true of a `psql` session and of whatever writes this
--    table next.
--
--    This is deliberately *not* the trade `entry_url` makes two rows down.
--    0032's decision 4 refuses a CHECK regexp for a URL because it would be a
--    worse parser than `url::Url` wearing a constraint's authority — and that is
--    correct, a URL is not a regular language. An identifier is. The grammar
--    here has one production and the regexp *is* it, so there is no second,
--    weaker copy of anything.
--
--    What the shape buys, clause by clause, is that a selector cannot be:
--      * a sentence or any prose — no space is in the charset;
--      * a script — no `(`, no `)`, no `<`, no `=`, no quote of either kind;
--      * a selector list — no `,`, so it cannot match a first element somewhere
--        else on the page;
--      * a combinator walk — no space, no `>`, no `+`, no `~`, so it cannot
--        start at the element we looked at and land on one we did not;
--      * a functional pseudo-class — no `:`, so no `:has()`, no `:nth-child()`,
--        no `:not()`;
--      * an attribute selector — no `[`, no `]`;
--      * an escape — no `\`;
--      * a payload — 64 characters, and an `id` longer than that is not an id a
--        reviewer can check at a glance either.
--    Bounded, ASCII, and one token long, which is what makes the review a
--    reviewer can actually do: paste it into `document.querySelector` and look
--    at what lights up.
--
--    Selectors are NULLABLE here and NOT NULL over there. A proposal is what the
--    employee could find, and the results panel of an entry-requirements widget
--    is frequently not in the markup of the entry page at all — it is rendered
--    after the form is submitted. `flow promote` refuses a proposal that is
--    missing one of the three columns `prospect_flows` requires, and names the
--    one that is missing. An incomplete proposal is worth having: four selectors
--    read and one typed is still four fewer than five typed.
--
-- 3. ONE PROPOSAL PER PROSPECT, KEYED ON `accounts.id`, DOMAIN NOT COPIED.
--    0032's decision 1, unchanged and for its reasons. A second proposal would
--    be a second answer to "what does their booking page look like" and nothing
--    could choose. Re-proposing overwrites, which is right: the newer look at
--    the page is the better one, and no confirmation is being revoked because
--    there is none here to revoke.
--
-- 4. `app_role` WRITES THIS TABLE, AND THAT IS THE WHOLE POINT.
--    Full grants, unlike `prospect_flows`. The thing 0032 is protecting is not
--    "a selector chosen by a machine exists somewhere" — it is "a selector
--    chosen by a machine is probed". A row here is probed by nothing:
--    `next_flow_to_probe` and `flow_of` both read `prospect_flows` and neither
--    has ever heard of this table, and `Flow::confirmed` — the only constructor
--    of the value `Prober` runs — takes a `ProspectFlow`, which no query over
--    this table can produce.
--
-- 5. PROMOTION GRANTS NOTHING ELSE.
--    Writing a confirmed flow does not put its host on `allowed_domains`, and
--    `Prober` *types* into the form, which is a `BrowserWrite`. So a promoted
--    flow on a host that is not on the write allowlist is a flow that will not
--    probe, and the operator has to add it deliberately with
--    `agentos-server policy`. `docs/ORIZN.md` says so where the promotion is
--    documented. Granting it here, silently, as a convenience of promotion,
--    would be a policy change nobody asked for hidden inside a data change.
--
-- Replayable: IF NOT EXISTS / OR REPLACE throughout.

create table if not exists prospect_flow_proposals (
  -- One proposal per prospect. See decision 3.
  account_id         uuid        primary key,
  tenant_id          uuid        not null references tenants (id) on delete cascade,
  -- The page the employee looked at. `https://` here for 0032's reason, and its
  -- host is checked against the account's domain in Rust, where both values are
  -- already parsed — the proposal is written by an INSERT that resolves the
  -- account *from* this host, so the two cannot disagree by construction.
  entry_url          text        not null,
  -- Every one nullable: a proposal is what could be found. See decision 2.
  passport_field     text,
  destination_field  text,
  date_field         text,
  submit             text,
  panel              text,
  -- Which employee looked. A uuid, so this column cannot hold a person's name
  -- even by accident, and cannot be read as a confirmation. See decision 1.
  proposed_by        uuid        not null references employees (id) on delete cascade,
  proposed_at        timestamptz not null default now(),
  -- The composite FK, so a proposal cannot point at another tenant's account.
  constraint prospect_flow_proposals_account_fk
    foreign key (tenant_id, account_id) references accounts (tenant_id, id)
    on delete cascade,
  constraint prospect_flow_proposals_entry_https check (entry_url like 'https://%'),
  -- Decision 2. `is null or` on each, because absent is a state and a malformed
  -- selector is not.
  constraint prospect_flow_proposals_selector_shape check (
    (passport_field    is null or passport_field    ~ '^#[A-Za-z_][A-Za-z0-9_-]{0,63}$')
    and (destination_field is null or destination_field ~ '^#[A-Za-z_][A-Za-z0-9_-]{0,63}$')
    and (date_field        is null or date_field        ~ '^#[A-Za-z_][A-Za-z0-9_-]{0,63}$')
    and (submit            is null or submit            ~ '^#[A-Za-z_][A-Za-z0-9_-]{0,63}$')
    and (panel             is null or panel             ~ '^#[A-Za-z_][A-Za-z0-9_-]{0,63}$')
  )
);

comment on table prospect_flow_proposals is
  'What an employee read off a prospect''s booking page. Never probed: '
  'agentos_app::proof_of_need::Flow is built only from prospect_flows, which '
  'app_role cannot write. Promoted by a human with `agentos-server flow promote`.';
comment on column prospect_flow_proposals.proposed_by is
  'The employee that produced this row. A uuid on purpose: this column cannot '
  'hold a person''s name, so no value of it can be read as a confirmation.';

-- ---------------------------------------------------------------------------
-- Row-level security, same shape as 0001_core
-- ---------------------------------------------------------------------------

alter table prospect_flow_proposals enable row level security;
alter table prospect_flow_proposals force row level security;
drop policy if exists tenant_isolation on prospect_flow_proposals;
create policy tenant_isolation on prospect_flow_proposals
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- All four, unlike `prospect_flows` — see decision 4. The employee proposes,
-- re-proposes and (through `flow promote`) has its proposal cleared away.

grant select, insert, update, delete on prospect_flow_proposals to app_role;
