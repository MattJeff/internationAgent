-- 0035_evidence_opener: the sentence a finding came to, kept on the row the
-- finding is.
--
-- `agentos_app::queue` produces the file the founder uploads to Smartlead. It
-- needs two things per row: a person, which is `contacts` joined to `accounts`,
-- and an opener, which is `agentos_app::vertical::Approach` — and until now an
-- `Approach` existed only for the few milliseconds of the selling turn that
-- rendered it, so the export had no source and nothing called it.
--
-- These two columns are that source, and they are on `evidence` rather than in
-- a table of their own for one reason: **the row a claim was rendered from is
-- the row that should carry the rendered claim.** `evidence` is already
-- append-only (`evidence_append_only`), already keyed to the account, already
-- indexed by `(tenant_id, account_id, checked_at desc)` — which is exactly the
-- lookup the export does — and already the thing whose existence means a
-- finding was reproduced. A separate `queued_openers` table would be a second
-- place for a claim to live and a second lifecycle to get wrong.
--
-- # What may be in them
--
-- `agentos_app::vertical::Approach::new`'s output, byte for byte. Not one byte
-- of the prospect's page is in that — `claim_line()` is built from our own
-- configuration, the probe inputs and parsed enums, and the verbatim panel text
-- stays in `observed_claim` beside it, quoted as data. So these columns are as
-- safe to interpolate into an email as `reproduction` is, and for the same
-- reason.
--
-- # NULL is a decision, not an absence
--
-- `Approach::new` returns nothing at all for the two findings that rest on our
-- own entry-requirements row rather than on the prospect's page
-- (`Finding::Contradicts`, `Finding::StayLength`) — they are evidence, they are
-- filed, and a human reads them. NULL here is that refusal, **stored**: the
-- export selects `where opener_subject is not null`, so "may this be asserted
-- to a prospect" is decided once, by the code that held the `Evidence`, and is
-- never recomputed from a string by something that did not.
--
-- Both or neither: a subject with no body is half a message.
--
-- # What this is not
--
-- It is not a rehydration path for `Evidence`. That type is sealed and
-- deliberately not `Deserialize` — "a claim is made from a fresh observation,
-- not from a row somebody rehydrated" — and nothing here reconstructs one. What
-- is stored and read back is the `Approach`, which is already the value the
-- codebase makes outlive its evidence: `vertical::follow_up` takes one, and it
-- carries `known_good_at` copied off the evidence precisely so the freshness
-- bar travels with the sentence. `checked_at` is that instant, already on this
-- row, so the export applies `MAX_FINDING_AGE` from the same column.

alter table evidence add column if not exists opener_subject text;
alter table evidence add column if not exists opener_body    text;

do $$
begin
  alter table evidence
    add constraint evidence_opener_pair
      check ((opener_subject is null) = (opener_body is null));
exception
  when duplicate_object then null;
end
$$;

do $$
begin
  alter table evidence
    add constraint evidence_opener_nonempty
      check (opener_subject is null
             or (length(btrim(opener_subject)) > 0 and length(btrim(opener_body)) > 0));
exception
  when duplicate_object then null;
end
$$;
