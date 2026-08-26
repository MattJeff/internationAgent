-- 0033_prospect_listing: the two things a directory says about a prospect that
-- 0011_revenue.sql has no column for.
--
-- `agentos_app::prospects` loads the founder's Smartlead-shaped CSVs into
-- `accounts` and `contacts`. Eight columns come in — email, first_name,
-- last_name, company_name, phone_number, website, linkedin_profile, location —
-- and two of them had nowhere to land. Both are on `accounts` and both are
-- deliberately free text: they are a third party's directory entry, copied
-- verbatim, and the typed columns beside them keep their meanings.
--
-- 1. `location`. `accounts.country` is ISO 3166-1 alpha-2 with a CHECK, and the
--    lists carry `États-Unis`, `Mandaluyong, Philippines`, `TAIPEI CITY,
--    Taiwan`, `Portugal / Royaume-Uni` and `inconnu` — 118 distinct spellings
--    across three languages in 2,152 rows. A name-to-code table would be wrong
--    for a long tail nobody would notice, and `country` is not a field anything
--    reads yet, so the import writes the founder's own string here and leaves
--    `country` at `ZZ` unless the operator passes `--country`. Nothing is
--    guessed and nothing is lost. The upgrade path is a lookup table feeding
--    `country` — this column keeps the input it would be derived from.
--
-- 2. `website`. `accounts.domain` is the *registrable* domain, lower case,
--    because that is the identity of a prospect and where its booking flow
--    lives. It is derived: `https://www.qyer.com/` becomes `qyer.com`. The
--    scheme, the `www.` and the path are the founder's data and they do not
--    survive that derivation, so the URL as the list spells it is kept here.
--    `agentos_app::queue` has a test that a row of his file comes back out of
--    the export byte for byte; this is the column that makes that possible for
--    a row that came *in* through the importer.
--
-- What still has no column, and is dropped rather than bent:
--
-- * `linkedin_profile` — empty in all 3,048 rows of every list. A column for a
--   field nobody has filled is a guess about its shape; the importer counts the
--   non-empty ones and says so, which is the signal that this migration has a
--   sequel.
-- * a phone that is not E.164 — 584 of 2,044, e.g. `(02)83518906`. It cannot go
--   in `contacts.phone`: that CHECK exists because `revenue_suppression_of`
--   matches a phone by string equality, so an address in a shape the
--   suppression list can never match is one that cannot be checked against an
--   opt-out. Normalising it needs a country guess per row, and a wrong guess is
--   a stranger's phone ringing.
--
-- No CHECK beyond "not the empty string": these are somebody else's prose and
-- this schema has no opinion about it. NULL means the list left it blank.
-- Replayable, like every migration here.

alter table accounts add column if not exists location text;
alter table accounts add column if not exists website  text;

do $$
begin
  alter table accounts
    add constraint accounts_location_nonempty
      check (location is null or location <> '');
exception
  when duplicate_object then null;
end
$$;

do $$
begin
  alter table accounts
    add constraint accounts_website_nonempty
      check (website is null or website <> '');
exception
  when duplicate_object then null;
end
$$;

comment on column accounts.location is
  'The prospect''s location as the source list spells it, verbatim. Free text: '
  'see accounts.country for the ISO-2 code, which is not derived from this.';
comment on column accounts.website is
  'The prospect''s site as the source list spells it, verbatim, scheme and all. '
  'accounts.domain is the derived registrable host and is the identity.';
