-- 0079_tenant_model_tariff: the price the tenant pays for a token, declared by the tenant.
--
-- `GET /v1/usage` reports tokens and stops, and its module docs say why: "there
-- is no cost figure here and no price anywhere in this repository. A price per
-- million tokens is a fact with a source and a date". That argument is about
-- *the repository* holding a price, and it stands. This migration does not put
-- a price in the repository. It gives the tenant three nullable columns to put
-- *their own* price in — the rate on the Anthropic contract they signed, which
-- is a fact they know and we never will — so that `GET /v1/pnl` can multiply
-- tokens by it and hand back a figure whose source is the person who typed it.
--
-- WHY THESE COLUMNS SIT ON `tenant_model_access`
--
-- Because a tariff is a fact about a credential, not about a tenant in general.
-- The row `0041_tenant_model_access` created is "the model this tenant thinks
-- with, by what path, proven when"; a price per token is the fourth thing you
-- know about that same arrangement, and it changes when the arrangement does —
-- reconnect with another account's key and the old rate is the wrong rate. One
-- row per tenant already, so there is nothing to join and no second table that
-- could describe a connection the first table does not have.
--
-- A `cli` connection may carry a tariff too. That path spends the host's
-- logged-in CLI and the token is never metered by us, so a figure on it is
-- indicative rather than billed — and the reader is told so: the route reports
-- `cost_source = declared_tariff_on_cli_path` for exactly this row shape.
--
-- WHAT THE COLUMNS ARE
--
-- USD per million tokens, one per token kind the provider meters
-- (`model_usage_daily` has the same three: input, output, cache read). NUMERIC
-- and not a float, because 0.30 has to survive a round trip and a float makes
-- that a question. Nullable, because a tenant that has not declared a rate has
-- no cost — null, not zero: `GET /v1/pnl` answers `cost_usd: null` there, and
-- the discipline is the same one 0024 set for tokens: unknown is not zero.
--
-- No currency column. The unit is in the name, and the only contract this
-- product connects to is priced in USD. The day that changes, the column is
-- renamed rather than reinterpreted.
--
-- No `tariff_declared_at`, no `declared_by`. Who set it is a `model_connected`
-- audit row away, and the tariff is not a fact this system observed — it is a
-- claim the tenant made, and a claim carries its own date badly.
--
-- Replayable: `if not exists` on every column and the duplicate_object catch
-- `0050` uses for the constraint. No backfill: nobody has declared a rate yet,
-- and null is what "not declared" means.

alter table tenant_model_access
  add column if not exists usd_per_mtok_input      numeric,
  add column if not exists usd_per_mtok_output     numeric,
  add column if not exists usd_per_mtok_cache_read numeric;

-- Negative is not a price. Zero is allowed: a promotional or internal rate is a
-- rate, and refusing it would push the tenant to leave the column null, which
-- reads as "unknown" rather than "free".
do $$
begin
  alter table tenant_model_access
    add constraint tenant_model_tariff_nonnegative
    check (
      (usd_per_mtok_input      is null or usd_per_mtok_input      >= 0) and
      (usd_per_mtok_output     is null or usd_per_mtok_output     >= 0) and
      (usd_per_mtok_cache_read is null or usd_per_mtok_cache_read >= 0)
    );
exception
  when duplicate_object then null;
end
$$;
