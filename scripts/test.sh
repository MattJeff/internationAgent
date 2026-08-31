#!/usr/bin/env bash
# Run the whole test suite.
#
# Why not plain `cargo test --workspace`: the integration tests talk to a real
# Postgres, and cargo runs each package's test binary in parallel. Several tests
# are cross-tenant by nature — the outbox poller reads every tenant's rows, which
# is exactly its job — so two packages sharing one database see each other's
# fixtures and fail in ways that have nothing to do with the code. One database
# per package, and the interference is gone.
#
# There is no `--test-threads=1` on the package runs any more, and putting it
# back would hide the next regression rather than prevent one. It used to be
# load-bearing because four test helpers ran `DELETE FROM tenants` / `DELETE
# FROM outbox_events` with no `WHERE`, so any test could delete the rows of any
# test running beside it. Tests that need a whole database to themselves now
# take one (`apps/server/src/loops/mod.rs`, `apps/server/tests/end_to_end.rs`)
# and everything else is scoped to the tenant it created, which
# `crates/app/tests/scoped_deletes.rs` enforces. If this suite goes flaky
# again, that is a bug to find, not a flag to restore.
#
# Why the two guards below: dozens of fixtures in this workspace open with
#
#     let Ok(url) = std::env::var("DATABASE_URL") else { eprintln!("SKIP: …"); return };
#
# so a run with no database is not red, it is *green and empty* — the one test
# failure mode nobody notices. So: refuse to start without a reachable Postgres,
# and refuse to finish if any test skipped itself anyway. `--nocapture` is what
# makes the second guard possible at all; libtest throws away the output of
# passing tests, and a skipped test passes.
#
# Why the lints are in here too, and this is the same argument a third time.
# This script is what everybody — every contributor, every agent — runs before
# saying "green". Until now green meant "the tests pass", while `cargo clippy`
# and `cargo fmt --check` were something somebody remembered to run separately.
# That is another failure mode nobody notices, and it is not hypothetical: a
# `pub fn` in `apps/server/src/metrics.rs` sat behind an `#[allow(dead_code)]`
# with a note reading "delete it in the commit that adds the call", the call
# never came, and every green run agreed. Model-usage metrics were not wired at
# all in a product whose closing screen is a forecast of model spend.
#
# `fmt` first because it costs a second and a diff is cheaper to fix before a
# build than after one. Clippy last because it needs a compiled tree and the
# tests have just warmed one — and `-D warnings` because a lint nobody is
# forced to read is a lint that does not exist.
set -euo pipefail

cd "$(dirname "$0")/.."

die() { echo >&2; echo "FATAL: $*" >&2; exit 1; }

# --- formatting, before anything is compiled ---------------------------------
echo "==> cargo fmt --check"
cargo fmt --all --check || die "the tree is not formatted; run \`cargo fmt --all\`"

HOST=${PGHOST:-localhost}
PORT=${PGPORT:-5442}
USER=${PGUSER:-postgres}
PASS=${PGPASSWORD:-postgres}
PACKAGES=(agentos-domain agentos-providers agentos-store agentos-app agentos-server)

psql_admin() { PGPASSWORD="$PASS" psql -h "$HOST" -p "$PORT" -U "$USER" -d postgres -q "$@"; }


# --- guard 1: a database has to be there before anything is worth running ----
command -v psql >/dev/null 2>&1 ||
  die "psql is not on PATH. macOS: brew install libpq && brew link --force libpq"

if ! psql_admin -v ON_ERROR_STOP=1 -c 'SELECT 1' >/dev/null 2>&1; then
  echo >&2
  echo "FATAL: no PostgreSQL answering at $HOST:$PORT as user '$USER'." >&2
  echo >&2
  echo "  Every integration test in this workspace skips itself when it cannot" >&2
  echo "  reach a database, so continuing would print a green run of nothing." >&2
  echo >&2
  echo "  Start one:  docker compose up -d       (publishes 5442, see docker-compose.yml)" >&2
  echo "  Point here: PGHOST=… PGPORT=… PGUSER=… PGPASSWORD=… scripts/test.sh" >&2
  echo >&2
  PGPASSWORD="$PASS" pg_isready -h "$HOST" -p "$PORT" -U "$USER" >&2 || true
  exit 1
fi

# One run's databases are that run's alone. Two concurrent runs used to share
# the fixed names `ci_<pkg>` and deadlock: the second run's DROP DATABASE waits
# forever on a connection the first run still holds, and neither ever finishes.
# `RUN_ID` is the shell's PID folded together with the checkout — the last
# paragraph in this block is why the PID alone was not enough. Override RUN_ID
# to get stable names for debugging.
#
# Lowercased, and that is not tidiness. `CREATE DATABASE ci_agentosstore_wB`
# is an *unquoted* identifier, which PostgreSQL folds to `ci_agentosstore_wb` —
# while `DATABASE_URL` below is a string and keeps the `B`. So an override with
# a capital in it creates one database and connects to another, and every test
# in the package dies with `3D000: database … does not exist` a tenth of a
# second in. It reads exactly like somebody dropped the database mid-run, which
# is what it cost to find: an accusation aimed at the wrong process.
#
# Folding here rather than quoting the identifiers: quoting would make
# `ci_agentosstore_wB` real and case-sensitive everywhere, including in the
# cleanup pattern and in anything an operator types by hand at 2am. Postgres
# already has an opinion about the case of a bare identifier and this agrees
# with it.
#
# `$$` alone is not unique enough, and the failure it caused was expensive to
# read. The cleanup trap below drops every database matching this run's id, so
# two runs that share one are two runs where whichever finishes first deletes
# the other's databases mid-suite. That reads as `3D000: database
# "ci_agentosapp_37123" does not exist` — 283 instant failures that look like a
# broken migration and are not the code at all.
#
# PIDs are unique among *live* processes, which is why this looks safe and is
# not: a suite runs for the better part of an hour, cargo and rustc spawn
# thousands of processes inside it, and macOS wraps at 99999. A second run
# started an hour later can legitimately be handed the number the first one is
# still using. Folding in the checkout — the same hash the migration ledger
# uses, for the same reason — makes a collision need both the same PID and the
# same worktree, which is one run.
RUN_ID=$(printf '%s' "${RUN_ID:-$$$(printf '%s' "$PWD" | shasum | cut -c1-6)}" |
  tr '[:upper:]' '[:lower:]')

log=$(mktemp)
# Drop this run's databases whichever way we leave — including the ^C that
# leaves them behind and eventually fills the disk. WITH (FORCE) rather than a
# bare DROP for the same reason it is used below.
cleanup() {
  rm -f "$log"
  # Asked of pg_database rather than rebuilt from PACKAGES: a package's database
  # is not the only one its run makes, and this script deliberately does not
  # know which. Every private database in the workspace derives its name from
  # DATABASE_URL and therefore begins with the one below — the loops'
  # `<db>_outbox` / `_inbound` / `_provisioning` / `_initiative`, the gate's
  # `<db>_gateceiling`, and the server harnesses' `<db>_e2e_…` / `_orizn_…` /
  # `_srcg_…` / `_readyz_…` / `_turn_…`. That is the whole contract, and it is
  # why the pattern is a prefix rather than a list: a harness that invents a
  # name of its own is a database nothing on the machine will ever collect, and
  # three of them did exactly that until `apps/server/tests/common/mod.rs`
  # existed.
  psql_admin -tAc \
    "SELECT datname FROM pg_database \
      WHERE datname LIKE 'ci\_%\_$RUN_ID' OR datname LIKE 'ci\_%\_${RUN_ID}\_%'" 2>/dev/null |
    while read -r db; do
      [ -n "$db" ] || continue
      psql_admin -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT INT TERM

# --- what a green run here does NOT prove -----------------------------------
# This machine is probably macOS, and macOS hands out a **microsecond** clock:
# `Utc::now()`'s nanoseconds are always a multiple of a thousand. PostgreSQL's
# `timestamptz` also holds microseconds, so an instant written and read back
# comes home unchanged, and any test comparing the two passes.
#
# Linux hands out real nanoseconds. The same round trip drops the last three
# digits, and the same assertion fails. Two tests lived that way for as long as
# they existed — green on every laptop, red in CI, about the clock and nothing
# else. They now build their instants with `trunc_subsecs(6)`.
#
# To find the next one without waiting for CI, give the tests a finer clock:
#
#   inside `mod tests`, replace `Utc::now()` with
#   `(Utc::now() + chrono::TimeDelta::nanoseconds(1))`, run, and revert.
#
# Skip `crates/app/tests/ui/` when you do — those are trybuild fixtures whose
# whole job is to produce one exact compiler error, and editing them fails
# the comparison for a reason that has nothing to do with clocks.
#
# Anything that compares an instant against its own round trip goes red.
#
# **Run it one crate at a time.** A single failure stops the whole suite, so a
# workspace-wide sweep reports the first crate and stays silent about the rest —
# which is exactly how the first attempt concluded the class was closed after
# covering four crates of six. Swept individually and to completion: two sites
# in `agentos-store`, two in `agentos-app`, one in `agentos-server`, none in
# `agentos-domain`, `agentos-providers` or `agentos-eval`. All five fixed.

# --- guard: an applied migration is immutable, and only a long-lived database
# can say so -------------------------------------------------------------------
# Every database above is created fresh, so every migration is applied for the
# first time and no checksum is ever compared. That is precisely the blind spot:
# sqlx stores a hash of each migration file in `_sqlx_migrations`, and editing a
# file that has already been applied makes every existing database refuse to
# start with `VersionMismatch` — while a fresh run stays green. It has happened
# here: a comment changed in an applied `0041` took down every database that had
# it, and the suite said nothing.
#
# So one database is deliberately NOT dropped between runs, and NOT named after
# RUN_ID. It carries the migration history of every previous run, which makes it
# the only thing in this repo that can notice an edit. It is never used by a
# test — only migrated — so nothing in it needs to be clean.
#
# On the very first run it is created empty, every migration applies for the
# first time, and this guard proves nothing. It is vacant exactly once per
# checkout and real from then on; there is no way to have it both ways, and
# saying so beats a green run that looks like evidence.
#
# Keyed to the tree rather than to the run, and both halves of that matter. It
# has to outlive the run, or it could never see an edit at all. And it has to
# be per tree, because several worktrees migrate in parallel against one
# Postgres: a fixed name means the moment any of them adds a migration the
# others fail on a file nobody in their tree touched — the exact error this
# guard exists to raise, raised for the wrong reason, and a guard that cries
# wolf is worse than none. The price is that a fresh worktree is blind on its
# first run, which for waves of agents is the common case rather than a
# one-off. It is the right price; it is not nothing.
LEDGER="ci_migration_ledger_$(printf '%s' "$PWD" | shasum | cut -c1-10)"
echo "==> migrations against $LEDGER (kept between runs on purpose)"
psql_admin -v ON_ERROR_STOP=1 -c "SELECT 1 FROM pg_database WHERE datname = '$LEDGER'" \
  | grep -q 1 || psql_admin -v ON_ERROR_STOP=1 -c "CREATE DATABASE $LEDGER"
if command -v sqlx >/dev/null 2>&1; then
  sqlx migrate run --source migrations \
    --database-url "postgres://$USER:$PASS@$HOST:$PORT/$LEDGER" 2>&1 | tail -3 ||
    die "migrations failed against a database that already had earlier ones applied.
  If this says VersionMismatch, a migration file that was already applied has
  been edited. Restore it byte-for-byte from the commit that added it and put
  the correction in a NEW migration -- editing it breaks every database that
  ever ran it, and every fresh database will keep passing while they do."
else
  # Not fatal: the ledger is the only thing here that needs the CLI, and a run
  # without it is still a real run — it just cannot see this one class of edit.
  # Said out loud rather than skipped quietly, because a guard nobody knows is
  # off is worse than no guard.
  echo "==> sqlx CLI absent: the applied-migration check did NOT run" >&2
fi

for pkg in "${PACKAGES[@]}"; do
  db="ci_${pkg//-/}_$RUN_ID"
  echo "==> $pkg  (database $db)"
  # WITH (FORCE) terminates any leftover backend instead of blocking on it.
  # A test binary killed mid-run leaves its connection open, and a plain DROP
  # then hangs with no output — which reads exactly like a slow build.
  psql_admin -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" -c "CREATE DATABASE $db"
  # No psql migration loop. `Db::migrate` runs sqlx's migrator, and sqlx tracks
  # what it applied in `_sqlx_migrations` — a table psql's pass does not write.
  # So applying them here did not save sqlx the work, it just meant every
  # migration ran twice against every package's database. That silently made
  # idempotence a requirement of every migration, and the trap is sharper than
  # it sounds: `create or replace view` can add a column but never drop one, so
  # a later migration that widens a view makes the earlier one's own
  # `create or replace` fail with 42P16 on the second pass — an error about a
  # migration nobody edited.
  DATABASE_URL="postgres://$USER:$PASS@$HOST:$PORT/$db" \
    cargo test -p "$pkg" -- --nocapture 2>&1 | tee "$log"

  # --- guard 2: "ok" is only ok if nothing opted out ------------------------
  # Unanchored: libtest prints the skip on the same line as the test name,
  # `test foo::bar ... SKIP: DATABASE_URL is unset; …`.
  if grep -q 'SKIP: ' "$log"; then
    echo >&2
    grep -o 'SKIP: .*' "$log" | sort -u >&2
    die "$pkg reported success but skipped the tests above. \
DATABASE_URL was set and Postgres was reachable, so this is a new skip \
condition — remove it or teach this script to satisfy it. A suite that \
silently skips its integration tests and prints 'ok' is worse than a red one."
  fi
done

# --- the evaluations ---------------------------------------------------------
# Outside the loop above, and deliberately: `agentos-eval` opens no connection,
# so giving it a database would mean applying every migration in the tree to
# prove a ranking still ranks. Its deterministic suites are pure functions over
# fixtures — a regression in ranking, in the psyche, or in the proof-of-need
# classification breaks the build here. What is NOT run: the model held-out
# set, which needs the local `claude` binary and about a minute, and lives
# behind `cargo run -p agentos-eval -- --live`. A suite that takes twenty
# minutes is a suite nobody runs.
echo "==> agentos-eval  (no database; deterministic suites only)"
cargo test -p agentos-eval


# --- the lints ---------------------------------------------------------------
# Last, and with `-D warnings`. See the header: a warning nobody is forced to
# read is a warning that does not exist, and this workspace has already paid for
# that once.
echo "==> cargo clippy --workspace --all-targets"
cargo clippy --workspace --all-targets -- -D warnings \
  || die "clippy is not silent"

# --- and again with every feature on, because until this line whole modules
# were compiled by nothing at all ----------------------------------------------
# Everything above builds the default feature set, and `live-orizn` is not in
# it. Keeping those tests out of a default *run* is right — they want `npx`, the
# open internet, a logged-in `claude` binary and ten minutes — but the price
# nobody meant to pay was that `cargo` never so much as parsed them. There are
# deux `#[cfg(feature = "live-orizn")]` sites, and behind them:
# `crates/eval/src/dryrun.rs` (2 280 lines that stand a tenant up against the
# real model — the only end-to-end measurement of this product there is, gated
# at `crates/eval/src/lib.rs`), and the `--dry-run` arm of
# `crates/eval/src/main.rs`. There were three more, in `agentos-app`; they
# dialled the real Orizn MCP server and went with it.
# `dryrun.rs` used to say so about itself, in the comment above the finance caps
# it reads out of `docs/orizn-roles/finance.json` — that this script "compiles
# neither `cargo test -p agentos-eval` nor `cargo clippy --all-targets` with
# it". It named the hole and left it open; this line closes it, and that comment
# now records the correction.
#
# Checking, not running. Clippy never executes a test binary, so nothing here
# dials a real server, spends an API call or needs a key — and an assertion
# written behind the feature is still an assertion nothing runs. What this buys
# is narrower and real: a rename in `store::policy`, `app::mcp` or
# `domain::action` can no longer rot that harness silently, which is exactly how
# it would rot, because nobody runs `--features live-orizn` between releases.
#
# A second clippy invocation rather than `--all-features` on the one above,
# because the two feature sets are two separate compilations and only running
# both lints what each one `cfg`s out of the other. Measured here: ~35 s cold,
# ~10 s after an edit that touches three crates, ~1 s when nothing moved. It was
# checked the only way this kind of line can be: by breaking `dryrun.rs` and
# confirming that the whole suite above stays green (`agentos-eval`: 39 passed)
# while this line goes red.
echo "==> cargo clippy --workspace --all-targets --all-features"
cargo clippy --workspace --all-targets --all-features -- -D warnings \
  || die "clippy is not silent with every feature on (\`live-orizn\` is the only \
one today: crates/eval/src/dryrun.rs and crates/app's live Orizn tests). Nothing \
in a default run compiles these, so this is the only line that would have told \
you."
