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
# `$$` is the shell's PID, so a stale set from a killed run can never collide
# with a live one either. Override RUN_ID to get stable names for debugging.
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
RUN_ID=$(printf '%s' "${RUN_ID:-$$}" | tr '[:upper:]' '[:lower:]')

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
# first time, and this guard proves nothing. It is vacant exactly once and
# real from then on; there is no way to have it both ways, and saying so
# beats a green run that looks like evidence.
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
