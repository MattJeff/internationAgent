#!/usr/bin/env bash
# Run the whole test suite.
#
# Why not plain `cargo test --workspace`: the integration tests talk to a real
# Postgres, and cargo runs each package's test binary in parallel. Several tests
# are cross-tenant by nature — the outbox poller reads every tenant's rows, which
# is exactly its job — so two packages sharing one database see each other's
# fixtures and fail in ways that have nothing to do with the code. One database
# per package, serialised within a package, and the interference is gone.
set -euo pipefail

HOST=${PGHOST:-localhost}
PORT=${PGPORT:-5442}
USER=${PGUSER:-postgres}
PASS=${PGPASSWORD:-postgres}
PACKAGES=(agentos-domain agentos-providers agentos-store agentos-app agentos-server)

psql_admin() { PGPASSWORD="$PASS" psql -h "$HOST" -p "$PORT" -U "$USER" -d postgres -q "$@"; }

for pkg in "${PACKAGES[@]}"; do
  db="ci_${pkg//-/}"
  echo "==> $pkg  (database $db)"
  psql_admin -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"
  for m in migrations/*.sql; do
    PGPASSWORD="$PASS" psql -h "$HOST" -p "$PORT" -U "$USER" -d "$db" -q -v ON_ERROR_STOP=1 -f "$m"
  done
  DATABASE_URL="postgres://$USER:$PASS@$HOST:$PORT/$db" \
    cargo test -p "$pkg" -- --test-threads=1
done
