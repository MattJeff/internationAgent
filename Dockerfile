# Two stages, and the split is the whole point: the builder carries rustc, a
# cargo registry and a couple of gigabytes of intermediate objects, none of
# which can serve a request. What ships is one binary and a libc.
#
# No `# syntax=` directive on purpose. Nothing below needs a frontend newer than
# the one built into the daemon — no cache mounts, no heredocs — and a syntax
# directive is a network fetch on every build, including the offline ones.

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
# Pinned to the exact toolchain in rust-toolchain.toml. Not `rust:1`, not
# `rust:slim`: a base tag that floats is a compiler that changes between the
# build CI passed and the build that ships, and edition 2024 plus a workspace
# that pins `rust-version = 1.94` gives that plenty of room to matter.
#
# Bookworm rather than alpine. A musl image is smaller, and it is also a
# different target triple, a different allocator, and a `ring` build that has to
# be proven separately — paid for an image saving that the runtime stage below
# gets anyway by not shipping the toolchain.
FROM rust:1.98.0-slim-bookworm AS build

# No pkg-config, no libssl-dev, no apt-get at all. reqwest, sqlx and
# tokio-tungstenite are all configured for rustls in the workspace Cargo.toml,
# so nothing in this tree links OpenSSL; installing it would be 40 MB of build
# dependency for a library no crate opens.
WORKDIR /src

# --- the dependency layer --------------------------------------------------
# Manifests first, real sources second, and the layer boundary between them is
# what this whole block buys: editing a .rs file must not re-resolve, re-fetch
# and re-compile four hundred crates.
#
# Cargo has no "build only the dependencies" verb, so the substitute is a
# workspace whose members are empty. Same Cargo.lock, same feature resolution,
# same external crates compiled — and nothing of ours to compile, because there
# is nothing in them yet.
#
# Rejected alternative: BuildKit `--mount=type=cache` over /usr/local/cargo and
# target/. It is a third of the lines and faster on a developer's laptop, but a
# cache mount is not a layer — it lives in the builder, not in the image — so it
# is cold on every fresh CI runner, which is precisely where ten minutes hurts.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/domain/Cargo.toml    crates/domain/
COPY crates/eval/Cargo.toml      crates/eval/
COPY crates/store/Cargo.toml     crates/store/
COPY crates/providers/Cargo.toml crates/providers/
COPY crates/app/Cargo.toml       crates/app/
COPY apps/server/Cargo.toml      apps/server/
# `apps/social` is a workspace member too: cargo refuses to load the workspace
# with one manifest missing, whichever package is being built. Stubbed like the
# server, never built here.
COPY apps/social/Cargo.toml      apps/social/
RUN set -eux; \
    for crate in crates/domain crates/eval crates/store crates/providers crates/app; do \
      mkdir -p "$crate/src"; : > "$crate/src/lib.rs"; \
    done; \
    for app in apps/server apps/social; do \
      mkdir -p "$app/src"; echo 'fn main() {}' > "$app/src/main.rs"; \
    done; \
    cargo build --release --locked -p agentos-server --bin agentos-server; \
    rm -rf crates apps target/release/.fingerprint/agentos-*

# --- the real build --------------------------------------------------------
# `migrations/` arrives here and gets *embedded*: `Db::migrate` calls
# `sqlx::migrate!`, a proc macro that reads the .sql files at compile time. That
# is why the runtime stage copies one file and nothing else — the schema is
# inside the binary, so a pod can never run a binary and a migrations directory
# that disagree about the schema.
COPY . .
# `touch` before cargo, and it is load-bearing. COPY preserves the mtime of the
# files it copies, so cargo can conclude the sources it just received are older
# than the stub artifacts from the layer above and skip them — a build that
# succeeds and ships `fn main() {}`. Deleting the stub fingerprints above is the
# belt; this is the braces, because the failure is silent and ships.
RUN set -eux; \
    find crates apps -name '*.rs' -exec touch {} +; \
    cargo build --release --locked -p agentos-server --bin agentos-server

# ---------------------------------------------------------------------------
# Stage 2: run
# ---------------------------------------------------------------------------
# Debian rather than distroless, and it is a trade rather than an oversight.
# distroless/cc is ~40 MB smaller and non-root by construction; it also has no
# shell, and the first thing anybody does to a pod that is up and refusing every
# action (see the platform-policy warning in main.rs) is exec into it. Same
# bookworm userland as the builder, so the glibc the binary was linked against
# is the glibc it runs on — the one thing a newer or smaller base breaks, and it
# breaks at startup with a symbol version error nobody enjoys reading.
FROM debian:bookworm-slim AS runtime

# ca-certificates, and nothing else. reqwest and tokio-tungstenite are built
# with webpki-roots and carry their own trust store, but sqlx's rustls stack
# does not, and a managed Postgres over TLS is the normal deployment — a missing
# root here is an outage that reads like a network problem.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# A fixed numeric uid, and USER is numeric for the reason the uid is fixed:
# Kubernetes' `runAsNonRoot` reads the uid out of the image config and cannot
# resolve a *name* against this image's /etc/passwd, so `USER agentos` would be
# rejected as "container has runAsNonRoot and image has non-numeric user".
# `--system` so the account has no password, no expiry and nothing to log in to.
RUN useradd --system --uid 10001 --user-group --no-create-home agentos
USER 10001:10001

COPY --from=build /src/target/release/agentos-server /usr/local/bin/agentos-server

# Matches DEFAULT_BIND in apps/server/src/config.rs. Documentation, not a
# firewall — the process still binds whatever APP_BIND says.
EXPOSE 8080

# --- migrations run on boot, not as a separate step ------------------------
# `serve_until_signal` awaits `Db::migrate()` before `TcpListener::bind`, and
# this image deliberately has no second entrypoint that would run them instead.
# Both sides of the argument are real:
#
#   * A separate step — an init container, a Job, an operator's runbook line —
#     cannot race, and never applies a migration nobody meant to apply. It is
#     also one more thing to forget, and forgetting it does not fail loudly: it
#     is a replica that boots happily against a schema one migration behind and
#     dies on the first request that needs the new column.
#   * On boot races when a rollout starts three replicas at once. Except it does
#     not here: sqlx wraps the whole run in a Postgres advisory lock, so pods
#     two and three block until pod one finishes, then read `_sqlx_migrations`
#     and find nothing left to do. The lock is held across the run rather than
#     per migration, which is what makes the racing case safe rather than merely
#     unlikely.
#
# So: on boot. The failure the lock removes is worse than the one it leaves,
# which is a slow first boot while one pod migrates. What it does *not* make
# safe is a migration that the currently-running version cannot tolerate — that
# is a rollout discipline (expand, deploy, contract) and no entrypoint can fix
# it.
#
# Nothing is baked into this image. No DATABASE_URL, no AGENTOS_MASTER_KEY, no
# default AGENTOS_ALLOW_MOCKS: a credential in an image is a credential in every
# registry that mirrors it, and a default ALLOW_MOCKS would silently disarm the
# boot guard for every deployment that forgot to unset it. The only thing this
# image asserts about its configuration is that config.rs refuses to start
# without the rest of it.
#
# No HEALTHCHECK either. It would mean shipping curl to poll a /readyz that
# Kubernetes already polls over the network, and a HEALTHCHECK is invisible to
# an orchestrator that does not read one.
#
# Exec form, so PID 1 is the server itself. Under the shell form SIGTERM goes to
# /bin/sh, which does not forward it, so `shutdown_signal` never fires and the
# twenty-second drain never happens — every rolling deploy would drop its
# in-flight requests and look fine doing it.
ENTRYPOINT ["/usr/local/bin/agentos-server"]
