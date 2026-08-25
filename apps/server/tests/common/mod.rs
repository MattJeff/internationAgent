//! One rule, shared by the three harnesses in this directory that each stand a
//! whole server up on a database of its own.
//!
//! # The bug this exists to stop coming back
//!
//! `scripts/test.sh` creates `ci_<pkg>_<RUN_ID>` per package and drops, on its
//! way out and on the `^C` that is how a suite usually ends, everything
//! matching `ci\_%\_<RUN_ID>` or `ci\_%\_<RUN_ID>\_%`. A database whose name
//! starts with this run's own therefore goes with it, and a database whose name
//! starts with anything else is collected by nothing on the machine, ever.
//!
//! `end_to_end.rs`, `orizn.rs` and `sourcing_e2e.rs` each derived a name as
//! `e2e_`, `orizn_` or `srcg_` plus a UUID, so every interrupted run left a
//! migrated database per server behind. The cluster this was found on had them
//! going back weeks. `apps/server/src/loops/mod.rs` and `crates/store/src/db.rs`
//! always got it right, by starting from `DATABASE_URL`.
//!
//! # Why a module and not a fourth copy
//!
//! Because the copies are what broke. The rule got written three times and was
//! wrong all three times in the same way — which is the argument for one
//! spelling of it, even though it is four lines and even though this directory
//! already duplicates a whole `Server` harness three times over. The harnesses
//! differ from each other on purpose; the naming rule never did.
//!
//! `apps/server/src/main.rs` has the fifth copy and cannot use this one: it is
//! a `#[cfg(test)]` helper inside the binary crate, and an integration test is
//! a different crate. Its doc comment carries the same argument.

use std::sync::atomic::{AtomicU32, Ordering};

/// A private database's name: **this run's own database, then a tag, then who
/// and which**.
///
/// `url` is `DATABASE_URL` verbatim. The caller has already established it is
/// set — every harness here skips loudly when it is not, and
/// `scripts/test.sh`'s second guard turns that skip into a failed run.
///
/// # A pid and a counter, not a UUID
///
/// Uniqueness is required: each `Server::start` in one file takes a database of
/// its own and `cargo test` runs them concurrently. But 32 hex characters no
/// longer fit — Postgres truncates an identifier at 63 bytes *silently*, and
/// `ci_agentosserver_<pid>` plus `_e2e_` plus 32 is over. Created under one
/// name and connected to under another fails in a way that looks nothing like a
/// name that was too long.
///
/// The pid separates the test binaries `cargo test` runs in parallel; the
/// counter separates the servers one binary starts. That is every collision
/// available, in eleven characters rather than thirty-two.
pub fn private_name(url: &str, tag: &str) -> String {
    /// Per process. `Relaxed`: nothing is ordered against it, it only has to
    /// hand out a different integer each time.
    static NTH: AtomicU32 = AtomicU32::new(0);

    // `postgres://user:pass@host:port/name`, or the same with `?options`. Split
    // by hand rather than pull in a URL parser for one path segment —
    // `loops::private_db` says the same thing about the same two lines.
    let (_, tail) = url.rsplit_once('/').expect("DATABASE_URL names a database");
    let base = tail.split_once('?').map_or(tail, |(name, _)| name);
    format!(
        "{base}_{tag}_{}_{}",
        std::process::id(),
        NTH.fetch_add(1, Ordering::Relaxed)
    )
}
