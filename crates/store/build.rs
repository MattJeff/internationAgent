//! One line, and it exists because `sqlx::migrate!` cannot see a file that was
//! not there when it last ran.
//!
//! # The bug this exists to stop coming back
//!
//! `migrate!` expands to one `include_str!` per migration it finds, and
//! `include_str!` is what makes cargo watch a file. So *editing* a migration
//! rebuilds `Db::migrate`'s migrator, and *adding* one does not: the new file
//! is referenced by no `include_str!` anywhere, the directory is referenced by
//! nothing at all, and cargo has no reason to re-expand the macro. The binary
//! goes on shipping the migrator it built yesterday.
//!
//! What that costs is not a build error. The next `cargo test` runs the old set
//! against a database that never gets the new table or the new column, and the
//! failure surfaces hundreds of lines away as a `CHECK` violation, a missing
//! relation, or a row count that is one short — none of which mentions
//! migrations. It is a `touch crates/store/src/db.rs` away from working, which
//! is exactly the sort of thing that is only ever in one person's head.
//!
//! sqlx knows: `expand_with_path` calls `proc_macro::tracked::path` on the
//! directory, behind `#[cfg(any(sqlx_macros_unstable, procmacro2_semver_exempt))]`.
//! Both are nightly. This is the stable spelling of the same line.
//!
//! # Why here and not in `apps/server` too
//!
//! `doctor.rs` embeds a second migrator with the same macro, and it is covered
//! anyway: a build script that re-runs makes cargo rebuild this crate, and
//! `agentos-server` depends on it, so its own `migrate!` re-expands behind it.
//! One build script for the whole workspace, at the crate the migrations belong
//! to.
//!
//! # What it costs, and why that is worth paying
//!
//! A build script is a compilation unit that did not exist and a graph edge
//! that will never go away — the standard argument against one, and it is a
//! real argument. It is outweighed here by the shape of the failure rather than
//! its frequency: adding a migration is rare, and *every single person* who
//! does it hits this once, having first spent an afternoon on a `CHECK`
//! violation that points nowhere near the cause. Four lines to make a whole
//! class of debugging session not exist.

fn main() {
    // Relative to this package's root, and deliberately the directory rather
    // than a glob over it: a glob evaluated here is the same snapshot
    // `include_str!` already took, so it would miss the new file for the same
    // reason. Cargo walks the directory itself and notices the arrival.
    println!("cargo::rerun-if-changed=../../migrations");
}
