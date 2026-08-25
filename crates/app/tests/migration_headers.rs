//! Every migration's first line names the file it is in.
//!
//! # The bug this exists to stop coming back
//!
//! Migration files get renumbered. Two units developed in parallel both claim
//! `0025`, one of them is renamed on the way in, and the header — which opens
//! `-- 0025_positions: what a team is for` and is the first thing anyone reads
//! — keeps announcing the number the file no longer has. Ten files in this
//! workspace drifted that way before anybody counted, and two Rust modules
//! pointed at a `migrations/0023_model_usage.sql` that has never existed.
//!
//! Nothing breaks. That is the problem: a header is load-bearing exactly when
//! somebody is lost, and being lost is when a wrong signpost costs the most.
//! A migration is also the one kind of file whose *name* is its identity —
//! `sqlx` keys `_sqlx_migrations` on the version prefix — so a header and a
//! filename that disagree are two different claims about which migration this
//! is.
//!
//! A pass was already done by hand once and missed nine of the ten, which is
//! the argument for a test rather than a second pass: this costs a directory
//! walk and no database, and it cannot be half-done.
//!
//! # What counts as naming the file
//!
//! The first line is `-- <stem>` followed by anything: a colon and a sentence,
//! a dash, or nothing. `<stem>` is the filename without `.sql`, verbatim. The
//! prose after it is the author's and this test has no opinion about it.

use std::fs;
use std::path::Path;

#[test]
fn every_migration_header_names_its_own_file() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above this crate")
        .join("migrations");

    let mut checked = 0usize;
    let mut wrong = Vec::new();

    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    entries.sort();

    for path in entries {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a .sql file has a UTF-8 stem")
            .to_owned();
        let body = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {stem}: {err}"));
        let first = body.lines().next().unwrap_or_default();
        checked += 1;

        // `-- <stem>` and then anything, or nothing. The delimiter after the
        // stem must not be a word character, or `0002_tenants` would be
        // accepted by a file called `0002_tenants_and_keys.sql`.
        let named = first.strip_prefix("-- ").is_some_and(|rest| {
            rest.strip_prefix(stem.as_str())
                .is_some_and(|tail| !tail.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
        });
        if !named {
            wrong.push(format!("{stem}.sql opens with {first:?}"));
        }
    }

    // A directory walk that finds nothing passes, and would keep passing after
    // somebody moves `migrations/`. The count is the guard against that, and
    // the number is deliberately a floor rather than an equality: adding a
    // migration must not turn this test red for the wrong reason.
    assert!(
        checked >= 25,
        "only {checked} migrations found in {} — this test walked the wrong directory",
        dir.display()
    );

    assert!(
        wrong.is_empty(),
        "a migration's first line must name its own file, because that line is \
         what somebody reads when they are lost:\n  {}",
        wrong.join("\n  ")
    );
}
