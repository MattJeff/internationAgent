//! Every `DELETE` in this workspace names what it is allowed to remove, and the
//! one row no `DELETE` can name is written from a database of its own.
//!
//! Two tests, one subject: **a test may not touch rows it was not told about.**
//! [`no_delete_reaches_a_whole_table`] is the case where the statement forgot to
//! say which rows; [`the_global_policy_row_is_only_touched_from_a_private_database`]
//! is the case where there is no way for it to say, because the row belongs to
//! no tenant. Both cost a directory walk and no database.
//!
//! # The bug this exists to stop coming back
//!
//! Two test helpers — `agentos_app::provisioning`'s `reset` and the
//! provisioning loop's — ran `DELETE FROM tenants` on an
//! `admin_tx_bypassing_rls` connection. Not this test's tenant: *every* tenant.
//! Under `cargo test` at its default parallelism that deleted the rows of
//! whatever tests happened to be running beside them, and the bill was two to
//! six failures per run, **in a different set each time**, in tests with
//! nothing to do with provisioning. It cost a day of chasing before anybody
//! looked at the `DELETE`, because the failures never pointed at it. Two more
//! helpers did the same thing to `outbox_events`.
//!
//! A comment saying "do not do this again" would not survive the next person in
//! a hurry, so this is a test instead. It costs a directory walk and no
//! database.
//!
//! # What counts as scoped
//!
//! A `WHERE`, anywhere in the same string literal. That is a deliberately low
//! bar: the point is not to prove the predicate is *right*, it is to make
//! writing a statement with no predicate at all something you cannot do by
//! accident. `WHERE tenant_id IS NULL` — the platform policy layer — passes,
//! and it should: it names one row, and `routes::turns` guards it with a lock
//! instead. `TRUNCATE` takes no predicate at all, so it is banned outright.
//!
//! Only `DELETE` is checked. `UPDATE` without a `WHERE` is the same hazard, but
//! `ON CONFLICT ... DO UPDATE SET` and `FOR UPDATE SKIP LOCKED` are neither,
//! and a check that cries wolf about thirty of those is a check somebody
//! deletes.
//!
//! # If this fails on a statement that is genuinely fine
//!
//! Then it is not fine. Scope it, or give the test that needs an empty database
//! a database of its own — `apps/server/src/loops/mod.rs`'s `private_db` and
//! `apps/server/tests/end_to_end.rs` both do that, in about twenty lines. There
//! is deliberately no way to suppress this from the offending line.

use std::path::{Path, PathBuf};

#[test]
fn no_delete_reaches_a_whole_table() {
    let root = workspace_root();
    let mut offences = Vec::new();

    for file in rust_files(&root) {
        let source = std::fs::read_to_string(&file).expect("read a source file");
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();

        for (line, statement) in statements(&source) {
            let upper = statement.to_uppercase();
            let why = if upper.contains("TRUNCATE ") {
                "TRUNCATE takes no predicate"
            } else if !upper.contains("WHERE") {
                "no WHERE"
            } else {
                continue;
            };
            offences.push(format!("{shown}:{line}: {why}: {statement}"));
        }
    }

    assert!(
        offences.is_empty(),
        "these statements can remove rows they were not told about:\n  {}\n\n\
         A test that empties a table empties it for every test running beside \
         it — see this file's docs for what to do instead.",
        offences.join("\n  ")
    );
}

/// **The platform policy row is the one row in this schema that no tenant
/// filter can reach, so a test that touches it takes a database.**
///
/// # The bug this exists to stop coming back
///
/// Ask the schema which rows are not reachable by `WHERE tenant_id = $1`:
///
/// ```sql
/// SELECT table_name FROM information_schema.columns
///  WHERE column_name = 'tenant_id' AND is_nullable = 'YES';
/// ```
///
/// Out of every table in this schema the answer is two — `policy_versions` and
/// `policy_layers`, the platform ceiling, `tenant_id IS NULL`, one row for the
/// whole database. (The query also returns the views; `information_schema`
/// calls every view column nullable.) Every other collision in this workspace is a
/// name two tests both chose. This one is a row they cannot help but share.
///
/// `store::policy`'s tests are about that row, and until they took a database of
/// their own they wrote it into the suite's, which cost three failures under a
/// plain `cargo test --workspace` — all of them red for reasons that had nothing
/// to do with the code under test:
///
/// - `agentos-app` first: five ceiling tests died on `install_ceiling`'s
///   currency guard, because app's fixtures leave EUR tenant layers behind and
///   the guard reads the whole database. A sixth went **green off somebody
///   else's EUR layer** — a test proving nothing is the expensive kind.
/// - `agentos-store` first: 103 of `agentos-app`'s 350 tests, and 41 of
///   `agentos-server`'s, died on `policy::install` refusing to run its fixture
///   DELETE over the operator ceiling the store's tests deliberately leave up.
///
/// Every one of those guards is right. What was missing was the isolation, and
/// `scripts/test.sh` hid it by giving each package a database — so the only
/// people who ever saw it were the ones running the obvious command.
///
/// # What counts as touching it
///
/// A call to `install_ceiling`, `rollback_ceiling` or `policy::tests::platform`,
/// or a statement naming `policy_versions`/`policy_layers` alongside
/// `tenant_id IS NULL`. Reads count as well as writes, deliberately: a test that
/// *asserts* on the global row on a shared database is asserting on a row any
/// other test may have replaced a millisecond earlier.
///
/// Production code is not checked — `agentos-server policy install` exists to
/// write that row, and an operator's ceiling is the product, not a fixture.
/// Only what follows the first `#[cfg(test)]` in a `src/` file is test code;
/// everything in a `tests/` directory is.
///
/// # What counts as a database of its own
///
/// The file mentions one: `private_db`, `own_database`, or a literal
/// `CREATE DATABASE`. That is a deliberately low bar, the same one
/// [`no_delete_reaches_a_whole_table`] sets by accepting any `WHERE` — the point
/// is not to prove the handle is private, it is to make writing the global row
/// out of the shared pool something you cannot do without noticing. The
/// workspace already hands them out from four places — `crates/store/src/db.rs`
/// and `apps/server/src/loops/mod.rs` (`private_db`), `crates/app/src/gate.rs`,
/// `apps/server/src/main.rs` (`own_database`) — plus
/// `apps/server/tests/common/mod.rs`, which the three server harnesses share
/// for the *name*. The next one is twenty lines, and the name has to come from
/// `DATABASE_URL` or `scripts/test.sh` will never collect it.
///
/// # If this fails on something that is genuinely fine
///
/// Then it is not fine — or it belongs in production code rather than a test.
/// There is deliberately no way to suppress this from the offending line.
#[test]
fn the_global_policy_row_is_only_touched_from_a_private_database() {
    let root = workspace_root();
    let mut offences = Vec::new();

    for file in rust_files(&root) {
        let source = std::fs::read_to_string(&file).expect("read a source file");
        // In code, not in prose. This test was written the other way first and
        // it did not catch its own regression: reverting `store::policy`'s
        // tests to the shared pool left the words `crate::db::private_db`
        // behind in the doc comment that explains why they must not be, and the
        // file went on being exempt. A guard a comment can satisfy is a comment.
        if code_lines(&source).iter().any(|line| {
            line.contains("private_db")
                || line.contains("own_database")
                || line.contains("CREATE DATABASE")
        }) {
            continue;
        }
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();
        // An integration test is test code from its first line; a `src/` file
        // only becomes one at `#[cfg(test)]` — the attribute, at the start of a
        // line of code. Matching it anywhere would find the three doc comments
        // in `store::policy` that discuss it, and put the boundary hundreds of
        // lines early: `policy::install`'s own production DELETE would be
        // reported as a test writing the row.
        let Some(first_test_line) = (if file.components().any(|c| c.as_os_str() == "tests") {
            Some(0)
        } else {
            source
                .lines()
                .position(|l| l.trim_start().starts_with("#[cfg(test)]"))
        }) else {
            continue;
        };

        for (line, touch) in global_policy_touches(&source, first_test_line) {
            offences.push(format!("{shown}:{line}: {touch}"));
        }
    }

    assert!(
        offences.is_empty(),
        "these tests touch the platform policy row — `tenant_id IS NULL`, one row \
         for the whole database — from a database other tests are using:\n  {}\n\n\
         Give them one of their own; `crates/store/src/db.rs`'s `private_db` is \
         twenty lines and this file's docs explain what it costs not to.",
        offences.join("\n  ")
    );
}

/// `source` with its comment lines removed, so a check cannot be satisfied by
/// prose about the thing it is checking for.
fn code_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect()
}

/// Every line of test code in `source` that reaches the platform policy row.
///
/// The unit is a small window rather than a line, because SQL literals here are
/// split with `\` continuations and `DELETE FROM policy_versions` can sit two
/// lines above its `WHERE tenant_id IS NULL`. Three lines is enough for every
/// one in the workspace and short enough that an unrelated comment below cannot
/// wander into the match.
fn global_policy_touches(source: &str, from_line: usize) -> Vec<(usize, String)> {
    const WINDOW: usize = 3;
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();

    for i in from_line..lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        // Comments are skipped, or this file's own prose would be the first
        // offender — and so would every doc comment naming these functions.
        if trimmed.starts_with("//") {
            continue;
        }
        // There is no "but that line is only a function signature" exemption.
        // There was, and it put a hole in this exactly the width of
        // `async fn ceiling(db: &Db) { …platform(db, …).await; }` on one line.
        // The definitions of these functions are production code and stop above
        // `#[cfg(test)]` on their own.

        let why = if line.contains("install_ceiling(") {
            "installs an operator ceiling"
        } else if line.contains("rollback_ceiling(") {
            "rolls the operator ceiling back"
        } else if line.contains("tests::platform(") {
            "replaces the platform layer"
        } else if line.contains("policy_versions") || line.contains("policy_layers") {
            let window = lines[i..lines.len().min(i + WINDOW)].join(" ");
            if window.to_uppercase().contains("TENANT_ID IS NULL") {
                "names the platform row directly"
            } else {
                continue;
            }
        } else {
            continue;
        };
        found.push((i + 1, format!("{why}: {}", trimmed.trim_end())));
    }

    found
}

/// How many lines a single SQL literal may span before we stop looking for its
/// closing quote. Generous; the longest `DELETE` in the workspace is two.
const MAX_LITERAL_LINES: usize = 10;

/// Every `DELETE`/`TRUNCATE` string literal in `source`, with its line number.
///
/// SQL lives in ordinary Rust string literals here and long ones are split with
/// `\` line continuations, so the unit is the *literal*, not the line:
/// `"DELETE FROM tenants \` and the `WHERE` on the line below are one statement
/// and have to be judged as one. Lines are joined from the verb until the one
/// that closes the literal.
///
/// Comments are skipped, or this file's own prose would be the first offender.
fn statements(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let upper = line.to_uppercase();
        let Some(start) = upper
            .find("DELETE FROM")
            .or_else(|| upper.find("TRUNCATE "))
        else {
            continue;
        };

        let mut text = line[start..].trim().to_owned();
        let mut next = i + 1;
        while !text.contains('"') && next < lines.len() && next - i < MAX_LITERAL_LINES {
            text.push(' ');
            text.push_str(lines[next].trim());
            next += 1;
        }
        found.push((i + 1, text));
    }

    found
}

/// Every `.rs` file in the workspace, this one and `target/` excluded.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates"), root.join("apps")];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && path != Path::new(file!())
                && !path.ends_with("scoped_deletes.rs")
            {
                out.push(path);
            }
        }
    }

    assert!(
        out.len() > 20,
        "found only {} source files under {}; the walk is wrong, not the workspace",
        out.len(),
        root.display()
    );
    out
}

/// `crates/app` is two levels below the workspace root.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/app is two levels down")
        .to_path_buf()
}
