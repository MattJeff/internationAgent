//! Every `DELETE` in this workspace names what it is allowed to remove.
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
