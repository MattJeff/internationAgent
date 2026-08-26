//! The evidence bar reaching the export, proved by the compiler.
//!
//! `tests/vertical_ui.rs` says an unevidenced *email* does not compile. This
//! says the same about the file the founder uploads and the API call that
//! replaces it in September, which is the same claim about a different sink and
//! therefore needs its own check: `queue::Lead` is what both of them read, and a
//! public field or a `pub fn new` on it would put a row nobody reproduced into
//! the founder's Smartlead account without anything in `vertical.rs` changing.
//!
//! To re-record the expected error after a compiler upgrade:
//! `TRYBUILD=overwrite cargo test -p agentos-app --test queue_ui`.

#[test]
fn a_row_cannot_be_exported_without_a_reproduced_finding() {
    trybuild::TestCases::new().compile_fail("tests/ui/queue_lead_without_evidence.rs");
}
