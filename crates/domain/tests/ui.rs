//! The trust boundary, proved by the compiler.
//!
//! `crates/domain/src/untrusted.rs` claims that hostile text cannot reach a
//! prompt by accident. An ordinary unit test cannot demonstrate that, because
//! the code that would demonstrate it does not compile — which is the point.
//! So these cases live in `tests/ui/*.rs`, are compiled by `trybuild` as
//! standalone programs, and each one must FAIL with the error recorded in the
//! matching `tests/ui/*.stderr`.
//!
//! If someone later adds `impl Display for Untrusted<T>`, or an `Add`, or a
//! `Deref`, to make one stubborn call site "just work", these programs start
//! compiling and this suite goes red. That is the alarm, and it is the only
//! part of the design that cannot be defeated by forgetting a convention.
//!
//! To re-record the expected errors after a compiler upgrade:
//! `TRYBUILD=overwrite cargo test -p agentos-domain --test ui`.

#[test]
fn untrusted_content_cannot_reach_a_prompt() {
    let t = trybuild::TestCases::new();

    // `format!("{}", untrusted)` and `.to_string()` — no `Display` impl.
    t.compile_fail("tests/ui/display_untrusted.rs");

    // `system_prompt + untrusted` — no `Add`, no `Deref`, no `AsRef<str>`.
    t.compile_fail("tests/ui/concat_into_system_prompt.rs");
}
