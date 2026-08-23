//! A credential in a prompt, proved impossible by the compiler.
//!
//! `SafeForPrompt` is implemented for `SecretRef` and for nothing that holds a
//! plaintext. That is the whole rule, and it is worth a compile-fail test
//! rather than a unit test because the failure mode it prevents — someone
//! writing the one line that puts an API key in a context window — is a line
//! that must not build, not a line that must be caught in review.
//!
//! To re-record the expected errors after a compiler upgrade:
//! `TRYBUILD=overwrite cargo test -p agentos-app --test prompt_ui`.

#[test]
fn a_secret_cannot_be_rendered_into_a_prompt() {
    trybuild::TestCases::new().compile_fail("tests/ui/prompt_secret_in_prompt.rs");
}
