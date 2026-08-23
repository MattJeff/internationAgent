//! No side effect without a capability token, proved by the compiler.
//!
//! `crates/app/src/effects.rs` is the only code that calls a provider, and
//! every one of its methods takes an `Authorized<_>`. The claim worth testing
//! is the negative one: there is no way to send an email — or pay anybody —
//! from a bare action, and a token minted for one effect cannot be spent on
//! another. Neither program below compiles, which is the whole point; if
//! somebody later adds a convenience overload that takes an action, they start
//! compiling and this suite goes red.
//!
//! To re-record the expected errors after a compiler upgrade:
//! `TRYBUILD=overwrite cargo test -p agentos-app --test effects_ui`.

#[test]
fn an_effect_cannot_be_performed_without_a_token() {
    let t = trybuild::TestCases::new();

    // The one that matters: a bare `EmailSend` where a token is required.
    t.compile_fail("tests/ui/effects_bare_action.rs");

    // And the near miss: a real token, for a different effect.
    t.compile_fail("tests/ui/effects_wrong_token.rs");
}
