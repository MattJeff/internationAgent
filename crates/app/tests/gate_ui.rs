//! The unforgeable capability token, proved by the compiler.
//!
//! `Authorized<A>` is the whole point of `crates/app/src/gate.rs`: holding one
//! means the Policy Gate ruled on the action, and there must be no second way
//! to obtain one. An ordinary unit test cannot show that, because the code
//! that would show it does not compile — which is exactly the claim.
//!
//! So each case below is a standalone program that MUST fail to build. If
//! somebody later adds a public constructor, a public field, a `From`, a
//! `Default` or a `Deserialize` to make one stubborn call site "just work",
//! these programs start compiling and this suite goes red. That alarm is the
//! only part of the design that cannot be defeated by forgetting a convention.
//!
//! To re-record the expected errors after a compiler upgrade:
//! `TRYBUILD=overwrite cargo test -p agentos-app --test gate_ui`.

#[test]
fn an_authorization_cannot_be_minted_outside_the_gate() {
    let t = trybuild::TestCases::new();

    // A struct literal: every field is private, and the seal is not nameable.
    t.compile_fail("tests/ui/gate_forge_literal.rs");

    // The constructors somebody would reach for next: `new`, `From`,
    // `Default`, and `serde` — none of which exist, on purpose.
    t.compile_fail("tests/ui/gate_forge_constructor.rs");
}
