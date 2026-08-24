//! The evidence bar, proved by the compiler.
//!
//! `crates/app/src/proof_of_need.rs` runs a prospect's own booking flow twice
//! and yields nothing when the two runs disagree. That suppression is the whole
//! design — an unreproduced claim about another company's product is a false
//! statement about their product — and a runtime check for it is a check a busy
//! turn can be refactored past.
//!
//! So on the vertical path it is a type. `vertical::Approach` is the only
//! message `vertical::sell` will send, its only constructor takes an
//! `&Evidence`, and `Evidence` carries a private zero-sized seal that only
//! `Prober::check` can mint. Neither program below compiles, which is the
//! claim: if somebody later adds a public constructor, a public field, a
//! `From`, a `Default` or a `Deserialize` to make one stubborn call site "just
//! work", they start compiling and this suite goes red.
//!
//! To re-record the expected errors after a compiler upgrade:
//! `TRYBUILD=overwrite cargo test -p agentos-app --test vertical_ui`.

#[test]
fn a_prospect_cannot_be_approached_without_a_reproduced_finding() {
    let t = trybuild::TestCases::new();

    // Wrapping a hand-written message: the field is private.
    t.compile_fail("tests/ui/vertical_approach_without_evidence.rs");

    // And the way round that: writing the finding out by hand. The seal has no
    // name outside `proof_of_need`.
    t.compile_fail("tests/ui/vertical_forged_evidence.rs");
}
