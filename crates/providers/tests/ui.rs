//! Compile-fail tests: things that must stay impossible to write.

#[test]
fn secret_cannot_be_serialized() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
