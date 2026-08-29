//! And the way round *that*: not writing a finding out, but editing a real one.
//!
//! The struct literal was never the cheap forgery. This is: take the `Evidence`
//! `Prober::check` handed you about one prospect — seal and all, two runs that
//! genuinely agreed — and assign new fields onto it. The seal is a fact about
//! the value's *history*, so it survives every edit, and `Approach::new` would
//! render the doctored claim without noticing. It needs no `Evidence` in hand to
//! typecheck, which is the point: a `&Evidence` is enough.

use agentos_app::proof_of_need::{Claim, Evidence, Finding};

fn doctor(real: &Evidence) -> Evidence {
    let mut forged = real.clone();
    forged.prospect = "Someone Else Entirely".to_owned();
    forged.finding = Finding::Contradicts {
        shown: Claim::NoVisa,
        correct: Claim::VisaRequired,
    };
    forged.steps = vec!["1. take our word for it".to_owned()];
    forged.screenshot = Vec::new();
    forged
}

fn main() {
    let _ = doctor;
}
