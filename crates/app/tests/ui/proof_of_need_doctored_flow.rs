//! The same edit one step earlier, and this is the worse of the two.
//!
//! A doctored `Evidence` is a claim nobody observed. A confirmed `Flow` with a
//! selector assigned onto it afterwards is a *real* observation of the wrong
//! element: both runs read it, both agree, and the reproducibility bar passes a
//! screenshotted finding about a cookie banner out to a stranger. Nothing
//! downstream can tell that from the real thing.
//!
//! The seal records that a named human opened the page. It does not record
//! *which selectors* they checked, so it survives having them replaced —
//! which is why the fields have to be unreachable rather than merely
//! unspellable at construction.

use agentos_app::proof_of_need::Flow;

fn guess_selectors(confirmed: &Flow) -> Flow {
    let mut guessed = confirmed.clone();
    guessed.panel = "body".to_owned();
    guessed.submit = Some("#book-now".to_owned());
    guessed
}

fn main() {
    let _ = guess_selectors;
}
