//! And one step earlier: writing the selectors out by hand.
//!
//! A guessed selector is not a broken one. It resolves, it resolves to the same
//! wrong element on both runs, and the reproducibility bar passes a
//! screenshotted claim about a cookie banner out to a stranger. Nothing
//! downstream can catch that, so the only fact a `Flow` may rest on is that a
//! named human opened the page — and the only constructor that can record one is
//! `Flow::confirmed`.

use agentos_app::proof_of_need::Flow;
use agentos_domain::action::Domain;
use url::Url;

fn guessed_selectors() -> Flow {
    // `Flow` is readable through accessors and impossible to build: one of its
    // fields is a private zero-sized seal that only `Flow::confirmed` can mint,
    // from a stored row with `confirmed_by` on it. See
    // `proof_of_need_doctored_flow.rs` for the version that edits a confirmed
    // one instead.
    Flow {
        prospect: "Airline Example".to_owned(),
        domain: Domain::parse("book.airline.example").unwrap(),
        entry: Url::parse("https://book.airline.example/entry").unwrap(),
        // Plausible. Nobody has looked.
        passport_field: "#passport".to_owned(),
        destination_field: "#destination".to_owned(),
        date_field: None,
        submit: None,
        panel: "#visa-info".to_owned(),
    }
}

fn main() {
    let _ = guessed_selectors();
}
