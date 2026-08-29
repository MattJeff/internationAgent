//! And the way round *that*: writing the finding out by hand.

use agentos_app::proof_of_need::{Answer, Claim, Evidence, Finding, Probe, RuleAge};
use agentos_app::rolepack::CountryCode;
use agentos_app::vertical::Approach;
use agentos_domain::action::Domain;
use agentos_domain::untrusted::Untrusted;
use chrono::{NaiveDate, Utc};
use url::Url;

fn invented_finding() -> Approach {
    // `Evidence` is readable through accessors and impossible to build: one of
    // its fields is a private zero-sized seal that only `Prober::check` can
    // mint, after two agreeing runs, and none of the rest can be named from
    // out here either. See `vertical_doctored_evidence.rs` for the forgery that
    // needs no literal at all.
    let evidence = Evidence {
        prospect: "Airline Example".to_owned(),
        domain: Domain::parse("book.airline.example").unwrap(),
        entry: Url::parse("https://book.airline.example/entry").unwrap(),
        probe: Probe {
            passport: CountryCode::parse("FR").unwrap(),
            destination: CountryCode::parse("VN").unwrap(),
            travel_date: NaiveDate::from_ymd_opt(2026, 8, 24).unwrap(),
        },
        finding: Finding::SaysNothing,
        observed: Untrusted::new(String::new()),
        authority: Some(Answer {
            requirement: Claim::VisaRequired,
            stay_days: None,
            source: "made up".to_owned(),
            retrieved_at: Utc::now(),
            effective_from: None,
        }),
        rule_age: RuleAge::Unknown,
        observed_at: Utc::now(),
        steps: Vec::new(),
        screenshot: Vec::new(),
    };
    Approach::new(&evidence, "Reply STOP.").expect("sendable")
}

fn main() {
    let _ = invented_finding();
}
