//! A row of the export with nothing reproduced behind it must not compile.

use agentos_app::queue::{Lead, Recipient};
use agentos_app::revenue::Outreach;

fn a_row_nobody_can_defend() -> Lead {
    let who = Recipient {
        contact_id: uuid::Uuid::nil(),
        email: agentos_domain::action::EmailAddress::parse("info@example.com").expect("address"),
        first_name: String::new(),
        last_name: String::new(),
        company_name: "Example".to_owned(),
        phone_number: String::new(),
        website: String::new(),
        linkedin_profile: String::new(),
        location: String::new(),
    };

    // `queue::plan` is the only thing that builds a `Lead`, and it only builds
    // one out of a `Ready`, which carries an `Approach`, which needs an
    // `Evidence`. Spelling the struct literal is the way round all three, so
    // both fields are private and this is the error.
    Lead {
        who,
        opener: Outreach {
            subject: "your booking flow is wrong".to_owned(),
            body: "trust me".to_owned(),
        },
    }
}

fn main() {
    let _ = a_row_nobody_can_defend();
}
