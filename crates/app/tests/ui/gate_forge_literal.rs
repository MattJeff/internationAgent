//! Forging an `Authorized` with a struct literal must not compile.

use agentos_app::gate::Authorized;
use agentos_domain::action::{Action, EmailAddress};
use agentos_domain::ids::DecisionId;
use chrono::Utc;

fn main() {
    let action = Action::EmailSend {
        to: EmailAddress::parse("victim@example.com").unwrap(),
    };

    // Every field is private, and the seal — which has no spelling outside
    // `gate.rs` — cannot be supplied at all.
    let forged = Authorized {
        action,
        decision_id: DecisionId::new_v7(Utc::now()),
        reservation: None,
    };

    let _ = forged.into_action();
}
