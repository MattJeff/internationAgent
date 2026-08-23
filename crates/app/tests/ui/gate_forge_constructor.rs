//! The other four ways in: a constructor, `From`, `Default`, and `serde`.
//! None of them exists, and none of them may be added.

use agentos_app::gate::Authorized;
use agentos_domain::action::{Action, EmailAddress};

fn action() -> Action {
    Action::EmailSend {
        to: EmailAddress::parse("victim@example.com").unwrap(),
    }
}

fn main() {
    // No public constructor.
    let _ = Authorized::new(action());

    // No `From<Action>`: an action is a request, not a permission.
    let _: Authorized<Action> = action().into();

    // No `Default`: there is no such thing as a default authorization.
    let _: Authorized<Action> = Default::default();

    // No `Deserialize`: a capability that can be parsed from JSON is a
    // capability an attacker can post.
    let _: Authorized<Action> = serde_json::from_str("{}").unwrap();
}
