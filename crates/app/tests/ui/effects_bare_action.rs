//! Sending an email from a bare action must not compile.

use agentos_app::effects::{Effects, EmailSend, RenderedEmail};
use agentos_domain::action::EmailAddress;

async fn no_gate_no_email(effects: &Effects, to: EmailAddress, body: RenderedEmail) {
    // `EmailSend` is the *request*. Only the Policy Gate turns it into an
    // `Authorized<EmailSend>`, and only that is accepted here.
    let _ = effects.send_email(EmailSend { to }, body).await;
}

fn main() {}
