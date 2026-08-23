//! A token minted for one effect must not be spendable on another.

use agentos_app::effects::{Effects, PaymentCreate, RenderedEmail};
use agentos_app::gate::Authorized;

async fn not_that_effect(
    effects: &Effects,
    approved_payment: Authorized<PaymentCreate>,
    body: RenderedEmail,
) {
    // The gate ruled on a payment. That ruling is not permission to send mail.
    let _ = effects.send_email(approved_payment, body).await;
}

fn main() {}
