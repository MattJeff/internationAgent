//! No effect accepts a token whose subject is an arbitrary `Action`.
//!
//! `tests/ui/effects_wrong_token.rs` pins one bound by handing `send_email` a
//! payment ruling. This pins *every* bound at once, against the one type that
//! satisfies a bare `A: Subject`: `Untrusted<Action>` is `Authorizable`
//! (`gate.rs`), so the blanket `impl<T> Subject for Untrusted<T>` gives it
//! `Of = Action` — and `Action` is whatever a hostile text talked the model
//! into proposing. Widen any bound below to `A: Subject` and the matching line
//! stops erroring, which is this file's whole job.
//!
//! Written as bare paths rather than calls on purpose: instantiating the fn
//! item checks the bound and nothing else, so the expected error does not move
//! when a body's arguments change.

use agentos_app::effects::{Effects, InvoiceDraft, InvoiceIssue};
use agentos_app::gate::Authorized;
use agentos_domain::action::Action;
use agentos_domain::untrusted::Untrusted;

fn main() {
    let _ = Effects::send_email::<Untrusted<Action>>;
    let _ = Effects::stage_lead::<Untrusted<Action>>;
    let _ = Effects::send_sms::<Untrusted<Action>>;
    let _ = Effects::send_whatsapp::<Untrusted<Action>>;
    let _ = Effects::place_call::<Untrusted<Action>>;
    let _ = Effects::browse_write::<Untrusted<Action>>;
    let _ = Effects::read_page::<Untrusted<Action>>;
    let _ = Effects::discover_prospects::<Untrusted<Action>>;
    let _ = Effects::propose_flow::<Untrusted<Action>>;
    let _ = Effects::call_tool::<Untrusted<Action>>;
    let _ = Effects::pay::<Untrusted<Action>>;
    let _ = Effects::send_internal::<Untrusted<Action>>;
    let _ = Effects::brief::<Untrusted<Action>>;
    let _ = Effects::book_hour::<Untrusted<Action>>;
    let _ = agentos_app::a2a::sign_request::<Untrusted<Action>>;

    // The **trusted** flavour of the same type, which is not a symmetry for
    // tidiness: it is what `sourcing::place_order` declines to return, and what
    // `routes::approvals::approve` still holds for every kind but one. A bare
    // `Action` has no `Subject` impl at all — the `subject!` macro writes one
    // per newtype — so this is `E0277` where the lines above are `E0271`, and
    // that is why link eight destructures `Action::PaymentCreate` into
    // `effects::PaymentCreate` *before* redeeming rather than converting after.
    // There is no `Authorized<Action>` → effect anywhere and there must not be.
    // `x402.rs`, "The bridge from a human approved to the money moved".
    let _ = Effects::pay::<Action>;
}

/// `issue_invoice` is the one effect with no `Of =` to widen: it takes the
/// trusted newtype concretely, so the tainted flavour is what has to be refused
/// here. Spelled as a call because there is no generic to instantiate.
async fn tainted_invoice(
    effects: &Effects,
    ok: Authorized<Untrusted<InvoiceIssue>>,
    draft: &InvoiceDraft,
) {
    let _ = effects.issue_invoice(ok, draft).await;
}
