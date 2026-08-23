//! The model may know it *has* a credential. It may never see the value.
//!
//! `SafeForPrompt` is implemented for `SecretRef` and deliberately not for
//! `Secret`, so every spelling of "just put the key in the prompt" is a
//! compile error.

use agentos_app::prompt::{SafeForPrompt, SystemPrompt};
use agentos_providers::Secret;

fn main() {
    let key = Secret::new("sk-live-do-not-print-me");

    // The builder only accepts things that are safe for a context window.
    let _ = SystemPrompt::new("You are Lena.").with_credential(&key);

    // Nor is the trait method reachable on its own.
    let _ = key.render_for_prompt();
}
