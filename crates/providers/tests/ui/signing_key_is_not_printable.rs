//! A private signing key must not be serializable, printable as text, or
//! copyable out of the one type that owns it.
//!
//! `ed25519_dalek::SigningKey` is all three; `SigningKey` wraps it precisely so
//! that it is none of them. If this program ever compiles, an employee's
//! private key has become one `#[derive]` away from a log line.

use agentos_providers::signing::SigningKey;

#[derive(serde::Serialize)]
struct PublishedIdentity {
    key: SigningKey,
}

fn leak(key: &SigningKey) -> String {
    // No `Display`: a key cannot be interpolated into a string.
    format!("{key}")
}

fn steal(key: &SigningKey) -> SigningKey {
    // No `Clone`: there is one copy, and it drops (and zeroizes) where it was
    // opened.
    key.clone()
}

fn main() {
    let _ = leak;
    let _ = steal;
}
