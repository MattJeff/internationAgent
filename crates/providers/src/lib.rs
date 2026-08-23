//! The only crate allowed to hold reqwest / aws-sdk / rmcp clients.
//!
//! Every adapter ships with a mock beside it and a shared contract suite. The
//! contract every adapter must satisfy: `ensure` reconciles before it creates,
//! keyed on an idempotency key stamped into the provider's own tag field, so a
//! crashed-and-retried provisioning run never buys a second phone number.

pub mod browser; // U18
pub mod email; // U16
pub mod embedder; // U19
pub mod llm; // U19
pub mod secrets; // U18
pub mod telephony; // U17
