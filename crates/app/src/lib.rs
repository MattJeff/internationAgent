//! Orchestration. The only crate that may call a provider, and only while
//! holding an `Authorized<A>` — a capability token whose constructor is private
//! to `gate.rs`. That turns "did this code path consult the Policy Gate?" from
//! a code-review obligation into a compile error.

pub mod a2a; // U28
pub mod effects; // U21
pub mod gate; // U20
pub mod inbound; // U29
pub mod knowledge; // U26
pub mod mcp; // U27
pub mod mocks; // U38 — the fakes the binary cannot build for itself
pub mod prompt; // U23
pub mod provisioning; // U24
pub mod rolepack;
pub mod secrets; // U22
pub mod sourcing;
pub mod turn; // U25
