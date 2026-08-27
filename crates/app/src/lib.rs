//! Orchestration. The only crate that may call a provider, and only while
//! holding an `Authorized<A>` — a capability token whose constructor is private
//! to `gate.rs`. That turns "did this code path consult the Policy Gate?" from
//! a code-review obligation into a compile error.

pub mod a2a; // U28
pub mod api_keys; // wave J: step zero — a key a customer can be given and can lose
pub mod catalog; // the connectors we wrote down, so a customer clicks instead of typing
pub mod effects; // U21
pub mod flow_proposal; // the employee proposes a prospect's selectors, a human promotes them
pub mod gate; // U20
pub mod hosted; // running somebody else's stdio server, outside our process tree
pub mod http_signature;
pub mod identity;
pub mod inbound; // U29
pub mod knowledge; // U26
pub mod mcp; // U27
pub mod mocks; // U38 — the fakes the binary cannot build for itself
pub mod model_access; // wave H: the tenant's own model, connected and proven
pub mod oauth; // wave I: a consent page instead of a pasted token
pub mod orizn; // wave 4 — the authoritative half of proof_of_need
pub mod peer_keys;
pub mod pool_ops;
pub mod prompt; // U23
pub mod proof_of_need; // wave 12
pub mod prospects; // the seller's input: the founder's own lists, become rows
pub mod provisioning; // U24
pub mod psyche; // le fil de production de la psyché
pub mod queue; // the seller's output: one producer, two sinks
pub mod revenue; // wave 12
pub mod rolepack;
pub mod rolepack_sales; // wave 12
pub mod rolepack_service; // customer success, growth, finance
pub mod secrets; // U22
pub mod sourcing;
pub mod turn; // U25
pub mod vertical; // le fil du pack de rôle vers une verticale
