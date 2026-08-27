//! Pure domain: types, the employee state machine, and the Policy Gate evaluator.
//!
//! This crate performs no I/O. It has no tokio, sqlx, reqwest or async-trait
//! dependency, and that absence is the enforcement mechanism: a business rule
//! physically cannot reach the network or the database from here.
//!
//! Module owners are fixed so that units can be built in parallel without two
//! of them editing the same file.

pub mod action; // U5
pub mod employee; // U3
pub mod identity;
pub mod ids; // U1
pub mod initiative;
pub mod message; // U4
pub mod model_access; // wave H: the tenant's own model, connected and proven
pub mod money; // U2
pub mod org; // wave 13: teams and sections
pub mod phone_pool;
pub mod policy; // U5
pub mod psyche; // wave 8: ported MPCP subset
pub mod revenue; // wave 12: seller vertical
pub mod sourcing;
pub mod untrusted; // U4 // wave 7: buyer vertical
