//! The only crate that speaks SQL. Every connection is handed out through
//! `Db::tenant_tx`, which sets `app.tenant_id` so row-level security applies;
//! the raw pool is never exported.

pub mod a2a; // U28
pub mod approvals; // U13
pub mod audit; // U11
pub mod db; // U6
pub mod employee; // U7
pub mod idempotency; // U10
pub mod knowledge; // U14
pub mod outbox; // U9
pub mod phone_pool;
pub mod policy; // U41
pub mod provisioning; // U8
pub mod psyche;
pub mod sourcing;
pub mod spend; // U12
