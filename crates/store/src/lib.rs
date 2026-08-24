//! The only crate that speaks SQL. Every connection is handed out through
//! `Db::tenant_tx`, which sets `app.tenant_id` so row-level security applies;
//! the raw pool is never exported.

pub mod a2a; // U28
pub mod approvals; // U13
pub mod audit; // U11
pub mod db; // U6
pub mod employee; // U7
pub mod idempotency; // U10
pub mod initiative;
pub mod knowledge; // U14
pub mod model_usage; // le grand livre des jetons
pub mod org; // wave 13: teams and sections
pub mod outbox; // U9
pub mod phone_pool;
pub mod policy; // U41
pub mod provisioning; // U8
pub mod psyche;
pub mod revenue; // wave 12: seller vertical
pub mod signing;
pub mod sourcing;
pub mod spend; // U12
pub mod turns; // le budget de tours quotidien
