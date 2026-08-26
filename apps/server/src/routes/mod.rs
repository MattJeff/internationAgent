pub mod a2a; // U34
pub mod approvals;
pub mod autonomy;
pub mod employees; // U31
pub mod initiative;
pub mod inventory;
pub mod knowledge;
pub mod mcp;
pub mod pool;
pub mod queue; // the file the founder uploads, and the only caller of `app::queue`
pub mod reports; // the manager's view of its own line
pub mod spend;
pub mod teams;
pub mod turns; // the daily turn budget, read-side
pub mod usage;
pub mod webhooks; // U33
pub mod well_known;
