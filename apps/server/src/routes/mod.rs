pub mod a2a; // U34
pub mod approvals;
pub mod autonomy;
pub mod companies; // a whole company, standing, from one call
pub mod employees; // U31
// wave K: the founder picks a window and gets a quote — effort and money, never
// a chance of success. Beside `usage` and `turns` in spirit: those two report
// what already happened, this one is the same arithmetic pointed forwards.
pub mod forecast;
pub mod halt; // wave J: stop the whole company, and let it go again
pub mod initiative;
pub mod inventory;
pub mod knowledge;
pub mod mcp;
pub mod model; // wave H: the tenant connects the model their employees think with
pub mod platform; // wave J: step zero — a tenant signs up and gets a key that can be revoked
pub mod pool;
pub mod queue; // the file the founder uploads, and the only caller of `app::queue`
pub mod reports; // the manager's view of its own line
pub mod spend;
pub mod teams;
pub mod turns; // the daily turn budget, read-side
pub mod usage;
pub mod webhooks; // U33
pub mod well_known;
