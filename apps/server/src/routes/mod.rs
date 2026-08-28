pub mod a2a; // U34
pub mod approvals;
pub mod autonomy;
// wave M: what we may charge for — seats and connectors, by the day, derived
// from the trail. The counter, deliberately not the collection.
pub mod billing;
pub mod companies; // a whole company, standing, from one call
pub mod employees; // U31
// wave K: the founder picks a window and gets a quote — effort and money, never
// a chance of success. Beside `usage` and `turns` in spirit: those two report
// what already happened, this one is the same arithmetic pointed forwards.
pub mod forecast;
pub mod halt; // wave J: stop the whole company, and let it go again
pub mod initiative;
pub mod interview; // the guided conversation that finishes a company
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
// le carnet: the founder writes work down, ranks it, and gives it to a seat.
// The employee's half is `agentos_app::backlog` and `loops::initiative`.
pub mod work;
