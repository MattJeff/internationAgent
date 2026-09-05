pub mod a2a; // U34
pub mod approvals;
pub mod autonomy;
// wave M: what we may charge for — seats and connectors, by the day, derived
// from the trail. The counter, deliberately not the collection.
pub mod billing;
// le calendrier: the founder promises a moment and sees what has been promised.
// The employee's half is `agentos_app::calendar` and `loops::initiative`.
pub mod calendar;
pub mod companies; // a whole company, standing, from one call
// le fil: the person reads what landed on a seat's desk and writes back from it.
// No table and no port — `0028`'s internal channel already is the thread; see
// `agentos_app::inbound`'s desk section and `migrations/0065`.
pub mod desk;
pub mod employees; // U31
// le classeur: the founder files a document and gets those exact bytes back.
// `knowledge` next door indexes in order to find again; this one keeps.
pub mod files;
// wave K: the founder picks a window and gets a quote — effort and money, never
// a chance of success. Beside `usage` and `turns` in spirit: those two report
// what already happened, this one is the same arithmetic pointed forwards.
pub mod forecast;
pub mod halt; // wave J: stop the whole company, and let it go again
pub mod initiative;
pub mod interview; // the guided conversation that finishes a company
pub mod inventory;
// la facturation: the founder reads what the company is owed and says when it
// arrived. The employee's half is `agentos_app::effects::issue_invoice` — and
// there is deliberately no operator way to *issue* one; see the module docs.
pub mod invoices;
pub mod knowledge;
pub mod mcp;
pub mod model; // wave H: the tenant connects the model their employees think with
// the one route that changes a limit. `POST /v1/companies` creates a role layer
// where none exists; this one replaces one, and can only tighten — see its
// module docs for the invariant and the three mechanisms that hold it.
pub mod platform; // wave J: step zero — a tenant signs up and gets a key that can be revoked
pub mod policy;
pub mod pool;
// le registre public: la preuve qu'on a et qu'un concurrent sans gate ne peut
// pas copier — ce que la gate a refusé, agrégé, sur consentement explicite. Sa
// lecture est montée hors de toute clé; sa bascule est un acte de locataire.
pub mod public_register;
pub mod queue; // the file the founder uploads, and the only caller of `app::queue`
pub mod refusals; // ce que la gate a refusé, lu dans le journal
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
