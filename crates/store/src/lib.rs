//! The schema, the migrations, and `TenantTx` — through which every connection
//! is handed out, setting `app.tenant_id` so row-level security applies before
//! the caller gets it. The raw pool is never exported, and the two ways past it
//! are named to be greppable: `Db::admin_tx_bypassing_rls`, and
//! `agentos-server`'s `doctor`, which needs a pool before there is a `Db`.
//!
//! **Not the only crate that speaks SQL**, which is what this header claimed
//! for a long time. `agentos-app` and `agentos-server` both run `sqlx::query*`
//! in production, in around thirty files between them — nearly all of it
//! against a `TenantTx` this crate opened. `README.md` retracted the sentence
//! and this header went on making it.

pub mod a2a; // U28
pub mod api_keys; // wave J: a keyring that outlives the deployment that made it
pub mod approvals; // U13
pub mod audit; // U11
pub mod backlog; // le carnet: work that outlives the turn that wrote it down
pub mod billing; // wave M: what we may charge for — seats and connectors, derived from the trail
pub mod calendar; // le calendrier: a moment an employee promised, and the claim that rings it
pub mod capability; // wave K: the tool an employee is missing, derived from the refusals
pub mod db; // U6
pub mod employee; // U7
pub mod files; // le classeur: the bytes somebody gave us, kept as they are
pub mod halt; // wave J: the switch that stops a whole company
pub mod idempotency; // U10
pub mod initiative;
pub mod invoices; // la facturation: what the company is owed, and what arrived
pub mod knowledge; // U14
pub mod model_access; // wave H: whose model this tenant thinks with
pub mod model_usage; // le grand livre des jetons
pub mod org; // wave 13: teams and sections
pub mod outbox; // U9
pub mod outreach; // le troisième plafond quotidien: les inconnus qu'on approche
pub mod phone_pool;
pub mod policy; // U41
pub mod provisioning; // U8
pub mod psyche;
// le registre public: ce que la gate a refusé, agrégé, sur consentement explicite
pub mod public_register;
pub mod revenue; // wave 12: seller vertical
pub mod signing;
pub mod sourcing;
pub mod spend; // U12
pub mod turns; // le budget de tours quotidien
pub mod webhooks; // wave M: which customer a provider callback belongs to
