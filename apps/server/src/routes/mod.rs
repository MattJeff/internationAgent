// la session de console : une personne s'authentifie, et la console appelle
// `/v1/*` pour SON locataire. `platform` en est la moitié fournisseur — c'est
// lui qui crée une personne et qui la révoque, jamais le client lui-même.
pub mod a2a;
pub mod accounts; // U34
// l'export comptable: the same books as `pnl`, one CSV line per movement, for
// a human accountant's tool. Its totals foot to `/v1/pnl` by construction.
pub mod accounting;
pub mod approvals;
pub mod autonomy;
// wave M: what we may charge for — seats and connectors, by the day, derived
// from the trail. The counter, deliberately not the collection.
pub mod billing;
// la page de réservation: a stranger picks an hour on a seat that opened its
// door, and the seat is woken by it. Public pair + one private switch.
pub mod booking;
// le navigateur : le journal de ses tâches, la vue en direct de l'une d'elles,
// et le résumé du jour. Le lecteur de `BrowserObserver`, côté routes.
pub mod browser;
// le calendrier: the founder promises a moment and sees what has been promised.
// The employee's half is `agentos_app::calendar` and `loops::initiative`.
pub mod calendar;
pub mod companies; // a whole company, standing, from one call
// la boucle de citation : les questions qu'on veut gagner, ce qu'un moteur y
// répond aujourd'hui, le brief qui en sort, et ce qu'on écrit pour y répondre.
// Le seul verbe du produit qui sorte sur le web pour *mesurer* plutôt que pour
// vendre — d'où l'`employee_id` dans le corps de la mesure.
pub mod content;
pub mod controls; // tâche K: ce qui borne chaque siège et le bouton d'arrêt, en une lecture
// le fil: the person reads what landed on a seat's desk and writes back from it.
// No table and no port — `0028`'s internal channel already is the thread; see
// `agentos_app::inbound`'s desk section and `migrations/0065`.
pub mod desk;
// le domaine d'envoi : au locataire, vérifié chez le fournisseur, posé chez
// Cloudflare en un appel. `Hiring` y vit aussi — l'état des trois routes qui
// embauchent, parce qu'embaucher enregistre le domaine au passage.
pub mod domain;
pub mod employees; // U31
// le classeur: the founder files a document and gets those exact bytes back.
// `knowledge` next door indexes in order to find again; this one keeps.
pub mod files;
// wave K: the founder picks a window and gets a quote — effort and money, never
// a chance of success. Beside `usage` and `turns` in spirit: those two report
// what already happened, this one is the same arithmetic pointed forwards.
pub mod forecast;
// le journal : `audit_log` rendu comme un flux avec un curseur, pour que
// l'écran d'accueil cesse de reconstituer l'activité à partir de six lectures
// d'état — et pour que l'autonomie d'un fait se lise sur le fait lui-même.
pub mod events;
// la santé de la société : est-ce que ses employés pensent encore. Née du
// 2026-09-06, quatre jours pendant lesquels tout le reste répondait vert.
pub mod growth; // l'entonnoir de bout en bout, la cible chiffrée, et le verdict
pub mod halt; // wave J: stop the whole company, and let it go again
pub mod health;
pub mod initiative;
pub mod interview; // the guided conversation that finishes a company
pub mod inventory;
// la facturation: the founder reads what the company is owed and says when it
// arrived. The employee's half is `agentos_app::effects::issue_invoice` — and
// there is deliberately no operator way to *issue* one; see the module docs.
pub mod invoices;
// la clé que le locataire émet pour lui-même : celle qu'on colle dans
// `claude mcp add`. `platform` en est la moitié fournisseur — il nomme le
// locataire, celui-ci le lit dans le credential et ne sait pas dire « autrui ».
pub mod keys;
pub mod knowledge;
pub mod mcp;
// le serveur MCP : l'autre sens de `mcp`. Celui-ci n'appelle personne — il
// rend cette société pilotable depuis le Claude Code du fondateur, en rejouant
// ses propres routes en interne. Une ligne de table par outil.
pub mod mcp_server;
pub mod model; // wave H: the tenant connects the model their employees think with
// the one route that changes a limit. `POST /v1/companies` creates a role layer
// where none exists; this one replaces one, and can only tighten — see its
// module docs for the invariant and the three mechanisms that hold it.
pub mod platform; // wave J: step zero — a tenant signs up and gets a key that can be revoked
// l'activité commerciale plutôt que l'administration : combien d'inconnus ont
// été approchés cette semaine, et combien ont répondu. Avec ce que le chiffre
// ne mesure pas, dans la réponse.
pub mod outreach;
// l'import de prospects : le fichier Smartlead du fondateur, déposé depuis la
// console. Le même `agentos_app::prospects::import` que la sous-commande.
pub mod prospects;
// la séquence : le fondateur définit les pas et inscrit un contact ; le siège
// écrit chaque mail lui-même, réveillé par une promesse. Aucune route d'envoi.
pub mod pnl; // the seat's P&L: tokens at the declared tariff against the money it moved
pub mod policy;
pub mod pool;
pub mod sequences;
pub mod signatures; // la signature d'un document : préparer le pli, et constater l'exemplaire exécuté
// le social : `apps/social` est un agrégateur abouti et séparé ; ces quatre
// chemins sont tout ce qu'il fallait pour qu'un locataire qui l'a branché
// publie depuis le produit. Aucun octet de plateforme ne passe par ici — le
// service le fait, et lui seul sait ce qu'une plateforme accepte.
pub mod social;
// le registre public: la preuve qu'on a et qu'un concurrent sans gate ne peut
// pas copier — ce que la gate a refusé, agrégé, sur consentement explicite. Sa
// lecture est montée hors de toute clé; sa bascule est un acte de locataire.
pub mod public_register;
pub mod queue;
// le devis : le fondateur lit ce qui a été proposé et dit ce que le client en a
// répondu. La moitié employé est un effet derrière la gate.
pub mod quotes; // the file the founder uploads, and the only caller of `app::queue`
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
