-- 0099_un_tour_rate_laisse_une_trace : la trace qu'un tour laisse derrière lui,
-- pour qu'une entreprise qui a cessé de penser puisse être vue depuis une
-- requête au lieu des journaux d'un conteneur.
--
-- ---------------------------------------------------------------------------
-- CE QUI MANQUAIT, ET CE QUI NE MANQUAIT PAS
-- ---------------------------------------------------------------------------
--
-- Le 2026-09-06, `agentos_app::model_access::NoModel::SubscriptionIsNotOursToHold`
-- s'est mis à refuser chaque tour d'Orizn. Le fondateur l'a découvert quatre
-- jours plus tard, parce qu'un employé ne lui répondait pas. Rien n'était
-- cassé du point de vue de tout ce qu'on sait interroger : `/readyz` répondait,
-- les sièges étaient `active`, `GET /v1/model` rendait une connexion vérifiée.
--
-- Les quatre tables candidates ont été relues avant d'en écrire une cinquième :
--
-- * `employee_initiative` (0020) porte `last_outcome` et `last_detail`, mais
--   c'est **un instantané par siège**, écrasé à chaque battement. On y lit
--   « ce siège a raté son dernier tour », jamais « il rate tous ses tours
--   depuis quatre jours », et surtout jamais la date du dernier qui a marché :
--   le succès du 2026-09-06 avait été recouvert à 09 h 05.
-- * `turn_buckets` (0016) compte les réservations du jour, donc les tours
--   *tentés* — mais pas leur issue, et pas ceux refusés avant la réservation.
-- * `model_usage_daily` (0024/0097) compte des jetons. Un tour qui échoue avant
--   le premier appel n'y écrit rien, et un tour qui échoue après y écrit la
--   même ligne qu'un tour réussi.
-- * `audit_log` (0001) enregistre ce que la gate a **ruled** et ce qui est
--   arrivé à l'entreprise. Un tour de cadence qui ne fait que penser ne
--   déclenche aucune action gatée : il n'y laisse rien. `AuditKind` n'a
--   d'ailleurs aucune variante d'issue de tour, et lui en ajouter une ferait
--   d'un fait d'exploitation une ligne du registre de sécurité — 0001 dit
--   pourquoi ce registre n'admet que des faits que quelqu'un a décidés.
--
-- Aucune des quatre ne répond « depuis quand cette société ne pense plus ».
-- D'où cette table, en ajout seul.
--
-- ---------------------------------------------------------------------------
-- POURQUOI `turn_outcomes` ET PAS `turn_failures`
-- ---------------------------------------------------------------------------
--
-- Parce que la question posée à l'écran d'accueil — « depuis combien de temps
-- rien n'a marché » — a besoin des **succès** autant que des échecs. Une table
-- d'échecs seuls donne « 288 tours ratés aujourd'hui » et ne peut pas dire
-- « dernier travail effectué il y a quatre jours » : c'est exactement la
-- phrase qui manquait au fondateur, et elle n'est dérivable d'aucune autre
-- table (voir ci-dessus). Deux tables — une pour les succès, une pour les
-- échecs — seraient deux écritures et deux index pour un `count(*) FILTER`.
--
-- Les colonnes sont celles demandées, `code` valant `turn` pour un succès.
--
-- ---------------------------------------------------------------------------
-- CE QUI EST ÉCRIT, ET CE QUI NE L'EST PAS
-- ---------------------------------------------------------------------------
--
-- `loops::initiative::record` écrit ici **une ligne par battement qui comptait**,
-- et rien pour les battements au repos. Une société sans charte, sans travail
-- en attente, ou dont l'objectif pose une question à l'opérateur n'est pas
-- malade : elle se repose, et remplir cette table de son repos ferait à la fois
-- grossir la table à la vitesse de la cadence et rendre `degraded` une société
-- neuve. `Outcome::health` en Rust est la liste exacte, et elle est exhaustive
-- par `match`, donc une neuvième issue est une erreur de compilation.
--
-- `over_budget` est délibérément au repos : c'est un plafond que l'opérateur a
-- posé lui-même, pas une panne, et `store::turns::reserve` a déjà levé son
-- alerte au moment où la ligne a été franchie.
--
-- ---------------------------------------------------------------------------
-- `detail` EST NOTRE TEXTE
-- ---------------------------------------------------------------------------
--
-- La colonne reçoit `Outcome::detail()`, qui ne contient jamais la prose d'un
-- fournisseur : la seule branche qui pourrait en porter — un tour qui échoue
-- dans `Turn::run` — est déjà réduite à `failed.error.code()`, un vocabulaire
-- fermé, par `take_turn`. Tout le reste est une phrase de ce dépôt (les
-- variantes de `NoModel`, la phrase du plafond d'abonnement). C'est ce qui rend
-- cette colonne publiable telle quelle par `GET /v1/health/company`, et donc
-- affichable dans une bannière de console.

create table if not exists turn_outcomes (
  -- Engendré par l'application, comme partout ailleurs dans ce schéma : 0001
  -- dit qu'il n'y a pas de `DEFAULT gen_random_uuid()` ici.
  id          uuid        primary key,

  tenant_id   uuid        not null references tenants (id) on delete cascade,
  -- Le siège dont c'était le battement. Une société ne pense pas ; ses employés
  -- pensent, et la première question après « laquelle est arrêtée » est
  -- « lequel ».
  employee_id uuid        not null references employees (id) on delete cascade,

  -- L'instant du battement, tel que la boucle le connaît (`now` du tick), pas
  -- `now()` : `loops::initiative` passe une horloge à travers `tick`, et deux
  -- horloges dans une même ligne sont une fenêtre de six heures qu'on ne peut
  -- pas tester.
  at          timestamptz not null,

  -- `Outcome::code()`. Quatre valeurs seulement y arrivent aujourd'hui — `turn`
  -- pour un succès, `error`, `no_model` et `unreadable_charter` pour un échec —
  -- parce que `Outcome::health` filtre les quatre autres. Pas de CHECK sur la
  -- liste, pour la raison que 0097 donne de son côté : l'enum Rust est la
  -- liste, elle est exhaustive au compilateur, et une deuxième liste ici serait
  -- une migration bloquante le jour où une neuvième issue existe.
  code        text        not null,

  -- La phrase, quand il y en a une. Toujours la nôtre — voir ci-dessus.
  detail      text
);

-- La lecture de `GET /v1/health/company` : un locataire, une fenêtre, du plus
-- récent au plus ancien. C'est aussi ce que sert `max(at) FILTER (code='turn')`.
create index if not exists turn_outcomes_tenant_at_idx
  on turn_outcomes (tenant_id, at desc);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, la forme de 0085 : le rôle propriétaire ne doit
-- pas non plus lire l'état de santé de toutes les entreprises par distraction.
--
-- L'exception est la même que celle de `employee_initiative` : la boucle écrit
-- depuis `admin_tx_bypassing_rls`, parce qu'un poller qui ne verrait qu'un
-- locataire n'est pas un poller. L'écriture y nomme `tenant_id` explicitement.
-- Toute lecture, elle, passe par `Db::tenant_tx`.
alter table turn_outcomes enable row level security;
alter table turn_outcomes force row level security;
drop policy if exists tenant_isolation on turn_outcomes;
create policy tenant_isolation on turn_outcomes
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Ni UPDATE ni DELETE : ce qu'un tour a fait ne se réécrit pas. La ligne meurt
-- avec le locataire ou avec le siège, par cascade, et pas autrement.
grant select, insert on turn_outcomes to app_role;
