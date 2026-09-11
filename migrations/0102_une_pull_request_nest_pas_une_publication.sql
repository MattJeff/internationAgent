-- 0102_une_pull_request_nest_pas_une_publication : le dépôt qui sert le site
-- d'un client, attaché à un siège, et le troisième état qu'un brouillon peut
-- prendre — celui où une personne a quelque chose à relire.
--
-- `docs/CONTENU.md` § 5 « chemin A ». Jusqu'ici **rien ne publiait** : le
-- moteur de citation mesurait, briefait, rangeait un brouillon, et s'arrêtait
-- là. `content_drafts.url` est une adresse **constatée**, écrite par la
-- personne qui a publié à la main, et le CHECK de `0100` refuse un « publié »
-- sans adresse ni date pour que ce mot ne puisse pas être menti.
--
-- Cette migration ne touche pas à ce mot. Elle ajoute ce qu'il manquait avant
-- lui : de quoi pousser l'article dans un dépôt et ouvrir une pull request.
--
-- ---------------------------------------------------------------------------
-- POURQUOI `content_repos` ET PAS UNE LIGNE DE `employee_resources`
-- ---------------------------------------------------------------------------
--
-- `docs/CONTENU.md` § 5 écrit « une entrée dans `employee_resources` pour le
-- dépôt et la branche ». C'est la bonne intuition — un dépôt est bien une
-- ressource d'un siège, et pas une variable d'environnement — et c'est la
-- mauvaise table, pour deux raisons **mesurées dans le code**, pas supposées :
--
-- 1. `agentos_store::employee::load` refuse un employé dont le nombre de
--    lignes de `employee_resources` n'est pas exactement `Step::ALL.len()` —
--    « a short read is corruption, not a shrug ». Une douzième ligne sous un
--    `step` de plus rendrait *corrompu* chaque siège qui l'aurait, et le
--    message accuserait la table, pas cette migration.
-- 2. Donc il faudrait une douzième variante de `employee::Step`, c'est-à-dire
--    une étape de **provisionnement** : quelque chose que le moteur achète,
--    loue, surveille et relâche. Un dépôt n'est rien de tout ça. C'est le
--    client qui le possède, personne ne le paie, `release` n'aurait rien à
--    rendre, et le `ProvisioningEngine` passerait sa vie à « provisionner »
--    une ligne que seul un humain peut remplir.
--
-- La forme retenue est celle de `browser_proxies` (0098), et pour son argument
-- exactement : une prise, et rien d'autre. Un siège sans ligne ici ne publie
-- pas, comme un locataire sans proxy sort par l'adresse du VPS.
--
-- Par **siège** et pas par locataire, à l'inverse de 0098 : ce qui part vers
-- GitHub part sous un jeton que la Policy Gate a émis pour un employé nommé
-- (`agentos_app::content::propose`), et un dépôt attaché au locataire
-- laisserait la question « au nom de qui » sans réponse au moment où une pull
-- request s'ouvre chez le client.
--
-- ---------------------------------------------------------------------------
-- `server` PORTE UNE CLÉ ÉTRANGÈRE VERS `mcp_servers`, ET C'EST LA GARANTIE
-- ---------------------------------------------------------------------------
--
-- Le connecteur GitHub est déjà au catalogue (`agentos_app::catalog`) et un
-- locataire le branche sous **le handle de son choix** : `mcp_servers` a pour
-- clé primaire `(tenant_id, server)` et `connector` ne dit que de quelle entrée
-- du catalogue la ligne vient. Une colonne libre ici aurait laissé écrire un
-- handle que personne n'a branché, et l'erreur serait sortie trois appels plus
-- tard sous la forme `unknown_tool`. La clé étrangère composite — la forme de
-- `mcp_tool_declarations` (0013) — la fait sortir à l'écriture.
--
-- Elle emporte aussi le débranchement : un client qui retire son GitHub retire
-- le dépôt qui en dépendait, plutôt que de garder une ligne qui nomme un
-- serveur absent.
--
-- ---------------------------------------------------------------------------
-- `folder` A UN CHECK PARCE QU'IL FINIT DANS UN CHEMIN DE FICHIER
-- ---------------------------------------------------------------------------
--
-- `repo`, `branch` et `folder` sont recopiés tels quels dans les arguments d'un
-- appel d'outil qui écrit un fichier chez le client. Ce sont des valeurs
-- d'opérateur, pas d'étranger — mais c'est la dernière place où la forme est
-- vérifiable d'un coup pour toutes les lignes, et un `..` dans `folder` écrit
-- l'article hors du dossier que le générateur lit. Les trois CHECK disent la
-- forme et rien de plus : `propriétaire/nom`, une branche sans blanc, un
-- dossier relatif sans `..` ni barre de tête.
--
-- ---------------------------------------------------------------------------
-- `proposed` : LE TROISIÈME ÉTAT, ET POURQUOI IL EN FALLAIT UN
-- ---------------------------------------------------------------------------
--
-- **Ouvrir une pull request n'est pas publier.** L'article n'est à aucune
-- adresse publique ; il attend qu'une personne le lise et le fusionne — et
-- cette relecture *est* la pull request, pas un circuit d'approbation qu'on
-- aurait inventé à côté (§ 5 : « la revue de code du client est déjà le
-- garde-fou »).
--
-- Trois façons de ne pas ajouter d'état ont été essayées sur le papier, et
-- chacune se casse sur le même CHECK :
--
-- * **Écrire l'URL de la pull request dans `url`.** C'est `state = 'published'`
--   par construction (le CASE de `drafts::update`) : le produit dirait publié
--   pour un texte que personne n'a fusionné, et `url` cesserait d'être une
--   adresse constatée. C'est exactement le mensonge que `0100` a écrit son
--   CHECK pour rendre impossible.
-- * **Laisser l'état à `draft` et ne garder que l'adresse de relecture.** Une
--   liste de brouillons ne distinguerait plus « écrit » de « soumis », et le
--   seul moyen de le savoir serait de tester la nullité d'une colonne — une
--   convention plutôt qu'un fait, et la convention finit toujours par être lue
--   à l'envers quelque part.
-- * **Une table `content_proposals` à part.** Une deuxième vérité sur le cycle
--   de vie d'une même ligne, avec la jointure à chaque lecture et la
--   possibilité qu'elle contredise `state`. C'est l'argument que `0100` fait
--   déjà pour ne pas donner de table au brief.
--
-- Donc : un état de plus, et **une** colonne de plus. `review_url` est
-- l'adresse où un humain relit — la pull request — et elle est aussi
-- constatée que `url`, à ceci près que celle-là, c'est nous qui l'avons fait
-- exister. Elle ne remplace jamais `url` : un article fusionné a les deux, et
-- c'est la seule ligne où les deux adresses disent des choses différentes et
-- vraies.
--
-- L'élargissement ne peut pas échouer sur des données vivantes : toute ligne
-- existante est `draft` ou `published` avec `review_url` nul, et les deux
-- premières branches du nouveau CHECK les acceptent inchangées. Pas de
-- `NOT VALID`, donc, contrairement à 0002 — il n'y a rien d'ancien à épargner.

create table if not exists content_repos (
  -- Un siège, un dépôt. La clé primaire est l'employé : c'est lui que la Gate
  -- nomme quand la pull request s'ouvre.
  --
  -- La clé étrangère vers `employees` est **composite**, posée plus bas avec
  -- celle vers `mcp_servers` : Postgres vérifie une clé étrangère **hors de la
  -- RLS**, donc `references employees (id)` seul accepte l'identifiant d'un
  -- siège d'en face, et la clé primaire étant l'employé, la ligne squattée
  -- interdit au vrai propriétaire de poser la sienne. `migrations/0103` porte
  -- l'argument en entier et referme les trente-sept autres ; celle-ci naît du
  -- bon côté plutôt que d'être corrigée un fichier plus loin.
  employee_id uuid        not null primary key,
  tenant_id   uuid        not null references tenants (id) on delete cascade,

  -- Le handle sous lequel ce locataire a branché son GitHub, tel que
  -- `Action::McpCall` le nomme. Voir l'argument en tête.
  server      text        not null,

  -- `propriétaire/nom`, comme GitHub l'écrit partout.
  repo        text        not null
                          constraint content_repos_repo_shape
                          check (repo ~ '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'),

  -- La branche **qui sert le site** : celle vers laquelle la pull request est
  -- ouverte, jamais celle qui porte l'article. Cette dernière est dérivée du
  -- brouillon et n'a pas à être configurée — une branche par article, et son
  -- nom est l'identifiant du brouillon.
  branch      text        not null
                          constraint content_repos_branch_shape
                          check (branch ~ '^[^[:space:]]{1,255}$'),

  -- Le dossier que le générateur lit : `content/blog`, `_posts`, `src/pages` —
  -- « peu importe, ils lisent tous un dossier ».
  folder      text        not null
                          constraint content_repos_folder_shape
                          check (folder ~ '^[^[:space:]/][^[:space:]]{0,254}$'
                                 and folder !~ '\.\.'
                                 and folder !~ '/$'),

  created_at  timestamptz not null default now(),

  -- La garantie de l'existence du branchement, et du débranchement qui
  -- l'emporte. Voir l'argument en tête.
  foreign key (tenant_id, server) references mcp_servers (tenant_id, server)
    on delete cascade,
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
    on delete cascade
);

-- La lecture qui compte : les dépôts d'un locataire, pour la console et pour
-- `content_repos_list`. Le siège, lui, est déjà la clé primaire.
create index if not exists content_repos_tenant_idx
  on content_repos (tenant_id);

-- ---------------------------------------------------------------------------
-- `content_drafts` : un état de plus, une adresse de plus
-- ---------------------------------------------------------------------------

alter table content_drafts add column if not exists review_url text;

alter table content_drafts
  drop constraint if exists content_drafts_state_is_known;
alter table content_drafts
  add constraint content_drafts_state_is_known
  check (state in ('draft', 'proposed', 'published'));

alter table content_drafts
  drop constraint if exists content_drafts_published_carries_its_proof;
alter table content_drafts
  add constraint content_drafts_published_carries_its_proof
  check (
    -- Écrit, et nulle part encore.
    (state = 'draft' and url is null and published_at is null and review_url is null)
    -- Soumis : une pull request est ouverte à cette adresse, et l'article
    -- n'est à aucune adresse publique. Les deux moitiés tiennent ensemble.
    or (state = 'proposed' and url is null and published_at is null and review_url is not null)
    -- Publié veut toujours dire : une adresse et une date. Inchangé depuis
    -- 0100, et `review_url` est libre — un article peut avoir été publié à la
    -- main, sans pull request, comme avant cette migration.
    or (state = 'published' and url is not null and published_at is not null)
  );

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, la forme de 0100 et pour son argument : la ligne
-- d'un voisin nomme le dépôt privé de son site.

alter table content_repos enable row level security;
alter table content_repos force row level security;
drop policy if exists tenant_isolation on content_repos;
create policy tenant_isolation on content_repos
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Les quatre, comme les autres tables pendues à un employé (`employee_resources`,
-- `employee_initiative`, 0020) : `delete` pour que la disparition d'un siège ou
-- d'un locataire cascade en tant que `app_role` plutôt que d'échouer sur un
-- privilège. `update` parce qu'un dépôt se change — un client qui déménage son
-- site garde ses brouillons.
grant select, insert, update, delete on content_repos to app_role;
