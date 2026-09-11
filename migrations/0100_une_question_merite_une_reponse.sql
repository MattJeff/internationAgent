-- 0100_une_question_merite_une_reponse : les questions sur lesquelles on veut
-- être cité, ce qu'un moteur répond quand on les pose, et ce qu'on écrit pour y
-- répondre.
--
-- ---------------------------------------------------------------------------
-- POURQUOI CES TROIS TABLES, ET PAS UNE DE PLUS
-- ---------------------------------------------------------------------------
--
-- `docs/ROADMAP_CROISSANCE.md` § 2.1 : quand un développeur demande à un modèle
-- « comment vérifier par API si un passeport permet d'entrer quelque part », la
-- réponse cite deux ou trois produits. Y être vaut plus qu'une campagne, et
-- c'est le seul canal où un petit acteur bat un gros à budget égal. La boucle
-- qui le produit a exactement trois états, et chacun est une table :
--
--   * la **question** qu'on veut gagner — `content_questions` ;
--   * ce qu'un moteur répond **aujourd'hui** — `content_citations` ;
--   * ce qu'on **écrit** pour y répondre mieux — `content_drafts`.
--
-- Le brief — ce qu'un employé doit couvrir pour battre les pages citées — n'a
-- **pas** de table, et c'est une décision, pas un oubli : `content::brief` est
-- une fonction pure d'une question et d'une mesure, toutes deux stockées ici.
-- Une table de briefs serait un cache d'un calcul de trois microsecondes, et
-- surtout une deuxième vérité qui vieillit pendant que la mesure, elle, bouge.
-- Le jour où un employé *annote* un brief à la main, la table sera celle des
-- annotations, pas celle des briefs.
--
-- ---------------------------------------------------------------------------
-- `content_citations` EST EN AJOUT SEUL, ET C'EST LE PRODUIT
-- ---------------------------------------------------------------------------
--
-- L'argument est celui de `0091` et de `0099`, et il est ici encore plus direct.
-- Le fait intéressant n'est pas « sommes-nous cités » : c'est « depuis quand »,
-- et « qu'est-ce qui a changé quand on a publié ». Une ligne par (question,
-- moteur, instant) qu'on ne réécrit jamais est la seule forme qui répond à ça.
--
-- Une colonne `cited boolean` sur `content_questions`, mise à jour à chaque
-- mesure, aurait coûté une table de moins et aurait rendu la question de départ
-- inrépondable — c'est exactement l'erreur que `contacts.last_contacted_at` a
-- faite côté prospection (`apps/server/src/routes/outreach.rs` la raconte).
-- Donc : `grant select, insert`, jamais `update`, jamais `delete`. Une mesure
-- fausse se corrige par une mesure suivante, comme une écriture comptable.
--
-- ---------------------------------------------------------------------------
-- `competitors` EST DU `jsonb`, ET `excerpt` EST LA PROSE D'UN ÉTRANGER
-- ---------------------------------------------------------------------------
--
-- `competitors` est un tableau d'hôtes, dans l'ordre où le moteur les a rendus.
-- Du `jsonb` plutôt qu'une table fille parce que rien ne joint jamais dessus :
-- on le lit entier, avec la mesure, ou pas du tout. Et `text[]` aurait forcé un
-- type Postgres dans chaque signature Rust pour la même chose.
--
-- `excerpt` porte **les mots de la page de résultats**, pas les nôtres : les
-- titres et résumés que le moteur affiche. C'est la seule matière que
-- `content::brief` a pour dire ce que les pages citées couvrent, donc elle est
-- stockée — mais elle est ce que `agentos_domain::untrusted` appelle une
-- source non fiable, et toute surface qui la rend à un modèle doit la traiter
-- comme telle. `content.rs` le redit au-dessus de la structure.
--
-- ---------------------------------------------------------------------------
-- `state` A UN CHECK, `engine` ET `source` N'EN ONT PAS
-- ---------------------------------------------------------------------------
--
-- `state` en a un parce que les deux valeurs sont un cycle de vie que cette
-- table gouverne seule : un brouillon est `draft` ou `published`, `url` et
-- `published_at` n'ont de sens que dans le second cas, et le CHECK les lie.
--
-- `engine` et `source` n'en ont pas, pour la raison que `0097` et `0099`
-- donnent : la liste est un enum Rust (`content::Engine`), exhaustive au
-- compilateur, et une deuxième liste ici serait une migration bloquante le jour
-- où un moteur de plus devient lisible. Ce qui compte est qu'une mesure dise
-- **par quoi** elle a été faite, pas que Postgres ait un avis sur le catalogue.

create table if not exists content_questions (
  -- Engendré par l'application, comme partout ailleurs dans ce schéma (0001).
  id         uuid        primary key,
  tenant_id  uuid        not null references tenants (id) on delete cascade,

  -- La question telle qu'un humain la poserait. Pas un mot-clé : ce qu'on
  -- mesure est une réponse à une question, et une page de résultats sur trois
  -- mots n'est pas la même chose qu'une page de résultats sur une phrase.
  question   text        not null,

  -- `fr`, `en`, … La même question en deux langues est deux lignes : les pages
  -- citées ne sont pas les mêmes, donc la mesure ne l'est pas non plus.
  locale     text        not null,

  -- D'où elle vient : `founder`, `search_suggest`, `customer`. Pas un CHECK —
  -- voir plus haut — mais la colonne existe parce que la provenance change ce
  -- qu'on en fait : une question qu'un client a posée vaut dix questions
  -- devinées, et sans cette colonne les deux se ressemblent dans la table.
  source     text        not null,

  -- Combien elle compte, pour trier une liste qui va grossir. Un entier libre
  -- et pas un rang : deux questions peuvent compter autant.
  weight     int         not null default 1,

  created_at timestamptz not null
);

-- Une même question posée deux fois dans la même langue est la même ligne, et
-- la série dans le temps n'a de sens que si elle pend à une seule. La contrainte
-- porte le locataire : deux clients ont le droit de viser la même question.
create unique index if not exists content_questions_tenant_question_idx
  on content_questions (tenant_id, question, locale);

create table if not exists content_citations (
  id          uuid        primary key,
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  question_id uuid        not null references content_questions (id) on delete cascade,

  -- L'instant de la mesure, tel que l'appelant le connaît. Pas `now()` : deux
  -- horloges dans une ligne sont une fenêtre qu'on ne peut pas tester (0099).
  checked_at  timestamptz not null,

  -- Le moteur interrogé. `content::Engine::as_str`.
  engine      text        not null,

  -- Y étions-nous. Redondant avec `rank is not null` et gardé : c'est la
  -- colonne qu'on lit, qu'on compte et qu'on trace, et la dériver à chaque
  -- lecture aurait fait dépendre le graphe d'une convention plutôt que d'un
  -- fait. Le CHECK ci-dessous interdit aux deux de se contredire.
  cited       boolean     not null,

  -- Le rang, à partir de 1, quand on y est. `null` quand on n'y est pas — et
  -- pas 0 : un zéro se trie, se moyenne et ment.
  rank        int,

  -- Les hôtes cités, dans l'ordre du moteur, y compris le nôtre. Un tableau
  -- JSON de chaînes.
  competitors jsonb       not null default '[]'::jsonb,

  -- Ce que le moteur a affiché : titres et résumés. Les mots d'un étranger.
  excerpt     text        not null,

  constraint content_citations_rank_agrees_with_cited
    check ((cited and rank is not null and rank >= 1) or (not cited and rank is null))
);

-- La lecture qui compte : une question, du plus récent au plus ancien. C'est
-- `GET /v1/content/citations?question_id&days` et rien d'autre.
create index if not exists content_citations_question_at_idx
  on content_citations (question_id, checked_at desc);

create table if not exists content_drafts (
  id           uuid        primary key,
  tenant_id    uuid        not null references tenants (id) on delete cascade,
  question_id  uuid        not null references content_questions (id) on delete cascade,

  title        text        not null,
  -- Le texte, écrit par un employé avec son modèle. Rien dans ce dépôt ne
  -- l'engendre : `content::brief` rend une structure, pas de la prose.
  body         text        not null,

  state        text        not null default 'draft',
  -- Où il a été publié. Aujourd'hui personne ne publie — voir `docs/CONTENU.md`
  -- « ce qui manque » — donc cette colonne est remplie **à la main** par qui a
  -- publié, et c'est ce qui la rend honnête : elle dit une adresse constatée,
  -- pas une adresse promise.
  url          text,

  created_at   timestamptz not null,
  published_at timestamptz,

  constraint content_drafts_state_is_known
    check (state in ('draft', 'published')),
  -- Publié veut dire : une adresse et une date. Les trois tiennent ou aucun ne
  -- tient. Sans ce CHECK, « publié » serait un mot qu'on met dans une colonne.
  constraint content_drafts_published_carries_its_proof
    check (
      (state = 'draft' and url is null and published_at is null)
      or (state = 'published' and url is not null and published_at is not null)
    )
);

create index if not exists content_drafts_tenant_question_idx
  on content_drafts (tenant_id, question_id);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, la forme de 0085 et 0099 : le rôle propriétaire
-- ne doit pas non plus lire par distraction les questions que vise une autre
-- entreprise. Ce sont, littéralement, les mots-clés d'un concurrent.
--
-- Toute lecture et toute écriture passent par `Db::tenant_tx` : aucune boucle
-- ne balaie ces tables, donc rien ici n'a l'exception que `turn_outcomes` a.

alter table content_questions enable row level security;
alter table content_questions force row level security;
drop policy if exists tenant_isolation on content_questions;
create policy tenant_isolation on content_questions
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table content_citations enable row level security;
alter table content_citations force row level security;
drop policy if exists tenant_isolation on content_citations;
create policy tenant_isolation on content_citations
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table content_drafts enable row level security;
alter table content_drafts force row level security;
drop policy if exists tenant_isolation on content_drafts;
create policy tenant_isolation on content_drafts
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Le minimum que chaque table demande, et pas un verbe de plus.
--
-- `content_questions` : une question s'ajoute, se lit, se retire. Elle ne se
-- modifie pas — changer le texte d'une question sous une série de mesures
-- transformerait l'historique en mensonge ; on en ajoute une autre.
--
-- L'absence d'`UPDATE` mord, et c'est pour ça qu'elle est écrite ici plutôt que
-- seulement dans un commentaire Rust : `ON CONFLICT DO UPDATE` réclame ce
-- droit, donc `content::questions::add` est un `DO NOTHING` suivi d'un `SELECT`
-- et un ajout rejoué ne repondère rien. Le jour où repondérer compte, c'est un
-- grant sur `weight` et `source` seules — pas sur la table.
grant select, insert, delete on content_questions to app_role;

-- `content_citations` : ajout seul. Voir le raisonnement en tête.
grant select, insert on content_citations to app_role;

-- `content_drafts` : un brouillon se réécrit tant qu'il est un brouillon, et se
-- retire tant que personne ne l'a vu. C'est la seule des trois tables qui a un
-- `update`, et c'est parce qu'elle est la seule dont le contenu est le nôtre.
grant select, insert, update, delete on content_drafts to app_role;
