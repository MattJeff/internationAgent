-- 0089_une_personne_ouvre_la_console: la deuxième moitié de l'étape zéro.
--
-- `0044_api_keys.sql` a sorti les credentials des CLIENTS de l'environnement.
-- Ce qui est resté dedans, c'est l'accès de la PERSONNE : la console lit
-- `ADMIN_EMAIL` / `ADMIN_PASSWORD`, donc il y a exactement un administrateur par
-- déploiement, donc un deuxième client est un deuxième déploiement. C'est la
-- seule chose qui empêche de vendre deux fois, et c'est cette table.
--
-- ---------------------------------------------------------------------------
-- POURQUOI LA TABLE S'APPELLE `console_accounts` ET PAS `accounts`
-- ---------------------------------------------------------------------------
--
-- Parce que `accounts` est prise, depuis `0011_revenue.sql`, et qu'elle y
-- désigne l'exact contraire : une entreprise À QUI on vend, un objet de CRM,
-- rempli par le vertical vendeur. Ici c'est une personne DE CHEZ un client, qui
-- ouvre la console.
--
-- Ça s'est vu de la pire façon possible et c'est la raison de ce paragraphe :
-- `create table if not exists accounts (...)` sur une base déjà migrée ne dit
-- rien du tout. Il ne crée pas, il ne refuse pas, il passe — et l'erreur sort
-- huit lignes plus bas, sur un GRANT qui parle d'une colonne `email` absente
-- d'une table qui n'est pas celle qu'on croyait écrire. Le préfixe est ce qui
-- fait que ça n'arrivera pas deux fois.
--
-- Le module Rust en face s'appelle quand même `agentos_store::accounts`, et
-- celui du CRM `agentos_store::revenue` : les deux noms ne se croisent nulle
-- part côté Rust, et c'est la table qui a besoin d'être désambiguïsée.
--
-- ---------------------------------------------------------------------------
-- POURQUOI L'EMPREINTE EST UN PBKDF2 ET PAS LE HMAC DE `api_keys`
-- ---------------------------------------------------------------------------
--
-- `0044` argumente longuement l'inverse, et il a raison — pour son entrée. Les
-- deux arguments ne parlent pas de la même chose et il faut les tenir côte à
-- côte :
--
-- * `api_keys.secret_hash` protège 256 bits tirés du CSPRNG. Il n'y a pas de
--   dictionnaire à précalculer, donc rien à étirer, et un sel par ligne
--   interdirait la recherche par index dont dépend l'authentification.
-- * `accounts.password_hash` protège un mot de passe CHOISI PAR UN HUMAIN. Le
--   dictionnaire existe, il est public, et il fait quelques milliards
--   d'entrées. Un HMAC nu ici, c'est un dump qui se casse en une nuit de GPU.
--
-- Et la contrainte structurelle qui interdisait le sel dans `0044` n'existe pas
-- ici : la recherche se fait `WHERE email = $1`, jamais par empreinte. On
-- connaît la ligne AVANT de dériver, donc on dérive une fois, avec le sel de
-- cette ligne. Le coût est payé une fois par ouverture de session, pas une fois
-- par requête d'API.
--
-- Le format stocké est `[version:1][sel:16][clé dérivée:32]` = 49 octets :
--
-- * `bytea` et pas `text`, pour la raison de `0044` — une colonne hexadécimale
--   est une colonne que quelqu'un compare un jour sans tenir compte de la
--   casse.
-- * L'octet de version est ce qui rend le facteur de travail AUGMENTABLE. Les
--   itérations d'un PBKDF2 doivent monter avec le matériel ; sans ce préfixe,
--   les monter invaliderait toutes les lignes d'un coup. Avec, une ligne se
--   re-dérive à la prochaine ouverture de session réussie, quand le mot de
--   passe en clair est là et nulle part ailleurs.
-- * Le sel est par ligne, donc deux personnes qui choisissent le même mot de
--   passe ont deux empreintes différentes, donc un dump ne dit pas qui partage
--   quoi.
--
-- La bibliothèque est `ring` — déjà dans le graphe de compilation (rustls la
-- tire par `sqlx/tls-rustls-ring`), donc ce choix n'ajoute rien à la lock file.
-- `argon2` aurait été un crate de plus pour un gain qui, au facteur de travail
-- retenu, se discute ; `sha2` nu aurait été un refus de livrer. L'argument
-- complet est dans `apps/server/src/routes/accounts.rs`.
--
-- ---------------------------------------------------------------------------
-- POURQUOI L'ADRESSE EST UNIQUE GLOBALEMENT ET PAS PAR LOCATAIRE
-- ---------------------------------------------------------------------------
--
-- Parce que la connexion prend une adresse et un mot de passe, et rien d'autre.
-- Un unique par locataire obligerait la personne à dire de quel locataire elle
-- est avant d'être authentifiée — c'est-à-dire à nommer un locataire depuis la
-- requête, ce que `apps/server/src/auth.rs` interdit dans sa première phrase.
-- Ici le locataire vient de la LIGNE, jamais du corps.
--
-- Ce que ça coûte : une même personne ne peut pas avoir un compte chez deux
-- clients avec la même adresse, et une création refusée en 409 dit que
-- l'adresse est prise quelque part sans dire où. La création est réservée à la
-- clé plateforme (`POST /v1/platform/accounts`), donc ce 409 n'est jamais lu
-- par un inconnu.
--
-- ---------------------------------------------------------------------------
-- POURQUOI `deactivated_at` EST UNE COLONNE, LÀ OÙ `api_keys` SUPPRIME LA LIGNE
-- ---------------------------------------------------------------------------
--
-- `0044` supprime, et son argument est bon : un `revoked_at` est un prédicat
-- qu'un futur SELECT peut oublier, et l'oublier ré-active silencieusement une
-- clé volée. Ici c'est l'inverse pour deux raisons :
--
--   1. Il n'y a qu'UN lecteur — `agentos_store::accounts::credentials`, la
--      seule requête qui lit `password_hash` — et son prédicat est dans un
--      `&'static str`. Rien d'autre ne peut l'oublier.
--   2. Une personne désactivée doit rester NOMMÉE : son adresse reste prise,
--      son id reste lisible dans les traces, et sa réactivation est un UPDATE
--      plutôt qu'une re-création qui lui donnerait un autre id. Un compte
--      supprimé, c'est une adresse que quelqu'un d'autre peut reprendre.
--
-- Et la partie qui, elle, doit disparaître disparaît bien : désactiver un
-- compte SUPPRIME sa clé de session dans la même transaction
-- (`accounts::deactivate` → `api_keys::revoke_session_in`), donc la révocation
-- reste ce que `0044` a construit — un DELETE senti par la requête suivante.

create table if not exists console_accounts (
  id              uuid        primary key,

  -- Le locataire pour qui cette personne agit. Écrit à la création par la clé
  -- plateforme, jamais par la personne. C'est ce qui fait que la session ouvre
  -- un locataire et un seul : la ligne dit lequel, la requête ne dit rien.
  tenant_id       uuid        not null references tenants (id) on delete cascade,

  -- Normalisée avant d'arriver ici : minuscules, sans espaces autour. La
  -- contrainte ci-dessous est ce qui le garantit plutôt qu'un commentaire, sans
  -- quoi `Alice@x.com` et `alice@x.com` seraient deux comptes et la personne
  -- découvrirait lequel des deux a son mot de passe en essayant.
  email           text        not null,

  -- `[version:1][sel:16][clé dérivée:32]`. Voir l'en-tête. Jamais lu par autre
  -- chose que la vérification du mot de passe, jamais renvoyé par une route,
  -- et hors de portée d'`app_role` par un GRANT au niveau colonne plus bas.
  password_hash   bytea       not null,

  created_at      timestamptz not null default now(),

  -- NULL = la personne peut ouvrir une session. Non-NULL = elle ne peut plus,
  -- et sa session en cours a été supprimée dans la transaction qui a posé cette
  -- date.
  deactivated_at  timestamptz,

  constraint console_accounts_email_key unique (email),

  -- Trois choses en une : normalisée, non vide, et vaguement une adresse. Pas
  -- une validation RFC 5322 — celle-là n'existe pas en une ligne de SQL et
  -- n'attrape rien qu'un envoi de courriel n'attrape mieux. Ce qu'elle attrape,
  -- c'est le formulaire qui poste un champ vide et le client qui n'a pas
  -- normalisé.
  constraint console_accounts_email_is_normalised
    check (email = lower(email) and length(email) between 3 and 254
           and position('@' in email) > 1),

  -- 49 octets, exactement. Une empreinte plus courte est une empreinte qui n'a
  -- pas été produite par le KDF, et la seule façon d'en écrire une est un bug
  -- ou un INSERT à la main.
  constraint console_accounts_password_hash_shape check (length(password_hash) >= 49)
);

create index if not exists console_accounts_tenant_idx on console_accounts (tenant_id);

-- ---------------------------------------------------------------------------
-- Row-level security, et un GRANT au niveau colonne par-dessus
-- ---------------------------------------------------------------------------
--
-- `enable` + `force` + une politique `ALL` portant `using` ET `with check`,
-- comme partout : `crates/store/src/db.rs::every_table_forces_row_level_security_and_checks_its_writes`
-- refuse le contraire, et `0062` existe parce que la paire de clauses avait été
-- prise à moitié sur deux tables.
--
-- Puis la partie qui n'est pas partout. `0044` retire TOUT à `app_role` sur
-- `api_keys` : aucune transaction de locataire ne touche cette table. Ici on ne
-- peut pas aller aussi loin — une console montre l'annuaire des personnes de sa
-- propre entreprise, et cette lecture-là passe par `tenant_tx` — mais on peut
-- aller plus loin sur la seule colonne qui compte :
--
--   * SELECT est accordé colonne par colonne, et `password_hash` n'y est pas.
--     `app_role` ne peut donc pas lire les empreintes même en écrivant
--     `select *` : Postgres refuse la requête avec 42501, il ne renvoie pas une
--     colonne vide.
--   * INSERT, UPDATE et DELETE ne sont accordés à personne. Un locataire ne se
--     crée pas de compte, n'en désactive pas un, n'en change pas le mot de
--     passe. Ces trois actes passent par la clé plateforme et par
--     `admin_tx_bypassing_rls`, ce qui est la même règle que pour l'émission
--     d'une clé et pour la même raison — voir `apps/server/src/routes/platform.rs`.
--
-- Les deux ceintures échouent différemment, ce qui est l'intérêt d'en avoir
-- deux : le GRANT manquant donne `42501 permission denied`, fort et nommant la
-- colonne ; la politique donne zéro ligne, silencieuse, et tient encore le jour
-- où une migration accorde `all on all tables in schema public to app_role`.

alter table console_accounts enable row level security;
alter table console_accounts force row level security;
drop policy if exists tenant_isolation on console_accounts;
create policy tenant_isolation on console_accounts
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Dit comme un revoke plutôt que comme une absence, pour la raison de `0044` :
-- `grant all on all tables in schema public to app_role` est une ligne que
-- quelqu'un ajoute un jour pour débloquer autre chose, et elle donnerait à
-- chaque locataire les empreintes de mots de passe de tous les autres. Ceci
-- fait que cette ligne-là ne suffit plus.
revoke all on console_accounts from app_role;
grant select (id, tenant_id, email, created_at, deactivated_at) on console_accounts to app_role;
