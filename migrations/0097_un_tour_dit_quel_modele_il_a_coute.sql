-- 0097_un_tour_dit_quel_modele_il_a_coute : la colonne qui manquait au grand
-- livre des jetons pour qu'on puisse relire ce que le routage a changé.
--
-- `0024_model_usage.sql` a été écrit quand un déploiement entier tournait sur
-- une chaîne de caractères lue dans `AGENTOS_LLM` : le modèle était une
-- constante de processus, donc une colonne l'aurait répétée à chaque ligne. Ce
-- n'est plus vrai deux fois. Depuis les packs de rôle, deux sièges d'un même
-- locataire tournent sur deux modèles ; depuis `agentos_app::model_choice`,
-- **deux tours d'un même siège dans la même journée** tournent sur deux
-- modèles. Sans cette colonne, la ligne du jour additionne des jetons à 1 $/M
-- et des jetons à 5 $/M et le total ne se convertit en euros par aucune
-- multiplication : `GET /v1/usage` publie une somme dont le multiplicateur
-- n'existe pas.
--
-- Trois décisions.
--
-- 1. LE GRAIN GAGNE UNE COLONNE, IL N'EN PERD AUCUNE. La clé primaire passe de
--    `(tenant_id, employee_id, day)` à `(tenant_id, employee_id, day, model)`.
--    C'est le même grain vu d'un cran plus fin : tout lecteur qui veut l'ancien
--    l'obtient avec un `sum(...) GROUP BY tenant_id, employee_id, day`, ce que
--    `model_usage::on_day` fait maintenant, et aucun agrégat existant ne change
--    de valeur — `GET /v1/usage` groupe déjà par employé et somme.
--
-- 2. `''` EST LA VALEUR DES LIGNES ÉCRITES AVANT CE FICHIER, ET ELLE VEUT DIRE
--    « PERSONNE NE L'A NOTÉ ». Pas `'claude-opus-5'` : remplir rétroactivement
--    un modèle plausible reviendrait à fabriquer la mesure que cette colonne
--    existe pour rendre possible. C'est la même règle que `calls_unmetered` en
--    (3) de `0024` — inconnu n'est pas zéro, et ici inconnu n'est pas Opus.
--    `GET /v1/usage/models` rend ces lignes sous le modèle `""`, visiblement,
--    plutôt que de les répartir.
--
-- 3. `text` LIBRE, PAS D'ENUM SQL NI DE CHECK SUR LA LISTE DES MODÈLES.
--    `ModelId` est un enum fermé côté Rust et c'est là que la faute de frappe
--    est attrapée — au parseur de la politique de l'opérateur, avant qu'aucun
--    appel ne parte. Une CHECK ici ajouterait une deuxième liste à tenir à jour
--    et transformerait « ce build connaît un modèle de plus » en migration
--    bloquante ; `0024` a refusé une table de prix pour la même raison.
--
-- RLS : rien à ajouter. `model_usage_daily` porte déjà `tenant_isolation`,
-- `enable` **et** `force`, avec `using` et `with check` — la forme de `0085` et
-- de `0001_core` — et une nouvelle colonne d'une table existante hérite de la
-- politique de la table. Les `grant` de `0024` (select, insert, update ; jamais
-- delete) valent tels quels : l'upsert ci-dessous a besoin des deux premiers.

alter table model_usage_daily
  add column if not exists model text not null default '';

-- La clé primaire, remplacée en deux temps parce que Postgres n'a pas de
-- `alter ... alter primary key`. Le nom `model_usage_daily_pkey` est celui que
-- `primary key (...)` a engendré dans 0024 ; `if exists` rend le fichier
-- rejouable sur une base déjà migrée.
alter table model_usage_daily drop constraint if exists model_usage_daily_pkey;
alter table model_usage_daily
  add constraint model_usage_daily_pkey
  primary key (tenant_id, employee_id, day, model);
