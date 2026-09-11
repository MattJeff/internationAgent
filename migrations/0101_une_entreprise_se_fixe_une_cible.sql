-- 0101_une_entreprise_se_fixe_une_cible : le chiffre que le fondateur vise, et
-- la date à laquelle il le veut.
--
-- ---------------------------------------------------------------------------
-- POURQUOI UNE TABLE, ET POURQUOI CELLE-CI N'EN EST PAS UNE DE PLUS
-- ---------------------------------------------------------------------------
--
-- `GET /v1/growth` sait dire ce qui s'est passé : sept étapes, de l'inconnu
-- ajouté à la facture réglée, chacune tirée de la table qui en fait foi. Un
-- entonnoir sans cible ne dit pourtant rien — « 3 réponses » est un bon chiffre
-- ou un désastre selon qu'on visait 5 ou 500, et la console ne peut pas
-- trancher toute seule. Le verdict (`ahead` / `on_track` / `behind`) est une
-- comparaison entre deux rythmes, et il lui manquait le second.
--
-- Les tables candidates ont été relues avant d'en écrire une :
--
-- * `spend_caps` (0011) est un plafond de dépense, pas un objectif de recette,
--   et un plafond qu'on dépasse est une alarme là où une cible qu'on dépasse
--   est une bonne nouvelle. Les deux signes sont opposés.
-- * `charters` (0020) porte l'objectif **d'un siège**, en prose, relu par un
--   modèle. Un nombre que la console compare à un autre nombre n'y est pas
--   interrogeable, et l'y mettre reviendrait à demander à un modèle de rendre
--   un entier à chaque chargement d'écran.
-- * `tenant_model_access` (0050/0079) porte le tarif déclaré, donc un coût.
--   Une recette visée n'a rien à y faire.
--
-- D'où cette table. **Une ligne par locataire, pas un historique** : la clé
-- primaire est `tenant_id` et la lecture est un `SELECT` sans `ORDER BY`. Un
-- historique des cibles serait une table d'ambitions successives que personne
-- n'ouvre, et la question de l'écran est au présent — « celle d'aujourd'hui,
-- est-ce que j'y arrive ». `set_at` garde quand même la date de la dernière
-- pose : une cible fixée il y a quatre mois et jamais revue se lit
-- différemment d'une posée ce matin, et c'est une colonne plutôt qu'une table.
--
-- ---------------------------------------------------------------------------
-- CE QUE `mrr_minor` EST, ET CE QU'IL N'EST PAS
-- ---------------------------------------------------------------------------
--
-- Le couple `Money` de tout ce schéma : des unités mineures et un code ISO,
-- comme `invoices` (0066), `sales_quotes` (0090) et `opportunities` (0011).
-- Strictement positif, comme `invoices_amount_positive` : une cible à zéro est
-- l'absence de cible, et l'absence de cible est l'absence de ligne.
--
-- C'est une recette **mensuelle** visée, et la route la compare à ce que le
-- locataire a encaissé sur trente jours glissants. Ce dépôt n'a aucune table
-- d'abonnement : rien n'y porte de récurrence, et `GET /v1/growth` le dit dans
-- son `unmeasured` plutôt que de fabriquer un MRR à partir d'une moyenne.

create table if not exists growth_targets (
  -- Une entreprise, une cible. Pas d'`id` : la clé est le locataire lui-même,
  -- ce qui rend un second objectif concurrent non représentable plutôt
  -- qu'interdit par un index partiel que quelqu'un relira mal.
  tenant_id    uuid        primary key references tenants (id) on delete cascade,

  currency     text        not null
                           constraint growth_targets_currency_iso
                           check (currency ~ '^[A-Z]{3}$'),
  mrr_minor    bigint      not null
                           constraint growth_targets_mrr_positive
                           check (mrr_minor > 0),

  -- Quand. Un horodatage et non une date : la fenêtre restante se compte en
  -- secondes par la route, et une `date` obligerait à choisir une heure, donc
  -- un fuseau, donc une convention de plus.
  --
  -- **Aucune contrainte de futur.** Une échéance qu'on a manquée reste la
  -- vérité de ce qu'on avait visé, et un CHECK `at > now()` rendrait la ligne
  -- immodifiable le jour d'après — c'est-à-dire exactement le jour où l'on
  -- vient regarder. `verdict` rend `behind` et la console le dit.
  at           timestamptz not null,

  -- La dernière pose. Écrasée par chaque `PUT`, comme le reste de la ligne.
  set_at       timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, la forme de 0099 : l'objectif chiffré d'une
-- entreprise est ce qu'elle a de plus commercialement sensible, et le rôle
-- propriétaire ne doit pas le lire par distraction non plus.
--
-- Contrairement à `turn_outcomes`, il n'y a **aucune exception** : aucune
-- boucle n'écrit ici, seul un opérateur pose une cible, et toute écriture comme
-- toute lecture passe par `Db::tenant_tx`.
alter table growth_targets enable row level security;
alter table growth_targets force row level security;
drop policy if exists tenant_isolation on growth_targets;
create policy tenant_isolation on growth_targets
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- `update` en plus d'`insert` : le `PUT` est un upsert, et une cible qu'on
-- révise est le cas normal — le fondateur en pose une, la rate, en pose une
-- autre. Pas de `delete` : retirer une cible se fait en en posant une autre, et
-- `verdict` a déjà `no_target` pour l'entreprise qui n'en a jamais posé.
grant select, insert, update on growth_targets to app_role;
