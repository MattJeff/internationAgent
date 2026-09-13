-- 0108_une_recette_dabonnement_a_sa_propre_cle : la clé restreinte avec
-- laquelle on va **lire** Stripe, et rien d'autre.
--
-- ---------------------------------------------------------------------------
-- LE FAIT MESURÉ QUI COMMANDE CETTE TABLE
-- ---------------------------------------------------------------------------
--
-- `invoices.opportunity_id` est `NOT NULL` (0066) et
-- `opportunities_won_needs_approval` (0011) refuse un `closed_won` sans
-- `approval_id`. Les deux sont justes pour ce qu'elles gardent : **un document
-- commercial que la société a émis**, derrière un humain qui a approuvé les
-- termes qu'il facture. La conséquence, elle, n'était pas voulue : un euro ne
-- peut pas entrer dans ce registre sans qu'un humain ait approuvé une affaire.
--
-- Or Orizn vend en libre-service — 0 $ / 49 $ / 199 $ / dès 600 $, compte par
-- Google ou Apple, clé instantanée, abonnement pris sans parler à personne. Un
-- abonnement à 49 $ souscrit par carte à 3 h du matin n'a ni affaire, ni devis,
-- ni approbation : il n'entre nulle part. Et `crates/app/src/stripe.rs` ne
-- rattrape rien, parce qu'il **règle** une facture qui existe déjà chez nous
-- (reconnue par `metadata.invoice_number`) et n'en crée aucune.
--
-- `GET /v1/growth` le disait déjà, dans `unmeasured`, depuis le 2026-09-12 :
-- ces euros-là ne sont pas « d'origine inconnue », ils sont **hors de la
-- lecture**. Cette table est ce qui les y fait entrer, et elle les y fait
-- entrer **à côté** du registre de factures, jamais dedans.
--
-- ---------------------------------------------------------------------------
-- POURQUOI UNE TABLE POUR UNE CLÉ, ET NON UNE VARIABLE D'ENVIRONNEMENT
-- ---------------------------------------------------------------------------
--
-- `STRIPE_API_KEY` dans `config.rs` serait une ligne au lieu de ce fichier, et
-- ce serait la recette d'un locataire affichée sur l'écran d'un autre. Le
-- compte Stripe appartient à l'entreprise, pas au déploiement : la clé est donc
-- une colonne du locataire, sous RLS, comme `tenant_model_access.sealed_key`
-- (0050) est la clé de modèle du locataire et non celle de l'hébergeur.
--
-- ---------------------------------------------------------------------------
-- CE QU'IL N'Y A PAS ICI, ET C'EST DÉLIBÉRÉ
-- ---------------------------------------------------------------------------
--
-- **Aucune donnée Stripe.** Pas de cliché du MRR, pas de table d'abonnés, pas
-- de colonne « lu à ». `GET /v1/growth` appelle Stripe au moment où l'écran se
-- charge et ne garde rien. L'argument est celui de l'en-tête de
-- `apps/server/src/routes/growth.rs` : *chaque nombre sort de la table qui en
-- fait foi*, et la table qui fait foi du MRR d'Orizn est celle de Stripe. Un
-- cliché ici serait un **second endroit** où « notre recette » peut être vraie,
-- c'est-à-dire exactement ce que ce dépôt a déjà payé une fois (`docs/ORIZN.md`
-- publiait 76 $/mois en prose pendant que le calcul en disait un autre). Le
-- dépôt stocke ce qu'un tiers lui **pousse et signe** (`webhook_endpoints`,
-- 0053) et ce qu'il **mesure lui-même** (`model_usage_daily`, 0024) ; il n'a
-- nulle part un miroir de l'état courant d'un tiers, et ce fichier n'en ouvre
-- pas le premier.
--
-- **Aucune empreinte, aucun last-four, aucun `verified_at` public.**
-- L'argument de 0040 et de 0053, inchangé : un préfixe de credential est un
-- credential, et la seule question d'un opérateur est « y en a-t-il une », à
-- laquelle l'existence de la ligne répond. `connected_at` reste, parce qu'une
-- clé posée il y a six mois et une clé posée ce matin ne se lisent pas pareil —
-- c'est la colonne de `growth_targets.set_at`, pour la même raison.
--
-- **Aucun DELETE, et c'est le refus de 0041 mot pour mot.** « Débrancher
-- Stripe » n'est pas un verbe que ce produit offre : la forme utile de cette
-- demande est *rebrancher avec une autre clé*, ce que l'upsert ci-dessous fait.
-- Et il y a mieux ici que là-bas — la clé est **restreinte et lisible seule**,
-- donc le vrai débranchement est sa révocation dans le tableau de bord Stripe,
-- qui est le seul geste qui arrête réellement la lecture. Un `delete` accordé à
-- `app_role` n'ajouterait qu'une façon de perdre la ligne.

create table if not exists tenant_stripe_access (
  -- Une entreprise, un compte Stripe. Pas d'`id` : la clé est le locataire,
  -- ce qui rend une seconde clé concurrente non représentable plutôt
  -- qu'interdite par un index partiel que quelqu'un relira mal. Même forme que
  -- `tenant_model_access` (0041) et `growth_targets` (0101).
  tenant_id    uuid        primary key references tenants (id) on delete cascade,

  -- `Envelope::to_bytes`, AAD `stripe://<tenant>`. Un quatrième espace de clés
  -- après `secret://`, `mcp://` et `model://` : deux blobs de deux colonnes
  -- d'un même locataire ne doivent pas s'ouvrir l'un pour l'autre, et l'AAD du
  -- locataire ne suffit pas à l'empêcher puisque les deux lui appartiennent.
  --
  -- `not null` **et** non vide, pour la raison de 0014, 0040 et 0053 : une
  -- moitié scellée présente mais vide est une ligne qui croit porter une clé et
  -- n'ouvre rien.
  sealed_key   bytea       not null
                           constraint tenant_stripe_access_key_nonempty
                           check (octet_length(sealed_key) > 0),

  -- Quand la clé a été posée et prouvée. Écrasée par chaque pose, comme le
  -- reste de la ligne : `POST /v1/growth/stripe` vérifie la clé contre Stripe
  -- avant d'écrire, donc cette date est celle d'une lecture qui a réussi.
  connected_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, la forme de 0041 et de 0101, et ici pour la
-- raison la plus courte du schéma : cette ligne ouvre le compte Stripe d'une
-- entreprise. Le rôle propriétaire ne doit pas la lire par distraction non
-- plus, et `every_table_forces_row_level_security_and_checks_its_writes`
-- (`crates/store/src/db.rs`) refuserait la table sans les deux clauses.
alter table tenant_stripe_access enable row level security;
alter table tenant_stripe_access force row level security;
drop policy if exists tenant_isolation on tenant_stripe_access;
create policy tenant_isolation on tenant_stripe_access
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- `select` pour l'écran, `insert` et `update` pour l'upsert qu'est une
-- reconnexion. Pas de `delete` : voir l'en-tête. La suppression d'un locataire
-- cascade quand même, parce qu'elle tourne sous le rôle propriétaire.
grant select, insert, update on tenant_stripe_access to app_role;
revoke delete on tenant_stripe_access from app_role;
