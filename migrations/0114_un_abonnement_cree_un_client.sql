-- 0114_un_abonnement_cree_un_client : un client qui paie chez Stripe devient
-- une ligne de `contacts`, et la séquence qui l'accueille est celle que
-- l'opérateur a rattachée à son palier.
--
-- Mesuré le 2026-09-22 : les livraisons Stripe arrivent (0081) et ne
-- deviennent qu'un règlement de facture (`agentos_app::stripe`) ou une ligne
-- de MRR lue à la source (`stripe_subscriptions`). Un client qui vient de
-- payer 49 $ sur `visa.orizn.app` n'existe dans aucune table d'ici : pas de
-- compte, pas de contact, personne pour lui écrire. Trois colonnes le font
-- entrer par la porte qui existe déjà — `upsert_contact`, la seule voie
-- d'écriture, pour la raison de 0107 — sans en ouvrir une seconde.
--
-- # `contacts.stripe_customer` : la clé de jointure, pas l'attribution
--
-- Les événements de Stripe se répondent par l'identifiant du **client**
-- (`cus_…`) : il est sur `customer.created` avec l'adresse, sur
-- `checkout.session.completed` avec l'adresse aussi, et sur chaque
-- `customer.subscription.*` — qui, eux, ne portent aucune adresse. Il faut
-- donc retrouver un contact par ce `cus_…`, et `origin_ref` ne peut pas le
-- porter : un prospect importé qui finit par s'abonner garde `origin =
-- 'import'` et le nom de sa liste — c'est exactement la chaîne que 0107 a
-- construite pour dire quelle liste a produit l'euro — et l'écraser par
-- `stripe:…` détruirait l'attribution au moment où elle sert. Une colonne à
-- part, écrite sur un contact neuf comme sur un contact retrouvé, et unique
-- par locataire : deux contacts pour un client Stripe seraient deux parcours
-- d'accueil.
--
-- # `origin = 'stripe'` : une troisième porte, pour un contact neuf seulement
--
-- 0107 ferme `origin` sur `import` et `discovery`. Un client venu de nulle
-- part — pas de liste, pas de page — est une troisième porte, et la plus
-- rentable : la vente au prix affiché. `origin_ref = 'stripe:<cus_…>'` sur
-- ces lignes-là. La contrainte est reposée entière (`drop` puis `add`) parce
-- qu'une CHECK ne s'élargit pas autrement ; 0107 n'est pas touchée.
--
-- # `sequences.welcomes_tier` : le parcours est celui de l'opérateur
--
-- Aucun texte de mail ici, ni dans le code : une séquence (0092) est déjà
-- une liste de briefs que le siège rédige derrière la Gate. Ce qui manquait
-- est le lien entre un palier et une séquence. `welcomes_tier` est le nom du
-- palier tel que Stripe le nomme (`price.nickname`, en minuscules — `starter`,
-- `gratuit` —, ou `lookup_key`, ou l'id du prix), et trois mots réservés :
-- `upgrade`, `downgrade`, `churned`. NULL veut dire « pas un parcours
-- d'accueil », ce qu'est toute séquence existante. Pas d'unicité : deux
-- séquences vivantes pour un palier, c'est la plus récente qui accueille, et
-- l'opérateur archive l'autre.
--
-- Rejouable : `add column if not exists`, `drop constraint if exists`,
-- `create unique index if not exists`.

alter table contacts  add column if not exists stripe_customer text;
alter table sequences add column if not exists welcomes_tier   text;

create unique index if not exists contacts_stripe_customer_key
  on contacts (tenant_id, stripe_customer)
  where stripe_customer is not null;

alter table contacts drop constraint if exists contacts_origin;
alter table contacts
  add constraint contacts_origin
    check (origin is null or origin in ('import', 'discovery', 'stripe'));

comment on column contacts.stripe_customer is
  'L''identifiant client chez Stripe (cus_…), la cle par laquelle un '
  'evenement d''abonnement retrouve cette personne. Ecrit sur un contact neuf '
  'comme sur un prospect qui s''abonne ; jamais l''attribution, qui est origin.';
comment on column sequences.welcomes_tier is
  'Le palier que cette sequence accueille (price.nickname en minuscules, ou '
  'upgrade / downgrade / churned). NULL : pas un parcours d''accueil.';
