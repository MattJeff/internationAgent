-- 0094_un_locataire_tourne_sur_plusieurs_domaines : un locataire envoie
-- depuis plusieurs domaines, chacun sous un plafond journalier.
--
-- Mesuré le 2026-09-10, le jour où 0093 a été déployé : Orizn a
-- `agents.getorizn.com` vérifié et un second domaine, `agent.oriznapi.uk`,
-- vérifié chez Resend et inutilisé — parce que `tenant_domains` a `tenant_id`
-- pour clé primaire et qu'un locataire n'a qu'une ligne. Or la prospection à
-- volume ne se fait pas depuis un domaine : c'est ce que Smartlead et Lumail
-- vendent sous « sending domains » — N domaines, chacun sous un plafond de
-- quelques dizaines de mails par jour, pour que la réputation d'aucun ne
-- s'effondre et qu'un domaine grillé n'emporte pas les autres.
--
-- ---------------------------------------------------------------------------
-- PLUSIEURS LIGNES PAR LOCATAIRE, UNE PRIMAIRE
-- ---------------------------------------------------------------------------
--
-- La clé primaire devient `(tenant_id, domain)`. `domain` reste unique dans
-- toute la base : un domaine est à un locataire, pour la raison que 0093
-- donne (le fournisseur ne distinguerait pas deux locataires sous un même
-- nom). `is_primary` marque **la** ligne dont les sièges lisent le domaine
-- (`POST /v1/org`, `POST /v1/employees` sans `domain` dans le corps) et qui
-- répond à `GET /v1/domain` — le contrat de la console tient. L'index unique
-- partiel est ce qui en interdit deux ; `sending_domain::register` fait de la
-- première ligne la primaire, et la ligne qui existe déjà — celle d'Orizn est
-- en production — le devient ici, sans geste.
--
-- `daily_cap` est fixe, posé à la main (`PUT /v1/domains/{domain}/cap`) :
-- 50 par défaut, ce que Smartlead recommande pour un domaine tiède. Ce n'est
-- pas une rampe de warm-up — voir `sending_domain.rs`, c'est l'étape suivante.
--
-- ---------------------------------------------------------------------------
-- LE COMPTEUR EST RÉSERVÉ, PAS COMPTÉ — LA FORME DE 0055
-- ---------------------------------------------------------------------------
--
-- `domain_send_buckets (tenant_id, domain, day, sent)` est `outreach_buckets`
-- avec le domaine à la place de l'employé. Le plafond n'est jamais lu puis
-- écrit : `sending_domain::pick_from` fait
-- `INSERT … ON CONFLICT DO UPDATE SET sent = sent + 1 WHERE sent < cap
-- RETURNING`, et deux tours concurrents qui liraient « 49 de 50 » ne peuvent
-- pas envoyer tous les deux — 0055 argue pourquoi un `count(*)` ne peut pas
-- être verrouillé et pourquoi une ligne compteur est la seule forme qui
-- sérialise. UTC pour le jour, comme 0016 et 0055 : il n'y a pas de
-- `tenants.timezone`.
--
-- Pas de verbe de relâche, pour la raison de 0055 : un mail que le
-- fournisseur a refusé a quand même été tenté depuis ce domaine, et une place
-- rendue est la place qu'une boucle de réessai prendrait pour envoyer dix
-- fois.

alter table tenant_domains drop constraint if exists tenant_domains_pkey;
alter table tenant_domains add primary key (tenant_id, domain);

alter table tenant_domains
  add column if not exists is_primary boolean not null default false,
  add column if not exists daily_cap  integer not null default 50
    constraint tenant_domains_daily_cap_positive check (daily_cap > 0);

-- Une seule primaire par locataire.
create unique index if not exists tenant_domains_one_primary
  on tenant_domains (tenant_id) where is_primary;

-- La ligne qui existe est, par construction de 0093, la seule de son
-- locataire : elle devient primaire.
update tenant_domains set is_primary = true where not is_primary;

-- `DELETE /v1/domains/{domain}` retire un domaine secondaire — 0093 refusait
-- le `delete` parce qu'un locataire n'avait qu'un domaine et que le retirer
-- était « changer de domaine ». Retirer un secondaire ne change rien aux
-- sièges ; la primaire, elle, reste sans `DELETE` (`sending_domain::remove`
-- refuse, `primary_domain`).
grant delete on tenant_domains to app_role;

create table if not exists domain_send_buckets (
  tenant_id   uuid        not null,
  domain      text        not null,
  -- UTC. Voir 0016, « WHICH DAY ».
  day         date        not null,
  sent        integer     not null default 0,
  updated_at  timestamptz not null default now(),
  primary key (tenant_id, domain, day),
  foreign key (tenant_id, domain) references tenant_domains (tenant_id, domain)
    on delete cascade,
  constraint domain_send_buckets_nonnegative check (sent >= 0)
);

alter table domain_send_buckets enable row level security;
alter table domain_send_buckets force row level security;
drop policy if exists tenant_isolation on domain_send_buckets;
create policy tenant_isolation on domain_send_buckets
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Pas de `delete`, exactement comme `outreach_buckets` : c'est le registre de
-- ce qui est parti depuis chaque domaine, et un registre dont on efface des
-- lignes n'en est pas un. La suppression d'un domaine cascade, en propriétaire.
grant select, insert, update on domain_send_buckets to app_role;
revoke delete on domain_send_buckets from app_role;
