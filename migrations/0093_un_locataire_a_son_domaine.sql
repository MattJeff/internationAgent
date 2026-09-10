-- 0093_un_locataire_a_son_domaine : le domaine d'envoi est au locataire, pas
-- au déploiement — et il est vérifié chez le fournisseur avant qu'un siège
-- s'y assoie.
--
-- Mesuré en production le 2026-09-10 : le domaine d'envoi était une variable
-- par déploiement (`AGENT_EMAIL_DOMAIN` → `EmailCredentials::domain` →
-- `ResendEmailProvider::new(…, domain)`), et `ensure_identity` réconciliait
-- ce nom-là sans regarder la fiche de l'employé. Or chaque employé porte déjà
-- son domaine (`employees.domain`, posé par `POST /v1/org` et
-- `POST /v1/employees`) et son adresse est `slug@domain`. Rien ne vérifiait
-- que ce domaine existe chez le fournisseur : Orizn a tourné cinq jours sur
-- `agent-orizn.com`, un domaine que personne ne possède, et le premier mail
-- aurait été le premier signal.
--
-- ---------------------------------------------------------------------------
-- UN DOMAINE PAR LOCATAIRE, UN LOCATAIRE PAR DOMAINE
-- ---------------------------------------------------------------------------
--
-- `tenant_id` est la clé primaire : un locataire a un domaine. `domain` est
-- unique : un domaine est à un locataire — deux entreprises derrière un même
-- compte Resend (`docs/PROVIDERS.md`, « More than one customer on one provider
-- account ») ne peuvent pas envoyer sous le même nom, parce que le fournisseur
-- ne les distinguerait pas non plus. Changer de domaine n'est pas une mise à
-- jour de cette ligne : les adresses déjà imprimées dans des mails partis
-- vivent sur l'ancien, et « re-adresser une entreprise » est une autre
-- histoire que ce dépôt n'a pas encore écrite (`sending_domain::register`
-- répond 409 `another_domain`).
--
-- `status` suit le fournisseur en trois mots — `pending` tant que le DNS n'est
-- pas vu, `verified` quand DKIM + SPF le sont, `failed` quand il a renoncé —
-- et `records` recopie tels quels les enregistrements qu'il demande, pour que
-- la console les affiche et que `POST /v1/domain/dns` les pose. Le MX de
-- réception n'y est **pas** tant que la réception n'est pas activée côté
-- fournisseur ; `region` est gardée pour le dériver plutôt que l'inventer.
--
-- Un siège dont le domaine n'est pas `verified` attend en `pending_external`
-- (`employee_resources`, 0001) avec l'id fournisseur du domaine pour
-- `poll_ref` ; `sending_domain::verify` réveille ces sièges quand le
-- fournisseur dit oui.

create table if not exists tenant_domains (
  tenant_id           uuid        primary key references tenants (id) on delete cascade,

  -- Minuscules, au moins deux étiquettes, un TLD alphabétique : la forme que
  -- `Domain::parse` accepte, redite ici pour qu'un `INSERT` direct ne puisse
  -- pas y déposer autre chose.
  domain              text        not null unique
                                  constraint tenant_domains_domain_shape
                                  check (domain = lower(domain)
                                         and domain ~ '^[a-z0-9.-]+\.[a-z]{2,}$'),

  -- `resend`, ou `mock-email` sur un déploiement à blanc.
  provider            text        not null,
  provider_domain_id  text,
  region              text,

  status              text        not null
                                  constraint tenant_domains_status
                                  check (status in ('pending', 'verified', 'failed')),
  records             jsonb       not null default '[]',

  created_at          timestamptz not null default now(),
  -- Dernière relecture chez le fournisseur, quel qu'en soit le verdict.
  checked_at          timestamptz,
  -- Premier `verified` vu ; reste posé si le fournisseur repasse `failed`.
  verified_at         timestamptz
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, comme `unsubscribe_links` (0085) et
-- `message_events` (0091) : le rôle propriétaire ne lit pas non plus le
-- domaine des autres par distraction.

alter table tenant_domains enable row level security;
alter table tenant_domains force row level security;
drop policy if exists tenant_isolation on tenant_domains;
create policy tenant_isolation on tenant_domains
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Pas de `delete` : un domaine ne se retire pas d'un locataire par l'API, il
-- meurt avec lui, par cascade.
grant select, insert, update on tenant_domains to app_role;
