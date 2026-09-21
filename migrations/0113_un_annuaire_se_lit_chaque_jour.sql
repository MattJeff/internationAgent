-- 0113_un_annuaire_se_lit_chaque_jour : la liste des annuaires qu'un
-- locataire fait relire chaque jour, et le jour où chacun l'a été.
--
-- Mesuré le 2026-09-21 : la liste importée (1 300 contacts Apollo) était une
-- liste de CTO d'éditeurs de logiciels, et le siège commercial a refusé les
-- cinq inscrits du jour, à raison — « aucun tunnel de réservation chez eux ».
-- Les acheteurs d'Orizn sont des voyagistes, des OTA, des assureurs voyage,
-- des compagnies, des TMC, et ils sont **dans des annuaires publics** :
-- adhérents d'une fédération, agences accréditées, membres d'une chambre.
-- `POST /v1/prospects/discover` (0107) sait lire une telle page ; il fallait
-- qu'un opérateur le fasse, page par page, chaque matin.
--
-- ---------------------------------------------------------------------------
-- UNE TABLE, PAS DEUX COLONNES SUR UNE SÉQUENCE
-- ---------------------------------------------------------------------------
--
-- Le flux d'une séquence (0111) est un attribut : une séquence n'en a qu'un.
-- Un annuaire, lui, n'appartient à rien d'autre qu'au locataire, et un
-- locataire en a plusieurs — la fédération de son pays, celle du voisin, la
-- liste des accrédités IATA. C'est une relation, donc une table. Chaque ligne
-- est une page, un segment, un siège dont le budget et la Gate s'appliquent,
-- une heure, et trois compteurs qui disent ce que la page a rendu.
--
-- `read_on` est le dernier jour UTC lu, et il fait « une fois par jour au
-- plus » sans horloge ni verrou, exactement comme `sequences.fed_on` : la
-- boucle lit quand `read_on < aujourd'hui`, et l'UPDATE qui le pose est la
-- réclamation elle-même. `hour` a 7 pour défaut, une heure avant le flux des
-- séquences (8) : ce que l'annuaire rend ce matin est ce que le flux inscrit
-- ce matin.
--
-- `host` est l'hôte de `url`, à part, pour l'unicité : deux pages d'un même
-- site sont deux lectures par jour du même tiers, et la seconde n'apporte que
-- des adresses que la première a déjà vues. Un annuaire, c'est un hôte.
--
-- `failures` compte les jours consécutifs sans lecture. Au troisième la source
-- passe `last_outcome = 'stalled'` et n'est plus relue : une page qui refuse
-- trois matins de suite a déménagé, ou nous refuse, et la relire chaque jour
-- serait exactement le crawler que `browser_http` dit ne pas être. La reposer
-- (`remove` + `add`) est le geste d'un humain qui a regardé.
--
-- Pas de `other` : le CHECK est celui d'`accounts_segment` (0011) moins ce
-- mot. Un annuaire vaut par le segment qu'il nourrit, et le siège commercial
-- ne sait rien reproduire d'un compte rangé sous `other`.
--
-- Rejouable : `create table if not exists`, `drop policy if exists`.

create table if not exists discovery_sources (
  id             uuid        primary key,
  tenant_id      uuid        not null references tenants (id) on delete cascade,
  url            text        not null
                             constraint discovery_sources_url_nonempty
                             check (length(url) > 0),
  host           text        not null,
  segment        text        not null
                             constraint discovery_sources_segment check (segment in (
                               'airline', 'ota', 'corporate_travel', 'tmc', 'insurer',
                               'cruise', 'relocation'
                             )),
  country        text        constraint discovery_sources_country_iso
                             check (country is null or country ~ '^[A-Z]{2}$'),
  employee_id    uuid        not null,
  hour           smallint    not null default 7
                             constraint discovery_sources_hour check (hour between 0 and 23),
  read_on        date,
  pages_read     integer     not null default 0,
  contacts_added integer     not null default 0,
  failures       smallint    not null default 0,
  last_outcome   text,
  created_at     timestamptz not null default now(),
  constraint discovery_sources_one_per_host unique (tenant_id, host),
  -- `0103` : une clé vers `employees` porte le locataire, sinon Postgres la
  -- vérifie hors de la RLS et un locataire peut poser une source sur le siège
  -- d'un autre.
  foreign key (tenant_id, employee_id) references employees (tenant_id, id) on delete cascade
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, la forme de 0108 ; `delete` accordé parce que
-- retirer un annuaire est un verbe de ce produit (`discovery_sources_remove`),
-- et la seule façon de faire repartir une source `stalled`.
alter table discovery_sources enable row level security;
alter table discovery_sources force row level security;
drop policy if exists tenant_isolation on discovery_sources;
create policy tenant_isolation on discovery_sources
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

grant select, insert, update, delete on discovery_sources to app_role;
