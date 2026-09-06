-- 0090_un_devis_est_un_document_revisable : ce que le client a accepté, écrit
-- avant qu'on le facture.
--
-- ---------------------------------------------------------------------------
-- LE TROU
-- ---------------------------------------------------------------------------
--
-- `opportunities` (0011) passe de `negotiation` à `closed_won` en une seule
-- écriture, et `invoices` (0066, 0071) démarre à `closed_won`. Entre les deux
-- il n'y a rien : aucune ligne ne dit ce qui a été proposé, à quel prix, sur
-- quel périmètre, ni jusqu'à quand l'offre tenait. `opportunity_events` a bien
-- un `proposal_sent`, mais c'est un événement — il nomme un contact et une
-- date, pas un montant, pas une ligne, pas une durée. Un employé peut donc
-- prospecter, convaincre et facturer sans qu'aucune ligne ne dise **ce que le
-- client a accepté**.
--
-- Cette table est ce document.
--
-- ---------------------------------------------------------------------------
-- POURQUOI ELLE NE S'APPELLE PAS `quotes`
-- ---------------------------------------------------------------------------
--
-- Parce que `quotes` existe déjà, et que c'est l'autre sens de la flèche :
-- `0007_sourcing.sql` la crée pour la verticale acheteur — l'offre qu'un
-- **fournisseur** nous fait contre une demande de prix. Réutiliser le nom
-- ferait tenir deux documents opposés dans une table, avec deux RLS à
-- réconcilier et un lecteur qui ne sait plus de quel côté de la vente il est.
-- `sales_quotes` dit le côté ; le module `agentos_store::quotes` le redit en
-- une phrase à son en-tête.
--
-- ---------------------------------------------------------------------------
-- TROIS DIFFÉRENCES AVEC `invoices`, ET AUCUNE N'EST COSMÉTIQUE
-- ---------------------------------------------------------------------------
--
-- Le devis est écrit sur le modèle de la facture — mêmes parties, mêmes lignes,
-- même ventilation — et en diffère sur trois points qui sont chacun une
-- colonne :
--
-- 1. **`valid_until`, et il est NOT NULL.** Une facture est due ; un devis
--    expire. C'est la seule mention obligatoire d'un devis français que ce
--    schéma peut porter tout seul, et elle est la garde de `accept` : une offre
--    périmée n'est pas une offre qu'on relance, c'en est une qu'on réémet. NOT
--    NULL parce qu'un devis sans durée est une offre ouverte indéfiniment,
--    c'est à dire un engagement que personne n'a pris volontairement.
--
-- 2. **Aucun numéro de séquence.** `invoice_counters` (0071) existe parce
--    qu'une facture est une pièce comptable et qu'un trou dans la suite se lit
--    comme une suppression. Un devis n'est pas une pièce comptable : il n'entre
--    dans aucun livre, l'administration ne le compte pas, et lui donner un
--    numéro sans trou coûterait exactement ce que 0071 nomme comme son prix —
--    **l'émission sérialise par entreprise**. Faire attendre un commercial
--    derrière un autre pour un document qui n'a aucune obligation de suite est
--    un coût payé pour rien. Le couple `(id, version)` est la référence qu'un
--    humain cite, et `id` est un uuid v7 : unique, non devinable, ordonné.
--
-- 3. **Il se révise.** Une facture fausse est corrigée par un second document
--    qui la retire (0071, l'avoir) ; un devis refusé est *rejoué* — même
--    affaire, autre prix. `supersedes_quote_id` est ce lien, et la révision est
--    **une nouvelle ligne**, jamais une écriture sur l'ancienne : ce qui a été
--    proposé lundi doit rester lisible le jour où l'on discute de ce qui a été
--    proposé vendredi. Le déclencheur plus bas est ce qui rend cette phrase
--    vraie plutôt que promise.
--
-- ---------------------------------------------------------------------------
-- CE QUI FAIT QU'UN DEVIS EST PÉRIMÉ, ET OÙ C'EST DÉCIDÉ
-- ---------------------------------------------------------------------------
--
-- Nulle part ici. Il n'y a **pas** de colonne `expired`, pas de tâche qui
-- balaye, pas d'état à maintenir : un devis est périmé quand `valid_until` est
-- passé, et c'est une comparaison, pas un fait à écrire. Une colonne d'état
-- serait une deuxième réponse à la même question, fausse pendant l'intervalle
-- entre l'expiration et le passage du balai — et c'est précisément l'intervalle
-- où quelqu'un accepterait ce qui n'est plus offert.
--
-- La garde est donc dans la clause `WHERE` de l'acceptation
-- (`agentos_store::quotes::accept`), avec le `now` du transaction, et le
-- CHECK `sales_quotes_validity_is_a_future` en dessous garantit qu'aucune ligne
-- ne naît déjà morte.
--
-- ---------------------------------------------------------------------------
-- QUI RÉPOND
-- ---------------------------------------------------------------------------
--
-- Le client. Rien dans ce processus ne l'observe : comme pour `invoices.
-- paid_at` (0066), « il a accepté » n'est pas mesuré, il est **affirmé** — par
-- un opérateur, jamais par le siège qui a émis le devis. Un employé qui pourrait
-- déclarer acceptés ses propres devis a un pipeline impeccable et pas un client.
-- `apps/server/src/routes/quotes.rs` porte la séparation des tâches, et c'est
-- exactement l'argument de `POST /v1/invoices/{id}/paid`.
--
-- Le jour où une signature électronique arrive par un webhook, l'écrivain de
-- ces deux colonnes n'est toujours pas un employé, et ce que la table gagne ce
-- jour-là est une colonne `accepted_source` à côté — parce que « qui l'a dit »
-- aura deux réponses pour la première fois. Elle en a une aujourd'hui.

create table if not exists sales_quotes (
  id                  uuid        primary key,

  tenant_id           uuid        not null references tenants (id) on delete cascade,

  -- L'affaire qu'il chiffre. Composite contre `opportunities_tenant_id_key`
  -- (0011), comme partout ici : un devis ne peut pas nommer l'affaire d'une
  -- autre entreprise même si quelqu'un en connaît l'identifiant.
  opportunity_id      uuid        not null,

  -- Le siège qui l'a proposé. **uuid nu**, l'argument de `invoices.issued_by`
  -- (0066) mot pour mot : `on delete set null` est un UPDATE que le déclencheur
  -- ci-dessous refuse, et `on delete restrict` ferait qu'un devis bloque la
  -- fermeture d'un siège.
  issued_by           uuid        not null,

  -- Le couple `Money`, comme `invoices` et `opportunities`.
  currency            text        not null
                                  constraint sales_quotes_currency_iso
                                  check (currency ~ '^[A-Z]{3}$'),
  amount_minor        bigint      not null
                                  constraint sales_quotes_amount_positive
                                  check (amount_minor > 0),

  -- L'objet, en une ligne. Même borne que `invoices_memo_shape` (0066), reprise
  -- plutôt qu'inventée.
  memo                text        not null
                                  constraint sales_quotes_memo_shape
                                  check (char_length(btrim(memo)) between 1 and 200),

  -- Le rang dans la chaîne de révisions. 1 pour le premier, +1 par révision.
  -- Dérivable de la chaîne, et stocké quand même : c'est ce qu'un humain lit
  -- sur le PDF (« Devis v2 »), et le calculer à chaque lecture demanderait de
  -- remonter la chaîne pour afficher un titre.
  version             int         not null default 1
                                  constraint sales_quotes_version_positive
                                  check (version >= 1),

  -- Le devis que celui-ci remplace. `NULL` sur le premier, et c'est ce qui fait
  -- de cette ligne un original plutôt qu'une révision — il n'y a pas de colonne
  -- `kind`, pour la raison que 0071 donne de `corrects_invoice_id` : une
  -- deuxième colonne qui doit s'accorder avec celle-ci est un deuxième endroit
  -- où la vérité peut être.
  supersedes_quote_id uuid,

  issued_at           timestamptz not null default now(),

  -- **La durée de validité, matérialisée.** Voir l'en-tête.
  valid_until         timestamptz not null,

  -- La réponse du client, affirmée par un opérateur. `NULL` sur les deux :
  -- personne n'a répondu.
  accepted_at         timestamptz,
  declined_at         timestamptz,

  -- Un devis qui naît périmé est un devis que personne ne peut accepter, donc
  -- un document qui n'aurait pas dû partir. Strict : `valid_until = issued_at`
  -- est une offre valable zéro seconde.
  constraint sales_quotes_validity_is_a_future
    check (valid_until > issued_at),

  -- On répond une fois et dans un sens. Le déclencheur plus bas empêche de
  -- revenir sur la réponse ; ce CHECK empêche d'en donner deux d'un coup.
  constraint sales_quotes_one_answer
    check (accepted_at is null or declined_at is null),

  -- Un original est une v1 et une révision ne l'est pas. Les deux colonnes
  -- disent la même chose et cette contrainte est ce qui les empêche de se
  -- contredire.
  constraint sales_quotes_version_follows_the_chain
    check ((version = 1) = (supersedes_quote_id is null)),

  constraint sales_quotes_opportunity_fk
    foreign key (tenant_id, opportunity_id) references opportunities (tenant_id, id)
    on delete cascade,

  constraint sales_quotes_tenant_id_key unique (tenant_id, id),

  -- Auto-référence composite, même raison que partout : une révision ne
  -- remplace pas le devis d'une autre entreprise.
  constraint sales_quotes_supersedes_fk
    foreign key (tenant_id, supersedes_quote_id) references sales_quotes (tenant_id, id)
    on delete cascade
);

-- **Une seule révision par devis**, et cet index fait un travail de
-- concurrence et pas de rangement : sans lui, deux commerciaux qui révisent le
-- même devis au même instant lisent tous les deux une chaîne non ramifiée dans
-- leur propre instantané et écrivent tous les deux — et « le devis en cours »
-- cesse d'avoir une réponse. Avec lui le second bloque puis perd, ce qui est le
-- mécanisme de `invoices_one_credit_note_per_invoice_idx` (0071) exactement.
--
-- La conséquence est ce qui rend la chaîne lisible : elle est **linéaire**.
-- « Le devis en cours » est celui que personne ne remplace, et c'est un
-- anti-jointure d'une ligne.
create unique index if not exists sales_quotes_one_revision_per_quote_idx
  on sales_quotes (supersedes_quote_id)
  where supersedes_quote_id is not null;

-- Le registre : ce que cette affaire a proposé, dans l'ordre.
create index if not exists sales_quotes_opportunity_idx
  on sales_quotes (tenant_id, opportunity_id, version);

-- ---------------------------------------------------------------------------
-- L'IMMUTABILITÉ, ET LES DEUX SEULES COLONNES QUI BOUGENT
-- ---------------------------------------------------------------------------
--
-- Le devis que le client a reçu est un PDF qu'il garde. Une ligne qu'on peut
-- réécrire est une ligne qui finit par ne plus dire ce que dit la copie qu'il
-- tient — c'est l'argument de `invoices_are_issued_once` (0066), et il vaut
-- ici, à ceci près que le remède n'est pas un avoir mais une révision.
--
-- Deux colonnes bougent, et une seule fois chacune : la réponse du client. Le
-- déclencheur refuse d'y revenir, parce qu'un devis « accepté puis désaccepté »
-- est un document dont personne ne peut dire s'il engage.
--
-- Il lie le propriétaire et les superutilisateurs, ce que le GRANT par colonne
-- plus bas ne fait pas — la même ceinture-et-bretelles que 0066.
create or replace function sales_quotes_are_revised_never_edited() returns trigger
language plpgsql as $$
begin
  if row(new.id, new.tenant_id, new.opportunity_id, new.issued_by, new.currency,
         new.amount_minor, new.memo, new.version, new.supersedes_quote_id,
         new.issued_at, new.valid_until)
     is distinct from
     row(old.id, old.tenant_id, old.opportunity_id, old.issued_by, old.currency,
         old.amount_minor, old.memo, old.version, old.supersedes_quote_id,
         old.issued_at, old.valid_until)
  then
    raise exception 'a quote is revised by a new version, never edited: %', old.id
      using errcode = 'restrict_violation';
  end if;

  if (old.accepted_at is not null and new.accepted_at is distinct from old.accepted_at)
     or (old.declined_at is not null and new.declined_at is distinct from old.declined_at)
  then
    raise exception 'quote % has already been answered', old.id
      using errcode = 'restrict_violation';
  end if;

  return new;
end
$$;

drop trigger if exists sales_quotes_are_revised_never_edited on sales_quotes;
create trigger sales_quotes_are_revised_never_edited
  before update on sales_quotes
  for each row execute function sales_quotes_are_revised_never_edited();

alter table sales_quotes enable row level security;
alter table sales_quotes force row level security;
drop policy if exists tenant_isolation on sales_quotes;
create policy tenant_isolation on sales_quotes
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- `update (accepted_at, declined_at)` et pas un UPDATE de table : le privilège
-- dit ce que le déclencheur redit, et c'est 0066 et 0071 pour `paid_at` et
-- `last_number`. DELETE est refusé ; la cascade depuis `tenants` marche quand
-- même, parce qu'une cascade s'exécute avec les droits du propriétaire.
grant select, insert on sales_quotes to app_role;
grant update (accepted_at, declined_at) on sales_quotes to app_role;
revoke delete on sales_quotes from app_role;

-- ---------------------------------------------------------------------------
-- LES LIGNES
-- ---------------------------------------------------------------------------
--
-- `invoice_lines` (0071) en tous points, et pour la même raison : c'est là
-- qu'un taux de TVA peut être porté, parce qu'un taux est par ligne. La forme
-- identique n'est pas une coïncidence — c'est ce qui fait que le total d'un
-- devis accepté est *le même calcul* que celui de la facture qui le reprend, et
-- pas un second calcul qui pourrait en différer d'un centime.
-- `agentos_app::quote_document` appelle la ventilation de
-- `agentos_app::invoice_document`, sans en écrire une deuxième.
create table if not exists sales_quote_lines (
  tenant_id     uuid   not null references tenants (id) on delete cascade,

  quote_id      uuid   not null,

  position      int    not null
                       constraint sales_quote_lines_position_positive
                       check (position >= 1),

  description   text   not null
                       constraint sales_quote_lines_description_shape
                       check (char_length(btrim(description)) between 1 and 200),

  -- Signé : une remise est une ligne négative, et la tête reste positive.
  -- Zéro est refusé, pour la raison de `Money::new` — une ligne qui ne vaut
  -- rien est une phrase, et `description` porte déjà les phrases.
  amount_minor  bigint not null
                       constraint sales_quote_lines_amount_nonzero
                       check (amount_minor <> 0),

  -- Le taux, en points de base. `NULL` veut dire « celui de l'émetteur »
  -- (`tenants.vat_rate_bp`, 0087), et un `0` veut dire « hors TVA » — jamais
  -- « TVA à 0 % ». Voir `agentos_app::invoice_document::ventilate`.
  tax_rate_bp   int    constraint sales_quote_lines_tax_rate_not_negative
                       check (tax_rate_bp is null or tax_rate_bp >= 0),

  constraint sales_quote_lines_quote_fk
    foreign key (tenant_id, quote_id) references sales_quotes (tenant_id, id)
    on delete cascade,

  constraint sales_quote_lines_pkey primary key (quote_id, position)
);

-- Les lignes totalisent le document, vérifié au commit — 0071 mot pour mot,
-- déclencheur de contrainte différé compris, parce que la tête doit exister
-- avant ses lignes et que chaque ligne arrive sur son propre INSERT.
--
-- Et la même deuxième propriété, qui est celle qui vaut le différé : **une
-- ligne ne peut pas être ajoutée à un devis qui en avait déjà**, dans aucune
-- transaction ultérieure, puisque la somme collait et qu'une ligne de plus la
-- fait cesser de coller. Un devis émis ne pousse pas une ligne.
create or replace function sales_quote_lines_total_the_document() returns trigger
language plpgsql as $$
declare
  head  bigint;
  lines bigint;
begin
  -- Les deux lectures reviennent NULL ensemble quand un locataire est supprimé,
  -- et `is distinct from` appelle deux NULL un accord : la cascade passe sans
  -- bras dédié. Voir 0071.
  select amount_minor into head from sales_quotes where id = new.quote_id;
  select sum(amount_minor) into lines from sales_quote_lines where quote_id = new.quote_id;
  if lines is distinct from head then
    raise exception 'quote % offers % but its lines total %', new.quote_id, head, lines
      using errcode = 'restrict_violation';
  end if;
  return null;
end
$$;

drop trigger if exists sales_quote_lines_total_the_document on sales_quote_lines;
create constraint trigger sales_quote_lines_total_the_document
  after insert on sales_quote_lines
  deferrable initially deferred
  for each row execute function sales_quote_lines_total_the_document();

alter table sales_quote_lines enable row level security;
alter table sales_quote_lines force row level security;
drop policy if exists tenant_isolation on sales_quote_lines;
create policy tenant_isolation on sales_quote_lines
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Aucun UPDATE, pas même une colonne : une ligne n'a pas de champ qui arrive
-- plus tard. C'est le GRANT de `invoice_lines` (0071) et de `files` (0067).
grant select, insert on sales_quote_lines to app_role;
revoke update, delete on sales_quote_lines from app_role;

-- ---------------------------------------------------------------------------
-- LE PIPELINE, QUI DOIT POUVOIR LE DIRE
-- ---------------------------------------------------------------------------
--
-- `opportunity_events` (0011) est la trace de ce qui est arrivé à une affaire,
-- et son vocabulaire s'arrête à `proposal_sent` : « une proposition est
-- partie », sans montant, sans document, et sans réponse possible. Un lecteur
-- de la chronologie voyait donc une affaire passer de `proposal_sent` à
-- `stage_changed → closed_won` sans que rien entre les deux ne dise ce qui
-- avait été accepté.
--
-- **On ajoute, on ne renomme pas.** `proposal_sent` reste ce qu'il est et garde
-- ses lignes ; les trois valeurs ci-dessous sont ce qu'il ne pouvait pas dire.
-- Le lien vers `sales_quotes` est ce qui les rend vérifiables : un événement
-- « devis accepté » qui ne nomme pas le devis est une humeur, exactement ce que
-- 0011 dit d'une objection sans `objection`.
alter table opportunity_events
  add column if not exists quote_id uuid;

alter table opportunity_events drop constraint if exists opportunity_events_kind;
alter table opportunity_events add constraint opportunity_events_kind check (kind in (
  'outreach_sent', 'reply_received', 'call_held', 'meeting_held',
  'evidence_shared', 'proposal_sent', 'objection_raised', 'objection_answered',
  'stage_changed', 'opt_out_received', 'no_response',
  'quote_issued', 'quote_accepted', 'quote_declined'
));

-- Le lien nomme le document, dans les deux sens : les trois genres l'exigent,
-- et personne d'autre ne peut le porter — un `outreach_sent` qui désignerait un
-- devis serait un deuxième endroit où lire « le devis est parti ».
alter table opportunity_events drop constraint if exists opportunity_events_has_quote;
alter table opportunity_events add constraint opportunity_events_has_quote
  check ((quote_id is not null)
         = (kind in ('quote_issued', 'quote_accepted', 'quote_declined')));

-- Composite, comme `opportunity_events_evidence_fk` juste à côté : un événement
-- ne peut pas nommer le devis d'une autre entreprise. Pas de `on delete
-- cascade` — `sales_quotes` ne se supprime pas, et la cascade depuis `tenants`
-- prend les deux tables ensemble.
alter table opportunity_events drop constraint if exists opportunity_events_quote_fk;
alter table opportunity_events add constraint opportunity_events_quote_fk
  foreign key (tenant_id, quote_id) references sales_quotes (tenant_id, id);

comment on column opportunity_events.quote_id is
  'Le devis dont parle cet événement. NOT NULL exactement sur les trois genres '
  'de devis, NULL partout ailleurs : « devis accepté » sans le devis serait une '
  'affirmation que personne ne peut relire.';

comment on table sales_quotes is
  'Ce qui a été proposé à un prospect, et ce qu''il en a dit. Le chaînon entre '
  '`opportunities` (0011) et `invoices` (0066) : la facture reprend le total '
  'd''un devis accepté. À ne pas confondre avec `quotes` (0007), qui est '
  'l''offre qu''un fournisseur nous fait.';
