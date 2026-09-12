-- 0105_une_signature_est_un_constat : le pli envoyé en signature, et
-- l'exemplaire exécuté qui prouve qu'elle a eu lieu.
--
-- `docs/CE_QUI_MANQUE.md` § 3.9 dit où ça s'arrêtait : « `ActionKind::
-- ContractSign` existe, l'acheteur le propose, la gate en fait toujours une
-- décision humaine et ne la refuse jamais » — et derrière, rien. Les trois
-- moitiés existaient séparément : `docusign` au catalogue
-- (`agentos_app::catalog`), deux générateurs de PDF (`quote_document`,
-- `invoice_document`) et `files` (`0067`) pour ranger l'exemplaire signé.
-- Cette table est ce qui les joint.
--
-- ---------------------------------------------------------------------------
-- POURQUOI UNE TABLE, ET PAS UNE COLONNE SUR `sales_quotes`
-- ---------------------------------------------------------------------------
--
-- `0100` refuse une table qui double une vérité existante, et c'est la première
-- question à poser ici : un devis porte déjà `accepted_at` / `declined_at`, une
-- facture porte `paid_at` — est-ce qu'« envoyé en signature / signé le … » n'est
-- pas simplement deux colonnes de plus sur l'un des deux ?
--
-- Non, pour trois raisons, et chacune suffirait :
--
--   1. **`accepted_at` et `signed_at` ne sont pas le même fait.** `accepted_at`
--      est ce qu'un opérateur affirme après un coup de téléphone —
--      `routes::quotes` l'argumente : *« rien dans ce processus n'observe un
--      accord »*. Une signature, elle, est attestée par un tiers dont c'est le
--      métier, et ce que la colonne gagne ce jour-là est un **artefact** : un
--      PDF exécuté, avec sa piste d'audit. Fusionner les deux ferait d'une
--      affirmation et d'un constat une seule colonne, et on ne saurait plus
--      lequel on lit.
--   2. **Un contrat n'est pas toujours un devis.** `ActionKind::ContractSign`
--      est proposé des deux côtés : `revenue::Seller::propose_terms` (on vend)
--      et `sourcing::Buyer::place_order` (on achète). Un bon de commande
--      fournisseur n'a pas de ligne dans `sales_quotes` et n'en aura jamais.
--      Une colonne là-bas ne couvrirait que la moitié vendeuse.
--   3. **Rien ici ne porte l'identifiant du prestataire.** Ce qui fait qu'une
--      signature est vérifiable est le numéro de pli que DocuSign nous rend, et
--      aucune table de ce dépôt n'a d'endroit où le mettre.
--
-- Ce qui est **délibérément absent** de cette table, et qui pourrait sembler y
-- manquer : aucune clé vers `opportunities`, `sales_quotes` ou `invoices`. Un
-- pli nomme un fichier du classeur, et ce fichier est déjà `devis-…pdf` ou
-- `facture-…pdf` — les rattacher deux fois serait la vérité doublée que ce
-- paragraphe refuse. Le jour où quelqu'un veut lire « les plis de cette
-- affaire », c'est une jointure sur le nom du document, pas une colonne.
--
-- ---------------------------------------------------------------------------
-- CE QUI REND LE MOT « SIGNÉ » INFALSIFIABLE
-- ---------------------------------------------------------------------------
--
-- `docs/CONTENU.md` § 5 a déjà posé la discipline pour la publication :
-- `content_drafts.url` est une **adresse constatée**, et un CHECK interdit de
-- mentir sur le mot *publié*. `POST /v1/invoices/{id}/paid` fait la même chose
-- pour l'encaissement : un acte d'opérateur, parce que rien n'observe un
-- paiement.
--
-- Ici, la même règle, en trois contraintes qui se tiennent :
--
--   * `signature_envelopes_sent_carries_its_id` — on n'est « envoyé » que si le
--     prestataire nous a rendu un numéro de pli. Pas de `sent_at` seul : une
--     date sans identifiant serait notre parole contre la sienne.
--   * `signature_envelopes_signed_carries_its_copy` — **on n'est « signé » que
--     s'il y a un exemplaire exécuté dans le classeur.** C'est la contrainte qui
--     compte : personne, ni un opérateur, ni une route, ni un employé, ne peut
--     écrire `signed_at` sans déposer d'abord les octets du document exécuté.
--     Un `UPDATE` qui essaierait se fait refuser par Postgres.
--   * `signature_envelopes_signed_after_sent` — on ne signe pas un pli qui n'est
--     jamais parti, et pas avant qu'il parte.
--
-- Et `signature_envelopes_copy_is_not_the_original` : l'exemplaire exécuté n'est
-- pas le fichier qu'on a envoyé. Sans elle, la contrainte du dessus se satisfait
-- en pointant sur le PDF non signé, ce qui est exactement le mensonge qu'elle
-- existe pour empêcher.
--
-- ---------------------------------------------------------------------------
-- CE QU'IL N'Y A PAS : UNE COLONNE `source`
-- ---------------------------------------------------------------------------
--
-- `routes::quotes` prévoit, pour le jour où une signature électronique arrive,
-- « une colonne `accepted_source` — parce que *qui l'a dit* aura deux réponses
-- pour la première fois ». Cette table n'en a pas, et c'est volontaire : elle
-- n'a qu'un écrivain aujourd'hui (`POST /v1/signatures/{id}/signed`, une clé
-- d'opérateur), donc la colonne ne porterait qu'une valeur et n'apprendrait
-- rien. Le jour où DocuSign Connect pousse la complétion, elle prend une
-- deuxième valeur et c'est un `alter table` de deux lignes.
--
-- Ce webhook n'est pas ici, et la raison est nommée plutôt qu'oubliée : il
-- demanderait un schéma de signature, donc le **nom de l'en-tête** où DocuSign
-- met la sienne — et ce dépôt refuse déjà de le deviner ailleurs
-- (`agentos_app::inbound::SMARTLEAD_SIGNATURE_HEADER` vaut `None` : *« un
-- vérificateur qui devine son en-tête accepte ou refuse au hasard »*). Aucun
-- compte DocuSign n'existe, donc aucune livraison réelle n'a jamais été lue.
--
-- ---------------------------------------------------------------------------
-- L'IMMUABILITÉ, ET POURQUOI ELLE EST UN DÉCLENCHEUR
-- ---------------------------------------------------------------------------
--
-- C'est la forme de `0066` pour les factures : une ligne s'écrit, puis deux
-- transitions peuvent la compléter, chacune une seule fois, et rien d'autre ne
-- bouge jamais. Une signature ne se retire pas ; une ligne qui dirait le
-- contraire mentirait sur ce qu'on a engagé devant un tiers.

create table if not exists signature_envelopes (
  -- Chez qui. Écrit par la transaction, jamais par le corps de la requête.
  tenant_id             uuid        not null references tenants (id) on delete cascade,

  id                    uuid        not null,

  -- Le siège pour lequel la Gate a statué. Pas une clé d'API : une signature
  -- est un `Action::ContractSign`, et la Gate statue sur un employé.
  employee_id           uuid        not null,

  -- **La décision humaine dont ce pli dépend.** `domain::policy::evaluate`
  -- répond `RequireApproval` sans condition pour `ContractSign` ; c'est donc
  -- l'unique porte, et cette colonne est ce qui permet à
  -- `POST /v1/approvals/{id}/approve` de retrouver le pli que l'humain vient
  -- d'autoriser. Pas de clé étrangère vers `approvals` : cette table-là n'a pas
  -- d'index unique sur `(tenant_id, id)` et en ajouter un pour cette seule
  -- lecture serait plus cher que l'unicité ci-dessous, qui suffit.
  approval_id           uuid        not null,

  -- Le `title` de l'action, c'est-à-dire exactement la phrase sur laquelle le
  -- hachage de l'approbation est pris et que l'humain a lue dans sa file.
  title                 text        not null
                                    constraint signature_envelopes_title_shape
                                    check (char_length(btrim(title)) between 1 and 200),

  -- À qui on demande de signer. Une adresse, telle qu'un opérateur l'a écrite.
  signatory             text        not null
                                    constraint signature_envelopes_signatory_shape
                                    check (char_length(btrim(signatory)) between 3 and 320
                                           and signatory !~ '[[:cntrl:]]'),

  -- Le branchement MCP qui parle au prestataire — `docusign` au catalogue.
  --
  -- **Pas de clé étrangère vers `mcp_servers`, et c'est l'écart assumé avec
  -- `content_repos` (`0102`).** Là-bas, une ligne qui nomme un serveur débranché
  -- ne sert à rien et `on delete cascade` la retire avec lui. Ici, la ligne est
  -- le **dossier d'un contrat** : un client qui débranche DocuSign l'année
  -- suivante ne doit pas voir disparaître la trace des contrats qu'il a signés
  -- par lui. Un serveur absent se paie donc à l'envoi — la flotte du locataire
  -- ne le connaît pas, et l'appel sort en `unknown_tool` plutôt qu'en promesse,
  -- ce que `routes::content` documente déjà.
  server                text        not null
                                    constraint signature_envelopes_server_shape
                                    check (char_length(btrim(server)) between 1 and 64),

  -- Le document à signer, dans le classeur. `files` s'adresse par son nom
  -- (`0067` : « le nom est l'adresse »), donc la clé étrangère est le nom.
  document_name         text        not null,

  -- **Le numéro de pli du prestataire.** Null tant que rien n'est parti ; sa
  -- présence est ce qui fait de `sent_at` autre chose qu'une affirmation.
  provider_envelope_id  text
                                    constraint signature_envelopes_provider_id_shape
                                    check (provider_envelope_id is null
                                           or (char_length(btrim(provider_envelope_id)) between 1 and 200
                                               and provider_envelope_id !~ '[[:cntrl:]]')),
  sent_at               timestamptz,

  -- **L'exemplaire exécuté.** Les octets tels que le prestataire les a rendus,
  -- déposés dans le classeur par `POST /v1/files`. Sans lui, `signed_at` ne
  -- s'écrit pas.
  executed_name         text,
  signed_at             timestamptz,

  created_at            timestamptz not null default now(),

  primary key (tenant_id, id),

  -- Une approbation, un pli. Sans cette unicité, deux plis pourraient attendre
  -- la même décision humaine et un seul clic en enverrait un au hasard.
  constraint signature_envelopes_one_per_approval unique (tenant_id, approval_id),

  constraint signature_envelopes_sent_carries_its_id
    check ((provider_envelope_id is null) = (sent_at is null)),

  constraint signature_envelopes_signed_carries_its_copy
    check ((executed_name is null) = (signed_at is null)),

  constraint signature_envelopes_signed_after_sent
    check (signed_at is null or (sent_at is not null and signed_at >= sent_at)),

  constraint signature_envelopes_copy_is_not_the_original
    check (executed_name is null or executed_name <> document_name),

  -- Composites, pour `0103` : Postgres vérifie la paire, pas l'appelant.
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
    on delete cascade,
  foreign key (tenant_id, document_name) references files (tenant_id, name)
    on delete restrict,
  foreign key (tenant_id, executed_name) references files (tenant_id, name)
    on delete restrict
);

-- `on delete restrict` sur les deux fichiers, là où tout le reste cascade : un
-- classeur d'où l'on peut retirer l'exemplaire exécuté d'un contrat signé est un
-- classeur qui rend la contrainte du dessus contournable en deux temps. `0067`
-- ne donne de toute façon aucun `DELETE` à `app_role` ; ceci tient le jour où il
-- en donnera un.

-- La lecture qui compte : le registre d'un locataire, le plus récent d'abord.
create index if not exists signature_envelopes_tenant_created_idx
  on signature_envelopes (tenant_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Immuable, sauf deux transitions, chacune une fois
-- ---------------------------------------------------------------------------
--
-- La forme d'`invoices` (`0066`) : le déclencheur nomme les colonnes qui
-- peuvent bouger, et refuse tout le reste avec une phrase qu'un opérateur peut
-- lire. `restrict_violation` parce que c'est le code que ce dépôt utilise déjà
-- pour « ce n'est pas une panne, c'est un refus ».

create or replace function signature_envelopes_are_append_only()
returns trigger
language plpgsql
as $$
begin
  if row(new.id, new.tenant_id, new.employee_id, new.approval_id, new.title,
         new.signatory, new.server, new.document_name, new.created_at)
     is distinct from
     row(old.id, old.tenant_id, old.employee_id, old.approval_id, old.title,
         old.signatory, old.server, old.document_name, old.created_at)
  then
    raise exception 'un pli de signature ne se réécrit pas : %', old.id
      using errcode = 'restrict_violation';
  end if;

  if old.sent_at is not null
     and (new.sent_at is distinct from old.sent_at
          or new.provider_envelope_id is distinct from old.provider_envelope_id)
  then
    raise exception 'le pli % est déjà parti chez le prestataire', old.id
      using errcode = 'restrict_violation';
  end if;

  if old.signed_at is not null
     and (new.signed_at is distinct from old.signed_at
          or new.executed_name is distinct from old.executed_name)
  then
    raise exception 'le pli % est déjà signé ; une signature ne se retire pas', old.id
      using errcode = 'restrict_violation';
  end if;

  return new;
end;
$$;

drop trigger if exists signature_envelopes_append_only on signature_envelopes;
create trigger signature_envelopes_append_only
  before update on signature_envelopes
  for each row execute function signature_envelopes_are_append_only();

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` autant qu'`enable`, la forme de `0100` et de `0102` : la ligne d'un
-- voisin nomme qui signe quoi chez lui, ce qui est la liste de ses contrats en
-- cours.

alter table signature_envelopes enable row level security;
alter table signature_envelopes force row level security;
drop policy if exists tenant_isolation on signature_envelopes;
create policy tenant_isolation on signature_envelopes
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- **Les privilèges d'`invoices` et de `sales_quotes`, à la colonne près**, et
-- pas ceux de `content_repos` : un dépôt se change et se retire, un document qui
-- engage l'entreprise ne fait ni l'un ni l'autre. `0066` accorde
-- `update (paid_at)` et rien d'autre ; `0090` accorde
-- `update (accepted_at, declined_at)`. Ici ce sont les quatre colonnes des deux
-- transitions, et aucune autre — le titre, le signataire et le document ne sont
-- pas seulement immuables par déclencheur, ils sont **hors du privilège**. Le
-- déclencheur reste, parce qu'il tient l'autre moitié : une transition ne se
-- rejoue pas.
--
-- Pas de `delete` non plus, comme `files` (`0067`) et pour sa raison : un pli ne
-- s'efface pas. La disparition d'un locataire ou d'un siège cascade depuis la
-- table parente, ce qui se fait en tant que propriétaire et n'a pas besoin de ce
-- privilège-ci.
grant select, insert on signature_envelopes to app_role;
grant update (provider_envelope_id, sent_at, executed_name, signed_at)
  on signature_envelopes to app_role;
