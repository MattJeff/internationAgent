-- 0107_un_contact_dit_dou_il_vient : la porte par laquelle une adresse est
-- entrée, qui est le seul maillon manquant entre un euro et sa cause.
--
-- # Ce qui existait déjà, et qui n'avait pas besoin d'être rebâti
--
-- La chaîne d'une facture réglée jusqu'à une personne est **entière** depuis
-- 0011 et 0066 : `invoices.opportunity_id` nomme l'affaire, `opportunities
-- .account_id` nomme l'entreprise, et `contacts.account_id` nomme les humains
-- qui y travaillent. Trois jointures, toutes composites sur `(tenant_id, id)`,
-- toutes déjà écrites. Rien n'a jamais manqué **à ce bout-là** de la chaîne.
--
-- Ce qui manquait est le premier anneau : une fois dans `contacts`, une adresse
-- venue d'un CSV du fondateur et une adresse lue sur une page d'annuaire sont
-- la même ligne. `agentos_app::prospects` a deux portes — `import` et
-- `discover` — qui écrivent par le **même** `upsert_contact`, délibérément
-- (une seconde voie d'écriture serait une voie qui contourne la cascade
-- d'opt-out), et aucune des deux ne laissait de trace de laquelle elle était.
-- Donc `GET /v1/growth` savait dire « sept factures réglées » et ne savait pas
-- dire laquelle des cinq listes les avait produites.
--
-- Deux colonnes, sur `contacts`, et pas sur `accounts` : une entreprise peut
-- être entrée par un import et la personne qui a fini par répondre avoir été
-- trouvée sur une page. Ce sont deux faits différents et celui qui compte est
-- celui de la personne.
--
-- # `NULL` veut dire inconnu, et jamais « organique »
--
-- Les lignes écrites avant cette migration n'ont pas d'origine, et aucune
-- valeur par défaut ne leur en donne une : un euro dont on ignore la cause
-- n'est pas un euro venu de nulle part, c'est un euro qu'on n'a pas su suivre.
-- `GET /v1/growth` le rend comme une origine vide et non comme un seau nommé.
--
-- # Deux colonnes et pas une
--
-- `origin` est un ensemble fermé, parce que c'est la porte et qu'il n'y en a
-- que deux ; `origin_ref` est le texte de l'opérateur — le nom du fichier, ou
-- l'URL de la page lue. Sans lui, les 1 133 contacts des listes du fondateur
-- répondent tous « import » et la lecture n'apprend rien : les cinq listes
-- (getorizn, oriznapi, DMW, FIDI, ECTAA) ne se comportent pas de la même
-- façon, et c'est exactement la question. Un préfixe dans une seule colonne
-- (`import:fichier.csv`) tiendrait les deux faits, mais aucune CHECK ne peut
-- alors garder la porte fermée et chaque lecteur devient un analyseur.
--
-- `origin_ref` n'est jamais seul : une référence sans porte ne se lit pas.
-- L'inverse est permis — `POST /v1/prospects/import` reçoit un corps `text/csv`
-- sans nom de fichier, et l'appelant qui ne passe pas `?source=` dit « importé,
-- d'un fichier que je ne sais pas nommer », ce qui est vrai.
--
-- ponytail : aucun index. La lecture part d'une facture et descend vers les
-- contacts d'**un** compte par `contacts_account_idx` (0011), qui rend une
-- poignée de lignes ; `origin` y est un filtre sur ces lignes-là, pas un
-- balayage. Le jour où quelqu'un demande « tous les contacts de telle liste »,
-- c'est ce jour-là l'index.
--
-- Rejouable : `add column if not exists`, et les deux contraintes sous le
-- garde-fou `duplicate_object` de 0033.

alter table contacts add column if not exists origin     text;
alter table contacts add column if not exists origin_ref text;

do $$
begin
  alter table contacts
    add constraint contacts_origin
      check (origin is null or origin in ('import', 'discovery'));
exception
  when duplicate_object then null;
end
$$;

do $$
begin
  alter table contacts
    add constraint contacts_origin_ref_needs_origin
      check (origin_ref is null or (origin is not null and btrim(origin_ref) <> ''));
exception
  when duplicate_object then null;
end
$$;

comment on column contacts.origin is
  'La porte par laquelle cette adresse est entrée : import (un fichier du '
  'fondateur) ou discovery (une page d''annuaire lue par un siege). NULL veut '
  'dire inconnu — jamais organique.';
comment on column contacts.origin_ref is
  'Le nom que l''operateur donne a cette source : le chemin du fichier, ou '
  'l''URL de la page. Texte libre, jamais seul sans origin.';
