-- 0111_une_sequence_se_nourrit_seule : le flux qui inscrit les contacts d'une
-- séquence à la place du fondateur, et le jour où il l'a fait pour la dernière
-- fois.
--
-- Une séquence (0092) reçoit ses inscrits un par un, par `POST
-- /v1/sequences/{id}/enroll`. Un pas `email` réserve une promesse ; la Gate
-- borne les inconnus par jour (`max_new_contacts_per_day`) ; et **un inscrit que
-- la Gate refuse a dépensé sa promesse pour rien** — mesuré le 2026-09-20 : le
-- sixième du jour est refusé `contact_budget_exhausted`, son run meurt 24 h
-- plus tard en `not_sent`. Tenir cinq par jour sur une liste de 1300 demandait
-- que quelqu'un inscrive exactement cinq contacts chaque matin.
--
-- ---------------------------------------------------------------------------
-- DEUX COLONNES SUR `sequences`, PAS UNE TABLE
-- ---------------------------------------------------------------------------
--
-- Un flux n'existe pas sans sa séquence et une séquence n'en a qu'un : c'est
-- un attribut, pas une relation. `feed jsonb` porte le siège qui écrira, le
-- nombre par jour, le segment, l'ordre des pays et la liste d'origine
-- (`agentos_app::sequence::Feed`, qui en est la seule forme) ; NULL veut dire
-- « pas de flux ». `fed_on date` est le dernier jour UTC nourri : c'est lui
-- qui fait « une fois par jour » sans horloge ni verrou — la boucle nourrit
-- quand `fed_on < aujourd'hui`, et l'UPDATE qui pose `fed_on` est la
-- réclamation elle-même.
--
-- Pourquoi une date et pas un compteur de budget : le budget d'inconnus n'est
-- pas lu dans la boucle, il est neuf à 00:00 UTC et le flux ne nourrit qu'à ce
-- moment-là. L'argument entier est en tête de `agentos_app::sequence`.
--
-- Rejouable : `add column if not exists`.

alter table sequences
  add column if not exists feed   jsonb,
  add column if not exists fed_on date;
