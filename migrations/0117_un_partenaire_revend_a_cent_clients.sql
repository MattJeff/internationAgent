-- 0117_un_partenaire_revend_a_cent_clients : `partner` entre dans les segments
-- de prospection, pour le PMS, le channel manager, le moteur de réservation
-- en marque blanche et la plate-forme d'assurance embarquée.
--
-- Mesuré le 2026-09-21 : en cherchant chez BookingSync, le siège commercial a
-- trouvé Smily — un PMS pour gestionnaires de locations — et l'a laissé
-- passer, à raison selon son plan : « pas de tunnel voyageur, donc rien à
-- reproduire ». Or un PMS ne réserve rien lui-même ; il revend une
-- intégration à cent gestionnaires d'un coup, et chacun de ces cent a des
-- voyageurs qui partent sans condition d'entrée. C'est exactement le palier
-- « dès 600 $ » (marque blanche, redistribution) de `visa.orizn.app`, et
-- aucun segment ne le nommait.
--
-- Ce n'est ni `tmc` ni `relocation` : une TMC voyage pour ses clients, un
-- partenaire vend à des entreprises qui font voyager. Le ranger sous l'un des
-- deux ferait lire au siège un plan de tunnel de réservation chez quelqu'un
-- qui n'en a pas — le refus du 2026-09-21, une seconde fois.
--
-- Les deux CHECK sont reposés entiers (`drop` puis `add`), la forme de 0114 :
-- une CHECK ne s'élargit pas autrement. 0011 et 0113 ne sont pas touchées.
--
-- Rejouable : `drop constraint if exists` avant chaque `add`.

alter table accounts drop constraint if exists accounts_segment;
alter table accounts
  add constraint accounts_segment check (segment in (
    'airline', 'ota', 'corporate_travel', 'tmc', 'insurer', 'cruise',
    'relocation', 'partner', 'other'
  ));

alter table discovery_sources drop constraint if exists discovery_sources_segment;
alter table discovery_sources
  add constraint discovery_sources_segment check (segment in (
    'airline', 'ota', 'corporate_travel', 'tmc', 'insurer', 'cruise',
    'relocation', 'partner'
  ));
