-- 0115_la_boucle_se_ferme_sauf_le_clic : un brouillon refusé garde son motif,
-- et un dépôt sait quand ses questions ont été mesurées pour la dernière fois.
--
-- Mesuré le 2026-09-22 : la boucle de citation (0100, 0102, 0106) était posée
-- et personne ne la faisait tourner. Un brouillon rédigé la nuit par le siège
-- growth n'avait atterri nulle part — le tour d'un siège n'a pas d'outil qui
-- range un brouillon, donc la page finissait dans un message interne — et la
-- mesure n'était jamais appelée seule. `agentos_app::content`, « La boucle se
-- ferme, sauf le clic », porte l'argument entier. Cette migration ne porte que
-- les deux colonnes que la fermeture demande.
--
-- ---------------------------------------------------------------------------
-- `archived` : LE QUATRIÈME ÉTAT, ET `note`
-- ---------------------------------------------------------------------------
--
-- Publier passe maintenant par une approbation (`approvals`, avec le brouillon
-- attaché comme une lettre). `approvals_deny` refuse — et un brouillon refusé
-- n'est ni `draft` (il serait reproposé) ni supprimé (le fondateur a écrit
-- pourquoi, et un siège qui réécrit le même article doit pouvoir le lire).
-- Donc un état, et le motif à côté. `note` est le `decision_note` de
-- l'approbation, recopié ici parce que c'est ici qu'on relit un brouillon.
--
-- ---------------------------------------------------------------------------
-- `measured_on` SUR `content_repos`, PAS SUR `content_questions`
-- ---------------------------------------------------------------------------
--
-- `content_citations.checked_at` dit quand une question a été mesurée, mais
-- seulement quand la mesure a réussi : une boucle qui s'en servirait comme
-- réclamation relirait toutes les trente secondes une question qu'un siège
-- sans `web` ne peut pas mesurer. La réclamation doit être écrite **avant** la
-- lecture — la forme de `discovery_sources.read_on` (0113). Elle est sur le
-- dépôt parce que c'est le dépôt qui porte `site`, c'est-à-dire ce que « nous »
-- veut dire dans une mesure, et parce que `content_questions` ne donne pas
-- d'`UPDATE` à `app_role` (0100 l'argumente). Une date, pas un instant : une
-- fois par semaine, et la latence après l'échéance n'importe pas.

alter table content_drafts add column if not exists note text;

alter table content_drafts
  drop constraint if exists content_drafts_state_is_known;
alter table content_drafts
  add constraint content_drafts_state_is_known
  check (state in ('draft', 'proposed', 'published', 'archived'));

alter table content_drafts
  drop constraint if exists content_drafts_published_carries_its_proof;
alter table content_drafts
  add constraint content_drafts_published_carries_its_proof
  check (
    (state = 'draft' and url is null and published_at is null and review_url is null)
    or (state = 'proposed' and url is null and published_at is null and review_url is not null)
    or (state = 'published' and url is not null and published_at is not null)
    -- Refusé : jamais en ligne, et le motif est là. `review_url` est libre —
    -- un brouillon peut être refusé après une proposition retirée.
    or (state = 'archived' and url is null and published_at is null and note is not null)
  );

alter table content_repos add column if not exists measured_on date;
comment on column content_repos.measured_on is
  'Le dernier jour UTC où la boucle de citation a mesuré les questions de ce '
  'locataire sous ce siège. Réclamé avant la lecture, une fois par semaine.';
