-- 0110_un_run_tire_sa_variante : la colonne qui fait d'une séquence un A/B
-- mesurable, sans second chemin d'envoi ni deuxième source de traces.
--
-- Un pas `email` (`sequences.steps`, 0092) portait UN brief ; il peut en porter
-- plusieurs (`variants`) et `brief` seul reste valide — aucune séquence
-- existante ne change de forme. Ce qui manquait n'est pas dans les pas : c'est
-- **quelle variante ce run lit**, et ça se tire une fois, à l'inscription.
--
-- ---------------------------------------------------------------------------
-- POURQUOI SUR LE RUN, ET PAS SUR LE MESSAGE
-- ---------------------------------------------------------------------------
--
-- On compare des parcours, pas des mails. Un run de la variante A est écrit
-- dans l'esprit A à chacun de ses pas `email` ; si chaque mail tirait le sien,
-- « A a mieux répondu » ne voudrait plus rien dire — la réponse termine le run
-- (`replied`, 0092), pas un mail. La colonne est donc sur `sequence_runs`, et
-- la lecture (`agentos_app::sequence::variants`) compte des runs par variante
-- dans les traces qui existent déjà : `message_events` (0091) pour ouvert et
-- cliqué, `state = 'replied'` pour la réponse.
--
-- Le tirage est déterministe (l'id du run modulo le nombre de variantes,
-- `agentos_app::sequence::draw`) : rejouable, testable, pas de RNG. `default 0`
-- pour les runs d'avant : une séquence à un seul brief n'a qu'une variante, la
-- zéro, et c'est exactement ce qu'ils lisaient déjà.

alter table sequence_runs
  add column if not exists variant integer not null default 0
    constraint sequence_runs_variant_nonneg check (variant >= 0);
