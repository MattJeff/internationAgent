-- 0112_un_siege_peut_decliner : `declined`, la quatrième raison d'arrêt d'un
-- run de séquence, et la contrainte qui ferme la liste.
--
-- Un pas `email` (0092) réserve une promesse ; quand elle sonne, le siège est
-- réveillé et écrit. Trois fois mesuré, le réveil n'a rien envoyé et le run est
-- mort `not_sent` un jour plus tard — le même mot pour une charte absente, un
-- budget épuisé et un siège qui a posé une question au fondateur au lieu
-- d'écrire (AssoConnect, 2026-09-20). Les deux premiers sont des pannes
-- transitoires que `agentos_app::sequence::advance` rejoue désormais. Le
-- troisième est une **décision** : le siège a lu le brief et jugé qu'il ne
-- fallait pas écrire. Ce run-là s'arrête tout de suite, et son mot est
-- `declined` — pas `not_sent`, qui dit « rien n'est parti » sans dire que
-- quelqu'un l'a choisi.
--
-- `stop_reason` n'avait pas de liste : 0092 ne l'imposait que sous
-- `state = 'stopped'`. Quatre mots écrits par un seul module sont une liste
-- (`suppressed`, `max_touches`, `not_sent`, `declined`), et la fermer ici
-- est ce qui fait d'un cinquième mot une migration plutôt qu'une faute de
-- frappe que `sequences_runs_list` rendrait telle quelle. Même geste que
-- `appointments_outcome_is_a_code` (0072) : `do $$ … duplicate_object` parce
-- que `add constraint` n'a pas de `if not exists` et que chaque migration ici
-- est rejouable.

do $$
begin
  alter table sequence_runs
    add constraint sequence_runs_stop_reason_is_a_code
      check (stop_reason is null
             or stop_reason in ('suppressed', 'max_touches', 'not_sent', 'declined'));
exception
  when duplicate_object then null;
end
$$;
