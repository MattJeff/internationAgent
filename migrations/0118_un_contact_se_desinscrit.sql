-- 0118_un_contact_se_desinscrit : `unenrolled`, la cinquième raison d'arrêt
-- d'un run de séquence — un opérateur retire un contact d'une séquence.
--
-- Le 2026-09-20, le siège a signalé qu'AssoConnect n'avait pas de tunnel de
-- réservation et le fondateur a demandé de le retirer. Il n'y avait pas de
-- geste : `sequences_archive` ferme la séquence entière et ne touche pas aux
-- runs (0092), et le run est resté `active` jusqu'à mourir `not_sent` le
-- lendemain. Retirer une personne d'une séquence est une décision d'opérateur,
-- distincte de la suppression (0053 : « laissez-moi tranquille », qui vaut pour
-- toutes les séquences) : ici le contact reste joignable, il n'est plus dans
-- celle-là. La contrainte de 0112 ferme la liste ; elle est reposée avec le mot.
-- Même forme rejouable que 0112 (`duplicate_object`).

alter table sequence_runs drop constraint if exists sequence_runs_stop_reason_is_a_code;

do $$
begin
  alter table sequence_runs
    add constraint sequence_runs_stop_reason_is_a_code
      check (stop_reason is null
             or stop_reason in ('suppressed', 'max_touches', 'not_sent', 'declined', 'unenrolled'));
exception
  when duplicate_object then null;
end
$$;
