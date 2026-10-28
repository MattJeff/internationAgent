-- 0120_un_contact_eteint : `inactive`, la sixième raison d'arrêt d'un run.
--
-- `sequence::advance` arrête un run dont le contact est `active = false` avec
-- `stop_reason = 'inactive'` depuis le début, mais la liste fermée de 0112/0118
-- ne contenait pas le mot : le 2026-10-28, 1 428 contacts @mailinator.com ont
-- été éteints, et chaque run encore actif aurait échoué sur la contrainte à
-- chaque tick. Additive : la liste de 0118 plus `inactive`. Même forme
-- rejouable que 0118 (`duplicate_object`).

alter table sequence_runs drop constraint if exists sequence_runs_stop_reason_is_a_code;

do $$
begin
  alter table sequence_runs
    add constraint sequence_runs_stop_reason_is_a_code
      check (stop_reason is null
             or stop_reason in ('suppressed', 'max_touches', 'not_sent', 'declined', 'unenrolled',
                                'inactive'));
exception
  when duplicate_object then null;
end
$$;
