-- 0084_un_abonnement_claude_est_un_jeton_scelle : la voie `cli` peut porter
-- une clé scellée, et c'est l'abonnement Claude du tenant.
--
-- 0050 avait fait de `sealed_key` une biconditionnelle avec `path` : une ligne
-- `api_key` en a toujours une, une ligne `cli` jamais. La seconde moitié
-- disait « le CLI, c'est la session de cette machine », et c'était vrai le
-- jour où un seul fondateur faisait tourner un seul serveur. Un client, lui,
-- n'a pas de SSH : il lance `claude setup-token` chez lui, colle le jeton dans
-- la console, et le serveur le passe au binaire dans l'environnement de
-- chaque appel (`CLAUDE_CODE_OAUTH_TOKEN`). Ce jeton est un secret comme une
-- clé API, scellé sous la même AAD `model://<tenant>`, dans la même colonne.
--
-- Ce qui reste interdit : une ligne `api_key` sans clé, et une enveloppe
-- vide. Une ligne `cli` sans clé garde son sens d'avant : la session du hôte.
do $$
begin
  alter table tenant_model_access
    drop constraint if exists tenant_model_access_key_matches_path;
  alter table tenant_model_access
    add constraint tenant_model_access_key_matches_path
    check (
      (path <> 'api_key' or sealed_key is not null)
      and (sealed_key is null or octet_length(sealed_key) > 0)
    );
exception
  when duplicate_object then null;
end $$;
