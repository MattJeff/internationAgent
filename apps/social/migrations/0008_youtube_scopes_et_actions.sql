-- 0008 : portées OAuth stockées, et actions YouTube dans la file d'approbation.
--
-- `oauth_scopes` est NULL pour un compte connecté avant cette migration :
-- les outils Analytics refusent alors avec un message qui renvoie vers
-- account_connect_url, au lieu d'un 403 brut. Une reconnexion réécrit la
-- colonne (le callback porte le `scope` du point de jeton).
--
-- `kind = youtube` : suppression, visibilité, modération. Rien de tout ça
-- ne part tant que approval_decide n'a pas approuvé. `result` garde la
-- réponse pour le rejeu de la même idempotency_key.

ALTER TABLE social_accounts ADD COLUMN oauth_scopes text;

ALTER TABLE social_scheduled DROP CONSTRAINT IF EXISTS social_scheduled_kind_check;
ALTER TABLE social_scheduled ADD CONSTRAINT social_scheduled_kind_check
    CHECK (kind IN ('post', 'thread', 'youtube'));

ALTER TABLE social_scheduled ADD COLUMN result jsonb;
