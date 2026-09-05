-- 0006_trois_plateformes : Instagram, TikTok, YouTube — et l'expiration des
-- jetons.
--
-- 1. `token_expires_at` : l'heure de mort annoncee du jeton d'acces scelle
--    (now() + expires_in au callback et a chaque rescellement). Elle existe
--    pour UNE plateforme : Instagram n'a pas de refresh_token separe — son
--    jeton long se rafraichit LUI-MEME et seulement tant qu'il est ENCORE
--    VALIDE (« The token must be at least 24 hours old but not expired »,
--    refresh_access_token, releve 2026-09-02). Un 401 arrive donc TROP TARD :
--    mcp::jeton_frais rafraichit PROACTIVEMENT quand il reste moins de 7
--    jours. NULL = compte connecte avant cette colonne, ou duree inconnue —
--    pas de rafraichissement proactif, le chemin 401 existant fait foi.
--
-- 2. Les CHECK de plateforme s'elargissent aux trois nouvelles. Les noms de
--    contrainte sont ceux que Postgres genere pour un CHECK de colonne
--    anonyme (table_colonne_check). Sans cet elargissement, le callback OAuth
--    d'un compte Instagram echouerait a l'INSERT — la colonne typee refuse
--    au visage de l'operateur, c'est son travail, mais il faut la mettre a
--    jour quand le perimetre grandit reellement.

ALTER TABLE social_accounts ADD COLUMN token_expires_at timestamptz;

ALTER TABLE social_accounts DROP CONSTRAINT social_accounts_platform_check;
ALTER TABLE social_accounts ADD CONSTRAINT social_accounts_platform_check
    CHECK (platform IN ('x', 'linkedin', 'instagram', 'tiktok', 'youtube'));

ALTER TABLE social_oauth_pending DROP CONSTRAINT social_oauth_pending_platform_check;
ALTER TABLE social_oauth_pending ADD CONSTRAINT social_oauth_pending_platform_check
    CHECK (platform IN ('x', 'linkedin', 'instagram', 'tiktok', 'youtube'));

ALTER TABLE social_suppressions DROP CONSTRAINT social_suppressions_platform_check;
ALTER TABLE social_suppressions ADD CONSTRAINT social_suppressions_platform_check
    CHECK (platform IN ('x', 'linkedin', 'instagram', 'tiktok', 'youtube'));
