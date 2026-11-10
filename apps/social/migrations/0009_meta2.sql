-- 0009_meta2 : second connecteur Meta (instagram_reels, facebook_page, threads).
--
-- Le connecteur historique `instagram` (SOCIAL_META_*) ne change pas de
-- contrainte : ses lignes restent valides. Les trois noms nouveaux sont une
-- autre app (META2_APP_* / META2_THREADS_APP_*).
--
-- `meta_user_id` est l'utilisateur Meta qui a consenti (id du signed_request
-- de suppression). Pour une Page, ce n'est PAS l'id de la Page : le jeton
-- scellé est celui de la Page, et la suppression doit quand même retrouver
-- toutes les Pages de cet utilisateur. NULL pour les comptes d'avant, et
-- pour `instagram` : la suppression du second connecteur ne les touche pas.

ALTER TABLE social_accounts ADD COLUMN meta_user_id text;

CREATE INDEX social_accounts_meta_user_id_idx
    ON social_accounts (meta_user_id)
    WHERE meta_user_id IS NOT NULL;

ALTER TABLE social_accounts DROP CONSTRAINT social_accounts_platform_check;
ALTER TABLE social_accounts ADD CONSTRAINT social_accounts_platform_check
    CHECK (platform IN (
        'x', 'linkedin', 'instagram', 'tiktok', 'youtube',
        'instagram_reels', 'facebook_page', 'threads'
    ));

ALTER TABLE social_oauth_pending DROP CONSTRAINT social_oauth_pending_platform_check;
ALTER TABLE social_oauth_pending ADD CONSTRAINT social_oauth_pending_platform_check
    CHECK (platform IN (
        'x', 'linkedin', 'instagram', 'tiktok', 'youtube',
        'instagram_reels', 'facebook_page', 'threads'
    ));

ALTER TABLE social_suppressions DROP CONSTRAINT social_suppressions_platform_check;
ALTER TABLE social_suppressions ADD CONSTRAINT social_suppressions_platform_check
    CHECK (platform IN (
        'x', 'linkedin', 'instagram', 'tiktok', 'youtube',
        'instagram_reels', 'facebook_page', 'threads'
    ));

-- Preuve publique d'une demande de suppression (data deletion callback).
-- Le code est 16 octets d'OS en hex, pas l'id Meta : la page de statut ne
-- nomme pas la personne.
CREATE TABLE social_meta_deletions (
    confirmation_code text PRIMARY KEY,
    app               text NOT NULL CHECK (app IN ('meta2', 'threads')),
    accounts_revoked  integer NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
