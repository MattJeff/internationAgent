-- 0002_refresh : garder le refresh token de X.
--
-- X emet un jeton d'acces de 2 heures et, avec le scope offline.access, un
-- refresh token (authorization-code, releve le 2026-09-02). Le perdre coute un
-- re-consentement humain ; on le scelle donc des la connexion, sous une AAD A
-- PART ("social-refresh://...") pour qu'un blob echange avec sealed_token ne
-- dechiffre rien. Le rafraichissement automatique n'est pas encore cable —
-- cette colonne est ce qui permettra de le cabler sans re-consentir.
-- LinkedIn n'emet pas de refresh self-serve : la colonne y reste NULL.
ALTER TABLE social_accounts
    ADD COLUMN sealed_refresh bytea;
