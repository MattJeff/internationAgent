-- 0004_suppressions : la liste des gens qui ont dit non.
--
-- Un destinataire qui a refuse un jour n'est plus jamais contacte par ce
-- tenant. C'est LA liste des refus — X ne la sert pas : le refus n'est
-- detectable qu'a l'envoi (403 « The recipient may have DM settings that
-- prevent messages from unknown users, or may have blocked you »,
-- docs.x.com/x-api/direct-messages/manage/integrate, releve 2026-09-02).
-- D'ou OptOuts::HeldHere au catalogue : la seule liste est celle-ci.
--
-- Aucun outil MCP ne lit ni n'ecrit cette table au jour un : un agent
-- n'efface pas la liste des gens qui ont dit non (une demande humaine passe
-- par l'operateur, SQL a la main).
CREATE TABLE social_suppressions (
    tenant_id  uuid NOT NULL REFERENCES social_tenants(id) ON DELETE CASCADE,
    platform   text NOT NULL CHECK (platform IN ('x', 'linkedin')),
    -- participant_id chez X ; le type d'identifiant est celui que dm_open recoit.
    target     text NOT NULL,
    reason     text NOT NULL,           -- '403_plateforme' | 'demande_humaine'
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, platform, target)
);
