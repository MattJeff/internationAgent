-- 0001_social : le socle de l'agregateur de publication sociale.
--
-- Base SEPAREE du runtime (SOCIAL_DATABASE_URL) : ce service est un produit
-- vendable seul ; partager la base du runtime souderait les deux cycles de vie
-- et interdirait de le deployer chez un client qui n'a pas le runtime.
--
-- Trois decisions, chacune un bug qui n'arrive pas :
--
-- 1. `token_hash` ET JAMAIS LE JETON. Un dump de cette table ne donne aucun
--    acces : le jeton ne se frappe qu'une fois, par la CLI, et seul son
--    SHA-256 est ecrit. La comparaison se fait en temps constant cote Rust
--    (tenants.rs), pas en SQL — un `WHERE token_hash = $1` laisserait l'index
--    decider du temps de reponse.
--
-- 2. UNIQUE (tenant_id, idempotency_key) SUR social_posts. C'est LA garantie
--    du produit : un agent qui retente un tour ne double-poste pas, parce que
--    la contrainte est dans la base et non dans du code qu'un chemin peut
--    contourner. Le rejeu rend la ligne existante.
--
-- 3. `sealed_token` EST UNE ENVELOPPE AES-256-GCM, AAD
--    "social://<tenant>/<platform>/<handle>" — meme discipline que
--    crates/app/src/mcp.rs : un chiffre deplace vers un autre tenant, une
--    autre plateforme ou un autre compte ne dechiffre rien. L'AAD porte le
--    handle et non l'id de ligne, parce qu'une reconnexion OAuth reutilise la
--    ligne (upsert) et doit pouvoir re-sceller sans changer de contexte.

CREATE TABLE social_tenants (
    id         uuid PRIMARY KEY,
    label      text NOT NULL UNIQUE,
    -- SHA-256 du jeton, 32 octets, rien d'autre.
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE social_accounts (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES social_tenants(id) ON DELETE CASCADE,
    -- Colonne typee, pas de jsonb : une plateforme inconnue echoue a l'ecriture,
    -- au visage de l'operateur — meme argument que 0013_mcp du runtime.
    -- Perimetre jour un : X et LinkedIn, texte seul.
    platform     text NOT NULL CHECK (platform IN ('x', 'linkedin')),
    handle       text NOT NULL,
    status       text NOT NULL DEFAULT 'connected' CHECK (status IN ('connected', 'revoked')),
    -- Enveloppe (agentos_providers::secrets::Envelope::to_bytes), jamais le clair.
    sealed_token bytea,
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- Une reconnexion du meme compte est un upsert sur cette cle, pas un doublon.
    UNIQUE (tenant_id, platform, handle)
);

CREATE TABLE social_posts (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES social_tenants(id) ON DELETE CASCADE,
    account_id       uuid NOT NULL REFERENCES social_accounts(id) ON DELETE CASCADE,
    idempotency_key  text NOT NULL,
    text_body        text NOT NULL,
    -- SHA-256 hex du texte : c'est l'empreinte que post_preview a montree et
    -- qu'une approbation humaine a contresignee. Rejouer la meme cle avec un
    -- texte different est un bug d'agent, et l'empreinte le rend detectable.
    digest           text NOT NULL,
    platform_post_id text,
    url              text,
    -- 'pending' est une reclamation : la ligne s'insere AVANT l'appel
    -- plateforme, pour qu'un crash entre les deux ne puisse pas double-poster.
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'published', 'failed')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    published_at     timestamptz,
    UNIQUE (tenant_id, idempotency_key)
);

-- L'etat d'un flux OAuth en cours : account_connect_url ecrit une ligne,
-- GET /oauth/callback la consomme (et la supprime — un state ne sert qu'une
-- fois). `sealed_verifier` est le code_verifier PKCE de X, scelle sous l'AAD
-- "social://<tenant>/<platform>/oauth-state/<state>" — meme raison que le
-- verificateur PKCE de crates/app/src/mcp.rs : un blob copie ne s'ouvre pas.
CREATE TABLE social_oauth_pending (
    state           text PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES social_tenants(id) ON DELETE CASCADE,
    platform        text NOT NULL CHECK (platform IN ('x', 'linkedin')),
    sealed_verifier bytea,
    created_at      timestamptz NOT NULL DEFAULT now()
);
