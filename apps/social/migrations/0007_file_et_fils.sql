-- 0007 : file durable (calendrier + approbation) et fils.
--
-- `social_posts` reste la garantie d'idempotence d'une publication réelle
-- (UNIQUE tenant + idempotency_key). Cette table-ci est la file d'AVANT :
-- un créneau, ou un contenu qui attend un humain. Le worker ne poste qu'une
-- ligne `scheduled`, et il réutilise la MÊME clé dans `social_posts` — un
-- rejeu ne double-poste pas, même après un crash entre les deux tables.
--
-- `pending_approval` ne part jamais tout seul. `expired` non plus.
-- `partial` sur social_posts : un fil dont une partie est déjà en ligne.
-- Le rejeu reprend au premier élément non publié, il ne republie pas le début.

ALTER TABLE social_posts DROP CONSTRAINT IF EXISTS social_posts_status_check;
ALTER TABLE social_posts ADD CONSTRAINT social_posts_status_check
    CHECK (status IN ('pending', 'published', 'failed', 'partial'));

CREATE TABLE social_scheduled (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES social_tenants(id) ON DELETE CASCADE,
    account_id       uuid NOT NULL REFERENCES social_accounts(id) ON DELETE CASCADE,
    idempotency_key  text NOT NULL,
    -- 'post' ou 'thread'. Le payload est le corps d'outil, rejouable tel quel.
    kind             text NOT NULL CHECK (kind IN ('post', 'thread')),
    payload          jsonb NOT NULL,
    -- L'empreinte globale contresignée (texte + médias + options). Un rejeu
    -- avec un autre contenu est un bug d'agent, pas un second créneau.
    digest           text NOT NULL,
    publish_at       timestamptz,
    status           text NOT NULL CHECK (status IN (
        'pending_approval', 'scheduled', 'publishing', 'published',
        'failed', 'cancelled', 'rejected', 'expired'
    )),
    attempts         int NOT NULL DEFAULT 0,
    max_attempts     int NOT NULL DEFAULT 5,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    post_id          uuid REFERENCES social_posts(id),
    expires_at       timestamptz,
    decision_note    text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX social_scheduled_echeance
    ON social_scheduled (status, next_attempt_at);

CREATE TABLE social_thread_items (
    post_id           uuid NOT NULL REFERENCES social_posts(id) ON DELETE CASCADE,
    position          int NOT NULL CHECK (position >= 0),
    text_body         text NOT NULL,
    digest            text NOT NULL,
    media             jsonb NOT NULL DEFAULT '[]',
    media_digests     text[] NOT NULL DEFAULT '{}',
    made_with_ai      boolean NOT NULL DEFAULT false,
    poll              jsonb,
    status            text NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'published', 'failed')),
    platform_post_id  text,
    url               text,
    last_error        text,
    PRIMARY KEY (post_id, position)
);
