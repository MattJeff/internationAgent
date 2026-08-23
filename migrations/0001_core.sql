CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE employees (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  display_name text NOT NULL,
  slug text NOT NULL,
  role text NOT NULL,
  objective text NOT NULL,
  status text NOT NULL,
  address text NOT NULL,
  did text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (tenant_id, slug),
  UNIQUE (address),
  UNIQUE (did)
);

CREATE TABLE employee_resources (
  employee_id uuid NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  step text NOT NULL,
  state text NOT NULL,
  provider text,
  external_id text,
  message text,
  attempt_count int NOT NULL DEFAULT 0,
  last_error text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (employee_id, step)
);

CREATE TABLE conversations (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  employee_id uuid NOT NULL REFERENCES employees(id),
  channel text NOT NULL,
  external_thread_id text,
  contact_ref text NOT NULL,
  language text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE messages (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  employee_id uuid NOT NULL REFERENCES employees(id),
  conversation_id uuid NOT NULL REFERENCES conversations(id),
  direction text NOT NULL,
  channel text NOT NULL,
  provider_message_id text,
  idempotency_key text NOT NULL,
  subject text,
  body_text text,
  body_json jsonb,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE approvals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  employee_id uuid NOT NULL REFERENCES employees(id),
  action_type text NOT NULL,
  action_payload jsonb NOT NULL,
  status text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  decided_by uuid
);

CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  employee_id uuid,
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  trace_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE knowledge_sources (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  kind text NOT NULL,
  uri text,
  title text NOT NULL,
  status text NOT NULL,
  checksum text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE knowledge_chunks (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  source_id uuid NOT NULL REFERENCES knowledge_sources(id) ON DELETE CASCADE,
  content text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  embedding vector(1536),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX knowledge_chunks_embedding_idx
ON knowledge_chunks USING hnsw (embedding vector_cosine_ops);

CREATE TABLE mcp_bindings (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  employee_id uuid NOT NULL REFERENCES employees(id),
  server_url text NOT NULL,
  server_name text NOT NULL,
  auth_secret_ref text,
  enabled boolean NOT NULL DEFAULT true,
  discovered_tools jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  employee_id uuid NOT NULL REFERENCES employees(id),
  network text NOT NULL,
  address text NOT NULL,
  signer_ref text NOT NULL,
  status text NOT NULL,
  UNIQUE (network, address)
);

CREATE TABLE payment_intents (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  employee_id uuid NOT NULL REFERENCES employees(id),
  protocol text NOT NULL,
  amount_minor bigint NOT NULL,
  currency text NOT NULL,
  payee text NOT NULL,
  status text NOT NULL,
  approval_id uuid REFERENCES approvals(id),
  external_ref text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE browser_profiles (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  employee_id uuid NOT NULL REFERENCES employees(id),
  provider text NOT NULL,
  external_context_id text NOT NULL,
  vault_namespace text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE outbox_events (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  available_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  attempts int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX outbox_pending_idx
ON outbox_events (available_at)
WHERE published_at IS NULL;
