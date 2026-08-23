-- 0004_knowledge: company knowledge, chunked, embedded and searchable.
--
-- Two retrieval paths over one table, because neither one alone is good enough
-- for a buyer:
--
--   * cosine similarity over `embedding`, which finds "what is your return
--     window on damaged goods" in a paragraph that never uses those words;
--   * `ts_rank_cd` over `tsv`, which finds `BRK-4471-XZ`. A 1536-dimension
--     embedding of a part number is noise — nearest-neighbour search will
--     happily hand back a different SKU, and the buyer quoting an exact code is
--     the single most common search we serve.
--
-- The fusion happens in Rust (Reciprocal Rank Fusion), so each leg is a small
-- query that can be read, EXPLAINed and tested on its own.
--
-- `model` is NOT NULL on purpose. The dimension is baked into the column type
-- and the semantics are baked into the weights; a vector from
-- text-embedding-3-small and one from some future model are both `vector(1536)`
-- and are not comparable. Without the column, swapping models silently mixes
-- them and retrieval quality decays with no error anywhere. With it, every
-- vector query carries `WHERE model = $n` and a mixed table just means two
-- disjoint index-able sets.

create extension if not exists vector;

-- ---------------------------------------------------------------------------
-- knowledge_sources
-- ---------------------------------------------------------------------------
--
-- One row per ingested thing: a URL, an uploaded PDF, a price list, a CRM
-- export. Chunks point back here so every retrieval result can be cited.

create table if not exists knowledge_sources (
  id           uuid        primary key,
  tenant_id    uuid        not null references tenants (id) on delete cascade,
  -- NULL means the source belongs to the whole tenant rather than to one
  -- employee; both are visible to that employee's searches.
  employee_id  uuid        references employees (id) on delete cascade,
  kind         text        not null,
  uri          text,
  title        text,
  -- Content hash of the fetched bytes: re-ingesting an unchanged document is a
  -- no-op, and a changed one is visible as a changed checksum.
  checksum     text,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create index if not exists knowledge_sources_tenant_idx
  on knowledge_sources (tenant_id, created_at desc);

-- ---------------------------------------------------------------------------
-- knowledge_chunks
-- ---------------------------------------------------------------------------

create table if not exists knowledge_chunks (
  id           uuid        primary key,
  tenant_id    uuid        not null references tenants (id) on delete cascade,
  source_id    uuid        not null references knowledge_sources (id) on delete cascade,
  -- Denormalised from the source so retrieval never needs a join: an extra join
  -- on the vector leg is an extra qual the HNSW scan has to filter after the
  -- fact, which is exactly the under-return problem described below.
  employee_id  uuid,
  -- Position within the source, so neighbouring chunks can be stitched back
  -- together when a citation needs context.
  ordinal      integer     not null,
  content      text        not null,
  -- Nullable: a chunk exists as soon as it is parsed, and gets its vector when
  -- the embedding call returns. A crashed embed leaves a findable row rather
  -- than nothing.
  embedding    vector(1536),
  model        text        not null,
  -- Generated, so it can never drift from `content`. `english` on both sides;
  -- `websearch_to_tsquery` uses the same config, and a hyphenated part number
  -- indexes as its parts *and* as the whole token, which is what makes the
  -- exact-SKU lookup land.
  tsv          tsvector    generated always as (to_tsvector('english', content)) stored,
  created_at   timestamptz not null default now(),
  constraint knowledge_chunks_source_ordinal_key unique (source_id, ordinal)
);

-- HNSW, cosine, PARTIAL on model.
--
-- Partial because a single index over mixed models would build one graph out of
-- two incomparable vector spaces; the neighbour lists would be garbage. One
-- index per model in use is the honest structure, and a model we no longer
-- serve costs nothing to drop.
create index if not exists knowledge_chunks_embedding_hnsw
  on knowledge_chunks using hnsw (embedding vector_cosine_ops)
  where model = 'text-embedding-3-small';

create index if not exists knowledge_chunks_tsv_gin
  on knowledge_chunks using gin (tsv);

create index if not exists knowledge_chunks_source_idx
  on knowledge_chunks (source_id, ordinal);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- Same shape as 0001. Worth stating what it costs on the vector leg: RLS adds
-- `tenant_id = ...` as a filter applied *after* the HNSW scan has produced its
-- ef_search candidates, so a query that asks for 10 rows can come back with 3
-- and no error at all. `SET LOCAL hnsw.iterative_scan = 'relaxed_order'` in
-- `knowledge.rs` is what makes the scan keep going until the LIMIT is actually
-- satisfied. It is not an optimisation; without it filtered search is silently
-- wrong.

do $$
declare
  t text;
begin
  foreach t in array array['knowledge_sources', 'knowledge_chunks']
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format(
      'create policy tenant_isolation on %I'
      ' using (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)'
      ' with check (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );
  end loop;
end
$$;

grant select, insert, update, delete on knowledge_sources, knowledge_chunks
  to app_role;
