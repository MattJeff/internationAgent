-- 0025_knowledge_team_scope: the middle of "the whole company" and "one agent".
--
-- 0004 gave `knowledge_sources` a nullable `employee_id` and that was the whole
-- vocabulary: NULL meant every employee of the tenant could retrieve the
-- document, non-NULL meant exactly one could. There was nothing in between, and
-- a company is nothing but in-between. A developer knows its tickets, its sprint
-- and its releases; it knows nothing about the sales strategy, and sales knows
-- nothing about the backlog. Both of those were the same row before this file.
--
-- The consequence was a bill, not just a permission smell. Every retrieved chunk
-- is context and every turn pays for its context, so an employee retrieving
-- against the tenant-wide corpus pays a share of the whole company on every
-- turn — and gets worse answers doing it, because a top-k of five is competing
-- against documents that have nothing to do with its work. Scoping knowledge is
-- a cost control before it is an access control.
--
-- Four decisions.
--
-- 1. ONE MORE NULLABLE COLUMN, NOT A SCOPE ENUM AND NOT A JOIN TABLE. The
--    three-way choice — company / team / employee — is encoded as "at most one
--    of `employee_id`, `team_id` is set", and `knowledge_sources_one_scope`
--    below makes the fourth state unrepresentable rather than merely unused. A
--    scope *table* would be the general answer (a document shared with two
--    teams), and it would put a join on the vector leg, which is exactly the
--    extra qual 0004's own notes say makes an HNSW scan under-return. A document
--    that two teams need is company-wide or it is two documents.
--
-- 2. `team_id` IS DENORMALISED ONTO `knowledge_chunks`, for the same reason
--    `employee_id` already is and stated in 0004: retrieval must not join. The
--    chunk copies it from its source inside the INSERT (see
--    `store::knowledge::insert_chunks`), so a chunk can never be more widely
--    visible than the document it came from.
--
-- 3. THE MEMBERSHIP IS NOT COPIED HERE, AND THAT IS THE POINT. This column says
--    which team a *document* belongs to. It does not say which team an employee
--    is on — `team_memberships` says that, and the retrieval predicate reads it
--    at query time, every time. A scope resolved at write time would mean an
--    employee moved from purchasing to sales keeps reading purchasing's
--    documents until somebody re-ingests them, and an employee on no team would
--    need a row saying so. Read-time costs one uncorrelated subquery on a
--    primary key and is correct by construction on both counts.
--
-- 4. `on delete cascade`, LIKE `employee_id`. Dissolving a team deletes the
--    documents that belonged to that team and nobody else. The alternative —
--    `set null` — would turn a dissolved team's private documents into
--    company-wide ones, which is a widening triggered by an org chart edit and
--    the worst of the available failure modes. `restrict` is not available: a
--    tenant delete cascades into `teams`, and a RESTRICT here would make
--    deleting a tenant depend on the order Postgres happens to walk the graph.
--    The composite FK targets `teams (id, tenant_id)` — the unique key 0012
--    added for precisely this — so a document cannot name another tenant's team
--    even if a caller forgets the tenant predicate.
--
-- No index, and this was checked rather than assumed. The team predicate is
-- evaluated as a filter on rows the HNSW or GIN scan already produced, exactly
-- like the `employee_id` predicate beside it; a btree on `team_id` would not be
-- reachable from either leg. On `EXPLAIN`, against 5000 chunks, the vector leg
-- is still
--
--     Limit
--       InitPlan 1
--         ->  <lookup on team_memberships>
--       ->  Index Scan using knowledge_chunks_embedding_hnsw on knowledge_chunks c
--             Order By: (embedding <=> $1)
--             Filter: (... AND ((employee_id IS NULL) OR (employee_id = $3))
--                          AND ((team_id IS NULL) OR (team_id = (InitPlan 1).col1)))
--
-- — the membership lookup is an InitPlan above the scan, not a join inside it,
-- and the team test lands on the same `Filter:` line the employee test was
-- already on. The text leg likewise still reaches `knowledge_chunks_tsv_gin` by
-- bitmap scan for any term selective enough to be worth it; a term that matches
-- most rows sequential-scans, and sequential-scanned before this file too.
--
-- The index that decides whether the vector leg works at all is
-- `knowledge_chunks_embedding_hnsw`, and it is not touched here.
--
-- No FK on `knowledge_chunks.team_id`, deliberately. Dissolving a team deletes
-- its `knowledge_sources` rows through the FK above, and those cascade into
-- their chunks through `knowledge_chunks_source_id_fkey` — a second composite FK
-- on the hot table would buy nothing and cost every chunk insert a check.

alter table knowledge_sources
  add column if not exists team_id uuid;

alter table knowledge_chunks
  add column if not exists team_id uuid;

alter table knowledge_sources
  add constraint knowledge_sources_team_fk
    foreign key (team_id, tenant_id) references teams (id, tenant_id) on delete cascade;

-- A document belongs to the company, to one team, or to one employee. The
-- fourth combination has no meaning a retrieval could ask for, so it cannot be
-- written. Both tables, because the chunk is the row the ACL is actually read
-- off — a copy that drifts is a copy that decides.
alter table knowledge_sources
  add constraint knowledge_sources_one_scope
    check (employee_id is null or team_id is null);

alter table knowledge_chunks
  add constraint knowledge_chunks_one_scope
    check (employee_id is null or team_id is null);
