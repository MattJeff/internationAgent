-- 0026_knowledge_index_model: the vector index names a model this system writes.
--
-- 0004 created `knowledge_chunks_embedding_hnsw` PARTIAL on
-- `model = 'text-embedding-3-small'`. Nothing has ever written that string.
-- `app::knowledge::model_name` stamps `mock-sha256-1536` on every chunk, so the
-- predicate never matched, the index was never applicable, and every knowledge
-- retrieval was a sequential scan over the whole table. Measured on 20 000
-- chunks in one tenant, with the same three `hnsw.*` knobs `search_vector`
-- sets:
--
--   before   Seq Scan on knowledge_chunks (rows=20000)   889 ms, 120 614 buffers
--   after    Index Scan using knowledge_chunks_embedding_hnsw  2.8 ms, 562 buffers
--
-- Nothing about the index was wrong except which model it named, and the
-- `model = ...` qual moves out of the Filter and into the index predicate,
-- which is the plan's own proof that it is the right index.
--
-- WHY STILL PARTIAL, AND WHAT IT COSTS
--
-- 0004's reasoning stands and is not softened here: an embedding from one model
-- and an embedding from another are the same `vector(1536)` and are not the
-- same space, so a search that mixes them is a correctness bug and not a
-- performance one. One index per model in use keeps the two sets disjoint at
-- the storage layer.
--
-- The alternative — one index with no predicate, plus a mandatory
-- `WHERE model = $n` — was rejected for a specific reason and not on
-- principle. That query already carries a second post-filter, `tenant_id`, and
-- `store::knowledge` documents at length that the filter is applied to whatever
-- the HNSW scan hands back and that the scan gives up at `hnsw.max_scan_tuples`
-- — under-returning silently, with no error. Adding a second selective filter
-- to a budget that is already the module's documented failure mode buys nothing
-- and risks exactly that. Under a partial index the scan never sees the other
-- model's rows at all.
--
-- What that costs when a second model appears: one more migration, adding one
-- more partial index, and until it exists that model's searches are sequential
-- scans — slow, never wrong. That cost is the point. The migration is the
-- moment somebody has to say out loud whether the new vectors belong in the old
-- space, which is the question a predicate-free index lets you not answer.
--
-- WHY THE DRIFT WAS INVISIBLE, AND WHAT STOPS IT REPEATING
--
-- There were two names for one thing: `store::knowledge::DEFAULT_EMBEDDING_MODEL`
-- (which only the store's own tests wrote) and `app::knowledge::model_name`
-- (which everything real wrote). The store's tests were the only rows in the
-- world matching the old predicate, so `iterative_scan_returns_a_full_limit_under_rls`
-- — which EXPLAINs the vector leg and asserts an HNSW index scan — passed while
-- production never touched the index once. In the same change
-- `DEFAULT_EMBEDDING_MODEL` becomes that one name and `model_name` returns it,
-- so that test now asserts the index over the model production actually stamps
-- and fails the moment the two disagree again.

drop index if exists knowledge_chunks_embedding_hnsw;

create index if not exists knowledge_chunks_embedding_hnsw
  on knowledge_chunks using hnsw (embedding vector_cosine_ops)
  where model = 'mock-sha256-1536';
