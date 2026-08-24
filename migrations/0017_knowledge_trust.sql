-- 0016_knowledge_trust: where a knowledge source came from, written down once,
-- at the only moment anybody knows.
--
-- `conversations` and `messages` have carried `trust_label` since 0001. A
-- knowledge source is the third thing in this system that holds text somebody
-- outside the company wrote, and it is the most dangerous of the three, because
-- it does not reach the model on the turn that accepted it. An email is checked,
-- framed and answered in one flow; a document is accepted on Tuesday and
-- retrieved into a prompt on Friday, by which point the request that carried it
-- is gone and nothing else in the row says who wrote the bytes. So the answer is
-- recorded here, beside the text, at ingest.
--
-- Same spelling and same default as `messages.trust_label`, for the same reason:
-- a source whose provenance nobody recorded is a source whose provenance nobody
-- knows, and the only safe reading of "unknown" is "a stranger". A backfill is
-- therefore not needed and would be wrong — every row that predates this column
-- has exactly the provenance the default describes.
--
-- What this column is NOT: the input to the turn's trust decision. Retrieval
-- taints unconditionally, and `crates/app/src/knowledge.rs` says why at length —
-- briefly, *which* documents land in front of the model is chosen by a query
-- derived from a counterparty's message, so the retrieved set is steered from
-- outside whatever the documents themselves are. No per-source label can undo
-- that. This column is the provenance record: the audit answer to "where did
-- this come from", and the thing that stops a future un-taint path being built
-- on a guess.

alter table knowledge_sources
  add column if not exists trust_label text not null default 'untrusted';
