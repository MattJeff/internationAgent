//! Company knowledge: sources, chunks, and hybrid retrieval over both.
//!
//! Three things here are load-bearing and each one is a silent failure if you
//! drop it.
//!
//! **1. `SET LOCAL hnsw.iterative_scan = 'relaxed_order'`.** Every vector query
//! in this module runs under row-level security, so `tenant_id = ...` is a
//! filter Postgres applies to whatever the HNSW scan hands back. A plain HNSW
//! scan produces `ef_search` candidates and stops; if most of them belong to
//! other tenants, the filter throws them away and your `LIMIT 10` returns 3
//! rows. No error, no warning, no log line — just a shorter answer that looks
//! like "we have nothing else on file". [`search_vector`] therefore sets
//! iterative scan before the query, which makes the scan keep pulling until the
//! limit is genuinely satisfied — along with the two budget knobs that decide
//! when it gives up, because "keeps pulling" has a default ceiling of 20 000
//! tuples and `tenant_id` is the most selective filter there is. The test
//! `iterative_scan_returns_a_full_limit_under_rls` fails without them, and it
//! fails by returning *fewer rows*, not by erroring — which is why it asserts
//! the unfixed query under-returns before it asserts the fixed one does not.
//!
//! **2. `model` is part of the query, not decoration.** A `vector(1536)` from
//! one embedding model and a `vector(1536)` from another are the same Postgres
//! type and are not remotely the same space. Mixing them does not fail, it just
//! quietly returns nonsense, so the column is `NOT NULL`, every search binds
//! it, and the HNSW index is partial on it.
//!
//! **3. Hybrid, not vector-only.** Semantic search is very good at "what is
//! your policy on damaged pallets" and very bad at `BRK-4471-XZ`. Part numbers,
//! HS codes and SKUs carry no distributional meaning — the nearest neighbours
//! of one part number are other part numbers. Those exact-token lookups are
//! most of what a buyer actually types, so retrieval runs a `ts_rank` full-text
//! leg alongside the vector leg and fuses the two with Reciprocal Rank Fusion. RRF needs no score calibration between the legs, which is the
//! whole reason to prefer it over a weighted sum of a cosine distance and a
//! rank score that share no units.
//!
//! **4. A document is the company's, a team's, or one employee's.** That is
//! [`Scope`], stamped at ingest, and the retrieval predicate is the whole of the
//! access control: company-wide rows, plus rows belonging to the team this
//! employee is on *right now*, plus rows filed against this employee. The team a
//! search is entitled to is read from `team_memberships` inside the query rather
//! than passed in by the caller, which buys two things a bound parameter would
//! not. An employee moved between teams loses the old team's documents on its
//! next retrieval, with nothing to re-ingest and no cache to invalidate. And an
//! employee on **no** team gets a NULL out of that subquery, so `c.team_id =
//! NULL` is NULL, so every team row is filtered out — being on no team is the
//! narrowest scope there is rather than the widest, which is the direction a
//! missing row has to fail in.
//!
//! Retrieved text comes back as [`Untrusted<String>`]: it is a stranger's PDF,
//! and it is on its way into a prompt. Each [`Hit`] carries its `source_id` so
//! the caller can cite it. That wrapper is unconditional and is not read off a
//! column — see [`NewSource::trust`], which records where a source came from for
//! the audit trail, and `crates/app/src/knowledge.rs` for why no per-source
//! label may ever be allowed to remove the wrapper. [`Scope`] does not touch it:
//! a document from your own team is still a document somebody may have emailed
//! in, and it is still *selected* by a query a counterparty wrote.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use agentos_domain::ids::EmployeeId;
use agentos_domain::untrusted::{TrustLabel, Untrusted};
use pgvector::Vector;
use sqlx::Row;
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

/// Dimension of the `embedding` column. Baked into the schema, so a model with
/// a different width needs a migration, not a config change.
pub const EMBEDDING_DIM: usize = 1536;

/// The model the HNSW index is partial on, and the one every chunk this system
/// writes carries — `app::knowledge::model_name` returns *this constant* rather
/// than a second spelling of it.
///
/// That indirection is the fix for a real bug and not tidiness. Until 0026 the
/// index predicate named `text-embedding-3-small` and nothing but this file's
/// own tests ever wrote that string, so the index served no query in production
/// and every retrieval was a sequential scan — while the test that EXPLAINs the
/// vector leg and demands an HNSW index scan passed, because the test data was
/// the only data the predicate matched. Two names for one thing is what made
/// that invisible; there is now one, and the same test guards it.
///
/// Anything else stores and searches fine, it just falls back to a sequential
/// scan until someone adds a partial index for it — see `0026`, which argues
/// why a second model is a migration rather than a config change.
pub const DEFAULT_EMBEDDING_MODEL: &str = "mock-sha256-1536";

/// The model a deployment with `EMBEDDER_API_KEY` set writes, and the second
/// partial HNSW index — `0076_knowledge_index_real_embedder.sql`.
///
/// **This constant is here, next to the index it names, for the reason 0026
/// exists**: the predicate is a SQL literal and a literal cannot see a Rust
/// `const`, so the two drift in silence and the symptom is a sequential scan
/// with every test still green. It is spelled once here, once in that
/// migration, and once in `agentos_providers::embedder_openai::OpenAiEmbedder`
/// — which is a crate this one cannot see. The two Rust spellings are proved
/// equal at compile time by a `const` block in `agentos_app::knowledge`, which
/// sees both; this one and the migration are proved equal by
/// [`the_real_embedders_index_names_the_model_it_writes`], which reads the
/// predicate back out of `pg_indexes`.
///
/// Not configurable, and that is the same statement as the index being partial.
/// See `agentos_providers::embedder_openai` for why a model an operator can
/// type is a model with no index.
pub const OPENAI_EMBEDDING_MODEL: &str = "text-embedding-3-small";

/// The `k` in `1 / (k + rank)`. 60 is the constant from the original RRF paper
/// and its job is to flatten the top of the curve, so rank 1 and rank 2 do not
/// differ by 2x and one leg cannot dominate the fusion on its own.
const RRF_K: f64 = 60.0;

/// The retrieval ACL, once, with the employee parameter spelled `$n`.
///
/// Company-wide, plus its own team's, plus its own — and nothing else: not its
/// manager's, not a sibling team's. The employee id is the *only* thing a caller
/// supplies; the team comes out of `team_memberships`, under RLS, at query time.
/// Three things fall out of writing it this way:
///
/// * A caller cannot name a team it is not on. There is no team parameter.
/// * An employee moved between teams sees the new team's documents on its next
///   retrieval and the old team's on none.
/// * An employee on no team gets NULL from the subquery, and `c.team_id = NULL`
///   is NULL rather than true, so it sees company-wide and its own only. The
///   absent membership fails closed without a line of code saying so.
///
/// `$n IS NULL` still means "everything this tenant has" — what
/// [`Search::employee_id`]`= None` has always meant, unchanged and still bounded
/// by row-level security.
///
/// The subquery is uncorrelated (`$n` is a parameter, not a column), so Postgres
/// runs it once as an InitPlan and the rest is a constant filter — the same
/// shape as the `employee_id` comparison beside it, and no join on either leg.
///
/// **Neither leg changes index.** Checked on `EXPLAIN`, because "it is only a
/// filter" is the kind of claim that is true until the planner disagrees: the
/// vector leg is still `Index Scan using knowledge_chunks_embedding_hnsw` with
/// the team test added to the same `Filter:` line the employee test was already
/// on, and the text leg still reaches `knowledge_chunks_tsv_gin` by bitmap scan
/// whenever the term is selective enough to be worth it — a common term
/// sequential-scans with this predicate and sequential-scanned without it too.
/// The membership lookup shows up once, as `InitPlan 1`, above the scan rather
/// than inside it.
///
/// A macro because the two legs number their parameters differently and this is
/// an ACL: written twice it is fixed once, and the copy nobody edited is the one
/// that decides what a query returns.
macro_rules! entitled {
    ($employee:literal) => {
        concat!(
            "(",
            $employee,
            "::uuid IS NULL ",
            " OR ((c.employee_id IS NULL OR c.employee_id = ",
            $employee,
            ")",
            "     AND (c.team_id IS NULL",
            "          OR c.team_id = (SELECT m.team_id FROM team_memberships m",
            "                           WHERE m.employee_id = ",
            $employee,
            "))))"
        )
    };
}

/// Vector leg. Shared with the test that proves the iterative-scan setting is
/// what fills the limit, which is why it is a `const` and not inline.
const VECTOR_SQL: &str = concat!(
    "SELECT c.id, c.source_id, c.ordinal, c.content, ",
    "       (1 - (c.embedding <=> $1))::float8 AS score ",
    "FROM knowledge_chunks c ",
    "WHERE c.model = $2 ",
    "  AND c.embedding IS NOT NULL ",
    "  AND ",
    entitled!("$3"),
    " ORDER BY c.embedding <=> $1 ",
    "LIMIT $4"
);

/// Full-text leg. **The sender's words, ORed, ranked by how many of them a
/// passage carries — and cut off below [`Search::min_coverage`].**
///
/// `$1` is not a search box. Its only production caller is
/// `agentos_app::knowledge::recall`, whose query text is the first 512
/// characters of the message a counterparty sent — and while the embedder is
/// not semantic, this leg is the *only* thing selecting what an employee
/// recalls. Whoever writes `$1` therefore chooses which of this tenant's
/// documents reach the model. Two separate things have to be true of the
/// parser, and the two previous versions of this constant each had one of them.
///
/// **1. The sender writes words, never structure.** `websearch_to_tsquery`,
/// which was here first, is a query *language*: `or` is disjunction, `-` is
/// negation, `"…"` is a phrase. That handed the sender the query's boolean
/// structure on top of its words, and negation is the one with no honest
/// equivalent — extra words can only narrow, so only `-` can *remove* the
/// passage that constrains the sender and leave a full, plausible top-k in its
/// place. Both operators are reproduced in `agentos_app::knowledge`'s
/// `a_senders_message_is_words_and_not_a_query_language`.
///
/// `plainto_tsquery` replaced it and closed that hole by ANDing every lexeme.
/// The query below closes it a second way, and a stronger one: the lexemes are
/// taken out of `to_tsvector('english', $1)` — the *document* parser — which
/// has no operators at all. `-`, `or`, `"` and `!` do not survive
/// tokenisation, so there is no expression left for the sender to write. What
/// reaches `tsquery` is a list of normalised lexemes quoted one by one, which
/// is why the string is built with a doubled `''` rather than with
/// `quote_literal`: `quote_literal` emits an `E'…'` string for a lexeme
/// containing a backslash, the `tsquery` parser does not understand one, and
/// the symptom would be a syntax error on the first live retrieval whose email
/// contained a Windows path. Lexemes carrying a backslash are dropped instead.
///
/// **2. A whole message has to be able to match something.** That is what
/// `plainto_tsquery` gave away. It ANDs, so a chunk had to contain *every*
/// non-stopword of an email — three sentences of ordinary correspondence
/// matched nothing, ever, and `agentos_app::knowledge` said so in its own
/// module docs: "That is close to never." An employee whose only selection
/// channel matches close to never does not answer from company knowledge, it
/// only appears to.
///
/// So the lexemes are ORed, and **the threshold is what keeps an OR from
/// padding** — which is the failure this repository refuses one layer up, in
/// `agentos_app::knowledge`'s argument for consulting no leg that has no
/// opinion: a passage sharing one common word with a long email is not an
/// answer, and five of those wrapped around one real hit are worse than an
/// empty hand, because an empty hand is visibly empty.
///
/// **`ts_rank` over an OR query is coverage, which is why the score is
/// divided.** `calc_rank_or` sums a weight per *matched query operand* and
/// divides by the number of operands, so the score of a passage carrying every
/// one of the query's lexemes is a constant — measured at 0.06079271 here, and
/// deliberately not written down anywhere in this file, because
/// `array_to_tsvector(lex)` **is** that passage and Postgres computes the
/// constant itself, once per query, in the `MATERIALIZED` CTE below. The ratio is therefore the fraction of the
/// question's distinct lexemes this passage carries, in `0..1`, comparable
/// across queries and across Postgres versions, and it is the same number the
/// `WHERE` thresholds on. Repetition raises a term's weight sub-linearly and
/// saturates — measured against a one-lexeme query: one occurrence 0.0203,
/// three 0.0276, five hundred 0.0998 — so a chunk that repeats one of the
/// sender's words fifty times still does not out-score one that carries two of
/// them once.
///
/// `ts_rank_cd`, which this replaces, is cover *density*: it is defined over
/// the span containing the whole query and has no meaning for a disjunction
/// most of whose branches are absent from the passage.
///
/// What none of this fixes is selection itself — a sender who writes the
/// document's own words still gets that document, which
/// `agentos_app::knowledge` accepts on purpose and argues. What changed is the
/// price of steering: under the AND the message had to *be* the document, and
/// it now has to spend [`Search::min_coverage`] of its own words on it.
///
/// If a human search box ever lands, it gets its own query built from
/// structured input. It does not get this one back.
const TEXT_SQL: &str = concat!(
    // The sender's words as the *document* parser sees them: normalised,
    // de-punctuated, stopwords gone, and no operator expressible.
    "WITH lexemes AS ( ",
    "  SELECT array_agg(lexeme) AS lex ",
    "    FROM unnest(to_tsvector('english', $1)) AS w(lexeme, positions, weights) ",
    // See the doc comment: a lexeme with a backslash in it is a `tsquery`
    // syntax error waiting for the email that contains one.
    "   WHERE position('\\' in lexeme) = 0 ), ",
    // `array_agg` over no rows is NULL, so a question that survives
    // tokenisation as nothing at all leaves this empty, the join below returns
    // nothing, and the caller gets an empty hand rather than a division by
    // zero.
    "built AS ( ",
    "  SELECT lex, (SELECT string_agg('''' || replace(l, '''', '''''') || '''', ' | ') ",
    "                 FROM unnest(lex) AS l)::tsquery AS query ",
    "    FROM lexemes WHERE lex IS NOT NULL ), ",
    // MATERIALIZED, and it is worth the keyword. Without it the planner inlines
    // the CTE and re-derives the `tsquery` and the divisor as five separate
    // SubPlans, two of them inside the per-row `Filter`. With it both are
    // computed once, and the scan still reaches `knowledge_chunks_tsv_gin` by
    // bitmap index scan — checked on `EXPLAIN`, both ways.
    //
    // `perfect` is `ts_rank` of the passage that carries every one of the
    // query's own lexemes: what a coverage of 1.0 means, and what the score
    // below is a fraction of.
    "q AS MATERIALIZED ( ",
    "  SELECT query, ts_rank(array_to_tsvector(lex), query) AS perfect FROM built ) ",
    "SELECT c.id, c.source_id, c.ordinal, c.content, ",
    "       (ts_rank(c.tsv, q.query) / q.perfect)::float8 AS score ",
    "FROM knowledge_chunks c, q ",
    "WHERE c.tsv @@ q.query ",
    // The threshold, written as a multiplication rather than a division so it
    // stays a plain filter beside the index condition.
    "  AND ts_rank(c.tsv, q.query) >= $2 * q.perfect ",
    "  AND ",
    entitled!("$3"),
    " ORDER BY score DESC, c.id ",
    "LIMIT $4"
);

/// Who a document is for. **Stamped at ingest, and there are exactly three.**
///
/// The whole company, one team, or one employee — a closed enum rather than two
/// nullable fields, because "filed against a team *and* an employee" is a
/// question no retrieval asks and a state no caller should be able to build. The
/// database says the same thing with `knowledge_sources_one_scope`; this is the
/// half that says it before the round trip.
///
/// Provenance is recorded at ingest for the reason
/// `crates/app/src/knowledge.rs` gives at length: by retrieval time, on some
/// other day, nothing left in the row remembers where the bytes came from or who
/// they were for. Scope is the same kind of fact and is written the same way.
///
/// What it is **not** is a trust decision. A document scoped to your own team is
/// still third-party text and still arrives [`Untrusted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// Every employee of the tenant retrieves it. The handbook.
    #[default]
    Company,
    /// One team's, by `teams.id`. Its members retrieve it and nobody else —
    /// not a sibling team, not a manager, and not the same employee tomorrow if
    /// it has been moved off the team by then.
    Team(Uuid),
    /// One employee's own. Narrower than its team, and unaffected by moving it.
    Employee(EmployeeId),
}

impl Scope {
    /// `(employee_id, team_id)`, the two columns this is stored as.
    ///
    /// Public only because the dedupe key in `agentos_app::knowledge` has to
    /// compare against the same two columns this writes, and two hand-written
    /// copies of that mapping is one copy that can disagree about which column
    /// a team goes in. Nothing else should need it: everything above this
    /// module says [`Scope`] and cannot say anything else.
    pub const fn columns(self) -> (Option<Uuid>, Option<Uuid>) {
        match self {
            Scope::Company => (None, None),
            Scope::Team(team) => (None, Some(team)),
            Scope::Employee(employee) => (Some(employee.as_uuid()), None),
        }
    }
}

/// A thing that was ingested: a URL, an upload, a price list, a CRM export.
#[derive(Debug, Clone)]
pub struct NewSource {
    /// App-minted UUIDv7.
    pub id: Uuid,
    /// Who may retrieve it: the company, one team, or one employee.
    pub scope: Scope,
    /// `url`, `pdf`, `catalog`, `policy`, ... — free text, the ingest pipeline
    /// owns the vocabulary.
    pub kind: String,
    /// Where it came from, for citation.
    pub uri: Option<String>,
    /// Human label.
    pub title: Option<String>,
    /// Hash of the fetched bytes, so re-ingesting an unchanged document is a
    /// no-op instead of a duplicate.
    pub checksum: Option<String>,
    /// **Who wrote the text**, recorded at ingest because by retrieval time
    /// nothing else in the row remembers. Not optional and not defaulted here:
    /// a caller that has to name it is a caller that had to think about it, and
    /// the column's own default only covers rows written before 0016.
    pub trust: TrustLabel,
}

/// One chunk of a source, ready to store.
#[derive(Debug, Clone)]
pub struct NewChunk {
    /// App-minted UUIDv7.
    pub id: Uuid,
    /// Position in the source; `(source_id, ordinal)` is unique.
    pub ordinal: i32,
    /// The chunk text. Stored as-is; `tsv` is generated from it.
    pub content: String,
    /// `None` when the embedding call has not returned yet. The row still
    /// exists, so a crashed embed is a findable gap rather than lost text.
    pub embedding: Option<Vector>,
}

/// What to search for.
#[derive(Debug, Clone)]
pub struct Search<'a> {
    /// The query embedded with `model`.
    pub embedding: &'a Vector,
    /// The query as the user typed it, for the full-text leg.
    pub text: &'a str,
    /// Must match the `model` the chunks were embedded with.
    pub model: &'a str,
    /// **Who is asking**, and the whole of the retrieval ACL: this employee's
    /// own sources, plus the ones scoped to the team it is on at this instant,
    /// plus the tenant-wide ones. There is deliberately no team parameter beside
    /// it — see the `entitled!` predicate. `None` searches everything the tenant
    /// has, which is the operator-side mode and not something a turn passes.
    pub employee_id: Option<EmployeeId>,
    /// Rows wanted. The legs each fetch this many before fusion.
    pub limit: i64,
    /// **The share of the question's own words a passage has to carry to be
    /// returned at all**, in `0..=1`. Below it the passage is not an answer to
    /// this question and is dropped, even when that leaves nothing.
    ///
    /// A field rather than a constant here because it is a product decision —
    /// how much silence is worth how much noise — and this crate has no
    /// standing to make it. `agentos_app::knowledge::MIN_COVERAGE` is the one
    /// number every caller passes, and it is argued there against measurements.
    /// `0.0` disables the threshold, which is what the test that shows what the
    /// threshold is holding back passes.
    ///
    /// Read by [`search_text`] only. The vector leg has no comparable quantity:
    /// a cosine distance is not a fraction of anything the sender wrote.
    pub min_coverage: f64,
}

/// One retrieved chunk.
#[derive(Debug, Clone)]
pub struct Hit {
    /// The chunk.
    pub chunk_id: Uuid,
    /// The source it came from — join to `knowledge_sources` for the URI and
    /// checksum a citation needs.
    pub source_id: Uuid,
    /// Position within the source, for stitching neighbouring chunks together.
    pub ordinal: i32,
    /// The text. Wrapped because it is third-party content heading for a
    /// prompt: see [`Untrusted`].
    pub content: Untrusted<String>,
    /// What it means depends on which function produced it: cosine similarity
    /// from [`search_vector`], the fused RRF score from [`search_hybrid`], and
    /// from [`search_text`] the **fraction of the question's distinct lexemes
    /// this passage carries**, in `0..=1` and comparable across queries — see
    /// [`TEXT_SQL`]. The other two are comparable within one result set only.
    pub score: f64,
}

/// Wire spelling of a trust label, matching `messages.trust_label`. One
/// vocabulary across every table that records provenance, or a query that joins
/// two of them compares 'untrusted' against something else.
const fn trust_str(label: TrustLabel) -> &'static str {
    match label {
        TrustLabel::Trusted => "trusted",
        TrustLabel::Untrusted => "untrusted",
    }
}

/// Record an ingested source.
///
/// A [`Scope::Team`] naming another tenant's team is refused by the composite
/// foreign key 0025 adds, not by a check here: the tenant is half the key, so
/// there is no version of "forgot the tenant predicate" that gets through.
pub async fn insert_source(tx: &mut TenantTx<'_>, source: &NewSource) -> Result<(), StoreError> {
    let (employee_id, team_id) = source.scope.columns();
    sqlx::query(
        "INSERT INTO knowledge_sources \
             (id, tenant_id, employee_id, team_id, kind, uri, title, checksum, trust_label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(source.id)
    .bind(tx.tenant_id().as_uuid())
    .bind(employee_id)
    .bind(team_id)
    .bind(&source.kind)
    .bind(&source.uri)
    .bind(&source.title)
    .bind(&source.checksum)
    .bind(trust_str(source.trust))
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// Store chunks of `source_id`, all embedded with `model`.
///
/// **Both scope columns are copied from the source by the INSERT itself**, so a
/// chunk can never end up more widely visible than the document it came from —
/// and a caller cannot widen one by supplying it, because there is no parameter
/// to supply. The same `SELECT ... FROM knowledge_sources` is what makes an
/// unknown or other-tenant source id a [`StoreError::NotFound`] rather than an
/// orphan row.
///
// ponytail: one INSERT per chunk. A document is tens of chunks and this runs
// once per ingest, not per request; if a 10k-chunk PDF ever shows up, this
// becomes one `UNNEST($1::uuid[], $2::int[], ...)` statement.
pub async fn insert_chunks(
    tx: &mut TenantTx<'_>,
    source_id: Uuid,
    model: &str,
    chunks: &[NewChunk],
) -> Result<(), StoreError> {
    for chunk in chunks {
        let done = sqlx::query(
            "INSERT INTO knowledge_chunks \
                 (id, tenant_id, source_id, employee_id, team_id, ordinal, content, \
                  embedding, model) \
             SELECT $1, $2, s.id, s.employee_id, s.team_id, $3, $4, $5, $6 \
             FROM knowledge_sources s WHERE s.id = $7",
        )
        .bind(chunk.id)
        .bind(tx.tenant_id().as_uuid())
        .bind(chunk.ordinal)
        .bind(&chunk.content)
        .bind(chunk.embedding.clone())
        .bind(model)
        .bind(source_id)
        .execute(&mut ***tx)
        .await?;

        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
    }
    Ok(())
}

/// Nearest neighbours by cosine similarity.
///
/// Turns on iterative scan first, plus the two budgets that decide when it
/// stops — see the module docs. All three are `SET LOCAL`, so they die with the
/// transaction and never leak onto a pooled connection.
pub async fn search_vector(
    tx: &mut TenantTx<'_>,
    search: &Search<'_>,
) -> Result<Vec<Hit>, StoreError> {
    for knob in [
        // The whole reason this function exists as a wrapper.
        "SET LOCAL hnsw.iterative_scan = 'relaxed_order'",
        // Iterative scan buffers what it has scanned so far, and the budget is
        // `work_mem * scan_mem_multiplier`. A 1536-dimension vector is 6 KB, so
        // the default 4 MB `work_mem` is a few hundred tuples — the scan gives
        // up long before it has filled a filtered LIMIT, and under-returns for
        // a second time in exactly the same silent way. Same symptom, different
        // knob.
        "SET LOCAL hnsw.scan_mem_multiplier = 4",
        // And the third: iterative scan restarts with a doubled `ef` each
        // round, so the tuples it has looked at add up fast, and it stops for
        // good at `max_scan_tuples` — 20 000 by default. Our filter is
        // `tenant_id`, the most selective filter there is, so a tenant holding
        // 1% of the index blows that budget before it finds ten of its own
        // rows. Measured: with 8 000 foreign rows crowding 50 of ours, the
        // default returns 0 of a LIMIT 10 and this value returns all 10.
        //
        // ponytail: a raised ceiling, not a fix. A tenant whose rows are a
        // vanishing fraction of a very large index will eventually exhaust
        // this too; the real answer at that size is partitioning the index by
        // tenant, which is a migration, not a GUC.
        "SET LOCAL hnsw.max_scan_tuples = 200000",
    ] {
        sqlx::query(knob).execute(&mut ***tx).await?;
    }

    let rows = sqlx::query(VECTOR_SQL)
        .bind(search.embedding.clone())
        .bind(search.model)
        .bind(search.employee_id.map(|e| e.as_uuid()))
        .bind(search.limit)
        .fetch_all(&mut ***tx)
        .await?;

    Ok(rows.iter().map(hit).collect())
}

/// Full-text ranking. Finds the exact token the vector leg cannot — a SKU, a
/// part number, an HS code, an invoice number — and, since the lexemes are ORed
/// rather than ANDed, finds a document that a whole three-sentence message is
/// only partly about. [`TEXT_SQL`] argues both halves and
/// [`Search::min_coverage`] is what stops the second one padding.
pub async fn search_text(
    tx: &mut TenantTx<'_>,
    search: &Search<'_>,
) -> Result<Vec<Hit>, StoreError> {
    let rows = sqlx::query(TEXT_SQL)
        .bind(search.text)
        .bind(search.min_coverage)
        .bind(search.employee_id.map(|e| e.as_uuid()))
        .bind(search.limit)
        .fetch_all(&mut ***tx)
        .await?;

    Ok(rows.iter().map(hit).collect())
}

/// Both legs, fused with Reciprocal Rank Fusion. **Only correct when the
/// embedding actually means something.**
///
/// Each leg contributes `1 / (RRF_K + rank)` to a chunk's score, so a chunk
/// both legs like outranks one that only a single leg loves. Ties break on
/// `chunk_id` so the order is stable across runs.
///
/// The precondition is not a nicety. [`search_vector`] always returns `limit`
/// rows if the tenant has that many — it ranks whatever it is given and there is
/// no threshold below which it declines — so fusing it in when the vectors are a
/// hash pads every answer out to `limit` with chunks drawn by digest, scored and
/// sorted like the real ones. The caller that knows which backend produced the
/// query vector is `agentos_app::knowledge::retrieve`, and it calls
/// [`search_text`] alone rather than this when
/// `Embedder::is_semantic()` is false. Nothing in this crate can check that: a
/// `vector(1536)` does not know where it came from, which is the same reason
/// [`Search::model`] has to be bound rather than inferred.
pub async fn search_hybrid(
    tx: &mut TenantTx<'_>,
    search: &Search<'_>,
) -> Result<Vec<Hit>, StoreError> {
    let vector = search_vector(tx, search).await?;
    let text = search_text(tx, search).await?;

    let mut fused: HashMap<Uuid, Hit> = HashMap::new();
    for leg in [vector, text] {
        for (index, hit) in leg.into_iter().enumerate() {
            let contribution = 1.0 / (RRF_K + (index + 1) as f64);
            match fused.entry(hit.chunk_id) {
                Entry::Occupied(mut seen) => seen.get_mut().score += contribution,
                Entry::Vacant(slot) => {
                    slot.insert(Hit {
                        score: contribution,
                        ..hit
                    });
                }
            }
        }
    }

    let mut hits: Vec<Hit> = fused.into_values().collect();
    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.chunk_id.cmp(&b.chunk_id))
    });
    hits.truncate(search.limit.max(0) as usize);
    Ok(hits)
}

/// Both legs select the same five columns in the same order.
fn hit(row: &sqlx::postgres::PgRow) -> Hit {
    Hit {
        chunk_id: row.get(0),
        source_id: row.get(1),
        ordinal: row.get(2),
        content: Untrusted::new(row.get(3)),
        score: row.get(4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use agentos_domain::ids::TenantId;
    use chrono::Utc;

    /// The tenant the search runs as, and the noisy neighbour it must not see.
    struct Fixture {
        db: Db,
        mine: TenantId,
        theirs: TenantId,
        source: Uuid,
        /// The one chunk that carries the exact part number, deliberately
        /// parked far away in vector space.
        sku_chunk: Uuid,
    }

    const SKU: &str = "BRK-4471-XZ";
    /// Enough neighbours that a plain HNSW scan runs out of candidates before
    /// it finds ours. Paired with `hnsw.ef_search = 20` in the tests, this
    /// stands in for a production table with a few million rows.
    const NEIGHBOUR_ROWS: i32 = 2000;
    /// The noisy neighbour is **persistent**: created once per database and
    /// never torn down.
    ///
    /// Deleting and re-inserting 2000 vectors on every run would leave 2000
    /// dead entries in the HNSW graph each time, and an HNSW scan has to walk
    /// dead entries to skip them — they count against `hnsw.max_scan_tuples`
    /// just like live ones. After a handful of runs the search under-returns
    /// again and the suite fails with no code change in between. Keeping the
    /// haystack still means each run churns only its own ~51 rows, which
    /// autovacuum handles on its own.
    const NOISE_TENANT: Uuid = Uuid::from_u128(0x0192_0000_7000_8000_0000_0000_0000_00ff);
    const NOISE_SOURCE: Uuid = Uuid::from_u128(0x0192_0000_7000_8000_0000_0000_0000_00fe);

    /// A vector that only uses its first three dimensions, so tests can reason
    /// about distance by eye.
    fn embed(x: f32, y: f32, z: f32) -> Vector {
        let mut v = vec![0.0f32; EMBEDDING_DIM];
        v[0] = x;
        v[1] = y;
        v[2] = z;
        Vector::from(v)
    }

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; knowledge tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// Sweep per-run fixtures a previous *failed* run left behind. A panicking
    /// test skips its teardown, and its rows would otherwise sit in the index
    /// forever. Five minutes is far longer than a run, so a fixture belonging
    /// to a sibling test running right now is never touched.
    async fn sweep_leaked_fixtures(db: &Db) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "DELETE FROM tenants \
             WHERE slug LIKE 'knowledge-run-%' AND created_at < now() - interval '5 minutes'",
        )
        .execute(&mut *tx)
        .await
        .expect("sweep");
        tx.commit().await.expect("commit sweep");
    }

    async fn create_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'knowledge test')")
            .bind(tenant.as_uuid())
            .bind(format!("knowledge-run-{}", tenant.as_uuid()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Create the persistent haystack if this database does not have it yet.
    ///
    /// Every statement is `ON CONFLICT DO NOTHING`, so four tests racing to
    /// build it end up with exactly one copy: the loser blocks on the winner's
    /// row locks and then skips.
    async fn ensure_noise_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::from_uuid(NOISE_TENANT);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query(
            "INSERT INTO tenants (id, slug, name) \
             VALUES ($1, 'knowledge-noise', 'knowledge noise') ON CONFLICT DO NOTHING",
        )
        .bind(NOISE_TENANT)
        .execute(&mut *tx)
        .await
        .expect("insert noise tenant");
        sqlx::query(
            "INSERT INTO knowledge_sources (id, tenant_id, kind) \
             VALUES ($1, $2, 'catalog') ON CONFLICT DO NOTHING",
        )
        .bind(NOISE_SOURCE)
        .bind(NOISE_TENANT)
        .execute(&mut *tx)
        .await
        .expect("insert noise source");

        // Check before writing. `ON CONFLICT DO NOTHING` is not free: Postgres
        // still speculatively inserts each row and then deletes it, so blindly
        // re-running this would leave 2000 dead tuples per test per run — the
        // exact index bloat the persistent fixture exists to avoid.
        let built: i64 =
            sqlx::query_scalar("SELECT count(*) FROM knowledge_chunks WHERE source_id = $1")
                .bind(NOISE_SOURCE)
                .fetch_one(&mut *tx)
                .await
                .expect("count noise rows");
        if built >= i64::from(NEIGHBOUR_ROWS) {
            tx.commit().await.expect("commit noise");
            return tenant;
        }

        // Generated server-side: 2000 round trips carrying 1536 floats each is
        // a slow test for no extra coverage. These vectors sit *closer* to every
        // query the tests make than our own rows do, and they mention the same
        // SKU, so both legs have something to leak if isolation is broken.
        sqlx::query(
            "INSERT INTO knowledge_chunks \
                 (id, tenant_id, source_id, ordinal, content, embedding, model) \
             SELECT gen_random_uuid(), $1, $2, i, \
                    'Competitor listing ' || i || ' for part ' || $3::text, \
                    ('[' || array_to_string( \
                        array[1.0::real, (0.0001 * i)::real] \
                        || array_fill(0.0::real, array[$4::int - 2]), ',') || ']')::vector, \
                    $5::text \
             FROM generate_series(1, $6) i \
             ON CONFLICT (source_id, ordinal) DO NOTHING",
        )
        .bind(NOISE_TENANT)
        .bind(NOISE_SOURCE)
        .bind(SKU)
        .bind(EMBEDDING_DIM as i32)
        .bind(DEFAULT_EMBEDDING_MODEL)
        .bind(NEIGHBOUR_ROWS)
        .execute(&mut *tx)
        .await
        .expect("insert neighbour rows");
        tx.commit().await.expect("commit noise");
        tenant
    }

    /// Our tenant: 50 middling chunks plus one far-away chunk holding the SKU,
    /// against the persistent haystack of [`ensure_noise_tenant`].
    async fn seed() -> Option<Fixture> {
        let db = db().await?;
        sweep_leaked_fixtures(&db).await;
        let theirs = ensure_noise_tenant(&db).await;
        let mine = create_tenant(&db).await;

        let source = Uuid::now_v7();
        let sku_chunk = Uuid::now_v7();
        let mut tx = db.tenant_tx(mine).await.expect("tenant tx");
        insert_source(
            &mut tx,
            &NewSource {
                id: source,
                scope: Scope::Company,
                kind: "policy".to_owned(),
                uri: Some("https://example.test/handbook.pdf".to_owned()),
                title: Some("Handbook".to_owned()),
                checksum: Some("sha256:deadbeef".to_owned()),
                trust: TrustLabel::Untrusted,
            },
        )
        .await
        .expect("insert source");

        let mut chunks: Vec<NewChunk> = (0..50)
            .map(|i| NewChunk {
                id: Uuid::now_v7(),
                ordinal: i,
                content: format!("Paragraph {i}: shipping, returns and damaged pallets."),
                embedding: Some(embed(1.0, 0.3 + 0.001 * i as f32, 0.0)),
            })
            .collect();
        // Orthogonal to every query vector below: cosine similarity ~0, so the
        // vector leg will never surface it.
        chunks.push(NewChunk {
            id: sku_chunk,
            ordinal: 999,
            content: format!("Replacement caliper, part {SKU}, 14 day lead time."),
            embedding: Some(embed(0.0, 0.0, 1.0)),
        });
        insert_chunks(&mut tx, source, DEFAULT_EMBEDDING_MODEL, &chunks)
            .await
            .expect("insert chunks");
        tx.commit().await.expect("commit");

        Some(Fixture {
            db,
            mine,
            theirs,
            source,
            sku_chunk,
        })
    }

    async fn teardown(fixture: &Fixture) {
        let mut tx = fixture.db.admin_tx_bypassing_rls().await.expect("admin tx");
        // Only our own tenant: the noisy neighbour is deliberately permanent.
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(fixture.mine.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    fn query<'a>(embedding: &'a Vector, text: &'a str, limit: i64) -> Search<'a> {
        Search {
            embedding,
            text,
            model: DEFAULT_EMBEDDING_MODEL,
            employee_id: None,
            // The threshold is `agentos_app::knowledge`'s number and is
            // exercised by its tests; these ones are about which *rows* each
            // leg can reach, so they take everything that matched at all.
            min_coverage: 0.0,
            limit,
        }
    }

    /// Force the planner to use the HNSW index and keep `ef_search` small, so
    /// 2000 rows behave like a production-sized table.
    async fn force_index_scan(tx: &mut TenantTx<'_>) {
        for stmt in [
            "SET LOCAL enable_seqscan = off",
            "SET LOCAL hnsw.ef_search = 20",
        ] {
            sqlx::query(stmt)
                .execute(&mut ***tx)
                .await
                .expect("set planner knob");
        }
    }

    /// The headline test: a tenant-filtered vector search must return a full
    /// `LIMIT` worth of rows.
    ///
    /// The negative half runs the identical SQL with iterative scan off and
    /// asserts it comes back *short* — otherwise this test would keep passing
    /// on the day someone deletes the `SET LOCAL` and nobody would know until a
    /// customer said "it only ever finds three documents".
    /// **The index for the real embedder names the model the real embedder
    /// writes**, read out of the catalogue rather than assumed from the
    /// migration file.
    ///
    /// This is 0026's whole bug in one assertion. The predicate is a SQL literal
    /// and [`OPENAI_EMBEDDING_MODEL`] is a Rust constant; nothing in either
    /// language can see the other, so the two drift silently and the symptom is
    /// a sequential scan on every retrieval with the vector-leg test still
    /// green — because that test seeds its own data under whatever model it
    /// binds. Reading `pg_indexes` compares the two things that actually have to
    /// agree.
    ///
    /// Needs no rows: an index predicate is schema, so this costs one catalogue
    /// query and cannot be made flaky by what is in the table.
    #[tokio::test]
    async fn the_real_embedders_index_names_the_model_it_writes() {
        let Some(db) = db().await else { return };
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        let definition: Option<String> = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes \
              WHERE indexname = 'knowledge_chunks_embedding_hnsw_openai'",
        )
        .fetch_optional(&mut *tx)
        .await
        .expect("read pg_indexes");

        let definition = definition.expect(
            "0076 did not create knowledge_chunks_embedding_hnsw_openai, so every retrieval \
             on a deployment with EMBEDDER_API_KEY set is a sequential scan",
        );
        assert!(
            definition.contains(&format!("'{OPENAI_EMBEDDING_MODEL}'")),
            "the index predicate and OPENAI_EMBEDDING_MODEL have drifted, which is 0026 \
             happening again: {definition}"
        );
        assert!(
            definition.contains("hnsw"),
            "a b-tree here would answer every vector query with a sequential scan: {definition}"
        );

        // And the mock's index is still its own, because the two spaces are not
        // one space. A single index over both would build one graph out of two
        // incomparable geometries.
        let mock: Option<String> = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes \
              WHERE indexname = 'knowledge_chunks_embedding_hnsw'",
        )
        .fetch_optional(&mut *tx)
        .await
        .expect("read pg_indexes");
        assert!(
            mock.expect("0026's index")
                .contains(&format!("'{DEFAULT_EMBEDDING_MODEL}'")),
            "the mock's index stopped naming the mock's model"
        );

        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn iterative_scan_returns_a_full_limit_under_rls() {
        let Some(fixture) = seed().await else { return };
        let probe = embed(1.0, 0.0, 0.0);
        let search = query(&probe, "shipping", 10);

        let mut tx = fixture.db.tenant_tx(fixture.mine).await.expect("tenant tx");
        force_index_scan(&mut tx).await;

        // The premise: this must actually be an HNSW index scan. If the planner
        // picked a sequential scan the filter would be applied first, every
        // assertion below would pass, and none of them would mean anything.
        // `AssertSqlSafe` because the "dynamic" part is a `const` in this file.
        let plan: Vec<String> = sqlx::query(sqlx::AssertSqlSafe(format!("EXPLAIN {VECTOR_SQL}")))
            .bind(probe.clone())
            .bind(DEFAULT_EMBEDDING_MODEL)
            .bind(Option::<Uuid>::None)
            .bind(10i64)
            .fetch_all(&mut **tx)
            .await
            .expect("explain")
            .iter()
            .map(|r| r.get::<String, _>(0))
            .collect();
        assert!(
            plan.iter()
                .any(|line| line.contains("knowledge_chunks_embedding_hnsw")),
            "expected an HNSW index scan, got:\n{}",
            plan.join("\n")
        );

        // Without iterative scan: ef_search candidates are all the neighbour
        // tenant's, RLS discards them, and the answer is short.
        sqlx::query("SET LOCAL hnsw.iterative_scan = off")
            .execute(&mut **tx)
            .await
            .expect("disable iterative scan");
        let short = sqlx::query(VECTOR_SQL)
            .bind(probe.clone())
            .bind(DEFAULT_EMBEDDING_MODEL)
            .bind(Option::<Uuid>::None)
            .bind(10i64)
            .fetch_all(&mut **tx)
            .await
            .expect("unfixed vector search");
        assert!(
            short.len() < 10,
            "this test proves nothing unless the unfixed query under-returns; \
             got {} rows — the neighbour tenant is not crowding the index",
            short.len()
        );

        // With it, via the real API: the full limit.
        let hits = search_vector(&mut tx, &search).await.expect("search");
        assert_eq!(
            hits.len(),
            10,
            "filtered HNSW search under-returned; is hnsw.iterative_scan set?"
        );
        assert!(hits.iter().all(|h| h.source_id == fixture.source));

        tx.rollback().await.expect("rollback");
        teardown(&fixture).await;
    }

    /// Why the full-text leg exists. Nobody embeds a part number usefully.
    #[tokio::test]
    async fn the_text_leg_finds_an_exact_sku_the_vector_leg_misses() {
        let Some(fixture) = seed().await else { return };
        let probe = embed(1.0, 0.0, 0.0);
        let search = query(&probe, SKU, 5);

        let mut tx = fixture.db.tenant_tx(fixture.mine).await.expect("tenant tx");

        let vector = search_vector(&mut tx, &search).await.expect("vector");
        assert_eq!(vector.len(), 5);
        assert!(
            !vector.iter().any(|h| h.chunk_id == fixture.sku_chunk),
            "vector-only search was supposed to miss the SKU chunk"
        );

        let text = search_text(&mut tx, &search).await.expect("text");
        assert_eq!(
            text.iter().map(|h| h.chunk_id).collect::<Vec<_>>(),
            vec![fixture.sku_chunk],
            "the full-text leg must find the exact part number, and only ours"
        );
        assert!(text[0].content.expose_for_parsing().contains(SKU));

        // The point of the hybrid: the SKU chunk is in the answer, and so are
        // the semantically-near paragraphs the text leg knows nothing about.
        let hybrid = search_hybrid(&mut tx, &search).await.expect("hybrid");
        assert!(hybrid.iter().any(|h| h.chunk_id == fixture.sku_chunk));
        assert!(hybrid.len() > 1, "hybrid collapsed to the text leg only");
        assert!(
            hybrid.windows(2).all(|w| w[0].score >= w[1].score),
            "fused hits must come back ranked"
        );

        tx.rollback().await.expect("rollback");
        teardown(&fixture).await;
    }

    /// The neighbour tenant's 2000 chunks are nearer in vector space *and*
    /// mention the same SKU. Neither leg may return one.
    #[tokio::test]
    async fn no_leg_ever_returns_another_tenants_chunk() {
        let Some(fixture) = seed().await else { return };
        let probe = embed(1.0, 0.0, 0.0);
        let search = query(&probe, SKU, 10);

        let mut tx = fixture.db.tenant_tx(fixture.mine).await.expect("tenant tx");
        force_index_scan(&mut tx).await;

        for hits in [
            search_vector(&mut tx, &search).await.expect("vector"),
            search_text(&mut tx, &search).await.expect("text"),
            search_hybrid(&mut tx, &search).await.expect("hybrid"),
        ] {
            assert!(!hits.is_empty());
            assert!(
                hits.iter().all(|h| h.source_id == fixture.source),
                "a leg leaked another tenant's chunk"
            );
        }
        tx.rollback().await.expect("rollback");

        // And the neighbour, searching the same words, sees only its own.
        let mut tx = fixture
            .db
            .tenant_tx(fixture.theirs)
            .await
            .expect("tenant tx");
        let hits = search_text(&mut tx, &search).await.expect("text");
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.source_id != fixture.source));
        tx.rollback().await.expect("rollback");

        teardown(&fixture).await;
    }

    /// A chunk cannot be attached to a source this tenant cannot see, which is
    /// what keeps `employee_id` — the retrieval ACL — copied from a real row
    /// rather than supplied by the caller.
    #[tokio::test]
    async fn chunks_for_an_invisible_source_are_not_found() {
        let Some(fixture) = seed().await else { return };

        let mut tx = fixture
            .db
            .tenant_tx(fixture.theirs)
            .await
            .expect("tenant tx");
        let err = insert_chunks(
            &mut tx,
            fixture.source, // belongs to the other tenant
            DEFAULT_EMBEDDING_MODEL,
            &[NewChunk {
                id: Uuid::now_v7(),
                ordinal: 0,
                content: "smuggled".to_owned(),
                embedding: Some(embed(1.0, 0.0, 0.0)),
            }],
        )
        .await
        .expect_err("must not attach to another tenant's source");
        assert!(matches!(err, StoreError::NotFound), "got {err:?}");

        tx.rollback().await.expect("rollback");
        teardown(&fixture).await;
    }
}
