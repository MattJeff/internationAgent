//! The real embedder, against the `/v1/embeddings` wire shape.
//!
//! The shape is [`crate::embedder`]'s — this module only supplies the wire
//! call. Four things about it are load-bearing and none of them are guessable
//! from [`Embedder::embed`](crate::embedder::Embedder::embed), so they are
//! written down here.
//!
//! # The model is a constant, and the key is the customer's
//!
//! **We never supply the model.** That is the product invariant this whole
//! workspace is arranged around — `LlmBackend::pays_with_our_key` is the same
//! rule one port over — and here it means exactly one thing: this adapter reads
//! an API key out of the deployment's configuration and nothing else. The
//! customer's key, the customer's bill, the customer's rate limit.
//!
//! What is **not** the customer's is [`OpenAiEmbedder::MODEL`]. That is
//! deliberate and it is not a limitation we forgot to lift, it is
//! `migrations/0026_knowledge_index_model.sql` being obeyed: the HNSW index is
//! partial on a model *name*, a partial index predicate is a SQL literal, and a
//! literal cannot name a string an operator types into an environment variable.
//! A configurable model would therefore be a model with no index — a sequential
//! scan over the whole table on every retrieval, which 0026 measured at 889 ms
//! against 2.8 ms. So the name is a constant, the migration names the same
//! constant, and `agentos_app::knowledge` proves at compile time that the two
//! spellings have not drifted. Adding a second model stays what 0026 says it
//! is: a migration, and the moment somebody has to say out loud whether the new
//! vectors belong in the old space.
//!
//! # 1536 is not a default, it is the column
//!
//! `knowledge_chunks.embedding` is `vector(1536)` and
//! [`Embedder::DIM`](crate::embedder::Embedder::DIM) is that number in Rust.
//! `text-embedding-3-small` is natively 1536 wide, which is why it is the model
//! named above rather than a preference — but the request still asks for
//! `dimensions` explicitly and the response is still measured, because a vendor
//! that changes a default is a vendor that would otherwise be discovered by
//! Postgres, mid-ingest, three layers below anything that can say what
//! happened. A width that is not [`Embedder::DIM`](crate::embedder::Embedder::DIM)
//! is [`ProviderError::Terminal`] with [`DIM_MISMATCH`], here, before a row is
//! written.
//!
//! **Nothing is projected to fit.** A random projection down to 1536 would make
//! any model storable and is the one answer that must not ship: it puts a
//! transform of ours between the customer's model and the customer's answers,
//! it is invisible from the outside (1536 plausible floats in, 1536 plausible
//! floats out), and it makes `model` on the row a lie — the stored vector is no
//! longer the model's. Refusing costs a customer one decision and no silence.
//!
//! # Order is ours to restore
//!
//! The port's contract is that result row *i* is the embedding of input *i*.
//! The wire's contract is weaker: every element carries an `index` and the
//! array is not promised to be sorted by it. Reading the array positionally is
//! therefore a bug that only shows up as *retrieval quietly ranking the wrong
//! chunk*, with no error anywhere — so [`OpenAiEmbedder::embed`] places each row
//! by its own `index` and refuses a batch whose indices are not a permutation of
//! the inputs.
//!
//! # It is never run from a test in this workspace
//!
//! Every test below talks to a loopback socket that speaks the same wire shape.
//! No test in this repository holds a key, and none may: an assertion that costs
//! money per run is an assertion that gets deleted or, worse, kept and skipped.

use serde::Deserialize;

use crate::embedder::{Embedder, normalise};
use crate::{ProviderError, Secret};

/// The public API root. `with_base_url` points it elsewhere for tests.
pub const API_BASE: &str = "https://api.openai.com/v1";

/// Every vector this adapter produces is refused unless it is this wide.
///
/// A separate code from [`UNUSABLE`] because the two ask an operator for
/// opposite things: this one says "the model you configured is not 1536 wide
/// and this schema stores 1536", which is a decision, and the other says "the
/// vendor answered with something unusable", which is a ticket.
pub const DIM_MISMATCH: &str = "embedding_dim_mismatch";

/// The vendor answered, and the answer cannot be stored: a short batch, a
/// duplicated or out-of-range `index`, or a component that is not finite.
///
/// One code for three shapes on purpose — [`ProviderError::code`] is a metric
/// label and the remedy is the same for all three. Which one it was goes to
/// `tracing::warn!` where a human can read it, not into the cardinality.
pub const UNUSABLE: &str = "unusable_embedding";

/// Hard ceiling on one request, connect included.
///
/// The same argument `email_resend::REQUEST_TIMEOUT` makes at the same value: a
/// `reqwest::Client` has no request timeout of its own, and a provider that
/// never answers is an ingest handler holding a tenant transaction open
/// indefinitely. A backstop against a hung socket, not a service level.
///
/// **On the recall path it is not the binding one and should not be read as
/// reassurance.** `agentos_app::knowledge::RECALL_TIMEOUT` is two seconds
/// covering the connection and both search legs, and it was sized when the
/// embedding step was a SHA-256 of a 512-character string. With this adapter
/// selected, a turn's retrieval spends a network round trip inside that budget,
/// and a provider having a slow minute becomes `Recalled::unavailable` — which
/// the employee says out loud, and which is the right failure, but it is a
/// different failure rate from the one that constant was chosen against.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Most inputs one request may carry.
///
/// ponytail: a refusal, not a loop. The only ingest path in this workspace is
/// `POST /v1/knowledge/documents` under a 1 MiB body cap, and
/// `agentos_app::knowledge` cuts ~1000 characters of new text per chunk — so a
/// request cannot reach 2048 chunks today and the loop would be dead code with
/// a batching bug in it. Named ceiling: the day something ingests more than
/// this, split `inputs` into chunks of `MAX_BATCH` and concatenate the results
/// in order. The refusal is here rather than at the vendor because a 400 from
/// over there arrives as `bad_request` and says nothing about what to do.
pub const MAX_BATCH: usize = 2048;

/// The real embedding client.
#[derive(Debug)]
pub struct OpenAiEmbedder {
    http: reqwest::Client,
    base_url: String,
    api_key: Secret,
}

impl OpenAiEmbedder {
    /// Adapter identity, as it appears in a boot summary.
    pub const PROVIDER: &'static str = "openai";

    /// **The model, and the one written into every chunk's `model` column.**
    ///
    /// `text-embedding-3-small`: natively 1536 wide, so it fits
    /// `vector(1536)` without a migration and without a truncation. It is also
    /// the exact string `migrations/0004_knowledge.sql` named and `0026` had to
    /// remove — 0004 named a model nothing wrote, which made the index
    /// inapplicable and every retrieval a sequential scan. The name is back
    /// because something writes it now: setting `EMBEDDER_API_KEY` is what puts
    /// this string on a row.
    ///
    /// Not configurable. See this module's header for why a partial index
    /// predicate cannot name an environment variable.
    pub const MODEL: &'static str = "text-embedding-3-small";

    /// Build a client from the deployment's key.
    ///
    /// Nothing here reaches the network: the credential selects the adapter at
    /// boot, and the first request is whatever ingest or recall happens first.
    pub fn new(api_key: Secret) -> Self {
        Self {
            // Built rather than `new()`, for `REQUEST_TIMEOUT`. `build` fails
            // only if the TLS backend cannot start, at which point nothing in
            // this process works.
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: API_BASE.to_owned(),
            api_key,
        }
    }

    /// Point the adapter at another origin. For hermetic tests, and for a
    /// customer running an API-compatible endpoint of their own.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    /// Embed a batch, preserving order. See [`Embedder::embed`].
    pub async fn embed(&self, inputs: &[String]) -> Result<Vec<Vec<f32>>, ProviderError> {
        // Not a request. The port says an empty batch is an empty result rather
        // than an error, and `{"input": []}` is a 400 that would arrive as one.
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        if inputs.len() > MAX_BATCH {
            tracing::warn!(
                inputs = inputs.len(),
                max = MAX_BATCH,
                "refusing an embedding batch larger than one request may carry"
            );
            return Err(ProviderError::Terminal { code: UNUSABLE });
        }

        let response = self
            .http
            .post(format!("{}/embeddings", self.base_url))
            .bearer_auth(self.api_key.expose_for_transport())
            .json(&serde_json::json!({
                "model": Self::MODEL,
                "input": inputs,
                // Asked for rather than assumed: this model's native width is
                // already 1536, and a vendor that changes a default must not be
                // discovered by Postgres.
                "dimensions": Embedder::DIM,
                "encoding_format": "float",
            }))
            .send()
            .await
            // Connect, TLS and read failures are all "we do not know whether it
            // landed", which is one retryable answer. Same call as
            // `email_resend::call`.
            .map_err(|_| ProviderError::timeout())?;

        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::from_status(
                status.as_u16(),
                retry_after(response.headers()),
            ));
        }
        let body: EmbeddingList = response
            .json()
            .await
            // A body cut short is a wait, not a refusal — the same trade
            // `email_resend::call_json` argues at length: parking an ingest on
            // attempt one over a reset socket is the expensive direction.
            .map_err(|_| ProviderError::timeout())?;

        place(body.data, inputs.len())
    }
}

/// `Retry-After` in seconds. The HTTP-date form is legal and unused here; an
/// unparseable header means "use our default backoff".
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(std::time::Duration::from_secs)
}

#[derive(Deserialize)]
struct EmbeddingList {
    #[serde(default)]
    data: Vec<EmbeddingRow>,
}

#[derive(Deserialize)]
struct EmbeddingRow {
    /// Which input this is the embedding of. The array is not promised to be
    /// sorted by it, so this is read rather than the position.
    index: usize,
    #[serde(default)]
    embedding: Vec<f32>,
}

/// Put `rows` back in the caller's order, checking everything the schema
/// assumes on the way.
///
/// Free-standing and pure so the whole of the interesting logic — the
/// permutation, the width, the normalisation — is testable without a socket,
/// which is the only way it gets tested at all in a workspace that holds no key.
///
/// Four refusals, and each one is a thing that would otherwise be silent:
///
/// * a short or long batch — the caller zips this against its chunk texts, so a
///   missing row shifts every embedding after it onto the wrong chunk;
/// * an `index` out of range or seen twice — the same shift, arrived at
///   differently;
/// * a width that is not [`Embedder::DIM`] — a Postgres error mid-ingest at
///   best, and at worst a model whose vectors are quietly unstorable only for
///   the documents somebody has already uploaded;
/// * a vector that will not normalise — a zero or non-finite row makes cosine
///   similarity NaN and poisons every comparison it ever takes part in.
fn place(rows: Vec<EmbeddingRow>, expected: usize) -> Result<Vec<Vec<f32>>, ProviderError> {
    if rows.len() != expected {
        tracing::warn!(
            got = rows.len(),
            expected,
            "the embedder returned a different number of vectors than inputs"
        );
        return Err(ProviderError::Terminal { code: UNUSABLE });
    }

    // `None` is "no row claimed this slot yet", which is what makes a duplicate
    // `index` a refusal rather than a last-write-wins.
    let mut placed: Vec<Option<Vec<f32>>> = vec![None; expected];
    for row in rows {
        if row.embedding.len() != Embedder::DIM {
            tracing::warn!(
                got = row.embedding.len(),
                expected = Embedder::DIM,
                model = OpenAiEmbedder::MODEL,
                "the embedder returned a vector the knowledge column cannot store"
            );
            return Err(ProviderError::Terminal { code: DIM_MISMATCH });
        }
        let Some(slot) = placed.get_mut(row.index).filter(|slot| slot.is_none()) else {
            tracing::warn!(
                index = row.index,
                expected,
                "the embedder returned an index that is out of range or repeated"
            );
            return Err(ProviderError::Terminal { code: UNUSABLE });
        };
        let mut vector = row.embedding;
        if !normalise(&mut vector) {
            tracing::warn!("the embedder returned a vector that will not normalise");
            return Err(ProviderError::Terminal { code: UNUSABLE });
        }
        *slot = Some(vector);
    }

    // Every slot is filled: `rows.len() == expected` and no two rows took the
    // same slot, so this cannot fail. Written as a `collect` into an `Option`
    // rather than an `expect` so that it stays true if the loop above changes.
    placed
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(ProviderError::Terminal { code: UNUSABLE })
}

// ---------------------------------------------------------------------------
// Tests — hermetic: a loopback HTTP server, no account, no key, no network.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    /// A vector of the right width whose components are all `fill`.
    fn wide(fill: f32) -> Vec<f32> {
        vec![fill; Embedder::DIM]
    }

    fn row(index: usize, embedding: Vec<f32>) -> EmbeddingRow {
        EmbeddingRow { index, embedding }
    }

    // -- placement: the whole of the non-trivial logic, without a socket -----

    /// The wire does not promise sorted rows, so the adapter has to put them
    /// back. A positional read passes every other test in this file and ranks
    /// the wrong chunk in production.
    #[test]
    fn rows_are_placed_by_their_index_and_not_by_their_position() {
        let mut first = wide(0.0);
        first[0] = 3.0;
        let mut second = wide(0.0);
        second[1] = 5.0;
        let mut third = wide(0.0);
        third[2] = 7.0;

        // Deliberately shuffled, which is the case the wire allows.
        let placed = place(vec![row(2, third), row(0, first), row(1, second)], 3)
            .expect("a permutation of the inputs");

        assert_eq!(placed.len(), 3);
        // Normalised, so each one is a unit basis vector at its own position.
        assert!((placed[0][0] - 1.0).abs() < 1e-6, "{}", placed[0][0]);
        assert!((placed[1][1] - 1.0).abs() < 1e-6, "{}", placed[1][1]);
        assert!((placed[2][2] - 1.0).abs() < 1e-6, "{}", placed[2][2]);
    }

    /// Every shape that would otherwise be discovered by Postgres, or not at
    /// all.
    #[test]
    fn a_batch_that_cannot_be_trusted_is_refused_before_anything_is_stored() {
        // Short: the caller zips this against its chunks, so a missing row
        // shifts every embedding after it onto the wrong text.
        assert_eq!(
            place(vec![row(0, wide(1.0))], 2),
            Err(ProviderError::Terminal { code: UNUSABLE })
        );
        // Long.
        assert_eq!(
            place(vec![row(0, wide(1.0)), row(1, wide(1.0))], 1),
            Err(ProviderError::Terminal { code: UNUSABLE })
        );
        // Out of range, and the same slot twice — both are the same shift,
        // reached differently, and neither may be papered over.
        assert_eq!(
            place(vec![row(0, wide(1.0)), row(9, wide(1.0))], 2),
            Err(ProviderError::Terminal { code: UNUSABLE })
        );
        assert_eq!(
            place(vec![row(1, wide(1.0)), row(1, wide(1.0))], 2),
            Err(ProviderError::Terminal { code: UNUSABLE })
        );
        // Unusable arithmetic: a zero vector and a non-finite one both make
        // cosine similarity NaN and poison every comparison downstream.
        assert_eq!(
            place(vec![row(0, wide(0.0))], 1),
            Err(ProviderError::Terminal { code: UNUSABLE })
        );
        assert_eq!(
            place(vec![row(0, wide(f32::NAN))], 1),
            Err(ProviderError::Terminal { code: UNUSABLE })
        );

        // And none of these is retryable: asking the same vendor the same
        // question again gets the same answer, and five attempts is five bills.
        for err in [
            place(vec![row(0, wide(1.0))], 2),
            place(vec![row(0, wide(0.0))], 1),
        ] {
            assert!(!err.expect_err("refused").is_retryable());
        }
    }

    /// **The dimension, which is the trap this adapter exists to not fall into.**
    ///
    /// A model of another width is a decision somebody has to make, not a
    /// number to quietly reshape. It gets its own code because the remedy is
    /// its own: this schema stores 1536.
    #[test]
    fn a_vector_of_the_wrong_width_is_refused_by_name() {
        for width in [1024, 1535, 1537, 3072] {
            assert_eq!(
                place(vec![row(0, vec![0.5; width])], 1),
                Err(ProviderError::Terminal { code: DIM_MISMATCH }),
                "a {width}-wide vector was not refused, and vector(1536) is the column"
            );
        }
        // The column, the constant and the model are one number.
        assert_eq!(Embedder::DIM, 1536);
        assert!(place(vec![row(0, wide(0.5))], 1).is_ok());
    }

    // -- the wire ----------------------------------------------------------

    struct FakeApi {
        addr: SocketAddr,
        /// Every request body the adapter sent, in order.
        seen: Arc<Mutex<Vec<Value>>>,
    }

    impl FakeApi {
        async fn start(status: u16) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let seen = Arc::new(Mutex::new(Vec::new()));

            let recorded = Arc::clone(&seen);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move { serve(stream, recorded, status).await });
                }
            });
            Self { addr, seen }
        }

        fn embedder(&self) -> OpenAiEmbedder {
            OpenAiEmbedder::new(Secret::new("sk-not-a-real-key"))
                .with_base_url(format!("http://{}", self.addr))
        }

        fn requests(&self) -> Vec<Value> {
            self.seen.lock().expect("not poisoned").clone()
        }
    }

    async fn serve(mut stream: TcpStream, seen: Arc<Mutex<Vec<Value>>>, status: u16) {
        let mut buffer = Vec::new();
        loop {
            let Some(body) = read_body(&mut stream, &mut buffer).await else {
                return;
            };
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            seen.lock().expect("not poisoned").push(request.clone());

            let payload = if status == 200 {
                // Answered in the order the wire allows and not the order the
                // caller asked in: reversed, so a positional read is wrong.
                let inputs = request["input"].as_array().cloned().unwrap_or_default();
                let width = request["dimensions"].as_u64().unwrap_or(0) as usize;
                let data: Vec<Value> = (0..inputs.len())
                    .rev()
                    .map(|index| {
                        let mut embedding = vec![0.0_f32; width];
                        if let Some(slot) = embedding.get_mut(index) {
                            *slot = 1.0;
                        }
                        json!({ "index": index, "embedding": embedding })
                    })
                    .collect();
                json!({ "object": "list", "data": data })
            } else {
                json!({ "error": { "message": "no" } })
            };
            let body = serde_json::to_vec(&payload).expect("serialize");

            let mut head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
            if status == 429 {
                head.push_str("Retry-After: 11\r\n");
            }
            head.push_str("\r\n");
            let mut out = head.into_bytes();
            out.extend_from_slice(&body);
            if stream.write_all(&out).await.is_err() {
                return;
            }
        }
    }

    async fn read_body(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
        loop {
            if let Some(head) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buffer[..head]).into_owned();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                let start = head + 4;
                if buffer.len() >= start + length {
                    let body = buffer[start..start + length].to_vec();
                    buffer.drain(..start + length);
                    return Some(body);
                }
            }
            let mut chunk = [0_u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// What actually goes on the wire, asserted on the socket rather than taken
    /// from the adapter's word — including the width, which is the whole
    /// argument of this module.
    #[tokio::test]
    async fn the_request_names_the_model_and_asks_for_the_column_width() {
        let fake = FakeApi::start(200).await;
        let vectors = fake
            .embedder()
            .embed(&["damaged pallets".to_owned(), "BRK-4471-XZ".to_owned()])
            .await
            .expect("the fake answered");

        let sent = fake.requests();
        assert_eq!(sent.len(), 1, "one batch is one request");
        assert_eq!(sent[0]["model"], OpenAiEmbedder::MODEL);
        assert_eq!(sent[0]["dimensions"], Embedder::DIM);
        assert_eq!(sent[0]["encoding_format"], "float");
        assert_eq!(
            sent[0]["input"],
            json!(["damaged pallets", "BRK-4471-XZ"]),
            "the batch goes up in the caller's order"
        );

        // And comes back in it, although the fake answered backwards.
        assert_eq!(vectors.len(), 2);
        assert!((vectors[0][0] - 1.0).abs() < 1e-6);
        assert!((vectors[1][1] - 1.0).abs() < 1e-6);
    }

    /// An empty batch costs nothing, because it never becomes a request.
    #[tokio::test]
    async fn an_empty_batch_is_not_a_request() {
        let fake = FakeApi::start(200).await;
        assert_eq!(
            fake.embedder().embed(&[]).await.expect("empty"),
            Vec::<Vec<f32>>::new()
        );
        assert!(
            fake.requests().is_empty(),
            "an empty batch reached the vendor and would have been a 400"
        );
    }

    /// Over the ceiling is refused here, with the batch never leaving the
    /// process — see [`MAX_BATCH`] for why this is a refusal and not a loop.
    #[tokio::test]
    async fn an_oversized_batch_is_refused_without_a_request() {
        let fake = FakeApi::start(200).await;
        let inputs: Vec<String> = (0..=MAX_BATCH).map(|i| i.to_string()).collect();

        assert_eq!(
            fake.embedder().embed(&inputs).await,
            Err(ProviderError::Terminal { code: UNUSABLE })
        );
        assert!(fake.requests().is_empty(), "the vendor was asked anyway");
    }

    /// The status mapping is the shared one, and the vendor's own `Retry-After`
    /// has to survive it: a 429 retried immediately is a 429 again.
    #[tokio::test]
    async fn a_429_is_rate_limited_and_a_401_is_terminal() {
        let throttled = FakeApi::start(429).await;
        let err = throttled
            .embedder()
            .embed(&["x".to_owned()])
            .await
            .expect_err("throttled");
        assert_eq!(
            err,
            ProviderError::RateLimited {
                retry_after: std::time::Duration::from_secs(11)
            }
        );
        assert!(err.is_retryable());

        // The customer's key, expired or wrong. Retrying it forever spends the
        // turn budget on discovering the same thing.
        let refused = FakeApi::start(401).await;
        let err = refused
            .embedder()
            .embed(&["x".to_owned()])
            .await
            .expect_err("refused");
        assert_eq!(
            err,
            ProviderError::Terminal {
                code: "unauthorized"
            }
        );
        assert!(!err.is_retryable());
    }

    /// The key is a credential and the adapter is a struct somebody will one
    /// day put in a log line.
    #[test]
    fn debug_never_reveals_the_key() {
        let rendered = format!("{:?}", OpenAiEmbedder::new(Secret::new("sk-hunter2")));
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains(Secret::REDACTED), "{rendered}");
    }
}
