//! The embedding port.
//!
//! Retrieval tests are worthless if they are flaky, and they are flaky the
//! moment they call a real embedding API: the vectors move between model
//! versions, the call needs a key, and it costs money per assertion. So
//! [`Embedder::Mock`] derives its vector from a hash of the input and nothing
//! else — same string in, byte-identical vector out, on any machine, forever,
//! with no network. It is the default, and every test in this workspace runs on
//! it.
//!
//! It is a *hash*, so it makes no attempt at semantics: "cat" and "kitten" are
//! as unrelated as "cat" and "diesel". That is fine, and it is the deliberate
//! limit of what this mock proves. Use it to test the plumbing — dimensions,
//! batching, storage round-trips, top-k ordering, cosine arithmetic — and use a
//! real embedder to test whether retrieval finds the right documents.
//!
//! Vectors are unit-length, so cosine similarity is a plain dot product and the
//! store never has to know which embedder produced a row.
//!
//! # The real one, and what selecting it changes
//!
//! [`Embedder::OpenAi`] is [`crate::embedder_openai`], selected by
//! `EMBEDDER_API_KEY` exactly as email, telephony and browser are selected by
//! theirs. Two things follow from the credential and neither is cosmetic:
//! [`Embedder::is_semantic`] becomes `true`, which is what makes
//! `agentos_app::knowledge::retrieve` run the vector leg it refuses to run on a
//! hash; and `agentos_app::knowledge::model_name` stamps a different model on
//! every chunk, which is what keeps the two vector spaces from mixing in one
//! table.
//!
//! **The dimension does not change and cannot.** [`Embedder::DIM`] is the
//! `vector(1536)` column, and the real adapter refuses a model of another width
//! rather than projecting one to fit — see that module's header for the whole
//! argument, which is the one thing about this port worth reading before adding
//! a third variant.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::ProviderError;
use crate::embedder_openai::OpenAiEmbedder;

/// Which embedding backend to use.
///
/// Two variants. Further real adapters (Voyage, Bedrock) land here as further
/// variants; [`Embedder::embed`] stays the whole surface, and [`Embedder::DIM`]
/// stays the contract they must satisfy — a backend with a different dimension
/// is a schema migration, not a config change, and until somebody writes that
/// migration it is a refusal.
///
/// Not `Copy`, and not `PartialEq`: a real adapter holds an HTTP client and a
/// key, so it is an `Arc` behind a variant rather than a value in a register.
/// Callers take `&Embedder`.
#[derive(Debug, Clone, Default)]
pub enum Embedder {
    /// Deterministic hash-to-vector. No network, no key, no cost.
    #[default]
    Mock,
    /// The real client, against the customer's own key.
    OpenAi(Arc<OpenAiEmbedder>),
}

impl Embedder {
    /// Dimension of every vector this crate produces.
    ///
    /// Baked into the `vector(1536)` column, so it is a constant rather than a
    /// per-call parameter: a mismatch must fail at the type level here, or at
    /// the adapter boundary for a vendor that answers with another width — not
    /// as a Postgres error three layers down.
    pub const DIM: usize = 1536;

    /// **Whether the distance between two of these vectors means anything.**
    ///
    /// `false` is not a caveat to note in a doc comment, it is a branch a
    /// caller has to take. A hash embedder's nearest neighbours are an
    /// arbitrary draw from the corpus, and they are an arbitrary draw that
    /// arrives *sorted*, with a score attached, in the shape of an answer. Rank
    /// by them and a `LIMIT 5` is five confident unrelated passages rather than
    /// nothing — which is the worse of the two, because nothing is visibly
    /// nothing. `agentos_app::knowledge::retrieve` is the caller that branches,
    /// and it drops the vector leg entirely when this is `false`.
    ///
    /// Exhaustive on purpose: a real backend cannot be added without answering
    /// this, and the answer decides whether retrieval ranks by meaning at all.
    pub const fn is_semantic(&self) -> bool {
        match self {
            Self::Mock => false,
            // A trained embedding model, which is the whole reason to pay for
            // one. This `true` is what turns `retrieve` back into a hybrid
            // search, and it is the only line in this workspace that does.
            Self::OpenAi(_) => true,
        }
    }

    /// Embed a batch, preserving order.
    ///
    /// The result has exactly `inputs.len()` rows, each exactly [`Self::DIM`]
    /// long and L2-normalised. An empty batch yields an empty result rather
    /// than an error — callers filter before they embed, and an empty filter is
    /// not a failure. On the real adapter it is also not a request.
    ///
    /// `async` for the one variant that has a socket. The mock never awaits
    /// anything and every test in the workspace pays a state machine for it,
    /// which is the price of the port having one shape rather than two.
    pub async fn embed(&self, inputs: &[String]) -> Result<Vec<Vec<f32>>, ProviderError> {
        match self {
            Self::Mock => Ok(inputs.iter().map(|text| mock_vector(text)).collect()),
            Self::OpenAi(client) => client.embed(inputs).await,
        }
    }
}

/// Scale `vector` to unit length in place. `false` when it cannot be: a zero
/// vector, or one carrying a NaN or an infinity.
///
/// Shared by both variants rather than written twice, because the invariant is
/// the port's and not an adapter's: the store compares vectors from one model
/// with a cosine distance, and one row that will not normalise is a row whose
/// every future comparison is NaN.
///
/// `norm.is_finite()` is the whole check. A NaN component makes the sum of
/// squares NaN and an infinite one makes it infinite, so both fall out of the
/// one condition rather than needing a scan of their own.
pub(crate) fn normalise(vector: &mut [f32]) -> bool {
    let norm = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
    if !norm.is_finite() || norm == 0.0 {
        return false;
    }
    for x in vector {
        *x /= norm;
    }
    true
}

/// SHA-256 the input, then stretch the digest into `DIM` floats with SplitMix64
/// and normalise.
///
/// SplitMix64 rather than another hash per component: 1536 SHA-256 calls per
/// document is real cost in an ingest loop, and the sequence only has to be
/// deterministic and well-spread, not unpredictable.
fn mock_vector(text: &str) -> Vec<f32> {
    let digest = Sha256::digest(text.as_bytes());
    let mut seed = u64::from_le_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"));

    let mut vector: Vec<f32> = (0..Embedder::DIM)
        .map(|_| {
            // SplitMix64.
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            // Top 24 bits into (-1.0, 1.0); 24 bits is f32's mantissa.
            ((z >> 40) as f32 / (1u32 << 23) as f32) - 1.0
        })
        .collect();

    if !normalise(&mut vector) {
        // Unreachable for any real digest, but a zero vector would make cosine
        // similarity NaN and poison every comparison downstream.
        vector[0] = 1.0;
    }
    vector
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn embed_one(text: &str) -> Vec<f32> {
        Embedder::Mock
            .embed(std::slice::from_ref(&text.to_owned()))
            .await
            .unwrap()
            .pop()
            .unwrap()
    }

    fn norm(v: &[f32]) -> f32 {
        v.iter().map(|x| x * x).sum::<f32>().sqrt()
    }

    fn dot(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| x * y).sum()
    }

    #[tokio::test]
    async fn the_same_input_always_gives_the_same_vector() {
        let once = embed_one("provisioning runbook, section 3").await;
        let twice = embed_one("provisioning runbook, section 3").await;
        assert_eq!(once, twice);

        // Including across batch shapes and positions.
        let batched = Embedder::Mock
            .embed(&[
                "filler".to_owned(),
                "provisioning runbook, section 3".to_owned(),
            ])
            .await
            .unwrap();
        assert_eq!(batched[1], once);
    }

    #[tokio::test]
    async fn every_vector_has_the_right_dimension_and_unit_norm() {
        let inputs: Vec<String> = ["", "a", "lena@agents.example.com", &"x".repeat(10_000)]
            .into_iter()
            .map(str::to_owned)
            .collect();

        let vectors = Embedder::Mock.embed(&inputs).await.unwrap();
        assert_eq!(vectors.len(), inputs.len());

        for vector in &vectors {
            assert_eq!(vector.len(), Embedder::DIM);
            assert!(vector.iter().all(|x| x.is_finite()));
            assert!(
                (norm(vector) - 1.0).abs() < 1e-4,
                "norm was {}",
                norm(vector)
            );
            // Unit norm and self-similarity 1 are the same statement, and the
            // second is the one retrieval code actually relies on.
            assert!((dot(vector, vector) - 1.0).abs() < 1e-4);
        }
    }

    #[tokio::test]
    async fn different_inputs_give_different_vectors() {
        let a = embed_one("cat").await;
        let b = embed_one("kitten").await;
        let c = embed_one("cat ").await; // one trailing space
        assert_ne!(a, b);
        assert_ne!(a, c);

        // A hash embedder is not a semantic one: nothing here should look
        // similar to anything else, and no test may come to depend on it.
        assert!(
            dot(&a, &b).abs() < 0.2,
            "unexpected structure: {}",
            dot(&a, &b)
        );
        assert!(dot(&a, &c).abs() < 0.2);

        // The same fact, in the form a caller can branch on. "cat" and "kitten"
        // being orthogonal is the evidence; `is_semantic` is what retrieval
        // reads, and the two must not be able to disagree.
        assert!(
            !Embedder::Mock.is_semantic(),
            "a backend whose nearest neighbours are a hash draw claimed to rank by meaning"
        );
    }

    #[tokio::test]
    async fn an_empty_batch_is_not_an_error() {
        assert_eq!(
            Embedder::Mock.embed(&[]).await.unwrap(),
            Vec::<Vec<f32>>::new()
        );
    }

    #[test]
    fn the_dimension_matches_the_stored_column() {
        assert_eq!(Embedder::DIM, 1536);
        assert!(matches!(Embedder::default(), Embedder::Mock));
    }

    /// The branch every caller reads, and the two variants must not agree about
    /// it — that agreement is precisely what "the credential selects nothing"
    /// looked like.
    #[test]
    fn only_the_real_backend_claims_to_rank_by_meaning() {
        let real = Embedder::OpenAi(Arc::new(OpenAiEmbedder::new(crate::Secret::new(
            "sk-not-a-real-key",
        ))));
        assert!(real.is_semantic());
        assert!(!Embedder::Mock.is_semantic());
    }

    /// The shared invariant, at the boundary values the port's arithmetic
    /// breaks on.
    #[test]
    fn a_vector_that_cannot_be_normalised_says_so_rather_than_becoming_nan() {
        let mut zero = vec![0.0_f32; 4];
        assert!(!normalise(&mut zero));
        let mut nan = vec![1.0, f32::NAN, 0.0, 0.0];
        assert!(!normalise(&mut nan));
        let mut infinite = vec![f32::INFINITY, 1.0, 0.0, 0.0];
        assert!(!normalise(&mut infinite));

        let mut ordinary = vec![3.0_f32, 4.0, 0.0, 0.0];
        assert!(normalise(&mut ordinary));
        assert!((norm(&ordinary) - 1.0).abs() < 1e-6);
        assert!((ordinary[0] - 0.6).abs() < 1e-6);
    }
}
