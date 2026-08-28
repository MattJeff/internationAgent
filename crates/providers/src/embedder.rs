//! The embedding port.
//!
//! Retrieval tests are worthless if they are flaky, and they are flaky the
//! moment they call a real embedding API: the vectors move between model
//! versions, the call needs a key, and it costs money per assertion. So
//! [`Embedder::Mock`] derives its vector from a hash of the input and nothing
//! else — same string in, byte-identical vector out, on any machine, forever,
//! with no network.
//!
//! It is a *hash*, so it makes no attempt at semantics: "cat" and "kitten" are
//! as unrelated as "cat" and "diesel". That is fine, and it is the deliberate
//! limit of what this mock proves. Use it to test the plumbing — dimensions,
//! batching, storage round-trips, top-k ordering, cosine arithmetic — and use a
//! real embedder to test whether retrieval finds the right documents.
//!
//! Vectors are unit-length, so cosine similarity is a plain dot product and the
//! store never has to know which embedder produced a row.

use sha2::{Digest, Sha256};

use crate::ProviderError;

/// Which embedding backend to use.
///
/// One variant today. Real adapters (Voyage, OpenAI, Bedrock) land here as
/// further variants; [`Embedder::embed`] stays the whole surface, and
/// [`Embedder::DIM`] stays the contract they must satisfy — a backend with a
/// different dimension is a schema migration, not a config change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Embedder {
    /// Deterministic hash-to-vector. No network, no key, no cost.
    #[default]
    Mock,
}

impl Embedder {
    /// Dimension of every vector this crate produces.
    ///
    /// Baked into the `vector(1536)` column, so it is a constant rather than a
    /// per-call parameter: a mismatch must fail at the type level here, not as
    /// a Postgres error three layers down.
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
    pub const fn is_semantic(self) -> bool {
        match self {
            Self::Mock => false,
        }
    }

    /// Embed a batch, preserving order.
    ///
    /// The result has exactly `inputs.len()` rows, each exactly [`Self::DIM`]
    /// long and L2-normalised. An empty batch yields an empty result rather
    /// than an error — callers filter before they embed, and an empty filter is
    /// not a failure.
    pub fn embed(&self, inputs: &[String]) -> Result<Vec<Vec<f32>>, ProviderError> {
        match self {
            Self::Mock => Ok(inputs.iter().map(|text| mock_vector(text)).collect()),
        }
    }
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

    let norm = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut vector {
            *x /= norm;
        }
    } else {
        // Unreachable for any real digest, but a zero vector would make cosine
        // similarity NaN and poison every comparison downstream.
        vector[0] = 1.0;
    }
    vector
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embed_one(text: &str) -> Vec<f32> {
        Embedder::Mock
            .embed(std::slice::from_ref(&text.to_owned()))
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

    #[test]
    fn the_same_input_always_gives_the_same_vector() {
        let once = embed_one("provisioning runbook, section 3");
        let twice = embed_one("provisioning runbook, section 3");
        assert_eq!(once, twice);

        // Including across batch shapes and positions.
        let batched = Embedder::Mock
            .embed(&[
                "filler".to_owned(),
                "provisioning runbook, section 3".to_owned(),
            ])
            .unwrap();
        assert_eq!(batched[1], once);
    }

    #[test]
    fn every_vector_has_the_right_dimension_and_unit_norm() {
        let inputs: Vec<String> = ["", "a", "lena@agents.example.com", &"x".repeat(10_000)]
            .into_iter()
            .map(str::to_owned)
            .collect();

        let vectors = Embedder::Mock.embed(&inputs).unwrap();
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

    #[test]
    fn different_inputs_give_different_vectors() {
        let a = embed_one("cat");
        let b = embed_one("kitten");
        let c = embed_one("cat "); // one trailing space
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

    #[test]
    fn an_empty_batch_is_not_an_error() {
        assert_eq!(Embedder::Mock.embed(&[]).unwrap(), Vec::<Vec<f32>>::new());
    }

    #[test]
    fn the_dimension_matches_the_stored_column() {
        assert_eq!(Embedder::DIM, 1536);
        assert_eq!(Embedder::default(), Embedder::Mock);
    }
}
