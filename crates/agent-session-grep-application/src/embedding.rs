//! Bigram-hash vectorizer (#3 default), and the contract a real model plugs into.
//!
//! This is NOT a semantic embedding model. It maps text to a deterministic
//! vector by hashing the text and its character bigrams, so two texts that
//! share bigrams get correlated dimensions. That yields fuzzy lexical
//! similarity (typo tolerance, substring overlap, CJK without word
//! segmentation) — it does not capture meaning. Two paraphrases with no shared
//! bigrams score near zero.
//!
//! It ships as the default because it is honest about what it does, needs no
//! model download, and makes the whole vector path real end to end (storage,
//! rebuild, hybrid fusion, benchmark). A real semantic model (ONNX Runtime /
//! candle, e.g. multilingual-e5-small) implements the same `EmbeddingModel`
//! trait and swaps in without touching `SemanticIndex` or `hybrid::fuse`; the
//! manifest already carries the model id/hash/dimension/license it needs.
//!
//! Per the roadmap, semantic/hybrid retrieval may not be promoted past beta or
//! made the default on the strength of this vectorizer alone — lexical stays
//! the default until a real model clears the recall benchmark.
//!
//! The 384 dimensions match multilingual-e5-small so the storage layout does
//! not change when a real model replaces this one.

use agent_session_grep_ports::{EmbeddingManifest, EmbeddingModel, PortResult};

/// Vector dimension (matches multilingual-e5-small so storage is unchanged
/// when a real model swaps in).
pub const BIGRAM_HASH_DIMENSION: usize = 384;

/// The model id recorded alongside every stored vector. Changing the
/// vectorizer MUST change this id: `message_vec` rows are scoped by model id,
/// so a new id makes the old vectors inert instead of silently mixing
/// incomparable vector spaces.
pub const BIGRAM_HASH_MODEL_ID: &str = "bigram-hash-v1";

/// Manifest for the bigram-hash vectorizer.
pub fn bigram_hash_manifest() -> EmbeddingManifest {
    EmbeddingManifest {
        model_id: BIGRAM_HASH_MODEL_ID.to_string(),
        file_hash: "n/a (computed in-process, no model file)".to_string(),
        dimension: BIGRAM_HASH_DIMENSION,
        license: "MIT OR Apache-2.0".to_string(),
    }
}

/// A deterministic bigram-hash vectorizer.
///
/// Same text always produces the same vector. Texts sharing character bigrams
/// produce vectors with correlated dimensions, giving fuzzy lexical similarity
/// — not semantic similarity.
pub struct BigramHashModel {
    manifest: EmbeddingManifest,
}

impl BigramHashModel {
    pub fn new() -> Self {
        Self {
            manifest: bigram_hash_manifest(),
        }
    }
}

impl Default for BigramHashModel {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbeddingModel for BigramHashModel {
    fn embed(&self, text: &str, is_query: bool) -> PortResult<Vec<f32>> {
        // Query/passage prefixes follow the E5 convention so a real E5 model
        // can replace this one without changing callers.
        let prefixed = if is_query {
            format!("query: {text}")
        } else {
            format!("passage: {text}")
        };
        Ok(hash_to_vector(&prefixed, BIGRAM_HASH_DIMENSION))
    }

    fn dimension(&self) -> usize {
        BIGRAM_HASH_DIMENSION
    }

    fn manifest(&self) -> &EmbeddingManifest {
        &self.manifest
    }
}

/// Hash text to a fixed-dimensional L2-normalized vector.
///
/// Uses BLAKE3 to produce a deterministic byte stream, then maps it to
/// float dimensions. For approximate similarity, we also hash bigrams of
/// the text and accumulate their contributions into the same vector space
/// — texts sharing bigrams will have correlated dimensions.
fn hash_to_vector(text: &str, dim: usize) -> Vec<f32> {
    let mut vec = vec![0.0f32; dim];

    // Full-text hash → seeds the vector.
    let full_hash = blake3::hash(text.as_bytes());
    for (i, byte) in full_hash.as_bytes().iter().enumerate() {
        let idx = (i * 7 + *byte as usize) % dim;
        vec[idx] += (*byte as f32 / 255.0) * 0.5;
    }

    // Bigram hashing for approximate similarity.
    let chars: Vec<char> = text.chars().collect();
    for window in chars.windows(2) {
        let bigram: String = window.iter().collect();
        let h = blake3::hash(bigram.as_bytes());
        let bytes = h.as_bytes();
        let idx = (u16::from_le_bytes([bytes[0], bytes[1]]) as usize) % dim;
        vec[idx] += 1.0;
    }

    // L2 normalize.
    let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for v in &mut vec {
            *v /= norm;
        }
    }

    vec
}

/// Cosine similarity between two vectors (dot product of L2-normalized vectors).
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_produces_correct_dimension() {
        let model = BigramHashModel::new();
        let emb = model.embed("hello world", false).unwrap();
        assert_eq!(emb.len(), BIGRAM_HASH_DIMENSION);
        assert_eq!(model.dimension(), BIGRAM_HASH_DIMENSION);
    }

    #[test]
    fn same_text_produces_same_vector() {
        let model = BigramHashModel::new();
        let a = model.embed("hello world", false).unwrap();
        let b = model.embed("hello world", false).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_text_produces_different_vector() {
        let model = BigramHashModel::new();
        let a = model.embed("hello world", false).unwrap();
        let b = model.embed("goodbye universe", false).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn query_and_passage_prefixes_differ() {
        let model = BigramHashModel::new();
        let q = model.embed("hello", true).unwrap();
        let p = model.embed("hello", false).unwrap();
        assert_ne!(q, p);
    }

    #[test]
    fn similar_texts_have_higher_similarity_than_dissimilar() {
        let model = BigramHashModel::new();
        let a = model.embed("the quick brown fox", false).unwrap();
        let b = model.embed("the quick brown dog", false).unwrap();
        let c = model.embed("completely different text", false).unwrap();
        let sim_ab = cosine_similarity(&a, &b);
        let sim_ac = cosine_similarity(&a, &c);
        // Texts sharing bigrams ("the ", "he q", " qu", etc.) should be
        // more similar than completely different texts.
        assert!(
            sim_ab >= sim_ac,
            "sim(a,b)={sim_ab} should be >= sim(a,c)={sim_ac}"
        );
    }

    #[test]
    fn vectors_are_l2_normalized() {
        let model = BigramHashModel::new();
        let emb = model.embed("some text here for testing", false).unwrap();
        let norm: f32 = emb.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "norm should be ~1.0, got {norm}");
    }

    #[test]
    fn cosine_similarity_identical_is_one() {
        let model = BigramHashModel::new();
        let a = model.embed("identical text", false).unwrap();
        let sim = cosine_similarity(&a, &a);
        assert!(
            (sim - 1.0).abs() < 0.01,
            "self-similarity should be ~1.0, got {sim}"
        );
    }

    #[test]
    fn manifest_is_stamped() {
        let model = BigramHashModel::new();
        let m = model.manifest();
        assert_eq!(m.model_id, BIGRAM_HASH_MODEL_ID);
        assert_eq!(m.dimension, BIGRAM_HASH_DIMENSION);
    }

    #[test]
    fn model_id_scopes_stored_vectors() {
        // 换 vectorizer 必须换 model_id：message_vec 行按 model_id 隔离，
        // 沿用旧 id 会让不可比的向量空间静默混在一起。
        assert_eq!(BIGRAM_HASH_MODEL_ID, "bigram-hash-v1");
        assert_eq!(bigram_hash_manifest().model_id, BIGRAM_HASH_MODEL_ID);
    }

    #[test]
    fn empty_text_does_not_panic() {
        let model = BigramHashModel::new();
        let emb = model.embed("", false).unwrap();
        assert_eq!(emb.len(), BIGRAM_HASH_DIMENSION);
    }

    #[test]
    fn different_dimensions_dont_match() {
        let sim = cosine_similarity(&[1.0, 0.0], &[1.0, 0.0, 0.0]);
        assert_eq!(sim, 0.0);
    }
}
