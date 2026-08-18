//! Hybrid retrieval: Reciprocal Rank Fusion (RRF) of lexical + semantic results.
//!
//! RRF merges two ranked lists into one without needing score calibration.
//! Weighted variant: `score(d) = w_lexical * 1/(k + rank_lexical) +
//! w_semantic * 1/(k + rank_semantic)`. Default weights are equal (0.5/0.5),
//! k=60 (following ctx's production tuning; Recall uses k=10).
//!
//! Reference: ctx (Apache-2.0) `src/search.rs` weighted RRF k=60.

use agent_session_grep_ports::SearchHit;

/// RRF 常数 k：抑制高排名结果的过度优势。ctx 用 60，Recall 用 10。
const DEFAULT_K: u64 = 60;

/// 融合 lexical 和 semantic 检索结果，返回按 RRF 分数降序的合并列表。
///
/// 输入两个列表各自按相关性降序排列；输出合并后同样降序。
/// 同一消息在两个列表中都出现时，两个 RRF 分数相加。
pub fn fuse(lexical: &[SearchHit], semantic: &[SearchHit]) -> Vec<SearchHit> {
    fuse_weighted(lexical, semantic, 0.5, 0.5, DEFAULT_K)
}

/// 加权 RRF 融合。`w_lexical` + `w_semantic` 应为 1.0（未归一化时自动归一化）。
pub fn fuse_weighted(
    lexical: &[SearchHit],
    semantic: &[SearchHit],
    w_lexical: f64,
    w_semantic: f64,
    k: u64,
) -> Vec<SearchHit> {
    let total = w_lexical + w_semantic;
    if total == 0.0 {
        return Vec::new();
    }
    let wl = w_lexical / total;
    let ws = w_semantic / total;

    // 用 StableId 字符串作为去重键。
    use std::collections::HashMap;
    let mut scores: HashMap<String, (f64, SearchHit)> = HashMap::new();

    for (rank, hit) in lexical.iter().enumerate() {
        let key = hit.id.as_str().to_string();
        let rrf = wl / (k as f64 + (rank + 1) as f64);
        scores
            .entry(key)
            .and_modify(|(s, _)| *s += rrf)
            .or_insert_with(|| (rrf, hit.clone()));
    }
    for (rank, hit) in semantic.iter().enumerate() {
        let key = hit.id.as_str().to_string();
        let rrf = ws / (k as f64 + (rank + 1) as f64);
        scores
            .entry(key)
            .and_modify(|(s, _)| *s += rrf)
            .or_insert_with(|| (rrf, hit.clone()));
    }

    let mut fused: Vec<(f64, SearchHit)> = scores.into_values().collect();
    // RRF 分数高的排前面；同分按 id 排序保证确定性。
    fused.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.id.as_str().cmp(b.1.id.as_str()))
    });

    // 把 RRF 分数写入 hit.score（保留原 score 语义为"命中来源"，见 #3 Req 5）。
    fused
        .into_iter()
        .map(|(rrf, mut hit)| {
            hit.score = rrf as f32;
            hit
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::StableId;

    fn hit(id: &str, score: f32) -> SearchHit {
        SearchHit {
            id: StableId::from_wire(id).unwrap_or_else(|| StableId::from_wire("msg_v1_0").unwrap()),
            score,
            session_id: None,
            text: None,
            why_matched: Vec::new(),
            suggested_next_commands: Vec::new(),
            occurrences: 1,
            resume_available: false,
        }
    }

    #[test]
    fn fuse_merges_disjoint_lists() {
        let lexical = vec![hit("msg_v1_aaa", 1.0), hit("msg_v1_bbb", 0.8)];
        let semantic = vec![hit("msg_v1_ccc", 1.0), hit("msg_v1_ddd", 0.8)];
        let fused = fuse(&lexical, &semantic);
        assert_eq!(fused.len(), 4);
    }

    #[test]
    fn fuse_deduplicates_overlapping_hits() {
        let lexical = vec![hit("msg_v1_aaa", 1.0), hit("msg_v1_bbb", 0.8)];
        let semantic = vec![hit("msg_v1_aaa", 1.0), hit("msg_v1_ccc", 0.8)];
        let fused = fuse(&lexical, &semantic);
        assert_eq!(fused.len(), 3);
        // aaa appears in both → highest RRF score → first.
        assert_eq!(fused[0].id.as_str(), "msg_v1_aaa");
    }

    #[test]
    fn fuse_is_deterministic() {
        let lexical = vec![hit("msg_v1_aaa", 1.0), hit("msg_v1_bbb", 0.8)];
        let semantic = vec![hit("msg_v1_ccc", 1.0), hit("msg_v1_ddd", 0.8)];
        let fused1 = fuse(&lexical, &semantic);
        let fused2 = fuse(&lexical, &semantic);
        assert_eq!(fused1.len(), fused2.len());
        for (a, b) in fused1.iter().zip(fused2.iter()) {
            assert_eq!(a.id.as_str(), b.id.as_str());
        }
    }

    #[test]
    fn fuse_empty_lists() {
        let fused: Vec<SearchHit> = fuse(&[], &[]);
        assert!(fused.is_empty());
    }

    #[test]
    fn fuse_weighted_favors_higher_weight() {
        let lexical = vec![hit("msg_v1_aaa", 1.0)];
        let semantic = vec![hit("msg_v1_aaa", 1.0)];
        // Equal weights → equal RRF contributions.
        let fused_equal = fuse_weighted(&lexical, &semantic, 0.5, 0.5, DEFAULT_K);
        // Lexical-heavy weight → lexical rank contribution dominates.
        let fused_lex = fuse_weighted(&lexical, &semantic, 0.9, 0.1, DEFAULT_K);
        assert_eq!(fused_equal.len(), 1);
        assert_eq!(fused_lex.len(), 1);
        // Both should have the same single hit.
        assert_eq!(fused_equal[0].id.as_str(), "msg_v1_aaa");
        assert_eq!(fused_lex[0].id.as_str(), "msg_v1_aaa");
    }
}
