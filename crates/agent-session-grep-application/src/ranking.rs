//! Lexical search rank signals（competitor-borrowings #1）：把 relevance 相关性、
//! 时效衰减、sidechain 惩罚与当前仓库偏好合成为单一评分函数。
//!
//! 借鉴来源：
//! - AgentRecall `smartScore`：30 天指数半衰期衰减（`decay = 0.5^(ageDays/30)`，
//!   经 `(floor + (1-floor)*decay)` 插值保住下限）；
//! - sessiongrep：FTS 召回后应用层重排补充新鲜度/业务信号（本模块同构），
//!   其"当前仓库 +200"即本模块 [`CURRENT_REPO_SCORE_BOOST`] 的来源（量级按本仓
//!   relevance 口径重新定标，不照搬数值）；
//! - agentsview：subordinate（sidechain/subagent）命中 rank+5 的 RRF 惩罚精神。
//!
//! 教训（deep-read-claude-historian-mcp.md §11.7）：多层经验参数无测试固化必
//! 回归——本模块是唯一评分入口（单一函数 [`final_score`]），全部参数集中在
//! 下方常量区，且每个参数都有单测锚定（半衰期/下限/钳制/惩罚值/加分值/确定性）。
//!
//! 边界（README 明示）：
//! - 只作用于纯 lexical 检索（含 semantic/hybrid 未就绪时的 lexical_fallback）
//!   的命中排序；semantic 命中与 hybrid RRF 融合排序不受影响；
//! - 无 timestamp（缺失/null/非法）的命中按 0 龄处理（衰减恒 1.0）——
//!   无信号不加罚；`is_sidechain` 缺失或 null（歧义）按 false，不惩罚未知；
//! - 当前仓库偏好同样"无信号不动分"：调用方没有可派生的仓库身份（不在 git
//!   工作树内、无 origin、或该入口没有 cwd 语义）时该项恒 0，且不产生任何
//!   额外读取；会话侧无 repo 投影行同理（未知 ≠ 匹配）；
//! - recency 随注入时钟推移、当前仓库偏好随调用方 cwd 变化（均为生产特性），
//!   测试必须注入固定时钟与固定 slug 保持确定性。

use agent_session_grep_ports::SearchHit;

/// 时效半衰期（天）：30 天前的时间戳衰减到 0.5（AgentRecall smartScore 同款）。
pub const RECENCY_HALF_LIFE_DAYS: f64 = 30.0;

/// 时效衰减下限：无论多老都保留该比例的 relevance 分，防止老消息被完全压没。
pub const RECENCY_DECAY_FLOOR: f64 = 0.3;

/// One first-place contribution under RRF with k=60.
const RRF_SCORE_UNIT: f32 = 1.0 / 61.0;

/// Fixed sidechain penalty: a quarter of a first-place RRF contribution.
/// A strong sidechain match may still outrank a weak mainline match.
pub const SIDECHAIN_SCORE_PENALTY: f32 = 0.25 * RRF_SCORE_UNIT;

/// Current-repository preference: half a first-place RRF contribution.
/// This is an explicit policy scale, not a relevance-calibration claim.
pub const CURRENT_REPO_SCORE_BOOST: f32 = 0.5 * RRF_SCORE_UNIT;

/// 每天毫秒数（仅内部换算用，非调参常量）。
const MS_PER_DAY: f64 = 86_400_000.0;

/// 指数半衰期衰减：`0.5^(age / half_life)`。
///
/// - `age` 钳制 ≥ 0：未来时间戳按 0 龄处理（衰减 1.0，无惩罚）；
/// - 结果钳制下限 [`RECENCY_DECAY_FLOOR`]：老消息不被完全压没。
pub fn recency_decay(age_ms: i64) -> f64 {
    let age_days = age_ms.max(0) as f64 / MS_PER_DAY;
    let decay = 0.5_f64.powf(age_days / RECENCY_HALF_LIFE_DAYS);
    decay.max(RECENCY_DECAY_FLOOR)
}

/// 单一评分函数：
/// `final = max(0, relevance × decay(age) − sidechain_penalty + current_repo_boost)`。
///
/// 惩罚与加分同量纲、同一表达式内合成后才钳制到 0——先钳制再加分会让所有被
/// 钳到 0 的命中"凭偏好复活"，顺序失去意义。
///
/// 证据门（B4，D3 边界 1）：`relevance <= 0`（含 NaN）视为零证据候选，直接
/// 返回 0.0——recency/repo 偏好信号只能放大已准入的证据，不得把"无证据"变成
/// "有候选"。准入本身属于检索端口（FTS MATCH / 相似度下限），此处的防御锁死
/// 未来新增候选源（ANN 平局、外部 rerank）忘记设门的情形；当前生产 lexical
/// 命中分恒 > 0，防御不可达但必须存在且有测试锚定。
///
/// 展示的 `score` 字段即本函数输出；relevance 原值不保留在命中结构里
/// （why_matched/guidance 不消费 score，语义不变）。
pub fn final_score(relevance: f32, age_ms: i64, is_sidechain: bool, in_current_repo: bool) -> f32 {
    // `<= 0` 与 NaN 都视为零证据（NaN 不满足任何序关系，单独判定）。
    if relevance <= 0.0 || relevance.is_nan() {
        return 0.0;
    }
    let mut score = f64::from(relevance) * recency_decay(age_ms);
    if is_sidechain {
        score -= f64::from(SIDECHAIN_SCORE_PENALTY);
    }
    if in_current_repo {
        score += f64::from(CURRENT_REPO_SCORE_BOOST);
    }
    // 用 `> 0.0` 而非 `max(0.0)`：钳制的同时把 `-0.0` 与 NaN 归一为 `+0.0`
    // （`max(-0.0, 0.0)` 的符号在不同平台上未定义），保证
    // (final desc, id asc) 排序跨平台逐位稳定。
    if score > 0.0 { score as f32 } else { 0.0 }
}

/// 从 canonical payload 解析 message 时间戳（RFC3339 串，与
/// [`crate::parse_search_instant`] 同一解析器）为 Unix 毫秒；
/// 缺失/非字符串/非法 → `None`（调用方按 0 龄处理）。
fn payload_timestamp_ms(payload: Option<&[u8]>) -> Option<i64> {
    let value: serde_json::Value = serde_json::from_slice(payload?).ok()?;
    let instant = crate::parse_search_instant(value.get("timestamp")?.as_str()?)?;
    Some(
        instant
            .unix_seconds
            .saturating_mul(1_000)
            .saturating_add(i64::from(instant.nanosecond / 1_000_000)),
    )
}

/// 从 canonical payload 解析 `is_sidechain`；缺失/null（歧义）按 false——
/// 不惩罚未知，与 store 侧 canonical payload 的 `is_sidechain: null` 语义一致。
fn payload_is_sidechain(payload: Option<&[u8]>) -> bool {
    let value: serde_json::Value =
        match payload.and_then(|bytes| serde_json::from_slice(bytes).ok()) {
            Some(value) => value,
            None => return false,
        };
    value
        .get("is_sidechain")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// 对纯 lexical 扫描窗应用排序信号：逐 hit 从 canonical payload 派生
/// 时效与 sidechain 事实，重算 `hit.score` 为最终分，并重排为
/// `(final desc, id asc)` 全序（与 store 层 relevance+id 的钉住排序同一 tiebreak
/// 约定，保证同 query 同 clock 下分页稳定）。
///
/// 输入是已与命中同序配对的 `(hit, payload, in_current_repo)` 三元组——排序
/// 发生在配对之后，结构上排除"重排后 payload/仓库事实错位"的可能；
/// `in_current_repo` 由调用方从会话 repo 投影派生（无当前仓库身份的调用方
/// 一律 false，不加分）；`now_ms` 来自注入的应用时钟。
pub(crate) fn apply_lexical_signals(
    scored: Vec<(SearchHit, Option<Vec<u8>>, bool)>,
    now_ms: i64,
) -> Vec<SearchHit> {
    let mut ranked: Vec<SearchHit> = scored
        .into_iter()
        .map(|(mut hit, payload, in_current_repo)| {
            let age_ms = payload_timestamp_ms(payload.as_deref())
                .map_or(0, |timestamp_ms| now_ms.saturating_sub(timestamp_ms));
            hit.score = final_score(
                hit.score,
                age_ms,
                payload_is_sidechain(payload.as_deref()),
                in_current_repo,
            );
            hit
        })
        .collect();
    ranked.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.as_str().cmp(right.id.as_str()))
    });
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::{IdKind, StableId};

    const DAY_MS: i64 = 86_400_000;

    fn hit(tag: &str, score: f32) -> SearchHit {
        SearchHit {
            id: StableId::native(IdKind::Message, tag),
            score,
            session_id: None,
            text: None,
            why_matched: Vec::new(),
            suggested_next_commands: Vec::new(),
            occurrences: 1,
            resume_available: false,
        }
    }

    // ---- 半衰期：30 天衰减到 0.5（AgentRecall 同款），地板约 52 天处接管 ----

    #[test]
    fn recency_decay_is_one_at_zero_age_and_halves_every_thirty_days() {
        assert_eq!(recency_decay(0), 1.0);
        assert!((recency_decay(30 * DAY_MS) - 0.5).abs() < 1e-9);
        // 60/90 天无地板时本应为 0.25/0.125——RECENCY_DECAY_FLOOR=0.3 在
        // ~52 天处接管，半衰期只作用到地板为止（老消息保留 0.3 下限）。
        assert!((recency_decay(60 * DAY_MS) - 0.3).abs() < 1e-9);
        assert!((recency_decay(90 * DAY_MS) - 0.3).abs() < 1e-9);
    }

    // ---- clamp：未来时间戳按 0 龄处理（不因时钟偏差反向加分）----

    #[test]
    fn recency_decay_clamps_future_timestamps_to_full_score() {
        assert_eq!(recency_decay(-1), 1.0);
        assert_eq!(recency_decay(-365 * DAY_MS), 1.0);
        assert_eq!(recency_decay(i64::MIN), 1.0);
    }

    // ---- 衰减下限：老消息保留 RECENCY_DECAY_FLOOR 比例 ----

    #[test]
    fn recency_decay_never_drops_below_floor() {
        assert!((recency_decay(200 * DAY_MS) - RECENCY_DECAY_FLOOR).abs() < 1e-9);
        assert_eq!(recency_decay(i64::MAX / 2), RECENCY_DECAY_FLOOR);
        // 衰减单调不升：更老的消息绝不比更年轻的衰减更浅。
        assert!(recency_decay(31 * DAY_MS) < recency_decay(30 * DAY_MS));
        assert!(recency_decay(29 * DAY_MS) > recency_decay(30 * DAY_MS));
    }

    // ---- sidechain 固定分惩罚 ----

    #[test]
    fn final_score_applies_decay_then_fixed_sidechain_penalty() {
        let top = 1.0 / 61.0;
        assert!((final_score(top, 30 * DAY_MS, false, false) - top * 0.5).abs() < 1e-8);
        assert!((final_score(top, 30 * DAY_MS, true, false) - top * 0.25).abs() < 1e-8);
        assert_eq!(final_score(top * 0.1, 0, true, false), 0.0);
        assert!(final_score(top, 0, true, false) > final_score(1.0 / 572.0, 0, false, false));
    }

    #[test]
    fn final_score_adds_current_repo_boost_only_when_the_repo_matches() {
        let top = 1.0 / 61.0;
        assert_eq!(CURRENT_REPO_SCORE_BOOST, 0.5 / 61.0);
        let plain = final_score(top, 0, false, false);
        let boosted = final_score(top, 0, false, true);
        assert!((boosted - plain - CURRENT_REPO_SCORE_BOOST).abs() < 1e-8);
        assert_eq!(plain.to_bits(), top.to_bits());
        assert!(final_score(top, 0, false, true) > final_score(top, 0, false, false));
        // A weak current-repository hit cannot displace a strong external hit.
        assert!(final_score(1.0 / 572.0, 0, false, true) < final_score(top, 0, false, false));
        assert!((final_score(top, 0, true, true) - top * 1.25).abs() < 1e-8);
    }

    // ---- 证据门（B4）：零证据候选不得仅凭 repo/recency 偏好得正分 ----

    #[test]
    fn final_score_zero_evidence_never_gains_boost() {
        // 零/负/NaN relevance：无论多新（0 龄）、是否属于当前仓库，都不得因
        // 偏好信号复活为正分（D3 边界 1；当前不可达，防未来候选源爆雷）。
        for relevance in [0.0, -0.0, -1.0, f32::NAN, f32::NEG_INFINITY] {
            for in_repo in [false, true] {
                for age_ms in [0, i64::MAX / 2] {
                    assert_eq!(
                        final_score(relevance, age_ms, false, in_repo),
                        0.0,
                        "zero/negative/NaN relevance {relevance} must stay 0 (repo={in_repo})"
                    );
                }
            }
        }
        // 纯偏好差在零证据上没有排序能力：repo/新 与 非 repo/老 同为 0.0。
        assert_eq!(
            final_score(0.0, 0, false, true),
            final_score(0.0, i64::MAX / 2, false, false)
        );
        // 已准入的正证据仍按原信号放大（防御不改变既有排序语义）。
        assert!(final_score(0.5, 0, false, true) > final_score(0.5, 0, false, false));
    }

    // ---- 单一函数确定性：同输入同输出 ----

    #[test]
    fn final_score_is_deterministic() {
        for _ in 0..3 {
            for in_repo in [false, true] {
                assert_eq!(
                    final_score(1.5, 45 * DAY_MS, false, in_repo),
                    final_score(1.5, 45 * DAY_MS, false, in_repo)
                );
                assert_eq!(
                    final_score(1.5, 45 * DAY_MS, true, in_repo),
                    final_score(1.5, 45 * DAY_MS, true, in_repo)
                );
            }
        }
    }

    // ---- apply：payload 事实派生 + 重排 ----

    fn payload(timestamp: Option<&str>, is_sidechain: Option<bool>) -> Vec<u8> {
        let mut map = serde_json::Map::new();
        if let Some(ts) = timestamp {
            map.insert("timestamp".into(), serde_json::json!(ts));
        }
        if let Some(side) = is_sidechain {
            map.insert("is_sidechain".into(), serde_json::json!(side));
        }
        serde_json::Value::Object(map).to_string().into_bytes()
    }

    /// 固定时钟 2026-08-25T00:00:00Z 下应用信号；无当前仓库身份（调用方
    /// 没有 cwd 语义或不在 git 工作树内）的默认路径：全部 hit 不加分。
    fn apply(pairs: Vec<(SearchHit, Option<Vec<u8>>)>) -> Vec<SearchHit> {
        apply_scored(
            pairs
                .into_iter()
                .map(|(hit, payload)| (hit, payload, false))
                .collect(),
        )
    }

    /// 同上，但逐 hit 指定"是否属于当前仓库"。
    fn apply_scored(scored: Vec<(SearchHit, Option<Vec<u8>>, bool)>) -> Vec<SearchHit> {
        let now_ms = 1_787_616_000_000;
        apply_lexical_signals(scored, now_ms)
    }

    #[test]
    fn apply_lexical_signals_decays_older_hit_below_newer() {
        let pairs = vec![
            (
                hit("old", 1.0),
                Some(payload(Some("2026-01-01T00:00:00Z"), None)),
            ),
            (
                hit("new", 1.0),
                Some(payload(Some("2026-08-24T00:00:00Z"), None)),
            ),
        ];
        let hits = apply(pairs);
        assert_eq!(hits[0].id.as_str(), "msg_v1_new", "newer must rank first");
        assert_eq!(hits[1].id.as_str(), "msg_v1_old");
        // 1 天龄衰减接近 1.0，高于老命中的地板值。
        assert!(hits[0].score > hits[1].score);
    }

    #[test]
    fn apply_lexical_signals_demotes_sidechain_under_equal_relevance() {
        let pairs = vec![
            (hit("main", 2.0), Some(payload(None, Some(false)))),
            (hit("side", 2.0), Some(payload(None, Some(true)))),
        ];
        let hits = apply(pairs);
        assert_eq!(
            hits[0].id.as_str(),
            "msg_v1_main",
            "sidechain must rank later"
        );
        assert_eq!(hits[1].id.as_str(), "msg_v1_side");
        assert_eq!(hits[0].score, 2.0);
        assert_eq!(hits[1].score, 2.0 - SIDECHAIN_SCORE_PENALTY);
    }

    #[test]
    fn apply_lexical_signals_treats_missing_facts_as_no_signal() {
        // 无 timestamp / is_sidechain null / 非法 timestamp：衰减恒 1.0、
        // 无 sidechain 惩罚——无信号不加罚，顺序保持 relevance 序。
        let pairs = vec![
            (hit("b", 2.0), Some(payload(None, Some(false)))),
            (
                hit("a", 1.0),
                Some(
                    serde_json::json!({ "timestamp": null, "is_sidechain": null })
                        .to_string()
                        .into_bytes(),
                ),
            ),
        ];
        let hits = apply(pairs);
        assert_eq!(hits[0].id.as_str(), "msg_v1_b");
        assert_eq!(hits[0].score, 2.0);
        assert_eq!(hits[1].score, 1.0);
    }

    #[test]
    fn apply_lexical_signals_ties_break_by_wire_id_ascending() {
        // 全零分（惩罚后钳 0）：tiebreak 落到 id 升序，跨运行稳定。
        let pairs = vec![
            (hit("zeta", 0.5), Some(payload(None, Some(true)))),
            (hit("alpha", 0.5), Some(payload(None, Some(true)))),
            (hit("middle", 0.5), Some(payload(None, Some(true)))),
        ];
        let hits = apply(pairs);
        let order: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(order, vec!["msg_v1_alpha", "msg_v1_middle", "msg_v1_zeta"]);
    }

    #[test]
    fn apply_lexical_signals_zero_scores_are_normalized_positive() {
        // `-0.0`/NaN relevance 归一为 +0.0（负零符号在平台上未定义，排序必须逐位稳定）。
        let pairs = vec![(hit("neg", -0.0), None), (hit("zero", 0.0), None)];
        let hits = apply(pairs);
        assert_eq!(hits[0].score.to_bits(), 0.0f32.to_bits());
        assert_eq!(hits[1].score.to_bits(), 0.0f32.to_bits());
    }

    #[test]
    fn apply_lexical_signals_promotes_current_repo_hit_under_equal_relevance() {
        // 同 relevance 同龄：属于当前仓库的命中排前，且分差恰为加分常量。
        let scored = vec![
            (hit("other", 2.0), Some(payload(None, Some(false))), false),
            (hit("current", 2.0), Some(payload(None, Some(false))), true),
        ];
        let hits = apply_scored(scored);
        assert_eq!(hits[0].id.as_str(), "msg_v1_current");
        assert_eq!(hits[1].id.as_str(), "msg_v1_other");
        assert!((hits[0].score - hits[1].score - CURRENT_REPO_SCORE_BOOST).abs() < 1e-6);
    }

    #[test]
    fn apply_lexical_signals_without_repo_signal_is_byte_identical() {
        // "无信号不动分"：全 false（MCP/Web 等无 cwd 语义的入口，或不在 git
        // 工作树内）时逐位等于只有时效/sidechain 两个信号的旧结果。
        let make = || {
            vec![
                (
                    hit("a", 3.0),
                    Some(payload(Some("2026-08-24T00:00:00Z"), Some(false))),
                ),
                (
                    hit("b", 3.0),
                    Some(payload(Some("2026-01-01T00:00:00Z"), Some(true))),
                ),
            ]
        };
        let baseline: Vec<(String, u32)> = make()
            .into_iter()
            .map(|(hit, payload)| {
                let age = payload_timestamp_ms(payload.as_deref())
                    .map_or(0, |ms| 1_787_616_000_000_i64.saturating_sub(ms));
                (
                    hit.id.as_str().to_string(),
                    final_score(
                        hit.score,
                        age,
                        payload_is_sidechain(payload.as_deref()),
                        false,
                    )
                    .to_bits(),
                )
            })
            .collect();
        let applied: Vec<(String, u32)> = apply(make())
            .into_iter()
            .map(|hit| (hit.id.as_str().to_string(), hit.score.to_bits()))
            .collect();
        for (id, bits) in &baseline {
            let found = applied
                .iter()
                .find(|(applied_id, _)| applied_id == id)
                .expect("hit kept");
            assert_eq!(found.1, *bits, "{id} 的分值必须逐位不变");
        }
    }

    #[test]
    fn apply_lexical_signals_repo_boost_ties_break_by_wire_id_ascending() {
        // 全部属于当前仓库、同 relevance：加分一致 → tiebreak 仍落到 id 升序，
        // 跨运行逐字节稳定（分页不会因偏好而抖动）。
        let scored = vec![
            (hit("zeta", 1.0), Some(payload(None, None)), true),
            (hit("alpha", 1.0), Some(payload(None, None)), true),
            (hit("middle", 1.0), Some(payload(None, None)), true),
        ];
        let hits = apply_scored(scored);
        let order: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(order, vec!["msg_v1_alpha", "msg_v1_middle", "msg_v1_zeta"]);
        for hit in &hits {
            assert!((hit.score - (1.0 + CURRENT_REPO_SCORE_BOOST)).abs() < 1e-6);
        }
    }
}
