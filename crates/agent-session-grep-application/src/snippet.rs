//! Match-centered snippet windows for `SearchHit.text`.
//!
//! When the canonical payload `text` contains provable literal evidence, the
//! display summary is a contiguous window of the original text centered on the
//! earliest hit; without literal evidence it falls back to the existing
//! character prefix. The window is bounded by `max_snippet_chars` only —
//! serialized bytes stay charged through the caller's response byte gate
//! ([`crate::search_hit_charge`]); this module performs no local byte cut.
//!
//! The algorithm follows a synthetic Wake reuse study experiment
//! as an independent implementation. Deliberate product differences: a
//! trailing `*` stays part of the literal term (same as `why_matched`, no
//! prefix-operator parsing), there is no local byte gate, and an anchor that
//! exceeds the cap emits its own leading slice instead of an empty window.
//!
//! Documented prototype limits carry over: the whole text is materialized as
//! scalar and lowercase-expansion arrays, a single earliest-hit window can miss
//! a more useful later hit, and scalar safety is not grapheme safety.

/// Build the display summary for `text`:
///
/// - No canonical text -> `None`.
/// - Literal evidence: an exact contiguous slice of `text`, grown from the
///   earliest hit (smallest start, ties by term order) with a 2-right : 1-left
///   alternating schedule until `max_chars` or the text boundary. An anchor
///   longer than `max_chars` yields its first `max_chars` characters.
/// - No evidence: the first `max_chars` characters (the existing prefix).
///
/// Matching is case-insensitive via a per-character lowercase expansion mapped
/// back to original scalar boundaries (e.g. `İ` expands to `i` + U+0307 and
/// still maps to the whole original scalar). Output never inserts ellipses,
/// highlights or any synthetic characters, and is not grapheme-cluster safe.
pub fn build(text: Option<&str>, terms: &[String], max_chars: usize) -> Option<String> {
    let text = text?;
    let chars: Vec<char> = text.chars().collect();
    Some(match anchor(&chars, terms) {
        Some((start, end)) => window(&chars, start, end, max_chars),
        None => prefix(&chars, max_chars),
    })
}

/// First `max_chars` characters (the pre-snippet-window fallback semantics).
fn prefix(chars: &[char], max_chars: usize) -> String {
    chars[..chars.len().min(max_chars)].iter().collect()
}

/// Grow a contiguous window from the anchor: two characters right, one left,
/// repeating until `max_chars` or the text boundary (whichever comes first).
fn window(chars: &[char], start: usize, end: usize, max_chars: usize) -> String {
    if end - start >= max_chars {
        // The anchor alone reaches the cap: emit its leading slice. No
        // synthetic substitute and no partial-anchor re-anchoring.
        return chars[start..start + max_chars].iter().collect();
    }
    let mut start = start;
    let mut end = end;
    loop {
        let mut grew = false;
        for _ in 0..2 {
            if end < chars.len() && end - start < max_chars {
                end += 1;
                grew = true;
            }
        }
        if start > 0 && end - start < max_chars {
            start -= 1;
            grew = true;
        }
        if !grew {
            break;
        }
    }
    chars[start..end].iter().collect()
}

/// Earliest literal hit over the original characters: smallest start, ties by
/// term order. Lowercase expansion offsets are mapped back to original scalar
/// boundaries — never sliced directly against the expanded string.
fn anchor(chars: &[char], terms: &[String]) -> Option<(usize, usize)> {
    let mut lower = Vec::new();
    let mut origins = Vec::new();
    for (index, ch) in chars.iter().enumerate() {
        for folded in ch.to_lowercase() {
            lower.push(folded);
            origins.push(index);
        }
    }
    let mut best: Option<(usize, usize, usize)> = None;
    for (term_index, term) in terms.iter().enumerate() {
        let needle: Vec<char> = term.chars().flat_map(char::to_lowercase).collect();
        if needle.is_empty() || needle.len() > lower.len() {
            continue;
        }
        let Some(offset) = lower
            .windows(needle.len())
            .position(|candidate| candidate == needle.as_slice())
        else {
            continue;
        };
        // A match beginning/ending inside a multi-scalar expansion still maps
        // to the whole original scalar (over-approximation, never overrun).
        let start = origins[offset];
        let end = origins[offset + needle.len() - 1] + 1;
        let found = (start, term_index, end);
        if best.is_none_or(|current| found < current) {
            best = Some(found);
        }
    }
    best.map(|(start, _, end)| (start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(list: &[&str]) -> Vec<String> {
        list.iter().map(|term| (*term).to_string()).collect()
    }

    /// `build` for payloads that do carry canonical text.
    fn snippet(text: &str, list: &[&str], max_chars: usize) -> String {
        build(Some(text), &terms(list), max_chars).expect("text is Some")
    }

    #[test]
    fn short_text_is_emitted_whole() {
        // 实验 A ascii_head：短正文即使命中在中间也整体输出。
        assert_eq!(
            snippet("hello needle world", &["needle"], 40),
            "hello needle world"
        );
    }

    #[test]
    fn long_tail_window_keeps_the_hit_visible() {
        // 实验 A long_tail：命中在 201 字符之后，上限 40 → 窗口必须包含命中，
        // 且左右扩展按 2 右 : 1 左 结算（10 左 + 命中 + 22 右）。
        let text = format!("{} needle {}", "a".repeat(200), "z".repeat(100));
        let out = snippet(&text, &["needle"], 40);
        assert_eq!(out, format!("{} needle {}", "a".repeat(10), "z".repeat(22)));
        assert!(out.contains("needle"));
        assert_eq!(out.chars().count(), 40);
    }

    #[test]
    fn earliest_hit_wins_regardless_of_query_order() {
        // 实验 A earliest_hit_not_query_order：锚点是正文最早命中，不是词元顺序。
        let text = format!("first {} last", "x".repeat(60));
        assert_eq!(
            snippet(&text, &["last", "first"], 20),
            format!("first {}", "x".repeat(14))
        );
    }

    #[test]
    fn absent_earlier_term_falls_through_to_later_match() {
        // 实验 A absent_first_term_present_second：第一个词元缺席不阻断证据。
        let text = format!("{} match!", "z".repeat(50));
        let out = snippet(&text, &["absent", "match"], 16);
        assert_eq!(out, format!("{} match!", "z".repeat(9)));
        assert!(text.contains(&out));
    }

    #[test]
    fn cjk_bigram_is_literal_evidence() {
        // 实验 A cjk_one_scalar：CJK 词元是真实子串证据，窗口按字符计。
        let text = format!("{}库{}", "前".repeat(30), "后".repeat(30));
        assert_eq!(
            snippet(&text, &["库"], 9),
            format!("{}库{}", "前".repeat(2), "后".repeat(6))
        );
    }

    #[test]
    fn emoji_and_combining_are_sliced_at_scalar_boundaries() {
        // 实验 A emoji_window / combining_sequence：只保证 Unicode 标量边界。
        let emoji = format!("{}🚀 launch {}", "🙂".repeat(20), "🙂".repeat(10));
        assert_eq!(snippet(&emoji, &["🚀"], 5), "🙂🚀 la");
        let combining = format!("{} e\u{301} {}", "x".repeat(10), "y".repeat(10));
        assert_eq!(snippet(&combining, &["e\u{301}"], 5), " e\u{301} y");
    }

    #[test]
    fn lowercase_expansion_maps_back_to_original_scalar_boundaries() {
        // 实验 A partial_expansion_maps_whole_source_scalar：命中小写展开的一部分
        // （İ -> i + U+0307）仍切片整个原字符，绝不按展开串偏移切原文。
        assert_eq!(snippet("İ", &["i"], 1), "İ");
        // 实验 A expansion_inside_hit：命中起点落在展开中段时回映到原字符边界；
        // 上限被锚点占满，不再扩展。
        assert_eq!(snippet("ab İSTANBUL cd", &["i\u{307}stan"], 5), "İSTAN");
        // 实验 A expansions_before_hit：前缀回退同样按原字符切（不切碎 İ）。
        assert_eq!(snippet("İİ ΩK target!", &[], 7), "İİ ΩK t");
        assert_eq!(snippet("İİ ΩK target!", &["target"], 7), "target!");
    }

    #[test]
    fn anchor_longer_than_cap_emits_its_leading_slice() {
        // 原型允许的超预算锚点空窗行为不进入产品：输出锚点起始的连续切片。
        assert_eq!(snippet("ab needle cd", &["needle"], 3), "nee");
        assert_eq!(snippet("needle", &["needle"], 6), "needle");
    }

    #[test]
    fn no_evidence_falls_back_to_prefix() {
        // 语义-only / 无匹配 / 空词元 / 空文本都不伪造命中：回退既有前缀语义。
        let text = format!("{} needle {}", "a".repeat(30), "z".repeat(30));
        let prefix = snippet(&text, &["absent"], 8);
        assert_eq!(prefix, "aaaaaaaa");
        assert_eq!(snippet(&text, &[], 8), "aaaaaaaa");
        assert_eq!(snippet("", &["needle"], 8), "");
        assert_eq!(snippet("", &[], 0), "");
        assert_eq!(build(None, &terms(&["needle"]), 8), None);
        // 大小写不敏感匹配之外的语义不做承诺：不做 Unicode 规范化，
        // 不做完整 case folding（实验 A 的负例边界）。
        assert_eq!(snippet("café", &["cafe\u{301}"], 8), "café");
        assert_eq!(snippet("Straße", &["STRASSE"], 8), "Straße");
        assert_eq!(snippet("ΟΣ", &["ος"], 8), "ΟΣ");
    }

    #[test]
    fn window_is_an_exact_contiguous_slice() {
        // 输出永远是原文连续切片：不插入省略号/高亮等合成字符。
        for (text, term, max) in [
            (
                format!("{} needle {}", "a".repeat(200), "z".repeat(100)),
                "needle",
                40,
            ),
            (format!("{}库{}", "前".repeat(30), "后".repeat(30)), "库", 9),
            (format!("{} match!", "z".repeat(50)), "match", 16),
            ("İİ ΩK target!".to_string(), "target", 7),
        ] {
            let out = snippet(&text, &[term], max);
            assert!(text.contains(&out), "{out:?} not a slice of {text:?}");
            assert!(out.chars().count() <= max);
        }
    }

    #[test]
    fn zero_cap_is_empty_not_a_panic() {
        // 预算下限是 1，但构建器本身对 0 保持安全（与旧 `take(0)` 一致）。
        assert_eq!(snippet("needle", &["needle"], 0), "");
        assert_eq!(snippet("", &[], 0), "");
    }
}
