//! CJK n-gram 预处理（ADR-0007）。
//!
//! FTS5 默认 unicode61 分词把整段连续汉字当一个词元，`search 配置`/`search 数据库`
//! 这类双字核心查询对纯汉字句子大面积 miss。本模块在索引写入与查询两侧应用同一
//! transform：每段连续汉字切分为单字（unigram）+ 相邻两字（bigram）、以单个空格
//! 连接，作为 FTS 词元（[`fts_tokens_cjk`]，见下）。
//!
//! 词元增长：一段 N 字连续汉字的词元数从 1 变为 2N-1（纯 CJK 文本约 4x 最坏增长），
//! 索引体积相应膨胀，可接受（ADR-0007 §后果）。
//!
//! [`bigram_cjk`] 保持纯 bigram 输出（不产出单字词元），供 guidance 的证据词
//! 提取使用——单字证据太弱，不进 why_matched。

/// 汉字（Unicode Han）分类：CJK 统一表意文字主区 + 扩展 A + 兼容区 + 扩展 B-F。
pub(crate) fn is_han(c: char) -> bool {
    matches!(
        c as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x2FA1F
    )
}

/// 运行级分词骨架：把每个空白分词内的字符分组为 汉字/非汉字 交替运行，
/// 汉字运行交给 `han_run_tokens` 产出词元，非汉字运行原样保留为一个词元；
/// 同一空白分词内的词元以单个空格连接（索引与查询两侧共用同一变换，顺序敏感）。
///
/// 输入不含任何汉字时整体原样返回（纯 ASCII/路径/标点行为逐字节不变，
/// ADR-0003 兼容性承诺）。
fn tokenize_han_runs(s: &str, han_run_tokens: fn(&[char]) -> Vec<String>) -> String {
    if !s.chars().any(is_han) {
        return s.to_string();
    }
    let mut tokens: Vec<String> = Vec::new();
    for word in s.split_whitespace() {
        let mut runs: Vec<(bool, Vec<char>)> = Vec::new();
        for c in word.chars() {
            let han = is_han(c);
            match runs.last_mut() {
                Some((same, run)) if *same == han => run.push(c),
                _ => runs.push((han, vec![c])),
            }
        }
        let mut parts: Vec<String> = Vec::new();
        for (han, run) in runs {
            if han {
                parts.extend(han_run_tokens(&run));
            } else {
                parts.push(run.into_iter().collect());
            }
        }
        if !parts.is_empty() {
            tokens.push(parts.join(" "));
        }
    }
    tokens.join(" ")
}

/// 汉字运行只产出相邻两字 bigram（单字运行不产出任何词元）。
fn han_bigrams(run: &[char]) -> Vec<String> {
    run.windows(2)
        .map(|pair| format!("{}{}", pair[0], pair[1]))
        .collect()
}

/// 汉字运行同时产出单字与相邻两字 bigram（单字在前，与 spike analyzer 一致）。
fn han_unigrams_and_bigrams(run: &[char]) -> Vec<String> {
    let mut tokens: Vec<String> = run.iter().map(|c| c.to_string()).collect();
    tokens.extend(run.windows(2).map(|pair| format!("{}{}", pair[0], pair[1])));
    tokens
}

/// 把连续汉字运行切分为相邻两字 bigram，以单个空格连接；非 CJK 文本原样保留。
///
/// 规则：
/// - 一段 N 字连续汉字产生 N-1 个 bigram（"配置备份" → "配置 置备 备份"）；
///   单字运行（N=1）不产出任何词元；
/// - 非汉字运行（ASCII / 路径 / 标点 / 空白）原样保留，与相邻运行以单个空格分隔，
///   避免跨类型拼接成一个无法拆分的 FTS 词元（"设置X" → "设置 X"）；
/// - 输入不含任何汉字时整体原样返回（纯 ASCII/路径/标点行为逐字节不变，
///   ADR-0003 兼容性承诺）。
///
/// FTS 索引/查询词元流请用 [`fts_tokens_cjk`]（额外带单字词元）；本函数
/// 保持纯 bigram，供 guidance 的证据词提取（单字证据太弱，不进 why_matched）。
pub fn bigram_cjk(s: &str) -> String {
    tokenize_han_runs(s, han_bigrams)
}

/// FTS 索引与查询两侧的 CJK 词元串：每段连续汉字切分为单字 + 相邻两字 bigram，
/// 以单个空格连接（"配置备份" → "配 置 备 份 配置 置备 备份"）；非 CJK 文本
/// 原样保留，与 [`bigram_cjk`] 相同的运行分隔规则（"设置X" → "设 置 设置 X"）。
///
/// 相比纯 bigram 多出的单字词元让单字查询（如"了"）不再落空：bigram 覆盖
/// 双字及以上子串，unigram 覆盖单字（ADR-0007 §后果的"单字查询仍弱"边界
/// 由此消除）。索引与查询两侧必须使用同一 transform，先 transform 再字面量化，
/// 顺序敏感。
pub fn fts_tokens_cjk(s: &str) -> String {
    tokenize_han_runs(s, han_unigrams_and_bigrams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn han_runs_become_adjacent_char_bigrams() {
        assert_eq!(bigram_cjk("配置备份"), "配置 置备 备份");
        assert_eq!(bigram_cjk("数据库"), "数据 据库");
        assert_eq!(bigram_cjk("配置"), "配置");
        assert_eq!(bigram_cjk("配置了"), "配置 置了");
        // 长句：每个相邻两字都是可检索词元。
        assert_eq!(
            bigram_cjk("配置数据库迁移方案"),
            "配置 置数 数据 据库 库迁 迁移 移方 方案"
        );
    }

    #[test]
    fn non_cjk_text_passes_through_verbatim() {
        // 纯 ASCII/路径/标点输入逐字节不变（ADR-0003 兼容性承诺）。
        assert_eq!(bigram_cjk("mcp.json"), "mcp.json");
        assert_eq!(bigram_cjk("hello world"), "hello world");
        assert_eq!(bigram_cjk("hello  world"), "hello  world");
        assert_eq!(bigram_cjk(r"C:\Users\me\a.txt"), r"C:\Users\me\a.txt");
        assert_eq!(bigram_cjk("a:b x-y"), "a:b x-y");
        assert_eq!(bigram_cjk("..."), "...");
        assert_eq!(bigram_cjk("AND OR NOT"), "AND OR NOT");
    }

    #[test]
    fn mixed_ascii_cjk_runs_stay_separable() {
        // 汉字运行与相邻非汉字运行以单个空格分隔，避免拼成一个整词元。
        assert_eq!(bigram_cjk("用cargo测试"), "cargo 测试");
        assert_eq!(bigram_cjk("设置X"), "设置 X");
        assert_eq!(bigram_cjk("a配b"), "a b");
        assert_eq!(bigram_cjk("配置v2.0备份"), "配置 v2.0 备份");
    }

    #[test]
    fn empty_and_single_char_inputs() {
        assert_eq!(bigram_cjk(""), "");
        assert_eq!(bigram_cjk("   "), "   ");
        // 纯 bigram 输出：单字 CJK 运行不产出词元（单字词元见 fts_tokens_cjk）。
        assert_eq!(bigram_cjk("配"), "");
        assert_eq!(bigram_cjk("版本 v2.0 中"), "版本 v2.0");
    }

    #[test]
    fn punctuation_between_han_runs_is_preserved_and_separated() {
        assert_eq!(bigram_cjk("配置.备份"), "配置 . 备份");
        assert_eq!(bigram_cjk("配置，备份"), "配置 ， 备份");
        assert_eq!(bigram_cjk("配置：备份"), "配置 ： 备份");
    }

    #[test]
    fn already_bigrammed_text_is_stable() {
        // 幂等性：二次应用不再改变输出（索引/查询两侧各应用一次后收敛）。
        let once = bigram_cjk("配置备份");
        assert_eq!(bigram_cjk(&once), once);
    }

    // ─── fts_tokens_cjk（单字 + bigram 索引流）───

    #[test]
    fn fts_tokens_emit_unigrams_then_bigrams() {
        assert_eq!(fts_tokens_cjk("配置"), "配 置 配置");
        assert_eq!(fts_tokens_cjk("配置备份"), "配 置 备 份 配置 置备 备份");
        assert_eq!(fts_tokens_cjk("数据库"), "数 据 库 数据 据库");
        // 单字运行产出一个单字词元，不再落空。
        assert_eq!(fts_tokens_cjk("配"), "配");
        // 非汉字运行与 bigram_cjk 同规则原样保留、分隔。
        assert_eq!(fts_tokens_cjk("设置X"), "设 置 设置 X");
        assert_eq!(fts_tokens_cjk("a配b"), "a 配 b");
        assert_eq!(fts_tokens_cjk("版本 v2.0 中"), "版 本 版本 v2.0 中");
    }

    #[test]
    fn fts_tokens_pass_through_non_cjk_verbatim() {
        // 与 bigram_cjk 相同的 ADR-0003 承诺：不含汉字逐字节不变。
        assert_eq!(fts_tokens_cjk("mcp.json"), "mcp.json");
        assert_eq!(fts_tokens_cjk(""), "");
        assert_eq!(fts_tokens_cjk("   "), "   ");
        assert_eq!(fts_tokens_cjk("..."), "...");
    }
}
