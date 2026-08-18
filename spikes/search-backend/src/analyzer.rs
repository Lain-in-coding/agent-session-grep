//! Backend-neutral analyzer（ADR-0001 的检索对照方法）。
//! FTS5 与 Tantivy 都索引这里产出的 token 串，隔离"引擎本身"的差异，
//! 避免把两边 tokenizer 质量差异误算成引擎差异。
//!
//! 规则：
//! - CJK（含中日韩统一表意文字）：2-gram bigram + 单字，覆盖无空格分词场景；
//! - Latin/数字：小写整词 token；
//! - 代码/路径分隔符（. :: / \ - _）：既保留整词，也切分出子 token。

/// 判断是否为需要 n-gram 的 CJK 表意/假名/谚文字符。
fn is_cjk(c: char) -> bool {
    matches!(c as u32,
        0x3400..=0x4DBF   // CJK 扩展 A
        | 0x4E00..=0x9FFF // CJK 统一表意
        | 0xF900..=0xFAFF // CJK 兼容表意
        | 0x3040..=0x309F // 平假名
        | 0x30A0..=0x30FF // 片假名
        | 0xAC00..=0xD7AF // 谚文音节
    )
}

fn is_token_char(c: char) -> bool {
    c.is_alphanumeric() && !is_cjk(c)
}

/// 把一段文本分析成 token 列表。用于索引与查询两侧，保证一致。
pub fn analyze(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut latin = String::new();

    let flush_latin = |latin: &mut String, out: &mut Vec<String>| {
        if latin.is_empty() {
            return;
        }
        // 整词（小写）
        out.push(latin.to_lowercase());
        // 代码/路径子 token：按分隔符切（小写）
        let parts: Vec<&str> = latin
            .split(|c: char| matches!(c, '.' | '/' | '\\' | '-' | '_' | ':'))
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() > 1 {
            for p in &parts {
                out.push(p.to_lowercase());
            }
        }
        // camelCase 切分
        let camel = split_camel(latin);
        if camel.len() > 1 {
            for p in camel {
                out.push(p);
            }
        }
        latin.clear();
    };

    let mut cjk_buf: Vec<char> = Vec::new();
    let flush_cjk = |buf: &mut Vec<char>, out: &mut Vec<String>| {
        if buf.is_empty() {
            return;
        }
        // 单字
        for &c in buf.iter() {
            out.push(c.to_string());
        }
        // 2-gram
        for w in buf.windows(2) {
            out.push(w.iter().collect());
        }
        buf.clear();
    };

    for c in text.chars() {
        if is_cjk(c) {
            flush_latin(&mut latin, &mut out);
            cjk_buf.push(c);
        } else if is_token_char(c) || matches!(c, '.' | '/' | '\\' | '-' | '_' | ':') {
            flush_cjk(&mut cjk_buf, &mut out);
            latin.push(c);
        } else {
            flush_latin(&mut latin, &mut out);
            flush_cjk(&mut cjk_buf, &mut out);
        }
    }
    flush_latin(&mut latin, &mut out);
    flush_cjk(&mut cjk_buf, &mut out);
    out
}

/// camelCase / PascalCase 切分：normalizeProjectPath -> [normalize, project, path]
fn split_camel(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_ascii_uppercase() && prev_lower {
            if !cur.is_empty() {
                parts.push(cur.to_lowercase());
                cur.clear();
            }
        }
        cur.push(c);
        prev_lower = c.is_ascii_lowercase();
    }
    if !cur.is_empty() {
        parts.push(cur.to_lowercase());
    }
    parts
}

/// 把 token 列表拼成空格分隔的可索引串。FTS5/Tantivy 都用它。
pub fn analyze_to_string(text: &str) -> String {
    analyze(text).join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cjk_bigram() {
        let t = analyze("索引重建");
        assert!(t.contains(&"索引".to_string()));
        assert!(t.contains(&"引重".to_string()));
        assert!(t.contains(&"重建".to_string()));
        assert!(t.contains(&"索".to_string()));
    }

    #[test]
    fn code_identifier_split() {
        let t = analyze("normalizeProjectPath");
        assert!(t.contains(&"normalizeprojectpath".to_string()));
        assert!(t.contains(&"normalize".to_string()));
        assert!(t.contains(&"project".to_string()));
        assert!(t.contains(&"path".to_string()));
    }

    #[test]
    fn path_split() {
        let t = analyze("src/db/search.rs");
        assert!(t.contains(&"search".to_string()));
        assert!(t.contains(&"db".to_string()));
        assert!(t.contains(&"rs".to_string()));
    }

    #[test]
    fn module_path() {
        let t = analyze("tantivy::schema::Field");
        assert!(t.contains(&"tantivy".to_string()));
        assert!(t.contains(&"schema".to_string()));
        assert!(t.contains(&"field".to_string()));
    }
}
