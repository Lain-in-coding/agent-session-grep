//! Shared cross-boundary secret redaction (ADR-0009).
//!
//! High-confidence secret detection + redaction for plain strings. This is the
//! shared engine that both the CLI envelope redactor (`redact_value` JSON-tree
//! walker in the CLI crate) and the Handoff Pack builder delegate to, so a pack
//! always carries the same default-mode redaction as any other cross-boundary
//! output. Status projection (`RedactionMode`/`RedactionState`) stays in the
//! calling layer; this module only redacts text and reports span counts.

/// Ruleset version — bumped when detection patterns change.
pub const RULESET_VERSION: &str = "v1.0";

/// Detect and replace high-confidence secrets in a plain string.
///
/// Returns the redacted text and `1` when at least one secret span was
/// replaced, `0` otherwise. `redacted_count` is the number of redacted
/// entries, not the number of spans inside one entry (ADR-0009 field shape).
pub fn redact_text(s: &str) -> (String, u64) {
    match redact_string(s) {
        Some(redacted) => (redacted, 1),
        None => (s.to_string(), 0),
    }
}

/// Detect and replace high-confidence secrets in a plain string.
///
/// Returns `None` when nothing matched, so callers can distinguish "no secret"
/// from "redacted to an empty/placeholder value". Patterns are deliberately
/// conservative: only high-confidence, structured secret formats are matched to
/// avoid false positives that would erode trust. Matches both standalone
/// secrets (the whole string is a secret) and secrets embedded inside prose
/// ("the key is AKIA...") — cross-boundary output must not leak either form
/// (ADR-0009).
pub fn redact_string(s: &str) -> Option<String> {
    if s.is_empty() || s.len() < 8 {
        return None;
    }
    // Standalone (whole-string) match first: the value is exactly one secret.
    if let Some(marker) = standalone_secret(s) {
        return Some(marker.to_string());
    }
    // Embedded match: scan for each known secret shape inside the string and
    // replace matched spans with their redaction marker.
    let mut redacted = s.to_string();
    let mut count = 0u64;
    for shape in embedded_shapes() {
        replace_spans(&mut redacted, &mut count, |text| find_embedded(text, shape));
    }
    // The AWS secret key shape carries no prefix to anchor on, so it gets its
    // own boundary-anchored pass (the standalone rule only covers a value that
    // *is* the key; an embedded one must be redacted too).
    replace_spans(&mut redacted, &mut count, find_embedded_aws_secret);
    if count == 0 { None } else { Some(redacted) }
}

/// Replace every span a finder reports, bounded to 16 spans per value.
///
/// The finder returns `(start, span_len, marker)` relative to the slice it was
/// given; scanning resumes after the inserted marker so a marker is never
/// re-scanned.
fn replace_spans(
    text: &mut String,
    count: &mut u64,
    finder: impl Fn(&str) -> Option<(usize, usize, &'static str)>,
) {
    let mut search_from = 0usize;
    while let Some((start, span_len, marker)) = finder(&text[search_from..]) {
        let abs_start = search_from + start;
        text.replace_range(abs_start..abs_start + span_len, marker);
        search_from = abs_start + marker.len();
        *count += 1;
        if *count >= 16 {
            break; // bounded: never rewrite more than 16 spans per value
        }
    }
}

/// Whole-string secret match: the value itself is a single secret token.
fn standalone_secret(s: &str) -> Option<&'static str> {
    // AWS access key: AKIA + 16 uppercase alphanumeric
    if s.starts_with("AKIA") && s.len() >= 20 && s[..20].chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Some("[redacted:aws_access_key]");
    }
    // AWS secret key: 40-char base64-ish (heuristic, only if it looks like a standalone token)
    if s.len() == 40
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Some("[redacted:aws_secret_key]");
    }
    // GitHub tokens: fine-grained PAT (github_pat_) plus the classic
    // ghp_/gho_/ghs_/ghu_/ghr_ family. Mirrors `embedded_shapes`.
    for &(prefix, min_len) in &[
        ("github_pat_", 20),
        ("ghp_", 40),
        ("gho_", 40),
        ("ghs_", 40),
        ("ghu_", 40),
        ("ghr_", 40),
    ] {
        if s.starts_with(prefix) && s.len() >= min_len {
            return Some("[redacted:github_token]");
        }
    }
    // Generic API key patterns: sk- (OpenAI), sk-ant- (Anthropic), xai- (xAI)
    for prefix in &["sk-ant-", "sk-", "xai-"] {
        if s.starts_with(prefix) && s.len() >= 20 {
            return Some("[redacted:api_key]");
        }
    }
    // Bearer token in a string value
    if s.starts_with("Bearer ") && s.len() > 10 {
        return Some("[redacted:bearer_token]");
    }
    // Private key header (PEM)
    if s.contains("-----BEGIN ") && s.contains("PRIVATE KEY-----") {
        return Some("[redacted:private_key]");
    }
    None
}

/// Embedded secret shape: (prefix, minimum total length, redaction marker).
type SecretShape = (&'static str, usize, &'static str);

/// The known secret shapes, longest prefix first so more specific shapes
/// (sk-ant- before sk-) win the first-match.
fn embedded_shapes() -> Vec<SecretShape> {
    vec![
        // AWS access key: AKIA + 16 alphanumeric = 20 chars
        ("AKIA", 20, "[redacted:aws_access_key]"),
        // GitHub fine-grained PAT: github_pat_ + 9 = 20 chars minimum
        ("github_pat_", 20, "[redacted:github_token]"),
        // GitHub PAT: ghp_ + 36 = 40 chars
        ("ghp_", 40, "[redacted:github_token]"),
        ("gho_", 40, "[redacted:github_token]"),
        ("ghs_", 40, "[redacted:github_token]"),
        ("ghu_", 40, "[redacted:github_token]"),
        ("ghr_", 40, "[redacted:github_token]"),
        // Anthropic before generic sk-
        ("sk-ant-", 20, "[redacted:api_key]"),
        // OpenAI / xAI
        ("sk-", 20, "[redacted:api_key]"),
        ("xai-", 20, "[redacted:api_key]"),
        // Bearer tokens in prose
        ("Bearer ", 11, "[redacted:bearer_token]"),
    ]
}

/// Find one embedded secret span in `s` starting at the given offset.
///
/// Returns (start, end, marker) where end is the matched span length —
/// prefix + the trailing run of token characters (alphanumerics, '_', '-',
/// '+', '/', '='). The span is bounded to the shape's minimum length to
/// avoid over-consuming trailing prose.
fn find_embedded(s: &str, shape: SecretShape) -> Option<(usize, usize, &'static str)> {
    let (prefix, min_len, marker) = shape;
    let mut search = 0usize;
    while let Some(rel) = s[search..].find(prefix) {
        let start = search + rel;
        let after = start + prefix.len();
        // Require a non-alphanumeric boundary before the prefix (avoid
        // matching inside a longer identifier like "myAKIA...").
        let boundary_ok = start == 0
            || !s[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if boundary_ok {
            let mut end = after;
            for c in s[after..].chars() {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=') {
                    end += c.len_utf8();
                } else {
                    break;
                }
            }
            let span_len = end - start;
            if span_len >= min_len {
                return Some((start, span_len, marker));
            }
        }
        search = after;
    }
    None
}

/// Find one embedded AWS secret access key span in `s`.
///
/// An AWS secret key carries no prefix to anchor on — the shape is a 40-char
/// token from the base64 alphabet (`[A-Za-z0-9+/]`, never padded at that
/// length). The span is therefore anchored the other way round: a maximal run
/// of those characters, exactly 40 long, whose preceding character is a
/// boundary (not `_`/`-`, so a slice of a longer identifier never matches).
///
/// The run must additionally mix upper and lower case, which a random base64
/// secret always does and a 40-character hex digest (a git object id, quoted
/// constantly in real transcripts) never does.
fn find_embedded_aws_secret(s: &str) -> Option<(usize, usize, &'static str)> {
    const AWS_SECRET_LEN: usize = 40;
    let bytes = s.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if !is_base64_token_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_base64_token_byte(bytes[index]) {
            index += 1;
        }
        let span = &s[start..index];
        let boundary_ok = start == 0 || !matches!(bytes[start - 1], b'_' | b'-');
        if boundary_ok
            && span.len() == AWS_SECRET_LEN
            && span.bytes().any(|b| b.is_ascii_uppercase())
            && span.bytes().any(|b| b.is_ascii_lowercase())
        {
            return Some((start, AWS_SECRET_LEN, "[redacted:aws_secret_key]"));
        }
    }
    None
}

fn is_base64_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_aws_access_key() {
        let (redacted, count) = redact_text("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(redacted, "[redacted:aws_access_key]");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_openai_key() {
        let (redacted, count) = redact_text("sk-proj-abcdef1234567890");
        assert_eq!(redacted, "[redacted:api_key]");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_anthropic_key() {
        let (redacted, count) = redact_text("sk-ant-api03-1234567890abcdef");
        assert_eq!(redacted, "[redacted:api_key]");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_github_pat() {
        let (redacted, count) = redact_text("ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        assert_eq!(redacted, "[redacted:github_token]");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_bearer_token() {
        let (redacted, count) = redact_text("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert_eq!(redacted, "[redacted:bearer_token]");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_private_key() {
        let key =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let (redacted, count) = redact_text(key);
        assert_eq!(redacted, "[redacted:private_key]");
        assert_eq!(count, 1);
    }

    #[test]
    fn does_not_redact_normal_text() {
        let (redacted, count) = redact_text("hello world");
        assert_eq!(redacted, "hello world");
        assert_eq!(count, 0);
    }

    #[test]
    fn redacts_embedded_secret_in_prose() {
        let (redacted, count) = redact_text(
            "config with key AKIAIOSFODNN7EXAMPLE and token ghp_1234567890abcdefghijklmnopqrstuvwxyz trailing",
        );
        assert_eq!(
            redacted,
            "config with key [redacted:aws_access_key] and token [redacted:github_token] trailing"
        );
        assert_eq!(count, 1); // one entry, two spans
    }

    #[test]
    fn does_not_redact_embedded_like_prefixes() {
        assert_eq!(
            redact_text("myAKIAIOSFODNN7EXAMPLE-suffix").0,
            "myAKIAIOSFODNN7EXAMPLE-suffix"
        );
        assert_eq!(
            redact_text("token ghp_tooshort trailing").0,
            "token ghp_tooshort trailing"
        );
        assert_eq!(
            redact_text("plain sk- text with nothing after").0,
            "plain sk- text with nothing after"
        );
    }

    #[test]
    fn short_strings_not_redacted() {
        let (redacted, count) = redact_text("AKIA");
        assert_eq!(redacted, "AKIA");
        assert_eq!(count, 0);
    }
    #[test]
    fn redacts_github_fine_grained_pat() {
        let (redacted, count) = redact_text("github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz");
        assert_eq!(redacted, "[redacted:github_token]");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_embedded_github_fine_grained_pat_in_prose() {
        let (redacted, count) =
            redact_text("set GITHUB_TOKEN=github_pat_11ABCDEFG0abcdefghijrstuvwxyz before running");
        assert_eq!(
            redacted,
            "set GITHUB_TOKEN=[redacted:github_token] before running"
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_embedded_aws_secret_key_in_prose() {
        let (redacted, count) = redact_text(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY trailing",
        );
        assert_eq!(
            redacted,
            "aws_secret_access_key = [redacted:aws_secret_key] trailing"
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn does_not_redact_forty_char_hex_git_sha() {
        let (redacted, count) =
            redact_text("commit 1234567890abcdef1234567890abcdef12345678 landed");
        assert_eq!(
            redacted,
            "commit 1234567890abcdef1234567890abcdef12345678 landed"
        );
        assert_eq!(count, 0);
    }
}
