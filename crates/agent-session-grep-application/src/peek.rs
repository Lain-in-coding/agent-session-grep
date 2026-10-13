//! Session peek bundle (#7): a small, deterministic, adapter-agnostic triage
//! preview attached to every `list_sessions` entry.
//!
//! Borrowed from hstry's Peek Bundle idea (1-2 KB gist instead of a full
//! `show`, designed for agents that triage many sessions cheaply). This crate's
//! minimal variant keeps only the first and last user message text; the message
//! count is already derivable from the session payload's `messages` array, and
//! bash samples / file touches stay out of scope until a caller asks for them.
//!
//! The preview is built from already-stored catalog data (session payload +
//! member message payloads). It never fails: unparsable inputs degrade to
//! all-null fields — a list must not fail because one entity's preview cannot
//! be derived.

use serde::Serialize;

/// Per-field character cap for peek text (hstry pins 240; this crate pins 200).
pub const PEEK_FIELD_MAX_CHARS: usize = 200;

/// Serialized peek byte budget per session (hard gate, test-guarded).
///
/// 200 chars are at most 800 UTF-8 bytes per field, so the byte pass only kicks
/// in for very wide characters (emoji) or heavy JSON escaping (quotes/control
/// bytes); ASCII text of 200 chars (404 serialized bytes per field) fits.
pub const PEEK_MAX_BYTES: usize = 1024;

/// JSON syntax overhead when a peek is attached to a list entry: the
/// `,"peek":` prefix (`,` + `"peek"` + `:`). The surrounding
/// `{"id":...,"payload":...}` skeleton is already charged as the fixed 18
/// bytes in the list byte-gate estimate.
pub const PEEK_ENTRY_OVERHEAD_BYTES: usize = 8;

/// Characters popped from the larger field per byte-budget iteration.
/// Convergence is fast (each step drops ~4x bytes for 4-byte chars) while the
/// loop stays obviously terminating: fields only shrink, and the empty peek
/// (42 bytes of JSON) always fits the budget.
const PEEK_TRIM_STEP_CHARS: usize = 32;

/// A minimal session triage preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionPeek {
    /// First user-role message text in member order, truncated to
    /// [`PEEK_FIELD_MAX_CHARS`]; `None` when the session has no user message
    /// with non-empty text.
    pub first_user_text: Option<String>,
    /// Last user-role message text in member order, truncated to
    /// [`PEEK_FIELD_MAX_CHARS`]; `None` when the session has no user message
    /// with non-empty text.
    pub last_user_text: Option<String>,
}

impl SessionPeek {
    /// Serialized JSON byte length (what the list byte-gate must charge).
    pub fn json_len(&self) -> usize {
        serde_json::to_vec(self)
            .expect("SessionPeek serialization cannot fail")
            .len()
    }
}

/// Build the peek from the session's member message payloads, aligned with the
/// session payload's `messages` array order.
///
/// A `None` payload (missing message) is skipped. Non-user roles, empty text,
/// and unparsable payloads are skipped; a sidechain user turn counts the same
/// as a mainline one (member order is the single source of truth).
///
/// Total: never fails. The returned peek always serializes to at most
/// [`PEEK_MAX_BYTES`] bytes and each field to at most
/// [`PEEK_FIELD_MAX_CHARS`] characters.
pub fn build_session_peek<'a>(
    message_payloads: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> SessionPeek {
    let mut first_user_text: Option<String> = None;
    let mut last_user_text: Option<String> = None;
    for payload in message_payloads {
        let Some(bytes) = payload else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            continue;
        };
        if value.get("role").and_then(serde_json::Value::as_str) != Some("user") {
            continue;
        }
        let Some(text) = value.get("text").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if first_user_text.is_none() {
            first_user_text = Some(text.to_string());
        }
        last_user_text = Some(text.to_string());
    }
    let mut peek = SessionPeek {
        first_user_text: first_user_text.map(|text| truncate_chars(&text, PEEK_FIELD_MAX_CHARS)),
        last_user_text: last_user_text.map(|text| truncate_chars(&text, PEEK_FIELD_MAX_CHARS)),
    };
    peek.fit_byte_budget();
    peek
}

impl SessionPeek {
    /// Shrink the larger field (last first on ties) until the serialized form
    /// fits [`PEEK_MAX_BYTES`]. Char-boundary safe and deterministically
    /// convergent: the tail is always the cheaper cut for triage.
    fn fit_byte_budget(&mut self) {
        while self.json_len() > PEEK_MAX_BYTES {
            let last_len = self.last_user_text.as_ref().map_or(0, String::len);
            let first_len = self.first_user_text.as_ref().map_or(0, String::len);
            if last_len >= first_len && last_len > 0 {
                pop_chars(
                    self.last_user_text.as_mut().expect("non-empty"),
                    PEEK_TRIM_STEP_CHARS,
                );
            } else if first_len > 0 {
                pop_chars(
                    self.first_user_text.as_mut().expect("non-empty"),
                    PEEK_TRIM_STEP_CHARS,
                );
            } else {
                // Both fields empty: `{"first_user_text":null,"last_user_text":null}`
                // (42 bytes) always fits — unreachable, kept total.
                break;
            }
        }
    }
}

/// Truncate to at most `max_chars` characters on a char boundary.
fn truncate_chars(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((index, _)) => text[..index].to_string(),
        None => text.to_string(),
    }
}

/// Drop up to `count` characters from the tail, on a char boundary.
fn pop_chars(text: &mut String, count: usize) {
    let cut = text
        .char_indices()
        .nth_back(count.saturating_sub(1))
        .map_or(0, |(index, _)| index);
    text.truncate(cut);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_payload(text: &str) -> Vec<u8> {
        serde_json::json!({ "role": "user", "text": text })
            .to_string()
            .into_bytes()
    }

    #[test]
    fn extracts_first_and_last_user_text_in_member_order() {
        let peek = build_session_peek([
            Some(user_payload("open the repo").as_slice()),
            Some(br#"{"role":"assistant","text":"ok"}"#.as_slice()),
            Some(br#"{"role":"tool","text":"output"}"#.as_slice()),
            Some(user_payload("now fix the bug").as_slice()),
        ]);
        assert_eq!(peek.first_user_text.as_deref(), Some("open the repo"));
        assert_eq!(peek.last_user_text.as_deref(), Some("now fix the bug"));
    }

    #[test]
    fn skips_user_messages_without_text_and_missing_payloads() {
        let peek = build_session_peek([
            Some(br#"{"role":"user"}"#.as_slice()),
            Some(br#"{"role":"user","text":"   "}"#.as_slice()),
            None,
            Some(br#"not json"#.as_slice()),
            Some(user_payload("the only real turn").as_slice()),
        ]);
        assert_eq!(peek.first_user_text.as_deref(), Some("the only real turn"));
        assert_eq!(peek.last_user_text.as_deref(), Some("the only real turn"));
    }

    #[test]
    fn no_user_turns_yields_null_fields_that_serialize_small() {
        let peek =
            build_session_peek([Some(br#"{"role":"assistant","text":"answer"}"#.as_slice())]);
        assert_eq!(peek.first_user_text, None);
        assert_eq!(peek.last_user_text, None);
        assert!(peek.json_len() <= PEEK_MAX_BYTES);
    }

    #[test]
    fn fields_are_char_truncated_at_the_cap() {
        // ASCII (1 byte/char) stays under the byte budget even at the char cap,
        // so this test isolates the char boundary logic.
        let long = "a".repeat(500);
        let peek = build_session_peek([Some(user_payload(&long).as_slice())]);
        let first = peek.first_user_text.expect("first user text");
        let last = peek.last_user_text.expect("last user text");
        assert_eq!(first.chars().count(), PEEK_FIELD_MAX_CHARS);
        assert_eq!(last.chars().count(), PEEK_FIELD_MAX_CHARS);
        assert!(long.starts_with(&first), "prefix kept, tail cut");
    }

    #[test]
    fn wide_chars_are_byte_trimmed_to_the_per_session_budget() {
        // 500 emoji (4 bytes each): char-truncated fields alone would serialize
        // to ~1.6 KiB — the byte pass must cut further to honor the 1 KiB gate.
        let long = "🦀".repeat(500);
        let peek = build_session_peek([Some(user_payload(&long).as_slice())]);
        let serialized = peek.json_len();
        assert!(
            serialized <= PEEK_MAX_BYTES,
            "serialized {serialized} bytes"
        );
        assert!(
            serialized > 900,
            "gate should cut close, not slash to nothing: {serialized}"
        );
    }

    #[test]
    fn heavy_json_escaping_stays_within_the_budget() {
        // Quotes (2x) and control bytes (6x) inflate on serialization; the loop
        // must converge on the serialized length, not the raw byte count.
        let nasty = "\u{0001}\"".repeat(300);
        let peek = build_session_peek([Some(user_payload(&nasty).as_slice())]);
        let serialized = peek.json_len();
        assert!(
            serialized <= PEEK_MAX_BYTES,
            "serialized {serialized} bytes"
        );
    }

    #[test]
    fn pop_chars_is_char_boundary_safe() {
        let mut text = "界a🦀b".to_string();
        pop_chars(&mut text, 2);
        assert_eq!(text, "界a");
        pop_chars(&mut text, 10);
        assert_eq!(text, "");
    }
}
