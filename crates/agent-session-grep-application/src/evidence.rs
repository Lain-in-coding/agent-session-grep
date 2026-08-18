//! EvidenceSpan DTO assembly from typed contextual relations.
//!
//! Application receives an exact [`MessagePlacement`] and [`SourceDocument`]
//! from the backend-independent context graph. Evidence assembly therefore
//! never parses compatibility aliases or invents document/span correspondence.

use agent_session_grep_domain::{Message, MessagePlacement, SourceDocument};
use serde::{Deserialize, Serialize};

/// Evidence location precision (`byte|line|record|unknown`).
///
/// v1 emits `Byte` when a placement has an exact byte span and `Unknown` when
/// the provider could not attribute one contiguous range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precision {
    Byte,
    Line,
    Record,
    Unknown,
}

/// Versioned evidence span returned by the shared Application ADT.
///
/// Byte ranges are half-open `[byte_start, byte_end)` offsets into the exact
/// verified source document named by `source_document_id`. Absolute paths are
/// never included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EvidenceSpanDto {
    /// Authoritative occurrence identity; always the placement ID.
    pub occurrence_id: String,
    /// Stable Message wire ID.
    pub message_id: String,
    /// Exact source document that owns this placement.
    pub source_document_id: Option<String>,
    /// Active generation used to assemble the response.
    pub generation: u64,
    /// Fingerprint of the exact verified source document.
    pub source_fingerprint: Option<String>,
    pub byte_start: Option<u64>,
    pub byte_end: Option<u64>,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    /// Source-local ordinal in the exact placement document.
    pub record_ordinal: Option<u32>,
    pub snippet_char_start: Option<u32>,
    pub snippet_char_end: Option<u32>,
    pub precision: Precision,
}

/// Assemble evidence from one selected placement and its exact stable entities.
pub fn assemble(
    message: &Message,
    placement: &MessagePlacement,
    document: &SourceDocument,
    generation: u64,
) -> EvidenceSpanDto {
    let (byte_start, byte_end, precision) = match &placement.span {
        Some(span) => (Some(span.start), Some(span.end), Precision::Byte),
        None => (None, None, Precision::Unknown),
    };
    EvidenceSpanDto {
        occurrence_id: placement.id.as_str().to_string(),
        message_id: message.id.as_str().to_string(),
        source_document_id: Some(document.id.as_str().to_string()),
        generation,
        source_fingerprint: Some(document.fingerprint.clone()),
        byte_start,
        byte_end,
        line_start: None,
        line_end: None,
        record_ordinal: Some(placement.source_ordinal),
        snippet_char_start: None,
        snippet_char_end: None,
        precision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::{
        EvidenceSpan, IdKind, MessagePlacement, Role, Stability, StableId,
    };

    fn message() -> Message {
        Message {
            id: StableId::native(IdKind::Message, "message-a"),
            role: Role::User,
            text: "hello".into(),
            timestamp: None,
        }
    }

    fn document() -> SourceDocument {
        SourceDocument {
            id: StableId::derive(IdKind::Document, Stability::Reconstructed, &[b"document-a"]),
            provider_id: "test-provider".into(),
            variant_id: "test-provider/v1".into(),
            fingerprint: "b3-deadbeef".into(),
            len: 123,
        }
    }

    fn placement(
        message: &Message,
        document: &SourceDocument,
        ordinal: u32,
        span: Option<(u64, u64)>,
    ) -> MessagePlacement {
        MessagePlacement::new(
            StableId::native(IdKind::Session, "session-a"),
            document.id.clone(),
            message.id.clone(),
            ordinal,
            false,
            span.map(|(start, end)| EvidenceSpan { start, end }),
        )
    }

    #[test]
    fn exact_placement_span_yields_byte_precision() {
        let message = message();
        let document = document();
        let placement = placement(&message, &document, 4, Some((10, 42)));
        let dto = assemble(&message, &placement, &document, 7);

        assert_eq!(dto.occurrence_id, placement.id.as_str());
        assert_eq!(dto.message_id, message.id.as_str());
        assert_eq!(
            dto.source_document_id.as_deref(),
            Some(document.id.as_str())
        );
        assert_eq!(
            dto.source_fingerprint.as_deref(),
            Some(document.fingerprint.as_str())
        );
        assert_eq!(dto.precision, Precision::Byte);
        assert_eq!(dto.byte_start, Some(10));
        assert_eq!(dto.byte_end, Some(42));
        assert_eq!(dto.record_ordinal, Some(4));
        assert_eq!(dto.generation, 7);
    }

    #[test]
    fn missing_placement_span_is_unknown_without_losing_document_identity() {
        let message = message();
        let document = document();
        let placement = placement(&message, &document, 0, None);
        let dto = assemble(&message, &placement, &document, 7);

        assert_eq!(dto.precision, Precision::Unknown);
        assert_eq!(dto.byte_start, None);
        assert_eq!(dto.byte_end, None);
        assert_eq!(
            dto.source_document_id.as_deref(),
            Some(document.id.as_str())
        );
        assert_eq!(dto.occurrence_id, placement.id.as_str());
    }

    #[test]
    fn occurrence_identity_is_the_placement_id() {
        let message = message();
        let document = document();
        let first = placement(&message, &document, 0, None);
        let repeated = placement(&message, &document, 1, None);

        let first_dto = assemble(&message, &first, &document, 7);
        let repeated_dto = assemble(&message, &repeated, &document, 7);
        assert_eq!(first_dto.occurrence_id, first.id.as_str());
        assert_eq!(repeated_dto.occurrence_id, repeated.id.as_str());
        assert_ne!(first_dto.occurrence_id, repeated_dto.occurrence_id);
        assert_eq!(first_dto.message_id, repeated_dto.message_id);
    }

    #[test]
    fn serializes_snake_case_wire_shape() {
        let message = message();
        let document = document();
        let placement = placement(&message, &document, 4, Some((3, 9)));
        let dto = assemble(&message, &placement, &document, 5);
        let wire = serde_json::to_value(&dto).unwrap();

        assert_eq!(wire["occurrence_id"], placement.id.as_str());
        assert_eq!(wire["precision"], "byte");
        assert_eq!(wire["byte_start"], 3);
        assert_eq!(wire["byte_end"], 9);
        assert_eq!(wire["message_id"], message.id.as_str());
        assert_eq!(wire["source_document_id"], document.id.as_str());
        assert_eq!(wire["source_fingerprint"], "b3-deadbeef");
        assert_eq!(wire["record_ordinal"], 4);
        assert_eq!(wire["generation"], 5);
        assert!(wire["line_start"].is_null());
        assert!(wire["snippet_char_start"].is_null());
    }
}
