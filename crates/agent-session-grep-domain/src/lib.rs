//! agent-session-grep domain core: canonical data, stable identity, contextual
//! placement, and deterministic branch selection.
//!
//! This crate has no I/O, storage, or framework dependencies.

mod error;
mod ids;
mod thread;

pub use error::{DomainError, DomainResult};
pub use ids::{IdKind, PlacementId, SessionIdentityNamespace, Stability, StableId};
pub use thread::{BranchSelection, ContextPolicy, select_full, select_mainline};

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The canonical speaker role of a Message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    System,
    // Codex's authoritative system/permission-layer role; distinct from
    // `System` because providers emit it verbatim.
    Developer,
    Tool,
}

/// A byte range in one verified source-document snapshot; `end` is exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSpan {
    pub start: u64,
    pub end: u64,
}

/// A stable canonical Message identity and its intrinsic content.
///
/// Session membership, document occurrence, source-local order, sidechain
/// state, evidence, and parentage are contextual relations represented by
/// [`MessagePlacement`] and [`MessageEdge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub id: StableId,
    pub role: Role,
    /// Normalized plain text used by the canonical catalog and search index.
    pub text: String,
    /// Provider-reported timestamp preserved losslessly; absence stays explicit.
    #[serde(default)]
    pub timestamp: Option<String>,
}

impl Message {
    /// Validate invariants intrinsic to a stable Message.
    pub fn validate(&self) -> DomainResult<()> {
        if self.id.kind() != IdKind::Message {
            return Err(DomainError::InvariantViolation(format!(
                "message id has wrong kind: {:?}",
                self.id.kind()
            )));
        }
        if !self.id.validate() {
            return Err(DomainError::InvariantViolation(
                "message id value is inconsistent with its kind".into(),
            ));
        }
        Ok(())
    }
}

/// A stable canonical Session identity.
///
/// Documents and Messages are related through [`MessagePlacement`] rather than
/// embedded in this entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: StableId,
}

impl Session {
    /// Validate invariants intrinsic to a Session.
    pub fn validate(&self) -> DomainResult<()> {
        if self.id.kind() != IdKind::Session {
            return Err(DomainError::InvariantViolation(format!(
                "session id has wrong kind: {:?}",
                self.id.kind()
            )));
        }
        if !self.id.validate() {
            return Err(DomainError::InvariantViolation(
                "session id value is inconsistent with its kind".into(),
            ));
        }
        Ok(())
    }
}

/// A verified, content-addressed source-document snapshot.
///
/// The entity stores no source path. Path-to-document claims belong to the
/// persistence boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDocument {
    pub id: StableId,
    pub provider_id: String,
    pub variant_id: String,
    /// BLAKE3 fingerprint of the verified snapshot bytes.
    pub fingerprint: String,
    /// Snapshot byte length and upper bound for placement evidence spans.
    pub len: u64,
}

impl SourceDocument {
    /// Validate invariants intrinsic to a SourceDocument.
    pub fn validate(&self) -> DomainResult<()> {
        if self.id.kind() != IdKind::Document {
            return Err(DomainError::InvariantViolation(format!(
                "document id has wrong kind: {:?}",
                self.id.kind()
            )));
        }
        if !self.id.validate() {
            return Err(DomainError::InvariantViolation(
                "document id value is inconsistent with its kind".into(),
            ));
        }
        Ok(())
    }
}

/// One contextual occurrence of a stable Message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePlacement {
    pub id: PlacementId,
    pub session_id: StableId,
    pub source_document_id: StableId,
    pub message_id: StableId,
    /// Source-local ordinal within the exact document snapshot.
    pub source_ordinal: u32,
    pub is_sidechain: bool,
    /// Evidence range in `source_document_id`, when reported by the provider.
    #[serde(default)]
    pub span: Option<EvidenceSpan>,
}

impl MessagePlacement {
    /// Construct a placement with its deterministic path-independent identity.
    pub fn new(
        session_id: StableId,
        source_document_id: StableId,
        message_id: StableId,
        source_ordinal: u32,
        is_sidechain: bool,
        span: Option<EvidenceSpan>,
    ) -> Self {
        let id = PlacementId::derive(
            &session_id,
            &source_document_id,
            &message_id,
            source_ordinal,
        );
        Self {
            id,
            session_id,
            source_document_id,
            message_id,
            source_ordinal,
            is_sidechain,
            span,
        }
    }
}

/// The provider-supported semantic relationship between parent and child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRelation {
    Reply,
    Retry,
    Fork,
    Continuation,
    Subagent,
    ToolResult,
}

impl MessageRelation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::Retry => "retry",
            Self::Fork => "fork",
            Self::Continuation => "continuation",
            Self::Subagent => "subagent",
            Self::ToolResult => "tool_result",
        }
    }
}

/// A contextual parent edge for one child placement.
///
/// The parent is a stable Message identity. Selection resolves it to a
/// placement inside the requested session without inventing a global parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEdge {
    pub child_placement_id: PlacementId,
    pub parent_message_id: StableId,
    #[serde(default)]
    pub parent_native_id: Option<String>,
    pub relation: MessageRelation,
}

/// The retrieval facet kind of one tool activity (design R2).
///
/// Fail-closed: a tool name outside the known closed set infers `Unknown`,
/// never a guessed kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolActivityKind {
    /// File-system content tools (Read/Write/Edit/...).
    File,
    /// Shell/command execution tools (Bash/shell/exec).
    Command,
    /// Web retrieval tools (WebFetch/WebSearch).
    Web,
    /// Pattern/search tools (Glob/Grep) and Task-style queries.
    Query,
    /// Name outside the known set — never guessed.
    Unknown,
}

impl ToolActivityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Command => "command",
            Self::Web => "web",
            Self::Query => "query",
            Self::Unknown => "unknown",
        }
    }
}

/// Who performed the tool activity (design R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolActivityActor {
    Main,
    Subagent,
}

impl ToolActivityActor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Subagent => "subagent",
        }
    }
}

/// The provider-recorded outcome of one tool activity (design R4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolActivityStatus {
    Success,
    Error,
    /// The call was observed but no result record exists in the source
    /// (truncated transcript) — never guessed.
    Unknown,
}

impl ToolActivityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Unknown => "unknown",
        }
    }
}

/// One typed tool activity observation attached to a canonical Message.
///
/// Facts are provider-recorded first; extraction follows an explicit ordered
/// rule set (R1 target priority chain, R2 kind inference,
/// R3 actor, R4 status). Fail-closed: unknown → `kind = Unknown`,
/// `target = None` — never guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolActivity {
    pub kind: ToolActivityKind,
    pub actor: ToolActivityActor,
    /// Provider-reported tool name, verbatim (e.g. `Bash`, `Read`, `shell`).
    pub name: String,
    /// Extracted target (file path / command / url / pattern); `None` when
    /// unknown. Bounding happens at the persistence boundary.
    pub target: Option<String>,
    pub status: ToolActivityStatus,
}

impl ToolActivity {
    /// Validate invariants intrinsic to a ToolActivity.
    pub fn validate(&self) -> DomainResult<()> {
        if self.name.trim().is_empty() {
            return Err(DomainError::InvariantViolation(
                "tool activity name must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Where one usage observation came from.
///
/// `Observed` = the provider recorded a per-event token count (e.g. Claude
/// Code's `message.usage`). `Derived` = the value was deterministically
/// derived from accumulated provider totals (e.g. Codex `token_count`
/// cumulative counters, converted to per-event deltas under monotonicity
/// validation). Every stored number keeps this provenance — never erased.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSource {
    Observed,
    Derived,
}

impl TokenSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Derived => "derived",
        }
    }
}

/// One token-usage observation: five non-negative buckets.
///
/// Only numbers the provider format explicitly gives are recorded — never
/// estimated from text length or any other proxy. A stored row means the
/// provider reported usage for that message/session (agentsview-style
/// coverage marker: absence of rows means "unknown", not "zero"). Buckets a
/// provider format does not carry are stored as 0 (documented per adapter);
/// a provider-reported negative value fails the event closed (never clamped,
/// never invented).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageObservation {
    /// Non-cached prompt tokens (cache reads are split out, see below).
    pub input_tokens: u64,
    /// Completion tokens.
    pub output_tokens: u64,
    /// Tokens served from the provider cache (read side).
    pub cache_read_tokens: u64,
    /// Tokens written into the provider cache (creation side).
    pub cache_write_tokens: u64,
    /// Reasoning/thinking tokens, where the format records them separately.
    pub reasoning_tokens: u64,
    /// Provenance of the numbers (observed vs derived).
    pub token_source: TokenSource,
}

/// The complete typed graph needed to resolve one Session context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContextGraph {
    pub session_id: StableId,
    pub messages: Vec<Message>,
    pub source_documents: Vec<SourceDocument>,
    pub placements: Vec<MessagePlacement>,
    pub edges: Vec<MessageEdge>,
}

impl SessionContextGraph {
    /// Validate the graph without resolving contextual parent ambiguity.
    ///
    /// Orphan parent Message IDs are valid because a provider may reference a
    /// parent occurrence outside the visible context. Ambiguous in-session
    /// parent resolution is reported by [`select_mainline`].
    pub fn validate(&self) -> DomainResult<()> {
        if self.session_id.kind() != IdKind::Session {
            return Err(DomainError::InvariantViolation(format!(
                "context session id has wrong kind: {:?}",
                self.session_id.kind()
            )));
        }
        if !self.session_id.validate() {
            return Err(DomainError::InvariantViolation(
                "context session id value is inconsistent with its kind".into(),
            ));
        }

        let mut message_ids = HashSet::new();
        for (index, message) in self.messages.iter().enumerate() {
            message.validate()?;
            if !message_ids.insert(message.id.as_str()) {
                return Err(DomainError::InvariantViolation(format!(
                    "message[{index}] duplicates a prior message id"
                )));
            }
        }

        let mut documents = HashMap::new();
        for (index, document) in self.source_documents.iter().enumerate() {
            document.validate()?;
            if documents.insert(document.id.as_str(), document).is_some() {
                return Err(DomainError::InvariantViolation(format!(
                    "source_document[{index}] duplicates a prior document id"
                )));
            }
        }

        let mut placement_ids = HashSet::new();
        let mut placement_coordinates = HashSet::new();
        for (index, placement) in self.placements.iter().enumerate() {
            if placement.session_id.kind() != IdKind::Session {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] session id has wrong kind: {:?}",
                    placement.session_id.kind()
                )));
            }
            if !placement.session_id.validate() {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] session id value is inconsistent with its kind"
                )));
            }
            if placement.source_document_id.kind() != IdKind::Document {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] document id has wrong kind: {:?}",
                    placement.source_document_id.kind()
                )));
            }
            if !placement.source_document_id.validate() {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] document id value is inconsistent with its kind"
                )));
            }
            if placement.message_id.kind() != IdKind::Message {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] message id has wrong kind: {:?}",
                    placement.message_id.kind()
                )));
            }
            if !placement.message_id.validate() {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] message id value is inconsistent with its kind"
                )));
            }
            if placement.session_id.as_str() != self.session_id.as_str() {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] is outside the context session"
                )));
            }

            let expected_id = PlacementId::derive(
                &placement.session_id,
                &placement.source_document_id,
                &placement.message_id,
                placement.source_ordinal,
            );
            if placement.id != expected_id {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] id does not match its identity fields"
                )));
            }
            if !placement_ids.insert(placement.id.as_str()) {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] duplicates a prior placement id"
                )));
            }
            if !placement_coordinates.insert((
                placement.session_id.as_str(),
                placement.source_document_id.as_str(),
                placement.message_id.as_str(),
                placement.source_ordinal,
            )) {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] duplicates a placement coordinate"
                )));
            }
            if !message_ids.contains(placement.message_id.as_str()) {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] references a missing message"
                )));
            }

            let Some(document) = documents.get(placement.source_document_id.as_str()) else {
                return Err(DomainError::InvariantViolation(format!(
                    "placement[{index}] references a missing source document"
                )));
            };
            if let Some(span) = &placement.span {
                if span.start > span.end {
                    return Err(DomainError::InvariantViolation(format!(
                        "placement[{index}] span start exceeds end"
                    )));
                }
                if span.end > document.len {
                    return Err(DomainError::InvariantViolation(format!(
                        "placement[{index}] span exceeds source document length"
                    )));
                }
            }
        }

        let mut edge_children = HashSet::new();
        for (index, edge) in self.edges.iter().enumerate() {
            if edge.parent_message_id.kind() != IdKind::Message {
                return Err(DomainError::InvariantViolation(format!(
                    "edge[{index}] parent id has wrong kind: {:?}",
                    edge.parent_message_id.kind()
                )));
            }
            if !placement_ids.contains(edge.child_placement_id.as_str()) {
                return Err(DomainError::InvariantViolation(format!(
                    "edge[{index}] references a missing child placement"
                )));
            }
            if !edge_children.insert(edge.child_placement_id.as_str()) {
                return Err(DomainError::InvariantViolation(format!(
                    "edge[{index}] duplicates a child placement"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(kind: IdKind, tag: &str) -> StableId {
        StableId::derive(kind, Stability::Reconstructed, &[tag.as_bytes()])
    }

    fn message(tag: &str) -> Message {
        Message {
            id: id(IdKind::Message, tag),
            role: Role::User,
            text: tag.to_string(),
            timestamp: None,
        }
    }

    fn document(tag: &str, len: u64) -> SourceDocument {
        SourceDocument {
            id: id(IdKind::Document, tag),
            provider_id: "test-provider".into(),
            variant_id: "test-provider/v1".into(),
            fingerprint: format!("fingerprint-{tag}"),
            len,
        }
    }

    fn placement(
        session_id: &StableId,
        document_id: &StableId,
        message_id: &StableId,
        source_ordinal: u32,
    ) -> MessagePlacement {
        MessagePlacement::new(
            session_id.clone(),
            document_id.clone(),
            message_id.clone(),
            source_ordinal,
            false,
            None,
        )
    }

    fn graph() -> SessionContextGraph {
        let session_id = id(IdKind::Session, "session");
        let document = document("document", 128);
        let message = message("message");
        let placement = placement(&session_id, &document.id, &message.id, 0);
        SessionContextGraph {
            session_id,
            messages: vec![message],
            source_documents: vec![document],
            placements: vec![placement],
            edges: Vec::new(),
        }
    }

    #[test]
    fn stable_entities_validate_only_intrinsic_id_kinds() {
        assert!(
            Session {
                id: id(IdKind::Session, "session")
            }
            .validate()
            .is_ok()
        );
        assert!(message("message").validate().is_ok());
        assert!(document("document", 0).validate().is_ok());

        let invalid = Message {
            id: id(IdKind::Session, "not-a-message"),
            role: Role::User,
            text: String::new(),
            timestamp: None,
        };
        assert_eq!(
            invalid.validate().unwrap_err().code(),
            "invariant_violation"
        );
    }

    #[test]
    fn valid_graph_accepts_exact_span_bounds() {
        let mut graph = graph();
        graph.placements[0].span = Some(EvidenceSpan { start: 0, end: 128 });
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn graph_rejects_wrong_context_and_relation_id_kinds() {
        let mut wrong_context = graph();
        wrong_context.session_id = id(IdKind::Source, "wrong");
        assert_eq!(
            wrong_context.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut wrong_placement_session = graph();
        wrong_placement_session.placements[0].session_id = id(IdKind::Source, "wrong");
        assert_eq!(
            wrong_placement_session.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut wrong_document = graph();
        wrong_document.placements[0].source_document_id = id(IdKind::Source, "wrong");
        assert_eq!(
            wrong_document.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut wrong_message = graph();
        wrong_message.placements[0].message_id = id(IdKind::Session, "wrong");
        assert_eq!(
            wrong_message.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut wrong_parent = graph();
        wrong_parent.edges.push(MessageEdge {
            child_placement_id: wrong_parent.placements[0].id.clone(),
            parent_message_id: id(IdKind::Session, "wrong"),
            parent_native_id: None,
            relation: MessageRelation::Reply,
        });
        assert_eq!(
            wrong_parent.validate().unwrap_err().code(),
            "invariant_violation"
        );
    }

    #[test]
    fn graph_rejects_placement_outside_requested_session() {
        let mut graph = graph();
        let other_session = id(IdKind::Session, "other-session");
        graph.placements[0] = placement(
            &other_session,
            &graph.source_documents[0].id,
            &graph.messages[0].id,
            0,
        );
        assert_eq!(graph.validate().unwrap_err().code(), "invariant_violation");
    }

    #[test]
    fn graph_rejects_mismatched_derived_placement_id() {
        let mut graph = graph();
        graph.placements[0].id = PlacementId::derive(
            &graph.session_id,
            &graph.source_documents[0].id,
            &graph.messages[0].id,
            99,
        );
        assert_eq!(graph.validate().unwrap_err().code(), "invariant_violation");
    }

    #[test]
    fn graph_rejects_duplicate_messages_documents_placements_and_edges() {
        let mut duplicate_message = graph();
        duplicate_message
            .messages
            .push(duplicate_message.messages[0].clone());
        assert_eq!(
            duplicate_message.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut duplicate_document = graph();
        duplicate_document
            .source_documents
            .push(duplicate_document.source_documents[0].clone());
        assert_eq!(
            duplicate_document.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut duplicate_placement = graph();
        duplicate_placement
            .placements
            .push(duplicate_placement.placements[0].clone());
        assert_eq!(
            duplicate_placement.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut duplicate_edge = graph();
        let edge = MessageEdge {
            child_placement_id: duplicate_edge.placements[0].id.clone(),
            parent_message_id: id(IdKind::Message, "orphan"),
            parent_native_id: Some("native-parent".into()),
            relation: MessageRelation::Reply,
        };
        duplicate_edge.edges.extend([edge.clone(), edge]);
        assert_eq!(
            duplicate_edge.validate().unwrap_err().code(),
            "invariant_violation"
        );
    }

    #[test]
    fn graph_allows_same_ordinal_for_distinct_messages() {
        // 交织 sidechain:同文档同 ordinal 的不同消息是合法坐标——placement id
        // 已含 message_id 不会碰撞,坐标唯一性键也含 message_id,不得误拒。
        let mut graph = graph();
        let second = message("second");
        graph.placements.push(placement(
            &graph.session_id,
            &graph.source_documents[0].id,
            &second.id,
            0,
        ));
        graph.messages.push(second);
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn graph_rejects_duplicate_coordinate_for_same_message() {
        // 同文档同 ordinal 同消息仍是重复坐标(placement id 也会碰撞),拒绝。
        let mut graph = graph();
        graph.placements.push(placement(
            &graph.session_id,
            &graph.source_documents[0].id,
            &graph.messages[0].id,
            0,
        ));
        assert_eq!(graph.validate().unwrap_err().code(), "invariant_violation");
    }

    #[test]
    fn graph_rejects_missing_message_document_and_child_references() {
        let mut missing_message = graph();
        let absent_message = id(IdKind::Message, "absent");
        missing_message.placements[0] = placement(
            &missing_message.session_id,
            &missing_message.source_documents[0].id,
            &absent_message,
            0,
        );
        assert_eq!(
            missing_message.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut missing_document = graph();
        let absent_document = id(IdKind::Document, "absent");
        missing_document.placements[0] = placement(
            &missing_document.session_id,
            &absent_document,
            &missing_document.messages[0].id,
            0,
        );
        assert_eq!(
            missing_document.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut missing_child = graph();
        missing_child.edges.push(MessageEdge {
            child_placement_id: PlacementId::derive(
                &missing_child.session_id,
                &missing_child.source_documents[0].id,
                &missing_child.messages[0].id,
                77,
            ),
            parent_message_id: id(IdKind::Message, "orphan"),
            parent_native_id: None,
            relation: MessageRelation::Reply,
        });
        assert_eq!(
            missing_child.validate().unwrap_err().code(),
            "invariant_violation"
        );
    }

    #[test]
    fn graph_rejects_invalid_and_out_of_bounds_spans() {
        let mut reversed = graph();
        reversed.placements[0].span = Some(EvidenceSpan { start: 5, end: 4 });
        assert_eq!(
            reversed.validate().unwrap_err().code(),
            "invariant_violation"
        );

        let mut out_of_bounds = graph();
        out_of_bounds.placements[0].span = Some(EvidenceSpan {
            start: 127,
            end: 129,
        });
        assert_eq!(
            out_of_bounds.validate().unwrap_err().code(),
            "invariant_violation"
        );
    }

    #[test]
    fn orphan_parent_message_is_structurally_valid() {
        let mut graph = graph();
        graph.edges.push(MessageEdge {
            child_placement_id: graph.placements[0].id.clone(),
            parent_message_id: id(IdKind::Message, "outside-context"),
            parent_native_id: Some("outside-native".into()),
            relation: MessageRelation::Reply,
        });
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn message_relation_wire_values_are_stable() {
        let variants = [
            (MessageRelation::Reply, "reply"),
            (MessageRelation::Retry, "retry"),
            (MessageRelation::Fork, "fork"),
            (MessageRelation::Continuation, "continuation"),
            (MessageRelation::Subagent, "subagent"),
            (MessageRelation::ToolResult, "tool_result"),
        ];
        for (relation, wire) in variants {
            assert_eq!(relation.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&relation).unwrap(),
                format!("\"{wire}\"")
            );
        }
    }

    #[test]
    fn tool_activity_wire_values_are_stable() {
        let kinds = [
            (ToolActivityKind::File, "file"),
            (ToolActivityKind::Command, "command"),
            (ToolActivityKind::Web, "web"),
            (ToolActivityKind::Query, "query"),
            (ToolActivityKind::Unknown, "unknown"),
        ];
        for (kind, wire) in kinds {
            assert_eq!(kind.as_str(), wire);
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{wire}\""));
        }
        let actors = [
            (ToolActivityActor::Main, "main"),
            (ToolActivityActor::Subagent, "subagent"),
        ];
        for (actor, wire) in actors {
            assert_eq!(actor.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&actor).unwrap(),
                format!("\"{wire}\"")
            );
        }
        let statuses = [
            (ToolActivityStatus::Success, "success"),
            (ToolActivityStatus::Error, "error"),
            (ToolActivityStatus::Unknown, "unknown"),
        ];
        for (status, wire) in statuses {
            assert_eq!(status.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&status).unwrap(),
                format!("\"{wire}\"")
            );
        }
        // Round-trip of the full model.
        let activity = ToolActivity {
            kind: ToolActivityKind::Command,
            actor: ToolActivityActor::Main,
            name: "Bash".into(),
            target: Some("ls -la".into()),
            status: ToolActivityStatus::Success,
        };
        activity.validate().unwrap();
        let json = serde_json::to_string(&activity).unwrap();
        let restored: ToolActivity = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, activity);
    }

    #[test]
    fn tool_activity_rejects_empty_name() {
        let activity = ToolActivity {
            kind: ToolActivityKind::Unknown,
            actor: ToolActivityActor::Main,
            name: " ".into(),
            target: None,
            status: ToolActivityStatus::Unknown,
        };
        assert_eq!(
            activity.validate().unwrap_err().code(),
            "invariant_violation"
        );
    }
}
