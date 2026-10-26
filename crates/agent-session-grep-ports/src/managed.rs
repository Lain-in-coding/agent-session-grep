//! Typed, private source-projection contracts. Proofs are not wire responses.
//! None of these types grants permission without current control/binding checks.

use crate::{PortError, PortResult, SearchFacets, SearchFilters, SearchProvider};
use agent_session_grep_domain::{
    Message, MessagePlacement, MessageRelation, PlacementId, Session, SourceDocument, StableId,
    ToolActivity, UsageObservation,
};
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! private_id {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: &str) -> PortResult<Self> {
                if value.is_empty()
                    || value.len() > 128
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
                    return Err(PortError::InvalidRequest(
                        "invalid projection identifier".into(),
                    ));
                }
                Ok(Self(value.into()))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([private])"))
            }
        }
    };
}
private_id!(SourceId);
private_id!(RevisionId);
private_id!(ProjectionId);

/// Verified filesystem/control binding. Locators never enter public provenance.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceBinding {
    pub source_id: SourceId,
    pub source_path: String,
    pub provider: SearchProvider,
    pub namespace_id: Option<String>,
    pub root_identity: String,
}
impl fmt::Debug for SourceBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceBinding([private])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationState {
    /// Caller verified the entire snapshot and completed rewrite/deletion holds.
    Complete,
    Incomplete,
    Unstable,
    RewritePending,
    DeletionPending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionProof {
    pub selection_id: String,
    pub selection_revision: i64,
    pub root_identity: String,
}

/// One source observation included in an exact discovered selection set.
/// Identifiers and receipts remain private; this is not public provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySource {
    pub source_id: SourceId,
    pub revision_id: RevisionId,
}

/// Catalog publication input, authorized by the caller's real worker/cycle
/// capability. A complete empty set is valid. Scheduling acknowledgement and
/// wall-clock values cannot replace this observation or its source receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryObservation {
    pub cycle_seq: i64,
    pub worker_boot_id: String,
    pub catalog_incarnation: String,
    pub policy_epoch: i64,
    pub started_control_seq: i64,
    pub selection: SelectionProof,
    pub sources: Vec<DiscoverySource>,
    pub complete: bool,
}

/// One full observation, never a delta. SourceBatch completeness/fingerprint
/// must agree; append optimization requires a separate future prefix-proof API.
#[derive(Debug, Clone)]
pub struct SourceObservation {
    pub binding: SourceBinding,
    pub revision_id: RevisionId,
    pub revision_digest: String,
    pub parser_version: u32,
    pub state: ObservationState,
    pub cycle_seq: i64,
    pub worker_boot_id: String,
    pub catalog_incarnation: String,
    pub policy_epoch: i64,
    pub started_control_seq: i64,
    pub observed_at_ms: i64,
    pub committed_at_ms: i64,
    pub selections: Vec<SelectionProof>,
    /// Derived from this source's verified paired resume claim by the existing
    /// repository resolver; never copied from global merged repo tables.
    pub repositories: Vec<RepositoryClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryClaim {
    pub session_id: StableId,
    pub slug: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRef {
    pub revision_id: RevisionId,
    pub digest: String,
    pub observed_at_ms: i64,
    pub cycle_seq: i64,
    pub worker_boot_id: String,
    pub catalog_incarnation: String,
    pub policy_epoch: i64,
    pub started_control_seq: i64,
    pub committed_generation: Option<i64>,
    pub published: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    pub receipt: RevisionRef,
    pub content_changed: bool,
    pub destructive: bool,
    /// Minimum generation required by this source. Caller CASes the batch's
    /// maximum requirement in the SAME transaction, then finalizes all receipts.
    pub required_generation: i64,
    pub destructive_epoch: i64,
}

#[derive(Debug, Clone)]
pub struct ReadScope {
    pub catalog_incarnation: String,
    pub policy_epoch: i64,
    /// Already authorized by current control; the adapter rechecks each binding.
    pub allowed: Vec<SourceBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadSnapshot {
    pub catalog_incarnation: String,
    pub generation: i64,
    pub destructive_epoch: i64,
    pub policy_epoch: i64,
}

/// Content-free source progress in the same catalog snapshot. A latest receipt
/// still requires cycle/discovery ownership checks by Application; it is not
/// by itself a claim that a request's latest barrier is satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProgress {
    pub source_id: SourceId,
    pub visible_revision: Option<RevisionId>,
    pub latest_receipt: Option<RevisionRef>,
    pub last_attempt: Option<RevisionRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionQuery {
    pub filters: SearchFilters,
    pub facets: SearchFacets,
    pub include_system: bool,
    pub session_id: Option<StableId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceProof {
    pub source_id: SourceId,
    pub projection_id: ProjectionId,
    pub revision: RevisionRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageProjection {
    pub message: Message,
    pub index_text: String,
    pub payload_digest: String,
    pub index_digest: String,
    pub proof: EvidenceProof,
    pub occurrence: Option<OccurrenceProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OccurrenceData {
    pub placement: MessagePlacement,
    pub provider_id: String,
    pub project_id: Option<String>,
    pub timestamp: Option<String>,
    pub role: agent_session_grep_domain::Role,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceProjection {
    pub data: OccurrenceData,
    pub source_id: SourceId,
    pub revision: RevisionRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionData {
    pub session: Session,
    pub documents: Vec<StableId>,
    pub title: Option<String>,
    pub repo_slug: Option<String>,
    pub provider_id: String,
    pub first_user_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum ResumeValue {
    Missing,
    Resolved(String),
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeData {
    pub session_id: StableId,
    pub provider_id: String,
    pub provider_session_id: ResumeValue,
    pub original_working_directory: ResumeValue,
    pub pair_observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum EntityData {
    Session(SessionData),
    Document(SourceDocument),
    Edge {
        child: PlacementId,
        parent: StableId,
        relation: MessageRelation,
    },
    Tool {
        activity_id: String,
        message_id: StableId,
        activity: ToolActivity,
    },
    Usage {
        usage_id: String,
        session_id: StableId,
        message_id: Option<StableId>,
        usage: UsageObservation,
    },
    Resume(ResumeData),
    Repository(RepositoryClaim),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Session,
    Document,
    Edge,
    Tool,
    Usage,
    Resume,
    Repository,
}
impl EntityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Document => "document",
            Self::Edge => "edge",
            Self::Tool => "tool_activity",
            Self::Usage => "usage_event",
            Self::Resume => "resume_claim",
            Self::Repository => "repo_identity",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityProjection {
    pub data: EntityData,
    pub proof: EvidenceProof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexicalHit {
    pub projection: MessageProjection,
    /// Positive BM25 computed only over authorized logical text variants.
    pub score: f64,
    pub claim_count: usize,
}
#[derive(Debug, Clone, PartialEq)]
pub struct LexicalPage {
    pub hits: Vec<LexicalHit>,
    /// More canonical matches than the requested retained window; not total count.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMetadataField {
    Title,
    Repository,
    Provider,
    FirstUser,
}
impl SessionMetadataField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Title => "session_title",
            Self::Repository => "repository",
            Self::Provider => "provider",
            Self::FirstUser => "session_first_user",
        }
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct SessionMetadataHit {
    pub projection: EntityProjection,
    pub score: f64,
    /// Empty when a single phrase crosses metadata-field boundaries. The
    /// session_metadata match itself remains exact; no field snippet is claimed.
    pub fields: Vec<SessionMetadataField>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct SessionMetadataPage {
    pub hits: Vec<SessionMetadataHit>,
    pub truncated: bool,
    pub incomplete: bool,
}

/// One deterministic permitted projection for a canonical list item. No
/// merged payload bytes cross the adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionListEntry {
    Message(Box<MessageProjection>),
    Entity(Box<EntityProjection>),
}
impl ProjectionListEntry {
    pub fn id(&self) -> &StableId {
        match self {
            Self::Message(projection) => &projection.message.id,
            Self::Entity(projection) => match &projection.data {
                EntityData::Session(data) => &data.session.id,
                EntityData::Document(data) => &data.id,
                // List producers return containers only. Other typed facts can
                // still be addressed through their canonical anchor.
                EntityData::Edge { parent, .. } => parent,
                EntityData::Tool { message_id, .. } => message_id,
                EntityData::Usage { session_id, .. } => session_id,
                EntityData::Resume(data) => &data.session_id,
                EntityData::Repository(data) => &data.session_id,
            },
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionListPage {
    pub entries: Vec<ProjectionListEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPreviewRequest {
    pub session_id: StableId,
    pub source_id: SourceId,
}
/// Original user-text prefix (at most the shared peek field limit), paired
/// with the exact occurrence and published source evidence. Never merged text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewMessage {
    pub text: String,
    pub occurrence: OccurrenceProjection,
    pub proof: EvidenceProof,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPreview {
    pub request: SessionPreviewRequest,
    pub first_user: Option<PreviewMessage>,
    pub last_user: Option<PreviewMessage>,
    pub unavailable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionStats {
    pub catalog_count: u64,
    pub placements: u64,
    pub source_placement_claims: u64,
    pub usage: Option<crate::UsageTotals>,
    pub repos: Vec<crate::RepoTotals>,
    pub repos_truncated: bool,
    /// Conflicting/unattributable aggregate facts were omitted, never summed
    /// as if they were observed zeros or independently corroborated copies.
    pub facts_incomplete: bool,
}

/// Bounds for loading a COMPLETE topology before branch selection. Exceeding
/// either bound is an error, never a partial graph presented as a real leaf.
#[derive(Debug, Clone, Copy)]
pub struct GraphReadLimits {
    pub max_occurrences: usize,
    pub max_bytes: usize,
}
impl Default for GraphReadLimits {
    fn default() -> Self {
        Self {
            max_occurrences: 16_384,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextProjection {
    /// Original text and occurrence selected together from ONE source.
    pub message: MessageProjection,
    pub document: SourceDocument,
    pub document_proof: EvidenceProof,
    /// Parent must have a permitted occurrence in this filtered session graph.
    pub edge: Option<EntityProjection>,
    pub tools: Vec<EntityProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProjectionGraph {
    pub session: EntityProjection,
    pub occurrences: Vec<ContextProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedMessageContext {
    pub session_id: StableId,
    pub occurrences: Vec<OccurrenceEvidence>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceEvidence {
    pub occurrence: OccurrenceProjection,
    pub proof: EvidenceProof,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageContextsPage {
    pub candidates: Vec<ProjectedMessageContext>,
    /// Distinct permitted sessions, even when returned placement IDs are capped.
    pub candidate_count: u64,
    pub truncated: bool,
}

/// A read capability; there is no unscoped overload or merged payload fallback.
pub trait ProjectionRead {
    fn snapshot(&self) -> &ReadSnapshot;
    /// Exact historical receipt authorized by a verified recovery in this
    /// current snapshot. Default refusal keeps unrelated/mock foreign proof
    /// fail-closed. This permits original evidence, never currentness/latest.
    fn retained_revision_allowed(&self, _revision: &RevisionRef) -> PortResult<bool> {
        Ok(false)
    }
    fn source_progress(&self) -> PortResult<Vec<SourceProgress>>;
    /// Canonical ID order, authorization and request predicates before limit.
    /// Limit is 1..=512; one additional eligible ID supplies truncation proof.
    fn list(
        &self,
        query: &ProjectionQuery,
        sessions_only: bool,
        limit: usize,
    ) -> PortResult<ProjectionListPage>;
    fn stats(&self, query: &ProjectionQuery, repo_limit: usize) -> PortResult<ProjectionStats>;
    /// Input-aligned previews of the specified source's qualified members in
    /// (document, source ordinal, placement) order. Bounded as a whole; exhausted
    /// work capacity reports unavailable rather than inventing empty content.
    fn session_previews(
        &self,
        requests: &[SessionPreviewRequest],
        query: &ProjectionQuery,
        max_bytes: usize,
    ) -> PortResult<Vec<SessionPreview>>;
    fn session_graph(
        &self,
        session_id: &StableId,
        query: &ProjectionQuery,
        limits: GraphReadLimits,
    ) -> PortResult<SessionProjectionGraph>;
    fn message_contexts(
        &self,
        message_id: &StableId,
        query: &ProjectionQuery,
        max_candidates: usize,
        max_occurrences: usize,
    ) -> PortResult<MessageContextsPage>;
    fn messages(
        &self,
        ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<Option<MessageProjection>>>;
    /// Sessions retain one row/proof per allowed source. Conflicting title/repo
    /// fields are unavailable; consumers must not assign a union to one proof.
    fn entities(
        &self,
        kind: EntityKind,
        ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<EntityProjection>>;
    fn occurrences(
        &self,
        ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<OccurrenceProjection>>;
    fn query_lexical(
        &self,
        text: &str,
        query: &ProjectionQuery,
        limit: usize,
    ) -> PortResult<LexicalPage>;
    /// Separate Session metadata channel, authorized and qualified before
    /// matching/ranking. Documents remain ID/list navigation only.
    fn query_session_metadata(
        &self,
        text: &str,
        query: &ProjectionQuery,
        limit: usize,
    ) -> PortResult<SessionMetadataPage>;
}
