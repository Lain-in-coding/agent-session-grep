//! Request-scoped projection reader. Never constructs the legacy App/store.
//! The caller keeps the catalog snapshot alive through this call, then rechecks
//! control under the emission gate before serializing the bounded response.
//! Safe continuation storage remains an explicit gap.

use crate::{
    AppError, AppRequest, AppResponse, ContextLevel, ContextMessage, MessageAmbiguity,
    MessageContextCandidate, MessageWindow, ResponseBudget, Truncation, budget, cursor, evidence,
    guidance,
    handoff_pack::{self, HandoffInput, MessageFact, SourceLocationInfo},
    ranking, snippet,
};
use agent_session_grep_domain::{
    ContextPolicy, IdKind, Message, MessageEdge, SessionContextGraph, StableId, select_full,
    select_mainline,
};
use agent_session_grep_ports::{
    CatalogEntry, PortError, RetrievalMode, SearchHit, SessionResumeMetadata, SidechainFacet,
    handoff::{HandoffFilters, HandoffPack, HandoffTarget, TruncationReason},
    managed::*,
};
use std::collections::{BTreeMap, BTreeSet};

/// Immutable restriction/budget intersection for every request, including the
/// legacy ADT variants which lack filters or budgets of their own. Deadline
/// observation is injected; no Application filesystem or system-clock access.
pub struct ManagedRequestContext<'a> {
    pub intersection: ProjectionQuery,
    pub budget: ResponseBudget,
    pub now_ms: i64,
    pub current_repo: Option<String>,
    pub deadline_expired: &'a dyn Fn() -> bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPartial {
    ContinuationUnavailable,
    RankingWindow,
    ResponseBudget,
    MetadataSearchUnavailable,
    ResumeAvailabilityUnavailable,
    ListPreviewUnavailable,
    SemanticUnavailable,
    AggregateFactsUnavailable,
    HandoffEnrichmentUnavailable,
    ContextUnavailable,
    RetainedEvidence,
}
impl ManagedPartial {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContinuationUnavailable => "continuation_unavailable",
            Self::RankingWindow => "ranking_window",
            Self::ResponseBudget => "response_budget",
            Self::MetadataSearchUnavailable => "metadata_search_unavailable",
            Self::ResumeAvailabilityUnavailable => "resume_availability_unavailable",
            Self::ListPreviewUnavailable => "list_preview_unavailable",
            Self::SemanticUnavailable => "semantic_unavailable",
            Self::AggregateFactsUnavailable => "aggregate_facts_unavailable",
            Self::HandoffEnrichmentUnavailable => "handoff_enrichment_unavailable",
            Self::ContextUnavailable => "context_unavailable",
            Self::RetainedEvidence => "retained_evidence",
        }
    }
}

/// Internal proof for exactly one retained output item. Never serialize this
/// wholesale: source/projection identifiers are private. Public provenance is a
/// separate safe projection, charged within the same response budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedEvidence {
    pub entity_id: StableId,
    pub proof: EvidenceProof,
    pub occurrence: Option<OccurrenceProjection>,
    /// Supporting document/edge/tool and session/branch proofs. Occurrence
    /// facts are from its source; a session or branch proof can have another
    /// permitted source. Metadata proofs do not consume an evidence span.
    pub related: Vec<EvidenceProof>,
}

/// The composition root MUST combine `partial` with ADT truncation when choosing
/// its protocol outcome. Snapshot generation is as-of disclosure, not freshness
/// or latest-barrier satisfaction. No legacy stateless cursor is ever issued.
#[derive(Debug, Clone, PartialEq)]
pub struct ManagedResponse {
    pub response: AppResponse,
    pub snapshot: ReadSnapshot,
    pub evidence: Vec<ManagedEvidence>,
    pub partial: Vec<ManagedPartial>,
}
impl ManagedResponse {
    pub fn is_partial(&self) -> bool {
        !self.partial.is_empty()
    }
}

/// Exact frozen projection in first-query order. Cache adapters copy these
/// fields; they never reselect a canonical-ID representative or recompute rank.
#[derive(Debug, Clone, PartialEq)]
pub struct ManagedCandidate {
    pub entry: ProjectionListEntry,
    pub hit: Option<SearchHit>,
    pub evidence: Vec<ManagedEvidence>,
    pub peek: Option<crate::SessionPeek>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagedCandidateSet {
    pub candidates: Vec<ManagedCandidate>,
    pub snapshot: ReadSnapshot,
    pub request_now_ms: i64,
    pub partial: Vec<ManagedPartial>,
    /// The retained window is incomplete, independently of output page size.
    pub truncated: bool,
}

/// Search and every enrichment intersect this restriction with the request
/// context. Pack limits can only narrow that context's response budget.
pub struct ManagedHandoffRequest {
    /// Full literal query, at most 256 Unicode characters (pack term schema).
    pub query: String,
    pub intersection: ProjectionQuery,
    pub limit: usize,
    pub budget: ResponseBudget,
    pub max_tokens: u64,
    pub max_bytes: u64,
    pub max_evidence: usize,
    pub mode: RetrievalMode,
    pub target: Option<HandoffTarget>,
}

/// Owned inputs, with an inherited deadline. No source path, legacy resolver or
/// subsequent store read is needed. Proofs describe the candidate inputs;
/// generate() returns only proofs for retained pack evidence.
pub struct ManagedHandoffInput<'a> {
    pub snapshot: ReadSnapshot,
    pub evidence: Vec<ManagedEvidence>,
    pub partial: Vec<ManagedPartial>,
    /// None is an empty/disjoint intersection, never unrestricted access.
    pub intersection: Option<ProjectionQuery>,
    hits: Vec<SearchHit>,
    locations: Vec<SourceLocationInfo>,
    facts: Vec<MessageFact>,
    tools: Vec<HandoffTool>,
    tool_values: Vec<serde_json::Value>,
    terms: Vec<String>,
    filters: HandoffFilters,
    mode: RetrievalMode,
    target: Option<HandoffTarget>,
    max_tokens: u64,
    max_bytes: usize,
    max_evidence: usize,
    metadata_redactions: u64,
    deadline_expired: &'a dyn Fn() -> bool,
}

pub struct ManagedHandoffResponse {
    pub pack: HandoffPack,
    pub snapshot: ReadSnapshot,
    pub evidence: Vec<ManagedEvidence>,
    pub partial: Vec<ManagedPartial>,
    pub intersection: Option<ProjectionQuery>,
}
impl ManagedHandoffResponse {
    pub fn is_partial(&self) -> bool {
        !self.partial.is_empty() || self.pack.truncation.truncated
    }
}

struct HandoffTool {
    message_id: String,
    value: serde_json::Value,
    redacted: bool,
}

impl ManagedHandoffInput<'_> {
    /// Low-level borrowed adapter for the shared deterministic generator. For
    /// output use generate(): it also aligns retained proofs/tools, removes
    /// legacy cursor hints and enforces the WHOLE serialized response budget.
    pub fn as_input(&self) -> HandoffInput<'_> {
        HandoffInput {
            query_terms: &self.terms,
            retrieval_mode: self.mode,
            filters: self.filters.clone(),
            hits: &self.hits,
            source_locations: &self.locations,
            tool_activities: &self.tool_values,
            message_facts: &self.facts,
            catalog_generation: self.snapshot.generation as u64,
            max_tokens: self.max_tokens,
            max_bytes: self.max_bytes as u64,
            max_evidence: self.max_evidence,
            target: self.target.clone(),
        }
    }

    /// Call inside the same managed read closure; output still requires the
    /// composition root's policy-emission recheck. No clock/deadline is reset.
    pub fn generate(mut self) -> Result<ManagedHandoffResponse, AppError> {
        let mut dropped = 0_u64;
        let mut reason = TruncationReason::None;
        let attempts = self.hits.len() + 1;
        for _ in 0..attempts {
            handoff_deadline(self.deadline_expired)?;
            let mut pack = handoff_pack::generate_deterministic(self.as_input());
            handoff_deadline(self.deadline_expired)?;
            let retained: BTreeSet<_> = pack
                .evidence
                .iter()
                .map(|e| e.message_id.as_str())
                .collect();
            if retained.len() > self.hits.len()
                || retained
                    .iter()
                    .any(|id| !self.hits.iter().any(|h| h.id.as_str() == *id))
            {
                return Err(inconsistent());
            }
            if retained.len() < self.hits.len() {
                dropped += (self.hits.len() - retained.len()) as u64;
                reason = pack.truncation.reason;
                self.retain(&retained);
                self.partial.push(ManagedPartial::ResponseBudget);
                continue;
            }
            // These are canonical document IDs, never private filesystem paths.
            // The legacy generator labels a message ID as a cursor; do not
            // issue such hints from the managed continuation contract.
            for locator in &mut pack.source_locators {
                locator.cursor = None;
            }
            pack.truncation.dropped_locators.clear();
            pack.truncation.dropped_count = dropped;
            if dropped > 0
                || self.partial.iter().any(|p| {
                    matches!(
                        p,
                        ManagedPartial::ResponseBudget | ManagedPartial::RankingWindow
                    )
                })
            {
                pack.truncation.truncated = true;
                pack.truncation.reason = if reason == TruncationReason::None {
                    TruncationReason::MaxItems
                } else {
                    reason
                };
            }
            pack.redaction.redacted_count += self.metadata_redactions
                + self.tools.iter().filter(|tool| tool.redacted).count() as u64;
            if pack.redaction.redacted_count > 0 {
                pack.redaction.status = agent_session_grep_ports::RedactionState::Applied;
            }
            // The legacy pack identifier knows only generation/provider/time.
            // Bind managed context and exact retained proofs as well. Private
            // identifiers enter the digest, never its serialized input/output.
            let mut identity = blake3::Hasher::new();
            identity.update(b"managed-handoff-v1");
            let scope = self.intersection.as_ref().map(|q| {
                serde_json::json!({
                    "repo":q.filters.repo,"session":q.session_id.as_ref().map(StableId::as_str),
                    "sidechain":q.facets.sidechain.as_str(),"kind":q.facets.tool_kind,
                    "name":q.facets.tool_name,"include_system":q.include_system,
                })
            });
            for field in [
                bytes(&pack)?,
                bytes(&scope)?,
                bytes(&serde_json::json!({
                    "incarnation":self.snapshot.catalog_incarnation,"policy":self.snapshot.policy_epoch,
                    "destructive_epoch":self.snapshot.destructive_epoch,
                }))?,
            ] {
                identity.update(&(field.len() as u64).to_le_bytes());
                identity.update(&field);
            }
            for evidence in &self.evidence {
                for field in [
                    evidence.proof.source_id.as_str(),
                    evidence.proof.projection_id.as_str(),
                    evidence.proof.revision.revision_id.as_str(),
                ] {
                    identity.update(&(field.len() as u64).to_le_bytes());
                    identity.update(field.as_bytes());
                }
            }
            pack.pack_id = format!("pack_v1_{}", &identity.finalize().to_hex()[..32]);
            // The managed budget is stronger than the generator's content-only
            // budget: diagnostics and internal/public provenance reserves count.
            let proof_bytes = self
                .evidence
                .iter()
                .fold(0usize, |n, p| n.saturating_add(proof_charge(p)));
            let mut size = 0;
            for _ in 0..4 {
                size = bytes(&pack)?.len();
                if pack.budget.used_bytes == size as u64 {
                    break;
                }
                pack.budget.used_bytes = size as u64;
            }
            size = size.max(bytes(&pack)?.len());
            if size.saturating_add(proof_bytes) <= self.max_bytes {
                handoff_deadline(self.deadline_expired)?;
                let mut seen = BTreeSet::new();
                self.partial.retain(|p| seen.insert(p.as_str()));
                return Ok(ManagedHandoffResponse {
                    pack,
                    snapshot: self.snapshot,
                    evidence: self.evidence,
                    partial: self.partial,
                    intersection: self.intersection,
                });
            }
            if self.hits.is_empty() {
                return Err(handoff_budget());
            }
            let keep: BTreeSet<_> = self.hits[..self.hits.len() - 1]
                .iter()
                .map(|h| h.id.as_str().to_owned())
                .collect();
            self.retain(&keep.iter().map(String::as_str).collect());
            dropped += 1;
            reason = TruncationReason::MaxBytes;
            self.partial.push(ManagedPartial::ResponseBudget);
        }
        Err(handoff_budget())
    }

    fn retain(&mut self, ids: &BTreeSet<&str>) {
        self.hits.retain(|h| ids.contains(h.id.as_str()));
        self.locations
            .retain(|l| ids.contains(l.message_id.as_str()));
        self.facts.retain(|f| ids.contains(f.message_id.as_str()));
        self.evidence.retain(|p| ids.contains(p.entity_id.as_str()));
        self.tools.retain(|t| ids.contains(t.message_id.as_str()));
        self.tool_values = self.tools.iter().map(|t| t.value.clone()).collect();
    }
}

pub struct ManagedApp<'a, R: ProjectionRead + ?Sized> {
    read: &'a R,
    context: ManagedRequestContext<'a>,
}

fn invalid() -> AppError {
    PortError::InvalidRequest("invalid managed request".into()).into()
}
fn inconsistent() -> AppError {
    PortError::SchemaIncompatible("managed projection response is inconsistent".into()).into()
}
fn bytes(value: &impl serde::Serialize) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(value).map_err(|_| inconsistent())
}
fn handoff_deadline(expired: &dyn Fn() -> bool) -> Result<(), AppError> {
    if expired() {
        Err(PortError::DeadlineExceeded("managed request deadline exceeded".into()).into())
    } else {
        Ok(())
    }
}
fn handoff_budget() -> AppError {
    budget::BudgetError::TooSmall("max_response_bytes cannot fit managed handoff metadata".into())
        .into()
}
fn redact_handoff_text(value: &mut String) -> u64 {
    if let Some(redacted) = agent_session_grep_ports::redact::redact_string(value) {
        *value = redacted;
        1
    } else {
        0
    }
}
fn handoff_filters(query: Option<&ProjectionQuery>) -> HandoffFilters {
    let Some(query) = query else {
        return HandoffFilters::default();
    };
    // Preserve the established HandoffFilters normalized instant notation.
    // The full typed intersection remains on the managed result as authority.
    HandoffFilters {
        providers: query
            .filters
            .providers
            .iter()
            .map(|p| p.as_str().into())
            .collect(),
        since: query
            .filters
            .since
            .map(|s| format!("{}.{:09}Z", s.unix_seconds, s.nanosecond)),
        until: query
            .filters
            .until
            .map(|s| format!("{}.{:09}Z", s.unix_seconds, s.nanosecond)),
    }
}

impl<'a, R: ProjectionRead + ?Sized> ManagedApp<'a, R> {
    pub fn new(read: &'a R, context: ManagedRequestContext<'a>) -> Result<Self, AppError> {
        context.budget.validate()?;
        validate_query(&context.intersection)?;
        if context.now_ms < 0
            || read.snapshot().generation < 0
            || read.snapshot().policy_epoch < 0
            || read.snapshot().destructive_epoch < 0
        {
            return Err(invalid());
        }
        let app = Self { read, context };
        app.check_deadline()?;
        Ok(app)
    }
    fn check_deadline(&self) -> Result<(), AppError> {
        if (self.context.deadline_expired)() {
            Err(PortError::DeadlineExceeded("managed request deadline exceeded".into()).into())
        } else {
            Ok(())
        }
    }
    fn finish(
        &self,
        response: AppResponse,
        evidence: Vec<ManagedEvidence>,
        mut partial: Vec<ManagedPartial>,
    ) -> Result<ManagedResponse, AppError> {
        self.check_deadline()?;
        if evidence.iter().any(|e| {
            std::iter::once(&e.proof)
                .chain(e.related.iter())
                .any(|p| p.revision.catalog_incarnation != self.read.snapshot().catalog_incarnation)
        }) {
            partial.push(ManagedPartial::RetainedEvidence);
        }
        let mut seen = BTreeSet::new();
        partial.retain(|p| seen.insert(p.as_str()));
        Ok(ManagedResponse {
            response,
            snapshot: self.read.snapshot().clone(),
            evidence,
            partial,
        })
    }
    fn generation(&self) -> u64 {
        self.read.snapshot().generation as u64
    }
    fn validate_revision(&self, revision: &RevisionRef) -> Result<(), AppError> {
        let snapshot = self.read.snapshot();
        if !revision.published
            || (revision.catalog_incarnation != snapshot.catalog_incarnation
                && !self.read.retained_revision_allowed(revision)?)
            || revision
                .committed_generation
                .is_none_or(|g| g < 0 || g > snapshot.generation)
            || revision.policy_epoch < 0
            || revision.policy_epoch > snapshot.policy_epoch
            || revision.observed_at_ms < 0
            || revision.cycle_seq < 0
            || revision.started_control_seq < 0
        {
            return Err(inconsistent());
        }
        Ok(())
    }

    pub fn handle(&self, request: AppRequest) -> Result<ManagedResponse, AppError> {
        self.check_deadline()?;
        match request {
            AppRequest::Search {
                query,
                filters,
                facets,
                limit,
                cursor,
                budget,
                include_system,
                group_by_session,
                mode,
                query_embedding,
            } => {
                crate::validate_search_request(&query, &filters, limit, &budget)?;
                reject_cursor(cursor.as_deref())?;
                if query_embedding
                    .as_ref()
                    .is_some_and(|v| v.is_empty() || v.iter().any(|n| !n.is_finite()))
                {
                    return Err(invalid());
                }
                let request_query = ProjectionQuery {
                    filters,
                    facets,
                    include_system,
                    session_id: None,
                };
                let qualified = intersect(&self.context.intersection, &request_query)?;
                let budget = intersect_budget(&self.context.budget, &budget);
                self.search(
                    &query,
                    qualified.as_ref(),
                    limit,
                    &budget,
                    group_by_session,
                    mode,
                )
            }
            AppRequest::Get { id } => self.get(id, false),
            AppRequest::Show { id } => self.get(id, true),
            AppRequest::List {
                limit,
                cursor,
                budget,
                sessions_only,
            } => {
                if limit == 0 {
                    return Err(invalid());
                }
                budget.validate()?;
                reject_cursor(cursor.as_deref())?;
                self.list(
                    limit,
                    &intersect_budget(&self.context.budget, &budget),
                    sessions_only,
                )
            }
            AppRequest::Status => self.status(),
            AppRequest::GetSessionResume { session_id } => self.resume(session_id),
            AppRequest::Context {
                session_id,
                policy,
                level,
                budget,
            } => {
                budget.validate()?;
                self.context_response(
                    session_id,
                    policy,
                    level,
                    &intersect_budget(&self.context.budget, &budget),
                )
            }
            AppRequest::Message {
                message_id,
                session_id,
                around,
                budget,
            } => {
                budget.validate()?;
                self.message_window(
                    message_id,
                    session_id,
                    around,
                    &intersect_budget(&self.context.budget, &budget),
                )
            }
            AppRequest::MessageContexts { message_id } => self.message_contexts(message_id),
        }
    }

    /// Collect a bounded first-query window BEFORE output pagination. A cache
    /// must retain this complete DTO and bind the original request predicates.
    pub fn collect_candidates(&self, request: AppRequest) -> Result<ManagedCandidateSet, AppError> {
        self.check_deadline()?;
        match request {
            AppRequest::Search {
                query,
                filters,
                facets,
                limit,
                cursor,
                budget,
                include_system,
                group_by_session,
                mode,
                query_embedding,
            } => {
                crate::validate_search_request(&query, &filters, limit, &budget)?;
                reject_cursor(cursor.as_deref())?;
                if query_embedding
                    .as_ref()
                    .is_some_and(|v| v.is_empty() || v.iter().any(|n| !n.is_finite()))
                {
                    return Err(invalid());
                }
                let query_filter = intersect(
                    &self.context.intersection,
                    &ProjectionQuery {
                        filters,
                        facets,
                        include_system,
                        session_id: None,
                    },
                )?;
                self.collect_search_with_metadata(
                    &query,
                    query_filter.as_ref(),
                    &intersect_budget(&self.context.budget, &budget),
                    group_by_session,
                    mode,
                )
            }
            AppRequest::List {
                limit,
                cursor,
                budget,
                sessions_only,
            } => {
                if limit == 0 {
                    return Err(invalid());
                }
                budget.validate()?;
                reject_cursor(cursor.as_deref())?;
                let mut budget = intersect_budget(&self.context.budget, &budget);
                // Item counts are page limits; collecting the fixed cache window
                // does not grant a larger eventual response or preview budget.
                budget.max_items = 512;
                self.collect_list(512, &budget, sessions_only)
            }
            _ => Err(invalid()),
        }
    }

    /// Render an authenticated cached window without storage enrichment or
    /// ranking. The cache owns query binding/current authorization; this checks
    /// snapshot compatibility and the candidate DTOs before output clamping.
    /// Advance a cursor by actual returned items, never the requested limit.
    pub fn render_candidates(
        &self,
        request: AppRequest,
        set: &ManagedCandidateSet,
        offset: usize,
    ) -> Result<ManagedResponse, AppError> {
        self.check_deadline()?;
        let current = self.read.snapshot();
        if set.candidates.len() > 512
            || offset > set.candidates.len()
            || set.request_now_ms < 0
            || set.snapshot.generation < 0
            || set.snapshot.generation > current.generation
            || set.snapshot.catalog_incarnation != current.catalog_incarnation
            || set.snapshot.policy_epoch != current.policy_epoch
            || set.snapshot.destructive_epoch != current.destructive_epoch
        {
            return Err(inconsistent());
        }
        for candidate in set.candidates.iter().skip(offset) {
            self.check_deadline()?;
            if candidate.evidence.is_empty() {
                return Err(inconsistent());
            }
            for proof in &candidate.evidence {
                self.validate_revision(&proof.proof.revision)?;
                if proof
                    .proof
                    .revision
                    .committed_generation
                    .is_none_or(|g| g > set.snapshot.generation)
                {
                    return Err(inconsistent());
                }
                if let Some(o) = &proof.occurrence {
                    self.validate_revision(&o.revision)?;
                    if o.source_id != proof.proof.source_id
                        || o.data.placement.message_id.as_str() != proof.entity_id.as_str()
                    {
                        return Err(inconsistent());
                    }
                }
                for related in &proof.related {
                    self.validate_revision(&related.revision)?;
                }
            }
        }
        match request {
            AppRequest::Search {
                query,
                filters,
                facets,
                limit,
                cursor: _,
                budget,
                include_system,
                group_by_session: _,
                mode,
                query_embedding: _,
            } => {
                crate::validate_search_request(&query, &filters, limit, &budget)?;
                let predicates = intersect(
                    &self.context.intersection,
                    &ProjectionQuery {
                        filters,
                        facets,
                        include_system,
                        session_id: None,
                    },
                )?;
                for candidate in set.candidates.iter().skip(offset) {
                    let predicates = predicates.as_ref().ok_or_else(inconsistent)?;
                    match &candidate.entry {
                        ProjectionListEntry::Message(p) => validate_message(p, predicates)?,
                        ProjectionListEntry::Entity(p) => validate_session_metadata(p, predicates)?,
                    }
                }
                self.render_search(
                    set,
                    offset,
                    limit,
                    &intersect_budget(&self.context.budget, &budget),
                    mode,
                )
            }
            AppRequest::List {
                limit,
                cursor: _,
                budget,
                sessions_only,
            } => {
                if limit == 0 {
                    return Err(invalid());
                }
                budget.validate()?;
                self.render_list(
                    set,
                    offset,
                    limit,
                    &intersect_budget(&self.context.budget, &budget),
                    sessions_only,
                )
            }
            _ => Err(invalid()),
        }
    }

    pub fn prepare_handoff(
        &self,
        request: ManagedHandoffRequest,
    ) -> Result<ManagedHandoffInput<'a>, AppError> {
        self.check_deadline()?;
        crate::validate_search_request(
            &request.query,
            &request.intersection.filters,
            request.limit,
            &request.budget,
        )?;
        if request.max_tokens == 0
            || request.max_evidence == 0
            || request.max_bytes < budget::MIN_RESPONSE_BYTES as u64
            || request.query.chars().count() > 256
            || request.target.as_ref().is_some_and(|target| {
                target.provider_id.is_empty()
                    || target.provider_id.chars().count() > 64
                    || target
                        .agent
                        .as_ref()
                        .is_some_and(|v| v.chars().count() > 128)
            })
        {
            return Err(invalid());
        }
        let query = intersect(&self.context.intersection, &request.intersection)?;
        let mut budget = intersect_budget(&self.context.budget, &request.budget);
        budget.max_response_bytes = budget
            .max_response_bytes
            .min(usize::try_from(request.max_bytes).unwrap_or(usize::MAX));
        budget.max_evidence_spans = budget
            .max_evidence_spans
            .min(request.max_evidence)
            .min(budget.max_messages);
        let limit = request
            .limit
            .min(budget.max_items)
            .min(budget.max_evidence_spans)
            .min(500);
        // Packs require original message occurrences. Metadata hits are
        // navigation results and must never be promoted into message evidence.
        let candidates =
            self.collect_search(&request.query, query.as_ref(), &budget, false, request.mode)?;
        let response = self.render_search(&candidates, 0, limit, &budget, request.mode)?;
        let AppResponse::Search {
            hits,
            retrieval_mode,
            ..
        } = response.response
        else {
            return Err(inconsistent());
        };
        if hits.len() != response.evidence.len() {
            return Err(inconsistent());
        }
        let mut partial = response.partial;
        // Handoff never suggests native resume or uses resume metadata.
        partial.retain(|p| *p != ManagedPartial::ResumeAvailabilityUnavailable);
        let mut input = ManagedHandoffInput {
            snapshot: response.snapshot,
            evidence: Vec::new(),
            partial,
            intersection: query.clone(),
            hits: Vec::new(),
            locations: Vec::new(),
            facts: Vec::new(),
            tools: Vec::new(),
            tool_values: Vec::new(),
            terms: vec![request.query],
            filters: handoff_filters(query.as_ref()),
            mode: retrieval_mode,
            target: request.target,
            max_tokens: request.max_tokens,
            max_bytes: net_bytes(&budget),
            max_evidence: limit,
            metadata_redactions: 0,
            deadline_expired: self.context.deadline_expired,
        };
        for term in &mut input.terms {
            input.metadata_redactions += redact_handoff_text(term);
        }
        if let Some(target) = &mut input.target {
            for value in std::iter::once(&mut target.provider_id)
                .chain(target.agent.iter_mut())
                .chain(target.suggested_command.iter_mut())
            {
                if value.len() > 4096 || value.chars().any(char::is_control) {
                    return Err(invalid());
                }
                input.metadata_redactions += redact_handoff_text(value);
            }
        }
        // Cache only the selected facts, never a collection of full session
        // graphs. Repeated sessions reuse one bounded graph observation.
        let mut pending = BTreeMap::<String, Vec<(SearchHit, ManagedEvidence)>>::new();
        let order: Vec<_> = hits.iter().map(|h| h.id.as_str().to_owned()).collect();
        for (hit, proof) in hits.into_iter().zip(response.evidence) {
            if hit.id != proof.entity_id {
                return Err(inconsistent());
            }
            self.validate_revision(&proof.proof.revision)?;
            let occurrence = proof.occurrence.as_ref().ok_or_else(inconsistent)?;
            self.validate_revision(&occurrence.revision)?;
            validate_occurrence(occurrence, query.as_ref().ok_or_else(inconsistent)?)?;
            if occurrence.source_id != proof.proof.source_id
                || hit.session_id.as_deref() != Some(occurrence.data.placement.session_id.as_str())
            {
                return Err(inconsistent());
            }
            pending
                .entry(occurrence.data.placement.session_id.as_str().into())
                .or_default()
                .push((hit, proof));
        }
        let mut remaining = net_bytes(&budget);
        let mut remaining_tools = 500;
        let mut assembled = BTreeMap::new();
        for (session, entries) in pending {
            self.check_deadline()?;
            let mut scoped = query.clone().ok_or_else(inconsistent)?;
            // Keep the actual typed identity: a wire round-trip intentionally
            // loses its stability tier and is not structurally equal to it.
            let session_id = entries
                .first()
                .and_then(|(_, p)| p.occurrence.as_ref())
                .map(|o| o.data.placement.session_id.clone())
                .ok_or_else(inconsistent)?;
            if session_id.as_str() != session {
                return Err(inconsistent());
            }
            scoped.session_id = Some(session_id.clone());
            let graph = match self.read.session_graph(
                &session_id,
                &scoped,
                GraphReadLimits {
                    max_occurrences: GraphReadLimits::default().max_occurrences,
                    max_bytes: budget
                        .max_response_bytes
                        .min(GraphReadLimits::default().max_bytes),
                },
            ) {
                Ok(graph) => Some(graph),
                Err(PortError::WriterBusy(_) | PortError::NotFound(_)) => {
                    self.check_deadline()?;
                    input
                        .partial
                        .push(ManagedPartial::HandoffEnrichmentUnavailable);
                    None
                }
                Err(error) => return Err(error.into()),
            };
            self.check_deadline()?;
            if graph.as_ref().is_some_and(
                |g| !matches!(&g.session.data,EntityData::Session(s) if s.session.id==session_id),
            ) {
                return Err(inconsistent());
            }
            for (hit, mut proof) in entries {
                self.check_deadline()?;
                let o = proof.occurrence.as_ref().ok_or_else(inconsistent)?;
                let p = &o.data.placement;
                let matches: Vec<_> = graph
                    .iter()
                    .flat_map(|g| &g.occurrences)
                    .filter(|r| {
                        r.message
                            .occurrence
                            .as_ref()
                            .is_some_and(|candidate| candidate.data.placement.id == p.id)
                            && r.message.proof.source_id == proof.proof.source_id
                    })
                    .collect();
                if matches.len() > 1 {
                    return Err(inconsistent());
                }
                let mut tools = Vec::new();
                let mut activities = BTreeMap::new();
                let mut conflicts = BTreeSet::new();
                if let Some(record) = matches.first() {
                    validate_message(&record.message, &scoped)?;
                    if record.message.proof != proof.proof
                        || record.message.occurrence.as_ref() != Some(o)
                        || record.document.id != p.source_document_id
                        || record.document.provider_id != o.data.provider_id
                        || record.document_proof.source_id != proof.proof.source_id
                        || p.span
                            .as_ref()
                            .is_some_and(|s| s.end > record.document.len || s.start > s.end)
                        || hit
                            .text
                            .as_ref()
                            .is_some_and(|text| !record.message.message.text.contains(text))
                    {
                        return Err(inconsistent());
                    }
                    self.validate_revision(&record.document_proof.revision)?;
                    record.document.validate().map_err(|_| inconsistent())?;
                    proof.related.push(record.document_proof.clone());
                    if hit
                        .text
                        .as_ref()
                        .is_some_and(|text| text.len() < record.message.message.text.len())
                    {
                        input.partial.push(ManagedPartial::ResponseBudget);
                    }
                    for tool in &record.tools {
                        self.check_deadline()?;
                        let EntityData::Tool {
                            activity_id,
                            message_id,
                            activity,
                            ..
                        } = &tool.data
                        else {
                            return Err(inconsistent());
                        };
                        self.validate_revision(&tool.proof.revision)?;
                        if *message_id != hit.id || tool.proof.source_id != proof.proof.source_id {
                            return Err(inconsistent());
                        }
                        activity.validate().map_err(|_| inconsistent())?;
                        if conflicts.contains(activity_id) {
                            continue;
                        }
                        if let Some(prior) = activities.insert(activity_id.clone(), tool)
                            && prior.data != tool.data
                        {
                            activities.remove(activity_id);
                            conflicts.insert(activity_id.clone());
                            input
                                .partial
                                .push(ManagedPartial::HandoffEnrichmentUnavailable);
                        }
                    }
                    for tool in activities.into_values() {
                        self.check_deadline()?;
                        let EntityData::Tool { activity, .. } = &tool.data else {
                            return Err(inconsistent());
                        };
                        if scoped
                            .facets
                            .tool_kind
                            .as_ref()
                            .is_some_and(|kind| kind != activity.kind.as_str())
                            || scoped
                                .facets
                                .tool_name
                                .as_ref()
                                .is_some_and(|name| name != &activity.name)
                        {
                            continue;
                        }
                        let mut value = tool_value(tool)?;
                        let mut redacted = false;
                        for field in ["name", "target"] {
                            if let Some(serde_json::Value::String(value)) = value.get_mut(field) {
                                redacted |= redact_handoff_text(value) > 0;
                            }
                        }
                        // Activity identifiers may be adapter-private. The
                        // evidence proof retains identity without exposing it.
                        value
                            .as_object_mut()
                            .ok_or_else(inconsistent)?
                            .remove("activity_id");
                        let cost = bytes(&value)?.len().saturating_add(1024);
                        if cost > remaining || remaining_tools == 0 {
                            input.partial.extend([
                                ManagedPartial::ResponseBudget,
                                ManagedPartial::HandoffEnrichmentUnavailable,
                            ]);
                            break;
                        }
                        remaining -= cost;
                        remaining_tools -= 1;
                        proof.related.push(tool.proof.clone());
                        tools.push(HandoffTool {
                            message_id: hit.id.as_str().into(),
                            value,
                            redacted,
                        });
                    }
                } else {
                    // The graph can legitimately select another permitted copy
                    // of this placement. Retain the actual search proof/text and
                    // omit enrichment; never borrow that other copy's fields.
                    input
                        .partial
                        .push(ManagedPartial::HandoffEnrichmentUnavailable);
                }
                let location = SourceLocationInfo {
                    message_id: hit.id.as_str().into(),
                    source_document_id: Some(p.source_document_id.clone()),
                    byte_start: p.span.as_ref().map(|s| s.start),
                    byte_end: p.span.as_ref().map(|s| s.end),
                };
                let fact = MessageFact {
                    message_id: hit.id.as_str().into(),
                    role: crate::role_name(o.data.role).into(),
                    is_sidechain: p.is_sidechain,
                };
                assembled.insert(
                    hit.id.as_str().to_owned(),
                    (hit, proof, location, fact, tools),
                );
            }
        }
        for id in order {
            let (hit, proof, location, fact, tools) =
                assembled.remove(&id).ok_or_else(inconsistent)?;
            input.hits.push(hit);
            input.evidence.push(proof);
            input.locations.push(location);
            input.facts.push(fact);
            input.tools.extend(tools);
        }
        input.tool_values = input.tools.iter().map(|t| t.value.clone()).collect();
        self.check_deadline()?;
        Ok(input)
    }

    fn search(
        &self,
        text: &str,
        query: Option<&ProjectionQuery>,
        limit: usize,
        budget: &ResponseBudget,
        group: bool,
        mode: RetrievalMode,
    ) -> Result<ManagedResponse, AppError> {
        let set = self.collect_search_with_metadata(text, query, budget, group, mode)?;
        self.render_search(&set, 0, limit, budget, mode)
    }

    fn collect_search_with_metadata(
        &self,
        text: &str,
        query: Option<&ProjectionQuery>,
        budget: &ResponseBudget,
        group: bool,
        mode: RetrievalMode,
    ) -> Result<ManagedCandidateSet, AppError> {
        let mut set = self.collect_search(text, query, budget, group, mode)?;
        set.partial
            .retain(|p| *p != ManagedPartial::MetadataSearchUnavailable);
        let Some(query) = query else { return Ok(set) };
        self.check_deadline()?;
        let page = self.read.query_session_metadata(text, query, 512)?;
        if page.hits.len() > 512 {
            return Err(inconsistent());
        }
        if page.incomplete {
            set.partial.push(ManagedPartial::MetadataSearchUnavailable);
        }
        let message_sessions: BTreeSet<_> = set
            .candidates
            .iter()
            .filter_map(|c| c.hit.as_ref()?.session_id.clone())
            .collect();
        let mut unique = BTreeSet::new();
        for (rank, candidate) in page.hits.into_iter().enumerate() {
            self.check_deadline()?;
            let p = candidate.projection;
            validate_session_metadata(&p, query)?;
            self.validate_revision(&p.proof.revision)?;
            let EntityData::Session(session) = &p.data else {
                return Err(inconsistent());
            };
            if !candidate.score.is_finite()
                || candidate.score <= 0.0
                || !unique.insert(session.session.id.as_str().to_owned())
            {
                return Err(inconsistent());
            }
            // A metadata match is not another message occurrence in a group.
            if group && message_sessions.contains(session.session.id.as_str()) {
                continue;
            }
            let hit = SearchHit {
                id: session.session.id.clone(),
                score: ranking::final_score(
                    1.0 / (61.0 + rank as f32),
                    0,
                    false,
                    self.context
                        .current_repo
                        .as_ref()
                        .is_some_and(|r| session.repo_slug.as_ref() == Some(r)),
                ),
                session_id: Some(session.session.id.as_str().to_owned()),
                text: None,
                why_matched: std::iter::once("session_metadata".to_owned())
                    .chain(candidate.fields.iter().map(|f| f.as_str().to_owned()))
                    .collect(),
                suggested_next_commands: Vec::new(),
                occurrences: 1,
                resume_available: false,
            };
            let proof = ManagedEvidence {
                entity_id: hit.id.clone(),
                proof: p.proof.clone(),
                occurrence: None,
                related: Vec::new(),
            };
            set.candidates.push(ManagedCandidate {
                entry: ProjectionListEntry::Entity(Box::new(p)),
                hit: Some(hit),
                evidence: vec![proof],
                peek: None,
                title: None,
            });
        }
        set.candidates.sort_by(|a, b| {
            b.hit
                .as_ref()
                .expect("search hit")
                .score
                .total_cmp(&a.hit.as_ref().expect("search hit").score)
                .then_with(|| a.entry.id().as_str().cmp(b.entry.id().as_str()))
        });
        set.truncated |= page.truncated || set.candidates.len() > 512;
        set.candidates.truncate(512);
        if set.truncated && !set.partial.contains(&ManagedPartial::RankingWindow) {
            set.partial.push(ManagedPartial::RankingWindow);
        }
        self.check_deadline()?;
        Ok(set)
    }

    fn collect_search(
        &self,
        text: &str,
        query: Option<&ProjectionQuery>,
        budget: &ResponseBudget,
        group: bool,
        mode: RetrievalMode,
    ) -> Result<ManagedCandidateSet, AppError> {
        let mut partial = vec![
            ManagedPartial::MetadataSearchUnavailable,
            ManagedPartial::ResumeAvailabilityUnavailable,
        ];
        if mode != RetrievalMode::Lexical {
            partial.push(ManagedPartial::SemanticUnavailable);
        }
        let page = match query {
            Some(query) => self.read.query_lexical(text, query, 512)?,
            None => LexicalPage {
                hits: Vec::new(),
                truncated: false,
            },
        };
        if page.hits.len() > 512 {
            return Err(inconsistent());
        }
        if page.truncated {
            partial.push(ManagedPartial::RankingWindow);
        }
        let terms = guidance::literal_terms(text);
        let mut ranked = Vec::new();
        let mut unique = BTreeSet::new();
        for (rank, candidate) in page.hits.into_iter().enumerate() {
            self.check_deadline()?;
            let p = candidate.projection;
            if !candidate.score.is_finite()
                || candidate.score <= 0.0
                || !unique.insert(p.message.id.as_str().to_owned())
            {
                return Err(inconsistent());
            }
            validate_message(&p, query.ok_or_else(inconsistent)?)?;
            let occurrence = p.occurrence.as_ref().ok_or_else(inconsistent)?;
            let time = occurrence
                .data
                .timestamp
                .as_deref()
                .and_then(crate::parse_search_instant)
                .and_then(|t| {
                    t.unix_seconds
                        .checked_mul(1000)?
                        .checked_add(i64::from(t.nanosecond / 1_000_000))
                });
            let age = time.map_or(0, |t| self.context.now_ms.saturating_sub(t));
            let in_repo = self
                .context
                .current_repo
                .as_ref()
                .is_some_and(|repo| occurrence.data.project_id.as_ref() == Some(repo));
            let mut hit = SearchHit {
                id: p.message.id.clone(),
                score: ranking::final_score(
                    1.0 / (61.0 + rank as f32),
                    age,
                    occurrence.data.placement.is_sidechain,
                    in_repo,
                ),
                session_id: Some(occurrence.data.placement.session_id.as_str().into()),
                text: None,
                why_matched: Vec::new(),
                suggested_next_commands: Vec::new(),
                occurrences: 1,
                resume_available: false,
            };
            // Exactly the matched source projection: never call messages(id) to
            // replace it after ranking, grouping or metadata enrichment.
            hit.text = snippet::build(Some(&p.message.text), &terms, budget.max_snippet_chars);
            hit.why_matched = guidance::why_matched(
                &terms,
                Some(&p.message.text),
                None,
                None,
                hit.text.as_deref(),
            );
            // The shared guidance currently suggests get_message/context, which
            // this bounded bridge explicitly does not implement yet.
            let proof = ManagedEvidence {
                entity_id: p.message.id.clone(),
                proof: p.proof.clone(),
                occurrence: p.occurrence.clone(),
                related: Vec::new(),
            };
            ranked.push(ManagedCandidate {
                entry: ProjectionListEntry::Message(Box::new(p)),
                hit: Some(hit),
                evidence: vec![proof],
                peek: None,
                title: None,
            });
        }
        ranked.sort_by(|a, b| {
            b.hit
                .as_ref()
                .expect("search hit")
                .score
                .total_cmp(&a.hit.as_ref().expect("search hit").score)
                .then_with(|| a.entry.id().as_str().cmp(b.entry.id().as_str()))
        });
        if group {
            let mut grouped = Vec::<ManagedCandidate>::new();
            let mut keys = BTreeMap::new();
            for candidate in ranked {
                let key = candidate
                    .hit
                    .as_ref()
                    .ok_or_else(inconsistent)?
                    .session_id
                    .clone()
                    .ok_or_else(inconsistent)?;
                if let Some(index) = keys.get(&key).copied() {
                    let item: &mut ManagedCandidate = &mut grouped[index];
                    item.hit.as_mut().ok_or_else(inconsistent)?.occurrences += 1;
                } else {
                    keys.insert(key, grouped.len());
                    grouped.push(candidate);
                }
            }
            ranked = grouped;
        }
        self.check_deadline()?;
        Ok(ManagedCandidateSet {
            candidates: ranked,
            snapshot: self.read.snapshot().clone(),
            request_now_ms: self.context.now_ms,
            partial,
            truncated: page.truncated,
        })
    }

    fn render_search(
        &self,
        set: &ManagedCandidateSet,
        offset: usize,
        limit: usize,
        budget: &ResponseBudget,
        mode: RetrievalMode,
    ) -> Result<ManagedResponse, AppError> {
        let mut ranked = Vec::new();
        for candidate in set.candidates.iter().skip(offset) {
            self.check_deadline()?;
            let mut hit = candidate.hit.clone().ok_or_else(inconsistent)?;
            if hit.id.as_str() != candidate.entry.id().as_str()
                || !hit.score.is_finite()
                || candidate.evidence.is_empty()
            {
                return Err(inconsistent());
            }
            if let Some(text) = &mut hit.text {
                *text = text.chars().take(budget.max_snippet_chars).collect();
            }
            ranked.push((hit, candidate.evidence.clone()));
        }
        let mut partial = set.partial.clone();
        let (kept, mut truncation, _) = budget::clamp_items(
            ranked,
            limit.min(budget.max_items).min(budget.max_evidence_spans),
            net_bytes(budget),
            |(hit, proofs)| {
                crate::search_hit_charge(hit)
                    .saturating_add(proofs.iter().map(proof_charge).sum::<usize>())
            },
        );
        if truncation.truncated {
            if budget.max_evidence_spans < limit.min(budget.max_items)
                && truncation.reason.as_deref() == Some(budget::TRUNCATION_MAX_ITEMS)
            {
                truncation.reason = Some(budget::TRUNCATION_MAX_EVIDENCE_SPANS.into());
            }
            partial.extend([
                ManagedPartial::ResponseBudget,
                ManagedPartial::ContinuationUnavailable,
            ]);
        }
        if set.truncated {
            truncation.truncated = true;
            truncation
                .reason
                .get_or_insert_with(|| "ranking_window".into());
            partial.push(ManagedPartial::ContinuationUnavailable);
        }
        let (hits, evidence): (Vec<_>, Vec<Vec<_>>) = kept.into_iter().unzip();
        let mode = if mode == RetrievalMode::Lexical {
            mode
        } else {
            RetrievalMode::LexicalFallback
        };
        let mut response = self.finish(
            AppResponse::Search {
                hits,
                next_cursor: None,
                generation: set.snapshot.generation as u64,
                truncation,
                retrieval_mode: mode,
                fallback_warning: (mode == RetrievalMode::LexicalFallback)
                    .then(|| "managed semantic search unavailable; lexical evidence only".into()),
            },
            evidence.into_iter().flatten().collect(),
            partial,
        )?;
        response.snapshot = set.snapshot.clone();
        Ok(response)
    }

    fn get(&self, id: StableId, show: bool) -> Result<ManagedResponse, AppError> {
        let query = &self.context.intersection;
        let entry = match id.kind() {
            IdKind::Message => self
                .read
                .messages(std::slice::from_ref(&id), query)?
                .into_iter()
                .next()
                .flatten()
                .map(|p| ProjectionListEntry::Message(Box::new(p))),
            IdKind::Session | IdKind::Document => self
                .read
                .entities(
                    if id.kind() == IdKind::Session {
                        EntityKind::Session
                    } else {
                        EntityKind::Document
                    },
                    std::slice::from_ref(&id),
                    query,
                )?
                .into_iter()
                .next()
                .map(|p| ProjectionListEntry::Entity(Box::new(p))),
            IdKind::Source => return Err(invalid()),
        };
        let mut evidence = Vec::new();
        let mut partial = Vec::new();
        let payload = if let Some(entry) = entry {
            if entry.id().as_str() != id.as_str() {
                return Err(inconsistent());
            }
            let (mut payload, proof, _) = project_entry(&entry, query)?;
            let available = net_bytes(&self.context.budget).saturating_sub(proof_charge(&proof));
            if crate::lossy_payload_json_len(&payload).saturating_add(48) > available {
                match &entry {
                    ProjectionListEntry::Message(p) => {
                        payload = fit_message_payload(p, available, self.context.deadline_expired)?;
                        partial.push(ManagedPartial::ResponseBudget);
                    }
                    ProjectionListEntry::Entity(_) => {
                        return Err(budget::BudgetError::TooSmall(
                            "max_response_bytes cannot fit the managed entity".into(),
                        )
                        .into());
                    }
                }
            }
            evidence.push(proof);
            Some(payload)
        } else {
            None
        };
        self.finish(
            if show {
                AppResponse::Show { payload }
            } else {
                AppResponse::Get { payload }
            },
            evidence,
            partial,
        )
    }

    fn list(
        &self,
        limit: usize,
        budget: &ResponseBudget,
        sessions_only: bool,
    ) -> Result<ManagedResponse, AppError> {
        let set = self.collect_list(limit, budget, sessions_only)?;
        self.render_list(&set, 0, limit, budget, sessions_only)
    }

    fn collect_list(
        &self,
        limit: usize,
        budget: &ResponseBudget,
        sessions_only: bool,
    ) -> Result<ManagedCandidateSet, AppError> {
        let take = limit.min(budget.max_items).min(512);
        let page = self
            .read
            .list(&self.context.intersection, sessions_only, take)?;
        if page.entries.len() > take {
            return Err(inconsistent());
        }
        let requests = if sessions_only {
            page.entries
                .iter()
                .map(|entry| {
                    let ProjectionListEntry::Entity(p) = entry else {
                        return Err(inconsistent());
                    };
                    let EntityData::Session(s) = &p.data else {
                        return Err(inconsistent());
                    };
                    Ok(SessionPreviewRequest {
                        session_id: s.session.id.clone(),
                        source_id: p.proof.source_id.clone(),
                    })
                })
                .collect::<Result<Vec<_>, AppError>>()?
        } else {
            Vec::new()
        };
        let previews = if requests.is_empty() {
            Vec::new()
        } else {
            match self.read.session_previews(
                &requests,
                &self.context.intersection,
                net_bytes(budget).min(64 * 1024 * 1024),
            ) {
                Ok(previews) => previews,
                Err(PortError::WriterBusy(_)) => {
                    self.check_deadline()?;
                    requests
                        .iter()
                        .map(|r| SessionPreview {
                            request: r.clone(),
                            first_user: None,
                            last_user: None,
                            unavailable: true,
                        })
                        .collect()
                }
                Err(error) => return Err(error.into()),
            }
        };
        if previews.len() != requests.len() {
            return Err(inconsistent());
        }
        let mut projected = Vec::new();
        let mut previous = None;
        let mut partial = Vec::new();
        for (index, entry) in page.entries.into_iter().enumerate() {
            self.check_deadline()?;
            let id = entry.id().clone();
            if previous
                .as_ref()
                .is_some_and(|p: &String| p.as_str() >= id.as_str())
                || (sessions_only && id.kind() != IdKind::Session)
            {
                return Err(inconsistent());
            }
            previous = Some(id.as_str().to_owned());
            let (_, proof, title) = project_entry(&entry, &self.context.intersection)?;
            self.validate_revision(&proof.proof.revision)?;
            let mut proofs = vec![proof];
            let (peek, unavailable) = if let Some(preview) = previews.get(index) {
                if preview.request != requests[index] {
                    return Err(inconsistent());
                }
                let unavailable = preview.unavailable;
                let mut payloads = Vec::new();
                let mut included = [false, false];
                let mut seen = BTreeSet::new();
                for (slot, message) in [preview.first_user.as_ref(), preview.last_user.as_ref()]
                    .into_iter()
                    .enumerate()
                {
                    let Some(message) = message else { continue };
                    self.validate_revision(&message.proof.revision)?;
                    self.validate_revision(&message.occurrence.revision)?;
                    validate_occurrence(&message.occurrence, &self.context.intersection)?;
                    if message.proof.source_id != preview.request.source_id
                        || message.occurrence.source_id != preview.request.source_id
                        || message.occurrence.data.placement.session_id.as_str() != id.as_str()
                        || message.occurrence.data.role != agent_session_grep_domain::Role::User
                    {
                        return Err(inconsistent());
                    }
                    let unique = seen.insert(message.occurrence.data.placement.id.as_str());
                    let text: String = message
                        .text
                        .chars()
                        .take(
                            budget
                                .max_snippet_chars
                                .min(crate::peek::PEEK_FIELD_MAX_CHARS),
                        )
                        .collect();
                    payloads.push(bytes(&serde_json::json!({"role":"user","text":text}))?);
                    included[slot] = true;
                    if unique {
                        proofs.push(ManagedEvidence {
                            entity_id: message.occurrence.data.placement.message_id.clone(),
                            proof: message.proof.clone(),
                            occurrence: Some(message.occurrence.clone()),
                            related: Vec::new(),
                        });
                    }
                }
                let mut peek =
                    crate::peek::build_session_peek(payloads.iter().map(|p| Some(p.as_slice())));
                if !included[0] {
                    peek.first_user_text = None;
                }
                if !included[1] {
                    peek.last_user_text = None;
                }
                (Some(peek), unavailable)
            } else {
                (None, false)
            };
            if unavailable {
                partial.push(ManagedPartial::ListPreviewUnavailable);
            }
            projected.push(ManagedCandidate {
                entry,
                hit: None,
                evidence: proofs,
                title,
                peek,
            });
        }
        Ok(ManagedCandidateSet {
            candidates: projected,
            snapshot: self.read.snapshot().clone(),
            request_now_ms: self.context.now_ms,
            partial,
            truncated: page.truncated,
        })
    }

    fn render_list(
        &self,
        set: &ManagedCandidateSet,
        offset: usize,
        limit: usize,
        budget: &ResponseBudget,
        sessions_only: bool,
    ) -> Result<ManagedResponse, AppError> {
        let take = limit
            .min(budget.max_items)
            .min(budget.max_evidence_spans)
            .min(512);
        let mut partial = set.partial.clone();
        let mut projected = Vec::new();
        let mut spans = budget.max_evidence_spans;
        for candidate in set
            .candidates
            .iter()
            .skip(offset)
            .take(take.saturating_add(1))
        {
            self.check_deadline()?;
            if candidate.hit.is_some()
                || (sessions_only && candidate.entry.id().kind() != IdKind::Session)
            {
                return Err(inconsistent());
            }
            let (payload, _, _) = project_entry(&candidate.entry, &self.context.intersection)?;
            let mut proofs = candidate.evidence.clone();
            let mut peek = candidate.peek.clone();
            let needed = proofs.iter().filter(|p| p.occurrence.is_some()).count();
            if needed > spans {
                let mut left = spans;
                proofs.retain(|p| {
                    if p.occurrence.is_none() {
                        true
                    } else if left > 0 {
                        left -= 1;
                        true
                    } else {
                        false
                    }
                });
                if let Some(peek) = &mut peek {
                    if spans == 0 {
                        peek.first_user_text = None;
                        peek.last_user_text = None;
                    } else if needed > 1 {
                        peek.last_user_text = None;
                    }
                }
                partial.push(ManagedPartial::ListPreviewUnavailable);
            }
            spans = spans.saturating_sub(needed);
            if let Some(peek) = &mut peek {
                for value in [&mut peek.first_user_text, &mut peek.last_user_text]
                    .into_iter()
                    .flatten()
                {
                    *value = value.chars().take(budget.max_snippet_chars).collect();
                }
            }
            projected.push((
                CatalogEntry {
                    id: candidate.entry.id().clone(),
                    payload,
                },
                proofs,
                candidate.title.clone(),
                peek,
            ));
        }
        let (kept, mut truncation, _) = budget::clamp_items(
            projected,
            take,
            net_bytes(budget),
            |(entry, proofs, title, peek)| {
                crate::json_string_len(entry.id.as_str())
                    + crate::lossy_payload_json_len(&entry.payload)
                    + proofs.iter().map(proof_charge).sum::<usize>()
                    + title.as_ref().map_or(4, |s| crate::json_string_len(s))
                    + peek
                        .as_ref()
                        .map_or(0, |p| p.json_len() + crate::peek::PEEK_ENTRY_OVERHEAD_BYTES)
                    + 64
            },
        );
        if truncation.truncated {
            partial.push(ManagedPartial::ResponseBudget);
            if budget.max_evidence_spans < limit.min(budget.max_items)
                && truncation.reason.as_deref() == Some(budget::TRUNCATION_MAX_ITEMS)
            {
                truncation.reason = Some(budget::TRUNCATION_MAX_EVIDENCE_SPANS.into());
            }
        }
        if set.truncated || set.candidates.len().saturating_sub(offset) > take {
            truncation.truncated = true;
            truncation.reason.get_or_insert_with(|| {
                if budget.max_evidence_spans < limit.min(budget.max_items) {
                    budget::TRUNCATION_MAX_EVIDENCE_SPANS.into()
                } else {
                    budget::TRUNCATION_MAX_ITEMS.into()
                }
            });
        }
        if truncation.truncated {
            partial.push(ManagedPartial::ContinuationUnavailable);
        }
        let mut entries = Vec::new();
        let mut evidence = Vec::new();
        let mut titles = Vec::new();
        let mut peeks = Vec::new();
        for (entry, proofs, title, peek) in kept {
            entries.push(entry);
            evidence.extend(proofs);
            titles.push(if sessions_only { title } else { None });
            peeks.push(peek);
        }
        let mut response = self.finish(
            AppResponse::List {
                entries,
                peeks,
                titles,
                next_cursor: None,
                generation: set.snapshot.generation as u64,
                truncation,
            },
            evidence,
            partial,
        )?;
        response.snapshot = set.snapshot.clone();
        Ok(response)
    }

    fn status(&self) -> Result<ManagedResponse, AppError> {
        let budget = &self.context.budget;
        let stats = self
            .read
            .stats(&self.context.intersection, budget.max_items.min(512))?;
        let mut partial = Vec::new();
        if stats.facts_incomplete {
            partial.push(ManagedPartial::AggregateFactsUnavailable);
        }
        let (repos, truncation, _) = budget::clamp_items(
            stats.repos,
            budget.max_items,
            net_bytes(budget).saturating_sub(512),
            |r| crate::json_string_len(&r.repo_slug) + 64,
        );
        if truncation.truncated || stats.repos_truncated {
            partial.push(ManagedPartial::ResponseBudget);
        }
        self.finish(
            AppResponse::Status {
                catalog_count: stats.catalog_count,
                active_generation: self.generation(),
                placements: stats.placements,
                source_placement_claims: stats.source_placement_claims,
                usage: stats.usage,
                repos,
            },
            Vec::new(),
            partial,
        )
    }

    fn resume(&self, session_id: StableId) -> Result<ManagedResponse, AppError> {
        if session_id.kind() != IdKind::Session {
            return Err(invalid());
        }
        let query = &self.context.intersection;
        if self
            .read
            .entities(
                EntityKind::Session,
                std::slice::from_ref(&session_id),
                query,
            )?
            .is_empty()
        {
            return Err(PortError::NotFound("managed session not found".into()).into());
        }
        let claims =
            self.read
                .entities(EntityKind::Resume, std::slice::from_ref(&session_id), query)?;
        let mut metadata = SessionResumeMetadata {
            session_id: session_id.clone(),
            provider_id: None,
            resume_available: false,
            provider_session_id: None,
            original_working_directory: None,
            unavailable_reason: Some("no unambiguous permitted resume claim".into()),
        };
        let mut evidence = Vec::new();
        if let Some(first) = claims.first() {
            if claims.iter().any(|c| c.data != first.data) {
                return Err(inconsistent());
            }
            let EntityData::Resume(data) = &first.data else {
                return Err(inconsistent());
            };
            if data.session_id != session_id {
                return Err(inconsistent());
            }
            metadata.provider_id = Some(data.provider_id.clone());
            if let ResumeValue::Resolved(native) = &data.provider_session_id {
                metadata.provider_session_id = Some(native.clone());
                metadata.resume_available = true;
                metadata.unavailable_reason = None;
                if data.pair_observed
                    && let ResumeValue::Resolved(cwd) = &data.original_working_directory
                {
                    metadata.original_working_directory = Some(cwd.clone());
                }
            }
            evidence.push(ManagedEvidence {
                entity_id: session_id,
                proof: first.proof.clone(),
                occurrence: None,
                related: Vec::new(),
            });
        }
        let size=bytes(&serde_json::json!({"session_id":metadata.session_id.as_str(),"provider_id":metadata.provider_id,"resume_available":metadata.resume_available,"provider_session_id":metadata.provider_session_id,"original_working_directory":metadata.original_working_directory,"unavailable_reason":metadata.unavailable_reason}))?.len();
        if size.saturating_add(evidence.iter().map(proof_charge).sum::<usize>())
            > net_bytes(&self.context.budget)
        {
            return Err(budget::BudgetError::TooSmall(
                "max_response_bytes cannot fit resume metadata".into(),
            )
            .into());
        }
        self.finish(AppResponse::SessionResume(metadata), evidence, Vec::new())
    }

    fn scoped_session(&self, id: &StableId) -> Result<ProjectionQuery, AppError> {
        if id.kind() != IdKind::Session || !id.validate() {
            return Err(invalid());
        }
        let mut query = self.context.intersection.clone();
        if query.session_id.as_ref().is_some_and(|other| other != id) {
            return Err(context_not_found());
        }
        query.session_id = Some(id.clone());
        Ok(query)
    }
    fn load_graph(&self, id: &StableId, query: &ProjectionQuery) -> Result<LoadedGraph, AppError> {
        self.check_deadline()?;
        let projection = self
            .read
            .session_graph(id, query, GraphReadLimits::default())?;
        let EntityData::Session(session) = &projection.session.data else {
            return Err(inconsistent());
        };
        if session.session.id != *id || !projection.session.proof.revision.published {
            return Err(inconsistent());
        }
        self.validate_revision(&projection.session.proof.revision)?;
        let mut graph = SessionContextGraph {
            session_id: id.clone(),
            messages: Vec::new(),
            source_documents: Vec::new(),
            placements: Vec::new(),
            edges: Vec::new(),
        };
        let mut messages = BTreeMap::<String, Message>::new();
        let mut documents = BTreeMap::new();
        let mut records = BTreeMap::new();
        for record in projection.occurrences {
            self.check_deadline()?;
            validate_message(&record.message, query)?;
            let occurrence = record
                .message
                .occurrence
                .as_ref()
                .ok_or_else(inconsistent)?;
            let p = &occurrence.data.placement;
            let source = &record.message.proof.source_id;
            self.validate_revision(&record.message.proof.revision)?;
            self.validate_revision(&occurrence.revision)?;
            self.validate_revision(&record.document_proof.revision)?;
            if p.session_id != *id
                || p.source_document_id != record.document.id
                || *source != record.document_proof.source_id
                || !record.document_proof.revision.published
                || record.document.provider_id != occurrence.data.provider_id
            {
                return Err(inconsistent());
            }
            if let Some(prior) = documents.insert(
                record.document.id.as_str().to_owned(),
                record.document.clone(),
            ) && prior != record.document
            {
                return Err(inconsistent());
            }
            // Domain selectors order one timestamp per canonical Message. A
            // conflicting timestamp is not representable without inventing an
            // order, so fail explicitly. Text stays only in occurrence records.
            let key = record.message.message.id.as_str().to_owned();
            if let Some(prior) = messages.get(&key) {
                if prior.timestamp != record.message.message.timestamp {
                    return Err(inconsistent());
                }
            } else {
                messages.insert(
                    key,
                    Message {
                        id: record.message.message.id.clone(),
                        role: record.message.message.role,
                        text: String::new(),
                        timestamp: record.message.message.timestamp.clone(),
                    },
                );
            }
            if let Some(edge) = &record.edge {
                self.validate_revision(&edge.proof.revision)?;
                let EntityData::Edge {
                    child,
                    parent,
                    relation,
                } = &edge.data
                else {
                    return Err(inconsistent());
                };
                if *child != p.id
                    || edge.proof.source_id != *source
                    || !edge.proof.revision.published
                {
                    return Err(inconsistent());
                }
                graph.edges.push(MessageEdge {
                    child_placement_id: child.clone(),
                    parent_message_id: parent.clone(),
                    parent_native_id: None,
                    relation: *relation,
                });
            }
            for tool in &record.tools {
                self.validate_revision(&tool.proof.revision)?;
                if tool.proof.source_id != *source
                    || !tool.proof.revision.published
                    || !matches!(&tool.data,EntityData::Tool{message_id,..} if *message_id==p.message_id)
                {
                    return Err(inconsistent());
                }
            }
            graph.placements.push(p.clone());
            if records.insert(p.id.as_str().to_owned(), record).is_some() {
                return Err(inconsistent());
            }
        }
        graph.messages = messages.into_values().collect();
        graph.source_documents = documents.into_values().collect();
        let visible: BTreeSet<_> = graph.messages.iter().map(|m| m.id.as_str()).collect();
        if graph
            .edges
            .iter()
            .any(|e| !visible.contains(e.parent_message_id.as_str()))
        {
            return Err(inconsistent());
        }
        graph.validate().map_err(|_| inconsistent())?;
        Ok(LoadedGraph {
            graph,
            session_proof: projection.session.proof,
            records,
        })
    }

    fn context_response(
        &self,
        session_id: StableId,
        policy: ContextPolicy,
        level: ContextLevel,
        budget: &ResponseBudget,
    ) -> Result<ManagedResponse, AppError> {
        let query = self.scoped_session(&session_id)?;
        let loaded = self.load_graph(&session_id, &query)?;
        let selected = match policy {
            ContextPolicy::Mainline => select_mainline(&loaded.graph)?
                .map(|s| s.placements)
                .unwrap_or_default(),
            ContextPolicy::Full => select_full(&loaded.graph)?,
        };
        let leaf = selected.last().copied();
        let branch_leaf = leaf.map(|p| p.message_id.as_str().to_owned());
        let branch_leaf_placement_id = leaf.map(|p| p.id.as_str().to_owned());
        let session_evidence = ManagedEvidence {
            entity_id: session_id.clone(),
            proof: loaded.session_proof.clone(),
            occurrence: None,
            related: leaf
                .map(|p| vec![loaded.records[p.id.as_str()].message.proof.clone()])
                .unwrap_or_default(),
        };
        let fixed = proof_charge(&session_evidence)
            .saturating_add(crate::json_string_len(session_id.as_str()))
            .saturating_add(512);
        let capacity = net_bytes(budget).checked_sub(fixed).ok_or_else(|| {
            budget::BudgetError::TooSmall("max_response_bytes cannot fit context identity".into())
        })?;
        let mut proofs = BTreeMap::new();
        let mut occurrences = Vec::new();
        for placement in selected {
            self.check_deadline()?;
            let record = loaded
                .records
                .get(placement.id.as_str())
                .ok_or_else(inconsistent)?;
            let proof = context_evidence(record, true);
            let message = context_message(record)?;
            let evidence = evidence::assemble(
                &record.message.message,
                placement,
                &record.document,
                self.generation(),
            );
            let tool_bytes = record.tools.iter().try_fold(0usize, |size, tool| {
                Ok::<_, AppError>(
                    size.saturating_add(bytes(&tool_value(tool)?)?.len())
                        .saturating_add(16),
                )
            })?;
            let estimated_bytes = bytes(&message)?
                .len()
                .saturating_add(bytes(&evidence)?.len())
                .saturating_add(proof_charge(&proof))
                .saturating_add(tool_bytes)
                .saturating_add(
                    placement.message_id.as_str().len()
                        + placement.source_document_id.as_str().len()
                        + 128,
                );
            proofs.insert(placement.id.as_str().to_owned(), proof);
            occurrences.push(crate::ContextOccurrence {
                message,
                evidence,
                role: record.message.message.role,
                source_document_id: record.document.id.as_str().into(),
                estimated_bytes,
            });
        }
        let maximum = budget
            .max_messages
            .min(budget.max_items)
            .min(budget.max_evidence_spans);
        let mut effective = crate::available_level(level, &occurrences);
        let (mut kept, mut truncation, _) = crate::clamp_context_occurrences(
            occurrences.clone(),
            effective,
            maximum,
            capacity.saturating_sub(crate::structural_metadata_reserve(&session_id, effective)),
        );
        if effective != ContextLevel::Raw
            && crate::available_level(effective, &kept) == ContextLevel::Raw
        {
            effective = ContextLevel::Raw;
            (kept, truncation, _) =
                crate::clamp_context_occurrences(occurrences, effective, maximum, capacity);
        }
        normalize_context_limit(&mut truncation, budget);
        let (effective_level, talks, summary) = crate::assemble_level(effective, &kept);
        let hint = crate::build_hint(&session_id, level, effective_level);
        let mut evidence_proofs = vec![session_evidence];
        let mut tools = BTreeMap::new();
        for occurrence in &kept {
            self.check_deadline()?;
            evidence_proofs.push(
                proofs
                    .remove(&occurrence.message.placement_id)
                    .ok_or_else(inconsistent)?,
            );
            for tool in &loaded.records[&occurrence.message.placement_id].tools {
                let value = tool_value(tool)?;
                tools
                    .entry(tool.proof.projection_id.as_str().to_owned())
                    .or_insert(value);
            }
        }
        let session = serde_json::json!({"id":session_id.as_str(),"documents":kept.iter().map(|o|o.source_document_id.as_str()).collect::<BTreeSet<_>>(),"messages":kept.iter().map(|o|o.message.message_id.as_str()).collect::<BTreeSet<_>>()});
        let response = AppResponse::Context {
            session_id: session_id.as_str().into(),
            session,
            branch_leaf,
            branch_leaf_placement_id,
            messages: kept.iter().map(|o| o.message.clone()).collect(),
            evidence: kept.iter().map(|o| o.evidence.clone()).collect(),
            tool_activities: tools.into_values().collect(),
            requested_level: level,
            effective_level,
            talks,
            summary,
            hint,
            truncation: truncation.clone(),
            generation: self.generation(),
        };
        self.finish(
            response,
            evidence_proofs,
            if truncation.truncated {
                vec![ManagedPartial::ResponseBudget]
            } else {
                Vec::new()
            },
        )
    }

    fn message_window(
        &self,
        message_id: StableId,
        requested: Option<StableId>,
        around: usize,
        budget: &ResponseBudget,
    ) -> Result<ManagedResponse, AppError> {
        if message_id.kind() != IdKind::Message || !message_id.validate() {
            return Err(invalid());
        }
        let mut query = self.context.intersection.clone();
        if let Some(id) = &requested {
            query = self.scoped_session(id)?;
        }
        let candidates = self.read.message_contexts(
            &message_id,
            &query,
            crate::MAX_MESSAGE_AMBIGUITY_CANDIDATES,
            crate::MAX_MESSAGE_AMBIGUITY_CANDIDATES,
        )?;
        let session_id = if let Some(id) = requested {
            id
        } else if candidates.candidate_count == 1 {
            candidates
                .candidates
                .first()
                .ok_or_else(inconsistent)?
                .session_id
                .clone()
        } else if candidates.candidate_count > 1 {
            return Err(MessageAmbiguity {
                candidate_session_ids: candidates
                    .candidates
                    .iter()
                    .map(|c| c.session_id.as_str().into())
                    .collect(),
                candidate_count: usize::try_from(candidates.candidate_count)
                    .map_err(|_| inconsistent())?,
                hint: "retry get_message with one candidate session_id".into(),
            }
            .into());
        } else {
            return Err(context_not_found());
        };
        if !candidates
            .candidates
            .iter()
            .any(|c| c.session_id == session_id)
        {
            return Err(context_not_found());
        }
        query.session_id = Some(session_id.clone());
        // An explicit anchor is verified evidence even when a provider supplies
        // no conversational parent edges or the mainline stops at metadata.
        // Do not require an unrelated chosen branch to contain the requested ID.
        if around == 0 {
            return self.message_anchor(&message_id, &session_id, &query, budget, false);
        }
        let loaded = self.load_graph(&session_id, &query)?;
        let selected = select_mainline(&loaded.graph)?
            .map(|s| s.placements)
            .unwrap_or_default();
        let anchors: Vec<_> = selected
            .iter()
            .enumerate()
            .filter_map(|(i, p)| (p.message_id == message_id).then_some(i))
            .collect();
        let anchor = match anchors.as_slice() {
            [index] => *index,
            [] => {
                // Return only the verified anchor, with an honest context gap.
                // Chronological adjacency across disconnected branches is not
                // proof of the user's requested conversational neighborhood.
                return self.message_anchor(&message_id, &session_id, &query, budget, true);
            }
            _ => {
                return Err(PortError::InvalidRequest(
                    "message has multiple mainline occurrences; request session context".into(),
                )
                .into());
            }
        };
        let anchor_placement_id = selected[anchor].id.as_str().to_owned();
        let mut proofs = BTreeMap::new();
        let mut occurrences = Vec::new();
        let capacity = net_bytes(budget).saturating_sub(
            512 + crate::json_string_len(session_id.as_str())
                + crate::json_string_len(message_id.as_str()),
        );
        let start = anchor.saturating_sub(around);
        let end = anchor
            .saturating_add(around)
            .saturating_add(1)
            .min(selected.len());
        for placement in &selected[start..end] {
            self.check_deadline()?;
            let record = &loaded.records[placement.id.as_str()];
            let mut proof = context_evidence(record, false);
            proof.related.push(loaded.session_proof.clone());
            let mut message = context_message(record)?;
            let is_anchor = placement.id.as_str() == anchor_placement_id;
            let payload_truncated = if is_anchor {
                // The shared window helper estimates framing. Account for its
                // difference from the exact ADT serialization before fitting.
                let framing = bytes(&message)?
                    .len()
                    .saturating_sub(crate::context_message_bytes(&message));
                crate::project_anchor_payload(
                    &mut message,
                    record.message.message.role,
                    &record.message.message.text,
                    capacity.saturating_sub(proof_charge(&proof) + 128 + framing),
                )?
            } else {
                false
            };
            let cost = bytes(&message)?
                .len()
                .saturating_add(proof_charge(&proof))
                .saturating_add(128);
            if is_anchor && cost > capacity {
                return Err(budget::BudgetError::TooSmall(
                    "max_response_bytes cannot fit message proof".into(),
                )
                .into());
            }
            proofs.insert(placement.id.as_str().to_owned(), proof);
            occurrences.push(crate::MessageOccurrence {
                message,
                estimated_bytes: cost,
                is_anchor,
                payload_truncated,
            });
        }
        let mut window_budget = budget.clone();
        window_budget.max_items = budget
            .max_items
            .min(budget.max_messages)
            .min(budget.max_evidence_spans);
        let (kept, mut truncation) =
            crate::clamp_message_window(occurrences, &window_budget, capacity);
        normalize_context_limit(&mut truncation, budget);
        let mut evidence = Vec::new();
        let mut messages = Vec::new();
        for occurrence in kept {
            evidence.push(
                proofs
                    .remove(&occurrence.message.placement_id)
                    .ok_or_else(inconsistent)?,
            );
            messages.push(occurrence.message);
        }
        self.finish(
            AppResponse::Message {
                window: MessageWindow {
                    message_id: message_id.as_str().into(),
                    session_id: session_id.as_str().into(),
                    anchor_placement_id,
                    messages,
                    truncation: truncation.clone(),
                    generation: self.generation(),
                },
            },
            evidence,
            if truncation.truncated {
                vec![ManagedPartial::ResponseBudget]
            } else {
                Vec::new()
            },
        )
    }

    fn message_anchor(
        &self,
        message_id: &StableId,
        session_id: &StableId,
        query: &ProjectionQuery,
        budget: &ResponseBudget,
        context_missing: bool,
    ) -> Result<ManagedResponse, AppError> {
        self.check_deadline()?;
        let mut projections = self
            .read
            .messages(std::slice::from_ref(message_id), query)?;
        if projections.len() != 1 {
            return Err(inconsistent());
        }
        let projection = projections.pop().flatten().ok_or_else(context_not_found)?;
        validate_message(&projection, query)?;
        self.validate_revision(&projection.proof.revision)?;
        let occurrence = projection.occurrence.as_ref().ok_or_else(inconsistent)?;
        self.validate_revision(&occurrence.revision)?;
        if projection.message.id != *message_id
            || occurrence.data.placement.session_id != *session_id
            || !projection.proof.revision.published
        {
            return Err(inconsistent());
        }
        let proof = ManagedEvidence {
            entity_id: projection.message.id.clone(),
            proof: projection.proof.clone(),
            occurrence: projection.occurrence.clone(),
            related: Vec::new(),
        };
        let anchor_placement_id = occurrence.data.placement.id.as_str().to_owned();
        let mut message = ContextMessage {
            id: message_id.as_str().into(),
            message_id: message_id.as_str().into(),
            placement_id: anchor_placement_id.clone(),
            payload: serde_json::to_value(&projection.message).map_err(|_| inconsistent())?,
        };
        let capacity = net_bytes(budget).saturating_sub(
            512 + crate::json_string_len(session_id.as_str())
                + crate::json_string_len(message_id.as_str()),
        );
        let framing = bytes(&message)?
            .len()
            .saturating_sub(crate::context_message_bytes(&message));
        let payload_truncated = crate::project_anchor_payload(
            &mut message,
            projection.message.role,
            &projection.message.text,
            capacity.saturating_sub(proof_charge(&proof) + 128 + framing),
        )?;
        let cost = bytes(&message)?
            .len()
            .saturating_add(proof_charge(&proof) + 128);
        if cost > capacity {
            return Err(budget::BudgetError::TooSmall(
                "max_response_bytes cannot fit message proof".into(),
            )
            .into());
        }
        let mut window_budget = budget.clone();
        window_budget.max_items = budget
            .max_items
            .min(budget.max_messages)
            .min(budget.max_evidence_spans);
        let (kept, mut truncation) = crate::clamp_message_window(
            vec![crate::MessageOccurrence {
                message,
                estimated_bytes: cost,
                is_anchor: true,
                payload_truncated,
            }],
            &window_budget,
            capacity,
        );
        normalize_context_limit(&mut truncation, budget);
        if kept.len() != 1 {
            return Err(inconsistent());
        }
        let mut partial = Vec::new();
        if truncation.truncated {
            partial.push(ManagedPartial::ResponseBudget);
        }
        if context_missing {
            partial.push(ManagedPartial::ContextUnavailable);
        }
        self.finish(
            AppResponse::Message {
                window: MessageWindow {
                    message_id: message_id.as_str().into(),
                    session_id: session_id.as_str().into(),
                    anchor_placement_id,
                    messages: kept
                        .into_iter()
                        .map(|occurrence| occurrence.message)
                        .collect(),
                    truncation,
                    generation: self.generation(),
                },
            },
            vec![proof],
            partial,
        )
    }

    fn message_contexts(&self, message_id: StableId) -> Result<ManagedResponse, AppError> {
        if message_id.kind() != IdKind::Message || !message_id.validate() {
            return Err(invalid());
        }
        let budget = &self.context.budget;
        let page = self.read.message_contexts(
            &message_id,
            &self.context.intersection,
            budget.max_items.min(512),
            budget
                .max_messages
                .min(budget.max_evidence_spans)
                .min(16_384),
        )?;
        let mut items = Vec::new();
        for candidate in page.candidates {
            self.check_deadline()?;
            for binding in candidate.occurrences {
                let o = &binding.occurrence;
                self.validate_revision(&binding.proof.revision)?;
                self.validate_revision(&o.revision)?;
                validate_occurrence(o, &self.context.intersection)?;
                if o.data.placement.message_id != message_id
                    || o.data.placement.session_id != candidate.session_id
                    || o.source_id != binding.proof.source_id
                    || !binding.proof.revision.published
                    || !o.revision.published
                {
                    return Err(inconsistent());
                }
                let proof = ManagedEvidence {
                    entity_id: message_id.clone(),
                    proof: binding.proof,
                    occurrence: Some(binding.occurrence),
                    related: Vec::new(),
                };
                items.push((candidate.session_id.clone(), proof));
            }
        }
        let (kept, truncation, _) = budget::clamp_items(
            items,
            budget.max_messages.min(budget.max_evidence_spans),
            net_bytes(budget).saturating_sub(256),
            |(session, p)| proof_charge(p) + crate::json_string_len(session.as_str()) + 128,
        );
        let mut grouped = BTreeMap::<String, BTreeSet<String>>::new();
        let mut evidence = Vec::new();
        for (session, proof) in kept {
            grouped.entry(session.as_str().into()).or_default().insert(
                proof
                    .occurrence
                    .as_ref()
                    .ok_or_else(inconsistent)?
                    .data
                    .placement
                    .id
                    .as_str()
                    .into(),
            );
            evidence.push(proof);
        }
        let candidates = grouped
            .into_iter()
            .map(|(session_id, ids)| MessageContextCandidate {
                session_id,
                placement_ids: ids.into_iter().collect(),
            })
            .collect();
        self.finish(
            AppResponse::MessageContexts {
                message_id: message_id.as_str().into(),
                candidates,
            },
            evidence,
            if page.truncated || truncation.truncated {
                vec![ManagedPartial::ResponseBudget]
            } else {
                Vec::new()
            },
        )
    }
}

struct LoadedGraph {
    graph: SessionContextGraph,
    session_proof: EvidenceProof,
    records: BTreeMap<String, ContextProjection>,
}
fn context_not_found() -> AppError {
    PortError::NotFound("managed context or message not found".into()).into()
}
fn context_message(record: &ContextProjection) -> Result<ContextMessage, AppError> {
    let p = &record.message;
    let o = p.occurrence.as_ref().ok_or_else(inconsistent)?;
    Ok(ContextMessage {
        id: p.message.id.as_str().into(),
        message_id: p.message.id.as_str().into(),
        placement_id: o.data.placement.id.as_str().into(),
        payload: serde_json::to_value(&p.message).map_err(|_| inconsistent())?,
    })
}
fn context_evidence(record: &ContextProjection, tools: bool) -> ManagedEvidence {
    let mut related = vec![record.document_proof.clone()];
    if let Some(edge) = &record.edge {
        related.push(edge.proof.clone());
    }
    if tools {
        related.extend(record.tools.iter().map(|t| t.proof.clone()));
    }
    ManagedEvidence {
        entity_id: record.message.message.id.clone(),
        proof: record.message.proof.clone(),
        occurrence: record.message.occurrence.clone(),
        related,
    }
}
fn tool_value(tool: &EntityProjection) -> Result<serde_json::Value, AppError> {
    let EntityData::Tool {
        activity_id,
        message_id,
        activity,
    } = &tool.data
    else {
        return Err(inconsistent());
    };
    Ok(
        serde_json::json!({"activity_id":activity_id,"message_id":message_id.as_str(),"kind":activity.kind,"actor":activity.actor,"name":activity.name,"target":activity.target,"status":activity.status}),
    )
}
fn normalize_context_limit(truncation: &mut Truncation, budget: &ResponseBudget) {
    if matches!(
        truncation.reason.as_deref(),
        Some(budget::TRUNCATION_MAX_ITEMS | budget::TRUNCATION_MAX_MESSAGES)
    ) {
        truncation.reason = Some(
            if budget.max_evidence_spans < budget.max_messages.min(budget.max_items) {
                budget::TRUNCATION_MAX_EVIDENCE_SPANS
            } else if budget.max_items < budget.max_messages {
                budget::TRUNCATION_MAX_ITEMS
            } else {
                budget::TRUNCATION_MAX_MESSAGES
            }
            .into(),
        );
    }
}

fn reject_cursor(cursor: Option<&str>) -> Result<(), AppError> {
    if cursor.is_some() {
        Err(cursor::CursorError::Expired("managed continuation unavailable".into()).into())
    } else {
        Ok(())
    }
}
fn net_bytes(budget: &ResponseBudget) -> usize {
    budget
        .max_response_bytes
        .saturating_sub(crate::ENVELOPE_RESERVE_BYTES)
}
fn intersect_budget(a: &ResponseBudget, b: &ResponseBudget) -> ResponseBudget {
    ResponseBudget {
        max_response_bytes: a.max_response_bytes.min(b.max_response_bytes),
        max_items: a.max_items.min(b.max_items),
        max_snippet_chars: a.max_snippet_chars.min(b.max_snippet_chars),
        max_messages: a.max_messages.min(b.max_messages),
        max_evidence_spans: a.max_evidence_spans.min(b.max_evidence_spans),
    }
}
fn validate_query(query: &ProjectionQuery) -> Result<(), AppError> {
    if query
        .filters
        .since
        .is_some_and(|t| t.nanosecond >= 1_000_000_000)
        || query
            .filters
            .until
            .is_some_and(|t| t.nanosecond >= 1_000_000_000)
        || query
            .filters
            .since
            .zip(query.filters.until)
            .is_some_and(|(a, b)| a >= b)
        || query
            .session_id
            .as_ref()
            .is_some_and(|id| id.kind() != IdKind::Session || !id.validate())
    {
        return Err(invalid());
    }
    Ok(())
}
fn intersect(
    a: &ProjectionQuery,
    b: &ProjectionQuery,
) -> Result<Option<ProjectionQuery>, AppError> {
    validate_query(a)?;
    validate_query(b)?;
    let mut out = a.clone();
    if a.filters.providers.is_empty() {
        out.filters.providers = b.filters.providers.clone();
    } else if !b.filters.providers.is_empty() {
        out.filters
            .providers
            .retain(|p| b.filters.providers.contains(p));
        if out.filters.providers.is_empty() {
            return Ok(None);
        }
    }
    out.filters.providers.sort();
    out.filters.providers.dedup();
    out.filters.since = a.filters.since.into_iter().chain(b.filters.since).max();
    out.filters.until = a.filters.until.into_iter().chain(b.filters.until).min();
    if out
        .filters
        .since
        .zip(out.filters.until)
        .is_some_and(|(a, b)| a >= b)
    {
        return Ok(None);
    }
    macro_rules! exact {
        ($field:expr,$left:expr,$right:expr) => {
            match ($left, $right) {
                (Some(a), Some(b)) if a != b => return Ok(None),
                (_, Some(value)) => $field = Some(value.clone()),
                _ => {}
            }
        };
    }
    exact!(out.filters.repo, &a.filters.repo, &b.filters.repo);
    exact!(
        out.facets.tool_kind,
        &a.facets.tool_kind,
        &b.facets.tool_kind
    );
    exact!(
        out.facets.tool_name,
        &a.facets.tool_name,
        &b.facets.tool_name
    );
    match (&a.session_id, &b.session_id) {
        (Some(a), Some(b)) if a.as_str() != b.as_str() => return Ok(None),
        (_, Some(value)) => out.session_id = Some(value.clone()),
        _ => {}
    }
    out.facets.sidechain = match (a.facets.sidechain, b.facets.sidechain) {
        (SidechainFacet::Include, b) => b,
        (a, SidechainFacet::Include) => a,
        (a, b) if a == b => a,
        _ => return Ok(None),
    };
    out.include_system = a.include_system && b.include_system;
    Ok(Some(out))
}
fn validate_message(p: &MessageProjection, query: &ProjectionQuery) -> Result<(), AppError> {
    p.message.validate().map_err(|_| inconsistent())?;
    let o = p.occurrence.as_ref().ok_or_else(inconsistent)?;
    if o.source_id != p.proof.source_id
        || o.data.placement.message_id != p.message.id
        || o.data.role != p.message.role
        || o.data.timestamp != p.message.timestamp
        || !p.proof.revision.published
        || !o.revision.published
    {
        return Err(inconsistent());
    }
    validate_occurrence(o, query)
}
fn validate_occurrence(o: &OccurrenceProjection, query: &ProjectionQuery) -> Result<(), AppError> {
    let placement = &o.data.placement;
    if placement.session_id.kind() != IdKind::Session
        || !placement.session_id.validate()
        || placement.message_id.kind() != IdKind::Message
        || !placement.message_id.validate()
        || placement.source_document_id.kind() != IdKind::Document
        || !placement.source_document_id.validate()
        || *placement
            != agent_session_grep_domain::MessagePlacement::new(
                placement.session_id.clone(),
                placement.source_document_id.clone(),
                placement.message_id.clone(),
                placement.source_ordinal,
                placement.is_sidechain,
                placement.span.clone(),
            )
        || query
            .session_id
            .as_ref()
            .is_some_and(|id| id.as_str() != o.data.placement.session_id.as_str())
        || query
            .filters
            .repo
            .as_ref()
            .is_some_and(|repo| o.data.project_id.as_ref() != Some(repo))
        || (!query.filters.providers.is_empty()
            && !query
                .filters
                .providers
                .iter()
                .any(|p| p.as_str() == o.data.provider_id))
        || (!query.include_system
            && matches!(
                o.data.role,
                agent_session_grep_domain::Role::System
                    | agent_session_grep_domain::Role::Developer
            ))
        || (query.facets.sidechain == SidechainFacet::MainOnly && o.data.placement.is_sidechain)
        || (query.facets.sidechain == SidechainFacet::SubagentOnly
            && !o.data.placement.is_sidechain)
    {
        return Err(inconsistent());
    }
    let instant = o
        .data
        .timestamp
        .as_deref()
        .and_then(crate::parse_search_instant);
    if query
        .filters
        .since
        .is_some_and(|since| instant.is_none_or(|t| t < since))
        || query
            .filters
            .until
            .is_some_and(|until| instant.is_none_or(|t| t >= until))
    {
        return Err(inconsistent());
    }
    Ok(())
}
fn validate_session_metadata(
    p: &EntityProjection,
    query: &ProjectionQuery,
) -> Result<(), AppError> {
    let EntityData::Session(s) = &p.data else {
        return Err(inconsistent());
    };
    if s.session.id.kind() != IdKind::Session
        || !p.proof.revision.published
        || query
            .session_id
            .as_ref()
            .is_some_and(|id| *id != s.session.id)
        || query
            .filters
            .repo
            .as_ref()
            .is_some_and(|repo| s.repo_slug.as_ref() != Some(repo))
        || (!query.filters.providers.is_empty()
            && !query
                .filters
                .providers
                .iter()
                .any(|p| p.as_str() == s.provider_id))
    {
        return Err(inconsistent());
    }
    // Time/tool/sidechain qualification belongs to the same-snapshot port;
    // a Session has no synthetic timestamp or occurrence to re-evaluate here.
    Ok(())
}
fn project_entry(
    entry: &ProjectionListEntry,
    query: &ProjectionQuery,
) -> Result<(Vec<u8>, ManagedEvidence, Option<String>), AppError> {
    match entry {
        ProjectionListEntry::Message(p) => {
            validate_message(p, query)?;
            Ok((
                bytes(&p.message)?,
                ManagedEvidence {
                    entity_id: p.message.id.clone(),
                    proof: p.proof.clone(),
                    occurrence: p.occurrence.clone(),
                    related: Vec::new(),
                },
                None,
            ))
        }
        ProjectionListEntry::Entity(p) => {
            if !p.proof.revision.published {
                return Err(inconsistent());
            }
            let (id, payload, title) = match &p.data {
                EntityData::Session(s) => (
                    s.session.id.clone(),
                    bytes(
                        &serde_json::json!({"id":s.session.id.as_str(),"documents":s.documents.iter().map(StableId::as_str).collect::<Vec<_>>(),"title":s.title,"repo_slug":s.repo_slug,"provider":s.provider_id}),
                    )?,
                    s.title.clone(),
                ),
                EntityData::Document(d) => (d.id.clone(), bytes(d)?, None),
                _ => return Err(inconsistent()),
            };
            Ok((
                payload,
                ManagedEvidence {
                    entity_id: id,
                    proof: p.proof.clone(),
                    occurrence: None,
                    related: Vec::new(),
                },
                title,
            ))
        }
    }
}
fn proof_charge(p: &ManagedEvidence) -> usize {
    let r = &p.proof.revision;
    [
        p.entity_id.as_str(),
        p.proof.source_id.as_str(),
        p.proof.projection_id.as_str(),
        r.revision_id.as_str(),
        &r.digest,
        &r.worker_boot_id,
        &r.catalog_incarnation,
    ]
    .iter()
    .fold(512usize, |n, s| n.saturating_add(crate::json_string_len(s)))
    .saturating_add(p.related.iter().fold(0usize, |size, proof| {
        size.saturating_add(
            512 + crate::json_string_len(proof.source_id.as_str())
                + crate::json_string_len(proof.projection_id.as_str())
                + crate::json_string_len(proof.revision.revision_id.as_str())
                + crate::json_string_len(&proof.revision.digest)
                + crate::json_string_len(&proof.revision.catalog_incarnation)
                + crate::json_string_len(&proof.revision.worker_boot_id),
        )
    }))
    .saturating_add(p.occurrence.as_ref().map_or(0, |o| {
        o.data.placement.id.as_str().len()
            + o.data.placement.session_id.as_str().len()
            + o.data.placement.source_document_id.as_str().len()
            + o.data.project_id.as_ref().map_or(0, String::len)
            + o.data.timestamp.as_ref().map_or(0, String::len)
            + 256
    }))
}
fn fit_message_payload(
    p: &MessageProjection,
    available: usize,
    expired: &dyn Fn() -> bool,
) -> Result<Vec<u8>, AppError> {
    // JSON escaping never shrinks text bytes. Examine only a budget-sized
    // prefix; do not allocate a character-offset table for the full transcript
    // or clone its entire text during each binary-search step.
    let mut low = 0;
    let mut high = p.message.text.len().min(available) + 1;
    let mut best = None;
    while low < high {
        if expired() {
            return Err(
                PortError::DeadlineExceeded("managed request deadline exceeded".into()).into(),
            );
        }
        let mid = low + (high - low) / 2;
        let mut end = mid;
        while !p.message.text.is_char_boundary(end) {
            end -= 1;
        }
        let payload = bytes(&serde_json::json!({
            "id": p.message.id,
            "role": p.message.role,
            "text": &p.message.text[..end],
            "timestamp": p.message.timestamp,
        }))?;
        if crate::lossy_payload_json_len(&payload).saturating_add(48) <= available {
            best = Some(payload);
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    best.ok_or_else(|| {
        budget::BudgetError::TooSmall("max_response_bytes cannot fit the managed message".into())
            .into()
    })
}
