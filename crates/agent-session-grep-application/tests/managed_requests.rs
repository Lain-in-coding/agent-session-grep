//! Synthetic typed port tests. No SQLite, source history or host configuration.
use agent_session_grep_application::{
    AppRequest, AppResponse, ContextLevel, ResponseBudget,
    managed::{ManagedApp, ManagedHandoffRequest, ManagedPartial, ManagedRequestContext},
};
use agent_session_grep_domain::{
    ContextPolicy, IdKind, Message, MessagePlacement, Role, Session, SourceDocument, StableId,
};
use agent_session_grep_ports::{
    PortResult, RetrievalMode, SearchFacets, SearchFilters, SearchProvider, SidechainFacet,
    managed::*,
};
use std::cell::{Cell, RefCell};

fn id(kind: IdKind, name: &str) -> StableId {
    StableId::native_checked(kind, name).unwrap()
}
fn projection(name: &str, text: &str) -> MessageProjection {
    let message = Message {
        id: id(IdKind::Message, name),
        role: Role::User,
        text: text.into(),
        timestamp: None,
    };
    let source = SourceId::parse("matched-source").unwrap();
    let revision = RevisionRef {
        revision_id: RevisionId::parse("revision-1").unwrap(),
        digest: "synthetic-digest".into(),
        observed_at_ms: 1,
        cycle_seq: 1,
        worker_boot_id: "boot".into(),
        catalog_incarnation: "incarnation".into(),
        policy_epoch: 1,
        started_control_seq: 1,
        committed_generation: Some(1),
        published: true,
    };
    let occurrence = OccurrenceProjection {
        data: OccurrenceData {
            placement: MessagePlacement::new(
                id(IdKind::Session, "session"),
                id(IdKind::Document, "document"),
                message.id.clone(),
                0,
                false,
                None,
            ),
            provider_id: "claude-code".into(),
            project_id: Some("example.test/team/repo".into()),
            timestamp: None,
            role: Role::User,
        },
        source_id: source.clone(),
        revision: revision.clone(),
    };
    MessageProjection {
        message,
        index_text: text.into(),
        payload_digest: "synthetic-payload".into(),
        index_digest: "synthetic-index".into(),
        proof: EvidenceProof {
            source_id: source,
            projection_id: ProjectionId::parse(&format!("projection-{name}")).unwrap(),
            revision,
        },
        occurrence: Some(occurrence),
    }
}
fn graph_record(message: MessageProjection, tools: Vec<EntityProjection>) -> ContextProjection {
    let occurrence = message.occurrence.as_ref().unwrap();
    ContextProjection {
        document: SourceDocument {
            id: occurrence.data.placement.source_document_id.clone(),
            provider_id: occurrence.data.provider_id.clone(),
            variant_id: "synthetic".into(),
            fingerprint: "synthetic-fingerprint".into(),
            len: 4096,
        },
        document_proof: message.proof.clone(),
        message,
        edge: None,
        tools,
    }
}
fn handoff_tool(message: &MessageProjection, name: &str, target: &str) -> EntityProjection {
    use agent_session_grep_domain::{
        ToolActivity, ToolActivityActor, ToolActivityKind, ToolActivityStatus,
    };
    EntityProjection {
        data: EntityData::Tool {
            activity_id: format!("private-activity-{name}"),
            message_id: message.message.id.clone(),
            activity: ToolActivity {
                kind: ToolActivityKind::File,
                actor: ToolActivityActor::Main,
                name: name.into(),
                target: Some(target.into()),
                status: ToolActivityStatus::Success,
            },
        },
        proof: EvidenceProof {
            projection_id: ProjectionId::parse(&format!("tool-{name}")).unwrap(),
            ..message.proof.clone()
        },
    }
}
fn handoff_request() -> ManagedHandoffRequest {
    ManagedHandoffRequest {
        query: "alpha".into(),
        intersection: ProjectionQuery::default(),
        limit: 50,
        budget: ResponseBudget::default(),
        max_tokens: 8000,
        max_bytes: 2_000_000,
        max_evidence: 20,
        mode: RetrievalMode::Lexical,
        target: None,
    }
}
fn session_projection(message: &MessageProjection, title: Option<&str>) -> EntityProjection {
    let occurrence = message.occurrence.as_ref().unwrap();
    EntityProjection {
        data: EntityData::Session(SessionData {
            session: Session {
                id: occurrence.data.placement.session_id.clone(),
            },
            documents: vec![occurrence.data.placement.source_document_id.clone()],
            title: title.map(str::to_owned),
            repo_slug: occurrence.data.project_id.clone(),
            provider_id: occurrence.data.provider_id.clone(),
            first_user_text: None,
        }),
        proof: message.proof.clone(),
    }
}
struct Read {
    snapshot: ReadSnapshot,
    candidate: MessageProjection,
    direct: MessageProjection,
    calls: RefCell<Vec<(&'static str, ProjectionQuery)>>,
    direct_calls: Cell<usize>,
    page_truncated: bool,
    extra: Option<MessageProjection>,
    graph_override: Option<Vec<ContextProjection>>,
    graph_busy: bool,
    no_hits: bool,
    list_sessions: Vec<EntityProjection>,
    preview_unavailable: bool,
    metadata_hits: Vec<SessionMetadataHit>,
}
impl Read {
    fn new(text: &str) -> Self {
        Self {
            snapshot: ReadSnapshot {
                catalog_incarnation: "incarnation".into(),
                generation: 1,
                destructive_epoch: 0,
                policy_epoch: 1,
            },
            candidate: projection("shared", text),
            direct: projection("shared", "wrong direct representative"),
            calls: RefCell::new(Vec::new()),
            direct_calls: Cell::new(0),
            page_truncated: false,
            extra: None,
            graph_override: None,
            graph_busy: false,
            no_hits: false,
            list_sessions: Vec::new(),
            preview_unavailable: false,
            metadata_hits: Vec::new(),
        }
    }
    fn note(&self, name: &'static str, query: &ProjectionQuery) {
        self.calls.borrow_mut().push((name, query.clone()));
    }
}
impl ProjectionRead for Read {
    fn query_session_metadata(
        &self,
        _text: &str,
        query: &ProjectionQuery,
        limit: usize,
    ) -> PortResult<SessionMetadataPage> {
        self.note("metadata", query);
        Ok(SessionMetadataPage {
            hits: self.metadata_hits.iter().take(limit).cloned().collect(),
            truncated: self.metadata_hits.len() > limit,
            incomplete: false,
        })
    }
    fn snapshot(&self) -> &ReadSnapshot {
        &self.snapshot
    }
    fn source_progress(&self) -> PortResult<Vec<SourceProgress>> {
        Ok(Vec::new())
    }
    fn session_previews(
        &self,
        requests: &[SessionPreviewRequest],
        query: &ProjectionQuery,
        _max_bytes: usize,
    ) -> PortResult<Vec<SessionPreview>> {
        self.note("previews", query);
        Ok(requests
            .iter()
            .map(|request| {
                let rows: Vec<_> = std::iter::once(&self.candidate)
                    .chain(self.extra.iter())
                    .filter(|p| {
                        p.proof.source_id == request.source_id
                            && p.occurrence
                                .as_ref()
                                .unwrap()
                                .data
                                .placement
                                .session_id
                                .as_str()
                                == request.session_id.as_str()
                    })
                    .collect();
                let project = |p: &&MessageProjection| PreviewMessage {
                    text: p.message.text.clone(),
                    proof: p.proof.clone(),
                    occurrence: p.occurrence.clone().unwrap(),
                };
                SessionPreview {
                    request: request.clone(),
                    first_user: rows.first().map(project),
                    last_user: rows.last().map(project),
                    unavailable: self.preview_unavailable,
                }
            })
            .collect())
    }
    fn session_graph(
        &self,
        session_id: &StableId,
        query: &ProjectionQuery,
        _limits: GraphReadLimits,
    ) -> PortResult<SessionProjectionGraph> {
        self.note("graph", query);
        if self.graph_busy {
            return Err(agent_session_grep_ports::PortError::WriterBusy(
                "bounded graph unavailable".into(),
            ));
        }
        let document_id = self
            .candidate
            .occurrence
            .as_ref()
            .unwrap()
            .data
            .placement
            .source_document_id
            .clone();
        Ok(SessionProjectionGraph {
            session: EntityProjection {
                data: EntityData::Session(SessionData {
                    session: Session {
                        id: session_id.clone(),
                    },
                    documents: vec![document_id.clone()],
                    title: None,
                    repo_slug: None,
                    provider_id: "claude-code".into(),
                    first_user_text: None,
                }),
                proof: self.candidate.proof.clone(),
            },
            occurrences: self.graph_override.clone().unwrap_or_else(|| {
                std::iter::once(&self.candidate)
                    .chain(self.extra.iter())
                    .map(|p| graph_record(p.clone(), Vec::new()))
                    .collect()
            }),
        })
    }
    fn message_contexts(
        &self,
        _id: &StableId,
        query: &ProjectionQuery,
        _max_candidates: usize,
        _max_occurrences: usize,
    ) -> PortResult<MessageContextsPage> {
        self.note("contexts", query);
        let occurrence = self.candidate.occurrence.as_ref().unwrap().clone();
        Ok(MessageContextsPage {
            candidates: vec![ProjectedMessageContext {
                session_id: occurrence.data.placement.session_id.clone(),
                occurrences: vec![OccurrenceEvidence {
                    occurrence,
                    proof: self.candidate.proof.clone(),
                }],
            }],
            candidate_count: 1,
            truncated: false,
        })
    }
    fn list(
        &self,
        query: &ProjectionQuery,
        sessions_only: bool,
        limit: usize,
    ) -> PortResult<ProjectionListPage> {
        self.note("list", query);
        if sessions_only {
            return Ok(ProjectionListPage {
                entries: self
                    .list_sessions
                    .iter()
                    .take(limit)
                    .cloned()
                    .map(|p| ProjectionListEntry::Entity(Box::new(p)))
                    .collect(),
                truncated: self.page_truncated || self.list_sessions.len() > limit,
            });
        }
        let mut entries = vec![ProjectionListEntry::Message(Box::new(
            self.candidate.clone(),
        ))];
        if let Some(extra) = &self.extra {
            entries.push(ProjectionListEntry::Message(Box::new(extra.clone())));
        }
        entries.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));
        let truncated = self.page_truncated || entries.len() > limit;
        entries.truncate(limit);
        Ok(ProjectionListPage { entries, truncated })
    }
    fn stats(&self, query: &ProjectionQuery, _repo_limit: usize) -> PortResult<ProjectionStats> {
        self.note("stats", query);
        Ok(ProjectionStats {
            catalog_count: 3,
            placements: 1,
            source_placement_claims: 1,
            usage: None,
            repos: vec![],
            repos_truncated: false,
            facts_incomplete: false,
        })
    }
    fn messages(
        &self,
        ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<Option<MessageProjection>>> {
        self.note("messages", query);
        self.direct_calls.set(self.direct_calls.get() + 1);
        Ok(ids.iter().map(|_| Some(self.direct.clone())).collect())
    }
    fn entities(
        &self,
        _kind: EntityKind,
        _ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<EntityProjection>> {
        self.note("entities", query);
        Ok(vec![])
    }
    fn occurrences(
        &self,
        _ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<OccurrenceProjection>> {
        self.note("occurrences", query);
        Ok(vec![])
    }
    fn query_lexical(
        &self,
        _text: &str,
        query: &ProjectionQuery,
        _limit: usize,
    ) -> PortResult<LexicalPage> {
        self.note("query", query);
        if self.no_hits {
            return Ok(LexicalPage {
                hits: Vec::new(),
                truncated: false,
            });
        }
        let mut hits = vec![LexicalHit {
            projection: self.candidate.clone(),
            score: 2.0,
            claim_count: 1,
        }];
        if let Some(extra) = &self.extra {
            hits.push(LexicalHit {
                projection: extra.clone(),
                score: 1.0,
                claim_count: 1,
            });
        }
        Ok(LexicalPage {
            hits,
            truncated: self.page_truncated,
        })
    }
}
fn context(expired: &dyn Fn() -> bool) -> ManagedRequestContext<'_> {
    ManagedRequestContext {
        intersection: ProjectionQuery::default(),
        budget: ResponseBudget::default(),
        now_ms: 1,
        current_repo: None,
        deadline_expired: expired,
    }
}
fn search() -> AppRequest {
    AppRequest::Search {
        query: "alpha".into(),
        filters: SearchFilters::default(),
        facets: SearchFacets::default(),
        limit: 10,
        cursor: None,
        budget: ResponseBudget::default(),
        include_system: false,
        group_by_session: false,
        mode: RetrievalMode::Lexical,
        query_embedding: None,
    }
}

#[test]
fn search_retains_matched_projection_and_never_fetches_a_different_id_representative() {
    let read = Read::new("alpha from matched source");
    let expired = || false;
    let response = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .handle(search())
        .unwrap();
    let AppResponse::Search {
        hits, next_cursor, ..
    } = &response.response
    else {
        panic!("expected search");
    };
    assert_eq!(hits[0].text.as_deref(), Some("alpha from matched source"));
    assert_eq!(read.direct_calls.get(), 0);
    assert_eq!(response.evidence[0].proof, read.candidate.proof);
    assert!(next_cursor.is_none());
    assert!(
        !response
            .partial
            .contains(&ManagedPartial::MetadataSearchUnavailable)
    );
    assert!(
        response
            .partial
            .contains(&ManagedPartial::ResumeAvailabilityUnavailable)
    );
}

#[test]
fn context_restrictions_are_intersected_and_disjoint_filters_never_query_storage() {
    let read = Read::new("alpha");
    let expired = || false;
    let mut ctx = context(&expired);
    ctx.intersection.filters.providers = vec![SearchProvider::Claude];
    ctx.intersection.filters.repo = Some("example.test/team/repo".into());
    ctx.intersection.session_id = Some(id(IdKind::Session, "session"));
    ctx.intersection.facets.sidechain = SidechainFacet::MainOnly;
    let app = ManagedApp::new(&read, ctx).unwrap();
    let mut request = search();
    if let AppRequest::Search {
        filters,
        include_system,
        ..
    } = &mut request
    {
        filters.providers = vec![SearchProvider::Claude, SearchProvider::Codex];
        *include_system = true;
    }
    app.handle(request).unwrap();
    let calls = read.calls.borrow();
    let q = &calls[0].1;
    assert_eq!(q.filters.providers, vec![SearchProvider::Claude]);
    assert_eq!(q.filters.repo.as_deref(), Some("example.test/team/repo"));
    assert!(!q.include_system);
    assert_eq!(q.facets.sidechain, SidechainFacet::MainOnly);
    drop(calls);
    read.calls.borrow_mut().clear();
    let mut request = search();
    if let AppRequest::Search { filters, .. } = &mut request {
        filters.providers = vec![SearchProvider::Codex];
    }
    let response = app.handle(request).unwrap();
    assert!(read.calls.borrow().is_empty());
    assert!(matches!(response.response,AppResponse::Search{hits,..} if hits.is_empty()));
}

#[test]
fn get_show_list_status_use_the_context_query_and_no_legacy_cursor_is_accepted() {
    let read = Read::new("alpha");
    let expired = || false;
    let mut ctx = context(&expired);
    ctx.intersection.filters.repo = Some("example.test/team/repo".into());
    ctx.intersection.session_id = Some(id(IdKind::Session, "session"));
    let app = ManagedApp::new(&read, ctx).unwrap();
    for request in [
        AppRequest::Get {
            id: id(IdKind::Message, "shared"),
        },
        AppRequest::Show {
            id: id(IdKind::Message, "shared"),
        },
        AppRequest::List {
            limit: 10,
            cursor: None,
            budget: ResponseBudget::default(),
            sessions_only: false,
        },
        AppRequest::Status,
    ] {
        app.handle(request).unwrap();
    }
    assert!(
        read.calls
            .borrow()
            .iter()
            .all(
                |(_, q)| q.filters.repo.as_deref() == Some("example.test/team/repo")
                    && q.session_id == Some(id(IdKind::Session, "session"))
            )
    );
    let calls = read.calls.borrow().len();
    let mut request = search();
    if let AppRequest::Search { cursor, .. } = &mut request {
        *cursor = Some("legacy-cursor".into());
    }
    assert!(app.handle(request).is_err());
    assert!(
        app.handle(AppRequest::List {
            limit: 1,
            cursor: Some("legacy-cursor".into()),
            budget: ResponseBudget::default(),
            sessions_only: false
        })
        .is_err()
    );
    assert_eq!(calls, read.calls.borrow().len());
}

#[test]
fn payload_and_snippet_budgets_keep_proofs_aligned_and_truncation_explicit() {
    let text = format!("alpha {}", "\"\\界".repeat(12000));
    let mut read = Read::new(&text);
    read.direct = read.candidate.clone();
    let expired = || false;
    let mut ctx = context(&expired);
    ctx.budget.max_response_bytes = 4096;
    ctx.budget.max_snippet_chars = 7;
    let app = ManagedApp::new(&read, ctx).unwrap();
    let response = app
        .handle(AppRequest::Get {
            id: id(IdKind::Message, "shared"),
        })
        .unwrap();
    let AppResponse::Get {
        payload: Some(payload),
    } = &response.response
    else {
        panic!("expected get");
    };
    let rendered = serde_json::to_vec(
        &serde_json::json!({"payload":String::from_utf8(payload.clone()).unwrap()}),
    )
    .unwrap();
    assert!(rendered.len() < 4096 - 1024);
    let message: Message = serde_json::from_slice(payload).unwrap();
    assert!(text.starts_with(&message.text));
    assert!(message.text.len() < text.len());
    assert!(response.partial.contains(&ManagedPartial::ResponseBudget));
    assert_eq!(response.evidence[0].proof, read.direct.proof);
    let response = app.handle(search()).unwrap();
    let AppResponse::Search { hits, .. } = &response.response else {
        panic!();
    };
    assert_eq!(hits.len(), response.evidence.len());
    assert!(hits[0].text.as_ref().unwrap().chars().count() <= 7);
}

#[test]
fn context_message_and_contexts_use_occurrence_projection_and_expired_deadlines_do_not_read() {
    let read = Read::new("alpha");
    let expired = Cell::new(false);
    let clock = || expired.get();
    let app = ManagedApp::new(&read, context(&clock)).unwrap();
    for request in [
        AppRequest::Context {
            session_id: id(IdKind::Session, "session"),
            policy: ContextPolicy::Full,
            level: ContextLevel::Raw,
            budget: ResponseBudget::default(),
        },
        AppRequest::Message {
            message_id: id(IdKind::Message, "shared"),
            session_id: None,
            around: 1,
            budget: ResponseBudget::default(),
        },
        AppRequest::MessageContexts {
            message_id: id(IdKind::Message, "shared"),
        },
    ] {
        let result = app.handle(request).unwrap();
        match result.response {
            AppResponse::Context { messages, .. } => {
                assert_eq!(messages[0].payload["text"], "alpha")
            }
            AppResponse::Message { window } => {
                assert_eq!(window.messages[0].payload["text"], "alpha")
            }
            AppResponse::MessageContexts { candidates, .. } => assert_eq!(candidates.len(), 1),
            _ => panic!("unexpected response"),
        }
    }
    assert_eq!(read.direct_calls.get(), 0);
    read.calls.borrow_mut().clear();
    expired.set(true);
    assert!(app.handle(AppRequest::Status).is_err());
    for request in [
        AppRequest::Context {
            session_id: id(IdKind::Session, "session"),
            policy: ContextPolicy::Full,
            level: ContextLevel::Raw,
            budget: ResponseBudget::default(),
        },
        AppRequest::Message {
            message_id: id(IdKind::Message, "shared"),
            session_id: None,
            around: 1,
            budget: ResponseBudget::default(),
        },
        AppRequest::MessageContexts {
            message_id: id(IdKind::Message, "shared"),
        },
    ] {
        assert!(app.handle(request).is_err());
    }
    assert!(read.calls.borrow().is_empty());
}

#[test]
fn context_rejects_proofs_from_another_incarnation_or_future_generation() {
    for future_generation in [false, true] {
        let mut read = Read::new("alpha");
        if future_generation {
            read.candidate.proof.revision.committed_generation = Some(2);
        } else {
            read.candidate.proof.revision.catalog_incarnation = "other-incarnation".into();
        }
        let expired = || false;
        let app = ManagedApp::new(&read, context(&expired)).unwrap();
        for request in [
            AppRequest::Context {
                session_id: id(IdKind::Session, "session"),
                policy: ContextPolicy::Full,
                level: ContextLevel::Raw,
                budget: ResponseBudget::default(),
            },
            AppRequest::MessageContexts {
                message_id: id(IdKind::Message, "shared"),
            },
        ] {
            assert!(app.handle(request).is_err());
        }
    }
}

#[test]
fn mismatched_source_proof_fails_closed_and_semantic_fallback_is_explicit() {
    let mut read = Read::new("alpha");
    read.candidate.occurrence.as_mut().unwrap().source_id =
        SourceId::parse("other-source").unwrap();
    let expired = || false;
    assert!(
        ManagedApp::new(&read, context(&expired))
            .unwrap()
            .handle(search())
            .is_err()
    );
    let read = Read::new("alpha");
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let mut request = search();
    if let AppRequest::Search { mode, .. } = &mut request {
        *mode = RetrievalMode::Hybrid;
    }
    let response = app.handle(request).unwrap();
    assert!(
        response
            .partial
            .contains(&ManagedPartial::SemanticUnavailable)
    );
    assert!(matches!(
        response.response,
        AppResponse::Search {
            retrieval_mode: RetrievalMode::LexicalFallback,
            fallback_warning: Some(_),
            ..
        }
    ));
}

#[test]
fn retained_window_cannot_claim_exhaustion_or_issue_an_unsafe_cursor() {
    let mut read = Read::new("alpha");
    read.page_truncated = true;
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let response = app.handle(search()).unwrap();
    assert!(response.partial.contains(&ManagedPartial::RankingWindow));
    assert!(
        response
            .partial
            .contains(&ManagedPartial::ContinuationUnavailable)
    );
    assert!(
        matches!(response.response,AppResponse::Search{next_cursor:None,truncation,..} if truncation.truncated)
    );
}

#[test]
fn evidence_budget_caps_search_and_list_without_orphaned_proofs() {
    let mut read = Read::new("alpha");
    read.extra = Some(projection("second", "alpha second"));
    let expired = || false;
    let mut ctx = context(&expired);
    ctx.budget.max_evidence_spans = 1;
    let app = ManagedApp::new(&read, ctx).unwrap();
    let response = app.handle(search()).unwrap();
    let AppResponse::Search {
        hits, truncation, ..
    } = &response.response
    else {
        panic!()
    };
    assert_eq!(hits.len(), 1);
    assert_eq!(response.evidence.len(), 1);
    assert_eq!(hits[0].id, response.evidence[0].entity_id);
    assert_eq!(truncation.reason.as_deref(), Some("max_evidence_spans"));
    assert!(hits[0].suggested_next_commands.is_empty());
    let response = app
        .handle(AppRequest::List {
            limit: 10,
            cursor: None,
            budget: ResponseBudget::default(),
            sessions_only: false,
        })
        .unwrap();
    let AppResponse::List {
        entries,
        truncation,
        ..
    } = &response.response
    else {
        panic!()
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(response.evidence.len(), 1);
    assert_eq!(entries[0].id, response.evidence[0].entity_id);
    assert_eq!(truncation.reason.as_deref(), Some("max_evidence_spans"));
}

#[test]
fn handoff_keeps_exact_search_text_location_and_source_proofs_without_legacy_reads() {
    let mut read = Read::new("alpha exact original");
    read.candidate
        .occurrence
        .as_mut()
        .unwrap()
        .data
        .placement
        .span = Some(agent_session_grep_domain::EvidenceSpan { start: 12, end: 50 });
    let tool = handoff_tool(&read.candidate, "Read", "synthetic-file");
    read.graph_override = Some(vec![graph_record(
        read.candidate.clone(),
        vec![tool.clone()],
    )]);
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let input = app.prepare_handoff(handoff_request()).unwrap();
    let raw = input.as_input();
    assert_eq!(raw.hits[0].text.as_deref(), Some("alpha exact original"));
    assert_eq!(
        (
            raw.source_locations[0].byte_start,
            raw.source_locations[0].byte_end
        ),
        (Some(12), Some(50))
    );
    assert_eq!(raw.message_facts[0].role, "user");
    let result = input.generate().unwrap();
    assert_eq!(read.direct_calls.get(), 0);
    assert!(
        read.calls
            .borrow()
            .iter()
            .all(|(name, _)| matches!(*name, "query" | "graph"))
    );
    assert_eq!(result.evidence[0].proof, read.candidate.proof);
    assert!(result.evidence[0].related.contains(&tool.proof));
    assert_eq!(result.pack.evidence[0].text, "alpha exact original");
    assert_eq!(
        result.pack.evidence[0].source_document_id,
        id(IdKind::Document, "document").as_str()
    );
    assert_eq!(result.pack.tool_activity[0]["target"], "synthetic-file");
    let wire = serde_json::to_string(&result.pack).unwrap();
    assert!(!wire.contains("wrong direct representative"));
    assert!(!wire.contains("matched-source"));
    assert!(!wire.contains("private-activity"));
    assert!(
        result
            .pack
            .source_locators
            .iter()
            .all(|l| l.cursor.is_none())
    );
    assert!(
        result
            .partial
            .contains(&ManagedPartial::MetadataSearchUnavailable)
    );
    assert_eq!(result.snapshot, read.snapshot);
}

#[test]
fn handoff_intersection_covers_all_enrichment_and_filters_tool_values() {
    let mut read = Read::new("alpha exact original");
    read.candidate.message.timestamp = Some("2026-10-17T02:00:00Z".into());
    read.candidate.occurrence.as_mut().unwrap().data.timestamp =
        read.candidate.message.timestamp.clone();
    let tool = handoff_tool(&read.candidate, "Read", "permitted");
    let other = handoff_tool(&read.candidate, "Write", "not-requested");
    read.graph_override = Some(vec![graph_record(
        read.candidate.clone(),
        vec![tool, other],
    )]);
    let expired = || false;
    let mut ctx = context(&expired);
    ctx.intersection.filters.providers = vec![SearchProvider::Claude];
    ctx.intersection.filters.repo = Some("example.test/team/repo".into());
    ctx.intersection.filters.since =
        agent_session_grep_application::parse_search_instant("2026-10-17T01:00:00Z");
    ctx.intersection.filters.until =
        agent_session_grep_application::parse_search_instant("2026-10-17T03:00:00Z");
    ctx.intersection.facets.sidechain = SidechainFacet::MainOnly;
    ctx.intersection.session_id = Some(id(IdKind::Session, "session"));
    ctx.budget.max_evidence_spans = 1;
    let app = ManagedApp::new(&read, ctx).unwrap();
    let mut request = handoff_request();
    request.intersection.filters.providers = vec![SearchProvider::Claude, SearchProvider::Codex];
    request.intersection.facets.tool_name = Some("Read".into());
    request.intersection.include_system = true;
    let result = app.prepare_handoff(request).unwrap().generate().unwrap();
    for (_, query) in read.calls.borrow().iter() {
        assert_eq!(query.filters.providers, vec![SearchProvider::Claude]);
        assert_eq!(
            query.filters.repo.as_deref(),
            Some("example.test/team/repo")
        );
        assert_eq!(query.session_id, Some(id(IdKind::Session, "session")));
        assert!(query.filters.since.is_some() && query.filters.until.is_some());
        assert_eq!(query.facets.sidechain, SidechainFacet::MainOnly);
        assert_eq!(query.facets.tool_name.as_deref(), Some("Read"));
        assert!(!query.include_system);
    }
    assert_eq!(result.pack.tool_activity.len(), 1);
    assert_eq!(result.pack.tool_activity[0]["name"], "Read");
    assert!(result.intersection.as_ref().unwrap().filters.repo.is_some());
    read.calls.borrow_mut().clear();
    let mut request = handoff_request();
    request.intersection.filters.providers = vec![SearchProvider::Codex];
    let result = app.prepare_handoff(request).unwrap().generate().unwrap();
    assert!(result.intersection.is_none());
    assert!(read.calls.borrow().is_empty());
    assert!(result.pack.evidence.is_empty() && result.evidence.is_empty());
}

#[test]
fn handoff_does_not_borrow_enrichment_from_another_shared_source_or_rejected_evidence() {
    let mut read = Read::new("alpha allowed");
    let mut other = read.direct.clone();
    other.proof.source_id = SourceId::parse("other-source").unwrap();
    other.occurrence.as_mut().unwrap().source_id = other.proof.source_id.clone();
    let tool = handoff_tool(&other, "Read", "other-source-only");
    read.graph_override = Some(vec![graph_record(other, vec![tool])]);
    let expired = || false;
    let result = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .prepare_handoff(handoff_request())
        .unwrap()
        .generate()
        .unwrap();
    assert_eq!(result.pack.evidence[0].text, "alpha allowed");
    assert_eq!(
        result.evidence[0].proof.source_id,
        read.candidate.proof.source_id
    );
    assert!(result.pack.tool_activity.is_empty());
    assert!(
        result
            .partial
            .contains(&ManagedPartial::HandoffEnrichmentUnavailable)
    );
    read.no_hits = true;
    let result = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .prepare_handoff(handoff_request())
        .unwrap()
        .generate()
        .unwrap();
    assert!(result.pack.evidence.is_empty());
    assert!(result.pack.matched_sessions.is_empty());
    assert!(result.evidence.is_empty());
}

#[test]
fn handoff_pack_budget_drops_tools_and_proofs_with_their_evidence() {
    let mut read = Read::new("alpha one");
    let second = projection("second", "alpha two");
    read.extra = Some(second.clone());
    read.graph_override = Some(vec![
        graph_record(read.candidate.clone(), Vec::new()),
        graph_record(
            second.clone(),
            vec![handoff_tool(&second, "Read", "second-only")],
        ),
    ]);
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let mut request = handoff_request();
    request.max_tokens = 3;
    let result = app.prepare_handoff(request).unwrap().generate().unwrap();
    assert_eq!(result.pack.evidence.len(), 1);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.pack.mainline.len(), 1);
    assert_eq!(result.pack.matched_sessions[0].occurrences, 1);
    assert!(result.pack.tool_activity.is_empty());
    assert!(result.pack.truncation.truncated);
    assert_eq!(result.pack.truncation.dropped_count, 1);
    assert!(result.partial.contains(&ManagedPartial::ResponseBudget));
    let wire = serde_json::to_vec(&result.pack).unwrap();
    assert_eq!(result.pack.budget.used_bytes, wire.len() as u64);
    let mut request = handoff_request();
    request.max_evidence = 1;
    let result = app.prepare_handoff(request).unwrap().generate().unwrap();
    assert_eq!(result.evidence.len(), 1);
    assert!(result.pack.tool_activity.is_empty());
}

#[test]
fn handoff_redacts_original_text_tool_values_and_target_metadata_deterministically() {
    // Synthetic shape only; assembled at runtime so the literal never lands
    // in the source tree as credential-looking text.
    let secret = format!(
        "AKIA{}",
        "SYNTHETIC0EXAMPLE".chars().take(16).collect::<String>()
    );
    let secret = secret.as_str();
    let mut read = Read::new(&format!("alpha token {secret}"));
    read.graph_override = Some(vec![graph_record(
        read.candidate.clone(),
        vec![handoff_tool(&read.candidate, "Read", secret)],
    )]);
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let make_request = || {
        let mut request = handoff_request();
        request.query = format!("alpha {secret}");
        request.target = Some(agent_session_grep_ports::handoff::HandoffTarget {
            provider_id: "claude-code".into(),
            agent: None,
            suggested_command: Some(format!("example {secret}")),
        });
        request
    };
    let first = app
        .prepare_handoff(make_request())
        .unwrap()
        .generate()
        .unwrap();
    let second = app
        .prepare_handoff(make_request())
        .unwrap()
        .generate()
        .unwrap();
    let wire = serde_json::to_string(&first.pack).unwrap();
    assert!(!wire.contains(secret));
    assert!(wire.contains("[redacted:aws_access_key]"));
    assert!(first.pack.redaction.redacted_count >= 3);
    assert!(first.pack.target.as_ref().unwrap().agent.is_none());
    assert_eq!(wire, serde_json::to_string(&second.pack).unwrap());
    assert_eq!(first.evidence[0].proof, read.candidate.proof);
}

#[test]
fn handoff_deadline_is_inherited_by_prepare_enrichment_and_generate() {
    let read = Read::new("alpha");
    let expired = Cell::new(false);
    let clock = || expired.get();
    let app = ManagedApp::new(&read, context(&clock)).unwrap();
    let input = app.prepare_handoff(handoff_request()).unwrap();
    expired.set(true);
    assert!(input.generate().is_err());
    read.calls.borrow_mut().clear();
    assert!(app.prepare_handoff(handoff_request()).is_err());
    assert!(read.calls.borrow().is_empty());
    let check = || read.calls.borrow().iter().any(|(name, _)| *name == "graph");
    let app = ManagedApp::new(&read, context(&check)).unwrap();
    assert!(app.prepare_handoff(handoff_request()).is_err());
}

#[test]
fn handoff_inconsistent_revision_or_tools_fail_closed_and_graph_capacity_is_partial() {
    let expired = || false;
    let mut read = Read::new("alpha");
    let mut tool = handoff_tool(&read.candidate, "Read", "synthetic");
    tool.proof.source_id = SourceId::parse("wrong-source").unwrap();
    read.graph_override = Some(vec![graph_record(read.candidate.clone(), vec![tool])]);
    assert!(
        ManagedApp::new(&read, context(&expired))
            .unwrap()
            .prepare_handoff(handoff_request())
            .is_err()
    );
    read.graph_busy = true;
    let result = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .prepare_handoff(handoff_request())
        .unwrap()
        .generate()
        .unwrap();
    assert_eq!(result.pack.evidence[0].text, "alpha");
    assert!(
        result
            .partial
            .contains(&ManagedPartial::HandoffEnrichmentUnavailable)
    );
    assert!(result.pack.tool_activity.is_empty());
    read.candidate.proof.revision.catalog_incarnation = "different-incarnation".into();
    assert!(
        ManagedApp::new(&read, context(&expired))
            .unwrap()
            .prepare_handoff(handoff_request())
            .is_err()
    );
}

#[test]
fn handoff_whole_json_and_proofs_obey_tight_response_budget() {
    let text = format!("alpha {}", "\"\\界".repeat(20_000));
    let read = Read::new(&text);
    let expired = || false;
    let mut ctx = context(&expired);
    ctx.budget.max_response_bytes = 8192;
    ctx.budget.max_snippet_chars = 200;
    let app = ManagedApp::new(&read, ctx).unwrap();
    let result = app
        .prepare_handoff(handoff_request())
        .unwrap()
        .generate()
        .unwrap();
    let wire = serde_json::to_vec(&result.pack).unwrap();
    assert!(wire.len() + 1024 <= 8192);
    assert_eq!(wire.len() as u64, result.pack.budget.used_bytes);
    assert!(result.partial.contains(&ManagedPartial::ResponseBudget));
    assert_eq!(result.pack.evidence.len(), result.evidence.len());
    for evidence in result.pack.evidence {
        assert!(text.contains(&evidence.text));
    }
}

#[test]
fn handoff_conflicting_activities_are_omitted_and_pack_identity_binds_managed_scope() {
    let mut read = Read::new("alpha original");
    let first = handoff_tool(&read.candidate, "Read", "first");
    let mut conflict = first.clone();
    if let EntityData::Tool { activity, .. } = &mut conflict.data {
        activity.target = Some("conflicting".into());
    }
    read.graph_override = Some(vec![graph_record(
        read.candidate.clone(),
        vec![first, conflict],
    )]);
    let expired = || false;
    let first = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .prepare_handoff(handoff_request())
        .unwrap()
        .generate()
        .unwrap();
    assert!(first.pack.tool_activity.is_empty());
    assert!(
        first
            .partial
            .contains(&ManagedPartial::HandoffEnrichmentUnavailable)
    );
    assert_eq!(first.evidence[0].related.len(), 1); // document only
    let mut ctx = context(&expired);
    ctx.intersection.filters.repo = Some("example.test/team/repo".into());
    let scoped = ManagedApp::new(&read, ctx)
        .unwrap()
        .prepare_handoff(handoff_request())
        .unwrap()
        .generate()
        .unwrap();
    assert_ne!(first.pack.pack_id, scoped.pack.pack_id);
    read.snapshot.policy_epoch = 2;
    let newer = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .prepare_handoff(handoff_request())
        .unwrap()
        .generate()
        .unwrap();
    assert_ne!(first.pack.pack_id, newer.pack.pack_id);
}

#[test]
fn handoff_rejects_invalid_limits_and_semantic_fallback_stays_explicit() {
    let read = Read::new("alpha");
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    for invalid in 0..4 {
        let mut request = handoff_request();
        match invalid {
            0 => request.max_tokens = 0,
            1 => request.max_bytes = 4095,
            2 => request.max_evidence = 0,
            _ => request.query = "x".repeat(257),
        }
        assert!(app.prepare_handoff(request).is_err());
    }
    assert!(read.calls.borrow().is_empty());
    let mut request = handoff_request();
    request.mode = RetrievalMode::Hybrid;
    let result = app.prepare_handoff(request).unwrap().generate().unwrap();
    assert_eq!(
        result.pack.query.retrieval_mode,
        RetrievalMode::LexicalFallback
    );
    assert!(
        result
            .partial
            .contains(&ManagedPartial::SemanticUnavailable)
    );
    assert!(result.is_partial());
}

#[test]
fn session_list_preview_uses_source_scoped_endpoints_and_charges_evidence_budget() {
    let mut read = Read::new("first original user");
    read.extra = Some(projection("last", "last original user"));
    read.list_sessions = vec![session_projection(&read.candidate, Some("source title"))];
    let expired = || false;
    let mut ctx = context(&expired);
    ctx.intersection.filters.repo = Some("example.test/team/repo".into());
    let app = ManagedApp::new(&read, ctx).unwrap();
    let request = || AppRequest::List {
        limit: 10,
        cursor: None,
        budget: ResponseBudget::default(),
        sessions_only: true,
    };
    let response = app.handle(request()).unwrap();
    let AppResponse::List {
        entries,
        peeks,
        titles,
        ..
    } = &response.response
    else {
        panic!()
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(titles[0].as_deref(), Some("source title"));
    let peek = peeks[0].as_ref().unwrap();
    assert_eq!(peek.first_user_text.as_deref(), Some("first original user"));
    assert_eq!(peek.last_user_text.as_deref(), Some("last original user"));
    assert_eq!(
        response
            .evidence
            .iter()
            .filter(|p| p.occurrence.is_some())
            .count(),
        2
    );
    assert!(
        !response
            .partial
            .contains(&ManagedPartial::ListPreviewUnavailable)
    );
    assert_eq!(read.direct_calls.get(), 0);
    assert!(
        read.calls
            .borrow()
            .iter()
            .all(|(_, q)| q.filters.repo.as_deref() == Some("example.test/team/repo"))
    );
    let mut ctx = context(&expired);
    ctx.budget.max_evidence_spans = 1;
    let response = ManagedApp::new(&read, ctx)
        .unwrap()
        .handle(request())
        .unwrap();
    let AppResponse::List { peeks, .. } = &response.response else {
        panic!()
    };
    assert!(peeks[0].as_ref().unwrap().last_user_text.is_none());
    assert!(
        response
            .partial
            .contains(&ManagedPartial::ListPreviewUnavailable)
    );
}

#[test]
fn metadata_only_session_list_has_null_preview_without_fabricated_message_proof() {
    let mut read = Read::new("hidden source text");
    let mut session = session_projection(&read.candidate, Some("metadata title"));
    session.proof.source_id = SourceId::parse("metadata-source").unwrap();
    read.list_sessions = vec![session];
    let expired = || false;
    let response = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .handle(AppRequest::List {
            limit: 5,
            cursor: None,
            budget: ResponseBudget::default(),
            sessions_only: true,
        })
        .unwrap();
    let AppResponse::List { peeks, titles, .. } = &response.response else {
        panic!()
    };
    assert_eq!(titles[0].as_deref(), Some("metadata title"));
    assert!(peeks[0].as_ref().unwrap().first_user_text.is_none());
    assert!(peeks[0].as_ref().unwrap().last_user_text.is_none());
    assert_eq!(response.evidence.len(), 1);
    assert!(response.evidence[0].occurrence.is_none());
}

#[test]
fn cached_search_window_keeps_first_scores_proofs_and_snippets_after_append() {
    let mut read = Read::new("alpha original first");
    read.extra = Some(projection("second", "alpha original second"));
    let expired = || false;
    let mut request = search();
    if let AppRequest::Search { limit, budget, .. } = &mut request {
        *limit = 1;
        budget.max_items = 1;
    }
    let set = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .collect_candidates(request)
        .unwrap();
    assert_eq!(set.candidates.len(), 2);
    assert_eq!(set.request_now_ms, 1);
    let expected = set.candidates[1].hit.as_ref().unwrap().clone();
    read.candidate.message.text = "changed live text".into();
    read.snapshot.generation = 2;
    read.calls.borrow_mut().clear();
    let mut later = context(&expired);
    later.now_ms = 2_000_000_000_000;
    let app = ManagedApp::new(&read, later).unwrap();
    let result = app.render_candidates(search(), &set, 1).unwrap();
    let AppResponse::Search {
        hits, generation, ..
    } = result.response
    else {
        panic!()
    };
    assert_eq!(hits, vec![expected]);
    assert_eq!(generation, 1);
    assert_eq!(result.snapshot.generation, 1);
    assert_eq!(result.evidence, set.candidates[1].evidence);
    assert!(read.calls.borrow().is_empty());
    read.snapshot.destructive_epoch = 1;
    assert!(
        ManagedApp::new(&read, context(&expired))
            .unwrap()
            .render_candidates(search(), &set, 0)
            .is_err()
    );
}

#[test]
fn cached_group_counts_and_session_previews_do_not_enrich_again() {
    let mut read = Read::new("first cached user");
    read.extra = Some(projection("last", "last cached user"));
    read.list_sessions = vec![session_projection(&read.candidate, Some("cached title"))];
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let mut grouped = search();
    if let AppRequest::Search {
        group_by_session, ..
    } = &mut grouped
    {
        *group_by_session = true;
    }
    let group = app.collect_candidates(grouped).unwrap();
    assert_eq!(group.candidates.len(), 1);
    assert_eq!(group.candidates[0].hit.as_ref().unwrap().occurrences, 2);
    let list = || AppRequest::List {
        limit: 1,
        cursor: None,
        budget: ResponseBudget::default(),
        sessions_only: true,
    };
    let set = app.collect_candidates(list()).unwrap();
    assert!(set.candidates[0].peek.is_some());
    read.candidate.message.text = "new first".into();
    read.extra = None;
    read.list_sessions.clear();
    read.snapshot.generation = 2;
    read.calls.borrow_mut().clear();
    let result = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .render_candidates(list(), &set, 0)
        .unwrap();
    let AppResponse::List {
        peeks,
        titles,
        generation,
        ..
    } = result.response
    else {
        panic!()
    };
    assert_eq!(titles[0].as_deref(), Some("cached title"));
    assert_eq!(
        peeks[0].as_ref().unwrap().last_user_text.as_deref(),
        Some("last cached user")
    );
    assert_eq!(generation, 1);
    assert!(read.calls.borrow().is_empty());
}

#[test]
fn metadata_search_and_cached_render_keep_session_proof_without_message_text() {
    let mut read = Read::new("unrelated message");
    read.no_hits = true;
    let metadata = session_projection(&read.candidate, Some("alpha metadata"));
    read.metadata_hits.push(SessionMetadataHit {
        projection: metadata.clone(),
        score: 1.0,
        fields: vec![SessionMetadataField::Title],
    });
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let set = app.collect_candidates(search()).unwrap();
    assert_eq!(set.candidates.len(), 1);
    let expected = set.candidates[0].hit.as_ref().unwrap().clone();
    assert_eq!(expected.id.kind(), IdKind::Session);
    assert!(expected.text.is_none());
    assert_eq!(expected.why_matched, ["session_metadata", "session_title"]);
    assert_eq!(set.candidates[0].evidence[0].proof, metadata.proof);
    assert!(set.candidates[0].evidence[0].occurrence.is_none());
    read.metadata_hits.clear();
    read.snapshot.generation = 2;
    read.calls.borrow_mut().clear();
    let response = ManagedApp::new(&read, context(&expired))
        .unwrap()
        .render_candidates(search(), &set, 0)
        .unwrap();
    assert!(
        matches!(response.response, AppResponse::Search { hits, generation: 1, .. } if hits == vec![expected])
    );
    assert!(read.calls.borrow().is_empty());
    let mut restricted = context(&expired);
    restricted.intersection.filters.providers = vec![SearchProvider::Codex];
    assert!(
        ManagedApp::new(&read, restricted)
            .unwrap()
            .render_candidates(search(), &set, 0)
            .is_err()
    );
}

#[test]
fn metadata_does_not_inflate_message_groups_or_enter_handoff_evidence() {
    let mut read = Read::new("alpha first");
    read.extra = Some(projection("second", "alpha second"));
    read.metadata_hits.push(SessionMetadataHit {
        projection: session_projection(&read.candidate, Some("alpha title")),
        score: 1.0,
        fields: vec![SessionMetadataField::Title],
    });
    let expired = || false;
    let app = ManagedApp::new(&read, context(&expired)).unwrap();
    let mut request = search();
    if let AppRequest::Search {
        group_by_session, ..
    } = &mut request
    {
        *group_by_session = true;
    }
    let set = app.collect_candidates(request).unwrap();
    assert_eq!(set.candidates.len(), 1);
    assert_eq!(set.candidates[0].hit.as_ref().unwrap().occurrences, 2);
    assert_eq!(set.candidates[0].entry.id().kind(), IdKind::Message);
    read.calls.borrow_mut().clear();
    let input = app.prepare_handoff(handoff_request()).unwrap();
    assert!(
        input
            .partial
            .contains(&ManagedPartial::MetadataSearchUnavailable)
    );
    assert!(
        read.calls
            .borrow()
            .iter()
            .all(|(name, _)| *name != "metadata")
    );
}
