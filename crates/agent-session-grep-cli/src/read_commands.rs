//! Typed read commands shared by the CLI dispatcher and the loopback Web API.
//!
//! The Web surface used to translate query parameters into synthetic argv and
//! hand them back to [`crate::dispatch`]. That made a request value equal to a
//! CLI flag ambiguous, so the HTTP layer needed a hand-maintained denylist that
//! had to track every parser change. The values below are constructed once by
//! each front end and executed here without any string-to-flag round trip.

use agent_session_grep_adapters_sqlite::SqliteStore;
use agent_session_grep_application::{
    AppRequest, AppResponse, ContextLevel, ResponseBudget,
    handoff_pack::{HandoffInput, resolve_source_locations},
};
use agent_session_grep_domain::{ContextPolicy, IdKind, StableId};
use agent_session_grep_ports::{
    RetrievalMode, SearchFacets, SearchFilters, SidechainFacet, handoff::HandoffFilters,
};

/// The rendered projection every read surface returns.
pub(crate) type Rendered = (
    crate::protocol::Outcome,
    serde_json::Value,
    crate::protocol::Page,
    Vec<String>,
);

pub(crate) const DEFAULT_SEARCH_LIMIT: usize = 20;
pub(crate) const DEFAULT_HANDOFF_SEARCH_LIMIT: usize = 50;
pub(crate) const DEFAULT_HANDOFF_EVIDENCE: usize = 20;
pub(crate) const DEFAULT_HANDOFF_TOKENS: usize = 8_000;
pub(crate) const DEFAULT_HANDOFF_BYTES: usize = 2_000_000;

/// A fully validated legacy search request.
#[derive(Debug)]
pub(crate) struct SearchCommand {
    pub(crate) query: String,
    pub(crate) filters: SearchFilters,
    pub(crate) facets: SearchFacets,
    pub(crate) limit: usize,
    pub(crate) cursor: Option<String>,
    pub(crate) budget: ResponseBudget,
    pub(crate) include_system: bool,
    pub(crate) group_by_session: bool,
    pub(crate) mode: RetrievalMode,
    /// Human output adds resume columns after rendering; machine surfaces do
    /// not. This is a projection choice, never a parser choice.
    pub(crate) attach_session_rows: bool,
}

pub(crate) fn search(
    store: &SqliteStore,
    command: SearchCommand,
) -> Result<Rendered, crate::CliError> {
    let SearchCommand {
        query,
        filters,
        facets,
        limit,
        cursor,
        budget,
        include_system,
        group_by_session,
        mode,
        attach_session_rows,
    } = command;
    let query_embedding =
        crate::prepare_search_embedding(store, mode, &query).map_err(crate::CliError)?;
    // Per-request repo probe: the Web server is long-lived, while the shell it
    // was started from can change remotes. Dispatch, MCP, and Web all share
    // this call instead of caching a stale slug.
    let repo_slug = crate::current_repo_slug();
    let request = AppRequest::Search {
        query,
        filters,
        facets: facets.clone(),
        limit,
        cursor,
        budget,
        include_system,
        group_by_session,
        mode,
        query_embedding,
    };
    let response = if mode == RetrievalMode::Lexical {
        crate::resume_app_with_repo(store, repo_slug).handle(request)?
    } else {
        crate::resume_semantic_app_with_repo(store, repo_slug).handle(request)?
    };
    let (outcome, mut data, page, warnings) = crate::render(response);
    if attach_session_rows {
        crate::attach_session_resume_rows(store, &mut data)?;
    }
    if !facets.is_default() {
        let echo = data.as_object_mut().expect("search data is an object");
        echo.insert(
            "facets".into(),
            serde_json::json!({
                "sidechain": facets.sidechain.as_str(),
                "tool_kind": facets.tool_kind,
                "tool_name": facets.tool_name,
            }),
        );
    }
    Ok((outcome, data, page, warnings))
}

/// A fully validated deterministic handoff request.
#[derive(Debug)]
pub(crate) struct HandoffCommand {
    pub(crate) query: String,
    pub(crate) filters: SearchFilters,
    pub(crate) search_limit: usize,
    pub(crate) max_evidence: usize,
    pub(crate) max_tokens: usize,
    pub(crate) max_bytes: usize,
}

pub(crate) fn handoff(
    store: &SqliteStore,
    command: HandoffCommand,
) -> Result<Rendered, crate::CliError> {
    let HandoffCommand {
        query,
        filters,
        search_limit,
        max_evidence,
        max_tokens,
        max_bytes,
    } = command;
    validate_handoff_budget(max_evidence, max_tokens, max_bytes)?;

    // Retrieval is the assembly source: a wide fetch budget and full-length
    // snippets let the pack builder apply the caller's budget exactly once.
    let app = crate::resume_app_with_repo(store, crate::current_repo_slug());
    let response = app.handle(AppRequest::Search {
        query: query.clone(),
        filters: filters.clone(),
        facets: SearchFacets::default(),
        limit: search_limit,
        cursor: None,
        budget: ResponseBudget {
            max_items: search_limit,
            max_response_bytes: 64 * 1024 * 1024,
            max_snippet_chars: 65536,
            max_messages: search_limit,
            max_evidence_spans: 512,
        },
        include_system: false,
        group_by_session: false,
        mode: RetrievalMode::Lexical,
        query_embedding: None,
    })?;
    let (hits, generation) = match response {
        AppResponse::Search {
            hits, generation, ..
        } => (hits, generation),
        _ => {
            return Err(crate::CliError(crate::protocol::ProtocolError::new(
                crate::protocol::CanonicalCode::Internal,
                "handoff: unexpected search response",
            )));
        }
    };
    let source_locations = resolve_source_locations(store, &hits).map_err(crate::CliError::from)?;
    let hit_ids: Vec<_> = hits.iter().map(|hit| hit.id.clone()).collect();
    let tool_activities = store
        .tool_activities_for_messages(&hit_ids)
        .map_err(crate::CliError::from)?;
    let message_facts = store
        .message_facts_for(&hit_ids)
        .map_err(crate::CliError::from)?
        .into_iter()
        .map(|(message_id, role, is_sidechain)| {
            agent_session_grep_application::handoff_pack::MessageFact {
                message_id,
                role,
                is_sidechain,
            }
        })
        .collect::<Vec<_>>();
    let pack = agent_session_grep_application::handoff_pack::generate_deterministic(HandoffInput {
        query_terms: std::slice::from_ref(&query),
        retrieval_mode: RetrievalMode::Lexical,
        filters: HandoffFilters {
            providers: filters
                .providers
                .iter()
                .map(|provider| provider.as_str().to_string())
                .collect(),
            since: filters
                .since
                .map(|instant| format!("{}.{:09}Z", instant.unix_seconds, instant.nanosecond)),
            until: filters
                .until
                .map(|instant| format!("{}.{:09}Z", instant.unix_seconds, instant.nanosecond)),
        },
        hits: &hits,
        source_locations: &source_locations,
        tool_activities: &tool_activities,
        message_facts: &message_facts,
        catalog_generation: generation,
        max_tokens: max_tokens as u64,
        max_bytes: max_bytes as u64,
        max_evidence,
        target: None,
    });
    let outcome = if pack.truncation.truncated {
        crate::protocol::Outcome::Partial
    } else {
        crate::protocol::Outcome::Success
    };
    let data = serde_json::to_value(&pack).map_err(|_| {
        crate::CliError(crate::protocol::ProtocolError::new(
            crate::protocol::CanonicalCode::Internal,
            "handoff: pack serialization failed",
        ))
    })?;
    Ok((outcome, data, crate::protocol::Page::default(), Vec::new()))
}

pub(crate) fn validate_handoff_budget(
    max_evidence: usize,
    max_tokens: usize,
    max_bytes: usize,
) -> Result<(), crate::CliError> {
    if max_evidence == 0 {
        return Err(crate::CliError::usage(
            "max_evidence must be a positive integer",
        ));
    }
    if max_tokens == 0 {
        return Err(crate::CliError::usage(
            "max_tokens must be a positive integer",
        ));
    }
    if max_bytes < agent_session_grep_application::budget::MIN_RESPONSE_BYTES {
        return Err(crate::CliError::usage(format!(
            "max_bytes must be at least {}",
            agent_session_grep_application::budget::MIN_RESPONSE_BYTES
        )));
    }
    Ok(())
}

/// A fully validated context assembly request.
#[derive(Debug)]
pub(crate) struct ContextCommand {
    pub(crate) session_id: StableId,
    pub(crate) policy: ContextPolicy,
    pub(crate) level: ContextLevel,
    pub(crate) budget: ResponseBudget,
}

pub(crate) fn context(
    store: &SqliteStore,
    command: ContextCommand,
) -> Result<Rendered, crate::CliError> {
    let response = crate::resume_app(store).handle(AppRequest::Context {
        session_id: command.session_id,
        policy: command.policy,
        level: command.level,
        budget: command.budget,
    })?;
    Ok(crate::render(response))
}

pub(crate) fn show(store: &SqliteStore, id: StableId) -> Result<Rendered, crate::CliError> {
    let response = crate::resume_app(store).handle(AppRequest::Show { id })?;
    if matches!(&response, AppResponse::Show { payload: None }) {
        return Err(crate::CliError(crate::protocol::ProtocolError::new(
            crate::protocol::CanonicalCode::NotFound,
            "entity not found",
        )));
    }
    Ok(crate::render(response))
}

pub(crate) fn status(store: &SqliteStore) -> Result<Rendered, crate::CliError> {
    let response = crate::resume_app(store).handle(AppRequest::Status)?;
    Ok(crate::render(response))
}

/// Build the CLI/Web resume preview without acknowledging the first-run
/// marker or executing anything. The caller that can execute (`resume --yes`)
/// owns the acknowledgement state.
pub(crate) fn resume_preview(
    store: &SqliteStore,
    session_id: StableId,
) -> Result<
    (
        serde_json::Value,
        agent_session_grep_application::resume::ResumePreview,
    ),
    crate::CliError,
> {
    let response = crate::resume_app(store).handle(AppRequest::GetSessionResume {
        session_id: session_id.clone(),
    })?;
    let AppResponse::SessionResume(metadata) = response else {
        return Err(crate::CliError(crate::protocol::ProtocolError::new(
            crate::protocol::CanonicalCode::Internal,
            "resume: unexpected response",
        )));
    };
    let preview = agent_session_grep_application::resume::build_resume_descriptor(&metadata);
    let data = serde_json::json!({
        "session_id": metadata.session_id.as_str(),
        "provider_id": metadata.provider_id,
        "available": preview.available,
        "command": if preview.command_string.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::json!(preview.command_string)
        },
        "working_directory": preview.descriptor.working_directory,
        "permission_mode": preview.descriptor.permission_mode,
        "permission_mode_verified": false,
        "unavailable_reason": preview.unavailable_reason,
        "executed": false,
    });
    Ok((data, preview))
}

/// Parse the shared closed vocabulary used by CLI, Web, and MCP.
pub(crate) fn retrieval_mode(value: &str) -> Option<RetrievalMode> {
    match value {
        "lexical" => Some(RetrievalMode::Lexical),
        "semantic" => Some(RetrievalMode::Semantic),
        "hybrid" => Some(RetrievalMode::Hybrid),
        _ => None,
    }
}

pub(crate) fn sidechain_facet(value: &str) -> Option<SidechainFacet> {
    match value {
        "include" => Some(SidechainFacet::Include),
        "main_only" => Some(SidechainFacet::MainOnly),
        "subagent_only" => Some(SidechainFacet::SubagentOnly),
        _ => None,
    }
}

pub(crate) const TOOL_KINDS: &[&str] = &["file", "command", "web", "query", "unknown"];

pub(crate) fn valid_tool_kind(value: &str) -> bool {
    TOOL_KINDS.contains(&value)
}

pub(crate) fn context_policy(value: &str) -> Option<ContextPolicy> {
    match value {
        "mainline" => Some(ContextPolicy::Mainline),
        "full" => Some(ContextPolicy::Full),
        _ => None,
    }
}

pub(crate) fn context_level(value: &str) -> Option<ContextLevel> {
    match value {
        "raw" => Some(ContextLevel::Raw),
        "talks" => Some(ContextLevel::Talks),
        "sessions" => Some(ContextLevel::Sessions),
        _ => None,
    }
}

pub(crate) fn session_id(wire: &str) -> Result<StableId, crate::CliError> {
    StableId::from_wire(wire)
        .filter(|id| id.kind() == IdKind::Session)
        .ok_or_else(|| crate::CliError::usage("not a valid session id"))
}

pub(crate) fn entity_id(wire: &str) -> Result<StableId, crate::CliError> {
    StableId::from_wire(wire).ok_or_else(|| crate::CliError::usage("not a valid entity id"))
}
