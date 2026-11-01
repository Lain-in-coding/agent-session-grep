//! Managed CLI composition: one authorized catalog snapshot, shared AppResponse
//! rendering, bounded safe provenance, and the subprocess emission boundary.
use crate::{
    CliError, ProtocolError, arg, budget_from_flags, extract_flag, extract_repeated_flag,
    managed_emit, no_extra_args,
    protocol::{self, CanonicalCode, Outcome, OutputMode},
    redaction, render, search_filters_from_flags, take_bool_flag,
};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed::{ManagedRead, SnapshotFreshness},
    managed_cache::{
        CacheBinding, CacheError, CachePageRequest, CacheSetInsert, InsertOutcome, ManagedCache,
    },
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity, SharedGuard},
    managed_store::ManagedStore,
};
use agent_session_grep_application::{
    AppError, AppRequest, AppResponse, ContextLevel, ResponseBudget,
    managed::{
        ManagedApp, ManagedCandidateSet, ManagedEvidence, ManagedHandoffRequest, ManagedPartial,
        ManagedRequestContext, ManagedResponse, provenance_row,
    },
};
use agent_session_grep_domain::{ContextPolicy, IdKind, StableId};
use agent_session_grep_ports::{
    PortError, RetrievalMode, SearchFacets, SearchFilters, SearchProvider, SidechainFacet,
    control::{
        BackgroundControl, BackgroundFailure, ControlId, ControlStatus, ControlStore,
        DesiredUpdates, LatestAdmission, LatestBarrier, LatestRequest, MaintenanceState,
        PolicyEpoch, RequestIntersection, SelectionRevision, UpdateState,
    },
    managed::{
        EntityData, EntityKind, ProjectionListEntry, ProjectionQuery, ProjectionRead, ReadSnapshot,
    },
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const DEFAULT_ITEMS: usize = 5;
const DEFAULT_FRAME_BYTES: usize = 8192;
const MAX_RENDERS: usize = 8;

fn invalid() -> CliError {
    CliError(ProtocolError::new(
        CanonicalCode::InvalidRequest,
        "invalid managed read request",
    ))
}
fn unsupported() -> CliError {
    CliError(ProtocolError::new(
        CanonicalCode::CapabilityNotSupported,
        "managed command is not available",
    ))
}
fn private_port(error: PortError) -> CliError {
    let code = ProtocolError::from_private_port_error(error).code;
    CliError(ProtocolError::new(
        code,
        "managed read could not be completed",
    ))
}
fn private_app(error: AppError) -> CliError {
    if let AppError::Port(error) = error {
        return private_port(error);
    }
    let mapped = ProtocolError::from(error);
    CliError(ProtocolError::new(
        mapped.code,
        "managed read could not be completed",
    ))
}
fn boundary_error() -> CliError {
    CliError(ProtocolError::new(
        CanonicalCode::SchemaIncompatible,
        "managed evidence is unavailable",
    ))
}

/// Content-free classification for an evidence frame proven withheld before
/// any output byte. Only contention is retryable; a changed policy or a broken
/// helper keeps its own category so clients do not retry permanent failures.
pub(crate) fn withheld_emission_error(kind: managed_emit::EmissionFailureKind) -> ProtocolError {
    use managed_emit::EmissionFailureKind as Kind;
    match kind {
        Kind::Blocked | Kind::Deadline => ProtocolError::new(
            CanonicalCode::WriterBusy,
            "managed response was withheld before output; retry the request",
        ),
        Kind::PolicyChanged => ProtocolError::new(
            CanonicalCode::SchemaIncompatible,
            "managed policy changed before output; send a new request",
        ),
        Kind::StorageOrIo => ProtocolError::new(
            CanonicalCode::SourceIo,
            "managed response could not be emitted",
        ),
        Kind::InvalidFrame | Kind::TerminationUnconfirmed => ProtocolError::new(
            CanonicalCode::Internal,
            "managed response could not be emitted",
        ),
    }
}

struct Request {
    command: &'static str,
    operation: Operation,
    intersection: ProjectionQuery,
    budget: ResponseBudget,
    frame_bytes: usize,
    latest: Option<u32>,
    override_data: Option<Value>,
    cursor: Option<String>,
    now_ms: i64,
}
enum Operation {
    Handoff {
        query: String,
        limit: usize,
        mode: RetrievalMode,
        options: HandoffOptions,
    },
    Search {
        query: String,
        group: bool,
        mode: RetrievalMode,
    },
    Get {
        id: StableId,
        show: bool,
    },
    List {
        limit: usize,
        sessions_only: bool,
    },
    Context {
        id: StableId,
        policy: ContextPolicy,
        level: ContextLevel,
    },
    Message {
        id: StableId,
        session: Option<StableId>,
        around: usize,
    },
    Resume {
        id: StableId,
    },
    Status,
    Typed(Box<AppRequest>),
}
impl Request {
    fn app_request(&self, budget: &ResponseBudget) -> AppRequest {
        match &self.operation {
            Operation::Handoff {
                query, limit, mode, ..
            } => AppRequest::Search {
                query: query.clone(),
                filters: self.intersection.filters.clone(),
                facets: self.intersection.facets.clone(),
                limit: (*limit).min(budget.max_items),
                cursor: None,
                budget: budget.clone(),
                include_system: self.intersection.include_system,
                group_by_session: false,
                mode: *mode,
                query_embedding: None,
            },
            Operation::Search { query, group, mode } => AppRequest::Search {
                query: query.clone(),
                filters: self.intersection.filters.clone(),
                facets: self.intersection.facets.clone(),
                limit: budget.max_items,
                cursor: None,
                budget: budget.clone(),
                include_system: self.intersection.include_system,
                group_by_session: *group,
                mode: *mode,
                query_embedding: None,
            },
            Operation::Get { id, show: false } => AppRequest::Get { id: id.clone() },
            Operation::Get { id, show: true } => AppRequest::Show { id: id.clone() },
            Operation::List {
                limit,
                sessions_only,
            } => AppRequest::List {
                limit: (*limit).min(budget.max_items),
                cursor: None,
                budget: budget.clone(),
                sessions_only: *sessions_only,
            },
            Operation::Context { id, policy, level } => AppRequest::Context {
                session_id: id.clone(),
                policy: *policy,
                level: *level,
                budget: budget.clone(),
            },
            Operation::Message {
                id,
                session,
                around,
            } => AppRequest::Message {
                message_id: id.clone(),
                session_id: session.clone(),
                around: *around,
                budget: budget.clone(),
            },
            Operation::Resume { id } => AppRequest::GetSessionResume {
                session_id: id.clone(),
            },
            Operation::Status => AppRequest::Status,
            Operation::Typed(request) => {
                let mut request = request.as_ref().clone();
                match &mut request {
                    AppRequest::Search { budget: b, .. }
                    | AppRequest::List { budget: b, .. }
                    | AppRequest::Context { budget: b, .. }
                    | AppRequest::Message { budget: b, .. } => *b = budget.clone(),
                    _ => {}
                }
                match &mut request {
                    AppRequest::Search { cursor, .. } | AppRequest::List { cursor, .. } => {
                        *cursor = None
                    }
                    _ => {}
                }
                request
            }
        }
    }
}

fn entity(value: &str, kind: Option<IdKind>) -> Result<StableId, CliError> {
    StableId::from_wire(value)
        .filter(|id| {
            id.validate() && id.kind() != IdKind::Source && kind.is_none_or(|k| k == id.kind())
        })
        .ok_or_else(invalid)
}
fn parse(rest: &[String], now_ms: i64) -> Result<Request, CliError> {
    let command = match rest.first().map(String::as_str) {
        Some("handoff") => "handoff",
        Some("search") => "search",
        Some("get") => "get",
        Some("show") => "show",
        Some("list") => "list",
        Some("status") => "status",
        Some("context") => "context",
        Some("get-message") => "get-message",
        Some("get-session-resume") => "get-session-resume",
        _ => return Err(unsupported()),
    };
    let mut args = rest.to_vec();
    let cursor = extract_flag(&mut args, "--cursor").map_err(|_| invalid())?;
    if cursor
        .as_ref()
        .is_some_and(|s| s.len() > 192 || !s.starts_with("asgmc1."))
        || (cursor.is_some() && !matches!(command, "search" | "list"))
    {
        return Err(cursor_error());
    }
    let max_items = extract_flag(&mut args, "--max-items").map_err(|_| invalid())?;
    let max_bytes = extract_flag(&mut args, "--max-bytes").map_err(|_| invalid())?;
    let max_messages = extract_flag(&mut args, "--max-messages").map_err(|_| invalid())?;
    let mut budget = budget_from_flags(
        max_items.as_deref(),
        max_bytes.as_deref(),
        max_messages.as_deref(),
    )
    .map_err(|_| invalid())?;
    if max_items.is_none() {
        budget.max_items = DEFAULT_ITEMS;
    }
    if max_messages.is_none() {
        budget.max_messages = DEFAULT_ITEMS;
    }
    if max_bytes.is_none() {
        budget.max_response_bytes = DEFAULT_FRAME_BYTES;
    }
    if budget.max_response_bytes > managed_emit::MAX_FRAME_BYTES {
        return Err(invalid());
    }
    budget.max_snippet_chars = 512;
    budget.max_evidence_spans = budget
        .max_items
        .max(budget.max_messages)
        .saturating_mul(4)
        .min(512);
    budget.validate().map_err(|_| invalid())?;
    let frame_bytes = budget.max_response_bytes;
    let providers = extract_repeated_flag(&mut args, "--provider").map_err(|_| invalid())?;
    let since = extract_flag(&mut args, "--since").map_err(|_| invalid())?;
    let until = extract_flag(&mut args, "--until").map_err(|_| invalid())?;
    let repo = extract_flag(&mut args, "--repo").map_err(|_| invalid())?;
    let filters = search_filters_from_flags(
        &providers,
        since.as_deref(),
        until.as_deref(),
        repo.as_deref(),
        now_ms,
    )
    .map_err(|_| invalid())?;
    if filters
        .since
        .zip(filters.until)
        .is_some_and(|(a, b)| a >= b)
    {
        return Err(invalid());
    }
    let include_system = take_bool_flag(&mut args, "--include-system");
    let main = take_bool_flag(&mut args, "--main-only");
    let subagent = take_bool_flag(&mut args, "--subagent-only");
    let sidechain = take_bool_flag(&mut args, "--include-sidechain");
    if (main && subagent) || (sidechain && (main || subagent)) {
        return Err(invalid());
    }
    let tool_kind = extract_flag(&mut args, "--tool-kind").map_err(|_| invalid())?;
    if tool_kind
        .as_deref()
        .is_some_and(|s| !matches!(s, "file" | "command" | "web" | "query" | "unknown"))
    {
        return Err(invalid());
    }
    let tool_name = extract_flag(&mut args, "--tool-name").map_err(|_| invalid())?;
    if tool_name
        .as_ref()
        .is_some_and(|s| s.trim().is_empty() || s.len() > 256)
    {
        return Err(invalid());
    }
    let facets = SearchFacets {
        sidechain: if main {
            SidechainFacet::MainOnly
        } else if subagent {
            SidechainFacet::SubagentOnly
        } else {
            SidechainFacet::Include
        },
        tool_kind,
        tool_name,
    };
    let latest = take_bool_flag(&mut args, "--latest");
    let wait = extract_flag(&mut args, "--max-wait-ms")
        .map_err(|_| invalid())?
        .map(|n| n.parse::<u64>().map_err(|_| invalid()))
        .transpose()?;
    let latest = latest_wait(latest, wait)?;
    if latest.is_some() && cursor.is_some() {
        return Err(cursor_error());
    }
    let operation = match command {
        "handoff" => {
            let max_tokens = extract_flag(&mut args, "--max-tokens")
                .map_err(|_| invalid())?
                .map(|v| v.parse::<u64>().map_err(|_| invalid()))
                .transpose()?
                .unwrap_or(2048);
            let max_evidence = extract_flag(&mut args, "--max-evidence")
                .map_err(|_| invalid())?
                .map(|v| v.parse::<usize>().map_err(|_| invalid()))
                .transpose()?
                .unwrap_or(DEFAULT_ITEMS);
            let mode = match extract_flag(&mut args, "--mode")
                .map_err(|_| invalid())?
                .as_deref()
            {
                None | Some("lexical") => RetrievalMode::Lexical,
                Some("semantic") => RetrievalMode::Semantic,
                Some("hybrid") => RetrievalMode::Hybrid,
                _ => return Err(invalid()),
            };
            no_extra_args(&args, 1, "handoff").map_err(|_| invalid())?;
            let query = arg(&args, 1, "handoff").map_err(|_| invalid())?.to_owned();
            if max_tokens == 0 || max_evidence == 0 || query.chars().count() > 256 {
                return Err(invalid());
            }
            Operation::Handoff {
                query,
                limit: budget.max_items,
                mode,
                options: HandoffOptions {
                    max_tokens,
                    max_evidence,
                },
            }
        }
        "search" => {
            let group = take_bool_flag(&mut args, "--group-by-session");
            let mode = match extract_flag(&mut args, "--mode")
                .map_err(|_| invalid())?
                .as_deref()
            {
                None | Some("lexical") => RetrievalMode::Lexical,
                Some("semantic") => RetrievalMode::Semantic,
                Some("hybrid") => RetrievalMode::Hybrid,
                _ => return Err(invalid()),
            };
            no_extra_args(&args, 1, "search").map_err(|_| invalid())?;
            let query = arg(&args, 1, "search").map_err(|_| invalid())?.to_string();
            agent_session_grep_application::validate_search_request(
                &query,
                &filters,
                budget.max_items,
                &budget,
            )
            .map_err(|_| invalid())?;
            Operation::Search { query, group, mode }
        }
        "get" | "show" | "get-session-resume" => {
            no_extra_args(&args, 1, command).map_err(|_| invalid())?;
            let id = entity(
                arg(&args, 1, command).map_err(|_| invalid())?,
                (command == "get-session-resume").then_some(IdKind::Session),
            )?;
            if command == "get-session-resume" {
                Operation::Resume { id }
            } else {
                Operation::Get {
                    id,
                    show: command == "show",
                }
            }
        }
        "list" => {
            let sessions_only = take_bool_flag(&mut args, "--sessions-only");
            no_extra_args(&args, 1, command).map_err(|_| invalid())?;
            let limit = args
                .get(1)
                .map(|s| s.parse::<usize>().map_err(|_| invalid()))
                .transpose()?
                .unwrap_or(budget.max_items);
            if limit == 0 {
                return Err(invalid());
            }
            Operation::List {
                limit,
                sessions_only,
            }
        }
        "status" => {
            no_extra_args(&args, 0, command).map_err(|_| invalid())?;
            Operation::Status
        }
        "context" => {
            let policy = match extract_flag(&mut args, "--policy")
                .map_err(|_| invalid())?
                .as_deref()
            {
                None | Some("mainline") => ContextPolicy::Mainline,
                Some("full") => ContextPolicy::Full,
                _ => return Err(invalid()),
            };
            let level = match extract_flag(&mut args, "--level")
                .map_err(|_| invalid())?
                .as_deref()
            {
                None | Some("raw") => ContextLevel::Raw,
                Some("talks") => ContextLevel::Talks,
                Some("sessions") => ContextLevel::Sessions,
                _ => return Err(invalid()),
            };
            no_extra_args(&args, 1, command).map_err(|_| invalid())?;
            Operation::Context {
                id: entity(
                    arg(&args, 1, command).map_err(|_| invalid())?,
                    Some(IdKind::Session),
                )?,
                policy,
                level,
            }
        }
        "get-message" => {
            let session = extract_flag(&mut args, "--session")
                .map_err(|_| invalid())?
                .map(|s| entity(&s, Some(IdKind::Session)))
                .transpose()?;
            let around = extract_flag(&mut args, "--around")
                .map_err(|_| invalid())?
                .map(|s| s.parse::<usize>().map_err(|_| invalid()))
                .transpose()?
                .unwrap_or(0);
            if around > 512 {
                return Err(invalid());
            }
            no_extra_args(&args, 1, command).map_err(|_| invalid())?;
            Operation::Message {
                id: entity(
                    arg(&args, 1, command).map_err(|_| invalid())?,
                    Some(IdKind::Message),
                )?,
                session,
                around,
            }
        }
        _ => return Err(unsupported()),
    };
    // Parent helpers remove recognized flags; unknown/repeated switches cannot
    // become an extra positional identifier or silently broaden the request.
    if args.iter().skip(1).any(|v| v.starts_with("--")) {
        return Err(invalid());
    }
    Ok(Request {
        command,
        operation,
        intersection: ProjectionQuery {
            filters,
            facets,
            include_system,
            session_id: None,
        },
        budget,
        frame_bytes,
        latest,
        override_data: None,
        cursor,
        now_ms,
    })
}

struct PreparedFrame {
    bytes: Vec<u8>,
    payload: Value,
    outcome: Outcome,
    epoch: PolicyEpoch,
}

/// One request only: no database handles survive the returned emission authority.
pub(crate) struct McpReadInput {
    /// Identity pinned when the MCP connection was established, not rediscovered
    /// from the current pathname for each request.
    pub identity: McpReadIdentity,
    pub request: AppRequest,
    pub filters: SearchFilters,
    pub rpc_id: Value,
    pub latest: bool,
    pub max_wait_ms: Option<u64>,
    pub started: Instant,
    /// Trusted static tool projection, accepted only with a scoped Status read.
    pub override_data: Option<Value>,
    pub handoff: Option<HandoffOptions>,
}

#[derive(Clone, Copy)]
pub(crate) struct HandoffOptions {
    pub max_tokens: u64,
    pub max_evidence: usize,
}

pub(crate) struct McpReadIdentity {
    pub root: RootIdentity,
    pub installation: ControlId,
}

pub(crate) struct McpReadOutput {
    pub payload: Value,
    pub root: PathBuf,
    pub expected_root: RootIdentity,
    pub installation: ControlId,
    pub epoch: PolicyEpoch,
    pub deadline: Instant,
}

#[derive(Clone, Copy)]
enum RenderTarget<'a> {
    Cli(OutputMode, Option<&'a str>),
    Mcp(&'a Value),
}

fn latest_wait(latest: bool, wait: Option<u64>) -> Result<Option<u32>, CliError> {
    if wait.is_some_and(|n| !latest || n > 30_000) {
        return Err(invalid());
    }
    Ok(latest.then_some(wait.unwrap_or(5000) as u32))
}

fn request_deadline(started: Instant, latest: Option<u32>) -> Instant {
    started
        + Duration::from_millis(
            latest.map_or(10_000, |w| u64::from(w).saturating_add(5000).max(10_000)),
        )
}

pub(crate) fn prepare_mcp(db: &Path, input: McpReadInput) -> Result<McpReadOutput, CliError> {
    let cursor = match &input.request {
        AppRequest::Search { cursor, .. } | AppRequest::List { cursor, .. } => cursor.clone(),
        _ => None,
    };
    if cursor
        .as_ref()
        .is_some_and(|c| c.len() > 192 || !c.starts_with("asgmc1."))
        || (cursor.is_some() && (input.latest || input.handoff.is_some()))
    {
        return Err(cursor_error());
    }
    let mut budget = ResponseBudget {
        max_items: DEFAULT_ITEMS,
        max_messages: DEFAULT_ITEMS,
        max_response_bytes: DEFAULT_FRAME_BYTES,
        ..ResponseBudget::default()
    };
    let mut intersection = ProjectionQuery {
        filters: input.filters,
        ..ProjectionQuery::default()
    };
    let command = match &input.request {
        AppRequest::Search {
            query,
            filters,
            facets,
            limit,
            budget: b,
            include_system,
            ..
        } => {
            agent_session_grep_application::validate_search_request(query, filters, *limit, b)
                .map_err(private_app)?;
            budget = b.clone();
            intersection.facets = facets.clone();
            intersection.include_system = *include_system;
            "search"
        }
        AppRequest::List {
            limit, budget: b, ..
        } => {
            if *limit == 0 {
                return Err(invalid());
            }
            budget = b.clone();
            "list"
        }
        AppRequest::Context {
            session_id,
            budget: b,
            ..
        } => {
            entity(session_id.as_str(), Some(IdKind::Session))?;
            budget = b.clone();
            "context"
        }
        AppRequest::Message {
            message_id,
            session_id,
            around,
            budget: b,
        } => {
            entity(message_id.as_str(), Some(IdKind::Message))?;
            if let Some(id) = session_id {
                entity(id.as_str(), Some(IdKind::Session))?;
            }
            if *around > 512 {
                return Err(invalid());
            }
            budget = b.clone();
            "get-message"
        }
        AppRequest::GetSessionResume { session_id } => {
            entity(session_id.as_str(), Some(IdKind::Session))?;
            "get-session-resume"
        }
        AppRequest::Get { id } | AppRequest::Show { id } => {
            entity(id.as_str(), None)?;
            if matches!(input.request, AppRequest::Get { .. }) {
                "get"
            } else {
                "show"
            }
        }
        AppRequest::Status => "status",
        AppRequest::MessageContexts { .. } => return Err(unsupported()),
    };
    if input.override_data.is_some() && !matches!(input.request, AppRequest::Status) {
        return Err(invalid());
    }
    if input.override_data.as_ref().is_some_and(|v| !v.is_object())
        || budget.max_response_bytes > managed_emit::MAX_FRAME_BYTES
        || intersection
            .filters
            .since
            .zip(intersection.filters.until)
            .is_some_and(|(a, b)| a >= b)
        || intersection
            .filters
            .since
            .is_some_and(|v| v.nanosecond >= 1_000_000_000)
        || intersection
            .filters
            .until
            .is_some_and(|v| v.nanosecond >= 1_000_000_000)
    {
        return Err(invalid());
    }
    budget.validate().map_err(|_| invalid())?;
    let operation = if let Some(options) = input.handoff {
        if options.max_tokens == 0 || options.max_evidence == 0 {
            return Err(invalid());
        }
        match input.request {
            AppRequest::Search {
                query, limit, mode, ..
            } if query.chars().count() <= 256 => Operation::Handoff {
                query,
                limit,
                mode,
                options,
            },
            _ => return Err(invalid()),
        }
    } else {
        Operation::Typed(Box::new(input.request))
    };
    let request = Request {
        command: if input.handoff.is_some() {
            "handoff"
        } else {
            command
        },
        operation,
        intersection,
        frame_bytes: budget.max_response_bytes,
        budget,
        latest: latest_wait(input.latest, input.max_wait_ms)?,
        override_data: input.override_data,
        cursor,
        now_ms: crate::app_clock_ms(),
    };
    let (frame, authority) = execute(
        db,
        &request,
        RenderTarget::Mcp(&input.rpc_id),
        input.started,
        Some(&input.identity),
    )?;
    Ok(McpReadOutput {
        payload: frame.payload,
        ..authority
    })
}

fn cursor_error() -> CliError {
    CliError(ProtocolError::new(
        CanonicalCode::CursorInvalid,
        "invalid managed continuation",
    ))
}
fn cache_error(error: CacheError) -> CliError {
    CliError(ProtocolError::new(
        if error == CacheError::CursorInvalid {
            CanonicalCode::CursorInvalid
        } else {
            CanonicalCode::CursorExpired
        },
        "managed continuation is unavailable; rerun without cursor",
    ))
}

pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
    started: Instant,
) -> Result<Outcome, CliError> {
    let request = parse(rest, crate::app_clock_ms())?;
    emit_cli_request(db, &request, mode, request_id, started)
}

pub(crate) fn run_doctor(
    db: &str,
    mode: OutputMode,
    request_id: Option<&str>,
    offline: bool,
    started: Instant,
) -> Result<Outcome, CliError> {
    let request = Request {
        command: "doctor",
        operation: Operation::Status,
        intersection: ProjectionQuery::default(),
        budget: ResponseBudget {
            max_items: DEFAULT_ITEMS,
            max_messages: DEFAULT_ITEMS,
            max_response_bytes: DEFAULT_FRAME_BYTES,
            ..ResponseBudget::default()
        },
        frame_bytes: DEFAULT_FRAME_BYTES,
        latest: None,
        override_data: Some(json!({
            "managed": true,
            "offline": offline,
            "checks": [{"name": "catalog", "status": "ok"}],
            "diagnostics_complete": false
        })),
        cursor: None,
        now_ms: crate::app_clock_ms(),
    };
    emit_cli_request(db, &request, mode, request_id, started)
}

fn emit_cli_request(
    db: &str,
    request: &Request,
    mode: OutputMode,
    request_id: Option<&str>,
    started: Instant,
) -> Result<Outcome, CliError> {
    if request_id.is_some_and(|s| !protocol::valid_request_id(s)) {
        return Err(invalid());
    }
    let (result, authority) = execute(
        Path::new(db),
        request,
        RenderTarget::Cli(mode, request_id),
        started,
        None,
    )?;
    match managed_emit::emit_frame(
        &authority.root,
        authority.expected_root,
        &authority.installation,
        authority.epoch,
        &result.bytes,
        authority.deadline,
    ) {
        Ok(_) => Ok(result.outcome),
        Err(error) => {
            // No helper byte reached stdout, so the ordinary single error
            // envelope is the complete response. Writing it holds no gate.
            if error.output_untouched() {
                return Err(CliError(withheld_emission_error(error.kind())));
            }
            // A possibly partial evidence frame permanently closes this transport.
            if let Some(mut pending) = error.into_pending()
                && !pending.confirm_termination(authority.deadline)
            {
                std::mem::forget(pending);
            }
            Ok(Outcome::Partial)
        }
    }
}

fn check_deadline(deadline: Instant) -> Result<(), CliError> {
    if Instant::now() >= deadline {
        return Err(private_port(PortError::WriterBusy(
            "managed read deadline exceeded".into(),
        )));
    }
    Ok(())
}

/// Retry one idempotent control/catalog SQL read while a SQLite busy episode
/// outlasts its 250 ms allowance and the request deadline remains. Only reads
/// that take no OS lock are wrapped: a held catalog or control lock (purge,
/// retirement) still answers busy at once. An active control fence is state,
/// so its busy refusal also returns at once instead of waiting it out.
fn transient<T>(
    control: &SqliteControlStore,
    deadline: Instant,
    mut read: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    loop {
        let error = match read() {
            Err(error @ PortError::WriterBusy(_)) => error,
            other => return other,
        };
        if Instant::now() >= deadline || fenced(control, deadline) {
            return Err(error);
        }
        std::thread::sleep(
            Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}
fn fenced(control: &SqliteControlStore, deadline: Instant) -> bool {
    // A contended fence read proves no fence; the caller keeps its deadline.
    control
        .with_runtime_deadline(deadline, || {
            control.read_policy(RequestIntersection::Selected)
        })
        .is_ok_and(|policy| policy.emission_blocked())
}

fn failure_reason(reason: BackgroundFailure) -> &'static str {
    match reason {
        BackgroundFailure::Paused => "paused",
        BackgroundFailure::Stopped => "stopped",
        BackgroundFailure::Offline => "offline",
        BackgroundFailure::Busy => "busy",
        BackgroundFailure::Failed => "failed",
        BackgroundFailure::Deferred => "deferred",
        BackgroundFailure::Upgrading => "upgrading",
        BackgroundFailure::PolicyChanged => "policy_changed",
        BackgroundFailure::Timeout => "timeout",
        BackgroundFailure::ScopeUnverified => "scope_unverified",
        BackgroundFailure::SourceChanged => "source_changed",
        BackgroundFailure::WorkerRestarted => "worker_restarted",
        BackgroundFailure::CatalogChanged => "catalog_changed",
        BackgroundFailure::RewritePending => "rewrite_pending",
        BackgroundFailure::DeletionPending => "deletion_pending",
    }
}

fn relevant_providers(
    store: &ManagedStore,
    control: &SqliteControlStore,
    request: &Request,
    deadline: Instant,
) -> Result<Vec<SearchProvider>, CliError> {
    let app = request.app_request(&request.budget);
    let id = match &app {
        AppRequest::Get { id } | AppRequest::Show { id } => Some(id),
        AppRequest::Context { session_id, .. } | AppRequest::GetSessionResume { session_id } => {
            Some(session_id)
        }
        AppRequest::Message { message_id, .. } | AppRequest::MessageContexts { message_id } => {
            Some(message_id)
        }
        _ => None,
    };
    let requested = &request.intersection.filters.providers;
    if let Some(id) = id {
        // Only this identity-resolution snapshot precedes admission; its content
        // is never emitted. Project/time cannot eliminate undiscovered claims.
        return transient(control, deadline, || {
            store.with_read(control, RequestIntersection::Selected, deadline, |read| {
                let query = ProjectionQuery {
                    filters: SearchFilters {
                        providers: requested.clone(),
                        ..SearchFilters::default()
                    },
                    include_system: true,
                    ..ProjectionQuery::default()
                };
                let providers = if id.kind() == IdKind::Message {
                    read.occurrences(std::slice::from_ref(id), &query)?
                        .into_iter()
                        .map(|o| o.data.provider_id)
                        .collect::<Vec<_>>()
                } else {
                    let kind = if id.kind() == IdKind::Session {
                        EntityKind::Session
                    } else {
                        EntityKind::Document
                    };
                    read.entities(kind, std::slice::from_ref(id), &query)?
                        .into_iter()
                        .filter_map(|e| match e.data {
                            EntityData::Session(s) => Some(s.provider_id),
                            EntityData::Document(d) => Some(d.provider_id),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                };
                let mut providers = providers
                    .into_iter()
                    .map(|s| {
                        SearchProvider::parse(&s).ok_or_else(|| {
                            PortError::SchemaIncompatible("managed provider unavailable".into())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                providers.sort();
                providers.dedup();
                // Unknown identity cannot establish narrower discovery relevance.
                if providers.is_empty() {
                    providers = requested.clone();
                }
                Ok(providers)
            })
        })
        .map_err(private_port);
    }
    let mut providers = requested.clone();
    if let AppRequest::Search { filters, .. } = app {
        if providers.is_empty() {
            providers = filters.providers;
        } else if !filters.providers.is_empty() {
            providers.retain(|p| filters.providers.contains(p));
            // Disjoint predicates return no evidence; conservatively retain the
            // explicit outer scope for admission rather than treating [] as all.
            if providers.is_empty() {
                providers = requested.clone();
            }
        }
    }
    Ok(providers)
}

fn admit_latest(
    control: &SqliteControlStore,
    initial: &ControlStatus,
    providers: &[SearchProvider],
    wait: u32,
    deadline: Instant,
) -> Result<(Option<LatestBarrier>, Option<&'static str>), CliError> {
    let mut selections = Vec::new();
    for selection in
        initial.policy.selections.iter().filter(|s| {
            s.enabled && (providers.is_empty() || providers.contains(&s.region.provider))
        })
    {
        let Some(root_identity) = selection.root_identity.clone() else {
            return Ok((None, Some("scope_unverified")));
        };
        selections.push(SelectionRevision {
            selection_id: selection.id.clone(),
            revision: selection.revision,
            root_identity,
        });
    }
    if selections.is_empty() {
        return Ok((None, Some("scope_unverified")));
    }
    for _ in 0..3 {
        check_deadline(deadline)?;
        let current = control
            .with_runtime_deadline(deadline, || control.status())
            .map_err(private_port)?;
        if current.policy.installation_id != initial.policy.installation_id
            || current.policy.policy_epoch != initial.policy.policy_epoch
        {
            return Ok((None, Some("policy_changed")));
        }
        match control.with_runtime_deadline(deadline, || {
            control.admit_latest(
                current.policy.control_seq,
                LatestRequest {
                    selections: selections.clone(),
                    max_wait_ms: wait,
                    now_ms: crate::app_clock_ms(),
                },
            )
        }) {
            Ok(change) => {
                return Ok(match change.value {
                    LatestAdmission::Queued(b) => (Some(b), None),
                    LatestAdmission::Blocked(reason) => (None, Some(failure_reason(reason))),
                });
            }
            Err(PortError::GenerationMismatch(_) | PortError::WriterBusy(_)) => {}
            Err(error) => return Err(private_port(error)),
        }
    }
    Ok((None, Some("busy")))
}

#[derive(Clone, Copy)]
struct Freshness {
    desired: DesiredUpdates,
    satisfied: bool,
    reason: &'static str,
    update_state: &'static str,
    scope: SnapshotFreshness,
}
fn update_state_name(state: UpdateState) -> &'static str {
    match state {
        UpdateState::Running => "running",
        UpdateState::Idle => "idle",
        UpdateState::Paused => "paused",
        UpdateState::Stopped => "stopped",
        UpdateState::Offline => "offline",
        UpdateState::Busy => "busy",
        UpdateState::Failed => "failed",
        UpdateState::Deferred => "deferred",
        UpdateState::Upgrading => "upgrading",
    }
}
fn direct_evidence_command(command: &str) -> bool {
    matches!(
        command,
        "get" | "show" | "get-message" | "get-session-resume" | "context"
    )
}

fn execute(
    path: &Path,
    request: &Request,
    target: RenderTarget<'_>,
    started: Instant,
    identity: Option<&McpReadIdentity>,
) -> Result<(PreparedFrame, McpReadOutput), CliError> {
    let deadline = request_deadline(started, request.latest);
    check_deadline(deadline)?;
    let root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root = root.canonicalize().map_err(|_| boundary_error())?;
    let path = root.join(path.file_name().ok_or_else(invalid)?);
    let expected_root = RootIdentity::read(&root).map_err(private_port)?;
    if identity.is_some_and(|expected| expected.root != expected_root) {
        return Err(boundary_error());
    }
    let control = SqliteControlStore::open_current_read_only_with_deadline(&root, deadline)
        .map_err(private_port)?;
    let status = transient(&control, deadline, || {
        control.with_runtime_deadline(deadline, || control.status())
    })
    .map_err(private_port)?;
    if identity.is_some_and(|expected| expected.installation != status.policy.installation_id)
        || RootIdentity::read(&root).map_err(private_port)? != expected_root
    {
        return Err(boundary_error());
    }
    // ControlHandles stays shared through history admission and latest waits:
    // terminal retirement cannot publish a marker in this interval.
    // Retention cannot discard this request's barrier or source revisions
    // while latest releases its catalog snapshot to wait. Pause and revocation
    // still use their independent policy/lifecycle gates.
    let _history_read = loop {
        check_deadline(deadline)?;
        match SharedGuard::try_acquire(&root, LockKind::HistoryReaders) {
            Ok(guard) => break guard,
            Err(PortError::WriterBusy(_)) => {
                std::thread::sleep(
                    Duration::from_millis(1)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(private_port(error)),
        }
    };
    // Check installation through a read-only connection before even opening a
    // writer. Latest admission must never mutate a replacement installation.
    let control = if request.latest.is_some() {
        // Acquire the writable handle while the original read-only lease remains
        // live. There is no terminal-admission gap between these handles.
        let writable = SqliteControlStore::open_existing_writable_with_deadline(
            &root,
            &status.policy.installation_id,
            deadline,
        )
        .map_err(private_port)?;
        drop(control);
        if RootIdentity::read(&root).map_err(private_port)? != expected_root {
            return Err(boundary_error());
        }
        writable
    } else {
        control
    };
    let store = control
        .with_runtime_deadline(deadline, || ManagedStore::open(&path, &control))
        .map_err(private_port)?;
    let cache = if matches!(request.command, "search" | "list") {
        control
            .with_runtime_deadline(deadline, || Ok(ManagedCache::at(&root, &control).ok()))
            .map_err(private_port)?
    } else {
        None
    };
    if RootIdentity::read(&root).map_err(private_port)? != expected_root {
        return Err(boundary_error());
    }
    // Both ordinary disclosure and latest admission have the same provider
    // relevance. Project/time predicates cannot exclude unknown new sources.
    let providers = relevant_providers(&store, &control, request, deadline)?;
    let (barrier, blocked) = if let Some(wait) = request.latest {
        admit_latest(&control, &status, &providers, wait, deadline)?
    } else {
        (None, None)
    };
    let wait_deadline = started + Duration::from_millis(u64::from(request.latest.unwrap_or(0)));
    let result = loop {
        check_deadline(deadline)?;
        let current = transient(&control, deadline, || {
            control.with_runtime_deadline(deadline, || control.status())
        })
        .map_err(private_port)?;
        if current.policy.installation_id != status.policy.installation_id {
            return Err(boundary_error());
        }
        let barrier_now = barrier
            .as_ref()
            .map(|b| {
                transient(&control, deadline, || {
                    control.with_runtime_deadline(deadline, || control.barrier(&b.id))
                })
            })
            .transpose()
            .map_err(private_port)?;
        // barrier() overlays the live worker advisory on the stored row. A
        // stored Blocked row never reopens, so its own error stays terminal even
        // when a later worker boot reports Busy or Deferred over it.
        let persisted_error = barrier
            .as_ref()
            .map(|b| {
                transient(&control, deadline, || {
                    control.with_runtime_deadline(deadline, || control.persisted_barrier(&b.id))
                })
            })
            .transpose()
            .map_err(private_port)?
            .and_then(|b| b.error);
        let worker = transient(&control, deadline, || {
            control.with_runtime_deadline(deadline, || control.background_status())
        })
        .map_err(private_port)?
        .worker;
        let reason = if current.desired_updates == DesiredUpdates::Paused {
            "paused"
        } else if current.desired_updates == DesiredUpdates::Stopped {
            "stopped"
        } else if current.policy.policy_epoch != status.policy.policy_epoch {
            "policy_changed"
        } else if barrier_now.is_some()
            && current.policy.maintenance.state != MaintenanceState::Idle
        {
            "upgrading"
        } else if barrier_now.is_some()
            && matches!(
                worker.state,
                UpdateState::Paused
                    | UpdateState::Stopped
                    | UpdateState::Offline
                    | UpdateState::Failed
                    | UpdateState::Upgrading
            )
        {
            update_state_name(worker.state)
        } else if barrier_now.is_some()
            && let Some(reason) = worker.error.filter(|error| {
                !matches!(error, BackgroundFailure::Busy | BackgroundFailure::Deferred)
            })
        {
            failure_reason(reason)
        } else if let Some(reason) = blocked {
            reason
        } else if let Some(reason) = persisted_error {
            failure_reason(reason)
        } else if let Some(reason) = barrier_now.as_ref().and_then(|b| b.error) {
            failure_reason(reason)
        } else if barrier_now.is_some()
            && matches!(worker.state, UpdateState::Busy | UpdateState::Deferred)
        {
            update_state_name(worker.state)
        } else {
            "timeout"
        };
        // A live owner permits waiting through advisory contention, never success.
        let offline = if current.desired_updates == DesiredUpdates::Running
            && (reason == "timeout"
                || (barrier_now.is_some()
                    && blocked.is_none()
                    && matches!(reason, "busy" | "deferred")))
        {
            match ExclusiveGuard::try_acquire(&root, LockKind::Background) {
                Ok(guard) => {
                    drop(guard);
                    true
                }
                Err(PortError::WriterBusy(_)) => false,
                Err(e) => return Err(private_port(e)),
            }
        } else {
            false
        };
        let reason = if offline { "offline" } else { reason };
        // Admission and stored barrier failures stay terminal. Retry only the
        // original barrier, with its original end and unchanged update permission.
        let can_wait = blocked.is_none()
            && persisted_error.is_none()
            && current.desired_updates == DesiredUpdates::Running
            && current.policy.policy_epoch == status.policy.policy_epoch
            && current.policy.maintenance.state == MaintenanceState::Idle
            && worker.error.is_none_or(|error| {
                matches!(error, BackgroundFailure::Busy | BackgroundFailure::Deferred)
            })
            && barrier_now.as_ref().is_some_and(|barrier| {
                barrier.error.is_none_or(|error| {
                    matches!(error, BackgroundFailure::Busy | BackgroundFailure::Deferred)
                })
            })
            && matches!(reason, "timeout" | "busy" | "deferred");
        let stop = request.latest.is_none() || !can_wait || Instant::now() >= wait_deadline;
        let result = transient(&control, deadline, || {
            store.with_read(&control, RequestIntersection::Selected, deadline, |read| {
                // Proof and payload use this very transaction. Drop it before every wait.
                let satisfied = barrier_now
                    .as_ref()
                    .map(|b| read.latest_satisfied(b))
                    .transpose()?
                    .unwrap_or(false);
                if !satisfied && !stop {
                    return Ok(None);
                }
                let scope = read.scope_freshness(&providers)?;
                let coverage_verified = scope.selected_scopes == scope.complete_scopes;
                let update_state = match current.desired_updates {
                    DesiredUpdates::Paused => "paused",
                    DesiredUpdates::Stopped => "stopped",
                    DesiredUpdates::Running if offline => "offline",
                    DesiredUpdates::Running
                        if current.policy.maintenance.state != MaintenanceState::Idle =>
                    {
                        "upgrading"
                    }
                    DesiredUpdates::Running => update_state_name(worker.state),
                };
                let disclosed_reason = if satisfied {
                    "verified"
                } else if request.latest.is_some() {
                    reason
                } else if matches!(
                    update_state,
                    "paused" | "stopped" | "offline" | "busy" | "failed" | "upgrading"
                ) {
                    update_state
                } else if coverage_verified {
                    "as_of_verified"
                } else if scope.pending_sources > 0 || update_state == "deferred" {
                    "deferred"
                } else {
                    "discovery_pending"
                };
                Ok(Some(prepare(
                    read,
                    request,
                    target,
                    started,
                    deadline,
                    Freshness {
                        desired: current.desired_updates,
                        satisfied,
                        reason: disclosed_reason,
                        update_state,
                        scope,
                    },
                    cache.as_ref().map(|c| (c, &control)),
                )))
            })
        })
        .map_err(private_port)?;
        if let Some(result) = result {
            break result?;
        }
        let remaining = wait_deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(Duration::from_millis(25).min(remaining));
    };
    drop(store);
    let current = transient(&control, deadline, || {
        control.with_runtime_deadline(deadline, || control.status())
    })
    .map_err(private_port)?;
    if current.policy.installation_id != status.policy.installation_id
        || current.policy.policy_epoch != result.epoch
        || RootIdentity::read(&root).map_err(private_port)? != expected_root
    {
        return Err(boundary_error());
    }
    drop(control);
    check_deadline(deadline)?;
    let authority = McpReadOutput {
        payload: Value::Null,
        root,
        expected_root,
        installation: status.policy.installation_id,
        epoch: result.epoch,
        deadline,
    };
    Ok((result, authority))
}

fn prepare(
    read: &ManagedRead<'_>,
    request: &Request,
    target: RenderTarget<'_>,
    started: Instant,
    deadline: Instant,
    freshness: Freshness,
    cache: Option<(&ManagedCache, &SqliteControlStore)>,
) -> Result<PreparedFrame, CliError> {
    if matches!(request.command, "search" | "list") {
        return prepare_collection(read, request, target, started, deadline, freshness, cache);
    }
    let expired = || Instant::now() >= deadline;
    let now_ms = request.now_ms;
    let mut budget = request.budget.clone();
    let mut reduced = false;
    // Machine transports select a context prefix by measuring each candidate
    // with this very final serializer: MCP counts its JSON-RPC wrapper, both
    // payload copies (one escaped) and the newline; Robot counts its single
    // envelope. The last candidate that fit is emitted as measured when
    // Application returns that same response, so selection and the gate below
    // see identical bytes and a later `duration_ms` cannot grow the frame.
    // A reused Robot frame therefore reports `duration_ms` as elapsed when it
    // was measured; later probes and the gate are not included.
    // Human output keeps the Application estimate. A render failure keeps its
    // own error instead of the Application error it must cross as.
    let measured = matches!(
        target,
        RenderTarget::Mcp(_) | RenderTarget::Cli(OutputMode::Json | OutputMode::Jsonl, _)
    );
    let frame_error = std::cell::RefCell::new(None);
    let fitted = std::cell::RefCell::new(None::<(ManagedResponse, PreparedFrame)>);
    let context_frame_size = |response: &ManagedResponse| -> Result<usize, AppError> {
        let frame = render_frame(
            read,
            FrameData::from_managed(response.clone()),
            request,
            target,
            started,
            freshness,
            false,
        )
        .map_err(|error| {
            frame_error.replace(Some(error));
            AppError::Port(PortError::SchemaIncompatible(
                "managed context frame is unavailable".into(),
            ))
        })?;
        let size = frame.bytes.len();
        if size <= request.frame_bytes {
            fitted.replace(Some((response.clone(), frame)));
        }
        Ok(size)
    };
    for _ in 0..MAX_RENDERS {
        fitted.take();
        let app = ManagedApp::new(
            read,
            ManagedRequestContext {
                intersection: request.intersection.clone(),
                budget: budget.clone(),
                now_ms,
                current_repo: None,
                deadline_expired: &expired,
            },
        )
        .map_err(private_app)?;
        let app = if measured && !reduced {
            app.with_context_frame_size(&context_frame_size)
        } else {
            app
        };
        let mut reuse = None;
        let response = if let Operation::Handoff {
            query,
            limit,
            mode,
            options,
        } = &request.operation
        {
            let response = app
                .prepare_handoff(ManagedHandoffRequest {
                    query: query.clone(),
                    intersection: request.intersection.clone(),
                    limit: (*limit).min(budget.max_items),
                    budget: budget.clone(),
                    max_tokens: options.max_tokens,
                    max_bytes: budget.max_response_bytes as u64,
                    max_evidence: options.max_evidence.min(budget.max_items),
                    mode: *mode,
                    target: None,
                })
                .map_err(private_app)?
                .generate()
                .map_err(private_app)?;
            let outcome = if response.is_partial() {
                Outcome::Partial
            } else {
                Outcome::Success
            };
            let redacted_count = response.pack.redaction.redacted_count;
            FrameData {
                snapshot: response.snapshot,
                evidence: response.evidence,
                partial: response.partial,
                outcome,
                data: serde_json::to_value(response.pack).map_err(|_| boundary_error())?,
                warnings: Vec::new(),
                redacted_count,
                page: protocol::Page::default(),
                providers: Vec::new(),
            }
        } else {
            let app_request =
                bind_request_ids(read, request.app_request(&budget), &request.intersection)?;
            let response = app
                .handle(app_request)
                .map_err(|error| frame_error.take().unwrap_or_else(|| private_app(error)))?;
            if matches!(
                &response.response,
                AppResponse::Get { payload: None } | AppResponse::Show { payload: None }
            ) {
                return Err(CliError(ProtocolError::new(
                    CanonicalCode::NotFound,
                    "entity not found",
                )));
            }
            reuse = fitted
                .take()
                .filter(|(candidate, _)| *candidate == response)
                .map(|(_, frame)| frame);
            FrameData::from_managed(response)
        };
        let frame = match reuse {
            Some(frame) => frame,
            None => render_frame(read, response, request, target, started, freshness, reduced)?,
        };
        if frame.bytes.len() <= request.frame_bytes {
            return Ok(frame);
        }
        reduced = true;
        budget.max_items = (budget.max_items / 2).max(1);
        budget.max_messages = (budget.max_messages / 2).max(1);
        budget.max_evidence_spans = (budget.max_evidence_spans / 2).max(1);
        budget.max_snippet_chars = (budget.max_snippet_chars / 2).max(16);
        budget.max_response_bytes = (budget.max_response_bytes / 2).max(4096);
    }
    Err(CliError(ProtocolError::new(
        CanonicalCode::InvalidRequest,
        "response budget cannot fit managed evidence",
    )))
}

fn collection_binding(request: &Request) -> Result<CacheBinding, CliError> {
    let app = request.app_request(&request.budget);
    let (query, model, group, order) = match app {
        AppRequest::Search {
            query,
            filters,
            facets,
            group_by_session,
            mode,
            query_embedding,
            ..
        } => {
            let mut providers = filters
                .providers
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>();
            providers.sort();
            providers.dedup();
            let order=json!({"order":"managed-score-v1","providers":providers,"since":filters.since.map(|t|(t.unix_seconds,t.nanosecond)),"until":filters.until.map(|t|(t.unix_seconds,t.nanosecond)),"repo":filters.repo,"sidechain":facets.sidechain.as_str(),"tool_kind":facets.tool_kind,"tool_name":facets.tool_name}).to_string();
            let vector = query_embedding
                .map(|v| serde_json::to_vec(&v))
                .transpose()
                .map_err(|_| invalid())?;
            let model = format!(
                "{}:{}",
                mode.as_str(),
                vector
                    .map(|v| blake3::hash(&v).to_hex().to_string())
                    .unwrap_or_default()
            );
            (
                query,
                model,
                if group_by_session { "session" } else { "none" },
                blake3::hash(order.as_bytes()).to_hex().to_string(),
            )
        }
        AppRequest::List { sessions_only, .. } => (
            format!("list:{sessions_only}"),
            "none".into(),
            "none",
            "canonical-id-v1".into(),
        ),
        _ => return Err(invalid()),
    };
    CacheBinding::new(&query, &model, &request.intersection, group, &order).map_err(cache_error)
}

fn frozen_providers(
    set: &ManagedCandidateSet,
) -> Result<
    Vec<(
        StableId,
        agent_session_grep_ports::managed::EvidenceProof,
        SearchProvider,
    )>,
    CliError,
> {
    let mut providers = Vec::new();
    for candidate in &set.candidates {
        if let ProjectionListEntry::Entity(p) = &candidate.entry {
            let (id, name) = match &p.data {
                EntityData::Session(s) => (&s.session.id, &s.provider_id),
                EntityData::Document(d) => (&d.id, &d.provider_id),
                _ => return Err(boundary_error()),
            };
            providers.push((
                id.clone(),
                p.proof.clone(),
                SearchProvider::parse(name).ok_or_else(boundary_error)?,
            ));
        }
    }
    Ok(providers)
}

fn prepare_collection(
    read: &ManagedRead<'_>,
    request: &Request,
    target: RenderTarget<'_>,
    started: Instant,
    deadline: Instant,
    freshness: Freshness,
    cache: Option<(&ManagedCache, &SqliteControlStore)>,
) -> Result<PreparedFrame, CliError> {
    let expired = || Instant::now() >= deadline;
    let binding = collection_binding(request)?;
    let cached = if let Some(cursor) = &request.cursor {
        let (cache, control) = cache.ok_or_else(|| cache_error(CacheError::CursorExpired))?;
        Some(
            cache
                .load_set(
                    control,
                    read,
                    CachePageRequest {
                        binding: &binding,
                        cursor,
                        limit: 512,
                        now_ms: crate::app_clock_ms(),
                        deadline,
                    },
                )
                .map_err(cache_error)?,
        )
    } else {
        None
    };
    let collected;
    let (set, offset) = if let Some(cached) = &cached {
        (&cached.set, cached.continuation.offset())
    } else {
        let app = ManagedApp::new(
            read,
            ManagedRequestContext {
                intersection: request.intersection.clone(),
                budget: request.budget.clone(),
                now_ms: request.now_ms,
                current_repo: None,
                deadline_expired: &expired,
            },
        )
        .map_err(private_app)?;
        collected = app
            .collect_candidates(request.app_request(&request.budget))
            .map_err(private_app)?;
        (&collected, 0)
    };
    let providers = frozen_providers(set)?;
    let mut budget = request.budget.clone();
    let mut reduced = false;
    for _ in 0..MAX_RENDERS {
        check_deadline(deadline)?;
        let app = ManagedApp::new(
            read,
            ManagedRequestContext {
                intersection: request.intersection.clone(),
                budget: budget.clone(),
                now_ms: set.request_now_ms,
                current_repo: None,
                deadline_expired: &expired,
            },
        )
        .map_err(private_app)?;
        let response = app
            .render_candidates(request.app_request(&budget), set, offset)
            .map_err(private_app)?;
        let (outcome, data, _, warnings) = render(response.response);
        let retained = data
            .get(if request.command == "search" {
                "hits"
            } else {
                "entries"
            })
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let more = offset + retained < set.candidates.len();
        if retained == 0 && more {
            return Err(invalid());
        }
        let mut framed = FrameData {
            snapshot: response.snapshot,
            evidence: response.evidence,
            partial: response.partial,
            outcome,
            data,
            warnings,
            redacted_count: 0,
            page: protocol::Page::default(),
            providers: providers.clone(),
        };
        // Reserve a worst-case token plus the fallback warning before exact
        // frame sizing. Success only removes bytes from this checked shape.
        let next = if let Some(cached) = &cached {
            if retained == 0 {
                None
            } else {
                cached
                    .continuation
                    .cursor_after(retained)
                    .map_err(cache_error)?
                    .map(|c| c.into_string())
            }
        } else if more && cache.is_some() {
            Some("x".repeat(192))
        } else {
            None
        };
        framed.page = protocol::Page {
            has_more: next.is_some(),
            next_cursor: next,
        };
        framed
            .partial
            .retain(|p| *p != ManagedPartial::ContinuationUnavailable);
        if (more && cached.is_none()) || set.truncated {
            framed.partial.push(ManagedPartial::ContinuationUnavailable);
        }
        let reserved = render_frame(
            read,
            framed.clone(),
            request,
            target,
            started,
            freshness,
            reduced,
        )?;
        if reserved.bytes.len() <= request.frame_bytes {
            if more && cached.is_none() {
                let stored = cache.map(|(cache, control)| {
                    cache.insert_set(
                        control,
                        read,
                        CacheSetInsert {
                            binding: &binding,
                            set,
                            next_offset: retained,
                            now_ms: crate::app_clock_ms(),
                            deadline,
                        },
                    )
                });
                match stored {
                    Some(InsertOutcome::Stored(cursor)) => {
                        framed.page = protocol::Page {
                            next_cursor: Some(cursor.into_string()),
                            has_more: true,
                        };
                        if !set.truncated {
                            framed
                                .partial
                                .retain(|p| *p != ManagedPartial::ContinuationUnavailable);
                        }
                    }
                    _ => {
                        framed.page = protocol::Page::default();
                    }
                }
            }
            let result = render_frame(read, framed, request, target, started, freshness, reduced)?;
            if result.bytes.len() <= request.frame_bytes {
                return Ok(result);
            }
        }
        reduced = true;
        budget.max_items = (budget.max_items / 2).max(1);
        budget.max_messages = (budget.max_messages / 2).max(1);
        budget.max_evidence_spans = (budget.max_evidence_spans / 2).max(1);
        budget.max_snippet_chars = (budget.max_snippet_chars / 2).max(16);
        budget.max_response_bytes = (budget.max_response_bytes / 2).max(4096);
    }
    Err(invalid())
}

/// Wire IDs encode kind/value, not the persisted stability annotation. Resolve
/// that annotation from a permitted typed projection in this same snapshot;
/// never infer Native/Unstable from a string or relax internal proof equality.
fn bind_request_ids(
    read: &impl ProjectionRead,
    mut request: AppRequest,
    query: &ProjectionQuery,
) -> Result<AppRequest, CliError> {
    match &mut request {
        AppRequest::Context { session_id, .. } => {
            *session_id = stored_id(read, session_id, query, false)?
        }
        AppRequest::GetSessionResume { session_id } => {
            *session_id = stored_id(read, session_id, query, true)?
        }
        AppRequest::Message {
            message_id,
            session_id,
            ..
        } => {
            let mut qualified = query.clone();
            if let Some(session) = session_id {
                *session = stored_id(read, session, query, false)?;
                qualified.session_id = Some(session.clone());
            }
            *message_id = stored_id(read, message_id, &qualified, false)?;
        }
        AppRequest::MessageContexts { message_id } => {
            *message_id = stored_id(read, message_id, query, false)?
        }
        _ => {}
    }
    Ok(request)
}

fn stored_id(
    read: &impl ProjectionRead,
    requested: &StableId,
    query: &ProjectionQuery,
    resume: bool,
) -> Result<StableId, CliError> {
    let ids = std::slice::from_ref(requested);
    let mut candidates = if requested.kind() == IdKind::Message {
        read.messages(ids, query)
            .map_err(private_port)?
            .into_iter()
            .flatten()
            .map(|p| p.message.id)
            .collect::<Vec<_>>()
    } else {
        let sessions = read
            .entities(EntityKind::Session, ids, query)
            .map_err(private_port)?;
        if sessions.is_empty() {
            return Err(private_port(PortError::NotFound("entity not found".into())));
        }
        let claims = if resume {
            read.entities(EntityKind::Resume, ids, query)
                .map_err(private_port)?
        } else {
            Vec::new()
        };
        let rows = if claims.is_empty() { sessions } else { claims };
        rows.into_iter()
            .map(|p| match p.data {
                EntityData::Session(s) => Ok(s.session.id),
                EntityData::Resume(r) => Ok(r.session_id),
                _ => Err(boundary_error()),
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let Some(first) = candidates.pop() else {
        return Err(private_port(PortError::NotFound("entity not found".into())));
    };
    if first.kind() != requested.kind()
        || first.as_str() != requested.as_str()
        || !first.validate()
        || candidates.iter().any(|id| id != &first)
    {
        return Err(boundary_error());
    }
    Ok(first)
}

fn provider_for(
    read: &impl ProjectionRead,
    e: &ManagedEvidence,
    query: &ProjectionQuery,
    resume: bool,
) -> Result<Option<SearchProvider>, CliError> {
    if let Some(o) = &e.occurrence {
        return SearchProvider::parse(&o.data.provider_id)
            .map(Some)
            .ok_or_else(boundary_error);
    }
    let kind = match e.entity_id.kind() {
        IdKind::Session if resume => EntityKind::Resume,
        IdKind::Session => EntityKind::Session,
        IdKind::Document => EntityKind::Document,
        _ => return Ok(None),
    };
    let rows = read
        .entities(kind, std::slice::from_ref(&e.entity_id), query)
        .map_err(private_port)?;
    let row = rows
        .iter()
        .find(|p| p.proof == e.proof)
        .ok_or_else(boundary_error)?;
    let name = match &row.data {
        EntityData::Session(s) => s.provider_id.as_str(),
        EntityData::Document(d) => d.provider_id.as_str(),
        EntityData::Resume(r) => r.provider_id.as_str(),
        _ => return Err(boundary_error()),
    };
    SearchProvider::parse(name)
        .map(Some)
        .ok_or_else(boundary_error)
}
#[derive(Clone)]
struct FrameData {
    snapshot: ReadSnapshot,
    evidence: Vec<ManagedEvidence>,
    partial: Vec<ManagedPartial>,
    outcome: Outcome,
    data: Value,
    warnings: Vec<String>,
    redacted_count: u64,
    page: protocol::Page,
    providers: Vec<(
        StableId,
        agent_session_grep_ports::managed::EvidenceProof,
        SearchProvider,
    )>,
}

impl FrameData {
    fn from_managed(response: agent_session_grep_application::managed::ManagedResponse) -> Self {
        let (outcome, data, _page, warnings) = render(response.response);
        Self {
            snapshot: response.snapshot,
            evidence: response.evidence,
            partial: response.partial,
            outcome,
            data,
            warnings,
            redacted_count: 0,
            page: protocol::Page::default(),
            providers: Vec::new(),
        }
    }
}

fn provenance(
    read: &impl ProjectionRead,
    response: &FrameData,
    request: &Request,
) -> Result<Value, CliError> {
    let mut rows = Vec::new();
    for e in &response.evidence {
        let cached_provider = response
            .providers
            .iter()
            .find(|(id, proof, _)| id == &e.entity_id && proof == &e.proof)
            .map(|(_, _, p)| *p);
        let provider = if cached_provider.is_some() {
            cached_provider
        } else {
            provider_for(
                read,
                e,
                &request.intersection,
                request.command == "get-session-resume",
            )?
        };
        // One row shape shared with Application; the context frames measured
        // above embed exactly these rows.
        rows.push(provenance_row(e, provider));
    }
    Ok(Value::Array(rows))
}

fn redact_embedded_payloads(data: &mut Value) -> u64 {
    let mut count = 0;
    match data {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "payload"
                    && let Value::String(text) = value
                    && let Ok(parsed) = serde_json::from_str::<Value>(text)
                {
                    // Preserve the shared renderer's string payload shape while
                    // redacting secret-key values inside the typed JSON payload.
                    let (redacted, status) = redaction::redact_value(parsed);
                    count += status.redacted_count;
                    *text = redacted.to_string();
                } else {
                    count += redact_embedded_payloads(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                count += redact_embedded_payloads(value);
            }
        }
        _ => {}
    }
    count
}

fn render_frame(
    read: &ManagedRead<'_>,
    response: FrameData,
    request: &Request,
    target: RenderTarget<'_>,
    started: Instant,
    freshness: Freshness,
    reduced: bool,
) -> Result<PreparedFrame, CliError> {
    let provenance = provenance(read, &response, request)?;
    let contributing = if direct_evidence_command(request.command) {
        let sources = response
            .evidence
            .iter()
            .flat_map(|e| std::iter::once(&e.proof).chain(e.related.iter()))
            .map(|proof| proof.source_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Some(
            read.contributing_freshness(&sources)
                .map_err(private_port)?,
        )
    } else {
        None
    };
    let epoch = PolicyEpoch::new(response.snapshot.policy_epoch).map_err(private_port)?;
    let snapshot = json!({"generation":response.snapshot.generation,"destructive_epoch":response.snapshot.destructive_epoch,"policy_epoch":response.snapshot.policy_epoch});
    let partial = response
        .partial
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect::<Vec<_>>();
    let app_partial = !response.partial.is_empty();
    let (mut outcome, mut data, mut warnings) =
        (response.outcome, response.data, response.warnings);
    if let Some(override_data) = &request.override_data {
        data = override_data.clone();
    }
    let page = response.page;
    if app_partial || (request.latest.is_some() && !freshness.satisfied) || reduced {
        outcome = Outcome::Partial;
    }
    warnings.extend(partial);
    if request.latest.is_some() && !freshness.satisfied {
        warnings.push(freshness.reason.into());
    }
    if reduced {
        warnings.push("response_budget".into());
        if request.command == "handoff" {
            data["truncation"]["truncated"] = json!(true);
        } else {
            data["truncation"] = json!({"truncated":true,"reason":"max_response_bytes"});
        }
    }
    // Native resume identifiers remain explicit opt-in on their sole command.
    // They are never added to provenance, snippets or ordinary entity output.
    data["provenance"] = provenance;
    data["snapshot"] = snapshot;
    data["generation"] = json!(response.snapshot.generation);
    let scope = freshness.scope;
    let coverage = if freshness.satisfied {
        "complete"
    } else {
        match scope.coverage {
            agent_session_grep_ports::control::Coverage::Empty => "empty",
            agent_session_grep_ports::control::Coverage::Partial => "partial",
            agent_session_grep_ports::control::Coverage::Complete => "complete",
        }
    };
    let update_state = match freshness.desired {
        DesiredUpdates::Paused => "paused",
        DesiredUpdates::Stopped => "stopped",
        DesiredUpdates::Running
            if direct_evidence_command(request.command)
                && matches!(freshness.update_state, "deferred" | "failed") =>
        {
            if contributing.is_some_and(|s| s.failed_sources > 0) {
                "failed"
            } else if contributing.is_some_and(|s| s.pending_sources > 0) {
                "deferred"
            } else {
                "running"
            }
        }
        DesiredUpdates::Running => freshness.update_state,
    };
    let counts = contributing.unwrap_or(scope);
    let reason = if request.latest.is_none()
        && direct_evidence_command(request.command)
        && matches!(freshness.reason, "deferred" | "failed")
    {
        if counts.failed_sources > 0 {
            "failed"
        } else if counts.pending_sources > 0 {
            "deferred"
        } else if scope.selected_scopes != scope.complete_scopes {
            "discovery_pending"
        } else {
            "as_of_verified"
        }
    } else {
        freshness.reason
    };
    data["freshness"] = json!({"coverage":coverage,"update_state":update_state,
        "latest_requested":request.latest.is_some(),"latest_satisfied":freshness.satisfied,"reason":reason,
        "selected_scopes":scope.selected_scopes,"complete_scopes":scope.complete_scopes,
        "contributing_sources":counts.sources,"verified_sources":counts.verified_sources,
        "pending_sources":counts.pending_sources,"failed_sources":counts.failed_sources,
        "last_verified_observation_at_ms":counts.last_verified_observation_at_ms});
    let retrieval = match data.get("retrieval_mode").and_then(Value::as_str) {
        Some("lexical_fallback") => RetrievalMode::LexicalFallback,
        Some("semantic") => RetrievalMode::Semantic,
        Some("hybrid") => RetrievalMode::Hybrid,
        _ => RetrievalMode::Lexical,
    };
    // Robot owns retrieval mode in its envelope; MCP keeps the disclosure in
    // data because its common tool-result wrapper has no retrieval-mode field.
    if matches!(target, RenderTarget::Cli(_, _))
        && let Value::Object(map) = &mut data
    {
        map.remove("retrieval_mode");
    }
    let embedded_redactions = redact_embedded_payloads(&mut data);
    let (data, mut status) = redaction::redact_value(data);
    status.redacted_count += embedded_redactions + response.redacted_count;
    if embedded_redactions + response.redacted_count > 0 {
        status.status = agent_session_grep_ports::RedactionState::Applied;
    }
    let warnings = warnings
        .iter()
        .map(|w| redaction::redact_text(w).0)
        .collect::<Vec<_>>();
    let payload = json!({"outcome":if outcome == Outcome::Partial {"partial"} else {"success"},"data":data,"warnings":warnings,"page":{"next_cursor":page.next_cursor,"has_more":page.has_more},"redaction":protocol::redaction_block(&status)});
    let mut bytes = match target {
        RenderTarget::Mcp(id) => {
            crate::mcp::managed_result_frame(id.clone(), payload.clone()).into_bytes()
        }
        RenderTarget::Cli(OutputMode::Json | OutputMode::Jsonl, request_id) => {
            protocol::success_envelope(
                request.command,
                outcome,
                data,
                started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                &page,
                &warnings,
                request_id,
                retrieval,
                &status,
            )
            .into_bytes()
        }
        RenderTarget::Cli(OutputMode::Human, _) => {
            let mut lines = crate::human::render_success(request.command, outcome, &data, &page);
            lines.push(format!(
                "freshness: {} ({})",
                data["freshness"]["update_state"]
                    .as_str()
                    .unwrap_or("unknown"),
                data["freshness"]["reason"].as_str().unwrap_or("unknown"),
            ));
            for item in data["provenance"].as_array().into_iter().flatten() {
                lines.push(format!("evidence: {}", item));
            }
            for warning in warnings {
                lines.push(format!("warning: {warning}"));
            }
            lines.join("\n").into_bytes()
        }
    };
    bytes.push(b'\n');
    Ok(PreparedFrame {
        bytes,
        payload,
        outcome,
        epoch,
    })
}

#[cfg(test)]
mod transient_read_tests {
    use super::*;
    use agent_session_grep_ports::control::{MaintenanceFence, MaintenancePhase, MaintenanceState};

    fn store() -> (tempfile::TempDir, SqliteControlStore) {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let control = SqliteControlStore::create(
            &temp.path().join("private"),
            &ControlId::parse("unit-installation").unwrap(),
            DesiredUpdates::Running,
        )
        .unwrap();
        (temp, control)
    }

    #[test]
    fn sqlite_contention_is_retried_within_the_request_deadline() {
        let (_temp, control) = store();
        let mut attempts = 0;
        let value = transient(&control, Instant::now() + Duration::from_secs(5), || {
            attempts += 1;
            if attempts < 3 {
                Err(PortError::WriterBusy("synthetic busy episode".into()))
            } else {
                Ok(attempts)
            }
        })
        .unwrap();
        assert_eq!(value, 3);
        let mut attempts = 0;
        let error = transient(&control, Instant::now() + Duration::from_secs(5), || {
            attempts += 1;
            Err::<(), _>(PortError::SchemaIncompatible("synthetic".into()))
        })
        .unwrap_err();
        assert!(matches!(error, PortError::SchemaIncompatible(_)));
        assert_eq!(attempts, 1);
        let error = transient(&control, Instant::now(), || {
            Err::<(), _>(PortError::WriterBusy("synthetic".into()))
        })
        .unwrap_err();
        assert!(matches!(error, PortError::WriterBusy(_)));
    }

    #[test]
    fn active_fence_answers_busy_without_waiting_out_the_deadline() {
        let (_temp, control) = store();
        let owner = ControlId::parse("unit-maintenance").unwrap();
        control
            .set_maintenance(
                control.status().unwrap().policy.control_seq,
                &owner,
                MaintenanceFence {
                    state: MaintenanceState::Updating,
                    owner: Some(owner.clone()),
                    phase: Some(MaintenancePhase::Quiescing),
                },
            )
            .unwrap();
        let started = Instant::now();
        let mut attempts = 0;
        let error = transient(&control, started + Duration::from_secs(10), || {
            attempts += 1;
            Err::<(), _>(PortError::WriterBusy(
                "managed control fence is active".into(),
            ))
        })
        .unwrap_err();
        assert!(matches!(error, PortError::WriterBusy(_)));
        // A definite fence read stops retrying; a contended fence read may
        // allow one more attempt, never a wait to the request deadline.
        assert!(attempts <= 3, "fenced refusal retried {attempts} times");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
