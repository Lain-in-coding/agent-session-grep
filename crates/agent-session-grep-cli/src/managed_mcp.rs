//! Managed composition for the existing MCP protocol. Idle connections keep no
//! catalog handles; every evidence response reopens and uses one authorized read.
use crate::{
    CliError, managed_emit, managed_read,
    mcp::{self, ToolError},
    protocol::{CanonicalCode, ProtocolError},
};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore, managed_locks::RootIdentity, managed_store::ManagedStore,
};
use agent_session_grep_application::AppRequest;
use agent_session_grep_ports::{
    PortError, SearchFilters,
    control::{ControlId, ControlStore, PolicyEpoch},
};
use serde_json::{Map, Value, json};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

struct Call {
    id: Value,
    filters: SearchFilters,
    latest: bool,
    max_wait_ms: Option<u64>,
    started: Instant,
}
struct Emission {
    root: PathBuf,
    expected_root: RootIdentity,
    installation: ControlId,
    epoch: PolicyEpoch,
    deadline: Instant,
}
pub(crate) struct ManagedBackend {
    db: PathBuf,
    expected_root: RootIdentity,
    installation: ControlId,
    call: RefCell<Option<Call>>,
    emission: RefCell<Option<Emission>>,
    started: RefCell<Instant>,
}
fn private(error: PortError) -> CliError {
    let code = ProtocolError::from_private_port_error(error).code;
    ProtocolError::new(code, "managed MCP state is unavailable").into()
}
fn invalid(message: &'static str) -> ToolError {
    ToolError::Params(message.into())
}

impl ManagedBackend {
    pub(crate) fn open(db: &Path) -> Result<Self, CliError> {
        agent_session_grep_adapters_sqlite::managed_store::validate_catalog_path(db)
            .map_err(private)?;
        let root = db
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()
            .map_err(|_| private(PortError::SourceIo("root unavailable".into())))?;
        let db = root.join(
            db.file_name()
                .ok_or_else(|| private(PortError::InvalidRequest("invalid catalog".into())))?,
        );
        let expected_root = RootIdentity::read(&root).map_err(private)?;
        let control = SqliteControlStore::open_current_read_only(&root).map_err(private)?;
        let installation = control.status().map_err(private)?.policy.installation_id;
        drop(ManagedStore::open(&db, &control).map_err(private)?);
        if RootIdentity::read(&root).map_err(private)? != expected_root {
            return Err(private(PortError::SchemaIncompatible(
                "root changed".into(),
            )));
        }
        Ok(Self {
            db,
            expected_root,
            installation,
            call: RefCell::new(None),
            emission: RefCell::new(None),
            started: RefCell::new(Instant::now()),
        })
    }

    pub(crate) fn begin_frame(&self) {
        self.call.borrow_mut().take();
        self.emission.borrow_mut().take();
        *self.started.borrow_mut() = Instant::now();
    }

    /// Remove shared managed options only after strict validation. Existing
    /// per-tool validation remains the single owner of every other argument.
    pub(crate) fn begin_call(
        &self,
        id: &Value,
        name: &str,
        args: &Map<String, Value>,
    ) -> Result<Map<String, Value>, ToolError> {
        let mut args = args.clone();
        let latest = match args.remove("latest") {
            None => false,
            Some(Value::Bool(value)) => value,
            Some(_) => return Err(invalid("latest must be a boolean")),
        };
        let max_wait_ms = match args.remove("max_wait_ms") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .filter(|n| *n <= 30_000 && latest)
                    .ok_or_else(|| {
                        invalid("max_wait_ms requires latest and an integer in 0..30000")
                    })?,
            ),
        };
        let filters = mcp::opt_filters(&args)?;
        if filters
            .since
            .zip(filters.until)
            .is_some_and(|(a, b)| a >= b)
        {
            return Err(invalid("since must precede until"));
        }
        if name != "search_sessions" {
            for key in ["providers", "since", "until", "repo"] {
                args.remove(key);
            }
        }
        match name {
            "generate_handoff" => {
                args.entry("limit").or_insert(json!(5));
                args.entry("max_evidence").or_insert(json!(5));
                args.entry("max_tokens").or_insert(json!(2048));
                args.entry("max_bytes").or_insert(json!(8192));
            }
            "search_sessions" | "list_sessions" | "get_message" => {
                args.entry("max_items").or_insert(json!(5));
                args.entry("max_bytes").or_insert(json!(8192));
            }
            "get_session_context" => {
                args.entry("max_messages").or_insert(json!(5));
                args.entry("max_bytes").or_insert(json!(8192));
            }
            _ => {}
        }
        *self.call.borrow_mut() = Some(Call {
            id: id.clone(),
            filters,
            latest,
            max_wait_ms,
            started: *self.started.borrow(),
        });
        Ok(args)
    }

    pub(crate) fn run_app(&self, request: AppRequest) -> Result<Value, ToolError> {
        self.run_projection(request, None, None)
    }

    pub(crate) fn handoff(
        &self,
        query: String,
        limit: usize,
        max_evidence: usize,
        max_tokens: u64,
        max_bytes: usize,
    ) -> Result<Value, ToolError> {
        if query.chars().count() > 256 || limit > 500 || max_evidence > 500 {
            return Err(invalid("handoff exceeds query or item bounds"));
        }
        let filters = self
            .call
            .borrow()
            .as_ref()
            .ok_or_else(|| invalid("missing tool call"))?
            .filters
            .clone();
        self.run_projection(
            AppRequest::Search {
                query,
                filters,
                facets: Default::default(),
                limit,
                cursor: None,
                budget: agent_session_grep_application::ResponseBudget {
                    max_items: limit,
                    max_response_bytes: max_bytes,
                    ..Default::default()
                },
                include_system: false,
                group_by_session: false,
                mode: agent_session_grep_ports::RetrievalMode::Lexical,
                query_embedding: None,
            },
            None,
            Some(managed_read::HandoffOptions {
                max_tokens,
                max_evidence,
            }),
        )
    }

    fn run_projection(
        &self,
        request: AppRequest,
        override_data: Option<Value>,
        handoff: Option<managed_read::HandoffOptions>,
    ) -> Result<Value, ToolError> {
        let call = self.call.borrow();
        let call = call.as_ref().ok_or_else(|| invalid("missing tool call"))?;
        let response = managed_read::prepare_mcp(
            &self.db,
            managed_read::McpReadInput {
                identity: managed_read::McpReadIdentity {
                    root: self.expected_root,
                    installation: self.installation.clone(),
                },
                request,
                filters: call.filters.clone(),
                rpc_id: call.id.clone(),
                latest: call.latest,
                max_wait_ms: call.max_wait_ms,
                started: call.started,
                override_data,
                handoff,
            },
        )
        .map_err(|CliError(error)| ToolError::Business(error))?;
        if response.expected_root != self.expected_root
            || response.installation != self.installation
        {
            return Err(ToolError::Business(ProtocolError::new(
                CanonicalCode::SchemaIncompatible,
                "managed installation changed; reconnect MCP",
            )));
        }
        *self.emission.borrow_mut() = Some(Emission {
            root: response.root,
            expected_root: response.expected_root,
            installation: response.installation,
            epoch: response.epoch,
            deadline: response.deadline,
        });
        Ok(response.payload)
    }

    pub(crate) fn doctor(&self, offline: bool) -> Result<Value, ToolError> {
        // Read only the scoped managed status. Global legacy corpus diagnostics
        // are deliberately inaccessible through this backend.
        self.run_projection(
            AppRequest::Status,
            Some(json!({
                "managed":true,"offline":offline,"checks":[{"name":"catalog","status":"ok"}],
                "diagnostics_complete":false
            })),
            None,
        )
    }

    pub(crate) fn providers(&self, data: Value) -> Result<Value, ToolError> {
        self.run_projection(AppRequest::Status, Some(data), None)
    }

    pub(crate) fn has_prepared_frame(&self) -> bool {
        self.emission.borrow().is_some()
    }

    pub(crate) fn emit(&self, frame: &str) -> bool {
        let mut bytes = frame.as_bytes().to_vec();
        bytes.push(b'\n');
        let emission = self.emission.borrow_mut().take();
        let (result, deadline) = match emission {
            Some(emission) => (
                managed_emit::emit_frame(
                    &emission.root,
                    emission.expected_root,
                    &emission.installation,
                    emission.epoch,
                    &bytes,
                    emission.deadline,
                ),
                emission.deadline,
            ),
            None => {
                // Content-free protocol and sanitized business errors must stay
                // available while evidence is fenced for revoke or maintenance.
                let deadline = *self.started.borrow() + Duration::from_secs(10);
                (managed_emit::emit_control_frame(&bytes, deadline), deadline)
            }
        };
        match result {
            Ok(_) => true,
            Err(error) => {
                if error.output_untouched()
                    && Instant::now() < deadline
                    && let Some(call) = self.call.borrow().as_ref()
                {
                    // The helper exited or was confirmed dead before READY,
                    // so no evidence byte can be on stdout. Answer this RPC
                    // with a content-free classified error and keep its session.
                    let classified = managed_read::withheld_emission_error(error.kind());
                    let mut frame =
                        mcp::business_error_frame(call.id.clone(), &classified).into_bytes();
                    frame.push(b'\n');
                    match managed_emit::emit_control_frame(&frame, deadline) {
                        Ok(_) => return true,
                        Err(fallback) => {
                            if let Some(mut pending) = fallback.into_pending()
                                && !pending.confirm_termination(deadline)
                            {
                                std::mem::forget(pending);
                            }
                            return false;
                        }
                    }
                }
                if let Some(mut pending) = error.into_pending()
                    && !pending.confirm_termination(deadline)
                {
                    std::mem::forget(pending);
                }
                // A cancelled/partial frame terminates the whole transport. No
                // next JSON-RPC response may be appended to a partial frame.
                false
            }
        }
    }
}

/// Additive options on the same nine read tools; no extra mutation surface.
pub(crate) fn extend_catalog(catalog: &mut Value) {
    let Some(tools) = catalog.as_array_mut() else {
        return;
    };
    for tool in tools {
        let name = tool["name"].as_str().unwrap_or_default().to_owned();
        // All nine tools accept latest, which can enqueue a private observation
        // request. Paged reads may retain/evict regenerable continuation caches.
        // Those effects do not alter scope, update intent, catalog evidence or
        // provider histories, and contact no external service. Do not claim a
        // pure or idempotent read, and do not leave conservative destructive /
        // open-world defaults that unnecessarily require interactive approval.
        tool["annotations"] = json!({
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": false,
            "openWorldHint": false
        });
        match name.as_str() {
            "search_sessions" => {}
            "list_sessions" => {
                tool["description"] = json!(
                    "Browse permitted indexed sessions when the user wants to choose one without a topic. Known activity is ordered newest first, with unknown activity last and stable IDs breaking ties; unknown time cannot prove recency. Start with a small page and follow a continuation only for missing evidence. Does not resume anything."
                )
            }
            "doctor" => {
                tool["description"] = json!(
                    "Inspect managed catalog availability for a reported problem. Detailed interrupted-batch diagnostics are unavailable in this mode. A healthy catalog does not prove source freshness; not a routine lookup prerequisite."
                )
            }
            _ => {}
        }
        let Some(props) = tool["inputSchema"]["properties"].as_object_mut() else {
            continue;
        };
        props.insert("latest".into(), json!({"type":"boolean","default":false,"description":"Wait for a post-request observation within the selected history; never resumes paused updates."}));
        props.insert("max_wait_ms".into(), json!({"type":"integer","minimum":0,"maximum":30000,"default":5000,"description":"Requires latest=true. An unmet barrier returns permitted evidence with a partial reason."}));
        props.entry("providers").or_insert(json!({"type":"array","maxItems":agent_session_grep_ports::capability::search_provider_filter_values().len(),"items":{"type":"string","enum":agent_session_grep_ports::capability::search_provider_filter_values()}}));
        for key in ["since", "until"] {
            props.entry(key).or_insert(json!({"type":"string","maxLength":64,"description":"Absolute ISO-8601 instant; selected-history intersection."}));
        }
        props
            .entry("repo")
            .or_insert(json!({"type":"string","minLength":1,"maxLength":255}));
        for (key, value) in [("max_items", 5), ("max_messages", 5), ("max_bytes", 8192)] {
            if let Some(schema) = props.get_mut(key) {
                schema["default"] = json!(value);
            }
        }
        if let Some(schema) = props.get_mut("limit") {
            schema["description"] = json!("Page size; defaults to 5 and is capped by max_items.");
        }
        if let Some(schema) = props.get_mut("max_bytes") {
            schema["description"] = json!(
                "Complete JSON-RPC frame budget, including structuredContent, text compatibility copy, escaping, and newline. Defaults to 8192 bytes."
            );
        }
        if let Some(schema) = props.get_mut("cursor") {
            schema["description"] = json!(
                "Opaque as-of continuation from a previous response with the same query, scope and budgets. Use only when more evidence is needed; policy/rewrite/model changes or expiry invalidate it. latest and handoff cannot use a cursor."
            );
        }
        if name == "generate_handoff" {
            props.get_mut("query").unwrap()["maxLength"] = json!(256);
            for key in ["limit", "max_evidence"] {
                props.get_mut(key).unwrap()["maximum"] = json!(500);
            }
        }
    }
}
