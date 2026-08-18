//! MCP stdio server：JSON-RPC 2.0 over stdin/stdout（CONTRACT §8）。
//!
//! 每行一个完整 JSON-RPC 消息；stdout 只输出协议 frame（唯一出口
//! [`protocol::write_stdout_line`]），诊断一律走 stderr。handler 只做协议校验与
//! 参数映射：良构参数构造 [`AppRequest`] 交给 Application，成功结果复用 CLI
//! 同一个 [`crate::render`] 投影——不复制搜索/分支/分页/预算业务规则。
//!
//! 错误分层（design §0.3）：
//! - 协议层问题（坏 JSON、批量数组、未知方法/工具、非法参数、未初始化）→
//!   JSON-RPC error 对象；`-32602` 携带 `data.canonical_code = invalid_request`；
//! - 良构 [`AppRequest`] 之后的业务失败（cursor_invalid、not_found、...）→
//!   成功 JSON-RPC response，result 携 `isError: true` + canonical error 结构。

use crate::protocol::{self, CanonicalCode, Outcome, ProtocolError};
use crate::{CliError, canonical_search_provider, provider_registry, render, store_ref};
use agent_session_grep_adapters_sqlite::SqliteStore;
use agent_session_grep_application::{
    App, AppRequest, AppResponse, ContextLevel, ResponseBudget,
    handoff_pack::{HandoffInput, resolve_source_locations},
    parse_search_instant,
};
use agent_session_grep_domain::{ContextPolicy, IdKind, StableId};
use agent_session_grep_ports::{
    RetrievalMode, SearchFacets, SearchFilters, SidechainFacet,
    capability::{ProviderCapabilityMatrix, ProviderMaturity},
    handoff::HandoffFilters,
};
use serde_json::{Map, Value, json};

/// 支持的 MCP 协议版本（新→旧）。协商绝不谎报支持：请求版本在列才回显。
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// 钉住的最新协议版本：请求版本不在支持列表时的协商回落值。
const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// JSON-RPC 2.0 预定义错误码。
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// 错误消息插值上界（design R5）：回显的 method/tool/id/参数值截断到 128 字符，
/// 截断处以 "..." 标记——超长输入不得放大错误帧。
const ECHO_CAP: usize = 128;

/// 在已打开的只读 store 上服务 MCP，直到 stdin EOF（→ 干净停机）。
///
/// 空行跳过；stdin 读错误归 `source_io`。stdout 写失败/EPIPE 的退出语义由
/// [`protocol::write_stdout_line`] 统一执行（design §0.8）。
pub(crate) fn serve(store: &SqliteStore) -> Result<Outcome, CliError> {
    let mut server = McpServer {
        store,
        initialized: false,
        initialize_seen: false,
    };
    for line in std::io::stdin().lines() {
        let line = line.map_err(|error| {
            ProtocolError::new(
                CanonicalCode::SourceIo,
                format!("cannot read stdin: {error}"),
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(frame) = server.handle_line(&line) {
            protocol::write_stdout_line(&frame);
        }
    }
    Ok(Outcome::Success)
}

/// 单连接 MCP 服务状态：注入的只读 store + initialize 门闩。
struct McpServer<'a> {
    store: &'a SqliteStore,
    /// `notifications/initialized` 之前只放行 initialize/ping（design §0.7）。
    initialized: bool,
    /// 是否收到过成功 initialize 握手：门闩只在握手之后打开，未握手先发
    /// initialized 通知是协议违规，不得开门（Minor-8）；失败的 initialize
    /// （参数校验不过）不算握手。
    initialize_seen: bool,
}

/// 工具调用的两类失败（design §0.3）：结构/校验问题 → JSON-RPC `-32602`；
/// 良构 [`AppRequest`] 之后的业务失败 → `isError: true` 工具结果。
#[derive(Debug)]
enum ToolError {
    Params(String),
    Business(ProtocolError),
}

impl McpServer<'_> {
    /// 处理一行输入：notification（无 `id` 键）永不回应，request 必回一帧。
    /// 坏 JSON → `-32700`（id null）；非对象（含批量数组）→ `-32600`；
    /// `jsonrpc` 非字面 "2.0" 或 id 非法（array/object/浮点）→ `-32600`。
    fn handle_line(&mut self, line: &str) -> Option<String> {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                return Some(error_frame(
                    Value::Null,
                    PARSE_ERROR,
                    &format!("parse error: {error}"),
                    None,
                ));
            }
        };
        let Value::Object(message) = value else {
            // 2025-06-18 已移除 JSON-RPC batching；数组与其它非对象一律拒绝。
            return Some(error_frame(
                Value::Null,
                INVALID_REQUEST,
                "request must be a single JSON object (batching is not supported)",
                None,
            ));
        };
        // 每个消息（request 与 notification 一视同仁，R3）必须携带字面 "2.0"；
        // 版本不符时请求 id 不可信 → 错误帧 id null（JSON-RPC §5）。
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error_frame(
                Value::Null,
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
                None,
            ));
        }
        // id：键缺席是 notification（JSON-RPC 规定永不回应；未知 notification
        // 方法静默忽略，`notifications/cancelled` 是 documented no-op）；
        // 键在场必须是 string/整数/null，array/object/浮点 id 是非法请求
        // → -32600（非法 id 无法回显，错误帧 id null）。
        let id = match message.get("id") {
            None => None,
            Some(id) if is_valid_jsonrpc_id(id) => Some(id.clone()),
            Some(_) => {
                return Some(error_frame(
                    Value::Null,
                    INVALID_REQUEST,
                    "id must be a string, an integer, or null",
                    None,
                ));
            }
        };
        let method = message.get("method").and_then(Value::as_str);
        match id {
            // `notifications/initialized` 只在收到过成功 initialize 后开门闩；
            // params 必须是对象或缺失，畸形通知回 -32600 且不得开门（R3）。
            None => match method {
                Some("notifications/initialized") => {
                    if !params_object_or_absent(message.get("params")) {
                        return Some(error_frame(
                            Value::Null,
                            INVALID_REQUEST,
                            "notification params must be an object when present",
                            None,
                        ));
                    }
                    if self.initialize_seen {
                        self.initialized = true;
                    }
                    None
                }
                Some(_) => None,
                None => Some(error_frame(
                    Value::Null,
                    INVALID_REQUEST,
                    "notification must carry a string method",
                    None,
                )),
            },
            Some(id) => {
                let Some(method) = method else {
                    return Some(error_frame(
                        id,
                        INVALID_REQUEST,
                        "method must be a string",
                        None,
                    ));
                };
                Some(self.handle_request(id, method, message.get("params")))
            }
        }
    }

    /// request 分发。initialize/ping 始终放行；其余方法要求已初始化（design §0.7），
    /// 门闩优先于方法分发——未初始化时未知方法同样回 `-32600`。
    /// ping/tools/list 的 params 必须是对象或缺失（R3）；未知方法回显截断（R5）。
    fn handle_request(&mut self, id: Value, method: &str, params: Option<&Value>) -> String {
        match method {
            "initialize" => self.handle_initialize(id, params),
            "ping" => {
                if !params_object_or_absent(params) {
                    return error_frame(
                        id,
                        INVALID_PARAMS,
                        "params must be an object when present",
                        Some(invalid_request_data()),
                    );
                }
                result_frame(id, json!({}))
            }
            _ if !self.initialized => {
                error_frame(id, INVALID_REQUEST, "server not initialized", None)
            }
            "tools/list" => {
                if !params_object_or_absent(params) {
                    return error_frame(
                        id,
                        INVALID_PARAMS,
                        "params must be an object when present",
                        Some(invalid_request_data()),
                    );
                }
                result_frame(id, json!({ "tools": tool_catalog() }))
            }
            "tools/call" => self.handle_tools_call(id, params),
            other => error_frame(
                id,
                METHOD_NOT_FOUND,
                &format!("method not found: {}", bounded(other)),
                None,
            ),
        }
    }

    /// initialize 握手（R3）：params 必须是对象且含 protocolVersion(string)、
    /// capabilities(object)、clientInfo(object)；缺失或类型不符 → -32602。
    /// 只有校验全部通过才算成功握手（推进 initialize_seen）——失败的 initialize
    /// 之后，notifications/initialized 通知无权开门闩。
    fn handle_initialize(&mut self, id: Value, params: Option<&Value>) -> String {
        let Some(Value::Object(object)) = params else {
            return error_frame(
                id,
                INVALID_PARAMS,
                "params must be an object carrying protocolVersion, capabilities and clientInfo",
                Some(invalid_request_data()),
            );
        };
        let requested = match object.get("protocolVersion") {
            Some(Value::String(version)) => version.as_str(),
            Some(_) => {
                return error_frame(
                    id,
                    INVALID_PARAMS,
                    "params.protocolVersion must be a string",
                    Some(invalid_request_data()),
                );
            }
            None => {
                return error_frame(
                    id,
                    INVALID_PARAMS,
                    "missing required parameter: protocolVersion",
                    Some(invalid_request_data()),
                );
            }
        };
        if !object.get("capabilities").is_some_and(Value::is_object) {
            return error_frame(
                id,
                INVALID_PARAMS,
                "params.capabilities must be an object",
                Some(invalid_request_data()),
            );
        }
        if !object.get("clientInfo").is_some_and(Value::is_object) {
            return error_frame(
                id,
                INVALID_PARAMS,
                "params.clientInfo must be an object",
                Some(invalid_request_data()),
            );
        }
        // 成功握手：此后的 initialized 通知才有权开门闩（Minor-8）。
        self.initialize_seen = true;
        result_frame(
            id,
            json!({
                "protocolVersion": negotiate_version(Some(requested)),
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "agent-session-grep",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
        )
    }

    /// tools/call：解出 name/arguments 后按 [`ToolError`] 分层投影。
    fn handle_tools_call(&self, id: Value, params: Option<&Value>) -> String {
        let Some(params) = params.and_then(Value::as_object) else {
            return error_frame(
                id,
                INVALID_PARAMS,
                "params must be an object carrying name/arguments",
                Some(invalid_request_data()),
            );
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return error_frame(
                id,
                INVALID_PARAMS,
                "params.name must be a string",
                Some(invalid_request_data()),
            );
        };
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None => &empty,
            Some(Value::Object(map)) => map,
            Some(_) => {
                return error_frame(
                    id,
                    INVALID_PARAMS,
                    "params.arguments must be an object",
                    Some(invalid_request_data()),
                );
            }
        };
        match self.call_tool(name, arguments) {
            Ok(payload) => {
                // ADR-0009: MCP is a cross-boundary output → redact by default.
                let (redacted_payload, _redaction) = crate::redaction::redact_value(payload);
                // content.text 与 structuredContent 是同一 payload 的两种载体
                // （2025-06-18 字段；老客户端忽略未知字段，design §0.2）。
                let text = redacted_payload.to_string();
                result_frame(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": text }],
                        "structuredContent": redacted_payload,
                        "isError": false,
                    }),
                )
            }
            Err(ToolError::Params(message)) => {
                error_frame(id, INVALID_PARAMS, &message, Some(invalid_request_data()))
            }
            Err(ToolError::Business(error)) => result_frame(id, business_error_result(&error)),
        }
    }

    /// 工具名分发（合同 §8 的 9 个工具）；未知工具是请求校验失败 → `-32602`。
    fn call_tool(&self, name: &str, args: &Map<String, Value>) -> Result<Value, ToolError> {
        match name {
            "search_sessions" => self.tool_search(args),
            "get_session_context" => self.tool_context(args),
            "get_session_resume" => self.tool_session_resume(args),
            "get_message" => self.tool_message(args),
            "list_sessions" => self.tool_list(args),
            "generate_handoff" => self.tool_handoff(args),
            "list_providers" => {
                reject_unknown_keys(args, &[])?;
                Ok(providers_payload())
            }
            "get_status" => {
                reject_unknown_keys(args, &[])?;
                self.run_app(AppRequest::Status)
            }
            "doctor" => {
                reject_unknown_keys(args, &[])?;
                self.tool_doctor()
            }
            other => Err(ToolError::Params(format!(
                "unknown tool: {}",
                bounded(other)
            ))),
        }
    }

    fn tool_search(&self, args: &Map<String, Value>) -> Result<Value, ToolError> {
        reject_unknown_keys(
            args,
            &[
                "query",
                "limit",
                "cursor",
                "max_items",
                "max_bytes",
                "providers",
                "since",
                "until",
                "include_system",
                "group_by_session",
                "sidechain",
                "tool_kind",
                "tool_name",
                "mode",
            ],
        )?;
        let query = required_str(args, "query")?;
        let limit = opt_usize(args, "limit")?;
        let cursor = opt_str(args, "cursor")?;
        let max_items = opt_usize(args, "max_items")?;
        let max_bytes = opt_usize(args, "max_bytes")?;
        // 预算下限（R4）：limit/max_items < 1、max_bytes < 4096 在协议层 -32602，
        // 在构造 AppRequest 之前拒绝；App 层 validate 保留为纵深防御。
        // schema 同步声明这些 minimum（design §3），additionalProperties 由
        // reject_unknown_keys 代码侧强制。
        reject_below_floor(limit, "limit", 1)?;
        reject_below_floor(max_items, "max_items", 1)?;
        reject_below_floor(max_bytes, "max_bytes", 4096)?;
        // 检索模式：与 CLI --mode 同一闭集；semantic/hybrid 在向量索引未就绪时
        // 由 Application 显式降级 lexical_fallback + warning（禁止静默切换）。
        let mode = match opt_str(args, "mode")?.as_deref() {
            None | Some("lexical") => RetrievalMode::Lexical,
            Some("semantic") => RetrievalMode::Semantic,
            Some("hybrid") => RetrievalMode::Hybrid,
            Some(other) => {
                return Err(ToolError::Params(format!(
                    "mode must be lexical|semantic|hybrid, got {other}"
                )));
            }
        };
        let filters = opt_filters(args)?;
        let include_system = opt_bool(args, "include_system", false)?;
        let group_by_session = opt_bool(args, "group_by_session", false)?;
        let sidechain = match opt_str(args, "sidechain")?.as_deref() {
            None | Some("include") => SidechainFacet::Include,
            Some("main_only") => SidechainFacet::MainOnly,
            Some("subagent_only") => SidechainFacet::SubagentOnly,
            Some(other) => {
                return Err(ToolError::Params(format!(
                    "sidechain must be include|main_only|subagent_only, got {other}"
                )));
            }
        };
        let tool_kind = opt_str(args, "tool_kind")?;
        if let Some(kind) = &tool_kind
            && !matches!(
                kind.as_str(),
                "file" | "command" | "web" | "query" | "unknown"
            )
        {
            return Err(ToolError::Params(format!(
                "tool_kind must be file|command|web|query|unknown, got {kind}"
            )));
        }
        let tool_name = opt_str(args, "tool_name")?;
        let facets = SearchFacets {
            sidechain,
            tool_kind,
            tool_name,
        };
        // 语义/混合查询向量：与 CLI search 同一策略——有已导入且验证过的
        // 本地 Candle E5 bundle 时用真实模型（进程内缓存，MCP 长连接下后续
        // 查询零加载成本），否则回退 bigram-hash。向量索引未就绪时 Application
        // 显式 lexical_fallback。
        let query_embedding = if mode == RetrievalMode::Lexical {
            None
        } else {
            use agent_session_grep_application::embedding::BigramHashModel;
            use agent_session_grep_ports::EmbeddingModel;
            let (model_id, embedding) = {
                #[cfg(feature = "semantic-candle")]
                {
                    let cache = crate::platform_paths_for_mcp().ok().and_then(|v| {
                        v.get("cache")
                            .and_then(|c| c.as_str())
                            .map(|s| s.to_string())
                    });
                    if let Some(cache) = cache {
                        let dir =
                            agent_session_grep_application::candle_embedding::default_model_dir(
                                std::path::Path::new(&cache),
                            );
                        if let Ok(model) =
                            agent_session_grep_application::candle_embedding::CandleE5Model::load_cached(
                                &dir,
                            )
                        {
                            let emb =
                                model.embed(&query, true).map_err(|error| ToolError::Business(error.into()))?;
                            (model.manifest().model_id.clone(), Some(emb))
                        } else {
                            let model = BigramHashModel::new();
                            let emb = model
                                .embed(&query, true)
                                .map_err(|error| ToolError::Business(error.into()))?;
                            (model.manifest().model_id.clone(), Some(emb))
                        }
                    } else {
                        let model = BigramHashModel::new();
                        let emb = model
                            .embed(&query, true)
                            .map_err(|error| ToolError::Business(error.into()))?;
                        (model.manifest().model_id.clone(), Some(emb))
                    }
                }
                #[cfg(not(feature = "semantic-candle"))]
                {
                    let model = BigramHashModel::new();
                    let emb = model
                        .embed(&query, true)
                        .map_err(|error| ToolError::Business(error.into()))?;
                    (model.manifest().model_id.clone(), Some(emb))
                }
            };
            self.store.set_semantic_model(&model_id);
            embedding
        };
        let mut payload = self.run_app(AppRequest::Search {
            query,
            filters,
            facets: facets.clone(),
            limit: limit.or(max_items).unwrap_or(20),
            cursor,
            budget: budget_with(max_items, max_bytes, None),
            include_system,
            group_by_session,
            mode,
            query_embedding,
        })?;
        // CLI（Robot）search 在非默认 facet 时回显 data.facets；MCP 必须一致，
        // 否则同一能力在两个入口呈现不同契约（audit P1-5）。
        if !facets.is_default() {
            let data = payload
                .as_object_mut()
                .and_then(|frame| frame.get_mut("data"))
                .and_then(|data| data.as_object_mut())
                .expect("success_payload carries a data object");
            data.insert(
                "facets".into(),
                serde_json::json!({
                    "sidechain": facets.sidechain.as_str(),
                    "tool_kind": facets.tool_kind,
                    "tool_name": facets.tool_name,
                }),
            );
        }
        Ok(payload)
    }

    fn tool_context(&self, args: &Map<String, Value>) -> Result<Value, ToolError> {
        reject_unknown_keys(
            args,
            &["session_id", "policy", "level", "max_messages", "max_bytes"],
        )?;
        let wire = required_str(args, "session_id")?;
        // wire id 解析失败属请求校验（→ -32602）；格式合法但库中不存在则走
        // Application 的 not_found 业务路径（design §2 note）。kind 同样属于
        // 协议层校验：session_id 必须是 Session 实体，Message/Document id 不能
        // 冒充（否则 get_session_context 的上下文装配语义会被错置）。
        let session_id = StableId::from_wire(&wire)
            .filter(|id| id.kind() == IdKind::Session)
            .ok_or_else(|| {
                ToolError::Params(format!(
                    "session_id is not a valid session id: {}",
                    bounded(&wire)
                ))
            })?;
        let policy = match opt_str(args, "policy")?.as_deref() {
            None | Some("mainline") => ContextPolicy::Mainline,
            Some("full") => ContextPolicy::Full,
            Some(other) => {
                return Err(ToolError::Params(format!(
                    "policy must be mainline|full, got {}",
                    bounded(other)
                )));
            }
        };
        let level = match opt_str(args, "level")?.as_deref() {
            None | Some("raw") => ContextLevel::Raw,
            Some("talks") => ContextLevel::Talks,
            Some("sessions") => ContextLevel::Sessions,
            Some(other) => {
                return Err(ToolError::Params(format!(
                    "level must be raw|talks|sessions, got {}",
                    bounded(other)
                )));
            }
        };
        let max_messages = opt_usize(args, "max_messages")?;
        let max_bytes = opt_usize(args, "max_bytes")?;
        // 预算下限（R4）：max_messages < 1、max_bytes < 4096 协议层 -32602。
        reject_below_floor(max_messages, "max_messages", 1)?;
        reject_below_floor(max_bytes, "max_bytes", 4096)?;
        self.run_app(AppRequest::Context {
            session_id,
            policy,
            level,
            budget: budget_with(None, max_bytes, max_messages),
        })
    }

    fn tool_session_resume(&self, args: &Map<String, Value>) -> Result<Value, ToolError> {
        reject_unknown_keys(args, &["session_id"])?;
        let wire = required_str(args, "session_id")?;
        let session_id = StableId::from_wire(&wire)
            .filter(|id| id.kind() == IdKind::Session)
            .ok_or_else(|| {
                ToolError::Params(format!(
                    "session_id is not a valid session id: {}",
                    bounded(&wire)
                ))
            })?;
        self.run_app(AppRequest::GetSessionResume { session_id })
    }

    fn tool_message(&self, args: &Map<String, Value>) -> Result<Value, ToolError> {
        reject_unknown_keys(
            args,
            &[
                "message_id",
                "session_id",
                "around",
                "max_items",
                "max_bytes",
            ],
        )?;
        let message_wire = required_str(args, "message_id")?;
        // wire id 解析失败属请求校验（→ -32602）；格式合法但库中不存在则走
        // Application 的 not_found 业务路径 (design §2 note). kind 同属协议层
        // 校验：message_id 必须是 Message 实体。
        let message_id = StableId::from_wire(&message_wire)
            .filter(|id| id.kind() == IdKind::Message)
            .ok_or_else(|| {
                ToolError::Params(format!(
                    "message_id is not a valid message id: {}",
                    bounded(&message_wire)
                ))
            })?;
        let session_id = match opt_str(args, "session_id")? {
            None => None,
            Some(wire) => Some(
                StableId::from_wire(&wire)
                    .filter(|id| id.kind() == IdKind::Session)
                    .ok_or_else(|| {
                        ToolError::Params(format!(
                            "session_id is not a valid session id: {}",
                            bounded(&wire)
                        ))
                    })?,
            ),
        };
        let around = opt_usize(args, "around")?.unwrap_or(0);
        let max_items = opt_usize(args, "max_items")?;
        let max_bytes = opt_usize(args, "max_bytes")?;
        // 预算下限（R4）：max_items < 1、max_bytes < 4096 协议层 -32602。
        reject_below_floor(max_items, "max_items", 1)?;
        reject_below_floor(max_bytes, "max_bytes", 4096)?;
        self.run_app(AppRequest::Message {
            message_id,
            session_id,
            around,
            budget: budget_with(max_items, max_bytes, None),
        })
    }

    fn tool_list(&self, args: &Map<String, Value>) -> Result<Value, ToolError> {
        reject_unknown_keys(args, &["limit", "cursor", "max_items", "max_bytes"])?;
        let limit = opt_usize(args, "limit")?;
        let cursor = opt_str(args, "cursor")?;
        let max_items = opt_usize(args, "max_items")?;
        let max_bytes = opt_usize(args, "max_bytes")?;
        // 与 search_sessions 同层（R4，Minor-7）：limit/max_items/max_bytes 低于
        // 下限在协议层 -32602，不得漏到 App 层变 isError 业务帧。
        reject_below_floor(limit, "limit", 1)?;
        reject_below_floor(max_items, "max_items", 1)?;
        reject_below_floor(max_bytes, "max_bytes", 4096)?;
        self.run_app(AppRequest::List {
            limit: limit.or(max_items).unwrap_or(20),
            cursor,
            budget: budget_with(max_items, max_bytes, None),
            sessions_only: true,
        })
    }

    /// generate_handoff：检索命中 → 权威 source locator → deterministic pack。
    /// 与 CLI `handoff` 走同一 Application ADT 用例与同一包构建器；预算截断
    /// 如实报 `partial`（outcome），绝不伪装 success。
    fn tool_handoff(&self, args: &Map<String, Value>) -> Result<Value, ToolError> {
        reject_unknown_keys(
            args,
            &[
                "query",
                "limit",
                "max_evidence",
                "max_tokens",
                "max_bytes",
                "providers",
                "since",
                "until",
            ],
        )?;
        let query = required_str(args, "query")?;
        let limit = opt_usize(args, "limit")?;
        let max_evidence = opt_usize(args, "max_evidence")?.unwrap_or(20);
        let max_tokens = opt_usize(args, "max_tokens")?.unwrap_or(8000);
        let max_bytes = opt_usize(args, "max_bytes")?.unwrap_or(2_000_000);
        reject_below_floor(limit, "limit", 1)?;
        reject_below_floor(max_evidence.into(), "max_evidence", 1)?;
        reject_below_floor(max_tokens.into(), "max_tokens", 1)?;
        reject_below_floor(max_bytes.into(), "max_bytes", 4096)?;
        let filters = opt_filters(args)?;
        let search_limit = limit.unwrap_or(50);
        let app = App::with_resume(
            store_ref(self.store),
            store_ref(self.store),
            store_ref(self.store),
        );
        // 检索作为装配源：宽松 fetch-all 预算 + 全文级 snippet；pack 预算由
        // 包构建器单一执行（与 CLI handoff 同一约定）。
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
        });
        let (hits, generation) = match response {
            Ok(AppResponse::Search {
                hits, generation, ..
            }) => (hits, generation),
            Ok(_) => {
                return Err(ToolError::Params(
                    "handoff: unexpected search response".into(),
                ));
            }
            Err(error) => return Err(ToolError::Business(error.into())),
        };
        let source_locations = resolve_source_locations(self.store, &hits).map_err(business)?;
        let hit_ids: Vec<_> = hits.iter().map(|h| h.id.clone()).collect();
        let tool_activities = self
            .store
            .tool_activities_for_messages(&hit_ids)
            .map_err(business)?;
        let message_facts: Vec<_> = self
            .store
            .message_facts_for(&hit_ids)
            .map_err(business)?
            .into_iter()
            .map(|(message_id, role, is_sidechain)| {
                agent_session_grep_application::handoff_pack::MessageFact {
                    message_id,
                    role,
                    is_sidechain,
                }
            })
            .collect();
        let pack =
            agent_session_grep_application::handoff_pack::generate_deterministic(HandoffInput {
                query_terms: std::slice::from_ref(&query),
                retrieval_mode: RetrievalMode::Lexical,
                filters: HandoffFilters {
                    providers: filters
                        .providers
                        .iter()
                        .map(|p| p.as_str().to_string())
                        .collect(),
                    since: filters
                        .since
                        .map(|s| format!("{}.{:09}Z", s.unix_seconds, s.nanosecond)),
                    until: filters
                        .until
                        .map(|s| format!("{}.{:09}Z", s.unix_seconds, s.nanosecond)),
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
            Outcome::Partial
        } else {
            Outcome::Success
        };
        let data = serde_json::to_value(&pack)
            .map_err(|e| ToolError::Params(format!("handoff: serialization error: {e}")))?;
        Ok(success_payload(
            outcome,
            data,
            &protocol::Page::default(),
            &[],
        ))
    }

    /// doctor 不经 App：直接读 store 只读事实，data 形状与 CLI doctor 对齐。
    fn tool_doctor(&self) -> Result<Value, ToolError> {
        let schema = self.store.schema_version().map_err(business)?;
        let generation = self.store.active_generation().map_err(business)?;
        let interrupted = self.store.interrupted_batch_count().map_err(business)?;
        let (orphaned_tool_activities, orphaned_activity_memberships) =
            self.store.orphaned_activity_counts().map_err(business)?;
        Ok(success_payload(
            Outcome::Success,
            json!({
                "tool": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
                "db": "ok",
                "schema": schema,
                "generation": generation,
                "interrupted_batches": interrupted,
                "orphaned_tool_activities": orphaned_tool_activities,
                "orphaned_activity_memberships": orphaned_activity_memberships,
            }),
            &protocol::Page::default(),
            &[],
        ))
    }

    /// 良构请求进 Application，成功走 CLI 同一个 [`render`] 投影；
    /// 失败即业务错误——此后不再产生 `-32602`（design §2 note）。
    fn run_app(&self, request: AppRequest) -> Result<Value, ToolError> {
        let app = App::with_resume(
            store_ref(self.store),
            store_ref(self.store),
            store_ref(self.store),
        );
        match app.handle(request) {
            Ok(response) => {
                let (outcome, data, page, warnings) = render(response);
                Ok(success_payload(outcome, data, &page, &warnings))
            }
            Err(error) => Err(ToolError::Business(error.into())),
        }
    }
}

/// 版本协商（design §0.1）：回显受支持的请求版本，否则回落钉住的最新版。
/// 只返回支持集合内的静态字符串，结构上排除"谎报支持"的可能。
fn negotiate_version(requested: Option<&str>) -> &'static str {
    for supported in SUPPORTED_PROTOCOL_VERSIONS {
        if Some(supported) == requested {
            return supported;
        }
    }
    LATEST_PROTOCOL_VERSION
}

/// tools/list catalog: the eight MCP tools exposed by this build. Schema and
/// code-side validation remain aligned (`additionalProperties: false`).
fn tool_catalog() -> Value {
    json!([
        {
            "name": "search_sessions",
            "description": "Full-text search over ingested AI coding-agent session \
                history. Hits are message-level entities (msg_v1_ ids) in relevance \
                order, each carrying session_id (owning session wire id) and text \
                (body summary); pass page.next_cursor back as cursor to fetch the \
                next page.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "maxLength": 4096,
                        "description": "Full-text query."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Page size; defaults to 20."
                    },
                    "cursor": {
                        "type": "string",
                        "maxLength": 512,
                        "description": "Continuation token from the previous page's \
                            page.next_cursor."
                    },
                    "max_items": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Response item budget; also caps the page size. Minimum 1 (runtime rejects 0)."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 4096,
                        "description": "Response byte budget. Minimum 4096 (runtime rejects smaller)."
                    },
                    "providers": {
                        "type": "array",
                        "maxItems": 2,
                        "items": { "type": "string", "enum": ["claude", "claude-code", "codex"] },
                        "description": "Restrict hits to these providers (OR). Omitted matches all providers."
                    },
                    "since": {
                        "type": "string",
                        "maxLength": 64,
                        "description": "Inclusive lower time bound as an absolute ISO-8601 \
                            timestamp with offset (e.g. 2026-08-01T00:00:00Z). Compact \
                            durations are not accepted."
                    },
                    "until": {
                        "type": "string",
                        "maxLength": 64,
                        "description": "Exclusive upper time bound; same syntax as since. \
                            Interval is half-open [since, until)."
                    },
                    "include_system": {
                        "type": "boolean",
                        "description": "Include system/developer-role messages. Default \
                            false: system noise is excluded from hits."
                    },
                    "group_by_session": {
                        "type": "boolean",
                        "description": "Collapse hits per session: best-scoring hit first, \
                            with an occurrences count. Default false keeps one hit per match."
                    },
                    "sidechain": {
                        "type": "string",
                        "enum": ["include", "main_only", "subagent_only"],
                        "description": "Sidechain facet: include (default) keeps all; \
                            main_only keeps messages with no sidechain placement; \
                            subagent_only keeps messages with at least one."
                    },
                    "tool_kind": {
                        "type": "string",
                        "enum": ["file", "command", "web", "query", "unknown"],
                        "description": "Keep only messages carrying a tool activity of \
                            this kind (closed set; unknown = tools outside the known set)."
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Keep only messages carrying a tool activity with \
                            this exact tool name (e.g. Bash, Read, shell)."
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["lexical", "semantic", "hybrid"],
                        "description": "Retrieval mode. Default lexical. semantic/hybrid \
                            require the vector index (`index embeddings`); when it is \
                            not ready the response honestly reports \
                            retrieval_mode=lexical_fallback with a warning."
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }
        },
        {
            "name": "get_session_context",
            "description": "Assemble one session's branch: ordered messages plus \
                evidence spans. policy mainline (default) walks the parent chain \
                excluding sidechains; full returns every message in seq order.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "maxLength": 128,
                        "description": "Session wire id (ses_v1_ prefix)."
                    },
                    "policy": {
                        "type": "string",
                        "enum": ["mainline", "full"],
                        "description": "Branch selection policy; defaults to mainline."
                    },
                    "level": {
                        "type": "string",
                        "enum": ["raw", "talks", "sessions"],
                        "description": "Structural response level; defaults to raw \
                            (omission preserves the raw message stream). talks groups \
                            each user message with its following assistant/tool \
                            messages; sessions adds one structural overview. Empty \
                            derived views fall back toward more detail \
                            (sessions -> talks -> raw) and report effective_level."
                    },
                    "max_messages": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Message count budget. Minimum 1 (runtime rejects 0)."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 4096,
                        "description": "Response byte budget. Minimum 4096 (runtime rejects smaller)."
                    }
                },
                "required": ["session_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "get_session_resume",
            "description": "Return read-only structured resume metadata for one canonical Session. Nullable fields remain explicit; no command or source path is returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "maxLength": 128,
                        "description": "Canonical Session wire id (ses_v1_ prefix)."
                    }
                },
                "required": ["session_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "get_message",
            "description": "Return one message and a bounded ordered window around it. The message_id may be shared across sessions; omit session_id only when it resolves uniquely. around defaults to 0 and includes the anchor only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message_id": {
                        "type": "string",
                        "maxLength": 128,
                        "description": "Message wire id (msg_v1_ prefix)."
                    },
                    "session_id": {
                        "type": "string",
                        "maxLength": 128,
                        "description": "Optional Session wire id (ses_v1_ prefix). Required when the message occurs in multiple sessions."
                    },
                    "around": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of mainline neighbors requested on each side; defaults to 0."
                    },
                    "max_items": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Maximum number of returned messages, including the anchor."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 4096,
                        "description": "Response byte budget. Minimum 4096 (runtime rejects smaller)."
                    }
                },
                "required": ["message_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "list_sessions",
            "description": "Page Session entities (ses_v1_) in stable wire-id order. \
                Documents and messages are not returned (competitor-borrowings R1.3); \
                only session entities are listed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Page size; defaults to 20. Minimum 1 (runtime rejects 0)."
                    },
                    "cursor": {
                        "type": "string",
                        "maxLength": 512,
                        "description": "Continuation token from the previous page's \
                            page.next_cursor."
                    },
                    "max_items": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Response item budget; also caps the page size. Minimum 1 (runtime rejects 0)."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 4096,
                        "description": "Response byte budget. Minimum 4096 (runtime rejects smaller)."
                    }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "generate_handoff",
            "description": "Assemble a deterministic handoff pack (handoff-pack/v1) for \
                a query: search hits become evidence spans with authoritative source \
                document locators, budgets (max_evidence/max_tokens/max_bytes) are \
                enforced, and evidence is cross-boundary redacted by default (ADR-0009). \
                Truncation is reported as outcome partial.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "maxLength": 4096,
                        "description": "Full-text query."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Search page size; defaults to 50."
                    },
                    "max_evidence": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Evidence entry cap. Minimum 1 (runtime rejects 0)."
                    },
                    "max_tokens": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Token budget for evidence. Minimum 1 (runtime rejects 0)."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 4096,
                        "description": "Serialized pack byte budget. Minimum 4096 (runtime rejects smaller)."
                    },
                    "providers": {
                        "type": "array",
                        "maxItems": 2,
                        "items": { "type": "string", "enum": ["claude", "claude-code", "codex"] },
                        "description": "Restrict hits to these providers (OR). Omitted matches all providers."
                    },
                    "since": {
                        "type": "string",
                        "maxLength": 64,
                        "description": "Inclusive lower time bound as an absolute ISO-8601 timestamp with offset."
                    },
                    "until": {
                        "type": "string",
                        "maxLength": 64,
                        "description": "Exclusive upper time bound; same syntax as since."
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }
        },
        {
            "name": "list_providers",
            "description": "List the provider adapters this build can ingest, including each adapter's capability-matrix maturity \
                (stable ids such as claude-code).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "get_status",
            "description": "Report catalog entity count and the active generation.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "doctor",
            "description": "Read-only store health check: schema version, active \
                generation, interrupted batch count.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }
    ])
}

/// 成功工具 payload（9 个工具同形，design §2）：outcome/data/warnings/page。
fn success_payload(
    outcome: Outcome,
    data: Value,
    page: &protocol::Page,
    warnings: &[String],
) -> Value {
    let outcome_str = match outcome {
        Outcome::Success => "success",
        Outcome::Partial => "partial",
    };
    json!({
        "outcome": outcome_str,
        "data": data,
        "warnings": warnings,
        "page": {
            "next_cursor": page.next_cursor.as_deref().map_or(Value::Null, |c| json!(c)),
            "has_more": page.has_more,
        },
    })
}

/// list_providers 投影完整 16 行能力矩阵（14 个可 ingest + 2 个 deferred），
/// 与 CLI `providers` 命令同一单源。`ingestible` 区分注册表内 adapter 与
/// deferred 行：deferred 行如实标注 false 而非被静默省略（audit P1-5）。
fn providers_payload() -> Value {
    let matrix = ProviderCapabilityMatrix::current();
    let registered = provider_registry();
    let registry: Vec<&str> = registered
        .iter()
        .map(|adapter| adapter.provider_id())
        .collect();
    let providers: Vec<Value> = matrix
        .providers
        .iter()
        .map(|capability| {
            json!({
                "id": capability.provider_id.as_str(),
                "variant": capability.variant_id.as_str(),
                "maturity": capability.maturity,
                "maturity_target": ProviderMaturity::target_for(&capability.provider_id),
                "ingestible": registry.contains(&capability.provider_id.as_str()),
            })
        })
        .collect();
    success_payload(
        Outcome::Success,
        json!({ "providers": providers }),
        &protocol::Page::default(),
        &[],
    )
}

/// 业务失败的工具结果：`isError: true` + canonical error（design §2）。
/// 与成功路径同一脱敏纪律：error message/details 也经 cross-boundary
/// 脱敏后再上帧，防止用户参数回声里的密钥/路径泄漏（ADR-0009）。
fn business_error_result(error: &ProtocolError) -> Value {
    let (message, _) = crate::redaction::redact_text(&error.message);
    let (details, _) = crate::redaction::redact_value(error.details.clone());
    json!({
        "content": [{ "type": "text", "text": message }],
        "structuredContent": {
            "error": {
                "canonical_code": error.code.as_str(),
                "message": message,
                "retryable": error.code.retryable(),
                "details": details,
            }
        },
        "isError": true,
    })
}

fn business(error: impl Into<ProtocolError>) -> ToolError {
    ToolError::Business(error.into())
}

/// `-32602` 的 `error.data`：结构化 canonical 标注（design §2 note）。
fn invalid_request_data() -> Value {
    json!({
        "canonical_code": CanonicalCode::InvalidRequest.as_str(),
        "retryable": CanonicalCode::InvalidRequest.retryable(),
    })
}

fn result_frame(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_frame(id: Value, code: i64, message: &str, data: Option<Value>) -> String {
    // 协议错误帧同样脱敏：-32602 消息可能回声用户参数（工具名/键名），
    // 跨边界输出不得泄漏密钥/路径（ADR-0009）。
    let (message, _) = crate::redaction::redact_text(message);
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error }).to_string()
}

/// schema `additionalProperties: false` 的代码侧强制：未知键 → `-32602`。
/// 键名回显前截断（R5）。
fn reject_unknown_keys(args: &Map<String, Value>, allowed: &[&str]) -> Result<(), ToolError> {
    for key in args.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ToolError::Params(format!(
                "unknown parameter: {}",
                bounded(key)
            )));
        }
    }
    Ok(())
}

fn required_str(args: &Map<String, Value>, key: &str) -> Result<String, ToolError> {
    match args.get(key) {
        Some(Value::String(value)) => {
            validate_string_length(key, value)?;
            Ok(value.clone())
        }
        Some(_) => Err(ToolError::Params(format!("{key} must be a string"))),
        None => Err(ToolError::Params(format!(
            "missing required parameter: {key}"
        ))),
    }
}

fn opt_str(args: &Map<String, Value>, key: &str) -> Result<Option<String>, ToolError> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => {
            validate_string_length(key, value)?;
            Ok(Some(value.clone()))
        }
        Some(_) => Err(ToolError::Params(format!("{key} must be a string"))),
    }
}

fn validate_string_length(key: &str, value: &str) -> Result<(), ToolError> {
    let max = match key {
        "query" => 4096,
        "cursor" => 512,
        "since" | "until" => 64,
        "session_id" | "message_id" => 128,
        _ => return Ok(()),
    };
    if value.chars().count() > max {
        return Err(ToolError::Params(format!(
            "{key} exceeds the maximum length of {max} characters"
        )));
    }
    Ok(())
}

/// 检索过滤参数（design §3）：providers 别名数组（OR 语义）+ 绝对 ISO-8601
/// 的 since/until（半开区间 [since, until)，边界比较由 Application 统一执行）。
/// provider 值经 [`crate::canonical_search_provider`] 归一（canonical id 与
/// 历史别名），与 CLI `--provider` 同一套取值。
/// MCP 只接受绝对时间：紧凑相对量（"1h"）没有声明的时钟基准，属非法参数。
fn opt_filters(args: &Map<String, Value>) -> Result<SearchFilters, ToolError> {
    let mut filters = SearchFilters::default();
    if let Some(value) = args.get("providers") {
        let Value::Array(entries) = value else {
            return Err(ToolError::Params("providers must be an array".into()));
        };
        for entry in entries {
            let Some(provider) = entry.as_str() else {
                return Err(ToolError::Params(
                    "providers entries must be strings".into(),
                ));
            };
            filters
                .providers
                .push(canonical_search_provider(provider).ok_or_else(|| {
                    ToolError::Params(format!(
                        "providers must contain only claude|claude-code|codex, got {}",
                        bounded(provider)
                    ))
                })?);
        }
    }
    filters.since = opt_instant(args, "since")?;
    filters.until = opt_instant(args, "until")?;
    Ok(filters)
}

/// 绝对时间参数：RFC3339/ISO-8601（带 offset/Z）。紧凑相对量（"1h"）在 MCP
/// 层直接拒绝——协议不携带时钟基准，不得静默换算。
fn opt_instant(
    args: &Map<String, Value>,
    key: &str,
) -> Result<Option<agent_session_grep_ports::SearchInstant>, ToolError> {
    let Some(raw) = opt_str(args, key)? else {
        return Ok(None);
    };
    parse_search_instant(&raw).map(Some).ok_or_else(|| {
        ToolError::Params(format!(
            "{key} must be an absolute ISO-8601 timestamp with offset (e.g. 2026-08-01T00:00:00Z)"
        ))
    })
}

/// 整数参数（design §3）：必须是非负整数 JSON number 且装得进 usize；
/// 负数、小数、字符串数字一律 `-32602`。
fn opt_usize(args: &Map<String, Value>, key: &str) -> Result<Option<usize>, ToolError> {
    match args.get(key) {
        None => Ok(None),
        Some(value) => {
            let n = value.as_u64().ok_or_else(|| {
                ToolError::Params(format!("{key} must be a non-negative integer"))
            })?;
            usize::try_from(n)
                .map(Some)
                .map_err(|_| ToolError::Params(format!("{key} exceeds the platform usize range")))
        }
    }
}

/// 布尔参数：必须是 JSON bool；省略时取 `default`。
fn opt_bool(args: &Map<String, Value>, key: &str, default: bool) -> Result<bool, ToolError> {
    match args.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .map(Ok)
            .unwrap_or_else(|| Err(ToolError::Params(format!("{key} must be a boolean")))),
    }
}

/// params 形状（ping / tools/list / notifications/initialized 共用，R3）：
/// 缺失或对象合法；null/数组/原语非法。
fn params_object_or_absent(params: Option<&Value>) -> bool {
    matches!(params, None | Some(Value::Object(_)))
}

/// 严格 id 校验（R3）：string / null / 整数 number 合法；array、object、
/// 浮点型 number（含 1.0 这类 float 字面量）与 bool 一律非法 → `-32600`。
fn is_valid_jsonrpc_id(id: &Value) -> bool {
    match id {
        Value::Null | Value::String(_) => true,
        Value::Number(number) => number.is_i64() || number.is_u64(),
        _ => false,
    }
}

/// 错误消息插值截断（R5）：超长 method/tool/id/参数值回显前截到
/// [`ECHO_CAP`] 字符，截断处以 "..." 标记。
fn bounded(value: &str) -> String {
    let mut chars = value.chars();
    let head: String = chars.by_ref().take(ECHO_CAP).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

/// 预算/分页下限（R4）：低于下限在协议层 -32602，在构造 [`AppRequest`]
/// 之前拒绝；App 层 `ResponseBudget::validate` 保留为纵深防御。
fn reject_below_floor(value: Option<usize>, key: &str, floor: usize) -> Result<(), ToolError> {
    match value {
        Some(value) if value < floor => Err(ToolError::Params(format!("{key} must be >= {floor}"))),
        _ => Ok(()),
    }
}

/// 默认预算 + 工具参数覆盖。CLI 的 `budget_from_flags` 是字符串 flag 形，
/// 这里参数已是类型化 usize，故独立构造；下限校验仍由 App 层统一执行。
fn budget_with(
    max_items: Option<usize>,
    max_bytes: Option<usize>,
    max_messages: Option<usize>,
) -> ResponseBudget {
    let mut budget = ResponseBudget::default();
    if let Some(value) = max_items {
        budget.max_items = value;
    }
    if let Some(value) = max_bytes {
        budget.max_response_bytes = value;
    }
    if let Some(value) = max_messages {
        budget.max_messages = value;
    }
    budget
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::{IdKind, Stability};
    use agent_session_grep_ports::SearchProvider;

    fn open_store(dir: &tempfile::TempDir) -> SqliteStore {
        let path = dir.path().join("mcp-test.db");
        SqliteStore::open_for_write(path.to_str().expect("temp path must be utf-8"))
            .expect("open store for write")
    }

    /// 两条可检索消息（都命中 "hello"），供搜索/分页/status 用例。
    fn seeded_store(dir: &tempfile::TempDir) -> SqliteStore {
        let store = open_store(dir);
        let entries = [
            (
                StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"t1"]),
                b"payload-1".to_vec(),
                "hello world".to_string(),
            ),
            (
                StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"t2"]),
                b"payload-2".to_vec(),
                "hello there".to_string(),
            ),
        ];
        store
            .commit_batch(&entries)
            .expect("commit searchable rows");
        store
    }

    fn fresh(store: &SqliteStore) -> McpServer<'_> {
        McpServer {
            store,
            initialized: false,
            initialize_seen: false,
        }
    }

    fn ready(store: &SqliteStore) -> McpServer<'_> {
        McpServer {
            store,
            initialized: true,
            initialize_seen: true,
        }
    }

    fn parse(frame: &str) -> Value {
        serde_json::from_str(frame).expect("frame must be valid JSON")
    }

    fn request(id: u64, method: &str, params: Value) -> String {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
    }

    /// 完整合法的 initialize params（R3 起 protocolVersion/capabilities/clientInfo
    /// 三个字段全部必填）。
    fn init_params(version: &str) -> Value {
        json!({
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0" },
        })
    }

    fn respond(server: &mut McpServer<'_>, line: &str) -> Value {
        let frame = server
            .handle_line(line)
            .expect("request must get a response");
        parse(&frame)
    }

    fn call(server: &mut McpServer<'_>, name: &str, arguments: Value) -> Value {
        respond(
            server,
            &request(
                7,
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            ),
        )
    }

    #[test]
    fn negotiate_version_echoes_each_supported_version() {
        for supported in SUPPORTED_PROTOCOL_VERSIONS {
            assert_eq!(negotiate_version(Some(supported)), supported);
        }
    }

    #[test]
    fn negotiate_version_falls_back_to_latest_when_unsupported_or_absent() {
        assert_eq!(
            negotiate_version(Some("9999-01-01")),
            LATEST_PROTOCOL_VERSION
        );
        assert_eq!(negotiate_version(None), LATEST_PROTOCOL_VERSION);
    }

    #[test]
    fn initialize_reports_negotiated_version_and_server_info() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        let v = respond(
            &mut server,
            &request(1, "initialize", init_params("2024-11-05")),
        );
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(v["result"]["serverInfo"]["name"], "agent-session-grep");
        assert_eq!(
            v["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert!(v["result"]["capabilities"]["tools"].is_object());
        // 不支持的版本诚实回落钉住的最新版，绝不回显谎报。
        let v = respond(
            &mut server,
            &request(2, "initialize", init_params("9999-01-01")),
        );
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn ping_is_allowed_before_initialization() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        let v = respond(&mut server, &request(3, "ping", json!({})));
        assert_eq!(v["result"], json!({}));
    }

    #[test]
    fn requests_before_initialized_notification_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        let v = respond(&mut server, &request(2, "tools/list", json!({})));
        assert_eq!(v["error"]["code"], -32600);
        assert!(
            v["error"]["message"]
                .as_str()
                .expect("message")
                .contains("not initialized")
        );
        // 门闩优先于方法分发：未初始化时未知方法同样 -32600（design §0.7）。
        let v = respond(&mut server, &request(3, "foo/bar", json!({})));
        assert_eq!(v["error"]["code"], -32600);
    }

    #[test]
    fn initialized_notification_is_silent_and_opens_the_gate_after_handshake() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        // 握手先行：initialize 请求之后，initialized 通知才开门闩（Minor-8）。
        let v = respond(
            &mut server,
            &request(1, "initialize", init_params("2025-06-18")),
        );
        assert!(v["result"]["protocolVersion"].is_string());
        let silent = server.handle_line(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
        );
        assert!(silent.is_none(), "notification must not get a response");
        let v = respond(&mut server, &request(4, "tools/list", json!({})));
        assert!(v["result"]["tools"].is_array());
    }

    #[test]
    fn initialized_notification_without_handshake_does_not_open_gate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        // 未发过 initialize 请求就发 initialized 通知：门闩保持关闭。
        let silent = server.handle_line(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
        );
        assert!(silent.is_none(), "notification must not get a response");
        let v = respond(&mut server, &request(4, "tools/list", json!({})));
        assert_eq!(v["error"]["code"], -32600);
        assert!(
            v["error"]["message"]
                .as_str()
                .expect("message")
                .contains("not initialized")
        );
    }

    #[test]
    fn notification_without_string_method_is_invalid_request() {
        // 缺 method / method 非字符串的不是合法 notification，必须回 -32600
        // 而非静默丢弃（JSON-RPC 对无效消息的拒绝义务，Minor-8）。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for line in [
            json!({ "jsonrpc": "2.0" }).to_string(),
            json!({ "jsonrpc": "2.0", "method": 42 }).to_string(),
        ] {
            let frame = server
                .handle_line(&line)
                .unwrap_or_else(|| panic!("invalid notification must get a response: {line}"));
            let v = parse(&frame);
            assert_eq!(v["error"]["code"], -32600, "{line}");
            assert!(v["id"].is_null(), "{line}");
        }
    }

    #[test]
    fn initialize_with_non_object_params_is_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        for params in [json!(42), json!(null), json!("x"), json!([])] {
            let v = respond(&mut server, &request(1, "initialize", params.clone()));
            assert_eq!(v["error"]["code"], -32602, "{params}");
            assert_eq!(v["error"]["data"]["canonical_code"], "invalid_request");
        }
        // params 键缺席同样是失败握手：initialize 必须携带完整 params（R3），
        // 不再静默回落钉住的最新版。
        let v = respond(
            &mut server,
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize" }).to_string(),
        );
        assert_eq!(v["error"]["code"], -32602, "{v}");
    }

    #[test]
    fn non_2_0_jsonrpc_is_invalid_request_everywhere() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for line in [
            json!({ "id": 1, "method": "ping" }).to_string(),
            json!({ "jsonrpc": "1.0", "id": 1, "method": "ping" }).to_string(),
            json!({ "jsonrpc": 2.0, "id": 1, "method": "ping" }).to_string(),
            json!({ "jsonrpc": ["2.0"], "id": 1, "method": "ping" }).to_string(),
            // notification 同样必须携带 2.0（R3）。
            json!({ "jsonrpc": "1.0", "method": "notifications/initialized" }).to_string(),
        ] {
            let frame = server
                .handle_line(&line)
                .unwrap_or_else(|| panic!("bad jsonrpc must get a response: {line}"));
            let v = parse(&frame);
            assert_eq!(v["error"]["code"], -32600, "{line}");
            assert!(v["id"].is_null(), "{line}");
        }
    }

    #[test]
    fn invalid_id_types_are_invalid_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for line in [
            json!({ "jsonrpc": "2.0", "id": [1], "method": "ping" }).to_string(),
            json!({ "jsonrpc": "2.0", "id": {}, "method": "ping" }).to_string(),
            json!({ "jsonrpc": "2.0", "id": true, "method": "ping" }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 1.5, "method": "ping" }).to_string(),
            json!({ "jsonrpc": "2.0", "id": 1.0, "method": "ping" }).to_string(),
        ] {
            let v = respond(&mut server, &line);
            assert_eq!(v["error"]["code"], -32600, "{line}");
            assert!(v["id"].is_null(), "非法 id 无法回显: {line}");
        }
        // 合法形态照常应答：整数、字符串（null 由既有用例覆盖）。
        let v = respond(
            &mut server,
            &json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }).to_string(),
        );
        assert_eq!(v["id"], 7);
        let v = respond(
            &mut server,
            &json!({ "jsonrpc": "2.0", "id": "abc", "method": "ping" }).to_string(),
        );
        assert_eq!(v["id"], "abc");
    }

    #[test]
    fn initialize_requires_protocol_version_capabilities_and_client_info() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        let cases = [
            json!({}),
            json!({ "protocolVersion": "2025-06-18" }),
            json!({ "protocolVersion": "2025-06-18", "capabilities": {} }),
            json!({ "protocolVersion": 7, "capabilities": {}, "clientInfo": {} }),
            json!({ "protocolVersion": "2025-06-18", "capabilities": [], "clientInfo": {} }),
            json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": "x" }),
        ];
        for (index, params) in cases.iter().enumerate() {
            let v = respond(
                &mut server,
                &request(index as u64, "initialize", params.clone()),
            );
            assert_eq!(v["error"]["code"], -32602, "{params}");
            assert_eq!(v["error"]["data"]["canonical_code"], "invalid_request");
        }
        // 任何一次失败握手都不得推进 initialize_seen：initialized 通知无权开门。
        let silent = server.handle_line(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
        );
        assert!(silent.is_none());
        let v = respond(&mut server, &request(9, "tools/list", json!({})));
        assert_eq!(v["error"]["code"], -32600, "{v}");
        // 完整 params 才握手成功（MCP 允许的额外字段不影响校验）。
        let mut params = init_params("2025-06-18");
        params["extra"] = json!(true);
        let v = respond(&mut server, &request(10, "initialize", params));
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn failed_initialize_does_not_open_gate_via_initialized_notification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        // 失败握手（params 非对象）：initialize_seen 不得推进。
        let v = respond(&mut server, &request(1, "initialize", json!(42)));
        assert_eq!(v["error"]["code"], -32602);
        // 随后的 initialized 通知不得开门闩。
        let silent = server.handle_line(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
        );
        assert!(silent.is_none());
        let v = respond(&mut server, &request(2, "tools/list", json!({})));
        assert_eq!(v["error"]["code"], -32600, "{v}");
    }

    #[test]
    fn ping_and_tools_list_require_object_or_absent_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for params in [json!([]), json!("x"), json!(5), json!(null)] {
            let v = respond(&mut server, &request(1, "ping", params.clone()));
            assert_eq!(v["error"]["code"], -32602, "ping {params}");
            let v = respond(&mut server, &request(2, "tools/list", params.clone()));
            assert_eq!(v["error"]["code"], -32602, "tools/list {params}");
        }
        // 对象（含未知键）与缺失照常应答。
        let v = respond(&mut server, &request(3, "ping", json!({ "extra": true })));
        assert_eq!(v["result"], json!({}));
        let v = respond(
            &mut server,
            &json!({ "jsonrpc": "2.0", "id": 4, "method": "ping" }).to_string(),
        );
        assert_eq!(v["result"], json!({}));
        let v = respond(&mut server, &request(5, "tools/list", json!({})));
        assert!(v["result"]["tools"].is_array());
    }

    #[test]
    fn initialized_notification_with_non_object_params_is_rejected_and_does_not_open_gate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        // 成功握手先行。
        let v = respond(
            &mut server,
            &request(1, "initialize", init_params("2025-06-18")),
        );
        assert!(v["result"]["protocolVersion"].is_string());
        // params 非法（数组）→ 畸形通知回 -32600（id null），且不得开门闩。
        let frame = server
            .handle_line(
                &json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": [1] })
                    .to_string(),
            )
            .expect("malformed notification must get a response");
        let v = parse(&frame);
        assert_eq!(v["error"]["code"], -32600);
        assert!(v["id"].is_null());
        let v = respond(&mut server, &request(2, "tools/list", json!({})));
        assert_eq!(v["error"]["code"], -32600, "gate must stay closed: {v}");
        // 合法 initialized 通知（对象 params）→ 静默且开门。
        let silent = server.handle_line(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} })
                .to_string(),
        );
        assert!(silent.is_none());
        let v = respond(&mut server, &request(3, "tools/list", json!({})));
        assert!(v["result"]["tools"].is_array());
    }

    #[test]
    fn notifications_never_get_a_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for method in ["notifications/cancelled", "totally/unknown", "tools/list"] {
            let silent =
                server.handle_line(&json!({ "jsonrpc": "2.0", "method": method }).to_string());
            assert!(silent.is_none(), "{method} without id must stay silent");
        }
    }

    #[test]
    fn request_with_explicit_null_id_is_answered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = fresh(&store);
        let v = respond(
            &mut server,
            &json!({ "jsonrpc": "2.0", "id": null, "method": "ping" }).to_string(),
        );
        assert!(v["id"].is_null());
        assert_eq!(v["result"], json!({}));
    }

    #[test]
    fn malformed_json_yields_parse_error_with_null_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = respond(&mut server, "{ not json");
        assert_eq!(v["error"]["code"], -32700);
        assert!(v["id"].is_null());
    }

    #[test]
    fn non_object_and_batch_inputs_are_invalid_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let batch = format!("[{}]", request(1, "ping", json!({})));
        for line in ["[]", "42", "\"frame\"", batch.as_str()] {
            let v = respond(&mut server, line);
            assert_eq!(v["error"]["code"], -32600, "{line}");
            assert!(v["id"].is_null(), "{line}");
        }
    }

    #[test]
    fn unknown_request_method_yields_method_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = respond(&mut server, &request(5, "foo/bar", json!({})));
        assert_eq!(v["error"]["code"], -32601);
    }

    #[test]
    fn tools_list_exposes_exactly_the_nine_contract_tools() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = respond(&mut server, &request(6, "tools/list", json!({})));
        let tools = v["result"]["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect();
        assert_eq!(
            names,
            [
                "search_sessions",
                "get_session_context",
                "get_session_resume",
                "get_message",
                "list_sessions",
                "generate_handoff",
                "list_providers",
                "get_status",
                "doctor",
            ]
        );
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object", "{}", tool["name"]);
            assert_eq!(
                tool["inputSchema"]["additionalProperties"], false,
                "{}",
                tool["name"]
            );
            assert!(tool["description"].as_str().is_some_and(|d| !d.is_empty()));
        }
    }

    #[test]
    fn generate_handoff_tool_returns_deterministic_pack_with_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let message_a = StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"h1"]);
        let message_b = StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"h2"]);
        store
            .commit_batch(&[
                (
                    message_a.clone(),
                    br#"{"text":"hello world"}"#.to_vec(),
                    "hello world".to_string(),
                ),
                (
                    message_b.clone(),
                    br#"{"text":"hello there"}"#.to_vec(),
                    "hello there".to_string(),
                ),
            ])
            .expect("commit searchable rows");
        // 权威 source placement：直接写入 message → session/document/span 关系行。
        let session = StableId::derive(IdKind::Session, Stability::Reconstructed, &[b"ses1"]);
        let document = StableId::derive(IdKind::Document, Stability::Reconstructed, &[b"doc1"]);
        {
            use rusqlite::Connection;
            let conn = Connection::open(dir.path().join("mcp-test.db")).expect("open raw conn");
            for (index, (message, byte_end)) in [(&message_a, 11u64), (&message_b, 12u64)]
                .iter()
                .enumerate()
            {
                conn.execute(
                    "INSERT INTO message_placements(
                         placement_id, session_id, document_id, message_id,
                         source_ordinal, is_sidechain, byte_start, byte_end)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6)",
                    rusqlite::params![
                        format!("plc_v1_{}", message.as_str()),
                        session.as_str(),
                        document.as_str(),
                        message.as_str(),
                        index as i64,
                        *byte_end as i64,
                    ],
                )
                .expect("insert placement");
            }
        }
        let mut server = ready(&store);
        let v = call(&mut server, "generate_handoff", json!({ "query": "hello" }));
        assert_eq!(v["result"]["isError"], false, "{v}");
        let data = &v["result"]["structuredContent"]["data"];
        assert_eq!(data["schema_version"], "1.0");
        assert_eq!(data["generation_mode"], "deterministic");
        assert!(
            data["pack_id"].as_str().is_some_and(|id| id.len() > 8),
            "pack_id must be present"
        );
        let evidence = data["evidence"].as_array().expect("evidence array");
        assert_eq!(evidence.len(), 2);
        assert!(
            evidence[0]["source_document_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("doc_v1_"))
        );
        assert_eq!(data["redaction"]["status"], "none");
        assert_eq!(data["truncation"]["truncated"], false);
        assert_eq!(v["result"]["structuredContent"]["outcome"], "success");
    }

    #[test]
    fn unknown_tool_yields_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(&mut server, "frobnicate", json!({}));
        assert_eq!(v["error"]["code"], -32602);
        assert_eq!(v["error"]["data"]["canonical_code"], "invalid_request");
    }

    #[test]
    fn missing_required_query_is_invalid_params_with_canonical_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(&mut server, "search_sessions", json!({}));
        assert_eq!(v["error"]["code"], -32602);
        assert_eq!(v["error"]["data"]["canonical_code"], "invalid_request");
        assert_eq!(v["error"]["data"]["retryable"], false);
    }

    #[test]
    fn get_session_resume_validates_session_id_at_protocol_layer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let cases = [
            json!({}),
            json!({ "session_id": "not-a-wire-id" }),
            json!({ "session_id": "msg_v1_c0000000-0000-4000-8000-000000000001" }),
            json!({
                "session_id": "ses_v1_ccdd1234-5678-4abc-8def-001122334455",
                "extra": true,
            }),
        ];
        for arguments in cases {
            let v = call(&mut server, "get_session_resume", arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{arguments}"
            );
        }
    }

    #[test]
    fn get_session_resume_returns_fixed_read_only_metadata_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let session_id = "ses_v1_ccdd1234-5678-4abc-8def-001122334455";
        let v = call(
            &mut server,
            "get_session_resume",
            json!({ "session_id": session_id }),
        );
        assert_eq!(v["result"]["isError"], false, "{v}");
        let data = &v["result"]["structuredContent"]["data"];
        assert_eq!(data["session_id"], session_id);
        for field in [
            "provider_id",
            "resume_available",
            "provider_session_id",
            "original_working_directory",
            "unavailable_reason",
        ] {
            assert!(data.get(field).is_some(), "missing {field}: {data}");
        }
        assert!(data["provider_id"].is_null(), "{data}");
        assert_eq!(data["resume_available"], false, "{data}");
        assert!(data["provider_session_id"].is_null(), "{data}");
        assert!(data["original_working_directory"].is_null(), "{data}");
        assert!(data["unavailable_reason"].is_string(), "{data}");
        assert!(data.get("command").is_none(), "{data}");
        assert!(data.get("source_path").is_none(), "{data}");
        assert!(data.get("transcript_path").is_none(), "{data}");
    }

    #[test]
    fn out_of_schema_parameter_values_are_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let cases = [
            json!({ "query": 5 }),
            json!({ "query": "x", "cursor": 5 }),
            json!({ "query": "x", "max_items": -1 }),
            json!({ "query": "x", "max_items": 1.5 }),
            json!({ "query": "x", "limit": 0 }),
            json!({ "query": "x", "max_items": 0 }),
        ];
        for arguments in &cases {
            let v = call(&mut server, "search_sessions", arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{arguments}"
            );
        }
    }

    #[test]
    fn search_filter_schema_and_runtime_validation_stay_aligned() {
        let catalog = tool_catalog();
        let search = catalog
            .as_array()
            .and_then(|tools| tools.iter().find(|tool| tool["name"] == "search_sessions"))
            .expect("search_sessions tool must exist");
        let properties = &search["inputSchema"]["properties"];
        assert_eq!(
            properties["providers"]["items"]["enum"],
            json!(["claude", "claude-code", "codex"])
        );
        assert_eq!(properties["since"]["type"], "string");
        assert_eq!(properties["until"]["type"], "string");

        let valid = json!({
            "providers": ["codex", "claude", "claude-code"],
            "since": "2026-08-01T00:00:00Z",
            "until": "2026-08-02T00:00:00+00:00"
        });
        let filters = opt_filters(valid.as_object().expect("filter object"))
            .expect("declared filter values must parse");
        assert_eq!(
            filters.providers,
            vec![
                SearchProvider::Codex,
                SearchProvider::Claude,
                SearchProvider::Claude
            ]
        );
        assert!(filters.since.is_some());
        assert!(filters.until.is_some());
        assert!(filters.since < filters.until);

        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for arguments in [
            json!({ "query": "x", "providers": "claude" }),
            json!({ "query": "x", "providers": ["other"] }),
            json!({ "query": "x", "providers": [1] }),
            json!({ "query": "x", "since": "1h" }),
            json!({ "query": "x", "until": "2026-08-01" }),
        ] {
            let v = call(&mut server, "search_sessions", arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{arguments}"
            );
            assert!(v["result"].is_null(), "{arguments}");
        }
    }

    #[test]
    fn search_r2r3_flags_validate_and_apply() {
        // R2/R3 参数：schema 声明布尔型；非布尔值协议层拒绝；合法布尔被接受并
        // 贯通到 Application（seeded store 无 placement → 归并退化为单例组）。
        let catalog = tool_catalog();
        let search = catalog
            .as_array()
            .and_then(|tools| tools.iter().find(|tool| tool["name"] == "search_sessions"))
            .expect("search_sessions tool must exist");
        let properties = &search["inputSchema"]["properties"];
        assert_eq!(properties["include_system"]["type"], "boolean");
        assert_eq!(properties["group_by_session"]["type"], "boolean");

        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        for arguments in [
            json!({ "query": "x", "include_system": "yes" }),
            json!({ "query": "x", "group_by_session": 1 }),
        ] {
            let v = call(&mut server, "search_sessions", arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{arguments}"
            );
        }
        let v = call(
            &mut server,
            "search_sessions",
            json!({
                "query": "hello",
                "include_system": true,
                "group_by_session": true,
                "limit": 5
            }),
        );
        assert_eq!(v["result"]["isError"], false);
        let hits = v["result"]["structuredContent"]["data"]["hits"]
            .as_array()
            .expect("hits");
        // seeded store 两条命中均无 placement → 归并退化为逐条单例组（各 1 次）。
        assert_eq!(hits.len(), 2);
        // 归并模式下 occurrences==1 仍省略（与默认值省略约定一致）。
        assert!(hits[0].get("occurrences").is_none(), "{hits:?}");
        assert!(hits[1].get("occurrences").is_none(), "{hits:?}");
    }

    #[test]
    fn search_echoes_non_default_facets_like_the_cli_robot_surface() {
        // CLI（Robot）search 在非默认 facet 时回显 data.facets；MCP 必须一致
        // （audit P1-5）。默认 facet 请求不出现 facets 键，保持输出字节兼容。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "search_sessions",
            json!({ "query": "hello", "tool_kind": "file", "tool_name": "Bash" }),
        );
        assert_eq!(v["result"]["isError"], false);
        let facets = &v["result"]["structuredContent"]["data"]["facets"];
        assert_eq!(facets["sidechain"], "include", "{facets}");
        assert_eq!(facets["tool_kind"], "file", "{facets}");
        assert_eq!(facets["tool_name"], "Bash", "{facets}");

        let v = call(&mut server, "search_sessions", json!({ "query": "hello" }));
        assert!(
            v["result"]["structuredContent"]["data"]
                .get("facets")
                .is_none(),
            "default facets must not echo"
        );
    }

    #[test]
    fn unknown_extra_property_is_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "search_sessions",
            json!({ "query": "x", "surprise": true }),
        );
        assert_eq!(v["error"]["code"], -32602);
    }

    #[test]
    fn list_sessions_rejects_zero_limit_and_max_items_at_protocol_layer() {
        // 分层一致性（Minor-7）：与 search_sessions 一样，list_sessions 的
        // limit:0 / max_items:0 在协议层拒（-32602），不落成 App 层 isError 业务帧。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        for arguments in [json!({ "limit": 0 }), json!({ "max_items": 0 })] {
            let v = call(&mut server, "list_sessions", arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{arguments}"
            );
            assert!(v["result"].is_null(), "{arguments}");
        }
        // 合法下限（1）不受影响：仍走正常业务帧。
        let v = call(&mut server, "list_sessions", json!({ "limit": 1 }));
        assert_eq!(v["result"]["isError"], false);
    }

    #[test]
    fn budget_floors_are_protocol_errors_before_app_request() {
        // R4：max_bytes < 4096、max_messages < 1、max_items < 1、limit < 1 都在
        // 协议层 -32602（构造 AppRequest 之前），不落成 App 层 isError 业务帧。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        let cases = [
            (
                "search_sessions",
                json!({ "query": "hello", "max_bytes": 4095 }),
            ),
            (
                "search_sessions",
                json!({ "query": "hello", "max_items": 0 }),
            ),
            ("search_sessions", json!({ "query": "hello", "limit": 0 })),
            (
                "get_session_context",
                json!({ "session_id": "ses_v1_aaaa", "max_bytes": 4095 }),
            ),
            (
                "get_session_context",
                json!({ "session_id": "ses_v1_aaaa", "max_messages": 0 }),
            ),
            (
                "get_message",
                json!({ "message_id": "msg_v1_aaaa", "max_bytes": 4095 }),
            ),
            (
                "get_message",
                json!({ "message_id": "msg_v1_aaaa", "max_items": 0 }),
            ),
            ("list_sessions", json!({ "max_bytes": 4095 })),
            ("list_sessions", json!({ "max_items": 0 })),
            ("list_sessions", json!({ "limit": 0 })),
        ];
        for (tool, arguments) in cases {
            let v = call(&mut server, tool, arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{tool} {arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{tool} {arguments}"
            );
            assert!(v["result"].is_null(), "{tool} {arguments}");
        }
        // 精确下限（4096/1）放行到 App 层：合法业务请求。
        let v = call(
            &mut server,
            "search_sessions",
            json!({ "query": "hello", "max_bytes": 4096 }),
        );
        assert_eq!(v["result"]["isError"], false, "{v}");
        let v = call(
            &mut server,
            "get_session_context",
            json!({ "session_id": "ses_v1_aaaa", "max_messages": 1 }),
        );
        assert_eq!(
            v["result"]["structuredContent"]["error"]["canonical_code"], "not_found",
            "{v}"
        );
    }

    #[test]
    fn error_messages_truncate_echoed_values() {
        // R5：method/tool/id/参数值回显进错误消息前截断到 ECHO_CAP 字符。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let long = "x".repeat(500);
        // 未知方法：method 值回显截断。
        let v = respond(&mut server, &request(1, &long, json!({})));
        assert_eq!(v["error"]["code"], -32601);
        let message = v["error"]["message"].as_str().expect("message");
        assert!(message.starts_with("method not found: "), "{message}");
        assert!(
            message.len() <= "method not found: ".len() + ECHO_CAP + 3,
            "{message}"
        );
        assert!(message.ends_with("..."), "{message}");
        // 未知工具：tool 值回显截断。
        let v = call(&mut server, &long, json!({}));
        assert_eq!(v["error"]["code"], -32602);
        let message = v["error"]["message"].as_str().expect("message");
        assert!(
            message.len() <= "unknown tool: ".len() + ECHO_CAP + 3,
            "{message}"
        );
        assert!(message.ends_with("..."), "{message}");
        // 未知参数键回显截断。
        let mut args = Map::new();
        args.insert("query".to_string(), json!("x"));
        args.insert(long.clone(), json!(true));
        let v = call(&mut server, "search_sessions", Value::Object(args));
        assert_eq!(v["error"]["code"], -32602);
        let message = v["error"]["message"].as_str().expect("message");
        assert!(
            message.len() <= "unknown parameter: ".len() + ECHO_CAP + 3,
            "{message}"
        );
        assert!(message.ends_with("..."), "{message}");
        // enum 参数值与 wire id 回显截断。
        let v = call(
            &mut server,
            "get_session_context",
            json!({ "session_id": "ses_v1_aaaa", "policy": long.as_str() }),
        );
        assert_eq!(v["error"]["code"], -32602);
        let message = v["error"]["message"].as_str().expect("message");
        assert!(
            message.len() <= "policy must be mainline|full, got ".len() + ECHO_CAP + 3,
            "{message}"
        );
        assert!(message.ends_with("..."), "{message}");
        let wire = format!("ses_v1_{long}");
        let v = call(
            &mut server,
            "get_session_context",
            json!({ "session_id": wire }),
        );
        assert_eq!(v["error"]["code"], -32602);
        let message = v["error"]["message"].as_str().expect("message");
        assert!(message.contains("maximum length of 128"), "{message}");
    }

    #[test]
    fn tool_schemas_bound_unbounded_strings_and_arrays() {
        // R5：无界 string 参数加 maxLength、无界 array 参数加 maxItems。
        let tools = tool_catalog().as_array().expect("tools").clone();
        let tool = |name: &str| -> Value {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("missing tool {name}"))
                .clone()
        };
        let search = tool("search_sessions");
        let properties = &search["inputSchema"]["properties"];
        assert_eq!(properties["query"]["maxLength"], 4096);
        assert_eq!(properties["cursor"]["maxLength"], 512);
        assert_eq!(properties["since"]["maxLength"], 64);
        assert_eq!(properties["until"]["maxLength"], 64);
        assert_eq!(properties["providers"]["maxItems"], 2);
        let context = tool("get_session_context");
        assert_eq!(
            context["inputSchema"]["properties"]["session_id"]["maxLength"],
            128
        );
        let resume = tool("get_session_resume");
        assert_eq!(
            resume["inputSchema"]["properties"]["session_id"]["maxLength"],
            128
        );
        let message = tool("get_message");
        assert_eq!(
            message["inputSchema"]["properties"]["message_id"]["maxLength"],
            128
        );
        assert_eq!(
            message["inputSchema"]["properties"]["session_id"]["maxLength"],
            128
        );
        let list = tool("list_sessions");
        assert_eq!(
            list["inputSchema"]["properties"]["cursor"]["maxLength"],
            512
        );
    }

    #[test]
    fn tool_schema_floors_match_runtime_budget_validation() {
        // 发布 schema 的下限必须与 ResponseBudget::validate 的运行时下限一致
        // （1 / 4096），不允许声明 0 又让运行时拒绝（Minor-6）。
        let tools = tool_catalog().as_array().expect("tools").clone();
        let floors: [(&str, &str, u64); 5] = [
            ("search_sessions", "limit", 1),
            ("search_sessions", "max_items", 1),
            ("search_sessions", "max_bytes", 4096),
            ("list_sessions", "limit", 1),
            ("list_sessions", "max_items", 1),
        ];
        for (tool_name, param, floor) in floors {
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == tool_name)
                .unwrap_or_else(|| panic!("missing tool {tool_name}"));
            assert_eq!(
                tool["inputSchema"]["properties"][param]["minimum"], floor,
                "{tool_name}.{param} 下限必须与运行时一致"
            );
        }
        let context = tools
            .iter()
            .find(|tool| tool["name"] == "get_session_context")
            .expect("get_session_context");
        assert_eq!(
            context["inputSchema"]["properties"]["max_messages"]["minimum"], 1,
            "get_session_context.max_messages 下限必须与运行时一致"
        );
        assert_eq!(
            context["inputSchema"]["properties"]["max_bytes"]["minimum"], 4096,
            "get_session_context.max_bytes 下限必须与运行时一致"
        );
        let message = tools
            .iter()
            .find(|tool| tool["name"] == "get_message")
            .expect("get_message");
        assert_eq!(
            message["inputSchema"]["properties"]["around"]["minimum"], 0,
            "get_message.around 下限必须与运行时一致"
        );
        assert_eq!(
            message["inputSchema"]["properties"]["max_items"]["minimum"], 1,
            "get_message.max_items 下限必须与运行时一致"
        );
        assert_eq!(
            message["inputSchema"]["properties"]["max_bytes"]["minimum"], 4096,
            "get_message.max_bytes 下限必须与运行时一致"
        );
    }

    #[test]
    fn non_object_params_or_arguments_are_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = respond(&mut server, &request(8, "tools/call", json!(null)));
        assert_eq!(v["error"]["code"], -32602);
        let v = respond(
            &mut server,
            &request(
                9,
                "tools/call",
                json!({ "name": "get_status", "arguments": 5 }),
            ),
        );
        assert_eq!(v["error"]["code"], -32602);
    }

    #[test]
    fn invalid_session_wire_id_is_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "get_session_context",
            json!({ "session_id": "not-a-wire-id" }),
        );
        assert_eq!(v["error"]["code"], -32602);
        assert_eq!(v["error"]["data"]["canonical_code"], "invalid_request");
    }

    #[test]
    fn get_message_wire_id_errors_are_invalid_params() {
        // 与 get_session_context 同层：缺失/非法 wire id 与 max_items:0 都是
        // 请求校验失败（-32602），不得落成 App 层 isError 业务帧（design §2 note）。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for arguments in [
            json!({}),
            json!({ "message_id": "not-a-wire-id" }),
            json!({ "message_id": "msg_v1_aaaa", "session_id": "junk" }),
            json!({ "message_id": "msg_v1_aaaa", "max_items": 0 }),
            // kind 错配也是请求校验：session/document id 不能冒充 message_id，
            // message id 也不能冒充 session_id（协议层校验，不落 App 层）。
            json!({ "message_id": "ses_v1_aaaa" }),
            json!({ "message_id": "msg_v1_aaaa", "session_id": "doc_v1_aaaa" }),
        ] {
            let v = call(&mut server, "get_message", arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{arguments}"
            );
            assert!(v["result"].is_null(), "{arguments}");
        }
    }

    #[test]
    fn get_session_context_rejects_wrong_kind_session_id() {
        // session_id 必须是 Session 实体；message/document id 属于协议层请求
        // 校验失败，而非 App 层 not_found。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        for arguments in [
            json!({ "session_id": "msg_v1_aaaa" }),
            json!({ "session_id": "doc_v1_aaaa" }),
        ] {
            let v = call(&mut server, "get_session_context", arguments.clone());
            assert_eq!(v["error"]["code"], -32602, "{arguments}");
            assert_eq!(
                v["error"]["data"]["canonical_code"], "invalid_request",
                "{arguments}"
            );
            assert!(v["result"].is_null(), "{arguments}");
        }
    }

    #[test]
    fn get_message_unknown_message_is_business_not_found() {
        // 格式合法但库中不存在的 message_id 走 Application 的 not_found 业务
        // 路径（isError 工具结果），而非协议层 -32602（design §2 note）。
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "get_message",
            json!({ "message_id": "msg_v1_aaaa" }),
        );
        assert_eq!(v["result"]["isError"], true);
        assert_eq!(
            v["result"]["structuredContent"]["error"]["canonical_code"],
            "not_found"
        );
    }

    #[test]
    fn out_of_enum_policy_is_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "get_session_context",
            json!({ "session_id": "ses_v1_nope", "policy": "weird" }),
        );
        assert_eq!(v["error"]["code"], -32602);
    }

    #[test]
    fn out_of_enum_level_is_invalid_params() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "get_session_context",
            json!({ "session_id": "ses_v1_nope", "level": "everything" }),
        );
        assert_eq!(v["error"]["code"], -32602);
        assert_eq!(v["error"]["data"]["canonical_code"], "invalid_request");
    }

    #[test]
    fn get_session_context_schema_declares_level_enum() {
        let catalog = tool_catalog();
        let context_tool = catalog
            .as_array()
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|tool| tool["name"] == "get_session_context")
            })
            .expect("get_session_context tool must exist");
        let level = &context_tool["inputSchema"]["properties"]["level"];
        assert_eq!(
            level["enum"],
            json!(["raw", "talks", "sessions"]),
            "schema must declare the level enum"
        );
    }

    #[test]
    fn garbage_cursor_is_a_business_error_with_cursor_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "search_sessions",
            json!({ "query": "hello", "cursor": "garbage" }),
        );
        let result = &v["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"]["error"]["canonical_code"],
            "cursor_invalid"
        );
        assert_eq!(result["structuredContent"]["error"]["retryable"], false);
        assert!(result["content"][0]["text"].as_str().is_some());
    }

    #[test]
    fn unknown_session_with_valid_wire_id_is_business_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(
            &mut server,
            "get_session_context",
            json!({ "session_id": "ses_v1_nope" }),
        );
        assert_eq!(v["result"]["isError"], true);
        assert_eq!(
            v["result"]["structuredContent"]["error"]["canonical_code"],
            "not_found"
        );
    }

    #[test]
    fn search_round_trip_projects_the_shared_render_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        let v = call(&mut server, "search_sessions", json!({ "query": "world" }));
        let result = &v["result"];
        assert_eq!(result["isError"], false);
        let payload = &result["structuredContent"];
        assert_eq!(payload["outcome"], "success");
        let hits = payload["data"]["hits"].as_array().expect("hits");
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0]["id"]
                .as_str()
                .expect("hit id")
                .starts_with("msg_v1_")
        );
        // R4（ADR-0008）：MCP search_sessions 命中与 CLI 共用同一 render 投影，
        // 携带追加的 session_id/text。seeded store 无 placement、payload 非 JSON，
        // 二者恒为 null（不臆造会话/摘要）——追加字段、无字段删除。
        assert!(hits[0]["session_id"].is_null(), "{payload}");
        assert!(hits[0]["text"].is_null(), "{payload}");
        assert!(hits[0]["score"].is_number(), "{payload}");
        // Search guidance is assembled and byte-clamped by Application, then
        // carried through this same render projection. A catalog-only fixture
        // has no text/session evidence, so guidance must remain absent.
        assert!(hits[0].get("why_matched").is_none(), "{payload}");
        assert!(
            hits[0].get("suggested_next_commands").is_none(),
            "{payload}"
        );
        assert_eq!(payload["page"]["next_cursor"], Value::Null);
        assert_eq!(payload["page"]["has_more"], false);
        // content.text 与 structuredContent 必须是同一 payload 的两种载体。
        assert_eq!(result["content"][0]["type"], "text");
        let text = result["content"][0]["text"].as_str().expect("text content");
        assert_eq!(parse(text), *payload);
    }

    #[test]
    fn search_paginates_with_cursor_across_disjoint_pages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        let first = call(
            &mut server,
            "search_sessions",
            json!({ "query": "hello", "max_items": 1 }),
        );
        let first_payload = &first["result"]["structuredContent"];
        let first_hits = first_payload["data"]["hits"].as_array().expect("hits");
        assert_eq!(first_hits.len(), 1);
        assert_eq!(first_payload["page"]["has_more"], true);
        let cursor = first_payload["page"]["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string();

        let second = call(
            &mut server,
            "search_sessions",
            json!({ "query": "hello", "max_items": 1, "cursor": cursor }),
        );
        let second_payload = &second["result"]["structuredContent"];
        let second_hits = second_payload["data"]["hits"].as_array().expect("hits");
        assert_eq!(second_hits.len(), 1);
        assert_ne!(
            first_hits[0]["id"], second_hits[0]["id"],
            "pages must be disjoint"
        );
    }

    #[test]
    fn get_status_reports_real_catalog_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_store(&dir);
        let mut server = ready(&store);
        let v = call(&mut server, "get_status", json!({}));
        let payload = &v["result"]["structuredContent"];
        assert_eq!(payload["outcome"], "success");
        assert_eq!(payload["data"]["catalog_count"], 2);
        assert!(payload["data"]["generation"].is_number());
    }

    #[test]
    fn doctor_reports_db_ok_with_store_facts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(&mut server, "doctor", json!({}));
        let data = &v["result"]["structuredContent"]["data"];
        assert_eq!(data["tool"], env!("CARGO_PKG_NAME"));
        assert_eq!(data["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(data["db"], "ok");
        assert!(data["schema"].is_number());
        assert!(data["generation"].is_number());
        assert_eq!(data["interrupted_batches"], 0);
        assert_eq!(data["orphaned_tool_activities"], 0);
        assert_eq!(data["orphaned_activity_memberships"], 0);
    }

    #[test]
    fn list_providers_enumerates_the_registry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_store(&dir);
        let mut server = ready(&store);
        let v = call(&mut server, "list_providers", json!({}));
        let payload = &v["result"]["structuredContent"];
        assert_eq!(payload["outcome"], "success");
        assert_eq!(payload["page"]["next_cursor"], Value::Null);
        let providers = payload["data"]["providers"].as_array().expect("providers");
        // 16 行全量矩阵投影：14 个 ingestible + 2 个 deferred（ingestible=false）。
        assert_eq!(providers.len(), 16, "{providers:?}");
        let ids: Vec<&str> = providers
            .iter()
            .map(|provider| provider["id"].as_str().expect("provider id"))
            .collect();
        assert!(ids.contains(&"claude-code"), "{ids:?}");
        assert!(ids.contains(&"codex"), "{ids:?}");
        for provider in providers {
            let id = provider["id"].as_str().expect("provider id");
            let expected = ProviderCapabilityMatrix::current()
                .find(id)
                .unwrap_or_else(|| panic!("missing capability matrix row for {id}"))
                .maturity;
            assert_eq!(
                provider["maturity"],
                serde_json::to_value(expected).expect("serialize maturity"),
                "{provider}"
            );
            if provider["ingestible"] == true {
                assert!(
                    provider_registry()
                        .iter()
                        .any(|adapter| adapter.provider_id() == id),
                    "{id} marked ingestible but not registered"
                );
            }
        }
        let deferred: Vec<&Value> = providers
            .iter()
            .filter(|provider| provider["ingestible"] == false)
            .collect();
        assert_eq!(deferred.len(), 2, "{deferred:?}");
        assert!(
            deferred
                .iter()
                .all(|provider| provider["maturity"] == "unsupported")
        );
    }
}
