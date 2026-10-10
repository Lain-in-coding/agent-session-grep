//! MCP stdio e2e：驱动真实二进制的 `mcp` 子命令，覆盖 design §4 的 9 个必测场景
//! （initialize 协商 → tools/list → tools/call 往返、错误分层、initialize gate）。
//!
//! stdout 纯净性断言固化在会话 helper 里：MCP 模式下 stdout 只允许合法 JSON-RPC
//! frame（contract §6/§8），任何解析失败的行当场 panic。响应按 JSON-RPC id 匹配，
//! 不按行位置——通知不产生响应帧。

use rusqlite::Connection;
use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// 刚构建出的 `agent-session-grep` 二进制的绝对路径（由 Cargo 在编译期注入）。
const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");

/// 每个测试用独立临时目录，避免 WAL/SHM 旁文件互相干扰。
fn temp_db(tag: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{tag}.db"));
    // The MCP server opens an existing catalog read-only. Fixture creation is
    // an explicit writer operation, not a side effect of protocol startup.
    drop(
        agent_session_grep_adapters_sqlite::SqliteStore::open_for_write(&path.to_string_lossy())
            .expect("initialize MCP catalog fixture"),
    );
    (dir, path)
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn session_wire_for_message(db: &Path, message_wire: &str) -> String {
    Connection::open(db)
        .expect("open catalog")
        .query_row(
            "SELECT session_id
             FROM message_placements
             WHERE message_id = ?1
             ORDER BY session_id
             LIMIT 1",
            [message_wire],
            |row| row.get(0),
        )
        .expect("message must have a canonical Session placement")
}

/// 固定应用时钟（`ASG_CLOCK_MS`，2026-08-25T00:00:00Z 的 Unix 毫秒）：
/// 与 e2e.rs 同值——rank signals 时效衰减随注入时钟确定，MCP 会话同样
/// 注入该值保持排序/得分确定性。
const E2E_CLOCK_MS: &str = "1787616000000";

/// 以 robot 模式跑一次 CLI：仅用于测试前置的数据准备（ingest 夹具），不涉 MCP。
fn run_cli(db: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--db")
        .arg(db)
        .arg("--robot")
        .args(args)
        .env("ASG_CLOCK_MS", E2E_CLOCK_MS)
        .output()
        .expect("failed to spawn agent-session-grep binary")
}

/// 跑一个完整 MCP stdio 会话：逐行写入 → 关 stdin（EOF）→ 收全 stdout。
///
/// 两条契约在此执行：EOF 后服务器必须干净停机 exit 0（design §0.8）；
/// stdout 每一行都必须是完整 JSON frame，解析失败当场 panic（诊断只准走 stderr）。
fn mcp_session_raw(db: &Path, lines: &[&str]) -> Vec<Value> {
    mcp_session_raw_stderr(db, lines).0
}

/// 同 [`mcp_session_raw`]，额外返回 stderr 全文（隐私回归守卫用）。
fn mcp_session_raw_stderr(db: &Path, lines: &[&str]) -> (Vec<Value>, String) {
    let mut child = Command::new(BIN)
        .arg("--db")
        .arg(db)
        .arg("mcp")
        .env("ASG_CLOCK_MS", E2E_CLOCK_MS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn agent-session-grep mcp");
    {
        let mut stdin = child.stdin.take().expect("child stdin must be piped");
        for line in lines {
            stdin.write_all(line.as_bytes()).expect("write stdin line");
            stdin.write_all(b"\n").expect("write stdin newline");
        }
        // 作用域结束丢弃 stdin → EOF，服务器应据此优雅停机。
    }
    let out = child.wait_with_output().expect("wait for mcp server");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "mcp server must exit 0 on EOF, got {:?}\nstderr: {stderr}",
        out.status.code()
    );
    let text = stdout(&out);
    let frames = text
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("stdout not pure JSON-RPC: {error}\nline: {line}\nstderr: {stderr}")
            })
        })
        .collect();
    (frames, stderr)
}

/// design §4 冻结的 helper：以 JSON Value 逐条喂入一个 MCP 会话。
fn mcp_session(db: &Path, inputs: &[Value]) -> Vec<Value> {
    let lines: Vec<String> = inputs.iter().map(|input| input.to_string()).collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    mcp_session_raw(db, &refs)
}

/// 原始字节版会话：整段 stdin 由调用方给出（含非 UTF-8 字节），退出码原样返回。
///
/// 与 [`mcp_session_raw_stderr`] 不同，本 helper 不断言 exit 0——退出语义本身
/// 就是被测对象。stdout 纯净性仍然强制：每一行必须是完整 JSON frame。
fn mcp_session_bytes(db: &Path, payload: &[u8]) -> (Vec<Value>, String, Option<i32>) {
    let mut child = Command::new(BIN)
        .arg("--db")
        .arg(db)
        .arg("mcp")
        .env("ASG_CLOCK_MS", E2E_CLOCK_MS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn agent-session-grep mcp");
    {
        let mut stdin = child.stdin.take().expect("child stdin must be piped");
        stdin.write_all(payload).expect("write stdin bytes");
    }
    let out = child.wait_with_output().expect("wait for mcp server");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let frames = stdout(&out)
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("stdout not pure JSON-RPC: {error}\nline: {line}\nstderr: {stderr}")
            })
        })
        .collect();
    (frames, stderr, out.status.code())
}

/// 按 JSON-RPC id 取响应帧：通知没有响应，按位置对齐不可靠。
fn frame_by_id(frames: &[Value], id: i64) -> &Value {
    frames
        .iter()
        .find(|frame| frame["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response frame with id {id}, got: {frames:?}"))
}

/// initialize 请求（协商目标版本由用例指定）。
fn initialize_request(id: i64, version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "0" }
        }
    })
}

/// initialized 通知：发出后 initialize gate 才放行其余请求（design §0.7）。
fn initialized_notification() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

fn tool_call(id: i64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

/// 写入 context 用的真实 Claude 格式夹具（合成数据，与 e2e.rs 同形状）：
/// root → reply → { sidechain probe, mainline tail }，全部消息含检索词 "ctx"。
/// 返回 (夹具路径, 锚点消息 wire id)。
fn write_context_fixture(dir: &Path) -> (String, String) {
    let lines = concat!(
        r#"{"type":"user","uuid":"c0000000-0000-4000-8000-000000000001","parentUuid":null,"sessionId":"ccdd1234-5678-4abc-8def-001122334455","timestamp":"2026-07-26T01:00:00.000Z","message":{"role":"user","content":"ctx root question"}}"#,
        "\n",
        r#"{"type":"assistant","uuid":"c0000000-0000-4000-8000-000000000002","parentUuid":"c0000000-0000-4000-8000-000000000001","sessionId":"ccdd1234-5678-4abc-8def-001122334455","message":{"role":"assistant","content":"ctx first answer"}}"#,
        "\n",
        r#"{"type":"user","uuid":"c0000000-0000-4000-8000-000000000003","parentUuid":"c0000000-0000-4000-8000-000000000002","isSidechain":true,"sessionId":"ccdd1234-5678-4abc-8def-001122334455","message":{"role":"user","content":"ctx sidechain probe"}}"#,
        "\n",
        r#"{"type":"assistant","uuid":"c0000000-0000-4000-8000-000000000004","parentUuid":"c0000000-0000-4000-8000-000000000002","sessionId":"ccdd1234-5678-4abc-8def-001122334455","message":{"role":"assistant","content":"ctx final answer"}}"#,
        "\n",
    );
    let fixture = dir.join("context.jsonl");
    std::fs::write(&fixture, lines).expect("write context fixture");
    (
        fixture.to_string_lossy().into_owned(),
        "msg_v1_c0000000-0000-4000-8000-000000000001".to_string(),
    )
}

struct RelationalContextFixture {
    paths: [String; 3],
    contents: [String; 3],
    session_a: String,
    session_b: String,
    parent_a: String,
    parent_b: String,
    shared_message: String,
}

fn write_relational_context_fixture(dir: &Path) -> RelationalContextFixture {
    let session_a_native = "da111111-1111-4111-8111-111111111111";
    let session_b_native = "db222222-2222-4222-8222-222222222222";
    let parent_a_native = "da333333-3333-4333-8333-333333333333";
    let parent_b_native = "db444444-4444-4444-8444-444444444444";
    let shared_native = "dc555555-5555-4555-8555-555555555555";
    let head_a = format!(
        "{{\"type\":\"user\",\"uuid\":\"{parent_a_native}\",\"parentUuid\":null,\
         \"sessionId\":\"{session_a_native}\",\"timestamp\":\"2026-07-28T02:00:00.000Z\",\
         \"message\":{{\"role\":\"user\",\"content\":\"mcp relational parent A\"}}}}\n"
    );
    let tail_a = format!(
        "{{\"type\":\"assistant\",\"uuid\":\"{shared_native}\",\
         \"parentUuid\":\"{parent_a_native}\",\"sessionId\":\"{session_a_native}\",\
         \"timestamp\":\"2026-07-28T02:00:01.000Z\",\
         \"message\":{{\"role\":\"assistant\",\"content\":\"mcp relational shared\"}}}}\n"
    );
    let source_b = format!(
        "{{\"type\":\"user\",\"uuid\":\"{parent_b_native}\",\"parentUuid\":null,\
         \"sessionId\":\"{session_b_native}\",\"timestamp\":\"2026-07-28T02:00:00.000Z\",\
         \"message\":{{\"role\":\"user\",\"content\":\"mcp relational parent B\"}}}}\n\
         {{\"type\":\"assistant\",\"uuid\":\"{shared_native}\",\
         \"parentUuid\":\"{parent_b_native}\",\"sessionId\":\"{session_b_native}\",\
         \"timestamp\":\"2026-07-28T02:00:01.000Z\",\
         \"message\":{{\"role\":\"assistant\",\"content\":\"mcp relational shared\"}}}}\n"
    );
    let files = [
        ("mcp-relational-a-head.jsonl", head_a.clone()),
        ("mcp-relational-a-tail.jsonl", tail_a.clone()),
        ("mcp-relational-b.jsonl", source_b.clone()),
    ];
    let mut paths = Vec::new();
    for (name, content) in &files {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write MCP relational fixture");
        paths.push(path.to_string_lossy().into_owned());
    }
    RelationalContextFixture {
        paths: paths.try_into().expect("three MCP fixture paths"),
        contents: [head_a, tail_a, source_b],
        session_a: format!("msg_v1_{parent_a_native}"),
        session_b: format!("msg_v1_{parent_b_native}"),
        parent_a: format!("msg_v1_{parent_a_native}"),
        parent_b: format!("msg_v1_{parent_b_native}"),
        shared_message: format!("msg_v1_{shared_native}"),
    }
}

// ─── design §4 场景 1：initialize 握手与版本协商 ────────────────────────────

#[test]
fn initialize_negotiates_versions_honestly_and_ping_answers() {
    let (_dir, db) = temp_db("mcp-init");
    // 客户端请求受支持的旧版本 → 原样回显（version negotiation 不撒谎）。
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2024-11-05"),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }),
        ],
    );
    assert_eq!(frames.len(), 2, "initialize + ping 各一帧: {frames:?}");
    let init = frame_by_id(&frames, 1);
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(init["result"]["serverInfo"]["name"], "agent-session-grep");
    assert!(
        init["result"]["serverInfo"]["version"]
            .as_str()
            .is_some_and(|version| !version.is_empty()),
        "serverInfo.version 必须存在: {init}"
    );
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "capabilities 必须声明 tools: {init}"
    );
    // ping 在任何阶段都可答，result 为空对象。
    assert_eq!(frame_by_id(&frames, 2)["result"], json!({}));

    // 不支持的版本 → 回落到我们钉住的最新版，绝不假装支持对方版本。
    let (_dir2, db2) = temp_db("mcp-init-unsupported");
    let frames = mcp_session(&db2, &[initialize_request(1, "9999-01-01")]);
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(
        frame_by_id(&frames, 1)["result"]["protocolVersion"],
        "2025-06-18"
    );
}

// ─── design §4 场景 2：tools/list 固定工具集 ────────────────────────────────

#[test]
fn tools_list_exposes_exactly_nine_contract_tools() {
    let (_dir, db) = temp_db("mcp-tools");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        ],
    );
    assert_eq!(frames.len(), 2, "{frames:?}");
    let tools = frame_by_id(&frames, 2)["result"]["tools"]
        .as_array()
        .expect("result.tools must be an array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool.name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "search_sessions",
            "get_session_context",
            "get_session_resume",
            "get_message",
            "list_sessions",
            "generate_handoff",
            "list_providers",
            "get_status",
            "doctor",
        ],
        "contract §8 固定的工具集与顺序"
    );
    for tool in tools {
        assert!(
            tool["inputSchema"].is_object(),
            "每个工具必须发布 inputSchema: {tool}"
        );
        assert!(
            tool["description"].as_str().is_some_and(|d| !d.is_empty()),
            "每个工具必须自带描述: {tool}"
        );
    }
}

// ─── design §4 场景 3：search_sessions 分页（复用 ADT cursor）───────────────

#[test]
fn search_sessions_cursor_pages_are_disjoint() {
    let (dir, db) = temp_db("mcp-search");
    let (fixture_path, _anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    // 第一页：夹具 4 条消息全含 "ctx"，页大小 1 → 必发续读令牌。
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "ctx", "max_items": 1 }),
            ),
        ],
    );
    assert_eq!(frames.len(), 2, "{frames:?}");
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "search 应成功: {result}");
    let payload = &result["structuredContent"];
    assert_eq!(payload["outcome"], "success");
    let hits = payload["data"]["hits"].as_array().expect("data.hits");
    assert_eq!(hits.len(), 1, "页大小 1: {payload}");
    let first_id = hits[0]["id"].as_str().expect("hit.id").to_string();
    assert_eq!(payload["page"]["has_more"], true, "{payload}");
    let cursor = payload["page"]["next_cursor"]
        .as_str()
        .expect("第一页必须签发 next_cursor")
        .to_string();

    // 第二页：cursor 是无状态签名令牌，跨会话（新进程）依然有效；页间不重叠
    // （复用 ADT 分页的钉住排序，MCP 层不得另造分页规则）。
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "ctx", "max_items": 1, "cursor": cursor.as_str() }),
            ),
        ],
    );
    assert_eq!(frames.len(), 2, "{frames:?}");
    let payload = &frame_by_id(&frames, 2)["result"]["structuredContent"];
    let hits = payload["data"]["hits"].as_array().expect("data.hits");
    assert_eq!(hits.len(), 1, "{payload}");
    let second_id = hits[0]["id"].as_str().expect("hit.id");
    assert_ne!(first_id, second_id, "分页必须不重不漏: {payload}");
}

// ─── design §4 场景 4：get_session_context 真实夹具往返 ─────────────────────

#[test]
fn get_session_context_returns_mainline_messages_and_evidence() {
    let (dir, db) = temp_db("mcp-context");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": session_wire.as_str() }),
            ),
        ],
    );
    assert_eq!(frames.len(), 2, "{frames:?}");
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "context 应成功: {result}");
    let payload = &result["structuredContent"];
    assert_eq!(payload["outcome"], "success");
    assert_eq!(payload["data"]["session_id"], session_wire.as_str());
    // 默认 mainline 策略：排除 sidechain → root/reply/tail 共 3 条。
    let messages = payload["data"]["messages"]
        .as_array()
        .expect("data.messages");
    assert_eq!(messages.len(), 3, "{payload}");
    // 证据数组与消息链对齐（byte 精度夹具 → 每条消息一个 span）。
    let evidence = payload["data"]["evidence"]
        .as_array()
        .expect("data.evidence");
    assert_eq!(evidence.len(), 3, "{payload}");
}

#[test]
fn get_session_context_keeps_shared_message_parent_and_evidence_per_session() {
    let (dir, db) = temp_db("mcp-relational-context");
    let fixture = write_relational_context_fixture(dir.path());
    let out = run_cli(
        &db,
        &[
            "sync",
            &fixture.paths[0],
            &fixture.paths[1],
            &fixture.paths[2],
        ],
    );
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let session_a_wire = session_wire_for_message(&db, &fixture.session_a);
    let session_b_wire = session_wire_for_message(&db, &fixture.session_b);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": session_a_wire.as_str() }),
            ),
            tool_call(
                3,
                "get_session_context",
                json!({ "session_id": session_b_wire.as_str() }),
            ),
        ],
    );
    assert_eq!(frames.len(), 3, "{frames:?}");

    let mut shared_placements = Vec::new();
    let mut shared_documents = Vec::new();
    let cases = [
        (2, fixture.parent_a.as_str(), 1usize),
        (3, fixture.parent_b.as_str(), 2usize),
    ];
    for (id, expected_parent, content_index) in cases {
        let result = &frame_by_id(&frames, id)["result"];
        assert_eq!(result["isError"], false, "{result}");
        let payload = &result["structuredContent"];
        let messages = payload["data"]["messages"]
            .as_array()
            .expect("context messages");
        assert_eq!(
            messages
                .iter()
                .map(|message| message["message_id"].as_str().expect("message id"))
                .collect::<Vec<_>>(),
            vec![expected_parent, fixture.shared_message.as_str()]
        );
        let evidence = payload["data"]["evidence"]
            .as_array()
            .expect("context evidence");
        assert_eq!(evidence[1]["occurrence_id"], messages[1]["placement_id"]);
        let start = evidence[1]["byte_start"].as_u64().expect("byte start") as usize;
        let end = evidence[1]["byte_end"].as_u64().expect("byte end") as usize;
        assert!(
            fixture.contents[content_index].as_bytes()[start..end]
                .starts_with(br#"{"type":"assistant""#)
        );
        shared_placements.push(
            messages[1]["placement_id"]
                .as_str()
                .expect("placement id")
                .to_string(),
        );
        shared_documents.push(
            evidence[1]["source_document_id"]
                .as_str()
                .expect("document id")
                .to_string(),
        );
    }
    assert_ne!(shared_placements[0], shared_placements[1]);
    assert_ne!(shared_documents[0], shared_documents[1]);
}

// ─── ADR-0009：get_session_resume 只读结构化恢复元数据 ───────────────────────

#[test]
fn get_session_resume_returns_structured_metadata_without_commands_or_paths() {
    let (dir, db) = temp_db("mcp-session-resume");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_resume",
                json!({ "session_id": session_wire.as_str() }),
            ),
        ],
    );
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "{result}");
    let payload = &result["structuredContent"];
    assert_eq!(payload["outcome"], "success", "{payload}");
    let data = &payload["data"];
    assert_eq!(data["session_id"], session_wire.as_str());
    assert_eq!(data["provider_id"], "claude-code", "{data}");
    assert_eq!(data["resume_available"], true, "{data}");
    assert_eq!(
        data["provider_session_id"], "ccdd1234-5678-4abc-8def-001122334455",
        "{data}"
    );
    assert!(data["original_working_directory"].is_null(), "{data}");
    assert!(data["unavailable_reason"].is_null(), "{data}");
    for forbidden in [
        "command",
        "resume_command",
        "source_path",
        "transcript_path",
    ] {
        assert!(
            data.get(forbidden).is_none(),
            "unexpected {forbidden}: {data}"
        );
    }

    let text_payload: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .expect("content[0].text"),
    )
    .expect("text carrier must contain the same JSON payload");
    assert_eq!(text_payload, *payload, "MCP dual carriers must agree");
}

#[test]
fn get_session_resume_wire_id_errors_are_protocol_layer() {
    let (_dir, db) = temp_db("mcp-session-resume-params");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "get_session_resume", json!({})),
            tool_call(
                3,
                "get_session_resume",
                json!({ "session_id": "not-a-wire-id" }),
            ),
            tool_call(
                4,
                "get_session_resume",
                json!({ "session_id": "msg_v1_c0000000-0000-4000-8000-000000000001" }),
            ),
            tool_call(
                5,
                "get_session_resume",
                json!({ "session_id": "doc_v1_c0000000-0000-4000-8000-000000000001" }),
            ),
            tool_call(
                6,
                "get_session_resume",
                json!({
                    "session_id": "ses_v1_ccdd1234-5678-4abc-8def-001122334455",
                    "extra": true,
                }),
            ),
        ],
    );
    for id in [2, 3, 4, 5, 6] {
        let frame = frame_by_id(&frames, id);
        assert!(frame["result"].is_null(), "{frame}");
        assert_eq!(frame["error"]["code"], -32602, "{frame}");
        assert_eq!(
            frame["error"]["data"]["canonical_code"], "invalid_request",
            "{frame}"
        );
    }
}

// ─── design §4 场景 4b：get_message 窗口与显式歧义 ───────────────────────────

#[test]
fn get_message_returns_anchor_and_mainline_window() {
    let (dir, db) = temp_db("mcp-message");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_message",
                json!({ "message_id": "msg_v1_c0000000-0000-4000-8000-000000000002" }),
            ),
        ],
    );
    assert_eq!(frames.len(), 2, "{frames:?}");
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "get_message 应成功: {result}");
    let payload = &result["structuredContent"];
    assert_eq!(payload["outcome"], "success");
    let data = &payload["data"];
    assert_eq!(
        data["message_id"],
        "msg_v1_c0000000-0000-4000-8000-000000000002"
    );
    assert_eq!(data["session_id"], session_wire.as_str());
    let messages = data["messages"].as_array().expect("data.messages");
    assert_eq!(messages.len(), 1, "around=0 只回锚点: {data}");
    assert_eq!(messages[0]["placement_id"], data["anchor_placement_id"]);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_message",
                json!({
                    "message_id": "msg_v1_c0000000-0000-4000-8000-000000000002",
                    "session_id": session_wire.as_str(),
                    "around": 1,
                }),
            ),
        ],
    );
    let data = &frame_by_id(&frames, 2)["result"]["structuredContent"]["data"];
    let ids: Vec<&str> = data["messages"]
        .as_array()
        .expect("data.messages")
        .iter()
        .map(|message| message["message_id"].as_str().expect("message_id"))
        .collect();
    assert_eq!(
        ids,
        vec![
            "msg_v1_c0000000-0000-4000-8000-000000000001",
            "msg_v1_c0000000-0000-4000-8000-000000000002",
            "msg_v1_c0000000-0000-4000-8000-000000000004",
        ],
        "sidechain probe 不得进入 mainline 窗口: {data}"
    );
}

#[test]
fn get_message_shared_message_is_explicit_ambiguity_then_resolvable() {
    let (dir, db) = temp_db("mcp-message-ambiguous");
    let fixture = write_relational_context_fixture(dir.path());
    let out = run_cli(
        &db,
        &[
            "sync",
            &fixture.paths[0],
            &fixture.paths[1],
            &fixture.paths[2],
        ],
    );
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let session_a_wire = session_wire_for_message(&db, &fixture.session_a);
    let session_b_wire = session_wire_for_message(&db, &fixture.session_b);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_message",
                json!({ "message_id": fixture.shared_message.as_str() }),
            ),
        ],
    );
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], true, "{result}");
    let error = &result["structuredContent"]["error"];
    assert_eq!(error["canonical_code"], "invalid_request", "{error}");
    let details = &error["details"];
    assert_eq!(details["candidate_count"], 2, "{details}");
    let mut candidate_ids: Vec<String> = details["candidate_session_ids"]
        .as_array()
        .expect("candidate_session_ids")
        .iter()
        .map(|candidate| candidate.as_str().expect("candidate id").to_string())
        .collect();
    candidate_ids.sort();
    let mut expected = vec![session_a_wire.clone(), session_b_wire.clone()];
    expected.sort();
    assert_eq!(candidate_ids, expected);
    assert!(
        details["hint"]
            .as_str()
            .is_some_and(|hint| !hint.is_empty())
    );

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_message",
                json!({
                    "message_id": fixture.shared_message.as_str(),
                    "session_id": session_b_wire.as_str(),
                    "around": 1,
                }),
            ),
            tool_call(
                3,
                "get_message",
                json!({
                    "message_id": fixture.shared_message.as_str(),
                    "session_id": "ses_v1_00000000-0000-4000-8000-000000000000",
                }),
            ),
        ],
    );
    let data = &frame_by_id(&frames, 2)["result"]["structuredContent"]["data"];
    assert_eq!(data["session_id"], session_b_wire.as_str());
    let ids: Vec<&str> = data["messages"]
        .as_array()
        .expect("data.messages")
        .iter()
        .map(|message| message["message_id"].as_str().expect("message_id"))
        .collect();
    assert_eq!(
        ids,
        vec![fixture.parent_b.as_str(), fixture.shared_message.as_str()]
    );
    let not_found = &frame_by_id(&frames, 3)["result"];
    assert_eq!(not_found["isError"], true, "{not_found}");
    assert_eq!(
        not_found["structuredContent"]["error"]["canonical_code"],
        "not_found"
    );
}

#[test]
fn get_message_wire_id_errors_are_protocol_layer() {
    let (_dir, db) = temp_db("mcp-message-params");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "get_message", json!({})),
            tool_call(3, "get_message", json!({ "message_id": "not-a-wire-id" })),
            tool_call(
                4,
                "get_message",
                json!({
                    "message_id": "msg_v1_c0000000-0000-4000-8000-000000000001",
                    "session_id": "junk",
                }),
            ),
            tool_call(
                5,
                "get_message",
                json!({
                    "message_id": "msg_v1_c0000000-0000-4000-8000-000000000001",
                    "max_items": 0,
                }),
            ),
        ],
    );
    for id in [2, 3, 4, 5] {
        let frame = frame_by_id(&frames, id);
        assert_eq!(frame["error"]["code"], -32602, "{frame}");
        assert_eq!(
            frame["error"]["data"]["canonical_code"], "invalid_request",
            "{frame}"
        );
    }
}

// ─── context level：raw 兼容 / talks 分组 / sessions 概览 / 单向 fallback ──

/// 写入 assistant-only 夹具：无用户消息，用于派生层级 fallback。
/// 返回 (夹具路径, 锚点消息 wire id)。
fn write_assistant_only_context_fixture(dir: &Path) -> (String, String) {
    let lines = concat!(
        r#"{"type":"assistant","uuid":"a0000000-0000-4000-8000-000000000001","parentUuid":null,"sessionId":"eeff1234-5678-4abc-8def-001122334455","timestamp":"2026-07-26T03:00:00.000Z","message":{"role":"assistant","content":"ctx assistant-only first"}}"#,
        "\n",
        r#"{"type":"assistant","uuid":"a0000000-0000-4000-8000-000000000002","parentUuid":"a0000000-0000-4000-8000-000000000001","sessionId":"eeff1234-5678-4abc-8def-001122334455","timestamp":"2026-07-26T03:00:01.000Z","message":{"role":"assistant","content":"ctx assistant-only second"}}"#,
        "\n",
    );
    let fixture = dir.join("assistant-only.jsonl");
    std::fs::write(&fixture, lines).expect("write assistant-only fixture");
    (
        fixture.to_string_lossy().into_owned(),
        "msg_v1_a0000000-0000-4000-8000-000000000001".to_string(),
    )
}

#[test]
fn get_session_context_without_level_stays_raw_compatible() {
    let (dir, db) = temp_db("mcp-context-default-level");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": session_wire.as_str() }),
            ),
            tool_call(
                3,
                "get_session_context",
                json!({ "session_id": session_wire.as_str(), "level": "raw" }),
            ),
        ],
    );
    let omitted = &frame_by_id(&frames, 2)["result"]["structuredContent"]["data"];
    let explicit = &frame_by_id(&frames, 3)["result"]["structuredContent"]["data"];
    assert_eq!(omitted, explicit, "omitted and explicit raw must match");
    assert_eq!(omitted["requested_level"], "raw", "{omitted}");
    assert_eq!(omitted["effective_level"], "raw", "{omitted}");
    assert_eq!(omitted["talks"], json!([]), "{omitted}");
    assert!(omitted["summary"].is_null(), "{omitted}");
    assert!(omitted["hint"].is_null(), "{omitted}");
    assert_eq!(omitted["messages"].as_array().expect("messages").len(), 3);
}

#[test]
fn get_session_context_talks_groups_user_with_following_messages() {
    let (dir, db) = temp_db("mcp-context-talks");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": session_wire.as_str(), "level": "talks" }),
            ),
        ],
    );
    let payload = &frame_by_id(&frames, 2)["result"]["structuredContent"]["data"];
    assert_eq!(payload["requested_level"], "talks", "{payload}");
    assert_eq!(payload["effective_level"], "talks", "{payload}");
    let talks = payload["talks"].as_array().expect("data.talks");
    assert_eq!(talks.len(), 1, "{payload}");
    assert!(
        talks[0]["user_message"]["payload"]["text"]
            .as_str()
            .is_some_and(|text| text.contains("ctx root question")),
        "{payload}"
    );
    assert_eq!(
        talks[0]["following_messages"]
            .as_array()
            .expect("following_messages")
            .len(),
        2
    );
    assert_eq!(payload["hint"]["command"], "get_session_context");
    assert_eq!(payload["hint"]["session_id"], session_wire.as_str());
    assert_eq!(payload["hint"]["level"], "raw");
}

#[test]
fn get_session_context_sessions_returns_structural_overview() {
    let (dir, db) = temp_db("mcp-context-sessions");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": session_wire.as_str(), "level": "sessions" }),
            ),
        ],
    );
    let payload = &frame_by_id(&frames, 2)["result"]["structuredContent"]["data"];
    assert_eq!(payload["requested_level"], "sessions", "{payload}");
    assert_eq!(payload["effective_level"], "sessions", "{payload}");
    let summary = &payload["summary"];
    assert!(summary.is_object(), "{payload}");
    assert_eq!(summary["message_count"], 3, "{payload}");
    assert_eq!(summary["turn_count"], 1, "{payload}");
    assert!(
        summary["first_user_message"]["payload"]["text"]
            .as_str()
            .is_some_and(|text| text.contains("ctx root question")),
        "{payload}"
    );
    assert_eq!(
        summary["file_references"]
            .as_array()
            .expect("file_references")
            .len(),
        1
    );
    assert_eq!(payload["talks"], json!([]), "{payload}");
    assert_eq!(payload["hint"]["level"], "talks", "{payload}");
}

#[test]
fn get_session_context_invalid_level_is_protocol_error() {
    let (_dir, db) = temp_db("mcp-context-bad-level");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": "ses_v1_any", "level": "everything" }),
            ),
        ],
    );
    let frame = frame_by_id(&frames, 2);
    assert!(frame["result"].is_null(), "{frame}");
    assert_eq!(frame["error"]["code"], -32602, "{frame}");
}

#[test]
fn get_session_context_empty_derived_levels_fall_back_toward_raw() {
    let (dir, db) = temp_db("mcp-context-fallback");
    let (fixture_path, anchor_message) = write_assistant_only_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": session_wire.as_str(), "level": "talks" }),
            ),
            tool_call(
                3,
                "get_session_context",
                json!({ "session_id": session_wire.as_str(), "level": "sessions" }),
            ),
        ],
    );
    for id in [2, 3] {
        let payload = &frame_by_id(&frames, id)["result"]["structuredContent"]["data"];
        assert_eq!(payload["effective_level"], "raw", "{payload}");
        assert_eq!(payload["talks"], json!([]), "{payload}");
        assert!(payload["summary"].is_null(), "{payload}");
        assert!(payload["hint"].is_null(), "{payload}");
        assert_eq!(payload["messages"].as_array().expect("messages").len(), 2);
    }
}

#[test]
fn get_session_context_derived_level_honors_small_byte_budget() {
    let (dir, db) = temp_db("mcp-context-level-budget");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({
                    "session_id": session_wire.as_str(),
                    "level": "talks",
                    "max_bytes": 4096,
                }),
            ),
        ],
    );
    let payload = &frame_by_id(&frames, 2)["result"]["structuredContent"];
    assert_eq!(payload["outcome"], "partial", "{payload}");
    assert_eq!(
        payload["data"]["truncation"]["reason"], "max_response_bytes",
        "{payload}"
    );
}

// ─── design §4 场景 5：坏 cursor 是业务错误（isError 结果帧）────────────────

#[test]
fn garbage_cursor_is_business_error_cursor_invalid() {
    let (_dir, db) = temp_db("mcp-bad-cursor");
    // 通过结构校验但业务层失败（App 拒绝 cursor）→ isError 结果帧，
    // 不是 JSON-RPC error（design §0.3 错误分层）。
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "x", "cursor": "garbage" }),
            ),
        ],
    );
    assert_eq!(frames.len(), 2, "{frames:?}");
    let frame = frame_by_id(&frames, 2);
    assert!(frame["error"].is_null(), "应为 result 帧: {frame}");
    let result = &frame["result"];
    assert_eq!(result["isError"], true, "{result}");
    let error = &result["structuredContent"]["error"];
    assert_eq!(error["canonical_code"], "cursor_invalid");
    assert_eq!(error["retryable"], false);
    assert!(
        result["content"][0]["text"]
            .as_str()
            .is_some_and(|text| !text.is_empty()),
        "content[0] 必须携带人读文本: {result}"
    );
}

// ─── design §4 场景 6：协议层错误的 JSON-RPC code 映射 ──────────────────────

#[test]
fn protocol_errors_map_to_json_rpc_codes() {
    // 未知工具 → -32602；未知方法 → -32601（同一已握手会话内验证）。
    let (_dir, db) = temp_db("mcp-protocol-errors");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(10, "does_not_exist", json!({})),
            json!({ "jsonrpc": "2.0", "id": 11, "method": "foo/bar" }),
        ],
    );
    assert_eq!(frames.len(), 3, "{frames:?}");
    let unknown_tool = frame_by_id(&frames, 10);
    assert!(unknown_tool["result"].is_null(), "{unknown_tool}");
    assert_eq!(unknown_tool["error"]["code"], -32602);
    assert_eq!(frame_by_id(&frames, 11)["error"]["code"], -32601);

    // 畸形 JSON 行 → -32700 且 id:null（parse error 无从关联请求 id）。
    let (_dir2, db2) = temp_db("mcp-malformed");
    let frames = mcp_session_raw(&db2, &["not json"]);
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["error"]["code"], -32700);
    assert!(frames[0]["id"].is_null(), "{:?}", frames[0]);

    // JSON-RPC batch 数组：2025-06-18 已移除 batching → 整体 -32600 拒绝。
    let (_dir3, db3) = temp_db("mcp-batch");
    let frames = mcp_session(
        &db3,
        &[json!([{ "jsonrpc": "2.0", "id": 1, "method": "ping" }])],
    );
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["error"]["code"], -32600);
}

// ─── design §4 场景 7：initialize gate ──────────────────────────────────────

#[test]
fn requests_before_initialized_are_rejected() {
    let (_dir, db) = temp_db("mcp-gate");
    // 首条消息即 tools/list（未 initialize）→ -32600 server not initialized。
    let frames = mcp_session(
        &db,
        &[json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })],
    );
    assert_eq!(frames.len(), 1, "{frames:?}");
    let frame = frame_by_id(&frames, 1);
    assert!(frame["result"].is_null(), "{frame}");
    assert_eq!(frame["error"]["code"], -32600);
}

// ─── JSON-RPC envelope hardening（08-14）：jsonrpc / id / initialize / params /
//     预算下限 / 有界错误 / schema 约束 ───────────────────────────────────────

#[test]
fn jsonrpc_envelope_and_id_are_strictly_validated() {
    let (_dir, db) = temp_db("mcp-envelope");
    let frames = mcp_session(
        &db,
        &[
            json!({ "id": 1, "method": "ping" }), // 缺 jsonrpc
            json!({ "jsonrpc": "1.0", "id": 2, "method": "ping" }), // 旧版本
            json!({ "jsonrpc": 2.0, "id": 2, "method": "ping" }), // 数字型版本
            json!({ "jsonrpc": "2.0", "id": [3], "method": "ping" }), // id 数组
            json!({ "jsonrpc": "2.0", "id": {}, "method": "ping" }), // id 对象
            json!({ "jsonrpc": "2.0", "id": 4.5, "method": "ping" }), // id 小数
            json!({ "jsonrpc": "2.0", "id": 1.0, "method": "ping" }), // id 浮点字面量
            json!({ "jsonrpc": "2.0", "id": "str-id", "method": "ping" }), // 字符串 id 合法
            json!({ "jsonrpc": "2.0", "id": null, "method": "ping" }), // null id 合法
        ],
    );
    assert_eq!(frames.len(), 9, "{frames:?}");
    for frame in &frames[..7] {
        assert_eq!(frame["error"]["code"], -32600, "{frame}");
        assert!(frame["id"].is_null(), "{frame}");
    }
    assert_eq!(frames[7]["id"], "str-id");
    assert_eq!(frames[7]["result"], json!({}));
    assert!(frames[8]["id"].is_null());
    assert_eq!(frames[8]["result"], json!({}));
}

#[test]
fn initialize_requires_complete_params_and_failed_handshake_stays_closed() {
    let (_dir, db) = temp_db("mcp-init-strict");
    let frames = mcp_session(
        &db,
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } }),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize" }),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }),
            initialize_request(4, "2025-06-18"),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }),
        ],
    );
    assert_eq!(frames.len(), 5, "{frames:?}");
    // 不完整 params（缺 capabilities/clientInfo）与缺失 params 都是失败握手。
    for id in [1, 2] {
        let frame = frame_by_id(&frames, id);
        assert_eq!(frame["error"]["code"], -32602, "{frame}");
    }
    // 失败握手后的 initialized 通知不得开门闩。
    assert_eq!(frame_by_id(&frames, 3)["error"]["code"], -32600);
    // 完整 params 才握手成功，随后 initialized 通知照常开门。
    assert!(frame_by_id(&frames, 4)["result"]["protocolVersion"].is_string());
    assert!(frame_by_id(&frames, 5)["result"]["tools"].is_array());
}

#[test]
fn ping_and_tools_list_reject_non_object_params() {
    let (_dir, db) = temp_db("mcp-params-shape");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "ping", "params": [1, 2] }),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": "x" }),
            json!({ "jsonrpc": "2.0", "id": 4, "method": "ping", "params": null }),
            json!({ "jsonrpc": "2.0", "id": 5, "method": "ping", "params": {} }),
        ],
    );
    for id in [2, 3, 4] {
        let frame = frame_by_id(&frames, id);
        assert_eq!(frame["error"]["code"], -32602, "{frame}");
        assert_eq!(frame["error"]["data"]["canonical_code"], "invalid_request");
    }
    assert_eq!(frame_by_id(&frames, 5)["result"], json!({}));
}

#[test]
fn malformed_initialized_notification_does_not_open_gate() {
    let (_dir, db) = temp_db("mcp-init-notification");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": [1] }),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
            json!({ "jsonrpc": "1.0", "method": "notifications/initialized" }),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }),
        ],
    );
    // 畸形 notification（params 数组 / 旧 jsonrpc）回错误帧（id null），且不得开门闩。
    assert_eq!(frames.len(), 5, "{frames:?}");
    for frame in [&frames[1], &frames[3]] {
        assert_eq!(frame["error"]["code"], -32600, "{frame}");
        assert!(frame["id"].is_null(), "{frame}");
    }
    assert_eq!(frame_by_id(&frames, 2)["error"]["code"], -32600);
    // 合法 notification 照常静默开门。
    assert!(frame_by_id(&frames, 3)["result"]["tools"].is_array());
}

#[test]
fn budget_floors_below_minimum_are_protocol_errors() {
    let (dir, db) = temp_db("mcp-budget-floors");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "ctx", "max_bytes": 4095 }),
            ),
            tool_call(3, "search_sessions", json!({ "query": "ctx", "limit": 0 })),
            tool_call(
                4,
                "get_session_context",
                json!({ "session_id": session_wire, "max_messages": 0 }),
            ),
            tool_call(
                5,
                "get_session_context",
                json!({ "session_id": session_wire, "max_bytes": 1 }),
            ),
            tool_call(
                6,
                "get_message",
                json!({ "message_id": "msg_v1_c0000000-0000-4000-8000-000000000002", "max_items": 0 }),
            ),
            tool_call(7, "list_sessions", json!({ "max_bytes": 4095 })),
        ],
    );
    for id in [2, 3, 4, 5, 6, 7] {
        let frame = frame_by_id(&frames, id);
        assert!(frame["result"].is_null(), "{frame}");
        assert_eq!(frame["error"]["code"], -32602, "{frame}");
        assert_eq!(frame["error"]["data"]["canonical_code"], "invalid_request");
    }
    // 精确下限（4096/1）放行到 App 层，正常业务帧。
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "ctx", "max_bytes": 4096 }),
            ),
            tool_call(
                3,
                "get_session_context",
                json!({ "session_id": session_wire, "max_messages": 1 }),
            ),
        ],
    );
    for id in [2, 3] {
        assert_eq!(
            frame_by_id(&frames, id)["result"]["isError"],
            false,
            "{frames:?}"
        );
    }
}

#[test]
fn error_messages_bound_echoed_values() {
    let (_dir, db) = temp_db("mcp-bounded-errors");
    let long_method = "x".repeat(400);
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": long_method.as_str() }),
        ],
    );
    let frame = frame_by_id(&frames, 2);
    assert_eq!(frame["error"]["code"], -32601, "{frame}");
    let message = frame["error"]["message"].as_str().expect("message");
    assert!(message.starts_with("method not found: "), "{message}");
    assert!(
        message.len() <= "method not found: ".len() + 128 + 3,
        "{message}"
    );
}

#[test]
fn tool_schemas_publish_string_and_array_bounds() {
    let (_dir, db) = temp_db("mcp-schema-bounds");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        ],
    );
    let tools = frame_by_id(&frames, 2)["result"]["tools"]
        .as_array()
        .expect("tools");
    let search = tools
        .iter()
        .find(|tool| tool["name"] == "search_sessions")
        .expect("search_sessions tool");
    let properties = &search["inputSchema"]["properties"];
    assert_eq!(properties["query"]["maxLength"], 4096, "{search}");
    assert_eq!(properties["cursor"]["maxLength"], 512, "{search}");
    assert_eq!(properties["since"]["maxLength"], 64, "{search}");
    assert_eq!(properties["until"]["maxLength"], 64, "{search}");
    // All implemented provider IDs and aliases share the registry's bounds.
    let provider_values = agent_session_grep_ports::capability::search_provider_filter_values();
    assert_eq!(
        properties["providers"]["maxItems"],
        provider_values.len(),
        "{search}"
    );
    assert_eq!(
        properties["providers"]["items"]["enum"],
        json!(provider_values),
        "{search}"
    );
    assert_eq!(properties["tool_name"]["maxLength"], 128, "{search}");
    let context = tools
        .iter()
        .find(|tool| tool["name"] == "get_session_context")
        .expect("get_session_context tool");
    assert_eq!(
        context["inputSchema"]["properties"]["session_id"]["maxLength"],
        128
    );
    let resume = tools
        .iter()
        .find(|tool| tool["name"] == "get_session_resume")
        .expect("get_session_resume tool");
    assert_eq!(
        resume["inputSchema"]["properties"]["session_id"]["maxLength"],
        128
    );
    let message = tools
        .iter()
        .find(|tool| tool["name"] == "get_message")
        .expect("get_message tool");
    assert_eq!(
        message["inputSchema"]["properties"]["message_id"]["maxLength"],
        128
    );
    assert_eq!(
        message["inputSchema"]["properties"]["session_id"]["maxLength"],
        128
    );
    let list = tools
        .iter()
        .find(|tool| tool["name"] == "list_sessions")
        .expect("list_sessions tool");
    assert_eq!(
        list["inputSchema"]["properties"]["cursor"]["maxLength"],
        512
    );
}

// ─── design §4 场景 8：status / doctor / list_providers 真实数据 ────────────

#[test]
fn status_doctor_and_providers_return_real_data() {
    let (dir, db) = temp_db("mcp-status");
    let (fixture_path, _anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "get_status", json!({})),
            tool_call(3, "doctor", json!({})),
            tool_call(4, "list_providers", json!({})),
        ],
    );
    assert_eq!(frames.len(), 4, "{frames:?}");

    // get_status：入库后 catalog 非空（4 消息 + 会话 + 文档）。
    let status = &frame_by_id(&frames, 2)["result"]["structuredContent"];
    assert_eq!(status["outcome"], "success");
    let catalog_count = status["data"]["catalog_count"]
        .as_u64()
        .expect("data.catalog_count");
    assert!(catalog_count >= 1, "{status}");

    // doctor：真实打开的库 → db:ok，干净库无待收敛 intent、无孤儿投影行。
    let doctor = &frame_by_id(&frames, 3)["result"]["structuredContent"];
    assert_eq!(doctor["data"]["db"], "ok", "{doctor}");
    assert!(doctor["data"]["generation"].is_number(), "{doctor}");
    assert_eq!(doctor["data"]["interrupted_batches"], 0, "{doctor}");
    assert_eq!(doctor["data"]["orphaned_tool_activities"], 0, "{doctor}");
    assert_eq!(
        doctor["data"]["orphaned_activity_memberships"], 0,
        "{doctor}"
    );

    // list_providers：真实枚举组合根注册表，两个已支持 provider 必在。
    let providers = &frame_by_id(&frames, 4)["result"]["structuredContent"];
    let ids: Vec<&str> = providers["data"]["providers"]
        .as_array()
        .expect("data.providers")
        .iter()
        .map(|provider| provider["id"].as_str().expect("provider.id"))
        .collect();
    assert!(ids.contains(&"claude-code"), "{ids:?}");
    assert!(ids.contains(&"codex"), "{ids:?}");
}

#[test]
fn mcp_doctor_data_matches_the_cli_doctor_envelope_field_for_field() {
    // 跨入口一致性（release 一致性 harness 只比对 search 一个操作，doctor 从未
    // 被比对过）：MCP doctor 曾比 CLI `doctor --db` 少 6 个字段——offline /
    // semantic_feature / tool_activity_storage / usage_storage /
    // orphaned_usage_events / orphaned_usage_memberships。AI 客户端靠 doctor
    // 判断"为什么语义检索退化""为什么 usage 是空的"，经 MCP 问会得到严格更弱
    // 的答案。期望值取自真实 CLI 输出，不是手抄清单。
    let (dir, db) = temp_db("mcp-doctor-parity");
    let (fixture_path, _anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    let out = run_cli(&db, &["doctor"]);
    assert!(out.status.success(), "cli doctor failed: {}", stdout(&out));
    let cli: Value = serde_json::from_str(stdout(&out).trim())
        .unwrap_or_else(|error| panic!("cli doctor envelope must be JSON: {error}"));
    let cli_data = &cli["data"];

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "doctor", json!({})),
        ],
    );
    let mcp_data = &frame_by_id(&frames, 2)["result"]["structuredContent"]["data"];
    assert_eq!(
        mcp_data, cli_data,
        "MCP doctor 与 CLI doctor 的 data 投影必须逐字段一致"
    );
}

// ─── search-match-guidance：MCP search 命中携带追加 guidance 字段 ─────────────

#[test]
fn mcp_search_hits_carry_why_matched_and_suggestions() {
    let (dir, db) = temp_db("mcp-guidance");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "search_sessions", json!({ "query": "ctx" })),
        ],
    );
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "{result}");
    let hits = result["structuredContent"]["data"]["hits"]
        .as_array()
        .expect("data.hits");
    assert!(!hits.is_empty(), "{result}");
    let hit = &hits[0];
    assert_eq!(hit["session_id"].as_str(), Some(session_wire.as_str()));
    assert!(
        hit["why_matched"]
            .as_array()
            .is_some_and(|a| a.iter().any(|t| t == "ctx")),
        "{hit}"
    );
    let suggested = hit["suggested_next_commands"]
        .as_array()
        .expect("suggested_next_commands");
    assert_eq!(suggested.len(), 2);
    assert!(
        suggested[0].as_str().is_some_and(
            |c| c.contains("get-message") && c.contains(hit["id"].as_str().expect("id"))
        )
    );
    assert!(
        suggested[1]
            .as_str()
            .is_some_and(|c| c.contains("context ") && c.contains(&session_wire))
    );
}

fn write_long_hits_fixture(dir: &Path) -> (String, String) {
    let body_a = format!("widgets in the attic{}", "x".repeat(2000));
    let body_b = format!("widgets reply{}", "y".repeat(2000));
    let line_a = serde_json::json!({
        "type": "user",
        "uuid": "eeee1111-2222-4333-8444-555566667777",
        "sessionId": "abcd1234-5678-4abc-8def-aabbccddeeff",
        "message": { "role": "user", "content": body_a },
    })
    .to_string();
    let line_b = serde_json::json!({
        "type": "assistant",
        "uuid": "ffff2222-3333-4444-8555-666677778888",
        "sessionId": "abcd1234-5678-4abc-8def-aabbccddeeff",
        "message": { "role": "assistant", "content": body_b },
    })
    .to_string();
    let fixture = dir.join("long-hits.jsonl");
    std::fs::write(&fixture, format!("{line_a}\n{line_b}\n")).expect("write long hits fixture");
    (
        fixture.to_string_lossy().into_owned(),
        "ses_v1_abcd1234-5678-4abc-8def-aabbccddeeff".to_string(),
    )
}

#[test]
fn mcp_search_byte_budget_includes_guidance() {
    let (dir, db) = temp_db("mcp-guidance-budget");
    let (fixture_path, _session_wire) = write_long_hits_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "widgets", "max_bytes": 4096 }),
            ),
        ],
    );
    let payload = &frame_by_id(&frames, 2)["result"]["structuredContent"];
    assert_eq!(payload["outcome"], "partial", "{payload}");
    assert_eq!(
        payload["data"]["truncation"]["reason"], "max_response_bytes",
        "{payload}"
    );
    let hits = payload["data"]["hits"].as_array().expect("data.hits");
    assert!(hits.len() < 2, "{payload}");
    for hit in hits {
        assert!(
            hit["why_matched"]
                .as_array()
                .is_some_and(|a| a.iter().any(|t| t == "widgets")),
            "{hit}"
        );
        let suggested = hit["suggested_next_commands"]
            .as_array()
            .expect("suggested_next_commands");
        assert_eq!(suggested.len(), 2, "{hit}");
        assert!(suggested.iter().any(|command| {
            command.as_str().is_some_and(|text| {
                text.contains("get-message") && text.contains(hit["id"].as_str().expect("id"))
            })
        }));
    }
}

// ─── search_sessions provider/time 过滤（08-13）──────────────────────────────

fn write_filter_fixtures(dir: &Path) -> (String, String) {
    let claude = dir.join("mcp-filter-claude.jsonl");
    std::fs::write(
        &claude,
        concat!(
            r#"{"type":"user","uuid":"f2222222-2222-4222-8222-222222222221","sessionId":"fa222222-2222-4222-8222-222222222222","timestamp":"2026-07-01T00:00:00.000Z","message":{"role":"user","content":"mcpfilter early note"}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"f2222222-2222-4222-8222-222222222222","parentUuid":"f2222222-2222-4222-8222-222222222221","sessionId":"fa222222-2222-4222-8222-222222222222","timestamp":"2026-07-28T00:00:00.000Z","message":{"role":"assistant","content":"mcpfilter mid note"}}"#,
            "\n",
        ),
    )
    .expect("write claude filter fixture");
    let codex = dir.join("mcp-filter-codex.jsonl");
    std::fs::write(
        &codex,
        concat!(
            r#"{"timestamp":"2026-08-10T00:00:00.000Z","type":"session_meta","payload":{"session_id":"fb333333-3333-4333-8333-333333333333","cwd":"/tmp","originator":"codex","cli_version":"1.0"}}"#,
            "\n",
            r#"{"timestamp":"2026-08-10T00:01:00.000Z","type":"response_item","payload":{"type":"message","id":"msg_mcpfilter_codex","role":"user","content":[{"type":"input_text","text":"mcpfilter codex note"}]}}"#,
            "\n",
        ),
    )
    .expect("write codex filter fixture");
    (
        claude.to_string_lossy().into_owned(),
        codex.to_string_lossy().into_owned(),
    )
}

fn filter_db(tag: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let (dir, db) = temp_db(tag);
    let (claude, codex) = write_filter_fixtures(dir.path());
    for fixture in [&claude, &codex] {
        let out = run_cli(&db, &["ingest", fixture]);
        assert!(out.status.success(), "ingest {fixture}: {}", stdout(&out));
    }
    (dir, db)
}

fn two_searches(db: &Path, first: Value, second: Value) -> (Value, Value) {
    let frames = mcp_session(
        db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "search_sessions", first),
            tool_call(3, "search_sessions", second),
        ],
    );
    (
        frame_by_id(&frames, 2)["result"].clone(),
        frame_by_id(&frames, 3)["result"].clone(),
    )
}

fn hit_texts(result: &Value) -> Vec<String> {
    assert_eq!(result["isError"], false, "{result}");
    result["structuredContent"]["data"]["hits"]
        .as_array()
        .expect("data.hits")
        .iter()
        .map(|hit| hit["text"].as_str().expect("hit text").to_string())
        .collect()
}

#[test]
fn search_sessions_schema_publishes_provider_and_time_filters() {
    let (_dir, db) = temp_db("mcp-filter-schema");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        ],
    );
    let tools = frame_by_id(&frames, 2)["result"]["tools"]
        .as_array()
        .expect("tools");
    let search = tools
        .iter()
        .find(|tool| tool["name"] == "search_sessions")
        .expect("search_sessions tool");
    let properties = &search["inputSchema"]["properties"];
    assert_eq!(properties["providers"]["type"], "array", "{search}");
    assert_eq!(
        properties["providers"]["items"]["enum"],
        json!(agent_session_grep_ports::capability::search_provider_filter_values()),
        "{search}"
    );
    assert_eq!(properties["since"]["type"], "string", "{search}");
    assert_eq!(properties["until"]["type"], "string", "{search}");
}

#[test]
fn semantic_and_hybrid_mcp_search_use_vectors_and_keep_cli_filters() {
    let (_dir, db) = filter_db("mcp-semantic-filters");
    let before: Value = serde_json::from_str(&stdout(&run_cli(&db, &["status"]))).unwrap();
    let indexed = run_cli(&db, &["index", "embeddings"]);
    assert!(indexed.status.success(), "{}", stdout(&indexed));
    let after: Value = serde_json::from_str(&stdout(&run_cli(&db, &["status"]))).unwrap();
    assert_eq!(
        after["data"]["generation"].as_u64().unwrap(),
        before["data"]["generation"].as_u64().unwrap() + 1,
        "a complete rebuild must advance generation once, not once per vector"
    );
    for mode in ["semantic", "hybrid"] {
        let cli = run_cli(
            &db,
            &[
                "search",
                "mcpfilter",
                "--mode",
                mode,
                "--provider",
                "claude-code",
                "--since",
                "2026-07-28T00:00:00Z",
            ],
        );
        assert!(cli.status.success(), "{}", stdout(&cli));
        let cli: Value = serde_json::from_str(&stdout(&cli)).unwrap();
        let (matching, excluded) = two_searches(
            &db,
            json!({"query":"mcpfilter", "mode":mode, "providers":["claude"], "since":"2026-07-28T00:00:00Z"}),
            json!({"query":"mcpfilter", "mode":mode, "providers":["claude"], "since":"2026-08-01T00:00:00Z"}),
        );
        assert_eq!(
            matching["structuredContent"]["data"]["retrieval_mode"], mode,
            "{matching}"
        );
        assert_eq!(hit_texts(&matching), ["mcpfilter mid note"], "{matching}");
        assert!(hit_texts(&excluded).is_empty(), "{excluded}");
        assert_eq!(
            matching["structuredContent"]["data"]["hits"],
            cli["data"]["hits"]
        );
    }
}

#[test]
fn search_sessions_filters_subset_or_and_time() {
    let (_dir, db) = filter_db("mcp-filter-search");
    let (claude_only, codex_only) = two_searches(
        &db,
        json!({ "query": "mcpfilter", "providers": ["claude"] }),
        json!({ "query": "mcpfilter", "providers": ["codex"] }),
    );
    let claude_texts = hit_texts(&claude_only);
    assert_eq!(claude_texts.len(), 2, "{claude_texts:?}");
    assert!(!claude_texts.iter().any(|text| text.contains("codex")));
    assert_eq!(hit_texts(&codex_only), vec!["mcpfilter codex note"]);

    let (both, window) = two_searches(
        &db,
        json!({ "query": "mcpfilter", "providers": ["codex", "claude"] }),
        json!({
            "query": "mcpfilter",
            "providers": ["claude"],
            "since": "2026-07-28T00:00:00Z",
        }),
    );
    assert_eq!(hit_texts(&both).len(), 3, "{both}");
    assert_eq!(hit_texts(&window), vec!["mcpfilter mid note"], "{window}");
}

#[test]
fn search_sessions_rejects_unknown_provider_and_compact_durations() {
    let (_dir, db) = filter_db("mcp-filter-invalid");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "mcpfilter", "providers": ["gemini"] }),
            ),
            tool_call(
                3,
                "search_sessions",
                json!({ "query": "mcpfilter", "since": "1h" }),
            ),
            tool_call(
                4,
                "search_sessions",
                json!({ "query": "mcpfilter", "until": "1d" }),
            ),
            tool_call(
                5,
                "search_sessions",
                json!({ "query": "mcpfilter", "providers": "claude" }),
            ),
        ],
    );
    for id in [2, 3, 4, 5] {
        let frame = frame_by_id(&frames, id);
        assert_eq!(frame["error"]["code"], -32602, "{frame}");
        assert_eq!(frame["error"]["data"]["canonical_code"], "invalid_request");
    }
}

#[test]
fn search_sessions_rejects_inverted_time_range_as_business_error() {
    let (_dir, db) = filter_db("mcp-filter-range");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({
                    "query": "mcpfilter",
                    "since": "2026-08-10T00:00:00Z",
                    "until": "2026-07-01T00:00:00Z",
                }),
            ),
        ],
    );
    let frame = frame_by_id(&frames, 2);
    assert!(frame["error"].is_null(), "{frame}");
    let result = &frame["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(
        result["structuredContent"]["error"]["canonical_code"],
        "invalid_request"
    );
}

#[test]
fn search_sessions_cursor_reissued_with_mutated_filters_is_rejected() {
    let (_dir, db) = filter_db("mcp-filter-cursor");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "mcpfilter", "providers": ["claude"], "max_items": 1 }),
            ),
        ],
    );
    let payload = &frame_by_id(&frames, 2)["result"]["structuredContent"];
    let cursor = payload["page"]["next_cursor"]
        .as_str()
        .expect("next_cursor")
        .to_string();
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({
                    "query": "mcpfilter",
                    "providers": ["claude"],
                    "max_items": 1,
                    "cursor": cursor,
                }),
            ),
            tool_call(
                3,
                "search_sessions",
                json!({
                    "query": "mcpfilter",
                    "providers": ["codex"],
                    "max_items": 1,
                    "cursor": cursor,
                }),
            ),
            tool_call(
                4,
                "search_sessions",
                json!({ "query": "mcpfilter", "max_items": 1, "cursor": cursor }),
            ),
        ],
    );
    assert_eq!(frame_by_id(&frames, 2)["result"]["isError"], false);
    for id in [3, 4] {
        let result = &frame_by_id(&frames, id)["result"];
        assert_eq!(result["isError"], true, "{result}");
        assert_eq!(
            result["structuredContent"]["error"]["canonical_code"],
            "cursor_invalid"
        );
    }
}

// ─── design §4 场景 9：参数值域校验失败 → -32602 + canonical data ───────────

#[test]
fn invalid_session_id_param_is_protocol_error() {
    let (_dir, db) = temp_db("mcp-invalid-params");
    // 参数结构合法但值域校验失败（非法 wire id）→ 协议层 -32602，
    // error.data 携带 canonical 映射（design §2 注记）。
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(
                2,
                "get_session_context",
                json!({ "session_id": "not-a-wire-id" }),
            ),
        ],
    );
    assert_eq!(frames.len(), 2, "{frames:?}");
    let frame = frame_by_id(&frames, 2);
    assert!(frame["result"].is_null(), "{frame}");
    assert_eq!(frame["error"]["code"], -32602);
    assert_eq!(frame["error"]["data"]["canonical_code"], "invalid_request");
    assert_eq!(frame["error"]["data"]["retryable"], false);
}

// ─── 分层一致性（Minor-7，E5）：list_sessions limit:0 与 search 同层拒绝 ──────

#[test]
fn list_sessions_zero_limit_is_protocol_error_like_search() {
    // list_sessions 的 limit:0 必须在协议层回 -32602，与 search_sessions 一致；
    // 不得漏到 App 层变成 isError 业务帧（分层一致性）。
    let (_dir, db) = temp_db("mcp-list-limit");
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "list_sessions", json!({ "limit": 0 })),
            tool_call(3, "list_sessions", json!({ "max_items": 0 })),
        ],
    );
    assert_eq!(frames.len(), 3, "{frames:?}");
    for id in [2, 3] {
        let frame = frame_by_id(&frames, id);
        assert!(frame["result"].is_null(), "{frame}");
        assert_eq!(frame["error"]["code"], -32602, "{frame}");
        assert_eq!(frame["error"]["data"]["canonical_code"], "invalid_request");
    }
    // 对照：search_sessions 的 limit:0 同样 -32602（分层一致性的基准）。
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "search_sessions", json!({ "query": "x", "limit": 0 })),
        ],
    );
    assert_eq!(frame_by_id(&frames, 2)["error"]["code"], -32602);
}

// ─── Peek Bundle（#7，hstry 借用）：list_sessions 条目附分诊预览 ─────────────

#[test]
fn list_sessions_entries_carry_peek_with_first_and_last_user_text() {
    // 真实 ingest 后的 list_sessions：每条会话条目附 peek，首/尾用户消息按
    // member 顺序抽取（sidechain 用户轮同样计入——member 顺序是唯一事实源）。
    let (dir, db) = temp_db("mcp-list-peek");
    let (fixture_path, _anchor) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "list_sessions", json!({ "limit": 10 })),
        ],
    );
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "list_sessions 应成功: {result}");
    let entries = result["structuredContent"]["data"]["entries"]
        .as_array()
        .expect("entries must be an array");
    assert_eq!(entries.len(), 1, "fixture ingests exactly one session");
    let peek = &entries[0]["peek"];
    assert!(peek.is_object(), "peek key must be present: {entries:?}");
    assert_eq!(
        peek["first_user_text"], "ctx root question",
        "first user turn: {peek}"
    );
    assert_eq!(
        peek["last_user_text"], "ctx sidechain probe",
        "last user turn (sidechain included): {peek}"
    );
    // 预览必须是小对象：序列化 ≤1 KiB（per-session 预算常量）。
    let serialized = serde_json::to_string(peek).expect("peek serializes");
    assert!(
        serialized.len() <= 1024,
        "peek over budget: {serialized} bytes"
    );
}

// ─── 会话标题派生链（#6）：list_sessions 条目附派生标题 ─────────────────────

#[test]
fn list_sessions_entries_carry_title_skipping_injected_noise() {
    // 真实 ingest：首条 user 消息是注入噪声封套（`<system-reminder>`，parse 层
    // 过滤，feat/noise-filter 已合 main）→ 标题派生链跳过它，取第二条有效
    // user 消息；条目在 peek 旁附 title 字段。
    let (dir, db) = temp_db("mcp-list-title");
    let fixture = dir.path().join("title-noise.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","uuid":"d0000000-0000-4000-8000-000000000001","parentUuid":null,"sessionId":"ddee1234-5678-4abc-8def-001122334455","timestamp":"2026-07-26T01:00:00.000Z","message":{"role":"user","content":"<system-reminder>"#,
            r#"\ninjected context noise\n</system-reminder>"}}"#,
            "\n",
            r#"{"type":"user","uuid":"d0000000-0000-4000-8000-000000000002","parentUuid":"d0000000-0000-4000-8000-000000000001","sessionId":"ddee1234-5678-4abc-8def-001122334455","timestamp":"2026-07-26T01:01:00.000Z","message":{"role":"user","content":"real title prompt"}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"d0000000-0000-4000-8000-000000000003","parentUuid":"d0000000-0000-4000-8000-000000000002","sessionId":"ddee1234-5678-4abc-8def-001122334455","message":{"role":"assistant","content":"answer"}}"#,
            "\n",
        ),
    )
    .expect("write title fixture");
    let out = run_cli(&db, &["ingest", &fixture.to_string_lossy()]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "list_sessions", json!({ "limit": 10 })),
        ],
    );
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "list_sessions 应成功: {result}");
    let entries = result["structuredContent"]["data"]["entries"]
        .as_array()
        .expect("entries must be an array");
    assert_eq!(entries.len(), 1, "fixture ingests exactly one session");
    assert_eq!(
        entries[0]["title"], "real title prompt",
        "派生标题必须跳过注入噪声、取首条有效 user: {entries:?}"
    );
}

// ─── stderr 隐私（E2）：协议错误不落 stderr ─────────────────────────────────

#[test]
fn mcp_stderr_stays_clean_on_protocol_errors() {
    // stderr 是进程级诊断通道，正常协议交互（含错误帧）下必须为空或至少
    // 不含 db 路径——隐私回归守卫。
    let (_dir, db) = temp_db("mcp-stderr-privacy");
    let db_str = db.to_string_lossy().into_owned();

    // 坏 JSON → -32700 帧；stderr 不得出现 db 路径。
    let (frames, stderr) = mcp_session_raw_stderr(&db, &["{ not json"]);
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["error"]["code"], -32700);
    assert!(!stderr.contains(&db_str), "stderr 泄露 db 路径: {stderr}");

    // 未握手请求 → -32600；stderr 保持为空。
    let uninitialized =
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }).to_string();
    let (_, stderr) = mcp_session_raw_stderr(&db, &[&uninitialized]);
    assert!(stderr.is_empty(), "协议错误不得写入 stderr: {stderr}");

    // 工具参数错误 → -32602；stderr 保持为空。
    let (_, stderr) = mcp_session_raw_stderr(
        &db,
        &[
            &initialize_request(1, "2025-06-18").to_string(),
            &initialized_notification().to_string(),
            &tool_call(2, "list_sessions", json!({ "limit": 0 })).to_string(),
        ],
    );
    assert!(stderr.is_empty(), "参数错误不得写入 stderr: {stderr}");
}

#[test]
fn all_tool_results_carry_the_redaction_block() {
    // ADR-0009：跨边界脱敏状态必须随
    // 每个成功工具结果上报。曾经 MCP 只做脱敏、丢弃状态，调用方拿到
    // "[redacted:...]" 无法区分服务端涂红与原文逐字如此。真实夹具上覆盖全部
    // 9 个工具（含需要关系行的 context/message/handoff）。
    let (dir, db) = temp_db("mcp-redaction-block");
    let (fixture_path, anchor_message) = write_context_fixture(dir.path());
    let out = run_cli(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let calls = [
        ("doctor", json!({})),
        ("get_status", json!({})),
        ("list_providers", json!({})),
        ("search_sessions", json!({ "query": "ctx" })),
        ("list_sessions", json!({ "limit": 5 })),
        ("generate_handoff", json!({ "query": "ctx" })),
        (
            "get_session_context",
            json!({ "session_id": session_wire.as_str() }),
        ),
        (
            "get_session_resume",
            json!({ "session_id": session_wire.as_str() }),
        ),
        (
            "get_message",
            json!({ "message_id": anchor_message.as_str(), "around": 1 }),
        ),
    ];
    let mut inputs = vec![
        initialize_request(1, "2025-06-18"),
        initialized_notification(),
    ];
    for (index, (name, arguments)) in calls.iter().enumerate() {
        inputs.push(tool_call(index as i64 + 10, name, arguments.clone()));
    }
    let frames = mcp_session(&db, &inputs);

    for (index, (name, _)) in calls.iter().enumerate() {
        let result = &frame_by_id(&frames, index as i64 + 10)["result"];
        assert_eq!(result["isError"], false, "{name} 应成功: {result}");
        let payload = &result["structuredContent"];
        let redaction = &payload["redaction"];
        assert!(redaction.is_object(), "{name} 缺少 redaction 块: {payload}");
        assert_eq!(redaction["mode"], "default", "{name}: {redaction}");
        assert_eq!(redaction["status"], "none", "{name}: {redaction}");
        assert_eq!(redaction["redacted_count"], 0, "{name}: {redaction}");
        assert!(
            redaction["ruleset_version"].is_string(),
            "{name}: {redaction}"
        );
        assert!(redaction["audit_id"].is_null(), "{name}: {redaction}");
        // 双载体同形：状态进两个载体，不只进 structuredContent。
        let text = result["content"][0]["text"].as_str().expect("text content");
        let parsed: Value = serde_json::from_str(text).expect("content.text is JSON");
        assert_eq!(&parsed, payload, "{name} 双载体漂移");
    }
}

#[test]
fn non_utf8_line_is_a_parse_error_and_the_server_keeps_serving() {
    // 曾经 `serve` 用 `BufRead::lines()` 读 stdin：一行非法 UTF-8 字节让迭代器
    // 返回 Err，`?` 直接把它当 source_io 抛出整个进程（exit 5）。待答请求与其后
    // 所有请求全部无声消失——客户端只能等到超时，而正确答复是 -32700。
    let (_dir, db) = temp_db("mcp-non-utf8");
    let mut payload = Vec::new();
    payload.extend_from_slice(initialize_request(1, "2025-06-18").to_string().as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(initialized_notification().to_string().as_bytes());
    payload.push(b'\n');
    // 0xFF 0xFE 不是合法 UTF-8 序列。
    payload.extend_from_slice(br#"{"jsonrpc":"2.0","id":2,"method":"ping","x":""#);
    payload.extend_from_slice(&[0xFF, 0xFE]);
    payload.extend_from_slice(br#""}"#);
    payload.push(b'\n');
    payload.extend_from_slice(
        json!({ "jsonrpc": "2.0", "id": 3, "method": "ping" })
            .to_string()
            .as_bytes(),
    );
    payload.push(b'\n');

    let (frames, stderr, code) = mcp_session_bytes(&db, &payload);
    assert_eq!(code, Some(0), "EOF 必须干净停机；stderr: {stderr}");
    // 坏字节那一行得到 -32700（id 无法回显 → null）。
    let parse_errors: Vec<&Value> = frames
        .iter()
        .filter(|frame| frame["error"]["code"] == json!(-32700))
        .collect();
    assert_eq!(parse_errors.len(), 1, "{frames:?}");
    assert!(parse_errors[0]["id"].is_null(), "{frames:?}");
    // 其后的请求照常应答——这是回归的核心。
    assert_eq!(frame_by_id(&frames, 3)["result"], json!({}), "{frames:?}");
    assert!(
        !stderr.contains(&db.to_string_lossy().to_string()),
        "stderr 泄露 db 路径: {stderr}"
    );
}

// ─── design §4 场景补充：search_sessions facet 参数（structured activity）──

#[test]
fn search_sessions_facet_params_filter_and_validate() {
    let (dir, db) = temp_db("mcp-facets");
    // 种子数据：Claude 合成夹具（Bash 主线 + Read sidechain，含检索词 "facet"）。
    let fixture = dir.path().join("claude-tools.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","uuid":"f-1","sessionId":"sess-f","message":{"role":"user","content":"facet kickoff"}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"f-2","parentUuid":"f-1","sessionId":"sess-f","message":{"role":"assistant","content":[{"type":"text","text":"facet running"},{"type":"tool_use","id":"toolu_f1","name":"Bash","input":{"command":"facet build"}}]}}"#,
            "\n",
            r#"{"type":"user","uuid":"f-3","parentUuid":"f-2","sessionId":"sess-f","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_f1","content":"facet done","is_error":false}]}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"f-4","parentUuid":"f-3","sessionId":"sess-f","isSidechain":true,"message":{"role":"assistant","content":[{"type":"text","text":"facet subagent work"},{"type":"tool_use","id":"toolu_f2","name":"Read","input":{"file_path":"facet.txt"}}]}}"#,
            "\n",
            r#"{"type":"user","uuid":"f-5","parentUuid":"f-4","sessionId":"sess-f","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_f2","content":"facet contents","is_error":false}]}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();
    let out = run_cli(&db, &["sync", &path]);
    assert!(out.status.success(), "seed sync: {}", stdout(&out));
    assert!(
        stdout(&out).contains("\"messages\":5"),
        "seed sync content: {}",
        stdout(&out)
    );

    let init = initialize_request(1, "2025-06-18");
    let frames = mcp_session(
        &db,
        &[
            init,
            initialized_notification(),
            tool_call(
                2,
                "search_sessions",
                json!({ "query": "facet", "tool_kind": "command" }),
            ),
            tool_call(
                3,
                "search_sessions",
                json!({ "query": "facet", "sidechain": "subagent_only" }),
            ),
            tool_call(
                4,
                "search_sessions",
                json!({ "query": "facet", "tool_kind": "bogus" }),
            ),
        ],
    );

    // --tool-kind command：只有锚定 Bash 活动的 f-3 命中。
    let result = &frame_by_id(&frames, 2)["result"];
    assert_eq!(result["isError"], false, "{result}");
    let hits = result["structuredContent"]["data"]["hits"]
        .as_array()
        .unwrap();
    assert_eq!(hits.len(), 1, "{result}");
    assert_eq!(hits[0]["id"], "msg_v1_f-3", "{result}");

    // sidechain=subagent_only：只有 sidechain 的 f-4 命中。
    let result = &frame_by_id(&frames, 3)["result"];
    let hits = result["structuredContent"]["data"]["hits"]
        .as_array()
        .unwrap();
    assert_eq!(hits.len(), 1, "{result}");
    assert_eq!(hits[0]["id"], "msg_v1_f-4", "{result}");

    // 非法 tool_kind 是协议层 -32602。
    let error = &frame_by_id(&frames, 4)["error"];
    assert_eq!(error["code"], -32602, "{error}");
}

#[test]
fn relocation_is_described_as_cli_only_and_rejected_as_an_mcp_mutation() {
    let (_dir, db) = temp_db("mcp-relocation-boundary");
    let before = std::fs::read(&db).unwrap();
    let cli = run_cli(&db, &["providers"]);
    assert!(cli.status.success());
    let providers: Value = serde_json::from_str(&stdout(&cli)).unwrap();
    assert_eq!(
        providers["data"]["relocation"]["interfaces"],
        json!(["cli"])
    );
    let frames = mcp_session(
        &db,
        &[
            initialize_request(1, "2025-06-18"),
            initialized_notification(),
            tool_call(2, "list_providers", json!({})),
            tool_call(
                3,
                "relocate",
                json!({
                    "provider": "claude-code", "from": "/private/retired-root",
                    "to": "/private/new-root", "apply": true, "plan": "private-plan",
                    "backup": "/private/backup.db",
                }),
            ),
            tool_call(4, "relocate.apply", json!({})),
        ],
    );
    assert!(frame_by_id(&frames, 2)["result"]["structuredContent"]["data"]["providers"].is_array());
    for id in [3, 4] {
        let frame = frame_by_id(&frames, id);
        assert_eq!(frame["error"]["code"], -32602);
        assert!(frame["result"].is_null());
        assert!(!frame.to_string().contains("/private/"));
        assert!(!frame.to_string().contains("private-plan"));
    }
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "MCP cannot mutate relocation state"
    );
}
