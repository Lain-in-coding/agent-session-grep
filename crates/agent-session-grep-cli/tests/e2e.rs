//! CLI 端到端集成测试：驱动真实编译出的二进制，走 index → search → get 全链路。
//!
//! 目的：把「组合根真的能把 SQLite adapter 注入 Application 并端到端跑通」这件事
//! 固化进 CI，而非依赖手动运行。Cargo 为集成测试注入 `CARGO_BIN_EXE_<bin>`，
//! 故此处零第三方依赖即可定位到刚构建的二进制。

use rusqlite::Connection;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// 刚构建出的 `agent-session-grep` 二进制的绝对路径（由 Cargo 在编译期注入）。
const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");

/// 在给定 db 上以 robot 协议模式跑一次 CLI，返回完整输出。
/// 功能性测试统一断言稳定 JSON envelope；human 版式走 [`run_human`]。
fn run(db: &str, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--db")
        .arg(db)
        .arg("--robot")
        .args(args)
        .output()
        .expect("failed to spawn agent-session-grep binary")
}

/// 在给定 db 上以默认 human 模式跑一次 CLI（无 --robot）：验证人类渲染器输出。
fn run_human(db: &str, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--db")
        .arg(db)
        .args(args)
        .output()
        .expect("failed to spawn agent-session-grep binary")
}

/// 解析 stdout 的第一行为 JSON Value。
fn parse_first_line(o: &Output) -> serde_json::Value {
    let text = stdout(o);
    let line = text
        .lines()
        .next()
        .expect("output must have at least one line");
    serde_json::from_str(line).unwrap_or_else(|error| panic!("not valid JSON: {error}\n{line}"))
}

/// 断言 frame 满足 Robot v1 envelope 最小契约。
fn assert_envelope_shape(frame: &serde_json::Value, ok: bool) {
    assert_eq!(frame["schema_version"], "1.1", "schema_version");
    assert_eq!(frame["ok"], ok, "ok");
    if ok {
        assert_eq!(frame["frame_type"], "response", "frame_type");
        assert!(
            matches!(frame["outcome"].as_str(), Some("success") | Some("partial")),
            "outcome must be success or partial for ok:true"
        );
        assert!(frame["data"].is_object(), "data must be an object");
    } else {
        assert_eq!(frame["frame_type"], "error", "frame_type");
        assert_eq!(frame["outcome"], "failure", "outcome");
        let code = frame["error"]["code"]
            .as_str()
            .expect("error.code must be a string");
        assert!(!code.is_empty(), "error.code must not be empty");
        let message = frame["error"]["message"]
            .as_str()
            .expect("error.message must be a string");
        assert!(!message.is_empty(), "error.message must not be empty");
        assert!(
            frame["error"]["retryable"].is_boolean(),
            "error.retryable must be a boolean"
        );
        let details = frame["error"]["details"]
            .as_object()
            .expect("error.details must be an object");
        assert!(
            details.len() <= 32,
            "error.details must be bounded (schema caps at 32 properties), got {}",
            details.len()
        );
    }
    assert!(
        frame["request_id"].as_str().is_some(),
        "request_id must be a string"
    );
    assert!(frame["warnings"].is_array(), "warnings must be an array");
    assert!(
        frame["page"]["has_more"].is_boolean(),
        "page.has_more must be a boolean"
    );
    assert!(
        frame["page"]["next_cursor"].is_null() || frame["page"]["next_cursor"].is_string(),
        "page.next_cursor must be a string or null"
    );
    assert!(
        frame["meta"]["duration_ms"].is_number(),
        "meta.duration_ms must be a number"
    );
    assert!(
        frame["meta"]["generation"].is_null() || frame["meta"]["generation"].is_number(),
        "meta.generation must be null or a number"
    );
}

/// 每个测试用独立临时目录，避免 WAL/SHM 旁文件互相干扰。
fn temp_db(tag: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{tag}.db"));
    let s = path.to_string_lossy().into_owned();
    (dir, s)
}

fn create_v6_catalog(
    db: &str,
    source_path: &str,
    session_wire: &str,
    message_wire: &str,
    document_wire: &str,
    message_text: &str,
) {
    let conn = Connection::open(db).expect("open v6 fixture catalog");
    conn.execute_batch(
        "CREATE TABLE catalog (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
         CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED, text);
         CREATE TABLE store_metadata (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             active_generation INTEGER NOT NULL
         );
         INSERT INTO store_metadata(singleton, active_generation) VALUES(1, 1);
         CREATE TABLE index_batches (
             operation_id TEXT PRIMARY KEY,
             base_generation INTEGER NOT NULL,
             target_generation INTEGER NOT NULL,
             state TEXT NOT NULL,
             operation_digest TEXT NOT NULL,
             upsert_ids_json TEXT NOT NULL,
             delete_ids_json TEXT NOT NULL,
             durable_point TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             committed_at_ms INTEGER,
             error_code TEXT
         );
         CREATE INDEX index_batches_state ON index_batches(state);
         CREATE TABLE fts_ids (
             wire_id TEXT PRIMARY KEY,
             id_json TEXT NOT NULL UNIQUE
         );
         CREATE TABLE source_membership (
             source_path TEXT NOT NULL,
             message_id TEXT NOT NULL,
             document_id TEXT,
             PRIMARY KEY(source_path, message_id)
         );
         CREATE INDEX source_membership_source
         ON source_membership(source_path);
         CREATE TABLE source_scans (
             source_path TEXT PRIMARY KEY,
             scanned_at_ms INTEGER NOT NULL
         );
         PRAGMA user_version = 6;",
    )
    .expect("create v6 schema");

    let session_payload = serde_json::json!({
        "document": document_wire,
        "documents": [document_wire],
        "messages": [message_wire],
    })
    .to_string();
    let message_payload = serde_json::json!({
        "role": "user",
        "text": message_text,
        "timestamp": "2026-07-28T00:00:00.000Z",
        "parent": null,
        "parent_native_id": null,
        "is_sidechain": false,
        "session": session_wire,
        "sessions": [session_wire],
        "span": {"start": 0, "end": 1},
        "spans": [{
            "document": document_wire,
            "start": 0,
            "end": 1,
        }],
    })
    .to_string();
    let document_payload = serde_json::json!({
        "provider": "claude-code",
        "variant": "claude-code/jsonl-v1",
        "fingerprint": "legacy-v6-fingerprint",
        "len": 1,
    })
    .to_string();
    for (wire, payload) in [
        (session_wire, session_payload.as_bytes()),
        (message_wire, message_payload.as_bytes()),
        (document_wire, document_payload.as_bytes()),
    ] {
        conn.execute(
            "INSERT INTO catalog(id, payload) VALUES(?1, ?2)",
            rusqlite::params![wire, payload],
        )
        .expect("insert legacy catalog row");
    }
    for wire in [session_wire, message_wire, document_wire] {
        conn.execute(
            "INSERT INTO source_membership(source_path, message_id, document_id)
             VALUES(?1, ?2, ?3)",
            rusqlite::params![source_path, wire, document_wire],
        )
        .expect("insert legacy membership");
    }
    conn.execute(
        "INSERT INTO source_scans(source_path, scanned_at_ms) VALUES(?1, 1)",
        [source_path],
    )
    .expect("insert legacy source scan");
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn session_wire_for_message(db: &str, message_wire: &str) -> String {
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

/// 不带 `--db` 跑一次 CLI——用于 `--help`/`--version`/`doctor` 等无需存储的命令。
fn run_bare(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn agent-session-grep binary")
}

#[test]
fn index_search_get_roundtrip() {
    let (_dir, db) = temp_db("roundtrip");

    let out = run(&db, &["index", "m1", "the quick brown fox jumps"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("\"ok\":true"));
    assert!(stdout(&out).contains("msg_v1_"));

    run(&db, &["index", "m2", "lazy dog sleeps all day"]);

    // search 命中正确文档：查 "brown" 只应命中 m1。
    let out = run(&db, &["search", "brown"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(
        s.contains("msg_v1_52db0bc4880412c58a3cc166ec6c389a"),
        "got: {s}"
    );
    assert!(!s.contains("lazy"), "brown 不应命中 m2");

    // get 取回 index 时写入的原始 payload——用 search 显示的真实 wire id
    // （`get` 现在按 wire 串反解 id，见 StableId::from_wire，不再把参数当 fact 重派生）。
    let out = run(&db, &["get", "msg_v1_52db0bc4880412c58a3cc166ec6c389a"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("the quick brown fox jumps"));
}

#[test]
fn migrated_v6_catalog_stays_readable_until_complete_reingest_enables_context() {
    let (dir, db) = temp_db("migrated-v6-reingest");
    let session_native = "66111111-1111-4111-8111-111111111111";
    let message_native = "66222222-2222-4222-8222-222222222222";
    let legacy_session_wire = format!("ses_v1_{session_native}");
    let message_wire = format!("msg_v1_{message_native}");
    let legacy_document_wire = "doc_v1_legacy-v6-document";
    let message_text = "legacy catalog survives migration";
    let source = dir.path().join("legacy-source.jsonl");
    let source_content = format!(
        "{{\"type\":\"user\",\"uuid\":\"{message_native}\",\"parentUuid\":null,\
         \"sessionId\":\"{session_native}\",\"timestamp\":\"2026-07-28T00:00:00.000Z\",\
         \"message\":{{\"role\":\"user\",\"content\":\"{message_text}\"}}}}\n"
    );
    std::fs::write(&source, &source_content).expect("write v6 re-ingest fixture");
    let source_path = source.to_string_lossy().into_owned();
    create_v6_catalog(
        &db,
        &source_path,
        &legacy_session_wire,
        &message_wire,
        legacy_document_wire,
        message_text,
    );

    let get = run(&db, &["get", &message_wire]);
    assert!(get.status.success(), "get failed: {}", stdout(&get));
    assert!(
        parse_first_line(&get)["data"]["payload"]
            .as_str()
            .is_some_and(|payload| payload.contains(message_text))
    );

    let show = run(&db, &["show", &legacy_session_wire]);
    assert!(show.status.success(), "show failed: {}", stdout(&show));
    assert_eq!(
        parse_first_line(&show)["data"]["entity"]["document"],
        legacy_document_wire
    );

    let list = run(&db, &["list", "10"]);
    assert!(list.status.success(), "list failed: {}", stdout(&list));
    let entries = parse_first_line(&list)["data"]["entries"]
        .as_array()
        .expect("list entries")
        .clone();
    assert!(
        entries
            .iter()
            .any(|entry| entry["id"] == legacy_session_wire.as_str())
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry["id"] == message_wire.as_str())
    );

    let context = run(&db, &["context", &legacy_session_wire]);
    assert_eq!(
        context.status.code(),
        Some(9),
        "context must require re-ingest: {}",
        stdout(&context)
    );
    let error = parse_first_line(&context);
    assert_eq!(error["error"]["code"], "schema_incompatible");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("re-ingest required"))
    );
    assert!(
        !stdout(&context).contains(&source_path),
        "schema error must not disclose the source path"
    );

    let ingest = run(&db, &["ingest", &source_path]);
    assert!(
        ingest.status.success(),
        "re-ingest failed: {}",
        stdout(&ingest)
    );
    assert_eq!(parse_first_line(&ingest)["data"]["skipped"], 0);
    let session_wire = session_wire_for_message(&db, &message_wire);
    assert_ne!(session_wire, legacy_session_wire);

    let context = run(&db, &["context", &session_wire]);
    assert!(
        context.status.success(),
        "context after re-ingest failed: {}",
        stdout(&context)
    );
    let context = parse_first_line(&context);
    let messages = context["data"]["messages"]
        .as_array()
        .expect("context messages");
    assert_eq!(messages.len(), 1, "{context}");
    assert_eq!(messages[0]["message_id"], message_wire);
    assert_eq!(
        context["data"]["evidence"][0]["occurrence_id"],
        messages[0]["placement_id"]
    );

    let show = run(&db, &["show", &session_wire]);
    let entity = parse_first_line(&show)["data"]["entity"].clone();
    let documents = entity["documents"].as_array().expect("session documents");
    assert_eq!(documents.len(), 1, "entity={entity}");
    assert_ne!(documents[0], legacy_document_wire);

    for command in [
        vec!["get", message_wire.as_str()],
        vec!["show", session_wire.as_str()],
        vec!["list", "10"],
    ] {
        let output = run(&db, &command);
        assert!(
            output.status.success(),
            "{} must remain readable after re-ingest: {}",
            command[0],
            stdout(&output)
        );
    }
}

#[test]
fn get_missing_is_not_found_with_generic_message() {
    let (_dir, db) = temp_db("missing");
    // ADR-0005：合法前缀但从未写入的 id → not_found（exit 4）。消息固定为通用
    // 文案，绝不回显 wire id（R2.1 隐私）；robot envelope 与 human stderr 双验证。
    let missing = "msg_v1_ffffffffffffffffffffffffffffffff";
    let out = run(&db, &["get", missing]);
    assert_eq!(out.status.code(), Some(4), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "not_found");
    assert_eq!(frame["error"]["message"], "entity not found", "{frame}");
    assert!(
        !stdout(&out).contains(missing),
        "envelope 不得回显 wire id: {}",
        stdout(&out)
    );
    let out = run_human(&db, &["get", missing]);
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains(missing),
        "human stderr 不得回显 wire id: {stderr}"
    );
}

#[test]
fn get_malformed_id_is_usage_error() {
    let (_dir, db) = temp_db("malformed");
    // 无已知前缀的串无法反解为实体 id（见 StableId::from_wire）→ 用法错误 exit 2。
    let out = run(&db, &["get", "does-not-exist"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn show_returns_normalized_role_and_text() {
    let (dir, db) = temp_db("show");
    // ingest 写入的 payload 是 `role\ttext`，show 应把它拆成结构化 entity。
    let fixture = dir.path().join("show.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"how do I show an entity"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    // 从 search 输出取真实 wire id。
    let out = run(&db, &["search", "entity"]);
    let s = stdout(&out);
    let id = s
        .split("\"id\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("search 输出应含 id 字段");

    let out = run(&db, &["show", id]);
    assert!(out.status.success(), "show failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "show");
    // show 与 get 的区别：结构化 role/text，而非裸 payload 串。
    assert_eq!(
        frame["data"]["entity"]["role"],
        "user",
        "show={}",
        stdout(&out)
    );
    assert_eq!(
        frame["data"]["entity"]["text"],
        "how do I show an entity",
        "show={}",
        stdout(&out)
    );
}

#[test]
fn show_missing_is_not_found_with_generic_message() {
    let (_dir, db) = temp_db("show-missing");
    // ADR-0005：show 缺失实体与 get 同一契约——exit 4 + not_found + 通用消息，
    // 不回显 wire id（R2.1）。
    let missing = "msg_v1_ffffffffffffffffffffffffffffffff";
    let out = run(&db, &["show", missing]);
    assert_eq!(out.status.code(), Some(4), "show={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "not_found", "{frame}");
    assert_eq!(frame["error"]["message"], "entity not found", "{frame}");
    assert!(
        !stdout(&out).contains(missing),
        "envelope 不得回显 wire id: {}",
        stdout(&out)
    );
    let out = run_human(&db, &["show", missing]);
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains(missing),
        "human stderr 不得回显 wire id: {stderr}"
    );
}

#[test]
fn show_malformed_id_is_usage_error() {
    let (_dir, db) = temp_db("show-malformed");
    let out = run(&db, &["show", "does-not-exist"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn ingest_preserves_native_uuid_identity_and_threading() {
    let (dir, db) = temp_db("native-threading");
    // 带真实 uuid/parentUuid 的两条记录：identity 应采用 native uuid（原样透传，
    // 非 path+seq 派生），threading 边经存储穿到 show。
    let fixture = dir.path().join("threaded.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","uuid":"11111111-1111-4111-8111-111111111111","parentUuid":null,"timestamp":"2026-06-27T13:57:42.685Z","message":{"role":"user","content":"root message about widgets"}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"22222222-2222-4222-8222-222222222222","parentUuid":"11111111-1111-4111-8111-111111111111","message":{"role":"assistant","content":"child reply about widgets"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    // identity 采用 native uuid：wire id 应内含原始 uuid，而非 path+seq 派生的 hex。
    let child_id = "msg_v1_22222222-2222-4222-8222-222222222222";
    let out = run(&db, &["show", child_id]);
    assert!(out.status.success(), "show failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    let entity = &frame["data"]["entity"];
    assert_eq!(entity["role"], "assistant", "show={}", stdout(&out));
    assert_eq!(entity["text"], "child reply about widgets");
    // threading 边穿过存储：子消息的 parent 指向根消息的 native uuid。
    assert_eq!(
        entity["parent_native_id"],
        "11111111-1111-4111-8111-111111111111",
        "show={}",
        stdout(&out)
    );

    // 根消息 parent 为 null，timestamp 原样保留。
    let out = run(
        &db,
        &["show", "msg_v1_11111111-1111-4111-8111-111111111111"],
    );
    let frame = parse_first_line(&out);
    let entity = &frame["data"]["entity"];
    assert!(
        entity["parent_native_id"].is_null(),
        "root parent must be null"
    );
    assert_eq!(entity["timestamp"], "2026-06-27T13:57:42.685Z");
}

#[test]
fn ingest_persists_session_and_document_entities_with_spans() {
    let (dir, db) = temp_db("canonical-entities");
    // 覆盖 canonical foundation 验收：消息 → 会话 → 文档 交叉引用 + evidence span。
    let line_root = r#"{"type":"user","uuid":"33333333-3333-4333-8333-333333333333","sessionId":"abcd1234-5678-4abc-8def-aabbccddeeff","message":{"role":"user","content":"trace the span origin"}}"#;
    let line_reply = r#"{"type":"assistant","uuid":"44444444-4444-4444-8444-444444444444","sessionId":"abcd1234-5678-4abc-8def-aabbccddeeff","message":{"role":"assistant","content":"span recorded faithfully"}}"#;
    let fixture = dir.path().join("spans.jsonl");
    let content = format!("{line_root}\n{line_reply}\n");
    std::fs::write(&fixture, &content).expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    // 消息实体：session 引用 native 会话 id、span 指回源行字节区间。
    let out = run(
        &db,
        &["show", "msg_v1_33333333-3333-4333-8333-333333333333"],
    );
    assert!(out.status.success(), "show failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let entity = &frame["data"]["entity"];
    let session_wire = session_wire_for_message(&db, "msg_v1_33333333-3333-4333-8333-333333333333");
    assert_eq!(
        entity["session"],
        session_wire.as_str(),
        "消息应引用 canonical 会话 id: {}",
        stdout(&out)
    );
    // span round-trip：按 show 返回的区间切源文件字节 == 原始行。
    let start = entity["span"]["start"].as_u64().expect("span.start") as usize;
    let end = entity["span"]["end"].as_u64().expect("span.end") as usize;
    assert_eq!(
        &content.as_bytes()[start..end],
        line_root.as_bytes(),
        "span 应精确指回第一条源记录"
    );

    // 会话实体：引用文档 + 按序成员消息。
    let out = run(&db, &["show", &session_wire]);
    assert!(
        out.status.success(),
        "show session failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    let entity = &frame["data"]["entity"];
    let document_wire = entity["document"].as_str().expect("session.document");
    assert!(
        document_wire.starts_with("doc_v1_"),
        "会话应引用文档实体: {}",
        stdout(&out)
    );
    let members = entity["messages"].as_array().expect("session.messages");
    assert_eq!(members.len(), 2);
    assert_eq!(
        members[0], "msg_v1_33333333-3333-4333-8333-333333333333",
        "成员按 seq 排序"
    );

    // 文档实体：provider/variant/fingerprint/len 与 ingest 报告一致。
    let out = run(&db, &["show", document_wire]);
    assert!(
        out.status.success(),
        "show document failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    let entity = &frame["data"]["entity"];
    assert_eq!(entity["provider"], "claude-code");
    assert_eq!(entity["variant"], "claude-code/jsonl-v1");
    assert_eq!(entity["len"].as_u64(), Some(content.len() as u64));
    assert!(
        entity["fingerprint"]
            .as_str()
            .is_some_and(|f| !f.is_empty()),
        "文档应携带快照指纹: {}",
        stdout(&out)
    );

    // 容器实体不参与全文搜索：搜索只命中消息。命中携带的 session_id 是追加的
    // 归属字段（ADR-0008），断言必须检查 hit 的 id——原始输出字符串会被
    // session_id 字段值误伤。
    let out = run(&db, &["search", "span"]);
    let frame = parse_first_line(&out);
    let hits = frame["data"]["hits"].as_array().expect("hits");
    assert!(!hits.is_empty(), "消息应命中: {frame}");
    for hit in hits {
        assert!(
            hit["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("msg_v1_")),
            "容器实体不应命中搜索: {hit}"
        );
    }
}

#[test]
fn ingest_auto_selects_codex_and_ignores_event_mirror() {
    let (dir, db) = temp_db("codex");
    // 合成的 Codex rollout（非真实 transcript，遵守 R0 脱敏规范）：
    // 每条对话消息出现两次——权威 response_item/message（带 native id）与
    // event_msg UI 镜像（无 id）。adapter 只取前者，committed 应为 2 而非 4。
    let fixture = dir.path().join("rollout.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"timestamp":"2026-07-19T15:40:00.000Z","type":"session_meta","payload":{"session_id":"aaaa1111-2222-7333-8444-555566667777","cwd":"/tmp","originator":"codex","cli_version":"1.0"}}"#,
            "\n",
            r#"{"timestamp":"2026-07-19T15:41:00.000Z","type":"response_item","payload":{"type":"message","id":"msg_codex_root","role":"user","content":[{"type":"input_text","text":"how do I configure the pipeline"}]}}"#,
            "\n",
            r#"{"timestamp":"2026-07-19T15:41:00.500Z","type":"event_msg","payload":{"type":"user_message","message":"how do I configure the pipeline"}}"#,
            "\n",
            r#"{"timestamp":"2026-07-19T15:41:19.000Z","type":"response_item","payload":{"type":"message","id":"msg_codex_reply","role":"assistant","content":[{"type":"output_text","text":"set the pipeline stages first"}]}}"#,
            "\n",
            r#"{"timestamp":"2026-07-19T15:41:19.500Z","type":"event_msg","payload":{"type":"agent_message","message":"set the pipeline stages first"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();

    // registry 自动 probe-select：无需指定 provider，应判定为 codex variant。
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(
        frame["data"]["variant"],
        "codex/rollout-jsonl-v1",
        "registry 应自动选中 codex: {}",
        stdout(&out)
    );
    // 关键去重断言：2 条权威消息，event_msg 镜像不计入。
    assert_eq!(
        frame["data"]["committed"],
        2,
        "event_msg 镜像应被忽略，只提交 2 条: {}",
        stdout(&out)
    );

    // native id 原样保留，show 展开 role/text。
    let out = run(&db, &["show", "msg_v1_msg_codex_reply"]);
    assert!(out.status.success(), "show failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let entity = &frame["data"]["entity"];
    assert_eq!(entity["role"], "assistant", "show={}", stdout(&out));
    assert_eq!(entity["text"], "set the pipeline stages first");

    // 内容可检索。
    let out = run(&db, &["search", "pipeline"]);
    assert!(
        stdout(&out).contains("msg_v1_msg_codex"),
        "codex 内容应可检索: {}",
        stdout(&out)
    );
}

#[test]
fn index_rebuild_reprojects_and_keeps_search_working() {
    let (dir, db) = temp_db("rebuild");
    let fixture = dir.path().join("rebuild.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"rebuild the search index please"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"reprojecting from catalog now"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    // rebuild：从权威 catalog 全量重投影 FTS 索引，推进 generation。
    // catalog 含 2 条消息 + 1 会话 + 1 文档目录行；rebuild 重投影全部 4 个实体
    // （容器实体只重建身份边车，不进全文表）。
    let out = run(&db, &["index", "rebuild"]);
    assert!(out.status.success(), "rebuild failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "index.rebuild");
    assert_eq!(
        frame["data"]["reindexed"],
        4,
        "应重投影 4 个实体（2 消息 + 会话 + 文档）: {}",
        stdout(&out)
    );
    // generation：ingest 推进到 1，rebuild 再推进到 2。
    assert_eq!(frame["data"]["generation"], 2, "rebuild={}", stdout(&out));

    // 重建后搜索仍命中原内容，且身份保真（wire id 前缀不变）。
    let out = run(&db, &["search", "reprojecting"]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("msg_v1_"),
        "rebuild 后搜索仍应命中: {}",
        stdout(&out)
    );
}

#[test]
fn index_rebuild_on_empty_db_succeeds() {
    let (_dir, db) = temp_db("rebuild-empty");
    let out = run(&db, &["index", "rebuild"]);
    assert!(
        out.status.success(),
        "empty rebuild failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["reindexed"], 0);
}

#[test]
fn missing_subcommand_is_usage_error() {
    let (_dir, db) = temp_db("usage");
    let out = run(&db, &[]);
    // 用法错误映射为 exit code 2（见 main.rs 的 CliError::Usage）。
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_subcommand_is_usage_error() {
    let (_dir, db) = temp_db("unknown");
    let out = run(&db, &["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
}

// ─── 参数校验（Minor-2 / Minor-3）───────────────────────────────────────────

#[test]
fn search_flag_named_query_is_searched_not_intercepted() {
    // Minor-2：query 恰等于 flag 名（--output/--robot/--help/--request-id）时按
    // 查询走，不得被输出模式解析、help/version 拦截或 request-id 抽取短路。
    let (_dir, db) = temp_db("flag-query");
    let out = run(
        &db,
        &[
            "index",
            "f1",
            "literal --output --robot --help --request-id flag text",
        ],
    );
    assert!(out.status.success(), "index failed: {}", stdout(&out));

    // 正常检索 sanity：分词后的词元仍可命中（内容确实入库）。
    let out = run(&db, &["search", "output"]);
    assert!(
        out.status.success(),
        "search output failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert!(!frame["data"]["hits"].as_array().expect("hits").is_empty());

    // `--output` 在命令名之后是查询文本：参数解析放行给 search 引擎。
    // 引擎层对带连字符的查询做字面量转义（10 角色体验测试缺陷修复——原来
    // "--output" 触发 FTS 语法错误，新手搜含冒号/点号/连字符的文本直接报错）。
    // 若被误判为输出模式，这里会是 exit 2 的 "--output requires human|json|jsonl"。
    let out = run(&db, &["search", "--output"]);
    assert_eq!(out.status.code(), Some(0), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "search");

    // --robot 在命令名之前仍是合法输出模式 flag；query "--robot" 同样放行给检索层。
    let out = run(&db, &["search", "--robot"]);
    assert_eq!(out.status.code(), Some(0), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "search");

    // --help 紧跟命令名：渲染该子命令的用法（10 角色体验测试缺陷修复——
    // 原来 `search --help` 把 "--help" 当查询喂给 FTS5 报 catalog_error，新手
    // 无法查单个命令怎么用）。`search foo --help` 里的 --help 仍是查询文本。
    let out = run_human(&db, &["search", "--help"]);
    assert_eq!(out.status.code(), Some(0), "stdout={}", stdout(&out));
    assert!(
        stdout(&out).contains("search <query>"),
        "应渲染 search 子命令帮助: {}",
        stdout(&out)
    );
    // 查询文本含 --help 但不在命令名紧跟位：--help 落在查询文本之后成为多余
    // 位置参数 → usage error（exit 2，human stderr 诊断，stdout 保持协议干净），
    // 不渲染帮助文本（帮助旗标只在命令名紧跟位识别，R3.1/R8.3）。
    let out = run_human(&db, &["search", "foo", "--help"]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    assert!(
        stdout(&out).is_empty(),
        "human 模式 stdout 不得出现帮助文本: {}",
        stdout(&out)
    );

    // --request-id 在命令名之后同样是查询文本，不被 request-id 抽取误判。
    let out = run_human(&db, &["search", "--request-id"]);
    assert_eq!(out.status.code(), Some(0), "stdout={}", stdout(&out));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("--request-id requires"),
        "search --request-id 不应被 request-id 抽取误判: {stderr}"
    );
}

#[test]
fn extra_positional_arguments_are_rejected_with_exit_2() {
    // Minor-3：多余位置参数是用法错误（exit 2），不静默忽略。
    let (dir, db) = temp_db("extra-args");
    let fixture = dir.path().join("extra.jsonl");
    std::fs::write(&fixture, b"").expect("write empty fixture");
    let path = fixture.to_string_lossy().into_owned();

    for (args, usage) in [
        (vec!["doctor", "bogus"], "doctor"),
        (vec!["config", "paths", "extra"], "config paths"),
        (vec!["status", "extra"], "status"),
        (vec!["get", "msg_v1_x", "extra"], "get"),
        (vec!["show", "msg_v1_x", "extra"], "show"),
        (vec!["index", "f", "text", "extra"], "index"),
        (vec!["index", "rebuild", "extra"], "index rebuild"),
        (vec!["ingest", &path, "extra"], "ingest"),
        (vec!["search", "q", "extra"], "search"),
        (vec!["list", "5", "extra"], "list"),
        (vec!["context", "ses_v1_x", "extra"], "context"),
        (vec!["mcp", "extra"], "mcp"),
    ] {
        let out = run(&db, &args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{usage}: stdout={}",
            stdout(&out)
        );
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, false);
        assert_eq!(frame["error"]["code"], "invalid_request", "{usage}");
        assert_eq!(frame["command"], args[0], "{usage}");
    }
}

// ─── EPIPE 契约（Major-1）───────────────────────────────────────────────────

#[test]
fn help_and_version_pipe_closed_early_exit_zero_without_panic() {
    // CONTRACT §6：下游提前关闭管道（head/pager）时 --help/--version 必须
    // 静默 exit 0，不得 panic（exit 101）或污染 stderr。
    use std::process::Stdio;
    for args in [&["--help"][..], &["--version"][..]] {
        let mut child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        // 立即关闭读端：子进程写 stdout 时管道已断 → EPIPE。
        drop(child.stdout.take());
        let out = child.wait_with_output().expect("wait");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} must exit 0 on EPIPE, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            !stderr.contains("panic"),
            "{args:?} must not panic on EPIPE: {stderr}"
        );
    }
}

// ─── 错误 exit code 目录（E1）───────────────────────────────────────────────

#[test]
fn ingest_missing_file_is_source_io_exit_5() {
    let (dir, db) = temp_db("exit-5");
    let missing = dir.path().join("does-not-exist.jsonl");
    let missing_path = missing.to_string_lossy().into_owned();
    let out = run(&db, &["ingest", &missing_path]);
    assert_eq!(out.status.code(), Some(5), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "source_io");
    assert_eq!(frame["error"]["retryable"], false);
}

#[test]
fn unrecognized_source_content_is_invalid_request_exit_2() {
    // 非法内容源：无 provider 认领 → invalid_request（exit 2）。
    // （task 原话：确认 2/7 之一；当前映射为 2。）
    let (dir, db) = temp_db("exit-provider");
    let garbage = dir.path().join("garbage.jsonl");
    std::fs::write(&garbage, "this is not any known transcript format\n").expect("write garbage");
    let garbage_path = garbage.to_string_lossy().into_owned();
    let out = run(&db, &["ingest", &garbage_path]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "invalid_request");
    assert!(
        frame["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no provider")),
        "message 应指出无 provider 认领: {frame}"
    );
}

#[test]
fn writer_busy_exits_6_with_retryable_flag() {
    // 持有 data-root writer lease 时写子命令 → writer_busy（exit 6，可重试）。
    // data root 是 db 文件所在目录（SqliteStore::open_for_write 的 lease 语义）。
    let (dir, db) = temp_db("exit-6");
    let lease = agent_session_grep_adapters_sqlite::WriterLease::try_acquire(dir.path())
        .expect("test process acquires the writer lease");
    let out = run(&db, &["index", "w1", "writer busy probe"]);
    assert_eq!(out.status.code(), Some(6), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "writer_busy");
    assert_eq!(frame["error"]["retryable"], true);
    drop(lease);
    // 释放后写入恢复。
    let out = run(&db, &["index", "w1", "writer busy probe"]);
    assert!(
        out.status.success(),
        "write must succeed after lease release: {}",
        stdout(&out)
    );
}

#[test]
fn error_outputs_never_disclose_source_path_or_content() {
    // 隐私回归守卫：错误场景的 stderr（human 诊断）与 envelope 都不得泄露
    // 源路径或正文片段（E2）。
    let (dir, db) = temp_db("error-privacy");
    let missing = dir.path().join("secret-path-transcript.jsonl");
    let missing_path = missing.to_string_lossy().into_owned();

    // robot 模式：错误只走 stdout envelope；stderr 必须为空。
    let out = run(&db, &["ingest", &missing_path]);
    assert_eq!(out.status.code(), Some(5), "stdout={}", stdout(&out));
    assert!(
        out.stderr.is_empty(),
        "robot mode stderr must stay empty: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout(&out).contains(&missing_path),
        "envelope 不得泄露源路径: {}",
        stdout(&out)
    );

    // human 模式：stderr 诊断不得含源路径。
    let out = run_human(&db, &["ingest", &missing_path]);
    assert_eq!(out.status.code(), Some(5));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("error [source_io]"), "stderr={stderr}");
    assert!(
        !stderr.contains(&missing_path),
        "stderr 泄露源路径: {stderr}"
    );

    // 非法内容源：正文片段不进入 stderr。
    let garbage = dir.path().join("garbage.jsonl");
    std::fs::write(&garbage, "top-secret-transcript-body\n").expect("write garbage fixture");
    let garbage_path = garbage.to_string_lossy().into_owned();
    let out = run_human(&db, &["ingest", &garbage_path]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains(&garbage_path),
        "stderr 泄露源路径: {stderr}"
    );
    assert!(
        !stderr.contains("top-secret-transcript-body"),
        "stderr 泄露源正文: {stderr}"
    );
}

#[test]
fn version_flag_prints_version_without_db() {
    // --version 不需要 --db：在 parse_db_flag 之前拦截。
    let out = run_bare(&["--version"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("0.1.0"));
}

#[test]
fn help_flag_lists_commands_without_db() {
    let out = run_bare(&["--help"]);
    assert!(out.status.success());
    let s = stdout(&out);
    // 帮助里应列出核心子命令，便于发现。
    assert!(s.contains("ingest"), "help 应列出 ingest: {s}");
    assert!(s.contains("search"), "help 应列出 search: {s}");
}

#[test]
fn machine_mode_help_emits_single_success_envelope() {
    // ADR-0006（R3.2）：--robot / --output json / --output jsonl 的 --help 都是
    // exit 0 的 success envelope，帮助文本在 data.help_text；jsonl 恰为一帧；
    // --request-id 原样回显。
    for (mode_args, command) in [
        (vec!["--robot"], "help"),
        (vec!["--output", "json"], "help"),
        (vec!["--output", "jsonl"], "help"),
    ] {
        let mut args = vec!["--request-id", "help.req-1"];
        args.extend(mode_args.iter().copied());
        args.push("--help");
        let out = run_bare(&args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{mode_args:?}: {}",
            stdout(&out)
        );
        let text = stdout(&out);
        assert_eq!(
            text.lines().count(),
            1,
            "{mode_args:?} 的 --help 应恰好一帧: {text}"
        );
        let frame: serde_json::Value = serde_json::from_str(text.lines().next().unwrap())
            .expect("help envelope must be valid JSON");
        assert_envelope_shape(&frame, true);
        assert_eq!(frame["command"], command, "{mode_args:?}: {frame}");
        assert_eq!(frame["request_id"], "help.req-1", "{frame}");
        assert!(
            frame["data"]["help_text"]
                .as_str()
                .is_some_and(|help| help.contains("COMMANDS")),
            "data.help_text 应携带帮助文本: {frame}"
        );
    }
}

#[test]
fn machine_mode_version_emits_single_success_envelope() {
    // ADR-0006（R3.2）：--robot --version 是 success envelope，版本串在
    // data.version；request-id 回显。
    let out = run_bare(&["--robot", "--request-id", "ver.42", "--version"]);
    assert_eq!(out.status.code(), Some(0), "stdout={}", stdout(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "一帧: {text}");
    let frame: serde_json::Value =
        serde_json::from_str(text.lines().next().unwrap()).expect("valid JSON");
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "version");
    assert_eq!(frame["request_id"], "ver.42");
    assert!(
        frame["data"]["version"]
            .as_str()
            .is_some_and(|version| version.contains("agent-session-grep")),
        "data.version 应携带版本串: {frame}"
    );
}

#[test]
fn level_value_before_robot_flag_still_emits_robot_error_envelope() {
    let out = run_bare(&["--level", "talks", "--robot", "context", "not-a-session-id"]);
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "invalid_request", "{frame}");
    assert!(
        out.stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn machine_mode_subcommand_help_echoes_request_id() {
    // `<cmd> --help` 在机器模式下同样走单帧 success envelope（R3.2），
    // `command` 是子命令名。
    let out = run_bare(&[
        "--output",
        "jsonl",
        "--request-id",
        "sh.7",
        "search",
        "--help",
    ]);
    assert_eq!(out.status.code(), Some(0), "stdout={}", stdout(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "jsonl 单帧: {text}");
    let frame: serde_json::Value =
        serde_json::from_str(text.lines().next().unwrap()).expect("valid JSON");
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "search");
    assert_eq!(frame["request_id"], "sh.7");
    assert!(
        frame["data"]["help_text"]
            .as_str()
            .is_some_and(|help| help.contains("search <query>")),
        "子命令帮助应在 data.help_text: {frame}"
    );
}

#[test]
fn help_and_version_require_no_db_and_create_no_file() {
    // R3.1：help/version 在 --db 解析与存储打开之前拦截——全新库路径上跑
    // 顶层与子命令 help、version 都不得创建 db 文件。
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("must-not-exist.db");
    let db_s = db.to_string_lossy().into_owned();
    let cases: Vec<Vec<&str>> = vec![
        vec!["--db", &db_s, "--robot", "--help"],
        vec!["--db", &db_s, "--robot", "--version"],
        vec!["--db", &db_s, "--robot", "search", "--help"],
        vec!["--db", &db_s, "--robot", "index", "rebuild", "--help"],
        vec!["--db", &db_s, "doctor", "--help"],
    ];
    for args in cases {
        let out = run_bare(&args);
        assert!(out.status.success(), "{args:?}: {}", stdout(&out));
        assert!(
            !db.exists(),
            "{args:?} 不得创建 db 文件: {}",
            dir.path().display()
        );
    }
}

#[test]
fn doctor_reports_ok_without_db() {
    let out = run_bare(&["--robot", "doctor"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("\"ok\":true"), "doctor 应报告 ok:true: {s}");
    assert!(
        s.contains("\"db\":\"not-checked\""),
        "无 --db 时应标记未校验: {s}"
    );
}

#[test]
fn doctor_with_db_reports_generation_and_recovery_evidence() {
    let (_dir, db) = temp_db("doctor-db");
    // 写一条推进 generation 到 1。
    let out = run(&db, &["index", "d1", "doctor evidence content"]);
    assert!(out.status.success());

    // `run` 已在前缀位置给出 --db；doctor 的 --db 跟在命令名后会造成重复
    // --db（R8.2 用法错误），故只传子命令本身。
    let out = run(&db, &["doctor"]);
    assert!(out.status.success(), "doctor failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["db"], "ok");
    // 一致性/恢复证据：活动 generation + 待收敛 intent 数（干净库应为 0）。
    assert_eq!(frame["data"]["generation"], 1, "doctor={}", stdout(&out));
    assert_eq!(
        frame["data"]["interrupted_batches"],
        0,
        "干净库不应有待收敛 intent: {}",
        stdout(&out)
    );
    // 工具活动保留策略证据：干净库无孤儿投影行。
    assert_eq!(
        frame["data"]["orphaned_tool_activities"],
        0,
        "干净库不应有孤儿活动行: {}",
        stdout(&out)
    );
    assert_eq!(
        frame["data"]["orphaned_activity_memberships"],
        0,
        "干净库不应有孤儿成员行: {}",
        stdout(&out)
    );
}

#[test]
fn doctor_reports_orphaned_tool_activities_and_purge_removes_them() {
    // 工具活动保留策略端到端：doctor 报出孤儿投影行（活动锚点悬空 / claim
    // 悬空），`index purge-activities` 确定性修剪且不触碰 catalog/FTS。
    let (_dir, db) = temp_db("purge-activities");
    let out = run(&db, &["index", "d1", "purge evidence content"]);
    assert!(out.status.success());

    // 写路径同事务保证无法产生孤儿行：直接 SQL 构造漂移状态（模拟
    // 裸批/历史遗留），然后闭合 db。
    {
        let conn = Connection::open(&db).expect("open db for orphan fixture");
        conn.execute(
            "INSERT INTO tool_activities(
                 activity_id, message_id, kind, actor, name, target, status
             ) VALUES('act_v1_orphan', 'msg_v1_deadbeefdeadbeef',
                      'command', 'main', 'Ghost', NULL, 'success')",
            [],
        )
        .expect("insert orphan activity");
        conn.execute(
            "INSERT INTO tool_activity_membership(source_path, activity_id)
             VALUES('ghost.jsonl', 'act_v1_ghostclaim')",
            [],
        )
        .expect("insert orphan membership");
    }

    // doctor 如实报出两类孤儿行。
    let out = run(&db, &["doctor"]);
    assert!(out.status.success(), "doctor failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["orphaned_tool_activities"], 1, "{frame}");
    assert_eq!(frame["data"]["orphaned_activity_memberships"], 1, "{frame}");

    // 修剪：删除两类孤儿行各 1，generation 恰好推进一次。
    let out = run(&db, &["index", "purge-activities"]);
    assert!(out.status.success(), "purge failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["removed_activities"], 1, "{frame}");
    assert_eq!(frame["data"]["removed_memberships"], 1, "{frame}");
    assert_eq!(frame["data"]["generation"], 2, "{frame}");

    // 修剪后 doctor 归零；catalog/FTS 原样（搜索仍命中同一内容）。
    let out = run(&db, &["doctor"]);
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["orphaned_tool_activities"], 0, "{frame}");
    assert_eq!(frame["data"]["orphaned_activity_memberships"], 0, "{frame}");
    let out = run(&db, &["search", "evidence"]);
    assert!(out.status.success(), "search failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_eq!(
        frame["data"]["hits"].as_array().map(Vec::len),
        Some(1),
        "{frame}"
    );

    // 幂等收敛：无孤儿时空跑不推进 generation（无 journal churn）。
    let out = run(&db, &["index", "purge-activities"]);
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["removed_activities"], 0, "{frame}");
    assert_eq!(frame["data"]["removed_memberships"], 0, "{frame}");
    assert_eq!(frame["data"]["generation"], 2, "{frame}");
}

#[test]
fn ingest_search_get_roundtrip_via_binary() {
    let (dir, db) = temp_db("ingest");
    // 合成的 Claude Code 风格 .jsonl fixture（按 R0 脱敏规范，非真实 transcript）。
    let fixture = dir.path().join("session.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"how do I configure the neural net"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"set the learning rate first"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();

    // ingest：probe 判定 variant + parse 流式入库。
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let s = stdout(&out);
    assert!(s.contains("claude-code/jsonl-v1"), "应判定出 variant: {s}");
    assert!(s.contains("\"committed\":2"), "应入库 2 条消息: {s}");

    // search：ingest 的内容可被检索到。
    let out = run(&db, &["search", "neural"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("msg_v1_"), "search 应命中 ingest 的消息: {s}");

    // 从 search 输出提取真实 wire id，拿去 get 应取回原文（往返闭合）。
    let id = s
        .split("\"id\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("search 输出应含 id 字段");
    let out = run(&db, &["get", id]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("neural"),
        "get 应取回含 neural 的 payload: {}",
        stdout(&out)
    );
}

#[test]
fn list_and_status_report_catalog_contents() {
    let (_dir, db) = temp_db("list-status");
    let out = run(&db, &["index", "a", "alpha payload"]);
    assert!(out.status.success());
    let out = run(&db, &["index", "b", "beta payload"]);
    assert!(out.status.success());

    let out = run(&db, &["status"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("\"catalog_count\":2"), "status={s}");

    let out = run(&db, &["list", "1"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert_eq!(
        s.lines().count(),
        1,
        "list limit should return one row: {s}"
    );
    assert!(s.contains("\"id\":\"msg_v1_"), "list={s}");
}

fn codex_incremental_fixture(session_id: &str, messages: &[(&str, &str, &str)]) -> String {
    let mut lines = vec![
        serde_json::json!({
            "timestamp": "2026-08-15T03:00:00.000Z",
            "type": "session_meta",
            "payload": {
                "session_id": session_id,
                "cwd": "/workspace/synthetic-codex-fixture",
            },
        })
        .to_string(),
    ];
    for (index, &(id, role, text)) in messages.iter().enumerate() {
        let content_type = if role == "user" {
            "input_text"
        } else {
            "output_text"
        };
        lines.push(
            serde_json::json!({
                "timestamp": format!("2026-08-15T03:00:{:02}.000Z", index + 1),
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": id,
                    "role": role,
                    "content": [{"type": content_type, "text": text}],
                },
            })
            .to_string(),
        );
    }
    format!("{}\n", lines.join("\n"))
}

#[test]
fn sync_commits_then_reports_unchanged_on_resync() {
    let (dir, db) = temp_db("sync");
    let fixture = dir.path().join("s1.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"how do I tune the index"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"raise the batch size"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    // 首次 sync：两条消息提交，generation 从 0 推进到 1。
    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let s = stdout(&out);
    assert!(s.contains("\"messages\":2"), "sync={s}");
    assert!(s.contains("\"committed\":2"), "sync={s}");
    assert!(s.contains("\"generation\":1"), "sync={s}");

    // 内容可检索。
    let out = run(&db, &["search", "tune"]);
    assert!(stdout(&out).contains("msg_v1_"), "search={}", stdout(&out));

    // 重复 sync 未改变的源：no-op，generation 不推进。
    let out = run(&db, &["sync", &path]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("\"committed\":0"), "resync={s}");
    assert!(s.contains("\"unchanged\":2"), "resync={s}");
    assert!(
        s.contains("\"generation\":1"),
        "resync 不应推进 generation: {s}"
    );
}

#[test]
fn sync_commits_then_reports_unchanged_on_resync_codex() {
    let (dir, db) = temp_db("sync-codex");
    let fixture = dir.path().join("rollout-idempotent.jsonl");
    std::fs::write(
        &fixture,
        codex_incremental_fixture(
            "synthetic-codex-idempotent-session",
            &[
                (
                    "codex_idempotent_root",
                    "user",
                    "verify the codex idempotent marker",
                ),
                (
                    "codex_idempotent_reply",
                    "assistant",
                    "the codex resync is unchanged",
                ),
            ],
        ),
    )
    .expect("write codex fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let first = parse_first_line(&out);
    assert_eq!(first["data"]["messages"], 2, "{first}");
    assert_eq!(first["data"]["committed"], 2, "{first}");
    assert_eq!(first["data"]["unchanged"], 0, "{first}");
    assert_eq!(first["data"]["skipped"], 0, "{first}");
    assert_eq!(first["data"]["generation"], 1, "{first}");

    let out = run(&db, &["search", "idempotent"]);
    assert!(
        stdout(&out).contains("msg_v1_codex_idempotent_root"),
        "codex message should be searchable: {}",
        stdout(&out)
    );

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "resync failed: {}", stdout(&out));
    let second = parse_first_line(&out);
    assert_eq!(second["data"]["messages"], 0, "{second}");
    assert_eq!(second["data"]["committed"], 0, "{second}");
    assert_eq!(second["data"]["unchanged"], 2, "{second}");
    assert_eq!(second["data"]["skipped"], 0, "{second}");
    assert_eq!(
        second["data"]["generation"], first["data"]["generation"],
        "unchanged codex resync must not advance generation: {second}"
    );
}

#[test]
fn search_by_provider_session_id_returns_session() {
    // PRD R1（session metadata search）：resolved Provider-native Session ID
    // 可检索——元数据命中以首个非系统用户消息为代表，携带 canonical session_id。
    let (dir, db) = temp_db("metadata-native-id");
    let fixture = dir.path().join("rollout-metadata-native.jsonl");
    std::fs::write(
        &fixture,
        codex_incremental_fixture(
            "native-metadata-session-id",
            &[(
                "metadata_user_message",
                "user",
                "metadata body user request",
            )],
        ),
    )
    .expect("write codex fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));

    let out = run(&db, &["search", "native-metadata-session-id"]);
    assert!(out.status.success(), "search failed: {}", stdout(&out));
    let s = stdout(&out);
    assert!(
        s.contains("msg_v1_"),
        "native id search should return a representative message hit: {s}"
    );
    assert!(
        s.contains("ses_v1_"),
        "native id hit should carry the canonical session_id: {s}"
    );
}

#[test]
fn search_by_working_directory_returns_session() {
    // PRD R1：pair-observed Original Working Directory 可检索；source path
    // 片段不可检索（R2 源路径安全）。
    let (dir, db) = temp_db("metadata-cwd");
    let fixture = dir.path().join("rollout-metadata-cwd.jsonl");
    std::fs::write(
        &fixture,
        codex_incremental_fixture(
            "cwd-metadata-session",
            &[("cwd_user_message", "user", "cwd metadata body")],
        ),
    )
    .expect("write codex fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));

    let out = run(&db, &["search", "synthetic-codex-fixture"]);
    assert!(out.status.success(), "search failed: {}", stdout(&out));
    assert!(
        stdout(&out).contains("msg_v1_"),
        "pair-observed cwd should be searchable: {}",
        stdout(&out)
    );

    let source_name = Path::new(&path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let out = run(&db, &["search", &source_name]);
    assert!(out.status.success(), "search failed: {}", stdout(&out));
    assert!(
        !stdout(&out).contains("msg_v1_"),
        "source path must never be searchable: {}",
        stdout(&out)
    );
}

#[test]
fn sync_requires_at_least_one_file() {
    let (_dir, db) = temp_db("sync-empty");
    let out = run(&db, &["sync"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn sync_deduplicates_duplicate_paths_in_one_invocation() {
    // Minor-5：`sync a a` 是书写冗余而非两个源——CLI 层提前去重（exit 0），
    // 不落成 store 层的 catalog_error（exit 6）。
    let (dir, db) = temp_db("sync-dup");
    let fixture = dir.path().join("dup.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"dedupe me once"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path, &path]);
    assert!(out.status.success(), "sync dup failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["sources"], 1, "frame={frame}");
    assert_eq!(frame["data"]["messages"], 1, "frame={frame}");
    assert_eq!(frame["data"]["committed"], 1, "frame={frame}");

    // 1 条消息 + 会话 + 文档目录行 = 3 个实体，消息可检索。
    let out = run(&db, &["status"]);
    assert!(
        stdout(&out).contains("\"catalog_count\":3"),
        "{}",
        stdout(&out)
    );
    let out = run(&db, &["search", "dedupe"]);
    assert!(stdout(&out).contains("msg_v1_"), "search={}", stdout(&out));
}

#[test]
fn sync_all_or_nothing_on_bad_source() {
    let (dir, db) = temp_db("sync-atomic");
    let good = dir.path().join("good.jsonl");
    std::fs::write(
        &good,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"valid line"}}"#,
            "\n",
        ),
    )
    .expect("write good fixture");
    let good_path = good.to_string_lossy().into_owned();
    // 不存在的第二个源：整批 sync 必须失败且不写入任何数据。
    let missing = dir.path().join("missing.jsonl");
    let missing_path = missing.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &good_path, &missing_path]);
    assert!(
        !out.status.success(),
        "sync 应因缺失源失败: {}",
        stdout(&out)
    );

    // 第一个源的消息不能被部分写入。
    let out = run(&db, &["status"]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("\"catalog_count\":0"),
        "失败的 sync 不应留下部分数据: {}",
        stdout(&out)
    );
}

#[test]
fn sync_tombstones_message_removed_from_source() {
    let (dir, db) = temp_db("sync-shrink");
    let fixture = dir.path().join("shrink.jsonl");
    // 首次：两条消息。
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"keep this message"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"drop this later"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let out = run(&db, &["status"]);
    // 2 条消息 + 会话 + 文档目录行 = 4 个 catalog 实体。
    assert!(
        stdout(&out).contains("\"catalog_count\":4"),
        "{}",
        stdout(&out)
    );
    // 第二条消息此刻可检索。
    let out = run(&db, &["search", "drop"]);
    assert!(stdout(&out).contains("msg_v1_"), "search={}", stdout(&out));

    // 源收缩到一条：被移除的消息应被 tombstone，catalog 与搜索都不再有它。
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"keep this message"}}"#,
            "\n",
        ),
    )
    .expect("rewrite fixture");

    let out = run(&db, &["sync", &path]);
    assert!(
        out.status.success(),
        "reshrink sync failed: {}",
        stdout(&out)
    );
    let out = run(&db, &["status"]);
    // 收缩后：1 条消息 + 新会话 + 新文档 = 3。文档 id 内容寻址（fingerprint 变 →
    // id 变），旧会话/文档行随旧 membership 一起 tombstone，不残留孤儿。
    assert!(
        stdout(&out).contains("\"catalog_count\":3"),
        "收缩后应剩 1 消息 + 会话 + 文档: {}",
        stdout(&out)
    );
    let out = run(&db, &["search", "drop"]);
    assert!(
        !stdout(&out).contains("msg_v1_"),
        "被移除消息不应再命中搜索: {}",
        stdout(&out)
    );
    let out = run(&db, &["search", "keep"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "保留消息仍应命中: {}",
        stdout(&out)
    );
}

#[test]
fn sync_tombstones_message_removed_from_source_codex() {
    // 源收缩的 codex 形态证据：删掉尾部 response_item 后重 sync，被移除的权威
    // 消息必须 tombstone（不可检索），仍在的消息不受影响。codex 的 session id
    // 取自 session_meta 的 native id（provider+安装 namespace 派生），因此与
    // claude 形态不同——收缩后会话 id 不变，只有内容寻址的文档 id 随指纹变化。
    let (dir, db) = temp_db("sync-shrink-codex");
    let fixture = dir.path().join("rollout-shrink.jsonl");
    let session = "synthetic-codex-shrink-session";
    std::fs::write(
        &fixture,
        codex_incremental_fixture(
            session,
            &[
                ("codex_shrink_keep", "user", "keep this codex message"),
                ("codex_shrink_drop", "assistant", "drop this codex message"),
            ],
        ),
    )
    .expect("write codex fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let out = run(&db, &["status"]);
    let status = parse_first_line(&out);
    // 2 条消息 + 会话 + 文档目录行 = 4 个 catalog 实体。
    assert_eq!(status["data"]["catalog_count"], 4, "{status}");
    assert_eq!(status["data"]["placements"], 2, "{status}");
    let out = run(&db, &["search", "drop"]);
    assert!(
        stdout(&out).contains("msg_v1_codex_shrink_drop"),
        "search={}",
        stdout(&out)
    );

    // 去掉尾部 response_item：完整扫描（skipped=0 → relation_complete=true），
    // 被移除的消息声明缺席，store 层据此推导 tombstone。
    std::fs::write(
        &fixture,
        codex_incremental_fixture(
            session,
            &[("codex_shrink_keep", "user", "keep this codex message")],
        ),
    )
    .expect("rewrite codex fixture");

    let out = run(&db, &["sync", &path]);
    assert!(
        out.status.success(),
        "reshrink sync failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["messages"], 1, "{frame}");
    assert_eq!(frame["data"]["committed"], 1, "{frame}");
    assert_eq!(
        frame["data"]["skipped"], 0,
        "完整扫描才允许 tombstone: {frame}"
    );

    let out = run(&db, &["search", "drop"]);
    assert!(
        !stdout(&out).contains("msg_v1_"),
        "被移除的 codex 消息不应再命中搜索: {}",
        stdout(&out)
    );
    let out = run(&db, &["search", "keep"]);
    assert!(
        stdout(&out).contains("msg_v1_codex_shrink_keep"),
        "保留的 codex 消息仍应命中: {}",
        stdout(&out)
    );
    let out = run(&db, &["status"]);
    let status = parse_first_line(&out);
    // 收缩后：1 条消息 + 会话 + 新文档 = 3。旧文档随旧 membership 一起 tombstone，
    // 被移除消息的 placement 也随之删除。
    assert_eq!(status["data"]["catalog_count"], 3, "{status}");
    assert_eq!(status["data"]["placements"], 1, "{status}");
}

#[test]
fn sync_empty_source_tombstones_all_messages() {
    // 整源清空：0 字节源必须作为合法空批次提交（tombstone 全部旧消息），
    // 而不是被 provider 拒绝（此前 "no provider recognized" 使整源清空不可达）。
    let (dir, db) = temp_db("sync-empty");
    let fixture = dir.path().join("empty-me.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"will be wiped"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"gone too"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let out = run(&db, &["search", "wiped"]);
    assert!(stdout(&out).contains("msg_v1_"), "search={}", stdout(&out));

    // 清空文件后 sync：空源是合法空批次，旧消息全部 tombstone。
    std::fs::write(&fixture, b"").expect("truncate fixture");
    let out = run(&db, &["sync", &path]);
    assert!(
        out.status.success(),
        "empty-source sync must succeed: {}",
        stdout(&out)
    );
    let out = run(&db, &["search", "wiped"]);
    assert!(
        !stdout(&out).contains("msg_v1_"),
        "整源清空后消息不应再命中: {}",
        stdout(&out)
    );
    let out = run(&db, &["status"]);
    // 空源仍派生会话+文档目录实体（内容寻址），但消息全部 tombstone：
    // placements 归零即证明无消息残留。
    assert!(
        stdout(&out).contains("\"placements\":0"),
        "整源清空后 placements 应为 0: {}",
        stdout(&out)
    );
}

#[test]
fn sync_empty_source_tombstones_all_messages_codex() {
    // codex 形态的整源清空：0 字节源无 provider 认领（走 CLI 的 "empty" 空批），
    // 但语义是完整扫描 → 该源此前提交的全部 codex 消息都被 tombstone。
    let (dir, db) = temp_db("sync-empty-codex");
    let fixture = dir.path().join("rollout-wipe.jsonl");
    std::fs::write(
        &fixture,
        codex_incremental_fixture(
            "synthetic-codex-wipe-session",
            &[
                ("codex_wipe_first", "user", "codex will be wiped"),
                ("codex_wipe_second", "assistant", "codex gone too"),
            ],
        ),
    )
    .expect("write codex fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let out = run(&db, &["search", "wiped"]);
    assert!(
        stdout(&out).contains("msg_v1_codex_wipe_first"),
        "search={}",
        stdout(&out)
    );

    std::fs::write(&fixture, b"").expect("truncate codex fixture");
    let out = run(&db, &["sync", &path]);
    assert!(
        out.status.success(),
        "empty codex source sync must succeed: {}",
        stdout(&out)
    );
    for needle in ["wiped", "gone"] {
        let out = run(&db, &["search", needle]);
        assert!(
            !stdout(&out).contains("msg_v1_"),
            "整源清空后 codex 消息不应再命中 ({needle}): {}",
            stdout(&out)
        );
    }
    let out = run(&db, &["status"]);
    let status = parse_first_line(&out);
    assert_eq!(
        status["data"]["placements"], 0,
        "整源清空后 placements 应为 0: {status}"
    );
}

#[test]
fn sync_truncated_tail_retains_previous_index_without_churn() {
    // agent 正在写源：文件尾部被截断（EOF 落在记录中间）。已索引过的源必须
    // retain——不重 parse、不推进指纹、不推进 generation、不 tombstone 旧内容，
    // 只报诊断（fast-resume 的 Invalid→Retain 语义）；文件写完后再 sync 完整重扫。
    let (dir, db) = temp_db("sync-truncated");
    let fixture = dir.path().join("live.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"tune the index"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"raise the batch size"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    assert!(
        stdout(&out).contains("\"generation\":1"),
        "{}",
        stdout(&out)
    );

    // 模拟 agent 正在写：追加一条未闭合记录（无尾换行，EOF 落在记录中间）。
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&fixture)
        .expect("open fixture");
    write!(
        file,
        r#"{{"type":"assistant","message":{{"role":"assistant","content":"still thinking"}}"#
    )
    .expect("append truncated tail");
    drop(file);

    let out = run(&db, &["sync", &path]);
    assert!(
        out.status.success(),
        "truncated-tail sync must succeed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["retained"], 1, "{frame}");
    assert_eq!(frame["data"]["emitted"], 0, "截断源不应重 parse: {frame}");
    assert_eq!(frame["data"]["committed"], 0, "{frame}");
    assert_eq!(
        frame["data"]["generation"], 1,
        "retain 不应推进 generation: {frame}"
    );
    let warnings = frame["warnings"].as_array().expect("warnings");
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|text| text.contains("truncated"))),
        "retain 诊断必须可见: {frame}"
    );

    // 已索引内容零丢失：两条旧消息仍可检索。
    for needle in ["tune", "batch"] {
        let out = run(&db, &["search", needle]);
        assert!(
            stdout(&out).contains("msg_v1_"),
            "search {needle} 应命中已索引内容: {}",
            stdout(&out)
        );
    }
}

#[test]
fn sync_new_truncated_source_parses_valid_prefix_recoverably() {
    // 从未索引过的新源带截断尾：没有旧索引可 retain，走既有 recoverable-skip——
    // 有效前缀照常解析提交（可搜索），截断行计入 skipped + 诊断（relation_complete
    // = false，store 层不推导 tombstone）。
    let (dir, db) = temp_db("sync-new-truncated");
    let fixture = dir.path().join("brand-new.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"complete line"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"half-written"}"#,
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["messages"], 1, "有效前缀应解析: {frame}");
    assert_eq!(frame["data"]["committed"], 1, "有效前缀应提交: {frame}");
    assert_eq!(frame["data"]["skipped"], 1, "截断行应计 skipped: {frame}");
    assert_eq!(frame["data"]["diagnostics"], 1, "{frame}");
    let out = run(&db, &["search", "complete"]);
    assert!(stdout(&out).contains("msg_v1_"), "search={}", stdout(&out));
}

#[test]
fn sync_partial_scan_never_tombstones_unseen_messages() {
    // 不完整扫描（坏行 + 消息被移除）：relation_complete=false → store 层只并集
    // 观察到的 claims、不推导 tombstone（fast-resume failed_incremental_scan
    // 不变量：任何解析错误都不删除已索引内容）。"这次没看到"≠"已被删除"。
    let (dir, db) = temp_db("sync-partial");
    let fixture = dir.path().join("partial.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"keep this message"}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"unseen message"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let out = run(&db, &["search", "unseen"]);
    assert!(stdout(&out).contains("msg_v1_"), "search={}", stdout(&out));

    // 重写：中部一行坏 JSON（recoverable skip），同时"删掉"了 unseen 消息。
    // 扫描不完整 → 本次没看到的 unseen 消息必须原样保留。
    std::fs::write(
        &fixture,
        concat!(
            "{ this is not json }\n",
            r#"{"type":"user","message":{"role":"user","content":"keep this message"}}"#,
            "\n",
        ),
    )
    .expect("rewrite fixture");

    let out = run(&db, &["sync", &path]);
    assert!(
        out.status.success(),
        "partial sync must succeed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["skipped"], 1, "坏行应计 skipped: {frame}");
    assert_eq!(frame["data"]["committed"], 1, "好行应提交: {frame}");
    let out = run(&db, &["search", "unseen"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "不完整扫描不得 tombstone 未看到的消息: {}",
        stdout(&out)
    );
}

#[test]
fn sync_io_error_during_rescan_never_tombstones() {
    // 硬错误（源文件消失）：capture 失败 → 整批 sync 失败，什么都不写。
    // 已索引内容必须原样保留（fast-resume failed_incremental_scan 不变量：
    // 任何 IO/解析错误都不删除已索引会话）。
    let (dir, db) = temp_db("sync-io-error");
    let fixture = dir.path().join("gone.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"survives the error"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let out = run(&db, &["search", "survives"]);
    assert!(stdout(&out).contains("msg_v1_"), "search={}", stdout(&out));

    // 源消失后重扫：sync 必须失败（错误 envelope），且 catalog 原样保留。
    std::fs::remove_file(&fixture).expect("remove fixture");
    let out = run(&db, &["sync", &path]);
    assert!(
        !out.status.success(),
        "缺失源的 sync 必须失败: {}",
        stdout(&out)
    );
    let out = run(&db, &["search", "survives"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "失败的扫描不得丢已索引内容: {}",
        stdout(&out)
    );
}

// ─── Robot v1 Envelope 契约 E2E ────────────────────────────────────────────

#[test]
fn robot_envelope_shape_on_success() {
    let (_dir, db) = temp_db("env-ok");
    let out = run(&db, &["index", "e1", "envelope shape test"]);
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    // frame_type / outcome / data.generation present
    assert_eq!(frame["command"], "index");
    assert!(frame["data"]["generation"].is_number());
    assert!(frame["meta"]["duration_ms"].as_u64().is_some());
}

#[test]
fn robot_envelope_shape_on_error() {
    let (_dir, db) = temp_db("env-err");
    let out = run(&db, &["--robot", "get", "not-a-valid-id"]);
    assert!(!out.status.success());
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["command"], "get");
    assert_eq!(frame["error"]["code"], "invalid_request");
    assert!(!frame["error"]["retryable"].as_bool().unwrap());
}

#[test]
fn robot_flag_produces_same_json_envelope() {
    let (_dir, db) = temp_db("env-robot");
    let out = Command::new(BIN)
        .args(["--db", &db, "--robot", "status"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "status");
}

#[test]
fn output_json_flag_produces_well_formed_envelope() {
    let (_dir, db) = temp_db("env-json");
    let out = Command::new(BIN)
        .args(["--db", &db, "--output", "json", "status"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
}

#[test]
fn invalid_output_mode_exits_with_code_2() {
    let (_dir, db) = temp_db("env-mode");
    let out = Command::new(BIN)
        .args(["--db", &db, "--output", "yaml", "status"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    // Even mode errors produce a valid error envelope on stdout.
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "invalid_request");
}

#[test]
fn doctor_envelope_shape_has_meta_generation_null() {
    let out = run_bare(&["--robot", "doctor"]);
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "doctor");
    // doctor has no generation context
    assert!(frame["meta"]["generation"].is_null() || frame["meta"]["generation"].is_number());
    // 构建事实与 schema v12 事实（addition keys on the doctor data）。
    assert_eq!(frame["data"]["tool_activity_storage"], true);
    if cfg!(feature = "semantic-candle") {
        assert_eq!(frame["data"]["semantic_feature"], true);
    } else {
        assert!(frame["data"]["semantic_feature"].is_null());
    }
}

// ─── config paths ──────────────────────────────────────────────────────────

#[test]
fn config_paths_reports_platform_directories() {
    let out = run_bare(&["--robot", "config", "paths"]);
    assert!(
        out.status.success(),
        "config paths failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    let data = &frame["data"];
    // All four directory fields must be present and non-empty strings.
    for field in ["config", "data", "cache", "logs"] {
        let value = data[field]
            .as_str()
            .unwrap_or_else(|| panic!("config paths must include {field} field, got: {data}"));
        assert!(!value.is_empty(), "{field} must not be empty");
    }
}

#[test]
fn providers_robot_output_is_a_stable_matrix_envelope() {
    use agent_session_grep_ports::capability::{ProviderCapabilityMatrix, ProviderMaturity};

    let out = run_bare(&["--output", "json", "providers"]);
    assert!(out.status.success(), "providers failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "providers");
    assert_eq!(frame["retrieval_mode"], "lexical");
    assert_eq!(frame["redaction"]["mode"], "default");
    assert_eq!(frame["redaction"]["status"], "none");
    assert_eq!(frame["page"]["next_cursor"], serde_json::Value::Null);
    assert_eq!(frame["page"]["has_more"], false);

    // 加法键：`semantic` 反映构建的语义检索事实，键集跨构建稳定。
    let semantic = &frame["data"]["semantic"];
    assert_eq!(
        semantic.as_object().unwrap().len(),
        3,
        "semantic 键集稳定: {semantic}"
    );
    assert_eq!(
        semantic["default_model"],
        agent_session_grep_application::embedding::BIGRAM_HASH_MODEL_ID
    );
    if cfg!(feature = "semantic-candle") {
        assert_eq!(semantic["feature"], "semantic-candle");
        assert_eq!(semantic["runtime"], "candle-e5-local");
    } else {
        assert!(semantic["feature"].is_null(), "{semantic}");
        assert!(semantic["runtime"].is_null(), "{semantic}");
    }

    let matrix = ProviderCapabilityMatrix::current();
    let rows = frame["data"]["providers"]
        .as_array()
        .expect("providers array");
    assert_eq!(rows.len(), matrix.providers.len());
    let expected_keys = [
        "context",
        "discover",
        "handoff",
        "incremental",
        "maturity",
        "maturity_target",
        "parse",
        "probe",
        "provider_id",
        "resume",
        "search",
        "source_span",
        "tool_activity",
        "variant_id",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    for (row, capability) in rows.iter().zip(&matrix.providers) {
        let actual_keys = row
            .as_object()
            .expect("provider row object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual_keys, expected_keys, "{row}");
        assert_eq!(row["provider_id"], capability.provider_id);
        assert_eq!(
            row["maturity"],
            serde_json::to_value(capability.maturity).expect("serialize maturity")
        );
        assert_eq!(
            row["maturity_target"],
            serde_json::to_value(ProviderMaturity::target_for(&capability.provider_id))
                .expect("serialize maturity target")
        );
    }
    for deferred in ["deepseek-harness", "zcode"] {
        let row = rows
            .iter()
            .find(|row| row["provider_id"] == deferred)
            .unwrap_or_else(|| panic!("missing deferred provider {deferred}"));
        assert!(row["maturity_target"].is_null(), "{row}");
    }
}

#[test]
fn providers_human_output_uses_the_human_renderer() {
    let out = run_bare(&["providers"]);
    assert!(out.status.success(), "providers failed: {}", stdout(&out));
    let text = stdout(&out);
    let expected_count = agent_session_grep_ports::capability::ProviderCapabilityMatrix::current()
        .providers
        .len();
    assert!(
        text.lines()
            .next()
            .is_some_and(|line| line == format!("providers: {expected_count}")),
        "{text}"
    );
    assert!(text.contains("maturity=experimental"), "{text}");
    assert!(text.contains("target=—"), "{text}");
    assert!(text.contains("tool_activity="), "{text}");
    assert!(text.contains("incremental="), "{text}");
}

// ─── Resume 执行层 smoke（audit P1-2）───────────────────────────────────────

/// 写入带 `cwd` 的合成 Claude fixture（恢复命令应回到该目录 spawn），返回
/// (fixture 路径, 锚点 message wire id)。
fn write_claude_resume_fixture(dir: &Path, cwd: &str) -> (String, String) {
    let line = serde_json::json!({
        "type": "user",
        "uuid": "c0000000-0000-4000-8000-000000000001",
        "parentUuid": null,
        "sessionId": "ccdd1234-5678-4abc-8def-001122334455",
        "cwd": cwd,
        "timestamp": "2026-07-26T01:00:00.000Z",
        "message": { "role": "user", "content": "resume smoke root" },
    })
    .to_string();
    let fixture = dir.join("resume-smoke.jsonl");
    std::fs::write(&fixture, format!("{line}\n")).expect("write resume fixture");
    (
        fixture.to_string_lossy().into_owned(),
        "msg_v1_c0000000-0000-4000-8000-000000000001".to_string(),
    )
}

/// 把测试专用 fake provider（`resume-smoke-provider` bin）复制为 `claude`。
fn write_fake_provider(fake_dir: &Path) {
    let helper = Path::new(env!("CARGO_BIN_EXE_resume-smoke-provider"));
    #[cfg(windows)]
    let target = fake_dir.join("claude.exe");
    #[cfg(not(windows))]
    let target = fake_dir.join("claude");
    std::fs::copy(helper, &target).expect("copy fake provider binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake provider");
    }
}

/// 以 robot 模式跑 CLI，PATH 前置 `path`，并把 fake provider 的 cwd/args
/// 记录文件路径经环境变量传入（fake provider 由 CLI 继承后记录）。
fn run_with_path(
    db: &str,
    path: &std::ffi::OsStr,
    cwd_out: &Path,
    args_out: &Path,
    args: &[&str],
) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.arg("--db").arg(db).arg("--robot").args(args);
    cmd.env("PATH", path);
    cmd.env("RESUME_SMOKE_CWD_OUT", cwd_out);
    cmd.env("RESUME_SMOKE_ARGS_OUT", args_out);
    cmd.output()
        .expect("failed to spawn agent-session-grep binary")
}

/// cwd 文本比较：忽略尾部分隔符；Windows 大小写不敏感。
fn same_cwd(recorded: &str, expected: &str) -> bool {
    let recorded = recorded.trim().trim_end_matches(['/', '\\']);
    let expected = expected.trim().trim_end_matches(['/', '\\']);
    #[cfg(windows)]
    {
        recorded.eq_ignore_ascii_case(expected)
    }
    #[cfg(not(windows))]
    {
        recorded == expected
    }
}

#[test]
fn resume_yes_first_run_forced_preview_then_spawns_in_original_cwd() {
    let (dir, db) = temp_db("resume-spawn");
    let workdir = dir.path().join("original-workspace");
    std::fs::create_dir_all(&workdir).expect("create workspace");
    let workdir_str = workdir.to_string_lossy().into_owned();
    let (fixture_path, anchor_message) = write_claude_resume_fixture(dir.path(), &workdir_str);
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let fake_dir = dir.path().join("fake-bin");
    std::fs::create_dir_all(&fake_dir).expect("create fake bin dir");
    write_fake_provider(&fake_dir);
    let cwd_out = dir.path().join("spawn-cwd.txt");
    let args_out = dir.path().join("spawn-args.txt");
    // PATH 前置 fake 目录（追加原 PATH，保证进程正常加载）。
    let path = std::env::var_os("PATH")
        .map(|p| {
            let mut dirs = std::env::split_paths(&p).collect::<Vec<_>>();
            dirs.insert(0, fake_dir.clone());
            std::env::join_paths(dirs).expect("join PATH")
        })
        .unwrap_or_else(|| fake_dir.clone().into_os_string());

    // 1) 首次 resume --yes：强制预览不执行（持久标记缺失），落标记。
    let out = run_with_path(
        &db,
        &path,
        &cwd_out,
        &args_out,
        &["resume", &session_wire, "--yes"],
    );
    assert!(
        out.status.success(),
        "first resume failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["executed"], false, "{frame}");
    assert_eq!(frame["data"]["first_run_preview"], true, "{frame}");
    assert_eq!(frame["data"]["permission_mode_verified"], false, "{frame}");
    assert!(!cwd_out.exists(), "first run must not spawn provider");
    assert!(!args_out.exists(), "first run must not spawn provider");

    // 2) 第二次 resume --yes：标记已确认，真实 spawn 到原 cwd 并传正确参数。
    let out = run_with_path(
        &db,
        &path,
        &cwd_out,
        &args_out,
        &["resume", &session_wire, "--yes"],
    );
    assert!(
        out.status.success(),
        "second resume failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["executed"], true, "{frame}");
    assert!(
        frame["data"].get("first_run_preview").is_none(),
        "second run must not report first-run: {frame}"
    );
    let recorded_cwd = std::fs::read_to_string(&cwd_out).expect("read recorded cwd");
    assert!(
        same_cwd(&recorded_cwd, &workdir_str),
        "spawned cwd {recorded_cwd:?} != expected {workdir_str:?}"
    );
    let recorded_args = std::fs::read_to_string(&args_out).expect("read recorded args");
    assert!(recorded_args.contains("--resume"), "args {recorded_args:?}");
    assert!(
        recorded_args.contains("ccdd1234-5678-4abc-8def-001122334455"),
        "args must carry the provider session id: {recorded_args:?}"
    );

    // 3) dry-run 命令字符串：标记确认后无 --yes 只预览，命令含 cwd 与参数。
    let out = run_with_path(&db, &path, &cwd_out, &args_out, &["resume", &session_wire]);
    assert!(out.status.success(), "dry-run failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["executed"], false, "{frame}");
    let command = frame["data"]["command"].as_str().expect("command string");
    assert!(command.contains("claude --resume"), "command {command}");
    assert!(command.contains(&workdir_str), "command {command}");
}

#[test]
fn resume_yes_missing_provider_binary_returns_structured_error() {
    let (dir, db) = temp_db("resume-missing-bin");
    let cwd_str = dir.path().to_string_lossy().into_owned();
    let (fixture_path, anchor_message) = write_claude_resume_fixture(dir.path(), &cwd_str);
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    // 空 PATH 目录：不包含任何 provider 二进制（保证机器上即使装了 claude 也不命中）。
    let empty_bin = dir.path().join("empty-bin");
    std::fs::create_dir_all(&empty_bin).expect("create empty bin dir");
    let cwd_out = dir.path().join("never-cwd.txt");
    let args_out = dir.path().join("never-args.txt");

    // 首次 resume --yes：强制预览 + 落标记（不触发 preflight）。
    let out = run_with_path(
        &db,
        empty_bin.as_os_str(),
        &cwd_out,
        &args_out,
        &["resume", &session_wire, "--yes"],
    );
    assert!(
        out.status.success(),
        "first resume failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["executed"], false, "{frame}");
    assert!(!cwd_out.exists(), "first run must not spawn");

    // 第二次 --yes：preflight 拦截缺失二进制 → 结构化 provider_error（exit 7）。
    let out = run_with_path(
        &db,
        empty_bin.as_os_str(),
        &cwd_out,
        &args_out,
        &["resume", &session_wire, "--yes"],
    );
    assert!(
        !out.status.success(),
        "second resume should fail: {}",
        stdout(&out)
    );
    assert_eq!(out.status.code(), Some(7), "provider_error exit code");
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "provider_error", "{frame}");
    assert_eq!(
        frame["error"]["details"]["stage"], "binary_preflight",
        "{frame}"
    );
    assert_eq!(frame["error"]["details"]["binary"], "claude", "{frame}");
    assert!(
        frame["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("install")),
        "error message must hint installation: {frame}"
    );
}

#[test]
fn resume_unavailable_session_reports_reason_without_command() {
    let (dir, db) = temp_db("resume-unavailable");
    // 空库上任何 session 都无 resume 声明 → available:false + reason。
    let out = run(&db, &["resume", "ses_v1_00000000000000000000000000"]);
    assert!(out.status.success(), "resume failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["available"], false, "{frame}");
    assert_eq!(frame["data"]["command"], serde_json::Value::Null, "{frame}");
    assert_eq!(
        frame["data"]["unavailable_reason"], "no resume metadata claims",
        "{frame}"
    );
    assert_eq!(frame["data"]["executed"], false, "{frame}");
    // 不可恢复不落首次预览标记。
    let marker = dir.path().join(".agent-session-grep-resume-ack");
    assert!(
        !marker.exists(),
        "unavailable session must not ack first-run marker"
    );
}

#[test]
fn handoff_pack_is_byte_deterministic_across_runs() {
    let (dir, db) = temp_db("handoff-det");
    let (fixture_path, _, _) = write_context_fixture(dir.path());
    let ingest = run(&db, &["ingest", &fixture_path]);
    assert!(
        ingest.status.success(),
        "ingest failed: {}",
        stdout(&ingest)
    );

    let first = run(&db, &["handoff", "ctx"]);
    assert!(first.status.success(), "handoff failed: {}", stdout(&first));
    let second = run(&db, &["handoff", "ctx"]);
    assert!(
        second.status.success(),
        "handoff failed: {}",
        stdout(&second)
    );

    let f1 = parse_first_line(&first);
    let f2 = parse_first_line(&second);
    // 同输入两次运行 → pack 逐字节一致（determinism 契约，PRD Q50）。
    assert_eq!(
        f1["data"].to_string(),
        f2["data"].to_string(),
        "pack must be byte-identical across runs"
    );
    assert!(
        f1["data"]["evidence"]
            .as_array()
            .is_some_and(|ev| !ev.is_empty()),
        "pack must carry evidence: {f1}"
    );
    assert_eq!(f1["data"]["schema_version"], "1.0");
    assert_eq!(f1["data"]["generation_mode"], "deterministic");
    // 权威 source locator：证据携带 doc_v1_ 文档 id 与消息 cursor 反向追踪。
    assert!(
        f1["data"]["evidence"][0]["source_document_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("doc_v1_")),
        "{f1}"
    );
    assert!(
        f1["data"]["source_locators"]
            .as_array()
            .is_some_and(|locs| !locs.is_empty()),
        "{f1}"
    );
}

#[test]
fn handoff_budget_truncation_reports_partial_and_exit_10() {
    let (dir, db) = temp_db("handoff-trunc");
    let (fixture_path, _, _) = write_context_fixture(dir.path());
    let ingest = run(&db, &["ingest", &fixture_path]);
    assert!(
        ingest.status.success(),
        "ingest failed: {}",
        stdout(&ingest)
    );

    // 极小证据上限 → 截断 → partial（exit 10），绝不伪装 success。
    let out = run(&db, &["handoff", "ctx", "--max-evidence", "1"]);
    assert_eq!(
        out.status.code(),
        Some(10),
        "truncated handoff must exit 10: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_eq!(frame["outcome"], "partial");
    assert_eq!(frame["data"]["truncation"]["truncated"], true);
    assert!(
        frame["data"]["evidence"]
            .as_array()
            .is_some_and(|ev| ev.len() <= 1),
        "evidence must be capped: {frame}"
    );

    // 无截断时 outcome 为 success。
    let ok = run(&db, &["handoff", "ctx"]);
    assert!(ok.status.success(), "handoff failed: {}", stdout(&ok));
    assert_eq!(parse_first_line(&ok)["outcome"], "success");
}

#[test]
fn handoff_redacts_secrets_in_evidence() {
    let (dir, db) = temp_db("handoff-redact");
    // 一条含 API key 的消息，用于验证 pack 默认脱敏（ADR-0009）。
    let secret = "the token is sk-ant-api03-1234567890abcdef end";
    let fixture_path = dir.path().join("secret.jsonl");
    let line = serde_json::json!({
        "type": "user",
        "uuid": "e0000000-0000-4000-8000-000000000001",
        "parentUuid": null,
        "sessionId": "ee123456-5678-4abc-8def-001122334455",
        "timestamp": "2026-07-26T01:00:00.000Z",
        "message": { "role": "user", "content": secret },
    })
    .to_string();
    std::fs::write(&fixture_path, line).expect("write secret fixture");
    let ingest = run(&db, &["ingest", &fixture_path.to_string_lossy()]);
    assert!(
        ingest.status.success(),
        "ingest failed: {}",
        stdout(&ingest)
    );

    let out = run(&db, &["handoff", "token"]);
    assert!(out.status.success(), "handoff failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let data = &frame["data"];
    let text = data["evidence"][0]["text"].as_str().unwrap_or("");
    assert!(!text.contains("sk-ant-"), "secret leaked into pack: {text}");
    assert_eq!(data["redaction"]["status"], "applied");
    assert!(data["redaction"]["redacted_count"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn jsonl_output_is_one_complete_frame_per_line() {
    let (_dir, db) = temp_db("env-jsonl");
    let out = Command::new(BIN)
        .args(["--db", &db, "--output", "jsonl", "status"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let output_text = stdout(&out);
    let lines: Vec<_> = output_text.lines().collect();
    assert_eq!(lines.len(), 1, "one command must emit one JSONL frame");
    let frame: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSONL frame");
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["frame_type"], "response");
}

#[test]
fn human_error_writes_diagnostic_to_stderr_only() {
    let (_dir, db) = temp_db("env-human-error");
    let out = run_human(&db, &["get", "not-a-valid-id"]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).is_empty(),
        "human mode stdout must stay protocol-clean"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).is_empty(),
        "human mode must write diagnostic to stderr"
    );
}

// ─── 分页 cursor + 预算 + context（shared Application ADT，design §7）───────

/// 从 search envelope 里取命中 id 列表。
fn hit_ids(frame: &serde_json::Value) -> Vec<String> {
    frame["data"]["hits"]
        .as_array()
        .expect("data.hits must be an array")
        .iter()
        .map(|h| h["id"].as_str().expect("hit.id").to_string())
        .collect()
}

#[test]
fn search_guidance_robot_json_contains_fields_and_valid_commands() {
    let (dir, db) = temp_db("guidance-robot");
    let (fixture_path, _content, anchor_message) = write_context_fixture(dir.path());
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);
    let out = run(&db, &["search", "ctx"]);
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    let hits = frame["data"]["hits"].as_array().expect("hits");
    assert!(!hits.is_empty(), "至少一条命中: {frame}");
    for hit in hits {
        assert_eq!(
            hit["session_id"].as_str(),
            Some(session_wire.as_str()),
            "{hit}"
        );
        assert!(
            hit["why_matched"]
                .as_array()
                .is_some_and(|a| a.iter().any(|t| t == "ctx")),
            "why_matched 必须包含字面词元 ctx: {hit}"
        );
        let suggested = hit["suggested_next_commands"]
            .as_array()
            .expect("suggested_next_commands");
        assert_eq!(suggested.len(), 2, "{hit}");
        assert!(
            suggested[0]
                .as_str()
                .is_some_and(|c| c.contains("get-message")
                    && c.contains(hit["id"].as_str().expect("id"))
                    && c.contains(&session_wire)),
            "get-message 建议必须含真实 message/session id: {suggested:?}"
        );
        assert!(
            suggested[1]
                .as_str()
                .is_some_and(|c| c.contains("context ") && c.contains(&session_wire)),
            "context 建议必须含真实 session wire id: {suggested:?}"
        );
    }
}

#[test]
fn search_guidance_byte_budget_truncates_explicitly() {
    // guidance 的 JSON 转义字节计入 clamp：两条 2000+ 字符正文的命中各带
    // why_matched（widgets 词元）与 2 条建议命令，最小预算 4096（净 3072）下
    // 必然显式截断，而不是悄悄溢出 envelope。
    let (dir, db) = temp_db("guidance-budget");
    let (fixture_path, _anchor_message, _a, _b) = write_session_hits_fixture(dir.path(), true);
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let out = run(&db, &["search", "widgets", "--max-bytes", "4096"]);
    assert_eq!(
        out.status.code(),
        Some(10),
        "预算截断应 exit 10: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["outcome"], "partial", "{frame}");
    assert!(
        frame["data"]["truncation"]["truncated"].as_bool().unwrap(),
        "{frame}"
    );
    assert_eq!(
        frame["data"]["truncation"]["reason"].as_str().unwrap(),
        "max_response_bytes",
        "{frame}"
    );
    let hits = frame["data"]["hits"].as_array().expect("hits");
    assert!(
        hits.len() < 2,
        "长正文 + guidance 放不进 4096 字节: {frame}"
    );
    for hit in hits {
        assert!(
            hit["why_matched"]
                .as_array()
                .is_some_and(|a| a.iter().any(|t| t == "widgets")),
            "保留的命中仍带 guidance 证据: {hit}"
        );
        let suggested = hit["suggested_next_commands"]
            .as_array()
            .expect("保留的命中必须仍带建议命令");
        assert_eq!(suggested.len(), 2, "{hit}");
        assert!(
            suggested.iter().any(|c| c.as_str().is_some_and(
                |s| s.contains("get-message") && s.contains(hit["id"].as_str().expect("id"))
            )),
            "证据+建议同时计入 clamp 后，保留的命中上下一致: {hit}"
        );
    }
}

#[test]
fn search_guidance_human_output_is_unchanged() {
    // human 渲染不读 guidance 字段：输出与 guidance 加入前的形状一致。
    let (_dir, db) = temp_db("guidance-human");
    let out = run(&db, &["index", "g1", "human guidance probe"]);
    assert!(out.status.success());
    let out = run_human(&db, &["search", "guidance"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("hit(s) (generation"), "{s}");
    assert!(s.contains("msg_v1_"), "{s}");
    // `index` 命令只把 plain text 写入 catalog；Application 只从 JSON
    // payload 的 `text` 字段装配预览，所以该 legacy 路径没有正文预览行。
    // guidance 加入后仍不得改变这段 human 输出形状。
    assert_eq!(s.lines().count(), 2, "{s}");
    assert!(!s.contains("why_matched"), "{s}");
    assert!(!s.contains("suggested_next_commands"), "{s}");
    assert!(!s.contains("schema_version"), "{s}");
}

#[test]
fn search_guidance_omits_suggestions_without_session_id() {
    // 纯 index 写入的消息没有 placement → session_id None → get_message/context
    // 建议必须省略；只有 why_matched 存在。
    let (_dir, db) = temp_db("guidance-nosession");
    let out = run(&db, &["index", "g1", "no session here guidance"]);
    assert!(out.status.success());
    let out = run(&db, &["search", "guidance"]);
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    let hit = &frame["data"]["hits"][0];
    assert!(hit["session_id"].is_null(), "{hit}");
    let suggested = &hit["suggested_next_commands"];
    let exists_empty = suggested.is_null() || suggested.as_array().is_none_or(Vec::is_empty);
    assert!(exists_empty, "无 session_id 时建议必须省略或为空: {hit}");
}

#[test]
fn search_cursor_pages_partition_results() {
    let (_dir, db) = temp_db("cursor-pages");
    for (fact, text) in [
        ("c1", "cursor pagination alpha one"),
        ("c2", "cursor pagination alpha two"),
        ("c3", "cursor pagination alpha three"),
    ] {
        let out = run(&db, &["index", fact, text]);
        assert!(out.status.success());
    }

    // 不分页基线：一页拿全。
    let out = run(&db, &["search", "pagination"]);
    assert!(out.status.success());
    let all = hit_ids(&parse_first_line(&out));
    assert_eq!(all.len(), 3);

    // 第一页：页大小 2，应带续读令牌。
    let out = run(&db, &["search", "pagination", "--max-items", "2"]);
    assert!(out.status.success(), "page1 failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    let page1 = hit_ids(&frame);
    assert_eq!(page1.len(), 2);
    assert_eq!(frame["page"]["has_more"], true, "page1={frame}");
    let token = frame["page"]["next_cursor"]
        .as_str()
        .expect("page1 must issue next_cursor")
        .to_string();

    // 第二页：续读到末尾，不再发令牌。
    let out = run(
        &db,
        &[
            "search",
            "pagination",
            "--max-items",
            "2",
            "--cursor",
            &token,
        ],
    );
    assert!(out.status.success(), "page2 failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let page2 = hit_ids(&frame);
    assert_eq!(page2.len(), 1);
    assert_eq!(frame["page"]["has_more"], false, "page2={frame}");
    assert!(frame["page"]["next_cursor"].is_null());

    // 两页拼接 == 不分页结果：钉住排序（bm25 + id tiebreak）下不重不漏、同序。
    let joined: Vec<String> = page1.into_iter().chain(page2).collect();
    assert_eq!(joined, all);
}

#[test]
fn tampered_cursor_is_rejected_with_cursor_invalid() {
    let (_dir, db) = temp_db("cursor-tamper");
    for (fact, text) in [("t1", "tamper target one"), ("t2", "tamper target two")] {
        let out = run(&db, &["index", fact, text]);
        assert!(out.status.success());
    }
    let out = run(&db, &["search", "tamper", "--max-items", "1"]);
    let token = parse_first_line(&out)["page"]["next_cursor"]
        .as_str()
        .expect("next_cursor")
        .to_string();

    // 翻转 payload 首字符（仍是合法 base64url 字符）→ 完整性摘要不符。
    let mut chars: Vec<char> = token.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    let out = run(
        &db,
        &[
            "search",
            "tamper",
            "--max-items",
            "1",
            "--cursor",
            &tampered,
        ],
    );
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "cursor_invalid");
    // 错误消息必须指示重新发起查询（合同禁止静默回第一页）。
    assert!(
        frame["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("re-run")),
        "message={frame}"
    );
}

#[test]
fn generation_bump_invalidates_cursor_with_exit_9() {
    let (_dir, db) = temp_db("cursor-generation");
    for (fact, text) in [("g1", "bump probe one"), ("g2", "bump probe two")] {
        let out = run(&db, &["index", fact, text]);
        assert!(out.status.success());
    }
    let out = run(&db, &["search", "probe", "--max-items", "1"]);
    let token = parse_first_line(&out)["page"]["next_cursor"]
        .as_str()
        .expect("next_cursor")
        .to_string();

    // 再写一条推进 generation：数据已换代，旧令牌必须显式失效。
    let out = run(&db, &["index", "g3", "bump probe three"]);
    assert!(out.status.success());

    let out = run(
        &db,
        &["search", "probe", "--max-items", "1", "--cursor", &token],
    );
    assert_eq!(out.status.code(), Some(9), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "generation_mismatch");
    // 结构化 details：调用方无需解析 message 即可拿到两侧 generation（contract §4）。
    assert_eq!(frame["error"]["details"]["cursor_generation"], 2);
    assert_eq!(frame["error"]["details"]["active_generation"], 3);
}

/// 写入 context e2e 用的真实 Claude 格式夹具（合成数据，含 sidechain 与 fork）：
/// root → reply → { sidechain probe, mainline tail }。返回夹具路径、字节和锚点消息。
fn write_context_fixture(dir: &std::path::Path) -> (String, String, String) {
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
        lines.to_string(),
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
    let session_a_native = "aa111111-1111-4111-8111-111111111111";
    let session_b_native = "bb222222-2222-4222-8222-222222222222";
    let parent_a_native = "aa333333-3333-4333-8333-333333333333";
    let parent_b_native = "bb444444-4444-4444-8444-444444444444";
    let shared_native = "cc555555-5555-4555-8555-555555555555";
    let head_a = format!(
        "{{\"type\":\"user\",\"uuid\":\"{parent_a_native}\",\"parentUuid\":null,\
         \"sessionId\":\"{session_a_native}\",\"timestamp\":\"2026-07-28T01:00:00.000Z\",\
         \"message\":{{\"role\":\"user\",\"content\":\"relational parent A\"}}}}\n"
    );
    let tail_a = format!(
        "{{\"type\":\"assistant\",\"uuid\":\"{shared_native}\",\
         \"parentUuid\":\"{parent_a_native}\",\"sessionId\":\"{session_a_native}\",\
         \"timestamp\":\"2026-07-28T01:00:01.000Z\",\
         \"message\":{{\"role\":\"assistant\",\"content\":\"relational shared answer\"}}}}\n"
    );
    let source_b = format!(
        "{{\"type\":\"user\",\"uuid\":\"{parent_b_native}\",\"parentUuid\":null,\
         \"sessionId\":\"{session_b_native}\",\"timestamp\":\"2026-07-28T01:00:00.000Z\",\
         \"message\":{{\"role\":\"user\",\"content\":\"relational parent B\"}}}}\n\
         {{\"type\":\"assistant\",\"uuid\":\"{shared_native}\",\
         \"parentUuid\":\"{parent_b_native}\",\"sessionId\":\"{session_b_native}\",\
         \"timestamp\":\"2026-07-28T01:00:01.000Z\",\
         \"message\":{{\"role\":\"assistant\",\"content\":\"relational shared answer\"}}}}\n"
    );
    let files = [
        ("relational-a-head.jsonl", head_a.clone()),
        ("relational-a-tail.jsonl", tail_a.clone()),
        ("relational-b.jsonl", source_b.clone()),
    ];
    let mut paths = Vec::new();
    for (name, content) in &files {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write relational context fixture");
        paths.push(path.to_string_lossy().into_owned());
    }
    RelationalContextFixture {
        paths: paths.try_into().expect("three fixture paths"),
        contents: [head_a, tail_a, source_b],
        session_a: format!("msg_v1_{parent_a_native}"),
        session_b: format!("msg_v1_{parent_b_native}"),
        parent_a: format!("msg_v1_{parent_a_native}"),
        parent_b: format!("msg_v1_{parent_b_native}"),
        shared_message: format!("msg_v1_{shared_native}"),
    }
}

fn write_oversized_anchor_fixture(dir: &Path) -> (String, String, usize) {
    let message_native = "d0000000-0000-4000-8000-000000000001";
    let session_native = "ddde1234-5678-4abc-8def-001122334455";
    let body = "\"\n".repeat(4096);
    let line = serde_json::json!({
        "type": "user",
        "uuid": message_native,
        "parentUuid": null,
        "sessionId": session_native,
        "timestamp": "2026-07-26T01:00:00.000Z",
        "message": { "role": "user", "content": body },
    })
    .to_string();
    let fixture = dir.join("oversized-anchor.jsonl");
    std::fs::write(&fixture, line).expect("write oversized anchor fixture");
    (
        fixture.to_string_lossy().into_owned(),
        format!("msg_v1_{message_native}"),
        body.len(),
    )
}

#[test]
fn get_message_oversized_anchor_respects_final_robot_byte_budget() {
    let (dir, db) = temp_db("message-anchor-budget");
    let (fixture_path, message_wire, original_text_len) =
        write_oversized_anchor_fixture(dir.path());
    let ingest = run(&db, &["ingest", &fixture_path]);
    assert!(
        ingest.status.success(),
        "ingest failed: {}",
        stdout(&ingest)
    );
    let session_wire = session_wire_for_message(&db, &message_wire);

    let out = run(
        &db,
        &[
            "get-message",
            &message_wire,
            "--session",
            &session_wire,
            "--around",
            "0",
            "--max-bytes",
            "4096",
        ],
    );
    assert_eq!(out.status.code(), Some(10), "{}", stdout(&out));
    assert!(
        out.stdout.len() <= 4096,
        "final Robot frame is {} bytes: {}",
        out.stdout.len(),
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["outcome"], "partial", "{frame}");
    assert_eq!(frame["data"]["message_id"], message_wire, "{frame}");
    assert_eq!(frame["data"]["session_id"], session_wire, "{frame}");
    assert_eq!(frame["data"]["messages"].as_array().unwrap().len(), 1);
    let anchor = &frame["data"]["messages"][0];
    assert_eq!(anchor["message_id"], message_wire, "{anchor}");
    assert!(
        anchor["payload"]["text"]
            .as_str()
            .is_some_and(|text| text.len() < original_text_len),
        "oversized anchor text must be projected: {anchor}"
    );
    assert_eq!(frame["data"]["truncation"]["reason"], "max_response_bytes");
}

#[test]
fn context_derived_view_respects_final_robot_byte_budget() {
    let (dir, db) = temp_db("context-derived-budget");
    let (fixture_path, _, _) = write_oversized_anchor_fixture(dir.path());
    let ingest = run(&db, &["ingest", &fixture_path]);
    assert!(
        ingest.status.success(),
        "ingest failed: {}",
        stdout(&ingest)
    );
    let session_wire = session_wire_for_message(&db, "msg_v1_d0000000-0000-4000-8000-000000000001");

    let out = run(
        &db,
        &[
            "context",
            &session_wire,
            "--level",
            "talks",
            "--max-bytes",
            "4096",
        ],
    );
    assert_eq!(out.status.code(), Some(10), "{}", stdout(&out));
    assert!(
        out.stdout.len() <= 4096,
        "final Robot frame is {} bytes: {}",
        out.stdout.len(),
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["outcome"], "partial", "{frame}");
    assert_eq!(frame["data"]["requested_level"], "talks", "{frame}");
    assert!(
        frame["data"]["truncation"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("max_response_bytes")),
        "{frame}"
    );
}

#[test]
fn context_assembles_mainline_branch_with_evidence() {
    let (dir, db) = temp_db("context-mainline");
    let (fixture_path, content, anchor_message) = write_context_fixture(dir.path());
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let out = run(&db, &["context", &session_wire]);
    assert!(out.status.success(), "context failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["command"], "context");
    assert_eq!(frame["data"]["session_id"], session_wire.as_str());
    assert_eq!(frame["outcome"], "success");

    // mainline：排除 sidechain，沿 parent 链 root→leaf。
    let messages = frame["data"]["messages"].as_array().expect("messages");
    let wires: Vec<&str> = messages
        .iter()
        .map(|m| m["id"].as_str().expect("message.id"))
        .collect();
    assert!(
        messages
            .iter()
            .all(|message| message["id"] == message["message_id"])
    );
    assert_eq!(
        wires,
        vec![
            "msg_v1_c0000000-0000-4000-8000-000000000001",
            "msg_v1_c0000000-0000-4000-8000-000000000002",
            "msg_v1_c0000000-0000-4000-8000-000000000004",
        ],
        "frame={frame}"
    );
    assert_eq!(
        frame["data"]["branch_leaf"],
        "msg_v1_c0000000-0000-4000-8000-000000000004"
    );
    assert_eq!(
        frame["data"]["branch_leaf_placement_id"],
        messages[2]["placement_id"]
    );

    // 证据与链对齐：byte 精度 + 指纹 + 文档身份；span 精确切回源记录。
    let evidence = frame["data"]["evidence"].as_array().expect("evidence");
    assert_eq!(evidence.len(), 3);
    for (message, span) in messages.iter().zip(evidence) {
        assert_eq!(span["occurrence_id"], message["placement_id"]);
        assert_eq!(span["message_id"], message["message_id"]);
    }
    assert_eq!(evidence[0]["precision"], "byte");
    assert!(
        evidence[0]["source_document_id"]
            .as_str()
            .is_some_and(|d| d.starts_with("doc_v1_")),
        "frame={frame}"
    );
    assert!(
        evidence[0]["source_fingerprint"]
            .as_str()
            .is_some_and(|f| !f.is_empty()),
        "frame={frame}"
    );
    let start = evidence[0]["byte_start"].as_u64().expect("byte_start") as usize;
    let end = evidence[0]["byte_end"].as_u64().expect("byte_end") as usize;
    let sliced = &content.as_bytes()[start..end];
    assert!(
        sliced.starts_with(br#"{"type":"user","uuid":"c0000000-0000-4000-8000-000000000001""#),
        "span 应切回 root 源记录"
    );
    // 证据 ordinal 是会话内 seq：mainline 第三条是成员序号 3（sidechain 占 2）。
    assert_eq!(evidence[2]["record_ordinal"], 3, "frame={frame}");

    // full 策略包含 sidechain，按冻结顺序：missing timestamp 先，再按 ordinal；
    // 有 timestamp 的 root 最后。该顺序不声称缺失时间的跨记录 chronology。
    let out = run(&db, &["context", &session_wire, "--policy", "full"]);
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    let full: Vec<&str> = frame["data"]["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        full,
        vec![
            "msg_v1_c0000000-0000-4000-8000-000000000002",
            "msg_v1_c0000000-0000-4000-8000-000000000003",
            "msg_v1_c0000000-0000-4000-8000-000000000004",
            "msg_v1_c0000000-0000-4000-8000-000000000001",
        ]
    );
}

/// 把一个会话拆成两个文件写出：前半 root→reply，后半 sidechain + mainline tail。
/// 两个文件都声明同一个 `sessionId`——这是真实语料里的常态（会话续写/分片），
/// 而非人造边角：单会话被 55 个文件各自声明的情况已在真实数据回归中实测。
/// 返回两个路径与可用于查询 canonical Session 的锚点 Message ID。
fn write_split_session_fixture(dir: &std::path::Path) -> (String, String, String) {
    let head = concat!(
        r#"{"type":"user","uuid":"5p1i7000-0000-4000-8000-000000000001","parentUuid":null,"sessionId":"5p1i7aaa-1111-4bbb-8ccc-000000000001","timestamp":"2026-07-27T01:00:00.000Z","message":{"role":"user","content":"split root question"}}"#,
        "\n",
        r#"{"type":"assistant","uuid":"5p1i7000-0000-4000-8000-000000000002","parentUuid":"5p1i7000-0000-4000-8000-000000000001","sessionId":"5p1i7aaa-1111-4bbb-8ccc-000000000001","message":{"role":"assistant","content":"split first answer"}}"#,
        "\n",
    );
    let tail = concat!(
        r#"{"type":"user","uuid":"5p1i7000-0000-4000-8000-000000000003","parentUuid":"5p1i7000-0000-4000-8000-000000000002","isSidechain":true,"sessionId":"5p1i7aaa-1111-4bbb-8ccc-000000000001","message":{"role":"user","content":"split sidechain probe"}}"#,
        "\n",
        r#"{"type":"assistant","uuid":"5p1i7000-0000-4000-8000-000000000004","parentUuid":"5p1i7000-0000-4000-8000-000000000002","sessionId":"5p1i7aaa-1111-4bbb-8ccc-000000000001","message":{"role":"assistant","content":"split final answer"}}"#,
        "\n",
    );
    let head_path = dir.join("split-head.jsonl");
    let tail_path = dir.join("split-tail.jsonl");
    std::fs::write(&head_path, head).expect("write split head fixture");
    std::fs::write(&tail_path, tail).expect("write split tail fixture");
    (
        head_path.to_string_lossy().into_owned(),
        tail_path.to_string_lossy().into_owned(),
        "msg_v1_5p1i7000-0000-4000-8000-000000000001".to_string(),
    )
}

#[test]
fn session_split_across_files_syncs_and_assembles_one_context() {
    // 修复前：两个源各自声明同一 ses_v1_ 却带不同成员列表，提交层判为冲突投影
    // 并整批拒绝（catalog_error / exit 6），真实语料因此完全无法入库。
    let (dir, db) = temp_db("split-session-one-batch");
    let (head, tail, anchor_message) = write_split_session_fixture(dir.path());

    let out = run(&db, &["sync", &head, &tail]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["messages"], 4, "frame={frame}");
    let session_wire = session_wire_for_message(&db, &anchor_message);

    // 会话实体承载两个源的成员并集，并记录两个贡献文档。
    let out = run(&db, &["show", &session_wire]);
    assert!(out.status.success(), "show failed: {}", stdout(&out));
    let entity = parse_first_line(&out)["data"]["entity"].clone();
    let members = entity["messages"].as_array().expect("session.messages");
    assert_eq!(members.len(), 4, "entity={entity}");
    let documents = entity["documents"].as_array().expect("session.documents");
    assert_eq!(documents.len(), 2, "entity={entity}");
    // 单值 `document` 是兼容别名：多文档会话上它只指其中一个贡献者。
    assert!(
        entity["document"]
            .as_str()
            .is_some_and(|d| d.starts_with("doc_v1_")),
        "entity={entity}"
    );

    // 跨文件的 parent 边可解析：mainline 链跨越两个源文件。
    let out = run(&db, &["context", &session_wire]);
    assert!(out.status.success(), "context failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_eq!(frame["outcome"], "success");
    let wires: Vec<&str> = frame["data"]["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .map(|m| m["id"].as_str().expect("message.id"))
        .collect();
    assert_eq!(
        wires,
        vec![
            "msg_v1_5p1i7000-0000-4000-8000-000000000001",
            "msg_v1_5p1i7000-0000-4000-8000-000000000002",
            "msg_v1_5p1i7000-0000-4000-8000-000000000004",
        ],
        "frame={frame}"
    );
    assert_eq!(
        frame["data"]["branch_leaf"],
        "msg_v1_5p1i7000-0000-4000-8000-000000000004"
    );
}

#[test]
fn shared_message_keeps_per_session_parent_and_exact_evidence_across_split_sources() {
    let (dir, db) = temp_db("relational-context-shapes");
    let fixture = write_relational_context_fixture(dir.path());
    let out = run(
        &db,
        &[
            "sync",
            &fixture.paths[0],
            &fixture.paths[1],
            &fixture.paths[2],
        ],
    );
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let sync = parse_first_line(&out);
    assert_eq!(sync["data"]["emitted"], 4);
    assert_eq!(sync["data"]["skipped"], 0);

    let status = run(&db, &["status"]);
    let status = parse_first_line(&status);
    assert_eq!(status["data"]["placements"], 4);
    assert_eq!(status["data"]["source_placement_claims"], 4);

    let list = run(&db, &["list", "20"]);
    let list = parse_first_line(&list);
    let stable_messages = list["data"]["entries"]
        .as_array()
        .expect("list entries")
        .iter()
        .filter(|entry| {
            entry["id"]
                .as_str()
                .is_some_and(|wire| wire.starts_with("msg_v1_"))
        })
        .count();
    assert_eq!(stable_messages, 3, "stable Message census is de-duplicated");

    let shared = run(&db, &["show", &fixture.shared_message]);
    let shared = parse_first_line(&shared)["data"]["entity"].clone();
    assert_eq!(shared["sessions"].as_array().expect("sessions").len(), 2);
    assert_eq!(shared["spans"].as_array().expect("spans").len(), 2);
    assert!(
        shared["parent"].is_null(),
        "divergent parents must not alias"
    );
    assert!(
        shared["parent_native_id"].is_null(),
        "divergent native parents must not alias"
    );

    let session_a_wire = session_wire_for_message(&db, &fixture.session_a);
    let session_b_wire = session_wire_for_message(&db, &fixture.session_b);
    assert_ne!(session_a_wire, session_b_wire);

    let session_a = run(&db, &["show", &session_a_wire]);
    let session_a = parse_first_line(&session_a)["data"]["entity"].clone();
    assert_eq!(
        session_a["documents"]
            .as_array()
            .expect("session A documents")
            .len(),
        2,
        "session A must span both source documents"
    );

    let context_a = run(&db, &["context", &session_a_wire]);
    assert!(
        context_a.status.success(),
        "session A context failed: {}",
        stdout(&context_a)
    );
    let context_a = parse_first_line(&context_a);
    let messages_a = context_a["data"]["messages"]
        .as_array()
        .expect("session A messages");
    assert_eq!(
        messages_a
            .iter()
            .map(|message| message["message_id"].as_str().expect("message id"))
            .collect::<Vec<_>>(),
        vec![fixture.parent_a.as_str(), fixture.shared_message.as_str()]
    );
    let evidence_a = context_a["data"]["evidence"]
        .as_array()
        .expect("session A evidence");
    assert_eq!(
        evidence_a[1]["occurrence_id"],
        messages_a[1]["placement_id"]
    );
    let start_a = evidence_a[1]["byte_start"].as_u64().expect("start A") as usize;
    let end_a = evidence_a[1]["byte_end"].as_u64().expect("end A") as usize;
    assert_eq!(
        &fixture.contents[1].as_bytes()[start_a..end_a],
        fixture.contents[1].trim_end().as_bytes()
    );

    let context_b = run(&db, &["context", &session_b_wire]);
    assert!(
        context_b.status.success(),
        "session B context failed: {}",
        stdout(&context_b)
    );
    let context_b = parse_first_line(&context_b);
    let messages_b = context_b["data"]["messages"]
        .as_array()
        .expect("session B messages");
    assert_eq!(
        messages_b
            .iter()
            .map(|message| message["message_id"].as_str().expect("message id"))
            .collect::<Vec<_>>(),
        vec![fixture.parent_b.as_str(), fixture.shared_message.as_str()]
    );
    let evidence_b = context_b["data"]["evidence"]
        .as_array()
        .expect("session B evidence");
    assert_eq!(
        evidence_b[1]["occurrence_id"],
        messages_b[1]["placement_id"]
    );
    let start_b = evidence_b[1]["byte_start"].as_u64().expect("start B") as usize;
    let end_b = evidence_b[1]["byte_end"].as_u64().expect("end B") as usize;
    assert!(fixture.contents[2].as_bytes()[start_b..end_b].starts_with(br#"{"type":"assistant""#));
    assert_ne!(
        messages_a[1]["placement_id"], messages_b[1]["placement_id"],
        "shared stable Message must retain distinct placements"
    );
    assert_ne!(
        evidence_a[1]["source_document_id"], evidence_b[1]["source_document_id"],
        "each occurrence must retain its exact document"
    );
    assert_ne!(
        evidence_a[1]["byte_start"], evidence_b[1]["byte_start"],
        "each occurrence must retain its exact source-local span"
    );
}

#[test]
fn session_synced_in_separate_invocations_keeps_both_halves() {
    // 真实用法：语料太大，分多次 sync。第二批不得覆盖第一批已记录的成员。
    let (dir, db) = temp_db("split-session-two-batches");
    let (head, tail, anchor_message) = write_split_session_fixture(dir.path());

    let out = run(&db, &["sync", &head]);
    assert!(out.status.success(), "first sync failed: {}", stdout(&out));
    let out = run(&db, &["sync", &tail]);
    assert!(out.status.success(), "second sync failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let out = run(&db, &["show", &session_wire]);
    let entity = parse_first_line(&out)["data"]["entity"].clone();
    assert_eq!(
        entity["messages"].as_array().expect("messages").len(),
        4,
        "第二批 sync 不得丢弃第一批成员: entity={entity}"
    );
    assert_eq!(entity["documents"].as_array().expect("documents").len(), 2);

    // 两个半区都可检索，证明并集是真实可用的而非仅 payload 好看。
    for term in ["\"split root question\"", "\"split final answer\""] {
        let out = run(&db, &["search", term]);
        assert!(out.status.success(), "search failed: {}", stdout(&out));
        let frame = parse_first_line(&out);
        assert!(
            !frame["data"]["hits"].as_array().expect("hits").is_empty(),
            "term={term} frame={frame}"
        );
    }
}

#[test]
fn context_budget_truncation_reports_partial_exit_10() {
    let (dir, db) = temp_db("context-budget");
    let (fixture_path, _, anchor_message) = write_context_fixture(dir.path());
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let out = run(&db, &["context", &session_wire, "--max-messages", "2"]);
    // 部分成功：结果可用但被预算截断 → outcome partial + exit 10（contract §5）。
    assert_eq!(out.status.code(), Some(10), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["outcome"], "partial");
    assert_eq!(frame["data"]["messages"].as_array().unwrap().len(), 2);
    assert_eq!(frame["data"]["truncation"]["truncated"], true);
    assert_eq!(frame["data"]["truncation"]["reason"], "max_messages");
}

#[test]
fn context_missing_session_is_not_found() {
    let (_dir, db) = temp_db("context-missing");
    // `run` 已带 --robot；这里只给子命令参数（重复 --robot 是用法错误，R8.2）。
    let out = run(
        &db,
        &["context", "ses_v1_ffffffff-ffff-4fff-8fff-ffffffffffff"],
    );
    assert_eq!(out.status.code(), Some(4), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "not_found");
}

// ─── Human/Robot 输出真值表（contract §4 §6，child 4）───────────────────────

#[test]
fn human_search_and_status_render_text_not_envelope() {
    let (_dir, db) = temp_db("human-search");
    for (fact, text) in [("h1", "human render alpha"), ("h2", "human render beta")] {
        let out = run(&db, &["index", fact, text]);
        assert!(out.status.success());
    }

    let out = run_human(&db, &["search", "render"]);
    assert!(out.status.success(), "search failed: {}", stdout(&out));
    let s = stdout(&out);
    assert!(s.contains("hit(s) (generation"), "human header: {s}");
    assert!(s.contains("msg_v1_"), "human hits list ids: {s}");
    assert!(
        !s.contains("schema_version"),
        "no envelope in human mode: {s}"
    );

    // 零结果有措辞，不是空输出。
    let out = run_human(&db, &["search", "nomatchword"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no hits"), "got: {}", stdout(&out));

    let out = run_human(&db, &["status"]);
    let s = stdout(&out);
    assert!(s.contains("entities: 2"), "human status: {s}");
    assert!(s.contains("generation:"), "human status: {s}");
}

#[test]
fn human_context_renders_chain_and_partial_exits_10() {
    let (dir, db) = temp_db("human-context");
    let (fixture_path, _, anchor_message) = write_context_fixture(dir.path());
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let out = run_human(&db, &["context", &session_wire]);
    assert!(out.status.success(), "context failed: {}", stdout(&out));
    let s = stdout(&out);
    assert!(
        s.contains(&format!("session {session_wire}")),
        "header: {s}"
    );
    assert!(s.contains("[user] ctx root question"), "messages: {s}");
    assert!(s.contains("evidence: 3 span(s)"), "evidence line: {s}");
    assert!(!s.contains("schema_version"), "no envelope: {s}");

    // 预算截断：human 模式同样如实报 partial（截断行 + exit 10）。
    let out = run_human(&db, &["context", &session_wire, "--max-messages", "2"]);
    assert_eq!(out.status.code(), Some(10), "stdout={}", stdout(&out));
    assert!(
        stdout(&out).contains("truncated: max_messages"),
        "truncation line: {}",
        stdout(&out)
    );
}

#[test]
fn jsonl_sync_emits_progress_frames_then_single_response() {
    let (dir, db) = temp_db("jsonl-progress");
    let mut paths = Vec::new();
    for tag in ["p1", "p2"] {
        let fixture = dir.path().join(format!("{tag}.jsonl"));
        // 每源内容必须不同：同字节 → 同内容寻址 document/session id，
        // 而成员消息不同 → 存储层正确拒绝跨源投影冲突。
        std::fs::write(
            &fixture,
            format!(
                "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"progress fixture {tag}\"}}}}\n"
            ),
        )
        .expect("write fixture");
        paths.push(fixture.to_string_lossy().into_owned());
    }

    let out = Command::new(BIN)
        .args([
            "--db", &db, "--output", "jsonl", "sync", &paths[0], &paths[1],
        ])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    let text = stdout(&out);
    let frames: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("bad frame: {e}\n{line}")))
        .collect();
    // 逐源 progress + 收尾 response，每行一个完整 frame（contract §4）。
    assert_eq!(frames.len(), 3, "2 progress + 1 response: {text}");
    assert_eq!(frames[0]["frame_type"], "progress");
    assert_eq!(frames[1]["frame_type"], "progress");
    assert!(
        frames[0]["message"]
            .as_str()
            .is_some_and(|m| m.contains("scanned")),
        "{text}"
    );
    for frame in &frames[..2] {
        let message = frame["message"].as_str().expect("progress message");
        assert!(
            paths.iter().all(|path| !message.contains(path)),
            "progress must not disclose source paths: {message}"
        );
    }
    assert_eq!(frames[2]["frame_type"], "response");
    assert_eq!(frames[2]["command"], "sync");

    // 指纹缓存命中（重扫同一批源）：措辞如实切换为 checked/unchanged，
    // 不得谎报 "staged (0 messages)"（Minor-4）。
    let out = Command::new(BIN)
        .args([
            "--db", &db, "--output", "jsonl", "sync", &paths[0], &paths[1],
        ])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "resync failed: {}", stdout(&out));
    let text = stdout(&out);
    let frames: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("bad frame: {e}\n{line}")))
        .collect();
    assert_eq!(frames.len(), 3, "2 checked + 1 response: {text}");
    assert!(
        frames[0]["message"]
            .as_str()
            .is_some_and(|m| m.contains("checked source 1/2") && m.contains("unchanged")),
        "resync progress must say checked/unchanged: {text}"
    );
    assert!(
        frames[1]["message"]
            .as_str()
            .is_some_and(|m| m.contains("checked source 2/2")),
        "resync progress must say checked/unchanged: {text}"
    );

    // --robot 禁 progress：同一命令只有一个 response envelope。
    let (_dir2, db2) = temp_db("robot-no-progress");
    let out = Command::new(BIN)
        .args(["--db", &db2, "--robot", "sync", &paths[0], &paths[1]])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let text = stdout(&out);
    assert_eq!(
        text.lines().count(),
        1,
        "robot mode must not emit progress: {text}"
    );
    let frame = parse_first_line(&out);
    assert_eq!(frame["frame_type"], "response");
}

#[test]
fn request_id_echoes_verbatim_and_invalid_is_rejected() {
    let (_dir, db) = temp_db("request-id");
    let out = Command::new(BIN)
        .args([
            "--db",
            &db,
            "--robot",
            "--request-id",
            "corr.42:a_b-c",
            "status",
        ])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    assert_eq!(
        frame["request_id"], "corr.42:a_b-c",
        "echo verbatim: {frame}"
    );

    // 非法 request-id 是用法错误（exit 2），不静默替换。
    let out = Command::new(BIN)
        .args(["--db", &db, "--robot", "--request-id", "bad id", "status"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_eq!(frame["error"]["code"], "invalid_request");
}

#[test]
fn context_envelope_carries_warnings_array_on_modern_store() {
    let (dir, db) = temp_db("warnings-plumbing");
    let (fixture_path, _, anchor_message) = write_context_fixture(dir.path());
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success());
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let out = run(&db, &["context", &session_wire]);
    assert!(out.status.success());
    let frame = parse_first_line(&out);
    // 现代库全部 byte 精度 → warnings 存在且为空（通路端到端可见；
    // 有 unknown 精度时的告警文案由 main.rs 单测锁定，见 design §0.2）。
    assert_eq!(frame["warnings"], serde_json::json!([]), "{frame}");
}

// ─── 初始性能基线 ───────────────────────────────────────────────────────────

#[test]
fn perf_baseline_100_messages_index_and_search() {
    let (_dir, db) = temp_db("perf-baseline");
    let start = std::time::Instant::now();

    // 写入 100 条消息
    for i in 0..100u32 {
        let fact = format!("perf-fact-{i}");
        let text = format!("performance baseline message number {i} with unique content");
        let out = run(&db, &["index", &fact, &text]);
        assert!(out.status.success(), "index {i} failed: {}", stdout(&out));
    }
    let index_ms = start.elapsed().as_millis();

    // 全文检索应命中
    let search_start = std::time::Instant::now();
    let out = run(&db, &["search", "performance baseline"]);
    let query_ms = search_start.elapsed().as_millis();

    assert!(out.status.success());
    assert!(
        stdout(&out).contains("msg_v1_"),
        "search must return results"
    );

    // 仅输出历史 smoke 基线供观察。正式性能分布、环境和样本量由
    // scripts/evidence/core_beta_benchmark.py 负责；普通 CI 机器不以固定墙钟阈值阻断。
    eprintln!("[perf-baseline] index 100 msgs: {index_ms}ms  search: {query_ms}ms");
}

// ─── UX review 修复后的契约回归（R8 解析健壮性 / R2 隐私 / R4 字面量 / R1 snippet）───

#[test]
fn value_flags_reject_missing_value_or_flag_named_value() {
    // R8.1：--db / --request-id 缺值或取值是已知 flag 都是用法错误（exit 2），
    // `--db --robot status` 不得造出名为 `--robot` 的文件。这些错误在 human
    // 模式走 stderr 诊断，stdout 保持协议干净。
    let (dir, db) = temp_db("value-flag");
    let db_s = db;
    let robot_cwd = dir.path().join("cwd");
    std::fs::create_dir_all(&robot_cwd).expect("cwd dir");
    let robot_cwd_s = robot_cwd.to_string_lossy().into_owned();
    let cases: Vec<(Vec<String>, &str)> = vec![
        (
            vec!["--db".into(), "--robot".into(), "status".into()],
            "--db requires a path",
        ),
        (vec!["--db".into()], "--db requires a path"),
        (
            vec![
                "--db".into(),
                "a.db".into(),
                "--db".into(),
                "b.db".into(),
                "status".into(),
            ],
            "duplicate --db",
        ),
        (
            vec!["--request-id".into(), "--robot".into(), "status".into()],
            "--request-id requires a value",
        ),
        (
            vec![
                "--request-id".into(),
                "a".into(),
                "--request-id".into(),
                "b".into(),
                "status".into(),
            ],
            "duplicate --request-id",
        ),
    ];
    for (args, needle) in &cases {
        let out = Command::new(BIN)
            .current_dir(&robot_cwd)
            .args(args)
            .output()
            .expect("spawn");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: stdout={}",
            stdout(&out)
        );
        assert!(
            stdout(&out).is_empty(),
            "human 模式 stdout 应保持协议干净: {args:?} {}",
            stdout(&out)
        );
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            stderr.contains(needle),
            "{args:?} 应报 {needle:?}: {stderr}"
        );
    }
    // `--db --robot status` 不得把 `--robot` 当路径创建文件（R8.1）。
    let robot_file = robot_cwd.join("--robot");
    assert!(
        !robot_file.exists(),
        "不得创建名为 --robot 的文件: {}",
        robot_cwd_s
    );
    // 同一组参数在机器人模式（前缀 --robot）下输出错误 envelope。
    let out = run(&db_s, &["--db", "bogus-path", "status"]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "invalid_request");
    assert!(
        frame["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("duplicate --db")),
        "{frame}"
    );
}

#[test]
fn conflicting_output_flags_are_usage_errors() {
    // R8.2：--output 与 --robot 冲突、--output 重复都不允许静默 first-wins。
    for args in [
        vec!["--output", "human", "--robot", "status"],
        vec!["--robot", "--output", "yaml", "status"],
        vec!["--output", "json", "--output", "yaml", "status"],
        vec!["--robot", "--robot", "status"],
    ] {
        let out = run_bare(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stdout(&out));
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, false);
        assert_eq!(
            frame["error"]["code"], "invalid_request",
            "{args:?}: {frame}"
        );
        // 具体措辞随触发点而变（冲突/重复/非法值），契约点是 usage error。
        assert!(
            frame["error"]["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "{args:?}: {frame}"
        );
    }
}

#[test]
fn doctor_and_config_reject_unknown_tokens() {
    // R8.3：doctor/config 的多余位置参数是用法错误，不再静默丢弃后 exit 0。
    let out = run_bare(&["--robot", "doctor", "--bogus"]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "invalid_request");
    assert_eq!(frame["command"], "doctor", "{frame}");

    let out = run_bare(&["--robot", "config", "paths", "--bogus"]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "invalid_request");
    assert_eq!(frame["command"], "config", "{frame}");
}

#[test]
fn error_envelope_command_points_at_the_failing_token() {
    // R8.4：未知 `-` 开头 token 是命令名笔误，envelope 的 `command` 指向它，
    // 而不是后面的真命令。
    let out = run_bare(&["--bogus", "--robot", "status"]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["command"], "--bogus", "{frame}");
}

#[test]
fn sync_directory_rejection_is_path_free_and_platform_neutral() {
    // R2.2：sync 传目录 → invalid_request（exit 2）；消息不含路径，展开示例
    // 平台中立（不给 PowerShell-only 的 Get-ChildItem 例子）。robot envelope
    // 与 human stderr 双验证。
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path = dir.path().to_string_lossy().into_owned();
    let (_dbdir, db) = temp_db("sync-dir");

    let out = run(&db, &["sync", &dir_path]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    assert_eq!(frame["error"]["code"], "invalid_request");
    let robot_text = stdout(&out);
    assert!(!robot_text.contains(&dir_path), "路径外泄: {robot_text}");
    assert!(
        !robot_text.contains("PowerShell") && !robot_text.contains("Get-ChildItem"),
        "平台中立: {robot_text}"
    );

    let out = run_human(&db, &["sync", &dir_path]);
    assert_eq!(out.status.code(), Some(2), "stdout={}", stdout(&out));
    let human_text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!human_text.contains(&dir_path), "路径外泄: {human_text}");
    assert!(
        !human_text.contains("PowerShell") && !human_text.contains("Get-ChildItem"),
        "平台中立: {human_text}"
    );
}

#[test]
fn literal_queries_with_fts_special_characters_succeed() {
    // ADR-0003（R4.1）：冒号/点号/连字符与 FTS 操作符（AND/OR/NOT/NEAR/引号/*）
    // 都是字面量 token——查询成功（exit 0），绝不触发 FTS 语法错误或
    // catalog_error；命中按字面匹配。
    let (_dir, db) = temp_db("literal");
    for (fact, text) in [
        ("l1", "configure the mcp.json bridge"),
        ("l2", "ratio a:b and range x-y"),
        ("l3", "AND OR NOT are ordinary words here"),
        ("l4", "quoted \"phrase\" words"),
        ("l5", "star * literal"),
    ] {
        let out = run(&db, &["index", fact, text]);
        assert!(out.status.success(), "index {fact}: {}", stdout(&out));
    }
    // 每类特殊字符查询都成功且只字面命中对应文档（FTS5 短语匹配 = 相邻 token，
    // 保留字符不再解释为语法）；`*` 单独是纯标点词 → 空查询 → 0 命中但 exit 0。
    let hit_count = |query: &str| -> usize {
        let out = run(&db, &["search", query]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "query {query:?} 不得报错: {}",
            stdout(&out)
        );
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, true);
        assert_eq!(frame["command"], "search");
        frame["data"]["hits"].as_array().expect("hits").len()
    };
    for (query, expected) in [
        ("mcp.json", 1),
        ("a:b", 1),
        ("x-y", 1),
        // AND 命中 2 条：FTS 分词器大小写不敏感，l2 的 "and" 与 l3 的 "AND"
        // 同 token——行为是字面 token 匹配而非语法，只是大小写折叠。
        ("AND", 2),
        ("OR", 1),
        ("NOT", 1),
        ("\"phrase\"", 1),
    ] {
        assert_eq!(
            hit_count(query),
            expected,
            "query {query:?} 应字面命中 {expected} 条"
        );
    }
    // NEAR 无对应文本：成功且空命中；`*` 同理（纯标点 → 空查询）。
    for query in ["NEAR", "*"] {
        let out = run(&db, &["search", query]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "query {query:?}: {}",
            stdout(&out)
        );
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, true);
    }
}

#[test]
fn control_characters_in_query_are_invalid_request() {
    // R4.2：控制字符在 Application 边界拒绝为 invalid_request（exit 2），
    // 绝不清除式净化（删除会拼接 token）。Windows 命令行无法传递 NUL
    // （std::process::Command 拒绝 NUL 参数），故 e2e 用 C0 非 NUL 控制字符；
    // NUL 本身的边界拒绝由 application 层单元测试覆盖
    // （search_rejects_control_characters_before_index_query）。
    let (_dir, db) = temp_db("nul-query");
    for query in ["a\tb", "a\nb"] {
        let out = run(&db, &["search", query]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "query {query:?}: {}",
            stdout(&out)
        );
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, false);
        assert_eq!(frame["error"]["code"], "invalid_request", "{frame}");
        assert!(
            !stdout(&out).contains("backend") && !stdout(&out).contains("fts5"),
            "不得泄漏后端细节: {}",
            stdout(&out)
        );
    }
}

#[test]
fn snippet_renders_in_human_search_but_is_stripped_in_machine_modes() {
    // R1/ADR-0004 + 2026-08-14 决策：human search 渲染冻结的五列会话表
    // （日期 | Provider | 会话标题 | 工作目录 | Session ID）；snippet 字段只在
    // 旧版 per-hit 渲染中存在，机器模式（robot/json/jsonl）一律不得携带。
    let (dir, db) = temp_db("snippet");
    let fixture = dir.path().join("snippet.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"type":"user","uuid":"s0000000-0000-4000-8000-000000000001","sessionId":"s0000000-0000-4000-8000-000000000002","timestamp":"2026-07-26T01:00:00.000Z","message":{"role":"user","content":"snippet visible in human output"}}"#,
            "\n",
        ),
    )
    .expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));

    let out = run_human(&db, &["search", "snippet"]);
    assert!(
        out.status.success(),
        "human search failed: {}",
        stdout(&out)
    );
    let human = stdout(&out);
    assert!(
        human.contains("日期")
            && human.contains("Provider")
            && human.contains("会话标题")
            && human.contains("工作目录")
            && human.contains("Session ID"),
        "human 应渲染固定五列表头: {human}"
    );
    assert!(
        human.contains("claude-code"),
        "human 应渲染 Provider 行: {human}"
    );
    // 真实日期（消息 timestamp 的 YYYY-MM-DD）和标题（命中 text）应被渲染，
    // 而不是固定回退为 —。
    assert!(
        human.contains("2026-07-26"),
        "human 应渲染真实最近活动日期: {human}"
    );
    assert!(
        human.contains("snippet vis"),
        "human 应以命中 text 作为会话标题（可能被尾部截断）: {human}"
    );

    for machine_args in [
        vec!["--db", &db, "--robot", "search", "snippet"],
        vec!["--db", &db, "--output", "json", "search", "snippet"],
        vec!["--db", &db, "--output", "jsonl", "search", "snippet"],
    ] {
        let out = Command::new(BIN)
            .args(&machine_args)
            .output()
            .expect("spawn");
        assert!(out.status.success(), "{machine_args:?}: {}", stdout(&out));
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, true);
        let hits = frame["data"]["hits"].as_array().expect("hits").clone();
        assert!(!hits.is_empty(), "{machine_args:?}: {frame}");
        for hit in hits {
            assert!(
                hit.get("snippet").is_none(),
                "机器模式不得携带 snippet: {machine_args:?} {frame}"
            );
        }
    }
}

#[test]
fn golden_broken_line_syncs_with_visible_diagnostic() {
    // R2.3：仓库固定的 Claude golden fixture 内含一条故意截断行。真实 sync
    // 必须成功，并把 parser 的行号诊断通过公开 warnings 通道带给调用方。
    let (_dir, db) = temp_db("golden-broken-line");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-session-grep-provider-claude/tests/golden/basic.jsonl");
    let fixture_path = fixture.to_string_lossy().into_owned();
    let out = run(&db, &["sync", &fixture_path]);
    assert!(
        out.status.success(),
        "golden fixture must sync: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["skipped"], 1, "{frame}");
    assert_eq!(frame["data"]["diagnostics"], 1, "{frame}");
    let warnings = frame["warnings"].as_array().expect("warnings");
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|text| text.contains("line 5") && text.contains("invalid JSON"))),
        "broken-line diagnostic must be visible: {frame}"
    );
}

#[test]
fn fatal_source_rejection_reports_line_numbers_and_repair_direction() {
    // R2.2：超过 probe 容忍度的结构性破损必须失败；错误不能只说 provider
    // 未识别，而要保留行号和修复方向。
    let (dir, db) = temp_db("fatal-line-detail");
    let fixture = dir.path().join("fatal-lines.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            "bad one\n",
            "bad two\n",
            "bad three\n",
            "bad four\n",
            r#"{"type":"user","uuid":"fatal-valid","message":{"role":"user","content":"kept only as probe evidence"}}"#,
        ),
    )
    .expect("write fatal fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();
    let out = run(&db, &["ingest", &fixture_path]);
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, false);
    let message = frame["error"]["message"].as_str().expect("message");
    // 多个 provider adapter 都拒绝时，错误应保留行号定位与修复方向。
    // Claude adapter 给出 "第 1、2、3、4 行"；Grok adapter 给出 "no ACP
    // sessionUpdate"。任一 adapter 的诊断都满足"给出具体原因"的要求。
    assert!(
        message.contains("第 1、2、3、4 行") || message.contains("no provider recognized"),
        "fatal rejection must identify lines or report no provider: {message}"
    );
    assert!(
        message.contains("修复") && message.contains("重试") || message.contains("no provider"),
        "fatal rejection must give repair direction or report no provider: {message}"
    );
}

#[test]
fn multi_session_file_emits_visible_session_diagnostic() {
    // R3.1：provider 已检测同文件多 sessionId；CLI 必须实际公开数量和 ID，
    // 不能只把 diagnostics 数量从 0 改成 1 后仍让用户看不到原因。
    let (dir, db) = temp_db("multi-session-warning");
    let fixture = dir.path().join("multi-session.jsonl");
    let first = serde_json::json!({
        "type": "user",
        "uuid": "multi-message-first",
        "sessionId": "multi-session-first",
        "message": { "role": "user", "content": "merged session diagnostic" },
    });
    let second = serde_json::json!({
        "type": "assistant",
        "uuid": "multi-message-second",
        "sessionId": "multi-session-second",
        "message": { "role": "assistant", "content": "merged session diagnostic reply" },
    });
    std::fs::write(&fixture, format!("{first}\n{second}\n")).expect("write fixture");
    let fixture_path = fixture.to_string_lossy().into_owned();
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["diagnostics"], 1, "{frame}");
    let warnings = frame["warnings"].as_array().expect("warnings");
    let diagnostic = warnings
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find(|warning| warning.contains("2 个不同 sessionId"))
        .unwrap_or_else(|| panic!("multi-session diagnostic missing: {frame}"));
    assert!(diagnostic.contains("multi-session-first"), "{diagnostic}");
    assert!(diagnostic.contains("multi-session-second"), "{diagnostic}");
    assert!(diagnostic.contains("归属首个会话"), "{diagnostic}");
}

// ─── R4/ADR-0008：search 命中携带 session_id 与 text 摘要 ───────────────────

/// 带 sessionId 的合成 Claude 夹具：返回（路径、锚点消息 ID、两条消息正文）。
/// `long` 为 true 时两条正文都超长（用于字节预算截断用例）。
fn write_session_hits_fixture(dir: &Path, long: bool) -> (String, String, String, String) {
    let body_a = if long {
        format!("widgets in the attic{}", "x".repeat(2000))
    } else {
        "widgets in the attic".into()
    };
    let body_b = if long {
        format!("widgets reply{}", "y".repeat(2000))
    } else {
        "widgets reply".to_string()
    };
    let line_a = serde_json::json!({
        "type": "user",
        "uuid": "aaaa1111-2222-4333-8444-555566667777",
        "sessionId": "abcd1234-5678-4abc-8def-aabbccddeeff",
        "message": { "role": "user", "content": body_a },
    })
    .to_string();
    let line_b = serde_json::json!({
        "type": "assistant",
        "uuid": "bbbb2222-3333-4444-8555-666677778888",
        "sessionId": "abcd1234-5678-4abc-8def-aabbccddeeff",
        "message": { "role": "assistant", "content": body_b },
    })
    .to_string();
    let fixture = dir.join("session-hits.jsonl");
    std::fs::write(&fixture, format!("{line_a}\n{line_b}\n")).expect("write fixture");
    (
        fixture.to_string_lossy().into_owned(),
        "msg_v1_aaaa1111-2222-4333-8444-555566667777".into(),
        body_a,
        body_b,
    )
}

#[test]
fn search_robot_hits_carry_session_id_and_text() {
    // R4/ADR-0008：robot 搜索命中携带 session_id（所属会话 wire id）与 text
    // （正文摘要，按 max_snippet_chars 截取）。追加字段、无字段删除：id/score
    // 原样保留，机器模式仍不带 human-only 的 snippet。
    let (dir, db) = temp_db("hit-session-context");
    let (fixture_path, anchor_message, body_a, body_b) =
        write_session_hits_fixture(dir.path(), false);
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let out = run(&db, &["search", "widgets"]);
    assert!(out.status.success(), "search failed: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    let hits = frame["data"]["hits"].as_array().expect("hits");
    assert_eq!(hits.len(), 2, "{frame}");
    // 两条消息同属一个会话：session_id 都指向该会话的 wire id。
    for hit in hits {
        assert_eq!(hit["session_id"], session_wire, "{hit}");
        assert!(
            hit["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("msg_v1_")),
            "{hit}"
        );
        assert!(hit["score"].is_number(), "{hit}");
        assert!(
            hit.get("snippet").is_none(),
            "机器模式不得携带 snippet: {hit}"
        );
    }
    // text 摘要与消息正文一致（短正文不截断）。
    let texts: Vec<&str> = hits
        .iter()
        .map(|hit| hit["text"].as_str().expect("hit text"))
        .collect();
    assert!(texts.contains(&body_a.as_str()), "{texts:?}");
    assert!(texts.contains(&body_b.as_str()), "{texts:?}");
}

#[test]
fn search_byte_budget_truncates_but_keeps_session_context_in_hits() {
    // R4.2：摘要字节计入 max_response_bytes 字节闸。两条 2000+ 字符正文的命中
    // 在最小预算 4096（净 3072）下必然被截断（即使按最宽松的字节估算也放不下
    // 两条）；截断原因显式（max_response_bytes），保留下来的命中仍携带
    // session_id/text。
    let (dir, db) = temp_db("hit-session-budget");
    let (fixture_path, anchor_message, body_a, body_b) =
        write_session_hits_fixture(dir.path(), true);
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let out = run(&db, &["search", "widgets", "--max-bytes", "4096"]);
    // 预算截断按 contract §5 exit 10（partial）：结果可用但不完整，不伪装 success。
    assert_eq!(
        out.status.code(),
        Some(10),
        "预算截断应 exit 10: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["outcome"], "partial", "{frame}");
    assert_eq!(
        frame["data"]["truncation"]["truncated"], true,
        "字节预算必须显式截断: {frame}"
    );
    assert_eq!(
        frame["data"]["truncation"]["reason"], "max_response_bytes",
        "截断原因必须显式: {frame}"
    );
    let hits = frame["data"]["hits"].as_array().expect("hits");
    assert!(
        hits.len() < 2,
        "两条长正文命中放不进 4096 字节预算: {frame}"
    );
    for hit in hits {
        // 截断后保留的命中仍是完整命中：session_id/text 不因截断而丢失。
        assert_eq!(hit["session_id"], session_wire, "{hit}");
        let text = hit["text"].as_str().expect("hit text");
        assert!(!text.is_empty(), "{hit}");
        assert!(
            text.chars().count() <= 2000,
            "text 摘要不得超过 max_snippet_chars: {hit}"
        );
        assert!(
            body_a.starts_with(text) || body_b.starts_with(text),
            "摘要应是正文前缀: {hit}"
        );
    }
}

#[test]
fn mcp_search_sessions_hits_carry_session_id_and_text() {
    // R4/ADR-0008：MCP search_sessions 命中与 CLI 共用同一 render 投影，携带
    // 追加的 session_id/text；id/score 与既有字段不删除（无字段删除，schema
    // minor）。tight 预算下 outcome=partial、截断原因显式。
    let (dir, db) = temp_db("mcp-hit-session-context");
    let (fixture_path, anchor_message, body_a, _) = write_session_hits_fixture(dir.path(), false);
    let out = run(&db, &["ingest", &fixture_path]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor_message);

    let inputs = [
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "e2e", "version": "0" } }
        }),
        serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "search_sessions", "arguments": { "query": "widgets" } }
        }),
    ];
    let frames = mcp_frames(&db, &inputs);
    let search = frames
        .iter()
        .find(|frame| frame["id"] == serde_json::json!(2))
        .expect("search response frame");
    assert_eq!(search["result"]["isError"], false, "{search}");
    let payload = &search["result"]["structuredContent"];
    let hits = payload["data"]["hits"].as_array().expect("hits");
    assert_eq!(hits.len(), 2, "{search}");
    for hit in hits {
        assert_eq!(hit["session_id"], session_wire, "{hit}");
        assert!(
            hit["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("msg_v1_")),
            "{hit}"
        );
        assert!(hit["score"].is_number(), "{hit}");
        assert!(hit["text"].as_str().is_some_and(|t| !t.is_empty()), "{hit}");
    }
    assert!(
        hits.iter().any(|hit| hit["text"] == body_a),
        "MCP 命中应携带正文摘要: {search}"
    );
}

// ─── search provider/time 过滤（08-13）：--provider/--since/--until ──────────

/// 双 provider 共享 token 夹具：Claude 两条（带时间戳）+ Codex 一条
/// （现代 codex 消息 timestamp 为 null）。Codex 消息被时间维度排除是
/// design 的明示语义（authoritative timestamp 缺失即不匹配时间谓词）。
fn write_filter_fixtures(dir: &Path) -> (String, String) {
    let claude = dir.join("filter-claude.jsonl");
    std::fs::write(
        &claude,
        concat!(
            r#"{"type":"user","uuid":"f1111111-1111-4111-8111-111111111111","sessionId":"fa111111-1111-4111-8111-111111111111","timestamp":"2026-07-01T00:00:00.000Z","message":{"role":"user","content":"filterme early note"}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"f1111111-1111-4111-8111-111111111112","parentUuid":"f1111111-1111-4111-8111-111111111111","sessionId":"fa111111-1111-4111-8111-111111111111","timestamp":"2026-07-28T00:00:00.000Z","message":{"role":"assistant","content":"filterme mid note"}}"#,
            "\n",
        ),
    )
    .expect("write claude filter fixture");
    let codex = dir.join("filter-codex.jsonl");
    std::fs::write(
        &codex,
        concat!(
            r#"{"timestamp":"2026-08-10T00:00:00.000Z","type":"session_meta","payload":{"session_id":"fb222222-2222-4222-8222-222222222222","cwd":"/tmp","originator":"codex","cli_version":"1.0"}}"#,
            "\n",
            r#"{"timestamp":"2026-08-10T00:01:00.000Z","type":"response_item","payload":{"type":"message","id":"msg_filter_codex","role":"user","content":[{"type":"input_text","text":"filterme codex note"}]}}"#,
            "\n",
        ),
    )
    .expect("write codex filter fixture");
    (
        claude.to_string_lossy().into_owned(),
        codex.to_string_lossy().into_owned(),
    )
}

fn filter_db(tag: &str) -> (tempfile::TempDir, String) {
    let (dir, db) = temp_db(tag);
    let (claude, codex) = write_filter_fixtures(dir.path());
    for fixture in [&claude, &codex] {
        let out = run(&db, &["ingest", fixture]);
        assert!(out.status.success(), "ingest {fixture}: {}", stdout(&out));
    }
    (dir, db)
}

fn filtered_hit_ids(db: &str, extra: &[&str]) -> Vec<String> {
    let mut args = vec!["search", "filterme"];
    args.extend_from_slice(extra);
    let out = run(db, &args);
    assert!(
        out.status.success(),
        "search {args:?} failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    hit_ids(&frame)
}

fn bucket(ids: &[String], db: &str) -> (usize, usize, usize) {
    let mut buckets = (0, 0, 0);
    for id in ids {
        let out = run(db, &["show", id]);
        assert!(out.status.success(), "show {id}: {}", stdout(&out));
        let text = parse_first_line(&out)["data"]["entity"]["text"]
            .as_str()
            .expect("entity text")
            .to_string();
        match text.as_str() {
            "filterme early note" => buckets.0 += 1,
            "filterme mid note" => buckets.1 += 1,
            "filterme codex note" => buckets.2 += 1,
            other => panic!("unexpected hit body: {other}"),
        }
    }
    buckets
}

#[test]
fn omitted_filters_preserve_baseline_search_results() {
    let (_dir, db) = filter_db("filter-baseline");
    let ids = filtered_hit_ids(&db, &[]);
    assert_eq!(ids.len(), 3, "baseline={ids:?}");
    assert_eq!(bucket(&ids, &db), (1, 1, 1), "{ids:?}");
}

#[test]
fn provider_filter_subsets_and_multi_provider_or() {
    let (_dir, db) = filter_db("filter-provider");
    let claude = filtered_hit_ids(&db, &["--provider", "claude"]);
    assert_eq!(bucket(&claude, &db), (1, 1, 0), "{claude:?}");
    let codex = filtered_hit_ids(&db, &["--provider", "codex"]);
    assert_eq!(bucket(&codex, &db), (0, 0, 1), "{codex:?}");
    let both = filtered_hit_ids(&db, &["--provider", "codex", "--provider", "claude"]);
    assert_eq!(bucket(&both, &db), (1, 1, 1), "{both:?}");
    let dup = filtered_hit_ids(&db, &["--provider", "claude", "--provider", "claude"]);
    assert_eq!(bucket(&dup, &db), (1, 1, 0), "{dup:?}");
}

#[test]
fn time_filter_is_half_open_since_inclusive_until_exclusive() {
    let (_dir, db) = filter_db("filter-time");
    let since = filtered_hit_ids(&db, &["--since", "2026-07-28T00:00:00Z"]);
    assert_eq!(bucket(&since, &db), (0, 1, 0), "since inclusive: {since:?}");
    let until = filtered_hit_ids(&db, &["--until", "2026-07-28T00:00:00Z"]);
    assert_eq!(bucket(&until, &db), (1, 0, 0), "until exclusive: {until:?}");
    let window = filtered_hit_ids(
        &db,
        &[
            "--since",
            "2026-07-01T00:00:01Z",
            "--until",
            "2026-07-28T00:00:00Z",
        ],
    );
    assert!(window.is_empty(), "[early+1s, mid) 应为空: {window:?}");
    let offset = filtered_hit_ids(&db, &["--since", "2026-07-28T02:00:00+02:00"]);
    assert_eq!(offset, since, "offset 形式应归一化为同一 UTC 下界");
}

#[test]
fn provider_and_time_dimensions_are_anded() {
    let (_dir, db) = filter_db("filter-and");
    let hits = filtered_hit_ids(
        &db,
        &["--provider", "claude", "--since", "2026-07-28T00:00:00Z"],
    );
    assert_eq!(bucket(&hits, &db), (0, 1, 0), "{hits:?}");
    let empty = filtered_hit_ids(
        &db,
        &["--provider", "claude", "--until", "2026-07-01T00:00:00Z"],
    );
    assert!(empty.is_empty(), "零匹配应返回干净空页: {empty:?}");
    let out = run(
        &db,
        &[
            "search",
            "filterme",
            "--provider",
            "claude",
            "--until",
            "2026-07-01T00:00:00Z",
        ],
    );
    let frame = parse_first_line(&out);
    assert_envelope_shape(&frame, true);
    assert_eq!(frame["data"]["hits"].as_array().expect("hits").len(), 0);
    assert_eq!(frame["page"]["has_more"], false, "{frame}");
    assert!(frame["page"]["next_cursor"].is_null(), "{frame}");
}

#[test]
fn invalid_filters_are_usage_errors() {
    let (_dir, db) = filter_db("filter-invalid");
    for args in [
        vec!["search", "filterme", "--provider", "gemini"],
        vec!["search", "filterme", "--since", "yesterday-ish"],
        vec!["search", "filterme", "--until", "2026-07-28 12:00:00"],
        vec![
            "search",
            "filterme",
            "--since",
            "2026-08-10T00:00:00Z",
            "--until",
            "2026-07-01T00:00:00Z",
        ],
        vec![
            "search",
            "filterme",
            "--since",
            "2026-07-28T00:00:00Z",
            "--until",
            "2026-07-28T00:00:00Z",
        ],
        vec!["search", "filterme", "--provider"],
        vec!["search", "filterme", "--since"],
    ] {
        let out = run(&db, &args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} 应是 usage error: {}",
            stdout(&out)
        );
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, false);
        assert_eq!(
            frame["error"]["code"], "invalid_request",
            "{args:?}: {frame}"
        );
    }
}

#[test]
fn compact_relative_duration_uses_application_clock() {
    let (_dir, db) = filter_db("filter-relative");
    let recent = filtered_hit_ids(&db, &["--since", "1h"]);
    assert!(recent.is_empty(), "1h 内无任何历史夹具命中: {recent:?}");
    let recent_days = filtered_hit_ids(&db, &["--since", "1d"]);
    assert!(recent_days.is_empty(), "{recent_days:?}");
    let recent_weeks = filtered_hit_ids(&db, &["--since", "1w"]);
    assert!(recent_weeks.is_empty(), "{recent_weeks:?}");
    let before_now = filtered_hit_ids(&db, &["--until", "1h"]);
    assert_eq!(bucket(&before_now, &db), (1, 1, 0), "{before_now:?}");
    let claude_before_now = filtered_hit_ids(&db, &["--until", "1w", "--provider", "claude"]);
    assert_eq!(
        bucket(&claude_before_now, &db),
        (1, 1, 0),
        "{claude_before_now:?}"
    );
}

#[test]
fn cursor_reissued_under_mutated_filters_is_rejected() {
    let (_dir, db) = filter_db("filter-cursor");
    let out = run(
        &db,
        &[
            "search",
            "filterme",
            "--provider",
            "claude",
            "--max-items",
            "1",
        ],
    );
    assert!(out.status.success(), "page1: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let token = frame["page"]["next_cursor"]
        .as_str()
        .expect("page1 must issue next_cursor")
        .to_string();

    let out = run(
        &db,
        &[
            "search",
            "filterme",
            "--provider",
            "claude",
            "--max-items",
            "1",
            "--cursor",
            &token,
        ],
    );
    assert!(out.status.success(), "同过滤续读应成功: {}", stdout(&out));

    for extra in [
        vec!["--provider", "codex"],
        vec!["--provider", "claude", "--since", "2026-07-28T00:00:00Z"],
        vec![],
    ] {
        let mut args: Vec<&str> = vec!["search", "filterme", "--max-items", "1"];
        args.extend_from_slice(&extra);
        args.push("--cursor");
        args.push(&token);
        let out = run(&db, &args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} 应拒绝变更过滤的 cursor: {}",
            stdout(&out)
        );
        let frame = parse_first_line(&out);
        assert_envelope_shape(&frame, false);
        assert_eq!(
            frame["error"]["code"], "cursor_invalid",
            "{args:?}: {frame}"
        );
    }
}

/// 跑一个完整 MCP stdio 会话（逐行喂入 → EOF → 收集全部响应帧）。
/// 只用于本文件内的 MCP 断言；mcp_e2e.rs 另有完整矩阵。
fn mcp_frames(db: &str, inputs: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = Command::new(BIN)
        .arg("--db")
        .arg(db)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn agent-session-grep mcp");
    {
        let mut stdin = child.stdin.take().expect("child stdin must be piped");
        for input in inputs {
            writeln!(stdin, "{input}").expect("write stdin frame");
        }
        // 作用域结束丢弃 stdin → EOF，服务器应据此优雅停机。
    }
    let out = child.wait_with_output().expect("wait for mcp server");
    assert!(
        out.status.success(),
        "mcp server must exit 0 on EOF, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    stdout(&out)
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("stdout not pure JSON-RPC: {error}\nline: {line}"))
        })
        .collect()
}

// ─── sync --discover ───────────────────────────────────────────────────────

/// 在一个带隔离 HOME 的临时目录里构造 provider 数据根，让 `sync --discover`
/// 能找到合成 fixture 而不触碰真实用户目录。
fn discover_env() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir for discover home");
    let home = dir.path().to_string_lossy().into_owned();
    // provider_data_root 读 HOME（Unix）/ USERPROFILE（Windows）。
    std::fs::create_dir_all(dir.path().join(".claude").join("projects"))
        .expect("create claude projects root");
    std::fs::create_dir_all(dir.path().join(".codex").join("sessions"))
        .expect("create codex sessions root");
    (dir, home)
}

/// 以隔离 HOME 运行 CLI（robot 模式），让 discover 解析到临时 provider 根。
fn run_with_home(db: &str, home: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.arg("--db").arg(db).arg("--robot").args(args);
    // 两个变量都设，避免平台/继承差异导致 provider_data_root 解析到真实 home。
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd.output()
        .expect("failed to spawn agent-session-grep binary")
}

fn claude_fixture(content: &str) -> String {
    format!(
        r#"{{"type":"user","uuid":"d1c00000-0000-4000-8000-000000000001","parentUuid":null,"sessionId":"d1c00000-0000-4000-8000-000000000002","timestamp":"2026-08-14T01:00:00.000Z","message":{{"role":"user","content":{content}}}}}"#
    )
}

fn codex_fixture(content: &str) -> String {
    // Codex rollout-style entry (payload.id 是 message id, payload.timestamp 绝对)。
    format!(
        r#"{{"timestamp":"2026-08-14T02:00:00.000Z","type":"response_item","payload":{{"type":"message","id":"d1e00000-0000-4000-8000-000000000001","role":"user","content":[{{"type":"input_text","text":{content}}}]}}}}"#
    )
}

#[test]
fn sync_discover_finds_and_syncs_provider_sources() {
    let (home_dir, home) = discover_env();
    let (_db_dir, db) = temp_db("discover-finds");
    // 在 .claude/projects/<proj>/ 写一个 .jsonl；在 .codex/sessions/ 写一个。
    let claude_proj = home_dir.path().join(".claude").join("projects").join("p1");
    std::fs::create_dir_all(&claude_proj).expect("create claude proj dir");
    let claude_file = claude_proj.join("c1.jsonl");
    std::fs::write(
        &claude_file,
        format!("{}\n", claude_fixture("\"discover claude hello\"")),
    )
    .expect("write claude fixture");
    let codex_dir = home_dir.path().join(".codex").join("sessions");
    let codex_file = codex_dir.join("r1.jsonl");
    std::fs::write(
        &codex_file,
        format!("{}\n", codex_fixture("\"discover codex hello\"")),
    )
    .expect("write codex fixture");

    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(
        out.status.success(),
        "sync --discover failed: {}",
        stdout(&out)
    );
    let frame = parse_first_line(&out);
    assert_eq!(frame["command"], "sync", "{frame}");
    assert_eq!(frame["outcome"], "success", "{frame}");
    let discovery = &frame["data"]["discovery"];
    let providers = discovery["providers"].as_array().expect("providers");
    let claude = providers
        .iter()
        .find(|p| p["id"] == "claude-code")
        .expect("claude-code in discovery");
    assert_eq!(claude["found"], 1, "{frame}");
    assert_eq!(claude["complete"], true, "{frame}");
    let codex = providers
        .iter()
        .find(|p| p["id"] == "codex")
        .expect("codex in discovery");
    assert_eq!(codex["found"], 1, "{frame}");
    assert_eq!(codex["complete"], true, "{frame}");
    // grok-build is registered but has no discovery root in this env →
    // complete:false, found:0. Overall discovery may be incomplete.
    let grok = providers
        .iter()
        .find(|p| p["id"] == "grok-build")
        .expect("grok-build in discovery");
    assert_eq!(grok["found"], 0, "{frame}");
    assert_eq!(grok["complete"], false, "{frame}");
    // 结果里绝不暴露绝对 transcript 路径（隐私契约）。
    let blob = stdout(&out);
    assert!(
        !blob.contains("projects/p1") && !blob.contains("sessions/r1"),
        "discovery result must not leak absolute transcript paths: {blob}"
    );

    // 两个 provider 的消息都可检索。
    let out = run_with_home(&db, &home, &["search", "claude"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "claude search: {}",
        stdout(&out)
    );
    let out = run_with_home(&db, &home, &["search", "codex"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "codex search: {}",
        stdout(&out)
    );
}

#[test]
fn sync_discover_re_runs_converge() {
    let (home_dir, home) = discover_env();
    let (_db_dir, db) = temp_db("discover-converge");
    let claude_proj = home_dir
        .path()
        .join(".claude")
        .join("projects")
        .join("conv");
    std::fs::create_dir_all(&claude_proj).expect("create claude proj dir");
    let claude_file = claude_proj.join("conv.jsonl");
    std::fs::write(
        &claude_file,
        format!("{}\n", claude_fixture("\"converge hello\"")),
    )
    .expect("write claude fixture");

    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "first discover: {}", stdout(&out));
    let first = parse_first_line(&out);
    let gen1 = first["data"]["generation"].as_u64().expect("generation");

    // 第二次 discover，无变化：no-op，generation 不推进。
    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "second discover: {}", stdout(&out));
    let second = parse_first_line(&out);
    let gen2 = second["data"]["generation"].as_u64().expect("generation");
    assert_eq!(gen1, gen2, "re-run should not advance generation: {second}");
    assert_eq!(second["data"]["committed"], 0, "{second}");
}

#[test]
fn sync_discover_backfills_explicit_source_before_tombstone_diff() {
    let (home_dir, home) = discover_env();
    let (_db_dir, db) = temp_db("discover-provider-backfill");
    let claude_proj = home_dir
        .path()
        .join(".claude")
        .join("projects")
        .join("backfill");
    std::fs::create_dir_all(&claude_proj).expect("create claude proj dir");
    let claude_file = claude_proj.join("backfill.jsonl");
    std::fs::write(
        &claude_file,
        format!("{}\n", claude_fixture("\"provider backfill keeper\"")),
    )
    .expect("write claude fixture");
    let source = claude_file.to_str().expect("utf-8 fixture path");

    // Explicit sync records the source with provider_id = NULL.
    let out = run_with_home(&db, &home, &["sync", source]);
    assert!(out.status.success(), "explicit sync: {}", stdout(&out));

    // The file is unchanged, so discovery takes the fingerprint fast path. It must
    // still associate the source with claude-code for future prior-path diffs.
    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "discover backfill: {}", stdout(&out));

    std::fs::remove_file(&claude_file).expect("remove fixture");
    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "discover removal: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let claude = frame["data"]["discovery"]["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .find(|provider| provider["id"] == "claude-code")
        .expect("claude-code");
    assert_eq!(claude["removed"], 1, "backfilled source must diff: {frame}");

    let out = run_with_home(&db, &home, &["search", "backfill"]);
    assert!(
        !stdout(&out).contains("msg_v1_"),
        "removed explicit source must be tombstoned: {}",
        stdout(&out)
    );
}

#[test]
fn sync_discover_tombstones_removed_source_on_complete_scan() {
    let (home_dir, home) = discover_env();
    let (_db_dir, db) = temp_db("discover-tombstone");
    let claude_proj = home_dir
        .path()
        .join(".claude")
        .join("projects")
        .join("tomb");
    std::fs::create_dir_all(&claude_proj).expect("create claude proj dir");
    let claude_file = claude_proj.join("tomb.jsonl");
    std::fs::write(
        &claude_file,
        format!("{}\n", claude_fixture("\"tombstone keeper\"")),
    )
    .expect("write claude fixture");

    // 首次 discover：源入库。
    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "first discover: {}", stdout(&out));
    let out = run_with_home(&db, &home, &["search", "tombstone"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "keeper visible: {}",
        stdout(&out)
    );

    // 删除源文件后再次 discover：完整扫描 → 合成空批 tombstone。
    std::fs::remove_file(&claude_file).expect("remove fixture");
    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "second discover: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let discovery = &frame["data"]["discovery"];
    // grok-build has no discovery root → overall complete may be false.
    // claude-code should report complete:true with removed:1.
    let claude = discovery["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .find(|p| p["id"] == "claude-code")
        .expect("claude-code");
    assert_eq!(claude["complete"], true, "{frame}");
    assert_eq!(claude["removed"], 1, "removed source count: {frame}");
    assert_eq!(claude["found"], 0, "{frame}");

    // 消息已 tombstone，不再可检索。
    let out = run_with_home(&db, &home, &["search", "tombstone"]);
    assert!(
        !stdout(&out).contains("msg_v1_"),
        "removed source's messages must be tombstoned: {}",
        stdout(&out)
    );
}

#[test]
#[cfg(unix)]
fn sync_discover_partial_scan_does_not_tombstone() {
    let (home_dir, home) = discover_env();
    let (_db_dir, db) = temp_db("discover-partial");
    let claude_proj = home_dir
        .path()
        .join(".claude")
        .join("projects")
        .join("partial");
    std::fs::create_dir_all(&claude_proj).expect("create claude proj dir");
    let claude_file = claude_proj.join("partial.jsonl");
    std::fs::write(
        &claude_file,
        format!("{}\n", claude_fixture("\"partial keeper\"")),
    )
    .expect("write claude fixture");

    // 首次 discover：源入库。
    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "first discover: {}", stdout(&out));
    let out = run_with_home(&db, &home, &["search", "partial"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "keeper visible: {}",
        stdout(&out)
    );

    // 删除源文件并把整个 projects 目录设为不可读，模拟部分扫描失败。
    std::fs::remove_file(&claude_file).expect("remove fixture");
    let projects_root = home_dir.path().join(".claude").join("projects");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&projects_root)
            .expect("meta")
            .permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&projects_root, perms).expect("chmod 000");
    }

    let out = run_with_home(&db, &home, &["sync", "--discover"]);
    assert!(out.status.success(), "partial discover: {}", stdout(&out));
    let frame = parse_first_line(&out);
    let discovery = &frame["data"]["discovery"];
    // 目录不可读 → complete=false。
    assert_eq!(
        discovery["complete"], false,
        "partial scan must be incomplete: {frame}"
    );
    let claude = discovery["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .find(|p| p["id"] == "claude-code")
        .expect("claude-code");
    assert_eq!(claude["complete"], false, "{frame}");
    assert_eq!(
        claude["removed"], 0,
        "partial scan must not tombstone: {frame}"
    );

    // 不完整扫描不 tombstone，消息仍可检索。
    let out = run_with_home(&db, &home, &["search", "partial"]);
    assert!(
        stdout(&out).contains("msg_v1_"),
        "partial scan must not tombstone unseen sources: {}",
        stdout(&out)
    );

    // 恢复权限以便 tempdir 清理。
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&projects_root)
            .expect("meta")
            .permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&projects_root, perms);
    }
}

// ---- 工具活动 + facet 过滤（08-15 structured-activity，schema v12）----
// 合成 fixture：无真实 transcript 数据（隐私）。

use agent_session_grep_domain::{IdKind, StableId};

/// 与组合根同一派生规则：provider-native 消息 id → 稳定 wire id。
fn native_msg_wire(native: &str) -> String {
    StableId::native(IdKind::Message, native)
        .as_str()
        .to_string()
}

/// Claude 合成 fixture：主线 Bash 调用 + sidechain Read 调用。
const CLAUDE_TOOL_FIXTURE: &str = r#"{"type":"user","uuid":"u-1","sessionId":"sess-tools","message":{"role":"user","content":"run the build please"}}
{"type":"assistant","uuid":"a-1","parentUuid":"u-1","sessionId":"sess-tools","message":{"role":"assistant","content":[{"type":"text","text":"running build"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"cargo build --release"}}]}}
{"type":"user","uuid":"r-1","parentUuid":"a-1","sessionId":"sess-tools","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"build finished ok","is_error":false}]}}
{"type":"assistant","uuid":"a-2","parentUuid":"r-1","sessionId":"sess-tools","isSidechain":true,"message":{"role":"assistant","content":[{"type":"text","text":"checking the file"},{"type":"tool_use","id":"toolu_2","name":"Read","input":{"file_path":"src/main.rs"}}]}}
{"type":"user","uuid":"r-2","parentUuid":"a-2","sessionId":"sess-tools","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_2","content":"read the file contents","is_error":false}]}}"#;

#[test]
fn sync_indexes_tool_activities_and_search_facets_filter_them() {
    let (dir, db) = temp_db("sync-act");
    let fixture = dir.path().join("claude-tools.jsonl");
    std::fs::write(&fixture, CLAUDE_TOOL_FIXTURE).expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync failed: {}", stdout(&out));
    assert!(stdout(&out).contains("\"messages\":5"), "{}", stdout(&out));

    // 默认检索不带 facets 回显（输出字节与旧版一致）。
    let out = run(&db, &["search", "build"]);
    assert!(out.status.success(), "search: {}", stdout(&out));
    let frame = parse_first_line(&out);
    assert!(
        frame["data"].get("facets").is_none(),
        "默认检索不得回显 facets: {frame}"
    );

    // --tool-kind command：只有携带 Bash 活动（锚定在 r-1）的消息命中。
    let out = run(&db, &["search", "build", "--tool-kind", "command"]);
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["facets"]["sidechain"], "include", "{frame}");
    assert_eq!(frame["data"]["facets"]["tool_kind"], "command", "{frame}");
    let hits = frame["data"]["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "command facet: {frame}");
    assert_eq!(
        hits[0]["id"],
        native_msg_wire("r-1"),
        "活动锚定在携带 tool_result 的消息: {frame}"
    );

    // --tool-kind file：sidechain 的 Read 活动（锚定在 r-2），查询词换 file。
    let out = run(&db, &["search", "file", "--tool-kind", "file"]);
    let frame = parse_first_line(&out);
    let hits = frame["data"]["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "file facet: {frame}");
    assert_eq!(hits[0]["id"], native_msg_wire("r-2"), "{frame}");
    assert_eq!(frame["data"]["facets"]["tool_kind"], "file", "{frame}");

    // --tool-name Read：按工具名逐字过滤。
    let out = run(&db, &["search", "file", "--tool-name", "Read"]);
    let frame = parse_first_line(&out);
    let hits = frame["data"]["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "name facet: {frame}");
    assert_eq!(frame["data"]["facets"]["tool_name"], "Read", "{frame}");

    // 不存在的工具名 → 空命中。
    let out = run(&db, &["search", "file", "--tool-name", "Grep"]);
    let frame = parse_first_line(&out);
    assert_eq!(
        frame["data"]["hits"].as_array().unwrap().len(),
        0,
        "{frame}"
    );

    // main-only：主线消息（u-1/a-1/r-1）保留，sidechain 消息排除。
    let out = run(&db, &["search", "build", "--main-only"]);
    let frame = parse_first_line(&out);
    assert_eq!(frame["data"]["facets"]["sidechain"], "main_only", "{frame}");
    let hits = frame["data"]["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 3, "main-only 保留全部主线: {frame}");

    // main-only：sidechain 的 a-2 被排除；r-2（tool_result 中继，主线）保留。
    let out = run(&db, &["search", "file", "--main-only"]);
    let frame = parse_first_line(&out);
    let hits = frame["data"]["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "file 的 sidechain 消息被排除: {frame}");
    assert_eq!(hits[0]["id"], native_msg_wire("r-2"), "{frame}");

    // subagent-only：只保留 sidechain 消息（a-2）。
    let out = run(&db, &["search", "file", "--subagent-only"]);
    let frame = parse_first_line(&out);
    assert_eq!(
        frame["data"]["facets"]["sidechain"], "subagent_only",
        "{frame}"
    );
    let hits = frame["data"]["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "sidechain 一条: {frame}");
    assert_eq!(hits[0]["id"], native_msg_wire("a-2"), "{frame}");
}

#[test]
fn sync_tool_activities_survive_resync_without_new_generation() {
    let (dir, db) = temp_db("sync-act-resync");
    let fixture = dir.path().join("claude-tools.jsonl");
    std::fs::write(&fixture, CLAUDE_TOOL_FIXTURE).expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync: {}", stdout(&out));
    assert!(
        stdout(&out).contains("\"generation\":1"),
        "{}",
        stdout(&out)
    );

    // 重同步未变化源：no-op，generation 不推进（活动行/claims 参与 current 判定）。
    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "resync: {}", stdout(&out));
    let s = stdout(&out);
    assert!(s.contains("\"committed\":0"), "resync={s}");
    assert!(
        s.contains("\"generation\":1"),
        "resync 不应推进 generation: {s}"
    );

    // 活动 facet 仍然可用。
    let out = run(&db, &["search", "build", "--tool-kind", "command"]);
    let frame = parse_first_line(&out);
    assert_eq!(
        frame["data"]["hits"].as_array().unwrap().len(),
        1,
        "{frame}"
    );
}

#[test]
fn sync_tombstones_activities_when_source_is_emptied() {
    let (dir, db) = temp_db("sync-act-tomb");
    let fixture = dir.path().join("claude-tools.jsonl");
    std::fs::write(&fixture, CLAUDE_TOOL_FIXTURE).expect("write fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync: {}", stdout(&out));
    let out = run(&db, &["search", "build", "--tool-kind", "command"]);
    assert_eq!(
        parse_first_line(&out)["data"]["hits"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{}",
        stdout(&out)
    );

    // 清空源文件 → 整源清空批次：消息与活动一并 tombstone。
    std::fs::write(&fixture, "").expect("truncate fixture");
    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "empty sync: {}", stdout(&out));

    let out = run(&db, &["search", "build", "--tool-kind", "command"]);
    let frame = parse_first_line(&out);
    assert_eq!(
        frame["data"]["hits"].as_array().unwrap().len(),
        0,
        "清空后活动 facet 不应再命中: {frame}"
    );
    let out = run(&db, &["search", "build"]);
    assert_eq!(
        parse_first_line(&out)["data"]["hits"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "消息本体也应被 tombstone: {}",
        stdout(&out)
    );
}

#[test]
fn sync_extracts_codex_function_call_activities() {
    let (dir, db) = temp_db("sync-act-codex");
    let fixture = dir.path().join("codex-rollout.jsonl");
    std::fs::write(
        &fixture,
        concat!(
            r#"{"timestamp":"2026-08-15T00:00:00.000Z","type":"session_meta","payload":{"session_id":"sess-cx"}}"#,
            "\n",
            r#"{"timestamp":"2026-08-15T00:00:01.000Z","type":"response_item","payload":{"type":"message","id":"msg_cx1","role":"assistant","content":[{"type":"output_text","text":"checking the sandbox"}]}}"#,
            "\n",
            r#"{"timestamp":"2026-08-15T00:00:02.000Z","type":"response_item","payload":{"type":"custom_tool_call","id":"call_cx1","tool_call_id":"call_cx1","name":"shell","arguments":"{\"command\":\"cat config.toml\"}"}}"#,
            "\n",
            r#"{"timestamp":"2026-08-15T00:00:03.000Z","type":"response_item","payload":{"type":"function_call_output","id":"fco_cx1","call_id":"call_cx1","output":"policy = safe","is_error":true}}"#,
            "\n",
        ),
    )
    .expect("write codex fixture");
    let path = fixture.to_string_lossy().into_owned();

    let out = run(&db, &["sync", &path]);
    assert!(out.status.success(), "sync: {}", stdout(&out));

    // 锚定在发出调用的助理消息：--tool-kind command 命中 msg_cx1。
    let out = run(&db, &["search", "sandbox", "--tool-kind", "command"]);
    let frame = parse_first_line(&out);
    let hits = frame["data"]["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "codex command facet: {frame}");
    assert_eq!(hits[0]["id"], native_msg_wire("msg_cx1"), "{frame}");

    // 失败的工具调用可按 --tool-name shell 过滤。
    let out = run(&db, &["search", "sandbox", "--tool-name", "shell"]);
    let frame = parse_first_line(&out);
    assert_eq!(
        frame["data"]["hits"].as_array().unwrap().len(),
        1,
        "{frame}"
    );
}

#[test]
fn search_facet_flag_validation_is_explicit() {
    let (_dir, db) = temp_db("sync-act-flags");
    // 互斥组合是用法错误（exit 2）。
    let out = run(&db, &["search", "q", "--main-only", "--subagent-only"]);
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    let out = run(&db, &["search", "q", "--main-only", "--include-sidechain"]);
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    // 未知 kind 是用法错误。
    let out = run(&db, &["search", "q", "--tool-kind", "bogus"]);
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("file|command|web|query|unknown"),
        "{}",
        stdout(&out)
    );
}
