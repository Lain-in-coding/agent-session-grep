//! `asg hook <event>` 的端到端契约测试：驱动真实二进制、真实 stdin payload。
//!
//! Claude Code 直接把这条命令的 stdout 当协议读——`SessionStart` 与
//! `UserPromptSubmit` 在 exit 0 时会把 stdout 注入模型上下文（带
//! `hookSpecificOutput` 时按 JSON 解析，否则原样当纯文本）。所以这里断言的是
//! 「stdout 上恰好一行契约 JSON，或者一个字节都没有」，而不是 CLI 的通用
//! envelope；单测覆盖投影函数，这里覆盖真实进程的 stdout/stderr/exit。

use std::io::Write;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");

/// 在临时空库上跑一次 hook，payload 从 stdin 送入。
fn run_hook(db: &std::path::Path, payload: &str, args: &[&str]) -> Output {
    let mut child = Command::new(BIN)
        .arg("--db")
        .arg(db)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn agent-session-grep binary");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload.as_bytes())
        .expect("failed to write hook payload");
    child.wait_with_output().expect("failed to collect output")
}

fn temp_db(tag: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join(format!("{tag}.db"));
    (dir, db)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn disabled_hook_writes_nothing_to_stdout() {
    let (_dir, db) = temp_db("hook-disabled");
    for (event, payload) in [
        ("session-start", r#"{"cwd":"/synthetic/project"}"#),
        ("user-prompt-submit", r#"{"prompt":"fix the parser"}"#),
    ] {
        for mode in [vec!["hook", event], vec!["--robot", "hook", event]] {
            let out = run_hook(&db, payload, &mode);
            assert!(out.status.success(), "stderr={}", stderr(&out));
            assert_eq!(
                stdout(&out),
                "",
                "off-by-default hook must not write to stdout ({mode:?}); \
                 Claude Code injects exit-0 stdout verbatim"
            );
            assert!(
                stderr(&out).contains("injected=false"),
                "stderr={}",
                stderr(&out)
            );
            assert!(!db.exists(), "disabled hooks must not create a catalog");
        }
    }
}

#[test]
fn enabled_hook_writes_only_the_bare_contract_line() {
    let (_dir, db) = temp_db("hook-enabled");
    // 先写一条命中，才有历史可注入。
    let indexed = Command::new(BIN)
        .arg("--db")
        .arg(&db)
        .args(["--robot", "index", "hook-seed", "synthetic parser rewrite"])
        .output()
        .expect("index");
    assert!(indexed.status.success(), "{}", stderr(&indexed));

    let out = run_hook(
        &db,
        r#"{"prompt":"parser"}"#,
        &["hook", "user-prompt-submit", "--enable"],
    );
    assert!(out.status.success(), "stderr={}", stderr(&out));

    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "stdout must be one line: {lines:?}");
    let frame: serde_json::Value = serde_json::from_str(lines[0]).expect("stdout is JSON");

    // 契约形状：hookSpecificOutput 在顶层，带 hookEventName 判别键。
    assert_eq!(
        frame["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit",
        "{frame}"
    );
    assert!(
        frame["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|context| context.contains("Historical Session Context")),
        "{frame}"
    );
    // envelope 字段一个都不能出现——它们会被原样注入会话上下文。
    for leaked in [
        "schema_version",
        "frame_type",
        "command",
        "ok",
        "outcome",
        "data",
        "redaction",
        "request_id",
        "meta",
        "page",
        "enabled",
        "offline",
        "hits",
    ] {
        assert!(frame.get(leaked).is_none(), "{leaked} leaked: {frame}");
    }
    assert_eq!(
        frame.as_object().expect("object").len(),
        1,
        "only hookSpecificOutput may travel: {frame}"
    );
}

#[test]
fn hook_failures_are_non_blocking_and_silent_on_stdout() {
    let (_dir, db) = temp_db("hook-non-blocking");
    // Claude Code 的 hook 契约里 exit 2 是"阻塞这次提交"：用 CLI 通用的
    // usage-error 退出码，一个含控制字符的普通 prompt 或 settings 里拼错的
    // 事件名就会让用户的提问被丢弃。注入失败只能是非阻塞的 exit 1。
    for (label, payload, args) in [
        (
            "control characters in the prompt",
            "{\"prompt\":\"parser\\u001b[31mrewrite\"}",
            vec!["hook", "user-prompt-submit", "--enable"],
        ),
        (
            "event name typo in settings",
            "{}",
            vec!["hook", "post-tool-use"],
        ),
        (
            "payload that is not JSON",
            "{not json",
            vec!["hook", "user-prompt-submit", "--enable"],
        ),
        (
            "unknown provider filter",
            r#"{"prompt":"parser"}"#,
            vec![
                "hook",
                "user-prompt-submit",
                "--enable",
                "--provider",
                "not-a-provider",
            ],
        ),
    ] {
        let out = run_hook(&db, payload, &args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{label} must not block the prompt (exit 2): stderr={}",
            stderr(&out)
        );
        assert_eq!(
            stdout(&out),
            "",
            "{label} must leave stdout clean: it is injected verbatim"
        );
        assert!(
            stderr(&out).contains("not injecting"),
            "{label} must say why on stderr: stderr={}",
            stderr(&out)
        );
    }
}

#[test]
fn enabled_hook_without_a_query_writes_nothing() {
    let (_dir, db) = temp_db("hook-no-query");
    // UserPromptSubmit 缺 prompt / SessionStart 缺 cwd / stdin 全空：无从检索，
    // 不能退化成往上下文里塞一个空 additionalContext。
    for (event, payload) in [
        ("user-prompt-submit", r#"{"session_id":"synthetic"}"#),
        ("session-start", "{}"),
        ("session-start", ""),
    ] {
        let out = run_hook(&db, payload, &["hook", event, "--enable"]);
        assert!(out.status.success(), "stderr={}", stderr(&out));
        assert_eq!(stdout(&out), "", "event={event} payload={payload:?}");
        assert!(
            !db.exists(),
            "a hook without a query must not create a catalog"
        );
    }
}
