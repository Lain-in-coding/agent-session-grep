//! D3 六项不变量自查（CLI 层）：#5 resume 全参数化（对比 agf AGF-02）。
//!
//! 竞品反例：provider 会话 ID 原样插入单引号 shell 模板、无转义——特殊字符
//! ID 会命令解析出错甚至注入。
//!
//! ASG 侧落地事实（本文件用可执行断言钉住）。
//!
//! `ResumeDescriptor` 是 typed intent：`provider_binary`、`args: Vec<String>`、
//! `working_directory` 分开携带（`crates/agent-session-grep-application/src/
//! resume.rs:17-30`）。执行层 `execute_resume` 用
//! `std::process::Command::args(&descriptor.args)` + `current_dir(...)` 直接
//! spawn，绝不过 shell（`crates/agent-session-grep-cli/src/lib.rs:2800-2806`）。
//! dry-run 展示串是另一条路径：危险 token 会被引用或整体拒绝
//! （`resume.rs:196-232`），展示被拒绝不影响 argv 执行。
//!
//! 证据均为合成 fixture + 测试专用 fake provider；无网络、无真实数据。

use rusqlite::Connection;
use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
const SMOKE_PROVIDER: &str = env!("CARGO_BIN_EXE_resume-smoke-provider");

/// 无空白 + shell 元字符的会话 ID：POSIX shell 会在 `&` 处断句并执行
/// `echo>asg-resume-pwned.txt`，cmd.exe 同样把 `&` 当命令分隔符。任何
/// shell 字符串拼接都会留下痕迹文件。
const ADVERSARIAL_SESSION_ID: &str = "ccdd&echo>asg-resume-pwned.txt";

fn temp_db(tag: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join(format!("{tag}.db"));
    let db = db.to_str().unwrap().to_string();
    (dir, db)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn run(db: &str, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--db")
        .arg(db)
        .arg("--robot")
        .args(args)
        .output()
        .expect("failed to spawn agent-session-grep binary")
}

fn first_json(output: &Output) -> serde_json::Value {
    let text = stdout(output);
    let line = text
        .lines()
        .next()
        .unwrap_or_else(|| panic!("no stdout: {text}"));
    serde_json::from_str(line).unwrap_or_else(|error| panic!("not JSON: {error}\n{line}"))
}

fn session_wire_for_message(db: &str, message_wire: &str) -> String {
    Connection::open(db)
        .expect("open catalog")
        .query_row(
            "SELECT session_id FROM message_placements
             WHERE message_id = ?1 ORDER BY session_id LIMIT 1",
            [message_wire],
            |row| row.get(0),
        )
        .expect("message must have a canonical Session placement")
}

/// 写入带 `cwd` 且 sessionId 含 shell 元字符的合成 Claude fixture。
fn write_claude_fixture(dir: &Path, cwd: &str, session_id: &str) -> (String, String) {
    let line = serde_json::json!({
        "type": "user",
        "uuid": "c0000000-0000-4000-8000-0000000000aa",
        "parentUuid": null,
        "sessionId": session_id,
        "cwd": cwd,
        "timestamp": "2026-07-26T01:00:00.000Z",
        "message": { "role": "user", "content": "invariant resume argv" },
    })
    .to_string();
    let fixture = dir.join("invariant-resume.jsonl");
    std::fs::write(&fixture, format!("{line}\n")).expect("write fixture");
    (
        fixture.to_string_lossy().into_owned(),
        "msg_v1_c0000000-0000-4000-8000-0000000000aa".to_string(),
    )
}

fn write_fake_provider(fake_dir: &Path) {
    #[cfg(windows)]
    let target = fake_dir.join("claude.exe");
    #[cfg(not(windows))]
    let target = fake_dir.join("claude");
    std::fs::copy(Path::new(SMOKE_PROVIDER), &target).expect("copy fake provider");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake provider");
    }
}

fn path_with_fake_dir(fake_dir: &Path) -> std::ffi::OsString {
    let mut dirs = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    dirs.insert(0, fake_dir.to_path_buf());
    std::env::join_paths(dirs).expect("join PATH")
}

fn run_resume(
    db: &str,
    path: &std::ffi::OsStr,
    cwd_out: &Path,
    args_out: &Path,
    session_wire: &str,
) -> Output {
    Command::new(BIN)
        .arg("--db")
        .arg(db)
        .arg("--robot")
        .args(["resume", session_wire, "--yes"])
        .env("PATH", path)
        .env("RESUME_SMOKE_CWD_OUT", cwd_out)
        .env("RESUME_SMOKE_ARGS_OUT", args_out)
        .output()
        .expect("failed to spawn agent-session-grep binary")
}

fn same_path(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    #[cfg(windows)]
    {
        a.eq_ignore_ascii_case(b)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn same_cwd(recorded: &str, expected: &str) -> bool {
    let recorded = recorded.trim().trim_end_matches(std::path::is_separator);
    let expected = expected.trim().trim_end_matches(std::path::is_separator);
    if same_path(recorded, expected) {
        return true;
    }
    // 临时目录路径常带别名：macOS 的 TMPDIR 是 /var/...，子进程 getcwd 报
    // /private/var/...；Windows 侧有 junction / 8.3 短名 / 盘符大小写。
    // 字面比较失败时按真实路径再比一次，不成立才判否。
    match (
        std::fs::canonicalize(recorded),
        std::fs::canonicalize(expected),
    ) {
        (Ok(recorded_real), Ok(expected_real)) => same_path(
            &recorded_real.to_string_lossy(),
            &expected_real.to_string_lossy(),
        ),
        _ => false,
    }
}

#[test]
fn descriptor_keeps_argv_and_cwd_separate_and_refuses_unsafe_display() {
    use agent_session_grep_application::resume::build_resume_descriptor;
    use agent_session_grep_domain::{IdKind, StableId};
    use agent_session_grep_ports::SessionResumeMetadata;

    let provider_session_id = "sid$injection\"payload".to_string();
    let working_directory = "C:/work dir/with spaces".to_string();
    let metadata = SessionResumeMetadata {
        session_id: StableId::native(IdKind::Session, "typed-intent"),
        provider_id: Some("claude-code".into()),
        resume_available: true,
        provider_session_id: Some(provider_session_id.clone()),
        original_working_directory: Some(working_directory.clone()),
        unavailable_reason: None,
    };
    let preview = build_resume_descriptor(&metadata);
    assert!(preview.available);
    assert_eq!(preview.descriptor.provider_binary, "claude");
    // argv 逐元素携带：provider session id 是**独立**的 argv 元素，绝不与
    // cwd 拼接、绝不进 shell 模板。
    assert_eq!(
        preview.descriptor.args,
        vec!["--resume".to_string(), provider_session_id.clone()]
    );
    assert_eq!(
        preview.descriptor.working_directory.as_deref(),
        Some(working_directory.as_str())
    );
    assert!(
        preview
            .descriptor
            .args
            .iter()
            .all(|arg| !arg.contains(&working_directory)),
        "cwd must never be concatenated into argv"
    );
    // dry-run 展示串是独立路径：token 含 `$`/`"`（可在常见 shell 内转义/展开）
    // 时整体拒绝（command: null），但 typed intent 不受影响。
    assert!(
        preview.command_string.is_empty(),
        "unsafe display token must refuse the preview string: {:?}",
        preview.command_string
    );
}

#[test]
fn resume_executes_adversarial_session_id_as_one_argv_without_a_shell() {
    let (dir, db) = temp_db("invariant-resume");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let workspace_str = workspace.to_string_lossy().into_owned();
    let (fixture, anchor) =
        write_claude_fixture(dir.path(), &workspace_str, ADVERSARIAL_SESSION_ID);
    let out = run(&db, &["ingest", &fixture]);
    assert!(out.status.success(), "ingest failed: {}", stdout(&out));
    let session_wire = session_wire_for_message(&db, &anchor);

    let fake_dir = dir.path().join("fake-bin");
    std::fs::create_dir_all(&fake_dir).expect("create fake bin dir");
    write_fake_provider(&fake_dir);
    let path = path_with_fake_dir(&fake_dir);
    let cwd_out = dir.path().join("spawn-cwd.txt");
    let args_out = dir.path().join("spawn-args.txt");

    // 1) 首次 `--yes` 强制只预览（持久标记缺失），不 spawn。
    let out = run_resume(&db, &path, &cwd_out, &args_out, &session_wire);
    assert!(
        out.status.success(),
        "first resume failed: {}",
        stdout(&out)
    );
    let frame = first_json(&out);
    assert_eq!(frame["data"]["executed"], false);
    assert_eq!(frame["data"]["first_run_preview"], true);
    assert!(!cwd_out.exists() && !args_out.exists());

    // 2) 第二次 `--yes` 真实执行：argv 数组 + current_dir，绝无 shell 拼接。
    let out = run_resume(&db, &path, &cwd_out, &args_out, &session_wire);
    assert!(
        out.status.success(),
        "second resume failed: {}",
        stdout(&out)
    );
    let frame = first_json(&out);
    assert_eq!(frame["data"]["executed"], true, "{frame}");

    let recorded_args = std::fs::read_to_string(&args_out).expect("read recorded args");
    assert_eq!(
        recorded_args, "--resume ccdd&echo>asg-resume-pwned.txt",
        "the provider session id must arrive as one verbatim argv element"
    );
    let recorded_cwd = std::fs::read_to_string(&cwd_out).expect("read recorded cwd");
    assert!(
        same_cwd(&recorded_cwd, &workspace_str),
        "spawned cwd {recorded_cwd:?} != expected {workspace_str:?}"
    );
    // 无 shell 解释：若执行路径走过任何 shell 字符串，`&`/`>` 会断句并在 spawn
    // 的 cwd 里留下这个痕迹文件。
    let pwned = workspace.join("asg-resume-pwned.txt");
    assert!(
        !pwned.exists(),
        "shell metacharacters in the session id were interpreted: {}",
        pwned.display()
    );
}
