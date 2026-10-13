//! B3 首用闭环回归（真实二进制集成测试）。
//!
//! 覆盖四件事：
//! 1. 缺库读命令 fail-closed：`catalog_error`（exit 6）、不创建任何文件、
//!    错误里附一条准确的显式 `sync --discover` 指令；
//! 2. 默认库路径解析：`--db` 显式优先；未给时用平台默认 data 目录下的
//!    `asg.db`（与 `config paths` 同源）；解析失败给可执行指引；
//! 3. `sync --discover` 零发现时明确要求显式指定源，而不是让用户猜"为什么
//!    零结果"；
//! 4. human `search` 已满足的标题/项目/provider/时间/命中文本/可采取动作
//!    投影用回归测试锁定（不改投影）。
//!
//! 隔离：所有用例都在临时 HOME / APPDATA / XDG 根下运行真实二进制，绝不触碰
//! 真实用户目录，也不依赖任何预置数据。

use std::path::PathBuf;
use std::process::{Command, Output};

/// 刚构建出的 `agent-session-grep` 二进制（Cargo 为集成测试注入）。
const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
/// 固定应用时钟（与 e2e.rs 一致），输出只依赖夹具数据与注入时钟。
const CLOCK_MS: &str = "1787616000000";

/// 隔离沙箱：一个临时目录同时充当 HOME / USERPROFILE（provider 发现）与
/// Windows APPDATA/LOCALAPPDATA、Unix XDG 根（默认库路径解析）。
struct Sandbox {
    dir: tempfile::TempDir,
    home: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).expect("create isolated home");
        Sandbox { dir, home }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("ASG_CLOCK_MS", CLOCK_MS);
        #[cfg(windows)]
        {
            cmd.env("APPDATA", self.home.join("AppData").join("Roaming"));
            cmd.env("LOCALAPPDATA", self.home.join("AppData").join("Local"));
        }
        #[cfg(not(windows))]
        {
            cmd.env("XDG_CONFIG_HOME", self.home.join(".config"));
            cmd.env("XDG_DATA_HOME", self.home.join(".local").join("share"));
            cmd.env("XDG_CACHE_HOME", self.home.join(".cache"));
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args)
            .output()
            .expect("failed to spawn agent-session-grep binary")
    }

    /// 平台默认库路径——与 CLI `config paths` 报告的 data 目录同源。
    fn default_db(&self) -> PathBuf {
        #[cfg(windows)]
        {
            self.home
                .join("AppData")
                .join("Local")
                .join("AgentSessions")
                .join("data")
                .join("asg.db")
        }
        #[cfg(target_os = "macos")]
        {
            self.home
                .join("Library")
                .join("Application Support")
                .join("AgentSessions")
                .join("data")
                .join("asg.db")
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            self.home
                .join(".local")
                .join("share")
                .join("agentsessions")
                .join("asg.db")
        }
        #[cfg(not(any(windows, unix)))]
        {
            self.home.join(".agentsessions").join("data").join("asg.db")
        }
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn first_frame(out: &Output) -> serde_json::Value {
    let text = stdout(out);
    serde_json::from_str(text.lines().next().expect("at least one stdout line"))
        .expect("first stdout line is a JSON frame")
}

#[test]
fn read_on_missing_catalog_fails_closed_without_writing() {
    let sb = Sandbox::new();
    let db = sb
        .dir
        .path()
        .join("nested")
        .join("missing")
        .join("catalog.db");
    let db_s = db.to_string_lossy().into_owned();

    // robot 模式：契约点是 catalog_error（exit 6）+ 可执行的 sync 指令。
    let out = sb.run(&["--db", &db_s, "--robot", "status"]);
    assert_eq!(out.status.code(), Some(6), "stderr={}", stderr(&out));
    let frame = first_frame(&out);
    assert_eq!(frame["ok"], false, "{frame}");
    assert_eq!(frame["error"]["code"], "catalog_error", "{frame}");
    let message = frame["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("sync --discover"),
        "缺库错误必须附一条显式 sync 指令: {frame}"
    );

    // human 模式：报错走 stderr（本地、不脱敏），指令必须带准确的库路径。
    let out = sb.run(&["--db", &db_s, "status"]);
    assert_eq!(out.status.code(), Some(6), "stderr={}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("catalog 不存在"), "stderr={err}");
    let expected = format!("agent-session-grep --db {db_s} sync --discover");
    assert!(err.contains(&expected), "stderr={err}");

    // fail-closed：读命令不写盘——库文件、父目录都不允许出现。
    assert!(!db.exists(), "read must not create the catalog file");
    assert!(
        !db.parent().expect("db has a parent").exists(),
        "read must not create the data directory"
    );
}

#[test]
fn doctor_on_missing_catalog_gives_sync_guidance_without_writing() {
    // doctor 也是读路径（B3 补漏）：缺库时与常规读命令同一条 fail-closed
    // 指引——catalog_error（exit 6）+ 显式 sync 指令，且不创建库或父目录；
    // 不再回落成无指引的掩码错误（`数据库内部错误`）。
    let sb = Sandbox::new();
    let db = sb
        .dir
        .path()
        .join("nested")
        .join("missing")
        .join("doctor.db");
    let db_s = db.to_string_lossy().into_owned();

    // robot：单帧 catalog_error + 可执行 sync 指令。
    let out = sb.run(&["--db", &db_s, "--robot", "doctor"]);
    assert_eq!(out.status.code(), Some(6), "stderr={}", stderr(&out));
    let frame = first_frame(&out);
    assert_eq!(frame["command"], "doctor", "{frame}");
    assert_eq!(frame["error"]["code"], "catalog_error", "{frame}");
    let message = frame["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("sync --discover"),
        "doctor 缺库必须附一条显式 sync 指令: {frame}"
    );

    // human：`doctor --db <path>`（--db 可在命令名后）给同一准确指令。
    let out = sb.run(&["doctor", "--db", &db_s]);
    assert_eq!(out.status.code(), Some(6), "stderr={}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("catalog 不存在"), "stderr={err}");
    let expected = format!("agent-session-grep --db {db_s} sync --discover");
    assert!(err.contains(&expected), "stderr={err}");

    // fail-closed：库文件、父目录都不允许出现。
    assert!(!db.exists(), "doctor must not create the catalog file");
    assert!(
        !db.parent().expect("db has a parent").exists(),
        "doctor must not create the data directory"
    );
}

#[test]
fn explicit_db_wins_and_absent_db_uses_platform_default() {
    let sb = Sandbox::new();
    let default_db = sb.default_db();
    let default_s = default_db.to_string_lossy().into_owned();

    // 未给 --db：解析到平台默认 data 目录下的 asg.db，并且 fail-closed 不写盘。
    let out = sb.run(&["status"]);
    assert_eq!(out.status.code(), Some(6), "stderr={}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(&default_s),
        "缺 --db 时错误必须指向平台默认库路径 {default_s}: {err}"
    );
    assert!(
        !default_db.exists(),
        "reads must not create the default catalog"
    );
    assert!(
        !default_db.parent().expect("db has a parent").exists(),
        "reads must not create the default data directory"
    );

    // 显式 --db 优先：错误信息指向显式路径，默认路径不再出现。
    let explicit = sb.dir.path().join("explicit").join("other.db");
    let explicit_s = explicit.to_string_lossy().into_owned();
    let out = sb.run(&["--db", &explicit_s, "status"]);
    assert_eq!(out.status.code(), Some(6), "stderr={}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains(&explicit_s), "stderr={err}");
    assert!(
        !err.contains(&default_s),
        "explicit --db must take priority: {err}"
    );
}

#[test]
fn unresolvable_default_path_gives_actionable_guidance() {
    let sb = Sandbox::new();
    let mut cmd = sb.cmd(&["--robot", "status"]);
    #[cfg(windows)]
    {
        cmd.env_remove("APPDATA");
        cmd.env_remove("LOCALAPPDATA");
    }
    #[cfg(not(windows))]
    {
        cmd.env_remove("HOME");
        cmd.env_remove("XDG_CONFIG_HOME");
        cmd.env_remove("XDG_DATA_HOME");
        cmd.env_remove("XDG_CACHE_HOME");
    }
    let out = cmd
        .output()
        .expect("failed to spawn agent-session-grep binary");
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr(&out));
    let frame = first_frame(&out);
    assert_eq!(frame["error"]["code"], "invalid_request", "{frame}");
    let message = frame["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("--db") && message.contains("可显式传"),
        "默认路径解析失败必须给出显式 --db 指引: {frame}"
    );
}

#[test]
fn sync_discover_zero_sources_says_to_specify_one_explicitly() {
    let sb = Sandbox::new();
    let db = sb.dir.path().join("discover.db");
    let db_s = db.to_string_lossy().into_owned();

    // robot：零发现仍是合法空成功，但 warnings 必须给出可执行的"指定源"指引。
    let out = sb.run(&["--db", &db_s, "--robot", "sync", "--discover"]);
    assert!(out.status.success(), "stderr={}", stderr(&out));
    let frame = first_frame(&out);
    assert_eq!(frame["data"]["sources"], 0, "{frame}");
    let warnings = frame["warnings"].as_array().expect("warnings array");
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w.contains("sync <file>"))),
        "零发现必须明确要求显式指定源: {frame}"
    );

    // human：stderr 给指引；stdout 不再谎称"源文件未变化"。
    let out = sb.run(&["--db", &db_s, "sync", "--discover"]);
    assert!(out.status.success(), "stderr={}", stderr(&out));
    assert!(
        stderr(&out).contains("显式指定源"),
        "stderr={}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("sources: 0"), "{text}");
    assert!(
        !text.contains("源文件未变化"),
        "零发现时不得声称源文件未变化: {text}"
    );
}

#[test]
fn human_search_projection_stays_readable() {
    let sb = Sandbox::new();
    let db = sb.dir.path().join("search.db");
    let db_s = db.to_string_lossy().into_owned();

    // 合成 Claude fixture：provider 原生 session id + cwd + 独特正文。
    let project = sb.home.join(".claude").join("projects").join("demo");
    std::fs::create_dir_all(&project).expect("create claude project root");
    let fixture = project.join("s1.jsonl");
    let fixture_line = r#"{"type":"user","uuid":"11111111-1111-4111-8111-111111111111","parentUuid":null,"sessionId":"22222222-2222-4222-8222-222222222222","timestamp":"2026-08-14T01:00:00.000Z","cwd":"C:/dev/first-run","message":{"role":"user","content":"first-run closure needle"}}"#;
    std::fs::write(&fixture, format!("{fixture_line}\n")).expect("write claude fixture");
    let fixture_s = fixture.to_string_lossy().into_owned();

    let synced = sb.run(&["--db", &db_s, "--robot", "sync", &fixture_s]);
    assert!(synced.status.success(), "stderr={}", stderr(&synced));
    let frame = first_frame(&synced);
    assert!(
        frame["data"]["emitted"].as_u64().unwrap_or(0) >= 1,
        "{frame}"
    );

    let out = sb.run(&["--db", &db_s, "search", "closure"]);
    assert!(out.status.success(), "stderr={}", stderr(&out));
    let text = stdout(&out);

    // 冻结的五列投影（human.rs）：日期 | Provider | 会话标题 | 工作目录 | Session ID。
    for header in ["日期", "Provider", "会话标题", "工作目录", "Session ID"] {
        assert!(
            text.contains(header),
            "human search 必须保留五列投影（缺 {header}）: {text}"
        );
    }
    // 时间 / provider / 项目（工作目录）/ 命中文本（标题列 = 最高相关度命中的
    // 正文前缀，即该版式上的"命中片段"投影）都必须直接可读。
    assert!(text.contains("2026-08-14"), "{text}");
    assert!(text.contains("claude-code"), "{text}");
    assert!(text.contains("C:/dev/first-run"), "{text}");
    assert!(text.contains("first-run"), "{text}");
    // 可采取的动作：wire-id 命令可直接复制（表里的原生 Session ID 不是 wire id）。
    assert!(text.contains("下一步"), "{text}");
    assert!(text.contains("show msg_v1_"), "{text}");
    assert!(text.contains("context ses_v1_"), "{text}");
}
