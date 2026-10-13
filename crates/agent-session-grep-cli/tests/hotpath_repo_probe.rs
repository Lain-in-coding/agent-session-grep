//! B1 热路径回归：按 ID 的读取命令零 git 探测；search 每请求至多一轮 repo 解析。
//!
//! 观测手段是真实 git 的 `GIT_TRACE`：每个被派发的 git 进程恰好写一行
//! `trace: built-in: git <args>`（git.c `run_builtin`，跨平台/版本一致）。
//! 不用「假 git」注入：`Command::new("git")` 在 Windows 上只按 `.exe` 解析
//! PATH（实测 `.cmd` shim 不会被选中）。临时目录里建一个带 origin 的空仓库
//! 作为 cwd：`rev-parse --show-toplevel` + `remote get-url origin` 各产生一行，
//! 即「一轮解析」= 2 个 git 子进程。真实 git 依赖与 e2e.rs 的 repo identity
//! 测试一致；无网络、无真实用户数据。

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// 刚构建出的 `agent-session-grep` 二进制（Cargo 为集成测试注入）。
const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
/// 固定应用时钟（与 e2e.rs 一致），输出只依赖夹具数据与注入时钟。
const CLOCK_MS: &str = "1787616000000";
/// 每个被派发的 git 进程都会写下的 trace 行片段。
const GIT_BUILTIN_TRACE: &str = "built-in: git ";

/// 临时目录里建一个带 origin 的最小 git 仓库（空仓库即可让两级探测全部命中）。
fn init_git_repo_with_origin(dir: &Path, name: &str, url: &str) -> PathBuf {
    let repo = dir.join(name);
    std::fs::create_dir_all(&repo).expect("create repo dir");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .expect("spawn git init")
            .success(),
        "git init failed"
    );
    assert!(
        Command::new("git")
            .args(["remote", "add", "origin", url])
            .current_dir(&repo)
            .status()
            .expect("spawn git remote add")
            .success(),
        "git remote add failed"
    );
    repo
}

/// 在 `cwd` 里跑一次 CLI；`trace` 非空时用 GIT_TRACE 统计派发过的 git 进程数。
fn run_cli(db: &Path, cwd: &Path, trace: Option<&Path>, args: &[&str]) -> (Output, usize) {
    let mut cmd = Command::new(BIN);
    cmd.arg("--db")
        .arg(db)
        .arg("--robot")
        .args(args)
        .current_dir(cwd)
        .env("ASG_CLOCK_MS", CLOCK_MS)
        // 必须走真实 repo 发现：ASG_CURRENT_REPO 是注入旁路，观测不到探测次数。
        .env_remove("ASG_CURRENT_REPO");
    if let Some(path) = trace {
        let _ = std::fs::remove_file(path);
        cmd.env("GIT_TRACE", path);
    }
    let output = cmd.output().expect("spawn agent-session-grep");
    (output, trace.map_or(0, count_git_processes))
}

/// GIT_TRACE 里的 built-in 行数 = 本次请求派发过的 git 子进程数。
fn count_git_processes(trace: &Path) -> usize {
    std::fs::read_to_string(trace)
        .map(|text| {
            text.lines()
                .filter(|line| line.contains(GIT_BUILTIN_TRACE))
                .count()
        })
        .unwrap_or(0)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn indexed_wire_id(output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stdout);
    let frame: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("index prints one frame"))
            .expect("index frame is JSON");
    frame["data"]["indexed"]
        .as_str()
        .expect("index frame carries data.indexed")
        .to_string()
}

#[test]
fn read_commands_probe_no_git_and_search_resolves_repo_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = init_git_repo_with_origin(dir.path(), "repo", "https://example.com/owner/name.git");
    let db = dir.path().join("hotpath.db");
    let trace = dir.path().join("git-trace.log");

    // 一条合成消息：index 是写路径；该条无 session cwd，不触发任何探测。
    let (seeded, _) = run_cli(
        &db,
        dir.path(),
        None,
        &["index", "hotpath-fact-1", "needle in the haystack"],
    );
    assert!(seeded.status.success(), "index failed: {}", stderr(&seeded));
    let wire = indexed_wire_id(&seeded);

    // get/show/status：按 ID 纯读取。cwd 故意放进带 origin 的仓库——修复前
    // 每个 App 构造都会探测 2 次，期望恒为 0。
    fn assert_zero_probes(db: &Path, repo: &Path, trace: &Path, label: &str, args: &[&str]) {
        let (output, probes) = run_cli(db, repo, Some(trace), args);
        assert!(
            output.status.success(),
            "{label} failed: {}",
            stderr(&output)
        );
        assert_eq!(
            probes, 0,
            "{label} must not spawn git (cwd is a repo with origin)"
        );
    }
    assert_zero_probes(&db, &repo, &trace, "get", &["get", wire.as_str()]);
    assert_zero_probes(&db, &repo, &trace, "show", &["show", wire.as_str()]);
    assert_zero_probes(&db, &repo, &trace, "status", &["status"]);

    // search：repo-aware 排序需要当前仓库，但每请求只解析一轮
    // （rev-parse + remote get-url = 2 个 git 子进程；修复前构造两次 App = 4）。
    let (output, probes) = run_cli(&db, &repo, Some(&trace), &["search", "needle"]);
    assert!(
        output.status.success(),
        "search failed: {}",
        stderr(&output)
    );
    assert_eq!(
        probes, 2,
        "search must resolve the current repo exactly once per request"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&wire),
        "search must still return the indexed hit"
    );

    // 语义分支（semantic/hybrid 装配）复用同一个已解析 slug：向量表为空时
    // 显式降级为 lexical_fallback（warning），探测次数仍是一轮 = 2。
    let (output, probes) = run_cli(
        &db,
        &repo,
        Some(&trace),
        &["search", "--mode", "semantic", "needle"],
    );
    assert!(
        output.status.success(),
        "semantic search failed: {}",
        stderr(&output)
    );
    assert_eq!(
        probes, 2,
        "semantic search must reuse the single per-request repo resolution"
    );
}
