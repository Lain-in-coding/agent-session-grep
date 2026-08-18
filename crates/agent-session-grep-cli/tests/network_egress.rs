//! 零遥测静态审计（design D5：零出网是硬要求）：
//! 证明默认 build 无 HTTP client 依赖，且唯一 socket 是 `serve` 的 loopback
//! TcpListener。README/SECURITY 的 "zero telemetry, zero upload, offline by
//! default" 宣称由本测试固化——任何新增 HTTP client 依赖或额外 socket 都
//! 必须显式经过评审，否则测试失败。

use std::path::{Path, PathBuf};

/// 默认 build 中禁止出现的 HTTP client crate（名称前缀匹配 Cargo.lock 包名）。
const FORBIDDEN_HTTP_CLIENT_CRATES: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "isahc",
    "surf",
    "attohttpc",
    "tiny_http",
    "rouille",
    "warp",
    "axum",
    "tokio",
    "async-std",
];

/// 允许出现 socket 用法的文件（仅 serve 的 loopback 监听；其余任何 crate
/// 出现 TcpListener/TcpStream/TcpSocket/udp 用法即审计失败）。
const ALLOWED_SOCKET_FILE: &str = "crates/agent-session-grep-cli/src/serve.rs";

fn workspace_root() -> PathBuf {
    // 本测试位于 crates/agent-session-grep-cli/tests/，工作区根在上级的上级。
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root must be canonicalizable")
}

#[test]
fn default_build_has_no_http_client_dependency() {
    let root = workspace_root();
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))
        .expect("workspace Cargo.lock must exist and be readable");
    for crate_name in FORBIDDEN_HTTP_CLIENT_CRATES {
        // Cargo.lock 包名行形如 `name = "reqwest"`；匹配整个 token 防误伤
        // （例如 hyper 在注释/其他字符串里出现不算依赖）。
        let needle = format!("name = \"{crate_name}\"");
        assert!(
            !lock.contains(&needle),
            "default build must not depend on HTTP client crate `{crate_name}` \
             (zero-telemetry audit, design D5)"
        );
    }
}

#[test]
fn only_socket_is_serve_loopback_tcp_listener() {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut offenders: Vec<(PathBuf, String)> = Vec::new();
    collect_socket_uses(&crates_dir, &mut offenders);

    for (path, line) in &offenders {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        assert_eq!(
            relative, ALLOWED_SOCKET_FILE,
            "socket usage found outside serve.rs (zero-telemetry audit): \
             {relative}:{line}"
        );
    }

    // 唯一允许的 socket 文件必须真的绑定 loopback（127.0.0.1）。
    let serve_src = std::fs::read_to_string(root.join(ALLOWED_SOCKET_FILE))
        .expect("serve.rs must exist and be readable");
    assert!(
        serve_src.contains("127.0.0.1") || serve_src.contains("loopback"),
        "serve.rs must bind loopback explicitly: {}",
        ALLOWED_SOCKET_FILE
    );
    assert!(
        serve_src.contains("TcpListener::bind"),
        "serve.rs must bind its loopback TcpListener"
    );
}

/// 递归扫描 `dir` 下所有 `.rs` 文件，收集含 socket API 的行。
fn collect_socket_uses(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_socket_uses(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && is_production_source(&path)
        {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for (index, line) in text.lines().enumerate() {
                if line.contains("TcpListener")
                    || line.contains("TcpStream")
                    || line.contains("TcpSocket")
                    || line.contains("UdpSocket")
                    || line.contains("std::net")
                {
                    out.push((path.clone(), format!("{}: {}", index + 1, line.trim())));
                }
            }
        }
    }
}

/// 只审计生产代码：`src/` 目录下的 `.rs` 文件（tests/ 与 examples/ 不产生
/// 运行时网络出口，且测试自身会引用本审计的关键词）。
fn is_production_source(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "src")
}
