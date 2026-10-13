//! Repo identity 派生（schema v16 `session_repo_slugs` 投影的写入侧依赖）。
//!
//! 借鉴来源：
//! - Recall `repo_identity.rs`：`git rev-parse --show-toplevel` +
//!   `remote get-url origin` 两级检测、按目录缓存、normalize 为
//!   host/owner/name 三段 slug；
//! - sessiongrep `find_repo_root`：worktree 感知——我们不自行解析 `.git`
//!   文件，`git rev-parse` 原生处理 worktree/submodule（返回工作树根），
//!   比手工走 `gitdir:` 指针更少出错。
//!
//! 诚实边界：检测失败（目录不存在 / 非 git 仓库 / 无 origin / URL 形状
//! 不认识 / slug 超长）一律 `None`，绝不猜。派生结果只含
//! `host/owner/name` 三段 slug——**绝不落绝对路径**（privacy 契约：
//! `scripts/evidence/privacy_scan.py` 会扫全部 tracked 文本）。
//!
//! 本模块只被 CLI 组合根注入到 [`SqliteStore`]（写路径），测试注入
//! 确定性的 fake；`git` 不在 PATH 或调用失败与"目录不是仓库"同义降级，
//! 不阻塞 sync/index。

use agent_session_grep_adapters_sqlite::RepoSlugResolver;
use std::cell::RefCell;
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};

/// 派生 slug 最大长度（host/owner/name 三段之和）。超长即拒绝（None）——
/// 截断会破坏身份唯一性，把两个仓库并成一个。
pub const REPO_SLUG_MAX_CHARS: usize = 255;

/// 运行一次 git 取 stdout（trim）；spawn 失败 / 非零退出 / 非 UTF-8 /
/// 空输出一律 `None`。
///
/// 这是**改动前**的串行原语：重叠派发不可用时解析器回退到它，五个仓库
/// 上下文的语义矩阵也用它做对照，保证回退路径与旧行为逐字一致。
fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    parse_git_output(output)
}

/// 串行/重叠两条路径共用的 stdout 解析：非零退出 / 非 UTF-8 / 空输出一律
/// `None`，否则 trim 后的整体内容（两条命令的输出都只有单行，等价于取首行）。
fn parse_git_output(output: std::process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// `git -C <cwd> rev-parse --show-toplevel`：目录在 git 工作树内时返回
/// 工作树根（worktree/submodule 也由 git 自身解析）；否则 None。
fn git_toplevel(cwd: &str) -> Option<String> {
    git_output(&["-C", cwd, "rev-parse", "--show-toplevel"])
}

/// `git -C <toplevel> remote get-url origin`：宿主仓的 origin 远端 URL；
/// 无 origin（本地仓）→ None。
fn git_origin_url(toplevel: &str) -> Option<String> {
    git_output(&["-C", toplevel, "remote", "get-url", "origin"])
}

/// by_directory 缓存未命中的重叠派发：**先同时 spawn 两个 git 子进程**
/// （都用 `-C <cwd>`，仓库发现交给 git 自己），再依次收割输出；单侧语义与
/// `git_output` 逐字一致（spawn 失败 / 非零退出 / 非 UTF-8 / 空 → None，
/// 流语义同 `Command::output`：stdin 立即 EOF、stderr 丢弃不继承）。
///
/// 返回 `(toplevel, origin_url)`：toplevel 是门禁——`None` 表示 bare repo /
/// `.git` 内 cwd / 非仓库等，调用方必须丢弃 URL 结果。URL 探测从 cwd 出发
/// （改动前从 toplevel 出发）；git 自行向上发现同一仓库，输出等价。
fn git_toplevel_and_origin_url(cwd: &str) -> (Option<String>, Option<String>) {
    fn spawn(args: &[&str]) -> Option<Child> {
        Command::new("git")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    }
    let collect = |child: Option<Child>| {
        child
            .and_then(|child| child.wait_with_output().ok())
            .and_then(parse_git_output)
    };
    let toplevel = spawn(&["-C", cwd, "rev-parse", "--show-toplevel"]);
    let origin_url = spawn(&["-C", cwd, "remote", "get-url", "origin"]);
    (collect(toplevel), collect(origin_url))
}

/// 重叠派发只有在"从 cwd 发现"与"从 toplevel 发现"落在同一仓库时才等价于
/// 改动前的串行两级探测。两类信号会让两者分叉，命中任一即回退串行路径：
///
/// 1. 可能改变 discover 落点的环境变量（GIT_DIR / GIT_WORK_TREE /
///    GIT_COMMON_DIR / GIT_CEILING_DIRECTORIES /
///    GIT_DISCOVERY_ACROSS_FILESYSTEM）；
/// 2. 门禁返回的 toplevel 自身不是可重新发现的仓库根（`<toplevel>/.git`
///    不存在）——典型是 `core.worktree` 外指到 gitdir 树之外的布局，此时
///    改动前那次以 toplevel 为 `-C` 的探测会走到另一个仓库（实测中甚至
///    走到了外层仓）。
fn discovery_env_overrides_present() -> bool {
    const VARS: [&str; 5] = [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    ];
    VARS.iter().any(|name| std::env::var_os(name).is_some())
}

/// `<toplevel>/.git` 存在（目录、worktree/submodule 指针文件、
/// separate-git-dir 指针）即认为 toplevel 可被重新发现到同一仓库。
fn toplevel_is_rediscoverable(toplevel: &str) -> bool {
    std::path::Path::new(toplevel).join(".git").exists()
}

/// 重叠还要求 cwd 落在门禁返回的 toplevel 之内（正常仓库、子目录、linked
/// worktree、submodule 恒成立）。core.worktree 把工作树指到别处、或该路径
/// 本身是另一个仓库根时 cwd 不在 toplevel 之下——那正是从 toplevel
/// 重新发现会落到另一仓库（甚至外层仓）的布局，必须回退串行。
///
/// 路径别名必须按真实路径比较：`git rev-parse --show-toplevel` 会解析
/// junction / 符号链接（实测 Windows junction 下 cwd 报链接路径、toplevel
/// 报真实路径；macOS `/var` -> `/private/var` 同理），CI 的临时目录正是这种
/// 布局，字面比较会把命中的重叠误判成需要回退。字面比较不成立时再比较
/// canonicalize 后的路径；两侧都解析失败才判否（保守回退串行）。
fn cwd_is_inside_toplevel(cwd: &str, toplevel: &str) -> bool {
    let cwd_path = std::path::Path::new(cwd);
    let toplevel_path = std::path::Path::new(toplevel);
    if cwd_path.starts_with(toplevel_path) {
        return true;
    }
    match (
        std::fs::canonicalize(cwd_path),
        std::fs::canonicalize(toplevel_path),
    ) {
        (Ok(cwd_real), Ok(toplevel_real)) => cwd_real.starts_with(&toplevel_real),
        _ => false,
    }
}

/// 远端 URL → 三段 slug（`host/owner/name`）。
///
/// 支持五种常见形状（Recall 同款，但 host 通用不限 github.com）：
/// - `https://HOST/OWNER/NAME[.git]`（http 同）；
/// - `ssh://git@HOST/OWNER/NAME[.git]`；
/// - `git@HOST:OWNER/NAME[.git]`（scp-like）；
/// - `HOST:OWNER/NAME[.git]`（scp-like 无用户）；
/// - `HOST/OWNER/NAME[.git]`（无协议前缀）。
///
/// 不认识的形状（本地路径 / `file://` / Windows 盘符 / 带端口 / 多级
/// namespace / 空段）一律 None——诚实拒绝，绝不半猜。
pub fn normalize_remote_url(url: &str) -> Option<String> {
    let raw = url.trim().trim_end_matches('/');
    if raw.is_empty() {
        return None;
    }
    let (host, path) = if let Some(rest) = raw.strip_prefix("https://") {
        split_slash(rest)?
    } else if let Some(rest) = raw.strip_prefix("http://") {
        split_slash(rest)?
    } else if let Some(rest) = raw.strip_prefix("ssh://git@") {
        split_slash(rest)?
    } else if let Some(rest) = raw.strip_prefix("git@") {
        split_scp(rest)?
    } else if let Some((host, path)) = raw.split_once(':') {
        // scp-like 无用户（host:owner/name）：冒号前不得含 '/'，冒号后
        // 不得再含 ':'（多冒号是端口或 Windows 盘符，不猜）。
        if host.contains('/') || path.contains(':') {
            return None;
        }
        (host, path)
    } else {
        split_slash(raw)?
    };
    // 单字符 host 是 Windows 盘符（C:/...）而非宿主，拒绝；带端口拒绝。
    if host.len() < 2 || host.contains(':') {
        return None;
    }
    let path = path
        .trim_start_matches('/')
        .strip_suffix(".git")
        .unwrap_or(path);
    let mut segments = path.split('/');
    let owner = segments.next()?.trim();
    let name = segments.next()?.trim();
    if owner.is_empty() || name.is_empty() || segments.next().is_some() {
        return None;
    }
    if owner.contains('\\') || name.contains('\\') {
        return None;
    }
    let slug = format!("{host}/{owner}/{name}");
    if slug.chars().count() > REPO_SLUG_MAX_CHARS {
        return None;
    }
    Some(slug)
}

/// `https://host/rest` 形状的 (host, rest) 拆分；host 为空 → None。
fn split_slash(rest: &str) -> Option<(&str, &str)> {
    let (host, path) = rest.split_once('/')?;
    if host.is_empty() {
        return None;
    }
    Some((host, path))
}

/// `host:owner/name` 形状的 (host, rest) 拆分；缺冒号 → None。
fn split_scp(rest: &str) -> Option<(&str, &str)> {
    let (host, path) = rest.split_once(':')?;
    if host.contains('/') || path.contains(':') {
        return None;
    }
    Some((host, path))
}

/// 带两级缓存的 git 解析器（Recall 同款）：
/// - 按 cwd → toplevel：同一目录的重复派生不重跑 `rev-parse`；
/// - 按 toplevel → slug：同仓库多个子目录共享一次 `remote get-url`。
///
/// 失败（None）同样入缓存——重建大批会话时"仓库已不存在"的 cwd 只
/// 探测一次。
#[derive(Default)]
pub struct GitRepoSlugResolver {
    by_directory: RefCell<HashMap<String, Option<String>>>,
    by_toplevel: RefCell<HashMap<String, Option<String>>>,
}

impl RepoSlugResolver for GitRepoSlugResolver {
    fn resolve(&self, cwd: &str) -> Option<String> {
        if cwd.trim().is_empty() {
            return None;
        }
        let directory_hit = self.by_directory.borrow().get(cwd).cloned();
        if let Some(cached) = directory_hit {
            // 命中：toplevel 已定性（None 亦然），且未命中路径把 toplevel 与
            // 结果成对写进两级缓存——by_toplevel 必有同一轮写入的条目。
            let toplevel = cached?;
            return self.by_toplevel.borrow().get(&toplevel).cloned().flatten();
        }
        // 未命中：能重叠就重叠（两个 git 进程并行），不能就回退到改动前的
        // 串行两级探测；判据见 `discovery_env_overrides_present`。
        let (toplevel, overlapped_url) = if discovery_env_overrides_present() {
            (git_toplevel(cwd), None)
        } else {
            let (toplevel, url) = git_toplevel_and_origin_url(cwd);
            (toplevel, Some(url))
        };
        self.by_directory
            .borrow_mut()
            .insert(cwd.to_string(), toplevel.clone());
        // 门禁语义逐字不变：toplevel 为 None（bare repo / `.git` 内 cwd /
        // 非仓库）一律 None——URL 结果即便探测成功也必须丢弃。
        let toplevel = toplevel?;
        if let Some(cached) = self.by_toplevel.borrow().get(&toplevel) {
            return cached.clone();
        }
        // 重叠结果只在 toplevel 可被重新发现时代表"改动前那次以 toplevel 为
        // -C 的探测"；否则丢弃并串行补齐（只发生在 core.worktree 外指等
        // 非常规布局）。归一化路径不变。
        let url = match overlapped_url {
            Some(url)
                if toplevel_is_rediscoverable(&toplevel)
                    && cwd_is_inside_toplevel(cwd, &toplevel) =>
            {
                url
            }
            _ => git_origin_url(&toplevel),
        };
        let slug = url.as_deref().and_then(normalize_remote_url);
        self.by_toplevel.borrow_mut().insert(toplevel, slug.clone());
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// 测试专用组合：cwd → 检测本机 git 仓库并归一远端 URL，任何一步失败
    /// → None。生产路径走带缓存的 [`GitRepoSlugResolver`]（两级缓存把同一
    /// 仓库的多个目录共享一次 remote get-url），本函数锚定组合语义。
    /// 空/纯空白 cwd 与生产解析器同一门禁：直接拒绝（`git -C ""` 会退化为
    /// 当前目录，绝不能把调用者未提供目录时的宿主仓身份派生出来）。
    fn derive_repo_slug(cwd: &str) -> Option<String> {
        if cwd.trim().is_empty() {
            return None;
        }
        let toplevel = git_toplevel(cwd)?;
        let url = git_origin_url(&toplevel)?;
        normalize_remote_url(&url)
    }

    fn temp_git_repo(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("asg-repo-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let init = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .expect("git init");
        assert!(init.success(), "git init failed");
        root
    }

    fn add_origin(repo: &Path, url: &str) {
        let status = Command::new("git")
            .args(["remote", "add", "origin", url])
            .current_dir(repo)
            .status()
            .expect("git remote add");
        assert!(status.success(), "git remote add failed");
    }

    // ---- 失败测试先行：检测失败绝不猜 ----

    #[test]
    fn derive_none_for_nonexistent_directory() {
        let missing = std::env::temp_dir().join(format!("asg-no-such-dir-{}", std::process::id()));
        assert_eq!(derive_repo_slug(missing.to_str().unwrap()), None);
    }

    #[test]
    fn derive_none_for_non_git_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(derive_repo_slug(dir.path().to_str().unwrap()), None);
    }

    #[test]
    fn derive_none_for_git_repo_without_origin() {
        let repo = temp_git_repo("no-origin");
        assert_eq!(derive_repo_slug(repo.to_str().unwrap()), None);
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn derive_none_for_empty_cwd() {
        assert_eq!(derive_repo_slug(""), None);
        assert_eq!(derive_repo_slug("   "), None);
    }

    // ---- 成功路径：真实临时 git 仓库 ----

    #[test]
    fn derive_slug_from_git_directory_with_origin() {
        let repo = temp_git_repo("origin");
        add_origin(&repo, "git@github.com:synthetic-owner/synthetic-repo.git");
        assert_eq!(
            derive_repo_slug(repo.to_str().unwrap()).as_deref(),
            Some("github.com/synthetic-owner/synthetic-repo")
        );
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn derive_slug_from_nested_subdirectory() {
        let repo = temp_git_repo("nested");
        add_origin(&repo, "https://gitlab.example.com/team/project.git");
        let sub = repo.join("packages").join("app");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(
            derive_repo_slug(sub.to_str().unwrap()).as_deref(),
            Some("gitlab.example.com/team/project")
        );
        let _ = fs::remove_dir_all(&repo);
    }

    /// 五种仓库上下文的判定矩阵（证伪性测试）：每个上下文同时对照旧串行
    /// 组合（`derive_repo_slug`：rev-parse 门禁 + toplevel 上的 URL 探测）与
    /// 生产解析器的重叠派发路径，并且对照字面期望值——任何 None↔Some 漂移
    /// 都会在此暴露。bare repo 与 `.git` 内 cwd 的 URL 探测本身会成功，
    /// 判定必须仍为 None（门禁丢弃 URL 结果）。
    #[test]
    fn resolve_context_matrix_matches_pre_change_semantics() {
        fn assert_context(cwd: &str, expected: Option<&str>) {
            assert_eq!(
                derive_repo_slug(cwd).as_deref(),
                expected,
                "串行锚定 {cwd:?}"
            );
            assert_eq!(
                GitRepoSlugResolver::default().resolve(cwd).as_deref(),
                expected,
                "重叠派发 {cwd:?}"
            );
        }

        let dir = tempfile::tempdir().unwrap();

        // (1) 普通仓（根与子目录）：Some(宿主仓 slug)
        let repo = temp_git_repo("ctx-plain");
        add_origin(&repo, "git@github.com:synthetic-owner/plain.git");
        let sub = repo.join("packages").join("app");
        fs::create_dir_all(&sub).unwrap();
        assert_context(
            repo.to_str().unwrap(),
            Some("github.com/synthetic-owner/plain"),
        );
        assert_context(
            sub.to_str().unwrap(),
            Some("github.com/synthetic-owner/plain"),
        );

        // (2) 嵌套仓：内层自成一仓 → 内层 slug；外层不受影响
        let inner = repo.join("vendor").join("inner");
        fs::create_dir_all(&inner).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .current_dir(&inner)
                .status()
                .expect("git init")
                .success(),
            "git init failed"
        );
        add_origin(&inner, "https://gitlab.example.com/team/inner.git");
        assert_context(
            inner.to_str().unwrap(),
            Some("gitlab.example.com/team/inner"),
        );
        assert_context(
            repo.to_str().unwrap(),
            Some("github.com/synthetic-owner/plain"),
        );

        // (3) bare repo（带 origin）：门禁失败 → None，URL 探测成功也不采用
        let bare = dir.path().join("bare.git");
        fs::create_dir_all(&bare).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "--bare"])
                .current_dir(&bare)
                .status()
                .expect("git init --bare")
                .success(),
            "git init --bare failed"
        );
        add_origin(&bare, "git@github.com:synthetic-owner/bare.git");
        assert_context(bare.to_str().unwrap(), None);

        // (4) `.git` 内 cwd：门禁失败 → None，URL 探测成功也不采用
        assert_context(repo.join(".git").to_str().unwrap(), None);

        // (5) 非 git 目录：两侧都 None
        let plain = dir.path().join("plain");
        fs::create_dir_all(&plain).unwrap();
        assert_context(plain.to_str().unwrap(), None);

        let _ = fs::remove_dir_all(&repo);
    }

    // ---- 归一化：每种 URL 形状一个参数 ----

    #[test]
    fn normalizes_each_supported_url_shape() {
        for url in [
            "https://github.com/samzong/Recall.git",
            "https://github.com/samzong/Recall/",
            "http://github.com/samzong/Recall",
            "ssh://git@github.com/samzong/Recall.git",
            "git@github.com:samzong/Recall.git",
            "github.com:samzong/Recall",
            "github.com/samzong/Recall",
            "gitlab.example.com/team/notes.git",
        ] {
            let slug = normalize_remote_url(url).unwrap_or_else(|| panic!("{url:?}"));
            assert_eq!(
                slug.split('/').count(),
                3,
                "{url:?} -> {slug:?} 必须恒为 host/owner/name 三段"
            );
        }
        assert_eq!(
            normalize_remote_url("https://github.com/samzong/Recall.git").as_deref(),
            Some("github.com/samzong/Recall")
        );
        assert_eq!(
            normalize_remote_url("git@github.com:samzong/Recall.git").as_deref(),
            Some("github.com/samzong/Recall")
        );
    }

    #[test]
    fn rejects_unknown_shapes_instead_of_guessing() {
        for url in [
            "",                                   // 空
            "   ",                                // 空白
            "/srv/git/local-repo.git",            // 本地绝对路径
            "file:///srv/git/local-repo.git",     // file:// 传输
            "ssh://git@host:2222/owner/name.git", // 带端口
            "https://github.com:443/owner/name",  // 带端口
            "github.com/owner/sub/name",          // 多级 namespace
            "github.com/owner",                   // 缺 name 段
            "github.com//name",                   // 空 owner 段
            "https:///owner/name",                // 空 host
            "git@",                               // 无路径
            "owner/name.git",                     // 单段（无 host）
        ] {
            assert_eq!(
                normalize_remote_url(url),
                None,
                "{url:?} 必须诚实拒绝而不是半猜"
            );
        }
    }

    #[test]
    fn rejects_windows_drive_paths_as_hosts() {
        // 盘符路径会被误读成 host:path；单字符 host 必须拒绝。
        assert_eq!(normalize_remote_url("C:/repo/app"), None);
        assert_eq!(normalize_remote_url("D:\\repo\\app"), None);
    }

    #[test]
    fn rejects_slug_over_length_bound() {
        let owner = "o".repeat(REPO_SLUG_MAX_CHARS + 1);
        let url = format!("https://github.com/{owner}/name");
        assert_eq!(normalize_remote_url(&url), None);
        let owner = "o".repeat(REPO_SLUG_MAX_CHARS - "github.com//name".len());
        let url = format!("https://github.com/{owner}/name");
        assert!(normalize_remote_url(&url).is_some());
    }

    // ---- 解析器缓存：失败也缓存，同目录不重跑 git ----

    #[test]
    fn resolver_caches_failures_and_successes() {
        let resolver = GitRepoSlugResolver::default();
        let missing = std::env::temp_dir().join(format!("asg-no-such-dir-{}", std::process::id()));
        let missing = missing.to_str().unwrap().to_string();
        // 同一不存在目录解析两次：两次都 None（缓存命中，无 spawn）。
        assert_eq!(resolver.resolve(&missing), None);
        assert_eq!(resolver.resolve(&missing), None);

        let repo = temp_git_repo("cache");
        add_origin(&repo, "https://github.com/owner/cached.git");
        let sub = repo.join("sub");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(
            resolver.resolve(repo.to_str().unwrap()).as_deref(),
            Some("github.com/owner/cached")
        );
        assert_eq!(
            resolver.resolve(sub.to_str().unwrap()).as_deref(),
            Some("github.com/owner/cached")
        );
        // 删掉仓库后缓存仍返回已缓存结果（派生数据按重建批次的快照语义）。
        let _ = fs::remove_dir_all(&repo);
        assert_eq!(
            resolver.resolve(repo.to_str().unwrap()).as_deref(),
            Some("github.com/owner/cached")
        );
    }

    /// CI 的临时目录常是别名路径（macOS `/var` -> `/private/var`、Windows
    /// junction / 8.3 短名 / 大小写差异），而 `git rev-parse --show-toplevel`
    /// 报的是解析后的真实路径。守卫必须按真实路径判定，否则重叠派发被误判
    /// 成需要回退，search 会多花一次 git 子进程（CI 实测 3 次探测）。
    #[cfg(unix)]
    #[test]
    fn cwd_inside_toplevel_resolves_symlink_alias() {
        let base = std::env::temp_dir().join(format!("asg-alias-{}", std::process::id()));
        let real = base.join("real");
        let nested = real.join("sub");
        fs::create_dir_all(&nested).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let cwd_via_link = link.join("sub");
        assert!(cwd_is_inside_toplevel(
            cwd_via_link.to_str().unwrap(),
            real.to_str().unwrap()
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn cwd_inside_toplevel_accepts_case_alias() {
        let dir = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let as_written = dir.to_string_lossy().to_string();
        let lowered = as_written.to_lowercase();
        assert!(cwd_is_inside_toplevel(&as_written, &lowered));
    }
    #[test]
    fn resolver_rejects_empty_cwd_without_spawning() {
        let resolver = GitRepoSlugResolver::default();
        assert_eq!(resolver.resolve(""), None);
        assert_eq!(resolver.resolve("  "), None);
    }
}
