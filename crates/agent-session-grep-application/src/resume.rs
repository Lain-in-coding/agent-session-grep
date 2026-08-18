//! Resume command descriptor and dry-run preview (#5).
//!
//! Builds the resume command from `SessionResumeMetadata`. Default is
//! dry-run preview (prints the command, does not execute). `--yes` / config
//! opt-in is required for actual execution; first install forces preview
//! once regardless.
//!
//! This module owns the resume descriptor/preview; the actual provider process
//! spawn is deferred to the execution layer (requires owner authorization per
//! CLAUDE.md). Handoff pack (#4) only consumes the descriptor, never executes.

use agent_session_grep_ports::SessionResumeMetadata;

/// Provider resume command descriptor: the command + args + cwd + permission
/// mode that would restore the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeDescriptor {
    /// Provider binary name (e.g. `claude`, `codex`, `pi`).
    pub provider_binary: String,
    /// Command arguments (e.g. `["--resume", "<session-id>"]`).
    pub args: Vec<String>,
    /// Original working directory to restore (if known).
    pub working_directory: Option<String>,
    /// Permission/approval mode flag (e.g. `--dangerously-skip-permissions`).
    /// `None` means default (no yolo/auto mode).
    pub permission_mode: Option<String>,
}

/// Dry-run preview result: what would be executed, without executing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumePreview {
    pub descriptor: ResumeDescriptor,
    /// Full command as a displayable string (e.g. `claude --resume abc-123`).
    pub command_string: String,
    /// Whether the session is resumable at all.
    pub available: bool,
    /// Why the session is not resumable (when `available` is false).
    pub unavailable_reason: Option<String>,
}

/// Build a resume descriptor from session metadata.
///
/// Unknown/unverified providers return `available:false` with a reason —
/// never fabricates a command. Only providers with known resume commands
/// produce a descriptor.
pub fn build_resume_descriptor(metadata: &SessionResumeMetadata) -> ResumePreview {
    if !metadata.resume_available {
        return ResumePreview {
            descriptor: ResumeDescriptor {
                provider_binary: String::new(),
                args: Vec::new(),
                working_directory: metadata.original_working_directory.clone(),
                permission_mode: None,
            },
            command_string: String::new(),
            available: false,
            unavailable_reason: metadata
                .unavailable_reason
                .clone()
                .or_else(|| Some("resume not available".to_string())),
        };
    }

    let provider_id = metadata.provider_id.as_deref().unwrap_or("");
    let session_id = metadata.provider_session_id.as_deref().unwrap_or("");

    // Fail-closed 边界（audit P1-2）：`resume_available=true` 但 provider
    // session id 缺失/空白时，已知 provider 也会造出空 SID 命令
    // （`claude --resume ""`）——必须降级为不可用 + 原因，绝不生成空命令。
    if session_id.trim().is_empty() {
        return ResumePreview {
            descriptor: ResumeDescriptor {
                provider_binary: String::new(),
                args: Vec::new(),
                working_directory: metadata.original_working_directory.clone(),
                permission_mode: None,
            },
            command_string: String::new(),
            available: false,
            unavailable_reason: Some(
                "resume metadata is missing the provider session id".to_string(),
            ),
        };
    }

    let (binary, args) = match provider_id {
        "claude-code" => (
            "claude",
            vec!["--resume".to_string(), session_id.to_string()],
        ),
        "codex" => ("codex", vec!["resume".to_string(), session_id.to_string()]),
        "pi" => ("pi", vec!["--session".to_string(), session_id.to_string()]),
        "grok-build" => ("grok", vec!["--resume".to_string(), session_id.to_string()]),
        // Unknown/unverified providers: resume command is null/— (not fabricated).
        // These include: opencode, antigravity, hermes, kimi-code (version conflicts),
        // and all not-yet-implemented providers.
        _ => {
            return ResumePreview {
                descriptor: ResumeDescriptor {
                    provider_binary: String::new(),
                    args: Vec::new(),
                    working_directory: metadata.original_working_directory.clone(),
                    permission_mode: None,
                },
                command_string: String::new(),
                available: false,
                unavailable_reason: Some(format!(
                    "resume command for provider '{provider_id}' is unverified or unsupported"
                )),
            };
        }
    };

    let mut full_args = args.clone();
    if let Some(mode) = &metadata_provider_permission_hint(provider_id) {
        full_args.push(mode.clone());
    }

    let command_string = format_command(binary, &full_args, &metadata.original_working_directory);

    ResumePreview {
        descriptor: ResumeDescriptor {
            provider_binary: binary.to_string(),
            args: full_args,
            working_directory: metadata.original_working_directory.clone(),
            permission_mode: metadata_provider_permission_hint(provider_id),
        },
        command_string,
        available: true,
        unavailable_reason: None,
    }
}

/// Format a resume command as a displayable string for dry-run preview.
fn format_command(binary: &str, args: &[String], cwd: &Option<String>) -> String {
    let mut parts = vec![binary.to_string()];
    parts.extend(args.iter().cloned());
    let cmd = parts.join(" ");
    if let Some(dir) = cwd {
        format!("(cd {dir} && {cmd})")
    } else {
        cmd
    }
}

/// Provider-specific permission mode hint (none by default — user must opt-in).
/// Returns `None` for all providers: resume never auto-carries yolo/full-auto.
///
/// 诚实口径：permission mode 目前恒未核验（metadata/配置均不携带真实模式），
/// 由 CLI 层在 preview 中如实标注 `permission_mode_verified: false`，不编造。
fn metadata_provider_permission_hint(_provider_id: &str) -> Option<String> {
    None
}

/// 首次 resume 强制预览的持久标记（PRD Q24 / audit P1-2）。
///
/// 契约：安装后第一次 `resume`（无论是否 `--yes`）只预览不执行，并落一个
/// 持久标记；标记存在后 `--yes` 才允许实际执行。标记按 db 所在 data root
/// 放置（与 writer lease 同一根），同一 data root 的多库共享"已看过预览"状态。
pub const RESUME_PREVIEW_ACK_FILE: &str = ".agent-session-grep-resume-ack";

/// 返回 data root 下首次预览标记的路径。
pub fn resume_preview_ack_path(data_root: &std::path::Path) -> std::path::PathBuf {
    data_root.join(RESUME_PREVIEW_ACK_FILE)
}

/// 首次预览是否已被确认（标记文件存在）。
pub fn resume_preview_acknowledged(data_root: &std::path::Path) -> bool {
    resume_preview_ack_path(data_root).is_file()
}

/// 落首次预览标记（幂等）。写失败返回错误——调用方必须保持强制预览（fail closed）。
pub fn acknowledge_resume_preview(data_root: &std::path::Path) -> std::io::Result<()> {
    let path = resume_preview_ack_path(data_root);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::StableId;
    use agent_session_grep_ports::SessionResumeMetadata;

    fn metadata(
        provider: &str,
        available: bool,
        session_id: &str,
        cwd: Option<&str>,
    ) -> SessionResumeMetadata {
        SessionResumeMetadata {
            session_id: StableId::from_wire("ses_v1_test").unwrap(),
            provider_id: Some(provider.to_string()),
            resume_available: available,
            provider_session_id: if available {
                Some(session_id.to_string())
            } else {
                None
            },
            original_working_directory: cwd.map(|s| s.to_string()),
            unavailable_reason: if !available {
                Some("no resume metadata claims".to_string())
            } else {
                None
            },
        }
    }

    #[test]
    fn builds_claude_resume_command() {
        let m = metadata("claude-code", true, "abc-123", Some("/home/user/proj"));
        let preview = build_resume_descriptor(&m);
        assert!(preview.available);
        assert_eq!(preview.descriptor.provider_binary, "claude");
        assert_eq!(preview.descriptor.args, vec!["--resume", "abc-123"]);
        assert!(preview.command_string.contains("claude --resume abc-123"));
        assert!(preview.command_string.contains("/home/user/proj"));
    }

    #[test]
    fn builds_codex_resume_command() {
        let m = metadata("codex", true, "sess-456", None);
        let preview = build_resume_descriptor(&m);
        assert!(preview.available);
        assert_eq!(preview.descriptor.provider_binary, "codex");
        assert_eq!(preview.descriptor.args, vec!["resume", "sess-456"]);
    }

    #[test]
    fn builds_pi_resume_command() {
        let m = metadata("pi", true, "uuid-789", None);
        let preview = build_resume_descriptor(&m);
        assert!(preview.available);
        assert_eq!(preview.descriptor.provider_binary, "pi");
        assert_eq!(preview.descriptor.args, vec!["--session", "uuid-789"]);
    }

    #[test]
    fn unverified_provider_returns_unavailable() {
        let m = metadata("kimi-code", true, "k-sess", None);
        let preview = build_resume_descriptor(&m);
        assert!(!preview.available);
        assert!(
            preview
                .unavailable_reason
                .as_deref()
                .unwrap()
                .contains("unverified")
        );
    }

    #[test]
    fn not_available_returns_unavailable() {
        let m = metadata("claude-code", false, "", None);
        let preview = build_resume_descriptor(&m);
        assert!(!preview.available);
        assert!(preview.unavailable_reason.is_some());
        assert!(preview.command_string.is_empty());
    }

    #[test]
    fn no_permission_mode_by_default() {
        let m = metadata("claude-code", true, "abc", None);
        let preview = build_resume_descriptor(&m);
        // Resume never auto-carries yolo/full-auto — user must opt-in.
        assert!(preview.descriptor.permission_mode.is_none());
    }

    #[test]
    fn grok_build_resume_command() {
        let m = metadata("grok-build", true, "grok-sess", None);
        let preview = build_resume_descriptor(&m);
        assert!(preview.available);
        assert_eq!(preview.descriptor.provider_binary, "grok");
        assert_eq!(preview.descriptor.args, vec!["--resume", "grok-sess"]);
    }

    #[test]
    fn resume_available_without_provider_session_id_fails_closed() {
        // audit P1-2：`resume_available=true` 但 provider_session_id 缺失——
        // 已知 provider 也会生成空 SID 命令，必须降级为不可用 + 原因。
        let m = SessionResumeMetadata {
            session_id: StableId::from_wire("ses_v1_test").unwrap(),
            provider_id: Some("claude-code".to_string()),
            resume_available: true,
            provider_session_id: None,
            original_working_directory: None,
            unavailable_reason: None,
        };
        let preview = build_resume_descriptor(&m);
        assert!(!preview.available);
        assert!(preview.command_string.is_empty());
        let reason = preview.unavailable_reason.as_deref().unwrap();
        assert!(
            reason.contains("missing the provider session id"),
            "reason: {reason}"
        );

        // 空白字符串同样视为缺失。
        let m_blank = SessionResumeMetadata {
            session_id: StableId::from_wire("ses_v1_test").unwrap(),
            provider_id: Some("codex".to_string()),
            resume_available: true,
            provider_session_id: Some("   ".to_string()),
            original_working_directory: None,
            unavailable_reason: None,
        };
        let preview = build_resume_descriptor(&m_blank);
        assert!(!preview.available);
        assert!(preview.command_string.is_empty());
    }

    #[test]
    fn capability_matrix_resume_level_matches_builder_support() {
        // audit P1-2 drift 测试：capability.rs 的 resume 级别必须与 resume
        // builder 的实际支持一致，防止矩阵与 builder 漂移。
        use agent_session_grep_ports::capability::{CapabilityLevel, ProviderCapabilityMatrix};
        let matrix = ProviderCapabilityMatrix::current();
        for capability in &matrix.providers {
            let m = SessionResumeMetadata {
                session_id: StableId::from_wire("ses_v1_drift").unwrap(),
                provider_id: Some(capability.provider_id.clone()),
                resume_available: true,
                provider_session_id: Some("synthetic-session".to_string()),
                original_working_directory: None,
                unavailable_reason: None,
            };
            let builder_supports = build_resume_descriptor(&m).available;
            assert_eq!(
                capability.resume == CapabilityLevel::Derived,
                builder_supports,
                "provider {}: capability matrix resume={:?} but resume builder support={}",
                capability.provider_id,
                capability.resume,
                builder_supports
            );
        }
    }

    #[test]
    fn first_run_preview_marker_starts_unacknowledged_and_is_idempotent() {
        let dir = unique_temp_dir("marker-ack");
        assert!(!resume_preview_acknowledged(&dir));
        acknowledge_resume_preview(&dir).expect("acknowledge");
        assert!(resume_preview_acknowledged(&dir));
        // 幂等：重复落标记不报错。
        acknowledge_resume_preview(&dir).expect("acknowledge again");
        assert!(resume_preview_acknowledged(&dir));
    }

    #[test]
    fn first_run_preview_marker_is_scoped_to_data_root() {
        let a = unique_temp_dir("marker-a");
        let b = unique_temp_dir("marker-b");
        acknowledge_resume_preview(&a).expect("acknowledge a");
        assert!(resume_preview_acknowledged(&a));
        assert!(!resume_preview_acknowledged(&b));
    }

    /// 测试专用唯一临时目录（std-only，避免新增依赖）。
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "asg-resume-marker-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
