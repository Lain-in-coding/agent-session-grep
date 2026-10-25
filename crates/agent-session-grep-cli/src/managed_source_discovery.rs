//! Provider layout planning for explicitly selected managed histories.
//!
//! This module never opens files or grants scope. The worker admits every
//! returned path independently before metadata or content I/O. Preferred source
//! selection is an enumeration fact, not parser completeness or deletion proof.
use agent_session_grep_ports::{PortError, PortResult, SearchProvider, control::RootKind};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceKind {
    Jsonl,
    WorkBuddyMetadata,
    ZCodeDatabase,
    DeepSeekHarness { version: u64 },
    AntigravityFull,
    AntigravityDatabase,
}
impl SourceKind {
    pub(crate) fn is_jsonl(self) -> bool {
        matches!(self, Self::Jsonl | Self::AntigravityFull)
    }
    pub(crate) fn max_input_bytes(self) -> u64 {
        match self {
            Self::ZCodeDatabase => agent_session_grep_ports::manifest::ZCODE_MAX_SOURCE_BYTES,
            _ => agent_session_grep_ports::manifest::SQLITE_MAX_SOURCE_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceDescriptor {
    pub kind: SourceKind,
    /// Verified layout candidate only; physical identity and permission are
    /// supplied by the worker. Equal native IDs on different surfaces differ.
    pub surface: Option<PathBuf>,
    pub native_session: Option<String>,
}
impl SourceDescriptor {
    fn plain(kind: SourceKind) -> Self {
        Self {
            kind,
            surface: None,
            native_session: None,
        }
    }
}

fn unavailable() -> PortError {
    PortError::InvalidRequest("selected provider layout is unsupported".into())
}
fn name(path: &Path) -> Option<&str> {
    path.file_name()?.to_str()
}
fn named_ancestor(path: &Path, marker: &str) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| name(ancestor) == Some(marker))
        .map(Path::to_path_buf)
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}
fn generation(file: &str) -> Option<u64> {
    if file == "session.jsonl.zstd" {
        return Some(0);
    }
    let value = file
        .strip_prefix("session.v")?
        .strip_suffix(".jsonl.zstd")?;
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(value.parse().unwrap_or(u64::MAX))
}

/// Restrict broad native surfaces to known history children, rather than
/// traversing credentials, caches, tool outputs or every SQLite/JSON file.
/// Exact files are returned unchanged and still require provider validation.
pub(crate) fn traversal_roots(
    provider: SearchProvider,
    selected: &Path,
    kind: RootKind,
) -> PortResult<Vec<PathBuf>> {
    if kind == RootKind::Exact {
        return Ok(vec![selected.to_path_buf()]);
    }
    let roots = match provider.as_str() {
        "claude-code" | "codex" => vec![selected.to_path_buf()],
        "workbuddy" if name(selected) == Some(".workbuddy") => {
            vec![selected.join("projects"), selected.join("workbuddy.db")]
        }
        "workbuddy" => vec![selected.to_path_buf()],
        "zcode" => {
            let database = match name(selected) {
                Some(".zcode") => selected.join("cli/db/db.sqlite"),
                Some("cli") => selected.join("db/db.sqlite"),
                Some("db") => selected.join("db.sqlite"),
                _ => return Err(unavailable()),
            };
            vec![database]
        }
        "deepseek-harness" if name(selected) == Some(".dsh") => vec![selected.join("sessions")],
        "deepseek-harness" => vec![selected.to_path_buf()],
        "antigravity" => match name(selected) {
            Some(".gemini") => vec![
                selected.join("antigravity/brain"),
                selected.join("antigravity/conversations"),
                selected.join("antigravity-cli/brain"),
                selected.join("antigravity-cli/conversations"),
            ],
            Some("antigravity" | "antigravity-cli") => {
                vec![selected.join("brain"), selected.join("conversations")]
            }
            Some("brain" | "conversations") => vec![selected.to_path_buf()],
            _ if named_ancestor(selected, "brain").is_some() => vec![selected.to_path_buf()],
            _ => return Err(unavailable()),
        },
        _ => return Err(unavailable()),
    };
    Ok(roots)
}

/// Whether a directory inside an admitted traversal should be enumerated.
/// Antigravity's leaf layout is exact; mirror/chunk/step directories are pruned.
pub(crate) fn descend(provider: SearchProvider, path: &Path) -> bool {
    if provider.as_str() != "antigravity" {
        return true;
    }
    if let Some(brain) = named_ancestor(path, "brain") {
        let Ok(relative) = path.strip_prefix(&brain) else {
            return false;
        };
        let components = relative
            .iter()
            .filter_map(|value| value.to_str())
            .collect::<Vec<_>>();
        return match components.as_slice() {
            [] => true,
            [id] => uuid(id),
            [id, ".system_generated"] => uuid(id),
            [id, ".system_generated", "logs"] => uuid(id),
            _ => false,
        };
    }
    name(path) == Some("conversations")
}

pub(crate) fn describe(
    provider: SearchProvider,
    path: &Path,
    exact: bool,
) -> Option<SourceDescriptor> {
    match provider.as_str() {
        "claude-code" | "codex"
            if exact || path.extension().is_some_and(|value| value == "jsonl") =>
        {
            Some(SourceDescriptor::plain(SourceKind::Jsonl))
        }
        "workbuddy" if name(path) == Some("workbuddy.db") => Some(SourceDescriptor {
            kind: SourceKind::WorkBuddyMetadata,
            surface: path.parent().map(Path::to_path_buf),
            native_session: None,
        }),
        "workbuddy" if path.extension().is_some_and(|value| value == "jsonl") => {
            let projects = named_ancestor(path.parent()?, "projects");
            if projects.is_none() && !exact {
                return None;
            }
            Some(SourceDescriptor {
                kind: SourceKind::Jsonl,
                surface: projects.and_then(|projects| projects.parent().map(Path::to_path_buf)),
                native_session: None,
            })
        }
        "zcode" if exact || name(path) == Some("db.sqlite") => {
            Some(SourceDescriptor::plain(SourceKind::ZCodeDatabase))
        }
        "deepseek-harness" => {
            let version = generation(name(path)?)?;
            let session = path.parent()?;
            let native = name(session)?.to_string();
            if native.is_empty() || native.len() > 65_536 {
                return None;
            }
            let surface = named_ancestor(session, "sessions")
                .or_else(|| exact.then(|| session.to_path_buf()))?;
            Some(SourceDescriptor {
                kind: SourceKind::DeepSeekHarness { version },
                surface: Some(surface),
                native_session: Some(native),
            })
        }
        "antigravity" if name(path) == Some("transcript_full.jsonl") => {
            let logs = path.parent()?;
            if name(logs) != Some("logs") {
                return None;
            }
            let generated = logs.parent()?;
            if name(generated) != Some(".system_generated") {
                return None;
            }
            let session = generated.parent()?;
            let native = name(session)?;
            if !uuid(native) {
                return None;
            }
            let brain = session.parent()?;
            if name(brain) != Some("brain") {
                return None;
            }
            Some(SourceDescriptor {
                kind: SourceKind::AntigravityFull,
                surface: brain.parent().map(Path::to_path_buf),
                native_session: Some(native.to_ascii_lowercase()),
            })
        }
        "antigravity" if path.extension().is_some_and(|value| value == "db") => {
            let native = path.file_stem()?.to_str()?;
            if !uuid(native) {
                return None;
            }
            let conversations = path.parent()?;
            if name(conversations) != Some("conversations") {
                return None;
            }
            Some(SourceDescriptor {
                kind: SourceKind::AntigravityDatabase,
                surface: conversations.parent().map(Path::to_path_buf),
                native_session: Some(native.to_ascii_lowercase()),
            })
        }
        _ => None,
    }
}

/// Match the documented UTF-16 code-unit escaping used for native session IDs.
/// This verifies an already parsed header against its physical session segment;
/// it never decodes an arbitrary filename into an asserted provider identity.
pub(crate) fn dsh_segment_matches(native: &str, segment: &str) -> bool {
    if native.is_empty() || native.len() > 65_536 {
        return false;
    }
    let mut encoded = String::new();
    for unit in native.encode_utf16() {
        if unit < 128
            && ((unit as u8).is_ascii_alphanumeric() || matches!(unit as u8, b'.' | b'_' | b'-'))
            && !matches!(native, "." | "..")
        {
            encoded.push(char::from(unit as u8));
        } else {
            use std::fmt::Write;
            if write!(&mut encoded, "~{unit:04X}").is_err() {
                return false;
            }
        }
        if encoded.len() > 65_536 {
            return false;
        }
    }
    encoded == segment
}

/// Pick only the preferred physical representation per proven-layout candidate.
/// A future DSH generation is retained here and will be refused by parsing;
/// filtering it away would incorrectly resurrect an older supported version.
pub(crate) fn authoritative_indices(descriptors: &[SourceDescriptor]) -> Vec<usize> {
    let mut preferred = BTreeMap::<(&str, &Path, &str), (usize, u64)>::new();
    let mut independent = Vec::new();
    for (index, descriptor) in descriptors.iter().enumerate() {
        let rank = match descriptor.kind {
            SourceKind::DeepSeekHarness { version } => version,
            SourceKind::AntigravityFull => 2,
            SourceKind::AntigravityDatabase => 1,
            _ => {
                independent.push(index);
                continue;
            }
        };
        let (Some(surface), Some(native)) = (&descriptor.surface, &descriptor.native_session)
        else {
            independent.push(index);
            continue;
        };
        preferred
            .entry((
                if matches!(descriptor.kind, SourceKind::DeepSeekHarness { .. }) {
                    "deepseek-harness"
                } else {
                    "antigravity"
                },
                surface.as_path(),
                native.as_str(),
            ))
            .and_modify(|current| {
                if rank > current.1 {
                    *current = (index, rank);
                }
            })
            .or_insert((index, rank));
    }
    independent.extend(preferred.values().map(|(index, _)| *index));
    independent.sort_unstable();
    independent
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provider(value: &str) -> SearchProvider {
        SearchProvider::parse(value).unwrap()
    }
    #[test]
    fn broad_surfaces_restrict_history_without_adjacent_permission() {
        let selected = Path::new("/synthetic/.workbuddy/projects");
        assert_eq!(
            traversal_roots(provider("workbuddy"), selected, RootKind::Root).unwrap(),
            vec![selected]
        );
        assert_eq!(
            traversal_roots(
                provider("zcode"),
                Path::new("/synthetic/.zcode"),
                RootKind::Root
            )
            .unwrap(),
            vec![PathBuf::from("/synthetic/.zcode/cli/db/db.sqlite")]
        );
        assert!(
            traversal_roots(
                provider("zcode"),
                Path::new("/synthetic/cache"),
                RootKind::Root
            )
            .is_err()
        );
        let roots = traversal_roots(
            provider("antigravity"),
            Path::new("/synthetic/.gemini"),
            RootKind::Root,
        )
        .unwrap();
        assert_eq!(roots.len(), 4);
        assert!(roots.iter().all(|path| !path.ends_with("config")));
    }
    #[test]
    fn full_transcript_wins_only_within_its_surface_and_mirrors_are_excluded() {
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let full = PathBuf::from(format!(
            "/synthetic/antigravity/brain/{id}/.system_generated/logs/transcript_full.jsonl"
        ));
        let db = PathBuf::from(format!("/synthetic/antigravity/conversations/{id}.db"));
        let other = PathBuf::from(format!("/synthetic/antigravity-cli/conversations/{id}.db"));
        let descriptors = [
            describe(provider("antigravity"), &db, false).unwrap(),
            describe(provider("antigravity"), &full, false).unwrap(),
            describe(provider("antigravity"), &other, false).unwrap(),
        ];
        assert_eq!(authoritative_indices(&descriptors), vec![1, 2]);
        assert!(
            describe(
                provider("antigravity"),
                &full.with_file_name("transcript.jsonl"),
                true
            )
            .is_none()
        );
        assert!(!descend(
            provider("antigravity"),
            &full.parent().unwrap().join("chunks")
        ));
        assert!(!descend(
            provider("antigravity"),
            &full.parent().unwrap().parent().unwrap().join("steps")
        ));
    }
    #[test]
    fn highest_future_dsh_source_is_kept_and_noncanonical_versions_are_not_fallback() {
        let root = Path::new("/synthetic/.dsh/sessions/project/native-session");
        let descriptors = [4, 3, 99].map(|version| {
            describe(
                provider("deepseek-harness"),
                &root.join(format!("session.v{version}.jsonl.zstd")),
                false,
            )
            .unwrap()
        });
        assert_eq!(authoritative_indices(&descriptors), vec![2]);
        let enormous = describe(
            provider("deepseek-harness"),
            &root.join("session.v18446744073709551616.jsonl.zstd"),
            true,
        )
        .unwrap();
        assert!(matches!(
            enormous.kind,
            SourceKind::DeepSeekHarness { version: u64::MAX }
        ));
        let with_enormous = [descriptors[0].clone(), enormous];
        assert_eq!(authoritative_indices(&with_enormous), vec![1]);
        for file in [
            "session.v04.jsonl.zstd",
            "session.v4.jsonl",
            "session.v0.jsonl.zstd",
        ] {
            assert!(describe(provider("deepseek-harness"), &root.join(file), true).is_none());
        }
    }
    #[test]
    fn dsh_native_segment_uses_exact_utf16_escaping_and_canonical_zero_generation() {
        assert!(dsh_segment_matches("native-session", "native-session"));
        assert!(dsh_segment_matches(
            "中文/😀~",
            "~4E2D~6587~002F~D83D~DE00~007E"
        ));
        assert!(dsh_segment_matches(".", "~002E"));
        assert!(dsh_segment_matches("..", "~002E~002E"));
        assert!(!dsh_segment_matches("中文", "中文"));
        assert!(!dsh_segment_matches("native", "other"));
        assert_eq!(generation("session.jsonl.zstd"), Some(0));
        assert_eq!(generation("session.v0.jsonl.zstd"), None);
    }

    #[test]
    fn metadata_and_database_never_take_jsonl_prefix_rules() {
        let metadata = describe(
            provider("workbuddy"),
            Path::new("/synthetic/.workbuddy/workbuddy.db"),
            true,
        )
        .unwrap();
        assert_eq!(metadata.kind, SourceKind::WorkBuddyMetadata);
        assert!(!metadata.kind.is_jsonl());
        let database = describe(
            provider("zcode"),
            Path::new("/synthetic/.zcode/cli/db/db.sqlite"),
            true,
        )
        .unwrap();
        assert!(!database.kind.is_jsonl());
        assert_eq!(database.kind.max_input_bytes(), 256 * 1024 * 1024);
        assert_eq!(metadata.kind.max_input_bytes(), 128 * 1024 * 1024);
    }
}
