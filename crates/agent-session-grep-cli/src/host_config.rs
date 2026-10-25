//! Explicit-path host configuration transactions. No host discovery, trust,
//! process launch, autostart or provider-history access occurs here.
//!
//! Native displacement preserves the actual replaced inode. It is not content
//! CAS against noncooperating writers. Every observed version is retained in a
//! private journal; a later write through an old handle is detected on the next
//! operation, not prevented forever. Config-stage success is not host acceptance.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use toml_edit::{DocumentMut, Item, TableLike};

const KEY: &str = "agent-session-grep";
const MAX_BYTES: u64 = 1024 * 1024;
const MAX_TRANSACTIONS: usize = 256;
const MAX_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Host {
    ClaudeCode,
    Codex,
    #[serde(rename = "zcode")]
    ZCode,
    #[serde(rename = "workbuddy")]
    WorkBuddy,
    #[serde(rename = "antigravity")]
    Antigravity,
    #[serde(rename = "deepseek-harness")]
    DeepSeekHarness,
}
impl Host {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::ZCode => "zcode",
            Self::WorkBuddy => "workbuddy",
            Self::Antigravity => "antigravity",
            Self::DeepSeekHarness => "deepseek-harness",
        }
    }
    fn parent_path(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["mcp_servers"],
            Self::ZCode => &["mcp", "servers"],
            Self::DeepSeekHarness => &["@asg-cordis-owned"],
            _ => &["mcpServers"],
        }
    }
    fn is_json(self) -> bool {
        !matches!(self, Self::Codex | Self::DeepSeekHarness)
    }
    fn preserves_format(self) -> bool {
        !self.is_json()
    }
}

/// Private local command data. No Debug implementation: these paths may be private.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpRegistration {
    pub command: String,
    pub args: Vec<String>,
}
impl McpRegistration {
    pub fn new(command: String, args: Vec<String>) -> Result<Self> {
        if command.is_empty()
            || !Path::new(&command).is_absolute()
            || args.len() > 64
            || std::iter::once(&command)
                .chain(args.iter())
                .any(|s| s.len() > 32768 || s.contains('\0'))
        {
            return Err(ErrorCode::Invalid.into());
        }
        Ok(Self { command, args })
    }
    pub(crate) fn value(&self, host: Host) -> Value {
        if host == Host::DeepSeekHarness {
            return json!({"id":KEY,"name":"@deepseek-ai/dsh-mcp-client",
                "config":{"serverName":KEY,"transport":"stdio",
                    "command":self.command,"args":self.args}});
        }
        let mut value = json!({"command": self.command, "args": self.args});
        if host == Host::ClaudeCode {
            value["type"] = json!("stdio");
        }
        value
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditStatus {
    Applied,
    Unchanged,
    Removed,
}

/// Config-stage evidence only. Ownership is revalidated against the private
/// persisted receipt and current parsed node before an update or removal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfigReceipt {
    pub schema: String,
    pub transaction_id: String,
    pub host: Host,
    pub status: EditStatus,
    pub owned_by_asg: bool,
    pub attempts: u8,
    pub before_sha256: Option<String>,
    pub after_sha256: String,
    pub owned_value_sha256: Option<String>,
    pub formatting_changed: bool,
    pub displaced_verification: bool,
    pub directory_sync_supported: bool,
}
impl fmt::Debug for HostConfigReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostConfigReceipt")
            .field("host", &self.host)
            .field("status", &self.status)
            .field("owned_by_asg", &self.owned_by_asg)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Invalid,
    Malformed,
    Unowned,
    Conflict,
    Unsupported,
    Busy,
    Io,
    RecoveryRequired,
}
#[derive(Debug)]
pub struct HostConfigError {
    pub code: ErrorCode,
    pub transaction_id: Option<String>,
}
impl fmt::Display for HostConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "host configuration {:?}; inspect private transaction state",
            self.code
        )
    }
}
impl std::error::Error for HostConfigError {}
impl From<ErrorCode> for HostConfigError {
    fn from(code: ErrorCode) -> Self {
        Self {
            code,
            transaction_id: None,
        }
    }
}
pub type Result<T> = std::result::Result<T, HostConfigError>;
fn io(_: impl fmt::Debug) -> HostConfigError {
    ErrorCode::Io.into()
}
fn lock_error(error: std::fs::TryLockError) -> HostConfigError {
    match error {
        std::fs::TryLockError::WouldBlock => ErrorCode::Busy.into(),
        std::fs::TryLockError::Error(error) => io(error),
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn node_hash(node: &Option<Value>) -> Result<Option<String>> {
    node.as_ref()
        .map(|value| serde_json::to_vec(value).map(|b| hash(&b)).map_err(io))
        .transpose()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Exchanged,
    Verified,
    Conflict,
    Settled,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryInfo {
    pub transaction_id: String,
    pub phase: Phase,
    pub attempts: u8,
    pub retained_artifact_changed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Identity {
    volume: u64,
    file: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    before: Option<String>,
    intended: String,
    original_identity: Option<Identity>,
    staged_identity: Identity,
    displaced: Option<String>,
    live: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    id: String,
    host: Host,
    logical: PathBuf,
    target: PathBuf,
    parent_identity: Identity,
    phase: Phase,
    seq: u32,
    expected: Option<Value>,
    desired: Option<Value>,
    owned: bool,
    previous_receipt: Option<String>,
    attempts: Vec<Attempt>,
    receipt: Option<HostConfigReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zcode_fallback: Option<ZcodeFallback>,
}

/// Private dependency proof for first native ZCode activation. The generic
/// config remains independently owned and read-only; copied nodes are unrelated
/// state, never part of ASG's owned-value hash.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZcodeFallback {
    logical: PathBuf,
    target: Option<PathBuf>,
    identity: Option<Identity>,
    parent_identity: Option<Identity>,
    sha256: Option<String>,
}
impl ZcodeFallback {
    fn capture(path: &Path) -> Result<(Self, Option<Vec<u8>>)> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || path.as_os_str().to_string_lossy().contains('\0')
        {
            return Err(ErrorCode::Invalid.into());
        }
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((
                Self {
                    logical: path.into(),
                    target: None,
                    identity: None,
                    parent_identity: None,
                    sha256: None,
                },
                None,
            )),
            Err(error) => Err(io(error)),
            Ok(_) => {
                let target = resolve_target(path)?;
                let parent = platform::open_directory(target.parent().ok_or(ErrorCode::Invalid)?)
                    .map_err(io)?;
                let parent_identity = platform::identity(&parent).map_err(io)?;
                let original = snapshot(&target)?.ok_or(ErrorCode::Conflict)?;
                let proof = Self {
                    logical: path.into(),
                    target: Some(target),
                    identity: Some(original.identity),
                    parent_identity: Some(parent_identity),
                    sha256: Some(hash(&original.bytes)),
                };
                proof.verify()?;
                Ok((proof, Some(original.bytes)))
            }
        }
    }
    fn verify(&self) -> Result<()> {
        let Some(target) = &self.target else {
            return match fs::symlink_metadata(&self.logical) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(ErrorCode::Conflict.into()),
            };
        };
        if resolve_target(&self.logical)? != *target {
            return Err(ErrorCode::Conflict.into());
        }
        let parent =
            platform::open_directory(target.parent().ok_or(ErrorCode::Invalid)?).map_err(io)?;
        if Some(platform::identity(&parent).map_err(io)?) != self.parent_identity {
            return Err(ErrorCode::Conflict.into());
        }
        let current = snapshot(target)?.ok_or(ErrorCode::Conflict)?;
        if Some(current.identity) != self.identity || Some(hash(&current.bytes)) != self.sha256 {
            return Err(ErrorCode::Conflict.into());
        }
        Ok(())
    }
}
fn zcode_servers(bytes: Option<&[u8]>) -> Result<Map<String, Value>> {
    let value = match bytes {
        Some(bytes) => Document::parse(Host::WorkBuddy, bytes)?.value,
        None => json!({}),
    };
    Ok(value
        .get("mcpServers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default())
}
fn copy_zcode_servers(mut value: Value, copied: &Map<String, Value>) -> Result<Value> {
    if copied.is_empty() {
        return Ok(value);
    }
    let mut object = value.as_object_mut().ok_or(ErrorCode::Malformed)?;
    for key in Host::ZCode.parent_path() {
        object = object
            .entry(*key)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or(ErrorCode::Malformed)?;
    }
    for (key, server) in copied {
        if key == KEY {
            continue;
        }
        if object.get(key).is_some_and(|existing| existing != server) {
            return Err(ErrorCode::Conflict.into());
        }
        object.entry(key.clone()).or_insert_with(|| server.clone());
    }
    Ok(value)
}

struct Snapshot {
    bytes: Vec<u8>,
    identity: Identity,
    permissions: fs::Permissions,
}
fn snapshot(path: &Path) -> Result<Option<Snapshot>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
        Ok(meta) if !meta.is_file() || platform::linked(&meta) => {
            return Err(ErrorCode::Conflict.into());
        }
        Ok(_) => {}
    }
    let mut file = platform::open_regular(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return Err(ErrorCode::Malformed.into());
    }
    let identity = platform::identity(&file).map_err(io)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(ErrorCode::Malformed.into());
    }
    Ok(Some(Snapshot {
        bytes,
        identity,
        permissions: meta.permissions(),
    }))
}
fn content(path: &Path) -> Result<Option<Vec<u8>>> {
    Ok(snapshot(path)?.map(|s| s.bytes))
}

/// UTF-8/BOM and line-ending envelope retained across DOM edits.
struct Document {
    host: Host,
    value: Value,
    toml: Option<DocumentMut>,
    cordis: Option<cordis::Document>,
    bom: bool,
    crlf: bool,
}
impl Document {
    fn parse(host: Host, bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ErrorCode::Malformed.into());
        }
        let bom = bytes.starts_with(b"\xef\xbb\xbf");
        let bytes = if bom { &bytes[3..] } else { bytes };
        let text = std::str::from_utf8(bytes).map_err(|_| ErrorCode::Malformed)?;
        let crlf = text.contains("\r\n");
        let normalized = if crlf {
            text.replace("\r\n", "\n")
        } else {
            text.to_owned()
        };
        let (value, toml, cordis) = match host {
            Host::Codex => {
                let doc = normalized
                    .parse::<DocumentMut>()
                    .map_err(|_| ErrorCode::Malformed)?;
                let value = toml_edit::de::from_document::<Value>(doc.clone())
                    .map_err(|_| ErrorCode::Malformed)?;
                (value, Some(doc), None)
            }
            Host::DeepSeekHarness => {
                let doc = cordis::Document::parse(&normalized)?;
                (doc.value(), None, Some(doc))
            }
            _ => (strict_json(&normalized)?, None, None),
        };
        if !value.is_object() {
            return Err(ErrorCode::Malformed.into());
        }
        let mut parent = &value;
        for key in host.parent_path() {
            match parent.get(*key) {
                Some(value) if value.is_object() => parent = value,
                Some(_) => return Err(ErrorCode::Malformed.into()),
                None => break,
            }
        }
        Ok(Self {
            host,
            value,
            toml,
            cordis,
            bom,
            crlf,
        })
    }
    fn empty(host: Host) -> Result<Self> {
        Self::parse(host, if host.is_json() { b"{}" } else { b"" })
    }
    fn node(&self) -> Option<Value> {
        parent(&self.value, self.host.parent_path())
            .and_then(|v| v.get(KEY))
            .cloned()
    }
    fn render(mut self, desired: &Option<Value>, unrelated: &Value) -> Result<Vec<u8>> {
        let mut final_value = unrelated.clone();
        if desired.is_some() || parent(&self.value, self.host.parent_path()).is_some() {
            let mut object = final_value.as_object_mut().ok_or(ErrorCode::Malformed)?;
            for key in self.host.parent_path() {
                object = object
                    .entry(*key)
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or(ErrorCode::Malformed)?;
            }
            match desired {
                Some(value) => {
                    object.insert(KEY.into(), value.clone());
                }
                None => {
                    object.remove(KEY);
                }
            }
        }
        let text = if let Some(doc) = &mut self.toml {
            merge_toml(doc.as_table_mut(), &self.value, &final_value)?;
            doc.to_string()
        } else if let Some(doc) = &self.cordis {
            doc.render(desired, unrelated)?
        } else {
            serde_json::to_string_pretty(&final_value).map_err(io)? + "\n"
        };
        let text = if self.crlf {
            text.replace('\n', "\r\n")
        } else {
            text
        };
        let mut bytes = if self.bom {
            vec![0xef, 0xbb, 0xbf]
        } else {
            Vec::new()
        };
        bytes.extend(text.as_bytes());
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ErrorCode::Malformed.into());
        }
        // Parent objects without an owned node carry no ownership claim.
        if without_node(Self::parse(self.host, &bytes)?.value, self.host)
            != without_node(final_value, self.host)
            || Self::parse(self.host, &bytes)?.node() != *desired
        {
            return Err(ErrorCode::Unsupported.into());
        }
        Ok(bytes)
    }
}
fn parent<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |value, key| value.get(*key))
}
fn without_node(mut value: Value, host: Host) -> Value {
    fn remove(value: &mut Value, path: &[&str]) -> bool {
        let Some(object) = value.as_object_mut() else {
            return false;
        };
        if let Some((key, rest)) = path.split_first() {
            if object
                .get_mut(*key)
                .is_some_and(|child| remove(child, rest))
            {
                object.remove(*key);
            }
        } else {
            object.remove(KEY);
        }
        object.is_empty()
    }
    remove(&mut value, host.parent_path());
    value
}

/// The YAML grammar is parsed by yaml-rust2. This module only selects a typed
/// Cordis insert row and its source range; it never evaluates or emits unrelated
/// YAML nodes. Unsupported selectors/styles cannot grant or overwrite ownership.
mod cordis {
    use super::*;
    use std::{collections::BTreeSet, ops::Range};
    use yaml_rust2::{
        Yaml,
        parser::{Event, Parser},
        scanner::TScalarStyle,
    };

    const RAW: &str = "@asg-cordis-unrelated";
    const MAX_EVENTS: usize = 65536;
    const MAX_DEPTH: usize = 64;

    enum Kind {
        Scalar(String, TScalarStyle),
        Alias,
        Sequence(Vec<Node>),
        Mapping(Vec<(String, Node)>),
    }
    struct Node {
        kind: Kind,
        start: usize,
        end: usize,
        decorated: bool,
    }
    impl Node {
        fn get(&self, key: &str) -> Option<&Self> {
            match &self.kind {
                Kind::Mapping(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
        fn literal(&self) -> Result<Option<&str>> {
            if self.decorated || matches!(self.kind, Kind::Alias) {
                return Err(ErrorCode::Unsupported.into());
            }
            match &self.kind {
                Kind::Scalar(value, _) => Ok(Some(value)),
                _ => Err(ErrorCode::Unsupported.into()),
            }
        }
        fn json(&self) -> Result<Value> {
            if self.decorated {
                return Err(ErrorCode::Unsupported.into());
            }
            match &self.kind {
                Kind::Alias => Err(ErrorCode::Unsupported.into()),
                Kind::Scalar(value, style) => {
                    if matches!(style, TScalarStyle::Literal | TScalarStyle::Folded) {
                        return Err(ErrorCode::Unsupported.into());
                    }
                    if *style != TScalarStyle::Plain {
                        return Ok(value.clone().into());
                    }
                    match Yaml::from_str(value) {
                        Yaml::String(v) => Ok(v.into()),
                        Yaml::Integer(v) => Ok(v.into()),
                        Yaml::Boolean(v) => Ok(v.into()),
                        Yaml::Null => Ok(Value::Null),
                        Yaml::Real(v) => {
                            serde_json::from_str(&v).map_err(|_| ErrorCode::Unsupported.into())
                        }
                        _ => Err(ErrorCode::Unsupported.into()),
                    }
                }
                Kind::Sequence(items) => items
                    .iter()
                    .map(Node::json)
                    .collect::<Result<Vec<_>>>()
                    .map(Value::Array),
                Kind::Mapping(items) => items
                    .iter()
                    .map(|(key, value)| {
                        if key == "<<" {
                            return Err(ErrorCode::Unsupported.into());
                        }
                        Ok((key.clone(), value.json()?))
                    })
                    .collect::<Result<Map<_, _>>>()
                    .map(Value::Object),
            }
        }
        fn reserved(&self) -> bool {
            match &self.kind {
                Kind::Mapping(items) => items.iter().any(|(key, value)| {
                    (matches!(key.as_str(), "id" | "serverName")
                        && matches!(&value.kind, Kind::Scalar(v, _) if v == KEY))
                        || value.reserved()
                }),
                Kind::Sequence(items) => items.iter().any(Node::reserved),
                _ => false,
            }
        }
    }
    fn node(events: &[(Event, usize)], index: &mut usize, depth: usize) -> Result<Node> {
        if depth > MAX_DEPTH {
            return Err(ErrorCode::Unsupported.into());
        }
        let (event, mark) = events.get(*index).ok_or(ErrorCode::Malformed)?;
        *index += 1;
        let mut start = *mark;
        let mut end = start;
        let (kind, decorated) = match event {
            Event::Scalar(value, style, anchor, tag) => (
                Kind::Scalar(value.clone(), *style),
                *anchor != 0 || tag.is_some(),
            ),
            Event::Alias(_) => (Kind::Alias, false),
            Event::SequenceStart(anchor, tag) => {
                let mut items = Vec::new();
                while !matches!(events.get(*index).map(|e| &e.0), Some(Event::SequenceEnd)) {
                    items.push(node(events, index, depth + 1)?);
                }
                end = events[*index].1;
                *index += 1;
                (Kind::Sequence(items), *anchor != 0 || tag.is_some())
            }
            Event::MappingStart(anchor, tag) => {
                let mut items = Vec::new();
                let mut keys = BTreeSet::new();
                while !matches!(events.get(*index).map(|e| &e.0), Some(Event::MappingEnd)) {
                    let key = node(events, index, depth + 1)?;
                    // Block MappingStart can mark the first colon, after its
                    // key. A row starts at the earlier key; flow maps keep {.
                    start = start.min(key.start);
                    let key = key.literal()?.ok_or(ErrorCode::Unsupported)?.to_owned();
                    if !keys.insert(key.clone()) {
                        return Err(ErrorCode::Malformed.into());
                    }
                    items.push((key, node(events, index, depth + 1)?));
                }
                end = events[*index].1;
                *index += 1;
                (Kind::Mapping(items), *anchor != 0 || tag.is_some())
            }
            _ => return Err(ErrorCode::Malformed.into()),
        };
        Ok(Node {
            kind,
            start,
            end,
            decorated,
        })
    }
    fn line_start(text: &str, index: usize) -> Result<usize> {
        let prefix = text.get(..index).ok_or(ErrorCode::Unsupported)?;
        Ok(prefix.rfind('\n').map_or(0, |i| i + 1))
    }
    fn patch_start(text: &str, item: &Node) -> Result<usize> {
        let start = line_start(text, item.start)?;
        let leading = text.get(start..item.start).ok_or(ErrorCode::Unsupported)?;
        if !leading.starts_with('-') || !leading[1..].trim().is_empty() {
            return Err(ErrorCode::Unsupported.into());
        }
        Ok(start)
    }
    fn trim_comments(text: &str, start: usize, mut end: usize) -> usize {
        // Owned block/folded scalars are refused, so a whole trailing comment
        // line cannot be part of the selected row's literal content.
        while end > start {
            let previous = if text.as_bytes()[end - 1] == b'\n' {
                end - 1
            } else {
                end
            };
            let line = text[..previous]
                .rfind('\n')
                .map_or(start, |i| (i + 1).max(start));
            let trimmed = text[line..previous].trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                break;
            }
            end = line;
        }
        end
    }
    pub(super) struct Document {
        raw: String,
        owned: Option<Value>,
        insertion: usize,
    }
    impl Document {
        pub(super) fn parse(text: &str) -> Result<Self> {
            let mut parser = Parser::new_from_str(text);
            let mut events = Vec::new();
            // This scanner consumes chars and increments Marker::index by one
            // per char, despite its byte-index documentation. Translate once
            // before any UTF-8 source splice, including Unicode before a row.
            let byte_offsets: Vec<_> = text
                .char_indices()
                .map(|(offset, _)| offset)
                .chain(std::iter::once(text.len()))
                .collect();
            let mut depth = 0usize;
            loop {
                if events.len() >= MAX_EVENTS {
                    return Err(ErrorCode::Unsupported.into());
                }
                let event = parser.next_token().map_err(|_| ErrorCode::Malformed)?;
                match &event.0 {
                    Event::SequenceStart(..) | Event::MappingStart(..) => {
                        depth += 1;
                        if depth > MAX_DEPTH {
                            return Err(ErrorCode::Unsupported.into());
                        }
                    }
                    Event::SequenceEnd | Event::MappingEnd => {
                        depth = depth.saturating_sub(1);
                    }
                    _ => {}
                }
                let done = matches!(event.0, Event::StreamEnd);
                let offset = *byte_offsets
                    .get(event.1.index())
                    .ok_or(ErrorCode::Unsupported)?;
                events.push((event.0, offset));
                if done {
                    break;
                }
            }
            if events
                .iter()
                .filter(|e| matches!(e.0, Event::DocumentStart))
                .count()
                > 1
            {
                return Err(ErrorCode::Unsupported.into());
            }
            let Some(mut index) = events
                .iter()
                .position(|e| matches!(e.0, Event::DocumentStart))
                .map(|i| i + 1)
            else {
                let mut raw = text.to_owned();
                if !raw.is_empty() && !raw.ends_with('\n') {
                    raw.push('\n');
                }
                let insertion = raw.len();
                return Ok(Self {
                    raw,
                    owned: None,
                    insertion,
                });
            };
            let root = node(&events, &mut index, 0)?;
            let document_end = events
                .get(index)
                .filter(|e| matches!(e.0, Event::DocumentEnd))
                .ok_or(ErrorCode::Malformed)?
                .1;
            let insertion = if text
                .get(document_end..)
                .is_some_and(|s| s.starts_with("..."))
            {
                line_start(text, document_end)?
            } else {
                text.len()
            };
            let mut owned = None;
            let mut removal: Option<Range<usize>> = None;
            match &root.kind {
                Kind::Sequence(items) if !root.decorated => {
                    if text.get(root.start..).is_some_and(|s| s.starts_with('[')) {
                        if !items.is_empty() {
                            return Err(ErrorCode::Unsupported.into());
                        }
                        let end = root.end.checked_add(1).ok_or(ErrorCode::Unsupported)?;
                        if text.get(root.start..end) != Some("[]") {
                            return Err(ErrorCode::Unsupported.into());
                        }
                        removal =
                            Some(root.start..text[end..].find('\n').map_or(end, |i| end + i + 1));
                    }
                    for (position, patch) in items.iter().enumerate() {
                        let start = patch_start(text, patch)?;
                        if patch.decorated || !matches!(patch.kind, Kind::Mapping(_)) {
                            return Err(ErrorCode::Unsupported.into());
                        }
                        let Some(insert) = patch.get("insert") else {
                            if patch.reserved() {
                                return Err(ErrorCode::Conflict.into());
                            }
                            continue;
                        };
                        let Kind::Sequence(rows) = &insert.kind else {
                            return Err(ErrorCode::Unsupported.into());
                        };
                        if insert.decorated {
                            return Err(ErrorCode::Unsupported.into());
                        }
                        for row in rows {
                            let id = row.get("id").map(Node::literal).transpose()?.flatten();
                            let server = row
                                .get("config")
                                .and_then(|config| config.get("serverName"))
                                .map(Node::literal)
                                .transpose()?
                                .flatten();
                            if id != Some(KEY) && server != Some(KEY) {
                                if matches!(row.kind, Kind::Alias)
                                    || row.get("<<").is_some()
                                    || row.get("config").is_some_and(|c| {
                                        matches!(c.kind, Kind::Alias) || c.get("<<").is_some()
                                    })
                                    || row.reserved()
                                {
                                    return Err(ErrorCode::Unsupported.into());
                                }
                                continue;
                            }
                            if owned.is_some() {
                                return Err(ErrorCode::Conflict.into());
                            }
                            if rows.len() != 1
                                || patch.decorated
                                || !matches!(&patch.kind, Kind::Mapping(fields) if fields.len() == 1)
                            {
                                return Err(ErrorCode::Unsupported.into());
                            }
                            let value = row.json()?;
                            if id != Some(KEY)
                                || server != Some(KEY)
                                || value.get("name").and_then(Value::as_str)
                                    != Some("@deepseek-ai/dsh-mcp-client")
                            {
                                return Err(ErrorCode::Unowned.into());
                            }
                            let limit = match items.get(position + 1) {
                                Some(next) => patch_start(text, next)?,
                                None => insertion,
                            };
                            let end = trim_comments(text, start, limit);
                            removal = Some(start..end);
                            owned = Some(value);
                        }
                    }
                }
                Kind::Scalar(value, _) if value.is_empty() && !root.decorated => {}
                _ => return Err(ErrorCode::Unsupported.into()),
            }
            let mut raw = text.to_owned();
            let mut insertion = insertion;
            if let Some(range) = removal {
                if range.end > insertion {
                    return Err(ErrorCode::Unsupported.into());
                }
                insertion = if owned.is_some() {
                    range.start
                } else {
                    insertion - range.len()
                };
                raw.replace_range(range, "");
            }
            if !raw.is_empty() && !raw.ends_with('\n') {
                raw.push('\n');
                if insertion == text.len() {
                    insertion = raw.len();
                }
            }
            Ok(Self {
                raw,
                owned,
                insertion,
            })
        }
        pub(super) fn value(&self) -> Value {
            let mut value = json!({RAW:self.raw});
            if let Some(owned) = &self.owned {
                value["@asg-cordis-owned"] = json!({KEY:owned});
            }
            value
        }
        pub(super) fn render(&self, desired: &Option<Value>, unrelated: &Value) -> Result<String> {
            let raw = unrelated
                .get(RAW)
                .and_then(Value::as_str)
                .ok_or(ErrorCode::Conflict)?;
            let parsed = Self::parse(raw)?;
            if parsed.owned.is_some() {
                return Err(ErrorCode::Conflict.into());
            }
            let addition = match desired {
                Some(value) => format!(
                    "- insert:\n    - {}\n",
                    serde_json::to_string(value).map_err(io)?
                ),
                None => "[]\n".into(),
            };
            // Preserve the owned patch's position: later Cordis patches may
            // depend on insertion order. Do not guess a slot after a raw merge.
            if parsed.raw != self.raw {
                return Err(ErrorCode::Conflict.into());
            }
            let mut output = parsed.raw;
            if desired.is_some()
                || output.lines().all(|line| {
                    let line = line.trim();
                    line.is_empty() || line.starts_with('#') || matches!(line, "---" | "...")
                })
            {
                output.insert_str(self.insertion, &addition);
            }
            Ok(output)
        }
    }
}
fn toml_item(value: &Value) -> Result<Item> {
    // Serialize a small inserted/reconciled subtree through the format editor.
    let document = toml_edit::ser::to_document(&json!({"value": value}))
        .map_err(|_| HostConfigError::from(ErrorCode::Unsupported))?;
    document
        .get("value")
        .cloned()
        .ok_or_else(|| ErrorCode::Malformed.into())
}
fn merge_toml(table: &mut dyn TableLike, before: &Value, after: &Value) -> Result<()> {
    let before = before.as_object().ok_or(ErrorCode::Malformed)?;
    let after = after.as_object().ok_or(ErrorCode::Malformed)?;
    for key in before.keys() {
        if !after.contains_key(key) {
            table.remove(key);
        }
    }
    for (key, value) in after {
        if before.get(key) == Some(value) {
            continue;
        }
        if let (Some(old), Some(nested)) = (
            before.get(key).filter(|v| v.is_object()),
            table.get_mut(key).and_then(Item::as_table_like_mut),
        ) && value.is_object()
        {
            merge_toml(nested, old, value)?;
            continue;
        }
        let mut replacement = toml_item(value)?;
        if let (Some(old), Some(new)) = (
            table.get(key).and_then(Item::as_value),
            replacement.as_value_mut(),
        ) {
            *new.decor_mut() = old.decor().clone();
        }
        table.insert(key, replacement);
    }
    Ok(())
}
fn merge_values(
    base: Option<&Value>,
    left: Option<&Value>,
    right: Option<&Value>,
) -> Result<Option<Value>> {
    if left == right {
        return Ok(left.cloned());
    }
    if left == base {
        return Ok(right.cloned());
    }
    if right == base {
        return Ok(left.cloned());
    }
    if let (Some(Value::Object(l)), Some(Value::Object(r))) = (left, right) {
        let empty = Map::new();
        let b = match base {
            Some(Value::Object(b)) => b,
            None => &empty,
            _ => return Err(ErrorCode::Conflict.into()),
        };
        let keys: std::collections::BTreeSet<_> =
            b.keys().chain(l.keys()).chain(r.keys()).collect();
        let mut result = Map::new();
        for key in keys {
            if let Some(value) = merge_values(b.get(key), l.get(key), r.get(key))? {
                result.insert(key.clone(), value);
            }
        }
        return Ok(Some(Value::Object(result)));
    }
    Err(ErrorCode::Conflict.into())
}

// serde_json normally accepts duplicate object keys; configuration edits must
// reject them at every depth rather than silently discard one value.
fn strict_json(text: &str) -> Result<Value> {
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("unambiguous JSON")
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut result = Vec::new();
                    while let Some(Unique(v)) = a.next_element()? {
                        result.push(v);
                    }
                    Ok(Unique(result.into()))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut result = Map::new();
                    while let Some((key, Unique(value))) = a.next_entry::<String, Unique>()? {
                        if result.insert(key, value).is_some() {
                            return Err(serde::de::Error::custom("duplicate key"));
                        }
                    }
                    Ok(Unique(result.into()))
                }
            }
            de.deserialize_any(Visitor)
        }
    }
    serde_json::from_str::<Unique>(text)
        .map(|v| v.0)
        .map_err(|_| ErrorCode::Malformed.into())
}

/// One explicit config and a private sibling transaction directory. The root
/// must be dedicated to this host/config. No default profile paths are read.
pub struct HostConfigStore {
    logical: PathBuf,
    target: PathBuf,
    root: PathBuf,
    host: Host,
    parent_identity: Identity,
    _parent: File,
}
impl HostConfigStore {
    pub fn open(config_path: &Path, transaction_root: &Path, host: Host) -> Result<Self> {
        if !config_path.is_absolute()
            || !transaction_root.is_absolute()
            || config_path
                .components()
                .chain(transaction_root.components())
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ErrorCode::Invalid.into());
        }
        let target = resolve_target(config_path)?;
        let parent_path = target.parent().ok_or(ErrorCode::Invalid)?;
        let parent = platform::open_directory(parent_path).map_err(io)?;
        let parent_identity = platform::identity(&parent).map_err(io)?;
        let root_parent =
            fs::canonicalize(transaction_root.parent().ok_or(ErrorCode::Invalid)?).map_err(io)?;
        if root_parent != parent_path || transaction_root == config_path {
            return Err(ErrorCode::Invalid.into());
        }
        let root = root_parent.join(transaction_root.file_name().ok_or(ErrorCode::Invalid)?);
        if fs::symlink_metadata(&root).is_ok() {
            platform::validate_private_directory(&root)
                .map_err(|_| HostConfigError::from(ErrorCode::Unsupported))?;
        }
        Ok(Self {
            logical: config_path.into(),
            target,
            root,
            host,
            parent_identity,
            _parent: parent,
        })
    }
    fn pinned(&self) -> Result<()> {
        if resolve_target(&self.logical)? != self.target {
            return Err(ErrorCode::Conflict.into());
        }
        let parent = platform::open_directory(self.target.parent().ok_or(ErrorCode::Invalid)?)
            .map_err(io)?;
        if platform::identity(&parent).map_err(io)? != self.parent_identity {
            return Err(ErrorCode::Conflict.into());
        }
        if fs::symlink_metadata(&self.root).is_ok() {
            platform::validate_private_directory(&self.root)
                .map_err(|_| HostConfigError::from(ErrorCode::Conflict))?;
        }
        Ok(())
    }
    fn lock(&self) -> Result<File> {
        self.pinned()?;
        platform::private_directory(&self.root)
            .map_err(|_| HostConfigError::from(ErrorCode::Unsupported))?;
        let path = self.root.join("owner.lock");
        if fs::symlink_metadata(&path).is_ok_and(|m| platform::linked(&m) || !m.is_file()) {
            return Err(ErrorCode::Conflict.into());
        }
        let file = platform::open_lock(&path).map_err(io)?;
        file.try_lock().map_err(lock_error)?;
        Ok(file)
    }
    /// Register one stdio MCP server. An identical unowned entry is usable,
    /// but the resulting receipt never grants permission to remove it.
    pub fn install(
        &self,
        registration: &McpRegistration,
        prior: Option<&HostConfigReceipt>,
    ) -> Result<HostConfigReceipt> {
        McpRegistration::new(registration.command.clone(), registration.args.clone())?;
        self.change(Some(registration.value(self.host)), prior, &mut |_| Ok(()))
    }
    /// ZCode first activation snapshots its independently owned generic user
    /// fallback and copies effective server nodes without acquiring ownership.
    /// Once native servers already exist the generic fallback is not consulted.
    pub fn install_with_zcode_fallback(
        &self,
        registration: &McpRegistration,
        prior: Option<&HostConfigReceipt>,
        fallback: &Path,
    ) -> Result<HostConfigReceipt> {
        if self.host != Host::ZCode {
            return Err(ErrorCode::Invalid.into());
        }
        McpRegistration::new(registration.command.clone(), registration.args.clone())?;
        self.change_with_fallback(
            Some(registration.value(self.host)),
            prior,
            Some(fallback),
            &mut |_| Ok(()),
        )
    }
    /// Remove only the still-identical owned node. Other settings remain.
    pub fn remove(&self, prior: &HostConfigReceipt) -> Result<HostConfigReceipt> {
        if !prior.owned_by_asg && prior.status != EditStatus::Removed {
            return Err(ErrorCode::Unowned.into());
        }
        self.change(None, Some(prior), &mut |_| Ok(()))
    }
    /// Read-only recovery inspection. It never repairs a config or changes a journal.
    pub fn inspect_recovery(&self) -> Result<Vec<RecoveryInfo>> {
        self.pinned()?;
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let lock_path = self.root.join("owner.lock");
        let _lock = if lock_path.exists() {
            let file = platform::open_regular(&lock_path).map_err(io)?;
            file.try_lock_shared().map_err(lock_error)?;
            Some(file)
        } else {
            None
        };
        self.inspect_locked()
    }

    /// Try to settle every outstanding interrupted transaction before a new
    /// configuration change. A host that briefly held its config open during
    /// a previous setup otherwise leaves a Conflict journal that blocks all
    /// later setup and uninstall attempts with no production repair path.
    pub fn recover_pending(&self) -> Result<usize> {
        let infos = self.inspect_recovery()?;
        let mut recovered = 0;
        for info in &infos {
            if matches!(info.phase, Phase::Verified | Phase::Settled) {
                continue;
            }
            if self.recover(&info.transaction_id).is_ok() {
                recovered += 1;
            }
        }
        Ok(recovered)
    }
    fn inspect_locked(&self) -> Result<Vec<RecoveryInfo>> {
        let mut result = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| HostConfigError::from(ErrorCode::Conflict))?;
            if name == "owner.lock" {
                continue;
            }
            if !valid_id(&name) {
                return Err(ErrorCode::Conflict.into());
            }
            let journal = self.load(&name)?;
            let changed = self.artifacts_changed(&journal)?;
            result.push(RecoveryInfo {
                transaction_id: name,
                phase: journal.phase,
                attempts: journal.attempts.len() as u8,
                retained_artifact_changed: changed,
            });
            if result.len() > MAX_TRANSACTIONS {
                return Err(ErrorCode::RecoveryRequired.into());
            }
        }
        Ok(result)
    }
    fn change(
        &self,
        desired: Option<Value>,
        prior: Option<&HostConfigReceipt>,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<HostConfigReceipt> {
        self.change_with_fallback(desired, prior, None, hook)
    }
    fn change_with_fallback(
        &self,
        desired: Option<Value>,
        prior: Option<&HostConfigReceipt>,
        fallback: Option<&Path>,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<HostConfigReceipt> {
        let _lock = self.lock()?;
        if self.inspect_locked()?.iter().any(|i| {
            !matches!(i.phase, Phase::Verified | Phase::Settled) || i.retained_artifact_changed
        }) {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let current = snapshot(&self.target)?;
        let document = match &current {
            Some(s) => Document::parse(self.host, &s.bytes)?,
            None => Document::empty(self.host)?,
        };
        let expected = document.node();
        let mut fallback_image = None;
        let mut copied = Map::new();
        let zcode_fallback = if let Some(path) = fallback
            && desired.is_some()
            && parent(&document.value, Host::ZCode.parent_path())
                .and_then(Value::as_object)
                .is_none_or(Map::is_empty)
        {
            let (proof, bytes) = ZcodeFallback::capture(path)?;
            if proof.target.as_ref() == Some(&self.target)
                || (proof.identity.is_some()
                    && proof.identity == current.as_ref().map(|snapshot| snapshot.identity))
            {
                return Err(ErrorCode::Invalid.into());
            }
            copied = zcode_servers(bytes.as_deref())?;
            if copied
                .get(KEY)
                .is_some_and(|value| Some(value) != desired.as_ref())
            {
                return Err(ErrorCode::Unowned.into());
            }
            fallback_image = bytes;
            Some(proof)
        } else {
            None
        };
        let mut owned = expected.is_none() && !copied.contains_key(KEY);
        if let Some(prior) = prior {
            let persisted = self.load(&prior.transaction_id)?;
            if persisted.receipt.as_ref() != Some(prior)
                || prior.host != self.host
                || !matches!(persisted.phase, Phase::Verified | Phase::Settled)
            {
                return Err(ErrorCode::Unowned.into());
            }
            if node_hash(&expected)? != prior.owned_value_sha256 {
                return Err(ErrorCode::Conflict.into());
            }
            owned = prior.owned_by_asg
                || (prior.status == EditStatus::Removed && expected.is_none() && desired.is_some());
        }
        if expected.is_some() && expected != desired && (!owned || prior.is_none()) {
            return Err(ErrorCode::Unowned.into());
        }
        if desired.is_none() && prior.is_none() {
            return Err(ErrorCode::Unowned.into());
        }
        let id = new_id()?;
        platform::private_directory(&self.root.join(&id)).map_err(io)?;
        let mut journal = Journal {
            schema: "asg.host-config-journal/v1".into(),
            id,
            host: self.host,
            logical: self.logical.clone(),
            target: self.target.clone(),
            parent_identity: self.parent_identity,
            phase: Phase::Prepared,
            seq: 0,
            expected: expected.clone(),
            desired: desired.clone(),
            owned,
            previous_receipt: prior.map(|p| p.transaction_id.clone()),
            attempts: Vec::new(),
            receipt: None,
            zcode_fallback,
        };
        if let Some(bytes) = &fallback_image {
            write_new(
                &self.root.join(&journal.id).join("zcode-fallback-preimage"),
                bytes,
            )?;
        }
        if expected == desired {
            let bytes = current
                .as_ref()
                .map(|s| s.bytes.clone())
                .unwrap_or_default();
            if content(&self.target)? != current.as_ref().map(|s| s.bytes.clone()) {
                return self.terminal(&mut journal, ErrorCode::Conflict);
            }
            let receipt = self.receipt(
                &journal,
                &bytes,
                Some(hash(&bytes)),
                EditStatus::Unchanged,
                false,
            );
            journal.phase = Phase::Settled;
            journal.receipt = Some(receipt.clone());
            self.save(&mut journal)?;
            return Ok(receipt);
        }
        let unrelated =
            copy_zcode_servers(without_node(document.value.clone(), self.host), &copied)?;
        let intended = document.render(&desired, &unrelated)?;
        let basis = current.map(|s| s.bytes);
        self.save(&mut journal)?;
        self.verify_fallback(&journal)?;
        hook(TestPoint::BeforeRead)?;
        let result = self.run_transaction(&mut journal, intended, basis, hook);
        result.map_err(|mut error| {
            error.transaction_id.get_or_insert(journal.id);
            error
        })
    }
    fn receipt(
        &self,
        journal: &Journal,
        bytes: &[u8],
        before: Option<String>,
        status: EditStatus,
        displaced: bool,
    ) -> HostConfigReceipt {
        HostConfigReceipt {
            schema: "asg.host-config-receipt/v1".into(),
            transaction_id: journal.id.clone(),
            host: self.host,
            status,
            owned_by_asg: journal.owned && journal.desired.is_some(),
            attempts: journal.attempts.len() as u8,
            before_sha256: before,
            after_sha256: hash(bytes),
            owned_value_sha256: node_hash(&journal.desired).ok().flatten(),
            formatting_changed: self.host.is_json() && status != EditStatus::Unchanged,
            displaced_verification: displaced,
            directory_sync_supported: cfg!(unix),
        }
    }
    fn run_transaction(
        &self,
        journal: &mut Journal,
        mut intended: Vec<u8>,
        mut basis: Option<Vec<u8>>,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<HostConfigReceipt> {
        let started = Instant::now();
        while journal.attempts.len() < MAX_ATTEMPTS && started.elapsed() < Duration::from_secs(5) {
            if let Err(error) = self.verify_fallback(journal) {
                return self.terminal(journal, error.code);
            }
            self.pinned()?;
            let before = snapshot(&self.target)?;
            let index = journal.attempts.len();
            let base = self.root.join(&journal.id);
            // Reconcile changes occurring between the original read (or last
            // attempt) and preparation. The new preimage must never silently
            // legitimize overwriting settings captured by an older rendering.
            let original = match &basis {
                Some(bytes) => Document::parse(self.host, bytes)?,
                None => Document::empty(self.host)?,
            };
            let latest = match &before {
                Some(s) => Document::parse(self.host, &s.bytes)?,
                None => Document::empty(self.host)?,
            };
            if latest.node() != original.node() {
                write_observation(&base, "unpublished-intended", &intended)?;
                return self.terminal(journal, ErrorCode::Conflict);
            }
            if before.as_ref().map(|s| s.bytes.as_slice()) != basis.as_deref() {
                if journal.zcode_fallback.is_some()
                    && index == 0
                    && parent(&latest.value, Host::ZCode.parent_path())
                        .and_then(Value::as_object)
                        .is_some_and(|servers| !servers.is_empty())
                {
                    return self.terminal(journal, ErrorCode::Conflict);
                }
                let planned = Document::parse(self.host, &intended)?;
                let merged = merge_values(
                    Some(&without_node(original.value, self.host)),
                    Some(&without_node(latest.value.clone(), self.host)),
                    Some(&without_node(planned.value, self.host)),
                )?
                .ok_or(ErrorCode::Conflict)?;
                intended = latest.render(&journal.desired, &merged)?;
            }
            if let Some(s) = &before {
                write_new(&base.join(format!("{index}-preimage")), &s.bytes)?;
            }
            write_new(&base.join(format!("{index}-intended")), &intended)?;
            let staging = base.join(format!("{index}-staged"));
            write_new(&staging, &intended)?;
            if let Some(s) = &before {
                fs::set_permissions(&staging, s.permissions.clone()).map_err(io)?;
            }
            let staged_identity = snapshot(&staging)?.ok_or(ErrorCode::Conflict)?.identity;
            journal.attempts.push(Attempt {
                before: before.as_ref().map(|s| hash(&s.bytes)),
                intended: hash(&intended),
                original_identity: before.as_ref().map(|s| s.identity),
                staged_identity,
                displaced: None,
                live: None,
            });
            journal.phase = Phase::Prepared;
            self.save(journal)?;
            hook(TestPoint::Prepared)?;
            if let Err(error) = self.pinned() {
                return self.terminal(journal, error.code);
            }
            if let Err(error) = self.verify_fallback(journal) {
                return self.terminal(journal, error.code);
            }
            let displaced_path = base.join(format!("{index}-displaced"));
            let result =
                platform::exchange(&self.target, &staging, &displaced_path, before.is_some());
            // Even a failing native operation may have moved one or more files.
            // Inspect all recorded names before choosing a recovery outcome.
            if let Err(error) = result {
                self.observe_artifacts(journal, index)?;
                let code = platform::classify(&error);
                return self.terminal(journal, code);
            }
            journal.phase = Phase::Exchanged;
            self.save(journal)?;
            hook(TestPoint::Exchanged)?;
            let current = self.observe_artifacts(journal, index)?;
            hook(TestPoint::Observed)?;
            if let Err(error) = self.verify_fallback(journal) {
                return self.terminal(journal, error.code);
            }
            let displaced = content(&displaced_path)?;
            if before.is_some() && displaced.is_none() {
                return self.terminal(journal, ErrorCode::Conflict);
            }
            if let Err(error) = self.pinned() {
                return self.terminal(journal, error.code);
            }
            let current = match current {
                Some(v) => v,
                None => return self.terminal(journal, ErrorCode::Conflict),
            };
            let reconciled = self.reconcile(journal, index, displaced.as_deref(), &current);
            let reconciled = match reconciled {
                Ok(v) => v,
                Err(e) => return self.terminal(journal, e.code),
            };
            // Re-read the retained inode, including changes through an old open
            // handle, before success. Later writes remain detectable next time.
            journal.attempts[index].displaced = displaced.as_ref().map(|b| hash(b));
            if self.artifacts_changed(journal)?
                || content(&displaced_path)?.as_deref() != displaced.as_deref()
                || content(&self.target)?.as_deref() != Some(current.as_slice())
            {
                return self.terminal(journal, ErrorCode::Conflict);
            }
            if reconciled == current {
                let status = if journal.desired.is_some() {
                    EditStatus::Applied
                } else {
                    EditStatus::Removed
                };
                let receipt = self.receipt(
                    journal,
                    &current,
                    journal.attempts.first().and_then(|a| a.before.clone()),
                    status,
                    before.is_some(),
                );
                journal.receipt = Some(receipt.clone());
                journal.phase = Phase::Verified;
                self.save(journal)?;
                hook(TestPoint::Verified)?;
                return Ok(receipt);
            }
            intended = reconciled;
            basis = Some(current);
            if index < 2 {
                std::thread::sleep(Duration::from_millis(if index == 0 { 50 } else { 150 }));
            }
        }
        self.terminal(journal, ErrorCode::Conflict)
    }
    fn reconcile(
        &self,
        journal: &Journal,
        index: usize,
        displaced: Option<&[u8]>,
        current: &[u8],
    ) -> Result<Vec<u8>> {
        let base = self.root.join(&journal.id);
        let preimage = content(&base.join(format!("{index}-preimage")))?;
        if preimage.as_ref().map(|b| hash(b)) != journal.attempts[index].before {
            return Err(ErrorCode::Conflict.into());
        }
        let before = match preimage {
            Some(ref bytes) => Document::parse(self.host, bytes)?,
            None => Document::empty(self.host)?,
        };
        let intended =
            content(&base.join(format!("{index}-intended")))?.ok_or(ErrorCode::Conflict)?;
        let intended_doc = Document::parse(self.host, &intended)?;
        if hash(&intended) != journal.attempts[index].intended {
            return Err(ErrorCode::Conflict.into());
        }
        let displaced_doc = match displaced {
            Some(bytes) => Document::parse(self.host, bytes)?,
            None => Document::empty(self.host)?,
        };
        let current_doc = Document::parse(self.host, current)?;
        if displaced_doc.node() != before.node() || current_doc.node() != journal.desired {
            return Err(ErrorCode::Conflict.into());
        }
        if journal.zcode_fallback.is_some()
            && index == 0
            && parent(&displaced_doc.value, Host::ZCode.parent_path())
                .and_then(Value::as_object)
                .is_some_and(|servers| !servers.is_empty())
        {
            return Err(ErrorCode::Conflict.into());
        }
        let original =
            self.with_fallback_servers(journal, without_node(before.value, self.host))?;
        let external = self.with_fallback_servers(
            journal,
            without_node(displaced_doc.value.clone(), self.host),
        )?;
        let intended_values = without_node(intended_doc.value, self.host);
        let live_values = without_node(current_doc.value.clone(), self.host);
        let merged = merge_values(Some(&original), Some(&external), Some(&intended_values))?
            .ok_or(ErrorCode::Conflict)?;
        let merged = merge_values(Some(&intended_values), Some(&merged), Some(&live_values))?
            .ok_or(ErrorCode::Conflict)?;
        if self.host.preserves_format() && displaced != preimage.as_deref() && current != intended {
            // Do not guess which of two independent formatting/comment edits
            // should win. Both observed byte images remain in the journal.
            return Err(ErrorCode::Conflict.into());
        }
        if merged == live_values
            && !(self.host.preserves_format()
                && displaced != preimage.as_deref()
                && current == intended)
        {
            return Ok(current.to_vec());
        }
        // If the live file is still our exact output, use the external document
        // as the formatting base so its comments/order survive the retry.
        if current == intended {
            displaced_doc.render(&journal.desired, &merged)
        } else {
            current_doc.render(&journal.desired, &merged)
        }
    }
    fn observe_artifacts(&self, journal: &mut Journal, index: usize) -> Result<Option<Vec<u8>>> {
        let base = self.root.join(&journal.id);
        let live = content(&self.target)?;
        if let Some(bytes) = &live {
            write_observation(&base, &format!("{index}-live"), bytes)?;
        }
        let displaced = content(&base.join(format!("{index}-displaced")))?;
        if let Some(bytes) = &displaced {
            write_observation(&base, &format!("{index}-observed-displaced"), bytes)?;
        }
        journal.attempts[index].live = live.as_ref().map(|b| hash(b));
        journal.attempts[index].displaced = displaced.as_ref().map(|b| hash(b));
        self.save(journal)?;
        Ok(live)
    }
    fn terminal<T>(&self, journal: &mut Journal, code: ErrorCode) -> Result<T> {
        journal.phase = Phase::Conflict;
        // Preserve the terminal observed live file as well as earlier observations.
        if let Some(bytes) = content(&self.target)? {
            write_observation(&self.root.join(&journal.id), "terminal-live", &bytes)?;
        }
        self.save(journal)?;
        Err(HostConfigError {
            code,
            transaction_id: Some(journal.id.clone()),
        })
    }
    fn save(&self, journal: &mut Journal) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(journal).map_err(io)?;
        let root = self.root.join(&journal.id);
        let path = root.join(format!("state-{:04}.json", journal.seq));
        let pending = root.join(format!("state-{:04}-{}.pending", journal.seq, new_id()?));
        write_new(&pending, &bytes)?;
        fs::rename(&pending, &path).map_err(io)?;
        platform::sync_directory(&root).map_err(io)?;
        journal.seq = journal.seq.checked_add(1).ok_or(ErrorCode::Conflict)?;
        Ok(())
    }
    fn load(&self, id: &str) -> Result<Journal> {
        if !valid_id(id) {
            return Err(ErrorCode::Invalid.into());
        }
        let root = self.root.join(id);
        platform::validate_private_directory(&root).map_err(io)?;
        let mut states = BTreeMap::new();
        for entry in fs::read_dir(&root).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(number) = name
                .strip_prefix("state-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if number.len() != 4 {
                    return Err(ErrorCode::Conflict.into());
                }
                let number: u32 = number
                    .parse()
                    .map_err(|_| HostConfigError::from(ErrorCode::Conflict))?;
                states.insert(number, entry.path());
            }
        }
        let (seq, path) = states.last_key_value().ok_or(ErrorCode::RecoveryRequired)?;
        if states.len() > 128 || states.keys().copied().ne(0..=*seq) {
            return Err(ErrorCode::Conflict.into());
        }
        let bytes = content(path)?.ok_or(ErrorCode::RecoveryRequired)?;
        let mut journal: Journal = serde_json::from_slice(&bytes)
            .map_err(|_| HostConfigError::from(ErrorCode::Conflict))?;
        if journal.schema != "asg.host-config-journal/v1"
            || journal.id != id
            || journal.host != self.host
            || journal.logical != self.logical
            || journal.target != self.target
            || journal.parent_identity != self.parent_identity
            || journal.seq != *seq
            || journal.attempts.len() > MAX_ATTEMPTS
        {
            return Err(ErrorCode::Conflict.into());
        }
        journal.seq += 1;
        Ok(journal)
    }
    fn fallback_servers(&self, journal: &Journal) -> Result<Map<String, Value>> {
        let Some(proof) = &journal.zcode_fallback else {
            return Ok(Map::new());
        };
        let bytes = content(&self.root.join(&journal.id).join("zcode-fallback-preimage"))?;
        if bytes.as_ref().map(|bytes| hash(bytes)) != proof.sha256 {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        zcode_servers(bytes.as_deref())
    }
    fn verify_fallback(&self, journal: &Journal) -> Result<()> {
        if let Some(proof) = &journal.zcode_fallback {
            self.fallback_servers(journal)?;
            proof.verify()?;
        }
        Ok(())
    }
    fn with_fallback_servers(&self, journal: &Journal, value: Value) -> Result<Value> {
        copy_zcode_servers(value, &self.fallback_servers(journal)?)
    }
    fn artifacts_changed(&self, journal: &Journal) -> Result<bool> {
        if journal.zcode_fallback.is_some() && self.fallback_servers(journal).is_err() {
            return Ok(true);
        }
        for (index, attempt) in journal.attempts.iter().enumerate() {
            let actual = content(
                &self
                    .root
                    .join(&journal.id)
                    .join(format!("{index}-displaced")),
            )?
            .as_ref()
            .map(|b| hash(b));
            if attempt.displaced != actual {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Explicit repair only. A terminal independent owned-key conflict is not
    /// overwritten. Uncertain partial operations preserve all paths for review.
    pub fn recover(&self, transaction_id: &str) -> Result<HostConfigReceipt> {
        let _lock = self.lock()?;
        let mut journal = self.load(transaction_id)?;
        if matches!(journal.phase, Phase::Verified | Phase::Settled)
            && !self.artifacts_changed(&journal)?
        {
            let current = content(&self.target)?;
            let doc = match current {
                Some(ref b) => Document::parse(self.host, b)?,
                None => Document::empty(self.host)?,
            };
            if doc.node() != journal.desired {
                return self.terminal(&mut journal, ErrorCode::Conflict);
            }
            return journal
                .receipt
                .ok_or_else(|| ErrorCode::RecoveryRequired.into());
        }
        if let Err(error) = self.verify_fallback(&journal) {
            return self.terminal(&mut journal, error.code);
        }
        if journal.attempts.is_empty() {
            if journal.zcode_fallback.is_none() {
                return self.terminal(&mut journal, ErrorCode::RecoveryRequired);
            }
            let current = snapshot(&self.target)?;
            let doc = match &current {
                Some(snapshot) => Document::parse(self.host, &snapshot.bytes)?,
                None => Document::empty(self.host)?,
            };
            if doc.node() != journal.expected
                || parent(&doc.value, Host::ZCode.parent_path())
                    .and_then(Value::as_object)
                    .is_some_and(|servers| !servers.is_empty())
            {
                return self.terminal(&mut journal, ErrorCode::Conflict);
            }
            let unrelated =
                self.with_fallback_servers(&journal, without_node(doc.value.clone(), self.host))?;
            let intended = doc.render(&journal.desired, &unrelated)?;
            return self.run_transaction(
                &mut journal,
                intended,
                current.map(|snapshot| snapshot.bytes),
                &mut |_| Ok(()),
            );
        }
        let index = journal.attempts.len() - 1;
        let base = self.root.join(&journal.id);
        // Earlier displaced inodes remain relevant after subsequent retries.
        // A new late write there needs explicit conflict review, never a fake
        // recovery success based solely on the final attempt.
        for (earlier, attempt) in journal.attempts[..index].iter().enumerate() {
            if content(&base.join(format!("{earlier}-displaced")))?
                .as_ref()
                .map(|b| hash(b))
                != attempt.displaced
            {
                return self.terminal(&mut journal, ErrorCode::Conflict);
            }
        }
        // Unix exchange can succeed before staging is renamed to displaced.
        // Recover by recorded identities, not by assuming an error had no effect.
        let stage = base.join(format!("{index}-staged"));
        let displaced_path = base.join(format!("{index}-displaced"));
        if content(&displaced_path)?.is_none()
            && let Some(staged) = snapshot(&stage)?
            && Some(staged.identity) == journal.attempts[index].original_identity
        {
            fs::rename(&stage, &displaced_path).map_err(io)?;
            platform::sync_directory(&base).map_err(io)?;
        }
        let current_snapshot = snapshot(&self.target)?;
        if journal.attempts[index].before.is_none()
            && current_snapshot
                .as_ref()
                .is_some_and(|s| s.identity != journal.attempts[index].staged_identity)
        {
            return self.terminal(&mut journal, ErrorCode::Conflict);
        }
        let current = self.observe_artifacts(&mut journal, index)?;
        let displaced = content(&base.join(format!("{index}-displaced")))?;
        let attempt = journal.attempts[index].clone();
        if current.is_none() && displaced.is_some() {
            // Native partial failure may have moved the original away but not
            // published the candidate. Publish through the next no-clobber
            // attempt only; preserve the displaced file regardless of outcome.
            let bytes = displaced.as_ref().ok_or(ErrorCode::Conflict)?;
            let doc = Document::parse(self.host, bytes)?;
            if doc.node() != journal.expected {
                return self.terminal(&mut journal, ErrorCode::Conflict);
            }
            let values =
                self.with_fallback_servers(&journal, without_node(doc.value.clone(), self.host))?;
            let intended = doc.render(&journal.desired, &values)?;
            return self.run_transaction(&mut journal, intended, None, &mut |_| Ok(()));
        }
        if displaced.is_none() && current.as_ref().map(|b| hash(b)) == attempt.before {
            // Prepared/no-effect failure: retry from current without reusing a
            // possibly moved staging name, through a new journaled attempt.
            let doc = match &current {
                Some(bytes) => Document::parse(self.host, bytes)?,
                None => Document::empty(self.host)?,
            };
            if doc.node() != journal.expected {
                return self.terminal(&mut journal, ErrorCode::Conflict);
            }
            let unrelated =
                self.with_fallback_servers(&journal, without_node(doc.value.clone(), self.host))?;
            let intended = doc.render(&journal.desired, &unrelated)?;
            return self.run_transaction(&mut journal, intended, current, &mut |_| Ok(()));
        }
        let current = current.ok_or(ErrorCode::Conflict)?;
        if displaced.is_none() && attempt.before.is_some() {
            return self.terminal(&mut journal, ErrorCode::Conflict);
        }
        let intended = match self.reconcile(&journal, index, displaced.as_deref(), &current) {
            Ok(v) => v,
            Err(e) => return self.terminal(&mut journal, e.code),
        };
        if self.artifacts_changed(&journal)?
            || content(&self.target)?.as_deref() != Some(current.as_slice())
        {
            return self.terminal(&mut journal, ErrorCode::Conflict);
        }
        if intended == current {
            let status = if journal.desired.is_some() {
                EditStatus::Applied
            } else {
                EditStatus::Removed
            };
            let receipt = self.receipt(
                &journal,
                &current,
                journal.attempts[0].before.clone(),
                status,
                displaced.is_some(),
            );
            journal.receipt = Some(receipt.clone());
            journal.phase = Phase::Verified;
            self.save(&mut journal)?;
            return Ok(receipt);
        }
        self.run_transaction(&mut journal, intended, Some(current), &mut |_| Ok(()))
    }
}

#[derive(Clone, Copy)]
enum TestPoint {
    BeforeRead,
    Prepared,
    Exchanged,
    Observed,
    Verified,
}
fn resolve_target(path: &Path) -> Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(target) => Ok(target),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // An established but now dangling link must not become a new file.
            if fs::symlink_metadata(path).is_ok() {
                return Err(ErrorCode::Conflict.into());
            }
            Ok(fs::canonicalize(path.parent().ok_or(ErrorCode::Invalid)?)
                .map_err(io)?
                .join(path.file_name().ok_or(ErrorCode::Invalid)?))
        }
        Err(e) => Err(io(e)),
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn new_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(io)?;
    Ok(bytes.iter().map(|v| format!("{v:02x}")).collect())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = platform::create_private(path).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(())
}
fn write_observation(root: &Path, prefix: &str, bytes: &[u8]) -> Result<()> {
    let path = root.join(format!("{prefix}-{}", hash(bytes)));
    if path.exists() {
        if content(&path)?.as_deref() != Some(bytes) {
            return Err(ErrorCode::Conflict.into());
        }
    } else {
        write_new(&path, bytes)?;
    }
    Ok(())
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        },
    };
    fn unsupported() -> std::io::Error {
        std::io::ErrorKind::Unsupported.into()
    }
    pub(super) fn linked(meta: &fs::Metadata) -> bool {
        meta.file_type().is_symlink()
    }
    pub(super) fn identity(file: &File) -> std::io::Result<Identity> {
        let meta = file.metadata()?;
        Ok(Identity {
            volume: meta.dev(),
            file: meta.ino(),
        })
    }
    pub(super) fn open_directory(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }
    pub(super) fn open_regular(path: &Path) -> std::io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(unsupported());
        }
        // Mode-only replacement cannot promise ACL/xattr preservation. Refuse
        // such files until an audited native metadata-copy path exists.
        #[cfg(target_os = "linux")]
        let attrs = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
        #[cfg(target_os = "macos")]
        let attrs = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if attrs != 0 {
            return Err(unsupported());
        }
        Ok(file)
    }
    pub(super) fn create_private(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }
    pub(super) fn open_lock(path: &Path) -> std::io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() != 0 {
            return Err(unsupported());
        }
        Ok(file)
    }
    pub(super) fn private_directory(path: &Path) -> std::io::Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => sync_directory(path.parent().ok_or_else(unsupported)?)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        validate_private_directory(path)
    }
    pub(super) fn validate_private_directory(path: &Path) -> std::io::Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir()
            || linked(&meta)
            || meta.mode() & 0o777 != 0o700
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err(unsupported());
        }
        Ok(())
    }
    pub(super) fn sync_directory(path: &Path) -> std::io::Result<()> {
        open_directory(path)?.sync_all()
    }
    pub(super) fn exchange(
        target: &Path,
        staging: &Path,
        displaced: &Path,
        exists: bool,
    ) -> std::io::Result<()> {
        if exists {
            let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| unsupported())?;
            let stage = CString::new(staging.as_os_str().as_bytes()).map_err(|_| unsupported())?;
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    target.as_ptr(),
                    libc::AT_FDCWD,
                    stage.as_ptr(),
                    libc::RENAME_EXCHANGE,
                )
            };
            #[cfg(target_os = "macos")]
            let result =
                unsafe { libc::renamex_np(target.as_ptr(), stage.as_ptr(), libc::RENAME_SWAP) };
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let result = -1;
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
            fs::rename(staging, displaced)?;
        } else {
            let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| unsupported())?;
            let stage = CString::new(staging.as_os_str().as_bytes()).map_err(|_| unsupported())?;
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    stage.as_ptr(),
                    libc::AT_FDCWD,
                    target.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            #[cfg(target_os = "macos")]
            let result =
                unsafe { libc::renamex_np(stage.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            return Err(unsupported());
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        sync_directory(target.parent().ok_or_else(unsupported)?)?;
        sync_directory(staging.parent().ok_or_else(unsupported)?)
    }
    pub(super) fn classify(error: &std::io::Error) -> ErrorCode {
        match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL | libc::EXDEV) => {
                ErrorCode::Unsupported
            }
            Some(libc::EEXIST | libc::ENOENT | libc::EBUSY) => ErrorCode::Conflict,
            _ => ErrorCode::Io,
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        io,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    fn failure() -> io::Error {
        io::Error::last_os_error()
    }
    fn unsupported() -> io::Error {
        io::ErrorKind::Unsupported.into()
    }
    pub(super) fn linked(meta: &fs::Metadata) -> bool {
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    pub(super) fn identity(file: &File) -> io::Result<Identity> {
        let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(failure());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(unsupported());
        }
        Ok(Identity {
            volume: info.dwVolumeSerialNumber.into(),
            file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }
    pub(super) fn open_directory(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    pub(super) fn open_regular(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        identity(&file)?;
        let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(failure());
        }
        if info.nNumberOfLinks != 1 || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(unsupported());
        }
        Ok(file)
    }
    pub(super) fn create_private(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    pub(super) fn open_lock(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        identity(&file)?;
        if file.metadata()?.len() != 0 {
            return Err(unsupported());
        }
        Ok(file)
    }
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn private_descriptor() -> io::Result<Descriptor> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(failure());
        }
        let mut needed = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        unsafe {
            CloseHandle(token);
        }
        if result == 0 {
            return Err(failure());
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
            return Err(failure());
        }
        let mut len = 0;
        unsafe {
            while *sid.add(len) != 0 {
                len += 1;
            }
        }
        let sid_text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid, len) });
        unsafe {
            LocalFree(sid.cast());
        }
        let sddl: Vec<u16> = format!("O:{sid_text}D:P(A;OICI;FA;;;{sid_text})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(failure());
        }
        Ok(Descriptor(descriptor))
    }
    fn acl(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<Vec<u8>> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            == 0
            || present == 0
            || acl.is_null()
        {
            return Err(unsupported());
        }
        Ok(
            unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize) }
                .to_vec(),
        )
    }
    pub(super) fn private_directory(path: &Path) -> io::Result<()> {
        let descriptor = private_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
            let error = failure();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        validate_private_directory(path)
    }
    pub(super) fn validate_private_directory(path: &Path) -> io::Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() || linked(&meta) {
            return Err(unsupported());
        }
        let expected = private_descriptor()?;
        let mut descriptor = ptr::null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let actual = Descriptor(descriptor);
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(actual.0, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
            || acl(actual.0)? != acl(expected.0)?
        {
            return Err(unsupported());
        }
        let mut owner = ptr::null_mut();
        let mut expected_owner = ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(actual.0, &mut owner, &mut defaulted) } == 0
            || unsafe {
                GetSecurityDescriptorOwner(expected.0, &mut expected_owner, &mut defaulted)
            } == 0
            || unsafe { EqualSid(owner, expected_owner) } == 0
        {
            return Err(unsupported());
        }
        Ok(())
    }
    // File sync_all is required for each journal/image. Windows has no general
    // unprivileged directory flush equivalent; receipts disclose this limit.
    pub(super) fn sync_directory(_path: &Path) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn exchange(
        target: &Path,
        staging: &Path,
        displaced: &Path,
        exists: bool,
    ) -> io::Result<()> {
        let target = wide(target);
        let staging = wide(staging);
        let displaced = wide(displaced);
        let result = unsafe {
            if exists {
                ReplaceFileW(
                    target.as_ptr(),
                    staging.as_ptr(),
                    displaced.as_ptr(),
                    0,
                    ptr::null(),
                    ptr::null(),
                )
            } else {
                MoveFileExW(staging.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH)
            }
        };
        if result == 0 { Err(failure()) } else { Ok(()) }
    }
    pub(super) fn classify(error: &io::Error) -> ErrorCode {
        match error.raw_os_error() {
            Some(32 | 33) => ErrorCode::Busy,
            Some(1 | 17 | 50) => ErrorCode::Unsupported,
            Some(2 | 3 | 80 | 183 | 1175 | 1176 | 1177) => ErrorCode::Conflict,
            _ => ErrorCode::Io,
        }
    }
}

#[cfg(test)]
#[path = "host_config_tests.rs"]
mod tests;
