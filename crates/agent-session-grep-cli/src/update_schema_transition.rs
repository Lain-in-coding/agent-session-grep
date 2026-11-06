//! Pure records for the one repository-proof schema transition.
//!
//! Successful decoding establishes record agreement only. It never verifies a
//! file, running executable, root, lock, old-directory absence or complete v2
//! state. The internal command is deliberately an unconditional effect-free
//! refusal until the complete transition protocol is available.
use crate::{
    protocol::CanonicalCode,
    update_state::{Checkpoint, Phase, State, VersionIdentity},
};
use agent_session_grep_adapters_sqlite::managed_store::validate_catalog_path;
use agent_session_grep_launcher::metadata::{APP_NAME, BUILD_TARGET};
use agent_session_grep_ports::control::ControlId;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt,
    path::{Component, Path, PathBuf},
};

const COMMAND: &str = "__asg-schema-transition";
const MODE: &str = "repository-proof-22-2-to-23-3";
const ADMISSION_SCHEMA: &str = "asg.schema-transition-admission/v2";
const GUARD_SCHEMA: &str = "asg.update-supersede/v2";
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 8192;
const MAX_COUNTER: u64 = i64::MAX as u64;

/// Bounded, content-free record failure. No private input is included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    Invalid,
    TooLarge,
    MissingOldTerminal,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid schema-transition record",
            Self::TooLarge => "schema-transition record exceeds its limit",
            Self::MissingOldTerminal => "schema-transition old terminal record is required",
        })
    }
}

impl std::error::Error for RecordError {}

type Result<T> = std::result::Result<T, RecordError>;

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(RecordError::Invalid)
    }
}

fn bounded(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_RECORD_BYTES {
        Err(RecordError::TooLarge)
    } else {
        require(!bytes.is_empty())
    }
}

fn lower_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn id(value: &str) -> Result<()> {
    require(ControlId::parse(value).is_ok())
}

fn fresh_id(value: &str, prefix: &str) -> Result<()> {
    id(value)?;
    require(
        value
            .strip_prefix(prefix)
            .is_some_and(|suffix| lower_hex(suffix, 32)),
    )
}

fn root_token(value: &str) -> Result<()> {
    require(
        value
            .strip_prefix("root_v1_")
            .is_some_and(|suffix| lower_hex(suffix, 64)),
    )
}

fn absolute_path(path: &Path) -> Result<()> {
    let text = path.to_str().ok_or(RecordError::Invalid)?;
    require(
        !text.is_empty()
            && text.len() <= MAX_PATH_BYTES
            && !text.chars().any(char::is_control)
            && path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
    )?;
    // This existing path grammar is pure; it opens no catalog or directory.
    validate_catalog_path(path).map_err(|_| RecordError::Invalid)
}

/// Preflight objects without materializing an untyped JSON value. In particular,
/// serde's struct sequence representation and duplicate enum keys are forbidden.
struct ObjectShape;
struct FieldShape;

fn object_fields<'de, M: MapAccess<'de>>(mut map: M) -> std::result::Result<(), M::Error> {
    let mut keys = BTreeSet::new();
    while let Some(key) = map.next_key::<String>()? {
        if !keys.insert(key) {
            return Err(serde::de::Error::custom("duplicate record field"));
        }
        map.next_value::<FieldShape>()?;
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ObjectShape {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = ObjectShape;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a record object")
            }

            fn visit_map<M: MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                object_fields(map)?;
                Ok(ObjectShape)
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

impl<'de> Deserialize<'de> for FieldShape {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct FieldVisitor;
        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = FieldShape;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a record object, string, unsigned integer, boolean or null")
            }

            fn visit_map<M: MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                object_fields(map)?;
                Ok(FieldShape)
            }

            fn visit_str<E: serde::de::Error>(
                self,
                _: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(FieldShape)
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
                Ok(FieldShape)
            }

            fn visit_bool<E: serde::de::Error>(
                self,
                _: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(FieldShape)
            }

            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(FieldShape)
            }
        }
        deserializer.deserialize_any(FieldVisitor)
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bounded(bytes)?;
    serde_json::from_slice::<ObjectShape>(bytes).map_err(|_| RecordError::Invalid)?;
    serde_json::from_slice(bytes).map_err(|_| RecordError::Invalid)
}

fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(record).map_err(|_| RecordError::Invalid)?;
    bounded(&bytes)?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum TransitionMode {
    #[serde(rename = "repository-proof-22-2-to-23-3")]
    RepositoryProof,
}

impl<'de> Deserialize<'de> for TransitionMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            MODE => Ok(Self::RepositoryProof),
            _ => Err(serde::de::Error::custom("invalid transition mode")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundRootRecord {
    path: PathBuf,
    identity: String,
}

impl BoundRootRecord {
    fn validate(&self) -> Result<()> {
        absolute_path(&self.path)?;
        root_token(&self.identity)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleRecord {
    archive_path: PathBuf,
    manifest_path: PathBuf,
    checksums_path: PathBuf,
    archive_sha256: String,
    manifest_sha256: String,
    checksums_sha256: String,
}

impl BundleRecord {
    fn validate(&self) -> Result<()> {
        for path in [
            &self.archive_path,
            &self.manifest_path,
            &self.checksums_path,
        ] {
            absolute_path(path)?;
        }
        require(
            lower_hex(&self.archive_sha256, 64)
                && lower_hex(&self.manifest_sha256, 64)
                && lower_hex(&self.checksums_sha256, 64),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExecutorRole {
    Bootstrap,
    Final,
}

impl<'de> Deserialize<'de> for ExecutorRole {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "bootstrap" => Ok(Self::Bootstrap),
            "final" => Ok(Self::Final),
            _ => Err(serde::de::Error::custom("invalid executor role")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutorRecord {
    role: ExecutorRole,
    path: PathBuf,
    app_sha256: String,
}

impl ExecutorRecord {
    fn compare(&self, role: ExecutorRole, root: &Path, new: &VersionIdentity) -> Result<()> {
        absolute_path(&self.path)?;
        require(
            self.role == role
                && self.path.as_os_str() == root.join(&new.relative_dir).join(APP_NAME).as_os_str()
                && self.app_sha256 == new.app_sha256,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OldJournalLayout {
    Absent {
        updated: bool,
        generation: u64,
    },
    TerminalV1 {
        update_id: String,
        state_sha256: String,
        state_size_bytes: u64,
        run_identity: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRecord {
    schema: String,
    mode: TransitionMode,
    update_id: String,
    owner_nonce: String,
    prefix: BoundRootRecord,
    control_root: BoundRootRecord,
    catalog: PathBuf,
    installation_id: String,
    old: VersionIdentity,
    new: VersionIdentity,
    old_pointer_generation: u64,
    new_pointer_generation: u64,
    stable_launcher_sha256: String,
    incoming_root: BoundRootRecord,
    bundle: BundleRecord,
    bootstrap: ExecutorRecord,
    final_executor: ExecutorRecord,
    checkpoint: Checkpoint,
    old_layout: OldJournalLayout,
}

fn version(record: &VersionIdentity, pair: (u32, u32)) -> Result<()> {
    record.validate().map_err(|_| RecordError::Invalid)?;
    require(
        record.version.len() <= 128
            && record.target.len() <= 128
            && record.target == BUILD_TARGET
            && record.relative_dir.len() <= 240
            && record.relative_dir.is_ascii()
            && (record.catalog_schema, record.control_schema) == pair,
    )
}

impl AdmissionRecord {
    fn validate(&self) -> Result<()> {
        require(self.schema == ADMISSION_SCHEMA)?;
        fresh_id(&self.update_id, "update_")?;
        fresh_id(&self.owner_nonce, "update_owner_")?;
        self.prefix.validate()?;
        self.control_root.validate()?;
        self.incoming_root.validate()?;
        absolute_path(&self.catalog)?;
        id(&self.installation_id)?;
        version(&self.old, (22, 2))?;
        version(&self.new, (23, 3))?;
        self.checkpoint
            .validate()
            .map_err(|_| RecordError::Invalid)?;
        require(
            self.catalog.parent() == Some(self.control_root.path.as_path())
                && self.old_pointer_generation > 0
                && self.new_pointer_generation <= MAX_COUNTER
                && self.old_pointer_generation.checked_add(1) == Some(self.new_pointer_generation)
                && lower_hex(&self.stable_launcher_sha256, 64)
                && self.checkpoint.installation_id == self.installation_id
                && self.checkpoint.catalog_schema == 22
                && self.checkpoint.policy_epoch <= self.checkpoint.control_seq,
        )?;
        self.bundle.validate()?;
        self.bootstrap
            .compare(ExecutorRole::Bootstrap, &self.incoming_root.path, &self.new)?;
        self.final_executor
            .compare(ExecutorRole::Final, &self.prefix.path, &self.new)?;
        match &self.old_layout {
            OldJournalLayout::Absent {
                updated,
                generation,
            } => require(!*updated && *generation == 1 && self.old_pointer_generation == 1),
            OldJournalLayout::TerminalV1 {
                update_id,
                state_sha256,
                state_size_bytes,
                run_identity,
            } => {
                id(update_id)?;
                root_token(run_identity)?;
                require(
                    update_id != &self.update_id
                        && lower_hex(state_sha256, 64)
                        && (1..=MAX_RECORD_BYTES as u64).contains(state_size_bytes),
                )
            }
        }
    }
}

/// An immutable decoded admission and the exact bytes received.
///
/// No field is a verified physical capability. Only a future retained-input
/// admission may establish filesystem, package or running-image authority.
#[derive(Debug)]
pub struct AdmissionV2 {
    record: AdmissionRecord,
    raw: Vec<u8>,
}

impl AdmissionV2 {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let record: AdmissionRecord = decode(bytes)?;
        record.validate()?;
        Ok(Self {
            record,
            raw: bytes.to_vec(),
        })
    }

    /// Encode canonical bytes without replacing the received bytes' identity.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.record.validate()?;
        encode(&self.record)
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn compare_old_layout(&self, supplied: Option<OldTerminalInput<'_>>) -> Result<()> {
        let record = &self.record;
        match &record.old_layout {
            OldJournalLayout::Absent { .. } => require(supplied.is_none()),
            OldJournalLayout::TerminalV1 {
                update_id,
                state_sha256,
                state_size_bytes,
                run_identity,
            } => {
                let supplied = supplied.ok_or(RecordError::MissingOldTerminal)?;
                bounded(supplied.state)?;
                absolute_path(supplied.run_path)?;
                root_token(supplied.run_identity)?;
                require(
                    supplied.state.len() as u64 == *state_size_bytes
                        && sha256(supplied.state) == *state_sha256
                        && supplied.run_identity == run_identity
                        && supplied.run_path == record.prefix.path.join("update").join(update_id),
                )?;
                // Keep the v1 compatibility decoder and its existing validation;
                // v1 has optional/default fields and arrays that v2 records lack.
                let old: State =
                    serde_json::from_slice(supplied.state).map_err(|_| RecordError::Invalid)?;
                old.validate().map_err(|_| RecordError::Invalid)?;
                require(
                    old.update_id == *update_id
                        && old.prefix_binding == record.prefix.identity
                        && old.catalog == record.catalog
                        && old.checkpoint.installation_id == record.installation_id,
                )?;
                // Same selection as v1 journal_permits. Directory/residue/root
                // checks from that real predicate are deliberately still pending.
                let (selected, generation) = match old.phase {
                    Phase::Complete if old.error_code.is_none() => {
                        (&old.new, old.new_pointer_generation)
                    }
                    Phase::Failed | Phase::RolledBack => (&old.old, old.old_pointer_generation),
                    _ => return Err(RecordError::Invalid),
                };
                require(selected == &record.old && generation == record.old_pointer_generation)
            }
        }
    }
}

/// Caller-supplied bytes and labels for pure old-terminal comparisons.
///
/// These values do not prove that a directory exists, is private, or is the
/// originally held run. The future filesystem admission must establish that.
pub struct OldTerminalInput<'a> {
    pub state: &'a [u8],
    pub run_path: &'a Path,
    pub run_identity: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardRecord {
    schema: String,
    mode: TransitionMode,
    update_id: String,
    owner_nonce: String,
    prefix_binding: String,
    admission_sha256: String,
    initial_state_sha256: String,
}

impl GuardRecord {
    fn validate(&self) -> Result<()> {
        require(self.schema == GUARD_SCHEMA)?;
        fresh_id(&self.update_id, "update_")?;
        fresh_id(&self.owner_nonce, "update_owner_")?;
        root_token(&self.prefix_binding)?;
        require(lower_hex(&self.admission_sha256, 64) && lower_hex(&self.initial_state_sha256, 64))
    }
}

/// A strict guard record, with no publication or recovery authority.
#[derive(Debug)]
pub struct SupersedeGuardV2 {
    record: GuardRecord,
    raw: Vec<u8>,
}

impl SupersedeGuardV2 {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let record: GuardRecord = decode(bytes)?;
        record.validate()?;
        Ok(Self {
            record,
            raw: bytes.to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.record.validate()?;
        encode(&self.record)
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Compare exact records. `initial_state` remains opaque: its digest does
    /// not establish a valid StateV2. Success never permits an external effect.
    pub fn validate_relations(
        &self,
        admission: &AdmissionV2,
        initial_state: &[u8],
        old_terminal: Option<OldTerminalInput<'_>>,
    ) -> Result<()> {
        bounded(initial_state)?;
        self.record.validate()?;
        admission.record.validate()?;
        let (guard, record) = (&self.record, &admission.record);
        require(
            guard.mode == record.mode
                && guard.update_id == record.update_id
                && guard.owner_nonce == record.owner_nonce
                && guard.prefix_binding == record.prefix.identity
                && guard.admission_sha256 == sha256(admission.raw_bytes())
                && guard.initial_state_sha256 == sha256(initial_state),
        )?;
        admission.compare_old_layout(old_terminal)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InternalAction {
    Prepare {
        source: PathBuf,
        archive: PathBuf,
        manifest: PathBuf,
        checksums: PathBuf,
    },
    Continue {
        update_id: String,
    },
}

/// Closed internal argv. Parsing does not inspect the host or start a clock.
///
/// The eventual user upgrade automates these roles and retains its original
/// effective end across processes; they are not two manual 120-second requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    prefix: PathBuf,
    control_root: PathBuf,
    catalog: PathBuf,
    action: InternalAction,
}

impl Invocation {
    pub fn parse(args: &[OsString]) -> Result<Self> {
        require(args.first().is_some_and(|word| word == COMMAND) && matches!(args.len(), 13 | 19))?;
        let mut fields = BTreeMap::new();
        for pair in args[1..].as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(RecordError::Invalid)?;
            let value = pair[1].to_str().ok_or(RecordError::Invalid)?;
            require(matches!(
                key,
                "--mode"
                    | "--action"
                    | "--install-prefix"
                    | "--control-root"
                    | "--db"
                    | "--source"
                    | "--from"
                    | "--manifest"
                    | "--checksums"
                    | "--update-id"
            ))?;
            require(
                !value.is_empty()
                    && value.len() <= MAX_PATH_BYTES
                    && !value.starts_with('-')
                    && !value.chars().any(char::is_control)
                    && fields.insert(key, value).is_none(),
            )?;
        }
        let required = |key| fields.get(key).copied().ok_or(RecordError::Invalid);
        require(required("--mode")? == MODE)?;
        let prefix = PathBuf::from(required("--install-prefix")?);
        let control_root = PathBuf::from(required("--control-root")?);
        let catalog = PathBuf::from(required("--db")?);
        for path in [&prefix, &control_root, &catalog] {
            absolute_path(path)?;
        }
        require(catalog.parent() == Some(control_root.as_path()))?;
        let action = match required("--action")? {
            "prepare" => {
                require(fields.len() == 9 && !fields.contains_key("--update-id"))?;
                let source = PathBuf::from(required("--source")?);
                let archive = PathBuf::from(required("--from")?);
                let manifest = PathBuf::from(required("--manifest")?);
                let checksums = PathBuf::from(required("--checksums")?);
                for path in [&source, &archive, &manifest, &checksums] {
                    absolute_path(path)?;
                }
                InternalAction::Prepare {
                    source,
                    archive,
                    manifest,
                    checksums,
                }
            }
            "continue" => {
                require(fields.len() == 6)?;
                let update_id = required("--update-id")?;
                fresh_id(update_id, "update_")?;
                InternalAction::Continue {
                    update_id: update_id.into(),
                }
            }
            _ => return Err(RecordError::Invalid),
        };
        Ok(Self {
            prefix,
            control_root,
            catalog,
            action,
        })
    }

    /// Compare supplied argv with supplied records, never with physical state.
    pub fn validate_relations(&self, admission: &AdmissionV2) -> Result<()> {
        let record = &admission.record;
        record.validate()?;
        require(
            self.prefix == record.prefix.path
                && self.control_root == record.control_root.path
                && self.catalog == record.catalog,
        )?;
        match &self.action {
            InternalAction::Prepare {
                source,
                archive,
                manifest,
                checksums,
            } => require(
                source == &record.incoming_root.path
                    && archive == &record.bundle.archive_path
                    && manifest == &record.bundle.manifest_path
                    && checksums == &record.bundle.checksums_path,
            ),
            InternalAction::Continue { update_id } => require(update_id == &record.update_id),
        }
    }
}

/// Consume the reserved command before global --db/help handling. Both valid and
/// malformed reserved invocations are silent failures, with no I/O or deadline.
pub(crate) fn intercept(args: &[OsString]) -> Option<i32> {
    // Reuse the ordinary prefix scanner only to recognize (and refuse) misplaced
    // global flags. Lossy strings are not admitted: parse uses the original argv.
    let words: Vec<String> = args
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect();
    if crate::command_name(&words) != COMMAND {
        return None;
    }
    Some(match Invocation::parse(args) {
        Ok(_) => CanonicalCode::CapabilityNotSupported.exit_code(),
        Err(_) => CanonicalCode::InvalidRequest.exit_code(),
    })
}

#[cfg(test)]
#[path = "update_schema_transition_tests.rs"]
mod tests;
