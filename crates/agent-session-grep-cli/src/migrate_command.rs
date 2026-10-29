//! Explicit, side-path-only legacy migration. Private immutable intent binds a
//! receiving root before control/catalog creation; retries retain that identity.
//! Copied merged rows are inventory, never permission or source evidence.
use crate::{
    CliError, emit_result,
    native_autostart::platform,
    package_installation::{Installation, absolute, inspect_installation, ordinary},
    protocol::{self, CanonicalCode, Outcome, OutputMode, ProtocolError},
};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore, WriterLease,
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, RootIdentity},
    managed_migration::{LegacyInspection, LegacyMigrationRequest, inspect_legacy, migrate_legacy},
    managed_purge::{ClassifiedPrivateArtifact, PrivateArtifactClass, PrivateArtifactInventory},
    managed_store::{ManagedStore, validate_catalog_path},
};
use agent_session_grep_ports::{
    PortError, RetrievalMode,
    control::{ControlId, ControlStore, DesiredUpdates, PolicyEpoch},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) const HELP: &str = "migrate — copy a legacy catalog into a new private managed side path\n\
USAGE: asg --db <new-side-catalog> migrate --from <legacy-catalog> [--install-prefix <prefix>]\n\
The receiving directory must be new or empty and private; its immediate parent must exist.\n\
Migration preserves the legacy catalog and its WAL, namespaces and canonical IDs.\n\
The new control starts paused with no selected histories; merged legacy facts remain hidden.\n\
Use setup, sources add and resume explicitly after migration. Existing legacy clients need a new managed connection.\n\
--install-prefix verifies an installed managed package and binds its actual installation lock.\n\
Retry the same command and paths to recover its private intent. After activation recovery is forward-only.";

const SCHEMA: &str = "asg.legacy-migration-command/v1";
const INTENT: &str = "legacy-migration-command.json";
const PENDING: &str = "legacy-migration-command.pending";
const CONTROL_STARTED: &str = "legacy-migration-control-start.json";
const CONTROL_CREATE_INTENT: &str = "control.db.creating.intent";
const CONTROL_CREATE_PENDING: &str = "control.db.creating";
const CONTROL_CREATE_PUBLISH: &str = "control.db.creating.publish";
const MAX_INTENT: u64 = 64 * 1024;
const TOTAL_BUDGET: Duration = Duration::from_secs(30);
const LOCK_BUDGET: Duration = Duration::from_secs(5);
const MAX_LOCK_ATTEMPTS: usize = 256;

pub(crate) fn is_command(rest: &[String]) -> bool {
    rest.first().map(String::as_str) == Some("migrate")
}

struct Options {
    source: PathBuf,
    prefix: Option<PathBuf>,
}
fn parse(rest: &[String]) -> Result<Options, CliError> {
    if !is_command(rest) {
        return Err(CliError::usage(HELP));
    }
    let (mut source, mut prefix) = (None, None);
    let mut index = 1;
    while index < rest.len() {
        let value = rest
            .get(index + 1)
            .filter(|value| !value.is_empty() && !value.starts_with('-'))
            .ok_or_else(|| CliError::usage(HELP))?;
        match rest[index].as_str() {
            "--from" if source.is_none() => source = Some(PathBuf::from(value)),
            "--install-prefix" if prefix.is_none() => prefix = Some(PathBuf::from(value)),
            _ => return Err(CliError::usage(HELP)),
        }
        index += 2;
    }
    Ok(Options {
        source: source.ok_or_else(|| CliError::usage(HELP))?,
        prefix,
    })
}

fn error(code: CanonicalCode) -> CliError {
    let message = match code {
        CanonicalCode::InvalidRequest => {
            "migration requires distinct source and receiving roots and an explicit --from catalog"
        }
        CanonicalCode::WriterBusy => {
            "migration is busy or its deadline was reached; retry the same receiving catalog"
        }
        CanonicalCode::SourceChanged => {
            "migration identity changed; preserve the legacy catalog and verify the receiving intent"
        }
        CanonicalCode::SourceIo => {
            "migration storage is unavailable; preserve both catalogs and retry the same intent"
        }
        CanonicalCode::NotFound => "legacy catalog or private migration state is unavailable",
        _ => {
            "migration state or schema is incompatible; preserve the legacy catalog and verify the receiving state"
        }
    };
    ProtocolError::new(code, message).into()
}
fn port(value: PortError) -> CliError {
    error(ProtocolError::from_private_port_error(value).code)
}
fn io(_: impl std::fmt::Debug) -> CliError {
    error(CanonicalCode::SourceIo)
}
fn invalid() -> CliError {
    error(CanonicalCode::SchemaIncompatible)
}
fn check(end: Instant) -> Result<(), CliError> {
    if Instant::now() >= end {
        Err(error(CanonicalCode::WriterBusy))
    } else {
        Ok(())
    }
}
fn exists(path: &Path) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(value) if value.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(value) => Err(io(value)),
    }
}
fn suffix(path: &Path, ending: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(ending);
    PathBuf::from(name)
}
fn catalog_input(path: &Path) -> Result<PathBuf, CliError> {
    if path.as_os_str().is_empty()
        || path
            .as_os_str()
            .to_string_lossy()
            .chars()
            .any(char::is_control)
    {
        return Err(error(CanonicalCode::InvalidRequest));
    }
    let path = absolute(path).map_err(|_| error(CanonicalCode::InvalidRequest))?;
    validate_catalog_path(&path).map_err(|_| error(CanonicalCode::InvalidRequest))?;
    if path.file_name().is_none() {
        return Err(error(CanonicalCode::InvalidRequest));
    }
    Ok(path)
}

struct Paths {
    source: PathBuf,
    destination: PathBuf,
    root: PathBuf,
    source_root: RootIdentity,
    receiving_root: Option<RootIdentity>,
}
impl Paths {
    fn inspect(db: &str, source: &Path) -> Result<Self, CliError> {
        let source = catalog_input(source)?;
        let destination = catalog_input(Path::new(db))?;
        let source_parent = source.parent().ok_or_else(invalid)?;
        ordinary(source_parent).map_err(|_| error(CanonicalCode::InvalidRequest))?;
        let source_parent = fs::canonicalize(source_parent).map_err(io)?;
        let source = source_parent.join(source.file_name().ok_or_else(invalid)?);
        let source_root = RootIdentity::read(&source_parent).map_err(port)?;
        let requested_root = destination.parent().ok_or_else(invalid)?;
        let receiving_root = if exists(requested_root)? {
            ordinary(requested_root).map_err(|_| error(CanonicalCode::InvalidRequest))?;
            Some(RootIdentity::read(requested_root).map_err(port)?)
        } else {
            None
        };
        if receiving_root == Some(source_root) {
            return Err(error(CanonicalCode::InvalidRequest));
        }
        let root = if receiving_root.is_some() {
            fs::canonicalize(requested_root).map_err(io)?
        } else {
            let parent = requested_root.parent().ok_or_else(invalid)?;
            ordinary(parent).map_err(|_| error(CanonicalCode::InvalidRequest))?;
            fs::canonicalize(parent)
                .map_err(io)?
                .join(requested_root.file_name().ok_or_else(invalid)?)
        };
        let name = destination.file_name().ok_or_else(invalid)?;
        let folded = name.to_string_lossy().to_ascii_lowercase();
        if matches!(
            folded.as_str(),
            "control.db"
                | "control.db-wal"
                | "control.db-shm"
                | "control.db-journal"
                | INTENT
                | PENDING
                | CONTROL_STARTED
        ) || folded.ends_with(".lock")
            || folded.ends_with(".asg-managed-create")
            || folded.ends_with(".asg-legacy-file")
        {
            return Err(error(CanonicalCode::InvalidRequest));
        }
        let destination = root.join(name);
        if receiving_root.is_some() {
            platform::validate_private(&root).map_err(|_| invalid())?;
            if !exists(&root.join(INTENT))? && !exists(&root.join(PENDING))? {
                // Never adopt an existing catalog/control or unrelated files.
                // Check before creating even the command's lock file.
                if fs::read_dir(&root).map_err(io)?.next().is_some() {
                    return Err(error(CanonicalCode::InvalidRequest));
                }
            }
        }
        Ok(Self {
            source,
            destination,
            root,
            source_root,
            receiving_root,
        })
    }
    fn validate(&self, root: RootIdentity) -> Result<(), CliError> {
        ordinary(&self.root).map_err(|_| error(CanonicalCode::SourceChanged))?;
        ordinary(self.source.parent().ok_or_else(invalid)?)
            .map_err(|_| error(CanonicalCode::SourceChanged))?;
        if RootIdentity::read(&self.root).map_err(port)? != root
            || RootIdentity::read(self.source.parent().ok_or_else(invalid)?).map_err(port)?
                != self.source_root
        {
            return Err(error(CanonicalCode::SourceChanged));
        }
        platform::validate_private(&self.root).map_err(|_| invalid())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prefix {
    path: PathBuf,
    root: String,
}
fn prefix_identity(install: Option<&Installation>) -> Result<Option<Prefix>, CliError> {
    install
        .map(|install| {
            Ok(Prefix {
                path: fs::canonicalize(&install.prefix).map_err(io)?,
                root: RootIdentity::read(&install.prefix)
                    .map_err(port)?
                    .control_id()
                    .as_str()
                    .to_owned(),
            })
        })
        .transpose()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    operation: String,
    installation: String,
    incarnation: String,
    root: String,
    source_root: String,
    source: PathBuf,
    destination: String,
    created_at_ms: i64,
    prefix: Option<Prefix>,
    inspected: LegacyInspection,
}
impl Intent {
    fn validate(
        &self,
        paths: &Paths,
        root: RootIdentity,
        prefix: &Option<Prefix>,
    ) -> Result<(), CliError> {
        if self.schema != SCHEMA
            || self.root != root.control_id().as_str()
            || self.source_root != paths.source_root.control_id().as_str()
            || self.source != paths.source
            || Some(self.destination.as_str())
                != paths.destination.file_name().and_then(|v| v.to_str())
            || &self.prefix != prefix
            || self.created_at_ms < 0
            || self.inspected.generation() > i64::MAX as u64
            || self.inspected.canonical_entities() > i64::MAX as u64
            || self.inspected.namespace_count() > i64::MAX as u64
            || !crate::package_installation::hex(self.inspected.namespace_digest(), 64)
            || !crate::package_installation::hex(self.inspected.identity_digest(), 64)
        {
            return Err(invalid());
        }
        for value in [&self.operation, &self.installation, &self.incarnation] {
            ControlId::parse(value).map_err(|_| invalid())?;
        }
        Ok(())
    }
}
fn id() -> Result<String, CliError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(io)?;
    Ok(random.iter().map(|value| format!("{value:02x}")).collect())
}
fn now() -> Result<i64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io)?
        .as_millis()
        .try_into()
        .map_err(io)
}
fn read_private_bytes(path: &Path) -> Result<Vec<u8>, CliError> {
    ordinary(path).map_err(|_| invalid())?;
    let mut file = platform::open_file(path).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if metadata.len() == 0 || metadata.len() > MAX_INTENT {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(invalid());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.nNumberOfLinks != 1
        {
            return Err(invalid());
        }
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_INTENT + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_INTENT {
        return Err(invalid());
    }
    if bytes.len() as u64 != metadata.len()
        || platform::identity(&file).map_err(io)?
            != platform::identity(&platform::open_file(path).map_err(io)?).map_err(io)?
    {
        return Err(error(CanonicalCode::SourceChanged));
    }
    Ok(bytes)
}
fn read_private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    serde_json::from_slice(&read_private_bytes(path)?).map_err(|_| invalid())
}
fn read_intent(path: &Path) -> Result<Intent, CliError> {
    read_private(path)
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ControlStart {
    schema: String,
    operation: String,
    installation: String,
    incarnation: String,
    root: String,
    intent_digest: String,
}
impl ControlStart {
    fn from_intent(intent: &Intent) -> Result<Self, CliError> {
        Ok(Self {
            schema: "asg.legacy-migration-control-start/v1".into(),
            operation: intent.operation.clone(),
            installation: intent.installation.clone(),
            incarnation: intent.incarnation.clone(),
            root: intent.root.clone(),
            intent_digest: blake3::hash(&serde_json::to_vec(intent).map_err(io)?)
                .to_hex()
                .to_string(),
        })
    }
}

fn acquire<T>(
    end: Instant,
    mut attempt: impl FnMut() -> Result<T, PortError>,
) -> Result<T, CliError> {
    let end = end.min(Instant::now() + LOCK_BUDGET);
    for _ in 0..MAX_LOCK_ATTEMPTS {
        check(end)?;
        match attempt() {
            Ok(value) => return Ok(value),
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(16).min(end.saturating_duration_since(Instant::now())),
            ),
            Err(value) => return Err(port(value)),
        }
    }
    Err(error(CanonicalCode::WriterBusy))
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    IntentFlushed,
    IntentPublished,
    ControlIntent,
    ControlCreated,
    Activated,
}
#[cfg(test)]
thread_local! {
    static INJECTED: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn fault(point: Fault) -> Result<(), CliError> {
    INJECTED.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            Err(io("injected migration interruption"))
        } else {
            Ok(())
        }
    })
}

fn execute(db: &str, options: Options, end: Instant) -> Result<Value, CliError> {
    check(end)?;
    let paths = Paths::inspect(db, &options.source)?;
    // Verify the entire installed package before receiving-root creation. A
    // supplied prefix is never accepted just because its path/label matches.
    let install = options
        .prefix
        .as_deref()
        .map(inspect_installation)
        .transpose()
        .map_err(|_| invalid())?;
    check(end)?;
    let prefix = prefix_identity(install.as_ref())?;
    let installation_lock = install
        .as_ref()
        .map(|install| {
            crate::update_state::acquire_installation_lock(
                &install.prefix,
                end.min(Instant::now() + LOCK_BUDGET),
            )
        })
        .transpose()?;
    if let (Some(install), Some(binding), Some(lock)) = (&install, &prefix, &installation_lock) {
        ordinary(&install.prefix).map_err(|_| invalid())?;
        let actual = RootIdentity::read(&install.prefix).map_err(port)?;
        if actual != lock.root_identity() || actual.control_id().as_str() != binding.root {
            return Err(error(CanonicalCode::SourceChanged));
        }
    }
    let source_parent = paths.source.parent().ok_or_else(invalid)?;
    let _source_pin = platform::directory(source_parent).map_err(io)?;
    // The legacy lease freezes cooperating ASG writers; it is not a promise
    // that old readers/independent unscoped processes have been drained.
    let source_lock = source_parent.join("writer.lock");
    if exists(&source_lock)? {
        ordinary(&source_lock).map_err(|_| invalid())?;
    }
    let _source_writer = acquire(end, || WriterLease::try_acquire(source_parent))?;
    let prior = exists(&paths.root.join(INTENT))? || exists(&paths.root.join(PENDING))?;
    let inspected = if prior {
        None
    } else {
        Some(inspect_legacy(&paths.source, end).map_err(port)?)
    };
    check(end)?;
    platform::create_private_directory(&paths.root).map_err(io)?;
    let _root_pin = platform::directory(&paths.root).map_err(io)?;
    let root = RootIdentity::read(&paths.root).map_err(port)?;
    if paths
        .receiving_root
        .is_some_and(|expected| expected != root)
        || root == paths.source_root
    {
        return Err(error(CanonicalCode::SourceChanged));
    }
    let _command = acquire(end, || {
        ExclusiveGuard::try_acquire(
            &paths.root,
            LockKind::MaintenanceJob(JobLockKey::parse("legacy-migration")?),
        )
    })?;
    paths.validate(root)?;
    let intent_path = paths.root.join(INTENT);
    let pending_path = paths.root.join(PENDING);
    if exists(&intent_path)? && exists(&pending_path)? {
        return Err(invalid());
    }
    let intent = if exists(&intent_path)? {
        read_intent(&intent_path)?
    } else if exists(&pending_path)? {
        let intent = read_intent(&pending_path)?;
        intent.validate(&paths, root, &prefix)?;
        check(end)?;
        paths.validate(root)?;
        platform::move_new(&pending_path, &intent_path).map_err(io)?;
        platform::sync_directory(&paths.root).map_err(io)?;
        intent
    } else {
        // A missing command intent never authorizes existing catalog/control
        // adoption, including an empty control.db left by failed creation.
        for path in [
            SqliteControlStore::path(&paths.root),
            paths.root.join(CONTROL_STARTED),
            paths.destination.clone(),
            suffix(&paths.destination, ".asg-managed-create"),
            suffix(&paths.destination, ".asg-legacy-file"),
        ] {
            if exists(&path)? {
                return Err(invalid());
            }
        }
        let intent = Intent {
            schema: SCHEMA.into(),
            operation: id()?,
            installation: id()?,
            incarnation: id()?,
            root: root.control_id().as_str().into(),
            source_root: paths.source_root.control_id().as_str().into(),
            source: paths.source.clone(),
            destination: paths
                .destination
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid)?
                .into(),
            created_at_ms: now()?,
            prefix: prefix.clone(),
            inspected: inspected.ok_or_else(invalid)?,
        };
        intent.validate(&paths, root, &prefix)?;
        let bytes = serde_json::to_vec(&intent).map_err(io)?;
        if bytes.len() as u64 > MAX_INTENT {
            return Err(invalid());
        }
        paths.validate(root)?;
        let mut file = platform::create_file(&pending_path).map_err(io)?;
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        #[cfg(test)]
        fault(Fault::IntentFlushed)?;
        check(end)?;
        paths.validate(root)?;
        platform::move_new(&pending_path, &intent_path).map_err(io)?;
        platform::sync_directory(&paths.root).map_err(io)?;
        intent
    };
    intent.validate(&paths, root, &prefix)?;
    #[cfg(test)]
    fault(Fault::IntentPublished)?;
    check(end)?;
    paths.validate(root)?;
    let installation = ControlId::parse(&intent.installation).map_err(port)?;
    let incarnation = ControlId::parse(&intent.incarnation).map_err(port)?;
    let operation = ControlId::parse(&intent.operation).map_err(port)?;
    let control = {
        let owner = acquire(end, || {
            ExclusiveGuard::try_acquire(&paths.root, LockKind::PolicyOwner)
        })?;
        paths.validate(root)?;
        let started_path = paths.root.join(CONTROL_STARTED);
        let expected_start = ControlStart::from_intent(&intent)?;
        let started = exists(&started_path)?;
        if started && read_private::<ControlStart>(&started_path)? != expected_start {
            return Err(invalid());
        }
        let control = if exists(&SqliteControlStore::path(&paths.root))? {
            // The durable pre-creation record binds this exact policy identity.
            // An unbound existing control is never silently adopted.
            if !started {
                return Err(invalid());
            }
            SqliteControlStore::open_existing_writable(&paths.root, &installation).map_err(port)?
        } else {
            for path in [
                &paths.destination,
                &suffix(&paths.destination, ".asg-managed-create"),
                &suffix(&paths.destination, ".asg-legacy-file"),
            ] {
                if exists(path)? {
                    return Err(invalid());
                }
            }
            if started {
                // Only the exact unpublished intent bound to this start may be
                // rebuilt. A publish marker without the final name means policy
                // may once have been live and can never be reset.
                let pending = SqliteControlStore::read_create_intent(&paths.root).map_err(port)?;
                match pending {
                    Some((stored, DesiredUpdates::Paused)) if stored == installation => {
                        paths.validate(root)?;
                        acquire(end, || {
                            SqliteControlStore::recover_create_with_deadline(
                                &paths.root,
                                &installation,
                                DesiredUpdates::Paused,
                                end,
                            )
                        })?
                    }
                    _ => return Err(invalid()),
                }
            } else {
                // A creation intent without its durable command binding is
                // never adopted by a fresh migration operation.
                if SqliteControlStore::read_create_intent(&paths.root)
                    .map_err(port)?
                    .is_some()
                {
                    return Err(invalid());
                }
                for name in [
                    CONTROL_CREATE_INTENT,
                    CONTROL_CREATE_PENDING,
                    CONTROL_CREATE_PUBLISH,
                    "control.db.creating-wal",
                    "control.db.creating-shm",
                    "control.db.creating-journal",
                ] {
                    if exists(&paths.root.join(name))? {
                        return Err(invalid());
                    }
                }
                let bytes = serde_json::to_vec(&expected_start).map_err(io)?;
                let mut file = platform::create_file(&started_path).map_err(io)?;
                file.write_all(&bytes).map_err(io)?;
                file.sync_all().map_err(io)?;
                drop(file);
                platform::sync_directory(&paths.root).map_err(io)?;
                #[cfg(test)]
                fault(Fault::ControlIntent)?;
                check(end)?;
                paths.validate(root)?;
                SqliteControlStore::create_with_deadline(
                    &paths.root,
                    &installation,
                    DesiredUpdates::Paused,
                    end,
                )
                .map_err(port)?
            }
        };
        acquire(end, || control.finish_create())?;
        let bound = control.bind_control_root(&owner).map_err(port)?;
        if let (Some(install), Some(lock)) = (&install, &installation_lock) {
            control
                .record_verified_installation_prefix(&install.prefix, lock, &bound, end)
                .map_err(port)?;
        }
        control
    }; // PolicyOwner is released before copying or waiting on destination locks.
    #[cfg(test)]
    fault(Fault::ControlCreated)?;
    let receipt = migrate_legacy(
        LegacyMigrationRequest {
            source: &paths.source,
            destination: &paths.destination,
            inspected: &intent.inspected,
            installation: &installation,
            incarnation: &incarnation,
            operation: &operation,
            now_ms: now()?,
            deadline: end,
        },
        &control,
    )
    .map_err(port)?;
    #[cfg(test)]
    fault(Fault::Activated)?;
    check(end)?;
    paths.validate(root)?;
    let status = control.status().map_err(port)?;
    if receipt.operation != operation
        || receipt.installation != installation
        || receipt.incarnation != incarnation
    {
        return Err(invalid());
    }
    Ok(json!({
        "phase": "managed_activated", "status": "attention", "recovered": prior,
        "legacy_schema": intent.inspected.schema_version(), "catalog_schema": agent_session_grep_adapters_sqlite::SCHEMA_VERSION,
        "canonical_entities": receipt.canonical_entities, "namespace_count": intent.inspected.namespace_count(),
        "generation": receipt.generation, "classification": "scope_unverified",
        "selected_scopes": status.policy.selections.iter().filter(|selection| selection.enabled).count(),
        "desired_updates": match status.desired_updates { DesiredUpdates::Running => "running", DesiredUpdates::Paused => "paused", DesiredUpdates::Stopped => "stopped" },
        "installation_bound": install.is_some(), "recovery": "forward_only",
        "setup_required": true, "host_integration": "not_attempted", "freshness": "unknown",
    }))
}

pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    let options = parse(rest)?;
    if request_id.is_some_and(|value| !protocol::valid_request_id(value)) {
        return Err(CliError::usage("invalid request id"));
    }
    let started = Instant::now();
    let data = execute(db, options, started + TOTAL_BUDGET)?;
    let outcome = Outcome::Partial;
    emit_result(
        "migrate",
        mode,
        outcome,
        data,
        started.elapsed().as_millis() as u64,
        &protocol::Page::default(),
        &["merged legacy facts remain hidden until selected sources are reimported".into()],
        request_id,
        RetrievalMode::Lexical,
    );
    Ok(outcome)
}

/// Strict decoder for the existing SQLite migration v1 side-record. It is not a
/// generic JSON escape: future schema/field changes stay unclassified until the
/// migration owner and this read-only inventory boundary are updated together.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationMarkerV1 {
    schema: String,
    operation: String,
    installation: String,
    incarnation: String,
    root_identity: String,
    destination: String,
    policy_epoch: i64,
    inspected: LegacyInspection,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationFileV1 {
    schema: String,
    operation: String,
    identity: String,
}

fn classified_migration_record<T: serde::de::DeserializeOwned>(
    path: &Path,
    relative: &str,
    deadline: Instant,
) -> Result<(T, ClassifiedPrivateArtifact), CliError> {
    check(deadline)?;
    let bytes = read_private_bytes(path)?;
    check(deadline)?;
    let value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let proof = ClassifiedPrivateArtifact::new(
        PrivateArtifactClass::LegacyMigrationIntent,
        relative,
        bytes.len() as u64,
        blake3::hash(&bytes).to_hex().as_str(),
    )
    .map_err(port)?;
    Ok((value, proof))
}

/// Existing v1 file binding uses this domain, not a content digest. Preserve its
/// native component encoding exactly; no file replacement is authorized here.
fn migration_file_identity(path: &Path) -> Result<String, CliError> {
    ordinary(path).map_err(|_| invalid())?;
    let file = platform::open_file(path).map_err(io)?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"asg-legacy-file-identity-v1\0");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(io)?;
        if metadata.nlink() != 1 {
            return Err(invalid());
        }
        digest.update(&metadata.dev().to_le_bytes());
        digest.update(&metadata.ino().to_le_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.nNumberOfLinks != 1
        {
            return Err(invalid());
        }
        digest.update(&info.dwVolumeSerialNumber.to_le_bytes());
        digest.update(&info.nFileIndexHigh.to_le_bytes());
        digest.update(&info.nFileIndexLow.to_le_bytes());
    }
    if platform::identity(&file).map_err(io)?
        != platform::identity(&platform::open_file(path).map_err(io)?).map_err(io)?
    {
        return Err(error(CanonicalCode::SourceChanged));
    }
    Ok(digest.finalize().to_hex().to_string())
}

/// Read-only integration inventory. Lists ONLY the four exact owned migration
/// intent/binding files, after strict schema, root/install/incarnation, original
/// legacy logical snapshot/file identity and receiving inode checks. It never
/// redoes migration, creates control/locks, releases a fence or adopts a file.
/// Failure leaves migration unclassified. Returned evidence does not classify,
/// purge or authorize use of the original external legacy catalog. Original
/// DB/WAL content hashes were not journaled, so no raw-byte immutability claim
/// is inferred from the snapshot equality verified here.
pub(crate) fn inspect_private_artifacts(
    catalog: &Path,
    control: &SqliteControlStore,
    expected_root: RootIdentity,
    expected_epoch: PolicyEpoch,
    deadline: Instant,
) -> Result<Vec<ClassifiedPrivateArtifact>, CliError> {
    check(deadline)?;
    control
        .with_runtime_deadline(deadline, || {
            Ok(inspect_private_artifacts_scoped(
                catalog,
                control,
                expected_root,
                expected_epoch,
                deadline,
            ))
        })
        .map_err(port)?
}

fn inspect_private_artifacts_scoped(
    catalog: &Path,
    control: &SqliteControlStore,
    expected_root: RootIdentity,
    expected_epoch: PolicyEpoch,
    deadline: Instant,
) -> Result<Vec<ClassifiedPrivateArtifact>, CliError> {
    let catalog = catalog_input(catalog)?;
    let root = catalog.parent().ok_or_else(invalid)?;
    ordinary(root).map_err(|_| invalid())?;
    platform::validate_private(root).map_err(|_| invalid())?;
    if RootIdentity::read(root).map_err(port)? != expected_root {
        return Err(error(CanonicalCode::SourceChanged));
    }
    // Reuse the adapter's same-root binding check; an installation ID alone
    // cannot prove that the caller supplied the control paired with this root.
    PrivateArtifactInventory::bind(control, expected_root, expected_epoch, vec![]).map_err(port)?;
    let status = control.status().map_err(port)?;
    if status.policy.policy_epoch != expected_epoch {
        return Err(error(CanonicalCode::SourceChanged));
    }
    // No stale retained connection can authorize missing replacement policy.
    let fresh =
        SqliteControlStore::open_read_only(root, &status.policy.installation_id).map_err(port)?;
    let intent_path = root.join(INTENT);
    if !exists(&intent_path)? {
        if exists(&root.join(PENDING))?
            || exists(&root.join(CONTROL_STARTED))?
            || exists(&suffix(&catalog, ".asg-legacy-file"))?
        {
            return Err(invalid());
        }
        return Ok(vec![]);
    }
    if exists(&root.join(PENDING))? {
        return Err(invalid());
    }
    let (intent, command_proof): (Intent, _) =
        classified_migration_record(&intent_path, INTENT, deadline)?;
    let paths = Paths::inspect(catalog.to_str().ok_or_else(invalid)?, &intent.source)?;
    let prefix = intent.prefix.clone();
    intent.validate(&paths, expected_root, &prefix)?;
    paths.validate(expected_root)?;
    if intent.installation != status.policy.installation_id.as_str() {
        return Err(invalid());
    }
    if let Some(prefix) = &prefix {
        ordinary(&prefix.path).map_err(|_| invalid())?;
        if !prefix.path.is_absolute()
            || RootIdentity::read(&prefix.path)
                .map_err(port)?
                .control_id()
                .as_str()
                != prefix.root
        {
            return Err(error(CanonicalCode::SourceChanged));
        }
    }
    let (start, control_proof): (ControlStart, _) =
        classified_migration_record(&root.join(CONTROL_STARTED), CONTROL_STARTED, deadline)?;
    if start != ControlStart::from_intent(&intent)? {
        return Err(invalid());
    }
    let marker_name = format!("{}.asg-managed-create", intent.destination);
    let (marker, marker_proof): (MigrationMarkerV1, _) = classified_migration_record(
        &suffix(&catalog, ".asg-managed-create"),
        &marker_name,
        deadline,
    )?;
    if marker.schema != "asg.legacy-migration/v1"
        || marker.operation != intent.operation
        || marker.installation != intent.installation
        || marker.incarnation != intent.incarnation
        || marker.root_identity != intent.root
        || marker.destination != intent.destination
        || marker.policy_epoch < 0
        || marker.policy_epoch > expected_epoch.get()
        || marker.inspected != intent.inspected
    {
        return Err(invalid());
    }
    let file_name = format!("{}.asg-legacy-file", intent.destination);
    let (binding, file_proof): (MigrationFileV1, _) =
        classified_migration_record(&suffix(&catalog, ".asg-legacy-file"), &file_name, deadline)?;
    if binding.schema != "asg.legacy-migration/v1"
        || binding.operation != intent.operation
        || !crate::package_installation::hex(&binding.identity, 64)
        || binding.identity != migration_file_identity(&catalog)?
    {
        return Err(invalid());
    }
    check(deadline)?;
    let store = ManagedStore::open(&catalog, &fresh).map_err(port)?;
    if store.incarnation().as_str() != intent.incarnation {
        return Err(invalid());
    }
    check(deadline)?;
    let generation = store.inspected_generation().map_err(port)?;
    if generation < intent.inspected.generation() {
        return Err(invalid());
    }
    drop(store);
    // Uses a bounded read-only SQLite transaction; only SQLite SHM reader marks
    // may change, no source writer lease/diagnostic record is created here.
    if inspect_legacy(&paths.source, deadline).map_err(port)? != intent.inspected {
        return Err(error(CanonicalCode::SourceChanged));
    }
    check(deadline)?;
    paths.validate(expected_root)?;
    let current = fresh.status().map_err(port)?;
    if current.policy.installation_id != status.policy.installation_id
        || current.policy.policy_epoch != expected_epoch
        || migration_file_identity(&catalog)? != binding.identity
    {
        return Err(error(CanonicalCode::SourceChanged));
    }
    Ok(vec![command_proof, control_proof, marker_proof, file_proof])
}
#[cfg(test)]
#[path = "migrate_command_tests.rs"]
mod tests;
