//! Explicit program update composition. Ordinary history reads and background
//! indexing never enter this command or invoke a transport helper.
use crate::{
    CliError, emit_result,
    package_installation::{self, Installation},
    protocol::{self, CanonicalCode, Outcome, OutputMode, ProtocolError},
    update_check::{self, Channel, HelperTransport, InstalledIdentity, UpdateCheckErrorCode},
    update_state::{self, Phase},
};
use agent_session_grep_ports::RetrievalMode;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) const HELP: &str = "update — explicitly check, apply or recover the installed program\n\
USAGE: asg update check [--channel beta|stable] [--install-prefix <prefix>]\n\
       asg [--db <catalog>] update apply --from <archive> [--manifest <file>] [--checksums <file>] [--install-prefix <prefix>]\n\
       asg [--db <catalog>] update recover|status [--install-prefix <prefix>]\n\
Check downloads bounded public metadata only. Apply from a verified bundle is offline.\n\
Background history updating does not upgrade the program. Recovery keeps current pause and scope policy.\n\
One archive, its sibling .manifest.json and SHA256SUMS are required for offline apply.";
#[derive(Debug)]
struct Options {
    action: Action,
    prefix: Option<PathBuf>,
    channel: Option<Channel>,
}
#[derive(Debug)]
enum Action {
    Check,
    Apply {
        archive: PathBuf,
        manifest: PathBuf,
        sums: PathBuf,
    },
    Recover,
    Status,
}
fn parse(rest: &[String]) -> Result<Options, CliError> {
    if rest.first().map(String::as_str) != Some("update") {
        return Err(CliError::usage(HELP));
    }
    let word = rest.get(1).ok_or_else(|| CliError::usage(HELP))?.as_str();
    let mut prefix = None;
    let mut channel = None;
    let mut archive = None;
    let mut manifest = None;
    let mut sums = None;
    let mut i = 2;
    while i < rest.len() {
        let value = rest
            .get(i + 1)
            .filter(|s| !s.is_empty() && !s.starts_with('-'))
            .ok_or_else(|| CliError::usage(HELP))?;
        match rest[i].as_str() {
            "--install-prefix" if prefix.is_none() => prefix = Some(PathBuf::from(value)),
            "--channel" if word == "check" && channel.is_none() => {
                channel = Some(Channel::parse(value).ok_or_else(|| CliError::usage(HELP))?)
            }
            "--from" if word == "apply" && archive.is_none() => {
                archive = Some(PathBuf::from(value))
            }
            "--manifest" if word == "apply" && manifest.is_none() => {
                manifest = Some(PathBuf::from(value))
            }
            "--checksums" if word == "apply" && sums.is_none() => sums = Some(PathBuf::from(value)),
            _ => return Err(CliError::usage(HELP)),
        }
        i += 2;
    }
    let action = match word {
        "check" => Action::Check,
        "recover" => Action::Recover,
        "status" => Action::Status,
        "apply" => {
            let archive =
                archive.ok_or_else(|| CliError::usage("update apply requires --from archive"))?;
            let name = archive
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| CliError::usage("invalid archive name"))?;
            let stem = name
                .strip_suffix(".tar.gz")
                .or_else(|| name.strip_suffix(".zip"))
                .ok_or_else(|| CliError::usage("update bundle must be .zip or .tar.gz"))?;
            let parent = archive.parent().unwrap_or_else(|| Path::new("."));
            let manifest = manifest.unwrap_or_else(|| parent.join(format!("{stem}.manifest.json")));
            let sums = sums.unwrap_or_else(|| parent.join("SHA256SUMS"));
            Action::Apply {
                archive,
                manifest,
                sums,
            }
        }
        _ => return Err(CliError::usage(HELP)),
    };
    Ok(Options {
        action,
        prefix,
        channel,
    })
}
fn check_error(e: update_check::UpdateCheckError) -> CliError {
    let code = match e.code {
        UpdateCheckErrorCode::InvalidInstalledIdentity => CanonicalCode::InvalidRequest,
        UpdateCheckErrorCode::Capability
        | UpdateCheckErrorCode::UnsupportedTarget
        | UpdateCheckErrorCode::HelperMissing => CanonicalCode::CapabilityNotSupported,
        UpdateCheckErrorCode::Network
        | UpdateCheckErrorCode::HttpStatus
        | UpdateCheckErrorCode::Io
        | UpdateCheckErrorCode::HelperFailed => CanonicalCode::SourceIo,
        UpdateCheckErrorCode::Timeout => CanonicalCode::SourceIo,
        UpdateCheckErrorCode::Internal => CanonicalCode::Internal,
        _ => CanonicalCode::SchemaIncompatible,
    };
    let detail = serde_json::to_value(e.code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "update_check_failed".into());
    ProtocolError::new(code,format!("update check failed: {detail}; verify the installed helper, network and release metadata")).into()
}
fn check(
    installation: &Installation,
    channel: Option<Channel>,
    end: Instant,
) -> Result<Value, CliError> {
    let identity = InstalledIdentity::new(
        &installation.pointer.version,
        &installation.release.target,
        channel,
        None,
    )
    .map_err(check_error)?;
    let helper = installation.update_check_helper()?;
    if !package_installation::hex(&helper.sha256, 64) {
        return Err(package_installation::invalid_install("helper digest"));
    }
    #[cfg(windows)]
    let program = package_installation::system_powershell()?;
    #[cfg(unix)]
    let program = PathBuf::from("/bin/sh");
    let mut transport = HelperTransport::from_installed_script(program, &helper.path);
    let report =
        update_check::check_with_deadline(&mut transport, &identity, end).map_err(check_error)?;
    serde_json::to_value(report).map_err(|_| {
        ProtocolError::new(
            CanonicalCode::Internal,
            "update report serialization failed",
        )
        .into()
    })
}
fn state_report(state: &update_state::State) -> Value {
    json!({"schema":update_state::SCHEMA,"update_id":state.update_id,"phase":state.phase,"sequence":state.seq,
        "from_version":state.old.version,"to_version":state.new.version,"target":state.new.target,
        "pointer_generation":state.new_pointer_generation,"cleanup_pending":state.cleanup_pending,
        "recovery_required":!state.phase.terminal(),"error_code":state.error_code,"freshness":"unknown"})
}
pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
    offline: bool,
) -> Result<Outcome, CliError> {
    let started = Instant::now();
    let options = parse(rest)?;
    let operation = match &options.action {
        Action::Check => "update.check",
        Action::Apply { .. } => "update.apply",
        Action::Recover => "update.recover",
        Action::Status => "update.status",
    };
    let end = started
        + match options.action {
            Action::Check => update_check::CHECK_DEADLINE,
            _ => Duration::from_secs(120),
        };
    let (outcome, data) = match options.action {
        Action::Check => {
            if offline {
                return Err(problem(
                    CanonicalCode::CapabilityNotSupported,
                    "offline mode does not check network release inventory; apply --from is available",
                ));
            }
            let installed = package_installation::installation(options.prefix.as_deref())?;
            (Outcome::Success, check(&installed, options.channel, end)?)
        }
        Action::Status => {
            let prefix = resolve_prefix(options.prefix.as_deref())?;
            let lock = update_state::acquire_installation_lock(&prefix, end)?;
            let journal = update_state::Journal::open(&prefix, &lock, end)?;
            let outcome = if journal.state.phase.terminal() {
                Outcome::Success
            } else {
                Outcome::Partial
            };
            (outcome, state_report(&journal.state))
        }
        Action::Apply {
            archive,
            manifest,
            sums,
        } => apply(
            Path::new(db),
            options.prefix.as_deref(),
            &archive,
            &manifest,
            &sums,
            end,
        )?,
        Action::Recover => recover(Path::new(db), options.prefix.as_deref(), end)?,
    };
    emit_result(
        operation,
        mode,
        outcome,
        data,
        started.elapsed().as_millis() as u64,
        &protocol::Page::default(),
        &[],
        request_id,
        RetrievalMode::Lexical,
    );
    Ok(outcome)
}
fn resolve_prefix(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(prefix) = explicit {
        return package_installation::absolute(prefix);
    }
    let executable = std::env::current_exe().map_err(package_installation::invalid_install)?;
    executable
        .parent()
        .and_then(Path::parent)
        .filter(|p| p.file_name().is_some_and(|n| n == "versions"))
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| package_installation::invalid_install("managed program location"))
}
// apply/recover implementations follow the maintenance capability seam. Neither
// normal ManagedStore nor a shared catalog connection is held during drain.
use crate::{
    app_clock_ms,
    native_autostart::platform,
    update_bundle::VerifiedBundle,
    update_state::{
        BackupReference, Checkpoint, Journal, MetadataFile, State, UpdateStart, VersionIdentity,
    },
};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    control::{BackupPurpose, InstallationLockAuthority},
    managed_locks::{ExclusiveGuard, LockKind},
    managed_maintenance::{BackupOutcome, MaintenanceCatalog, RestoreOutcome},
};
use agent_session_grep_ports::{
    PortError,
    control::{
        ControlId, ControlStore, DesiredUpdates, MaintenanceFence, MaintenancePhase,
        MaintenanceState,
    },
};

fn problem(code: CanonicalCode, message: &str) -> CliError {
    ProtocolError::new(code, message).into()
}
fn port(error: PortError) -> CliError {
    let code = match error {
        PortError::InvalidRequest(_) => CanonicalCode::InvalidRequest,
        PortError::NotFound(_) => CanonicalCode::NotFound,
        PortError::WriterBusy(_) => CanonicalCode::WriterBusy,
        PortError::DeadlineExceeded(_) => CanonicalCode::DeadlineExceeded,
        PortError::SchemaIncompatible(_) => CanonicalCode::SchemaIncompatible,
        PortError::GenerationMismatch(_) => CanonicalCode::GenerationMismatch,
        PortError::SourceIo(_) => CanonicalCode::SourceIo,
        PortError::SnapshotChanged(_) => CanonicalCode::SourceChanged,
        PortError::Backend(_) => CanonicalCode::CatalogError,
    };
    problem(
        code,
        "update maintenance failed; preserve current policy and inspect recovery status",
    )
}
fn fresh(prefix: &str) -> Result<ControlId, CliError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(package_installation::invalid_install)?;
    ControlId::parse(&format!(
        "{prefix}_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
    .map_err(port)
}
/// A recorded old or staged-new immutable application may run recovery after
/// pointer effects. An arbitrary external executable gains no update authority.
fn verify_update_executor(
    prefix: &Path,
    candidates: &[&VersionIdentity],
    end: Instant,
) -> Result<(), CliError> {
    require_time(end)?;
    use sha2::Digest;
    let running = std::env::current_exe().map_err(package_installation::invalid_install)?;
    let canonical_running = running
        .canonicalize()
        .map_err(package_installation::invalid_install)?;
    for candidate in candidates {
        let expected = prefix
            .join(&candidate.relative_dir)
            .join(agent_session_grep_launcher::metadata::APP_NAME);
        if let Ok(canonical) = expected.canonicalize()
            && canonical == canonical_running
        {
            let mut file = package_installation::pinned(&expected)?;
            let mut hash = sha2::Sha256::new();
            use std::io::Read;
            let mut chunk = [0u8; 65536];
            loop {
                require_time(end)?;
                let count = file
                    .read(&mut chunk)
                    .map_err(package_installation::invalid_install)?;
                require_time(end)?;
                if count == 0 {
                    break;
                }
                hash.update(&chunk[..count]);
            }
            if format!("{:x}", hash.finalize()) == candidate.app_sha256 {
                require_time(end)?;
                return Ok(());
            }
        }
    }
    Err(package_installation::invalid_install(
        "unrecorded update executable",
    ))
}

fn require_time(end: Instant) -> Result<(), CliError> {
    if Instant::now() >= end {
        Err(problem(
            CanonicalCode::WriterBusy,
            "update deadline reached; run update recover",
        ))
    } else {
        Ok(())
    }
}
/// Every control observation/mutation in one apply/recover reuses the original
/// request end. Nested maintenance/read scopes may shorten it, never extend it.
fn with_update_deadline<T>(
    control: &SqliteControlStore,
    end: Instant,
    operation: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    control
        .with_runtime_deadline(end, || Ok(operation()))
        .map_err(port)?
}
fn control_lock(root: &Path, end: Instant) -> Result<ExclusiveGuard, CliError> {
    loop {
        require_time(end)?;
        match ExclusiveGuard::try_acquire(root, LockKind::PolicyOwner) {
            Ok(lock) => return Ok(lock),
            Err(PortError::WriterBusy(_)) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(port(e)),
        }
    }
}
fn set_fence(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    root: &Path,
    phase: MaintenancePhase,
    recovering: bool,
    end: Instant,
) -> Result<(), CliError> {
    loop {
        require_time(end)?;
        let lock = control_lock(root, end)?;
        let bound = control.bind_control_root(&lock).map_err(port)?;
        let status = control.status().map_err(port)?;
        let fence = MaintenanceFence {
            state: if recovering {
                MaintenanceState::Recovering
            } else {
                MaintenanceState::Updating
            },
            owner: Some(owner.clone()),
            phase: Some(phase),
        };
        match control.begin_maintenance(
            status.policy.control_seq,
            owner,
            &bound,
            installation,
            fence,
        ) {
            Ok(_) => return Ok(()),
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {}
            Err(e) => return Err(port(e)),
        }
        drop(lock);
    }
}
fn clear_fence(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    root: &Path,
    end: Instant,
) -> Result<(), CliError> {
    loop {
        require_time(end)?;
        let lock = control_lock(root, end)?;
        let bound = control.bind_control_root(&lock).map_err(port)?;
        let status = control.status().map_err(port)?;
        if status.policy.maintenance.state == MaintenanceState::Idle {
            return Ok(());
        }
        match control.clear_maintenance(status.policy.control_seq, owner, &bound, installation) {
            Ok(_) => return Ok(()),
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {}
            Err(e) => return Err(port(e)),
        }
        drop(lock);
    }
}
fn installed_identity(installed: &Installation) -> VersionIdentity {
    VersionIdentity {
        version: installed.pointer.version.clone(),
        target: installed.release.target.clone(),
        source_commit: installed.release.source_commit.clone(),
        relative_dir: installed.pointer.dir.clone(),
        app_sha256: installed.pointer.app_sha256.clone(),
        catalog_schema: installed.release.catalog_schema.get(),
        control_schema: installed.release.control_schema.get(),
        launcher_protocol: installed.pointer.launcher_protocol,
    }
}
fn bundle_identity(bundle: &VerifiedBundle) -> VersionIdentity {
    VersionIdentity {
        version: bundle.version().into(),
        target: bundle.target().into(),
        source_commit: bundle.source_commit().into(),
        relative_dir: bundle.relative_dir().into(),
        app_sha256: bundle.app_sha256().into(),
        catalog_schema: bundle.catalog_schema(),
        control_schema: bundle.control_schema(),
        launcher_protocol: bundle.launcher_protocol(),
    }
}
fn backup_reference(
    metadata: agent_session_grep_adapters_sqlite::managed_maintenance::BackupMetadata,
) -> BackupReference {
    BackupReference {
        id: metadata.backup_id.as_str().into(),
        relative_locator: metadata.relative_locator,
        digest: metadata.digest,
        size_bytes: metadata.size_bytes,
        catalog_incarnation: metadata.catalog_incarnation.as_str().into(),
        catalog_generation: metadata.catalog_generation,
        schema: metadata.schema_version,
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeInventory {
    schema: String,
    location: crate::native_autostart::NativeLocation,
    journal_root: PathBuf,
    receipt: crate::native_autostart::AutostartReceipt,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeBinding {
    schema: String,
    update_id: String,
    installation_id: String,
    location: crate::native_autostart::NativeLocation,
    journal_root: PathBuf,
    original_receipt: crate::native_autostart::AutostartReceipt,
    old_supervisor_sha256: String,
    new_supervisor_sha256: String,
}
const NATIVE_BINDING_FILE: &str = "native-binding.json";
const NATIVE_RECORD_LIMIT: u64 = 65536;
fn native_journal_root(
    location: &crate::native_autostart::NativeLocation,
    root: &Path,
    installation: &str,
) -> PathBuf {
    use crate::native_autostart::NativeLocation;
    match location {
        NativeLocation::WindowsRun { .. } => root.join("native-autostart"),
        NativeLocation::LaunchAgent { directory, .. }
        | NativeLocation::SystemdUser { directory } => {
            directory.join(format!(".asg-{installation}"))
        }
    }
}
fn open_native_store(
    binding: &NativeBinding,
    journal: &Journal<'_>,
    root: &Path,
) -> Result<crate::native_autostart::NativeAutostartStore, CliError> {
    if binding.schema != "asg.update-native-binding/v1"
        || binding.update_id != journal.state.update_id
        || binding.installation_id != journal.state.checkpoint.installation_id
        || binding.original_receipt.installation_id != binding.installation_id
        || !binding.original_receipt.owned
        || binding.original_receipt.state != crate::native_autostart::ConfigurationState::Present
        || !package_installation::hex(&binding.old_supervisor_sha256, 64)
        || !package_installation::hex(&binding.new_supervisor_sha256, 64)
        || binding.journal_root
            != native_journal_root(&binding.location, root, &binding.installation_id)
    {
        return Err(package_installation::invalid_install(
            "native update binding",
        ));
    }
    crate::native_autostart::NativeAutostartStore::open(
        binding.location.clone(),
        &binding.journal_root,
        &binding.installation_id,
    )
    .map_err(package_installation::invalid_install)
}
fn native_registration(
    journal: &Journal<'_>,
    identity: &VersionIdentity,
    digest: &str,
) -> crate::native_autostart::SupervisorRegistration {
    crate::native_autostart::SupervisorRegistration {
        supervisor: journal
            .prefix()
            .join(&identity.relative_dir)
            .join(if cfg!(windows) {
                "asg-supervisor.exe"
            } else {
                "asg-supervisor"
            }),
        supervisor_sha256: digest.into(),
        catalog: journal.state.catalog.clone(),
    }
}
fn read_native_binding(journal: &Journal<'_>) -> Result<Option<NativeBinding>, CliError> {
    use sha2::Digest;
    let bytes = update_state::read(
        &journal.run_root().join(NATIVE_BINDING_FILE),
        NATIVE_RECORD_LIMIT,
    )?;
    match (&journal.state.native_binding_sha256, bytes) {
        (None, None) => Ok(None),
        (Some(expected), Some(bytes))
            if format!("{:x}", sha2::Sha256::digest(&bytes)) == *expected =>
        {
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(package_installation::invalid_install)
        }
        _ => Err(package_installation::invalid_install(
            "unconfirmed native binding",
        )),
    }
}
fn replace_native_registration(
    control: &SqliteControlStore,
    root: &Path,
    journal: &Journal<'_>,
    end: Instant,
) -> Result<(), CliError> {
    let Some(binding) = read_native_binding(journal)? else {
        return Ok(());
    };
    let store = open_native_store(&binding, journal, root)?;
    let current = control.status().map_err(port)?;
    let prior = match store.latest_receipt() {
        Ok(Some(prior)) => Some(prior),
        Ok(None) => {
            return Err(package_installation::invalid_install(
                "native receipt missing",
            ));
        }
        Err(error) if error.code == crate::native_autostart::ErrorCode::RecoveryRequired => None,
        Err(error) => return Err(package_installation::invalid_install(error)),
    };
    if prior
        .as_ref()
        .is_some_and(|p| p.state == crate::native_autostart::ConfigurationState::Absent)
    {
        if current.autostart_enabled {
            return Err(package_installation::invalid_install(
                "enabled registration disappeared",
            ));
        }
        return Ok(());
    }
    let old = native_registration(journal, &journal.state.old, &binding.old_supervisor_sha256);
    let new = native_registration(journal, &journal.state.new, &binding.new_supervisor_sha256);
    let change = store
        .replace_owned(
            &journal.state.update_id,
            &old,
            &new,
            &binding.original_receipt,
            end,
        )
        .map_err(package_installation::invalid_install)?;
    // Updating the registered command may reload the native manager; no new
    // worker is allowed before maintenance has been cleared.
    crate::native_manager::reload_owned(&store, &change, &new, end)
        .map_err(package_installation::invalid_install)?;
    Ok(())
}
fn restore_native_registration(
    control: &SqliteControlStore,
    root: &Path,
    journal: &Journal<'_>,
    end: Instant,
) -> Result<(), CliError> {
    let Some(binding) = read_native_binding(journal)? else {
        return Ok(());
    };
    let store = open_native_store(&binding, journal, root)?;
    let current = control.status().map_err(port)?;
    let prior = match store.latest_receipt() {
        Ok(Some(prior)) => Some(prior),
        Ok(None) => {
            return Err(package_installation::invalid_install(
                "native receipt missing",
            ));
        }
        Err(error) if error.code == crate::native_autostart::ErrorCode::RecoveryRequired => None,
        Err(error) => return Err(package_installation::invalid_install(error)),
    };
    if prior
        .as_ref()
        .is_some_and(|p| p.state == crate::native_autostart::ConfigurationState::Absent)
    {
        if current.autostart_enabled {
            return Err(package_installation::invalid_install(
                "enabled registration disappeared",
            ));
        }
        return Ok(());
    }
    let original = native_registration(journal, &journal.state.old, &binding.old_supervisor_sha256);
    if prior.as_ref() == Some(&binding.original_receipt) {
        drop(
            store
                .manager_registration(&binding.original_receipt, &original)
                .map_err(package_installation::invalid_install)?,
        );
        return Ok(());
    }
    let replacement = match store.operation_receipt(&journal.state.update_id) {
        Ok(receipt) => receipt,
        Err(error)
            if error.code == crate::native_autostart::ErrorCode::RecoveryRequired
                && prior.is_none() =>
        {
            // The apply operation may still need its acknowledgement. If its
            // verified result already exists, restore_owned instead reconciles
            // this update's known pending rollback. Never recover another job.
            let target =
                native_registration(journal, &journal.state.new, &binding.new_supervisor_sha256);
            store
                .replace_owned(
                    &journal.state.update_id,
                    &original,
                    &target,
                    &binding.original_receipt,
                    end,
                )
                .map_err(package_installation::invalid_install)?
                .receipt
        }
        Err(error) => return Err(package_installation::invalid_install(error)),
    };
    let restored = store
        .restore_owned(
            &format!("{}-rollback", journal.state.update_id),
            &original,
            &replacement,
            end,
        )
        .map_err(package_installation::invalid_install)?;
    crate::native_manager::reload_owned(&store, &restored, &original, end)
        .map_err(package_installation::invalid_install)?;
    Ok(())
}
fn prepare_native_binding(
    control: &SqliteControlStore,
    root: &Path,
    installed: &Installation,
    new_supervisor_sha256: &str,
    journal: &mut Journal<'_>,
    end: Instant,
) -> Result<(), CliError> {
    use crate::native_autostart::{ConfigurationState, NativeAutostartStore};
    use sha2::Digest;
    require_time(end)?;
    let mut inventories = Vec::new();
    for (count, entry) in std::fs::read_dir(root)
        .map_err(package_installation::invalid_install)?
        .enumerate()
    {
        require_time(end)?;
        if count >= 1024 {
            return Err(package_installation::invalid_install("inventory bound"));
        }
        let entry = entry.map_err(package_installation::invalid_install)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("setup-autostart-") || !name.ends_with(".json") {
            continue;
        }
        if inventories.len() >= 256 {
            return Err(package_installation::invalid_install(
                "native inventory bound",
            ));
        }
        let bytes = update_state::read(&entry.path(), NATIVE_RECORD_LIMIT)?
            .ok_or_else(|| package_installation::invalid_install("native inventory missing"))?;
        let inventory: NativeInventory =
            serde_json::from_slice(&bytes).map_err(package_installation::invalid_install)?;
        if inventory.schema != "asg.setup-autostart-inventory/v1" {
            return Err(package_installation::invalid_install(
                "native inventory schema",
            ));
        }
        if inventory.receipt.installation_id == journal.state.checkpoint.installation_id {
            inventories.push(inventory);
        }
    }
    let current = control.status().map_err(port)?;
    let Some(first) = inventories.first() else {
        if current.autostart_enabled {
            return Err(package_installation::invalid_install(
                "enabled native inventory missing",
            ));
        }
        return Ok(());
    };
    if inventories
        .iter()
        .any(|i| i.location != first.location || i.journal_root != first.journal_root)
        || first.journal_root
            != native_journal_root(
                &first.location,
                root,
                &journal.state.checkpoint.installation_id,
            )
    {
        return Err(package_installation::invalid_install(
            "ambiguous native inventory",
        ));
    }
    let store = NativeAutostartStore::open(
        first.location.clone(),
        &first.journal_root,
        &journal.state.checkpoint.installation_id,
    )
    .map_err(package_installation::invalid_install)?;
    let prior = store
        .latest_receipt()
        .map_err(package_installation::invalid_install)?
        .ok_or_else(|| package_installation::invalid_install("native receipt missing"))?;
    if prior.state == ConfigurationState::Absent {
        if current.autostart_enabled {
            return Err(package_installation::invalid_install(
                "enabled registration absent",
            ));
        }
        return Ok(());
    }
    if !prior.owned {
        return Err(package_installation::invalid_install(
            "native registration unowned",
        ));
    }
    let (_, old_digest) = installed
        .supervisor
        .as_ref()
        .ok_or_else(|| package_installation::invalid_install("old supervisor missing"))?;
    let binding = NativeBinding {
        schema: "asg.update-native-binding/v1".into(),
        update_id: journal.state.update_id.clone(),
        installation_id: journal.state.checkpoint.installation_id.clone(),
        location: first.location.clone(),
        journal_root: first.journal_root.clone(),
        original_receipt: prior,
        old_supervisor_sha256: old_digest.clone(),
        new_supervisor_sha256: new_supervisor_sha256.into(),
    };
    let original = native_registration(journal, &journal.state.old, old_digest);
    drop(
        store
            .manager_registration(&binding.original_receipt, &original)
            .map_err(package_installation::invalid_install)?,
    );
    let bytes = serde_json::to_vec(&binding).map_err(package_installation::invalid_install)?;
    if bytes.len() as u64 > NATIVE_RECORD_LIMIT {
        return Err(package_installation::invalid_install(
            "native binding bound",
        ));
    }
    update_state::write_new(&journal.run_root().join(NATIVE_BINDING_FILE), &bytes)?;
    platform::sync_directory(&journal.run_root()).map_err(package_installation::invalid_install)?;
    journal.state.native_binding_sha256 = Some(format!("{:x}", sha2::Sha256::digest(&bytes)));
    journal.save(end)
}
/// Initial managed Beta program updates require both immutable applications to
/// use the current catalog and control schemas. Internal migration/exact restore
/// capabilities do not supply a verified new-executor handoff.
fn schema_update_supported(old: &VersionIdentity, new: &VersionIdentity) -> bool {
    let current_catalog = u32::try_from(agent_session_grep_adapters_sqlite::SCHEMA_VERSION).ok();
    let current_control =
        u32::try_from(agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION).ok();
    current_catalog == Some(old.catalog_schema)
        && current_catalog == Some(new.catalog_schema)
        && current_control == Some(old.control_schema)
        && current_control == Some(new.control_schema)
}

fn apply(
    db: &Path,
    prefix: Option<&Path>,
    archive: &Path,
    manifest: &Path,
    sums: &Path,
    end: Instant,
) -> Result<(Outcome, Value), CliError> {
    let prefix = resolve_prefix(prefix)?;
    let lock = update_state::acquire_installation_lock(&prefix, end)?;
    if prefix
        .join("update/state.json")
        .try_exists()
        .map_err(package_installation::invalid_install)?
    {
        let old = Journal::open(&prefix, &lock, end)?;
        if !old.state.phase.terminal() {
            return Ok((Outcome::Partial, state_report(&old.state)));
        }
    }
    let mut installed = package_installation::inspect_installation_for_update(&prefix)?;
    let db = package_installation::absolute(db)?;
    let root = db
        .parent()
        .ok_or_else(|| CliError::usage("catalog has no root"))?;
    // Inspect supported package identities before opening a writable control:
    // refusing a cross-control update must not migrate it as a side effect.
    let bundle = VerifiedBundle::open(archive, manifest, sums, &installed.release.target, end)?;
    let new = bundle_identity(&bundle);
    let old = installed_identity(&installed);
    verify_update_executor(&prefix, &[&old, &new], end)?;
    if !schema_update_supported(&old, &new) {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "program update requires both packages to use current catalog and control schemas; installation retained",
        ));
    }
    let control_read =
        SqliteControlStore::open_current_read_only_with_deadline(root, end).map_err(port)?;
    let installation_id = control_read
        .with_runtime_deadline(end, || control_read.status())
        .map_err(port)?
        .policy
        .installation_id;
    let control =
        SqliteControlStore::open_existing_writable_with_deadline(root, &installation_id, end)
            .map_err(port)?;
    drop(control_read);
    with_update_deadline(&control, end, || {
        let status = control.status().map_err(port)?;
        if status.policy.maintenance.state != MaintenanceState::Idle {
            return Err(problem(
                CanonicalCode::UpdateRecoveryRequired,
                "unmatched maintenance fence; recover the recorded update first",
            ));
        }
        if installed.prefix != prefix
            || !package_installation::hex(&installed.archive_sha256, 64)
            || !package_installation::hex(&installed.manifest_sha256, 64)
            || !package_installation::hex(&installed.package_files_sha256, 64)
        {
            return Err(package_installation::invalid_install(
                "old package identity",
            ));
        }
        let old_version =
            semver::Version::parse(&old.version).map_err(package_installation::invalid_install)?;
        let new_version =
            semver::Version::parse(&new.version).map_err(package_installation::invalid_install)?;
        if new_version.cmp_precedence(&old_version) != std::cmp::Ordering::Greater {
            return Err(CliError::usage(
                "apply requires a newer SemVer candidate; recover handles an interrupted same candidate",
            ));
        }
        let catalog =
            agent_session_grep_adapters_sqlite::managed_maintenance::inspect_catalog_identity(
                &control, &db, end,
            )
            .map_err(port)?;
        if catalog.schema != old.catalog_schema
            || catalog.installation != status.policy.installation_id
            || status.catalog_incarnation.as_ref() != Some(&catalog.incarnation)
        {
            return Err(problem(
                CanonicalCode::SchemaIncompatible,
                "catalog identity does not match the installed update baseline",
            ));
        }
        let generation = catalog.generation;
        let incarnation = catalog.incarnation.as_str().to_owned();
        let checkpoint = Checkpoint {
            installation_id: status.policy.installation_id.as_str().into(),
            policy_epoch: status.policy.policy_epoch.get() as u64,
            control_seq: status.policy.control_seq.get() as u64,
            desired_updates: match status.desired_updates {
                DesiredUpdates::Running => "running",
                DesiredUpdates::Paused => "paused",
                DesiredUpdates::Stopped => "stopped",
            }
            .into(),
            catalog_incarnation: incarnation,
            catalog_generation: generation,
            catalog_schema: old.catalog_schema,
        };
        let owner = fresh("update_owner")?;
        let state = State::new(UpdateStart {
            update_id: fresh("update")?,
            owner: owner.clone(),
            old,
            new,
            archive_sha256: bundle.archive_sha256().into(),
            manifest_sha256: bundle.manifest_sha256().into(),
            old_pointer_generation: installed.pointer.generation.get(),
            stable_launcher_sha256: installed.expected.launcher_sha256.clone(),
            catalog: db.clone(),
            checkpoint,
        })?;
        let installation = control.bind_installation(&prefix, &lock).map_err(port)?;
        // Every preflight above may refuse or race without losing the prior
        // terminal recovery record. Archive and create only after the writable
        // control, policy, catalog identity and installation binding agree.
        let mut journal = Journal::create_after_terminal(&prefix, &lock, state, end)?;
        // The journal is authoritative before maintenance can change any catalog
        // lifetime. Mutable package pins must be released before publication.
        if let Err(error) = prepare_native_binding(
            &control,
            root,
            &installed,
            bundle.supervisor_sha256(),
            &mut journal,
            end,
        ) {
            if journal.poisoned() {
                return Err(error);
            }
            journal.state.error_code = Some("native_binding_failed".into());
            let _ = journal.transition(Phase::Failed, end);
            return Err(error);
        }
        installed.release_update_pins();
        let result = apply_steps(
            &control,
            &installation,
            &owner,
            root,
            CandidateFiles {
                bundle: &bundle,
                manifest,
                sums,
            },
            &mut journal,
            end,
        );
        if let Err(error) = result {
            if journal.poisoned() {
                // Failed durable publication may have succeeded before its ACK.
                // Do not issue more effects from stale in-memory state.
                return Err(error);
            }
            journal.state.error_code = Some("update_failed".into());
            let rollback = if matches!(journal.state.phase, Phase::Verified | Phase::Quiescing) {
                Phase::Failed
            } else {
                Phase::RollbackPending
            };
            // Failure recording and reconciliation use only the original budget;
            // when storage/budget is exhausted, persisted last intent remains.
            if journal.transition(rollback, end).is_ok() && rollback == Phase::Failed {
                clear_fence(&control, &installation, &owner, root, end)?;
            }
            return Err(error);
        }
        drop(installed);
        finish_update(&control, &installation, &owner, root, &mut journal, end)
    })
}
fn quiesced_checkpoint(
    current: &agent_session_grep_ports::control::ControlStatus,
    catalog: &agent_session_grep_adapters_sqlite::managed_maintenance::CatalogIdentity,
    initial: &Checkpoint,
) -> Result<Checkpoint, CliError> {
    if catalog.installation.as_str() != initial.installation_id
        || current.policy.installation_id != catalog.installation
        || catalog.incarnation.as_str() != initial.catalog_incarnation
        || current
            .catalog_incarnation
            .as_ref()
            .is_some_and(|id| id != &catalog.incarnation)
        || catalog.schema != initial.catalog_schema
        || catalog.generation < initial.catalog_generation
        || (current.policy.policy_epoch.get() as u64) < initial.policy_epoch
        || (current.policy.control_seq.get() as u64) < initial.control_seq
    {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "catalog or control identity changed before the maintenance drain; retain the old installation",
        ));
    }
    Ok(Checkpoint {
        installation_id: catalog.installation.as_str().into(),
        policy_epoch: current.policy.policy_epoch.get() as u64,
        control_seq: current.policy.control_seq.get() as u64,
        desired_updates: match current.desired_updates {
            DesiredUpdates::Running => "running",
            DesiredUpdates::Paused => "paused",
            DesiredUpdates::Stopped => "stopped",
        }
        .into(),
        catalog_incarnation: catalog.incarnation.as_str().into(),
        catalog_generation: catalog.generation,
        catalog_schema: catalog.schema,
    })
}
fn drain_background_lifetime(
    root: &Path,
    end: Instant,
) -> Result<(ExclusiveGuard, ExclusiveGuard), CliError> {
    let identity = agent_session_grep_adapters_sqlite::managed_locks::RootIdentity::read(root)
        .map_err(port)?;
    let supervisor = crate::native_manager::wait_supervisor_drained(root, identity, end)
        .map_err(package_installation::invalid_install)?;
    loop {
        require_time(end)?;
        match ExclusiveGuard::try_acquire(root, LockKind::Background) {
            Ok(worker) if worker.root_identity() == identity => return Ok((supervisor, worker)),
            Ok(_) => {
                return Err(package_installation::invalid_install(
                    "background root changed",
                ));
            }
            Err(PortError::WriterBusy(_)) => {}
            Err(error) => return Err(port(error)),
        }
        std::thread::sleep(
            Duration::from_millis(10).min(end.saturating_duration_since(Instant::now())),
        );
    }
}
struct CandidateFiles<'a> {
    bundle: &'a VerifiedBundle,
    manifest: &'a Path,
    sums: &'a Path,
}
fn apply_steps(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    root: &Path,
    candidate: CandidateFiles<'_>,
    journal: &mut Journal<'_>,
    end: Instant,
) -> Result<(), CliError> {
    let CandidateFiles {
        bundle,
        manifest,
        sums,
    } = candidate;
    journal.transition(Phase::Quiescing, end)?;
    set_fence(
        control,
        installation,
        owner,
        root,
        MaintenancePhase::Quiescing,
        false,
        end,
    )?;
    let drain = std::cmp::min(end, Instant::now() + Duration::from_secs(30));
    // Catalog handle drain alone does not prove the old login supervisor has
    // exited. Its lifetime lock and the worker lock must both be released while
    // the durable fence still denies new work; never kill a host by PID.
    let _background_lifetime = drain_background_lifetime(root, drain)?;
    let mut catalog = MaintenanceCatalog::open_authorized(
        control,
        installation,
        owner,
        &journal.state.catalog,
        drain,
    )
    .map_err(port)?;
    if catalog.identity().schema != journal.state.old.catalog_schema {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "catalog schema changed before upgrade",
        ));
    }
    // A worker may commit between the initial identity read and fence/drain.
    // Keep the immutable admission checkpoint, then persist the authoritative
    // post-drain identity before the backup or any package effect.
    let current = control.status().map_err(port)?;
    journal.state.quiesced_checkpoint = Some(quiesced_checkpoint(
        &current,
        catalog.identity(),
        &journal.state.checkpoint,
    )?);
    journal.save(end)?;
    let backup_id =
        ControlId::parse(&format!("backup_{}", journal.state.update_id)).map_err(port)?;
    let backup = catalog
        .create_backup(
            control,
            installation,
            owner,
            &backup_id,
            BackupPurpose::BetaRollback,
            app_clock_ms(),
            end,
        )
        .map_err(port)?;
    let BackupOutcome::Created(backup) = backup else {
        return Err(problem(
            CanonicalCode::UpdateRecoveryRequired,
            "current denied scope prevents a rollback image; finish owned purge before applying the update",
        ));
    };
    journal.state.backup = Some(backup_reference(backup));
    journal.transition(Phase::BackedUp, end)?;
    set_fence(
        control,
        installation,
        owner,
        root,
        MaintenancePhase::BackedUp,
        false,
        end,
    )?;
    let stage = journal.run_root().join("stage");
    platform::create_private_directory(&stage).map_err(package_installation::invalid_install)?;
    bundle.members_to_new_private_stage(&stage, end)?;
    let manifest_bytes = update_state::read(manifest, 512 * 1024)?
        .ok_or_else(|| package_installation::invalid_install("manifest missing"))?;
    use sha2::Digest;
    if format!("{:x}", sha2::Sha256::digest(&manifest_bytes)) != journal.state.manifest_sha256 {
        return Err(package_installation::invalid_install("manifest changed"));
    }
    let sums_bytes = update_state::read(sums, 512 * 1024)?
        .ok_or_else(|| package_installation::invalid_install("checksums missing"))?;
    update_state::write_new(&stage.join("release.manifest.json"), &manifest_bytes)?;
    update_state::write_new(&stage.join("SHA256SUMS"), &sums_bytes)?;
    let files = update_state::read(&stage.join("PACKAGE-MANIFEST.tsv"), 65536)?
        .ok_or_else(|| package_installation::invalid_install("file manifest missing"))?;
    let receipt = json!({"schema":"asg.package-install/v1","product":"agent-session-grep","version":journal.state.new.version,"target":journal.state.new.target,
        "source_commit":journal.state.new.source_commit,"launcher_protocol":1,"manifest_sha256":journal.state.manifest_sha256,"archive_sha256":journal.state.archive_sha256,
        "package_files_sha256":format!("{:x}",sha2::Sha256::digest(&files))});
    update_state::write_new(
        &stage.join("package-install.json"),
        &serde_json::to_vec(&receipt).map_err(package_installation::invalid_install)?,
    )?;
    package_installation::verify_staged_package(&stage)?;
    candidate_info(
        &stage
            .join(&journal.state.new.relative_dir)
            .join(agent_session_grep_launcher::metadata::APP_NAME),
        &journal.state.new,
        end,
    )?;
    let final_dir = journal.prefix().join(&journal.state.new.relative_dir);
    package_installation::ordinary(
        final_dir
            .parent()
            .ok_or_else(|| package_installation::invalid_install("version parent"))?,
    )?;
    journal.save(end)?; // intent includes the exact new immutable directory/hash
    platform::move_new(&stage.join(&journal.state.new.relative_dir), &final_dir)
        .map_err(package_installation::invalid_install)?;
    platform::sync_directory(
        final_dir
            .parent()
            .ok_or_else(|| package_installation::invalid_install("versions"))?,
    )
    .map_err(package_installation::invalid_install)?;
    journal.state.staged = true;
    journal.transition(Phase::Staged, end)?;
    set_fence(
        control,
        installation,
        owner,
        root,
        MaintenancePhase::Staged,
        false,
        end,
    )?;
    // The exact old-schema rollback image is durable before this caller-owned
    // catalog migration. No normal read/open can reach the schema writer.
    if catalog.identity().schema != journal.state.new.catalog_schema {
        catalog
            .migrate_to_current(control, installation, owner, end)
            .map_err(port)?;
    }
    if catalog.identity().schema != journal.state.new.catalog_schema {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "candidate catalog schema is not supported by the verified migration",
        ));
    }
    journal.state.migrated = true;
    journal.transition(Phase::Migrated, end)?;
    set_fence(
        control,
        installation,
        owner,
        root,
        MaintenancePhase::Migrated,
        false,
        end,
    )?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(package_installation::invalid_install)?;
    let pointer = journal
        .state
        .new
        .pointer(journal.state.new_pointer_generation, &now)?;
    let pointer_bytes =
        serde_json::to_vec(&pointer).map_err(package_installation::invalid_install)?;
    let mut receipt = receipt;
    receipt["schema"] = json!("asg.package-install/v2");
    receipt["current_sha256"] = json!(format!("{:x}", sha2::Sha256::digest(&pointer_bytes)));
    receipt["current_generation"] = json!(journal.state.new_pointer_generation);
    receipt["launcher_sha256"] = json!(journal.state.stable_launcher_sha256);
    for role in [
        MetadataFile::InstallerSh,
        MetadataFile::InstallerPowerShell,
        MetadataFile::InstallGuide,
        MetadataFile::Readme,
        MetadataFile::Changelog,
        MetadataFile::LicenseMit,
        MetadataFile::LicenseApache,
        MetadataFile::Notice,
        MetadataFile::Security,
        MetadataFile::DependenciesJson,
        MetadataFile::DependenciesCsv,
    ] {
        let bytes = update_state::read(&stage.join(role.name()), 1024 * 1024)?
            .ok_or_else(|| package_installation::invalid_install("package member missing"))?;
        journal.replace_metadata(role, &bytes, end)?;
    }
    journal.replace_metadata(MetadataFile::PackageManifest, &files, end)?;
    journal.replace_metadata(MetadataFile::ReleaseManifest, &manifest_bytes, end)?;
    journal.replace_metadata(MetadataFile::Checksums, &sums_bytes, end)?;
    journal.replace_metadata(
        MetadataFile::PackageReceipt,
        &serde_json::to_vec(&receipt).map_err(package_installation::invalid_install)?,
        end,
    )?;
    journal.replace_metadata(MetadataFile::Current, &pointer_bytes, end)?;
    replace_native_registration(control, root, journal, end)?;
    journal.transition(Phase::Switched, end)?;
    set_fence(
        control,
        installation,
        owner,
        root,
        MaintenancePhase::Switched,
        false,
        end,
    )?;
    verify_active(
        journal,
        &journal.state.new,
        journal.state.new_pointer_generation,
        end,
    )?;
    // No normal evidence read is opened by this self-check. Existing catalog
    // identity/integrity is verified under the live maintenance handle.
    journal.state.self_checked = true;
    journal.transition(Phase::SelfChecked, end)?;
    set_fence(
        control,
        installation,
        owner,
        root,
        MaintenancePhase::SelfChecked,
        false,
        end,
    )?;
    drop(catalog);
    Ok(())
}
fn candidate_info(app: &Path, expected: &VersionIdentity, end: Instant) -> Result<(), CliError> {
    let output =
        crate::setup_hosts::capture_local(app, &[std::ffi::OsStr::new("__asg-build-info")], end)
            .map_err(|_| {
                problem(
                    CanonicalCode::UpdateRecoveryRequired,
                    "candidate content-free self-check failed; retain maintenance and run recover",
                )
            })?;
    validate_candidate_info(&output, expected)
}
fn validate_candidate_info(
    output: &crate::setup_hosts::LocalCapture,
    expected: &VersionIdentity,
) -> Result<(), CliError> {
    if !output.success {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "candidate self-check process failed; retain the verified installation and inspect recovery",
        ));
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(package_installation::invalid_install)?;
    if !output.stderr.is_empty()
        || value["schema"] != "asg.build-info/v1"
        || value["product"] != "agent-session-grep"
        || value["version"] != expected.version
        || value["target"] != expected.target
        || value["catalog_schema"] != expected.catalog_schema
        || value["control_schema"] != expected.control_schema
        || value["launcher_protocol"] != 1
    {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "candidate build identity or schema self-check did not match the verified package",
        ));
    }
    Ok(())
}
fn verify_active(
    journal: &Journal<'_>,
    expected: &VersionIdentity,
    expected_generation: u64,
    end: Instant,
) -> Result<(), CliError> {
    let installed = package_installation::inspect_installation_for_update(journal.prefix())?;
    let actual = installed_identity(&installed);
    if !active_identity_matches(
        &actual,
        installed.pointer.generation.get(),
        expected,
        expected_generation,
    ) {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "active installation does not match the update identity",
        ));
    }
    candidate_info(
        &journal
            .prefix()
            .join(&expected.relative_dir)
            .join(agent_session_grep_launcher::metadata::APP_NAME),
        expected,
        end,
    )
}
fn active_identity_matches(
    actual: &VersionIdentity,
    actual_generation: u64,
    expected: &VersionIdentity,
    expected_generation: u64,
) -> bool {
    actual == expected && actual_generation == expected_generation
}
fn resume_background(
    control: &SqliteControlStore,
    root: &Path,
    journal: &Journal<'_>,
    expected: &VersionIdentity,
    end: Instant,
) -> Result<bool, CliError> {
    require_time(end)?;
    let current = control.status().map_err(port)?;
    if current.desired_updates != DesiredUpdates::Running {
        return Ok(false);
    }
    if current.policy.maintenance.state != MaintenanceState::Idle {
        return Err(problem(
            CanonicalCode::UpdateRecoveryRequired,
            "maintenance remains active before restart",
        ));
    }
    let installed = package_installation::inspect_installation_for_update(journal.prefix())?;
    if installed_identity(&installed) != *expected {
        return Err(package_installation::invalid_install(
            "restart installation identity",
        ));
    }
    let (path, digest) = installed
        .supervisor
        .as_ref()
        .ok_or_else(|| package_installation::invalid_install("restart supervisor missing"))?;
    let registration = crate::native_autostart::SupervisorRegistration {
        supervisor: path.clone(),
        supervisor_sha256: digest.clone(),
        catalog: journal.state.catalog.clone(),
    };
    let allowed = |needs_autostart: bool| -> Result<bool, crate::native_manager::ManagerError> {
        package_installation::ordinary(root)
            .map_err(|_| crate::native_manager::ErrorCode::Conflict)?;
        let observed = control
            .status()
            .map_err(|_| crate::native_manager::ErrorCode::Conflict)?;
        if observed.policy.installation_id.as_str() != journal.state.checkpoint.installation_id {
            return Err(crate::native_manager::ErrorCode::Conflict.into());
        }
        Ok(observed.desired_updates == DesiredUpdates::Running
            && observed.policy.maintenance.state == MaintenanceState::Idle
            && (!needs_autostart || observed.autostart_enabled))
    };
    if current.autostart_enabled {
        let binding = read_native_binding(journal)?.ok_or_else(|| {
            package_installation::invalid_install("restart native binding missing")
        })?;
        let store = open_native_store(&binding, journal, root)?;
        let receipt = store
            .latest_receipt()
            .map_err(package_installation::invalid_install)?
            .ok_or_else(|| {
                package_installation::invalid_install("restart native receipt missing")
            })?;
        let change = crate::native_autostart::AutostartChange { receipt };
        crate::native_manager::restart_owned_for_update(
            &store,
            &change,
            &registration,
            end,
            &mut || allowed(true),
        )
        .map_err(package_installation::invalid_install)?;
    } else {
        crate::native_manager::spawn_detached_for_update(&registration, end, &mut || {
            allowed(false)
        })
        .map_err(package_installation::invalid_install)?;
    }
    let ready_end = std::cmp::min(end, Instant::now() + Duration::from_secs(5));
    loop {
        require_time(ready_end)?;
        let now = control.status().map_err(port)?;
        if now.desired_updates != DesiredUpdates::Running {
            return Ok(false);
        }
        if now.policy.installation_id.as_str() != journal.state.checkpoint.installation_id
            || now.policy.maintenance.state != MaintenanceState::Idle
        {
            return Err(package_installation::invalid_install(
                "restart policy changed",
            ));
        }
        let observed = crate::managed_background::status(&journal.state.catalog)?;
        if observed.running
            && observed.desired_updates == "running"
            && matches!(
                observed.effective_state,
                "running" | "idle" | "busy" | "deferred"
            )
        {
            return Ok(true);
        }
        std::thread::sleep(
            Duration::from_millis(20).min(ready_end.saturating_duration_since(Instant::now())),
        );
    }
}
fn finish_update(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    root: &Path,
    journal: &mut Journal<'_>,
    end: Instant,
) -> Result<(Outcome, Value), CliError> {
    verify_catalog_program_pair(
        control,
        installation,
        owner,
        &journal.state.catalog,
        &journal.state.new,
        &journal.state.checkpoint,
        end,
    )?;
    clear_fence(control, installation, owner, root, end)?;
    match resume_background(control, root, journal, &journal.state.new, end) {
        Ok(resumed) => journal.state.resumed = resumed,
        Err(_) => {
            // A concurrent pause or stop is intentional, even when it races a
            // native start. Keep it rather than reporting it as restart failure.
            if control.status().map_err(port)?.desired_updates == DesiredUpdates::Running {
                journal.state.error_code = Some("restart_failed".into());
                journal.save(end)?;
                return Ok((Outcome::Partial, state_report(&journal.state)));
            }
            journal.state.resumed = false;
        }
    }
    journal.state.error_code = None;
    journal.transition(Phase::Complete, end)?;
    Ok((Outcome::Success, state_report(&journal.state)))
}
fn finish_rollback(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    root: &Path,
    journal: &Journal<'_>,
    end: Instant,
) -> Result<(Outcome, Value), CliError> {
    verify_catalog_program_pair(
        control,
        installation,
        owner,
        &journal.state.catalog,
        &journal.state.old,
        &journal.state.checkpoint,
        end,
    )?;
    clear_fence(control, installation, owner, root, end)?;
    match resume_background(control, root, journal, &journal.state.old, end) {
        Ok(_) => Ok((Outcome::Success, state_report(&journal.state))),
        Err(_) if control.status().map_err(port)?.desired_updates != DesiredUpdates::Running => {
            Ok((Outcome::Success, state_report(&journal.state)))
        }
        Err(_) => {
            // A terminal rollback record remains immutable. Re-running recover
            // may retry current desired startup without replaying rollback.
            let mut report = state_report(&journal.state);
            report["recovery_required"] = json!(true);
            report["error_code"] = json!("restart_failed");
            Ok((Outcome::Partial, report))
        }
    }
}
fn recovered_catalog_matches_program(
    identity: &agent_session_grep_adapters_sqlite::managed_maintenance::CatalogIdentity,
    expected: &VersionIdentity,
    checkpoint: &Checkpoint,
) -> bool {
    identity.schema == expected.catalog_schema
        && identity.installation.as_str() == checkpoint.installation_id
        && identity.generation >= checkpoint.catalog_generation
}

fn recovery_can_finish_active_update(state: &State) -> bool {
    matches!(state.phase, Phase::Switched | Phase::SelfChecked)
        && state.error_code.as_deref() != Some("restart_failed")
}

fn verify_catalog_program_pair(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    catalog: &Path,
    expected: &VersionIdentity,
    checkpoint: &Checkpoint,
    end: Instant,
) -> Result<(), CliError> {
    with_update_deadline(control, end, || {
        require_time(end)?;
        let before = control.status().map_err(port)?;
        // Completion still owns the installation lock and durable fence. The
        // idle admission inspector is reserved for preflight/terminal replay;
        // an active fence requires the existing exclusive maintenance gates.
        let owned_catalog = if before.policy.maintenance.state == MaintenanceState::Idle {
            None
        } else {
            Some(
                MaintenanceCatalog::open_authorized(control, installation, owner, catalog, end)
                    .map_err(port)?,
            )
        };
        let identity = match owned_catalog.as_ref() {
            Some(catalog) => catalog.identity().clone(),
            None => {
                agent_session_grep_adapters_sqlite::managed_maintenance::inspect_catalog_identity(
                    control, catalog, end,
                )
                .map_err(port)?
            }
        };
        let status = control.status().map_err(port)?;
        if status.policy != before.policy
            || status.catalog_incarnation != before.catalog_incarnation
            || status.desired_updates != before.desired_updates
        {
            return Err(problem(
                CanonicalCode::WriterBusy,
                "catalog completion policy changed during identity verification",
            ));
        }
        if !recovered_catalog_matches_program(&identity, expected, checkpoint)
            || status.policy.installation_id != identity.installation
            || status.catalog_incarnation.as_ref() != Some(&identity.incarnation)
        {
            return Err(problem(
                CanonicalCode::UpdateRecoveryRequired,
                "catalog identity does not match the verified active program; retain the maintenance fence",
            ));
        }
        require_time(end)
    })
}

fn recover(db: &Path, prefix: Option<&Path>, end: Instant) -> Result<(Outcome, Value), CliError> {
    let prefix = resolve_prefix(prefix)?;
    let lock = update_state::acquire_installation_lock(&prefix, end)?;
    let mut journal = Journal::open(&prefix, &lock, end)?;
    let db = package_installation::absolute(db)?;
    if db != journal.state.catalog {
        return Err(CliError::usage(
            "recover requires the same selected catalog as the update journal",
        ));
    }
    let root = db
        .parent()
        .ok_or_else(|| CliError::usage("catalog has no root"))?;
    verify_update_executor(&prefix, &[&journal.state.old, &journal.state.new], end)?;
    // Unsupported schema recovery cannot migrate the control as an open side
    // effect, including when replaying a historical development journal.
    if !schema_update_supported(&journal.state.old, &journal.state.new) {
        return Err(problem(
            CanonicalCode::SchemaIncompatible,
            "recorded program pair requires current matching schemas; retain its journal and catalog",
        ));
    }
    let expected_installation =
        ControlId::parse(&journal.state.checkpoint.installation_id).map_err(port)?;
    let control =
        SqliteControlStore::open_existing_writable_with_deadline(root, &expected_installation, end)
            .map_err(port)?;
    with_update_deadline(&control, end, || {
        if control
            .status()
            .map_err(port)?
            .policy
            .installation_id
            .as_str()
            != journal.state.checkpoint.installation_id
        {
            return Err(problem(
                CanonicalCode::SchemaIncompatible,
                "recovery installation policy identity differs",
            ));
        }
        let installation = control.bind_installation(&prefix, &lock).map_err(port)?;
        let owner = ControlId::parse(&journal.state.owner_nonce).map_err(port)?;
        if journal.state.phase == Phase::Complete {
            verify_active(
                &journal,
                &journal.state.new,
                journal.state.new_pointer_generation,
                end,
            )?;
            verify_catalog_program_pair(
                &control,
                &installation,
                &owner,
                &db,
                &journal.state.new,
                &journal.state.checkpoint,
                end,
            )?;
            clear_fence(&control, &installation, &owner, root, end)?;
            return Ok((Outcome::Success, state_report(&journal.state)));
        }
        if matches!(journal.state.phase, Phase::Failed | Phase::RolledBack) {
            verify_active(
                &journal,
                &journal.state.old,
                journal.state.old_pointer_generation,
                end,
            )?;
            verify_catalog_program_pair(
                &control,
                &installation,
                &owner,
                &db,
                &journal.state.old,
                &journal.state.checkpoint,
                end,
            )?;
            return finish_rollback(&control, &installation, &owner, root, &journal, end);
        }
        set_fence(
            &control,
            &installation,
            &owner,
            root,
            MaintenancePhase::Reconciling,
            true,
            end,
        )?;
        let drain = std::cmp::min(end, Instant::now() + Duration::from_secs(30));
        let background_lifetime = drain_background_lifetime(root, drain)?;
        let mut catalog =
            MaintenanceCatalog::open_authorized(&control, &installation, &owner, &db, drain)
                .map_err(port)?;
        journal.reconcile_metadata(end)?;
        if recovery_can_finish_active_update(&journal.state)
            && verify_active(
                &journal,
                &journal.state.new,
                journal.state.new_pointer_generation,
                end,
            )
            .is_ok()
            && recovered_catalog_matches_program(
                catalog.identity(),
                &journal.state.new,
                &journal.state.checkpoint,
            )
        {
            if journal.state.phase == Phase::Switched {
                journal.state.self_checked = true;
                journal.transition(Phase::SelfChecked, end)?;
            }
            drop(catalog);
            drop(background_lifetime);
            return finish_update(&control, &installation, &owner, root, &mut journal, end);
        }
        if matches!(journal.state.phase, Phase::Verified | Phase::Quiescing) {
            journal.transition(Phase::Failed, end)?;
        } else {
            if journal.state.phase != Phase::RollbackPending
                && journal.state.phase != Phase::Reconciling
            {
                journal.transition(Phase::RollbackPending, end)?;
            }
            if journal.state.phase == Phase::RollbackPending {
                journal.transition(Phase::Reconciling, end)?;
            }
            let original =
                ControlId::parse(&journal.state.checkpoint.catalog_incarnation).map_err(port)?;
            if journal.state.recovery_incarnation.is_none() {
                journal.state.recovery_incarnation =
                    Some(fresh("recovered_catalog")?.as_str().into());
                journal.save(end)?;
            }
            let recovery = ControlId::parse(
                journal
                    .state
                    .recovery_incarnation
                    .as_deref()
                    .ok_or_else(|| package_installation::invalid_install("recovery intent"))?,
            )
            .map_err(port)?;
            if journal.state.old.catalog_schema != journal.state.new.catalog_schema {
                // A schema-changing rollback must restore the exact verified old
                // image before its program pointer. Keeping a22 image under a21
                // program would turn a recoverable failed update into a dead store.
                let backup = journal.state.backup.as_ref().ok_or_else(|| {
                    problem(
                        CanonicalCode::UpdateRecoveryRequired,
                        "schema rollback requires the recorded verified catalog backup",
                    )
                })?;
                if backup.schema != journal.state.old.catalog_schema {
                    return Err(problem(
                        CanonicalCode::SchemaIncompatible,
                        "rollback backup schema does not match the old program",
                    ));
                }
                let id = ControlId::parse(&backup.id).map_err(port)?;
                let side = root.join(format!("restore-{}.db", journal.state.update_id));
                let prepared =
                    agent_session_grep_adapters_sqlite::managed_maintenance::prepare_restore_exact(
                        &control,
                        &installation,
                        &owner,
                        &id,
                        &recovery,
                        &side,
                        end,
                    )
                    .map_err(port)?;
                let RestoreOutcome::Prepared(prepared) = prepared else {
                    return Err(problem(
                        CanonicalCode::UpdateRecoveryRequired,
                        "rollback backup cannot be restored under current scope policy",
                    ));
                };
                if prepared.schema_version() != journal.state.old.catalog_schema {
                    return Err(problem(
                        CanonicalCode::SchemaIncompatible,
                        "prepared rollback image does not match the old program",
                    ));
                }
                agent_session_grep_adapters_sqlite::managed_maintenance::apply_restore(
                    &mut catalog,
                    &control,
                    &installation,
                    &owner,
                    &prepared,
                    app_clock_ms(),
                    end,
                )
                .map_err(port)?;
            } else {
                catalog
                    .rotate_after_recovery(
                        &control,
                        &installation,
                        &owner,
                        &original,
                        &recovery,
                        app_clock_ms(),
                        end,
                    )
                    .map_err(port)?;
            }
            if !recovered_catalog_matches_program(
                catalog.identity(),
                &journal.state.old,
                &journal.state.checkpoint,
            ) {
                return Err(problem(
                    CanonicalCode::UpdateRecoveryRequired,
                    "rollback catalog identity does not match the program to restore",
                ));
            }
            journal.restore_metadata(end)?;
            restore_native_registration(&control, root, &journal, end)?;
            verify_active(
                &journal,
                &journal.state.old,
                journal.state.old_pointer_generation,
                end,
            )?;
            journal.state.cleanup_pending = journal.state.staged;
            journal.transition(Phase::RolledBack, end)?;
        }
        drop(catalog);
        drop(background_lifetime);
        finish_rollback(&control, &installation, &owner, root, &journal, end)
    })
}
#[cfg(test)]
#[path = "update_command_tests.rs"]
mod tests;
